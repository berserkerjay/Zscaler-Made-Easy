"""SOC review: who can administer the tenant (RBAC) and what leaves it as logs (telemetry).

Two read-only reviews a security operations team runs on a Zscaler tenant.
Each reads once, with GET only, through the app's assessment client (the
offline client for the sample tenant and snapshots), and reuses what the app
already has rather than reading or judging anything a second time:

* rbac_review: for ZIA, ZPA, Client Connector, ZDX and ZIdentity, the admins
  and roles, who holds full and who holds scoped rights, disabled and stale
  admins (last sign-in only where an API reports it), the API keys and API
  clients with their scopes, and the findings (too many full-access admins,
  no second factor where it is readable, rights broader than the account
  uses). The RBAC.* checks (zscaler_rbac_checks), the ZIdentity admin checks
  (zscaler_zidentity_checks ZID.5 to ZID.7), the ZPA role helpers
  (zscaler_rbac_checks._role_kind and friends) and the ZIA Admin Ranking
  setting (admin_rank) are reused as they are.
* telemetry_review: what is streamed out of the tenant (ZIA Cloud NSS feeds,
  NSS servers and collectors, ZPA Log Streaming Service), the Client
  Connector log settings, the SIEM destinations, and the gaps (a product with
  nothing streamed, a disabled feed, a missing log type). The governance
  checks USR.5, GOV.7, GOV.8 and ZPA.14 (zscaler_full_checks) are reused, the
  log families the Traffic and session logs page reads (traffic_logs) and
  the SIEM query languages it writes (siem_queries) are named per stream.

The Scope rule: a review reads only the services ticked on the Scope page
(Guard refuses any other service without sending a request); the routes and
the MCP tools refuse, before sign-in, a review with nothing it may read.

Honesty: a status is "fail", "review", "pass", "unknown" or "na". Anything
the API does not report (ZIA and Client Connector admins' second factor,
most last sign-in times, ZDX log streaming) is "unknown" with the reason,
never "pass".

Secrets: only listed fields are copied out of an answer. A feed's
connection URL becomes its host name; connection headers, tokens, client
secrets, passwords and key values are never read into a result.

Verified against zscaler-sdk-python 1.11.3 (the installed SDK):
  zia/models/admin_users.py AdminUser (loginName, role, adminScopeType
    ORGANIZATION | DEPARTMENT | LOCATION | LOCATION_GROUP, disabled,
    isPasswordLoginAllowed; no last sign-in, no MFA field);
  zia/models/admin_roles.py AdminRoles (name, rank, roleType, policyAccess,
    adminAcctAccess, isAuditor);
  zia/models/cloud_nss.py NssFeeds (name, feedStatus, nssLogType, nssType,
    siemType, connectionURL, lastSuccessFullTest);
  zpa/models/administrator_controller.py (username, role, isEnabled,
    localLoginDisabled, twoFactorAuthEnabled, microtenantId; no last sign-in);
  zpa/models/api_keys.py (name, enabled, roleId, readOnly, tokenExpiryTimeInSec);
  zpa/models/lss.py LSSResourceModel {id, config{name, enabled, sourceLogType,
    useTls, lssHost, lssPort}, connectorGroups} and zpa/lss.py source_log_map;
  zcc/models/admin_user.py AdminUser (userName, companyRole, accountEnabled,
    editEnabled, serviceType); zcc/models/admin_roles.py (roleName);
  zcc/models/application_profiles.py (logMode, logLevel, logFileSize) and
    zcc/web_policy.py ("log_mode -1 disabled, 0 info, 3 debug");
  zcc/models/company_info.py (enableGlobalZCCTelemetry, fetchLogsForAdminsEnabled,
    enableFlowLogger, disableLoggingControls);
  zid/models/users.py (adminEntitlementEnabled, status), zid/user_entitlement.py
    get_admin_entitlement, zid/models/api_client.py (name, status,
    accessTokenLifeTime, clientResources[].selectedScopes[]);
  zdx: admin.py offers departments and locations only; no admin list, no
    log streaming and no log setting is in the ZDX API.
"""
from __future__ import annotations

import re
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

KIND_RBAC = "soc-rbac"
KIND_TELEMETRY = "soc-telemetry"
MAX_ROWS = 300                 # rows kept per product list
SUPER_MAX = 3                  # more enabled full-access admins than this is a finding
STALE_DAYS = 90
STATUSES = ("fail", "review", "pass", "unknown", "na")
STATUS_WORDS = {"fail": "Fix", "review": "Review", "pass": "As recommended", "unknown": "Unknown", "na": "Not applicable"}

# The scopes each review reads, product by product (Scope page keys).
RBAC_SCOPE = "rbac"
RBAC_PRODUCTS = (("zia", "ZIA", "rbac"), ("zpa", "ZPA", "zpa"), ("zcc", "Client Connector", "zcc"),
                 ("zdx", "ZDX", "zidentity"), ("zidentity", "ZIdentity", "zidentity"))
TELEMETRY_PRODUCTS = (("zia", "ZIA", "zia_extras"), ("zpa", "ZPA", "zpa"), ("zcc", "Client Connector", "zcc"), ("zdx", "ZDX", "zdx"))
TELEMETRY_SCOPES = tuple(sorted({s for _k, _n, s in TELEMETRY_PRODUCTS}))

STOPPED_REASON = "Stopped: you clicked Stop; nothing more was read and no partial result is kept."


class Stopped(Exception):
    """Stop was clicked: the review ends with nothing more read."""


# ── reading ──────────────────────────────────────────────────────────
_SERVICE = {"zia": "zia", "zpa": "zpa", "zcc": "zcc", "zdx": "zdx", "zid": "zid", "ziam": "zid"}


class Guard:
    """The assessment client as a review sees it: GET only, of the services
    in `allowed` (any other is refused with code 0 and never sent), each
    distinct read answered once, and Stop honoured before every read. It
    exposes no write method at all."""

    PASS_THROUGH = ("customer_id", "legacy", "offline", "method")

    def __init__(self, client: Any, allowed: Iterable[str], cancel: Optional[threading.Event] = None):
        self._client = client
        self._allowed = set(allowed)
        self._cancel = cancel
        self._memo: Dict[Tuple[str, str], Tuple[Any, int]] = {}
        self.refused: List[str] = []
        self.reads = 0

    def __getattr__(self, name: str) -> Any:
        if name in Guard.PASS_THROUGH:
            return getattr(self._client, name)
        raise AttributeError(name)

    def get(self, ep: Any, p: Any = None, *_a: Any, **_k: Any) -> Tuple[Any, int]:
        if self._cancel is not None and self._cancel.is_set():
            raise Stopped(STOPPED_REASON)
        path = str(ep or "")
        service = _SERVICE.get(path.lstrip("/").split("/", 1)[0])
        if service not in self._allowed:
            self.refused.append(path)
            return {"error": "not in scope", "message": "This service is not ticked on the Scope page; no request was sent."}, 0
        key = (path, repr(sorted(p.items())) if isinstance(p, dict) else repr(p))
        if key not in self._memo:
            self.reads += 1
            res = self._client.get(path, p) if p is not None else self._client.get(path)
            try:
                body, code = res[0], int(res[1])
            except Exception:  # noqa: BLE001 — an answer that is not (body, code) is unreadable
                body, code = None, -1
            self._memo[key] = (body, code)
        return self._memo[key]


def _rows(body: Any) -> List[Dict[str, Any]]:
    from dlp_assessment_full_auto import _ls
    rows = _ls(body)
    if not rows and isinstance(body, dict):
        for k in ("list", "records", "policies", "items"):
            if isinstance(body.get(k), list):
                rows = body[k]
                break
    return [r for r in rows if isinstance(r, dict)]


def _list(cl: Any, ep: str) -> Tuple[List[Dict[str, Any]], int]:
    from offline_tenant import scrub
    body, code = cl.get(ep)
    return (scrub(_rows(body)) if code == 200 else []), code


def state_for(code: int) -> Tuple[str, str]:
    """(state, why) of a product read from its HTTP status."""
    if code in (200, 204):
        return "read", ""
    if code == 0:
        return "not_in_scope", "not ticked on the Scope page, so it was not read"
    if code in (401, 403):
        return "not_permitted", f"the API client's role cannot read it (HTTP {code})"
    if code in (400, 404, 405):
        return "not_available", f"not available on this tenant (HTTP {code}): not licensed or not in use"
    return "not_readable", f"it could not be read (HTTP {code})"


def _text(v: Any, n: int = 120) -> str:
    s = " ".join(str(v if v is not None else "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "enabled", "active")


def _falsy(v: Any) -> bool:
    return v is False or str(v).strip().lower() in ("false", "0", "no", "disabled", "inactive")


def _when(v: Any) -> Optional[float]:
    from zscaler_zidentity_checks import _when as when
    return when(v)


def _iso(t: Optional[float]) -> Optional[str]:
    return time.strftime("%Y-%m-%d", time.gmtime(t)) if t else None


# ── findings ─────────────────────────────────────────────────────────
def finding(fid: str, product: str, title: str, status: str, detail: str, fix: str = "", source: str = "") -> Dict[str, Any]:
    assert status in STATUSES
    return {"id": fid, "product": product, "title": title, "status": status, "detail": detail, "fix": fix, "source": source}


_NA = re.compile(r"\bN/A\b|not licensed|not in use|Not applicable", re.I)


def check_status(r_status: str, detail: str) -> str:
    """A check result as a review status. INFO (not judged) is never a pass:
    "na" when the check says the feature is not licensed or not in use,
    else "unknown". An ERROR is "unknown"."""
    return {"PASS": "pass", "FAIL": "fail", "REVIEW": "review"}.get(str(r_status), "na" if _NA.search(str(detail or "")) else "unknown")


def run_checks(cl: Any, reg: Iterable[Tuple[str, str, str, Callable[[Any], Any]]], creds: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run reused checks [(id, section, label, fn)] on the guarded client.
    A check that raises is "unknown" with its error masked; Stop ends the review."""
    import tenant_auth
    out = []
    for cid, sec, label, fn in reg:
        try:
            r = fn(cl)
            st, detail = r.status, str(r.detail or "")
        except Stopped:
            raise
        except Exception as e:  # noqa: BLE001 — a failed check is not judged
            st, detail = "ERROR", tenant_auth.mask_secrets(f"The check could not run ({type(e).__name__}: {str(e)[:160]}).", creds or {})
        out.append({"id": cid, "section": sec, "label": label, "status": check_status(st, detail), "detail": detail})
    return out


def counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    c = {s: 0 for s in STATUSES}
    for f in findings:
        c[f["status"]] = c.get(f["status"], 0) + 1
    return c


def _product(key: str, name: str, state: str = "read", why: str = "") -> Dict[str, Any]:
    return {"key": key, "name": name, "state": state, "why": why}


# ═════════════════════════════════════════════════════════════════════
# RBAC
# ═════════════════════════════════════════════════════════════════════
_SUPER = re.compile(r"super|full ?access|full ?admin|owner|root", re.I)
_READ_ONLY = re.compile(r"read|view|audit|observer|monitor", re.I)


def zia_role_kind(role: Dict[str, Any]) -> str:
    """"full", "scoped", "read_only" or "unknown" for a ZIA admin role.
    policyAccess / adminAcctAccess are READ_WRITE, READ_ONLY or NONE
    (assumed: the SDK documents READ_WRITE as an example, not the list)."""
    name = str(role.get("name") or "")
    pol = str(role.get("policyAccess") or role.get("policy_access") or "").upper()
    acct = str(role.get("adminAcctAccess") or role.get("admin_acct_access") or "").upper()
    if _truthy(role.get("isAuditor")):
        return "read_only"
    if _SUPER.search(name) or (pol == "READ_WRITE" and acct == "READ_WRITE"):
        return "full"
    if pol == "READ_ONLY" and acct in ("", "READ_ONLY", "NONE"):
        return "read_only"
    if pol == "READ_WRITE":
        return "scoped"
    if not pol and _READ_ONLY.search(name):
        return "read_only"
    return "unknown"


def named_kind(name: Any) -> str:
    """"full", "read_only" or "scoped" from a role name alone (assumed:
    built-in full roles say super or full, read-only ones read, view or audit)."""
    n = str(name or "")
    if _SUPER.search(n):
        return "full"
    if _READ_ONLY.search(n):
        return "read_only"
    return "scoped" if n else "unknown"


def _admin(name: Any, product: str, role: Any, access: str, enabled: Optional[bool], scope: str = "",
           mfa: Optional[bool] = None, mfa_note: str = "", local_password: Optional[bool] = None,
           last_sign_in: Optional[float] = None, last_sign_in_reported: bool = False) -> Dict[str, Any]:
    stale = None
    if enabled is False:
        stale = True
    elif last_sign_in_reported:
        stale = bool(last_sign_in and time.time() - last_sign_in > STALE_DAYS * 86400)
    return {"name": _text(name, 120), "product": product, "role": _text(role, 80), "access": access, "scope": scope,
            "enabled": enabled, "mfa": mfa, "mfa_note": mfa_note, "local_password": local_password,
            "last_sign_in": _iso(last_sign_in), "last_sign_in_reported": last_sign_in_reported, "stale": stale}


def _admin_counts(admins: List[Dict[str, Any]]) -> Dict[str, Any]:
    on = [a for a in admins if a["enabled"] is not False]
    return {"admins": len(admins), "enabled": len(on), "disabled": len(admins) - len(on),
            "full": sum(1 for a in on if a["access"] == "full"), "scoped": sum(1 for a in on if a["access"] == "scoped"),
            "read_only": sum(1 for a in on if a["access"] == "read_only"), "access_unknown": sum(1 for a in on if a["access"] == "unknown"),
            "mfa_off": sum(1 for a in on if a["mfa"] is False), "mfa_unknown": sum(1 for a in on if a["mfa"] is None),
            "stale": sum(1 for a in admins if a["stale"] is True),
            "last_sign_in_reported": sum(1 for a in admins if a["last_sign_in_reported"])}


def _rbac_zia(cl: Any, scopes: List[str]) -> Dict[str, Any]:
    import admin_rank
    p = _product("zia", "ZIA")
    roles, rc = _list(cl, "/zia/adminRoles")
    admins, ac = _list(cl, "/zia/adminUsers")
    if ac not in (200, 204):
        p["state"], p["why"] = state_for(ac)
        return p
    by_id = {str(r.get("id")): r for r in roles}
    p["roles"] = [{"name": _text(r.get("name"), 80), "kind": zia_role_kind(r), "rank": r.get("rank"), "type": _text(r.get("roleType"), 40),
                   "policy_access": _text(r.get("policyAccess"), 20), "admin_access": _text(r.get("adminAcctAccess"), 20)}
                  for r in roles[:MAX_ROWS]]
    p["roles_read"] = rc in (200, 204)
    rows = []
    for a in admins[:MAX_ROWS]:
        role = a.get("role") if isinstance(a.get("role"), dict) else {}
        full_role = by_id.get(str(role.get("id"))) or role
        kind = zia_role_kind(full_role) if full_role else "unknown"
        scope = str(a.get("adminScopeType") or "").upper()
        if kind == "full" and scope and scope != "ORGANIZATION":
            kind = "scoped"   # full rights over some departments or locations only
        rows.append(_admin(a.get("loginName") or a.get("userName") or a.get("email"), "ZIA", role.get("name"), kind,
                           enabled=not _truthy(a.get("disabled")), scope=scope.lower().replace("_", " ") or "not reported",
                           mfa=None, mfa_note="ZIA admin MFA is enforced by Authentication Service and is not in the admin API",
                           local_password=_truthy(a.get("isPasswordLoginAllowed")) if "isPasswordLoginAllowed" in a else None))
    p["admins"] = rows
    p["api_clients"] = []
    p["api_note"] = "ZIA automation signs in with OneAPI clients, listed under ZIdentity."
    p["admin_rank"] = admin_rank.read(cl, scopes)
    p["counts"] = _admin_counts(rows)
    return p


def _rbac_zpa(cl: Any) -> Dict[str, Any]:
    import zscaler_rbac_checks as rb
    p = _product("zpa", "ZPA")
    admins, ac = rb._zpa_rows(cl, rb.ZPA_ADMINS)
    if ac not in (200, 204):
        p["state"], p["why"] = state_for(ac)
        return p
    roles, rc = rb._roles_by_id(cl)
    p["roles"] = [{"name": _text(r.get("name"), 80), "kind": {"custom": "scoped"}.get(rb._role_kind(r), rb._role_kind(r)),
                   "classes": len(rb._role_classes(r))} for r in list(roles.values())[:MAX_ROWS]]
    p["roles_read"] = rc in (200, 204)
    enabled_ids = {id(a) for a in rb._enabled_admins(admins)}
    rows = []
    for a in admins[:MAX_ROWS]:
        rid = rb._role_id(a)
        role = roles.get(rid)
        kind = {"custom": "scoped"}.get(rb._role_kind(role), rb._role_kind(role)) if role else "unknown"
        mt = str(a.get("microtenantId") or "")
        if kind == "full" and mt not in ("", "0"):
            kind = "scoped"   # full rights inside one microtenant only
        local = not rb._truthy(a.get("localLoginDisabled"))
        rname = (a.get("role") or {}).get("name") if isinstance(a.get("role"), dict) else (role or {}).get("name")
        rows.append(_admin(a.get("username") or a.get("email") or a.get("displayName"), "ZPA", rname, kind,
                           enabled=id(a) in enabled_ids, scope=("microtenant " + _text(a.get("microtenantName") or mt, 60)) if mt not in ("", "0") else "tenant",
                           mfa=rb._truthy(a.get("twoFactorAuthEnabled")) if local else None,
                           mfa_note="" if local else "signs in through SSO only: the second factor is the IdP's",
                           local_password=local))
    p["admins"] = rows
    keys, kc = rb._zpa_rows(cl, rb.ZPA_API_KEYS)
    p["api_clients"] = []
    for k in keys[:MAX_ROWS]:
        role = roles.get(rb._role_id(k))
        kind = "read_only" if rb._truthy(k.get("readOnly")) else ({"custom": "scoped"}.get(rb._role_kind(role), rb._role_kind(role)) if role else "unknown")
        try:
            life = int(k.get("tokenExpiryTimeInSec") or 0) or None
        except (TypeError, ValueError):
            life = None
        p["api_clients"].append({"name": _text(k.get("name"), 80), "kind": "ZPA API key", "enabled": not _falsy(k.get("enabled")),
                                 "access": kind, "role": _text((role or {}).get("name"), 80), "token_lifetime_seconds": life,
                                 "scopes": [], "broad": kind == "full"})
    p["api_read"] = kc in (200, 204)
    body, ec = cl.get(rb.ZPA_EMERGENCY)
    if ec == 200:
        users = _rows(body)
        last = [t for t in (rb._epoch(u.get("lastLoginTime")) for u in users) if t]
        p["break_glass"] = {"accounts": len(users), "active": sum(1 for u in users if str(u.get("userStatus") or "").upper() in ("ACTIVE", "ACTIVATED", "ENABLED")),
                            "last_used": _iso(max(last)) if last else None}
    p["counts"] = _admin_counts(rows)
    return p


def _rbac_zcc(cl: Any) -> Dict[str, Any]:
    p = _product("zcc", "Client Connector")
    admins, ac = _list(cl, "/zcc/adminUsers")
    if ac not in (200, 204):
        p["state"], p["why"] = state_for(ac)
        return p
    # The admin list is read once per user type and an admin can appear in more
    # than one answer: each admin is kept once (by id, else by user name).
    seen, unique = set(), []
    for a in admins:
        k = str(a.get("id") or a.get("userName") or len(unique))
        if k not in seen:
            seen.add(k)
            unique.append(a)
    admins = unique
    roles, rc = _list(cl, "/zcc/adminRoles")
    p["roles"] = [{"name": _text(r.get("roleName") or r.get("name"), 80), "kind": named_kind(r.get("roleName") or r.get("name")),
                   "editable": r.get("isEditable")} for r in roles[:MAX_ROWS]]
    p["roles_read"] = rc in (200, 204)
    rows = []
    for a in admins[:MAX_ROWS]:
        role = a.get("companyRole") if isinstance(a.get("companyRole"), dict) else {}
        rname = role.get("roleName") or role.get("name")
        kind = named_kind(rname)
        if kind != "read_only" and _falsy(a.get("editEnabled")):
            kind = "read_only"   # assumed: editEnabled false means the admin cannot change anything
        rows.append(_admin(a.get("userName"), "Client Connector", rname, kind, enabled=not _falsy(a.get("accountEnabled")),
                           scope=_text(a.get("serviceType") or "", 20).lower() or "not reported",
                           mfa=None, mfa_note="the Client Connector portal admin API reports no second factor"))
    p["admins"] = rows
    p["api_clients"] = []
    p["counts"] = _admin_counts(rows)
    return p


def _zid_scopes(c: Dict[str, Any]) -> List[str]:
    out = []
    for res in (c.get("clientResources") or c.get("client_resources") or [])[:50]:
        if isinstance(res, dict):
            for s in (res.get("selectedScopes") or res.get("selected_scopes") or [])[:100]:
                if isinstance(s, dict) and s.get("name"):
                    out.append(_text(s.get("name"), 120))
    return out


def _rbac_zid(cl: Any) -> Dict[str, Any]:
    import ops_zid
    import zscaler_zidentity_checks as zid
    p = _product("zidentity", "ZIdentity")
    admins, ac = zid._admins(cl)
    if admins is None:
        p["state"], p["why"] = state_for(ac)
        return p
    rows, ents_by = [], {}
    for u in admins:
        uid = zid._uid(u)
        ents = zid._entitlements(cl, uid) if uid else None
        services, roles = [], []
        for e in ents or []:
            svc = e.get("service") if isinstance(e.get("service"), dict) else {}
            sname = _text(svc.get("serviceName") or svc.get("service_name") or "", 40)
            rnames = [_text((r or {}).get("displayName") or (r or {}).get("name"), 60) for r in (e.get("roles") or [])[:20] if isinstance(r, dict)]
            if sname:
                services.append(sname)
            roles += [f"{sname} {r}".strip() for r in rnames]
        ents_by[uid] = ents
        why = zid.broad_reason(ents or [])
        if ents is None:
            kind = "unknown"
        elif why:
            kind = "full"
        elif roles and all(_READ_ONLY.search(r) for r in roles):
            kind = "read_only"
        else:
            kind = "scoped" if roles else "unknown"
        t = next((zid._when(u.get(k)) for k in zid._LAST_SIGN_IN if u.get(k) not in (None, "")), None)
        row = _admin(u.get("loginName") or u.get("displayName"), "ZIdentity", "; ".join(roles[:6]) or ("not read" if ents is None else "none"),
                     kind, enabled=zid._active(u), scope=", ".join(sorted(set(services))) or "not read",
                     mfa=None, mfa_note="the directory API reports no second factor per admin",
                     last_sign_in=t, last_sign_in_reported=t is not None)
        row["services"] = sorted(set(services))
        row["entitlements"] = [{"service": s, "roles": [r[len(s):].strip() for r in roles if r.startswith(s + " ") or r == s]} for s in sorted(set(services))]
        rows.append(row)
    p["admins"] = rows
    p["roles"] = sorted({r for a in rows for e in a.get("entitlements", []) for r in (f"{e['service']} {x}" for x in e["roles"])})[:MAX_ROWS]
    p["roles"] = [{"name": r, "kind": named_kind(r)} for r in p["roles"]]
    clients, cc = _list(cl, "/zid/api-clients")
    p["api_read"] = cc in (200, 204)
    p["api_clients"] = []
    for c in clients[:MAX_ROWS]:
        scopes = _zid_scopes(c)
        broad = [s for s in scopes if ops_zid._BROAD.search(s)]
        kind = "full" if broad else ("read_only" if scopes and all(_READ_ONLY.search(s) for s in scopes) else ("scoped" if scopes else "unknown"))
        try:
            life = int(c.get("accessTokenLifeTime") or c.get("access_token_life_time") or 0) or None
        except (TypeError, ValueError):
            life = None
        p["api_clients"].append({"name": _text(c.get("name"), 80), "kind": "OneAPI client", "enabled": not _falsy(c.get("status")),
                                 "access": kind, "role": "", "token_lifetime_seconds": life, "scopes": scopes[:30], "broad": bool(broad)})
    p["counts"] = _admin_counts(rows)
    return p


def _rbac_zdx(zid_product: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    p = _product("zdx", "ZDX")
    note = ("The ZDX API has no admin list (zscaler-sdk-python 1.11.3 zdx admin offers departments and locations only). "
            "ZDX admins are read from their ZIdentity admin entitlements.")
    if not zid_product or zid_product.get("state") != "read":
        why = (zid_product or {}).get("why") or "ZIdentity was not read"
        p["state"], p["why"] = "unknown", f"{note} ZIdentity: {why}."
        return p
    rows = []
    for a in zid_product.get("admins") or []:
        ent = next((e for e in a.get("entitlements") or [] if e["service"].upper() == "ZDX"), None)
        if not ent:
            continue
        kind = "full" if any(_SUPER.search(r) for r in ent["roles"]) else ("read_only" if ent["roles"] and all(_READ_ONLY.search(r) for r in ent["roles"]) else "scoped")
        row = dict(a, product="ZDX", role="; ".join(ent["roles"]) or "none", access=kind, scope="ZDX")
        row.pop("entitlements", None)
        row.pop("services", None)
        rows.append(row)
    p["state"], p["why"] = "derived", note
    p["admins"], p["roles"], p["api_clients"] = rows, [], []
    p["counts"] = _admin_counts(rows)
    return p


def _rbac_findings(products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    read = [p for p in products if p["state"] in ("read", "derived")]
    # 1. Too many full-access admins, per product.
    for p in read:
        c = p.get("counts") or {}
        if not c.get("enabled"):
            continue
        if c.get("full", 0) > SUPER_MAX:
            out.append(finding("SOC.R1", p["name"], f"{p['name']}: too many full-access admins", "review",
                               f"{c['full']} of {c['enabled']} enabled {p['name']} admins hold full access.",
                               f"Keep full access to {SUPER_MAX} people or fewer (break-glass included) and give everyone else a role scoped to "
                               "what they run, or read-only.", "admins and roles"))
        elif c.get("access_unknown") == c.get("enabled"):
            out.append(finding("SOC.R1", p["name"], f"{p['name']}: full-access admins", "unknown",
                               f"The rights of the {c['enabled']} enabled {p['name']} admin(s) could not be matched to a role, so full access was not counted.",
                               "", "admins and roles"))
        else:
            out.append(finding("SOC.R1", p["name"], f"{p['name']}: full-access admins", "pass",
                               f"{c['full']} of {c['enabled']} enabled {p['name']} admin(s) hold full access"
                               + (f"; {c['access_unknown']} could not be matched to a role." if c.get("access_unknown") else "."), "", "admins and roles"))
    # 2. A second factor, where an API reports it.
    no_mfa, judged, unreadable = [], [], []
    for p in read:
        c = p.get("counts") or {}
        if not c.get("enabled"):
            continue
        if c.get("enabled", 0) - c.get("mfa_unknown", 0) > 0:
            judged.append(p["name"])
            if c.get("mfa_off"):
                no_mfa.append(f"{c['mfa_off']} {p['name']}")
        if c.get("mfa_unknown") and p["key"] in ("zia", "zcc", "zidentity", "zdx"):
            unreadable.append(p["name"])
    if no_mfa:
        out.append(finding("SOC.R2", ", ".join(judged), "Admins without a second factor", "fail",
                           f"Admins who can sign in with a local password and have no second factor: {', '.join(no_mfa)}.",
                           "Turn on two-factor authentication for every local admin, or turn off local sign-in so they sign in through your IdP with MFA.",
                           "admins (two-factor and local sign-in fields)"))
    elif judged:
        out.append(finding("SOC.R2", ", ".join(judged), "Admins without a second factor", "pass",
                           f"Every admin with a local password has a second factor ({', '.join(judged)}).", "", "admins"))
    if unreadable:
        out.append(finding("SOC.R2", ", ".join(unreadable), "Second factor not reported", "unknown",
                           f"{', '.join(unreadable)}: the API does not say whether admins use a second factor (MFA is enforced by "
                           "Authentication Service or your IdP), so it is not judged here.",
                           "Check MFA under Administration > Authentication > Authentication Methods and in your IdP.", "admins"))
    # 3. Disabled and stale admins.
    stale_parts, reported = [], []
    for p in read:
        if p["key"] == "zdx":
            continue   # the same ZIdentity accounts
        c = p.get("counts") or {}
        if c.get("stale"):
            stale_parts.append(f"{c['stale']} {p['name']}")
        if c.get("last_sign_in_reported"):
            reported.append(p["name"])
    no_time = [p["name"] for p in read if p["key"] != "zdx" and (p.get("counts") or {}).get("admins") and not (p.get("counts") or {}).get("last_sign_in_reported")]
    if stale_parts:
        out.append(finding("SOC.R3", "", "Disabled or unused admins still listed", "fail",
                           f"Admin accounts that are disabled, or have not signed in for {STALE_DAYS} days, still listed with their rights: "
                           f"{', '.join(stale_parts)}.",
                           "Remove the admin rights of disabled and unused accounts, and make it part of the leaver process.", "admins"))
    elif reported:
        out.append(finding("SOC.R3", ", ".join(reported), "Disabled or unused admins still listed", "pass",
                           f"No disabled or unused admin account in {', '.join(reported)}.", "", "admins"))
    if no_time:
        out.append(finding("SOC.R3", ", ".join(no_time), "Last sign-in not reported", "unknown",
                           f"{', '.join(no_time)}: the API gives no last sign-in time, so an unused but enabled admin cannot be found here.",
                           "Review last sign-in in each admin portal or in your IdP's sign-in logs.", "admins"))
    # 4. Rights broader than the account uses: automation with full access,
    # and full access left on disabled or unused accounts. Use per permission
    # is not readable from any API, so this is judged from breadth and activity.
    broad_clients = [f"{c['name']} ({p['name']} {c['kind']})" for p in read for c in p.get("api_clients") or [] if c.get("enabled") and c.get("broad")]
    idle_full = [f"{a['product']}" for p in read if p["key"] != "zdx" for a in p.get("admins") or [] if a["access"] == "full" and a["stale"]]
    api_read = [p["name"] for p in read if p.get("api_read")]
    if broad_clients or idle_full:
        parts = []
        if broad_clients:
            parts.append(f"{len(broad_clients)} API key(s) or client(s) with full access: {', '.join(broad_clients[:8])}")
        if idle_full:
            parts.append(f"{len(idle_full)} disabled or unused account(s) still holding full access ({', '.join(sorted(set(idle_full)))})")
        out.append(finding("SOC.R4", "", "Rights broader than they are used", "review", "; ".join(parts) + ".",
                           "Give automation a read-only or task-scoped role (an assessment needs read only) and take full access off accounts "
                           "that no longer use it.", "API keys, API clients and admins"))
    elif api_read:
        out.append(finding("SOC.R4", ", ".join(api_read), "Rights broader than they are used", "pass",
                           f"No enabled API key or client holds full access ({', '.join(api_read)}), and no disabled or unused account holds full access. "
                           "Use per permission is not in any API, so rights an active admin never uses cannot be seen here.", "", "API keys and clients"))
    else:
        out.append(finding("SOC.R4", "", "Rights broader than they are used", "unknown",
                           "No API key or API client list could be read, so automation rights were not judged.", "", "API keys and clients"))
    return out


def rbac_review(cl: Any, scopes: Iterable[str], log: Optional[Callable[[str], None]] = None,
                cancel: Optional[threading.Event] = None, creds: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The RBAC review of the services in scope. `cl` is the assessment
    client (signed in, or offline). Read-only; Stop raises Stopped."""
    import zscaler_rbac_checks as rb
    import zscaler_zidentity_checks as zid
    sc = [str(s) for s in scopes or []]
    say = log or (lambda _t: None)
    allowed = {"zia"} | ({"zpa"} if "zpa" in sc else set()) | ({"zcc"} if "zcc" in sc else set()) | ({"zid"} if "zidentity" in sc else set())
    g = Guard(cl, allowed, cancel)
    products: List[Dict[str, Any]] = []
    say("Reading ZIA admins, roles and the Admin Ranking setting.")
    products.append(_rbac_zia(g, sc))
    if "zpa" in sc:
        say("Reading ZPA administrators, roles, API keys and emergency access.")
        products.append(_rbac_zpa(g))
    else:
        products.append(_product("zpa", "ZPA", *state_for(0)))
    if "zcc" in sc:
        say("Reading Client Connector portal admins and roles.")
        products.append(_rbac_zcc(g))
    else:
        products.append(_product("zcc", "Client Connector", *state_for(0)))
    zp = None
    if "zidentity" in sc:
        say("Reading ZIdentity admins, their entitlements and the API clients.")
        zp = _rbac_zid(g)
    else:
        zp = _product("zidentity", "ZIdentity", *state_for(0))
    products.append(_rbac_zdx(zp))
    products.append(zp)
    say("Running the RBAC checks on what was read.")
    in_scope = {"ZIA"} | ({"ZPA"} if "zpa" in sc else set()) | ({"ZCC"} if "zcc" in sc else set()) | ({"ZIdentity"} if "zidentity" in sc else set())
    reg = [c for c in rb.RBAC_REG if c[1].split("—")[-1].strip() in in_scope]
    if "zidentity" in sc:
        reg += [c for c in zid.ZID_REG if c[0] in ("ZID.5", "ZID.6", "ZID.7")]
    checks = run_checks(g, reg, creds)
    findings = _rbac_findings(products)
    allc = counts(findings)
    lines = []
    for p in products:
        c = p.get("counts")
        if p["state"] in ("read", "derived") and c:
            lines.append(f"{p['name']}: {c['enabled']} enabled admin(s), {c['full']} with full access, {c['scoped']} scoped, {c['read_only']} read-only"
                         + (f", {c['stale']} disabled or unused" if c.get("stale") else "") + ".")
        else:
            lines.append(f"{p['name']}: {p['why'] or p['state']}.")
    say(f"Done: {allc['fail']} to fix, {allc['review']} to review, {allc['unknown']} unknown.")
    return {"kind": KIND_RBAC, "status": "done", "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scopes": sc,
            "products": products, "findings": findings, "checks": checks, "counts": allc, "check_counts": counts(checks),
            "summary": lines, "refused_reads": len(g.refused), "reads": g.reads,
            "assumptions": [
                "ZIA role rights: policyAccess and adminAcctAccess are READ_WRITE, READ_ONLY or NONE (the SDK documents READ_WRITE as an example).",
                "Client Connector and ZIdentity role rights are read from role names (super or full: full access; read, view or audit: read-only).",
                "A Client Connector admin with editEnabled false cannot change anything.",
                "ZIdentity last sign-in fields (lastLoginTime and similar) are read only when the tenant sends them; the SDK model has none.",
                "Rights broader than used: use per permission is in no API, so this is judged from role breadth, automation and account activity.",
            ]}


# ═════════════════════════════════════════════════════════════════════
# Telemetry
# ═════════════════════════════════════════════════════════════════════
# ZIA log types worth streaming (terraform zia_cloud_nss_feed / SDK nssLogType):
# web (MULTIFEEDLOG and a feed with no type count as web, as zscaler checks 12.8 and 12.9 read them), firewall, DNS, admin audit.
ZIA_TYPES = (("web", "Web", ("WEBLOG", "MULTIFEEDLOG", "")), ("firewall", "Firewall", ("FWLOG",)), ("dns", "DNS", ("DNSLOG",)),
             ("audit", "Admin audit", ("ADMIN_AUDIT",)))
# The NSS server type that carries each family (assumed: firewall NSS servers carry the DNS feed too).
ZIA_VM = {"web": "NSS_FOR_WEB", "firewall": "NSS_FOR_FIREWALL", "dns": "NSS_FOR_FIREWALL"}
ZIA_FAMILY = {"WEBLOG": "zia_web", "MULTIFEEDLOG": "zia_web", "": "zia_web", "FWLOG": "zia_fw", "DNSLOG": "zia_dns"}
# ZPA LSS log types (zscaler/zpa/lss.py source_log_map, verified) and the ones a SOC needs streamed.
LSS_NAMES = {"zpn_trans_log": "User Activity", "zpn_auth_log": "User Status", "zpn_audit_log": "Audit logs",
             "zpn_ast_auth_log": "App Connector Status", "zpn_ast_comprehensive_stats": "App Connector Metrics",
             "zpn_http_trans_log": "Browser Access", "zpn_sys_auth_log": "Private Service Edge Status",
             "zpn_waf_http_exchanges_log": "Web Inspection"}
LSS_NEEDED = ("zpn_trans_log", "zpn_auth_log", "zpn_audit_log", "zpn_ast_auth_log")
ZPA_FAMILY = {"zpn_trans_log": "zpa_activity", "zpn_auth_log": "zpa_status", "zpn_ast_auth_log": "zpa_connector", "zpn_sys_auth_log": "zpa_pse"}
# Client Connector log mode (zcc/web_policy.py: -1 disabled, 0 info, 3 debug; other values shown as a level).
ZCC_LOG_MODES = {-1: "disabled", 0: "info", 3: "debug"}
_HOST = re.compile(r"\A[A-Za-z0-9.-]{1,253}\Z")


def _lss_names() -> Dict[str, str]:
    """The SDK's own LSS log type names, else the copy above."""
    try:
        from zscaler.zpa.lss import LSSConfigControllerAPI
        sdk = {code: name.replace("_", " ") for name, code in LSSConfigControllerAPI.source_log_map.items()}
        return {code: LSS_NAMES.get(code, sdk[code].title()) for code in sdk} | {k: v for k, v in LSS_NAMES.items() if k not in sdk}
    except Exception:  # noqa: BLE001 — the copy is verified against the same SDK
        return dict(LSS_NAMES)


def host_of(url: Any) -> str:
    """The host name of a destination URL, never its path, query or credentials."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        h = urlsplit(raw if "://" in raw else "https://" + raw).hostname or ""
    except ValueError:
        return ""
    return h if _HOST.match(h) else ""


def siem_key(siem_type: Any) -> str:
    """The siem_queries language for a Cloud NSS SIEM type (assumed spellings: SPLUNK, AZURE_SENTINEL / SENTINEL, ELASTIC)."""
    t = str(siem_type or "").upper()
    if "SPLUNK" in t:
        return "splunk"
    if "SENTINEL" in t or "AZURE" in t:
        return "sentinel"
    if "ELASTIC" in t:
        return "elastic"
    return ""


def _family_label(fam: str) -> str:
    import traffic_logs
    return traffic_logs.LOG_LABELS.get(fam, "")


def _tel_zia(cl: Any) -> Dict[str, Any]:
    from zscaler_full_checks import _nss_state, _subscriptions, _LOG_SKUS
    p = _product("zia", "ZIA")
    feeds, fc = _list(cl, "/zia/nssFeeds")
    servers, sc = _list(cl, "/zia/nssServers")
    collectors, cc = _list(cl, "/zia/nssCollectors")
    if fc not in (200, 204) and sc not in (200, 204) and cc not in (200, 204):
        p["state"], p["why"] = state_for(fc)
        return p
    p["streams"] = []
    for f in feeds[:MAX_ROWS]:
        lt = str(f.get("nssLogType") or "").upper()
        fam = ZIA_FAMILY.get(lt, "")
        p["streams"].append({"name": _text(f.get("name"), 80), "kind": "Cloud NSS feed", "enabled": str(f.get("feedStatus") or "ENABLED").upper() == "ENABLED",
                             "log_type": lt or "not reported (read as web)", "log_code": lt, "nss_type": _text(f.get("nssType"), 30), "siem": _text(f.get("siemType"), 30),
                             "destination": host_of(f.get("connectionURL")), "tls": None,
                             "last_test": _iso(_when(f.get("lastSuccessFullTest"))), "traffic_logs": _family_label(fam),
                             "siem_queries": siem_key(f.get("siemType"))})
    p["servers"] = [{"name": _text(s.get("name"), 80), "type": _text(s.get("type"), 30), "status": _text(s.get("status"), 30),
                     "health": _nss_state(s)} for s in servers[:MAX_ROWS]]
    p["collectors"] = len(collectors)
    subs = _subscriptions(cl)
    p["licensed"] = None if subs is None else bool(subs & set(_LOG_SKUS))
    p["reads"] = {"feeds": fc in (200, 204), "servers": sc in (200, 204), "collectors": cc in (200, 204)}
    return p


def _tel_zpa(cl: Any) -> Dict[str, Any]:
    import zscaler_rbac_checks as rb
    p = _product("zpa", "ZPA")
    rows, code = rb._zpa_rows(cl, "/zpa/lssConfig")
    if code not in (200, 204):
        p["state"], p["why"] = state_for(code)
        return p
    names = _lss_names()
    p["streams"] = []
    for r in rows[:MAX_ROWS]:
        c = r.get("config") if isinstance(r.get("config"), dict) else r
        lt = str(c.get("sourceLogType") or "")
        port = c.get("lssPort")
        host = host_of(c.get("lssHost"))
        p["streams"].append({"name": _text(c.get("name"), 80), "kind": "Log Streaming Service", "enabled": not _falsy(c.get("enabled")),
                             "log_type": names.get(lt, lt or "not reported"), "log_code": lt, "siem": "",
                             "destination": f"{host}:{_text(port, 6)}" if host and port else host,
                             "tls": None if c.get("useTls") is None else _truthy(c.get("useTls")),
                             "connector_groups": len(r.get("connectorGroups") or []), "last_test": None,
                             "traffic_logs": _family_label(ZPA_FAMILY.get(lt, "")), "siem_queries": ""})
    return p


def _tel_zcc(cl: Any) -> Dict[str, Any]:
    p = _product("zcc", "Client Connector")
    profiles, pc = _list(cl, "/zcc/webPolicies")
    info_body, ic = cl.get("/zcc/companyInfo")
    if pc not in (200, 204) and ic not in (200, 204):
        p["state"], p["why"] = state_for(pc)
        return p
    p["profiles"] = []
    for x in profiles[:MAX_ROWS]:
        mode = x.get("logMode", x.get("log_mode"))
        try:
            mode = int(mode) if mode not in (None, "") else None
        except (TypeError, ValueError):
            mode = None
        p["profiles"].append({"name": _text(x.get("name"), 80), "log_mode": None if mode is None else ZCC_LOG_MODES.get(mode, f"level {mode}"),
                              "log_level": x.get("logLevel", x.get("log_level")), "log_file_size_mb": x.get("logFileSize", x.get("log_file_size"))})
    info = info_body if ic == 200 and isinstance(info_body, dict) else {}
    yn = lambda k: None if info.get(k) is None else _truthy(info.get(k))   # noqa: E731
    p["settings"] = {"telemetry": yn("enableGlobalZCCTelemetry"), "admins_fetch_logs": yn("fetchLogsForAdminsEnabled"),
                     "flow_logger": yn("enableFlowLogger"), "logging_controls_hidden": yn("disableLoggingControls")}
    p["streams"] = []
    p["why"] = ("Client Connector logs stay on the device (an admin fetches them); its traffic reaches the SIEM through the ZIA and ZPA "
                "log streams. The settings below are what the API reports.")
    return p


def _tel_zdx() -> Dict[str, Any]:
    return _product("zdx", "ZDX", "unknown",
                    "The ZDX API has no log-streaming or log-setting read (zscaler-sdk-python 1.11.3 zdx: admin, alerts, apps, devices, "
                    "inventory, snapshot, troubleshooting, users), so what ZDX streams cannot be seen here. Nothing was read.")


def _tel_findings(products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    by = {p["key"]: p for p in products}
    zia = by.get("zia")
    if zia and zia["state"] == "read":
        streams = zia.get("streams") or []
        on = [s for s in streams if s["enabled"]]
        up_vm = [s for s in zia.get("servers") or [] if s["health"] != "down"]
        off = [s for s in streams if not s["enabled"]]
        down = [s for s in zia.get("servers") or [] if s["health"] == "down"]
        if not on and not up_vm and not zia.get("collectors"):
            if zia.get("licensed") is False:
                out.append(finding("SOC.T1", "ZIA", "ZIA: nothing streamed", "na", "Nanolog Streaming Service is not licensed on this tenant.", "", "NSS"))
            else:
                out.append(finding("SOC.T1", "ZIA", "ZIA: nothing streamed", "review",
                                   "No enabled Cloud NSS feed, no NSS server that is up and no NSS collector: ZIA logs stay in ZIA (six months) and reach no SIEM.",
                                   "Stream web, firewall, DNS and admin audit logs to your SIEM with Cloud NSS feeds (or NSS servers).", "NSS feeds, servers, collectors"))
        else:
            out.append(finding("SOC.T1", "ZIA", "ZIA: logs streamed", "pass",
                               f"{len(on)} enabled Cloud NSS feed(s), {len(up_vm)} NSS server(s) not reported down, {zia.get('collectors', 0)} NSS collector(s).",
                               "", "NSS feeds, servers, collectors"))
        if off or down:
            parts = ([f"{len(off)} disabled feed(s): {', '.join(s['name'] for s in off[:6])}"] if off else []) + \
                    ([f"{len(down)} NSS server(s) disabled or unhealthy: {', '.join(s['name'] for s in down[:6])}"] if down else [])
            out.append(finding("SOC.T2", "ZIA", "ZIA: feeds or NSS servers not running", "review", "; ".join(parts) + ".",
                               "Turn the feed back on or delete it, and bring every NSS server back to enabled and healthy; a stopped feed is a blind spot nobody sees.",
                               "NSS feeds and servers"))
        if zia.get("licensed") is not False:
            missing, vm_only = [], []
            for fam, label, types in ZIA_TYPES:
                if any(s["enabled"] and s["log_code"] in types for s in streams):
                    continue
                vm = ZIA_VM.get(fam)
                if vm and any(s["type"].upper() == vm and s["health"] == "up" for s in zia.get("servers") or []):
                    vm_only.append(label)
                else:
                    missing.append(label)
            if missing:
                out.append(finding("SOC.T3", "ZIA", "ZIA: log types not streamed", "review",
                                   f"No enabled feed streams these log types: {', '.join(missing)}.",
                                   "Add a Cloud NSS feed for each (Administration > Nanolog Streaming Service > Cloud NSS Feeds); the admin audit feed keeps "
                                   "admin changes beyond ZIA's six months.", "NSS feeds"))
            if vm_only:
                out.append(finding("SOC.T3", "ZIA", "ZIA: log types on NSS servers only", "unknown",
                                   f"{', '.join(vm_only)}: no Cloud NSS feed, but an NSS server of that type is up; the feeds an NSS server carries "
                                   "may not be listed by the API (assumed), so whether they stream is not known here.",
                                   "Check the NSS server's feeds in the ZIA admin portal.", "NSS servers"))
            if not missing and not vm_only:
                out.append(finding("SOC.T3", "ZIA", "ZIA: log types streamed", "pass", "Web, firewall, DNS and admin audit logs each have an enabled feed.", "", "NSS feeds"))
    zpa = by.get("zpa")
    if zpa and zpa["state"] == "read":
        streams = zpa.get("streams") or []
        on = [s for s in streams if s["enabled"]]
        if not on:
            out.append(finding("SOC.T1", "ZPA", "ZPA: nothing streamed", "review",
                               f"{'No' if not streams else 'No enabled'} Log Streaming Service configuration: ZPA keeps user activity for 14 days and nothing reaches a SIEM.",
                               "Add LSS configurations for User Activity, User Status, Audit logs and App Connector Status.", "LSS configurations"))
        else:
            out.append(finding("SOC.T1", "ZPA", "ZPA: logs streamed", "pass", f"{len(on)} enabled Log Streaming Service configuration(s).", "", "LSS configurations"))
        off = [s for s in streams if not s["enabled"]]
        if off:
            out.append(finding("SOC.T2", "ZPA", "ZPA: LSS configurations disabled", "review",
                               f"{len(off)} disabled: {', '.join(s['name'] for s in off[:6])}.", "Turn them back on or delete them.", "LSS configurations"))
        have = {s["log_code"] for s in on}
        missing = [LSS_NAMES[c] for c in LSS_NEEDED if c not in have]
        if missing and on:
            out.append(finding("SOC.T3", "ZPA", "ZPA: log types not streamed", "review", f"No enabled LSS configuration streams: {', '.join(missing)}.",
                               "Add an LSS configuration for each; Audit logs record admin changes, User Status sign-ins.", "LSS configurations"))
        elif on:
            out.append(finding("SOC.T3", "ZPA", "ZPA: log types streamed", "pass", "User Activity, User Status, Audit logs and App Connector Status are streamed.", "", "LSS"))
        no_tls = [s for s in on if s["tls"] is False]
        if no_tls:
            out.append(finding("SOC.T4", "ZPA", "ZPA: logs streamed without TLS", "review",
                               f"{len(no_tls)} enabled LSS configuration(s) send logs in clear text: {', '.join(s['name'] for s in no_tls[:6])}.",
                               "Turn on TLS for each LSS receiver.", "LSS configurations"))
    zcc = by.get("zcc")
    if zcc and zcc["state"] == "read":
        modes = [x for x in zcc.get("profiles") or [] if x["log_mode"] is not None]
        debug = [x["name"] for x in modes if x["log_mode"] == "debug"]
        off = [x["name"] for x in modes if x["log_mode"] == "disabled"]
        if debug or off:
            parts = ([f"debug logging on {', '.join(debug[:6])}"] if debug else []) + ([f"logging off on {', '.join(off[:6])}"] if off else [])
            out.append(finding("SOC.T5", "Client Connector", "Client Connector: device log level", "review", "App profiles with " + "; ".join(parts) + ".",
                               "Use the info level in production: debug logs fill disks and hold more personal data; with logging off there is nothing to troubleshoot with.",
                               "app profiles (logMode)"))
        elif modes:
            out.append(finding("SOC.T5", "Client Connector", "Client Connector: device log level", "pass", f"{len(modes)} app profile(s) log at the info level.", "", "app profiles"))
        if len(modes) < len(zcc.get("profiles") or []):
            out.append(finding("SOC.T5", "Client Connector", "Client Connector: device log level not reported", "unknown",
                               f"{len(zcc.get('profiles') or []) - len(modes)} app profile(s) report no log mode.", "", "app profiles"))
        out.append(finding("SOC.T1", "Client Connector", "Client Connector: no log stream of its own", "unknown",
                           "Client Connector has no log stream: device logs stay on the device and its traffic is in the ZIA and ZPA logs.", "", "Client Connector"))
    zdx = by.get("zdx")
    if zdx and zdx["state"] == "unknown":
        out.append(finding("SOC.T1", "ZDX", "ZDX: streaming not readable", "unknown", zdx["why"], "Check ZDX data export in the ZDX admin portal.", "ZDX"))
    return out


def _destinations(products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    import siem_queries
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for p in products:
        for s in p.get("streams") or []:
            dest = s.get("destination") or ""
            key = (dest or f"(not reported) {p['name']}", s.get("kind") or "")
            d = seen.setdefault(key, {"destination": key[0], "kind": key[1], "siem": s.get("siem") or "", "products": [], "log_types": [],
                                      "enabled_streams": 0, "queries": siem_queries.SIEMS.get(s.get("siem_queries") or "", "")})
            if p["name"] not in d["products"]:
                d["products"].append(p["name"])
            if s.get("log_type") and s["log_type"] not in d["log_types"]:
                d["log_types"].append(s["log_type"])
            d["enabled_streams"] += 1 if s.get("enabled") else 0
    return list(seen.values())[:MAX_ROWS]


def telemetry_review(cl: Any, scopes: Iterable[str], log: Optional[Callable[[str], None]] = None,
                     cancel: Optional[threading.Event] = None, creds: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The telemetry review of the services in scope. Read-only; Stop raises Stopped."""
    import zscaler_full_checks as full
    sc = [str(s) for s in scopes or []]
    say = log or (lambda _t: None)
    allowed = ({"zia"} if "zia_extras" in sc else set()) | ({"zpa"} if "zpa" in sc else set()) | ({"zcc"} if "zcc" in sc else set())
    g = Guard(cl, allowed, cancel)
    products: List[Dict[str, Any]] = []
    for key, name, scope in TELEMETRY_PRODUCTS:
        if scope not in sc:
            products.append(_product(key, name, *state_for(0)))
            continue
        say(f"Reading what {name} streams and logs.")
        products.append({"zia": _tel_zia, "zpa": _tel_zpa, "zcc": _tel_zcc}[key](g) if key != "zdx" else _tel_zdx())
    say("Running the log streaming checks on what was read.")
    want = (["USR.5", "GOV.7", "GOV.8"] if "zia_extras" in sc else []) + (["ZPA.14"] if "zpa" in sc else [])
    checks = run_checks(g, [c for c in full.PLATFORM_REG if c[0] in want], creds)
    findings = _tel_findings(products)
    allc = counts(findings)
    nothing = [p["name"] for p in products if p["state"] == "read" and p["key"] in ("zia", "zpa") and not any(s["enabled"] for s in p.get("streams") or [])
               and not (p["key"] == "zia" and (any(s["health"] != "down" for s in p.get("servers") or []) or p.get("collectors")))]
    lines = []
    for p in products:
        if p["state"] == "read" and p["key"] in ("zia", "zpa"):
            st = p.get("streams") or []
            lines.append(f"{p['name']}: {sum(1 for s in st if s['enabled'])} of {len(st)} stream(s) enabled"
                         + (f", {len(p.get('servers') or [])} NSS server(s)" if p["key"] == "zia" else "") + ".")
        elif p["state"] == "read":
            lines.append(f"{p['name']}: log settings only (no log stream of its own).")
        else:
            lines.append(f"{p['name']}: {p['why'] or p['state']}.")
    say(f"Done: {allc['fail']} to fix, {allc['review']} to review, {allc['unknown']} unknown.")
    return {"kind": KIND_TELEMETRY, "status": "done", "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scopes": sc,
            "products": products, "destinations": _destinations(products), "nothing_streamed": nothing,
            "findings": findings, "checks": checks, "counts": allc, "check_counts": counts(checks), "summary": lines,
            "refused_reads": len(g.refused), "reads": g.reads,
            "assumptions": [
                "A Cloud NSS feed with no log type is a web feed, as the assessment's NSS checks read it.",
                "Firewall NSS servers carry the DNS feed too; the feeds an NSS server carries may not be listed by the feed API.",
                "Cloud NSS SIEM types are spelled SPLUNK, AZURE_SENTINEL (or SENTINEL) and ELASTIC when matched to a query language.",
                "Client Connector log mode: -1 disabled, 0 info, 3 debug (the SDK's own example); other values are shown as a level.",
            ]}


# ── scope ────────────────────────────────────────────────────────────
def telemetry_in_scope(scopes: Iterable[str]) -> List[str]:
    """The telemetry products the ticked scopes allow."""
    sc = set(str(s) for s in scopes or [])
    return [name for _k, name, s in TELEMETRY_PRODUCTS if s in sc]


# ── for an assistant: people counted, never named ───────────────────
def for_assistant(rep: Dict[str, Any]) -> Dict[str, Any]:
    """The review as the MCP tools answer it: every admin is "admin n" of
    their product (role, rights, state kept), API clients and feeds keep
    their names (configuration, not people)."""
    import copy
    out = copy.deepcopy({k: v for k, v in rep.items() if k not in ("refused_reads", "reads")})
    for p in out.get("products") or []:
        for i, a in enumerate(p.get("admins") or [], 1):
            a["name"] = f"{p['name']} admin {i}"
    out["people_note"] = "Admins are numbered per product, never named; roles, rights and states are kept."
    return out
