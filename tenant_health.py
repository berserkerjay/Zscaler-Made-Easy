"""Tenant health: the signals that break a tenant quietly, read only.

* ZIA activation: changes saved in ZIA but not activated (they are not
  live, and the next activation by anyone, this app's deploys included,
  makes all of them live at once).
* SSL inspection rule order: a broad Do Not Inspect rule above Inspect
  rules (they never decrypt), a broad Inspect rule above the exemptions
  (they never apply), and nothing to inspect what reaches the Default rule.
* Certificate expiry: ZIA's SSL inspection intermediate CA certificates
  (Zscaler's and custom ones), ZPA's enrollment certificates (the
  connectors and service edges enrolled with each are counted), ZPA's web
  server certificates and the ZPA client signing certificate, with a
  warning and a critical threshold (30 and 7 days by default;
  DLP_CHECK_CERT_WARN_DAYS / DLP_CHECK_CERT_CRIT_DAYS, or per request).
* ZPA App Connector groups with no connector in them.

Every read is only for what the Scope page ticks (user rule 1): ZIA
activation for any ZIA scope (DLP, ZIA platform, Gen AI, Automation,
RBAC), the SSL rules and ZIA certificates for DLP or ZIA platform (both
read SSL inspection), the ZPA reads for ZPA with a customer ID. Nothing is
written. Only names, dates, counts and states are kept: never a
certificate, key, CSR or any other field of the objects read.

Verified against zscaler-sdk-python 1.11.3:
  zia.activate.status()                     GET /zia/api/v1/status, {status}
  zia.ssl_inspection_rules.list_rules()     GET /zia/api/v1/sslInspectionRules
  zia.intermediate_certificates.list_ca_certificates()
                                            GET /zia/api/v1/intermediateCaCertificate
                                            (name, type, status, defaultCertificate,
                                            certStartDate, certExpDate)
  zpa.enrollment_certificates.list_enrolment()
                                            GET /zpa/mgmtconfig/v2/admin/customers/{id}/enrollmentCert
                                            (name, validFromInEpochSec, validToInEpochSec)
  zpa.certificates.list_certificates()      GET .../v1/.../certificate (name, validToInEpochSec)
  zpa.client_settings.get_client_settings() GET .../v1/.../clientSetting (singningCertExpiryInEpochSec,
                                            the SDK's spelling)
  zpa.app_connector_groups.list_connector_groups()
                                            GET .../v1/.../appConnectorGroup (name, connectors,
                                            enrollmentCertId)
  zpa.app_connectors.list_connectors()      GET .../v1/.../connector (enrollmentCert)
  zpa.service_edges.list_service_edges()    GET .../v1/.../serviceEdge (enrollmentCert.name)
Assumed (not stated by the SDK): the activation status words (ACTIVE,
PENDING, INPROGRESS: the SDK keeps the field as free text), the unit of
certExpDate (epoch seconds; a value in milliseconds is recognised by its
size) and an App Connector's enrollmentCert shape (an object with a name,
or the name itself).
"""
from __future__ import annotations

import math
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

WARN_DAYS = 30
CRIT_DAYS = 7
MAX_DAYS = 365
DAY = 86400.0
MAX_ROWS = 500                 # certificates, rules, groups read per list (more are counted, not listed)
NAME_MAX = 120

ZIA_SCOPES = ("dlp", "zia_extras", "genai", "automation", "rbac")
SSL_SCOPES = ("dlp", "zia_extras")

STATES = ("ok", "warning", "critical", "expired", "unknown")
STATUS_WORDS = {"ok": "Healthy", "warning": "Needs attention soon", "critical": "Needs attention now", "unknown": "Could not be checked",
                "not_in_scope": "Not in scope"}

# ── Thresholds ────────────────────────────────────────────────────────


def _days(v: Any, name: str) -> int:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number of days.")
    if not 1 <= n <= MAX_DAYS:
        raise ValueError(f"{name} must be between 1 and {MAX_DAYS} days.")
    return n


def thresholds(warn: Any = None, crit: Any = None) -> Tuple[int, int]:
    """(warning days, critical days): the request's values, else the
    settings, else 30 and 7. A bad request value is a ValueError; a bad
    setting falls back to the default. Critical must be below warning."""
    def setting(env: str, default: int) -> int:
        try:
            return _days(os.environ.get(env, default), env)
        except ValueError:
            return default
    w = _days(warn, "The warning threshold") if warn not in (None, "") else setting("DLP_CHECK_CERT_WARN_DAYS", WARN_DAYS)
    c = _days(crit, "The critical threshold") if crit not in (None, "") else setting("DLP_CHECK_CERT_CRIT_DAYS", CRIT_DAYS)
    if c >= w:
        if warn in (None, "") and crit in (None, ""):
            return WARN_DAYS, CRIT_DAYS
        raise ValueError("The critical threshold must be fewer days than the warning threshold.")
    return w, c


# ── Dates ─────────────────────────────────────────────────────────────


def parse_time(v: Any) -> Optional[float]:
    """An expiry as epoch seconds: a number in seconds or milliseconds (a
    value past the year 5000 in seconds is taken as milliseconds), a
    numeric string, or an ISO 8601 date. None when missing or unreadable."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, str):
        s = v.strip()[:40]
        if not s:
            return None
        if re.fullmatch(r"-?\d{1,16}(\.\d+)?", s):
            v = float(s)
        else:
            try:
                d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.timestamp()
    if isinstance(v, (int, float)):
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")) or f <= 0:
            return None
        if f > 95_617_584_000:      # past 5000-01-01 in seconds: milliseconds
            f /= 1000.0
        return f if f < 95_617_584_000 else None
    return None


def expiry(end: Optional[float], now: float, warn_days: int = WARN_DAYS, crit_days: int = CRIT_DAYS) -> Dict[str, Any]:
    """{state, days_left, ends_on} for an expiry moment. Expired at or
    before now; critical within crit_days (inclusive); warning within
    warn_days (inclusive); ok after; unknown without a date."""
    if end is None:
        return {"state": "unknown", "days_left": None, "ends_on": None}
    left = end - now
    days = math.floor(left / DAY)
    ends_on = datetime.fromtimestamp(end, timezone.utc).strftime("%Y-%m-%d")
    if left <= 0:
        state = "expired"
    elif left <= crit_days * DAY:
        state = "critical"
    elif left <= warn_days * DAY:
        state = "warning"
    else:
        state = "ok"
    return {"state": state, "days_left": days, "ends_on": ends_on}


def _name(v: Any) -> str:
    s = re.sub(r"[\x00-\x1f\x7f‪-‮⁦-⁩]", " ", str(v if v is not None else "")).strip()
    return (s[:NAME_MAX - 1] + "…") if len(s) > NAME_MAX else s


def _f(obj: Any, *keys: str) -> Any:
    if not isinstance(obj, dict):
        return None
    for k in keys:
        if obj.get(k) is not None:
            return obj[k]
    return None


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _rows(body: Any) -> List[Dict[str, Any]]:
    if isinstance(body, dict):
        for k in ("list", "items", "records", "content"):
            if isinstance(body.get(k), list):
                body = body[k]
                break
    return [x for x in body if isinstance(x, dict)] if isinstance(body, list) else []


# ── ZIA activation ────────────────────────────────────────────────────

ACTIVATION_STEPS = [
    "Sign in to the ZIA Admin Portal.",
    "Open Activation (the icon in the left-hand menu shows how many changes wait) and review the pending changes; "
    "the audit log (Administration > Audit Logs) names who made each one.",
    "When the changes are wanted, click Activate. When they are not, ask the admin who made them to finish or undo them first.",
    "Then click Check again here.",
]
ACTIVATION_DEPLOY_NOTE = ("A deploy, a removal or a bulk change from this app ends with an activation, and an activation makes every "
                          "pending change live, someone else's too. Activate or undo these first.")


def activation(body: Any) -> Dict[str, Any]:
    """{state: active | pending | in_progress | unknown, status}: ZIA's
    activation status (GET /status). The words are assumed: ACTIVE,
    PENDING, INPROGRESS."""
    raw = body.get("status") if isinstance(body, dict) else getattr(body, "status", None)
    st = re.sub(r"[^A-Z_]", "", str(raw or "").upper())[:24]
    state = {"ACTIVE": "active", "PENDING": "pending", "INPROGRESS": "in_progress", "IN_PROGRESS": "in_progress"}.get(st, "unknown")
    return {"state": state, "status": st or None}


# ── SSL inspection rule order ─────────────────────────────────────────

_SSL_INSPECT = {"DECRYPT", "INSPECT", "SSL_INSPECT"}
_SSL_DNI = {"DO_NOT_DECRYPT", "DO_NOT_INSPECT", "SSL_DO_NOT_INSPECT", "EXEMPT"}
# The criteria that scope an SSL Inspection rule (zscaler-sdk-python
# zia/models/ssl_inspection_rules.py, as dlp_assessment_full_auto reads them).
_SSL_SCOPE = ("urlCategories", "cloudApplications", "users", "groups", "departments", "locations", "locationGroups", "devices",
              "deviceGroups", "platforms", "sourceIpGroups", "destIpGroups", "userAgentTypes", "deviceTrustLevels", "workloadGroups",
              "zpaAppSegments", "proxyGateways", "urls",
              "url_categories", "cloud_applications", "location_groups", "device_groups", "source_ip_groups", "dest_ip_groups",
              "user_agent_types", "device_trust_levels", "workload_groups", "zpa_app_segments", "proxy_gateways")
_ANY = {"ANY", "ALL", "NONE", ""}


def _action(r: Dict[str, Any]) -> str:
    a = r.get("action")
    if isinstance(a, dict):
        a = a.get("type") or a.get("name") or ""
    return str(a or "").upper()


def _enabled(r: Dict[str, Any]) -> bool:
    return str(r.get("state") or "ENABLED").upper() != "DISABLED"


def _scoped(r: Dict[str, Any]) -> bool:
    for k in _SSL_SCOPE:
        v = r.get(k)
        if isinstance(v, (list, tuple, set)):
            if any(str(x.get("id") if isinstance(x, dict) else x).upper() not in _ANY for x in v):
                return True
        elif isinstance(v, dict) and v:
            return True
        elif isinstance(v, str) and v.strip().upper() not in _ANY:
            return True
    return False


def _order(r: Dict[str, Any]) -> int:
    try:
        return int(r.get("order"))
    except (TypeError, ValueError):
        return 0


def _builtin(r: Dict[str, Any]) -> bool:
    return _truthy(_f(r, "predefined")) or _is_default(r)


def _is_default(r: Dict[str, Any]) -> bool:
    return _truthy(_f(r, "defaultRule", "default_rule")) or str(r.get("name") or "").strip().lower() in ("default ssl inspection rule",)


def _is_recommended(r: Dict[str, Any]) -> bool:
    n = str(r.get("name") or "").lower()
    return "recommend" in n and "exempt" in n


SSL_STEPS_BASE = ["Sign in to the ZIA Admin Portal and go to Policy > SSL/TLS Inspection (Policy > SSL Inspection on older portals)."]
SSL_STEPS_END = ["Save, then activate the change (Activation in the left-hand menu).", "Then click Check again here."]


def ssl_order(rules: Any) -> Dict[str, Any]:
    """Problems in the SSL Inspection rule order, each with the rules it
    names and plain steps. ZIA evaluates rules in ascending order and the
    first match decides; the Default rule is evaluated last whatever its
    order. {state: ok | attention | unknown, problems: [...], checked}."""
    rows = _rows(rules)
    if not isinstance(rules, (list, dict)):
        return {"state": "unknown", "problems": [], "checked": 0}
    live = sorted([r for r in rows if _enabled(r) and not _is_default(r)], key=_order)
    default = next((r for r in rows if _is_default(r)), None)
    problems: List[Dict[str, Any]] = []

    # 1. A broad (no criteria) custom Do Not Inspect rule above Inspect rules: they never decrypt.
    for i, r in enumerate(live):
        if _action(r) in _SSL_DNI and not _builtin(r) and not _scoped(r):
            below = [x for x in live[i + 1:] if _action(x) in _SSL_INSPECT]
            if below:
                names = [_name(x.get("name")) for x in below[:5]]
                problems.append({
                    "kind": "dni_above_inspect", "severity": "critical", "rule": _name(r.get("name")), "order": _order(r),
                    "affected": names, "affected_count": len(below),
                    "why": (f"'{_name(r.get('name'))}' (order {_order(r)}) does not inspect any traffic and has no criteria, so it matches "
                            f"everything first: the {len(below)} Inspect rule(s) below it ({', '.join(names)}) never decrypt anything."),
                    "steps": SSL_STEPS_BASE + [
                        f"Either give '{_name(r.get('name'))}' the criteria it is meant for (the URL categories, apps or locations to exempt), "
                        f"or drag it below '{names[-1]}'; a Do Not Inspect rule with no criteria is the same as turning inspection off."]
                    + SSL_STEPS_END})
            break

    # 2. A broad Inspect rule above Do Not Inspect exemptions: they never apply (pinned apps break).
    for i, r in enumerate(live):
        if _action(r) in _SSL_INSPECT and not _builtin(r) and not _scoped(r):
            ex = [x for x in live[i + 1:] if _action(x) in _SSL_DNI]
            if ex:
                rec = [x for x in ex if _is_recommended(x)]
                names = [_name(x.get("name")) for x in (rec + [x for x in ex if x not in rec])[:5]]
                problems.append({
                    "kind": "inspect_above_exemptions", "severity": "critical" if rec else "warning", "rule": _name(r.get("name")),
                    "order": _order(r), "affected": names, "affected_count": len(ex),
                    "why": (f"'{_name(r.get('name'))}' (order {_order(r)}) inspects everything and sits above {len(ex)} Do Not Inspect "
                            f"exemption(s) ({', '.join(names)}), so they never apply"
                            + ("; that includes Zscaler Recommended Exemptions, so apps that pin their certificates break." if rec else ".")),
                    "steps": SSL_STEPS_BASE + [
                        f"Drag '{_name(r.get('name'))}' to just above the Default rule, below every exemption; an Inspect-all rule "
                        "belongs at the bottom of the custom rules."] + SSL_STEPS_END})
            break

    # 3. Nothing inspects what reaches the Default rule, and the Default rule does not inspect.
    catch_all = [r for r in live if _action(r) in _SSL_INSPECT and not _builtin(r) and not _scoped(r)]
    default_inspects = default is not None and _enabled(default) and _action(default) in _SSL_INSPECT
    if not catch_all and not default_inspects and rows:
        problems.append({
            "kind": "default_decides", "severity": "warning", "rule": _name(default.get("name")) if default else "the Default rule",
            "order": _order(default) if default else None, "affected": [], "affected_count": 0,
            "why": ("No rule inspects everything that is not exempted, and the Default rule does not inspect: traffic no rule names "
                    "(new users, apps and categories) reaches the Default rule and is not inspected."),
            "steps": SSL_STEPS_BASE + [
                "Add a rule named, for example, 'Inspect everything else' with the action Inspect and no criteria.",
                "Place it last among your rules, just above the Default rule, so every exemption above it still applies."] + SSL_STEPS_END})
    sev = {"critical": 2, "warning": 1}
    worst = max((sev.get(p["severity"], 0) for p in problems), default=0)
    return {"state": "attention" if problems else "ok", "severity": {2: "critical", 1: "warning", 0: "ok"}[worst],
            "problems": problems, "checked": len(rows)}


# ── Certificates ──────────────────────────────────────────────────────


def zia_certificates(rows: Any, now: float, warn: int = WARN_DAYS, crit: int = CRIT_DAYS) -> List[Dict[str, Any]]:
    """ZIA's SSL inspection intermediate CA certificates: name, type,
    whether it is the default, and its expiry (certExpDate)."""
    out = []
    for r in _rows(rows)[:MAX_ROWS]:
        e = expiry(parse_time(_f(r, "certExpDate", "cert_exp_date")), now, warn, crit)
        out.append(dict(e, name=_name(_f(r, "name")) or "(no name)", type=_name(_f(r, "type"))[:40] or None,
                        default=_truthy(_f(r, "defaultCertificate", "default_certificate")),
                        status=_name(_f(r, "status", "currentState", "current_state"))[:40] or None))
    return _sorted(out)


def zpa_certificates(rows: Any, now: float, warn: int = WARN_DAYS, crit: int = CRIT_DAYS) -> List[Dict[str, Any]]:
    """ZPA enrollment or web server certificates: id, name and expiry (validToInEpochSec)."""
    out = []
    for r in _rows(rows)[:MAX_ROWS]:
        e = expiry(parse_time(_f(r, "validToInEpochSec", "valid_to_in_epoch_sec", "valid_to")), now, warn, crit)
        cid = _f(r, "id")
        out.append(dict(e, id=str(cid)[:40] if isinstance(cid, (str, int)) and not isinstance(cid, bool) else None,
                        name=_name(_f(r, "name")) or "(no name)"))
    return _sorted(out)


_RANK = {"expired": 0, "critical": 1, "warning": 2, "unknown": 3, "ok": 4}


def _sorted(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(rows, key=lambda c: (_RANK.get(c["state"], 5), c["days_left"] if c["days_left"] is not None else 10 ** 9, c["name"].lower()))


def _cert_ref(obj: Any) -> str:
    """The enrollment certificate a connector or service edge names (an
    object with a name, the SDK's service edge shape, or the name itself: assumed)."""
    v = obj.get("enrollmentCert", obj.get("enrollment_cert")) if isinstance(obj, dict) else None
    if isinstance(v, dict):
        v = v.get("name")
    return _name(v) if isinstance(v, (str, int)) and not isinstance(v, bool) else ""


def enrolled_counts(connectors: Any, edges: Any, groups: Any, certs: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Per enrollment certificate name: the App Connectors and Private
    Service Edges enrolled with it (by their enrollmentCert, else their
    group's enrollmentCertId)."""
    by_id = {c["id"]: c["name"] for c in certs if c.get("id")}
    group_cert = {}
    for g in _rows(groups):
        cid = _f(g, "enrollmentCertId", "enrollment_cert_id")
        if cid is not None and str(cid) in by_id:
            for x in _f(g, "connectors") or []:
                if isinstance(x, dict) and _f(x, "id") is not None:
                    group_cert[str(_f(x, "id"))] = by_id[str(cid)]
    out: Dict[str, Dict[str, int]] = {}
    for kind, rows in (("connectors", connectors), ("service_edges", edges)):
        for x in _rows(rows):
            name = _cert_ref(x) or group_cert.get(str(_f(x, "id")), "")
            if name:
                out.setdefault(name, {"connectors": 0, "service_edges": 0})[kind] += 1
    return out


def empty_groups(groups: Any) -> List[str]:
    """App Connector groups with no connector (a segment served only by
    them is unreachable)."""
    out = []
    for g in _rows(groups)[:MAX_ROWS]:
        c = _f(g, "connectors")
        if isinstance(c, list) and not [x for x in c if isinstance(x, dict)]:
            out.append(_name(_f(g, "name")) or "(no name)")
    return sorted(out, key=str.lower)


# ── Reading the tenant (SDK, read only, only what is in scope) ────────


def _ask(fn: Callable[[], Any]) -> Dict[str, Any]:
    """One SDK read: {state: ok | denied | missing | error, code, body}. No
    error text is kept (it may echo a request)."""
    import readiness
    return readiness._ask(fn)


def _stop(cancel: Any) -> None:
    import readiness
    readiness._stop(cancel)


def in_scope(scopes: Iterable[str]) -> Dict[str, bool]:
    sc = {str(s) for s in scopes or []}
    return {"zia": bool(sc & set(ZIA_SCOPES)), "ssl": bool(sc & set(SSL_SCOPES)), "zpa": "zpa" in sc}


def read(client: Any, scopes: Iterable[str], *, customer_id: str = "", auth_method: str = "oneapi",
         log: Optional[Callable[[str], None]] = None, cancel: Any = None) -> Dict[str, Any]:
    """Every tenant-health read for what is in scope, one at a time. The
    bodies are reduced by evaluate(); nothing else is kept."""
    say = log or (lambda m: None)
    want = in_scope(scopes)
    legacy = str(auth_method or "").lower() == "legacy"
    facts: Dict[str, Any] = {"in_scope": want, "auth_method": "legacy" if legacy else "oneapi",
                             "customer_id_given": bool(str(customer_id or "").strip())}

    def get(key: str, what: str, fn: Callable[[], Any]) -> None:
        _stop(cancel)
        say(f"Reading {what}…")
        facts[key] = _ask(fn)

    if want["zia"]:
        get("activation", "ZIA's activation status", lambda: client.zia.activate.status())
    if want["ssl"]:
        get("ssl_rules", "the SSL inspection rules", lambda: client.zia.ssl_inspection_rules.list_rules())
        get("zia_certs", "the SSL inspection certificates", lambda: client.zia.intermediate_certificates.list_ca_certificates())
    if want["zpa"] and not legacy and facts["customer_id_given"]:
        get("zpa_enroll", "the ZPA enrollment certificates", lambda: client.zpa.enrollment_certificates.list_enrolment())
        get("zpa_web", "the ZPA web server certificates", lambda: client.zpa.certificates.list_certificates())
        get("zpa_client", "the ZPA client settings", lambda: client.zpa.client_settings.get_client_settings())
        get("zpa_groups", "the App Connector groups", lambda: client.zpa.app_connector_groups.list_connector_groups())
        get("zpa_connectors", "the App Connectors", lambda: client.zpa.app_connectors.list_connectors())
        get("zpa_edges", "the Private Service Edges", lambda: client.zpa.service_edges.list_service_edges())
    _stop(cancel)
    return facts


def _state_words(r: Optional[Dict[str, Any]]) -> str:
    import readiness
    return readiness._state_words(r or {})


def _ok(r: Optional[Dict[str, Any]]) -> bool:
    return isinstance(r, dict) and r.get("state") == "ok"


def _cert_item(key: str, product: str, label: str, certs: List[Dict[str, Any]], warn: int, crit: int, steps: List[str],
               extra: Optional[Dict[str, Dict[str, int]]] = None) -> Dict[str, Any]:
    bad = [c for c in certs if c["state"] in ("expired", "critical")]
    soon = [c for c in certs if c["state"] == "warning"]
    undated = [c for c in certs if c["state"] == "unknown"]
    for c in certs:
        if extra and c["name"] in extra:
            c.update(extra[c["name"]])
    if not certs:
        return {"key": key, "product": product, "label": label, "status": "ok", "summary": "None in the tenant.", "rows": [], "steps": []}

    def say(c: Dict[str, Any]) -> str:
        users = ""
        if c.get("connectors") or c.get("service_edges"):
            users = f" ({c.get('connectors', 0)} connector(s), {c.get('service_edges', 0)} service edge(s) enrolled with it)"
        if c["state"] == "expired":
            return f"'{c['name']}' expired on {c['ends_on']}{users}"
        return f"'{c['name']}' expires on {c['ends_on']}, in {c['days_left']} day(s){users}"
    if bad:
        status, summary = "critical", "; ".join(say(c) for c in bad[:4]) + "."
    elif soon:
        status, summary = "warning", "; ".join(say(c) for c in soon[:4]) + "."
    else:
        status = "ok"
        summary = f"{len(certs)} certificate(s), none expiring within {warn} days."
    if undated:
        summary += f" {len(undated)} certificate(s) show no expiry date, so they could not be judged."
    return {"key": key, "product": product, "label": label, "status": status, "summary": summary, "rows": certs,
            "steps": steps if status != "ok" else [], "thresholds": {"warning_days": warn, "critical_days": crit}}


ZIA_CERT_STEPS = ["Sign in to the ZIA Admin Portal and go to Administration > Intermediate Root Certificates (under Certificate Management).",
                  "For a custom certificate: create a new intermediate CA certificate (generate the key pair and CSR, have your PKI "
                  "sign it, upload it), make it the default or pick it in your SSL Inspection rules, then push its root to devices.",
                  "Zscaler's own intermediate certificate is renewed by Zscaler; if it shows as expiring, open a ticket with Zscaler Support.",
                  "Activate the change, then click Check again here."]
ZPA_ENROLL_STEPS = ["Sign in to the ZPA Admin Portal and go to Administration > Certificate Management > Enrollment Certificates.",
                    "Create a new enrollment certificate (or ask Zscaler Support to renew Zscaler's own), then point the App Connector "
                    "and Service Edge provisioning keys at it.",
                    "Re-enroll the connectors and service edges with a new provisioning key before the old certificate expires: a "
                    "connector whose certificate expired can no longer connect.",
                    "Then click Check again here."]
ZPA_WEB_STEPS = ["Sign in to the ZPA Admin Portal and go to Administration > Certificate Management > Web Server Certificates "
                 "(Browser Access certificates).",
                 "Upload the renewed certificate and its key, and pick it on every Browser Access, AppProtection, Isolation or PRA "
                 "application that used the old one.",
                 "Then click Check again here."]
ZPA_CLIENT_STEPS = ["Sign in to the ZPA Admin Portal and go to Administration > Client Settings (Client Connector signing certificate).",
                    "Renew the signing certificate, or ask Zscaler Support to, before it expires.",
                    "Then click Check again here."]
ZPA_EMPTY_STEPS = ["Sign in to the ZPA Admin Portal and go to Configuration & Control > Private Infrastructure > App Connectors.",
                   "For each group listed: enroll at least two App Connectors into it (N+1), or move its server groups to a group that has "
                   "connectors, or delete the group if nothing uses it.",
                   "Then click Check again here."]


def evaluate(facts: Dict[str, Any], *, now: Optional[float] = None, warn: int = WARN_DAYS, crit: int = CRIT_DAYS) -> Dict[str, Any]:
    """The tenant-health answer: one item per signal with its status (ok,
    warning, critical, unknown, not_in_scope), a plain summary and the steps."""
    now = time.time() if now is None else now
    want = facts.get("in_scope") or {}
    items: List[Dict[str, Any]] = []

    def unread(key: str, product: str, label: str, r: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {"key": key, "product": product, "label": label, "status": "unknown", "rows": [], "steps": [],
                "summary": f"Could not be read: {_state_words(r)}."}

    def out_of_scope(key: str, product: str, label: str, why: str) -> Dict[str, Any]:
        return {"key": key, "product": product, "label": label, "status": "not_in_scope", "summary": why, "rows": [], "steps": []}

    # ZIA activation
    label = "ZIA changes waiting for activation"
    if not want.get("zia"):
        items.append(out_of_scope("zia_activation", "ZIA", label, "No ZIA scope is ticked on the Scope page, so ZIA was not read."))
    elif not _ok(facts.get("activation")):
        items.append(unread("zia_activation", "ZIA", label, facts.get("activation")))
    else:
        a = activation(facts["activation"]["body"])
        if a["state"] == "active":
            items.append({"key": "zia_activation", "product": "ZIA", "label": label, "status": "ok", "rows": [], "steps": [],
                          "summary": "Every saved change is activated (ZIA reports ACTIVE).", "activation": a})
        elif a["state"] in ("pending", "in_progress"):
            items.append({"key": "zia_activation", "product": "ZIA", "label": label, "status": "warning", "rows": [], "activation": a,
                          "steps": ACTIVATION_STEPS,
                          "summary": ("Changes are saved in ZIA but not activated (ZIA reports PENDING): they are not live yet. "
                                      if a["state"] == "pending" else "ZIA is activating changes right now (INPROGRESS); check again in a minute. ")
                          + ACTIVATION_DEPLOY_NOTE})
        else:
            items.append({"key": "zia_activation", "product": "ZIA", "label": label, "status": "unknown", "rows": [], "steps": [],
                          "summary": "ZIA answered with an activation status this app does not know.", "activation": a})

    # SSL inspection rule order and certificates
    label = "SSL inspection rule order"
    if not want.get("ssl"):
        items.append(out_of_scope("ssl_rule_order", "ZIA", label, "Neither DLP nor ZIA platform is ticked on the Scope page."))
        items.append(out_of_scope("zia_certificates", "ZIA", "SSL inspection certificates", "Neither DLP nor ZIA platform is ticked on the Scope page."))
    else:
        if not _ok(facts.get("ssl_rules")):
            items.append(unread("ssl_rule_order", "ZIA", label, facts.get("ssl_rules")))
        else:
            so = ssl_order(facts["ssl_rules"]["body"])
            status = "ok" if so["state"] == "ok" else so["severity"]
            items.append({"key": "ssl_rule_order", "product": "ZIA", "label": label, "status": status, "rows": [],
                          "problems": so["problems"],
                          "steps": (SSL_STEPS_BASE + [x for p in so["problems"] for x in p["steps"] if x not in SSL_STEPS_BASE + SSL_STEPS_END]
                                    + SSL_STEPS_END) if so["problems"] else [],
                          "summary": (f"{so['checked']} rule(s) read; the order lets every Inspect rule and every exemption apply."
                                      if not so["problems"] else " ".join(p["why"] for p in so["problems"]))})
        if not _ok(facts.get("zia_certs")):
            items.append(unread("zia_certificates", "ZIA", "SSL inspection certificates", facts.get("zia_certs")))
        else:
            items.append(_cert_item("zia_certificates", "ZIA", "SSL inspection certificates (intermediate CA)",
                                    zia_certificates(facts["zia_certs"]["body"], now, warn, crit), warn, crit, ZIA_CERT_STEPS))

    # ZPA
    zkeys = (("zpa_enrollment_certificates", "ZPA enrollment certificates (connectors and service edges)"),
             ("zpa_web_certificates", "ZPA web server certificates"), ("zpa_client_certificate", "ZPA client signing certificate"),
             ("zpa_empty_groups", "App Connector groups with no connector"))
    if not want.get("zpa"):
        items += [out_of_scope(k, "ZPA", lab, "ZPA is not ticked on the Scope page, so ZPA was not read.") for k, lab in zkeys]
    elif facts.get("auth_method") == "legacy":
        items += [out_of_scope(k, "ZPA", lab, "The classic ZIA API sign-in cannot read ZPA.") for k, lab in zkeys]
    elif not facts.get("customer_id_given"):
        items += [{"key": k, "product": "ZPA", "label": lab, "status": "unknown", "rows": [], "steps": [],
                   "summary": "The ZPA customer ID is empty: every ZPA read needs it."} for k, lab in zkeys]
    else:
        enroll = zpa_certificates(facts["zpa_enroll"]["body"], now, warn, crit) if _ok(facts.get("zpa_enroll")) else None
        if enroll is None:
            items.append(unread(zkeys[0][0], "ZPA", zkeys[0][1], facts.get("zpa_enroll")))
        else:
            used = enrolled_counts(facts["zpa_connectors"]["body"] if _ok(facts.get("zpa_connectors")) else [],
                                   facts["zpa_edges"]["body"] if _ok(facts.get("zpa_edges")) else [],
                                   facts["zpa_groups"]["body"] if _ok(facts.get("zpa_groups")) else [], enroll)
            items.append(_cert_item(zkeys[0][0], "ZPA", zkeys[0][1], enroll, warn, crit, ZPA_ENROLL_STEPS, used))
        if not _ok(facts.get("zpa_web")):
            items.append(unread(zkeys[1][0], "ZPA", zkeys[1][1], facts.get("zpa_web")))
        else:
            items.append(_cert_item(zkeys[1][0], "ZPA", zkeys[1][1], zpa_certificates(facts["zpa_web"]["body"], now, warn, crit),
                                    warn, crit, ZPA_WEB_STEPS))
        if not _ok(facts.get("zpa_client")):
            items.append(unread(zkeys[2][0], "ZPA", zkeys[2][1], facts.get("zpa_client")))
        else:
            body = facts["zpa_client"]["body"]
            body = body[0] if isinstance(body, list) and body else body
            end = parse_time(_f(body, "singningCertExpiryInEpochSec", "singning_cert_expiry_in_epoch_sec", "signingCertExpiryInEpochSec"))
            rows = [dict(expiry(end, now, warn, crit), name="Client Connector signing certificate", id=None)] if end is not None else []
            item = _cert_item(zkeys[2][0], "ZPA", zkeys[2][1], rows, warn, crit, ZPA_CLIENT_STEPS)
            if not rows:
                item["summary"] = "The client settings name no signing certificate expiry."
            items.append(item)
        if not _ok(facts.get("zpa_groups")):
            items.append(unread(zkeys[3][0], "ZPA", zkeys[3][1], facts.get("zpa_groups")))
        else:
            empty = empty_groups(facts["zpa_groups"]["body"])
            n = len(_rows(facts["zpa_groups"]["body"]))
            items.append({"key": zkeys[3][0], "product": "ZPA", "label": zkeys[3][1], "status": "warning" if empty else "ok",
                          "rows": [{"name": g} for g in empty[:50]], "steps": ZPA_EMPTY_STEPS if empty else [],
                          "summary": (f"{len(empty)} of {n} group(s) have no App Connector: {', '.join(empty[:5])}"
                                      f"{' and more' if len(empty) > 5 else ''}. An application served only by them cannot be reached."
                                      if empty else f"Every one of the {n} App Connector group(s) has at least one connector.")})
    rank = {"critical": 3, "warning": 2, "unknown": 1, "ok": 0, "not_in_scope": -1}
    checked = [i for i in items if i["status"] != "not_in_scope"]
    worst = max((rank[i["status"]] for i in checked), default=-1)
    counts = {s: sum(1 for i in items if i["status"] == s) for s in ("critical", "warning", "unknown", "ok", "not_in_scope")}
    if not checked:
        summary = "Nothing was checked: tick ZIA (DLP or ZIA platform) or ZPA on the Scope page."
    elif counts["critical"] or counts["warning"]:
        summary = (f"{counts['critical']} problem(s) to fix now and {counts['warning']} to fix soon; "
                   f"{counts['ok']} healthy, {counts['unknown']} could not be checked.")
    else:
        summary = f"Healthy: {counts['ok']} signal(s) checked, {counts['unknown']} could not be checked."
    return {"items": items, "summary": summary, "counts": counts,
            "worst": {3: "critical", 2: "warning", 1: "unknown", 0: "ok", -1: "not_in_scope"}[worst],
            "thresholds": {"warning_days": warn, "critical_days": crit}}


READINESS_KEYS = ("zia_activation", "ssl_rule_order")


def readiness_checks(activation_read: Optional[Dict[str, Any]], ssl_read: Optional[Dict[str, Any]], *, zia: bool, ssl: bool) -> List[Dict[str, Any]]:
    """The two tenant checks the readiness answer carries (ZIA pending
    activation, SSL rule order), from readiness' own reads, as readiness
    items: status ok | attention | unknown | not_in_scope, with why and steps."""
    facts = {"in_scope": {"zia": zia, "ssl": ssl, "zpa": False}, "activation": activation_read, "ssl_rules": ssl_read}
    out = []
    for it in evaluate(facts)["items"]:
        if it["key"] not in READINESS_KEYS:
            continue
        st = {"warning": "attention", "critical": "attention"}.get(it["status"], it["status"])
        problems = it.get("problems") or []
        out.append({"key": it["key"], "label": it["label"], "product": it["product"], "kind": "check", "status": st,
                    "severity": it["status"] if st == "attention" else None, "why": problems[0]["why"] if problems else it["summary"],
                    "steps": list(it.get("steps") or []), "notes": [p["why"] for p in problems[1:]]})
    return out


def run(client: Any, scopes: Iterable[str], *, customer_id: str = "", auth_method: str = "oneapi", warn: int = WARN_DAYS,
        crit: int = CRIT_DAYS, log: Optional[Callable[[str], None]] = None, cancel: Any = None, label: str = "",
        now: Optional[float] = None) -> Dict[str, Any]:
    """The tenant-health job: the reads, then the verdict. Stop ends it
    with no partial result."""
    import readiness
    say = log or (lambda m: None)
    try:
        facts = read(client, scopes, customer_id=customer_id, auth_method=auth_method, log=say, cancel=cancel)
    except readiness.Stopped:
        say("STOPPED — you clicked Stop; nothing more is read and no partial result is kept.")
        return {"status": "stopped", "tenant_label": label}
    out = evaluate(facts, now=now, warn=warn, crit=crit)
    out.update(status="done", tenant_label=label,
               checked_at=datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    say("Done: " + out["summary"])
    return out
