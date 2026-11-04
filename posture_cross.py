"""Device posture across products: where each posture check is defined,
which devices it applies to, and every ZPA and ZIA rule that uses it.

How the pieces fit (Zscaler's model):

  * Device posture checks are defined in Client Connector (the Client
    Connector portal's device posture profiles). ZPA reads them through its
    own API (`zpa.posture_profiles.list_posture_profiles`, GET
    /zpa/mgmtconfig/v2/admin/customers/{id}/posture); device_posture.py
    classifies them and links them to the ZPA access rules' POSTURE
    conditions.
  * ZIA posture profiles are also defined in Client Connector: each one
    sets, per platform, the device posture checks a device must pass to be
    rated High, Medium or Low trust. An app profile picks one
    (`ziaPostureConfigId`, verified in the SDK's zcc/models/webpolicy.py and
    application_profiles.py). Client Connector evaluates them on the device
    and sends the resulting trust level to ZIA.
  * ZIA rules use that trust level as a condition (`deviceTrustLevels`,
    verified in the SDK models of URL filtering, Cloud App Control, SSL
    inspection, Cloud Firewall and File Type Control rules; values ANY,
    UNKNOWN_DEVICETRUSTLEVEL, LOW_TRUST, MEDIUM_TRUST, HIGH_TRUST from the
    SDK docstrings).

What is read (read-only; each product only when it is ticked on the Scope
page, and a product that cannot be read is shown as such, never as an
error page):

  * ZPA: device_posture.read (zpa_reader; posture profiles, trusted
    networks, policies).
  * Client Connector: trusted networks (device_posture.read_zcc_networks),
    company info (`zcc.company.get_company_info`: zpnEnabled is ZPA,
    proxyEnabled is ZIA), the app profiles per platform
    (`zcc.web_policy.list_by_company`, device_type windows, macos, ios,
    android, linux, through ops_zcc.read_apps) and the ZIA posture profiles
    (GET /zcc/papi/public/v2/zia-posture-profiles: the SDK has no call for
    it, so it is read raw as the Terraform export reads it,
    tenant_terraform._raw_list).
  * ZIA: the rules of URL filtering (`zia.url_filtering.list_rules`), Cloud
    App Control (`zia.cloudappcontrol.list_rules(rule_type)` per rule
    type), SSL inspection (`zia.ssl_inspection_rules.list_rules`), Cloud
    Firewall (`zia.cloud_firewall_rules.list_rules`) and File Type Control
    (`zia.file_type_control_rule.list_rules`).

Assumed (not verifiable from the SDK; said on the page and in exports):
see ASSUMPTIONS.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import device_posture
import zpa_reader

# ── words ───────────────────────────────────────────────────────────────
PLATFORMS = ("windows", "macos", "linux", "ios", "android", "chromeos")
PLATFORM_LABEL = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "ios": "iOS", "android": "Android", "chromeos": "ChromeOS"}
# The Client Connector API numbers the platforms (zscaler-sdk-python utils.zcc_param_map["os"]).
ZCC_PLATFORM = {"1": "ios", "2": "android", "3": "windows", "4": "macos", "5": "linux"}
_PLATFORM_WORDS = {"win": "windows", "windows": "windows", "mac": "macos", "macos": "macos", "osx": "macos", "darwin": "macos", "linux": "linux",
                   "ios": "ios", "android": "android", "chromeos": "chromeos", "chrome_os": "chromeos"}
# The trust levels as the ZIA rules name them (SDK docstrings), strongest first.
TRUST_LEVELS = ("HIGH_TRUST", "MEDIUM_TRUST", "LOW_TRUST", "UNKNOWN_DEVICETRUSTLEVEL")
TRUST_LABEL = {"HIGH_TRUST": "High trust", "MEDIUM_TRUST": "Medium trust", "LOW_TRUST": "Low trust",
               "UNKNOWN_DEVICETRUSTLEVEL": "Unknown trust", "ANY": "Any trust level"}
WEAK_TRUST = ("LOW_TRUST", "UNKNOWN_DEVICETRUSTLEVEL")
# A ZIA posture profile's criteria per level (the zcc provider's zcc_zia_posture schema:
# high_trust_criteria / medium_trust_criteria / low_trust_criteria {cs: [{cn: [{id, name, udid}]}]}).
CRITERIA_KEYS = (("HIGH_TRUST", "highTrustCriteria"), ("MEDIUM_TRUST", "mediumTrustCriteria"), ("LOW_TRUST", "lowTrustCriteria"))
# assumed: the zcc provider 0.1.2-beta.3's path for ZIA posture profiles (no SDK call); one GET, possibly cut short.
ZIA_POSTURE_PATH = "/zcc/papi/public/v2/zia-posture-profiles"
APP_PLATFORMS = ("windows", "macos", "ios", "android", "linux")   # web_policy.list_by_company device_type values (SDK docstring)

PRODUCTS = (("zpa", "ZPA", "Access rules with a device posture condition"),
            ("zcc", "Client Connector", "Where posture checks and ZIA posture profiles are defined and which app profiles use them"),
            ("zia", "ZIA", "URL filtering, Cloud App Control, SSL inspection, Cloud Firewall and File Type Control rules that use the device trust level"))
PRODUCT_LABEL = {k: label for k, label, _ in PRODUCTS}
SCOPE_KEY = {"zpa": "zpa", "zcc": "zcc", "zia": "zia_extras"}
SCOPE_WORDS = {"zpa": "ZPA", "zcc": "ZCC / Mobile Portal", "zia": "ZIA platform"}
STATUS_WORDS = {"read": "Read", "partial": "Partly read", "not_in_scope": "Not in scope", "not_readable": "Not readable",
                "not_licensed": "Not licensed"}

# (key, label, SDK service, takes a rule type)
ZIA_SECTIONS = (("url", "URL filtering", "url_filtering", False), ("cac", "Cloud App Control", "cloudappcontrol", True),
                ("ssl", "SSL inspection", "ssl_inspection_rules", False), ("firewall", "Cloud Firewall", "cloud_firewall_rules", False),
                ("ftc", "File Type Control", "file_type_control_rule", False))
ZIA_SECTION_LABEL = {k: label for k, label, _, _ in ZIA_SECTIONS}
_LOOSE_CAC = re.compile(r"_(UPLOAD|SHARE|SEND|POST|EDIT|CREATE)$")   # the verb ends the action name (ALLOW_FILE_SHARE_UPLOAD)

ASSUMPTIONS = [
    "A ZIA posture profile's criteria name Client Connector device posture checks; a criterion's udid is assumed to be the "
    "device posture profile's posture UDID (the one ZPA reads). A criterion without a udid is matched by name and marked as "
    "inferred.",
    "Client Connector rates a device High, Medium or Low trust by the first level whose criteria it meets, using the ZIA posture "
    "profile its app profile names; a device whose app profile names none has no trust level, which ZIA rules see as "
    "UNKNOWN_DEVICETRUSTLEVEL. How the criteria groups (cs) and their checks (cn) combine is not documented in the SDK, so they "
    "are listed, not evaluated.",
    "The ZIA posture profile list (/zcc/papi/public/v2/zia-posture-profiles) can be cut short without saying so (the zscaler/zcc "
    "provider's documentation), so a profile an app profile names but the list lacks is said to be possibly missing, never "
    "certainly missing.",
    "A ZIA rule loosens policy when it allows traffic (URL filtering or Cloud Firewall Allow), skips SSL inspection (Do not "
    "inspect), allows uploads or sharing (Cloud App Control) or allows file uploads (File Type Control). Such a rule is a "
    "candidate for a device trust level condition; predefined and default rules are left out.",
    "A product that is not licensed usually answers 401 or 403 to every list. That is reported as not readable (a missing licence "
    "or an API role without access) unless Client Connector's company info says the product is off.",
]


def plat_key(v: Any) -> Optional[str]:
    """A platform as this page names it, from 3, "3", "windows", "mac", "DEVICE_TYPE_WINDOWS"."""
    s = str(v if v is not None else "").strip().lower().removeprefix("device_type_")
    m = re.fullmatch(r"(\d+)(?:\.0*)?", s)
    if m:
        return ZCC_PLATFORM.get(str(int(m.group(1))))
    return _PLATFORM_WORDS.get(s)


def plat_keys(values: Iterable[Any]) -> List[str]:
    """Every platform named by a list whose items may be comma-separated."""
    out: List[str] = []
    for v in values or []:
        for part in str(v).split(","):
            k = plat_key(part)
            if k and k not in out:
                out.append(k)
    return out


def _g(r: Any, camel: str, default: Any = None) -> Any:
    """A field from a raw (camelCase) or SDK (snake_case) dict."""
    if not isinstance(r, dict):
        return default
    for k in (camel, re.sub(r"(?<!^)(?=[A-Z])", "_", camel).lower()):
        if r.get(k) is not None:
            return r[k]
    return default


def _list(v: Any) -> List[Any]:
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _s(v: Any, n: int = 200) -> str:
    return str(v if v is not None else "").strip()[:n]


def _q(name: str) -> str:
    return "“{}”".format(name)


def _names_list(items: Iterable[str], n: int = 4) -> str:
    items = list(items)
    q = [_q(x) for x in items[:n]]
    if len(items) > n:
        return ", ".join(q) + f" and {len(items) - n} more"
    return device_posture._join(q, "and")


# assumed: an unlicensed product answers 401 or 403 (said as "not readable" unless company info says it is off).
def _denied(err: str) -> bool:
    return bool(re.search(r"\b(401|403)\b|unauthori[sz]ed|forbidden|not licensed|not entitled|not subscribed", err or "", re.I))


# ── reading ─────────────────────────────────────────────────────────────
def _stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise zpa_reader.Stopped(zpa_reader.STOPPED_REASON)


def _triple(ret: Any) -> Tuple[Any, Any, Any]:
    if isinstance(ret, tuple) and len(ret) == 3:
        return ret
    if isinstance(ret, tuple) and len(ret) == 2:
        return ret[0], None, ret[1]
    return ret, None, None


def read_company(client: Any) -> Dict[str, Any]:
    """Client Connector company info: {read, zpa, zia (True / False / None), reason}."""
    svc = getattr(getattr(client, "zcc", None), "company", None)
    fn = getattr(svc, "get_company_info", None) if svc is not None else None
    if not callable(fn):
        return {"read": False, "zpa": None, "zia": None, "reason": "This sign-in has no Client Connector company info call."}
    try:
        result, resp, err = _triple(fn())
    except Exception as e:  # noqa: BLE001 — unread company info only leaves the licences unknown
        return {"read": False, "zpa": None, "zia": None, "reason": zpa_reader._err_text(e)}
    if err:
        return {"read": False, "zpa": None, "zia": None, "reason": zpa_reader._err_text(err)}
    # The wire body first: the SDK's CompanyInfo models can come back with their flags unset.
    body = None
    getter = getattr(resp, "get_body", None)
    if callable(getter):
        try:
            body = getter()
        except Exception:  # noqa: BLE001 — fall back to the models
            body = None
    if isinstance(body, list):
        body = body[0] if body and isinstance(body[0], dict) else None
    if isinstance(body, dict) and body:
        row = body
    else:
        rows = zpa_reader.raw_items(result if isinstance(result, list) else ([result] if result else []), resp)
        row = rows[0] if rows else {}

    def flag(camel: str) -> Optional[bool]:
        v = _g(row, camel)
        if v is None or v == "":
            return None
        return str(v).strip().lower() in ("1", "true", "yes")
    return {"read": bool(row), "zpa": flag("zpnEnabled"), "zia": flag("proxyEnabled"), "reason": ""}


def read_app_profiles(client: Any, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Every app profile, once per platform (web_policy.list_by_company with
    device_type): {read, profiles, errors}."""
    import ops_zcc
    out: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen = set()
    for plat in APP_PLATFORMS:
        _stop(cancel)
        try:
            rows, err = ops_zcc.read_apps(client, plat, cancel)
        except Exception as e:  # noqa: BLE001 — a platform that cannot be read is said so
            rows, err = [], zpa_reader._err_text(e)
        if err:
            errors.append(f"{PLATFORM_LABEL.get(plat, plat)}: {zpa_reader._err_text(err)}")
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            pk = plat_key(_g(r, "deviceType") if _g(r, "deviceType") is not None else _g(r, "device_type")) or plat
            key = (pk, _s(_g(r, "id")) or _s(_g(r, "name")))
            if key in seen:
                continue
            seen.add(key)
            active = _g(r, "active")
            zp = _g(r, "ziaPostureConfigId")
            out.append({"id": _s(_g(r, "id")), "name": _s(_g(r, "name")) or f"App profile {_s(_g(r, 'id'))}", "platform": pk,
                        "active": None if active is None else str(active).strip().lower() in ("1", "true", "yes"),
                        "zia_posture_id": _s(zp) if zp not in (None, "", 0, "0") else ""})
    read = len(errors) < len(APP_PLATFORMS)
    return {"read": read, "complete": not errors, "profiles": out, "errors": errors}


def read_zia_postures(client: Any) -> Dict[str, Any]:
    """The ZIA posture profiles (raw GET, no SDK call): {read, profiles, reason}."""
    import tenant_terraform
    rows, err = tenant_terraform._raw_list(client, ZIA_POSTURE_PATH)
    if err:
        return {"read": False, "profiles": [], "reason": zpa_reader._err_text(err)}
    return {"read": True, "profiles": [normalize_zia_posture(r) for r in rows if isinstance(r, dict)], "reason": ""}


def normalize_zia_posture(raw: Dict[str, Any]) -> Dict[str, Any]:
    levels: Dict[str, List[Dict[str, str]]] = {}
    for lvl, key in CRITERIA_KEYS:
        crit = _g(raw, key) or {}
        items: List[Dict[str, str]] = []
        for group in _list(crit.get("cs") if isinstance(crit, dict) else None)[:50]:
            for c in _list(group.get("cn") if isinstance(group, dict) else None)[:100]:
                if isinstance(c, dict):
                    items.append({"id": _s(c.get("id"), 64), "name": _s(c.get("name")) or _s(c.get("id"), 64), "udid": _s(c.get("udid"), 80)})
        levels[lvl] = items
    plat = plat_key(_g(raw, "platform"))
    return {"id": _s(_g(raw, "id"), 64), "name": _s(_g(raw, "name")) or f"ZIA posture profile {_s(_g(raw, 'id'), 64)}",
            "platform": plat, "platform_label": PLATFORM_LABEL.get(plat or "", _s(_g(raw, "platform"), 20) or "unknown"), "levels": levels}


def _zia_rows(fn: Callable[..., Any], *args: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        result, resp, err = _triple(fn(*args))
    except Exception as e:  # noqa: BLE001 — one section that cannot be read is said so
        return [], zpa_reader._err_text(e)
    if err:
        return [], zpa_reader._err_text(err)
    return zpa_reader.raw_items(result, resp), None


def read_zia_rules(client: Any, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """The rules of each ZIA section that can use a device trust level:
    {sections: {key: {read, error}}, rules: [normalized]}."""
    import pack_channels
    import zia_rate
    zia = getattr(client, "zia", None)
    sections: Dict[str, Dict[str, Any]] = {}
    rules: List[Dict[str, Any]] = []
    for key, label, svc_name, typed in ZIA_SECTIONS:
        _stop(cancel)
        svc = getattr(zia, svc_name, None) if zia is not None else None
        fn = getattr(svc, "list_rules", None) if svc is not None else None
        if not callable(fn):
            sections[key] = {"label": label, "read": False, "error": "this sign-in has no ZIA API for it"}
            continue
        got: List[Dict[str, Any]] = []
        errs: List[str] = []
        for rt in (pack_channels.CLOUD_APP_TYPES if typed else (None,)):
            _stop(cancel)
            zia_rate.wait("GET", "", what=f"{label} rules")
            rows, err = _zia_rows(fn, rt) if typed else _zia_rows(fn)
            if err:
                errs.append(err)
            got.extend(rows)
        ok = not errs or (typed and len(errs) < len(pack_channels.CLOUD_APP_TYPES))
        sections[key] = {"label": label, "read": ok, "complete": not errs, "error": errs[0] if errs else None}
        if ok:
            rules.extend(normalize_zia_rule(key, r) for r in got if isinstance(r, dict))
    return {"sections": sections, "rules": rules}


def normalize_zia_rule(section: str, r: Dict[str, Any]) -> Dict[str, Any]:
    action = _g(r, "action")
    if isinstance(action, dict):
        action = action.get("type")
    actions = [str(a).upper() for a in _list(_g(r, "actions")) if isinstance(a, str)]
    ftc_action = _s(_g(r, "filteringAction"), 40).upper()
    act = (ftc_action if section == "ftc" else _s(action, 60).upper())
    levels = [str(x).upper() for x in _list(_g(r, "deviceTrustLevels")) if isinstance(x, str)]
    uses = [x for x in levels if x in TRUST_LEVELS]
    state = _s(_g(r, "state") or "ENABLED", 20).upper()
    rule = {"section": section, "section_label": ZIA_SECTION_LABEL[section], "id": _s(_g(r, "id"), 64), "name": _s(_g(r, "name")) or f"rule {_s(_g(r, 'id'), 64)}",
            "order": _g(r, "order"), "enabled": state != "DISABLED", "action": act, "actions": actions[:20],
            "rule_type": _s(_g(r, "type"), 40).upper(), "trust_levels": uses,
            "uses_trust": bool(uses), "default": bool(_g(r, "defaultRule")), "predefined": bool(_g(r, "predefined"))}
    rule["loosens"] = _loosens(section, rule, r)
    return rule


# assumed: which actions loosen policy is this page's reading of the action names (ASSUMPTIONS), not Zscaler's.
def _loosens(section: str, rule: Dict[str, Any], raw: Dict[str, Any]) -> str:
    """How the rule loosens policy, in words, or ''."""
    a = rule["action"]
    if section == "url" and a == "ALLOW":
        return "allows the URL categories it names"
    if section == "firewall" and a == "ALLOW":
        return "allows the traffic it names"
    if section == "ssl" and a in ("DO_NOT_DECRYPT", "DO_NOT_INSPECT"):
        return "skips SSL inspection"
    if section == "cac":
        loose = [x for x in rule["actions"] if x.startswith("ALLOW") and _LOOSE_CAC.search(x)]
        if loose:
            return "allows " + device_posture._join([x.removeprefix("ALLOW_").lower().replace("_", " ") for x in loose[:2]], "and")
    if section == "ftc" and a == "ALLOW" and "UPLOAD" in _s(_g(raw, "operation"), 40).upper():
        return "allows file uploads"
    return ""


def read_all(client: Any, scopes: Iterable[str], *, zpa_problem: str = "", log: Optional[Callable[[str], None]] = None,
             cancel: Optional[threading.Event] = None, pace: Optional[float] = None) -> Dict[str, Any]:
    """Every product's posture pieces that are in scope. Never raises for a
    product that cannot be read (its status says why); raises
    zpa_reader.Stopped on Stop."""
    def _log(line: str) -> None:
        if log:
            log(line)
    scopes = set(scopes or [])
    out: Dict[str, Any] = {"scopes": sorted(scopes), "zpa": None, "zpa_error": "", "zcc": None, "zia": None, "company": None}
    if "zcc" in scopes:
        _stop(cancel)
        _log("Reading Client Connector company info…")
        out["company"] = read_company(client)
    if "zpa" in scopes and not zpa_problem:
        try:
            snap, raw, _ = device_posture.read(client, log=log, cancel=cancel, zcc=False, pace=pace)
            out["zpa"] = {"snap": snap, "raw": raw}
        except zpa_reader.Stopped:
            raise
        except zpa_reader.ReadError as e:
            out["zpa_error"] = str(e)
            _log(f"ZPA could not be read: {e}")
    elif "zpa" in scopes:
        out["zpa_error"] = zpa_problem
    if "zcc" in scopes:
        _stop(cancel)
        _log("Reading Client Connector trusted networks…")
        nets = device_posture.read_zcc_networks(client, log=log, cancel=cancel, pace=zpa_reader.PACE_SECONDS if pace is None else pace)
        _stop(cancel)
        _log("Reading Client Connector ZIA posture profiles…")
        zp = read_zia_postures(client)
        _log(f"Read {len(zp['profiles'])} ZIA posture profile(s)." if zp["read"] else f"ZIA posture profiles could not be read: {zp['reason']}")
        _stop(cancel)
        _log("Reading Client Connector app profiles…")
        apps = read_app_profiles(client, cancel)
        _log(f"Read {len(apps['profiles'])} app profile(s)." if apps["read"] else "App profiles could not be read.")
        out["zcc"] = {"networks": nets, "zia_postures": zp, "apps": apps}
    if "zia_extras" in scopes:
        _stop(cancel)
        _log("Reading ZIA rules that can use the device trust level…")
        out["zia"] = read_zia_rules(client, cancel)
        n = sum(1 for r in out["zia"]["rules"] if r["uses_trust"])
        _log(f"Read {len(out['zia']['rules'])} ZIA rule(s); {n} use the device trust level.")
    return out


# ── product status ──────────────────────────────────────────────────────
def statuses(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """{zpa, zcc, zia: {key, label, what, status, words, reason}}: never an error page."""
    scopes = set(data.get("scopes") or [])
    company = data.get("company") or {}
    out: Dict[str, Dict[str, Any]] = {}

    def put(k: str, status: str, reason: str) -> None:
        label = PRODUCT_LABEL[k]
        out[k] = {"key": k, "label": label, "what": dict((x, w) for x, _, w in PRODUCTS)[k], "status": status,
                  "words": STATUS_WORDS[status], "reason": reason}

    def off(k: str, flag: str) -> Optional[str]:
        if company.get(flag) is False:
            return f"Client Connector's company info says {PRODUCT_LABEL[k]} is off for this company, so it is treated as not licensed."
        return None

    # ZPA
    if "zpa" not in scopes:
        put("zpa", "not_in_scope", f"ZPA is not ticked on the Scope page, so its access rules were not read. Tick {SCOPE_WORDS['zpa']} to add them.")
    elif data.get("zpa") is None:
        put("zpa", "not_licensed" if off("zpa", "zpa") else "not_readable", off("zpa", "zpa") or f"ZPA could not be read: {data.get('zpa_error') or 'no answer'}")
    else:
        cols = (data["zpa"]["snap"].get("collections") or {})
        errs = [c.get("error") or "" for c in cols.values() if not c.get("read")]
        if cols and len(errs) == len(cols):
            why = off("zpa", "zpa")
            put("zpa", "not_licensed" if why else "not_readable", why or (
                "ZPA refused every list (HTTP 401 or 403): ZPA may not be licensed, or the API client's role cannot read ZPA."
                if all(_denied(e) for e in errs) else f"No ZPA list could be read ({errs[0][:120] or 'no answer'})."))
        elif errs:
            put("zpa", "partial", "Some ZPA lists could not be read: " + "; ".join(
                f"{c.get('label')} ({(c.get('error') or '')[:80]})" for c in cols.values() if not c.get("read"))[:400] + ".")
        else:
            put("zpa", "read", "")
    # Client Connector
    z = data.get("zcc")
    if "zcc" not in scopes:
        put("zcc", "not_in_scope", f"Client Connector is not ticked on the Scope page, so where posture is defined and which app profiles use "
                                   f"it were not read. Tick {SCOPE_WORDS['zcc']} to add it.")
    else:
        parts = {"trusted networks": (z or {}).get("networks", {}).get("read"), "ZIA posture profiles": (z or {}).get("zia_postures", {}).get("read"),
                 "app profiles": (z or {}).get("apps", {}).get("read")}
        bad = [k for k, v in parts.items() if not v]
        if len(bad) == len(parts):
            reasons = [(z or {}).get("zia_postures", {}).get("reason") or "", "; ".join((z or {}).get("apps", {}).get("errors") or [])]
            put("zcc", "not_readable", "No Client Connector list could be read" + (
                " (HTTP 401 or 403: Client Connector may not be licensed, or the API client's role cannot read it)." if any(_denied(x) for x in reasons)
                else f" ({next((x for x in reasons if x), 'no answer')[:160]})."))
        elif bad:
            put("zcc", "partial", "Not read: " + ", ".join(bad) + ".")
        else:
            put("zcc", "read", "")
    # ZIA
    zi = data.get("zia")
    if "zia_extras" not in scopes:
        put("zia", "not_in_scope", f"ZIA platform is not ticked on the Scope page, so the ZIA rules that use the device trust level were not read. "
                                   f"Tick {SCOPE_WORDS['zia']} to add them.")
    else:
        secs = (zi or {}).get("sections") or {}
        bad = [s for s in secs.values() if not s.get("read")]
        if secs and len(bad) == len(secs):
            why = off("zia", "zia")
            put("zia", "not_licensed" if why else "not_readable", why or (
                "ZIA refused every rule list (HTTP 401 or 403): the API client's role may not cover these rules."
                if all(_denied(s.get("error") or "") for s in bad) else f"No ZIA rule list could be read ({(bad[0].get('error') or 'no answer')[:120]})."))
        elif bad:
            put("zia", "partial", "Not read: " + ", ".join(f"{s['label']} rules ({(s.get('error') or '')[:60]})" for s in bad) + ".")
        else:
            put("zia", "read", "")
    return out


# ── the cross-product view ──────────────────────────────────────────────
FINDING_TITLES = {
    "XP-01": "Platforms in use with no device posture check",
    "XP-02": "ZIA posture profiles no app profile uses",
    "XP-03": "App profiles naming a ZIA posture profile that was not found",
    "XP-04": "ZIA posture profiles naming a device posture check that does not exist",
    "XP-05": "ZIA rules that use the device trust level while some devices get none",
    "XP-06": "ZIA rules that loosen policy for low-trust or unknown-trust devices",
    "XP-07": "ZIA rules that loosen policy without a device trust level condition",
    "XP-08": "Trust levels are worked out, but no ZIA rule uses them",
}


def cross(rep: Dict[str, Any], data: Dict[str, Any], st: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """The one view across products, its gaps (XP-*) and what could not be
    assessed. `rep` is device_posture.analyze's report (ZPA)."""
    F = device_posture._finding
    findings: List[Dict[str, Any]] = []
    not_assessed: List[str] = []
    zpa_ok = st["zpa"]["status"] in ("read", "partial")
    cols = rep.get("collections") or ((data.get("zpa") or {}).get("snap") or {}).get("collections") or {}
    zpa_postures_read = zpa_ok and bool((cols.get("posture_profiles") or {}).get("read"))
    zpa_postures_complete = zpa_postures_read and bool((cols.get("posture_profiles") or {}).get("complete"))
    access_read = zpa_ok and bool((cols.get("policy:access") or {}).get("read"))
    z = data.get("zcc") or {}
    zp_read = bool((z.get("zia_postures") or {}).get("read"))
    apps_read = bool((z.get("apps") or {}).get("read"))
    apps_complete = bool((z.get("apps") or {}).get("complete"))
    zi = data.get("zia") or {}
    zia_read = st["zia"]["status"] in ("read", "partial")
    zia_complete = st["zia"]["status"] == "read"

    zpa_profiles = (rep.get("profiles") or []) if zpa_postures_read else []
    by_udid = {p["posture_udid"].lower(): p for p in zpa_profiles if p.get("posture_udid")}
    by_name = {p["name"].casefold(): p for p in zpa_profiles if p.get("name")}
    zia_postures = ((z.get("zia_postures") or {}).get("profiles") or []) if zp_read else []
    apps = ((z.get("apps") or {}).get("profiles") or []) if apps_read else []
    zrules = [r for r in (zi.get("rules") or [])] if zia_read else []
    trust_rules = [r for r in zrules if r["uses_trust"] and r["enabled"]]

    # ZIA posture profiles: criteria resolved to device posture checks, app profiles using each
    zp_by_id = {p["id"]: p for p in zia_postures if p.get("id")}
    zia_view = []
    for p in zia_postures:
        levels = {}
        for lvl, items in p["levels"].items():
            rows = []
            for c in items:
                hit, how = None, ""
                # assumed: a criterion's udid is the device posture profile's postureUdid; by name it is only inferred.
                if c.get("udid") and c["udid"].lower() in by_udid:
                    hit, how = by_udid[c["udid"].lower()], "udid"
                elif c.get("name") and c["name"].casefold() in by_name:
                    hit, how = by_name[c["name"].casefold()], "name (inferred)"
                # resolved: True found, False not in the full device posture list, None not known (that list was not read in full).
                rows.append({"name": c["name"], "udid": c.get("udid") or "", "device_posture": hit["name"] if hit else None,
                             "family": hit["label"] if hit else None, "matched_by": how,
                             "resolved": True if hit else (False if zpa_postures_complete else None)})
            levels[lvl] = rows
        users = [{"id": a["id"], "name": a["name"], "platform": a["platform"], "active": a["active"]} for a in apps if a["zia_posture_id"] and a["zia_posture_id"] == p["id"]]
        zia_view.append({"id": p["id"], "name": p["name"], "platform": p["platform"], "platform_label": p["platform_label"],
                         "defined_in": "Client Connector (ZIA posture profile)", "levels": levels,
                         "app_profiles": users if apps_read else None,
                         "zia_rules": [_rule_ref(r) for r in trust_rules] if (zia_read and users) else ([] if zia_read else None)})

    # Device posture checks (ZPA's list), with the ZIA posture profiles that name them
    dev_view = []
    for p in zpa_profiles:
        refs = []
        for zv in zia_view:
            lv = [lvl for lvl, rows in zv["levels"].items() if any(x["device_posture"] == p["name"] for x in rows)]
            if lv:
                refs.append({"id": zv["id"], "name": zv["name"], "levels": lv, "level_labels": [TRUST_LABEL[x] for x in lv]})
        zpa_uses = [u for u in p.get("used_by") or []]
        used: Optional[bool]
        if zpa_uses or refs:
            used = True
        elif access_read and zp_read:
            used = False
        else:
            used = None
        dev_view.append({"id": p["id"], "name": p["name"], "family": p["label"], "enforces": p["enforces"],
                         "platforms": plat_keys(p.get("platforms") or []),
                         "platform_labels": [PLATFORM_LABEL.get(k, k) for k in plat_keys(p.get("platforms") or [])],
                         "defined_in": "Client Connector (device posture)", "read_via": "ZPA API",
                         "zpa_rules": [{"rule": u["rule"], "policy": u["policy_label"], "order": u.get("order"), "action": u.get("action"),
                                        "sense": u["sense"], "disabled": u.get("disabled")} for u in zpa_uses] if access_read else None,
                         "zia_postures": refs if zp_read else None, "used": used})
    if not zpa_postures_read:
        not_assessed.append("ZPA's device posture list was not read, so device posture checks are known only by the names ZIA posture profiles give them.")

    # DP-05 (from device_posture) says "no ZPA rule uses it": drop it for a check a ZIA posture profile uses, and say when ZIA was not looked at.
    keep = []
    for f in rep.get("findings") or []:
        if f["id"] == "DP-05":
            d = next((x for x in dev_view if x["id"] == f["object_id"]), None)
            if d and d["zia_postures"]:
                continue
            if not zp_read:
                f = dict(f, reason=f["reason"] + " Client Connector's ZIA posture profiles were not read, so a ZIA use is not ruled out.")
            else:
                f = dict(f, reason=f["reason"] + " No ZIA posture profile names it either.")
        keep.append(f)
    rep["findings"] = keep

    # XP-04: a ZIA posture criterion naming a device posture check that does not exist
    if zp_read and zpa_postures_complete:
        for zv in zia_view:
            missing = sorted({x["name"] for rows in zv["levels"].values() for x in rows if x["device_posture"] is None})
            if missing:
                findings.append(F("XP-04", "low", FINDING_TITLES["XP-04"], zv["name"], "ZIA posture profile", zv["id"],
                                  f"Its trust criteria name {_names_list(missing)}, which is not a device posture check in the tenant, so that "
                                  "criterion can never be met as intended.",
                                  "Edit the ZIA posture profile in Client Connector to name an existing device posture check."))
    elif zp_read and zia_postures:
        not_assessed.append("Whether every check a ZIA posture profile names exists is not assessed: ZPA's device posture list was not read in full.")

    # XP-02 / XP-03: ZIA posture profiles and app profiles
    if zp_read and apps_read:
        for zv in zia_view:
            if not zv["app_profiles"]:
                findings.append(F("XP-02", "low", FINDING_TITLES["XP-02"], zv["name"], "ZIA posture profile", zv["id"],
                                  f"No app profile{'' if apps_complete else ' that could be read'} names this {zv['platform_label']} ZIA posture "
                                  "profile, so it rates no device's trust level.",
                                  "Pick it in the app profiles of the devices it is meant for, or delete it."))
        for a in apps:
            if a["zia_posture_id"] and a["zia_posture_id"] not in zp_by_id:
                findings.append(F("XP-03", "info", FINDING_TITLES["XP-03"], a["name"], "app profile", a["id"],
                                  f"It names ZIA posture profile {a['zia_posture_id']}, which is not in the list Client Connector answered. That "
                                  "list can be cut short without saying so, so the profile may exist; if it does not, devices on this app "
                                  "profile get no trust level.",
                                  "Check the app profile's ZIA posture profile in the Client Connector portal."))
    else:
        not_assessed.append("Which app profiles use each ZIA posture profile is not assessed: "
                            + ("Client Connector is not in scope." if "zcc" not in set(data.get("scopes") or []) else "the app profiles or ZIA posture profiles could not be read."))

    # Platforms in use (active app profiles), and the posture that covers each
    platforms = []
    if apps_read:
        in_use = sorted({a["platform"] for a in apps if a["platform"] and a["active"] is not False}, key=lambda k: PLATFORMS.index(k) if k in PLATFORMS else 99)
        for pk in in_use:
            zpa_p = [d["name"] for d in dev_view if pk in d["platforms"]]
            zia_p = [zv["name"] for zv in zia_view if zv["platform"] == pk]
            assigned = [zv["name"] for zv in zia_view if any(a["platform"] == pk for a in zv["app_profiles"] or [])]
            covered: Optional[bool] = True if (zpa_p or zia_p) else (False if (zpa_postures_read and zp_read) else None)
            platforms.append({"platform": pk, "label": PLATFORM_LABEL.get(pk, pk), "app_profiles": sum(1 for a in apps if a["platform"] == pk),
                              "device_postures": zpa_p, "zia_postures": zia_p, "zia_postures_assigned": assigned, "covered": covered})
            if covered is False:
                findings.append(F("XP-01", "medium", FINDING_TITLES["XP-01"], PLATFORM_LABEL.get(pk, pk), "platform", pk,
                                  f"Client Connector has active app profiles for {PLATFORM_LABEL.get(pk, pk)}, but no device posture check and no "
                                  "ZIA posture profile is defined for it, so neither ZPA nor ZIA can tell a healthy device from an unhealthy one.",
                                  f"Define device posture checks for {PLATFORM_LABEL.get(pk, pk)} in Client Connector and a ZIA posture profile "
                                  "that uses them, then use them in ZPA access rules and ZIA rules."))
        if any(p["covered"] is None for p in platforms):
            not_assessed.append("Platform coverage is unknown for "
                                + ", ".join(p["label"] for p in platforms if p["covered"] is None)
                                + ": the device posture or ZIA posture list was not read, so no posture is not the same as none found.")
    else:
        not_assessed.append("Which platforms are in use is not assessed: Client Connector's app profiles were not read.")

    # ZIA rules
    trust_computed: Optional[bool] = None
    if zp_read and apps_read:
        trust_computed = any(a["zia_posture_id"] in zp_by_id for a in apps if a["active"] is not False)
    if zia_read:
        # assumed: a device whose app profile names no ZIA posture profile has no trust level, which ZIA sees as unknown.
        no_trust_apps = [a for a in apps if a["active"] is not False and not a["zia_posture_id"]] if apps_read else []
        if trust_rules and apps_read and no_trust_apps:
            for r in trust_rules:
                findings.append(F("XP-05", "medium" if not trust_computed else "low", FINDING_TITLES["XP-05"], r["name"], f"{r['section_label']} rule", r["id"],
                                  f"It applies to devices with {_trust_words(r['trust_levels'])}, but app profiles "
                                  f"{_names_list(a['name'] for a in no_trust_apps)} name no ZIA posture profile, so their devices have no trust "
                                  "level and count as unknown trust.",
                                  "Pick a ZIA posture profile in those app profiles, or make sure the rule's answer for unknown trust is what you want."))
        for r in zrules:
            if not r["enabled"] or r["default"] or r["predefined"] or not r["loosens"]:
                continue
            weak = [x for x in r["trust_levels"] if x in WEAK_TRUST]
            if r["uses_trust"] and weak:
                findings.append(F("XP-06", "medium", FINDING_TITLES["XP-06"], r["name"], f"{r['section_label']} rule", r["id"],
                                  f"It {r['loosens']} for devices with {_trust_words(weak)}, so a device that fails its posture checks gets "
                                  "the looser policy.",
                                  "Limit the rule to High or Medium trust, and add a stricter rule for low and unknown trust."))
            elif not r["uses_trust"] and trust_computed:
                findings.append(F("XP-07", "low", FINDING_TITLES["XP-07"], r["name"], f"{r['section_label']} rule", r["id"],
                                  f"It {r['loosens']} for every device, whatever its trust level, although Client Connector works out trust "
                                  "levels for this tenant's devices.",
                                  "Consider limiting it to High or Medium trust devices (the rule's Device trust level condition)."))
        if trust_computed and not trust_rules and zia_complete:
            findings.append(F("XP-08", "info", FINDING_TITLES["XP-08"], "ZIA rules", "policy", "zia",
                              "Client Connector rates devices High, Medium or Low trust, but no enabled ZIA rule read uses the device trust "
                              "level, so a failing device gets the same ZIA policy as a healthy one.",
                              "Use the Device trust level condition in the ZIA rules that loosen policy (see the rule list)."))
        if trust_computed is None and any(r["loosens"] and not r["uses_trust"] for r in zrules):
            not_assessed.append("Whether ZIA rules should use the device trust level is not assessed: Client Connector's ZIA posture "
                                "profiles and app profiles were not both read, so it is unknown whether devices get a trust level.")
    else:
        not_assessed.append("ZIA rules are not assessed: " + st["zia"]["reason"])

    zia_rules_view = [dict(_rule_ref(r), loosens=r["loosens"], uses_trust=r["uses_trust"], enabled=r["enabled"],
                           trust_labels=[TRUST_LABEL[x] for x in r["trust_levels"]]) for r in zrules if r["uses_trust"] or r["loosens"]]
    zia_rules_view.sort(key=lambda x: (not x["uses_trust"], x["section"], _ordkey(x["order"]), x["name"].lower()))
    return {"device_postures": dev_view, "zia_postures": zia_view if zp_read else [], "zia_rules": zia_rules_view, "platforms": platforms,
            "app_profiles": apps, "findings": findings, "not_assessed": not_assessed, "trust_computed": trust_computed,
            "counts": {"device_postures": len(dev_view), "zia_postures": len(zia_view), "zia_rules_with_trust": len(trust_rules),
                       "zia_rules_read": len(zrules), "app_profiles": len(apps), "platforms": len(platforms)}}


def _ordkey(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 10 ** 9


def _rule_ref(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"section": r["section"], "section_label": r["section_label"], "id": r["id"], "name": r["name"], "order": r.get("order"),
            "action": r["action"] or ", ".join(r.get("actions") or []), "trust_levels": list(r["trust_levels"])}


def _trust_words(levels: Iterable[str]) -> str:
    return device_posture._join([TRUST_LABEL.get(x, x).lower() for x in levels], "or")


def attach(rep: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """The device posture report with the products' status, the
    cross-product view and its findings merged in."""
    st = statuses(data)
    if st["zpa"]["status"] not in ("read", "partial"):
        rep["not_assessed"] = [f"ZPA: {st['zpa']['reason']}"]
    c = cross(rep, data, st)
    rep["findings"] = sorted(list(rep.get("findings") or []) + c.pop("findings"),
                             key=lambda f: (device_posture.SEV_ORDER.get(f["severity"], 9), f["id"], f["object"].lower()))
    rep["titles"] = dict(rep.get("titles") or {}, **FINDING_TITLES)
    rep["products"] = st
    rep["cross"] = c
    rep["assumptions"] = list(rep.get("assumptions") or []) + ASSUMPTIONS
    counts = rep.setdefault("counts", {})
    counts["findings"] = len(rep["findings"])
    counts["by_severity"] = {s: sum(1 for f in rep["findings"] if f["severity"] == s) for s in device_posture.SEV_ORDER}
    counts.update({f"cross_{k}": v for k, v in c["counts"].items()})
    return rep


# ── Excel ───────────────────────────────────────────────────────────────
def sheets(wb: Any, report: Dict[str, Any]) -> None:
    """The cross-product sheets: Products, Device posture checks, ZIA posture profiles, Platforms, ZIA rules."""
    c = report.get("cross") or {}
    if not report.get("products"):
        return
    wb.add_sheet("Products", columns=["Product", "Status", "What it gives", "Why"],
                 rows=[[p["label"], p["words"], p["what"], p.get("reason") or ""] for p in report["products"].values()])
    yn = lambda v: "unknown" if v is None else ("yes" if v else "no")  # noqa: E731
    wb.add_sheet("Device posture checks", columns=["Check", "Family", "Defined in", "Platforms", "ZPA rules", "ZIA posture profiles", "Used"],
                 rows=[[d["name"], d["family"], d["defined_in"], ", ".join(PLATFORM_LABEL.get(x, x) for x in d["platforms"]),
                        "not read" if d["zpa_rules"] is None else "; ".join(u["rule"] for u in d["zpa_rules"]),
                        "not read" if d["zia_postures"] is None else "; ".join(f"{z['name']} ({', '.join(z['level_labels'])})" for z in d["zia_postures"]),
                        yn(d["used"])] for d in c.get("device_postures") or []])
    wb.add_sheet("ZIA posture profiles", columns=["ZIA posture profile", "Platform", "High trust", "Medium trust", "Low trust", "App profiles", "ZIA rules using trust"],
                 rows=[[z["name"], z["platform_label"]] + ["; ".join(x["name"] + ("" if x["device_posture"] else " (no such check)") for x in z["levels"].get(lvl) or [])
                                                          for lvl in ("HIGH_TRUST", "MEDIUM_TRUST", "LOW_TRUST")]
                       + ["not read" if z["app_profiles"] is None else "; ".join(a["name"] for a in z["app_profiles"]),
                          "not read" if z["zia_rules"] is None else "; ".join(x["name"] for x in z["zia_rules"])] for z in c.get("zia_postures") or []])
    wb.add_sheet("Platforms", columns=["Platform", "App profiles", "Device posture checks", "ZIA posture profiles", "Covered"],
                 rows=[[p["label"], p["app_profiles"], "; ".join(p["device_postures"]), "; ".join(p["zia_postures"]), yn(p["covered"])]
                       for p in c.get("platforms") or []])
    wb.add_sheet("ZIA rules", columns=["Section", "Order", "Rule", "Action", "Device trust levels", "Loosens policy"],
                 rows=[[r["section_label"], r.get("order"), r["name"], r["action"], ", ".join(r.get("trust_labels") or []) or "any", r.get("loosens") or ""]
                       for r in c.get("zia_rules") or []])
