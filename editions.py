"""Licensed editions: Cloud Firewall (standard or advanced), Cloud Sandbox
(standard or advanced) and ZDX (Lite, M365, Standard or Advanced), read from
the tenant's ZIA subscriptions, and what each edition lets the builders
create.

Where the editions come from
----------------------------
The ZIA licence list (GET /zia/api/v1/subscriptions, zscaler-sdk-python
1.11.3 organization_information.get_subscriptions; readiness.SUBSCRIPTIONS_PATH)
lists one row per subscription id. The SDK documents the call but not the
ids: the ids below are the ones readiness.SKU_INFO names, as seen on
tenants, and are ASSUMED (not in the SDK). The ZDX edition is not exposed by
any ZDX API in the SDK either; it is read from the same ZIA licence list.

    Cloud Firewall  advanced  ZFW_NG_WITH_LOG
                    standard  Z_FIREWALL_BASIC, or ZIA_ATP (the threat bundle
                              brings the standard firewall; assumed)
    Cloud Sandbox   advanced  ZSEC_WEB_ABA_ADV
                    standard  ZSEC_WEB_ABA, or ZIA_ATP (assumed, as above)
    ZDX             advanced  ZDX_ADV_PLUS, ZDX_ADVANCED
                    standard  Z_ZDX_STD
                    m365      Z_ZDX_M365
                    lite      ZDX_LITE

What each edition allows (this app's reading of Zscaler's edition
descriptions, ASSUMED: not verified against a tenant)
----------------------------------------------------
* Cloud Firewall Standard enforces the geo-blocking and QUIC rules; the
  application-based rules (the allow lists of network applications, the
  peer-to-peer and tunnel blocks) need Cloud Firewall Advanced, and the
  default deny is left out with them (without its allow lists it would drop
  everything).
* Cloud Sandbox Standard analyses executables on first download (Allow and
  scan); quarantining first-time files (Office, PDF, archives) and AI Instant
  Verdict need Sandbox Advanced. The Office/PDF and archive rules are left
  out; the executables rule is kept with AI Instant Verdict off.
* ZDX Lite has no configurable probes; ZDX M365 monitors Microsoft 365 apps
  only; ZDX Standard has no call-quality (UCaaS) monitoring (Zoom, Webex,
  Teams, RingCentral, Google Meet); ZDX Advanced allows everything.

When the list cannot be read, is not in scope, or names no edition of a
product (a bundle id this app does not know may include it), the edition is
"unknown" and nothing is left out: the builders behave as before and say so.
Pure apart from read(), which makes one read-only GET.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

UNKNOWN = "unknown"

FIREWALL: Tuple[Tuple[str, Tuple[str, ...]], ...] = (("advanced", ("ZFW_NG_WITH_LOG",)), ("standard", ("Z_FIREWALL_BASIC", "ZIA_ATP")))
SANDBOX: Tuple[Tuple[str, Tuple[str, ...]], ...] = (("advanced", ("ZSEC_WEB_ABA_ADV",)), ("standard", ("ZSEC_WEB_ABA", "ZIA_ATP")))
ZDX: Tuple[Tuple[str, Tuple[str, ...]], ...] = (("advanced", ("ZDX_ADV_PLUS", "ZDX_ADVANCED")), ("standard", ("Z_ZDX_STD",)),
                                                ("m365", ("Z_ZDX_M365",)), ("lite", ("ZDX_LITE",)))
LABELS = {"firewall": {"advanced": "Cloud Firewall Advanced", "standard": "Cloud Firewall (standard)"},
          "sandbox": {"advanced": "Cloud Sandbox Advanced", "standard": "Cloud Sandbox (standard)"},
          "zdx": {"advanced": "ZDX Advanced", "standard": "ZDX Standard", "m365": "ZDX M365", "lite": "ZDX Lite"}}
SKU_NOTE = "Subscription ids are assumed (as seen on tenants; the SDK documents the licence list, not its ids)."

# ZIA baseline catalog keys (ops_zia_baseline.CATALOG) each edition limits.
FIREWALL_ADVANCED_ONLY = ("fw.allow_web", "fw.allow_ntp", "fw.collab", "fw.enterprise", "fw.p2p", "fw.tunnels", "fw.default_deny")
SANDBOX_ADVANCED_ONLY = ("sb.office_pdf", "sb.archives")
SANDBOX_STANDARD_FIELDS = {"sb.executables": {"ml_action_enabled": False}}   # kept, AI Instant Verdict off

# ZDX predefined providers: call quality (UCaaS) needs Advanced; M365 is Microsoft only.
ZDX_UCAAS = ("MICROSOFT_TEAMS", "ZOOM", "WEBEX", "RINGCENTRAL", "GOOGLE_MEET")
ZDX_MICROSOFT_PREFIXES = ("MICROSOFT", "OUTLOOK", "SHAREPOINT", "ONEDRIVE", "EXCHANGE", "OFFICE")

ZIA_SCOPES = ("zia_extras", "dlp", "genai", "automation", "rbac")


def _pick(have: set, table: Tuple[Tuple[str, Tuple[str, ...]], ...]) -> str:
    for edition, ids in table:
        if have & set(ids):
            return edition
    return UNKNOWN


def detect(ids: Optional[Iterable[str]]) -> Dict[str, Any]:
    """{firewall, sandbox, zdx, read} from the active subscription ids, or
    every edition unknown when the list was not read (None)."""
    if ids is None:
        return {"firewall": UNKNOWN, "sandbox": UNKNOWN, "zdx": UNKNOWN, "read": False}
    have = {str(x) for x in ids}
    return {"firewall": _pick(have, FIREWALL), "sandbox": _pick(have, SANDBOX), "zdx": _pick(have, ZDX), "read": True}


def read(client: Any, scope: Optional[Dict[str, Any]] = None, say: Any = None) -> Dict[str, Any]:
    """The editions of the tenant, from one read of the ZIA licence list. Read
    only when a ZIA scope is ticked on the Scope page; otherwise (or when the
    read fails) every edition is unknown, with why."""
    scopes = list((scope or {}).get("scopes") or [])
    if scope is not None and not any(s in scopes for s in ZIA_SCOPES):
        out = detect(None)
        out["why"] = "the licence list is a ZIA read and no ZIA scope is ticked on the Scope page"
        return out
    import readiness
    if say:
        say("Reading the licences (subscriptions) for the editions…")
    try:
        got = readiness._raw_get(client, readiness.SUBSCRIPTIONS_PATH)
    except Exception:  # noqa: BLE001 - a failed read is unknown, never a crash
        got = {"state": "error", "code": 0, "body": None}
    if got.get("state") != "ok":
        out = detect(None)
        out["why"] = f"the licence list was not available (HTTP {got.get('code') or 'error'})"
        return out
    subs = readiness.parse_subscriptions(got.get("body"))
    out = detect([s["id"] for s in subs if s.get("active")])
    out["why"] = ""
    return out


def label(product: str, edition: str) -> str:
    return LABELS.get(product, {}).get(edition, "")


def notes(ed: Dict[str, Any], products: Iterable[str] = ("firewall", "sandbox", "zdx")) -> List[str]:
    """One plain line per product: the edition found and what it means."""
    out: List[str] = []
    for p in products:
        e = ed.get(p, UNKNOWN)
        name = {"firewall": "Cloud Firewall", "sandbox": "Cloud Sandbox", "zdx": "ZDX"}[p]
        if e == UNKNOWN:
            why = ed.get("why") or "the licence list names no edition of it (a bundle may include it)"
            out.append(f"{name} edition not known ({why}): every {name} item is offered.")
        elif p == "firewall":
            out.append("Cloud Firewall Advanced is licensed: every firewall rule is offered." if e == "advanced" else
                       "Only the standard Cloud Firewall is licensed: the geo-blocking and QUIC rules are built; the application-based rules "
                       "(allow lists, peer-to-peer and tunnel blocks) and the default deny need Cloud Firewall Advanced and are left out.")
        elif p == "sandbox":
            out.append("Cloud Sandbox Advanced is licensed: every sandbox rule is offered." if e == "advanced" else
                       "Only the standard Cloud Sandbox is licensed: executables are scanned on first download (AI Instant Verdict off); "
                       "quarantining Office, PDF and archive files needs Sandbox Advanced, so those rules are left out.")
        else:
            out.append({"advanced": "ZDX Advanced is licensed: every app and probe is offered.",
                        "standard": "ZDX Standard is licensed: call-quality apps (Zoom, Webex, Teams, RingCentral, Google Meet) need ZDX "
                                    "Advanced and are left out.",
                        "m365": "ZDX M365 is licensed: only Microsoft 365 apps are monitored; other apps and custom apps are left out.",
                        "lite": "ZDX Lite is licensed: it has no configurable probes, so no app or probe is set up."}[e])
    if any(ed.get(p) not in (None, UNKNOWN) for p in products):
        out.append(SKU_NOTE + " What each edition allows is this app's reading of Zscaler's edition descriptions (assumed).")
    return out


def baseline_limit(key: str, ed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """What the edition does to a ZIA baseline rule: {"drop": why} or
    {"fields": {...}, "why": ...}, or None when it is allowed as it is."""
    if key in FIREWALL_ADVANCED_ONLY and ed.get("firewall") == "standard":
        why = ("needs Cloud Firewall Advanced (only the standard firewall is licensed)" if key != "fw.default_deny" else
               "the application allow lists it relies on need Cloud Firewall Advanced; without them a default deny would drop everything")
        return {"drop": why}
    if key in SANDBOX_ADVANCED_ONLY and ed.get("sandbox") == "standard":
        return {"drop": "quarantining first-time files needs Cloud Sandbox Advanced (only the standard sandbox is licensed)"}
    if key in SANDBOX_STANDARD_FIELDS and ed.get("sandbox") == "standard":
        return {"fields": dict(SANDBOX_STANDARD_FIELDS[key]), "why": "AI Instant Verdict needs Cloud Sandbox Advanced: it is turned off"}
    return None


def fit_baseline(rows: List[Dict[str, Any]], ed: Dict[str, Any]) -> List[str]:
    """Leave out or downgrade, in place, the baseline rules the licensed
    edition does not allow (rows get `dropped` or changed fields, as
    ops_zia_baseline.fit does); returns the warnings for the preview."""
    warns: List[str] = []
    for r in rows:
        if not r.get("on") or r.get("dropped"):
            continue
        lim = baseline_limit(r.get("key", ""), ed)
        if not lim:
            continue
        if "drop" in lim:
            r["dropped"] = lim["drop"]
            r["edition"] = lim["drop"]
        else:
            r["fields"] = dict(r["fields"], **lim["fields"])
            r["edition"] = lim["why"]
            if "ml_action_enabled" in lim["fields"] and "title" in r:
                r["title"] = str(r["title"]).replace(", AI Instant Verdict on", "") + " (AI Instant Verdict off: standard sandbox)"
            warns.append(f"{r['name']}: {lim['why']}.")
        if r.get("dropped") and r.get("locked"):
            warns.append(f"{r['name']} is {r['locked']}, but the licensed edition leaves it out: that control is not met until the "
                         "edition it needs is licensed.")
    gone = [r["name"] for r in rows if r.get("edition") and r.get("dropped")]
    if gone:
        warns.append(f"Left out for the licensed edition: {', '.join(gone)}.")
    return warns


def zdx_limit(edition: str, *, provider: str = "", custom: bool = False) -> str:
    """Why the ZDX edition does not allow an app ('' when it does)."""
    if edition == "lite":
        return "ZDX Lite has no configurable probes"
    if edition == "m365" and (custom or not str(provider).upper().startswith(ZDX_MICROSOFT_PREFIXES)):
        return "ZDX M365 monitors Microsoft 365 apps only"
    if edition == "standard" and not custom and str(provider).upper() in ZDX_UCAAS:
        return "call-quality (UCaaS) monitoring needs ZDX Advanced"
    return ""
