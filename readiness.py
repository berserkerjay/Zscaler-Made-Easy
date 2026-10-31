"""Readiness: what this API client can do in this app, before anything runs.

Answers, per product (ZIA, ZPA, Client Connector, ZDX, Z-Insights, AI Guard,
ZIdentity): can it read, can it change, or has it no access; which licences
(subscriptions, SKUs) the tenant has; and, for every Scope page key and every
feature of this app that changes the tenant, whether it will work and, if
not, what to ask the admin for, in plain steps.

Where the facts come from
-------------------------
* The OneAPI access token the sign-in already obtained. Its payload is
  decoded WITHOUT verifying the signature: it is used for display and for
  greying out what will fail, never for an authorization decision (the
  tenant decides that on every call). Only product codes, role names, role
  ids and scope names are kept; the token itself is never returned, logged
  or stored (tests/test_readiness.py proves it with a canary).
* A handful of reads, only for the products in scope on the Scope page
  (user rule 1): ZIA `/subscriptions` and the API role
  (`/adminRoles/{id}`), Client Connector company info and admin roles, ZPA
  roles, one ZDX and one Z-Insights call to see whether they answer.
* The permission catalogue of scope_permissions.py (labels, minimum read
  permissions, licence text) and permissions.WRITE_PERMISSIONS (what a
  change needs). This module adds the machine-readable needs on top: the
  ZIA feature-permission keys and the subscription ids.

Verified against zscaler-sdk-python 1.11.3: the ZIA feature-permission
keys (zia/admin_roles.py docstring), `/zia/api/v1/adminRoles/{id}`
(admin_roles.get_role), `/zcc/papi/public/v1/getCompanyInfo`
(zcc.company.get_company_info), `/getAdminRoles`
(zcc.admin_user.list_admin_roles), ZPA `/roles` (zpa.role_controller.
list_roles), `/zdx/v1/administration/departments` (zdx.admin.
list_departments), Z-Insights WEB_TRAFFIC (zins.web_traffic.
get_no_grouping) and the token on `ZscalerClient._auth_token`.
Assumed (not in the SDK): the ZIA `/subscriptions` endpoint and its row
shape, the token's `service-info` claim (`prd`, `ext.rnm`, `ext.rid`), the
product codes in it, the subscription ids that unlock a feature and the
Client Connector role field names.
"""
from __future__ import annotations

import base64
import binascii
import importlib
import json
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from scope_permissions import SCOPE_PERMISSIONS

# ── Limits for an untrusted token ──────────────────────────────────────
MAX_TOKEN_CHARS = 16384        # a OneAPI token is a few kilobytes
MAX_PAYLOAD_BYTES = 10240
MAX_DEPTH = 12                 # JSON nesting allowed in the payload
MAX_SERVICES = 32
MAX_SCOPES = 100
MAX_SUBSCRIPTIONS = 300
ENDING_SOON_DAYS = 21
SUBSCRIPTIONS_PATH = "/zia/api/v1/subscriptions"   # assumed: not in the SDK

# ── Products ───────────────────────────────────────────────────────────
# key -> label, the Scope page keys that let readiness read it, and the
# product codes the token's service-info claim uses for it (assumed).
PRODUCTS: "OrderedDict[str, Dict[str, Any]]" = OrderedDict([
    ("ZIA", {"label": "ZIA (Internet Access)", "scopes": ("dlp", "zia_extras", "genai", "automation", "rbac"), "codes": ("ZIA",),
             "portal": "the ZIA Admin Portal"}),
    ("ZPA", {"label": "ZPA (Private Access)", "scopes": ("zpa",), "codes": ("ZPA",), "portal": "the ZPA Admin Portal"}),
    ("ZCC", {"label": "Client Connector", "scopes": ("zcc",), "codes": ("ZCC",), "portal": "the Client Connector Portal"}),
    ("ZDX", {"label": "ZDX (Digital Experience)", "scopes": ("zdx",), "codes": ("ZDX",), "portal": "the ZDX Admin Portal"}),
    ("ZINSIGHTS", {"label": "Z-Insights (traffic data)", "scopes": ("insights",), "codes": ("ZINSIGHTS",), "portal": "ZIdentity"}),
    ("ZGUARD", {"label": "AI Guard", "scopes": ("aiguard", "ai_guard"), "codes": ("ZGUARD", "AIGUARD"), "portal": "the AI Guard console"}),
    ("ZIDENTITY", {"label": "ZIdentity", "scopes": ("zidentity",), "codes": ("ZIAM", "ZIDENTITY"), "portal": "ZIdentity"}),
    ("ZTW", {"label": "Cloud & Branch Connector", "scopes": ("ztw",), "codes": ("ZTW",), "portal": "the Cloud & Branch Connector Admin Portal"}),
    # The other products (other_products.py); token only, codes assumed like the rest.
    ("ZTB", {"label": "Zero Trust Branch", "scopes": ("ztb",), "codes": ("ZTB",), "portal": "the Zero Trust Branch admin portal"}),
    ("ZEASM", {"label": "External attack surface (EASM)", "scopes": ("easm",), "codes": ("ZEASM", "EASM"), "portal": "the EASM admin portal"}),
    ("ZBI", {"label": "Business Insights", "scopes": ("zbi",), "codes": ("ZBI", "BI"), "portal": "Business Insights"}),
    ("ZCELL", {"label": "Zero Trust Cellular", "scopes": ("zcell",), "codes": ("ZCELL",), "portal": "the Zero Trust Cellular admin portal"}),
    ("ZMS", {"label": "Microsegmentation", "scopes": ("zms",), "codes": ("ZMS",), "portal": "the Microsegmentation admin portal"}),
])
_CODE_TO_PRODUCT = {code: key for key, p in PRODUCTS.items() for code in p["codes"]}
PROBED = ("ZIA", "ZPA", "ZCC", "ZDX", "ZINSIGHTS", "ZGUARD")   # ZIdentity, Cloud & Branch Connector: token only

# ── ZIA feature permissions (keys verified in the SDK's admin_roles docs) ─
ZIA_PERMS: Dict[str, str] = {
    "INLINE_DLP": "Inline DLP (web DLP rules)",
    "DLP_DICTIONARIES_ENGINES": "DLP dictionaries and engines",
    "DLP_NOTIFICATION_TEMPLATES": "DLP notification templates",
    "DLP_INCIDENT_RECEIVER": "DLP incident receiver",
    "END_POINT_DLP": "Endpoint DLP",
    "SAAS_SECURITY_API": "SaaS Security API (CASB DLP)",
    "SAAS_APPLICATION_TENANTS": "SaaS application tenants",
    "URL_CLOUD_APP_CONTROL": "URL and Cloud App Control",
    "URL_FILTERING_CONTROL": "URL filtering",
    "CLOUD_APP_CONTROL": "Cloud App Control",
    "CUSTOM_URL_CAT": "Custom URL categories",
    "SSL_POLICY": "SSL inspection policy",
    "FIREWALL_CONTROL": "Firewall control",
    "DNS_CONTROL": "DNS control",
    "FILE_TYPE_CONTROL": "File Type Control",
    "LOCATIONS": "Locations",
    "ADVANCED_SETTINGS": "Advanced settings",
    "ADVANCED_THREAT_PROTECTION": "Advanced Threat Protection",
    "MALWARE_PROTECTION": "Malware protection",
    "CLOUD_SANDBOX": "Cloud Sandbox",
    "BROWSER_ISOLATION": "Browser Isolation",
    "HOSTED_PAC_FILES": "Hosted PAC files",
    "USER_MANAGEMENT": "User management",
    "ADMINISTRATOR_MANAGEMENT": "Administrator management",
    "ROLE_MANAGEMENT": "Role management",
    "AUDIT_LOGS": "Audit logs",
    "AUTHENTICATION_SETTINGS": "Authentication settings",
}
LEVELS = {"NONE": 0, "READ_ONLY": 1, "READ_WRITE": 2}
LEVEL_WORDS = {0: "no access", 1: "read only", 2: "full"}

# ── Licences: subscription id -> (area, plain name). Ids as seen on tenants (assumed). ─
SKU_INFO: Dict[str, Tuple[str, str]] = {
    "ZIA_TENANT": ("ZIA", "ZIA tenant"),
    "URL_FILTER": ("ZIA", "URL filtering"),
    "ZMAN_WEB_2_0": ("ZIA", "Cloud App Control"),
    "ZIA_SSL": ("ZIA", "SSL inspection"),
    "ZIA_ATP": ("ZIA", "Advanced Threat Protection"),
    "AV_AS": ("ZIA", "Antivirus and anti-spam"),
    "ZSEC_WEB_ABA": ("ZIA", "Cloud Sandbox"),
    "ZSEC_WEB_ABA_ADV": ("ZIA", "Cloud Sandbox Advanced"),
    "Z_FIREWALL_BASIC": ("ZIA", "Cloud Firewall (standard)"),
    "ZFW_NG_WITH_LOG": ("ZIA", "Cloud Firewall Advanced"),
    "Z_FIREWALL_IPS": ("ZIA", "Cloud IPS"),
    "Z_DNS_ESS": ("ZIA", "DNS Security (essential)"),
    "Z_DNS_ADVANCED": ("ZIA", "DNS Security (advanced)"),
    "ZIA_BW_CTRL": ("ZIA", "Bandwidth Control"),
    "Z_API": ("ZIA", "API access"),
    "Z_ICAP": ("ZIA", "ICAP integration"),
    "Z_WORKFLOW_AUTOMATION": ("Data Protection", "Workflow Automation"),
    "ZDLP_WEB_BASIC": ("Data Protection", "Web DLP (standard)"),
    "ZDLP_WEB": ("Data Protection", "Web DLP (full)"),
    "Z_DLP_ENDPOINT": ("Data Protection", "Endpoint DLP"),
    "Z_DLP_EDM": ("Data Protection", "Exact Data Match"),
    "Z_DLP_IDM": ("Data Protection", "Indexed Document Match"),
    "CUST_DICTIONARIES_ENGINES": ("Data Protection", "Custom DLP dictionaries and engines"),
    "ZS_DP_GEN_AI": ("Data Protection", "Gen AI data protection"),
    "ZS_DP_EMAIL": ("Data Protection", "Email DLP"),
    "Z_CASB_BASIC": ("Data Protection", "CASB (basic)"),
    "Z_CASB": ("Data Protection", "CASB"),
    "Z_LOGFEED": ("Logging", "NSS log feed (web)"),
    "Z_CLOUD_NSS_WEB": ("Logging", "Cloud NSS (web)"),
    "ZIA_ISO_STD": ("Isolation", "Cloud Browser Isolation (standard)"),
    "ZIA_ISO_ADV": ("Isolation", "Cloud Browser Isolation (advanced)"),
    "ZSCALER_CLIENT_CONNECTOR": ("Client Connector", "Zscaler Client Connector"),
    "ZDX_LITE": ("ZDX", "ZDX Lite"),
    "Z_ZDX_STD": ("ZDX", "ZDX Standard"),
    "ZDX_ADVANCED": ("ZDX", "ZDX Advanced"),
    "ZDX_ADV_PLUS": ("ZDX", "ZDX Advanced Plus"),
    "Z_ZDX_M365": ("ZDX", "ZDX M365"),
}
DLP_SKUS = ("ZDLP_WEB", "ZDLP_WEB_BASIC")

# ── What each Scope page key and each write feature needs ──────────────
# needs: every inner tuple is one permission, satisfied by any of its keys
# (the SDK documents URL_CLOUD_APP_CONTROL; some tenants show the split
# URL_FILTERING_CONTROL / CLOUD_APP_CONTROL). optional: missing ones make
# the feature partial, never blocked. skus: any one is enough; soft_skus:
# missing ones are a note only.
F = Dict[str, Any]
SCOPE_FEATURES: "OrderedDict[str, F]" = OrderedDict([
    ("dlp", {"product": "ZIA", "needs": [("INLINE_DLP",), ("DLP_DICTIONARIES_ENGINES",)],
             "optional": [("END_POINT_DLP",), ("SAAS_SECURITY_API",), ("DLP_NOTIFICATION_TEMPLATES",), ("DLP_INCIDENT_RECEIVER",)],
             "skus": DLP_SKUS, "licence": "Data Protection (web DLP)"}),
    ("zia_extras", {"product": "ZIA", "needs": [("URL_CLOUD_APP_CONTROL", "URL_FILTERING_CONTROL"), ("SSL_POLICY",), ("FIREWALL_CONTROL",)],
                    "optional": [("LOCATIONS",), ("ADVANCED_SETTINGS",), ("BROWSER_ISOLATION",), ("HOSTED_PAC_FILES",), ("USER_MANAGEMENT",),
                                 ("ADVANCED_THREAT_PROTECTION",), ("MALWARE_PROTECTION",), ("CLOUD_SANDBOX",), ("AUTHENTICATION_SETTINGS",)]}),
    ("zpa", {"product": "ZPA", "customer_id": True}),
    ("zcc", {"product": "ZCC"}),
    ("genai", {"product": "ZIA", "needs": [("URL_CLOUD_APP_CONTROL", "CLOUD_APP_CONTROL"), ("INLINE_DLP",)],
               "soft_skus": ("ZS_DP_GEN_AI",), "licence": "Gen AI data protection (for the AI prompt checks)"}),
    ("automation", {"product": "ZIA", "needs": [("AUDIT_LOGS",)], "optional": [("ADMINISTRATOR_MANAGEMENT", "ROLE_MANAGEMENT")]}),
    ("zdx", {"product": "ZDX", "soft_skus": ("ZDX_LITE", "Z_ZDX_STD", "ZDX_ADVANCED", "ZDX_ADV_PLUS", "Z_ZDX_M365"), "licence": "a ZDX subscription"}),
    ("zidentity", {"product": "ZIDENTITY"}),
    ("rbac", {"product": "ZIA", "needs": [("ADMINISTRATOR_MANAGEMENT", "ROLE_MANAGEMENT")], "optional": [("AUTHENTICATION_SETTINGS",)]}),
    ("insights", {"product": "ZINSIGHTS", "oneapi_only": True}),
    ("aiguard", {"product": "ZGUARD", "oneapi_only": True}),
    ("ztw", {"product": "ZTW", "oneapi_only": True}),
    ("ztb", {"product": "ZTB", "oneapi_only": True}),
    ("easm", {"product": "ZEASM", "oneapi_only": True}),
    ("zbi", {"product": "ZBI", "oneapi_only": True}),
    ("zcell", {"product": "ZCELL", "oneapi_only": True}),
    ("zms", {"product": "ZMS", "oneapi_only": True, "customer_id": True}),
])
SCOPE_LABELS = {"rbac": "RBAC", "zidentity": "ZIdentity"}

# One per permissions.WRITE_PERMISSIONS kind (test-enforced).
WRITE_KINDS: "OrderedDict[str, F]" = OrderedDict([
    ("dictionary", {"needs": [("DLP_DICTIONARIES_ENGINES",)], "skus": DLP_SKUS}),
    ("engine", {"needs": [("DLP_DICTIONARIES_ENGINES",)], "skus": DLP_SKUS}),
    ("web", {"needs": [("INLINE_DLP",)], "skus": DLP_SKUS}),
    ("endpoint", {"needs": [("END_POINT_DLP",)], "skus": ("Z_DLP_ENDPOINT",)}),
    ("saas", {"needs": [("SAAS_SECURITY_API",)], "skus": ("Z_CASB", "Z_CASB_BASIC")}),
    # No email DLP key is documented in the SDK: the role's policy access decides.
    ("email", {"needs": [], "policy_access": True, "skus": ("ZS_DP_EMAIL",)}),
    ("cloud_app", {"needs": [("URL_CLOUD_APP_CONTROL", "CLOUD_APP_CONTROL")]}),
    ("file_type", {"needs": [("FILE_TYPE_CONTROL",)]}),
    ("url", {"needs": [("URL_CLOUD_APP_CONTROL", "URL_FILTERING_CONTROL")]}),
    ("ssl", {"needs": [("SSL_POLICY",)]}),
    ("activation", {"needs": [], "info": "This app never activates by itself; an admin activates in the ZIA portal."}),
])

# ZPA object classes the ZPA builder creates (matched on the role's friendly names; assumed).
ZPA_BUILD_CLASSES = ("Application Segment", "Segment Group", "Server Group", "Connector Group", "Provisioning Key", "Policy")

# The app's features that change the tenant: the WRITE_KINDS they write.
# `any`: the feature works when at least one kind is writable (it acts per policy).
WRITE_FEATURES: "OrderedDict[str, F]" = OrderedDict([
    ("deploy_packs", {"label": "Deploy policy packs", "kinds": ("dictionary", "engine", "web"), "optional_kinds": ("endpoint", "saas", "email")}),
    ("remove_packs", {"label": "Remove policy packs", "kinds": ("dictionary", "engine", "web"), "optional_kinds": ("endpoint", "saas", "email")}),
    ("rule_migration", {"label": "Rule migration wizard (Evaluate All Rules)", "kinds": ("web",)}),
    ("self_heal", {"label": "Self-healing (Heal)", "kinds": ("dictionary", "engine", "web")}),
    ("bulk_changes", {"label": "Bulk changes (rules, order, URL categories)", "kinds": ("web", "endpoint", "email", "saas", "url", "ssl", "cloud_app", "file_type"), "any": True}),
    ("remediation", {"label": "Review and remediate (one-click fixes)", "kinds": ("web", "url", "ssl", "cloud_app", "file_type", "dictionary", "engine"), "any": True}),
    ("zpa_segment_moves", {"label": "Move ZPA domains between segments (Bulk changes)", "product": "ZPA", "zpa_classes": ("Application Segment",)}),
    # The Build new plugins on Bulk changes (ops_*.py): judged on their product's own access.
    ("zia_baseline", {"label": "ZIA security baseline and SSL certificates (Build new)", "kinds": ("url", "ssl", "cloud_app", "file_type"), "any": True}),
    ("zpa_builder", {"label": "ZPA builder (Build new)", "product": "ZPA", "zpa_classes": ZPA_BUILD_CLASSES}),
    ("zcc_builder", {"label": "Client Connector profiles (Build new)", "product": "ZCC"}),
    ("zdx_probes", {"label": "ZDX probe setup (Build new)", "product": "ZDX"}),
    ("aiguard_builders", {"label": "AI Guard routing and detection policy (Build new)", "product": "ZGUARD"}),
])

# ZPA object classes this app reads or writes (matched on the role's friendly names; assumed).
ZPA_CLASSES = ("Application Segment", "Segment Group", "Server Group", "Connector Group", "Policy")
# Client Connector role fields this app reads (0 none, 1 view, 2 full; names assumed).
ZCC_FIELDS = {"deviceOverview": "device list", "windowsProfile": "Windows app profiles", "macProfile": "macOS app profiles",
              "forwardingProfile": "forwarding profiles", "trustedNetwork": "trusted networks"}
# Client Connector company info: only these switches are kept (no names, e-mails or numbers).
ZCC_FLAGS = {"zpnEnabled": "ZPA enabled", "upmEnabled": "ZDX enabled", "dlpEnabled": "Endpoint DLP enabled",
             "zadEnabled": "Deception enabled", "proxyEnabled": "ZIA enabled", "secureAgentBasic": "Secure agent (basic)",
             "secureAgentAdvanced": "Secure agent (advanced)"}


# ── Small helpers ──────────────────────────────────────────────────────
_PRD_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
_SKU_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_PERM_RE = re.compile(r"[A-Z0-9_]{1,64}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_SCOPE_RE = re.compile(r"[\x21-\x7e]{1,128}")


def _clean_text(v: Any, limit: int = 120) -> str:
    """Printable text only, bounded: what is shown from a token or an answer."""
    if not isinstance(v, (str, int)) or isinstance(v, bool):
        return ""
    s = "".join(ch for ch in str(v) if ch.isprintable())
    return s.strip()[:limit]


def _iso(ts: Any) -> Optional[str]:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None
    # Bounded before any arithmetic: a JSON integer has no size limit, and
    # one too large for a float would raise OverflowError in the division.
    if not 0 < ts < 32503680000 * 1000:
        return None
    if ts > 1e11:   # milliseconds
        ts = ts / 1000.0
    if not 0 < ts < 32503680000:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _too_deep(text: str, limit: int) -> bool:
    """True when JSON text nests deeper than `limit` (linear scan, strings skipped)."""
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


# ── The token ──────────────────────────────────────────────────────────

def _no_claims(why: str) -> Dict[str, Any]:
    return {"ok": False, "why": why, "products": [], "products_listed": False, "scopes": [], "expires_at": None, "issued_at": None}


def decode_claims(token: Any) -> Dict[str, Any]:
    """The display facts of a OneAPI access token: products with their role
    names (the `service-info` claim), the scopes and the validity window.
    The signature is NOT verified: never use this to decide access. Never
    raises; a malformed, huge or hostile token gives ok=False and a reason
    in words that quotes nothing from the token."""
    if not isinstance(token, str) or not token:
        return _no_claims("No access token: the sign-in did not give one.")
    if len(token) > MAX_TOKEN_CHARS:
        return _no_claims("The access token is too large to read.")
    parts = token.split(".")
    if len(parts) != 3:
        return _no_claims("The access token is not a JSON Web Token.")
    seg = parts[1]
    if not _B64URL_RE.fullmatch(seg or ""):
        return _no_claims("The access token is not a JSON Web Token.")
    try:
        bare = seg.rstrip("=")
        raw = base64.urlsafe_b64decode(bare + "=" * (-len(bare) % 4))
    except (binascii.Error, ValueError):
        return _no_claims("The access token could not be decoded.")
    if len(raw) > MAX_PAYLOAD_BYTES:
        return _no_claims("The access token is too large to read.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _no_claims("The access token could not be decoded.")
    if _too_deep(text, MAX_DEPTH):
        return _no_claims("The access token is nested too deeply to read.")
    try:
        data = json.loads(text, parse_constant=lambda c: None)
    except (ValueError, RecursionError):
        return _no_claims("The access token's claims are not valid JSON.")
    if not isinstance(data, dict):
        return _no_claims("The access token's claims are not an object.")

    products: List[Dict[str, Any]] = []
    si = data.get("service-info")
    listed = isinstance(si, list)
    seen = set()
    for entry in (si if listed else [])[:MAX_SERVICES]:
        if not isinstance(entry, dict):
            continue
        code = entry.get("prd")
        if not isinstance(code, str) or not _PRD_RE.fullmatch(code):
            continue
        code = code.upper()
        ext = entry.get("ext") if isinstance(entry.get("ext"), dict) else {}
        rid = ext.get("rid")
        rid = str(rid) if isinstance(rid, (int, str)) and not isinstance(rid, bool) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(rid)) else ""
        key = _CODE_TO_PRODUCT.get(code, "")
        if (key or code) in seen:
            continue
        seen.add(key or code)
        products.append({"product": key or "OTHER", "code": code, "role": _clean_text(ext.get("rnm")), "role_id": rid})

    scopes: List[str] = []
    sc = data.get("scope", data.get("scp"))
    items = sc.split() if isinstance(sc, str) else sc if isinstance(sc, list) else []
    for s in items[: MAX_SCOPES * 2]:
        if isinstance(s, str) and _SCOPE_RE.fullmatch(s) and s not in scopes:
            scopes.append(s)
        if len(scopes) >= MAX_SCOPES:
            break
    return {"ok": True, "why": "", "products": products, "products_listed": listed, "scopes": scopes,
            "expires_at": _iso(data.get("exp")), "issued_at": _iso(data.get("iat"))}


def token_of(client: Any) -> Optional[str]:
    """The access token the OneAPI client signed in with (ZscalerClient._auth_token), or None."""
    tok = getattr(client, "__dict__", {}).get("_auth_token") if hasattr(client, "__dict__") else None
    return tok if isinstance(tok, str) and tok else None


def token_access(client: Any, auth_method: str = "oneapi") -> Dict[str, Any]:
    """What the sign-in token says, for /api/tenant/check: products and
    role names, nothing else. Reads nothing from the tenant."""
    if str(auth_method or "").lower() == "legacy":
        out = _no_claims("Signed in through the classic ZIA API: there is no OneAPI token. It reaches ZIA only.")
        out["source"] = "classic"
        out["products"] = [{"product": "ZIA", "code": "ZIA", "role": "", "role_id": ""}]
        return out
    out = decode_claims(token_of(client))
    out["source"] = "oneapi"
    return out


def product_label(key: str) -> str:
    return (PRODUCTS.get(key) or {}).get("label", key)


# ── Reads (only what is in scope) ──────────────────────────────────────

def _status_of(resp: Any, err: Any) -> int:
    for obj in (err, resp):
        code = getattr(obj, "status_code", None)
        if isinstance(code, int):
            return code
    try:
        code = resp.get_status() if resp is not None and callable(getattr(resp, "get_status", None)) else None
        if isinstance(code, int):
            return code
    except Exception:  # noqa: BLE001
        pass
    m = re.search(r"\b(40[0-9]|429|5\d\d)\b", str(err or ""))
    return int(m.group(1)) if m else 0


def _body_of(resp: Any, data: Any) -> Any:
    try:
        if resp is not None and callable(getattr(resp, "get_body", None)):
            b = resp.get_body()
            if b is not None:
                return b
    except Exception:  # noqa: BLE001
        pass
    if isinstance(data, list):
        return [x.as_dict() if callable(getattr(x, "as_dict", None)) else x for x in data]
    if callable(getattr(data, "as_dict", None)):
        try:
            return data.as_dict()
        except Exception:  # noqa: BLE001
            return None
    return data


def _ask(fn: Callable[[], Any]) -> Dict[str, Any]:
    """One SDK call: {state: ok|denied|missing|error, code, body}. No error text is kept (it may echo a request)."""
    try:
        res = fn()
    except Exception as e:  # noqa: BLE001 — a failed read is a state, never a crash
        code = _status_of(None, e)
        return {"state": "denied" if code in (401, 403) else "error", "code": code, "body": None}
    if not isinstance(res, tuple) or len(res) != 3:
        return {"state": "error", "code": 0, "body": None}
    data, resp, err = res
    if err is not None:
        code = _status_of(resp, err)
        state = "denied" if code in (401, 403) else "missing" if code in (404, 405) else "error"
        return {"state": state, "code": code, "body": None}
    return {"state": "ok", "code": 200, "body": _body_of(resp, data)}


def _executor(client: Any) -> Any:
    get = getattr(client, "get_request_executor", None)
    if callable(get):
        return get()
    return getattr(getattr(client, "zia", None), "request_executor", None)   # the classic sign-in's helper


def _raw_get(client: Any, path: str) -> Dict[str, Any]:
    def call():
        ex = _executor(client)
        request, error = ex.create_request("GET", path, {}, {})
        if error:
            return None, None, error
        response, error = ex.execute(request)
        return (response.get_body() if response is not None else None), response, error
    return _ask(call)


def parse_subscriptions(body: Any, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """The tenant's subscriptions, bounded and cleaned: id, plain name, area, status, end date."""
    now = time.time() if now is None else now
    rows = body if isinstance(body, list) else (body.get("list") if isinstance(body, dict) and isinstance(body.get("list"), list) else [])
    out: List[Dict[str, Any]] = []
    for s in rows[:MAX_SUBSCRIPTIONS]:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        sid = str(sid) if isinstance(sid, (str, int)) and not isinstance(sid, bool) else ""
        if not _SKU_RE.fullmatch(sid):
            continue
        status = _clean_text(s.get("status"), 32)
        active = s.get("subscribed") is not False and not re.search(r"EXPIRED|CANCEL", status, re.I)
        end = s.get("endDate")
        end_ts = None
        # Bounded before any arithmetic, as in _iso: a JSON integer has no size
        # limit, and one too large for a float raises OverflowError.
        if isinstance(end, (int, float)) and not isinstance(end, bool) and 0 < end < 32503680000 * 1000:
            end_ts = end / 1000.0 if end > 1e11 else float(end)
        area, name = SKU_INFO.get(sid, ("", ""))
        if not name and sid.startswith("ZIA_ISO_"):
            area, name = "Isolation", "Cloud Browser Isolation"
        out.append({"id": sid, "name": name or _clean_text(s.get("sku"), 80), "area": area or "Other", "status": status, "active": active,
                    "ends_on": (_iso(end_ts) or "")[:10] or None,
                    "ending_soon": bool(active and end_ts and now < end_ts < now + ENDING_SOON_DAYS * 86400)})
    return out


def parse_zia_role(body: Any) -> Optional[Dict[str, Any]]:
    """A ZIA admin role: its name, policy access and feature permissions (known value words only)."""
    if not isinstance(body, dict):
        return None
    fp = body.get("featurePermissions")
    perms = {}
    if isinstance(fp, dict):
        for k, v in list(fp.items())[:200]:
            if isinstance(k, str) and _PERM_RE.fullmatch(k) and v in LEVELS:
                perms[k] = v
    pa = body.get("policyAccess")
    return {"name": _clean_text(body.get("name")), "policy_access": pa if pa in LEVELS else None, "features": perms}


def _zia_level(role: Optional[Dict[str, Any]], alternatives: Iterable[str]) -> Optional[int]:
    """The role's level for one permission (any of its key spellings); None when unknown."""
    if not role:
        return None
    feats = role.get("features") or {}
    vals = [LEVELS[feats[k]] for k in alternatives if k in feats]
    if vals:
        return max(vals)
    if feats:
        return 0   # the role lists permissions and this one is not among them
    pa = role.get("policy_access")
    return LEVELS[pa] if pa in LEVELS else None


def _find_by(rows: Any, name: str, rid: str, name_keys=("name",)) -> Optional[Dict[str, Any]]:
    if isinstance(rows, dict):
        # ZPA lists in an envelope: {"totalPages": "1", "list": [...]} (zpa.role_controller.list_roles's body).
        rows = rows.get("list")
    for r in (rows if isinstance(rows, list) else [])[:1000]:
        if not isinstance(r, dict):
            continue
        if rid and str(r.get("id", "")) == rid:
            return r
        if name and any(str(r.get(k) or "") == name for k in name_keys):
            return r
    return None


def _zpa_classes(role: Dict[str, Any]) -> Dict[str, str]:
    """{friendly class name: FULL|VIEW_ONLY|NONE} of a ZPA role (bounded)."""
    out: Dict[str, str] = {}
    for g in (role.get("classPermissionGroups") or [])[:100] if isinstance(role.get("classPermissionGroups"), list) else []:
        for c in (g.get("classPermissions") or [])[:200] if isinstance(g, dict) and isinstance(g.get("classPermissions"), list) else []:
            if not isinstance(c, dict):
                continue
            ct = c.get("classType") if isinstance(c.get("classType"), dict) else {}
            name = _clean_text(ct.get("friendlyName") or ct.get("name"), 80)
            perm = c.get("permission") if isinstance(c.get("permission"), dict) else {}
            t = perm.get("type")
            if name and t in ("FULL", "VIEW_ONLY", "NONE"):
                out[name] = t
    return out


def _stop(cancel: Any) -> None:
    from data_flow import stop_requested
    if stop_requested(cancel):
        raise Stopped("stopped")


class Stopped(RuntimeError):
    """Stop was clicked: nothing more is read and no partial result is kept."""


def in_scope_products(scopes: Iterable[str]) -> List[str]:
    sc = {str(s) for s in scopes or []}
    return [k for k in PROBED if sc & set(PRODUCTS[k]["scopes"])]


def read(client: Any, scopes: Iterable[str], *, auth_method: str = "oneapi", customer_id: str = "",
         log: Optional[Callable[[str], None]] = None, cancel: Any = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Every readiness read for the products in scope, one at a time.
    Returns {claims, probes: {product: {...}}, in_scope: [...]} with no
    token and no error text from the tenant. Stop raises Stopped."""
    say = log or (lambda m: None)
    legacy = str(auth_method or "").lower() == "legacy"
    claims = token_access(client, auth_method)
    wanted = in_scope_products(scopes)
    probes: Dict[str, Dict[str, Any]] = {}
    roles = {p["product"]: p for p in claims.get("products") or []}

    if "ZIA" in wanted:
        _stop(cancel)
        say("ZIA: reading the licences (subscriptions)…")
        sub = _raw_get(client, SUBSCRIPTIONS_PATH)
        zia: Dict[str, Any] = {"responds": sub["state"] == "ok" or sub["state"] == "missing", "subscriptions_state": sub["state"],
                               "subscriptions_code": sub["code"], "subscriptions": parse_subscriptions(sub["body"], now) if sub["state"] == "ok" else None,
                               "role": None, "role_state": "not_read"}
        say(f"ZIA licences: {'read' if sub['state'] == 'ok' else _state_words(sub)}.")
        tok = roles.get("ZIA") or {}
        if legacy:
            zia["role_state"] = "classic"
            say("ZIA role: the classic sign-in has no API role to read.")
        else:
            _stop(cancel)
            say("ZIA: reading the API client's role…")
            res = None
            if tok.get("role_id", "").isdigit():
                res = _ask(lambda: client.zia.admin_roles.get_role(int(tok["role_id"])))
            if (res is None or res["state"] != "ok") and tok.get("role"):
                lst = _ask(lambda: client.zia.admin_roles.list_roles(query_params={"include_api_role": True}))
                hit = _find_by(lst["body"], tok["role"], "") if lst["state"] == "ok" else None
                if hit and str(hit.get("id", "")).isdigit():
                    _stop(cancel)
                    res = _ask(lambda: client.zia.admin_roles.get_role(int(hit["id"])))
                elif res is None:
                    res = lst if lst["state"] != "ok" else {"state": "not_found", "code": 0, "body": None}
            if res is None:
                res = {"state": "no_role", "code": 0, "body": None}
            zia["role"] = parse_zia_role(res["body"]) if res["state"] == "ok" else None
            zia["role_state"] = "ok" if zia["role"] else res["state"]
            zia["role_code"] = res.get("code", 0)
            if sub["state"] == "error" and res["state"] == "ok":
                zia["responds"] = True
            if res["state"] == "ok":
                zia["responds"] = True
            say(f"ZIA role: {'read' if zia['role'] else _state_words(res)}.")
        probes["ZIA"] = zia

    if "ZCC" in wanted:
        if legacy:
            probes["ZCC"] = {"responds": False, "state": "classic"}
        else:
            _stop(cancel)
            say("Client Connector: reading the company information…")
            ci = _ask(lambda: client.zcc.company.get_company_info())
            body = ci["body"][0] if isinstance(ci["body"], list) and ci["body"] else ci["body"]
            flags = {}
            if isinstance(body, dict):
                for k, label in ZCC_FLAGS.items():
                    v = body.get(k)
                    if isinstance(v, bool) or v in (0, 1, "0", "1", "true", "false"):
                        flags[label] = str(v).lower() in ("true", "1")
            _stop(cancel)
            say("Client Connector: reading the admin roles…")
            rl = _ask(lambda: client.zcc.admin_user.list_admin_roles())
            tok = roles.get("ZCC") or {}
            hit = _find_by(rl["body"], tok.get("role", ""), tok.get("role_id", ""), ("roleName", "name")) if rl["state"] == "ok" else None
            fields = {}
            if hit:
                for k, label in ZCC_FIELDS.items():
                    v = hit.get(k)
                    if str(v) in ("0", "1", "2"):
                        fields[label] = int(v)
            probes["ZCC"] = {"responds": ci["state"] == "ok" or rl["state"] == "ok", "state": ci["state"], "code": ci["code"],
                             "flags": flags, "roles_state": rl["state"], "role_found": bool(hit), "role_fields": fields}
            say(f"Client Connector: {'answered' if probes['ZCC']['responds'] else _state_words(ci)}.")

    if "ZPA" in wanted:
        if legacy:
            probes["ZPA"] = {"responds": False, "state": "classic"}
        elif not str(customer_id or "").strip():
            probes["ZPA"] = {"responds": False, "state": "no_customer_id"}
            say("ZPA: not read, the ZPA customer ID is empty.")
        else:
            _stop(cancel)
            say("ZPA: reading the roles…")
            rl = _ask(lambda: client.zpa.role_controller.list_roles())
            tok = roles.get("ZPA") or {}
            hit = _find_by(rl["body"], tok.get("role", ""), tok.get("role_id", "")) if rl["state"] == "ok" else None
            probes["ZPA"] = {"responds": rl["state"] == "ok", "state": rl["state"], "code": rl["code"], "role_found": bool(hit),
                             "classes": _zpa_classes(hit) if hit else {}}
            say(f"ZPA: {'answered' if rl['state'] == 'ok' else _state_words(rl)}.")

    if "ZDX" in wanted:
        if legacy:
            probes["ZDX"] = {"responds": False, "state": "classic"}
        else:
            _stop(cancel)
            say("ZDX: one read to see whether it answers…")
            r = _ask(lambda: client.zdx.admin.list_departments())
            probes["ZDX"] = {"responds": r["state"] == "ok", "state": r["state"], "code": r["code"]}
            say(f"ZDX: {'answered' if r['state'] == 'ok' else _state_words(r)}.")

    if "ZINSIGHTS" in wanted:
        if legacy:
            probes["ZINSIGHTS"] = {"responds": False, "state": "classic"}
        else:
            _stop(cancel)
            say("Z-Insights: one small question to see whether it answers (the numbers are not kept)…")
            end = int((time.time() if now is None else now) * 1000)
            r = _ask(lambda: client.zins.web_traffic.get_no_grouping(start_time=end - 3600_000, end_time=end, traffic_unit="TRANSACTIONS"))
            probes["ZINSIGHTS"] = {"responds": r["state"] == "ok", "state": r["state"], "code": r["code"]}
            say(f"Z-Insights: {'answered' if r['state'] == 'ok' else _state_words(r)}.")

    if "ZGUARD" in wanted:
        _stop(cancel)
        probes["ZGUARD"] = ai_guard_probe(client, legacy=legacy, log=say)

    return {"claims": claims, "probes": probes, "in_scope": wanted, "auth_method": "legacy" if legacy else "oneapi",
            "customer_id_given": bool(str(customer_id or "").strip())}


def ai_guard_probe(client: Any, *, legacy: bool = False, log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """AI Guard's own readiness (ai_guard.readiness(client), when that module
    is installed), reduced to a few safe fields. Without the module, or on
    the classic sign-in, AI Guard is judged from the token alone."""
    say = log or (lambda m: None)
    if legacy:
        return {"responds": False, "state": "classic"}
    try:
        mod = importlib.import_module("ai_guard")
    except Exception:  # noqa: BLE001 — not installed on this build
        return {"responds": False, "state": "not_checked"}
    fn = getattr(mod, "readiness", None)
    if not callable(fn):
        return {"responds": False, "state": "not_checked"}
    say("AI Guard: asking whether it answers…")
    try:
        # Only the AI Guard side: ZIA is read by its own probe.
        res = fn(client, zia=False, aiguard=True)
    except Exception as e:  # noqa: BLE001
        code = _status_of(None, e)
        return {"responds": False, "state": "denied" if code in (401, 403) else "error", "code": code}
    res = res if isinstance(res, dict) else {}
    ag = res.get("aiguard") if isinstance(res.get("aiguard"), dict) else {}
    if ag:   # ai_guard.readiness: {aiguard: {read, reachable, error}, checks: [...]}
        res = {"ok": ag.get("reachable") is True, "detail": ag.get("error") or ""}
    ok = bool(res.get("ok", res.get("responds", res.get("reachable", False))))
    state = _clean_text(res.get("state") or res.get("status") or ("ok" if ok else "error"), 24).lower()
    return {"responds": ok, "state": state if re.fullmatch(r"[a-z_]{1,24}", state) else ("ok" if ok else "error"),
            "detail": _clean_text(res.get("detail") or res.get("message"), 200)}


def _state_words(r: Dict[str, Any]) -> str:
    st, code = r.get("state"), r.get("code") or 0
    if st == "denied":
        return f"refused (HTTP {code}): the API client is not allowed"
    if st == "missing":
        return f"not available on this tenant (HTTP {code})"
    if st == "no_role":
        return "the token names no ZIA role, so the role was not read"
    if st == "not_found":
        return "the token's role is not in the role list"
    return f"no usable answer{f' (HTTP {code})' if code else ''}"


# ── The verdict ────────────────────────────────────────────────────────

def _steps_product(product: str) -> List[str]:
    label = product_label(product)
    return ["Open ZIdentity (admin.zidentity.net) and go to Integration > API Clients.",
            "Open the API client this app signs in with and edit it.",
            f"Add a {label} role to it: read-only is enough to assess; full access only for the features that change the tenant.",
            "Save, then click Authenticate here again: the readiness check runs again by itself."]


def _steps_zia(role: str, perms: List[Tuple[str, str]]) -> List[str]:
    what = "; ".join(f"{ZIA_PERMS.get(k, k)} to {w}" for k, w in perms)
    return ["In the ZIA Admin Portal, go to Administration > Role Management.",
            f"Edit the role {role or 'the API client uses (its name is shown above)'}.",
            f"Set {what}.",
            "Save and activate, then click Authenticate here again."]


def _steps_licence(licence: str, skus: Iterable[str]) -> List[str]:
    ids = ", ".join(skus)
    return [f"Ask your Zscaler account team to add {licence} to this tenant (subscription {ids}).",
            "Once it shows in the licence list above, click Authenticate here again."]


def _steps_customer_id() -> List[str]:
    return ["No admin needed: copy the ZPA customer ID from the ZPA admin URL (the long number after /app/).",
            "Paste it into ZPA customer ID on Connect to the tenant, then click Authenticate again."]


def _sku_set(zia: Optional[Dict[str, Any]]) -> Optional[set]:
    subs = (zia or {}).get("subscriptions")
    if subs is None:
        return None
    return {s["id"] for s in subs if s.get("active")}


def _product_state(product: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """Access to one product: write | read | none | unknown | not_in_scope, with why."""
    claims = facts["claims"]
    tok = {p["product"]: p for p in claims.get("products") or []}
    probe = (facts.get("probes") or {}).get(product)
    in_scope = product in (facts.get("in_scope") or [])
    has_listing = bool(claims.get("ok") and claims.get("products_listed"))
    legacy = facts.get("auth_method") == "legacy"
    role = (tok.get(product) or {}).get("role", "")
    out = {"product": product, "label": product_label(product), "role": role, "in_token": product in tok,
           "responds": None, "access": "unknown", "why": "", "steps": []}
    if legacy and product != "ZIA":
        out.update(access="none", why="The classic ZIA API sign-in reaches ZIA only. Sign in with a OneAPI API client for this product.")
        return out
    if has_listing and product not in tok:
        out.update(access="none", why=f"The access token lists no {out['label']} role for this API client.", steps=_steps_product(product))
        return out
    if probe is None:
        if product in PROBED and not in_scope:
            out.update(access="not_in_scope", why="Not in scope on the Scope page, so it was not read." + (f" The token gives it the role {role}." if role else ""))
        elif role:
            out.update(access="read", why=f"The token gives this API client the role {role}. Changes were not checked.")
        else:
            out["why"] = "Not checked."
        return out
    out["responds"] = bool(probe.get("responds"))
    state = probe.get("state") or probe.get("subscriptions_state")
    if product == "ZIA":
        r = probe.get("role")
        if probe.get("role_state") == "denied" and probe.get("subscriptions_state") == "denied":
            out.update(access="none", why="ZIA refused every read (HTTP 401 or 403).", steps=_steps_product(product))
        elif r:
            levels = [LEVELS.get(v, 0) for v in (r.get("features") or {}).values()] or ([LEVELS[r["policy_access"]]] if r.get("policy_access") in LEVELS else [])
            top = max(levels) if levels else None
            out["access"] = {2: "write", 1: "read", 0: "none"}.get(top, "unknown")
            out["why"] = f"Role {r.get('name') or role}: " + {"write": "it can read and change at least part of the policy.", "read": "it can read but not change.",
                                                             "none": "it grants no ZIA feature.", "unknown": "its permissions could not be told apart."}[out["access"]]
            if out["access"] == "none":
                out["steps"] = _steps_zia(r.get("name") or role, [("INLINE_DLP", "read only")])
        elif probe.get("role_state") == "classic":
            out.update(access="read" if out["responds"] else "unknown", why="Classic ZIA API sign-in: the admin's role cannot be read through the API, so changes are not checked here.")
        else:
            out.update(access="read" if out["responds"] else "unknown",
                       why="ZIA answered, but the API client's role could not be read (it needs Role management or Administrator management, read only), so changes are not checked." if out["responds"]
                       else "ZIA did not give a usable answer.")
        return out
    if state == "classic":
        out.update(access="none", why="The classic ZIA API sign-in reaches ZIA only.")
    elif state == "no_customer_id":
        out.update(access="unknown", why="Not read: the ZPA customer ID is empty.", steps=_steps_customer_id())
    elif state == "denied":
        out.update(access="none", why=f"{out['label']} refused the read (HTTP {probe.get('code') or 403}).", steps=_steps_product(product))
    elif state == "not_checked":
        out.update(access="read" if role else "unknown", why=(f"The token gives this API client the role {role}." if role else "Not checked.") + " AI Guard itself was not asked on this build.")
    elif out["responds"]:
        out["access"] = "read"
        if product == "ZPA":
            classes = probe.get("classes") or {}
            if classes and all(v == "FULL" for v in classes.values()) or (not classes and re.search(r"full|super", role, re.I)):
                out["access"] = "write"
            out["why"] = f"Role {role or '(unnamed)'}: " + ("full access." if out["access"] == "write" else "it can read; see below for what it cannot change.")
        elif product == "ZCC":
            f = probe.get("role_fields") or {}
            out["access"] = "write" if f and all(v == 2 for v in f.values()) else "read"
            out["why"] = f"Role {role or '(unnamed)'}: " + ("full access to what this app uses." if out["access"] == "write" else "it can read.")
        else:
            out["why"] = f"{out['label']} answered" + (f" for the role {role}." if role else ".")
    else:
        out.update(access="unknown", why=f"{out['label']} gave no usable answer" + (f" (HTTP {probe.get('code')})." if probe.get("code") else "."))
    return out


def _zia_need(role: Optional[Dict[str, Any]], needs: List[Tuple[str, ...]], level: int) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], bool]:
    """(missing, read_only, unknown) of a ZIA role against needs at `level`."""
    missing, ro, unknown = [], [], False
    for alts in needs:
        lv = _zia_level(role, alts)
        if lv is None:
            unknown = True
        elif lv < level:
            (ro if (level == 2 and lv == 1) else missing).append((alts[0], "full" if level == 2 else "read only"))
    return missing, ro, unknown


def _feature(key: str, label: str, product: str, facts: Dict[str, Any], products: Dict[str, Dict[str, Any]], *,
             needs: List[Tuple[str, ...]], optional: List[Tuple[str, ...]], level: int, skus: Iterable[str] = (),
             soft_skus: Iterable[str] = (), licence: str = "", kind: str = "scope", extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    p = products[product]
    zia = (facts.get("probes") or {}).get("ZIA") or {}
    role = zia.get("role") if product == "ZIA" else None
    out = {"key": key, "label": label, "kind": kind, "product": product, "status": "ok", "why": "", "steps": [], "notes": []}
    if extra:
        out.update(extra)
    if p["access"] == "not_in_scope" and kind in ("scope", "write"):
        # A builder for a product that is not in scope was not checked (and
        # refuses to run until it is): never "Will work" on no evidence.
        out.update(status="not_in_scope", why=f"{p['label']} is not in scope, so it was not checked." +
                   (" Tick it on the Scope page to use this." if kind == "write" else ""))
        return out
    if p["access"] == "none":
        out.update(status="blocked", why=p["why"], steps=p["steps"] or _steps_product(product))
        return out
    if product == "ZIA" and needs:
        missing, ro, unknown = _zia_need(role, needs, level)
        if missing or (ro and level == 2):
            words = "change" if level == 2 else "read"
            gaps = missing + ro
            partial = level == 1 and len(missing) < len(needs)   # a scope with some reads refused still runs the rest
            out.update(status="partial" if partial else "read_only" if (not missing and ro) else "blocked",
                       why=f"The API client's ZIA role cannot {words}: " + ", ".join(ZIA_PERMS.get(k, k) for k, _ in gaps) + ".",
                       steps=_steps_zia((role or {}).get("name") or p.get("role", ""), gaps))
            return out
        if unknown:
            out.update(status="unknown", why="The API client's ZIA role could not be read, so this was not checked." if p["access"] != "not_in_scope"
                       else "ZIA is not in scope on the Scope page, so the role was not read.")
        for alts in optional:
            lv = _zia_level(role, alts)
            if lv is not None and lv < level:
                out["notes"].append(f"Without {ZIA_PERMS.get(alts[0], alts[0])} ({'full' if level == 2 else 'read only'}) that part is skipped and shown as not permitted.")
    elif p["access"] == "unknown" and out["status"] == "ok":
        out.update(status="unknown", why=p["why"] or "Not checked.", steps=p["steps"])
    if level == 2 and out["status"] == "ok" and p["access"] == "read" and product != "ZIA":
        out.update(status="read_only", why=f"{p['label']}: the role can read, but changes need full access.", steps=_steps_product(product))
    have = _sku_set(zia)
    if skus and have is not None and have and not (have & set(skus)) and out["status"] in ("ok", "unknown", "read_only"):
        out.update(status="not_licensed", why=f"The licence list does not show {licence or SKU_INFO.get(next(iter(skus)), ('', next(iter(skus))))[1]}.",
                   steps=_steps_licence(licence or SKU_INFO.get(next(iter(skus)), ("", next(iter(skus))))[1], skus))
    elif soft_skus and have is not None and have and not (have & set(soft_skus)):
        out["notes"].append(f"The licence list does not show {licence or 'its licence'}: the checks that need it will say so.")
    return out


def evaluate(facts: Dict[str, Any]) -> Dict[str, Any]:
    """Turn the reads into the readiness answer: products, licences, every
    Scope page key and every write feature with its status (ok, read_only,
    blocked, not_licensed, unknown, not_in_scope) and the plain steps."""
    products = OrderedDict((k, _product_state(k, facts)) for k in PRODUCTS)
    zia = (facts.get("probes") or {}).get("ZIA") or {}
    scopes: List[Dict[str, Any]] = []
    for key, spec in SCOPE_FEATURES.items():
        sp = SCOPE_PERMISSIONS.get(key, {})
        label = sp.get("label") or SCOPE_LABELS.get(key, key)
        f = _feature(key, label, spec["product"], facts, products, needs=spec.get("needs", []), optional=spec.get("optional", []),
                     level=1, skus=spec.get("skus", ()), soft_skus=spec.get("soft_skus", ()), licence=spec.get("licence", ""))
        if spec.get("customer_id") and not facts.get("customer_id_given") and f["status"] in ("ok", "unknown"):
            f.update(status="blocked", why="The ZPA customer ID is empty: every ZPA read needs it.", steps=_steps_customer_id())
        if spec.get("oneapi_only") and facts.get("auth_method") == "legacy":
            f.update(status="blocked", why="Needs a OneAPI API client: the classic ZIA API cannot read it.", steps=_steps_product(spec["product"]))
        scopes.append(f)
    kinds = OrderedDict()
    for k, spec in WRITE_KINDS.items():
        if spec.get("info"):
            kinds[k] = {"key": k, "label": k, "kind": "write_kind", "product": "ZIA", "status": "info", "why": spec["info"], "steps": [], "notes": []}
            continue
        needs = list(spec.get("needs", []))
        f = _feature(k, k, "ZIA", facts, products, needs=needs, optional=[], level=2, skus=spec.get("skus", ()), kind="write_kind")
        if spec.get("policy_access") and f["status"] == "ok":
            pa = ((zia.get("role") or {}).get("policy_access"))
            if pa in LEVELS and LEVELS[pa] < 2:
                f.update(status="read_only", why="The role's policy access is not full, so it cannot change policy.",
                         steps=_steps_zia((zia.get("role") or {}).get("name", ""), [("INLINE_DLP", "full")]))
            elif pa not in LEVELS:
                f.update(status="unknown", why="The role's policy access could not be read.")
        kinds[k] = f
    writes: List[Dict[str, Any]] = []
    for key, spec in WRITE_FEATURES.items():
        if spec.get("product") in ("ZCC", "ZDX", "ZGUARD"):
            writes.append(_feature(key, spec["label"], spec["product"], facts, products, needs=[], optional=[], level=2, kind="write"))
            continue
        if spec.get("product") == "ZPA":
            f = _feature(key, spec["label"], "ZPA", facts, products, needs=[], optional=[], level=2, kind="write")
            if "ZPA" in (facts.get("in_scope") or []) and not facts.get("customer_id_given") and f["status"] in ("ok", "unknown", "read_only"):
                # as the zpa scope: every ZPA call names the customer ID, so nothing here can run without it
                f.update(status="blocked", why="The ZPA customer ID is empty: every ZPA read and change needs it.", steps=_steps_customer_id())
            classes = ((facts.get("probes") or {}).get("ZPA") or {}).get("classes") or {}
            weak = [n for n, t in classes.items() if any(c.lower() in n.lower() for c in spec.get("zpa_classes", ())) and t != "FULL"]
            if weak and f["status"] in ("ok", "read_only"):
                f.update(status="read_only", why="The ZPA role cannot change: " + ", ".join(weak) + ".",
                         steps=["In the ZPA Admin Portal, go to Administration > Role Management.",
                                f"Edit the role {products['ZPA']['role'] or 'the API client uses'} and give Full access to: {', '.join(weak)}.",
                                "Save, then click Authenticate here again."])
            elif f["status"] == "read_only" and not weak and classes:
                f.update(status="ok", why="", steps=[])
            writes.append(f)
            continue
        req = [kinds[k] for k in spec["kinds"]]
        rank = {"blocked": 5, "not_licensed": 4, "read_only": 3, "unknown": 2, "ok": 0, "info": 0, "not_in_scope": 1}
        if spec.get("any"):
            good = [r for r in req if r["status"] == "ok"]
            if good:
                cannot = [r["key"] for r in req if r["status"] != "ok"]
                f = {"status": "ok", "why": "", "steps": [], "notes": [f"It cannot change: {', '.join(cannot)}."] if cannot else []}
            else:
                mildest = min(req, key=lambda r: rank.get(r["status"], 0))
                f = {"status": mildest["status"], "why": "None of the policies it changes is writable. " + mildest["why"],
                     "steps": mildest["steps"], "notes": []}
        else:
            worst = max(req, key=lambda r: rank.get(r["status"], 0))
            f = {"status": worst["status"], "why": worst["why"], "steps": worst["steps"], "notes": []}
            for k in spec.get("optional_kinds", ()):
                if kinds[k]["status"] not in ("ok", "info"):
                    f["notes"].append(f"The {k} channel: {kinds[k]['why'] or kinds[k]['status']}")
        f.update(key=key, label=spec["label"], kind="write", product="ZIA", kinds=list(spec["kinds"]))
        writes.append(f)
    subs = zia.get("subscriptions")
    licences = {"read": subs is not None, "state": zia.get("subscriptions_state") or ("not_in_scope" if "ZIA" not in (facts.get("in_scope") or []) else "not_read"),
                "rows": sorted(subs or [], key=lambda s: (s["area"], s["id"])),
                "ending_soon": [s["id"] for s in subs or [] if s.get("ending_soon")],
                "zcc_flags": ((facts.get("probes") or {}).get("ZCC") or {}).get("flags") or {}}
    claims = facts.get("claims") or {}
    blocked = [f for f in scopes + writes if f["status"] in ("blocked", "not_licensed")]
    return {"products": list(products.values()), "licences": licences, "scopes": scopes, "writes": writes,
            "write_kinds": list(kinds.values()), "in_scope": list(facts.get("in_scope") or []),
            "token": {"ok": claims.get("ok", False), "why": claims.get("why", ""), "source": claims.get("source", ""),
                      "scopes": claims.get("scopes", []), "expires_at": claims.get("expires_at"), "products_listed": claims.get("products_listed", False),
                      "verified": False},
            "summary": summary_line(list(products.values()), blocked),
            "blocked_count": len(blocked)}


def summary_line(products: List[Dict[str, Any]], blocked: List[Dict[str, Any]]) -> str:
    words = {"write": "can read and change", "read": "can read", "none": "no access", "unknown": "not checked", "not_in_scope": "not in scope"}
    parts = [f"{p['label'].split(' (')[0]}: {words.get(p['access'], p['access'])}" for p in products if p["access"] != "not_in_scope" and (p["in_token"] or p["responds"] is not None or p["access"] == "none")]
    head = "; ".join(parts) + "." if parts else "Nothing in scope was checked."
    if blocked:
        return head + f" {len(blocked)} feature{'s' if len(blocked) != 1 else ''} will not work until an admin adds access or a licence."
    return head + " Everything checked will work."


def run(client: Any, scopes: Iterable[str], *, auth_method: str = "oneapi", customer_id: str = "",
        log: Optional[Callable[[str], None]] = None, cancel: Any = None, label: str = "", now: Optional[float] = None) -> Dict[str, Any]:
    """The readiness job: the reads, then the verdict. Stop ends it as
    stopped with no partial result."""
    say = log or (lambda m: None)
    try:
        facts = read(client, scopes, auth_method=auth_method, customer_id=customer_id, log=say, cancel=cancel, now=now)
        _stop(cancel)
    except Stopped:
        say("STOPPED — you clicked Stop; nothing more is read and no partial result is kept.")
        return {"status": "stopped", "tenant_label": label}
    out = evaluate(facts)
    out.update(status="done", tenant_label=label,
               checked_at=datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    say("Done: " + out["summary"])
    return out


def catalog() -> Dict[str, Any]:
    """The static map (no tenant): every Scope page key and every write
    feature with the product, ZIA permissions and licence it needs."""
    def perms(needs):
        return [{"keys": list(alts), "label": ZIA_PERMS.get(alts[0], alts[0])} for alts in needs]
    scopes = []
    for key, spec in SCOPE_FEATURES.items():
        sp = SCOPE_PERMISSIONS.get(key, {})
        scopes.append({"key": key, "label": sp.get("label") or SCOPE_LABELS.get(key, key), "product": spec["product"],
                       "product_label": product_label(spec["product"]), "zia_read": perms(spec.get("needs", [])),
                       "zia_optional": perms(spec.get("optional", [])), "skus": list(spec.get("skus", ())),
                       "licence": spec.get("licence") or sp.get("license_required", ""), "customer_id": bool(spec.get("customer_id"))})
    kinds = [{"kind": k, "zia_write": perms(s.get("needs", [])), "skus": list(s.get("skus", ())), "note": s.get("info", "")
              or ("No separate permission is documented: the role's policy access must be full." if s.get("policy_access") else "")}
             for k, s in WRITE_KINDS.items()]
    writes = [{"key": k, "label": s["label"], "product": s.get("product", "ZIA"), "kinds": list(s.get("kinds", ())),
               "optional_kinds": list(s.get("optional_kinds", ())), "zpa_classes": list(s.get("zpa_classes", ()))} for k, s in WRITE_FEATURES.items()]
    return {"products": [{"key": k, "label": p["label"], "scopes": list(p["scopes"])} for k, p in PRODUCTS.items()],
            "scopes": scopes, "write_kinds": kinds, "writes": writes,
            "note": ("The access token is read without checking its signature: it is used to show what will work and to grey out "
                     "what will not, never to allow anything. The tenant decides on every call.")}


# ── Required API access (/permissions): the live part ──────────────────
STATUS_WORDS = {"ok": "Will work", "partial": "Works in part", "read_only": "Can read, cannot change", "blocked": "Will not work",
                "not_licensed": "Not licensed", "unknown": "Not checked", "not_in_scope": "Not in scope", "info": "For information"}
ACCESS_WORDS = {"write": "Can read and change", "read": "Can read", "none": "No access", "unknown": "Not checked", "not_in_scope": "Not in scope"}
_PROBLEM = ("blocked", "not_licensed", "read_only", "partial")


def _e(v: Any) -> str:
    import html
    return html.escape(str(v if v is not None else ""), quote=True)


def _steps_html(steps: Iterable[str]) -> str:
    steps = [s for s in steps or [] if s]
    if not steps:
        return ""
    return '<details class="rd-steps"><summary>Ask your admin: the steps</summary><ol>' + "".join(f"<li>{_e(s)}</li>" for s in steps) + "</ol></details>"


def scope_badge(f: Optional[Dict[str, Any]]) -> str:
    """One line under a scope card of /permissions: what the last readiness check said for it."""
    if not f:
        return ""
    cls = "bad" if f.get("status") in _PROBLEM else "good" if f.get("status") == "ok" else "neutral"
    why = f" {_e(f.get('why'))}" if f.get("why") else ""
    return (f'<div class="rd-badge {cls}"><strong>Readiness: {_e(STATUS_WORDS.get(f.get("status"), f.get("status")))}.</strong>{why}'
            f'{_steps_html(f.get("steps"))}</div>')


LOCKED_NOTE = ("The live answers are shown only to a browser that has unlocked this app with its UI token (or signed in): open the app "
               "from the launcher, or paste the token from ui_token.txt, then reload this page. The minimum access per scope is listed below.")


def html_section(results: List[Dict[str, Any]], locked: bool = False) -> str:
    """The live readiness block of /permissions, from the latest answers
    (newest first). Every value is escaped; an empty state says why.
    `locked`: the caller has not passed the UI token or sign-in gate, so no
    answer is shown (they name a tenant, its roles and its licences)."""
    head = ('<section class="rd" aria-labelledby="rdH"><h2 id="rdH">What this API client can do now</h2>'
            '<p class="lead">Checked right after you click Authenticate on the Start page: the products and roles in the access token '
            '(read without checking its signature, for display only) and a few reads for what is in scope (licences, the API role). '
            'Click Authenticate again to refresh, then reload this page.</p>')
    if locked:
        return head + f'<p class="rd-empty">{_e(LOCKED_NOTE)}</p></section>'
    if not results:
        return head + ('<p class="rd-empty">No readiness check has run on this server yet, so there is nothing live to show. Sign in with '
                       'Authenticate on the Start page; the check runs by itself and its answer appears here. The minimum access per scope is listed below.</p></section>')
    parts = [head]
    for i, r in enumerate(results[:3]):
        parts.append(_one_result(r, i))
    parts.append("</section>")
    return "".join(parts)


def _one_result(r: Dict[str, Any], i: int) -> str:
    tid = f"rd{i}"
    rows = []
    for p in r.get("products") or []:
        if p.get("access") == "not_in_scope" and not p.get("in_token"):
            continue
        answers = "Yes" if p.get("responds") else "No" if p.get("responds") is False else "Not asked"
        rows.append(f'<tr><th scope="row">{_e(p.get("label"))}</th><td><span class="rd-chip {_e(p.get("access"))}">{_e(ACCESS_WORDS.get(p.get("access"), p.get("access")))}</span></td>'
                    f'<td>{_e(p.get("role") or "—")}</td><td>{answers}</td><td>{_e(p.get("why"))}{_steps_html(p.get("steps"))}</td></tr>')
    prod = (f'<div class="rd-wrap" tabindex="0" role="region" aria-label="Products"><table class="rd-t"><caption>Per product: access from the token and the reads</caption>'
            '<thead><tr><th scope="col">Product</th><th scope="col">Access</th><th scope="col">Role</th><th scope="col">Answers</th><th scope="col">Why, and what to do</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>') if rows else '<p class="rd-empty">No product was in the token or in scope, so there is no product to list.</p>'
    lic = r.get("licences") or {}
    if lic.get("read") and lic.get("rows"):
        lrows = "".join(f'<tr><td>{_e(s.get("area"))}</td><td>{_e(s.get("name") or "—")}</td><td><code>{_e(s.get("id"))}</code></td>'
                        f'<td>{"Active" if s.get("active") else _e(s.get("status") or "Not active")}</td><td>{_e(s.get("ends_on") or "—")}{" (ends soon)" if s.get("ending_soon") else ""}</td></tr>'
                        for s in lic["rows"])
        lic_html = (f'<div class="rd-wrap" tabindex="0" role="region" aria-label="Licences"><table class="rd-t"><caption>Licences and SKUs (ZIA subscriptions)</caption>'
                    '<thead><tr><th scope="col">Area</th><th scope="col">Licence</th><th scope="col">Subscription (SKU)</th><th scope="col">State</th><th scope="col">Ends</th></tr></thead>'
                    f'<tbody>{lrows}</tbody></table></div>')
    elif lic.get("read"):
        lic_html = '<p class="rd-empty">ZIA answered with an empty licence list, so there is no licence to show.</p>'
    else:
        why = {"not_in_scope": "ZIA is not in scope on the Scope page, so the licences were not read.",
               "denied": "ZIA refused to list the licences (the API role may not include it); features are not greyed out for licences."}.get(
            lic.get("state"), "The licence list could not be read on this tenant, so licences are not checked.")
        lic_html = f'<p class="rd-empty">{_e(why)}</p>'
    flags = lic.get("zcc_flags") or {}
    if flags:
        lic_html += '<p class="rd-flags">Client Connector says: ' + "; ".join(f"{_e(k)}: {'yes' if v else 'no'}" for k, v in flags.items()) + ".</p>"
    feats = (r.get("scopes") or []) + (r.get("writes") or [])
    gaps = [f for f in feats if f.get("status") in _PROBLEM]
    good = [f for f in feats if f.get("status") == "ok"]
    other = [f for f in feats if f.get("status") in ("unknown",)]
    gap_html = "".join(
        f'<li><strong>{_e(f.get("label"))}</strong> <span class="rd-chip {_e(f.get("status"))}">{_e(STATUS_WORDS.get(f.get("status")))}</span>'
        f'<span class="rd-kind">{"Scope page" if f.get("kind") == "scope" else "Changes the tenant"}</span><div>{_e(f.get("why"))}</div>'
        + "".join(f'<div class="rd-note">{_e(n)}</div>' for n in f.get("notes") or []) + f'{_steps_html(f.get("steps"))}</li>' for f in gaps)
    gaps_block = (f'<h4>What the gaps block in this app</h4><ul class="rd-gaps">{gap_html}</ul>' if gaps
                  else '<p class="rd-ok">Nothing that was checked is blocked.</p>')
    tail = ""
    if good:
        tail += '<p class="rd-flags"><strong>Will work:</strong> ' + ", ".join(_e(f.get("label")) for f in good) + ".</p>"
    if other:
        tail += '<p class="rd-flags"><strong>Not checked:</strong> ' + ", ".join(_e(f.get("label")) for f in other) + " (their product was not in scope or its role could not be read).</p>"
    tok = r.get("token") or {}
    tnote = "" if tok.get("ok") else f'<p class="rd-flags">{_e(tok.get("why"))}</p>'
    return (f'<article class="rd-card" aria-labelledby="{tid}"><h3 id="{tid}">{_e(r.get("tenant_label") or "Tenant")} '
            f'<span class="service">· checked {_e((r.get("checked_at") or "").replace("T", " ").replace("Z", " UTC"))}</span></h3>'
            f'<p>{_e(r.get("summary"))}</p>{tnote}{prod}{lic_html}{gaps_block}{tail}</article>')
