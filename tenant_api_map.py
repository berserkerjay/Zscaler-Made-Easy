"""Tenant API map: which Zscaler features this tenant has, and which API
reads the signed-in API client may make, found by asking.

A SEPARATE tool from the licence and editions check, and a separate action
from the assessment: the admin clicks "Map this tenant's APIs", is shown
every endpoint that will be read, and confirms. Nothing else reads this way.

What it does
  * Reads the endpoint catalogue (tenant_api_catalogue.json: every GET
    endpoint of the installed zscaler-sdk-python, made by
    tools/build_tenant_api_catalogue.py and checked against the installed SDK
    by tests/test_tenant_api_map.py) and keeps the ones that need no object
    id. Endpoints that need an id, and those that return credentials, one-time
    passwords, passwords, keys or exports, are skipped (skip_reason).
  * Sends GET requests only, one at a time, at most DEFAULT_RPS per second
    (MAX_RPS at the most), through the app's own signed-in client (the same
    sign-in every page uses, including the shared sign-in). It never asks for
    credentials and never signs in by itself. ReadOnlyClient has no write
    method at all, and refuses a path that is not in the confirmed plan.
  * Stop ends it at once; nothing partial is kept.
  * Turns each answer into a verdict (2xx present; 404 or a "not subscribed"
    code not licensed or not enabled; 401/403 no permission; anything else an
    error) and each feature's verdict into the answer of its deciding endpoint.

What it keeps: HTTP status, the number of items, the top-level field NAMES of
the answer and a fixed-vocabulary error word. Never a value, an id, a name,
a token or a secret: a response body is read in memory, summarised by
summarise() and dropped.

Saved per tenant label with the time, sealed through store_crypto like the
app's other stores (history_path); the newest KEEP_PER_TENANT are kept.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

import csv_safe
import safe_files
import store_crypto

ROOT = os.path.dirname(os.path.abspath(__file__))
CATALOGUE_FILE = os.path.join(ROOT, "tenant_api_catalogue.json")

# ── limits ───────────────────────────────────────────────────────────
DEFAULT_RPS = 1.0              # requests per second
MIN_RPS, MAX_RPS = 0.1, 5.0    # what the page may ask for
MAX_CONCURRENCY = 1            # one request at a time, and one map at a time per server
ABORT_AFTER_429 = 3            # this many rate-limited answers in a row end the run (Stopped, nothing kept)
MAX_FIELDS = 40                # field names kept per endpoint
MAX_ITEM_SAMPLE = 50           # list items whose keys are read for names
MAX_PLAN = 1200                # endpoints in one plan (the catalogue has ~380 probe-able)
KEEP_PER_TENANT = 3            # saved maps kept per tenant label
KEEP_TENANTS = 20
MAX_FILE_BYTES = 16 * 1024 * 1024

# ── verdicts ─────────────────────────────────────────────────────────
PRESENT = "present"
NOT_LICENSED = "not licensed or not enabled"
NO_PERMISSION = "no permission"
ERROR = "error"
NOT_PROBED = "not probed"
VERDICTS = (PRESENT, NOT_LICENSED, NO_PERMISSION, ERROR, NOT_PROBED)

PRODUCT_NAMES = {"zia": "ZIA", "zpa": "ZPA", "zcc": "Client Connector", "zdx": "ZDX", "zid": "ZIdentity", "ztw": "Cloud & Branch Connector",
                 "zwa": "Workflow Automation", "zeasm": "External Attack Surface", "ztb": "Zero Trust Branch", "zbi": "Business Insights",
                 "aiguard": "AI Guard", "zcell": "Zero Trust Cellular"}
_PREFIXES = (("/zia/", "zia"), ("/zpa/", "zpa"), ("/zcc/", "zcc"), ("/zdx/", "zdx"), ("/ziam/", "zid"), ("/ztw/", "ztw"), ("/zwa/", "zwa"),
             ("/easm/", "zeasm"), ("/ztb/", "ztb"), ("/bi/", "zbi"), ("/aiguard/", "aiguard"), ("/zcell/", "zcell"))

# Endpoints that are never read, on top of the catalogue's own skip rule
# (tools/build_tenant_api_catalogue.py SKIP_RE: otp, password, secret, api key,
# credential, provisioning URL and key, download, export, logs): material that
# is a key, a certificate request, an audit export or a tunnel's pre-shared key.
EXTRA_SKIP = re.compile(r"auditlogEntryReport|ipGreTunnelInfo|enrollmentCert|businessContinuitySettings/certificate|"
                        r"intermediateCaCertificate(?!/lite|/readyToUse)|private[_-]?key|/token|psk|ssh|"
                        # GETs the SDK lists whose names read as an action (a refresh, a sync, a scan): never sent, in case they do something
                        r"azure/refreshConnectionStatus|azure/virtualHubSync|azure/unConfigureTunnelStatus|casbTenant/scanInfo", re.I)
# A path that names an action is never read either, whatever its method in the SDK: any word of it (camelCase split) is one of these.
ACTION_WORDS = frozenset({"sync", "refresh", "configure", "unconfigure", "enable", "disable", "reset", "run", "start", "stop", "trigger",
                          "rotate", "generate", "activate", "deactivate", "scan"})


def action_words(path: str) -> List[str]:
    """The action verbs a path names (camelCase and separators split, case ignored): [] for a plain read."""
    words: List[str] = []
    for seg in re.split(r"[^A-Za-z0-9]+", path):
        words += [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", seg)]
    return sorted(set(words) & ACTION_WORDS)

SKIP_CREDENTIALS = ("otp", "password", "secret", "api-?key", "credential", "provurl", "provisioningkey", "download", "export",
                    "cloudformationtemplate", r"/logs\b", "/search$", "getAppsByType")
SKIP_RE = re.compile("|".join(SKIP_CREDENTIALS), re.I)
_PATH_OK = re.compile(r"\A/[A-Za-z0-9_./{}-]{1,300}\Z")

REASON_ID = "needs an object id in its address"
REASON_SENSITIVE = "returns credentials, one-time passwords, keys or an export, needs a query, or its name is an action: never read"
REASON_UNRESOLVED = "its address cannot be worked out from the SDK"
REASON_CUSTOMER = "needs the ZPA customer ID, which is not set for this sign-in"
REASON_CLASSIC = "the classic ZIA sign-in reaches ZIA only"
REASON_PRODUCT = "its product is not selected"
REASON_SCOPE = "skipped: not in scope"
SCOPE_LINK = "/#scopeField"   # the Scope page (the assessment page's scope field)

# The Scope page keys that put a product's reads in scope: any one of them ticked is enough.
SCOPE_KEYS = {"zia": ("dlp", "zia_extras"), "zpa": ("zpa",), "zcc": ("zcc",), "zdx": ("zdx",), "zid": ("zidentity",), "ztw": ("ztw",),
              "zwa": ("dlp",), "zeasm": ("easm",), "ztb": ("ztb",), "zbi": ("zbi",), "aiguard": ("aiguard",), "zcell": ("zcell",)}
SCOPE_LABELS = {"dlp": "DLP", "zia_extras": "ZIA platform", "zpa": "ZPA", "zcc": "ZCC", "zdx": "ZDX", "zidentity": "ZIdentity", "ztw": "Cloud & Branch Connector",
                "easm": "External attack surface (EASM)", "ztb": "Zero Trust Branch", "zbi": "Business Insights", "aiguard": "AI Guard",
                "zcell": "Zero Trust Cellular"}


def in_scope(product: str, scopes: Optional[Iterable[Any]]) -> bool:
    """True when the Scope page's ticked keys put `product` in scope. `scopes` None means no Scope page selection applies
    (library use, tests); an empty list means nothing is ticked: nothing is in scope (fail closed)."""
    if scopes is None:
        return True
    ticked = {str(x).strip() for x in scopes}   # exact keys, as the Scope page sends them: "DLP" is not "dlp"
    return any(k in ticked for k in SCOPE_KEYS.get(product, ("?",)))


def scope_hint(product: str) -> str:
    keys = SCOPE_KEYS.get(product, ())
    return " or ".join(SCOPE_LABELS.get(k, k) for k in keys)


# ── the catalogue ────────────────────────────────────────────────────
_CATALOGUE: Optional[Dict[str, Any]] = None
_CAT_LOCK = threading.Lock()


def catalogue() -> Dict[str, Any]:
    """{sdk, products: {product: [entry]}} from tenant_api_catalogue.json (cached)."""
    global _CATALOGUE
    with _CAT_LOCK:
        if _CATALOGUE is None:
            with open(CATALOGUE_FILE, "r", encoding="utf-8") as f:
                doc = json.load(f)
            prods = doc.get("products")
            if not isinstance(prods, dict):
                raise ValueError("tenant_api_catalogue.json has no products")
            _CATALOGUE = {"sdk": str(doc.get("sdk") or ""), "products": prods}
        return _CATALOGUE


def product_of(path: str) -> str:
    for pre, prod in _PREFIXES:
        if path.startswith(pre):
            return prod
    return "unknown"


def skip_reason(entry: Mapping[str, Any]) -> Optional[str]:
    """Why an endpoint is not read, else None: the catalogue's own reason, then the checks this module applies again."""
    path = str(entry.get("path") or "")
    if not _PATH_OK.match(path) or product_of(path) == "unknown":
        return REASON_UNRESOLVED
    if entry.get("path_params"):
        return REASON_ID
    if "{?}" in path:
        return REASON_UNRESOLVED
    if SKIP_RE.search(path) or EXTRA_SKIP.search(path) or action_words(path):
        return REASON_SENSITIVE
    if not entry.get("probeable"):
        return str(entry.get("skip_reason") or REASON_SENSITIVE)[:120]
    return None


# ── features: which endpoint decides whether the tenant has it ──────
def _zia(p: str) -> str:
    return "/zia/api/v1/" + p


def _zpa(p: str, v: str = "v1") -> str:
    return f"/zpa/mgmtconfig/{v}/admin/customers/{{customerId}}/" + p


EMAIL_TENANTS = (_zia("casbTenant/lite"), (("appType", "EMAIL"),))

# (name, product, deciders: any 2xx means present, info: extra reads shown as detail, note)
FEATURES: List[Tuple[str, str, List[str], List[Any], str]] = [
    ("Email DLP", "zia", [_zia("emailDlpRules")], [EMAIL_TENANTS], "also counts the email tenants the Email DLP rules use"),
    ("SaaS Security API (CASB)", "zia", [_zia("casbDlpRules"), _zia("casbTenant/lite")], [_zia("casbMalwareRules")], ""),
    ("Endpoint DLP", "zia", [_zia("endPointDlpRules")], [], ""),
    ("Web DLP", "zia", [_zia("webDlpRules")], [_zia("dlpEngines"), _zia("dlpDictionaries")], ""),
    ("Browser Isolation (ZIA)", "zia", [_zia("browserIsolation/profiles")], [], ""),
    ("Sandbox", "zia", [_zia("sandboxRules")], [_zia("sandbox/report/quota")], ""),
    ("Cloud Firewall", "zia", [_zia("firewallFilteringRules")], [], ""),
    ("Cloud IPS", "zia", [_zia("firewallIpsRules")], [], ""),
    ("Cloud DNS Control", "zia", [_zia("firewallDnsRules")], [], ""),
    ("SSL Inspection", "zia", [_zia("sslInspectionRules")], [], ""),
    ("File Type Control", "zia", [_zia("fileTypeRules")], [], ""),
    ("Cloud App Control", "zia", [_zia("webApplicationRules/ruleTypeMapping"), _zia("cloudApplications/policy")], [], ""),
    ("Bandwidth Control", "zia", [_zia("bandwidthControlRules")], [], ""),
    ("Forwarding Control", "zia", [_zia("forwardingRules")], [], ""),
    ("ZPA Privileged Remote Access", "zpa", [_zpa("praPortal"), _zpa("praConsole")], [], ""),
    ("ZPA Browser Access", "zpa", [_zpa("clientlessCertificate/issued", "v2")], [], ""),
    ("ZPA AppProtection (inspection)", "zpa", [_zpa("inspectionProfile")], [_zpa("inspectionControls/predefined")], ""),
    ("ZPA Isolation profiles", "zpa", [_zpa("isolation/profiles"), "/zpa/cbiconfig/cbi/api/customers/{customerId}/profiles"], [], ""),
    ("ZDX", "zdx", ["/zdx/v1/apps"], [], ""),
    ("Client Connector (ZCC)", "zcc", ["/zcc/papi/public/v1/webForwardingProfile/listByCompany"], [], ""),
    ("Cloud & Branch Connector (ZTW)", "ztw", ["/ztw/api/v1/ecgroup/lite"], [], ""),
    ("ZIdentity", "zid", ["/ziam/admin/api/v1/groups"], [], ""),
    ("Workflow Automation / ZWA (DLP incidents)", "zwa", [], [],
     "the SDK only has ZWA reads that need an incident id, so this cannot be checked without one"),
    ("External Attack Surface (EASM)", "zeasm", ["/easm/easm-ui/v1/organizations"], [], ""),
    ("Zero Trust Branch (ZTB)", "ztb", ["/ztb/api/v3/templates/names"], [], ""),
    ("Business Insights (ZBI)", "zbi", ["/bi/api/v1/customapps"], [], ""),
    ("AI Guard", "aiguard", ["/aiguard/v1/llm-provider-types"], [], ""),
    ("Risk360", "risk360", [], [], "the Zscaler SDK has no Risk360 endpoint, so this cannot be checked"),
]


# ── the plan: exactly what will be read ──────────────────────────────
def key_of(path: str, params: Iterable[Tuple[str, str]] = ()) -> str:
    q = "&".join(f"{k}={v}" for k, v in sorted(params))
    return path + ("?" + q if q else "")


def _entry_index() -> Dict[str, Dict[str, Any]]:
    return {e["path"]: dict(e, product=p) for p, items in catalogue()["products"].items() for e in items if isinstance(e, dict) and e.get("path")}


def feature_paths(feature: Tuple[Any, ...]) -> List[Tuple[str, Tuple[Tuple[str, str], ...], str]]:
    """(path, params, purpose) of every read a feature uses: deciders first."""
    _n, _p, deciders, info, _note = feature
    out: List[Tuple[str, Tuple[Tuple[str, str], ...], str]] = [(d, (), "decider") for d in deciders]
    for i in info:
        out.append((i, (), "info") if isinstance(i, str) else (i[0], tuple(i[1]), "info"))
    return out


def normalise_products(products: Optional[Iterable[Any]]) -> Optional[List[str]]:
    """The chosen products, or None for all. Unknown names are dropped."""
    if products is None:
        return None
    known = set(PRODUCT_NAMES)
    out = []
    for p in products:
        p = str(p or "").strip().lower()
        if p in known and p not in out:
            out.append(p)
    return out


def clamp_rps(rps: Any) -> float:
    try:
        v = float(rps)
    except (TypeError, ValueError):
        return DEFAULT_RPS
    if not math.isfinite(v):
        return DEFAULT_RPS
    return round(min(MAX_RPS, max(MIN_RPS, v)), 2)


def plan(products: Optional[Iterable[Any]] = None, features_only: bool = False, rps: Any = DEFAULT_RPS, scopes: Optional[Iterable[Any]] = None) -> Dict[str, Any]:
    """Everything the map would read and everything it would skip, without
    touching a tenant: `reads` (feature deciders first, then the rest of the
    catalogue), `skipped` (each with its reason) and a `plan_hash` the start
    request must repeat, so what was confirmed is what runs. `scopes` is the Scope page's ticked keys: an endpoint whose
    product is not ticked there is never read and is listed as "skipped: not in scope" (None: no Scope page selection)."""
    chosen = normalise_products(products)
    scopes = None if scopes is None else [str(x) for x in scopes]
    out_of_scope = sorted(p for p in PRODUCT_NAMES if not in_scope(p, scopes))
    idx = _entry_index()
    reads: Dict[str, Dict[str, Any]] = {}

    def add(path: str, params: Tuple[Tuple[str, str], ...], purpose: str) -> None:
        e = idx.get(path)
        if e is None or skip_reason(e):
            return
        prod = e["product"]
        if chosen is not None and prod not in chosen:
            return
        if not in_scope(prod, scopes):
            return
        k = key_of(path, params)
        if k in reads:
            if purpose == "decider":
                reads[k]["purpose"] = "decider"
            return
        reads[k] = {"product": prod, "path": path, "params": [list(p) for p in params], "sdk": f'{e.get("module", "")}.{e.get("method", "")}'.strip("."),
                    "purpose": purpose}

    for f in FEATURES:
        for path, params, purpose in feature_paths(f):
            add(path, params, purpose)
    if not features_only:
        for path in sorted(idx, key=lambda p: (idx[p]["product"], p)):
            add(path, (), "catalogue")
    rows = list(reads.values())[:MAX_PLAN]
    for n, r in enumerate(rows, 1):
        r["n"] = n
    skipped: List[Dict[str, Any]] = []
    for path in sorted(idx, key=lambda p: (idx[p]["product"], p)):
        e = idx[path]
        why = REASON_SCOPE if not in_scope(e["product"], scopes) else skip_reason(e)
        if why is None and chosen is not None and e["product"] not in chosen:
            why = REASON_PRODUCT
        if why is not None:
            skipped.append({"product": e["product"], "path": path, "reason": why})
    by_product: Dict[str, int] = {}
    for r in rows:
        by_product[r["product"]] = by_product.get(r["product"], 0) + 1
    by_reason: Dict[str, int] = {}
    for s in skipped:
        by_reason[s["reason"]] = by_reason.get(s["reason"], 0) + 1
    speed = clamp_rps(rps)
    digest = hashlib.sha256(json.dumps([[r["path"], r["params"]] for r in rows] + [speed], sort_keys=True).encode()).hexdigest()[:24]
    return {"reads": rows, "count": len(rows), "by_product": by_product, "skipped": skipped, "skipped_count": len(skipped),
            "skipped_by_reason": by_reason, "rps": speed, "seconds": int(math.ceil(len(rows) / speed)) if rows else 0,
            "features_only": bool(features_only), "selected": chosen, "scope_applied": scopes is not None,
            "not_in_scope": [{"product": p, "name": PRODUCT_NAMES[p], "tick": scope_hint(p)} for p in out_of_scope
                             if chosen is None or p in chosen] if scopes is not None else [],
            "scope_link": SCOPE_LINK, "products": chosen if chosen is not None else sorted(by_product),
            "sdk": catalogue()["sdk"], "plan_hash": digest, "method": "GET",
            "note": ("Only GET requests, one at a time, at the speed shown. Each answer is reduced to its status, how many items it holds and the "
                     "names of its top-level fields; no value, id, name or secret is kept.")}


# ── turning an answer into counts and field names ────────────────────
_NAME_OK = re.compile(r"\A[a-z][A-Za-z0-9_]{0,39}\Z")          # a field name as an identifier: lower-case first, no dot, @, dash or space
_LIST_KEYS = ("list", "items", "results", "data", "content", "records", "resources", "entries")

# Error words: the only text an error answer can contribute. Each is a fixed word of this list, never the API's own text.
KNOWN_ERROR_CODES = ("NOT_SUBSCRIBED", "NOT_ENABLED", "NOT_LICENSED", "FEATURE_NOT_ENABLED", "FEATURE_NOT_LICENSED",
                     "FEATURE_NOT_SUBSCRIBED", "FEATURE_NOT_AVAILABLE", "SUBSCRIPTION_REQUIRED", "RATE_LIMIT_EXCEEDED", "UNAUTHORIZED",
                     "NOT_AUTHORIZED", "INVALID_INPUT_ARGUMENT", "RESOURCE_NOT_FOUND", "INVALID_REQUEST")
KNOWN_PHRASES = (("not subscribed", "NOT_SUBSCRIBED"), ("not licensed", "NOT_LICENSED"), ("feature is not enabled", "FEATURE_NOT_ENABLED"),
                 ("not enabled", "NOT_ENABLED"), ("subscription required", "SUBSCRIPTION_REQUIRED"),
                 ("rate limit", "RATE_LIMIT_EXCEEDED"), ("not authorized", "NOT_AUTHORIZED"), ("unauthorized", "UNAUTHORIZED"))
GENERIC_HINT = "no known Zscaler error code"
_CODE_FIND = re.compile(r"\b(" + "|".join(sorted(KNOWN_ERROR_CODES, key=len, reverse=True)) + r")\b")
_HEXY = re.compile(r"[0-9a-fA-F]{8,}")


def safe_name(name: Any) -> Optional[str]:
    """A top-level field name as the API spells it, or None when it could be data: it must be an identifier (lower-case first, then
    letters, digits and underscores, 40 at most), with no UPPER_SNAKE code, no hex or other long run, no run of four digits or more
    (an id, a port, a year) and no email, domain, UUID or space (their characters do not pass the identifier pattern)."""
    n = str(name)
    if not _NAME_OK.match(n) or re.search(r"\d{4,}", n) or _HEXY.fullmatch(n) or re.fullmatch(r"[A-Z0-9_]+", n):
        return None
    return n


def _keys_are_data(d: Mapping[str, Any]) -> bool:
    """True for an object that is a map from a name to a record ({"jsmith": {...}, "acme": {...}}): its keys are data, not fields.
    Two or more record-valued keys whose records share a key are such a map."""
    recs = [v for v in d.values() if isinstance(v, dict) and v]
    if len(recs) < 2:
        return False
    first = set(recs[0])
    return all(first & set(r) for r in recs[1:])


def summarise(data: Any) -> Dict[str, Any]:
    """{count, total, fields, other_names, shape} of an answer already parsed. No value leaves this function."""
    out: Dict[str, Any] = {"count": None, "total": None, "fields": [], "other_names": 0, "shape": "empty"}
    if data is None or data == "" or data == [] or data == {}:
        out["count"] = 0 if isinstance(data, list) else None
        out["shape"] = "list" if isinstance(data, list) else "empty"
        return out
    items: Optional[list] = None
    top: Optional[dict] = None
    if isinstance(data, list):
        items, out["shape"] = data, "list"
    elif isinstance(data, dict):
        top = data
        for k in _LIST_KEYS:
            if isinstance(data.get(k), list):
                items, out["shape"] = data[k], "paged-list"
                tot = data.get("totalCount", data.get("total"))
                if isinstance(tot, (int, float)) and not isinstance(tot, bool) and 0 <= tot <= 10_000_000:
                    out["total"] = int(tot)
                break
        else:
            out["shape"] = "object"
    elif isinstance(data, str):
        out["shape"] = "text"
        return out
    else:
        out["shape"] = "scalar"
        return out
    names: List[Any] = []
    if items is not None:
        out["count"] = len(items)
        for it in items[:MAX_ITEM_SAMPLE]:
            if isinstance(it, dict):
                for k in it:
                    if k not in names:
                        names.append(k)
    elif top is not None:
        names = [] if _keys_are_data(top) else list(top.keys())
        if not names:
            out["other_names"] = len(top)
    fields: List[str] = []
    other = 0
    for n in names:
        s = safe_name(n)
        if s is None:
            other += 1
        elif s not in fields:
            fields.append(s)
    if len(fields) > MAX_FIELDS:
        other += len(fields) - MAX_FIELDS
        fields = fields[:MAX_FIELDS]
    out["fields"], out["other_names"] = fields, other + (out["other_names"] if top is not None and not names else 0)
    return out


def error_hint(body: Any) -> str:
    """A known Zscaler error word for an error answer: always a member of KNOWN_ERROR_CODES, or GENERIC_HINT. The answer's own
    text (a code it invents, an id, a name) is looked up in the list and never copied."""
    text = ""
    if isinstance(body, dict):
        for k in ("code", "errorCode", "error_code"):
            v = body.get(k)
            if isinstance(v, str) and v.strip().upper() in KNOWN_ERROR_CODES:
                return v.strip().upper()
        text = str(body.get("error") or body.get("message") or "")
    elif isinstance(body, str):
        text = body
    text = text[:400]
    m = _CODE_FIND.search(text)
    if m:
        return m.group(1)
    low = text.lower()
    for phrase, code in KNOWN_PHRASES:
        if phrase in low:
            return code
    return GENERIC_HINT


def verdict_for(status: Optional[int], hint: Optional[str] = None) -> str:
    """2xx present; a "not subscribed" code or 404 not licensed or not enabled; 401/403 no permission; the rest an error."""
    if status is None:
        return ERROR
    if 200 <= status < 300:
        return PRESENT
    if hint and re.search(r"NOT_SUBSCRIBED|NOT_ENABLED|NOT_LICENSED|FEATURE_NOT|SUBSCRIPTION_REQUIRED", hint):
        return NOT_LICENSED
    if status == 404:
        return NOT_LICENSED
    if status in (401, 403):
        return NO_PERMISSION
    return ERROR


def _error_word(body: Any, status: int) -> str:
    """A fixed word for a read that got no answer or an error: never the text the API sent."""
    t = str(body.get("error") if isinstance(body, dict) else body or "").lower()[:300]
    if status == 429 or "rate limit" in t:
        return "rate limited"
    if "timeout" in t or "timed out" in t:
        return "timed out"
    if "connection" in t:
        return "connection error"
    if status == 0:
        return "no answer"
    if status in (401, 403):
        return "refused"
    if status >= 500:
        return "server error"
    return "http " + str(status)


# ── pace ─────────────────────────────────────────────────────────────
class Throttle:
    """At most `rps` requests a second. `wait` blocks until the next may go and returns False when
    `cancel` was set meanwhile (nothing is then sent). Clock and sleeper are injected for tests."""

    def __init__(self, rps: float, clock: Callable[[], float] = time.monotonic, sleeper: Optional[Callable[[float], None]] = None):
        self.interval = 1.0 / clamp_rps(rps)
        self._clock, self._sleeper = clock, sleeper
        self._next = 0.0

    def wait(self, cancel: Optional[threading.Event] = None) -> bool:
        if cancel is not None and cancel.is_set():
            return False
        now = self._clock()
        if now < self._next:
            delay = self._next - now
            if self._sleeper is not None:
                self._sleeper(delay)
            elif cancel is not None:
                cancel.wait(delay)
            else:
                time.sleep(delay)
            now = max(now, self._next)
        self._next = now + self.interval
        self._started = now
        return not (cancel is not None and cancel.is_set())

    def account(self, sent: int) -> None:
        """Charge a read for every request it really sent: the client retries a 429, a 5xx or a timeout by itself, and each
        of those counts, so the next read waits `sent` intervals from this read's start. The rate never exceeds the setting."""
        if sent > 1:
            self._next = max(self._next, getattr(self, "_started", self._next) + sent * self.interval)


class Stopped(Exception):
    """The run was stopped (by the admin, or by the tenant's rate limit); nothing is kept."""


STOPPED_REASON = "Stopped: you clicked Stop; nothing more was read and no map was saved."
RATE_LIMITED_REASON = ("Stopped: the tenant answered 'too many requests' several times in a row, so the map ended and nothing was saved. "
                       "Wait a few minutes and run it again, or choose a lower speed.")


class ReadOnlyClient:
    """The app's signed-in client as the map sees it: GET only, and only of the paths in the confirmed plan.
    It has no write method (post, put, delete and every other attribute raise)."""

    PASS_THROUGH = ("customer_id", "legacy", "offline", "method")

    def __init__(self, client: Any, allowed: Iterable[str]):
        self._client = client
        self._allowed = set(allowed)
        self.reads = 0
        self._stopped = False

    def sent(self) -> Optional[int]:
        """How many requests the client has really sent (a retry is one more), when it counts them."""
        n = getattr(self._client, "requests_made", None)
        return n if isinstance(n, int) and not isinstance(n, bool) else None

    def stop(self) -> None:
        """End every wait and retry of the client at once; any later read here is refused."""
        self._stopped = True
        fn = getattr(self._client, "stop", None)
        if callable(fn):
            try:
                fn()
            except Exception:  # noqa: BLE001 - a client that cannot stop is abandoned by the caller anyway
                pass

    def __getattr__(self, name: str) -> Any:
        if name in ReadOnlyClient.PASS_THROUGH:
            return getattr(self._client, name)
        raise AttributeError(f"the API map is read-only: {name} is not available")

    def get(self, path: str, params: Optional[Mapping[str, Any]] = None) -> Tuple[Any, int]:
        if path not in self._allowed:
            raise PermissionError("the API map reads only the endpoints it showed you")
        if self._stopped:
            return None, 0
        self.reads += 1
        res = self._client.get(path, dict(params) if params else None)
        try:
            return res[0], int(res[1])
        except Exception:  # noqa: BLE001 - an answer that is not (body, status) is no answer
            return None, 0


def _wire_path(template: str, client: Any) -> Tuple[Optional[str], Optional[str]]:
    """(the address sent to the client, why it cannot be sent). The client's 'raw:' form sends the address as it is."""
    legacy = bool(getattr(client, "legacy", False))
    cust = str(getattr(client, "customer_id", "") or "")
    path = template
    if legacy:
        if not template.startswith("/zia/api/v1/"):
            return None, REASON_CLASSIC
        return "/zia/" + template[len("/zia/api/v1/"):], None
    if "{customerId}" in path:
        if not cust or not re.fullmatch(r"[0-9A-Za-z_-]{1,40}", cust):
            return None, REASON_CUSTOMER
        path = path.replace("{customerId}", cust)
    return "raw:" + path, None


# ── the run ──────────────────────────────────────────────────────────
_RUN_LOCK = threading.Lock()


class Busy(Exception):
    """Another map is running in this server."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row(r: Mapping[str, Any]) -> Dict[str, Any]:
    return {"product": r["product"], "path": r["path"], "params": [p[0] for p in r["params"]], "sdk_method": r["sdk"], "purpose": r["purpose"],
            "status": None, "verdict": NOT_PROBED, "item_count": None, "total_reported": None, "shape": "", "field_names": [], "other_names": 0,
            "error_code_hint": None, "error": None}


def read_one(ro: ReadOnlyClient, client: Any, r: Mapping[str, Any]) -> Dict[str, Any]:
    """One endpoint: the row with its status, verdict, count and field names. Never a value."""
    row = _row(r)
    wire, why = _wire_path(r["path"], client)
    if wire is None:
        row["error"] = why
        return row
    params = {k: v for k, v in r["params"]} if r["params"] else None
    body, status = ro.get(wire, params)
    row["status"] = status or None
    if status == 0:
        row["verdict"], row["error"] = ERROR, _error_word(body, 0)
        if isinstance(body, dict) and "not available with the classic" in str(body.get("error") or ""):
            row["verdict"], row["error"], row["status"] = NOT_PROBED, REASON_CLASSIC, None
        return row
    if 200 <= status < 300:
        s = summarise(body)
        row.update(item_count=s["count"], total_reported=s["total"], shape=s["shape"], field_names=s["fields"], other_names=s["other_names"])
        row["verdict"] = PRESENT
        return row
    row["error_code_hint"] = error_hint(body)
    row["verdict"] = verdict_for(status, row["error_code_hint"])
    if row["verdict"] == ERROR or status == 429:
        row["error"] = _error_word(body, status)
    return row


IN_FLIGHT_POLL = 0.1   # seconds between looks at Stop while a request is in flight


def _read_interruptible(ro: ReadOnlyClient, client: Any, r: Mapping[str, Any], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """read_one, but Stop does not wait for the request in flight: the client is told to stop (no retry, no back-off, no new
    request), the run ends at once and the late answer, if one comes, is dropped with its thread. Without a cancel it is a plain call."""
    if cancel is None:
        return read_one(ro, client, r)
    box: Dict[str, Any] = {}

    def work() -> None:
        try:
            box["row"] = read_one(ro, client, r)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            box["err"] = e

    t = threading.Thread(target=work, name="api-map-read", daemon=True)
    t.start()
    while t.is_alive():
        t.join(IN_FLIGHT_POLL)
        if cancel.is_set() and t.is_alive():
            ro.stop()
            raise Stopped(STOPPED_REASON)
    if "err" in box:
        raise box["err"]
    return box["row"]


def feature_rows(results: Mapping[str, Dict[str, Any]], chosen: Optional[List[str]], out_of_scope: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """The feature table: each feature's verdict is the best answer among its deciding endpoints."""
    rank = {PRESENT: 0, NO_PERMISSION: 1, NOT_LICENSED: 2, ERROR: 3, NOT_PROBED: 4}
    rows = []
    for f in FEATURES:
        name, prod, deciders, _info, note = f
        row: Dict[str, Any] = {"feature": name, "product": prod, "deciding_endpoint": None, "status": None, "verdict": NOT_PROBED,
                               "item_count": None, "detail": note, "info": []}
        if prod in set(out_of_scope):
            row["detail"] = REASON_SCOPE
            rows.append(row)
            continue
        if chosen is not None and prod not in chosen and prod != "risk360":
            row["detail"] = "its product was not selected"
            rows.append(row)
            continue
        got = [results[key_of(d)] for d in deciders if key_of(d) in results]
        if got:
            best = sorted(got, key=lambda x: rank.get(x["verdict"], 9))[0]
            row.update(deciding_endpoint=best["path"], status=best["status"], verdict=best["verdict"], item_count=best["item_count"])
            if best.get("error_code_hint"):
                row["detail"] = best["error_code_hint"]
            elif best.get("error") and best["verdict"] in (ERROR, NOT_PROBED):
                row["detail"] = best["error"]
        for path, params, _p in feature_paths(f):
            if _p != "info":
                continue
            x = results.get(key_of(path, params))
            if x:
                row["info"].append({"endpoint": path + ("?" + "&".join(k + "=…" for k, _v in params) if params else ""), "status": x["status"],
                                    "verdict": x["verdict"], "item_count": x["item_count"]})
        rows.append(row)
    return rows


def counts_of(endpoints: List[Dict[str, Any]], features: List[Dict[str, Any]], planned: int) -> Dict[str, int]:
    c = {"planned": planned, "read": sum(1 for e in endpoints if e["status"] is not None), "present": 0, "not_licensed": 0, "no_permission": 0,
         "error": 0, "not_probed": 0, "features_present": 0, "features_not_licensed": 0, "features_no_permission": 0, "features_error": 0,
         "features_not_probed": 0}
    key = {PRESENT: "present", NOT_LICENSED: "not_licensed", NO_PERMISSION: "no_permission", ERROR: "error", NOT_PROBED: "not_probed"}
    for e in endpoints:
        c[key[e["verdict"]]] += 1
    for f in features:
        c["features_" + key[f["verdict"]]] += 1
    return c


def run(client: Any, the_plan: Dict[str, Any], *, label: str = "", sign_in: str = "", log: Optional[Callable[[str], None]] = None,
        cancel: Optional[threading.Event] = None, throttle: Optional[Throttle] = None,
        progress: Optional[Callable[[Dict[str, Any]], Any]] = None) -> Dict[str, Any]:
    """Read every endpoint of `the_plan` through `client` (the app's signed-in client), one at a time at the plan's
    speed (none for an offline tenant). Raises Stopped on Stop or a run of rate-limit answers (nothing is kept) and
    Busy when another map is running. Returns the map: features, endpoints, skipped and counts."""
    if not _RUN_LOCK.acquire(blocking=False):
        raise Busy("Another API map is running in this server. Wait for it to finish.")
    try:
        say = log or (lambda _l: None)
        reads = the_plan["reads"]
        offline = bool(getattr(client, "offline", False))
        throttle = throttle or Throttle(the_plan["rps"], sleeper=(lambda _s: None) if offline else None)
        ro = ReadOnlyClient(client, {w for r in reads for w, _why in [_wire_path(r["path"], client)] if w})
        started = time.time()
        say(f"Mapping {label or 'the tenant'}: {len(reads)} GET reads, one at a time, up to {the_plan['rps']:g} a second. Nothing is changed.")
        results: Dict[str, Dict[str, Any]] = {}
        rows: List[Dict[str, Any]] = []
        streak = 0
        for n, r in enumerate(reads, 1):
            if not throttle.wait(cancel):
                raise Stopped(STOPPED_REASON)
            before = ro.sent()
            row = _read_interruptible(ro, client, r, cancel)
            after = ro.sent()
            throttle.account(max(1, after - before) if before is not None and after is not None else 1)
            if row["error"] == "rate limited":
                streak += 1
                if streak >= ABORT_AFTER_429:
                    raise Stopped(RATE_LIMITED_REASON)
            else:
                streak = 0
            if cancel is not None and cancel.is_set():
                raise Stopped(STOPPED_REASON)
            results[key_of(r["path"], tuple(tuple(p) for p in r["params"]))] = row
            rows.append(row)
            say(f"{n}/{len(reads)} {PRODUCT_NAMES.get(r['product'], r['product'])} {r['path']} -> "
                f"{row['status'] if row['status'] is not None else 'not read'} {row['verdict']}"
                + (f" ({row['item_count']} items)" if row["item_count"] is not None else ""))
            if progress:
                progress({"done": n, "total": len(reads), "present": sum(1 for x in rows if x["verdict"] == PRESENT)})
        feats = feature_rows(results, the_plan.get("selected"), [x["product"] for x in the_plan.get("not_in_scope") or []])
        counts = counts_of(rows, feats, len(reads))
        mode = "sample or snapshot" if offline else ("classic ZIA" if getattr(client, "legacy", False) else "OneAPI")
        out = {"status": "done", "tenant_label": label, "sign_in": sign_in or mode, "started_at": _now(), "rps": the_plan["rps"], "sdk": the_plan["sdk"],
               "features_only": the_plan["features_only"], "products": the_plan["products"], "plan_hash": the_plan["plan_hash"],
               "duration_seconds": round(time.time() - started, 1), "counts": counts, "features": feats, "endpoints": rows,
               "skipped_count": the_plan["skipped_count"], "skipped_by_reason": the_plan["skipped_by_reason"],
               "method": "GET", "values_kept": False,
               "note": "Only status, item counts and top-level field names were kept: no value, id, name or secret."}
        say(f"Done: {counts['read']} read, {counts['present']} present, {counts['not_licensed']} not licensed or not enabled, "
            f"{counts['no_permission']} no permission, {counts['error']} errors.")
        return out
    finally:
        _RUN_LOCK.release()


# ── exports ──────────────────────────────────────────────────────────
def to_json(rep: Mapping[str, Any]) -> str:
    return json.dumps({k: v for k, v in rep.items() if k not in ("logs",)}, indent=2, default=str)


def to_csv(rep: Mapping[str, Any], what: str = "endpoints") -> str:
    """CSV through csv_safe (a cell that starts like a formula is quoted)."""
    import io
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    if what == "features":
        w.writerow(["feature", "product", "verdict", "deciding endpoint", "http status", "items", "detail"])
        for f in rep.get("features") or []:
            w.writerow([f.get("feature"), f.get("product"), f.get("verdict"), f.get("deciding_endpoint") or "", f.get("status") or "",
                        "" if f.get("item_count") is None else f.get("item_count"), f.get("detail") or ""])
    else:
        w.writerow(["product", "endpoint", "http status", "verdict", "items", "total reported", "shape", "field names", "error code", "note"])
        for e in rep.get("endpoints") or []:
            w.writerow([e.get("product"), e.get("path"), e.get("status") or "", e.get("verdict"), "" if e.get("item_count") is None else e.get("item_count"),
                        "" if e.get("total_reported") is None else e.get("total_reported"), e.get("shape") or "", " ".join(e.get("field_names") or []),
                        e.get("error_code_hint") or "", e.get("error") or ""])
    return buf.getvalue()


def for_assistant(rep: Mapping[str, Any]) -> Dict[str, Any]:
    """The map for an AI assistant: counts, the feature table and the endpoints that did not answer 2xx;
    field names and item counts per endpoint are left to the page's export."""
    eps = rep.get("endpoints") or []
    return {"read_at": rep.get("started_at") or rep.get("saved_at"), "counts": rep.get("counts"), "sdk": rep.get("sdk"), "rps": rep.get("rps"),
            "features": [{k: f.get(k) for k in ("feature", "product", "verdict", "deciding_endpoint", "status", "item_count", "detail")}
                         for f in rep.get("features") or []],
            "present_by_product": _by_product(eps, PRESENT),
            "not_licensed_by_product": _by_product(eps, NOT_LICENSED),
            "no_permission_endpoints": [e["path"] for e in eps if e.get("verdict") == NO_PERMISSION][:60],
            "error_endpoints": [{"path": e["path"], "status": e.get("status"), "error": e.get("error")} for e in eps if e.get("verdict") == ERROR][:40],
            "values": "Never kept: only statuses, item counts and field names are in the map.",
            "evidence": "observed: GET reads the app made once, one at a time, through the signed-in client"}


def _by_product(eps: List[Dict[str, Any]], verdict: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for e in eps:
        if e.get("verdict") == verdict:
            out[e.get("product") or "?"] = out.get(e.get("product") or "?", 0) + 1
    return out


# ── saved maps (per tenant label, sealed through store_crypto) ──────
_LOCK = threading.Lock()
_PROFILE_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{0,47}\Z")
_AT = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(\+00:00|Z)?\Z")


def history_path() -> str:
    env = os.environ.get("DLP_CHECK_API_MAP")
    if env:
        return env
    from zscaler_update_check import _cache_path
    return os.path.join(os.path.dirname(_cache_path()), "tenant_api_map.json")


def tenant_key(tenant: Any) -> str:
    import tenant_auth
    return tenant_auth.scrub_classic_login(str(tenant or "tenant"))[:120]


def _count(v: Any, hi: int = 10_000_000) -> Optional[int]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)):
        return None
    n = int(v)
    return n if 0 <= n <= hi else None


def _word(v: Any, n: int = 120) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v if v is not None else ""))[:n]


def _clean_row(e: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(e, Mapping) or not _PATH_OK.match(str(e.get("path") or "")):
        return None
    verdict = e.get("verdict") if e.get("verdict") in VERDICTS else NOT_PROBED
    fields = [f for f in (e.get("field_names") or [])[:MAX_FIELDS] if isinstance(f, str) and safe_name(f)] if isinstance(e.get("field_names"), list) else []
    status = _count(e.get("status"), 999)
    return {"product": _word(e.get("product"), 12), "path": str(e["path"]), "params": [_word(p, 40) for p in (e.get("params") or [])[:4]]
            if isinstance(e.get("params"), list) else [], "sdk_method": _word(e.get("sdk_method"), 160), "purpose": _word(e.get("purpose"), 12),
            "status": status, "verdict": verdict, "item_count": _count(e.get("item_count")), "total_reported": _count(e.get("total_reported")),
            "shape": _word(e.get("shape"), 16), "field_names": fields, "other_names": _count(e.get("other_names"), 100000) or 0,
            "error_code_hint": e.get("error_code_hint") if e.get("error_code_hint") in KNOWN_ERROR_CODES + (GENERIC_HINT,) else None,
            "error": _word(e.get("error"), 120) or None}


def _clean_feature(f: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(f, Mapping) or not isinstance(f.get("feature"), str):
        return None
    info = [{"endpoint": _word(i.get("endpoint"), 300), "status": _count(i.get("status"), 999), "verdict": i.get("verdict") if i.get("verdict") in VERDICTS else NOT_PROBED,
             "item_count": _count(i.get("item_count"))} for i in (f.get("info") or [])[:6] if isinstance(i, Mapping)] if isinstance(f.get("info"), list) else []
    dep = f.get("deciding_endpoint")
    return {"feature": _word(f["feature"], 80), "product": _word(f.get("product"), 12), "deciding_endpoint": str(dep) if isinstance(dep, str) and _PATH_OK.match(dep) else None,
            "status": _count(f.get("status"), 999), "verdict": f.get("verdict") if f.get("verdict") in VERDICTS else NOT_PROBED,
            "item_count": _count(f.get("item_count")), "detail": _word(f.get("detail"), 200), "info": info}


def clean_map(m: Any) -> Optional[Dict[str, Any]]:
    """A saved map with only the known fields of the right type (the file is read back as untrusted), or None."""
    if not isinstance(m, Mapping):
        return None
    at = str(m.get("started_at") or m.get("saved_at") or "")[:40]
    if not _AT.match(at):
        return None
    eps = [c for c in (_clean_row(e) for e in (m.get("endpoints") or [])[:MAX_PLAN]) if c is not None] if isinstance(m.get("endpoints"), list) else []
    feats = [c for c in (_clean_feature(f) for f in (m.get("features") or [])[:len(FEATURES) + 5]) if c is not None] if isinstance(m.get("features"), list) else []
    counts = {k: (_count(v) or 0) for k, v in (m.get("counts") or {}).items() if isinstance(k, str) and re.fullmatch(r"[a-z_]{1,30}", k)} if isinstance(m.get("counts"), Mapping) else {}
    rps = m.get("rps")
    return {"status": "done", "tenant_label": _word(m.get("tenant_label"), 120), "sign_in": _word(m.get("sign_in"), 30), "started_at": at,
            "saved_at": str(m.get("saved_at") or at)[:40] if _AT.match(str(m.get("saved_at") or at)[:40]) else at,
            "rps": float(rps) if isinstance(rps, (int, float)) and not isinstance(rps, bool) and math.isfinite(rps) and 0 < rps <= 100 else DEFAULT_RPS,
            "sdk": _word(m.get("sdk"), 60), "features_only": bool(m.get("features_only")),
            "products": [p for p in (m.get("products") or []) if p in PRODUCT_NAMES][:20] if isinstance(m.get("products"), list) else [],
            "plan_hash": _word(m.get("plan_hash"), 40), "duration_seconds": float(m["duration_seconds"]) if isinstance(m.get("duration_seconds"), (int, float))
            and not isinstance(m.get("duration_seconds"), bool) and math.isfinite(m["duration_seconds"]) else 0.0,
            "counts": counts, "features": feats, "endpoints": eps, "skipped_count": _count(m.get("skipped_count")) or 0,
            "skipped_by_reason": {_word(k, 120): _count(v) or 0 for k, v in list((m.get("skipped_by_reason") or {}).items())[:12]} if isinstance(m.get("skipped_by_reason"), Mapping) else {},
            "method": "GET", "values_kept": False, "note": _word(m.get("note"), 200)}


def _read_doc(p: str, strict: bool = False) -> Any:
    try:
        if os.path.getsize(p) > MAX_FILE_BYTES * 4 // 3 + 256:
            return None
        with open(p, "r", encoding="utf-8") as f:
            text = store_crypto.open_text(f.read())
        if len(text) > MAX_FILE_BYTES:
            return None
        return json.loads(text)
    except store_crypto.StoreLocked:
        if strict:
            raise
        return None
    except (OSError, ValueError, RecursionError):
        return None


def _profiles(p: str, strict: bool = False) -> Dict[str, str]:
    data = _read_doc(p, strict)
    pr = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(pr, dict):
        return {}
    return {str(k)[:120]: str(v) for k, v in list(pr.items())[:KEEP_TENANTS] if isinstance(v, str) and _PROFILE_ID.match(v)}


def profile_of(tenant: Any, path: Optional[str] = None) -> str:
    """The tenant profile this tenant label's maps were kept for ("" when none was named)."""
    return _profiles(path or history_path()).get(tenant_key(tenant), "")


def _load_all(path: Optional[str] = None, strict: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    data = _read_doc(path or history_path(), strict)
    t = data.get("tenants") if isinstance(data, dict) else None
    if not isinstance(t, dict):
        return {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for k, v in list(t.items())[:KEEP_TENANTS]:
        if isinstance(k, str) and isinstance(v, list):
            rows = [c for c in (clean_map(x) for x in v[-KEEP_PER_TENANT:]) if c is not None]
            out[k[:120]] = sorted(rows, key=lambda r: r["started_at"])
    return out


def load(tenant: Any, path: Optional[str] = None) -> List[Dict[str, Any]]:
    """This tenant's saved maps, oldest first; a missing or unreadable file is none."""
    return list(_load_all(path).get(tenant_key(tenant), []))


def summaries(maps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"started_at": m["started_at"], "counts": m["counts"], "rps": m["rps"], "features_only": m["features_only"], "sign_in": m["sign_in"],
             "duration_seconds": m["duration_seconds"]} for m in maps]


def save(tenant: Any, rep: Mapping[str, Any], path: Optional[str] = None, *, profile_id: str = "") -> List[Dict[str, Any]]:
    """Keep a finished map for `tenant` (a record label, never a login); the tenant's maps, oldest first."""
    clean = clean_map(dict(rep, saved_at=_now()))
    if clean is None:
        raise ValueError("The map is not valid.")
    key = tenant_key(tenant)
    p = path or history_path()
    with _LOCK:
        data = _load_all(p, strict=True)
        hist = [h for h in data.pop(key, []) if h["started_at"] != clean["started_at"]]
        data[key] = sorted(hist + [clean], key=lambda r: r["started_at"])[-KEEP_PER_TENANT:]
        while len(data) > KEEP_TENANTS:
            data.pop(next(iter(data)))
        profs = {k: v for k, v in _profiles(p, strict=True).items() if k in data}
        if _PROFILE_ID.match(str(profile_id or "")):
            profs[key] = profile_id
        _write(p, {"version": 1, "tenants": data, "profiles": profs})
        return list(data[key])


def forget(tenant: Any, path: Optional[str] = None) -> int:
    """Remove this tenant's saved maps; how many."""
    key = tenant_key(tenant)
    p = path or history_path()
    with _LOCK:
        data = _load_all(p, strict=True)
        gone = len(data.pop(key, []))
        if gone:
            _write(p, {"version": 1, "tenants": data, "profiles": {k: v for k, v in _profiles(p).items() if k in data}})
    return gone


def _write(p: str, doc: Dict[str, Any]) -> None:
    safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)))
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(p) + ".", suffix=".tmp", dir=os.path.dirname(os.path.abspath(p)))
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(store_crypto.seal_text(json.dumps(doc, indent=1)))   # sealed when store encryption is on
        for attempt in range(20):
            try:
                os.replace(tmp, p)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
