"""URL tools: the URLs export and the custom URL category analyzer.

URLs export (`urls_export`): one workbook with every URL, domain, IP
range and keyword the tenant's policy names, from

  * custom URL categories (URLs, URLs retaining the parent category,
    keywords, keywords retaining the parent category, IP ranges, IP
    ranges retaining the parent category, regex patterns);
  * URL filtering and SSL inspection rules: ZIA rules name URL categories,
    not URLs, so every entry of a custom category a rule uses is listed
    with that rule (and an SSL rule's destination IP groups with theirs);
  * Cloud Firewall rules: destination addresses (FQDNs, IPs) and the
    addresses of the IP destination groups;
  * Advanced settings: the authentication / Kerberos / DNS-resolution
    bypass URL lists (ZIA platform);
  * Client Connector app-profile bypasses and the hosts PAC files send
    DIRECT, as data_flow.read_client_connector already reads them.

Every occurrence is one row of the Occurrences sheet; the URLs sheet is
deduplicated (case, scheme and a trailing slash ignored) with a Found in
column naming each place. Only what the Scope page puts in scope is read
(sources_for), GET requests only.

Custom URL category analyzer (`analyze_categories`): for every custom
category (or the ones picked) it lists the category's URLs and asks ZIA
which categories it assigns to each, with the URL lookup the portal's URL
Lookup uses. Verified in zscaler-sdk-python (zia/url_categories.py):
GET /urlCategories/lite (list_categories_lite), GET /urlCategories/{id}
(get_category), POST /urlLookup (lookup: 100 URLs per request, the SDK
sleeps 1 s between requests). The lookup is a POST that changes nothing
in the tenant (it is how path_analyzer.lookup_categories already places a
destination), so it is treated as a read: it is the only POST this module
sends, and it never runs in write mode only. Calls are paced (`pace`
seconds apart), a 429 is retried with a growing wait (at most RETRIES
times), Stop is checked before every request and during every wait, and
the number of URLs looked up is capped (MAX_LOOKUP_URLS) with a visible
note.

Verdicts per URL:
  redundant      Zscaler already puts it in a category of the same super
                 category as the custom category: the entry likely adds
                 nothing;
  different      Zscaler categorises it under another super category: an
                 intended override, or a miscategorisation to report;
  uncategorised  Zscaler does not categorise it (no category, or only
                 Miscellaneous or unknown): the custom category is what
                 places it;
  categorised    Zscaler categorises it, but the super categories could
                 not be compared (not in the category list read);
  not_looked_up  over the cap, refused by the lookup, or rate limited.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import xlsx_writer

XLSX = xlsx_writer.MEDIA_TYPE
LookupLog = Optional[Callable[[str], None]]

LOOKUP_ENDPOINT = "/zia/urlLookup"
CATEGORIES_LITE = "/zia/urlCategories/lite"
CATEGORIES_FULL = "/zia/urlCategories"
BATCH = 100                 # the SDK's lookup chunk size
PACE_SECONDS = 1.0          # the SDK's pause between lookup requests
RETRIES = 3                 # 429 retries per batch, waits PACE * 2, 4, 8 s
MAX_LOOKUP_URLS = 2000      # 20 lookup requests at most per run
UNKNOWN_CATS = {"MISCELLANEOUS_OR_UNKNOWN", "NONE", "OTHER_MISCELLANEOUS", ""}
NO_SUPER = {"", "USER_DEFINED", "NONE", "ANY"}

STOPPED_REASON = "You clicked Stop before it finished: nothing more was read from the tenant and no file was made."
NOTHING_IN_SCOPE_URLS = ("Nothing the URLs export reads is in scope: on the Scope page tick DLP or ZIA platform (URL categories, "
                         "URL filtering, SSL inspection, Cloud Firewall) or ZCC (Client Connector bypasses and PAC files), then export again.")
NOTHING_IN_SCOPE_CATS = ("The custom URL category analyzer is not in scope: URL categories belong to URL filtering, so on the Scope "
                         "page tick DLP or ZIA platform, then run it again.")
LOOKUP_NOTE = ("The URL lookup is a POST request that changes nothing in the tenant (the same lookup the portal's URL Lookup "
               "and this app's Path analyzer use); it is the only POST sent, 100 URLs per request, paced and retried on HTTP 429.")


class Stopped(RuntimeError):
    """The operator clicked Stop."""


def _stopped(cancel: Any) -> bool:
    import data_flow
    return data_flow.stop_requested(cancel)


def _stop_point(cancel: Any) -> None:
    if _stopped(cancel):
        raise Stopped(STOPPED_REASON)


def _wait(seconds: float, cancel: Any, sleep: Callable[[float], None]) -> None:
    """Sleep in short steps, so Stop ends a wait at once."""
    left = max(0.0, seconds)
    while left > 0:
        _stop_point(cancel)
        step = min(0.25, left)
        sleep(step)
        left -= step
    _stop_point(cancel)


def _ls(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("list", "data", "items", "results"):
            if isinstance(data.get(k), list):
                return data[k]
    return []


def _ref_name(x: Any) -> str:
    if isinstance(x, dict):
        return str(x.get("name") or x.get("configuredName") or x.get("id") or "")
    return "" if x is None else str(x)


def _f(d: Dict[str, Any], *names: str, default: Any = None) -> Any:
    for n in names:
        if n in d and d[n] is not None:
            return d[n]
    return default


def kind_of(value: str, list_kind: str = "") -> str:
    """URL, domain, IP address / range, keyword or regex."""
    if list_kind in ("keyword", "regex"):
        return "Keyword" if list_kind == "keyword" else "Regex"
    v = str(value or "").strip()
    try:
        ipaddress.ip_network(v, strict=False)
        return "IP address or range"
    except ValueError:
        pass
    m = re.fullmatch(r"([0-9.:a-fA-F]+)\s*-\s*([0-9.:a-fA-F]+)", v)
    if m and _is_ip(m.group(1)) and _is_ip(m.group(2)):
        return "IP address or range"   # a range is two addresses; "dead-beef.cc" is a domain
    if list_kind == "ip":
        return "IP address or range"
    return "URL" if "/" in re.sub(r"^[a-z]+://", "", v, flags=re.I).rstrip("/") else "Domain"


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.strip())
        return True
    except ValueError:
        return False


def _list(v: Any) -> List[Any]:
    """A tenant list field as a list: anything else (a string, a number, a
    damaged snapshot's value) is no entries, never its characters."""
    return v if isinstance(v, list) else []


def norm(value: Any) -> str:
    """The deduplication key: lower case, no scheme, no trailing slash."""
    v = str(value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    return v.rstrip("/")


# ── What is in scope ─────────────────────────────────────────────────
# source key -> (label, the Scope section that puts it in scope:
# data_flow.PATH_SECTIONS keys, or "zia_extras" for ZIA platform).
SOURCES: Dict[str, Tuple[str, str]] = {
    "custom_categories": ("Custom URL categories", "url"),
    "url_filtering": ("URL filtering rules", "url"),
    "ssl_inspection": ("SSL inspection rules", "ssl"),
    "firewall": ("Cloud Firewall rules and IP destination groups", "zia_extras"),
    "advanced_settings": ("Advanced settings bypass lists", "zia_extras"),
    "client_connector": ("Client Connector bypasses", "zcc"),
    "pac": ("PAC files (DIRECT)", "pac"),
}


def sources_for(scopes: Any, channels: Any) -> Dict[str, Any]:
    """The sources the Scope page's selection lets the URLs export read.
    {read, not_in_scope, path_scope, summary}. Pure."""
    import data_flow
    ps = data_flow.path_scope(scopes, channels)
    read: List[str] = []
    nis: Dict[str, str] = {}
    for key, (label, sec) in SOURCES.items():
        if sec == "zia_extras":
            if "zia_extras" in ps["scopes"]:
                read.append(key)
            else:
                nis[key] = f"Not in scope: ZIA platform is not ticked on the Scope page, so the {label[:1].lower() + label[1:]} were not read."
        elif sec in ps["read"]:
            read.append(key)
        else:
            nis[key] = (ps.get("read_blocked") or {}).get(sec) or ps["not_in_scope"].get(sec) or "Not in scope on the Scope page."
    summary = ("In scope on the Scope page: " + ", ".join(SOURCES[k][0] for k in read) + "." if read else NOTHING_IN_SCOPE_URLS)
    return {"read": read, "not_in_scope": nis, "path_scope": ps, "summary": summary}


def analyzer_in_scope(scopes: Any, channels: Any) -> Dict[str, Any]:
    """The analyzer reads URL categories, the objects of URL filtering:
    in scope when the URL filtering section is."""
    import data_flow
    ps = data_flow.path_scope(scopes, channels)
    ok = "url" in ps["read"]
    return {"in_scope": ok, "summary": ("In scope on the Scope page: URL categories (URL filtering)." if ok else NOTHING_IN_SCOPE_CATS)}


# ── URLs export ──────────────────────────────────────────────────────
CATEGORY_LISTS = (
    ("urls", "URLs", ""), ("dbCategorizedUrls", "URLs retaining parent category", ""),
    ("keywords", "Keywords", "keyword"), ("keywordsRetainingParentCategory", "Keywords retaining parent category", "keyword"),
    ("ipRanges", "IP ranges", "ip"), ("ipRangesRetainingParentCategory", "IP ranges retaining parent category", "ip"),
    ("regexPatterns", "Regex patterns", "regex"), ("regexPatternsRetainingParentCategory", "Regex patterns retaining parent category", "regex"),
)
_SNAKE = {"dbCategorizedUrls": "db_categorized_urls", "keywordsRetainingParentCategory": "keywords_retaining_parent_category",
          "ipRanges": "ip_ranges", "ipRangesRetainingParentCategory": "ip_ranges_retaining_parent_category",
          "regexPatterns": "regex_patterns", "regexPatternsRetainingParentCategory": "regex_patterns_retaining_parent_category"}
ADVANCED_URL_LISTS = (("authBypassUrls", "Authentication bypass URLs"), ("kerberosBypassUrls", "Kerberos bypass URLs"),
                      ("digestAuthBypassUrls", "Digest authentication bypass URLs"),
                      ("dnsResolutionOnTransparentProxyExemptUrls", "DNS resolution on transparent proxy: exempt URLs"),
                      ("dnsResolutionOnTransparentProxyUrls", "DNS resolution on transparent proxy: URLs"))


def _is_custom(c: Dict[str, Any]) -> bool:
    return bool(_f(c, "customCategory", "custom_category", default=False)) or str(c.get("id") or "").startswith("CUSTOM_")


def _cat_name(c: Dict[str, Any]) -> str:
    return str(_f(c, "configuredName", "configured_name", "name", default="") or c.get("id") or "")


def _action(r: Dict[str, Any]) -> str:
    from policy_exports import humanize
    a = r.get("action")
    if isinstance(a, dict):
        a = a.get("type") or a.get("name")
    return humanize(a or r.get("filteringAction") or ", ".join(str(x) for x in _list(r.get("actions"))))


def _occ(value: Any, source: str, lst: str, category: str = "", rule: str = "", action: str = "", list_kind: str = "") -> Dict[str, Any]:
    v = str(value if not isinstance(value, dict) else (value.get("url") or value.get("name") or value.get("ip") or "")).strip()
    return {"value": v, "kind": kind_of(v, list_kind), "source": source, "list": lst, "category": category, "rule": rule, "action": action}


def collect(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every occurrence from what was read (pure). `snap`: {categories,
    url_rules, ssl_rules, firewall_rules, ip_groups, advanced,
    client_connector} as read_for_urls returns it."""
    out: List[Dict[str, Any]] = []
    cats = [c for c in _list(snap.get("categories")) if isinstance(c, dict) and _is_custom(c)]
    by_id = {str(c.get("id")): c for c in cats}
    entries: Dict[str, List[Tuple[str, str, str]]] = {}
    for c in cats:
        name = _cat_name(c)
        for field, lst, lk in CATEGORY_LISTS:
            for v in _list(c.get(field) or c.get(_SNAKE.get(field, field))):
                if str(v).strip():
                    out.append(_occ(v, "Custom URL category", lst, name, list_kind=lk))
                    entries.setdefault(str(c.get("id")), []).append((str(v), lst, lk))
    groups = {str(g.get("id")): g for g in _list(snap.get("ip_groups")) if isinstance(g, dict)}

    def via_categories(rule: Dict[str, Any], source: str) -> None:
        for ref in _list(rule.get("urlCategories") or rule.get("url_categories")):
            cid = str(ref.get("id") if isinstance(ref, dict) else ref)
            if cid in by_id:
                for v, lst, lk in entries.get(cid, []):
                    out.append(_occ(v, source, lst, _cat_name(by_id[cid]), str(rule.get("name") or ""), _action(rule), lk))

    def via_groups(rule: Dict[str, Any], source: str) -> None:
        for ref in _list(rule.get("destIpGroups") or rule.get("dest_ip_groups")):
            gid = str(ref.get("id") if isinstance(ref, dict) else ref)
            g = groups.get(gid)
            if g:
                for a in _list(g.get("addresses")):
                    out.append(_occ(a, source, "Destination IP group", f"IP group: {g.get('name') or gid}", str(rule.get("name") or ""), _action(rule)))

    for r in _list(snap.get("url_rules")):
        if isinstance(r, dict):
            via_categories(r, "URL filtering rule")
    for r in _list(snap.get("ssl_rules")):
        if isinstance(r, dict):
            via_categories(r, "SSL inspection rule")
            via_groups(r, "SSL inspection rule")
    for r in _list(snap.get("firewall_rules")):
        if not isinstance(r, dict):
            continue
        for a in _list(r.get("destAddresses") or r.get("dest_addresses")):
            out.append(_occ(a, "Cloud Firewall rule", "Destination addresses", "", str(r.get("name") or ""), _action(r)))
        via_groups(r, "Cloud Firewall rule")
    if snap.get("firewall_rules") is not None:
        for g in groups.values():
            for a in _list(g.get("addresses")):
                out.append(_occ(a, "IP destination group", humanize_type(g.get("type")), f"IP group: {g.get('name') or g.get('id')}"))
    adv = snap.get("advanced") if isinstance(snap.get("advanced"), dict) else {}
    for field, lst in ADVANCED_URL_LISTS:
        for v in _list(adv.get(field)):
            out.append(_occ(v, "Advanced settings", lst))
    zcc = snap.get("client_connector") if isinstance(snap.get("client_connector"), dict) else {}
    for p in _list(zcc.get("app_profiles")):
        if not isinstance(p, dict):
            continue
        b = p.get("bypass") if isinstance(p.get("bypass"), dict) else {}
        for v in _list(b.get("domains")):
            out.append(_occ(v, "Client Connector app profile", "Domain bypass", "", str(p.get("name") or "")))
        for v in _list(b.get("ips")):
            out.append(_occ(v, "Client Connector app profile", "IP bypass", "", str(p.get("name") or ""), list_kind="ip"))
    for f in _list(zcc.get("pac_files")):
        if not isinstance(f, dict):
            continue
        for v in _list(f.get("direct_hosts")):
            out.append(_occ(v, "PAC file", "Sent DIRECT", "", str(f.get("name") or "")))
    return [o for o in out if o["value"]]


def humanize_type(t: Any) -> str:
    from policy_exports import humanize
    return humanize(t) or "Addresses"


def dedupe(occurrences: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One row per value (norm): every place it was found, in order."""
    rows: Dict[str, Dict[str, Any]] = {}
    for o in occurrences:
        k = norm(o["value"]) + ("|" + o["kind"] if o["kind"] in ("Keyword", "Regex") else "")
        row = rows.get(k)
        if row is None:
            row = rows[k] = {"value": o["value"], "kind": o["kind"], "sources": [], "lists": [], "categories": [], "rules": [],
                             "found_in": [], "times": 0}
        row["times"] += 1
        for field, key in (("sources", "source"), ("lists", "list"), ("categories", "category"), ("rules", "rule")):
            if o[key] and o[key] not in row[field]:
                row[field].append(o[key])
        where = " · ".join(x for x in (o["source"], o["list"], o["category"], (f"rule {o['rule']}" if o["rule"] and "rule" in o["source"].lower()
                                                                                  else o["rule"]), o["action"]) if x)
        if where not in row["found_in"]:
            row["found_in"].append(where)
    return sorted(rows.values(), key=lambda r: (norm(r["value"]), r["kind"]))


def read_for_urls(client, sources: Dict[str, Any], *, log: LookupLog = None, cancel: Any = None) -> Dict[str, Any]:
    """GET only the sources in scope. A failed read is named in `errors`."""
    import data_flow
    import dlp_efficacy
    say = log or (lambda m: None)
    read = set(sources["read"])
    snap: Dict[str, Any] = {"errors": {}}

    def coll(key: str, ep: str, label: str) -> Optional[List[Dict[str, Any]]]:
        say(f"Reading the {label}…")
        _stop_point(cancel)
        ev = dlp_efficacy.read_collection(client, ep)
        if ev["status"] != "verified":
            snap["errors"][key] = ev.get("reason") or "no answer"
            say(f"The {label} could not be read ({snap['errors'][key]}).")
            return None
        say(f"{label[:1].upper() + label[1:]}: {len(ev['items'])} found.")
        return ev["items"]

    try:
        with data_flow.stop_on(client, cancel):
            if read & {"custom_categories", "url_filtering", "ssl_inspection"}:
                snap["categories"] = coll("custom_categories", CATEGORIES_FULL, "URL categories") or []
            if "url_filtering" in read:
                snap["url_rules"] = coll("url_filtering", "/zia/urlFilteringRules", "URL filtering rules")
            if "ssl_inspection" in read:
                snap["ssl_rules"] = coll("ssl_inspection", "/zia/sslInspectionRules", "SSL inspection rules")
            if "firewall" in read:
                snap["firewall_rules"] = coll("firewall", "/zia/firewallFilteringRules", "Cloud Firewall rules")
            if "firewall" in read or "ssl_inspection" in read:
                snap["ip_groups"] = coll("ip_groups", "/zia/ipDestinationGroups", "IP destination groups") or []
            if "advanced_settings" in read:
                say("Reading the Advanced settings bypass lists…")
                _stop_point(cancel)
                try:
                    data, code = client.get("/zia/advancedSettings")
                except Exception as e:  # noqa: BLE001
                    data, code = {"error": type(e).__name__}, 0
                if code == 200 and isinstance(data, dict):
                    snap["advanced"] = data
                else:
                    snap["errors"]["advanced_settings"] = f"HTTP {code}"
                    say(f"The Advanced settings could not be read (HTTP {code}).")
            if read & {"client_connector", "pac"}:
                say("Reading the Client Connector app profiles and PAC files…")
                _stop_point(cancel)
                zcc = data_flow.read_client_connector(client, scope=sources["path_scope"], cancel=cancel)
                snap["client_connector"] = zcc
                for err in zcc.get("errors") or []:
                    key = "pac" if "pacFiles" in str(err) else "client_connector"
                    snap["errors"].setdefault(key, str(err)[:200])
            _stop_point(cancel)
    except (data_flow.ReadStopped, dlp_efficacy.CorpusReadStopped) as e:
        raise Stopped(STOPPED_REASON) from e
    except Exception as e:  # noqa: BLE001
        import zia_rate
        if isinstance(e, zia_rate.Cancelled):
            raise Stopped(STOPPED_REASON) from e
        raise
    return snap


URLS_NOTE = ("ZIA URL filtering and SSL inspection rules name URL categories, not URLs: each entry of a custom category a rule "
             "uses is listed with that rule. Predefined categories are maintained by Zscaler and list no URLs.")


def urls_workbook(occurrences: List[Dict[str, Any]], *, tenant_label: str = "", sources: Optional[Dict[str, Any]] = None,
                  errors: Optional[Dict[str, str]] = None) -> bytes:
    rows = dedupe(occurrences)
    wb = xlsx_writer.Workbook(title=f"URLs export {tenant_label}".strip(), subject="Every URL, domain and IP the policy names")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    from datetime import datetime, timezone
    s.extend([["Tenant", tenant_label or "Not named"], ["Exported", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
              ["Unique values", len(rows)], ["Occurrences", len(occurrences)]])
    per: Dict[str, int] = {}
    for o in occurrences:
        per[o["source"]] = per.get(o["source"], 0) + 1
    for k, n in sorted(per.items()):
        s.append([f"Found in {k[:1].lower() + k[1:]}", n])
    for k, why in sorted((errors or {}).items()):
        s.append([f"Could not be read: {SOURCES.get(k, (k,))[0] if k in SOURCES else k.replace('_', ' ')}", why])
    for k, why in sorted(((sources or {}).get("not_in_scope") or {}).items()):
        s.append([f"Not in scope: {SOURCES[k][0]}", why])
    s.append(["Note", URLS_NOTE])
    s.append(["How it was read", "Read-only: GET requests only; nothing was written. Only the sources in scope on the Scope page were read."])
    wb.add_sheet("URLs", columns=["Value", "Kind", "Found in", "Sources", "Lists", "Categories", "Rules or profiles", "Times found"],
                 rows=[[r["value"], r["kind"], r["found_in"], r["sources"], r["lists"], r["categories"], r["rules"], r["times"]] for r in rows])
    wb.add_sheet("Occurrences", columns=["Value", "Kind", "Source", "List", "Category", "Rule or profile", "Action"],
                 rows=[[o["value"], o["kind"], o["source"], o["list"], o["category"], o["rule"], o["action"]] for o in occurrences])
    return wb.to_bytes()


def urls_export(client, sources: Dict[str, Any], *, tenant_label: str = "", log: LookupLog = None, cancel: Any = None) -> Dict[str, Any]:
    say = log or (lambda m: None)
    snap = read_for_urls(client, sources, log=say, cancel=cancel)
    occ = collect(snap)
    _stop_point(cancel)
    data = urls_workbook(occ, tenant_label=tenant_label, sources=sources, errors=snap["errors"])
    from policy_exports import safe_part
    from datetime import datetime, timezone
    name = f"urls_export_{safe_part(tenant_label)}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    uniq = len(dedupe(occ))
    say(f"Ready: {name}: {uniq} unique value{'s' if uniq != 1 else ''} from {len(occ)} occurrence{'s' if len(occ) != 1 else ''}.")
    return {"status": "ready", "filename": name, "unique": uniq, "occurrences": len(occ), "errors": snap["errors"],
            "not_in_scope": sources.get("not_in_scope") or {}, "artifact": (name, XLSX, data)}


# ── Custom URL category analyzer ─────────────────────────────────────
def lookup_batches(client, urls: Sequence[str], *, pace: Optional[float] = None, retries: int = RETRIES, log: LookupLog = None,
                   cancel: Any = None, sleep: Callable[[float], None] = time.sleep) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str], Dict[str, int]]:
    """POST /zia/urlLookup, BATCH URLs per request, `pace` seconds between
    requests, a 429 retried after pace * 2**attempt seconds. Returns
    ({url: {categories, security_alerts}}, {url: why not looked up},
    stats). Raises Stopped on Stop."""
    say = log or (lambda m: None)
    pace = PACE_SECONDS if pace is None else pace
    post = getattr(client, "post", None)
    found: Dict[str, Dict[str, Any]] = {}
    missed: Dict[str, str] = {}
    stats = {"requests": 0, "retries": 0}
    if not callable(post):
        return found, {u: "this client cannot run a URL lookup" for u in urls}, stats
    batches = [list(urls[i:i + BATCH]) for i in range(0, len(urls), BATCH)]
    for n, batch in enumerate(batches, 1):
        if n > 1:
            _wait(pace, cancel, sleep)
        attempt = 0
        while True:
            _stop_point(cancel)
            say(f"Looking up {len(batch)} URL{'s' if len(batch) != 1 else ''} (request {n} of {len(batches)})…")
            stats["requests"] += 1
            try:
                data, code = post(LOOKUP_ENDPOINT, [_lookup_form(u) for u in batch])
            except Exception as e:  # noqa: BLE001
                data, code = {"error": type(e).__name__}, 0
            _stop_point(cancel)   # a Stop during the request: the client answered "run stopped"
            if code == 429 and attempt < retries:
                attempt += 1
                stats["retries"] += 1
                wait = max(pace, 0.5) * (2 ** attempt)
                say(f"ZIA asked to slow down (HTTP 429): waiting {wait:g} s, then retry {attempt} of {retries}.")
                _wait(wait, cancel, sleep)
                continue
            break
        if code not in (200, 201) or not isinstance(data, list):
            why = "rate limited (HTTP 429) after retries" if code == 429 else f"the lookup answered HTTP {code}"
            for u in batch:
                missed[u] = why
            say(f"Request {n}: {why}; those URLs are marked not looked up.")
            continue
        by_url = {}
        for e in data:
            if isinstance(e, dict) and e.get("url") is not None:
                by_url[_match_key(e.get("url"))] = e
        for i, u in enumerate(batch):
            e = by_url.get(_match_key(_lookup_form(u)))
            if e is None and i < len(data) and isinstance(data[i], dict) and "url" not in data[i]:
                e = data[i]
            if e is None:
                missed[u] = "not in the lookup's answer"
                continue
            cats = _list(e.get("urlClassifications") or e.get("url_classifications"))
            alerts = _list(e.get("urlClassificationsWithSecurityAlert") or e.get("url_classifications_with_security_alert"))
            found[u] = {"categories": sorted({str(c).upper() for c in cats if c}), "security_alerts": sorted({str(c).upper() for c in alerts if c})}
    return found, missed, stats


def _match_key(u: Any) -> str:
    """How a URL asked about is found in the lookup's answer: norm(), with
    an internationalised host in its ASCII (IDNA) form, so a URL sent as
    bücher.de is matched whether the answer spells it that way or as
    xn--bcher-kva.de (how the lookup spells it is assumed, not documented)."""
    v = norm(u)
    host, sep, rest = v.partition("/")
    if host and not host.isascii():
        try:
            host = ".".join(lbl.encode("idna").decode("ascii") if lbl and not lbl.isascii() else lbl for lbl in host.split("."))
        except UnicodeError:
            pass
    return host + sep + rest


def _lookup_form(u: str) -> str:
    """What the lookup is asked for: no scheme, no leading wildcard or dot."""
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(u).strip(), flags=re.I)
    return re.sub(r"^(\*\.|\.)", "", v)


def classify(entry: Optional[Dict[str, Any]], custom: Dict[str, Any], supers: Dict[str, str]) -> Tuple[str, List[str]]:
    """(verdict, Zscaler's categories) for one looked-up URL of `custom`."""
    if entry is None:
        return "not_looked_up", []
    own = {str(custom.get("id") or "").upper()}
    # Only Zscaler's own categories say how Zscaler places a URL: the
    # tenant's other custom categories (CUSTOM_nn) are the tenant's choice.
    cats = [c for c in _list(entry.get("categories")) if c not in own and not str(c).upper().startswith("CUSTOM_")]
    known = [c for c in cats if c not in UNKNOWN_CATS]
    if not known:
        return "uncategorised", cats
    mine = str(custom.get("superCategory") or custom.get("super_category") or "").upper()
    if mine in NO_SUPER:
        return "different", cats
    theirs = [supers.get(c) for c in known]
    if any(s and s.upper() == mine for s in theirs):
        return "redundant", cats
    if all(s for s in theirs):
        return "different", cats
    return "categorised", cats


VERDICTS = {
    "redundant": "Zscaler already puts it in a category of the same super category: the custom entry is likely redundant.",
    "different": "Zscaler categorises it differently: your custom category overrides that; check it is an intended override, "
                 "or report the miscategorisation to Zscaler.",
    "uncategorised": "Zscaler does not categorise it: the custom category is what places it.",
    "categorised": "Zscaler categorises it, but its super category is not in the category list read, so it could not be compared.",
    "not_looked_up": "Not looked up.",
}
VERDICT_LABELS = {"redundant": "Redundant", "different": "Categorised differently", "uncategorised": "Not categorised",
                  "categorised": "Categorised (not compared)", "not_looked_up": "Not looked up"}


def analyze_categories(client, *, picked: Optional[Sequence[str]] = None, max_urls: int = MAX_LOOKUP_URLS, pace: Optional[float] = None,
                       log: LookupLog = None, cancel: Any = None, sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    """List the custom categories (GET /urlCategories/lite), read each
    picked one (GET /urlCategories/{id}), look its URLs up (POST
    /urlLookup, paced, capped) and classify every URL. Raises Stopped."""
    import data_flow
    import dlp_efficacy
    from urllib.parse import quote
    say = log or (lambda m: None)
    pace = PACE_SECONDS if pace is None else pace
    max_urls = max(1, min(int(max_urls or MAX_LOOKUP_URLS), MAX_LOOKUP_URLS))
    notes: List[str] = [LOOKUP_NOTE]
    try:
        with data_flow.stop_on(client, cancel):
            say("Reading the URL categories (lite list)…")
            _stop_point(cancel)
            ev = dlp_efficacy.read_collection(client, CATEGORIES_LITE)
            if ev["status"] != "verified":
                return {"status": "error", "error": f"The URL categories could not be read ({ev.get('reason') or 'no answer'}); nothing was looked up."}
            lite = [c for c in ev["items"] if isinstance(c, dict)]
            supers = {str(c.get("id")).upper(): str(c.get("superCategory") or c.get("super_category") or "") for c in lite if c.get("id")}
            supers = {k: v for k, v in supers.items() if v}
            names = {str(c.get("id")).upper(): _cat_name(c) for c in lite if c.get("id")}
            custom = [c for c in lite if _is_custom(c)]
            say(f"URL categories: {len(lite)} found, {len(custom)} custom.")
            want = [str(p).strip() for p in picked or [] if str(p).strip()]
            if want:
                keys = {w.lower() for w in want}
                chosen = [c for c in custom if str(c.get("id")).lower() in keys or _cat_name(c).lower() in keys]
                unknown = sorted(w for w in want if w.lower() not in {str(c.get("id")).lower() for c in chosen} | {_cat_name(c).lower() for c in chosen})
                if unknown:
                    shown = [u[:80] for u in unknown[:20]]
                    more = f" and {len(unknown) - len(shown)} more" if len(unknown) > len(shown) else ""
                    notes.append("Not custom categories of this tenant, so not analysed: " + ", ".join(shown) + more + ".")
            else:
                chosen = custom
            details: List[Dict[str, Any]] = []
            for c in chosen:
                say(f"Reading the custom category {_cat_name(c)}…")
                _stop_point(cancel)
                try:
                    data, code = client.get(f"{CATEGORIES_FULL}/{quote(str(c.get('id')), safe='')}")
                except Exception as e:  # noqa: BLE001
                    data, code = {"error": type(e).__name__}, 0
                if code != 200 or not isinstance(data, dict):
                    details.append(dict(c, _error=f"HTTP {code}"))
                    say(f"{_cat_name(c)} could not be read (HTTP {code}).")
                    continue
                details.append(dict(c, **data))
            # Every (category, list, url), in order; the lookup is asked once per distinct URL.
            items: List[Tuple[Dict[str, Any], str, str]] = []
            for c in details:
                for field, lst in (("urls", "URLs"), ("dbCategorizedUrls", "URLs retaining parent category")):
                    for u in _list(c.get(field) or c.get(_SNAKE.get(field, field))):
                        if str(u).strip():
                            items.append((c, lst, str(u).strip()))
            distinct: List[str] = []
            seen = set()
            for _, _, u in items:
                k = norm(_lookup_form(u))
                if k not in seen:
                    seen.add(k)
                    distinct.append(u)
            capped = distinct[max_urls:]
            todo = distinct[:max_urls]
            if capped:
                notes.append(f"Capped at {max_urls} URLs: {len(capped)} more were not looked up (shown as not looked up). "
                             "Pick fewer categories to look the rest up.")
                say(notes[-1])
            say(f"Looking up {len(todo)} URL{'s' if len(todo) != 1 else ''} in {(len(todo) + BATCH - 1) // BATCH} request(s), "
                f"{pace:g} s apart. {LOOKUP_NOTE}")
            found, missed, stats = lookup_batches(client, todo, pace=pace, log=say, cancel=cancel, sleep=sleep)
            _stop_point(cancel)
    except (data_flow.ReadStopped, dlp_efficacy.CorpusReadStopped) as e:
        raise Stopped(STOPPED_REASON) from e
    except Exception as e:  # noqa: BLE001
        import zia_rate
        if isinstance(e, zia_rate.Cancelled):
            raise Stopped(STOPPED_REASON) from e
        raise
    by_norm = {norm(_lookup_form(u)): u for u in todo}
    rows: List[Dict[str, Any]] = []
    per: Dict[str, Dict[str, Any]] = {}
    for c, lst, u in items:
        key = by_norm.get(norm(_lookup_form(u)))
        entry = found.get(key) if key else None
        verdict, cats = classify(entry, c, supers)
        why = VERDICTS[verdict]
        if verdict == "not_looked_up":
            why = "Not looked up: " + (missed.get(key) if key and key in missed else "over the cap") + "."
        elif lst.startswith("URLs retaining") and verdict in ("different", "categorised", "redundant"):
            why += " It is listed to retain its parent category, so Zscaler's category still applies alongside the custom one."
        name = _cat_name(c)
        rows.append({"category": name, "category_id": c.get("id"), "list": lst, "url": u, "zscaler_categories": [names.get(x, x) for x in cats],
                     "security_alerts": [names.get(x, x) for x in (entry or {}).get("security_alerts", [])], "verdict": verdict,
                     "verdict_label": VERDICT_LABELS[verdict], "why": why})
        p = per.setdefault(name, {"category": name, "id": c.get("id"), "super_category": c.get("superCategory") or "", "urls": 0,
                                  **{v: 0 for v in VERDICTS}})
        p["urls"] += 1
        p[verdict] += 1
    for c in details:
        if c.get("_error"):
            per.setdefault(_cat_name(c), {"category": _cat_name(c), "id": c.get("id"), "super_category": c.get("superCategory") or "",
                                          "urls": 0, "error": c["_error"], **{v: 0 for v in VERDICTS}})
    totals = {v: sum(1 for r in rows if r["verdict"] == v) for v in VERDICTS}
    say(f"Done: {len(rows)} URL{'s' if len(rows) != 1 else ''} in {len(per)} categor{'ies' if len(per) != 1 else 'y'}: "
        f"{totals['redundant']} redundant, {totals['different']} categorised differently, {totals['uncategorised']} not categorised, "
        f"{totals['not_looked_up']} not looked up.")
    return {"status": "ready", "rows": rows, "per_category": list(per.values()), "totals": totals, "notes": notes,
            "lookup": {"requests": stats["requests"], "retries": stats["retries"], "looked_up": len(found), "cap": max_urls,
                       "over_cap": len(capped), "batch": BATCH, "pace_seconds": pace}}


def analyzer_workbook(res: Dict[str, Any], *, tenant_label: str = "") -> bytes:
    from datetime import datetime, timezone
    wb = xlsx_writer.Workbook(title=f"Custom URL category analysis {tenant_label}".strip(), subject="Custom URL categories against Zscaler's own categories")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    t = res.get("totals") or {}
    lk = res.get("lookup") or {}
    s.extend([["Tenant", tenant_label or "Not named"], ["Analysed", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
              ["Custom categories", len(res.get("per_category") or [])], ["URLs", len(res.get("rows") or [])]]
             + [[VERDICT_LABELS[v], t.get(v, 0)] for v in VERDICTS]
             + [["Lookup requests", lk.get("requests", 0)], ["Retries after HTTP 429", lk.get("retries", 0)], ["Cap (URLs looked up per run)", lk.get("cap", "")]]
             + [["Note", n] for n in res.get("notes") or []]
             + [["What the verdicts mean", "; ".join(f"{VERDICT_LABELS[k]}: {v}" for k, v in VERDICTS.items() if k != "not_looked_up")]])
    wb.add_sheet("Per category", columns=["Category", "ID", "Super category", "URLs"] + [VERDICT_LABELS[v] for v in VERDICTS] + ["Could not be read"],
                 rows=[[p["category"], p["id"], p.get("super_category") or "", p["urls"]] + [p.get(v, 0) for v in VERDICTS] + [p.get("error") or ""]
                       for p in res.get("per_category") or []])
    wb.add_sheet("URLs", columns=["Category", "List", "URL", "Zscaler categories", "Security alert categories", "Verdict", "What it means"],
                 rows=[[r["category"], r["list"], r["url"], r["zscaler_categories"], r["security_alerts"], r["verdict_label"], r["why"]]
                       for r in res.get("rows") or []])
    return wb.to_bytes()
