"""Category lookup: what ZIA calls a URL, host or IP address (or a URL
category), and every rule that names that category, in evaluation order.

For each entry (up to MAX_ENTRIES per run):

* a URL, host name or IP address: its ZIA URL categories, predefined and
  custom. The predefined ones come from ZIA's URL lookup (POST /urlLookup,
  the lookup the Path analyzer and Test a list use, paced and capped by
  bulk_test.lookup_all); the custom ones, and any predefined category the
  tenant added the host to, come from the tenant's own category lists
  (GET /urlCategories, matched with ZIA's URL-list semantics:
  zia_path_modules.url_hit). The cloud application the lookup names is
  given too, with the Cloud App Control rules that name it.
* a category (its id, such as GAMBLING or CUSTOM_01, or its name, such as
  "Partner portals"): the category itself.

Then, for every category, each rule that references it across URL
filtering, SSL inspection, Cloud Firewall, DNS Control, File Type Control,
Web DLP and Sandbox, in the order ZIA evaluates the rules (the default rule
last; by admin rank first when admin ranking is on: admin_rank), with the
rule's order, rank, action and state, and where it names the category
(URL categories, the second URL category set, destination IP categories,
resolved IP categories, or an IP destination group's categories). Cloud
App Control rules name applications, not categories: they are listed for
the application the lookup names. Rules with no category condition (they
apply to every category) are counted per policy, not listed.

What is read is only what the Scope page puts in scope (data_flow.
path_scope: URL filtering, SSL inspection, Cloud App Control and File Type
Control with DLP or ZIA platform; Web DLP with DLP and Inline Web DLP on
Zscaler; Cloud Firewall, DNS Control and Sandbox with ZIA platform); a
policy out of scope says so and is never read. Read-only: the URL lookup is
a POST that changes nothing. Stop is honoured between every request.
Every endpoint is in zscaler-sdk-python 1.11.3 (zia/url_filtering_rules,
ssl_inspection_rules, cloudappcontrol, file_type_control_rule, dlp_web_rules,
cloud_firewall_rules, cloud_firewall_dns, sandbox_rules, cloud_firewall
(ipDestinationGroups), url_categories (list, lookup)).
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import admin_rank

LogFn = Optional[Callable[[str], None]]

MAX_ENTRIES = 100           # entries per run: one POST /urlLookup of up to 100 hosts (bulk_test.LOOKUP_CHUNK), paced
MAX_TEXT = 64_000           # characters of input (100 entries of up to MAX_ENTRY characters, with separators)
MAX_ENTRY = 512             # characters per entry
MAX_RULES_PER_CATEGORY = 300
MAX_NAME = 200
LOOKUP_REQUESTS = 5         # POST /urlLookup requests per run at most (a hundred hosts each)

# key -> label, endpoint, the fields that name URL categories (field, how
# the page says it), the field(s) that hold the action.
SECTIONS: Dict[str, Dict[str, Any]] = {
    "url": {"label": "URL filtering", "endpoint": "/zia/urlFilteringRules",
            "fields": (("urlCategories", "URL categories"), ("urlCategories2", "second URL category set (both sets must match)")),
            "action": ("action",)},
    "cac": {"label": "Cloud App Control", "endpoint": "/zia/cloudApplicationRules", "fields": (), "action": ("actions", "action")},
    "ssl": {"label": "SSL inspection", "endpoint": "/zia/sslInspectionRules", "fields": (("urlCategories", "URL categories"),),
            "action": ("action",)},
    "firewall": {"label": "Cloud Firewall", "endpoint": "/zia/firewallFilteringRules",
                 "fields": (("destIpCategories", "destination IP categories"),), "groups": True, "action": ("action",)},
    "dns": {"label": "DNS Control", "endpoint": "/zia/firewallDnsRules",
            "fields": (("destIpCategories", "requested domain categories"), ("resCategories", "resolved IP categories")),
            "groups": True, "action": ("action",)},
    "ftc": {"label": "File Type Control", "endpoint": "/zia/fileTypeRules", "fields": (("urlCategories", "URL categories"),),
            "action": ("filteringAction", "action")},
    "dlp": {"label": "Web DLP", "endpoint": "/zia/webDlpRules", "fields": (("urlCategories", "URL categories"),), "action": ("action",)},
    "sandbox": {"label": "Sandbox", "endpoint": "/zia/sandboxRules", "fields": (("urlCategories", "URL categories"),),
                "action": ("baRuleAction", "action")},
}
ORDER = ("url", "cac", "ssl", "firewall", "dns", "ftc", "dlp", "sandbox")
GROUPS_ENDPOINT = "/zia/ipDestinationGroups"
CATEGORIES_ENDPOINT = "/zia/urlCategories"
NOTHING = ("Nothing the category lookup reads is in scope on the Scope page: tick DLP or ZIA platform (and mark the channels Zscaler) "
           "so URL filtering, SSL inspection or the other policies can be read. Nothing was read.")
STOPPED = "You clicked Stop before the lookup finished: nothing more was read and no partial result is shown. Nothing was written."


class Stopped(RuntimeError):
    pass


class EntryError(ValueError):
    """An entry list that cannot be looked up (said in words)."""


def _clip(v: Any, n: int = MAX_NAME) -> str:
    return str(v if v is not None else "")[:n]


def _upper_id(v: Any) -> str:
    return re.sub(r"\s+", "_", str(v or "").strip()).upper()[:120]


# ── The entries ──────────────────────────────────────────────────────
_CAT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _&()'/+,.-]{0,79}$")


def parse(text: Any) -> Dict[str, Any]:
    """The entries typed or sent: one per line (commas and semicolons
    separate too, except inside a category name after 'category:'). A URL,
    host name or IP address is a destination; anything without a dot that
    is not an IP address, or that starts with 'category:', is a category.
    Returns {entries: [{input, kind, host, path, query}], skipped: [{text,
    why}]}. Raises EntryError for nothing to look up or too much."""
    import path_analyzer
    if not isinstance(text, str):
        raise EntryError("Type a URL, a host name, an IP address or a category.")
    if len(text) > MAX_TEXT:
        raise EntryError(f"The list is longer than {MAX_TEXT:,} characters: look up at most {MAX_ENTRIES} entries at a time.")
    parts: List[str] = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("category:"):
            parts.append(line)
        else:
            parts += [p.strip() for p in re.split(r"[,;\t]+", line) if p.strip()]
    entries: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []
    seen = set()
    for p in parts:
        if len(entries) >= MAX_ENTRIES:
            skipped.append({"text": _clip(p, 120), "why": f"Only the first {MAX_ENTRIES} entries are looked up in one run."})
            continue
        if len(p) > MAX_ENTRY:
            skipped.append({"text": _clip(p, 120) + "…", "why": f"Longer than {MAX_ENTRY} characters."})
            continue
        if any(ord(c) < 32 or ord(c) == 127 for c in p):
            skipped.append({"text": _clip(p.encode("unicode_escape").decode("ascii"), 120), "why": "It holds control characters."})
            continue
        forced = p.lower().startswith("category:")
        q = p[9:].strip() if forced else p
        is_ip = False
        try:
            ipaddress.ip_address(q.strip("[]"))
            is_ip = True
        except ValueError:
            pass
        if forced or ("." not in q and "/" not in q and not is_ip):
            if not _CAT_RE.match(q):
                skipped.append({"text": _clip(p, 120), "why": "A category is its id (GAMBLING, CUSTOM_01) or its name, in letters, digits and spaces."})
                continue
            key = ("category", q.upper())
            if key in seen:
                continue
            seen.add(key)
            entries.append({"input": _clip(p, MAX_ENTRY), "kind": "category", "host": "", "path": "", "query": q})
            continue
        try:
            d = path_analyzer.parse_destination(q)
        except ValueError as e:
            skipped.append({"text": _clip(p, 120), "why": str(e)[:200]})
            continue
        key = ("host", d["host"], d["path"])
        if key in seen:
            continue
        seen.add(key)
        entries.append({"input": _clip(p, MAX_ENTRY), "kind": "host", "host": d["host"], "path": d["path"] or "/",
                        "is_ip": d["is_ip"], "query": ""})
    if not entries:
        raise EntryError("Nothing to look up: type a URL, a host name, an IP address or a category (one per line)."
                           + (f" Skipped: {skipped[0]['text']} ({skipped[0]['why']})" if skipped else ""))
    return {"entries": entries, "skipped": skipped}


# ── What is in scope ─────────────────────────────────────────────────
def lookup_scope(scope: Dict[str, Any]) -> Dict[str, Any]:
    """The policies this lookup may read for a data_flow.path_scope:
    {read: [keys in ORDER], not_in_scope: {key: why}, lookup: whether ZIA's
    URL lookup and the category list may be read}."""
    read = [k for k in ORDER if k in (scope.get("read") or [])]
    nis = {k: str((scope.get("not_in_scope") or {}).get(k) or f"Not in scope: the {SECTIONS[k]['label']} rules were not read.")
           for k in ORDER if k not in read}
    # A control declared covered by another product (data_flow's
    # read_blocked) is not read here either: said with its reason.
    blocked = {k: str(v) for k, v in (scope.get("read_blocked") or {}).items() if k in SECTIONS}
    nis.update({k: f"Not read: {v}" for k, v in blocked.items()})
    read = [k for k in read if k not in blocked]
    return {"read": read, "not_in_scope": nis, "lookup": bool(read)}


# ── Reading the tenant ───────────────────────────────────────────────
def _stop(cancel: Any) -> None:
    from data_flow import stop_requested
    if stop_requested(cancel):
        raise Stopped(STOPPED)


def _get_list(client: Any, ep: str, label: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """(complete list, None) or (None, why): a failed read is never an empty list."""
    from ssl_flow import _fetch_rules
    diags: List[Dict[str, Any]] = []
    rows = _fetch_rules(client, ep, diags, label)
    if diags:
        d = diags[0]
        return None, f"{label}: {d.get('error_type')}" + (f" ({_clip(d.get('error'), 160)})" if d.get("error") else "")
    return rows, None


def read(client: Any, scope: Dict[str, Any], *, cancel: Any = None, log: LogFn = None) -> Dict[str, Any]:
    """Read the policies in scope once: {sections: {key: {state: read |
    unread | out_of_scope, why, rules}}, groups, categories, categories_error,
    admin_ranking, read_at}. Only what is in scope is read."""
    from data_flow import ReadStopped, stop_on
    import zia_rate
    say = log or (lambda m: None)
    ls = lookup_scope(scope)
    out: Dict[str, Any] = {"sections": {}, "groups": None, "groups_error": None, "categories": {}, "categories_error": None,
                           "scope_key": scope.get("key"), "read_at": time.time()}
    try:
        with stop_on(client, cancel):
            for k in ORDER:
                if k not in ls["read"]:
                    out["sections"][k] = {"state": "out_of_scope", "why": ls["not_in_scope"].get(k), "rules": []}
                    continue
                _stop(cancel)
                say(f"Reading the {SECTIONS[k]['label']} rules…")
                rows, err = _get_list(client, SECTIONS[k]["endpoint"], f"{SECTIONS[k]['label']} rules")
                out["sections"][k] = {"state": "unread" if rows is None else "read", "why": err, "rules": rows or []}
            if any(k in ls["read"] for k in ("firewall", "dns")):
                _stop(cancel)
                say("Reading the IP destination groups (their IP categories)…")
                groups, err = _get_list(client, GROUPS_ENDPOINT, "IP destination groups")
                out["groups"] = None if groups is None else {str(g.get("id")): g for g in groups}
                out["groups_error"] = err
            if ls["lookup"]:
                _stop(cancel)
                say("Reading the URL categories (their names and the tenant's own lists)…")
                cats, err = _get_list(client, CATEGORIES_ENDPOINT, "URL categories")
                out["categories"] = category_map(cats or [])
                out["categories_error"] = err
            _stop(cancel)
            if admin_rank.in_scope(scope.get("scopes")):
                out["admin_ranking"] = admin_rank.read(client, scope.get("scopes"))
            else:
                out["admin_ranking"] = {"state": admin_rank.OUT_OF_SCOPE, "why": admin_rank.NOT_IN_SCOPE_WHY, "source": admin_rank.SOURCE}
            _stop(cancel)
    except (ReadStopped, zia_rate.Cancelled) as e:
        raise Stopped(STOPPED) from e
    return out


def category_map(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """{ID: {id, name, custom, urls, db_urls}} from /urlCategories (the id
    upper case; custom when the API says so or the id is CUSTOM_*)."""
    out: Dict[str, Dict[str, Any]] = {}
    for c in rows:
        if not isinstance(c, dict) or c.get("id") in (None, ""):
            continue
        cid = _upper_id(c.get("id"))
        urls = [str(u) for u in (c.get("urls") or []) if isinstance(u, (str, int))][:50_000]
        db = [str(u) for u in (c.get("dbCategorizedUrls") or c.get("db_categorized_urls") or []) if isinstance(u, (str, int))][:50_000]
        out[cid] = {"id": cid, "name": _clip(c.get("configuredName") or c.get("configured_name") or c.get("name") or cid),
                    "custom": bool(c.get("customCategory") or c.get("custom_category") or c.get("custom")) or cid.startswith("CUSTOM_"),
                    "urls": urls, "db_urls": db}
    return out


def lookups(client: Any, hosts: List[str], *, cancel: Any = None, log: LogFn = None) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """ZIA's URL lookup for the hosts, through bulk_test.lookup_all (a
    hundred per request, paced, a quota stop said in words)."""
    import bulk_test
    if not hosts:
        return {}, {"destinations": 0, "requests": 0}
    try:
        return bulk_test.lookup_all(client, hosts, cancel=cancel, log=log, max_requests=LOOKUP_REQUESTS)
    except bulk_test.Stopped as e:
        raise Stopped(STOPPED) from e


# ── The answer ───────────────────────────────────────────────────────
def _ids(v: Any) -> List[str]:
    """Category ids from a rule field: strings, or {id, name} objects."""
    items = v if isinstance(v, (list, tuple)) else [v] if isinstance(v, (str, dict)) else []
    out = []
    for x in items:
        if isinstance(x, dict):
            x = x.get("id") if x.get("id") not in (None, "") else x.get("name")
        if isinstance(x, (str, int)) and str(x).strip():
            out.append(_upper_id(x))
    return out


def _field(r: Dict[str, Any], camel: str) -> Any:
    import zia_path_modules
    return zia_path_modules._f(r, camel)


def _action(r: Dict[str, Any], fields: Tuple[str, ...]) -> str:
    for f in fields:
        a = _field(r, f)
        if isinstance(a, dict):
            a = a.get("type") or a.get("name")
        if isinstance(a, list):
            a = ", ".join(str(x) for x in a[:6]) + (f" (+{len(a) - 6})" if len(a) > 6 else "")
        if a not in (None, ""):
            return _clip(str(a).upper(), 160)
    return ""


def _ordered(key: str, rules: List[Dict[str, Any]], ranked: bool) -> List[Dict[str, Any]]:
    """The rules in evaluation order: the default rule last, by admin rank
    first when ranking is on, then by rule order and id."""
    import zia_path_modules as zpm
    return admin_rank.ordered([r for r in rules if isinstance(r, dict)], lambda r: zpm._order_key(r)[1:], ranked, zpm._is_default)


def _ref(key: str, r: Dict[str, Any], pos: Optional[int], via: str, ranked: bool) -> Dict[str, Any]:
    import zia_path_modules as zpm
    state = str(_field(r, "state") or "ENABLED").upper()
    out = {"section": key, "section_label": SECTIONS[key]["label"], "id": _clip(_field(r, "id"), 40), "name": _clip(_field(r, "name") or f"rule {_field(r, 'id')}"),
           "order": _field(r, "order"), "rank": admin_rank.shown_rank({"rank": _field(r, "rank")}), "position": pos,
           "action": _action(r, SECTIONS[key]["action"]), "enabled": state != "DISABLED", "default": zpm._is_default(r), "via": via}
    if ranked:
        out["ranked"] = True
    return out


def index(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Per policy, the rules in evaluation order and, per category id, the
    rules that name it: {by_category: {ID: [ref]}, by_app: {APP: [ref]},
    any_count: {key: n}, ranked, ranking_state}."""
    st = admin_rank.state_of(snap.get("admin_ranking"))
    ranked = st == admin_rank.ON
    groups = snap.get("groups") or {}
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    by_app: Dict[str, List[Dict[str, Any]]] = {}
    any_count: Dict[str, int] = {}
    for key in ORDER:
        sec = (snap.get("sections") or {}).get(key) or {}
        if sec.get("state") != "read":
            continue
        pos = 0
        for r in _ordered(key, sec.get("rules") or [], ranked):
            enabled = str(_field(r, "state") or "ENABLED").upper() != "DISABLED"
            if enabled:
                pos += 1
            p = pos if enabled else None
            if key == "cac":
                for app in _ids(_field(r, "applications")):
                    by_app.setdefault(app, []).append(_ref(key, r, p, "cloud applications", ranked))
                continue
            named = False
            for f, words in SECTIONS[key]["fields"]:
                ids = _ids(_field(r, f))
                if any(i in ("ANY", "ALL") for i in ids):
                    continue
                for cid in dict.fromkeys(ids):
                    if cid in ("NONE",):
                        continue
                    named = True
                    by_cat.setdefault(cid, []).append(_ref(key, r, p, words, ranked))
            if SECTIONS[key].get("groups"):
                for g in (_field(r, "destIpGroups") or []):
                    gid = str(g.get("id")) if isinstance(g, dict) else str(g)
                    full = groups.get(gid) or {}
                    for cid in dict.fromkeys(_ids(full.get("ipCategories") or full.get("ip_categories"))):
                        named = True
                        gname = _clip((g.get("name") if isinstance(g, dict) else None) or full.get("name") or gid, 80)
                        by_cat.setdefault(cid, []).append(_ref(key, r, p, f"IP destination group '{gname}'", ranked))
            if not named and enabled and key in ("url", "ssl", "ftc", "dlp", "sandbox") and not _ids(_field(r, "cloudApplications")):
                any_count[key] = any_count.get(key, 0) + 1
    return {"by_category": by_cat, "by_app": by_app, "any_count": any_count, "ranked": ranked, "ranking_state": st}


def _cat_ref(cid: str, cats: Dict[str, Dict[str, Any]], source: str) -> Dict[str, Any]:
    c = cats.get(cid) or {}
    return {"id": cid, "name": c.get("name") or cid.replace("_", " ").title(), "custom": bool(c.get("custom")) or cid.startswith("CUSTOM_"),
            "known": bool(c), "source": source}


def _resolve_category(q: str, cats: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """A typed category (its id or its name, any case) as its id."""
    qid = _upper_id(q)
    if qid in cats:
        return qid
    ql = q.strip().lower()
    hit = next((cid for cid, c in cats.items() if str(c.get("name") or "").strip().lower() == ql), None)
    if hit:
        return hit
    # Not in the tenant's list: an id as typed (GAMBLING) is kept, a name (with spaces) is not.
    return qid if re.fullmatch(r"[A-Za-z0-9_]{2,80}", q.strip()) else None


def answer(snap: Dict[str, Any], parsed: Dict[str, Any], looked: Dict[str, Dict[str, Any]], lookup_state: Optional[Dict[str, Any]] = None,
           scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The result: per entry its categories (each with the rules that name
    it), its application (with the Cloud App Control rules that name it),
    the custom categories that list it, and what was not read. Pure."""
    import zia_path_modules as zpm
    ix = index(snap)
    cats = snap.get("categories") or {}
    out_entries = []
    for e in parsed["entries"]:
        row: Dict[str, Any] = {"input": e["input"], "kind": e["kind"], "host": e.get("host") or "", "categories": [], "application": None,
                               "application_rules": [], "security_alerts": [], "lookup_error": None, "custom_containing": [], "note": ""}
        ids: List[Tuple[str, str]] = []
        if e["kind"] == "category":
            cid = _resolve_category(e["query"], cats)
            if cid is None:
                row["note"] = f"No category with that id or name is in the tenant's category list: '{_clip(e['query'], 80)}'."
            else:
                ids.append((cid, "the category you typed" if cid in cats or not cats else "the category you typed, not in the tenant's category list"))
        else:
            lk = looked.get(e["host"]) or {}
            if lk.get("error"):
                row["lookup_error"] = _clip(lk["error"], 300)
            for cid in lk.get("categories") or []:
                ids.append((_upper_id(cid), "from ZIA's URL lookup"))
            row["security_alerts"] = [_clip(x, 80) for x in (lk.get("security_alerts") or [])][:20]
            app = lk.get("application")
            if app:
                row["application"] = _clip(app, 120)
                row["application_rules"] = list(ix["by_app"].get(_upper_id(app), []))[:MAX_RULES_PER_CATEGORY]
            where = {"host": e["host"], "path": e.get("path") or "/"}
            for cid, c in cats.items():
                listed = c.get("urls") or []
                kept = c.get("db_urls") or []
                if listed and zpm.url_hit(listed, where, e.get("path") not in ("", "/", None))[0] == "match":
                    ids.append((cid, "listed in the tenant's category"))
                    if c.get("custom"):
                        row["custom_containing"].append({"id": cid, "name": c.get("name") or cid})
                elif kept and zpm.url_hit(kept, where, e.get("path") not in ("", "/", None))[0] == "match":
                    ids.append((cid, "listed in the tenant's category (it keeps its own category too)"))
                    if c.get("custom"):
                        row["custom_containing"].append({"id": cid, "name": c.get("name") or cid})
        seen = {}
        for cid, source in ids:
            if cid in seen:
                if source not in seen[cid]["source"]:
                    seen[cid]["source"] += f"; {source}"
                continue
            ref = _cat_ref(cid, cats, source)
            ref["rules"] = list(ix["by_category"].get(cid, []))[:MAX_RULES_PER_CATEGORY]
            ref["rules_cut"] = len(ix["by_category"].get(cid, [])) > MAX_RULES_PER_CATEGORY
            seen[cid] = ref
        row["categories"] = list(seen.values())
        if e["kind"] == "host" and not row["categories"] and not row["lookup_error"]:
            row["note"] = "ZIA's URL lookup gave no category and no custom category in the tenant lists it."
        out_entries.append(row)
    sections = []
    for k in ORDER:
        sec = (snap.get("sections") or {}).get(k) or {"state": "out_of_scope", "why": "Not in scope."}
        sections.append({"key": k, "label": SECTIONS[k]["label"], "state": sec.get("state"), "why": sec.get("why"),
                         "rules": len(sec.get("rules") or []), "any_count": ix["any_count"].get(k, 0)})
    notes: List[str] = []
    if snap.get("categories_error"):
        notes.append(f"The URL categories could not be read ({snap['categories_error']}): category names are shown as ids and the "
                     "tenant's own category lists are not searched.")
    if snap.get("groups_error"):
        notes.append(f"The IP destination groups could not be read ({snap['groups_error']}): Cloud Firewall and DNS Control rules that "
                     "name a category only through a group are not listed.")
    notes.append(admin_rank.describe(snap.get("admin_ranking")))
    if ix["ranking_state"] not in (admin_rank.ON, admin_rank.OFF):
        notes.append("Admin ranking is not known, so the rules are listed in rule order.")
    notes.append("Cloud App Control rules name applications, not URL categories: they are listed for the application ZIA's lookup names.")
    return {"entries": out_entries, "skipped": parsed.get("skipped") or [], "sections": sections, "notes": notes,
            "ranked": ix["ranked"], "lookup": lookup_state or {}, "read_at": snap.get("read_at"),
            "scope_summary": _summary(sections, bool(cats) or bool(snap.get("categories_error")))}


def _summary(sections: List[Dict[str, Any]], categories: bool) -> str:
    """What this lookup read, in words (the Path analyzer's own summary names parts it does not read)."""
    read = [s["label"] for s in sections if s["state"] in ("read", "unread")]
    if not read:
        return "Nothing was read."
    names = read[0] if len(read) == 1 else ", ".join(read[:-1]) + " and " + read[-1]
    return ("Reads only what is in scope on the Scope page: the " + names + " rules"
            + (", the URL categories" if categories else "") + " and ZIA's URL lookup.")


def run(client: Any, parsed: Dict[str, Any], scope: Dict[str, Any], *, snapshot: Optional[Dict[str, Any]] = None, cancel: Any = None,
        log: LogFn = None) -> Dict[str, Any]:
    """Read (or take the kept read for the same scope), look the hosts up,
    answer. Returns the answer with `snapshot_for_cache` (a fresh read)."""
    say = log or (lambda m: None)
    fresh = None
    if snapshot is None or snapshot.get("scope_key") != scope.get("key"):
        snapshot = fresh = read(client, scope, cancel=cancel, log=say)
    else:
        say("Using the tenant configuration read a moment ago for the same scope.")
    hosts = [e["host"] for e in parsed["entries"] if e["kind"] == "host"]
    looked, state = ({}, {"destinations": len(hosts), "requests": 0})
    if hosts:
        say(f"Asking ZIA's URL lookup about {len(hosts)} destination(s)…")
        looked, state = lookups(client, hosts, cancel=cancel, log=say)
    res = answer(snapshot, parsed, looked, state, scope)
    res["snapshot_for_cache"] = fresh
    return res
