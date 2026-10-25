"""Console index: what Zscaler Made Easy knows about each object an admin sees in
the Zscaler admin console, for the companion browser extension's badges
and side panel.

DLP (from the same read-only inventory the rule picker uses,
pack_removal.inventory): every DLP rule on the channels in scope, every
custom engine and every dictionary, with what it uses, what uses it, the
policy pack that created it and short findings (unused, disabled,
monitor-only, no engines, shadowed).

ZIA (from the shadowed-rule analysis' own read, shadow_rules.read_policies,
plus the File Type Control rules data_flow reads; only what the Scope page
puts in scope): the URL filtering, Cloud App Control, SSL inspection,
Cloud Firewall and File Type Control rules (order, state, action, what
they reference, shadowed-rule findings), the URL categories (custom ones,
and predefined ones a rule references) and the objects the rules reference
by name: locations and location groups, departments, groups, rule labels,
network services and applications (and their groups), IP groups and file
types (File Type Control and Web DLP rules), each with how many rules use
it, per policy. Each custom engine carries its expression as the tenant
has it, the same with dictionary names and a one-sentence summary
(engine_explain).

Pure apart from build(): the tests feed it an inventory and raw rules.

The extension matches object names it sees on a console page against this
index locally; the page's content never leaves the browser. The index
holds configuration metadata only (names, counts, states): never a secret,
a user name (rules' users, excluded users and devices are never read into
it), a file name, a description or who last changed a rule. Each kind is
capped (MAX_PER_KIND, the rest counted in `more`) so the index stays small
enough for the browser's session storage.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pack_channels as pc
from engine_explain import file_type_label

MONITOR_ACTIONS = {"ALLOW", "OFLCASB_DLP_REPORT_INCIDENT", "REPORT", "MONITOR"}


def _finding(severity: str, text: str, short: str = "") -> Dict[str, str]:
    """A finding: its severity, one plain sentence, and the few words a
    console badge shows for it."""
    return {"severity": severity, "text": text, "short": short}


def _names(items: Iterable[Any], limit: int = 25) -> List[str]:
    out = sorted({str(x) for x in items if x not in (None, "")}, key=str.lower)
    return out[:limit]


def from_inventory(inv: Dict[str, Any], *, tenant_label: str = "", shadow: Optional[Dict[Any, List[Dict[str, Any]]]] = None,
                   zia: Optional[Dict[str, Any]] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """The index from an inventory (pack_removal.inventory's answer).
    `shadow` maps (channel, rule name) to shadowed-rule findings on the DLP
    rules. `zia` (zia_read's shape: raw rules per policy, the URL
    categories, the shadowed-rule findings, what was not read) adds the
    ZIA policies and the objects their rules reference."""
    zia_objects, dlp_refs, zia_note = _zia(zia)
    rules = [r for r in (inv.get("rules") or []) if r.get("name")]
    engines = [e for e in (inv.get("engines") or []) if e.get("name")]
    dicts = {str(n): d for n, d in (inv.get("dictionaries") or {}).items()}

    rules_by_engine: Dict[str, List[Dict[str, Any]]] = {}
    for r in rules:
        for e in r.get("engines") or []:
            rules_by_engine.setdefault(str(e), []).append(r)
    engines_by_dict: Dict[str, List[str]] = {}
    for e in engines:
        for d in e.get("dictionaries") or []:
            engines_by_dict.setdefault(str(d), []).append(e["name"])

    objects: List[Dict[str, Any]] = []
    for name, d in sorted(dicts.items(), key=lambda kv: kv[0].lower()):
        users = engines_by_dict.get(name, [])
        via_rules = {r["name"] for e in users for r in rules_by_engine.get(e, [])}
        f = []
        if d.get("custom") and not users:
            f.append(_finding("low", "No custom engine uses this dictionary, so it detects nothing on its own.", "unused"))
        objects.append({"kind": "dictionary", "name": name, "id": d.get("id"), "custom": bool(d.get("custom")),
                        "type": d.get("type") or "", "used_by": {"engines": _names(users), "rules": _names(via_rules)},
                        "counts": {"engines": len(set(users)), "rules": len(via_rules)}, "pack": None, "findings": f})
    for e in sorted(engines, key=lambda x: str(x["name"]).lower()):
        users = rules_by_engine.get(e["name"], [])
        f = []
        if not users:
            f.append(_finding("low", "No DLP rule uses this engine, so it never acts.", "unused"))
        objects.append({"kind": "engine", "name": e["name"], "id": e.get("id"), "custom": True,
                        # The expression as the tenant has it (for copying), with
                        # dictionary names, and in one sentence (engine_explain).
                        "expression": str(e.get("expression") or "")[:MAX_EXPRESSION],
                        "readable": str(e.get("readable") or "")[:MAX_EXPRESSION], "summary": str(e.get("summary") or "")[:MAX_EXPRESSION],
                        "uses": {"dictionaries": _names(e.get("dictionaries") or [])},
                        "used_by": {"rules": _names(r["name"] for r in users)},
                        "counts": {"rules": len({r["name"] for r in users}), "dictionaries": len(set(e.get("dictionaries") or []))},
                        "pack": None, "findings": f})
    for r in rules:
        ch = r.get("channel") or ""
        state = str(r.get("state") or "").upper()
        action = str(r.get("action") or "").upper()
        f = []
        if state == "DISABLED":
            f.append(_finding("info", "Disabled: this rule does not inspect anything until it is enabled.", "disabled"))
        elif action in MONITOR_ACTIONS:
            f.append(_finding("medium", "Monitor only: matches are logged but the data still leaves.", "monitor only"))
        if pc.has_engines(ch) and not (r.get("engines") or []):
            f.append(_finding("medium", "No DLP engine: the rule has nothing to match content with.", "no engine"))
        for s in (shadow or {}).get((ch, r["name"]), []) + (shadow or {}).get(("dlp", r["name"]), []):
            f.append(_shadow_finding(s))
        uses: Dict[str, List[str]] = {"engines": _names(r.get("engines") or [])}
        ucounts: Dict[str, int] = {"engines": len(set(r.get("engines") or []))}
        for kind, refs in (dlp_refs.get((ch, r["name"])) or {}).items():
            uses[kind], ucounts[kind] = _names(refs), len(set(refs))
        objects.append({"kind": "rule", "key": f"rule:{ch}:{r['name']}", "name": r["name"], "id": r.get("id"), "channel": ch,
                        "channel_label": pc.label(ch) if ch else "", "policy": _CHANNEL_POLICY.get(ch, ""),
                        "state": state, "action": action, "parent_id": r.get("parent_id"),
                        "uses": uses, "counts": ucounts, "pack": r.get("pack"), "findings": f})
    for o in objects:
        o.setdefault("key", f"{o['kind']}:{o['name']}")
    objects += zia_objects
    more: Dict[str, int] = {}
    objects = _cap(objects, more)
    counts = {k: sum(1 for o in objects if o["kind"] == k) for k in ("dictionary", "engine", "rule")}
    counts.update({k: sum(1 for o in objects if o["kind"] == k) for k in KINDS if k not in counts})
    counts["findings"] = sum(len(o["findings"]) for o in objects)
    return {"version": 2, "tenant_label": tenant_label, "read_at": int(now if now is not None else time.time()),
            "channels": sorted({r.get("channel") for r in rules if r.get("channel")}),
            "errors": inv.get("errors") or {}, "counts": counts, "more": more, "objects": objects,
            "kinds": [dict(v, kind=k) for k, v in KINDS.items()], "policy_labels": dict(POLICY_LABELS),
            "policy_kinds": dict(POLICY_KIND), "zia": zia_note}


def build(client, channels: Optional[Iterable[str]] = None, *, tenant_label: str = "",
          shadow: Optional[Dict[Any, List[Dict[str, Any]]]] = None, zia: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read the tenant (read-only, the in-scope channels only) and index it,
    with the shadowed-rule findings (shadow_by_channel) and the ZIA read
    (zia_read) when given. No DLP channel in scope (`channels` an empty
    list): no DLP object is read, only the ZIA part is indexed."""
    import pack_removal
    if channels is not None and not list(channels):
        inv: Dict[str, Any] = {"status": "ready", "rules": [], "engines": [], "dictionaries": {}}
    else:
        inv = pack_removal.inventory(client, list(channels) if channels is not None else None)
    if inv.get("status") != "ready":
        return {"status": "blocked", "blockers": inv.get("blockers") or ["Could not read the tenant."], "errors": inv.get("errors") or {}}
    out = from_inventory(inv, tenant_label=tenant_label, shadow=shadow, zia=zia)
    out["status"] = "ready"
    return out


# ---------------------------------------------------------------------------
# ZIA: the policies beyond DLP and the objects their rules reference
# ---------------------------------------------------------------------------

# Every kind the index holds: its label (sentence case), the plural, the
# group the side panel files it under, and whether Export from tenant can
# export it (DLP only).
KINDS: Dict[str, Dict[str, Any]] = {
    "dictionary": {"label": "DLP dictionary", "plural": "DLP dictionaries", "group": "DLP", "export": True},
    "engine": {"label": "DLP engine", "plural": "DLP engines", "group": "DLP", "export": True},
    "rule": {"label": "DLP rule", "plural": "DLP rules", "group": "DLP", "export": True},
    "url_rule": {"label": "URL filtering rule", "plural": "URL filtering rules", "group": "Policies"},
    "cac_rule": {"label": "Cloud App Control rule", "plural": "Cloud App Control rules", "group": "Policies"},
    "ssl_rule": {"label": "SSL inspection rule", "plural": "SSL inspection rules", "group": "Policies"},
    "firewall_rule": {"label": "Cloud Firewall rule", "plural": "Cloud Firewall rules", "group": "Policies"},
    "ftc_rule": {"label": "File Type Control rule", "plural": "File Type Control rules", "group": "Policies"},
    "url_category": {"label": "URL category", "plural": "URL categories", "group": "Objects"},
    "location": {"label": "Location", "plural": "Locations", "group": "Objects"},
    "location_group": {"label": "Location group", "plural": "Location groups", "group": "Objects"},
    "department": {"label": "Department", "plural": "Departments", "group": "Objects"},
    "group": {"label": "Group", "plural": "Groups", "group": "Objects"},
    "label": {"label": "Rule label", "plural": "Rule labels", "group": "Objects"},
    "network_service": {"label": "Network service", "plural": "Network services", "group": "Objects"},
    "network_service_group": {"label": "Network service group", "plural": "Network service groups", "group": "Objects"},
    "network_application": {"label": "Network application", "plural": "Network applications", "group": "Objects"},
    "network_application_group": {"label": "Network application group", "plural": "Network application groups", "group": "Objects"},
    "source_ip_group": {"label": "Source IP group", "plural": "Source IP groups", "group": "Objects"},
    "destination_ip_group": {"label": "Destination IP group", "plural": "Destination IP groups", "group": "Objects"},
    "file_type": {"label": "File type", "plural": "File types", "group": "Objects"},
}
for _k in KINDS.values():
    _k.setdefault("export", False)

# The policies (shadow_rules.POLICIES keys, plus File Type Control, which
# the shadowed-rule analysis does not cover) and the kind of their rules.
FTC = "file_type_control"
FTC_ENDPOINT = "/zia/fileTypeRules"
POLICY_LABELS: Dict[str, str] = {
    "web_dlp": "Inline Web DLP", "endpoint_dlp": "Endpoint DLP", "email_dlp": "Outbound Email DLP", "saas_dlp": "SaaS Security API DLP",
    "url_filtering": "URL filtering", "cloud_app_control": "Cloud App Control", "ssl_inspection": "SSL inspection",
    "firewall": "Cloud Firewall", FTC: "File Type Control"}
POLICY_KIND: Dict[str, str] = {"web_dlp": "rule", "endpoint_dlp": "rule", "email_dlp": "rule", "saas_dlp": "rule",
                               "url_filtering": "url_rule", "cloud_app_control": "cac_rule", "ssl_inspection": "ssl_rule",
                               "firewall": "firewall_rule", FTC: "ftc_rule"}
# The policies whose rules name URL categories (the SDK models urlCategories
# on URL filtering, SSL inspection, File Type Control and Web DLP rules,
# and destIpCategories on Cloud Firewall rules).
CATEGORY_POLICIES = ("url_filtering", "ssl_inspection", "firewall", FTC, "web_dlp")

# A rule's reference fields (canonical: lower case, no separators) and the
# kind they name. Users, excluded users, override users and devices are
# deliberately absent: the index never holds a person's name.
REF_FIELDS: Dict[str, str] = {
    "urlcategories": "url_category", "destipcategories": "url_category",
    "locations": "location", "locationgroups": "location_group",
    "departments": "department", "excludeddepartments": "department",
    "groups": "group", "excludedgroups": "group",
    "labels": "label",
    "nwservices": "network_service", "nwservicegroups": "network_service_group",
    "nwapplications": "network_application", "nwapplicationgroups": "network_application_group",
    "srcipgroups": "source_ip_group", "sourceipgroups": "source_ip_group", "destipgroups": "destination_ip_group",
    "filetypes": "file_type",
}
# References by id only (no name in the rule): resolved, or named after the id.
_ID_KINDS = {"url_category", "network_application", "file_type"}

MAX_PER_KIND = 300
MAX_NAMES = 25
MAX_EXPRESSION = 600   # an engine's expression, readable form and summary, each

_SHORT = {"shadowed": "shadowed", "after_catch_all": "shadowed", "duplicate": "duplicate", "superseded": "superseded",
          "missing_reference": "missing reference", "disabled": "disabled"}
_SMALL_WORDS = {"and", "or", "of", "the", "for", "in", "to", "a", "an", "on", "with", "by", "at"}
_ANY = {"ANY", "ALL", "ANY_RULE", "NONE"}


def _canon(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _shadow_finding(s: Dict[str, Any]) -> Dict[str, str]:
    return _finding(str(s.get("severity") or "high"), str(s.get("reason") or "Shadowed by an earlier rule."),
                    _SHORT.get(str(s.get("kind") or ""), "shadowed"))


def category_label(cid: Any) -> str:
    """A predefined URL category's name from its id (OTHER_ADULT_MATERIAL
    -> Other Adult Material). The API gives predefined categories no
    display name; this is the console's usual spelling, not a promise."""
    words = str(cid or "").replace("_", " ").lower().split()
    return " ".join(w if (i and w in _SMALL_WORDS) else w.capitalize() for i, w in enumerate(words))


def _category_catalogue(categories: Optional[Iterable[Any]]) -> Dict[str, Dict[str, Any]]:
    """{id: {id, name, custom, derived}} from /zia/urlCategories items.
    Only these four fields are kept: never a category's URLs or keywords."""
    out: Dict[str, Dict[str, Any]] = {}
    for c in categories or []:
        if not isinstance(c, dict) or c.get("id") in (None, ""):
            continue
        cid = str(c["id"])
        given = c.get("configuredName") or c.get("configured_name") or c.get("name")
        custom = bool(c.get("customCategory") or c.get("custom_category") or c.get("custom"))
        out[cid] = {"id": cid, "name": str(given) if given else category_label(cid), "custom": custom, "derived": not given}
    return out


def _ref_names(raw: Dict[str, Any], cats: Dict[str, Dict[str, Any]]) -> Dict[str, List[Tuple[str, Optional[str]]]]:
    """{kind: [(name, id)]} a raw rule references (REF_FIELDS only)."""
    out: Dict[str, List[Tuple[str, Optional[str]]]] = {}
    for k, v in (raw or {}).items():
        kind = REF_FIELDS.get(_canon(k))
        if not kind or v in (None, "", [], {}):
            continue
        for x in v if isinstance(v, (list, tuple)) else [v]:
            if isinstance(x, dict):
                rid = x.get("id")
                name = x.get("name") or x.get("configuredName") or x.get("configured_name")
            else:
                rid, name = x, None
            rid = None if rid in (None, "") else str(rid)
            if kind == "url_category":
                if rid is None and name:
                    rid = next((cid for cid, c in cats.items() if c["name"] == name), str(name))
                if rid is None or rid.upper() in _ANY:
                    continue
                name = (cats.get(rid) or {}).get("name") or name or category_label(rid)
            elif kind == "file_type":
                if rid is None or rid.upper() in _ANY:
                    continue
                name = file_type_label(name or rid)[0]
            elif kind in _ID_KINDS:
                name = name or rid
            if not name or str(name).upper() in _ANY:
                continue
            out.setdefault(kind, []).append((str(name), rid))
    return out


def _rule_shape(policy: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Order, state and action of a raw rule, through the normalisers the
    shadowed-rule analysis and the Path analyzer use."""
    if policy == FTC:
        from data_flow import _norm_generic
        n = _norm_generic(raw)
        return {"name": n["name"], "order": n.get("order"), "state": n["state"], "action": n["action"], "actions": [], "type": ""}
    import shadow_rules
    n = shadow_rules.normalize(policy, raw)
    return {"name": n["name"], "order": n.get("order"), "state": n["state"], "action": n.get("action") or "",
            "actions": list(n.get("actions") or []), "type": n.get("type") or ""}


def _zia(zia: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[Any, Dict[str, List[str]]], Dict[str, Any]]:
    """(objects, {(DLP channel, rule name): {kind: [names]}}, a note on what
    was read) from a ZIA read (zia_read's shape)."""
    if not zia:
        return [], {}, {"read": [], "not_in_scope": {}, "read_errors": {}, "categories_read": False}
    rules_by_policy: Dict[str, List[Dict[str, Any]]] = {k: v for k, v in (zia.get("rules") or {}).items()
                                                        if k in POLICY_KIND and isinstance(v, list)}
    cats_read = zia.get("categories") is not None
    cats = _category_catalogue(zia.get("categories"))
    shadow: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for f in zia.get("findings") or []:
        if isinstance(f, dict) and f.get("policy") in POLICY_KIND and f.get("rule") is not None and f.get("kind") != "disabled":
            shadow.setdefault((str(f["policy"]), str(f["rule"])), []).append(f)

    objects: List[Dict[str, Any]] = []
    dlp_refs: Dict[Any, Dict[str, List[str]]] = {}
    # kind -> name -> {"id", "by": {policy: set(rule names)}}
    used: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for policy, raws in rules_by_policy.items():
        kind = POLICY_KIND[policy]
        for raw in raws:
            if not isinstance(raw, dict):
                continue
            shape = _rule_shape(policy, raw)
            name = str(shape["name"] or "")
            if not name:
                continue
            refs = _ref_names(raw, cats)
            for rkind, items in refs.items():
                for rname, rid in items:
                    slot = used.setdefault(rkind, {}).setdefault(rname, {"id": rid, "by": {}})
                    slot["by"].setdefault(policy, set()).add(name)
            names = {rk: [n for n, _ in items] for rk, items in refs.items()}
            if kind == "rule":
                ch = _SHADOW_CHANNEL.get(policy, "")
                dlp_refs[(ch, name)] = names
                continue
            state = str(shape["state"] or "").upper()
            f: List[Dict[str, str]] = []
            if state == "DISABLED":
                f.append(_finding("info", "Disabled: this rule does not match anything until it is enabled.", "disabled"))
            f += [_shadow_finding(s) for s in shadow.get((policy, name), [])]
            key = f"{kind}:{shape['type']}:{name}" if kind == "cac_rule" else f"{kind}:{name}"
            objects.append({"kind": kind, "key": key, "name": name, "id": raw.get("id"), "policy": policy,
                            "policy_label": POLICY_LABELS[policy], "order": shape["order"], "state": state,
                            "action": str(shape["action"] or "").upper(), "actions": shape["actions"][:12],
                            "type": shape["type"], "uses": {rk: _names(v, MAX_NAMES) for rk, v in names.items()},
                            "counts": {rk: len(set(v)) for rk, v in names.items()}, "pack": None, "findings": f})

    # Custom URL categories are indexed whether or not a rule uses them.
    for cid, c in cats.items():
        if c["custom"]:
            used.setdefault("url_category", {}).setdefault(c["name"], {"id": cid, "by": {}})
    read = set(rules_by_policy)
    checked = [POLICY_LABELS[p] for p in CATEGORY_POLICIES if p in read]
    unread = [POLICY_LABELS[p] for p in CATEGORY_POLICIES if p not in read]
    for rkind, by_name in used.items():
        for name, slot in by_name.items():
            by = {p: sorted(n, key=str.lower) for p, n in slot["by"].items()}
            total = sum(len(v) for v in by.values())
            o: Dict[str, Any] = {"kind": rkind, "key": f"{rkind}:{name}", "name": name, "id": slot["id"],
                                 "used_by": {p: v[:MAX_NAMES] for p, v in by.items()},
                                 "counts": {"rules": total, "by_policy": {p: len(v) for p, v in by.items()}}, "pack": None, "findings": []}
            if rkind == "file_type":
                o["category"] = file_type_label(slot["id"])[1]
            if rkind == "url_category":
                c = cats.get(str(slot["id"])) or {}
                o["custom"] = bool(c.get("custom"))
                o["name_derived"] = bool(c.get("derived", slot["id"] is not None and not c))
                if o["custom"] and not total and checked:
                    rest = f" ({', '.join(unread)} not read: out of scope or unreadable)" if unread else ""
                    o["findings"].append(_finding(
                        "low", f"No {', '.join(checked)} rule uses this custom category{rest}; other policies, such as Bandwidth "
                               "Control or Sandbox, were not checked.", "unused"))
            objects.append(o)
    note = {"read": sorted(read, key=list(POLICY_LABELS).index), "not_in_scope": dict(zia.get("not_in_scope") or {}),
            "read_errors": dict(zia.get("read_errors") or {}), "categories_read": cats_read}
    return objects, dlp_refs, note


def _cap(objects: List[Dict[str, Any]], more: Dict[str, int]) -> List[Dict[str, Any]]:
    """At most MAX_PER_KIND objects of each kind: the ones with findings
    and the most used first; the rest counted in `more` (kind -> N)."""
    by_kind: Dict[str, List[Dict[str, Any]]] = {}
    for o in objects:
        by_kind.setdefault(o["kind"], []).append(o)
    keep = set()
    for kind, objs in by_kind.items():
        if len(objs) <= MAX_PER_KIND:
            keep.update(id(o) for o in objs)
            continue
        ranked = sorted(objs, key=lambda o: (not o["findings"], -int((o.get("counts") or {}).get("rules") or 0), str(o["name"]).lower()))
        keep.update(id(o) for o in ranked[:MAX_PER_KIND])
        more[kind] = len(objs) - MAX_PER_KIND
    return [o for o in objects if id(o) in keep]


def zia_read(client, scope: Dict[str, Any], *, ftc: bool = False, log=None, cancel: Any = None) -> Dict[str, Any]:
    """The ZIA part of the index, read-only and only what is in scope:
    shadow_rules.read_policies (the rules of every policy type `scope`
    puts in scope, the DLP engines and the URL categories), its analysis,
    and the File Type Control rules when `ftc` (data_flow.path_scope puts
    them in scope). {rules: {policy: [raw]}, categories, findings,
    read_errors, not_in_scope}."""
    import shadow_rules
    from ssl_flow import _fetch_rules
    got = shadow_rules.read_policies(client, scope, log=log, cancel=cancel)
    mode = (got.get("mode") or {}).get("web_dlp") or shadow_rules.MODE_UNKNOWN
    res = shadow_rules.analyse(got["rules"], web_dlp_mode=mode, engines=got.get("engines"), categories=got.get("categories"))
    rules = dict(got["rules"])
    errors = dict(got.get("read_errors") or {})
    nis = dict(got.get("not_in_scope") or {})
    if ftc:
        diags: List[Dict[str, Any]] = []
        items = _fetch_rules(client, FTC_ENDPOINT, diags, "File Type Control rules")
        if diags:
            errors[FTC] = " ".join(str(x) for x in (diags[-1].get("error_type"), diags[-1].get("error")) if x).strip()[:200] or "the read failed"
        else:
            rules[FTC] = items
    else:
        nis[FTC] = "Not in scope on the Scope page, so the File Type Control rules were not read."
    return {"rules": rules, "categories": got.get("categories"), "findings": res["findings"], "read_errors": errors, "not_in_scope": nis}


# shadow_rules names DLP policies by policy type; the index by channel.
_SHADOW_CHANNEL = {"web_dlp": "web", "endpoint_dlp": "endpoint", "email_dlp": "email", "saas_dlp": "saas"}
_CHANNEL_POLICY = {v: k for k, v in _SHADOW_CHANNEL.items()}


def shadow_by_channel(findings: Iterable[Dict[str, Any]]) -> Dict[Any, List[Dict[str, Any]]]:
    """Shadowed-rule findings (shadow_rules) keyed (channel, rule name) for
    the DLP rules the index holds. Disabled rules are left out: the index
    already says so itself."""
    out: Dict[Any, List[Dict[str, Any]]] = {}
    for f in findings or []:
        ch = _SHADOW_CHANNEL.get(str(f.get("policy") or ""))
        if ch and f.get("rule") is not None and f.get("kind") != "disabled":
            out.setdefault((ch, str(f["rule"])), []).append(f)
    return out


# ---------------------------------------------------------------------------
# A small per-profile cache, so the side panel does not read the tenant on
# every page the admin opens. Kept in memory only.
# ---------------------------------------------------------------------------

CACHE_SECONDS = 30 * 60
_CACHE: Dict[str, Dict[str, Any]] = {}


def cache_key(profile_id: str, channels: Iterable[str]) -> str:
    return f"{profile_id or 'server'}|{','.join(sorted(channels or []))}"


def cache_put(key: str, index: Dict[str, Any]) -> None:
    _CACHE[key] = {"at": time.time(), "index": index}
    for k in sorted(_CACHE, key=lambda k: _CACHE[k]["at"])[:-16]:   # bounded
        _CACHE.pop(k, None)


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    hit = _CACHE.get(key)
    if not hit or time.time() - hit["at"] > CACHE_SECONDS:
        return None
    return dict(hit["index"], cached_at=int(hit["at"]))


def cache_latest(profile_id: str) -> Optional[Dict[str, Any]]:
    """The newest index still kept for a profile (any scope it was read
    with), or None. Reads nothing."""
    prefix = f"{profile_id or 'server'}|"
    keys = [k for k in _CACHE if k.startswith(prefix) and time.time() - _CACHE[k]["at"] <= CACHE_SECONDS]
    return cache_get(max(keys, key=lambda k: _CACHE[k]["at"])) if keys else None


def cache_clear() -> None:
    _CACHE.clear()
