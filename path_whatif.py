"""What-if for the Path analyzer: the same destination for one user,
group, department and location, and the conditions a policy action
depends on.

ZIA rules can be scoped to users, groups, departments, locations,
location groups, time windows, device trust levels and more. The Path
analyzer's trace treats every such rule as "conditional": it cannot know
who is browsing. This module adds two things on top of the trace:

* `apply_identity` evaluates each scoped rule against the identity the
  operator typed (or picked from ZIA): a rule whose scope includes it
  applies to everyone in the trace, a rule whose scope excludes it is
  skipped, and a rule that still depends on something not given (a time
  window, a device trust level, a location group) stays conditional.
  Within a rule, users, groups and departments are alternatives (any one
  is enough), as are locations and location groups; the kinds of
  criteria must all hold. The groups given are taken as the user's only
  groups.
* `depends_on` lists, for the destination, each scoped rule that would
  change the action of a policy section (Cloud App Control, URL
  filtering, SSL inspection, File Type Control, Web DLP), with the
  condition, the action it would give and the action everyone else gets.

`search_identities` looks a user, group, department or location up in ZIA
by name: one page of at most SEARCH_LIMIT answers, never a bulk listing.
The caller checks the Scope page first.

Pure except for `search_identities`; nothing here writes to a tenant.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# (key, label, raw field names): every scope field the trace counts
# (ssl_flow.SCOPE_FIELDS), named.
DIMENSIONS: List[Tuple[str, str, Tuple[str, ...]]] = [
    ("users", "user", ("users",)),
    ("groups", "group", ("groups",)),
    ("departments", "department", ("departments",)),
    ("locations", "location", ("locations",)),
    ("location_groups", "location group", ("location_groups", "locationGroups")),
    ("time_windows", "time window", ("time_windows", "timeWindows")),
    ("device_trust", "device trust level", ("device_trust_levels", "deviceTrustLevels")),
    ("devices", "device", ("devices",)),
    ("device_groups", "device group", ("device_groups", "deviceGroups")),
    ("platforms", "platform", ("platforms",)),
    ("user_agents", "user agent", ("user_agent_types", "userAgentTypes")),
    ("source_ip_groups", "source IP group", ("source_ip_groups", "sourceIpGroups", "srcIpGroups")),
    ("workload_groups", "workload group", ("workload_groups", "workloadGroups")),
    ("zpa_app_segments", "ZPA app segment", ("zpa_app_segments", "zpaAppSegments")),
    ("user_risk", "user risk score level", ("user_risk_score_levels", "userRiskScoreLevels")),
    # Web DLP exclusions: the rule does not apply to these (negated).
    ("excluded_users", "excluded user", ("excluded_users", "excludedUsers")),
    ("excluded_groups", "excluded group", ("excluded_groups", "excludedGroups")),
    ("excluded_departments", "excluded department", ("excluded_departments", "excludedDepartments")),
    # A URL filtering rule's validity period (enforceTimeValidity): never given.
    ("validity", "validity period", ()),
]
LABEL = {k: label for k, label, _ in DIMENSIONS}
WHO = ("users", "groups", "departments")
WHERE = ("locations", "location_groups")
EXCLUDED = {"excluded_users": "users", "excluded_groups": "groups", "excluded_departments": "departments"}
MAX_ITEMS = 100
MAX_NAME = 200
MAX_GROUPS = 20
MAX_ENTRIES = 50
SEARCH_LIMIT = 20
SEARCH_KINDS = ("user", "group", "department", "location")
_QUERY = re.compile(r"^[^\x00-\x1f\x7f]{2,64}$")


def _clip(v: Any) -> str:
    return str(v)[:MAX_NAME] if v is not None else ""


def scope_items(r: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """A raw rule's scope, named: {dimension: [{id, name}]}. Empty means
    the rule is not scoped. Bounded: MAX_ITEMS per dimension."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not isinstance(r, dict):
        return out
    for key, _label, fields in DIMENSIONS:
        items: List[Dict[str, Any]] = []
        for f in fields:
            v = r.get(f)
            if isinstance(v, list):
                for x in v[:MAX_ITEMS]:
                    if isinstance(x, dict):
                        items.append({"id": x.get("id"), "name": _clip(x.get("name") or x.get("id") or "")})
                    elif x is not None:
                        items.append({"id": None, "name": _clip(x)})
        if items:
            out[key] = items[:MAX_ITEMS]
    import zia_path_modules
    window = zia_path_modules.validity(r)
    if window:
        out["validity"] = [{"id": None, "name": _clip(window)}]
    return out


# ── The identity ───────────────────────────────────────────────────────
def _ref(v: Any) -> Optional[Dict[str, Any]]:
    if isinstance(v, dict):
        name = _clip(v.get("name") or "").strip()
        rid = v.get("id")
        rid = rid if isinstance(rid, (int, str)) and str(rid).strip() and len(str(rid)) <= 40 else None
        out = {"id": rid, "name": name}
        if v.get("email"):
            out["email"] = _clip(v.get("email")).strip()
        return out if name or rid is not None else None
    if isinstance(v, str) and v.strip():
        return {"id": None, "name": _clip(v.strip())}
    return None


def normalize_identity(raw: Any) -> Optional[Dict[str, Any]]:
    """What the page sent → {user, groups, department, location} (each a
    {id, name}; groups a list), or None when nothing was given. A group
    field may hold several names separated by commas. Bounded."""
    if not isinstance(raw, dict):
        return None
    groups_raw = raw.get("groups") if isinstance(raw.get("groups"), list) else raw.get("group")
    groups: List[Dict[str, Any]] = []
    if isinstance(groups_raw, str):
        groups_raw = [g for g in groups_raw.split(",")]
    for g in (groups_raw if isinstance(groups_raw, list) else [groups_raw])[:MAX_GROUPS]:
        r = _ref(g)
        if r:
            groups.append(r)
    ident = {"user": _ref(raw.get("user")), "groups": groups, "department": _ref(raw.get("department")),
             "location": _ref(raw.get("location"))}
    if not any((ident["user"], ident["groups"], ident["department"], ident["location"])):
        return None
    return ident


def describe(ident: Optional[Dict[str, Any]]) -> str:
    if not ident:
        return ""
    parts = []
    if ident.get("user"):
        parts.append(f"user {ident['user']['name']}")
    if ident.get("groups"):
        parts.append("group " + ", ".join(g["name"] for g in ident["groups"]))
    if ident.get("department"):
        parts.append(f"department {ident['department']['name']}")
    if ident.get("location"):
        parts.append(f"location {ident['location']['name']}")
    return "; ".join(parts)


def _same(item: Dict[str, Any], val: Dict[str, Any], user: bool = False) -> bool:
    if item.get("id") is not None and val.get("id") is not None and str(item["id"]) == str(val["id"]):
        return True
    a, b = (item.get("name") or "").casefold().strip(), (val.get("name") or "").casefold().strip()
    if a and a == b:
        return True
    if user:
        email = (val.get("email") or (b if "@" in b else "")).casefold()
        # ZIA names a user in a rule by display name, sometimes with the login in parentheses.
        if email and (a == email or f"({email})" in a.replace(" ", "")):
            return True
    return False


def _values(ident: Dict[str, Any], dim: str) -> Optional[List[Dict[str, Any]]]:
    if dim == "users":
        return [ident["user"]] if ident.get("user") else None
    if dim == "groups":
        return list(ident["groups"]) if ident.get("groups") else None
    if dim == "departments":
        return [ident["department"]] if ident.get("department") else None
    if dim == "locations":
        return [ident["location"]] if ident.get("location") else None
    return None   # location groups, time windows, device trust, ...: never given


def rule_criteria(rule: Dict[str, Any], ident: Optional[Dict[str, Any]]) -> Tuple[Optional[bool], List[Dict[str, Any]]]:
    """(applies, criteria) for a scoped rule and the identity: applies is
    True, False or None (still depends on something not given);
    criteria [{dim, name, values, state: match|nomatch|unknown}], one per
    kind of criterion the rule has."""
    items = rule.get("scope_items") or {}
    if not items:
        if rule.get("scope") or rule.get("scoped"):
            return None, [{"dim": "identity", "name": "identity: " + ", ".join(rule.get("scope") or []), "values": [], "state": "unknown"}]
        return True, []
    crit: List[Dict[str, Any]] = []
    for key, label, _ in DIMENSIONS:
        if key not in items:
            continue
        names = [i["name"] for i in items[key] if i.get("name")]
        vals = _values(ident or {}, EXCLUDED.get(key, key))
        if vals is None:
            state = "unknown"
        else:
            hit = any(_same(i, v, EXCLUDED.get(key, key) == "users") for i in items[key] for v in vals)
            # An exclusion is met when the identity is NOT in it.
            state = ("nomatch" if hit else "match") if key in EXCLUDED else ("match" if hit else "nomatch")
        crit.append({"dim": key, "name": f"{label}: " + ", ".join(names[:5]) + (f" (+{len(names) - 5})" if len(names) > 5 else ""),
                     "values": names[:MAX_ITEMS], "state": state})

    def any_of(keys) -> Optional[bool]:
        sts = [c["state"] for c in crit if c["dim"] in keys]
        if not sts:
            return True
        if "match" in sts:
            return True
        return None if "unknown" in sts else False

    one = {"match": True, "nomatch": False}
    parts = [any_of(WHO), any_of(WHERE)] + [one.get(c["state"]) for c in crit if c["dim"] not in WHO + WHERE]
    if False in parts:
        return False, crit
    if None in parts:
        return None, crit
    return True, crit


SECTIONS = ("cac", "url", "ssl", "ftc", "dlp")
SECTION_LABEL = {"cac": "Cloud App Control", "url": "URL filtering", "ssl": "SSL inspection", "ftc": "File Type Control", "dlp": "Inline Web DLP"}


def apply_identity(zia: Dict[str, Any], ident: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """A copy of the ZIA read with each scoped rule evaluated for `ident`:
    included → unscoped (it applies, like a rule for everyone), excluded →
    not enabled for this trace (its state is untouched, so the policy pack
    overlay still finds it), undecided → left scoped. Returns (zia, counts
    {applies, skipped, open})."""
    counts = {"applies": 0, "skipped": 0, "open": 0}
    out = dict(zia)
    if not ident:
        return out, counts
    for sec in SECTIONS:
        rows = []
        for r in zia.get(sec) or []:
            if not isinstance(r, dict) or not (r.get("scope") or r.get("scoped")):
                rows.append(r)
                continue
            state, crit = rule_criteria(r, ident)
            if state is True:
                counts["applies"] += 1
                rows.append(dict(r, scope=[], scoped=False, whatif="applies", whatif_criteria=crit))
            elif state is False:
                counts["skipped"] += 1
                rows.append(dict(r, enabled=False, whatif="skipped", whatif_criteria=crit))
            else:
                counts["open"] += 1
                rows.append(dict(r, whatif="open", whatif_criteria=crit))
        out[sec] = rows
    return out, counts


# ── Policy action also depends on ──────────────────────────────────────
_BLOCKING = ("BLOCK", "DROP", "RESET")


def _weight(sec: str, action: str, otherwise: str) -> int:
    both = f"{action} {otherwise}".upper()
    if any(w in both for w in _BLOCKING):
        return 0
    if sec == "ssl":
        return 1
    if any(w in both for w in ("CAUTION", "ISOLATE", "CONFIRM")):
        return 2
    return 3


def _order(r: Dict[str, Any]) -> int:
    try:
        return int(r.get("order"))
    except (TypeError, ValueError):
        return 10 ** 9


def depends_on(zia: Dict[str, Any], dest: Dict[str, Any], ident: Optional[Dict[str, Any]] = None,
               not_in_scope: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Each scoped rule that would change a section's action for `dest`
    (the trace's destination), ranked: blocking changes first, then
    decryption, then cautions, then the rest. Each entry is in the shared
    hop shape {module, verdict, rule, overlaps, criteria, notes} plus
    section, action, otherwise, otherwise_rule. `zia` may be an
    apply_identity copy: conditions already met by the identity show as
    "match"; rules it excludes are not listed."""
    from data_flow import _cac_matches, _generic_matches
    from ssl_flow import _matches, _sort_key
    nis = not_in_scope or {}
    cats, apps = list(dest.get("categories") or []), list(dest.get("applications") or [])
    klass = {"catch_all": dest.get("kind") == "class" and dest.get("class") == "general"}
    entries: List[Dict[str, Any]] = []
    for sec in SECTIONS:
        if sec in nis:
            continue
        rules = [r for r in zia.get(sec) or [] if isinstance(r, dict) and r.get("enabled")]
        if sec == "ssl":
            rules = sorted(rules, key=_sort_key)
            hit = lambda r: bool(_matches(r, klass, cats, apps))  # noqa: E731
            act = lambda r: str(r.get("action") or "")  # noqa: E731
            default = "not decrypted (no SSL rule matches)"
        elif sec == "cac":
            rules = sorted(rules, key=_order)
            hit = lambda r: bool(_cac_matches(r, dest))  # noqa: E731
            act = lambda r: ", ".join(r.get("actions") or []) or str(r.get("action") or "")  # noqa: E731
            default = "no app rule (URL filtering decides)"
        elif sec == "dlp":
            rules = sorted(rules, key=_order)
            hit = lambda r: bool(r.get("catch_all") or set(r.get("url_categories") or []) & set(cats) or set(r.get("cloud_applications") or []) & set(apps))  # noqa: E731
            act = lambda r: str(r.get("action") or "")  # noqa: E731
            default = "no DLP rule"
        else:
            rules = sorted(rules, key=_order)
            hit = lambda r: bool(_generic_matches(r, dest))  # noqa: E731
            act = lambda r: str(r.get("action") or "ALLOW")  # noqa: E731
            default = "ALLOW (no rule matches; the default applies)" if sec == "url" else "no file type rule"
        matching = [r for r in rules if hit(r)]
        fallback = next((r for r in matching if not (r.get("scope") or r.get("scoped"))), None)
        otherwise = act(fallback) if fallback else default
        for r in matching:
            if r is fallback:
                break
            if not (r.get("scope") or r.get("scoped")):
                continue
            state, crit = rule_criteria(r, ident)
            if state is False:
                continue
            action = act(r) or "(no action)"
            if action == otherwise:
                continue
            entries.append({
                "module": sec, "verdict": action,
                "rule": {"name": r.get("name"), "order": r.get("order"), "id": r.get("id")},
                "overlaps": [],
                "criteria": [{"name": c["name"], "state": c["state"]} for c in crit],
                "notes": [f"Otherwise: {otherwise}" + (f" (rule '{fallback.get('name')}')" if fallback else "") + "."],
                "section": SECTION_LABEL[sec], "action": action, "otherwise": otherwise,
                "otherwise_rule": fallback.get("name") if fallback else None,
                "conditions": [{"kind": LABEL.get(c["dim"], c["dim"]), "values": c["values"], "state": c["state"]} for c in crit],
                "_rank": (_weight(sec, action, otherwise), SECTIONS.index(sec), _order(r)),
            })
    entries.sort(key=lambda e: e["_rank"])
    for e in entries:
        e.pop("_rank", None)
    return entries[:MAX_ENTRIES]


def whatif(zia: Dict[str, Any], dest: Dict[str, Any], ident: Optional[Dict[str, Any]], counts: Dict[str, int],
           not_in_scope: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The result block the page shows: the identity evaluated, how many
    scoped rules it decided, and the conditions the action still depends on."""
    deps = depends_on(zia, dest, ident, not_in_scope)
    return {"identity": ident, "identity_label": describe(ident), "counts": counts, "depends_on": deps, "shown": min(3, len(deps)),
            "empty_reason": ("" if deps else
                             "For this identity, no remaining condition changes the action: the rules still undecided come after the one that decides it, "
                             "or give the same action." if ident else
                             "No rule on this path is scoped to a user, group, department, location, time window or device trust level "
                             "that would change the action.")}


def assumption(ident: Optional[Dict[str, Any]]) -> Optional[str]:
    """The assumption line that replaces 'any user' when an identity is given."""
    if not ident:
        return None
    return (f"Evaluated for {describe(ident)}: rules scoped to this identity apply, rules scoped to others are skipped. "
            "The groups given are taken as the user's only groups; location groups, time windows, device trust and the other "
            "criteria stay conditional and are listed under 'Policy action also depends on'.")


# ── Live lookup ────────────────────────────────────────────────────────
_SEARCH = {
    # kind: (endpoint, query parameter). Verified against zscaler-sdk-python
    # 1.11.3: user_management.list_users (/users, `name` starts-with
    # filter, page, pageSize), list_groups and list_departments (/groups,
    # /departments, `search`), locations.list_locations (/locations, `search`).
    "user": ("/zia/users", "name"),
    "group": ("/zia/groups", "search"),
    "department": ("/zia/departments", "search"),
    "location": ("/zia/locations", "search"),
}


def valid_query(q: Any) -> Optional[str]:
    s = str(q or "").strip()
    return s if _QUERY.match(s) else None


def search_identities(client: Any, kind: str, query: str, cancel: Any = None) -> Dict[str, Any]:
    """One GET for at most SEARCH_LIMIT names matching `query`. Returns
    {kind, query, results ([{id, name}], users also email, department,
    groups), capped, error}. Never pages on: a search is never a bulk read."""
    if kind not in _SEARCH:
        raise ValueError(f"Search for one of: {', '.join(SEARCH_KINDS)}.")
    q = valid_query(query)
    if q is None:
        raise ValueError("Type 2 to 64 characters to search.")
    ep, param = _SEARCH[kind]
    out: Dict[str, Any] = {"kind": kind, "query": q, "results": [], "capped": False, "error": None}
    try:
        data, code = client.get(ep, {param: q, "page": 1, "pageSize": SEARCH_LIMIT})
    except Exception as e:  # noqa: BLE001
        out["error"] = f"the lookup failed ({type(e).__name__})"
        return out
    if code not in (200, 204):
        out["error"] = f"ZIA answered HTTP {code}"
        return out
    rows = data.get("list") if isinstance(data, dict) and isinstance(data.get("list"), list) else data if isinstance(data, list) else []
    out["capped"] = len(rows) >= SEARCH_LIMIT
    for r in rows[:SEARCH_LIMIT]:
        if not isinstance(r, dict):
            continue
        row: Dict[str, Any] = {"id": r.get("id"), "name": _clip(r.get("name") or r.get("id") or "")}
        if kind == "user":
            row["email"] = _clip(r.get("email") or "")
            dept = r.get("department")
            row["department"] = _ref(dept) if isinstance(dept, dict) else None
            row["groups"] = [g for g in (_ref(x) for x in (r.get("groups") or [])[:MAX_GROUPS] if isinstance(x, dict)) if g]
        out["results"].append(row)
    return out
