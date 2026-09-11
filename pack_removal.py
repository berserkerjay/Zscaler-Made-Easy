"""
Methodical removal of a deployed pack or baseline.

Find what a pack put into a tenant — by its DLP-Check provenance tag, and
by the names in the pack definition — and take it out safely, in reverse
dependency order (rules, then endpoint application groups, then engines,
then dictionaries). An object is removed only when nothing OUTSIDE the
removal set still references it: an engine a surviving rule still uses, or
a dictionary a surviving engine still uses, is kept and reported. Nothing
predefined is ever touched.

Two phases, mirroring deploy:
  * plan_removal(client, packs)  -> a preview with a plan_hash
  * remove(client, packs, plan_hash, ...) -> deletes, re-checking each id
    still carries the name and tag the plan saw.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pack_channels as pc
import pack_deploy as pd
from dlp_importer import _load_json, _resolve_configs, discover_packs

# The in-app deploy tags baseline objects with BASELINE_MARK; the Terraform
# hand-off tags every object with "[DLP-Check baseline <id>]" or
# "[DLP-Check pack <id>]". Match either, scoped to the pack id.
_BASELINE_MARK = pd.BASELINE_MARK            # "[DLP-Check baseline"
_PACK_MARK = pd.PACK_MARK                    # "[DLP-Check pack"
_ANY_MARKS = (_BASELINE_MARK, _PACK_MARK)    # any DLP-Check provenance, whatever the pack id

# Objects earlier versions of the shipped packs created under names no
# current pack defines (Fed 1.1 CUI objects, the retired endpoint and CUI
# packs, the pre-v4.14 source-code pack, extension rules named after the
# packs' old "Baseline" names). Packs without a baseline section were
# deployed untagged before pack_description existed, so "remove
# everything" finds these by name and flags them for the operator.
_OLD_PACK_NAMES = ("Global Banking Baseline", "Healthcare PHI Baseline", "ZBP Enterprise Baseline",
                   "Source Code to AI Baseline", "CUI Marking Baseline", "ZBP Endpoint DLP Baseline", "Fed Policy Pack", "CJIS Policy Pack")
LEGACY_NAMES: Dict[str, set] = {
    "dictionary": {"CUI Category Phrase", "CUI Contextual Phrases", "CUI Portion Marking Pattern (High confidence)",
                   "CUI Portion Marking Pattern (Medium confidence)", "CUI Registry Marking Pattern (High confidence)",
                   "CUI Registry Marking Pattern (Medium confidence)", "Declassify Date Pattern (High Confidence)",
                   "Declassify Date Pattern (Medium Confidence)", "ZBP-JavaScript Code Detection", "ZBP-Python Code Detection",
                   "ZBP-Shell Script Detection"},
    "engine": {"AEA Medium Confidence", "CUI Engine (High Confidence)", "CUI Engine (Low Confidence)", "CUI Engine (Medium Confidence)",
               "PCI - High", "PCI - Low", "PCI - Medium", "ZBP-JavaScript Code Detection Engine", "ZBP-Python Code Detection Engine",
               "ZBP-Shell Script Detection Engine"},
    "policy": {"Z-Controlled Unclassified Information-Monitor", "Z-Controlled Unclassified Information [Endpoint]",
               "Z-Controlled Unclassified Information [SaaS]", "Z-Controlled Unclassified Information [Email]",
               "zbp-GenAI Application Block", "zbp-GenAI Application Monitor", "zbp-PCI High USB Block", "zbp-PCI Low USB",
               "zbp-PCI Medium USB", "zbp-Sensitive Data Private Share", "zbp-Sensitive Data to USB", "zbp-Unapproved GenAI Applications",
               "ZBP-[DLP] Block Source Code Uploads"}
              | {f"{n} {tag}" for n in _OLD_PACK_NAMES for tag in pc.EXTENSION_TAG.values()},
    "app_group": {"zbp-GenAI Applications"},
}
_DICT_ID_RE = re.compile(r"D(\d+)\.S")

UNDO_ORDER = pd.UNDO_ORDER   # ("policy", "app_group", "engine", "dictionary")


def _pack_marks(pack_id: str) -> Tuple[str, str]:
    return (f"{_BASELINE_MARK} {pack_id}", f"{_PACK_MARK} {pack_id}")


def _defs(pack: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    configs = _resolve_configs(pack["dir"])
    dicts = _load_json(configs, "dlp_dictionaries.json")
    engines = _load_json(configs, "dlp_engines.json")
    policies = pc.expand_sub_rules(_load_json(configs, "dlp_policies.json"))
    return dicts, engines, policies


def _matched(desc: Any, name: str, marks: Tuple[str, str], def_names: set) -> Optional[str]:
    """How a tenant object maps to a pack: by its provenance tag, or by a
    name the pack defines. Tag wins; a name-only match is flagged so the
    operator sees it was not tool-tagged."""
    d = str(desc or "")
    if any(m in d for m in marks):
        return "tag"
    if name in def_names:
        return "name"
    return None


def _is_custom_dictionary(d: Any, how: Optional[str] = None) -> bool:
    """A dictionary this tool may delete: the tenant flags it custom, or it
    carries our provenance tag (a predefined dictionary never does). A
    listing that omits the custom flag must not hide our own objects."""
    custom = pd._field(d, "custom", "customDictionary", default=None)
    if custom is not None:
        return bool(custom)   # the tenant said so, either way
    # No flag at all in this listing: our tag on a dictionary whose name is
    # not one of Zscaler's localised predefined names means it is ours.
    return how == "tag" and not pd._field(d, "name_l10n_tag", "nameL10nTag", default=False)


def _read_summary(snap: Dict[str, Any]) -> Dict[str, Any]:
    """What the preview could see, so "nothing to remove" can say what was
    read (and what was not) instead of leaving the operator guessing."""
    dicts = snap.get("dictionaries") or {}
    custom = [d for d in dicts.values() if pd._field(d, "custom", "customDictionary", default=False)]
    tagged = [d for d in dicts.values() if any(m in str(pd._field(d, "description", default="") or "") for m in _ANY_MARKS)]
    engines = snap.get("engines") or {}
    tagged_engines = [e for e in engines.values() if any(m in str(pd._field(e, "description", default="") or "") for m in _ANY_MARKS)]
    rules = {pc.WEB: len(snap.get("rules") or [])}
    for ch, rs in ((snap.get("channels") or {}).get("rules") or {}).items():
        rules[ch] = len(rs or [])
    tagged_rules = sum(1 for r in (snap.get("rules") or []) if any(m in str(r.get("description") or "") for m in _ANY_MARKS))
    for rs in ((snap.get("channels") or {}).get("rules") or {}).values():
        tagged_rules += sum(1 for r in (rs or []) if any(m in str(r.get("description") or "") for m in _ANY_MARKS))
    return {"dictionaries": len(dicts), "custom_dictionaries": len(custom), "tagged_dictionaries": len(tagged),
            "engines": len(engines), "tagged_engines": len(tagged_engines), "rules": rules, "tagged_rules": tagged_rules,
            "unreadable": dict(snap.get("unreadable") or {}), "channel_errors": dict(((snap.get("channels") or {}).get("errors") or {})),
            "errors": list(snap.get("errors") or [])}


def _engine_dict_ids(eng_obj: Any) -> set:
    expr = str(pd._field(eng_obj, "engine_expression", "expression", default="") or "")
    return {m.group(1) for m in _DICT_ID_RE.finditer(expr)}


def _tenant(client, packs: Sequence[Dict[str, Any]], tenant_cache: Optional[Dict[str, Any]] = None,
            everything: bool = False) -> Dict[str, Any]:
    """Read dictionaries, engines and every DLP channel's rules the packs
    could have touched (every channel when removing everything)."""
    all_policies: List[Dict[str, Any]] = []
    for p in packs:
        all_policies.extend(_defs(p)[2])
    need = pc.needs(all_policies)
    if everything:
        need["channels"] = set(need["channels"]) | set(pc.DLP_CHANNELS)
        need["casb"] = True
        need["endpoint_app_groups"] = True
    snap = tenant_cache or pd.fetch_tenant(client, need)
    # fetch_tenant reads web rules and (given need) the other channels.
    return snap


def plan_removal(client, packs: Sequence[Dict[str, Any]], *, tenant_cache: Optional[Dict[str, Any]] = None,
                 everything: bool = False) -> Dict[str, Any]:
    """Preview the removal of one or more deployed packs. Returns items
    (each remove | keep | not-found), a summary, and a plan_hash the apply
    step must echo. With `everything`, the scope is everything DLP-Check
    ever put in the tenant: any object carrying a DLP-Check provenance
    tag (whatever pack id or version wrote it) plus the names of every
    given pack and of the objects earlier pack versions shipped."""
    snap = _tenant(client, packs, tenant_cache, everything=everything)
    warnings: List[str] = []
    if not snap.get("reachable", True):
        return {"status": "blocked", "found": False, "items": [], "summary": {},
                "blockers": ["Could not read the tenant (no dictionaries, engines or rules listed). Check credentials and permissions."],
                "warnings": snap.get("errors", []), "plan_hash": "", "read": _read_summary(snap)}
    # A partial read must never look like "nothing to remove": say what
    # could not be listed, and block when it is the very kind the packs own.
    unreadable = snap.get("unreadable") or {}
    for kind, err in unreadable.items():
        warnings.append(f"Could not list the tenant's {kind}: {err}. Anything of that kind is invisible to this preview.")
    for ch, err in ((snap.get("channels") or {}).get("errors") or {}).items():
        warnings.append(f"Could not list the {pc.CHANNELS.get(ch, {}).get('label', ch)} rules: {err}.")

    # Pack definitions and provenance marks.
    def_dicts, def_engines, def_policies = set(), set(), set()
    marks: List[Tuple[str, str]] = []
    pack_ids: List[str] = []
    for p in packs:
        pack_ids.append(p["id"])
        marks.append(_pack_marks(p["id"]))
        d, e, pol = _defs(p)
        def_dicts |= {x["name"] for x in d if x.get("name")}
        def_engines |= {x["name"] for x in e if x.get("name")}
        def_policies |= {x["name"] for x in pol if x.get("name")}
    if everything:
        def_dicts |= LEGACY_NAMES["dictionary"]
        def_engines |= LEGACY_NAMES["engine"]
        def_policies |= LEGACY_NAMES["policy"]

    def any_match(desc: Any, name: str, def_names: set) -> Optional[str]:
        d = str(desc or "")
        if everything and any(mk in d for mk in _ANY_MARKS):
            return "tag"
        for m in marks:
            if any(mk in d for mk in m):
                return "tag"
        return "name" if name in def_names else None

    # ---- rules across every channel ----------------------------------------
    rule_items: List[Dict[str, Any]] = []
    tenant_rules: List[Dict[str, Any]] = []   # every rule the tenant has, for reference-keep checks
    web = [dict(r, channel=pc.WEB) for r in snap.get("rules", [])]
    chan_rules = (snap.get("channels") or {}).get("rules") or {}
    others: List[Dict[str, Any]] = []
    for ch, rules in chan_rules.items():
        for r in rules or []:
            others.append(dict(r, channel=ch))
    tenant_rules = web + others
    for r in tenant_rules:
        how = any_match(r.get("description"), r.get("name", ""), def_policies)
        if how:
            rule_items.append({
                "kind": "policy", "channel": r["channel"], "id": r.get("id"), "name": r.get("name"),
                "parent_id": r.get("parent_id"), "type": r.get("type"), "match": how,
                "engine_ids": [str(x) for x in (r.get("engine_ids") or [])],
            })
    remove_rule_ids = {str(i["id"]) for i in rule_items}

    # ---- endpoint application groups ---------------------------------------
    group_items: List[Dict[str, Any]] = []
    groups = (snap.get("channels") or {}).get("app_groups") or {}
    def_groups: set = set()
    for p in packs:
        for g in _load_json(_resolve_configs(p["dir"]), "endpoint_application_groups.json"):
            if g.get("name"):
                def_groups.add(g["name"])
    if everything:
        def_groups |= LEGACY_NAMES["app_group"]
    for name, g in groups.items():
        how = any_match(g.get("description"), name, def_groups)
        if how:
            group_items.append({"kind": "app_group", "channel": None, "id": g.get("id"), "name": name, "match": how})

    # ---- engines ------------------------------------------------------------
    engine_items: List[Dict[str, Any]] = []
    engines = snap.get("engines") or {}
    remove_engine_ids: set = set()
    # Engine ids still needed by a rule that is NOT being removed.
    engine_ids_used_by_survivors: set = set()
    for r in tenant_rules:
        if str(r.get("id")) in remove_rule_ids:
            continue
        for eid in (r.get("engine_ids") or []):
            engine_ids_used_by_survivors.add(str(eid))
    for name, e in engines.items():
        how = any_match(pd._field(e, "description"), name, def_engines)
        if not how:
            continue
        eid = str(pd._field(e, "id"))
        keep_reason = None
        if eid in engine_ids_used_by_survivors:
            keep_reason = "still used by a rule outside this pack"
        item = {"kind": "engine", "channel": None, "id": pd._field(e, "id"), "name": name, "match": how,
                "dict_ids": sorted(_engine_dict_ids(e))}
        if keep_reason:
            item["keep"] = keep_reason
        else:
            remove_engine_ids.add(eid)
        engine_items.append(item)

    # ---- dictionaries (custom only) ----------------------------------------
    dict_items: List[Dict[str, Any]] = []
    dicts = snap.get("dictionaries") or {}
    # Dict ids still referenced by an engine that is NOT being removed.
    dict_ids_used_by_survivors: set = set()
    for name, e in engines.items():
        if str(pd._field(e, "id")) in remove_engine_ids:
            continue
        dict_ids_used_by_survivors |= _engine_dict_ids(e)
    for name, d in dicts.items():
        how = any_match(pd._field(d, "description"), name, def_dicts)
        if not how:
            continue
        if not _is_custom_dictionary(d, how):
            continue   # never touch a predefined dictionary
        did = str(pd._field(d, "id"))
        item = {"kind": "dictionary", "channel": None, "id": pd._field(d, "id"), "name": name, "match": how}
        if did in dict_ids_used_by_survivors:
            item["keep"] = "still used by an engine outside this pack"
        dict_items.append(item)

    items = rule_items + group_items + engine_items + dict_items
    for it in items:
        it["status"] = "keep" if it.get("keep") else "remove"
        if it.get("match") == "name":
            warnings.append(f"{it['kind']} '{it['name']}' matched by name only (no DLP-Check tag); confirm it is yours before removing.")

    # Dependency links, so the flow diagram can draw dictionary -> engine ->
    # rule for the objects in the plan (a rule depends on its engines, an
    # engine on its dictionaries), using only objects the plan itself holds.
    eng_id_to_name = {str(i["id"]): i["name"] for i in engine_items}
    dict_id_to_name = {str(i["id"]): i["name"] for i in dict_items}
    for it in rule_items:
        it["depends_on"] = [f"engine:{eng_id_to_name[eid]}" for eid in it.get("engine_ids", []) if eid in eng_id_to_name]
    for it in engine_items:
        it["depends_on"] = [f"dictionary:{dict_id_to_name[did]}" for did in it.get("dict_ids", []) if did in dict_id_to_name]

    rank = {k: i for i, k in enumerate(UNDO_ORDER)}
    items.sort(key=lambda c: (rank.get(c["kind"], 9), 0 if c.get("parent_id") is not None else 1, str(c["name"])))

    summary: Dict[str, int] = {}
    for it in items:
        key = f"{it['status']}_{it['kind']}"
        summary[key] = summary.get(key, 0) + 1
    to_remove = [it for it in items if it["status"] == "remove"]
    plan_hash = hashlib.sha256(json.dumps(
        [(i["kind"], i.get("channel"), str(i["id"]), i["name"]) for i in to_remove], sort_keys=True).encode()).hexdigest()[:16]

    status = "ready" if to_remove else "nothing"
    blockers: List[str] = []
    if not items and unreadable:
        # Nothing matched, but part of the tenant could not be read: that is
        # not "nothing to remove", it is "could not look".
        status = "blocked"
        blockers.append("Nothing matched, but the tenant could not be fully read: " + "; ".join(f"{k}: {v}" for k, v in unreadable.items())
                        + ". Check the API client's permissions for that area, then run the preview again.")
    return {
        "status": status, "found": bool(items), "packs": pack_ids, "everything": everything, "items": items,
        "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
        "plan_hash": plan_hash, "warnings": warnings, "blockers": blockers, "read": _read_summary(snap),
    }


def plan_removal_deployment(client, record: Dict[str, Any], *, tenant_cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Preview the undo of one recorded deployment through the same plan
    shape as a pack removal: every object the deployment created (and
    has not undone yet) that the tenant still lists under the name we
    gave it is removed; an id that now carries another name is kept and
    said so; an object already gone is reported as not found. Engines and
    dictionaries a rule outside the deployment still uses are kept."""
    snap = tenant_cache or pd.fetch_tenant(client, _all_need())
    if not snap.get("reachable", True):
        return {"status": "blocked", "found": False, "items": [], "summary": {},
                "blockers": ["Could not read the tenant (no dictionaries, engines or rules listed). Check credentials and permissions."],
                "warnings": snap.get("errors", []), "plan_hash": ""}
    created = [c for c in (record.get("created") or []) if not c.get("undone")]
    warnings: List[str] = []
    web = [dict(r, channel=pc.WEB) for r in snap.get("rules", [])]
    others = [dict(r, channel=ch) for ch, rs in ((snap.get("channels") or {}).get("rules") or {}).items() for r in (rs or [])]
    tenant_rules = web + others
    rules_by_key = {(r["channel"], str(r.get("id"))): r for r in tenant_rules}
    engines = {str(pd._field(e, "id")): (n, e) for n, e in (snap.get("engines") or {}).items()}
    dicts = {str(pd._field(d, "id")): (n, d) for n, d in (snap.get("dictionaries") or {}).items()}
    groups = {str(g.get("id")): (n, g) for n, g in ((snap.get("channels") or {}).get("app_groups") or {}).items()}
    items: List[Dict[str, Any]] = []
    remove_rule_ids: set = set()
    for c in created:
        kind, cid, name = c.get("kind"), str(c.get("id")), str(c.get("name") or "")
        item = {"kind": kind, "channel": c.get("channel") if kind == "policy" else None, "id": c.get("id"), "name": name,
                "parent_id": c.get("parent_id"), "match": "deployment"}
        if kind == "policy":
            cur = rules_by_key.get((str(c.get("channel") or pc.WEB), cid))
            item["type"] = (cur or {}).get("type")
            item["engine_ids"] = [str(x) for x in ((cur or {}).get("engine_ids") or [])]
        elif kind == "engine":
            cur = {"name": engines[cid][0]} if cid in engines else None
            if cur:
                item["dict_ids"] = sorted(_engine_dict_ids(engines[cid][1]))
        elif kind == "dictionary":
            cur = {"name": dicts[cid][0]} if cid in dicts else None
        elif kind == "app_group":
            cur = {"name": groups[cid][0]} if cid in groups else None
        else:
            continue
        if cur is None:
            item["status"] = "not-found"; item["reason"] = "already gone from the tenant"
        elif str(cur.get("name") or "") != name:
            item["status"] = "keep"; item["keep"] = f"id {cid} now carries the name '{cur.get('name')}', not '{name}'"
        else:
            item["status"] = "remove"
            if kind == "policy":
                remove_rule_ids.add(cid)
        items.append(item)
    # Keep rule: an engine a surviving rule still uses, a dictionary a surviving engine still uses.
    used_engines = {str(eid) for r in tenant_rules if str(r.get("id")) not in remove_rule_ids for eid in (r.get("engine_ids") or [])}
    remove_engine_ids = set()
    for it in items:
        if it["kind"] == "engine" and it["status"] == "remove":
            if str(it["id"]) in used_engines:
                it["status"] = "keep"; it["keep"] = "still used by a rule outside this deployment"
            else:
                remove_engine_ids.add(str(it["id"]))
    used_dicts: set = set()
    for eid, (n, e) in engines.items():
        if eid not in remove_engine_ids:
            used_dicts |= _engine_dict_ids(e)
    for it in items:
        if it["kind"] == "dictionary" and it["status"] == "remove" and str(it["id"]) in used_dicts:
            it["status"] = "keep"; it["keep"] = "still used by an engine outside this deployment"
    eng_id_to_name = {str(i["id"]): i["name"] for i in items if i["kind"] == "engine"}
    dict_id_to_name = {str(i["id"]): i["name"] for i in items if i["kind"] == "dictionary"}
    for it in items:
        if it["kind"] == "policy":
            it["depends_on"] = [f"engine:{eng_id_to_name[e]}" for e in it.get("engine_ids", []) if e in eng_id_to_name]
        elif it["kind"] == "engine":
            it["depends_on"] = [f"dictionary:{dict_id_to_name[d]}" for d in it.get("dict_ids", []) if d in dict_id_to_name]
    rank = {k: i for i, k in enumerate(UNDO_ORDER)}
    items.sort(key=lambda c: (rank.get(c["kind"], 9), 0 if c.get("parent_id") is not None else 1, str(c["name"])))
    summary: Dict[str, int] = {}
    for it in items:
        key = f"{it['status']}_{it['kind']}"
        summary[key] = summary.get(key, 0) + 1
    to_remove = [it for it in items if it["status"] == "remove"]
    plan_hash = hashlib.sha256(json.dumps([(i["kind"], i.get("channel"), str(i["id"]), i["name"]) for i in to_remove], sort_keys=True).encode()).hexdigest()[:16]
    return {"status": "ready" if to_remove else "nothing", "found": bool(items), "packs": list(record.get("packs") or []),
            "deployment": {"id": record.get("id"), "at": record.get("at"), "tenant_label": record.get("tenant_label"), "packs": record.get("packs")},
            "everything": False, "items": items, "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
            "plan_hash": plan_hash, "warnings": warnings, "blockers": []}


def remove_deployment(client, record: Dict[str, Any], *, plan_hash: str, writes_enabled: Optional[bool] = None,
                      log: pd.LogFn = None, settle_seconds: float = 45.0) -> Dict[str, Any]:
    """Undo one recorded deployment through the guided path: the plan
    previewed by plan_removal_deployment, tiered deletes with activation,
    then the same read-back verification as a pack removal."""
    return _execute(client, lambda: plan_removal_deployment(client, record),
                    plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds)


def _settle(zia, settle_seconds: float, _log) -> Optional[str]:
    """Wait for ZIA to report the activation as ACTIVE (see pc.wait_active)."""
    return pc.wait_active(zia, settle_seconds, _log)


def _all_need() -> Dict[str, Any]:
    need = pc.needs([])
    need["channels"] = set(pc.DLP_CHANNELS)
    need["casb"] = True
    need["endpoint_app_groups"] = True
    return need


def _tag_pack(desc: Any) -> Optional[str]:
    """The pack id inside a DLP-Check provenance tag, or None."""
    d = str(desc or "")
    for mk in _ANY_MARKS:
        if mk in d:
            rest = d.split(mk, 1)[1].strip()
            return rest.split("]", 1)[0].split(" v")[0].strip() or None
    return None


def _tenant_rules(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    web = [dict(r, channel=pc.WEB) for r in snap.get("rules", [])]
    others = [dict(r, channel=ch) for ch, rs in ((snap.get("channels") or {}).get("rules") or {}).items() for r in (rs or [])]
    return web + others


def inventory(client) -> Dict[str, Any]:
    """Every DLP rule the tenant has, on every channel, with its engines
    and provenance, so an operator can pick the leftovers to remove."""
    snap = pd.fetch_tenant(client, _all_need())
    if not snap.get("reachable", True):
        return {"status": "blocked", "rules": [], "blockers": ["Could not read the tenant. Check credentials and permissions."],
                "errors": snap.get("errors", [])}
    engines = snap.get("engines") or {}
    eng_name = {str(pd._field(e, "id")): n for n, e in engines.items()}
    rules = []
    for r in _tenant_rules(snap):
        desc = r.get("description")
        pack = _tag_pack(desc)
        rules.append({"channel": r["channel"], "id": r.get("id"), "name": r.get("name"), "state": r.get("state"),
                      "action": r.get("action"), "parent_id": r.get("parent_id"), "type": r.get("type"),
                      "engine_ids": [str(x) for x in (r.get("engine_ids") or [])],
                      "engines": [eng_name.get(str(x), str(x)) for x in (r.get("engine_ids") or [])],
                      "tagged": pack is not None, "pack": pack})
    order = {ch: i for i, ch in enumerate(pc.DLP_CHANNELS)}
    rules.sort(key=lambda r: (order.get(r["channel"], 9), str(r["name"]).lower()))
    # The dictionary definitions, for whoever needs to explain a match
    # (Detection Health): custom or predefined, type, confidence, proximity.
    dicts = {}
    for name, d in (snap.get("dictionaries") or {}).items():
        dicts[str(name)] = {"id": pd._field(d, "id"), "custom": bool(pd._field(d, "custom", "customDictionary", default=False)),
                            "type": str(pd._field(d, "dictionary_type", "dictionaryType", default="") or ""),
                            "confidence_threshold": pd._field(d, "confidence_threshold", "confidenceThreshold"),
                            "predefined_confidence": pd._field(d, "confidence_level_for_predefined_dict", "confidenceLevelForPredefinedDict"),
                            "phrase_match": str(pd._field(d, "custom_phrase_match_type", "customPhraseMatchType", default="") or ""),
                            "proximity": pd._field(d, "proximity"),
                            "proximity_enabled": bool(pd._field(d, "proximity_enabled_for_custom_dictionary", "proximityEnabledForCustomDictionary", default=False)),
                            "phrases": len(pd._field(d, "phrases", default=[]) or []), "patterns": len(pd._field(d, "patterns", default=[]) or [])}
    return {"status": "ready", "rules": rules, "dictionaries": dicts, "errors": (snap.get("channels") or {}).get("errors") or {}}


def plan_removal_selected(client, selected: Sequence[Dict[str, Any]], *, tenant_cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Preview the removal of the chosen rules ({channel, id} each) and of
    the engines and dictionaries only they use, with the same keep rule
    as a pack removal: an engine a rule outside the selection still uses,
    or a dictionary a surviving engine still uses, is kept. Predefined
    objects are never touched."""
    keys = {(str(x.get("channel") or pc.WEB), str(x.get("id"))) for x in (selected or []) if x.get("id") is not None}
    snap = tenant_cache or pd.fetch_tenant(client, _all_need())
    if not snap.get("reachable", True):
        return {"status": "blocked", "found": False, "items": [], "summary": {},
                "blockers": ["Could not read the tenant (no dictionaries, engines or rules listed). Check credentials and permissions."],
                "warnings": snap.get("errors", []), "plan_hash": ""}
    warnings: List[str] = []
    tenant_rules = _tenant_rules(snap)
    rule_items = []
    for r in tenant_rules:
        if (r["channel"], str(r.get("id"))) in keys:
            rule_items.append({"kind": "policy", "channel": r["channel"], "id": r.get("id"), "name": r.get("name"),
                               "parent_id": r.get("parent_id"), "type": r.get("type"), "match": "selected",
                               "engine_ids": [str(x) for x in (r.get("engine_ids") or [])]})
    found_keys = {(i["channel"], str(i["id"])) for i in rule_items}
    for k in sorted(keys - found_keys):
        warnings.append(f"rule {k[1]} on {k[0]} is no longer in the tenant; skipped.")
    remove_rule_ids = {str(i["id"]) for i in rule_items}

    engines = snap.get("engines") or {}
    wanted_engine_ids = {eid for i in rule_items for eid in i["engine_ids"]}
    engine_ids_used_by_survivors: set = set()
    for r in tenant_rules:
        if str(r.get("id")) in remove_rule_ids:
            continue
        engine_ids_used_by_survivors |= {str(e) for e in (r.get("engine_ids") or [])}
    engine_items = []
    remove_engine_ids: set = set()
    for name, e in engines.items():
        eid = str(pd._field(e, "id"))
        if eid not in wanted_engine_ids:
            continue
        if pd._field(e, "predefined_engine", default=False) or pd._field(e, "custom_dlp_engine", default=True) is False:
            continue   # never a predefined engine
        item = {"kind": "engine", "channel": None, "id": pd._field(e, "id"), "name": name, "match": "dependency",
                "dict_ids": sorted(_engine_dict_ids(e))}
        if eid in engine_ids_used_by_survivors:
            item["keep"] = "still used by a rule you did not select"
        else:
            remove_engine_ids.add(eid)
        engine_items.append(item)

    dicts = snap.get("dictionaries") or {}
    wanted_dict_ids = {did for i in engine_items if "keep" not in i for did in i["dict_ids"]}
    dict_ids_used_by_survivors: set = set()
    for name, e in engines.items():
        if str(pd._field(e, "id")) in remove_engine_ids:
            continue
        dict_ids_used_by_survivors |= _engine_dict_ids(e)
    dict_items = []
    for name, d in dicts.items():
        did = str(pd._field(d, "id"))
        if did not in wanted_dict_ids or not pd._field(d, "custom", default=False):
            continue
        item = {"kind": "dictionary", "channel": None, "id": pd._field(d, "id"), "name": name, "match": "dependency"}
        if did in dict_ids_used_by_survivors:
            item["keep"] = "still used by an engine that stays"
        dict_items.append(item)

    items = rule_items + engine_items + dict_items
    for it in items:
        it["status"] = "keep" if it.get("keep") else "remove"
    eng_id_to_name = {str(i["id"]): i["name"] for i in engine_items}
    dict_id_to_name = {str(i["id"]): i["name"] for i in dict_items}
    for it in rule_items:
        it["depends_on"] = [f"engine:{eng_id_to_name[eid]}" for eid in it["engine_ids"] if eid in eng_id_to_name]
    for it in engine_items:
        it["depends_on"] = [f"dictionary:{dict_id_to_name[did]}" for did in it.get("dict_ids", []) if did in dict_id_to_name]
    rank = {k: i for i, k in enumerate(UNDO_ORDER)}
    items.sort(key=lambda c: (rank.get(c["kind"], 9), 0 if c.get("parent_id") is not None else 1, str(c["name"])))
    summary: Dict[str, int] = {}
    for it in items:
        key = f"{it['status']}_{it['kind']}"
        summary[key] = summary.get(key, 0) + 1
    to_remove = [it for it in items if it["status"] == "remove"]
    plan_hash = hashlib.sha256(json.dumps(
        [(i["kind"], i.get("channel"), str(i["id"]), i["name"]) for i in to_remove], sort_keys=True).encode()).hexdigest()[:16]
    return {"status": "ready" if to_remove else "nothing", "found": bool(items), "packs": [], "selection": sorted(keys),
            "items": items, "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
            "plan_hash": plan_hash, "warnings": warnings, "blockers": []}


def remove(client, packs: Sequence[Dict[str, Any]], *, plan_hash: str, writes_enabled: Optional[bool] = None,
           log: pd.LogFn = None, settle_seconds: float = 45.0, everything: bool = False) -> Dict[str, Any]:
    """Execute a removal previewed by plan_removal. Re-reads the tenant,
    verifies the plan_hash still matches, then deletes each object in
    reverse dependency order, re-checking that the id still carries the
    name the plan saw (so a renamed/replaced object is left alone).
    Activates, waits for the activation to settle, then VERIFIES BY
    READING the tenant again: the result's `verification` says whether
    anything of the pack is still there."""
    return _execute(client, lambda: plan_removal(client, packs, everything=everything),
                    plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds)


def remove_selected(client, selected: Sequence[Dict[str, Any]], *, plan_hash: str, writes_enabled: Optional[bool] = None,
                    log: pd.LogFn = None, settle_seconds: float = 45.0) -> Dict[str, Any]:
    """Execute a removal previewed by plan_removal_selected: the chosen
    rules, then the engines and dictionaries only they used."""
    return _execute(client, lambda: plan_removal_selected(client, selected),
                    plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds)


def _execute(client, planner, *, plan_hash: str, writes_enabled: Optional[bool], log: pd.LogFn, settle_seconds: float) -> Dict[str, Any]:
    _log = log or (lambda m: None)
    if writes_enabled is False:
        return {"status": "blocked", "blockers": ["The server is in read-only mode. Enable write mode to remove a deployment."], "results": []}
    plan = planner()
    if plan["status"] == "blocked":
        return {"status": "blocked", "blockers": plan["blockers"], "results": []}
    if plan_hash and plan["plan_hash"] != plan_hash:
        return {"status": "stale", "blockers": [
            "The tenant changed since the preview (the removal plan no longer matches). Run the preview again and confirm the new plan."],
            "results": [], "plan_hash": plan["plan_hash"]}

    zia = client.zia
    to_remove = [it for it in plan["items"] if it["status"] == "remove"]
    names_cache: Dict[Tuple[str, Optional[str]], Tuple[Optional[Dict[str, str]], Optional[str]]] = {}
    results: List[Dict[str, Any]] = []
    activations: List[Dict[str, Any]] = []

    # Delete in dependency tiers — rules and endpoint application groups
    # first, then engines, then dictionaries — and ACTIVATE between tiers.
    # ZIA validates a delete against the saved (activated) config, so an
    # engine or dictionary cannot be removed while a rule that references it
    # is only pending-deleted; activating each tier clears those references
    # so the next tier's objects (the engines and dictionaries tied to the
    # pack) actually delete.
    TIERS = [("policy", "app_group"), ("engine",), ("dictionary",)]
    for ti, kinds in enumerate(TIERS):
        tier = [c for c in to_remove if c["kind"] in kinds]
        if not tier:
            continue
        deleted_here = 0
        for c in tier:
            key = (c["kind"], c.get("channel") if c["kind"] == "policy" else None)
            if key not in names_cache:
                names_cache[key] = pd._current_names(zia, c["kind"], c.get("channel"))
            current, err = names_cache[key]
            entry = {"kind": c["kind"], "name": c["name"], "id": c["id"], "channel": c.get("channel"), "match": c.get("match")}
            if current is None:
                entry.update(status="failed", error=f"could not list the tenant's {c['kind']} objects: {err}")
            elif str(c["id"]) not in current:
                entry.update(status="gone", reason="already removed from the tenant")
            elif current[str(c["id"])] != c["name"]:
                entry.update(status="skipped", reason=f"id {c['id']} now carries the name '{current[str(c['id'])]}', not '{c['name']}'; left alone")
            else:
                derr = pd._delete(zia, c)
                if derr:
                    entry.update(status="failed", error=derr)
                else:
                    entry.update(status="deleted"); deleted_here += 1
                    current.pop(str(c["id"]), None)
            results.append(entry)
            _log(f"[{entry['kind']}] {entry['name']}: {entry['status']}" + (f" — {entry.get('error') or entry.get('reason')}" if entry.get('error') or entry.get('reason') else ""))
        # Activate before the next tier so its objects are no longer referenced.
        more = any(c["kind"] in k for k in TIERS[ti + 1:] for c in to_remove)
        if deleted_here and more:
            _log("Activating deleted rules before removing engines/dictionaries…")
            act = pc.activate(zia)
            activations.append(act)
            _log("Activation " + ("done." if act.get("activated") else f"could not run: {act.get('error')}"))
            names_cache.clear()   # re-read after activation

    # Final activation so every deletion is live, then wait for ZIA to
    # report ACTIVE (an activation is not instantaneous).
    final_activation = None
    settled_status = None
    if any(r["status"] == "deleted" for r in results):
        _log("Activating pending ZIA changes…")
        final_activation = pc.activate(zia)
        activations.append(final_activation)
        _log("Activation " + ("done." if final_activation.get("activated") else f"could not run: {final_activation.get('error')}"))
        settled_status = _settle(zia, settle_seconds, _log)

    # VERIFY BY READING: run the same discovery the preview ran, against
    # the tenant as it is now. Anything of the pack still there is
    # reported as still present, and the removal is not called complete.
    _log("Re-reading the tenant to verify the removal…")
    verify = planner()
    remaining = [it for it in verify.get("items", []) if it["status"] == "remove"]
    remaining_keys = {(it["kind"], it.get("channel"), str(it["id"])) for it in remaining}
    # Also look for every object this run deleted, by id and name: a plan
    # keyed on rules (pick mode) cannot see a leftover engine once its
    # rules are gone, but a fresh listing can.
    names_cache.clear()
    for entry in results:
        if entry["status"] != "deleted":
            continue
        key = (entry["kind"], entry.get("channel") if entry["kind"] == "policy" else None)
        if key not in names_cache:
            names_cache[key] = pd._current_names(zia, entry["kind"], entry.get("channel"))
        current, _err = names_cache[key]
        if current is not None and current.get(str(entry["id"])) == entry["name"] \
                and (entry["kind"], entry.get("channel"), str(entry["id"])) not in remaining_keys:
            remaining.append({"kind": entry["kind"], "channel": entry.get("channel"), "id": entry["id"], "name": entry["name"],
                              "status": "remove", "match": entry.get("match")})
            remaining_keys.add((entry["kind"], entry.get("channel"), str(entry["id"])))
    for entry in results:
        if entry["status"] == "deleted" and (entry["kind"], entry.get("channel"), str(entry["id"])) in remaining_keys:
            entry.update(status="still_present",
                         error="the delete call returned no error but a fresh read still lists this object; activate in ZIA and remove the leftovers")
    verification = {
        "read": verify.get("status") != "blocked",
        "clean": not remaining and verify.get("status") != "blocked",
        "remaining": remaining,
        "kept": [it for it in verify.get("items", []) if it["status"] == "keep"],
        "activation_status": settled_status,
        "plan": verify,
        "blockers": verify.get("blockers", []),
    }
    _log("Verification: " + ("nothing of the pack remains in the tenant." if verification["clean"]
                             else (f"{len(remaining)} object(s) still present." if remaining else "could not re-read the tenant.")))

    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    complete = verification["clean"] and not counts.get("failed") and not counts.get("skipped") and not counts.get("still_present")
    status = "removed" if complete and results else ("partial" if counts.get("deleted") else ("nothing" if not results else "failed"))
    return {"status": status, "summary": counts, "results": results, "complete": complete,
            "kept": [it for it in plan["items"] if it["status"] == "keep"],
            "verification": verification,
            "activation": final_activation, "activations": activations,
            "activation_required": bool(counts.get("deleted")) and not (final_activation and final_activation.get("activated"))}
