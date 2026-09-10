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
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pack_channels as pc
import pack_deploy as pd
from dlp_importer import _load_json, _resolve_configs, discover_packs

# The in-app deploy tags baseline objects with BASELINE_MARK; the Terraform
# hand-off tags every object with "[DLP-Check baseline <id>]" or
# "[DLP-Check pack <id>]". Match either, scoped to the pack id.
_BASELINE_MARK = pd.BASELINE_MARK            # "[DLP-Check baseline"
_PACK_MARK = "[DLP-Check pack"
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


def _engine_dict_ids(eng_obj: Any) -> set:
    expr = str(pd._field(eng_obj, "engine_expression", "expression", default="") or "")
    return {m.group(1) for m in _DICT_ID_RE.finditer(expr)}


def _tenant(client, packs: Sequence[Dict[str, Any]], tenant_cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read dictionaries, engines and every DLP channel's rules the packs
    could have touched."""
    all_policies: List[Dict[str, Any]] = []
    for p in packs:
        all_policies.extend(_defs(p)[2])
    need = pc.needs(all_policies)
    snap = tenant_cache or pd.fetch_tenant(client, need)
    # fetch_tenant reads web rules and (given need) the other channels.
    return snap


def plan_removal(client, packs: Sequence[Dict[str, Any]], *, tenant_cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Preview the removal of one or more deployed packs. Returns items
    (each remove | keep | not-found), a summary, and a plan_hash the apply
    step must echo."""
    snap = _tenant(client, packs, tenant_cache)
    warnings: List[str] = []
    if not snap.get("reachable", True):
        return {"status": "blocked", "found": False, "items": [], "summary": {},
                "blockers": ["Could not read the tenant (no dictionaries, engines or rules listed). Check credentials and permissions."],
                "warnings": snap.get("errors", []), "plan_hash": ""}

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

    def any_match(desc: Any, name: str, def_names: set) -> Optional[str]:
        for m in marks:
            if any(mk in str(desc or "") for mk in m):
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
    for name, g in groups.items():
        if name in def_groups:
            group_items.append({"kind": "app_group", "channel": None, "id": g.get("id"), "name": name, "match": "name"})

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
        if not pd._field(d, "custom", default=False):
            continue   # never touch a predefined dictionary
        how = any_match(pd._field(d, "description"), name, def_dicts)
        if not how:
            continue
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
    return {
        "status": status, "found": bool(items), "packs": pack_ids, "items": items,
        "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
        "plan_hash": plan_hash, "warnings": warnings, "blockers": [],
    }


def remove(client, packs: Sequence[Dict[str, Any]], *, plan_hash: str, writes_enabled: Optional[bool] = None,
           log: pd.LogFn = None) -> Dict[str, Any]:
    """Execute a removal previewed by plan_removal. Re-reads the tenant,
    verifies the plan_hash still matches, then deletes each object in
    reverse dependency order, re-checking that the id still carries the
    name the plan saw (so a renamed/replaced object is left alone)."""
    _log = log or (lambda m: None)
    if writes_enabled is False:
        return {"status": "blocked", "blockers": ["The server is in read-only mode. Enable write mode to remove a deployment."], "results": []}
    plan = plan_removal(client, packs)
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
    for c in to_remove:
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
                entry.update(status="deleted")
                current.pop(str(c["id"]), None)
        results.append(entry)
        _log(f"[{entry['kind']}] {entry['name']}: {entry['status']}" + (f" — {entry.get('error') or entry.get('reason')}" if entry.get('error') or entry.get('reason') else ""))

    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    complete = not counts.get("failed") and not counts.get("skipped")
    status = "removed" if complete and results else ("partial" if counts.get("deleted") else ("nothing" if not results else "failed"))
    return {"status": status, "summary": counts, "results": results, "complete": complete,
            "kept": [it for it in plan["items"] if it["status"] == "keep"],
            "activation_required": bool(counts.get("deleted"))}
