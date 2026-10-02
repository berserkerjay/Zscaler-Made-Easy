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
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pack_channels as pc
import pack_deploy as pd
import pack_ops as ops
from dlp_importer import _load_json, _resolve_configs, heal_predefined_names

# The in-app deploy and the Terraform hand-off tag every object with
# "[<assessor> baseline <id> ...]" or "[<assessor> pack <id> ...]" at the end
# of its description ("[DLP-Check ...]" before the assessor's name was used,
# or when none was given). pack_deploy.has_mark / tag_pack recognise both,
# scoped to the pack id.

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


def _tagged(desc: Any, known: Optional[Iterable[str]] = None) -> bool:
    """Whether a description carries a deploy's provenance tag: the tool's
    own "[DLP-Check ..." form, or an assessor's tag at the end for a pack
    id in `known` (the library) or one carrying a version or the deploy's
    sentence, so a customer's "[Q3 pack review]" never counts."""
    return pd.tag_pack(desc, known=known if known is not None else ()) is not None


def _defs(pack: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    configs = _resolve_configs(pack["dir"])
    # The deploy renamed a dictionary named like a predefined display name; the removal must look for that name.
    dicts, engines, _ = heal_predefined_names(_load_json(configs, "dlp_dictionaries.json"), _load_json(configs, "dlp_engines.json"))
    policies = pc.expand_sub_rules(_load_json(configs, "dlp_policies.json"))
    return dicts, engines, policies


def _matched(desc: Any, name: str, pack_ids: Sequence[str], def_names: set) -> Optional[str]:
    """How a tenant object maps to a pack: by its provenance tag, or by a
    name the pack defines. Tag wins; a name-only match is flagged so the
    operator sees it was not tool-tagged."""
    if any(pd.has_mark(desc, pack_id=pid) for pid in pack_ids):
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
    known = pd.library_ids()
    dicts = snap.get("dictionaries") or {}
    custom = [d for d in dicts.values() if pd._field(d, "custom", "customDictionary", default=False)]
    tagged = [d for d in dicts.values() if _tagged(pd._field(d, "description", default=""), known)]
    engines = snap.get("engines") or {}
    tagged_engines = [e for e in engines.values() if _tagged(pd._field(e, "description", default=""), known)]
    rules = {pc.WEB: len(snap.get("rules") or [])}
    for ch, rs in ((snap.get("channels") or {}).get("rules") or {}).items():
        rules[ch] = len(rs or [])
    tagged_rules = sum(1 for r in (snap.get("rules") or []) if _tagged(r.get("description"), known))
    for rs in ((snap.get("channels") or {}).get("rules") or {}).values():
        tagged_rules += sum(1 for r in (rs or []) if _tagged(r.get("description"), known))
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


def _with_rate(plan: Dict[str, Any], client: Any = None) -> Dict[str, Any]:
    """Add how this removal meets ZIA's rate limits, from the requests this
    app sent in the last hour: its deletes plus the one activation."""
    import zia_rate
    n = int(plan.get("remove_count") or 0)
    f = zia_rate.forecast({"delete": n, "activate": 1}, key=zia_rate.key_of(client), tenant_label=zia_rate.labels_of(client)) if n and not plan.get("blockers") else None
    if f:
        f["detail"] = zia_rate.history_text(f)
        if f["severity"] != "ok":
            plan.setdefault("warnings", []).insert(0, f"ZIA rate limits: {f['verdict']}")
    plan["rate_forecast"] = f
    return plan


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
    pack_ids: List[str] = []
    for p in packs:
        pack_ids.append(p["id"])
        d, e, pol = _defs(p)
        def_dicts |= {x["name"] for x in d if x.get("name")}
        def_engines |= {x["name"] for x in e if x.get("name")}
        def_policies |= {x["name"] for x in pol if x.get("name")}
    # The app's own historical names (packs renamed their objects over
    # time) are always in scope: an object under an old name is DLP-Check's
    # whether one pack or everything is being removed. It is reported as a
    # name-only match for the operator to confirm.
    def_dicts |= LEGACY_NAMES["dictionary"]
    def_engines |= LEGACY_NAMES["engine"]
    def_policies |= LEGACY_NAMES["policy"]

    def any_match(desc: Any, name: str, def_names: set) -> Optional[str]:
        # "Everything" is every object carrying a deploy's tag at the end of
        # its description, whoever deployed it and whether or not its pack is
        # still in the library (pack_deploy._counts: a version or the deploy's
        # sentence), so a customer's own "[x pack y]" never qualifies.
        if everything and pd.has_mark(desc):
            return "tag"
        if any(pd.has_mark(desc, pack_id=pid) for pid in pack_ids):
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
    return _with_rate({
        "status": status, "found": bool(items), "packs": pack_ids, "everything": everything, "items": items,
        "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
        "plan_hash": plan_hash, "warnings": warnings, "blockers": blockers, "read": _read_summary(snap),
    }, client)


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
    return _with_rate({"status": "ready" if to_remove else "nothing", "found": bool(items), "packs": list(record.get("packs") or []),
            "deployment": {"id": record.get("id"), "at": record.get("at"), "tenant_label": record.get("tenant_label"), "packs": record.get("packs")},
            "everything": False, "items": items, "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
            "plan_hash": plan_hash, "warnings": warnings, "blockers": []}, client)


def remove_deployment(client, record: Dict[str, Any], *, plan_hash: str, writes_enabled: Optional[bool] = None,
                      log: pd.LogFn = None, settle_seconds: float = 45.0, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Undo one recorded deployment through the guided path: the plan
    previewed by plan_removal_deployment, tiered deletes with activation,
    then the same read-back verification as a pack removal."""
    return _execute(client, lambda: plan_removal_deployment(client, record),
                    plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds, cancel=cancel)


def _settle(zia, settle_seconds: float, _log) -> Optional[str]:
    """Wait for ZIA to report the activation as ACTIVE (see pc.wait_active)."""
    return pc.wait_active(zia, settle_seconds, _log)


def _users_now(client, kind: str, ids: set, log=None) -> Tuple[Dict[str, str], Optional[str]]:
    """A fresh read of who uses the candidate objects right now: for an
    engine, every DLP rule on every channel that still references it; for
    a dictionary, every engine that still references it. Returns
    ({id: 'rule X (Web DLP), rule Y (Endpoint DLP)'} for the ids in use,
    error-or-None). A read that fails leaves the plan (and ZIA's own
    refusal of anything in use) as the safeguard."""
    _log = log or (lambda m: None)
    users: Dict[str, List[str]] = {}
    try:
        zia = client.zia
        if kind == "engine":
            _log("Checking again which rules still use the engines about to be removed…")
            rules: List[Dict[str, Any]] = []
            web, err = pd._nx(zia.dlp_web_rules.list_rules())
            if err:
                return {}, f"web DLP rules: {str(err)[:120]}"
            rules += [dict(pd_rule_summary(r), channel=pc.WEB) for r in (web or [])]
            state = pc.fetch_channel_state(zia, _all_need())
            for ch, rs in (state.get("rules") or {}).items():
                rules += [dict(r, channel=ch) for r in (rs or [])]
            if state.get("errors"):
                unread = ", ".join(f"{pc.label(ch)} ({e})" for ch, e in state["errors"].items())
                _log(f"Some channels could not be re-read ({unread}); their rules are not part of this check.")
            for r in rules:
                for eid in (r.get("engine_ids") or []):
                    if str(eid) in ids:
                        users.setdefault(str(eid), []).append(f"rule '{r.get('name')}' ({pc.label(r['channel'])})")
        elif kind == "dictionary":
            _log("Checking again which engines still use the dictionaries about to be removed…")
            engines, err = pd._nx(zia.dlp_engine.list_dlp_engines())
            if err:
                return {}, f"engines: {str(err)[:120]}"
            for e in engines or []:
                for did in _engine_dict_ids(e):
                    if did in ids:
                        users.setdefault(did, []).append(f"engine '{pd._field(e, 'name', default='?')}'")
    except Exception as e:  # noqa: BLE001
        return {}, str(e)[:120]
    return {k: ", ".join(v[:3]) + (f" and {len(v) - 3} more" if len(v) > 3 else "") for k, v in users.items()}, None


def pd_rule_summary(r: Any) -> Dict[str, Any]:
    """The few fields of a web DLP rule the usage check needs."""
    return {"id": pd._field(r, "id"), "name": str(pd._field(r, "name", default="") or "").strip(), "engine_ids": pc.engine_ids_of(r)}


# Deletes ZIA refuses for a reason that time clears (edit lock, rate
# limit, an activation in progress) are tried again, up to MAX_PASSES per
# tier, after a wait. Nothing is activated mid-run: a removal activates
# once, at the end. An engine or dictionary still referenced by a rule
# that is only pending deletion stays "in use" until that activation, so
# such a refusal is not retried (a retry cannot succeed, and a run of
# refused requests gets the client blocked): it is reported with the
# advice to run the removal again once this one has activated.
MAX_PASSES = 3
RETRY_BASE_SECONDS = 3.0
_IN_USE_WORDS = ("in use", "referenced", "associated", "being used", "used by")
_RETRYABLE_WORDS = ("in progress", "activation", "pending",
                    "edit lock", "edit_lock", "locked", "rate limit", "too many", "429", "409", "503", "502", "timeout", "timed out",
                    "temporarily", "try again", "ruletype", "rule type")
RUN_AGAIN = ("still in use by a rule this removal deleted; ZIA frees it when this removal's activation is live. "
             "Run the removal again to remove it.")


def _in_use(error: Any) -> bool:
    """A delete refused because a pending-deleted rule still references the object."""
    e = str(error or "").lower()
    return any(w in e for w in _IN_USE_WORDS)


def _retryable(error: Any, http_status: Any = None) -> bool:
    """A delete refusal that a later pass (after an activation and a wait)
    may clear. A 403 is not one: `ops.call` has already answered it with
    five activations and waits, and a 403 still there after that is about
    the client, not the object (`Resource Access Blocked` must not read as
    a lock because of the letters 'lock' in 'blocked')."""
    e = str(error or "").lower()
    if e.startswith("not attempted"):
        return False   # the run has stopped; nothing clears that inside this run
    if http_status == 403 or "resource access blocked" in e or "forbidden" in e:
        return False
    if _in_use(e):
        return False   # only the end-of-run activation clears it
    return any(w in e for w in _RETRYABLE_WORDS)


def _sleep(seconds: float) -> None:
    import time as _t
    if seconds > 0:
        _t.sleep(seconds)


def _all_need() -> Dict[str, Any]:
    need = pc.needs([])
    need["channels"] = set(pc.DLP_CHANNELS)
    need["casb"] = True
    need["endpoint_app_groups"] = True
    return need


def _tag_pack(desc: Any, known: Optional[Iterable[str]] = None) -> Optional[str]:
    """The pack id inside a provenance tag, or None: the tool's own
    "[DLP-Check ..." form, or an assessor's tag for a pack id in `known`
    (the library)."""
    return pd.tag_pack(desc, known=known if known is not None else ())


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
    known = pd.library_ids()
    eng_name = {str(pd._field(e, "id")): n for n, e in engines.items()}
    rules = []
    for r in _tenant_rules(snap):
        desc = r.get("description")
        pack = _tag_pack(desc, known)
        rules.append({"channel": r["channel"], "id": r.get("id"), "name": r.get("name"), "state": r.get("state"),
                      "action": r.get("action"), "parent_id": r.get("parent_id"), "type": r.get("type"),
                      "engine_ids": [str(x) for x in (r.get("engine_ids") or [])],
                      "engines": [eng_name.get(str(x), str(x)) for x in (r.get("engine_ids") or [])],
                      "tagged": pack is not None, "pack": pack})
    order = {ch: i for i, ch in enumerate(pc.DLP_CHANNELS)}
    rules.sort(key=lambda r: (order.get(r["channel"], 9), str(r["name"]).lower()))
    # The dictionary definitions, for whoever needs to explain a match
    # (FP/TP Detection Ratio): custom or predefined, type, confidence, proximity.
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
    # Orphans: custom engines no rule on any channel references, and custom
    # dictionaries no engine references. They cannot be reached through a
    # rule, so the pick screen lists them on their own.
    used_engines = {str(x) for r in rules for x in r["engine_ids"]}
    orphan_engines = []
    for name, e in engines.items():
        eid = str(pd._field(e, "id"))
        if eid in used_engines or pd._field(e, "predefined_engine", default=False) or pd._field(e, "custom_dlp_engine", default=True) is False:
            continue
        pack = _tag_pack(pd._field(e, "description"), known)
        orphan_engines.append({"kind": "engine", "id": pd._field(e, "id"), "name": name, "tagged": pack is not None, "pack": pack,
                               "dictionaries": sorted(n for n, d in (snap.get("dictionaries") or {}).items() if str(pd._field(d, "id")) in _engine_dict_ids(e))})
    used_dicts: set = set()
    for e in engines.values():
        used_dicts |= _engine_dict_ids(e)
    orphan_dicts = []
    for name, d in (snap.get("dictionaries") or {}).items():
        did = str(pd._field(d, "id"))
        if did in used_dicts or not pd._field(d, "custom", "customDictionary", default=False):
            continue
        pack = _tag_pack(pd._field(d, "description"), known)
        orphan_dicts.append({"kind": "dictionary", "id": pd._field(d, "id"), "name": name, "tagged": pack is not None, "pack": pack})
    orphan_engines.sort(key=lambda x: str(x["name"]).lower()); orphan_dicts.sort(key=lambda x: str(x["name"]).lower())
    return {"status": "ready", "rules": rules, "dictionaries": dicts, "orphans": {"engines": orphan_engines, "dictionaries": orphan_dicts},
            "errors": (snap.get("channels") or {}).get("errors") or {}}


def plan_removal_selected(client, selected: Sequence[Dict[str, Any]], *, tenant_cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Preview the removal of the chosen rules ({channel, id} each) and of
    the engines and dictionaries only they use, with the same keep rule
    as a pack removal: an engine a rule outside the selection still uses,
    or a dictionary a surviving engine still uses, is kept. Predefined
    objects are never touched."""
    # A selection is a rule ({channel, id}), or an engine or dictionary
    # picked on its own ({kind: "engine" | "dictionary", id}) for the
    # orphans no rule reaches.
    keys = {(str(x.get("channel") or pc.WEB), str(x.get("id"))) for x in (selected or [])
            if x.get("id") is not None and x.get("kind") not in ("engine", "dictionary")}
    picked_engines = {str(x.get("id")) for x in (selected or []) if x.get("kind") == "engine" and x.get("id") is not None}
    picked_dicts = {str(x.get("id")) for x in (selected or []) if x.get("kind") == "dictionary" and x.get("id") is not None}
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
    seen_engine_ids: set = set()
    for name, e in engines.items():
        eid = str(pd._field(e, "id"))
        if eid not in wanted_engine_ids and eid not in picked_engines:
            continue
        if pd._field(e, "predefined_engine", default=False) or pd._field(e, "custom_dlp_engine", default=True) is False:
            continue   # never a predefined engine
        seen_engine_ids.add(eid)
        item = {"kind": "engine", "channel": None, "id": pd._field(e, "id"), "name": name,
                "match": "selected" if eid in picked_engines else "dependency", "dict_ids": sorted(_engine_dict_ids(e))}
        if eid in engine_ids_used_by_survivors:
            item["keep"] = "still used by a rule you did not select"
        else:
            remove_engine_ids.add(eid)
        engine_items.append(item)
    for eid in sorted(picked_engines - seen_engine_ids):
        warnings.append(f"engine {eid} is no longer in the tenant (or is predefined); skipped.")

    dicts = snap.get("dictionaries") or {}
    wanted_dict_ids = {did for i in engine_items if "keep" not in i for did in i["dict_ids"]}
    dict_ids_used_by_survivors: set = set()
    for name, e in engines.items():
        if str(pd._field(e, "id")) in remove_engine_ids:
            continue
        dict_ids_used_by_survivors |= _engine_dict_ids(e)
    dict_items = []
    seen_dict_ids: set = set()
    for name, d in dicts.items():
        did = str(pd._field(d, "id"))
        if (did not in wanted_dict_ids and did not in picked_dicts) or not pd._field(d, "custom", default=False):
            continue
        seen_dict_ids.add(did)
        item = {"kind": "dictionary", "channel": None, "id": pd._field(d, "id"), "name": name,
                "match": "selected" if did in picked_dicts else "dependency"}
        if did in dict_ids_used_by_survivors:
            item["keep"] = "still used by an engine that stays"
        dict_items.append(item)
    for did in sorted(picked_dicts - seen_dict_ids):
        warnings.append(f"dictionary {did} is no longer in the tenant (or is predefined); skipped.")

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
    return _with_rate({"status": "ready" if to_remove else "nothing", "found": bool(items), "packs": [],
            "selection": sorted(keys) + sorted(("engine", e) for e in picked_engines) + sorted(("dictionary", d) for d in picked_dicts),
            "items": items, "summary": summary, "remove_count": len(to_remove), "keep_count": len(items) - len(to_remove),
            "plan_hash": plan_hash, "warnings": warnings, "blockers": []}, client)


def remove(client, packs: Sequence[Dict[str, Any]], *, plan_hash: str, writes_enabled: Optional[bool] = None,
           log: pd.LogFn = None, settle_seconds: float = 45.0, everything: bool = False,
           cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Execute a removal previewed by plan_removal. Re-reads the tenant,
    verifies the plan_hash still matches, then deletes each object in
    reverse dependency order, re-checking that the id still carries the
    name the plan saw (so a renamed/replaced object is left alone).
    Activates, waits for the activation to settle, then VERIFIES BY
    READING the tenant again: the result's `verification` says whether
    anything of the pack is still there. `cancel` (the operator's Stop)
    and a refusal no later delete can get past stop the remaining deletes;
    the result's `stopped` says why."""
    return _execute(client, lambda: plan_removal(client, packs, everything=everything),
                    plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds, cancel=cancel)


def remove_selected(client, selected: Sequence[Dict[str, Any]], *, plan_hash: str, writes_enabled: Optional[bool] = None,
                    log: pd.LogFn = None, settle_seconds: float = 45.0, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Execute a removal previewed by plan_removal_selected: the chosen
    rules, then the engines and dictionaries only they used."""
    return _execute(client, lambda: plan_removal_selected(client, selected),
                    plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds, cancel=cancel)


def _execute(client, planner, *, plan_hash: str, writes_enabled: Optional[bool], log: pd.LogFn, settle_seconds: float,
             cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Run one removal under pack_ops run control (see pack_deploy.apply),
    on the client's own tenant's ZIA rate limits. Every delete and the
    run's summary go to the audit log (pack_ops.audited_run)."""
    import zia_rate
    with zia_rate.using_client(client), ops.run_scope(cancel), ops.audited_run("removal", client, plan_hash=plan_hash, cancel=cancel) as run:
        run["result"] = _execute_run(client, planner, plan_hash=plan_hash, writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds)
        return run["result"]


def _execute_run(client, planner, *, plan_hash: str, writes_enabled: Optional[bool], log: pd.LogFn, settle_seconds: float) -> Dict[str, Any]:
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
    names_cache: Dict[Tuple[str, Optional[str], str], Tuple[Optional[Dict[str, str]], Optional[str]]] = {}
    recorder = ops.Recorder(log=None, run="remove")   # log lines are written below, with the retry note
    results = recorder.results
    activations: List[Dict[str, Any]] = []

    # Delete in dependency tiers — rules and endpoint application groups
    # first, then engines, then dictionaries (pack_ops.DELETE_TIERS) — and
    # ACTIVATE ONCE, after the last tier. ZIA validates a delete against the
    # saved (activated) config, so an engine or dictionary a pending-deleted
    # rule still references is refused as "in use"; it is reported with the
    # advice to run the removal again after this one's activation.
    TIERS = ops.DELETE_TIERS
    TIER_LABEL = dict(enumerate(ops.TIER_LABELS))
    entries: Dict[Tuple[str, Optional[str], str], Dict[str, Any]] = {}
    final_activation: Optional[Dict[str, Any]] = None   # the last activation issued, whichever tier it followed
    settled_status: Optional[str] = None
    last_sent_tier = "rules"
    sent_any = False               # some delete reached ZIA (a STOPPED run that never sent one activates nothing)

    def attempt(c: Dict[str, Any], entry: Dict[str, Any]) -> bool:
        """One delete of one object, after checking the id still carries the
        name the plan saw. Returns True when the object is gone."""
        kind, channel = c["kind"], c.get("channel") if c["kind"] == "policy" else None
        key = (kind, channel)
        if key not in names_cache:
            names_cache[key] = ops.current_names(zia, kind, channel)
        current, err = names_cache[key]
        if current is None:
            recorder.record(kind, c["name"], "failed", op="delete", channel=c.get("channel"), entry=entry,
                            error=f"could not list the tenant's {kind} objects: {err}")
            return False
        if str(c["id"]) not in current:
            recorder.record(kind, c["name"], "gone", op="delete", channel=c.get("channel"), entry=entry, reason="already removed from the tenant")
            return True
        if current[str(c["id"])] != c["name"]:
            recorder.record(kind, c["name"], "skipped", op="delete", channel=c.get("channel"), entry=entry,
                            reason=f"id {c['id']} now carries the name '{current[str(c['id'])]}', not '{c['name']}'; left alone")
            return True
        out = ops.delete(zia, c, log=_log)
        if not out.ok:
            # A STOPPED outcome is recorded as skipped by the recorder, with the reason.
            recorder.record(kind, c["name"], "failed", op="delete", channel=c.get("channel"), entry=entry, outcome=out)
            return False
        recorder.record(kind, c["name"], "deleted", op="delete", channel=c.get("channel"), entry=entry, outcome=out, id=c["id"])
        current.pop(str(c["id"]), None)
        return True

    for ti, kinds in enumerate(TIERS):
        tier = [c for c in to_remove if c["kind"] in kinds]
        if not tier:
            continue
        # The check before anything goes: right before the engines and the
        # dictionaries, the tenant is read again and anything a rule (or an
        # engine that stays) now uses is left alone and named, whatever the
        # plan said when it was previewed.
        if kinds in (("engine",), ("dictionary",)) and not ops.stop_reason():
            users, read_err = _users_now(client, kinds[0], {str(c["id"]) for c in tier}, log=_log)
            if read_err:
                _log(f"Could not check the {TIER_LABEL[ti]} against the tenant again ({read_err}); relying on the plan and on ZIA's own refusal of anything in use.")
            kept_now = []
            for c in tier:
                who = users.get(str(c["id"]))
                if not who:
                    continue
                entry = {"kind": c["kind"], "name": c["name"], "id": c["id"], "channel": c.get("channel"), "match": c.get("match")}
                entries[(c["kind"], c.get("channel"), str(c["id"]))] = entry
                results.append(entry)
                recorder.record(c["kind"], c["name"], "skipped", op="delete", entry=entry,
                                reason=f"checked again just before removal: still used by {who}; left alone")
                _log(f"[{c['kind']}] {c['name']}: skipped — {entry['reason']}")
                kept_now.append(c)
            if kept_now:
                tier = [c for c in tier if c not in kept_now]
                if not tier:
                    continue
        deleted_here = 0
        pending = list(tier)
        # Up to three passes over the tier: the first straight through, the
        # later ones only for deletes ZIA refused for a reason that time or
        # an activation can clear (still referenced, activation in progress,
        # edit lock, rate limit), after waiting for the tenant to report
        # ACTIVE. Anything else fails once and stays failed.
        for pass_no in range(1, MAX_PASSES + 1):
            retry: List[Dict[str, Any]] = []
            for c in pending:
                ek = (c["kind"], c.get("channel"), str(c["id"]))
                entry = entries.get(ek)
                if entry is None:
                    entry = {"kind": c["kind"], "name": c["name"], "id": c["id"], "channel": c.get("channel"), "match": c.get("match")}
                    entries[ek] = entry; results.append(entry)
                ok = attempt(c, entry)
                if ok and entry["status"] == "deleted":
                    deleted_here += 1
                elif not ok and _retryable(entry.get("error"), entry.get("http_status")):
                    entry["attempts"] = pass_no
                    if c.get("channel") == pc.SAAS:
                        # The SaaS delete is refused without the rule's type; read it fresh for the next try.
                        fresh = pc.saas_rule_type(zia, c["id"])
                        if fresh:
                            c["type"] = fresh
                    retry.append(c)
                _log(f"[{entry['kind']}] {entry['name']}: {entry['status']}" + (f" — {entry.get('error') or entry.get('reason')}" if entry.get('error') or entry.get('reason') else "")
                     + (f" (will retry after the tenant settles, pass {pass_no} of {MAX_PASSES})" if c in retry else ""))
            if not retry or pass_no == MAX_PASSES or ops.stop_reason():
                break
            # Give ZIA time to finish what it is doing before the next pass.
            _log(f"{len(retry)} {TIER_LABEL[ti]} refused for now; waiting {RETRY_BASE_SECONDS * pass_no:.0f}s and trying again "
                 "(nothing is activated until the removal is done)…")
            _sleep(RETRY_BASE_SECONDS * pass_no)
            names_cache.clear()
            pending = retry
        # No activation between tiers: the removal activates once, below.
        more = any(c["kind"] in k for k in TIERS[ti + 1:] for c in to_remove)
        # A delete that reached ZIA (deleted, or refused by ZIA) is what an
        # activation follows; a call the run stopped before sending is not.
        sent_here = sum(1 for c in tier if entries.get((c["kind"], c.get("channel"), str(c["id"])), {}).get("status") in ("deleted", "failed"))
        if sent_here:
            sent_any = True
        if ops.stop_reason():
            # Say what was never tried, then finish the bookkeeping below.
            for c in to_remove:
                if (c["kind"], c.get("channel"), str(c["id"])) not in entries:
                    entry = {"kind": c["kind"], "name": c["name"], "id": c["id"], "channel": c.get("channel"), "match": c.get("match")}
                    entries[(c["kind"], c.get("channel"), str(c["id"]))] = entry
                    results.append(entry)
                    recorder.record(c["kind"], c["name"], "skipped", op="delete", channel=c.get("channel"), entry=entry,
                                    reason=f"not attempted: {ops.stop_reason()}")
            break
        last_sent_tier = TIER_LABEL[ti] if sent_here else last_sent_tier

    # The one activation of the removal, after the last tier, whatever its
    # deletes returned, so every deletion goes live together; then wait for
    # ZIA to report ACTIVE (an activation is not instantaneous). A run that
    # sent no delete activates nothing.
    if sent_any:
        _log(f"Every tier done; activating once and waiting for ZIA to report ACTIVE…")
        act = ops.activate_once(zia, _log)
        final_activation = dict(act, after=last_sent_tier)
        activations.append(final_activation)
        _log("Activation " + ("done." if act.get("activated") else f"could not run: {act.get('error')}"))
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
            names_cache[key] = ops.current_names(zia, entry["kind"], entry.get("channel"))
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

    run_again = [r for r in results if r["status"] == "failed" and _in_use(r.get("error"))]
    for r in run_again:
        r["reason"] = RUN_AGAIN
    if run_again:
        _log(f"{len(run_again)} object(s) were still in use by rules this removal deleted; run the removal again now that it has activated.")
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    complete = verification["clean"] and not counts.get("failed") and not counts.get("skipped") and not counts.get("still_present")
    status = "removed" if complete and results else ("partial" if counts.get("deleted") else ("nothing" if not results else "failed"))
    return {"status": status, "summary": counts, "results": results, "events": recorder.events, "complete": complete,
            "kept": [it for it in plan["items"] if it["status"] == "keep"],
            "gone": [it for it in plan["items"] if it["status"] == "not-found"],
            "verification": verification,
            "activation": final_activation, "activations": activations,
            "activation_required": bool(counts.get("deleted")) and not (final_activation and final_activation.get("activated")),
            # Engines / dictionaries refused as in use: run the removal again to finish.
            "run_again": bool(run_again),
            # Why the run stopped deleting before the end (None when it ran through).
            "stopped": ops.stop_reason()}
