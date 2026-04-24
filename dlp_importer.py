#!/usr/bin/env python3
"""
DLP Policy Pack Importer — general-purpose library
====================================================
Imports DLP dictionaries (custom + clones), engines, and policies from
any pack directory containing JSON definition files. The pack layout:

    <pack_dir>/
      configs/
        dlp_dictionaries.json   (optional)
        dlp_engines.json        (optional)
        dlp_policies.json       (optional)
      pack.json                 (optional — metadata: name, version, description)

Or flat layout (JSON files directly in pack_dir):

    <pack_dir>/
      dlp_dictionaries.json
      dlp_engines.json
      dlp_policies.json

All functions accept a `pack_dir` path and a ZIA client instance.
They return structured dicts instead of printing, so the web GUI and
API server can stream progress to the frontend.

The fed_policy_pack/ directory ships as a built-in pack; users can
drop additional pack directories alongside it or upload zips via the
web GUI.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nx(ret):
    if not isinstance(ret, tuple):
        return ret, None
    if len(ret) == 1:
        return ret[0], None
    return ret[0], ret[-1]


def _obj_to_dict(obj):
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "as_dict"):
        return obj.as_dict()
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return obj


def _extract_id(response):
    if response and isinstance(response, tuple) and response[0] is not None:
        first = response[0]
        return first.id if hasattr(first, "id") else _obj_to_dict(first).get("id")
    return None


def _extract_error(response):
    if not response:
        return "No response"
    if isinstance(response, tuple) and len(response) > 2 and response[2]:
        err = response[2]
        if isinstance(err, dict):
            return err.get("message", str(err))
        return str(err)
    return "Unknown error"


# ---------------------------------------------------------------------------
# Pack discovery
# ---------------------------------------------------------------------------

PACKS_ROOT = os.path.dirname(os.path.abspath(__file__))


def _resolve_configs(pack_dir: str) -> str:
    """Return the directory containing the JSON files. Supports both
    <pack>/configs/ layout and flat layout."""
    configs = os.path.join(pack_dir, "configs")
    if os.path.isdir(configs):
        return configs
    return pack_dir


def _load_json(configs_dir: str, filename: str) -> List[Dict[str, Any]]:
    path = os.path.join(configs_dir, filename)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_pack_metadata(pack_dir: str) -> Dict[str, Any]:
    """Load pack.json if present, else infer metadata from dir name."""
    meta_path = os.path.join(pack_dir, "pack.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    configs = _resolve_configs(pack_dir)
    dicts = _load_json(configs, "dlp_dictionaries.json")
    engines = _load_json(configs, "dlp_engines.json")
    policies = _load_json(configs, "dlp_policies.json")
    return {
        "name": os.path.basename(pack_dir).replace("_", " ").title(),
        "dir": pack_dir,
        "dictionaries": len(dicts),
        "engines": len(engines),
        "policies": len(policies),
    }


def discover_packs(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan the project root for directories that look like DLP packs
    (contain configs/dlp_*.json or dlp_*.json at top level)."""
    root = root or PACKS_ROOT
    packs = []
    for entry in sorted(os.listdir(root)):
        d = os.path.join(root, entry)
        if not os.path.isdir(d):
            continue
        configs = _resolve_configs(d)
        has_json = any(
            f.startswith("dlp_") and f.endswith(".json")
            for f in os.listdir(configs)
        ) if os.path.isdir(configs) else False
        if has_json:
            meta = load_pack_metadata(d)
            meta["dir"] = d
            meta["id"] = entry
            packs.append(meta)
    return packs


def load_pack_contents(pack_dir: str) -> Dict[str, Any]:
    """Load all three config files from a pack and return summary."""
    configs = _resolve_configs(pack_dir)
    dicts = _load_json(configs, "dlp_dictionaries.json")
    engines = _load_json(configs, "dlp_engines.json")
    policies = _load_json(configs, "dlp_policies.json")

    clone_count = sum(1 for d in dicts if d.get("predefined_clone"))
    return {
        "pack_dir": pack_dir,
        "metadata": load_pack_metadata(pack_dir),
        "dictionaries": {
            "total": len(dicts),
            "custom": len(dicts) - clone_count,
            "clones": clone_count,
            "items": [
                {
                    "name": d["name"],
                    "type": "clone" if d.get("predefined_clone") else "custom",
                    "patterns": len(d.get("patterns", [])),
                    "phrases": len(d.get("phrases", [])),
                    "proximity": d.get("proximity", 0),
                }
                for d in dicts
            ],
        },
        "engines": {
            "total": len(engines),
            "items": [{"name": e["name"]} for e in engines],
        },
        "policies": {
            "total": len(policies),
            "items": [
                {
                    "name": p["name"],
                    "action": p.get("action", "?"),
                    "severity": p.get("severity", "?"),
                    "engines": p.get("engines", []),
                }
                for p in policies
            ],
        },
    }


# ---------------------------------------------------------------------------
# Import operations — each returns a structured result dict and calls an
# optional `on_progress(msg: str)` callback for live streaming.
# ---------------------------------------------------------------------------

LogFn = Optional[Callable[[str], None]]


def import_dictionaries(
    zia, pack_dir: str, *, log: LogFn = None
) -> Dict[str, Any]:
    """Phase 1: create missing dictionaries (custom + clones)."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    desired = _load_json(configs, "dlp_dictionaries.json")
    if not desired:
        return {"phase": "dictionaries", "status": "skipped", "reason": "no file"}

    _log(f"Loaded {len(desired)} dictionary definitions")

    existing_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        return {"phase": "dictionaries", "status": "error", "error": str(err)}

    existing_names: Dict[str, int] = {}
    predefined_name_to_id: Dict[str, int] = {}
    for d in existing_dicts:
        dd = _obj_to_dict(d)
        name = dd.get("name", "").strip()
        existing_names[name] = dd.get("id")
        if not dd.get("custom", False):
            predefined_name_to_id[name] = dd.get("id")

    missing = [d for d in desired if d["name"].strip() not in existing_names]
    if not missing:
        _log("All dictionaries already exist")
        return {"phase": "dictionaries", "status": "ok", "created": 0, "skipped": 0, "failed": 0, "total": len(desired)}

    _log(f"Creating {len(missing)} missing dictionaries")
    created, failed, skipped = 0, 0, 0
    details: List[Dict[str, Any]] = []

    for d in missing:
        is_clone = d.get("predefined_clone", False)
        name = d["name"]
        try:
            if is_clone:
                template_id = d.get("dict_template_id")
                template_name = d.get("dict_template_name")
                if not template_id and template_name:
                    template_id = predefined_name_to_id.get(template_name)
                if not template_id:
                    failed += 1
                    details.append({"name": name, "status": "failed", "error": f"No template ID for '{template_name}'"})
                    continue
                kwargs = {"description": d.get("description", ""), "dict_template_id": int(template_id), "custom": True}
            else:
                has_patterns = bool(d.get("patterns"))
                has_phrases = bool(d.get("phrases"))
                if not has_patterns and not has_phrases:
                    skipped += 1
                    details.append({"name": name, "status": "skipped", "reason": "no patterns/phrases"})
                    continue
                kwargs = {"description": d.get("description", "")}

            for opt in ("confidence_threshold", "confidence_level_for_predefined_dict", "hierarchical_identifiers"):
                if d.get(opt):
                    kwargs[opt] = d[opt]
            for flag in ("include_bin_numbers", "include_ssn_numbers"):
                if d.get(flag):
                    kwargs[flag] = True

            proximity = d.get("proximity") or 0
            if proximity > 0:
                kwargs["proximity"] = proximity
                kwargs["proximity_length_enabled"] = True
                if not is_clone:
                    kwargs["proximity_enabled_for_custom_dictionary"] = True

            if d.get("patterns"):
                kwargs["patterns"] = [(p["action"], p["pattern"]) for p in d["patterns"]]
            if d.get("phrases"):
                kwargs["phrases"] = [(p["action"], p["phrase"]) for p in d["phrases"]]

            response = zia.dlp_dictionary.add_dict(
                name, d["custom_phrase_match_type"], "PATTERNS_AND_PHRASES", **kwargs
            )
            new_id = _extract_id(response)
            if new_id:
                created += 1
                details.append({"name": name, "status": "created", "id": new_id})
                _log(f"  Created: {name} (ID {new_id})")
            else:
                failed += 1
                details.append({"name": name, "status": "failed", "error": _extract_error(response)})
        except Exception as e:
            failed += 1
            details.append({"name": name, "status": "failed", "error": str(e)[:200]})

    _log(f"Dictionaries: {created} created, {skipped} skipped, {failed} failed")
    return {"phase": "dictionaries", "status": "ok", "created": created, "skipped": skipped, "failed": failed, "total": len(desired), "details": details}


def import_engines(
    zia, pack_dir: str, *, log: LogFn = None
) -> Dict[str, Any]:
    """Phase 2: create missing engines, resolving D:name → D<id>.S."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    desired = _load_json(configs, "dlp_engines.json")
    if not desired:
        return {"phase": "engines", "status": "skipped", "reason": "no file"}

    _log(f"Loaded {len(desired)} engine definitions")

    existing_engines, err = _nx(zia.dlp_engine.list_dlp_engines_lite())
    if err:
        return {"phase": "engines", "status": "error", "error": str(err)}
    existing_names = {e.name.strip() for e in existing_engines if e.name}

    missing = [e for e in desired if e["name"].strip() not in existing_names]
    if not missing:
        _log("All engines already exist")
        return {"phase": "engines", "status": "ok", "created": 0, "failed": 0, "total": len(desired)}

    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        return {"phase": "engines", "status": "error", "error": f"Could not fetch dictionaries: {err}"}
    dict_name_to_id = {_obj_to_dict(d).get("name", "").strip(): _obj_to_dict(d).get("id") for d in all_dicts}

    _log(f"Creating {len(missing)} missing engines")
    created, failed = 0, 0
    details: List[Dict[str, Any]] = []

    sorted_names = sorted(dict_name_to_id.keys(), key=len, reverse=True)
    for engine_def in missing:
        name = engine_def["name"]
        try:
            expr = engine_def["expression"]
            for dict_name in sorted_names:
                placeholder = f"D:{dict_name}"
                if placeholder in expr:
                    expr = expr.replace(placeholder, f"D{dict_name_to_id[dict_name]}.S")

            unresolved = re.findall(r"D:[^D\d][^&|>)]*", expr)
            response = zia.dlp_engine.add_dlp_engine(
                name=name,
                engine_expression=expr,
                custom_dlp_engine=True,
                description=engine_def.get("description", "Imported engine"),
            )
            new_id = _extract_id(response)
            if new_id:
                created += 1
                detail = {"name": name, "status": "created", "id": new_id}
                if unresolved:
                    detail["warnings"] = [f"Unresolved: {u}" for u in unresolved]
                details.append(detail)
                _log(f"  Created: {name} (ID {new_id})")
            else:
                failed += 1
                details.append({"name": name, "status": "failed", "error": _extract_error(response)})
        except Exception as e:
            failed += 1
            details.append({"name": name, "status": "failed", "error": str(e)[:200]})

    _log(f"Engines: {created} created, {failed} failed")
    return {"phase": "engines", "status": "ok", "created": created, "failed": failed, "total": len(desired), "details": details}


def import_policies(
    client, pack_dir: str, *, use_rank_0: bool = False, log: LogFn = None
) -> Dict[str, Any]:
    """Phase 3: create missing DLP web rules."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    desired = _load_json(configs, "dlp_policies.json")
    if not desired:
        return {"phase": "policies", "status": "skipped", "reason": "no file"}

    _log(f"Loaded {len(desired)} policy definitions")

    existing_rules, err = _nx(client.zia.dlp_web_rules.list_rules())
    if err:
        return {"phase": "policies", "status": "error", "error": str(err)}
    existing_names = {r.name.strip() for r in existing_rules if r.name}

    missing = [p for p in desired if p["name"].strip() not in existing_names]
    if not missing:
        _log("All policies already exist")
        return {"phase": "policies", "status": "ok", "created": 0, "failed": 0, "total": len(desired)}

    all_engines, err = _nx(client.zia.dlp_engine.list_dlp_engines_lite())
    if err:
        return {"phase": "policies", "status": "error", "error": f"Could not fetch engines: {err}"}
    engine_name_to_id = {e.name.strip(): e.id for e in all_engines if e.name}

    _log(f"Creating {len(missing)} missing policies")
    created, failed = 0, 0
    details: List[Dict[str, Any]] = []

    for policy_def in missing:
        name = policy_def["name"]
        try:
            engine_names = policy_def.get("engines", [])
            engine_ids = [engine_name_to_id[n] for n in engine_names if n in engine_name_to_id]
            if not engine_ids:
                failed += 1
                details.append({"name": name, "status": "failed", "error": "No valid engines found"})
                continue

            payload: Dict[str, Any] = {
                "name": name,
                "order": "1",
                "state": policy_def.get("state", "ENABLED"),
                "action": policy_def.get("action", "ALLOW"),
                "dlp_engines": engine_ids,
                "protocols": policy_def.get("protocols", ["ANY_RULE"]),
                "rank": 0 if use_rank_0 else policy_def.get("rank", 7),
            }
            for opt in ("description", "severity", "min_size", "file_types", "cloud_applications"):
                if policy_def.get(opt):
                    payload[opt] = policy_def[opt]
            for field in ("locations", "location_groups", "groups", "departments", "users", "url_categories", "labels"):
                if policy_def.get(field):
                    payload[field] = policy_def[field]
            for flag in ("match_only", "without_content_inspection"):
                if policy_def.get(flag):
                    payload[flag] = True

            response = client.zia.dlp_web_rules.add_rule(**payload)
            new_id = _extract_id(response)
            if new_id:
                created += 1
                details.append({"name": name, "status": "created", "id": new_id})
                _log(f"  Created: {name} (ID {new_id})")
            else:
                failed += 1
                details.append({"name": name, "status": "failed", "error": _extract_error(response)})
        except Exception as e:
            failed += 1
            details.append({"name": name, "status": "failed", "error": str(e)[:200]})

    _log(f"Policies: {created} created, {failed} failed")
    return {"phase": "policies", "status": "ok", "created": created, "failed": failed, "total": len(desired), "details": details}


# ---------------------------------------------------------------------------
# Verification — compares deployed state against the pack's JSON definitions
# ---------------------------------------------------------------------------

def verify_deployment(
    zia, pack_dir: str, *, log: LogFn = None
) -> Dict[str, Any]:
    """Compare deployed dictionaries + engines against the pack's JSON files."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    result: Dict[str, Any] = {"phase": "verify", "dictionaries": {}, "engines": {}, "all_good": True}

    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    deployed_map = {_obj_to_dict(d).get("name", "").strip(): _obj_to_dict(d) for d in all_dicts} if not err else {}

    all_engines, err = _nx(zia.dlp_engine.list_dlp_engines_lite())
    deployed_engine_names = {e.name.strip() for e in all_engines if e.name} if not err else set()

    # Dictionary verification
    desired_dicts = _load_json(configs, "dlp_dictionaries.json")
    missing_dicts: List[str] = []
    mismatched: Dict[str, List[str]] = {}

    def _extract_items(item_list, key_name):
        out = set()
        if not item_list:
            return out
        for item in item_list:
            item_d = item if isinstance(item, dict) else _obj_to_dict(item)
            out.add((item_d.get("action", ""), item_d.get(key_name, "")))
        return out

    for d_json in desired_dicts:
        dname = d_json["name"].strip()
        if dname not in deployed_map:
            missing_dicts.append(dname)
            continue
        dd = deployed_map[dname]
        issues = []
        exp_prox = d_json.get("proximity") or 0
        act_prox = dd.get("proximity") or 0
        if exp_prox != act_prox:
            issues.append(f"Proximity mismatch (expected {exp_prox}, got {act_prox})")
        if exp_prox > 0:
            if not dd.get("proximity_length_enabled", dd.get("proximityLengthEnabled", False)):
                issues.append("proximity_length_enabled missing")
            if not d_json.get("predefined_clone") and not dd.get(
                "proximity_enabled_for_custom_dictionary",
                dd.get("proximityEnabledForCustomDictionary", False),
            ):
                issues.append("custom proximity flag missing")
        if _extract_items(d_json.get("patterns", []), "pattern") != _extract_items(dd.get("patterns", []), "pattern"):
            issues.append("Pattern content mismatch")
        if _extract_items(d_json.get("phrases", []), "phrase") != _extract_items(dd.get("phrases", []), "phrase"):
            issues.append("Phrase content mismatch")
        if issues:
            mismatched[dname] = issues

    result["dictionaries"] = {"missing": missing_dicts, "mismatched": mismatched, "total": len(desired_dicts), "ok": len(desired_dicts) - len(missing_dicts) - len(mismatched)}

    # Engine verification
    desired_engines = _load_json(configs, "dlp_engines.json")
    desired_engine_names = {e["name"].strip() for e in desired_engines}
    missing_engines = sorted(desired_engine_names - deployed_engine_names)
    result["engines"] = {"missing": missing_engines, "total": len(desired_engines), "ok": len(desired_engines) - len(missing_engines)}

    result["all_good"] = not missing_dicts and not mismatched and not missing_engines
    _log("Verification passed" if result["all_good"] else "Verification found issues")
    return result


# ---------------------------------------------------------------------------
# Post-import confidence tweaks (generic — driven by pack.json or defaults)
# ---------------------------------------------------------------------------

DEFAULT_CONFIDENCE_TWEAKS = [
    {"name": "MEDICAL", "target_confidence": "CONFIDENCE_LEVEL_LOW", "label": "Medical → Low confidence"},
    {"name_patterns": ["Financial Document", "Financial Documents", "FINANCIAL_DOCUMENT", "FINANCIAL_DOCUMENTS", "FINANCIAL"],
     "target_confidence": "CONFIDENCE_LEVEL_HIGH", "label": "Financial → High confidence"},
]


def apply_confidence_tweaks(
    zia, tweaks: Optional[List[Dict[str, Any]]] = None, *, log: LogFn = None
) -> List[Dict[str, Any]]:
    """Apply confidence-level overrides to named dictionaries.
    Tweaks can come from pack.json's "confidence_tweaks" key or from
    the DEFAULT_CONFIDENCE_TWEAKS fallback."""
    _log = log or (lambda m: None)
    tweaks = tweaks or DEFAULT_CONFIDENCE_TWEAKS
    if not tweaks:
        return []

    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        return [{"status": "error", "error": str(err)}]
    dict_map = {_obj_to_dict(d).get("name", "").strip(): _obj_to_dict(d) for d in all_dicts}

    results = []
    for tweak in tweaks:
        candidates = tweak.get("name_patterns") or ([tweak["name"]] if tweak.get("name") else [])
        match = next((dict_map[n] for n in candidates if n in dict_map), None)
        if not match:
            results.append({"label": tweak.get("label", "?"), "status": "not_found"})
            continue
        mid = match.get("id")
        mname = match.get("name")
        try:
            _, _, err2 = zia.dlp_dictionary.update_dict(
                mid,
                name=mname,
                dictionary_type=match.get("dictionary_type", "PATTERNS_AND_PHRASES"),
                custom_phrase_match_type=match.get("custom_phrase_match_type", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"),
                confidence_threshold=tweak["target_confidence"],
            )
            if err2:
                results.append({"label": tweak.get("label", mname), "status": "failed", "error": str(err2)})
            else:
                results.append({"label": tweak.get("label", mname), "status": "applied", "id": mid})
                _log(f"  Applied: {tweak.get('label', mname)}")
        except Exception as e:
            results.append({"label": tweak.get("label", mname), "status": "failed", "error": str(e)[:200]})
    return results


# ---------------------------------------------------------------------------
# Full import — orchestrates all phases
# ---------------------------------------------------------------------------

def run_full_import(
    client,
    pack_dir: str,
    *,
    use_rank_0: bool = False,
    apply_tweaks: bool = True,
    verify: bool = True,
    log: LogFn = None,
) -> Dict[str, Any]:
    """Run the complete 5-phase import pipeline for any DLP pack."""
    _log = log or (lambda m: None)
    started = time.time()
    results: Dict[str, Any] = {"pack_dir": pack_dir, "phases": {}}

    meta = load_pack_metadata(pack_dir)
    _log(f"Importing pack: {meta.get('name', pack_dir)}")

    # Phase 1
    _log("Phase 1: Dictionaries")
    results["phases"]["dictionaries"] = import_dictionaries(client.zia, pack_dir, log=log)

    # Phase 2
    _log("Phase 2: Engines")
    results["phases"]["engines"] = import_engines(client.zia, pack_dir, log=log)

    # Phase 3
    _log("Phase 3: Policies")
    results["phases"]["policies"] = import_policies(client, pack_dir, use_rank_0=use_rank_0, log=log)

    # Phase 4 — confidence tweaks (pack-specific or defaults)
    if apply_tweaks:
        _log("Phase 4: Confidence tweaks")
        pack_tweaks = meta.get("confidence_tweaks")
        results["phases"]["tweaks"] = apply_confidence_tweaks(client.zia, pack_tweaks, log=log)

    # Phase 5 — verification
    if verify:
        _log("Phase 5: Verification")
        results["phases"]["verify"] = verify_deployment(client.zia, pack_dir, log=log)

    results["elapsed_seconds"] = round(time.time() - started, 2)
    results["metadata"] = meta
    return results
