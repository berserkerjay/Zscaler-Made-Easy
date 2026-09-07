#!/usr/bin/env python3
"""
DLP Policy Pack Deployment Planner
==================================
Turns "import this pack" into a guided, safe deployment of ONE OR MORE
packs at once:

  preflight()  Read the tenant, merge the selected packs, and produce a
               plan that says — per dictionary / engine / policy — whether
               it will be created, reused as-is from the tenant, blocked,
               or would modify existing tenant configuration. Nothing is
               written.
  apply()      Re-run the preflight, refuse to proceed if the tenant or
               the selection changed since the user approved the plan
               (plan_hash mismatch), then execute the plan in dependency
               order. Blocked items are skipped, never half-applied, and
               one failure never stops the others.

Cross-referencing performed by preflight
----------------------------------------
* Cross-pack conflicts — the same name defined differently in two
  selected packs. Blocked: we can't know which one the admin meant.
* Identical duplicates across packs are collapsed into one item.
* Dependency resolution — engine `D:<dictionary>` references and policy
  engine references must resolve to something in the selected packs or
  already in the tenant (predefined dictionaries count). Clone
  dictionaries need their predefined template to exist in the tenant.
  Anything unresolved is blocked, and the block cascades to dependents.
* Tenant overlap — an object with the same name already in the tenant
  is REUSED (the importer never overwrites). If its content differs
  from the pack definition that is surfaced as a warning, because
  everything downstream will run against the tenant's version, not the
  pack's.
* Impact analysis — new web DLP rules are inserted at order 1 and push
  every existing rule down; the API caps web DLP rules at 127; policies
  whose action enforces (BLOCK / CONFIRM / ICAP_RESPONSE) rather than
  monitors are called out; confidence tweaks that would MODIFY an
  existing tenant dictionary are listed as explicit modifications; and
  ZIA changes always need activation afterwards.

The report is plain data (dicts/lists) so the GUI can render it and the
API can return it verbatim. `plan_hash` binds an approval to exactly the
plan the user saw.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from dlp_importer import (
    EMPTY_DICT_REASON,
    _extract_error,
    _extract_id,
    _load_json,
    _nx,
    _obj_to_dict,
    _resolve_configs,
    build_dict_kwargs,
    build_policy_payload,
    engine_references,
    load_pack_metadata,
    resolve_engine_expression,
    verify_deployment,
    DEFAULT_CONFIDENCE_TWEAKS,
)

# Documented limit for rules created through the API (see the zia_dlp_web_rules
# provider docs). Exceeding it fails at apply time, so we block up front.
WEB_DLP_RULE_API_CAP = 127

# Web DLP rule actions that enforce rather than observe. A pack shipping any
# of these is flagged so a monitor-first rollout is a deliberate choice.
ENFORCING_ACTIONS = {"BLOCK", "CONFIRM", "ICAP_RESPONSE"}

# Item statuses. Everything the GUI needs to explain is keyed off these.
CREATE = "create"                        # new object, will be created
REUSE = "reuse"                          # exists in tenant with identical content
REUSE_DIFFERS = "reuse_differs"          # exists in tenant with DIFFERENT content — tenant version kept
CONFLICT = "conflict"                    # defined differently in two selected packs
BLOCKED_DEPENDENCY = "blocked_dependency"  # needs something that is missing or blocked
SKIP_EMPTY = "skip_empty"                # custom dictionary with nothing to match on
MODIFY = "modify"                        # will change an existing tenant object (tweaks)
NOOP = "noop"                            # tweak whose target is already at the desired value

BLOCKING_STATUSES = {CONFLICT, BLOCKED_DEPENDENCY, SKIP_EMPTY}
AVAILABLE_STATUSES = {CREATE, REUSE, REUSE_DIFFERS}

LogFn = Optional[Callable[[str], None]]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _field(obj: Any, *keys: str, default: Any = None) -> Any:
    """Read a field from an SDK object or dict, trying snake_case and
    camelCase spellings. The SDK returns both depending on the call."""
    d = obj if isinstance(obj, dict) else _obj_to_dict(obj)
    if isinstance(d, dict):
        for k in keys:
            if k in d and d[k] is not None:
                return d[k]
    for k in keys:
        v = getattr(obj, k, None)
        if v is not None:
            return v
    return default


def _items_set(items: Optional[Iterable[Any]], key: str) -> List[List[str]]:
    out: Set[Tuple[str, str]] = set()
    for item in items or []:
        d = item if isinstance(item, dict) else _obj_to_dict(item)
        if not isinstance(d, dict):
            continue
        out.add((str(d.get("action", "")), str(d.get(key, ""))))
    return sorted([list(t) for t in out])


def _norm_expr(expr: str) -> str:
    return "".join((expr or "").split())


# ---------------------------------------------------------------------------
# Pack loading + merging
# ---------------------------------------------------------------------------

def load_sources(packs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Load every selected pack. `packs` items need `id` and `dir`."""
    sources = []
    for p in packs:
        configs = _resolve_configs(p["dir"])
        meta = load_pack_metadata(p["dir"])
        sources.append({
            "id": p["id"],
            "name": meta.get("name", p["id"]),
            "dir": p["dir"],
            "dictionaries": _load_json(configs, "dlp_dictionaries.json"),
            "engines": _load_json(configs, "dlp_engines.json"),
            "policies": _load_json(configs, "dlp_policies.json"),
            "tweaks": meta.get("confidence_tweaks"),
        })
    return sources


def dict_signature(d: Dict[str, Any], predefined_name_to_id: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Content-only view of a pack dictionary, used to compare packs with
    each other and with the tenant."""
    predefined_name_to_id = predefined_name_to_id or {}
    if d.get("predefined_clone"):
        template = d.get("dict_template_id") or predefined_name_to_id.get(d.get("dict_template_name", ""), d.get("dict_template_name"))
        return {
            "kind": "clone",
            "template": str(template) if template is not None else None,
            "proximity": int(d.get("proximity") or 0),
            "confidence": d.get("confidence_level_for_predefined_dict") or d.get("confidence_threshold"),
        }
    return {
        "kind": "custom",
        "match": d.get("custom_phrase_match_type"),
        "patterns": _items_set(d.get("patterns"), "pattern"),
        "phrases": _items_set(d.get("phrases"), "phrase"),
        "proximity": int(d.get("proximity") or 0),
        "confidence": d.get("confidence_threshold"),
    }


def tenant_dict_signature(t: Any) -> Optional[Dict[str, Any]]:
    """Same shape as dict_signature() but built from a tenant object.
    Returns None when the tenant payload is too thin to compare."""
    template = _field(t, "dict_template_id", "dictTemplateId")
    patterns = _field(t, "patterns")
    phrases = _field(t, "phrases")
    if template:
        return {
            "kind": "clone",
            "template": str(template),
            "proximity": int(_field(t, "proximity", default=0) or 0),
            "confidence": _field(t, "confidence_level_for_predefined_dict", "confidenceLevelForPredefinedDict")
            or _field(t, "confidence_threshold", "confidenceThreshold"),
        }
    if patterns is None and phrases is None:
        return None
    return {
        "kind": "custom",
        "match": _field(t, "custom_phrase_match_type", "customPhraseMatchType"),
        "patterns": _items_set(patterns, "pattern"),
        "phrases": _items_set(phrases, "phrase"),
        "proximity": int(_field(t, "proximity", default=0) or 0),
        "confidence": _field(t, "confidence_threshold", "confidenceThreshold"),
    }


def policy_signature(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action": p.get("action", "ALLOW"),
        "state": p.get("state", "ENABLED"),
        "engines": sorted(p.get("engines", [])),
        "protocols": sorted(p.get("protocols", ["ANY_RULE"])),
        "severity": p.get("severity"),
        "rank": p.get("rank", 7),
    }


def merge_sources(sources: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Merge all packs into name-keyed maps per kind, recording provenance
    and flagging cross-pack conflicts."""
    merged: Dict[str, Dict[str, Dict[str, Any]]] = {"dictionary": {}, "engine": {}, "policy": {}}
    sig_fns = {
        "dictionary": lambda d: _canonical(dict_signature(d)),
        "engine": lambda e: _norm_expr(e.get("expression", "")),
        "policy": lambda p: _canonical(policy_signature(p)),
    }
    for src in sources:
        for kind, key in (("dictionary", "dictionaries"), ("engine", "engines"), ("policy", "policies")):
            for definition in src[key]:
                name = (definition.get("name") or "").strip()
                if not name:
                    continue
                sig = sig_fns[kind](definition)
                existing = merged[kind].get(name)
                if existing is None:
                    merged[kind][name] = {
                        "kind": kind, "name": name, "definition": definition,
                        "packs": [src["id"]], "signature": sig, "status": None,
                        "reason": "", "warnings": [], "depends_on": [], "tenant": None,
                    }
                elif existing["signature"] == sig:
                    existing["packs"].append(src["id"])
                else:
                    existing["packs"].append(src["id"])
                    existing["status"] = CONFLICT
                    existing["reason"] = (
                        f"Defined differently in packs {', '.join(existing['packs'])}. "
                        "Deselect one of them or align the definitions."
                    )
    return merged


# ---------------------------------------------------------------------------
# Tenant snapshot
# ---------------------------------------------------------------------------

def fetch_tenant(client) -> Dict[str, Any]:
    """Read everything the plan needs from the tenant in three calls.
    Never raises: each failure is recorded and `reachable` reflects it."""
    snap: Dict[str, Any] = {
        "reachable": True, "errors": [],
        "dictionaries": {}, "predefined": {}, "engines": {}, "rules": [],
    }
    zia = client.zia
    try:
        dicts, err = _nx(zia.dlp_dictionary.list_dicts())
        if err:
            raise RuntimeError(str(err))
        for d in dicts or []:
            name = str(_field(d, "name", default="") or "").strip()
            if not name:
                continue
            snap["dictionaries"][name] = d
            if not _field(d, "custom", default=False):
                snap["predefined"][name] = _field(d, "id")
    except Exception as e:  # noqa: BLE001 — surfaced to the user, not hidden
        snap["reachable"] = False
        snap["errors"].append(f"dictionaries: {str(e)[:200]}")

    try:
        lister = getattr(zia.dlp_engine, "list_dlp_engines", None) or zia.dlp_engine.list_dlp_engines_lite
        engines, err = _nx(lister())
        if err:
            raise RuntimeError(str(err))
        for e in engines or []:
            name = str(_field(e, "name", default="") or "").strip()
            if name:
                snap["engines"][name] = e
    except Exception as e:  # noqa: BLE001
        snap["reachable"] = False
        snap["errors"].append(f"engines: {str(e)[:200]}")

    try:
        rules, err = _nx(zia.dlp_web_rules.list_rules())
        if err:
            raise RuntimeError(str(err))
        for r in rules or []:
            snap["rules"].append({
                "id": _field(r, "id"),
                "name": str(_field(r, "name", default="") or "").strip(),
                "order": int(_field(r, "order", default=0) or 0),
                "rank": _field(r, "rank"),
                "action": _field(r, "action"),
                "state": _field(r, "state"),
            })
        snap["rules"].sort(key=lambda r: r["order"])
    except Exception as e:  # noqa: BLE001
        snap["reachable"] = False
        snap["errors"].append(f"web DLP rules: {str(e)[:200]}")
    return snap


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _plan_dictionaries(items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any]) -> None:
    predefined = tenant["predefined"]
    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        d = item["definition"]
        if d.get("predefined_clone"):
            template_name = d.get("dict_template_name")
            if not d.get("dict_template_id") and template_name and template_name not in predefined:
                item["depends_on"].append(("predefined", template_name))
        existing = tenant["dictionaries"].get(name)
        if existing is not None:
            pack_sig = dict_signature(d, predefined)
            ten_sig = tenant_dict_signature(existing)
            item["tenant"] = {"id": _field(existing, "id"), "custom": bool(_field(existing, "custom", default=True))}
            if ten_sig is None:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant; existing dictionary will be used (content not compared — tenant returned a summary only)."
            elif ten_sig == pack_sig:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant with identical content; nothing to do."
            else:
                item["status"] = REUSE_DIFFERS
                diffs = [k for k in pack_sig if pack_sig.get(k) != ten_sig.get(k)]
                item["reason"] = (
                    "Already in the tenant but its content differs from this pack "
                    f"({', '.join(diffs) or 'content'}). The tenant's version will be kept and "
                    "used by every engine below; the pack's version will NOT be applied."
                )
                item["warnings"].append("tenant version differs from pack")
            continue
        _, build_err = build_dict_kwargs(d, predefined)
        if build_err == EMPTY_DICT_REASON:
            item["status"] = SKIP_EMPTY
            item["reason"] = "Custom dictionary has no patterns or phrases — nothing to match on, so it can't be created."
        elif build_err and item["depends_on"]:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = f"Clone template '{item['depends_on'][0][1]}' is not a predefined dictionary in this tenant."
        elif build_err:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = build_err
        else:
            item["status"] = CREATE
            item["reason"] = "Will be created as a new dictionary."


def _plan_engines(items: Dict[str, Dict[str, Any]], dict_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any]) -> None:
    # Every dictionary name that could satisfy a D:<name> reference.
    candidates: Dict[str, Any] = {n: n for n in tenant["dictionaries"]}
    candidates.update({n: n for n in dict_items})
    tenant_ids = {n: _field(t, "id") for n, t in tenant["dictionaries"].items()}

    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        expr = item["definition"].get("expression", "")
        _, unresolved = resolve_engine_expression(expr, candidates)
        referenced = engine_references(expr, candidates)
        item["depends_on"] = [("dictionary", n) for n in referenced]
        missing = [u for u in unresolved]
        blocked_deps = [n for n in referenced if n in dict_items and dict_items[n]["status"] not in AVAILABLE_STATUSES]
        if missing or blocked_deps:
            item["status"] = BLOCKED_DEPENDENCY
            parts = []
            if missing:
                parts.append("references dictionaries that exist in neither the selected packs nor the tenant: " + ", ".join(missing))
            if blocked_deps:
                parts.append("depends on blocked dictionaries: " + ", ".join(blocked_deps))
            item["reason"] = "Can't be created — " + "; ".join(parts) + "."
            continue
        existing = tenant["engines"].get(name)
        if existing is not None:
            item["tenant"] = {"id": _field(existing, "id")}
            ten_expr = _field(existing, "engine_expression", "engineExpression")
            if ten_expr and all(n in tenant_ids and tenant_ids[n] is not None for n in referenced):
                pack_expr, _ = resolve_engine_expression(expr, tenant_ids)
                if _norm_expr(pack_expr) == _norm_expr(str(ten_expr)):
                    item["status"] = REUSE
                    item["reason"] = "Already in the tenant with the same expression; nothing to do."
                else:
                    item["status"] = REUSE_DIFFERS
                    item["reason"] = ("Already in the tenant with a different expression. The tenant's engine will be kept "
                                      "and used by the policies below; the pack's expression will NOT be applied.")
                    item["warnings"].append("tenant version differs from pack")
            else:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant; existing engine will be used (expression not compared)."
            continue
        item["status"] = CREATE
        item["reason"] = "Will be created as a new engine."


def _plan_policies(items: Dict[str, Dict[str, Any]], engine_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any]) -> None:
    tenant_rules = {r["name"]: r for r in tenant["rules"]}
    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        p = item["definition"]
        engine_names = [e for e in p.get("engines", [])]
        item["depends_on"] = [("engine", e) for e in engine_names]
        missing = [e for e in engine_names if e not in engine_items and e not in tenant["engines"]]
        blocked = [e for e in engine_names if e in engine_items and engine_items[e]["status"] not in AVAILABLE_STATUSES]
        if not engine_names:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = "Policy lists no engines, so it would match nothing."
            continue
        if missing or blocked:
            item["status"] = BLOCKED_DEPENDENCY
            parts = []
            if missing:
                parts.append("references engines that exist in neither the selected packs nor the tenant: " + ", ".join(missing))
            if blocked:
                parts.append("depends on blocked engines: " + ", ".join(blocked))
            item["reason"] = "Can't be created — " + "; ".join(parts) + "."
            continue
        existing = tenant_rules.get(name)
        if existing is not None:
            item["tenant"] = existing
            pack_action = p.get("action", "ALLOW")
            if existing.get("action") and existing["action"] != pack_action:
                item["status"] = REUSE_DIFFERS
                item["reason"] = (f"A rule with this name already exists with action {existing['action']} (pack says {pack_action}). "
                                  "The existing rule is kept unchanged; the pack's settings will NOT be applied.")
                item["warnings"].append("existing rule action differs from pack")
            else:
                item["status"] = REUSE
                item["reason"] = "A rule with this name already exists; it is kept unchanged."
            continue
        item["status"] = CREATE
        item["reason"] = f"Will be created as a new rule at the top of the policy (action {p.get('action', 'ALLOW')})."
        if p.get("action", "ALLOW") in ENFORCING_ACTIONS:
            item["warnings"].append("enforcing action")


def _plan_tweaks(sources: Sequence[Dict[str, Any]], tenant: Dict[str, Any], apply_tweaks: bool) -> List[Dict[str, Any]]:
    """Confidence tweaks change dictionaries that may already exist in the
    tenant — that is a real modification, so each one is an explicit item."""
    if not apply_tweaks:
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for src in sources:
        # None = pack didn't say → defaults; [] = pack explicitly opted out.
        tweaks = src.get("tweaks")
        if tweaks is None:
            tweaks = DEFAULT_CONFIDENCE_TWEAKS
        for tweak in tweaks:
            candidates = tweak.get("name_patterns") or ([tweak["name"]] if tweak.get("name") else [])
            target = tweak.get("target_confidence")
            label = tweak.get("label") or (candidates[0] if candidates else "tweak")
            key = f"{'|'.join(candidates)}->{target}"
            if key in seen:
                continue
            seen.add(key)
            match_name = next((n for n in candidates if n in tenant["dictionaries"]), None)
            item = {"kind": "tweak", "name": label, "packs": [src["id"]], "definition": tweak,
                    "warnings": [], "depends_on": [], "tenant": None}
            if match_name is None:
                item.update(status=NOOP, reason=f"No dictionary named {', '.join(candidates)} in the tenant; nothing to change.")
            else:
                t = tenant["dictionaries"][match_name]
                current = _field(t, "confidence_threshold", "confidenceThreshold")
                item["tenant"] = {"id": _field(t, "id"), "name": match_name, "current": current}
                if current == target:
                    item.update(status=NOOP, reason=f"'{match_name}' is already at {target}.")
                else:
                    item.update(status=MODIFY, reason=(
                        f"Will change the confidence level of the EXISTING tenant dictionary '{match_name}' "
                        f"from {current or 'unset'} to {target}. This affects every rule that already uses it."))
                    item["warnings"].append("modifies existing tenant object")
            out.append(item)
    return out


def _impacts(policy_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], use_rank_0: bool) -> Tuple[List[Dict[str, Any]], List[str]]:
    impacts: List[Dict[str, Any]] = []
    blockers: List[str] = []
    new_rules = [i for i in policy_items.values() if i["status"] == CREATE]
    n_new = len(new_rules)
    n_existing = len(tenant["rules"])

    if n_new:
        if n_existing + n_new > WEB_DLP_RULE_API_CAP:
            blockers.append(
                f"Web DLP rule limit: the tenant has {n_existing} rules and this plan adds {n_new}, "
                f"exceeding the API cap of {WEB_DLP_RULE_API_CAP}. Remove rules or deselect packs.")
        shifted = tenant["rules"][:5]
        impacts.append({
            "type": "order_shift",
            "title": f"{n_new} new rule{'s' if n_new != 1 else ''} will be inserted at the top of the DLP policy",
            "detail": (f"Every existing rule moves down by {n_new}. Existing rules are evaluated after the new ones. "
                       + (f"For example: " + "; ".join(f"'{r['name']}' order {r['order']} → {r['order'] + n_new}" for r in shifted) + "."
                          if shifted else "The tenant currently has no web DLP rules.")),
            "severity": "warning" if n_existing else "info",
        })
        if use_rank_0:
            impacts.append({
                "type": "rank_0",
                "title": "Rank 0 mode is on",
                "detail": "New rules get admin rank 0, which takes precedence over rules created by lower-ranked admins. Use only to resolve ordering conflicts.",
                "severity": "warning",
            })
        enforcing = [i["name"] for i in new_rules if i["definition"].get("action", "ALLOW") in ENFORCING_ACTIONS]
        if enforcing:
            impacts.append({
                "type": "enforcement",
                "title": f"{len(enforcing)} new rule{'s' if len(enforcing) != 1 else ''} will ENFORCE rather than monitor",
                "detail": ("These rules block or challenge user traffic as soon as they are activated: " + ", ".join(enforcing)
                           + ". Best practice is to deploy in monitor mode (ALLOW) first and switch to BLOCK after tuning."),
                "severity": "warning",
            })
        else:
            impacts.append({
                "type": "monitor_only",
                "title": "All new rules are monitor-only",
                "detail": "Every new rule uses a non-enforcing action, so users will not be blocked. Incidents are logged for review.",
                "severity": "ok",
            })
    impacts.append({
        "type": "activation",
        "title": "Changes must be activated to take effect",
        "detail": "ZIA saves configuration as pending. After this deployment finishes, activate changes in the ZIA Admin Portal (or with ziaActivator) — nothing changes for users until then.",
        "severity": "info",
    })
    return impacts, blockers


def _plan_hash(pack_ids: Sequence[str], options: Dict[str, Any], items: Sequence[Dict[str, Any]], tenant: Dict[str, Any]) -> str:
    core = {
        "packs": sorted(pack_ids),
        "options": options,
        "items": sorted((i["kind"], i["name"], i["status"]) for i in items),
        "tenant": {
            "dictionaries": len(tenant["dictionaries"]),
            "engines": len(tenant["engines"]),
            "rules": len(tenant["rules"]),
        },
    }
    return hashlib.sha256(_canonical(core).encode("utf-8")).hexdigest()


def _public_item(item: Dict[str, Any]) -> Dict[str, Any]:
    d = item.get("definition", {}) or {}
    out = {
        "kind": item["kind"], "name": item["name"], "status": item["status"],
        "reason": item.get("reason", ""), "warnings": item.get("warnings", []),
        "packs": item.get("packs", []), "depends_on": [f"{k}:{n}" for k, n in item.get("depends_on", [])],
        "tenant": item.get("tenant"),
    }
    if item["kind"] == "dictionary":
        out["detail"] = {"type": "clone" if d.get("predefined_clone") else "custom",
                         "patterns": len(d.get("patterns") or []), "phrases": len(d.get("phrases") or []),
                         "proximity": d.get("proximity") or 0}
    elif item["kind"] == "engine":
        out["detail"] = {"expression": d.get("expression", "")}
    elif item["kind"] == "policy":
        out["detail"] = {"action": d.get("action", "ALLOW"), "severity": d.get("severity"),
                         "engines": d.get("engines", []), "protocols": d.get("protocols", ["ANY_RULE"])}
    elif item["kind"] == "tweak":
        out["detail"] = {"target": d.get("target_confidence")}
    return out


def preflight(
    client,
    packs: Sequence[Dict[str, Any]],
    *,
    use_rank_0: bool = False,
    apply_tweaks: bool = True,
    writes_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build the deployment plan for the selected packs without writing.

    `packs` items need `id` and `dir` (as returned by
    dlp_importer.discover_packs). `writes_enabled` is the server's write
    gate; when False the plan is blocked so the GUI can explain why."""
    started = time.time()
    if not packs:
        return {"status": "blocked", "blockers": ["No packs selected."], "items": [], "warnings": [],
                "impacts": [], "summary": {}, "packs": [], "plan_hash": "", "tenant": {"reachable": False}}

    sources = load_sources(packs)
    merged = merge_sources(sources)
    tenant = fetch_tenant(client)
    options = {"use_rank_0": bool(use_rank_0), "apply_tweaks": bool(apply_tweaks)}

    blockers: List[str] = []
    if not tenant["reachable"]:
        blockers.append("Could not read the tenant's current configuration, so overlaps and dependencies can't be checked: "
                        + "; ".join(tenant["errors"]))
    if writes_enabled is False:
        blockers.append("The server is running in read-only mode. Restart it with START_Zscaler_Assessment_WRITES_ENABLED.bat "
                        "(ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND) to deploy.")

    if tenant["reachable"]:
        _plan_dictionaries(merged["dictionary"], tenant)
        _plan_engines(merged["engine"], merged["dictionary"], tenant)
        _plan_policies(merged["policy"], merged["engine"], tenant)
        tweak_items = _plan_tweaks(sources, tenant, apply_tweaks)
        impacts, impact_blockers = _impacts(merged["policy"], tenant, use_rank_0)
        blockers.extend(impact_blockers)
    else:
        for kind in merged:
            for item in merged[kind].values():
                if item["status"] != CONFLICT:
                    item["status"] = BLOCKED_DEPENDENCY
                    item["reason"] = "Tenant unreachable — cannot verify."
        tweak_items, impacts = [], []

    all_items = (list(merged["dictionary"].values()) + list(merged["engine"].values())
                 + list(merged["policy"].values()) + tweak_items)

    summary: Dict[str, Any] = {}
    for kind in ("dictionary", "engine", "policy", "tweak"):
        counts: Dict[str, int] = {}
        for i in all_items:
            if i["kind"] == kind:
                counts[i["status"]] = counts.get(i["status"], 0) + 1
        summary[kind] = counts

    warnings: List[str] = []
    for i in all_items:
        if i["status"] == CONFLICT:
            warnings.append(f"{i['kind'].title()} '{i['name']}' is defined differently in {', '.join(i['packs'])} — it and everything that depends on it will be skipped.")
        elif i["status"] == BLOCKED_DEPENDENCY:
            warnings.append(f"{i['kind'].title()} '{i['name']}' will be skipped: {i['reason']}")
        elif i["status"] == REUSE_DIFFERS:
            warnings.append(f"{i['kind'].title()} '{i['name']}' already exists with different content — the tenant's version is kept.")
        elif i["status"] == MODIFY:
            warnings.append(f"{i['name']}: {i['reason']}")
        elif i["status"] == SKIP_EMPTY:
            warnings.append(f"Dictionary '{i['name']}' has nothing to match on and will be skipped.")
    for imp in impacts:
        if imp.get("severity") == "warning":
            warnings.append(imp["title"])

    creates = sum(1 for i in all_items if i["status"] in (CREATE, MODIFY))
    if tenant["reachable"] and creates == 0 and not blockers:
        blockers.append("Nothing to deploy: everything in the selected packs already exists in the tenant or is blocked.")

    status = "blocked" if blockers else ("warnings" if warnings else "ready")
    public_items = [_public_item(i) for i in all_items]
    report = {
        "status": status,
        "packs": [{"id": s["id"], "name": s["name"], "dictionaries": len(s["dictionaries"]),
                   "engines": len(s["engines"]), "policies": len(s["policies"])} for s in sources],
        "options": options,
        "tenant": {"reachable": tenant["reachable"], "errors": tenant["errors"],
                   "dictionaries": len(tenant["dictionaries"]), "engines": len(tenant["engines"]),
                   "rules": len(tenant["rules"]), "rule_cap": WEB_DLP_RULE_API_CAP},
        "summary": summary,
        "items": public_items,
        "warnings": warnings,
        "blockers": blockers,
        "impacts": impacts,
        "will_create": creates,
        "will_skip": sum(1 for i in all_items if i["status"] in BLOCKING_STATUSES),
        "plan_hash": _plan_hash([s["id"] for s in sources], options, all_items, tenant) if tenant["reachable"] else "",
        "elapsed_seconds": round(time.time() - started, 2),
        # Internal — stripped by the API layer, consumed by apply().
        "_internal": {"merged": merged, "tweaks": tweak_items, "tenant": tenant, "sources": sources},
    }
    return report


def public_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Strip internal state so the report can be returned over the API."""
    return {k: v for k, v in report.items() if not k.startswith("_")}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def apply(
    client,
    packs: Sequence[Dict[str, Any]],
    *,
    plan_hash: str,
    use_rank_0: bool = False,
    apply_tweaks: bool = True,
    verify: bool = True,
    writes_enabled: Optional[bool] = None,
    log: LogFn = None,
) -> Dict[str, Any]:
    """Execute a previously approved plan.

    The preflight is recomputed first; if its hash differs from
    `plan_hash` the tenant or selection changed after the user approved,
    and nothing is written (status `plan_changed`). Items are applied in
    dependency order; each is isolated, blocked items are skipped with
    their reason, and dependents of a failed item are skipped rather
    than created against a missing dependency."""
    _log = log or (lambda m: None)
    started = time.time()
    report = preflight(client, packs, use_rank_0=use_rank_0, apply_tweaks=apply_tweaks, writes_enabled=writes_enabled)
    if report["status"] == "blocked":
        return {"status": "blocked", "blockers": report["blockers"], "report": public_report(report), "results": []}
    if not plan_hash or report["plan_hash"] != plan_hash:
        return {"status": "plan_changed",
                "message": "The tenant or the selection changed since this plan was approved. Review the new plan and approve again.",
                "expected_hash": plan_hash, "current_hash": report["plan_hash"],
                "report": public_report(report), "results": []}

    internal = report["_internal"]
    merged, tenant = internal["merged"], internal["tenant"]
    zia = client.zia
    results: List[Dict[str, Any]] = []
    failed_names: Dict[str, Set[str]] = {"dictionary": set(), "engine": set()}

    def record(item: Dict[str, Any], status: str, **extra: Any) -> None:
        entry = {"kind": item["kind"], "name": item["name"], "status": status, **extra}
        results.append(entry)
        _log(f"[{item['kind']}] {item['name']}: {status}" + (f" — {extra.get('error') or extra.get('reason')}" if extra.get('error') or extra.get('reason') else ""))

    # Name → ID maps, extended as objects are created so later phases resolve them.
    dict_ids: Dict[str, Any] = {n: _field(t, "id") for n, t in tenant["dictionaries"].items()}
    engine_ids: Dict[str, Any] = {n: _field(t, "id") for n, t in tenant["engines"].items()}

    _log("Phase 1: dictionaries")
    for item in merged["dictionary"].values():
        if item["status"] in (REUSE, REUSE_DIFFERS):
            record(item, "reused", id=(item.get("tenant") or {}).get("id"))
            continue
        if item["status"] != CREATE:
            record(item, "skipped", reason=item["reason"])
            continue
        d = item["definition"]
        try:
            kwargs, build_err = build_dict_kwargs(d, tenant["predefined"])
            if build_err:
                record(item, "skipped", reason=build_err)
                failed_names["dictionary"].add(item["name"])
                continue
            resp = zia.dlp_dictionary.add_dict(d["name"], d["custom_phrase_match_type"], "PATTERNS_AND_PHRASES", **kwargs)
            new_id = _extract_id(resp)
            if new_id:
                dict_ids[item["name"]] = new_id
                record(item, "created", id=new_id)
            else:
                failed_names["dictionary"].add(item["name"])
                record(item, "failed", error=_extract_error(resp))
        except Exception as e:  # noqa: BLE001 — isolate per item
            failed_names["dictionary"].add(item["name"])
            record(item, "failed", error=str(e)[:200])

    _log("Phase 2: engines")
    for item in merged["engine"].values():
        if item["status"] in (REUSE, REUSE_DIFFERS):
            record(item, "reused", id=(item.get("tenant") or {}).get("id"))
            continue
        if item["status"] != CREATE:
            record(item, "skipped", reason=item["reason"])
            continue
        deps_failed = [n for _, n in item["depends_on"] if n in failed_names["dictionary"]]
        if deps_failed:
            failed_names["engine"].add(item["name"])
            record(item, "skipped", reason="dependency failed: " + ", ".join(deps_failed))
            continue
        e = item["definition"]
        try:
            expr, unresolved = resolve_engine_expression(e["expression"], dict_ids)
            if unresolved:
                failed_names["engine"].add(item["name"])
                record(item, "skipped", reason="unresolved dictionaries: " + ", ".join(unresolved))
                continue
            resp = zia.dlp_engine.add_dlp_engine(name=e["name"], engine_expression=expr, custom_dlp_engine=True,
                                                 description=e.get("description", "Imported engine"))
            new_id = _extract_id(resp)
            if new_id:
                engine_ids[item["name"]] = new_id
                record(item, "created", id=new_id)
            else:
                failed_names["engine"].add(item["name"])
                record(item, "failed", error=_extract_error(resp))
        except Exception as ex:  # noqa: BLE001
            failed_names["engine"].add(item["name"])
            record(item, "failed", error=str(ex)[:200])

    _log("Phase 3: policies")
    for item in merged["policy"].values():
        if item["status"] in (REUSE, REUSE_DIFFERS):
            record(item, "reused", id=(item.get("tenant") or {}).get("id"))
            continue
        if item["status"] != CREATE:
            record(item, "skipped", reason=item["reason"])
            continue
        p = item["definition"]
        deps_failed = [n for _, n in item["depends_on"] if n in failed_names["engine"]]
        if deps_failed:
            record(item, "skipped", reason="dependency failed: " + ", ".join(deps_failed))
            continue
        ids = [engine_ids[n] for n in p.get("engines", []) if n in engine_ids and engine_ids[n] is not None]
        if len(ids) != len(p.get("engines", [])):
            record(item, "skipped", reason="one or more engines could not be resolved to an ID")
            continue
        try:
            resp = zia.dlp_web_rules.add_rule(**build_policy_payload(p, ids, use_rank_0=use_rank_0))
            new_id = _extract_id(resp)
            if new_id:
                record(item, "created", id=new_id)
            else:
                record(item, "failed", error=_extract_error(resp))
        except Exception as ex:  # noqa: BLE001
            record(item, "failed", error=str(ex)[:200])

    if apply_tweaks:
        _log("Phase 4: confidence tweaks")
        for item in internal["tweaks"]:
            if item["status"] != MODIFY:
                continue  # no-ops were already explained in the plan; nothing to report
            t = item["tenant"]
            existing = tenant["dictionaries"][t["name"]]
            try:
                _, _, err = zia.dlp_dictionary.update_dict(
                    t["id"],
                    name=t["name"],
                    dictionary_type=_field(existing, "dictionary_type", "dictionaryType", default="PATTERNS_AND_PHRASES"),
                    custom_phrase_match_type=_field(existing, "custom_phrase_match_type", "customPhraseMatchType",
                                                    default="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"),
                    confidence_threshold=item["definition"]["target_confidence"],
                )
                if err:
                    record(item, "failed", error=str(err)[:200])
                else:
                    record(item, "modified", id=t["id"])
            except Exception as ex:  # noqa: BLE001
                record(item, "failed", error=str(ex)[:200])

    verification: Dict[str, Any] = {}
    if verify:
        _log("Phase 5: verification")
        for src in internal["sources"]:
            try:
                verification[src["id"]] = verify_deployment(zia, src["dir"], log=log)
            except Exception as ex:  # noqa: BLE001
                verification[src["id"]] = {"phase": "verify", "all_good": False, "error": str(ex)[:200]}

    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    if counts.get("failed"):
        status = "partial" if (counts.get("created") or counts.get("modified")) else "failed"
    else:
        status = "applied"
    return {
        "status": status,
        "summary": counts,
        "results": results,
        "verification": verification,
        "plan_hash": plan_hash,
        "elapsed_seconds": round(time.time() - started, 2),
        "activation_required": bool(counts.get("created") or counts.get("modified")),
    }
