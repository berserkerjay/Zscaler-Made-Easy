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
* Channels — a policy's `channel` (web, endpoint, saas, email) decides
  which rule API it targets. Non-web channels have tenant prerequisites
  a pack cannot ship (onboarded SaaS/email tenants, notification
  templates, labels, the feature's API answering at all); these are
  resolved by name in preflight, listed in the report's `dependencies`,
  and a rule whose prerequisites are missing is blocked, not created.
  See pack_channels.py.
* Impact analysis — new rules are inserted at order 1 of their channel's
  policy and push every existing rule down; the API caps web DLP rules
  at 127; policies whose action enforces rather than monitors are called
  out; confidence tweaks that would MODIFY an existing tenant dictionary
  are listed as explicit modifications; and ZIA changes always need
  activation afterwards.

The report is plain data (dicts/lists) so the GUI can render it and the
API can return it verbatim. `plan_hash` binds an approval to exactly the
plan the user saw.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pack_channels as pc
from dlp_importer import (
    DICT_DESCRIPTION_MAX,
    EMPTY_DICT_REASON,
    fit_description,
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
RESTORE = "restore"                      # baseline object drifted in the tenant — will be overwritten with the baseline

BLOCKING_STATUSES = {CONFLICT, BLOCKED_DEPENDENCY, SKIP_EMPTY}
AVAILABLE_STATUSES = {CREATE, REUSE, REUSE_DIFFERS, RESTORE}
WRITE_STATUSES = {CREATE, MODIFY, RESTORE}

# Provenance marker stamped into the description of every object an
# immutable baseline creates or restores. Lets admins (and the next
# preflight) see that the object is baseline-managed.
BASELINE_MARK = "[DLP-Check baseline"

LogFn = Optional[Callable[[str], None]]


# ---------------------------------------------------------------------------
# Immutable baselines
# ---------------------------------------------------------------------------
#
# A pack whose pack.json carries `"baseline": {...}` is a BASELINE: the
# authoritative definition of the objects it names. Deploying it is
# convergent rather than additive —
#   * objects it defines that are missing are created,
#   * objects that exist with identical content are left alone (in sync),
#   * objects that exist with DIFFERENT content are RESTORED to the
#     baseline definition (this is the one case where the planner
#     overwrites; it is listed for approval like any other write),
#   * objects the baseline does not define are never touched.
# Every object it writes gets a provenance tag in its description.

def baseline_meta(meta: Dict[str, Any], pack_id: str) -> Optional[Dict[str, Any]]:
    """Normalise pack.json's `baseline` field. Returns None for ordinary packs."""
    b = meta.get("baseline")
    if not b:
        return None
    if b is True:
        b = {}
    if not isinstance(b, dict):
        return None
    if b.get("immutable", True) is False:
        return None
    return {
        "pack": pack_id,
        "name": meta.get("name", pack_id),
        "version": str(b.get("version") or meta.get("version") or ""),
        "prefix": str(b.get("prefix") or ""),
    }


def baseline_description(item: Dict[str, Any], base: Optional[str], *, limit: Optional[int] = None) -> str:
    """Description with the provenance tag appended (idempotent). `limit`
    clamps the total length (dictionaries: 255) without losing the tag."""
    b = item.get("baseline") or {}
    tag = f"{BASELINE_MARK} {b.get('pack', '?')}{(' v' + b['version']) if b.get('version') else ''}] Immutable: drift is reverted on the next deploy."
    base = (base or "").strip()
    if BASELINE_MARK in base:
        base = base.split(BASELINE_MARK, 1)[0].strip()
    if limit:
        return fit_description(base, tag, limit)
    return f"{base} {tag}".strip()


def _has_mark(obj: Any) -> bool:
    return BASELINE_MARK in str(_field(obj, "description", default="") or "")


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
            "baseline": baseline_meta(meta, p["id"]),
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
    sig = {
        "action": p.get("action", pc.default_action(pc.channel_of(p))),
        "state": p.get("state", "ENABLED"),
        "engines": sorted(p.get("engines", [])),
        "protocols": sorted(p.get("protocols", ["ANY_RULE"])),
        "severity": p.get("severity"),
        "rank": p.get("rank", 7),
    }
    sig.update(pc.policy_signature_extra(p))
    return sig


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
                        "baseline": src.get("baseline"), "drift": None, "adopt": False,
                    }
                elif existing["signature"] == sig:
                    existing["packs"].append(src["id"])
                    if src.get("baseline") and not existing.get("baseline"):
                        existing["baseline"] = src["baseline"]
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

def fetch_tenant(client, need: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read everything the plan needs from the tenant: dictionaries,
    engines and web DLP rules always; other channels' rules and their
    prerequisites (SaaS tenants, notification templates, labels) only
    when `need` (see pack_channels.needs) says the packs use them.
    Never raises: each failure is recorded and `reachable` reflects it."""
    snap: Dict[str, Any] = {
        "reachable": True, "errors": [],
        "dictionaries": {}, "predefined": {}, "engines": {}, "rules": [],
        "channels": {"rules": {}, "errors": {}, "casb_tenants": None, "casb_error": None,
                     "templates": None, "templates_error": None, "labels": None, "labels_error": None},
    }
    zia = client.zia
    if need and (need["channels"] - {pc.WEB} or need["casb"] or need["templates"] or need["labels"] or need.get("app_classes")):
        snap["channels"] = pc.fetch_channel_state(zia, need)
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
                # Content fields used for baseline drift detection.
                "engine_ids": pc.engine_ids_of(r),
                "protocols": sorted(str(x) for x in (_field(r, "protocols", default=[]) or [])),
                "severity": _field(r, "severity"),
                "description": _field(r, "description"),
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
            is_custom = bool(_field(existing, "custom", default=True))
            item["tenant"] = {"id": _field(existing, "id"), "custom": is_custom}
            baseline = item.get("baseline")
            if baseline and not is_custom:
                item["status"] = CONFLICT
                item["reason"] = ("A predefined Zscaler dictionary already has this name; a baseline cannot manage "
                                  "predefined objects. Rename the baseline dictionary.")
                continue
            if baseline:
                item["adopt"] = not _has_mark(existing)
            if ten_sig is None:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant; existing dictionary will be used (content not compared — tenant returned a summary only)."
            elif ten_sig == pack_sig:
                item["status"] = REUSE
                item["reason"] = ("In sync with the baseline; nothing to do." if baseline
                                  else "Already in the tenant with identical content; nothing to do.")
            elif baseline:
                diffs = [k for k in pack_sig if pack_sig.get(k) != ten_sig.get(k)]
                item["status"] = RESTORE
                item["drift"] = diffs
                item["reason"] = (
                    f"Drifted from the baseline ({', '.join(diffs) or 'content'}). "
                    "The dictionary will be overwritten with the baseline definition."
                    + (" It was not created by DLP-Check and will be brought under baseline management." if item["adopt"] else "")
                )
                item["warnings"].append("drifted from baseline")
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
            baseline = item.get("baseline")
            if baseline:
                item["adopt"] = not _has_mark(existing)
            ten_expr = _field(existing, "engine_expression", "engineExpression")
            # A referenced dictionary the plan will CREATE has no ID yet, so
            # the tenant expression cannot be current. (A RESTORE keeps its
            # ID, so existing references to it stay valid.)
            deps_changing = [n for n in referenced if n in dict_items and dict_items[n]["status"] == CREATE]
            if ten_expr and all(n in tenant_ids and tenant_ids[n] is not None for n in referenced):
                pack_expr, _ = resolve_engine_expression(expr, tenant_ids)
                if _norm_expr(pack_expr) == _norm_expr(str(ten_expr)) and not (baseline and deps_changing):
                    item["status"] = REUSE
                    item["reason"] = ("In sync with the baseline; nothing to do." if baseline
                                      else "Already in the tenant with the same expression; nothing to do.")
                elif baseline:
                    item["status"] = RESTORE
                    item["drift"] = ["expression"]
                    item["reason"] = ("Drifted from the baseline (expression). The engine will be overwritten with the baseline expression."
                                      + (" It was not created by DLP-Check and will be brought under baseline management." if item["adopt"] else ""))
                    item["warnings"].append("drifted from baseline")
                else:
                    item["status"] = REUSE_DIFFERS
                    item["reason"] = ("Already in the tenant with a different expression. The tenant's engine will be kept "
                                      "and used by the policies below; the pack's expression will NOT be applied.")
                    item["warnings"].append("tenant version differs from pack")
            elif baseline and deps_changing:
                item["status"] = RESTORE
                item["drift"] = ["dictionaries"]
                item["reason"] = ("References dictionaries the baseline is creating or restoring; the engine will be "
                                  "rewritten against the baseline dictionaries.")
            else:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant; existing engine will be used (expression not compared)."
            continue
        item["status"] = CREATE
        item["reason"] = "Will be created as a new engine."


def _tenant_rules_for(tenant: Dict[str, Any], channel: str) -> List[Dict[str, Any]]:
    if channel == pc.WEB:
        return tenant["rules"]
    return tenant["channels"]["rules"].get(channel, [])


def _plan_policies(items: Dict[str, Dict[str, Any]], engine_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any]) -> None:
    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        p = item["definition"]
        channel = pc.channel_of(p)
        item["channel"] = channel
        bad = pc.validate(p)
        if bad:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = f"Invalid policy definition in the pack: {bad}."
            continue
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
        # Channel prerequisites (SaaS/email tenants, templates, labels, API reachability).
        res = pc.resolve(channel, p, tenant["channels"])
        item["resolved"] = res["resolved"]
        item["depends_on"].extend(res["depends"])
        if res["missing"]:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = f"Can't be created ({pc.label(channel)}) — " + "; ".join(res["missing"]) + "."
            continue
        tenant_rules = {r["name"]: r for r in _tenant_rules_for(tenant, channel)}
        existing = tenant_rules.get(name)
        pack_action = p.get("action", pc.default_action(channel))
        if existing is not None:
            item["tenant"] = existing
            baseline = item.get("baseline")
            if baseline:
                item["adopt"] = BASELINE_MARK not in str(existing.get("description") or "")
                drift = _policy_drift(p, channel, existing, engine_items, tenant)
                if drift:
                    item["status"] = RESTORE
                    item["drift"] = drift
                    item["reason"] = (f"Drifted from the baseline ({', '.join(drift)}). The {pc.label(channel)} rule will be "
                                      "overwritten with the baseline definition; its position in the policy is kept."
                                      + (" It was not created by DLP-Check and will be brought under baseline management." if item["adopt"] else ""))
                    item["warnings"].append("drifted from baseline")
                    if pc.is_enforcing(channel, pack_action):
                        item["warnings"].append("enforcing action")
                else:
                    item["status"] = REUSE
                    item["reason"] = "In sync with the baseline; nothing to do."
                continue
            if existing.get("action") and existing["action"] != pack_action:
                item["status"] = REUSE_DIFFERS
                item["reason"] = (f"A {pc.label(channel)} rule with this name already exists with action {existing['action']} (pack says {pack_action}). "
                                  "The existing rule is kept unchanged; the pack's settings will NOT be applied.")
                item["warnings"].append("existing rule action differs from pack")
            else:
                item["status"] = REUSE
                item["reason"] = f"A {pc.label(channel)} rule with this name already exists; it is kept unchanged."
            continue
        item["status"] = CREATE
        scope = ""
        if item["resolved"].get("tenants"):
            scope = " scoped to " + ", ".join(t["name"] for t in item["resolved"]["tenants"])
        item["reason"] = f"Will be created as a new {pc.label(channel)} rule at the top of that policy (action {pack_action}){scope}."
        if pc.is_enforcing(channel, pack_action):
            item["warnings"].append("enforcing action")


def _policy_drift(p: Dict[str, Any], channel: str, existing: Dict[str, Any],
                  engine_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any]) -> List[str]:
    """Fields on which an existing rule differs from its baseline definition.
    Only fields the tenant snapshot carries are compared; anything the API
    does not echo back (e.g. dynamic cloud-application scope) is left alone."""
    drift: List[str] = []
    if existing.get("action") and existing["action"] != p.get("action", pc.default_action(channel)):
        drift.append("action")
    if existing.get("state") and existing["state"] != p.get("state", "ENABLED"):
        drift.append("state")
    if p.get("severity") and existing.get("severity") and existing["severity"] != p["severity"]:
        drift.append("severity")
    # Engines: expected = the tenant IDs of the baseline's engines. An
    # engine the plan is about to CREATE has no ID yet, so the rule cannot
    # be in sync with it. (A RESTORE keeps its ID.)
    expected: List[Any] = []
    changing = False
    for n in p.get("engines", []):
        it = engine_items.get(n)
        if it is not None and it["status"] == CREATE:
            changing = True
        t = tenant["engines"].get(n)
        if t is not None:
            expected.append(_field(t, "id"))
    if changing or sorted(map(str, expected)) != sorted(map(str, existing.get("engine_ids") or [])):
        drift.append("engines")
    if channel == pc.WEB and existing.get("protocols"):
        if sorted(str(x) for x in p.get("protocols", ["ANY_RULE"])) != existing["protocols"]:
            drift.append("protocols")
    return drift


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


def _baseline_impacts(all_items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One card per baseline pack: how many of its objects are in sync,
    drifted (will be restored) or missing (will be created)."""
    per: Dict[str, Dict[str, Any]] = {}
    for i in all_items:
        b = i.get("baseline")
        if not b:
            continue
        row = per.setdefault(b["pack"], {"meta": b, "in_sync": 0, "drifted": 0, "missing": 0, "blocked": 0,
                                          "drifted_names": [], "adopted": 0})
        st = i["status"]
        if st == RESTORE:
            row["drifted"] += 1
            row["drifted_names"].append(i["name"])
            if i.get("adopt"):
                row["adopted"] += 1
        elif st == CREATE:
            row["missing"] += 1
        elif st in (REUSE, REUSE_DIFFERS, NOOP):
            row["in_sync"] += 1
        else:
            row["blocked"] += 1
    out: List[Dict[str, Any]] = []
    for pack_id, row in per.items():
        b = row["meta"]
        label = f"{b.get('name') or pack_id}{(' v' + b['version']) if b.get('version') else ''}"
        if row["drifted"]:
            names = ", ".join(row["drifted_names"][:6]) + (f" +{len(row['drifted_names']) - 6} more" if len(row["drifted_names"]) > 6 else "")
            out.append({
                "type": "baseline_restore", "baseline": pack_id,
                "title": f"{row['drifted']} object{'s' if row['drifted'] != 1 else ''} drifted from baseline {label} and will be restored",
                "detail": (f"Baselines are immutable: dictionaries, engines and rules whose content differs from the baseline are "
                           f"overwritten with the baseline definition. Drifted: {names}."
                           + (f" {row['adopted']} of them were not created by DLP-Check and will be brought under baseline management."
                              if row["adopted"] else "")
                           + " Objects the baseline does not define are never touched."),
                "severity": "warning",
            })
        else:
            out.append({
                "type": "baseline_in_sync", "baseline": pack_id,
                "title": f"Baseline {label}: {row['in_sync']} in sync, {row['missing']} missing"
                         + (f", {row['blocked']} blocked" if row["blocked"] else ""),
                "detail": ("Nothing in the tenant deviates from this baseline. Missing objects will be created with a provenance "
                           "tag; future deploys restore any drift."),
                "severity": "ok" if not row["blocked"] else "info",
            })
    return out


def _impacts(policy_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], use_rank_0: bool) -> Tuple[List[Dict[str, Any]], List[str]]:
    impacts: List[Dict[str, Any]] = []
    blockers: List[str] = []
    new_rules = [i for i in policy_items.values() if i["status"] == CREATE]
    n_new = len(new_rules)

    by_channel: Dict[str, List[Dict[str, Any]]] = {}
    for i in new_rules:
        by_channel.setdefault(i.get("channel") or pc.channel_of(i["definition"]), []).append(i)

    for channel in (pc.WEB, pc.ENDPOINT, pc.SAAS, pc.EMAIL):
        rules = by_channel.get(channel)
        if not rules:
            continue
        n_ch = len(rules)
        existing_rules = _tenant_rules_for(tenant, channel)
        n_existing = len(existing_rules)
        cap = pc.CHANNELS[channel]["rule_cap"]
        if cap and n_existing + n_ch > cap:
            blockers.append(
                f"{pc.label(channel)} rule limit: the tenant has {n_existing} rules and this plan adds {n_ch}, "
                f"exceeding the API cap of {cap}. Remove rules or deselect packs.")
        shifted = existing_rules[:5]
        impacts.append({
            "type": "order_shift",
            "channel": channel,
            "title": f"{n_ch} new {pc.label(channel)} rule{'s' if n_ch != 1 else ''} will be inserted at the top of that policy",
            "detail": (f"Every existing {pc.label(channel)} rule moves down by {n_ch}. Existing rules are evaluated after the new ones. "
                       + (f"For example: " + "; ".join(f"'{r['name']}' order {r['order']} → {r['order'] + n_ch}" for r in shifted) + "."
                          if shifted else f"The tenant currently has no {pc.label(channel)} rules.")),
            "severity": "warning" if n_existing else "info",
        })
        scoped = [i for i in rules if i.get("resolved", {}).get("tenants")]
        if scoped:
            tenants = sorted({t["name"] for i in scoped for t in i["resolved"]["tenants"]})
            impacts.append({
                "type": "saas_scope",
                "channel": channel,
                "title": f"{pc.label(channel)} rules will apply to {len(tenants)} onboarded SaaS tenant{'s' if len(tenants) != 1 else ''}",
                "detail": "Content in these tenants will be scanned by the new rules: " + ", ".join(tenants)
                          + ". Out-of-band scanning generates incidents for existing data at rest, not only new uploads.",
                "severity": "info",
            })

    if n_new:
        if use_rank_0:
            impacts.append({
                "type": "rank_0",
                "title": "Rank 0 mode is on",
                "detail": "New rules get admin rank 0, which takes precedence over rules created by lower-ranked admins. Use only to resolve ordering conflicts.",
                "severity": "warning",
            })
        enforcing = [i["name"] for i in list(new_rules) + [i for i in policy_items.values() if i["status"] == RESTORE]
                     if pc.is_enforcing(i.get("channel") or pc.channel_of(i["definition"]),
                                        i["definition"].get("action", pc.default_action(i.get("channel") or pc.WEB)))]
        if enforcing:
            impacts.append({
                "type": "enforcement",
                "title": f"{len(enforcing)} new rule{'s' if len(enforcing) != 1 else ''} will ENFORCE rather than monitor",
                "detail": ("These rules block, quarantine or challenge user activity as soon as they are activated: " + ", ".join(enforcing)
                           + ". Best practice is to deploy in monitor mode first and switch to an enforcing action after tuning."),
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
            "channel_rules": {ch: len(rs) for ch, rs in tenant["channels"]["rules"].items()},
            "casb_tenants": sorted(t["name"] for t in (tenant["channels"].get("casb_tenants") or [])),
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
        "baseline": (item.get("baseline") or {}).get("pack"),
        "drift": item.get("drift"),
        "adopt": bool(item.get("adopt")),
    }
    if item["kind"] == "dictionary":
        out["detail"] = {"type": "clone" if d.get("predefined_clone") else "custom",
                         "patterns": len(d.get("patterns") or []), "phrases": len(d.get("phrases") or []),
                         "proximity": d.get("proximity") or 0}
    elif item["kind"] == "engine":
        out["detail"] = {"expression": d.get("expression", "")}
    elif item["kind"] == "policy":
        channel = item.get("channel") or pc.channel_of(d)
        resolved = item.get("resolved") or {}
        out["detail"] = {"action": d.get("action", pc.default_action(channel)), "severity": d.get("severity"),
                         "engines": d.get("engines", []), "protocols": d.get("protocols", ["ANY_RULE"]),
                         "channel": channel, "channel_label": pc.label(channel),
                         "saas_type": d.get("saas_type"),
                         "tenants": [t["name"] for t in resolved.get("tenants", [])],
                         "notification_template": d.get("notification_template"),
                         "labels": d.get("labels", [])}
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
    need = pc.needs(i["definition"] for i in merged["policy"].values())
    tenant = fetch_tenant(client, need)
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
        impacts = _baseline_impacts(list(merged["dictionary"].values()) + list(merged["engine"].values())
                                    + list(merged["policy"].values())) + impacts
        blockers.extend(impact_blockers)
        dependencies = pc.dependency_report(list(merged["policy"].values()), tenant["channels"], len(tenant["rules"]))
    else:
        dependencies = []
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
    channels: Dict[str, Dict[str, int]] = {}
    for i in merged["policy"].values():
        ch = i.get("channel") or pc.channel_of(i["definition"])
        channels.setdefault(ch, {})
        channels[ch][i["status"]] = channels[ch].get(i["status"], 0) + 1
    summary["channels"] = channels

    warnings: List[str] = []
    for i in all_items:
        if i["status"] == CONFLICT:
            warnings.append(f"{i['kind'].title()} '{i['name']}' is defined differently in {', '.join(i['packs'])} — it and everything that depends on it will be skipped.")
        elif i["status"] == BLOCKED_DEPENDENCY:
            warnings.append(f"{i['kind'].title()} '{i['name']}' will be skipped: {i['reason']}")
        elif i["status"] == REUSE_DIFFERS:
            warnings.append(f"{i['kind'].title()} '{i['name']}' already exists with different content — the tenant's version is kept.")
        elif i["status"] == RESTORE:
            warnings.append(f"{i['kind'].title()} '{i['name']}' drifted from baseline ({', '.join(i.get('drift') or ['content'])}) — it will be restored.")
        elif i["status"] == MODIFY:
            warnings.append(f"{i['name']}: {i['reason']}")
        elif i["status"] == SKIP_EMPTY:
            warnings.append(f"Dictionary '{i['name']}' has nothing to match on and will be skipped.")
    for imp in impacts:
        if imp.get("severity") == "warning":
            warnings.append(imp["title"])

    creates = sum(1 for i in all_items if i["status"] in WRITE_STATUSES)
    if tenant["reachable"] and creates == 0 and not blockers:
        if any(s.get("baseline") for s in sources):
            blockers.append("Nothing to deploy: every baseline object is already in sync with the tenant.")
        else:
            blockers.append("Nothing to deploy: everything in the selected packs already exists in the tenant or is blocked.")

    status = "blocked" if blockers else ("warnings" if warnings else "ready")
    public_items = [_public_item(i) for i in all_items]
    report = {
        "status": status,
        "packs": [{"id": s["id"], "name": s["name"], "dictionaries": len(s["dictionaries"]),
                   "engines": len(s["engines"]), "policies": len(s["policies"]),
                   "baseline": s.get("baseline")} for s in sources],
        "baselines": baseline_status_rows(all_items, sources),
        "options": options,
        "tenant": {"reachable": tenant["reachable"], "errors": tenant["errors"],
                   "dictionaries": len(tenant["dictionaries"]), "engines": len(tenant["engines"]),
                   "rules": len(tenant["rules"]), "rule_cap": WEB_DLP_RULE_API_CAP,
                   "channel_rules": {ch: len(rs) for ch, rs in tenant["channels"]["rules"].items()},
                   "channel_errors": tenant["channels"]["errors"],
                   "casb_tenants": [{"name": t["name"], "app": t["app"]} for t in (tenant["channels"].get("casb_tenants") or [])]},
        "summary": summary,
        "items": public_items,
        "warnings": warnings,
        "blockers": blockers,
        "impacts": impacts,
        "dependencies": dependencies,
        "will_create": creates,
        "will_restore": sum(1 for i in all_items if i["status"] == RESTORE),
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


# Plan status → baseline drift vocabulary.
_DRIFT_STATUS = {REUSE: "in_sync", REUSE_DIFFERS: "in_sync", NOOP: "in_sync", RESTORE: "drifted", CREATE: "missing"}


def baseline_status_rows(all_items: Sequence[Dict[str, Any]], sources: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-baseline drift summary derived from a plan: every object of a
    baseline pack is in_sync, drifted, missing or blocked. Read-only; the
    same numbers the review step shows, in a shape the drift check and
    the assessment can consume."""
    rows: List[Dict[str, Any]] = []
    for src in sources:
        b = src.get("baseline")
        if not b:
            continue
        row = {"id": src["id"], "name": src["name"], "version": b.get("version", ""), "prefix": b.get("prefix", ""),
               "in_sync": 0, "drifted": 0, "missing": 0, "blocked": 0, "total": 0, "objects": []}
        for i in all_items:
            if i.get("kind") == "tweak" or src["id"] not in (i.get("packs") or []):
                continue
            st = _DRIFT_STATUS.get(i["status"], "blocked")
            row[st] += 1
            row["total"] += 1
            if st != "in_sync":
                row["objects"].append({"kind": i["kind"], "name": i["name"], "state": st,
                                       "drift": i.get("drift"), "adopt": bool(i.get("adopt")), "reason": i.get("reason", "")})
        row["state"] = "blocked" if row["blocked"] else ("drifted" if row["drifted"] else ("missing" if row["missing"] else "in_sync"))
        rows.append(row)
    return rows


def baseline_status(report: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, read-only drift report for the baselines in a preflight."""
    rows = report.get("baselines") or []
    overall = "in_sync"
    for r in rows:
        if r["state"] == "blocked":
            overall = "blocked"
            break
        if r["state"] in ("drifted", "missing"):
            overall = "drifted"
    return {
        "status": overall,
        "baselines": rows,
        "tenant": report.get("tenant"),
        "blockers": [b for b in report.get("blockers", []) if not b.startswith("Nothing to deploy")
                     and not b.startswith("The server is running in read-only mode")],
        "plan_hash": report.get("plan_hash", ""),
        "elapsed_seconds": report.get("elapsed_seconds"),
    }


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

    def described(item: Dict[str, Any], definition: Dict[str, Any], fallback: str = "") -> Dict[str, Any]:
        """Definition with the baseline provenance tag in its description
        (clamped to the API limit for dictionaries)."""
        if not item.get("baseline"):
            return definition
        limit = DICT_DESCRIPTION_MAX if item["kind"] == "dictionary" else None
        return dict(definition, description=baseline_description(item, definition.get("description") or fallback, limit=limit))

    _log("Phase 1: dictionaries")
    for item in merged["dictionary"].values():
        if item["status"] in (REUSE, REUSE_DIFFERS):
            record(item, "reused", id=(item.get("tenant") or {}).get("id"))
            continue
        if item["status"] not in (CREATE, RESTORE):
            record(item, "skipped", reason=item["reason"])
            continue
        d = described(item, item["definition"])
        try:
            kwargs, build_err = build_dict_kwargs(d, tenant["predefined"])
            if build_err:
                record(item, "skipped", reason=build_err)
                failed_names["dictionary"].add(item["name"])
                continue
            if item["status"] == RESTORE:
                tid = item["tenant"]["id"]
                resp = zia.dlp_dictionary.update_dict(tid, name=d["name"], custom_phrase_match_type=d["custom_phrase_match_type"],
                                                      dictionary_type="PATTERNS_AND_PHRASES", **kwargs)
                err = _extract_error(resp) if _extract_id(resp) is None else None
                if err:
                    failed_names["dictionary"].add(item["name"])
                    record(item, "failed", error=err)
                else:
                    dict_ids[item["name"]] = tid
                    record(item, "restored", id=tid, drift=item.get("drift"))
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
        if item["status"] not in (CREATE, RESTORE):
            record(item, "skipped", reason=item["reason"])
            continue
        deps_failed = [n for _, n in item["depends_on"] if n in failed_names["dictionary"]]
        if deps_failed:
            failed_names["engine"].add(item["name"])
            record(item, "skipped", reason="dependency failed: " + ", ".join(deps_failed))
            continue
        e = described(item, item["definition"], "Imported engine")
        try:
            expr, unresolved = resolve_engine_expression(e["expression"], dict_ids)
            if unresolved:
                failed_names["engine"].add(item["name"])
                record(item, "skipped", reason="unresolved dictionaries: " + ", ".join(unresolved))
                continue
            if item["status"] == RESTORE:
                eid = item["tenant"]["id"]
                resp = zia.dlp_engine.update_dlp_engine(eid, name=e["name"], engine_expression=expr, custom_dlp_engine=True,
                                                        description=e.get("description", "Imported engine"))
                err = _extract_error(resp) if _extract_id(resp) is None else None
                if err:
                    failed_names["engine"].add(item["name"])
                    record(item, "failed", error=err)
                else:
                    engine_ids[item["name"]] = eid
                    record(item, "restored", id=eid, drift=item.get("drift"))
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
        if item["status"] not in (CREATE, RESTORE):
            record(item, "skipped", reason=item["reason"])
            continue
        p = described(item, item["definition"])
        deps_failed = [n for _, n in item["depends_on"] if n in failed_names["engine"]]
        if deps_failed:
            record(item, "skipped", reason="dependency failed: " + ", ".join(deps_failed))
            continue
        ids = [engine_ids[n] for n in p.get("engines", []) if n in engine_ids and engine_ids[n] is not None]
        if len(ids) != len(p.get("engines", [])):
            record(item, "skipped", reason="one or more engines could not be resolved to an ID")
            continue
        channel = item.get("channel") or pc.channel_of(p)
        try:
            payload = pc.build_payload(channel, p, ids, item.get("resolved") or {}, use_rank_0=use_rank_0)
            if item["status"] == RESTORE:
                existing = item["tenant"]
                # Keep the rule where the admin placed it; only its content is restored.
                payload["order"] = existing.get("order") or payload.get("order")
                resp = pc.update_rule(zia, channel, existing["id"], payload)
                err = _extract_error(resp) if _extract_id(resp) is None else None
                if err:
                    record(item, "failed", error=err, channel=channel)
                else:
                    record(item, "restored", id=existing["id"], channel=channel, drift=item.get("drift"))
                continue
            resp = pc.add_rule(zia, channel, payload)
            new_id = _extract_id(resp)
            if new_id:
                record(item, "created", id=new_id, channel=channel)
            else:
                record(item, "failed", error=_extract_error(resp), channel=channel)
        except Exception as ex:  # noqa: BLE001
            record(item, "failed", error=str(ex)[:200], channel=channel)

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
            # Rules: every policy that should now exist (created or reused) must be listed by its channel API.
            expected: Dict[str, List[str]] = {}
            for item in merged["policy"].values():
                if src["id"] in item["packs"] and item["status"] in AVAILABLE_STATUSES:
                    expected.setdefault(item.get("channel") or pc.channel_of(item["definition"]), []).append(item["name"])
            rules_check: Dict[str, Any] = {}
            for channel, names in expected.items():
                present, err = pc.list_rule_names(zia, channel)
                if err or present is None:
                    rules_check[channel] = {"total": len(names), "ok": 0, "missing": names, "error": err}
                    verification[src["id"]]["all_good"] = False
                    continue
                missing_rules = [n for n in names if n not in present]
                rules_check[channel] = {"total": len(names), "ok": len(names) - len(missing_rules), "missing": missing_rules}
                if missing_rules:
                    verification[src["id"]]["all_good"] = False
            verification[src["id"]]["rules"] = rules_check

    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    wrote = bool(counts.get("created") or counts.get("modified") or counts.get("restored"))
    if counts.get("failed"):
        status = "partial" if wrote else "failed"
    else:
        status = "applied"
    return {
        "status": status,
        "summary": counts,
        "results": results,
        "verification": verification,
        "plan_hash": plan_hash,
        "elapsed_seconds": round(time.time() - started, 2),
        "activation_required": wrote,
    }
