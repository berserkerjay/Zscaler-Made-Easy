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

import functools
import re
import hashlib
import json
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pack_channels as pc
import pack_ops as ops
from dlp_importer import (resolve_template, engine_limit_problems, heal_predefined_names, norm_name,
    DICT_DESCRIPTION_MAX,
    ENGINE_DESCRIPTION_MAX,
    EMPTY_DICT_REASON,
    fit_description,
    _load_json,
    _nx,
    _obj_to_dict,
    _resolve_configs,
    build_dict_kwargs,
    engine_references,
    prune_engine_terms,
    load_pack_metadata,
    resolve_engine_expression,
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
RESTORE = "restore"                      # converge mode only: baseline object differs and will be overwritten

BLOCKING_STATUSES = {CONFLICT, BLOCKED_DEPENDENCY, SKIP_EMPTY}
AVAILABLE_STATUSES = {CREATE, REUSE, REUSE_DIFFERS, RESTORE}
WRITE_STATUSES = {CREATE, MODIFY, RESTORE}

# Provenance marker stamped into the description of every object a
# baseline creates. Lets admins (and the next journey check) see which
# objects came from which baseline version.
BASELINE_MARK = "[DLP-Check baseline"
PACK_MARK = "[DLP-Check pack"          # provenance tag for packs without a baseline section

# The tag names the assessor who deployed the pack ("[Jane Doe pack pci v2]"),
# not the tool. DEFAULT_BY is used only when no assessor name is given, and
# is what every tag written before the assessor name was used says, so the
# recognisers below match both. A tag is always the END of a description
# (the deploy appends it; fit_description keeps it whole), which is what
# keeps "[Q3 baseline review]" in a customer's own text from matching.
DEFAULT_BY = "DLP-Check"
BY_MAX = 40          # UTF-8 bytes (ZIA measures descriptions in bytes), so the tag always fits
_BY_BAD = re.compile(r"[\[\]\x00-\x1f\x7f]+")
# A name that begins like the tool's own legacy tag ("DLP-Check pack alpha")
# would put the literal "[DLP-Check pack alpha" marker into another pack's tag.
_BY_FORGED = re.compile(r"(?i)^dlp-check(?=\s+(?:pack|baseline)\b)")
_TAG_SUFFIX = (r"(?P<suffix>(?: Measured on every journey check, never overwritten\.)?(?: Deployed DISABLED; enable once reviewed\.)?"
               r"(?: Terraform-managed\.?)?)")
_TAG_VER = r"(?: v(?P<ver>[^\[\]\r\n]*))?"     # versions are free text (pack.json), spaces included
_TAG_BY = r"\[(?P<by>[^\[\]\r\n]{1,60}?) (?P<kind>baseline|pack) "
_TAG_BODY = _TAG_BY + r"(?P<pack>[^\s\[\]]+)" + _TAG_VER + r"\]" + _TAG_SUFFIX
MARK_RE = re.compile(r"\s*" + _TAG_BODY + r"\s*$")
_LOOKS_VER = re.compile(r"\d")


@functools.lru_cache(maxsize=512)
def _id_re(pack_id: str, anywhere: bool = False) -> "re.Pattern":
    """A tag for exactly this pack id (which may contain spaces), at the end
    of a description or, with `anywhere`, wherever it stands."""
    body = _TAG_BY + "(?P<pack>" + re.escape(pack_id) + ")" + _TAG_VER + r"\]" + _TAG_SUFFIX
    return re.compile(r"\s*" + body + ("" if anywhere else r"\s*$"))


def attribution(assessor: Any) -> str:
    """The name a provenance tag carries: the assessor's name, cleaned so it
    cannot break the tag (no brackets or control characters, at most
    BY_MAX UTF-8 bytes, never the tool's own "DLP-Check pack|baseline"
    marker), or DEFAULT_BY when there is none."""
    s = " ".join(_BY_BAD.sub(" ", str(assessor or "")).split())
    s = _BY_FORGED.sub("DLP Check", s)
    s = s.encode("utf-8")[:BY_MAX].decode("utf-8", errors="ignore").strip()
    return s or DEFAULT_BY


def assessor_name(assessor: Any) -> str:
    """The sanitized assessor name a record stores: attribution() of a given
    name, or blank when none was given (the tag then says DLP-Check)."""
    given = " ".join(_BY_BAD.sub(" ", str(assessor or "")).split())
    return attribution(assessor) if given else ""


def _counts(m: Any, known: Optional[Set[str]]) -> bool:
    """Whether a tag match at the end of a description is a real provenance
    tag: the tool's own "[DLP-Check ..." form, an assessor's tag for a known
    pack id, or an assessor's tag for any other pack id that carries what
    every deploy writes (a version, or the deploy's closing sentence), so an
    object deployed from a pack since gone from the library is still found
    while a customer's "[Q3 pack review]" is not."""
    if m.group("by") == DEFAULT_BY or (known is not None and m.group("pack") in known):
        return True
    return bool(m.group("suffix")) or bool(_LOOKS_VER.match(m.group("ver") or ""))


def has_mark(desc: Any, *, pack_id: Optional[str] = None, kind: Optional[str] = None) -> bool:
    """Whether a description carries a deploy's provenance tag, optionally
    for one pack id and/or kind ("baseline" / "pack"). A tag naming an
    assessor counts only at the end of the description, and with a pack id
    only for that pack id; a customer's "[Q3 baseline review]" never
    qualifies."""
    d = str(desc or "")
    legacy = [BASELINE_MARK] if kind == "baseline" else [PACK_MARK] if kind == "pack" else [BASELINE_MARK, PACK_MARK]
    m = MARK_RE.search(d)
    if pack_id is not None:
        pm = _id_re(str(pack_id)).search(d)
        if pm and (kind is None or pm.group("kind") == kind):
            return True
        if not pm and m and m.group("by") != DEFAULT_BY and _counts(m, None):
            return False      # the description ends in another pack's tag
        return any(f"{mk} {pack_id}" in d for mk in legacy)
    if m and (kind is None or m.group("kind") == kind) and _counts(m, None):
        return True
    return any(mk in d for mk in legacy)


def library_ids() -> Set[str]:
    """The ids of every pack in the library (shipped and uploaded): the
    pack ids an assessor's tag is recognised for when no pack is named."""
    try:
        from dlp_importer import discover_packs
        return {str(p["id"]) for p in discover_packs()}
    except Exception:  # noqa: BLE001 — no library: only "[DLP-Check ..." tags count
        return set()


def tag_pack(desc: Any, known: Optional[Iterable[str]] = None) -> Optional[str]:
    """The pack id inside a provenance tag, or None. Pack ids in `known`
    are matched exactly (spaces included); any other tag counts as _counts
    says (the tool's own, or one carrying a version or deploy sentence)."""
    d = str(desc or "")
    ks = set(known) if known is not None else None
    for k in sorted(ks or (), key=len, reverse=True):
        if k and k in d and _id_re(k).search(d):
            return k
    m = MARK_RE.search(d)
    if m and _counts(m, ks):
        return m.group("pack")
    for mk in (BASELINE_MARK, PACK_MARK):
        if mk in d:
            rest = d.split(mk, 1)[1].strip()
            return rest.split("]", 1)[0].split(" v")[0].strip() or None
    return None


def strip_mark(base: Any, known: Optional[Iterable[str]] = None) -> str:
    """A description without its provenance tag: the tool's own
    "[DLP-Check ..." tag (and anything after it, as before), an assessor's
    tag for a pack id in `known` wherever it stands (text an admin added
    after it is kept), and a tag at the end that _counts. Customer text
    such as "[Q3 pack review]" is kept."""
    s = str(base or "")
    ks = set(known) if known is not None else None
    for k in sorted(ks or (), key=len, reverse=True):
        if k and k in s:
            s = _id_re(k, True).sub(lambda m: "" if m.group("by") != DEFAULT_BY else m.group(0), s)
    m = MARK_RE.search(s)
    if m and _counts(m, ks):
        s = s[:m.start()]
    for mk in (PACK_MARK, BASELINE_MARK):
        if mk in s:
            s = s.split(mk, 1)[0]
    return s.strip()

LogFn = Optional[Callable[[str], None]]


# ---------------------------------------------------------------------------
# Baselines and the data-governance journey
# ---------------------------------------------------------------------------
#
# A pack whose pack.json carries `"baseline": {...}` is a BASELINE: the
# reference definition a tenant is measured against. Deploying it works
# in a GREENFIELD tenant (nothing exists: the whole pack is created) and
# in a BROWNFIELD tenant (some objects exist: they are kept exactly as the
# customer has them, only what is missing is created). Nothing the
# customer changed is ever overwritten by default — an enabled rule, a
# hardened action or a tuned dictionary is the customer's progress, not
# drift to revert.
#
# After deployment the same comparison answers "where is this tenant on
# the journey?": every baseline object is missing, deployed (present but
# off), monitoring (on, non-enforcing), enforcing, or customized, and the
# stages below roll that up into one position plus the next steps.
#
# `restore_drift=True` (explicit, off by default, not offered in the
# guided UI) switches a deploy to CONVERGE mode, where differing objects
# are overwritten with the baseline definition. Use it only when the
# customer has asked for the tenant to be reset to the reference.

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


def baseline_description(item: Dict[str, Any], base: Optional[str], *, limit: Optional[int] = None, by: Any = None) -> str:
    """Description with the provenance tag appended (idempotent). `limit`
    clamps the total length (dictionaries: 255) without losing the tag.
    `by` is the assessor's name the tag carries (DEFAULT_BY when blank)."""
    b = item.get("baseline") or {}
    tag = f"[{attribution(by)} baseline {b.get('pack', '?')}{(' v' + b['version']) if b.get('version') else ''}] Measured on every journey check, never overwritten."
    if item.get("kind") == "policy":
        tag += " Deployed DISABLED; enable once reviewed."
    base = strip_mark(base, known={b.get('pack', '?')})
    if limit:
        return fit_description(base, tag, limit)
    return f"{base} {tag}".strip()


def pack_description(item: Dict[str, Any], base: Optional[str], *, limit: Optional[int] = None, by: Any = None) -> str:
    """Provenance tag for a pack that is not a baseline, so a removal can
    find its objects by tag instead of by name alone (idempotent). `by` is
    the assessor's name the tag carries (DEFAULT_BY when blank)."""
    ver = str(item.get("pack_version") or "")
    tag = f"[{attribution(by)} pack {item.get('pack', '?')}{(' v' + ver) if ver else ''}]"
    if item.get("kind") == "policy":
        tag += " Deployed DISABLED; enable once reviewed."
    base = strip_mark(base, known={item.get('pack', '?')})
    if limit:
        return fit_description(base, tag, limit)
    return f"{base} {tag}".strip()


def _has_mark(obj: Any, pack_id: Optional[str] = None) -> bool:
    """Whether a tenant object carries a baseline tag: the tool's own, or
    an assessor's for this baseline's pack id."""
    d = _field(obj, "description", default="") if not isinstance(obj, str) else obj
    return has_mark(d, kind="baseline") or (pack_id is not None and has_mark(d, kind="baseline", pack_id=pack_id))


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


_field = pc._field   # one implementation, shared with pack_channels


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

def load_sources(packs: Sequence[Dict[str, Any]], channel_targets: Optional[Dict[str, Sequence[str]]] = None) -> List[Dict[str, Any]]:
    """Load every selected pack. `packs` items need `id` and `dir`.
    `channel_targets` (pack id → DLP channels) narrows or extends the
    pack's rules per channel; see pack_channels.apply_channel_targets."""
    sources = []
    for p in packs:
        configs = _resolve_configs(p["dir"])
        meta = load_pack_metadata(p["dir"])
        # Like ship_monitor for rules: a dictionary named like one of ZIA's
        # predefined display names is renamed here, once, so the plan, the
        # deploy, a removal, the journey and Terraform all see the same name.
        dictionaries, engines, renamed = heal_predefined_names(_load_json(configs, "dlp_dictionaries.json"), _load_json(configs, "dlp_engines.json"))
        policies = pc.ship_monitor(pc.expand_sub_rules(_load_json(configs, "dlp_policies.json")))
        targets = (channel_targets or {}).get(p["id"])
        baseline = baseline_meta(meta, p["id"])
        policies, note = pc.apply_channel_targets(
            policies, targets, pack_name=meta.get("name", p["id"]), prefix=(baseline or {}).get("prefix") or "",
            engine_names=[e.get("name") for e in engines if e.get("name")], pack_id=p["id"])
        sources.append({
            "id": p["id"],
            "name": meta.get("name", p["id"]),
            "dir": p["dir"],
            "dictionaries": dictionaries,
            "engines": engines,
            "policies": policies,
            "app_groups": _load_json(configs, "endpoint_application_groups.json"),
            "tweaks": meta.get("confidence_tweaks"),
            "baseline": baseline,
            "version": str(meta.get("version") or ""),
            "channel_note": note,
            "renamed": renamed,
        })
    return sources


def dict_signature(d: Dict[str, Any], predefined_name_to_id: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Content-only view of a pack dictionary, used to compare packs with
    each other and with the tenant."""
    predefined_name_to_id = predefined_name_to_id or {}
    if d.get("predefined_clone"):
        template = d.get("dict_template_id") or resolve_template(d.get("dict_template_name"), predefined_name_to_id) or d.get("dict_template_name")
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
        "confidence": None,   # a custom dictionary has no confidence score in ZIA
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
        "confidence": None,
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


def app_group_signature(g: Dict[str, Any]) -> Dict[str, Any]:
    """Content of an endpoint application group: the catalogue IDs it holds."""
    return {"resources": sorted(str(x) for x in (g.get("resources") or []))}


def _plan_app_groups(items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], *, restore: bool = False) -> None:
    """Endpoint application groups: create when missing, keep when present."""
    known = tenant["channels"].get("app_groups") or {}
    err = tenant["channels"].get("app_groups_error")
    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        problems = ops.validate("app_group", dict(item["definition"], name=name))
        if problems:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = "Invalid application group in the pack: " + "; ".join(problems) + "."
            continue
        if err:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = f"Endpoint application groups could not be listed ({err}); the Endpoint DLP feature is probably not licensed."
            continue
        existing = known.get(name)
        if existing is not None:
            item["tenant"] = {"id": existing.get("id"), "resources": existing.get("resources") or []}
            same = sorted(existing.get("resources") or []) == app_group_signature(item["definition"])["resources"]
            if same:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant with the same applications; nothing to do."
            elif item.get("baseline") and restore:
                item["status"] = RESTORE
                item["drift"] = ["resources"]
                item["reason"] = "Differs from the policy pack (applications). Converge mode: the group will be overwritten."
            else:
                item["status"] = REUSE_DIFFERS
                item["drift"] = ["resources"]
                item["reason"] = ("Already in the tenant with a different application list. Kept exactly as the customer has it; "
                                  "the rules below use the tenant's group.")
                item["warnings"].append("customized in tenant" if item.get("baseline") else "tenant version differs from pack")
            continue
        if not (item["definition"].get("resources") or []):
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = "The application group lists no applications (resources), so it cannot be created."
            continue
        item["status"] = CREATE
        n = len(item["definition"].get("resources") or [])
        item["reason"] = f"Will be created as a new Endpoint DLP application group with {n} application(s) from the Zscaler catalogue."


def merge_sources(sources: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Merge all packs into name-keyed maps per kind, recording provenance
    and flagging cross-pack conflicts."""
    merged: Dict[str, Dict[str, Dict[str, Any]]] = {"dictionary": {}, "engine": {}, "app_group": {}, "policy": {}}
    sig_fns = {
        "dictionary": lambda d: _canonical(dict_signature(d)),
        "engine": lambda e: _norm_expr(e.get("expression", "")),
        "app_group": lambda g: _canonical(app_group_signature(g)),
        "policy": lambda p: _canonical(policy_signature(p)),
    }
    for src in sources:
        for kind, key in (("dictionary", "dictionaries"), ("engine", "engines"), ("app_group", "app_groups"), ("policy", "policies")):
            for definition in src.get(key) or []:
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
                        "baseline": src.get("baseline"), "pack": src["id"], "pack_version": src.get("version") or "", "drift": None, "adopt": False,
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

def fetch_tenant(client, need: Optional[Dict[str, Any]] = None, log: LogFn = None) -> Dict[str, Any]:
    """Read everything the plan needs from the tenant: dictionaries,
    engines and web DLP rules always; other channels' rules and their
    prerequisites (SaaS tenants, notification templates, labels) only
    when `need` (see pack_channels.needs) says the packs use them.
    Never raises: each failure is recorded and `reachable` reflects it.
    `log` gets one line per read (a full read is many API calls and can
    take a minute; it must never look like a hang)."""
    _log = log or (lambda m: None)
    started = time.time()
    snap: Dict[str, Any] = {
        "reachable": True, "errors": [], "unreadable": {},
        "dictionaries": {}, "predefined": {}, "engines": {}, "rules": [],
        "channels": {"rules": {}, "errors": {}, "casb_tenants": None, "casb_error": None,
                     "templates": None, "templates_error": None, "labels": None, "labels_error": None},
    }
    zia = client.zia
    if need and (need["channels"] - {pc.WEB} or need["casb"] or need["templates"] or need["labels"] or need.get("app_classes")):
        snap["channels"] = pc.fetch_channel_state(zia, need, log=_log)
    _log("Reading the tenant: DLP dictionaries (custom and predefined)…")
    try:
        dicts, err = _nx(zia.dlp_dictionary.list_dicts())
        if err:
            raise RuntimeError(str(err))
        _log(f"Reading the tenant: DLP dictionaries: {len(dicts or [])} found.")
        for d in dicts or []:
            name = str(_field(d, "name", default="") or "").strip()
            if not name:
                continue
            snap["dictionaries"][name] = d
            if not _field(d, "custom", default=False):
                snap["predefined"][name] = _field(d, "id")
                # A predefined dictionary is exported under its API code with the
                # portal's display name in the description ("CREDIT_CARD" /
                # "Credit Cards"); packs may reference either, so both resolve.
                disp = str(_field(d, "description", default="") or "").strip()
                if disp and disp not in snap["predefined"] and len(disp) <= 80:
                    snap["predefined"][disp] = _field(d, "id")
                from dlp_importer import predefined_candidates
                for alias in predefined_candidates(name):
                    snap["predefined"].setdefault(alias, _field(d, "id"))
    except Exception as e:  # noqa: BLE001 — surfaced to the user, not hidden
        snap["unreadable"]["dictionaries"] = str(e)[:200]
        snap["errors"].append(f"dictionaries: {str(e)[:200]}")

    _log("Reading the tenant: DLP engines…")
    try:
        lister = getattr(zia.dlp_engine, "list_dlp_engines", None) or zia.dlp_engine.list_dlp_engines_lite
        engines, err = _nx(lister())
        if err:
            raise RuntimeError(str(err))
        _log(f"Reading the tenant: DLP engines: {len(engines or [])} found.")
        for e in engines or []:
            name = str(_field(e, "name", default="") or "").strip()
            if name:
                snap["engines"][name] = e
    except Exception as e:  # noqa: BLE001
        snap["unreadable"]["engines"] = str(e)[:200]
        snap["errors"].append(f"engines: {str(e)[:200]}")

    _log("Reading the tenant: Web DLP rules…")
    try:
        rules, err = _nx(zia.dlp_web_rules.list_rules())
        if err:
            raise RuntimeError(str(err))
        _log(f"Reading the tenant: Web DLP rules: {len(rules or [])} found.")
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
        snap["unreadable"]["web DLP rules"] = str(e)[:200]
        snap["errors"].append(f"web DLP rules: {str(e)[:200]}")
    # A partial read still yields a plan: only when nothing could be listed
    # is the tenant unreachable. What could not be read is planned as new
    # (the API rejects duplicate names, so nothing is overwritten) and every
    # such item is marked unverified, with the permission that would fix it.
    snap["reachable"] = len(snap["unreadable"]) < 3
    # Each refused read with ZIA's status in front ("HTTP 403: Resource
    # Access Blocked"), so a 403 is never mistaken for a 429 or a timeout.
    _log(f"Tenant read in {time.time() - started:.0f} s"
         + ("; could not read: " + ", ".join(f"{k} ({ops.describe_error(e)})" for k, e in snap["unreadable"].items()) + "."
            if snap["unreadable"] else "."))
    return snap


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _norm_name(name: Any) -> str:
    """A name as ZIA compares it for duplicates: case and spacing ignored."""
    return norm_name(name)


def _lookup_ci(by_name: Dict[str, Any], name: str) -> Any:
    """The tenant object whose name matches `name` ignoring case and
    spacing, or None. Exact matches are found by the caller first."""
    want = _norm_name(name)
    for n, obj in by_name.items():
        if _norm_name(n) == want:
            return obj
    return None


def _predefined_display_names(tenant: Dict[str, Any]) -> Set[str]:
    """The names ZIA shows its predefined dictionaries under (the
    description of a predefined entry: CRED_LEAKAGE → "Private Key"),
    normalised. ZIA refuses a custom dictionary with one of these names."""
    cached = tenant.get("_predefined_display")
    if cached is None:
        cached = set()
        for n, d in tenant["dictionaries"].items():
            if _field(d, "custom", default=False):
                continue
            disp = _norm_name(_field(d, "description", default=""))
            if disp and disp != _norm_name(n):
                cached.add(disp)
        tenant["_predefined_display"] = cached
    return cached


def _plan_dictionaries(items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], *, restore: bool = False) -> None:
    predefined = tenant["predefined"]
    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        d = item["definition"]
        if d.get("predefined_clone"):
            template_name = d.get("dict_template_name")
            if not d.get("dict_template_id") and template_name and resolve_template(template_name, predefined) is None:
                item["depends_on"].append(("predefined", template_name))
        existing = tenant["dictionaries"].get(name)
        if existing is None:
            # ZIA compares names without regard to case; so does the plan.
            existing = _lookup_ci(tenant["dictionaries"], name)
        if existing is None and _norm_name(name) in _predefined_display_names(tenant):
            # The tenant shows a predefined dictionary under this display name
            # (CRED_LEAKAGE is shown as "Private Key") and refuses a second
            # dictionary with that name: said in the plan, not at write time.
            item["status"] = CONFLICT
            item["reason"] = ("ZIA already shows one of Zscaler's predefined dictionaries under this name and refuses a second "
                              "dictionary with the same name ('Duplicate DLP dictionary names are not allowed'). Rename the policy "
                              "pack dictionary, for example by adding what distinguishes it (' - Medium Confidence').")
            continue
        if existing is not None:
            pack_sig = dict_signature(d, predefined)
            ten_sig = tenant_dict_signature(existing)
            is_custom = bool(_field(existing, "custom", default=True))
            item["tenant"] = {"id": _field(existing, "id"), "custom": is_custom}
            baseline = item.get("baseline")
            if baseline and not is_custom:
                item["status"] = CONFLICT
                item["reason"] = ("A predefined Zscaler dictionary already has this name; a policy pack cannot manage "
                                  "predefined objects. Rename the policy pack dictionary.")
                continue
            if baseline:
                item["adopt"] = not _has_mark(existing, (baseline or {}).get("pack"))
            if ten_sig is None:
                item["status"] = REUSE
                item["reason"] = "Already in the tenant; existing dictionary will be used (content not compared — tenant returned a summary only)."
            elif ten_sig == pack_sig:
                item["status"] = REUSE
                item["reason"] = ("In sync with the policy pack; nothing to do." if baseline
                                  else "Already in the tenant with identical content; nothing to do.")
            elif baseline and restore:
                diffs = [k for k in pack_sig if pack_sig.get(k) != ten_sig.get(k)]
                item["status"] = RESTORE
                item["drift"] = diffs
                item["reason"] = (
                    f"Differs from the policy pack ({', '.join(diffs) or 'content'}). Converge mode: "
                    "the dictionary will be overwritten with the policy pack definition."
                )
                item["warnings"].append("differs from policy pack")
            elif baseline:
                diffs = [k for k in pack_sig if pack_sig.get(k) != ten_sig.get(k)]
                item["status"] = REUSE_DIFFERS
                item["drift"] = diffs
                item["reason"] = (
                    f"Customized in the tenant ({', '.join(diffs) or 'content'} differ from the policy pack). "
                    "Kept exactly as the customer has it; the policy pack version is NOT applied."
                )
                item["warnings"].append("customized in tenant")
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
        problems = ops.validate("dictionary", d)
        if problems:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = "Outside ZIA's documented dictionary limits: " + "; ".join(problems) + "."
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


def _plan_engines(items: Dict[str, Dict[str, Any]], dict_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], *, restore: bool = False) -> None:
    # Every dictionary name that could satisfy a D:<name> reference.
    candidates: Dict[str, Any] = {n: n for n in tenant["dictionaries"]}
    candidates.update({n: n for n in (tenant.get("predefined") or {})})   # predefined ones by code, display name and alias
    candidates.update({n: n for n in dict_items})
    tenant_ids = {n: _field(t, "id") for n, t in tenant["dictionaries"].items()}

    for name, item in items.items():
        if item["status"] == CONFLICT:
            continue
        if name not in tenant["engines"]:
            # ZIA compares engine names without regard to case; so does the plan.
            twin = _lookup_ci(tenant["engines"], name)
            if twin is not None:
                tenant["engines"][name] = twin
        expr = item["definition"].get("expression", "")
        limit_problems = ops.validate("engine", dict(item["definition"], name=name))
        if limit_problems:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = "Outside ZIA's documented engine limits: " + "; ".join(limit_problems) + "."
            continue
        _, unresolved = resolve_engine_expression(expr, candidates)
        referenced = engine_references(expr, candidates)
        item["depends_on"] = [("dictionary", n) for n in referenced]
        missing = [u for u in unresolved]
        blocked_deps = [n for n in referenced if n in dict_items and dict_items[n]["status"] not in AVAILABLE_STATUSES]
        # A pack clone whose predefined template this tenant does not expose
        # is the same case as a missing predefined dictionary: drop its terms
        # from the engine (named in the plan) instead of blocking the engine
        # and every rule behind it.
        template_less = [n for n in blocked_deps
                         if dict_items[n]["status"] == BLOCKED_DEPENDENCY and any(k == "predefined" for k, _ in dict_items[n].get("depends_on") or [])]
        if template_less and not restore:
            missing = missing + [n for n in template_less if n not in missing]
            blocked_deps = [n for n in blocked_deps if n not in template_less]
        if missing and not blocked_deps and not restore:
            # A dictionary that exists in neither the packs nor the tenant is
            # a predefined one this tenant does not expose (or a typo). Rather
            # than skip the engine and every rule behind it, deploy the engine
            # without those terms and say so loudly.
            pruned_expr, dropped = prune_engine_terms(expr, missing, candidates)
            if pruned_expr and not engine_limit_problems(pruned_expr):
                item["definition"] = dict(item["definition"], expression=pruned_expr)
                item["pruned"] = dropped
                item.setdefault("warnings", []).append("deployed without " + ", ".join(dropped))
                expr = pruned_expr
                missing = []
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
                item["adopt"] = not _has_mark(existing, (baseline or {}).get("pack"))
            ten_expr = _field(existing, "engine_expression", "engineExpression")
            # A referenced dictionary the plan will CREATE has no ID yet, so
            # the tenant expression cannot be current. (A RESTORE keeps its
            # ID, so existing references to it stay valid.)
            deps_changing = [n for n in referenced if n in dict_items and dict_items[n]["status"] == CREATE]
            if ten_expr and all(n in tenant_ids and tenant_ids[n] is not None for n in referenced):
                pack_expr, _ = resolve_engine_expression(expr, tenant_ids)
                if _norm_expr(pack_expr) == _norm_expr(str(ten_expr)) and not (baseline and deps_changing):
                    item["status"] = REUSE
                    item["reason"] = ("In sync with the policy pack; nothing to do." if baseline
                                      else "Already in the tenant with the same expression; nothing to do.")
                elif baseline and restore:
                    item["status"] = RESTORE
                    item["drift"] = ["expression"]
                    item["reason"] = "Differs from the policy pack (expression). Converge mode: the engine will be overwritten with the policy pack expression."
                    item["warnings"].append("differs from policy pack")
                elif baseline:
                    item["status"] = REUSE_DIFFERS
                    item["drift"] = ["expression"]
                    item["reason"] = ("Customized in the tenant (expression differs from the policy pack). Kept exactly as the customer "
                                      "has it and used by the rules below; the policy pack expression is NOT applied.")
                    item["warnings"].append("customized in tenant")
                else:
                    item["status"] = REUSE_DIFFERS
                    item["reason"] = ("Already in the tenant with a different expression. The tenant's engine will be kept "
                                      "and used by the policies below; the pack's expression will NOT be applied.")
                    item["warnings"].append("tenant version differs from pack")
            elif baseline and deps_changing and restore:
                item["status"] = RESTORE
                item["drift"] = ["dictionaries"]
                item["reason"] = ("References dictionaries the policy pack is creating; converge mode: the engine will be "
                                  "rewritten against the policy pack dictionaries.")
            elif baseline and deps_changing:
                item["status"] = REUSE_DIFFERS
                item["drift"] = ["dictionaries"]
                item["reason"] = ("Exists in the tenant but references dictionaries the policy pack is about to create. Kept as-is; "
                                  "point it at the new dictionaries in the portal once they exist, or re-run in converge mode.")
                item["warnings"].append("customized in tenant")
            elif ten_expr and deps_changing:
                # The tenant's engine cannot use a dictionary that is not in
                # the tenant yet, so its expression certainly differs.
                item["status"] = REUSE_DIFFERS
                item["reason"] = ("Already in the tenant, but its expression cannot match the pack's (it does not use "
                                  + ", ".join(deps_changing) + ", which this deploy creates). The tenant's engine is kept and used by "
                                  "the rules below; the pack's expression is NOT applied.")
                item["warnings"].append("tenant version differs from pack")
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


def _plan_policies(items: Dict[str, Dict[str, Any]], engine_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], *,
                   restore: bool = False, app_group_items: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
    app_group_items = app_group_items or {}
    # Parents before their sub-rules, so a sub-rule can see its parent's status.
    ordered = sorted(items.items(), key=lambda kv: 1 if kv[1]["definition"].get("parent_rule") else 0)
    for name, item in ordered:
        if item["status"] == CONFLICT:
            continue
        p = item["definition"]
        channel = pc.channel_of(p)
        item["channel"] = channel
        problems = ops.validate("policy", p)
        if problems:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = f"Invalid policy definition in the pack: {'; '.join(problems)}."
            continue
        engine_names = [e for e in p.get("engines", [])] if pc.has_engines(channel) else []
        item["depends_on"] = [("engine", e) for e in engine_names]
        missing = [e for e in engine_names if e not in engine_items and e not in tenant["engines"]]
        blocked = [e for e in engine_names if e in engine_items and engine_items[e]["status"] not in AVAILABLE_STATUSES]
        if not engine_names and pc.has_engines(channel):
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
        # Endpoint DLP: application groups the pack creates, and the parent of a sub-rule.
        blocked_groups = [n for k, n in item["depends_on"] if k == "app_group"
                          and (app_group_items.get(n) or {}).get("status") not in (None, CREATE, REUSE, REUSE_DIFFERS, RESTORE)]
        if blocked_groups:
            item["status"] = BLOCKED_DEPENDENCY
            item["reason"] = "Can't be created — depends on blocked endpoint application group(s): " + ", ".join(blocked_groups) + "."
            continue
        if p.get("parent_rule"):
            parent = items.get(str(p["parent_rule"]))
            if parent is None:
                item["status"] = BLOCKED_DEPENDENCY
                item["reason"] = f"Sub-rule of '{p['parent_rule']}', which is not in the selected packs."
                continue
            if parent["status"] in BLOCKING_STATUSES:
                item["status"] = BLOCKED_DEPENDENCY
                item["reason"] = f"Sub-rule of '{p['parent_rule']}', which is blocked: {parent.get('reason', '')}"
                continue
        tenant_rules = {r["name"]: r for r in _tenant_rules_for(tenant, channel)}
        existing = tenant_rules.get(name)
        pack_action = pc.policy_action(p)
        if channel == pc.CLOUD_APP and item["resolved"].get("actions"):
            pack_action = ",".join(sorted(item["resolved"]["actions"]))
        if existing is not None:
            item["tenant"] = existing
            baseline = item.get("baseline")
            if baseline:
                item["adopt"] = not _has_mark(existing.get("description") or "", (baseline or {}).get("pack"))
                drift = _policy_drift(p, channel, existing, engine_items, tenant, pack_action=pack_action,
                                      resolved=item.get("resolved") or {})
                if drift and restore:
                    item["status"] = RESTORE
                    item["drift"] = drift
                    item["reason"] = (f"Differs from the policy pack ({', '.join(drift)}). Converge mode: the {pc.label(channel)} rule "
                                      "will be overwritten with the policy pack definition; its position in the policy is kept.")
                    item["warnings"].append("differs from policy pack")
                    if pc.is_enforcing(channel, pack_action):
                        item["warnings"].append("enforcing action")
                elif drift:
                    item["status"] = REUSE_DIFFERS
                    item["drift"] = drift
                    item["reason"] = (f"Customized in the tenant ({', '.join(drift)} differ from the policy pack): "
                                      f"{_journey_phrase(item, channel, existing, p)} Kept exactly as the customer has it.")
                    item["warnings"].append("customized in tenant")
                else:
                    item["status"] = REUSE
                    item["reason"] = f"Deployed as the policy pack defines it ({_journey_phrase(item, channel, existing, p)})."
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
        if p.get("parent_rule"):
            scope = f" as a sub-rule of '{p['parent_rule']}'"
        if item["resolved"].get("tenants"):
            scope = " scoped to " + ", ".join(t["name"] for t in item["resolved"]["tenants"])
        elif item["resolved"].get("cloud_applications"):
            scope = f" scoped to {len(item['resolved']['cloud_applications'])} cloud application(s)"
        elif item["resolved"].get("unscoped_note"):
            scope = f"; {item['resolved']['unscoped_note']}"
            item["warnings"].append("no email tenant filter")
        shown_action = pack_action if len(pack_action) <= 80 else f"{len(item['resolved'].get('actions') or [])} per-application actions"
        item["reason"] = f"Will be created as a new {pc.label(channel)} rule at the top of that policy (action {shown_action}){scope}."
        if pc.is_enforcing(channel, pack_action):
            item["warnings"].append("enforcing action")


def _rule_position(channel: str, existing: Dict[str, Any], p: Dict[str, Any]) -> str:
    """Journey position of an existing rule: deployed (present but off),
    monitoring (on, non-enforcing), enforcing (on, enforcing), relaxed
    (the pack ships it on but the tenant turned it off)."""
    state = str(existing.get("state") or "").upper()
    action = existing.get("action") or pc.policy_action(p)
    if state and state != "ENABLED":
        return "relaxed" if str(p.get("state", "ENABLED")).upper() == "ENABLED" else "deployed"
    return "enforcing" if pc.is_enforcing(channel, str(action)) else "monitoring"


_POSITION_PHRASE = {
    "deployed": "present but still disabled",
    "monitoring": "enabled in monitor mode",
    "enforcing": "enabled and enforcing",
    "relaxed": "the policy pack ships it enabled but the tenant has disabled it",
}


def _journey_phrase(item: Dict[str, Any], channel: str, existing: Dict[str, Any], p: Dict[str, Any]) -> str:
    pos = _rule_position(channel, existing, p)
    item["position"] = pos
    return _POSITION_PHRASE[pos] + (f", action {existing['action']}" if existing.get("action") and pos != "deployed" and len(str(existing["action"])) <= 60 else "")


def _policy_drift(p: Dict[str, Any], channel: str, existing: Dict[str, Any],
                  engine_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any],
                  *, pack_action: Optional[str] = None, resolved: Optional[Dict[str, Any]] = None) -> List[str]:
    """Fields on which an existing rule differs from its policy pack definition.
    Only fields the tenant snapshot carries are compared; anything the API
    does not echo back is left alone."""
    drift: List[str] = []
    resolved = resolved or {}
    want_action = pack_action if pack_action is not None else pc.policy_action(p)
    if existing.get("action") and existing["action"] != want_action:
        drift.append("action")
    if existing.get("state") and existing["state"] != p.get("state", "ENABLED"):
        drift.append("state")
    if p.get("severity") and existing.get("severity") and existing["severity"] != p["severity"]:
        drift.append("severity")
    if channel in pc.CONTROL_CHANNELS:
        apps = [str(a) for a in (p.get("applications") or [])] or list(resolved.get("cloud_applications") or [])
        if apps and existing.get("applications") and sorted(apps) != existing["applications"]:
            drift.append("applications")
        if p.get("url_categories") and existing.get("url_categories") and sorted(map(str, p["url_categories"])) != existing["url_categories"]:
            drift.append("url_categories")
        if p.get("file_types") and existing.get("file_types") and sorted(map(str, p["file_types"])) != existing["file_types"]:
            drift.append("file_types")
        if p.get("operation") and existing.get("operation") and existing["operation"] != p["operation"]:
            drift.append("operation")
        return drift
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


_CAMEL_RE = re.compile(r"(?<!^)(?=[A-Z])")


def dictionary_update_body(existing: Any, **changes: Any) -> Dict[str, Any]:
    """The whole dictionary as the tenant has it, with `changes` applied,
    for PUT /dlpDictionaries/{id}. A PUT replaces the object, so a body with
    only the changed field would reset what it leaves out (proximity,
    identifiers, the match type). Keys are snake_case like every other
    payload here; phrases and patterns go as (action, text) pairs, the
    form the SDK's update_dict turns back into API objects."""
    if hasattr(existing, "request_format"):
        raw = existing.request_format()
    elif hasattr(existing, "as_dict"):
        raw = existing.as_dict()
    else:
        raw = dict(existing or {})
    body: Dict[str, Any] = {}
    for k, v in raw.items():
        key = _CAMEL_RE.sub("_", str(k)).lower()
        if key == "id" or v is None:
            continue
        body[key] = v
    for key, field in (("phrases", "phrase"), ("patterns", "pattern")):
        items = body.get(key)
        if items:
            body[key] = [(_field(x, "action"), _field(x, field)) if not isinstance(x, (tuple, list)) else tuple(x) for x in items]
        elif key in body:
            del body[key]
    body.setdefault("dictionary_type", "PATTERNS_AND_PHRASES")
    body.setdefault("custom_phrase_match_type", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY")
    body.update(changes)
    return body


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


def _baseline_impacts(all_items: Sequence[Dict[str, Any]], restore: bool = False) -> List[Dict[str, Any]]:
    """One card per policy pack: greenfield (nothing exists yet, the
    whole pack is created) or brownfield (some objects exist and are kept
    as the customer has them; only what is missing is created)."""
    per: Dict[str, Dict[str, Any]] = {}
    for i in all_items:
        b = i.get("baseline")
        if not b:
            continue
        row = per.setdefault(b["pack"], {"meta": b, "present": 0, "customized": 0, "missing": 0, "blocked": 0,
                                          "restore": 0, "customized_names": [], "restore_names": []})
        st = i["status"]
        if st == RESTORE:
            row["restore"] += 1
            row["restore_names"].append(i["name"])
        elif st == CREATE:
            row["missing"] += 1
        elif st == REUSE_DIFFERS:
            row["present"] += 1
            row["customized"] += 1
            row["customized_names"].append(i["name"])
        elif st in (REUSE, NOOP):
            row["present"] += 1
        else:
            row["blocked"] += 1
    out: List[Dict[str, Any]] = []
    for pack_id, row in per.items():
        b = row["meta"]
        label = f"{b.get('name') or pack_id}{(' v' + b['version']) if b.get('version') else ''}"
        total = row["present"] + row["missing"] + row["blocked"] + row["restore"]
        if row["restore"]:
            names = ", ".join(row["restore_names"][:6]) + (f" +{len(row['restore_names']) - 6} more" if len(row["restore_names"]) > 6 else "")
            out.append({
                "type": "baseline_restore", "baseline": pack_id,
                "title": f"Converge mode: {row['restore']} object{'s' if row['restore'] != 1 else ''} will be overwritten with policy pack {label}",
                "detail": (f"You asked for the tenant to be reset to the reference. These objects differ from the policy pack and will be "
                           f"overwritten: {names}. If the customer changed any of them on purpose, stop and deploy without converge mode."),
                "severity": "warning",
            })
        elif row["present"] == 0 and row["blocked"] == 0:
            out.append({
                "type": "greenfield", "baseline": pack_id,
                "title": f"Greenfield for policy pack {label}: none of its {total} objects exist yet",
                "detail": ("The whole policy pack will be created from scratch, every rule DISABLED. This is the starting point of the "
                           "data governance journey; enabling rules moves the tenant along it."),
                "severity": "ok",
            })
        else:
            cust = (f" {row['customized']} of them {'has' if row['customized'] == 1 else 'have'} been customized by the customer "
                    f"({', '.join(row['customized_names'][:6])}{' +' + str(len(row['customized_names']) - 6) + ' more' if len(row['customized_names']) > 6 else ''}) "
                    "and stay exactly as they are." if row["customized"] else "")
            out.append({
                "type": "brownfield", "baseline": pack_id,
                "title": f"Brownfield for policy pack {label}: {row['present']} of {total} objects already exist, {row['missing']} will be created"
                         + (f", {row['blocked']} blocked" if row["blocked"] else ""),
                "detail": ("Existing objects are kept as the customer has them (enabled rules, hardened actions and tuned dictionaries "
                           "are progress, not drift)." + cust + " Only the missing objects are created, DISABLED. Objects the policy pack "
                           "does not define are never touched."),
                "severity": "info" if not row["blocked"] else "warning",
            })
    return out


# SaaS Security API rules are ordered per rule type and the API does not
# shuffle the others down for a new order 1 the way Web DLP does. A real
# tenant also refused the next free order outright ("Rule with rank 7 is
# not allowed at order 12") once a type held enough rules, so a refused
# order is answered by re-reading the type's rules and trying the orders
# ZIA can still accept, from the last one down, a bounded number of times.
MAX_SAAS_PLACEMENTS = 8


def _rank_refusal(err: Any) -> bool:
    """ZIA refused the rule's rank against the API client's admin rank
    (403 RBA_LIMITED 'Rule rank is higher than the admin rank.'): not an
    ordering problem, and no order will get past it."""
    return "admin rank" in str(err or "").lower()


def _order_refusal(err: Any) -> bool:
    e = str(err or "").lower()
    return ("order" in e or "rank" in e) and not _rank_refusal(err)


def _other_rank(payload: Dict[str, Any]) -> int:
    """The rank to try when ZIA refuses the one sent: 7 for 0, 0 for
    anything else. Rules ship at rank 0 so they always deploy; a tenant
    whose API client cannot use rank 0 gets them at rank 7 rather than
    not at all, and the log says so."""
    try:
        cur = int(payload.get("rank", 7) or 0)
    except (TypeError, ValueError):
        cur = 7
    return 7 if cur == 0 else 0


def _saas_orders_now(zia, saas_type: str) -> List[int]:
    """The orders the tenant currently holds for one SaaS rule type."""
    svc = getattr(zia, "casb_dlp_rules", None)
    if svc is None:
        return []
    try:
        lister = getattr(svc, "list_all_rules", None)
        data, err = pc._nx(lister()) if lister else pc._nx(svc.list_rules(saas_type))
    except Exception:  # noqa: BLE001
        return []
    if err:
        return []
    out = []
    for r in data or []:
        t = str(pc._field(r, "type", default="") or "")
        if t in ("", saas_type):
            out.append(int(pc._field(r, "order", default=0) or 0))
    return sorted(out)


# Key in a run's saas_next: the rank ZIA accepted after refusing the one a
# rule asked for. Later SaaS rules of the run start there, so a pack's SaaS
# rules cost one refused request, not one each: a burst of refused writes
# makes ZIA block the API client (Resource Access Blocked).
_ACCEPTED_RANK = "__accepted_rank__"


def _add_saas_rule(zia, payload: Dict[str, Any], saas_orders: Dict[str, int], saas_next: Dict[str, int], _log, name: str) -> ops.Outcome:
    """Create one SaaS rule at an order ZIA accepts, through the shared path."""
    t = str(payload.get("type") or "ANY")
    first = saas_next.get(t) or (saas_orders.get(t, 0) + 1)
    tried: List[int] = []
    errors: List[str] = []
    rank_was = None
    learned = saas_next.get(_ACCEPTED_RANK)
    if learned is not None and payload.get("rank") != learned:
        rank_was, payload["rank"] = payload.get("rank"), learned
        _log(f"[saas] '{name}': starting at rank {learned}; ZIA refused rank {rank_was} earlier in this run (admin rank)")

    def attempt(order: int) -> ops.Outcome:
        payload["order"] = order
        tried.append(order)
        out = ops.create(zia, "policy", payload, channel=pc.SAAS, name=name, log=_log)
        if not out.ok:
            errors.append(out.as_error() or "")
        elif out.id is None:
            errors.append("the API returned no id")
        return out

    def placed(out: ops.Outcome) -> bool:
        return out.ok and out.id is not None

    out = attempt(first)
    if not placed(out) and _rank_refusal(errors[-1]):
        # A real tenant refused rank 0 with 'Rule rank is higher than the
        # admin rank' and every order tried after it: the rank, not the
        # order, was the problem. Try the other rank once, same order; an
        # order refusal after that goes through the order retry below.
        rank_was, payload["rank"] = payload.get("rank"), _other_rank(payload)
        _log(f"[saas] '{name}': ZIA refused rank {rank_was} ({errors[0]}); trying rank {payload['rank']} — "
             f"the API client's admin rank does not allow rank {rank_was} on SaaS rules")
        out = attempt(first)
    if not placed(out) and _order_refusal(errors[-1]):
        current = _saas_orders_now(zia, t)
        top = max(current) if current else 0
        candidates = [top + 1, top] + list(range(top - 1, 0, -1))
        for order in candidates:
            if len(tried) >= MAX_SAAS_PLACEMENTS:
                break
            if order in tried or order < 1:
                continue
            out = attempt(order)
            if placed(out) or not _order_refusal(errors[-1]):
                break
        if placed(out):
            _log(f"[saas] '{name}': ZIA refused order {', '.join(str(o) for o in tried[:-1])} ({errors[0]}); "
                 f"placed at order {payload['order']} after re-reading the tenant's {len(current)} {t} rule(s)")
        else:
            _log(f"[saas] '{name}': ZIA refused every order tried ({', '.join(str(o) for o in tried)}); last answer: {errors[-1]}")
    if placed(out) and rank_was is not None:
        payload["rank_note"] = f"rank {rank_was} refused by ZIA (admin rank); created at rank {payload['rank']}"
        _log(f"[saas] '{name}': created at rank {payload['rank']} instead of {rank_was}")
        saas_next[_ACCEPTED_RANK] = payload["rank"]
    if placed(out):
        saas_orders[t] = max(saas_orders.get(t, 0), int(payload["order"]))
        # The next rule of this type starts where this one landed, plus one.
        saas_next[t] = int(payload["order"]) + 1 if len(tried) > 1 else saas_orders[t] + 1
    return out


def _impacts(policy_items: Dict[str, Dict[str, Any]], tenant: Dict[str, Any], use_rank_0: bool) -> Tuple[List[Dict[str, Any]], List[str]]:
    impacts: List[Dict[str, Any]] = []
    blockers: List[str] = []
    new_rules = [i for i in policy_items.values() if i["status"] == CREATE]
    n_new = len(new_rules)

    by_channel: Dict[str, List[Dict[str, Any]]] = {}
    for i in new_rules:
        by_channel.setdefault(i.get("channel") or pc.channel_of(i["definition"]), []).append(i)

    for channel in pc.CHANNELS:
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
                       + ("For example: " + "; ".join(f"'{r['name']}' order {r['order']} → {r['order'] + n_ch}" for r in shifted) + "."
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
        enforcing_items = [i for i in list(new_rules) + [i for i in policy_items.values() if i["status"] == RESTORE]
                           if pc.is_enforcing(i.get("channel") or pc.channel_of(i["definition"]),
                                              ",".join(sorted((i.get("resolved") or {}).get("actions") or [])) or pc.policy_action(i["definition"]))]
        enforcing = [i["name"] for i in enforcing_items if str(i["definition"].get("state", "ENABLED")).upper() != "DISABLED"]
        enforcing_disabled = [i["name"] for i in enforcing_items if i["name"] not in enforcing]
        containment = [i for i in new_rules if (i.get("channel") or pc.channel_of(i["definition"])) in pc.CONTROL_CHANNELS]
        if containment:
            impacts.append({
                "type": "containment",
                "title": f"{len(containment)} containment rule{'s' if len(containment) != 1 else ''} (Cloud App Control, File Type, URL, SSL) run before DLP",
                "detail": ("ZIA evaluates Cloud App Control, File Type Control, URL Filtering and SSL Inspection before content inspection. "
                           "Once enabled, a block in these rules stops the transaction whether or not DLP would have matched: "
                           + ", ".join(i["name"] for i in containment[:6]) + ("…" if len(containment) > 6 else "") + "."),
                "severity": "info",
            })
        if enforcing:
            impacts.append({
                "type": "enforcement",
                "title": f"{len(enforcing)} new rule{'s' if len(enforcing) != 1 else ''} will ENFORCE rather than monitor",
                "detail": ("These rules block, quarantine or challenge user activity as soon as they are activated: " + ", ".join(enforcing)
                           + ". Best practice is to deploy in monitor mode first and switch to an enforcing action after tuning."),
                "severity": "warning",
            })
        elif enforcing_disabled:
            impacts.append({
                "type": "enforcement_disabled",
                "title": f"{len(enforcing_disabled)} new rule{'s' if len(enforcing_disabled) != 1 else ''} carr{'y' if len(enforcing_disabled) != 1 else 'ies'} an enforcing action but ship DISABLED",
                "detail": ("Nothing changes for users until you enable them one by one in the ZIA Admin Portal: " + ", ".join(enforcing_disabled)
                           + ". When you do, these rules block, decrypt or challenge user activity. Enable them after reviewing the monitor-mode "
                           "DLP incidents and confirming the application scope is right."),
                "severity": "info",
            })
        else:
            impacts.append({
                "type": "monitor_only",
                "title": "All new rules are DISABLED and monitor-only",
                "detail": "Every new rule is created DISABLED with a non-enforcing action, so nothing changes for users until you enable it "
                          "in the ZIA Admin Portal. Each rule's own description says the same, so this is clear from the tenant alone.",
                "severity": "ok",
            })
    impacts.append({
        "type": "activation",
        "title": "Changes must be activated to take effect",
        "detail": "ZIA saves configuration as pending. DLP-Check activates the changes automatically when the deployment finishes; if that call is blocked, activate in the ZIA Admin Portal (or with ziaActivator).",
        "severity": "info",
    })
    return impacts, blockers


def _rate_forecast(all_items: Sequence[Dict[str, Any]], client: Any = None) -> Dict[str, Any]:
    """This deploy's writes per ZIA rate-limit bucket (what it creates or
    changes, plus its one activation), forecast against the requests this
    app sent in the last hour."""
    import zia_rate
    counts = {"write": 0, "endpoint_rules": 0, "cloud_app": 0, "activate": 1}
    for i in all_items:
        if i["status"] not in WRITE_STATUSES:
            continue
        ch = (i.get("channel") or (pc.channel_of(i["definition"]) if i["kind"] == "policy" and i.get("definition") else None)) if i["kind"] == "policy" else None
        counts[zia_rate.bucket_of("POST", channel=ch, kind=i["kind"])] = counts.get(zia_rate.bucket_of("POST", channel=ch, kind=i["kind"]), 0) + 1
    return zia_rate.forecast(counts, key=zia_rate.key_of(client), tenant_label=zia_rate.labels_of(client))


def _rate_detail(f: Dict[str, Any]) -> str:
    parts = [f"{r['requests']} {r['label']} (limit {r['limits']}; {r['used_last_hour']} sent in the last hour)" for r in f["buckets"]]
    import zia_rate
    return "This run sends: " + "; ".join(parts) + ". " + zia_rate.history_text(f)


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
        "position": journey_position(item),
        "extension": bool(d.get("extension")),
        "pruned": item.get("pruned") or [],
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
        target = pc.target_action(d)
        out["detail"] = {"action": pc.policy_action(d), "severity": d.get("severity"),
                         # Every rule ships monitor-only and DISABLED; a rule designed to enforce carries the action to harden to.
                         "target_action": target if d.get("target_action") and pc.is_enforcing(channel, target) else None,
                         "engines": d.get("engines", []), "protocols": d.get("protocols", ["ANY_RULE"]),
                         "channel": channel, "channel_label": pc.label(channel),
                         "saas_type": d.get("saas_type"),
                         "tenants": [t["name"] for t in resolved.get("tenants", [])],
                         "notification_template": d.get("notification_template"),
                         "labels": d.get("labels", []),
                         "type": d.get("type"),
                         "applications": resolved.get("cloud_applications") or d.get("applications") or [],
                         "actions": resolved.get("actions") or d.get("actions") or [],
                         "url_categories": d.get("url_categories", []),
                         "file_types": d.get("file_types", []),
                         "operation": d.get("operation"),
                         "parent_rule": d.get("parent_rule"),
                         "data_transfer_method": d.get("data_transfer_method"),
                         "endpoint_application_groups": d.get("endpoint_application_groups", [])}
    elif item["kind"] == "app_group":
        out["detail"] = {"resources": [str(x) for x in (d.get("resources") or [])],
                         "applications": [f"{a.get('applicationName', a.get('name', '?'))} ({a.get('osType', '?')})" for a in (d.get("applications") or [])]}
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
    restore_drift: bool = False,
    channel_targets: Optional[Dict[str, Sequence[str]]] = None,
    tenant_cache: Optional[Dict[str, Any]] = None,
    log: LogFn = None,
) -> Dict[str, Any]:
    """Build the deployment plan for the selected packs without writing.
    `log` receives one line per tenant read (see fetch_tenant).

    `tenant_cache` (a dict the caller keeps across calls) makes several
    preflights against the same tenant read it once: the first call stores
    the snapshot (read for `tenant_cache["need"]` when the caller set it,
    a superset of every pack's needs), later calls plan from a copy.

    `channel_targets` (pack id → list of web/endpoint/saas/email) chooses
    which DLP channels each pack is deployed into: deselected channels
    are skipped, channels the pack has no rule for get a monitor-only
    extension rule with the pack's engines.

    `restore_drift` (converge mode) makes policy pack objects that differ from
    the reference RESTORE (overwrite) instead of being kept; it is off by
    default and never chosen for the user.

    `packs` items need `id` and `dir` (as returned by
    dlp_importer.discover_packs). `writes_enabled` is the server's write
    gate; when False the plan is blocked so the GUI can explain why."""
    started = time.time()
    if not packs:
        return {"status": "blocked", "blockers": ["No packs selected."], "items": [], "warnings": [],
                "impacts": [], "summary": {}, "packs": [], "plan_hash": "", "tenant": {"reachable": False}}

    targets_norm = {pid: pc.normalize_targets(t) for pid, t in (channel_targets or {}).items() if pc.normalize_targets(t) is not None}
    sources = load_sources(packs, targets_norm)
    merged = merge_sources(sources)
    need = pc.needs(i["definition"] for i in merged["policy"].values())
    if tenant_cache is not None:
        import copy
        if tenant_cache.get("snapshot") is None:
            tenant_cache["snapshot"] = fetch_tenant(client, tenant_cache.get("need") or need, log=log)
        tenant = copy.deepcopy(tenant_cache["snapshot"])
    else:
        tenant = fetch_tenant(client, need, log=log)
    options = {"use_rank_0": bool(use_rank_0), "apply_tweaks": bool(apply_tweaks), "restore_drift": bool(restore_drift),
               "channel_targets": {k: sorted(v) for k, v in sorted(targets_norm.items())}}

    blockers: List[str] = []
    if not tenant["reachable"]:
        blockers.append("Could not read the tenant's current configuration, so overlaps and dependencies can't be checked: "
                        + "; ".join(tenant["errors"]))
    read_only_note = ("The server is in read-only mode: this plan can be reviewed and exported but not deployed. "
                      "Click Enable write mode in Deploy Policy Packs (you type a confirmation phrase) where the page offers it; otherwise "
                      + __import__("security").write_enable_hint() + ".") if writes_enabled is False else ""

    unreadable = tenant.get("unreadable") or {}

    if tenant["reachable"]:
        _plan_dictionaries(merged["dictionary"], tenant, restore=restore_drift)
        _plan_engines(merged["engine"], merged["dictionary"], tenant, restore=restore_drift)
        _plan_app_groups(merged["app_group"], tenant, restore=restore_drift)
        tenant["channels"]["planned_app_groups"] = {n for n, i in merged["app_group"].items() if i["status"] in (CREATE, REUSE, REUSE_DIFFERS, RESTORE)}
        _plan_policies(merged["policy"], merged["engine"], tenant, restore=restore_drift, app_group_items=merged["app_group"])
        tweak_items = _plan_tweaks(sources, tenant, apply_tweaks)
        impacts, impact_blockers = _impacts(merged["policy"], tenant, use_rank_0)
        impacts = _baseline_impacts(list(merged["dictionary"].values()) + list(merged["engine"].values())
                                    + list(merged["app_group"].values()) + list(merged["policy"].values()), restore_drift) + impacts
        blockers.extend(impact_blockers)
        dependencies = pc.dependency_report(list(merged["policy"].values()), tenant["channels"], len(tenant["rules"]))
        for kind, key in (("dictionaries", "dictionary"), ("engines", "engine"), ("web DLP rules", "policy")):
            if kind in unreadable:
                for item in merged[key].values():
                    if item["status"] == CREATE and (key != "policy" or pc.channel_of(item["definition"]) == pc.WEB):
                        item["warnings"].append("unverified: the tenant's list could not be read, so an existing object of this name would make the create fail (never overwrite)")
    else:
        dependencies = []
        for kind in merged:
            for item in merged[kind].values():
                if item["status"] != CONFLICT:
                    item["status"] = BLOCKED_DEPENDENCY
                    item["reason"] = "Tenant unreachable — cannot verify."
        tweak_items, impacts = [], []

    all_items = (list(merged["dictionary"].values()) + list(merged["engine"].values())
                 + list(merged["app_group"].values()) + list(merged["policy"].values()) + tweak_items)

    summary: Dict[str, Any] = {}
    for kind in ("dictionary", "engine", "app_group", "policy", "tweak"):
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
    if tenant["reachable"] and unreadable:
        _perm = {"dictionaries": "DLP Dictionaries", "engines": "DLP Engines", "web DLP rules": "Web DLP Rules"}
        for kind, err in unreadable.items():
            warnings.append(f"Could not list the tenant's {kind} ({ops.describe_error(err)}). Those objects are planned as new and will be attempted; "
                            f"the API rejects a duplicate name, so nothing existing is overwritten. For a verified plan grant the "
                            f"API client '{_perm.get(kind, kind)}' read access.")
    for i in all_items:
        if i.get("pruned"):
            warnings.append(f"Engine '{i['name']}' will be created without {', '.join(i['pruned'])}: not a dictionary this tenant exposes. "
                            "Its expression will differ from the pack, so the journey check will show it as customized.")
        if i["status"] == CONFLICT:
            warnings.append(f"{i['kind'].title()} '{i['name']}' is defined differently in {', '.join(i['packs'])} — it and everything that depends on it will be skipped.")
        elif i["status"] == BLOCKED_DEPENDENCY:
            warnings.append(f"{i['kind'].title()} '{i['name']}' will be skipped: {i['reason']}")
        elif i["status"] == REUSE_DIFFERS and i.get("baseline"):
            warnings.append(f"{i['kind'].title()} '{i['name']}' is customized in the tenant ({', '.join(i.get('drift') or ['content'])}) — kept as-is.")
        elif i["status"] == REUSE_DIFFERS:
            warnings.append(f"{i['kind'].title()} '{i['name']}' already exists with different content — the tenant's version is kept.")
        elif i["status"] == RESTORE:
            warnings.append(f"{i['kind'].title()} '{i['name']}' differs from the policy pack ({', '.join(i.get('drift') or ['content'])}) — converge mode will overwrite it.")
        elif i["status"] == MODIFY:
            warnings.append(f"{i['name']}: {i['reason']}")
        elif i["status"] == SKIP_EMPTY:
            warnings.append(f"Dictionary '{i['name']}' has nothing to match on and will be skipped.")
    for imp in impacts:
        if imp.get("severity") == "warning":
            warnings.append(imp["title"])
    for src in sources:
        note = src.get("channel_note") or {}
        for w in note.get("warnings") or []:
            warnings.append(f"{src['name']}: {w}")
        if note.get("skipped_channels"):
            labels = ", ".join(pc.label(ch) for ch in note["skipped_channels"])
            warnings.append(f"{src['name']}: {labels} rules are packed but not selected ({len(note.get('skipped_rules') or [])} rule(s)); "
                            f"they will NOT be deployed. Tick the channel in the pack card to deploy them.")
        for old, new in src.get("renamed") or []:
            warnings.append(f"{src['name']}: dictionary '{old}' will be deployed as '{new}' — ZIA shows one of its predefined "
                            f"dictionaries under the original name and refuses a second dictionary with it. The pack file is unchanged.")
    if read_only_note:
        warnings.append(read_only_note)

    creates = sum(1 for i in all_items if i["status"] in WRITE_STATUSES)
    rate_forecast = _rate_forecast(all_items, client) if creates and not blockers else None
    if rate_forecast:
        rate_forecast["detail"] = _rate_detail(rate_forecast)
        if rate_forecast["severity"] != "ok":
            warnings.insert(0, f"ZIA rate limits: {rate_forecast['verdict']}")
    if tenant["reachable"] and creates == 0 and not blockers:
        if any(s.get("baseline") for s in sources):
            blockers.append("Nothing to deploy: every policy pack object already exists in the tenant. Use the journey check to see how far the tenant has taken them.")
        else:
            blockers.append("Nothing to deploy: everything in the selected packs already exists in the tenant or is blocked.")

    status = "blocked" if blockers else ("warnings" if warnings else "ready")
    public_items = [_public_item(i) for i in all_items]
    report = {
        "status": status,
        "packs": [{"id": s["id"], "name": s["name"], "dictionaries": len(s["dictionaries"]),
                   "engines": len(s["engines"]), "policies": len(s["policies"]), "app_groups": len(s.get("app_groups") or []),
                   "baseline": s.get("baseline"), "channels": s.get("channel_note"), "renamed": s.get("renamed") or []} for s in sources],
        "baselines": baseline_status_rows(all_items, sources),
        "tenant_mode": tenant_mode(all_items, sources, tenant) if tenant["reachable"] else None,
        "options": options,
        "tenant": {"reachable": tenant["reachable"], "errors": tenant["errors"], "unreadable": dict(tenant.get("unreadable") or {}),
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
        "rate_forecast": rate_forecast,
        "dependencies": dependencies,
        "read_only": bool(read_only_note),
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


# ---------------------------------------------------------------------------
# The data-governance journey
# ---------------------------------------------------------------------------
#
# Every baseline object has a POSITION in the tenant:
#   missing     not there yet (plan will create it)
#   deployed    present, matches the baseline, rule still DISABLED
#   monitoring  rule ENABLED with a non-enforcing action (ALLOW, report)
#   enforcing   rule ENABLED with an enforcing action (BLOCK, DECRYPT, ...)
#   customized  present but content differs from the baseline (kept)
#   relaxed     the baseline ships it enabled, the tenant turned it off
#   blocked     cannot be created (missing prerequisite / conflict)
# Stages roll those up. A stage is reached when every object it needs is
# at or beyond the required position; the tenant's stage is the highest
# one with every earlier stage also reached.

POSITIONS = ("missing", "deployed", "monitoring", "enforcing", "customized", "relaxed", "blocked")

STAGES = [
    {"n": 1, "key": "foundation", "name": "Foundation",
     "what": "Dictionaries and engines exist, so the tenant can recognise the data the policy pack is about."},
    {"n": 2, "key": "deployed", "name": "Policies deployed",
     "what": "Every rule of the policy pack exists in the tenant (still disabled is fine)."},
    {"n": 3, "key": "visibility", "name": "Visibility",
     "what": "SSL Inspection decrypts the risky application classes and the DLP rules are enabled, so incidents are being logged."},
    {"n": 4, "key": "containment", "name": "Containment",
     "what": "Cloud App Control, File Type Control and URL Filtering rules are enabled: risky uploads, shares and unknown destinations are stopped before content inspection."},
    {"n": 5, "key": "enforcement", "name": "Enforcement",
     "what": "DLP rules block rather than monitor: sensitive data cannot leave through the inspected channels."},
]


def journey_position(item: Dict[str, Any]) -> Optional[str]:
    """Position of one planned item (None for tweaks / non-baseline items)."""
    if item.get("kind") == "tweak" or not item.get("baseline"):
        return None
    st = item["status"]
    if st == CREATE:
        return "missing"
    if st in BLOCKING_STATUSES:
        return "blocked"
    if st == RESTORE:
        return "customized"
    if item["kind"] != "policy":
        return "customized" if st == REUSE_DIFFERS else "deployed"
    pos = item.get("position")
    if pos is None and item.get("tenant"):
        pos = _rule_position(item.get("channel") or pc.channel_of(item["definition"]), item["tenant"], item["definition"])
    if st == REUSE_DIFFERS and pos in (None, "deployed"):
        return "customized"
    return pos or "deployed"


def _needed_for(stage_key: str, item: Dict[str, Any]) -> Optional[str]:
    """Minimum position an item must reach for a stage, or None if the
    stage does not care about this item."""
    kind = item["kind"]
    ch = item.get("channel") or (pc.channel_of(item["definition"]) if kind == "policy" else None)
    if stage_key == "foundation":
        return "present" if kind in ("dictionary", "engine", "app_group") else None
    if kind != "policy":
        return None
    if stage_key == "deployed":
        return "present"
    if stage_key == "visibility":
        return "enabled" if ch == pc.SSL or pc.has_engines(ch) else None
    if stage_key == "containment":
        return "enabled" if ch in (pc.CLOUD_APP, pc.FILE_TYPE, pc.URL) else None
    if stage_key == "enforcement":
        return "enforcing" if pc.has_engines(ch) else None
    return None


def _meets(position: str, need: str) -> bool:
    if position == "blocked":
        return False
    if need == "present":
        return position != "missing"
    if need == "enabled":
        return position in ("monitoring", "enforcing")
    if need == "enforcing":
        return position == "enforcing"
    return False


def _next_step(item: Dict[str, Any], position: str, need: str) -> str:
    kind, name = item["kind"], item["name"]
    ch = item.get("channel") or (pc.channel_of(item["definition"]) if kind == "policy" else None)
    portal = {pc.WEB: "Policy > Data Loss Prevention", pc.ENDPOINT: "Policy > Endpoint DLP",
              pc.SAAS: "Policy > SaaS Security API", pc.EMAIL: "Policy > Email DLP",
              pc.CLOUD_APP: "Policy > Cloud App Control", pc.FILE_TYPE: "Policy > File Type Control",
              pc.URL: "Policy > URL Filtering", pc.SSL: "Policy > SSL Inspection"}.get(ch or "", "the ZIA Admin Portal")
    if position == "blocked":
        return f"Unblock {kind} '{name}': {item.get('reason', '')}".strip()
    if position == "missing":
        return f"Deploy {kind.replace('_', ' ')} '{name}' (select the policy pack and run preflight)."
    if need == "enabled":
        if position == "customized":
            return f"Enable rule '{name}' in {portal} (it is customized; check the action still fits)."
        return f"Enable rule '{name}' in {portal} after reviewing its scope."
    if need == "enforcing":
        want = pc.target_action(item["definition"])
        return (f"Switch rule '{name}' in {portal} from monitor to an enforcing action ({want if pc.is_enforcing(ch or pc.WEB, want) else 'BLOCK'}) "
                "once incidents have been reviewed and tuned.")
    return f"Review {kind} '{name}'."


def journey_rows(all_items: Sequence[Dict[str, Any]], sources: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-baseline journey: position of every object, stage ladder,
    score and the concrete next steps. Read-only; derived from a plan."""
    rows: List[Dict[str, Any]] = []
    for src in sources:
        b = src.get("baseline")
        if not b:
            continue
        items = [i for i in all_items if i.get("kind") != "tweak" and src["id"] in (i.get("packs") or [])]
        counts = {p: 0 for p in POSITIONS}
        objects = []
        for i in items:
            pos = journey_position(i) or "deployed"
            counts[pos] += 1
            objects.append({"kind": i["kind"], "name": i["name"], "position": pos,
                            "channel": i.get("channel") or (pc.channel_of(i["definition"]) if i["kind"] == "policy" else None),
                            "drift": i.get("drift"), "reason": i.get("reason", ""),
                            "action": (i.get("tenant") or {}).get("action") if i["kind"] == "policy" and i.get("tenant") else None,
                            "state": (i.get("tenant") or {}).get("state") if i["kind"] == "policy" and i.get("tenant") else None})
        stages = []
        reached = 0
        chain_ok = True
        next_steps: List[str] = []
        for st in STAGES:
            needed = [(i, _needed_for(st["key"], i)) for i in items]
            needed = [(i, n) for i, n in needed if n]
            met = [(i, n) for i, n in needed if _meets(journey_position(i) or "deployed", n)]
            todo = [(i, n) for i, n in needed if not _meets(journey_position(i) or "deployed", n)]
            done = not todo  # a stage with nothing to require is trivially done
            if done and chain_ok:
                reached = st["n"]
            elif not done:
                chain_ok = False
            stages.append({"n": st["n"], "key": st["key"], "name": st["name"], "what": st["what"],
                           "required": len(needed), "met": len(met), "done": done,
                           "todo": [i["name"] for i, _ in todo]})
            if todo and not next_steps:
                # SSL first: nothing else can inspect HTTPS until it is on.
                todo_sorted = sorted(todo, key=lambda t: 0 if (t[0].get("channel") or "") == pc.SSL else 1)
                next_steps = [_next_step(i, journey_position(i) or "deployed", n) for i, n in todo_sorted][:8]
        applicable = [s for s in stages if s["required"]]
        score = round(100 * sum(s["met"] / s["required"] for s in applicable) / len(applicable)) if applicable else 100
        row = {"id": src["id"], "name": src["name"], "version": b.get("version", ""), "prefix": b.get("prefix", ""),
               "total": len(items), **counts,
               # legacy keys kept for older callers
               "in_sync": counts["deployed"] + counts["monitoring"] + counts["enforcing"],
               "drifted": counts["customized"] + counts["relaxed"],
               "stage": reached, "stage_name": (STAGES[reached - 1]["name"] if reached else "Not started"),
               "stages": stages, "score": score, "next_steps": next_steps, "objects": objects}
        if counts["blocked"]:
            row["state"] = "blocked"
        elif reached == len(STAGES):
            row["state"] = "governed"
        elif counts["missing"] == len(items):
            row["state"] = "not_started"
        else:
            row["state"] = "in_progress"
        row["secure_by_design"] = secure_by_design_findings(row)
        rows.append(row)
    return rows


# CISA Secure by Design, applied to a deployed policy pack. The app scores
# itself against the principles in secure_by_design.py; this measures what
# the pack looks like in the tenant, from the same journey read.
SBD_OWN = "Take ownership of customer security outcomes"
SBD_OPEN = "Embrace radical transparency and accountability"
SBD_DEFAULTS = "Secure by default"


def secure_by_design_findings(row: Dict[str, Any]) -> Dict[str, Any]:
    """Deviations from CISA's Secure by Design principles in one deployed
    pack, from its journey row: what is not in place (ownership of
    outcomes), what was changed in the tenant without the pack recording
    it (transparency), and what was weakened against the pack (secure
    defaults). Each finding says what it is, why it matters and what to
    do, in plain words."""
    objs = list(row.get("objects") or [])
    rules = [o for o in objs if o.get("kind") == "policy"]
    findings: List[Dict[str, Any]] = []

    def add(principle: str, severity: str, title: str, detail: str, items: List[Dict[str, Any]], next_step: str) -> None:
        findings.append({"principle": principle, "severity": severity, "title": title, "detail": detail,
                         "objects": [{"kind": o.get("kind"), "name": o.get("name"), "channel": o.get("channel"), "position": o.get("position")} for o in items[:12]],
                         "count": len(items), "next": next_step})

    missing = [o for o in objs if o.get("position") == "missing"]
    blocked = [o for o in objs if o.get("position") == "blocked"]
    if missing and len(missing) + len(blocked) == len(objs):
        add(SBD_OWN, "info", "This pack is not deployed yet",
            "None of its dictionaries, engines or rules exist in the tenant, so none of the protection it defines is in place.",
            missing, "Deploy the pack from Deploy Policy Packs; every object is created switched off and monitor-only.")
    elif missing:
        add(SBD_OWN, "high", "Part of the pack is not in the tenant",
            f"{len(missing)} of {len(objs)} objects this pack defines are missing, so part of the protection it promises is not in place. "
            "Ownership of the outcome means the whole design is deployed, not a fragment.",
            missing, "Deploy the pack again: only what is missing is created, everything that exists is kept.")
    if blocked:
        add(SBD_OWN, "high", "Part of the pack cannot be created on this tenant",
            f"{len(blocked)} object(s) are blocked (a template this tenant does not have, or a limit ZIA enforces). The rules behind them are created without those terms or not at all.",
            blocked, "Open the plan in Deploy Policy Packs; each blocked object carries the reason and what to change.")
    off = [o for o in rules if o.get("position") == "deployed"]
    if rules and off and len(off) == len(rules) and not missing:
        add(SBD_OWN, "medium", "Every rule is still switched off",
            "The pack is in the tenant but no rule is enabled, so nothing is being watched yet. Rules ship switched off on purpose; the outcome only starts when they are turned on.",
            off, "Enable the rules one at a time in monitor mode, review the incidents for a few days, then raise severity or move to an enforcing action.")
    elif off:
        add(SBD_OWN, "info", f"{len(off)} rule(s) still switched off",
            "These rules exist but are not evaluated. Nothing is watched on the channels they cover until they are enabled.",
            off, "Enable them in monitor mode once the enabled rules' incidents look right.")
    customized = [o for o in objs if o.get("position") == "customized"]
    if customized:
        add(SBD_OPEN, "medium", "Changed in the tenant without the pack recording it",
            f"{len(customized)} object(s) differ from what the pack defines" + (": " + "; ".join(f"{o.get('name')} ({', '.join(o.get('drift') or [])})" for o in customized[:4] if o.get("drift")) if any(o.get("drift") for o in customized) else "")
            + ". The pack is the documented design; a change made only in the ZIA portal is written down nowhere, so the next person cannot tell a deliberate tuning from an accident.",
            customized, "Fold the change into the pack (so the design says what the tenant does), or deploy in converge mode to restore the pack's version.")
    relaxed = [o for o in objs if o.get("position") == "relaxed"]
    if relaxed:
        add(SBD_DEFAULTS, "high", "Weakened compared with the pack",
            f"{len(relaxed)} rule(s) the pack ships enabled have been switched off in the tenant. Secure by default means the protection the design enables stays enabled unless someone decides otherwise and records why.",
            relaxed, "Re-enable the rule, or record the reason it is off in the pack (target_state) so the assessment stops flagging it.")
    enforcing_customized = [o for o in customized if o.get("kind") == "policy" and o.get("position") == "enforcing"]
    if enforcing_customized:
        add(SBD_DEFAULTS, "high", "An enforcing rule no longer matches the pack",
            "A rule that blocks or confirms differs from the pack's design; a wider scope or a different engine can block traffic nobody intended to block, or miss what it was meant to catch.",
            enforcing_customized, "Compare the rule with the pack in the plan (Deploy Policy Packs → preflight) and restore or record the change.")
    worst = {"high": 3, "medium": 2, "info": 1}
    level = max((worst[f["severity"]] for f in findings), default=0)
    return {"ok": level < 2, "level": {3: "high", 2: "medium", 1: "info", 0: "none"}[level], "findings": findings,
            "principles": [SBD_OWN, SBD_OPEN, SBD_DEFAULTS]}


# Kept name: preflight reports and older callers use "baselines".
baseline_status_rows = journey_rows


def tenant_mode(all_items: Sequence[Dict[str, Any]], sources: Sequence[Dict[str, Any]], tenant: Dict[str, Any]) -> Dict[str, Any]:
    """Greenfield (none of the selected packs' objects exist) or brownfield."""
    items = [i for i in all_items if i.get("kind") != "tweak"]
    present = [i for i in items if i["status"] in (REUSE, REUSE_DIFFERS, RESTORE, NOOP)]
    customized = [i for i in present if i["status"] in (REUSE_DIFFERS, RESTORE)]
    custom_dicts = sum(1 for d in tenant["dictionaries"].values() if _field(d, "custom", default=False))
    own = (f"The tenant has {custom_dicts} custom dictionar{'y' if custom_dicts == 1 else 'ies'}, {len(tenant['engines'])} engines and "
           f"{len(tenant['rules'])} web DLP rules of its own; nothing outside the selected packs is touched.")
    if not present:
        return {"mode": "greenfield", "present": 0, "customized": 0, "total": len(items),
                "detail": "None of the selected packs' objects exist yet: the whole selection is created from scratch. " + own}
    return {"mode": "brownfield", "present": len(present), "customized": len(customized), "total": len(items),
            "detail": (f"{len(present)} of {len(items)} objects already exist and are kept as the customer has them"
                       + (f" ({len(customized)} customized)" if customized else "") + "; only the missing ones are created. " + own)}


def journey(report: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, read-only journey report for the policy packs in a preflight:
    where the tenant is, what the next steps are. Nothing is written."""
    rows = report.get("baselines") or []
    if any(r["state"] == "blocked" for r in rows):
        overall = "blocked"
    elif rows and all(r["state"] == "governed" for r in rows):
        overall = "governed"
    elif rows and all(r["state"] == "not_started" for r in rows):
        overall = "not_started"
    else:
        overall = "in_progress"
    return {
        "status": overall,
        "stage": min((r["stage"] for r in rows), default=0),
        "score": round(sum(r["score"] for r in rows) / len(rows)) if rows else 0,
        "stages": [{"n": st["n"], "key": st["key"], "name": st["name"], "what": st["what"]} for st in STAGES],
        "baselines": rows,
        "tenant_mode": report.get("tenant_mode"),
        "tenant": report.get("tenant"),
        "blockers": [b for b in report.get("blockers", []) if not b.startswith("Nothing to deploy")
                     and not b.startswith("The server is running in read-only mode")],
        "plan_hash": report.get("plan_hash", ""),
        "elapsed_seconds": report.get("elapsed_seconds"),
    }


baseline_status = journey


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
    restore_drift: bool = False,
    channel_targets: Optional[Dict[str, Sequence[str]]] = None,
    activate: bool = True,
    log: LogFn = None,
    settle_seconds: float = 45.0,
    cancel: Optional[threading.Event] = None,
    assessor: str = "",
) -> Dict[str, Any]:
    """Execute a previously approved plan. `assessor` is the name the
    provenance tag in each created object's description carries.

    The preflight is recomputed first; if its hash differs from
    `plan_hash` the tenant or selection changed after the user approved,
    and nothing is written (status `plan_changed`). Items are applied in
    dependency order; each is isolated, blocked items are skipped with
    their reason, and dependents of a failed item are skipped rather
    than created against a missing dependency.

    The run is under pack_ops run control: a refusal no later write can
    get past (the portal's edit lock, the hourly request limit, refused
    credentials) or a set `cancel` event stops the remaining writes at
    once; the result's `stopped` says why, in words, and the objects that
    were never sent are reported as skipped, not failed. Activation and
    the read-back still run, so what was written is live and recorded. Its
    waits, holds and refusals draw on the client's own tenant's ZIA rate
    limits, whichever thread runs it. Every write and the run's summary
    go to the audit log (pack_ops.audited_run)."""
    import zia_rate
    with zia_rate.using_client(client), ops.run_scope(cancel), ops.audited_run("deploy", client, plan_hash=plan_hash, cancel=cancel) as run:
        run["result"] = _apply(client, packs, plan_hash=plan_hash, use_rank_0=use_rank_0, apply_tweaks=apply_tweaks, verify=verify,
                               writes_enabled=writes_enabled, restore_drift=restore_drift, channel_targets=channel_targets,
                               activate=activate, log=log, settle_seconds=settle_seconds, assessor=assessor)
        return run["result"]


def _apply(client, packs: Sequence[Dict[str, Any]], *, plan_hash: str, use_rank_0: bool, apply_tweaks: bool, verify: bool,
           writes_enabled: Optional[bool], restore_drift: bool, channel_targets: Optional[Dict[str, Sequence[str]]],
           activate: bool, log: LogFn, settle_seconds: float, assessor: str = "") -> Dict[str, Any]:
    _log = log or (lambda m: None)
    started = time.time()
    _log("Checking the approved plan against the tenant as it is now…")
    report = preflight(client, packs, use_rank_0=use_rank_0, apply_tweaks=apply_tweaks, writes_enabled=writes_enabled,
                       restore_drift=restore_drift, channel_targets=channel_targets, log=_log)
    if writes_enabled is False:
        return {"status": "blocked", "blockers": ["The server is in read-only mode. Enable write mode in Deploy Policy Packs where the page "
                                                  "offers it; otherwise " + __import__("security").write_enable_hint() + ". Then deploy."],
                "report": public_report(report), "results": []}
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
    # Every write goes through pack_ops (the shared execution path); the
    # recorder keeps the per-object results the UI renders and one
    # structured event per write.
    recorder = ops.Recorder(log=_log, run="deploy")
    results = recorder.results
    failed_names: Dict[str, Set[str]] = {"dictionary": set(), "engine": set()}
    _OPS = {"created": "create", "restored": "update", "modified": "update", "reused": "reuse", "skipped": "skip", "failed": "write"}

    def record(item: Dict[str, Any], status: str, *, outcome: Optional[ops.Outcome] = None, **extra: Any) -> None:
        channel = extra.pop("channel", None)
        if channel is None and item["kind"] == "policy":
            # A rule is counted under its own channel whatever happened to it:
            # a reused or skipped SaaS or Email rule used to land under Web in
            # the per-channel summary.
            channel = item.get("channel") or pc.channel_of(item.get("definition") or {})
        recorder.record(item["kind"], item["name"], status, op=extra.pop("op", None) or _OPS.get(status, status), channel=channel,
                        outcome=outcome, **extra)

    # Name → ID maps, extended as objects are created so later phases resolve them.
    dict_ids: Dict[str, Any] = {n: _field(t, "id") for n, t in tenant["dictionaries"].items()}
    for n, i in (tenant.get("predefined") or {}).items():
        dict_ids.setdefault(n, i)   # predefined dictionaries by display name and alias too
    engine_ids: Dict[str, Any] = {n: _field(t, "id") for n, t in tenant["engines"].items()}

    def described(item: Dict[str, Any], definition: Dict[str, Any], fallback: str = "") -> Dict[str, Any]:
        """Definition with the policy pack provenance tag in its description
        (clamped to the API limit for dictionaries)."""
        limit = {"dictionary": DICT_DESCRIPTION_MAX, "engine": ENGINE_DESCRIPTION_MAX}.get(item["kind"])
        if item.get("baseline"):
            return dict(definition, description=baseline_description(item, definition.get("description") or fallback, limit=limit, by=assessor))
        if item.get("pack"):
            return dict(definition, description=pack_description(item, definition.get("description") or fallback, limit=limit, by=assessor))
        return definition

    # Say up front what the channel selection left out, so a missing
    # channel in the log is never a mystery.
    for src in report.get("packs") or []:
        note = src.get("channels") or {}
        if note.get("skipped_channels"):
            labels = ", ".join(pc.label(ch) for ch in note["skipped_channels"])
            _log(f"[channels] {src.get('name') or src.get('id')}: {labels} NOT deployed: unticked in the pack card "
                 f"({len(note.get('skipped_rules') or [])} rule(s) skipped). Tick the channel and deploy again to add them.")
        for old, new in src.get("renamed") or []:
            _log(f"[dictionary] {src.get('name') or src.get('id')}: '{old}' deployed as '{new}': ZIA shows one of its predefined "
                 f"dictionaries under the original name and would refuse it as a duplicate.")
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
            payload = dict(name=d["name"], custom_phrase_match_type=d["custom_phrase_match_type"], dictionary_type="PATTERNS_AND_PHRASES", **kwargs)
            if item["status"] == RESTORE:
                tid = item["tenant"]["id"]
                out = ops.update(zia, "dictionary", tid, payload, log=_log)
                if not out.ok:
                    failed_names["dictionary"].add(item["name"])
                    record(item, "failed", outcome=out)
                else:
                    dict_ids[item["name"]] = tid
                    record(item, "restored", outcome=out, id=tid, drift=item.get("drift"))
                continue
            out = ops.create(zia, "dictionary", payload, log=_log)
            if out.ok and out.id is not None:
                dict_ids[item["name"]] = out.id
                record(item, "created", outcome=out, id=out.id)
            elif (twin := _twin_after_duplicate(zia, "dictionary", item["name"], out)) is not None:
                dict_ids[item["name"]] = twin
                record(item, "reused", id=twin, reason=_DUPLICATE_REUSED)
            else:
                failed_names["dictionary"].add(item["name"])
                record(item, "failed", outcome=out, error=out.as_error() or "the API returned no id")
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
        if ops.stop_reason():
            # The run has stopped: say so, rather than blaming the dictionary that was never sent either.
            failed_names["engine"].add(item["name"])
            record(item, "skipped", reason=f"not attempted: {ops.stop_reason()}")
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
            payload = dict(name=e["name"], engine_expression=expr, custom_dlp_engine=True, description=e.get("description", "Imported engine"))
            if item["status"] == RESTORE:
                eid = item["tenant"]["id"]
                out = ops.update(zia, "engine", eid, payload, log=_log)
                if not out.ok:
                    failed_names["engine"].add(item["name"])
                    record(item, "failed", outcome=out)
                else:
                    engine_ids[item["name"]] = eid
                    record(item, "restored", outcome=out, id=eid, drift=item.get("drift"))
                continue
            out = ops.create(zia, "engine", payload, log=_log)
            if out.ok and out.id is not None:
                engine_ids[item["name"]] = out.id
                record(item, "created", outcome=out, id=out.id)
            elif (twin := _twin_after_duplicate(zia, "engine", item["name"], out)) is not None:
                engine_ids[item["name"]] = twin
                record(item, "reused", id=twin, reason=_DUPLICATE_REUSED)
            else:
                failed_names["engine"].add(item["name"])
                record(item, "failed", outcome=out, error=out.as_error() or "the API returned no id")
        except Exception as ex:  # noqa: BLE001
            failed_names["engine"].add(item["name"])
            record(item, "failed", error=str(ex)[:200])

    _log("Phase 2b: endpoint application groups")
    app_group_ids: Dict[str, Any] = {n: g.get("id") for n, g in (tenant["channels"].get("app_groups") or {}).items()}
    failed_names["app_group"] = set()
    for item in merged["app_group"].values():
        if item["status"] in (REUSE, REUSE_DIFFERS):
            record(item, "reused", id=(item.get("tenant") or {}).get("id"))
            continue
        if item["status"] not in (CREATE, RESTORE):
            record(item, "skipped", reason=item["reason"])
            failed_names["app_group"].add(item["name"])
            continue
        if ops.stop_reason():
            failed_names["app_group"].add(item["name"])
            record(item, "skipped", reason=f"not attempted: {ops.stop_reason()}")
            continue
        g = described(item, item["definition"])
        try:
            if item["status"] == RESTORE:
                gid = item["tenant"]["id"]
                out = ops.update(zia, "app_group", gid, g, log=_log)
                if not out.ok:
                    failed_names["app_group"].add(item["name"])
                    record(item, "failed", outcome=out)
                else:
                    record(item, "restored", outcome=out, id=gid, drift=item.get("drift"))
                continue
            out = ops.create(zia, "app_group", g, log=_log)
            if not out.ok or out.id is None:
                failed_names["app_group"].add(item["name"])
                record(item, "failed", outcome=out, error=out.as_error() or "the API returned no id")
            else:
                app_group_ids[item["name"]] = out.id
                record(item, "created", outcome=out, id=out.id)
        except Exception as ex:  # noqa: BLE001
            failed_names["app_group"].add(item["name"])
            record(item, "failed", error=str(ex)[:200])

    _log("Phase 3: policies")
    policy_ids: Dict[str, Any] = {}
    # SaaS Security API rules are ordered per rule type and the API does
    # not shuffle the others down for a new order 1 the way Web DLP does:
    # every rule of a type must have its own order, so each new SaaS rule
    # takes the next free order of its type.
    saas_orders: Dict[str, int] = {}
    saas_next: Dict[str, int] = {}   # per type, the order the next rule tries first once ZIA has refused an order
    for r in tenant["channels"]["rules"].get(pc.SAAS) or []:
        t = str(r.get("type") or "ANY")
        saas_orders[t] = max(saas_orders.get(t, 0), int(r.get("order") or 0))
    for ch_rules in tenant["channels"]["rules"].values():
        for r in ch_rules:
            policy_ids.setdefault(r["name"], r.get("id"))
    for r in tenant["rules"]:
        policy_ids.setdefault(r["name"], r.get("id"))
    # Web, Endpoint and Email DLP insert a new rule at order 1 and move the
    # others down, so rules created in pack order would end up reversed.
    # Create those top-level rules last-first so the first pack rule ends up
    # on top; SaaS rules take the next free order and keep pack order, and
    # sub-rules still come after their parents. The results are put back in
    # pack order below so the report reads the same way as the plan.
    in_pack_order = sorted(merged["policy"].values(), key=lambda i: 1 if i["definition"].get("parent_rule") else 0)
    top_level = [i for i in in_pack_order if not i["definition"].get("parent_rule")]
    inserted_on_top = [i for i in top_level if (i.get("channel") or pc.channel_of(i["definition"])) != pc.SAAS]
    on_top_ids = {id(i) for i in inserted_on_top}
    creation_order = (list(reversed(inserted_on_top)) + [i for i in top_level if id(i) not in on_top_ids]
                      + [i for i in in_pack_order if i["definition"].get("parent_rule")])
    first_policy_result = len(results)
    for item in creation_order:
        if item["status"] in (REUSE, REUSE_DIFFERS):
            record(item, "reused", id=(item.get("tenant") or {}).get("id"))
            continue
        if item["status"] not in (CREATE, RESTORE):
            record(item, "skipped", reason=item["reason"])
            continue
        if ops.stop_reason():
            record(item, "skipped", reason=f"not attempted: {ops.stop_reason()}", channel=item.get("channel") or pc.channel_of(item["definition"]))
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
        resolved = dict(item.get("resolved") or {})
        if channel == pc.ENDPOINT and p.get("endpoint_application_groups"):
            groups_failed = [g for g in p["endpoint_application_groups"] if g in failed_names["app_group"] or app_group_ids.get(g) is None]
            if groups_failed:
                record(item, "skipped", reason="endpoint application group not available: " + ", ".join(groups_failed), channel=channel)
                continue
            resolved["app_group_ids"] = [app_group_ids[g] for g in p["endpoint_application_groups"]]
        parent_id = None
        if p.get("parent_rule"):
            parent_id = policy_ids.get(str(p["parent_rule"]))
            if parent_id is None:
                record(item, "skipped", reason=f"parent rule '{p['parent_rule']}' was not created", channel=channel)
                continue
        try:
            payload = pc.build_payload(channel, p, ids, resolved, use_rank_0=use_rank_0)
            if parent_id is not None:
                payload["order"] = int(p.get("order") or 1)
            if item["status"] == RESTORE:
                existing = item["tenant"]
                # Keep the rule where the admin placed it; only its content is restored.
                payload["order"] = existing.get("order") or payload.get("order")
                out = ops.update(zia, "policy", existing["id"], payload, channel=channel, parent_id=parent_id, log=_log)
                if not out.ok:
                    record(item, "failed", outcome=out, channel=channel)
                else:
                    record(item, "restored", outcome=out, id=existing["id"], channel=channel, drift=item.get("drift"))
                continue
            if channel == pc.SAAS and parent_id is None:
                out = _add_saas_rule(zia, payload, saas_orders, saas_next, _log, item["name"])
            else:
                out = ops.create(zia, "policy", payload, channel=channel, parent_id=parent_id, log=_log)
                if not out.ok and parent_id is None and _rank_refusal(out.error):
                    was, payload["rank"] = payload.get("rank"), _other_rank(payload)
                    _log(f"[policy] {item['name']}: ZIA refused rank {was} ({out.error}); trying rank {payload['rank']}")
                    out = ops.create(zia, "policy", payload, channel=channel, parent_id=parent_id, log=_log)
                    if out.ok and out.id is not None:
                        payload["rank_note"] = f"rank {was} refused by ZIA (admin rank); created at rank {payload['rank']}"
            rank_note = payload.pop("rank_note", None)
            if out.ok and out.id is not None:
                policy_ids[item["name"]] = out.id
                record(item, "created", outcome=out, id=out.id, channel=channel,
                       order=payload.get("order") if parent_id is None else None, parent_id=parent_id, rank_note=rank_note)
            elif parent_id is None and (twin := _twin_after_duplicate(zia, "policy", item["name"], out, channel)) is not None:
                policy_ids[item["name"]] = twin
                record(item, "reused", id=twin, channel=channel, reason=_DUPLICATE_REUSED)
            else:
                record(item, "failed", outcome=out, channel=channel, error=out.as_error() or "the API returned no id")
        except Exception as ex:  # noqa: BLE001
            record(item, "failed", error=str(ex)[:200], channel=channel)
    pack_position = {i["name"]: n for n, i in enumerate(in_pack_order)}
    results[first_policy_result:] = sorted(results[first_policy_result:], key=lambda r: pack_position.get(r["name"], len(pack_position)))

    if apply_tweaks:
        _log("Phase 4: confidence tweaks")
        for item in internal["tweaks"]:
            if item["status"] != MODIFY:
                continue  # no-ops were already explained in the plan; nothing to report
            t = item["tenant"]
            existing = tenant["dictionaries"][t["name"]]
            out = ops.update(zia, "dictionary", t["id"],
                             dictionary_update_body(existing, confidence_threshold=item["definition"]["target_confidence"]), log=_log)
            if not out.ok:
                record(item, "failed", outcome=out)
            else:
                record(item, "modified", outcome=out, id=t["id"])

    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    channels: Dict[str, Dict[str, Any]] = {}
    for r in results:
        if r.get("kind") != "policy":
            continue
        ch = channels.setdefault(str(r.get("channel") or pc.WEB), {"created": 0, "reused": 0, "failed": 0, "skipped": 0, "restored": 0, "errors": []})
        st = r.get("status")
        if st in ch:
            ch[st] += 1
        if st == "failed" and r.get("error") and len(ch["errors"]) < 3 and r["error"] not in ch["errors"]:
            ch["errors"].append(str(r["error"])[:200])
    wrote = bool(counts.get("created") or counts.get("modified") or counts.get("restored"))
    if counts.get("failed"):
        status = "partial" if wrote else "failed"
    else:
        status = "applied"
    # ZIA saves every change as pending; activate so the deployment is live
    # for users without a manual step in the portal.
    activation = None
    settled = None
    if wrote and activate:
        _log("Activating pending ZIA changes…")
        activation = ops.activate_once(client.zia, _log)
        _log("Activation " + ("done." if activation.get("activated") else f"could not run: {activation.get('error')}"))
        if activation.get("activated"):
            settled = pc.wait_active(client.zia, settle_seconds, _log)

    # READ BACK: run the same preflight again against the tenant as it is
    # now. Every object this run created, overwrote, modified or reused
    # must be found; anything the fresh read would still create is missing.
    read_check: Dict[str, Any] = {"read": False, "clean": False, "expected": 0, "present": 0, "missing": [], "activation_status": settled}
    fresh: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if wrote or counts.get("reused"):
        _log("Reading the tenant back to verify the deployment…")
        try:
            again = preflight(client, packs, use_rank_0=use_rank_0, apply_tweaks=apply_tweaks, writes_enabled=writes_enabled,
                              restore_drift=restore_drift, channel_targets=channel_targets, log=_log)
            fresh = {(i["kind"], i["name"]): i for i in again.get("items", [])}
            tenant_now = again.get("tenant") or {}
            read_check["read"] = bool(tenant_now.get("reachable", True))
            # A list the tenant refused to give (a 403, a 429, a timeout) makes
            # its objects unverifiable, not missing: say which, with the status.
            unread = dict(tenant_now.get("unreadable") or {})
            for ch, err in (tenant_now.get("channel_errors") or {}).items():
                if err:
                    unread[f"{ch} rules"] = err
            list_of = {"dictionary": "dictionaries", "engine": "engines", "policy": "web DLP rules"}
            read_check["unreadable"] = {k: ops.describe_error(e) for k, e in unread.items()}
            for r in results:
                if r.get("status") not in ("created", "restored", "modified", "reused") or r.get("kind") == "tweak":
                    continue
                read_check["expected"] += 1
                f = fresh.get((r["kind"], r["name"]))
                if f is not None and f.get("status") not in (CREATE, BLOCKED_DEPENDENCY, CONFLICT, SKIP_EMPTY):
                    read_check["present"] += 1
                else:
                    ch = r.get("channel")
                    key = f"{ch} rules" if (r["kind"] == "policy" and ch and ch != pc.WEB) else list_of.get(r["kind"])
                    if key in unread:
                        reason = f"could not be verified: the tenant refused to list its {key} ({ops.describe_error(unread[key])})"
                    else:
                        reason = (f or {}).get("reason") or "not listed by the tenant"
                    read_check["missing"].append({"kind": r["kind"], "name": r["name"], "channel": ch, "reason": reason,
                                                  "unverified": key in unread})
            read_check["clean"] = read_check["read"] and not read_check["missing"]
            unverified = [m for m in read_check["missing"] if m.get("unverified")]
            not_found = len(read_check["missing"]) - len(unverified)
            parts = []
            if not_found:
                parts.append(f"{not_found} object(s) not found")
            if unverified:
                parts.append(f"{len(unverified)} object(s) could not be verified — the tenant refused to be read: "
                             + "; ".join(f"{k} ({v})" for k, v in read_check["unreadable"].items()))
            _log("Read-back: " + (f"all {read_check['present']} object(s) present." if read_check["clean"] else "; ".join(parts) + "."))
        except Exception as ex:  # noqa: BLE001
            read_check["error"] = str(ex)[:300]
            _log(f"Read-back failed: {read_check['error']}")
    # Per-pack verification comes from the same read-back (one source of
    # truth: the planner), not from a second comparison with its own rules.
    verification: Dict[str, Any] = {}
    if verify:
        _log("Phase 5: verification (from the read-back)")
        verification = _verification_from_read_back(internal["sources"], merged, results, fresh, read_check)
        for pid, v in verification.items():
            _log(f"[verify] {pid}: " + ("everything the deployment created or reused is in the tenant" if v.get("all_good") else (v.get("error") or "differences found")))
    return {
        "status": status,
        "summary": counts,
        "channels": channels,
        "results": results,
        "events": recorder.events,
        "verification": verification,
        "read_check": read_check,
        "plan_hash": plan_hash,
        "elapsed_seconds": round(time.time() - started, 2),
        "activation_required": wrote and not (activation and activation.get("activated")),
        "activation": activation,
        # Why the run stopped writing before the end (None when it ran through).
        "stopped": ops.stop_reason(),
    }


_DUPLICATE_REUSED = "ZIA answered that an object with this name already exists; the plan had not seen it, so the existing one is used"


def _twin_after_duplicate(zia, kind: str, name: str, out: ops.Outcome, channel: Optional[str] = None) -> Optional[Any]:
    """When ZIA refuses a create as a duplicate the plan did not see (a name
    that differs only in case, an object created since the plan), the id
    of the existing object, so its dependents are built on it instead of
    being skipped. None for any other refusal, or when nothing is listed
    under that name (a predefined dictionary's display name, for one)."""
    if out.ok or not ops.is_duplicate(out.error):
        return None
    return ops.find_by_name(zia, kind, name, channel)


# ---------------------------------------------------------------------------
# Undo a deployment
# ---------------------------------------------------------------------------

UNDO_ORDER = ops.DELETE_ORDER

# Kept names: the identity check and the delete live in pack_ops now.
_current_names = ops.current_names


def _delete(zia, item: Dict[str, Any]) -> Optional[str]:
    """Delete one object through the shared path. Error string or None."""
    return ops.delete(zia, item).as_error()


def _verification_from_read_back(sources: Sequence[Dict[str, Any]], merged: Dict[str, Dict[str, Dict[str, Any]]],
                                 results: Sequence[Dict[str, Any]], fresh: Dict[Tuple[str, str], Dict[str, Any]],
                                 read_check: Dict[str, Any]) -> Dict[str, Any]:
    """Per-pack verification derived from the read-back preflight: every
    dictionary, engine and rule the run created, restored or reused must
    be found by the same planner that planned it. One source of truth."""
    outcome = {r["name"]: r for r in results}
    out: Dict[str, Any] = {}
    for src in sources:
        pid = src["id"]
        if not read_check.get("read") or read_check.get("error"):
            out[pid] = {"phase": "verify", "all_good": False, "error": read_check.get("error") or "the tenant could not be read back"}
            continue
        v: Dict[str, Any] = {"phase": "verify", "all_good": True, "dictionaries": {"total": 0, "ok": 0, "missing": [], "mismatched": {}},
                             "engines": {"total": 0, "ok": 0, "missing": [], "mismatched": {}}, "rules": {}}
        for kind, bucket in (("dictionary", "dictionaries"), ("engine", "engines"), ("policy", None)):
            for item in merged.get(kind, {}).values():
                if pid not in (item.get("packs") or []):
                    continue
                r = outcome.get(item["name"])
                if not r or r.get("status") not in ("created", "restored", "modified", "reused"):
                    continue
                f = fresh.get((kind, item["name"]))
                present = f is not None and f.get("status") not in (CREATE, BLOCKED_DEPENDENCY, CONFLICT, SKIP_EMPTY)
                if kind == "policy":
                    ch = item.get("channel") or pc.channel_of(item["definition"])
                    slot = v["rules"].setdefault(ch, {"total": 0, "ok": 0, "missing": []})
                    slot["total"] += 1
                    if present:
                        slot["ok"] += 1
                    else:
                        slot["missing"].append(item["name"])
                        v["all_good"] = False
                    continue
                slot = v[bucket]
                slot["total"] += 1
                if not present:
                    slot["missing"].append(item["name"])
                    v["all_good"] = False
                elif f.get("status") == REUSE_DIFFERS:
                    slot["ok"] += 1
                    slot["mismatched"][item["name"]] = f.get("reason") or "differs from the pack"
                else:
                    slot["ok"] += 1
        out[pid] = v
    return out


def verify_pack(client, pack: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only: is everything one pack defines in the tenant? Answered by
    the planner (the same read a deploy ends with), in the shape the
    pack page shows: dictionaries and engines found / missing / differing,
    rules found per channel."""
    report = preflight(client, [pack], writes_enabled=False)
    items = report.get("items") or []
    v: Dict[str, Any] = {"phase": "verify", "all_good": True,
                         "dictionaries": {"total": 0, "ok": 0, "missing": [], "mismatched": {}},
                         "engines": {"total": 0, "ok": 0, "missing": [], "mismatched": {}}, "rules": {},
                         "blocked": [], "message": ""}
    if not (report.get("tenant") or {}).get("reachable", True):
        v["all_good"] = False
        v["error"] = "; ".join(report.get("blockers") or []) or "the tenant could not be read"
        v["message"] = "The tenant could not be read, so nothing could be checked. " + v["error"]
        return v
    for i in items:
        if i.get("kind") == "tweak":
            continue
        present = i["status"] in (REUSE, REUSE_DIFFERS, RESTORE, NOOP)   # in the tenant now; CREATE means missing
        if i["kind"] == "policy":
            channel = i.get("channel") or (i.get("detail") or {}).get("channel") or pc.WEB
            slot = v["rules"].setdefault(channel, {"total": 0, "ok": 0, "missing": []})
        elif i["kind"] in ("dictionary", "engine"):
            slot = v["dictionaries" if i["kind"] == "dictionary" else "engines"]
        else:
            continue
        if not present and i["status"] in (BLOCKED_DEPENDENCY, CONFLICT, SKIP_EMPTY):
            # Cannot exist on this tenant (a template it lacks, a limit): said, not counted as missing.
            v["blocked"].append({"kind": i["kind"], "name": i["name"], "reason": i.get("reason") or ""})
            continue
        slot["total"] += 1
        if present:
            slot["ok"] += 1
            if i["status"] == REUSE_DIFFERS and "mismatched" in slot:
                slot["mismatched"][i["name"]] = i.get("reason") or "differs from the pack"
        else:
            slot["missing"].append(i["name"])
            v["all_good"] = False
    missing = len(v["dictionaries"]["missing"]) + len(v["engines"]["missing"]) + sum(len(s["missing"]) for s in v["rules"].values())
    v["message"] = ("Everything this pack defines is in the tenant." if v["all_good"]
                    else f"{missing} object(s) this pack defines are not in the tenant; deploy the pack to create only what is missing.")
    if v["blocked"]:
        v["message"] += (f" {len(v['blocked'])} object(s) cannot be created on this tenant and were left out: "
                         + "; ".join(f"{b['name']} ({b['reason']})" for b in v["blocked"][:3]) + ("…" if len(v["blocked"]) > 3 else ""))
    return v


def undo(client, record: Dict[str, Any], *, writes_enabled: Optional[bool] = None, log: LogFn = None,
         settle_seconds: float = 45.0) -> Dict[str, Any]:
    """Delete what a recorded deployment created, through the same executor
    as a pack removal (pack_removal._execute): dependents before
    dependencies in tiers, activation and a wait for ACTIVE between tiers,
    retries for what time clears, then a read-back. Only objects the
    deployment created are touched, and only while the tenant still lists
    that id under the name it was given; an id that now carries another
    name is skipped and said so, an object already gone is reported as
    gone. Returns the undo shape (undone / partial / nothing / failed /
    blocked) older callers and the deployment store expect."""
    import pack_removal
    out = pack_removal.remove_deployment(client, record, plan_hash="", writes_enabled=writes_enabled, log=log, settle_seconds=settle_seconds)
    results = list(out.get("results") or [])
    for it in out.get("kept") or []:
        results.append({"kind": it["kind"], "name": it["name"], "id": it.get("id"), "channel": it.get("channel"), "status": "skipped",
                        "reason": f"{it.get('keep') or 'kept'}; left alone"})
    for it in out.get("gone") or []:
        results.append({"kind": it["kind"], "name": it["name"], "id": it.get("id"), "channel": it.get("channel"), "status": "gone",
                        "reason": "already removed from the tenant"})
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    if out.get("status") in ("blocked", "stale"):
        return {**out, "status": "blocked" if out.get("status") == "blocked" else "failed", "results": results, "summary": counts}
    complete = not counts.get("failed") and not counts.get("skipped") and not counts.get("still_present")
    deleted = counts.get("deleted", 0)
    if complete and deleted:
        status = "undone"
    elif deleted:
        status = "partial"
    elif counts.get("failed") or counts.get("still_present"):
        status = "failed"
    else:
        status = "nothing"   # nothing left to delete: every item is gone, or kept for something the customer still uses
    return {**out, "status": status, "summary": counts, "results": results, "complete": complete,
            "activation_required": bool(deleted) and not ((out.get("activation") or {}).get("activated"))}
