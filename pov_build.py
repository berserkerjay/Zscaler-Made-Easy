"""POV build: one combined plan, one dry run and one apply across the Build
new plugins (admin_ops.register), for the POV planner (/report/pov).

After the intake, the planner builds ONE plan over the builders the POV
needs (the ZIA security baseline, the SSL certificate manager, the ZPA App
Connector group, application segments and policy rules, Client Connector
profiles, ZDX probes, AI Guard routing and its detection policy), shows ONE
dry run with a section per product listing every object, and applies it
with ONE typed confirmation. Nothing here writes on its own: every step is
the builder's own operation on the Bulk changes engine.

  plan(client, parts, scope)      each step planned with admin_ops.plan, in
                                  the safe order (STEPS: what others use
                                  first), never writing. A step that needs
                                  what an earlier step creates (segments
                                  need the connector group, policy rules
                                  the segments) is planned with
                                  admin_ops.pending_plan in effect, so it
                                  shows the object as "built by an earlier
                                  step" instead of a blocker. One plan hash
                                  (sha256) covers every step's operation,
                                  items, before and after, and writes.
  execute(client, parts, ...)     plans everything again: a different hash
                                  means the tenant moved and nothing is
                                  written. Then, step by step: the step is
                                  planned again from the tenant as it is
                                  now (the earlier steps applied) and must
                                  equal the preview, except that the ids
                                  the earlier steps just created stand
                                  where the preview said "built by an
                                  earlier step"; it is applied through
                                  admin_ops.execute (write mode, the
                                  assessor, its own plan hash and typed
                                  phrase, a re-read before every write,
                                  read-back, activation, audit) and
                                  recorded (admin_ops.record) with its
                                  Undo. The first step that does not apply
                                  completely stops the run: nothing after
                                  it is written, and the report names it.
  undo_parts(build)               the Undo of everything a build applied:
                                  each applied step's recorded inverse, in
                                  reverse order, planned and applied the
                                  same way (one dry run, one typed
                                  confirmation, stop at the first failure).

The gates stay where they are: the route checks the writer, confirm=true,
the plan hash, the named assessor, write mode and the Scope page (each
step's own scope check, before sign-in); the engine checks write mode and
the assessor again, and each step's admin_ops.execute keeps every check of
its own. On the sample tenant or a snapshot the plan and the dry run work
(a rehearsal: nothing is written) and an apply is refused by the route.

Every new object arrives disabled or monitor-only unless the step's spec
says otherwise (each builder's default: rules disabled, segments disabled,
AI Guard in Monitor, ZDX probes created off and turned on only when asked).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao

LogFn = Optional[Callable[[str], None]]
RecordFn = Optional[Callable[[Dict[str, Any], str], Optional[str]]]

MAX_SPEC_BYTES = 300 * 1024      # one step's spec, as JSON (a ZPA CSV is at most 256 KB)
KIND = "pov_build"


class BuildError(ValueError):
    """A request the POV build cannot plan (the endpoint's 400)."""


# ── The steps, in the safe order: what other steps use comes first ───────
# key: the part's name in a request; type: the Build new operation type;
# section: the product heading of the dry run; scope: the Scope page key the
# page checks before offering it (the builder's own scope check decides);
# needs: steps whose objects this one uses when they run in the same build;
# products: POV intake products that switch it on by default (empty: off
# until picked); arrives: how its new objects arrive, in plain words.
STEPS: List[Dict[str, Any]] = [
    {"key": "zia_baseline", "type": "zia_baseline", "section": "Internet Access (ZIA)", "label": "ZIA security baseline",
     "scope": "zia_extras", "needs": [], "products": ["url_filtering", "threat", "cloud_apps", "firewall", "dns", "ssl"],
     "arrives": "Rules arrive disabled unless 'Create the rules enabled' is ticked; Advanced Threat Protection is changed only when picked."},
    {"key": "ssl_certificates", "type": "ssl_certificate_move", "section": "Internet Access (ZIA)", "label": "SSL certificates",
     "scope": "zia_extras", "needs": [], "products": [],
     "arrives": "Moves the picked Inspect rules to the picked certificate; nothing new is created."},
    {"key": "zpa_connector_group", "type": "zpa_connector_group", "section": "Private Access (ZPA)", "label": "ZPA App Connector group",
     "scope": "zpa", "needs": [], "products": ["zpa"],
     "arrives": "The group and its provisioning key; the key is shown once, right after it is created."},
    {"key": "zpa_app_segments", "type": "zpa_app_segments", "section": "Private Access (ZPA)", "label": "ZPA application segments",
     "scope": "zpa", "needs": ["zpa_connector_group"], "products": ["zpa"],
     "arrives": "Application segments arrive disabled unless 'create enabled' is ticked."},
    {"key": "zpa_policies", "type": "zpa_policies", "section": "Private Access (ZPA)", "label": "ZPA policy rules",
     "scope": "zpa", "needs": ["zpa_app_segments"], "products": ["zpa"],
     "arrives": "Rules over the prefix's segments; they decide nothing while the segments are disabled."},
    {"key": "zcc_profiles", "type": "zcc_profile_build", "section": "Client Connector", "label": "Client Connector profiles",
     "scope": "zcc", "needs": [], "products": [],
     "arrives": "A forwarding profile and an app profile; no device uses them until it is assigned to them."},
    {"key": "zdx_probes", "type": "zdx_probes", "section": "Digital Experience (ZDX)", "label": "ZDX probes",
     "scope": "zdx", "needs": [], "products": ["zdx"],
     "arrives": "Apps and probes are created off, then turned on as the template asks."},
    {"key": "aiguard_routing", "type": "aiguard_routing", "section": "AI Guard", "label": "AI Guard routing",
     "scope": "aiguard", "needs": ["zia_baseline"], "products": [],
     "arrives": "New ZIA rules arrive disabled; prompt capture is turned on only when licensed."},
    {"key": "aiguard_policy", "type": "aiguard_detection_policy", "section": "AI Guard", "label": "AI Guard detection policy",
     "scope": "aiguard", "needs": [], "products": [],
     "arrives": "Monitor (detect only) unless Block is picked."},
]
STEP_BY_KEY: Dict[str, Dict[str, Any]] = {s["key"]: s for s in STEPS}
ORDER: Tuple[str, ...] = tuple(s["key"] for s in STEPS)

# ── Vertical presets: what each intake preset asks the builders for ──────
# Data, keyed by the POV's vertical (pov.VERTICALS). A preset with no row
# here takes "_default"; a preset may also carry its own "build" mapping
# (pov.VERTICALS[key]["build"]), which wins. Keys: tier (ZIA baseline),
# overlays (compliance overlays), zpa_preset (ops_zpa.VERTICALS), aiguard
# (ai_guard.PROFILES), zdx (ops_zdx.TEMPLATES).
PRESET_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "_default": {"tier": "balanced", "overlays": [], "zpa_preset": "general", "aiguard": "GENERAL", "zdx": "best_practice"},
    "healthcare": {"tier": "healthcare", "overlays": ["HIPAA", "HITRUST"], "zpa_preset": "healthcare", "aiguard": "HIPAA", "zdx": "microsoft_365"},
    "financial": {"tier": "strict", "overlays": ["PCI", "SOX"], "zpa_preset": "finance", "aiguard": "PCI", "zdx": "best_practice"},
    "general": {"tier": "balanced", "overlays": [], "zpa_preset": "general", "aiguard": "GENERAL", "zdx": "best_practice"},
    "education": {"tier": "balanced", "overlays": ["FERPA"], "zpa_preset": "education", "aiguard": "FERPA", "zdx": "microsoft_365"},
}
# ZIA baseline areas each intake product asks for (ATP is never on by default: it has no disabled state).
AREAS_FOR: Dict[str, List[str]] = {"url_filtering": ["url"], "threat": ["sandbox", "ftc"], "firewall": ["firewall"], "dns": ["dns"],
                                   "ssl": ["ssl"], "cloud_apps": ["cac"]}


def preset_for(vertical: str) -> Dict[str, Any]:
    """The builder defaults of an intake preset (data-driven: PRESET_DEFAULTS,
    then the preset's own "build" mapping)."""
    out = dict(PRESET_DEFAULTS["_default"])
    out.update(PRESET_DEFAULTS.get(str(vertical or ""), {}))
    try:
        import pov
        own = (pov.VERTICALS.get(str(vertical or "")) or {}).get("build")
    except Exception:  # noqa: BLE001 - no planner module: the table alone
        own = None
    if isinstance(own, dict):
        out.update({k: v for k, v in own.items() if k in PRESET_DEFAULTS["_default"]})
    return out


def catalog() -> List[Dict[str, Any]]:
    """The steps as the page offers them (no callables)."""
    return [{k: s[k] for k in ("key", "type", "section", "label", "scope", "needs", "arrives")} for s in STEPS]


def defaults(intake: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """{step key: {"on", "spec", "why"}} for a POV intake (pov.clean_intake's
    shape). Reads nothing. Every spec asks for the builders' safe defaults:
    rules disabled, segments disabled, AI Guard in Monitor."""
    products = list(intake.get("products") or [])
    prefix = str(intake.get("prefix") or "POV")
    domain = str(intake.get("domain") or "")
    customer = str(intake.get("customer") or "")
    pre = preset_for(str(intake.get("vertical") or ""))
    out: Dict[str, Dict[str, Any]] = {}
    areas = [a for a in ("firewall", "url", "ssl", "sandbox", "dns", "ftc", "cac") if any(a in AREAS_FOR.get(p, []) for p in products)]
    out["zia_baseline"] = {"on": bool(areas), "spec": {"type": "zia_baseline", "tier": pre["tier"], "mode": "tier", "prefix": prefix[:10],
                                                       "areas": areas or ["url", "ssl"], "overlays": list(pre["overlays"]), "enable_rules": False},
                           "why": "" if areas else "No ZIA product is in the intake."}
    out["ssl_certificates"] = {"on": False, "spec": {"type": "ssl_certificate_move", "certificate": "", "rules": []},
                               "why": "Pick the certificate and the Inspect rules to move (Load choices from the tenant)."}
    zpa = "zpa" in products
    out["zpa_connector_group"] = {"on": zpa, "spec": {"type": "zpa_connector_group", "prefix": prefix, "mode": "create", "location": "san_jose",
                                                      "max_usage": 5}, "why": "" if zpa else "ZPA is not in the intake."}
    seg_spec: Dict[str, Any] = {"type": "zpa_app_segments", "prefix": prefix, "enable": False}
    if domain:
        seg_spec["preset"] = {"vertical": pre["zpa_preset"], "domain": domain}
    out["zpa_app_segments"] = {"on": zpa and bool(domain), "spec": seg_spec,
                               "why": "" if zpa and domain else ("ZPA is not in the intake." if not zpa else "Enter the internal domain in the intake: the segments are made under it.")}
    out["zpa_policies"] = {"on": zpa and bool(domain), "spec": {"type": "zpa_policies", "prefix": prefix, "access": True, "timeout": True,
                                                               "inspection": False, "reauth_timeout": "28800", "reauth_idle_timeout": "3600"},
                           "why": out["zpa_app_segments"]["why"]}
    out["zcc_profiles"] = {"on": False, "spec": {"type": "zcc_profile_build", "platform": "windows",
                                                 "forwarding": {"template": "best_practice", "name": f"{prefix} POV forwarding"},
                                                 "app": {"template": "best_practice", "name": f"{prefix} POV Windows"}},
                           "why": "Tick it to build the Client Connector profiles the POV devices use."}
    zdx = "zdx" in products
    try:
        import ops_zdx
        tpl = ops_zdx.TEMPLATES.get(pre["zdx"]) or ops_zdx.TEMPLATES["best_practice"]
    except Exception:  # noqa: BLE001
        tpl = {"id": "best_practice", "predefined": [], "custom": []}
    custom = [{"name": f"{customer or prefix} intranet"[:60], "url": f"https://intranet.{domain}/", "cloudpath": True}] if domain else list(tpl.get("custom") or [])
    out["zdx_probes"] = {"on": zdx, "spec": {"type": "zdx_probes", "template": tpl.get("id") or "best_practice", "interval_minutes": 5,
                                             "protocol": "ADAPTIVE", "predefined": [dict(p) for p in tpl.get("predefined") or []
                                                                                    if p.get("provider") not in ("SHAREPOINT", "ONEDRIVE")],
                                             "custom": custom}, "why": "" if zdx else "ZDX is not in the intake."}
    out["aiguard_routing"] = {"on": False, "spec": {"type": "aiguard_routing", "prefix": prefix[:12], "apps": ["chatgpt", "m365copilot", "claude", "gemini"],
                                                    "cert": {}}, "why": "Tick it to send GenAI apps through AI Guard (needs ZIA platform and AI Guard ticked)."}
    out["aiguard_policy"] = {"on": False, "spec": {"type": "aiguard_detection_policy", "prefix": prefix[:12], "profile": pre["aiguard"], "mode": "monitor",
                                                   "apps": ["chatgpt", "m365copilot", "claude", "gemini"]},
                             "why": "Tick it to add an AI Guard detection policy (Monitor) for the GenAI apps."}
    return out


# ── Requests ──────────────────────────────────────────────────────────

def clean_parts(raw: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """[(step key, spec)] in the safe order, from a request's {key: spec}.
    Each spec must be an object of its step's operation type; an unknown
    step, a wrong type or an oversized spec is refused."""
    if not isinstance(raw, dict) or not raw:
        raise BuildError("Pick at least one part to build.")
    unknown = [str(k)[:40] for k in raw if k not in STEP_BY_KEY]
    if unknown:
        raise BuildError(f"Unknown part(s): {', '.join(unknown[:5])}. Use: {', '.join(ORDER)}.")
    out = []
    for key in ORDER:
        if key not in raw:
            continue
        spec = raw[key]
        if not isinstance(spec, dict):
            raise BuildError(f"{STEP_BY_KEY[key]['label']}: the part must be an object.")
        if spec.get("type") != STEP_BY_KEY[key]["type"]:
            raise BuildError(f"{STEP_BY_KEY[key]['label']}: its operation type must be {STEP_BY_KEY[key]['type']}.")
        if ao.is_undo_only(spec):
            raise BuildError(f"{STEP_BY_KEY[key]['label']}: an Undo is planned from the build's record (Undo on the build), never sent as a part.")
        if len(json.dumps(spec, default=str)) > MAX_SPEC_BYTES:
            raise BuildError(f"{STEP_BY_KEY[key]['label']}: the part is larger than {MAX_SPEC_BYTES // 1024} KB.")
        out.append((key, spec))
    return out


# ── The combined plan and its hash ────────────────────────────────────

def _core(prepared: Dict[str, Any]) -> Dict[str, Any]:
    """What admin_ops.plan_hash covers: the operation, its items (before,
    after, status, dependencies) and its writes."""
    return {"type": prepared["type"], "spec": prepared["spec"], "product": prepared.get("product"),
            "items": [[u["key"], u["field"], u["before"], u["after"], u["status"], u["depends_on"]] for u in prepared["items"]],
            "groups": [[g["key"], g["handler"], g["target"]] for g in prepared["groups"]]}


def normalized(core: Any, created: Optional[Dict[str, str]] = None) -> Any:
    """`core` with every id an earlier step of this run created (`created`:
    real id -> its stand-in) replaced by the stand-in the preview showed,
    and every list that holds a stand-in in a fixed order (the builders
    sort id lists; a real id and a stand-in sort differently)."""
    created = created or {}

    def walk(v: Any) -> Tuple[Any, bool]:
        if isinstance(v, str):
            if v in created:
                return created[v], True
            return v, v.startswith(ao.PENDING_PREFIX)
        if isinstance(v, dict):
            out, any_tok = {}, False
            for k, x in v.items():
                out[k], t = walk(x)
                any_tok = any_tok or t
            return out, any_tok
        if isinstance(v, (list, tuple)):
            items = [walk(x) for x in v]
            vals = [x for x, _ in items]
            tok = any(t for _, t in items)
            if tok and all(not isinstance(x, (dict, list)) for x in vals):
                vals = sorted(vals, key=lambda x: json.dumps(x, sort_keys=True, default=str))
            return vals, tok
        return v, False
    return walk(core)[0]


def _hash(obj: Any) -> str:
    return hashlib.sha256(ao._canonical(obj).encode("utf-8")).hexdigest()


def _phrase(n: int, undo: bool) -> str:
    return f"{'UNDO' if undo else 'APPLY'} {n} POV CHANGE{'S' if n != 1 else ''}"


def _part(key: str, prepared: Dict[str, Any], *, undo_of: str = "") -> Dict[str, Any]:
    step = STEP_BY_KEY.get(key, {})
    return {"key": key, "label": step.get("label") or key, "section": step.get("section") or "", "arrives": "" if undo_of else step.get("arrives") or "",
            "type": prepared["type"], "product": prepared.get("product"), "spec": prepared["spec"], "undo_of": undo_of or None,
            "title": prepared.get("title") or "", "status": prepared["status"], "counts": prepared["counts"],
            "plan_hash": prepared["plan_hash"], "confirm_phrase": prepared.get("confirm_phrase") or "",
            "warnings": list(prepared.get("warnings") or []), "blockers": list(prepared.get("blockers") or []),
            "notes": list(prepared.get("notes") or []), "impact": list(prepared.get("impact") or []),
            "items": [{k: u.get(k) for k in ("key", "kind", "object", "field", "value", "before", "after", "status", "reason")}
                      for u in prepared["items"]],
            "core": normalized(_core(prepared))}


def plan(client: Any, parts: Sequence[Tuple[str, Dict[str, Any]]], *, scope: Dict[str, Any], tenant_label: str = "", log: LogFn = None,
         cancel: Optional[threading.Event] = None, undo_of: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The combined dry run (reads only): every part planned by its builder
    in order, each with what the earlier parts create or delete in effect.
    `undo_of` ({key: operation id}) marks the parts of an Undo. Raises
    BuildError naming the part that cannot be planned, admin_ops.Stopped on Stop."""
    say = log or (lambda m: None)
    if not parts:
        raise BuildError("Pick at least one part to build.")
    creates: List[Tuple[str, str, str]] = []
    deletes: List[Tuple[str, str, str]] = []
    out_parts: List[Dict[str, Any]] = []
    for key, spec in parts:
        label = STEP_BY_KEY.get(key, {}).get("label") or key
        ao._check_stop(cancel)
        say(f"Planning {label}…")
        try:
            with ao.pending_plan(creates, deletes):
                prepared = ao.plan(client, spec, scope=scope, tenant_label=tenant_label, log=say, cancel=cancel)
        except ao.OperationError as e:
            raise BuildError(f"{label}: {e}")
        eff = ao.planned_effects(prepared)
        creates += eff["creates"]
        deletes += eff["deletes"]
        out_parts.append(_part(key, prepared, undo_of=(undo_of or {}).get(key, "")))
    undo = bool(undo_of)
    n = sum(p["counts"]["change"] for p in out_parts)
    blockers = [f"{p['label']}: {b}" for p in out_parts for b in p["blockers"]]
    status = "blocked" if blockers else ("nothing_to_do" if n == 0 else "ready")
    combined = {"kind": KIND, "undo": undo, "tenant_label": tenant_label, "parts": out_parts,
                "order": [p["key"] for p in out_parts], "changes": n, "status": status, "blockers": blockers,
                "sections": _sections(out_parts),
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    combined["plan_hash"] = _hash({"undo": undo, "parts": [[p["key"], p["undo_of"], p["core"]] for p in out_parts]})
    combined["confirm_phrase"] = _phrase(n, undo) if n else ""
    return combined


def _sections(parts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in parts:
        if not out or out[-1]["section"] != p["section"]:
            out.append({"section": p["section"], "parts": []})
        out[-1]["parts"].append(p["key"])
    return out


def public(combined: Dict[str, Any]) -> Dict[str, Any]:
    """The combined plan as the page and an export see it (no internal core)."""
    out = dict(combined)
    out["parts"] = [{k: v for k, v in p.items() if k != "core"} for p in combined.get("parts") or []]
    return out


# ── Apply ─────────────────────────────────────────────────────────────

def _created_ids(result: Dict[str, Any], product: str) -> Dict[str, str]:
    """real id -> stand-in of what an applied step created (its run's
    `created` list and its applied "exists" items)."""
    out: Dict[str, str] = {}
    for c in result.get("created") or []:
        if isinstance(c, dict) and c.get("id") not in (None, "") and c.get("kind") and c.get("name"):
            out[str(c["id"])] = ao.pending_token(product, str(c["kind"]), str(c["name"]))
    for u in result.get("items") or []:
        obj = u.get("object") or {}
        if (u.get("status") == "applied" and u.get("field") == "exists" and u.get("before") in (False, None)
                and obj.get("id") not in (None, "") and obj.get("name")):
            out.setdefault(str(obj["id"]), ao.pending_token(product, str(u.get("kind")), str(obj["name"])))
    return out


def _step_summary(part: Dict[str, Any], status: str, message: str = "", result: Optional[Dict[str, Any]] = None,
                  operation_id: Optional[str] = None) -> Dict[str, Any]:
    res = result or {}
    failed = [{"object": (u.get("object") or {}).get("name"), "field": u.get("field"), "status": u.get("status"),
               "reason": u.get("explanation") or u.get("reason") or u.get("error") or ""}
              for u in res.get("items") or [] if u.get("status") in ("failed", "conflict", "skipped")][:50]
    return {"key": part["key"], "label": part["label"], "section": part["section"], "type": part["type"], "status": status,
            "message": message, "operation_id": operation_id, "undo_of": part.get("undo_of"),
            "counts": res.get("counts_run") or {}, "verification": res.get("verification") or {},
            "activation": res.get("activation"), "problems": failed, "title": part.get("title") or "",
            # A new ZPA provisioning key: only its single-use token (ops_zpa.stash), never the key.
            "one_time_secrets": [{"name": x.get("name"), "token": x.get("token"), "expires_in_seconds": x.get("expires_in_seconds")}
                                 for x in res.get("one_time_secrets") or [] if isinstance(x, dict)] or None}


def execute(client: Any, parts: Sequence[Tuple[str, Dict[str, Any]]], *, plan_hash: str, scope: Dict[str, Any], writes_enabled: Optional[bool],
            confirm_text: str = "", assessor: str = "", tenant_label: str = "", log: LogFn = None, cancel: Optional[threading.Event] = None,
            record: RecordFn = None, undo_of: Optional[Dict[str, str]] = None, settle_seconds: float = 45.0) -> Dict[str, Any]:
    """Apply a previewed combined plan step by step (see the module
    docstring). `record(result, undo_of)` stores an applied step and returns
    its operation id. Returns {status, steps, applied_operations, logs, ...}."""
    if writes_enabled is not True:
        raise PermissionError("write mode is off: nothing was written")
    if not str(assessor or "").strip():
        raise BuildError("A named assessor is required to apply the POV build: nothing was read or written.")
    logs: List[str] = []

    def say(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    started = time.time()
    undo = bool(undo_of)
    say("Checking the previewed plan against the tenant as it is now (every part, in order)…")
    try:
        combined = plan(client, parts, scope=scope, tenant_label=tenant_label, log=say, cancel=cancel, undo_of=undo_of)
    except ao.Stopped as e:
        return {"kind": KIND, "status": "stopped", "message": str(e), "steps": [], "applied_operations": [], "logs": logs}
    base = {"kind": KIND, "undo": undo, "plan_hash": combined["plan_hash"], "tenant_label": tenant_label, "logs": logs}
    if not plan_hash or combined["plan_hash"] != plan_hash:
        say("The tenant changed since the preview: nothing was written. Review the new preview and confirm again.")
        return dict(base, status="plan_changed", expected_hash=plan_hash, preview=public(combined), steps=[], applied_operations=[],
                    message="The tenant changed since this preview (or the parts are not the ones previewed). Nothing was written: "
                            "review the new preview and confirm again.")
    if combined["status"] == "blocked":
        return dict(base, status="blocked", blockers=combined["blockers"], preview=public(combined), steps=[], applied_operations=[],
                    message="The plan has blockers: nothing was written.")
    import security
    if combined["confirm_phrase"] and not security.typed_phrase_matches(confirm_text, combined["confirm_phrase"]):
        return dict(base, status="refused", preview=public(combined), steps=[], applied_operations=[],
                    message=f"Type {combined['confirm_phrase']} to confirm the whole build. Nothing was written.")
    created: Dict[str, str] = {}
    steps: List[Dict[str, Any]] = []
    applied_ops: List[str] = []
    halt: Optional[Dict[str, Any]] = None
    for part in combined["parts"]:
        label = part["label"]
        if halt is not None:
            steps.append(_step_summary(part, "not_attempted", f"Not attempted: the run stopped at {halt['label']}."))
            continue
        if part["status"] == "nothing_to_do":
            steps.append(_step_summary(part, "nothing_to_do", "Nothing to change: already as asked."))
            continue
        if cancel is not None and cancel.is_set():
            halt = {"label": label, "status": "stopped"}
            steps.append(_step_summary(part, "not_attempted", "Not attempted: you clicked Stop."))
            continue
        say(f"{label}: reading the tenant again before writing…")
        try:
            fresh = ao.plan(client, part["spec"], scope=scope, tenant_label=tenant_label, log=say, cancel=cancel)
        except (ao.OperationError, ao.Stopped) as e:
            halt = {"label": label, "status": "failed"}
            steps.append(_step_summary(part, "failed", f"Could not be planned again, so nothing of it was written: {e}"))
            continue
        if normalized(_core(fresh), created) != part["core"]:
            halt = {"label": label, "status": "plan_changed"}
            say(f"STOPPED — {label} no longer matches the preview: the tenant changed while the build ran. Nothing of it was written.")
            steps.append(_step_summary(part, "plan_changed", "The tenant changed for this part since the preview (or while the earlier parts "
                                                             "ran): nothing of it was written. Undo what was applied, or preview again to finish."))
            continue
        res = ao.execute(client, part["spec"], plan_hash=fresh["plan_hash"], scope=scope, writes_enabled=True,
                         confirm_text=fresh.get("confirm_phrase") or "", assessor=assessor, tenant_label=tenant_label, log=say,
                         cancel=cancel, settle_seconds=settle_seconds)
        op_id = None
        if record is not None:
            try:
                op_id = record(res, part.get("undo_of") or "")
            except Exception as e:  # noqa: BLE001 - what was applied is reported even if the record failed
                res["record_error"] = f"not recorded for Undo: {str(e)[:200]}"
        if op_id:
            applied_ops.append(op_id)
        created.update(_created_ids(res, str(part.get("product") or "")))
        status = str(res.get("status") or "failed")
        if status in ("applied", "nothing_to_do"):
            steps.append(_step_summary(part, status, "Applied and read back." if status == "applied" else "Nothing to change.", res, op_id))
            continue
        halt = {"label": label, "status": status}
        why = res.get("message") or res.get("stopped") or "; ".join(res.get("blockers") or []) or ""
        say(f"STOPPED at {label} ({status}). Nothing after it is written.")
        steps.append(_step_summary(part, status, f"Stopped here ({status.replace('_', ' ')}){': ' + str(why)[:300] if why else ''}. "
                                                  "Nothing after it was written.", res, op_id))
    n_applied = sum(1 for s in steps if s["status"] == "applied")
    if halt is None:
        status = "applied" if n_applied else "nothing_to_do"
    elif applied_ops or any(s["status"] == "partial" for s in steps):
        status = "stopped"
    else:
        status = "failed"
    say({"applied": "Every part was applied.", "nothing_to_do": "Nothing to change.",
         "stopped": f"Stopped at {halt['label'] if halt else ''}: what was applied so far is listed; Undo reverses it.",
         "failed": f"Nothing was applied: {halt['label'] if halt else ''} did not apply."}[status])
    return dict(base, status=status, steps=steps, applied_operations=applied_ops, stopped_at=halt["label"] if halt else None,
                changes=combined["changes"], elapsed_seconds=round(time.time() - started, 1),
                undo_available=bool(applied_ops) and not undo)


# ── The build record and its Undo ─────────────────────────────────────

def build_record(result: Dict[str, Any], *, by: str, build_id: str) -> Dict[str, Any]:
    """What the POV keeps about an applied build: its steps, the operation
    each step was recorded as, the plan hash. No secret, no tenant data."""
    return {"id": build_id, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "by": by, "plan_hash": result.get("plan_hash"),
            "status": result.get("status"), "undo": bool(result.get("undo")),
            "steps": [{"key": s["key"], "label": s["label"], "status": s["status"], "operation_id": s.get("operation_id")}
                      for s in result.get("steps") or []]}


def undo_parts(build: Dict[str, Any], get_operation: Callable[[str], Optional[Dict[str, Any]]]) -> Tuple[List[Tuple[str, Dict[str, Any]]], Dict[str, str]]:
    """([(key, inverse spec)], {key: operation id}) of a build's Undo: each
    applied step's recorded inverse, latest first. Steps already undone, or
    whose run applied nothing reversible, are left out."""
    parts: List[Tuple[str, Dict[str, Any]]] = []
    ids: Dict[str, str] = {}
    for s in reversed(build.get("steps") or []):
        op = s.get("operation_id")
        if not op:
            continue
        rec = get_operation(str(op))
        if not rec or rec.get("undone_by") or not isinstance(rec.get("inverse"), dict):
            continue
        parts.append((s["key"], rec["inverse"]))
        ids[s["key"]] = str(op)
    return parts, ids
