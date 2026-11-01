"""DLP dictionaries and engines, ad hoc: create, edit or delete one custom
dictionary or engine on the Bulk changes engine (admin_ops plugin).

One operation type on /report/operations, under "Change":

  dlp_object_edit
    object dictionary  a custom dictionary: name, description, match type,
                       phrases and patterns (each "all" or "unique"
                       matches), proximity; or the confidence of a dictionary
                       that carries one (a predefined dictionary or a clone:
                       a custom one has none in ZIA). Checked before anything
                       is read against ZIA's limits and the ReDoS guard
                       (dlp_importer.dictionary_limit_problems, the checks a
                       policy pack deploy runs).
    object engine      a custom engine: name, description and its
                       expression. The expression is read by the app's own
                       engine-expression parser (engine_explain.parse): every
                       dictionary it names must exist, `D:<name>` is turned
                       into `D<id>.S` (dlp_importer.resolve_engine_expression)
                       and the preview shows what it means in words (the DLP
                       explainer: engine_explain.readable and summary, before
                       and after).
    action create      created as asked (a dictionary or engine matches
                       nothing until a rule uses it); Undo deletes it.
    action update      the object is sent back as read with only the asked
                       fields changed (PUT); Undo puts them back. A change
                       to what it matches (phrases, patterns, match type,
                       proximity, confidence, expression) while an enabled
                       DLP rule uses it (an engine directly, a dictionary
                       through an engine) asks "APPLY <n> CHANGES" typed; a
                       rule policy not in scope or unreadable cannot be
                       checked, so it counts as used.
    action delete      typed "DELETE <name>"; refused while anything uses it:
                       a dictionary named by any engine's expression, an
                       engine named by any DLP rule (Web, Endpoint, Email and
                       SaaS DLP rules are read; one not in scope on the Scope
                       page cannot be checked, so the delete is blocked until
                       it is ticked). Predefined objects are never deleted.
                       Undo creates it again (a new id).

The engine supplies the scope check before any read (DLP in scope: Inline
Web DLP rules readable), the plan hash and re-plan, write mode, the writer,
the named assessor, the typed confirmation, the re-read right before each
write (an object changed since the preview is a conflict, left alone), one
ZIA activation, the read-back, the record, the audit log with the actor,
and Undo.

SDK calls, verified against zscaler-sdk-python 1.11.3: zia/dlp_dictionary.py
list_dicts, get_dict, add_dict (name, custom_phrase_match_type,
dictionary_type, phrases and patterns as (action, text) pairs, description,
proximity...), update_dict (PUT), delete_dict; zia/dlp_engine.py
list_dlp_engines, get_dlp_engines, add_dlp_engine (name, description,
engine_expression, custom_dlp_engine), update_dlp_engine, delete_dlp_engine.
Writes go through pack_ops (kinds dictionary and engine); the update body is
pack_deploy.dictionary_update_body (the dictionary as read). DLP rules:
admin_ops.read_rules (field dlp_engines).
ASSUMED: that ZIA itself refuses deleting an object something outside the
rules read here uses.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import dlp_importer as di
import engine_explain as ee
import ops_zia_baseline as zb
import pack_ops as ops

TYPE = "dlp_object_edit"
FAMILY = "dlp_object_targets"
SCRIPT = "ops_dlp_objects.js"
RULE_POLICIES = ("web_dlp", "endpoint_dlp", "email_dlp", "saas_dlp")
CONFIDENCE = ("CONFIDENCE_LEVEL_LOW", "CONFIDENCE_LEVEL_MEDIUM", "CONFIDENCE_LEVEL_HIGH")
ACTIONS = {"phrases": {"all": "PHRASE_COUNT_TYPE_ALL", "unique": "PHRASE_COUNT_TYPE_UNIQUE"},
           "patterns": {"all": "PATTERN_COUNT_TYPE_ALL", "unique": "PATTERN_COUNT_TYPE_UNIQUE"}}
DICT_FIELDS = ("name", "description", "custom_phrase_match_type", "phrases", "patterns", "proximity", "confidence_threshold")
ENGINE_FIELDS = ("name", "description", "expression")
MAX_DICTS = 3000
NOT_CHECKED = "Anything outside the DLP rules and engines read here that uses it makes ZIA refuse the delete (assumed)."

LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    if "web_dlp" in (scope.get("policies") or []):
        return None
    return ((scope.get("not_in_scope") or {}).get("web_dlp") or "Not in scope: DLP dictionaries and engines are read and changed when DLP "
            "is ticked on the Scope page (Inline Web DLP). Nothing was read.")


# ---------------------------------------------------------------------------
# Reading (GET only)
# ---------------------------------------------------------------------------

def _svc(zia: Any, obj: str) -> Any:
    name = "dlp_dictionary" if obj == "dictionary" else "dlp_engine"
    svc = getattr(zia, name, None)
    if svc is None:
        raise ao.OperationError(f"The installed zscaler-sdk-python has no {name} service.")
    return svc


def read_all(zia: Any, obj: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    svc = _svc(zia, obj)
    try:
        rows, err = ao._rows(svc.list_dicts() if obj == "dictionary" else svc.list_dlp_engines())
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"
    return [zb._deep_snake(r) for r in rows][:MAX_DICTS], err


def get_one(zia: Any, obj: str, oid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    svc = _svc(zia, obj)
    try:
        row, err = ao._one(svc.get_dict(oid) if obj == "dictionary" else svc.get_dlp_engines(oid))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    return (zb._deep_snake(row) if row else None), err


def is_custom(row: Dict[str, Any], obj: str) -> bool:
    if obj == "dictionary":
        return ao._truthy(row.get("custom")) and not ao._truthy(row.get("predefined_clone_of_custom"))
    return ao._truthy(row.get("custom_dlp_engine")) and not row.get("predefined_engine_name")


def _items(row: Dict[str, Any], key: str) -> List[Dict[str, str]]:
    field = key[:-1]
    out = []
    for x in row.get(key) or []:
        if isinstance(x, dict) and str(x.get(field) or ""):
            out.append({"action": str(x.get("action") or ""), field: str(x.get(field))})
    return out


def state(row: Dict[str, Any], obj: str) -> Dict[str, Any]:
    """The managed fields as read (what the preview compares and the conflict guard checks)."""
    if obj == "dictionary":
        return {"name": str(row.get("name") or ""), "description": str(row.get("description") or ""),
                "custom_phrase_match_type": str(row.get("custom_phrase_match_type") or ""), "phrases": _items(row, "phrases"),
                "patterns": _items(row, "patterns"), "proximity": ao._int(row.get("proximity"), 0),
                "confidence_threshold": str(row.get("confidence_threshold") or "")}
    return {"name": str(row.get("name") or ""), "description": str(row.get("description") or ""), "expression": str(row.get("engine_expression") or "")}


def engine_dict_ids(expr: str) -> List[str]:
    return sorted({m.group(1) for m in ee._ID_TERM_RE.finditer(str(expr or ""))})


MATCHING_FIELDS = ("phrases", "patterns", "custom_phrase_match_type", "proximity", "confidence_threshold", "expression")


def live_users(zia: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event], obj: str, row: Dict[str, Any],
               engines: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """(enabled DLP rules that use the object, directly for an engine or
    through an engine for a dictionary; what could not be checked). A rule
    policy not in scope or not readable cannot be checked, so it is listed:
    unknown is treated as used (the typed phrase is asked)."""
    oid = str(row.get("id"))
    eids = {oid} if obj == "engine" else {str(e.get("id")) for e in engines if oid in engine_dict_ids(e.get("engine_expression"))}
    if not eids:
        return [], []
    refs, rerr, out = rule_engine_refs(zia, scope, say, cancel)
    live = [f"{r['policy_label']} rule {r['order']} '{r['name']}'" for eid in sorted(eids) for r in refs.get(eid, []) if r["state"] == "ENABLED"]
    unknown = ([f"{', '.join(out)} not in scope on the Scope page"] if out else []) + [f"could not be read: {e}" for e in rerr]
    return live, unknown


def rule_engine_refs(zia: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str], List[str]]:
    refs: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[str] = []
    pols = [p for p in RULE_POLICIES if p in (scope.get("policies") or [])]
    out = [ao._label(p) for p in RULE_POLICIES if p not in (scope.get("policies") or [])]
    for pol in pols:
        ao._check_stop(cancel)
        say(f"Reading the {ao._label(pol)} rules (which rules use the engines)…")
        try:
            rows, err = ao.read_rules(zia, pol, cancel=cancel)
        except ao.OperationError as e:
            rows, err = [], str(e)
        if err:
            errors.append(f"{ao._label(pol)}: {err}")
            continue
        for r in rows:
            for e in r.get("dlp_engines") or []:
                eid = e.get("id") if isinstance(e, dict) else e
                if eid not in (None, ""):
                    refs.setdefault(str(eid), []).append({"policy": pol, "policy_label": ao._label(pol), "id": r.get("id"),
                                                          "name": str(r.get("name") or ""), "order": r.get("order"), "state": ao._state(r)})
    return refs, errors, out


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Every dictionary (custom ones editable) and engine with its expression
    in words, and what uses each. Read-only."""
    zia = client.zia
    errors: Dict[str, str] = {}
    say("Reading the DLP dictionaries…")
    dicts, err = read_all(zia, "dictionary")
    if err:
        errors["dictionaries"] = err
    say("Reading the DLP engines…")
    engines, err = read_all(zia, "engine")
    if err:
        errors["engines"] = err
    refs, rerr, out = rule_engine_refs(zia, scope, say, cancel)
    if rerr:
        errors["rules"] = "; ".join(rerr)
    names = ee.names_by_id(dicts)
    used_by_engines: Dict[str, List[str]] = {}
    for e in engines:
        for d in engine_dict_ids(e.get("engine_expression")):
            used_by_engines.setdefault(d, []).append(str(e.get("name") or ""))
    return {"dictionaries": [dict(state(d, "dictionary"), id=d.get("id"), custom=is_custom(d, "dictionary"), used_by=used_by_engines.get(str(d.get("id")), []))
                             for d in sorted(dicts, key=lambda d: str(d.get("name") or "").lower())],
            "engines": [dict(state(e, "engine"), id=e.get("id"), custom=is_custom(e, "engine"), readable=ee.readable(e.get("engine_expression") or "", names),
                             summary=ee.summary(e.get("engine_expression") or "", names), used_by=refs.get(str(e.get("id")), []))
                        for e in sorted(engines, key=lambda e: str(e.get("name") or "").lower())],
            "match_types": list(di.DICT_MATCH_TYPES), "confidence_levels": list(CONFIDENCE), "errors": errors, "not_checked": out,
            "limits": {"phrases": di.DICT_MAX_PHRASES, "patterns": di.DICT_MAX_PATTERNS, "pattern_bytes": di.DICT_PATTERN_MAX_BYTES,
                       "expression": ee.MAX_EXPRESSION}}


def explain_expression(expr: str, dicts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The DLP explainer's answer for one expression (pure; for the page's live preview too)."""
    return ee.explain(expr, ee.names_by_id(dicts))


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

def _oid(v: Any, what: str) -> int:
    s = str(v if v is not None else "").strip()
    if not re.fullmatch(r"[0-9]{1,19}", s):
        raise ao.OperationError(f"{what} must be the id of an existing object (a number).")
    return int(s)


def _text(v: Any, what: str, limit: int) -> str:
    s = " ".join(str(v if v is not None else "").split())
    if ao._has_control(s) or len(s.encode("utf-8")) > limit:
        raise ao.OperationError(f"The {what} must be at most {limit} bytes, with no control character.")
    return s


def _entries(raw: Any, key: str) -> List[Dict[str, str]]:
    if not isinstance(raw, list):
        raise ao.OperationError(f"{key} must be a list of {{\"{key[:-1]}\": ..., \"action\": \"all\" or \"unique\"}}.")
    field, cap = key[:-1], (di.DICT_MAX_PHRASES if key == "phrases" else di.DICT_MAX_PATTERNS)
    if len(raw) > cap:
        raise ao.OperationError(f"At most {cap} {key} per dictionary (ZIA's limit).")
    out = []
    for x in raw:
        if not isinstance(x, dict):
            raise ao.OperationError(f"Each of the {key} is an object with a {field} and an action.")
        text = str(x.get(field) if x.get(field) is not None else "")
        if not text or "\x00" in text or len(text) > 1000:
            raise ao.OperationError(f"A {field} must be non-empty text without a NUL character.")
        act = str(x.get("action") or "all").strip()
        act = ACTIONS[key].get(act.lower(), act.upper())
        if act not in ACTIONS[key].values():
            raise ao.OperationError(f"A {field}'s action is all or unique.")
        out.append({"action": act, field: text})
    return out


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    obj = str(spec.get("object") or "").strip().lower()
    if obj not in ("dictionary", "engine"):
        raise ao.OperationError("Pick what to change: a dictionary or an engine.")
    act = str(spec.get("action") or "").strip().lower()
    undo = spec.get("undo") is True
    if act not in ("create", "update", "delete"):
        raise ao.OperationError("Pick create, update or delete.")
    n: Dict[str, Any] = {"type": TYPE, "object": obj, "action": act}
    if undo:
        n["undo"] = True
    if act != "create":
        n["id"] = _oid(spec.get("id"), f"The {obj}")
    if act == "delete":
        if undo:
            n["expect"] = spec.get("expect") if isinstance(spec.get("expect"), dict) else {}
        return n
    raw = spec.get("fields") if isinstance(spec.get("fields"), dict) else {}
    allowed = DICT_FIELDS if obj == "dictionary" else ENGINE_FIELDS
    extra = sorted(set(raw) - set(allowed))
    if extra:
        raise ao.OperationError(f"Only {', '.join(allowed)} can be set on a {obj}, not {', '.join(extra[:3])}.")
    f: Dict[str, Any] = {}
    if "name" in raw:
        f["name"] = _text(raw["name"], f"{obj} name", di.DICT_NAME_MAX)
        probs = di.name_problems(f["name"], obj)
        if probs:
            raise ao.OperationError(probs[0])
    if "description" in raw:
        f["description"] = _text(raw["description"], "description", di.DICT_DESCRIPTION_MAX if obj == "dictionary" else di.ENGINE_DESCRIPTION_MAX)
    if obj == "dictionary":
        for key in ("phrases", "patterns"):
            if key in raw:
                f[key] = _entries(raw[key], key)
        if "custom_phrase_match_type" in raw:
            mt = str(raw["custom_phrase_match_type"] or "").strip().upper()
            if mt not in di.DICT_MATCH_TYPES:
                raise ao.OperationError("The match type is one of " + ", ".join(di.DICT_MATCH_TYPES) + ".")
            f["custom_phrase_match_type"] = mt
        if "proximity" in raw:
            try:
                f["proximity"] = int(raw["proximity"] or 0)
            except (TypeError, ValueError):
                raise ao.OperationError("Proximity is a number of bytes.")
            if not 0 <= f["proximity"] <= di.DICT_PROXIMITY_MAX:
                raise ao.OperationError(f"Proximity is 0 to {di.DICT_PROXIMITY_MAX} bytes.")
        if "confidence_threshold" in raw:
            c = str(raw["confidence_threshold"] or "").strip().upper()
            if c not in CONFIDENCE:
                raise ao.OperationError("The confidence is CONFIDENCE_LEVEL_LOW, _MEDIUM or _HIGH.")
            if act == "create":
                raise ao.OperationError("A custom dictionary has no confidence in ZIA; confidence is set on a dictionary that has one.")
            f["confidence_threshold"] = c
    else:
        if "expression" in raw:
            expr = str(raw["expression"] or "").strip()
            if not expr or len(expr) > ee.MAX_EXPRESSION or ao._has_control(expr):
                raise ao.OperationError(f"The engine's expression is required, at most {ee.MAX_EXPRESSION} characters, with no control character.")
            f["expression"] = expr
    if act == "create":
        if "name" not in f:
            raise ao.OperationError(f"Name the new {obj}.")
        if obj == "engine" and "expression" not in f:
            raise ao.OperationError("Give the new engine its expression.")
        if obj == "dictionary" and not f.get("phrases") and not f.get("patterns"):
            raise ao.OperationError("A new dictionary needs at least one phrase or pattern.")
    elif not f:
        raise ao.OperationError("Change at least one field.")
    n["fields"] = f
    return n


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _show(field: str, v: Any) -> Any:
    if field in ("phrases", "patterns"):
        key = field[:-1]
        return "; ".join(f"{x[key]} ({'unique' if x['action'].endswith('UNIQUE') else 'all'})" for x in v or []) or "(none)"
    return v


def _obj(obj: str, oid: Any, name: str) -> Dict[str, Any]:
    return {"type": "dlp_dictionary" if obj == "dictionary" else "dlp_engine", "policy_label": "DLP dictionary" if obj == "dictionary" else "DLP engine",
            "id": oid, "name": name, "object": obj}


def _resolve(expr: str, dicts: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
    """The expression with D:<name> turned into D<id>.S, and the problems found."""
    by_name = {str(d.get("name") or ""): d.get("id") for d in dicts if d.get("id") is not None}
    out, unresolved = di.resolve_engine_expression(expr, by_name)
    problems = [f"no dictionary is named '{u}'" for u in unresolved]
    ids = {str(d.get("id")) for d in dicts}
    problems += [f"no dictionary has id {i}" for i in engine_dict_ids(out) if i not in ids]
    try:
        ee.parse(out)
    except ee.ParseError as e:
        problems.append(f"the expression cannot be read: {str(e)[:120]}")
    except RecursionError:
        problems.append("the expression nests too deeply")
    problems += di.engine_limit_problems(out)
    return out, problems


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    zia = client.zia
    obj, act = n["object"], n["action"]
    say("Reading the DLP dictionaries…")
    dicts, err = read_all(zia, "dictionary")
    if err:
        raise ao.OperationError(f"The DLP dictionaries could not be read: {err}. Nothing was written.")
    engines: List[Dict[str, Any]] = []
    if obj == "engine" or act in ("delete", "update"):
        say("Reading the DLP engines…")
        engines, err = read_all(zia, "engine")
        if err:
            raise ao.OperationError(f"The DLP engines could not be read: {err}. Nothing was written.")
    rows = dicts if obj == "dictionary" else engines
    names = ee.names_by_id(dicts)
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    impact: List[Dict[str, Any]] = []
    notes: List[str] = []
    confirm = ""
    label = "dictionary" if obj == "dictionary" else "engine"
    explain: Optional[Dict[str, Any]] = None
    if act == "create":
        f = dict(n["fields"])
        title = f"New DLP {label} '{f['name']}'"
        o = _obj(obj, None, f["name"])
        if any(str(r.get("name") or "").strip().lower() == f["name"].lower() for r in rows):
            items.append(ao._unit("obj", "obj", o["type"], o, "exists", True, True, status="excluded", reason=f"a {label} with this name exists"))
        else:
            if obj == "dictionary":
                d = {"name": f["name"], "description": f.get("description", ""), "phrases": f.get("phrases") or [], "patterns": f.get("patterns") or [],
                     "custom_phrase_match_type": f.get("custom_phrase_match_type") or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                     "proximity": f.get("proximity") or 0}
                blockers += [f"The dictionary is outside ZIA's limits: {p}." for p in di.dictionary_limit_problems(d)]
                target = {"object": obj, "name": f["name"], "definition": d}
            else:
                expr, probs = _resolve(f["expression"], dicts)
                blockers += [f"The engine's expression: {p}." for p in probs]
                explain = {"after": ee.explain(expr, names)}
                target = {"object": obj, "name": f["name"], "definition": {"name": f["name"], "description": f.get("description", ""), "engine_expression": expr}}
            items.append(ao._unit("obj", "obj", o["type"], o, "exists", False, True, reason=f"new custom {label}; nothing uses it until "
                                  f"{'an engine names it' if obj == 'dictionary' else 'a DLP rule names it'}; Undo deletes it"))
            for k, v in (target["definition"].items()):
                if k != "name" and v not in ("", [], 0, None):
                    items.append(ao._unit(f"obj:{k}", "obj", o["type"], o, k, None, _show(k, v), depends_on=["obj"]))
            groups.append({"key": "obj", "handler": "dlp_obj_create", "target": target})
    else:
        row = next((r for r in rows if str(r.get("id")) == str(n["id"])), None)
        if row is None:
            if act == "delete":
                return {"type": TYPE, "product": "zia", "title": f"Delete a DLP {label}", "spec": n,
                        "items": [ao._unit("obj", "obj", _obj(obj, n["id"], str(n["id"]))["type"], _obj(obj, n["id"], str(n["id"])), "exists", False, False,
                                           status="noop", reason="already gone")], "groups": []}
            raise ao.OperationError(f"DLP {label} {n['id']} is not in this tenant now. Read again.")
        cur = state(row, obj)
        o = _obj(obj, row.get("id"), cur["name"])
        if act == "update":
            title = f"Edit the DLP {label} '{cur['name']}'"
            custom = is_custom(row, obj)
            want = dict(n["fields"])
            if not custom and set(want) - {"confidence_threshold"}:
                items.append(ao._unit("obj", "obj", o["type"], o, "fields", None, None, status="excluded",
                                      reason=f"a predefined {label}: only a dictionary's confidence can be changed here"))
                want = {}
            if "confidence_threshold" in want and not cur["confidence_threshold"]:
                items.append(ao._unit("obj:confidence_threshold", "obj", o["type"], o, "confidence_threshold", "", want.pop("confidence_threshold"),
                                      status="excluded", reason="this dictionary has no confidence in ZIA (a custom dictionary has none)"))
            if obj == "engine" and "expression" in want:
                expr, probs = _resolve(want["expression"], dicts)
                blockers += [f"The engine's expression: {p}." for p in probs]
                want["expression"] = expr
                explain = {"before": ee.explain(cur["expression"], names), "after": ee.explain(expr, names)}
            changed = {}
            for k, v in want.items():
                if cur.get(k) == v:
                    items.append(ao._unit(f"obj:{k}", "obj", o["type"], o, k, _show(k, cur.get(k)), _show(k, v), status="noop", reason="already as asked"))
                else:
                    changed[k] = v
                    items.append(ao._unit(f"obj:{k}", "obj", o["type"], o, k, _show(k, cur.get(k)), _show(k, v)))
            if obj == "dictionary" and changed:
                merged = dict(cur, **changed)
                blockers += [f"The dictionary would be outside ZIA's limits: {p}." for p in di.dictionary_limit_problems(merged)]
                if (merged.get("phrases") or merged.get("patterns")) == [] and custom:
                    blockers.append("A custom dictionary needs at least one phrase or pattern.")
            if changed:
                groups.append({"key": "obj", "handler": "dlp_obj_update", "target": {"object": obj, "id": row.get("id"), "name": cur["name"], "before": cur,
                                                                                    "set": changed, "undo_set": {k: cur.get(k) for k in changed}}})
                notes.append(f"The {label} is sent back as read with only the changed fields (PUT); Undo puts them back.")
                if obj == "dictionary" and any(k in changed for k in ("phrases", "patterns", "custom_phrase_match_type", "proximity", "confidence_threshold")):
                    warnings.append("What this dictionary matches changes at once (after activation) for every engine and rule that uses it.")
                if obj == "engine" and "expression" in changed:
                    warnings.append("What this engine detects changes at once (after activation) for every DLP rule that uses it.")
                if any(k in changed for k in MATCHING_FIELDS):
                    live, unknown = live_users(zia, scope, say, cancel, obj, row, engines)
                    if live or unknown:
                        # A change to what an enabled rule detects acts on traffic at activation: typed, as ip_group_edit does.
                        confirm = f"APPLY {len(changed)} CHANGE{'' if len(changed) == 1 else 'S'}"
                        impact.append({"object": cur["name"], "id": row.get("id"), "used_by": live,
                                       "detail": (f"Used by {len(live)} enabled DLP rule{'s' if len(live) != 1 else ''}: what "
                                                  f"{'they detect' if len(live) != 1 else 'it detects'} changes at activation. " if live else "")
                                                 + (f"Not checked ({'; '.join(unknown)}), so it is treated as used. " if unknown else "")
                                                 + f"Type {confirm} to confirm."})
        else:
            title = f"Delete the DLP {label} '{cur['name']}'"
            if not is_custom(row, obj):
                items.append(ao._unit("obj", "obj", o["type"], o, "exists", True, False, status="excluded", reason=f"a predefined {label}: never deleted"))
            elif n.get("undo") and n.get("expect") and any(state(row, obj).get(k) != v for k, v in n["expect"].items()):
                items.append(ao._unit("obj", "obj", o["type"], o, "exists", True, False, status="excluded",
                                      reason="it changed since this app created it, so it is kept (someone else's change is never removed)"))
            else:
                users: List[str] = []
                if obj == "dictionary":
                    users = [f"engine '{e.get('name')}'" for e in engines if str(row.get("id")) in engine_dict_ids(e.get("engine_expression"))]
                else:
                    refs, rerr, out = rule_engine_refs(zia, scope, say, cancel)
                    users = [f"{r['policy_label']} rule {r['order']} '{r['name']}' ({r['state'].lower()})" for r in refs.get(str(row.get("id")), [])]
                    if out:
                        blockers.append("These DLP rules can name an engine but are not in scope on the Scope page, so they cannot be checked: "
                                        + ", ".join(out) + ". Tick them, read again and preview again; nothing was deleted.")
                    if rerr:
                        blockers.append("These rules could not be read, so the delete cannot be checked: " + "; ".join(rerr) + ".")
                impact.append({"object": cur["name"], "id": row.get("id"), "used_by": users,
                               "detail": f"Used by {len(users)}: change {'them' if len(users) != 1 else 'it'} first." if users else "Nothing read here uses it."})
                if users:
                    items.append(ao._unit("obj", "obj", o["type"], o, "exists", True, False, status="excluded",
                                          reason="still used by " + "; ".join(users[:10]) + (f" and {len(users) - 10} more" if len(users) > 10 else "")))
                else:
                    items.append(ao._unit("obj", "obj", o["type"], o, "exists", True, False,
                                          reason="Undo deletes what the change created" if n.get("undo") else "Undo creates it again (with a new id)"))
                    groups.append({"key": "obj", "handler": "dlp_obj_delete", "target": {"object": obj, "id": row.get("id"), "name": cur["name"], "before": cur,
                                                                                        "raw": _recreate_definition(row, obj)}})
                    confirm = f"DELETE {cur['name']}" if len(cur["name"]) <= 60 else f"DELETE DLP {label.upper()}"
                    warnings.append(NOT_CHECKED)
            if obj == "engine":
                explain = {"before": ee.explain(cur["expression"], names)}
    out = {"type": TYPE, "product": "zia", "title": ("Undo: " if n.get("undo") else "") + title, "spec": n, "items": items, "groups": groups,
           "warnings": warnings, "blockers": blockers, "impact": impact, "notes": notes, "confirm_always": confirm}
    if explain:
        out["explain"] = explain
    return out


def _recreate_definition(row: Dict[str, Any], obj: str) -> Dict[str, Any]:
    """What an Undo of a delete sends to create the object again."""
    s = state(row, obj)
    if obj == "dictionary":
        d = {k: s[k] for k in ("name", "description", "custom_phrase_match_type", "phrases", "patterns", "proximity")}
        d["custom_phrase_match_type"] = d["custom_phrase_match_type"] or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
        return d
    return {"name": s["name"], "description": s["description"], "engine_expression": s["expression"]}


# ---------------------------------------------------------------------------
# Writes (pack_ops), each right after the object is read again
# ---------------------------------------------------------------------------

def create_payload(t: Dict[str, Any]) -> Dict[str, Any]:
    d = t["definition"]
    if t["object"] == "engine":
        body = {"name": d["name"], "engine_expression": d["engine_expression"], "custom_dlp_engine": True}
        if d.get("description"):
            body["description"] = d["description"]
        return body
    kwargs, err = di.build_dict_kwargs(dict(d), {})
    if err:
        raise ao.OperationError(err)
    if not kwargs.get("description"):
        kwargs.pop("description", None)
    return dict(name=d["name"], custom_phrase_match_type=d["custom_phrase_match_type"], dictionary_type="PATTERNS_AND_PHRASES", **kwargs)


def update_payload(fresh_raw: Any, obj: str, changes: Dict[str, Any]) -> Dict[str, Any]:
    if obj == "engine":
        body = {"name": str(fresh_raw.get("name") or ""), "description": str(fresh_raw.get("description") or ""),
                "engine_expression": str(fresh_raw.get("engine_expression") or ""), "custom_dlp_engine": True}
        for k, v in changes.items():
            body["engine_expression" if k == "expression" else k] = v
        if not body["description"]:
            body.pop("description")
        return body
    import pack_deploy
    ch: Dict[str, Any] = {}
    for k, v in changes.items():
        if k in ("phrases", "patterns"):
            ch[k] = [(x["action"], x[k[:-1]]) for x in v]
        else:
            ch[k] = v
    body = pack_deploy.dictionary_update_body(fresh_raw, **ch)
    if changes.get("proximity"):
        body["proximity_length_enabled"] = True
        body["proximity_enabled_for_custom_dictionary"] = True
    for k in ("phrases", "patterns"):
        if k in changes and not changes[k]:
            body[k] = []
    return body


def _reread(run: Any, units: List[Dict[str, Any]], t: Dict[str, Any], *, gone_ok: bool) -> Optional[Dict[str, Any]]:
    fresh, err = get_one(run.zia, t["object"], t["id"])
    if fresh is not None:
        return fresh
    halt = ao._read_halt(err)
    if halt:
        run.halt = halt
        run.mark(units, "skipped", f"not attempted: {halt}")
    elif gone_ok:
        run.mark(units, "noop", "already gone")
    else:
        run.mark(units, "failed", "", error=f"could not read it again before the change: {err}"[:300])
        run.counts["failed"] += 1
    return None


def h_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = read_all(run.zia, t["object"])
    if err:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the DLP {t['object']}s")
        return
    if any(str(r.get("name") or "").strip().lower() == t["name"].lower() for r in rows):
        run.mark(units, "conflict", f"a {t['object']} named '{t['name']}' was made since the preview; nothing was created")
        run.counts["skipped"] += len(units)
        return
    out = ops.create(run.zia, t["object"], create_payload(t), name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.created.append({"type": t["object"], "id": out.id, "name": t["name"]})
        run.log(f"[DLP {t['object']}] {t['name']}: created")


def h_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh = _reread(run, units, t, gone_ok=False)
    if fresh is None:
        return
    if state(fresh, t["object"]) != t["before"]:
        run.mark(units, "conflict", "it changed since the preview; left as it is")
        run.counts["skipped"] += len(units)
        return
    out = ops.update(run.zia, t["object"], t["id"], update_payload(fresh, t["object"], t["set"]), name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[DLP {t['object']}] {t['name']}: {', '.join(t['set'])} changed")


def h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh = _reread(run, units, t, gone_ok=True)
    if fresh is None:
        return
    if state(fresh, t["object"]) != t["before"]:
        run.mark(units, "conflict", "it changed since the preview, so it is kept")
        run.counts["skipped"] += len(units)
        return
    out = ops.delete(run.zia, {"kind": t["object"], "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[DLP {t['object']}] {t['name']}: deleted")


HANDLERS = {"dlp_obj_create": h_create, "dlp_obj_update": h_update, "dlp_obj_delete": h_delete}


def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        units = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not units:
            continue
        t = g["target"]
        oid = units[0]["object"].get("id") if g["handler"] == "dlp_obj_create" else t["id"]
        row, err = get_one(run.zia, t["object"], oid) if oid not in (None, "") else (None, "no id")
        out["checked"] += len(units)
        if g["handler"] == "dlp_obj_delete":
            ok = row is None and not ao._read_halt(err)
        elif row is None:
            out["checked"] -= len(units)
            out["unread"].append(f"{t['name']}: {err}")
            continue
        elif g["handler"] == "dlp_obj_update":
            s = state(row, t["object"])
            ok = all(s.get(k) == v for k, v in t["set"].items())
        else:
            s = state(row, t["object"])
            d = t["definition"]
            ok = s["name"] == t["name"] and (s["expression"] == d["engine_expression"] if t["object"] == "engine" else
                                             s["phrases"] == d["phrases"] and s["patterns"] == d["patterns"])
        for u in units:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(units)
        else:
            out["mismatched"].append(f"{t['name']}: not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """A create is deleted (while unchanged), an update put back, a delete
    created again: an Undo-only form of this type."""
    applied = {u["group"] for u in result.get("items") or [] if u.get("status") == "applied"}
    for g in result.get("groups") or []:
        if g["key"] not in applied:
            continue
        t = g["target"]
        if g["handler"] == "dlp_obj_create":
            made = next((c for c in result.get("created") or [] if c.get("type") == t["object"]), None)
            if not made or made.get("id") in (None, ""):
                return None
            d = t["definition"]
            expect = ({"name": t["name"], "expression": d["engine_expression"]} if t["object"] == "engine" else
                      {"name": t["name"], "phrases": d["phrases"], "patterns": d["patterns"]})
            return {"type": TYPE, "object": t["object"], "action": "delete", "id": made["id"], "undo": True, "expect": expect}
        if g["handler"] == "dlp_obj_update":
            back = {("expression" if k == "expression" else k): v for k, v in t["undo_set"].items()}
            return {"type": TYPE, "object": t["object"], "action": "update", "id": t["id"], "fields": back, "undo": True}
        r = t["raw"]
        fields = ({"name": r["name"], "description": r.get("description", ""), "expression": r["engine_expression"]} if t["object"] == "engine" else
                  {k: r[k] for k in ("name", "description", "custom_phrase_match_type", "phrases", "patterns", "proximity")})
        return {"type": TYPE, "object": t["object"], "action": "create", "fields": fields, "undo": True}
    return None


ao.register(TYPE, family=FAMILY, product="zia", label="DLP dictionaries and engines", plan=plan, read_objects=read_objects, in_scope=in_scope,
            handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT, group="Change",
            hint=("Create, edit or delete one custom DLP dictionary or engine; an engine's expression is checked and explained in words. A "
                  "delete needs DELETE and its name typed and is refused while an engine or rule uses it. Undo puts it back. Needs DLP ticked "
                  "on the Scope page."))
