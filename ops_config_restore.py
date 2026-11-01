"""Restore, clone and template apply: operation types on the Bulk changes
engine (admin_ops.register), one per product.

  config_restore_zia   ZIA objects and settings from a backup or a template
  config_restore_zpa   ZPA objects
  config_restore_zcc   Client Connector objects and settings

The source is a configuration backup (config_backup.py) or a template; the
target is the tenant this page is signed in to. Three modes:

  add_missing       create only what the target lacks
  update_matching   create what it lacks and update what differs
  full              the same, and delete the target's own objects of the
                    chosen types that the source does not have (needs the
                    typed "DELETE <n> OBJECTS"; never from a template)

The same plan serves three cases. *Restore* (the backup is of this tenant,
target "same"): objects are matched by id, then name. *Clone* (another
tenant's backup, target "other"): objects are matched by name and every
reference is remapped by the name of what it points at; an object whose
reference the target cannot satisfy is not cloned and is listed with the
reason, and so is every object of a type that cannot be cloned (locations,
static IPs, GRE tunnels: bound to the tenant's own addresses). *Template*
(target "other"): the template's own objects are named with your prefix and
everything else is found by name. The routes check, before anything is read,
that the target is the saved profile the person has open (a clone or template
writes only to a tenant the person signed in to through its profile) and that
"same" really is the backup's tenant (tenant_fingerprint).

The plan is ordered by dependency (what a rule uses is created first;
deletes run the other way) and starts with a fresh automatic backup of the
target's affected types: nothing is ever deleted or overwritten without one.
Every write re-reads its object first: an object someone changed since the
preview (or a name someone took) stops the run before it is overwritten.
The first failure or conflict stops the run: nothing more is written, and
the Undo of what was applied is offered. ZIA's activation is the plan's last
item, shown and optional; after a stop, nothing is activated, so what was
written stays pending in ZIA until Undo (or the portal). New objects are
created disabled unless the person keeps each rule's state from the source.
Every applied item is read back.

Secrets never travel: a backup and a template hold none (config_backup),
no payload ever sends a masked value, and a VPN credential is created only
with a pre-shared key the person types on the page, which reaches the write
through an in-memory hand-over keyed by the plan hash (provide / _take),
never through the operation, the plan, the record, a log or the audit log.
"""
from __future__ import annotations

import copy
import re
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import admin_ops as ao
import config_backup as cb
import pack_ops as ops

FAMILY = "config_backups"
TYPE_FOR = {"zia": "config_restore_zia", "zpa": "config_restore_zpa", "zcc": "config_restore_zcc"}
PRODUCT_OF = {v: k for k, v in TYPE_FOR.items()}
MODES = ("add_missing", "update_matching", "full")
MODE_WORDS = {"add_missing": "add what is missing", "update_matching": "add what is missing and update what differs",
              "full": "make the target match exactly (with deletes)"}
MAX_CHANGES = 2000
MAX_PICKS = 2000
MAX_STEPS = 5000
MAX_PSK = 200
PROFILE_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{0,47}\Z")
FIRST_FAILURE = ("the first failure stops the run, so nothing more was written. What was applied is listed: Undo puts it back "
                 "(preview first)")
CONFLICT_STOP = ("someone changed it in the tenant since the preview, so it was not overwritten and nothing more was written. "
                 "Preview again")
NOT_IN_SCOPE = "Not in scope: tick on the Scope page what this restore reads (ZIA platform or DLP for ZIA, ZPA, or Client Connector)."
SECRET_TTL = 900.0
ZPA_NEW_NEEDS_TICK = ("not created: a ZPA policy rule cannot be created disabled (the SDK's add calls have no such field), so it is "
                      "created only when you tick 'keep each rule's state from the source' (it is then active at once)")
TENANT_BOUND_WORDS = ("Tenant-bound objects (static IP addresses, GRE tunnels, locations) are created only because you included "
                      "them: each static IP address was checked with the target first, and GRE tunnels and locations use only "
                      "static IP addresses the target has or this plan adds. They are never updated or deleted here; Undo "
                      "removes the ones this run created.")


class _Unresolved(Exception):
    pass


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


def _label(t: Dict[str, Any]) -> str:
    return f"{cb.PRODUCT_LABELS[t['product']]} {t['label']}"


# ---------------------------------------------------------------------------
# Dependency tiers: what an object uses comes first
# ---------------------------------------------------------------------------

def _deps(t: Dict[str, Any]) -> Set[str]:
    out = set()
    targets = list(cb.refs_of(t).values()) + list(t["after"])
    for spec in (cb.OPERAND_REFS.values() if t["conditions"] else ()):
        targets.extend(spec[1])
    for nested in t["nested_refs"].values():
        targets.extend(nested.values())
    for target in targets:
        tt = cb.BY_KEY.get(target)
        if tt is not None and tt["key"] != t["key"] and cb.writable(tt, tenant_bound=True) and tt["product"] == t["product"]:
            out.add(target)
    if t["expr"]:
        out.add(t["expr"][1])
    return out


def _tiers() -> Dict[str, int]:
    tier: Dict[str, int] = {}

    def depth(k: str, seen: Tuple[str, ...] = ()) -> int:
        if k in tier:
            return tier[k]
        if k in seen:
            raise RuntimeError(f"reference cycle in the catalogue at {k}")
        d = 1 + max((depth(x, seen + (k,)) for x in _deps(cb.BY_KEY[k])), default=-1)
        tier[k] = d
        return d
    for t in cb.TYPES:
        if cb.writable(t, tenant_bound=True):
            depth(t["key"])
    return tier


TIER = _tiers()


def ordered_types(product: str) -> List[Dict[str, Any]]:
    """The writable types of a product in dependency order (catalogue order within a tier)."""
    pos = {t["key"]: i for i, t in enumerate(cb.TYPES)}
    return sorted((t for t in cb.types_for(product) if cb.writable(t, tenant_bound=True)), key=lambda t: (TIER[t["key"]], pos[t["key"]]))


# ---------------------------------------------------------------------------
# The in-memory hand-over of typed secrets (pre-shared keys)
# ---------------------------------------------------------------------------

_HANDOVER: Dict[str, Tuple[Dict[str, Any], float]] = {}
_HANDOVER_LOCK = threading.Lock()


def provide(plan_hash: str, *, secrets: Optional[Dict[str, str]] = None, tenant_ids: Optional[Dict[str, str]] = None,
            now: Optional[float] = None) -> None:
    """Hand the apply of `plan_hash` what must not travel in the operation:
    the typed pre-shared keys (by VPN credential name) and the target's
    opaque tenant ids (for the safety backup's record). Kept in memory only,
    for SECRET_TTL seconds, and taken once by the run."""
    now = time.time() if now is None else now
    clean = {}
    for k, v in list((secrets or {}).items())[:MAX_PSK]:
        if isinstance(k, str) and isinstance(v, str) and 0 < len(v) <= 128 and len(k) <= 255:
            clean[k] = v
    with _HANDOVER_LOCK:
        for h in [h for h, (_v, exp) in _HANDOVER.items() if exp <= now]:
            del _HANDOVER[h]
        _HANDOVER[str(plan_hash)] = ({"secrets": clean, "tenant_ids": dict(tenant_ids or {})}, now + SECRET_TTL)


def _take(plan_hash: str) -> Dict[str, Any]:
    with _HANDOVER_LOCK:
        got = _HANDOVER.pop(str(plan_hash), None)
    if got is None or got[1] <= time.time():
        return {"secrets": {}, "tenant_ids": {}}
    return got[0]


# ---------------------------------------------------------------------------
# What the page sends
# ---------------------------------------------------------------------------

def _str_list(v: Any, what: str, cap: int) -> List[str]:
    if v in (None, ""):
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise _err(f"'{what}' must be a list of names.")
    if len(v) > cap:
        raise _err(f"At most {cap} entries in '{what}'.")
    return [x for x in v]


def check_spec(spec: Dict[str, Any], product: str) -> Dict[str, Any]:
    """The operation as the plan uses it (validated, canonical); refused in
    words before anything is read."""
    if str(spec.get("action") or "") == "undo":
        return _check_undo(spec, product)
    src = spec.get("source")
    if not isinstance(src, dict) or len(src) != 1 or not (set(src) <= {"backup", "template"}):
        raise _err("Pick the source: one backup or one template.")
    kind, sid = next(iter(src.items()))
    if not isinstance(sid, str) or not (cb.BACKUP_ID if kind == "backup" else cb.TEMPLATE_ID).match(sid):
        raise _err("The source is not a backup or template this app made.")
    mode = str(spec.get("mode") or "add_missing")
    if mode not in MODES:
        raise _err(f"The mode must be one of {', '.join(MODES)}.")
    target = str(spec.get("target") or "")
    if target not in ("same", "other"):
        raise _err("Say whether the target is the backup's own tenant (same) or another tenant (other).")
    if kind == "template":
        if target != "other":
            raise _err("A template is applied to a tenant as 'other': its objects are matched by name.")
        if mode == "full":
            raise _err("A template never deletes: pick 'add what is missing' or 'update what differs'.")
    pid = str(spec.get("target_profile_id") or "")
    if pid and not PROFILE_ID.match(pid):
        raise _err("The target profile id is not one this app made.")
    if target == "other" and not pid:
        raise _err("Cloning or applying a template writes to another tenant: open that tenant's saved profile (Tenant, in the bar) first.")
    tenant_bound = spec.get("include_tenant_bound") is True
    if tenant_bound and product != "zia":
        raise _err("Only ZIA has tenant-bound objects (locations, static IP addresses, GRE tunnels).")
    if tenant_bound and kind == "template":
        raise _err("A template never carries tenant-bound objects.")

    def check_type(k: Any) -> Dict[str, Any]:
        t = cb.BY_KEY.get(str(k))
        if t is None or t["product"] != product or not cb.writable(t, tenant_bound=True):
            raise _err(f"{str(k)[:60]} is not an object type this restore writes for {cb.PRODUCT_LABELS[product]}.")
        if t["tenant_bound"] and not tenant_bound:
            raise _err(f"{t['key']} is a tenant-bound object type: tick 'Include tenant-bound objects' (its own confirmation) to "
                       "create it.")
        return t
    types = _str_list(spec.get("types"), "types", 200)
    for k in types:
        check_type(k)
    picks = spec.get("objects") or []
    if not isinstance(picks, list) or len(picks) > MAX_PICKS:
        raise _err(f"'objects' must be a list of at most {MAX_PICKS} objects.")
    objects = []
    for p in picks:
        if not isinstance(p, dict) or set(p) - {"type", "name"} or not isinstance(p.get("name"), str) or len(p["name"]) > 255:
            raise _err("Every picked object is {type, name}.")
        t = check_type(p.get("type"))
        objects.append({"type": t["key"], "name": p["name"]})
    sel_raw = spec.get("select") or {}
    if not isinstance(sel_raw, dict) or set(sel_raw) - {"label", "prefix"}:
        raise _err("'select' names a rule label and / or a name prefix.")
    select = {}
    for k in ("label", "prefix"):
        v = sel_raw.get(k)
        if v in (None, ""):
            continue
        if not isinstance(v, str) or len(v) > 128 or re.search(r"[\x00-\x1f\x7f]", v):
            raise _err("The label and the prefix are at most 128 characters, with no control characters.")
        select[k] = v
    prefix = str(spec.get("prefix") or "")
    if kind != "template" and prefix:
        raise _err("A prefix is for templates only.")
    if not cb.PREFIX_RE.match(prefix):
        raise _err("The prefix may be up to 20 letters, digits, spaces and . _ -.")
    psk = sorted(set(_str_list(spec.get("psk"), "psk", MAX_PSK)))
    keys_raw = spec.get("settings_keys") or {}
    if not isinstance(keys_raw, dict) or len(keys_raw) > 20:
        raise _err("'settings_keys' must name, per settings type, the keys to restore.")
    settings_keys = {}
    for k, v in keys_raw.items():
        t = cb.BY_KEY.get(str(k))
        if t is None or t["product"] != product or not t["singleton"] or not cb.writable(t):
            raise _err(f"{str(k)[:60]} is not a settings type this restore writes for {cb.PRODUCT_LABELS[product]}.")
        names = _str_list(v, "settings_keys", 500)
        if not names or not all(re.fullmatch(r"[a-z][a-z0-9_]{0,80}", x) for x in names):
            raise _err("Settings keys are field names such as enable_office365.")
        settings_keys[t["key"]] = sorted(set(names))
    return {"type": TYPE_FOR[product], "source": {kind: sid}, "mode": mode, "target": target, "target_profile_id": pid,
            "types": sorted(set(types)), "objects": sorted(objects, key=lambda o: (o["type"], o["name"])), "prefix": prefix,
            "keep_state": spec.get("keep_state") is True, "activate": spec.get("activate") is not False, "psk": psk,
            "settings_keys": settings_keys, "licence_ack": spec.get("licence_ack") is True,
            "rollback_on_stop": spec.get("rollback_on_stop") is True, "include_tenant_bound": tenant_bound, "select": select}


def _check_undo(spec: Dict[str, Any], product: str) -> Dict[str, Any]:
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise _err("An Undo lists the steps to reverse.")
    out = []
    for s in steps:
        if not isinstance(s, dict) or s.get("op") not in ("create", "update", "delete"):
            raise _err("An Undo step is create, update or delete.")
        t = cb.BY_KEY.get(str(s.get("type")))
        if t is None or t["product"] != product or not cb.writable(t, tenant_bound=True):
            raise _err("An Undo step names an object type this restore does not write.")
        step = {"op": s["op"], "type": t["key"], "name": str(s.get("name") or "")[:255], "id": str(s.get("id") or "")[:128],
                "rule_type": str(s.get("rule_type") or "")[:60]}
        for k in ("desired", "expect"):
            if s.get(k) is not None:
                if not isinstance(s[k], dict):
                    raise _err("An Undo step's object must be an object.")
                step[k] = s[k]
        out.append(step)
    pid = str(spec.get("target_profile_id") or "")
    if pid and not PROFILE_ID.match(pid):
        raise _err("The target profile id is not one this app made.")
    return {"type": TYPE_FOR[product], "action": "undo", "steps": out, "target": "same", "target_profile_id": pid,
            "keep_state": True, "activate": spec.get("activate") is not False, "rollback_on_stop": False}


# ---------------------------------------------------------------------------
# Readers: the live tenant (SDK) or a backup document (rehearsal)
# ---------------------------------------------------------------------------

class LiveReader:
    """Reads the signed-in tenant through the SDK (GET only)."""

    def __init__(self, client: Any, scope: Dict[str, Any], cancel: Any = None):
        self.client, self.scope, self.cancel = client, scope, cancel

    def allowed(self, t: Dict[str, Any]) -> bool:
        return cb.allowed(t, self.scope)

    def read(self, t: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        ao._check_stop(self.cancel)
        return cb.read_type(self.client, t, self.cancel)

    def check(self, t: Dict[str, Any], value: str) -> Tuple[Optional[bool], str]:
        """Ask the tenant whether a new object may be added (static IPs:
        traffic_static_ip.check_static_ip, POST /staticIP/validate, read-only).
        (True, "") may be added; (False, why) may not; (None, why) unknown."""
        ao._check_stop(self.cancel)
        svc = getattr(getattr(self.client, t["product"], None), t["svc"], None)
        fn = getattr(svc, t["check"] or "", None) if svc is not None else None
        if not callable(fn):
            return None, f"the installed zscaler-sdk-python has no {t['svc']}.{t['check']}"
        try:
            ok, _resp, err = fn(value)
        except Exception as e:  # noqa: BLE001 - an unknown answer is not a yes
            return None, f"{type(e).__name__}"
        if err:
            text = str(err)[:200]
            if re.search(r"409|exist|duplicate|already", text, re.I):
                return False, "the address is already in use by an organisation (the target cannot add it: it must own it)"
            return None, text
        return (True, "") if ok else (False, "the tenant refused the address")


class DocReader:
    """Reads a backup document's objects instead of a tenant: a rehearsal
    plan never builds a client and never reaches a tenant."""

    def __init__(self, types: Dict[str, List[Dict[str, Any]]]):
        self.types = types or {}

    def allowed(self, t: Dict[str, Any]) -> bool:
        return True

    def read(self, t: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        if t["key"] not in self.types:
            return [], "not in the target backup"
        return copy.deepcopy(self.types[t["key"]]), None

    def check(self, t: Dict[str, Any], value: str) -> Tuple[Optional[bool], str]:
        return None, "a rehearsal reads no tenant, so the target cannot be asked whether it may add the address"


# ---------------------------------------------------------------------------
# Payloads and comparable forms
# ---------------------------------------------------------------------------

def _clean(v: Any) -> Any:
    """A nested value without secret-named fields or masked values (an app
    profile's platform policies carry its passwords as "(set)")."""
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items() if not cb.is_secret_key(k) and not (isinstance(x, str) and x in cb.MASKS)}
    if isinstance(v, list):
        return [_clean(x) for x in v if not (isinstance(x, str) and x in cb.MASKS)]
    return v


def payload(t: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    """What a write sends for an object: no id, no volatile, stripped or
    derived field, and never a secret-named field or a masked value (at any
    depth)."""
    out = {}
    for k, v in row.items():
        if k in ("id", "$stub") or k in t["strip"] or cb._volatile(k) or cb.is_secret_key(k) or v in cb.MASKS:
            continue
        out[k] = _clean(copy.deepcopy(v))
    return out


def raw_form(t: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    """An object's comparable form with references as sorted ids (no names):
    the conflict guard, the read-back and the Undo compare this."""
    refs = cb.refs_of(t)
    out = {}
    for k, v in (row or {}).items():
        if k in ("id", "$stub") or k in t["strip"] or cb._volatile(k) or v in cb.MASKS or cb.is_secret_key(k):
            continue
        if t["conditions"] and k == "conditions":
            out[k] = cb.condition_canon(v)
        elif k in refs:
            out[k] = sorted(i for i, _n in cb.ref_items(v)[0])
        else:
            out[k] = cb._norm_value(_clean(v), k, ())
    return out


def _subset_equal(t: Dict[str, Any], want: Dict[str, Any], row: Dict[str, Any]) -> bool:
    """Every field of `want` (that the tenant answers) is as wanted in `row`."""
    a, b = raw_form(t, want), raw_form(t, row)
    empty = (None, "", [], {})
    for k, v in a.items():
        if k not in b:
            continue
        if cb.canonical(v) != cb.canonical(b[k]) and not (v in empty and b[k] in empty):
            return False
    return True


def _show(v: Any) -> Any:
    """A value as the preview shows it (long values shortened)."""
    if isinstance(v, (dict, list)):
        s = cb.canonical(v)
        return s if len(s) <= 300 else s[:297] + "…"
    if isinstance(v, str) and len(v) > 300:
        return v[:297] + "…"
    return v


def _off(t: Dict[str, Any]) -> Tuple[str, Any]:
    return (t["state"], "DISABLED") if t["state"] == "state" else (t["state"], False)


# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------

class _Plan:
    def __init__(self, product: str, same: bool):
        self.product, self.same = product, same
        self.items: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.blockers: List[str] = []
        self.notes: List[str] = []
        self.manual_steps: List[str] = []
        self.n = 0

    def key(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}:{self.n}"

    def obj(self, t: Dict[str, Any], name: str, oid: Any = None) -> Dict[str, Any]:
        return {"type": t["key"], "policy_label": _label(t), "name": name, "id": None if oid in (None, "") else str(oid)}

    def exclude(self, t: Dict[str, Any], name: str, why: str, oid: Any = None, status: str = "excluded") -> None:
        k = self.key("x")
        self.items.append(ao._unit(k, k, "object", self.obj(t, name, oid), "object", None, None, status=status, reason=why))


def _load_source(nspec: Dict[str, Any], product: str) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any], str]:
    kind, sid = next(iter(nspec["source"].items()))
    try:
        if kind == "backup":
            doc = cb.load_backup(sid)
            meta = doc["meta"]
            when = str(meta.get("saved_at") or "")[:16].replace("T", " ")
            return doc["types"], meta, f"the backup of {meta.get('tenant_label') or 'a tenant'} ({when})"
        tpl = cb.load_template(sid)
        src = cb.template_source(tpl, nspec["prefix"])
        return src["types"], dict(tpl["meta"], template=True), f"the template '{tpl['meta']['name']}'"
    except cb.BackupError as e:
        raise _err(str(e))


def build_plan(source: Dict[str, List[Dict[str, Any]]], reader: Any, nspec: Dict[str, Any], product: str, *, what: str = "",
               say=None) -> Dict[str, Any]:
    """The restore / clone / template plan (pure: reads through `reader`
    only, never writes). Returns the prepared operation for admin_ops."""
    say = say or (lambda m: None)
    same = nspec["target"] == "same"
    p = _Plan(product, same)
    picks: Dict[str, Set[str]] = {}
    for o in nspec["objects"]:
        picks.setdefault(o["type"], set()).add(o["name"])
    include_tb = bool(nspec.get("include_tenant_bound"))
    select = nspec.get("select") or {}
    sel = [t for t in ordered_types(product) if (include_tb or not t["tenant_bound"])
           and (not nspec["types"] or t["key"] in nspec["types"]) and (not picks or t["key"] in picks)]
    in_scope = []
    for t in sel:
        if reader.allowed(t):
            in_scope.append(t)
        else:
            p.warnings.append(f"{_label(t)}: not in scope on the Scope page, so not read or restored.")
    sel = in_scope
    absent = [t for t in sel if t["key"] not in source and not (picks and t["key"] in picks)]
    if absent and not nspec["types"]:
        p.notes.append("Not in the source, so not touched: " + ", ".join(t["label"] for t in absent[:12]) + ("…" if len(absent) > 12 else "") + ".")
    elif absent:
        p.warnings.extend(f"{_label(t)}: the source holds none, so nothing of it is planned." for t in absent)
    sel = [t for t in sel if t not in absent]
    if not any(source.get(t["key"]) for t in sel):
        p.blockers.append(f"{what or 'The source'} holds nothing of the chosen {cb.PRODUCT_LABELS[product]} object types.")
    full = nspec["mode"] == "full" and not picks
    if nspec["mode"] == "full" and picks:
        p.warnings.append("Full mode deletes only when whole object types are restored; with objects picked, nothing is deleted.")
    # What the target must be read for: the chosen types, what they refer to,
    # and (with deletes) what refers to them.
    need: Dict[str, Dict[str, Any]] = {t["key"]: t for t in sel}
    for t in sel:
        targets = list(cb.refs_of(t).values()) + ([t["expr"][1]] if t["expr"] else []) + list(t["after"])
        if t["conditions"]:
            targets += [k for spec_ in cb.OPERAND_REFS.values() for k in spec_[1]] + ["zpa.idps"]
        targets += [k for nested in t["nested_refs"].values() for k in nested.values()]
        for target in targets:
            tt = cb.BY_KEY.get(target)
            if tt is not None and tt["product"] == product:
                need.setdefault(target, tt)
    if full:
        sel_keys = {t["key"] for t in sel}
        for t in cb.types_for(product):
            if set(cb.refs_of(t).values()) & sel_keys or (t["expr"] and t["expr"][1] in sel_keys):
                need.setdefault(t["key"], t)
    tgt: Dict[str, List[Dict[str, Any]]] = {}
    unread: Dict[str, str] = {}
    for k, t in need.items():
        if not reader.allowed(t):
            unread[k] = "not in scope on the Scope page"
            continue
        say(f"Reading the target's {_label(t)}…")
        rows, err = reader.read(t)
        if err and not rows:
            unread[k] = err
            if k in {x["key"] for x in sel}:
                p.warnings.append(f"{_label(t)}: the target could not be read ({str(err)[:160]}), so nothing of it is planned.")
            continue
        tgt[k] = rows
    sel = [t for t in sel if t["key"] in tgt]
    if not sel and not p.blockers:
        p.blockers.append("None of the chosen object types could be read in the target, so nothing was planned.")
    tgt_by_id = {k: {cb.rid(r): r for r in rows if cb.rid(r)} for k, rows in tgt.items()}
    tgt_by_name: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for k, rows in tgt.items():
        t = cb.BY_KEY[k]
        tgt_by_name[k] = {}
        for r in rows:
            tgt_by_name[k].setdefault(cb.name_of(t, r), r)
    src_idx = cb.index(source)
    state: Dict[Tuple[str, str], Tuple[str, Any]] = {}
    asked: Set[str] = set()   # the types a source object referred to (an unread one is worth a warning)

    def resolve(target_key: str, src_id: str, hint: str) -> Tuple[str, Any]:
        asked.add(target_key)
        tt = cb.BY_KEY.get(target_key)
        if tt is not None and tt["global_id"] and tt["global_id"](src_id):
            return ("id", src_id)
        got = state.get((target_key, src_id))
        if got is not None:
            return got
        nm = (src_idx.get(target_key) or {}).get(src_id) or hint
        if tt is None:
            if same:
                return ("id", src_id)
            what_ = target_key.split(".", 1)[-1].replace("_", " ")
            return ("unresolved", f"it names {what_}, which backups do not carry, so it cannot be matched in another tenant")
        if target_key not in tgt:
            if same:
                return ("id", src_id)
            return ("unresolved", f"{_label(tt)} could not be read in the target ({unread.get(target_key, 'not read')}), so '{nm or src_id}' "
                                  "cannot be matched by name")
        if same and src_id in tgt_by_id[target_key]:
            return ("id", src_id)
        if nm and nm in tgt_by_name[target_key]:
            return ("id", cb.rid(tgt_by_name[target_key][nm]))
        return ("unresolved", f"it uses {_label(tt)} '{nm or '#' + src_id}', which the target tenant does not have"
                              + ("" if tt["key"] in {x["key"] for x in sel} or not cb.writable(tt) else " (restore that type too)"))

    def resolve_alt(target_key: str, value: str, keyf: str, hint: str) -> Tuple[str, Any]:
        """A reference by another identifying field (a posture profile's
        UDID, a trusted network's network id): matched by name across tenants."""
        asked.add(target_key)
        tt = cb.BY_KEY[target_key]
        if target_key not in tgt:
            if same:
                return ("id", value)
            return ("unresolved", f"{_label(tt)} could not be read in the target, so '{hint or value}' cannot be matched by name")
        if same and any(str(r.get(keyf)) == value for r in tgt[target_key]):
            return ("id", value)
        srow = next((r for r in source.get(target_key) or [] if str(r.get(keyf)) == value), None)
        nm = cb.name_of(tt, srow) if srow else hint
        hit = tgt_by_name[target_key].get(nm) if nm else None
        if hit is not None and hit.get(keyf) not in (None, ""):
            return ("id", str(hit[keyf]))
        return ("unresolved", f"it uses {_label(tt)} '{nm or value}', which the target tenant does not have")

    def resolve_any(keys: Sequence[str], value: str, keyf: str, hint: str) -> Tuple[str, Any]:
        """The first of several types that resolves (an APP operand may be a
        plain, Browser Access, PRA or inspection segment)."""
        first: Optional[Tuple[str, Any]] = None
        for k in keys:
            got = resolve(k, value, hint) if keyf == "id" else resolve_alt(k, value, keyf, hint)
            if got[0] in ("id", "new"):
                return got
            first = first or got
        return first or ("unresolved", "it names an object no backup type carries")

    def resolve_scim_group(value: str, idp: str) -> Tuple[str, Any]:
        k = "zpa.scim_groups"
        asked.add(k)
        tt = cb.BY_KEY[k]
        if k not in tgt:
            return ("id", value) if same else ("unresolved", f"{_label(tt)} could not be read in the target")
        if same and value in tgt_by_id[k]:
            return ("id", value)
        srow = next((r for r in source.get(k) or [] if cb.rid(r) == value), None)
        nm = cb.name_of(tt, srow) if srow else ""
        hit = next((r for r in tgt[k] if nm and cb.name_of(tt, r) == nm and (not idp or str(r.get("idp_id") or "") == idp)), None)
        if hit is not None:
            return ("id", cb.rid(hit))
        return ("unresolved", f"it uses the SCIM group '{nm or value}', which the target's identity provider does not have")

    def remap_conditions(conds: List[Any], why: List[str], waits: List[str]) -> List[Any]:
        """Every operand of a ZPA rule's conditions pointed at the target's
        object (by name across tenants); literals kept; an operand of a kind
        no backup carries is kept on the same tenant and blocks a clone."""
        def put(o: Dict[str, Any], side: str, got: Tuple[str, Any]) -> None:
            kind, val = got
            if kind == "new":
                o[side] = f"@new:{val}"
                waits.append(val)
            elif kind == "id":
                o[side] = str(val)
            else:
                why.append(val if kind == "unresolved" else f"a condition uses an object that is not restored: {val}")
        out = []
        for b in conds:
            if not isinstance(b, dict):
                continue
            nb, ops = dict(b), []
            for o in b.get("operands") or []:
                if not isinstance(o, dict):
                    continue
                o = dict(o)
                ty = str(o.get("object_type") or o.get("objectType") or "").upper()
                spec_ = cb.OPERAND_REFS.get(ty)
                f = cb.OPERAND_IDP.get(ty)
                if f and o.get(f) not in (None, "", "0") and not (spec_ and f == spec_[0]):
                    put(o, f, resolve_any(("zpa.idps",), str(o[f]), "id", str(o.get("idp_name") or "")))
                if spec_:
                    side, keys, keyf = spec_
                    v = str(o.get(side) or "")
                    if ty == "SCIM_GROUP":
                        put(o, side, resolve_scim_group(v, str(o.get("lhs") or "")))
                    elif v:
                        put(o, side, resolve_any(keys, v, keyf, str(o.get("name") or "")))
                elif ty not in cb.OPERAND_LITERAL and not same:
                    why.append(f"a condition names {ty.lower().replace('_', ' ')} objects, which backups do not carry, so it cannot be "
                               "matched in another tenant")
                ops.append(o)
            nb["operands"] = ops
            out.append(nb)
        return out

    def typed(v: Any) -> Any:
        """An id as the product's API takes it: ZIA and Client Connector
        ids are numbers, ZPA ids stay strings; a CUSTOM_ category id is text."""
        return int(v) if product != "zpa" and isinstance(v, str) and v.isdigit() else v

    def remap(t: Dict[str, Any], body: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], List[str]]:
        out, why, waits = dict(body), [], []
        for f, target in cb.refs_of(t).items():
            if f not in out:
                continue
            ids, shape = cb.ref_items(out[f])
            new = []
            for i, hint in ids:
                kind, val = resolve(target, i, hint)
                if kind == "unresolved" or kind == "excluded":
                    why.append(val if kind == "unresolved" else f"it uses '{hint or (src_idx.get(target) or {}).get(i) or i}', which is not restored: {val}")
                elif kind == "new":
                    new.append(f"@new:{val}")
                    waits.append(val)
                else:
                    new.append(typed(val))
            out[f] = cb._shape(new, shape) if shape != "dict" or new else None
        if t["expr"] and isinstance(out.get(t["expr"][0]), str):
            def sub(m: "re.Match[str]") -> str:
                kind, val = resolve(t["expr"][1], m.group(1), "")
                if kind == "id":
                    return f"D{val}."
                if kind == "new":
                    waits.append(val)
                    return f"D@new:{val}."
                why.append(val if kind == "unresolved" else f"it uses a dictionary that is not restored: {val}")
                return m.group(0)
            out[t["expr"][0]] = cb.EXPR_ID.sub(sub, out[t["expr"][0]])
        if t["conditions"] and isinstance(out.get("conditions"), list):
            out["conditions"] = remap_conditions(out["conditions"], why, waits)
        for f, refmap in t["nested_refs"].items():
            if not isinstance(out.get(f), list):
                continue
            items = []
            for a in out[f]:
                if isinstance(a, dict):
                    a = dict(a)
                    for rf, target in refmap.items():
                        if a.get(rf) in (None, "", 0, "0"):
                            continue
                        kind, val = resolve(target, str(a[rf]), str(a.get(rf[:-3] + "_name") or "") if rf.endswith("_id") else "")
                        if kind == "id":
                            a[rf] = typed(val)
                        elif kind == "new":
                            a[rf] = f"@new:{val}"
                            waits.append(val)
                        else:
                            why.append(val)
                items.append(a)
            out[f] = items
        return out, why, waits

    def selected(t: Dict[str, Any], r: Dict[str, Any], idx: Dict[str, Dict[str, str]]) -> bool:
        """The job's selection (a sync): a name prefix and / or a rule label."""
        pre, lab = select.get("prefix") or "", select.get("label") or ""
        if pre and not cb.name_of(t, r).startswith(pre):
            return False
        if lab:
            if "labels" not in cb.refs_of(t):
                return False
            return lab.casefold() in {n.casefold() for n in cb._ref_names(r.get("labels"), "zia.rule_labels", idx)}
        return True

    target_ips = {str(r.get("ip_address")) for r in tgt.get("zia.static_ips") or [] if r.get("ip_address")}
    planned_ips: Dict[str, str] = {}
    tb_report: List[str] = []

    def tenant_bound_check(t: Dict[str, Any], r: Dict[str, Any], body: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
        """Before a tenant-bound object is created: a static IP the target may
        add (asked of the tenant), a GRE tunnel from a static IP the target
        has (or this plan adds), a location whose addresses are such static
        IPs. (why not, the creates it waits for)."""
        waits_: List[str] = []

        def own(ip: str) -> Optional[str]:
            if ip in target_ips:
                return None
            if ip in planned_ips:
                waits_.append(planned_ips[ip])
                return None
            return (f"{ip} is not a static IP address of the target: the target must own it (include static IP addresses, or add "
                    "it in the portal first)")
        if t["key"] == "zia.static_ips":
            ok, why_ = reader.check(t, str(r.get("ip_address") or ""))
            if ok is not True:
                return f"the target could not confirm it may add this address ({why_})", []
            return None, []
        if t["key"] == "zia.gre_tunnels":
            return own(str(r.get("source_ip") or "")), waits_
        if t["key"] == "zia.locations":
            for ip in body.get("ip_addresses") or []:
                ip = str(ip)
                if "/" in ip or "-" in ip:
                    return f"its address {ip} is a range: a location's own addresses are single static IP addresses", []
                why_ = own(ip)
                if why_:
                    return why_, []
        return None, waits_

    matched: Dict[str, Set[str]] = {}
    changes = 0
    for t in sel:
        key = t["key"]
        matched[key] = set()
        rows = [r for r in source.get(key) or [] if not r.get("$stub")]
        if select.get("label") and "labels" not in cb.refs_of(t):
            p.notes.append(f"{_label(t)}: carries no rule labels, so a label selection leaves it out.")
        if select:
            rows = [r for r in rows if selected(t, r, src_idx)]
        if picks:
            rows = [r for r in rows if cb.name_of(t, r) in picks[key]]
            missing = picks[key] - {cb.name_of(t, r) for r in rows}
            for n in sorted(missing):
                p.exclude(t, n, "the source has no object with this name")
        for r in rows:
            name = cb.name_of(t, r)
            sid = cb.rid(r)
            if t["keep"] and not t["keep"](r):
                continue   # predefined by Zscaler: every tenant has it
            if t["singleton"]:
                counterpart = (tgt[key] or [None])[0]
            elif same and sid and sid in tgt_by_id[key]:
                counterpart = tgt_by_id[key][sid]
            else:
                counterpart = tgt_by_name[key].get(name)
            if counterpart is not None:
                matched[key].add(cb.rid(counterpart) or "(settings)")
            why_not = ((t["exclude_if"](r) if t["exclude_if"] else None)
                       or (t["clone_why"] if not same and t["clone_why"] and not (t["tenant_bound"] and include_tb) else None)
                       or (t["clone_exclude_if"](r) if not same and t["clone_exclude_if"] else None)
                       or cb.zpa_rule_problem(t, r))
            if why_not:
                p.exclude(t, name, f"not {'cloned' if not same else 'restored'}: {why_not}")
                state[(key, sid)] = ("excluded", why_not) if counterpart is None else ("id", cb.rid(counterpart))
                continue
            body, why, waits = remap(t, payload(t, r))
            only = nspec.get("settings_keys", {}).get(key) if t["singleton"] else None
            if only:
                body = {k: v for k, v in body.items() if k in only}
                missing_keys = [k for k in only if k not in body]
                if missing_keys:
                    p.warnings.append(f"{_label(t)}: the source has no {', '.join(missing_keys[:5])}; left as it is in the target.")
            if why:
                p.exclude(t, name, "not " + ("cloned" if not same else "restored") + ": " + "; ".join(sorted(set(why))[:3]))
                state[(key, sid)] = ("excluded", "; ".join(sorted(set(why))[:2])) if counterpart is None else ("id", cb.rid(counterpart))
                continue
            if counterpart is None:
                if not (t["add"] or t["add_via_upd"]):
                    p.exclude(t, name, f"the target has no such object and it is not created here: {t['why'] or 'the SDK cannot create it'}")
                    state[(key, sid)] = ("excluded", "it is not created here")
                    continue
                if t["zpa_policy"] and not nspec["keep_state"]:
                    p.exclude(t, name, ZPA_NEW_NEEDS_TICK)
                    state[(key, sid)] = ("excluded", "ZPA rules are created only with the tick")
                    continue
                if t["tenant_bound"]:
                    tb_why, tb_waits = tenant_bound_check(t, r, body)
                    if tb_why:
                        p.exclude(t, name, f"not created: {tb_why}")
                        state[(key, sid)] = ("excluded", tb_why)
                        continue
                    waits = list(waits) + tb_waits
                if t["secret_prompt"] and name not in nspec["psk"]:
                    p.exclude(t, name, "needs its pre-shared key, which no backup holds: type it on the page, or leave it out "
                                       "(the credential is then not created)")
                    state[(key, sid)] = ("excluded", "its pre-shared key was not given")
                    continue
                if t["state"] and not nspec["keep_state"]:
                    f, v = _off(t)
                    body[f] = v
                gkey = p.key("create")
                state[(key, sid)] = ("new", gkey)
                after = "created" + (" (disabled)" if t["state"] and body.get(t["state"]) in ("DISABLED", False) else "")
                p.items.append(ao._unit(gkey, gkey, "object", p.obj(t, name), "object", "does not exist", after,
                                        reason=_why_create(t, same, nspec), depends_on=sorted(set(waits))))
                p.groups.append({"key": gkey, "handler": "cfg_create", "target": {"type": key, "name": name, "src_id": sid,
                                                                                   "desired": body, "rule_type": str(r.get("type") or "") if t["per_type"] else "",
                                                                                   "clamp_order": not same}})
                if key == "zia.static_ips":
                    planned_ips[name] = gkey
                if t["tenant_bound"]:
                    tb_report.append(_tenant_bound_step(t, name, body))
                changes += 1
                continue
            tid = cb.rid(counterpart)
            state[(key, sid)] = ("id", tid)
            if t["state"] and not nspec["keep_state"] and t["state"] in counterpart:
                body[t["state"]] = counterpart.get(t["state"])
            if t["upd"] is None:
                p.items.append(ao._unit(p.key("n"), p.key("n"), "object", p.obj(t, name, tid), "object", "exists", "exists", status="noop",
                                        reason=f"already in the target; {t['why'] or 'it is never updated here'}"))
                continue
            idx = cb.index(tgt)
            have = {k: v for k, v in counterpart.items() if k in only} if only else counterpart
            fd = cb.field_diff(cb.normal(t, have, idx), cb.normal(t, dict(body, id=tid), idx))
            if t["singleton"]:
                fd = [d for d in fd if d["path"].split(".", 1)[0] in body]   # a key-level merge: keys the source lacks stay as they are
            if t["keep_nested"]:
                kept = [d for d in fd if d["path"].split(".", 1)[0] in t["keep_nested"]]
                fd = [d for d in fd if d["path"].split(".", 1)[0] not in t["keep_nested"]]
                if kept:
                    p.warnings.append(f"{_label(t)} '{name}': its applications differ from the source; an update sends the target's own "
                                      "applications back as they are (change them in the ZPA Admin Portal).")
            if not fd:
                p.items.append(ao._unit(p.key("n"), p.key("n"), "object", p.obj(t, name, tid), "object", "as in the source", "as in the source",
                                        status="noop", reason="already the same (ignoring ids, change times and counters)"))
                continue
            if nspec["mode"] == "add_missing":
                p.items.append(ao._unit(p.key("n"), p.key("n"), "object", p.obj(t, name, tid), "object", "differs", "left as it is",
                                        status="excluded", reason=f"differs in {len(fd)} field(s), but this mode only adds what is missing"))
                continue
            gkey = p.key("update")
            for d in fd[:200]:
                p.items.append(ao._unit(f"{gkey}:{d['path']}", gkey, "field", p.obj(t, name, tid), d["path"], _show(d["old"]), _show(d["new"]),
                                        depends_on=sorted(set(waits))))
            p.groups.append({"key": gkey, "handler": "cfg_update", "target": {"type": key, "name": name, "id": tid, "desired": body,
                                                                               "before_hash": cb.digest(raw_form(t, counterpart)),
                                                                               "rule_type": str(counterpart.get("type") or "") if t["per_type"] else ""}})
            changes += 1
    _licence_check(p, source, reader, nspec, product, same)
    manual = sorted({t["manual"] for t in cb.types_for(product) if t["manual"] and (source.get(t["key"]) or [])
                     and (not same or cb.writable(t)) and not (t["tenant_bound"] and include_tb)})
    if manual and not same:
        p.manual_steps.extend(manual)
    p.manual_steps.extend(tb_report)
    # Deletes: the target's own objects the source does not have (full mode).
    if full:
        idx = cb.index(tgt)
        cands: List[Tuple[str, str]] = []
        for t in sel:
            if t["singleton"]:
                continue
            for r in tgt.get(t["key"]) or []:
                if (t["keep"] and not t["keep"](r)) or cb.rid(r) in matched.get(t["key"], set()):
                    continue
                if t["exclude_if"] and t["exclude_if"](r):
                    continue   # managed as another type (a special segment) or never written (a sub-location)
                if select and not selected(t, r, idx):
                    continue   # outside the selection (a sync's label or prefix)
                if t["no_delete"] or not t["rm"]:
                    p.exclude(t, cb.name_of(t, r), f"not deleted: {t['no_delete'] or 'it is never deleted here'}", cb.rid(r))
                    continue
                cands.append((t["key"], cb.rid(r)))
        users = _users(tgt)
        blocked: Dict[Tuple[str, str], str] = {}
        doomed = set(cands)
        changed = True
        while changed:
            changed = False
            for c in cands:
                if c in blocked:
                    continue
                why = []
                for u in users.get(c, []):
                    if u not in doomed or u in blocked:
                        ut = cb.BY_KEY[u[0]]
                        why.append(f"{_label(ut)} '{cb.name_of(ut, tgt_by_id[u[0]][u[1]])}'")
                if why:
                    blocked[c] = "kept: still used by " + ", ".join(why[:4]) + (" and more" if len(why) > 4 else "")
                    changed = True
        for t in reversed(sel):
            for k, i in [c for c in cands if c[0] == t["key"]]:
                r = tgt_by_id[k][i]
                name = cb.name_of(t, r)
                if (k, i) in blocked:
                    p.exclude(t, name, blocked[(k, i)], i)
                    continue
                gkey = p.key("delete")
                p.items.append(ao._unit(gkey, gkey, "object", p.obj(t, name, i), "object", "exists", "deleted",
                                        reason="the source does not have it (full mode)"))
                p.groups.append({"key": gkey, "handler": "cfg_delete", "target": {"type": k, "name": name, "id": i,
                                                                                   "before_hash": cb.digest(raw_form(t, r)),
                                                                                   "rule_type": str(r.get("type") or "") if t["per_type"] else ""}})
                changes += 1
        del idx
    for k, err in sorted(unread.items()):
        if k not in {t["key"] for t in sel} and (k in asked or not cb.BY_KEY[k]["product"] == "zpa"):
            p.warnings.append(f"{_label(cb.BY_KEY[k])} could not be read in the target ({str(err)[:120]}): references to it are "
                              + ("kept as they are" if same else "not matched, so what uses them is not cloned") + ".")
    if changes > MAX_CHANGES:
        p.blockers.append(f"This plan has {changes} changes; one operation takes at most {MAX_CHANGES}. Pick fewer object types or objects.")
    return _finish_plan(p, nspec, changes)


def subscription_key(row: Dict[str, Any]) -> str:
    for f in ("sku", "name", "feature", "subscription", "product", "id"):
        if row.get(f) not in (None, ""):
            return str(row[f])[:120]
    return ""


def _active(row: Dict[str, Any]) -> bool:
    st = row.get("status", row.get("state"))
    return st in (None, "", True) or str(st).strip().upper() in ("ACTIVE", "ENABLED", "TRUE", "SUBSCRIBED", "1")


def licence_gaps(source_rows: List[Dict[str, Any]], target_rows: List[Dict[str, Any]]) -> List[str]:
    """Subscriptions the source has (active) that the target lacks or has
    inactive: what the cloned configuration may rely on without a licence."""
    have = {subscription_key(r) for r in target_rows if _active(r)}
    return sorted({subscription_key(r) for r in source_rows if _active(r) and subscription_key(r) and subscription_key(r) not in have})


def _licence_check(p: "_Plan", source: Dict[str, List[Dict[str, Any]]], reader: Any, nspec: Dict[str, Any], product: str, same: bool) -> None:
    """Before any clone: the source's subscriptions against the target's.
    A gap blocks the plan until the person acknowledges it (licence_ack)."""
    if same:
        return
    if product != "zia":
        p.notes.append(f"Licences: zscaler-sdk-python has no {cb.PRODUCT_LABELS[product]} subscription read, so they were not compared.")
        return
    t = cb.BY_KEY["zia.subscriptions"]
    src = source.get(t["key"])
    if not src:
        p.warnings.append("Licences: the source holds no subscription list (a template, or a backup without ZIA platform in scope), "
                          "so the target's licences were not compared with it.")
        return
    if not reader.allowed(t):
        p.warnings.append("Licences: ZIA platform is not in scope, so the target's subscriptions were not read and not compared.")
        return
    rows, err = reader.read(t)
    if err and not rows:
        p.blockers.append(f"Licences: the target's subscriptions could not be read ({str(err)[:120]}), so the clone was not compared with them.")
        return
    gaps = licence_gaps(src, rows)
    if not gaps:
        p.notes.append("Licences: the target has every subscription the source has.")
        return
    words = (f"Licences: the target lacks {len(gaps)} subscription(s) the source has ({', '.join(gaps[:8])}"
             f"{', …' if len(gaps) > 8 else ''}); objects that rely on them may be refused or do nothing there.")
    if nspec.get("licence_ack"):
        p.warnings.append(words + " You acknowledged this.")
    else:
        p.blockers.append(words + " Tick 'I checked the licences' to plan anyway.")


def _users(tgt: Dict[str, List[Dict[str, Any]]]) -> Dict[Tuple[str, str], List[Tuple[str, str]]]:
    """Who uses what in the target: (type, id) → the objects that refer to it."""
    users: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
    for k, rows in tgt.items():
        t = cb.BY_KEY[k]
        for r in rows:
            me = (k, cb.rid(r))
            for f, target in cb.refs_of(t).items():
                for i, _n in cb.ref_items(r.get(f))[0]:
                    users.setdefault((target, i), []).append(me)
            if t["expr"] and isinstance(r.get(t["expr"][0]), str):
                for i in cb.EXPR_ID.findall(r[t["expr"][0]]):
                    users.setdefault((t["expr"][1], i), []).append(me)
    return users


def _tenant_bound_step(t: Dict[str, Any], name: str, body: Dict[str, Any]) -> str:
    """The manual step after a tenant-bound object is created on the target."""
    if t["key"] == "zia.static_ips":
        return (f"static IP {name}: check its city and coordinates in the ZIA Admin Portal (they are worked out from the address "
                "unless the source overrode them)")
    if t["key"] == "zia.gre_tunnels":
        return (f"GRE tunnel from {name}: ZIA picked the closest data-centre VIPs and the internal addresses; read them from the "
                "target and configure the tunnel on the site's router")
    return (f"location {name}: add its sub-locations, check its bandwidth and authentication settings, and point the site's "
            "tunnels or VPN at the target tenant")


def _why_create(t: Dict[str, Any], same: bool, nspec: Dict[str, Any]) -> str:
    bits = ["the target does not have it"]
    if t["state"] and not nspec["keep_state"]:
        bits.append("created disabled (tick 'keep each rule's state' to keep the source's)")
    if t["secret_prompt"]:
        bits.append("with the pre-shared key you typed (never stored)")
    return "; ".join(bits)


def _finish_plan(p: _Plan, nspec: Dict[str, Any], changes: int) -> Dict[str, Any]:
    """Add the safety backup first and the ZIA activation last, the typed
    phrase for deletes, and the words around it."""
    product = p.product
    deletes = sum(1 for g in p.groups if g["handler"] == "cfg_delete")
    bound = sum(1 for g in p.groups if g["handler"] == "cfg_create" and nspec.get("action") != "undo"
                and (cb.BY_KEY.get(str(g["target"].get("type"))) or {}).get("tenant_bound"))
    if changes:
        bkey = "backup:0"
        types = sorted({g["target"]["type"] for g in p.groups})
        p.items.insert(0, ao._unit(bkey, bkey, "backup", {"type": "backup", "policy_label": "Safety backup", "name": "the target tenant", "id": None},
                                   "backup", "none", "saved before the first write",
                                   reason="a fresh backup of the affected object types, taken right before anything is written"))
        p.groups.insert(0, {"key": bkey, "handler": "cfg_backup", "target": {"types": types, "profile_id": nspec.get("target_profile_id") or ""}})
        if product == "zia":
            akey = "activate:0"
            on = nspec.get("activate", True)
            p.items.append(ao._unit(akey, akey, "activate", {"type": "activation", "policy_label": "ZIA", "name": "Activation", "id": None},
                                    "activation", "pending", "activated" if on else "left pending", status="change" if on else "excluded",
                                    reason="one activation after the last write, only if every write before it succeeded" if on else
                                    "you unticked it: the changes stay pending in ZIA until someone activates them in the portal"))
            if on:
                p.groups.append({"key": akey, "handler": "cfg_activate", "target": {}})
    p.notes += [
        "Order: what an object uses is created first; deletes run the other way round.",
        "Each object is read again right before its write: if someone changed it since this preview, nothing more is written.",
        "The first failure stops the run: nothing more is written, nothing is activated, and Undo is offered for what was applied.",
        "Secrets never travel: no backup or template holds one, and none is copied from one tenant to another.",
    ]
    if product == "zia" and changes and nspec.get("activate", True):
        p.notes.append("ZIA keeps every change pending until it is activated: activation is the last item of this plan.")
    if p.manual_steps:
        p.warnings.append("Manual steps after this clone (the app never makes these): " + "; ".join(p.manual_steps) + ".")
    prepared = {"product": product, "items": p.items, "groups": p.groups, "warnings": p.warnings, "blockers": p.blockers, "notes": p.notes,
                "activation_step": product == "zia", "manual_steps": list(p.manual_steps)}
    phrases = []
    if deletes:
        phrases.append(f"DELETE {deletes} OBJECT{'S' if deletes != 1 else ''}")
        p.warnings.insert(0, f"This plan deletes {deletes} object{'s' if deletes != 1 else ''} from the target. A fresh backup is saved first; "
                             f"type DELETE {deletes} OBJECT{'S' if deletes != 1 else ''} to confirm.")
    if bound:
        # Its own confirmation, whatever else the plan does: the person types that tenant-bound objects are created.
        phrases.append(f"CREATE {bound} TENANT-BOUND OBJECT{'S' if bound != 1 else ''}")
        p.warnings.insert(0, f"This plan creates {bound} tenant-bound object{'s' if bound != 1 else ''} (static IP addresses, GRE tunnels, "
                             "locations) on the target. " + TENANT_BOUND_WORDS)
        prepared["tenant_bound"] = bound
    if phrases:
        prepared["confirm_always"] = " AND ".join(phrases)
    return prepared


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    product = PRODUCT_OF[str(spec.get("type"))]
    nspec = check_spec(spec, product)
    if nspec.get("action") == "undo":
        prepared = plan_undo(LiveReader(client, scope, cancel), nspec, product, say)
        prepared.update(type=nspec["type"], spec=nspec, title=f"Undo a {cb.PRODUCT_LABELS[product]} restore")
        return prepared
    source, meta, what = _load_source(nspec, product)
    prepared = build_plan(source, LiveReader(client, scope, cancel), nspec, product, what=what, say=say)
    prepared.update(type=nspec["type"], spec=nspec, title=_title(nspec, product, what))
    return prepared


def _title(nspec: Dict[str, Any], product: str, what: str) -> str:
    verb = "Apply" if "template" in nspec["source"] else ("Restore" if nspec["target"] == "same" else "Clone")
    pre = f" with the prefix '{nspec['prefix']}'" if nspec.get("prefix") else ""
    return f"{verb} {cb.PRODUCT_LABELS[product]} from {what}{pre}: {MODE_WORDS[nspec['mode']]}"


def rehearse(source: Dict[str, List[Dict[str, Any]]], target_types: Dict[str, List[Dict[str, Any]]], spec: Dict[str, Any], *,
             tenant_label: str = "", what: str = "") -> Dict[str, Any]:
    """A plan made against a backup document instead of a tenant: no client
    is built and nothing can be applied from it (rehearsal, plan only)."""
    product = PRODUCT_OF.get(str(spec.get("type")))
    if product is None:
        raise _err("Pick ZIA, ZPA or Client Connector.")
    nspec = check_spec(dict(spec, target_profile_id=spec.get("target_profile_id") or ("rehearsal" if spec.get("target") == "other" else "")),
                       product)
    prepared = build_plan(source, DocReader(target_types), nspec, product, what=what)
    prepared.update(type=nspec["type"], spec=nspec, title="Rehearsal: " + _title(nspec, product, what or "the source"))
    out = ao._finish(prepared, tenant_label=tenant_label or "rehearsal")
    out["rehearsal"] = True
    out["notes"].insert(0, "Rehearsal: this plan was made against a saved copy, not a tenant. Nothing was read from a tenant and "
                           "nothing can be applied from it.")
    return out


# ---------------------------------------------------------------------------
# Undo: the exact reverse of what was applied
# ---------------------------------------------------------------------------

def plan_undo(reader: Any, nspec: Dict[str, Any], product: str, say=None) -> Dict[str, Any]:
    say = say or (lambda m: None)
    p = _Plan(product, True)
    cache: Dict[str, List[Dict[str, Any]]] = {}

    def rows_of(t: Dict[str, Any]) -> List[Dict[str, Any]]:
        if t["key"] not in cache:
            rows, err = reader.read(t)
            if err and not rows:
                raise _err(f"{_label(t)} could not be read ({str(err)[:160]}); the Undo was not planned.")
            cache[t["key"]] = rows
        return cache[t["key"]]
    recreated: Dict[str, str] = {}
    changes = 0
    for s in nspec["steps"]:
        t = cb.BY_KEY[s["type"]]
        rows = rows_of(t)
        by_id = {cb.rid(r): r for r in rows}
        name = s["name"]
        if s["op"] == "delete":
            cur = by_id.get(s["id"])
            if not t["rm"]:
                # (a VPN credential: the SDK has no delete, so the Undo says so instead of failing halfway)
                p.exclude(t, name, f"not deleted: {t['no_delete'] or 'the SDK cannot delete it'}; remove it in the portal if it is not "
                                   "wanted", s["id"])
                continue
            if cur is None:
                p.exclude(t, name, "already gone, so there is nothing to delete", s["id"], status="noop")
                continue
            if s.get("expect") and not _subset_equal(t, s["expect"], cur):
                p.exclude(t, name, "changed in the tenant since the restore, so it is left as it is", s["id"])
                continue
            gkey = p.key("delete")
            p.items.append(ao._unit(gkey, gkey, "object", p.obj(t, name, s["id"]), "object", "exists", "deleted", reason="the restore created it"))
            p.groups.append({"key": gkey, "handler": "cfg_delete", "target": {"type": t["key"], "name": name, "id": s["id"],
                                                                               "before_hash": cb.digest(raw_form(t, cur)), "rule_type": s["rule_type"]}})
        elif s["op"] == "update":
            cur = by_id.get(s["id"]) if not t["singleton"] else (rows or [None])[0]
            if cur is None:
                p.exclude(t, name, "no longer in the tenant, so it cannot be put back", s["id"])
                continue
            if s.get("expect") and not _subset_equal(t, s["expect"], cur):
                p.exclude(t, name, "changed in the tenant since the restore, so it is left as it is", s["id"])
                continue
            want = s.get("desired") or {}
            fd = cb.field_diff(raw_form(t, cur), raw_form(t, want))
            if not fd:
                p.exclude(t, name, "already as it was before the restore", s["id"], status="noop")
                continue
            gkey = p.key("update")
            for d in fd[:200]:
                p.items.append(ao._unit(f"{gkey}:{d['path']}", gkey, "field", p.obj(t, name, s["id"]), d["path"], _show(d["old"]), _show(d["new"]),
                                        reason="put back as it was before the restore"))
            p.groups.append({"key": gkey, "handler": "cfg_update", "target": {"type": t["key"], "name": name, "id": cb.rid(cur), "desired": want,
                                                                               "replace": True, "before_hash": cb.digest(raw_form(t, cur)),
                                                                               "rule_type": s["rule_type"]}})
        else:
            if any(cb.name_of(t, r) == name for r in rows):
                p.exclude(t, name, "an object with this name is in the tenant again, so it is not recreated")
                continue
            if t["secret_prompt"]:
                p.exclude(t, name, "needs its pre-shared key, which was never stored: recreate it in the portal")
                continue
            want = copy.deepcopy(s.get("desired") or {})
            waits = []
            for f, target in cb.refs_of(t).items():
                if f in want:
                    ids, shape = cb.ref_items(want[f])
                    new = []
                    for i, _n in ids:
                        g = recreated.get(f"{target}:{i}")
                        if g:
                            waits.append(g)
                        new.append(f"@new:{g}" if g else i)
                    want[f] = cb._shape(new, shape)
            gkey = p.key("create")
            recreated[f"{t['key']}:{s['id']}"] = gkey
            p.items.append(ao._unit(gkey, gkey, "object", p.obj(t, name), "object", "does not exist", "recreated as it was",
                                    reason="the restore deleted it", depends_on=sorted(set(waits))))
            p.groups.append({"key": gkey, "handler": "cfg_create", "target": {"type": t["key"], "name": name, "src_id": s["id"], "desired": want,
                                                                               "rule_type": s["rule_type"], "clamp_order": False}})
        changes += 1
    return _finish_plan(p, nspec, changes)


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The Undo of a restore: what it created is deleted, what it updated
    is put back as it was read right before the write, what it deleted is
    recreated as it was (with a new id). Previewed and guarded like any
    other operation: an object someone changed since is left alone."""
    spec = result.get("spec") or {}
    steps = []
    applied_groups = []
    for g in result.get("groups") or []:
        units = [u for u in result.get("items") or [] if u.get("group") == g["key"]]
        if units and all(u.get("status") == "applied" for u in units) and g["handler"] in ("cfg_create", "cfg_update", "cfg_delete"):
            applied_groups.append(g)
    for g in reversed(applied_groups):
        t = g["target"]
        if g["handler"] == "cfg_create" and t.get("new_id"):
            steps.append({"op": "delete", "type": t["type"], "id": t["new_id"], "name": t["name"], "expect": t.get("sent") or {},
                          "rule_type": t.get("rule_type") or ""})
        elif g["handler"] == "cfg_update" and t.get("undo_before") is not None:
            steps.append({"op": "update", "type": t["type"], "id": t["id"], "name": t["name"], "desired": t["undo_before"],
                          "expect": t.get("sent") or {}, "rule_type": t.get("rule_type") or ""})
        elif g["handler"] == "cfg_delete" and t.get("undo_before") is not None:
            steps.append({"op": "create", "type": t["type"], "id": t["id"], "name": t["name"], "desired": t["undo_before"],
                          "rule_type": t.get("rule_type") or ""})
    if not steps:
        return None
    return {"type": result.get("type"), "action": "undo", "steps": steps, "target_profile_id": spec.get("target_profile_id") or "",
            "activate": spec.get("activate") is not False}


# ---------------------------------------------------------------------------
# Handlers (the engine calls one per group, in order); writes go through pack_ops
# ---------------------------------------------------------------------------

def _ctx(run: Any) -> Dict[str, Any]:
    ctx = getattr(run, "cfg", None)
    if ctx is None:
        hand = _take(run.p.get("plan_hash") or "")
        ctx = {"ids": {}, "secrets": hand.get("secrets") or {}, "tenant_ids": hand.get("tenant_ids") or {}}
        run.cfg = ctx
    return ctx


def _resolve(v: Any, ids: Dict[str, str]) -> Any:
    if isinstance(v, str) and "@new:" in v:
        def one(m: "re.Match[str]") -> str:
            got = ids.get(m.group(1))
            if got is None:
                raise _Unresolved(f"it uses an object whose creation did not succeed ({m.group(1)})")
            return str(got)
        if v.startswith("@new:"):
            got = ids.get(v[5:])
            if got is None:
                raise _Unresolved(f"it uses an object whose creation did not succeed ({v[5:]})")
            return got
        return re.sub(r"@new:([a-z]+:\d+)", one, v)
    if isinstance(v, dict):
        return {k: _resolve(x, ids) for k, x in v.items()}
    if isinstance(v, list):
        return [_resolve(x, ids) for x in v]
    return v


def _root(run: Any, t: Dict[str, Any]) -> Any:
    return getattr(run.client, t["product"], None)


def _stop(run: Any, units: List[Dict[str, Any]], status: str, why: str, **extra: Any) -> None:
    run.mark(units, status, why, **extra)
    if status == "failed":
        run.counts["failed"] += 1
    run.halt = run.halt or (CONFLICT_STOP if status == "conflict" else FIRST_FAILURE)


def _after_write(run: Any, units: List[Dict[str, Any]], out: Any, verb: str) -> bool:
    ok = run.outcome(units, out, verb)
    if not ok and not run.halt:
        run.halt = FIRST_FAILURE
    return ok


def _h_backup(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    import tenant_profiles
    ctx = _ctx(run)
    keys = [k for k in g["target"]["types"] if k in cb.BY_KEY]
    run.log(f"Saving a safety backup of the target ({len(keys)} object types) before anything is written…")
    types: Dict[str, List[Dict[str, Any]]] = {}
    unread = {}
    for k in keys:
        rows, err = cb.read_type(run.client, cb.BY_KEY[k])
        if err and not rows:
            unread[k] = err
            continue
        types[k] = rows
    if unread:
        _stop(run, units, "failed", "", error="the safety backup could not read " + ", ".join(_label(cb.BY_KEY[k]) for k in sorted(unread))
              + ", so nothing was written")
        return
    pid = g["target"].get("profile_id") or ""
    if pid and not tenant_profiles.get(pid):
        pid = ""
    meta = {"tenant_label": run.p.get("tenant_label") or "", "saved_at": cb._now(), "products": [run.p["product"]], "kind": "pre-restore",
            "profile_id": pid, "note": f"before {str(run.p.get('title') or '')[:150]}"}
    meta.update({k: v for k, v in (ctx.get("tenant_ids") or {}).items() if k in ("tenant_key", "tenant_fp")})
    try:
        entry = cb.save_backup(cb.build_doc(types, meta))
    except Exception as e:  # noqa: BLE001 - no safety copy, no write
        _stop(run, units, "failed", "", error=f"the safety backup could not be saved ({type(e).__name__}), so nothing was written")
        return
    run.mark(units, "applied", f"saved as {entry['id']}", value=entry["id"])
    g["target"]["backup_id"] = entry["id"]
    run.log(f"Safety backup saved: {entry['id']} ({entry.get('objects', 0)} objects).")


def _rows_named(run: Any, t: Dict[str, Any], name: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    rows, err = cb.read_type(run.client, t)
    if err and not rows:
        return None, err
    return rows, None


def _h_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    ctx = _ctx(run)
    tg = g["target"]
    t = cb.BY_KEY[tg["type"]]
    try:
        body = _resolve(tg["desired"], ctx["ids"])
    except _Unresolved as e:
        _stop(run, units, "skipped", f"not attempted: {e}")
        return
    rows, err = _rows_named(run, t, tg["name"])
    if rows is None:
        why = ao._read_halt(err)
        _stop(run, units, "skipped" if why else "failed", f"not attempted: {why}" if why else "",
              **({} if why else {"error": f"could not read the target again before the create: {str(err)[:200]}"}))
        return
    if any(cb.name_of(t, r) == tg["name"] for r in rows):
        _stop(run, units, "conflict", f"an object named '{tg['name']}' is in the target now (made since the preview); {CONFLICT_STOP}")
        return
    of = t["order_field"]
    if tg.get("clamp_order") and of in body:
        try:
            count = sum(1 for r in rows if int(r.get(of) or 0) > 0)
            clamped = max(1, min(int(body[of]), count + 1))
            body[of] = str(clamped) if isinstance(body[of], str) else clamped
        except (TypeError, ValueError):
            body.pop(of, None)
    sent = {k: v for k, v in copy.deepcopy(body).items() if k not in t["keep_nested"]}
    if t["app_kind"]:
        tg["sent_apps"] = sorted({str(a.get("domain") or "") for a in cb.segment_apps(t, body)} - {""})
    if t["secret_prompt"]:
        secret = (ctx.get("secrets") or {}).get(tg["name"])
        if not secret:
            _stop(run, units, "failed", "", error="the pre-shared key was not given with the apply (it is never stored); nothing was sent")
            return
        body[t["secret_prompt"]] = secret
    if t["per_type"]:
        body["type"] = tg.get("rule_type") or body.get("type")
    out = ops.create(_root(run, t), f"cfg:{t['key']}", body, name=tg["name"], log=run.log)
    body.pop(t["secret_prompt"], None) if t["secret_prompt"] else None
    if out.data is not None:
        out.data = None   # the create's answer is not kept: it may echo a secret
    if _after_write(run, units, out, "create"):
        new_id = str(out.id or "")
        if not new_id:
            again, _e = _rows_named(run, t, tg["name"])
            hit = next((r for r in again or [] if cb.name_of(t, r) == tg["name"]), None)
            new_id = cb.rid(hit) if hit else ""
        ctx["ids"][g["key"]] = out.id if out.id not in (None, "") else (int(new_id) if new_id.isdigit() and t["product"] != "zpa" else new_id)
        tg["new_id"], tg["sent"] = new_id, sent
        for u in units:
            u["object"] = dict(u["object"], id=new_id or None)
        run.created.append({"type": f"cfg:{t['key']}", "kind": t["key"], "id": new_id, "name": tg["name"]})
        run.log(f"[{_label(t)}] {tg['name']}: created")


def _h_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    ctx = _ctx(run)
    tg = g["target"]
    t = cb.BY_KEY[tg["type"]]
    fresh, err = cb.get_one(run.client, t, tg["id"], tg.get("rule_type") or "")
    if fresh is None:
        why = ao._read_halt(err)
        _stop(run, units, "skipped" if why else "failed", f"not attempted: {why}" if why else "",
              **({} if why else {"error": f"could not read it again before the change: {str(err)[:200]}"}))
        return
    if cb.digest(raw_form(t, fresh)) != tg["before_hash"]:
        _stop(run, units, "conflict", CONFLICT_STOP)
        return
    try:
        want = _resolve(tg["desired"], ctx["ids"])
    except _Unresolved as e:
        _stop(run, units, "skipped", f"not attempted: {e}")
        return
    before = payload(t, fresh)
    body = copy.deepcopy(want) if tg.get("replace") else dict(before, **want)
    if t["per_type"]:
        body["type"] = tg.get("rule_type") or fresh.get("type")
    for f in t["keep_nested"]:
        # ZPA's own applications are sent back as the target holds them (a Browser Access segment's clientless apps),
        # or not sent (PRA and inspection: ZPA keeps them unless they are listed for deletion, assumed).
        body.pop(f, None)
        if t["app_kind"] == "ba" and f in before:
            body[f] = copy.deepcopy(before[f])
    tg["undo_before"], tg["sent"] = before, {k: v for k, v in copy.deepcopy(want).items() if k not in t["keep_nested"]}
    out = ops.update(_root(run, t), f"cfg:{t['key']}", tg["id"], body, name=tg["name"], log=run.log)
    out.data = None
    if _after_write(run, units, out, "update"):
        run.log(f"[{_label(t)}] {tg['name']}: updated")


def _h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    tg = g["target"]
    t = cb.BY_KEY[tg["type"]]
    fresh, err = cb.get_one(run.client, t, tg["id"], tg.get("rule_type") or "")
    if fresh is None:
        if err and re.search(r"not.?found|404|does not exist|no such", str(err), re.I):
            run.mark(units, "noop", "already gone")
            return
        why = ao._read_halt(err)
        _stop(run, units, "skipped" if why else "failed", f"not attempted: {why}" if why else "",
              **({} if why else {"error": f"could not read it again before the delete: {str(err)[:200]}"}))
        return
    if cb.digest(raw_form(t, fresh)) != tg["before_hash"]:
        _stop(run, units, "conflict", CONFLICT_STOP)
        return
    tg["undo_before"] = payload(t, fresh)
    tg["undo_before"][t["name"]] = cb.name_of(t, fresh)
    out = ops.delete(_root(run, t), {"kind": f"cfg:{t['key']}", "id": tg["id"], "name": tg["name"], "type": tg.get("rule_type") or ""},
                     log=run.log)
    if _after_write(run, units, out, "delete"):
        run.log(f"[{_label(t)}] {tg['name']}: deleted")


def _h_activate(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    wrote = any(u["status"] == "applied" and u["kind"] in ("object", "field") for u in run.p["items"])
    if not wrote:
        run.mark(units, "noop", "nothing was written, so nothing was activated")
        return
    run.log("Activating the ZIA changes (the plan's last step)…")
    act = ops.activate_once(run.zia, run.log)
    g["target"]["activation"] = {k: act.get(k) for k in ("activated", "status", "error")}
    run.p["activation_step_result"] = g["target"]["activation"]
    if act.get("activated"):
        run.mark(units, "applied", "activated")
    else:
        _stop(run, units, "failed", "", error=f"the activation did not go through: {str(act.get('error') or '')[:200]}. The changes stay "
                                              "pending in ZIA: activate them in the portal, or Undo")


HANDLERS = {"cfg_backup": _h_backup, "cfg_create": _h_create, "cfg_update": _h_update, "cfg_delete": _h_delete, "cfg_activate": _h_activate}


def verify(run: Any) -> Dict[str, Any]:
    """Read back every applied object: created and updated ones carry what
    was sent, deleted ones are gone."""
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        out["checked"] += len(applied)
        tg = g["target"]
        if g["handler"] in ("cfg_backup", "cfg_activate"):
            ok = True
        else:
            t = cb.BY_KEY[tg["type"]]
            oid = tg.get("new_id") or tg.get("id")
            row, err = cb.get_one(run.client, t, oid, tg.get("rule_type") or "") if oid else (None, "no id")
            if g["handler"] == "cfg_delete":
                ok = row is None
            elif row is None:
                out["unread"].append(f"{tg['name']}: {str(err)[:120]}")
                for u in applied:
                    u["verified"] = None
                continue
            else:
                ok = _subset_equal(t, tg.get("sent") or {}, row)
                if ok and tg.get("sent_apps"):
                    have = {str(a.get("domain") or "") for a in cb.segment_apps(t, row)}
                    ok = set(tg["sent_apps"]) <= have
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{tg.get('name')}: not as sent when read back")
    return out


# ---------------------------------------------------------------------------
# After the run: re-push what is missing, and the opt-in rollback
# ---------------------------------------------------------------------------

def repush_spec(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """A new operation for what this run did not get into the tenant: the
    objects that failed, were not attempted, conflicted or did not read
    back as sent. Previewed and gated like any other (never applied on its
    own)."""
    spec = result.get("spec") or {}
    if spec.get("action") == "undo" or not spec.get("source"):
        return None
    names: Dict[Tuple[str, str], None] = {}
    for u in result.get("items") or []:
        o = u.get("object") or {}
        if u.get("kind") not in ("object", "field") or o.get("type") not in cb.BY_KEY:
            continue
        bad = u.get("status") in ("failed", "skipped", "conflict") or (u.get("status") == "applied" and u.get("verified") is False)
        if bad and not str(u.get("group") or "").startswith("delete:"):
            names[(o["type"], str(o.get("name") or ""))] = None
    if not names:
        return None
    out = {k: v for k, v in spec.items() if k not in ("objects", "types")}
    out["objects"] = [{"type": k, "name": n} for k, n in sorted(names)]
    if out.get("mode") == "full":
        out["mode"] = "update_matching"
    if any(u.get("verified") is False for u in result.get("items") or []) and out.get("mode") == "add_missing":
        out["mode"] = "update_matching"
    return out


def rollback(client: Any, inverse_spec: Dict[str, Any], *, scope: Dict[str, Any], assessor: str, tenant_label: str, log=None) -> Dict[str, Any]:
    """The opt-in automatic rollback after a stopped or failed run: the
    recorded inverse, planned against the tenant as it is now and applied
    through the same engine (re-read before each write, read-back). The
    person asked for it when they confirmed the forward plan
    (rollback_on_stop); anything someone changed meanwhile is left alone."""
    say = log or (lambda m: None)
    say("Rolling back what this run applied (you asked for this when you confirmed the plan)…")
    prepared = ao.plan(client, inverse_spec, scope=scope, tenant_label=tenant_label, log=say)
    if prepared["status"] != "ready":
        return dict(prepared, status=prepared["status"], items=prepared.get("items") or [])
    return ao.execute(client, inverse_spec, plan_hash=prepared["plan_hash"], scope=scope, writes_enabled=True,
                      confirm_text=prepared.get("confirm_phrase") or "", assessor=assessor, tenant_label=tenant_label, log=say)


# ---------------------------------------------------------------------------
# Scope, the object picker, registration
# ---------------------------------------------------------------------------

def in_scope(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
    t = str((spec or {}).get("type") or "") if isinstance(spec, dict) else ""
    products = [PRODUCT_OF[t]] if t in PRODUCT_OF else list(cb.PRODUCTS)
    for p in products:
        if any(cb.allowed(x, scope) for x in cb.types_for(p) if cb.writable(x)):
            return None
    return NOT_IN_SCOPE if len(products) > 1 else f"Not in scope: nothing {cb.PRODUCT_LABELS[products[0]]} is ticked on the Scope page."


def read_objects(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """What the form picks from: the saved backups and templates, the
    schedules and what each product covers. Reads nothing from the tenant."""
    say("Listing the saved backups and templates. Nothing is read from the tenant.")
    return {"backups": cb.list_backups(), "templates": cb.list_templates(), "schedules": cb.schedules(), "coverage": cb.coverage(),
            "in_scope": {p: [t["key"] for t in cb.types_for(p) if cb.allowed(t, scope)] for p in cb.PRODUCTS},
            "modes": [{"id": m, "label": MODE_WORDS[m]} for m in MODES]}


def _in_scope_for(product: str):
    """The scope check of one product's restore type and its family (the
    object picker): refused unless that product is ticked."""
    def check(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
        return in_scope(scope, {"type": TYPE_FOR[product]})
    return check


def _read_for(product: str):
    def read(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
        return read_objects(client, scope, say, cancel)
    return read


FAMILY_FOR = {p: f"{FAMILY}_{p}" for p in TYPE_FOR}
_COMMON = dict(handlers=HANDLERS, verify=verify, inverse=inverse, plan=plan, script="ops_config_restore.js", group="Backups")
for _p, _t in TYPE_FOR.items():
    ao.register(_t, product=_p, family=FAMILY_FOR[_p], in_scope=_in_scope_for(_p), read_objects=_read_for(_p),
                label=f"Restore or clone {cb.PRODUCT_LABELS[_p]}",
                hint=f"From a backup or a template: add what is missing, update what differs, or match exactly (with deletes). "
                     f"Planned in dependency order, with a fresh backup first{', ZIA activation last' if _p == 'zia' else ''}, and Undo.",
                **_COMMON)
