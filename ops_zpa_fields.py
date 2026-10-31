"""ZPA segment settings in bulk: one operation type on the Bulk changes engine.

`zpa_segment_fields` sets chosen fields across picked ZPA application
segments, Browser Access, Privileged Remote Access (PRA) and
inspection-enabled (AppProtection) segments included:

  enabled, health reporting (NONE / ON_ACCESS / CONTINUOUS), bypass
  (NEVER / ALWAYS / ON_NET), double encryption, use in disaster recovery
  mode, passive health checks, ICMP access, the segment group, server groups
  (add, remove or replace) and TCP / UDP port ranges (add or remove).

It is planned from the tenant as it is now (one item per segment and field,
before and after), approved by its plan hash and applied through the
engine's gates (write mode, a writer, the assessor, the typed confirmation).
Right before each segment's write the segment is read again and every item
is compared with the preview's "before": a field someone changed since is a
conflict and left alone. Every applied segment is read back, and Undo is a
new operation that puts back exactly what was changed.

ZPA's update replaces the segment (PUT /application/{id}; the SDK clears the
port ranges it is not given), so each write sends the segment back as it was
just read (admin_ops.segment_body) with only the chosen fields changed.

SDK facts, verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zpa/application_segment.py): health_reporting NONE / ON_ACCESS /
CONTINUOUS, bypass_type ALWAYS / NEVER / ON_NET, double_encrypt bool (the
add_segment docstring); update_segment PUT /application/{id} clears omitted
port fields; every segment kind (plain, Browser Access, PRA, inspection) is
the same /application/{id} resource (app_segments_ba_v2, app_segments_pra,
app_segments_inspection PUT the same path). The model's fields are
clientlessApps (Browser Access), praApps, inspectionApps and
commonAppsDto (models/application_segment.py).

Assumed, not verifiable without a tenant (said in the preview's notes):
  * a PUT keeps a PRA or inspection segment's applications when it carries
    no commonAppsDto (the SDK deletes them only through the explicit
    deletedPraApps / deletedInspectApps lists), so none is sent;
  * a Browser Access segment's clientlessApps are sent back as read, so the
    PUT cannot drop them; the read-back checks every Browser Access, PRA and
    inspection application is still there and reports any that is not;
  * the ICMP access values NONE / PING / PING_TRACEROUTING;
  * a segment needs at least one port range and one server group, the port
    of a Browser Access, PRA or inspection application must stay inside the
    segment's TCP ranges, and one domain may not sit in two segments on
    overlapping ports (ZPA refuses the save otherwise).
"""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import admin_ops as ao
import ops_zpa as zb
import pack_ops as ops
import zpa_reader as zr

TYPE = "zpa_segment_fields"
FAMILY = "zpa_segment_edit"
HANDLER = "zpa_f_update"
NOT_IN_SCOPE = "Not in scope: ZPA is not ticked on the Scope page, so the application segments are not read or changed."
MAX_SEGMENTS = 200       # segments per operation (one PUT each)
MAX_GROUPS = 20          # server group ids per add / remove / replace
MAX_RANGES = zb.MAX_RANGES
MAX_LIST = 5000          # segments listed for the form

# field -> (label, allowed values; None for a true / false field)
FIELDS: Dict[str, Tuple[str, Optional[Tuple[str, ...]]]] = {
    "enabled": ("Enabled", None),
    "health_reporting": ("Health reporting", ("NONE", "ON_ACCESS", "CONTINUOUS")),
    "bypass_type": ("Bypass", ("NEVER", "ALWAYS", "ON_NET")),
    "double_encrypt": ("Double encryption", None),
    "use_in_dr_mode": ("Use in disaster recovery mode", None),
    "passive_health_enabled": ("Passive health checks", None),
    "icmp_access_type": ("ICMP access", ("NONE", "PING", "PING_TRACEROUTING")),   # values assumed (not in the SDK docstrings)
    "segment_group_id": ("Segment group", ()),
}
CHOICE_LABELS = {"NONE": "None", "ON_ACCESS": "On access", "CONTINUOUS": "Continuous", "NEVER": "Never", "ALWAYS": "Always",
                 "ON_NET": "On trusted network", "PING": "Ping", "PING_TRACEROUTING": "Ping and traceroute"}
APP_KINDS = (("browser_access", "clientlessApps", "Browser Access"), ("pra", "praApps", "PRA"), ("inspection", "inspectionApps", "inspection"))
NOTES = ["ZPA's update replaces the segment, so each write sends the segment back as it was read right before it, with only the "
         "fields you chose changed.",
         "Browser Access applications are sent back as read; PRA and inspection applications are not sent (ZPA keeps them unless "
         "they are listed for deletion: assumed). The read-back checks every one is still there.",
         "Assumed ZPA rules, checked in the preview: a segment keeps at least one port range and one server group, the port of a "
         "Browser Access, PRA or inspection application stays inside its TCP ranges, and one domain is never in two segments on "
         "overlapping ports."]


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if scope.get("zpa") else NOT_IN_SCOPE


# ---------------------------------------------------------------------------
# A segment's current values
# ---------------------------------------------------------------------------

def _bool(v: Any, default: bool = False) -> bool:
    x = zr.as_bool(v)
    return default if x is None else x


def value(row: Dict[str, Any], field: str) -> Any:
    """The field's current value, normalised for comparing and showing."""
    raw = zr.get(row, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), field))
    if field == "enabled":
        return _bool(raw, True)
    if FIELDS[field][1] is None:
        return _bool(raw, False)
    return zr.as_str(raw).upper() if field != "segment_group_id" else zr.as_str(raw)


def ranges(row: Dict[str, Any], proto: str) -> List[Tuple[int, int]]:
    return [(int(a), int(b)) for a, b in zr.port_ranges(row, proto)[0]]


def server_groups(row: Dict[str, Any]) -> List[str]:
    return zr._ref_ids(zr.get(row, "serverGroups"))


def domains(row: Dict[str, Any]) -> List[str]:
    return [zr.as_str(d).lower().rstrip(".") for d in zr._items(zr.get(row, "domainNames")) if zr.as_str(d)]


def apps(row: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """The Browser Access, PRA and inspection applications of a segment:
    kind -> [{id, name, port}]."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for kind, key, _label in APP_KINDS:
        rows = []
        for a in zr._items(zr.get(row, key)):
            if isinstance(a, dict):
                p = zr._port(zr.get(a, "applicationPort"))
                rows.append({"id": zr.as_str(zr.get(a, "id")), "name": zr.as_str(zr.get(a, "name")) or zr.as_str(zr.get(a, "domain")), "port": p})
        out[kind] = rows
    return out


def kinds(row: Dict[str, Any]) -> List[str]:
    """Which of Browser Access / PRA / inspection the segment is (it may be several)."""
    flags = zr.normalize_segment(row)["flags"]
    return [label for kind, _k, label in APP_KINDS if flags.get(kind)]


def _app_ids(row: Dict[str, Any]) -> List[str]:
    return sorted(f"{k}:{a['id']}" for k, rows in apps(row).items() for a in rows if a["id"])


def locked(row: Dict[str, Any]) -> str:
    """Why a segment is not changed here ('' when it may be)."""
    if _bool(zr.get(row, "readOnly")):
        return "read-only in ZPA"
    if _bool(zr.get(row, "zscalerManaged")):
        return "managed by Zscaler"
    if zr.get(row, "sharedFromMicrotenant") not in (None, "", {}):
        # Assumed: a segment shared from another microtenant is changed only there.
        return "shared from another microtenant; change it there"
    return ""


def _rstr(r: Sequence[int]) -> str:
    return f"{r[0]}" if r[0] == r[1] else f"{r[0]}-{r[1]}"


def _covered(r: Tuple[int, int], have: Sequence[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    return next((h for h in have if h[0] <= r[0] and r[1] <= h[1]), None)


def _overlaps(a: Sequence[Tuple[int, int]], b: Sequence[Tuple[int, int]]) -> List[str]:
    out = []
    for a1, a2 in a:
        for b1, b2 in b:
            lo, hi = max(a1, b1), min(a2, b2)
            if lo <= hi:
                out.append(_rstr((lo, hi)))
    return out


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------

def _id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if not re.fullmatch(r"[0-9A-Za-z_-]{1,40}", s):
        raise _err(f"{what}: '{s[:40]}' is not a ZPA id.")
    return s


def _ids(v: Any, what: str) -> List[str]:
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        raise _err(f"{what} must be a list of ids.")
    if len(v) > MAX_GROUPS:
        raise _err(f"{what}: at most {MAX_GROUPS} ids.")
    return list(dict.fromkeys(_id(x, what) for x in v))


def _ports(v: Any, what: str) -> List[Tuple[int, int]]:
    return [(a, b) for a, b in zb.parse_ports(v, what)]


def _changes(raw: Any, where: str) -> Dict[str, Any]:
    """The fields to set, checked and normalised: {fields: {f: v},
    server_groups: {add, remove, replace}, tcp: {add, remove}, udp: {...}}.
    Anything not known is refused (deny by default)."""
    if not isinstance(raw, dict) or not raw:
        raise _err(f"{where}: choose at least one setting to change.")
    out: Dict[str, Any] = {"fields": {}, "server_groups": {"add": [], "remove": [], "replace": None},
                           "tcp": {"add": [], "remove": []}, "udp": {"add": [], "remove": []}}
    for k, v in raw.items():
        if k in FIELDS:
            label, allowed = FIELDS[k]
            if allowed is None:
                b = v if isinstance(v, bool) else zr.as_bool(v) if isinstance(v, str) else None
                if b is None:
                    raise _err(f"{label}: choose on or off.")
                out["fields"][k] = b
            elif k == "segment_group_id":
                out["fields"][k] = _id(v, label)
            else:
                s = str(v or "").strip().upper()
                if s not in allowed:
                    raise _err(f"{label}: '{str(v)[:30]}' is not one of {', '.join(allowed)}.")
                out["fields"][k] = s
        elif k == "server_groups":
            if not isinstance(v, dict) or not set(v) <= {"add", "remove", "replace"}:
                raise _err("Server groups: give add, remove or replace, each a list of ids.")
            sg = out["server_groups"]
            sg["add"], sg["remove"] = _ids(v.get("add"), "Server groups to add"), _ids(v.get("remove"), "Server groups to remove")
            if v.get("replace") not in (None, ""):
                sg["replace"] = _ids(v.get("replace"), "Server groups")
                if not sg["replace"]:
                    raise _err("Server groups: a segment needs at least one server group.")
                if sg["add"] or sg["remove"]:
                    raise _err("Server groups: replace them, or add and remove some, not both.")
            if set(sg["add"]) & set(sg["remove"]):
                raise _err("Server groups: the same group is both added and removed.")
        elif k in ("tcp_ports", "udp_ports"):
            proto = k[:3]
            if not isinstance(v, dict) or not set(v) <= {"add", "remove"}:
                raise _err(f"{proto.upper()} ports: give add and / or remove, like {{\"add\": \"443, 8000-8080\"}}.")
            p = out[proto]
            p["add"], p["remove"] = _ports(v.get("add"), f"{proto.upper()} ports to add"), _ports(v.get("remove"), f"{proto.upper()} ports to remove")
            if set(p["add"]) & set(p["remove"]):
                raise _err(f"{proto.upper()} ports: the same range is both added and removed.")
        else:
            raise _err(f"'{str(k)[:40]}' is not a segment setting this operation changes.")
    sg, empty = out["server_groups"], True
    for part in (out["fields"], sg["add"], sg["remove"], sg["replace"], out["tcp"]["add"], out["tcp"]["remove"], out["udp"]["add"], out["udp"]["remove"]):
        if part:
            empty = False
    if empty:
        raise _err(f"{where}: choose at least one setting to change.")
    return out


def _requests(spec: Dict[str, Any]) -> Tuple[List[Tuple[str, Dict[str, Any]]], Dict[str, Any]]:
    """[(segment id, changes)] and the normalised spec (for the plan hash).
    Either {segments: [ids], set: {...}} (the page: the same settings on every
    picked segment) or {per_segment: [{segment, set}]} (an Undo)."""
    if spec.get("per_segment") is not None:
        rows = ao._list_field(spec, "per_segment", objects=True, cap=MAX_SEGMENTS)
        out = [(_id(r.get("segment"), "Segment"), _changes(r.get("set"), "Segment " + str(r.get("segment"))[:40])) for r in rows]
        if not out:
            raise _err("Pick at least one application segment.")
        if len({s for s, _ in out}) != len(out):
            raise _err("A segment is listed twice.")
        nspec = {"type": TYPE, "per_segment": [{"segment": s, "set": c} for s, c in out]}
        return out, nspec
    raw = spec.get("segments")
    if not isinstance(raw, list) or not raw:
        raise _err("Pick at least one application segment.")
    if len(raw) > MAX_SEGMENTS:
        raise _err(f"At most {MAX_SEGMENTS} segments per operation; this one picks {len(raw)}. Split it.")
    ids = list(dict.fromkeys(_id(x, "Segment") for x in raw))
    ch = _changes(spec.get("set"), "The settings")
    return [(s, ch) for s in ids], {"type": TYPE, "segments": ids, "set": ch}


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _show(field: str, v: Any, names: Dict[str, str]) -> Any:
    if field == "segment_group_id":
        return f"{names.get(v) or v}" if v else "none"
    if isinstance(v, bool):
        return v
    return CHOICE_LABELS.get(v, v) if v else "not set"


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    reqs, nspec = _requests(spec)
    zpa = zb._zpa(client)
    data, _errs = zb.read(zpa, ("segment", "segment_group", "server_group"), say, cancel)
    by_id = {zb._oid(s): s for s in data["segment"]}
    sg_names = {zb._oid(g): zb._name(g) for g in data["segment_group"]}
    srv_names = {zb._oid(g): zb._name(g) for g in data["server_group"]}
    names = dict(sg_names, **srv_names)
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    for sid, ch in reqs:
        for g in ch["server_groups"]["add"] + (ch["server_groups"]["replace"] or []):
            if g not in srv_names:
                blockers.append(f"Server group {g} is not in the tenant now. Read the tenant again.")
        gid = ch["fields"].get("segment_group_id")
        if gid and gid not in sg_names:
            blockers.append(f"Segment group {gid} is not in the tenant now. Read the tenant again.")
        if sid not in by_id:
            raise _err(f"The segment {sid!r} is not in the tenant now. Read the tenant again.")
    # Ports each segment will have, for the overlap check across picked segments.
    planned: Dict[str, Dict[str, List[Tuple[int, int]]]] = {k: {p: ranges(s, p) for p in ("tcp", "udp")} for k, s in by_id.items()}
    for sid, ch in reqs:
        row = by_id[sid]
        name = zb._name(row) or sid
        ref = {"type": "zpa_segment", "id": sid, "name": name, "kinds": kinds(row)}
        gkey = f"seg:{sid}"
        units: List[Dict[str, Any]] = []
        why_locked = locked(row)

        def unit(field: str, before: Any, after: Any, *, val: Any = None, status: str = "change", reason: str = "", kx: str = "") -> Dict[str, Any]:
            k = f"{gkey}:{field}" + (f":{'+' if after else '-'}{kx or val}" if val is not None else "")
            u = ao._unit(k, gkey, "segment_field", ref, field, before, after, value=val, status=status, reason=reason)
            units.append(u)
            return u

        # scalar fields
        for f, want in ch["fields"].items():
            cur = value(row, f)
            if cur == want:
                unit(f, _show(f, cur, names), _show(f, want, names), status="noop", reason="already as asked")
                continue
            note = ""
            if f == "double_encrypt" and want and ref["kinds"]:
                note = f"check first: ZPA may refuse double encryption on a {' / '.join(ref['kinds'])} segment (assumed)"
                warnings.append(f"'{name}' is a {' / '.join(ref['kinds'])} segment: ZPA may refuse double encryption on it.")
            if f == "bypass_type" and want != "NEVER":
                warnings.append(f"Bypass {CHOICE_LABELS[want].lower()} on '{name}': matching traffic goes direct, not through ZPA"
                                + (" (no PRA or inspection for it)." if set(ref["kinds"]) & {"PRA", "inspection"} else "."))
            if f == "enabled" and not want:
                warnings.append(f"Disabling '{name}': users lose access through it until it is enabled again.")
            unit(f, _show(f, cur, names), _show(f, want, names), reason=note).update(raw_before=cur, raw_after=want)
        # server groups
        have = server_groups(row)
        sgc = ch["server_groups"]
        add = [g for g in sgc["replace"] if g not in have] if sgc["replace"] is not None else list(sgc["add"])
        rem = [g for g in have if g not in sgc["replace"]] if sgc["replace"] is not None else list(sgc["remove"])
        if sgc["replace"] is None:
            for g in [g for g in add if g in have]:
                unit("server_groups", True, True, val=srv_names.get(g, g), kx=g, status="noop", reason="already in this segment").update(gid=g)
            for g in [g for g in rem if g not in have]:
                unit("server_groups", False, False, val=srv_names.get(g, g), kx=g, status="noop", reason="not in this segment").update(gid=g)
            add, rem = [g for g in add if g not in have], [g for g in rem if g in have]
        left = [g for g in have if g not in rem] + add
        for g in add:
            unit("server_groups", False, True, val=srv_names.get(g, g), kx=g).update(gid=g)
        for g in rem:
            unit("server_groups", True, False, val=srv_names.get(g, g), kx=g,
                 **({"status": "excluded", "reason": "a segment needs at least one server group, so the last one is not removed (assumed ZPA rule)"}
                    if not left else {})).update(gid=g)
        # ports
        app_ports = [(lab, a) for kind, _key, lab in APP_KINDS for a in apps(row)[kind] if a["port"]]
        after_ports: Dict[str, List[Tuple[int, int]]] = {}
        for proto in ("tcp", "udp"):
            cur_r = ranges(row, proto)
            rm_ok = []
            for r in ch[proto]["remove"]:
                if r not in cur_r:
                    within = _covered(r, cur_r)
                    unit(f"{proto}_port_ranges", False, False, val=_rstr(r), status="noop",
                         reason=f"not a range of its own here{' (it is inside ' + _rstr(within) + '; ranges are removed whole)' if within else ''}")
                else:
                    rm_ok.append(r)
            add_ok = []
            for r in ch[proto]["add"]:
                within = _covered(r, cur_r)
                if within:
                    unit(f"{proto}_port_ranges", True, True, val=_rstr(r), status="noop",
                         reason="already in this segment" if within == r else f"already covered by {_rstr(within)}")
                else:
                    add_ok.append(r)
            after_ports[proto] = sorted([r for r in cur_r if r not in rm_ok] + add_ok)
            for r in rm_ok:
                u = unit(f"{proto}_port_ranges", True, False, val=_rstr(r))
                if proto == "tcp":
                    uses = [f"{lab} application '{a['name']}' (port {a['port']})" for lab, a in app_ports
                            if not any(lo <= a["port"] <= hi for lo, hi in after_ports["tcp"]) and r[0] <= a["port"] <= r[1]]
                    if uses:
                        u.update(status="excluded", reason=f"the {uses[0]} needs this port in the segment's TCP ranges (assumed ZPA rule)")
            for r in add_ok:
                u = unit(f"{proto}_port_ranges", False, True, val=_rstr(r))
                mine = set(domains(row))
                for oid, other in by_id.items():
                    if oid == sid:
                        continue
                    shared = sorted(mine & set(domains(other)))
                    hit = _overlaps([r], planned[oid][proto]) if shared else []
                    if hit:
                        u.update(status="excluded", reason=f"'{zb._name(other)}' serves {shared[0]} on {proto.upper()} {hit[0]} too; ZPA refuses one "
                                                          "domain in two segments on overlapping ports (assumed ZPA rule)")
                        break
        for proto in ("tcp", "udp"):   # what this segment keeps, as planned (the excluded steps put back)
            kept = [r for r in ranges(row, proto) if not any(u["field"] == f"{proto}_port_ranges" and u["status"] == "change" and not u["after"]
                                                             and u["value"] == _rstr(r) for u in units)]
            added = [r for r in ch[proto]["add"] if any(u["field"] == f"{proto}_port_ranges" and u["status"] == "change" and u["after"]
                                                       and u["value"] == _rstr(r) for u in units)]
            planned[sid][proto] = sorted(kept + added)
        if not planned[sid]["tcp"] and not planned[sid]["udp"]:
            for u in units:
                if u["field"].endswith("_port_ranges") and u["status"] == "change" and not u["after"]:
                    u.update(status="excluded", reason="a segment needs at least one port range, so the last one is not removed (assumed ZPA rule)")
            planned[sid] = {p: ranges(row, p) for p in ("tcp", "udp")}
        if why_locked:
            for u in units:
                if u["status"] == "change":
                    u.update(status="excluded", reason=f"not changed here: {why_locked}")
        items.extend(units)
        todo = [u for u in units if u["status"] == "change"]
        if todo:
            groups.append({"key": gkey, "handler": HANDLER, "target": {"id": sid, "name": name, "kinds": ref["kinds"], "keep_apps": _app_ids(row)}})
    n = len(reqs)
    title = f"Change settings on {n} ZPA application segment{'s' if n != 1 else ''}"
    return {"type": TYPE, "product": "zpa", "title": title, "spec": nspec, "items": items, "groups": groups,
            "warnings": list(dict.fromkeys(warnings)), "blockers": list(dict.fromkeys(blockers)), "notes": list(NOTES),
            "apply_note": "ZPA applies each segment's change as it is saved; there is no activation step."}


# ---------------------------------------------------------------------------
# The write (one PUT per segment)
# ---------------------------------------------------------------------------

def _now(fresh: Dict[str, Any], u: Dict[str, Any]) -> Any:
    """The item's field in the segment as read now, in the form of its 'before'."""
    f = u["field"]
    if f == "server_groups":
        return u["gid"] in server_groups(fresh)
    if f.endswith("_port_ranges"):
        return u["value"] in [_rstr(r) for r in ranges(fresh, f[:3])]
    return value(fresh, f)


def _h_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = zb.get_one(run.zpa, "segment", t["id"])
    if fresh is None:
        zb._halt_or_fail(run, units, err, f"the segment '{t['name']}'")
        return
    ok = []
    for u in units:
        before = u.get("raw_before", u["before"])
        if _now(fresh, u) != before:
            run.mark([u], "conflict", f"changed in ZPA since the preview ({u['field'].replace('_', ' ')}); left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    body = ao.segment_body(fresh)
    for u in ok:
        if u["field"] in FIELDS:
            body[u["field"]] = u.get("raw_after", u["after"])
    sgs = [x for x in server_groups(fresh) if not any(u["field"] == "server_groups" and not u["after"] and u["gid"] == x for u in ok)]
    sgs += [u["gid"] for u in ok if u["field"] == "server_groups" and u["after"] and u["gid"] not in sgs]
    body["server_group_ids"] = sgs
    for proto in ("tcp", "udp"):
        f = f"{proto}_port_ranges"
        rng = [r for r in ranges(fresh, proto) if not any(u["field"] == f and not u["after"] and u["value"] == _rstr(r) for u in ok)]
        for u in ok:
            if u["field"] == f and u["after"]:
                a, _, b = u["value"].partition("-")
                r = (int(a), int(b or a))
                if r not in rng:
                    rng.append(r)
        body[f] = [str(x) for a, b in sorted(rng) for x in (a, b)]
    if not sgs:
        run.mark(ok, "excluded", "a segment needs at least one server group (assumed ZPA rule)")
        return
    if not body["tcp_port_ranges"] and not body["udp_port_ranges"]:
        run.mark(ok, "excluded", "a segment needs at least one port range (assumed ZPA rule)")
        return
    ba = zr.get(fresh, "clientlessApps")
    if ba:
        # Sent back as read (with their ids), so the replacing PUT cannot drop them (assumed safe; see the module docstring).
        body["clientlessApps"] = [dict(a) for a in zr._items(ba) if isinstance(a, dict)]
    out = ops.update(run.zpa, "zpa_segment", t["id"], body, name=str(zb._name(fresh) or t["name"]), log=run.log)
    if run.outcome(ok, out, "update"):
        run.log(f"[ZPA segment] {t['name']}: {', '.join(sorted({u['field'].replace('_', ' ') for u in ok}))} changed")


def verify(run: Any) -> Dict[str, Any]:
    """Read back every changed segment: each applied field is as asked and
    every Browser Access, PRA and inspection application is still there."""
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t = g["target"]
        out["checked"] += len(applied)
        row, err = zb.get_one(run.zpa, "segment", t["id"])
        if row is None:
            out["unread"].append(f"{t['name']}: {err}")
            for u in applied:
                u["verified"] = None
            continue
        lost = sorted(set(t.get("keep_apps") or []) - set(_app_ids(row)))
        if lost:
            out["mismatched"].append(f"{t['name']}: {len(lost)} Browser Access / PRA / inspection application(s) are missing when read back "
                                     f"({', '.join(lost[:5])}); check the segment in the ZPA Admin Portal")
        for u in applied:
            want = u.get("raw_after", u["after"])
            good = _now(row, u) == want and not lost
            u["verified"] = good
            if good:
                out["confirmed"] += 1
            elif not lost:
                out["mismatched"].append(f"{t['name']}: {u['field'].replace('_', ' ')} {u.get('value') or ''} is not {u['after']} when read back".replace("  ", " "))
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Puts back exactly what was applied, segment by segment."""
    per: Dict[str, Dict[str, Any]] = {}
    for u in result.get("items") or []:
        if u.get("status") != "applied":
            continue
        sid = str(u["object"]["id"])
        s = per.setdefault(sid, {})
        f = u["field"]
        if f in FIELDS:
            before = u.get("raw_before", u["before"])
            if before in ("", None):
                continue   # it had no value before; ZPA's own default is not set back here
            s[f] = before
        elif f == "server_groups":
            sg = s.setdefault("server_groups", {"add": [], "remove": []})
            sg["remove" if u["after"] else "add"].append(u["gid"])
        elif f.endswith("_port_ranges"):
            p = s.setdefault(f"{f[:3]}_ports", {"add": [], "remove": []})
            p["remove" if u["after"] else "add"].append(u["value"])
    per = {k: v for k, v in per.items() if v}
    if not per:
        return None
    return {"type": TYPE, "per_segment": [{"segment": k, "set": v} for k, v in sorted(per.items())]}


# ---------------------------------------------------------------------------
# What the form picks from
# ---------------------------------------------------------------------------

def segment_row(row: Dict[str, Any], names: Dict[str, str]) -> Dict[str, Any]:
    tcp, udp = ranges(row, "tcp"), ranges(row, "udp")
    return {"id": zb._oid(row), "name": zb._name(row) or zb._oid(row), "enabled": value(row, "enabled"),
            "segment_group": names.get(value(row, "segment_group_id")) or zr.as_str(zr.get(row, "segmentGroupName")) or value(row, "segment_group_id"),
            "server_groups": [names.get(g) or g for g in server_groups(row)],
            "tcp": [_rstr(r) for r in tcp], "udp": [_rstr(r) for r in udp], "domains": len(domains(row)),
            "health_reporting": value(row, "health_reporting"), "bypass_type": value(row, "bypass_type"),
            "double_encrypt": value(row, "double_encrypt"), "use_in_dr_mode": value(row, "use_in_dr_mode"),
            "kinds": kinds(row), "microtenant": zr.as_str(zr.get(row, "microtenantName")), "locked": locked(row)}


def read_objects(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    zpa = zb._zpa(client)
    data, errors = zb.read(zpa, (), say, cancel, optional=("segment", "segment_group", "server_group"))
    pick = lambda rows: sorted(({"id": zb._oid(r), "name": zb._name(r) or zb._oid(r)} for r in rows if zb._oid(r)), key=lambda x: x["name"].lower())  # noqa: E731
    names = {x["id"]: x["name"] for x in pick(data["segment_group"]) + pick(data["server_group"])}
    segs = sorted((segment_row(r, names) for r in data["segment"]), key=lambda x: x["name"].lower())
    return {"segments": segs[:MAX_LIST], "segments_truncated": len(segs) > MAX_LIST, "segment_groups": pick(data["segment_group"]),
            "server_groups": pick(data["server_group"]),
            "fields": [{"id": k, "label": lab, "choices": [{"id": c, "label": CHOICE_LABELS.get(c, c)} for c in (allowed or ())]
                        if allowed is not None else None} for k, (lab, allowed) in FIELDS.items() if k != "segment_group_id"],
            "errors": {zb.LIST_LABELS.get(k, k): v for k, v in errors.items()},
            "limits": {"segments": MAX_SEGMENTS, "server_groups": MAX_GROUPS, "port_ranges": MAX_RANGES}}


ao.register(TYPE, family=FAMILY, product="zpa", label="ZPA segment settings in bulk",
            hint="Set the same fields on many application segments at once (Browser Access, PRA and inspection segments too): enabled, "
                 "health reporting, bypass, double encryption, disaster recovery mode, segment group, server groups and port ranges.",
            in_scope=in_scope, plan=plan, read_objects=read_objects, handlers={HANDLER: _h_update}, verify=verify, inverse=inverse,
            group="Change existing", script="ops_zpa_fields.js")
