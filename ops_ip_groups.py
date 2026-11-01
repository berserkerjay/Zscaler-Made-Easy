"""IP source and destination groups: an IP source group editor, deleting
either kind, and CSV import and export, on the Bulk changes engine
(admin_ops plugin).

One operation type on /report/operations, under "Change":

  ip_group_admin
    action source_edit  one IP source group: an existing one ({"id": n}) or
                        a new one ({"new": name, "description": ...}); `add`
                        and `remove` list IPv4 addresses, CIDR blocks and
                        a-b ranges. The group goes back as read with its new
                        address list (PUT /ipSourceGroups/{id}). Undo puts
                        the list back, or deletes a group it created.
    action delete       one source or destination group (`kind`), typed
                        "DELETE <name>". Refused while any rule names it:
                        the preview lists those rules. The Cloud Firewall,
                        DNS Control and IPS rules are read for that; one of
                        them not in scope on the Scope page cannot be checked,
                        so the delete is blocked until it is ticked (deny by
                        default). A predefined (non-editable) group is never
                        deleted. Undo creates the group again with the same
                        name, type, description and addresses (a new id).
    action import       a CSV (the export's own form, below) of groups to
                        create or update, matched by kind and name. `mode`
                        merge adds what is missing to an existing group;
                        replace makes its list exactly the CSV's (the removals
                        are listed). Groups not in the CSV are not touched.
                        Undo deletes what the import created and puts each
                        updated list back.

  Export (read-only): the picker's answer carries the groups as CSV
  (`csv`), every cell made safe for spreadsheets (csv_safe), for the page to
  save. Columns: kind, name, type, description, addresses (separated by
  "; "). An import reads the same columns, one group per row or one row per
  address (rows with the same kind and name are joined).

Destination groups are also edited entry by entry by ip_group_edit
(ops_list_fix). IPv6 addresses are refused (zscaler-sdk-python 1.11.3
supports no user-defined IPv6 destination group; IPv6 source groups are
not offered here either).

The engine supplies the scope check before any read (Cloud Firewall in
scope), the plan hash and re-plan, write mode, the writer, the named
assessor, the typed confirmation, the re-read right before each write (a
group changed since the preview is a conflict, left alone), one ZIA
activation, the read-back, the record, the audit log with the actor, and
Undo.

SDK calls, verified against zscaler-sdk-python 1.11.3 (zia/cloud_firewall.py):
list_ip_source_groups, get_ip_source_group, add_ip_source_group (name,
ip_addresses, description), update_ip_source_group (PUT), delete_ip_source_group;
list_ip_destination_groups, get_ip_destination_group,
add_ip_destination_group (name, type, addresses, description, ip_categories,
countries), update_ip_destination_group (PUT; addresses replaced by default),
delete_ip_destination_group; model IPSourceGroup (id, name, description,
ip_addresses, is_non_editable). Rules: admin_ops.read_rules (src_ip_groups,
dest_ip_groups and their IPv6 forms). Writes go through pack_ops (kinds
ip_source_group, ip_destination_group).
ASSUMED: the limits below (ops_list_fix's, from ZIA's Ranges & Limitations
page as summarised); that ZIA refuses deleting a group a rule outside the
policies read here (forwarding, NAT control) still uses.
"""
from __future__ import annotations

import csv
import io
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import admin_ops as ao
import csv_safe
import ops_list_fix as lf
import ops_zia_baseline as zb
import pack_ops as ops

TYPE = "ip_group_admin"
FAMILY = "ip_group_admin_targets"
SCRIPT = "ops_ip_groups.js"
KINDS = {"source": {"label": "IP source group", "pack": "ip_source_group", "field": "ip_addresses"},
         "destination": {"label": "IP destination group", "pack": "ip_destination_group", "field": "addresses"}}
REF_POLICIES = ("firewall", "dns_control", "firewall_ips")
REF_FIELDS = {"source": ("src_ip_groups", "src_ipv6_groups"), "destination": ("dest_ip_groups", "dest_ipv6_groups")}
DEST_TYPES = ("DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN")
MAX_ENTRIES = lf.MAX_ENTRIES
MAX_GROUP_ADDRESSES = lf.MAX_GROUP_ADDRESSES
MAX_CSV_BYTES = 1024 * 1024
MAX_CSV_ROWS = 20000
MAX_IMPORT_GROUPS = 200
NAME_MAX = lf.GROUP_NAME_MAX
DESC_MAX = lf.DESC_MAX
CSV_COLUMNS = ("kind", "name", "type", "description", "addresses")
NOT_CHECKED = ("Forwarding control and NAT control rules are not read here; ZIA refuses the delete if one of them still uses the group "
               "(assumed).")

LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    if "firewall" in (scope.get("policies") or []):
        return None
    return ("Not in scope: IP source and destination groups are read and changed with the Cloud Firewall; tick ZIA platform on the "
            "Scope page. Nothing was read.")


# ---------------------------------------------------------------------------
# Reading (GET only)
# ---------------------------------------------------------------------------

def read_groups(zia: Any, kind: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if kind == "destination":
        return lf.read_groups(zia)
    try:
        rows, err = ao._rows(lf._fw(zia).list_ip_source_groups())
    except ao.OperationError:
        raise
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"
    return [zb._deep_snake(r) for r in rows], err


def get_group(zia: Any, kind: str, gid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if kind == "destination":
        return lf.get_group(zia, gid)
    try:
        row, err = ao._one(lf._fw(zia).get_ip_source_group(gid))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    return (zb._deep_snake(row) if row else None), err


def entries(g: Optional[Dict[str, Any]], kind: str) -> List[str]:
    v = (g or {}).get(KINDS[kind]["field"])
    return [str(x) for x in v if isinstance(x, (str, int))] if isinstance(v, list) else []


def snapshot(g: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """What the conflict guard compares and an Undo re-creates."""
    s = {"name": str(g.get("name") or ""), "description": str(g.get("description") or ""), "addresses": sorted(entries(g, kind))}
    if kind == "destination":
        s["group_type"] = str(g.get("type") or "").upper()
        for f in ("ip_categories", "countries"):
            v = g.get(f)
            if isinstance(v, list) and v:
                s[f] = sorted(str(x) for x in v)
    return s


def locked(g: Dict[str, Any]) -> bool:
    return ao._truthy(g.get("is_non_editable"))


def rule_refs(zia: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Tuple[Dict[Tuple[str, str], List[Dict[str, Any]]], List[str], List[str]]:
    """({(kind, group id): [rules naming it]}, read errors, policies not in scope)."""
    refs: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    errors: List[str] = []
    pols = [p for p in REF_POLICIES if p in (scope.get("policies") or [])]
    out = [ao._label(p) for p in REF_POLICIES if p not in (scope.get("policies") or [])]
    for pol in pols:
        ao._check_stop(cancel)
        say(f"Reading the {ao._label(pol)} rules (which rules use the groups)…")
        try:
            rows, err = ao.read_rules(zia, pol, cancel=cancel)
        except ao.OperationError as e:
            rows, err = [], str(e)
        if err:
            errors.append(f"{ao._label(pol)}: {err}")
            continue
        for r in rows:
            for kind, fields in REF_FIELDS.items():
                for f in fields:
                    for gid in lf._ids(r, f):
                        refs.setdefault((kind, gid), []).append({"policy": pol, "policy_label": ao._label(pol), "id": r.get("id"),
                                                                 "name": str(r.get("name") or ""), "order": r.get("order"), "state": ao._state(r)})
    return refs, errors, out


def to_csv(groups: Dict[str, List[Dict[str, Any]]]) -> str:
    """The groups as CSV (the import's own form), every cell made safe."""
    buf = io.StringIO()
    w = csv_safe.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for kind in ("source", "destination"):
        for g in sorted(groups.get(kind) or [], key=lambda g: str(g.get("name") or "").lower()):
            w.writerow([kind, str(g.get("name") or ""), str(g.get("type") or "") if kind == "destination" else "",
                        str(g.get("description") or ""), "; ".join(entries(g, kind))])
    return buf.getvalue()


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Both kinds of group with their entries and the rules in scope that use
    each, and the CSV export. Read-only."""
    zia = client.zia
    errors: Dict[str, str] = {}
    got: Dict[str, List[Dict[str, Any]]] = {}
    for kind in ("source", "destination"):
        say(f"Reading the {KINDS[kind]['label']}s…")
        rows, err = read_groups(zia, kind)
        if err:
            errors[kind] = err
        got[kind] = rows
    refs, rerr, out = rule_refs(zia, scope, say, cancel)
    if rerr:
        errors["rules"] = "; ".join(rerr)

    def summary(g: Dict[str, Any], kind: str) -> Dict[str, Any]:
        e = entries(g, kind)
        return {"id": g.get("id"), "name": str(g.get("name") or ""), "kind": kind, "type": str(g.get("type") or "") if kind == "destination" else "",
                "description": str(g.get("description") or "")[:DESC_MAX], "count": len(e), "entries": e[:50], "locked": locked(g),
                "used_by": refs.get((kind, str(g.get("id"))), [])}
    return {"source_groups": [summary(g, "source") for g in sorted(got["source"], key=lambda g: str(g.get("name") or "").lower())],
            "destination_groups": [summary(g, "destination") for g in sorted(got["destination"], key=lambda g: str(g.get("name") or "").lower())],
            "csv": to_csv(got), "csv_columns": list(CSV_COLUMNS), "errors": errors, "not_checked": out, "note": NOT_CHECKED,
            "limits": {"entries": MAX_ENTRIES, "csv_bytes": MAX_CSV_BYTES, "groups": MAX_IMPORT_GROUPS}}


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

def _name(v: Any, what: str = "group") -> str:
    n = " ".join(str(v or "").split())
    if not n:
        raise ao.OperationError(f"Give the {what} a name.")
    if ao._has_control(n) or len(n) > NAME_MAX:
        raise ao.OperationError(f"The {what} name must be at most {NAME_MAX} characters, with no control character.")
    return n


def _desc(v: Any) -> str:
    d = " ".join(str(v or "").split())
    if ao._has_control(d) or len(d) > DESC_MAX:
        raise ao.OperationError(f"A description must be at most {DESC_MAX} characters, with no control character.")
    return d


def _kind(v: Any) -> str:
    k = str(v or "").strip().lower()
    k = {"src": "source", "dst": "destination", "dest": "destination"}.get(k, k)
    if k not in KINDS:
        raise ao.OperationError("The group kind is source or destination.")
    return k


def check_entry(raw: Any, kind: str, group_type: str = "DSTN_IP") -> Tuple[Optional[str], Optional[str]]:
    """(the entry as stored, None) or (None, why refused)."""
    s = str(raw or "").strip()
    if kind == "destination" and group_type == "DSTN_DOMAIN" and s.startswith((".", "*.")):
        k, v, why = lf.classify(s.lstrip("*").lstrip("."))
        return (("." + v) if k == "host" else None), (None if k == "host" else (why or "is not a domain"))
    k, v, why = lf.classify(s)
    want = "ip" if kind == "source" or group_type == "DSTN_IP" else "host"
    if k == want:
        return v, None
    if k == "ipv6":
        return None, "an IPv6 address: not offered here"
    return None, why or ("is not an IPv4 address, block or range" if want == "ip" else "is not a host name")


def _clean(raw: List[Any], kind: str, group_type: str = "DSTN_IP") -> Tuple[List[str], List[Tuple[str, str]]]:
    ok, bad, seen = [], [], set()
    for x in raw:
        if not str(x or "").strip():
            continue
        v, why = check_entry(x, kind, group_type)
        if why:
            bad.append((str(x)[:120], why))
        elif v.lower() not in seen:
            seen.add(v.lower())
            ok.append(v)
    return ok, bad


def _list(spec: Dict[str, Any], key: str) -> List[Any]:
    v = spec.get(key)
    raw = ao._raw_entries(v) if not isinstance(v, list) else v
    if len(raw) > MAX_ENTRIES:
        raise ao.OperationError(f"At most {MAX_ENTRIES:,} entries per operation. Split it.")
    return [str(x)[:300] for x in raw]


def parse_csv(text: Any) -> List[Dict[str, Any]]:
    """The groups a CSV names: [{kind, name, group_type, description,
    addresses}], rows with the same kind and name joined. Untrusted input:
    size and row caps, no formula ever evaluated, a leading ' (the export's
    spreadsheet guard) taken off. OperationError in words."""
    if not isinstance(text, str):
        raise ao.OperationError("The CSV must be text.")
    if len(text.encode("utf-8", "ignore")) > MAX_CSV_BYTES:
        raise ao.OperationError(f"The CSV is larger than {MAX_CSV_BYTES // 1024} KB. Split it.")
    text = text.lstrip("﻿")
    if "\x00" in text:
        raise ao.OperationError("The CSV contains a NUL character: it is not a text CSV.")
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as e:
        raise ao.OperationError(f"The CSV could not be read: {str(e)[:120]}.")
    rows = [r for r in rows if any(str(c).strip() for c in r)]
    if not rows:
        raise ao.OperationError("The CSV is empty.")
    if len(rows) > MAX_CSV_ROWS + 1:
        raise ao.OperationError(f"At most {MAX_CSV_ROWS:,} rows. Split it.")
    head = [str(c).strip().lower() for c in rows[0]]
    col = {c: head.index(c) for c in CSV_COLUMNS if c in head}
    if "name" not in col or "addresses" not in col or "kind" not in col:
        raise ao.OperationError("The CSV's first row must name the columns kind, name and addresses (type and description are optional), as "
                                "the export writes them.")

    def cell(r: List[str], c: str) -> str:
        v = str(r[col[c]]).strip() if c in col and col[c] < len(r) else ""
        return v[1:] if v.startswith("'") and v[1:2] in csv_safe._TRIGGERS else v
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for i, r in enumerate(rows[1:], start=2):
        try:
            kind = _kind(cell(r, "kind"))
            name = _name(cell(r, "name"))
            desc = _desc(cell(r, "description"))
        except ao.OperationError as e:
            raise ao.OperationError(f"Row {i}: {e}")
        gt = cell(r, "type").upper() if kind == "destination" else ""
        if kind == "destination":
            gt = gt or "DSTN_IP"
            if gt not in DEST_TYPES:
                raise ao.OperationError(f"Row {i}: a destination group's type is DSTN_IP, DSTN_FQDN or DSTN_DOMAIN.")
        g = out.setdefault((kind, name.lower()), {"kind": kind, "name": name, "group_type": gt, "description": desc, "addresses": []})
        if g["group_type"] != gt:
            raise ao.OperationError(f"Row {i}: '{name}' is given two types.")
        if desc and not g["description"]:
            g["description"] = desc
        g["addresses"] += [a for a in (x.strip() for x in cell(r, "addresses").replace(",", ";").replace(" ", ";").split(";")) if a]
        if len(out) > MAX_IMPORT_GROUPS:
            raise ao.OperationError(f"At most {MAX_IMPORT_GROUPS} groups per import. Split it.")
    if sum(len(g["addresses"]) for g in out.values()) > MAX_ENTRIES * 4:
        raise ao.OperationError("The CSV has too many addresses for one import. Split it.")
    return list(out.values())


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    act = str(spec.get("action") or "").strip().lower()
    if act == "source_edit":
        g = spec.get("group") if isinstance(spec.get("group"), dict) else None
        if g is None:
            raise ao.OperationError("'group' must be {\"id\": ...} or {\"new\": \"name\"}.")
        add, remove = _list(spec, "add"), _list(spec, "remove")
        if not add and not remove:
            raise ao.OperationError("List at least one address to add or to remove.")
        if len(add) + len(remove) > MAX_ENTRIES:
            raise ao.OperationError(f"At most {MAX_ENTRIES:,} entries per operation. Split it.")
        if g.get("new") not in (None, ""):
            if remove:
                raise ao.OperationError("A new group has nothing to remove.")
            return {"type": TYPE, "action": act, "group": {"new": _name(g["new"]), "description": _desc(g.get("description"))}, "add": add, "remove": []}
        return {"type": TYPE, "action": act, "group": {"id": lf._oid(g.get("id"), "The group")}, "add": add, "remove": remove}
    if act == "delete":
        return {"type": TYPE, "action": act, "kind": _kind(spec.get("kind")), "id": lf._oid(spec.get("id"), "The group")}
    if act == "import":
        mode = str(spec.get("mode") or "merge").strip().lower()
        if mode not in ("merge", "replace"):
            raise ao.OperationError("The import mode is merge or replace.")
        groups = parse_csv(spec.get("csv")) if spec.get("csv") is not None else None
        if groups is None:
            raise ao.OperationError("Paste or open the CSV to import.")
        return {"type": TYPE, "action": act, "mode": mode, "groups": groups}
    if act == "revert" and spec.get("undo") is True:
        steps = []
        for s in ao._list_field(spec, "steps", objects=True, cap=MAX_IMPORT_GROUPS):
            op, kind = str(s.get("op") or ""), _kind(s.get("kind"))
            if op not in ("delete", "set", "create"):
                raise ao.OperationError(f"Unknown Undo step '{op[:20]}'.")
            st: Dict[str, Any] = {"op": op, "kind": kind, "name": _name(s.get("name")),
                                  "addresses": [str(x)[:300] for x in (s.get("addresses") or [])[:MAX_GROUP_ADDRESSES]]}
            if op in ("delete", "set"):
                st["id"] = lf._oid(s.get("id"), "The group")
            if op == "set":
                st["expect"] = sorted(str(x)[:300] for x in (s.get("expect") or [])[:MAX_GROUP_ADDRESSES])
                st["description"] = _desc(s.get("description"))
            if op == "create":
                st["description"] = _desc(s.get("description"))
                st["group_type"] = str(s.get("group_type") or "").upper() if kind == "destination" else ""
                if kind == "destination" and st["group_type"] not in DEST_TYPES:
                    raise ao.OperationError("A destination group's type is DSTN_IP, DSTN_FQDN or DSTN_DOMAIN.")
                for f in ("ip_categories", "countries"):
                    if isinstance(s.get(f), list):
                        st[f] = [str(x)[:64] for x in s[f][:500]]
            steps.append(st)
        if not steps:
            raise ao.OperationError("This Undo has no step.")
        return {"type": TYPE, "action": "revert", "undo": True, "steps": steps}
    raise ao.OperationError("Pick what to do: source_edit, delete or import.")


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _gobj(kind: str, gid: Any, name: str) -> Dict[str, Any]:
    return {"type": KINDS[kind]["pack"], "policy_label": KINDS[kind]["label"], "id": gid, "name": name, "kind": kind}


class _P:
    def __init__(self, client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]):
        self.zia, self.scope, self.say, self.cancel = client.zia, scope, say, cancel
        self.items: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.blockers: List[str] = []
        self.impact: List[Dict[str, Any]] = []
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self.n = 0
        self.deletes: List[str] = []

    def all(self, kind: str) -> List[Dict[str, Any]]:
        if kind not in self.cache:
            ao._check_stop(self.cancel)
            self.say(f"Reading the {KINDS[kind]['label']}s…")
            rows, err = read_groups(self.zia, kind)
            if err:
                raise ao.OperationError(f"The {KINDS[kind]['label']}s could not be read: {err}. Nothing was written.")
            self.cache[kind] = rows
        return self.cache[kind]

    def by_id(self, kind: str, gid: Any) -> Optional[Dict[str, Any]]:
        return next((g for g in self.all(kind) if str(g.get("id")) == str(gid)), None)

    def by_name(self, kind: str, name: str) -> Optional[Dict[str, Any]]:
        return next((g for g in self.all(kind) if str(g.get("name") or "").strip().lower() == name.strip().lower()), None)

    def key(self) -> str:
        self.n += 1
        return f"g{self.n}"

    def org_total(self) -> int:
        return sum(len(entries(g, "source")) for g in self.all("source")) + sum(len(entries(g, "destination")) for g in self.all("destination")
                                                                               if str(g.get("type") or "").upper() == "DSTN_IP")

    def create(self, kind: str, name: str, addresses: List[str], bad: List[Tuple[str, str]], *, description: str = "", group_type: str = "",
               extra: Optional[Dict[str, Any]] = None, why: str = "") -> None:
        k = self.key()
        obj = _gobj(kind, None, name)
        self.refused(obj, bad, k)
        if self.by_name(kind, name) is not None:
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", True, True, status="excluded",
                                       reason=f"a {KINDS[kind]['label']} named '{name}' exists: pick it instead"))
            return
        if len(addresses) > MAX_GROUP_ADDRESSES:
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", False, True, status="excluded",
                                       reason=f"more than {MAX_GROUP_ADDRESSES:,} addresses: split it into several groups"))
            return
        self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", False, True, value=f"{len(addresses)} entr{'y' if len(addresses) == 1 else 'ies'}",
                                   reason=why or "new group; Undo deletes it"))
        for a in addresses:
            self.items.append(ao._unit(f"{k}:+{a.lower()}", k, "address", obj, "addresses", False, True, value=a, depends_on=[k]))
        target = dict({"kind": kind, "name": name, "description": description, "addresses": addresses, "group_type": group_type}, **(extra or {}))
        self.groups.append({"key": k, "handler": "ipg_create", "target": target})

    def refused(self, obj: Dict[str, Any], bad: List[Tuple[str, str]], k: str) -> None:
        for raw, why in bad:
            self.items.append(ao._unit(f"{k}:bad:{raw}", k, "address", obj, "addresses", None, None, value=raw, status="excluded",
                                       reason=f"not changed: it {why}"))

    def set(self, kind: str, g: Dict[str, Any], want: List[str], bad: List[Tuple[str, str]], *, description: Optional[str] = None,
            expect: Optional[List[str]] = None, why: str = "") -> None:
        k = self.key()
        name = str(g.get("name") or "")
        obj = _gobj(kind, g.get("id"), name)
        self.refused(obj, bad, k)
        if locked(g):
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "addresses", None, None, status="excluded",
                                       reason="a predefined group: it cannot be changed"))
            return
        have = entries(g, kind)
        if expect is not None and sorted(have) != sorted(expect):
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "addresses", None, None, status="excluded",
                                       reason="its addresses changed since the change Undo reverses, so it is left as it is"))
            return
        hl = {a.lower() for a in have}
        wl = {a.lower() for a in want}
        add = [a for a in want if a.lower() not in hl]
        rem = [a for a in have if a.lower() not in wl]
        if len(want) > MAX_GROUP_ADDRESSES:
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "addresses", len(have), len(want), status="excluded",
                                       reason=f"would hold more than {MAX_GROUP_ADDRESSES:,} addresses"))
            return
        for a in add:
            self.items.append(ao._unit(f"{k}:+{a.lower()}", k, "address", obj, "addresses", False, True, value=a, reason=why))
        for a in rem:
            self.items.append(ao._unit(f"{k}:-{a.lower()}", k, "address", obj, "addresses", True, False, value=a, reason=why))
        desc_change = description is not None and description != str(g.get("description") or "")
        if desc_change:
            self.items.append(ao._unit(f"{k}:desc", k, KINDS[kind]["pack"], obj, "description", str(g.get("description") or ""), description))
        if not add and not rem and not desc_change:
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "addresses", len(have), len(want), status="noop", reason="already as asked"))
            return
        final = [a for a in have if a.lower() in wl] + add
        self.groups.append({"key": k, "handler": "ipg_set", "target": {"kind": kind, "id": g.get("id"), "name": name, "before": snapshot(g, kind),
                                                                        "addresses": final, "description": description if desc_change else None}})

    def delete(self, kind: str, g: Dict[str, Any], *, expect: Optional[List[str]] = None, why: str = "", check_refs: bool = True) -> None:
        k = self.key()
        name = str(g.get("name") or "")
        obj = _gobj(kind, g.get("id"), name)
        if locked(g):
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", True, False, status="excluded",
                                       reason="a predefined group: it cannot be deleted"))
            return
        if expect is not None and sorted(entries(g, kind)) != sorted(expect):
            self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", True, False, status="excluded",
                                       reason="its addresses changed since this app created it, so it is kept (someone else's change is never removed)"))
            return
        if check_refs:
            refs, rerr, out = rule_refs(self.zia, self.scope, self.say, self.cancel)
            users = refs.get((kind, str(g.get("id"))), [])
            if out:
                self.blockers.append("These policies can name an IP group but are not in scope on the Scope page, so their rules cannot be "
                                     "checked: " + ", ".join(out) + ". Tick them, read again and preview again; nothing was deleted.")
            if rerr:
                self.blockers.append("These rules could not be read, so the delete cannot be checked: " + "; ".join(rerr) + ".")
            self.impact.append({"group": name, "id": g.get("id"), "kind": kind, "rules": users,
                                "detail": (f"{len(users)} rule{'s' if len(users) != 1 else ''} use{'s' if len(users) == 1 else ''} this group: change "
                                           f"{'them' if len(users) != 1 else 'it'} first." if users else "No rule read here names this group.")})
            if users:
                self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", True, False, status="excluded",
                                           reason="still used by " + "; ".join(f"{r['policy_label']} rule {r['order']} '{r['name']}' ({r['state'].lower()})"
                                                                               for r in users[:10]) + (f" and {len(users) - 10} more" if len(users) > 10 else "")))
                return
            self.warnings.append(NOT_CHECKED)
        self.items.append(ao._unit(k, k, KINDS[kind]["pack"], obj, "exists", True, False, value=f"{len(entries(g, kind))} entries",
                                   reason=why or "its entries go with it; Undo creates it again (with a new id)"))
        self.groups.append({"key": k, "handler": "ipg_delete", "target": {"kind": kind, "id": g.get("id"), "name": name, "before": snapshot(g, kind)}})
        self.deletes.append(name)


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    P = _P(client, scope, say, cancel)
    act = n["action"]
    if act == "source_edit":
        add, bad_a = _clean(n["add"], "source")
        rem, bad_r = _clean(n["remove"], "source")
        g = n["group"]
        if "new" in g:
            P.create("source", g["new"], add, bad_a, description=g["description"])
            title = f"New IP source group '{g['new']}'"
        else:
            row = P.by_id("source", g["id"])
            if row is None:
                raise ao.OperationError(f"IP source group {g['id']} is not in this tenant now. Read the groups again.")
            have = entries(row, "source")
            rl = {a.lower() for a in rem}
            want = [a for a in have if a.lower() not in rl] + [a for a in add if a.lower() not in rl]
            P.set("source", row, want, bad_a + bad_r)
            title = f"IP source group '{row.get('name')}'"
    elif act == "delete":
        row = P.by_id(n["kind"], n["id"])
        if row is None:
            P.items.append(ao._unit("g0", "g0", KINDS[n["kind"]]["pack"], _gobj(n["kind"], n["id"], str(n["id"])), "exists", False, False,
                                    status="noop", reason="already gone"))
            title = f"Delete {KINDS[n['kind']]['label']} {n['id']}"
        else:
            P.delete(n["kind"], row)
            title = f"Delete {KINDS[n['kind']]['label']} '{row.get('name')}'"
    elif act == "import":
        for gi in n["groups"]:
            kind = gi["kind"]
            ok, bad = _clean(gi["addresses"], kind, gi["group_type"] or "DSTN_IP")
            row = P.by_name(kind, gi["name"])
            if row is None:
                P.create(kind, gi["name"], ok, bad, description=gi["description"], group_type=gi["group_type"], why="new group from the CSV; Undo deletes it")
                continue
            if kind == "destination" and str(row.get("type") or "").upper() != gi["group_type"]:
                P.items.append(ao._unit(P.key(), "", "ip_destination_group", _gobj(kind, row.get("id"), gi["name"]), "type", str(row.get("type") or ""),
                                        gi["group_type"], status="excluded", reason="the group in the tenant has another type: a type is not changed"))
                continue
            have = entries(row, kind)
            want = ok if n["mode"] == "replace" else have + [a for a in ok if a.lower() not in {h.lower() for h in have}]
            P.set(kind, row, want, bad, description=gi["description"] or None, why="from the CSV")
        title = f"Import IP groups from a CSV ({n['mode']})"
        if n["mode"] == "replace" and any(u["after"] is False and u["status"] == "change" for u in P.items):
            P.warnings.append("Replace mode removes every address of a listed group that the CSV does not list: check the removals below.")
    else:   # revert (Undo)
        for s in n["steps"]:
            if s["op"] == "create":
                extra = {f: s[f] for f in ("ip_categories", "countries") if s.get(f)}
                ok, bad = _clean(s["addresses"], s["kind"], s.get("group_type") or "DSTN_IP")
                P.create(s["kind"], s["name"], ok, bad, description=s["description"], group_type=s.get("group_type") or "", extra=extra,
                         why="created again, as it was before it was deleted (a new id)")
                continue
            row = P.by_id(s["kind"], s["id"])
            if row is None:
                P.items.append(ao._unit(P.key(), "", KINDS[s["kind"]]["pack"], _gobj(s["kind"], s["id"], s["name"]), "exists", None, None,
                                        status="noop" if s["op"] == "delete" else "excluded",
                                        reason="already gone" if s["op"] == "delete" else "the group is gone"))
                continue
            if s["op"] == "delete":
                P.delete(s["kind"], row, expect=s["addresses"], why="the group the change created", check_refs=True)
            else:
                P.set(s["kind"], row, s["addresses"], [], description=s["description"], expect=s["expect"], why="put back as it was")
        title = "Undo an IP group change"
    new_ip = sum(1 for u in P.items if u["status"] == "change" and u["kind"] == "address" and u["after"] is True
                 and (u["object"]["kind"] == "source" or lf.classify(str(u["value"]))[0] == "ip"))
    if new_ip:
        try:
            total = P.org_total()
            if total + new_ip > lf.ORG_IP_ENTRIES:
                P.warnings.append(f"The tenant would hold about {total + new_ip:,} IP entries across its source and destination groups; ZIA's "
                                  f"default organisation limit is {lf.ORG_IP_ENTRIES:,} (assumed): writes past it are refused.")
        except ao.OperationError:
            pass
    confirm = ""
    if P.deletes and act in ("delete",):
        confirm = f"DELETE {P.deletes[0]}" if len(P.deletes[0]) <= 60 else "DELETE IP GROUP"
    elif P.deletes:
        confirm = f"DELETE {len(P.deletes)} GROUP{'S' if len(P.deletes) != 1 else ''}"
    return {"type": TYPE, "product": "zia", "title": title, "spec": n, "items": P.items, "groups": P.groups, "warnings": P.warnings,
            "blockers": P.blockers, "impact": P.impact, "confirm_always": confirm,
            "notes": ["A group is sent back as read with its new address list (PUT); Undo puts every list back, deletes what was created and "
                      "creates again what was deleted."]}


# ---------------------------------------------------------------------------
# Writes (pack_ops), each right after the group is read again
# ---------------------------------------------------------------------------

def _payload(kind: str, s: Dict[str, Any], addresses: List[str], description: Optional[str]) -> Dict[str, Any]:
    body: Dict[str, Any] = {"name": s["name"], KINDS[kind]["field"]: list(addresses)}
    d = s.get("description") if description is None else description
    if d:
        body["description"] = d
    if kind == "destination":
        body["type"] = s.get("group_type") or "DSTN_IP"
        for f in ("ip_categories", "countries"):
            if s.get(f):
                body[f] = list(s[f])
    return body


def _reread(run: Any, units: List[Dict[str, Any]], t: Dict[str, Any], *, gone_ok: bool) -> Optional[Dict[str, Any]]:
    fresh, err = get_group(run.zia, t["kind"], t["id"])
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
    rows, err = read_groups(run.zia, t["kind"])
    if err:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the {KINDS[t['kind']]['label']}s")
        return
    if any(str(r.get("name") or "").strip().lower() == t["name"].lower() for r in rows):
        run.mark(units, "conflict", f"a group named '{t['name']}' was made since the preview; nothing was created")
        run.counts["skipped"] += len(units)
        return
    addrs = [u["value"] for u in units if u["kind"] == "address"]
    out = ops.create(run.zia, KINDS[t["kind"]]["pack"], _payload(t["kind"], t, addrs, None), name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.created.append({"type": KINDS[t["kind"]]["pack"], "kind": t["kind"], "id": out.id, "name": t["name"], "addresses": addrs})
        run.log(f"[{KINDS[t['kind']]['label']}] {t['name']}: created with {len(addrs)} entr{'y' if len(addrs) == 1 else 'ies'}")


def h_set(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh = _reread(run, units, t, gone_ok=False)
    if fresh is None:
        return
    if snapshot(fresh, t["kind"]) != t["before"]:
        run.mark(units, "conflict", "the group changed since the preview; left as it is")
        run.counts["skipped"] += len(units)
        return
    out = ops.update(run.zia, KINDS[t["kind"]]["pack"], t["id"], _payload(t["kind"], t["before"], t["addresses"], t.get("description")),
                     name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[{KINDS[t['kind']]['label']}] {t['name']}: now {len(t['addresses'])} entr{'y' if len(t['addresses']) == 1 else 'ies'}")


def h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh = _reread(run, units, t, gone_ok=True)
    if fresh is None:
        return
    if snapshot(fresh, t["kind"]) != t["before"]:
        run.mark(units, "conflict", "the group changed since the preview, so it is kept")
        run.counts["skipped"] += len(units)
        return
    out = ops.delete(run.zia, {"kind": KINDS[t["kind"]]["pack"], "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[{KINDS[t['kind']]['label']}] {t['name']}: deleted")


HANDLERS = {"ipg_create": h_create, "ipg_set": h_set, "ipg_delete": h_delete}


def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        units = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not units:
            continue
        t = g["target"]
        oid = t.get("id") if g["handler"] != "ipg_create" else units[0]["object"].get("id")
        row, err = get_group(run.zia, t["kind"], oid) if oid not in (None, "") else (None, "no id")
        out["checked"] += len(units)
        if g["handler"] == "ipg_delete":
            ok = row is None and not ao._read_halt(err)
        elif row is None:
            out["checked"] -= len(units)
            out["unread"].append(f"{t['name']}: {err}")
            continue
        elif g["handler"] == "ipg_set":
            ok = sorted(a.lower() for a in entries(row, t["kind"])) == sorted(a.lower() for a in t["addresses"])
        else:
            ok = str(row.get("name") or "") == t["name"] and sorted(a.lower() for a in entries(row, t["kind"])) == \
                sorted(str(u["value"]).lower() for u in units if u["kind"] == "address")
        for u in units:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(units)
        else:
            out["mismatched"].append(f"{t['name']}: not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Every created group deleted (if unchanged), every changed list put
    back, every deleted group created again: one Undo-only revert."""
    applied = {u["group"] for u in result.get("items") or [] if u.get("status") == "applied"}
    steps: List[Dict[str, Any]] = []
    for g in result.get("groups") or []:
        if g["key"] not in applied:
            continue
        t = g["target"]
        if g["handler"] == "ipg_create":
            made = next((c for c in result.get("created") or [] if c.get("kind") == t["kind"] and c.get("name") == t["name"]), None)
            if made and made.get("id") not in (None, ""):
                steps.append({"op": "delete", "kind": t["kind"], "id": made["id"], "name": t["name"], "addresses": made["addresses"]})
        elif g["handler"] == "ipg_set":
            steps.append({"op": "set", "kind": t["kind"], "id": t["id"], "name": t["name"], "addresses": t["before"]["addresses"],
                          "expect": sorted(t["addresses"]), "description": t["before"].get("description") or ""})
        else:
            b = t["before"]
            steps.append(dict({"op": "create", "kind": t["kind"], "name": b["name"], "addresses": b["addresses"], "description": b.get("description") or "",
                               "group_type": b.get("group_type") or ""}, **{f: b[f] for f in ("ip_categories", "countries") if b.get(f)}))
    return {"type": TYPE, "action": "revert", "undo": True, "steps": steps} if steps else None


ao.register(TYPE, family=FAMILY, product="zia", label="IP source and destination groups", plan=plan, read_objects=read_objects,
            in_scope=in_scope, handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT, group="Change",
            hint=("Edit an IP source group, delete a source or destination group (DELETE and its name typed; refused while a rule uses it), "
                  "or import and export groups as CSV. Undo puts everything back. Needs ZIA platform ticked on the Scope page."))
