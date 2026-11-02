"""Rules from a spreadsheet: CSV import as operation types on the Bulk
changes engine (admin_ops.register).

Two types, one per product (ZIA activates once at the end, ZPA saves each
change at once):

  zia_rules_csv   ZIA Cloud Firewall or URL filtering rules from a CSV
  zpa_access_csv  ZPA access policy rules from a CSV

The file format is rule_csv's. Planning reads the policy's rules (and the
objects a name has to resolve against, only when the rules do not already
name them) and never writes. It matches every row to a rule by name and
plans, in this order:

  delete   only when the spec says remove_missing (the page's "remove rules
           not in the file" tick): every rule of the policy that is not in
           the file (within the spec's filter, for a sync), except the
           Default, predefined and read-only rules. Any delete makes the
           typed confirmation "DELETE <n> RULES", whatever the count.
  update   the managed columns (the ones the file has) that differ.
  add      a row no rule has: ZIA rules are created DISABLED unless the spec
           says new_rules_enabled; ZPA access rules have no disabled state
           in the SDK's add_access_rule, so a new ZPA rule is only created
           when new_rules_enabled is set (the person said so), else the row
           is excluded and says why.
  move     the order column, as the fewest single-rule moves (ZIA, the
           reorder operation's algorithm) or one bulk reorder (ZPA,
           policies.bulk_reorder_rules).

A row that cannot be used (a name that resolves to nothing in the tenant,
a locked rule, a new ZPA rule without the tick) is excluded with the
reason; the rest still applies. Every write re-reads the rule first and
skips it (conflict) when it moved since the preview; the order moves check
the whole sequence before each move. Undo is a new operation of the same
type (action "undo"): it deletes what was added, puts back the fields that
were changed, re-creates what was deleted and restores the order, each
step skipped when the rule changed since.
"""
from __future__ import annotations

import json
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import admin_ops as ao
import pack_channels as pc
import pack_ops as ops
import rule_csv as rc

TYPE_ZIA = "zia_rules_csv"
TYPE_ZPA = "zpa_access_csv"
FAMILY_ZIA = "rule_csv_zia"
FAMILY_ZPA = "rule_csv_zpa"
TYPE_POLICIES = {TYPE_ZIA: ("firewall", "url_filtering"), TYPE_ZPA: ("zpa_access",)}
NEW = "new:"
MAX_EXPORT_RULES = 5000
GONE_WORDS = ("404", "not found", "not_found", "does not exist", "resource_not_found")

ZPA_NEW_NEEDS_TICK = ("ZPA access rules cannot be created disabled (the SDK's add_access_rule has no such field), so a new rule "
                      "takes effect at once: it is created only when you tick 'create new rules enabled'.")


def type_for(policy: str) -> str:
    return TYPE_ZPA if policy == "zpa_access" else TYPE_ZIA


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _gone(err: Any) -> bool:
    s = str(err or "").lower()
    return any(w in s for w in GONE_WORDS)


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)


# ---------------------------------------------------------------------------
# Reading the tenant (GET only)
# ---------------------------------------------------------------------------

_ZIA_LOOKUPS = {   # lookup -> (service, list method, paged)
    "locations": ("locations", "list_locations", True),
    "location_groups": ("locations", "list_location_groups", True),
    "departments": ("user_management", "list_departments", True),
    "groups": ("user_management", "list_groups", True),
    "labels": ("rule_labels", "list_labels", True),
    "network_services": ("cloud_firewall", "list_network_services", False),
    "network_service_groups": ("cloud_firewall", "list_network_svc_groups", False),
    "ip_source_groups": ("cloud_firewall", "list_ip_source_groups", False),
    "ip_destination_groups": ("cloud_firewall", "list_ip_destination_groups", False),
}
_ZPA_LOOKUPS = {
    "zpa_segments": ("application_segment", "list_segments"),
    "zpa_segment_groups": ("segment_groups", "list_groups"),
    "zpa_idps": ("idp", "list_idps"),
}
ZIA_PAGE = 500     # page_size for the paged ZIA lists (the SDK documents page / page_size; the maximum is assumed)
ZPA_PAGE = 500     # the largest page ZPA serves (policies.list_rules docstring)
MAX_PAGES = 40


def _zia_list(svc: Any, method: str, paged: bool) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    fn = getattr(svc, method, None) if svc is not None else None
    if fn is None:
        return [], f"the installed zscaler-sdk-python has no {method}"
    try:
        if not paged:
            return ao._rows(fn())
        out: List[Dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            rows, err = ao._rows(fn(query_params={"page": page, "page_size": ZIA_PAGE}))
            if err:
                return out, err
            out.extend(rows)
            if len(rows) < ZIA_PAGE:
                break
        return out, None
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def _zpa_list(fn: Optional[Callable[..., Any]], *args: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if fn is None:
        return [], "this sign-in has no ZPA service (ZPA needs a OneAPI API client)"
    out: List[Dict[str, Any]] = []
    try:
        for page in range(1, MAX_PAGES + 1):
            rows, err = ao._rows(fn(*args, query_params={"page": str(page), "page_size": str(ZPA_PAGE)}))
            if err:
                return out, err
            out.extend(rows)
            if len(rows) < ZPA_PAGE:
                break
        return out, None
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def _zpa(client: Any) -> Any:
    zpa = getattr(client, "zpa", None)
    if zpa is None or getattr(zpa, "policies", None) is None:
        raise _err("This sign-in has no ZPA service: ZPA needs a ZIdentity (OneAPI) API client with a ZPA role.")
    return zpa


def _rid(row: Dict[str, Any]) -> str:
    return str(pc._field(row, "id", default="") or "")


def _rname(row: Dict[str, Any]) -> str:
    return str(pc._field(row, "name", default="") or "")


def _rorder(policy: str, row: Dict[str, Any]) -> int:
    if policy == "zpa_access":
        return ao._int(pc._field(row, "rule_order", "ruleOrder"), 0)
    return ao._int(pc._field(row, "order"), 0)


def _is_default(policy: str, row: Dict[str, Any]) -> bool:
    if policy == "zpa_access":
        return _truthy(pc._field(row, "default_rule", "defaultRule", default=False))
    return ao._is_default(row)


def lock_reason(policy: str, row: Dict[str, Any]) -> Optional[str]:
    """Why a rule is never changed from a file: the Default rule,
    predefined, Zscaler-managed and read-only rules."""
    if policy == "zpa_access":
        if _is_default(policy, row):
            return "the Default rule: it is always evaluated last and is not changed here"
        if _truthy(pc._field(row, "read_only", "readOnly", default=False)) or _truthy(pc._field(row, "zscaler_managed", "zscalerManaged", default=False)):
            return "read-only or managed by Zscaler: not changed here"
        return None
    return ao.lock_reason(policy, row)


def _sort_key(policy: str, row: Dict[str, Any]) -> Tuple[int, int, str]:
    return (1 if _is_default(policy, row) else 0, _rorder(policy, row), _rid(row))


def read_rules(client: Any, policy: str, cancel: Optional[threading.Event] = None) -> List[Dict[str, Any]]:
    """The policy's rules, top first. OperationError when they cannot be read."""
    if policy == "zpa_access":
        zpa = _zpa(client)
        ao._check_stop(cancel)
        rows, err = _zpa_list(getattr(zpa.policies, "list_rules", None), "access")
    else:
        rows, err = ao.read_rules(client.zia, policy, cancel=cancel)
    if err:
        raise _err(f"The {rc.POLICIES[policy]['label']} rules could not be read, so nothing can be planned: {err}")
    return sorted(rows, key=lambda r: _sort_key(policy, r))


def get_rule(client_or_run: Any, policy: str, rid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if policy == "zpa_access":
        zpa = getattr(client_or_run, "zpa", None)
        try:
            return ao._one(zpa.policies.get_rule("access", rid))
        except Exception as e:  # noqa: BLE001
            return None, f"{type(e).__name__}: {str(e)[:200]}"
    return ao.get_rule(getattr(client_or_run, "zia", None), policy, rid)


# ---------------------------------------------------------------------------
# Names <-> ids
# ---------------------------------------------------------------------------

class Names:
    """id -> name per lookup, filled from the names the rules already carry
    and, only when a name is not among them, from one read of that list."""

    def __init__(self, client: Any, say: Callable[[str], None], cancel: Optional[threading.Event] = None):
        self.client = client
        self.say = say
        self.cancel = cancel
        self.by_id: Dict[str, Dict[str, str]] = {}
        self.loaded: Set[str] = set()
        self.errors: Dict[str, str] = {}

    def seed(self, lookup: str, oid: Any, name: Any) -> None:
        if oid in (None, "") or name in (None, ""):
            return
        self.by_id.setdefault(lookup, {}).setdefault(str(oid), str(name))

    def name_of(self, lookup: str, oid: Any) -> str:
        oid = str(oid)
        got = self.by_id.get(lookup, {}).get(oid)
        if got is not None:
            return got
        if lookup == "url_categories" and not oid.upper().startswith("CUSTOM_"):
            return oid
        if lookup not in self.loaded and lookup != "zpa_scim_groups":
            self.load(lookup)
            got = self.by_id.get(lookup, {}).get(oid)
        return got if got is not None else oid

    def load(self, lookup: str, need_idps: Sequence[str] = ()) -> None:
        if lookup in self.loaded and lookup != "zpa_scim_groups":
            return
        ao._check_stop(self.cancel)
        self.loaded.add(lookup)
        rows: List[Dict[str, Any]] = []
        err: Optional[str] = None
        if lookup in _ZIA_LOOKUPS:
            svc, method, paged = _ZIA_LOOKUPS[lookup]
            self.say(f"Reading the {lookup.replace('_', ' ')} to resolve names…")
            rows, err = _zia_list(getattr(self.client.zia, svc, None), method, paged)
        elif lookup == "url_categories":
            self.say("Reading the custom URL categories to resolve names…")
            rows, err = ao.read_categories(self.client.zia)
            for r in rows:
                self.seed(lookup, _rid(r), pc._field(r, "configured_name", "configuredName") or _rname(r))
            if err:
                self.errors[lookup] = err
            return
        elif lookup in _ZPA_LOOKUPS:
            svc, method = _ZPA_LOOKUPS[lookup]
            self.say(f"Reading the ZPA {lookup[4:].replace('_', ' ')} to resolve names…")
            rows, err = _zpa_list(getattr(getattr(_zpa(self.client), svc, None), method, None))
        elif lookup == "zpa_scim_groups":
            self.load("zpa_idps")
            for idp in need_idps:
                key = f"zpa_scim_groups:{idp}"
                if key in self.loaded:
                    continue
                self.loaded.add(key)
                self.say(f"Reading the SCIM groups of IdP {self.name_of('zpa_idps', idp)}…")
                grows, gerr = _zpa_list(getattr(getattr(_zpa(self.client), "scim_groups", None), "list_scim_groups", None), idp)
                if gerr:
                    self.errors[key] = gerr
                for g in grows:
                    self.seed(lookup, f"{idp}:{_rid(g)}", f"{self.name_of('zpa_idps', idp)}::{_rname(g)}")
            return
        if err:
            self.errors[lookup] = err
        for r in rows:
            self.seed(lookup, _rid(r), _rname(r))

    def resolve(self, lookup: str, name: str) -> Tuple[Optional[str], Optional[str]]:
        """(id, None) or (None, why)."""
        if lookup == "url_categories":
            hit = self._find(lookup, name)
            if hit is None and lookup not in self.loaded:
                self.load(lookup)
                hit = self._find(lookup, name)
            if hit is not None:
                return hit
            if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", name) and not name.startswith("CUSTOM_"):
                return name, None      # a predefined category id (ZIA refuses an unknown one; the read-back shows it)
            return None, f"no custom URL category named '{name}'"
        if lookup == "zpa_scim_groups":
            idp_name, sep, _g = name.partition("::")
            if not sep:
                return None, f"'{name}' is not IdP name::group name"
            hit = self._find(lookup, name)
            if hit is None:
                self.load("zpa_idps")
                idps = [i for i, n in self.by_id.get("zpa_idps", {}).items() if n == idp_name] or \
                       [i for i, n in self.by_id.get("zpa_idps", {}).items() if n.casefold() == idp_name.casefold()]
                if not idps:
                    return None, f"no IdP named '{idp_name}'"
                self.load(lookup, need_idps=idps)
                hit = self._find(lookup, name)
            return hit if hit is not None else (None, f"no SCIM group '{name}'")
        hit = self._find(lookup, name)
        if hit is None and lookup not in self.loaded:
            self.load(lookup)
            hit = self._find(lookup, name)
        if hit is not None:
            return hit
        why = self.errors.get(lookup)
        return None, (f"the {lookup.replace('_', ' ')} could not be read ({why})" if why
                      else f"no {lookup.replace('zpa_', '').replace('_', ' ').rstrip('s')} named '{name}'")

    def _find(self, lookup: str, name: str) -> Optional[Tuple[Optional[str], Optional[str]]]:
        table = self.by_id.get(lookup, {})
        exact = [i for i, n in table.items() if n == name]
        if len(exact) == 1:
            return exact[0], None
        if len(exact) > 1:
            return None, f"two objects are named '{name}' ({lookup.replace('_', ' ')}): rename one"
        folded = [i for i, n in table.items() if n.casefold() == name.casefold()]
        if len(folded) == 1:
            return folded[0], None
        if len(folded) > 1:
            return None, f"'{name}' matches several {lookup.replace('_', ' ')} when case is ignored: use the exact name"
        return None


# ---------------------------------------------------------------------------
# A rule's managed values (normalised) and their display
# ---------------------------------------------------------------------------

def _ref_list(v: Any) -> List[Tuple[str, str]]:
    out = []
    for x in v or []:
        if isinstance(x, dict):
            if x.get("id") is not None:
                out.append((str(x["id"]), str(x.get("name") or "")))
        elif x not in (None, ""):
            out.append((str(getattr(x, "id", x)), str(getattr(x, "name", "") or "")))
    return out


def _zia_field(row: Dict[str, Any], field: str) -> Any:
    camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), field)
    return pc._field(row, field, camel)


def seed_names(policy: str, rows: Sequence[Dict[str, Any]], names: Names) -> None:
    for row in rows:
        if policy == "zpa_access":
            for b in _blocks(row):
                for o in b["operands"]:
                    t = o["objectType"]
                    if t == "APP":
                        names.seed("zpa_segments", o["rhs"], o.get("name"))
                    elif t == "APP_GROUP":
                        names.seed("zpa_segment_groups", o["rhs"], o.get("name"))
                    elif t == "SCIM_GROUP":
                        if o.get("idp_name"):
                            names.seed("zpa_idps", o["lhs"], o["idp_name"])
                            if o.get("name"):
                                names.seed("zpa_scim_groups", f"{o['lhs']}:{o['rhs']}", f"{o['idp_name']}::{o['name']}")
            continue
        for c in rc.columns(policy):
            if c["kind"] == "refs" and c["lookup"] != "url_categories":
                for oid, nm in _ref_list(_zia_field(row, c["field"])):
                    names.seed(c["lookup"], oid, nm)


def norm_value(policy: str, col: Dict[str, Any], row: Dict[str, Any], z: Optional[Dict[str, Any]] = None) -> Any:
    """The rule's value for one column, normalised for comparison."""
    kind, field = col["kind"], col["field"]
    if policy == "zpa_access":
        z = z or zpa_conditions(row)
        if kind == "order":
            return _rorder(policy, row)
        if field in rc.ZPA_FAMILIES:
            return sorted(z["values"][field])
        if kind == "enum":
            return str(pc._field(row, "action", default="") or "").upper() or None
        return str(pc._field(row, field, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), field), default="") or "")
    v = _zia_field(row, field)
    if kind == "order":
        return _rorder(policy, row)
    if kind == "rank":
        return ao._int(v, 7) if v not in (None, "") else None
    if kind == "state":
        return ao._state(row)
    if kind == "enum":
        if isinstance(v, dict):
            v = v.get("type")
        return str(v or "").upper() or None
    if kind == "bool":
        return _truthy(v)
    if kind == "text":
        return str(v or "")
    if kind == "list":
        return sorted(str(x) for x in (v or []) if str(x))
    if kind == "refs":
        if col["lookup"] == "url_categories":
            return sorted(str(x) for x in (v or []) if str(x))
        return sorted(oid for oid, _n in _ref_list(v))
    return v


def display(policy: str, col: Dict[str, Any], value: Any, names: Names) -> str:
    if value is None:
        return ""
    if col["kind"] == "refs":
        return rc.join_list(sorted(names.name_of(col["lookup"], x) for x in value))
    if isinstance(value, list):
        return rc.join_list(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# ── ZPA conditions: AND of OR blocks ──

def _operand(o: Any) -> Dict[str, Any]:
    g = lambda k: pc._field(o, k, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k))  # noqa: E731
    return {"objectType": str(g("object_type") or "").upper(), "lhs": str(g("lhs") or ""), "rhs": str(g("rhs") or ""),
            "name": g("name"), "idp_id": g("idp_id"), "idp_name": g("idp_name")}


def _blocks(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for c in pc._field(row, "conditions", default=[]) or []:
        if not isinstance(c, dict):
            c = pc._obj_to_dict(c) if hasattr(pc, "_obj_to_dict") else {}
        ops_ = [_operand(o) for o in (pc._field(c, "operands", default=[]) or [])]
        out.append({"operator": str(pc._field(c, "operator", default="OR") or "OR").upper(), "negated": _truthy(pc._field(c, "negated", default=False)),
                    "operands": ops_})
    return out


def _family(t: str) -> str:
    return "APP" if t in ("APP", "APP_GROUP") else t


def _clean_block(b: Dict[str, Any]) -> Dict[str, Any]:
    """A block as a write sends it back: operator, negated and operands
    (objectType, lhs, rhs, idp_id when present), no ids or display names."""
    ops_ = []
    for o in b["operands"]:
        x = {"objectType": o["objectType"], "lhs": o["lhs"], "rhs": o["rhs"]}
        if o.get("idp_id"):
            x["idp_id"] = str(o["idp_id"])
        ops_.append(x)
    ops_.sort(key=lambda x: (x["objectType"], x["lhs"], x["rhs"]))
    return {"operator": b["operator"], "negated": b["negated"], "operands": ops_}


def zpa_conditions(row: Dict[str, Any]) -> Dict[str, Any]:
    """{values: {APP, APP_GROUP, CLIENT_TYPE, SCIM_GROUP: [...]}, locked:
    families the file cannot change (they also appear in a block it cannot
    express), other: the blocks kept as they are, text: those in words}."""
    blocks = _blocks(row)
    count: Dict[str, int] = {}
    simple: List[Tuple[str, Dict[str, Any]]] = []
    other: List[Dict[str, Any]] = []
    locked: Set[str] = set()
    for b in blocks:
        fams = {_family(o["objectType"]) for o in b["operands"]}
        if (not b["negated"] and len(fams) == 1 and fams <= {"APP", "CLIENT_TYPE", "SCIM_GROUP"}
                and (b["operator"] == "OR" or len(b["operands"]) <= 1)):
            fam = next(iter(fams))
            count[fam] = count.get(fam, 0) + 1
            simple.append((fam, b))
        else:
            other.append(b)
            locked |= {f for f in fams if f in ("APP", "CLIENT_TYPE", "SCIM_GROUP")}
    values: Dict[str, List[str]] = {f: [] for f in rc.ZPA_FAMILIES}
    for fam, b in simple:
        if count.get(fam, 0) > 1 or fam in locked:
            other.append(b)
            locked.add(fam)
            continue
        for o in b["operands"]:
            t = o["objectType"]
            if t == "SCIM_GROUP":
                values[t].append(f"{o['lhs']}:{o['rhs']}")
            elif t == "CLIENT_TYPE":
                values[t].append(o["rhs"].lower())
            else:
                values[t].append(o["rhs"])
    locked_cols = set()
    for f in locked:
        locked_cols |= ({"APP", "APP_GROUP"} if f == "APP" else {f})
    return {"values": values, "locked": locked_cols, "other": [_clean_block(b) for b in other], "text": _other_text(other)}


def _other_text(blocks: Sequence[Dict[str, Any]]) -> str:
    parts = []
    for b in blocks:
        joiner = f" {b['operator']} "
        inner = joiner.join(f"{o['objectType']} {o.get('name') or (o['lhs'] + '=' + o['rhs'] if o['lhs'] not in ('', 'id') else o['rhs'])}"
                            for o in b["operands"])
        parts.append(("NOT " if b["negated"] else "") + f"({inner})")
    return " AND ".join(parts)[:1000]


def zpa_build_conditions(other: Sequence[Dict[str, Any]], values: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    blocks = [dict(b, operands=list(b["operands"])) for b in other]
    app = [{"objectType": "APP", "lhs": "id", "rhs": v} for v in values.get("APP") or []] + \
          [{"objectType": "APP_GROUP", "lhs": "id", "rhs": v} for v in values.get("APP_GROUP") or []]
    if app:
        blocks.append({"operator": "OR", "negated": False, "operands": app})
    ct = [{"objectType": "CLIENT_TYPE", "lhs": "id", "rhs": v} for v in values.get("CLIENT_TYPE") or []]
    if ct:
        blocks.append({"operator": "OR", "negated": False, "operands": ct})
    sg = []
    for v in values.get("SCIM_GROUP") or []:
        idp, _s, gid = str(v).partition(":")
        sg.append({"objectType": "SCIM_GROUP", "lhs": idp, "rhs": gid})
    if sg:
        blocks.append({"operator": "OR", "negated": False, "operands": sg})
    return blocks


def _zpa_refs(row: Dict[str, Any], field: str) -> List[str]:
    return [oid for oid, _n in _ref_list(pc._field(row, field, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), field), default=[]))]


def zpa_payload(row_or_vals: Dict[str, Any], *, name: str, action: str, description: str, custom_msg: str,
                conditions: List[Dict[str, Any]], connector_groups: Sequence[str] = (), server_groups: Sequence[str] = ()) -> Dict[str, Any]:
    """An access rule as add_access_rule / update_access_rule take it. The
    SDK builds the PUT body from these keys only (a PUT replaces the rule),
    so everything the rule keeps is sent: description, message, the
    conditions and the App Connector and server groups."""
    return {"name": name, "action": action, "description": description, "custom_msg": custom_msg, "conditions": conditions,
            "app_connector_group_ids": list(connector_groups), "app_server_group_ids": list(server_groups)}


def _zpa_update_payload(fresh: Dict[str, Any], z: Dict[str, Any], set_vals: Dict[str, Any]) -> Dict[str, Any]:
    values = {f: list(z["values"][f]) for f in rc.ZPA_FAMILIES}
    for col, v in set_vals.items():
        if col in ("app_segments", "segment_groups", "client_types", "scim_groups"):
            values[{"app_segments": "APP", "segment_groups": "APP_GROUP", "client_types": "CLIENT_TYPE", "scim_groups": "SCIM_GROUP"}[col]] = list(v)
    g = lambda k: set_vals[k] if k in set_vals else None  # noqa: E731
    return zpa_payload(fresh, name=_rname(fresh), action=(g("action") or str(pc._field(fresh, "action", default="") or "")).upper(),
                       description=g("description") if "description" in set_vals else str(pc._field(fresh, "description", default="") or ""),
                       custom_msg=g("custom_msg") if "custom_msg" in set_vals else str(pc._field(fresh, "custom_msg", "customMsg", default="") or ""),
                       conditions=zpa_build_conditions(z["other"], values),
                       connector_groups=_zpa_refs(fresh, "app_connector_groups"), server_groups=_zpa_refs(fresh, "app_server_groups"))


def _restore_body(policy: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """What re-creates a deleted rule on Undo: the rule as it was read."""
    if policy == "zpa_access":
        z = zpa_conditions(row)
        conds = zpa_build_conditions(z["other"], z["values"])
        return zpa_payload(row, name=_rname(row), action=str(pc._field(row, "action", default="") or "").upper(),
                           description=str(pc._field(row, "description", default="") or ""),
                           custom_msg=str(pc._field(row, "custom_msg", "customMsg", default="") or ""), conditions=conds,
                           connector_groups=_zpa_refs(row, "app_connector_groups"), server_groups=_zpa_refs(row, "app_server_groups"))
    body = ao._body(row)
    for k in ("id", "order", "default_rule", "predefined", "access_control", "last_modified_time", "last_modified_by"):
        body.pop(k, None)
    return body


# ---------------------------------------------------------------------------
# Export (rules -> rows) — the CSV download and a sync's source snapshot
# ---------------------------------------------------------------------------

def export_rows(policy: str, rules: Sequence[Dict[str, Any]], names: Names) -> List[Dict[str, Any]]:
    """Every rule as a CSV row (names, not ids), top first."""
    seed_names(policy, rules, names)
    out = []
    for r in list(rules)[:MAX_EXPORT_RULES]:
        z = zpa_conditions(r) if policy == "zpa_access" else None
        row: Dict[str, Any] = {}
        for c in rc.columns(policy):
            if c["kind"] == "readonly":
                row[c["name"]] = z["text"] if z else ""
                continue
            v = norm_value(policy, c, r, z)
            if c["kind"] == "refs":
                if c["name"] == "scim_groups":
                    idps = sorted({x.split(":", 1)[0] for x in v})
                    if any(names.by_id.get("zpa_scim_groups", {}).get(x) is None for x in v) and idps:
                        names.load("zpa_scim_groups", need_idps=idps)
                row[c["name"]] = sorted(names.name_of(c["lookup"], x) for x in v)
            elif c["kind"] == "order":
                row[c["name"]] = v if v else ""
            elif c["kind"] == "rank":
                row[c["name"]] = "" if v is None else v
            else:
                row[c["name"]] = v if v is not None else ""
        row["name"] = _rname(r)
        out.append(row)
    return out


def export_csv(client: Any, policy: str, *, say: Callable[[str], None] = lambda m: None,
               cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read one policy (read-only) and return {policy, rules, csv, errors}."""
    rules = read_rules(client, policy, cancel)
    names = Names(client, say, cancel)
    rows = export_rows(policy, rules, names)
    return {"policy": policy, "label": rc.POLICIES[policy]["label"], "rules": len(rows), "csv": rc.to_csv(policy, rows),
            "errors": dict(names.errors), "truncated": len(rules) > MAX_EXPORT_RULES}


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _ref(policy: str, row: Optional[Dict[str, Any]], name: str = "", rid: Any = None) -> Dict[str, Any]:
    return {"type": "rule", "policy": policy, "policy_label": rc.POLICIES[policy]["label"],
            "id": (_rid(row) if row else None) or (str(rid) if rid not in (None, "") else None), "name": _rname(row) if row else name}


def _filter_match(policy: str, row: Dict[str, Any], flt: Dict[str, Any], names: Names) -> bool:
    """A sync's selection: the rule carries the label (ZIA) and/or its name starts with the prefix."""
    prefix, label = str(flt.get("prefix") or ""), str(flt.get("label") or "")
    if prefix and not _rname(row).startswith(prefix):
        return False
    if label:
        if policy == "zpa_access":
            return False
        got = {names.name_of("labels", oid).casefold() for oid in norm_value(policy, {"kind": "refs", "field": "labels", "lookup": "labels"}, row)}
        return label.casefold() in got
    return True


class _P:
    """The prepared operation being built."""

    def __init__(self, policy: str):
        self.policy = policy
        self.items: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.blockers: List[str] = []

    def unit(self, key: str, kind: str, obj: Dict[str, Any], field: str, before: Any, after: Any, *, status: str = "change",
             reason: str = "", value: Any = None, handler: str = "", target: Optional[Dict[str, Any]] = None,
             depends_on: Sequence[str] = ()) -> None:
        self.items.append(ao._unit(key, key, kind, obj, field, before, after, value=value, status=status, reason=reason, depends_on=depends_on))
        if status == "change" and handler:
            self.groups.append({"key": key, "handler": handler, "target": dict(target or {}, policy=self.policy)})


def _resolve_row(policy: str, vals: Dict[str, Any], managed: Sequence[str], names: Names) -> Tuple[Dict[str, Any], List[str]]:
    """The row's managed values, normalised (names -> ids); and the problems."""
    cols = {c["name"]: c for c in rc.columns(policy)}
    out: Dict[str, Any] = {}
    problems: List[str] = []
    for n in managed:
        c = cols[n]
        v = vals.get(n)
        if c["kind"] == "name":
            continue
        if c["kind"] == "refs":
            ids = []
            for x in v or []:
                oid, why = names.resolve(c["lookup"], x)
                if oid is None:
                    problems.append(f"{n}: {why}")
                else:
                    ids.append(str(oid))
            out[n] = sorted(set(ids))
        elif c["kind"] == "list":
            out[n] = sorted(v or [])
        elif c["kind"] == "text":
            out[n] = str(v or "")
        else:
            out[n] = v
    return out, problems


def _api_value(policy: str, col: Dict[str, Any], v: Any) -> Any:
    if col["kind"] == "refs" and policy != "zpa_access" and col["lookup"] != "url_categories":
        return [int(x) if str(x).isdigit() else x for x in v]
    return v


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: Callable[[str], None],
         cancel: Optional[threading.Event]) -> Dict[str, Any]:
    t = str(spec.get("type") or "")
    policy = str(spec.get("policy") or "")
    if policy not in TYPE_POLICIES.get(t, ()):
        raise _err(f"Pick the policy: {', '.join(rc.POLICIES[p]['label'] for p in TYPE_POLICIES.get(t, ()))}.")
    if ao.is_undo_only(spec):
        return _plan_undo(client, t, policy, spec, say, cancel)
    try:
        parsed = rc.parse(spec.get("csv"), policy)
    except rc.CsvError as e:
        detail = "; ".join(f"line {p['line']}{' ' + p['column'] if p['column'] else ''}: {p['message']}" for p in e.problems[:8])
        raise _err(f"{e}{' ' + detail if detail else ''}") from None
    flt = spec.get("filter") if isinstance(spec.get("filter"), dict) else {}
    flt = {"label": str(flt.get("label") or "")[:128], "prefix": str(flt.get("prefix") or "")[:128]}
    remove_missing = spec.get("remove_missing") is True
    new_enabled = spec.get("new_rules_enabled") is True
    nspec = {"type": t, "policy": policy, "csv": spec.get("csv"), "remove_missing": remove_missing, "new_rules_enabled": new_enabled,
             "filter": flt}
    label = rc.POLICIES[policy]["label"]
    say(f"Reading the {label} rules…")
    rules = read_rules(client, policy, cancel)
    names = Names(client, say, cancel)
    seed_names(policy, rules, names)
    P = _P(policy)
    cols = {c["name"]: c for c in rc.columns(policy)}
    managed = parsed["columns"]
    by_key: Dict[str, List[Dict[str, Any]]] = {}
    for r in rules:
        by_key.setdefault(rc.name_key(_rname(r)).casefold(), []).append(r)
    in_file: Set[str] = set()
    creates: List[Dict[str, Any]] = []
    wanted_order: Dict[str, Tuple[int, int]] = {}    # rule id or NEW+name -> (order, line)
    for row in parsed["rows"]:
        ao._check_stop(cancel)
        vals = row["values"]
        name = vals["name"]
        key = rc.name_key(name).casefold()
        matches = by_key.get(key) or []
        exact = [r for r in matches if rc.name_key(_rname(r)) == rc.name_key(name)]
        matches = exact or matches
        desired, problems = _resolve_row(policy, vals, managed, names)
        if len(matches) > 1:
            in_file.update(_rid(r) for r in matches)
            P.unit(f"row:{row['line']}", "rule_update", _ref(policy, None, name), "rule", None, None, status="excluded",
                   reason=f"line {row['line']}: {len(matches)} rules are named '{name}': rename them in the portal so each name is used once")
            continue
        if matches:
            cur = matches[0]
            in_file.add(_rid(cur))
            if isinstance(vals.get("order"), int):
                wanted_order[_rid(cur)] = (vals["order"], row["line"])
            _plan_update(P, policy, cur, desired, problems, cols, names, row["line"])
        else:
            if isinstance(vals.get("order"), int):
                wanted_order[NEW + rc.name_key(name)] = (vals["order"], row["line"])
            creates.append({"row": row, "desired": desired, "problems": problems})
    deletes: List[Dict[str, Any]] = []
    if remove_missing:
        for r in rules:
            if _rid(r) in in_file or (flt["label"] or flt["prefix"]) and not _filter_match(policy, r, flt, names):
                continue
            why = lock_reason(policy, r)
            if why:
                continue
            deletes.append(r)
    _plan_deletes(P, policy, deletes, cols, names)
    created = _plan_creates(P, policy, creates, cols, names, rules, new_enabled, managed)
    _plan_order(P, policy, rules, deletes, created, wanted_order, explicit=bool(wanted_order))
    n_del = sum(1 for u in P.items if u["kind"] == "rule_delete" and u["status"] == "change")
    if remove_missing and not n_del:
        P.warnings.append("Remove rules not in the file is ticked, but every rule of the policy is in the file (or locked): nothing is deleted.")
    for k, v in names.errors.items():
        P.warnings.append(f"Could not read {k.replace('_', ' ')}: {v}")
    counts = {k: sum(1 for u in P.items if u["kind"] == k and u["status"] == "change") for k in ("rule_add", "rule_update", "rule_delete", "rule_move")}
    title = (f"{label} from a file: {counts['rule_add']} to add, {counts['rule_update']} to update, {counts['rule_move']} to move, "
             f"{counts['rule_delete']} to delete")
    out = {"type": t, "spec": nspec, "product": rc.POLICIES[policy]["product"], "items": P.items, "groups": P.groups, "warnings": P.warnings,
           "blockers": P.blockers, "title": title, "csv_counts": counts, "rows_in_file": len(parsed["rows"]),
           "notes": ["Rows are matched to rules by name. Columns the file does not have are kept as they are."],
           "sequence_before": [x for x in _movable_sequence(policy, rules)[0] if x not in _movable_sequence(policy, rules)[1]]}
    if n_del:
        out["confirm_always"] = f"DELETE {n_del} RULES"
    if policy == "zpa_access":
        out["apply_note"] = "ZPA applies each change as it is saved; there is no activation step."
    return out


def _plan_update(P: _P, policy: str, cur: Dict[str, Any], desired: Dict[str, Any], problems: List[str], cols: Dict[str, Dict[str, Any]],
                 names: Names, line: int) -> None:
    rid = _rid(cur)
    ref = _ref(policy, cur)
    key = f"upd:{rid}"
    if problems:
        P.unit(key, "rule_update", ref, "fields", None, None, status="excluded", reason=f"line {line}: " + "; ".join(problems[:5]))
        return
    z = zpa_conditions(cur) if policy == "zpa_access" else None
    changed: Dict[str, Any] = {}
    expect: Dict[str, Any] = {}
    for n, want in desired.items():
        c = cols[n]
        if c["kind"] == "order" or (want is None and c["kind"] in ("rank", "state", "enum", "bool")):
            continue
        have = norm_value(policy, c, cur, z)
        if _canon(have) != _canon(want):
            changed[n], expect[n] = want, have
    if not changed:
        P.unit(key, "rule_update", ref, "fields", None, None, status="noop", reason="already as in the file")
        return
    before = {n: display(policy, cols[n], expect[n], names) for n in changed}
    after = {n: display(policy, cols[n], changed[n], names) for n in changed}
    locked = lock_reason(policy, cur)
    if locked:
        P.unit(key, "rule_update", ref, "fields", before, after, value=sorted(changed), status="excluded", reason=locked)
        return
    if z is not None:
        blocked = sorted({n for n in changed if cols[n]["field"] in z["locked"]})
        if blocked:
            P.unit(key, "rule_update", ref, "fields", before, after, value=sorted(changed), status="excluded",
                   reason=f"{', '.join(blocked)}: the rule's conditions also use these in a way the file cannot express ({z['text'][:200]}); change it in the ZPA portal")
            return
        expect["_other"] = z["other"]
    P.unit(key, "rule_update", ref, "fields", before, after, value=sorted(changed), handler="rcsv_update",
           target={"id": rid, "name": _rname(cur), "set": changed, "expect": expect})


def _plan_deletes(P: _P, policy: str, deletes: Sequence[Dict[str, Any]], cols: Dict[str, Dict[str, Any]], names: Names) -> None:
    for r in deletes:
        z = zpa_conditions(r) if policy == "zpa_access" else None
        expect = {n: norm_value(policy, c, r, z) for n, c in cols.items() if c["kind"] not in ("name", "readonly", "order")}
        if z is not None:
            expect["_other"] = z["other"]
        shown = {n: display(policy, cols[n], v, names) for n, v in expect.items() if not n.startswith("_") and v not in (None, "", [])}
        P.unit(f"del:{_rid(r)}", "rule_delete", _ref(policy, r), "rule", shown, None, handler="rcsv_delete",
               reason="not in the file, and 'remove rules not in the file' is ticked",
               target={"id": _rid(r), "name": _rname(r), "expect": expect, "restore_body": _restore_body(policy, r)})


def _plan_creates(P: _P, policy: str, creates: Sequence[Dict[str, Any]], cols: Dict[str, Dict[str, Any]], names: Names,
                  rules: Sequence[Dict[str, Any]], new_enabled: bool, managed: Sequence[str]) -> List[str]:
    """The add units; returns the placeholders of the rules that will exist."""
    made: List[str] = []
    name_max = rc.POLICIES[policy]["name_max"]
    for c in creates:
        vals, desired = c["row"]["values"], dict(c["desired"])
        name, line = vals["name"], c["row"]["line"]
        ph = NEW + rc.name_key(name)
        key = f"add:{rc.name_key(name)}"
        ref = _ref(policy, None, name)
        why = "; ".join(c["problems"][:5])
        if not why and len(name) > name_max:
            why = f"a new {rc.POLICIES[policy]['label']} rule's name is at most {name_max} characters"
        missing = [n for n, col in cols.items() if col["required_new"] and not desired.get(n)]
        if not why and missing:
            why = f"a new rule needs {', '.join(missing)}"
        if not why and policy == "zpa_access" and not new_enabled:
            why = ZPA_NEW_NEEDS_TICK
        shown = {n: display(policy, cols[n], v, names) for n, v in desired.items() if v not in (None, "", []) and cols[n]["kind"] != "order"}
        if why:
            P.unit(key, "rule_add", ref, "rule", None, shown, status="excluded", reason=f"line {line}: {why}")
            continue
        if policy != "zpa_access":
            asked = desired.get("state") or "ENABLED"
            desired["state"] = asked if new_enabled else "DISABLED"
            shown["state"] = desired["state"]
            if desired.get("rank") is None:
                desired["rank"] = 7
            if policy == "url_filtering" and not desired.get("protocols"):
                desired["protocols"] = ["ANY_RULE"]
        note = ("created DISABLED: tick 'create new rules enabled' to create it as the file says"
                if policy != "zpa_access" and not new_enabled else "new rule")
        P.unit(key, "rule_add", ref, "rule", None, shown, reason=note, handler="rcsv_create",
               target={"name": name, "placeholder": ph, "values": {k: v for k, v in desired.items() if k != "order"}})
        made.append(ph)
    return made


def _movable_sequence(policy: str, rules: Sequence[Dict[str, Any]]) -> Tuple[List[str], Set[str]]:
    seq = [_rid(r) for r in rules]
    locked = {_rid(r) for r in rules if lock_reason(policy, r) or _is_default(policy, r)}
    return seq, locked


def _sim_after(policy: str, rules: Sequence[Dict[str, Any]], deleted: Set[str], created: Sequence[str]) -> Tuple[List[str], Set[str]]:
    """The policy's sequence once the deletes and adds are done: a new rule
    is added after the last rule that is not the Default rule (assumed: ZIA
    and ZPA put a new rule at the bottom, above the Default rule)."""
    seq, locked = _movable_sequence(policy, rules)
    seq = [x for x in seq if x not in deleted]
    by_id = {_rid(r): r for r in rules}
    tail = [x for x in seq if x in by_id and _is_default(policy, by_id[x])]
    head = [x for x in seq if x not in tail]
    return head + list(created) + tail, locked


def _plan_order(P: _P, policy: str, rules: Sequence[Dict[str, Any]], deletes: Sequence[Dict[str, Any]], created: Sequence[str],
                wanted: Dict[str, Tuple[int, int]], *, explicit: bool, desired_override: Optional[List[str]] = None) -> None:
    """The moves that give the file's order (or `desired_override`, an
    Undo's recorded order)."""
    if not explicit and desired_override is None:
        return
    deleted = {_rid(r) for r in deletes}
    sim, locked = _sim_after(policy, rules, deleted, created)
    movable = [x for x in sim if x not in locked]
    if desired_override is not None:
        if sorted(desired_override) != sorted(movable):
            P.warnings.append("The rule order is not put back: rules were added or removed in the tenant since, so the earlier order "
                              "no longer lists exactly the rules there are. Reorder them in Bulk changes if needed.")
            return
        desired_movable = list(desired_override)
    else:
        by_id0 = {_rid(r): r for r in rules}
        keyed = []
        for i, x in enumerate(movable):
            if x in wanted:
                o, line = wanted[x]
                keyed.append(((o, 0, line), x))
            elif x in by_id0:       # not in the file (or no order given): keeps its order number
                keyed.append(((_rorder(policy, by_id0[x]), 1, i), x))
            else:                   # a new rule with no order: the bottom
                keyed.append(((10 ** 9, 1, i), x))
        desired_movable = [x for _k, x in sorted(keyed)]
    it = iter(desired_movable)
    desired = [x if x in locked else next(it) for x in sim]
    by_id = {_rid(r): r for r in rules}
    label_of = lambda x: (x[len(NEW):] if x.startswith(NEW) else _rname(by_id[x]) if x in by_id else x)  # noqa: E731
    P_before = [{"id": x, "name": label_of(x)} for x in sim]
    if desired == sim:
        return
    if policy == "zpa_access":
        key = "order:zpa_access"
        P.unit(key, "rule_move", {"type": "policy", "policy": policy, "policy_label": rc.POLICIES[policy]["label"], "id": None,
                                  "name": "Access policy order"}, "order",
               [label_of(x) for x in sim], [label_of(x) for x in desired], handler="rcsv_zpa_order",
               reason=f"{sum(1 for a, b in zip(sim, desired) if a != b)} positions change (one bulk reorder)",
               target={"expect_before": sim, "desired": desired, "sequence": P_before})
        return
    steps = ao.minimal_moves(sim, desired, locked)
    if deletes or created:
        slots = list(range(1, len(sim) + 1))    # assumed: after an add or a delete ZIA numbers its rules 1..n again, top first
    else:
        slots = [_rorder(policy, by_id[x]) for x in sim]   # the order numbers as they are (the reorder operation's way)
    pos_after = {x: i for i, x in enumerate(desired)}
    prev = None
    for s_ in steps:
        x = s_["id"]
        at = pos_after[x]
        before_name = label_of(desired[at - 1]) if at > 0 else None
        key = f"move:{x}"
        P.unit(key, "rule_move", _ref(policy, by_id.get(x), label_of(x), rid=None if x.startswith(NEW) else x), "order",
               sim.index(x) + 1, at + 1, handler="rcsv_zia_order",
               reason=f"moves to just below '{before_name}'" if before_name else "moves to the top", depends_on=[prev] if prev else [],
               target={"id": x, "name": label_of(x), "send_order": slots[s_["index"]], "expect_before": s_["before"],
                       "expect_after": s_["after"]})
        prev = key


# ── Undo ──

def _plan_undo(client: Any, t: str, policy: str, spec: Dict[str, Any], say: Callable[[str], None],
               cancel: Optional[threading.Event]) -> Dict[str, Any]:
    label = rc.POLICIES[policy]["label"]
    say(f"Reading the {label} rules to plan the Undo…")
    rules = read_rules(client, policy, cancel)
    by_id = {_rid(r): r for r in rules}
    names = Names(client, say, cancel)
    seed_names(policy, rules, names)
    cols = {c["name"]: c for c in rc.columns(policy)}
    P = _P(policy)
    deleted: List[Dict[str, Any]] = []
    for d in ao._list_field(spec, "deletes", objects=True, cap=rc.MAX_ROWS):
        rid = str(d.get("id") or "")
        row = by_id.get(rid)
        ref = _ref(policy, row, str(d.get("name") or ""), rid=rid)
        key = f"del:{rid}"
        if row is None:
            P.unit(key, "rule_delete", ref, "rule", None, None, status="noop", reason="already gone")
            continue
        z = zpa_conditions(row) if policy == "zpa_access" else None
        expect = d.get("expect") or {}
        now = {n: (z["other"] if n == "_other" else norm_value(policy, cols[n], row, z)) for n in expect if n == "_other" or n in cols}
        if _canon(now) != _canon(expect) or _rname(row) != str(d.get("name") or ""):
            P.unit(key, "rule_delete", ref, "rule", None, None, status="excluded",
                   reason="changed in the tenant since it was added, so the Undo leaves it as it is")
            continue
        P.unit(key, "rule_delete", ref, "rule", {"name": _rname(row)}, None, handler="rcsv_delete", reason="added by the change being undone",
               target={"id": rid, "name": _rname(row), "expect": expect, "restore_body": _restore_body(policy, row)})
        deleted.append(row)
    for u in ao._list_field(spec, "updates", objects=True, cap=rc.MAX_ROWS):
        rid = str(u.get("id") or "")
        row = by_id.get(rid)
        ref = _ref(policy, row, str(u.get("name") or ""), rid=rid)
        key = f"upd:{rid}"
        want, expect = dict(u.get("set") or {}), dict(u.get("expect") or {})
        if row is None:
            P.unit(key, "rule_update", ref, "fields", None, None, status="excluded", reason="no longer in the tenant")
            continue
        z = zpa_conditions(row) if policy == "zpa_access" else None
        now = {n: (z["other"] if n == "_other" else norm_value(policy, cols[n], row, z)) for n in set(want) | set(expect) if n == "_other" or n in cols}
        want_cols = {n: v for n, v in want.items() if n in cols}
        shown_before = {n: display(policy, cols[n], now.get(n), names) for n in want_cols}
        shown_after = {n: display(policy, cols[n], v, names) for n, v in want_cols.items()}
        if all(_canon(now.get(n)) == _canon(v) for n, v in want_cols.items()):
            P.unit(key, "rule_update", ref, "fields", shown_before, shown_after, value=sorted(want_cols), status="noop", reason="already as before")
            continue
        if any(_canon(now.get(n)) != _canon(v) for n, v in expect.items()):
            P.unit(key, "rule_update", ref, "fields", shown_before, shown_after, value=sorted(want_cols), status="excluded",
                   reason="changed in the tenant since the change, so the Undo leaves it as it is")
            continue
        P.unit(key, "rule_update", ref, "fields", shown_before, shown_after, value=sorted(want_cols), handler="rcsv_update",
               reason="put back as it was", target={"id": rid, "name": _rname(row), "set": want_cols, "expect": expect})
    made: List[str] = []
    taken = {rc.name_key(_rname(r)).casefold() for r in rules if _rid(r) not in {_rid(d) for d in deleted}}
    for c in ao._list_field(spec, "creates", objects=True, cap=rc.MAX_ROWS):
        name = str(c.get("name") or "")
        ref = _ref(policy, None, name)
        key = f"add:{rc.name_key(name)}"
        if not isinstance(c.get("body"), dict) or not name:
            P.unit(key, "rule_add", ref, "rule", None, None, status="excluded", reason="nothing recorded to re-create it from")
            continue
        if rc.name_key(name).casefold() in taken:
            P.unit(key, "rule_add", ref, "rule", None, {"name": name}, status="excluded",
                   reason=f"a rule named '{name}' exists again, so it is not re-created")
            continue
        P.unit(key, "rule_add", ref, "rule", None, {"name": name}, handler="rcsv_create", reason="deleted by the change being undone: re-created as it was",
               target={"name": name, "placeholder": NEW + rc.name_key(name), "body": c["body"]})
        made.append(NEW + rc.name_key(name))
    order = spec.get("order")
    if isinstance(order, list) and order:
        _plan_order(P, policy, rules, deleted, made, {}, explicit=False, desired_override=[str(x) for x in order][:rc.MAX_ROWS * 2])
    nspec = {k: spec.get(k) for k in ("type", "policy", "action", "undo", "deletes", "updates", "creates", "order") if k in spec}
    out = {"type": t, "spec": nspec, "product": rc.POLICIES[policy]["product"], "items": P.items, "groups": P.groups, "warnings": P.warnings,
           "blockers": P.blockers, "title": f"Undo a {label} file import"}
    if policy == "zpa_access":
        out["apply_note"] = "ZPA applies each change as it is saved; there is no activation step."
    return out


# ---------------------------------------------------------------------------
# Writes (each re-reads first)
# ---------------------------------------------------------------------------

def _halt_or_fail(run: Any, units: List[Dict[str, Any]], err: Any, what: str) -> None:
    run.halt = ao._read_halt(err)
    if run.halt:
        run.mark(units, "skipped", f"not attempted: {run.halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def _now_values(policy: str, row: Dict[str, Any], keys: Sequence[str]) -> Dict[str, Any]:
    cols = {c["name"]: c for c in rc.columns(policy)}
    z = zpa_conditions(row) if policy == "zpa_access" else None
    return {n: (z["other"] if n == "_other" and z else norm_value(policy, cols[n], row, z)) for n in keys if n == "_other" or n in cols}


def _h_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    policy = t["policy"]
    fresh, err = get_rule(run, policy, t["id"])
    if fresh is None:
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    now = _now_values(policy, fresh, list(t["expect"]))
    if _canon(now) != _canon(t["expect"]):
        run.mark(units, "conflict", "changed in the tenant since the preview; left as it is")
        run.log(f"[{rc.POLICIES[policy]['label']}] {t['name']}: conflict — changed since the preview; skipped")
        return
    cols = {c["name"]: c for c in rc.columns(policy)}
    if policy == "zpa_access":
        payload = _zpa_update_payload(fresh, zpa_conditions(fresh), t["set"])
        out = ops.update(run.zpa, "zpa_access_rule", t["id"], payload, name=t["name"], log=run.log)
    else:
        body = ao._body(fresh)
        for n, v in t["set"].items():
            body[cols[n]["field"]] = _api_value(policy, cols[n], v)
        body.pop("enabled", None)
        out = ops.update(run.zia, "policy", t["id"], body, channel=ao.POLICIES[policy]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        if policy != "zpa_access":
            run.wrote_zia = True
        run.log(f"[{rc.POLICIES[policy]['label']}] {t['name']}: {', '.join(sorted(t['set']))} updated")


def _h_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    policy = t["policy"]
    label = rc.POLICIES[policy]["label"]
    try:
        rows = read_rules(run.client, policy)
    except ao.OperationError as e:
        _halt_or_fail(run, units, str(e), f"the {label} rules")
        return
    if any(rc.name_key(_rname(r)).casefold() == rc.name_key(t["name"]).casefold() for r in rows):
        run.mark(units, "conflict", f"a rule named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    cols = {c["name"]: c for c in rc.columns(policy)}
    order = (max([_rorder(policy, r) for r in rows if not _is_default(policy, r)] or [0]) + 1)
    if policy == "zpa_access":
        if isinstance(t.get("body"), dict):
            payload = dict(t["body"])
        else:
            v = t["values"]
            vals = {"APP": v.get("app_segments") or [], "APP_GROUP": v.get("segment_groups") or [],
                    "CLIENT_TYPE": v.get("client_types") or [], "SCIM_GROUP": v.get("scim_groups") or []}
            payload = zpa_payload({}, name=t["name"], action=str(v.get("action") or "").upper(), description=str(v.get("description") or ""),
                                  custom_msg=str(v.get("custom_msg") or ""), conditions=zpa_build_conditions([], vals))
        out = ops.create(run.zpa, "zpa_access_rule", payload, name=t["name"], log=run.log)
    else:
        if isinstance(t.get("body"), dict):
            payload = dict(t["body"])
        else:
            payload = {"name": t["name"]}
            for n, v in t["values"].items():
                if v is None or cols[n]["kind"] == "order":
                    continue
                payload[cols[n]["field"]] = _api_value(policy, cols[n], v)
        payload["order"] = order
        payload.pop("enabled", None)
        out = ops.create(run.zia, "policy", payload, channel=ao.POLICIES[policy]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        oid = str(out.id or "")
        for u in units:
            u["object"] = dict(u["object"], id=oid)
        run.created.append({"type": "rule_csv_rule", "policy": policy, "id": oid, "name": t["name"], "placeholder": t["placeholder"]})
        if policy != "zpa_access":
            run.wrote_zia = True
        run.log(f"[{label}] {t['name']}: created" + (" (disabled)" if policy != "zpa_access" and payload.get("state") == "DISABLED" else ""))


def _h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    policy = t["policy"]
    fresh, err = get_rule(run, policy, t["id"])
    if fresh is None:
        if _gone(err):
            run.mark(units, "noop", "already gone")
            return
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    now = _now_values(policy, fresh, list(t["expect"]))
    if _rname(fresh) != t["name"] or _canon(now) != _canon(t["expect"]):
        run.mark(units, "conflict", "changed in the tenant since the preview, so it is kept")
        return
    if policy == "zpa_access":
        out = ops.delete(run.zpa, {"kind": "zpa_access_rule", "id": t["id"], "name": t["name"]}, log=run.log)
    else:
        out = ops.delete(run.zia, {"kind": "policy", "channel": ao.POLICIES[policy]["channel"], "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        if policy != "zpa_access":
            run.wrote_zia = True
        run.log(f"[{rc.POLICIES[policy]['label']}] {t['name']}: deleted")


def _mapped_sequence(run: Any, policy: str, rows: Sequence[Dict[str, Any]]) -> List[str]:
    ph = {str(c["id"]): c["placeholder"] for c in run.created if c.get("type") == "rule_csv_rule" and c.get("policy") == policy}
    return [ph.get(_rid(r), _rid(r)) for r in sorted(rows, key=lambda r: _sort_key(policy, r))]


def _real_id(run: Any, policy: str, x: str) -> Optional[str]:
    if not x.startswith(NEW):
        return x
    for c in run.created:
        if c.get("type") == "rule_csv_rule" and c.get("policy") == policy and c.get("placeholder") == x:
            return str(c["id"])
    return None


def _h_zia_order(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    policy = t["policy"]
    pkey = f"csv:{policy}"
    if pkey in run.order_broken:
        run.mark(units, "skipped", f"not attempted: {run.order_broken[pkey]}")
        return
    rows, err = ao.read_rules(run.zia, policy)
    if err:
        _halt_or_fail(run, units, err, f"the {rc.POLICIES[policy]['label']} rules")
        run.order_broken[pkey] = "the rules could not be read again before a move"
        return
    if _mapped_sequence(run, policy, rows) != list(t["expect_before"]):
        run.order_broken[pkey] = ao.REORDER_BROKEN
        run.mark(units, "conflict", "the policy's order is not what the preview expected at this step (a rule was changed, added or not "
                                    "created); this and the remaining moves were skipped")
        return
    rid = _real_id(run, policy, t["id"])
    fresh = next((r for r in rows if _rid(r) == rid), None)
    if fresh is None:
        run.order_broken[pkey] = ao.REORDER_BROKEN
        run.mark(units, "conflict", "the rule to move is not in the tenant")
        return
    body = ao._body(fresh)
    body["order"] = t["send_order"]
    body.pop("enabled", None)
    out = ops.update(run.zia, "policy", rid, body, channel=ao.POLICIES[policy]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=rid)
        run.log(f"[{rc.POLICIES[policy]['label']}] {t['name']}: moved to {t['send_order']}")
    else:
        run.order_broken[pkey] = f"the move of '{t['name']}' was not applied"


def _h_zpa_order(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = _zpa_list(getattr(getattr(run.zpa, "policies", None), "list_rules", None), "access")
    if err:
        _halt_or_fail(run, units, err, "the access policy rules")
        return
    if _mapped_sequence(run, "zpa_access", rows) != list(t["expect_before"]):
        run.mark(units, "conflict", "the access policy's order changed since the preview (or a rule was not created); the order was left as it is")
        return
    ids = [_real_id(run, "zpa_access", x) for x in t["desired"]]
    by_id = {_rid(r): r for r in rows}
    ids = [x for x in ids if x and not _is_default("zpa_access", by_id.get(x, {}))]
    fn = getattr(run.zpa.policies, "bulk_reorder_rules", None)
    if fn is None:
        run.mark(units, "failed", "", error="the installed zscaler-sdk-python has no policies.bulk_reorder_rules")
        run.counts["failed"] += 1
        return
    # One write for the whole order (assumed: the list names every rule but the Default rule, top first).
    out = ops.call(fn, "access", ids, op="update", kind="zpa_access_rule", name="access policy order", log=run.log)
    ops._audit_write("update", "zpa_access_rule", "order", "access policy order", None, out)
    if run.outcome(units, out, "update"):
        run.log("[ZPA access policy] order updated")


HANDLERS = {"rcsv_update": _h_update, "rcsv_create": _h_create, "rcsv_delete": _h_delete, "rcsv_zia_order": _h_zia_order,
            "rcsv_zpa_order": _h_zpa_order}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    policy = str((run.p.get("spec") or {}).get("policy") or "")
    order_groups = []
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t = g["target"]
        if g["handler"] in ("rcsv_zia_order", "rcsv_zpa_order"):
            order_groups.append((g, applied))
            continue
        out["checked"] += len(applied)
        oid = applied[0]["object"].get("id") or t.get("id")
        row, err = get_rule(run, policy, oid)
        if g["handler"] == "rcsv_delete":
            ok = row is None and _gone(err)
            if row is None and not ok:
                out["unread"].append(f"{t['name']}: {err}")
                continue
        elif row is None:
            out["unread"].append(f"{t['name']}: {err}")
            continue
        elif g["handler"] == "rcsv_update":
            ok = _canon(_now_values(policy, row, list(t["set"]))) == _canon(t["set"])
        else:
            want = {k: v for k, v in (t.get("values") or {}).items() if k not in ("order", "rank") and v not in (None, [], "")}
            ok = _rname(row) == t["name"] and _canon(_now_values(policy, row, list(want))) == _canon(want)
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{t['name']}: not as planned when read back")
    if order_groups:
        try:
            rows = read_rules(run.client, policy)
        except ao.OperationError as e:
            out["unread"].append(str(e))
            return out
        last = order_groups[-1][0]["target"]
        final = last.get("desired") or last.get("expect_after")
        ok = _mapped_sequence(run, policy, rows) == list(final)
        n = sum(len(a) for _g, a in order_groups)
        out["checked"] += n
        for _g, applied in order_groups:
            for u in applied:
                u["verified"] = ok
        if ok:
            out["confirmed"] += n
        else:
            out["mismatched"].append("the rule order read back differs from the planned order")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Undo: delete what was added (by id, only if unchanged since), put
    back what was changed, re-create what was deleted, restore the order."""
    items = result.get("items") or []
    applied = {u["group"] for u in items if u.get("status") == "applied"}
    if not applied:
        return None
    spec = result.get("spec") or {}
    policy = spec.get("policy")
    deletes, updates, creates = [], [], []
    deleted_ids: Dict[str, str] = {}
    created_ids: Set[str] = set()
    moved = False
    for g in result.get("groups") or []:
        if g["key"] not in applied:
            continue
        t = g["target"]
        unit = next(u for u in items if u["group"] == g["key"])
        if g["handler"] == "rcsv_create":
            oid = unit["object"].get("id")
            if oid:
                created_ids.add(str(oid))
                expect = {k: v for k, v in (t.get("values") or {}).items() if k != "order"} if not t.get("body") else {}
                deletes.append({"id": str(oid), "name": t["name"], "expect": expect})
        elif g["handler"] == "rcsv_update":
            updates.append({"id": t["id"], "name": t["name"], "set": {k: v for k, v in t["expect"].items() if k != "_other"},
                            "expect": dict(t["set"])})
        elif g["handler"] == "rcsv_delete":
            creates.append({"name": t["name"], "body": t["restore_body"]})
            deleted_ids[str(t["id"])] = NEW + rc.name_key(t["name"])
        else:
            moved = True
    out: Dict[str, Any] = {"type": result.get("type"), "policy": policy, "action": "undo", "undo": True,
                           "deletes": deletes, "updates": updates, "creates": creates}
    seq = result.get("sequence_before") or []
    if (moved or deleted_ids) and seq:
        out["order"] = [deleted_ids.get(x, x) for x in seq if x not in created_ids]
    return out


# ---------------------------------------------------------------------------
# Scope, the object picker, registration
# ---------------------------------------------------------------------------

def in_scope_zia(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
    pols = set(scope.get("policies") or [])
    if isinstance(spec, dict) and spec.get("policy"):
        p = str(spec["policy"])
        if p not in ("firewall", "url_filtering"):
            return f"Unknown policy '{p[:40]}' for this operation."
        return None if p in pols else (scope.get("not_in_scope") or {}).get(p) or ao.NOT_IN_SCOPE
    if pols & {"firewall", "url_filtering"}:
        return None
    return ("Neither Cloud Firewall nor URL filtering is in scope: on the Scope page tick ZIA platform (Cloud Firewall) or DLP / ZIA "
            "platform (URL filtering). Nothing was read.")


def in_scope_zpa(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
    if isinstance(spec, dict) and spec.get("policy") not in (None, "", "zpa_access"):
        return "Unknown policy for this operation."
    return None if scope.get("zpa") else "Not in scope: ZPA is not ticked on the Scope page, so the access policy is not read."


def _objects(policies: Sequence[str]) -> Callable[..., Dict[str, Any]]:
    def read_objects(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
        out: Dict[str, Any] = {"policies": [], "docs": rc.column_docs(), "errors": {}}
        for p in policies:
            if p != "zpa_access" and p not in (scope.get("policies") or []):
                out["policies"].append({"policy": p, "label": rc.POLICIES[p]["label"], "in_scope": False,
                                        "why": (scope.get("not_in_scope") or {}).get(p) or ao.NOT_IN_SCOPE})
                continue
            say(f"Reading the {rc.POLICIES[p]['label']} rules…")
            try:
                ex = export_csv(client, p, say=say, cancel=cancel)
            except ao.OperationError as e:
                out["errors"][p] = str(e)
                continue
            for k, v in ex["errors"].items():
                out["errors"][f"{p}: {k}"] = v
            out["policies"].append({"policy": p, "label": ex["label"], "in_scope": True, "rules": ex["rules"], "csv": ex["csv"],
                                    "filename": rc.filename(p), "truncated": ex["truncated"]})
            say(f"{ex['label']}: {ex['rules']} rules.")
        return out
    return read_objects


ao.register(TYPE_ZIA, family=FAMILY_ZIA, product="zia", label="Rules from a spreadsheet (ZIA)",
            hint="Export Cloud Firewall or URL filtering rules as CSV, edit them offline, then import: the preview lists every add, update, "
                 "move and (only if you ask) delete before anything is written.",
            in_scope=in_scope_zia, plan=plan, read_objects=_objects(("firewall", "url_filtering")), handlers=HANDLERS,
            verify=verify, inverse=inverse, group="Bulk changes", script="ops_rule_csv.js")
ao.register(TYPE_ZPA, family=FAMILY_ZPA, product="zpa", label="Rules from a spreadsheet (ZPA access policy)",
            hint="Export the ZPA access policy as CSV, edit it offline, then import: the preview lists every add, update, move and (only if "
                 "you ask) delete before anything is written. Needs ZPA ticked on the Scope page.",
            in_scope=in_scope_zpa, plan=plan, read_objects=_objects(("zpa_access",)), handlers=HANDLERS, verify=verify,
            inverse=inverse, group="Bulk changes", script="ops_rule_csv.js")
