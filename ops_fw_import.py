"""Firewall import: one operation type on the Bulk changes engine
(admin_ops.register) that builds ZIA Cloud Firewall objects and rules from a
migration plan (panos_migrate: a Palo Alto Networks PAN-OS export).

zia_firewall_import
    Creates the plan's IP source groups, IP destination groups, network
    services and Cloud Firewall rules, every name starting with the plan's
    prefix. Planned from the tenant as it is now: an object that already
    exists with the same content is reused (no-op); one that exists with
    other content is left alone and every rule that needs it is excluded,
    with the reason (the importer never changes an object it did not make);
    a rule naming a network application the tenant does not have is
    excluded. Rules are created DISABLED (unless the operator ticks "create
    the rules enabled"), at the bottom of the policy above the default rule,
    in the plan's order. Previewed item by item with a plan hash, applied
    through the four gates with a re-read before every write, activated
    once, read back, and reversible: the Undo (action "undo") re-reads each
    object it created and deletes it only while it still carries the
    prefix and its name, rules first.

The plan is untrusted (an uploaded or hand-edited file): every name,
address, port, action and application is checked here again, whatever
the migration page produced.

Verified against zscaler-sdk-python 1.11.3 (zscaler/zia/cloud_firewall.py,
cloud_firewall_rules.py): list_ip_source_groups, list_ip_destination_groups,
list_network_services, list_network_apps, get_ip_source_group,
get_ip_destination_group, get_network_service, cloud_firewall_rules
list_rules / get_rule; writes go through pack_ops (ip_source_group,
ip_destination_group, network_service; firewall rules as policy on the
firewall channel). Assumed: that the API accepts an IPv4 range a-b in an IP
group (the SDK documents it for rule destinations), the 63-character
object-name limit, and that the network application names in the plan are
the tenant's enum values (checked against list_network_apps).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import pack_ops as ops

TYPE = "zia_firewall_import"
FAMILY = "zia_firewall_objects"
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,62}$")
APP_RE = re.compile(r"^[A-Z0-9_]{1,60}$")
FQDN_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
RULE_NAME_MAX = 31
MAX_OBJECTS = 500
MAX_RULES = 200
MAX_ADDRESSES = 1000
MAX_LIST = 64
ACTIONS = ("ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP")
DEST_TYPES = ("DSTN_IP", "DSTN_FQDN")
PORT_KEYS = ("dest_tcp", "dest_udp", "src_tcp", "src_udp")
NOT_IN_SCOPE = ("Not in scope: the firewall import changes Cloud Firewall, which is read only when ZIA platform is ticked on the "
                "Scope page. Nothing was read.")
KINDS = {"src": ("ip_source_group", "IP source group", "POST /ipSourceGroups"),
         "dst": ("ip_destination_group", "IP destination group", "POST /ipDestinationGroups"),
         "svc": ("network_service", "Network service", "POST /networkServices"),
         "rule": ("policy", "Cloud Firewall rule", "POST /firewallFilteringRules")}
DELETE_ORDER = ("rule", "svc", "dst", "src")


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


# ---------------------------------------------------------------------------
# The spec (untrusted): checked field by field
# ---------------------------------------------------------------------------

def _name(v: Any, prefix: str, what: str, limit: int = 63) -> str:
    n = " ".join(str(v or "").split())
    if not n or len(n) > limit or not NAME_RE.match(n) or not n.startswith(prefix + "-"):
        raise _err(f"{what}: '{str(v)[:60]}' is not a usable name (letters, digits, space . _ ( ) -, at most {limit} characters, "
                   f"starting with the prefix '{prefix}-').")
    return n


def _address(v: Any, what: str, *, fqdn: bool) -> str:
    s = str(v or "").strip().lower()
    if fqdn:
        if not FQDN_RE.match(s):
            raise _err(f"{what}: '{s[:60]}' is not a host name.")
        return s
    m = re.fullmatch(r"([0-9.]+)-([0-9.]+)", s)
    try:
        if m:
            a, b = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
            if a > b:
                raise ValueError
            return f"{a}-{b}"
        net = ipaddress.IPv4Network(s, strict=False)
        return str(net) if "/" in s else str(net.network_address)
    except ValueError:
        raise _err(f"{what}: '{s[:60]}' is not an IPv4 address, subnet or range.") from None


def _port_list(v: Any, what: str) -> List[str]:
    out: List[str] = []
    for raw in (v if isinstance(v, list) else []):
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", str(raw).strip())
        if not m or not 1 <= int(m.group(1)) <= int(m.group(2) or m.group(1)) <= 65535:
            raise _err(f"{what}: '{str(raw)[:20]}' is not a port or a range within 1-65535.")
        s = m.group(1) if not m.group(2) or m.group(2) == m.group(1) else f"{m.group(1)}-{m.group(2)}"
        if s not in out:
            out.append(s)
    if len(out) > MAX_LIST:
        raise _err(f"{what}: at most {MAX_LIST} port ranges.")
    return sorted(out, key=lambda x: int(x.split("-")[0]))


def _list(v: Any, what: str, cap: int) -> List[Any]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise _err(f"{what} must be a list.")
    if len(v) > cap:
        raise _err(f"{what}: at most {cap}.")
    return v


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    """The checked spec. Raises OperationError naming the first problem."""
    if spec.get("action") == "undo":
        return _normalize_undo(spec)
    p = str(spec.get("prefix") or "").strip()
    if not PREFIX_RE.match(p):
        raise _err("The prefix must be 1 to 10 letters, digits, '-' or '_' (for example pan). Every object the import makes starts with it.")
    out: Dict[str, Any] = {"type": TYPE, "prefix": p, "enable": spec.get("enable") is True,
                           "source_sha256": str(spec.get("source_sha256") or "")[:64] if re.fullmatch(r"[0-9a-f]{64}", str(spec.get("source_sha256") or "")) else ""}
    seen: set = set()

    def unique(n: str) -> str:
        if n.lower() in seen:
            raise _err(f"'{n}' is named twice in the plan.")
        seen.add(n.lower())
        return n

    out["ip_source_groups"] = []
    for i, g in enumerate(_list(spec.get("ip_source_groups"), "ip_source_groups", MAX_OBJECTS)):
        g = g if isinstance(g, dict) else {}
        n = unique(_name(g.get("name"), p, f"Source group {i + 1}"))
        addrs = sorted({_address(a, n, fqdn=False) for a in _list(g.get("ip_addresses"), f"{n}: ip_addresses", MAX_ADDRESSES)})
        if not addrs:
            raise _err(f"{n}: a source group needs at least one address.")
        out["ip_source_groups"].append({"name": n, "ip_addresses": addrs})
    out["ip_destination_groups"] = []
    for i, g in enumerate(_list(spec.get("ip_destination_groups"), "ip_destination_groups", MAX_OBJECTS)):
        g = g if isinstance(g, dict) else {}
        n = unique(_name(g.get("name"), p, f"Destination group {i + 1}"))
        typ = str(g.get("type") or "DSTN_IP")
        if typ not in DEST_TYPES:
            raise _err(f"{n}: type must be DSTN_IP or DSTN_FQDN.")
        addrs = sorted({_address(a, n, fqdn=typ == "DSTN_FQDN") for a in _list(g.get("addresses"), f"{n}: addresses", MAX_ADDRESSES)})
        if not addrs:
            raise _err(f"{n}: a destination group needs at least one address.")
        out["ip_destination_groups"].append({"name": n, "type": typ, "addresses": addrs})
    out["network_services"] = []
    for i, s in enumerate(_list(spec.get("network_services"), "network_services", MAX_OBJECTS)):
        s = s if isinstance(s, dict) else {}
        n = unique(_name(s.get("name"), p, f"Network service {i + 1}"))
        ports = {k: _port_list(s.get(k), f"{n}: {k}") for k in PORT_KEYS}
        if not ports["dest_tcp"] and not ports["dest_udp"]:
            raise _err(f"{n}: a network service needs TCP or UDP destination ports.")
        out["network_services"].append(dict({"name": n}, **{k: v for k, v in ports.items() if v}))
    have = {"src": {g["name"] for g in out["ip_source_groups"]}, "dst": {g["name"] for g in out["ip_destination_groups"]},
            "svc": {s["name"] for s in out["network_services"]}}
    out["rules"] = []
    for i, r in enumerate(_list(spec.get("rules"), "rules", MAX_RULES)):
        r = r if isinstance(r, dict) else {}
        n = unique(_name(r.get("name"), p, f"Rule {i + 1}", RULE_NAME_MAX))
        act = str(r.get("action") or "")
        if act not in ACTIONS:
            raise _err(f"{n}: action must be one of {', '.join(ACTIONS)}.")
        rule: Dict[str, Any] = {"name": n, "action": act,
                                "description": re.sub("[\x00-\x1f\x7f<>]", " ", str(r.get("description") or ""))[:255]}
        for key, kind in (("src_ip_groups", "src"), ("dest_ip_groups", "dst"), ("nw_services", "svc")):
            names = [str(x) for x in _list(r.get(key), f"{n}: {key}", MAX_LIST)]
            missing = [x for x in names if x not in have[kind]]
            if missing:
                raise _err(f"{n}: {key} names {missing[0][:60]!r}, which the plan does not define.")
            rule[key] = list(dict.fromkeys(names))
        rule["src_ips"] = sorted({_address(a, n, fqdn=False) for a in _list(r.get("src_ips"), f"{n}: src_ips", MAX_LIST)})
        rule["dest_addresses"] = sorted({_address(a, n, fqdn=False) for a in _list(r.get("dest_addresses"), f"{n}: dest_addresses", MAX_LIST)})
        apps = [str(x) for x in _list(r.get("nw_applications"), f"{n}: nw_applications", MAX_LIST)]
        if any(not APP_RE.match(a) for a in apps):
            raise _err(f"{n}: nw_applications must be Zscaler network application names (A-Z, 0-9, _).")
        rule["nw_applications"] = list(dict.fromkeys(apps))
        if not any(rule[k] for k in ("src_ip_groups", "dest_ip_groups", "nw_services", "src_ips", "dest_addresses", "nw_applications")):
            raise _err(f"{n}: the rule names nothing to match, so it would match all traffic; ZIA's default rule plays that part.")
        out["rules"].append(rule)
    if not (out["ip_source_groups"] or out["ip_destination_groups"] or out["network_services"] or out["rules"]):
        raise _err("The plan has nothing to import. Build it on the migration page (Migrate from another vendor, Palo Alto Networks).")
    return out


_SELECT_RE = re.compile(r"^(rule|svc|dst|src):(\d{1,24})$")


def _normalize_undo(spec: Dict[str, Any]) -> Dict[str, Any]:
    p = str(spec.get("prefix") or "").strip()
    if not PREFIX_RE.match(p):
        raise _err("The Undo names no usable prefix.")
    items = []
    for x in _list(spec.get("delete"), "delete", MAX_OBJECTS * 3 + MAX_RULES):
        x = x if isinstance(x, dict) else {}
        m = _SELECT_RE.match(f"{x.get('kind')}:{x.get('id')}")
        if not m:
            raise _err("Each object the Undo deletes needs a kind (rule, svc, dst, src) and a numeric id.")
        items.append({"kind": m.group(1), "id": m.group(2), "name": _name(x.get("name"), p, "Undo", 63)})
    if not items:
        raise _err("The Undo has nothing to delete.")
    return {"type": TYPE, "action": "undo", "prefix": p, "delete": items}


# ---------------------------------------------------------------------------
# Reading ZIA (GET only)
# ---------------------------------------------------------------------------

def _fw(zia: Any) -> Any:
    fw = getattr(zia, "cloud_firewall", None)
    if fw is None:
        raise _err("cloud_firewall is not available in the installed zscaler-sdk-python.")
    return fw


def _call_rows(fn) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        return ao._rows(fn())
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:160]}"


LISTERS = {"src": "list_ip_source_groups", "dst": "list_ip_destination_groups", "svc": "list_network_services"}
GETTERS = {"src": "get_ip_source_group", "dst": "get_ip_destination_group", "svc": "get_network_service"}


def read_kind(zia: Any, kind: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if kind == "rule":
        return ao.read_rules(zia, "firewall")
    return _call_rows(getattr(_fw(zia), LISTERS[kind]))


def get_one(zia: Any, kind: str, oid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if kind == "rule":
        return ao.get_rule(zia, "firewall", oid)
    try:
        return ao._one(getattr(_fw(zia), GETTERS[kind])(int(oid)))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:160]}"


def _ids(v: Any) -> List[str]:
    out = []
    for x in v or []:
        out.append(str(x.get("id") if isinstance(x, dict) else getattr(x, "id", x)))
    return sorted(out)


def _pr(v: Any) -> List[str]:
    out = []
    for x in v or []:
        x = x if isinstance(x, dict) else {"start": getattr(x, "start", None), "end": getattr(x, "end", None)}
        a = int(x.get("start") or 0)
        b = int(x.get("end") or a)
        out.append(str(a) if a == b else f"{a}-{b}")
    return sorted(set(out), key=lambda s: int(s.split("-")[0]))


def state(kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """The fields the import manages, as the plan writes them."""
    if kind == "src":
        return {"ip_addresses": sorted(str(a).lower() for a in row.get("ip_addresses") or [])}
    if kind == "dst":
        return {"type": str(row.get("type") or ""), "addresses": sorted(str(a).lower() for a in row.get("addresses") or [])}
    if kind == "svc":
        return {k: _pr(row.get(f"{k}_ports")) for k in PORT_KEYS if row.get(f"{k}_ports")}
    return {"action": str(row.get("action") or ""), "src_ip_groups": _ids(row.get("src_ip_groups")), "dest_ip_groups": _ids(row.get("dest_ip_groups")),
            "nw_services": _ids(row.get("nw_services")), "nw_applications": sorted(str(a) for a in row.get("nw_applications") or []),
            "src_ips": sorted(str(a) for a in row.get("src_ips") or []), "dest_addresses": sorted(str(a) for a in row.get("dest_addresses") or [])}


def _desired(kind: str, obj: Dict[str, Any]) -> Dict[str, Any]:
    if kind == "src":
        return {"ip_addresses": list(obj["ip_addresses"])}
    if kind == "dst":
        return {"type": obj["type"], "addresses": list(obj["addresses"])}
    if kind == "svc":
        return {k: list(obj[k]) for k in PORT_KEYS if obj.get(k)}
    return {k: obj[k] for k in ("action", "src_ip_groups", "dest_ip_groups", "nw_services", "nw_applications", "src_ips", "dest_addresses")}


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def _by_name(rows: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    want = name.casefold()
    return next((r for r in rows if str(r.get("name") or "").casefold() == want), None)


def _obj(kind: str, name: str, oid: Any = None) -> Dict[str, Any]:
    return {"type": KINDS[kind][0], "kind": kind, "label": KINDS[kind][1], "id": str(oid) if oid not in (None, "") else None, "name": name}


def _summary(kind: str, d: Dict[str, Any]) -> str:
    if kind == "src":
        return f"{len(d['ip_addresses'])} address(es): {', '.join(d['ip_addresses'][:3])}{' …' if len(d['ip_addresses']) > 3 else ''}"
    if kind == "dst":
        return f"{d['type']}, {len(d['addresses'])} address(es): {', '.join(d['addresses'][:3])}{' …' if len(d['addresses']) > 3 else ''}"
    if kind == "svc":
        return " · ".join(f"{k.replace('_', ' ').upper()} {', '.join(v)}" for k, v in d.items())
    parts = [d["action"]]
    for k, w in (("src_ip_groups", "from"), ("src_ips", "from"), ("dest_ip_groups", "to"), ("dest_addresses", "to"), ("nw_services", "services"),
                 ("nw_applications", "apps")):
        if d.get(k):
            parts.append(f"{w} {', '.join(str(x) for x in d[k][:3])}{' …' if len(d[k]) > 3 else ''}")
    return " · ".join(parts)


def _plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    n = normalize(spec)
    zia = getattr(client, "zia", None)
    if zia is None:
        raise _err("This sign-in has no ZIA client.")
    if n.get("action") == "undo":
        return _plan_undo(zia, n, say, cancel)
    p = n["prefix"]
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    data: Dict[str, List[Dict[str, Any]]] = {}
    for kind, what in (("src", "IP source groups"), ("dst", "IP destination groups"), ("svc", "network services"), ("rule", "Cloud Firewall rules")):
        ao._check_stop(cancel)
        say(f"Reading the tenant: {what}…")
        rows, err = read_kind(zia, kind)
        if err:
            blockers.append(f"The {what} could not be read ({str(err)[:160]}), so the import cannot be checked against them.")
        data[kind] = rows
    say("Reading the tenant: network applications…")
    apps_rows, apps_err = _call_rows(_fw(zia).list_network_apps)
    have_apps = {str(r.get("id") or "").upper() for r in apps_rows} if not apps_err else None
    if apps_err:
        warnings.append(f"The network applications could not be read ({apps_err[:120]}); rules that name one are excluded.")
    keys: Dict[Tuple[str, str], str] = {}   # (kind, name) -> unit key whose object id rules use
    dead: set = set()
    for kind, rows_key in (("src", "ip_source_groups"), ("dst", "ip_destination_groups"), ("svc", "network_services")):
        for o in n[rows_key]:
            name = o["name"]
            key = f"{kind}:{name}"
            keys[(kind, name)] = key
            want = _desired(kind, o)
            row = _by_name(data[kind], name)
            summ = f"{KINDS[kind][1]} · {_summary(kind, want)}"
            if row is None:
                items.append(ao._unit(key, key, kind, _obj(kind, name), "exists", False, True, value=summ,
                                      reason=f"Creates it: {KINDS[kind][2]}."))
                groups.append({"key": key, "handler": "fwi_create", "target": {"kind": kind, "name": name, "prefix": p, "desired": want}})
            elif state(kind, row) == {k: v for k, v in want.items()}:
                items.append(ao._unit(key, key, kind, _obj(kind, name, row.get("id")), "exists", True, True, value=summ, status="noop",
                                      reason="already in ZIA as the plan asks: reused"))
            else:
                dead.add(key)
                items.append(ao._unit(key, key, kind, _obj(kind, name, row.get("id")), "exists", True, True, value=summ, status="excluded",
                                      reason="an object with this name exists in ZIA with other content; the import never changes an object it "
                                             "did not make. Rename the prefix, or align the object by hand, then preview again"))
    rule_rows = data["rule"]
    for i, r in enumerate(n["rules"]):
        name = r["name"]
        key = f"rule:{name}"
        want = _desired("rule", r)
        deps = [keys[(k, x)] for k, field in (("src", "src_ip_groups"), ("dst", "dest_ip_groups"), ("svc", "nw_services")) for x in r[field]]
        summ = f"Cloud Firewall rule · {_summary('rule', want)} · {'enabled' if n['enable'] else 'disabled'}"
        why = ""
        if any(d in dead for d in deps):
            why = "it needs an object that exists in ZIA with other content (see above), so it is not created"
        elif r["nw_applications"]:
            if have_apps is None:
                why = "the tenant's network applications could not be read, so its applications cannot be checked"
            else:
                miss = [a for a in r["nw_applications"] if a.upper() not in have_apps]
                if miss:
                    why = f"this tenant has no network application {', '.join(miss)}; a rule without it would match more than the source rule"
        row = _by_name(rule_rows, name)
        if row is not None:
            cur = state("rule", row)
            same = cur["action"] == want["action"] and cur["nw_applications"] == sorted(want["nw_applications"])
            items.append(ao._unit(key, key, "rule", _obj("rule", name, row.get("id")), "exists", True, True, value=summ,
                                  status="noop" if same else "excluded",
                                  reason="already in ZIA" if same else "a rule with this name exists with another action or applications; the "
                                                                      "import never changes an existing rule"))
            continue
        if why:
            items.append(ao._unit(key, key, "rule", _obj("rule", name), "exists", False, True, value=summ, status="excluded", reason=why))
            continue
        items.append(ao._unit(key, key, "rule", _obj("rule", name), "exists", False, True, value=summ, depends_on=deps,
                              reason=f"Creates it {'ENABLED' if n['enable'] else 'DISABLED'} at the bottom of the policy: {KINDS['rule'][2]}."))
        refs = {f: [{"ref": keys[(k, x)]} for x in r[f]] for k, f in (("src", "src_ip_groups"), ("dst", "dest_ip_groups"), ("svc", "nw_services"))}
        groups.append({"key": key, "handler": "fwi_create", "target": {"kind": "rule", "name": name, "prefix": p, "position": i,
                                                                       "desired": dict(want, **refs), "description": r["description"],
                                                                       "enable": n["enable"]}})
    if n["enable"]:
        warnings.append("Rules will be created ENABLED: they decide traffic as soon as ZIA activates, which the app does right after the writes.")
    warnings.append("Cloud Firewall rules apply to every location and user: the PAN-OS zones and users were not carried (see the migration page).")
    creates = sum(1 for g in groups)
    title = f"Import {sum(1 for u in items if u['kind'] == 'rule')} Cloud Firewall rule(s) and their objects for {p}"
    return {"type": TYPE, "product": "zia", "title": title, "spec": n, "items": items, "groups": groups, "warnings": warnings, "blockers": blockers,
            # Every import that creates something asks for the typed phrase, whatever the count (as the ZIA baseline does).
            "confirm_always": f"IMPORT {creates} OBJECTS" if creates else "",
            "notes": ["New rules are created disabled unless you ticked 'create the rules enabled'; Undo deletes what this import created."]}


def _plan_undo(zia: Any, n: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    items, groups = [], []
    for kind in DELETE_ORDER:
        for x in [d for d in n["delete"] if d["kind"] == kind]:
            ao._check_stop(cancel)
            key = f"del:{kind}:{x['id']}"
            row, err = get_one(zia, kind, x["id"])
            if row is None:
                gone = "404" in str(err) or "not found" in str(err).lower()
                items.append(ao._unit(key, key, kind, _obj(kind, x["name"], x["id"]), "exists", False, False, status="noop" if gone else "excluded",
                                      reason="already gone" if gone else f"could not be read ({str(err)[:120]}); left as it is"))
                continue
            if str(row.get("name") or "") != x["name"] or not x["name"].startswith(n["prefix"] + "-"):
                items.append(ao._unit(key, key, kind, _obj(kind, x["name"], x["id"]), "exists", True, True, status="excluded",
                                      reason="renamed in ZIA since the import, so it is kept"))
                continue
            items.append(ao._unit(key, key, kind, _obj(kind, x["name"], x["id"]), "exists", True, False,
                                  reason=f"Deletes it: DELETE {KINDS[kind][2].split(' ', 1)[1]}/{{id}}."))
            groups.append({"key": key, "handler": "fwi_delete", "target": {"kind": kind, "id": x["id"], "name": x["name"], "prefix": n["prefix"]}})
    return {"type": TYPE, "product": "zia", "title": f"Undo the firewall import for {n['prefix']}: delete {len(groups)} object(s)", "spec": n,
            "items": items, "groups": groups, "warnings": [], "blockers": [], "confirm_always": f"DELETE {len(groups)} OBJECTS" if groups else ""}


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

class _Unresolved(Exception):
    pass


def _resolve(v: Any, run: Any) -> Any:
    if isinstance(v, dict) and set(v) == {"ref"}:
        u = run.units.get(v["ref"])
        oid = (u or {}).get("object", {}).get("id")
        if not oid:
            raise _Unresolved(f"'{(u or {}).get('object', {}).get('name') or v['ref']}' has no id (it was not created)")
        return int(oid) if str(oid).isdigit() else oid
    if isinstance(v, list):
        return [_resolve(x, run) for x in v]
    if isinstance(v, dict):
        return {k: _resolve(x, run) for k, x in v.items()}
    return v


def _halt_or_fail(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    run.halt = ao._read_halt(err)
    if run.halt:
        run.mark(units, "skipped", f"not attempted: {run.halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def payload(kind: str, name: str, want: Dict[str, Any], t: Dict[str, Any], assessor: str) -> Dict[str, Any]:
    desc = f"Migrated from Palo Alto Networks by {assessor or 'the assessor'} (firewall import, prefix {t['prefix']})."[:255]
    if kind == "src":
        return {"name": name, "description": desc, "ip_addresses": list(want["ip_addresses"])}
    if kind == "dst":
        return {"name": name, "description": desc, "type": want["type"], "addresses": list(want["addresses"])}
    if kind == "svc":
        body: Dict[str, Any] = {"name": name, "description": desc, "type": "CUSTOM"}
        for k in PORT_KEYS:
            if want.get(k):
                body[f"{k}_ports"] = [{"start": int(r.split("-")[0]), "end": int(r.split("-")[-1])} for r in want[k]]
        return body
    body = {"name": name, "description": (t.get("description") or desc)[:255], "action": want["action"],
            "state": "ENABLED" if t.get("enable") else "DISABLED", "enable_full_logging": False}
    for k in ("src_ip_groups", "dest_ip_groups", "nw_services", "nw_applications", "src_ips", "dest_addresses"):
        if want.get(k):
            body[k] = list(want[k])
    return body


def _h_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind = t["kind"]
    for u in units:
        why = ao._deps_ok(run, u)
        if why:
            run.mark(units, "skipped", why)
            return
    try:
        want = _resolve(t["desired"], run)
    except _Unresolved as e:
        run.mark(units, "skipped", f"not attempted: {e}")
        return
    rows, err = read_kind(run.zia, kind)
    if err:
        _halt_or_fail(run, units, err, f"the {KINDS[kind][1]}s")
        return
    if _by_name(rows, t["name"]) is not None:
        run.mark(units, "conflict", f"an object named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    body = payload(kind, t["name"], want, t, run.assessor)
    if kind == "rule":
        orders = [int(r.get("order") or 0) for r in rows if not ao._is_default(r) and not r.get("predefined")]
        body["order"] = (max(orders) if orders else 0) + 1
        body["rank"] = 7
        out = ops.create(run.zia, "policy", body, channel="firewall", name=t["name"], log=run.log)
    else:
        out = ops.create(run.zia, KINDS[kind][0], body, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        oid = str(out.id or "")
        for u in units:
            u["object"] = dict(u["object"], id=oid)
        run.created.append({"type": KINDS[kind][0], "kind": kind, "id": oid, "name": t["name"]})
        t["applied_state"] = state(kind, dict(body, **({k: [{"id": x} for x in body.get(k, [])] for k in ("src_ip_groups", "dest_ip_groups", "nw_services")}
                                                       if kind == "rule" else {})))
        run.log(f"[{KINDS[kind][1]}] {t['name']}: created{' (' + body.get('state', '').lower() + ')' if kind == 'rule' else ''}")


def _h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    row, err = get_one(run.zia, t["kind"], t["id"])
    if row is None:
        if "404" in str(err) or "not found" in str(err).lower():
            run.mark(units, "noop", "already gone")
            return
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    if str(row.get("name") or "") != t["name"] or not t["name"].startswith(t["prefix"] + "-"):
        run.mark(units, "conflict", "renamed in ZIA since the preview, so it is kept")
        return
    item = {"kind": KINDS[t["kind"]][0], "id": int(t["id"]) if str(t["id"]).isdigit() else t["id"], "name": t["name"]}
    if t["kind"] == "rule":
        item["channel"] = "firewall"
    out = ops.delete(run.zia, item, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[{KINDS[t['kind']][1]}] {t['name']}: deleted")


def _verify(run: Any) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t = g["target"]
        oid = t.get("id") or applied[0]["object"].get("id")
        out["checked"] += len(applied)
        row, err = get_one(run.zia, t["kind"], oid)
        if g["handler"] == "fwi_delete":
            ok = row is None
        elif row is None:
            out["unread"].append(f"{t['name']}: {err}")
            for u in applied:
                u["verified"] = None
            continue
        else:
            want, cur = t.get("applied_state") or {}, state(t["kind"], row)
            ok = all(cur.get(k) == v for k, v in want.items() if k in cur)
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{t['name']}: not as written when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    spec = result.get("spec") or {}
    if spec.get("action") == "undo":
        return None
    out = []
    for g in result.get("groups") or []:
        applied = [u for u in result.get("items") or [] if u.get("group") == g["key"] and u.get("status") == "applied"]
        if g.get("handler") == "fwi_create" and applied and applied[0]["object"].get("id"):
            out.append({"kind": g["target"]["kind"], "id": applied[0]["object"]["id"], "name": g["target"]["name"]})
    if not out or not spec.get("prefix"):
        return None
    return {"type": TYPE, "action": "undo", "prefix": spec["prefix"], "delete": out}


def _in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "firewall" in (scope.get("policies") or []) else NOT_IN_SCOPE


def _read_objects(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """What the page shows next to the plan: the tenant's existing objects
    with the plan's names, and how many network applications it has."""
    zia = getattr(client, "zia", None)
    counts, errors = {}, {}
    for kind, what in (("src", "IP source groups"), ("dst", "IP destination groups"), ("svc", "network services"), ("rule", "Cloud Firewall rules")):
        ao._check_stop(cancel)
        rows, err = read_kind(zia, kind)
        counts[what] = len(rows)
        if err:
            errors[what] = err
    apps, err = _call_rows(_fw(zia).list_network_apps)
    if err:
        errors["network applications"] = err
    return {"status": "done", "counts": counts, "network_apps": sorted(str(a.get("id")) for a in apps if a.get("id"))[:2000], "errors": errors,
            "limits": {"rules": MAX_RULES, "objects": MAX_OBJECTS}}


ao.register(TYPE, family=FAMILY, product="zia", label="Firewall import from Palo Alto Networks",
            hint="Create the IP source and destination groups, network services and Cloud Firewall rules of a migration plan built from a "
                 "PAN-OS configuration export (Migrate from another vendor). Rules arrive disabled; Undo deletes what the import made.",
            in_scope=_in_scope, plan=_plan, read_objects=_read_objects, handlers={"fwi_create": _h_create, "fwi_delete": _h_delete},
            verify=_verify, inverse=_inverse, script="ops_fw_import.js")
