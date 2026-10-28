"""Workload traffic through a Cloud or Branch Connector, for the Path
analyzer: which workload groups a workload belongs to (from its tags),
which connector traffic forwarding rule decides, and where the traffic
goes next (ZIA, ZPA, direct, local switch, proxy chaining or drop).

What is read (zscaler-sdk-python `client.ztw.*`, each list method answers
`(items, response, error)`; methods and paths verified in the installed
SDK, zscaler/ztw/*.py, version 1.11.3):

  forwarding_rules.list_rules         GET /ztw/api/v1/ecRules/ecRdr
  workload_groups.list_groups         GET /ztw/api/v1/workloadGroups
  ec_groups.list_ec_groups            GET /ztw/api/v1/ecgroup
  ip_source_groups.list_ip_source_groups            GET /ztw/api/v1/ipSourceGroups
  ip_destination_groups.list_ip_destination_groups  GET /ztw/api/v1/ipDestinationGroups

Only list methods are called; nothing is written. Each list is read with
the SDK's own paging (response.has_next / next) up to MAX_PAGES, paced
`pace` seconds apart (an assumption, as zpa_reader's: no ZTW limit is
documented in the SDK), with Stop honoured before every call.

Field names are the SDK models' (ztw/models/forwarding_rules.py
ForwardingControlRule, workload_groups.py WorkloadGroups with
expressionJson / expressionContainers / tagContainer / tags {key, value},
ip_source_groups.py ipAddresses, ip_destination_groups.py addresses,
ecgroup.py location). The forward methods are the SDK's documented values
(add_rule docstring): ZIA, ZPA, ECZPA, ECSELF, DIRECT, PROXYCHAIN, DROP,
LOCAL_SWITCH, INVALID.

Assumed, not documented in the SDK (said on the page):
  * Rules are evaluated in `order` ascending, the first enabled rule whose
    criteria all match decides; predefined rules with a negative order run
    after every numbered rule (-2 before -1). With no rule matching, the
    traffic goes to ZIA.
  * A workload group's expression: within a tag container its tags are
    joined by the container's operator; the containers by the expression's
    operator (AND unless OR). A container's tagType (ATTR, VM, ENI, VPC,
    SUBNET) must match a tag typed with it; an untyped tag matches any.
  * A hostname is never resolved: a rule whose destinations are IP
    addresses depends on the hostname's address ("unknown"), except the
    ZPA IP pool 100.64.0.0/10, which a hostname reaches only as a ZPA
    application.
  * Criteria this tool cannot evaluate (countries, categories, network
    services and applications, locations, time windows, devices) make a
    rule "depends on", never a guess.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import zpa_path
import zpa_reader
from zpa_reader import as_str, get

PACE_SECONDS = 0.6
MAX_PAGES = 20
MAX_TAGS = 50
MAX_TAG_CHARS = 200
TAG_TYPES = ("ATTR", "VM", "ENI", "VPC", "SUBNET")

STOPPED_REASON = ("You clicked Stop before the Cloud & Branch Connector read finished, so it was abandoned: nothing more was "
                  "read from the tenant and no partial result is shown.")

LISTS = (
    ("forwarding_rules", "connector traffic forwarding rules", "forwarding_rules", "list_rules"),
    ("workload_groups", "workload groups", "workload_groups", "list_groups"),
    ("ec_groups", "Cloud & Branch Connector groups", "ec_groups", "list_ec_groups"),
    ("ip_source_groups", "connector IP source groups", "ip_source_groups", "list_ip_source_groups"),
    ("ip_destination_groups", "connector IP destination groups", "ip_destination_groups", "list_ip_destination_groups"),
)

# forward method: (where it goes, words)
FORWARD = {
    "ZIA": ("zia", "forwarded to ZIA"), "ECSELF": ("zia", "forwarded to ZIA by the connector itself"),
    "ZPA": ("zpa", "forwarded to ZPA"), "ECZPA": ("zpa", "forwarded to ZPA"),
    "DIRECT": ("direct", "sent direct to the internet: it never reaches Zscaler"),
    "LOCAL_SWITCH": ("local", "switched locally between workloads: it never leaves the connector"),
    "PROXYCHAIN": ("proxy", "proxy-chained to another proxy: it never reaches ZIA"),
    "DROP": ("drop", "dropped by the connector"),
}
UNEVALUATED = (("destCountries", "destination country"), ("destIpCategories", "destination IP category"),
               ("resCategories", "URL category"), ("nwServices", "network service"), ("nwServiceGroups", "network service group"),
               ("nwApplications", "network application"), ("nwApplicationGroups", "network application group"),
               ("appServiceGroups", "app service group"), ("locations", "location"), ("locationGroups", "location group"),
               ("timeWindows", "time window"), ("devices", "device"), ("deviceGroups", "device group"),
               ("departments", "department"), ("groups", "group"), ("users", "user"), ("destIpv6Groups", "destination IPv6 group"),
               ("srcIpv6Groups", "source IPv6 group"))

ASSUMPTIONS = [
    "Workload traffic: forwarded by a Cloud or Branch Connector, not by Client Connector, so Client Connector profiles, PAC files and ZPA bypass settings do not apply.",
    "Connector forwarding rules are evaluated in rule order; predefined rules with a negative order run last; with no rule matching the traffic goes to ZIA.",
    "Workload group membership comes from the tags you gave; a group picked by name counts as a member.",
    "Forwarding rule criteria this tool cannot evaluate (countries, categories, services, locations, time windows) make that rule conditional.",
]


class Stopped(RuntimeError):
    """The operator clicked Stop: nothing more is read."""


# ── the read ────────────────────────────────────────────────────────────
def read(client: Any, log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
         pace: Optional[float] = None) -> Dict[str, Any]:
    """Read the connector lists once. {collections: {key: {label, read,
    count, complete, error}}, <key>: [raw dicts] or None}. Raises Stopped."""
    _log = log or (lambda m: None)
    ztw = getattr(client, "ztw", None)
    if ztw is None:
        raise zpa_reader.ReadError("This sign-in has no Cloud & Branch Connector API (the classic ZIA API reaches ZIA only).")
    gap = PACE_SECONDS if pace is None else max(0.0, float(pace))
    last = [None]

    def gate() -> None:
        if cancel is not None and cancel.is_set():
            raise Stopped(STOPPED_REASON)
        if last[0] is not None and gap:
            left = gap - (time.monotonic() - last[0])
            if left > 0 and (cancel.wait(left) if cancel is not None else time.sleep(left)):
                raise Stopped(STOPPED_REASON)
        if cancel is not None and cancel.is_set():
            raise Stopped(STOPPED_REASON)
        last[0] = time.monotonic()

    snap: Dict[str, Any] = {"read_at": time.time(), "collections": {}}
    for key, label, svc_name, method in LISTS:
        fn = getattr(getattr(ztw, svc_name, None), method, None)
        if not callable(fn):
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False, "error": "not available in this SDK version"}
            snap[key] = None
            continue
        _log(f"Reading Cloud & Branch Connector {label}…")
        items: List[Dict[str, Any]] = []
        complete, error = True, None
        try:
            gate()
            res = zpa_reader._triple(fn())
            for page in range(MAX_PAGES):
                result, resp, err = res
                if err:
                    error = zpa_reader._err_text(err)
                    break
                items.extend(zpa_reader.raw_items(result, resp))
                more = getattr(resp, "has_next", None)
                if not (callable(more) and more() is True):
                    break
                if page == MAX_PAGES - 1:
                    complete = False
                    break
                gate()
                res = zpa_reader._triple(resp.next())
        except Stopped:
            raise
        except Exception as e:  # noqa: BLE001 — one failed list never ends the read
            error = zpa_reader._err_text(e)
        if error:
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False, "error": error}
            snap[key] = None
            _log(f"Could not read {label}: {error}")
            continue
        snap["collections"][key] = {"label": label, "read": True, "count": len(items), "complete": complete, "error": None}
        snap[key] = items
        _log(f"Read {len(items)} {label}.")
    return snap


# ── input ───────────────────────────────────────────────────────────────
def parse_tags(value: Any) -> List[Dict[str, Any]]:
    """Tags as typed ("VPC: Vpc-id=vpc-1, Env=prod" lines or a list of
    {type, key, value}) → [{type, key, value}]. At most MAX_TAGS, each part
    at most MAX_TAG_CHARS; ValueError in plain words beyond that."""
    out: List[Dict[str, Any]] = []
    if isinstance(value, list):
        raw = value
    else:
        text = str(value or "")
        if len(text) > MAX_TAGS * (MAX_TAG_CHARS + 2):
            raise ValueError(f"Too many workload tags: give at most {MAX_TAGS}.")
        raw = [p for p in re.split(r"[\n,;]+", text) if p.strip()]
    if len(raw) > MAX_TAGS:
        raise ValueError(f"Too many workload tags: give at most {MAX_TAGS}.")
    for item in raw:
        if isinstance(item, dict):
            t, k, v = as_str(item.get("type")).upper() or None, as_str(item.get("key")), as_str(item.get("value"))
        else:
            s = str(item).strip()
            t = None
            m = re.match(r"^([A-Za-z]+)\s*:\s*(.+)$", s)
            if m and m.group(1).upper() in TAG_TYPES:
                t, s = m.group(1).upper(), m.group(2)
            k, _, v = s.partition("=")
            k, v = k.strip(), v.strip()
        if not k:
            continue
        if len(k) > MAX_TAG_CHARS or len(v) > MAX_TAG_CHARS:
            raise ValueError(f"A workload tag is longer than {MAX_TAG_CHARS} characters.")
        out.append({"type": t if t in TAG_TYPES else None, "key": k, "value": v})
    return out


def workload_input(w: Dict[str, Any]) -> Dict[str, Any]:
    """The workload as the page sends it → {ip, tags, workload_group,
    connector_group}; ValueError in plain words for a bad source IP."""
    w = w if isinstance(w, dict) else {}
    ip = as_str(w.get("ip"))[:64]
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError(f"“{ip[:40]}” is not an IP address: give the workload's source IP, for example 10.1.2.3.")
    group = as_str(w.get("workload_group"))[:MAX_TAG_CHARS]
    ec = as_str(w.get("connector_group"))[:MAX_TAG_CHARS]
    return {"ip": ip or None, "tags": parse_tags(w.get("tags")), "workload_group": group or None, "connector_group": ec or None}


# ── membership ──────────────────────────────────────────────────────────
def _lc(s: Any) -> str:
    return as_str(s).lower()


def _tag_hit(want: Dict[str, Any], ctype: Optional[str], tags: List[Dict[str, Any]]) -> bool:
    for t in tags:
        if t["type"] and ctype and t["type"] != ctype:
            continue
        if _lc(t["key"]) == _lc(want.get("key")) and (as_str(want.get("value")) == "" or _lc(t["value"]) == _lc(want.get("value"))):
            return True
    return False


def group_expression(g: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    """(join operator, [{type, operator, tags}]) of a workload group."""
    ej = get(g, "expressionJson") or {}
    conts = []
    for c in get(ej, "expressionContainers") or []:
        if not isinstance(c, dict):
            continue
        tc = get(c, "tagContainer") or {}
        tags = [x for x in (get(tc, "tags") or []) if isinstance(x, dict) and as_str(x.get("key"))]
        conts.append({"type": as_str(get(c, "tagType")).upper() or None, "operator": (as_str(get(tc, "operator")) or "AND").upper(), "tags": tags})
    op = (as_str(get(ej, "operator")) or "AND").upper()
    return ("OR" if op == "OR" else "AND"), conts


def member(g: Dict[str, Any], tags: List[Dict[str, Any]], picked: Optional[str]) -> Dict[str, Any]:
    """{id, name, state: match | nomatch | unknown, why} for one group."""
    gid, name = as_str(get(g, "id")), as_str(get(g, "name")) or as_str(get(g, "id"))
    base = {"id": gid, "name": name}
    if picked and _lc(picked) in (_lc(gid), _lc(name)):
        return dict(base, state="match", why="picked as the workload's group")
    op, conts = group_expression(g)
    if not conts:
        return dict(base, state="unknown", why=f"workload group “{name}” has no tag expression this tool can read")
    if not tags:
        return dict(base, state="nomatch" if picked else "unknown", why="not the group picked" if picked else "no workload tags were given")
    parts, oks = [], []
    for c in conts:
        hits = [_tag_hit(w, c["type"], tags) for w in c["tags"]]
        ok = bool(hits) and (any(hits) if c["operator"] == "OR" else all(hits))
        oks.append(ok)
        words = (" or " if c["operator"] == "OR" else " and ").join(f"{w.get('key')}={w.get('value', '')}" for w in c["tags"][:6])
        parts.append(f"{'met' if ok else 'not met'}: {c['type'] or 'tag'} {words}")
    ok = any(oks) if op == "OR" else all(oks)
    return dict(base, state="match" if ok else "nomatch", why=f" {op} ".join(parts))


def membership(snap: Dict[str, Any], w: Dict[str, Any]) -> List[Dict[str, Any]]:
    groups = [member(g, w["tags"], w["workload_group"]) for g in snap.get("workload_groups") or [] if isinstance(g, dict)]
    if w["workload_group"] and not any(m["state"] == "match" for m in groups):
        groups.append({"id": "", "name": w["workload_group"], "state": "match", "why": "picked by name (not found in the workload groups read)"})
    return groups


# ── rule criteria ───────────────────────────────────────────────────────
def _refs(v: Any) -> List[Dict[str, str]]:
    out = []
    for x in v or []:
        if isinstance(x, dict):
            out.append({"id": as_str(x.get("id") or x.get("externalId") or x.get("external_id")), "name": as_str(x.get("name"))})
        elif x not in (None, ""):
            out.append({"id": as_str(x), "name": as_str(x)})
    return out


def _ip_in(ip: str, entries: List[str]) -> Optional[bool]:
    """Whether `ip` is in any IP, CIDR or a-b range entry; None when no
    entry is an address at all."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    seen = False
    for e in entries:
        e = as_str(e)
        try:
            if "-" in e:
                a, b = (ipaddress.ip_address(x.strip()) for x in e.split("-", 1))
                seen = True
                if a.version == addr.version and a <= addr <= b:
                    return True
                continue
            net = ipaddress.ip_network(e, strict=False)
            seen = True
            if net.version == addr.version and addr in net:
                return True
        except ValueError:
            continue
    return False if seen else None


ZPA_POOL = ipaddress.ip_network("100.64.0.0/10")


def _is_address(e: str) -> bool:
    return _ip_in("0.0.0.0", [e]) is not None or _ip_in("::", [e]) is not None


def _within(e: str, net: Any) -> bool:
    """Whether an IP, CIDR or a-b range entry lies inside `net`."""
    try:
        if "-" in e:
            return all(ipaddress.ip_address(x.strip()) in net for x in e.split("-", 1))
        n = ipaddress.ip_network(as_str(e), strict=False)
        return n.version == net.version and n.subnet_of(net)
    except (ValueError, TypeError):
        return False


def _host_in(host: str, entries: List[str]) -> bool:
    h = host.lower().rstrip(".")
    for e in entries:
        e = as_str(e).lower().rstrip(".")
        if not e:
            continue
        if e == h or (e.startswith("*.") and h.endswith(e[1:])) or (e.startswith(".") and (h.endswith(e) or h == e[1:])):
            return True
    return False


def normalize_rule(r: Dict[str, Any], index: int) -> Dict[str, Any]:
    try:
        order = int(str(get(r, "order")).strip())
    except (TypeError, ValueError):
        order = None
    out = {"id": as_str(get(r, "id")), "name": as_str(get(r, "name")) or as_str(get(r, "id")), "order": order, "index": index,
           "state": as_str(get(r, "state")).upper() or "ENABLED", "forward_method": as_str(get(r, "forwardMethod")).upper() or "ZIA",
           "src_ips": [as_str(x) for x in get(r, "srcIps") or []], "dest_addresses": [as_str(x) for x in get(r, "destAddresses") or []],
           "src_ip_groups": _refs(get(r, "srcIpGroups")), "dest_ip_groups": _refs(get(r, "destIpGroups")),
           "src_workload_groups": _refs(get(r, "srcWorkloadGroups")), "ec_groups": _refs(get(r, "ecGroups")),
           "zpa_segments": _refs(get(r, "zpaAppSegments")) + _refs(get(r, "zpaApplicationSegments")),
           "zpa_segment_groups": _refs(get(r, "zpaApplicationSegmentGroups")),
           "proxy_gateway": as_str((get(r, "proxyGateway") or {}).get("name")) if isinstance(get(r, "proxyGateway"), dict) else "",
           "zpa_gateway": as_str((get(r, "zpaGateway") or {}).get("name")) if isinstance(get(r, "zpaGateway"), dict) else "",
           "wan_selection": as_str(get(r, "wanSelection")),
           "unevaluated": [label for k, label in UNEVALUATED if get(r, k)]}
    return out


def order_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Numbered rules first in order, then the predefined negative ones
    (-2 before -1), then rules without an order (assumption)."""
    def k(r):
        o = r["order"]
        if o is None:
            return (2, 0, r["index"])
        return (0, o, r["index"]) if o >= 0 else (1, o, r["index"])
    return sorted(rules, key=k)


def _names(refs: List[Dict[str, str]], n: int = 4) -> str:
    items = [f"“{x['name'] or x['id']}”" for x in refs[:n]]
    return ", ".join(items) + (f" and {len(refs) - n} more" if len(refs) > n else "")


def _criteria(r: Dict[str, Any], w: Dict[str, Any], groups: List[Dict[str, Any]], snap: Dict[str, Any], d: Dict[str, Any],
              ec: Optional[Dict[str, Any]], zpa_seg: Optional[Dict[str, Any]], zpa_read: bool) -> List[Dict[str, str]]:
    """Each criterion of a forwarding rule with its state."""
    crit: List[Dict[str, str]] = []
    src_groups = {as_str(get(g, "id")): g for g in snap.get("ip_source_groups") or [] if isinstance(g, dict)}
    dst_groups = {as_str(get(g, "id")): g for g in snap.get("ip_destination_groups") or [] if isinstance(g, dict)}
    if r["src_ips"] or r["src_ip_groups"]:
        entries = list(r["src_ips"])
        missing = []
        for ref in r["src_ip_groups"]:
            g = src_groups.get(ref["id"])
            if g is None:
                missing.append(ref)
            else:
                entries += [as_str(x) for x in get(g, "ipAddresses") or []]
        hit = _ip_in(w["ip"], entries) if w["ip"] else None
        state = "match" if hit else ("unknown" if hit is None or (missing and not hit) else "nomatch")
        crit.append({"name": "Source IP " + ", ".join(r["src_ips"][:3] + [f"group “{x['name'] or x['id']}”" for x in r["src_ip_groups"][:3]]), "state": state})
    if r["src_workload_groups"]:
        want = {(_lc(x["id"]), _lc(x["name"])) for x in r["src_workload_groups"]}
        rel = [g for g in groups if (_lc(g["id"]), _lc(g["name"])) in want or _lc(g["name"]) in {n for _, n in want if n} or (g["id"] and _lc(g["id"]) in {i for i, _ in want})]
        state = "match" if any(g["state"] == "match" for g in rel) else ("unknown" if any(g["state"] == "unknown" for g in rel) or not rel else "nomatch")
        crit.append({"name": f"Source workload group {_names(r['src_workload_groups'])}", "state": state})
    if r["ec_groups"]:
        if ec is None:
            state = "unknown"
        else:
            state = "match" if any(_lc(x["id"]) == _lc(ec["id"]) or (x["name"] and _lc(x["name"]) == _lc(ec["name"])) for x in r["ec_groups"]) else "nomatch"
        crit.append({"name": f"Connector group {_names(r['ec_groups'])}", "state": state})
    if r["dest_addresses"] or r["dest_ip_groups"]:
        entries = list(r["dest_addresses"])
        missing = False
        for ref in r["dest_ip_groups"]:
            g = dst_groups.get(ref["id"])
            if g is None:
                missing = True
            else:
                entries += [as_str(x) for x in get(g, "addresses") or []]
        if d["is_ip"]:
            hit = _ip_in(d["host"], entries)
            state = "match" if hit else ("unknown" if hit is None or missing else "nomatch")
        else:
            hit = _host_in(d["host"], entries)
            # A hostname cannot be compared with IP entries without resolving
            # it, which this tool never does: "unknown". Except the ZPA IP
            # pool (100.64.0.0/10): a hostname reaches it only as a ZPA
            # application, which an earlier ZPA rule forwards (assumed).
            ips = [e for e in entries if _is_address(e)]
            in_pool = bool(ips) and all(_within(e, ZPA_POOL) for e in ips)
            state = "match" if hit else ("unknown" if missing or (ips and not in_pool) else "nomatch")
        crit.append({"name": "Destination " + ", ".join(r["dest_addresses"][:3] + [f"group “{x['name'] or x['id']}”" for x in r["dest_ip_groups"][:3]]), "state": state})
    if (r["zpa_segments"] or r["zpa_segment_groups"]) and r["forward_method"] in ("ZPA", "ECZPA"):
        if not zpa_read:
            state = "unknown"
        elif zpa_seg is None:
            state = "nomatch"
        else:
            names = {_lc(x["name"]) for x in r["zpa_segments"]} | {_lc(x["id"]) for x in r["zpa_segments"]}
            gnames = {_lc(x["name"]) for x in r["zpa_segment_groups"]} | {_lc(x["id"]) for x in r["zpa_segment_groups"]}
            every = any(re.match(r"^zpa edge app segment$", x["name"] or "", re.I) for x in r["zpa_segments"])
            state = "match" if (every or _lc(zpa_seg["name"]) in names or _lc(zpa_seg["id"]) in names
                                or _lc(zpa_seg.get("segment_group_name")) in gnames or _lc(zpa_seg.get("segment_group_id")) in gnames) else "nomatch"
        crit.append({"name": f"ZPA application segment {_names(r['zpa_segments'] + r['zpa_segment_groups'])}", "state": state})
    for label in r["unevaluated"]:
        crit.append({"name": f"{label[0].upper() + label[1:]} (not evaluated)", "state": "unknown"})
    return crit


def find_ec_group(snap: Dict[str, Any], name: Optional[str]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    for g in snap.get("ec_groups") or []:
        if isinstance(g, dict) and _lc(name) in (_lc(get(g, "id")), _lc(get(g, "name"))):
            loc = get(g, "location")
            return {"id": as_str(get(g, "id")), "name": as_str(get(g, "name")), "location": as_str((loc or {}).get("name")) if isinstance(loc, dict) else "",
                    "found": True}
    return {"id": name, "name": name, "location": "", "found": False}


# ── evaluation ──────────────────────────────────────────────────────────
def evaluate(snap: Dict[str, Any], w: Dict[str, Any], d: Dict[str, Any], zpa_seg: Optional[Dict[str, Any]] = None,
             zpa_read: bool = False) -> Dict[str, Any]:
    """Which forwarding rule decides for workload `w` (workload_input)
    and destination `d` (zpa_path.destination). {go: zia | zpa | direct |
    local | proxy | drop | conditional | unknown, possible, rule, groups,
    modules, hops, impacts, notes}."""
    cols = snap.get("collections") or {}
    groups = membership(snap, w)
    ec = find_ec_group(snap, w["connector_group"])
    member_names = [g["name"] for g in groups if g["state"] == "match"]
    mods: List[Dict[str, Any]] = []
    hops: List[Dict[str, Any]] = []
    tags_txt = ", ".join(f"{(t['type'] + ':') if t['type'] else ''}{t['key']}={t['value']}" for t in w["tags"][:6]) or "none given"
    wl_notes = [f"Source IP {w['ip'] or 'not given'}; tags: {tags_txt}."]
    if snap.get("workload_groups") is None:
        wl_notes.append("The workload groups could not be read, so membership is unknown.")
    mods.append(zpa_path.module_hop("Workload groups", "matched" if member_names else ("unknown" if any(g["state"] == "unknown" for g in groups) else "not_matched"),
                                    None, [], [{"name": f"“{g['name']}”: {g['why']}", "state": g["state"]} for g in groups[:20]], wl_notes, key="workload_groups"))
    hops.append(zpa_path.flow_hop("workload", "Workload", "pass", wl_notes[0] + (f" Member of {', '.join(member_names[:4])}." if member_names else "")))
    if ec is not None:
        ec_note = f"Connector group “{ec['name']}”" + (f", ZIA location “{ec['location']}”." if ec["location"] else ".") + \
            ("" if ec["found"] else " (not found in the connector groups read)")
    else:
        ec_note = "No connector group was given: rules that name one depend on it."

    rules = snap.get("forwarding_rules")
    if rules is None:
        reason = "The connector traffic forwarding rules could not be read" + (f" ({cols['forwarding_rules']['error']})" if (cols.get("forwarding_rules") or {}).get("error") else "") + \
            ", so where the connector sends this traffic is unknown."
        mods.append(zpa_path.module_hop("Connector forwarding", "unknown", None, [], [], [reason, ec_note], key="connector_forwarding"))
        hops.append(zpa_path.flow_hop("connector", "Connector forwarding", "unknown", reason))
        return {"go": "unknown", "possible": ["zia", "zpa", "direct", "local", "proxy", "drop"], "rule": None, "groups": groups, "connector_group": ec,
                "modules": mods, "hops": hops, "headline": reason, "impacts": [], "walked": []}
    norm = order_rules([normalize_rule(r, i) for i, r in enumerate(rules) if isinstance(r, dict)])
    walked, cond = [], []
    decided = None
    for r in norm:
        if r["state"] == "DISABLED":
            walked.append({"name": r["name"], "order": r["order"], "status": "disabled"})
            continue
        crit = _criteria(r, w, groups, snap, d, ec, zpa_seg, zpa_read)
        states = {c["state"] for c in crit}
        status = "not_matched" if "nomatch" in states else ("conditional" if "unknown" in states else "matched")
        row = {"name": r["name"], "order": r["order"], "status": status, "method": r["forward_method"], "criteria": crit}
        walked.append(row)
        if status == "conditional":
            cond.append((r, row))
        elif status == "matched":
            decided = (r, row)
            break
    go_of = lambda r: FORWARD.get(r["forward_method"], ("zia", f"forward method {r['forward_method']}"))[0]  # noqa: E731
    go = go_of(decided[0]) if decided else "zia"
    possible = sorted({go_of(r) for r, _ in cond} | {go})
    overlaps = [f"“{r['name']}” (order {r['order']}, {r['forward_method']}) could decide instead: "
                + ", ".join(c["name"] for c in row["criteria"] if c["state"] == "unknown")[:240] for r, row in cond[:8]]
    if decided:
        r, row = decided
        words = FORWARD.get(r["forward_method"], ("zia", f"forward method {r['forward_method']}"))[1]
        via = f" through gateway “{r['proxy_gateway'] or r['zpa_gateway']}”" if (r["proxy_gateway"] or r["zpa_gateway"]) else ""
        note = f"Rule “{r['name']}” (order {r['order']}) decides: {words}{via}."
        notes = [note, ec_note] + ([f"WAN selection: {r['wan_selection']}."] if r["wan_selection"] and r["wan_selection"].upper() not in ("NONE", "INVALID") else [])
        crit = row["criteria"] or [{"name": "No criteria: the rule matches all traffic", "state": "match"}]
        rule_ref = {"name": r["name"], "order": r["order"]}
    else:
        note = "No forwarding rule matches, so the connector forwards the traffic to ZIA (assumed default)."
        notes, crit, rule_ref = [note, ec_note], [], None
    verdict = "conditional" if len(possible) > 1 else {"drop": "dropped", "direct": "bypassed", "local": "bypassed", "proxy": "bypassed"}.get(go, "forwarded")
    mods.append(zpa_path.module_hop("Connector forwarding", verdict, rule_ref, overlaps, crit, notes, key="connector_forwarding"))
    status = {"dropped": "blocked", "bypassed": "bypass", "conditional": "conditional"}.get(verdict, "pass")
    hops.append(zpa_path.flow_hop("connector", "Connector forwarding", status, note, {"name": rule_ref["name"], "order": rule_ref["order"], "action": decided[0]["forward_method"]} if decided else None))
    impacts = []
    if len(possible) > 1:
        impacts.append({"hop": "connector", "label": "Connector forwarding", "status": "conditional", "rule": None, "severity": "medium",
                        "detail": "An earlier forwarding rule depends on criteria not given or not evaluated: " + "; ".join(overlaps[:3]), "fix": None})
    return {"go": go if len(possible) == 1 else "conditional", "possible": possible, "rule": rule_ref, "method": decided[0]["forward_method"] if decided else "ZIA",
            "groups": groups, "connector_group": ec, "modules": mods, "hops": hops, "headline": note, "impacts": impacts, "walked": walked[:60]}
