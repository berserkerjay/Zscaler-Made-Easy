"""ZIA app services and app service groups as a rule criterion: match,
no match or unknown, and why.

A Cloud Firewall rule (zscaler-sdk-python 1.11.3 zia/models/
cloud_firewall_rules.py appServices, appServiceGroups) can name
Zscaler-managed app services and app service groups, such as OFFICE365,
the only criterion of the predefined "Office 365 One Click Rule". The ZIA
API gives each one's id and name only (zia/models/
cloud_firewall_app_services.py: id, name, isNameL10nTag), and the SDK has
no endpoint that lists their members, so the tenant itself says nothing
about which destinations they hold.

What else was considered and is not used: Client Connector's IP-based
apps (zcc/predefined_ip_based_apps.py, zcc/web_app_service.py,
appDataBlob) list addresses for apps Client Connector bypasses. They are
a different object, and nothing in the SDK ties one to a ZIA app service
(an appSvcId there is not documented as a ZIA app service id), so taking
their addresses as a group's members would be a guess.

So membership comes from one source: Microsoft's published Microsoft 365
endpoint list (m365_endpoints), for the app services and groups this
module recognises as Microsoft 365 by name (M365_NAMES; the names are
assumed, as Zscaler does not publish them through the API). Zscaler
builds those groups from that list (assumed from its One Click
documentation). Every other app service, a missing list and a stale list
leave the criterion "unknown", as it always was.

Within the criterion the app services and groups a rule names are
alternatives (any one is enough, assumed: they are one field in the
console). A destination is:
  match      in a published host name or range of a Microsoft 365
             service area the rule names, on a port Microsoft publishes
             for that endpoint set (when it publishes ports);
  no match   an IP address in none of the published ranges of its
             family, when every app service the rule names is Microsoft
             365 and the list is current;
  unknown    otherwise: a host name not in the list (its address is
             not resolved here, and might be in a published range), a
             port Microsoft does not list for the set (whether Zscaler's
             group is limited to those ports is not published), an app
             service that is not Microsoft 365, no list or a stale one.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

import m365_endpoints

ALL = frozenset({"*"})
_MS_PREFIX = ("OFFICE365", "O365", "M365", "MICROSOFT365", "MICROSOFTOFFICE365")
# Normalised names (upper case, letters and digits) -> the Microsoft 365
# service areas they hold. Assumed: Zscaler's app service names are not in
# the SDK or the API reference; OFFICE365 is the predefined group the One
# Click rule names.
M365_NAMES: Dict[str, frozenset] = {
    **{n: ALL for n in _MS_PREFIX},
    "EXCHANGEONLINE": frozenset({"Exchange"}),
    "SHAREPOINTONLINE": frozenset({"SharePoint"}), "FILESHAREPTONEDRIVE": frozenset({"SharePoint"}),
    "ONEDRIVEFORBUSINESS": frozenset({"SharePoint"}),
    "SKYPEFORBUSINESS": frozenset({"Skype"}), "MICROSOFTTEAMS": frozenset({"Skype"}),
}
_AREA_WORDS = (("EXCHANGE", "Exchange"), ("OUTLOOK", "Exchange"), ("SHAREP", "SharePoint"), ("ONEDRIVE", "SharePoint"),
               ("SKYPE", "Skype"), ("TEAMS", "Skype"), ("LYNC", "Skype"), ("COMMON", "Common"))
FIELDS = (("appServiceGroups", "group"), ("appServices", "service"))


def _norm(name: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(name or "").upper())


def m365_areas(name: Any) -> Optional[frozenset]:
    """The Microsoft 365 service areas an app service or group holds
    (ALL for the whole of Microsoft 365), or None when it is not one this
    module recognises."""
    n = _norm(name)
    if n in M365_NAMES:
        return M365_NAMES[n]
    for p in _MS_PREFIX:
        if n.startswith(p) and len(n) > len(p):
            areas = frozenset(a for w, a in _AREA_WORDS if w in n[len(p):])
            return areas or None
    return None


def _name(x: Any) -> str:
    if isinstance(x, dict):
        return str(x.get("name") or x.get("id") or "")
    return str(x or "")


def _get(rule: Dict[str, Any], camel: str) -> Any:
    if not isinstance(rule, dict):
        return None
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", camel).lower()
    for k in (camel, snake):
        if rule.get(k) is not None:
            return rule[k]
    return None


def named(rule: Dict[str, Any]) -> List[Tuple[str, str]]:
    """[(kind, name)] of the app service groups and app services a rule names."""
    out = []
    for field, kind in FIELDS:
        v = _get(rule, field)
        for x in v if isinstance(v, (list, tuple)) else ([v] if v else []):
            n = _name(x).strip()
            if n and n.upper() not in ("ANY", "NONE", "ALL"):
                out.append((kind, n))
    return out


def _short(items: List[str], n: int = 3) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def _label(items: List[Tuple[str, str]]) -> str:
    kinds = {k for k, _ in items}
    return "App service groups" if kinds == {"group"} else "App services" if kinds == {"service"} else "App services and groups"


def _areas_words(areas: frozenset) -> str:
    if "*" in areas:
        return "Microsoft 365"
    return "Microsoft 365 " + ", ".join(f"'{m365_endpoints.AREAS.get(a, a)}'" for a in sorted(areas))


def _in_areas(s: Dict[str, Any], areas: frozenset) -> bool:
    return "*" in areas or s["area"] in areas


def ports_words(s: Dict[str, Any]) -> str:
    def rng(v):
        return ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in v)
    parts = ([f"TCP {rng(s['tcp'])}"] if s["tcp"] else []) + ([f"UDP {rng(s['udp'])}"] if s["udp"] else [])
    return "; ".join(parts) or "no port listed"


def port_ok(s: Dict[str, Any], protocol: str, port: Optional[int]) -> bool:
    """Whether Microsoft publishes this endpoint set for the traffic's
    protocol and port (a set that lists no port at all: yes)."""
    if not s["tcp"] and not s["udp"]:
        return True
    if port is None:
        return False
    return any(a <= port <= b for a, b in s.get(str(protocol or "tcp").lower(), []))


# ── Which list a run uses ────────────────────────────────────────────
def _is_sample(client: Any) -> bool:
    if getattr(client, "offline", False) is not True:
        return False
    store = getattr(client, "store", None) or getattr(client, "_store", None)
    return getattr(store, "kind", None) == "sample"


_SAMPLE: Dict[str, Any] = {}


def sample_list() -> "m365_endpoints.EndpointList":
    """The sample tenant's short excerpt of Microsoft's list (sample_tenant.
    M365_ENDPOINTS_EXCERPT): used only for the sample tenant, and only
    when no list is kept."""
    if "list" not in _SAMPLE:
        import json
        import sample_tenant
        sets = m365_endpoints.parse(json.dumps(sample_tenant.M365_ENDPOINTS_EXCERPT))
        _SAMPLE["list"] = m365_endpoints.EndpointList(sets, {"source": "sample", "version": None, "fetched_at": None})
    return _SAMPLE["list"]


def current(client: Any = None) -> Optional["m365_endpoints.EndpointList"]:
    """The list a run uses: the one kept (fetched or imported); for the
    sample tenant with none kept, its excerpt; else None."""
    lst = m365_endpoints.load()
    if lst is None and _is_sample(client):
        return sample_list()
    return lst


def summary(lst: Optional["m365_endpoints.EndpointList"], now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """The list as a result names it: {present, describe, stale, version, source}."""
    if lst is None:
        return {"present": False, "describe": "no Microsoft 365 endpoint list is kept", "stale": None, "version": None, "source": None}
    return {"present": True, "describe": lst.describe(), "stale": lst.stale(now), "version": lst.version, "source": lst.meta.get("source")}


# ── The criterion ────────────────────────────────────────────────────
def criterion(rule: Dict[str, Any], host: str, ip: Any, traffic: Optional[Dict[str, Any]], lst: Optional["m365_endpoints.EndpointList"],
              *, check_ports: bool = True, now: Optional[_dt.datetime] = None) -> Optional[Dict[str, str]]:
    """The rule's app service criterion for the destination (`host`, and
    `ip` when it is an address), or None when the rule names none.
    {name, state: match | no_match | unknown, detail}."""
    items = named(rule)
    if not items:
        return None
    label = _label(items)
    what = _short([n for _, n in items])
    mapped = [(n, m365_areas(n)) for _, n in items]
    known = [(n, a) for n, a in mapped if a is not None]
    other = [n for n, a in mapped if a is None]

    def crit(state: str, detail: str) -> Dict[str, str]:
        return {"name": label, "state": state, "detail": detail}

    if not known:
        return crit("unknown", f"Applies only to {what}; Zscaler does not expose the members of app services through the API, "
                               "and no published list is used for these.")
    if lst is None:
        return crit("unknown", f"Applies only to {what}; Zscaler does not expose the members through the API. Turn on Microsoft's published "
                               "Microsoft 365 endpoint list in Advanced settings, or import it there, to evaluate "
                               f"{_short([n for n, _ in known])}.")
    if lst.stale(now):
        age = lst.age_days(now)
        return crit("unknown", f"Applies only to {what}; the Microsoft 365 endpoint list ({lst.describe()}) was last confirmed "
                               + (f"{int(age)} days ago" if age is not None else "on an unknown date")
                               + f", more than {m365_endpoints.max_age_days()} days, so it settles nothing. Refresh or import it again in Advanced settings.")
    areas = frozenset().union(*(a for _, a in known))
    subject = str(ip) if ip is not None else host
    hits = lst.lookup_ip(ip) if ip is not None else lst.lookup_host(host)
    hits = [(s, e) for s, e in hits if _in_areas(s, areas)]
    if hits:
        proto, port = (traffic or {}).get("protocol") or "tcp", (traffic or {}).get("port")
        good = [(s, e) for s, e in hits if not check_ports or port_ok(s, proto, port)]
        if good:
            s, e = good[0]
            member = next((n for n, a in known if _in_areas(s, a)), known[0][0])
            via = f"{e}, " if e != subject else ""
            return crit("match", f"{subject} is in Microsoft 365 '{s['area_name']}' (endpoint set {s['id']}: {via}{ports_words(s)}; "
                                 f"{lst.describe()}), which {member} holds.")
        s, e = hits[0]
        return crit("unknown", f"{subject} is in Microsoft 365 '{s['area_name']}' (endpoint set {s['id']}), which Microsoft publishes for "
                               f"{ports_words(s)}, not {str(proto).upper()}/{port}; whether Zscaler's {what} holds other ports is not published "
                               f"({lst.describe()}).")
    if other:
        return crit("unknown", f"Applies only to {what}; {subject} is not a published {_areas_words(areas)} endpoint ({lst.describe()}), "
                               f"and the members of {_short(other)} are not known.")
    if ip is not None:
        v = 4 if ip.version == 4 or ip.ipv4_mapped is not None else 6
        n = sum(1 for s in lst.sets if _in_areas(s, areas) for r in s["ips"] if ipaddress.ip_network(r, strict=False).version == v)
        if n:
            return crit("no_match", f"{subject} is in none of the {n} IPv{v} ranges Microsoft publishes for {_areas_words(areas)} "
                                    f"({lst.describe()}); {what} is taken to hold Microsoft's published endpoints.")
        return crit("unknown", f"Applies only to {what}; the Microsoft 365 endpoint list ({lst.describe()}) has no IPv{v} range to compare {subject} with.")
    if not any(s["ips"] for s in lst.sets if _in_areas(s, areas)):
        return crit("no_match", f"{host} is not one of the host names Microsoft publishes for {_areas_words(areas)} ({lst.describe()}).")
    return crit("unknown", f"{host} is not one of the host names Microsoft publishes for {_areas_words(areas)} ({lst.describe()}); "
                           "its IP address is not resolved here, so whether it falls in Microsoft's published ranges is not known.")


def _as_networks(d: str) -> Optional[List[Any]]:
    """An address entry as networks: [network] for an address or a CIDR
    block, the blocks of an a-b range ([] when it is not one this compares:
    families differ, reversed, or more than 64 blocks), None for a name."""
    try:
        return [ipaddress.ip_network(d, strict=False)]
    except ValueError:
        pass
    if "-" in d:
        try:
            a, b = (ipaddress.ip_address(x.strip()) for x in d.split("-", 1))
        except ValueError:
            return None
        if a.version != b.version or a > b:
            return []
        nets = list(ipaddress.summarize_address_range(a, b))
        return nets if len(nets) <= 64 else []
    return None


# ── Shadowed rules: does an earlier rule's app service hold every destination of a later rule? ──
def covers(a_rule: Dict[str, Any], b_dests: Iterable[Any], b_ports: Optional[List[Tuple[str, int, int]]],
           lst: Optional["m365_endpoints.EndpointList"], now: Optional[_dt.datetime] = None) -> Tuple[bool, str]:
    """(True, why) when every destination entry `b_dests` of a later rule
    (host names, '.domain' or '*.domain', addresses, CIDR blocks, a-b
    ranges) is a published Microsoft 365 endpoint of an area rule A's app
    services hold, on every protocol and port range in `b_ports`
    ([(tcp|udp, first, last)]; None: any port, which is not covered). The
    list must be current. (False, why not) otherwise: never a guess."""
    from zia_path_modules import entry_host
    known = [m365_areas(n) for _, n in named(a_rule)]
    known = [a for a in known if a is not None]
    if not known:
        return False, "its app services are not Microsoft 365"
    if lst is None or lst.stale(now):
        return False, "no current Microsoft 365 endpoint list"
    if not b_ports:
        return False, "the later rule is not limited to ports Microsoft publishes"
    areas = frozenset().union(*known)
    dests = [str(d).strip() for d in b_dests or [] if str(d).strip()]
    if not dests:
        return False, "the later rule names no destination"

    def ports_held(sets: List[Dict[str, Any]]) -> bool:
        return all(any(not (s["tcp"] or s["udp"]) or any(a <= lo and hi <= b for a, b in s.get(p, [])) for s in sets)
                   for p, lo, hi in b_ports)

    for d in dests:
        sets: List[List[Dict[str, Any]]] = []
        nets = _as_networks(d)
        if nets == []:
            return False, f"{d} is not a range this analysis compares"
        if nets is not None:
            for net in nets:
                sets.append([s for s, _ in lst.covers_net(net) if _in_areas(s, areas)])
        else:
            h = entry_host(re.sub(r"^[a-z][a-z0-9+.-]*://", "", d.lower()).split("/")[0].split(":")[0])
            if "*" in h[2:] or not h:
                return False, f"{d} is not a host name this analysis compares"
            apex = h[2:] if h.startswith("*.") else h[1:] if h.startswith(".") else h
            sets.append([s for s, _ in lst.lookup_host(apex) if _in_areas(s, areas)])
            if h != apex:
                sets.append([s for s, _ in lst.subdomains_covered(apex) if _in_areas(s, areas)])
        for group in sets:
            if not group:
                return False, f"{d} is not a published {_areas_words(areas)} endpoint"
            if not ports_held(group):
                return False, f"Microsoft does not publish {d} for every port the later rule allows"
    return True, f"every destination it names is a published {_areas_words(areas)} endpoint on the ports it allows ({lst.describe()})"
