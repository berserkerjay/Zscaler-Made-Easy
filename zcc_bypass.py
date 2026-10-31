"""Client Connector bypasses on a traced path: which list decides.

The Path analyzer's Client Connector step (data_flow.trace) asks, in this
order, whether the device sends a destination around Zscaler, and names
the list and the entry that decided:

  1. VPN gateway bypass        the app profile's vpnGateways (host names
                               or addresses of the VPN concentrators, sent
                               direct so a VPN client can connect)
  2. Destination bypasses      the app profile's host name and address
                               bypass lists (read by data_flow)
  3. IP-based app bypass       the app profile's bypassAppIds and
                               appServiceIds (predefined IP-based apps),
                               bypassCustomAppIds (custom IP-based apps),
                               each resolved to its definition's addresses,
                               ports and protocols
  4. Application bypass        an application named in the profile's
                               bypass list (by name)
  5. Forwarding mode           None sends it direct; Enforce proxy (PAC)
                               and Z-Tunnel 1.0 carry web traffic only
                               (Z-Tunnel 1.0: TCP ports 80 and 443);
                               Z-Tunnel 2.0 carries every port and protocol
                               except its own destination exclusions, and
                               only its inclusions when they are limited
  6. PAC file                  evaluated by pac_eval, never run (data_flow)

A destination the definitions cannot settle stays unknown: a host name is
never resolved, a definition that could not be read is "could not be
read", never "no bypass". Every field name below is from the SDK
(zscaler-sdk-python 1.11.3, zscaler/zcc):

  models/webpolicy.py          PolicyExtension.vpn_gateways (vpnGateways),
                               packet_tunnel_dns_include_list / _exclude_list,
                               WebPolicy.bypass_app_ids (bypassAppIds),
                               bypass_custom_app_ids (bypassCustomAppIds),
                               app_service_ids (appServiceIds)
  custom_ip_base_apps.py       GET /zcc/papi/public/v1/custom-ip-based-apps,
                               body {customAppContracts: [...]}
  predefined_ip_based_apps.py  GET /zcc/papi/public/v1/predefined-ip-based-apps,
                               body {appServiceContracts: [...]}
  models/custom_ip_base_apps.py, models/predefined_ip_based_apps.py
                               appName, appDataBlob / appDataBlobV6:
                               [{proto, port, ipaddr, fqdn}]
  web_app_service.py           GET /zcc/papi/public/v1/webAppService/listByCompany

ASSUMED lists what the SDK does not say.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import zia_path_modules as _zpm

ASSUMED = [
    "bypassAppIds and appServiceIds name predefined IP-based applications (or web app services) and bypassCustomAppIds names custom "
    "IP-based applications; an id is looked up there first, then in the other definitions (the SDK names the fields, not what they point to).",
    "An IP-based application definition bypasses a destination when its address (ipaddr) or host name (fqdn) matches, and its port and "
    "protocol, when given, match the traffic; a port or protocol left empty or '*' matches any.",
    "Z-Tunnel 1.0 (and Tunnel with local proxy) carries web traffic on TCP ports 80 and 443 only; other traffic leaves the device directly. "
    "With the app profile's 'Use proxy port for Z-Tunnel 1.0' on (useProxyPortForT1), traffic on another web port may be carried, so it is unknown.",
    "Enforce proxy (PAC) carries web traffic only (what the browser sends to the proxy); other traffic leaves the device directly.",
    "Z-Tunnel 2.0's domain inclusions and exclusions (packetTunnelDnsIncludeList / packetTunnelDnsExcludeList) decide where the DNS lookup "
    "is resolved, not whether the traffic is tunnelled; the address lists decide that.",
    "VPN gateway entries are host names or addresses, optionally with a port, which is ignored.",
]

T1_PORTS = (80, 443)
MAX_ENTRIES = 2000
MAX_APPS = 2000
SOURCES = {
    # source: (logical endpoint the assessment client resolves, list keys in the body, label)
    "predefined": ("/zcc/predefinedIpBasedApps", ("appServiceContracts",), "predefined IP-based application"),
    "custom": ("/zcc/customIpBasedApps", ("customAppContracts",), "custom IP-based application"),
    "service": ("/zcc/webAppService", ("webAppServiceContracts", "appServiceContracts"), "app service"),
}
# Which definitions an id list names first (ASSUMED above).
ID_FIELDS = {"predefined": ("bypassAppIds", "bypassMacAppIds"), "custom": ("bypassCustomAppIds",), "service": ("appServiceIds",)}
LOOKUP_ORDER = {"predefined": ("predefined", "service", "custom"), "service": ("service", "predefined", "custom"),
                "custom": ("custom", "predefined", "service")}


# ── Reading the profile's lists ────────────────────────────────────────
def split_entries(v: Any) -> List[str]:
    """A list or a comma, semicolon or line separated string as entries;
    "[FF00::/8]" (the portal's IPv6 spelling) loses its brackets; anything
    else (a number, an object) is none."""
    if isinstance(v, str):
        items: List[Any] = re.split(r"[,;\s]+", v)
    elif isinstance(v, (list, tuple)):
        items = []
        for x in v:
            if isinstance(x, dict):
                x = x.get("value") or x.get("name") or x.get("ip") or x.get("host") or ""
            if isinstance(x, (str, int)) and not isinstance(x, bool):
                items.append(str(x))
    else:
        return []
    out = []
    for x in items:
        s = str(x).strip()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1].strip()
        if s and s not in out:
            out.append(s[:300])
        if len(out) >= MAX_ENTRIES:
            break
    return out


def _extension(raw: Dict[str, Any]) -> Dict[str, Any]:
    ext = raw.get("policyExtension") or raw.get("policy_extension")
    if isinstance(ext, str):
        try:
            ext = json.loads(ext)
        except (ValueError, RecursionError):
            ext = None
    return ext if isinstance(ext, dict) else {}


def _norm(k: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def _union(raw: Dict[str, Any], *names: str) -> List[str]:
    """Every entry under any of `names` (any casing) at the top level, in
    policyExtension and in the platform policies, in that order."""
    want = {_norm(n) for n in names}
    out: List[str] = []
    places = [raw, _extension(raw)] + [v for k, v in raw.items() if isinstance(v, dict) and re.search(r"policy$", str(k), re.I)
                                       and not re.search(r"extension", str(k), re.I)]
    for d in places:
        for k, v in d.items():
            if _norm(k) in want:
                for e in split_entries(v):
                    if e not in out:
                        out.append(e)
    return out[:MAX_ENTRIES]


def _flag(raw: Dict[str, Any], name: str) -> bool:
    for d in (raw, _extension(raw)):
        for k, v in d.items():
            if _norm(k) == _norm(name):
                return str(v).strip().lower() in ("1", "true", "on", "yes")
    return False


def profile_lists(raw: Dict[str, Any]) -> Dict[str, Any]:
    """The bypass lists of one app profile as read (any of the API's
    spellings): VPN gateways, Z-Tunnel 2.0's domain lists, the IP-based
    application ids per kind and the Z-Tunnel 1.0 proxy-port switch."""
    raw = raw if isinstance(raw, dict) else {}
    return {"vpn_gateways": _union(raw, "vpnGateways", "vpnGatewayBypass", "vpnGatewayBypasses"),
            "dns_exclude": _union(raw, "packetTunnelDnsExcludeList"),
            "dns_include": _union(raw, "packetTunnelDnsIncludeList"),
            "ip_app_ids": {kind: _union(raw, *fields) for kind, fields in ID_FIELDS.items()},
            "proxy_port_t1": _flag(raw, "useProxyPortForT1")}


# ── IP-based application definitions ───────────────────────────────────
def _blob_items(v: Any) -> List[Dict[str, Any]]:
    items = v if isinstance(v, list) else [v] if v not in (None, "") else []
    out = []
    for x in items[:MAX_ENTRIES]:
        if isinstance(x, str):
            try:
                x = json.loads(x)
            except (ValueError, RecursionError):
                x = {"ipaddr": x}
        if isinstance(x, dict):
            out.append(x)
        elif isinstance(x, list):
            out += [y for y in x[:MAX_ENTRIES] if isinstance(y, dict)]
    return out


def normalize_apps(body: Any, source: str) -> Dict[str, Dict[str, Any]]:
    """{id: {id, name, source, entries: [{ips, fqdns, ports, proto}]}} from a
    definitions list as the API answers it (a list, or a body holding it).
    An app is known by its id and by its appSvcId."""
    keys = SOURCES[source][1]
    items = body if isinstance(body, list) else next((body[k] for k in keys + ("list", "items", "data") if isinstance(body, dict) and isinstance(body.get(k), list)), [])
    out: Dict[str, Dict[str, Any]] = {}
    for a in items[:MAX_APPS]:
        if not isinstance(a, dict):
            continue
        name = str(a.get("appName") or a.get("name") or a.get("appSvcName") or a.get("id") or "?")[:120]
        entries = []
        for b in _blob_items(a.get("appDataBlob")) + _blob_items(a.get("appDataBlobV6")):
            entries.append({"ips": split_entries(b.get("ipaddr") or b.get("ip") or b.get("ipAddress")),
                            "fqdns": split_entries(b.get("fqdn") or b.get("domain")),
                            "ports": split_entries(b.get("port") if not isinstance(b.get("port"), int) else str(b.get("port"))),
                            "proto": str(b.get("proto") or b.get("protocol") or "").strip().lower()[:20]})
        rec = {"id": str(a.get("id")), "name": name, "source": source, "active": a.get("active"), "entries": entries[:MAX_ENTRIES]}
        for k in ("id", "appSvcId"):
            if a.get(k) not in (None, ""):
                out.setdefault(str(a[k]), rec)
    return out


def read_ip_apps(get: Callable[..., Any], kinds: Iterable[str], stop: Callable[[], None] = lambda: None) -> Dict[str, Any]:
    """Read the definitions the profiles name: {apps: {source: {id: app}},
    status: {source: read | unverified}, errors: [...]}. A refusal is
    recorded, never raised (and never read as "no definition")."""
    out: Dict[str, Any] = {"apps": {}, "status": {}, "errors": []}
    for source in kinds:
        if source not in SOURCES:
            continue
        ep = SOURCES[source][0]
        stop()
        try:
            body, code = get(ep)
        except Exception as e:  # noqa: BLE001 — recorded, never raised
            if type(e).__name__ == "ReadStopped":
                raise
            out["status"][source] = "unverified"
            out["errors"].append(f"{ep}: {type(e).__name__}: {str(e)[:160]}")
            continue
        if code not in (200, 204) or isinstance(body, dict) and body.get("error"):
            out["status"][source] = "unverified"
            out["errors"].append(f"{ep}: HTTP {code}")
            continue
        out["apps"][source] = normalize_apps(body if code == 200 else [], source)
        out["status"][source] = "read"
    return out


# ── Matching ───────────────────────────────────────────────────────────
def host_hit(entries: Iterable[str], host: str) -> Optional[str]:
    """The first host name entry that names `host` (itself, a "*." or "."
    domain, or a wildcard); an address entry never matches a host name."""
    h = str(host or "").lower().rstrip(".")
    if not h:
        return None
    for raw in entries:
        e = _zpm.entry_host(re.sub(r"^[a-z]+://", "", str(raw or "").strip().lower()).split("/")[0])
        if not e or _zpm._is_ip_entry(e):
            continue
        if e.count(":") == 1:
            e = e.split(":", 1)[0]
        if e == "*" or h == e.lstrip("*.") or h.endswith("." + e.lstrip("*.")) or fnmatch.fnmatchcase(h, e):
            return str(raw)
    return None


def _addr_entry(raw: str) -> str:
    """An address entry without a port (203.0.113.5:443) or brackets."""
    s = str(raw or "").strip()
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")]
    if s.count(":") == 1 and "." in s:
        return s.split(":", 1)[0]
    return s


def ip_hit(entries: Iterable[str], ip: Any) -> Optional[str]:
    if ip is None:
        return None
    for raw in entries:
        if _zpm._ip_rel(ip, _addr_entry(raw)):
            return str(raw)
    return None


def _ports_state(ports: List[str], port: Optional[int]) -> str:
    if not ports or any(p in ("*", "0", "any", "all", "1-65535", "0-65535") for p in (x.lower() for x in ports)):
        return "match"
    if port is None:
        return "unknown"
    for p in ports:
        a, _, b = p.partition("-")
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            return "unknown"
        if lo <= port <= hi:
            return "match"
    return "no_match"


_PROTO = {"tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp"}


def _proto_state(proto: str, want: Optional[str]) -> str:
    p = (proto or "").lower()
    if p in ("", "*", "any", "all", "0", "tcp_udp", "tcpudp", "both"):
        return "match"
    got = _PROTO.get(p)
    if got is None or want is None:
        return "unknown"
    return "match" if got == want else "no_match"


def app_hit(app: Dict[str, Any], ip: Any, host: str, proto: Optional[str], port: Optional[int]) -> Tuple[str, str]:
    """(match | no_match | unknown | needs_ip, what) for one IP-based app
    definition: needs_ip when only its addresses could match and the
    destination is a host name that is not resolved."""
    needs = ""
    unknown = ""
    for e in app.get("entries") or []:
        ps, pr = _ports_state(e.get("ports") or [], port), _proto_state(e.get("proto") or "", proto)
        where = (f" port {','.join(e['ports'])}" if e.get("ports") else "") + (f" {e['proto'].upper()}" if e.get("proto") else "")
        hit = ip_hit(e.get("ips") or [], ip) if ip is not None else None
        hit = hit or (host_hit(e.get("fqdns") or [], host) if host and ip is None else None)
        if hit:
            if ps == "match" and pr == "match":
                return "match", f"{hit}{where}"
            if "no_match" not in (ps, pr):
                unknown = unknown or f"{hit}{where} (the port or protocol could not be compared)"
            continue
        if ip is None and e.get("ips") and ps != "no_match" and pr != "no_match" and not needs:
            needs = _zpm._short(e["ips"], 3)
    if unknown:
        return "unknown", unknown
    if needs:
        return "needs_ip", needs
    return "no_match", ""


# ── The checks ─────────────────────────────────────────────────────────
def _c(name: str, state: str, detail: str) -> Dict[str, str]:
    return {"name": name, "state": state, "detail": detail}


def vpn_check(lists: Dict[str, Any], host: str, ip: Any) -> Tuple[Dict[str, str], Optional[str]]:
    gw = lists.get("vpn_gateways") or []
    if not gw:
        return _c("VPN gateway bypass", "no_match", "None configured."), None
    hit = ip_hit(gw, ip) if ip is not None else host_hit(gw, host)
    if hit:
        return _c("VPN gateway bypass", "match", f"{hit} is a VPN gateway: Client Connector sends it direct so the VPN client can connect."), hit
    named = [g for g in gw if not _zpm._is_ip_entry(_addr_entry(g))]
    note = ""
    if ip is not None and named:
        note = f" {len(named)} gateway(s) are host names ({_zpm._short(named, 3)}); the address is assumed not to be theirs."
    elif ip is None and len(named) < len(gw):
        note = " The gateway addresses apply if the host resolves into them; it is not resolved."
    return _c("VPN gateway bypass", "no_match", f"Not one of the {len(gw)} VPN gateway(s).{note}"), None


def ip_app_check(lists: Dict[str, Any], apps: Dict[str, Any], host: str, ip: Any, proto: Optional[str], port: Optional[int]
                 ) -> Tuple[Dict[str, str], Optional[Dict[str, str]], List[str]]:
    """The IP-based application bypass: (criterion, the app and entry that
    decided or None, notes)."""
    ids = lists.get("ip_app_ids") or {}
    named = [(kind, i) for kind in ("predefined", "custom", "service") for i in ids.get(kind) or []]
    if not named:
        return _c("IP-based application bypass", "no_match", "None configured."), None, []
    defs = (apps or {}).get("apps") or {}
    status = (apps or {}).get("status") or {}
    unread, missing, needs, unknown = [], [], [], []
    for kind, i in named:
        app = next((defs.get(s, {}).get(str(i)) for s in LOOKUP_ORDER[kind] if defs.get(s, {}).get(str(i))), None)
        if app is None:
            if any(status.get(s) != "read" for s in LOOKUP_ORDER[kind]):
                unread.append(str(i))
            else:
                missing.append(str(i))
            continue
        state, what = app_hit(app, ip, host, proto, port)
        label = f"{SOURCES[app['source']][2]} '{app['name']}'"
        if state == "match":
            return (_c("IP-based application bypass", "match", f"{label} covers {what}: its traffic leaves the device directly."),
                    {"name": app["name"], "entry": what, "source": app["source"], "id": app["id"]}, [])
        if state == "unknown":
            unknown.append(f"{label}: {what}")
        elif state == "needs_ip":
            needs.append(f"{label} ({what})")
    notes = []
    if missing:
        notes.append(f"The app profile names IP-based application id(s) the tenant does not define ({_zpm._short(missing, 3)}); they bypass nothing.")
    if needs:
        notes.append(f"IP-based application bypass {_zpm._short(needs, 3)}: it applies only if {host} resolves into those addresses; the host is "
                     "not resolved and is assumed to resolve outside them.")
    if unknown:
        return _c("IP-based application bypass", "unknown", "Could not be settled: " + "; ".join(unknown[:3]) + "."), None, notes
    if unread:
        why = f"{len(unread)} IP-based application definition(s) the profile names could not be read ({_zpm._short(unread, 3)})"
        if ip is not None:
            return _c("IP-based application bypass", "unknown", why + ", so whether they bypass this address is unknown."), None, notes
        notes.append(why + "; they are assumed not to name this host.")
    return _c("IP-based application bypass", "no_match", f"None of the {len(named)} IP-based application(s) covers this destination."), None, notes


def tunnel_check(mode_label: str, mode_kind: str, prof: Optional[Dict[str, Any]], host: str, ip: Any,
                 traffic: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """What the forwarding mode carries: {state: tunnelled | direct |
    unknown, criterion, title, fix, why} for this traffic. `traffic` None
    is HTTPS on TCP/443 (the Data Flow Map's assumption)."""
    proto = (traffic or {}).get("protocol") or "tcp"
    port = (traffic or {}).get("port") or 443
    web = (traffic or {}).get("web", True)
    label = (traffic or {}).get("label") or f"{proto.upper()}/{port}"
    lists = (prof or {}).get("lists") or {}
    if mode_kind == "pac":
        if not web:
            return {"state": "direct", "criterion": _c("Forwarding mode", "match", f"{mode_label} carries web traffic only: {label} goes direct."),
                    "title": "Non-web traffic not forwarded", "why": f"{mode_label} carries only web traffic, so {label} leaves the device directly and never reaches ZIA.",
                    "fix": "Use Z-Tunnel 2.0 so every port and protocol reaches the Cloud Firewall."}
        return {"state": "tunnelled", "criterion": _c("Forwarding mode", "no_match", f"{mode_label}: web traffic goes to the proxy the PAC file names (see PAC file).")}
    if mode_label in ("Z-Tunnel 1.0", "Tunnel with local proxy"):
        if proto == "tcp" and port in T1_PORTS:
            return {"state": "tunnelled", "criterion": _c("Forwarding mode", "no_match", f"{mode_label} carries TCP ports 80 and 443: {label} is tunnelled.")}
        if web and proto == "tcp" and lists.get("proxy_port_t1"):
            return {"state": "unknown", "criterion": _c("Forwarding mode", "unknown", f"{mode_label} carries TCP 80 and 443; the app profile's proxy port option may also carry {label}."),
                    "why": f"{mode_label} with the proxy port option: whether {label} is carried is not known"}
        title = "Non-web traffic not forwarded" if not web else "Port not carried by Z-Tunnel 1.0"
        return {"state": "direct", "criterion": _c("Forwarding mode", "match", f"{mode_label} carries web traffic on TCP ports 80 and 443 only: {label} goes direct."),
                "title": title, "why": f"{mode_label} carries only web traffic on TCP ports 80 and 443, so {label} leaves the device directly and never reaches ZIA.",
                "fix": "Use Z-Tunnel 2.0 so every port and protocol reaches the Cloud Firewall."}
    if mode_label == "Z-Tunnel 2.0":
        return {"state": "tunnelled", "criterion": _c("Forwarding mode", "no_match", f"Z-Tunnel 2.0 carries every port and protocol, {label} included, unless its own lists leave it out.")}
    return {"state": "tunnelled", "criterion": _c("Forwarding mode", "no_match", f"{mode_label}: tunnelled.")}


def tunnel2_lists(prof: Dict[str, Any], host: str, ip: Any) -> Dict[str, Any]:
    """Z-Tunnel 2.0's own lists: {state: in | out | unknown, criteria,
    entry, why, notes}. An address in the exclusions, or outside limited
    inclusions of its family, is not tunnelled; a host name is not
    resolved, so limited inclusions leave it unknown."""
    tl = prof.get("tunnel") or {}
    lists = prof.get("lists") or {}
    ex, inc = list(tl.get("exclude") or []), list(tl.get("include") or [])
    crit, notes = [], []
    out: Dict[str, Any] = {"state": "in", "entry": None, "why": "", "notes": notes, "criteria": crit}
    if ip is not None:
        hit = next((e for e in ex if _zpm._ip_rel(ip, e)), None)
        fam = [e for e in inc if _zpm._parse_entry(str(e).strip()) is not None and _family(e) == ip.version]
        if hit:
            crit.append(_c("Z-Tunnel 2.0 destination exclusions", "match", f"{hit} is excluded from the packet tunnel."))
            out.update(state="out", entry=hit, why=f"the app profile '{prof['name']}' excludes {hit} from the packet tunnel")
        else:
            crit.append(_c("Z-Tunnel 2.0 destination exclusions", "no_match", f"Not in the {len(ex)} exclusion(s)." if ex else "None configured."))
        if not hit:
            if fam and not any(_zpm._ip_rel(ip, e) for e in fam):
                crit.append(_c("Z-Tunnel 2.0 destination inclusions", "match", f"The packet tunnel takes only {_zpm._short(fam, 3)}."))
                out.update(state="out", entry=_zpm._short(fam, 3), why=f"the app profile '{prof['name']}' tunnels only {_zpm._short(fam, 3)}")
            else:
                crit.append(_c("Z-Tunnel 2.0 destination inclusions", "no_match",
                               "Inside the inclusions." if fam else f"No IPv{ip.version} inclusion list limits the tunnel."))
    else:
        public = [e for e in ex if _zpm._is_ip_entry(e) and not _local(e)]
        named = [e for e in ex if not _zpm._is_ip_entry(e)]
        hit = host_hit(named, host)
        if hit:
            crit.append(_c("Z-Tunnel 2.0 destination exclusions", "match", f"{hit} is excluded from the packet tunnel."))
            out.update(state="out", entry=hit, why=f"the app profile '{prof['name']}' excludes {hit} from the packet tunnel")
        else:
            crit.append(_c("Z-Tunnel 2.0 destination exclusions", "no_match",
                           (f"{len(public)} public address exclusion(s) apply if {host} resolves into them; it is not resolved." if public else
                            "Only private ranges are excluded; a public host is assumed to resolve outside them." if ex else "None configured.")))
        limited = [e for e in inc if _zpm._is_ip_entry(e) and str(e).strip() not in ("0.0.0.0/0", "::/0")]
        whole = any(str(e).strip() in ("0.0.0.0/0", "::/0", "*") for e in inc)
        if not hit and limited and not whole:
            crit.append(_c("Z-Tunnel 2.0 destination inclusions", "unknown",
                           f"The packet tunnel takes only {_zpm._short(limited, 3)}; whether {host} resolves into them is not known (it is not resolved)."))
            out.update(state="unknown", why=f"Z-Tunnel 2.0 tunnels only {_zpm._short(limited, 3)} and {host} is not resolved")
        elif not hit:
            crit.append(_c("Z-Tunnel 2.0 destination inclusions", "no_match", "Every address is included." if whole or not inc else "Inside the inclusions."))
    dx = host_hit(lists.get("dns_exclude") or [], host) if ip is None else None
    di = host_hit(lists.get("dns_include") or [], host) if ip is None else None
    if dx:
        notes.append(f"Z-Tunnel 2.0's domain exclusions name {dx}: its DNS lookup is resolved outside the tunnel; the traffic follows the address lists.")
    elif di and di != "*":
        notes.append(f"Z-Tunnel 2.0's domain inclusions name {di}: its DNS lookup goes through the tunnel.")
    return out


def _family(entry: str) -> Optional[int]:
    p = _zpm._parse_entry(str(entry).strip())
    return None if p is None else (p[1].version if p[0] == "range" else p[1].version)


_LOCAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                                            "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32", "fc00::/7", "fe80::/10", "ff00::/8", "::1/128")]


def _local(entry: str) -> bool:
    p = _zpm._parse_entry(str(entry).strip())
    if p is None:
        return False
    nets = [ipaddress.ip_network(f"{p[1]}/{p[1].max_prefixlen}"), ipaddress.ip_network(f"{p[2]}/{p[2].max_prefixlen}")] if p[0] == "range" else [p[1]]
    return all(any(n.version == l.version and n.subnet_of(l) for l in _LOCAL) for n in nets)


def module(verdict: str, decided: Optional[Dict[str, Any]], criteria: List[Dict[str, str]], notes: List[str], detail: str) -> Dict[str, Any]:
    """The Client Connector step in the shape every Path analyzer module
    shares (zia_path_modules.module_hop): the list that decided is the
    rule, every list checked a criterion."""
    rule = {"name": f"{decided['list']}: {decided['entry']}", "order": None} if decided else None
    return _zpm.module_hop("Client Connector", verdict, rule, key="zcc", criteria=criteria, notes=notes, detail=detail)
