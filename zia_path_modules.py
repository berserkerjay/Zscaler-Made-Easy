"""The ZIA modules the Path analyzer walks (listed module by module; no
claim is made about the order the cloud enforces them in), each with the rule that decides, the rules that also match, and
every criterion as match, no match or unknown.

The Path analyzer (path_analyzer.analyze) traces a destination through
Client Connector, forwarding and PAC, then ZIA's web controls
(data_flow.trace: Cloud App Control, URL filtering, SSL inspection, File
Type Control, Web DLP). This module adds the ZIA modules that trace does
not read and turns every ZIA step into one ordered pipeline:

  1. Advanced Threat Protection: the security exceptions and the
     malicious-URL list, the security policy allow and deny lists, the
     category toggles (malware, phishing, botnet, ...) and the blocked
     countries;
  2. Cloud Firewall: filtering rules with their network services and
     service groups, network application groups, IP destination and
     source groups, countries and the default rule;
  3. DNS Control: the firewall DNS rules, for the lookup of the hostname;
  4. Cloud App Control and URL filtering, as data_flow.trace decides them;
  5. Sandbox: the sandbox rules, for files on the decrypted path;
  6. File Type Control and Web DLP, as data_flow.trace decides them.

SSL inspection is a modifier, not a step that can be passed or failed on
its own here: it decides what the later modules can see (the full URL and
the content, or only the hostname and its category).

Traffic is more than web: the operator can give a protocol (TCP or UDP)
and a port. A well-known port table names the service (UDP/443 is QUIC,
TCP/22 is SSH). Only HTTP and HTTPS over TCP reach the web modules; other
traffic is decided by the Cloud Firewall (and reaches ZIA at all only
through Z-Tunnel 2.0 or a site tunnel).

Nothing is guessed. A condition this tool cannot evaluate (a time window,
device trust, user risk score, a user or group when the trace is for any
user, a source IP, a destination country, a hostname's IP address) is a
criterion with the state "unknown". A module decides only with a rule
whose every criterion matches; an earlier rule with an unknown criterion
and a different outcome makes the module "conditional", and so does an
unknown criterion on the deciding rule. The overall result says
"definite" or "conditional" and why.

Reads (read): only the sections the Scope page puts in scope (the
`atp`, `firewall`, `dns` and `sandbox` keys of data_flow.PATH_SECTIONS,
in scope when ZIA platform is ticked), through the assessment client,
whose session is paced for ZIA's read limit (zia_rate.attach); Stop is
honoured between every request. Every endpoint is in zscaler-sdk-python
1.11.3 (zia/atp_policy.py, zia/security_policy_settings.py,
zia/cloud_firewall_rules.py, zia/cloud_firewall.py,
zia/cloud_firewall_dns.py, zia/sandbox_rules.py). Read-only.
"""
from __future__ import annotations

import functools
import ipaddress
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# ── What is read ─────────────────────────────────────────────────────
# Scope table entries (merged into data_flow.PATH_SECTIONS): label, the
# scopes that put the section in scope, the Scope page channel (none: these
# are ZIA platform controls, not DLP channels).
SECTIONS: Dict[str, Tuple[str, Tuple[str, ...], Optional[str]]] = {
    "atp": ("Advanced Threat Protection settings and allow and deny lists", ("zia_extras",), None),
    "firewall": ("Cloud Firewall rules, network services and IP groups", ("zia_extras",), None),
    "dns": ("DNS Control rules", ("zia_extras",), None),
    "sandbox": ("Sandbox rules", ("zia_extras",), None),
}

# key -> [(part, endpoint, label, kind)]; kind "list" (a complete list of
# objects) or "object" (one settings object). The first part of a section
# is its primary read: without it the module cannot be evaluated.
READS: Dict[str, List[Tuple[str, str, str, str]]] = {
    "atp": [
        ("settings", "/zia/cyberThreatProtection/advancedThreatSettings", "ATP settings", "object"),
        ("exceptions", "/zia/cyberThreatProtection/securityExceptions", "ATP security exceptions", "object"),
        ("malicious", "/zia/cyberThreatProtection/maliciousUrls", "ATP malicious URLs", "object"),
        ("allowlist", "/zia/security", "Security policy allowlist", "object"),
        ("denylist", "/zia/security/advanced", "Security policy denylist", "object"),
    ],
    "firewall": [
        ("rules", "/zia/firewallFilteringRules", "Cloud Firewall rules", "list"),
        ("network_services", "/zia/networkServices", "Network services", "list"),
        ("network_service_groups", "/zia/networkServiceGroups", "Network service groups", "list"),
        ("network_app_groups", "/zia/networkApplicationGroups", "Network application groups", "list"),
        ("ip_destination_groups", "/zia/ipDestinationGroups", "IP destination groups", "list"),
        ("ip_source_groups", "/zia/ipSourceGroups", "IP source groups", "list"),
    ],
    "dns": [("rules", "/zia/firewallDnsRules", "DNS Control rules", "list")],
    "sandbox": [("rules", "/zia/sandboxRules", "Sandbox rules", "list")],
}
ENDPOINTS: List[str] = [ep for parts in READS.values() for _, ep, _, _ in parts]

# ── Well-known ports ─────────────────────────────────────────────────
# (protocol, first port, last port) -> service name, the network
# applications ZIA's firewall may identify on it, whether it is web
# traffic the proxy handles. The application names are the common ZIA
# network application names; a rule naming another application on that
# port is "unknown", never "no match".
WELL_KNOWN: List[Dict[str, Any]] = [
    {"name": "HTTP", "label": "HTTP (web)", "tcp": [(80, 80)], "apps": ["HTTP"], "web": True},
    {"name": "HTTPS", "label": "HTTPS (web)", "tcp": [(443, 443)], "apps": ["SSL", "HTTPS"], "web": True},
    {"name": "QUIC", "label": "QUIC (HTTP/3 over UDP)", "udp": [(443, 443)], "apps": ["QUIC"]},
    {"name": "HTTP_PROXY", "label": "HTTP on 8080", "tcp": [(8080, 8080)], "apps": ["HTTP"], "web": True},
    {"name": "HTTPS_ALT", "label": "HTTPS on 8443", "tcp": [(8443, 8443)], "apps": ["SSL", "HTTPS"], "web": True},
    {"name": "DNS", "label": "DNS", "tcp": [(53, 53)], "udp": [(53, 53)], "apps": ["DNS"]},
    {"name": "DOT", "label": "DNS over TLS", "tcp": [(853, 853)], "apps": ["DOT", "DNS_OVER_TLS"]},
    {"name": "SSH", "label": "SSH", "tcp": [(22, 22)], "apps": ["SSH"]},
    {"name": "TELNET", "label": "Telnet", "tcp": [(23, 23)], "apps": ["TELNET"]},
    {"name": "FTP", "label": "FTP", "tcp": [(20, 21)], "apps": ["FTP"]},
    {"name": "SMTP", "label": "SMTP (mail)", "tcp": [(25, 25), (587, 587)], "apps": ["SMTP"]},
    {"name": "SMTPS", "label": "SMTP over TLS", "tcp": [(465, 465)], "apps": ["SMTPS", "SMTP"]},
    {"name": "POP3", "label": "POP3 (mail)", "tcp": [(110, 110)], "apps": ["POP3"]},
    {"name": "POP3S", "label": "POP3 over TLS", "tcp": [(995, 995)], "apps": ["POP3S", "POP3"]},
    {"name": "IMAP", "label": "IMAP (mail)", "tcp": [(143, 143)], "apps": ["IMAP"]},
    {"name": "IMAPS", "label": "IMAP over TLS", "tcp": [(993, 993)], "apps": ["IMAPS", "IMAP"]},
    {"name": "NTP", "label": "NTP (time)", "udp": [(123, 123)], "apps": ["NTP"]},
    {"name": "SNMP", "label": "SNMP", "udp": [(161, 162)], "apps": ["SNMP"]},
    {"name": "LDAP", "label": "LDAP", "tcp": [(389, 389)], "udp": [(389, 389)], "apps": ["LDAP"]},
    {"name": "LDAPS", "label": "LDAP over TLS", "tcp": [(636, 636)], "apps": ["LDAPS", "LDAP"]},
    {"name": "KERBEROS", "label": "Kerberos", "tcp": [(88, 88)], "udp": [(88, 88)], "apps": ["KERBEROS"]},
    {"name": "SMB", "label": "SMB (file sharing)", "tcp": [(445, 445)], "apps": ["SMB"]},
    {"name": "NETBIOS", "label": "NetBIOS", "tcp": [(139, 139)], "udp": [(137, 138)], "apps": ["NETBIOS"]},
    {"name": "RDP", "label": "Remote Desktop (RDP)", "tcp": [(3389, 3389)], "udp": [(3389, 3389)], "apps": ["RDP"]},
    {"name": "VNC", "label": "VNC", "tcp": [(5900, 5900)], "apps": ["VNC"]},
    {"name": "IKE", "label": "IPsec IKE", "udp": [(500, 500), (4500, 4500)], "apps": ["IKE", "IPSEC"]},
    {"name": "OPENVPN", "label": "OpenVPN", "tcp": [(1194, 1194)], "udp": [(1194, 1194)], "apps": ["OPENVPN"]},
    {"name": "WIREGUARD", "label": "WireGuard", "udp": [(51820, 51820)], "apps": ["WIREGUARD"]},
    {"name": "PPTP", "label": "PPTP VPN", "tcp": [(1723, 1723)], "apps": ["PPTP"]},
    {"name": "L2TP", "label": "L2TP VPN", "udp": [(1701, 1701)], "apps": ["L2TP"]},
    {"name": "STUN", "label": "STUN (calls and meetings)", "udp": [(3478, 3478)], "apps": ["STUN"]},
    {"name": "SIP", "label": "SIP (voice)", "tcp": [(5060, 5061)], "udp": [(5060, 5060)], "apps": ["SIP"]},
    {"name": "SYSLOG", "label": "Syslog", "udp": [(514, 514)], "apps": ["SYSLOG"]},
    {"name": "TFTP", "label": "TFTP", "udp": [(69, 69)], "apps": ["TFTP"]},
    {"name": "DHCP", "label": "DHCP", "udp": [(67, 68)], "apps": ["DHCP"]},
    {"name": "MSSQL", "label": "Microsoft SQL Server", "tcp": [(1433, 1433)], "apps": ["TDS", "MSSQL"]},
    {"name": "MYSQL", "label": "MySQL", "tcp": [(3306, 3306)], "apps": ["MYSQL"]},
    {"name": "POSTGRES", "label": "PostgreSQL", "tcp": [(5432, 5432)], "apps": ["POSTGRESQL", "PGSQL"]},
]
PROTOCOLS = ("tcp", "udp")

# ── Conditions this tool never evaluates ─────────────────────────────
# field (camelCase, as the API sends it) -> how the page names it and why
# it is unknown. Each one present on a rule is an "unknown" criterion.
UNEVALUATED: List[Tuple[str, str, str]] = [
    ("users", "Users", "the trace is for any user"),
    ("groups", "Groups", "the trace is for any user"),
    ("departments", "Departments", "the trace is for any user"),
    ("locations", "Locations", "the trace is for any location"),
    ("locationGroups", "Location groups", "the trace is for any location"),
    ("timeWindows", "Time window", "the time of the transaction is not part of the trace"),
    ("deviceTrustLevels", "Device trust", "the device's trust level is not known"),
    ("devices", "Devices", "the device is not known"),
    ("deviceGroups", "Device groups", "the device is not known"),
    ("userRiskScoreLevels", "User risk score", "the user's risk score is not known"),
    ("userAgentTypes", "Browser (user agent)", "the browser is not known"),
    ("platforms", "Platform", "the rule's platform condition is not evaluated"),
    ("workloadGroups", "Workload groups", "workload identity is not part of the trace"),
    ("zpaAppSegments", "ZPA app segments", "ZPA app segments are not evaluated here"),
    ("appServices", "App services", "app services are not evaluated here"),
    ("appServiceGroups", "App service groups", "app services are not evaluated here"),
    ("sourceCountries", "Source country", "where the user connects from is not known"),
    ("excludeSrcCountries", "Excluded source countries", "where the user connects from is not known"),
    ("srcIps", "Source IP", "the user's source IP address is not known"),
    ("sourceIpGroups", "Source IP groups", "the user's source IP address is not known"),
    ("srcIpGroups", "Source IP groups", "the user's source IP address is not known"),
    ("srcIpv6Groups", "Source IPv6 groups", "the user's source IP address is not known"),
]
# Exclusions (Web DLP rules, zscaler-sdk-python 1.11.3 models/dlp_web_rules.py
# excludedUsers / excludedGroups / excludedDepartments): the rule applies to
# everyone in its scope except these, so for any user they are unknown too.
EXCLUDED: List[Tuple[str, str, str]] = [
    ("excludedUsers", "Excluded users", "the trace is for any user"),
    ("excludedGroups", "Excluded groups", "the trace is for any user"),
    ("excludedDepartments", "Excluded departments", "the trace is for any user"),
]

_ANY = {"ANY", "ALL", "ANY_RULE", "NONE", ""}


# ── Small helpers ────────────────────────────────────────────────────
@functools.lru_cache(maxsize=512)
def _snake(camel: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", camel).lower()


def _f(r: Dict[str, Any], camel: str, default: Any = None) -> Any:
    """A field from a raw (camelCase) or SDK (snake_case) dict."""
    if not isinstance(r, dict):
        return default
    for k in (camel, _snake(camel)):
        if k in r and r[k] is not None:
            return r[k]
    return default


def _list(v: Any) -> List[Any]:
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _name(x: Any) -> str:
    if isinstance(x, dict):
        return str(x.get("name") or x.get("id") or "")
    return str(x)


def _names(v: Any) -> List[str]:
    return [n for n in (_name(x) for x in _list(v)) if n and n.upper() not in _ANY]


def _id(x: Any) -> Optional[str]:
    if isinstance(x, dict):
        return str(x["id"]) if x.get("id") is not None else None
    return None


def _short(items: List[str], n: int = 4) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def _crit(name: str, state: str, detail: str) -> Dict[str, str]:
    return {"name": name, "state": state, "detail": detail}


def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def ascii_host(host: str) -> str:
    """A host name as ZIA and ZPA hold it: lower case, no trailing dot, and
    an internationalised name (münchen.de) in its punycode form
    (xn--mnchen-3ya.de), which is what DNS, the browser's SNI and the URL
    lists carry. UTS 46 through the idna package when it is installed,
    else Python's own IDNA codec. ValueError for a name that cannot be
    encoded."""
    h = str(host or "").strip().lower().rstrip(".")
    if h.isascii():
        return h
    try:
        import idna
    except ImportError:   # pragma: no cover - idna ships with requests
        idna = None
    try:
        if idna is not None:
            return idna.encode(h, uts46=True, transitional=False).decode("ascii")
        return h.encode("idna").decode("ascii")
    except Exception as e:  # noqa: BLE001 - every codec error is "not a host name"
        raise ValueError(f"'{h[:80]}' is not a valid internationalised host name") from e


def well_known(protocol: str, port: Optional[int]) -> Optional[Dict[str, Any]]:
    """The well-known service on protocol/port, or None."""
    if port is None:
        return None
    for w in WELL_KNOWN:
        if any(a <= port <= b for a, b in w.get(protocol, [])):
            return w
    return None


# ── Traffic: protocol and port ───────────────────────────────────────
def traffic_context(dest: Dict[str, Any], protocol: Any = None, port: Any = None) -> Dict[str, Any]:
    """The transaction's protocol and port, from what the operator chose
    or else from the URL (its port, then its scheme). Raises ValueError
    with a plain sentence for a protocol or port that is not valid.
    Returns {protocol, port, service, label, web, encrypted, assumed,
    notes}."""
    p = str(protocol or "").strip().lower()
    if p and p not in PROTOCOLS:
        raise ValueError("The protocol must be TCP or UDP.")
    if port in (None, ""):
        n = None
    else:
        whole = isinstance(port, int) or (isinstance(port, float) and port.is_integer()) or (isinstance(port, str) and port.strip().isascii() and port.strip().isdigit())
        n = _int(port) if whole else None
        if n is None or not 1 <= n <= 65535 or isinstance(port, bool):
            raise ValueError("The port must be a whole number from 1 to 65535.")
    notes: List[str] = []
    assumed = False
    scheme_typed = bool(re.match(r"^[a-z][a-z0-9+.-]*://", str(dest.get("input") or ""), re.I))
    given_protocol = bool(p)
    p = p or "tcp"
    if n is None:
        if dest.get("port"):
            n = int(dest["port"])
        elif scheme_typed and dest.get("scheme") in ("http", "https", "ftp"):
            n = {"http": 80, "https": 443, "ftp": 21}[dest["scheme"]]
        else:
            n, assumed = 443, True
            notes.append("No port was given, so port 443 is assumed; choose a port to trace other traffic." if given_protocol else
                         "No protocol or port was given, so HTTPS (TCP/443) is assumed; choose a protocol and port to trace other traffic.")
    w = well_known(p, n)
    web = p == "tcp" and bool(w and w.get("web"))
    label = f"{p.upper()}/{n}" + (f" ({w['label']})" if w else "")
    if p == "udp" and n == 443:
        notes.append("UDP/443 is QUIC (HTTP/3). The web proxy never sees QUIC: the Cloud Firewall decides it, and browsers fall back to HTTPS over TCP when it is blocked.")
    elif not web:
        notes.append(f"{label} is not web traffic: only the Cloud Firewall (and DNS Control for the lookup) decide it; URL filtering, Cloud App Control, SSL inspection, Sandbox, File Type Control and Web DLP never see it.")
    return {"protocol": p, "port": n, "service": w["name"] if w else None, "apps": list(w["apps"]) if w else [],
            "label": label, "web": web, "encrypted": n in (443, 8443) if web else None, "assumed": assumed, "notes": notes}


# ── Reading the tenant ───────────────────────────────────────────────
_KEEP = {
    "network_services": ("id", "name", "tag", "type", "destTcpPorts", "destUdpPorts", "srcTcpPorts", "srcUdpPorts"),
    "network_service_groups": ("id", "name", "services"),
    "network_app_groups": ("id", "name", "networkApplications"),
    "ip_destination_groups": ("id", "name", "type", "addresses", "countries", "ipCategories"),
    "ip_source_groups": ("id", "name", "ipAddresses"),
}


def _slim(part: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    keep = _KEEP.get(part)
    if not keep:
        return items
    return [{k: _f(x, k) for k in keep if _f(x, k) is not None} for x in items]


def _as_list(data: Any) -> Optional[List[Dict[str, Any]]]:
    if isinstance(data, dict):
        for k in ("list", "data", "items", "rules"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
    if isinstance(data, list) and all(isinstance(x, dict) for x in data):
        return data
    return None


def read(client: Any, scope: Optional[Dict[str, Any]], cancel: Any = None, log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Read the module sections in scope. {key: {state: read | partial |
    unread | out_of_scope, why, parts: {part: {ok, data, error}}}}.
    A failed read is recorded (never an empty list); Stop raises
    data_flow.ReadStopped and nothing more is sent."""
    from data_flow import ReadStopped, stop_requested
    import zia_rate
    nis = dict((scope or {}).get("not_in_scope") or {})
    out: Dict[str, Any] = {}
    for key, parts in READS.items():
        if scope is not None and key not in (scope.get("read") or []):
            out[key] = {"state": "out_of_scope", "why": nis.get(key) or f"Not in scope: the {SECTIONS[key][0]} were not read.", "parts": {}}
            continue
        got: Dict[str, Any] = {}
        for part, ep, label, kind in parts:
            if stop_requested(cancel):
                raise ReadStopped("stopped before the read finished")
            try:
                data, code = client.get(ep)
            except Exception as e:  # noqa: BLE001
                if isinstance(e, (ReadStopped, zia_rate.Cancelled)) or stop_requested(cancel):
                    raise ReadStopped("stopped while reading") from e
                got[part] = {"ok": False, "data": None, "error": f"{label}: {type(e).__name__}: {str(e)[:160]}"}
                continue
            if code == 204:
                data, code = ([] if kind == "list" else {}), 200
            if code != 200:
                err = data.get("error") if isinstance(data, dict) else ""
                got[part] = {"ok": False, "data": None, "error": f"{label}: HTTP {code}" + (f" ({str(err)[:120]})" if err else "")}
                continue
            if kind == "list":
                items = _as_list(data)
                if items is None:
                    got[part] = {"ok": False, "data": None, "error": f"{label}: the answer was not a complete list"}
                    continue
                got[part] = {"ok": True, "data": _slim(part, items), "error": None}
            else:
                if not isinstance(data, (dict, list)):
                    got[part] = {"ok": False, "data": None, "error": f"{label}: the answer was not a settings object"}
                    continue
                got[part] = {"ok": True, "data": data, "error": None}
        primary = parts[0][0]
        failed = [p for p in got.values() if not p["ok"]]
        state = "unread" if not got[primary]["ok"] else "partial" if failed else "read"
        out[key] = {"state": state, "why": "; ".join(p["error"] for p in failed)[:400] or None, "parts": got}
        if log and failed:
            log(f"{SECTIONS[key][0]}: {len(failed)} of {len(parts)} read(s) failed ({out[key]['why'][:160]}).")
    if stop_requested(cancel):
        raise ReadStopped("stopped before the read finished")
    return out


def snapshot_ready(snapshot: Optional[Dict[str, Any]], scope: Dict[str, Any]) -> bool:
    """A kept tenant read can answer only if it carries these modules
    whenever one is in scope (a Data Flow Map read does not)."""
    if not any(k in (scope.get("read") or []) for k in SECTIONS):
        return True
    zia = ((snapshot or {}).get("snapshot") or {}).get("zia") or {}
    return isinstance(zia.get("modules"), dict)


# ── Matching ─────────────────────────────────────────────────────────
def _norm_entry(entry: str) -> Tuple[str, str]:
    e = str(entry or "").strip().lower()
    e = re.sub(r"^[a-z][a-z0-9+.-]*://", "", e)
    host, _, path = e.partition("/")
    return host.split(":")[0].rstrip("."), ("/" + path if path else "")


def _parse_entry(entry: str) -> Optional[Tuple[Any, ...]]:
    """An IP, CIDR or a-b range entry parsed once (a 5,000-rule tenant names
    the same groups again and again): ("range", first, last), ("net",
    network) or None when it is not an address entry. No address entry is
    longer than 100 characters, so a longer string is none and never cached."""
    return None if len(entry) > 100 else _parse_cached(entry)


@functools.lru_cache(maxsize=16384)
def _parse_cached(entry: str) -> Optional[Tuple[Any, ...]]:
    try:
        if "-" in entry:
            a, b = (ipaddress.ip_address(x.strip()) for x in entry.split("-", 1))
            return ("range", a, b)
        return ("net", ipaddress.ip_network(entry, strict=False))
    except ValueError:
        return None


def _ip_rel(ip: Any, entry: str) -> bool:
    """Whether `ip` is in an IP, CIDR or a-b range entry. An address of the
    other family is never in it (ipaddress refuses to compare the two)."""
    e = _parse_entry(str(entry or "").strip())
    if e is None:
        return False
    if e[0] == "range":
        return e[1].version == e[2].version == ip.version and e[1] <= ip <= e[2]
    return ip in e[1]


def _is_ip_entry(entry: str) -> bool:
    return _parse_entry(str(entry or "").strip()) is not None


def url_hit(entries: Iterable[Any], dest: Dict[str, Any], visible: Optional[bool]) -> Tuple[str, Optional[str]]:
    """ZIA URL-list semantics: 'example.com' is that host, '.example.com'
    (or '*.example.com') the domain and its subdomains; an entry with a
    path needs the path, which ZIA sees only when the traffic is decrypted
    or plain HTTP. Returns (match | no_match | unknown, the entry)."""
    host = str(dest.get("host") or "").lower()
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    unknown = None
    for raw in entries or []:
        entry = str(raw or "")
        if not entry.strip():
            continue
        if _is_ip_entry(entry):
            if ip is not None and _ip_rel(ip, entry):
                return "match", entry
            continue
        h, path = _norm_entry(entry)
        if not h:
            continue
        if h.startswith("*."):
            h = h[1:]
        hit = host == h.lstrip(".") or (h.startswith(".") and host.endswith(h))
        if not hit:
            continue
        if not path or path == "/":
            return "match", entry
        if visible is None:
            unknown = unknown or entry
        elif visible and str(dest.get("path") or "/").lower().startswith(path):
            return "match", entry
    return ("unknown", unknown) if unknown else ("no_match", None)


def _port_ranges(v: Any) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for x in _list(v):
        if isinstance(x, dict):
            a, b = _int(x.get("start")), _int(x.get("end"))
            if a is not None:
                out.append((a, b if b else a))
        elif _int(x) is not None:
            out.append((_int(x), _int(x)))
    return out


def _norm(s: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


# ── Criteria ─────────────────────────────────────────────────────────
def unevaluated(rule: Dict[str, Any], skip: Iterable[str] = ()) -> List[Dict[str, str]]:
    """The conditions on `rule` this tool cannot evaluate, each an unknown
    criterion naming what the rule restricts to."""
    out = []
    skip = set(skip)
    for field, label, why in UNEVALUATED:
        if field in skip:
            continue
        v = _names(_f(rule, field))
        if v:
            out.append(_crit(label, "unknown", f"Applies only to {_short(v)}; {why}."))
    for field, label, why in EXCLUDED:
        v = _names(_f(rule, field))
        if v and field not in skip:
            out.append(_crit(label, "unknown", f"Does not apply to {_short(v)}; {why}."))
    window = validity(rule)
    if window and "validity" not in skip:
        out.append(_crit("Validity period", "unknown", f"Applies only {window}; the time of the transaction is not part of the trace."))
    return out


def validity(rule: Dict[str, Any]) -> Optional[str]:
    """'from <start> to <end> (UTC)' when a URL filtering rule enforces its
    validity period (zscaler-sdk-python 1.11.3 models/url_filtering_rules.py
    enforceTimeValidity, validityStartTime, validityEndTime: epoch
    seconds), else None. Outside the period the rule does not apply."""
    if not isinstance(rule, dict) or not _f(rule, "enforceTimeValidity"):
        return None
    import datetime as _dt

    def when(v: Any) -> str:
        n = _int(v)
        if n is None:
            return "an unknown time"
        try:
            return _dt.datetime.fromtimestamp(n, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
        except (OverflowError, OSError, ValueError):
            return "an unknown time"
    return f"from {when(_f(rule, 'validityStartTime'))} to {when(_f(rule, 'validityEndTime'))} (UTC)"


def protocol_applies(rule_protocols: Iterable[Any], web_protocol: str) -> bool:
    """Whether a URL filtering, File Type Control or Web DLP rule's
    protocols include this web transaction. `web_protocol` is HTTP_RULE
    (plain HTTP) or HTTPS_RULE; no protocol, or ANY, is every protocol.
    HTTPS also counts as SSL and Tunnel SSL (the SDK's protocol names;
    which of them ZIA records for HTTPS it does not decrypt is assumed)."""
    p = [str(x).upper() for x in rule_protocols or [] if str(x).upper() not in _ANY]
    if not p:
        return True
    return web_protocol in p or (web_protocol == "HTTPS_RULE" and any(x in p for x in ("TUNNELSSL_RULE", "SSL_RULE")))


def _crit_categories(rule_cats: List[str], ctx: Dict[str, Any], name: str = "URL category") -> Optional[Dict[str, str]]:
    cats = [c.upper() for c in rule_cats]
    if not cats or any(c in ("ANY", "ALL") for c in cats):
        return None
    have = set(ctx["categories"])
    hit = sorted(have & set(cats))
    if hit:
        return _crit(name, "match", f"{ctx['host']} is in {', '.join(hit)}.")
    if not have:
        return _crit(name, "unknown", f"Applies to {_short(cats)}; no category is known for {ctx['host']}.")
    return _crit(name, "no_match", f"{ctx['host']} is in {_short(sorted(have))}, not {_short(cats)}.")


def _crit_web_protocol(rule_protocols: List[str], ctx: Dict[str, Any]) -> Optional[Dict[str, str]]:
    p = [x.upper() for x in rule_protocols if x.upper() not in _ANY]
    if not p:
        return None
    t = ctx["traffic"]
    want = ("HTTPS_RULE" if t["encrypted"] else "HTTP_RULE") if t["web"] else None
    if want is None:
        return _crit("Protocol", "no_match", f"Applies to {', '.join(p)}; this is {t['label']}.")
    ok = protocol_applies(p, want)
    return _crit("Protocol", "match" if ok else "no_match", f"This is {want.replace('_RULE', '')}; the rule applies to {', '.join(x.replace('_RULE', '') for x in p)}.")


def _crit_destination(rule: Dict[str, Any], ctx: Dict[str, Any], groups: Optional[Dict[str, Dict[str, Any]]], label: str = "Destination") -> Optional[Dict[str, str]]:
    addrs = [str(a) for a in _list(_f(rule, "destAddresses")) if str(a).strip()]
    cats = [str(c).upper() for c in _names(_f(rule, "destIpCategories"))]
    countries = [str(c).upper() for c in _names(_f(rule, "destCountries"))]
    unresolved: List[str] = []
    gnames: List[str] = []
    for g in _list(_f(rule, "destIpGroups")):
        gid, gname = _id(g), _name(g)
        gnames.append(gname)
        full = (groups or {}).get(gid) if groups is not None and gid else None
        if full is None:
            unresolved.append(gname or str(gid))
            continue
        a = [str(x) for x in _list(_f(full, "addresses"))]
        c = [str(x).upper() for x in _names(_f(full, "ipCategories"))]
        k = [str(x).upper() for x in _names(_f(full, "countries"))]
        if not (a or c or k):
            unresolved.append(gname)   # a Zscaler-managed group: its members are not returned
        addrs += a
        cats += c
        countries += k
    # IPv6 destination groups (destIpv6Groups) are a list of their own
    # (/ipDestinationGroups/ipv6DestinationGroups), not read here: an IPv4
    # address is never in one; anything else depends on its members.
    v6 = [_name(g) or str(_id(g)) for g in _list(_f(rule, "destIpv6Groups"))]
    if not (addrs or cats or countries or unresolved or v6):
        return None
    host, ip = ctx["host"], ctx["ip"]
    hits: List[str] = []
    unknown: List[str] = []
    if v6 and not (ip is not None and ip.version == 4):
        unknown.append(f"the members of the IPv6 group(s) {_short(v6, 3)} are not read")
    gnames += [f"{g} (IPv6)" for g in v6]
    names_ = [a for a in addrs if not _is_ip_entry(a)]
    ips = [a for a in addrs if _is_ip_entry(a)]
    if names_ and ip is None:
        st, e = url_hit(names_, ctx["dest"], True)
        if st == "match":
            hits.append(f"{host} matches {e}")
    if ips:
        if ip is not None:
            e = next((x for x in ips if _ip_rel(ip, x)), None)
            if e:
                hits.append(f"{host} is in {e}")
        else:
            unknown.append(f"its IP addresses ({_short(ips, 3)}) need {host} resolved, which this tool does not do")
    if cats:
        hit = sorted(set(ctx["categories"]) & set(cats))
        if hit:
            hits.append(f"category {', '.join(hit)}")
        elif not ctx["categories"]:
            unknown.append(f"no category is known for {host}")
    if countries:
        unknown.append(f"the destination's country is not known (the rule names {_short(countries, 3)})")
    if unresolved:
        unknown.append(f"the members of {_short(unresolved, 3)} are not known (the group list was not read, or Zscaler manages its members)")
    what = _short(addrs + cats + countries + [f"group {g}" for g in gnames], 5)
    if hits:
        return _crit(label, "match", "; ".join(hits) + ".")
    if unknown:
        return _crit(label, "unknown", f"Applies to {what}; " + "; ".join(unknown) + ".")
    return _crit(label, "no_match", f"{host} is not in {what}.")


def _crit_source(rule: Dict[str, Any], groups: Optional[Dict[str, Dict[str, Any]]], src: Any = None) -> Optional[Dict[str, str]]:
    """The rule's source IP condition. Unknown unless the caller gave the
    source address (`src`, an ip_address: context["source_ip"]); then a
    match, or no match when every group's members are known."""
    ips = [str(x) for x in _list(_f(rule, "srcIps"))]
    names_ = []
    unresolved = []
    for g in _list(_f(rule, "srcIpGroups")):
        full = (groups or {}).get(_id(g) or "")
        names_.append(_name(g))
        members = [str(x) for x in _list(_f(full or {}, "ipAddresses"))]
        if not members:
            unresolved.append(_name(g))
        ips += members
    v6 = [_name(g) or str(_id(g)) for g in _list(_f(rule, "srcIpv6Groups"))]   # not read: see _crit_destination
    if not ips and not names_ and not v6:
        return None
    names_ += [f"{n} (IPv6)" for n in v6]
    if v6 and not (src is not None and src.version == 4):
        unresolved += [f"{n} (IPv6)" for n in v6]
    what = _short(ips + [f"group {n}" for n in names_], 4)
    if src is None:
        return _crit("Source IP", "unknown", f"Applies to {what}; the user's source IP address is not known.")
    hit = next((x for x in ips if _is_ip_entry(x) and _ip_rel(src, x)), None)
    if hit:
        return _crit("Source IP", "match", f"The source {src} is in {hit}.")
    if unresolved:
        return _crit("Source IP", "unknown", f"Applies to {what}; the members of {_short(unresolved, 3)} are not known.")
    return _crit("Source IP", "no_match", f"The source {src} is not in {what}.")


def _index(fw: Dict[str, Any], part: str) -> Dict[str, Dict[str, Any]]:
    """{id: object} of one firewall list, built once per evaluation (kept in
    `fw`), not once per rule."""
    key = "_by_id_" + part
    if key not in fw:
        fw[key] = {str(x.get("id")): x for x in fw.get(part) or [] if isinstance(x, dict)}
    return fw[key]


def _services(rule: Dict[str, Any], fw: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    by_id = _index(fw, "network_services")
    groups = _index(fw, "network_service_groups")
    out, unresolved = [], []
    for s in _list(_f(rule, "nwServices")):
        out.append(by_id.get(_id(s) or "") or (s if isinstance(s, dict) else {"name": str(s)}))
    for g in _list(_f(rule, "nwServiceGroups")):
        full = groups.get(_id(g) or "")
        if full and _list(full.get("services")):
            for s in _list(full.get("services")):
                out.append(by_id.get(_id(s) or "") or (s if isinstance(s, dict) else {"name": str(s)}))
        else:
            unresolved.append(_name(g))
    return [s for s in out if _name(s).upper() not in _ANY], unresolved


def _crit_services(rule: Dict[str, Any], ctx: Dict[str, Any], fw: Dict[str, Any]) -> Optional[Dict[str, str]]:
    svcs, unresolved = _services(rule, fw)
    if not svcs and not unresolved:
        return None
    t = ctx["traffic"]
    proto, port = t["protocol"], t["port"]
    unknown = [f"group {g}" for g in unresolved]
    src_only: List[str] = []
    for s in svcs:
        tag = str(_f(s, "tag") or "").upper()
        idents = {tag, _name(s).upper()} - {""}
        if idents & {f"{proto.upper()}_ANY", "ANY"}:
            return _crit("Network service", "match", f"{t['label']} is any {proto.upper()} ({_name(s)}).")
        if idents & ({"TCP_ANY", "UDP_ANY", "ICMP_ANY"} - {f"{proto.upper()}_ANY"}):
            continue   # every port of another protocol (ICMP_ANY, UDP_ANY, ...): never this traffic
        own = _port_ranges(_f(s, "destTcpPorts" if proto == "tcp" else "destUdpPorts"))
        other = _port_ranges(_f(s, "destUdpPorts" if proto == "tcp" else "destTcpPorts"))
        if not own and not other:
            w = next((x for x in WELL_KNOWN if _norm(x["name"]) in (_norm(tag), _norm(_name(s)))), None)
            own = list((w or {}).get(proto, []))
            if not w:
                unknown.append(_name(s))
                continue
        if any(a <= port <= b for a, b in own):
            if _port_ranges(_f(s, "srcTcpPorts" if proto == "tcp" else "srcUdpPorts")):
                src_only.append(_name(s))
                continue
            return _crit("Network service", "match", f"{t['label']} is in {_name(s)}.")
    what = _short([_name(s) for s in svcs] + [f"group {g}" for g in unresolved], 5)
    if unknown or src_only:
        why = ([f"the ports of {_short(unknown, 3)} are not known"] if unknown else []) + \
            ([f"{_short(src_only, 3)} also need(s) a source port, which is not known"] if src_only else [])
        return _crit("Network service", "unknown", f"Applies to {what}; " + "; ".join(why) + ".")
    return _crit("Network service", "no_match", f"{t['label']} is not in {what}.")


def _crit_network_apps(rule: Dict[str, Any], ctx: Dict[str, Any], fw: Dict[str, Any]) -> Optional[Dict[str, str]]:
    apps = _names(_f(rule, "nwApplications"))
    groups = _index(fw, "network_app_groups")
    unresolved = []
    for g in _list(_f(rule, "nwApplicationGroups")):
        full = groups.get(_id(g) or "")
        if full and _list(full.get("networkApplications")):
            apps += _names(full.get("networkApplications"))
        else:
            unresolved.append(_name(g))
    if not apps and not unresolved:
        return None
    t = ctx["traffic"]
    inferred = {_norm(a) for a in t["apps"]}
    hit = next((a for a in apps if _norm(a) in inferred), None)
    what = _short(apps + [f"group {g}" for g in unresolved], 5)
    if hit:
        return _crit("Network application", "match", f"{t['label']} is identified as {hit} (from the port).")
    known = [next((w for w in WELL_KNOWN if any(_norm(x) == _norm(a) for x in w["apps"])), None) for a in apps]
    # On a port no well-known service names, what runs there is not known
    # (ZIA identifies SSH on 2222 as SSH): never a definite no match.
    if t["service"] and apps and not unresolved and all(known) and not any(any(a <= t["port"] <= b for a, b in w.get(t["protocol"], [])) for w in known):
        return _crit("Network application", "no_match", f"{t['label']} is not {what}.")
    return _crit("Network application", "unknown", f"Applies to {what}; ZIA identifies the application from the traffic itself, which the port alone does not establish.")


# ── Rule evaluation ──────────────────────────────────────────────────
def _state(criteria: List[Dict[str, str]]) -> str:
    if any(c["state"] == "no_match" for c in criteria):
        return "no_match"
    if any(c["state"] == "unknown" for c in criteria):
        return "unknown"
    return "match"


def _is_default(r: Dict[str, Any]) -> bool:
    o = _int(_f(r, "order"))
    return bool(_f(r, "defaultRule")) or (o is not None and o < 0) or (bool(_f(r, "predefined")) and str(_f(r, "name") or "").lower().startswith("default"))


def _order_key(r: Dict[str, Any]) -> Tuple[int, int, str]:
    o = _int(_f(r, "order"))
    return (1 if _is_default(r) else 0, o if o is not None and o >= 0 else 10 ** 9, str(_f(r, "id") or ""))


def _action(r: Dict[str, Any], *fields: str) -> str:
    for k in fields or ("action",):
        a = _f(r, k)
        if isinstance(a, dict):
            a = a.get("type") or a.get("name")
        if a:
            return str(a).upper()
    return ""


def _enabled(r: Dict[str, Any]) -> bool:
    return str(_f(r, "state") or "ENABLED").upper() != "DISABLED"


def _run(module: str, key: str, rules: List[Dict[str, Any]], criteria: Callable[[Dict[str, Any]], List[Optional[Dict[str, str]]]],
         verdict_of: Callable[[Dict[str, Any]], str], action_of: Callable[[Dict[str, Any]], str], default_verdict: str, default_detail: str) -> Dict[str, Any]:
    """First definite match decides (rules in order, the default rule
    last). Earlier rules with an unknown criterion and another outcome
    could override it: the module is then conditional."""
    ev = []
    for r in sorted((r for r in rules if isinstance(r, dict) and _enabled(r)), key=_order_key):
        crits = [c for c in criteria(r) if c]
        ev.append({"id": _f(r, "id"), "name": str(_f(r, "name") or f"rule {_f(r, 'id')}"), "order": _f(r, "order"), "default": _is_default(r),
                   "action": action_of(r), "verdict": verdict_of(r), "state": _state(crits), "criteria": crits})
    idx = next((i for i, e in enumerate(ev) if e["state"] == "match"), None)
    deciding = ev[idx] if idx is not None else None
    verdict = deciding["verdict"] if deciding else default_verdict
    earlier = ev[:idx] if idx is not None else ev
    could = [e for e in earlier if e["state"] == "unknown" and e["verdict"] != verdict]
    after = [e for e in (ev[idx + 1:] if idx is not None else []) if e["state"] == "match"]
    catch_all = [e for e in after if e["default"] or not e["criteria"]]
    res = _module(module, key, verdict, "conditional" if could else "definite", "evaluated",
                  rule=_rule_ref(deciding), criteria=list(deciding["criteria"]) if deciding else [],
                  overlaps=[_overlap(e, verdict) for e in after if e not in catch_all], overlaps_catch_all=len(catch_all),
                  could_override=[_overlap(e, verdict, criteria=True) for e in could], considered=len(ev),
                  detail=((f"No other rule matches, so the default rule decides: {deciding['action'] or deciding['verdict']}." if deciding["default"] else
                           f"The first rule that matches decides: {deciding['action'] or deciding['verdict']}.") if deciding else default_detail))
    if could:
        res["reason"] = (f"{len(could)} earlier rule(s) with a condition that cannot be evaluated would give another outcome: "
                         + _short([f"'{e['name']}' ({e['action']})" for e in could], 3))
    return res


def _rule_ref(e: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not e:
        return None
    return {"id": e.get("id"), "name": e["name"], "order": e.get("order"), "action": e.get("action"), "default": bool(e.get("default"))}


def _overlap(e: Dict[str, Any], verdict: str, criteria: bool = False) -> Dict[str, Any]:
    o = {"id": e.get("id"), "name": e["name"], "order": e.get("order"), "action": e.get("action"), "verdict": e["verdict"], "differs": e["verdict"] != verdict}
    if criteria:
        o["criteria"] = list(e["criteria"])
    return o


# ── The one hop shape every Path analyzer module shares ──────────────
# static/path_modules.js renders it, for the ZIA modules here and for the
# steps before ZIA (ZPA, the Cloud or Branch Connector, the PAC file). The
# verdict words are one vocabulary (path_modules.js VERDICT); the ZPA and
# connector words that mean the same as a ZIA word are folded into it.
VERDICTS = frozenset({
    "allow", "block", "caution", "isolate", "redirect", "inspect", "decrypt", "no_decrypt", "none", "blind", "skipped",
    "conditional", "unknown", "not_applicable", "not_reached", "out_of_scope",
    # the steps before ZIA
    "matched", "not_matched", "intercepted", "bypassed", "forwarded", "dropped", "carried",
})
_VERDICT_ALIASES = {"allowed": "allow", "denied": "block", "not_in_scope": "out_of_scope"}
CRITERION_STATES = ("match", "no_match", "unknown")
_STATE_ALIASES = {"nomatch": "no_match"}


def _ref(r: Any, *keys: str) -> Dict[str, Any]:
    out = {"name": str(r.get("name") or ""), "order": r.get("order")}
    for k in keys:
        if r.get(k) not in (None, "", []):
            out[k] = r[k]
    return out


def criterion(c: Dict[str, Any]) -> Dict[str, Any]:
    """One criterion in the shared shape: {name, state, detail?}."""
    state = _STATE_ALIASES.get(str(c.get("state") or ""), str(c.get("state") or "unknown"))
    out = {"name": str(c.get("name") or ""), "state": state if state in CRITERION_STATES else "unknown"}
    if c.get("detail"):
        out["detail"] = str(c["detail"])
    return out


def module_hop(module: str, verdict: str, rule: Optional[Dict[str, Any]] = None, *, key: str = "",
               overlaps: Iterable[Dict[str, Any]] = (), could_override: Iterable[Dict[str, Any]] = (),
               criteria: Iterable[Dict[str, Any]] = (), notes: Iterable[str] = (), detail: str = "") -> Dict[str, Any]:
    """One step of a traced path in the shape static/path_modules.js
    renders: {key, module, verdict, rule: {name, order} | None, overlaps:
    [{name, order, action?, differs, detail?}] (other rules that also
    match and never apply), could_override: [{name, order, action?,
    criteria, detail?}] (earlier rules that could decide instead),
    criteria: [{name, state: match | no_match | unknown, detail?}], notes,
    detail}. Used for the steps before ZIA; the ZIA modules (_module)
    carry the same keys and a few more."""
    v = _VERDICT_ALIASES.get(verdict, verdict)
    return {"key": key, "module": module, "verdict": v if v in VERDICTS else "unknown",
            "rule": _ref(rule) if rule and rule.get("name") else None,
            "overlaps": [dict(_ref(o, "action", "detail"), differs=bool(o.get("differs"))) for o in overlaps if o and o.get("name")][:20],
            "could_override": [dict(_ref(o, "action", "detail"), criteria=[criterion(c) for c in o.get("criteria") or []][:30])
                               for o in could_override if o and o.get("name")][:8],
            "criteria": [criterion(c) for c in criteria][:30], "notes": [str(n) for n in notes if n][:12], "detail": str(detail or "")}


def _module(module: str, key: str, verdict: str, certainty: str, status: str, **kw: Any) -> Dict[str, Any]:
    """One module's result, in the shape static/path_modules.js renders:
    {module, key, verdict, certainty, status, rule: {name, order, ...} |
    None, overlaps, overlaps_catch_all, could_override, criteria: [{name,
    state, detail}], notes, detail, modifier}."""
    out = {"module": module, "key": key, "verdict": verdict, "certainty": certainty, "status": status, "rule": None,
           "overlaps": [], "overlaps_catch_all": 0, "could_override": [], "criteria": [], "notes": [], "detail": "", "modifier": False, "considered": 0}
    out.update(kw)
    return out


def _skip(module: str, key: str, verdict: str, detail: str, certainty: str = "definite", status: Optional[str] = None) -> Dict[str, Any]:
    """A module that is not evaluated (not applicable, not reached, not in
    scope) or whose answer is not established."""
    status = status or {"not_applicable": "not_applicable", "not_reached": "not_reached", "out_of_scope": "out_of_scope"}.get(verdict, "evaluated")
    return _module(module, key, verdict, certainty, status, detail=detail)


# ── The modules ──────────────────────────────────────────────────────
# ATP category toggles: ZIA URL lookup category (or security alert) -> the
# advancedThreatSettings flag that blocks it. The flags are the SDK's
# (models/advanced_threat_settings.py); which lookup category each flag
# acts on is this tool's mapping (assumed, see the report).
ATP_CATEGORIES: List[Tuple[Tuple[str, ...], str, str]] = [
    (("MALWARE_SITE", "MALICIOUS_CONTENT"), "malwareSitesBlocked", "Malicious content sites"),
    (("PHISHING",), "knownPhishingSitesBlocked", "Known phishing sites"),
    (("SUSPICIOUS_DESTINATION", "SUSPECTED_PHISHING"), "suspectedPhishingSitesBlocked", "Suspected phishing sites"),
    (("BOTNET", "COMMAND_AND_CONTROL"), "cmdCtlServerBlocked", "Command and control servers"),
    (("SPYWARE_OR_ADWARE",), "suspectAdwareSpywareSitesBlocked", "Suspected adware and spyware sites"),
    (("ADSPYWARE_SITES",), "adSpywareSitesBlocked", "Adware and spyware sites"),
    (("WEB_SPAM",), "webspamBlocked", "Web spam"),
    (("XSS",), "potentialMaliciousRequestsBlocked", "Cross-site scripting"),
    (("BROWSER_EXPLOIT",), "browserExploitsBlocked", "Browser exploits"),
    (("CRYPTOMINING",), "cryptoMiningBlocked", "Cryptomining"),
    (("ANONYMIZER",), "anonymizerBlocked", "Anonymizers"),
    (("P2P", "P2P_COMMUNICATION"), "bitTorrentBlocked", "BitTorrent and peer-to-peer"),
    (("TOR",), "torBlocked", "Tor"),
    (("DGA_DOMAINS", "DGA"), "dgaDomainsBlocked", "Domain generation algorithm domains"),
]


def _atp(ctx: Dict[str, Any], sec: Dict[str, Any]) -> Dict[str, Any]:
    name = "Advanced Threat Protection"
    parts = sec.get("parts") or {}

    def part(p: str, *keys: str) -> Tuple[Optional[List[str]], Optional[str]]:
        got = parts.get(p) or {}
        if not got.get("ok"):
            return None, got.get("error") or "not read"
        d = got.get("data")
        for k in keys:
            if isinstance(d, dict) and isinstance(d.get(k), list):
                return [str(x) for x in d[k] if isinstance(x, (str, int))], None
            if isinstance(d, dict) and isinstance(d.get(_snake(k)), list):
                return [str(x) for x in d[_snake(k)] if isinstance(x, (str, int))], None
        return ([str(x) for x in d] if isinstance(d, list) else []), None

    visible = ctx["visible"]
    rules: List[Dict[str, Any]] = []
    order = 0
    for p, keys, label, action, verdict in (("exceptions", ("bypassUrls",), "Security exceptions (ATP allowlist)", "ALLOW", "allow"),
                                            ("allowlist", ("whitelistUrls",), "Security policy allowlist", "ALLOW", "allow"),
                                            ("malicious", ("maliciousUrls",), "Malicious URLs (ATP denylist)", "BLOCK", "block"),
                                            ("denylist", ("blacklistUrls",), "Security policy denylist", "BLOCK", "block")):
        order += 1
        entries, err = part(p, *keys)
        if entries is None:
            crit = _crit("URL list", "unknown", f"The list could not be read ({err}).")
        else:
            st, e = url_hit(entries, ctx["dest"], visible)
            crit = _crit("URL list", st, f"{ctx['host']} matches {e}." if st == "match" else
                         f"{e} has a path, which ZIA sees only when the traffic is decrypted, and whether it is decrypted is not established." if st == "unknown" else
                         f"{ctx['host']} is not on the list ({len(entries)} entr{'y' if len(entries) == 1 else 'ies'}).")
        rules.append({"id": p, "name": label, "order": order, "action": action, "verdict": verdict, "default": False,
                      "state": crit["state"], "criteria": [crit]})
    settings_part = parts.get("settings") or {}
    s = settings_part.get("data") if settings_part.get("ok") and isinstance(settings_part.get("data"), dict) else None
    known = set(ctx["categories"]) | set(ctx["alerts"])
    notes: List[str] = []
    if s is None:
        notes.append(f"The ATP settings could not be read ({settings_part.get('error') or 'not read'}): the category toggles and blocked countries are unknown.")
        order += 1
        rules.append({"id": "settings", "name": "ATP category toggles and blocked countries", "order": order, "action": "BLOCK", "verdict": "block",
                      "default": False, "state": "unknown", "criteria": [_crit("ATP settings", "unknown", "The settings could not be read.")]})
    else:
        for cats, flag, label in ATP_CATEGORIES:
            v = _f(s, flag)
            if v is None:
                continue
            hit = sorted(known & set(cats))
            order += 1
            crit = (_crit("Threat category", "match", f"ZIA places {ctx['host']} in {', '.join(hit)}.") if hit else
                    _crit("Threat category", "unknown", f"No category is known for {ctx['host']}.") if not ctx["categories"] and not ctx["alerts"] else
                    _crit("Threat category", "no_match", f"{ctx['host']} is not in {', '.join(cats)}."))
            rules.append({"id": flag, "name": f"{label}: {'blocked' if v else 'not blocked'}", "order": order, "action": "BLOCK" if v else "ALLOW",
                          "verdict": "block" if v else "allow", "default": False, "state": crit["state"], "criteria": [crit]})
        countries = [str(c).upper() for c in _list(_f(s, "blockedCountries")) if c]
        if countries:
            order += 1
            rules.append({"id": "blockedCountries", "name": f"Blocked countries ({len(countries)})", "order": order, "action": "BLOCK", "verdict": "block",
                          "default": False, "state": "unknown",
                          "criteria": [_crit("Destination country", "unknown", f"Blocks {_short(countries, 4)}; the country of {ctx['host']}'s server is not known (this tool does not geolocate).")]})
        risk = _f(s, "riskTolerance")
        if risk is not None:
            notes.append(f"Page risk tolerance is {risk}: ZIA scores each page's content at run time, which no configuration read can predict.")
    # Allow lists first, then deny lists and toggles (assumed precedence).
    idx = next((i for i, e in enumerate(rules) if e["state"] == "match" and (e["verdict"] == "block" or e["id"] in ("exceptions", "allowlist"))), None)
    deciding = rules[idx] if idx is not None else None
    verdict = deciding["verdict"] if deciding else "allow"
    could = [e for e in (rules[:idx] if idx is not None else rules) if e["state"] == "unknown" and e["verdict"] != verdict]
    after = [e for e in (rules[idx + 1:] if idx is not None else []) if e["state"] == "match"]
    notes.append("Signature, sandbox and reputation detections act on the content at run time; they are not predicted here.")
    return _module(name, "atp", verdict, "conditional" if could else "definite", "evaluated", rule=_rule_ref(deciding),
                   criteria=list(deciding["criteria"]) if deciding else [], overlaps=[_overlap(e, verdict) for e in after],
                   could_override=[_overlap(e, verdict, criteria=True) for e in could], considered=len(rules), notes=notes,
                   reason=(f"{len(could)} check(s) that cannot be evaluated would give another outcome: " + _short([f"'{e['name']}'" for e in could], 3)) if could else None,
                   detail=(f"The first check that matches decides: {deciding['action']}." if deciding else
                           "No ATP list entry or blocked category matches this destination; ATP lets it through to the next module."))


def _firewall(ctx: Dict[str, Any], sec: Dict[str, Any]) -> Dict[str, Any]:
    parts = sec.get("parts") or {}
    data = {k: (v.get("data") if v.get("ok") else None) for k, v in parts.items()}
    fw = {k: (data.get(k) or []) for k in _KEEP}
    dgroups = None if data.get("ip_destination_groups") is None else {str(g.get("id")): g for g in data["ip_destination_groups"]}
    sgroups = None if data.get("ip_source_groups") is None else {str(g.get("id")): g for g in data["ip_source_groups"]}

    def criteria(r):
        return [_crit_source(r, sgroups, ctx.get("source_ip")), _crit_destination(r, ctx, dgroups), _crit_services(r, ctx, fw), _crit_network_apps(r, ctx, fw)] + \
            unevaluated(r, skip=("srcIps", "srcIpGroups", "sourceIpGroups", "srcIpv6Groups"))

    def verdict_of(r):
        a = _action(r, "action", "accessControl")
        return "block" if a.startswith("BLOCK") or a in ("DROP", "RESET") else "allow" if a in ("ALLOW", "EVAL_NWAPP") else (a.lower() or "unknown")

    res = _run("Cloud Firewall", "firewall", data.get("rules") or [], criteria, verdict_of, lambda r: _action(r, "action", "accessControl"),
               "unknown", "No Cloud Firewall rule matches and the default rule was not among the rules read, so the firewall's action is unknown.")
    if res["verdict"] == "unknown" and res["certainty"] == "definite":
        res["certainty"] = "unknown"
    missing = [READS["firewall"][i][2] for i, (p, _, _, _) in enumerate(READS["firewall"]) if p != "rules" and data.get(p) is None]
    if missing:
        res["notes"].append(f"Not read: {', '.join(missing)}; criteria that refer to them are unknown.")
    if ctx["traffic"]["web"]:
        res["notes"].append("Web traffic the firewall allows is handed to the web proxy modules below.")
    res["notes"].append("The Cloud Firewall sees non-web traffic only when it is forwarded by Z-Tunnel 2.0 or a GRE/IPsec site tunnel.")
    return res


def _dns(ctx: Dict[str, Any], sec: Dict[str, Any]) -> Dict[str, Any]:
    t = ctx["traffic"]
    if ctx["ip"] is not None:
        if t["service"] == "DNS":
            return _skip("DNS Control", "dns", "unknown", f"This is DNS traffic to the resolver {ctx['host']}: DNS Control rules apply to each query in it, and the names queried are not known.", "unknown")
        return _skip("DNS Control", "dns", "not_applicable", f"Not applicable: {ctx['host']} is an IP address, so the device looks no name up.")
    rules = ((sec.get("parts") or {}).get("rules") or {}).get("data") or []

    def criteria(r):
        # The IP destination groups are the Cloud Firewall's read (the same
        # /ipDestinationGroups list, in scope with it); without it unknown.
        out: List[Optional[Dict[str, str]]] = [_crit_destination(r, ctx, ctx.get("dst_groups"), "Requested domain")]
        # The SDK docstring writes TCP, UDP, DOHTTPS; the API answers TCP_RULE,
        # UDP_RULE, DOHTTPS_RULE (as every other ZIA rule's protocols).
        p = [x.upper() for x in _names(_f(r, "protocols"))]
        if p:
            out.append(_crit("DNS protocol", "match", "A lookup over UDP is assumed (the standard resolver path).") if {"UDP", "UDP_RULE"} & set(p) else
                       _crit("DNS protocol", "unknown", f"Applies to {', '.join(x.replace('_RULE', '') for x in p)}; whether this lookup uses TCP or DNS over HTTPS is not known."))
        types = [x.upper() for x in _names(_f(r, "dnsRuleRequestTypes"))]
        if types:
            out.append(_crit("Query type", "match" if {"A", "AAAA"} & set(types) else "no_match",
                             f"An address lookup (A or AAAA) is assumed; the rule applies to {_short(types, 5)}."))
        rc = _names(_f(r, "resCategories"))
        if rc:
            out.append(_crit("Resolved IP category", "unknown", f"Applies to answers in {_short(rc, 3)}; the category of the resolved address is not known."))
        apps = _names(_f(r, "applications")) + [f"group {g}" for g in _names(_f(r, "applicationGroups"))]
        if apps:
            out.append(_crit("DNS application", "unknown", f"Applies to {_short(apps, 4)}; ZIA identifies DNS tunnels and applications from the queries themselves."))
        return out + unevaluated(r)

    def verdict_of(r):
        a = _action(r)
        return "block" if a.startswith("BLOCK") else "allow" if a == "ALLOW" else "redirect" if a.startswith(("REDIR", "RESOLVE")) else (a.lower() or "unknown")

    res = _run("DNS Control", "dns", rules, criteria, verdict_of, lambda r: _action(r), "allow",
               f"No DNS Control rule matches: the lookup of {ctx['host']} resolves normally.")
    if res["verdict"] == "redirect" and res["rule"]:
        res["notes"].append(f"'{res['rule']['name']}' answers the lookup differently ({res['rule']['action']}): the traffic goes where that answer points (for example ZPA), not necessarily on through ZIA.")
    res["notes"].append("DNS Control sees the lookup only when DNS goes through ZIA (Z-Tunnel 2.0, a site tunnel, or ZIA as the resolver).")
    return res


def _sandbox(ctx: Dict[str, Any], sec: Dict[str, Any]) -> Dict[str, Any]:
    rules = ((sec.get("parts") or {}).get("rules") or {}).get("data") or []

    def criteria(r):
        out: List[Optional[Dict[str, str]]] = [_crit_categories(_names(_f(r, "urlCategories")), ctx), _crit_web_protocol(_names(_f(r, "protocols")), ctx)]
        ft = _names(_f(r, "fileTypes"))
        if ft:
            known = set(ctx["file_types"])
            out.append(_crit("File type", "match" if known & {x.upper() for x in ft} else "no_match" if known else "unknown",
                             f"Applies to {_short(ft, 4)}; " + (f"the file is {', '.join(sorted(known))}." if known else "no file type was given for this transaction.")))
        cats = _names(_f(r, "baPolicyCategories"))
        if cats:
            out.append(_crit("Threat category", "unknown", f"Applies to files ZIA classifies as {_short(cats, 3)}, decided on the file itself."))
        if _f(r, "byThreatScore"):
            out.append(_crit("Threat score", "unknown", f"Applies above threat score {_f(r, 'byThreatScore')}, decided on the file itself."))
        return out + unevaluated(r)

    def action_of(r):
        a = _action(r, "baRuleAction")
        first = str(_f(r, "firstTimeOperation") or "").upper() if _f(r, "firstTimeEnable") else ""
        return a + (f", first time: {first}" if first else "")

    res = _run("Sandbox", "sandbox", rules, criteria, lambda r: "inspect", action_of, "none",
               "No Sandbox rule matches: unknown files on this path are not held for behavioural analysis.")
    # Which file the transaction carries is content, decided at run time:
    # a rule unknown only on its file conditions applies to such a file.
    content = {"File type", "Threat category", "Threat score"}
    first = next((c for c in res["could_override"] if all(x["name"] in content for x in c.get("criteria") or [] if x["state"] != "match")), None)
    if res["certainty"] == "conditional" and first is not None and len(res["could_override"]) == 1:
        res.update(verdict="inspect", certainty="definite", rule={k: first.get(k) for k in ("id", "name", "order", "action")}, could_override=[],
                   criteria=[c for c in (first.get("criteria") or [])], content_dependent=True,
                   detail=f"Rule '{first['name']}' (order {first.get('order')}) holds files of its types for analysis ({first.get('action')}) when the transaction carries one.")
        res.pop("reason", None)
    res["notes"].append("The Sandbox analyses files, and what it finds decides at run time; the rule only says which files it holds and what happens to a malicious one.")
    return res


# ── Assembling the pipeline ──────────────────────────────────────────
_HOP_LABEL = {"atp": "Advanced Threat Protection", "firewall": "Cloud Firewall", "dns": "DNS Control", "sandbox": "Sandbox"}
_WEB_HOPS = ("cac", "url", "ssl", "ftc", "dlp", "incident")


def _visibility(t: Dict[str, Any], traffic: Dict[str, Any]) -> Tuple[Optional[bool], Dict[str, Any]]:
    """SSL inspection as a modifier: whether later modules see the full URL
    and the content (True), only the hostname (False) or that is not
    established (None); and its pipeline entry."""
    hop = next((h for h in t.get("hops") or [] if h.get("key") == "ssl"), {}) or {}
    st = hop.get("status")
    dec = hop.get("decided_by") or {}
    rule = {"id": dec.get("id"), "name": dec.get("name"), "order": dec.get("order"), "action": dec.get("action")} if dec.get("name") and traffic["web"] and traffic["encrypted"] else None
    if not traffic["web"]:
        vis, verdict, cert, detail = None, "not_applicable", "definite", f"Not applicable: {traffic['label']} is not web traffic."
    elif not traffic["encrypted"]:
        vis, verdict, cert, detail = True, "not_applicable", "definite", "Plain HTTP needs no decryption: every later module sees the full URL and the content."
    elif st == "pass":
        vis, verdict, cert, detail = True, "decrypt", "definite", "Decrypted: later modules see the full URL and the content."
    elif st == "blind":
        vis, verdict, cert, detail = False, "no_decrypt", "definite", "Left encrypted: later modules see only the hostname and its category, never the URL path or the content."
    elif st == "blocked":
        vis, verdict, cert, detail = False, "block", "definite", "Blocked at the TLS handshake."
    elif st == "out_of_scope":
        vis, verdict, cert, detail = None, "out_of_scope", "unknown", "SSL inspection is not in scope, so what later modules can see is not established."
    elif st == "not_reached":
        vis, verdict, cert, detail = False, "not_reached", "definite", "Not reached: an earlier step ends the transaction."
    elif st == "conditional":
        vis, verdict, cert, detail = None, "conditional", "conditional", "Whether this traffic is decrypted depends on identity-scoped rules, so what later modules see is conditional."
    else:
        vis, verdict, cert, detail = None, "unknown", "unknown", "Whether this traffic is decrypted is not established."
    entry = _module("SSL inspection", "ssl", verdict, cert, "modifier", rule=rule, modifier=True, detail=detail,
                    notes=[hop["detail"]] if hop.get("detail") and traffic["web"] else [])
    return vis, entry


def _from_hop(t: Dict[str, Any], key: str, module: str, zia: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """A module data_flow.trace decides (Cloud App Control, URL filtering,
    File Type Control, Web DLP): its decision as the trace made it, with
    the deciding rule's criteria and the later rules that also match."""
    hop = next((h for h in t.get("hops") or [] if h.get("key") == key), None)
    if hop is None:
        return _skip(module, key, "not_reached", "Not evaluated.")
    st = hop.get("status")
    verdict = {"blocked": "block", "pass": "allow", "warn": "caution", "none": "none", "conditional": "conditional", "unknown": "unknown",
               "blind": "blind", "out_of_scope": "out_of_scope", "not_reached": "not_reached", "na": "not_applicable",
               "enforce": "inspect", "monitor": "inspect", "metadata_only": "inspect"}.get(st, st or "unknown")
    if key == "url" and st == "na":
        verdict = "skipped"
    if key == "cac" and st == "pass":
        verdict = "allow"
    cert = "conditional" if st == "conditional" else "unknown" if st in ("unknown", "out_of_scope") else "definite"
    status = {"out_of_scope": "out_of_scope", "not_reached": "not_reached", "na": "not_applicable"}.get(st, "evaluated")
    dec = hop.get("decided_by") or {}
    pool = {"cac": zia.get("cac"), "url": zia.get("url"), "ftc": zia.get("ftc"), "dlp": zia.get("dlp")}.get(key) or []
    ordered = sorted((r for r in pool if r.get("enabled", True)), key=lambda r: (_int(r.get("order")) if _int(r.get("order")) is not None else 10 ** 9, str(r.get("id"))))
    evals = [(r, _generic_criteria(r, key, ctx)) for r in ordered]
    rule, criteria, overlaps = None, [], []
    if dec.get("name") and status == "evaluated":
        rule = {"id": dec.get("id"), "name": dec["name"], "order": dec.get("order"), "action": dec.get("action") if isinstance(dec.get("action"), str) else None}
        i = next((n for n, (r, _) in enumerate(evals) if str(r.get("id")) == str(dec.get("id"))), None)
        if i is not None:
            criteria = evals[i][1]
            if rule["order"] is None:
                rule["order"] = evals[i][0].get("order")
            overlaps = [{"id": r.get("id"), "name": r.get("name"), "order": r.get("order"), "action": r.get("action") or ", ".join(r.get("actions") or []),
                         "verdict": "", "differs": (r.get("action") or "") != (evals[i][0].get("action") or "")}
                        for r, c in evals[i + 1:] if _state(c) == "match"]
            if any(c["state"] == "unknown" for c in criteria) and cert == "definite":
                cert = "conditional"
    could = [{"id": r.get("id"), "name": r.get("name"), "order": r.get("order"), "action": r.get("action"), "verdict": "", "differs": True}
             for r in hop.get("candidate_rules") or [] if isinstance(r, dict)]
    res = _module(module, key, verdict, cert, status, rule=rule, criteria=criteria, overlaps=overlaps, could_override=could if st == "conditional" else [],
                  considered=len(evals), detail=hop.get("detail") or "")
    if key == "dlp" and status == "evaluated" and hop.get("rules"):
        res["overlaps"] = [{"id": r.get("id"), "name": r.get("name"), "order": r.get("order"), "action": r.get("action"), "verdict": "inspect", "differs": False}
                           for r in hop["rules"] if not rule or str(r.get("id")) != str(rule.get("id"))]
        res["notes"].append("DLP decides on the content: a rule blocks only when its engines match what is uploaded.")
    return res


def _generic_criteria(r: Dict[str, Any], key: str, ctx: Dict[str, Any]) -> List[Dict[str, str]]:
    """Criteria of a rule data_flow normalised (url, cac, ftc, dlp)."""
    out: List[Optional[Dict[str, str]]] = [_crit_categories(list(r.get("url_categories") or []), ctx)]
    apps = [a for a in (r.get("cloud_applications") or []) if a not in _ANY]
    if apps:
        hit = sorted(set(ctx["applications"]) & set(apps))
        out.append(_crit("Cloud application", "match" if hit else "no_match",
                         f"{ctx['host']} is {', '.join(hit)}." if hit else f"Applies to {_short(apps, 4)}; {ctx['host']} is " + (', '.join(ctx['applications']) or "no known cloud application") + "."))
    classes = [a for a in (r.get("app_classes") or []) if a not in _ANY]
    if classes:
        hit = sorted(set(ctx["app_classes"]) & set(classes))
        out.append(_crit("Application class", "match" if hit else "no_match", f"Applies to {_short(classes, 4)}" + (f"; {ctx['host']} is in {', '.join(hit)}." if hit else ".")))
    if key in ("url", "dlp"):
        out.append(_crit_web_protocol(list(r.get("protocols") or []), ctx))
    methods = [m for m in (r.get("request_methods") or []) if m not in _ANY]
    if methods:
        out.append(_crit("Request method", "unknown", f"Applies to {_short(methods, 5)}; the request method is not part of the trace."))
    if key == "ftc":
        ft = [x for x in (r.get("file_types") or []) if x not in _ANY]
        if ft:
            known = set(ctx["file_types"])
            out.append(_crit("File type", "match" if known & set(ft) else "no_match" if known else "unknown",
                             f"Applies to {_short(ft, 4)}; " + (f"the file is {', '.join(sorted(known))}." if known else "no file type was given.")))
        if r.get("operation") and r["operation"] not in _ANY:
            out.append(_crit("Operation", "unknown", f"Applies to {r['operation'].lower()}; the operation is not part of the trace."))
    if r.get("conditions"):
        out += r["conditions"]
    elif r.get("scope"):   # a rule read before conditions were kept: its scope, counted
        out.append(_crit("Rule scope", "unknown", f"Applies only to {', '.join(r['scope'])}; the trace is for any user."))
    return [c for c in out if c]


def evaluate(t: Dict[str, Any], dest: Dict[str, Any], traffic: Dict[str, Any], zia: Dict[str, Any], lookup: Dict[str, Any],
             context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Pure: the trace, the destination (path_analyzer.parse_destination
    plus the resolved categories), the traffic, the tenant read (with
    `modules` from read) and the URL lookup -> {traffic, modifier (SSL),
    modules (in order), stops_at, certainty, reasons}. `context` may give
    `file_types` and `source_ip` (the device's address as ZIA sees it,
    matched against the Cloud Firewall's source conditions; without it
    they are unknown)."""
    mods = zia.get("modules") or {}
    rd = t.get("destination") or {}
    ip = None
    try:
        ip = ipaddress.ip_address(str(dest.get("host") or ""))
    except ValueError:
        pass
    src = None
    try:
        src = ipaddress.ip_address(str((context or {}).get("source_ip") or ""))
    except ValueError:
        pass
    # A file type is a ZIA file category (FTCATEGORY_*), as data_flow.trace
    # takes it: a bare extension ("pdf") is not one, so it decides nothing.
    given = list((context or {}).get("file_types") or []) + [(context or {}).get("file_type")]
    fw_groups = (((mods.get("firewall") or {}).get("parts") or {}).get("ip_destination_groups") or {})
    ctx = {"host": dest.get("host") or "", "ip": ip, "dest": dest, "traffic": traffic, "visible": None, "source_ip": src,
           "categories": sorted({str(c).upper() for c in rd.get("categories") or []}), "alerts": sorted({str(c).upper() for c in lookup.get("security_alerts") or []}),
           "applications": sorted({str(a).upper() for a in rd.get("applications") or []}), "app_classes": sorted({str(a).upper() for a in rd.get("app_classes") or []}),
           "file_types": sorted({str(x).upper() for x in given if x and str(x).upper().startswith("FTCATEGORY_")}),
           "dst_groups": {str(g.get("id")): g for g in fw_groups.get("data") or [] if isinstance(g, dict)} if fw_groups.get("ok") else None}
    vis, ssl_entry = _visibility(t, traffic)
    ctx["visible"] = vis
    if ssl_entry.get("rule"):
        r = next((x for x in zia.get("ssl") or [] if str(x.get("id")) == str(ssl_entry["rule"].get("id"))), None)
        if r is not None:
            ssl_entry["criteria"] = _generic_criteria(r, "ssl", ctx)
    reached = bool(t.get("reaches_zscaler", True))
    seq: List[Dict[str, Any]] = []

    def own(key: str, fn: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]], web_only: bool) -> Dict[str, Any]:
        label = _HOP_LABEL[key]
        sec = mods.get(key) or {"state": "out_of_scope", "why": f"Not in scope: the {SECTIONS[key][0]} were not read."}
        if web_only and not traffic["web"]:
            return _skip(label, key, "not_applicable", f"Not applicable: {traffic['label']} is not web traffic, so {label} never sees it.")
        if sec.get("state") == "out_of_scope":
            return _skip(label, key, "out_of_scope", str(sec.get("why") or ""), "unknown")
        if sec.get("state") == "unread":
            return _skip(label, key, "unknown", f"The {SECTIONS[key][0]} could not be read ({sec.get('why')}), so what this module does is unknown.", "unknown", "unread")
        return fn(ctx, sec)

    seq.append(own("atp", _atp, True))
    seq.append(own("firewall", _firewall, False))
    seq.append(own("dns", _dns, False))
    for key, label in (("cac", "Cloud App Control"), ("url", "URL filtering")):
        seq.append(_from_hop(t, key, label, zia, ctx) if traffic["web"] else _skip(label, key, "not_applicable", f"Not applicable: {traffic['label']} is not web traffic."))
    sb = own("sandbox", _sandbox, True)
    if sb["status"] == "evaluated" and traffic["web"] and vis is not True and sb["rule"]:
        sb.update(verdict="blind" if vis is False else "unknown", certainty="definite" if vis is False else "conditional",
                  detail=f"Sandbox rule '{sb['rule']['name']}' would hold files, but " + ("the traffic is left encrypted, so no file is seen." if vis is False else "whether the traffic is decrypted is not established."))
    seq.append(sb)
    for key, label in (("ftc", "File Type Control"), ("dlp", "Inline Web DLP")):
        seq.append(_from_hop(t, key, label, zia, ctx) if traffic["web"] else _skip(label, key, "not_applicable", f"Not applicable: {traffic['label']} is not web traffic."))
    # Order and the first definite block.
    stop = None
    for m in seq:
        if not reached:
            m.update(verdict="not_reached", status="not_reached", certainty="definite", rule=None, criteria=[], overlaps=[], overlaps_catch_all=0,
                     could_override=[], detail="Not reached: the traffic never reaches Zscaler.")
            continue
        if stop is not None and m["status"] not in ("not_applicable",):
            m.update(verdict="not_reached", status="not_reached", certainty="definite", detail=f"Not reached: {stop['module']} ends the transaction first.",
                     overlaps=[], overlaps_catch_all=0, could_override=[], criteria=[], rule=None)
            continue
        if m["verdict"] == "block" and m["certainty"] == "definite":
            stop = m
    for n, m in enumerate(seq, 1):
        m["position"] = n
    if (stop is not None or not reached) and traffic["web"]:
        # SSL inspection acts on the web modules after these: a path that
        # ends before them (or never reaches Zscaler) never gets there.
        ssl_entry.update(verdict="not_reached", status="not_reached", certainty="definite", rule=None, criteria=[],
                         detail=f"Not reached: {stop['module']} ends the transaction first." if stop is not None else "Not reached: the traffic never reaches Zscaler.")
    reasons: List[str] = []
    for m in [ssl_entry] + seq:
        if m["status"] in ("not_reached", "not_applicable"):
            continue
        if m["certainty"] == "conditional":
            reasons.append(f"{m['module']}: " + (m.get("reason") or _conditional_reason(m, t, ssl_entry)).rstrip(".") + ".")
        elif m["certainty"] == "unknown" and m["status"] == "out_of_scope":
            reasons.append(f"{m['module']}: not in scope on the Scope page, so not assessed.")
        elif m["certainty"] == "unknown":
            reasons.append(f"{m['module']}: not established ({(m['detail'] or 'could not be read')[:160].rstrip('.')}).")
    if t.get("conditional"):
        reasons.insert(0, "Routing: whether the device's traffic reaches ZIA could not be verified.")
    certainty = "conditional" if reasons else "definite"
    return {"traffic": traffic, "modifier": ssl_entry, "modules": seq, "stops_at": stop["key"] if stop else None,
            "certainty": certainty, "reasons": [r.replace("..", ".") for r in reasons]}


def depends_words(r: Dict[str, Any]) -> str:
    """What a rule the trace calls conditional depends on, named: 'group
    Finance; time window Night', from its scope (path_whatif.scope_items),
    request methods and the conditions this tool does not evaluate."""
    import path_whatif
    parts: List[str] = []
    for dim, items in (r.get("scope_items") or {}).items():
        names = [str(i.get("name")) for i in items if isinstance(i, dict) and i.get("name")]
        parts.append(f"{path_whatif.LABEL.get(dim, dim)} {_short(names, 3)}" if names else path_whatif.LABEL.get(dim, dim))
    methods = [m for m in r.get("request_methods") or [] if str(m).upper() not in _ANY]
    if methods:
        parts.append(f"request method {_short(methods, 3)}")
    for c in r.get("conditions") or []:
        if isinstance(c, dict) and c.get("name") and not any(str(c["name"]).lower().rstrip("s") in p.lower() for p in parts):
            parts.append(str(c.get("detail") or c["name"]).rstrip("."))
    if not parts:
        parts = [str(x) for x in r.get("scope") or []]
    return "; ".join(parts) or "a condition that is not given"


def _conditional_reason(m: Dict[str, Any], t: Dict[str, Any], ssl_entry: Dict[str, Any]) -> str:
    """Why a module is conditional, naming the rule and the condition it
    depends on (never just 'conditions not established')."""
    unknown = [c for c in m.get("criteria") or [] if c.get("state") == "unknown"]
    rule = (m.get("rule") or {}).get("name")
    if unknown:
        return (f"the deciding rule '{rule}'" if rule else "the deciding rule") + " applies only when " + \
            "; ".join(f"{c['name'].lower()}: {str(c.get('detail') or 'not known').rstrip('.')}" for c in unknown[:3])
    hop = next((h for h in t.get("hops") or [] if h.get("key") == m.get("key")), {}) or {}
    cands = [r for r in hop.get("candidate_rules") or [] if isinstance(r, dict)]
    if not cands and hop.get("status") == "conditional":   # Web DLP: every covering rule is scoped
        cands = [r for r in hop.get("rules") or [] if isinstance(r, dict) and r.get("scope")]
    if cands:
        def act(r: Dict[str, Any]) -> str:
            return str(r.get("action") or ", ".join(r.get("actions") or []) or "its action")
        none = "a condition that is not given"
        scoped = [r for r in cands if depends_words(r) != none]
        rest = [r for r in cands if depends_words(r) == none]
        text = _short([f"rule '{r.get('name')}' ({act(r)}) applies only for {depends_words(r)}" for r in scoped], 3) if scoped else \
            "a rule's conditions cannot be evaluated"
        return text + (f"; otherwise rule '{rest[0].get('name')}' ({act(rest[0])}) decides" if rest else "")
    if hop.get("missing_context"):
        return "it depends on " + ", ".join(str(x) for x in hop["missing_context"]) + ", which the trace is not given"
    if m.get("key") != "ssl" and ssl_entry.get("certainty") == "conditional":
        return "it depends on SSL inspection, whose decision is conditional (see SSL inspection)"
    return "the decision depends on conditions that are not established"


# ── Folding the result into the trace and the verdict ────────────────
_HOP_STATUS = {"block": "blocked", "allow": "pass", "caution": "warn", "redirect": "warn", "inspect": "pass", "none": "none",
               "unknown": "unknown", "not_applicable": "na", "not_reached": "not_reached", "out_of_scope": "out_of_scope", "blind": "blind"}


def extend_trace(t: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Draw the modules data_flow.trace does not read as hops in their
    place, end the trace at the first definite block, and, for traffic
    that is not web, mark the web hops not applicable (and send it direct
    when the forwarding mode carries only web traffic)."""
    traffic = result["traffic"]
    hops: List[Dict[str, Any]] = t["hops"]
    by_key = {m["key"]: m for m in result["modules"]}
    fwd = next((h for h in hops if h.get("key") == "forwarding"), None)
    if not traffic["web"] and t.get("reaches_zscaler") and fwd and fwd.get("status") in ("pass", "warn") and \
            str(fwd.get("mode") or "") in ("Z-Tunnel 1.0", "Tunnel with local proxy", "Enforce proxy (PAC)"):
        fwd["status"] = "bypass"
        fwd["detail"] = (fwd.get("detail") or "") + f" {fwd['mode']} carries only web traffic, so {traffic['label']} leaves the device directly and never reaches ZIA."
        fwd["weak_point"] = {"severity": "high", "title": "Non-web traffic not forwarded", "fix": "Use Z-Tunnel 2.0 so every port and protocol reaches the Cloud Firewall."}
        t["reaches_zscaler"], t["outcome"], t["decrypted"] = False, "bypassed", False
        t["policy_conditional"] = False   # nothing on the path decides anything any more
        t["weak_points"] = [dict(fwd["weak_point"], hop="forwarding", hop_label=fwd["label"])] + list(t.get("weak_points") or [])
        for h in hops:
            if h.get("key") in _WEB_HOPS or h.get("key") == "pac":
                h.update(status="not_reached", decided_by=None, weak_point=None, why="sent direct by the forwarding profile",
                         detail="Not reached: the forwarding profile sends this traffic direct.")
                if h.get("module_hop"):
                    h["module_hop"] = module_hop(h["module_hop"]["module"], "not_reached", key=h["module_hop"]["key"],
                                                 detail="Not reached: the forwarding profile sends this traffic direct.")
        for m in result["modules"]:
            m.update(verdict="not_reached", status="not_reached", certainty="definite", rule=None, criteria=[], overlaps=[], overlaps_catch_all=0,
                     could_override=[], detail="Not reached: the forwarding mode sends this traffic direct.")
        result["stops_at"] = None
    if not t.get("reaches_zscaler", True):
        return

    def hop_for(key: str) -> Dict[str, Any]:
        m = by_key[key]
        r = m.get("rule") or None
        where = "the default rule" if r and r.get("default") else f"order {r.get('order')}" if r and r.get("order") is not None else ""
        detail = (f"Rule '{r['name']}'" + (f" ({where})" if where else "") + f" decides: {r.get('action') or m['verdict']}." if r else m["detail"])
        return {"key": key, "label": m["module"], "status": "conditional" if m["certainty"] == "conditional" and m["verdict"] == "block" else _HOP_STATUS.get(m["verdict"], "unknown"),
                "decided_by": {k: r.get(k) for k in ("id", "name", "order", "action")} if r else None, "detail": detail, "weak_point": None,
                "why": None if r or m["verdict"] not in ("unknown",) else "not established", "evidence_mode": "configuration", "observed": False,
                "certainty": m["certainty"]}

    first_web = next((i for i, h in enumerate(hops) if h.get("key") in _WEB_HOPS), len(hops))
    for k in ("dns", "firewall", "atp"):
        hops.insert(first_web, hop_for(k))
    ftc_i = next((i for i, h in enumerate(hops) if h.get("key") == "ftc"), len(hops))
    hops.insert(ftc_i, hop_for("sandbox"))
    stop = result.get("stops_at")
    if not traffic["web"]:
        for h in hops:
            if h.get("key") in _WEB_HOPS:
                h.update(status="na", decided_by=None, weak_point=None, why="not web traffic",
                         detail=f"Not applicable: {traffic['label']} is not HTTP or HTTPS over TCP, so the web proxy modules never see it.")
        t["decrypted"] = False
        if stop is None:
            fw = by_key["firewall"]
            t["outcome"] = "out_of_scope" if fw["status"] == "out_of_scope" else "unknown" if fw["verdict"] == "unknown" else "blind"
            t["policy_conditional"] = t.get("policy_conditional") or fw["certainty"] == "conditional"
            t["content_inspection_possible"] = False
    if stop in ("atp", "firewall", "dns"):
        idx = next(i for i, h in enumerate(hops) if h.get("key") == stop)
        src = {"key": stop, "label": by_key[stop]["module"], "object_id": (by_key[stop].get("rule") or {}).get("id"), "object_name": (by_key[stop].get("rule") or {}).get("name")}
        for h in hops[idx + 1:]:
            h.update(status="not_reached", decided_by=None, weak_point=None, why=f"stopped at {src['label']}", stopped_by=src,
                     detail=f"Not reached: the path stopped at {src['label']}. This control was not evaluated.")
        if not t.get("conditional"):
            t["outcome"] = "blocked"
        t["decrypted"] = False
        t["content_inspection_possible"] = False
    # Recomputed from the hops as they now stand: a web hop that is not
    # applicable or not reached makes nothing conditional.
    t["policy_conditional"] = any(h.get("status") == "conditional" and h.get("key") != "incident" for h in hops) or \
        (not traffic["web"] and stop is None and by_key["firewall"]["certainty"] == "conditional")


def annotate_verdict(v: Dict[str, Any], result: Dict[str, Any], host: str) -> None:
    """The overall result says definite or conditional, and why; for
    traffic that is not web the headline names the firewall decision."""
    v["certainty"] = result["certainty"]
    v["certainty_reasons"] = list(result["reasons"])
    v["traffic"] = result["traffic"]
    traffic = result["traffic"]
    stop = next((m for m in result["modules"] if m["key"] == result.get("stops_at")), None)
    if v["outcome"] == "blocked" and stop is not None and stop["key"] in ("firewall", "dns"):
        r = stop.get("rule") or {}
        v["summary"] = (f"Rule '{r.get('name')}' ({r.get('action')}) refuses the connection, so nothing reaches {host}." if stop["key"] == "firewall" else
                        f"Rule '{r.get('name')}' ({r.get('action')}) answers the lookup with a block, so the device never connects to {host}.")
    if traffic["web"] or v["outcome"] in ("bypassed", "blocked"):
        return
    fw = next(m for m in result["modules"] if m["key"] == "firewall")
    r = fw.get("rule") or {}
    if fw["status"] == "out_of_scope":
        v["headline"] = f"{traffic['label']} to {host}: whether the Cloud Firewall allows it is not assessed (not in scope)."
    elif fw["verdict"] == "unknown":
        v["headline"] = f"{traffic['label']} to {host}: the Cloud Firewall's decision is unknown."
    else:
        what = "blocked" if fw["verdict"] == "block" else "allowed"
        by = (f"Cloud Firewall rule '{r.get('name')}'" + (" (the default rule)" if r.get("default") else f" (order {r.get('order')})")) if r.get("name") else "the Cloud Firewall"
        v["headline"] = f"{traffic['label']} to {host} is {what} by {by}" + (
            ", unless an earlier rule with a condition this tool cannot evaluate applies first." if fw["certainty"] == "conditional" else ".")
    v["summary"] = (f"{traffic['label']} is not web traffic: URL filtering, Cloud App Control, SSL inspection, Sandbox, File Type Control and Web DLP never see it, "
                    "so its content is not inspected inline.")
    v["content_inspection_possible"] = False


ASSUMPTIONS: List[str] = [
    "ZIA modules are traced in this order: Advanced Threat Protection, Cloud Firewall, DNS Control, Cloud App Control and URL filtering, Sandbox, File Type Control and Web DLP; SSL inspection decides what the later modules can see.",
    "A condition this tool cannot evaluate (a time window, device trust, user risk score, users, groups, locations, a source IP, a destination country, a hostname's IP address) is shown as unknown, never guessed; the result is conditional when such a condition could change it.",
    "In Advanced Threat Protection an allowlist entry is taken to win over a denylist entry, and each threat category toggle is matched to the categories ZIA's URL lookup returns; content, signature and page-risk detections happen at run time and are not predicted.",
]
