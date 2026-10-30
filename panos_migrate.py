"""Firewall and private-access migration from Palo Alto Networks (PAN-OS).

Reads a PAN-OS configuration export (the running or candidate config an
admin saves from the firewall or Panorama: Device > Setup > Operations >
Export named configuration snapshot) and maps it to a migration plan for
the existing Bulk changes engine. Nothing here contacts a tenant or writes
to one: the plan is rehearsed (previewed) and applied on Bulk changes,
through the same four gates as every other change.

What is mapped (a PAN-OS object or field -> its Zscaler counterpart):

* Security rules -> ZIA Cloud Firewall rules (`cloud_firewall_rules`,
  POST /firewallFilteringRules), always created DISABLED unless the
  operator ticks "create enabled" on Bulk changes. Actions: allow -> ALLOW,
  deny and drop -> BLOCK_DROP, reset-client / reset-server / reset-both ->
  BLOCK_RESET (the PAN-OS "deny" sends the application's default deny,
  carried as a silent drop: assumed closest match).
* Address objects and address groups -> IP source groups
  (`cloud_firewall.add_ip_source_group`, POST /ipSourceGroups, field
  ip_addresses) when used as a rule's source, and IP destination groups
  (`add_ip_destination_group`, POST /ipDestinationGroups, type DSTN_IP or
  DSTN_FQDN, field addresses) when used as a destination. A group mixing
  IP addresses and FQDNs becomes two destination groups (a ZIA destination
  group has one type). Literal addresses in a rule go to the rule's src_ips
  and dest_addresses.
* Service objects and service groups -> network services
  (`cloud_firewall.add_network_service`, POST /networkServices, fields
  dest_tcp_ports / dest_udp_ports / src_tcp_ports / src_udp_ports as
  {start, end}). service-http and service-https carry their PAN-OS ports
  (TCP 80 and 8080; TCP 443). "application-default" adds no service: the
  ZIA network application matches the application on its own ports.
* Applications (App-ID names) -> ZIA network applications (nw_applications)
  where a mapping exists in APP_MAP (assumed enum names, checked against
  the tenant's list_network_apps when the plan is previewed).
* Zones are noted: Cloud Firewall has no zones (it inspects what a
  location or Client Connector forwards); each zone is listed with the
  rules that use it.
* Allow rules from a GlobalProtect zone (gp_zones: by default zone names
  that say globalprotect, gp, vpn or remote-access) to internal
  destinations (private addresses or host names) -> ZPA application
  segments (the ZPA builder's CSV: name, domains, tcp_ports, udp_ports) and
  an access rule over them (the ZPA builder's policy rules). The users a
  rule names are noted for the ZPA access rule; they are not mapped.

What is not mapped is listed with the reason: rules that negate the source
or destination, name users, URL categories, schedules or HIP profiles,
applications with no network application (web apps belong to URL
filtering or Cloud App Control), wildcard and dynamic addresses, IPv6,
SCTP services; NAT, decryption and policy-based forwarding rules;
GlobalProtect portal and gateway settings (they correspond to Client
Connector app and forwarding profiles). A rule is carried exactly or not
at all: dropping one of its conditions would widen or narrow what it
matches, so a rule with any unmappable part is listed, never trimmed.

The export is untrusted: it is parsed with defusedxml (no DTD, no entity
declarations, no external references), capped in size, nesting depth and
element count, and every value that becomes a Zscaler name is checked.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import defusedxml.ElementTree as DET
from defusedxml import DefusedXmlException

FORMAT = "panos-migration-plan"
FORMAT_VERSION = 1
OP_TYPE = "zia_firewall_import"
MAX_BYTES = 8 * 1024 * 1024          # a large Panorama export is a few MB
MAX_DEPTH = 48
MAX_ELEMENTS = 250_000
MAX_RULES = 200                      # rules one plan carries to ZIA (the importer's limit)
MAX_OBJECTS = 500                    # groups or services one plan carries
MAX_ADDRESSES = 1000                 # addresses in one group
MAX_SEGMENTS = 500                   # the ZPA builder's CSV limit
MAX_TEXT = 255
RULE_NAME_MAX = 31                   # ZIA refuses longer Cloud Firewall rule names
OBJECT_NAME_MAX = 63                 # assumed limit for IP group and network service names
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$")
DEFAULT_GP_ZONE_RE = re.compile(r"(global.?protect|(^|[^a-z])gp([^a-z]|$)|vpn|remote.?access)", re.I)
_FQDN_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$", re.I)
_UNSAFE = re.compile("[<>\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]")

# PAN-OS App-ID -> ZIA network application (Cloud Firewall nw_applications).
# Assumed enum names (Zscaler's published network application list; the
# same names the ZIA security baseline uses); the preview checks each one
# against the tenant's list_network_apps and refuses a rule naming one the
# tenant does not have.
APP_MAP: Dict[str, str] = {
    "web-browsing": "HTTP", "ssl": "SSL", "http2": "HTTP2", "quic": "QUIC", "dns": "DNS", "dns-base": "DNS", "ntp": "NTP", "ntp-base": "NTP",
    "ssh": "SSH", "ms-rdp": "RDP", "ftp": "FTP", "smtp": "SMTP", "smtp-base": "SMTP", "pop3": "POP3", "imap": "IMAP", "ldap": "LDAP",
    "kerberos": "KRB5", "radius": "RADIUS", "snmp": "SNMP", "snmp-base": "SNMP", "dhcp": "DHCP", "icmp": "ICMP", "ping": "ICMP",
    "ocsp": "OCSP", "sip": "SIP", "rtp": "RTP", "rtcp": "RTCP", "telnet": "TELNET", "ms-ds-smb": "SMB", "ms-ds-smb-base": "SMB",
    "netbios-ss": "NETBIOS", "bittorrent": "BITTORRENT", "tor": "TOR", "openvpn": "OPENVPN", "ultrasurf": "ULTRASURF",
    "psiphon": "PSIPHON", "zoom": "ZOOM", "webex": "WEBEX", "gotomeeting": "GOTOMEETING", "skype": "SKYPE", "teredo": "TEREDO",
}
# App-IDs that are web or SaaS applications: Cloud Firewall does not match
# them; they belong to URL filtering or Cloud App Control (said in the reason).
WEB_APP_HINT = re.compile(r"^(facebook|twitter|linkedin|instagram|youtube|office365|ms-office365|sharepoint|onedrive|salesforce|box|"
                          r"dropbox|google|gmail|slack|github|chatgpt|openai|outlook-web|workday|servicenow|zendesk|tiktok)", re.I)
# The TCP/UDP ports an App-ID uses by default, for a ZPA application
# segment of a rule whose service is application-default (assumed: the
# well-known ports of each protocol).
APP_PORTS: Dict[str, Tuple[str, str]] = {
    "web-browsing": ("80", ""), "ssl": ("443", ""), "ssh": ("22", ""), "ms-rdp": ("3389", "3389"), "ms-ds-smb": ("445", ""),
    "ms-ds-smb-base": ("445", ""), "ldap": ("389", "389"), "dns": ("53", "53"), "dns-base": ("53", "53"), "ftp": ("21", ""),
    "smtp": ("25", ""), "telnet": ("23", ""), "kerberos": ("88", "88"), "snmp": ("", "161"), "ntp": ("", "123"), "sip": ("5060", "5060"),
}
PREDEFINED_SERVICES: Dict[str, Dict[str, List[List[int]]]] = {
    "service-http": {"dest_tcp": [[80, 80], [8080, 8080]]},
    "service-https": {"dest_tcp": [[443, 443]]},
}
ACTIONS = {"allow": "ALLOW", "deny": "BLOCK_DROP", "drop": "BLOCK_DROP", "reset-client": "BLOCK_RESET", "reset-server": "BLOCK_RESET",
           "reset-both": "BLOCK_RESET"}

# Where each PAN-OS object lands (the page's cross-reference table).
CROSSREF: List[Dict[str, str]] = [
    {"source": "rulebase/security/rules/entry", "target": "ZIA Cloud Firewall rule", "api": "POST /firewallFilteringRules (cloud_firewall_rules.add_rule)",
     "how": "created DISABLED; name = prefix + rule name, cut to 31 characters"},
    {"source": "address/entry (ip-netmask, ip-range) and address-group/entry (static)", "target": "ZIA IP source group / IP destination group",
     "api": "POST /ipSourceGroups · POST /ipDestinationGroups (cloud_firewall.add_ip_source_group / add_ip_destination_group)",
     "how": "source use -> IP source group; destination use -> destination group (DSTN_IP)"},
    {"source": "address/entry (fqdn)", "target": "ZIA IP destination group (DSTN_FQDN)", "api": "POST /ipDestinationGroups",
     "how": "destinations only; an FQDN in a source is not carried"},
    {"source": "service/entry, service-group/entry", "target": "ZIA network service", "api": "POST /networkServices (cloud_firewall.add_network_service)",
     "how": "TCP and UDP destination and source ports"},
    {"source": "application/member (App-ID)", "target": "ZIA network application (nw_applications)", "api": "GET /networkApplications (checked)",
     "how": "where APP_MAP has one; web and SaaS apps belong to URL filtering or Cloud App Control"},
    {"source": "from / to (zones)", "target": "(none: noted)", "api": "-", "how": "Cloud Firewall has no zones; scope by location by hand"},
    {"source": "allow rule from a GlobalProtect zone to internal addresses", "target": "ZPA application segment + access rule",
     "api": "the ZPA builder (zpa_app_segments CSV, zpa_policies access)", "how": "segments created disabled; users noted for the access rule"},
    {"source": "source-user, category, schedule, source-hip, negate-*", "target": "(not mapped)", "api": "-", "how": "the rule is listed with the reason"},
    {"source": "rulebase/nat, decryption, pbf; global-protect portals and gateways", "target": "(not mapped)", "api": "-",
     "how": "listed: NAT has no Cloud Firewall equivalent here; decryption -> SSL inspection; GlobalProtect -> Client Connector profiles"},
]


class MigrationError(ValueError):
    """The export cannot be read (the endpoint's 400)."""


# ---------------------------------------------------------------------------
# Hardened parse
# ---------------------------------------------------------------------------

def _tag(e: Any) -> str:
    return str(e.tag).rsplit("}", 1)[-1] if isinstance(e.tag, str) else ""


def parse(data: bytes, name: str = "config.xml") -> Any:
    """The export's root element, parsed with defusedxml (DTDs, entity
    declarations and external references refused), within the size, depth
    and element-count caps. Raises MigrationError in plain words."""
    if not isinstance(data, (bytes, bytearray)):
        raise MigrationError(f"{name}: the export must be a file")
    if len(data) > MAX_BYTES:
        raise MigrationError(f"{name}: larger than {MAX_BYTES // (1024 * 1024)} MiB; export one virtual system or device group at a time")
    if not data.strip():
        raise MigrationError(f"{name}: the file is empty")
    try:
        root = DET.fromstring(bytes(data), forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException:
        raise MigrationError(f"{name}: DTDs, entity declarations and external references are not accepted") from None
    except DET.ParseError as e:
        raise MigrationError(f"{name}: not well-formed XML ({str(e)[:120]})") from None
    count = 0
    stack = [(root, 1)]
    while stack:
        el, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH:
            raise MigrationError(f"{name}: nested more than {MAX_DEPTH} levels deep; not a PAN-OS configuration")
        if count > MAX_ELEMENTS:
            raise MigrationError(f"{name}: more than {MAX_ELEMENTS:,} elements; export one virtual system or device group at a time")
        stack.extend((c, depth + 1) for c in el)
    if _tag(root) != "config":
        raise MigrationError(f"{name}: not a PAN-OS configuration export (the root element is <{_tag(root)[:40]}>, expected <config>)")
    return root


def _child(el: Any, *path: str) -> Any:
    for p in path:
        if el is None:
            return None
        el = next((c for c in el if _tag(c) == p), None)
    return el


def _entries(el: Any, *path: str) -> List[Any]:
    node = _child(el, *path)
    return [c for c in node if _tag(c) == "entry"] if node is not None else []


def _members(el: Any, *path: str) -> List[str]:
    node = _child(el, *path)
    if node is None:
        return []
    out = [_text(c) for c in node if _tag(c) == "member"]
    return [m for m in out if m]


def _text(el: Any, *path: str) -> str:
    node = _child(el, *path) if path else el
    return " ".join(str(node.text or "").split())[:MAX_TEXT] if node is not None else ""


def _name(el: Any) -> str:
    return " ".join(str(el.get("name") or "").split())[:MAX_TEXT]


# ---------------------------------------------------------------------------
# Inventory: containers (shared, virtual systems, device groups)
# ---------------------------------------------------------------------------

def _containers(root: Any) -> List[Dict[str, Any]]:
    """Each place objects and rules live: Panorama's shared, every device
    group, every virtual system. Rule order: shared pre, then each
    container's pre-rulebase or rulebase, then its post-rulebase, shared post."""
    out: List[Dict[str, Any]] = []
    shared = _child(root, "shared")
    if shared is not None:
        out.append({"kind": "shared", "name": "shared", "el": shared})
    for dev in _entries(root, "devices"):
        for vs in _entries(dev, "vsys"):
            out.append({"kind": "vsys", "name": _name(vs) or "vsys", "el": vs})
        for dg in _entries(dev, "device-group"):
            out.append({"kind": "device-group", "name": _name(dg) or "device-group", "el": dg})
    return out


def _objects(c: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    el = c["el"]
    addr = {_name(e): e for e in _entries(el, "address") if _name(e)}
    groups = {_name(e): e for e in _entries(el, "address-group") if _name(e)}
    svc = {_name(e): e for e in _entries(el, "service") if _name(e)}
    sgroups = {_name(e): e for e in _entries(el, "service-group") if _name(e)}
    agroups = {_name(e): e for e in _entries(el, "application-group") if _name(e)}
    return {"address": addr, "address-group": groups, "service": svc, "service-group": sgroups, "application-group": agroups}


def _rules(c: Dict[str, Any], where: str) -> List[Tuple[str, Any]]:
    el = c["el"]
    out: List[Tuple[str, Any]] = []
    for base in ((where,) if where != "rulebase" else ("rulebase",)):
        for r in _entries(el, base, "security", "rules"):
            out.append((base, r))
    return out


# ---------------------------------------------------------------------------
# Address and service resolution
# ---------------------------------------------------------------------------

class _Ctx:
    def __init__(self, scopes: List[Dict[str, Dict[str, Any]]]):
        self.scopes = scopes   # the rule's own container first, then shared

    def find(self, kind: str, name: str) -> Optional[Any]:
        for s in self.scopes:
            if name in s.get(kind, {}):
                return s[kind][name]
        return None


def _literal(v: str) -> Optional[Tuple[str, str]]:
    """A literal in a rule: ('ip', '10.0.0.0/8') or ('range', 'a-b') or None."""
    s = v.strip()
    try:
        net = ipaddress.ip_network(s, strict=False)
        return ("ip6" if net.version == 6 else "ip", str(net) if "/" in s else str(net.network_address))
    except ValueError:
        pass
    m = re.fullmatch(r"([0-9.]+)-([0-9.]+)", s)
    if m:
        try:
            a, b = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
            if a <= b:
                return ("range", f"{a}-{b}")
        except ValueError:
            return None
    return None


def _address_values(ctx: _Ctx, name: str, seen: Set[str], depth: int = 0) -> Tuple[List[Tuple[str, str]], Optional[str]]:
    """[(kind, value)] for an address or address group name, kind ip | range |
    fqdn; or a reason it cannot be carried."""
    if depth > 16 or name in seen:
        return [], f"address group '{name}' refers to itself"
    seen = seen | {name}
    a = ctx.find("address", name)
    if a is not None:
        if _child(a, "ip-netmask") is not None:
            lit = _literal(_text(a, "ip-netmask"))
            if not lit:
                return [], f"address '{name}' has an ip-netmask that is not an address ({_text(a, 'ip-netmask')[:40]})"
            if lit[0] == "ip6":
                return [], f"address '{name}' is IPv6 ({lit[1]}): create an IPv6 group in ZIA by hand"
            return [lit], None
        if _child(a, "ip-range") is not None:
            lit = _literal(_text(a, "ip-range"))
            if not lit or lit[0] != "range":
                return [], f"address '{name}' has an ip-range that is not an IPv4 range ({_text(a, 'ip-range')[:40]})"
            return [lit], None
        if _child(a, "fqdn") is not None:
            f = _text(a, "fqdn").lower().rstrip(".")
            if not _FQDN_RE.match(f):
                return [], f"address '{name}' has an FQDN that is not a host name ({f[:60]})"
            return [("fqdn", f)], None
        if _child(a, "ip-wildcard") is not None:
            return [], f"address '{name}' is a wildcard mask ({_text(a, 'ip-wildcard')[:40]}): ZIA has no wildcard masks"
        return [], f"address '{name}' has a type this mapping does not read"
    g = ctx.find("address-group", name)
    if g is not None:
        if _child(g, "dynamic") is not None:
            return [], f"address group '{name}' is dynamic (tag filter): ZIA groups are static lists"
        out: List[Tuple[str, str]] = []
        for m in _members(g, "static"):
            vals, why = _address_values(ctx, m, seen, depth + 1)
            if why:
                return [], why
            out.extend(vals)
        if not out:
            return [], f"address group '{name}' is empty"
        return out, None
    lit = _literal(name)
    if lit:
        if lit[0] == "ip6":
            return [], f"'{name}' is IPv6: create an IPv6 group in ZIA by hand"
        return [lit], None
    if _FQDN_RE.match(name.lower()) and "." in name:
        return [], f"'{name}' is not an address object in the export (a region, an external dynamic list or a missing object)"
    return [], f"'{name}' is not an address object in the export (a region, an external dynamic list or a missing object)"


def _ports(text: str) -> Optional[List[List[int]]]:
    out: List[List[int]] = []
    for part in [p for p in re.split(r"[,\s]+", text or "") if p]:
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            return None
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 1 <= a <= b <= 65535:
            return None
        if [a, b] not in out:
            out.append([a, b])
    return sorted(out)


def _service_def(ctx: _Ctx, name: str, seen: Set[str], depth: int = 0) -> Tuple[List[Tuple[str, Dict[str, List[List[int]]]]], Optional[str]]:
    """[(service name, {dest_tcp, dest_udp, src_tcp, src_udp})] for a service
    or service group, or the reason it cannot be carried."""
    if depth > 16 or name in seen:
        return [], f"service group '{name}' refers to itself"
    seen = seen | {name}
    s = ctx.find("service", name)
    if s is not None:
        proto = _child(s, "protocol")
        for p in ("tcp", "udp"):
            node = _child(proto, p) if proto is not None else None
            if node is not None:
                dst = _ports(_text(node, "port"))
                src = _ports(_text(node, "source-port")) if _child(node, "source-port") is not None else []
                if not dst or src is None:
                    return [], f"service '{name}' has ports that are not numbers or ranges"
                return [(name, {f"dest_{p}": dst, **({f"src_{p}": src} if src else {})})], None
        if proto is not None and _child(proto, "sctp") is not None:
            return [], f"service '{name}' is SCTP: ZIA network services carry TCP and UDP"
        return [], f"service '{name}' has no TCP or UDP ports"
    g = ctx.find("service-group", name)
    if g is not None:
        out: List[Tuple[str, Dict[str, List[List[int]]]]] = []
        for m in _members(g, "members") or _members(g):
            if m in PREDEFINED_SERVICES:
                out.append((m, PREDEFINED_SERVICES[m]))
                continue
            vals, why = _service_def(ctx, m, seen, depth + 1)
            if why:
                return [], why
            out.extend(vals)
        if not out:
            return [], f"service group '{name}' is empty"
        return out, None
    if name in PREDEFINED_SERVICES:
        return [(name, PREDEFINED_SERVICES[name])], None
    return [], f"service '{name}' is not in the export"


def _apps(ctx: _Ctx, names: Sequence[str]) -> Tuple[List[str], List[str], Optional[str]]:
    """(ZIA network apps, App-IDs, reason) for a rule's application list."""
    flat: List[str] = []
    for n in names:
        g = ctx.find("application-group", n)
        if g is not None:
            flat.extend(_members(g, "members") or _members(g))
        else:
            flat.append(n)
    zia: List[str] = []
    for a in flat:
        z = APP_MAP.get(a.lower())
        if z is None:
            if WEB_APP_HINT.match(a):
                return [], flat, (f"application '{a}' is a web or SaaS application: in ZIA it belongs to URL filtering or Cloud App "
                                  "Control, not to a Cloud Firewall rule")
            return [], flat, f"application '{a}' has no ZIA network application in the mapping"
        if z not in zia:
            zia.append(z)
    return zia, flat, None


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

def slug(text: str, limit: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-")[:limit] or "x"


class _Names:
    """Unique Zscaler names under the prefix, cut to each kind's limit."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.used: Dict[str, Set[str]] = {}

    def make(self, kind: str, base: str, limit: int) -> str:
        used = self.used.setdefault(kind, set())
        stem = f"{self.prefix}-{slug(base, limit)}"[:limit].rstrip("-")
        name, n = stem, 2
        while name.lower() in used:
            suffix = f"-{n}"
            name = stem[:limit - len(suffix)].rstrip("-") + suffix
            n += 1
        used.add(name.lower())
        return name


# ---------------------------------------------------------------------------
# Build the plan
# ---------------------------------------------------------------------------

def _is_internal(kind: str, value: str) -> bool:
    if kind == "fqdn":
        return True
    try:
        if kind == "range":
            a, b = value.split("-")
            return ipaddress.ip_address(a).is_private and ipaddress.ip_address(b).is_private
        return ipaddress.ip_network(value, strict=False).is_private
    except ValueError:
        return False


def _zpa_domains(vals: Sequence[Tuple[str, str]]) -> Tuple[List[str], Optional[str]]:
    out: List[str] = []
    for kind, v in vals:
        if kind == "range":
            a, b = v.split("-")
            nets = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)))
            if len(nets) > 20:
                return [], f"the range {v} needs more than 20 subnets in a ZPA segment"
            out.extend(str(n) if n.prefixlen < 32 else str(n.network_address) for n in nets)
        elif kind == "ip" and "/" in v and v.endswith("/32"):
            out.append(v[:-3])
        else:
            out.append(v)
    for d in out:
        if "/" in d and ipaddress.ip_network(d, strict=False).prefixlen < 9:
            return [], f"{d} is far wider than one application"
    return sorted(set(out)), None


def _csv_cell(v: str) -> str:
    v = str(v).replace('"', "'")
    if v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        v = "'" + v
    return f'"{v}"' if any(c in v for c in ",;\n") else v


def build_plan(data: bytes, *, source_name: str = "config.xml", prefix: str = "pan", gp_zones: Optional[Iterable[str]] = None,
               include_disabled: bool = False) -> Dict[str, Any]:
    """The migration plan for an export (see the module doc). Pure: reads the
    bytes given, never a tenant."""
    prefix = str(prefix or "").strip()
    if not PREFIX_RE.match(prefix):
        raise MigrationError("The prefix must be 1 to 10 letters, digits, '-' or '_', starting with a letter or digit (for example pan).")
    gp_list = [str(z).strip() for z in (gp_zones or []) if str(z).strip()][:50]
    if any(_UNSAFE.search(z) or len(z) > 63 for z in gp_list):
        raise MigrationError("A GlobalProtect zone name holds characters a zone name never has.")
    root = parse(data, source_name)
    sha = hashlib.sha256(bytes(data)).hexdigest()
    containers = _containers(root)
    objs = {c["name"]: _objects(c) for c in containers}
    shared = objs.get("shared") if any(c["kind"] == "shared" for c in containers) else {}
    is_gp = (lambda z: z in gp_list) if gp_list else (lambda z: bool(DEFAULT_GP_ZONE_RE.search(z)))

    names = _Names(prefix)
    src_groups: Dict[str, Dict[str, Any]] = {}
    dst_groups: Dict[str, Dict[str, Any]] = {}
    services: Dict[str, Dict[str, Any]] = {}
    rules: List[Dict[str, Any]] = []
    segments: List[Dict[str, Any]] = []
    mapped: List[Dict[str, Any]] = []
    unmappable: List[Dict[str, Any]] = []
    zones: Dict[str, Dict[str, Any]] = {}
    seg_names: Set[str] = set()

    def group_for(direction: str, obj_name: str, vals: List[Tuple[str, str]]) -> Tuple[List[str], Optional[str]]:
        """The group name(s) an address object or group becomes on one side."""
        if direction == "src":
            if any(k == "fqdn" for k, _ in vals):
                return [], f"'{obj_name}' holds host names: a ZIA IP source group holds IP addresses only"
            key = obj_name
            if key not in src_groups:
                if len(src_groups) >= MAX_OBJECTS:
                    return [], f"more than {MAX_OBJECTS} source groups in one plan"
                src_groups[key] = {"name": names.make("src", obj_name, OBJECT_NAME_MAX), "source": obj_name,
                                   "ip_addresses": sorted({v for _, v in vals})[:MAX_ADDRESSES]}
            return [src_groups[key]["name"]], None
        out = []
        for typ, want in (("DSTN_IP", ("ip", "range")), ("DSTN_FQDN", ("fqdn",))):
            part = sorted({v for k, v in vals if k in want})
            if not part:
                continue
            key = f"{obj_name}|{typ}"
            if key not in dst_groups:
                if len(dst_groups) >= MAX_OBJECTS:
                    return [], f"more than {MAX_OBJECTS} destination groups in one plan"
                mixed = any(k == "fqdn" for k, _ in vals) and any(k != "fqdn" for k, _ in vals)
                base = f"{obj_name}-fqdn" if (mixed and typ == "DSTN_FQDN") else obj_name
                dst_groups[key] = {"name": names.make("dst", base, OBJECT_NAME_MAX), "source": obj_name, "type": typ,
                                   "addresses": part[:MAX_ADDRESSES]}
            out.append(dst_groups[key]["name"])
        return out, None

    order = []
    for c in containers:
        if c["kind"] == "shared":
            continue
        order.append((c, "pre-rulebase"))
        order.append((c, "rulebase"))
        order.append((c, "post-rulebase"))
    sh = next((c for c in containers if c["kind"] == "shared"), None)
    if sh is not None:
        order = [(sh, "pre-rulebase")] + order + [(sh, "post-rulebase")]
    total_rules = 0
    for c, base in order:
        ctx = _Ctx([objs[c["name"]]] + ([shared] if shared and c["kind"] != "shared" else []))
        for _b, r in _rules(c, base):
            total_rules += 1
            rname = _name(r) or f"rule {total_rules}"
            where = f"{c['kind']} {c['name']}" + ("" if base == "rulebase" else f" ({base})")
            reasons: List[str] = []
            notes: List[str] = []
            if _UNSAFE.search(rname):
                unmappable.append({"kind": "rule", "name": rname[:80], "where": where, "reasons": ["its name holds characters a Zscaler name cannot carry"]})
                continue
            frm, to = _members(r, "from"), _members(r, "to")
            for z in frm + to:
                if z != "any":
                    zones.setdefault(z, {"name": z, "rules": [], "globalprotect": is_gp(z)})["rules"].append(rname)
            action_raw = _text(r, "action").lower()
            disabled = _text(r, "disabled").lower() == "yes"
            if disabled and not include_disabled:
                unmappable.append({"kind": "rule", "name": rname, "where": where, "reasons": ["disabled on the firewall (tick 'include disabled rules' to carry it)"],
                                   "info": True})
                continue
            if action_raw not in ACTIONS:
                reasons.append(f"its action '{action_raw or 'none'}' has no Cloud Firewall equivalent")
            for neg in ("negate-source", "negate-destination"):
                if _text(r, neg).lower() == "yes":
                    reasons.append(f"it uses {neg}: a Cloud Firewall rule cannot negate a match, and dropping it would invert the rule")
            users = [u for u in _members(r, "source-user") if u != "any"]
            cats = [u for u in _members(r, "category") if u != "any"]
            hips = [u for u in _members(r, "source-hip") if u not in ("any",)]
            if cats:
                reasons.append(f"it matches URL categories ({', '.join(cats[:4])}): build a ZIA URL filtering rule instead")
            if _text(r, "schedule"):
                reasons.append(f"it has a schedule ({_text(r, 'schedule')[:40]}): create a ZIA time interval and add it by hand")
            if hips:
                reasons.append(f"it checks HIP profiles ({', '.join(hips[:3])}): use device posture (ZPA) or ZIA device trust by hand")
            if _child(r, "profile-setting") is not None:
                notes.append("its security profiles are not carried: ZIA applies Advanced Threat Protection and IPS separately")
            if _child(r, "log-setting") is not None:
                notes.append("its log forwarding is not carried: ZIA logs go to NSS or Cloud NSS")
            src_vals: List[Tuple[str, str, str]] = []   # (object, kind, value)
            dst_vals: List[Tuple[str, str, str]] = []
            src_names, dst_names = _members(r, "source"), _members(r, "destination")
            for side, mem, acc in (("source", src_names, src_vals), ("destination", dst_names, dst_vals)):
                for m in mem:
                    if m == "any":
                        continue
                    vals, why = _address_values(ctx, m, set())
                    if why:
                        reasons.append(f"its {side} {why}")
                        continue
                    acc.extend((m, k, v) for k, v in vals)
            app_names = [a for a in _members(r, "application") if a != "any"]
            svc_names = [s for s in _members(r, "service") if s not in ("any",)]
            svc_defs: List[Tuple[str, Dict[str, List[List[int]]]]] = []
            app_default = "application-default" in svc_names
            for s in [s for s in svc_names if s != "application-default"]:
                defs, why = _service_def(ctx, s, set())
                if why:
                    reasons.append(f"its {why}")
                else:
                    svc_defs.extend(defs)
            zia_apps, app_ids, why = _apps(ctx, app_names)
            gp_rule = action_raw == "allow" and any(is_gp(z) for z in frm) and bool(dst_vals) \
                and not any(m == "any" for m in dst_names) and all(_is_internal(k, v) for _o, k, v in dst_vals)
            if gp_rule:
                # GlobalProtect remote access to internal apps -> ZPA application segment.
                zreasons = [x for x in reasons if not x.startswith("its source")]
                tcp: List[List[int]] = []
                udp: List[List[int]] = []
                for _n, d in svc_defs:
                    tcp += d.get("dest_tcp", [])
                    udp += d.get("dest_udp", [])
                if app_default or not svc_names:
                    for a in app_ids:
                        t, u = APP_PORTS.get(a.lower(), ("", ""))
                        if not t and not u:
                            zreasons.append(f"application '{a}' with application-default: its ports are not in the mapping; name a service instead")
                        tcp += _ports(t) or []
                        udp += _ports(u) or []
                    if not app_ids and not svc_defs:
                        notes.append("any application on any port: the segment opens every TCP port (1-65535); narrow it before enabling")
                        tcp = [[1, 65535]]
                domains, dwhy = _zpa_domains([(k, v) for _o, k, v in dst_vals])
                if dwhy:
                    zreasons.append(dwhy)
                if not tcp and not udp and not zreasons:
                    zreasons.append("no TCP or UDP port could be derived for the ZPA segment")
                if len(domains) > 50:
                    zreasons.append("more than 50 destinations for one ZPA segment")
                if zreasons:
                    unmappable.append({"kind": "rule", "name": rname, "where": where, "target": "ZPA", "reasons": zreasons})
                    continue
                if len(segments) >= MAX_SEGMENTS:
                    unmappable.append({"kind": "rule", "name": rname, "where": where, "target": "ZPA",
                                       "reasons": [f"more than {MAX_SEGMENTS} ZPA segments in one plan"]})
                    continue
                sname = slug(rname, 40).lower()
                base_name, n = sname, 2
                while sname in seg_names:
                    sname = f"{base_name[:36]}-{n}"
                    n += 1
                seg_names.add(sname)
                if users:
                    notes.append(f"users and groups ({', '.join(users[:4])}) are not mapped: add them to the ZPA access rule as SAML or SCIM conditions")
                seg = {"name": sname, "source_rule": rname, "domains": domains, "tcp": _ranges(tcp), "udp": _ranges(udp),
                       "description": f"Migrated from PAN-OS rule {rname}"[:200]}
                segments.append(seg)
                mapped.append({"rule": rname, "where": where, "to": "ZPA application segment", "target": f"{prefix}-{sname}", "notes": notes})
                continue
            if users:
                reasons.append(f"it names users or groups ({', '.join(users[:4])}): ZIA scopes rules by its own users and groups; add them by hand")
            if why and app_names:
                reasons.append(f"its {why}")
            if reasons:
                unmappable.append({"kind": "rule", "name": rname, "where": where, "target": "ZIA", "reasons": reasons})
                continue
            if len(rules) >= MAX_RULES:
                unmappable.append({"kind": "rule", "name": rname, "where": where, "target": "ZIA", "reasons": [f"more than {MAX_RULES} rules in one plan"]})
                continue
            rule = {"name": names.make("rule", rname, RULE_NAME_MAX), "source_rule": rname, "action": ACTIONS[action_raw],
                    "description": _UNSAFE.sub(" ", f"Migrated from PAN-OS rule {rname}. {_text(r, 'description')}".strip())[:MAX_TEXT],
                    "src_ip_groups": [], "dest_ip_groups": [], "src_ips": [], "dest_addresses": [], "nw_services": [],
                    "nw_applications": zia_apps, "zones": {"from": frm, "to": to}}
            failed = None
            for side, mem, acc in (("src", src_names, src_vals), ("dst", dst_names, dst_vals)):
                for m in mem:
                    if m == "any":
                        continue
                    vals = [(k, v) for o, k, v in acc if o == m]
                    if ctx.find("address", m) is None and ctx.find("address-group", m) is None:
                        rule["src_ips" if side == "src" else "dest_addresses"].extend(v for _k, v in vals)
                        continue
                    gnames, gwhy = group_for(side, m, vals)
                    if gwhy:
                        failed = gwhy
                        break
                    rule["src_ip_groups" if side == "src" else "dest_ip_groups"].extend(g for g in gnames if g not in rule["src_ip_groups" if side == "src" else "dest_ip_groups"])
                if failed:
                    break
            if not failed:
                for sn, d in svc_defs:
                    if sn not in services:
                        if len(services) >= MAX_OBJECTS:
                            failed = f"more than {MAX_OBJECTS} network services in one plan"
                            break
                        services[sn] = {"name": names.make("svc", sn, OBJECT_NAME_MAX), "source": sn,
                                        **{k: _ranges(v) for k, v in d.items()}}
                    if services[sn]["name"] not in rule["nw_services"]:
                        rule["nw_services"].append(services[sn]["name"])
            if failed:
                unmappable.append({"kind": "rule", "name": rname, "where": where, "target": "ZIA", "reasons": [failed]})
                continue
            if not any(rule[k] for k in ("src_ip_groups", "dest_ip_groups", "src_ips", "dest_addresses", "nw_services", "nw_applications")):
                # A catch-all: ZIA's own Default Firewall Filtering Rule plays this part.
                unmappable.append({"kind": "rule", "name": rname, "where": where, "target": "ZIA", "info": True,
                                   "reasons": [f"it matches all traffic ({action_raw}): ZIA's Default Firewall Filtering Rule plays this part; "
                                               "set that rule's action instead of adding a second catch-all"]})
                continue
            if frm or to:
                zl = [z for z in frm + to if z != "any"]
                if zl:
                    notes.append(f"zones {', '.join(dict.fromkeys(zl))} are not carried: Cloud Firewall applies to every location unless you scope it")
            rules.append(rule)
            mapped.append({"rule": rname, "where": where, "to": "ZIA Cloud Firewall rule", "target": rule["name"], "action": rule["action"],
                           "notes": notes})

    # Other parts of the configuration that are listed, not migrated.
    for c in containers:
        for b in ("rulebase", "pre-rulebase", "post-rulebase"):
            for kind, why in (("nat", "NAT rules: Zscaler applies its own source NAT; destination NAT to an internal server is ZPA or a ZIA "
                                      "location's port forwarding, set by hand"),
                              ("decryption", "decryption rules: build ZIA SSL inspection rules (Bulk changes, ZIA security baseline)"),
                              ("pbf", "policy-based forwarding rules: ZIA forwarding control rules, set by hand"),
                              ("qos", "QoS rules: ZIA bandwidth control, set by hand")):
                n = len(_entries(c["el"], b, kind, "rules"))
                if n:
                    unmappable.append({"kind": "config", "name": f"{n} {kind} rule{'s' if n != 1 else ''}", "where": f"{c['kind']} {c['name']} ({b})",
                                       "reasons": [why], "info": True})
        gp = _child(c["el"], "global-protect")
        if gp is not None:
            portals = len(_entries(gp, "global-protect-portal"))
            gws = len(_entries(gp, "global-protect-gateway"))
            unmappable.append({"kind": "config", "name": f"GlobalProtect: {portals} portal(s), {gws} gateway(s)", "where": f"{c['kind']} {c['name']}",
                               "reasons": ["portal and gateway settings correspond to Client Connector app profiles and forwarding profiles: "
                                           "set them up in Client Connector (the rules that let GlobalProtect users reach internal apps are "
                                           "mapped to ZPA above)"], "info": True})

    zone_rows = [dict(z, rules=sorted(set(z["rules"]))[:50],
                      note=("GlobalProtect zone: its allow rules to internal destinations are mapped to ZPA" if z["globalprotect"]
                            else "Cloud Firewall has no zones; scope the rule by location (or a source IP group) by hand")) for z in zones.values()]
    seg_csv = ""
    if segments:
        lines = ["name,domains,tcp_ports,udp_ports,description"]
        for s in segments:
            lines.append(",".join(_csv_cell(x) for x in (s["name"], ";".join(s["domains"]), ";".join(s["tcp"]), ";".join(s["udp"]), s["description"])))
        seg_csv = "\n".join(lines) + "\n"
    zia_spec = {"type": OP_TYPE, "prefix": prefix, "enable": False, "source_sha256": sha,
                "ip_source_groups": [dict(v) for v in src_groups.values()],
                "ip_destination_groups": [dict(v) for v in dst_groups.values()],
                "network_services": [dict(v) for v in services.values()],
                "rules": [{k: v for k, v in r.items() if k != "zones"} for r in rules]}
    real = [u for u in unmappable if not u.get("info")]
    return {"format": FORMAT, "format_version": FORMAT_VERSION, "source_file": str(source_name)[:200], "source_sha256": sha,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "prefix": prefix,
            "gp_zones": gp_list or "default (zone names with globalprotect, gp, vpn or remote-access)",
            "counts": {"security_rules": total_rules, "to_zia": len(rules), "to_zpa": len(segments), "unmappable": len(real),
                       "listed_only": len(unmappable) - len(real), "ip_source_groups": len(src_groups),
                       "ip_destination_groups": len(dst_groups), "network_services": len(services), "zones": len(zone_rows)},
            "zia": zia_spec if rules else None,
            "zpa": {"segments": segments, "segments_csv": seg_csv,
                    "segments_spec": {"type": "zpa_app_segments", "prefix": prefix, "enable": False, "csv": seg_csv},
                    "policies_spec": {"type": "zpa_policies", "prefix": prefix, "access": True}} if segments else None,
            "mapped": mapped, "unmappable": unmappable, "zones": zone_rows, "crossref": CROSSREF,
            "next_steps": ["Open Bulk changes (Build new: Firewall import from Palo Alto Networks), read the tenant and preview: the "
                           "preview checks every object against the tenant (names in use, network applications it has).",
                           "Apply only after the preview: write mode, a writer, the assessor's name and the typed confirmation are "
                           "needed; every rule arrives DISABLED and Undo deletes what the import created.",
                           "For ZPA, build the App Connector group, then ZPA application segments with the segments CSV, then ZPA "
                           "policy rules (access), each previewed and applied the same way."]}


def _ranges(r: Sequence[Sequence[int]]) -> List[str]:
    return [f"{a}-{b}" if a != b else str(a) for a, b in sorted((int(x[0]), int(x[1])) for x in r)]


# ---------------------------------------------------------------------------
# Upload entry point (the page's endpoint)
# ---------------------------------------------------------------------------

def plan_upload(export_file: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The plan for an uploaded export ({name, content, encoding})."""
    import vendor_migrate
    data = vendor_migrate.decode_upload(export_file)
    o = options if isinstance(options, dict) else {}
    zones = o.get("gp_zones")
    if isinstance(zones, str):
        zones = [z for z in re.split(r"[,;\n]+", zones) if z.strip()]
    if zones is not None and not isinstance(zones, list):
        raise MigrationError("gp_zones must be a list of zone names.")
    name = str(export_file.get("name") or "config.xml")
    return build_plan(data, source_name=_UNSAFE.sub("", name)[:200], prefix=str(o.get("prefix") or "pan"), gp_zones=zones,
                      include_disabled=o.get("include_disabled") is True)
