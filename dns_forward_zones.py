"""DNS records for Client Connector hostnames: download-only text, never applied.

Why: with ZPA client-to-client access, a user reaches a colleague's laptop
by name (``lt-0042.corp.example.com``), and that name must be answered by
the client-to-client resolver (a Branch Connector or the resolver Zscaler
gives for it), not by the corporate DNS. The usual way is one conditional
forwarder per client hostname. This module turns the enrolled devices the
Client Connector fleet page already read (read-only, only when ZCC is in
scope on the Scope page) into that configuration:

* Unbound: one ``forward-zone`` per name to the resolver addresses, with
  ``local-zone: "<name>." transparent`` (so a parent domain kept as a local
  zone on the same server still lets the name through) and
  ``domain-insecure`` (the resolver's answers are not DNSSEC signed), each
  switchable;
* BIND: ``named.conf`` forward zones (``type forward; forward only;``) and a
  zone file fragment for ``$INCLUDE`` in the parent domain's zone that
  delegates each name (NS) to the resolvers (glue A/AAAA records);
* Windows DNS Server: a PowerShell script of
  ``Add-DnsServerConditionalForwarderZone`` lines (a name that already has a
  zone is skipped) and the same as ``dnscmd /ZoneAdd ... /Forwarder`` lines;
* a plain CSV of every device considered: the hostname as the tenant has
  it, the DNS label made from it, the full name, and what happened to it.

Nothing here contacts a DNS server, runs a command or writes a file: the
server hands the text to the operator's browser as a download.

Hostnames are tenant data (any user can rename a laptop), so every name in
the output is rebuilt from scratch as an RFC 1123 label: the first label of
the hostname, accents folded, lower case, anything other than a-z, 0-9 and
'-' replaced by '-', '-' runs collapsed, no leading or trailing '-', at most
63 characters. No quote, space, ';', newline or brace can reach a
configuration file. Two different hostnames that end as the same label are
a collision; the same hostname on several enrolments is a duplicate. Both
are reported and the name is written once (the records are identical: the
same name to the same resolvers).

Semantics and sources:
  * device fields: zscaler-sdk-python 1.11.3 zcc/models/devices.py
    (machineHostname, user, registrationState, last_seen_time), normalised by
    zcc_fleet.normalize_devices;
  * label syntax: RFC 1123 section 2.1 and RFC 1035 section 2.3.4 (63
    characters a label, 253 a name); labels with '--' in positions 3-4 are
    reserved by RFC 5891 (they never come out of the cleaning: '-' runs are
    collapsed);
  * Unbound: unbound.conf(5) forward-zone, local-zone transparent and
    domain-insecure;
  * BIND 9: named.conf zone type forward, forward only, forwarders; zone file
    $ORIGIN, $TTL, NS and glue records (RFC 1034 section 4.2.1).
  * Assumed (not in the SDK or Zscaler's API reference): that the resolver
    the operator names answers for every client hostname under the domain,
    and answers a delegated query (the zone file form); the forward zones are
    the documented form for client-to-client name resolution, the zone file
    is offered for servers that only serve zones.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import csv_safe

MAX_DEVICES = 200_000           # rows considered from a fleet read
MAX_RESOLVERS = 8
MAX_MAPPINGS = 50
MAX_REPORT_ROWS = 200           # collisions, duplicates and refusals listed (all are counted)
MAX_PREVIEW_ROWS = 200
MAX_INPUT_HOSTNAME = 255
DEFAULT_TTL = 300
NS_LABEL = "zcc-resolver"       # glue names in the zone file: zcc-resolver-1, zcc-resolver-2, ...
PLATFORMS = ("Windows", "macOS", "Linux", "iOS", "Android", "other")
DEFAULT_PLATFORMS = ("Windows", "macOS", "Linux")

_LABEL = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_APOSTROPHES = re.compile("['’‘`´]")
_NOT_LDH = re.compile(r"[^a-z0-9-]+")
_DASHES = re.compile(r"-{2,}")


class DnsInputError(ValueError):
    """An option the operator typed that cannot be used; the message says why in plain words."""


# ── Cleaning ─────────────────────────────────────────────────────────
def clean_label(hostname: Any) -> Tuple[str, str]:
    """A hostname as the tenant has it -> (label, note). label is '' when
    nothing usable is left; note says what was changed ('' when nothing
    but the case was)."""
    raw = str(hostname if hostname is not None else "")[:MAX_INPUT_HOSTNAME].strip()
    notes = []
    first = raw.split(".", 1)[0]
    if first != raw.rstrip("."):
        notes.append("domain part dropped")
    folded = unicodedata.normalize("NFKD", first)
    ascii_only = "".join(c for c in folded if not unicodedata.combining(c)).encode("ascii", "ignore").decode("ascii")
    if ascii_only != first and any(ord(c) > 127 for c in first):
        notes.append("accents or other letters removed")
    s = _APOSTROPHES.sub("", ascii_only.lower())
    s2 = _DASHES.sub("-", _NOT_LDH.sub("-", s)).strip("-")
    if s2 != s:
        notes.append("characters other than letters, digits and '-' replaced")
    if len(s2) > 63:
        s2 = s2[:63].rstrip("-")
        notes.append("shortened to 63 characters")
    if not s2 or not _LABEL.match(s2):
        return "", "no letters or digits left"
    return s2, "; ".join(notes)


def check_domain(domain: Any, what: str = "The domain") -> str:
    """A DNS domain the operator typed -> lower case, no trailing dot.
    DnsInputError (the value is not echoed beyond 60 characters)."""
    d = str(domain or "").strip().lower().rstrip(".")
    if not d:
        raise DnsInputError(f"{what} is required: the DNS domain the client names go under, for example corp.example.com.")
    if len(d) > 240:
        raise DnsInputError(f"{what} is longer than 240 characters, which leaves no room for the hostnames.")
    labels = d.split(".")
    if not all(_LABEL.match(lab) for lab in labels):
        raise DnsInputError(f"{what} '{d[:60]}' is not a DNS name: use letters, digits, '-' and dots, like corp.example.com.")
    return d


def check_resolvers(values: Any) -> List[str]:
    """The resolver addresses (IPv4 or IPv6, one to eight, no repeats).
    DnsInputError for anything that is not a usable unicast address."""
    if isinstance(values, str):
        values = re.split(r"[\s,;]+", values)
    out: List[str] = []
    for v in values or []:
        s = str(v or "").strip()
        if not s:
            continue
        try:
            ip = ipaddress.ip_address(s[:64])
        except ValueError:
            raise DnsInputError(f"'{s[:40]}' is not an IP address: give the resolver's IPv4 or IPv6 address, like 10.0.0.12.") from None
        if ip.is_unspecified or ip.is_multicast or (ip.version == 4 and ip == ipaddress.ip_address("255.255.255.255")):
            raise DnsInputError(f"{ip} cannot answer DNS queries: give the resolver's own address.")
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if str(ip) not in out:
            out.append(str(ip))
    if not out:
        raise DnsInputError("Give at least one resolver address: the client-to-client resolver the names are sent to, like 10.0.0.12.")
    if len(out) > MAX_RESOLVERS:
        raise DnsInputError(f"At most {MAX_RESOLVERS} resolver addresses.")
    return out


def parse_mappings(text: Any) -> List[Tuple[str, str]]:
    """'email-domain: dns-domain' lines (or '=' between them; '#' starts a
    comment) -> [(email domain, DNS domain)]. A device whose user's e-mail
    domain is listed also gets a name under the DNS domain."""
    out: List[Tuple[str, str]] = []
    for n, line in enumerate(str(text or "").splitlines()[:MAX_MAPPINGS * 4], 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"\A([^:=\s]+)\s*[:=]\s*([^:=\s]+)\Z", line)
        if not m:
            raise DnsInputError(f"Mapping line {n} is not 'e-mail domain: DNS domain', like subsidiary.com: subsidiary.corp.example.")
        pair = (check_domain(m.group(1).lstrip("@"), f"The e-mail domain on mapping line {n}"),
                check_domain(m.group(2), f"The DNS domain on mapping line {n}"))
        if pair not in out:
            out.append(pair)
        if len(out) > MAX_MAPPINGS:
            raise DnsInputError(f"At most {MAX_MAPPINGS} mappings.")
    return out


def _platform(p: Any) -> str:
    p = str(p or "")
    return p if p in PLATFORMS[:-1] else "other"


def _email_domain(user: Any) -> str:
    u = str(user or "").strip().lower()
    return u.rsplit("@", 1)[1].rstrip(".") if "@" in u else ""


# ── Building ─────────────────────────────────────────────────────────
def build(devices: Iterable[Dict[str, Any]], *, domain: Any, resolvers: Any, platforms: Optional[Iterable[str]] = None,
          registered_only: bool = True, seen_within_days: Optional[int] = None, mappings: Any = "",
          ttl: int = DEFAULT_TTL, unbound_local_zone: bool = True, unbound_insecure: bool = True,
          read_at: Optional[str] = None, truncated: bool = False, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The records and the four files from normalised fleet devices
    (zcc_fleet.normalize_devices rows: hostname, user, platform,
    registration, seconds_since_seen). Pure: no network, no file."""
    dom = check_domain(domain)
    res = check_resolvers(resolvers)
    maps = parse_mappings(mappings)
    plats = {p for p in (platforms if platforms is not None else DEFAULT_PLATFORMS) if p in PLATFORMS}
    if not plats:
        raise DnsInputError("Pick at least one platform.")
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        raise DnsInputError("The TTL is a whole number of seconds.") from None
    if not 30 <= ttl <= 86400:
        raise DnsInputError("The TTL is from 30 to 86400 seconds.")
    if seen_within_days not in (None, ""):
        try:
            seen_within_days = int(seen_within_days)
        except (TypeError, ValueError):
            raise DnsInputError("'Seen within' is a whole number of days.") from None
        if not 1 <= seen_within_days <= 3650:
            raise DnsInputError("'Seen within' is from 1 to 3650 days.")
    else:
        seen_within_days = None
    now = now or datetime.now(timezone.utc)
    ns_names = {f"{NS_LABEL}-{i}" for i in range(1, len(res) + 1)}

    counts = {"devices": 0, "filtered_platform": 0, "filtered_registration": 0, "filtered_seen": 0, "considered": 0,
              "records": 0, "renamed": 0, "duplicates": 0, "collisions": 0, "invalid": 0, "reserved": 0, "too_long": 0}
    rows: List[Dict[str, Any]] = []
    # per (domain, label): the first original hostname and every other one
    names: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for d in devices:
        counts["devices"] += 1
        if counts["devices"] > MAX_DEVICES:
            raise DnsInputError(f"More than {MAX_DEVICES} devices: too many to write as forward zones.")
        plat = _platform(d.get("platform"))
        if plat not in plats:
            counts["filtered_platform"] += 1
            continue
        if registered_only and d.get("registration") != "registered":
            counts["filtered_registration"] += 1
            continue
        if seen_within_days is not None:
            s = d.get("seconds_since_seen")
            if not isinstance(s, (int, float)) or s > seen_within_days * 86400:
                counts["filtered_seen"] += 1
                continue
        counts["considered"] += 1
        host = str(d.get("hostname") or "")[:MAX_INPUT_HOSTNAME]
        label, note = clean_label(host)
        doms = [dom] + [dns for em, dns in maps if _email_domain(d.get("user")) in (em,) and dns != dom]
        for target in doms:
            row = {"hostname": host, "label": label, "fqdn": "", "domain": target, "platform": plat, "status": "", "note": note}
            if not label:
                row["status"] = "invalid"
                counts["invalid"] += 1
            elif label in ns_names:
                row["status"], row["note"] = "reserved", f"'{label}' is the name the zone file gives the resolver"
                counts["reserved"] += 1
            elif len(label) + 1 + len(target) > 253:
                row["status"], row["note"] = "too long", "the full name would be longer than 253 characters"
                counts["too_long"] += 1
            else:
                fq = f"{label}.{target}"
                row["fqdn"] = fq
                key = (target, label)
                seen = names.get(key)
                if seen is None:
                    names[key] = {"first": host, "others": set(), "dupes": 0}
                    row["status"] = "renamed" if note or label != host.strip().lower() else "ok"
                    if row["status"] == "renamed":
                        counts["renamed"] += 1
                    counts["records"] += 1
                elif host.strip().lower() == seen["first"].strip().lower():
                    seen["dupes"] += 1
                    row["status"], row["note"] = "duplicate", "the same hostname on another enrolment: written once"
                    counts["duplicates"] += 1
                else:
                    if not seen["others"]:
                        counts["collisions"] += 1
                    seen["others"].add(host)
                    row["status"], row["note"] = "collision", f"'{seen['first'][:60]}' already became {fq}: written once"
            rows.append(row)

    zones = sorted(((t, lab) for (t, lab) in names), key=lambda x: (x[0] != dom, x[0], x[1]))
    collisions = [{"fqdn": f"{lab}.{t}", "hostnames": [v["first"]] + sorted(v["others"])}
                  for (t, lab), v in sorted(names.items()) if v["others"]]
    duplicates = [{"fqdn": f"{lab}.{t}", "hostname": v["first"], "extra_enrolments": v["dupes"]}
                  for (t, lab), v in sorted(names.items()) if v["dupes"]]
    refused = [r for r in rows if r["status"] in ("invalid", "reserved", "too long")]
    meta = {"generated_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "read_at": read_at, "domain": dom,
            "resolvers": res, "ttl": ttl, "mappings": [{"email_domain": a, "dns_domain": b} for a, b in maps]}
    files = {
        "unbound": render_unbound(zones, res, meta, local_zone=unbound_local_zone, insecure=unbound_insecure),
        "bind_forward": render_bind_forward(zones, res, meta),
        "bind_zone": render_bind_zone(zones, res, meta),
        "windows_ps": render_windows_powershell(zones, res, meta),
        "windows_dnscmd": render_windows_dnscmd(zones, res, meta),
        "csv": render_csv(rows),
    }
    warnings = []
    if truncated:
        warnings.append("The fleet read kept only part of the device list, so some devices have no record: the files are incomplete.")
    if not zones:
        warnings.append("No device gave a usable name, so the files hold no records.")
    if counts["collisions"]:
        warnings.append(f"{counts['collisions']} collision(s): a name that more than one hostname gives. Check them before you use the files.")
    return {
        "meta": meta, "counts": counts, "truncated": bool(truncated),
        "options": {"platforms": sorted(plats), "registered_only": bool(registered_only), "seen_within_days": seen_within_days,
                    "unbound_local_zone": bool(unbound_local_zone), "unbound_insecure": bool(unbound_insecure)},
        "collisions": collisions[:MAX_REPORT_ROWS], "duplicates": duplicates[:MAX_REPORT_ROWS],
        "refused": [{k: r[k] for k in ("hostname", "domain", "status", "note")} for r in refused[:MAX_REPORT_ROWS]],
        "preview": rows[:MAX_PREVIEW_ROWS], "rows_total": len(rows),
        "warnings": warnings, "files": files,
    }


# ── Rendering (every name is an LDH label or a checked domain) ───────
def _header(meta: Dict[str, Any], zones: List[Tuple[str, str]], c: str) -> List[str]:
    doms = sorted({t for t, _ in zones}) or [meta["domain"]]
    return [
        f"{c} Generated by Zscaler Made Easy on {meta['generated_at']} from the Client Connector device list"
        + (f" read {meta['read_at']}" if meta.get("read_at") else "") + ".",
        f"{c} {len(zones)} client name(s) under {', '.join(doms)}, sent to {', '.join(meta['resolvers'])}.",
        f"{c} Review it, check it with your DNS server's own checker, then load it yourself: the app applies nothing.",
    ]


def render_unbound(zones: List[Tuple[str, str]], resolvers: List[str], meta: Dict[str, Any], *,
                   local_zone: bool = True, insecure: bool = True) -> str:
    out = _header(meta, zones, "#")
    out.append('# Include it at the end of unbound.conf (include: "/etc/unbound/zcc_client_zones.conf"), then unbound-checkconf.')
    if zones and (local_zone or insecure):
        out += ["", "server:"]
        for t, lab in zones:
            if local_zone:
                out.append(f'    local-zone: "{lab}.{t}." transparent')
            if insecure:
                out.append(f'    domain-insecure: "{lab}.{t}."')
    for t, lab in zones:
        out += ["", "forward-zone:", f'    name: "{lab}.{t}."'] + [f"    forward-addr: {ip}" for ip in resolvers]
    return "\n".join(out) + "\n"


def render_bind_forward(zones: List[Tuple[str, str]], resolvers: List[str], meta: Dict[str, Any]) -> str:
    out = _header(meta, zones, "//")
    out.append("// Include it from named.conf (include \"/etc/bind/zcc_client_zones.conf\";), then named-checkconf.")
    doms = sorted({t for t, _ in zones}) or [meta["domain"]]
    out.append("// With DNSSEC validation on, the resolver's answers are not signed: add the domain(s) to options { validate-except { "
               + " ".join(f'"{d}";' for d in doms) + " }; } if a parent zone is signed.")
    fwd = " ".join(f"{ip};" for ip in resolvers)
    for t, lab in zones:
        out += ["", f'zone "{lab}.{t}" {{', "    type forward;", "    forward only;", f"    forwarders {{ {fwd} }};", "};"]
    return "\n".join(out) + "\n"


def render_bind_zone(zones: List[Tuple[str, str]], resolvers: List[str], meta: Dict[str, Any]) -> str:
    out = _header(meta, zones, ";")
    out.append("; Delegations: put each $ORIGIN section in the zone for that domain ($INCLUDE), then named-checkzone.")
    out.append("; Each client name is delegated (NS) to the resolver(s), named " + NS_LABEL + "-N with glue records.")
    ttl = int(meta.get("ttl") or DEFAULT_TTL)
    by_dom: Dict[str, List[str]] = {}
    for t, lab in zones:
        by_dom.setdefault(t, []).append(lab)
    width = max([len(lab) for _, lab in zones] + [len(NS_LABEL) + 3])
    for t in sorted(by_dom, key=lambda d: (d != meta["domain"], d)):
        out += ["", f"$ORIGIN {t}.", f"$TTL {ttl}"]
        for i, ip in enumerate(resolvers, 1):
            rr = "AAAA" if ":" in ip else "A"
            out.append(f"{(NS_LABEL + '-' + str(i)).ljust(width)}  IN  {rr.ljust(4)}  {ip}")
        for lab in by_dom[t]:
            for i in range(1, len(resolvers) + 1):
                out.append(f"{lab.ljust(width)}  IN  NS    {NS_LABEL}-{i}")
    return "\n".join(out) + "\n"


# Windows DNS Server. Every name and address is checked again right here
# (defence in depth): a name is LDH labels joined by '.', an address is what
# ipaddress prints. Nothing else (no tenant text) reaches a command line, so
# no quote, ';', '`', '$', '|', '&', space or newline can start a second
# command in PowerShell or cmd.exe.
_WIN_NAME = re.compile(r"\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _win_safe(zones: List[Tuple[str, str]], resolvers: List[str]) -> Tuple[List[str], List[str]]:
    names = [f"{lab}.{t}" for t, lab in zones]
    for n in names:
        if len(n) > 253 or not _WIN_NAME.match(n):
            raise DnsInputError("A name could not be written safely for Windows DNS.")
    addrs = []
    for ip in resolvers:
        addrs.append(str(ipaddress.ip_address(ip)))   # ValueError for anything that is not an address
    return names, addrs


def render_windows_powershell(zones: List[Tuple[str, str]], resolvers: List[str], meta: Dict[str, Any]) -> str:
    """PowerShell for a Windows DNS Server (DnsServer module): one
    Add-DnsServerConditionalForwarderZone a name (-Name, -MasterServers),
    skipped when a zone of that name exists already (Get-DnsServerZone).
    File-backed zones; add -ReplicationScope Forest yourself for
    AD-integrated ones. Source: Microsoft's DnsServer module reference
    (Add-DnsServerConditionalForwarderZone, Get-DnsServerZone)."""
    names, addrs = _win_safe(zones, resolvers)
    out = _header(meta, zones, "#")
    out += ["# Run it in an elevated PowerShell on the DNS server (DnsServer module), after reading it. It changes nothing that exists:",
            "# a name that already has a zone is skipped and listed. Check with Get-DnsServerZone afterwards.",
            "$ErrorActionPreference = 'Stop'",
            "$servers = @(" + ", ".join(f"'{a}'" for a in addrs) + ")"]
    for n in names:
        out.append(f"if (Get-DnsServerZone -Name '{n}' -ErrorAction SilentlyContinue) {{ Write-Output 'exists, skipped: {n}' }} "
                   f"else {{ Add-DnsServerConditionalForwarderZone -Name '{n}' -MasterServers $servers }}")
    return "\r\n".join(out) + "\r\n"


def render_windows_dnscmd(zones: List[Tuple[str, str]], resolvers: List[str], meta: Dict[str, Any]) -> str:
    """dnscmd lines (Windows Server's command-line DNS tool): one
    `dnscmd /ZoneAdd <name> /Forwarder <addresses>` a name. Source:
    Microsoft's dnscmd reference (/zoneadd, /forwarder)."""
    names, addrs = _win_safe(zones, resolvers)
    out = ["REM " + ln[2:] for ln in _header(meta, zones, "#")]
    out += ["REM Run it in an elevated command prompt on the DNS server (or add /? to check the options of your Windows version).",
            "REM A name that already has a zone fails with an error and is left as it is."]
    fwd = " ".join(addrs)
    for n in names:
        out.append(f"dnscmd /ZoneAdd {n} /Forwarder {fwd}")
    return "\r\n".join(out) + "\r\n"


CSV_COLUMNS = ("hostname", "label", "fqdn", "domain", "platform", "status", "note")


def render_csv(rows: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv_safe.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([r.get(k, "") for k in CSV_COLUMNS])
    return buf.getvalue()


FILES = {
    "unbound": ("zcc_client_zones_unbound.conf", "text/plain; charset=utf-8"),
    "bind_forward": ("zcc_client_zones_named.conf", "text/plain; charset=utf-8"),
    "bind_zone": ("zcc_client_zones.db", "text/plain; charset=utf-8"),
    "windows_ps": ("zcc_client_zones_windows.ps1", "text/plain; charset=utf-8"),
    "windows_dnscmd": ("zcc_client_zones_dnscmd.cmd", "text/plain; charset=utf-8"),
    "csv": ("zcc_client_names.csv", "text/csv; charset=utf-8"),
}
