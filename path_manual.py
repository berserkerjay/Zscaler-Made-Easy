"""Manual bypass and PAC what-if for the Path analyzer.

The Path analyzer reads the tenant's Client Connector app profiles and
the PAC files ZIA hosts (data_flow.read_client_connector). Two questions
that read cannot answer:

* a PAC file that ZIA does not host (on a web server of the customer's,
  named by a forwarding profile or set on the device by GPO or MDM): its
  text is never fetched, so it cannot be evaluated;
* "what if": what a VPN gateway, an IP inclusion or exclusion, or a domain
  inclusion or exclusion that is not configured yet would do.

So the request may carry `whatif_bypass` (parse), all optional:

  pac_text       the PAC source, pasted (at most pac_eval.MAX_SOURCE
                 characters). Interpreted by pac_eval, never run.
  ipv4_include   Z-Tunnel 2.0 destination inclusions (addresses, CIDR
  ipv4_exclude   blocks, ranges; IPv6 too): the app profile's
                 packetTunnelIncludeList / packetTunnelExcludeList
  dest_include   Z-Tunnel 2.0 domain inclusions and exclusions: the app
  dest_exclude   profile's packetTunnelDnsIncludeList / ...DnsExcludeList
  vpn_gateways   VPN gateway bypass entries (host names or addresses,
                 optionally with a port): the app profile's vpnGateways
  mode           "alone" (default) evaluates these inputs on their own,
                 as a "Manual inputs" profile next to the tenant's answer;
                 "merge" adds them to every app profile that was read (and
                 the pasted PAC replaces the linked one) and traces the
                 whole path again, the answer labelled hypothetical.

The field names are the SDK's (zscaler-sdk-python 1.11.3,
zscaler/zcc/models/webpolicy.py: packet_tunnel_include_list,
packet_tunnel_exclude_list, packet_tunnel_dns_include_list,
packet_tunnel_dns_exclude_list, PolicyExtension.vpn_gateways). The checks
are the ones the tenant's own lists go through (zcc_bypass.vpn_check,
zcc_bypass.tunnel2_lists, pac_eval.path_hop), so a manual entry and a
read one are judged the same way, with the same assumptions
(zcc_bypass.ASSUMED).

Everything here is untrusted input: sizes are capped, each entry is
checked for its kind and refused in words when it is not, control
characters are refused, nothing is executed, fetched or resolved, and the
page escapes every value it shows. Nothing is written to the tenant and
nothing typed here is stored: it lives only in the one analysis.
"""
from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

import pac_eval
import zcc_bypass
import zia_path_modules as _zpm

MAX_LIST = 500            # entries per list
MAX_ENTRY = 253           # characters per entry (a DNS name's limit)
MAX_PAC = pac_eval.MAX_SOURCE
PAC_URL = "manual://pasted-pac"
PAC_NAME = "Pasted PAC (what-if)"
LABEL = "Manual inputs (what-if)"
MODES = ("alone", "merge")
LISTS = {
    # field: (label, kind)
    "vpn_gateways": ("VPN gateways", "gateway"),
    "ipv4_include": ("IP inclusions (Z-Tunnel 2.0)", "ip"),
    "ipv4_exclude": ("IP exclusions (Z-Tunnel 2.0)", "ip"),
    "dest_include": ("Domain inclusions (Z-Tunnel 2.0)", "domain"),
    "dest_exclude": ("Domain exclusions (Z-Tunnel 2.0)", "domain"),
}
_HOST = re.compile(r"^(\*\.|\.)?[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))*\.?$")
_WILD = re.compile(r"^[A-Za-z0-9_*.-]{1,253}$")
ASSUMED = [
    "Manual inputs are evaluated as a Client Connector app profile forwarding with Z-Tunnel 2.0: VPN gateways first, then the "
    "Z-Tunnel 2.0 address lists, then the pasted PAC for web traffic. A domain inclusion or exclusion decides where the DNS lookup "
    "is resolved, not whether the traffic is tunnelled (as for the tenant's own lists).",
]


class ManualError(ValueError):
    """Manual inputs that cannot be used (said in words)."""


def _shown(v: str) -> str:
    """An entry as a refusal may quote it: control characters escaped, clipped."""
    return v.encode("unicode_escape").decode("ascii")[:60]


def _entries(field: str, v: Any) -> List[str]:
    label, kind = LISTS[field]
    if v is None or v == "":
        return []
    if isinstance(v, str):
        if len(v) > MAX_LIST * (MAX_ENTRY + 2):
            raise ManualError(f"{label}: the list is too long; give at most {MAX_LIST} entries.")
        items: List[Any] = [x for x in re.split(r"[\r\n,;\t ]+", v)]
    elif isinstance(v, list):
        if len(v) > MAX_LIST:
            raise ManualError(f"{label}: {len(v)} entries; give at most {MAX_LIST}.")
        items = v
    else:
        raise ManualError(f"{label}: give a list of entries, one per line.")
    out: List[str] = []
    for x in items:
        if not isinstance(x, str):
            raise ManualError(f"{label}: every entry is text.")
        s = x.strip()
        if not s:
            continue
        if any(ord(c) < 32 or ord(c) == 127 for c in s):
            raise ManualError(f"{label}: “{_shown(s)}” holds control characters.")
        if len(s) > MAX_ENTRY:
            raise ManualError(f"{label}: an entry is longer than {MAX_ENTRY} characters.")
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1].strip()
        if kind == "ip" and not _zpm._is_ip_entry(s):
            raise ManualError(f"{label}: “{_shown(s)}” is not an address, a CIDR block or a range.")
        if kind == "domain" and not (_HOST.match(s) or (s.count("*") and _WILD.match(s))):
            raise ManualError(f"{label}: “{_shown(s)}” is not a host name or a domain (such as .example.com or *.example.com).")
        if kind == "gateway":
            bare = zcc_bypass._addr_entry(s)
            if bare.count(":") == 1 and bare.rsplit(":", 1)[1].isdigit():
                bare = bare.rsplit(":", 1)[0]
            if not (_zpm._is_ip_entry(bare) or _HOST.match(bare)):
                raise ManualError(f"{label}: “{_shown(s)}” is not a host name or an address (a port after a colon is allowed).")
        if s not in out:
            out.append(s)
        if len(out) > MAX_LIST:
            raise ManualError(f"{label}: give at most {MAX_LIST} entries.")
    return out


def parse(raw: Any) -> Optional[Dict[str, Any]]:
    """The manual inputs checked, or None when nothing was given.
    ManualError (a sentence) for anything that cannot be used."""
    if raw in (None, {}, ""):
        return None
    if not isinstance(raw, dict):
        raise ManualError("Manual inputs are a set of lists and a PAC; nothing else is accepted.")
    unknown = sorted(str(k)[:40] for k in raw if k not in LISTS and k not in ("pac_text", "mode"))
    if unknown:
        raise ManualError("Unknown manual input: " + ", ".join(_shown(k) for k in unknown[:3]) + ".")
    mode = raw.get("mode") or "alone"
    if mode not in MODES:
        raise ManualError("Manual inputs are evaluated on their own (alone) or added to the tenant's profiles (merge).")
    pac = raw.get("pac_text")
    if pac is None:
        pac = ""
    if not isinstance(pac, str):
        raise ManualError("The pasted PAC is text.")
    if len(pac) > MAX_PAC:
        raise ManualError(f"The pasted PAC is longer than {MAX_PAC // 1024} KB; paste at most that much.")
    pac = pac.strip()
    if "\x00" in pac:
        raise ManualError("The pasted PAC holds a NUL character; paste the text of the file.")
    if pac and "FindProxyForURL" not in pac:
        raise ManualError("The pasted PAC has no FindProxyForURL function, so no browser would use it.")
    out: Dict[str, Any] = {"mode": mode, "pac_text": pac}
    for f in LISTS:
        out[f] = _entries(f, raw.get(f))
    if not pac and not any(out[f] for f in LISTS):
        return None
    return out


def counts(m: Dict[str, Any]) -> Dict[str, Any]:
    """What was given, as counts (the text itself is not echoed back)."""
    return dict({f: len(m.get(f) or []) for f in LISTS}, pac_chars=len(m.get("pac_text") or ""), mode=m.get("mode") or "alone")


def _profile(m: Dict[str, Any]) -> Dict[str, Any]:
    """The inputs in the shape data_flow gives a read app profile."""
    return {"id": "manual", "name": LABEL,
            "tunnel": {"exclude": list(m["ipv4_exclude"]), "include": list(m["ipv4_include"])},
            "lists": {"vpn_gateways": list(m["vpn_gateways"]), "dns_exclude": list(m["dest_exclude"]), "dns_include": list(m["dest_include"]),
                      "ip_app_ids": {}, "proxy_port_t1": False}}


def pac_file(m: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": "manual", "name": PAC_NAME, "url": PAC_URL, "source": m["pac_text"], "has_content": True,
            "direct_hosts": pac_eval.direct_hosts(m["pac_text"]), "hypothetical": True}


def evaluate(m: Dict[str, Any], dest: Dict[str, Any], traffic: Dict[str, Any], pac_url: str) -> Dict[str, Any]:
    """The inputs on their own, in order: VPN gateways, the Z-Tunnel 2.0
    lists, then the pasted PAC (web traffic only). Returns {hypothetical,
    mode, label, outcome (bypassed | forwarded | unknown | conditional),
    headline, decided_by, modules ([Client Connector step, PAC step] in
    the shared hop shape), notes, assumptions, given (counts)}."""
    host = str(dest.get("host") or "")
    try:
        ip: Any = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    prof = _profile(m)
    crit: List[Dict[str, str]] = []
    notes: List[str] = []
    decided: Optional[Dict[str, Any]] = None
    state = "forwarded"
    vpn_c, hit_vpn = zcc_bypass.vpn_check(prof["lists"], host if ip is None else "", ip)
    crit.append(vpn_c)
    if hit_vpn:
        decided, state = {"list": "VPN gateway bypass", "entry": hit_vpn}, "bypassed"
    has_t2 = any(m[f] for f in ("ipv4_include", "ipv4_exclude", "dest_include", "dest_exclude"))
    if has_t2:
        t2 = zcc_bypass.tunnel2_lists(prof, host, ip)
        crit += t2["criteria"]
        notes += t2["notes"]
        if decided is None and t2["state"] == "out":
            decided = {"list": "Z-Tunnel 2.0 destination " + ("exclusions" if "excludes" in t2["why"] else "inclusions"), "entry": str(t2["entry"])}
            state = "bypassed"
        elif decided is None and t2["state"] == "unknown":
            state = "unknown"
            notes.append(t2["why"][:1].upper() + t2["why"][1:] + ".")
    zdetail = (f"Manual inputs send {host} direct ({decided['list']}: {decided['entry']}): it would never reach Zscaler." if decided else
               f"Whether the manual lists send {host} direct is unknown: it depends on how the host resolves." if state == "unknown" else
               f"None of the manual lists sends {host} direct: it is forwarded to Zscaler.")
    modules = [zcc_bypass.module("bypassed" if state == "bypassed" else state, decided, crit, notes, zdetail)]
    modules[0]["module"] = "Client Connector (manual inputs)"
    pac_block = None
    if m["pac_text"]:
        if not traffic.get("web", True):
            pac_block = {"status": "na", "detail": f"A PAC file decides web traffic only; {traffic.get('label') or 'this traffic'} is not sent by it."}
            notes.append(pac_block["detail"])
        else:
            pev = pac_eval.path_hop([pac_file(m)], host, pac_url)
            if pev is None:
                pac_block = {"status": "unknown", "detail": "The pasted PAC could not be evaluated for this destination (it needs a host name or address)."}
            else:
                hop = dict(pev["module_hop"], module="PAC file (pasted)")
                modules.append(hop)
                pac_block = {"status": "unknown" if pev["status"] == "error" else pev["status"], "detail": pev["detail"],
                             "outcomes": pev["evaluation"].get("outcomes") or [], "depends_on": pev["evaluation"].get("depends_on") or []}
                if state == "forwarded":
                    if pev["status"] == "bypass":
                        state = "bypassed"
                        decided = {"list": "Pasted PAC", "entry": (pev["evaluation"].get("outcomes") or [{}])[0].get("result") or "DIRECT"}
                    elif pev["status"] in ("error", "unknown"):
                        state = "unknown"
                    elif pev["status"] == "warn":
                        state = "conditional"
    headline = {"bypassed": f"What-if: {host} would never reach Zscaler ({decided['list']}: {decided['entry']})." if decided else "",
                "forwarded": f"What-if: the manual inputs forward {host} to Zscaler.",
                "unknown": f"What-if: whether the manual inputs send {host} direct is unknown.",
                "conditional": f"What-if: the pasted PAC sends {host} to Zscaler on some answers only."}[state]
    return {"hypothetical": True, "mode": m.get("mode") or "alone", "label": LABEL, "outcome": state, "headline": headline,
            "decided_by": dict(decided) if decided else None, "modules": modules, "pac": pac_block, "notes": notes[:12],
            "assumptions": list(ASSUMED), "given": counts(m),
            "note": "Hypothetical: these entries are not in the tenant. Nothing was written and nothing you typed is kept."}


def apply(zcc: Dict[str, Any], m: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """("merge" mode) the Client Connector read with the manual inputs
    added to every app profile, and the pasted PAC linked in place of any
    other: (zcc for the trace, what changed). The read itself is not
    changed (a copy is returned), so it is never kept with the inputs."""
    z = copy.deepcopy(zcc or {})
    profs = [p for p in z.get("app_profiles") or [] if isinstance(p, dict)]
    for p in profs:
        b = p.setdefault("bypass", {"domains": [], "apps": [], "processes": [], "ips": [], "vpn_gateways": []})
        lists = p.setdefault("lists", zcc_bypass.profile_lists({}))
        for g in m["vpn_gateways"]:
            if g not in (b.get("vpn_gateways") or []):
                b.setdefault("vpn_gateways", []).append(g)
            if g not in (lists.get("vpn_gateways") or []):
                lists.setdefault("vpn_gateways", []).append(g)
        tl = p.setdefault("tunnel", {"exclude": [], "include": []})
        tl["exclude"] = list(tl.get("exclude") or []) + [e for e in m["ipv4_exclude"] if e not in (tl.get("exclude") or [])]
        tl["include"] = list(tl.get("include") or []) + [e for e in m["ipv4_include"] if e not in (tl.get("include") or [])]
        lists["dns_exclude"] = list(lists.get("dns_exclude") or []) + [e for e in m["dest_exclude"] if e not in (lists.get("dns_exclude") or [])]
        lists["dns_include"] = list(lists.get("dns_include") or []) + [e for e in m["dest_include"] if e not in (lists.get("dns_include") or [])]
        if m["pac_text"]:
            p["pac_url"] = PAC_URL
    if m["pac_text"]:
        z["pac_files"] = [pac_file(m)] + [f for f in z.get("pac_files") or [] if isinstance(f, dict)]
        for f in z.get("forwarding_profiles") or []:
            if isinstance(f, dict):
                f["pac_url"] = PAC_URL
                for act in (f.get("actions") or {}).values():
                    if isinstance(act, dict):
                        act["pac_url"] = PAC_URL
    return z, {"profiles": len(profs), "given": counts(m)}
