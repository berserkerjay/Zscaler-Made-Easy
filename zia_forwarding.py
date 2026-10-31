"""ZIA forwarding and traffic path: the pure analysis behind the FWD.*
assessment checks (zscaler_full_checks) and the Path analyzer's
"Forwarding control" step (zia_path_modules).

What it looks at, all read-only:

  forwarding rules      /forwardingRules (zia.forwarding_control.list_rules):
                        DIRECT rules that send traffic around ZIA, proxy
                        chaining with no gateway or no fallback proxy, ZPA
                        and dedicated-IP forwarding;
  proxy gateways        /proxyGateways (zia.proxies.list_proxy_gateways):
                        primaryProxy, secondaryProxy, failClosed;
  ZPA gateways          /zpaGateways (zia.zpa_gateway.list_gateways):
                        zpaServerGroup, zpaAppSegments;
  data centres          /datacenters and /dcExclusions
                        (zia.traffic_datacenters.list_datacenters,
                        list_dc_exclusions): dcid, dcName, startTime,
                        endTime, expired;
  GRE tunnels           /greTunnels and /vips (zia.gre_tunnel.list_gre_tunnels,
                        list_vips): primaryDestVip and secondaryDestVip
                        (virtualIp, datacenter) and the public VIP list
                        (dataCenter, greIps) to place a VIP the tunnel
                        does not name a data centre for;
  IPv6                  /ipv6config and /ipv6config/nat64prefix
                        (zia.ipv6_config.get_ipv6_config, list_nat64_prefix):
                        ipV6Enabled, natPrefixes; the locations' ipv6Enabled;
  dedicated IP gateways /dedicatedIPGateways/lite
                        (zia.dedicated_ip_gateways.list_dedicated_ip_gw_lite):
                        primaryDataCenter, secondaryDataCenter;
  NAT control           /dnatRules (zia.nat_control_policy.list_rules):
                        redirectIp, redirectFqdn, redirectPort and the
                        destination criteria;
  Virtual Service Edges /virtualZenClusters, /virtualZenNodes
                        (zia.vzen_clusters.list_vzen_clusters,
                        zia.vzen_nodes.list_zen_nodes): virtualZenNodes,
                        status, inProduction, clusterName;
  DNS gateways          /dnsGateways (zia.dns_gatways.list_dns_gateways, the
                        SDK's own spelling): primaryIpOrFqdn,
                        secondaryIpOrFqdn, failureBehavior.

Every path, service, method and field above is in zscaler-sdk-python
1.11.3. Assumed (not in the SDK): the forwarding rule `type` values that
mark a Cloud or Branch Connector rule (anything other than FORWARDING,
for example EC_RDR, EC_DNS, EC_SELF), the DNS gateway failure behaviour
other than FAIL_RET_ERR (the SDK's only example), and that the times on
a data centre exclusion are epoch seconds (milliseconds are accepted).
Nothing here reads a credential: a proxy gateway or proxy is described
by name only, never by certificate.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Forwarding methods (zia/forwarding_control.py add_rule docstring).
DIRECT = "DIRECT"
PROXYCHAIN = "PROXYCHAIN"
ZPA = "ZPA"
DEDICATED_IP = "ENATDEDIP"
DROP = "DROP"
ZIA_TYPE = "FORWARDING"            # a ZIA forwarding rule; other types are connector rules (assumed)
FAIL_WITH_ERROR = "FAIL_RET_ERR"   # dns_gatways.add_dns_gateway docstring example
LONG_EXCLUSION_DAYS = 30
MAX_NAMES = 5

METHOD_WORDS = {
    DIRECT: "sends it direct", PROXYCHAIN: "chains it to another proxy", ZPA: "sends it to ZPA through a ZPA gateway",
    DEDICATED_IP: "sends it out from a dedicated egress IP", DROP: "drops it", "ZIA": "sends it to ZIA",
    "ECZPA": "sends it to ZPA from the connector", "ECSELF": "handles it on the connector", "GEOIP": "forwards it by country",
}


# ── Small helpers (raw camelCase or SDK snake_case dicts) ────────────
def _snake(camel: str) -> str:
    out = []
    for ch in camel:
        if ch.isupper():
            out.append("_" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def f(x: Any, camel: str, default: Any = None) -> Any:
    if not isinstance(x, dict):
        return default
    for k in (camel, _snake(camel)):
        if x.get(k) is not None:
            return x[k]
    return default


def name_of(x: Any) -> str:
    if isinstance(x, dict):
        return str(x.get("name") or x.get("id") or "")[:120]
    return str(x or "")[:120]


def ref_list(v: Any) -> List[Any]:
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def ref_id(x: Any) -> Optional[str]:
    if isinstance(x, dict) and x.get("id") is not None:
        return str(x["id"])
    if isinstance(x, (int, str)) and str(x).strip():
        return str(x)
    return None


def enabled(r: Any) -> bool:
    return str(f(r, "state") or "ENABLED").upper() not in ("DISABLED", "0", "FALSE")


def short(items: Iterable[str], n: int = MAX_NAMES) -> str:
    items = [str(i) for i in items if str(i)]
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def method(r: Any) -> str:
    return str(f(r, "forwardMethod") or "").upper()


def is_zia_rule(r: Any) -> bool:
    """A ZIA forwarding rule (type FORWARDING, or no type given); any other
    type is a Cloud or Branch Connector rule (assumed type values)."""
    t = str(f(r, "type") or ZIA_TYPE).upper()
    return t == ZIA_TYPE


def is_default(r: Any) -> bool:
    o = f(r, "order")
    try:
        neg = int(o) < 0
    except (TypeError, ValueError):
        neg = False
    return bool(f(r, "defaultRule")) or bool(f(r, "predefined")) or neg or str(f(r, "name") or "").lower().startswith("default")


_DEST_FIELDS = ("destAddresses", "destIpGroups", "destIpv6Groups", "destIpCategories", "resCategories", "destCountries",
                "nwServices", "nwServiceGroups", "nwApplications", "nwApplicationGroups", "zpaAppSegments", "zpaApplicationSegments",
                "zpaApplicationSegmentGroups")
_SCOPE_FIELDS = ("users", "groups", "departments", "locations", "locationGroups", "ecGroups", "srcIps", "srcIpGroups", "srcIpv6Groups",
                 "deviceGroups", "devices", "timeWindows")


def destination_bound(r: Any) -> bool:
    """The rule names what it applies to (an address, category, service,
    application or segment)."""
    return any(ref_list(f(r, k)) for k in _DEST_FIELDS)


def scoped(r: Any) -> bool:
    return any(ref_list(f(r, k)) for k in _SCOPE_FIELDS)


def by_id(rows: Optional[Iterable[Any]]) -> Dict[str, Dict[str, Any]]:
    return {str(f(x, "id")): x for x in rows or [] if isinstance(x, dict) and f(x, "id") is not None}


# ── Forwarding rules ─────────────────────────────────────────────────
def direct_bypasses(rules: Iterable[Any]) -> Dict[str, List[str]]:
    """Enabled DIRECT rules on Cloud or Branch Connector traffic: that
    traffic goes around ZIA, uninspected. `broad`: no destination named
    (everything in their scope goes direct); `narrow`: named destinations."""
    out: Dict[str, List[str]] = {"broad": [], "narrow": []}
    for r in rules:
        if not isinstance(r, dict) or not enabled(r) or method(r) != DIRECT or is_zia_rule(r) or is_default(r):
            continue
        out["narrow" if destination_bound(r) else "broad"].append(name_of(r))
    return out


def proxy_chain_findings(rules: Iterable[Any], gateways: Optional[Iterable[Any]]) -> Dict[str, List[str]]:
    """Enabled proxy-chaining rules: `no_gateway` (none named, or one that
    no longer exists when the gateways were read), `no_fallback` (the
    gateway has no secondary proxy), `fail_open` (no secondary and not fail
    closed: traffic goes direct, uninspected, when the proxy is down),
    `unknown` (the gateways could not be read)."""
    gw = by_id(gateways) if gateways is not None else None
    out: Dict[str, List[str]] = {"no_gateway": [], "no_fallback": [], "fail_open": [], "unknown": [], "ok": []}
    for r in rules:
        if not isinstance(r, dict) or not enabled(r) or method(r) != PROXYCHAIN:
            continue
        refs = ref_list(f(r, "proxyGateway"))
        label = name_of(r)
        if not refs:
            out["no_gateway"].append(label)
            continue
        if gw is None:
            out["unknown"].append(label)
            continue
        found = [gw.get(ref_id(x) or "") for x in refs]
        if not any(found):
            out["no_gateway"].append(label)
            continue
        g = next(x for x in found if x)
        if not ref_list(f(g, "secondaryProxy")):
            out["no_fallback"].append(f"{label} (gateway {name_of(g)})")
            if not f(g, "failClosed"):
                out["fail_open"].append(f"{label} (gateway {name_of(g)})")
        else:
            out["ok"].append(label)
    return out


def gateway_fallback(g: Optional[Dict[str, Any]]) -> str:
    """One sentence on a proxy gateway's fallback (for the Path analyzer)."""
    if not g:
        return "The proxy gateway the rule names was not found among the gateways read."
    if ref_list(f(g, "secondaryProxy")):
        return f"Proxy gateway {name_of(g)} has a secondary proxy ({name_of(f(g, 'secondaryProxy'))}) to fall back to."
    if f(g, "failClosed"):
        return f"Proxy gateway {name_of(g)} has no secondary proxy and fails closed: the traffic is blocked while its proxy is down."
    return f"Proxy gateway {name_of(g)} has no secondary proxy and does not fail closed: while its proxy is down this traffic is not chained."


def zpa_gateway_findings(rules: Iterable[Any], gateways: Iterable[Any]) -> Dict[str, List[str]]:
    """ZPA gateways with no server group or no application segment, ZPA
    rules naming no gateway, and gateways no enabled rule uses."""
    gws = [g for g in gateways if isinstance(g, dict)]
    zrules = [r for r in rules if isinstance(r, dict) and enabled(r) and method(r) == ZPA]
    used = {ref_id(x) for r in zrules for x in ref_list(f(r, "zpaGateway"))}
    return {"no_server_group": [name_of(g) for g in gws if not f(g, "zpaServerGroup")],
            "no_segments": [name_of(g) for g in gws if not ref_list(f(g, "zpaAppSegments"))],
            "rule_no_gateway": [name_of(r) for r in zrules if not ref_list(f(r, "zpaGateway"))],
            "unused": [name_of(g) for g in gws if str(f(g, "id")) not in used]}


# ── Data centre exclusions ───────────────────────────────────────────
def _epoch(v: Any) -> Optional[float]:
    try:
        t = float(v)
    except (TypeError, ValueError):
        return None
    return t / 1000.0 if t > 1e12 else t   # milliseconds accepted (assumed: seconds)


def active_exclusions(rows: Iterable[Any], now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Exclusions in force now: not expired, started, not yet ended. Each
    {name, dcid, days (or None when it has no end), long}."""
    now = time.time() if now is None else now
    out = []
    for x in rows:
        if not isinstance(x, dict) or f(x, "expired") is True:
            continue
        start, end = _epoch(f(x, "startTime")), _epoch(f(x, "endTime"))
        if start is not None and start > now:
            continue
        if end is not None and end <= now:
            continue
        days = None if end is None else round((end - (start if start is not None else now)) / 86400.0, 1)
        out.append({"name": name_of(f(x, "dcName")) or f"data centre {f(x, 'dcid')}", "dcid": str(f(x, "dcid") or ""),
                    "days": days, "long": days is None or days > LONG_EXCLUSION_DAYS})
    return out


# ── GRE tunnels ──────────────────────────────────────────────────────
def vip_index(vips: Optional[Iterable[Any]]) -> Dict[str, str]:
    """Public VIP address -> data centre, from the /vips list (greIps)."""
    out: Dict[str, str] = {}
    for v in vips or []:
        if not isinstance(v, dict):
            continue
        dc = str(f(v, "dataCenter") or f(v, "datacenter") or f(v, "city") or "")
        for ip in ref_list(f(v, "greIps")):
            if dc and isinstance(ip, str):
                out[ip.strip()] = dc
    return out


def _vip_dc(vip: Any, index: Dict[str, str]) -> Tuple[str, str]:
    if not isinstance(vip, dict):
        return "", ""
    ip = str(f(vip, "virtualIp") or "")
    dc = f(vip, "datacenter")
    dc = name_of(dc) if isinstance(dc, dict) else str(dc or "")
    if dc.lower() in ("false", "none"):
        dc = ""
    return ip, dc or index.get(ip, "")


def gre_diversity(tunnels: Iterable[Any], vips: Optional[Iterable[Any]] = None) -> Dict[str, List[str]]:
    """Each GRE tunnel: `no_secondary`, `same_dc` (both VIPs in one data
    centre: one outage takes both), `unknown_dc` (a data centre not known
    for one of them), `diverse`."""
    idx = vip_index(vips)
    out: Dict[str, List[str]] = {"no_secondary": [], "same_dc": [], "unknown_dc": [], "diverse": []}
    for t in tunnels:
        if not isinstance(t, dict):
            continue
        label = str(f(t, "sourceIp") or f(t, "comment") or f(t, "id") or "tunnel")[:80]
        p_ip, p_dc = _vip_dc(f(t, "primaryDestVip"), idx)
        s_ip, s_dc = _vip_dc(f(t, "secondaryDestVip"), idx)
        if not s_ip:
            out["no_secondary"].append(label)
        elif s_ip == p_ip:
            out["same_dc"].append(f"{label} (one VIP for both)")
        elif not p_dc or not s_dc:
            out["unknown_dc"].append(label)
        elif p_dc.lower() == s_dc.lower():
            out["same_dc"].append(f"{label} ({p_dc})")
        else:
            out["diverse"].append(label)
    return out


# ── IPv6 ─────────────────────────────────────────────────────────────
def ipv6_state(cfg: Any) -> Optional[bool]:
    if isinstance(cfg, list):
        cfg = cfg[0] if cfg and isinstance(cfg[0], dict) else {}
    if not isinstance(cfg, dict):
        return None
    v = f(cfg, "ipV6Enabled")
    if v is None:
        v = f(cfg, "ipv6Enabled")
    return None if v is None else bool(v)


# ── Dedicated IP gateways ────────────────────────────────────────────
def dedicated_ip_findings(gws: Iterable[Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"no_secondary": [], "same_dc": [], "ok": []}
    for g in gws:
        if not isinstance(g, dict):
            continue
        p, s = name_of(f(g, "primaryDataCenter")), name_of(f(g, "secondaryDataCenter"))
        if not s:
            out["no_secondary"].append(name_of(g))
        elif p and p.lower() == s.lower():
            out["same_dc"].append(f"{name_of(g)} ({p})")
        else:
            out["ok"].append(name_of(g))
    return out


# ── NAT control ──────────────────────────────────────────────────────
def redirect_target(r: Any) -> str:
    target = str(f(r, "redirectFqdn") or f(r, "redirectIp") or "")[:120]
    port = f(r, "redirectPort")
    return f"{target}:{port}" if target and port else target


def dnat_findings(rules: Iterable[Any]) -> Dict[str, List[str]]:
    """Enabled NAT control rules: `broad` (they redirect with no destination
    named, so every destination in their scope is rewritten), `no_target`
    (no redirect address or name), `ok`."""
    out: Dict[str, List[str]] = {"broad": [], "no_target": [], "ok": []}
    for r in rules:
        if not isinstance(r, dict) or not enabled(r) or f(r, "defaultRule") or f(r, "predefined"):
            continue
        if not redirect_target(r):
            out["no_target"].append(name_of(r))
        elif not destination_bound(r):
            out["broad"].append(f"{name_of(r)} (to {redirect_target(r)})")
        else:
            out["ok"].append(name_of(r))
    return out


# ── Virtual Service Edges ────────────────────────────────────────────
def vzen_findings(clusters: Iterable[Any], nodes: Iterable[Any]) -> Dict[str, List[str]]:
    """Clusters with fewer than two working nodes, nodes switched off or
    not in production, and nodes in no cluster."""
    nodes = [n for n in nodes if isinstance(n, dict)]
    working = lambda n: str(f(n, "status") or "ENABLED").upper() == "ENABLED" and f(n, "inProduction") is not False  # noqa: E731
    out: Dict[str, List[str]] = {"thin": [], "down": [], "standalone": [], "ok": []}
    by_cluster: Dict[str, List[Dict[str, Any]]] = {}
    for n in nodes:
        by_cluster.setdefault(str(f(n, "clusterName") or "").lower(), []).append(n)
    for c in clusters:
        if not isinstance(c, dict):
            continue
        members = ref_list(f(c, "virtualZenNodes"))
        ids = {ref_id(m) for m in members}
        mine = [n for n in nodes if str(f(n, "id")) in ids] or by_cluster.get(name_of(c).lower(), [])
        up = [n for n in mine if working(n)] if mine else []
        count = len(up) if mine else (len(members) if str(f(c, "status") or "ENABLED").upper() == "ENABLED" else 0)
        (out["ok"] if count >= 2 else out["thin"]).append(f"{name_of(c)} ({count} working node{'s' if count != 1 else ''})")
    in_cluster = {ref_id(m) for c in clusters if isinstance(c, dict) for m in ref_list(f(c, "virtualZenNodes"))}
    names = {name_of(c).lower() for c in clusters if isinstance(c, dict)}
    for n in nodes:
        if not working(n):
            out["down"].append(name_of(n))
        if str(f(n, "id")) not in in_cluster and str(f(n, "clusterName") or "").lower() not in names:
            out["standalone"].append(name_of(n))
    return out


# ── DNS gateways ─────────────────────────────────────────────────────
def dns_gateway_findings(gws: Iterable[Any]) -> Dict[str, List[str]]:
    """`no_secondary_fail` (no secondary and failing with an error: DNS
    stops while the provider is down), `no_secondary`, `ok`."""
    out: Dict[str, List[str]] = {"no_secondary_fail": [], "no_secondary": [], "ok": []}
    for g in gws:
        if not isinstance(g, dict):
            continue
        if f(g, "secondaryIpOrFqdn"):
            out["ok"].append(name_of(g))
        elif str(f(g, "failureBehavior") or "").upper() == FAIL_WITH_ERROR:
            out["no_secondary_fail"].append(name_of(g))
        else:
            out["no_secondary"].append(name_of(g))
    return out


def dns_gateway_note(g: Optional[Dict[str, Any]]) -> str:
    """One sentence on a DNS gateway's failover (for the Path analyzer)."""
    if not g:
        return "The DNS gateway the rule names was not found among the gateways read."
    if f(g, "secondaryIpOrFqdn"):
        return f"DNS gateway {name_of(g)} has a secondary resolver to fail over to."
    if str(f(g, "failureBehavior") or "").upper() == FAIL_WITH_ERROR:
        return f"DNS gateway {name_of(g)} has no secondary resolver and answers with an error when its resolver is down: the lookup fails."
    return f"DNS gateway {name_of(g)} has no secondary resolver; what happens when its resolver is down is {str(f(g, 'failureBehavior') or 'not set')[:40]}."
