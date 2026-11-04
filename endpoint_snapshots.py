"""Bundled, dated excerpts of the six providers' published endpoint lists,
so ZIA app service groups (app_services) match out of the box, offline,
with nothing fetched.

What this is, and what it is not:
  * One excerpt per provider (Microsoft 365, Zoom, Webex, RingCentral,
    GoTo, Talkdesk), each naming the provider's own published source and
    the date it was compiled (SNAPSHOT_DATE). Shipped with the app; no
    request is made to build or use it.
  * An EXCERPT, never the whole list: an address or host name in it is in
    the provider's published list ("match"), but one not in it says
    nothing, so an excerpt never makes a group "no match" (app_services
    checks `partial`). Only a list fetched or imported in Advanced
    settings, which is the provider's whole list, can do that.
  * Dated. An excerpt older than BUNDLED_MAX_AGE_DAYS settles nothing
    (unknown, "refresh it"); every result that used one says so, with its
    date and age. A list kept in Advanced settings (fetched or imported)
    replaces the excerpt for that provider: a fetch only refreshes it.

assumed: every entry below was compiled on SNAPSHOT_DATE from the source
named with it (the provider's network requirements article or published
file) and was not re-read from that source by the build machine, so the
entries are marked assumed until a fetch or an import replaces them.
Providers change their lists over time; that is why the excerpt is dated
and expires, and why a fetched or imported list wins.

Every excerpt is checked by the same strict parsers as a fetched or
imported list (vendor_endpoints.parse, m365_endpoints.parse) when it is
first used, so a bad entry fails loudly in tests, never silently.
"""
from __future__ import annotations

import datetime as _dt
import json
import threading
from typing import Any, Dict, List, Optional

SNAPSHOT_DATE = "2026-11-04"
BUNDLED_MAX_AGE_DAYS = 180          # an excerpt older than this settles nothing (it may have drifted)

# ── Microsoft 365 (Microsoft's endpoint sets, in its own JSON shape) ──
# assumed: compiled from Microsoft's "Office 365 IP Address and URL web
# service" (worldwide instance) as published; only these sets, and within
# them only these entries.
M365_SOURCE = "https://endpoints.office.com/endpoints/worldwide"
M365_SETS: List[Dict[str, Any]] = [
    {"id": 1, "serviceArea": "Exchange", "serviceAreaDisplayName": "Exchange Online", "category": "Optimize", "required": True,
     "expressRoute": True, "urls": ["outlook.office.com", "outlook.office365.com"],
     "ips": ["13.107.6.152/31", "13.107.18.10/31", "13.107.128.0/22", "23.103.160.0/20", "40.96.0.0/13", "40.104.0.0/15",
             "52.96.0.0/14", "131.253.33.215/32", "132.245.0.0/16", "150.171.32.0/22", "204.79.197.215/32", "2603:1006::/40",
             "2603:1016::/36", "2603:1026::/36", "2603:1036::/36", "2603:1046::/36", "2603:1056::/36"],
     "tcpPorts": "80,443", "udpPorts": "443"},
    {"id": 11, "serviceArea": "Skype", "serviceAreaDisplayName": "Skype for Business Online and Microsoft Teams", "category": "Optimize",
     "required": True, "expressRoute": True, "ips": ["13.107.64.0/18", "52.112.0.0/14", "52.122.0.0/15", "2603:1063::/38"],
     "udpPorts": "3478,3479,3480,3481"},
    {"id": 12, "serviceArea": "Skype", "serviceAreaDisplayName": "Skype for Business Online and Microsoft Teams", "category": "Allow",
     "required": True, "expressRoute": True, "urls": ["*.lync.com", "*.teams.microsoft.com", "teams.microsoft.com"],
     "ips": ["52.112.0.0/14", "52.122.0.0/15", "2603:1063::/38"], "tcpPorts": "443,80"},
    {"id": 31, "serviceArea": "SharePoint", "serviceAreaDisplayName": "SharePoint Online and OneDrive for Business", "category": "Optimize",
     "required": True, "expressRoute": True, "urls": ["<tenant>.sharepoint.com", "<tenant>-my.sharepoint.com"],
     "ips": ["13.107.136.0/22", "40.108.128.0/17", "52.104.0.0/14", "104.146.128.0/17", "150.171.40.0/22", "2603:1061:1300::/40",
             "2620:1ec:8f8::/46", "2620:1ec:908::/46"], "tcpPorts": "443,80"},
    {"id": 56, "serviceArea": "Common", "serviceAreaDisplayName": "Microsoft 365 Common and Office Online", "category": "Allow",
     "required": True, "expressRoute": True,
     "urls": ["*.auth.microsoft.com", "*.msftidentity.com", "*.msidentity.com", "account.activedirectory.windowsazure.com",
              "graph.microsoft.com", "login.microsoft.com", "login.microsoftonline.com", "login.windows.net"],
     "ips": ["20.20.32.0/19", "20.190.128.0/18", "20.231.128.0/19", "40.126.0.0/18"], "tcpPorts": "443,80"},
]

# ── The other UCaaS providers (vendor_endpoints' plain-text shape) ─────
# assumed: each list compiled from the source named with it on
# SNAPSHOT_DATE (see the module docstring).
VENDOR: Dict[str, Dict[str, Any]] = {
    "zoom": {
        "source": "https://assets.zoom.us/docs/ipranges/Zoom.txt",
        "source_name": "Zoom's published IP ranges (Zoom.txt) and its firewall or proxy server settings article",
        "ips": ["3.7.35.0/25", "8.5.128.0/23", "64.125.62.0/24", "64.211.144.0/24", "64.224.32.0/19", "65.39.152.0/24",
                "69.174.57.0/24", "69.174.108.0/22", "99.79.20.0/25", "103.122.166.0/23", "120.29.148.0/24", "144.195.0.0/16",
                "147.124.96.0/19", "149.137.0.0/17", "156.45.0.0/17", "159.124.0.0/16", "161.199.136.0/22", "162.12.232.0/22",
                "162.255.36.0/22", "165.254.88.0/23", "170.114.0.0/16", "173.231.80.0/20", "192.204.12.0/22", "198.251.128.0/17",
                "204.80.104.0/21", "204.141.28.0/22", "206.247.0.0/16", "207.226.132.0/24", "209.9.211.0/24", "209.9.215.0/24",
                "213.19.144.0/24", "213.244.140.0/24"],
        "hosts": ["zoom.us", "*.zoom.us", "zoom.com", "*.zoom.com", "*.zoomapp.cloud"]},
    "webex": {
        "source": "https://help.webex.com/en-us/article/WBX000028782/Network-Requirements-for-Webex-Services",
        "source_name": "Cisco's Network Requirements for Webex Services (IP subnets for Webex media services, and its domains)",
        "ips": ["23.89.0.0/16", "62.109.192.0/18", "64.68.96.0/19", "66.114.160.0/20", "66.163.32.0/19", "69.26.160.0/19",
                "114.29.192.0/19", "144.196.0.0/16", "150.253.128.0/17", "163.129.0.0/16", "170.72.0.0/16", "170.133.128.0/18",
                "173.39.224.0/19", "173.243.0.0/20", "207.182.160.0/19", "209.197.192.0/19", "210.4.192.0/20", "216.151.128.0/19"],
        "hosts": ["webex.com", "*.webex.com", "*.wbx2.com", "*.ciscospark.com", "*.webexcontent.com"]},
    "ringcentral": {
        "source": "https://support.ringcentral.com/gb/en/network-and-system-requirements/network-requirements/network-requirements-MVP.html",
        "source_name": "RingCentral's network requirements (advertised IP supernets, and its domains)",
        "ips": ["66.81.240.0/20", "104.245.56.0/21", "192.209.24.0/21", "199.68.212.0/22", "199.255.120.0/22", "208.87.40.0/22"],
        "hosts": ["ringcentral.com", "*.ringcentral.com"]},
    "goto": {
        "source": "https://support.goto.com/connect/help/allowlisting-and-firewall-configuration",
        "source_name": "GoTo's allowlisting and firewall configuration article",
        "ips": ["67.217.64.0/19", "68.64.0.0/19", "173.199.0.0/18", "216.115.208.0/20", "216.219.112.0/20"],
        "hosts": ["*.goto.com", "*.gotoconference.com", "*.jive.com", "*.getgo.com", "*.gotomeeting.com", "*.logmein.com"]},
    "talkdesk": {
        "source": "https://support.talkdesk.com/hc/en-us/articles/23849174371099",
        "source_name": "Talkdesk's Network Setup articles (IPs allowlist, SIP devices setup)",
        "ips": ["35.152.42.4/32"],
        "hosts": ["talkdesk.com", "*.talkdesk.com", "*.talkdeskapp.com"]},
}

_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {}


def captured() -> _dt.datetime:
    """When the excerpts were compiled (midnight UTC on SNAPSHOT_DATE)."""
    return _dt.datetime.strptime(SNAPSHOT_DATE, "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)


def _meta(source_url: str, source_name: str) -> Dict[str, Any]:
    at = captured().strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"source": "bundled", "partial": True, "fetched_at": at, "checked_at": at, "version": None, "sha256": None,
            "source_url": source_url, "source_name": source_name}


def vendor_list(pid: str) -> Optional[Any]:
    """The bundled excerpt of one UCaaS provider as a vendor_endpoints.
    VendorList (source 'bundled', partial), or None for a provider with
    none. Checked once by vendor_endpoints.parse."""
    import vendor_endpoints
    snap = VENDOR.get(pid)
    if snap is None or pid not in vendor_endpoints.PROVIDERS:
        return None
    with _LOCK:
        key = "v:" + pid
        if key not in _CACHE:
            entries = vendor_endpoints.parse("\n".join(list(snap["ips"]) + list(snap["hosts"])))
            _CACHE[key] = vendor_endpoints.VendorList(pid, entries, _meta(snap["source"], snap["source_name"]))
        return _CACHE[key]


def m365_list() -> Optional[Any]:
    """The bundled excerpt of Microsoft's Microsoft 365 list as an
    m365_endpoints.EndpointList (source 'bundled', partial)."""
    import m365_endpoints
    with _LOCK:
        if "m365" not in _CACHE:
            sets = m365_endpoints.parse(json.dumps(M365_SETS))
            _CACHE["m365"] = m365_endpoints.EndpointList(sets, _meta(M365_SOURCE, m365_endpoints.SOURCE_NAME))
        return _CACHE["m365"]


def age_days(now: Optional[_dt.datetime] = None) -> float:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return max(0.0, (now - captured()).total_seconds() / 86400)


def expired(now: Optional[_dt.datetime] = None) -> bool:
    return age_days(now) > BUNDLED_MAX_AGE_DAYS


def freshness(kind: str, *, present: bool, stale: Optional[bool], age: Optional[float], source: Optional[str],
              max_age: int) -> Dict[str, str]:
    """A plain label for a list's freshness, the same words on every page:
    {state: fresh | stale | bundled | bundled_old | none, label}."""
    if not present:
        return {"state": "none", "label": "No list"}
    days = "an unknown number of days" if age is None else f"{int(age)} day{'s' if int(age) != 1 else ''}"
    if source == "bundled":
        if stale:
            return {"state": "bundled_old", "label": f"Bundled excerpt from {SNAPSHOT_DATE}, {days} old: too old to use "
                                                       f"(over {BUNDLED_MAX_AGE_DAYS} days). Fetch or import {kind}'s list."}
        return {"state": "bundled", "label": f"Bundled excerpt from {SNAPSHOT_DATE}, {days} old. It can show a match, "
                                              f"never a no match. Fetch or import {kind}'s list to settle more."}
    if stale:
        return {"state": "stale", "label": f"Stale: last confirmed {days} ago, over {max_age} days. It settles nothing."}
    return {"state": "fresh", "label": f"Current: last confirmed {days} ago."}


def summary(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """What Advanced settings says about the excerpts: the date, the age,
    whether they are too old, and per provider the counts and source."""
    out = {"date": SNAPSHOT_DATE, "age_days": round(age_days(now), 1), "expired": expired(now), "max_age_days": BUNDLED_MAX_AGE_DAYS,
           "providers": {}}
    for pid, snap in VENDOR.items():
        out["providers"][pid] = {"source": snap["source"], "source_name": snap["source_name"], "ipv4": sum(1 for x in snap["ips"] if ":" not in x),
                                 "ipv6": sum(1 for x in snap["ips"] if ":" in x), "hosts": len(snap["hosts"])}
    out["providers"]["m365"] = {"source": M365_SOURCE, "sets": len(M365_SETS)}
    return out
