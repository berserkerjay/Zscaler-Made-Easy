"""A bundled, dated excerpt of Microsoft's published Microsoft 365
endpoint list, so ZIA app service groups for Microsoft 365 (app_services)
match out of the box, offline, with nothing fetched.

What this is, and what it is not:
  * Five of Microsoft's endpoint sets, copied entry for entry from
    Microsoft's published list, worldwide instance, version
    SNAPSHOT_VERSION (generated SNAPSHOT_DATE), and compared with that
    version on CHECKED_DATE, when it was the version in Microsoft's
    published documentation. Shipped with the app; no request is made to
    build or use it.
  * An EXCERPT, never the whole list: an address or host name in it is in
    Microsoft's published list ("match"), but one not in it says nothing,
    so the excerpt never makes a group "no match" (app_services checks
    `partial`). Only a list fetched or imported in Advanced settings,
    which is Microsoft's whole list, can do that.
  * Dated. Its age runs from CHECKED_DATE, the day it was last compared
    with Microsoft's list (as a kept list's runs from when it was last
    confirmed). Older than BUNDLED_MAX_AGE_DAYS it settles nothing
    (unknown, "refresh it"); every result that used it says so, with its
    version, date and age. A list kept in Advanced settings (fetched or
    imported) replaces it.

No other provider ships an excerpt (VENDOR is empty): Zoom's, Webex's,
RingCentral's, GoTo's and Talkdesk's published lists could not be read
from the build machine, so nothing unverified is bundled. Their groups
match only once the provider's list is fetched (Zoom, GoTo) or imported
in Advanced settings; until then they stay unknown. A verified excerpt can
be added to VENDOR later in vendor_endpoints' plain-text shape:
{"source", "source_name", "ips", "hosts"}.

The excerpt is checked by the same strict parser as a fetched or imported
list (m365_endpoints.parse; vendor_endpoints.parse for a VENDOR entry)
when it is first used, so a bad entry fails loudly in tests, never
silently.
"""
from __future__ import annotations

import datetime as _dt
import json
import threading
from typing import Any, Dict, List, Optional

SNAPSHOT_VERSION = "2026043000"     # Microsoft's version of the worldwide list the excerpt is copied from
SNAPSHOT_DATE = "2026-04-30"        # the day Microsoft generated that version
CHECKED_DATE = "2026-11-04"         # the day the excerpt was compared, entry by entry, with that version
BUNDLED_MAX_AGE_DAYS = 180          # an excerpt not checked for longer than this settles nothing (it may have drifted)

# ── Microsoft 365 (Microsoft's endpoint sets, in its own JSON shape) ──
# Copied from Microsoft's generated table of the worldwide endpoints
# ("Worldwide endpoints version 2026043000", file generated 2026-04-30),
# the source of the "Microsoft 365 URLs and IP address ranges" page: each
# set's category, ER, host names, address ranges and ports exactly as
# published there. serviceAreaDisplayName is the section the set is
# published under. assumed: serviceArea is the web service's key for that
# section (the table has no such column; the same keys as
# m365_endpoints.AREAS).
M365_SOURCE = "https://learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges"
M365_SETS: List[Dict[str, Any]] = [
    {"id": 1, "serviceArea": "Exchange", "serviceAreaDisplayName": "Exchange Online", "category": "Optimize", "required": True,
     "expressRoute": True, "urls": ["outlook.cloud.microsoft", "outlook.office.com", "outlook.office365.com"],
     "ips": ["13.107.6.152/31", "13.107.18.10/31", "13.107.128.0/22", "23.103.160.0/20", "40.96.0.0/13", "40.104.0.0/15",
             "52.96.0.0/14", "131.253.33.215/32", "132.245.0.0/16", "150.171.32.0/22", "204.79.197.215/32", "2603:1006::/40",
             "2603:1016::/36", "2603:1026::/36", "2603:1036::/36", "2603:1046::/36", "2603:1056::/36", "2620:1ec:4::152/128",
             "2620:1ec:4::153/128", "2620:1ec:c::10/128", "2620:1ec:c::11/128", "2620:1ec:d::10/128", "2620:1ec:d::11/128",
             "2620:1ec:8f0::/46", "2620:1ec:900::/46", "2620:1ec:a92::152/128", "2620:1ec:a92::153/128"],
     "tcpPorts": "443,80", "udpPorts": "443"},
    {"id": 31, "serviceArea": "SharePoint", "serviceAreaDisplayName": "SharePoint Online and OneDrive for Business", "category": "Optimize",
     "required": True, "expressRoute": True, "urls": ["*.sharepoint.com"],
     "ips": ["13.107.136.0/22", "40.108.128.0/17", "52.104.0.0/14", "104.146.128.0/17", "150.171.40.0/22", "2603:1061:1300::/40",
             "2603:1063:6000::/35", "2620:1ec:8f8::/46", "2620:1ec:908::/46", "2a01:111:f402::/48"],
     "tcpPorts": "443,80", "udpPorts": "443"},
    {"id": 11, "serviceArea": "Skype", "serviceAreaDisplayName": "Microsoft Teams", "category": "Optimize", "required": True,
     "expressRoute": True, "ips": ["52.112.0.0/14", "52.122.0.0/15", "2603:1063::/38"], "udpPorts": "3478,3479,3480,3481"},
    {"id": 12, "serviceArea": "Skype", "serviceAreaDisplayName": "Microsoft Teams", "category": "Allow", "required": True,
     "expressRoute": True,
     "urls": ["*.lync.com", "*.teams.cloud.microsoft", "*.teams.microsoft.com", "teams.cloud.microsoft", "teams.microsoft.com"],
     "ips": ["52.112.0.0/14", "52.122.0.0/15", "2603:1027::/48", "2603:1037::/48", "2603:1047::/48", "2603:1057::/48",
             "2603:1063::/38", "2620:1ec:6::/48", "2620:1ec:40::/42"],
     "tcpPorts": "443,80", "udpPorts": "443"},
    {"id": 56, "serviceArea": "Common", "serviceAreaDisplayName": "Microsoft 365 Common and Office Online", "category": "Allow",
     "required": True, "expressRoute": True,
     "urls": ["*.auth.microsoft.com", "*.msftidentity.com", "*.msidentity.com", "account.activedirectory.windowsazure.com",
              "accounts.accesscontrol.windows.net", "adminwebservice.microsoftonline.com", "api.passwordreset.microsoftonline.com",
              "autologon.microsoftazuread-sso.com", "becws.microsoftonline.com", "ccs.login.microsoftonline.com",
              "clientconfig.microsoftonline-p.net", "companymanager.microsoftonline.com", "device.login.microsoftonline.com",
              "graph.microsoft.com", "graph.windows.net", "login-us.microsoftonline.com", "login.microsoft.com",
              "login.microsoftonline-p.com", "login.microsoftonline.com", "login.windows.net", "logincert.microsoftonline.com",
              "loginex.microsoftonline.com", "nexus.microsoftonline-p.com", "passwordreset.microsoftonline.com",
              "provisioningapi.microsoftonline.com"],
     "ips": ["20.20.32.0/19", "20.190.128.0/18", "20.231.128.0/19", "40.126.0.0/18", "2603:1006:2000::/48", "2603:1007:200::/48",
             "2603:1016:1400::/48", "2603:1017::/48", "2603:1026:3000::/48", "2603:1027:1::/48", "2603:1036:3000::/48",
             "2603:1037:1::/48", "2603:1046:2000::/48", "2603:1047:1::/48", "2603:1056:2000::/48", "2603:1057:2::/48"],
     "tcpPorts": "443,80"},
]

# ── The other UCaaS providers (vendor_endpoints' plain-text shape) ─────
# None ships: no entry here has been checked against the provider's
# published list (see the module docstring).
VENDOR: Dict[str, Dict[str, Any]] = {}

_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {}


def captured() -> _dt.datetime:
    """When the source version was generated (midnight UTC on SNAPSHOT_DATE)."""
    return _dt.datetime.strptime(SNAPSHOT_DATE, "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)


def checked() -> _dt.datetime:
    """When the excerpt was last compared with its source (midnight UTC on CHECKED_DATE); its age runs from here."""
    return _dt.datetime.strptime(CHECKED_DATE, "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)


def _meta(source_url: str, source_name: str, version: Optional[str] = None) -> Dict[str, Any]:
    return {"source": "bundled", "partial": True, "fetched_at": captured().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "checked_at": checked().strftime("%Y-%m-%dT%H:%M:%SZ"), "version": version, "sha256": None,
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
            _CACHE["m365"] = m365_endpoints.EndpointList(sets, _meta(M365_SOURCE, m365_endpoints.SOURCE_NAME, SNAPSHOT_VERSION))
        return _CACHE["m365"]


def age_days(now: Optional[_dt.datetime] = None) -> float:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return max(0.0, (now - checked()).total_seconds() / 86400)


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
        what = f"Bundled excerpt of {kind}'s list as published {SNAPSHOT_DATE}, last checked against it {CHECKED_DATE} ({days} ago)"
        if stale:
            return {"state": "bundled_old", "label": f"{what}: too old to use (over {BUNDLED_MAX_AGE_DAYS} days). "
                                                       f"Fetch or import {kind}'s list."}
        return {"state": "bundled", "label": f"{what}. It can show a match, never a no match. Fetch or import {kind}'s list to settle more."}
    if stale:
        return {"state": "stale", "label": f"Stale: last confirmed {days} ago, over {max_age} days. It settles nothing."}
    return {"state": "fresh", "label": f"Current: last confirmed {days} ago."}


def summary(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """What Advanced settings says about the excerpts: the date, the age,
    whether they are too old, and per provider the counts and source."""
    out = {"date": SNAPSHOT_DATE, "version": SNAPSHOT_VERSION, "checked": CHECKED_DATE, "age_days": round(age_days(now), 1), "expired": expired(now), "max_age_days": BUNDLED_MAX_AGE_DAYS,
           "providers": {}}
    for pid, snap in VENDOR.items():
        out["providers"][pid] = {"source": snap["source"], "source_name": snap["source_name"], "ipv4": sum(1 for x in snap["ips"] if ":" not in x),
                                 "ipv6": sum(1 for x in snap["ips"] if ":" in x), "hosts": len(snap["hosts"])}
    out["providers"]["m365"] = {"source": M365_SOURCE, "version": SNAPSHOT_VERSION, "sets": len(M365_SETS)}
    return out
