"""Client Connector fleet health: configuration and enrolled devices together.

The assessment already judges every Client Connector setting strictly
(zcc_evaluation) and the Path analyzer follows one transaction through the
profiles (data_flow). This module answers the fleet questions neither of
them asks: how many devices are enrolled, which services actually run on
them, which ones Zscaler cannot see, how far behind their client is, and
which profile, weighted by the devices it governs, to fix first.

Reading (read-only, only when ZCC is ticked on the Scope page; the server
checks that before signing in):
  * app profiles, forwarding profiles, trusted networks and hosted PAC files
    through the existing paced reader data_flow.read_client_connector, then
    the raw profiles and PAC files again through the same client, whose
    cache answers them without another request;
  * the enrolled devices through zscaler-sdk-python
    (zcc.devices.list_devices: GET /zcc/papi/public/v1/getDevices, paged
    with page / pageSize, at most 5000 a page) and the per-device service
    status, the CSV that DevicesAPI.download_service_status fetches
    (GET /zcc/papi/public/v1/downloadServiceStatus), asked through the SDK's
    request executor so it is parsed in memory and never written to disk.

Stop (`cancel`) is honoured between every request: nothing more is sent and
the run ends as stopped with no partial result.

Personal data: device host names and user names are needed to act on an
alert, so they are in the result the page shows. They are never written to
the run log or the Python log, and the exports offer a counts-only form.

Everything below `analyze` is pure: it takes what was read and a clock.
"""
from __future__ import annotations

import csv
import difflib
import hashlib
import io
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from zcc_evaluation import (ZCC_SUPPORTED_REF, _truthy, _v, code_text, device_platform, field_index, flatten_profile, version_tuple,
                            zcc_unsupported)

# ── thresholds (each is part of a definition the page shows) ──────────
SEEN_RECENT_HOURS = 24          # "seen in the last 24 hours": at most this many hours before the read
GHOST_DAYS = 31                 # "ghost": registered and last seen MORE than this many days before the read
MULTI_DEVICE_THRESHOLD = 3      # a user with MORE than this many registered devices
OLD_MINOR_RELEASES = 2          # "old": a lower major version, or this many minor versions behind on the same major
MANY_BYPASSES = 20              # destination bypasses + exclusions above this is a warning
MANY_APP_BYPASSES = 10

DEVICE_PAGE_SIZE = 5000         # the SDK's documented maximum for getDevices (oneapi_response SERVICE_PAGE_LIMITS zcc max)
MAX_DEVICE_PAGES = 40           # 200 000 devices; beyond that the read says it is incomplete
PAGE_PAUSE_SECONDS = 1.0        # pacing between device pages (ZCC's public API is rate limited per hour)
MAX_CSV_BYTES = 40 * 1024 * 1024
MAX_CSV_ROWS = MAX_DEVICE_PAGES * DEVICE_PAGE_SIZE   # as many rows as the device read may return
MAX_CELL_CHARS = 200            # a kept cell is cut here (a host name, a version, a state)
MAX_RESULT_DEVICES = 10000      # rows kept in the result for the page and the device export
MAX_ALERT_ROWS = 500

APP_ENDPOINT_DEVICES = "/zcc/papi/public/v1/getDevices"
SERVICE_STATUS_ENDPOINT = "/zcc/papi/public/v1/downloadServiceStatus"

STOPPED_REASON = "You clicked Stop: nothing more was read from the tenant and no partial result is kept."
SERVICES = ("zia", "zpa", "zdx")
SERVICE_LABELS = {"zia": "ZIA", "zpa": "ZPA", "zdx": "ZDX"}


class Stopped(RuntimeError):
    """The operator clicked Stop."""


# ── the definitions the page shows word for word ──────────────────────
ALERTS: Dict[str, Dict[str, Any]] = {
    "blind_spot": {
        "label": "Blind spots", "impact": 3, "needs": "service",
        "definition": f"A registered device whose ZIA service status is not active, yet which was last seen at most {SEEN_RECENT_HOURS} hours "
                      f"before the read (exactly {SEEN_RECENT_HOURS} hours still counts as seen). The device is in use, but its internet "
                      "traffic is not reaching ZIA.",
        "fix": "Find out why ZIA is off on these devices (a user who disabled it, a failed sign-in, a forwarding profile set to None) and "
               "turn on strict enforcement and the disable password in their app profile so it cannot be switched off again.",
    },
    "bypass_risk": {
        "label": "Bypass risk", "impact": 3, "needs": "service",
        "definition": "A registered device whose ZIA service status is not active while its ZPA service status is active. Private "
                      "applications keep working, so the user notices nothing, while internet traffic goes uninspected.",
        "fix": "Treat as a priority: require the ZIA disable password, and check whether a forwarding profile or a VPN is sending "
               "internet traffic around the tunnel on these devices.",
    },
    "ghost": {
        "label": "Ghost devices", "impact": 1, "needs": "devices",
        "definition": f"A registered device last seen more than {GHOST_DAYS} days before the read (exactly {GHOST_DAYS} days is not a "
                      "ghost). It still counts as enrolled and inflates every coverage figure.",
        "fix": "Remove these devices in the Client Connector Portal (or set device cleanup to remove inactive devices automatically) "
               "so the fleet figures describe devices that exist.",
    },
    "registration_anomaly": {
        "label": "Registration anomalies", "impact": 2, "needs": "devices",
        "definition": "A device that is quarantined, has removal pending, is registered but has never reported a last-seen time, or "
                      "whose device ID (UDID) is registered more than once.",
        "fix": "Review each one in the Client Connector Portal: release or remove quarantined devices, finish pending removals and "
               "remove the duplicate registrations so one device has one record.",
    },
    "multi_device": {
        "label": "Multi-device users", "impact": 1, "needs": "devices",
        "definition": f"A user with more than {MULTI_DEVICE_THRESHOLD} registered devices. Often old laptops never removed, shared "
                      "accounts or a re-imaged device enrolled again.",
        "fix": "Confirm with each user which devices are real; remove the rest, and look at the device limit per user in the "
               "Client Connector Portal.",
    },
    "version_drift": {
        "label": "Version drift", "impact": 1, "needs": "devices",
        "definition": "A registered device whose Client Connector version is older than the newest version seen on the same platform "
                      "in this fleet.",
        "fix": "Check the app update policy (automatic updates or the version pushed by your software distribution) for these "
               "devices so the fleet converges on one release per platform.",
    },
    "old_version": {
        "label": "Old releases", "impact": 2, "needs": "devices",
        "definition": f"A registered device on a lower major version than the newest seen on its platform in this fleet, or "
                      f"{OLD_MINOR_RELEASES} or more minor versions behind it on the same major version.",
        "fix": "Upgrade these devices first: an old release lacks fixes and the newer forwarding and posture features the profiles "
               "assume.",
    },
    "unsupported_version": {
        "label": "Unsupported releases", "impact": 3, "needs": "devices",
        "definition": "A registered device on a release older than every release Zscaler supports on its platform (the latest "
                      f"release, the two before it and the LTS, as the assessment's ZCC checks use them: {ZCC_SUPPORTED_REF}).",
        "fix": "Upgrade now: Zscaler support will not troubleshoot a client on an unsupported release.",
    },
}

CHECKS: List[Dict[str, Any]] = [
    {"key": "forwarding_linked", "label": "Forwarding profile linked", "impact": 3,
     "definition": "The app profile names a forwarding profile that exists.",
     "fix": "Link the app profile to a forwarding profile that tunnels traffic: without one, Client Connector has no instruction to send traffic to Zscaler."},
    {"key": "off_network_tunnel", "label": "Off network tunnelled", "impact": 3,
     "definition": "The linked forwarding profile tunnels traffic off the trusted network (Z-Tunnel 2.0 passes; Z-Tunnel 1.0 warns; None or PAC fails).",
     "fix": "Set the forwarding profile's off-trusted-network action to Tunnel with Z-Tunnel 2.0 so remote users reach ZIA on every port and protocol."},
    {"key": "on_network_forwarding", "label": "On network forwarded", "impact": 1,
     "definition": "The linked forwarding profile forwards traffic on the trusted network (None warns: fine only behind a GRE or IPsec tunnel).",
     "fix": "If the office has no GRE or IPsec tunnel to Zscaler, set the on-trusted-network action to Tunnel; otherwise record that the site tunnel covers it."},
    {"key": "strict_enforcement", "label": "Strict enforcement", "impact": 2,
     "definition": "Strict enforcement is on, so the device has no internet until the user signs in to Client Connector.",
     "fix": "Turn on strict enforcement in the app profile."},
    {"key": "anti_tampering", "label": "Anti-tampering", "impact": 2,
     "definition": "Anti-tampering is on (a Windows setting; other platforms are not applicable).",
     "fix": "Turn on anti-tampering in the Windows app profile so the user cannot stop the service or alter its files."},
    {"key": "tamper_passwords", "label": "Uninstall and disable passwords", "impact": 2,
     "definition": "The app profile sets an uninstall password and a ZIA disable password (unknown when the API returned neither field).",
     "fix": "Set the uninstall and disable passwords in the app profile so a user cannot turn protection off."},
    {"key": "ssl_cert", "label": "Root certificate installed", "impact": 2,
     "definition": "The app profile installs the Zscaler root certificate, without which SSL inspection breaks sites or is bypassed.",
     "fix": "Turn on installing the Zscaler root certificate in the app profile (or confirm it is pushed by MDM or group policy)."},
    {"key": "bypass_breadth", "label": "Narrow bypasses", "impact": 3,
     "definition": f"No destination bypass is a whole top-level domain or wildcard, no IP exclusion is wider than a /16 outside the private "
                   f"ranges, and there are at most {MANY_BYPASSES} entries.",
     "fix": "Replace broad bypasses with the exact hostnames an application needs; keep IP exclusions to RFC 1918 and named exceptions."},
    {"key": "app_bypass", "label": "Few application bypasses", "impact": 1,
     "definition": f"At most {MANY_APP_BYPASSES} application bypasses.",
     "fix": "Review each application bypass; most were added for a problem an SSL inspection exemption now solves without a full bypass."},
    {"key": "pac_direct", "label": "PAC sends nothing risky direct", "impact": 3,
     "definition": "No PAC file the profile uses sends a file-sharing, webmail, chat or AI service, a whole top-level domain or a public IP range DIRECT (a DIRECT default warns).",
     "fix": "Remove the risky DIRECT statements from the PAC file; use an SSL inspection exemption or a Cloud App Control rule instead of a bypass."},
    {"key": "endpoint_dlp", "label": "Endpoint DLP installed", "impact": 1,
     "definition": "The app profile installs Endpoint DLP (Windows and macOS; other platforms are not applicable).",
     "fix": "Turn on Endpoint DLP in the app profile for devices that handle sensitive data."},
]
CHECK_BY_KEY = {c["key"]: c for c in CHECKS}
_STATUS_SCORE = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
_SEVERITY_FACTOR = {"fail": 1.0, "warn": 0.5}


# ── small helpers ─────────────────────────────────────────────────────
def _stop(cancel: Any) -> None:
    import data_flow
    if data_flow.stop_requested(cancel):
        raise Stopped(STOPPED_REASON)


def _nap(seconds: float, cancel: Any) -> None:
    end = time.time() + max(0.0, seconds)
    while True:
        _stop(cancel)
        left = end - time.time()
        if left <= 0:
            return
        time.sleep(min(0.25, left))


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _clean_reason(text: Any) -> str:
    """An error message fit for the log and the result: short, and with
    anything that looks like a user name (an e-mail address) removed."""
    return _EMAIL.sub("<user>", str(text or ""))[:200]


def _http_code(text: str) -> Optional[int]:
    m = re.search(r"\b(400|401|403|404|405|429|500|502|503|504)\b", text or "")
    return int(m.group(1)) if m else None


def _unavailable_why(code: Optional[int], what: str) -> str:
    if code in (401, 403):
        return (f"The API client is not allowed to read {what} (HTTP {code}). Grant the Client Connector device read "
                "permission (Devices) to its role in ZIdentity, then run this again.")
    if code == 404:
        return f"The tenant did not offer {what} (HTTP 404): Client Connector may not be licensed or exposed on this OneAPI tenant."
    if code == 429:
        return (f"Client Connector's API refused {what} for now (HTTP 429, rate limited). Its device downloads are limited per "
                "hour and per day; try again later.")
    if code:
        return f"Reading {what} failed (HTTP {code})."
    return f"Reading {what} failed."


def _plain(obj: Any) -> Dict[str, Any]:
    """An SDK model (ZscalerObject) or a dict as a plain dict."""
    if isinstance(obj, dict):
        return obj
    fn = getattr(obj, "as_dict", None)
    if callable(fn):
        try:
            d = fn()
            if isinstance(d, dict):
                return d
        except Exception:  # noqa: BLE001
            pass
    return dict(getattr(obj, "__dict__", {}) or {})


def parse_time(raw: Any) -> Optional[datetime]:
    """A device timestamp as an aware UTC datetime: epoch seconds or
    milliseconds (number or digits), ISO 8601, "YYYY-MM-DD HH:MM:SS" with
    an optional UTC/GMT suffix, "MM/DD/YYYY HH:MM:SS" or "Mon DD, YYYY
    HH:MM:SS AM". A time without a zone is taken as UTC. None when blank
    or unreadable (the format the API uses is not documented in the SDK)."""
    if raw is None or raw == "" or isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)) or re.fullmatch(r"\s*\d{9,14}(\.\d+)?\s*", str(raw)):
        v = float(raw)
        if v <= 0:
            return None
        if v > 1e11:          # milliseconds
            v /= 1000.0
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = re.sub(r"\s*\b(UTC|GMT|Z)\s*$", "", str(raw).strip(), flags=re.I)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%b %d, %Y %I:%M:%S %p",
                "%b %d, %Y %H:%M:%S", "%d %b %Y %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def registration(raw: Any) -> str:
    """registered / unregistered / removal_pending / removed / quarantined /
    unknown. Numbers follow the SDK's registration filter codes
    (utils.zcc_param_map["reg_type"]: 1 registered, 3 removal pending,
    4 unregistered, 5 removed, 6 quarantined)."""
    s = code_text(raw).replace("_", " ").replace("-", " ")
    codes = {"1": "registered", "3": "removal_pending", "4": "unregistered", "5": "removed", "6": "quarantined"}
    if s in codes:
        return codes[s]
    s = s.replace(" ", "")   # "Removal Pending", "UN-REGISTERED", "De registered" read as one word
    if "quarantin" in s:
        return "quarantined"
    if "pending" in s:
        return "removal_pending"
    if "unregist" in s or "deregist" in s:
        return "unregistered"
    if "removed" in s or "remove" in s:
        return "removed"
    if "regist" in s:
        return "registered"
    return "unknown"


REGISTRATION_LABELS = {"registered": "Registered", "unregistered": "Unregistered", "removal_pending": "Removal pending",
                       "removed": "Removed", "quarantined": "Quarantined", "unknown": "Unknown"}

_ACTIVE = re.compile(r"^(on|active|enabled|connected|up|running|true|yes|1|healthy|online|ok|success\w*|authenticated|tunnel ?(up|connected))\b")
_INACTIVE = re.compile(r"\b(off|inactive|disabled|disconnected|down|error\w*|fail\w*|false|no|0|stopped|unhealthy|offline|not running|"
                       r"not connected|not authenticated|unauthenticated|captive|blocked)\b")
_NOT_APPLICABLE = re.compile(r"^(|n/?a|-|—|none|null|not applicable|not entitled|not licensed|not enabled|not enabled for user|unknown)$")


def service_state(raw: Any) -> str:
    """active / inactive / not_applicable / unknown for one service-status
    cell. The CSV's wording is not documented in the SDK: unrecognised text
    is "unknown" (counted apart, never as healthy) and the page lists every
    value seen with its reading."""
    s = re.sub(r"\s+", " ", code_text(raw))
    if _NOT_APPLICABLE.match(s):
        return "not_applicable"
    if _ACTIVE.match(s):
        return "active"
    if _INACTIVE.search(s):
        return "inactive"
    return "unknown"


def _switched_off(raw: Any) -> bool:
    """An "Enabled" cell that says no (false, no, 0, disabled, off)."""
    return code_text(raw) in ("false", "no", "0", "disabled", "off", "n")


def _norm_header(h: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def portal_columns(headers: Iterable[str]) -> Dict[str, Optional[str]]:
    """The device columns of a Client Connector CSV (the service-status file
    the API returns, or the Client Connector Portal's Enrolled Devices
    exports) by keyword, first match wins. The SDK documents only that the
    files start with "User","Device type"; the other names (UDID, Hostname,
    Zscaler Client Connector Version, Policy Name, Registration State, OS
    Version, Last Seen Connected to ZIA, Tunnel Version) are assumed from
    the portal's exports, so each is matched loosely and an unmatched one
    is simply not read."""
    out: Dict[str, Optional[str]] = {k: None for k in ("user", "udid", "hostname", "platform", "os_version", "version", "registration",
                                                         "last_seen", "policy", "tunnel")}
    seen_any: List[str] = []
    for h in headers:
        n = _norm_header(h)
        if not n:
            continue
        if out["udid"] is None and "udid" in n:
            out["udid"] = h
        elif out["hostname"] is None and any(k in n for k in ("hostname", "machinename", "devicename", "computername")):
            out["hostname"] = h
        elif out["user"] is None and n in ("user", "username", "userid", "enrolleduser", "useremail", "owner"):
            out["user"] = h
        elif out["platform"] is None and n in ("devicetype", "platform", "ostype", "type", "os"):
            out["platform"] = h
        elif out["os_version"] is None and n in ("osversion", "operatingsystemversion", "operatingsystem"):
            out["os_version"] = h
        elif out["version"] is None and (n in ("zccversion", "agentversion", "appversion", "version", "zappversion")
                                         or ("clientconnector" in n and "version" in n)):
            out["version"] = h
        elif out["registration"] is None and ("registration" in n or n in ("devicestate", "state")):
            out["registration"] = h
        elif out["policy"] is None and n in ("policyname", "policy", "appprofile", "appprofilename", "profilename", "profile"):
            out["policy"] = h
        elif out["tunnel"] is None and "tunnelversion" in n:
            out["tunnel"] = h
        elif "lastseen" in n or "keepalive" in n:
            seen_any.append(h)
    # "Last Seen Connected to ZIA" first (the time the ghost and blind-spot rules use), then any last-seen column.
    zia_seen = [h for h in seen_any if "zia" in _norm_header(h)]
    plain = [h for h in seen_any if "lastseen" in _norm_header(h) and not re.search(r"zpa|zdx", _norm_header(h))]
    out["last_seen"] = (zia_seen or plain or seen_any or [None])[0]
    return out


def service_columns(headers: Iterable[str]) -> Dict[str, Optional[str]]:
    """Which CSV column holds what. The SDK only shows that the file starts
    with "User","Device type"; the rest is matched by keyword: a column
    naming the service (ZIA, ZPA, ZDX) and its health, status, state or
    service (in that order of preference; else the bare service name),
    never a version, time or reason column. A "<service> Enabled" column
    (assumed from the portal's Service Status export, which has
    "ZIA Enabled" beside "ZIA Health") is kept apart as `<svc>_enabled`:
    it is read as the state only when no health or status column exists."""
    hs = list(headers)
    out: Dict[str, Optional[str]] = {k: v for k, v in portal_columns(hs).items()}
    for svc in SERVICES:
        cands = [h for h in hs if svc in _norm_header(h) and not re.search(r"version|time|date|lastseen|reason|since|count", _norm_header(h))]
        enabled = next((h for h in cands if "enabled" in _norm_header(h)), None)
        ranked = None
        for word in ("health", "status", "state", "service"):
            hit = [h for h in cands if word in _norm_header(h) and h != enabled]
            if hit:
                ranked = hit[0]
                break
        bare = [h for h in cands if h != enabled]
        out[svc] = ranked or (bare[0] if bare else None) or enabled
        out[f"{svc}_enabled"] = enabled if out[svc] != enabled else None
    return out


# ── reading ───────────────────────────────────────────────────────────
def read_configuration(client: Any, *, log: Callable[[str], None], cancel: Any) -> Dict[str, Any]:
    """The Client Connector configuration through the existing paced
    reader (data_flow.read_client_connector: app and forwarding profiles,
    trusted networks, hosted PAC files), plus the raw profiles and PAC
    files the drift view and the PAC comparison need. The raw reads go
    through the same client after the reader, whose cache answers them."""
    import data_flow
    from zcc_profiles import read_app_profiles, read_profiles
    scope = data_flow.path_scope(["zcc"], {})
    _stop(cancel)
    log("Reading Client Connector app and forwarding profiles, trusted networks and hosted PAC files…")
    try:
        with data_flow.stop_on(client, cancel):
            cfg = data_flow.read_client_connector(client, scope=scope, cancel=cancel)
            _stop(cancel)
            raw_app, _, _ = read_app_profiles(client.get, cancel=lambda: _stop(cancel))
            fwd, fcode = read_profiles(client.get, "/zcc/forwardingProfiles", cancel=lambda: _stop(cancel))
            pac, pcode = read_profiles(client.get, "/zia/pacFiles", cancel=lambda: _stop(cancel))
    except data_flow.ReadStopped:
        raise Stopped(STOPPED_REASON)
    _stop(cancel)
    cfg["raw_app_profiles"] = [p for p in raw_app if isinstance(p, dict)]
    cfg["raw_forwarding_profiles"] = [p for p in fwd if isinstance(p, dict)] if fcode == 200 and isinstance(fwd, list) else []
    cfg["raw_pac_files"] = [p for p in pac if isinstance(p, dict)] if pcode in (200, 204) and isinstance(pac, list) else []
    log(f"Read {len(cfg.get('app_profiles') or [])} app profile(s), {len(cfg.get('forwarding_profiles') or [])} forwarding "
        f"profile(s) and {len(cfg.get('pac_files') or [])} hosted PAC file(s)" + (f"; {len(cfg['errors'])} part(s) could not be read." if cfg.get("errors") else "."))
    return cfg


def read_devices(sdk: Any, *, log: Callable[[str], None], cancel: Any) -> Dict[str, Any]:
    """Every enrolled device (SDK zcc.devices.list_devices, paged) and the
    service-status CSV. Never raises for a refusal: the answer says
    `status` read / partial (devices but no service status) / unavailable
    with the reason. Only counts and HTTP codes are logged."""
    import data_flow
    out: Dict[str, Any] = {"status": "unavailable", "reason": "", "devices": [], "service": {"status": "unavailable", "reason": "", "rows": []}}
    if sdk is None or getattr(getattr(sdk, "zcc", None), "devices", None) is None:
        out["reason"] = "This sign-in has no Client Connector API, so no enrolled devices could be read."
        return out
    devices: List[Dict[str, Any]] = []
    with data_flow.stop_on(sdk, cancel):
        for page in range(1, MAX_DEVICE_PAGES + 1):
            _stop(cancel)
            log(f"Reading enrolled devices, page {page} (up to {DEVICE_PAGE_SIZE} a page)…")
            try:
                items, _resp, err = sdk.zcc.devices.list_devices(query_params={"page": page, "page_size": DEVICE_PAGE_SIZE})
            except Exception as e:  # noqa: BLE001 — a refusal is reported, never raised
                items, err = None, e
            _stop(cancel)
            if err is not None:
                code = _http_code(str(err))
                if page == 1:
                    out["reason"] = _unavailable_why(code, "the enrolled devices")
                    log(f"Enrolled devices could not be read ({'HTTP ' + str(code) if code else type(err).__name__}); "
                        "the fleet view falls back to configuration only.")
                    return out
                out["reason"] = (f"The device list stopped answering after {len(devices)} device(s) "
                                 f"({'HTTP ' + str(code) if code else type(err).__name__}); the figures would be incomplete, so they are not shown.")
                log(f"The device list stopped answering on page {page}; the device figures are not shown.")
                return out
            batch = [_plain(x) for x in (items or [])]
            devices.extend(batch)
            if len(batch) < DEVICE_PAGE_SIZE:
                break
            _nap(PAGE_PAUSE_SECONDS, cancel)
        else:
            out["reason"] = f"More than {MAX_DEVICE_PAGES * DEVICE_PAGE_SIZE} devices: the read stopped there, so the figures are not shown."
            log(out["reason"])
            return out
        log(f"Read {len(devices)} enrolled device record(s).")
        out["devices"] = devices
        out["status"] = "partial"
        _nap(PAGE_PAUSE_SECONDS, cancel)
        out["service"] = read_service_status(sdk, log=log, cancel=cancel)
    if out["service"]["status"] == "read":
        out["status"] = "read"
    else:
        out["reason"] = out["service"]["reason"]
    return out


def read_service_status(sdk: Any, *, log: Callable[[str], None], cancel: Any) -> Dict[str, Any]:
    """The service-status CSV (the request DevicesAPI.download_service_status
    makes, through the SDK's request executor) parsed in memory."""
    _stop(cancel)
    log("Reading the per-device service status (ZIA, ZPA, ZDX)…")
    out: Dict[str, Any] = {"status": "unavailable", "reason": "", "rows": [], "columns": {}, "headers": []}
    try:
        ex = sdk.get_request_executor()
        req, err = ex.create_request("GET", SERVICE_STATUS_ENDPOINT, params={}, headers={"Accept": "*/*"})
        if err:
            raise RuntimeError(str(err))
        resp, err = ex.execute(req, return_raw_response=True)
        if err is not None:
            raise RuntimeError(str(err))
        if resp is None:
            raise RuntimeError("no response")
    except Exception as e:  # noqa: BLE001
        code = _http_code(str(e))
        out["reason"] = _unavailable_why(code, "the per-device service status")
        log(f"The service status could not be read ({'HTTP ' + str(code) if code else type(e).__name__}); ZIA, ZPA and ZDX "
            "activity is not shown.")
        return out
    _stop(cancel)
    code = getattr(resp, "status_code", 200)
    if code and code != 200:
        out["reason"] = _unavailable_why(code, "the per-device service status")
        log(f"The service status could not be read (HTTP {code}); ZIA, ZPA and ZDX activity is not shown.")
        return out
    data = getattr(resp, "content", None)
    text = data.decode("utf-8-sig", errors="replace") if isinstance(data, (bytes, bytearray)) else str(getattr(resp, "text", "") or "")
    parsed = parse_service_csv(text)
    out.update(parsed)
    log(f"Read the service status of {len(parsed['rows'])} device(s)." if parsed["status"] == "read" else
        "The service status file had no usable ZIA, ZPA or ZDX column; activity is not shown.")
    return out


def parse_service_csv(text: str) -> Dict[str, Any]:
    """Rows {user, udid, hostname, zia, zpa, zdx (raw cell text)} from the
    service-status CSV, defensively: size-capped, every cell a string."""
    out: Dict[str, Any] = {"status": "unavailable", "reason": "", "rows": [], "columns": {}, "headers": []}
    if len(text) > MAX_CSV_BYTES:
        out["reason"] = f"The service status file is larger than {MAX_CSV_BYTES // (1024 * 1024)} MB; it was not read."
        return out
    try:
        reader = csv.reader(io.StringIO(text))
        headers = next(reader, [])
    except csv.Error:
        out["reason"] = "The service status file is not a CSV file."
        return out
    cols = service_columns(headers)
    out["headers"] = [str(h)[:60] for h in headers][:60]
    out["columns"] = {k: v for k, v in cols.items()}
    if not any(cols.get(s) for s in SERVICES):
        out["reason"] = "The service status file has no ZIA, ZPA or ZDX column this app recognises."
        return out
    idx = {k: headers.index(v) for k, v in cols.items() if v is not None}
    rows = []
    try:
        for r in reader:
            if not r:
                continue
            if len(rows) >= MAX_CSV_ROWS:
                out["reason"] = f"The service status file has more than {MAX_CSV_ROWS} rows; it was not read."
                return out
            rows.append({k: (r[i].strip()[:MAX_CELL_CHARS] if i < len(r) else "") for k, i in idx.items()})
    except csv.Error:
        out["reason"] = "The service status file could not be parsed past a malformed line."
        return out
    out["rows"] = rows
    out["status"] = "read"
    return out


# ── normalising ───────────────────────────────────────────────────────
def _hash(value: Any) -> str:
    s = str(value or "").strip().lower()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16] if s else ""


def normalize_devices(raw: List[Dict[str, Any]], service_rows: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    """One record per device: the fields the analysis uses, the service
    states joined from the CSV (by UDID, else user and host name, else a
    user's only row to that user's only device), the hours since it was last seen. The UDID is kept
    only as a hash, to spot duplicates."""
    by_udid: Dict[str, Dict[str, Any]] = {}
    by_user_host: Dict[Tuple[str, str], Dict[str, Any]] = {}
    by_user: Dict[str, List[Dict[str, Any]]] = {}
    devices_of: Dict[str, int] = {}
    raw = [field_index(d) for d in raw]
    for d in raw:
        u = str(_v(d, "user", "userName", "owner", default="") or "").strip().lower()
        devices_of[u] = devices_of.get(u, 0) + 1
    for r in service_rows:
        if r.get("udid"):
            by_udid[_hash(r["udid"])] = r
        u, h = str(r.get("user") or "").strip().lower(), str(r.get("hostname") or "").strip().lower()
        if u and h:
            by_user_host[(u, h)] = r
        if u:
            by_user.setdefault(u, []).append(r)
    out = []
    for i, d in enumerate(raw):
        user = str(_v(d, "user", "userName", "owner", default="") or "").strip()
        host = str(_v(d, "machineHostname", "hostname", "deviceName", "machineName", default="") or "").strip()
        uid = _hash(_v(d, "udid", default=""))
        row = by_udid.get(uid) if uid else None
        if row is None and user and host:
            row = by_user_host.get((user.lower(), host.lower()))
        if row is None and user and len(by_user.get(user.lower(), [])) == 1 and devices_of.get(user.lower()) == 1:
            row = by_user[user.lower()][0]
        # The device record's last-seen time, else its keep-alive, else the service status file's last-seen column
        # ("Last Seen Connected to ZIA", assumed from the portal's export) for the same device.
        seen = (parse_time(_v(d, "last_seen_time", "lastSeenTime", "lastSeen", default=None)) or parse_time(_v(d, "keepAliveTime", default=None))
                or (parse_time(row.get("last_seen")) if row is not None else None))
        age = None if seen is None else max(0.0, (now - seen).total_seconds())
        services = {s: ("unread" if row is None else service_state(row.get(s)) if row.get(s) is not None else "unread") for s in SERVICES}
        raw_services = {s: (str(row.get(s))[:40] if row is not None and row.get(s) is not None else None) for s in SERVICES}
        for s in SERVICES:
            # A "<service> Enabled" column saying no: the service is not turned on for this device (assumed portal
            # semantics), so it is not counted as active or inactive. Listed as such under "How the service status was read".
            if row is not None and _switched_off(row.get(f"{s}_enabled")):
                services[s], raw_services[s] = "not_applicable", "not enabled"
        reg_raw = _v(d, "registrationState", "registration_state", default=None)
        out.append({
            "id": f"d{i + 1}", "user": user, "hostname": host, "platform": device_platform(d),
            "os_version": str(_v(d, "osVersion", default="") or "")[:60], "version": str(_v(d, "agentVersion", default="") or "").strip()[:40],
            "registration": registration(reg_raw), "registration_raw": str(reg_raw if reg_raw is not None else "")[:40],
            "last_seen": seen.isoformat() if seen else None, "seconds_since_seen": age,
            "hours_since_seen": None if age is None else round(age / 3600.0, 1),
            "profile": str(_v(d, "policyName", "policy_name", default="") or "").strip()[:MAX_CELL_CHARS], "uid": uid,
            "tunnel": str(_v(d, "tunnelVersion", "tunnel_version", default="") or "").strip()[:40],
            "services": services, "service_raw": raw_services,
        })
    return out


# ── analysis: devices ────────────────────────────────────────────────
def is_recent(dev: Dict[str, Any]) -> bool:
    """Seen at most SEEN_RECENT_HOURS hours before the read (inclusive),
    to the second."""
    s = dev.get("seconds_since_seen")
    return s is not None and s <= SEEN_RECENT_HOURS * 3600


def is_ghost(dev: Dict[str, Any]) -> bool:
    """Registered and last seen MORE than GHOST_DAYS days before the read,
    to the second."""
    s = dev.get("seconds_since_seen")
    return dev.get("registration") == "registered" and s is not None and s > GHOST_DAYS * 86400


def _release(v: str) -> Tuple[int, ...]:
    return version_tuple(v)


def device_alerts(devs: List[Dict[str, Any]], service_read: bool) -> Dict[str, Dict[str, Any]]:
    """Every alert's matching devices (or users), and whether it could be
    evaluated at all: the service alerts need the service status."""
    reg = [d for d in devs if d["registration"] == "registered"]
    out: Dict[str, Dict[str, Any]] = {}

    def put(key: str, rows: List[Dict[str, Any]], evaluated: bool = True, why: str = "", **extra: Any) -> None:
        out[key] = dict(ALERTS[key], key=key, evaluated=evaluated, why_not=why, count=len(rows), rows=rows[:MAX_ALERT_ROWS],
                        truncated=len(rows) > MAX_ALERT_ROWS, **extra)

    no_service = "Not evaluated: the per-device service status could not be read."
    if service_read:
        put("blind_spot", [d for d in reg if d["services"]["zia"] == "inactive" and is_recent(d)])
        put("bypass_risk", [d for d in reg if d["services"]["zia"] == "inactive" and d["services"]["zpa"] == "active"])
    else:
        put("blind_spot", [], False, no_service)
        put("bypass_risk", [], False, no_service)
    put("ghost", [d for d in reg if is_ghost(d)])
    dup = {}
    for d in devs:
        if d["uid"] and d["registration"] not in ("removed",):
            dup[d["uid"]] = dup.get(d["uid"], 0) + 1
    anomalies = []
    for d in devs:
        why = []
        if d["registration"] == "quarantined":
            why.append("quarantined")
        if d["registration"] == "removal_pending":
            why.append("removal pending")
        if d["registration"] == "registered" and d["seconds_since_seen"] is None:
            why.append("registered, never seen")
        if d["uid"] and dup.get(d["uid"], 0) > 1 and d["registration"] != "removed":
            why.append("device ID registered more than once")
        if why:
            anomalies.append(dict(d, reason=", ".join(why)))
    put("registration_anomaly", anomalies)
    per_user: Dict[str, List[Dict[str, Any]]] = {}
    for d in reg:
        if d["user"]:
            per_user.setdefault(d["user"].lower(), []).append(d)
    users = [{"user": ds[0]["user"], "devices": len(ds), "hostnames": sorted({x["hostname"] for x in ds if x["hostname"]})[:20],
              "platforms": sorted({x["platform"] for x in ds})} for ds in per_user.values() if len(ds) > MULTI_DEVICE_THRESHOLD]
    users.sort(key=lambda u: (-u["devices"], u["user"].lower()))
    put("multi_device", users)
    newest = newest_versions(devs)
    drift, old, unsupported = [], [], []
    for d in reg:
        t = _release(d["version"])
        top = newest.get(d["platform"])
        if not t or not top:
            continue
        nt = _release(top)
        if t < nt:
            drift.append(dict(d, newest=top))
            if nt[0] > t[0] or (nt[0] == t[0] and len(nt) > 1 and (nt[1] - (t[1] if len(t) > 1 else 0)) >= OLD_MINOR_RELEASES):
                old.append(dict(d, newest=top))
        if zcc_unsupported(d["platform"], d["version"]):
            unsupported.append(d)
    put("version_drift", drift)
    put("old_version", old)
    put("unsupported_version", unsupported)
    return out


def newest_versions(devs: List[Dict[str, Any]]) -> Dict[str, str]:
    """The newest Client Connector version seen per platform among
    registered devices."""
    best: Dict[str, Tuple[Tuple[int, ...], str]] = {}
    for d in devs:
        if d["registration"] != "registered" or not d["version"]:
            continue
        t = _release(d["version"])
        if t and (d["platform"] not in best or t > best[d["platform"]][0]):
            best[d["platform"]] = (t, d["version"])
    return {p: v for p, (_, v) in best.items()}


def fleet_kpis(devs: List[Dict[str, Any]], service_read: bool) -> Dict[str, Any]:
    reg = [d for d in devs if d["registration"] == "registered"]
    states: Dict[str, int] = {}
    for d in devs:
        states[d["registration"]] = states.get(d["registration"], 0) + 1
    os_mix: Dict[str, int] = {}
    versions: Dict[str, Dict[str, int]] = {}
    for d in reg:
        os_mix[d["platform"]] = os_mix.get(d["platform"], 0) + 1
        if d["version"]:
            versions.setdefault(d["platform"], {})
            versions[d["platform"]][d["version"]] = versions[d["platform"]].get(d["version"], 0) + 1
    services: Dict[str, Any] = {}
    for s in SERVICES:
        if not service_read:
            services[s] = {"available": False, "active": None, "inactive": None, "known": None, "percent": None,
                           "note": "Not available: the per-device service status could not be read."}
            continue
        act = sum(1 for d in reg if d["services"][s] == "active")
        ina = sum(1 for d in reg if d["services"][s] == "inactive")
        na = sum(1 for d in reg if d["services"][s] == "not_applicable")
        unk = len(reg) - act - ina - na
        services[s] = {"available": True, "active": act, "inactive": ina, "not_applicable": na, "unknown": unk, "known": act + ina,
                       "percent": round(100.0 * act / (act + ina), 1) if (act + ina) else None,
                       "note": f"{act} of {act + ina} registered devices with a known {SERVICE_LABELS[s]} status"
                               + (f"; {na} not entitled or not applicable" if na else "") + (f"; {unk} without a readable status" if unk else "")}
    return {"devices": len(devs), "registered": len(reg), "registration_states": states,
            "registration_labels": {k: REGISTRATION_LABELS.get(k, k) for k in states},
            "os_mix": dict(sorted(os_mix.items(), key=lambda kv: -kv[1])),
            "versions": {p: dict(sorted(v.items(), key=lambda kv: version_tuple(kv[0]), reverse=True)) for p, v in versions.items()},
            "newest": newest_versions(devs),
            "seen_24h": sum(1 for d in reg if is_recent(d)),
            "never_seen": sum(1 for d in reg if d["seconds_since_seen"] is None),
            "quarantined": states.get("quarantined", 0),
            "services": services}


def service_values_seen(devs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every distinct service-status text and how this app read it, so an
    operator can see the interpretation (the CSV's words are not documented)."""
    seen: Dict[Tuple[str, str], int] = {}
    for d in devs:
        for s in SERVICES:
            raw = (d.get("service_raw") or {}).get(s)
            if raw is not None:
                seen[(s, raw)] = seen.get((s, raw), 0) + 1
    return [{"service": SERVICE_LABELS[s], "value": v, "read_as": service_state(v), "devices": n}
            for (s, v), n in sorted(seen.items(), key=lambda kv: (kv[0][0], -kv[1]))][:60]


# ── analysis: fleet depth (versions, profiles, last seen, sites) ─────
BELOW_FLEET_POINTS = 10.0       # a group's active % this many points under the fleet's is flagged
BELOW_FLEET_MIN_KNOWN = 5       # ... when at least this many of its devices have a known status
MAX_MATRIX_ROWS = 80
MAX_PROFILE_ROWS = 200
MAX_SITES = 300
SITE_MIN_COUNTS_ONLY = 3        # a counts-only export merges sites with fewer registered devices than this
SITE_MAX_PREFIXES = 200
SITE_MAX_LENGTH = 12
SITE_DELIMITERS = ("-", "_", ".")
SITE_MAX_SEGMENTS = 4
NO_SITE = "(no site)"
OTHER_SITE = "Other"
SMALL_SITES = f"(sites with fewer than {SITE_MIN_COUNTS_ONLY} registered devices)"
NO_PROFILE = "(no app profile)"
NOT_REPORTED = "not reported"

LAST_SEEN_BUCKETS: Tuple[Tuple[str, str, Optional[float], Optional[float]], ...] = (
    # key, label, more than (days), at most (days): to the second, as the ghost and recent rules are.
    ("under_1d", "Under 1 day", None, 1.0),
    ("1_7d", "1 to 7 days", 1.0, 7.0),
    ("7_30d", "7 to 30 days", 7.0, 30.0),
    ("over_30d", "Over 30 days", 30.0, None),
)
LAST_SEEN_DEFINITION = ("Registered devices by the time between their last-seen time and the read: under 1 day is at most 24 hours; "
                        "1 to 7 days is more than 24 hours and at most 7 days; 7 to 30 days is more than 7 and at most 30 days; over 30 "
                        f"days is more than 30 days (a ghost is more than {GHOST_DAYS}); never seen has no last-seen time.")
VERSION_HEALTH_DEFINITION = (f"Registered devices per platform and Client Connector version, with each service's active share among the "
                             f"devices whose status is known (active or not active; not applicable and unreadable are left out). A cell is "
                             f"flagged when it is {BELOW_FLEET_POINTS:g} or more points below the whole fleet's share for that service and at "
                             f"least {BELOW_FLEET_MIN_KNOWN} of its devices have a known status.")
PROFILE_HEALTH_DEFINITION = ("Registered devices per app profile (the policy name each device reports) and, through the forwarding profile "
                             "the app profile links to, per forwarding profile, with each service's active share among the devices whose "
                             "status is known. A device's forwarding profile is known only when its app profile was read from the tenant.")


def _svc_counts(devs: List[Dict[str, Any]], service_read: bool) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for s in SERVICES:
        act = sum(1 for d in devs if d["services"][s] == "active")
        ina = sum(1 for d in devs if d["services"][s] == "inactive")
        na = sum(1 for d in devs if d["services"][s] == "not_applicable")
        out[s] = {"active": act, "inactive": ina, "not_applicable": na, "unknown": len(devs) - act - ina - na, "known": act + ina,
                  "percent": round(100.0 * act / (act + ina), 1) if service_read and (act + ina) else None}
    return out


def _add_counts(into: Dict[str, Dict[str, Any]], more: Dict[str, Dict[str, Any]], service_read: bool) -> None:
    for s in SERVICES:
        for k in ("active", "inactive", "not_applicable", "unknown", "known"):
            into[s][k] += more[s][k]
        kn = into[s]["known"]
        into[s]["percent"] = round(100.0 * into[s]["active"] / kn, 1) if service_read and kn else None


def _below(row: Dict[str, Dict[str, Any]], fleet: Dict[str, Dict[str, Any]]) -> List[str]:
    """The services whose active share in `row` is far enough below the fleet's to flag (see VERSION_HEALTH_DEFINITION)."""
    out = []
    for s in SERVICES:
        r, f = row[s], fleet.get(s) or {}
        if r["percent"] is None or f.get("percent") is None or r["known"] < BELOW_FLEET_MIN_KNOWN:
            continue
        if r["percent"] <= f["percent"] - BELOW_FLEET_POINTS:
            out.append(s)
    return out


def _version_key(v: str) -> Tuple[int, Tuple[int, ...], str]:
    t = version_tuple(v) if v != NOT_REPORTED else ()
    return (0 if t else 1, tuple(-x for x in t), v)


def version_health(devs: List[Dict[str, Any]], service_read: bool) -> Dict[str, Any]:
    """The version x service matrix: registered devices per platform and
    Client Connector version, each service's active share, and the cells
    far enough below the fleet to flag. Pure."""
    reg = [d for d in devs if d["registration"] == "registered"]
    fleet = _svc_counts(reg, service_read)
    per_plat: Dict[str, int] = {}
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for d in reg:
        per_plat[d["platform"]] = per_plat.get(d["platform"], 0) + 1
        groups.setdefault((d["platform"], d["version"] or NOT_REPORTED), []).append(d)
    newest = newest_versions(devs)
    rows = []
    for (plat, ver), ds in groups.items():
        svc = _svc_counts(ds, service_read)
        rows.append({"platform": plat, "version": ver, "devices": len(ds),
                     "share": round(100.0 * len(ds) / per_plat[plat], 1) if per_plat.get(plat) else None,
                     "seen_24h": sum(1 for d in ds if is_recent(d)), "services": svc, "below_fleet": _below(svc, fleet),
                     "newest": ver == newest.get(plat), "unsupported": ver != NOT_REPORTED and zcc_unsupported(plat, ver)})
    order = {p: i for i, (p, _) in enumerate(sorted(per_plat.items(), key=lambda kv: (-kv[1], kv[0])))}
    rows.sort(key=lambda r: (order.get(r["platform"], 99), _version_key(r["version"])))
    return {"rows": rows[:MAX_MATRIX_ROWS], "truncated": len(rows) > MAX_MATRIX_ROWS, "fleet": fleet, "service_read": service_read,
            "definition": VERSION_HEALTH_DEFINITION}


def profile_health(devs: List[Dict[str, Any]], service_read: bool, profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Health per app profile (the policy name each registered device
    reports, per platform) and, through the forwarding profile each read
    app profile links to, per forwarding profile. Pure."""
    reg = [d for d in devs if d["registration"] == "registered"]
    fleet = _svc_counts(reg, service_read)
    by_key = {_profile_key(p.get("name"), p.get("platform")): p for p in profiles}
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for p in profiles:
        by_name.setdefault(str(p.get("name") or "").strip().lower(), []).append(p)
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for d in reg:
        groups.setdefault(((d["profile"] or "").strip().lower(), d["platform"]), []).append(d)
    rows = []
    for (name, plat), ds in groups.items():
        p = by_key.get(_profile_key(name, plat))
        if p is None and len(by_name.get(name, [])) == 1:
            p = by_name[name][0]
        svc = _svc_counts(ds, service_read)
        rows.append({"name": ds[0]["profile"] or NO_PROFILE, "platform": plat, "devices": len(ds), "matched": p is not None,
                     "forwarding_profile": (p or {}).get("forwarding_profile") if p else None,
                     "score": (p or {}).get("score") if p else None, "seen_24h": sum(1 for d in ds if is_recent(d)),
                     "ghosts": sum(1 for d in ds if is_ghost(d)), "services": svc, "below_fleet": _below(svc, fleet)})
    rows.sort(key=lambda r: (-r["devices"], r["name"].lower(), r["platform"]))
    fwd: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        key = r["forwarding_profile"] if r["matched"] and r["forwarding_profile"] else ("" if r["matched"] else None)
        label = key if key else ("(no forwarding profile linked)" if key == "" else "(not known: app profile not read)")
        g = fwd.setdefault(label, {"name": label, "known": key is not None and key != "", "app_profiles": 0, "devices": 0,
                                   "seen_24h": 0, "services": _svc_counts([], service_read)})
        g["app_profiles"] += 1
        g["devices"] += r["devices"]
        g["seen_24h"] += r["seen_24h"]
        _add_counts(g["services"], r["services"], service_read)
    frows = sorted(fwd.values(), key=lambda g: (not g["known"], -g["devices"], g["name"].lower()))
    for g in frows:
        g["below_fleet"] = _below(g["services"], fleet)
    return {"app_profiles": rows[:MAX_PROFILE_ROWS], "truncated": len(rows) > MAX_PROFILE_ROWS, "forwarding_profiles": frows[:MAX_PROFILE_ROWS],
            "config_read": bool(profiles), "fleet": fleet, "service_read": service_read, "definition": PROFILE_HEALTH_DEFINITION}


def last_seen_bucket(dev: Dict[str, Any]) -> str:
    s = dev.get("seconds_since_seen")
    if s is None:
        return "never"
    for key, _label, low, high in LAST_SEEN_BUCKETS:
        if (low is None or s > low * 86400) and (high is None or s <= high * 86400):
            return key
    return "over_30d"


def last_seen_histogram(devs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Registered devices by how long before the read they were last seen
    (LAST_SEEN_DEFINITION), overall and per platform. Pure."""
    reg = [d for d in devs if d["registration"] == "registered"]
    keys = [b[0] for b in LAST_SEEN_BUCKETS] + ["never"]
    labels = {b[0]: b[1] for b in LAST_SEEN_BUCKETS}
    labels["never"] = "Never seen"
    counts = {k: 0 for k in keys}
    per: Dict[str, Dict[str, int]] = {}
    for d in reg:
        b = last_seen_bucket(d)
        counts[b] += 1
        per.setdefault(d["platform"], {k: 0 for k in keys})[b] += 1
    n = len(reg)
    return {"buckets": [{"key": k, "label": labels[k], "devices": counts[k], "percent": round(100.0 * counts[k] / n, 1) if n else None}
                        for k in keys],
            "by_platform": dict(sorted(per.items(), key=lambda kv: -sum(kv[1].values()))), "registered": n, "definition": LAST_SEEN_DEFINITION}


# ── sites: grouping by host name (no free regex: a prefix, a delimiter or a pick list) ──
_SITE_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def site_rule(raw: Any) -> Dict[str, Any]:
    """The operator's site grouping, checked: {"mode": "none"} (off);
    {"mode": "prefix", "length": 1-12} (the first characters of the host
    name); {"mode": "delimiter", "delimiter": "-", "_" or ".", "segments":
    1-4} (the host name up to that many delimiters); {"mode": "list",
    "prefixes": [...]} (up to 200 prefixes of letters, digits, '.', '_' and
    '-', the longest that starts the host name wins; none is Other). Raises
    ValueError with a plain reason. Never a regular expression: an
    operator's pattern could hang the server (CWE-1333)."""
    r = raw if isinstance(raw, dict) else {}
    mode = str(r.get("mode") or "none").strip().lower()
    if mode in ("", "none", "off"):
        return {"mode": "none"}

    def _int(key: str, lo: int, hi: int, default: int) -> int:
        v = r.get(key, default)
        if isinstance(v, bool):
            raise ValueError(f"{key} must be a whole number from {lo} to {hi}.")
        try:
            n = int(str(v).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a whole number from {lo} to {hi}.")
        if not lo <= n <= hi:
            raise ValueError(f"{key} must be a whole number from {lo} to {hi}.")
        return n
    if mode == "prefix":
        return {"mode": "prefix", "length": _int("length", 1, SITE_MAX_LENGTH, 2)}
    if mode == "delimiter":
        d = str(r.get("delimiter") or "-")
        if d not in SITE_DELIMITERS:
            raise ValueError(f"The delimiter must be one of {' '.join(SITE_DELIMITERS)}.")
        return {"mode": "delimiter", "delimiter": d, "segments": _int("segments", 1, SITE_MAX_SEGMENTS, 1)}
    if mode == "list":
        raw_list = r.get("prefixes")
        items = re.split(r"[\s,;]+", raw_list) if isinstance(raw_list, str) else list(raw_list or []) if isinstance(raw_list, (list, tuple)) else []
        out: List[str] = []
        for x in items:
            x = str(x).strip()
            if not x:
                continue
            if not _SITE_PREFIX_RE.fullmatch(x):
                raise ValueError("Each site prefix is 1 to 32 letters, digits, '.', '_' or '-', starting with a letter or digit.")
            if x.upper() not in (o.upper() for o in out):
                out.append(x)
            if len(out) > SITE_MAX_PREFIXES:
                raise ValueError(f"At most {SITE_MAX_PREFIXES} site prefixes.")
        if not out:
            raise ValueError("List at least one site prefix, separated by commas or spaces.")
        return {"mode": "list", "prefixes": out}
    raise ValueError("Grouping must be none, prefix, delimiter or list.")


def describe_site_rule(rule: Dict[str, Any]) -> str:
    m = rule.get("mode")
    if m == "prefix":
        return f"the first {rule['length']} character{'s' if rule['length'] != 1 else ''} of the host name"
    if m == "delimiter":
        return (f"the host name up to its {'first' if rule['segments'] == 1 else 'number ' + str(rule['segments'])} "
                f"'{rule['delimiter']}'")
    if m == "list":
        return f"the longest of {len(rule['prefixes'])} listed prefixes that starts the host name (none: {OTHER_SITE})"
    return "no grouping"


def site_of(hostname: Any, rule: Dict[str, Any]) -> str:
    h = str(hostname or "").strip()
    m = rule.get("mode")
    if not h or m in (None, "none"):
        return NO_SITE
    if m == "prefix":
        return h[:rule["length"]].upper() if len(h) >= rule["length"] else NO_SITE
    if m == "delimiter":
        parts = h.split(rule["delimiter"])
        if len(parts) <= rule["segments"] or not all(parts[:rule["segments"]]):
            return NO_SITE
        return rule["delimiter"].join(parts[:rule["segments"]]).upper()
    if m == "list":
        hu = h.upper()
        best = max((p for p in rule["prefixes"] if hu.startswith(p.upper())), key=len, default=None)
        return best.upper() if best else OTHER_SITE
    return NO_SITE


def site_groups(devs: List[Dict[str, Any]], rule: Dict[str, Any], service_read: bool, *, counts_only: bool = False,
                kept_of: Optional[int] = None) -> Dict[str, Any]:
    """Devices per site (site_of), with registered, seen in 24 hours,
    ghosts, quarantined, each service's active share and the versions in
    use. counts_only merges the sites with fewer than SITE_MIN_COUNTS_ONLY
    registered devices into one row, so a short site name cannot single
    out a device. `kept_of` is the fleet's size when `devs` are only the
    devices kept for the page. Pure."""
    rule = site_rule(rule)   # idempotent on a checked rule; raises ValueError on anything else
    out: Dict[str, Any] = {"rule": rule, "rule_text": describe_site_rule(rule), "groups": [], "truncated": False, "counts_only": counts_only,
                           "counted": len(devs), "of": kept_of if kept_of is not None else len(devs)}
    if rule["mode"] == "none":
        return out
    fleet = _svc_counts([d for d in devs if d["registration"] == "registered"], service_read)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for d in devs:
        groups.setdefault(site_of(d.get("hostname"), rule), []).append(d)

    def row(name: str, ds: List[Dict[str, Any]]) -> Dict[str, Any]:
        reg = [d for d in ds if d["registration"] == "registered"]
        svc = _svc_counts(reg, service_read)
        vers: Dict[str, int] = {}
        for d in reg:
            if d["version"]:
                vers[d["version"]] = vers.get(d["version"], 0) + 1
        top = max(vers.items(), key=lambda kv: (kv[1], version_tuple(kv[0])), default=(None, 0))[0]
        return {"site": name, "devices": len(ds), "registered": len(reg), "seen_24h": sum(1 for d in reg if is_recent(d)),
                "ghosts": sum(1 for d in reg if is_ghost(d)), "quarantined": sum(1 for d in ds if d["registration"] == "quarantined"),
                "versions": len(vers), "top_version": top, "services": svc, "below_fleet": _below(svc, fleet)}
    small: List[Dict[str, Any]] = []
    rows = []
    for name, ds in groups.items():
        if counts_only and sum(1 for d in ds if d["registration"] == "registered") < SITE_MIN_COUNTS_ONLY:
            small.extend(ds)
            continue
        rows.append(row(name, ds))
    rows.sort(key=lambda r: (r["site"] in (NO_SITE, OTHER_SITE), -r["registered"], -r["devices"], r["site"]))
    if len(rows) > MAX_SITES:
        rest = [d for r in rows[MAX_SITES:] for d in groups[r["site"]]]
        rows = rows[:MAX_SITES] + [row(f"(the other {len(rows) - MAX_SITES} sites)", rest)]
        out["truncated"] = True
    if small:
        rows.append(row(SMALL_SITES, small))
    out["groups"] = rows
    return out


# ── analysis: profiles ───────────────────────────────────────────────
_SECRET_KEY = re.compile(r"password|passwd|passcode|passphrase|secret|otp|token|apikey|api_key|private_?key|pre_?shared_?key|psk|"
                         r"cert(ificate)?data", re.I)
# The Client Connector's own short spellings of its passwords: exitPass,
# uninstallPass, zpaDisablePass, zdSettingsAccessPass (zcc/models/
# secrets_passwords.py); "bypass" is not one.
_PASS_SUFFIX = re.compile(r"(?:^pass|(?<![A-Za-z])pass|[a-z0-9_]Pass)$")


def is_secret_key(key: Any) -> bool:
    """True for a setting whose name says it holds a password, passcode,
    pre-shared key, private key, OTP or token (its value is never shown)."""
    k = str(key)
    return bool(_SECRET_KEY.search(k) or _PASS_SUFFIX.search(k))
_PRIVATE_CIDR = re.compile(r"^(10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16|100\.64\.0\.0/10|169\.254\.0\.0/16|127\.0\.0\.0/8|224\.0\.0\.0/4|fc00::/7|fe80::/10)$", re.I)


def _mask_value(v: Any) -> str:
    return v if v in ("(set)", "(not set)") else "(set)" if str(v if v is not None else "").strip() else "(not set)"


def mask_settings(obj: Any) -> Any:
    """A copy of a profile with every password, secret, OTP or token value
    replaced by "(set)" or "(not set)": the drift view shows whether it is
    set, never the value."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if is_secret_key(k) and not isinstance(v, (dict, list)):
                out[k] = _mask_value(v)
            elif is_secret_key(k) and isinstance(v, list):
                out[k] = [mask_settings(x) if isinstance(x, (dict, list)) else _mask_value(x) for x in v]
            else:
                out[k] = mask_settings(v)
        return out
    if isinstance(obj, list):
        return [mask_settings(x) for x in obj]
    return obj


def flat_settings(profile: Dict[str, Any]) -> Dict[str, str]:
    """A profile's settings as {dotted key: compact JSON value}, secrets
    masked, for the side-by-side drift view."""
    flat: Dict[str, str] = {}

    def walk(prefix: str, v: Any) -> None:
        if isinstance(v, dict) and v:
            for k in sorted(v, key=str):
                walk(f"{prefix}.{k}" if prefix else str(k), v[k])
        else:
            flat[prefix] = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    walk("", mask_settings(flatten_profile(profile)))
    return flat


def diff_profiles(a: Dict[str, Any], b: Dict[str, Any], *, a_name: str = "A", b_name: str = "B") -> Dict[str, Any]:
    """Side-by-side settings of two profiles (every key, `same` per row) and
    the unified diff of their masked JSON."""
    fa, fb = flat_settings(a), flat_settings(b)
    rows = []
    for k in sorted(set(fa) | set(fb)):
        va, vb = fa.get(k), fb.get(k)
        rows.append({"key": k, "a": va, "b": vb, "same": va == vb})
    ja = json.dumps(mask_settings(a), indent=2, sort_keys=True, default=str).splitlines()
    jb = json.dumps(mask_settings(b), indent=2, sort_keys=True, default=str).splitlines()
    unified = "\n".join(difflib.unified_diff(ja, jb, fromfile=a_name, tofile=b_name, lineterm="", n=2))
    return {"a": a_name, "b": b_name, "rows": rows, "differences": sum(1 for r in rows if not r["same"]), "unified": unified[:200000]}


def _pac_norm(url: Any) -> str:
    s = re.sub(r"^[a-z]+://", "", str(url or "").strip().lower())
    return s.split("?", 1)[0].rstrip("/")


def analyze_pacs(raw_pacs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each hosted PAC file through the Log analyzer's PAC parser: its
    DIRECT entries with their risk, its default, its findings' titles."""
    import log_analyzer
    out = []
    for f in raw_pacs:
        content = str(_v(f, "pacContent", "content", "pacScript", default="") or "")
        name = str(f.get("name") or f.get("id") or "PAC file")
        url = _v(f, "pacUrl", "pacUrlObfuscated", "url", default="")
        rec: Dict[str, Any] = {"id": f.get("id"), "name": name, "url": str(url or ""), "has_content": bool(content)}
        if content:
            a = log_analyzer.analyze_pac(name, content[:2_000_000])
            summ = a.get("summary") or {}
            rec.update({"default": summ.get("default", "none"),
                        "direct": [{"kind": b["kind"], "value": b["value"], "risk": b["risk"]} for b in summ.get("bypasses") or []],
                        "findings": [{"severity": x["severity"], "title": x["title"]} for x in a.get("findings") or []]})
        else:
            rec.update({"default": None, "direct": [], "findings": []})
        out.append(rec)
    return out


def _match_pac(url: Any, pacs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    n = _pac_norm(url)
    if not n:
        return None
    for p in pacs:
        if p["url"] and _pac_norm(p["url"]) == n:
            return p
    tail = n.rsplit("/", 1)[-1]
    hits = [p for p in pacs if p["url"] and _pac_norm(p["url"]).rsplit("/", 1)[-1] == tail]
    hits = hits or [p for p in pacs if str(p["name"]).strip().lower() == tail]
    return hits[0] if len(hits) == 1 else None


def _profile_pac_sources(app: Dict[str, Any], fwd: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    src = []
    if app.get("pac_url"):
        src.append({"where": "App profile", "url": str(app["pac_url"])})
    if fwd:
        if fwd.get("pac_url"):
            src.append({"where": "Forwarding profile", "url": str(fwd["pac_url"])})
        for net, a in (fwd.get("actions") or {}).items():
            if a.get("pac_url"):
                src.append({"where": f"Forwarding profile ({net} network)", "url": str(a["pac_url"])})
    seen, out = set(), []
    for s in src:
        if s["url"] not in seen:
            seen.add(s["url"])
            out.append(s)
    return out


def _check(status: str, detail: str) -> Dict[str, str]:
    return {"status": status, "detail": detail}


def profile_checks(app: Dict[str, Any], raw: Dict[str, Any], fwd: Optional[Dict[str, Any]], fwd_read: bool,
                   pacs: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, str]], List[Dict[str, Any]]]:
    """Every heatmap check for one app profile (pass / warn / fail /
    unknown / n/a with the reason) and the PAC files it uses."""
    c: Dict[str, Dict[str, str]] = {}
    plat = str(app.get("platform") or "").lower()
    flat = flatten_profile(raw) if raw else {}
    # forwarding
    if not fwd_read:
        c["forwarding_linked"] = _check("unknown", "The forwarding profiles could not be read.")
    elif fwd is None:
        c["forwarding_linked"] = _check("fail", "No forwarding profile is linked, or the one named does not exist."
                                        if app.get("forwarding_profile") is None else f"The linked forwarding profile ({app.get('forwarding_profile')}) was not found.")
    else:
        c["forwarding_linked"] = _check("pass", f"Linked to {fwd.get('name')}.")
    acts = (fwd or {}).get("actions") or {}
    off = acts.get("off") or acts.get("any") or {}
    on = acts.get("on") or acts.get("any") or {}
    if fwd is None:
        c["off_network_tunnel"] = _check("unknown", "No linked forwarding profile to read.")
        c["on_network_forwarding"] = _check("unknown", "No linked forwarding profile to read.")
    else:
        if not off:
            c["off_network_tunnel"] = _check("unknown", "The forwarding profile names no off-trusted-network action.")
        elif off.get("mode_kind") in ("none", "pac"):
            c["off_network_tunnel"] = _check("fail", f"Off the trusted network: {off.get('mode_label')}.")
        elif off.get("mode_label") == "Z-Tunnel 1.0":
            c["off_network_tunnel"] = _check("warn", "Off the trusted network: Z-Tunnel 1.0 (web ports only).")
        else:
            c["off_network_tunnel"] = _check("pass", f"Off the trusted network: {off.get('mode_label')}.")
        if not on:
            c["on_network_forwarding"] = _check("unknown", "The forwarding profile names no on-trusted-network action.")
        elif on.get("mode_kind") == "none":
            c["on_network_forwarding"] = _check("warn", "On the trusted network: None (fine only behind a GRE or IPsec tunnel).")
        else:
            c["on_network_forwarding"] = _check("pass", f"On the trusted network: {on.get('mode_label')}.")
    # app profile switches
    se = _v(flat, "strictEnforcement", "strictMode")
    c["strict_enforcement"] = _check("unknown", "The API did not return the setting.") if se is None else (
        _check("pass", "On.") if _truthy(se) else _check("fail", "Off: a user can use the internet without signing in."))
    if plat not in ("windows", "all", ""):
        c["anti_tampering"] = _check("n/a", "Anti-tampering is a Windows setting.")
    else:
        at = _v(flat, "enableAntiTampering", "antiTampering")
        c["anti_tampering"] = _check("unknown", "The API did not return the setting.") if at is None else (
            _check("pass", "On.") if _truthy(at) else _check("fail", "Off: the user can stop the service."))
    # Key presence, not _v (which reads an empty string as absent): an
    # empty password field is "not set", a missing one is "not returned".
    keyed = {re.sub(r"[^a-z0-9]", "", str(k).lower()): v for k, v in flat.items()}
    pw_keys = {"uninstallpassword": "uninstall", "disablepassword": "ZIA disable"}
    if not any(k in keyed for k in pw_keys):
        c["tamper_passwords"] = _check("unknown", "The API returned no password fields for this profile.")
    else:
        missing = [lbl for k, lbl in pw_keys.items() if not str(keyed.get(k) or "").strip()]
        c["tamper_passwords"] = _check("fail", f"No {' or '.join(missing)} password.") if missing else _check("pass", "Both are set.")
    ssl = _v(flat, "sslCertInstall", "installSslCert", "sslCertificateEnabled", "installCertificate", "installZscalerSslCertificate")
    c["ssl_cert"] = _check("unknown", "The API did not return the setting.") if ssl is None else (
        _check("pass", "Installed by the profile.") if _truthy(ssl) else _check("fail", "Not installed by the profile."))
    # bypasses
    import log_analyzer
    by = app.get("bypass") or {}
    domains = [str(x).strip() for x in by.get("domains") or [] if str(x).strip()]
    excl = _v(flat, "packetTunnelExcludeList", default="") or ""
    ips = [str(x).strip() for x in by.get("ips") or [] if str(x).strip()]
    ips += [x.strip() for x in (excl.split(",") if isinstance(excl, str) else excl) if str(x).strip()]
    broad_dom = [d for d in domains if d in ("*", "*.*") or log_analyzer._BROAD.match(d)]
    broad_ip = [x for x in ips if re.search(r"/([0-9]|1[0-5])$|^0\.0\.0\.0", x) and not _PRIVATE_CIDR.match(x)]
    total = len(domains) + len(ips)
    if broad_dom or broad_ip:
        c["bypass_breadth"] = _check("fail", "Broad: " + ", ".join((broad_dom + broad_ip)[:6]) + ".")
    elif total > MANY_BYPASSES:
        c["bypass_breadth"] = _check("warn", f"{total} destination bypasses and exclusions.")
    else:
        c["bypass_breadth"] = _check("pass", f"{total} destination bypass(es) and exclusion(s), none broad.")
    apps = by.get("apps") or []
    c["app_bypass"] = _check("warn", f"{len(apps)} application bypasses.") if len(apps) > MANY_APP_BYPASSES else _check("pass", f"{len(apps)} application bypass(es).")
    # PAC
    sources = _profile_pac_sources(app, fwd)
    used = []
    for s in sources:
        p = _match_pac(s["url"], pacs)
        used.append(dict(s, file=(p or {}).get("name"), hosted=bool(p and p.get("has_content"))))
    if not sources:
        c["pac_direct"] = _check("pass", "The profile uses no PAC file.")
    else:
        risky, default_direct, unread = [], False, []
        for u in used:
            p = _match_pac(u["url"], pacs)
            if not p or not p.get("has_content"):
                unread.append(u["where"])
                continue
            risky += [f"{b['value']} ({b['risk']})" for b in p.get("direct") or [] if b["risk"] in ("data-channel", "broad", "public-range")]
            default_direct = default_direct or p.get("default") == "direct"
        if risky:
            c["pac_direct"] = _check("fail", "DIRECT: " + ", ".join(sorted(set(risky))[:6]) + ".")
        elif unread and len(unread) == len(used):
            c["pac_direct"] = _check("unknown", "The PAC file is not hosted in ZIA, so its content could not be read: review it with the Log analyzer.")
        elif default_direct:
            c["pac_direct"] = _check("warn", "The PAC's default answer is DIRECT (expected only for a bypass PAC used with the tunnel).")
        else:
            c["pac_direct"] = _check("pass", "No risky DIRECT statement.")
    if plat in ("windows", "macos"):
        c["endpoint_dlp"] = _check("pass", "Installed.") if app.get("endpoint_dlp") else (
            _check("warn", "Not installed.") if _v(flat, "installEndpointDlp", "endpointDlpEnabled", "zdpEnabled") is not None else
            _check("unknown", "The API did not return the setting."))
    else:
        c["endpoint_dlp"] = _check("n/a", "Endpoint DLP runs on Windows and macOS.")
    return c, used


def _score(checks: Dict[str, Dict[str, str]]) -> Optional[float]:
    vals = [_STATUS_SCORE[v["status"]] for v in checks.values() if v["status"] in _STATUS_SCORE]
    return round(100.0 * sum(vals) / len(vals), 1) if vals else None


def _fwd_for(app: Dict[str, Any], fwds: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    ref = app.get("forwarding_profile")
    if ref is None or ref == "":
        return None
    for f in fwds:
        if str(f.get("id")) == str(ref) or str(f.get("name") or "").strip().lower() == str(ref).strip().lower():
            return f
    return None


def _raw_for(app: Dict[str, Any], raws: List[Dict[str, Any]]) -> Dict[str, Any]:
    for r in raws:
        if app.get("id") is not None and str(r.get("id")) == str(app.get("id")):
            return r
    for r in raws:
        if str(_v(flatten_profile(r), "name", "policyName", default="")).strip() == str(app.get("name") or "").strip():
            return r
    return {}


def _profile_key(name: Any, platform: Any) -> str:
    return f"{str(name or '').strip().lower()}|{str(platform or '').strip().lower()}"


# ── the whole analysis ───────────────────────────────────────────────
def analyze(cfg: Dict[str, Any], telemetry: Dict[str, Any], *, now: Optional[datetime] = None,
            site: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fleet KPIs, alerts, the profile heatmap and scores, PAC comparison,
    the ranked remediation plan, the version x service matrix, health per
    app and forwarding profile, the last-seen histogram and the site groups
    (`site`: a site_rule; none by default) from what was read. Pure."""
    now = now or datetime.now(timezone.utc)
    site = site_rule(site or {"mode": "none"})
    rs = cfg.get("read_status") or {}
    fwd_read = rs.get("forwarding_profiles") == "read"
    fwds = cfg.get("forwarding_profiles") or []
    pacs = analyze_pacs(cfg.get("raw_pac_files") or [])
    tel_status = telemetry.get("status") or "unavailable"
    service = telemetry.get("service") or {}
    service_read = tel_status == "read" and service.get("status") == "read"
    devs = normalize_devices(telemetry.get("devices") or [], service.get("rows") or [], now) if tel_status in ("read", "partial") else []
    have_devices = tel_status in ("read", "partial")

    # devices per profile (registered only), by name and platform, else name
    reg = [d for d in devs if d["registration"] == "registered"]
    counts_np: Dict[str, int] = {}
    counts_n: Dict[str, int] = {}
    for d in reg:
        counts_np[_profile_key(d["profile"], d["platform"])] = counts_np.get(_profile_key(d["profile"], d["platform"]), 0) + 1
        counts_n[d["profile"].strip().lower()] = counts_n.get(d["profile"].strip().lower(), 0) + 1
    names_seen = {str(a.get("name") or "").strip().lower() for a in cfg.get("app_profiles") or []}

    profiles = []
    raws = cfg.get("raw_app_profiles") or []
    name_platforms: Dict[str, int] = {}
    for a in cfg.get("app_profiles") or []:
        n = str(a.get("name") or "").strip().lower()
        name_platforms[n] = name_platforms.get(n, 0) + 1
    for i, a in enumerate(cfg.get("app_profiles") or []):
        raw = _raw_for(a, raws)
        fwd = _fwd_for(a, fwds)
        checks, pac_used = profile_checks(a, raw, fwd, fwd_read, pacs)
        n = str(a.get("name") or "").strip().lower()
        dcount: Optional[int] = None
        if have_devices:
            dcount = counts_np.get(_profile_key(a.get("name"), a.get("platform")), 0)
            if not dcount and name_platforms.get(n, 0) == 1:
                dcount = counts_n.get(n, 0)
        profiles.append({"pid": f"p{i + 1}", "id": a.get("id"), "name": a.get("name"), "platform": a.get("platform"),
                         "active": a.get("active", True), "forwarding_profile": (fwd or {}).get("name"),
                         "devices": dcount, "checks": checks, "score": _score(checks), "pac": pac_used})
    active = [p for p in profiles if p["active"]]
    scored = [p for p in active if p["score"] is not None]
    equal = round(sum(p["score"] for p in scored) / len(scored), 1) if scored else None
    weighted = exposure = None
    if have_devices:
        w = [(p["score"], p["devices"]) for p in scored if p["devices"]]
        tot = sum(n for _, n in w)
        if tot:
            weighted = round(sum(s * n for s, n in w) / tot, 1)
            exposure = round(100.0 - weighted, 1)
    unmatched = sorted({d["profile"] for d in reg if d["profile"] and d["profile"].strip().lower() not in names_seen})

    alerts = device_alerts(devs, service_read) if have_devices else {
        k: dict(v, key=k, evaluated=False, why_not="Not evaluated: no enrolled devices could be read.", count=None, rows=[], truncated=False)
        for k, v in ALERTS.items()}
    kpis = fleet_kpis(devs, service_read) if have_devices else None

    pac_matrix = pac_comparison(profiles, pacs)
    plan = remediation_plan(profiles, alerts, have_devices)
    mode = "full" if service_read else ("devices" if have_devices else "configuration")
    banner = {
        "full": "Configuration and device telemetry (device list and per-device service status).",
        "devices": "Configuration and the device list. The per-device service status could not be read, so ZIA, ZPA and ZDX activity, "
                   "blind spots and bypass risk are not shown (not zero: unknown). " + (service.get("reason") or ""),
        "configuration": "Configuration only. No enrolled devices could be read, so no device figure is shown (not zero: unknown) and the "
                         "profiles are scored without device weights. " + (telemetry.get("reason") or ""),
    }[mode].strip()
    return {
        "mode": mode, "banner": banner, "telemetry": {"status": tel_status, "reason": telemetry.get("reason") or "",
                                                       "service_status": service.get("status") or "unavailable",
                                                       "service_reason": service.get("reason") or "",
                                                       "service_columns": {k: v for k, v in (service.get("columns") or {}).items() if k in SERVICES},
                                                       "service_values": service_values_seen(devs)},
        "read_at": now.isoformat(), "kpis": kpis, "alerts": alerts,
        "alert_order": ["blind_spot", "bypass_risk", "unsupported_version", "registration_anomaly", "old_version", "ghost", "version_drift", "multi_device"],
        "checks": [{k: c[k] for k in ("key", "label", "definition", "impact")} for c in CHECKS],
        "profiles": profiles,
        "scores": {"equal_weight": equal, "device_weighted": weighted, "device_weighted_exposure": exposure, "profiles_scored": len(scored),
                   "note": "Equal weight: the mean of the active profiles' scores. Device weighted: each profile's score weighted by the "
                           "registered devices on it" + ("" if have_devices else " (not available without device telemetry)") + ". "
                           "A check scores 1 for pass, 0.5 for a warning, 0 for a failure; unknown and not applicable are left out."},
        "unmatched_profiles": unmatched[:50],
        "pac": {"files": [{k: p[k] for k in ("name", "url", "has_content", "default")} | {"direct": len(p["direct"]),
                           "risky": sum(1 for b in p["direct"] if b["risk"] in ("data-channel", "broad", "public-range"))} for p in pacs],
                "matrix": pac_matrix},
        "plan": plan,
        "devices": devs[:MAX_RESULT_DEVICES], "devices_total": len(devs), "devices_truncated": len(devs) > MAX_RESULT_DEVICES,
        "errors": [_clean_reason(e) for e in cfg.get("errors") or []][:20],
        "profile_settings_ids": {p["pid"]: p["name"] for p in profiles},
        "definitions": {"seen_recent_hours": SEEN_RECENT_HOURS, "ghost_days": GHOST_DAYS, "multi_device_threshold": MULTI_DEVICE_THRESHOLD,
                        "old_minor_releases": OLD_MINOR_RELEASES, "below_fleet_points": BELOW_FLEET_POINTS,
                        "below_fleet_min_known": BELOW_FLEET_MIN_KNOWN, "site_min_counts_only": SITE_MIN_COUNTS_ONLY},
        "source": "live", "service_read": service_read,
        "version_health": version_health(devs, service_read) if have_devices else None,
        "profile_health": profile_health(devs, service_read, profiles) if have_devices else None,
        "last_seen": last_seen_histogram(devs) if have_devices else None,
        "sites": site_groups(devs, site, service_read) if have_devices else None,
    }


def pac_comparison(profiles: List[Dict[str, Any]], pacs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """DIRECT entries (rows) × profiles with a readable PAC (columns):
    which profile sends what DIRECT, risky entries first."""
    cols = []
    entries: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for p in profiles:
        files = []
        for u in p.get("pac") or []:
            f = _match_pac(u["url"], pacs)
            if f and f.get("has_content"):
                files.append(f)
        if not files:
            continue
        cols.append({"pid": p["pid"], "name": p["name"], "platform": p["platform"], "files": sorted({f["name"] for f in files}),
                     "default": "direct" if any(f.get("default") == "direct" for f in files) else (files[0].get("default") or "none")})
        for f in files:
            for b in f.get("direct") or []:
                k = (b["kind"], b["value"])
                e = entries.setdefault(k, {"kind": b["kind"], "value": b["value"], "risk": b["risk"], "profiles": []})
                if p["pid"] not in e["profiles"]:
                    e["profiles"].append(p["pid"])
    order = {"data-channel": 0, "public-range": 1, "broad": 2, "ok": 3}
    rows = sorted(entries.values(), key=lambda e: (order.get(e["risk"], 9), -len(e["profiles"]), e["value"]))
    for e in rows:
        e["everywhere"] = len(e["profiles"]) == len(cols)
    return {"columns": cols, "rows": rows[:300], "truncated": len(rows) > 300,
            "differing": sum(1 for e in rows if not e["everywhere"]),
            "risky": sum(1 for e in rows if e["risk"] in ("data-channel", "broad", "public-range"))}


def remediation_plan(profiles: List[Dict[str, Any]], alerts: Dict[str, Dict[str, Any]], have_devices: bool) -> List[Dict[str, Any]]:
    """Every failing profile check and every non-empty fleet alert, ranked
    by impact × devices (impact 1-3, halved for a warning; devices = the
    registered devices on the profile or in the alert, at least 1). Without
    device telemetry the rank is by impact alone and says so."""
    items = []
    for p in profiles:
        if not p["active"]:
            continue
        for key, res in p["checks"].items():
            if res["status"] not in _SEVERITY_FACTOR:
                continue
            c = CHECK_BY_KEY[key]
            impact = c["impact"] * _SEVERITY_FACTOR[res["status"]]
            devs = p["devices"]
            items.append({"kind": "profile", "title": f"{c['label']}: {p['name']} ({p['platform']})", "check": key,
                          "where": f"App profile {p['name']} ({p['platform']})", "status": res["status"], "detail": res["detail"],
                          "impact": impact, "devices": devs, "priority": round(impact * max(1, devs or 0), 2) if have_devices else impact,
                          "fix": c["fix"]})
    for key, a in alerts.items():
        if not a.get("evaluated") or not a.get("count"):
            continue
        n = a["count"]
        items.append({"kind": "fleet", "title": f"{a['label']}: {n} {'user' if key == 'multi_device' else 'device'}{'' if n == 1 else 's'}",
                      "check": key, "where": "Enrolled devices", "status": "fail" if a["impact"] >= 2 else "warn",
                      "detail": a["definition"], "impact": a["impact"], "devices": n, "priority": round(a["impact"] * max(1, n), 2),
                      "fix": a["fix"]})
    items.sort(key=lambda x: (-x["priority"], -x["impact"], x["title"]))
    for i, x in enumerate(items, 1):
        x["rank"] = i
        x["device_count_known"] = have_devices
    return items


# ── the run ───────────────────────────────────────────────────────────
def run(client: Any, sdk: Any, *, log: Callable[[str], None], cancel: Any, label: str = "", sdk_reason: str = "",
        now: Optional[datetime] = None, site: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read, then analyse. Stop ends the run as stopped with no partial
    result. `sdk` None means no device telemetry (`sdk_reason` says why)."""
    try:
        cfg = read_configuration(client, log=log, cancel=cancel)
        if sdk is None:
            telemetry = {"status": "unavailable", "reason": sdk_reason or "No Client Connector API client for the devices.", "devices": [],
                         "service": {"status": "unavailable", "reason": "", "rows": []}}
            log("Enrolled devices are not read with this sign-in; the fleet view falls back to configuration only.")
        else:
            telemetry = read_devices(sdk, log=log, cancel=cancel)
        _stop(cancel)
    except Stopped:
        log("STOPPED — you clicked Stop; nothing more is read and no partial result is kept.")
        return {"stopped": STOPPED_REASON, "status": "stopped", "tenant_label": label}
    log("Analysing the fleet…")
    out = analyze(cfg, telemetry, now=now, site=site)
    # Kept for the drift view; masked, never logged.
    out["profile_settings"] = {p["pid"]: mask_settings(_raw_for(a, cfg.get("raw_app_profiles") or []))
                               for p, a in zip(out["profiles"], cfg.get("app_profiles") or [])}
    k = out.get("kpis") or {}
    log("Done: " + (f"{k.get('devices', 0)} device record(s), {k.get('registered', 0)} registered; " if k else "configuration only; ")
        + f"{len(out['profiles'])} app profile(s); {len(out['plan'])} remediation item(s).")
    out["status"] = "done"
    out["tenant_label"] = label
    return out


def regroup_sites(result: Dict[str, Any], rule: Any) -> Dict[str, Any]:
    """Group a finished run's devices by site again with another rule (no
    tenant call) and keep it as the run's `sites`, which the exports use.
    Counted over the devices kept for the page; when the run kept fewer
    than it read, the answer says how many of how many."""
    if result.get("kpis") is None:
        raise ValueError("This run has no device list, so there is nothing to group by site.")
    devs = result.get("devices") or []
    out = site_groups(devs, site_rule(rule), bool(result.get("service_read")), kept_of=result.get("devices_total") or len(devs))
    result["sites"] = out
    return out


def diff_from_result(result: Dict[str, Any], a: str, b: str) -> Dict[str, Any]:
    """The drift view for two profiles of a finished run (their pids)."""
    settings = result.get("profile_settings") or {}
    names = {p["pid"]: f"{p['name']} ({p['platform']})" for p in result.get("profiles") or []}
    if a not in settings or b not in settings:
        raise KeyError("Choose two app profiles from this run.")
    return diff_profiles(settings[a], settings[b], a_name=names.get(a, a), b_name=names.get(b, b))


# ── fleet depth in the exports (Excel sheets and the PDF) ─────────────
def svc_text(v: Optional[Dict[str, Any]]) -> str:
    """One service cell: '87.5% (35 of 40)', or why there is no share."""
    if not v:
        return "not read"
    if v.get("percent") is None:
        return "not read" if v.get("known") else "no known status"
    return f"{v['percent']}% ({v['active']} of {v['known']})"


def _flag(row: Dict[str, Any], s: str) -> str:
    return " - below the fleet" if s in (row.get("below_fleet") or []) else ""


def version_rows(result: Dict[str, Any]) -> List[List[Any]]:
    vh = result.get("version_health") or {}
    out = []
    for r in vh.get("rows") or []:
        notes = [x for x, on in (("newest on the platform", r.get("newest")), ("unsupported", r.get("unsupported"))) if on]
        out.append([r["platform"], r["version"], r["devices"], "" if r.get("share") is None else r["share"], r["seen_24h"]]
                   + [svc_text(r["services"][s]) + _flag(r, s) for s in SERVICES] + ["; ".join(notes)])
    return out


VERSION_COLUMNS = ["Platform", "Client Connector version", "Registered devices", "% of platform", "Seen in 24 hours", "ZIA active",
                   "ZPA active", "ZDX active", "Note"]
PROFILE_COLUMNS = ["App profile", "Platform", "Registered devices", "Forwarding profile", "Profile score", "Seen in 24 hours",
                   "Ghosts", "ZIA active", "ZPA active", "ZDX active"]
FORWARDING_COLUMNS = ["Forwarding profile", "App profiles", "Registered devices", "Seen in 24 hours", "ZIA active", "ZPA active", "ZDX active"]
SITE_COLUMNS = ["Site", "Device records", "Registered", "Seen in 24 hours", "Ghosts", "Quarantined", "Versions", "Most common version",
                "ZIA active", "ZPA active", "ZDX active"]


def profile_rows(result: Dict[str, Any]) -> List[List[Any]]:
    ph = result.get("profile_health") or {}
    return [[r["name"], r["platform"], r["devices"],
             r["forwarding_profile"] or ("not linked" if r["matched"] else "not known"), "" if r.get("score") is None else r["score"],
             r["seen_24h"], r["ghosts"]] + [svc_text(r["services"][s]) + _flag(r, s) for s in SERVICES]
            for r in ph.get("app_profiles") or []]


def forwarding_rows(result: Dict[str, Any]) -> List[List[Any]]:
    ph = result.get("profile_health") or {}
    return [[g["name"], g["app_profiles"], g["devices"], g["seen_24h"]] + [svc_text(g["services"][s]) + _flag(g, s) for s in SERVICES]
            for g in ph.get("forwarding_profiles") or []]


def site_table(result: Dict[str, Any], counts_only: bool) -> Optional[Dict[str, Any]]:
    """The run's site groups for an export: counts_only merges the small
    sites (site_groups), so a short site name cannot single out a device.
    None when no grouping is chosen."""
    sites = result.get("sites") or {}
    rule = sites.get("rule") or {"mode": "none"}
    if rule.get("mode") in (None, "none") or result.get("kpis") is None:
        return None
    if counts_only and not sites.get("counts_only"):
        devs = result.get("devices") or []
        sites = site_groups(devs, rule, bool(result.get("service_read")), counts_only=True,
                            kept_of=result.get("devices_total") or len(devs))
    return sites


def site_rows(sites: Dict[str, Any]) -> List[List[Any]]:
    return [[g["site"], g["devices"], g["registered"], g["seen_24h"], g["ghosts"], g["quarantined"], g["versions"], g["top_version"] or ""]
            + [svc_text(g["services"][s]) + _flag(g, s) for s in SERVICES] for g in sites.get("groups") or []]


def _sites_note(sites: Dict[str, Any]) -> str:
    n = f"Grouped by {sites.get('rule_text')}."
    if sites.get("counted") is not None and sites.get("of") and sites["counted"] < sites["of"]:
        n += f" Counted over the first {sites['counted']} of {sites['of']} devices kept for the page."
    if sites.get("counts_only"):
        n += f" Sites with fewer than {SITE_MIN_COUNTS_ONLY} registered devices are counted together."
    return n


def history_rows(history: List[Dict[str, Any]]) -> List[List[Any]]:
    out = []
    for e in history:
        s = e.get("services") or {}
        out.append([e["at"], "CSV import" if e.get("source") == "import" else "Read from the tenant", e["devices"], e.get("registered"),
                    e.get("seen_24h"), e.get("never_seen"), e.get("quarantined")]
                   + [("" if not s.get(x) or s[x].get("percent") is None else s[x]["percent"]) for x in SERVICES]
                   + [(e.get("alerts") or {}).get(k) for k in ("blind_spot", "bypass_risk", "ghost", "unsupported_version")])
    return out


HISTORY_COLUMNS = ["Read at (UTC)", "Source", "Device records", "Registered", "Seen in 24 hours", "Never seen", "Quarantined",
                   "ZIA active %", "ZPA active %", "ZDX active %", "Blind spots", "Bypass risk", "Ghost devices", "Unsupported releases"]


def export_pdf(result: Dict[str, Any], history: Optional[List[Dict[str, Any]]] = None, page_size: str = "A4") -> Tuple[str, bytes]:
    """(filename stem, PDF bytes): the fleet page as a printable report.
    Counts only: no user, host name or device ID is ever in it (alerts are
    counted, sites with fewer than SITE_MIN_COUNTS_ONLY registered devices
    are counted together). Built with pdf_writer (WinAnsi text only)."""
    import pdf_writer
    label = str(result.get("tenant_label") or "tenant")
    doc = pdf_writer.PdfDocument(title=f"Client Connector fleet: {label}", page_size=page_size,
                                 footer=f"Zscaler Made Easy - Client Connector fleet - {label} - counts only",
                                 subject="Client Connector fleet health")
    doc.heading("Client Connector fleet")
    doc.paragraph(f"{label}. Read {str(result.get('read_at') or '')[:16].replace('T', ' ')} UTC. "
                  + ("Imported from the portal's CSV exports." if result.get("source") == "import" else "Read-only, from the tenant's API."),
                  size=9, grey=0.3)
    doc.paragraph(str(result.get("banner") or ""), size=9)
    doc.paragraph("Counts only: this report names no user and no device.", size=9, grey=0.3)
    k = result.get("kpis")
    doc.heading("The fleet at a glance", 2)
    if not k:
        doc.paragraph("No device figure: no enrolled devices could be read (unknown, not zero).")
    else:
        pairs = [("Device records", k["devices"]), ("Registered", k["registered"]), ("Seen in 24 hours", k["seen_24h"]),
                 ("Never seen", k["never_seen"]), ("Quarantined", k.get("quarantined", 0))]
        for s in SERVICES:
            v = (k.get("services") or {}).get(s) or {}
            pairs.append((f"{SERVICE_LABELS[s]} active", "not available" if v.get("percent") is None else f"{v['percent']}% ({v.get('note')})"))
        sc = result.get("scores") or {}
        pairs.append(("Score, equal weight", "not available" if sc.get("equal_weight") is None else sc["equal_weight"]))
        pairs.append(("Score, device weighted", "not available" if sc.get("device_weighted") is None else sc["device_weighted"]))
        doc.key_values(pairs)
    doc.heading("Alerts", 2)
    doc.table(["Alert", "Count", "Definition"],
              [[a.get("label", key), a["count"] if a.get("evaluated") else (a.get("why_not") or "not evaluated"), a.get("definition", "")]
               for key in result.get("alert_order") or [] for a in [(result.get("alerts") or {}).get(key) or {}]], widths=[2, 1.4, 7])
    if k:
        doc.heading("Service health by Client Connector version", 2)
        doc.paragraph(VERSION_HEALTH_DEFINITION, size=8, grey=0.3)
        rows = version_rows(result)
        if rows:
            doc.table(VERSION_COLUMNS, rows, widths=[1.2, 1.6, 1, 1, 1, 1.9, 1.9, 1.9, 1.6], size=7)
        else:
            doc.paragraph("No registered device.")
        ph = result.get("profile_health") or {}
        doc.heading("Health per app profile", 2)
        doc.paragraph(PROFILE_HEALTH_DEFINITION, size=8, grey=0.3)
        rows = profile_rows(result)
        if rows:
            doc.table(PROFILE_COLUMNS, rows, widths=[2, 1, 1, 1.6, 0.9, 1, 0.9, 1.8, 1.8, 1.8], size=7)
        else:
            doc.paragraph("No registered device.")
        if ph.get("forwarding_profiles"):
            doc.heading("Health per forwarding profile", 2)
            doc.table(FORWARDING_COLUMNS, forwarding_rows(result), widths=[2.4, 1, 1, 1, 1.9, 1.9, 1.9], size=7)
        ls = result.get("last_seen") or {}
        doc.heading("When devices were last seen", 2)
        doc.paragraph(LAST_SEEN_DEFINITION, size=8, grey=0.3)
        doc.table(["Last seen", "Registered devices", "% of registered"],
                  [[b["label"], b["devices"], "" if b["percent"] is None else b["percent"]] for b in ls.get("buckets") or []], widths=[3, 2, 2])
        sites = site_table(result, True)
        if sites:
            doc.heading("Sites", 2)
            doc.paragraph(_sites_note(sites), size=8, grey=0.3)
            doc.table(SITE_COLUMNS, site_rows(sites), widths=[1.6, 0.9, 0.9, 0.9, 0.8, 0.9, 0.8, 1.3, 1.7, 1.7, 1.7], size=7)
    if history:
        doc.heading("History", 2)
        doc.paragraph(f"{len(history)} saved snapshot{'s' if len(history) != 1 else ''} of this tenant's fleet, oldest first.", size=8, grey=0.3)
        doc.table(HISTORY_COLUMNS[:10], [r[:10] for r in history_rows(history)], size=6.5)
    plan = result.get("plan") or []
    doc.heading("Remediation plan", 2)
    if plan:
        doc.table(["Rank", "What", "Devices", "Fix"],
                  [[x["rank"], x["title"], "unknown" if x["devices"] is None else x["devices"], x["fix"]] for x in plan[:60]],
                  widths=[0.6, 3.4, 0.9, 5.2], size=7)
        if len(plan) > 60:
            doc.paragraph(f"The first 60 of {len(plan)} items; the Excel export has all of them.", size=8, grey=0.3)
    else:
        doc.paragraph("Nothing to fix was found.")
    return "zcc_fleet_report", doc.to_bytes()


# ── exports ───────────────────────────────────────────────────────────
def _csv_rows(text: str) -> List[List[str]]:
    return list(csv.reader(io.StringIO(text)))


def export_xlsx(result: Dict[str, Any], counts_only: bool, history: Optional[List[Dict[str, Any]]] = None) -> Tuple[str, bytes]:
    """(filename stem, workbook bytes): Summary, Versions, Version health,
    Profile health, Forwarding health, Last seen, Sites (when grouped),
    History (the tenant's saved snapshots, when given), Operating systems,
    Stale devices, Devices, Alerts and Plan, the figures the page shows.
    With counts_only no sheet names a user or a host: the stale devices are
    counted per platform and the device sheet says why it is empty. Built
    with xlsx_writer: no cell is ever a formula."""
    import xlsx_writer
    wb = xlsx_writer.Workbook(title="Client Connector fleet", subject=str(result.get("tenant_label") or ""), creator="Zscaler Made Easy")
    summary = _csv_rows(export_csv(result, "summary", True)[1])
    wb.add_sheet("Summary", columns=summary[0], rows=[[_num(c) for c in r] for r in summary[1:]])
    k = result.get("kpis")
    devs = result.get("devices") or []
    reg = [d for d in devs if d.get("registration") == "registered"]
    no_devices = "Not available: no enrolled devices could be read, so there is no device figure (unknown, not zero)."
    vs = wb.add_sheet("Versions", columns=["Platform", "Client Connector version", "Registered devices", "Newest seen on the platform"])
    if not k:
        vs.append([no_devices])
    else:
        for plat, versions in (k.get("versions") or {}).items():
            for v, n in versions.items():
                vs.append([plat, v, n, v == (k.get("newest") or {}).get(plat)])
        if not k.get("versions"):
            vs.append(["No registered device reports a Client Connector version."])
    if k:
        vh = wb.add_sheet("Version health", columns=VERSION_COLUMNS, rows=version_rows(result))
        vh.append([VERSION_HEALTH_DEFINITION])
        ph = wb.add_sheet("Profile health", columns=PROFILE_COLUMNS, rows=profile_rows(result))
        ph.append([PROFILE_HEALTH_DEFINITION])
        wb.add_sheet("Forwarding health", columns=FORWARDING_COLUMNS, rows=forwarding_rows(result))
        ls = wb.add_sheet("Last seen", columns=["Last seen", "Registered devices", "% of registered"],
                          rows=[[b["label"], b["devices"], "" if b["percent"] is None else b["percent"]]
                                for b in (result.get("last_seen") or {}).get("buckets") or []])
        ls.append([LAST_SEEN_DEFINITION])
        sites = site_table(result, counts_only)
        if sites:
            st = wb.add_sheet("Sites", columns=SITE_COLUMNS, rows=site_rows(sites))
            st.append([_sites_note(sites)])
    if history:
        wb.add_sheet("History", columns=HISTORY_COLUMNS, rows=history_rows(history))
    os_ = wb.add_sheet("Operating systems", columns=["Platform", "OS version", "Registered devices"])
    if not k:
        os_.append([no_devices])
    else:
        mix: Dict[Tuple[str, str], int] = {}
        for d in reg:
            key = (d.get("platform") or "", d.get("os_version") or "not reported")
            mix[key] = mix.get(key, 0) + 1
        for (plat, ver), n in sorted(mix.items(), key=lambda kv: (kv[0][0], -kv[1], kv[0][1])):
            os_.append([plat, ver, n])
        if not mix:
            os_.append(["No registered device."])
        if result.get("devices_truncated"):
            os_.append([f"Counted over the first {len(devs)} of {result.get('devices_total')} devices kept for the page; the platform totals on Summary count all of them."])
    ghost = (result.get("alerts") or {}).get("ghost") or {}
    stale_note = f"{ALERTS['ghost']['label']}: {ALERTS['ghost']['definition']}"
    if counts_only:
        ss = wb.add_sheet("Stale devices", columns=["Platform", "Stale devices"])
        per: Dict[str, int] = {}
        for d in ghost.get("rows") or []:
            per[d.get("platform") or ""] = per.get(d.get("platform") or "", 0) + 1
        for plat, n in sorted(per.items(), key=lambda kv: -kv[1]):
            ss.append([plat, n])
    else:
        ss = wb.add_sheet("Stale devices", columns=["User", "Host name", "Platform", "OS version", "Client Connector version", "Last seen (UTC)", "Days since seen"])
        for d in ghost.get("rows") or []:
            hrs = d.get("hours_since_seen")
            ss.append([d.get("user"), d.get("hostname"), d.get("platform"), d.get("os_version"), d.get("version"), d.get("last_seen") or "",
                       None if hrs is None else round(hrs / 24.0, 1)])
    if not ghost.get("evaluated"):
        ss.append([ghost.get("why_not") or "Not evaluated."])
    elif not ghost.get("count"):
        ss.append(["No stale device."])
    elif ghost.get("truncated"):
        ss.append([f"The first {len(ghost.get('rows') or [])} of {ghost.get('count')} are listed."])
    ss.append([stale_note])
    if counts_only:
        wb.add_sheet("Devices", columns=["Note"], rows=[["Counts only: the device table names users and devices, so it is left out."]])
    else:
        rows = _csv_rows(export_csv(result, "devices", False)[1]) if devs else []
        ds = wb.add_sheet("Devices", columns=rows[0] if rows else ["Note"])
        if rows:
            ds.extend([[_num(c) for c in r] for r in rows[1:]])
        else:
            ds.append([no_devices if not k else "No device."])
        if result.get("devices_truncated"):
            ds.append([f"The first {len(devs)} of {result.get('devices_total')} devices are kept for the page and this export."])
    al = wb.add_sheet("Alerts", columns=["Alert", "Count", "Definition", "Fix"])
    for key in result.get("alert_order") or []:
        a = (result.get("alerts") or {}).get(key) or {}
        al.append([a.get("label", key), a.get("count") if a.get("evaluated") else (a.get("why_not") or "not evaluated"), a.get("definition"), a.get("fix")])
    plan = _csv_rows(export_csv(result, "plan", counts_only)[1])
    ps = wb.add_sheet("Plan", columns=plan[0], rows=[[_num(c) for c in r] for r in plan[1:]])
    if len(plan) == 1:
        ps.append(["Nothing to fix was found."])
    return "zcc_fleet" + ("_counts" if counts_only else ""), wb.to_bytes()


def _num(cell: str) -> Any:
    """A CSV cell back as a number when it is one (the CSV writer quoted
    nothing numeric), so Excel can sum it; anything else stays text."""
    if isinstance(cell, str) and re.fullmatch(r"-?\d+(\.\d+)?", cell.strip()):
        return float(cell) if "." in cell else int(cell)
    return cell


def export_csv(result: Dict[str, Any], what: str, counts_only: bool) -> Tuple[str, str]:
    """(filename stem, CSV text) through csv_safe. `what` is "plan" (the
    ranked remediation plan), "devices" (the device table: names; refused
    with counts_only) or "summary" (KPIs and alert counts). Counts only
    leaves every user and host name out. The Excel workbook (export_xlsx)
    carries the same rows."""
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    if what == "plan":
        w.writerow(["Rank", "Priority", "Impact", "Devices", "Status", "Title", "Where", "Detail", "Fix"])
        for x in result.get("plan") or []:
            w.writerow([x["rank"], x["priority"], x["impact"], "" if x["devices"] is None else x["devices"], x["status"], x["title"], x["where"],
                        x["detail"], x["fix"]])
        return "zcc_fleet_plan", buf.getvalue()
    if what == "devices":
        if counts_only:
            raise ValueError("The device table names users and devices; with counts only, export the summary or the plan instead.")
        w.writerow(["User", "Host name", "Platform", "OS version", "Client Connector version", "Registration", "Last seen (UTC)",
                    "Hours since seen", "App profile", "ZIA", "ZPA", "ZDX"])
        for d in result.get("devices") or []:
            s = d.get("services") or {}
            w.writerow([d["user"], d["hostname"], d["platform"], d["os_version"], d["version"], REGISTRATION_LABELS.get(d["registration"], d["registration"]),
                        d["last_seen"] or "", "" if d["hours_since_seen"] is None else d["hours_since_seen"], d["profile"],
                        s.get("zia", ""), s.get("zpa", ""), s.get("zdx", "")])
        return "zcc_fleet_devices", buf.getvalue()
    if what == "summary":
        w.writerow(["Section", "Item", "Value"])
        w.writerow(["Read", "Mode", result.get("mode")])
        w.writerow(["Read", "Note", result.get("banner")])
        k = result.get("kpis")
        if k:
            w.writerow(["Devices", "Device records", k["devices"]])
            w.writerow(["Devices", "Registered", k["registered"]])
            for st, n in (k.get("registration_states") or {}).items():
                w.writerow(["Registration", REGISTRATION_LABELS.get(st, st), n])
            for os_, n in (k.get("os_mix") or {}).items():
                w.writerow(["Platform", os_, n])
            for s, v in (k.get("services") or {}).items():
                w.writerow(["Service active %", SERVICE_LABELS[s], "not available" if v.get("percent") is None else v["percent"]])
        else:
            w.writerow(["Devices", "Device records", "not available"])
        for key in result.get("alert_order") or []:
            a = (result.get("alerts") or {}).get(key) or {}
            w.writerow(["Alert", a.get("label", key), a["count"] if a.get("evaluated") else "not evaluated"])
        sc = result.get("scores") or {}
        w.writerow(["Score", "Equal weight", "" if sc.get("equal_weight") is None else sc["equal_weight"]])
        w.writerow(["Score", "Device weighted", "not available" if sc.get("device_weighted") is None else sc["device_weighted"]])
        for p in result.get("profiles") or []:
            w.writerow(["Profile score", f"{p['name']} ({p['platform']})", "" if p["score"] is None else p["score"]])
        return "zcc_fleet_summary", buf.getvalue()
    raise ValueError("Choose plan, devices or summary.")
