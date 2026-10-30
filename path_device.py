"""Path analyzer: trace for one user's enrolled device.

Instead of the generic Platform select, the operator looks a user's
enrolled devices up in the Client Connector Portal and picks one. The
trace then uses what the Portal says about that device:

* its platform (the device type: 1 iOS, 2 Android, 3 Windows, 4 macOS,
  5 Linux, zscaler-sdk-python utils.zcc_param_map["os"]);
* the app profile the Portal reports for it (getDevices `policyName`,
  SDK zcc/models/devices.py Device.policy_name), matched by name to the
  app profiles the analysis read, instead of choosing a profile by
  platform, user and group; the forwarding profile then follows from that
  app profile's link, as for any trace;
* its Client Connector version (`agentVersion`), registration state, last
  seen time and tunnel version;
* from getDeviceDetails (SDK DeviceDetails, one call for the picked device,
  `udid` filter): whether ZIA, ZPA and ZDX are on and healthy, the device
  trust level and strict enforcement, when the API gives them.

What the API does not give stays "unknown" and is said: which network the
device is on right now (trusted, off-trusted or VPN; the Network select
still decides), and per-device ZPA posture results (ZPA is still answered
for posture passing and failing). The meaning of the details' on/off and
health values is assumed from their names (the SDK documents the fields,
not their values).

Reading (read-only, only when ZCC is ticked on the Scope page; the server
checks it before signing in): `search_devices` makes one getDevices call
filtered by user name (SDK zcc.devices.list_devices, query `username`,
one page of PAGE_SIZE) and keeps only devices whose user matches what was
typed, at most SEARCH_LIMIT, so a filter the API ignored never turns into a
bulk listing; `read_details` makes one getDeviceDetails call.

Personal data: host and user names are shown on the page (the operator
needs them to pick the device) but never written to the run log. The
device's UDID stays on the server: the page gets a one-way hash as the
device's id.

Everything below the readers is pure.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from zcc_evaluation import _v, device_platform, field_index, zcc_unsupported

SEARCH_LIMIT = 20          # devices shown for one search
PAGE_SIZE = 50             # one getDevices page (the SDK's default; never paged on)
MAX_TEXT = 200
_QUERY = re.compile(r"^[^\x00-\x1f\x7f]{2,128}$")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

# device_platform's labels -> the Path analyzer's platform keys (data_flow.PLATFORMS).
PLATFORM_KEY = {"Windows": "windows", "macOS": "macos", "iOS": "ios", "Android": "android", "Linux": "linux"}
PLATFORM_LABEL = {v: k for k, v in PLATFORM_KEY.items()}

NETWORK_UNKNOWN = ("Not given by the API: the Client Connector Portal does not say which network the device is on right now "
                   "(trusted, off-trusted or VPN), so the Network you chose above applies.")
POSTURE_UNKNOWN = ("Not given by the API: per-device ZPA posture results are not in the Client Connector device record, so ZPA is "
                   "answered for posture passing and failing.")


def _clip(v: Any, n: int = MAX_TEXT) -> str:
    return str(v if v is not None else "").strip()[:n]


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


def valid_query(q: Any) -> Optional[str]:
    """2 to 128 characters with no control character, or None."""
    s = str(q or "").strip()
    return s if _QUERY.match(s) else None


def device_id(udid: Any) -> str:
    """The id the page gets for a device: a one-way hash of its UDID."""
    return hashlib.sha256(("zme-device:" + str(udid or "")).encode("utf-8")).hexdigest()[:20]


def _on_off(v: Any) -> str:
    """'on', 'off' or 'unknown' from a flag the API may send as a bool, a
    number or text (assumed: 1/true/enabled is on)."""
    if v is None or v == "":
        return "unknown"
    if isinstance(v, bool):
        return "on" if v else "off"
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "enabled", "enable", "active"):
        return "on"
    if s in ("0", "false", "no", "off", "disabled", "disable", "inactive"):
        return "off"
    return "unknown"


def _registration(raw: Any) -> str:
    import zcc_fleet
    return zcc_fleet.registration(raw)


def normalize(raw: Any) -> Dict[str, Any]:
    """One getDevices record → the fields the trace and the page use, plus
    `udid` (server side only; `public` drops it)."""
    import zcc_fleet
    d = field_index(_plain(raw))
    plat_label = device_platform(d)
    seen = zcc_fleet.parse_time(_v(d, "last_seen_time", "lastSeenTime", "lastSeen", "keepAliveTime", default=None))
    udid = _clip(_v(d, "udid", default=""), 256)
    return {
        "id": device_id(udid) if udid else "",
        "udid": udid,
        "hostname": _clip(_v(d, "machineHostname", "hostname", "deviceName", "machineName", default="")),
        "user": _clip(_v(d, "user", "userName", "owner", default="")),
        "platform": PLATFORM_KEY.get(plat_label),
        "platform_label": plat_label if plat_label in PLATFORM_KEY else "unknown",
        "os_version": _clip(_v(d, "osVersion", default=""), 60),
        "version": _clip(_v(d, "agentVersion", default=""), 40),
        "registration": _registration(_v(d, "registrationState", "registration_state", default=None)),
        "last_seen": seen.isoformat() if seen else None,
        "profile": _clip(_v(d, "policyName", "policy_name", default="")),
        "tunnel": _clip(_v(d, "tunnelVersion", default=""), 40),
        "details": {"status": "unread", "reason": ""},
    }


def public(dev: Dict[str, Any]) -> Dict[str, Any]:
    """The device as the page may see it: everything but the UDID."""
    return {k: v for k, v in dev.items() if k != "udid"}


def _user_matches(dev: Dict[str, Any], q: str) -> bool:
    u = (dev.get("user") or "").casefold()
    return bool(u) and q.casefold() in u


def search_devices(sdk: Any, query: str) -> Dict[str, Any]:
    """One getDevices call filtered by user name. Returns {query, devices
    (normalized, with udid), capped, error}. Never raises for a refusal."""
    q = valid_query(query)
    if q is None:
        raise ValueError("Type 2 to 128 characters of the user's sign-in name to search.")
    out: Dict[str, Any] = {"query": q, "devices": [], "capped": False, "error": None}
    svc = getattr(getattr(sdk, "zcc", None), "devices", None)
    if svc is None:
        out["error"] = "This sign-in has no Client Connector API, so no enrolled devices could be read."
        return out
    try:
        items, _resp, err = svc.list_devices(query_params={"username": q, "page": 1, "page_size": PAGE_SIZE})
    except Exception as e:  # noqa: BLE001 — a refusal is reported, never raised
        items, err = None, e
    if err is not None:
        import zcc_fleet
        out["error"] = zcc_fleet._unavailable_why(zcc_fleet._http_code(str(err)), "the enrolled devices")
        return out
    rows = [normalize(x) for x in (items or [])[:PAGE_SIZE]]
    # Only devices whose user matches what was typed: the API filters by
    # user name, and a filter it ignored must never become a bulk listing.
    rows = [r for r in rows if _user_matches(r, q)]
    out["capped"] = len(rows) > SEARCH_LIMIT
    out["devices"] = rows[:SEARCH_LIMIT]
    return out


def read_details(sdk: Any, dev: Dict[str, Any]) -> Dict[str, Any]:
    """getDeviceDetails for one device (by its UDID) → dev["details"]:
    {status read | failed, reason, zia, zpa, zdx (on/off/unknown),
    zia_health, zpa_health, device_trust, strict_enforcement, vdi}."""
    det: Dict[str, Any] = {"status": "failed", "reason": ""}
    svc = getattr(getattr(sdk, "zcc", None), "devices", None)
    if svc is None or not dev.get("udid"):
        det["reason"] = "The device details could not be asked for (no Client Connector API, or no device id)."
        return det
    try:
        obj, _resp, err = svc.get_device_details(query_params={"udid": dev["udid"]})
    except Exception as e:  # noqa: BLE001
        obj, err = None, e
    if err is not None or obj is None:
        import zcc_fleet
        det["reason"] = _EMAIL.sub("<user>", zcc_fleet._unavailable_why(zcc_fleet._http_code(str(err or "")), "this device's details"))
        return det
    d = field_index(_plain(obj))
    det.update(status="read", reason="",
               zia=_on_off(_v(d, "ziaEnabled", default=None)), zpa=_on_off(_v(d, "zpaEnabled", default=None)),
               zdx=_on_off(_v(d, "zdxEnabled", default=None)),
               zia_health=_clip(_v(d, "ziaHealth", default=""), 40), zpa_health=_clip(_v(d, "zpaHealth", default=""), 40),
               device_trust=_clip(_v(d, "deviceTrust", default=""), 40),
               strict_enforcement=_on_off(_v(d, "strictEnforcement", default=None)),
               vdi=_on_off(_v(d, "vdi", default=None)))
    return det


# ── The device on the path (pure) ─────────────────────────────────────
def apply_device(zcc: Dict[str, Any], dev: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(zcc for the trace, how the app profile was chosen). When the
    Portal's profile name matches a read app profile, the trace sees only
    that profile, for everyone, so data_flow.trace follows it; otherwise
    the read is unchanged and the profile is chosen as for any device on
    the platform. The read itself is never changed (it is kept for the
    next destination)."""
    plat = dev.get("platform") or ""
    name = (dev.get("profile") or "").strip()
    profiles = [p for p in (zcc or {}).get("app_profiles") or [] if isinstance(p, dict)]
    ctx: Dict[str, Any] = {"reported": name or None, "status": "unknown", "why": "", "profile": None}
    if "zcc" in ((zcc or {}).get("not_in_scope") or {}):
        ctx.update(status="not_in_scope", why="Client Connector is not in scope on the Scope page, so the app profiles were not read.")
        return zcc, ctx
    if not name:
        ctx["why"] = (f"Unknown: the Client Connector Portal does not name this device's app profile, so it is chosen as for any "
                      f"{plat or 'device'} device (by platform, user and group).")
        return zcc, ctx
    same = [p for p in profiles if str(p.get("name") or "").strip().casefold() == name.casefold()]
    pick = next((p for p in same if p.get("platform") in (plat, "all", "")), same[0] if same else None)
    if pick is None:
        ctx.update(status="not_found",
                   why=f"The Client Connector Portal reports app profile “{name}” for this device, but no app profile of that name was read, "
                       f"so the profile is chosen as for any {plat or 'device'} device (by platform, user and group).")
        return zcc, ctx
    notes = []
    if not pick.get("active", True):
        notes.append("the profile list marks it inactive, but the device still reports it")
    if plat and pick.get("platform") not in (plat, "all", ""):
        notes.append(f"it is a {pick.get('platform')} profile and the device is {plat}")
    ctx.update(status="portal", profile={"id": pick.get("id"), "name": pick.get("name")},
               why=(f"The Client Connector Portal reports app profile “{pick.get('name')}” for this device (its policy name), so that profile "
                    "is used instead of choosing one by platform, user and group." + (" Note: " + "; ".join(notes) + "." if notes else "")))
    pinned = dict(pick, groups=[], users=[], active=True, platform=plat or pick.get("platform") or "all")
    return dict(zcc, app_profiles=[pinned]), ctx


def _fact(key: str, label: str, value: Any, source: str, known: bool = True, missing: str = "not given by the API") -> Dict[str, Any]:
    ok = bool(known and value not in (None, ""))
    return {"key": key, "label": label, "value": value if ok else "unknown", "known": ok, "source": source if ok else missing}


def describe(dev: Dict[str, Any], ctx: Optional[Dict[str, Any]] = None, trace: Optional[Dict[str, Any]] = None,
             network: str = "off") -> Dict[str, Any]:
    """The result's `device` block: what the Portal says about the device
    (each fact with where it came from, or "unknown"), which app and
    forwarding profile applied and why, and what it impacts."""
    import data_flow
    det = dev.get("details") or {}
    got = det.get("status") == "read"
    src_list, src_det = "Client Connector Portal (device list)", "Client Connector Portal (device details)"
    no_det = ("not given by the API" if got else "device details could not be read" if det.get("status") == "failed" else "device details not read")
    unsupported = bool(dev.get("platform_label") in PLATFORM_KEY and dev.get("version")
                       and zcc_unsupported(dev["platform_label"], dev["version"]))
    facts = [
        _fact("platform", "Platform", dev.get("platform_label") if dev.get("platform") else None, src_list),
        _fact("os_version", "Operating system", dev.get("os_version"), src_list),
        _fact("version", "Client Connector version", (dev.get("version") or "") + (" (no longer supported)" if unsupported else "")
              if dev.get("version") else None, src_list),
        _fact("profile", "App profile (reported)", dev.get("profile"), src_list),
        _fact("registration", "Registration", None if dev.get("registration") in (None, "unknown") else dev.get("registration"), src_list),
        _fact("last_seen", "Last seen", dev.get("last_seen"), src_list),
        _fact("tunnel", "Tunnel", dev.get("tunnel"), src_list),
        _fact("zia", "ZIA service", det.get("zia") if got and det.get("zia") != "unknown" else None, src_det, missing=no_det),
        _fact("zpa", "ZPA service", det.get("zpa") if got and det.get("zpa") != "unknown" else None, src_det, missing=no_det),
        _fact("device_trust", "Device trust level", det.get("device_trust") if got else None, src_det, missing=no_det),
        _fact("strict", "Strict enforcement", det.get("strict_enforcement") if got and det.get("strict_enforcement") != "unknown" else None, src_det, missing=no_det),
        _fact("network", "Network right now", None, "", known=False),
        _fact("posture", "ZPA posture results", None, "", known=False),
    ]
    hops = {h.get("key"): h for h in (trace or {}).get("hops") or [] if isinstance(h, dict)}
    zh, fh = hops.get("zcc") or {}, hops.get("forwarding") or {}
    applied = ((zh.get("decided_by") or {}).get("name") or zh.get("profile")) if zh else None
    ctx = ctx or {"reported": dev.get("profile") or None, "status": "not_traced",
                  "why": "The ZIA path was not traced (ZPA carries this destination, or no ZIA part is in scope), so no app profile was applied."}
    net_label = next((n["label"] for n in data_flow.NETWORKS if n["key"] == network), network)
    fwd_name = (fh.get("decided_by") or {}).get("name") if fh else None
    out = {
        "id": dev.get("id"), "hostname": dev.get("hostname"), "user": dev.get("user"), "platform": dev.get("platform"),
        "platform_label": dev.get("platform_label"), "facts": facts,
        "details": {"status": det.get("status") or "unread", "reason": det.get("reason") or ""},
        "app_profile": {"reported": ctx.get("reported"), "applied": applied, "status": ctx.get("status"), "why": ctx.get("why"),
                        "hop_status": zh.get("status") if zh else None},
        "forwarding_profile": {"name": fwd_name, "mode": fh.get("mode") if fh else None,
                               "why": (f"Linked from the app profile “{applied}”; its action for the network you chose ({net_label}) applies."
                                       if fwd_name and applied else
                                       "No forwarding profile was linked on this path." if trace else "Not traced.")},
        "network": {"value": net_label, "known": False, "why": NETWORK_UNKNOWN},
        "posture": {"device_trust": det.get("device_trust") if got and det.get("device_trust") else "unknown", "why": POSTURE_UNKNOWN},
        "impacts": impacts(dev, ctx, unsupported),
    }
    return out


def impacts(dev: Dict[str, Any], ctx: Dict[str, Any], unsupported: bool) -> List[Dict[str, Any]]:
    """What the device's own state changes, in the verdict's impact shape."""
    det = dev.get("details") or {}
    out: List[Dict[str, Any]] = []
    if det.get("status") == "read" and det.get("zia") == "off":
        out.append({"hop": "device", "label": "The picked device", "status": "bypass", "severity": "high", "rule": None,
                    "detail": "The Client Connector Portal says ZIA is turned off on this device: its internet traffic does not reach ZIA, "
                              "whatever the profiles below say.",
                    "fix": "Find out why ZIA is off on this device (disabled by the user, a failed sign-in, or a forwarding profile set to None)."})
    if dev.get("registration") not in (None, "registered", "unknown"):
        out.append({"hop": "device", "label": "The picked device", "status": "warn", "severity": "medium", "rule": None,
                    "detail": f"The device's registration is {str(dev.get('registration')).replace('_', ' ')}: Client Connector may not apply any profile to it.",
                    "fix": "Pick a registered device, or re-register this one in the Client Connector Portal."})
    if unsupported:
        out.append({"hop": "device", "label": "The picked device", "status": "warn", "severity": "medium", "rule": None,
                    "detail": f"Client Connector {dev.get('version')} is older than every release Zscaler supports on {dev.get('platform_label')}.",
                    "fix": "Upgrade Client Connector on this device."})
    if ctx.get("status") == "not_found":
        out.append({"hop": "device", "label": "The picked device", "status": "unknown", "severity": "info", "rule": None,
                    "detail": ctx.get("why"), "fix": None})
    return out


def assumption(dev: Dict[str, Any], network: str) -> str:
    """The assumption line that replaces 'the platform you chose'."""
    import data_flow
    net_label = next((n["label"] for n in data_flow.NETWORKS if n["key"] == network), network).lower()
    return (f"The device you picked ({dev.get('platform_label') or 'unknown platform'}, Client Connector {dev.get('version') or 'version unknown'}, "
            f"app profile {('“' + dev['profile'] + '”') if dev.get('profile') else 'not reported'}), as the Client Connector Portal reports it; "
            f"the network it is on is not reported, so {net_label} (your choice) is assumed.")
