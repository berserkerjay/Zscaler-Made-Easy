"""ZDX on the Path analyzer page: the measured cloud path of an application,
and a ZDX score analysis (root cause) on one device.

Cloud path (read-only; only when ZDX is ticked on the Scope page)
    `apps(sdk)` lists the applications ZDX monitors (name, id, score) and
    suggests the one whose name matches the destination the Path analyzer
    traced. `cloudpath(sdk, app_id)` finds a device that has a CloudPath
    probe for that application and returns the path it measured, leg by
    leg (device to egress, egress to Zscaler, Zscaler to the application):
    hop count, latency, loss, unanswered hops and the tunnel. The device is
    never named (personal data is counted, not listed): the answer says
    how many devices were looked at. A hop on a private address is shown
    as "private address" and no MAC address or vendor is ever returned.

Score analysis (root cause; ZDX runs it, nothing in the configuration changes)
    `start_analysis` asks ZDX to analyse one application on one device
    (picked automatically, or typed by the operator) over the last hours.
    The route gives it all four write gates (write mode, a writer, the
    named assessor and the typed phrase START ANALYSIS), and starts are
    rate-limited here: one per tenant every RCA_MIN_INTERVAL seconds and
    RCA_MAX_PER_HOUR per tenant an hour (ZDX's own limits are not
    published; these are assumed safe). `analysis_status` reads it back and
    `stop_analysis` stops it. Every start and stop is in the audit log with
    the actor.

API calls (zscaler-sdk-python 1.11.3, zscaler/zdx), verified there:

    apps.list_apps                      GET    /zdx/v1/apps
    devices.list_devices                GET    /zdx/v1/devices
    devices.list_cloudpath_probes       GET    /zdx/v1/devices/{device}/apps/{app}/cloudpath-probes
    devices.get_cloudpath               GET    /zdx/v1/devices/{device}/apps/{app}/cloudpath-probes/{probe}/cloudpath
    troubleshooting.start_analysis      POST   /zdx/v1/analysis           (device_id, app_id, t0, t1)
    troubleshooting.get_analysis        GET    /zdx/v1/analysis/{id}
    troubleshooting.delete_analysis     DELETE /zdx/v1/analysis/{id}

Assumed (see ASSUMED): the start answer carries the analysis id as `id`
(the SDK model DeviceApplicationAnalysis declares device_id, app_id, t0
and t1 only); t0 and t1 are epoch seconds; the status answer's shape.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

ASSUMED = [
    "The answer to POST /zdx/v1/analysis carries the new analysis id as `id` (the SDK model declares device_id, app_id, t0, t1 only).",
    "t0 and t1 of a score analysis are epoch seconds, as the other ZDX time windows are.",
    "The status answer of GET /zdx/v1/analysis/{id} is shown as ZDX words it (status, progress and findings), scrubbed of personal fields.",
    "ZDX's own limits for score analyses are not published: the app allows one start per tenant every 5 minutes and 6 an hour.",
]

MAX_APPS = 200
MAX_DEVICES = 10            # devices looked at for a CloudPath probe of the application
MAX_HOPS = 30
RCA_MIN_INTERVAL = 300      # seconds between two starts for one tenant
RCA_MAX_PER_HOUR = 6
RCA_HOURS = (1, 2, 4, 8, 24)
CONFIRM_PHRASE = "START ANALYSIS"
_ID = re.compile(r"^[0-9]{1,20}$")
_AID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PERSONAL = re.compile(r"user|email|mail|login|host|serial|mac|vendor|name_of|password|token|secret|key|phone|udid", re.I)
# Addresses inside a home, office or carrier network: masked (they can say where a person is).
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                        "fc00::/7", "fe80::/10"))
_LEG_WORDS = {"client": "the device", "egress": "the network exit (egress)", "zen": "the Zscaler service edge", "zia": "the Zscaler service edge",
              "app": "the application", "dst": "the application", "gateway": "the gateway"}


class InsightError(ValueError):
    """A request the page can fix (the route's 400)."""


class RateLimited(InsightError):
    """A start refused by the rate limit (the route's 429)."""


# ---------------------------------------------------------------------------
# Small readers over the SDK's (result, response, error) tuples
# ---------------------------------------------------------------------------

from sdk_read import call as _call, items as _items   # noqa: E402 — the SDK tuple readers


def _zdx(sdk: Any) -> Any:
    z = getattr(sdk, "zdx", None)
    if z is None:
        raise InsightError("This sign-in has no ZDX API. Sign in with a OneAPI API client.")
    return z


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return round(f, 2) if f == f and abs(f) != float("inf") else None


def _text(v: Any, n: int = 120) -> str:
    s = "" if v is None else str(v)
    s = "".join(ch for ch in s if ch.isprintable())
    return s[:n]


def _since(hours: int) -> Dict[str, int]:
    now = int(time.time())
    return {"from": now - hours * 3600, "to": now}


# ---------------------------------------------------------------------------
# Cloud path
# ---------------------------------------------------------------------------

def _tokens(s: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if len(t) >= 4]


def suggest(apps: List[Dict[str, Any]], host: str) -> Optional[str]:
    """The id of the application whose name shares a word with the destination (or None)."""
    h = (host or "").lower()
    if not h:
        return None
    best, score = None, 0
    for a in apps:
        hits = sum(1 for t in _tokens(a.get("name", "")) if t in h)
        if hits > score:
            best, score = a["id"], hits
    return best


def apps(sdk: Any, host: str = "") -> Dict[str, Any]:
    """The applications ZDX monitored in the last day (id, name, score) and the suggested one for `host`."""
    body, err = _call(_zdx(sdk).apps.list_apps, query_params=_since(24))
    rows = []
    for a in _items(body, "apps")[:MAX_APPS]:
        aid = _text(a.get("id"), 20)
        if not _ID.match(aid):
            continue
        rows.append({"id": aid, "name": _text(a.get("name") or aid, 80), "score": _num(a.get("score"))})
    rows.sort(key=lambda r: r["name"].lower())
    return {"apps": rows, "suggested": suggest(rows, host), "error": err}


def _hop_ip(v: Any) -> str:
    s = _text(v, 45).strip()
    if not s:
        return "no answer"
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return "not an address"
    if ip.is_loopback or ip.is_link_local or any(ip in n for n in _PRIVATE_NETS if n.version == ip.version):
        return "private address"
    return str(ip)


def _leg_word(v: Any) -> str:
    k = _text(v, 30).strip().lower()
    return _LEG_WORDS.get(k, k or "unknown")


def shape_path(raw: Any) -> List[Dict[str, Any]]:
    """The legs of the newest CloudPath sample, safe to show (no MAC, no vendor, private hops masked)."""
    samples = _items(raw, "cloudpath_list", "items")
    if not samples and isinstance(raw, dict) and isinstance(raw.get("cloudpath"), list):
        samples = [raw]
    if not samples:
        return []
    newest = max(samples, key=lambda s: _num(s.get("timestamp")) or 0)
    legs = []
    for leg in (newest.get("cloudpath") if isinstance(newest.get("cloudpath"), list) else [])[:10]:
        if not isinstance(leg, dict):
            continue
        hops = []
        for h in (leg.get("hops") if isinstance(leg.get("hops"), list) else [])[:MAX_HOPS]:
            if not isinstance(h, dict):
                continue
            sent, rcvd = _num(h.get("pkt_sent")), _num(h.get("pkt_rcvd"))
            loss = round(100.0 * (sent - rcvd) / sent, 1) if sent and rcvd is not None and sent > 0 else None
            hops.append({"ip": _hop_ip(h.get("ip")), "latency_ms": _num(h.get("latency_avg")), "loss_pct": loss})
        legs.append({"from": _leg_word(leg.get("src")), "to": _leg_word(leg.get("dst")), "hops": _num(leg.get("num_hops")),
                     "latency_ms": _num(leg.get("latency")), "loss_pct": _num(leg.get("loss")),
                     "unanswered_hops": _num(leg.get("num_unresp_hops")), "tunnel": _text(leg.get("tunnel_type"), 30),
                     "hop_list": hops})
    return legs


def verdict(legs: List[Dict[str, Any]]) -> str:
    """One plain sentence: where the time and the loss are."""
    if not legs:
        return "ZDX has no CloudPath measurement for this application on the devices looked at."
    slow = max(legs, key=lambda l: l.get("latency_ms") or 0)
    lossy = [l for l in legs if (l.get("loss_pct") or 0) > 1]
    total = sum(l.get("latency_ms") or 0 for l in legs)
    s = f"About {round(total)} ms end to end; the slowest leg is {slow['from']} to {slow['to']} ({slow.get('latency_ms')} ms)."
    if lossy:
        s += " Packets are lost between " + "; ".join(f"{l['from']} and {l['to']} ({l['loss_pct']}%)" for l in lossy) + "."
    return s


def cloudpath(sdk: Any, app_id: str, *, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """The measured path of one application from the first device (of up to
    MAX_DEVICES active in the last day) with a CloudPath probe for it."""
    app_id = _text(app_id, 20)
    if not _ID.match(app_id):
        raise InsightError("Pick the ZDX application.")
    z = _zdx(sdk)
    body, err = _call(z.devices.list_devices, query_params=_since(24))
    if err:
        return {"app_id": app_id, "legs": [], "devices_checked": 0, "verdict": "", "error": f"The ZDX devices could not be read: {err}"}
    devices = [d for d in _items(body, "devices") if _ID.match(_text(d.get("id"), 20))][:MAX_DEVICES]
    checked, errors = 0, 0
    for d in devices:
        if cancel is not None and cancel.is_set():
            break
        checked += 1
        did = _text(d.get("id"), 20)
        probes, perr = _call(z.devices.list_cloudpath_probes, did, app_id, query_params=_since(24))
        if perr:
            errors += 1
            continue
        plist = [p for p in _items(probes, "probes") if _ID.match(_text(p.get("id"), 20))]
        if not plist:
            continue
        probe = plist[0]
        raw, cerr = _call(z.devices.get_cloudpath, did, app_id, _text(probe.get("id"), 20), query_params=_since(24))
        if cerr:
            errors += 1
            continue
        legs = shape_path(raw)
        if legs:
            return {"app_id": app_id, "probe": _text(probe.get("name"), 80), "legs": legs, "devices_checked": checked,
                    "verdict": verdict(legs), "error": None,
                    "note": "Measured by ZDX from one device that probes this application (the device is not named)."}
    why = f" {errors} device(s) could not be read." if errors else ""
    return {"app_id": app_id, "legs": [], "devices_checked": checked, "verdict": verdict([]) + why, "error": None}


# ---------------------------------------------------------------------------
# Score analysis (root cause), rate-limited
# ---------------------------------------------------------------------------

_RATE_LOCK = threading.Lock()
_STARTS: Dict[str, List[float]] = {}


def rate_check(tenant_key: str, *, now: Optional[float] = None, record: bool = False) -> Optional[str]:
    """Why a start is refused by the rate limit now (None when allowed); with
    `record`, an allowed start is counted."""
    t = time.time() if now is None else now
    with _RATE_LOCK:
        recent = [x for x in _STARTS.get(tenant_key, []) if t - x < 3600]
        _STARTS[tenant_key] = recent
        if recent and t - recent[-1] < RCA_MIN_INTERVAL:
            wait = int(RCA_MIN_INTERVAL - (t - recent[-1])) + 1
            return f"A score analysis was started for this tenant less than {RCA_MIN_INTERVAL // 60} minutes ago: wait {wait} seconds, then try again."
        if len(recent) >= RCA_MAX_PER_HOUR:
            return f"{RCA_MAX_PER_HOUR} score analyses were started for this tenant in the last hour, the most allowed: try again later."
        if record:
            recent.append(t)
        return None


def reset_rate() -> None:
    with _RATE_LOCK:
        _STARTS.clear()


def _pick_device(z: Any, app_id: str) -> Tuple[Optional[str], int]:
    body, err = _call(z.devices.list_devices, query_params=_since(24))
    if err:
        raise InsightError(f"The ZDX devices could not be read, so no device could be picked: {err}")
    devices = [_text(d.get("id"), 20) for d in _items(body, "devices")][:MAX_DEVICES]
    devices = [d for d in devices if _ID.match(d)]
    for i, did in enumerate(devices, 1):
        probes, perr = _call(z.devices.list_cloudpath_probes, did, app_id, query_params=_since(24))
        if not perr and _items(probes, "probes"):
            return did, i
    return (devices[0], 1) if devices else (None, len(devices))


def start_analysis(sdk: Any, app_id: str, *, tenant_key: str, device_id: str = "", hours: int = 2,
                   actor: str = "", assessor: str = "", now: Optional[float] = None) -> Dict[str, Any]:
    """Ask ZDX to analyse `app_id` on one device over the last `hours`. The
    caller has passed the four write gates; this applies the rate limit,
    then starts it and records the start in the audit log."""
    import audit
    app_id = _text(app_id, 20)
    if not _ID.match(app_id):
        raise InsightError("Pick the ZDX application.")
    device_id = _text(device_id, 20).strip()
    if device_id and not _ID.match(device_id):
        raise InsightError("A ZDX device id is digits only (leave it empty to let the app pick a device).")
    if hours not in RCA_HOURS:
        raise InsightError("Analyse the last " + ", ".join(str(h) for h in RCA_HOURS) + " hours.")
    why = rate_check(tenant_key, now=now)
    if why:
        audit.record("zdx_analysis_refused", reason="rate limit", app_id=app_id, actor=actor or None, assessor=assessor)
        raise RateLimited(why)
    z = _zdx(sdk)
    picked = "typed"
    if not device_id:
        device_id, _n = _pick_device(z, app_id)
        picked = "auto"
        if not device_id:
            raise InsightError("ZDX saw no device in the last day, so there is nothing to analyse.")
    t1 = int(time.time() if now is None else now)
    rate_check(tenant_key, now=now, record=True)
    body, err = _call(z.troubleshooting.start_analysis, device_id=int(device_id), app_id=int(app_id), t0=t1 - hours * 3600, t1=t1)
    if err:
        audit.record("zdx_analysis_start", outcome="refused", app_id=app_id, hours=hours, device=picked, error=err[:200],
                     actor=actor or None, assessor=assessor)
        raise InsightError(f"ZDX refused the analysis: {err}")
    aid = _text((body or {}).get("id") if isinstance(body, dict) else "", 64)
    audit.record("zdx_analysis_start", outcome="started", app_id=app_id, hours=hours, device=picked, analysis_id=aid,
                 actor=actor or None, assessor=assessor)
    return {"analysis_id": aid if _AID.match(aid or "") else "", "app_id": app_id, "hours": hours,
            "device": "picked automatically" if picked == "auto" else "the device you entered",
            "note": "ZDX runs the analysis; nothing in the configuration changes. Read the status in a minute."}


def _safe(v: Any, depth: int = 0) -> Any:
    """An untrusted answer made safe to show: bounded, printable, no personal or secret field."""
    if depth > 4:
        return None
    if isinstance(v, dict):
        out = {}
        for k, x in list(v.items())[:40]:
            ks = _text(k, 40)
            if _PERSONAL.search(ks):
                continue
            out[ks] = _safe(x, depth + 1)
        return out
    if isinstance(v, list):
        return [_safe(x, depth + 1) for x in v[:50]]
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return _num(v)
    return _text(v, 300)


def analysis_status(sdk: Any, analysis_id: str) -> Dict[str, Any]:
    analysis_id = _text(analysis_id, 64)
    if not _AID.match(analysis_id):
        raise InsightError("Give the analysis id the start returned.")
    body, err = _call(_zdx(sdk).troubleshooting.get_analysis, analysis_id)
    if err:
        return {"analysis_id": analysis_id, "error": err, "result": None}
    if isinstance(body, list) and len(body) == 1:
        body = body[0]
    return {"analysis_id": analysis_id, "error": None, "result": _safe(body)}


def stop_analysis(sdk: Any, analysis_id: str, *, actor: str = "", assessor: str = "") -> Dict[str, Any]:
    import audit
    analysis_id = _text(analysis_id, 64)
    if not _AID.match(analysis_id):
        raise InsightError("Give the analysis id the start returned.")
    _body, err = _call(_zdx(sdk).troubleshooting.delete_analysis, analysis_id)
    audit.record("zdx_analysis_stop", outcome="refused" if err else "stopped", analysis_id=analysis_id,
                 error=(err or "")[:200] or None, actor=actor or None, assessor=assessor)
    if err:
        raise InsightError(f"ZDX refused to stop the analysis: {err}")
    return {"analysis_id": analysis_id, "stopped": True}
