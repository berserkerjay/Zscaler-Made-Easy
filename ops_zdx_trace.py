"""ZDX deep trace on the Bulk changes engine (admin_ops.register).

A deep trace makes Client Connector on one user's device collect detailed
measurements for a while (its Web and CloudPath probes for one application,
and the device's own health when asked), then ZDX keeps the results. Starting
one changes something on a user's device, so it is a write here: planned,
previewed, approved by its plan hash and applied through the engine's gates
(write mode, a writer, the assessor, the typed confirmation for a stop),
recorded, audited and undoable. Everything else ZDX offers stays read-only.

  zdx_deeptrace_start  start a deep trace on a device, with the API's
                       options: session name, application, Web probe,
                       CloudPath probe, length (5, 15, 30 or 60 minutes) and
                       whether to collect the device's own health. Refused
                       while the device already runs one, and rate-limited
                       (START_LIMIT starts per tenant per hour, and one per
                       device every DEVICE_COOLDOWN seconds). Undo stops it.
  zdx_deeptrace_stop   stop a deep trace: ZDX deletes the session and what it
                       collected. The typed confirmation is always asked. No
                       Undo (start a new one).

Read-only views (ZDX ticked on the Scope page): the tenant's application
scores and one application's score trend; user lookup by name or email;
device search by email; a device's details and health metrics; its
applications with their scores; one application's performance on that
device; its probes; a device's deep traces, one trace, and its results
(Web probe and CloudPath metrics, the CloudPath hops, health metrics,
events). follow() polls one trace until it ends, a bounded number of times
(at most MAX_POLLS, at least MIN_INTERVAL seconds apart), and Stop ends it.

SDK calls, all verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zdx, the read-only analytics API under /zdx/v1, whose bodies the
SDK sends as given, snake_case):

  devices.list_devices(query_params={"emails": [...]})   GET  /devices
  devices.get_device(id)                                 GET  /devices/{id}
  devices.get_device_apps(id)                            GET  /devices/{id}/apps
  devices.get_device_app(id, app)                        GET  /devices/{id}/apps/{app}
  devices.get_health_metrics(id)                         GET  /devices/{id}/health-metrics
  users.list_users(query_params={"search": ...})         GET  /users (search sent as q: ASSUMED to filter)
  apps.list_apps / apps.get_app_score(app)               GET  /apps, /apps/{app}/score
  devices.get_web_probes(id, app) / list_cloudpath_probes(id, app)
  troubleshooting.list_deeptraces(id)                    GET  /devices/{id}/deeptraces
  troubleshooting.get_deeptrace(id, trace)               GET  /devices/{id}/deeptraces/{trace}
  troubleshooting.start_deeptrace(id, session_name=, app_id=, web_probe_id=,
      cloudpath_probe_id=, session_length_minutes=5|15|30|60, probe_device=)
                                                         POST /devices/{id}/deeptraces
  troubleshooting.delete_deeptrace(id, trace)            DELETE /devices/{id}/deeptraces/{trace}
  troubleshooting.get_deeptrace_webprobe_metrics / get_deeptrace_cloudpath_metrics /
      get_deeptrace_cloudpath / get_deeptrace_health_metrics / get_deeptrace_events

ASSUMED: the status words of a trace (which mean running and which mean
ended), the start and cooldown limits (this app's own, kept low because ZDX
limits its API per tenant), and that the start answers the trace's id as
trace_id.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import pack_ops as ops

FAMILY = "zdx_trace"
T_START, T_STOP = "zdx_deeptrace_start", "zdx_deeptrace_stop"
GROUP = "Day-to-day admin"
NOT_IN_SCOPE = "Not in scope: ZDX is not ticked on the Scope page, so ZDX is not read or changed."
LENGTHS = (5, 15, 30, 60)                 # SDK docstring: session_length_minutes supported values
START_LIMIT = 10                          # deep traces started per tenant per hour (this app's limit)
DEVICE_COOLDOWN = 300.0                   # seconds between two starts on one device (this app's limit)
MAX_POLLS = 40
MIN_INTERVAL = 10.0
DEFAULT_INTERVAL = 30.0
MAX_ERRORS_IN_A_ROW = 3
MAX_ROWS = 500
MAX_RESULT_BYTES = 256 * 1024
_ID_RE = re.compile(r"^\d{1,24}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$")
_EMAIL_RE = re.compile(r"^[^\s@\x00-\x1f<>\"']{1,128}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,63}$")
RUNNING = ("in_progress", "inprogress", "started", "running", "pending", "queued", "scheduled", "processing", "collecting")
ENDED = ("completed", "complete", "done", "finished", "failed", "error", "expired", "stopped", "cancelled", "canceled", "timeout",
         "timed_out", "deleted")
ASSUMED = [
    "The trace's status words (running: in progress, started, pending; ended: completed, failed, expired, stopped) are assumed.",
    f"This app allows {START_LIMIT} deep trace starts per tenant per hour and one per device every {int(DEVICE_COOLDOWN // 60)} minutes: "
    "its own limits, kept low because ZDX limits its API per tenant.",
]


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """ZDX is read and changed only when it is ticked on the Scope page."""
    return None if "zdx" in (scope.get("scopes") or []) else NOT_IN_SCOPE


def _zdx(client: Any) -> Any:
    z = getattr(client, "zdx", None)
    if z is None:
        raise _err("This sign-in has no ZDX API: ZDX needs a OneAPI API client with a ZDX role.")
    return z


def check_id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if isinstance(v, bool) or not _ID_RE.match(s):
        raise _err(f"{what} is not a ZDX id (digits only).")
    return s


def _check_stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")


# ---------------------------------------------------------------------------
# Reads (paced with the app's request pacer)
# ---------------------------------------------------------------------------

def _plain(x: Any) -> Any:
    if isinstance(x, (dict, list, str, int, float, bool)) or x is None:
        return x
    fn = getattr(x, "as_dict", None)
    if callable(fn):
        try:
            return fn()
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _read(fn: Callable[..., Any], *args: Any, **kw: Any) -> Tuple[Any, Optional[str]]:
    """One SDK read: (the answer's JSON body, or the models as dicts; error)."""
    import zia_rate
    zia_rate.wait("GET", "", what="ZDX read")
    try:
        ret = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001 — reported, never raised
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        return None, ops.describe_error(err)[:300]
    body = None
    getter = getattr(resp, "get_body", None)
    if callable(getter):
        try:
            body = getter()
        except Exception:  # noqa: BLE001
            body = None
    if body is None:
        body = [_plain(x) for x in data] if isinstance(data, list) else _plain(data)
    return body, None


def _gone(err: Optional[str]) -> bool:
    return bool(re.search(r"\b404\b|not[ _.]?found|does not exist", str(err or ""), re.I))


def _items(body: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)]
    if isinstance(body, dict):
        for k in keys + ("items", "list", "data", "results"):
            if isinstance(body.get(k), list):
                return [x for x in body[k] if isinstance(x, dict)]
    return []


def _s(v: Any, n: int = 200) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v if v is not None else ""))[:n]


def norm_status(v: Any) -> str:
    return re.sub(r"[\s\-]+", "_", str(v or "").strip().lower())


def is_running(status: str) -> bool:
    s = norm_status(status)
    return s in RUNNING or (bool(s) and s not in ENDED)


def trace_summary(t: Dict[str, Any]) -> Dict[str, Any]:
    d = t.get("trace_details") if isinstance(t.get("trace_details"), dict) else {}
    st = norm_status(t.get("status"))
    return {"trace_id": _s(t.get("trace_id") or t.get("id"), 40), "status": st or "unknown", "running": is_running(st) if st else False,
            "ended": st in ENDED, "session_name": _s(d.get("session_name") or t.get("session_name"), 64),
            "length_minutes": d.get("session_length_minutes") or t.get("session_length_minutes"),
            "username": _s(d.get("username"), 128), "device_name": _s(d.get("device_name"), 128),
            "expected_minutes": t.get("expected_time_minutes"), "created_at": _s(t.get("created_at"), 40),
            "started_at": _s(t.get("started_at"), 40), "ended_at": _s(t.get("ended_at"), 40)}


def list_traces(client: Any, device_id: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    body, err = _read(_zdx(client).troubleshooting.list_deeptraces, device_id)
    if err:
        return [], err
    return [trace_summary(t) for t in _items(body, "deeptraces", "traces")][:MAX_ROWS], None


def get_trace(client: Any, device_id: str, trace_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    body, err = _read(_zdx(client).troubleshooting.get_deeptrace, device_id, trace_id)
    if err:
        return None, err
    row = body[0] if isinstance(body, list) and body and isinstance(body[0], dict) else body if isinstance(body, dict) else None
    return (trace_summary(row) if row else None), (None if row else "not found")


def _cap(v: Any, depth: int = 0) -> Any:
    """A tenant answer cut to size for the page (rows, depth, text): data only."""
    if depth > 8:
        return None
    if isinstance(v, dict):
        return {_s(k, 64): _cap(x, depth + 1) for k, x in list(v.items())[:100]}
    if isinstance(v, list):
        return [_cap(x, depth + 1) for x in v[:MAX_ROWS]]
    if isinstance(v, str):
        return _s(v, 500)
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    return _s(v, 200)


RESULT_PARTS = (("web_probe_metrics", "get_deeptrace_webprobe_metrics"), ("cloudpath_metrics", "get_deeptrace_cloudpath_metrics"),
                ("cloudpath", "get_deeptrace_cloudpath"), ("health_metrics", "get_deeptrace_health_metrics"), ("events", "get_deeptrace_events"))


def results(client: Any, device_id: str, trace_id: str, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """What a trace collected, part by part, each cut to size; errors per part."""
    z = _zdx(client).troubleshooting
    out: Dict[str, Any] = {"errors": {}}
    for key, method in RESULT_PARTS:
        _check_stop(cancel)
        body, err = _read(getattr(z, method), device_id, trace_id)
        if err:
            out["errors"][key] = err
            out[key] = None
            continue
        v = _cap(body)
        if len(json.dumps(v, default=str)) > MAX_RESULT_BYTES:
            v = {"note": "too large to show here: open the trace in the ZDX Admin Portal"}
        out[key] = v
    return out


_SEARCH_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{2,128}$")


def _app_row(a: Dict[str, Any]) -> Dict[str, Any]:
    region = a.get("most_impacted_region") if isinstance(a.get("most_impacted_region"), dict) else {}
    return {"id": _s(a.get("id"), 24), "name": _s(a.get("name"), 128), "score": a.get("score") if isinstance(a.get("score"), (int, float)) else None,
            "users": a.get("total_users") if isinstance(a.get("total_users"), (int, float)) else None,
            "most_impacted_region": _s(region.get("city") or region.get("country") or region.get("region"), 80)}


def app_scores(client: Any, hours: int = 2) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every application ZDX measures, with its ZDX score over the last hours (read-only)."""
    body, err = _read(_zdx(client).apps.list_apps, query_params={"since": hours})
    return [_app_row(a) for a in _items(body, "apps")][:MAX_ROWS], err


def lookup(client: Any, what: str, query: Dict[str, Any], cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read-only answers to the page's searches and views: users, devices,
    a device's health, applications (with their scores) and one
    application's performance on one device, the tenant's application
    scores and one application's score trend, and deep traces."""
    z = _zdx(client)
    if what == "users":
        term = str(query.get("user") or "").strip()
        if not _SEARCH_RE.match(term):
            raise _err("Type at least two characters of the user's name or email.")
        body, err = _read(z.users.list_users, query_params={"search": term, "since": 24})   # ASSUMED: ZDX filters users by q
        rows = []
        for u in _items(body, "users"):
            name, email = _s(u.get("name"), 128), _s(u.get("email"), 128)
            if term.lower() not in (name + " " + email).lower():
                continue   # the filter is assumed; anything else the API answers is not shown
            rows.append({"id": _s(u.get("id"), 24), "name": name, "email": email,
                         "devices": [{"id": _s(d.get("id"), 24), "name": _s(d.get("name"), 128)} for d in u.get("devices") or [] if isinstance(d, dict)][:50]})
        return {"users": rows[:MAX_ROWS], "error": err}
    if what == "app_scores":
        rows, err = app_scores(client)
        return {"apps": rows, "error": err}
    if what == "app_score":
        app = check_id(query.get("app_id"), "The application")
        body, err = _read(z.apps.get_app_score, app, query_params={"since": 24})
        return {"score": _cap(body), "error": err}
    if what == "devices":
        email = str(query.get("user") or "").strip()
        if not _EMAIL_RE.match(email):
            raise _err("Type the user's email address.")
        body, err = _read(z.devices.list_devices, query_params={"emails": [email]})
        devs = []
        for d in _items(body, "devices"):
            if isinstance(d.get("devices"), list):   # a user row with its devices
                devs += [dict(x, user=email) for x in d["devices"] if isinstance(x, dict)]
            else:
                devs.append(d)
        return {"devices": [{"id": _s(d.get("id"), 24), "name": _s(d.get("name") or d.get("device_name"), 128),
                             "user": _s(d.get("user_email") or d.get("email") or d.get("user") or email, 128)} for d in devs if _s(d.get("id"))][:MAX_ROWS],
                "error": err}
    device = check_id(query.get("device_id"), "The device")
    if what == "apps":
        body, err = _read(z.devices.get_device_apps, device)
        return {"apps": [_app_row(a) for a in _items(body, "apps")][:MAX_ROWS], "error": err}
    if what == "health":
        dev, e1 = _read(z.devices.get_device, device)
        hm, e2 = _read(z.devices.get_health_metrics, device, query_params={"since": 2})
        return {"device": _cap(dev), "health_metrics": _cap(hm), "error": e1 or e2}
    if what == "device_app":
        app = check_id(query.get("app_id"), "The application")
        body, err = _read(z.devices.get_device_app, device, app, query_params={"since": 2})
        return {"performance": _cap(body), "error": err}
    if what == "probes":
        app = check_id(query.get("app_id"), "The application")
        web, e1 = _read(z.devices.get_web_probes, device, app)
        cp, e2 = _read(z.devices.list_cloudpath_probes, device, app)
        return {"web_probes": [{"id": _s(p.get("id"), 24), "name": _s(p.get("name"), 128)} for p in _items(web, "probes")][:MAX_ROWS],
                "cloudpath_probes": [{"id": _s(p.get("id"), 24), "name": _s(p.get("name"), 128)} for p in _items(cp, "probes")][:MAX_ROWS],
                "error": e1 or e2}
    if what == "traces":
        rows, err = list_traces(client, device)
        return {"traces": rows, "error": err}
    trace = check_id(query.get("trace_id"), "The deep trace")
    if what == "trace":
        row, err = get_trace(client, device, trace)
        return {"trace": row, "error": err}
    if what == "results":
        return {"results": results(client, device, trace, cancel)}
    raise _err("Unknown lookup.")


def follow(client: Any, device_id: str, trace_id: str, *, log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
           max_polls: int = MAX_POLLS, interval: float = DEFAULT_INTERVAL, sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    """Poll one trace until it ends: at most min(max_polls, MAX_POLLS) reads,
    at least MIN_INTERVAL seconds apart, stopped by Stop. Read-only."""
    device_id, trace_id = check_id(device_id, "The device"), check_id(trace_id, "The deep trace")
    say = log or (lambda m: None)
    limit = max(1, min(int(max_polls or MAX_POLLS), MAX_POLLS))
    wait = max(MIN_INTERVAL, float(interval or DEFAULT_INTERVAL))
    polls, errors, last = 0, 0, None
    while polls < limit:
        if cancel is not None and cancel.is_set():
            return {"status": "stopped", "polls": polls, "trace": last, "final": False, "timed_out": False}
        row, err = get_trace(client, device_id, trace_id)
        polls += 1
        if err:
            if _gone(err) or err == "not found":
                say("The deep trace is gone (stopped or deleted).")
                return {"status": "gone", "polls": polls, "trace": last, "final": True, "timed_out": False}
            errors += 1
            say(f"Could not read the trace ({errors} of {MAX_ERRORS_IN_A_ROW}): {err}")
            if errors >= MAX_ERRORS_IN_A_ROW:
                return {"status": "unreadable", "polls": polls, "trace": last, "final": False, "timed_out": False, "error": err}
        else:
            errors, last = 0, row
            say(f"Read {polls} of at most {limit}: {row['status']}.")
            if row["ended"]:
                out = {"status": row["status"], "polls": polls, "trace": row, "final": True, "timed_out": False}
                if row["status"] in ("completed", "complete", "done", "finished"):
                    out["results"] = results(client, device_id, trace_id, cancel)
                return out
        if polls >= limit:
            break
        if cancel is not None:
            if cancel.wait(wait):
                return {"status": "stopped", "polls": polls, "trace": last, "final": False, "timed_out": False}
        else:
            sleep(wait)
    say(f"Stopped following after {polls} reads; the trace goes on in ZDX. Follow it again, or open it in the ZDX Admin Portal.")
    return {"status": (last or {}).get("status") or "unknown", "polls": polls, "trace": last, "final": False, "timed_out": True}


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """The tenant's application scores (read-only); devices are looked up per user."""
    _zdx(client)
    _check_stop(cancel)
    say("Reading the ZDX application scores (last 2 hours)…")
    apps, err = app_scores(client)
    say(f"{len(apps)} applications. Look the user's devices up by email.")
    return {"apps": apps, "lengths": list(LENGTHS), "limits": {"starts_per_hour": START_LIMIT, "device_cooldown_seconds": int(DEVICE_COOLDOWN),
                                                 "max_polls": MAX_POLLS, "min_interval_seconds": int(MIN_INTERVAL)},
            "assumed": list(ASSUMED), "errors": {"ZDX application scores": err} if err else {}}


# ---------------------------------------------------------------------------
# The start limit (this app's own; in memory, per tenant)
# ---------------------------------------------------------------------------

_STARTS: Dict[str, List[Tuple[float, str]]] = {}
_LIMIT_LOCK = threading.Lock()


def _tenant(client: Any) -> str:
    try:
        import zia_rate
        k = zia_rate.key_of(client)
        if k:
            return str(k)
    except Exception:  # noqa: BLE001
        pass
    return f"client-{id(client)}"


def limit_reason(client: Any, device_id: str, now: Optional[float] = None) -> Optional[str]:
    """Why another deep trace may not start now (None when it may)."""
    now = time.time() if now is None else now
    with _LIMIT_LOCK:
        recent = [(t, d) for t, d in _STARTS.get(_tenant(client), []) if now - t < 3600]
        _STARTS[_tenant(client)] = recent
    if len(recent) >= START_LIMIT:
        wait = int(3600 - (now - min(t for t, _ in recent))) + 1
        return f"{START_LIMIT} deep traces were started on this tenant in the last hour: wait {max(1, wait // 60)} minute(s)."
    last = max((t for t, d in recent if d == device_id), default=None)
    if last is not None and now - last < DEVICE_COOLDOWN:
        return f"A deep trace was started on this device {int(now - last)} seconds ago: wait {int(DEVICE_COOLDOWN - (now - last)) + 1} seconds."
    return None


def _note_start(client: Any, device_id: str, now: Optional[float] = None) -> None:
    with _LIMIT_LOCK:
        _STARTS.setdefault(_tenant(client), []).append((time.time() if now is None else now, device_id))


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------

def _done(t: str, title: str, spec: Dict[str, Any], items: List[Dict[str, Any]], groups: List[Dict[str, Any]], *, undo: str,
          warnings: Sequence[str] = (), blockers: Sequence[str] = (), notes: Sequence[str] = (), **extra: Any) -> Dict[str, Any]:
    return dict({"type": t, "product": "zdx", "title": title, "spec": spec, "items": items, "groups": groups, "undo_note": undo,
                 "warnings": list(dict.fromkeys(warnings)), "blockers": list(blockers),
                 "notes": [undo] + list(notes) + ["ZDX starts or stops the trace as it is asked; there is no activation step."]}, **extra)


def _obj(device_id: str, name: str, trace_id: str = "") -> Dict[str, Any]:
    return {"type": "zdx_deeptrace", "kind": "deeptrace", "label": "ZDX deep trace", "id": trace_id or None, "device_id": device_id, "name": name}


def plan_start(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    device = check_id(spec.get("device_id"), "The device")
    name = str(spec.get("session_name") or "").strip()
    if not _SESSION_RE.match(name):
        raise _err("The session name: 1 to 64 letters, digits, spaces and _ . -, starting with a letter or digit.")
    length = spec.get("session_length_minutes", 5)
    if isinstance(length, bool) or length not in LENGTHS:
        raise _err("The length must be 5, 15, 30 or 60 minutes.")
    probe_device = spec.get("probe_device", False)
    if not isinstance(probe_device, bool):
        raise _err("Collect the device's health: true or false.")
    body: Dict[str, Any] = {"session_name": name, "session_length_minutes": length, "probe_device": probe_device}
    for k, what in (("app_id", "The application"), ("web_probe_id", "The Web probe"), ("cloudpath_probe_id", "The CloudPath probe")):
        if spec.get(k) not in (None, ""):
            body[k] = check_id(spec.get(k), what)
    if ("web_probe_id" in body or "cloudpath_probe_id" in body) and "app_id" not in body:
        raise _err("Pick the application the probes belong to.")
    user = str(spec.get("user") or "").strip()[:128]
    nspec = dict({"type": T_START, "device_id": device}, **body)
    if user:
        nspec["user"] = user
    z = _zdx(client)
    _check_stop(cancel)
    say("Reading the device and its deep traces…")
    dev, err = _read(z.devices.get_device, device)
    blockers: List[str] = []
    if err:
        if not _gone(err):
            raise _err(f"The device could not be read, so nothing was planned: {err}")
        blockers.append("ZDX has no such device now. Look the user's devices up again.")
    dname = _s((dev or {}).get("name") if isinstance(dev, dict) else "", 128) or device
    traces, err = list_traces(client, device)
    if err:
        raise _err(f"The device's deep traces could not be read, so nothing was planned: {err}")
    running = [t for t in traces if t["running"]]
    if running:
        blockers.append(f"A deep trace is already running on this device ('{running[0]['session_name'] or running[0]['trace_id']}'): "
                        "wait for it to end or stop it first.")
    if "app_id" in body and not blockers:
        _check_stop(cancel)
        apps, err = _read(z.devices.get_device_apps, device)
        if not err and not any(_s(a.get("id")) == body["app_id"] for a in _items(apps, "apps")):
            blockers.append("This device has no such application in ZDX now: pick it again.")
        for k, method in (("web_probe_id", "get_web_probes"), ("cloudpath_probe_id", "list_cloudpath_probes")):
            if k in body and not blockers:
                probes, err = _read(getattr(z.devices, method), device, body["app_id"])
                if not err and not any(_s(p.get("id")) == body[k] for p in _items(probes, "probes")):
                    blockers.append("The probe you picked is not one of this application's probes on this device: pick it again.")
    why = limit_reason(client, device)
    if why:
        blockers.append(why)
    key = f"trace:{device}:{name}"
    what = f"{length} minutes" + (f", application {body['app_id']}" if "app_id" in body else "") + (", device health" if probe_device else "")
    items = [ao._unit(key, key, "deeptrace", _obj(device, f"{name} on {dname}" + (f" ({user})" if user else "")), "running", False, True, value=what,
                      reason="Starts it: POST /zdx/v1/devices/{id}/deeptraces (troubleshooting.start_deeptrace).")]
    groups = [] if blockers else [{"key": key, "handler": "zdx_adm_trace_start", "target": {"device_id": device, "body": body, "name": name}}]
    return _done(T_START, f"Start a {length}-minute ZDX deep trace on {dname}", nspec, items, groups, blockers=blockers,
                 warnings=["Client Connector on the user's device collects detailed measurements while it runs; the user is not interrupted."],
                 undo="Undo: stops the trace (ZDX deletes what it collected), previewed first.", notes=list(ASSUMED))


def plan_stop(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    device = check_id(spec.get("device_id"), "The device")
    trace = check_id(spec.get("trace_id"), "The deep trace")
    undo = spec.get("undo") is True
    nspec: Dict[str, Any] = {"type": T_STOP, "device_id": device, "trace_id": trace}
    if undo:
        nspec["undo"] = True
    _zdx(client)
    _check_stop(cancel)
    say("Reading the deep trace…")
    row, err = get_trace(client, device, trace)
    key = f"stop:{device}:{trace}"
    name = (row or {}).get("session_name") or trace
    items, groups = [], []
    if row is None:
        if not _gone(err) and err != "not found":
            raise _err(f"The deep trace could not be read, so nothing was planned: {err}")
        items.append(ao._unit(key, key, "deeptrace", _obj(device, name, trace), "exists", False, False, status="noop", reason="already gone"))
    else:
        items.append(ao._unit(key, key, "deeptrace", _obj(device, name, trace), "exists", True, False, value=row["status"],
                              reason="Stops it: DELETE /zdx/v1/devices/{id}/deeptraces/{trace} (troubleshooting.delete_deeptrace)."))
        groups.append({"key": key, "handler": "zdx_adm_trace_stop", "target": {"device_id": device, "trace_id": trace, "name": name}})
    return _done(T_STOP, ("Undo: stop" if undo else "Stop") + f" ZDX deep trace '{name}'", nspec, items, groups,
                 warnings=["ZDX deletes the session and everything it collected."] if groups else [],
                 confirm_always="DELETE DEEP TRACE" if groups else "",
                 undo="No Undo: a stopped deep trace and its results are deleted (start a new one).")


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def _write(fn: Callable[..., Any], *args: Any, op: str, name: str, log, oid: Any = None, kw: Optional[Dict[str, Any]] = None) -> ops.Outcome:
    def sdk_call(*a: Any, **k: Any) -> Any:
        ret = fn(*a, **k)
        data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
        if err:
            return (None, resp, err)
        body = None
        getter = getattr(resp, "get_body", None)
        if callable(getter):
            try:
                body = getter()
            except Exception:  # noqa: BLE001
                body = None
        if not isinstance(body, dict):
            body = _plain(data) if data is not None else {}
        rid = (body or {}).get("trace_id") or (body or {}).get("id") if isinstance(body, dict) else None
        return ({"id": rid}, resp, None)

    out = ops.call(sdk_call, *args, op=op, kind="zdx_deeptrace", name=name, log=log, kw=kw)
    out.data = None
    ops._audit_write(op, "zdx_deeptrace", out.id if op == "create" else oid, name, None, out)
    return out


def _fail_read(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    halt = ao._read_halt(err)
    if halt:
        run.halt = halt
        run.mark(units, "skipped", f"not attempted: {halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again right before the change: {err}"[:300])
        run.counts["failed"] += 1


def _h_start(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    why = limit_reason(run.client, t["device_id"])
    if why:
        run.mark(units, "skipped", f"not attempted: {why}")
        return
    traces, err = list_traces(run.client, t["device_id"])
    if err:
        _fail_read(run, units, err, "the device's deep traces")
        return
    if any(x["running"] for x in traces):
        run.mark(units, "conflict", "a deep trace started on this device since the preview; nothing was started")
        return
    out = _write(_zdx(run.client).troubleshooting.start_deeptrace, t["device_id"], op="create", name=t["name"], log=run.log, kw=dict(t["body"]))
    if run.outcome(units, out, "create"):
        _note_start(run.client, t["device_id"])
        tid = str(out.id or "")
        for u in units:
            u["object"] = dict(u["object"], id=tid or None)
        run.created.append({"type": "zdx_deeptrace", "device_id": t["device_id"], "trace_id": tid, "name": t["name"]})
        run.log(f"[ZDX deep trace] {t['name']}: started")


def _h_stop(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    row, err = get_trace(run.client, t["device_id"], t["trace_id"])
    if row is None:
        if _gone(err) or err == "not found":
            run.mark(units, "noop", "already gone")
            return
        _fail_read(run, units, err, "the deep trace")
        return
    out = _write(_zdx(run.client).troubleshooting.delete_deeptrace, t["device_id"], t["trace_id"], op="delete", name=t["name"], log=run.log,
                 oid=t["trace_id"])
    if run.outcome(units, out, "delete"):
        run.log(f"[ZDX deep trace] {t['name']}: stopped and deleted")


HANDLERS = {"zdx_adm_trace_start": _h_start, "zdx_adm_trace_stop": _h_stop}


def verify(run: Any) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t = g["target"]
        out["checked"] += len(applied)
        if g["handler"] == "zdx_adm_trace_start":
            tid = applied[0]["object"].get("id")
            if not tid:
                rows, err = list_traces(run.client, t["device_id"])
                ok = err is None and any(r["session_name"] == t["name"] for r in rows)
            else:
                row, err = get_trace(run.client, t["device_id"], tid)
                ok = row is not None
        else:
            row, err = get_trace(run.client, t["device_id"], t["trace_id"])
            ok = row is None and (_gone(err) or err == "not found")
            err = None if ok else (err if row is None else None)
        if not ok and err:
            out["unread"].append(f"{t['name']}: {err}")
            for u in applied:
                u["verified"] = None
            continue
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{t['name']}: not as expected when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The Undo of a start: stop that trace (a stop has none)."""
    if result.get("type") != T_START:
        return None
    made = next((c for c in result.get("created") or [] if c.get("type") == "zdx_deeptrace" and c.get("trace_id")), None)
    return {"type": T_STOP, "undo": True, "device_id": made["device_id"], "trace_id": made["trace_id"]} if made else None


_COMMON = dict(family=FAMILY, product="zdx", in_scope=in_scope, read_objects=read_objects, verify=verify, inverse=inverse,
               script="ops_admin.js", group=GROUP)

ao.register(T_START, label="Start a ZDX deep trace", plan=plan_start, handlers=HANDLERS,
            hint="Find the user's device, pick the application and its probes, the length and whether to collect device health, then start; "
                 "follow it and see the results. Rate-limited. Undo stops it.", **_COMMON)
ao.register(T_STOP, label="Stop a ZDX deep trace", plan=plan_stop, handlers=HANDLERS,
            hint="Stop a running deep trace: ZDX deletes it and what it collected. You type the confirmation. No Undo.", **_COMMON)
