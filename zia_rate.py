"""ZIA's API rate limits, kept on the app's side so a deploy or removal
waits instead of being refused.

Source: ZIA API Rate Limit Summary,
https://help.zscaler.com/legacy-apis/api-rate-limit-summary (read
2026-09-30). For the endpoints a policy pack writes to:

    dlpDictionaries, dlpEngines, webDlpRules, casbDlpRules,
    emailDlpRules, fileTypeRules, urlFilteringRules,
    sslInspectionRules, endPointApplicationGroups
        POST, PUT, DELETE   1 per second, 400 per hour
    endPointDlpRules (and its sub-rules)
        POST, PUT           10 per minute, 40 per hour
        DELETE              1 per second, 400 per hour
    webApplicationRules/{type} (Cloud App Control)
        POST                10 per minute, 40 per hour
    status/activate (an activation)
        POST                10 per minute, 40 per hour

Going over answers 429, and a burst of refused requests gets the API
client blocked for minutes (403 "Resource Access Blocked").

Each bucket's limits are a setting, "<count>/<s|m|h>" pairs separated
by commas; "0" or "off" turns a bucket off:

    DLP_CHECK_ZIA_LIMIT_WRITE           default "1/s,400/h"
    DLP_CHECK_ZIA_LIMIT_DELETE          default "1/s,400/h"
    DLP_CHECK_ZIA_LIMIT_ENDPOINT_RULES  default "10/m,40/h"
    DLP_CHECK_ZIA_LIMIT_CLOUD_APP       default "10/m,40/h"
    DLP_CHECK_ZIA_LIMIT_ACTIVATE        default "10/m,40/h"

Only writes are held back here: reads already have the assessment
client's own pacing."""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

DEFAULTS = {"write": "1/s,400/h", "delete": "1/s,400/h", "endpoint_rules": "10/m,40/h",
            "cloud_app": "10/m,40/h", "activate": "10/m,40/h",
            # GETs: counted from what the app sent (the HTTP tap), not paced.
            "read": "2/s,1000/h"}
_ENV = {k: f"DLP_CHECK_ZIA_LIMIT_{k.upper()}" for k in DEFAULTS}
_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0}
_WORDS = {"write": "write (POST/PUT)", "delete": "delete", "endpoint_rules": "Endpoint DLP rule write",
          "cloud_app": "Cloud App Control rule write", "activate": "activation", "read": "read (GET)"}
_PER = {1.0: "a second", 60.0: "a minute", 3600.0: "an hour"}

# Tests replace these two. Wall-clock seconds, so the requests counted
# survive a restart (the state file) and a forecast can use them.
_sleep: Callable[[float], None] = time.sleep
_now: Callable[[], float] = time.time

_lock = threading.Lock()
_sent: Dict[str, Deque[float]] = {k: deque() for k in DEFAULTS}
# After ZIA refuses a request for its rate (429, or 403 "Resource Access
# Blocked"), nothing more is sent until this moment: the limit's window
# has completely reset. Every bucket honours it.
_hold_until = [0.0]
_loaded = [False]
# Rate refusals ZIA gave in the last week: (when, bucket, message, and the
# requests of every kind this app had sent in the minute, 5 minutes and
# hour before it). The last hour decides "likely to fail"; the week is what
# ZIA has shown it tolerates from this client, whatever its documentation says.
_refused: Deque[Tuple[Any, ...]] = deque()
HISTORY_SECONDS = 7 * 24 * 3600
# ZIA's own count per bucket, from the x-ratelimit headers of the last write.
_server: Dict[str, Dict[str, Any]] = {}


def state_path() -> str:
    """Where the requests of the last hour are kept: DLP_CHECK_ZIA_RATE_STATE
    (the container keeps it on /data), else next to the app."""
    return os.environ.get("DLP_CHECK_ZIA_RATE_STATE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "zia_rate_state.json")


def _load() -> None:
    """Read the requests of the last hour once, so a restart or another run
    does not start from an empty count. Called with _lock held."""
    if _loaded[0]:
        return
    _loaded[0] = True
    try:
        import json
        with open(state_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001 - no file yet, or unreadable: start empty
        return
    now = _now()
    for k, ts in (data.get("sent") or {}).items():
        if k in _sent:
            _sent[k].extend(sorted(float(t) for t in ts if now - float(t) < 3600))
    _hold_until[0] = max(_hold_until[0], float(data.get("hold_until") or 0))
    _refused.extend(tuple(r) + (None,) * (6 - len(r)) for r in (data.get("refused") or []) if now - float(r[0]) < HISTORY_SECONDS)
    if "refused" not in data and _hold_until[0] > now:
        # Written before refusals were kept: a hold is only ever set after ZIA
        # refused a request for its rate, at the last request sent.
        last = max((t for q in _sent.values() for t in q), default=None)
        if last is not None:
            _refused.append((last, "write", "Resource Access Blocked (from the earlier run's hold)") + _windows_at(last))
    for k, v in (data.get("server") or {}).items():
        if k in DEFAULTS and isinstance(v, dict):
            _server.setdefault(k, v)


def _save() -> None:
    """Write the requests of the last hour. Called with _lock held; a file
    that cannot be written only loses the memory across restarts."""
    try:
        import json
        now = _now()
        while _refused and now - _refused[0][0] >= HISTORY_SECONDS:
            _refused.popleft()
        data = {"sent": {k: [t for t in q if now - t < 3600] for k, q in _sent.items()}, "hold_until": _hold_until[0],
                "refused": [list(r) for r in _refused], "server": _server}
        p = state_path()
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def limits(bucket: str) -> List[Tuple[int, float]]:
    """(count, window seconds) pairs for a bucket, from its setting."""
    raw = (os.environ.get(_ENV[bucket]) or DEFAULTS[bucket]).strip().lower()
    if raw in ("0", "off", "none", ""):
        return []
    out = []
    for part in raw.split(","):
        try:
            n, unit = part.strip().split("/")
            out.append((int(n), _UNITS[unit.strip()[:1]]))
        except (ValueError, KeyError):
            continue
    return [(n, w) for n, w in out if n > 0]


def bucket_of(method: str, path: str = "", *, channel: Optional[str] = None, kind: Optional[str] = None) -> str:
    """The limit a request draws on, from its method and its endpoint (a
    path, or the pack's channel and object kind)."""
    m = (method or "").upper()
    p = (path or "").lower()
    if "status/activate" in p or kind == "activation":
        return "activate"
    if m == "DELETE":
        return "delete"
    if "endpointdlprules" in p or (channel == "endpoint" and kind == "policy"):
        return "endpoint_rules"
    if "webapplicationrules" in p or (channel == "cloud_app" and kind == "policy"):
        return "cloud_app"
    return "write"


def _delay(bucket: str, now: float) -> Tuple[float, Optional[Tuple[int, float]]]:
    """Seconds until the next request of `bucket` fits every limit, and the
    limit that sets it (None when it fits now)."""
    sent = _sent[bucket]
    rules = limits(bucket)
    longest = max((w for _, w in rules), default=0)
    while sent and now - sent[0] >= longest:
        sent.popleft()
    wait, binding = 0.0, None
    for n, w in rules:
        recent = [t for t in sent if now - t < w]
        if len(recent) >= n:
            d = recent[-n] + w - now
            if d > wait:
                wait, binding = d, (n, w)
    return wait, binding


def wait(method: str, path: str = "", log: Optional[Callable[[str], None]] = None, what: str = "", *,
         channel: Optional[str] = None, kind: Optional[str] = None) -> float:
    """Block until one more request fits ZIA's limits, then count it.
    Returns the seconds waited. A wait long enough to notice is logged
    with the limit and the time the request goes out."""
    bucket = bucket_of(method, path, channel=channel, kind=kind)
    total = 0.0
    with _lock:
        _load()
    held = _hold_until[0] - _now()
    if held > 0:
        if log:
            log(f"{what + ': ' if what else ''}ZIA's rate limit is still resetting; waiting {_human(held)} more before sending anything.")
        _sleep(held)
        total += held
    with _lock:
        while True:
            d, binding = _delay(bucket, _now())
            if d <= 0:
                break
            if log and d >= 5 and binding:
                at = (datetime.now() + timedelta(seconds=d)).strftime("%H:%M")
                n, w = binding
                log(f"{what + ': ' if what else ''}ZIA allows {n} {_WORDS[bucket]}{'s' if n != 1 else ''} {_PER.get(w, f'per {w:.0f}s')}; "
                    f"waiting {_human(d)} (next at {at}).")
            _sleep(d)
            total += d
        _sent[bucket].append(_now())
        _save()
    return total


def full_reset(bucket: str) -> float:
    """Seconds until the limit's timer has completely elapsed for `bucket`:
    every request of it this app counted has aged out of the bucket's
    longest window. When none is counted (the limit was reached by other
    traffic), a whole longest window."""
    rules = limits(bucket) or limits_default(bucket)
    longest = max((w for _, w in rules), default=60.0)
    now = _now()
    with _lock:
        sent = _sent[bucket]
        while sent and now - sent[0] >= longest:
            sent.popleft()
        return (sent[0] + longest - now) if sent else longest


def limits_default(bucket: str) -> List[Tuple[int, float]]:
    """A bucket's limits from its default, whatever the setting says (a
    bucket turned off still has a window to wait out after a refusal)."""
    out = []
    for part in DEFAULTS[bucket].split(","):
        n, unit = part.split("/")
        out.append((int(n), _UNITS[unit[:1]]))
    return out


def hold(seconds: float) -> float:
    """Send nothing more, in any bucket, for `seconds`. Returns the moment
    (monotonic) the hold ends."""
    with _lock:
        _load()
        _hold_until[0] = max(_hold_until[0], _now() + max(0.0, seconds))
        _save()
        return _hold_until[0]


def estimate(bucket: str, count: int) -> float:
    """Seconds `count` requests of `bucket` take at the configured limits,
    starting from an empty window (for a removal's time estimate)."""
    if count <= 0:
        return 0.0
    worst = 0.0
    for n, w in limits(bucket):
        worst = max(worst, ((count - 1) // n) * w)
    return worst


BUCKET_LABELS = {"write": "dictionaries, engines and rules (POST/PUT)", "delete": "deletes",
                 "endpoint_rules": "Endpoint DLP rules", "cloud_app": "Cloud App Control rules", "activate": "activations",
                 "read": "reads (GET)"}


def _rules_text(bucket: str) -> str:
    unit = {1.0: "sec", 60.0: "min", 3600.0: "hr"}
    return " and ".join(f"{n}/{unit.get(w, f'{w:.0f}s')}" for n, w in limits_default(bucket))


def _clock(t: float) -> str:
    return time.strftime("%H:%M", time.localtime(t))


def _day_clock(t: float) -> str:
    return time.strftime("%b %d %H:%M", time.localtime(t))


def _windows_at(t: float) -> Tuple[int, int, int]:
    """Requests of every kind this app sent in the minute, 5 minutes and hour
    up to `t`. Called with _lock held."""
    every = [x for q in _sent.values() for x in q if x <= t]
    return tuple(sum(1 for x in every if t - x < w) for w in (60, 300, 3600))


def _server_used(bucket: str, now: float) -> List[float]:
    """Requests ZIA itself counts against `bucket`, from the x-ratelimit
    headers of its last answer: (limit - remaining) requests that leave the
    window when ZIA's reset timer runs out. This includes other tools on
    the same API client, which this app's own record cannot see."""
    s = _server.get(bucket)
    if not s or s.get("limit") is None or s.get("remaining") is None or not s.get("reset"):
        return []
    ends = s["at"] + s["reset"]
    if ends <= now:
        return []
    w = next((w for lim, w in limits_default(bucket) if lim == s["limit"]), None)
    if w is None:
        return []
    return [ends - w] * max(0, int(s["limit"]) - int(s["remaining"]))


def _deployment_refusals(now: float) -> List[Tuple[float, str]]:
    """Runs in the deployment log of the last week that ZIA refused for its
    rate: (when, what it answered)."""
    try:
        import deployments
        from datetime import datetime as _dt
        rows = deployments._read()["deployments"]
    except Exception:  # noqa: BLE001
        return []
    out = []
    for r in rows:
        for when, results in ((r.get("at"), (r.get("created") or []) + (r.get("other") or []) + (r.get("failed") or [])),
                              ((r.get("undo") or {}).get("at"), (r.get("undo") or {}).get("results") or [])):
            if not when:
                continue
            try:
                t = _dt.fromisoformat(str(when)).timestamp()
            except ValueError:
                continue
            if now - t >= HISTORY_SECONDS:
                continue
            hit = next((str(x.get("error") or "") for x in results if isinstance(x, dict) and _is_rate_answer(None, str(x.get("error") or ""))), None)
            if hit:
                out.append((t, hit))
    return sorted(out)


def _is_rate_answer(status: Optional[int], text: str) -> bool:
    low = (text or "").lower()
    return status == 429 or "resource access blocked" in low or "rate limit" in low or "too many requests" in low


def forecast(counts: Dict[str, int], *, use_recent: bool = True) -> Dict[str, Any]:
    """Will a run of `counts` requests per bucket succeed at ZIA's limits?
    Simulated, nothing is sent, against what this app actually executed:
    every request it sent to ZIA in the last hour (reads included), ZIA's
    own count from its rate-limit headers, the rate refusals ZIA gave, and
    the traffic ZIA tolerated before refusing.

    severity "ok": will succeed, straight through. "warn": will succeed,
    pausing for a limit. "fail": likely to fail, because ZIA refused this
    client in the last hour, or refused it before at less traffic than
    this run sends (ZIA's real limit is lower than its documentation)."""
    rows = []
    now = _now()
    with _lock:
        if use_recent:
            _load()
        recent = {k: [t for t in q if now - t < 3600] for k, q in _sent.items()} if use_recent else {k: [] for k in _sent}
        held = max(0.0, _hold_until[0] - now) if use_recent else 0.0
        refused = list(_refused) if use_recent else []
    planned: List[float] = []
    for bucket, n in counts.items():
        if n <= 0 or bucket not in DEFAULTS:
            continue
        rules = limits_default(bucket)
        mine = sorted(recent.get(bucket, []))
        zia = sorted(_server_used(bucket, now)) if use_recent else []
        sim = list(zia) if len(zia) > len([t for t in mine if zia and t >= zia[0]]) else list(mine)
        t = now + held
        for _ in range(n):
            wait_s = 0.0
            for lim, w in rules:
                inside = [x for x in sim if t - x < w]
                if len(inside) >= lim:
                    wait_s = max(wait_s, inside[-lim] + w - t)
            t += max(0.0, wait_s)
            sim.append(t)
            planned.append(t)
        took = t - now
        fresh = estimate(bucket, n)
        hourly = max((lim for lim, w in rules if w >= 3600), default=None)
        rows.append({"bucket": bucket, "label": BUCKET_LABELS.get(bucket, bucket), "requests": n, "limits": _rules_text(bucket),
                     "used_last_hour": len(mine), "zia_reports_used": len(zia) if zia else None,
                     "hourly_limit": hourly, "seconds": took, "fresh_seconds": fresh,
                     "pauses": took > fresh + 60, "over_hourly": bool(hourly and n > hourly),
                     "refused_last_hour": sum(1 for r in refused if r[1] == bucket and now - r[0] < 3600)})
    total = max((r["seconds"] for r in rows), default=0.0)
    # Busiest 5 minutes of this run, counting what was already sent.
    everything = sorted([x for q in recent.values() for x in q] + planned)
    peak5 = 0
    j = 0
    for i, x in enumerate(everything):
        while x - everything[j] >= 300:
            j += 1
        if x >= now:
            peak5 = max(peak5, i - j + 1)
    # What ZIA has shown it tolerates: the least traffic it refused at.
    tolerated = [r for r in refused if r[4]]
    ceiling = min(tolerated, key=lambda r: r[4]) if tolerated else None
    used_buckets = {r["bucket"] for r in rows}
    # "Resource Access Blocked" blocks the client as a whole; a 429 only its endpoint.
    hits = [r for r in refused if now - r[0] < 3600 and (r[1] in used_buckets or "blocked" in str(r[2]).lower())]
    history = _deployment_refusals(now) if use_recent else []
    sent_hour = {k: len(v) for k, v in recent.items() if v}
    if not rows:
        verdict, severity = "Nothing to send.", "ok"
    elif hits:
        last = max(hits, key=lambda r: r[0])
        verdict, severity = (f"Likely to fail: ZIA refused this API client {len(hits)} time(s) in the last hour "
                             f"(last at {_clock(last[0])}: '{last[2]}'"
                             + (f", after {last[4]} requests from DLP-Check in 5 minutes" if last[4] else "")
                             + f"). Run it after {_clock(last[0] + 3600)}, an hour after that refusal; a run started now "
                             f"pauses for an hour at each refusal and stops after {3}."), "fail"
    elif ceiling and peak5 >= ceiling[4]:
        verdict, severity = (f"Likely to fail: on {_day_clock(ceiling[0])} ZIA blocked this API client after {ceiling[4]} requests "
                             f"in 5 minutes ('{ceiling[2]}'), far below its documented limits, and this run sends up to {peak5} in its "
                             f"busiest 5 minutes. Deploy one channel at a time, and do not run an assessment meanwhile."), "fail"
    elif held > 0:
        verdict, severity = (f"Will succeed, with a pause: ZIA's rate limit is still resetting from an earlier refusal, "
                             f"so this run starts at {_clock(now + held)} ({_human(held)} from now) and takes about {_human(total)} in all."), "warn"
    elif ceiling and peak5 >= 0.8 * ceiling[4]:
        verdict, severity = (f"Will probably succeed, close to what ZIA tolerates: it blocked this client on {_day_clock(ceiling[0])} "
                             f"after {ceiling[4]} requests in 5 minutes, and this run sends up to {peak5}. About {_human(total)}."), "warn"
    else:
        pausing = [r for r in rows if r["pauses"] or r["over_hourly"]]
        if pausing:
            why = "; ".join(
                (f"{r['label']}: {r['requests']} needed, over the {r['hourly_limit']}/hr limit on its own" if r["over_hourly"] else
                 f"{r['label']}: {max(r['used_last_hour'], r['zia_reports_used'] or 0)} of {r['hourly_limit']}/hr already used in the last hour"
                 + (" (ZIA's own count)" if (r["zia_reports_used"] or 0) > r["used_last_hour"] else ""))
                for r in pausing)
            verdict, severity = (f"Will succeed, with pauses for ZIA's hourly limit: about {_human(total)} in all, done around "
                                 f"{_clock(now + total)} ({why}). The run waits and carries on by itself."), "warn"
        else:
            verdict, severity = f"Will succeed: goes straight through within ZIA's rate limits, about {_human(total)}.", "ok"
    return {"buckets": rows, "seconds": total, "verdict": verdict, "severity": severity,
            "title": {"ok": "Will succeed", "warn": "Will succeed, with pauses", "fail": "Likely to fail"}[severity],
            "refused_last_hour": len(hits), "peak_5min": peak5,
            "tolerated": {"at": ceiling[0], "requests_5min": ceiling[4], "requests_1min": ceiling[3], "message": ceiling[2]} if ceiling else None,
            "sent_last_hour": sent_hour, "refused_runs": [{"at": t, "error": e} for t, e in history],
            "recent": {k: len(v) for k, v in recent.items()} if use_recent else {}}


def history_text(f: Dict[str, Any]) -> str:
    """What the app executed that the check is based on, in one line."""
    parts = []
    sent = f.get("sent_last_hour") or {}
    if sent:
        plural = {"write": "writes (POST/PUT)", "delete": "deletes", "endpoint_rules": "Endpoint DLP rule writes",
                  "cloud_app": "Cloud App Control rule writes", "activate": "activations", "read": "reads (GET)"}
        parts.append("In the last hour DLP-Check sent ZIA " + ", ".join(f"{n} {plural.get(k, k)}" for k, n in sent.items()) + ".")
    else:
        parts.append("DLP-Check sent ZIA nothing in the last hour.")
    tol = f.get("tolerated")
    if tol:
        parts.append(f"Most traffic ZIA refused at: {tol['requests_5min']} requests in 5 minutes ({_day_clock(tol['at'])}).")
    runs = f.get("refused_runs") or []
    if runs:
        parts.append(f"{len(runs)} run(s) in the deployment log of the last week were refused for ZIA's rate (latest {_day_clock(runs[-1]['at'])}).")
    return " ".join(parts)


def note_refusal(bucket: str, message: str) -> None:
    """ZIA refused a request for its rate (429, or 403 Resource Access
    Blocked): kept for a week with the traffic that led to it."""
    with _lock:
        _load()
        now = _now()
        if _refused and _refused[-1][1] == bucket and now - _refused[-1][0] < 2:
            return   # the same refusal seen twice
        _refused.append((now, bucket, str(message or "")[:160]) + _windows_at(now))
        _save()


def note_headers(bucket: str, headers: Any) -> None:
    """Keep ZIA's own count for `bucket` from an answer's x-ratelimit headers."""
    try:
        low = {str(k).lower(): v for k, v in dict(headers or {}).items()}
    except Exception:  # noqa: BLE001
        return
    def first(k: str) -> Optional[float]:
        try:
            return float(str(low.get(k, "")).split(",")[0].split(";")[0].strip())
        except ValueError:
            return None
    lim, rem, rst = first("x-ratelimit-limit"), first("x-ratelimit-remaining"), first("x-ratelimit-reset")
    if lim is None or rem is None:
        return
    with _lock:
        _load()
        _server[bucket] = {"at": _now(), "limit": int(lim), "remaining": int(rem), "reset": rst}
        _save()


def _zia_path(url: str) -> Optional[str]:
    """The ZIA API path of a request URL (OneAPI /zia/api/v1/... or the
    legacy /api/v1/...), None for anything else."""
    from urllib.parse import urlparse
    u = urlparse(url or "")
    p = u.path or ""
    if "/zia/api/v1/" in p:
        return p.split("/zia/api/v1", 1)[1]
    if p.startswith("/api/v1/") and "zsapi" in (u.netloc or ""):
        return p[len("/api/v1"):]
    return None


def observe(method: str, url: str, status: Optional[int], headers: Any = None, text: str = "") -> None:
    """Every ZIA request the app sends passes here (install_tap): reads are
    counted (writes are already counted by wait), and ZIA's rate-limit
    headers and rate refusals are kept for the next preflight."""
    path = _zia_path(url)
    if path is None or "authenticatedsession" in path.lower():
        return
    m = (method or "GET").upper()
    bucket = "read" if m == "GET" else bucket_of(m, path)
    with _lock:
        _load()
        if m == "GET":
            _sent["read"].append(_now())
            while _sent["read"] and _now() - _sent["read"][0] >= 3600:
                _sent["read"].popleft()
    if headers is not None:
        note_headers(bucket, headers)
    if status in (403, 429) and _is_rate_answer(status, text):
        note_refusal(bucket, (text or f"HTTP {status}")[:160])
    elif m == "GET" and len(_sent["read"]) % 25 == 0:
        with _lock:
            _save()


_tapped = [False]


def install_tap() -> None:
    """Count every request this process sends to ZIA, whichever code sends
    it (the SDK, the assessment's session): one wrapper on requests'
    HTTPAdapter.send. Idempotent; a failure to observe never fails a request."""
    if _tapped[0]:
        return
    try:
        from requests.adapters import HTTPAdapter
    except Exception:  # noqa: BLE001
        return
    real = HTTPAdapter.send

    def send(self, request, *args, **kwargs):
        resp = real(self, request, *args, **kwargs)
        try:
            if _zia_path(getattr(request, "url", "")) is not None:
                text = ""
                if resp is not None and resp.status_code in (403, 429) and not kwargs.get("stream"):
                    text = (resp.text or "")[:300]
                observe(request.method, request.url, getattr(resp, "status_code", None), getattr(resp, "headers", None), text)
        except Exception:  # noqa: BLE001
            pass
        return resp

    HTTPAdapter.send = send
    _tapped[0] = True


def pack_counts(meta: Dict[str, Any]) -> Tuple[Dict[str, int], Dict[str, int]]:
    """(deploy, remove) request counts per bucket for a whole pack, from its
    metadata (dictionaries, engines, app_groups, channels): one activation each."""
    ch = meta.get("channels") or {}
    deploy = {"write": int(meta.get("dictionaries") or 0) + int(meta.get("engines") or 0) + int(meta.get("app_groups") or 0)
                       + sum(int(v) for k, v in ch.items() if k not in ("endpoint", "cloud_app")),
              "endpoint_rules": int(ch.get("endpoint") or 0), "cloud_app": int(ch.get("cloud_app") or 0), "activate": 1}
    total = int(meta.get("dictionaries") or 0) + int(meta.get("engines") or 0) + int(meta.get("app_groups") or 0) + sum(int(v) for v in ch.values())
    remove = {"delete": total, "activate": 1}
    return deploy, remove


def pack_note(meta: Dict[str, Any]) -> Dict[str, Any]:
    """How a pack measures against ZIA's rate limits, from a fresh start:
    a full deploy and a full removal, and each channel on its own."""
    deploy, remove = pack_counts(meta)
    d, r = forecast(deploy, use_recent=False), forecast(remove, use_recent=False)
    per_channel = {}
    for chan, n in (meta.get("channels") or {}).items():
        b = "endpoint_rules" if chan == "endpoint" else ("cloud_app" if chan == "cloud_app" else "write")
        per_channel[chan] = {"rules": int(n), "bucket": b, "seconds": estimate(b, int(n)),
                             "over_hourly": int(n) > max((lim for lim, w in limits_default(b) if w >= 3600), default=10 ** 9)}
    tight = [c for c, v in per_channel.items() if v["bucket"] != "write"]
    text = (f"Full deploy: {sum(deploy.values())} requests, about {_human(d['seconds'])} at ZIA's limits"
            + (f" (Endpoint DLP rules go at 10/min and 40/hr)" if "endpoint" in tight else "")
            + f". Removal: {remove['delete']} deletes, about {_human(r['seconds'])}.")
    over = [c for c, v in per_channel.items() if v["over_hourly"]]
    if over:
        text += f" {', '.join(over)} has more rules than ZIA allows in an hour, so that channel spans more than an hour."
    return {"deploy": deploy, "remove": remove, "deploy_seconds": d["seconds"], "remove_seconds": r["seconds"],
            "channels": per_channel, "text": text}


def _human(seconds: float) -> str:
    s = int(round(seconds))
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{round(s / 60)} min"
    return f"{s / 3600:.1f} h"


def human(seconds: float) -> str:
    return _human(seconds)


def reset() -> None:
    """Forget every request counted (tests)."""
    with _lock:
        for q in _sent.values():
            q.clear()
        _hold_until[0] = 0.0
        _refused.clear()
        _server.clear()
        _loaded[0] = True   # a reset is a fresh start: do not read the file back
