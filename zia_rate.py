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
            "cloud_app": "10/m,40/h", "activate": "10/m,40/h"}
_ENV = {k: f"DLP_CHECK_ZIA_LIMIT_{k.upper()}" for k in DEFAULTS}
_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0}
_WORDS = {"write": "write (POST/PUT)", "delete": "delete", "endpoint_rules": "Endpoint DLP rule write",
          "cloud_app": "Cloud App Control rule write", "activate": "activation"}
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


def _save() -> None:
    """Write the requests of the last hour. Called with _lock held; a file
    that cannot be written only loses the memory across restarts."""
    try:
        import json
        now = _now()
        data = {"sent": {k: [t for t in q if now - t < 3600] for k, q in _sent.items()}, "hold_until": _hold_until[0]}
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
                 "endpoint_rules": "Endpoint DLP rules", "cloud_app": "Cloud App Control rules", "activate": "activations"}


def _rules_text(bucket: str) -> str:
    unit = {1.0: "sec", 60.0: "min", 3600.0: "hr"}
    return " and ".join(f"{n}/{unit.get(w, f'{w:.0f}s')}" for n, w in limits_default(bucket))


def forecast(counts: Dict[str, int], *, use_recent: bool = True) -> Dict[str, Any]:
    """What a run of `counts` requests per bucket meets at ZIA's limits:
    per bucket the requests already sent in the last hour (use_recent),
    how long the run's requests take, and whether they pause for a limit
    because of what was sent recently. Simulated, nothing is sent."""
    rows = []
    now = _now()
    with _lock:
        if use_recent:
            _load()
        recent = {k: [t for t in q if now - t < 3600] for k, q in _sent.items()} if use_recent else {k: [] for k in _sent}
        held = max(0.0, _hold_until[0] - now) if use_recent else 0.0
    for bucket, n in counts.items():
        if n <= 0 or bucket not in DEFAULTS:
            continue
        rules = limits_default(bucket)
        sim = list(recent.get(bucket, []))
        t = now + held
        for _ in range(n):
            wait_s = 0.0
            for lim, w in rules:
                inside = [x for x in sim if t - x < w]
                if len(inside) >= lim:
                    wait_s = max(wait_s, inside[-lim] + w - t)
            t += max(0.0, wait_s)
            sim.append(t)
        took = t - now
        fresh = estimate(bucket, n)
        hourly = max((lim for lim, w in rules if w >= 3600), default=None)
        used = len(recent.get(bucket, []))
        rows.append({"bucket": bucket, "label": BUCKET_LABELS[bucket], "requests": n, "limits": _rules_text(bucket),
                     "used_last_hour": used, "hourly_limit": hourly, "seconds": took, "fresh_seconds": fresh,
                     "pauses": took > fresh + 60, "over_hourly": bool(hourly and n > hourly)})
    total = max((r["seconds"] for r in rows), default=0.0)
    pausing = [r for r in rows if r["pauses"] or r["over_hourly"]]
    if not rows:
        verdict, severity = "Nothing to send.", "info"
    elif held > 0:
        verdict, severity = f"ZIA's rate limit is still resetting from an earlier refusal: this run starts in {_human(held)}.", "warn"
    elif pausing:
        why = "; ".join(
            (f"{r['label']}: {r['requests']} needed, over the {r['hourly_limit']}/hr limit on its own" if r["over_hourly"] else
             f"{r['label']}: {r['used_last_hour']} of {r['hourly_limit']}/hr already used in the last hour")
            for r in pausing)
        verdict, severity = (f"Will succeed, but pauses for ZIA's hourly limit: about {_human(total)} in all ({why}). "
                             "The run waits and carries on by itself."), "warn"
    else:
        verdict, severity = f"Goes straight through within ZIA's rate limits: about {_human(total)}.", "ok"
    return {"buckets": rows, "seconds": total, "verdict": verdict, "severity": severity,
            "recent": {k: len(v) for k, v in recent.items()} if use_recent else {}}


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
        _loaded[0] = True   # a reset is a fresh start: do not read the file back
