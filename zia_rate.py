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
from typing import Callable, Deque, Dict, List, Optional, Tuple

DEFAULTS = {"write": "1/s,400/h", "delete": "1/s,400/h", "endpoint_rules": "10/m,40/h",
            "cloud_app": "10/m,40/h", "activate": "10/m,40/h"}
_ENV = {k: f"DLP_CHECK_ZIA_LIMIT_{k.upper()}" for k in DEFAULTS}
_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0}
_WORDS = {"write": "write (POST/PUT)", "delete": "delete", "endpoint_rules": "Endpoint DLP rule write",
          "cloud_app": "Cloud App Control rule write", "activate": "activation"}
_PER = {1.0: "a second", 60.0: "a minute", 3600.0: "an hour"}

# Tests replace these two.
_sleep: Callable[[float], None] = time.sleep
_now: Callable[[], float] = time.monotonic

_lock = threading.Lock()
_sent: Dict[str, Deque[float]] = {k: deque() for k in DEFAULTS}


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
    return total


def estimate(bucket: str, count: int) -> float:
    """Seconds `count` requests of `bucket` take at the configured limits,
    starting from an empty window (for a removal's time estimate)."""
    if count <= 0:
        return 0.0
    worst = 0.0
    for n, w in limits(bucket):
        worst = max(worst, ((count - 1) // n) * w)
    return worst


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
