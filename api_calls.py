"""API calls: every Zscaler API call this app made since it started.

A diagnostics log for the operator ("which call failed, how long did it
take, did ZIA make us wait?"), in memory only, bounded and cleared on
restart. Each row is one API call:

    seq, at (UTC), product, method, path (a template: every id masked),
    status, ms (duration), retries, wait_ms (rate-limit and back-off
    waits), error (a class word, never a message), job, job_kind

What a row never holds: a request or response body, a header (so never a
token, a cookie or a secret), the query string, the host (it names the
tenant's cloud and vanity domain) or any path segment that is not a fixed
word of the API (ids, names and anything else a tenant chose become
``{id}``). Error text is never kept: only a category ("rate_limited",
"denied", "server_error", "network" …) and the exception's class name.

Where the calls are seen (nothing changes how a call is sent):

* ``attach(session)``: a requests.Session's ``send``, timed. Every
  session zia_rate.attach paces is attached here too, so the assessment's
  raw client, the OneAPI SDK client and the classic ZIA API client are all
  covered (dlp_api_server._build_sdk_client, tenant_auth).
* ``install_sdk_hooks()``: the Zscaler SDK's RequestExecutor.execute and
  HTTPClient.send_request (zscaler-sdk-python 1.11.3, request_executor.py
  and oneapi_http_client.py), wrapped once at class level so one SDK call
  with its 401 refresh and 429/5xx retries is one row, also for a client
  whose session is not attached (sdk_client.SdkClient, the MCP server).
* ``note_wait(seconds)``: zia_rate.wait reports the seconds it held a
  request for ZIA's rate limit; they are added to the next call of the
  same thread.

Retries a caller makes itself (the assessment client sends the same GET
again after a 429) are folded into the earlier row: the same thread, the
same method and path, the earlier answer retryable (401, 409, 429, 5xx or
no answer) and less than RETRY_WINDOW seconds apart. The gap counts as a
wait.

The size is DLP_CHECK_API_CALLS_MAX rows (default 1000, 50 to 20000); the
oldest row goes first. Rows are tagged with the job (pack_jobs) whose
thread made the call, so a builder's run can be listed on its own.
"""
from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

DEFAULT_MAX = 1000
MIN_MAX, MAX_MAX = 50, 20000
RETRY_WINDOW = 900.0          # seconds: a retry later than this is a new call
MAX_PATH_CHARS = 200
FIELDS = ("seq", "at", "product", "method", "path", "status", "ms", "retries", "wait_ms", "error", "job", "job_kind")
RETRYABLE = frozenset({401, 409, 429, 500, 502, 503, 504})
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# A path segment kept as it is: a fixed word of the API (letters, _ and -,
# starting with a letter) or a version (v1, v2). Everything else is an id
# or a value someone chose, and is masked.
_WORD = re.compile(r"[A-Za-z][A-Za-z_-]{0,63}")
_VERSION = re.compile(r"v\d{1,2}")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,48}")
_JOB = re.compile(r"[A-Za-z0-9_-]{1,40}")

# The API's first path word -> the product it belongs to (the OneAPI
# gateway's prefixes, as zscaler-sdk-python's request_executor routes them).
PRODUCTS = {"zia": "ZIA", "zpa": "ZPA", "zcc": "ZCC", "zdx": "ZDX", "zins": "Z-Insights", "ztw": "Cloud & Branch Connector",
            "ziam": "ZIdentity", "zid": "ZIdentity", "zwa": "Workflow Automation", "aiguard": "AI Guard", "oauth2": "Sign-in",
            "api": "ZIA"}   # /api/v1/... is the classic ZIA API (zsapi.<cloud>.net)


def max_rows() -> int:
    """DLP_CHECK_API_CALLS_MAX, bounded; the default when unset or not a number."""
    try:
        n = int(str(os.environ.get("DLP_CHECK_API_CALLS_MAX", "") or DEFAULT_MAX).strip())
    except ValueError:
        n = DEFAULT_MAX
    return max(MIN_MAX, min(MAX_MAX, n))


_lock = threading.Lock()
_rows: Deque[Dict[str, Any]] = deque(maxlen=max_rows())
_seq = [0]
_dropped = [0]
_started = time.time()
_tl = threading.local()
_now = time.time               # tests replace these two
_clock = time.monotonic


# ── What a row may say ─────────────────────────────────────────────────

def template(url: Any) -> Tuple[str, str]:
    """(product, path template) of a request URL: the path only (no host,
    query or fragment), every segment that is not a fixed API word
    masked as {id}."""
    try:
        path = urlsplit(str(url or "")).path or "/"
    except ValueError:
        return "other", "/{id}"
    out = []
    for seg in path.split("/"):
        if not seg:
            continue
        out.append(seg if (_WORD.fullmatch(seg) or _VERSION.fullmatch(seg)) else "{id}")
    tpl = "/" + "/".join(out)
    if len(tpl) > MAX_PATH_CHARS:
        tpl = tpl[:MAX_PATH_CHARS - 4] + "/..."
    first = out[0].lower() if out else ""
    return PRODUCTS.get(first, "other"), tpl


def _status(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599 else None


def error_class(status: Optional[int], exc: Optional[BaseException] = None) -> str:
    """A category for a failed call, never its message: '' for a success."""
    name = type(exc).__name__ if exc is not None else ""
    name = name if _NAME.fullmatch(name or "") else ("Error" if exc is not None else "")
    low = name.lower()
    if status is None and exc is None:
        return ""
    if status is not None and status < 400 and exc is None:
        return ""
    if status == 429 or "retrytoolong" in low or "ratelimit" in low:
        word = "rate_limited"
    elif status in (401, 403):
        word = "denied"
    elif status == 404:
        word = "not_found"
    elif status == 409:
        word = "conflict"
    elif status is not None and 400 <= status < 500:
        word = "rejected"
    elif status is not None and status >= 500:
        word = "server_error"
    elif "timeout" in low:
        word = "timeout"
    elif "cancel" in low:
        word = "stopped"
    elif any(w in low for w in ("connection", "ssl", "proxy", "network", "requestexception")):
        word = "network"
    else:
        word = "error"
    return f"{word} ({name})" if name else word


def _job() -> Tuple[str, str]:
    try:
        import pack_jobs
        job = pack_jobs.current()
    except Exception:  # noqa: BLE001 — no job module: no job
        job = None
    if job is None:
        return "", ""
    jid, kind = str(getattr(job, "id", "") or ""), str(getattr(job, "kind", "") or "")
    return (jid if _JOB.fullmatch(jid) else ""), (kind if _JOB.fullmatch(kind) else "")


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((t % 1) * 1000):03d}Z"


# ── One call in flight ─────────────────────────────────────────────────

class _Call:
    __slots__ = ("method", "url", "t0", "at", "attempts", "status", "exc", "wait", "last_end", "net")

    def __init__(self, method: Any, url: Any) -> None:
        m = str(method or "GET").upper()
        self.method = m if m in METHODS else "OTHER"
        self.url = url
        self.t0 = _clock()
        self.at = _now()
        self.attempts = 0
        self.status: Optional[int] = None
        self.exc: Optional[BaseException] = None
        self.wait = _take_wait()
        self.last_end: Optional[float] = None
        self.net = 0.0

    def begin_attempt(self) -> float:
        t = _clock()
        if self.last_end is not None:
            self.wait += max(0.0, t - self.last_end)   # the back-off between two attempts
        self.wait += _take_wait()
        return t

    def end_attempt(self, t: float, status: Any = None, exc: Optional[BaseException] = None) -> None:
        self.attempts += 1
        self.last_end = _clock()
        self.net += max(0.0, self.last_end - t)
        self.status = _status(status)
        self.exc = exc


def _take_wait() -> float:
    w = float(getattr(_tl, "wait", 0.0) or 0.0)
    _tl.wait = 0.0
    return w


def note_wait(seconds: Any) -> None:
    """Seconds this thread was held for a rate limit before its next call
    (zia_rate.wait). Never raises."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return
    if s > 0 and s == s and s != float("inf"):
        _tl.wait = float(getattr(_tl, "wait", 0.0) or 0.0) + s


def current() -> Optional[_Call]:
    return getattr(_tl, "call", None)


@contextlib.contextmanager
def call(method: Any, url: Any) -> Iterator[_Call]:
    """One API call: the rows it makes are recorded when it ends. Inside
    another call (the SDK's execute around its HTTP attempts) it is that
    call."""
    outer = current()
    if outer is not None:
        yield outer
        return
    c = _Call(method, url)
    _tl.call = c
    try:
        yield c
    except BaseException as e:   # recorded, then raised as it was
        if c.exc is None:
            c.exc = e
        raise
    finally:
        _tl.call = None
        try:
            _record(c)
        except Exception:  # noqa: BLE001 — diagnostics never fail a call
            pass


def _record(c: _Call) -> None:
    if c.attempts == 0:   # never sent (stopped, refused before it went out, a cache hit): not an API call
        return
    end = _clock()
    product, path = template(c.url)
    status = c.status
    retries = max(0, c.attempts - 1)
    ms = int(round(max(0.0, end - c.t0) * 1000))
    wait_ms = int(round(c.wait * 1000))
    err = error_class(status, c.exc)
    job, kind = _job()
    retryable = (status in RETRYABLE) or (status is None)
    last = getattr(_tl, "last", None)
    with _lock:
        if (last is not None and last["row"] is not None and last["key"] == (c.method, path) and last["retryable"]
                and 0 <= c.t0 - last["end"] < RETRY_WINDOW and any(r is last["row"] for r in _rows)):
            row = last["row"]
            row["retries"] += 1 + retries
            row["wait_ms"] += int(round((c.t0 - last["end"]) * 1000)) + wait_ms
            row["ms"] += ms
            row["status"], row["error"] = status, err
        else:
            _seq[0] += 1
            if len(_rows) == _rows.maxlen:
                _dropped[0] += 1
            row = {"seq": _seq[0], "at": _iso(c.at), "product": product, "method": c.method, "path": path, "status": status,
                   "ms": ms, "retries": retries, "wait_ms": wait_ms, "error": err, "job": job, "job_kind": kind}
            _rows.append(row)
    _tl.last = {"row": row, "key": (c.method, path), "retryable": retryable, "end": end}


def record(method: Any, url: Any, status: Any = None, *, ms: float = 0.0, exc: Optional[BaseException] = None) -> None:
    """One finished call seen from outside (tests, a client with no hook)."""
    with call(method, url) as c:
        t = c.begin_attempt()
        c.end_attempt(t, status, exc)
        if ms:
            c.t0 -= ms / 1000.0


# ── The hooks ──────────────────────────────────────────────────────────

def attach(session: Any) -> Any:
    """Time every request `session` sends (one attempt of the call in
    flight, or a call of its own). Idempotent; never changes the request
    or the answer."""
    if session is None or getattr(session, "_api_calls_attached", False):
        return session
    real = getattr(session, "send", None)
    if not callable(real):
        return session

    def send(request, **kwargs):
        with call(getattr(request, "method", "GET"), getattr(request, "url", "")) as c:
            t = c.begin_attempt()
            try:
                resp = real(request, **kwargs)
            except BaseException as e:
                c.end_attempt(t, None, e)
                raise
            c.end_attempt(t, getattr(resp, "status_code", None), None)
            return resp

    try:
        session.send = send
        session._api_calls_attached = True
    except Exception:  # noqa: BLE001 — a session that takes no attribute is not timed
        pass
    return session


_installed = [False]


def install_sdk_hooks() -> bool:
    """Wrap the SDK's RequestExecutor.execute (one call per SDK request,
    with its retries) and HTTPClient.send_request (an attempt, when the
    session layer did not see it). Once per process; False when the SDK is
    not installed."""
    if _installed[0]:
        return True
    try:
        from zscaler import oneapi_http_client as hc
        from zscaler import request_executor as rx
    except Exception:  # noqa: BLE001
        return False
    ex_cls = getattr(rx, "RequestExecutor", None)
    http_cls = getattr(hc, "HTTPClient", None)
    if ex_cls is None or http_cls is None:
        return False
    real_execute = ex_cls.execute
    real_send = http_cls.send_request
    if getattr(real_execute, "_api_calls", False):
        _installed[0] = True
        return True

    def execute(self, request, *args, **kwargs):
        req = request if isinstance(request, dict) else {}
        with call(req.get("method"), req.get("url")) as c:
            got = real_execute(self, request, *args, **kwargs)
            # No attempt: nothing reached Zscaler (a cache hit, a request
            # that could not be built, a Stop before it went out), so no row.
            if c.attempts and isinstance(got, tuple) and len(got) >= 2 and isinstance(got[1], BaseException):
                err = got[1]
                st = getattr(err, "status_code", None)
                c.status = _status(st) or c.status
                c.exc = err
            return got

    def send_request(self, request, *args, **kwargs):
        req = request if isinstance(request, dict) else {}
        with call(req.get("method"), req.get("url")) as c:
            before, gap_from, t = c.attempts, c.last_end, _clock()
            got = real_send(self, request, *args, **kwargs)
            if c.attempts == before:   # the session layer did not time it: this was the attempt
                if gap_from is not None:
                    c.wait += max(0.0, t - gap_from)
                c.wait += _take_wait()
                resp, err = (got[0], got[1]) if isinstance(got, tuple) and len(got) >= 2 else (None, None)
                c.end_attempt(t, getattr(resp, "status_code", None), err if isinstance(err, BaseException) else None)
            return got

    execute._api_calls = True          # type: ignore[attr-defined]
    send_request._api_calls = True     # type: ignore[attr-defined]
    ex_cls.execute = execute
    http_cls.send_request = send_request
    _installed[0] = True
    return True


# ── Reading the log ────────────────────────────────────────────────────

def rows(*, job: str = "", product: str = "", limit: int = 0) -> List[Dict[str, Any]]:
    """The rows, newest first, optionally of one job or product."""
    with _lock:
        out = [dict(r) for r in _rows]
    if job:
        out = [r for r in out if r["job"] == job]
    if product:
        out = [r for r in out if r["product"].lower() == product.lower()]
    out.reverse()
    return out[:limit] if limit and limit > 0 else out


def jobs() -> List[Dict[str, Any]]:
    """The jobs that made calls, with their count, newest first."""
    seen: Dict[str, Dict[str, Any]] = {}
    with _lock:
        for r in _rows:
            if r["job"]:
                j = seen.setdefault(r["job"], {"id": r["job"], "kind": r["job_kind"], "calls": 0, "first": r["at"]})
                j["calls"] += 1
    return sorted(seen.values(), key=lambda j: j["first"], reverse=True)


def summary() -> Dict[str, Any]:
    with _lock:
        n = len(_rows)
        failed = sum(1 for r in _rows if r["error"])
        retried = sum(1 for r in _rows if r["retries"])
        waited = sum(r["wait_ms"] for r in _rows)
    return {"rows": n, "max": _rows.maxlen, "dropped": _dropped[0], "failed": failed, "retried": retried, "wait_ms": waited,
            "since": _iso(_started), "fields": list(FIELDS)}


def to_csv(rs: List[Dict[str, Any]]) -> str:
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(FIELDS)
    for r in rs:
        w.writerow(["" if r.get(k) is None else r.get(k) for k in FIELDS])
    return buf.getvalue()


def to_json(rs: List[Dict[str, Any]]) -> str:
    return json.dumps({"summary": summary(), "rows": rs}, indent=1)


def clear() -> None:
    """Empty the log (tests; a restart does the same)."""
    with _lock:
        _rows.clear()
        _dropped[0] = 0
    _tl.last = None
    _tl.wait = 0.0


def resize(n: int) -> None:
    """A new bound (tests), keeping the newest rows."""
    global _rows
    with _lock:
        _rows = deque(list(_rows)[-n:], maxlen=max(1, int(n)))
