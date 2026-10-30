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
client's own pacing. A hold after ZIA refused a read (hold(reads=True))
holds reads too, of every job and process on the tenant. Reads are counted, though, with ZIA's answers, per
tenant and API client, for the preflight's rate-limit check (forecast).

The state is kept per tenant and API client (key_for): requests of the
last hour, the hold after a refusal, ZIA's rate-limit headers, and the
refusals of the last week. It is saved to DLP_CHECK_ZIA_RATE_STATE,
merged with what other processes wrote."""
from __future__ import annotations

import bisect
import contextlib
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Iterator, List, Optional, Tuple

DEFAULTS = {"write": "1/s,400/h", "delete": "1/s,400/h", "endpoint_rules": "10/m,40/h",
            "cloud_app": "10/m,40/h", "activate": "10/m,40/h",
            # GETs: paced at the tenant's session (attach), 2 a second and 1000 an hour.
            "read": "2/s,1000/h"}
# A per-second limit is paced with this margin: two requests exactly one
# second apart can reach ZIA in the same second (network jitter), and ZIA
# answers "Rate Limit (1/SECOND) exceeded". DLP_CHECK_ZIA_SECOND_MARGIN.
SECOND_MARGIN = float(os.environ.get("DLP_CHECK_ZIA_SECOND_MARGIN", "1.25") or 1.25)
_ENV = {k: f"DLP_CHECK_ZIA_LIMIT_{k.upper()}" for k in DEFAULTS}
_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0}
_WORDS = {"write": "write (POST/PUT)", "delete": "delete", "endpoint_rules": "Endpoint DLP rule write",
          "cloud_app": "Cloud App Control rule write", "activate": "activation", "read": "read (GET)"}
_PER = {1.0: "a second", 60.0: "a minute", 3600.0: "an hour"}
# The order a run sends its buckets in (a forecast simulates them one after another).
_ORDER = ("write", "endpoint_rules", "cloud_app", "delete", "activate", "read")
HISTORY_SECONDS = 7 * 24 * 3600
HOUR = 3600.0

# Tests replace these two. Wall-clock seconds, so the requests counted
# survive a restart (the state file) and a forecast can use them.
_sleep: Callable[[float], None] = time.sleep
_now: Callable[[], float] = time.time


class _Tenant:
    """What one tenant's API client sent and what ZIA answered it."""

    def __init__(self) -> None:
        self.sent: Dict[str, Deque[float]] = {k: deque() for k in DEFAULTS}
        # After ZIA refuses a request for its rate, nothing more is sent
        # until this moment: the limit's window has completely reset.
        self.hold = [0.0]
        # The end of a hold that reads keep too: ZIA refused a read (one
        # job's 429), so no job on the tenant reads until it has passed.
        # A hold after a write refusal leaves reads alone (a preview reads).
        self.read_hold = [0.0]
        # Rate refusals of the last week, dicts: at, bucket, message, kind
        # ("blocked": 403 Resource Access Blocked, the client as a whole;
        # "429": one endpoint's limit), reset (ZIA's timer, seconds, or
        # None) and the writes/reads this app had sent before it.
        self.refused: Deque[Dict[str, Any]] = deque()
        # ZIA's own count per bucket, from the x-ratelimit headers of its last answer.
        self.server: Dict[str, Dict[str, Any]] = {}


# Rate state per tenant and API client (key_for). "" is a request with no
# tenant known, and the record written before tenants were told apart.
_lock = threading.Lock()
_tenants: Dict[str, _Tenant] = {"": _Tenant()}
_loaded = [False]
_seen: List[Optional[Tuple[int, int]]] = [None]   # the state file as last read or written (_stamp)
_saved_at = [0.0]            # when this process last saved (ZIA's counts are saved at most every SAVE_EVERY)
_save_failed = [False]       # logged once
SAVE_EVERY = 5.0
_ctx = threading.local()
# The unkeyed tenant's state under its old names (tests read them).
_sent = _tenants[""].sent
_hold_until = _tenants[""].hold
_refused = _tenants[""].refused
_server = _tenants[""].server


def key_for(cloud: str, who: str, client: str) -> str:
    """A tenant's API client as a short opaque key: cloud, vanity domain (or
    admin), client id. Hashed, so the state file names no tenant."""
    raw = "|".join(str(x or "").strip().lower() for x in (cloud, who, client))
    return hashlib.sha256(raw.encode()).hexdigest()[:16] if raw.strip("|") else ""


def key_of(client: Any) -> str:
    """The key stamped on an SDK client by the app (attach_client), or "".
    Only a string the app attached counts: an object that answers every
    attribute (a proxy, a test double) has no key."""
    key = getattr(client, "_zia_rate_key", "")
    return key if isinstance(key, str) else ""


def label_of(client: Any) -> Optional[str]:
    """The tenant label stamped on an SDK client, as the deployment log has it."""
    label = getattr(client, "_zia_rate_label", None)
    return label if isinstance(label, str) and label else None


def labels_of(client: Any) -> Optional[Tuple[str, ...]]:
    """Every label this client's tenant may carry in the deployment log
    (the current one first, then older forms), or None. Only the tuple of
    strings attach_client stamps counts."""
    labels = getattr(client, "_zia_rate_labels", None)
    if isinstance(labels, tuple) and labels and all(isinstance(x, str) and x for x in labels):
        return labels
    one = label_of(client)
    return (one,) if one else None


def _label_ok(rec_label: Any, tenant_label: Any) -> bool:
    """Whether a deployment record belongs to the tenant: `tenant_label` is
    one label or a sequence of them (tenant_auth.record_labels)."""
    if not tenant_label or rec_label is None:
        return True
    if isinstance(tenant_label, str):
        return rec_label == tenant_label
    return rec_label in tuple(tenant_label)


def _record_ok(r: Dict[str, Any], tenant_label: Any, key: Optional[str]) -> bool:
    """Whether a deployment record belongs to the tenant: by its classic-API
    fingerprint or opaque tenant key when both sides have one (classic-API
    tenants on a cloud share one label; their key here is the fingerprint,
    tenant_fingerprint.tenant_key), else by label."""
    rk = r.get("tenant_fp") or r.get("tenant_key")
    if key and rk:
        return rk == key
    return _label_ok(r.get("tenant_label"), tenant_label)


def current_key() -> str:
    return str(getattr(_ctx, "key", "") or "")


@contextlib.contextmanager
def using(key: Optional[str]) -> Iterator[None]:
    """Every wait() on this thread draws on `key`'s state (a run's job thread)."""
    before = getattr(_ctx, "key", "")
    _ctx.key = key or ""
    try:
        yield
    finally:
        _ctx.key = before


@contextlib.contextmanager
def using_client(client: Any) -> Iterator[None]:
    """using() with the key stamped on `client`: a deploy, removal, undo or
    proposal change draws on its own tenant's state, whichever thread runs
    it. A client with no key leaves the thread's key as it is."""
    key = key_of(client)
    if not key:
        yield
        return
    with using(key):
        yield


class Cancelled(RuntimeError):
    """The run on this thread was stopped (the operator's Stop) while a
    request waited for ZIA's rate limit: the request is not sent."""


def is_cancelled(error: Any) -> bool:
    """Whether an error (an exception, or the text an SDK made of one) is a
    Cancelled: the request was never sent because the run was stopped."""
    if isinstance(error, Cancelled):
        return True
    return "the request was not sent" in str(error or "")


# A wait() that honours a stop sleeps in steps no longer than this, so a
# Stop pressed during a long rate-limit wait is seen within a second.
CANCEL_STEP = 0.5


def stop_requested() -> bool:
    """Whether the stop hook of this thread (stopping_on) says stop."""
    fn = getattr(_ctx, "stop", None)
    if fn is None:
        return False
    try:
        return bool(fn())
    except Exception:  # noqa: BLE001 — a broken hook never stops a run by itself
        return False


@contextlib.contextmanager
def stopping_on(should_stop: Optional[Callable[[], bool]]) -> Iterator[None]:
    """While inside, a request this thread would pace (wait(), and every
    ZIA request a paced session sends) is not sent once `should_stop()` is
    true: Cancelled is raised instead, also in the middle of a rate-limit
    wait. None leaves the thread as it is. A hook already bound on this
    thread (an outer scope's) still stops it too: an inner scope never
    hides an outer Stop."""
    if should_stop is None:
        yield
        return
    before = getattr(_ctx, "stop", None)

    def either() -> bool:
        for fn in (should_stop, before):
            if fn is None:
                continue
            try:
                if fn():
                    return True
            except Exception:  # noqa: BLE001 — a broken hook never stops a run by itself
                continue
        return False
    _ctx.stop = either if before is not None else should_stop
    try:
        yield
    finally:
        _ctx.stop = before


def _t(key: Optional[str]) -> _Tenant:
    """A tenant's state. Called with _lock held."""
    k = current_key() if key is None else key
    if k not in _tenants:
        _tenants[k] = _Tenant()
    return _tenants[k]


# ── the state file ───────────────────────────────────────────────────────

def state_path() -> str:
    """Where the rate state is kept: DLP_CHECK_ZIA_RATE_STATE (the container
    keeps it on /data), else next to the app."""
    return os.environ.get("DLP_CHECK_ZIA_RATE_STATE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "zia_rate_state.json")


def _read_file() -> Dict[str, Any]:
    try:
        with open(state_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - no file yet, or unreadable: start empty
        return {}


def _windows(sent: Dict[str, Any], t: float) -> Dict[str, int]:
    """Writes (every bucket but reads) and reads sent in the minute, 5 minutes
    and hour up to `t`."""
    w = [x for k, q in sent.items() if k != "read" for x in q if x <= t]
    r = [x for x in sent.get("read", []) if x <= t]
    return {"writes_1m": sum(1 for x in w if t - x < 60), "writes_5m": sum(1 for x in w if t - x < 300),
            "writes_1h": sum(1 for x in w if t - x < HOUR), "reads_5m": sum(1 for x in r if t - x < 300)}


def _num(v: Any) -> Optional[float]:
    """A finite number from the state file, else None: the file is read back
    as it is on disk, and a damaged one ('abc', null, NaN, Infinity, a list)
    must cost only its own bad entries, never every paced request (CWE-20)."""
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def _clean_tenant(d: Dict[str, Any]) -> Dict[str, Any]:
    """A file tenant's record with every value this module reads checked:
    timestamps and holds finite numbers, refusals dicts with a finite `at`
    and a known bucket, ZIA's counts dicts with a finite `at`."""
    sent_in = d.get("sent")
    sent = {k: [x for x in (_num(t) for t in ts) if x is not None]
            for k, ts in (sent_in.items() if isinstance(sent_in, dict) else ()) if k in DEFAULTS and isinstance(ts, list)}
    refused = []
    for r in d.get("refused") if isinstance(d.get("refused"), list) else []:
        if isinstance(r, dict) and _num(r.get("at")) is not None and r.get("bucket") in DEFAULTS:
            refused.append(dict(r, at=_num(r.get("at"))))
    server_in = d.get("server")
    server = {k: dict(v, at=_num(v.get("at"))) for k, v in (server_in.items() if isinstance(server_in, dict) else ())
              if k in DEFAULTS and isinstance(v, dict) and _num(v.get("at")) is not None}
    out = {"sent": sent, "hold_until": _num(d.get("hold_until")) or 0.0, "refused": refused, "server": server}
    if _num(d.get("read_hold_until")):
        out["read_hold_until"] = _num(d.get("read_hold_until"))
    return out


def _tenants_from(data: Dict[str, Any], now: float) -> Dict[str, Dict[str, Any]]:
    """The file's tenants as plain dicts; a file written before tenants were
    told apart (version 1) becomes tenant "". Its hold is kept only while it
    runs: version 1 set one after any refusal (a short 429 too) and never
    cleared it, so it says neither what ZIA answered nor when."""
    if "tenants" in data:
        tenants = data.get("tenants")
        return {str(k): _clean_tenant(v) for k, v in (tenants.items() if isinstance(tenants, dict) else ()) if isinstance(v, dict)}
    old = _clean_tenant(data)
    hold = old["hold_until"]
    old.pop("read_hold_until", None)
    return {"": dict(old, hold_until=hold if hold > now else 0.0)}


def _merge_into(t: _Tenant, d: Dict[str, Any], now: float) -> None:
    """Add a file tenant's record to `t`: union of requests and refusals,
    the later hold, the newer ZIA count."""
    for k, ts in (d.get("sent") or {}).items():
        if k in t.sent:
            # Per moment, the larger count of the two: requests on the same clock tick stay apart.
            merged = sorted((Counter(t.sent[k]) | Counter(float(x) for x in ts if now - float(x) < HOUR)).elements())
            t.sent[k].clear()
            t.sent[k].extend(merged)
    t.hold[0] = max(t.hold[0], float(d.get("hold_until") or 0))
    t.read_hold[0] = max(t.read_hold[0], float(d.get("read_hold_until") or 0))
    seen = {(round(r["at"], 3), r["bucket"]) for r in t.refused}
    for r in d.get("refused") or []:
        if isinstance(r, dict) and now - float(r.get("at") or 0) < HISTORY_SECONDS and (round(float(r["at"]), 3), r.get("bucket")) not in seen:
            t.refused.append(dict(r))
            seen.add((round(float(r["at"]), 3), r.get("bucket")))
    ordered = sorted(t.refused, key=lambda r: r["at"])
    t.refused.clear()
    t.refused.extend(ordered)
    for k, v in (d.get("server") or {}).items():
        if k in DEFAULTS and isinstance(v, dict) and float(v.get("at") or 0) > float((t.server.get(k) or {}).get("at") or 0):
            t.server[k] = dict(v)


def _stamp() -> Optional[Tuple[int, int]]:
    """The state file's modification time and size, None when it is missing."""
    try:
        st = os.stat(state_path())
        return st.st_mtime_ns, st.st_size
    except OSError:
        return None


def _load() -> None:
    """Read the state file once. Called with _lock held."""
    if _loaded[0]:
        return
    _loaded[0] = True
    now = _now()
    _seen[0] = _stamp()
    for k, d in _tenants_from(_read_file(), now).items():
        _merge_into(_t(k), d, now)


def _refresh() -> None:
    """Read the state file again when another process has written it since
    (a CLI assessment, another server), so a preflight sees its refusals.
    Called with _lock held."""
    _load()
    stamp = _stamp()
    if stamp is not None and stamp != _seen[0]:
        _seen[0] = stamp
        now = _now()
        for k, d in _tenants_from(_read_file(), now).items():
            _merge_into(_t(k), d, now)


# How long a save waits for another process's lock file before removing it
# as stale (tests shorten it).
_LOCK_WAIT = 2.0


@contextlib.contextmanager
def _file_lock(path: str) -> Iterator[None]:
    """A lock file beside the state, so two processes merge instead of
    overwriting each other. After _LOCK_WAIT seconds the lock is taken as
    stale and removed once; one that is still there after that (it cannot
    be removed, or another process holds it open) is not waited for again:
    this save goes ahead without it."""
    lock = path + ".lock"
    fd = None
    deadline = time.monotonic() + _LOCK_WAIT
    removed = False
    while fd is None:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.monotonic() > deadline:
                if removed:
                    break
                removed = True
                with contextlib.suppress(OSError):
                    os.remove(lock)
                continue
            time.sleep(0.02)
        except OSError:
            break
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.remove(lock)


def _save() -> None:
    """Merge this process's record with the file's and write it back.
    Called with _lock held; a file that cannot be written only loses the
    memory across restarts."""
    try:
        p = state_path()
        now = _now()
        with _file_lock(p):
            for k, d in _tenants_from(_read_file(), now).items():
                _merge_into(_t(k), d, now)
            out = {}
            for k, t in _tenants.items():
                while t.refused and now - t.refused[0]["at"] >= HISTORY_SECONDS:
                    t.refused.popleft()
                rec = {"sent": {b: [x for x in q if now - x < HOUR] for b, q in t.sent.items() if q},
                       "hold_until": t.hold[0] if t.hold[0] > now else 0.0, "refused": list(t.refused), "server": t.server}
                if t.read_hold[0] > now:
                    rec["read_hold_until"] = t.read_hold[0]
                if rec["sent"] or rec["hold_until"] or rec.get("read_hold_until") or rec["refused"] or rec["server"]:
                    out[k] = rec
            fd, tmp = tempfile.mkstemp(prefix=".zia_rate-", dir=os.path.dirname(p) or ".")
            replaced = False
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump({"version": 2, "tenants": out}, f)
                for attempt in range(5):
                    try:
                        os.replace(tmp, p)
                        replaced = True
                        break
                    except PermissionError:   # Windows: a reader has the file open
                        time.sleep(0.05 * (attempt + 1))
            finally:
                if not replaced:   # a full disk, say: no temp file is left behind
                    with contextlib.suppress(OSError):
                        os.remove(tmp)
            _seen[0] = _stamp()
            _saved_at[0] = now
    except Exception as e:  # noqa: BLE001
        if not _save_failed[0]:
            _save_failed[0] = True
            logging.getLogger(__name__).warning("The ZIA rate-limit state could not be saved to %s: %s", state_path(), e)


# ── limits and pacing ────────────────────────────────────────────────────

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


def limits_default(bucket: str) -> List[Tuple[int, float]]:
    """A bucket's limits from its default, whatever the setting says (a
    bucket turned off still has a window to wait out after a refusal)."""
    out = []
    for part in DEFAULTS[bucket].split(","):
        n, unit = part.split("/")
        out.append((int(n), _UNITS[unit[:1]]))
    return out


def _paced(rules: List[Tuple[int, float]]) -> List[Tuple[int, float]]:
    """Limits as the app paces them: per-second windows with SECOND_MARGIN."""
    return [(n, w * SECOND_MARGIN if w <= 1.0 else w) for n, w in rules]


def _sim_rules(bucket: str) -> List[Tuple[int, float]]:
    """The limits a forecast applies: the app paces at its setting (with the
    per-second margin), ZIA refuses at its own, so both, the stricter binding."""
    return sorted(set(_paced(limits(bucket))) | set(limits_default(bucket)), key=lambda r: r[1])


def _covers(bucket: str) -> bool:
    """Does the bucket's setting pace at least as strictly as each of ZIA's
    limits for it? A setting window as long as ZIA's or longer covers it
    with no larger a count; a shorter one with its count times the
    windows that fit."""
    rules = limits(bucket)
    return all(any((n2 <= n) if w2 >= w else (n2 * -(-w // w2) <= n) for n2, w2 in rules) for n, w in limits_default(bucket))


def _breaks(bucket: str, prior: List[float], times: List[float]) -> Optional[Tuple[int, float]]:
    """ZIA's limit for `bucket` that requests sent at `times` (after `prior`)
    go over, or None."""
    for n, w in limits_default(bucket):
        seen = sorted(prior + times)
        j = 0
        for i, x in enumerate(seen):
            while x - seen[j] >= w:
                j += 1
            if times and x >= times[0] and i - j + 1 > n:
                return n, w
    return None


def _longest(bucket: str) -> float:
    return max((w for _, w in limits(bucket) + limits_default(bucket)), default=60.0)


def bucket_of(method: str, path: str = "", *, channel: Optional[str] = None, kind: Optional[str] = None) -> str:
    """The limit a request draws on, from its method and its endpoint (a
    path, or the pack's channel and object kind)."""
    m = (method or "").upper()
    p = (path or "").lower()
    if "status/activate" in p or kind == "activation":
        return "activate"
    if m == "GET":
        return "read"
    if m == "DELETE":
        return "delete"
    if "endpointdlprules" in p or (channel == "endpoint" and kind == "policy"):
        return "endpoint_rules"
    if "webapplicationrules" in p or (channel == "cloud_app" and kind == "policy"):
        return "cloud_app"
    return "write"


def _delay(t: _Tenant, bucket: str, now: float) -> Tuple[float, Optional[Tuple[int, float]]]:
    """Seconds until the next request of `bucket` fits every limit, and the
    limit that sets it (None when it fits now). Called with _lock held."""
    sent = t.sent[bucket]
    if sent and sent[-1] > now:
        # Requests counted "after" now: the clock was set back since. They
        # are taken as sent now, so the wait is one window at most, never
        # as long as the clock moved.
        moved = [min(x, now) for x in sent]
        sent.clear()
        sent.extend(moved)
    longest = _longest(bucket)   # kept for the forecast even when pacing is off
    while sent and now - sent[0] >= longest:
        sent.popleft()
    wait_s, binding = 0.0, None
    for n, w in _paced(limits(bucket)):
        recent = [x for x in sent if now - x < w]
        if len(recent) >= n:
            d = recent[-n] + w - now
            if d > wait_s:
                wait_s, binding = d, (n, w)
    return wait_s, binding


def wait(method: str, path: str = "", log: Optional[Callable[[str], None]] = None, what: str = "", *,
         channel: Optional[str] = None, kind: Optional[str] = None, key: Optional[str] = None) -> float:
    """Block until one more request fits ZIA's limits (and any hold after a
    refusal has passed), then count it. Returns the seconds waited. Never
    sleeps holding the lock, so other threads' requests and a preflight's
    forecast are not held up by a paced write."""
    bucket = bucket_of(method, path, channel=channel, kind=kind)
    total = 0.0
    told_hold = False
    slept_until = 0.0
    stoppable = getattr(_ctx, "stop", None) is not None
    told_wait = False
    hold_seen, hold_left = 0.0, 0.0
    while True:
        if stoppable and stop_requested():
            raise Cancelled(f"stopped while waiting for ZIA's rate limit{' (' + what + ')' if what else ''}; the request was not sent")
        with _lock:
            _load()
            t = _t(key)
            now = _now()
            # A hold is slept through once: it ends at a fixed moment, unless
            # another run set or extended it meanwhile. Reads wait only for a
            # hold set after a read was refused (read_hold): a hold after a
            # write refusal leaves them alone, so a preview can still read.
            hold_end = t.read_hold[0] if bucket == "read" else t.hold[0]
            held = 0.0 if hold_end <= slept_until else hold_end - now
            d, binding = (0.0, None) if held > 0 else _delay(t, bucket, now)
            if held <= 0 and d <= 0:
                t.sent[bucket].append(now)
                if bucket != "read" or len(t.sent[bucket]) % 25 == 0:
                    _save()
                _ctx.prepaced = now    # the session does not pace the request this wait was for again
                return total
        if held > 0:
            if log and not told_hold:
                log(f"{what + ': ' if what else ''}ZIA's rate limit is still resetting; waiting {_human(held)} more before sending anything.")
                told_hold = True
            slept_until = hold_end
            step = held
        else:
            if log and d >= 5 and binding and not told_wait:
                told_wait = stoppable   # a wait slept in steps is announced once
                at = datetime.fromtimestamp(now + d).strftime("%H:%M")   # the injected clock (_now), not the wall clock
                n, w = binding
                log(f"{what + ': ' if what else ''}ZIA allows {n} {_WORDS[bucket]}{'s' if n != 1 else ''} {_PER.get(w, f'per {w:.0f}s')}; "
                    f"waiting {_human(d)} (next at {at}).")
            step = d
        if stoppable:   # a Stop during a long wait is seen within CANCEL_STEP
            if held > 0:
                if hold_end != hold_seen:   # a new (or extended) hold: its whole length is still to sleep
                    hold_seen, hold_left = hold_end, held
                step = min(hold_left, CANCEL_STEP)
                hold_left -= step
                # The hold is slept through once its whole length has been
                # slept in steps (as an unstoppable wait sleeps it in one),
                # whatever the clock says meanwhile.
                slept_until = hold_end if hold_left <= 0 else 0.0
            else:
                step = min(step, CANCEL_STEP)
        _sleep(step)
        total += step


def full_reset(bucket: str, key: Optional[str] = None) -> float:
    """Seconds until the oldest request of `bucket` this app counted has
    aged out of the bucket's longest window, its setting's or ZIA's own,
    whichever is longer: from then on the limit has room again. When none
    is counted (the limit was reached by other traffic), a whole longest
    window."""
    longest = _longest(bucket)
    now = _now()
    with _lock:
        _load()
        sent = _t(key).sent[bucket]
        inside = [x for x in sent if now - x < longest]
        return (inside[0] + longest - now) if inside else longest


MAX_HOLD_SECONDS = float(HISTORY_SECONDS)


def hold_seconds(seconds: Any) -> float:
    """`seconds` as a hold may last: 0 for a negative, non-number or NaN,
    at most MAX_HOLD_SECONDS (a week). The value often comes from ZIA's
    answer (a reset header): an absurd one ('1e999', inf) is a week, never a
    hold for ever, and overlong_holds can still lift it."""
    v = _num(seconds)
    if v is None and seconds == float("inf"):
        v = MAX_HOLD_SECONDS
    return 0.0 if v is None or v <= 0 else min(v, MAX_HOLD_SECONDS)


def hold(seconds: float, key: Optional[str] = None, *, reads: bool = False) -> float:
    """Send nothing more, in any write bucket of this tenant, for `seconds`;
    with `reads` (ZIA refused a read) no read either, from any job or
    process on the tenant: the assessment's Client and the SDK's sessions
    alike. Returns the moment (epoch seconds) the hold ends."""
    with _lock:
        _load()
        t = _t(key)
        end = _now() + hold_seconds(seconds)
        t.hold[0] = max(t.hold[0], end)
        if reads:
            t.read_hold[0] = max(t.read_hold[0], end)
        _save()
        return t.hold[0]


def paused_for(key: Optional[str] = None, *, reads: bool = False) -> float:
    """Seconds left on this tenant's hold (0 when there is none), so a job
    window can count down to the moment the run sends again. With `reads`,
    the hold reads keep (set after a read was refused)."""
    with _lock:
        _refresh()
        t = _t(key)
        left = (t.read_hold[0] if reads else t.hold[0]) - _now()
    return left if left > 0 else 0.0


def overlong_holds(*, clear: bool = False, margin: float = 300.0) -> List[Dict[str, Any]]:
    """Holds that end further away than the longest limit window (an hour
    by default) plus `margin`: no refusal can justify them, so one is left
    over from a clock that was set back, or a damaged state file. With
    `clear` they are lifted, here and in the state file (whose later hold
    would otherwise be merged back in). Each is reported by the first 8
    characters of its opaque tenant key, never by a tenant name."""
    limit = max(_longest(b) for b in DEFAULTS) + max(0.0, margin)
    found: List[Dict[str, Any]] = []
    with _lock:
        _refresh()
        now = _now()
        for k, t in _tenants.items():
            for kind, box in (("writes", t.hold), ("reads", t.read_hold)):
                left = box[0] - now
                if left > limit:
                    found.append({"tenant": (k[:8] or "(no tenant)"), "kind": kind, "seconds_left": round(left)})
                    if clear:
                        box[0] = 0.0
        if clear and found:
            p = state_path()
            try:
                with _file_lock(p):
                    data = _read_file()
                    for d in (data.get("tenants") or {}).values() if isinstance(data.get("tenants"), dict) else []:
                        if isinstance(d, dict):
                            for key in ("hold_until", "read_hold_until"):
                                if float(d.get(key) or 0) - now > limit:
                                    d[key] = 0.0
                    if float(data.get("hold_until") or 0) - now > limit:   # a version 1 file
                        data["hold_until"] = 0.0
                    if data:
                        fd, tmp = tempfile.mkstemp(prefix=".zia_rate-", dir=os.path.dirname(p) or ".")
                        try:
                            with os.fdopen(fd, "w", encoding="utf-8") as f:
                                json.dump(data, f)
                            os.replace(tmp, p)
                        finally:
                            with contextlib.suppress(OSError):
                                os.remove(tmp)
                _seen[0] = _stamp()
            except Exception as e:  # noqa: BLE001 - the in-memory hold is lifted either way
                logging.getLogger(__name__).warning("The ZIA rate-limit state file could not be corrected: %s", e)
    return found


def estimate(bucket: str, count: int) -> float:
    """Seconds `count` requests of `bucket` take at the configured limits,
    starting from an empty window (for a removal's time estimate)."""
    if count <= 0:
        return 0.0
    worst = 0.0
    for n, w in limits(bucket):
        worst = max(worst, ((count - 1) // n) * w)
    return worst


# ── what ZIA answered ────────────────────────────────────────────────────

def _is_rate_answer(status: Optional[int], text: str) -> bool:
    low = (text or "").lower()
    return status == 429 or "resource access blocked" in low or "rate limit" in low or "too many requests" in low


def _header_num(low: Dict[str, Any], k: str) -> Optional[float]:
    """A number from an answer's header, or None (not a number, NaN or infinite)."""
    return _num(str(low.get(k, "")).split(",")[0].split(";")[0].strip()[:32])


def note_refusal(bucket: str, message: str, *, key: Optional[str] = None, reset: Optional[float] = None,
                 status: Optional[int] = None) -> None:
    """ZIA refused a request for its rate: kept for a week with the traffic
    that led to it. "Resource Access Blocked" blocks the client as a whole;
    a 429 is one endpoint's limit, with ZIA's reset timer when it gave one."""
    with _lock:
        _load()
        t = _t(key)
        now = _now()
        kind = "blocked" if "blocked" in (message or "").lower() and status != 429 else "429"
        last = t.refused[-1] if t.refused else None
        if last and last["bucket"] == bucket and last.get("kind") == kind and now - last["at"] < 2:
            return   # the same refusal seen twice (a 403 block right after a 429 is not the same)
        t.refused.append({"at": now, "bucket": bucket, "message": str(message or "")[:160], "kind": kind,
                          "reset": reset, **_windows({k: list(q) for k, q in t.sent.items()}, now)})
        _save()


def note_headers(bucket: str, headers: Any, key: Optional[str] = None) -> None:
    """Keep ZIA's own count for `bucket` from an answer's x-ratelimit headers.
    Kept in memory and saved at most every SAVE_EVERY seconds: nearly every
    answer carries them, and a save rewrites the whole state file."""
    try:
        low = {str(k).lower(): v for k, v in dict(headers or {}).items()}
    except Exception:  # noqa: BLE001
        return
    lim, rem, rst = (_header_num(low, h) for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"))
    if lim is None or rem is None:
        return
    with _lock:
        _load()
        now = _now()
        _t(key).server[bucket] = {"at": now, "limit": int(lim), "remaining": int(rem), "reset": rst}
        if not 0 <= now - _saved_at[0] < SAVE_EVERY:
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


def observe(method: str, url: str, status: Optional[int], headers: Any = None, text: str = "", *, key: Optional[str] = None) -> None:
    """One ZIA answer, seen by a session hook (attach): ZIA's rate-limit
    headers and rate refusals are kept for the next preflight (requests are
    counted when they are paced, by wait). Takes the lock only briefly."""
    path = _zia_path(url)
    if path is None or "authenticatedsession" in path.lower():
        return
    m = (method or "GET").upper()
    bucket = bucket_of(m, path)
    if headers is not None:
        note_headers(bucket, headers, key=key)
    if status in (403, 429) and _is_rate_answer(status, text):
        low = {}
        with contextlib.suppress(Exception):
            low = {str(k).lower(): v for k, v in dict(headers or {}).items()}
        reset = _header_num(low, "x-ratelimit-reset") or _header_num(low, "retry-after")
        note_refusal(bucket, (text or f"HTTP {status}")[:160], key=key, reset=reset, status=status)


def _pace_session(session: Any, key: str) -> None:
    """Pace every ZIA request `session` sends for tenant `key` before it goes
    out: reads at ZIA's read limit, writes at theirs, unless the caller has
    just paced this request itself (wait marks it)."""
    if getattr(session, "_zia_rate_paced", False):
        return
    real = session.send

    def send(request, **kwargs):
        path = _zia_path(getattr(request, "url", ""))
        if path is not None and stop_requested():
            raise Cancelled("stopped before it went out; the request was not sent")
        if path is not None and "authenticatedsession" not in path.lower():
            mark = getattr(_ctx, "prepaced", None)
            _ctx.prepaced = None
            if mark is None or not (0 <= _now() - mark < 5):   # paced by its caller only just now
                wait(getattr(request, "method", "GET"), path, key=key)
                _ctx.prepaced = None
        return real(request, **kwargs)

    session.send = send
    session._zia_rate_paced = True


def attach(session: Any, key: str) -> Any:
    """Pace and count every ZIA request `session` sends for tenant `key`
    (_pace_session), and see ZIA's answers with a response hook, so only
    this tenant's session is observed. The body of a 403/429 is read only
    for a request that was not streamed."""
    with contextlib.suppress(Exception):
        _pace_session(session, key)
    def hook(resp, *args, **kwargs):
        try:
            req = getattr(resp, "request", None)
            if req is not None and _zia_path(getattr(req, "url", "")) is not None:
                text = ""
                if resp.status_code in (403, 429) and not kwargs.get("stream"):
                    text = (resp.text or "")[:300]
                observe(req.method, req.url, resp.status_code, resp.headers, text, key=key)
        except Exception:  # noqa: BLE001 - observing never fails a request
            pass
        return resp
    hooks = getattr(session, "hooks", None)
    if isinstance(hooks, dict) and hook not in hooks.setdefault("response", []):
        hooks["response"].append(hook)
    return session


def attach_client(client: Any, key: str, label: Any = None) -> Any:
    """Stamp an SDK client with its tenant key (and the tenant label the
    deployment log uses), and give its request executor a session that
    reports ZIA's answers (attach). The classic-API client
    (tenant_auth.LegacyZiaClient) takes its paced session through its own
    set_session: its requests are paced and stoppable the same way."""
    with contextlib.suppress(Exception):
        setattr(client, "_zia_rate_key", key)
        labels = (label,) if isinstance(label, str) else tuple(x for x in (label or ()) if x)
        if labels:
            setattr(client, "_zia_rate_label", labels[0])
            setattr(client, "_zia_rate_labels", labels)
    ex = getattr(client, "_request_executor", None)
    if ex is None and callable(getattr(client, "set_session", None)):
        ex = client   # the classic API: tenant_auth.LegacyZiaClient
    if ex is not None and hasattr(ex, "set_session"):
        with contextlib.suppress(Exception):
            import requests
            ex.set_session(attach(requests.Session(), key))
    return client


# ── the forecast ─────────────────────────────────────────────────────────

_SINGULAR = {"write": "dictionary, engine or rule (POST/PUT)", "delete": "delete", "endpoint_rules": "Endpoint DLP rule",
             "cloud_app": "Cloud App Control rule", "activate": "activation", "read": "read (GET)"}
BUCKET_LABELS = {"write": "dictionaries, engines and rules (POST/PUT)", "delete": "deletes",
                 "endpoint_rules": "Endpoint DLP rules", "cloud_app": "Cloud App Control rules", "activate": "activations",
                 "read": "reads (GET)"}


def _rules_text(bucket: str) -> str:
    unit = {1.0: "sec", 60.0: "min", 3600.0: "hr"}
    return " and ".join(f"{n}/{unit.get(w, f'{w:.0f}s')}" for n, w in limits_default(bucket))


def _clock(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M UTC")


def _day_clock(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %H:%M UTC")


def _simulate(rules: List[Tuple[int, float]], prior: List[float], start: float, n: int) -> List[float]:
    """When each of `n` requests goes out, starting at `start`, after the
    `prior` ones, at the (count, window) `rules`."""
    sim = sorted(prior)
    out: List[float] = []
    t = start
    for _ in range(n):
        wait_s = 0.0
        for lim, w in rules:
            # sim stays sorted, so the requests inside the window (t - x < w)
            # are a suffix, found by bisection with that same test, not by a
            # scan of every request (quadratic: a 10k-rule pack took minutes).
            first = bisect.bisect_left(sim, True, key=lambda x, t=t, w=w: t - x < w)
            if len(sim) - first >= lim:
                wait_s = max(wait_s, sim[len(sim) - lim] + w - t)
        t += max(0.0, wait_s)
        bisect.insort(sim, t)
        out.append(t)
    return out


def _prior(bucket: str, mine: List[float], server: Dict[str, Any], now: float) -> List[float]:
    """This app's own requests of `bucket`, plus what ZIA's own count (its
    x-ratelimit headers: other tools on the same client) adds beyond them
    inside that header's window. Merged, so the app's hourly record stays."""
    s = server.get(bucket)
    out = list(mine)
    if s and s.get("limit") is not None and s.get("remaining") is not None and s.get("reset"):
        ends = float(s["at"]) + float(s["reset"])
        w = next((w for lim, w in limits_default(bucket) if lim == s["limit"]), None)
        if ends > now and w is not None:
            used = max(0, int(s["limit"]) - int(s["remaining"]))
            inside = sum(1 for x in mine if x >= ends - w)
            out += [ends - w] * max(0, used - inside)
    return out


def _view(key: Optional[str], use_recent: bool, now: float) -> Tuple[Dict[str, List[float]], float, List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """The requests of the last hour, the hold, the refusals and ZIA's counts
    of tenant `key`, the same record its runs are paced by (wait); and,
    apart, the refusals and hold of the record that names no tenant (""):
    one written before tenants were told apart, or by a run that did not
    say which tenant it wrote to. That one may be another tenant's."""
    if not use_recent:
        return {k: [] for k in DEFAULTS}, 0.0, [], {}, {"refused": [], "hold": 0.0}
    with _lock:
        _refresh()
        k = current_key() if key is None else key
        t = _t(k)
        sent = {b: sorted(x for x in q if now - x < HOUR) for b, q in t.sent.items()}
        held = max(0.0, t.hold[0] - now)
        refused = sorted((dict(r) for r in t.refused), key=lambda r: r["at"])
        server = {b: dict(v) for b, v in t.server.items()}
        u = _t("")
        unkeyed = {"refused": [dict(r) for r in u.refused] if k else [], "hold": max(0.0, u.hold[0] - now) if k else 0.0}
    return sent, held, refused, server, unkeyed


def _deployment_refusals(now: float, tenant_label: Any, key: Optional[str] = None) -> List[Tuple[float, str]]:
    """Runs of this tenant in the deployment log of the last week that ZIA
    refused for its rate: (when, what it answered)."""
    try:
        import deployments
        rows = deployments._read()["deployments"]
    except Exception:  # noqa: BLE001
        return []
    out = []
    for r in rows:
        if not _record_ok(r, tenant_label, key):
            continue
        for when, results in ((r.get("at"), (r.get("created") or []) + (r.get("other") or []) + (r.get("failed") or [])),
                              ((r.get("undo") or {}).get("at"), (r.get("undo") or {}).get("results") or [])):
            if not when:
                continue
            try:
                t = datetime.fromisoformat(str(when)).timestamp()
            except ValueError:
                continue
            if now - t >= HISTORY_SECONDS:
                continue
            hit = next((str(x.get("error") or "") for x in results if isinstance(x, dict) and _is_rate_answer(None, str(x.get("error") or ""))), None)
            if hit:
                out.append((t, hit))
    return sorted(out)


def _track_record(now: float, tenant_label: Any, key: Optional[str] = None) -> Dict[str, Any]:
    """This tenant's deploys and removals in the deployment log of the last
    week, and how many finished without ZIA refusing a request for its rate."""
    try:
        import deployments
        rows = deployments._read()["deployments"]
    except Exception:  # noqa: BLE001
        rows = []
    runs = clean = 0
    for r in rows:
        if not _record_ok(r, tenant_label, key):
            continue
        for when, results in ((r.get("at"), (r.get("created") or []) + (r.get("other") or []) + (r.get("failed") or [])),
                              ((r.get("undo") or {}).get("at"), (r.get("undo") or {}).get("results") or [])):
            try:
                t = datetime.fromisoformat(str(when)).timestamp() if when else None
            except ValueError:
                t = None
            if t is None or now - t >= HISTORY_SECONDS:
                continue
            runs += 1
            if not any(isinstance(x, dict) and _is_rate_answer(None, str(x.get("error") or "")) for x in results):
                clean += 1
    return {"runs": runs, "clean": clean, "percent": round(100 * clean / runs) if runs else None}


def forecast(counts: Dict[str, int], *, use_recent: bool = True, key: Optional[str] = None,
             tenant_label: Any = None) -> Dict[str, Any]:
    """Will a run of `counts` requests per bucket succeed at ZIA's limits,
    for tenant `key`? Simulated, nothing is sent, against what the app
    executed for that tenant: its requests of the last hour (reads too),
    ZIA's own count from its rate-limit headers, and the refusals ZIA gave,
    with the traffic ZIA tolerated before blocking the client.

    severity "ok": will succeed, straight through. "warn": will succeed,
    pausing (a limit still resetting, an hourly limit nearly used, or
    close to what ZIA has tolerated). "fail": likely to fail: ZIA blocked
    this client in the last hour, or blocked it before at fewer writes in
    5 minutes than this run sends."""
    now = _now()
    sent, held, refused, server, unkeyed = _view(key, use_recent, now)
    rows = []
    planned: List[float] = []
    start = fresh_start = now + held
    fresh_end = now
    too_fast: List[Tuple[str, Tuple[int, float]]] = []   # (bucket, ZIA's limit the app's own pacing would break)
    for bucket in sorted((b for b, n in counts.items() if n > 0 and b in DEFAULTS), key=_ORDER.index):
        n = counts[bucket]
        rules = _sim_rules(bucket)
        prior = _prior(bucket, sent[bucket], server, now)
        times = _simulate(rules, prior, start, n)
        if not _covers(bucket):
            # The setting paces looser than ZIA's limits (or not at all): the
            # run sends at the setting's pace, and ZIA refuses what is over.
            broken = _breaks(bucket, prior, _simulate(_paced(limits(bucket)), prior, start, n))
            if broken:
                too_fast.append((bucket, broken))
        # The same run from a quiet hour: the time its own pacing takes.
        fresh = _simulate(rules, [], fresh_start, n)
        planned += times
        start, fresh_start = times[-1], fresh[-1]
        fresh_end = fresh[-1]
        hourly = max((lim for lim, w in limits_default(bucket) if w >= HOUR), default=None)
        zia_used = len(_prior(bucket, [], server, now))
        rows.append({"bucket": bucket, "label": BUCKET_LABELS.get(bucket, bucket), "requests": n, "limits": _rules_text(bucket),
                     "used_last_hour": len(sent[bucket]), "zia_reports_used": zia_used or None, "hourly_limit": hourly,
                     "seconds": times[-1] - now, "duration": times[-1] - times[0], "over_hourly": bool(hourly and n > hourly)})
    total = max(0.0, start - now) if rows else 0.0
    pause = max(0.0, total - (fresh_end - now)) if rows else 0.0
    # Busiest 5 minutes of writes in this run, counting what was already sent.
    writes = sorted([x for b, q in sent.items() if b != "read" for x in q] + planned)
    peak5, j = 0, 0
    for i, x in enumerate(writes):
        while x - writes[j] >= 300:
            j += 1
        if x >= now:
            peak5 = max(peak5, i - j + 1)
    used = {r["bucket"] for r in rows}
    blocked = [r for r in refused if r.get("kind") == "blocked"]
    blocked_hour = [r for r in blocked if now - r["at"] < HOUR]
    # A 429 on a bucket this run uses whose reset is still running: a pause, not a failure.
    limited = [r for r in refused if r.get("kind") == "429" and r["bucket"] in used
               and r["at"] + float(r.get("reset") or _longest(r["bucket"])) > now]
    # What ZIA has shown it tolerates: the fewest writes in 5 minutes it blocked the client at.
    tolerated = [r for r in blocked if (r.get("writes_5m") or 0) > 0]
    ceiling = min(tolerated, key=lambda r: r["writes_5m"]) if tolerated else None
    history = _deployment_refusals(now, tenant_label, key) if use_recent else []
    # A run of deletes only is a removal: its advice is about removing, not deploying.
    removing = bool(counts.get("delete")) and not any(counts.get(b) for b in ("write", "endpoint_rules", "cloud_app"))
    run_after = None
    if not rows:
        verdict, severity = "Nothing to send.", "ok"
    elif blocked_hour:
        last = blocked_hour[-1]
        run_after = last["at"] + HOUR
        verdict, severity = (f"Likely to fail: ZIA blocked this API client {_ago(now - last['at'])} ('{last['message']}'"
                             + (f", after {last['writes_5m']} writes from Zscaler Made Easy in 5 minutes" if last.get("writes_5m") else "")
                             + f"). Run it after {_clock(run_after)}, an hour after that block. A run started now pauses for the "
                             f"limit's full window at each refusal and stops after 3."), "fail"
    elif ceiling and peak5 >= ceiling["writes_5m"]:
        verdict, severity = (f"Likely to fail: on {_day_clock(ceiling['at'])} ZIA blocked this API client after {ceiling['writes_5m']} writes "
                             f"in 5 minutes, below its documented limits, and this run sends up to {peak5} in its busiest 5 minutes. "
                             + ("Remove fewer objects at a time, and do not run an assessment meanwhile." if removing else
                                "Deploy one channel at a time, and do not run an assessment meanwhile.")), "fail"
    elif too_fast:
        what = "; ".join(f"{BUCKET_LABELS[b]} is set to \"{(os.environ.get(_ENV[b]) or '').strip() or 'off'}\" ({_ENV[b]}), "
                         f"and this run would send more than ZIA's {n} {_PER.get(w, f'per {w:.0f}s')}" for b, (n, w) in too_fast)
        verdict, severity = (f"Likely to fail: the app's own pacing is looser than ZIA's rate limits ({what}), so ZIA will refuse "
                             f"part of this run. Remove the setting to pace at ZIA's documented limits."), "fail"
    elif held > 0:
        run_after = now + held
        verdict, severity = (f"Will succeed, with a pause: ZIA's rate limit is still resetting from an earlier refusal, so this run "
                             f"starts sending at {_clock(run_after)} and takes about {_human(total)} in all."), "warn"
    elif limited:
        # ZIA's own reset timer: the run does not wait for it (no hold was
        # set), so a request sent before it ends may be refused and waited out.
        r = max(limited, key=lambda r: r["at"] + float(r.get("reset") or _longest(r["bucket"])))
        ends = r["at"] + float(r.get("reset") or _longest(r["bucket"]))
        verdict, severity = (f"Will succeed, with a pause: ZIA refused {BUCKET_LABELS[r['bucket']]} for its rate {_ago(now - r['at'])}, and its "
                             f"limit may still be resetting until {_clock(ends)}. The run starts now; if ZIA refuses a request again, it pauses "
                             f"until the limit has reset and carries on by itself. About {_human(total)} without a pause."), "warn"
    elif ceiling and peak5 >= 0.8 * ceiling["writes_5m"]:
        verdict, severity = (f"Will probably succeed, close to what ZIA tolerates: it blocked this client on {_day_clock(ceiling['at'])} "
                             f"after {ceiling['writes_5m']} writes in 5 minutes, and this run sends up to {peak5}. About {_human(total)}."), "warn"
    elif pause > 60 or any(r["over_hourly"] for r in rows):
        why = "; ".join(
            (f"{r['label']}: {r['requests']} needed, over the {r['hourly_limit']}/hr limit on its own" if r["over_hourly"] else
             f"{r['label']}: {max(r['used_last_hour'], r['zia_reports_used'] or 0)} of {r['hourly_limit']}/hr already used in the last hour"
             + (" (ZIA's own count)" if (r["zia_reports_used"] or 0) > r["used_last_hour"] else ""))
            for r in rows if r["over_hourly"] or r["used_last_hour"] or r["zia_reports_used"])
        verdict, severity = (f"Will succeed, with pauses for ZIA's limits: about {_human(total)} in all, done around "
                             f"{_clock(now + total)}{f' ({why})' if why else ''}. The run waits and carries on by itself."), "warn"
    else:
        verdict, severity = f"Will succeed: goes straight through within ZIA's rate limits, about {_human(total)}.", "ok"
    if rows and severity != "ok":
        case = ("blocked" if blocked_hour else ("ceiling" if ceiling and peak5 >= ceiling["writes_5m"] else "too_fast")) if severity == "fail" else (
            "resetting" if (held > 0 or limited) else ("close" if ceiling and peak5 >= 0.8 * ceiling["writes_5m"] else "pauses"))
        # The number a quip names is the one its verdict names: this hour's block, else the fewest writes ZIA blocked at.
        tol = (blocked_hour[-1].get("writes_5m") or None) if case == "blocked" else (ceiling["writes_5m"] if ceiling else None)
        quip = _quip(case, now, writes=tol, hourly=next((r["hourly_limit"] for r in rows if r["over_hourly"] or r["used_last_hour"]), None))
        if quip:
            verdict = f"{quip} {verdict}"
    # A block or hold in the record that names no tenant may be this tenant's
    # or another's: said as such, a warning at most, never a quip or a ceiling.
    ublocked = [r for r in unkeyed["refused"] if r.get("kind") == "blocked" and now - float(r.get("at") or 0) < HOUR]
    only_unkeyed = False
    if rows and severity != "fail" and (ublocked or unkeyed["hold"] > 0):
        if ublocked:
            u = ublocked[-1]
            note = (f"A Zscaler Made Easy record that names no tenant (written before tenants were kept apart, or by a run that did not say "
                    f"which tenant it wrote to) shows ZIA blocked an API client {_ago(now - u['at'])} ('{u['message']}'). If that was "
                    f"this tenant's, run this after {_clock(u['at'] + HOUR)}.")
        else:
            note = (f"A Zscaler Made Easy record that names no tenant (written before tenants were kept apart) holds writes until "
                    f"{_clock(now + unkeyed['hold'])} after ZIA refused a request for its rate. If that was this tenant's, run this after then.")
        if severity == "ok":
            verdict, severity = f"Will probably succeed: goes straight through within ZIA's rate limits, about {_human(total)}. {note}", "warn"
            only_unkeyed = True
        else:
            verdict = f"{verdict} {note}"
    # The API plan, one line per kind of request, and the success outlook with this tenant's track record.
    first = min((r["seconds"] - r["duration"] for r in rows), default=0.0)
    plan = ([f"Starts at {_clock(now + first)}, once ZIA's limit has reset ({_human(first)} from now)"] if first >= 60 else []) + [
        f"{r['requests']} {_SINGULAR.get(r['bucket'], r['label']) if r['requests'] == 1 else r['label']}: ZIA allows {r['limits']}; "
        f"{r['used_last_hour']} already sent this hour"
        + (f" (ZIA counts {r['zia_reports_used']})" if (r['zia_reports_used'] or 0) > r['used_last_hour'] else "")
        + f"; takes about {_human(max(1.0, r['duration']))}" for r in rows]
    record = _track_record(now, tenant_label, key) if use_recent else {"runs": 0, "clean": 0, "percent": None}
    outlook = "good, unless that refusal was this tenant's" if only_unkeyed else {"ok": "good", "warn": "good, but slow", "fail": "poor"}[severity]
    success = {"outlook": outlook, "track_record": record,
               "text": f"Outlook: {outlook}. " + (f"Track record: {record['clean']} of {record['runs']} of this tenant's runs in the last week "
                                                 f"finished without ZIA refusing them for its rate ({record['percent']}%)."
                                                 if record["runs"] else "Track record: no deploys or removals of this tenant in the last week.")}
    return {"buckets": rows, "plan": plan, "success": success, "seconds": total, "pause_seconds": pause, "verdict": verdict, "severity": severity,
            "title": "Will probably succeed" if only_unkeyed else {"ok": "Will succeed", "warn": "Will succeed, with pauses", "fail": "Likely to fail"}[severity],
            "run_after": run_after, "refused_last_hour": len(blocked_hour) + len(limited), "peak_5min_writes": peak5,
            "tolerated": {"at": ceiling["at"], "writes_5m": ceiling["writes_5m"], "writes_1m": ceiling.get("writes_1m"),
                          "reads_5m": ceiling.get("reads_5m"), "message": ceiling["message"]} if ceiling else None,
            "sent_last_hour": {k: len(v) for k, v in sent.items() if v}, "refused_runs": [{"at": t, "error": e} for t, e in history],
            "recent": {k: len(v) for k, v in sent.items()} if use_recent else {}}


# When the run is crushing ZIA's rate limits, the verdict says so with the
# respect those limits have earned. DLP_CHECK_RATE_TONE=plain keeps it dry.
_QUIPS = {
    "blocked": ["Zscaler's API has fainted again.",
                "Down goes the Zero Trust Exchange, felled by {writes} writes.",
                "Zscaler's API, a global cloud platform, needs a lie-down after {writes} writes."],
    "ceiling": ["Last time, {writes} writes in 5 minutes was apparently too much excitement for Zscaler's API.",
                "Zscaler's API has a documented limit and a real one; the real one is {writes} writes in 5 minutes.",
                "History lesson: Zscaler's API folded at {writes} writes in 5 minutes."],
    "resetting": ["Zscaler's API is still catching its breath.",
                  "Zscaler's API is on its union-mandated break.",
                  "Hold please: Zscaler's API is recovering from the last few requests."],
    "close": ["Living dangerously: this is within a whisker of what knocked Zscaler's API over last time.",
              "Fingers crossed: this is close to the {writes} writes that floored Zscaler's API before."],
    "pauses": ["Zscaler rations its API like wartime butter{hourly_text}.",
               "Patience: Zscaler's API counts its requests like a miser counts coins{hourly_text}.",
               "Plenty of time for coffee: Zscaler's API takes its limits very seriously{hourly_text}."],
}


def _quip(case: str, now: float, *, writes: Optional[int] = None, hourly: Optional[int] = None) -> str:
    """A sarcastic opener for a verdict where ZIA's limits bite, or "" when
    DLP_CHECK_RATE_TONE is "plain". Picked by the hour, so a preview does
    not change its wording on every refresh."""
    if (os.environ.get("DLP_CHECK_RATE_TONE") or "sarcastic").strip().lower() in ("plain", "off", "0", "no"):
        return ""
    options = [q for q in _QUIPS.get(case, []) if "{writes}" not in q or writes]
    if not options:
        return ""
    q = options[int(now // 3600) % len(options)]
    return q.format(writes=writes, hourly_text=f" ({hourly} an hour)" if hourly else "")


def _ago(seconds: float) -> str:
    return f"{_human(seconds)} ago" if seconds >= 1 else "just now"


def history_text(f: Dict[str, Any]) -> str:
    """What the app executed that the check is based on, in one line."""
    parts = []
    sent = f.get("sent_last_hour") or {}
    plural = {"write": "writes (POST/PUT)", "delete": "deletes", "endpoint_rules": "Endpoint DLP rule writes",
              "cloud_app": "Cloud App Control rule writes", "activate": "activations", "read": "reads (GET)"}
    if sent:
        parts.append("In the last hour Zscaler Made Easy sent this tenant's API client " + ", ".join(f"{n} {plural.get(k, k)}" for k, n in sent.items()) + ".")
    else:
        parts.append("Zscaler Made Easy sent this tenant's API client nothing in the last hour.")
    tol = f.get("tolerated")
    if tol:
        parts.append(f"Fewest writes ZIA blocked it at: {tol['writes_5m']} in 5 minutes"
                     + (f" (with {tol['reads_5m']} reads)" if tol.get("reads_5m") else "") + f", {_day_clock(tol['at'])}.")
    runs = f.get("refused_runs") or []
    if runs:
        parts.append(f"{len(runs)} run(s) in the deployment log of the last week were refused for ZIA's rate (latest {_day_clock(runs[-1]['at'])}).")
    return " ".join(parts)


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
        per_channel[chan] = {"rules": int(n), "bucket": b,
                             "seconds": (lambda ts: ts[-1] - ts[0] if ts else 0.0)(_simulate(limits_default(b), [], 0.0, int(n))),
                             "over_hourly": int(n) > max((lim for lim, w in limits_default(b) if w >= HOUR), default=10 ** 9)}
    tight = [c for c, v in per_channel.items() if v["bucket"] != "write"]
    text = (f"Full deploy: {sum(deploy.values())} requests, about {_human(d['seconds'])} at ZIA's limits"
            + (" (Endpoint DLP rules go at 10/min and 40/hr)" if "endpoint" in tight else "")
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
        for t in list(_tenants.values()):
            for q in t.sent.values():
                q.clear()
            t.hold[0] = 0.0
            t.read_hold[0] = 0.0
            t.refused.clear()
            t.server.clear()
        for k in [k for k in _tenants if k]:
            del _tenants[k]
        _loaded[0] = True   # a reset is a fresh start: do not read the file back
        _seen[0] = _stamp()
        _saved_at[0] = 0.0
    _ctx.prepaced = None
