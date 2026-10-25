"""Self-healing: the app repairs itself, and the tenant heals back to what
you approved.

Layer 1, this app (on by default, never touches the tenant). Small checks
that each find one kind of problem, repair it safely and say what they did:

  jobs         a background job whose thread died, or that has run far past
               any run's length without a log line, is ended as failed with
               the reason, so the page stops waiting and the user can retry;
  stores       a local JSON store (tenant profiles, deployment records,
               proposals, the change queue, digests, guidance and rate
               state...) that cannot be read is moved aside as
               <name>.corrupt-<time> (never deleted) and restored from its
               last good copy (<name>.last-good, kept by keep_last_good on
               every atomic write), else the store starts empty and says so;
  permissions  secrets and stores readable by others are set back to 0600,
               the digests folder to 0700;
  locks        a lock left by a process that is gone (the loop's run lock,
               the rate-state lock, server.pid, git's index.lock) is released;
  rate holds   a ZIA rate-limit hold that ends further away than any limit's
               window (a clock set back) is lifted;
  sign-in      after repeated sign-in failures the SDK's cached sign-in is
               dropped so the next call signs in from scratch;
  disk         low free space on the data folder: a warning, and the app's
               own old digests beyond retention are pruned;
  version      the code on disk changed after the server started (an update
               without a restart): reported, with Restart as the fix.

They run at startup, on a light timer (DLP_CHECK_SELF_HEAL_MINUTES, default
10, 0 turns both off) and when asked (POST /api/self-heal/run). Every run
is written to the audit log and kept for GET /api/self-heal.

Layer 2, your tenant (read-only until you click Heal). The drift step's
read (pack_deploy.preflight of the ticked packs, on the DLP channels in
scope) is compared with what was approved: the settings as first seen,
moved forward by every recorded approved change (this app's own writes,
its deployment and operation records, applied proposals and change
requests) and by enabling or hardening (progress, never drift). A rule
turned off, an action weakened, an engine or dictionary edited or deleted,
or a fix you applied that was undone becomes a heal proposal in the
proposal queue (kind heal_drift): the exact change that puts it back, with
who and when when ZIA's audit log was read. The person heals it through
the existing apply path (proposal_apply: write gate, a preview that
re-reads the rule and refuses when it moved again, the typed confirmation,
read-back, recorded rollback), or accepts it ("accepted - stop
proposing"), which makes the current value the approved one. Nothing here
writes to the tenant.

DLP_CHECK_SELF_HEAL_AUTO_APPLY (off): applying heal proposals without a
person clicking Heal is not part of this version. The setting is read so
the page can show it, and auto_apply() refuses it whatever it says,
because changing a customer's tenant on its own is a decision for the
product owner, not a default.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Iterator, List, Optional, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
OK, HEALED, NEEDS_YOU = "ok", "healed", "needs_you"
STATUS_WORDS = {OK: "OK", HEALED: "Healed", NEEDS_YOU: "Needs you"}
LAST_GOOD = ".last-good"
CORRUPT = ".corrupt-"
STATE_FILE = "self_heal.json"
MINUTES_ENV = "DLP_CHECK_SELF_HEAL_MINUTES"
AUTO_APPLY_ENV = "DLP_CHECK_SELF_HEAL_AUTO_APPLY"
DEFAULT_MINUTES = 10.0
MAX_MINUTES = 24 * 60.0
MAX_LAST_GOOD_BYTES = 64 * 1024 * 1024
APPROVED_LIMIT = 5000
ACCEPTED_LIMIT = 500
AUTO_APPLY_REFUSAL = ("Automatic healing is not enabled in this version: every heal is applied only when a person clicks Heal "
                      "and types the confirmation. Whether the app may ever change the tenant on its own is the product owner's decision.")

_STATE_LOCK = threading.RLock()
_RUN_LOCK = threading.Lock()
_STARTED = {"at": time.time(), "commit": None}
_AUTH_FAILURES: Deque[float] = deque(maxlen=50)
_AUTH_LOCK = threading.Lock()


def _iso(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).isoformat(timespec="seconds")


def _ts(value: Any) -> Optional[float]:
    """Epoch seconds of an ISO time (with or without a zone; +0000 too)."""
    s = str(value or "").strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", s):
        s = s[:-2] + ":" + s[-2:]
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def _env_float(name: str, default: float) -> float:
    try:
        return float((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


# ── settings ────────────────────────────────────────────────────────────
def interval_minutes() -> float:
    """DLP_CHECK_SELF_HEAL_MINUTES (default 10). 0, negative or unusable
    turns the startup run and the timer off (Run now still works); a value
    below 1 minute is raised to 1, one above a day lowered to a day."""
    raw = (os.environ.get(MINUTES_ENV) or "").strip()
    if not raw:
        return DEFAULT_MINUTES
    try:
        m = float(raw)
    except ValueError:
        return 0.0
    if m != m or m <= 0:   # NaN, 0, negative
        return 0.0
    return min(max(m, 1.0), MAX_MINUTES)


def auto_apply_setting() -> Dict[str, Any]:
    """What DLP_CHECK_SELF_HEAL_AUTO_APPLY says, and that it is not honoured."""
    raw = (os.environ.get(AUTO_APPLY_ENV) or "").strip()
    return {"setting": AUTO_APPLY_ENV, "value": raw or "(unset: off)",
            "requested": raw.lower() in ("1", "true", "yes", "on"), "enabled": False, "why": AUTO_APPLY_REFUSAL}


def auto_apply(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
    """Refused in this version, whatever the setting says. Reads and writes nothing."""
    return {"ok": False, "applied": 0, "status": "refused", "why": AUTO_APPLY_REFUSAL, "setting": auto_apply_setting()}


def settings() -> Dict[str, Any]:
    m = interval_minutes()
    return {"interval_minutes": m, "setting": MINUTES_ENV, "value": os.environ.get(MINUTES_ENV) or f"(unset: {DEFAULT_MINUTES:g})",
            "timer": ("every %g minute(s), and once when the server starts" % m) if m > 0 else "off (Run now still works)",
            "auto_apply": auto_apply_setting(), "data_dir": data_dir()}


# ── where things live ───────────────────────────────────────────────────
def data_dir() -> str:
    """The folder the app keeps its stores in (beside proposals.json: /data in the container)."""
    try:
        import proposals
        return os.path.dirname(os.path.abspath(proposals.store_path()))
    except Exception:  # noqa: BLE001
        return ROOT


def state_path() -> str:
    return os.environ.get("DLP_CHECK_SELF_HEAL_STATE") or os.path.join(data_dir(), STATE_FILE)


# ── safe files ──────────────────────────────────────────────────────────
def _chmod(path: str, mode: int) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


def _atomic_write_bytes(path: str, raw: bytes) -> None:
    folder = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".selfheal-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            with contextlib.suppress(OSError):
                os.fsync(f.fileno())
        _chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _parse(raw: bytes, shape: Optional[Callable[[Any], bool]] = None) -> Tuple[bool, str]:
    """(readable, why not) for a store's bytes."""
    if not raw.strip():
        return False, "the file is empty (a write that never finished)"
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return False, "the file is not text"
    except ValueError as e:
        return False, f"the file is not valid JSON ({str(e)[:80]})"
    if shape is not None:
        try:
            ok = bool(shape(data))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            return False, "the file is JSON but not in the shape the app writes"
    return True, ""


def _valid_file(path: str, shape: Optional[Callable[[Any], bool]] = None) -> Tuple[bool, str]:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_LAST_GOOD_BYTES + 1)
    except FileNotFoundError:
        return True, ""
    except OSError as e:
        return False, f"the file cannot be opened ({type(e).__name__})"
    if len(raw) > MAX_LAST_GOOD_BYTES:
        return True, ""   # too large to check here; the store itself decides
    return _parse(raw, shape)


def move_aside(path: str) -> str:
    """Move a damaged file to <path>.corrupt-<UTC time> (a number added when
    that name is taken) and return the new path. Never deletes it."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = f"{path}{CORRUPT}{stamp}"
    n = 1
    while os.path.exists(dest):
        n += 1
        dest = f"{path}{CORRUPT}{stamp}-{n}"
    os.replace(path, dest)
    _chmod(dest, 0o600)
    return dest


def keep_last_good(path: str) -> Optional[str]:
    """Called by a store's atomic write right before it replaces `path`.
    When the file there now is readable it is kept as <path>.last-good
    (one rolling copy, owner-only); when it is not, it is moved aside as
    <path>.corrupt-<time> (never lost, never copied over the last good
    one). Returns what was done, or None. Never raises."""
    try:
        try:
            if os.path.getsize(path) > MAX_LAST_GOOD_BYTES:
                return None
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            return None
        ok, _why = _parse(raw, _shape_for(path))
        if not ok:
            return "moved aside: " + os.path.basename(move_aside(path))
        _atomic_write_bytes(path + LAST_GOOD, raw)
        return "kept"
    except Exception:  # noqa: BLE001 - a store write never fails over its copy
        return None


# ── the app's stores ────────────────────────────────────────────────────
def _is_dict(d: Any) -> bool:
    return isinstance(d, dict)


def _store_entries() -> List[Dict[str, Any]]:
    """Every local JSON store the app keeps: label (plain words), path,
    shape check, the lock its writer holds, and whether it keeps a
    last-good copy."""
    out: List[Dict[str, Any]] = []

    def add(key: str, label: str, path_fn: Callable[[], str], shape: Callable[[Any], bool], lock: Any = None, keeps: bool = False) -> None:
        try:
            p = path_fn()
        except Exception:  # noqa: BLE001
            return
        if p:
            out.append({"key": key, "label": label, "path": os.path.abspath(p), "shape": shape, "lock": lock, "keeps": keeps})

    try:
        import tenant_profiles
        add("tenant_profiles", "Tenant profiles", tenant_profiles.store_path,
            lambda d: _is_dict(d) and isinstance(d.get("profiles", {}), dict), lambda: tenant_profiles._LOCK, True)
    except Exception:  # noqa: BLE001
        pass
    try:
        import deployments
        add("deployments", "Deployment records", deployments.store_path,
            lambda d: _is_dict(d) and isinstance(d.get("deployments", []), list), None, True)
    except Exception:  # noqa: BLE001
        pass
    try:
        import proposals
        add("proposals", "Proposal queue", proposals.store_path,
            lambda d: _is_dict(d) and isinstance(d.get("tenants"), dict), lambda: proposals._LOCK, True)
    except Exception:  # noqa: BLE001
        pass
    try:
        import change_queue
        add("change_queue", "Change queue", change_queue.store_path,
            lambda d: _is_dict(d) and isinstance(d.get("requests"), dict), lambda: change_queue._locked(), True)
    except Exception:  # noqa: BLE001
        pass
    add("self_heal", "Self-healing history and approved settings", state_path, _is_dict, lambda: _STATE_LOCK, True)
    try:
        import guidance
        add("guidance", "Guidance history", guidance.state_path, _is_dict)
    except Exception:  # noqa: BLE001
        pass
    try:
        import zia_rate
        add("zia_rate", "ZIA rate-limit history", zia_rate.state_path, _is_dict)
    except Exception:  # noqa: BLE001
        pass
    if os.environ.get("DLP_CHECK_BEACON_STATE"):
        add("beacon", "Beacon history", lambda: os.environ["DLP_CHECK_BEACON_STATE"], _is_dict)
    # Workspace data, when the installed version has a workspace store.
    try:
        import importlib
        ws = importlib.import_module("workspace")
        if callable(getattr(ws, "store_path", None)):
            add("workspace", "Workspace data", ws.store_path, _is_dict, getattr(ws, "_LOCK", None) and (lambda: ws._LOCK), True)
    except Exception:  # noqa: BLE001
        pass
    return out


def _shape_for(path: str) -> Optional[Callable[[Any], bool]]:
    ap = os.path.abspath(path)
    for e in _store_entries():
        if e["path"] == ap:
            return e["shape"]
    return None


@contextlib.contextmanager
def _held(lock_fn: Any) -> Iterator[None]:
    if lock_fn is None:
        yield
        return
    lk = lock_fn()
    if hasattr(lk, "__enter__"):
        with lk:
            yield
    else:
        yield


# ── the self-healing state (this module's own store) ────────────────────
def _read_state() -> Dict[str, Any]:
    try:
        with open(state_path(), "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("tenants", {})
            return d
    except (OSError, ValueError):
        pass
    return {"version": 1, "tenants": {}}


def _write_state(d: Dict[str, Any]) -> None:
    p = state_path()
    keep_last_good(p)
    _atomic_write_bytes(p, json.dumps(d, indent=1, default=str).encode("utf-8"))


# ═════════════════════════════ LAYER 1 ═════════════════════════════════
def _result(cid: str, name: str, status: str, summary: str, actions: Optional[List[str]] = None, next_step: str = "",
            fix: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    r = {"id": cid, "name": name, "status": status, "status_label": STATUS_WORDS[status], "summary": summary,
         "actions": list(actions or []), "next": next_step}
    if fix:
        r["fix"] = fix
    return r


# ── jobs ────────────────────────────────────────────────────────────────
def check_jobs(now: Optional[float] = None) -> Dict[str, Any]:
    """A running job whose thread is gone, or that has run longer than
    DLP_CHECK_SELF_HEAL_STUCK_MINUTES (120) with no log line for
    DLP_CHECK_SELF_HEAL_QUIET_MINUTES (30) and is not waiting out ZIA's rate
    limit, is ended as failed with the reason (pack_jobs.abandon)."""
    import pack_jobs
    now = now or time.time()
    stuck_after = max(1.0, _env_float("DLP_CHECK_SELF_HEAL_STUCK_MINUTES", 120.0)) * 60
    quiet_after = max(1.0, _env_float("DLP_CHECK_SELF_HEAL_QUIET_MINUTES", 30.0)) * 60
    actions: List[str] = []
    running = pack_jobs.running()
    for job in running:
        th = getattr(job, "thread", None)
        name = job.label or job.kind
        if th is not None and not th.is_alive():
            reason = ("Ended by self-healing: the job's worker stopped without reporting a result (the server may have run out "
                      "of memory or a library crashed). Nothing more is sent. Start it again.")
            if pack_jobs.abandon(job, reason):
                actions.append(f"Marked the job '{name}' as failed: its worker had stopped. You can start it again.")
            continue
        paused = 0.0
        if getattr(job, "rate_key", None) is not None:
            try:
                import zia_rate
                paused = zia_rate.paused_for(job.rate_key)
            except Exception:  # noqa: BLE001
                paused = 0.0
        age, quiet = now - job.started, now - float(getattr(job, "last_log_at", job.started) or job.started)
        if age > stuck_after and quiet > quiet_after and paused <= 0:
            reason = (f"Ended by self-healing: the job ran for {int(age // 60)} minutes and wrote nothing for {int(quiet // 60)} minutes, "
                      "so it is treated as stuck. Stop was sent, so nothing more is sent to the tenant. Start it again.")
            if pack_jobs.abandon(job, reason):
                actions.append(f"Marked the job '{name}' as failed: no progress for {int(quiet // 60)} minutes. You can start it again.")
    if actions:
        return _result("jobs", "Background jobs", HEALED, f"{len(actions)} stuck job(s) ended so the page stops waiting.", actions,
                       "Start the job again from the page that ran it. If it gets stuck again, look at server.log.")
    return _result("jobs", "Background jobs", OK, f"No job is stuck ({len(running)} running).")


# ── stores ──────────────────────────────────────────────────────────────
def check_stores() -> Dict[str, Any]:
    """Every store that cannot be read is moved aside and restored from its
    last good copy, else started empty; damaged digests are moved aside."""
    actions: List[str] = []
    lost: List[str] = []
    checked = 0
    for e in _store_entries():
        p = e["path"]
        if not os.path.exists(p):
            continue
        checked += 1
        ok, why = _valid_file(p, e["shape"])
        if ok:
            continue
        with _held(e["lock"]):
            ok, why = _valid_file(p, e["shape"])   # a write may have just replaced it
            if ok or not os.path.exists(p):
                continue
            dest = move_aside(p)
            lg = p + LAST_GOOD
            lg_ok = os.path.exists(lg) and _valid_file(lg, e["shape"])[0]
            if lg_ok:
                with open(lg, "rb") as f:
                    _atomic_write_bytes(p, f.read())
                when = _iso(os.path.getmtime(lg))
                actions.append(f"{e['label']}: {why}. Moved it aside as {os.path.basename(dest)} and restored the last good copy (saved {when}).")
            else:
                actions.append(f"{e['label']}: {why}. Moved it aside as {os.path.basename(dest)}; no good copy was kept, so it starts empty.")
                lost.append(f"{e['label']} ({os.path.basename(dest)})")
    try:
        import continuous_eval
        dd = continuous_eval.digest_dir()
        for n in sorted(os.listdir(dd)):
            if n.startswith("digest-") and n.endswith(".json"):
                p = os.path.join(dd, n)
                checked += 1
                ok, why = _valid_file(p, _is_dict)
                if not ok:
                    dest = move_aside(p)
                    actions.append(f"Digest {n}: {why}. Moved it aside as {os.path.basename(dest)}; the other digests are fine.")
    except Exception:  # noqa: BLE001
        pass
    now = time.time()
    with _STATE_LOCK:
        st = _read_state()
        losses = [x for x in st.get("store_losses") or [] if isinstance(x, dict) and now - (_ts(x.get("at")) or 0) < 7 * 86400]
        if lost or len(losses) != len(st.get("store_losses") or []):
            losses += [{"at": _iso(now), "what": x} for x in lost]
            st["store_losses"] = losses[-20:]
            with contextlib.suppress(Exception):
                _write_state(st)
    if not lost and losses:
        # Shown for a week, so a file that had to start empty is not forgotten after the next run.
        lost = [x["what"] for x in losses]
        actions = actions + [f"Earlier ({str(x['at'])[:16].replace('T', ' ')} UTC): {x['what']} was damaged and started empty." for x in losses]
    if lost:
        return _result("stores", "Saved data", NEEDS_YOU, f"{len(lost)} saved file(s) were damaged and had no good copy to restore.", actions,
                       "The damaged copies are kept next to the original (named .corrupt-<time>); nothing was deleted. Re-enter what is "
                       "missing, or open the kept copy in a text editor to recover it: " + "; ".join(lost) + ".")
    if actions:
        return _result("stores", "Saved data", HEALED, f"{len(actions)} damaged file(s) repaired.", actions,
                       "Nothing to do. The damaged copies are kept next to the original in case you want to look at them.")
    return _result("stores", "Saved data", OK, f"All {checked} saved file(s) can be read.")


# ── permissions ─────────────────────────────────────────────────────────
def _permission_targets() -> Tuple[List[str], List[str]]:
    files: List[str] = []
    for e in _store_entries():
        files += [e["path"], e["path"] + LAST_GOOD]
        folder = os.path.dirname(e["path"])
        base = os.path.basename(e["path"]) + CORRUPT
        with contextlib.suppress(OSError):
            files += [os.path.join(folder, n) for n in os.listdir(folder) if n.startswith(base)]
    with contextlib.suppress(Exception):
        import audit
        files += [audit.path(), audit.path() + ".1"]
    with contextlib.suppress(Exception):
        import security
        files.append(os.path.join(os.environ.get("DLP_CHECK_UI_TOKEN_DIR") or ROOT, security.UI_TOKEN_FILE))
    with contextlib.suppress(Exception):
        import tenant_fingerprint
        files.append(tenant_fingerprint.key_path())
    files.append(os.path.join(ROOT, "tenant_config.json"))
    dirs: List[str] = []
    with contextlib.suppress(Exception):
        import continuous_eval
        dirs.append(continuous_eval.digest_dir())
    seen = set()
    return [f for f in files if f and not (f in seen or seen.add(f)) and os.path.isfile(f)], [d for d in dirs if os.path.isdir(d)]


def check_permissions() -> Dict[str, Any]:
    """Secrets and stores that others can read are set to 0600, the digests folder to 0700 (POSIX, own files only)."""
    if os.name == "nt":
        return _result("permissions", "File permissions", OK, "Not checked on Windows: the folder's own access rules apply.")
    files, dirs = _permission_targets()
    uid = os.getuid()
    actions: List[str] = []
    failed: List[str] = []
    for path, want in [(f, 0o600) for f in files] + [(d, 0o700) for d in dirs]:
        try:
            st = os.stat(path)
        except OSError:
            continue
        if st.st_uid != uid or not (st.st_mode & 0o077):
            continue
        before = st.st_mode & 0o777
        try:
            os.chmod(path, want)
            actions.append(f"{os.path.basename(path)}: others could read it ({before:o}); now only you can ({want:o}).")
        except OSError as e:
            failed.append(f"{os.path.basename(path)} ({type(e).__name__})")
    if failed:
        return _result("permissions", "File permissions", NEEDS_YOU, "Some files others can read could not be locked down.", actions,
                       "Run the app as the user that owns its folder, or set these files to owner-only yourself: " + ", ".join(failed) + ".")
    if actions:
        return _result("permissions", "File permissions", HEALED, f"{len(actions)} file(s) made private again.", actions,
                       "Nothing to do. If this comes back, something else (a backup tool, a copy command) is changing the permissions.")
    return _result("permissions", "File permissions", OK, f"All {len(files) + len(dirs)} secret and data file(s) are private.")


# ── locks ───────────────────────────────────────────────────────────────
def pid_alive(pid: int) -> Optional[bool]:
    """True / False on POSIX; None where it cannot be told (Windows)."""
    if pid <= 0:
        return False
    if os.name == "nt":
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _pid_marker(path: str) -> Optional[int]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first = (f.read(200).split() or [""])[0]
        return int(first) if first.isdigit() else None
    except OSError:
        return None


def _flock_held(path: str) -> Optional[bool]:
    """Whether another open file holds an exclusive flock on `path` (POSIX)."""
    try:
        import fcntl
    except ImportError:
        return None
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _git_dir(app_dir: str) -> Optional[str]:
    g = os.path.join(app_dir, ".git")
    if os.path.isdir(g):
        return g
    try:
        with open(g, "r", encoding="utf-8") as f:
            line = f.read(4096).strip()
    except OSError:
        return None
    if line.startswith("gitdir:"):
        p = line[7:].strip()
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(app_dir, p))
    return None


def check_locks(now: Optional[float] = None) -> Dict[str, Any]:
    """Locks a crashed process left behind are released: the loop's run
    lock (its owner PID is gone while the lock is still held), the rate
    state's lock file (older than two minutes), server.pid naming a
    process that is gone, and git's index.lock (older than ten minutes)."""
    now = now or time.time()
    actions: List[str] = []
    notes: List[str] = []
    # 1. the continuous evaluation's run lock
    try:
        import continuous_eval
        p = os.path.join(continuous_eval.digest_dir(), continuous_eval.LOCK_NAME)
        if os.path.exists(p):
            pid = _pid_marker(p)
            held = _flock_held(p)
            alive = pid_alive(pid) if pid else None
            if held and pid and alive is False:
                os.remove(p)   # the next run locks a fresh file; a lock file holds no data
                actions.append(f"Released the evaluation loop's lock: its owner (process {pid}) is gone.")
            elif held and pid and alive:
                notes.append(f"a run of the evaluation loop is in progress (process {pid})")
            elif held is False and pid and alive is False:
                with open(p, "w", encoding="utf-8"):
                    pass   # the lock is free; only the stale owner note is cleared
    except Exception:  # noqa: BLE001
        pass
    # 2. the ZIA rate state's lock file (an O_EXCL file; a save waits at most seconds for it)
    try:
        import zia_rate
        p = zia_rate.state_path() + ".lock"
        if os.path.exists(p) and now - os.path.getmtime(p) > 120:
            os.remove(p)
            actions.append("Removed a leftover ZIA rate-limit state lock (older than two minutes).")
    except Exception:  # noqa: BLE001
        pass
    # 3. server.pid naming a process that is gone (stop.sh would otherwise act on a reused number)
    p = os.path.join(ROOT, "server.pid")
    pid = _pid_marker(p) if os.path.exists(p) else None
    if pid and pid != os.getpid() and pid_alive(pid) is False:
        with contextlib.suppress(OSError):
            os.remove(p)
            actions.append(f"Removed server.pid: process {pid} is gone.")
    # 4. git's index.lock left by an interrupted update
    g = _git_dir(ROOT)
    if g:
        p = os.path.join(g, "index.lock")
        if os.path.exists(p) and now - os.path.getmtime(p) > 600:
            try:
                os.remove(p)
                actions.append("Removed git's index.lock left by an interrupted update (older than ten minutes).")
            except OSError as e:
                return _result("locks", "Locks", NEEDS_YOU, "An old git lock could not be removed.", actions,
                               f"Close any git or update window, then delete {p} ({type(e).__name__}).")
    if actions:
        return _result("locks", "Locks", HEALED, f"{len(actions)} lock(s) left by a process that is gone released.", actions,
                       "Nothing to do; the next run takes a fresh lock.")
    return _result("locks", "Locks", OK, "No lock is held by a process that is gone" + (f" ({'; '.join(notes)})." if notes else "."))


# ── rate holds ──────────────────────────────────────────────────────────
def check_rate_holds() -> Dict[str, Any]:
    import zia_rate
    found = zia_rate.overlong_holds(clear=True)
    if found:
        acts = [f"Lifted a ZIA rate-limit pause on {h['kind']} (tenant key {h['tenant']}…) that would have lasted another "
                f"{zia_rate.human(h['seconds_left'])}, longer than any ZIA limit window." for h in found]
        return _result("rate_holds", "ZIA rate-limit pauses", HEALED, f"{len(found)} pause(s) that outlived their window lifted.", acts,
                       "Nothing to do. If it comes back, check the computer's clock: a clock set back makes a pause look longer.")
    return _result("rate_holds", "ZIA rate-limit pauses", OK, "No pause is longer than ZIA's limit windows.")


# ── sign-in ─────────────────────────────────────────────────────────────
def note_auth_failure() -> None:
    """The server calls this when signing in to a tenant fails. No detail is kept (never a secret)."""
    with _AUTH_LOCK:
        _AUTH_FAILURES.append(time.time())


def _drop_sdk_sign_in() -> bool:
    """Clear the zscaler SDK's process-wide OAuth token (zscaler.oneapi_oauth_client.OAuth: a singleton per
    configuration holding the access token) so the next client signs in from scratch."""
    try:
        from zscaler.oneapi_oauth_client import OAuth   # type: ignore
    except Exception:  # noqa: BLE001
        return False
    inst = getattr(OAuth, "_instance", None)
    if inst is not None:
        with contextlib.suppress(Exception):
            inst.clear_access_token()
    OAuth._instance = None
    OAuth._last_config = None
    return True


def check_sign_in(now: Optional[float] = None) -> Dict[str, Any]:
    now = now or time.time()
    window = 15 * 60
    with _AUTH_LOCK:
        recent = [t for t in _AUTH_FAILURES if now - t <= window]
        repeated = len(recent) >= 3
        if repeated:
            _AUTH_FAILURES.clear()
    if repeated:
        dropped = _drop_sdk_sign_in()
        return _result("sign_in", "Signing in to Zscaler", HEALED,
                       f"Signing in failed {len(recent)} times in 15 minutes.",
                       ["Dropped the cached sign-in, so the next call signs in from scratch." if dropped
                        else "Nothing was cached; the next call signs in from scratch."],
                       "If signing in still fails, check the client ID and secret on Connect to the tenant, and that the API client is enabled in ZIdentity.")
    return _result("sign_in", "Signing in to Zscaler", OK, "No repeated sign-in failures.")


# ── disk ────────────────────────────────────────────────────────────────
def check_disk() -> Dict[str, Any]:
    folder = data_dir()
    try:
        free = shutil.disk_usage(folder).free
    except OSError:
        return _result("disk", "Disk space", OK, "Free space could not be read; skipped.")
    need = max(1.0, _env_float("DLP_CHECK_SELF_HEAL_MIN_FREE_MB", 500.0)) * 1024 * 1024
    mb = free / 1024 / 1024
    if free >= need:
        return _result("disk", "Disk space", OK, f"{mb:,.0f} MB free where the app keeps its data.")
    pruned, freed = prune_old_digests()
    actions = [f"Removed {pruned} old digest file(s) the app wrote itself ({freed / 1024 / 1024:.1f} MB), keeping the newest ones and the last two weeks."] if pruned else []
    free2 = shutil.disk_usage(folder).free
    if free2 >= need:
        return _result("disk", "Disk space", HEALED, f"Disk space was low; {free2 / 1024 / 1024:,.0f} MB free now.", actions, "Nothing to do for now.")
    return _result("disk", "Disk space", NEEDS_YOU, f"Only {free2 / 1024 / 1024:,.0f} MB free where the app keeps its data ({folder}).", actions,
                   "Free up space on that disk: the app needs room to save profiles, the audit log and reports. "
                   "The app removed only its own old digests; your files were not touched.")


def prune_old_digests(keep_newest: int = 10, keep_days: float = 14.0) -> Tuple[int, int]:
    """Remove the app's own digest files (digest-<time>.json/.md) older than
    `keep_days`, always keeping the newest `keep_newest`. Moved-aside
    (.corrupt-) copies are never touched. Returns (files removed, bytes)."""
    import continuous_eval
    dd = continuous_eval.digest_dir()
    pat = re.compile(r"^digest-\d{8}-\d{6}\.(json|md)$")
    stems = sorted({n.rsplit(".", 1)[0] for n in os.listdir(dd) if pat.match(n)}, reverse=True)
    cutoff = time.time() - keep_days * 86400
    removed, freed = 0, 0
    for stem in stems[keep_newest:]:
        for ext in (".json", ".md"):
            p = os.path.join(dd, stem + ext)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mtime < cutoff:
                with contextlib.suppress(OSError):
                    os.remove(p)
                    removed += 1
                    freed += st.st_size
    return removed, freed


# ── version ─────────────────────────────────────────────────────────────
def _git_head(app_dir: str) -> Optional[str]:
    try:
        import subprocess
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=app_dir, stderr=subprocess.DEVNULL, timeout=3)
        return out.decode().strip() or None
    except Exception:  # noqa: BLE001
        return None


def mark_started() -> None:
    """At server start: the time and the commit the server loaded."""
    _STARTED["at"] = time.time()
    _STARTED["commit"] = _git_head(ROOT)


def _code_changed_since(ts: float) -> List[str]:
    out = []
    with contextlib.suppress(OSError):
        for n in os.listdir(ROOT):
            if n.endswith(".py"):
                with contextlib.suppress(OSError):
                    if os.path.getmtime(os.path.join(ROOT, n)) > ts + 2:
                        out.append(n)
    return sorted(out)


RESTART_FIX = {"label": "Restart the app", "method": "POST", "url": "/api/app/restart"}


def check_version() -> Dict[str, Any]:
    started, then = _STARTED["at"], _STARTED.get("commit")
    now_head = _git_head(ROOT) if then else None
    if then and now_head and now_head != then:
        return _result("version", "App version", NEEDS_YOU,
                       f"The app was updated (now {now_head}) but the server still runs the version it started with ({then}): pages may not match the server.",
                       [], "Restart the app so the new version is loaded, then reload this page.", RESTART_FIX)
    changed = _code_changed_since(started)
    if changed:
        return _result("version", "App version", NEEDS_YOU,
                       f"{len(changed)} program file(s) changed after the server started ({', '.join(changed[:4])}{'…' if len(changed) > 4 else ''}).",
                       [], "Restart the app so the changed files are loaded, then reload this page.", RESTART_FIX)
    return _result("version", "App version", OK, "The server runs the files on disk" + (f" ({then})." if then else "."))


# ── the run ─────────────────────────────────────────────────────────────
CHECKS: List[Tuple[str, str, Callable[[], Dict[str, Any]]]] = [
    ("jobs", "Background jobs", lambda: check_jobs()),
    ("stores", "Saved data", lambda: check_stores()),
    ("permissions", "File permissions", lambda: check_permissions()),
    ("locks", "Locks", lambda: check_locks()),
    ("rate_holds", "ZIA rate-limit pauses", lambda: check_rate_holds()),
    ("sign_in", "Signing in to Zscaler", lambda: check_sign_in()),
    ("disk", "Disk space", lambda: check_disk()),
    ("version", "App version", lambda: check_version()),
]


def run(trigger: str = "manual", actor: Optional[str] = None) -> Dict[str, Any]:
    """Run every layer-1 check once; keep and audit the result. One run at a
    time: a second caller gets the run in progress's last result."""
    if not _RUN_LOCK.acquire(blocking=False):
        last = last_run() or {}
        return dict(last, busy=True)
    try:
        started = time.time()
        results = []
        for cid, name, fn in CHECKS:
            try:
                results.append(fn())
            except Exception as e:  # noqa: BLE001 - one check never stops the others
                results.append(_result(cid, name, NEEDS_YOU, f"The check itself failed ({type(e).__name__}).", [],
                                       "Look at server.log; the other checks still ran."))
        counts = {s: sum(1 for r in results if r["status"] == s) for s in (OK, HEALED, NEEDS_YOU)}
        rec = {"at": _iso(started), "trigger": trigger, "duration_ms": int((time.time() - started) * 1000), "checks": results, "counts": counts}
        with _STATE_LOCK:
            d = _read_state()
            d["last_run"] = rec
            hist = [h for h in d.get("history") or [] if isinstance(h, dict)][-49:]
            hist.append({"at": rec["at"], "trigger": trigger, "counts": counts,
                         "healed": [r["id"] for r in results if r["status"] == HEALED]})
            d["history"] = hist
            with contextlib.suppress(Exception):
                _write_state(d)
        try:
            import audit
            audit.record("self_heal_run", **({"actor": actor} if actor else {}), trigger=trigger, counts=counts,
                         healed=[r["id"] for r in results if r["status"] == HEALED],
                         needs_you=[r["id"] for r in results if r["status"] == NEEDS_YOU],
                         actions=[a[:200] for r in results for a in r["actions"]][:40])
        except Exception:  # noqa: BLE001
            pass
        return rec
    finally:
        _RUN_LOCK.release()


def last_run() -> Optional[Dict[str, Any]]:
    with _STATE_LOCK:
        return _read_state().get("last_run")


def overview() -> Dict[str, Any]:
    """What GET /api/self-heal returns: the last run, the settings, and how
    many tenant heal proposals are open (local data only, nothing read)."""
    lr = last_run()
    open_heals = 0
    with contextlib.suppress(Exception):
        import proposals
        with proposals._LOCK:
            q = proposals._read()["tenants"]
        open_heals = sum(1 for t in q.values() for p in (t.get("proposals") or {}).values()
                         if p.get("kind") == "heal_drift" and p.get("status") in ("open", "approved"))
    needs = (lr or {}).get("counts", {}).get(NEEDS_YOU, 0)
    return {"last_run": lr, "settings": settings(), "running": _RUN_LOCK.locked(), "needs_you": needs, "tenant_heals_open": open_heals,
            "attention": bool(needs or open_heals)}


# ═════════════════════════════ LAYER 2 ═════════════════════════════════
DLP = ("web", "endpoint", "saas", "email")
KIND_WORDS = {"policy": "rule", "engine": "engine", "dictionary": "dictionary", "app_group": "application group"}


def object_key(kind: str, channel: Optional[str], name: str) -> str:
    return f"{kind}:{channel or ''}:{name}"


def _h(value: Any) -> Optional[str]:
    if value is None:
        return None
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def strength(channel: str, action: Any) -> int:
    """0 monitor only, 1 asks or warns the user, 2 blocks (or quarantines)."""
    import pack_channels as pc
    a = str(action or "").upper()
    if not pc.is_enforcing(channel, a):
        return 0
    if a in ("CONFIRM", "CAUTION", "ICAP_RESPONSE", "CUSTOMHEADERINSERTION"):
        return 1
    return 2


ACTION_WORDS = {0: "only watches (monitor)", 1: "asks or warns the user", 2: "blocks"}


def _action_phrase(channel: str, action: Any) -> str:
    return f"{action} ({ACTION_WORDS[strength(channel, action)]})"


def observe(rep: Dict[str, Any], channels: List[str]) -> Dict[str, Any]:
    """What a preflight read of the ticked packs found, per pack object, on
    the DLP channels in `channels`: present or missing, and for a rule its
    id, state, action and engines; for an engine or dictionary a
    fingerprint of its content. Objects whose list could not be read are
    left out (not measured), never reported missing. Pure."""
    import pack_channels as pc
    import pack_deploy as pd
    internal = rep.get("_internal") or {}
    merged, tenant = internal.get("merged") or {}, internal.get("tenant") or {}
    chans = [c for c in channels if c in DLP]
    unreadable = set((tenant.get("unreadable") or {}).keys()) | set(tenant.get("not_read") or [])
    ch_err = {c for c, e in ((tenant.get("channels") or {}).get("errors") or {}).items() if e}
    objects: Dict[str, Dict[str, Any]] = {}
    for kind in ("dictionary", "engine", "policy"):
        for name, item in (merged.get(kind) or {}).items():
            if item.get("status") in pd.BLOCKING_STATUSES:
                continue
            channel = None
            if kind == "policy":
                channel = item.get("channel") or pc.channel_of(item.get("definition") or {})
                if channel not in chans or channel in ch_err or (channel == pc.WEB and "web DLP rules" in unreadable):
                    continue
            elif ("dictionaries" if kind == "dictionary" else "engines") in unreadable:
                continue
            e: Dict[str, Any] = {"kind": kind, "name": name, "channel": channel, "pack": (item.get("packs") or [None])[0],
                                 "present": item.get("status") != pd.CREATE}
            if e["present"]:
                if kind == "policy":
                    t = item.get("tenant") or {}
                    e.update({"id": t.get("id"), "state": str(t.get("state") or "").upper() or None, "action": t.get("action"),
                              "sig": _h(sorted(str(x) for x in (t.get("engine_ids") or [])))})
                elif kind == "dictionary":
                    t = (tenant.get("dictionaries") or {}).get(name)
                    e.update({"id": pd._field(t, "id") if t is not None else None,
                              "sig": _h(pd.tenant_dict_signature(t)) if t is not None else None})
                else:
                    t = (tenant.get("engines") or {}).get(name)
                    e.update({"id": pd._field(t, "id") if t is not None else None,
                              "sig": _h(str(pd._field(t, "engine_expression", "engineExpression", default="") or "")) if t is not None else None})
                if e.get("id") is not None:
                    e["id"] = str(e["id"])
            objects[object_key(kind, channel, name)] = e
    rules: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for c in chans:
        rows = (tenant.get("rules") or []) if c == pc.WEB else ((tenant.get("channels") or {}).get("rules") or {}).get(c) or []
        if c == pc.WEB and "web DLP rules" in unreadable or c in ch_err:
            continue
        for r in rows:
            if isinstance(r, dict) and r.get("name"):
                rules[(c, str(r["name"]))] = r
    return {"objects": objects, "rules": rules, "channels": chans}


def approvals_for(tenant: str, labels: List[str]) -> List[Dict[str, Any]]:
    """Every recorded approved change this app knows of for the tenant:
    its own writes (audit log object_write), Bulk changes operations and
    deployments (deployments.json), applied proposals and applied change
    requests. Each: {name (lower case), id, ts, action (create / update /
    delete), field and value when the record says which value it set,
    source}."""
    import proposals
    tk = proposals.tenant_key(tenant)
    lab = {str(x).strip().lower() for x in labels or [] if x}
    out: List[Dict[str, Any]] = []

    def add(name: Any, oid: Any, ts: Optional[float], source: str, action: str = "update", field: Optional[str] = None, value: Any = None) -> None:
        if ts is None or (not name and oid in (None, "")):
            return
        out.append({"name": str(name or "").strip().lower(), "id": str(oid) if oid not in (None, "") else "", "ts": ts, "source": source,
                    "action": action, "field": field, "value": None if value is None else str(value).upper()})

    with contextlib.suppress(Exception):
        import audit
        for a in audit.tail(20000):
            if isinstance(a, dict) and a.get("event") == "object_write" and a.get("result") == "ok" and str(a.get("tenant") or "").strip().lower() in lab:
                act = str(a.get("action") or "update").lower()
                add(a.get("name"), a.get("id"), _ts(a.get("at")), f"this app's own {act} (audit log)", "delete" if "delet" in act else ("create" if "creat" in act else "update"))
    with contextlib.suppress(Exception):
        import deployments
        data = deployments._read()
        for r in data.get("deployments") or []:
            if str(r.get("tenant_label") or "").strip().lower() in lab:
                for c in r.get("created") or []:
                    add(c.get("name"), c.get("id"), _ts(r.get("at")), f"deployment {r.get('id')}", "create")
                if r.get("undo"):
                    for c in (r.get("undo") or {}).get("results") or []:
                        add(c.get("name"), c.get("id"), _ts((r.get("undo") or {}).get("at")), f"undo of deployment {r.get('id')}", "delete")
        for r in data.get("operations") or []:
            if str(r.get("tenant_label") or "").strip().lower() in lab:
                for u in r.get("items") or []:
                    if u.get("status") == "applied":
                        o = u.get("object") or {}
                        add(o.get("name"), o.get("id"), _ts(r.get("at")), f"Bulk changes: {r.get('title') or r.get('id')}", "update",
                            u.get("field") if u.get("field") in ("state", "action") else None, u.get("after") if u.get("field") in ("state", "action") else None)
    with contextlib.suppress(Exception):
        for p in proposals.list_queue(tk, include_closed=True):
            for key in ("applied", "rolled_back"):
                rec = p.get(key) or {}
                for res in rec.get("results") or []:
                    if res.get("result") == "changed":
                        add(res.get("name"), res.get("rule_id"), _ts(rec.get("at")), f"proposal: {p.get('title')}", "update",
                            rec.get("field") or res.get("field"), res.get("read_back", res.get("to")))
    with contextlib.suppress(Exception):
        import change_queue
        for r in change_queue.list_requests(tk, ["applied"]):
            act = {"pack_removal": "delete", "pack_deploy": "create"}.get(str(r.get("kind")), "update")
            for i in r.get("items") or []:
                add(i.get("name"), i.get("id"), _ts(r.get("applied_at")), f"change request {r.get('id')}", act)
    return out


def _created_by_app(tenant_labels: List[str]) -> Dict[str, Dict[str, Any]]:
    """Objects a recorded deployment created and no undo removed: approved, by the deployment."""
    lab = {str(x).strip().lower() for x in tenant_labels or [] if x}
    out: Dict[str, Dict[str, Any]] = {}
    with contextlib.suppress(Exception):
        import deployments
        for r in deployments._read().get("deployments") or []:
            if str(r.get("tenant_label") or "").strip().lower() not in lab:
                continue
            for c in r.get("created") or []:
                if c.get("undone") or r.get("undone_at"):
                    continue
                key = object_key(str(c.get("kind") or ""), c.get("channel") if c.get("kind") == "policy" else None, str(c.get("name") or ""))
                out[key] = {"at": r.get("at"), "source": f"deployment {r.get('id')}", "id": c.get("id")}
    return out


def _explained(approvals: List[Dict[str, Any]], name: str, oid: Any, since: Optional[float], field: Optional[str] = None,
               value: Any = None) -> Optional[Dict[str, Any]]:
    """The recorded approved change that explains what was read: for a
    deletion (field None) the latest delete of this object after `since`;
    for a field now holding `value`, the latest write after `since` that
    touched it, when it set that value (or does not say which value it set)."""
    n, i = str(name or "").strip().lower(), str(oid or "")
    hits = [a for a in approvals if ((n and a["name"] == n) or (i and a["id"] == i)) and (since is None or a["ts"] > since)]
    if field is None:
        dels = [a for a in hits if a["action"] == "delete"]
        return max(dels, key=lambda a: a["ts"]) if dels else None
    rel = [a for a in hits if a["action"] != "delete" and a.get("field") in (None, field)]
    if not rel:
        return None
    last = max(rel, key=lambda a: a["ts"])
    if last.get("value") is None or str(last["value"]) == str(value if value is None else str(value).upper()):
        return last
    return None


def _accepted(accepted: List[Dict[str, Any]], key: str, field: str, value: Any) -> bool:
    return any(a.get("key") == key and a.get("field") == field and str(a.get("value")) == str(value) for a in accepted or [])


def _who(who_events: Optional[List[Dict[str, Any]]], name: str, since: Optional[float]) -> Dict[str, Any]:
    if who_events is None:
        return {"who": None, "when": None, "how": "Not known yet. Who and when come from ZIA's admin audit log: tick Automation readiness on the Scope page and scan again with Who changed it on, or open Audit timeline."}
    n = str(name or "").strip().lower()
    hits = [e for e in who_events if n and n in {str(e.get("object") or "").strip().lower(), str(e.get("resource") or "").strip().lower()}
            and (since is None or (e.get("ts") or 0) >= since - 60)]
    if not hits:
        return {"who": None, "when": None, "how": "ZIA's admin audit log for the window read has no change to this object."}
    e = max(hits, key=lambda x: x.get("ts") or 0)
    return {"who": e.get("admin") or None, "when": _iso(e["ts"]) if e.get("ts") else (e.get("time_raw") or None),
            "how": f"ZIA admin audit log: {e.get('action') or 'change'}" + (f" via {e['interface']}" if e.get("interface") else "")}


def analyse(observed: Dict[str, Any], approved: Dict[str, Dict[str, Any]], *, approvals: List[Dict[str, Any]],
            accepted: List[Dict[str, Any]], created: Dict[str, Dict[str, Any]], applied_fixes: List[Dict[str, Any]],
            now: Optional[float] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Compare what was read with what was approved. Returns (drifts, the
    approved settings after this read). Pure: reads nothing, writes nothing.

    Approved moves forward on its own when a change is progress (a rule
    turned on, an action made stricter) or a recorded approved change
    explains it; a first look records what is there. Everything else that
    moved backwards is a drift: a rule turned off, an action weakened, an
    engine, dictionary or a rule's engines edited, an object deleted, or a
    fix applied through a proposal undone."""
    now = now or time.time()
    stamp = _iso(now)
    out = {k: dict(v) for k, v in approved.items()}
    drifts: List[Dict[str, Any]] = []
    objects = observed.get("objects") or {}

    def drift(key: str, cur: Dict[str, Any], field: str, kind: str, was: Any, now_v: Any, base: Dict[str, Any], **extra: Any) -> None:
        if _accepted(accepted, key, field, now_v):
            return
        drifts.append({"key": key, "kind": kind, "field": field, "object_kind": cur.get("kind"), "name": cur.get("name"),
                       "channel": cur.get("channel"), "pack": cur.get("pack"), "id": cur.get("id") or base.get("id"),
                       "approved": was, "current": now_v, "approved_at": base.get("at"), "approved_source": base.get("source"), **extra})

    for key, cur in objects.items():
        base = out.get(key)
        if base is None:
            if cur["present"]:
                out[key] = dict(cur, at=stamp, source="first look (what was there when self-healing first read it)")
            elif key in created:
                c = created[key]
                drift(key, cur, "present", "deleted", True, False, {"at": c["at"], "source": c["source"], "id": c.get("id")})
            continue
        since = _ts(base.get("at"))
        if not cur["present"]:
            if _explained(approvals, cur["name"], base.get("id"), since):
                out.pop(key, None)
                continue
            if _accepted(accepted, key, "present", False):
                out.pop(key, None)
                continue
            drift(key, cur, "present", "deleted", True, False, base)
            continue
        changed = [f for f in ("state", "action", "sig") if base.get(f) != cur.get(f)]
        if not changed:
            if cur.get("id") and cur.get("id") != base.get("id"):
                out[key]["id"] = cur["id"]
            continue
        new = dict(base)
        new["id"] = cur.get("id") or base.get("id")
        ch = cur.get("channel") or ""
        for f in changed:
            was, isv = base.get(f), cur.get(f)
            exp = _explained(approvals, cur["name"], new["id"], since, f, isv)
            if exp:
                new[f] = isv                      # a recorded approved change set it: the new approved value
                new["source"] = exp["source"]
                new["at"] = stamp
            elif f == "state":
                if isv == "ENABLED" or was != "ENABLED":
                    new[f] = isv                  # turned on (progress), or another off-state: follow it
                else:
                    drift(key, cur, f, "disabled", was, isv, base)
            elif f == "action":
                if was is None or strength(ch, isv) >= strength(ch, was):
                    new[f] = isv                  # as strict or stricter: progress
                else:
                    drift(key, cur, f, "weakened", was, isv, base)
            elif f == "sig":
                if was is None:
                    new[f] = isv
                else:
                    drift(key, cur, f, "edited", was, isv, base)
        out[key] = new
    # A fix applied through a proposal that was undone since.
    have = {(d["key"], d["field"]) for d in drifts}
    for fx in applied_fixes:
        key = object_key("policy", fx["channel"], fx["name"])
        row = (observed.get("rules") or {}).get((fx["channel"], fx["name"]))
        if row is None or fx["field"] not in row or (key, fx["field"]) in have:
            continue
        cur_v = str(row.get(fx["field"]) or "").upper() if fx["field"] in ("state", "action") else row.get(fx["field"])
        if cur_v == fx["to"]:
            continue
        if _explained(approvals, fx["name"], row.get("id"), _ts(fx["at"]) or 0, fx["field"], cur_v) or _accepted(accepted, key, fx["field"], cur_v):
            continue
        cur = {"kind": "policy", "name": fx["name"], "channel": fx["channel"], "id": str(row.get("id")) if row.get("id") is not None else None, "pack": None}
        drift(key, cur, fx["field"], "undone", fx["to"], cur_v, {"at": fx["at"], "source": f"proposal: {fx['title']}", "id": cur["id"]},
              fix_title=fx["title"])
        if key in out and fx["field"] in out[key]:
            out[key][fx["field"]] = fx["to"]
    if len(out) > APPROVED_LIMIT:
        out = dict(sorted(out.items(), key=lambda kv: str(kv[1].get("at") or ""))[-APPROVED_LIMIT:])
    return drifts, out


def applied_fixes_for(tenant: str) -> List[Dict[str, Any]]:
    """Rule fixes applied through a proposal (not heals), as {channel, name, field, to, at, title}."""
    import proposal_apply
    import proposals
    out = []
    for p in proposals.list_queue(tenant, include_closed=True):
        c = p.get("change") or {}
        if p.get("status") != "applied" or p.get("kind") == "heal_drift" or c.get("apply") != "rule" or c.get("field") not in ("state", "action"):
            continue
        at = (p.get("applied") or {}).get("at")
        for t in proposal_apply._targets(p):
            if t.get("name"):
                out.append({"channel": t["channel"], "name": t["name"], "field": c["field"], "to": str(c.get("to") or "").upper(), "at": at,
                            "title": p.get("title") or p.get("id")})
    return out


def _plain(d: Dict[str, Any]) -> Dict[str, str]:
    """Title, what changed and the heal, in plain words."""
    import pack_channels as pc
    what = KIND_WORDS.get(d.get("object_kind") or "", "object")
    ch = d.get("channel") or ""
    where = f" ({pc.label(ch)})" if ch else ""
    n = d.get("name")
    k = d["kind"]
    if k == "disabled":
        return {"title": f"Turn rule {n}{where} back on",
                "what": f"Rule {n}{where} was turned off ({d['current']}). It was on when you approved it.",
                "heal": "Turns the rule back on (state ENABLED), as you approved it."}
    if k == "weakened":
        return {"title": f"Put back the action of rule {n}{where}",
                "what": f"Rule {n}{where} now {ACTION_WORDS[strength(ch, d['current'])]}: its action went from {_action_phrase(ch, d['approved'])} to {_action_phrase(ch, d['current'])}.",
                "heal": f"Sets the action back to {d['approved']}, as you approved it."}
    if k == "undone":
        return {"title": f"Re-apply the fix to rule {n}{where}",
                "what": f"A fix you applied ({d.get('fix_title') or 'a proposal'}) was undone: the rule's {d['field']} is {d['current']} again, the fix set {d['approved']}.",
                "heal": f"Sets the rule's {d['field']} back to {d['approved']}, as the fix did."}
    if k == "deleted":
        return {"title": f"Bring back {what} {n}{where}",
                "what": f"The {what} {n}{where} was deleted from the tenant. It was there when you approved it.",
                "heal": (f"Open Deploy policy packs, tick the pack {d.get('pack') or ''} and run the preflight: it lists {n} as missing and creates it again "
                         "(a rule comes back turned off and monitor-only, like every pack rule; turn it back on the way you had it).")}
    return {"title": f"Check the changed {what} {n}{where}",
            "what": (f"The {what} {n}{where} was edited: " + ("the engines the rule uses changed." if what == "rule" else "its content is not what you approved.")),
            "heal": ("This app does not keep a copy of the earlier content, so it cannot put it back in one click. Restore it in the ZIA Admin Portal, "
                     "or click Accept if the change was agreed (for example a dictionary someone tuned).")}


def heal_proposals(tenant: str, drifts: List[Dict[str, Any]], who_events: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """One proposal per drift (kind heal_drift, gate approve_double). A rule's
    state or action is healed through proposal_apply (one click); the
    rest are made by hand, with the steps."""
    import proposals
    tk = proposals.tenant_key(tenant)
    out = []
    for d in drifts:
        words = _plain(d)
        target = f"heal:{d['key']}:{d['field']}"
        one_click = d["kind"] in ("disabled", "weakened", "undone") and d.get("object_kind") == "policy" and d["field"] in ("state", "action")
        if one_click:
            change = {"apply": "rule", "rule_id": d.get("id"), "channel": d.get("channel"), "field": d["field"], "from": d["current"], "to": d["approved"]}
            rollback = {"field": d["field"], "to": d["current"]}
        else:
            change = {"apply": "manual", "kind": "redeploy_pack" if d["kind"] == "deleted" else "restore_by_hand", "object": d.get("name"),
                      "object_kind": d.get("object_kind"), "pack": d.get("pack"), "steps": words["heal"]}
            rollback = {"note": "Made by hand; nothing for this app to roll back."}
        since = _ts(d.get("approved_at"))
        out.append({"id": proposals.proposal_id(tk, "heal_drift", target), "tenant": tk, "kind": "heal_drift", "label": proposals.KIND_LABELS["heal_drift"],
                    "target": target, "title": words["title"], "change": change,
                    "evidence": {"what_changed": words["what"], "drift": d["kind"],
                                 "approved_value": "the content you approved" if d["field"] == "sig" else ("present" if d["field"] == "present" else d["approved"]),
                                 "current_value": "different content" if d["field"] == "sig" else ("deleted" if d["field"] == "present" else d["current"]),
                                 "fingerprints": {"approved": d["approved"], "now": d["current"]} if d["field"] == "sig" else None,
                                 "approved_at": d.get("approved_at"), "approved_source": d.get("approved_source"), **_who(who_events, d.get("name") or "", since),
                                 "why": "This setting moved back from what was approved, and no approved change recorded by this app explains it."},
                    "expected_effect": words["heal"], "rollback": rollback, "gate": proposals.GATES["heal_drift"],
                    "applies_via": "phase 3" if one_click else "manual", "one_click": one_click,
                    "channel": d.get("channel"), "rule": d.get("name") if d.get("object_kind") == "policy" else None,
                    "object_key": d["key"], "field": d["field"], "drift": d["kind"], "pack": d.get("pack")})
    return out


def raise_from_report(rep: Dict[str, Any], *, tenant_key: str, labels: List[str], channels: List[str], source: str = "scan",
                      who_events: Optional[List[Dict[str, Any]]] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Self-healing on a preflight read (the drift step's, or a scan's):
    compare, move the approved settings forward, and put a heal proposal in
    the queue for every drift (an open one no longer drifted is resolved;
    one applied or resolved before that drifted again is reopened). Writes
    only local files; nothing is written to the tenant."""
    import proposals
    tk = proposals.tenant_key(tenant_key)
    now = now or time.time()
    observed = observe(rep, channels)
    with _STATE_LOCK:
        d = _read_state()
        t = d["tenants"].setdefault(tk, {})
        approved = t.get("approved") or {}
        accepted = t.get("accepted") or []
    drifts, new_approved = analyse(observed, approved, approvals=approvals_for(tk, labels), accepted=accepted,
                                   created=_created_by_app(labels), applied_fixes=applied_fixes_for(tk), now=now)
    fresh = heal_proposals(tk, drifts, who_events)
    for p in fresh:
        cur = proposals.get(tk, p["id"])
        if cur and cur.get("status") in ("applied", "rolled_back", "resolved", "failed"):
            proposals.set_status(tk, p["id"], "open", note="drifted again since it was healed or resolved", by="self-healing")
    stats = proposals.merge(tk, fresh, source="self_heal", resolve_missing=False) if fresh else {"new": 0, "updated": 0, "resolved": 0, "kept": 0}
    measured = set(observed["objects"]) | {object_key("policy", c, n) for (c, n) in observed["rules"]}
    raised = {p["id"] for p in fresh}
    resolved = 0
    for p in proposals.list_queue(tk):
        if p.get("kind") == "heal_drift" and p.get("status") == "open" and p["id"] not in raised and p.get("object_key") in measured:
            proposals.set_status(tk, p["id"], "resolved", note="no longer drifted: the setting is back to what was approved", by="self-healing")
            resolved += 1
    stats["resolved"] = resolved
    scan = {"at": _iso(now), "source": source, "channels": observed["channels"], "measured": len(observed["objects"]),
            "approved": len(new_approved), "drifts": [{"proposal": p["id"], "title": p["title"], "drift": p["drift"]} for p in fresh],
            "who_read": who_events is not None}
    with _STATE_LOCK:
        d = _read_state()
        t = d["tenants"].setdefault(tk, {})
        t["approved"] = new_approved
        t["last_scan"] = scan
        _write_state(d)
    return {"tenant": tk, "drifts": drifts, "proposals": stats, "scan": scan, "items": fresh}


def scan(client: Any, packs: List[Dict[str, Any]], *, tenant_key: str, labels: List[str], channels: List[str],
         channel_targets: Dict[str, List[str]], casb: bool, who_events: Optional[List[Dict[str, Any]]] = None,
         log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Read the ticked packs (the drift step's read, capped to the scope) and raise heal proposals. Read-only."""
    import pack_deploy
    _log = log or (lambda s: None)
    rep = pack_deploy.preflight(client, packs, writes_enabled=False, apply_tweaks=False, channel_targets=channel_targets,
                                read_scope={"channels": sorted(channels), "casb": bool(casb)}, log=_log)
    ten = rep.get("tenant") or {}
    failed = ([str(e)[:200] for e in (ten.get("errors") or [])] + [f"{ch} rules: {str(e)[:200]}" for ch, e in (ten.get("channel_errors") or {}).items() if e])
    if ten.get("reachable") is False:
        return {"ok": False, "errors": failed or ["the tenant could not be read"], "drifts": [], "items": [],
                "note": "Not measured: the tenant could not be read, so nothing is reported as drifted."}
    res = raise_from_report(rep, tenant_key=tenant_key, labels=labels, channels=channels, source="scan", who_events=who_events)
    res["ok"] = True
    res["errors"] = failed
    if failed:
        res["note"] = "Some lists could not be read; the objects on them were not measured (never reported as deleted)."
    _log(f"Self-healing: {len(res['drifts'])} setting(s) drifted from what was approved; {res['scan']['measured']} object(s) measured.")
    return res


def tenant_view(tenant: str) -> Dict[str, Any]:
    """The heal proposals of one tenant, its last scan and what was accepted. Local data only."""
    import proposals
    tk = proposals.tenant_key(tenant)
    with _STATE_LOCK:
        t = (_read_state().get("tenants") or {}).get(tk) or {}
    items = [p for p in proposals.list_queue(tk, include_closed=True) if p.get("kind") == "heal_drift"]
    return {"tenant": tk, "last_scan": t.get("last_scan"), "accepted": list(t.get("accepted") or [])[-50:],
            "approved_count": len(t.get("approved") or {}), "items": items, "confirm_phrase": proposals.CONFIRM_PHRASE,
            "open": sum(1 for p in items if p.get("status") in ("open", "approved")), "auto_apply": auto_apply_setting()}


def accept(tenant: str, pid: str, *, by: str, note: str = "") -> Dict[str, Any]:
    """"Accepted - stop proposing": the current value becomes the approved
    one for this tenant, the proposal is dismissed, and it is audited.
    Raises ValueError with a message the page can show."""
    import proposals
    tk = proposals.tenant_key(tenant)
    p = proposals.get(tk, pid)
    if not p or p.get("kind") != "heal_drift":
        raise ValueError("heal proposal not found (scan again)")
    if p.get("status") not in ("open", "approved"):
        raise ValueError(f"this heal proposal is {p.get('status')}; only an open one can be accepted")
    key, field = p.get("object_key"), p.get("field")
    ev = p.get("evidence") or {}
    value = (ev.get("fingerprints") or {}).get("now") if field == "sig" else (False if field == "present" else ev.get("current_value"))
    clean = "".join(ch for ch in str(note or "") if ch >= " ")[:300]
    with _STATE_LOCK:
        d = _read_state()
        t = d["tenants"].setdefault(tk, {})
        acc = [a for a in t.get("accepted") or [] if not (a.get("key") == key and a.get("field") == field)]
        acc.append({"key": key, "field": field, "value": value, "at": _iso(), "by": by, "note": clean, "title": p.get("title")})
        t["accepted"] = acc[-ACCEPTED_LIMIT:]
        appr = t.setdefault("approved", {})
        if field == "present":
            appr.pop(key, None)
        elif key in appr:
            appr[key][field] = value
            appr[key]["source"] = f"accepted by {by}"
        _write_state(d)
    out = proposals.decide(tk, pid, "dismiss", by=by, note=("accepted - stop proposing" + (f": {clean}" if clean else "")))
    try:
        import audit
        audit.record("self_heal_accept", tenant=tk, proposal=pid, object=str(key)[:200], field=field, by=by, note=clean)
    except Exception:  # noqa: BLE001
        pass
    return out
