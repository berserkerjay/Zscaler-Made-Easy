"""A daily traffic and session log report from a watched folder (opt-in).

The admin names a folder on this computer where the customer's log
streaming already writes its files (the ZPA LSS log receiver's or the NSS
feed's output folder) and turns the daily report on. Once a day, at the
hour set, the server reads the log files that changed since the previous
run (the first run: the last day) and saves one report with
traffic_logs.save_report: counts only (no user names, addresses or
devices) unless the admin ticked "keep user names". Off by default; nothing
runs until someone turns it on.

Read-only on the folder: files are opened for reading only, never
written, renamed, moved or deleted. Only regular files directly in the
folder are read (no sub-folder, no symbolic link, no hidden file), with a
log extension (LOG_EXTS), at most MAX_FILES files, MAX_FILE_BYTES each and
MAX_TOTAL_BYTES together; anything past that is listed in the run's notes,
never read. The files are untrusted input: traffic_logs.analyze parses
them under its own caps (lines, line length, archive members), exactly as
an upload.

Retention: the run keeps the newest `keep` reports it made itself (1 to
MAX_KEEP) and deletes older ones it made; a report saved by hand is never
touched. The settings, the last run and the names of the reports it made
are kept in an owner-only file (traffic_log_watch.json) in the app's data
folder. Changing the settings or running it now is a server-wide change:
the route asks for the writer check and records it in the audit log.
"""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import safe_files

STORE_FILE = "traffic_log_watch.json"
LOG_EXTS = (".json", ".jsonl", ".ndjson", ".log", ".txt", ".csv", ".tsv", ".gz", ".zip")
MAX_FILES = 200
MAX_FILE_BYTES = 48 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
MAX_KEEP = 30
DEFAULT_KEEP = 7
MAX_FOLDER_CHARS = 400
FIRST_RUN_WINDOW = timedelta(days=1)
_LOCK = threading.RLock()
_RUN_GUARD = threading.Lock()
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
DEFAULTS: Dict[str, Any] = {"enabled": False, "folder": "", "hour": 6, "names": False, "keep": DEFAULT_KEEP}


class WatchError(ValueError):
    """A setting or run this feature refuses; the message says why in plain words."""


def store_path() -> str:
    override = os.environ.get("DLP_CHECK_TRAFFIC_LOG_WATCH")
    if override:
        return override
    from zscaler_update_check import data_dir
    return os.path.join(data_dir(), STORE_FILE)


def _read() -> Dict[str, Any]:
    p = store_path()
    try:
        if os.path.islink(p) or os.path.getsize(p) > 256 * 1024:
            return {}
        with open(p, "r", encoding="utf-8") as f:
            data = safe_files.strict_json_loads(f.read())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: Dict[str, Any]) -> None:
    safe_files.write_private_atomic(store_path(), json.dumps(data, indent=1, default=str))


def get_state() -> Dict[str, Any]:
    """{settings, last_run, reports, next_run}: what the page shows."""
    with _LOCK:
        d = _read()
    s = dict(DEFAULTS)
    s.update({k: d.get("settings", {}).get(k, v) for k, v in DEFAULTS.items()})
    return {"settings": s, "last_run": d.get("last_run"), "reports": list(d.get("reports") or []),
            "next_run": _next_run(s, d.get("last_run")), "limits": {"files": MAX_FILES, "file_mb": MAX_FILE_BYTES // (1024 * 1024),
                                                                     "total_mb": MAX_TOTAL_BYTES // (1024 * 1024), "keep": MAX_KEEP,
                                                                     "extensions": list(LOG_EXTS)}}


def check_folder(folder: Any) -> str:
    """The watched folder, checked: an absolute path to an existing folder
    (its real path), not a file-system root and not the app's own saved
    reports folder. WatchError otherwise (the path is not echoed)."""
    import traffic_logs as tl
    f = str(folder or "").strip()
    if not f:
        raise WatchError("Type the folder the log files are written to.")
    if len(f) > MAX_FOLDER_CHARS or _CTRL.search(f):
        raise WatchError(f"The folder must be a path of at most {MAX_FOLDER_CHARS} characters, without control characters.")
    if not os.path.isabs(f):
        raise WatchError("The folder must be a full path, like /var/log/zscaler or D:\\Logs\\Zscaler.")
    real = os.path.realpath(f)
    if not os.path.isdir(real):
        raise WatchError("That folder does not exist on this computer, or this app may not open it.")
    if os.path.dirname(real) == real:
        raise WatchError("Pick the folder the logs are written to, not the root of a drive.")
    saved = os.path.realpath(tl.saved_dir())
    if real == saved or real.startswith(saved + os.sep):
        raise WatchError("That is the app's own saved reports folder; pick the folder the logs are written to.")
    return real


def check_settings(fields: Dict[str, Any]) -> Dict[str, Any]:
    """The settings as typed, checked (WatchError names what is wrong)."""
    enabled = fields.get("enabled") is True
    hour = fields.get("hour", DEFAULTS["hour"])
    if isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23:
        raise WatchError("The hour is a whole number from 0 to 23 (this computer's time).")
    keep = fields.get("keep", DEFAULT_KEEP)
    if isinstance(keep, bool) or not isinstance(keep, int) or not 1 <= keep <= MAX_KEEP:
        raise WatchError(f"Keep 1 to {MAX_KEEP} daily reports.")
    folder = str(fields.get("folder") or "").strip()
    if enabled or folder:
        folder = check_folder(folder)
    return {"enabled": enabled, "folder": folder, "hour": hour, "names": fields.get("names") is True, "keep": keep}


def save_settings(fields: Dict[str, Any]) -> Dict[str, Any]:
    s = check_settings(fields)
    with _LOCK:
        d = _read()
        d["settings"] = s
        _write(d)
    return get_state()


def _parse(t: Any) -> Optional[datetime]:
    try:
        v = datetime.fromisoformat(str(t))
    except (TypeError, ValueError):
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _next_run(s: Dict[str, Any], last: Optional[Dict[str, Any]], now: Optional[datetime] = None) -> Optional[str]:
    if not s.get("enabled") or not s.get("folder"):
        return None
    local = (now or datetime.now(timezone.utc)).astimezone()
    today_at = local.replace(hour=int(s.get("hour", 6)), minute=0, second=0, microsecond=0)
    last_at = _parse((last or {}).get("at"))
    ran_today = last_at is not None and (last or {}).get("trigger") == "schedule" and last_at.astimezone().date() == local.date()
    if ran_today:
        at = today_at + timedelta(days=1)
    else:
        at = today_at if local < today_at else local   # past the hour and not run yet today: at the next timer tick
    return at.isoformat(timespec="minutes")


def due(now: Optional[datetime] = None) -> bool:
    """True when the daily report should run now: on, a folder set, the
    hour reached (this computer's time) and no scheduled run yet today."""
    st = get_state()
    s, last = st["settings"], st["last_run"] or {}
    if not s.get("enabled") or not s.get("folder"):
        return False
    local = (now or datetime.now(timezone.utc)).astimezone()
    if local.hour < int(s["hour"]):
        return False
    last_at = _parse(last.get("at"))
    return not (last_at is not None and last.get("trigger") == "schedule" and last_at.astimezone().date() == local.date())


def collect(folder: str, since: Optional[datetime]) -> Dict[str, Any]:
    """The log files to read (read-only): {files: [{name, content, encoding}],
    notes, considered}. Regular files directly in the folder, with a log
    extension, changed after `since`, under the caps; never a link, a
    sub-folder or a hidden file."""
    real = check_folder(folder)
    notes: List[str] = []
    picked = []
    try:
        names = sorted(os.listdir(real))
    except OSError as e:
        raise WatchError(f"The folder could not be listed ({type(e).__name__}).") from None
    for name in names:
        if name.startswith(".") or _CTRL.search(name):
            continue
        if not name.lower().endswith(LOG_EXTS):
            continue
        path = os.path.join(real, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            notes.append(f"{name[:80]}: not a plain file (a link or a device), not read")
            continue
        mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc)
        if since is not None and mtime <= since:
            continue
        picked.append((mtime, name, path, st.st_size))
    picked.sort()
    files, total = [], 0
    for mtime, name, path, size in picked:
        if len(files) >= MAX_FILES:
            notes.append(f"more than {MAX_FILES} changed files: the oldest {MAX_FILES} were read, the rest wait for the next run")
            break
        if size > MAX_FILE_BYTES:
            notes.append(f"{name[:80]}: larger than {MAX_FILE_BYTES // (1024 * 1024)} MB, not read")
            continue
        if total + size > MAX_TOTAL_BYTES:
            notes.append(f"the files together pass {MAX_TOTAL_BYTES // (1024 * 1024)} MB: the rest wait for the next run")
            break
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
            with os.fdopen(fd, "rb") as fh:
                data = fh.read(MAX_FILE_BYTES + 1)
        except OSError as e:
            notes.append(f"{name[:80]}: could not be read ({type(e).__name__})")
            continue
        if len(data) > MAX_FILE_BYTES:
            notes.append(f"{name[:80]}: grew past {MAX_FILE_BYTES // (1024 * 1024)} MB while it was read, not read")
            continue
        total += len(data)
        files.append({"name": name, "content": base64.b64encode(data).decode("ascii"), "encoding": "base64"})
    return {"files": files, "notes": notes, "considered": len(picked), "bytes": total}


def run(*, trigger: str = "schedule", now: Optional[datetime] = None, say: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Read the changed log files and save one report (counts only unless
    the settings keep names), then trim the reports this feature made to
    `keep`. Returns the run record (also kept as last_run)."""
    import traffic_logs as tl
    log = say or (lambda m: None)
    if not _RUN_GUARD.acquire(blocking=False):
        raise WatchError("A daily report is being made right now; wait for it to finish.")
    try:
        st = get_state()
        s = st["settings"]
        if not s.get("folder"):
            raise WatchError("Set the folder first.")
        at = now or datetime.now(timezone.utc)
        prev = st["last_run"] or {}
        since = _parse(prev.get("read_until")) or (at - FIRST_RUN_WINDOW)
        rec: Dict[str, Any] = {"at": at.isoformat(timespec="seconds"), "trigger": trigger, "status": "", "since": since.isoformat(timespec="seconds"),
                               "files": 0, "records": 0, "report": None, "notes": [], "names": bool(s.get("names"))}
        try:
            got = collect(s["folder"], since)
            rec["files"], rec["notes"] = len(got["files"]), got["notes"][:20]
            if not got["files"]:
                rec["status"] = "nothing new"
                log("No log file changed since the last run.")
            else:
                log(f"Reading {len(got['files'])} log file(s)…")
                rep = tl.analyze(got["files"])
                del got
                title = f"Daily report {at.astimezone().strftime('%Y-%m-%d')} (watched folder)"
                saved = tl.save_report(rep, title, names=bool(s.get("names")))
                rec.update(status="saved", records=(rep.get("input") or {}).get("records", 0), report=saved["name"])
            rec["read_until"] = at.isoformat(timespec="seconds")
        except WatchError as e:
            rec.update(status="failed", error=str(e))
        except ValueError as e:   # nothing readable in the files (traffic_logs.analyze), or the saved-report limit
            rec.update(status="failed", error=str(e)[:400], read_until=at.isoformat(timespec="seconds"))
        with _LOCK:
            d = _read()
            mine = [n for n in (d.get("reports") or []) if isinstance(n, str)]
            if rec.get("report"):
                mine.append(rec["report"])
            keep = int(s.get("keep") or DEFAULT_KEEP)
            for old in mine[:-keep] if len(mine) > keep else []:
                try:
                    tl.delete_saved(old)
                except (OSError, ValueError):
                    pass
            d["reports"] = mine[-keep:]
            d["last_run"] = rec
            _write(d)
        return rec
    finally:
        _RUN_GUARD.release()
