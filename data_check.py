"""Self-check of the app's data folder, with a safe repair for leftovers.

The data folder is where the app keeps its own stores (tenant profiles,
snapshots, change queue, deployments, notes, POVs, team accounts, audit
log, configuration backups, the store key file). The check looks, and
changes nothing:

  folder      exists, is a folder, can be written (a probe file is made
              and removed);
  encryption  store encryption on or off, whether stores are being sealed,
              the key problem if there is one, store files still plain;
  stores      every store file reads (sealed ones open with a key held
              here), parses as JSON and has a schema version this app
              knows (no version, or 1);
  locks       empty lock files left beside stores that no process holds
              and that are older than STALE_LOCK_SECONDS;
  temp files  temporary copies a crashed write left (".<store>.<random>.tmp"),
              older than store_crypto.STALE_TMP_SECONDS.

Each finding has plain steps to fix it. The one repair action, `repair()`,
removes only the stale lock files and stale temporary copies named by the
check: it never touches a store, a key, a backup or a snapshot, and it
audits the file names (never contents). The same check is the data
contract for the helper scripts and is exposed as GET /api/data-check, POST
/api/data-check/repair and `--check-data` / `--repair-data` on the
assessment command line (python data_check.py [--repair] also works).
"""
from __future__ import annotations

import glob
import json
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

import store_crypto

STALE_LOCK_SECONDS = 3600
KNOWN_SCHEMA_VERSIONS = (1,)
# Lock files this app makes empty beside its stores (flock based: the OS releases the lock
# when a process dies, so a leftover file is harmless clutter, never a held lock).
LOCK_NAMES = (".loop.lock", ".lock")
OK, WARN, FAIL = "ok", "warn", "fail"


def data_dir() -> str:
    return store_crypto._data_dir()


def _row(cid: str, label: str, status: str, detail: str, fix: Optional[List[str]] = None, **extra: Any) -> Dict[str, Any]:
    return {"id": cid, "label": label, "status": status, "detail": detail, "fix": list(fix or []), **extra}


# ── Lock files and temporary copies ──────────────────────────────────
def _held(path: str) -> bool:
    """True when another process holds the lock file's OS lock (or it cannot be tested)."""
    try:
        with open(path, "a+") as f:
            if store_crypto._try_lock(f):
                store_crypto._unlock_only(f)
                return False
            return True
    except OSError:
        return True


def lock_files() -> List[Dict[str, Any]]:
    """Empty lock files of this app in the data folder and one level down:
    {path, age_seconds, held, stale}. A non-empty file (requirements.lock)
    or a name this app does not make is never listed."""
    base = data_dir()
    now = time.time()
    out: List[Dict[str, Any]] = []
    for folder in [base] + sorted(p for p in glob.glob(os.path.join(glob.escape(base), "*")) if os.path.isdir(p)):
        for p in sorted(glob.glob(os.path.join(glob.escape(folder), "*.lock")) + glob.glob(os.path.join(glob.escape(folder), ".*.lock"))
                        + glob.glob(os.path.join(glob.escape(folder), ".lock"))):
            name = os.path.basename(p)
            if name == store_crypto.LOCK_NAME or not os.path.isfile(p) or os.path.islink(p):
                continue    # the key lock is re-made on every use and is never removed
            try:
                st = os.stat(p)
            except OSError:
                continue
            sibling = p[:-len(".lock")]
            if st.st_size != 0 or not (name in LOCK_NAMES or os.path.isfile(sibling)):
                continue
            age = max(0.0, now - st.st_mtime)
            held = _held(p)
            out.append({"path": p, "age_seconds": int(age), "held": held, "stale": (not held) and age > STALE_LOCK_SECONDS})
    return out


def temp_files() -> List[Dict[str, Any]]:
    now = time.time()
    out = []
    for t in store_crypto._temp_files():
        try:
            age = max(0.0, now - os.path.getmtime(t))
        except OSError:
            continue
        out.append({"path": t, "age_seconds": int(age), "stale": age > store_crypto.STALE_TMP_SECONDS})
    return out


# ── The checks ───────────────────────────────────────────────────────
def _folder_checks(base: str) -> List[Dict[str, Any]]:
    rows = []
    if not os.path.isdir(base):
        rows.append(_row("folder_exists", "Data folder exists", FAIL, f"{base} is missing or is not a folder.",
                         ["Create the folder, or mount the data volume (the container's /data).",
                          "Or point the app at another folder with DLP_CHECK_PROFILES (the tenant profile store)."]))
        return rows
    rows.append(_row("folder_exists", "Data folder exists", OK, f"{base} is a folder."))
    try:
        fd, probe = tempfile.mkstemp(prefix=".datacheck-probe-", suffix=".probe", dir=base)
        os.close(fd)
        os.unlink(probe)
        rows.append(_row("folder_writable", "Data folder is writable", OK, "A probe file was made and removed."))
    except OSError as e:
        rows.append(_row("folder_writable", "Data folder is writable", FAIL, f"{base} cannot be written ({e.strerror or type(e).__name__}); nothing can be saved there.",
                         ["Mount a writable data folder (the container's /data volume), or fix the folder's owner and permissions.",
                          "Run the app as the user that owns the folder."]))
    return rows


def _encryption_check() -> List[Dict[str, Any]]:
    try:
        hv = store_crypto.health_view()
        plain = store_crypto.plain_stores() if hv["enabled"] else []
    except Exception as e:  # noqa: BLE001
        return [_row("encryption", "Store encryption", WARN, f"Could not read the encryption state ({type(e).__name__}).",
                     ["Run: python store_crypto.py status"])]
    if not hv["enabled"]:
        return [_row("encryption", "Store encryption", WARN, "Store encryption is off (DLP_CHECK_STORE_ENCRYPTION=0): stores are plain owner-only files.",
                     ["Remove DLP_CHECK_STORE_ENCRYPTION=0 and restart; the stores are sealed once at the next start."], enabled=False)]
    if hv["problem"]:
        return [_row("encryption", "Store encryption", FAIL, f"Encryption is on but cannot seal: {hv['problem']}",
                     ["Make the data folder writable, or set DLP_CHECK_STORE_KEY_FILE to a writable location.",
                      "Then restart; plain stores are sealed at the next start."], enabled=True, sealing=False)]
    if plain:
        return [_row("encryption", "Store encryption", WARN, f"Encryption is on, but {len(plain)} store file(s) are still plain.",
                     ["Restart the app (it seals them once), or run: python store_crypto.py seal-all"], enabled=True, sealing=True, plain_files=len(plain))]
    return [_row("encryption", "Store encryption", OK, "Encryption is on and every store file is sealed.", enabled=True, sealing=True)]


def _store_checks() -> List[Dict[str, Any]]:
    try:
        entries = store_crypto._store_paths()
    except Exception as e:  # noqa: BLE001
        return [_row("stores", "Store files", WARN, f"The store files could not be listed ({type(e).__name__}).")]
    bad, newer, n = [], [], 0
    for e in entries:
        p, name = e["path"], os.path.basename(e["path"])
        if ".corrupt-" in name:
            continue        # a damaged copy self-healing moved aside; kept on purpose
        n += 1
        try:
            text = store_crypto._read_text(p)
            docs = [store_crypto.open_text(ln) for ln in text.splitlines() if ln.strip()] if e["lines"] else [store_crypto.open_text(text)]
            parsed = [json.loads(d) for d in docs if d.strip()]
        except store_crypto.StoreLocked as ex:
            bad.append((name, str(ex)[:160], "locked"))
            continue
        except (OSError, UnicodeDecodeError) as ex:
            bad.append((name, f"cannot be read ({type(ex).__name__})", "read"))
            continue
        except ValueError:
            bad.append((name, "is not valid JSON (damaged)", "json"))
            continue
        for d in parsed:
            if isinstance(d, dict) and "version" in d and d["version"] not in KNOWN_SCHEMA_VERSIONS and not e["lines"]:
                newer.append(name)
                break
    rows = []
    if bad:
        rows.append(_row("stores_readable", "Store files read", FAIL, f"{len(bad)} of {n} store file(s) cannot be read: " + "; ".join(f"{a} {b}" for a, b, _ in bad[:6]),
                         ["A damaged store is moved aside (kept as <store>.corrupt-<time>) and the last good copy restored when the app starts.",
                          "A store sealed with a key that is not here needs that key file back (DLP_CHECK_STORE_KEY_FILE) or the stores recreated.",
                          "Restore the data folder from your backup if the file matters."], files=[a for a, _, _ in bad]))
    else:
        rows.append(_row("stores_readable", "Store files read", OK, f"All {n} store file(s) read and parse." if n else "No store files yet (a fresh data folder)."))
    if newer:
        rows.append(_row("stores_schema", "Store schema versions", WARN, f"{len(newer)} store file(s) carry a schema version this app does not know: {', '.join(newer[:6])}.",
                         ["They were written by a newer version of the app: update this copy before using them.", "Do not edit the files by hand."], files=newer))
    else:
        rows.append(_row("stores_schema", "Store schema versions", OK, "Every store carries a schema version this app knows (or none)."))
    return rows


def _leftover_checks() -> List[Dict[str, Any]]:
    locks, temps = lock_files(), temp_files()
    sl, st = [x for x in locks if x["stale"]], [x for x in temps if x["stale"]]
    rows = []
    if sl:
        rows.append(_row("stale_locks", "Stale lock files", WARN, f"{len(sl)} unused lock file(s) older than {STALE_LOCK_SECONDS // 60} minutes: " + ", ".join(os.path.basename(x["path"]) for x in sl[:6]) + ".",
                         ["They are harmless (the operating system releases a lock when a program ends) but can be removed: run the repair (POST /api/data-check/repair, or --repair-data)."], count=len(sl)))
    else:
        rows.append(_row("stale_locks", "Stale lock files", OK, "No stale lock files." + (f" {sum(1 for x in locks if x['held'])} in use right now." if any(x["held"] for x in locks) else "")))
    if st:
        rows.append(_row("stale_temp", "Leftover temporary files", WARN, f"{len(st)} temporary copy(ies) a crashed write left, older than an hour: " + ", ".join(os.path.basename(x["path"]) for x in st[:6]) + ".",
                         ["They may hold an unencrypted copy of a store: remove them with the repair (POST /api/data-check/repair, or --repair-data)."], count=len(st)))
    else:
        rows.append(_row("stale_temp", "Leftover temporary files", OK, "No leftover temporary files."))
    return rows


def check() -> Dict[str, Any]:
    """Run every check; read-only apart from the writable probe file."""
    base = data_dir()
    rows = _folder_checks(base)
    if os.path.isdir(base):
        rows += _encryption_check() + _store_checks() + _leftover_checks()
    worst = FAIL if any(r["status"] == FAIL for r in rows) else WARN if any(r["status"] == WARN for r in rows) else OK
    steps = []
    for r in rows:
        if r["status"] != OK:
            steps += [s for s in r["fix"] if s not in steps]
    return {"data_dir": base, "status": worst, "ok": worst == OK, "checks": rows, "steps": steps,
            "repairable": {"stale_locks": sum(1 for x in lock_files() if x["stale"]) if os.path.isdir(base) else 0,
                           "stale_temp_files": sum(1 for x in temp_files() if x["stale"]) if os.path.isdir(base) else 0},
            "note": "The check changes nothing. The repair removes only stale lock files and stale temporary copies; never a store, key, backup or snapshot."}


def repair() -> Dict[str, Any]:
    """Remove stale lock files and stale temporary copies, nothing else.
    A lock is removed only while this process holds its OS lock (so no one
    else can); every removal is named (file name only) in the audit log."""
    removed_locks, removed_temps, skipped = [], [], []
    for x in lock_files():
        if not x["stale"]:
            continue
        p = x["path"]
        try:
            with open(p, "a+") as f:
                if not store_crypto._try_lock(f):
                    skipped.append(os.path.basename(p))
                    continue
                try:
                    if os.path.getsize(p) == 0 and time.time() - os.path.getmtime(p) > STALE_LOCK_SECONDS:
                        os.unlink(p)
                        removed_locks.append(os.path.basename(p))
                finally:
                    store_crypto._unlock_only(f)
        except OSError:
            skipped.append(os.path.basename(p))
    for t in temp_files():
        if not t["stale"]:
            continue
        try:
            os.unlink(t["path"])
            removed_temps.append(os.path.basename(t["path"]))
        except OSError:
            skipped.append(os.path.basename(t["path"]))
    out = {"removed_locks": removed_locks, "removed_temp_files": removed_temps, "skipped": skipped,
           "message": f"Removed {len(removed_locks)} stale lock file(s) and {len(removed_temps)} leftover temporary file(s); no store, key, backup or snapshot was touched."}
    store_crypto._audit("data_check_repair", removed_locks=removed_locks, removed_temp_files=removed_temps, skipped=skipped)
    return out


def format_text(rep: Dict[str, Any]) -> str:
    mark = {OK: "OK  ", WARN: "WARN", FAIL: "FAIL"}
    lines = [f"Data folder: {rep['data_dir']}  ->  {rep['status'].upper()}"]
    lines += [f"  [{mark[r['status']]}] {r['label']}: {r['detail']}" for r in rep["checks"]]
    if rep["steps"]:
        lines += ["", "Suggested steps:"] + [f"  - {s}" for s in rep["steps"]]
    return "\n".join(lines)


def run_cli(repair_too: bool = False, as_json: bool = False) -> int:
    """Print the check (and, with repair_too, run the repair first); exit 0 when healthy, 1 on a warning, 2 on a failure."""
    done = repair() if repair_too else None
    rep = check()
    if as_json:
        print(json.dumps({"repair": done, "check": rep}, indent=1))
    else:
        if done:
            print(done["message"])
        print(format_text(rep))
    return {OK: 0, WARN: 1, FAIL: 2}[rep["status"]]


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="data_check", description="Self-check of the app's data folder.")
    ap.add_argument("--repair", action="store_true", help="remove stale lock files and leftover temporary copies, then check")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    return run_cli(a.repair, a.json)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
