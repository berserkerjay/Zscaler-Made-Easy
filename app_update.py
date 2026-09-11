"""
Update the app in place: from the web UI (Update app on the Start here
card) or from UPDATE_Zscaler_Assessment.bat, which runs this file.

What an update does
-------------------
1. Check the folder: a git checkout with git available.
2. Preserve local edits. Settings that older instructions had you put
   into the start scripts (REQUESTS_CA_BUNDLE, HTTPS_PROXY, ...) are moved
   into local_settings.bat, which git ignores, and the script is restored
   so the pull is not refused. Any other hand-edited tracked file is
   stashed before the pull and re-applied after it.
3. Fetch, switch to main, pull fast-forward only.
4. Install requirements (optional step; a pip problem never stops the
   update).
5. Restart the server through the same start script the shortcuts use.

Safety
------
- Only ever touches the folder the server runs from, and only through
  git. Nothing is deleted. Untracked files (local_settings, profiles,
  caches, logs) are never touched.
- The endpoints that call this are localhost-only (same rule as write
  mode) and go through the origin check.
- A restarted server has the same settings (local_settings, port) as one
  started by hand. Write mode is a per-process setting and is off again
  after a restart, exactly as after any restart.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

GIT_TIMEOUT = 60
PIP_TIMEOUT = 300

# Environment settings that belong in local_settings.bat. If a start
# script was edited to set one of these, the value is moved there.
SETTING_KEYS = (
    "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
    "ZSCALER_UPDATE_PROXY", "ZSCALER_UPDATE_VERIFY_TLS", "ZSCALER_BIND_HOST", "ZSCALER_PORT",
    "ZSCALER_CLOUD", "ZSCALER_VANITY_DOMAIN", "ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET",
    "ENABLE_WRITE_ACTIONS",
)
START_SCRIPTS = ("START_Zscaler_Assessment.bat", "START_Zscaler_Assessment_WRITES_ENABLED.bat")
_SET_RE = re.compile(r"^\s*set\s+\"?([A-Z_][A-Z0-9_]*)=([^\"\r\n]*)\"?\s*$", re.I)


def _git(app_dir: str, *args: str, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=app_dir, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})


def _out(cp: subprocess.CompletedProcess) -> str:
    return (cp.stdout or "").strip()


def _err(cp: subprocess.CompletedProcess, default: str = "") -> str:
    lines = [ln.strip() for ln in ((cp.stderr or "") + "\n" + (cp.stdout or "")).splitlines() if ln.strip()]
    fatal = [ln for ln in lines if ln.lower().startswith(("fatal:", "error:"))]
    return (fatal[0] if fatal else (lines[-1] if lines else default))[:400]


INDEX_LOCK_STALE_S = 20   # a lock older than this was left behind by an interrupted git


def _git_dir(app_dir: str) -> str:
    cp = _git(app_dir, "rev-parse", "--git-dir", timeout=15)
    path = _out(cp) if cp.returncode == 0 else ".git"
    return path if os.path.isabs(path) else os.path.join(app_dir, path)


def clear_stale_index_lock(app_dir: str) -> Optional[str]:
    """git refuses to touch the index while .git/index.lock exists; an
    interrupted git (closed window, crash, antivirus scan) leaves one
    behind and every later update fails with "could not write index".
    Remove it when it is old enough that no git can still be using it.
    Returns a note describing what was done, or None when there was no
    lock."""
    lock = os.path.join(_git_dir(app_dir), "index.lock")
    if not os.path.exists(lock):
        return None
    age = time.time() - os.path.getmtime(lock)
    if age < INDEX_LOCK_STALE_S:
        return f"another git operation is holding {lock} ({int(age)}s old); wait a moment and run the update again"
    try:
        os.remove(lock)
        return f"removed a stale git lock ({lock}, {int(age)}s old)"
    except OSError as e:
        return f"could not remove the stale git lock {lock}: {e}"


def unmerged_files(app_dir: str) -> List[str]:
    """Paths git holds in a conflicted (unmerged) state: what a stash pop
    that hit a conflict leaves behind. While any exist, git refuses to
    stash or pull."""
    cp = _git(app_dir, "diff", "--name-only", "--diff-filter=U")
    if cp.returncode != 0:
        return []
    return [ln.strip() for ln in (cp.stdout or "").splitlines() if ln.strip()]


def recover_unmerged(app_dir: str) -> Optional[Dict[str, Any]]:
    """A half-applied earlier update (re-applying the edits conflicted)
    leaves unmerged paths, and every later update fails at the stash
    step. Copy the conflicted files aside, reset the tree to the last
    build and carry on; the earlier edits are still in git stash. Returns
    {files, backup, ok} or None when there was nothing to recover."""
    files = unmerged_files(app_dir)
    if not files:
        return None
    backup = os.path.join(app_dir, "updater_backup", time.strftime("%Y%m%d-%H%M%S"))
    for rel in files:
        src = os.path.join(app_dir, rel)
        if os.path.isfile(src):
            dst = os.path.join(backup, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    cp = _git(app_dir, "reset", "--hard", "HEAD")
    return {"files": files, "backup": backup, "ok": cp.returncode == 0, "error": _err(cp) if cp.returncode else ""}


def _index_hint(msg: str) -> str:
    low = msg.lower()
    if "could not write index" in low or "index.lock" in low or "unable to write" in low or "permission denied" in low or "unable to create" in low:
        return (" Git could not write its index file in the app folder. That is usually a file in use by another program "
                "(an editor or IDE with the folder open, OneDrive or antivirus scanning it) or a read-only .git folder. "
                "Close those, then in the app folder run  git status  ; if .git\\index.lock exists and nothing is running, "
                "delete it and run the update again.")
    return ""


def _auth_hint(msg: str) -> str:
    low = msg.lower()
    if "could not read username" in low or "authentication failed" in low or "terminal prompts disabled" in low or "403" in low:
        return (" The repository is private and this machine is not signed in to GitHub for git. "
                "Open a Command Prompt in the app folder, run  git fetch  once and sign in when asked, then update again.")
    return ""


def is_checkout(app_dir: str) -> bool:
    """True when git manages this folder: a normal clone (.git directory),
    a worktree (.git file), or a folder inside a larger checkout. Asking
    git is the only reliable test."""
    if os.path.exists(os.path.join(app_dir, ".git")):
        return True
    if not shutil.which("git"):
        return False
    try:
        cp = _git(app_dir, "rev-parse", "--is-inside-work-tree", timeout=15)
        return cp.returncode == 0 and _out(cp).lower() == "true"
    except Exception:  # noqa: BLE001
        return False


def dirty_files(app_dir: str) -> List[str]:
    """Tracked files with local edits (untracked files are ignored: the
    per-machine settings and caches live there and never block a pull)."""
    cp = _git(app_dir, "status", "--porcelain", "--untracked-files=no")
    if cp.returncode != 0:
        return []
    # Porcelain lines are "XY path"; the first column may be a space, so
    # do not strip the line before slicing.
    return [line[3:].strip() for line in (cp.stdout or "").splitlines() if len(line) > 3 and line.strip()]


def status(app_dir: str, remote_sha: Optional[str] = None) -> Dict[str, Any]:
    """Where this install stands: current build, branch, whether GitHub
    is ahead, and whether it can be updated in place."""
    out: Dict[str, Any] = {"app_dir": app_dir, "git_available": bool(shutil.which("git")),
                           "is_git_checkout": is_checkout(app_dir), "branch": None, "local_commit": None,
                           "remote_commit": remote_sha, "update_available": None, "dirty_files": [],
                           "can_update": False, "reason": ""}
    if not out["git_available"]:
        out["reason"] = "git is not installed or not on PATH. Install Git from https://git-scm.com/download/win and restart the app."
        return out
    if not out["is_git_checkout"]:
        out["reason"] = ("This folder is not a git checkout, so it cannot be updated in place. "
                         "Clone the repository and run INSTALL_Zscaler_Assessment.bat from the clone.")
        return out
    try:
        out["branch"] = _out(_git(app_dir, "rev-parse", "--abbrev-ref", "HEAD")) or None
        out["local_commit"] = _out(_git(app_dir, "rev-parse", "--short", "HEAD")) or None
        out["dirty_files"] = dirty_files(app_dir)
    except Exception as e:  # noqa: BLE001
        out["reason"] = f"git could not read this folder: {e}"
        return out
    if remote_sha and out["local_commit"]:
        out["update_available"] = not remote_sha.startswith(out["local_commit"]) and not out["local_commit"].startswith(remote_sha)
    out["can_update"] = True
    if out["dirty_files"]:
        out["reason"] = ("Edited by hand: " + ", ".join(out["dirty_files"][:8]) + (" …" if len(out["dirty_files"]) > 8 else "")
                         + ". The update keeps these edits (settings move to local_settings.bat; other edits are re-applied after the pull).")
    return out


# ── Preserving local edits ─────────────────────────────────────────────

def _committed_settings(app_dir: str, rel: str) -> Dict[str, str]:
    cp = _git(app_dir, "show", f"HEAD:{rel}")
    vals: Dict[str, str] = {}
    if cp.returncode == 0:
        for line in (cp.stdout or "").splitlines():
            m = _SET_RE.match(line)
            if m and m.group(1).upper() in SETTING_KEYS:
                vals[m.group(1).upper()] = m.group(2).strip()
    return vals


def _local_settings_keys(path: str) -> Dict[str, str]:
    vals: Dict[str, str] = {}
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = _SET_RE.match(line)
                if m:
                    vals[m.group(1).upper()] = m.group(2).strip()
    return vals


def migrate_settings(app_dir: str, dirty: List[str]) -> Tuple[List[str], List[str]]:
    """Move `set KEY=value` lines that a hand-edited start script adds
    (compared with the committed script) into local_settings.bat, then
    restore the script. Returns (migrated 'FILE: KEY' labels, restored files)."""
    migrated: List[str] = []
    restored: List[str] = []
    ls_path = os.path.join(app_dir, "local_settings.bat")
    for rel in dirty:
        if os.path.basename(rel) not in START_SCRIPTS:
            continue
        path = os.path.join(app_dir, rel)
        if not os.path.isfile(path):
            continue
        base = _committed_settings(app_dir, rel)
        existing = _local_settings_keys(ls_path)
        found: List[Tuple[str, str]] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = _SET_RE.match(line)
                if not m:
                    continue
                key, val = m.group(1).upper(), m.group(2).strip()
                if key in SETTING_KEYS and val and base.get(key) != val:
                    found.append((key, val))
        if not found:
            continue
        lines_to_add = [f"set {k}={v}" for k, v in found if k not in existing]
        if lines_to_add:
            header = "" if os.path.isfile(ls_path) else ("@echo off\nREM Machine-specific settings (git-ignored; survive updates). Created by the updater.\n")
            with open(ls_path, "a", encoding="utf-8") as f:
                if header:
                    f.write(header)
                f.write(f"\nREM Moved from {rel} by the updater on {time.strftime('%Y-%m-%d %H:%M')}\n")
                f.write("\n".join(lines_to_add) + "\n")
        migrated.extend(f"{rel}: {k}" for k, _ in found)
        # Their settings now live in local_settings.bat; put the script back
        # so the pull is not refused. Any other edit in it goes to the stash
        # copy below, so nothing is lost.
        cp = _git(app_dir, "stash", "push", "-m", f"DLP-Check updater: {rel} before restore", "--", rel)
        if cp.returncode == 0:
            restored.append(rel)
    return migrated, restored


# ── Update ────────────────────────────────────────────────────────────

def update(app_dir: str, install_deps: bool = True, python: Optional[str] = None) -> Dict[str, Any]:
    """Preserve edits, fetch, switch to main, pull fast-forward only,
    install requirements. Never raises; every step is reported in
    `steps` and a failure sets `error`. `updated` is True when HEAD moved."""
    steps: List[Dict[str, Any]] = []
    result: Dict[str, Any] = {"ok": False, "updated": False, "before": None, "after": None, "steps": steps, "error": None,
                              "deps_ok": None, "restart_required": False, "preserved": [], "migrated": [], "recovered": None}

    def step(name: str, ok: bool, detail: str = "", soft: bool = False) -> None:
        # soft: a failure here does not stop the update (dependencies, re-applying edits).
        steps.append({"name": name, "ok": ok, "detail": detail[-1500:], "soft": soft})

    st = status(app_dir)
    result["before"] = st.get("local_commit")
    if not st["can_update"]:
        result["error"] = st["reason"]
        step("Check this folder", False, st["reason"])
        return result
    step("Check this folder", True, f"git checkout on branch {st.get('branch')}, build {st.get('local_commit')}")

    # A lock left behind by an interrupted git makes every write fail with
    # "could not write index"; clear it before touching anything.
    note = clear_stale_index_lock(app_dir)
    if note and note.startswith("removed"):
        step("Clear a stale git lock", True, note)

    # Unmerged paths from an earlier update whose re-apply conflicted: git
    # refuses every stash and pull until they are gone.
    rec = recover_unmerged(app_dir)
    if rec:
        step("Recover a half-applied earlier update", rec["ok"],
             f"{len(rec['files'])} conflicted file(s) ({', '.join(rec['files'][:6])}{' …' if len(rec['files']) > 6 else ''}) "
             f"copied to {rec['backup']} and the folder reset to the last build; the edits from that update also remain in git stash "
             f"(run  git stash list  in the app folder)." if rec["ok"] else "git reset failed: " + rec["error"])
        if not rec["ok"]:
            result["error"] = ("An earlier update was left half-applied (unmerged files: " + ", ".join(rec["files"]) +
                               ") and could not be reset: " + rec["error"] + _index_hint(rec["error"]))
            return result
        result["recovered"] = rec

    # Local edits: settings move to local_settings.bat; the rest is stashed.
    dirty = dirty_files(app_dir) if rec else list(st.get("dirty_files") or [])
    stashed = False
    if dirty:
        migrated, restored = migrate_settings(app_dir, dirty)
        result["migrated"] = migrated
        if migrated:
            step("Move settings to local_settings.bat", True,
                 ", ".join(migrated) + " (the script itself was restored; its old copy is in git stash)")
        remaining = dirty_files(app_dir)
        if remaining:
            msg_stash = f"DLP-Check updater: local edits before update {time.strftime('%Y-%m-%d %H:%M')}"
            cp = _git(app_dir, "stash", "push", "-m", msg_stash)
            if cp.returncode != 0 and _index_hint(_err(cp)):
                # The index could not be written: clear a lock that appeared
                # meanwhile and try once more before giving up.
                note = clear_stale_index_lock(app_dir)
                if note:
                    step("Clear a stale git lock", note.startswith("removed"), note, soft=True)
                cp = _git(app_dir, "stash", "push", "-m", msg_stash)
            if cp.returncode == 0 and "no local changes" not in (cp.stdout or "").lower():
                stashed = True
                result["preserved"] = remaining
                step("Set aside hand-edited files", True, ", ".join(remaining) + " (re-applied after the pull)")
            else:
                msg = _err(cp, "git stash failed")
                step("Set aside hand-edited files", False, msg)
                result["error"] = "Could not set aside the hand-edited files: " + msg + _index_hint(msg) \
                    + ((" " + note) if note and not note.startswith("removed") else "")
                return result

    try:
        cp = _git(app_dir, "fetch", "origin", timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        result["error"] = "GitHub did not answer within 60 seconds. Check the connection or proxy, then try again."
        step("Fetch from GitHub", False, result["error"])
        _restore(app_dir, stashed, step, result)
        return result
    if cp.returncode != 0:
        msg = _err(cp, "git fetch failed")
        result["error"] = "Could not reach GitHub: " + msg + _auth_hint(msg)
        step("Fetch from GitHub", False, result["error"])
        _restore(app_dir, stashed, step, result)
        return result
    step("Fetch from GitHub", True, "origin fetched")

    if st.get("branch") != "main":
        cp = _git(app_dir, "checkout", "main")
        if cp.returncode != 0:
            result["error"] = "Could not switch to main: " + _err(cp)
            step("Switch to main", False, result["error"])
            _restore(app_dir, stashed, step, result)
            return result
        step("Switch to main", True, f"was on {st.get('branch')}")

    cp = _git(app_dir, "pull", "--ff-only", "origin", "main", timeout=GIT_TIMEOUT)
    if cp.returncode != 0:
        msg = _err(cp, "git pull failed")
        result["error"] = "Pull refused: " + msg + _auth_hint(msg) + _index_hint(msg)
        step("Pull latest code", False, result["error"])
        _restore(app_dir, stashed, step, result)
        return result
    after = _out(_git(app_dir, "rev-parse", "--short", "HEAD")) or None
    result["after"] = after
    result["updated"] = bool(after and after != result["before"])
    step("Pull latest code", True, f"build {result['before']} → {after}" if result["updated"] else f"already on build {after}")

    _restore(app_dir, stashed, step, result)

    if install_deps and result["updated"]:
        lock = os.path.join(app_dir, "requirements.lock")
        req = os.path.join(app_dir, "requirements.txt")
        if os.path.isfile(lock) or os.path.isfile(req):
            py = python or sys.executable
            # The lock pins every wheel by hash; pip refuses anything that differs.
            args = ([py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--require-hashes", "--no-deps", "-r", lock]
                    if os.path.isfile(lock) else
                    [py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", req])
            try:
                cp = subprocess.run(args,
                                    cwd=app_dir, capture_output=True, text=True, timeout=PIP_TIMEOUT)
                result["deps_ok"] = cp.returncode == 0
                step("Install Python dependencies", cp.returncode == 0,
                     ("requirements.lock installed (hash-verified)" if os.path.isfile(lock) else "requirements.txt installed") if cp.returncode == 0
                     else "pip reported a problem; the app still runs. If a feature fails to import, run INSTALL_Zscaler_Assessment.bat once. "
                          + (cp.stderr or cp.stdout or "").strip()[-400:], soft=True)
            except subprocess.TimeoutExpired:
                result["deps_ok"] = False
                step("Install Python dependencies", False, "pip did not finish within 5 minutes; run INSTALL_Zscaler_Assessment.bat once.", soft=True)
            except Exception as e:  # noqa: BLE001
                result["deps_ok"] = False
                step("Install Python dependencies", False, str(e)[:300], soft=True)
    result["ok"] = True
    result["restart_required"] = result["updated"]
    return result


def _restore(app_dir: str, stashed: bool, step, result: Dict[str, Any]) -> None:
    """Re-apply the stashed edits. A conflict keeps the stash (nothing is
    lost) and is reported as a soft failure."""
    if not stashed:
        return
    cp = _git(app_dir, "stash", "pop")
    if cp.returncode == 0:
        step("Re-apply hand-edited files", True, ", ".join(result.get("preserved") or []))
    else:
        _git(app_dir, "checkout", "--", ".")   # leave the tree clean; the edits stay in the stash
        step("Re-apply hand-edited files", False,
             "Your edits could not be re-applied automatically; they are kept in git stash "
             "(run  git stash list  in the app folder). The app runs on the new build. " + _err(cp), soft=True)


# ── Restart ───────────────────────────────────────────────────────────

def restart_command(app_dir: str) -> List[str]:
    """The detached command that relaunches the server the same way the
    shortcuts do, after this process has exited."""
    if sys.platform == "win32":
        vbs = os.path.join(app_dir, "START_Zscaler_Assessment.vbs")
        bat = os.path.join(app_dir, "START_Zscaler_Assessment.bat")
        launch = f'wscript.exe "{vbs}"' if os.path.isfile(vbs) else f'"{bat}"'
        return ["cmd", "/c", f"timeout /t 3 /nobreak >nul && {launch}"]
    server = os.path.join(app_dir, "dlp_api_server.py")
    log = os.path.join(app_dir, "server.log")
    return ["sh", "-c", f'sleep 3; cd "{app_dir}" && nohup "{sys.executable}" "{server}" >> "{log}" 2>&1 &']


def schedule_restart(app_dir: str, delay: float = 0.8, dry_run: bool = False) -> Dict[str, Any]:
    """Spawn the relauncher detached from this process, then exit this
    process shortly after so the port is free for the new one. With
    dry_run the command is returned and nothing is spawned."""
    cmd = restart_command(app_dir)
    if dry_run:
        return {"scheduled": False, "command": cmd}
    kwargs: Dict[str, Any] = {"cwd": app_dir, "close_fds": True, "stdin": subprocess.DEVNULL,
                              "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    env = dict(os.environ)
    env.pop("DLPCHECK_HIDDEN", None)   # the launcher sets it itself
    subprocess.Popen(cmd, env=env, **kwargs)

    def _exit_soon() -> None:
        time.sleep(delay)
        os._exit(0)

    threading.Thread(target=_exit_soon, daemon=True).start()
    return {"scheduled": True, "command": cmd}


# ── Command line (used by UPDATE_Zscaler_Assessment.bat) ──────────────

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Update DLP-Check in place (git pull, edits preserved).")
    ap.add_argument("--dir", default=os.path.dirname(os.path.abspath(__file__)), help="app folder (default: this file's folder)")
    ap.add_argument("--no-deps", action="store_true", help="skip pip install -r requirements.txt")
    ap.add_argument("--status", action="store_true", help="only report where this install stands")
    args = ap.parse_args(argv)
    if args.status:
        st = status(args.dir)
        print(f"folder: {st['app_dir']}\nbranch: {st['branch']}  build: {st['local_commit']}\ncan update: {st['can_update']}")
        if st["reason"]:
            print(st["reason"])
        return 0 if st["can_update"] else 1
    res = update(args.dir, install_deps=not args.no_deps)
    for s in res["steps"]:
        mark = "OK " if s["ok"] else ("!! " if s.get("soft") else "ERR")
        print(f"  [{mark}] {s['name']}" + (f" - {s['detail']}" if s.get("detail") else ""))
    if not res["ok"]:
        print("\nUpdate failed: " + (res["error"] or "see above"))
        return 1
    print("\nNow on build " + str(res["after"]) + ("" if res["updated"] else " (already current)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
