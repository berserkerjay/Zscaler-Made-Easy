"""
Update the app from the web UI.

The server runs from a git checkout of the repository. This module lets
the GUI do what UPDATE_Zscaler_Assessment.bat does, without a command
prompt: see whether GitHub is ahead, pull main fast-forward only,
install any new Python dependencies, and restart the server process so
the new code is what answers the browser.

Safety
------
- Only ever touches the folder the server runs from, and only through
  git (fetch, checkout main, pull --ff-only). Nothing is deleted; a
  hand-edited tracked file makes the pull refuse, and the file list is
  reported so the operator can decide.
- The endpoints that call this are localhost-only (same rule as write
  mode) and go through the origin check, so a web page from elsewhere
  cannot trigger an update.
- The restart relaunches the same start script the shortcuts use, so a
  restarted server has the same settings (local_settings, port) as one
  started by hand. Write mode is a per-process setting and is off again
  after a restart, exactly as after any restart.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

GIT_TIMEOUT = 60
PIP_TIMEOUT = 300


def _git(app_dir: str, *args: str, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=app_dir, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})


def _out(cp: subprocess.CompletedProcess) -> str:
    return (cp.stdout or "").strip()


def is_checkout(app_dir: str) -> bool:
    return os.path.isdir(os.path.join(app_dir, ".git"))


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
    is ahead, and whether a pull would be refused."""
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
    if out["dirty_files"]:
        out["reason"] = ("A file in this folder was edited by hand, so a pull would be refused: "
                         + ", ".join(out["dirty_files"][:8]) + (" …" if len(out["dirty_files"]) > 8 else "")
                         + ". Discard the edit (git checkout -- <file>) or move the file out, then update.")
        return out
    out["can_update"] = True
    return out


def update(app_dir: str, install_deps: bool = True, python: Optional[str] = None) -> Dict[str, Any]:
    """Fetch, switch to main, pull fast-forward only, install requirements.
    Never raises; every step is reported in `steps` and a failure sets
    `error`. `updated` is True when HEAD moved."""
    steps: List[Dict[str, Any]] = []
    result: Dict[str, Any] = {"ok": False, "updated": False, "before": None, "after": None, "steps": steps, "error": None,
                              "deps_ok": None, "restart_required": False}

    def step(name: str, ok: bool, detail: str = "", soft: bool = False) -> None:
        # soft: a failure here does not stop the update (dependencies).
        steps.append({"name": name, "ok": ok, "detail": detail[-1500:], "soft": soft})

    st = status(app_dir)
    result["before"] = st.get("local_commit")
    if not st["can_update"]:
        result["error"] = st["reason"]
        step("Check this folder", False, st["reason"])
        return result
    step("Check this folder", True, f"git checkout on branch {st.get('branch')}, build {st.get('local_commit')}")

    try:
        cp = _git(app_dir, "fetch", "origin", timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        result["error"] = "GitHub did not answer within 60 seconds. Check the connection or proxy, then try again."
        step("Fetch from GitHub", False, result["error"])
        return result
    if cp.returncode != 0:
        result["error"] = "Could not reach GitHub: " + ((cp.stderr or cp.stdout or "").strip()[-400:] or "git fetch failed")
        step("Fetch from GitHub", False, result["error"])
        return result
    step("Fetch from GitHub", True, "origin fetched")

    if st.get("branch") != "main":
        cp = _git(app_dir, "checkout", "main")
        if cp.returncode != 0:
            result["error"] = "Could not switch to main: " + (cp.stderr or cp.stdout or "").strip()[-400:]
            step("Switch to main", False, result["error"])
            return result
        step("Switch to main", True, f"was on {st.get('branch')}")

    cp = _git(app_dir, "pull", "--ff-only", "origin", "main", timeout=GIT_TIMEOUT)
    if cp.returncode != 0:
        result["error"] = ("Pull refused: " + (cp.stderr or cp.stdout or "").strip()[-400:]
                           + ". Usually a file in this folder was edited by hand; git status shows which.")
        step("Pull latest code", False, result["error"])
        return result
    after = _out(_git(app_dir, "rev-parse", "--short", "HEAD")) or None
    result["after"] = after
    result["updated"] = bool(after and after != result["before"])
    step("Pull latest code", True, f"build {result['before']} → {after}" if result["updated"] else f"already on build {after}")

    if install_deps and result["updated"]:
        req = os.path.join(app_dir, "requirements.txt")
        if os.path.isfile(req):
            py = python or sys.executable
            try:
                cp = subprocess.run([py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", req],
                                    cwd=app_dir, capture_output=True, text=True, timeout=PIP_TIMEOUT)
                result["deps_ok"] = cp.returncode == 0
                step("Install Python dependencies", cp.returncode == 0,
                     "requirements.txt installed" if cp.returncode == 0
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
