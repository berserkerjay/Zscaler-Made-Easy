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
4. When origin is github.com, cross-check the commit just pulled against
   GitHub's REST API for main — a channel separate from the git pull
   itself. A mismatch rolls the pull back and refuses the update rather
   than running an unverified tree; see verify_against_github_api(). This
   does not verify commit/tag signatures (see SECURITY.md).
5. Install requirements (optional step; a pip problem never stops the
   update).
6. Restart the server through the same start script the shortcuts use.

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


def git_env() -> Dict[str, str]:
    """The environment git runs with: no interactive prompts, and the same
    corporate CA bundle the app uses for its own HTTPS calls (git does not
    read REQUESTS_CA_BUNDLE, so behind TLS inspection a fetch fails with
    'SSL certificate problem' unless GIT_SSL_CAINFO names the bundle)."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if not env.get("GIT_SSL_CAINFO"):
        for key in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "ZSCALER_CA_BUNDLE"):
            path = (env.get(key) or "").strip()
            if path and os.path.isfile(path):
                env["GIT_SSL_CAINFO"] = path
                break
    return env


def _git(app_dir: str, *args: str, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=app_dir, capture_output=True, text=True, timeout=timeout, env=git_env())


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
    if "ssl certificate problem" in low or "unable to get local issuer" in low or "self-signed certificate" in low or "certificate verify" in low or "schannel" in low:
        ca = git_env().get("GIT_SSL_CAINFO")
        if ca:
            return (f" Corporate TLS inspection is in the way and git did not accept the CA bundle it was given ({ca}). "
                    "Add the proxy's root certificate to that bundle file (it is the one the app uses for its own HTTPS calls), then update again.")
        return (" Corporate TLS inspection is in the way: the proxy re-signs github.com and git does not trust its certificate. "
                "Put the proxy's root CA in a .pem file and set REQUESTS_CA_BUNDLE to it in local_settings.bat next to the app "
                "(the updater passes it to git as GIT_SSL_CAINFO), restart the app, then update again.")
    if "could not resolve host" in low or "connection timed out" in low or "failed to connect" in low or "proxy" in low and "407" in low:
        return (" GitHub could not be reached from this machine. If a proxy is required, set HTTPS_PROXY in local_settings.bat "
                "(git reads it), restart the app, then update again.")
    return ""


_GITHUB_REMOTE_RE = re.compile(r"^(?:https://github\.com/|git@github\.com:)([^/]+)/([^/]+?)(?:\.git)?/?$")


def _github_owner_repo(app_dir: str) -> Optional[Tuple[str, str]]:
    """(owner, repo) when origin is a github.com remote, else None — a
    fork or a mirror is never assumed to be the upstream repository."""
    cp = _git(app_dir, "remote", "get-url", "origin", timeout=15)
    if cp.returncode != 0:
        return None
    m = _GITHUB_REMOTE_RE.match(_out(cp))
    return (m.group(1), m.group(2)) if m else None


def verify_against_github_api(app_dir: str, branch: str, local_sha: str, timeout: int = 10) -> Dict[str, Any]:
    """Cross-check the commit just pulled over git against what GitHub's
    REST API reports for the same branch: a channel separate from the
    git smart-HTTP pull used to fetch it, so the two would only disagree
    if one of them was tampered with in transit, or a mirror served a
    different tree than GitHub itself has. This does not verify commit
    or tag signatures (main carries no signed tags); see SECURITY.md.

    Best-effort and skipped, not failed, when origin is not github.com
    or the API cannot be reached (offline, blocked outbound, a private
    repository) — {"checked": False, "reason": ...}. Otherwise
    {"checked": True, "match": bool, "api_sha": str, "local_sha": str}."""
    owner_repo = _github_owner_repo(app_dir)
    if not owner_repo:
        return {"checked": False, "reason": "origin is not a github.com remote"}
    owner, repo = owner_repo
    try:
        import requests
        r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}",
                         headers={"Accept": "application/vnd.github+json"}, timeout=timeout)
        r.raise_for_status()
        api_sha = (r.json() or {}).get("sha") or ""
    except Exception as e:  # noqa: BLE001
        return {"checked": False, "reason": f"could not reach the GitHub API: {type(e).__name__}: {str(e)[:200]}"}
    if not api_sha:
        return {"checked": False, "reason": "the GitHub API response had no commit sha"}
    return {"checked": True, "match": api_sha.startswith(local_sha) or local_sha.startswith(api_sha),
            "api_sha": api_sha, "local_sha": local_sha, "owner": owner, "repo": repo}


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


# The branches an update may switch to, and nothing else: a branch name
# reaches git on the command line, so this is an allowlist, not free text.
# main is what customers run; the other two exist so a fix can be tried
# before it is promoted (README: Branching and releases).
BRANCHES: Tuple[str, ...] = ("main", "qa", "dev")
BRANCH_LABELS: Dict[str, str] = {"main": "Stable (main)", "qa": "QA (qa)", "dev": "Development (dev)"}
DEFAULT_BRANCH = "main"
# The name a branch had before the three were standardised as dev → qa →
# main. An install still checked out on the old name is treated as being
# on the new one, so its Update button keeps working and moves it over.
LEGACY_BRANCHES: Dict[str, str] = {"DLP-CHECK-QA": "qa"}


def valid_branch(name: Any) -> str:
    """The branch as one of BRANCHES (a legacy name is mapped to its new
    one), or ValueError naming the allowed ones."""
    b = str(name or "").strip()
    b = LEGACY_BRANCHES.get(b, b)
    if b not in BRANCHES:
        raise ValueError(f"Unknown branch {b!r}: choose one of {', '.join(BRANCHES)}.")
    return b


def current_branch(app_dir: str) -> Optional[str]:
    """The checked-out branch, or None (detached HEAD, not a checkout, no git)."""
    if not shutil.which("git"):
        return None
    try:
        cp = _git(app_dir, "rev-parse", "--abbrev-ref", "HEAD", timeout=15)
    except Exception:  # noqa: BLE001
        return None
    name = _out(cp) if cp.returncode == 0 else ""
    name = LEGACY_BRANCHES.get(name, name)
    return name if name and name != "HEAD" else None


def resolve_branch(app_dir: str, requested: Any = None) -> str:
    """The branch an update or a check applies to: the one asked for
    (validated), else the checked-out branch when it is one of BRANCHES
    — an update never silently moves an install off the branch it was
    put on — else main."""
    if requested:
        return valid_branch(requested)
    cur = current_branch(app_dir)
    return cur if cur in BRANCHES else DEFAULT_BRANCH


def branch_choices(app_dir: str) -> List[Dict[str, Any]]:
    """What the GUI offers: every allowed branch, its label, and whether
    it is the one checked out."""
    cur = current_branch(app_dir)
    return [{"name": b, "label": BRANCH_LABELS[b], "current": b == cur} for b in BRANCHES]


def status(app_dir: str, remote_sha: Optional[str] = None, branch: Optional[str] = None) -> Dict[str, Any]:
    """Where this install stands: current build, branch, whether GitHub
    is ahead on `branch` (the checked-out one by default), and whether
    it can be updated in place."""
    target = resolve_branch(app_dir, branch)
    out: Dict[str, Any] = {"app_dir": app_dir, "git_available": bool(shutil.which("git")),
                           "is_git_checkout": is_checkout(app_dir), "branch": None, "local_commit": None,
                           "target_branch": target, "branches": branch_choices(app_dir),
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

def update(app_dir: str, install_deps: bool = True, python: Optional[str] = None, branch: Optional[str] = None) -> Dict[str, Any]:
    """Preserve edits, fetch, switch to `branch` (one of BRANCHES; the
    checked-out one by default, else main), pull fast-forward only,
    install requirements. Never raises; every step is reported in
    `steps` and a failure sets `error`. `updated` is True when HEAD moved."""
    steps: List[Dict[str, Any]] = []
    result: Dict[str, Any] = {"ok": False, "updated": False, "before": None, "after": None, "steps": steps, "error": None,
                              "deps_ok": None, "restart_required": False, "preserved": [], "migrated": [], "recovered": None,
                              "branch": None}
    try:
        target = resolve_branch(app_dir, branch)
    except ValueError as e:
        result["error"] = str(e)
        steps.append({"name": "Check the branch", "ok": False, "detail": str(e), "soft": False})
        return result
    result["branch"] = target

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
    before_full = _out(_git(app_dir, "rev-parse", "HEAD")) or None

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

    if st.get("branch") != target:
        # A local branch is switched to; one only origin has is created to
        # track it; one GitHub does not have is refused before anything moves.
        if _git(app_dir, "show-ref", "--verify", "--quiet", f"refs/heads/{target}").returncode == 0:
            cp = _git(app_dir, "checkout", target)
        elif _git(app_dir, "show-ref", "--verify", "--quiet", f"refs/remotes/origin/{target}").returncode == 0:
            cp = _git(app_dir, "checkout", "-b", target, "--track", f"origin/{target}")
        else:
            cp = subprocess.CompletedProcess(["git"], 1, "", f"fatal: GitHub has no branch named {target}")
        if cp.returncode != 0:
            result["error"] = f"Could not switch to {target}: " + _err(cp)
            step(f"Switch to {target}", False, result["error"])
            _restore(app_dir, stashed, step, result)
            return result
        step(f"Switch to {target}", True, f"was on {st.get('branch')}")

    cp = _git(app_dir, "pull", "--ff-only", "origin", target, timeout=GIT_TIMEOUT)
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

    if result["updated"]:
        after_full = _out(_git(app_dir, "rev-parse", "HEAD")) or after
        verify = verify_against_github_api(app_dir, target, after_full)
        if verify.get("checked") and not verify.get("match"):
            reset_ok = False
            if before_full:
                reset_ok = _git(app_dir, "reset", "--hard", before_full).returncode == 0
            step("Verify against GitHub", False,
                 f"The commit just pulled ({after_full[:7]}) does not match what GitHub's REST API reports for "
                 f"{verify.get('owner')}/{verify.get('repo')}@{target} ({verify['api_sha'][:7]}) — this could mean the "
                 "git transport was tampered with in transit. " +
                 (f"Rolled back to {result['before']}." if reset_ok else "Could not roll back automatically; run  git status  in the app folder."))
            result["error"] = ("Update verification failed: the commit pulled over git does not match GitHub's REST API for the "
                               "same branch. " + ("Rolled back; nothing changed." if reset_ok else "Rollback failed; see the step detail.") +
                               " Try again, and check your network path to GitHub (a transparent proxy or DNS hijack can serve a different tree).")
            result["after"] = result["before"] if reset_ok else after
            result["updated"] = False
            _restore(app_dir, stashed, step, result)
            return result
        elif verify.get("checked"):
            step("Verify against GitHub", True,
                 f"Matches GitHub's REST API for {verify.get('owner')}/{verify.get('repo')}@{target} ({verify['api_sha'][:7]}).")

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
    shortcuts do, after this process has exited.

    Windows: the silent launcher itself, in batch mode (//B: Windows
    Script Host never shows an error dialog) with /restart, which makes
    it wait for this process to release the port before starting the
    new one. No `cmd /c timeout`: timeout refuses to run without a
    console ("Input redirection is not supported") and the relaunch
    silently never happened."""
    if sys.platform == "win32":
        vbs = os.path.join(app_dir, "START_Zscaler_Assessment.vbs")
        bat = os.path.join(app_dir, "START_Zscaler_Assessment.bat")
        if os.path.isfile(vbs):
            return ["wscript.exe", "//B", "//Nologo", vbs, "/restart"]
        return ["cmd", "/c", f'ping -n 4 127.0.0.1 >nul && "{bat}"']
    server = os.path.join(app_dir, "dlp_api_server.py")
    log = os.path.join(app_dir, "server.log")
    return ["sh", "-c", f'sleep 3; cd "{app_dir}" && nohup "{sys.executable}" "{server}" >> "{log}" 2>&1 &']


def manual_restart_hint(app_dir: str) -> str:
    """What to do by hand when the relaunch does not come back."""
    if sys.platform == "win32":
        return ("Close the app with STOP_Zscaler_Assessment.bat and open it again from the desktop shortcut "
                f"(or run START_Zscaler_Assessment.bat in {app_dir}). launcher.log next to the app records why a silent start failed.")
    return f"Start it again: cd \"{app_dir}\" && python dlp_api_server.py"


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
    # The new process keeps this one's UI token, so the page that asked
    # for the restart is still unlocked when it reloads (a fresh random
    # token would make the browser ask for ui_token.txt again).
    try:
        from security import ui_token
        env["ZSCALER_UI_TOKEN"] = ui_token()
    except Exception:  # noqa: BLE001
        pass
    try:
        subprocess.Popen(cmd, env=env, **kwargs)
    except Exception as e:  # noqa: BLE001
        return {"scheduled": False, "command": cmd, "error": f"{type(e).__name__}: {e}", "hint": manual_restart_hint(app_dir)}

    def _exit_soon() -> None:
        time.sleep(delay)
        os._exit(0)

    threading.Thread(target=_exit_soon, daemon=True).start()
    return {"scheduled": True, "command": cmd, "hint": manual_restart_hint(app_dir)}


# ── Command line (used by UPDATE_Zscaler_Assessment.bat) ──────────────

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Update DLP-Check in place (git pull, edits preserved).")
    ap.add_argument("--dir", default=os.path.dirname(os.path.abspath(__file__)), help="app folder (default: this file's folder)")
    ap.add_argument("--no-deps", action="store_true", help="skip pip install -r requirements.txt")
    ap.add_argument("--status", action="store_true", help="only report where this install stands")
    ap.add_argument("--branch", choices=BRANCHES, default=None,
                    help="branch to update to (default: the one checked out, else main)")
    args = ap.parse_args(argv)
    if args.status:
        st = status(args.dir, branch=args.branch)
        print(f"folder: {st['app_dir']}\nbranch: {st['branch']}  build: {st['local_commit']}\nupdates from: {st['target_branch']}\ncan update: {st['can_update']}")
        if st["reason"]:
            print(st["reason"])
        return 0 if st["can_update"] else 1
    res = update(args.dir, install_deps=not args.no_deps, branch=args.branch)
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
