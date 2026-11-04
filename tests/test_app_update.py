"""Update the app from the web UI: status, fast-forward pull, refusal on
hand-edited files, restart scheduling, and the endpoints."""
from __future__ import annotations

import ntpath
import os
import re
import shlex
import subprocess
import time

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient

import app_update as au

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}).stdout.strip()


@pytest.fixture
def repos(tmp_path):
    """A bare 'origin' with main, a clone that plays the installed app,
    and a working copy used to push new commits upstream."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    (work / "dlp_api_server.py").write_text("print('v1')\n")
    (work / "requirements.txt").write_text("requests>=2.28.0\n")
    (work / "requirements.lock").write_text("requests==2.32.3 \\\n    --hash=sha256:" + "0" * 64 + "\n")   # only hash-pinned installs
    _git(work, "add", "."); _git(work, "commit", "-q", "-m", "v1"); _git(work, "push", "-q", "origin", "HEAD:main")
    app = tmp_path / "app"
    _git(tmp_path, "clone", "-q", "-b", "main", str(origin), str(app))
    return {"origin": origin, "work": work, "app": app}


def _push_v2(work):
    (work / "dlp_api_server.py").write_text("print('v2')\n")
    _git(work, "commit", "-q", "-am", "v2"); _git(work, "push", "-q", "origin", "HEAD:main")
    return _git(work, "rev-parse", "--short", "HEAD")


def test_status_and_fast_forward_update(repos):
    app = str(repos["app"])
    v1 = _git(app, "rev-parse", "--short", "HEAD")
    st = au.status(app, remote_sha=v1)
    assert st["is_git_checkout"] and st["can_update"] and st["branch"] == "main" and st["update_available"] is False
    v2 = _push_v2(repos["work"])
    st = au.status(app, remote_sha=v2)
    assert st["update_available"] is True and st["local_commit"] == v1
    res = au.update(app, install_deps=False)
    assert res["ok"] and res["updated"] and res["before"] == v1 and res["after"] == v2 and res["restart_required"]
    names = [s["name"] for s in res["steps"]]
    assert names == ["Check this folder", "Fetch from GitHub", "Pull latest code", "Verify against GitHub: skipped"]
    assert all(s["ok"] for s in res["steps"][:-1])
    # The origin here is not GitHub, so the cross-check could not run: said so, never reported as verified.
    skip = res["steps"][-1]
    assert skip["ok"] is False and skip["soft"] and "NOT cross-checked" in skip["detail"] and "not a github.com remote" in skip["detail"]
    assert res["verified"] is False and res["verify_skipped"] == "origin is not a github.com remote"
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('v2')\n"
    # Second run: nothing to do, no restart needed.
    res2 = au.update(app, install_deps=False)
    assert res2["ok"] and not res2["updated"] and not res2["restart_required"] and "already on build" in res2["steps"][-1]["detail"]


def test_the_private_repository_is_cross_checked_with_the_token_and_a_skip_is_loud(tmp_path, monkeypatch, repos, capsys):
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    _git(repo, "remote", "add", "origin", "https://github.com/berserkerjay/DLP-Check.git")
    local_sha = "a" * 40
    seen = []

    class _Resp:
        def __init__(self, code, sha=""):
            self.status_code, self._sha = code, sha

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

        def json(self):
            return {"sha": self._sha}

    def private(url, headers=None, timeout=None):
        seen.append(dict(headers or {}))
        ok = (headers or {}).get("Authorization") == "Bearer tok-123"
        return _Resp(200, local_sha) if ok else _Resp(404)

    import requests
    monkeypatch.setattr(requests, "get", private)
    monkeypatch.delenv("DLP_CHECK_GITHUB_TOKEN", raising=False)
    v = au.verify_against_github_api(str(repo), "main", local_sha)
    assert not v["checked"] and "private" in v["reason"] and "DLP_CHECK_GITHUB_TOKEN" in v["reason"]
    monkeypatch.setenv("DLP_CHECK_GITHUB_TOKEN", "tok-123")
    v = au.verify_against_github_api(str(repo), "main", local_sha)
    assert v["checked"] and v["match"], "the token github_branch_head uses is sent here too"
    assert "tok-123" not in str(v)

    # A skipped check during a real update is a visible step, and the CLI warns.
    _push_v2(repos["work"])
    monkeypatch.setattr(au, "verify_against_github_api", lambda *a, **k: {"checked": False, "reason": "no token"})
    assert au.main(["--dir", str(repos["app"]), "--no-deps"]) == 0
    out = capsys.readouterr().out
    assert "[!! ] Verify against GitHub: skipped" in out and "WARNING: this update was NOT cross-checked" in out


def test_the_page_does_not_reload_over_an_unverified_update():
    js = open(os.path.join(ROOT, "static", "guide.js"), encoding="utf-8").read()
    assert "res.verified === false" in js and "not verified against GitHub" in js


def test_verify_against_github_api_matches_mismatches_and_skips(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    _git(repo, "remote", "add", "origin", "https://github.com/berserkerjay/DLP-Check.git")
    local_sha = "a" * 40

    class _Resp:
        def __init__(self, sha, code=200):
            self._sha, self.status_code = sha, code

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

        def json(self):
            return {"sha": self._sha}

    import requests
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp(local_sha))
    v = au.verify_against_github_api(str(repo), "main", local_sha)
    assert v == {"checked": True, "match": True, "api_sha": local_sha, "local_sha": local_sha, "owner": "berserkerjay", "repo": "DLP-Check"}

    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp("b" * 40))
    v = au.verify_against_github_api(str(repo), "main", local_sha)
    assert v["checked"] and not v["match"] and v["api_sha"] == "b" * 40

    # Not a github.com remote: skipped, not failed.
    _git(repo, "remote", "set-url", "origin", "/local/path")
    assert au.verify_against_github_api(str(repo), "main", local_sha) == {"checked": False, "reason": "origin is not a github.com remote"}

    # The API being unreachable is also skipped, not failed.
    _git(repo, "remote", "set-url", "origin", "https://github.com/berserkerjay/DLP-Check.git")

    def boom(url, headers=None, timeout=None):
        raise RuntimeError("network down")
    monkeypatch.setattr(requests, "get", boom)
    v = au.verify_against_github_api(str(repo), "main", local_sha)
    assert not v["checked"] and "network down" in v["reason"]


def test_update_verifies_against_github_api_when_it_agrees(repos, monkeypatch):
    app = str(repos["app"])
    v2 = _push_v2(repos["work"])
    monkeypatch.setattr(au, "verify_against_github_api",
                        lambda app_dir, branch, local_sha: {"checked": True, "match": True, "api_sha": local_sha,
                                                             "local_sha": local_sha, "owner": "berserkerjay", "repo": "DLP-Check"})
    res = au.update(app, install_deps=False)
    assert res["ok"] and res["updated"] and res["after"] == v2
    names = [s["name"] for s in res["steps"]]
    assert names == ["Check this folder", "Fetch from GitHub", "Pull latest code", "Verify against GitHub"]
    assert res["steps"][-1]["ok"] and "berserkerjay/DLP-Check" in res["steps"][-1]["detail"]


def test_update_rolls_back_when_the_github_api_disagrees(repos, monkeypatch):
    app = str(repos["app"])
    v1 = _git(app, "rev-parse", "HEAD")
    _push_v2(repos["work"])
    monkeypatch.setattr(au, "verify_against_github_api",
                        lambda app_dir, branch, local_sha: {"checked": True, "match": False, "api_sha": "f" * 40,
                                                             "local_sha": local_sha, "owner": "berserkerjay", "repo": "DLP-Check"})
    res = au.update(app, install_deps=False)
    assert not res["ok"] and not res["updated"]
    assert "Update verification failed" in res["error"] and "does not match GitHub's REST API" in res["error"]
    names = [s["name"] for s in res["steps"]]
    assert names == ["Check this folder", "Fetch from GitHub", "Pull latest code", "Verify against GitHub"]
    assert not res["steps"][-1]["ok"] and "Rolled back" in res["steps"][-1]["detail"]
    # The rollback actually happened: HEAD and the file content are back to v1.
    assert _git(app, "rev-parse", "HEAD") == v1
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('v1')\n"


def test_update_switches_back_to_main_and_installs_deps(repos, monkeypatch):
    app = str(repos["app"])
    _git(app, "checkout", "-q", "-b", "scratch")
    v2 = _push_v2(repos["work"])
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    real_run = subprocess.run
    monkeypatch.setattr(au.subprocess, "run", lambda cmd, **kw: fake_run(cmd, **kw) if cmd[1:3] == ["-m", "pip"] else real_run(cmd, **kw))
    res = au.update(app, python="/fake/python")
    assert res["ok"] and res["updated"] and res["after"] == v2 and res["deps_ok"] is True
    assert [s["name"] for s in res["steps"]] == ["Check this folder", "Fetch from GitHub", "Switch to main", "Pull latest code", "Verify against GitHub: skipped", "Install Python dependencies"]
    assert calls and calls[0][:4] == ["/fake/python", "-m", "pip", "install"] and calls[0][-1].endswith("requirements.lock")
    assert "--require-hashes" in calls[0], "the update only ever installs hash-verified"
    assert _git(app, "rev-parse", "--abbrev-ref", "HEAD") == "main"


def test_hand_edited_files_are_preserved_and_settings_move_to_local_settings(repos):
    app = str(repos["app"])
    # Older instructions: proxy / CA bundle set inside the start script.
    (repos["work"] / "START_Zscaler_Made_Easy.bat").write_text("@echo off\nREM set HTTPS_PROXY=http://proxy:8080\npython dlp_api_server.py\n")
    _git(repos["work"], "add", "."); _git(repos["work"], "commit", "-q", "-m", "start script"); _git(repos["work"], "push", "-q", "origin", "HEAD:main")
    _git(app, "pull", "-q", "--ff-only", "origin", "main")
    (repos["app"] / "START_Zscaler_Made_Easy.bat").write_text(
        "@echo off\nset REQUESTS_CA_BUNDLE=C:\\certs\\corp-root.pem\nset HTTPS_PROXY=http://proxy.corp:8080\npython dlp_api_server.py\n")
    (repos["app"] / "requirements.txt").write_text("requests>=2.28.0\n# my note\n")   # an unrelated hand edit
    v2 = _push_v2(repos["work"])
    st = au.status(app)
    assert st["can_update"] and sorted(st["dirty_files"]) == ["START_Zscaler_Made_Easy.bat", "requirements.txt"] and "keeps these edits" in st["reason"]
    res = au.update(app, install_deps=False)
    assert res["ok"] and res["updated"] and res["after"] == v2, res
    names = [s["name"] for s in res["steps"]]
    assert names == ["Check this folder", "Move settings to local_settings.bat", "Set aside hand-edited files", "Fetch from GitHub",
                     "Pull latest code", "Verify against GitHub: skipped", "Re-apply hand-edited files"] and all(s["ok"] for s in res["steps"] if s["name"] != "Verify against GitHub: skipped")
    assert res["migrated"] == ["START_Zscaler_Made_Easy.bat: REQUESTS_CA_BUNDLE", "START_Zscaler_Made_Easy.bat: HTTPS_PROXY"]
    ls = (repos["app"] / "local_settings.bat").read_text()
    assert "set REQUESTS_CA_BUNDLE=C:\\certs\\corp-root.pem" in ls and "set HTTPS_PROXY=http://proxy.corp:8080" in ls and ls.startswith("@echo off")
    # The start script is the committed one again; the unrelated edit survived the pull.
    assert "REQUESTS_CA_BUNDLE" not in (repos["app"] / "START_Zscaler_Made_Easy.bat").read_text()
    assert "# my note" in (repos["app"] / "requirements.txt").read_text() and res["preserved"] == ["requirements.txt"]
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('v2')\n"
    # Second update with the same edit still present: nothing lost, nothing to migrate twice.
    res2 = au.update(app, install_deps=False)
    assert res2["ok"] and not res2["updated"] and "# my note" in (repos["app"] / "requirements.txt").read_text()
    assert (repos["app"] / "local_settings.bat").read_text().count("REQUESTS_CA_BUNDLE") == 1
    # Untracked files (settings, caches) never appear as edits.
    (repos["app"] / "tenant_profiles.json").write_text("{}")
    assert "tenant_profiles.json" not in au.status(app)["dirty_files"]


def test_stale_index_lock_is_cleared_before_setting_edits_aside(repos):
    """An interrupted git leaves .git/index.lock behind; git then refuses
    every write ("could not write index"). The updater removes a lock old
    enough that nothing can still hold it, and carries on."""
    app = str(repos["app"])
    (repos["app"] / "requirements.txt").write_text("requests>=2.28.0\n# my note\n")
    lock = repos["app"] / ".git" / "index.lock"
    lock.write_text("")
    old = time.time() - 600
    os.utime(lock, (old, old))
    v2 = _push_v2(repos["work"])
    res = au.update(app, install_deps=False)
    assert res["ok"] and res["updated"] and res["after"] == v2, res
    names = [s["name"] for s in res["steps"]]
    assert names[:3] == ["Check this folder", "Clear a stale git lock", "Set aside hand-edited files"]
    assert "removed a stale git lock" in res["steps"][1]["detail"] and not lock.exists()
    assert "# my note" in (repos["app"] / "requirements.txt").read_text()


def test_half_applied_update_with_unmerged_paths_is_recovered(repos):
    """Re-applying stashed edits after a pull can conflict; git then holds
    unmerged paths and refuses to stash or pull. The next update copies the
    conflicted files aside, resets to the last build and completes."""
    app = str(repos["app"])
    # An edit to the file the next release also changes, then the old flow:
    # stash, pull, stash pop -> conflict left in place.
    (repos["app"] / "dlp_api_server.py").write_text("print('mine')\n")
    _git(app, "stash", "push", "-q", "-m", "old update")
    _push_v2(repos["work"])
    _git(app, "pull", "-q", "--ff-only", "origin", "main")
    cp = subprocess.run(["git", "stash", "pop"], cwd=app, capture_output=True, text=True)
    assert cp.returncode != 0 and au.unmerged_files(app) == ["dlp_api_server.py"]
    assert subprocess.run(["git", "stash", "push", "-m", "x"], cwd=app, capture_output=True, text=True).returncode != 0   # git refuses
    (repos["work"] / "dlp_api_server.py").write_text("print('v3')\n")
    _git(repos["work"], "commit", "-q", "-am", "v3"); _git(repos["work"], "push", "-q", "origin", "HEAD:main")
    v3 = _git(repos["work"], "rev-parse", "--short", "HEAD")
    res = au.update(app, install_deps=False)
    assert res["ok"] and res["updated"] and res["after"] == v3, res
    names = [s["name"] for s in res["steps"]]
    assert names == ["Check this folder", "Recover a half-applied earlier update", "Fetch from GitHub", "Pull latest code", "Verify against GitHub: skipped"]
    rec = res["recovered"]
    assert rec["files"] == ["dlp_api_server.py"] and os.path.isfile(os.path.join(rec["backup"], "dlp_api_server.py"))
    assert "<<<<<<<" in open(os.path.join(rec["backup"], "dlp_api_server.py")).read()    # the conflicted copy is kept
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('v3')\n" and au.unmerged_files(app) == []
    assert "old update" in _git(app, "stash", "list")                                    # the edits are still in the stash
    assert au.status(app)["can_update"]


def test_fresh_index_lock_is_left_alone_and_explained(repos):
    """A lock that is only seconds old may belong to a running git: the
    updater does not delete it, fails cleanly and says what to do."""
    app = str(repos["app"])
    (repos["app"] / "requirements.txt").write_text("requests>=2.28.0\n# my note\n")
    lock = repos["app"] / ".git" / "index.lock"
    lock.write_text("")
    res = au.update(app, install_deps=False)
    assert not res["ok"] and lock.exists()
    assert "Could not set aside the hand-edited files" in res["error"]
    assert "index.lock" in res["error"] and ("holding" in res["error"] or "delete it" in res["error"])
    # Nothing was pulled and the edit is untouched.
    assert "# my note" in (repos["app"] / "requirements.txt").read_text()
    lock.unlink()


def test_cli_reports_steps_and_exit_code(repos, capsys):
    app = str(repos["app"])
    v2 = _push_v2(repos["work"])
    assert au.main(["--dir", app, "--no-deps"]) == 0
    out = capsys.readouterr().out
    assert "[OK ] Pull latest code" in out and f"Now on build {v2}" in out
    assert au.main(["--dir", app, "--status"]) == 0
    _git(app, "remote", "set-url", "origin", "/nonexistent/origin.git")
    assert au.main(["--dir", app, "--no-deps"]) == 1
    assert "Update failed: Could not reach GitHub" in capsys.readouterr().out


def test_not_a_checkout_and_no_git(tmp_path, monkeypatch):
    plain = tmp_path / "plain"; plain.mkdir()
    st = au.status(str(plain))
    assert not st["is_git_checkout"] and not st["can_update"] and "not a git checkout" in st["reason"]
    res = au.update(str(plain))
    assert not res["ok"] and "not a git checkout" in res["error"]
    monkeypatch.setattr(au.shutil, "which", lambda _: None)
    assert "git is not installed" in au.status(str(plain))["reason"]


def test_restart_command_and_dry_run(tmp_path, monkeypatch):
    app = str(tmp_path)
    monkeypatch.setattr(au.sys, "platform", "win32")
    (tmp_path / "START_Zscaler_Made_Easy.vbs").write_text("x")
    cmd = au.restart_command(app)
    # The launcher runs in batch mode (no Windows Script Host dialogs) with
    # /restart so it waits for the port; never `cmd /c timeout`, which
    # refuses to run without a console and silently never relaunched.
    assert cmd[0] == "wscript.exe" and "//B" in cmd and cmd[-2].endswith("START_Zscaler_Made_Easy.vbs") and cmd[-1] == "/restart"
    assert "timeout" not in " ".join(cmd)
    (tmp_path / "START_Zscaler_Made_Easy.vbs").unlink()
    cmd = au.restart_command(app)
    assert cmd[:2] == ["cmd", "/c"] and "ping -n 4" in cmd[2] and "START_Zscaler_Made_Easy.bat" in cmd[2]
    assert "STOP_Zscaler_Made_Easy.bat" in au.manual_restart_hint(app)
    monkeypatch.setattr(au.sys, "platform", "linux")
    cmd = au.restart_command(app)
    assert cmd[:2] == ["sh", "-c"] and "dlp_api_server.py" in cmd[2] and "sleep 3" in cmd[2]
    out = au.schedule_restart(app, dry_run=True)
    assert out["scheduled"] is False and out["command"] == cmd
    # The relauncher inherits this process's UI token so the page stays unlocked after the restart.
    seen = {}
    monkeypatch.setattr(au.subprocess, "Popen", lambda c, env=None, **kw: seen.update({"cmd": c, "env": env}))
    monkeypatch.setattr(au.threading, "Thread", lambda *a, **k: type("T", (), {"start": lambda self: None})())
    import security
    out = au.schedule_restart(app)
    assert out["scheduled"] and seen["env"]["ZSCALER_UI_TOKEN"] == security.ui_token() and "DLPCHECK_HIDDEN" not in seen["env"] and out["hint"]
    def fail(c, env=None, **kw):
        raise OSError("wscript missing")
    monkeypatch.setattr(au.subprocess, "Popen", fail)
    out = au.schedule_restart(app)
    assert out["scheduled"] is False and "wscript missing" in out["error"] and out["hint"]


def test_launcher_never_shows_a_script_host_dialog():
    vbs = open(os.path.join(ROOT, "START_Zscaler_Made_Easy.vbs"), encoding="utf-8").read()
    assert "On Error Resume Next" in vbs and "launcher.log" in vbs and "/restart" in vbs
    assert 'WScript.Arguments' in vbs and "Do While Pinging()" in vbs and "WScript.Quit 0" in vbs
    # The .gitignore keeps the launcher log out of commits.
    assert "launcher.log" in open(os.path.join(ROOT, ".gitignore")).read()


def test_endpoints(repos, monkeypatch):
    import dlp_api_server as srv
    app = str(repos["app"])
    monkeypatch.setattr(srv, "_APP_DIR", app)
    v2 = _push_v2(repos["work"])
    monkeypatch.setattr(srv, "_latest_remote_commit", lambda branch="main": v2)
    c = TestClient(srv.app)
    st = c.get("/api/app/update/status?refresh=1").json()
    assert st["update_available"] is True and st["can_update"] and st["remote_commit"] == v2 and st["restart_command"]
    # The branch an update applies to, and the ones it may switch to, are reported; only those are accepted.
    assert st["target_branch"] == "main" and [b["name"] for b in st["branches"]] == list(au.BRANCHES) and st["branches"][0]["current"] is True
    assert c.get("/api/app/update/status?branch=dev").json()["target_branch"] == "dev"
    bad = c.get("/api/app/update/status?branch=release%2Fevil")
    assert bad.status_code == 400 and "choose one of" in bad.json()["detail"]
    h = c.get("/api/health").json()
    assert h["branch"] == "main" and [b["name"] for b in h["branches"]] == list(au.BRANCHES) and h["latest_commit"] == v2
    seen = {}
    monkeypatch.setattr(au, "update", lambda app_dir, install_deps=True, python=None, branch=None: seen.update({"branch": branch}) or {"ok": True, "updated": True, "before": "a", "after": v2, "steps": [], "error": None, "restart_required": True, "app_dir": app_dir, "branch": branch})
    r = c.post("/api/app/update")
    assert r.status_code == 200 and r.json()["updated"] and r.json()["app_dir"] == app and seen["branch"] == "main", "no body: the branch the install is on"
    r = c.post("/api/app/update", json={"branch": "dev"})
    assert r.status_code == 200 and seen["branch"] == "dev"
    assert c.post("/api/app/update", json={"branch": "feature/x"}).status_code == 400
    scheduled = {}
    monkeypatch.setattr(au, "schedule_restart", lambda app_dir, delay=0.8, dry_run=False: scheduled.update({"dir": app_dir}) or {"scheduled": True, "command": ["x"]})
    r = c.post("/api/app/restart")
    assert r.status_code == 200 and r.json()["scheduled"] and scheduled["dir"] == app
    # Not localhost-bound: refused, nothing runs.
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    assert c.post("/api/app/update").status_code == 403 and c.post("/api/app/restart").status_code == 403
    html = c.get("/static/guide.js").text
    assert "_gdUpdateApp" in html and "/api/app/update" in html and "Update app now" in html
    assert "gdUpdBranch" in html and "JSON.stringify({ branch })" in html, "the card offers the branch and posts the choice"
    # The button is offered even when the GitHub check failed, and the reason is shown.
    assert "could not check GitHub" in html and "latest_commit_error" in html and "btn('Update app', true)" in html


def test_health_reports_why_the_github_check_failed(repos, monkeypatch):
    import dlp_api_server as srv
    app = str(repos["app"])
    _git(app, "remote", "set-url", "origin", str(repos["origin"] / "does-not-exist"))
    monkeypatch.setattr(srv, "_APP_DIR", app)
    srv._LATEST.clear()
    c = TestClient(srv.app)
    h = c.get("/api/health").json()
    assert h["latest_commit"] is None and h["latest_commit_error"]
    st = c.get("/api/app/update/status?refresh=1").json()
    assert st["remote_commit"] is None and st["remote_error"] and st["can_update"]
    srv._LATEST.clear()


def test_worktree_and_nested_folders_count_as_checkouts(repos, tmp_path):
    # A worktree has a .git *file*, not a directory.
    wt = tmp_path / "wt"
    _git(str(repos["app"]), "worktree", "add", "-q", "--detach", str(wt), "main")
    assert (wt / ".git").is_file() and au.is_checkout(str(wt))
    st = au.status(str(wt))
    assert st["is_git_checkout"] and st["can_update"]
    # A folder inside a checkout is managed by git too.
    sub = repos["app"] / "sub"; sub.mkdir()
    assert au.is_checkout(str(sub))
    # A plain folder is not.
    plain = tmp_path / "plain"; plain.mkdir()
    assert not au.is_checkout(str(plain))


def test_git_gets_the_corporate_ca_bundle_and_ssl_failures_are_explained(tmp_path, monkeypatch):
    bundle = tmp_path / "corp-ca.pem"; bundle.write_text("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    for k in ("GIT_SSL_CAINFO", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "ZSCALER_CA_BUNDLE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    env = au.git_env()
    assert env["GIT_SSL_CAINFO"] == str(bundle) and env["GIT_TERMINAL_PROMPT"] == "0"
    # A bundle that does not exist is not handed to git.
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "missing.pem"))
    assert "GIT_SSL_CAINFO" not in au.git_env()
    # The explanation names the fix for TLS inspection, with and without a bundle.
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    hint = au._auth_hint("fatal: unable to access 'https://github.com/x': SSL certificate problem: unable to get local issuer certificate")
    assert "TLS inspection" in hint and str(bundle) in hint
    monkeypatch.delenv("REQUESTS_CA_BUNDLE")
    hint = au._auth_hint("fatal: SSL certificate problem: self-signed certificate in certificate chain")
    assert "REQUESTS_CA_BUNDLE" in hint and "local_settings.bat" in hint
    assert "could not be reached" in au._auth_hint("fatal: unable to access: Could not resolve host: github.com")


def test_update_can_switch_to_another_allowed_branch_and_then_stays_on_it(repos):
    """A dev branch on GitHub, one commit ahead of main: an update asked
    for dev switches to it (tracking origin), pulls it, and verifies it
    against that branch; an update with no branch named then stays on
    dev instead of silently moving the install back to main; asking for
    main switches back."""
    app, work = str(repos["app"]), repos["work"]
    _git(work, "checkout", "-q", "-b", "dev")
    (work / "dlp_api_server.py").write_text("print('dev')\n")
    _git(work, "commit", "-q", "-am", "dev work"); _git(work, "push", "-q", "origin", "dev")
    dev_sha = _git(work, "rev-parse", "--short", "HEAD")
    assert au.current_branch(app) == "main" and au.resolve_branch(app) == "main"
    st = au.status(app, remote_sha=dev_sha, branch="dev")
    assert st["target_branch"] == "dev" and st["update_available"] is True
    assert [b["name"] for b in st["branches"]] == list(au.BRANCHES) and [b["current"] for b in st["branches"]] == [True, False, False]
    res = au.update(app, install_deps=False, branch="dev")
    assert res["ok"] and res["updated"] and res["after"] == dev_sha and res["branch"] == "dev", res
    assert [s["name"] for s in res["steps"]] == ["Check this folder", "Fetch from GitHub", "Switch to dev", "Pull latest code", "Verify against GitHub: skipped"]
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('dev')\n" and au.current_branch(app) == "dev"
    assert au.resolve_branch(app) == "dev", "no branch asked for: the one the install is on"
    res2 = au.update(app, install_deps=False)
    assert res2["ok"] and not res2["updated"] and res2["branch"] == "dev" and au.current_branch(app) == "dev"
    res3 = au.update(app, install_deps=False, branch="main")
    assert res3["ok"] and res3["branch"] == "main" and au.current_branch(app) == "main"
    assert "Switch to main" in [s["name"] for s in res3["steps"]] and (repos["app"] / "dlp_api_server.py").read_text() == "print('v1')\n"


def test_only_the_allowed_branches_are_accepted_and_a_missing_one_is_refused_before_anything_moves(repos):
    app = str(repos["app"])
    with pytest.raises(ValueError, match="choose one of"):
        au.valid_branch("release/evil; rm -rf")
    res = au.update(app, install_deps=False, branch="feature/x")
    assert not res["ok"] and "Unknown branch" in res["error"] and res["steps"][0]["name"] == "Check the branch"
    with pytest.raises(SystemExit):
        au.main(["--dir", app, "--no-deps", "--branch", "feature/x"])   # argparse refuses anything outside the allowlist
    # An allowed branch this origin does not have: refused, the install untouched.
    res = au.update(app, install_deps=False, branch="qa")
    assert not res["ok"] and "no branch named qa" in res["error"], res
    # The names are the standard three; the old QA name is mapped, not refused, so an install still on it keeps updating.
    assert au.BRANCHES == ("main", "qa", "dev") and au.valid_branch("DLP-CHECK-QA") == "qa"
    assert [b["name"] for b in au.branch_choices(app)] == ["main", "qa", "dev"]
    assert au.current_branch(app) == "main" and (repos["app"] / "dlp_api_server.py").read_text() == "print('v1')\n"
    assert au.main(["--dir", app, "--status", "--branch", "main"]) == 0


# ── Restart and shortcuts across the rename to Zscaler Made Easy ──────
#
# A build from before the rename keeps running until it restarts. Its
# Update app restart runs START_Zscaler_Assessment.vbs (or, without it,
# START_Zscaler_Assessment.bat) from the freshly pulled folder, and its
# desktop shortcut runs the same .vbs. Those names are now shims that hand
# over to the renamed launchers. Windows itself runs them in
# tools/verify_native_install.py; here the shims are evaluated the way
# Windows Script Host and cmd would expand them.

WIN_APP = r"C:\Users\Jo O'Neil & Co\Zscaler Made Easy"


def _old_build_restart_command(app_dir):
    """What app_update.restart_command did before the rename (Windows)."""
    vbs = ntpath.join(app_dir, "START_Zscaler_Assessment.vbs")
    bat = ntpath.join(app_dir, "START_Zscaler_Assessment.bat")
    if os.path.isfile(os.path.join(ROOT, ntpath.basename(vbs))):
        return ["wscript.exe", "//B", "//Nologo", vbs, "/restart"]
    return ["cmd", "/c", f'ping -n 4 127.0.0.1 >nul && "{bat}"']


def _vbs_expr(expr, names):
    """Evaluate a VBScript string expression of literals, names and &."""
    out = []
    for tok in re.findall(r'"(?:[^"]|"")*"|[A-Za-z_][\w.]*(?:\(i\))?|&', expr):
        if tok == "&":
            continue
        out.append(tok[1:-1].replace('""', '"') if tok.startswith('"') else names[tok])
    return "".join(out)


def _run_vbs_shim(app_dir, args):
    """The command line START_Zscaler_Assessment.vbs runs, and whether it waits."""
    src = open(os.path.join(ROOT, "START_Zscaler_Assessment.vbs"), encoding="utf-8").read()
    target = re.search(r'launcher = fso\.BuildPath\(fso\.GetParentFolderName\(WScript\.ScriptFullName\), "([^"]+)"\)', src).group(1)
    names = {"launcher": ntpath.join(app_dir, target), "args": ""}
    loop = re.search(r"For i = 0 To WScript\.Arguments\.Count - 1\n\s*args = (.+)\nNext", src).group(1)
    for a in args:
        names["args"] = _vbs_expr(loop, {**names, "WScript.Arguments(i)": a})
    run = re.search(r"rc = sh\.Run\((.+), 0, (True|False)\)\n", src)
    return _vbs_expr(run.group(1), names), run.group(2) == "True", src


def _run_bat_shim(name, app_dir, args):
    """The one command a .bat shim runs, with %~dp0 and %* expanded as cmd does."""
    lines = [l for l in open(os.path.join(ROOT, name), encoding="utf-8").read().splitlines()
             if l.strip() and not l.lstrip().upper().startswith(("REM ", "@ECHO OFF"))]
    assert len(lines) == 1, "a shim runs exactly one command"
    return lines[0].replace("%~dp0", app_dir + "\\").replace("%*", " ".join(args))


def test_an_old_builds_update_restart_reaches_the_renamed_launcher(monkeypatch, tmp_path):
    # Arrange: the old build finds its launcher name in the pulled folder.
    old = _old_build_restart_command(WIN_APP)
    assert old[:3] == ["wscript.exe", "//B", "//Nologo"] and ntpath.basename(old[3]) == "START_Zscaler_Assessment.vbs"
    # Act: the shim builds the next command line from its own folder and arguments.
    line, waits, src = _run_vbs_shim(ntpath.dirname(old[3]), old[4:])
    # Assert: the renamed launcher, with /restart, the same one a new build restarts through.
    argv = shlex.split(line)
    monkeypatch.setattr(au.sys, "platform", "win32")
    (tmp_path / "START_Zscaler_Made_Easy.vbs").write_text("x")
    new = au.restart_command(str(tmp_path))
    assert argv == ["wscript.exe", "//B", "//Nologo", ntpath.join(WIN_APP, "START_Zscaler_Made_Easy.vbs"), "/restart"]
    assert argv[:3] == new[:3] and ntpath.basename(argv[3]) == os.path.basename(new[3]) and argv[4:] == new[4:]
    assert waits and "WScript.Quit rc" in src, "the shim waits and passes the launcher's exit code on"
    assert "On Error Resume Next" in src, "no Windows Script Host dialog from the shim either"


def test_an_old_desktop_shortcut_reaches_the_renamed_launcher():
    # An old shortcut runs:  wscript.exe "<app>\START_Zscaler_Assessment.vbs"  with no arguments.
    line, waits, _ = _run_vbs_shim(WIN_APP, [])
    assert shlex.split(line) == ["wscript.exe", "//B", "//Nologo", ntpath.join(WIN_APP, "START_Zscaler_Made_Easy.vbs")]


def test_an_old_builds_restart_fallback_reaches_the_renamed_batch_launcher(monkeypatch):
    # Arrange: an old build without the .vbs falls back to the batch file.
    monkeypatch.setattr(os.path, "isfile", lambda p: False)
    old = _old_build_restart_command(WIN_APP)
    monkeypatch.undo()
    bat = re.search(r'&& "(.+)"$', old[2]).group(1)
    assert ntpath.basename(bat) == "START_Zscaler_Assessment.bat"
    # Act
    line = _run_bat_shim(ntpath.basename(bat), ntpath.dirname(bat), [])
    # Assert: handed over (no call, so cmd never reads the shim again) to the renamed launcher.
    assert line == '"' + ntpath.join(WIN_APP, "START_Zscaler_Made_Easy.bat") + '" '
    assert not line.lower().startswith("call ")


@pytest.mark.parametrize("shim, target, args", [
    ("START_Zscaler_Assessment.bat", "START_Zscaler_Made_Easy.bat", ["--console"]),
    ("UPDATE_Zscaler_Assessment.bat", "UPDATE_Zscaler_Made_Easy.bat", ["dev"]),
])
def test_old_batch_names_pass_their_arguments_on(shim, target, args):
    line = _run_bat_shim(shim, WIN_APP, args)
    assert line == '"' + ntpath.join(WIN_APP, target) + '" ' + " ".join(args)
    assert os.path.isfile(os.path.join(ROOT, target))


def test_new_builds_restart_through_the_renamed_launcher_only(monkeypatch, tmp_path):
    monkeypatch.setattr(au.sys, "platform", "win32")
    (tmp_path / "START_Zscaler_Made_Easy.vbs").write_text("x")
    (tmp_path / "START_Zscaler_Assessment.vbs").write_text("x")
    assert os.path.basename(au.restart_command(str(tmp_path))[3]) == "START_Zscaler_Made_Easy.vbs"
    assert "START_Zscaler_Made_Easy" in au.manual_restart_hint(str(tmp_path))


def test_shortcut_refresh_is_windows_only(monkeypatch, tmp_path):
    monkeypatch.setattr(au.sys, "platform", "linux")
    monkeypatch.setattr(au.subprocess, "run", lambda *a, **k: pytest.fail("no PowerShell off Windows"))
    assert au.refresh_shortcuts(str(tmp_path)) is None


def test_shortcut_refresh_passes_the_folder_in_the_environment_not_the_script(monkeypatch, tmp_path):
    """ASVS V5.3.8 · CWE-78 · A03:2021: a folder name with quotes or an ampersand cannot change what PowerShell runs."""
    # Arrange
    app = tmp_path / "Jo's & \"Co\" $(calc)"
    app.mkdir()
    seen = {}
    def fake_run(cmd, **kw):
        seen.update(cmd=cmd, **kw)
        return subprocess.CompletedProcess(cmd, 0, "Desktop\nPrograms\n", "")
    monkeypatch.setattr(au.sys, "platform", "win32")
    monkeypatch.setattr(au.subprocess, "run", fake_run)
    # Act
    out = au.refresh_shortcuts(str(app))
    # Assert
    assert seen["cmd"] == ["powershell", "-NoProfile", "-NonInteractive", "-Command", au.SHORTCUT_SCRIPT]
    assert str(app) not in au.SHORTCUT_SCRIPT and seen["env"]["DLPCHECK_SHORTCUT_APP_DIR"] == str(app)
    assert seen["creationflags"] == 0x08000000 and seen["timeout"] == au.SHORTCUT_TIMEOUT
    assert out == {"ok": True, "detail": "Rewrote the desktop and Start Menu shortcut as Zscaler Made Easy"}


def test_shortcut_script_replaces_only_this_folders_shortcut_and_removes_the_old_name_last():
    s = au.SHORTCUT_SCRIPT
    assert "$env:DLPCHECK_SHORTCUT_APP_DIR" in s and '"' not in s
    assert "'Zscaler Made Easy.lnk'" in s and "'Zscaler Assessment.lnk'" in s and "'START_Zscaler_Made_Easy.vbs'" in s
    assert "WorkingDirectory.TrimEnd('\\') -eq $app" in s, "a shortcut of another copy of the app is left alone"
    assert "if ($ours.Count -eq 0) { continue }" in s, "a shortcut the user deleted is not brought back"
    assert s.index("$lnk.Save()") < s.index("if ((Test-Path -LiteralPath $new) -and ($old -in $ours)) { Remove-Item -LiteralPath $old }")
    assert s.count("Remove-Item") == 1


@pytest.mark.parametrize("result, expected", [
    (subprocess.CompletedProcess([], 0, "", ""), "No shortcut of this folder to rewrite"),
    (subprocess.CompletedProcess([], 0, "Desktop\n", ""), "Rewrote the desktop shortcut as Zscaler Made Easy"),
    (subprocess.CompletedProcess([], 1, "", "Cannot create type. Only core types are supported in this language mode."), "left as they were"),
])
def test_shortcut_refresh_reports_what_it_did(monkeypatch, tmp_path, result, expected):
    monkeypatch.setattr(au.sys, "platform", "win32")
    monkeypatch.setattr(au.subprocess, "run", lambda *a, **k: result)
    out = au.refresh_shortcuts(str(tmp_path))
    assert out["ok"] is (result.returncode == 0) and expected in out["detail"]


def test_shortcut_refresh_never_raises(monkeypatch, tmp_path):
    def missing(*a, **k):
        raise FileNotFoundError("powershell")
    monkeypatch.setattr(au.sys, "platform", "win32")
    monkeypatch.setattr(au.subprocess, "run", missing)
    out = au.refresh_shortcuts(str(tmp_path))
    assert out["ok"] is False and "left as they were" in out["detail"]


def test_the_in_app_update_refreshes_the_shortcuts_as_a_soft_step(repos, monkeypatch):
    app = str(repos["app"])
    _push_v2(repos["work"])
    calls = []
    monkeypatch.setattr(au, "refresh_shortcuts", lambda d: calls.append(d) or {"ok": False, "detail": "PowerShell could not"})
    res = au.update(app, install_deps=False)
    step = res["steps"][-1]
    assert calls == [app] and res["ok"] and step["name"] == "Refresh the desktop shortcuts" and step["soft"] and not step["ok"]


# ── Wave 6 UI check: an update is confirmed first and leaves an audit record ──

@pytest.mark.parametrize("script,handler", [("advanced.js", "async function runUpdate()"), ("guide.js", "async function _gdUpdateApp()")])
def test_every_update_button_asks_before_it_changes_the_app(script, handler):
    """WCAG 2.2 SC 3.3.4 · CWE-1188: table over both Update buttons (Advanced settings, the dashboard card): a confirmation names what happens before /api/app/update is called (one click updated, switched branch, stashed edits and installed packages)."""
    js = open(os.path.join(ROOT, "static", script), encoding="utf-8").read()
    body = js[js.index(handler):]
    body = body[: body.index("\n}") if script == "guide.js" else body.index("\n  }")]
    assert "window.confirm(" in body and body.index("window.confirm(") < body.index("/api/app/update")
    assert "if (!window.confirm(" in body, "cancelling the dialog stops the update"
    assert "git stash" in body and "restart" in body and "Nothing in the tenant changes" in body


def test_an_app_update_is_recorded_in_the_audit_log(repos, monkeypatch, tmp_path):
    """ASVS V7.1.3 · CWE-778: POST /api/app/update writes an app_update event (branch, builds, result) to the audit log."""
    import json as _json
    import dlp_api_server as srv
    # Arrange
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    monkeypatch.setattr(srv, "_APP_DIR", str(repos["app"]))
    monkeypatch.setattr(au, "update", lambda app_dir, install_deps=True, python=None, branch=None: {
        "ok": True, "updated": True, "before": "a" * 7, "after": "b" * 7, "steps": [], "error": None, "restart_required": True, "app_dir": app_dir, "branch": branch})
    # Act
    r = TestClient(srv.app).post("/api/app/update")
    # Assert
    assert r.status_code == 200
    events = [_json.loads(x) for x in read_store_text(log).splitlines()]
    hit = [e for e in events if e["event"] == "app_update"]
    assert hit and hit[-1]["branch"] == "main" and hit[-1]["ok"] is True and hit[-1]["before"] == "a" * 7 and hit[-1]["after"] == "b" * 7


def test_a_refused_update_writes_no_audit_event(repos, monkeypatch, tmp_path):
    """ASVS V7.1.3 · CWE-778: negative case: an update refused before it runs (not bound to localhost) records nothing and changes nothing."""
    import dlp_api_server as srv
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    monkeypatch.setattr(srv, "_APP_DIR", str(repos["app"]))
    monkeypatch.setattr(au, "update", lambda *a, **k: pytest.fail("the update must not run"))
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    assert TestClient(srv.app).post("/api/app/update").status_code == 403
    assert not log.exists() or "app_update" not in read_store_text(log)



@pytest.mark.parametrize("origin,trusted", [
    ("https://github.com/berserkerjay/Zscaler-Made-Easy.git", True),
    ("https://github.com/berserkerjay/DLP-Check.git", True),      # the same repository under its earlier name
    ("https://github.com/someone-else/Zscaler-Made-Easy.git", False),
    ("https://github.com/berserkerjay/Other.git", False),
])
def test_the_upstream_check_trusts_the_repository_under_both_its_names(tmp_path, monkeypatch, origin, trusted):
    """SLSA v1.0 Source · SSDF PS.2.1 · CWE-494: after the GitHub rename, a clone naming the new or the old name of the same repository is vouched for; a fork or another repository is not (refused before any request)."""
    import requests
    monkeypatch.delenv("DLP_CHECK_GITHUB_REPO", raising=False)
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", origin)
    calls = []

    class R:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"sha": "a" * 40}
    monkeypatch.setattr(requests, "get", lambda url, **kw: calls.append(url) or R())
    v = au.verify_against_github_api(str(repo), "main", "a" * 40)
    assert bool(v.get("checked")) is trusted and bool(calls) is trusted, v
