"""Update the app from the web UI: status, fast-forward pull, refusal on
hand-edited files, restart scheduling, and the endpoints."""
from __future__ import annotations

import os
import subprocess

import pytest
from fastapi.testclient import TestClient

import app_update as au


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
    assert names == ["Check this folder", "Fetch from GitHub", "Pull latest code"] and all(s["ok"] for s in res["steps"])
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('v2')\n"
    # Second run: nothing to do, no restart needed.
    res2 = au.update(app, install_deps=False)
    assert res2["ok"] and not res2["updated"] and not res2["restart_required"] and "already on build" in res2["steps"][-1]["detail"]


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
    assert [s["name"] for s in res["steps"]] == ["Check this folder", "Fetch from GitHub", "Switch to main", "Pull latest code", "Install Python dependencies"]
    assert calls and calls[0][:4] == ["/fake/python", "-m", "pip", "install"] and calls[0][-1].endswith("requirements.txt")
    assert _git(app, "rev-parse", "--abbrev-ref", "HEAD") == "main"


def test_hand_edited_files_are_preserved_and_settings_move_to_local_settings(repos):
    app = str(repos["app"])
    # Older instructions: proxy / CA bundle set inside the start script.
    (repos["work"] / "START_Zscaler_Assessment.bat").write_text("@echo off\nREM set HTTPS_PROXY=http://proxy:8080\npython dlp_api_server.py\n")
    _git(repos["work"], "add", "."); _git(repos["work"], "commit", "-q", "-m", "start script"); _git(repos["work"], "push", "-q", "origin", "HEAD:main")
    _git(app, "pull", "-q", "--ff-only", "origin", "main")
    (repos["app"] / "START_Zscaler_Assessment.bat").write_text(
        "@echo off\nset REQUESTS_CA_BUNDLE=C:\\certs\\corp-root.pem\nset HTTPS_PROXY=http://proxy.corp:8080\npython dlp_api_server.py\n")
    (repos["app"] / "requirements.txt").write_text("requests>=2.28.0\n# my note\n")   # an unrelated hand edit
    v2 = _push_v2(repos["work"])
    st = au.status(app)
    assert st["can_update"] and sorted(st["dirty_files"]) == ["START_Zscaler_Assessment.bat", "requirements.txt"] and "keeps these edits" in st["reason"]
    res = au.update(app, install_deps=False)
    assert res["ok"] and res["updated"] and res["after"] == v2, res
    names = [s["name"] for s in res["steps"]]
    assert names == ["Check this folder", "Move settings to local_settings.bat", "Set aside hand-edited files", "Fetch from GitHub",
                     "Pull latest code", "Re-apply hand-edited files"] and all(s["ok"] for s in res["steps"])
    assert res["migrated"] == ["START_Zscaler_Assessment.bat: REQUESTS_CA_BUNDLE", "START_Zscaler_Assessment.bat: HTTPS_PROXY"]
    ls = (repos["app"] / "local_settings.bat").read_text()
    assert "set REQUESTS_CA_BUNDLE=C:\\certs\\corp-root.pem" in ls and "set HTTPS_PROXY=http://proxy.corp:8080" in ls and ls.startswith("@echo off")
    # The start script is the committed one again; the unrelated edit survived the pull.
    assert "REQUESTS_CA_BUNDLE" not in (repos["app"] / "START_Zscaler_Assessment.bat").read_text()
    assert "# my note" in (repos["app"] / "requirements.txt").read_text() and res["preserved"] == ["requirements.txt"]
    assert (repos["app"] / "dlp_api_server.py").read_text() == "print('v2')\n"
    # Second update with the same edit still present: nothing lost, nothing to migrate twice.
    res2 = au.update(app, install_deps=False)
    assert res2["ok"] and not res2["updated"] and "# my note" in (repos["app"] / "requirements.txt").read_text()
    assert (repos["app"] / "local_settings.bat").read_text().count("REQUESTS_CA_BUNDLE") == 1
    # Untracked files (settings, caches) never appear as edits.
    (repos["app"] / "tenant_profiles.json").write_text("{}")
    assert "tenant_profiles.json" not in au.status(app)["dirty_files"]


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
    (tmp_path / "START_Zscaler_Assessment.vbs").write_text("x")
    cmd = au.restart_command(app)
    assert cmd[:2] == ["cmd", "/c"] and "wscript.exe" in cmd[2] and "START_Zscaler_Assessment.vbs" in cmd[2] and "timeout /t 3" in cmd[2]
    monkeypatch.setattr(au.sys, "platform", "linux")
    cmd = au.restart_command(app)
    assert cmd[:2] == ["sh", "-c"] and "dlp_api_server.py" in cmd[2] and "sleep 3" in cmd[2]
    out = au.schedule_restart(app, dry_run=True)
    assert out["scheduled"] is False and out["command"] == cmd


def test_endpoints(repos, monkeypatch):
    import dlp_api_server as srv
    app = str(repos["app"])
    monkeypatch.setattr(srv, "_APP_DIR", app)
    v2 = _push_v2(repos["work"])
    monkeypatch.setattr(srv, "_latest_remote_commit", lambda: v2)
    c = TestClient(srv.app)
    st = c.get("/api/app/update/status?refresh=1").json()
    assert st["update_available"] is True and st["can_update"] and st["remote_commit"] == v2 and st["restart_command"]
    monkeypatch.setattr(au, "update", lambda app_dir, install_deps=True, python=None: {"ok": True, "updated": True, "before": "a", "after": v2, "steps": [], "error": None, "restart_required": True, "app_dir": app_dir})
    r = c.post("/api/app/update")
    assert r.status_code == 200 and r.json()["updated"] and r.json()["app_dir"] == app
    scheduled = {}
    monkeypatch.setattr(au, "schedule_restart", lambda app_dir, delay=0.8, dry_run=False: scheduled.update({"dir": app_dir}) or {"scheduled": True, "command": ["x"]})
    r = c.post("/api/app/restart")
    assert r.status_code == 200 and r.json()["scheduled"] and scheduled["dir"] == app
    # Not localhost-bound: refused, nothing runs.
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    assert c.post("/api/app/update").status_code == 403 and c.post("/api/app/restart").status_code == 403
    html = c.get("/static/guide.js").text
    assert "_gdUpdateApp" in html and "/api/app/update" in html and "Update app now" in html
    # The button is offered even when the GitHub check failed, and the reason is shown.
    assert "could not check GitHub" in html and "latest_commit_error" in html and "btn('Update app', true)" in html


def test_health_reports_why_the_github_check_failed(repos, monkeypatch):
    import dlp_api_server as srv
    app = str(repos["app"])
    _git(app, "remote", "set-url", "origin", str(repos["origin"] / "does-not-exist"))
    monkeypatch.setattr(srv, "_APP_DIR", app)
    srv._LATEST.update({"at": 0.0, "sha": None, "error": None})
    c = TestClient(srv.app)
    h = c.get("/api/health").json()
    assert h["latest_commit"] is None and h["latest_commit_error"]
    st = c.get("/api/app/update/status?refresh=1").json()
    assert st["remote_commit"] is None and st["remote_error"] and st["can_update"]
    srv._LATEST.update({"at": 0.0, "sha": None, "error": None})
