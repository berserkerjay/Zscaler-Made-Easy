"""Both delivery modes are built from this one source tree: the local
installer (install.sh / the Windows .bat files) and the container
(Dockerfile, docker-compose.yml). These tests keep them in step: the
same pinned dependency file, the same entry point, every module listed
for the package, and shell scripts that parse."""
from __future__ import annotations

import glob
import os
import re
import subprocess
import sys

import pytest
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def test_pyproject_lists_every_top_level_module_and_the_entry_points():
    meta = tomllib.loads(_read("pyproject.toml"))
    modules = set(meta["tool"]["setuptools"]["py-modules"])
    on_disk = {os.path.basename(p)[:-3] for p in glob.glob(os.path.join(ROOT, "*.py"))}
    assert modules == on_disk, {"missing from pyproject": sorted(on_disk - modules), "not on disk": sorted(modules - on_disk)}
    scripts = meta["project"]["scripts"]
    assert scripts["dlp-check"] == "dlp_api_server:main" and scripts["dlp-check-assess"] == "dlp_assessment_full_auto:main"
    import dlp_api_server, dlp_assessment_full_auto, continuous_eval
    assert callable(dlp_api_server.main) and callable(dlp_assessment_full_auto.main) and callable(continuous_eval.main)
    assert meta["project"]["requires-python"] == ">=3.11"


def test_pyproject_dependencies_match_requirements_txt():
    meta = tomllib.loads(_read("pyproject.toml"))
    wanted = {re.split(r"[<>=!~]", d)[0].strip().lower() for d in meta["project"]["dependencies"]}
    listed = {re.split(r"[<>=!~]", l)[0].strip().lower() for l in _read("requirements.txt").splitlines() if l.strip() and not l.startswith("#")}
    assert wanted == listed, {"only in pyproject": sorted(wanted - listed), "only in requirements.txt": sorted(listed - wanted)}


def test_installer_and_container_install_the_same_pinned_file_and_run_the_same_entry_point():
    dockerfile = _read("Dockerfile")
    assert "requirements.lock" in dockerfile and "--require-hashes" in dockerfile
    assert 'CMD ["python", "dlp_api_server.py"]' in dockerfile
    assert "requirements.lock" in _read("install.sh") and "--require-hashes" in _read("install.sh")
    assert "requirements.lock" in _read("INSTALL_Zscaler_Assessment.bat") and "--require-hashes" in _read("INSTALL_Zscaler_Assessment.bat")
    assert "dlp_api_server.py" in _read("start.sh") and "dlp_api_server.py" in _read("START_Zscaler_Assessment.bat")
    compose = _read("docker-compose.yml")
    assert "context: ." in compose and '"${DLP_CHECK_HOST_BIND:-127.0.0.1}:${DLP_CHECK_HOST_PORT:-8001}:8000"' in compose and "read_only: true" in compose


def test_shell_scripts_parse_and_are_executable():
    for name in ("install.sh", "start.sh", "stop.sh"):
        path = os.path.join(ROOT, name)
        r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        assert r.returncode == 0, (name, r.stderr)
        assert os.access(path, os.X_OK) or sys.platform.startswith("win"), f"{name} is not executable (chmod +x)"


def test_secret_and_state_files_never_reach_the_image_or_the_repository():
    dockerignore = _read(".dockerignore").split()
    gitignore = _read(".gitignore")
    for name in ("tenant_config.json", "tenant_profiles.json", "deployments.json", "ui_token.txt", ".env"):
        assert name in dockerignore, f"{name} would be copied into the image"
    for name in ("tenant_config.json", "tenant_profiles.json", "local_settings.env", "*.log", ".venv/"):
        assert name in gitignore, f"{name} is not git-ignored"
    assert os.path.exists(os.path.join(ROOT, "local_settings.env.example"))


def test_the_container_build_trusts_a_corporate_root_certificate_from_certs():
    # TLS inspection re-signs pypi.org: the build must accept the company's
    # root certificate before pip runs, and the app must use it too.
    df = _read("Dockerfile")
    assert df.index("COPY certs/") < df.index("pip install --require-hashes"), "certificates go in before pip runs"
    assert "update-ca-certificates" in df and "BEGIN CERTIFICATE" in df
    for var in ("PIP_CERT", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        assert f"{var}=/etc/ssl/certs/ca-certificates.crt" in df, var
    assert os.path.exists(os.path.join(ROOT, "certs", "README.md")), "COPY certs/ needs the folder in every checkout"
    assert "certs" not in _read(".dockerignore").split()
    gi = _read(".gitignore")
    assert "certs/*.crt" in gi and "certs/*.pem" in gi and "certs/*.cer" in gi, "organisation certificates stay local"
    guide = _read("INSTALL.md")
    assert 'Zscaler Root CA' in guide and "certs\\zscaler-root.crt" in guide and "extra root certificates added" in guide


def test_the_container_is_updated_from_the_docker_host_with_a_schedulable_script():
    # "The container needs an auto update": it has no git and a read-only
    # filesystem, so the computer that runs Docker pulls and rebuilds it.
    sh, ps = _read("update_container.sh"), _read("update_container.ps1")
    import subprocess
    assert subprocess.run(["bash", "-n", os.path.join(ROOT, "update_container.sh")]).returncode == 0
    assert os.access(os.path.join(ROOT, "update_container.sh"), os.X_OK) or sys.platform.startswith("win")
    for src in (sh, ps):
        assert "git pull --ff-only" in src and "docker compose up -d --build" in src
        assert "DLP_CHECK_BUILD_COMMIT" in src and "Up to date" in src, "rebuilds only when GitHub is ahead"
        assert "git status --porcelain --untracked-files=no" in src, "never overwrites hand edits"
    assert "--schedule" in sh and "crontab" in sh and "--unschedule" in sh
    assert "Register-ScheduledTask" in ps and "-Daily" in ps and "Unregister-ScheduledTask" in ps
    df, dc = _read("Dockerfile"), _read("docker-compose.yml")
    assert "ARG DLP_CHECK_BUILD_COMMIT" in df and 'DLP_CHECK_BUILD_COMMIT: "${DLP_CHECK_BUILD_COMMIT:-unknown}"' in dc


def test_update_app_in_a_container_explains_the_host_update_instead_of_the_zip_message(monkeypatch):
    import app_update
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.setenv("DLP_CHECK_BUILD_COMMIT", "abc1234")
    monkeypatch.setenv("DLP_CHECK_BUILD_BRANCH", "main")
    st = app_update.status(ROOT, remote_sha="def5678")
    assert st["in_container"] and st["local_commit"] == "abc1234" and st["update_available"] is True and not st["can_update"]
    assert "update_container.ps1" in st["reason"] and "update_container.sh" in st["reason"]
    assert app_update.status(ROOT, remote_sha="abc1234ffff")["update_available"] is False
    c = TestClient(srv.app)
    h = c.get("/api/health").json()
    assert h["in_container"] is True
    r = c.post("/api/app/update", json={})
    assert r.status_code in (403, 409)
    page = _read(os.path.join("static", "guide.js"))
    assert "GD.about.in_container" in page and "_gdContainerUpdateHelp" in page and "update_container.ps1" in page


def test_an_update_beacon_checks_github_in_the_background_and_shows_a_notice():
    import dlp_api_server as srv
    assert ("update_beacon.js", "script") in srv.GUI_ADDONS, "injected into every served page"
    js = _read(os.path.join("static", "update_beacon.js"))
    assert "/api/app/update/status" in js and "setInterval(check" in js and "setTimeout(check" in js
    assert "update_available" in js and "localStorage" in js and "Later" in js, "dismiss hides that build only"
    assert "update_container.ps1" in js and "role', 'status'" in js


def test_the_container_asks_the_github_api_with_an_optional_token_and_never_leaks_it(monkeypatch):
    import app_update

    class Resp:
        def __init__(self, code, body=None):
            self.status_code, self._body = code, body or {}

        def json(self):
            return self._body

    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen["url"], seen["auth"] = url, (headers or {}).get("Authorization")
        return Resp(200, {"sha": "abcdef1234567"}) if seen["auth"] else Resp(404)

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.delenv("DLP_CHECK_GITHUB_TOKEN", raising=False)
    sha, err = app_update.github_branch_head("main")
    assert sha is None and "DLP_CHECK_GITHUB_TOKEN" in err and "private" in err
    assert seen["url"] == "https://api.github.com/repos/berserkerjay/DLP-Check/commits/main"
    monkeypatch.setenv("DLP_CHECK_GITHUB_TOKEN", "ghp_secret_value")
    sha, err = app_update.github_branch_head("main")
    assert sha == "abcdef1" and err is None and seen["auth"] == "Bearer ghp_secret_value"

    def boom(url, headers=None, timeout=None):
        raise RuntimeError("proxy said no to ghp_secret_value")
    monkeypatch.setattr(requests, "get", boom)
    sha, err = app_update.github_branch_head("main")
    assert sha is None and "ghp_secret_value" not in err


def test_read_only_messages_say_how_to_turn_writes_on_where_the_app_runs(monkeypatch):
    # In the container the browser switch is refused (the server listens on
    # 0.0.0.0 inside it; that safeguard stays), and the message must name
    # the container's way in, not a Windows .bat file.
    import security
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.delenv("DLP_CHECK_HOST_BIND", raising=False)
    st = security.write_mode_status()
    assert st["can_toggle"] is False, "the in-browser switch stays off beyond loopback"
    assert ".env" in st["reason"] and "docker compose up -d" in st["reason"] and ".bat" not in st["reason"]
    assert ".env" in st["how_to_enable"]
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER")
    hint = security.write_enable_hint()
    assert ("START_Zscaler_Assessment_WRITES_ENABLED.bat" in hint) if os.name == "nt" else ("./start.sh" in hint)
    for name in ("dlp_api_server.py", "pack_deploy.py", "remediation.py", os.path.join("static", "deploy_studio.js")):
        assert "WRITES_ENABLED.bat" not in _read(name), f"{name} still hard-codes the Windows start script"


def test_the_container_offers_the_write_switch_only_when_published_on_loopback(monkeypatch):
    # Inside the container the server listens on 0.0.0.0; who can reach it
    # is decided by the host address docker-compose.yml publishes on, which
    # the same file passes in as DLP_CHECK_HOST_BIND.
    import security
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.setattr(security, "_write_override", None)
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "127.0.0.1")
    assert security.write_mode_status()["can_toggle"] is True
    with pytest.raises(ValueError, match="YES_I_UNDERSTAND"):
        security.set_write_mode(True, "yes")          # the typed phrase is still required
    assert security.set_write_mode(True, security.WRITE_CONFIRM_PHRASE)["enabled"] is True
    assert security.set_write_mode(False)["enabled"] is False
    for published in ("0.0.0.0", "192.168.1.20", ""):
        monkeypatch.setenv("DLP_CHECK_HOST_BIND", published)
        st = security.write_mode_status()
        assert st["can_toggle"] is False and ".env" in st["reason"], published
        with pytest.raises(ValueError):
            security.set_write_mode(True, security.WRITE_CONFIRM_PHRASE)
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "127.0.0.1")
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER")
    assert security.write_mode_status()["can_toggle"] is False, "outside the container the setting means nothing"
    compose = _read("docker-compose.yml")
    assert 'DLP_CHECK_HOST_BIND: "${DLP_CHECK_HOST_BIND:-127.0.0.1}"' in compose, "the app reads the same address ports: publishes on"


def test_the_container_update_scripts_take_a_branch_and_keep_it():
    # "The container should also have the option to update from dev, qa or
    # main": both scripts take the branch, switch the checkout to it (so
    # later runs and the schedule keep it) and refuse any other name.
    sh, ps = _read("update_container.sh"), _read("update_container.ps1")
    assert "--branch" in sh and 'main|qa|dev' in sh and "Unknown branch" in sh
    assert "[ValidateSet('main', 'qa', 'dev', 'DLP-CHECK-QA')][string]$Branch" in ps
    assert "$want" in ps, "PowerShell names are case-insensitive: the request is kept apart from the checked-out $branch"
    for src in (sh, ps):
        assert "git checkout --quiet" in src and "--track" in src and "DLP-CHECK-QA" in src
        assert "later runs and the schedule update from" in src
    import app_update
    assert "--branch main|qa|dev" in app_update.CONTAINER_UPDATE_HELP and "-Branch main|qa|dev" in app_update.CONTAINER_UPDATE_HELP
    guide = _read(os.path.join("static", "guide.js"))
    i = guide.index("function _gdContainerUpdateHelp")
    helper = guide[i:guide.index("\nfunction ", i + 10)]
    assert "_gdUpdBranch()" in helper and "-Branch ${branch}" in helper and "--branch ${branch}" in helper, "the commands carry the Branch chosen"
    notice = _read(os.path.join("static", "update_beacon.js"))
    assert "-Branch ${esc(target)}" in notice and "--branch ${esc(target)}" in notice
    assert "--branch qa" in _read("INSTALL.md") and "-Branch qa" in _read("INSTALL.md")


def test_the_shell_update_script_switches_branches_against_a_scratch_remote(tmp_path):
    import shutil
    bash = shutil.which("bash")
    if not bash or not shutil.which("git"):
        pytest.skip("bash and git are needed to run the script")

    def sh(*args, cwd, env=None):
        return subprocess.run([bash, "-c", " ".join(args)], cwd=cwd, env=env, capture_output=True, text=True)

    def git(*args, cwd):
        r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "core.autocrlf=false", *args],
                           cwd=cwd, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    origin, seed, deploy, fake = tmp_path / "origin.git", tmp_path / "seed", tmp_path / "deploy", tmp_path / "bin"
    git("init", "-q", "--bare", "-b", "main", str(origin), cwd=tmp_path)
    git("clone", "-q", str(origin), str(seed), cwd=tmp_path)
    shutil.copy(os.path.join(ROOT, "update_container.sh"), seed / "update_container.sh")
    (seed / "which.txt").write_text("main\n")
    git("add", ".", cwd=seed); git("commit", "-qm", "main", cwd=seed); git("push", "-q", "origin", "main", cwd=seed)
    for b in ("qa", "dev"):
        git("checkout", "-qb", b, cwd=seed)
        (seed / "which.txt").write_text(b + "\n")
        git("commit", "-qam", b, cwd=seed); git("push", "-q", "origin", b, cwd=seed)
        git("checkout", "-q", "main", cwd=seed)
    git("clone", "-q", str(origin), str(deploy), cwd=tmp_path)
    fake.mkdir()
    (fake / "docker").write_text('#!/bin/sh\necho "$*" >> "$(dirname "$0")/calls"\n[ "$1" = ps ] && echo dlp-check\nexit 0\n', newline="\n")
    os.chmod(fake / "docker", 0o755)
    # A bash-style PATH entry: on Windows a C:\ path's colon would split PATH.
    fake_dir = sh("cd", f"'{fake.as_posix()}'", "&&", "pwd", cwd=tmp_path).stdout.strip()

    def run(*args):
        r = sh(f"PATH='{fake_dir}':\"$PATH\"", "./update_container.sh", *args, cwd=deploy)
        branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=deploy)
        return r.returncode, r.stdout + r.stderr, branch, (deploy / "which.txt").read_text().strip()

    code, out, branch, which = run("--branch", "qa")
    assert code == 0 and branch == "qa" and which == "qa" and "Switched from main to qa" in out, out
    code, out, branch, _ = run()
    assert code == 0 and branch == "qa" and "Up to date: qa" in out, "the branch chosen is kept"
    code, out, branch, _ = run("--branch=dev")
    assert code == 0 and branch == "dev", out
    code, out, branch, _ = run("--branch", "DLP-CHECK-QA")
    assert code == 0 and branch == "qa", "the QA branch's old name maps to qa"
    code, out, branch, _ = run("--branch", "prod")
    assert code == 2 and branch == "qa" and "choose main, qa or dev" in out
    calls = (fake / "calls").read_text()
    assert calls.count("compose up -d --build") == 3, "every switch rebuilds; staying up to date does not"


def test_the_windows_update_script_survives_docker_progress_on_stderr():
    # docker compose writes its build progress to stderr; under Windows
    # PowerShell 5.1 with ErrorActionPreference Stop, the first such line
    # ended the script mid-build. The build is judged by docker's exit code.
    ps = _read("update_container.ps1")
    i = ps.index("docker compose up -d --build")
    before, after = ps[max(0, i - 400):i], ps[i:i + 400]
    assert "$ErrorActionPreference = 'Continue'" in before
    assert "$buildExit = $LASTEXITCODE" in after and "$ErrorActionPreference = 'Stop'" in after and "if ($buildExit -ne 0)" in after
