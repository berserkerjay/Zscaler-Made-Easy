"""The standalone (no-install) edition: standalone_main.py, the PyInstaller
build script, its smoke test and the release workflow.

The launcher must keep every secure default of the other editions
(loopback only, the UI token, read-only), put everything it writes in the
per-user data folder, never run code handed to it on the command line, and
never become a second server. The build must ship only tracked files, and
the release workflow must build, smoke-test, checksum and attest every
platform without committing a binary or granting more than it needs.
Everything here is offline: fakes, temporary folders and the committed
files; the one subprocess is the launcher run from source.
"""
from __future__ import annotations

import io
import json
import os
import re
import socket
import subprocess
import sys
import tarfile

import pytest
import yaml

import standalone_main as sm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import build_standalone as bs  # noqa: E402
import smoke_standalone as smoke  # noqa: E402

WORKFLOW = os.path.join(ROOT, ".github", "workflows", "release-standalone.yml")


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _workflow() -> dict:
    with open(WORKFLOW, encoding="utf-8") as f:
        wf = yaml.safe_load(f)
    if True in wf:
        wf["on"] = wf.pop(True)
    return wf


# ── The launcher's secure defaults ─────────────────────────────────────

@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.20", "localhost.attacker.example", ""])
def test_the_server_is_bound_to_loopback_whatever_the_environment_says(tmp_path, host):
    """ASVS V1.14.1 · CWE-1327 · A05:2021 · SSDF PW.9.1: the standalone edition listens on 127.0.0.1 only; ZSCALER_BIND_HOST cannot widen it."""
    # Arrange
    env = {"ZSCALER_BIND_HOST": host}
    # Act
    notes = sm.configure(env, str(tmp_path))
    # Assert
    assert env["ZSCALER_BIND_HOST"] == "127.0.0.1"
    assert bool(notes) is bool(host and host != "127.0.0.1")


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "OFF", " 0 "])
def test_the_ui_token_gate_cannot_be_switched_off(tmp_path, value):
    """ASVS V4.1.1 · CWE-306 · A07:2021: ZSCALER_UI_AUTH=0 (any spelling) is ignored; every caller needs the UI token."""
    env = {"ZSCALER_UI_AUTH": value}
    notes = sm.configure(env, str(tmp_path))
    assert env["ZSCALER_UI_AUTH"] == "1" and any("ZSCALER_UI_AUTH" in n for n in notes)


def test_a_settings_file_applies_but_cannot_loosen_the_fixed_defaults(tmp_path):
    """ASVS V14.1.3 · CWE-15 · SSDF PW.9.1: local_settings.env in the data folder sets the proxy, never the bind address or the token gate."""
    # Arrange
    (tmp_path / "local_settings.env").write_text(
        "# corporate proxy\nHTTPS_PROXY=http://proxy.corp:8080\nZSCALER_BIND_HOST=0.0.0.0\nZSCALER_UI_AUTH=0\n"
        "REQUESTS_CA_BUNDLE=\"/etc/corp root.pem\"\nnot a setting\n", encoding="utf-8")
    env = {"HTTPS_PROXY": "http://from-the-shell:3128"}
    # Act
    sm.configure(env, str(tmp_path))
    # Assert
    assert env["HTTPS_PROXY"] == "http://from-the-shell:3128", "a value already in the environment wins"
    assert env["REQUESTS_CA_BUNDLE"] == "/etc/corp root.pem"
    assert env["ZSCALER_BIND_HOST"] == "127.0.0.1" and env["ZSCALER_UI_AUTH"] == "1"


def test_the_launcher_starts_read_only_and_outside_container_mode(tmp_path, monkeypatch):
    """CWE-1188 · A05:2021 · SSDF PW.9.1: nothing the launcher sets turns writes on, and the container's exposure rules do not apply."""
    # Arrange
    import security
    env = {"DLP_CHECK_IN_CONTAINER": "1"}
    # Act
    sm.configure(env, str(tmp_path))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER", raising=False)
    # Assert
    assert "DLP_CHECK_IN_CONTAINER" not in env
    assert not any(k in env for k in ("ENABLE_WRITE_ACTIONS", "ZSCALER_WRITES"))
    assert security.writes_enabled() is False


# Every store the app writes, and the function that says where it is.
STORES = [
    ("audit", "path"), ("deployments", "store_path"), ("tenant_profiles", "store_path"), ("proposals", "store_path"),
    ("change_queue", "store_path"), ("workspace_notes", "store_path"), ("guidance", "state_path"),
    ("guidance", "config_path"), ("saas_matrix", "_local_path"), ("zia_rate", "state_path"),
    ("continuous_eval", "digest_dir"), ("beacon", "state_path"), ("self_heal", "state_path"),
    ("tenant_fingerprint", "key_path"), ("posture_plus", "settings_path"), ("ssl_coverage", "history_path"),
    ("pack_library", "user_packs_dir"),
]


@pytest.fixture
def standalone_env(tmp_path, monkeypatch):
    """The process environment as the launcher leaves it, with tmp_path as the data folder."""
    import conftest
    import zscaler_update_check
    data = tmp_path / "data"
    data.mkdir()
    for key in list(conftest.STORE_ENV) + list(sm.STORE_SETTINGS):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(zscaler_update_check, "data_dir", lambda: str(data))
    env: dict = {}
    sm.configure(env, str(data))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return data


@pytest.mark.parametrize("module, fn", STORES, ids=lambda v: v if isinstance(v, str) else None)
def test_every_store_is_written_to_the_per_user_data_folder(standalone_env, module, fn):
    """ASVS V12.4.1 · CWE-552 · CWE-379: tenant profiles, the audit log and every other store go to the owner-only data folder, never the unpacked app folder."""
    # Arrange
    import importlib
    mod = importlib.import_module(module)
    # Act
    where = os.path.realpath(getattr(mod, fn)())
    # Assert
    assert where.startswith(os.path.realpath(str(standalone_env)) + os.sep), f"{module}.{fn}() -> {where}"


def test_the_ui_token_file_goes_to_the_data_folder(standalone_env):
    """ASVS V8.3.4 · CWE-552 · CWE-276: the UI token file is written owner-only in the data folder, not beside the program."""
    import security
    path = security.write_ui_token_file(os.environ["DLP_CHECK_UI_TOKEN_DIR"])
    assert os.path.dirname(path) == str(standalone_env)
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o077 == 0


def test_every_store_the_container_moves_to_data_is_moved_by_the_launcher_too():
    """ASVS V12.4.1 · CWE-552 · SSDF PW.9.1: a store setting added to the container's /data list must also be set here (or the build writes into its bundle)."""
    # Arrange
    moved = set(re.findall(r"\b((?:DLP_CHECK|DLPCHECK)_[A-Z_]+)=/data\b", _read("Dockerfile")))
    # Act
    missing = moved - set(sm.STORE_SETTINGS) - {"DLP_CHECK_UI_TOKEN_DIR"}
    # Assert
    assert moved and missing == set()


# ── Port, build info, recursion guard, regex worker ────────────────────

@pytest.mark.parametrize("busy, start, tries, expected", [
    (set(), 8000, 100, 8000),
    ({8000}, 8000, 100, 8001),
    ({8000, 8001, 8002}, 8000, 100, 8003),
    (set(range(8000, 8100)), 8000, 100, None),     # every port tried is taken
    ({65535}, 65535, 100, None),                   # never past the last port
    (set(), 8443, 100, 8443),                      # ZSCALER_PORT moves the start
])
def test_the_first_free_port_from_the_start_is_used(busy, start, tries, expected):
    """CWE-400 · SSDF PW.9.1: a taken 8000 (another copy, another program) does not stop the start; the search is bounded."""
    seen = []

    def is_free(host, port):
        seen.append((host, port))
        return port not in busy

    assert sm.first_free_port(start, tries, is_free=is_free) == expected
    assert all(h == "127.0.0.1" for h, _ in seen) and len(seen) <= tries


def test_a_port_another_program_listens_on_is_not_free():
    """CWE-1327 · CWE-605: the free-port probe sees a real listener on loopback (SO_EXCLUSIVEADDRUSE on Windows)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        assert sm.port_is_free("127.0.0.1", s.getsockname()[1]) is False


@pytest.mark.parametrize("raw, start", [("", 8000), ("8443", 8443), ("0", 8000), ("70000", 8000), ("abc", 8000), ("-1", 8000)])
def test_zscaler_port_only_moves_the_start_to_a_valid_port(raw, start):
    """ASVS V5.1.3 · CWE-20: a malformed ZSCALER_PORT falls back to 8000."""
    assert sm.starting_port({"ZSCALER_PORT": raw}) == start


@pytest.mark.parametrize("content, commit", [
    ('{"commit": "abc123def456", "ref": "v3.1.0", "version": "v3.1.0"}', "abc123def456"),
    ("not json", None),
    ("[1, 2]", None),
    (None, None),
])
def test_the_build_commit_is_taken_from_the_bundle_when_it_is_well_formed(tmp_path, content, commit):
    """ASVS V5.1.4 · CWE-20: the build's own record names the commit /api/health reports; a missing or malformed one sets nothing."""
    if content is not None:
        (tmp_path / sm.BUILD_INFO_FILE).write_text(content, encoding="utf-8")
    env: dict = {}
    sm.apply_build_info(env, str(tmp_path))
    assert env.get("DLP_CHECK_BUILD_COMMIT") == commit


def test_a_process_started_by_a_running_server_never_becomes_a_second_server(monkeypatch):
    """CWE-674 · CWE-400: with the server mark set (a subprocess that reached sys.executable), the program refuses before it reads anything."""
    import zscaler_update_check
    monkeypatch.setattr(zscaler_update_check, "data_dir", lambda: pytest.fail("must not get this far"))
    assert sm.main([], env={sm.SERVER_MARK: "1"}) == 2


@pytest.mark.parametrize("argv", [["--port", "1"], ["dlp_api_server.py"], ["-c", "print(1)"], ["-I", "-c"]])
def test_unknown_arguments_are_refused(argv, monkeypatch):
    """ASVS V5.1.3 · CWE-88: the program takes no arguments it does not know (the updater's relaunch line included)."""
    import zscaler_update_check
    monkeypatch.setattr(zscaler_update_check, "data_dir", lambda: pytest.fail("must not get this far"))
    assert sm.main(argv, env={}) == 2


def test_code_on_the_command_line_is_refused_not_run(tmp_path):
    """ASVS V5.2.4 · CWE-94 · A03:2021: `-I -c <code>` runs only dlp_efficacy's own regex worker; any other code is never executed."""
    # Arrange
    canary = tmp_path / "ran"
    code = f"open({str(canary)!r}, 'w').write('x')"
    # Act
    rc = sm.main(["-I", "-c", code], env={})
    # Assert
    assert rc == 2 and not canary.exists()
    assert sm.is_regex_worker(["-I", "-c", code]) is False


@pytest.mark.parametrize("pattern, content", [("a+", "aa b aaa"), ("\\d{3}-\\d{2}-\\d{4}", "x 123-45-6789 y"), ("ABC", "abc Abc"), ("(", "x"), ("x", "")])
def test_the_regex_worker_answers_through_the_program_exactly_as_the_python_one(pattern, content):
    """ASVS V5.2.4 · CWE-1333 · CWE-400: frozen, sys.executable is this program; it answers dlp_efficacy's worker call with the same count or the same failure."""
    # Arrange
    import dlp_efficacy
    stdin = json.dumps([pattern, content])
    # Act
    ours = subprocess.run([sys.executable, os.path.join(ROOT, "standalone_main.py"), "-I", "-c", dlp_efficacy._REGEX_WORKER],
                          input=stdin, capture_output=True, text=True, timeout=30, cwd=ROOT)
    python = subprocess.run([sys.executable, "-I", "-c", dlp_efficacy._REGEX_WORKER], input=stdin, capture_output=True, text=True, timeout=30)
    # Assert
    assert (ours.returncode == 0, ours.stdout.strip()) == (python.returncode == 0, python.stdout.strip())


@pytest.mark.parametrize("frozen_build, longest", [(False, 0.75), (True, 2.75)])
def test_the_worker_timeout_allows_the_programs_start_up_only_when_frozen(monkeypatch, frozen_build, longest):
    """CWE-400 · CWE-1333: the standalone program's slower start does not turn every pattern into unknown; a source install keeps 0.75 s."""
    # Arrange
    import time
    import dlp_efficacy
    seen = {}
    monkeypatch.setattr(sys, "frozen", frozen_build, raising=False)
    monkeypatch.setattr(dlp_efficacy.subprocess, "run", lambda args, **kw: seen.update(kw) or type("R", (), {"returncode": 0, "stdout": "1"})())
    # Act
    dlp_efficacy._safe_regex_count("a", "a", time.monotonic() + 30)
    # Assert
    assert seen["timeout"] == pytest.approx(longest)


def test_the_programs_regex_worker_has_the_python_workers_limits_and_compiles_no_text():
    """ASVS V5.2.4 · CWE-94 · CWE-770: the same memory and CPU limits as dlp_efficacy's worker, and no eval/exec in the launcher."""
    import dlp_efficacy
    assert f"({sm.WORKER_MEMORY_BYTES // (1024 * 1024)} * 1024 * 1024, " in dlp_efficacy._REGEX_WORKER
    assert f"RLIMIT_CPU, ({sm.WORKER_CPU_SECONDS}, {sm.WORKER_CPU_SECONDS})" in dlp_efficacy._REGEX_WORKER
    assert not re.search(r"\b(eval|exec|compile)\(", _read("standalone_main.py"))


# ── The standalone edition does not update or restart itself ──────────

@pytest.fixture
def frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("DLP_CHECK_BUILD_COMMIT", "abc123def456")


def test_the_standalone_edition_never_updates_itself_in_place(frozen, tmp_path, monkeypatch):
    """SSDF PS.2.1 · CWE-494 · SLSA v1.0 Build L2: a new version is a new, attested download; the in-app updater runs no git and no pip here."""
    # Arrange
    import app_update as au
    monkeypatch.setattr(au, "_git", lambda *a, **k: pytest.fail("git must not run"))
    # Act
    st = au.status(str(tmp_path))
    res = au.update(str(tmp_path))
    # Assert
    assert st["standalone"] is True and st["can_update"] is False and st["local_commit"] == "abc123def456"
    assert st["reason"] == au.STANDALONE_UPDATE_HELP and "attestation" in st["reason"]
    assert res["ok"] is False and res["error"] == au.STANDALONE_UPDATE_HELP


def test_the_standalone_edition_does_not_relaunch_itself(frozen, tmp_path, monkeypatch):
    """CWE-674 · ASVS V1.14.1: Restart starts nothing (sys.executable is the program itself); the person is told to start it again."""
    import app_update as au
    monkeypatch.setattr(au.subprocess, "Popen", lambda *a, **k: pytest.fail("nothing may be spawned"))
    out = au.schedule_restart(str(tmp_path))
    assert out["scheduled"] is False and "start ZscalerMadeEasy again" in out["hint"]


def test_the_update_route_refuses_and_health_reports_the_build(frozen, monkeypatch):
    """ASVS V14.2.1 · CWE-494: POST /api/app/update is a 409 with the download instructions; /api/health names the commit the build was made from."""
    # Arrange
    from fastapi.testclient import TestClient
    import app_update as au
    import dlp_api_server as srv
    monkeypatch.setattr(au, "update", lambda *a, **k: pytest.fail("the updater must not run"))
    monkeypatch.setattr(srv, "_latest_remote_commit", lambda branch="main": None)
    c = TestClient(srv.app)
    # Act
    r = c.post("/api/app/update")
    h = c.get("/api/health").json()
    # Assert
    assert r.status_code == 409 and r.json()["detail"] == au.STANDALONE_UPDATE_HELP
    assert h["git_commit"] == "abc123def456"


def test_the_write_mode_hint_fits_the_standalone_edition(frozen):
    """CWE-1188 · ASVS V1.14.1: the hint names the in-app switch and the setting, not a start script the standalone edition does not have."""
    import security
    hint = security.write_enable_hint()
    assert "switch in the app" in hint and "start.sh" not in hint and ".bat" not in hint


# ── What the build ships ───────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "tenant_profiles.json", "sub/tenant_profiles.json", "tenant_config.json", "ui_token.txt", "local_settings.env",
    "local_settings.bat", "audit.log", "audit.log.1", "deployments.json", "proposals.json", "tenant_fingerprint.key",
    "certs/corp-root.pem", "certs/corp-root.crt", "signing.pfx", "signing.p12", ".env", "server.log", "zia_rate_state.json",
])
def test_the_build_refuses_to_ship_a_file_that_holds_secrets_or_local_state(path):
    """ASVS V14.1.1 · ASVS V8.3.4 · CWE-538 · CWE-312 · SSDF PS.1.1: a tracked secret or state file stops the build instead of reaching every download."""
    with pytest.raises(ValueError, match=re.escape(path)):
        bs.bundle_files(["dlp_api_server.py", path])


def test_the_bundle_is_the_tracked_tree_without_the_other_editions_launchers():
    """ASVS V14.1.1 · CWE-538 · SLSA v1.0 Build L2 · SSDF PS.1.1: the bundle carries the app's tracked files and its licences, nothing local."""
    # Arrange
    tracked = bs.tracked_files()
    # Act
    files = bs.bundle_files(tracked)
    # Assert
    assert set(files) <= set(tracked)
    for needed in ("dlp_api_server.py", "standalone_main.py", "static/index.html", "LICENSE", "THIRD_PARTY_NOTICES.md",
                   "zscaler_full_checks.py", "fed_policy_pack/pack.json", "requirements.lock"):
        assert needed in files, needed
    assert any(f.startswith("third_party_licenses/") for f in files)
    assert not [f for f in files if f.startswith(".agents/") or re.fullmatch(r"[^/]+\.(bat|vbs|sh|ps1)", f)]


def test_only_files_git_tracks_are_candidates(tmp_path):
    """CWE-538 · ASVS V14.1.1: an untracked tenant_profiles.json next to the code is not even listed."""
    # Arrange
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q")
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "tenant_profiles.json").write_text('{"secret": "fake-test-value"}')
    git("add", "app.py")
    # Act / Assert
    assert bs.tracked_files(str(tmp_path)) == ["app.py"]


def test_the_freeze_names_every_app_module_and_signs_only_when_asked(tmp_path):
    """SLSA v1.0 Build L2 · SSDF PW.6.2: modules loaded by path or imported lazily are frozen too; code signing needs an explicit identity."""
    # Arrange
    modules = bs.py_modules()
    # Act
    plain = bs.pyinstaller_args(["static/index.html"], modules, str(tmp_path), "d", "w")
    signed = bs.pyinstaller_args([], modules, str(tmp_path), "d", "w", "Developer ID Application: Example (TEAMID)", "e.plist")
    # Assert
    assert "standalone_main" in modules and plain[0].endswith("standalone_main.py")
    hidden = {plain[i + 1] for i, a in enumerate(plain) if a == "--hidden-import"}
    assert set(modules) <= hidden and {"--onedir", "--console"} <= set(plain)
    assert "--codesign-identity" not in plain
    assert signed[signed.index("--codesign-identity") + 1].startswith("Developer ID") and "--osx-entitlements-file" in signed


@pytest.mark.parametrize("system, machine, label", [
    ("Windows", "AMD64", "windows-x64"), ("Darwin", "arm64", "macos-arm64"), ("Darwin", "x86_64", "macos-x64"),
    ("Linux", "x86_64", "linux-x64"),
])
def test_the_four_release_platforms_are_named(system, machine, label):
    """SSDF PS.3.1: each archive says which system it is for."""
    assert bs.platform_label(system, machine) == label


@pytest.mark.parametrize("raw, ok", [("v3.1.0", "v3.1.0"), ("v3.1.0/../../x", "v3.1.0-..-..-x"), ("../", None), ("", None)])
def test_the_version_is_safe_in_a_file_name(raw, ok):
    """ASVS V12.3.1 · CWE-22: a tag name cannot steer the archive outside the output folder."""
    if ok is None:
        with pytest.raises(ValueError):
            bs.safe_version(raw)
    else:
        assert bs.safe_version(raw) == ok and "/" not in bs.safe_version(raw)


# ── The smoke test checks what ships ───────────────────────────────────

def test_the_smoke_test_reads_the_line_the_server_prints():
    """SSDF PW.8.2: the smoke test parses the server's own "Open …?token=" line, so a changed message fails here, not silently in CI."""
    assert 'print(f"  Open {open_url} in your browser\\n")' in _read("dlp_api_server.py")
    m = smoke.OPEN_LINE.search("  Open http://localhost:8001/?token=Ab_9-xYz0123456789abcdefgh in your browser")
    assert m and m.group(2) == "8001" and m.group(3) == "Ab_9-xYz0123456789abcdefgh"


def test_the_smoke_test_runs_with_the_loosening_settings_set_and_its_own_home(tmp_path):
    """SSDF PW.8.2 · CWE-1327 · CWE-306: the binary is started with ZSCALER_UI_AUTH=0 and ZSCALER_BIND_HOST=0.0.0.0 to prove it ignores both."""
    env, data = smoke.isolated_env(str(tmp_path))
    assert env["ZSCALER_UI_AUTH"] == "0" and env["ZSCALER_BIND_HOST"] == "0.0.0.0" and env["ZSCALER_OPEN_BROWSER"] == "0"
    assert data.startswith(str(tmp_path)) and not any(k.startswith("DLP_CHECK_") for k in env)


def _tar(path, members):
    with tarfile.open(path, "w:gz") as t:
        for name, body in members:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))


def test_the_smoke_test_refuses_an_archive_whose_checksum_does_not_match(tmp_path):
    """ASVS V10.3.2 · CWE-354 · SLSA v1.0 Build L2: the archive is checked against its .sha256 before it is unpacked."""
    archive = tmp_path / "ZscalerMadeEasy-v1-linux-x64.tar.gz"
    _tar(archive, [("ZscalerMadeEasy-v1-linux-x64/ZscalerMadeEasy", b"#!/bin/sh\n")])
    (tmp_path / (archive.name + ".sha256")).write_text("0" * 64 + "  " + archive.name + "\n")
    with pytest.raises(SystemExit, match="does not match"):
        smoke.unpack(str(archive), str(tmp_path / "out"))


def test_the_smoke_test_unpacks_without_path_traversal(tmp_path):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: an entry pointing outside the folder is refused (tar "data" filter)."""
    archive = tmp_path / "evil.tar.gz"
    _tar(archive, [("../escaped.txt", b"x")])
    (tmp_path / "out").mkdir()
    with pytest.raises(tarfile.TarError):
        smoke.unpack(str(archive), str(tmp_path / "out"))
    assert not (tmp_path / "escaped.txt").exists()


# ── The release workflow ───────────────────────────────────────────────

def test_the_release_workflow_runs_only_on_a_manual_run_or_a_version_tag():
    """Scorecard Dangerous-Workflow · SLSA v1.0 Build L2 · CWE-829: no pull request (which could reach the signing secrets) triggers a build."""
    on = _workflow()["on"]
    assert set(on) == {"workflow_dispatch", "push"}
    assert on["push"] == {"tags": ["v*"]}


def test_each_platform_builds_on_its_own_runner():
    """SLSA v1.0 Build L2 · SSDF PS.3.1: Windows x64, macOS arm64 and x64, and Linux x64 each build natively."""
    include = _workflow()["jobs"]["build"]["strategy"]["matrix"]["include"]
    assert {(i["os"], i["label"]) for i in include} == {
        ("windows-2025", "windows-x64"), ("macos-15", "macos-arm64"), ("macos-15-intel", "macos-x64"), ("ubuntu-22.04", "linux-x64")}


def test_every_build_is_smoke_tested_then_attested_then_uploaded():
    """SLSA v1.0 Build L2 (provenance) · SSDF PS.3.2 · Scorecard Signed-Releases: the shipped archive is started and asked before it is attested and uploaded."""
    # Arrange
    steps = _workflow()["jobs"]["build"]["steps"]
    names = [s.get("name") or s.get("uses") for s in steps]

    def at(pred):
        return next(i for i, s in enumerate(steps) if pred(s))
    # Act
    pkg = at(lambda s: s.get("id") == "package")
    smoke_step = at(lambda s: "tools/smoke_standalone.py" in (s.get("run") or ""))
    attest = at(lambda s: str(s.get("uses", "")).startswith("actions/attest-build-provenance@"))
    upload = at(lambda s: str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    # Assert
    assert pkg < smoke_step < attest < upload, names
    assert "ARCHIVE" in steps[smoke_step]["run"] and steps[smoke_step]["env"]["ARCHIVE"] == "${{ steps.package.outputs.archive }}"
    assert steps[attest]["with"]["subject-path"] == "${{ steps.package.outputs.archive }}"


def test_only_the_tag_release_job_can_write_and_it_verifies_before_it_publishes():
    """Scorecard Token-Permissions · SSDF PO.5.1 · CWE-250 · SLSA v1.0 Build L2: contents: write only on tags, after every checksum and attestation is verified."""
    # Arrange
    jobs = _workflow()["jobs"]
    rel = jobs["release"]
    run = "\n".join(s.get("run") or "" for s in rel["steps"])
    # Act / Assert
    assert jobs["build"]["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}
    assert rel["permissions"] == {"contents": "write", "attestations": "read"}
    assert rel["needs"] == "build" and "github.ref_type == 'tag'" in rel["if"]
    assert run.index("sha256sum --check") < run.index("gh attestation verify") < run.index("gh release create")
    assert "--signer-workflow" in run and "--verify-tag" in run


def test_signing_is_optional_gated_on_secrets_and_an_unsigned_build_says_so():
    """Scorecard Signed-Releases · SSDF PS.2.1 · CWE-345: signing runs only with its secrets; otherwise the README and the release notes say UNSIGNED."""
    # Arrange
    wf = _workflow()
    steps = wf["jobs"]["build"]["steps"]
    with_secrets = [s for s in steps if "secrets." in json.dumps(s.get("env") or {})]
    notes = next(s["run"] for s in wf["jobs"]["release"]["steps"] if "notes.md" in (s.get("run") or ""))
    # Act
    ungated = [s.get("name") for s in with_secrets
               if "env.HAS_" not in str(s.get("if") or "")
               and not all("env.HAS_" in v for v in (s.get("env") or {}).values() if "secrets." in v)]
    # Assert
    assert len(with_secrets) >= 4 and ungated == []
    assert all("secrets." not in (s.get("run") or "") for s in steps), "secrets reach scripts through env: only"
    assert "UNSIGNED" in notes
    assert "NOT code-signed" in bs.UNSIGNED_NOTE


def test_no_build_output_is_committed():
    """Scorecard Binary-Artifacts · SLSA v1.0 Source · SSDF PS.1.1: no program or archive is tracked, and the build folders are git-ignored."""
    tracked = bs.tracked_files()
    binaries = [f for f in tracked if re.search(r"\.(exe|dll|dylib|so|zip|tar\.gz|tgz|dmg|pkg|msi|whl|app)$", f, re.I)]
    assert binaries == []
    gi = _read(".gitignore").splitlines()
    assert "dist/" in gi and "build/" in gi
    run = "\n".join(s.get("run") or "" for j in _workflow()["jobs"].values() for s in j["steps"])
    assert "git push" not in run and "git commit" not in run

def test_provenance_is_gated_on_the_repository_and_fails_closed_when_on():
    """SLSA v1.0 Build L2 · SSDF PS.3.2 · CWE-345: provenance runs when the repository can have it and must then pass verification; off, the notes say there is none."""
    # Arrange
    wf = _workflow()
    build = wf["jobs"]["build"]["steps"]
    rel = wf["jobs"]["release"]["steps"]
    attest = next(s for s in build if str(s.get("uses", "")).startswith("actions/attest-build-provenance@"))
    verify = next(s for s in rel if "gh attestation verify" in (s.get("run") or ""))
    notes = next(s for s in rel if "notes.md" in (s.get("run") or "") and "echo" in (s.get("run") or ""))
    # Act / Assert: one switch, from the repository's visibility or an explicit variable
    gate = wf["env"]["PROVENANCE"]
    assert "github.event.repository.private" in gate and "vars.STANDALONE_PROVENANCE == 'true'" in gate
    assert attest["if"] == "env.PROVENANCE == 'true'"
    assert "continue-on-error" not in attest   # when on, a failed attestation stops the build
    run = verify["run"]
    assert run.index('if [ "$PROVENANCE" = "true" ]') < run.index("gh attestation verify")
    assert "set -euo pipefail" in run           # a failed verification stops the release
    assert "No build provenance" in notes["run"]
