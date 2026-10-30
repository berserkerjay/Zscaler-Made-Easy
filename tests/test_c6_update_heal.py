"""Cloud QA wave 6, area update-heal: app_update.py, self_heal.py,
zscaler_update_check.py, upstream_check.py and standalone_main.py.

Every test is offline: git runs against local bare repositories, and every
outbound HTTP answer comes from a fake (requests' adapter, a fake getter or
a fake fetch). No real tenant, no real GitHub, PyPI or registry.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile

import pytest
import requests
from requests.models import Response

import app_update as au
import continuous_eval
import self_heal as sh
import standalone_main as sm
import upstream_check as uc
import zscaler_update_check as zu
from test_app_update import _git, _push_v2, repos  # noqa: F401 - the bare-origin + installed-clone fixture
from test_self_heal import _dead_pid, env  # noqa: F401 - every store in a temporary folder

SECRET = "S3cret-proxy-pass-never-shown"


# ── app_update: the update never raises, and network failure is plain ────────

def _git_raising(on: str, exc: BaseException):
    real = au._git

    def fake(app_dir, *args, **kw):
        if args and args[0] == on:
            raise exc
        return real(app_dir, *args, **kw)
    return fake


def test_a_pull_that_times_out_is_reported_and_the_edits_are_put_back(repos, monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a git pull that times out is a plain error, never an exception; set-aside edits come back."""
    app = repos["app"]
    _push_v2(repos["work"])
    (app / "requirements.txt").write_text("requests>=2.28.0\n# local note\n")
    monkeypatch.setattr(au, "_git", _git_raising("pull", subprocess.TimeoutExpired(["git", "pull"], 60)))
    res = au.update(str(app), install_deps=False)
    assert res["ok"] is False and res["updated"] is False and "60 seconds" in res["error"]
    assert (app / "requirements.txt").read_text().endswith("# local note\n"), "the hand edit is re-applied"


def test_git_vanishing_mid_update_is_an_error_result_not_a_server_error(repos, monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: an OSError from git (it was uninstalled mid-update) returns ok False with plain words."""
    monkeypatch.setattr(au, "_git", _git_raising("fetch", FileNotFoundError("git")))
    res = au.update(str(repos["app"]), install_deps=False)
    assert res["ok"] is False and "stopped unexpectedly (FileNotFoundError)" in res["error"] and "git stash" in res["error"]
    assert "Traceback" not in json.dumps(res)


class _Resp:
    def __init__(self, status=200, body=None, bad_json=False):
        self.status_code, self._body, self._bad = status, body, bad_json

    def json(self):
        if self._bad:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self._body

    def raise_for_status(self):
        return None


@pytest.mark.parametrize("resp", [_Resp(bad_json=True), _Resp(body=[]), _Resp(body={"sha": 1234567}), _Resp(body={"sha": "../../x"})],
                         ids=["not-json", "a-list", "a-number", "not-hex"])
def test_github_branch_head_reads_a_bad_answer_as_no_commit(monkeypatch, resp):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: a GitHub answer that is not JSON, not an object or has no hex sha gives (None, reason)."""
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: resp)
    sha, err = au.github_branch_head("main")
    assert sha is None and "no commit" in err


def test_github_branch_head_sends_nothing_for_a_branch_off_the_allowlist(monkeypatch):
    """ASVS V5.1.3 · CWE-88 · CWE-918 · WSTG-INPV-19: a branch outside BRANCHES never reaches the URL; nothing is requested."""
    sent = []
    monkeypatch.setattr(requests, "get", lambda url, **kw: sent.append(url) or _Resp(body={"sha": "a" * 40}))
    sha, err = au.github_branch_head("../../../orgs/evil/repos")
    assert sha is None and "Unknown branch" in err and sent == []


def test_github_branch_head_maps_a_legacy_branch_name(monkeypatch):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the pre-rename branch name is asked for as its new name."""
    sent = []
    monkeypatch.setattr(requests, "get", lambda url, **kw: sent.append(url) or _Resp(body={"sha": "b" * 40}))
    assert au.github_branch_head("DLP-CHECK-QA") == ("bbbbbbb", None) and sent[0].endswith("/commits/qa")


def _upstream_origin(monkeypatch):
    monkeypatch.setattr(au, "_github_owner_repo", lambda app_dir: ("berserkerjay", "DLP-Check"))
    monkeypatch.delenv("DLP_CHECK_GITHUB_REPO", raising=False)


def test_verify_reads_a_non_string_sha_as_unchecked(monkeypatch, tmp_path):
    """ASVS V5.1.3 · CWE-755 · WSTG-ERRH-01: an API answer whose sha is not a string is 'not checked', never an exception."""
    _upstream_origin(monkeypatch)
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp(body={"sha": ["a"]}))
    out = au.verify_against_github_api(str(tmp_path), "main", "a" * 40)
    assert out == {"checked": False, "reason": "the GitHub API response had no commit sha"}


def test_verify_never_matches_an_empty_local_commit(monkeypatch, tmp_path):
    """ASVS V1.14.1 · CWE-345 · WSTG-BUSL-01: an unknown local commit is never 'verified' (fail closed)."""
    _upstream_origin(monkeypatch)
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp(body={"sha": "c" * 40}))
    out = au.verify_against_github_api(str(tmp_path), "main", "")
    assert out["checked"] is True and out["match"] is False


def test_verify_matches_a_short_local_sha_of_the_same_commit(monkeypatch, tmp_path):
    """ASVS V1.14.1 · CWE-345 · WSTG-BUSL-01: the same commit, short or full and in any case, matches."""
    _upstream_origin(monkeypatch)
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp(body={"sha": "D" * 40}))
    assert au.verify_against_github_api(str(tmp_path), "main", "ddddddd")["match"] is True


def test_a_fork_origin_is_never_reported_as_verified(monkeypatch, tmp_path):
    """ASVS V10.3.2 · CWE-494 · SLSA v1.0 Source: a fork on github.com cannot vouch for its own pull."""
    monkeypatch.setattr(au, "_github_owner_repo", lambda app_dir: ("someone", "DLP-Check"))
    monkeypatch.delenv("DLP_CHECK_GITHUB_REPO", raising=False)
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("a fork is not asked"))
    out = au.verify_against_github_api(str(tmp_path), "main", "a" * 40)
    assert out["checked"] is False and "fork" in out["reason"]


@pytest.mark.parametrize("branch", ["--upload-pack=touch /tmp/x", "-b", "main;id", "refs/heads/main", ""])
def test_update_refuses_a_branch_that_is_not_on_the_list_before_any_git(monkeypatch, tmp_path, branch):
    """ASVS V5.3.8 · CWE-88 · WSTG-INPV-12: a branch that looks like a git option is refused before git runs."""
    monkeypatch.setattr(au, "_git", lambda *a, **k: pytest.fail("git must not run"))
    monkeypatch.setattr(au, "in_container", lambda: False)
    if branch:
        res = au.update(str(tmp_path), install_deps=False, branch=branch)
        assert res["ok"] is False and "Unknown branch" in res["error"]
    else:
        with pytest.raises(ValueError):
            au.valid_branch(branch)


# ── app_update: local data and the restart ───────────────────────────────────

def _repo_with_start_script(tmp_path):
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    (repo / "START_Zscaler_Made_Easy.bat").write_text("@echo off\nset ZSCALER_PORT=8000\n")
    _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "v1")
    return repo


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_settings_moved_to_local_settings_are_owner_only(tmp_path):
    """ASVS V8.3.4 · CWE-276 · CWE-732 · WSTG-CONF-11: local_settings.bat (it can hold the client secret) is created 0600."""
    repo = _repo_with_start_script(tmp_path)
    (repo / "START_Zscaler_Made_Easy.bat").write_text(f"@echo off\nset ZSCALER_PORT=8000\nset ZSCALER_CLIENT_SECRET={SECRET}\n")
    old = os.umask(0o022)
    try:
        migrated, restored = au.migrate_settings(str(repo), ["START_Zscaler_Made_Easy.bat"])
    finally:
        os.umask(old)
    assert migrated == ["START_Zscaler_Made_Easy.bat: ZSCALER_CLIENT_SECRET"] and restored == ["START_Zscaler_Made_Easy.bat"]
    assert oct(os.stat(repo / "local_settings.bat").st_mode & 0o777) == oct(0o600)


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_an_existing_local_settings_file_is_narrowed_to_owner_only(tmp_path):
    """ASVS V8.3.4 · CWE-732 · WSTG-CONF-11: appending to a world-readable local_settings.bat narrows it to 0600, keeping its lines."""
    repo = _repo_with_start_script(tmp_path)
    ls = repo / "local_settings.bat"
    ls.write_text("@echo off\nset HTTPS_PROXY=http://proxy:8080\n")
    os.chmod(ls, 0o644)
    (repo / "START_Zscaler_Made_Easy.bat").write_text("@echo off\nset ZSCALER_PORT=8000\nset REQUESTS_CA_BUNDLE=C:\\ca.pem\n")
    au.migrate_settings(str(repo), ["START_Zscaler_Made_Easy.bat"])
    assert oct(os.stat(ls).st_mode & 0o777) == oct(0o600)
    text = ls.read_text()
    assert "HTTPS_PROXY=http://proxy:8080" in text and "REQUESTS_CA_BUNDLE=C:\\ca.pem" in text


@pytest.mark.skipif(os.name == "nt", reason="the POSIX relauncher")
def test_a_folder_name_cannot_change_what_the_relauncher_runs(tmp_path, monkeypatch):
    """ASVS V5.3.8 · CWE-78 · WSTG-INPV-12: a folder named a$(touch PWNED)"b is a path to sh, never script text."""
    monkeypatch.setattr(au.sys, "platform", "linux")
    app = tmp_path / 'a$(touch PWNED)"b`touch PWNED2`'
    app.mkdir()
    monkeypatch.setattr(au.sys, "executable", "true")   # a harmless program as the server
    cmd = au.restart_command(str(app))
    # Run it for real, without the wait.
    subprocess.run([c.replace("sleep 3", "sleep 0") for c in cmd], cwd=tmp_path, timeout=10, check=False)
    assert not (tmp_path / "PWNED").exists() and not (tmp_path / "PWNED2").exists()
    assert (app / "server.pid").read_text().strip().isdigit(), "the relauncher ran in the named folder"


@pytest.mark.parametrize("text,want", [("/a b/c", "/a b/c"), ('a"b', 'a\\"b'), ("$(x)", "\\$(x)"), ("`x`", "\\`x\\`"), ("a\\b", "a\\\\b"), ("", "")])
def test_sh_double_quote_escaping_oracle(text, want):
    """ASVS V5.3.8 · CWE-78 · WSTG-INPV-12: oracle table: exactly backslash, double quote, $ and ` are escaped."""
    assert au._sh_dq(text) == want


def _conflict_on(repo, tmp_path, name):
    """A stash pop that conflicted on `name`: the state a half-applied update leaves."""
    _git(tmp_path, "init", "-q", "-b", "main", str(repo))
    (repo / name).write_text("v1\n")
    _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "v1")
    (repo / name).write_text("mine\n")
    _git(repo, "stash", "-q")
    (repo / name).write_text("theirs\n")
    _git(repo, "commit", "-q", "-am", "v2")
    subprocess.run(["git", "stash", "pop"], cwd=repo, capture_output=True)


def test_a_conflicted_file_with_a_non_ascii_name_is_copied_aside_before_the_reset(tmp_path):
    """ASVS V12.3.1 · CWE-22 · CWE-404 · WSTG-BUSL-01: 'café.py' is listed unquoted, so the recovery backs it up before git reset."""
    repo = tmp_path / "repo"
    _conflict_on(repo, tmp_path, "café.py")
    assert au.unmerged_files(str(repo)) == ["café.py"]
    rec = au.recover_unmerged(str(repo))
    assert rec["ok"] and rec["files"] == ["café.py"]
    assert "mine" in open(os.path.join(rec["backup"], "café.py"), encoding="utf-8").read()
    assert au.unmerged_files(str(repo)) == []


def test_no_unmerged_files_means_nothing_to_recover(tmp_path):
    """ASVS V12.3.1 · CWE-754 · WSTG-BUSL-01: a clean tree is left as it is (no backup folder, no reset)."""
    repo = _repo_with_start_script(tmp_path)
    assert au.recover_unmerged(str(repo)) is None and not (repo / "updater_backup").exists()


def test_a_fresh_index_lock_is_left_for_the_git_that_holds_it(tmp_path, monkeypatch):
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-07: an index.lock younger than the stale limit is never removed."""
    repo = _repo_with_start_script(tmp_path)
    lock = repo / ".git" / "index.lock"
    lock.write_text("")
    note = au.clear_stale_index_lock(str(repo))
    assert lock.exists() and "another git operation" in note
    old = os.path.getmtime(lock) - au.INDEX_LOCK_STALE_S - 1
    os.utime(lock, (old, old))
    assert au.clear_stale_index_lock(str(repo)).startswith("removed") and not lock.exists()


def test_the_standalone_edition_never_updates_or_restarts_itself(monkeypatch, tmp_path):
    """ASVS V10.3.2 · CWE-494 · SLSA v1.0 Build L2: frozen, status says download a new release; restart spawns nothing."""
    monkeypatch.setattr(au.sys, "frozen", True, raising=False)
    monkeypatch.setattr(au.subprocess, "Popen", lambda *a, **k: pytest.fail("nothing is spawned"))
    st = au.status(str(tmp_path))
    assert st["standalone"] and not st["can_update"] and "Releases page" in st["reason"]
    assert au.schedule_restart(str(tmp_path))["scheduled"] is False


# ── zscaler_update_check: response caps and secrets in the diagnostics ──────

class _Adapter:
    """Stands in for the network: one answer for every request."""

    def __init__(self, body: bytes, headers=None, status=200, stream_body=True):
        self.body, self.headers, self.status, self.stream_body, self.sent = body, headers or {}, status, stream_body, []

    def send(self, adapter, request, stream=False, **kw):
        self.sent.append({"url": request.url, "stream": stream})
        r = Response()
        r.status_code, r.url, r.request = self.status, request.url, request
        r.headers.update(self.headers)
        if self.stream_body:
            r.raw = io.BytesIO(self.body)
        else:
            r._content = self.body
        return r


@pytest.fixture
def net(monkeypatch):
    for key in ("ZSCALER_UPDATE_VERIFY_TLS", "ZSCALER_UPDATE_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy",
                "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)

    def install(adapter):
        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", lambda self, request, **kw: adapter.send(self, request, **kw))
        return adapter
    return install


def test_an_answer_larger_than_the_cap_is_refused_not_read(net, monkeypatch):
    """ASVS V12.1.1 · CWE-400 · CWE-770 · WSTG-BUSL-05: a body past MAX_BODY_BYTES is refused with plain words."""
    monkeypatch.setattr(zu, "MAX_BODY_BYTES", 1024, raising=False)
    a = net(_Adapter(b"x" * 1025))
    body, status, err = zu._safe_get("https://help.zscaler.com/zia")
    assert body is None and "larger than" in err and a.sent[0]["stream"] is True


def test_an_answer_exactly_at_the_cap_is_read(net, monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: the boundary: exactly MAX_BODY_BYTES is read in full."""
    monkeypatch.setattr(zu, "MAX_BODY_BYTES", 1024)
    net(_Adapter(b"y" * 1024))
    assert zu._safe_get("https://help.zscaler.com/zia") == (b"y" * 1024, 200, "")


def test_a_declared_length_past_the_cap_is_refused_before_reading(net, monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: Content-Length past the cap is refused without reading the body."""
    monkeypatch.setattr(zu, "MAX_BODY_BYTES", 1024)

    class Endless(io.RawIOBase):
        def readinto(self, b):
            raise AssertionError("the body is not read")
    a = _Adapter(b"", headers={"Content-Length": str(10 ** 12)})
    net(a)
    a.body = b""
    orig = a.send

    def send(adapter, request, **kw):
        r = orig(adapter, request, **kw)
        r.raw = Endless()
        return r
    a.send = send
    body, _status, err = zu._safe_get("https://pypi.org/pypi/zscaler-sdk-python/json")
    assert body is None and "larger than" in err


def test_a_body_already_in_memory_is_measured_too(net, monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: a response with no raw stream is held to the same cap."""
    monkeypatch.setattr(zu, "MAX_BODY_BYTES", 10)
    net(_Adapter(b"z" * 11, stream_body=False))
    assert zu._safe_get("https://pypi.org/simple/")[0] is None


def test_the_network_diagnostics_never_show_a_proxy_password(monkeypatch, tmp_path):
    """ASVS V8.3.4 · CWE-200 · CWE-532 · WSTG-INFO-05: HTTPS_PROXY=http://alice:<secret>@proxy is shown without its password."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("HTTPS_PROXY", f"http://alice:{SECRET}@proxy.corp:8080")
    monkeypatch.setenv("http_proxy", f"http://bob:{SECRET}@proxy.corp:3128")
    monkeypatch.setenv("ZSCALER_UPDATE_PROXY", f"https://carol:{SECRET}@egress.corp")
    out = zu.check_for_updates(only=["no-such-source"])
    text = json.dumps(out)
    assert SECRET not in text and "alice" not in text
    assert out["network"]["HTTPS_PROXY"] == "http://[redacted]@proxy.corp:8080"
    assert out["network"]["ZSCALER_UPDATE_PROXY"] == "https://[redacted]@egress.corp"


@pytest.mark.parametrize("exc", [requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.SSLError, RuntimeError])
def test_an_error_naming_the_proxy_never_shows_its_password(monkeypatch, exc):
    """ASVS V7.1.1 · CWE-209 · CWE-532 · WSTG-ERRH-01: a requests error that quotes the proxy URL is returned without the password."""
    def boom(*a, **k):
        raise exc(f"Cannot connect to proxy http://alice:{SECRET}@proxy.corp:8080 (tunnel failed)")
    monkeypatch.setattr(requests, "get", boom)
    body, status, err = zu._safe_get("https://pypi.org/pypi/zscaler-sdk-python/json")
    assert body is None and status == 0 and SECRET not in err and "[redacted]@proxy.corp" in err


def test_redact_url_credentials_oracle():
    """ASVS V8.3.4 · CWE-200 · WSTG-INFO-05: oracle table: only the user-info part of a URL is replaced."""
    cases = {"http://u:p@h:1/x": "http://[redacted]@h:1/x", "https://h/x@y": "https://h/x@y", "no url": "no url",
             "socks5://u@h": "socks5://[redacted]@h", "": "", None: ""}
    assert {k: zu.redact_url_credentials(k) for k in cases} == cases


@pytest.mark.parametrize("cache", ["[1, 2]", '"text"', '{"sdk_python": "not an object"}', "{"])
def test_a_cache_file_that_is_not_the_apps_shape_starts_a_new_baseline(monkeypatch, tmp_path, cache):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: a damaged or foreign update cache never stops the check."""
    monkeypatch.setattr(zu, "_cache_path", lambda: str(tmp_path / "update_cache.json"))
    (tmp_path / "update_cache.json").write_text(cache)
    pypi = json.dumps({"info": {"version": "1.11.3", "summary": "SDK"}, "releases": {"1.11.3": [{"upload_time": "2026-01-01"}]}}).encode()
    monkeypatch.setattr(zu, "_safe_get", lambda url, verify_tls=None: (pypi, 200, ""))
    out = zu.check_for_updates(only=["sdk_python"])
    assert [r["status"] for r in out["results"]] == ["new"] and out["results"][0]["key"] == "sdk_python"
    assert json.load(open(tmp_path / "update_cache.json"))["sdk_python"]["version"] == "1.11.3"


@pytest.mark.parametrize("body", [b"[]", b'{"info": []}', b'{"info": {"version": 7}}', b'"x"'])
def test_a_pypi_answer_in_the_wrong_shape_is_a_plain_error(monkeypatch, body):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: PyPI JSON that is not a package description is status error, never a raise."""
    monkeypatch.setattr(zu, "_safe_get", lambda url, verify_tls=None: (body, 200, ""))
    res = zu._check_pypi(zu.SOURCES[0], {})
    assert res["status"] == "error" and "not a package description" in res["error"]


# ── upstream_check: what PyPI and the registry answer is untrusted ──────────

def _wheel(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def _getter(wheel: bytes, version="1.12.0", sha=None, index=None):
    calls = []
    meta = index if index is not None else json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": f"zscaler-{version}.whl",
                                                                  "url": "https://files.pythonhosted.org/w.whl",
                                                                  "digests": {"sha256": sha or hashlib.sha256(wheel).hexdigest()}}]}).encode()

    def get(url):
        calls.append(url)
        return (wheel, 200, "") if url.endswith(".whl") else (meta, 200, "")
    get.calls = calls
    return get


@pytest.mark.parametrize("version", ["../../../evil", "1.0/../../x", "/abs", "C:\\x", "1.0 0", "", None, "9" * 65])
def test_download_sdk_refuses_a_version_that_is_not_one(tmp_path, version):
    """ASVS V12.3.1 · CWE-22 · CWE-918 · WSTG-ATHZ-01: a version from PyPI's answer never becomes a path or a URL segment."""
    get = _getter(_wheel({"zscaler/__init__.py": "x"}))
    out, err = uc.download_sdk(version, str(tmp_path / "dest"), get=get)
    assert out is None and "not a release version" in err and get.calls == []
    assert not (tmp_path / "dest").exists() and not (tmp_path / "evil").exists()


def test_download_sdk_unpacks_a_wheel_whose_hash_matches(tmp_path):
    """ASVS V10.3.2 · CWE-494 · SLSA v1.0 · OpenSSF Scorecard Pinned-Dependencies: a matching SHA-256 is unpacked under dest/<version>."""
    get = _getter(_wheel({"zscaler/zia/activate.py": "x = 1\n"}))
    out, err = uc.download_sdk("1.12.0", str(tmp_path), get=get)
    assert err == "" and out == os.path.join(str(tmp_path), "1.12.0")
    assert open(os.path.join(out, "zscaler", "zia", "activate.py")).read() == "x = 1\n"


def test_download_sdk_never_unpacks_a_wheel_whose_hash_differs(tmp_path):
    """ASVS V10.3.2 · CWE-494 · CWE-345 · SLSA v1.0: a wheel that is not the one PyPI publishes is not unpacked."""
    get = _getter(_wheel({"zscaler/x.py": "x"}), sha="0" * 64)
    out, err = uc.download_sdk("1.12.0", str(tmp_path), get=get)
    assert out is None and "SHA-256 does not match" in err and os.listdir(tmp_path) == []


def test_download_sdk_refuses_a_wheel_that_unpacks_past_the_cap(tmp_path, monkeypatch):
    """ASVS V12.1.1 · CWE-409 · CWE-400 · WSTG-BUSL-09: a decompression bomb (even with a matching hash) is refused, nothing written."""
    monkeypatch.setattr(uc, "MAX_WHEEL_UNPACKED", 1000, raising=False)
    get = _getter(_wheel({"zscaler/big.py": "0" * 1001}))
    out, err = uc.download_sdk("1.12.0", str(tmp_path), get=get)
    assert out is None and "larger unpacked" in err and os.listdir(tmp_path) == []


def test_download_sdk_reads_a_damaged_wheel_as_an_error(tmp_path):
    """ASVS V5.1.3 · CWE-755 · WSTG-ERRH-01: bytes that are not a ZIP (hash matching) are an error result, not an exception."""
    get = _getter(b"not a zip at all")
    out, err = uc.download_sdk("1.12.0", str(tmp_path), get=get)
    assert out is None and "could not be unpacked (BadZipFile)" in err


@pytest.mark.parametrize("index", [b"[]", b'{"urls": "x"}', b'{"urls": ["x", 1]}', b"{" * 3])
def test_download_sdk_reads_an_index_in_the_wrong_shape_as_an_error(tmp_path, index):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: a release index that is not JSON or not an object never raises."""
    out, err = uc.download_sdk("1.12.0", str(tmp_path), get=_getter(b"", index=index))
    assert out is None and err


def test_pypi_releases_ignores_versions_that_are_not_versions():
    """ASVS V5.1.3 · CWE-22 · CWE-20 · WSTG-INPV-01: a release key like '99/../../x' is never picked as the latest."""
    rel = {"releases": {"99/../../x": [{"upload_time": "2030"}], "1.11.3": [{"upload_time": "2026"}], "2.0.0b1": [{}],
                        "3.0.0": "not a list", "4.0.0": []}}
    out, err = uc.pypi_releases(lambda url: (json.dumps(rel), ""))
    assert err == "" and out["latest"] == "1.11.3" and out["latest_prerelease"] == "2.0.0b1" and out["newest_on_index"] == "2.0.0b1"


@pytest.mark.parametrize("text", ["[]", '"x"', '{"releases": []}', "{" * 5000])
def test_pypi_releases_reads_the_wrong_shape_as_an_error(text):
    """ASVS V5.1.3 · CWE-20 · CWE-674 · WSTG-INPV-01: PyPI JSON of another shape (or nested too deep) gives (None, reason)."""
    out, err = uc.pypi_releases(lambda url: (text, ""))
    assert out is None and err


@pytest.mark.parametrize("text", ["[]", "1", "{" * 5000])
def test_registry_latest_reads_the_wrong_shape_as_an_error(text):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: a registry answer that is not an object gives (None, reason)."""
    out, err = uc.registry_latest(lambda url: (text, ""))
    assert out is None and err


def test_registry_latest_drops_a_version_that_is_not_one():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a 'version' that is not a version string is not reported as the latest."""
    out, err = uc.registry_latest(lambda url: (json.dumps({"version": {"x": 1}, "versions": "many"}), ""))
    assert err == "" and out == {"latest": None, "published": None, "versions": 0}


def test_the_online_run_works_from_faked_answers_and_downloads_through_the_allowlist(monkeypatch, tmp_path):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: an online run with every answer faked: each request goes to an allowlisted host."""
    installed = uc.installed_sdk_version()
    newer = "99.0.0"
    wheel = _wheel({f"zscaler/{rel}": "changed\n" for rel in uc.WATCHED_SDK_FILES})
    asked = []

    def safe_get(url, verify_tls=None):
        asked.append(url)
        assert zu._allowed_url(url)[1] == "", url
        if url.endswith(".whl"):
            return wheel, 200, ""
        return json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": "z.whl", "url": "https://files.pythonhosted.org/z.whl",
                                     "digests": {"sha256": hashlib.sha256(wheel).hexdigest()}}]}).encode(), 200, ""

    def fetch(url):
        assert zu._allowed_url(url)[1] == "", url
        if url.startswith("https://pypi.org/pypi/"):
            return json.dumps({"releases": {installed: [{"upload_time": "2026"}], newer: [{"upload_time": "2030"}]}}), ""
        if url.startswith("https://registry.terraform.io/"):
            return json.dumps({"version": "9.9.9", "published_at": "2030-01-01", "versions": ["9.9.9"]}), ""
        return None, "offline in tests"

    monkeypatch.setattr(zu, "_safe_get", safe_get)
    monkeypatch.setattr(uc, "provider_schema", lambda *a, **k: (None, "terraform is not installed"))
    rep = uc.run(offline=False, fetch=fetch, workdir=str(tmp_path))
    assert rep["sdk"]["latest_diff"]["version"] == newer and rep["sdk"]["latest_diff"]["changed"]
    assert any(f["level"] == "drift" and newer in f["text"] for f in rep["findings"])
    assert rep["terraform"]["registry"]["latest"] == "9.9.9" and rep["api_reference"]["reachable"] is False
    assert asked and os.path.isdir(tmp_path / newer)
    assert "Upstream contract check" in uc.to_markdown(rep)


# ── standalone_main: the settings file cannot break or loosen a start ───────

def test_a_settings_file_saved_with_a_bom_is_read(tmp_path):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: Notepad's UTF-8 BOM does not glue itself to the first key."""
    p = tmp_path / sm.SETTINGS_FILE
    p.write_bytes("\ufeffHTTPS_PROXY=http://proxy.corp:8080\nREQUESTS_CA_BUNDLE=/ca.pem\n".encode("utf-8"))
    env = {}
    assert sm.load_settings_file(str(p), env) == ["HTTPS_PROXY", "REQUESTS_CA_BUNDLE"]
    assert env["HTTPS_PROXY"] == "http://proxy.corp:8080"


def test_a_settings_file_that_is_not_text_does_not_stop_the_start(tmp_path):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a UTF-16 or binary local_settings.env is skipped, never a traceback at start."""
    p = tmp_path / sm.SETTINGS_FILE
    p.write_bytes("HTTPS_PROXY=http://p:1\n".encode("utf-16") + b"\xff\xfe\x80")
    env = {}
    assert sm.load_settings_file(str(p), env) == [] and env == {}
    notes = sm.configure(env, str(tmp_path))
    assert env["ZSCALER_BIND_HOST"] == sm.LOOPBACK and env["ZSCALER_UI_AUTH"] == "1" and notes == []


def test_a_settings_file_far_larger_than_any_is_not_read(tmp_path):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: past MAX_SETTINGS_BYTES the file is ignored (boundary: at the cap it is read)."""
    p = tmp_path / sm.SETTINGS_FILE
    line = "HTTPS_PROXY=http://p:1\n"
    cap = getattr(sm, "MAX_SETTINGS_BYTES", 256 * 1024)
    p.write_text(line + "#" * (cap - len(line)))
    assert sm.load_settings_file(str(p), {}) == ["HTTPS_PROXY"]
    p.write_text(line + "#" * (cap - len(line) + 1))
    assert sm.load_settings_file(str(p), {}) == []


def test_a_settings_file_cannot_loosen_the_standalone_defaults(tmp_path):
    """ASVS V14.1.3 · CWE-1188 · CWE-284 · WSTG-CONF-02: bind host, UI token gate, a pinned token and write mode in the file are all overridden."""
    (tmp_path / sm.SETTINGS_FILE).write_text("ZSCALER_BIND_HOST=0.0.0.0\nZSCALER_UI_AUTH=off\nZSCALER_UI_TOKEN=short\n"
                                             "ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND\nDLP_CHECK_IN_CONTAINER=1\n")
    env = {}
    notes = sm.configure(env, str(tmp_path))
    assert env["ZSCALER_BIND_HOST"] == "127.0.0.1" and env["ZSCALER_UI_AUTH"] == "1"
    assert not {"ZSCALER_UI_TOKEN", "ENABLE_WRITE_ACTIONS", "DLP_CHECK_IN_CONTAINER"} & set(env)
    assert len(notes) == 4 and "short" not in " ".join(notes)


@pytest.mark.parametrize("raw,want", [("8100", 8100), ("0", 8000), ("65536", 8000), ("-1", 8000), ("80x", 8000), ("", 8000), ("65535", 65535)])
def test_starting_port_oracle(raw, want):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ZSCALER_PORT outside 1-65535 or not a number falls back to 8000."""
    assert sm.starting_port({"ZSCALER_PORT": raw}) == want


def test_first_free_port_never_passes_65535():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: from 65530 with every port taken, nothing past 65535 is tried."""
    tried = []
    assert sm.first_free_port(65530, 100, is_free=lambda h, p: tried.append(p) and False) is None
    assert tried == list(range(65530, 65536))


@pytest.mark.parametrize("argv", [["-I", "-c", "import os"], ["-I", "-c"], ["-c", "print(1)"], ["--evil"]])
def test_the_program_never_runs_python_code_from_its_arguments(argv, capsys):
    """ASVS V5.2.4 · CWE-94 · WSTG-INPV-11: any -c text other than the regex worker, or an unknown option, is refused (exit 2)."""
    assert sm.main(argv, env={}) == 2


def test_a_second_server_is_never_started_from_inside_the_app(capsys):
    """ASVS V1.14.1 · CWE-400 · WSTG-BUSL-05: a process started with the server mark set refuses to become another server."""
    assert sm.main([], env={sm.SERVER_MARK: "1"}) == 2 and "Refused" in capsys.readouterr().err


@pytest.mark.parametrize("content", ["[1]", "{", '{"commit": 5}'])
def test_build_info_that_is_not_an_object_sets_nothing(tmp_path, content):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a malformed standalone_build.json leaves the build commit unset (or a plain string)."""
    (tmp_path / sm.BUILD_INFO_FILE).write_text(content)
    env = {}
    info = sm.apply_build_info(env, str(tmp_path))
    assert env.get("DLP_CHECK_BUILD_COMMIT") in (None, "5") and isinstance(info, dict)


# ── self_heal: locks, stores and the refused automatic apply ────────────────

@pytest.mark.skipif(os.name == "nt", reason="flock")
def test_a_run_that_took_the_lock_after_the_check_keeps_its_owner_note(env, monkeypatch):  # noqa: F811
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-07: clearing a stale owner note never erases the note of a run that took the lock meanwhile."""
    path = os.path.join(continuous_eval.digest_dir(), continuous_eval.LOCK_NAME)
    with open(path, "w") as f:
        f.write(f"{_dead_pid()} 0\n")       # a free lock with a stale owner note
    run = continuous_eval.run_lock()
    real = sh._flock_held

    def racing(p):
        free = real(p)
        run.__enter__()                       # a run takes the lock right after the check found it free
        return free
    monkeypatch.setattr(sh, "_flock_held", racing)
    try:
        sh.check_locks()
        assert open(path).read().startswith(f"{os.getpid()} "), "the live run's note is kept"
    finally:
        run.__exit__(None, None, None)


@pytest.mark.skipif(os.name == "nt", reason="flock")
def test_a_stale_owner_note_on_a_free_lock_is_cleared(env):  # noqa: F811
    """ASVS V11.1.6 · CWE-667 · WSTG-BUSL-07: a free run lock naming a dead process has its note cleared, the file kept."""
    path = os.path.join(continuous_eval.digest_dir(), continuous_eval.LOCK_NAME)
    with open(path, "w") as f:
        f.write(f"{_dead_pid()} 0\n")
    assert sh.check_locks()["status"] == sh.OK
    assert os.path.exists(path) and open(path).read() == ""


def test_moving_aside_never_overwrites_an_earlier_damaged_copy(env, monkeypatch):  # noqa: F811
    """ASVS V12.3.1 · CWE-404 · WSTG-BUSL-01: two damaged copies in the same second keep both (a -2 suffix), nothing deleted."""
    import datetime as dt

    class Frozen(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime(2026, 10, 29, 12, 0, 0, tzinfo=tz)
    monkeypatch.setattr(sh, "datetime", Frozen)
    p = env / "store.json"
    p.write_text("first")
    one = sh.move_aside(str(p))
    p.write_text("second")
    two = sh.move_aside(str(p))
    assert one.endswith(".corrupt-20261029-120000") and two.endswith(".corrupt-20261029-120000-2")
    assert open(one).read() == "first" and open(two).read() == "second"


def test_keep_last_good_never_raises_and_skips_a_missing_file(env):  # noqa: F811
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: no file to keep is None, never an exception (a store write never fails over its copy)."""
    assert sh.keep_last_good(str(env / "missing.json")) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_a_last_good_copy_is_owner_only(env):  # noqa: F811
    """ASVS V8.3.4 · CWE-276 · WSTG-CONF-11: the rolling last-good copy is written 0600 whatever the umask."""
    p = env / "self_heal.json"
    p.write_text('{"version": 1, "tenants": {}}')
    old = os.umask(0o000)
    try:
        assert sh.keep_last_good(str(p)) == "kept"
    finally:
        os.umask(old)
    assert oct(os.stat(str(p) + sh.LAST_GOOD).st_mode & 0o777) == oct(0o600)


@pytest.mark.parametrize("raw,want", [("", 10.0), ("0", 0.0), ("-5", 0.0), ("nan", 0.0), ("0.2", 1.0), ("99999", 1440.0), ("inf", 1440.0), ("x", 0.0), ("15", 15.0)])
def test_interval_minutes_oracle(monkeypatch, raw, want):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: oracle table for DLP_CHECK_SELF_HEAL_MINUTES (off, clamped to 1 minute - 1 day)."""
    monkeypatch.setenv(sh.MINUTES_ENV, raw)
    assert sh.interval_minutes() == want


@pytest.mark.parametrize("value", ["1", "true", "YES", "on", "0", ""])
def test_unattended_heal_is_refused_and_reads_nothing(monkeypatch, value):
    """ASVS V1.14.1 · CWE-841 · WSTG-BUSL-06: whatever DLP_CHECK_SELF_HEAL_AUTO_APPLY says, auto_apply refuses and never imports a client."""
    monkeypatch.setenv(sh.AUTO_APPLY_ENV, value)
    out = sh.auto_apply(object(), tenant="acme")
    assert out["ok"] is False and out["applied"] == 0 and out["status"] == "refused" and out["setting"]["enabled"] is False
    assert out["setting"]["requested"] is (value.lower() in ("1", "true", "yes", "on"))


@pytest.mark.parametrize("value,want", [("2026-01-01T00:00:00Z", 1767225600.0), ("2026-01-01T00:00:00+0000", 1767225600.0),
                                        ("2026-01-01T01:00:00+01:00", 1767225600.0), ("2026-01-01T00:00:00", 1767225600.0),
                                        ("", None), (None, None), ("garbage", None), ("2026-13-01", None)])
def test_ts_oracle(value, want):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: oracle table for the ISO time reader (zone forms, naive as UTC, junk as None)."""
    assert sh._ts(value) == want


# ── coverage of the remaining branches ──────────────────────────────────────

def test_a_github_error_never_echoes_the_token(monkeypatch):
    """ASVS V8.3.4 · CWE-532 · CWE-209 · WSTG-ERRH-01: a network error that quotes the Authorization header has the token replaced."""
    token = "github_pat_never_shown_123"
    monkeypatch.setenv("DLP_CHECK_GITHUB_TOKEN", token)

    def boom(url, headers=None, timeout=None):
        raise requests.exceptions.ConnectionError(f"failed with header Bearer {token}")
    monkeypatch.setattr(requests, "get", boom)
    sha, err = au.github_branch_head("main")
    assert sha is None and token not in err and "[token]" in err


@pytest.mark.parametrize("status,token,needle", [(403, "tok", "refused the token"), (404, "", "read-only GitHub token"), (500, "", "HTTP 500")])
def test_github_branch_head_status_oracle(monkeypatch, status, token, needle):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: oracle table for GitHub's answers: each is a plain reason, never a sha."""
    monkeypatch.setenv("DLP_CHECK_GITHUB_TOKEN", token)
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp(status=status, body={"sha": "a" * 40}))
    sha, err = au.github_branch_head("main")
    assert sha is None and needle in err


def test_a_repository_setting_that_is_not_owner_slash_name_is_refused(monkeypatch):
    """ASVS V5.1.3 · CWE-918 · WSTG-INPV-19: DLP_CHECK_GITHUB_REPO with a path or a host in it never reaches the URL."""
    monkeypatch.setenv("DLP_CHECK_GITHUB_REPO", "evil.example/../x/y")
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("nothing is requested"))
    assert au.github_branch_head("main") == (None, "DLP_CHECK_GITHUB_REPO must look like owner/repository")


def test_the_standalone_start_forces_loopback_and_hands_over_to_the_server(monkeypatch, tmp_path, capsys):
    """ASVS V14.1.3 · CWE-1188 · WSTG-CONF-02: a start from a hostile environment runs the server on 127.0.0.1 with the token gate on."""
    import dlp_api_server
    seen = {}
    monkeypatch.setattr(zu, "data_dir", lambda: str(tmp_path))
    monkeypatch.setattr(sm, "first_free_port", lambda start, *a, **k: seen.setdefault("start", start) and 8123)
    monkeypatch.setattr(dlp_api_server, "main", lambda argv: seen.setdefault("argv", argv) and 0 or 0)
    env = {"ZSCALER_BIND_HOST": "0.0.0.0", "ZSCALER_UI_AUTH": "0", "ENABLE_WRITE_ACTIONS": "YES_I_UNDERSTAND", "ZSCALER_PORT": "9000"}
    assert sm.main([], env=env) == 0
    assert seen == {"start": 9000, "argv": []}
    assert env["ZSCALER_BIND_HOST"] == "127.0.0.1" and env["ZSCALER_UI_AUTH"] == "1" and env["ZSCALER_PORT"] == "8123"
    assert "ENABLE_WRITE_ACTIONS" not in env and env[sm.SERVER_MARK] == "1" and env["DLP_CHECK_UI_TOKEN_DIR"] == str(tmp_path)
    assert "is ignored" in capsys.readouterr().out


def test_the_standalone_start_without_a_free_port_says_so(monkeypatch, tmp_path, capsys):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: every port taken is exit 2 with what to do, the server never started."""
    import dlp_api_server
    monkeypatch.setattr(zu, "data_dir", lambda: str(tmp_path))
    monkeypatch.setattr(sm, "first_free_port", lambda *a, **k: None)
    monkeypatch.setattr(dlp_api_server, "main", lambda argv: pytest.fail("the server must not start"))
    assert sm.main([], env={}) == 2 and "no free port" in capsys.readouterr().err


def test_the_version_option_reads_the_build_info(monkeypatch, tmp_path, capsys):
    """ASVS V14.2.1 · CWE-1104 · SLSA v1.0 Provenance: --version names the commit the bundle was built from."""
    (tmp_path / sm.BUILD_INFO_FILE).write_text(json.dumps({"commit": "abc1234", "ref": "main", "version": "6.0"}))
    monkeypatch.setattr(sm, "bundle_dir", lambda: str(tmp_path))
    assert sm.main(["--version"], env={}) == 0 and "6.0 (abc1234)" in capsys.readouterr().out


def test_a_linked_old_data_folder_is_not_followed(monkeypatch, tmp_path):
    """ASVS V12.3.1 · CWE-59 · WSTG-ATHZ-01: a symlink under the old folder name is never renamed into place."""
    target = tmp_path / "elsewhere"
    target.mkdir()
    monkeypatch.setattr(zu.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    os.symlink(target, tmp_path / zu.DATA_DIR_NAMES["other"][1])   # the folder's name before the rename
    d = zu.data_dir()
    assert d == str(tmp_path / "zscaler_made_easy") and os.path.islink(tmp_path / zu.DATA_DIR_NAMES["other"][1]) and not os.path.islink(d)


def test_reset_cache_removes_only_the_cache_file(monkeypatch, tmp_path):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: reset removes update_cache.json and nothing else; a second reset is still True."""
    monkeypatch.setattr(zu, "data_dir", lambda: str(tmp_path))
    (tmp_path / "update_cache.json").write_text("{}")
    (tmp_path / "beacon_state.json").write_text("{}")
    assert zu.reset_cache() is True and zu.reset_cache() is True
    assert os.listdir(tmp_path) == ["beacon_state.json"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_an_existing_world_readable_data_folder_is_narrowed_to_owner_only(monkeypatch, tmp_path):
    """ASVS V8.3.4 · CWE-276 · CWE-732 · WSTG-CONF-11: ~/.cache/zscaler_made_easy left 0755 by an older version becomes 0700."""
    monkeypatch.setattr(zu.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    d = tmp_path / "zscaler_made_easy"
    d.mkdir()
    os.chmod(d, 0o755)
    assert zu.data_dir() == str(d) and oct(os.stat(d).st_mode & 0o777) == oct(0o700)


@pytest.mark.parametrize("stream", ["stderr", "stdout"])
def test_a_git_error_quoting_a_credentialed_remote_never_shows_the_token(stream):
    """ASVS V8.3.4 · CWE-532 · CWE-209 · WSTG-ERRH-01: an older git's "unable to access 'https://bob:<token>@github.com/'" is redacted."""
    token = "ghp_never_shown_456"
    text = f"fatal: unable to access 'https://bob:{token}@github.com/berserkerjay/DLP-Check.git/': Could not resolve host: github.com"
    cp = subprocess.CompletedProcess(["git"], 128, *(("", text) if stream == "stderr" else (text, "")))
    msg = au._err(cp)
    assert token not in msg and "bob" not in msg and msg.startswith("fatal: unable to access 'https://[redacted]@github.com/")


def test_a_git_error_without_a_url_is_passed_on_as_it_is():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: the first fatal line is kept verbatim (and capped at 400 characters)."""
    cp = subprocess.CompletedProcess(["git"], 1, "hint: x\n", "warning: y\nfatal: Not possible to fast-forward, aborting.\n" + "z" * 500)
    assert au._err(cp) == "fatal: Not possible to fast-forward, aborting."
    assert au._err(subprocess.CompletedProcess(["git"], 1, "", ""), "git pull failed") == "git pull failed"
