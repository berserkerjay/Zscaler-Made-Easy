"""Regression tests for the security review fixes: network exposure with the
UI token gate off, request-size limits on streamed bodies, no silent
plaintext secrets, audit-log hygiene, and immutable CI / image pins."""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys

import pytest

import audit
import security
import tenant_profiles as tp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


# ── 1. Network exposure with UI authentication disabled ────────────────

def test_the_container_refuses_to_start_with_the_ui_token_gate_off(monkeypatch):
    import sso as _sso
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "127.0.0.1")       # loopback publish: used to start regardless
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setattr(_sso, "sso_enabled", lambda: False)
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")                   # gate on: the shipped container starts
    security.require_safe_bind()


def test_ui_auth_off_starts_on_loopback_only(monkeypatch):
    import sso as _sso
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER", raising=False)
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setattr(security, "get_bind_host", lambda: "127.0.0.1")
    security.require_safe_bind()                                  # localhost-by-default keeps working
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()                              # outside the container: refused, as before
    monkeypatch.setattr(_sso, "sso_enabled", lambda: True)
    monkeypatch.setattr(_sso, "config_errors", lambda: [])
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()                              # even with SSO (the existing, stricter rule)
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()                              # and in the container: SSO never stands in for the gate


def _drive(app, scope_extra=None, chunks=(b"",), headers=None):
    """Run one HTTP request through an ASGI app; return (status, body bytes, bytes the inner app received)."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
             "path": "/api/x", "raw_path": b"/api/x", "query_string": b"", "root_path": "",
             "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
             "client": ("127.0.0.1", 5555), "server": ("127.0.0.1", 8000)}
    scope.update(scope_extra or {})
    pending = list(chunks)
    sent = []

    async def receive():
        if pending:
            body = pending.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def _inner_app(seen):
    async def app(scope, receive, send):
        more = True
        while more:
            m = await receive()
            seen.append(len(m.get("body", b"")))
            more = m.get("more_body", False)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    return app


def test_with_the_gate_off_a_request_on_a_network_address_is_refused(monkeypatch):
    # A server started some other way (uvicorn --host 0.0.0.0) skips the
    # startup check; the middleware still serves only loopback connections.
    import sso as _sso
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setattr(_sso, "sso_enabled", lambda: False)
    seen = []
    app = security.UIAuthMiddleware(_inner_app(seen))
    status, body = _drive(app, {"server": ("10.1.2.3", 8000), "client": ("10.9.9.9", 1)})
    assert status == 503 and b"ZSCALER_UI_AUTH=0" in body and seen == []
    assert _drive(app, {"server": ("127.0.0.1", 8000)})[0] == 200
    assert _drive(app, {"server": ("::1", 8000)})[0] == 200
    assert _drive(app, {"server": ("testserver", 80)})[0] == 200        # the test client
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")                            # gate on: the token decides, as before
    assert _drive(app, {"server": ("10.1.2.3", 8000)})[0] == 401


# ── 2. Request-size limits on streamed bodies ──────────────────────────

def test_a_chunked_body_over_the_cap_is_cut_off_before_the_app_holds_it():
    seen = []
    capped = security.BodySizeLimitMiddleware(audit.AuditMiddleware(_inner_app(seen)), max_bytes=1000)
    status, body = _drive(capped, chunks=[b"a" * 600, b"b" * 600, b"c" * 600])   # no Content-Length
    assert status == 413 and b"too large" in body
    assert sum(seen) == 0, "the audit layer buffered nothing past the cap, so the app never ran"


def test_a_declared_length_over_the_cap_is_refused_before_reading_and_logged(monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    seen = []
    capped = security.BodySizeLimitMiddleware(_inner_app(seen), max_bytes=1000)
    status, _ = _drive(capped, chunks=[b"x" * 10], headers={"Content-Length": "5000"})
    assert status == 413 and seen == []
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["event"] == "request_too_large" and entry["bytes"] == 5000 and entry["path"] == "/api/x"
    assert "x" * 10 not in log.read_text(), "the body is never logged"
    assert _drive(capped, headers={"Content-Length": "12abc"})[0] == 400


def test_bodies_within_the_cap_pass_through_unchanged():
    seen = []
    capped = security.BodySizeLimitMiddleware(_inner_app(seen), max_bytes=1000)
    status, body = _drive(capped, chunks=[b"a" * 400, b"b" * 400])
    assert status == 200 and body == b"ok" and sum(seen) == 800


def test_the_size_cap_is_the_outermost_layer_of_the_app():
    import dlp_api_server as srv
    assert srv.app.user_middleware[0].cls is security.BodySizeLimitMiddleware
    from fastapi.testclient import TestClient
    big = "x" * (security.get_max_body_bytes() + 10)
    r = TestClient(srv.app).post("/api/tenant/check", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


# ── 3. No silent plaintext fallback for remembered credentials ─────────

def test_a_keyring_that_fails_does_not_fall_back_to_plaintext(monkeypatch, tmp_path):
    class Broken:
        def set_password(self, *a):
            raise RuntimeError("no backend")

        def get_password(self, *a):
            return None

        def delete_password(self, *a):
            return None

    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE", raising=False)
    monkeypatch.setattr(tp, "_keyring", lambda: Broken())
    row = tp.upsert({"name": "Gamma", "vanity_domain": "gamma", "client_id": "abc123456789"},
                    client_secret="s3cret-value-xyz", password="pw-value-123", api_key="key-value-456", remember_secret=True)
    text = (tmp_path / "profiles.json").read_text()
    assert "s3cret-value-xyz" not in text and "pw-value-123" not in text and "key-value-456" not in text
    assert set(row["secret_not_remembered"]) == {"client_secret", "password", "api_key"} and row["has_secret"] is False
    assert "DLP_CHECK_SECRET_STORE=file" in row["secret_warning"]


def test_the_profile_api_says_when_a_secret_was_not_remembered(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE", raising=False)
    monkeypatch.setattr(tp, "_keyring", lambda: None)
    r = TestClient(srv.app).post("/api/tenant-profiles", json={"name": "Delta", "vanity_domain": "delta", "client_id": "abc123456789",
                                                               "client_secret": "AbCdEf0123456789xyz", "remember_secret": True})
    assert r.status_code == 200 and r.json()["has_secret"] is False and r.json()["secret_warning"]
    assert "AbCdEf0123456789xyz" not in (tmp_path / "profiles.json").read_text()
    assert "data.secret_warning" in _read("static", "guide.js"), "the page shows the warning instead of a success"


# ── 7. Audit logging never holds uploaded content ──────────────────────

def test_uploaded_content_is_omitted_from_the_audit_log_but_metadata_stays():
    body = {"files": [{"name": "ZSATray.log", "content": "user=jdoe ssn=123-45-6789 " * 50}],
            "corpus": "4111 1111 1111 1111", "export": {"name": "policy.xml", "content": "<policy/>"},
            "pack_ids": ["fed_policy_pack"], "client_secret": "s", "vanity_domain": "acme"}
    out = audit.redact(body)
    flat = json.dumps(out)
    assert "123-45-6789" not in flat and "4111" not in flat and "<policy/>" not in flat
    assert out["files"][0]["name"] == "ZSATray.log" and out["files"][0]["content"].startswith("[omitted:")
    assert out["pack_ids"] == ["fed_policy_pack"] and out["vanity_domain"] == "acme" and out["client_secret"] == "[redacted]"


# ── 4 / 5. CI tests the production dependency set; immutable pins ──────

def test_ci_installs_hash_pinned_test_tools_constrained_to_production():
    wf = _read(".github", "workflows", "tests.yml")
    assert "pip install --require-hashes --no-deps -r requirements.lock" in wf
    assert "pip install --require-hashes --no-deps -r requirements-dev.lock" in wf
    assert not re.search(r"pip install (pytest|httpx)", wf), "no test tool resolved at run time"
    assert "httpx2" not in wf
    prod = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", _read("requirements.lock"), re.M))
    dev_text = _read("requirements-dev.lock")
    dev = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", dev_text, re.M))
    assert {"pytest", "httpx"} <= set(dev)
    assert {k: (prod[k], v) for k, v in dev.items() if k in prod and prod[k] != v} == {}, "shared packages at the production versions"
    assert dev_text.count("--hash=sha256:") >= len(dev)
    assert "-c requirements.lock" in _read("Makefile"), "make lock-dev compiles the test tools against the production lock"


def test_every_action_and_scanner_image_is_pinned_immutably():
    for name in os.listdir(os.path.join(ROOT, ".github", "workflows")):
        text = _read(".github", "workflows", name)
        for use in re.findall(r"uses:\s*(\S+)", text):
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", use), f"{name}: {use} is not pinned to a commit SHA"
    wf = _read(".github", "workflows", "tests.yml")
    assert "trivy:latest" not in wf and re.search(r"aquasec/trivy:[\d.]+@sha256:[0-9a-f]{64}", wf)
    assert "ZSCALER_UI_AUTH=0 zscaler-made-easy:ci" not in wf, "the container smoke test keeps the token gate on"


def test_the_container_base_is_pinned_by_digest():
    df = _read("Dockerfile")
    assert re.search(r"^FROM python:3\.11-slim-trixie@sha256:[0-9a-f]{64} AS base$", df, re.M)
    assert "package-ecosystem: \"docker\"" in _read(".github", "dependabot.yml"), "the digest is refreshed by Dependabot"


# ── Further verified findings fixed in the same review ─────────────────

def test_dns_rebinding_with_the_gate_off_only_loopback_host_names_are_served(monkeypatch):
    import sso as _sso
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setattr(_sso, "sso_enabled", lambda: False)
    seen = []
    app = security.UIAuthMiddleware(_inner_app(seen))
    assert _drive(app, headers={"Host": "attacker.example:8000"})[0] == 403 and seen == []
    for ok in ("localhost:8000", "127.0.0.1:8000", "[::1]:8000", "localhost"):
        assert _drive(app, headers={"Host": ok})[0] == 200, ok


def test_unauthenticated_floods_are_rate_limited_before_the_token_check_writes_audit_lines(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    names = [m.cls.__name__ for m in srv.app.user_middleware]
    assert names.index("RateLimitMiddleware") < names.index("UIAuthMiddleware"), "throttled before authentication"
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    c = TestClient(srv.app)
    codes = [c.get("/api/health").status_code for _ in range(90)]
    assert 429 in codes, "a burst of unauthenticated calls is throttled"
    lines = (tmp_path / "audit.log").read_text().splitlines() if (tmp_path / "audit.log").exists() else []
    assert len(lines) < 90, "throttled calls do not each write an audit line"


def test_remediation_path_parameters_cannot_retarget_the_write():
    import remediation as r
    rec = next(x for x in r.REMEDIATIONS if x["endpoint"] == "/zia/{rule_type}/{rule_id}")
    errs = r._validate_criteria(rec, {"rule_type": "webDlpRules", "rule_id": "../../adminUsers/1", "description": "x"})
    assert any(e.startswith("rule_id:") for e in errs)
    assert not any(e.startswith("rule_id:") for e in r._validate_criteria(rec, {"rule_type": "webDlpRules", "rule_id": "12345", "description": "x"}))
    assert r._render_endpoint(rec["endpoint"], {"rule_type": "webDlpRules", "rule_id": "1/../2"}) == "/zia/webDlpRules/1%2F..%2F2"


def test_installs_never_fall_back_to_an_unhashed_requirements_txt():
    for name in ("install.sh", "INSTALL_Zscaler_Made_Easy.bat", "app_update.py"):
        text = _read(name)
        assert "-r requirements.txt" not in text and '-r "%INSTALL_DIR%\\requirements.txt"' not in text and '"-r", req]' not in text, name
        assert "requirements.lock is missing" in text, name
    assert "pip install --upgrade pip" not in _read("Dockerfile"), "no unhashed download inside the image build"


def test_local_secrets_and_logs_are_owner_only_and_customer_data_stays_out_of_the_image():
    assert "chmod 600 local_settings.env" in _read("install.sh")
    start = _read("start.sh")
    assert start.index("chmod 600 server.log") < start.index("dlp_api_server.py > server.log")
    ignored = set(_read(".dockerignore").split())
    for name in ("server.log", "proposals.json", "digests/", "guidance_state.json", "saas_apps.local.json", "tenant_profiles.json",
                 "deployments.json", "ui_token.txt", "local_settings.env"):
        assert name in ignored, name
    assert not any(n.startswith("certs/") for n in ignored), "corporate root certificates must still reach the build"
