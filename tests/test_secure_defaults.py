"""Secure-by-default behaviours: loopback binds, gated writes to the app
folder, temp report files removed after sending, no secrets echoed."""
from __future__ import annotations

import os
import re

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv


def test_mcp_server_binds_loopback_by_default():
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dlp_mcp_server.py"), encoding="utf-8").read()
    assert 'host="0.0.0.0"' not in src
    assert '"ZSCALER_MCP_BIND_HOST", "127.0.0.1"' in src


def test_mcp_server_imports_with_the_locked_mcp_and_takes_no_secret_from_the_llm(monkeypatch):
    import asyncio
    import dlp_mcp_server as mcp  # a hard import, so an mcp release that breaks the server fails the build
    tools = {t.name: t for t in asyncio.run(mcp.mcp.list_tools())}
    assert {"run_assessment", "run_section", "list_checks", "get_health"} <= set(tools)
    for t in tools.values():
        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
        props = set(schema.get("properties", {}))
        assert not props & {"client_id", "client_secret", "password", "api_key", "username"}, (t.name, props)
    for k in ("ZSCALER_AUTH_METHOD", "ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET", "ZSCALER_USERNAME", "ZSCALER_PASSWORD", "ZSCALER_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ZSCALER_VANITY_DOMAIN", "acme")
    h = mcp.get_health()
    assert h["credentials_configured"] is False and h["missing_environment_variables"] == ["ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET"]
    for k, v in (("ZSCALER_AUTH_METHOD", "legacy"), ("ZSCALER_USERNAME", "u"), ("ZSCALER_PASSWORD", "p"), ("ZSCALER_API_KEY", "k")):
        monkeypatch.setenv(k, v)
    h = mcp.get_health()
    assert h["credentials_configured"] is True and h["auth_method"] == "legacy", "a classic ZIA API sign-in in the environment counts"
    assert "p" not in h.values() and "k" not in h.values()


def test_pack_upload_is_refused_unless_bound_to_localhost(monkeypatch, tmp_path):
    monkeypatch.setattr(srv, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setattr(srv, "PACKS_ROOT", str(tmp_path))
    c = TestClient(srv.app)
    r = c.post("/api/dlp-packs/upload", json={"pack_name": "evil", "dictionaries": [], "engines": [], "policies": []})
    assert r.status_code == 403 and not os.path.exists(tmp_path / "evil")


def test_word_report_temp_file_is_removed_after_download(monkeypatch):
    removed = []
    real = srv._unlink_quietly

    def record(path):
        removed.append(path); real(path)

    monkeypatch.setattr(srv, "_unlink_quietly", record)
    c = TestClient(srv.app)
    checks = [{"id": "4.1", "section": "4 — SSL Policy", "label": "Decrypt", "status": "PASS", "detail": "ok"}]
    r = c.post("/api/report/docx", json={"checks": checks, "metadata": {"org": "Acme Bank/../x"}})
    assert r.status_code == 200, r.text[:200]
    assert re.search(r'filename="zscaler_Acme_Bank_x_\d{8}\.docx', r.headers["content-disposition"])
    assert len(r.content) > 1000
    # The FileResponse's background task unlinks the file once it has been sent.
    assert removed and not os.path.exists(removed[0])


def test_security_policy_is_documented():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sec = open(os.path.join(root, "SECURITY.md"), encoding="utf-8").read()
    assert "Reporting a vulnerability" in sec and "Known limitations" in sec
    assert "safe harbor" in sec.lower() and "authorizes good-faith" in sec.lower()
    assert "90 days" in sec and "7 days" in sec and "cwe" in sec.lower()
    readme = open(os.path.join(root, "README.md"), encoding="utf-8").read()
    assert "SECURITY.md" in readme and "read-only GET requests" not in readme


def test_vulnerability_classes_doc_covers_every_class():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    vc = open(os.path.join(root, "docs", "VULNERABILITY_CLASSES.md"), encoding="utf-8").read().lower()
    assert "memory-safe" in vc and "sql" in vc and "csp" in vc
    assert "pip-audit" in vc and "trivy" in vc and "hash" in vc


def test_license_and_readme_note_the_repo_is_private_and_not_for_redistribution():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lic = " ".join(open(os.path.join(root, "LICENSE"), encoding="utf-8").read().split())   # wrapped lines
    # The repository is private on GitHub; the LICENSE says so (not "public").
    assert "not for redistribution" in lic.lower() and "repository is private" in lic.lower()
    readme = open(os.path.join(root, "README.md"), encoding="utf-8").read()
    assert "not for redistribution" in readme.lower()


def test_require_safe_bind_allows_loopback_and_refuses_otherwise(monkeypatch):
    import security
    import sso as _sso
    monkeypatch.delenv("ZSCALER_ALLOW_NONLOCAL_BIND", raising=False)
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER", raising=False)
    monkeypatch.delenv("DLP_CHECK_HOST_BIND", raising=False)
    monkeypatch.setattr(security, "get_bind_host", lambda: "127.0.0.1")
    security.require_safe_bind()   # loopback: never refused, whatever else is set

    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: True)
    monkeypatch.setattr(_sso, "sso_enabled", lambda: False)
    with pytest.raises(RuntimeError, match="no identity-provider sign-in is configured"):
        security.require_safe_bind()

    # The operator's explicit override (they have their own authenticating proxy) starts it, with the UI token gate on.
    monkeypatch.setenv("ZSCALER_ALLOW_NONLOCAL_BIND", "YES_I_UNDERSTAND")
    security.require_safe_bind()

    # UI auth itself off, bound beyond loopback: always refused, the override no longer skips it.
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: False)
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()
    monkeypatch.delenv("ZSCALER_ALLOW_NONLOCAL_BIND", raising=False)
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()

    # SSO fully configured (and no override needed) also starts it.
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: True)
    monkeypatch.setattr(_sso, "sso_enabled", lambda: True)
    monkeypatch.setattr(_sso, "config_errors", lambda: [])
    security.require_safe_bind()


def test_in_the_container_the_host_publish_address_decides(monkeypatch):
    """Inside the container the server listens on 0.0.0.0; what matters is
    DLP_CHECK_HOST_BIND, the host address docker-compose.yml publishes on."""
    import security
    import sso as _sso
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.delenv("ZSCALER_ALLOW_NONLOCAL_BIND", raising=False)
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: True)
    monkeypatch.setattr(_sso, "sso_enabled", lambda: False)
    for published in ("", "127.0.0.1", "::1", "localhost"):   # unset is the compose default, 127.0.0.1
        monkeypatch.setenv("DLP_CHECK_HOST_BIND", published)
        security.require_safe_bind()
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "0.0.0.0")
    with pytest.raises(RuntimeError) as e:
        security.require_safe_bind()
    assert "ZSCALER_SSO_ENABLED=1" in str(e.value) and "DLP_CHECK_HOST_BIND=127.0.0.1" in str(e.value)
    # The old override is not an escape hatch in the container.
    monkeypatch.setenv("ZSCALER_ALLOW_NONLOCAL_BIND", "YES_I_UNDERSTAND")
    with pytest.raises(RuntimeError, match="DLP_CHECK_HOST_BIND"):
        security.require_safe_bind()
    # SSO fully configured: published beyond loopback starts.
    monkeypatch.setattr(_sso, "sso_enabled", lambda: True)
    monkeypatch.setattr(_sso, "config_errors", lambda: [])
    security.require_safe_bind()


def test_compose_and_the_manual_run_no_longer_set_the_nonlocal_override():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("docker-compose.yml", "Dockerfile", "INSTALL.md", os.path.join(".github", "workflows", "tests.yml")):
        assert "ZSCALER_ALLOW_NONLOCAL_BIND=YES" not in open(os.path.join(root, name), encoding="utf-8").read().replace(": ", "="), name
    assert "DLP_CHECK_IN_CONTAINER=1" in open(os.path.join(root, "Dockerfile"), encoding="utf-8").read()


def test_a_default_install_starts_accepts_the_ui_token_and_never_offers_sso(monkeypatch):
    """SSO is off by default: with no ZSCALER_SSO_* settings the server
    starts (loopback, or the container on its default loopback publish),
    the UI token works exactly as before and no sign-in is offered."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import security
    import sso as _sso
    for name in [k for k in os.environ if k.startswith("ZSCALER_SSO_")] + ["ZSCALER_BIND_HOST", "ZSCALER_ALLOW_NONLOCAL_BIND",
                                                                           "DLP_CHECK_IN_CONTAINER", "DLP_CHECK_HOST_BIND"]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "default-token-xyz")
    monkeypatch.setattr(security, "_ui_token", None)
    assert _sso.sso_enabled() is False
    _sso.require_configured()
    security.require_safe_bind()
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")          # the container as shipped: 0.0.0.0 inside, loopback publish
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    security.require_safe_bind()
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER")
    monkeypatch.delenv("ZSCALER_BIND_HOST")
    c = TestClient(srv.app)
    status = c.get("/api/auth/status").json()
    assert status == {"required": True, "unlocked": False, "token_file": "ui_token.txt", "sso": False}
    assert c.get("/api/health").json().get("sso_required") is None
    assert c.get("/api/auth/sso/login", follow_redirects=False).status_code == 404
    assert c.post("/api/auth/logout").status_code == 404
    assert c.get("/api/health", headers={"X-DLP-Check-Token": "default-token-xyz"}).status_code == 200
    assert c.post("/api/auth/unlock", json={"token": "default-token-xyz"}).status_code == 200
    assert c.get("/api/health").status_code == 200


def test_server_calls_require_safe_bind_at_startup():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "dlp_api_server.py"), encoding="utf-8").read()
    assert "_security.require_safe_bind()" in src
    assert src.index("_security.require_safe_bind()") > src.index("_sso.require_configured()")


def test_same_origin_requests_pass_on_any_port_cross_origin_is_refused(monkeypatch):
    """The CSRF check trusts the allowlist and the page the server itself
    served (Origin == scheme://Host), so a spare port or a machine name
    works; a page on another local port is still refused. (With the UI
    token gate on: with it off, only loopback Host names are served, the
    DNS-rebinding guard.)"""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    c = TestClient(srv.app, base_url="http://127.0.0.1:8013")
    ok = c.post("/api/auth/unlock", json={"token": "nope"}, headers={"Origin": "http://127.0.0.1:8013", "Host": "127.0.0.1:8013"})
    assert ok.status_code != 403, ok.text
    bad = c.post("/api/auth/unlock", json={"token": "nope"}, headers={"Origin": "http://127.0.0.1:9999", "Host": "127.0.0.1:8013"})
    assert bad.status_code == 403 and "Origin not allowed" in bad.text
    named = c.post("/api/auth/unlock", json={"token": "nope"}, headers={"Origin": "http://laptop-42:8000", "Host": "laptop-42:8000"})
    assert named.status_code != 403
