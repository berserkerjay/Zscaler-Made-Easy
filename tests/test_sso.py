"""SSO (OpenID Connect, Authorization Code + PKCE): off by default —
nothing here runs and nothing about the existing UI-token gate changes.
Enabled but misconfigured refuses to start rather than silently falling
back to the static-token shortcuts. Enabled and configured is a real
round trip against a fake identity provider (a genuine RSA keypair, a
signed ID token, a JWKS) with the usual attacks tried and refused:
unknown state, wrong signing key, wrong audience, mismatched nonce."""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

import dlp_api_server as srv
import security
import sso

ISSUER = "https://idp.example.test/oauth2/default"
CLIENT_ID = "client-123"
CLIENT_SECRET = "s3cret"
REDIRECT_URL = "http://testserver/api/auth/sso/callback"


class _Idp:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwk.update(kid="k1", use="sig", alg="RS256")
        self.discovery_doc = {
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
        }

    def make_id_token(self, *, nonce, aud=CLIENT_ID, iss=ISSUER, kid="k1", sign_key=None, **extra):
        claims = {"iss": iss, "aud": aud, "sub": "user-1", "email": "person@example.com", "nonce": nonce}
        claims.update(extra)
        return jwt.encode(claims, sign_key or self.key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def idp():
    return _Idp()


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _env(monkeypatch):
    # SSO only means anything once the base UI-token gate is itself on
    # (conftest.py turns it off by default for the rest of the suite).
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "1")
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", ISSUER)
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("ZSCALER_SSO_REDIRECT_URL", REDIRECT_URL)
    sso._DISCOVERY_CACHE.clear()
    sso._JWKS_CACHE.clear()
    sso._PENDING_LOGINS.clear()


def _mock_http(monkeypatch, idp, *, token_response=None):
    def fake_get(url, timeout=None):
        if url.endswith("/.well-known/openid-configuration"):
            return _Resp(idp.discovery_doc)
        if url == idp.discovery_doc["jwks_uri"]:
            return _Resp({"keys": [idp.jwk]})
        raise AssertionError(f"unexpected GET {url}")

    def fake_post(url, data=None, timeout=None):
        assert url == idp.discovery_doc["token_endpoint"]
        assert data["code_verifier"]   # PKCE verifier is always sent
        return _Resp(token_response if token_response is not None else {"id_token": "not-a-real-token"})

    monkeypatch.setattr(sso.requests, "get", fake_get)
    monkeypatch.setattr(sso.requests, "post", fake_post)


def _login_url_parts(monkeypatch, idp):
    _mock_http(monkeypatch, idp)
    url = sso.start_login()
    q = parse_qs(urlparse(url).query)
    return url, q["state"][0], q["nonce"][0]


# ── Off by default, and fails closed when enabled but not configured ──

def test_sso_is_off_by_default():
    assert sso.sso_enabled() is False
    assert sso.config_errors() == []
    sso.require_configured()   # must not raise


def test_enabled_but_unconfigured_fails_closed(monkeypatch):
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "1")
    for name in sso.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    errors = sso.config_errors()
    assert len(errors) == len(sso.REQUIRED_ENV)
    with pytest.raises(RuntimeError, match="ZSCALER_SSO_ISSUER"):
        sso.require_configured()


def test_a_plain_http_issuer_is_refused_unless_loopback(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", "http://idp.example.test")
    assert any("https://" in e for e in sso.config_errors())
    with pytest.raises(RuntimeError, match="https"):
        sso.require_configured()
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", "http://127.0.0.1:9000/oidc")
    assert sso.config_errors() == []   # loopback is fine for local testing


# ── The OpenID Connect mechanics, directly ─────────────────────────────

def test_start_login_builds_a_pkce_authorization_url(monkeypatch, idp):
    _env(monkeypatch)
    url, state, nonce = _login_url_parts(monkeypatch, idp)
    assert url.startswith(idp.discovery_doc["authorization_endpoint"] + "?")
    assert "code_challenge=" in url and "code_challenge_method=S256" in url
    assert f"client_id={CLIENT_ID}" in url
    assert sso._PENDING_LOGINS[state]["nonce"] == nonce


def test_complete_login_verifies_a_real_id_token_and_consumes_the_state(monkeypatch, idp):
    _env(monkeypatch)
    _, state, nonce = _login_url_parts(monkeypatch, idp)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=nonce)})
    claims = sso.complete_login(state, "auth-code")
    assert claims["email"] == "person@example.com" and claims["sub"] == "user-1"
    assert state not in sso._PENDING_LOGINS   # a replay of the same state must fail
    with pytest.raises(RuntimeError, match="not recognised"):
        sso.complete_login(state, "auth-code")


def test_complete_login_rejects_unknown_state(monkeypatch, idp):
    _env(monkeypatch)
    _mock_http(monkeypatch, idp)
    with pytest.raises(RuntimeError, match="not recognised"):
        sso.complete_login("never-issued", "code")


def test_complete_login_rejects_a_token_signed_by_the_wrong_key(monkeypatch, idp):
    _env(monkeypatch)
    _, state, nonce = _login_url_parts(monkeypatch, idp)
    forged_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = idp.make_id_token(nonce=nonce, sign_key=forged_key)   # attacker's key, wearing the real kid
    _mock_http(monkeypatch, idp, token_response={"id_token": forged})
    with pytest.raises(Exception):
        sso.complete_login(state, "auth-code")


def test_complete_login_rejects_a_mismatched_nonce(monkeypatch, idp):
    _env(monkeypatch)
    _, state, _real_nonce = _login_url_parts(monkeypatch, idp)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce="a-different-nonce")})
    with pytest.raises(RuntimeError, match="nonce"):
        sso.complete_login(state, "auth-code")


def test_complete_login_rejects_the_wrong_audience(monkeypatch, idp):
    _env(monkeypatch)
    _, state, nonce = _login_url_parts(monkeypatch, idp)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=nonce, aud="someone-elses-client")})
    with pytest.raises(Exception):
        sso.complete_login(state, "auth-code")


def test_complete_login_rejects_the_wrong_issuer(monkeypatch, idp):
    _env(monkeypatch)
    _, state, nonce = _login_url_parts(monkeypatch, idp)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=nonce, iss="https://not-the-configured-issuer")})
    with pytest.raises(Exception):
        sso.complete_login(state, "auth-code")


# ── Wired into the app: the gate, the routes, the end-to-end login ────

def test_the_static_token_shortcuts_are_refused_once_sso_is_on(monkeypatch):
    _env(monkeypatch)
    c = TestClient(srv.app)
    r = c.get(f"/?token={security.ui_token()}", follow_redirects=False)
    assert r.status_code != 303   # the query-token shortcut no longer mints the cookie
    unlock = c.post("/api/auth/unlock", json={"token": security.ui_token()})
    assert unlock.status_code == 403


def test_a_gated_call_reports_sso_required(monkeypatch):
    _env(monkeypatch)
    c = TestClient(srv.app)
    r = c.get("/api/health")
    assert r.status_code == 401
    body = r.json()
    assert body["sso_required"] is True and body["sso_login_url"] == "/api/auth/sso/login"
    assert c.get("/api/auth/status").json()["sso"] is True


def test_login_route_redirects_to_the_identity_provider(monkeypatch, idp):
    _env(monkeypatch)
    _mock_http(monkeypatch, idp)
    c = TestClient(srv.app)
    r = c.get("/api/auth/sso/login", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(idp.discovery_doc["authorization_endpoint"])


def test_callback_completes_the_login_and_unlocks_the_session(monkeypatch, idp):
    _env(monkeypatch)
    _mock_http(monkeypatch, idp)
    c = TestClient(srv.app)
    login = c.get("/api/auth/sso/login", follow_redirects=False)
    q = parse_qs(urlparse(login.headers["location"]).query)
    state, nonce = q["state"][0], q["nonce"][0]
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=nonce)})
    r = c.get(f"/api/auth/sso/callback?code=abc&state={state}", follow_redirects=False)
    cookie = r.headers.get("set-cookie", "")
    assert r.status_code == 303 and security.SSO_SESSION_COOKIE in cookie and security.UI_TOKEN_COOKIE not in cookie
    assert security.ui_token() not in cookie, "the cookie carries a per-login session id, never the UI token"
    assert "HttpOnly" in cookie and "samesite=lax" in cookie.lower()
    assert c.get("/api/auth/status").json()["unlocked"] is True
    assert c.get("/api/health").status_code == 200


def test_callback_with_a_tampered_token_does_not_unlock(monkeypatch, idp):
    _env(monkeypatch)
    _mock_http(monkeypatch, idp)
    c = TestClient(srv.app)
    login = c.get("/api/auth/sso/login", follow_redirects=False)
    q = parse_qs(urlparse(login.headers["location"]).query)
    state, nonce = q["state"][0], q["nonce"][0]
    forged = idp.make_id_token(nonce=nonce, sign_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    _mock_http(monkeypatch, idp, token_response={"id_token": forged})
    r = c.get(f"/api/auth/sso/callback?code=abc&state={state}", follow_redirects=False)
    assert r.status_code == 401
    assert c.get("/api/auth/status").json()["unlocked"] is False


def test_callback_with_an_idp_error_is_html_escaped_not_executed(monkeypatch):
    _env(monkeypatch)
    c = TestClient(srv.app)
    r = c.get("/api/auth/sso/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert r.status_code == 401
    assert "<script>" not in r.text and "&lt;script&gt;" in r.text


def test_a_failed_sso_sign_in_is_audited(monkeypatch, idp, tmp_path):
    """The callback is a GET, which the audit middleware skips; a failed
    sign-in is still recorded, both an IdP error and a forged token."""
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    _env(monkeypatch)
    c = TestClient(srv.app)
    assert c.get("/api/auth/sso/callback?error=access_denied").status_code == 401
    _mock_http(monkeypatch, idp)
    login = c.get("/api/auth/sso/login", follow_redirects=False)
    q = parse_qs(urlparse(login.headers["location"]).query)
    forged = idp.make_id_token(nonce=q["nonce"][0], sign_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    _mock_http(monkeypatch, idp, token_response={"id_token": forged})
    assert c.get(f"/api/auth/sso/callback?code=abc&state={q['state'][0]}", follow_redirects=False).status_code == 401
    events = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()]
    failed = [e for e in events if e["event"] == "sso_login_failed"]
    assert len(failed) == 2 and all(e["path"] == "/api/auth/sso/callback" for e in failed), events
    assert not any(e["event"] == "sso_login" for e in events)


def test_sso_routes_404_when_sso_is_not_enabled():
    c = TestClient(srv.app)
    assert c.get("/api/auth/sso/login", follow_redirects=False).status_code == 404
    assert c.get("/api/auth/sso/callback?code=x&state=y", follow_redirects=False).status_code == 404


# ── Per-person sessions, sign-out, who did it, writers by group ──────

def _sign_in(monkeypatch, idp, c=None, **claims):
    """A full sign-in through the app against the fake identity provider; returns the client."""
    c = c or TestClient(srv.app)
    _mock_http(monkeypatch, idp)
    login = c.get("/api/auth/sso/login", follow_redirects=False)
    q = parse_qs(urlparse(login.headers["location"]).query)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=q["nonce"][0], **claims)})
    c.last_callback = c.get(f"/api/auth/sso/callback?code=abc&state={q['state'][0]}", follow_redirects=False)
    return c


def test_each_sign_in_gets_its_own_server_side_session(monkeypatch, idp):
    _env(monkeypatch)
    sso._SESSIONS.clear()
    a = _sign_in(monkeypatch, idp, email="a@example.com", sub="a", groups=["dlp-readers"])
    b = _sign_in(monkeypatch, idp, email="b@example.com", sub="b")
    sid_a, sid_b = a.cookies.get(security.SSO_SESSION_COOKIE), b.cookies.get(security.SSO_SESSION_COOKIE)
    assert sid_a and sid_b and sid_a != sid_b and security.ui_token() not in (sid_a, sid_b)
    s = sso._SESSIONS[sid_a]
    assert s["email"] == "a@example.com" and s["sub"] == "a" and s["groups"] == ["dlp-readers"]
    assert s["expires"] - s["created"] == 12 * 3600 and s["last_seen"] >= s["created"]
    assert sso._SESSIONS[sid_b]["groups"] == []          # no groups claim: none recorded
    assert a.get("/api/auth/status").json()["user"] == "a@example.com"
    assert b.get("/api/auth/status").json()["user"] == "b@example.com"


def test_the_static_ui_token_is_refused_in_every_form_under_sso(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    _env(monkeypatch)
    tok = security.ui_token()
    c = TestClient(srv.app)
    assert c.get("/api/health", headers={security.UI_TOKEN_HEADER: tok}).status_code == 401
    assert c.get("/api/health", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    c.cookies.set(security.UI_TOKEN_COOKIE, tok)
    assert c.get("/api/health").status_code == 401
    c.cookies.set(security.SSO_SESSION_COOKIE, tok)          # the token dressed up as a session id
    assert c.get("/api/health").status_code == 401
    fresh = TestClient(srv.app)
    r = fresh.get(f"/?token={tok}", follow_redirects=False)
    assert r.status_code != 303 and security.UI_TOKEN_COOKIE not in r.headers.get("set-cookie", "")
    assert fresh.post("/api/auth/unlock", json={"token": tok}).status_code == 403
    assert fresh.get("/api/auth/status").json()["unlocked"] is False
    assert tok not in (tmp_path / "audit.log").read_text(encoding="utf-8")


def test_sessions_end_after_the_idle_timeout_and_after_12_hours(monkeypatch, idp):
    _env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_IDLE_MINUTES", "5")
    c = _sign_in(monkeypatch, idp)
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    assert c.get("/api/health").status_code == 200
    sso._SESSIONS[sid]["last_seen"] -= 6 * 60               # idle for 6 minutes
    assert c.get("/api/health").status_code == 401 and sid not in sso._SESSIONS
    c = _sign_in(monkeypatch, idp)
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    sso._SESSIONS[sid]["expires"] -= 12 * 3600              # busy all day: still ends at 12 hours
    assert c.get("/api/health").status_code == 401
    monkeypatch.delenv("ZSCALER_SSO_IDLE_MINUTES")
    assert sso.idle_seconds() == 30 * 60


def test_sign_out_ends_the_session_clears_the_cookie_and_is_audited(monkeypatch, idp, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    _env(monkeypatch)
    c = _sign_in(monkeypatch, idp, email="leaver@example.com")
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    r = c.post("/api/auth/logout")
    assert r.status_code == 200 and r.json()["signed_out"] is True
    assert security.SSO_SESSION_COOKIE in r.headers["set-cookie"] and "max-age=0" in r.headers["set-cookie"].lower()
    assert sid not in sso._SESSIONS
    replay = TestClient(srv.app)
    replay.cookies.set(security.SSO_SESSION_COOKIE, sid)    # a copied cookie is dead too
    assert replay.get("/api/health").status_code == 401
    events = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()]
    out = [e for e in events if e["event"] == "sso_logout"]
    assert out and out[0]["actor"] == "leaver@example.com" and out[0]["ended"] is True
    assert any(e["event"] == "sso_login" and e["actor"] == "leaver@example.com" for e in events)
    assert sid not in log.read_text(encoding="utf-8")


def test_sso_does_not_print_or_write_the_ui_token(monkeypatch, tmp_path, capsys):
    _env(monkeypatch)
    monkeypatch.setenv("DLP_CHECK_UI_TOKEN_DIR", str(tmp_path))
    monkeypatch.setattr(srv, "_port_problem", lambda host, port: None)
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    assert srv.main([]) == 0
    out = capsys.readouterr().out
    assert security.ui_token() not in out and "?token=" not in out and "identity provider" in out
    assert not (tmp_path / security.UI_TOKEN_FILE).exists()


def test_every_audit_line_names_the_signed_in_person(monkeypatch, idp, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    _env(monkeypatch)
    c = _sign_in(monkeypatch, idp, email="auditor@example.com")
    c.post("/api/tenant/check", json={"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "x" * 20})
    events = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()]
    api = [e for e in events if e["event"] == "api"]
    assert api and all(e["actor"] == "auditor@example.com" for e in api)
    assert all("actor" in e for e in events)


def test_allowed_groups_refuse_and_audit_a_sign_in_from_outside_them(monkeypatch, idp, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    _env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_ALLOWED_GROUPS", "dlp-team, secops")
    out = _sign_in(monkeypatch, idp, email="stranger@example.com", groups=["marketing"])
    assert out.last_callback.status_code == 403 and "ZSCALER_SSO_ALLOWED_GROUPS" in out.last_callback.text
    assert not out.cookies.get(security.SSO_SESSION_COOKIE)
    none = _sign_in(monkeypatch, idp, email="nogroups@example.com")
    assert none.last_callback.status_code == 403 and "'groups' claim" in none.last_callback.text
    ok = _sign_in(monkeypatch, idp, email="member@example.com", groups=["SecOps"])
    assert ok.last_callback.status_code == 303 and ok.get("/api/health").status_code == 200
    events = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()]
    refused = [e for e in events if e["event"] == "sso_login_refused"]
    assert [e["actor"] for e in refused] == ["stranger@example.com", "nogroups@example.com"]


def test_the_groups_claim_name_is_configurable(monkeypatch, idp):
    _env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_GROUPS_CLAIM", "roles")
    monkeypatch.setenv("ZSCALER_SSO_ALLOWED_GROUPS", "dlp-team")
    c = _sign_in(monkeypatch, idp, roles=["dlp-team"])
    assert c.last_callback.status_code == 303
    assert sso._SESSIONS[c.cookies.get(security.SSO_SESSION_COOKIE)]["groups"] == ["dlp-team"]


WRITER_CALLS = [
    ("/api/write-mode", {"enable": True, "confirm": "YES_I_UNDERSTAND"}),
    ("/api/dlp-packs/apply", {"pack_ids": ["x"], "confirm": True}),
    ("/api/dlp-packs/apply/start", {"pack_ids": ["x"], "confirm": True}),
    ("/api/dlp-packs/removal/apply", {"pack_ids": ["x"], "confirm": True}),
    ("/api/dlp-packs/removal/apply/start", {"pack_ids": ["x"], "confirm": True}),
    ("/api/deployments/dep-1/undo", {"confirm": True}),
    ("/api/dlp-packs/x/import", {"confirm": True}),
    ("/api/proposals/acme/p1/apply", {"confirm": True}),
    ("/api/proposals/acme/p1/rollback", {"confirm": True}),
    ("/api/remediation/execute", {"check_id": "x", "dry_run": False}),
    ("/api/migrate/enable", {"dry_run": False}),
    ("/api/migrate/delete-all", {"dry_run": False}),
    ("/api/migrate/post", {"dry_run": False, "proposed_rules": [{"name": "r"}]}),
]


def test_only_listed_writers_may_change_the_tenant(monkeypatch, idp):
    _env(monkeypatch)
    monkeypatch.setattr(security, "_write_override", None)
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.setenv("ZSCALER_SSO_WRITERS", "dlp-admins, boss@example.com")
    reader = _sign_in(monkeypatch, idp, email="reader@example.com", groups=["dlp-readers"])
    for path, body in WRITER_CALLS:
        r = reader.post(path, json=body)
        assert r.status_code == 403 and "ZSCALER_SSO_WRITERS" in r.json()["detail"] and "reader@example.com" in r.json()["detail"], (path, r.text)
    assert reader.get("/api/health").status_code == 200                                  # still reads
    assert reader.post("/api/write-mode", json={"enable": False}).status_code == 200      # and may always switch writes off
    assert "ZSCALER_SSO_WRITERS" not in reader.post("/api/remediation/execute", json={"check_id": "x", "dry_run": True}).text   # previews
    assert reader.get("/api/auth/status").json()["may_write"] is False
    for writer in (_sign_in(monkeypatch, idp, email="someone@example.com", groups=["DLP-Admins"]),
                   _sign_in(monkeypatch, idp, email="Boss@Example.com")):
        assert writer.get("/api/auth/status").json()["may_write"] is True
        for path, body in WRITER_CALLS:
            assert "ZSCALER_SSO_WRITERS" not in writer.post(path, json=body).text, path
    monkeypatch.setattr(security, "_write_override", None)


def test_without_writers_set_every_signed_in_person_may_write(monkeypatch, idp):
    _env(monkeypatch)
    monkeypatch.setattr(security, "_write_override", None)
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.delenv("ZSCALER_SSO_WRITERS", raising=False)
    c = _sign_in(monkeypatch, idp, email="anyone@example.com")
    for path, body in WRITER_CALLS:
        assert "ZSCALER_SSO_WRITERS" not in c.post(path, json=body).text, path
    monkeypatch.setattr(security, "_write_override", None)


def test_every_endpoint_that_writes_to_the_tenant_checks_the_writer_list():
    """Any handler with the write-mode gate, a dry_run switch or the write
    mode toggle calls security.require_writer() first, so a new writer
    cannot forget it."""
    import os
    import re
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dlp_api_server.py"), encoding="utf-8").read()
    handlers = re.split(r"\n@app\.", src)
    gated = [h for h in handlers if "if not writes_enabled():" in h or "req.dry_run)" in h or "req.dry_run, req.mode)" in h
             or "set_write_mode(req" in h or "_require_tenant_write(req" in h]
    assert len(gated) >= 13, len(gated)
    # The shared tenant-write gate checks the writer list first, before write mode.
    gate = src[src.index("def _require_tenant_write("):]
    gate = gate[:gate.index("\n\n\n")]
    assert gate.index("_security.require_writer()") < gate.index("if not writes_enabled():")
    for h in gated:
        head = h.split("\n", 1)[0]
        assert "_security.require_writer()" in h or "_require_tenant_write(req" in h, head
        if "if not writes_enabled():" in h and "_security.require_writer()" in h:
            assert h.index("_security.require_writer()") < h.index("if not writes_enabled():"), head


def test_proposal_decisions_record_the_signed_in_person_not_the_body(monkeypatch, idp, tmp_path):
    import proposals as pr
    from test_proposals import REPORT
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    _env(monkeypatch)
    pr.refresh_from_report(REPORT, "acme")
    pid = next(p["id"] for p in pr.list_queue("acme") if p["kind"] == "retire_rule")
    c = _sign_in(monkeypatch, idp, email="approver@example.com")
    r = c.post(f"/api/proposals/acme/{pid}/decide", json={"decision": "dismiss", "by": "someone-else", "note": "n"})
    assert r.status_code == 200, r.text
    assert r.json()["decided_by"] == "approver@example.com" and "someone-else" not in r.text
    events = [json.loads(ln) for ln in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]
    d = [e for e in events if e["event"] == "proposal_decision"][0]
    assert d["by"] == "approver@example.com" and d["actor"] == "approver@example.com"


def test_the_page_offers_sign_out_only_under_sso():
    ua = TestClient(srv.app).get("/static/ui_auth.js").text
    assert "Sign out" in ua and "/api/auth/logout" in ua and "status.sso" in ua
    assert "if (!status || !status.sso" in ua, "nothing is shown without SSO"


def _request(cookie=""):
    from starlette.requests import Request
    headers = [(b"cookie", cookie.encode())] if cookie else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "query_string": b""})


def test_current_actor_of_a_request(monkeypatch, idp):
    """security.current_actor(request): the SSO session's email (or sub),
    else "local UI token", or "local, no UI token" with the gate off."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)
    assert security.current_actor(_request()) == "local, no UI token"
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    assert security.current_actor(_request()) == "local UI token"
    _env(monkeypatch)
    assert security.current_actor(_request()) is None
    c = _sign_in(monkeypatch, idp, email="who@example.com")
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    assert security.current_actor(_request(f"{security.SSO_SESSION_COOKIE}={sid}")) == "who@example.com"
    c = _sign_in(monkeypatch, idp, email=None, sub="subject-9")
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    assert security.current_actor(_request(f"{security.SSO_SESSION_COOKIE}={sid}")) == "subject-9"
