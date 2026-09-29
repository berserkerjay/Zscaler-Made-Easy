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
    assert r.status_code == 303 and security.UI_TOKEN_COOKIE in r.headers.get("set-cookie", "")
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


def test_sso_routes_404_when_sso_is_not_enabled():
    c = TestClient(srv.app)
    assert c.get("/api/auth/sso/login", follow_redirects=False).status_code == 404
    assert c.get("/api/auth/sso/callback?code=x&state=y", follow_redirects=False).status_code == 404
