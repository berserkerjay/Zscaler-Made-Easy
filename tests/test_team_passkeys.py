"""Team server passkeys (team_passkeys.py, team_api.py): WebAuthn
registration and sign-in verified by py_webauthn, with this file's own
software authenticator (an ECDSA P-256 key made for the test run, CBOR
from cbor2). No browser, no network.

Proved: a registered passkey signs its account in; refused are a wrong
origin (a phishing page), a wrong RP ID, no user verification, a replayed
or lowered signature counter (a cloned authenticator), a reused or expired
challenge, a forged signature, an unknown passkey, a mismatched user
handle, a locked or turned-off account, a registration finished in another
session, and a registration without the current password. The origin and
RP ID come from the configuration, never from the Host header."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

import audit
import dlp_api_server as srv
import security
import sso
import team_passkeys
import team_server as team

ORIGIN = "https://zme.example.test"
RP_ID = "zme.example.test"
PW = "correct horse battery staple"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """A software passkey: one ECDSA P-256 credential, a signature counter,
    'none' attestation. Flags: UP 0x01, UV 0x04, AT 0x40 (WebAuthn 6.1)."""

    def __init__(self, counter_step=1):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.counter = 0
        self.step = counter_step
        self.user_handle = None

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    @staticmethod
    def _client_data(kind, challenge, origin):
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()

    def create(self, options, *, origin=ORIGIN, rp_id=None, uv=True):
        self.user_handle = unb64u(options["user"]["id"])
        rp = rp_id or options["rp"]["id"]
        flags = 0x01 | 0x40 | (0x04 if uv else 0)
        att = bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter) + att
        cdj = self._client_data("webauthn.create", options["challenge"], origin)
        ao = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(ao), "transports": ["internal"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def get(self, options, *, origin=ORIGIN, rp_id=RP_ID, uv=True, key=None, counter=None, user_handle=None):
        self.counter = self.counter + self.step if counter is None else counter
        flags = 0x01 | (0x04 if uv else 0)
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        cdj = self._client_data("webauthn.get", options["challenge"], origin)
        sig = (key or self.key).sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        handle = user_handle if user_handle is not None else self.user_handle
        resp = {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(auth), "signature": b64u(sig)}
        if handle is not None:
            resp["userHandle"] = b64u(handle)
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key", "response": resp,
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}


@pytest.fixture
def pk_on(monkeypatch):
    monkeypatch.setenv("ZSCALER_TEAM_MODE", "1")
    monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_ORIGIN", ORIGIN)
    monkeypatch.setattr(team, "SCRYPT_LOG_N", 10)
    monkeypatch.setattr(team, "_DUMMY_HASH", None)
    team._FAILURES.clear()
    team._IP_ATTEMPTS.clear()
    team._CACHE.update(key=None, data=None)
    sso._SESSIONS.clear()
    team_passkeys.reset()
    yield
    team_passkeys.reset()
    sso._SESSIONS.clear()
    team._CACHE.update(key=None, data=None)


H = {"Origin": ORIGIN}


def _client():
    return TestClient(srv.app, base_url=ORIGIN)


def _signed_in(name="alice", role="operator"):
    if not team.find_user(name):
        team.create_user(username=name, role=role, password=PW)
    c = _client()
    assert c.post("/api/auth/team/login", json={"username": name, "password": PW}, headers=H).status_code == 200
    return c


def _register(c, auth=None, password=PW, **kw):
    auth = auth or SoftAuthenticator()
    r = c.post("/api/team/me/passkeys/options", json={"current": password}, headers=H)
    assert r.status_code == 200, r.text
    r = c.post("/api/team/me/passkeys", json={"credential": auth.create(r.json()["options"], **kw), "name": "Laptop"}, headers=H)
    return auth, r


def _login(auth, c=None, **kw):
    c = c or _client()
    o = c.post("/api/auth/team/passkey/options", headers=H).json()
    return c, c.post("/api/auth/team/passkey/login", json={"ceremony": o["ceremony"], "credential": auth.get(o["options"], **kw)}, headers=H)


# ── 1. register, then sign in ───────────────────────────────────────────
def test_a_registered_passkey_signs_its_account_in(pk_on):
    """ASVS V2.8.1 · V2.2.4 · CWE-287 · WSTG-ATHN-04: register with the current password, then a passkey sign-in starts a fresh session for that account with its role."""
    c = _signed_in()
    auth, r = _register(c)
    assert r.status_code == 200, r.text
    assert c.get("/api/team/me").json()["user"]["passkeys"][0]["name"] == "Laptop"
    c2, r = _login(auth)
    assert r.status_code == 200 and r.json()["user"] == "alice" and r.json()["role"] == "operator"
    assert c2.get("/api/team/me").status_code == 200
    assert any(s.get("via") == "passkey" for s in sso._SESSIONS.values())
    stored = team.find_user("alice")["passkeys"][0]
    assert stored["sign_count"] == 1 and stored["last_used"]


def test_registration_options_require_uv_a_discoverable_key_and_the_configured_rp(pk_on):
    """ASVS V2.8.1 · CWE-287 · WSTG-ATHN-04: the options ask for user verification and a resident key, name the configured RP ID (not the Host header) and a random user handle with no personal data."""
    c = _signed_in()
    o = c.post("/api/team/me/passkeys/options", json={"current": PW}, headers={"Origin": "https://evil.example", "Host": "evil.example"}).json()["options"]
    assert o["rp"]["id"] == RP_ID and o["authenticatorSelection"]["userVerification"] == "required"
    assert o["authenticatorSelection"]["residentKey"] == "required"
    assert len(unb64u(o["user"]["id"])) == 32 and b"alice" not in unb64u(o["user"]["id"])
    assert len(unb64u(o["challenge"])) >= 32


def test_registration_needs_the_current_password_and_the_same_session(pk_on):
    """ASVS V2.2.3 · V3.7.1 · CWE-306 · WSTG-ATHN-04: a wrong current password is 403; a ceremony started in one session cannot be finished in another."""
    c = _signed_in()
    assert c.post("/api/team/me/passkeys/options", json={"current": "wrong password!!"}, headers=H).status_code == 403
    other = _signed_in()
    o = c.post("/api/team/me/passkeys/options", json={"current": PW}, headers=H).json()["options"]
    r = other.post("/api/team/me/passkeys", json={"credential": SoftAuthenticator().create(o)}, headers=H)
    assert r.status_code == 400 and "not started here" in r.json()["detail"]
    assert not team.find_user("alice").get("passkeys")


# ── 2. what registration refuses ────────────────────────────────────────
@pytest.mark.parametrize("kw,why", [({"origin": "https://zme.example.test.evil.example"}, "origin"),
                                    ({"rp_id": "evil.example"}, "rp id"), ({"uv": False}, "no uv")])
def test_registration_with_a_wrong_origin_rp_id_or_no_user_verification_is_refused(pk_on, kw, why):
    """ASVS V2.8.1 · CWE-346 · WSTG-ATHN-04: a passkey made on another origin, for another RP ID, or without PIN/biometric is not stored."""
    c = _signed_in()
    _, r = _register(c, **kw)
    assert r.status_code == 400, why
    assert not team.find_user("alice").get("passkeys")


def test_the_same_passkey_cannot_be_registered_twice_and_there_is_a_cap(pk_on, monkeypatch):
    """ASVS V2.8.1 · CWE-770 · WSTG-BUSL-05: a credential ID already registered is refused, and an account holds at most MAX_PASSKEYS."""
    c = _signed_in()
    auth, r = _register(c)
    assert r.status_code == 200
    auth.counter = 0
    _, r = _register(c, auth=auth)
    assert r.status_code == 409
    monkeypatch.setattr(team_passkeys, "MAX_PASSKEYS", 1)
    assert c.post("/api/team/me/passkeys/options", json={"current": PW}, headers=H).status_code == 409


# ── 3. what sign-in refuses ─────────────────────────────────────────────
@pytest.mark.parametrize("kw,why", [
    ({"origin": "https://phish.example"}, "phishing origin"),
    ({"rp_id": "phish.example"}, "rp id"),
    ({"uv": False}, "no user verification"),
    ({"key": ec.generate_private_key(ec.SECP256R1())}, "forged signature"),
    ({"user_handle": b"\x00" * 32}, "user handle of another account"),
])
def test_a_sign_in_from_a_phishing_origin_wrong_rp_no_uv_forged_or_mismatched_is_refused(pk_on, kw, why):
    """ASVS V2.8.1 · CWE-346 · CWE-347 · WSTG-ATHN-04: each failure is a generic 401 and no session."""
    auth, r = _register(_signed_in())
    assert r.status_code == 200
    sso._SESSIONS.clear()
    _, r = _login(auth, **kw)
    assert r.status_code == 401, why
    assert r.json()["detail"] == team_passkeys.GENERIC_FAILURE and not sso._SESSIONS


def test_a_replayed_or_lowered_counter_is_refused_and_audited(pk_on, monkeypatch):
    """ASVS V2.8.1 · CWE-294 · WSTG-SESS-05: a counter that does not go up (a cloned authenticator or a replay) is refused and raises an audit alarm."""
    seen = []
    real = audit.record
    monkeypatch.setattr(audit, "record", lambda e, **f: (seen.append(e), real(e, **f))[1])
    auth, _ = _register(_signed_in())
    assert _login(auth)[1].status_code == 200            # counter 1
    assert _login(auth, counter=1)[1].status_code == 401   # the same counter again
    assert _login(auth, counter=0)[1].status_code == 401   # lower
    assert "team_passkey_counter_alarm" in seen
    assert _login(auth, counter=5)[1].status_code == 200   # a higher counter is fine


def test_a_challenge_is_used_once_and_expires(pk_on, monkeypatch):
    """ASVS V2.8.1 · CWE-294 · WSTG-SESS-05: the same ceremony cannot be answered twice, and an old one is refused."""
    auth, _ = _register(_signed_in())
    c = _client()
    o = c.post("/api/auth/team/passkey/options", headers=H).json()
    assert c.post("/api/auth/team/passkey/login", json={"ceremony": o["ceremony"], "credential": auth.get(o["options"])}, headers=H).status_code == 200
    r = c.post("/api/auth/team/passkey/login", json={"ceremony": o["ceremony"], "credential": auth.get(o["options"])}, headers=H)
    assert r.status_code == 401 and "expired or was already used" in r.json()["detail"]
    o = c.post("/api/auth/team/passkey/options", headers=H).json()
    now = team._clock()
    monkeypatch.setattr(team, "_clock", lambda: now + team_passkeys.CHALLENGE_TTL_SECONDS + 1)
    assert c.post("/api/auth/team/passkey/login", json={"ceremony": o["ceremony"], "credential": auth.get(o["options"])}, headers=H).status_code == 401


def test_an_unknown_passkey_and_a_malformed_response_are_generic_401s(pk_on):
    """ASVS V2.2.1 · CWE-204 · WSTG-ATHN-04: an unregistered passkey or garbage gets the same generic refusal."""
    _signed_in()
    _, r = _login(SoftAuthenticator())
    assert r.status_code == 401 and r.json()["detail"] == team_passkeys.GENERIC_FAILURE
    c = _client()
    o = c.post("/api/auth/team/passkey/options", headers=H).json()
    r = c.post("/api/auth/team/passkey/login", json={"ceremony": o["ceremony"], "credential": "x" * 10}, headers=H)
    assert r.status_code == 401


def test_a_locked_or_turned_off_account_cannot_sign_in_with_a_passkey(pk_on, monkeypatch):
    """ASVS V2.2.1 · CWE-307 · WSTG-ATHN-03: a password lockout or a turned-off account also stops passkey sign-in."""
    monkeypatch.setenv("ZSCALER_TEAM_LOCKOUT_ATTEMPTS", "2")
    auth, _ = _register(_signed_in())
    for _ in range(2):
        _client().post("/api/auth/team/login", json={"username": "alice", "password": "wrong password!!"}, headers=H)
    assert _login(auth)[1].status_code == 423
    u = team.find_user("alice")
    team.unlock_user(u["id"])
    team.update_user(u["id"], active=False)
    assert _login(auth)[1].status_code == 401


def test_passkey_sign_in_is_rate_limited_per_address(pk_on, monkeypatch):
    """ASVS V2.2.1 · CWE-307 · WSTG-ATHN-03: like the password sign-in, too many attempts from one address are 429."""
    monkeypatch.setattr(team, "LOGIN_IP_ATTEMPTS", 2)
    _signed_in()
    team._IP_ATTEMPTS.clear()
    codes = [_login(SoftAuthenticator())[1].status_code for _ in range(3)]
    assert codes == [401, 401, 429]


# ── 4. removal and administration ───────────────────────────────────────
def test_a_removed_passkey_no_longer_signs_in_and_an_admin_can_remove_all(pk_on):
    """ASVS V2.8.4 · CWE-613 · WSTG-ATHN-04: removing your passkey, or an administrator removing an account's passkeys (a lost device), stops it signing in."""
    c = _signed_in()
    auth, _ = _register(c)
    cid = team.find_user("alice")["passkeys"][0]["id"]
    assert c.delete(f"/api/team/me/passkeys/{cid}", headers=H).status_code == 200
    assert _login(auth)[1].status_code == 401
    auth2, _ = _register(c)
    admin = _signed_in("root", "admin")
    uid = team.find_user("alice")["id"]
    assert c.delete(f"/api/team/users/{uid}/passkeys", headers=H).status_code == 403     # not an administrator
    assert admin.delete(f"/api/team/users/{uid}/passkeys", headers=H).json()["removed"] == 1
    assert _login(auth2)[1].status_code == 401


def test_the_store_and_the_admin_view_hold_no_secret(pk_on):
    """ASVS V2.10.4 · CWE-312 · WSTG-ATHN-07: only the public key and counter are stored; the overview shows names and dates, never the public key."""
    c = _signed_in("root", "admin")
    _register(c)
    rows = c.get("/api/team/overview").json()["users"]
    pk = rows[0]["passkeys"][0]
    assert set(pk) == {"id", "key", "name", "created", "last_used", "backed_up"}
    stored = team.find_user("root")["passkeys"][0]
    assert "private" not in json.dumps(stored).lower()


# ── 5. configuration ────────────────────────────────────────────────────
def test_passkeys_are_off_without_an_origin_and_refuse_unsafe_settings(pk_on, monkeypatch):
    """ASVS V14.1.1 · CWE-1188 · WSTG-CONF-02: no origin: the routes answer 404; an http:// origin (not localhost), an IP address, a path or an RP ID that does not match refuse to start."""
    monkeypatch.delenv("ZSCALER_TEAM_PASSKEY_ORIGIN")
    assert TestClient(srv.app).post("/api/auth/team/passkey/options", headers={"Origin": "http://testserver"}).status_code == 404
    assert team_passkeys.config_errors() == []
    for bad in ("http://zme.example.test", "https://10.0.0.5", "https://zme.example.test/app"):
        monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_ORIGIN", bad)
        assert team_passkeys.config_errors(), bad
        with pytest.raises(RuntimeError):
            team_passkeys.require_configured()
    monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_ORIGIN", ORIGIN)
    monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_RP_ID", "other.example")
    assert any("RP_ID" in e for e in team_passkeys.config_errors())
    monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_RP_ID", "example.test")
    assert team_passkeys.config_errors() == []          # a parent domain is allowed
    monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_ORIGIN", "http://localhost:8443")
    monkeypatch.delenv("ZSCALER_TEAM_PASSKEY_RP_ID")
    assert team_passkeys.config_errors() == []          # localhost may be plain http


def test_passkey_routes_are_public_only_for_sign_in_and_404_off_team_mode(pk_on, monkeypatch):
    """ASVS V4.1.1 · CWE-306 · WSTG-ATHZ-01: managing passkeys needs a session; outside team mode every passkey route is gated or 404."""
    c = _client()
    assert c.post("/api/team/me/passkeys/options", json={"current": PW}, headers=H).status_code == 401
    assert c.delete("/api/team/me/passkeys/abc", headers=H).status_code == 401
    assert c.get("/api/auth/status").json()["passkeys"] is True
    monkeypatch.delenv("ZSCALER_TEAM_MODE")
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: False)
    assert TestClient(srv.app).post("/api/auth/team/passkey/options", headers={"Origin": "http://testserver"}).status_code == 404
