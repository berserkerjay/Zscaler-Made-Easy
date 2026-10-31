"""Team server SAML 2.0 sign-in (sso_saml.py, team_api.py): SP-initiated,
strict. The identity provider here is this file's own: a key and a
self-signed certificate generated for the test run, signing with signxml.
No network, no real identity provider.

Proved: a correctly signed assertion signs the matching account in (in
the browser that started the sign-in only); every one of these is
refused: an unsigned assertion, one signed with another key, SHA-1, a
wrong audience / recipient / issuer / destination, an expired or
not-yet-valid one (with a small clock skew allowed), an unsolicited one,
a replayed one, a DTD or entity, an encrypted assertion, and the XML
signature wrapping variants (a second assertion before, after or around
the signed one, the signed one hidden in Extensions or in an Object, a
modified signed value, a copied signature, a NameID split by a comment)."""
from __future__ import annotations

import base64
import copy
import datetime as dt
import time
import zlib
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from lxml import etree
from signxml import XMLSigner, methods

import audit
import dlp_api_server as srv
import security
import sso
import sso_saml
import team_server as team

IDP = "https://idp.example.test/saml/metadata"
IDP_SSO = "https://idp.example.test/saml/sso"
SP = "https://zme.example.test/saml"
BASE = "https://testserver"
ACS = BASE + sso_saml.ACS_PATH
PW = "correct horse battery staple"
SAMLP, SAML, DS = sso_saml.NS["samlp"], sso_saml.NS["saml"], sso_saml.NS["ds"]


def _keypair(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=60)).sign(key, hashes.SHA256()))
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem_key, cert.public_bytes(serialization.Encoding.PEM)


IDP_KEY, IDP_CERT = _keypair("test-idp")
EVIL_KEY, EVIL_CERT = _keypair("attacker")


def _iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _el(parent, tag, text=None, **attrs):
    e = etree.SubElement(parent, tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        e.text = text
    return e


def assertion(request_id, *, nameid="alice@corp.example", email="alice@corp.example", groups=("zme-operators",),
              aid=None, issuer=IDP, audience=SP, recipient=ACS, now=None, life=300, not_before=None,
              confirmation_not_before=None, method=sso_saml.BEARER, nameid_format=sso_saml.NAMEID_EMAIL, session_until=None):
    now = now or time.time()
    aid = aid or "_a" + base64.b16encode(time.time_ns().to_bytes(8, "big")).decode().lower() + str(id(object()))
    a = etree.Element(f"{{{SAML}}}Assertion", nsmap={"saml": SAML}, ID=aid, Version="2.0", IssueInstant=_iso(now))
    _el(a, f"{{{SAML}}}Issuer", issuer)
    etree.SubElement(a, f"{{{DS}}}Signature", nsmap={"ds": DS}, Id="placeholder")
    subj = _el(a, f"{{{SAML}}}Subject")
    _el(subj, f"{{{SAML}}}NameID", nameid, Format=nameid_format)
    sc = _el(subj, f"{{{SAML}}}SubjectConfirmation", Method=method)
    scd = {"Recipient": recipient, "NotOnOrAfter": _iso(now + life)}
    if request_id is not None:
        scd["InResponseTo"] = request_id
    if confirmation_not_before is not None:
        scd["NotBefore"] = _iso(confirmation_not_before)
    _el(sc, f"{{{SAML}}}SubjectConfirmationData", **scd)
    cond = _el(a, f"{{{SAML}}}Conditions", NotBefore=_iso(not_before if not_before is not None else now - 5), NotOnOrAfter=_iso(now + life))
    ar = _el(cond, f"{{{SAML}}}AudienceRestriction")
    _el(ar, f"{{{SAML}}}Audience", audience)
    st = {"AuthnInstant": _iso(now)}
    if session_until is not None:
        st["SessionNotOnOrAfter"] = _iso(session_until)
    ast = _el(a, f"{{{SAML}}}AuthnStatement", **st)
    ctx = _el(ast, f"{{{SAML}}}AuthnContext")
    _el(ctx, f"{{{SAML}}}AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    ats = _el(a, f"{{{SAML}}}AttributeStatement")
    if email:
        at = _el(ats, f"{{{SAML}}}Attribute", Name="email")
        _el(at, f"{{{SAML}}}AttributeValue", email)
    if groups:
        at = _el(ats, f"{{{SAML}}}Attribute", Name="groups")
        for g in groups:
            _el(at, f"{{{SAML}}}AttributeValue", g)
    return a


class _Sha1Signer(XMLSigner):
    """The test IdP may sign with SHA-1; the server must refuse it."""

    def check_deprecated_methods(self):
        return None


def sign(el, key=IDP_KEY, cert=IDP_CERT, alg="rsa-sha256", digest="sha256"):
    signer = _Sha1Signer if (alg.endswith("sha1") or digest == "sha1") else XMLSigner
    signer = signer(method=methods.enveloped, signature_algorithm=alg, digest_algorithm=digest,
                    c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    if el.find(f"{{{DS}}}Signature") is None:
        el.insert(1, etree.Element(f"{{{DS}}}Signature", nsmap={"ds": DS}, Id="placeholder"))
    return signer.sign(el, key=key, cert=cert.decode(), reference_uri=el.get("ID"), id_attribute="ID")


def response(request_id, assertions, *, issuer=IDP, destination=ACS, status=sso_saml.STATUS_SUCCESS, rid="_r1"):
    r = etree.Element(f"{{{SAMLP}}}Response", nsmap={"samlp": SAMLP, "saml": SAML}, ID=rid, Version="2.0",
                      IssueInstant=_iso(time.time()))
    if destination is not None:
        r.set("Destination", destination)
    if request_id is not None:
        r.set("InResponseTo", request_id)
    _el(r, f"{{{SAML}}}Issuer", issuer)
    st = _el(r, f"{{{SAMLP}}}Status")
    _el(st, f"{{{SAMLP}}}StatusCode", Value=status)
    for a in assertions:
        r.append(a)
    return r


def xml(el):
    return etree.tostring(el)


@pytest.fixture
def saml_on(monkeypatch, tmp_path):
    cert = tmp_path / "idp.pem"
    cert.write_bytes(IDP_CERT)
    monkeypatch.setenv("ZSCALER_TEAM_MODE", "1")
    for k, v in {"ZSCALER_SAML_ENABLED": "1", "ZSCALER_SAML_IDP_ENTITY_ID": IDP, "ZSCALER_SAML_IDP_SSO_URL": IDP_SSO,
                 "ZSCALER_SAML_IDP_CERT_FILE": str(cert), "ZSCALER_SAML_SP_ENTITY_ID": SP, "ZSCALER_SAML_ACS_URL": ACS}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(team, "SCRYPT_LOG_N", 10)
    monkeypatch.setattr(team, "_DUMMY_HASH", None)
    team._FAILURES.clear()
    team._IP_ATTEMPTS.clear()
    team._CACHE.update(key=None, data=None)
    sso._SESSIONS.clear()
    sso_saml.reset()
    yield cert
    sso_saml.reset()
    sso._SESSIONS.clear()
    team._CACHE.update(key=None, data=None)


def _pending(binding="b1"):
    url = sso_saml.start_login(binding)
    return _request_id_of(url)


def _request_id_of(url):
    q = parse_qs(urlparse(url).query)
    req = etree.fromstring(zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15))
    return req.get("ID")


def _ok(rid, **kw):
    return xml(response(rid, [sign(assertion(rid, **kw))]))


# ── 1. the happy path and the request ───────────────────────────────────
def test_a_correctly_signed_assertion_is_accepted_and_only_signed_values_are_used(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: a signed assertion answering this server's request yields the NameID, email and groups it carries."""
    rid = _pending()
    claims = sso_saml.verify_response(_ok(rid, groups=("zme-operators", "all-staff")))
    assert claims["sub"] == "alice@corp.example" and claims["email"] == "alice@corp.example"
    assert claims["groups"] == ["zme-operators", "all-staff"] and claims["issuer"] == IDP and claims["binding"] == "b1"


def test_the_authn_request_is_well_formed_and_names_this_sp(saml_on):
    """ASVS V2.10.1 · CWE-345 · WSTG-ATHN-04: the redirect carries a deflated AuthnRequest with a fresh ID, this SP's entity ID, the ACS URL and the IdP as destination."""
    url = sso_saml.start_login("b")
    assert url.startswith(IDP_SSO + "?")
    q = parse_qs(urlparse(url).query)
    req = etree.fromstring(zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15))
    assert req.get("AssertionConsumerServiceURL") == ACS and req.get("Destination") == IDP_SSO
    assert req.findtext(f"{{{SAML}}}Issuer") == SP and req.get("ID") in sso_saml.pending_request_ids()
    assert q["RelayState"][0] and req.get("ID") != _request_id_of(sso_saml.start_login("b"))


def test_sp_metadata_names_the_acs_and_wants_signed_assertions(saml_on):
    """ASVS V14.1.1 · CWE-16 · WSTG-CONF-02: the SP metadata the IdP is set up from carries the entity ID, the POST ACS URL and WantAssertionsSigned."""
    md = etree.fromstring(sso_saml.sp_metadata_xml())
    assert md.get("entityID") == SP
    sp = md.find("{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor")
    assert sp.get("WantAssertionsSigned") == "true"
    assert sp.find("{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService").get("Location") == ACS


# ── 2. signature: unsigned, other key, weak algorithms ──────────────────
def test_an_unsigned_assertion_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: an assertion with no signature signs nobody in."""
    rid = _pending()
    a = assertion(rid)
    a.remove(a.find(f"{{{DS}}}Signature"))
    with pytest.raises(sso_saml.SamlError, match="not signed"):
        sso_saml.verify_response(xml(response(rid, [a])))


def test_a_signed_response_with_an_unsigned_assertion_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: the signature must be over the assertion itself; a signed Response around an unsigned assertion is refused."""
    rid = _pending()
    a = assertion(rid)
    a.remove(a.find(f"{{{DS}}}Signature"))
    r = response(rid, [a])
    r.insert(1, etree.Element(f"{{{DS}}}Signature", nsmap={"ds": DS}, Id="placeholder"))
    with pytest.raises(sso_saml.SamlError, match="not signed"):
        sso_saml.verify_response(xml(sign(r)))


def test_an_assertion_signed_with_another_key_is_refused_even_with_its_certificate_embedded(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: an attacker's own key and certificate in KeyInfo do not verify: only the configured IdP certificate does."""
    rid = _pending()
    with pytest.raises(sso_saml.SamlError, match="could not be verified"):
        sso_saml.verify_response(xml(response(rid, [sign(assertion(rid), key=EVIL_KEY, cert=EVIL_CERT)])))


def test_a_second_configured_certificate_is_accepted_during_a_rotation(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: with two certificates in the file (a rotation) either one verifies."""
    saml_on.write_bytes(EVIL_CERT + IDP_CERT)
    rid = _pending()
    assert sso_saml.verify_response(_ok(rid))["sub"] == "alice@corp.example"


@pytest.mark.parametrize("alg,digest", [("rsa-sha1", "sha256"), ("rsa-sha256", "sha1")])
def test_sha1_signatures_and_digests_are_refused(saml_on, alg, digest):
    """ASVS V6.2.5 · CWE-327 · WSTG-CRYP-04: a SHA-1 signature or digest is refused even when it is otherwise valid."""
    rid = _pending()
    with pytest.raises(sso_saml.SamlError, match="could not be verified"):
        sso_saml.verify_response(xml(response(rid, [sign(assertion(rid), alg=alg, digest=digest)])))


def test_a_modified_signed_value_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: changing the NameID after signing breaks the digest."""
    rid = _pending()
    a = sign(assertion(rid, nameid="bob@corp.example"))
    a.find(f"{{{SAML}}}Subject/{{{SAML}}}NameID").text = "root@corp.example"
    with pytest.raises(sso_saml.SamlError, match="could not be verified"):
        sso_saml.verify_response(xml(response(rid, [a])))


# ── 3. XML signature wrapping ───────────────────────────────────────────
def _evil(rid, aid="_evil"):
    a = assertion(rid, nameid="root@corp.example", email="root@corp.example", aid=aid)
    a.remove(a.find(f"{{{DS}}}Signature"))
    return a


def test_wrapping_a_second_assertion_before_the_signed_one_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: XSW: an unsigned evil assertion next to a validly signed one is refused (exactly one assertion)."""
    rid = _pending()
    with pytest.raises(sso_saml.SamlError, match="exactly one assertion"):
        sso_saml.verify_response(xml(response(rid, [_evil(rid), sign(assertion(rid))])))


def test_wrapping_the_signed_assertion_inside_an_evil_one_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: XSW: the signed assertion hidden inside the evil assertion (or its Subject) is refused."""
    rid = _pending()
    evil = _evil(rid)
    evil.find(f"{{{SAML}}}Subject").append(sign(assertion(rid)))
    with pytest.raises(sso_saml.SamlError, match="exactly one assertion"):
        sso_saml.verify_response(xml(response(rid, [evil])))


def test_wrapping_the_signed_assertion_in_extensions_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: XSW: the signed assertion moved into samlp:Extensions with an evil one in its place is refused."""
    rid = _pending()
    r = response(rid, [_evil(rid)])
    ext = etree.Element(f"{{{SAMLP}}}Extensions")
    ext.append(sign(assertion(rid)))
    r.insert(1, ext)
    with pytest.raises(sso_saml.SamlError, match="exactly one assertion"):
        sso_saml.verify_response(xml(r))


def test_a_signature_copied_onto_an_evil_assertion_with_the_same_id_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: XSW: the good assertion's signature moved onto a forged assertion with the same ID fails the digest."""
    rid = _pending()
    good = sign(assertion(rid, aid="_same"))
    evil = _evil(rid, aid="_same")
    evil.insert(1, copy.deepcopy(good.find(f"{{{DS}}}Signature")))
    with pytest.raises(sso_saml.SamlError, match="could not be verified"):
        sso_saml.verify_response(xml(response(rid, [evil])))


def test_the_signed_assertion_inside_the_signature_object_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: XSW: the signed original kept inside ds:Object of the forged assertion's signature is refused."""
    rid = _pending()
    good = sign(assertion(rid, aid="_orig"))
    evil = _evil(rid, aid="_forged")
    sig = copy.deepcopy(good.find(f"{{{DS}}}Signature"))
    obj = etree.SubElement(sig, f"{{{DS}}}Object")
    obj.append(good)
    evil.insert(1, sig)
    with pytest.raises(sso_saml.SamlError, match="exactly one assertion"):
        sso_saml.verify_response(xml(response(rid, [evil])))


def test_a_signature_referencing_another_element_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-347 · WSTG-ATHN-04: XSW: an assertion whose own signature references the Response (not itself) is refused."""
    rid = _pending()
    a = assertion(rid)
    a.remove(a.find(f"{{{DS}}}Signature"))
    r = response(rid, [a], rid="_resp")
    signed_r = sign(r)                     # a valid signature over the Response...
    sig = signed_r.find(f"{{{DS}}}Signature")
    signed_r.remove(sig)
    signed_r.find(f"{{{SAML}}}Assertion").insert(1, sig)   # ...moved into the assertion
    with pytest.raises(sso_saml.SamlError):
        sso_saml.verify_response(xml(signed_r))


def test_a_nameid_split_by_a_comment_is_read_whole(saml_on):
    """ASVS V2.10.1 · CWE-436 · WSTG-ATHN-04: comment injection: 'root@corp.example<!---->.evil.test' is read as the full signed value, never as root@corp.example."""
    rid = _pending()
    signed = sign(assertion(rid, nameid="root@corp.example.evil.test", email=""))
    name_id = signed.find(f"{{{SAML}}}Subject/{{{SAML}}}NameID")
    name_id.text = "root@corp.example"
    c = etree.Comment("")
    c.tail = ".evil.test"
    name_id.append(c)
    claims = sso_saml.verify_response(xml(response(rid, [signed])))
    assert claims["sub"] == "root@corp.example.evil.test" and claims["email"] == "root@corp.example.evil.test"


# ── 4. conditions ───────────────────────────────────────────────────────
@pytest.mark.parametrize("kw,needle", [
    ({"audience": "https://other.example/sp"}, "audience"),
    ({"recipient": "https://evil.example/acs"}, "bearer confirmation"),
    ({"issuer": "https://evil.example/idp"}, "another identity provider"),
    ({"method": "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"}, "bearer confirmation"),
    ({"confirmation_not_before": time.time() - 10}, "bearer confirmation"),
])
def test_wrong_audience_recipient_issuer_or_confirmation_is_refused(saml_on, kw, needle):
    """ASVS V2.10.1 · CWE-345 · WSTG-ATHN-04: an assertion for another SP, sent to another ACS, from another IdP or without a valid bearer confirmation is refused."""
    rid = _pending()
    with pytest.raises(sso_saml.SamlError, match=needle):
        sso_saml.verify_response(_ok(rid, **kw))


def test_expired_and_not_yet_valid_assertions_are_refused_with_a_small_skew(saml_on, monkeypatch):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-07: NotOnOrAfter in the past or NotBefore in the future (beyond 60 s of skew) is refused; within the skew it is accepted."""
    t0 = time.time()
    rid = _pending()
    old = _ok(rid, now=t0 - 400, life=300)                 # expired 100 s ago
    with pytest.raises(sso_saml.SamlError, match="expired"):
        sso_saml.verify_response(old)
    rid = _pending()
    early = _ok(rid, now=t0, not_before=t0 + 300, life=600)
    with pytest.raises(sso_saml.SamlError, match="not valid yet"):
        sso_saml.verify_response(early)
    rid = _pending()
    monkeypatch.setattr(sso_saml, "_clock", lambda: t0 + 330)  # 30 s past NotOnOrAfter: inside the skew
    assert sso_saml.verify_response(_ok(rid, now=t0, life=300))["sub"]


def test_an_unsolicited_or_unknown_response_is_refused(saml_on):
    """ASVS V2.10.1 · CWE-352 · WSTG-SESS-05: IdP-initiated (no InResponseTo) or answering a request this server never sent is refused."""
    with pytest.raises(sso_saml.SamlError, match="bearer confirmation"):
        sso_saml.verify_response(xml(response(None, [sign(assertion(None))])))
    with pytest.raises(sso_saml.SamlError, match="answers no sign-in"):
        sso_saml.verify_response(_ok("_never_sent"))


def test_a_replayed_response_and_a_reused_assertion_id_are_refused(saml_on):
    """ASVS V2.10.1 · CWE-294 · WSTG-SESS-05: the same response posted twice is refused, and an assertion ID is accepted once even for a new request."""
    rid = _pending()
    body = _ok(rid, aid="_once")
    assert sso_saml.verify_response(body)["sub"]
    with pytest.raises(sso_saml.SamlError, match="already used"):
        sso_saml.verify_response(body)
    rid2 = _pending()
    with pytest.raises(sso_saml.SamlError, match="already used"):
        sso_saml.verify_response(_ok(rid2, aid="_once"))


@pytest.mark.parametrize("change,needle", [
    (lambda r: r.set("Destination", "https://evil.example/acs"), "another address"),
    (lambda r: r.find(f"{{{SAMLP}}}Status/{{{SAMLP}}}StatusCode").set("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester"), "not Success"),
    (lambda r: r.set("InResponseTo", "_other"), "different requests"),
    (lambda r: r.find(f"{{{SAML}}}Issuer").__setattr__("text", "https://evil.example"), "another identity provider"),
])
def test_response_level_destination_status_and_issuer_are_checked(saml_on, change, needle):
    """ASVS V2.10.1 · CWE-345 · WSTG-ATHN-04: the Response's Destination, Status, InResponseTo and Issuer must match."""
    rid = _pending()
    r = response(rid, [sign(assertion(rid))])
    change(r)
    with pytest.raises(sso_saml.SamlError, match=needle):
        sso_saml.verify_response(xml(r))


# ── 5. parsing ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("doc", [
    b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>',
    b'<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&b;</samlp:Response>',
])
def test_dtds_and_entities_are_refused(saml_on, doc):
    """ASVS V5.5.2 · CWE-611 · WSTG-INPV-07: XXE and entity expansion: any DTD or entity declaration is refused before parsing."""
    with pytest.raises(sso_saml.SamlError, match="DTD"):
        sso_saml.verify_response(doc)


def test_encrypted_assertions_oversized_and_malformed_input_are_refused(saml_on):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: an EncryptedAssertion, an oversized or non-base64 field and broken XML are refused with a plain reason."""
    r = response("_x", [])
    etree.SubElement(r, f"{{{SAML}}}EncryptedAssertion")
    with pytest.raises(sso_saml.SamlError, match="Encrypted assertions"):
        sso_saml.verify_response(xml(r))
    with pytest.raises(sso_saml.SamlError, match="too large"):
        sso_saml.decode_post("A" * (sso_saml.MAX_RESPONSE_B64 + 1))
    with pytest.raises(sso_saml.SamlError, match="base64"):
        sso_saml.decode_post("not base64!!")
    with pytest.raises(sso_saml.SamlError, match="well-formed"):
        sso_saml.verify_response(b"<samlp:Response")


# ── 6. configuration ────────────────────────────────────────────────────
def test_saml_is_off_by_default_and_refuses_to_start_half_configured(saml_on, monkeypatch):
    """ASVS V14.1.1 · CWE-1188 · WSTG-CONF-02: off unless enabled; enabled without team mode, with an http:// IdP or a missing certificate, the server refuses to start."""
    assert sso_saml.config_errors() == []
    monkeypatch.setenv("ZSCALER_SAML_IDP_SSO_URL", "http://idp.example.test/sso")
    monkeypatch.delenv("ZSCALER_TEAM_MODE")
    monkeypatch.setenv("ZSCALER_SAML_IDP_CERT_FILE", "/nonexistent/idp.pem")
    errs = " ".join(sso_saml.config_errors())
    assert "team servers" in errs and "https://" in errs and "cannot be read" in errs
    with pytest.raises(RuntimeError):
        sso_saml.require_configured()
    monkeypatch.delenv("ZSCALER_SAML_ENABLED")
    assert sso_saml.config_errors() == [] and not sso_saml.enabled()


# ── 7. the HTTP flow on a team server ───────────────────────────────────
def _client():
    return TestClient(srv.app, base_url=BASE, follow_redirects=False)


def _start(c):
    r = c.get(sso_saml.LOGIN_PATH)
    assert r.status_code == 302, r.text
    return _request_id_of(r.headers["location"]), parse_qs(urlparse(r.headers["location"]).query)["RelayState"][0]


def _post_acs(c, body, relay=""):
    return c.post(sso_saml.ACS_PATH, data={"SAMLResponse": base64.b64encode(body).decode(), "RelayState": relay},
                  headers={"Origin": "https://idp.example.test"})


def test_the_full_flow_signs_the_matching_account_in_with_its_role_and_groups(saml_on):
    """ASVS V2.10.1 · V3.2.1 · CWE-287 · WSTG-ATHN-04: login → IdP → cross-site POST to the ACS → finish in the same browser: a fresh session for the account the email matches, its role, the IdP groups as team groups."""
    u = team.create_user(username="alice@corp.example", role="operator")
    c = _client()
    rid, relay = _start(c)
    r = _post_acs(c, _ok(rid, groups=("zme-operators",)), relay)
    assert r.status_code == 303 and r.headers["location"].startswith(sso_saml.FINISH_PATH)
    r = c.get(r.headers["location"])
    assert r.status_code == 303 and r.headers["location"] == "/", r.text
    me = c.get("/api/team/me")
    assert me.status_code == 200 and me.json()["user"]["username"] == "alice@corp.example"
    assert me.json()["user"]["saml_linked"] is True
    sess = next(iter(sso._SESSIONS.values()))
    assert sess["via"] == "saml" and sess["groups"] == ["zme-operators"] and sess["team_user"] == u["id"]
    assert "samesite=strict" in str(r.headers.get("set-cookie")).lower()


def test_a_response_posted_from_another_browser_does_not_sign_it_in(saml_on):
    """ASVS V3.2.1 · CWE-352 · WSTG-SESS-05: login CSRF: a valid response for a sign-in started in browser A, posted from browser B, is refused at finish (no binding cookie)."""
    team.create_user(username="alice@corp.example", role="viewer")
    a, b = _client(), _client()
    rid, relay = _start(a)
    r = _post_acs(b, _ok(rid), relay)
    assert r.status_code == 303
    r = b.get(r.headers["location"])
    assert r.status_code == 401 and "another browser" in r.text
    assert b.get("/api/team/me").status_code == 401 and not sso._SESSIONS


def test_no_account_turned_off_account_or_disallowed_group_is_refused(saml_on, monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a verified sign-in with no account here, a turned-off account, or outside ZSCALER_SAML_ALLOWED_GROUPS gets no session."""
    c = _client()
    rid, relay = _start(c)
    r = c.get(_post_acs(c, _ok(rid, nameid="nobody@corp.example", email="nobody@corp.example"), relay).headers["location"])
    assert r.status_code == 403 and "no active account" in r.text
    u = team.create_user(username="carol@corp.example", role="viewer")
    team.update_user(u["id"], active=False)
    rid, relay = _start(c)
    r = c.get(_post_acs(c, _ok(rid, nameid="carol@corp.example", email="carol@corp.example"), relay).headers["location"])
    assert r.status_code == 403
    team.update_user(u["id"], active=True)
    monkeypatch.setenv("ZSCALER_SAML_ALLOWED_GROUPS", "zme-users")
    rid, relay = _start(c)
    r = c.get(_post_acs(c, _ok(rid, nameid="carol@corp.example", email="carol@corp.example", groups=("other",)), relay).headers["location"])
    assert r.status_code == 403 and "not in a group" in r.text and not sso._SESSIONS


def test_an_account_linked_to_one_nameid_is_not_taken_over_by_another(saml_on):
    """ASVS V2.10.1 · CWE-287 · WSTG-ATHN-04: once linked, the account follows its NameID; a different NameID asserting the same email is refused."""
    team.create_user(username="dave@corp.example", role="viewer")
    assert team.link_saml({"issuer": IDP, "sub": "id-123", "email": "dave@corp.example"})
    assert team.link_saml({"issuer": IDP, "sub": "id-999", "email": "dave@corp.example"}) is None
    assert team.link_saml({"issuer": IDP, "sub": "id-123", "email": ""})["username"] == "dave@corp.example"


def test_acs_failures_are_plain_escaped_and_audited(saml_on, monkeypatch):
    """ASVS V7.4.1 · CWE-79 · WSTG-INPV-02: a refused response answers 401 with an escaped reason and an audit entry, never a stack trace."""
    seen = []
    monkeypatch.setattr(audit, "record", lambda e, **f: seen.append((e, f)))
    c = _client()
    r = c.post(sso_saml.ACS_PATH, data={"SAMLResponse": base64.b64encode(b"<x><script>alert(1)</script></x>").decode()},
               headers={"Origin": "https://idp.example.test"})
    assert r.status_code == 401 and "<script>" not in r.text and "Traceback" not in r.text
    assert any(e == "team_login_failed" and f.get("via") == "saml" for e, f in seen)


def test_with_saml_off_the_acs_is_404_and_a_cross_site_post_is_refused(saml_on, monkeypatch):
    """ASVS V4.2.2 · CWE-352 · WSTG-SESS-05: the Origin exemption exists only while SAML is on: off, a cross-site POST to the ACS is refused by the Origin check."""
    monkeypatch.delenv("ZSCALER_SAML_ENABLED")
    c = _client()
    r = c.post(sso_saml.ACS_PATH, data={"SAMLResponse": "x"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and "Origin not allowed" in r.text
    assert c.get(sso_saml.LOGIN_PATH).status_code == 404
    assert security._saml_acs_open() is False


def test_status_advertises_saml_on_a_team_server(saml_on):
    """ASVS V14.1.1 · CWE-1188 · WSTG-CONF-02: the sign-in page learns from /api/auth/status that SAML is on and where to start it."""
    s = _client().get("/api/auth/status").json()
    assert s["saml"] is True and s["saml_login_url"] == sso_saml.LOGIN_PATH
