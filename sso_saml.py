"""Team server SAML 2.0 sign-in (SP-initiated Web Browser SSO profile,
HTTP-Redirect binding out, HTTP-POST binding back). OFF by default and
for team servers only (team_server.py): unless ZSCALER_SAML_ENABLED is set
nothing in this module runs.

    ZSCALER_SAML_ENABLED        "1" turns it on (team mode must be on too)
    ZSCALER_SAML_IDP_ENTITY_ID  the identity provider's entity ID (Issuer)
    ZSCALER_SAML_IDP_SSO_URL    its single sign-on URL (https://)
    ZSCALER_SAML_IDP_CERT_FILE  a PEM file with its signing certificate
                                (two during a rotation: either is accepted)
    ZSCALER_SAML_SP_ENTITY_ID   this server's entity ID (the audience)
    ZSCALER_SAML_ACS_URL        this server's assertion consumer service,
                                exactly as registered at the identity
                                provider, e.g. https://zme.example.com/api/auth/saml/acs
    ZSCALER_SAML_EMAIL_ATTRIBUTE  optional: the attribute holding the email
                                (default: email, mail, or the claims URI)
    ZSCALER_SAML_GROUPS_ATTRIBUTE optional, default "groups"
    ZSCALER_SAML_ALLOWED_GROUPS optional, comma-separated: only people in
                                one of these groups may sign in

The XML signature is checked by signxml (pure Python on lxml and
cryptography; no xmlsec binary, no hand-made cryptography). What is
checked, and refused when it fails (verify_response):

  * the document: no DTD, no entities, no network, a size cap; exactly one
    Assertion and it is a direct child of the Response (an
    EncryptedAssertion is refused: turn assertion encryption off);
  * the signature: over the Assertion itself (its ds:Signature is the
    Assertion's own child and references the Assertion's ID; IDs are
    unique), made with the configured certificate's key, RSA/ECDSA with
    SHA-256 or stronger (never SHA-1, never HMAC). A Response signature,
    when present, must verify too. EVERYTHING the sign-in uses is read
    from the bytes the signature covers (signxml's signed_xml), never from
    the document as received: an injected or wrapped assertion is ignored
    or refused (XML signature wrapping, CWE-347);
  * Issuer, Audience (this SP's entity ID), bearer SubjectConfirmation
    with Recipient = the ACS URL, InResponseTo = a request this server
    sent (and has not seen answered), NotBefore / NotOnOrAfter with
    CLOCK_SKEW_SECONDS of leeway, Status Success, Destination;
  * one-time use: the request is consumed and the assertion ID is
    remembered until it expires, so a replayed response is refused.

A verified sign-in is then handed to the browser that started it (the
binding cookie, checked at /api/auth/saml/finish): a response posted from
another browser does not sign it in (login CSRF). The account is matched
like the OpenID Connect path (team_server.link_saml): an account already
linked to this identity provider's NameID, else the one whose user name or
email is the asserted email; groups map to team groups by display name.
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
import time
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from lxml import etree

NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "ds": "http://www.w3.org/2000/09/xmldsig#", "md": "urn:oasis:names:tc:SAML:2.0:metadata"}
_P, _A, _DS = "{%s}" % NS["samlp"], "{%s}" % NS["saml"], "{%s}" % NS["ds"]
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
REQUIRED_ENV = ("ZSCALER_SAML_IDP_ENTITY_ID", "ZSCALER_SAML_IDP_SSO_URL", "ZSCALER_SAML_IDP_CERT_FILE",
                "ZSCALER_SAML_SP_ENTITY_ID", "ZSCALER_SAML_ACS_URL")
ACS_PATH = "/api/auth/saml/acs"
LOGIN_PATH = "/api/auth/saml/login"
FINISH_PATH = "/api/auth/saml/finish"
METADATA_PATH = "/api/auth/saml/metadata"
COOKIE_PATH = "/api/auth/saml/"
LOGIN_COOKIE = "dlpcheck_saml_login"
CLOCK_SKEW_SECONDS = 60
MAX_RESPONSE_B64 = 256 * 1024          # the posted SAMLResponse field
MAX_RESPONSE_XML = 192 * 1024          # once decoded
MAX_ATTR_VALUES = 200
MAX_TEXT = 512
PENDING_TTL_SECONDS = 600
HANDOFF_TTL_SECONDS = 120
MAX_PENDING = 1000
MAX_SEEN_ASSERTIONS = 10000
MAX_CERT_FILE = 64 * 1024
# Public-key signatures with SHA-256 or stronger only: never SHA-1 or
# SHA-224, never HMAC (a shared secret) and never DSA.
SIGNATURE_METHODS = ("RSA_SHA256", "RSA_SHA384", "RSA_SHA512", "SHA256_RSA_MGF1", "SHA384_RSA_MGF1", "SHA512_RSA_MGF1",
                     "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512")
DIGEST_ALGORITHMS = ("SHA256", "SHA384", "SHA512")
DEFAULT_EMAIL_ATTRIBUTES = ("email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                            "urn:oid:0.9.2342.19200300.100.1.3")

_LOCK = threading.Lock()
_PENDING: Dict[str, Dict[str, Any]] = {}     # AuthnRequest ID -> {relay, binding, at}
_HANDOFF: Dict[str, Dict[str, Any]] = {}     # one-time code -> {claims, binding, at}
_SEEN: Dict[str, float] = {}                 # assertion ID -> forget after (epoch)
_clock = time.time                           # tests replace it


class SamlError(ValueError):
    """A refused SAML sign-in; the message is safe to show (it never echoes
    attacker-controlled XML beyond a short, escaped-by-the-caller reason)."""


def enabled() -> bool:
    return os.environ.get("ZSCALER_SAML_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def config_errors() -> List[str]:
    """What is missing or unsafe now that SAML is switched on. Empty: ready."""
    if not enabled():
        return []
    import sso
    import team_server
    errors = [f"{n} is not set" for n in REQUIRED_ENV if not _env(n)]
    if not team_server.enabled():
        errors.append("SAML sign-in is for team servers: set ZSCALER_TEAM_MODE=1 too")
    for n in ("ZSCALER_SAML_IDP_SSO_URL", "ZSCALER_SAML_ACS_URL"):
        if _env(n) and not sso.secure_url(_env(n)):
            errors.append(f"{n} must be https:// (plain http:// only to this computer)")
    if _env("ZSCALER_SAML_ACS_URL") and not _env("ZSCALER_SAML_ACS_URL").split("?", 1)[0].endswith(ACS_PATH):
        errors.append(f"ZSCALER_SAML_ACS_URL must end with {ACS_PATH}")
    if _env("ZSCALER_SAML_IDP_CERT_FILE"):
        try:
            idp_certs()
        except SamlError as e:
            errors.append(str(e))
    return errors


def require_configured() -> None:
    """Fail closed at start-up (and before each sign-in)."""
    errors = config_errors()
    if errors:
        raise RuntimeError("ZSCALER_SAML_ENABLED is set but SAML sign-in is not fully configured: " + "; ".join(errors) +
                           ". Set every ZSCALER_SAML_* variable, or unset ZSCALER_SAML_ENABLED.")


def idp_certs() -> List[Any]:
    """The identity provider's signing certificates from the PEM file (one,
    or two during a rotation). Refused: no certificate, more than four, or
    a file over MAX_CERT_FILE."""
    from cryptography import x509
    path = _env("ZSCALER_SAML_IDP_CERT_FILE")
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_CERT_FILE + 1)
    except OSError:
        raise SamlError("ZSCALER_SAML_IDP_CERT_FILE cannot be read") from None
    if len(raw) > MAX_CERT_FILE:
        raise SamlError("ZSCALER_SAML_IDP_CERT_FILE is too large to be a certificate file")
    try:
        certs = x509.load_pem_x509_certificates(raw)
    except ValueError:
        raise SamlError("ZSCALER_SAML_IDP_CERT_FILE holds no PEM certificate") from None
    if not certs or len(certs) > 4:
        raise SamlError("ZSCALER_SAML_IDP_CERT_FILE must hold one certificate (two during a rotation)")
    return certs


# ── the request (SP → IdP) ──────────────────────────────────────────────
def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sweep(now: float) -> None:
    """Called with _LOCK held: forget expired requests, hand-offs and seen IDs, and bound each map."""
    for k in [k for k, v in _PENDING.items() if now - v["at"] > PENDING_TTL_SECONDS]:
        _PENDING.pop(k, None)
    for k in [k for k, v in _HANDOFF.items() if now - v["at"] > HANDOFF_TTL_SECONDS]:
        _HANDOFF.pop(k, None)
    for k in [k for k, v in _SEEN.items() if v < now]:
        _SEEN.pop(k, None)
    for m, cap in ((_PENDING, MAX_PENDING - 1), (_HANDOFF, MAX_PENDING - 1)):
        extra = len(m) - cap
        if extra > 0:
            for k in sorted(m, key=lambda key: m[key]["at"])[:extra]:
                m.pop(k, None)


def authn_request_xml(request_id: str, now: float) -> bytes:
    """The AuthnRequest, built element by element (no string templating)."""
    req = etree.Element(_P + "AuthnRequest", nsmap={"samlp": NS["samlp"], "saml": NS["saml"]})
    req.set("ID", request_id)
    req.set("Version", "2.0")
    req.set("IssueInstant", _iso(now))
    req.set("Destination", _env("ZSCALER_SAML_IDP_SSO_URL"))
    req.set("AssertionConsumerServiceURL", _env("ZSCALER_SAML_ACS_URL"))
    req.set("ProtocolBinding", BINDING_POST)
    etree.SubElement(req, _A + "Issuer").text = _env("ZSCALER_SAML_SP_ENTITY_ID")
    return etree.tostring(req)


def start_login(binding: str) -> str:
    """Remember a new AuthnRequest (bound to this browser's cookie) and
    return the identity provider URL to redirect to (HTTP-Redirect binding)."""
    require_configured()
    now = _clock()
    request_id = "_" + secrets.token_hex(20)        # an NCName: starts with "_"
    relay = secrets.token_urlsafe(24)
    with _LOCK:
        _sweep(now)
        _PENDING[request_id] = {"relay": relay, "binding": binding, "at": now}
    deflater = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed = deflater.compress(authn_request_xml(request_id, now)) + deflater.flush()
    url = _env("ZSCALER_SAML_IDP_SSO_URL")
    query = urlencode({"SAMLRequest": base64.b64encode(packed).decode("ascii"), "RelayState": relay})
    return url + ("&" if "?" in url else "?") + query


def sp_metadata_xml() -> bytes:
    """This server's SP metadata, for the identity provider's setup."""
    ed = etree.Element("{%s}EntityDescriptor" % NS["md"], nsmap={"md": NS["md"]})
    ed.set("entityID", _env("ZSCALER_SAML_SP_ENTITY_ID"))
    sp = etree.SubElement(ed, "{%s}SPSSODescriptor" % NS["md"])
    sp.set("AuthnRequestsSigned", "false")
    sp.set("WantAssertionsSigned", "true")
    sp.set("protocolSupportEnumeration", NS["samlp"])
    acs = etree.SubElement(sp, "{%s}AssertionConsumerService" % NS["md"])
    acs.set("Binding", BINDING_POST)
    acs.set("Location", _env("ZSCALER_SAML_ACS_URL"))
    acs.set("index", "0")
    acs.set("isDefault", "true")
    return etree.tostring(ed, xml_declaration=True, encoding="UTF-8")


# ── the response (IdP → SP) ─────────────────────────────────────────────
def _parser() -> etree.XMLParser:
    """No DTD loading or validation, no entity expansion, no network, no
    huge trees (lxml's depth and size limits stay on)."""
    return etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
                           huge_tree=False, remove_pis=True)


def _parse(xml: bytes) -> Any:
    if len(xml) > MAX_RESPONSE_XML:
        raise SamlError("The SAML response is too large.")
    head = xml[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in xml.lower():
        raise SamlError("The SAML response carries a DTD or an entity declaration: refused.")
    try:
        root = etree.fromstring(xml, parser=_parser())
    except etree.XMLSyntaxError:
        raise SamlError("The SAML response is not well-formed XML.") from None
    docinfo = root.getroottree().docinfo
    if docinfo.internalDTD is not None or docinfo.externalDTD is not None or any(True for _ in root.iter(etree.Entity)):
        raise SamlError("The SAML response carries a DTD or an entity: refused.")
    return root


def decode_post(saml_response: Any) -> bytes:
    """The XML of an HTTP-POST binding SAMLResponse form field (base64)."""
    s = str(saml_response or "")
    if not s or len(s) > MAX_RESPONSE_B64:
        raise SamlError("The SAML response is missing or too large.")
    try:
        return base64.b64decode("".join(s.split()), validate=True)
    except (ValueError, TypeError):
        raise SamlError("The SAML response is not base64.") from None


def _time(value: Any, what: str) -> float:
    """An xs:dateTime in UTC (Z or an offset); a time with no zone is refused."""
    s = str(value or "").strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise SamlError(f"The assertion's {what} is not a valid time.") from None
    if dt.tzinfo is None:
        raise SamlError(f"The assertion's {what} has no time zone.")
    return dt.timestamp()


def _text(el: Any) -> str:
    """All of an element's text (comments are gone after canonicalisation,
    so a NameID split by a comment reads as one value), trimmed and capped."""
    if el is None:
        return ""
    return "".join(el.itertext()).strip()[:MAX_TEXT]


def _verify_signature(target: Any, location: str, certs: List[Any]) -> Any:
    """signxml's verification of the one signature at `location`, with the
    configured certificates (either works during a rotation). Returns the
    VerifyResult; raises SamlError when no certificate verifies it."""
    from signxml import SignatureConfiguration, SignatureMethod, DigestAlgorithm, XMLVerifier
    from signxml.exceptions import SignXMLException
    methods = frozenset(getattr(SignatureMethod, n) for n in SIGNATURE_METHODS)
    digests = frozenset(getattr(DigestAlgorithm, n) for n in DIGEST_ALGORITHMS)
    config = SignatureConfiguration(require_x509=True, location=location, expect_references=1,
                                    signature_methods=methods, digest_algorithms=digests)
    last = "no certificate"
    for cert in certs:
        try:
            return XMLVerifier().verify(etree.tostring(target), x509_cert=cert, expect_config=config, parser=_parser(),
                                        id_attribute="ID")
        except (SignXMLException, ValueError, TypeError, etree.LxmlError) as e:
            last = type(e).__name__
    raise SamlError(f"The SAML signature could not be verified with the identity provider's certificate ({last}).")


def _reference_id(result: Any) -> str:
    ref = result.signature_xml.find("ds:SignedInfo/ds:Reference", namespaces=NS)
    uri = (ref.get("URI") if ref is not None else "") or ""
    return uri[1:] if uri.startswith("#") else ""


def verify_response(xml: bytes, *, relay_state: str = "") -> Dict[str, Any]:
    """Verify a SAML Response (see the module docstring) and return the
    sign-in it carries: {sub, issuer, email, groups, attributes,
    session_not_on_or_after, assertion_id, binding}. The request it answers
    is consumed and the assertion ID remembered, whatever happens later."""
    require_configured()
    now = _clock()
    idp, sp, acs = _env("ZSCALER_SAML_IDP_ENTITY_ID"), _env("ZSCALER_SAML_SP_ENTITY_ID"), _env("ZSCALER_SAML_ACS_URL")
    root = _parse(xml)
    if root.tag != _P + "Response":
        raise SamlError("This is not a SAML Response.")
    if root.get("Version") != "2.0":
        raise SamlError("Only SAML 2.0 responses are accepted.")
    if list(root.iter(_A + "EncryptedAssertion")):
        raise SamlError("Encrypted assertions are not supported: turn assertion encryption off at the identity provider "
                        "(the connection is HTTPS, and the assertion is signed).")
    every = list(root.iter(_A + "Assertion"))
    direct = root.findall(_A + "Assertion")
    if len(every) != 1 or len(direct) != 1:
        raise SamlError("The SAML response must carry exactly one assertion, directly in the response "
                        "(a nested or second assertion is a signature-wrapping attempt).")
    status = root.find("samlp:Status/samlp:StatusCode", namespaces=NS)
    if status is None or status.get("Value") != STATUS_SUCCESS:
        raise SamlError("The identity provider did not sign you in (its status is not Success).")
    dest = root.get("Destination")
    if dest is not None and dest != acs:
        raise SamlError("The SAML response was sent to another address than this server's ACS URL.")
    r_issuer = root.find("saml:Issuer", namespaces=NS)
    if r_issuer is not None and _text(r_issuer) != idp:
        raise SamlError("The SAML response comes from another identity provider than the configured one.")
    certs = idp_certs()
    assertion = direct[0]
    aid = assertion.get("ID") or ""
    if not aid:
        raise SamlError("The assertion has no ID.")
    if assertion.find("ds:Signature", namespaces=NS) is None:
        raise SamlError("The assertion is not signed: the identity provider must sign the assertion itself.")
    # A Response signature, when the identity provider adds one, must hold too.
    if root.find("ds:Signature", namespaces=NS) is not None:
        rres = _verify_signature(root, "./", certs)
        if _reference_id(rres) != (root.get("ID") or "\0"):
            raise SamlError("The response signature does not cover the response.")
    result = _verify_signature(root, "./" + _A + "Assertion/", certs)
    signed = result.signed_xml
    if signed is None or signed.tag != _A + "Assertion" or _reference_id(result) != aid or signed.get("ID") != aid:
        raise SamlError("The signature does not cover the assertion (signature wrapping refused).")
    # From here on only `signed` (the bytes the signature covers) is read.
    if signed.get("Version") != "2.0":
        raise SamlError("Only SAML 2.0 assertions are accepted.")
    if _text(signed.find("saml:Issuer", namespaces=NS)) != idp:
        raise SamlError("The assertion was issued by another identity provider than the configured one.")
    issued = _time(signed.get("IssueInstant"), "IssueInstant")
    if issued > now + CLOCK_SKEW_SECONDS:
        raise SamlError("The assertion was issued in the future (check the clocks).")
    cond = signed.find("saml:Conditions", namespaces=NS)
    if cond is None:
        raise SamlError("The assertion has no Conditions (no audience).")
    if cond.get("NotBefore") is not None and now + CLOCK_SKEW_SECONDS < _time(cond.get("NotBefore"), "NotBefore"):
        raise SamlError("The assertion is not valid yet (NotBefore; check the clocks).")
    if cond.get("NotOnOrAfter") is not None and now - CLOCK_SKEW_SECONDS >= _time(cond.get("NotOnOrAfter"), "NotOnOrAfter"):
        raise SamlError("The assertion has expired (NotOnOrAfter): sign in again.")
    restrictions = cond.findall("saml:AudienceRestriction", namespaces=NS)
    if not restrictions:
        raise SamlError("The assertion names no audience.")
    for r in restrictions:   # every restriction must admit this SP (SAML core 2.5.1.4)
        if sp not in {_text(a) for a in r.findall("saml:Audience", namespaces=NS)}:
            raise SamlError("The assertion is meant for another service (its audience is not this server).")
    subject = signed.find("saml:Subject", namespaces=NS)
    name_id = subject.find("saml:NameID", namespaces=NS) if subject is not None else None
    sub = _text(name_id)
    if not sub:
        raise SamlError("The assertion names nobody (no NameID).")
    in_response_to, confirmed_until = "", 0.0
    for sc in (subject.findall("saml:SubjectConfirmation", namespaces=NS) if subject is not None else []):
        data = sc.find("saml:SubjectConfirmationData", namespaces=NS)
        if sc.get("Method") != BEARER or data is None:
            continue
        if data.get("Recipient") != acs or not data.get("InResponseTo") or data.get("NotOnOrAfter") is None:
            continue
        if data.get("NotBefore") is not None:
            continue   # the Web SSO profile forbids NotBefore on bearer confirmation data
        until = _time(data.get("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter")
        if now - CLOCK_SKEW_SECONDS >= until:
            continue
        in_response_to, confirmed_until = data.get("InResponseTo"), until
        break
    if not in_response_to:
        raise SamlError("The assertion has no valid bearer confirmation for this server (Recipient, InResponseTo, "
                        "NotOnOrAfter), or it has expired.")
    r_irt = root.get("InResponseTo")
    if r_irt is not None and r_irt != in_response_to:
        raise SamlError("The response and its assertion answer different requests.")
    if signed.find("saml:AuthnStatement", namespaces=NS) is None:
        raise SamlError("The assertion has no authentication statement.")
    with _LOCK:
        _sweep(now)
        pending = _PENDING.pop(in_response_to, None)
        replay = aid in _SEEN
        if not replay:
            _SEEN[aid] = max(confirmed_until, now) + CLOCK_SKEW_SECONDS
            if len(_SEEN) > MAX_SEEN_ASSERTIONS:
                for k in sorted(_SEEN, key=_SEEN.get)[: len(_SEEN) - MAX_SEEN_ASSERTIONS]:
                    _SEEN.pop(k, None)
    if replay:
        raise SamlError("This assertion was already used (a replayed SAML response is refused).")
    if pending is None:
        raise SamlError("This SAML response answers no sign-in this server started (or it expired, or was already used). "
                        "Start the sign-in again from the sign-in page.")
    if relay_state and not secrets.compare_digest(str(relay_state).encode(), str(pending["relay"]).encode()):
        raise SamlError("The SAML RelayState does not match the sign-in this server started.")
    attrs = _attributes(signed)
    session_until = None
    for st in signed.findall("saml:AuthnStatement", namespaces=NS):
        if st.get("SessionNotOnOrAfter"):
            t = _time(st.get("SessionNotOnOrAfter"), "SessionNotOnOrAfter")
            session_until = t if session_until is None else min(session_until, t)
    if session_until is not None and session_until <= now:
        raise SamlError("The identity provider's session has already ended: sign in again.")
    email = _email(attrs, name_id)
    return {"sub": sub, "issuer": idp, "name_id_format": (name_id.get("Format") or "")[:MAX_TEXT], "email": email,
            "groups": _groups(attrs), "attributes": sorted(attrs)[:50], "assertion_id": aid,
            "session_not_on_or_after": session_until, "binding": pending.get("binding")}


def _attributes(signed: Any) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    count = 0
    for st in signed.findall("saml:AttributeStatement", namespaces=NS):
        for a in st.findall("saml:Attribute", namespaces=NS):
            name = str(a.get("Name") or "").strip()[:MAX_TEXT]
            if not name:
                continue
            for v in a.findall("saml:AttributeValue", namespaces=NS):
                count += 1
                if count > MAX_ATTR_VALUES:
                    return out
                t = _text(v)
                if t:
                    out.setdefault(name, []).append(t)
    return out


def _attr(attrs: Dict[str, List[str]], name: str) -> List[str]:
    want = name.strip().lower()
    for k, v in attrs.items():
        if k.lower() == want:
            return v
    return []


def _email(attrs: Dict[str, List[str]], name_id: Any) -> str:
    names = [_env("ZSCALER_SAML_EMAIL_ATTRIBUTE")] if _env("ZSCALER_SAML_EMAIL_ATTRIBUTE") else list(DEFAULT_EMAIL_ATTRIBUTES)
    for n in names:
        vals = _attr(attrs, n)
        if vals and "@" in vals[0]:
            return vals[0].lower()
    if name_id is not None and name_id.get("Format") == NAMEID_EMAIL and "@" in _text(name_id):
        return _text(name_id).lower()
    return ""


def groups_attribute() -> str:
    return _env("ZSCALER_SAML_GROUPS_ATTRIBUTE") or "groups"


def _groups(attrs: Dict[str, List[str]]) -> List[str]:
    return [g for g in _attr(attrs, groups_attribute()) if g][:MAX_ATTR_VALUES]


def allowed_groups() -> List[str]:
    return [x.strip() for x in _env("ZSCALER_SAML_ALLOWED_GROUPS").split(",") if x.strip()]


def sign_in_allowed(claims: Dict[str, Any]) -> bool:
    allowed = {g.lower() for g in allowed_groups()}
    return not allowed or any(str(g).lower() in allowed for g in claims.get("groups") or [])


# ── the hand-off to the browser that started the sign-in ────────────────
def new_handoff(claims: Dict[str, Any]) -> str:
    """A one-time code for a verified sign-in, redeemed (once, within
    HANDOFF_TTL_SECONDS) by redeem_handoff in the browser that holds the
    sign-in's binding cookie."""
    now = _clock()
    code = secrets.token_urlsafe(32)
    with _LOCK:
        _sweep(now)
        _HANDOFF[code] = {"claims": claims, "at": now}
    return code


def redeem_handoff(code: Any, binding: Any) -> Dict[str, Any]:
    now = _clock()
    with _LOCK:
        _sweep(now)
        entry = _HANDOFF.pop(str(code or ""), None)
    if entry is None:
        raise SamlError("This sign-in hand-off is unknown, expired or already used: start the sign-in again.")
    expected = entry["claims"].get("binding")
    if not expected or not secrets.compare_digest(str(binding or "").encode(), str(expected).encode()):
        raise SamlError("This sign-in was started in another browser (or its sign-in cookie is missing): start it again here.")
    return entry["claims"]


def new_binding() -> str:
    return secrets.token_urlsafe(32)


def reset() -> None:
    """Forget every pending request, hand-off and seen assertion (tests)."""
    with _LOCK:
        _PENDING.clear()
        _HANDOFF.clear()
        _SEEN.clear()


def pending_request_ids() -> Tuple[str, ...]:
    with _LOCK:
        return tuple(_PENDING)
