"""Team server SAML 2.0 sign-in (SP-initiated Web Browser SSO profile,
HTTP-Redirect binding out, HTTP-POST binding back). OFF by default and
for team servers only (team_server.py): unless it is turned on nothing in
this module runs.

An administrator turns it on and sets it up on the Team server page
(save_settings: the identity provider's metadata, or its entity ID,
sign-on URL and signing certificate, kept in the team server's encrypted
account store), or the server's environment sets it (then the page shows
it read-only, and nothing is mixed):

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
MAX_METADATA = 256 * 1024             # an uploaded identity provider metadata file
# Page-saved settings (team_server.saml_settings) by the variable each one stands for.
STORE_KEYS = {"ZSCALER_SAML_IDP_ENTITY_ID": "idp_entity_id", "ZSCALER_SAML_IDP_SSO_URL": "idp_sso_url",
              "ZSCALER_SAML_SP_ENTITY_ID": "sp_entity_id", "ZSCALER_SAML_ACS_URL": "acs_url",
              "ZSCALER_SAML_EMAIL_ATTRIBUTE": "email_attribute", "ZSCALER_SAML_GROUPS_ATTRIBUTE": "groups_attribute",
              "ZSCALER_SAML_ALLOWED_GROUPS": "allowed_groups"}
SETTING_KEYS = tuple(STORE_KEYS.values()) + ("idp_cert_pem",)
REQUIRED_SETTINGS = ("idp_entity_id", "idp_sso_url", "idp_cert_pem", "sp_entity_id", "acs_url")
SETTING_LABELS = {"idp_entity_id": "The identity provider's entity ID", "idp_sso_url": "The identity provider's sign-on URL",
                  "idp_cert_pem": "The identity provider's signing certificate", "sp_entity_id": "This server's entity ID",
                  "acs_url": "This server's ACS URL", "email_attribute": "The email attribute",
                  "groups_attribute": "The groups attribute", "allowed_groups": "The allowed groups"}
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


def from_environment() -> bool:
    """SAML is set by the server's environment (ZSCALER_SAML_ENABLED): then
    every value comes from the ZSCALER_SAML_* variables and the Team server
    page shows them read-only."""
    return os.environ.get("ZSCALER_SAML_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")


def _stored() -> Dict[str, Any]:
    """The settings an administrator saved on the Team server page (kept in
    the team server's encrypted account store). Empty off team mode."""
    try:
        import team_server
        if not team_server.enabled():
            return {}
        return team_server.saml_settings()
    except Exception:  # noqa: BLE001 - fail closed: no stored settings, SAML stays off
        return {}


def enabled() -> bool:
    if from_environment():
        return True
    return _stored().get("enabled") is True


def _env(name: str) -> str:
    """One setting: from the environment when SAML is set there, else from
    the Team server page's saved settings (never a mix of the two)."""
    if from_environment():
        return os.environ.get(name, "").strip()
    v = _stored().get(STORE_KEYS.get(name, ""), "")
    return v.strip() if isinstance(v, str) else ""


def _team_errors() -> List[str]:
    import team_server
    return [] if team_server.enabled() else ["SAML sign-in is for team servers: set ZSCALER_TEAM_MODE=1 too"]


def config_errors() -> List[str]:
    """What is missing or unsafe now that SAML is switched on. Empty: ready."""
    if not enabled():
        return []
    if not from_environment():
        return _team_errors() + settings_errors(_stored())
    import sso
    errors = [f"{n} is not set" for n in REQUIRED_ENV if not _env(n)]
    errors += _team_errors()
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
        if not from_environment():
            raise RuntimeError("SAML sign-in is turned on but not fully set up: " + "; ".join(errors) +
                               ". Fix it on the Team server page, or turn SAML sign-in off there.")
        raise RuntimeError("ZSCALER_SAML_ENABLED is set but SAML sign-in is not fully configured: " + "; ".join(errors) +
                           ". Set every ZSCALER_SAML_* variable, or unset ZSCALER_SAML_ENABLED.")


def load_certs(raw: bytes, what: str) -> List[Any]:
    """PEM certificates (one, or two during a rotation). Refused: none, more
    than four, or more than MAX_CERT_FILE bytes."""
    from cryptography import x509
    if len(raw) > MAX_CERT_FILE:
        raise SamlError(f"{what} is too large to be a certificate file")
    try:
        certs = x509.load_pem_x509_certificates(raw)
    except ValueError:
        raise SamlError(f"{what} holds no PEM certificate") from None
    if not certs or len(certs) > 4:
        raise SamlError(f"{what} must hold one certificate (two during a rotation)")
    return certs


def idp_certs() -> List[Any]:
    """The identity provider's signing certificates: the PEM file named by
    ZSCALER_SAML_IDP_CERT_FILE, or the PEM saved on the Team server page."""
    if not from_environment():
        pem = _stored().get("idp_cert_pem")
        return load_certs(pem.encode("utf-8") if isinstance(pem, str) else b"", "The signing certificate")
    path = _env("ZSCALER_SAML_IDP_CERT_FILE")
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_CERT_FILE + 1)
    except OSError:
        raise SamlError("ZSCALER_SAML_IDP_CERT_FILE cannot be read") from None
    return load_certs(raw, "ZSCALER_SAML_IDP_CERT_FILE")


# ── settings saved on the Team server page ──────────────────────────────
def settings_errors(s: Dict[str, Any], *, partial: bool = False) -> List[str]:
    """What is missing or unsafe in page-saved settings. `partial`: only
    check the values that are filled in (saving a draft while SAML is off)."""
    import sso
    errors = []
    for key in REQUIRED_SETTINGS:
        v = s.get(key)
        if not partial and not (isinstance(v, str) and v.strip()):
            errors.append(f"{SETTING_LABELS[key]} is missing")
    for key in ("idp_sso_url", "acs_url"):
        v = s.get(key)
        if isinstance(v, str) and v.strip() and not sso.secure_url(v):
            errors.append(f"{SETTING_LABELS[key]} must be https:// (plain http:// only to this computer)")
    acs = s.get("acs_url")
    if isinstance(acs, str) and acs.strip() and not acs.strip().split("?", 1)[0].endswith(ACS_PATH):
        errors.append(f"{SETTING_LABELS['acs_url']} must end with {ACS_PATH}")
    pem = s.get("idp_cert_pem")
    if isinstance(pem, str) and pem.strip():
        try:
            load_certs(pem.encode("utf-8"), "The signing certificate")
        except SamlError as e:
            errors.append(str(e))
    return errors


def parse_idp_metadata(raw: Any) -> Dict[str, str]:
    """The identity provider's entity ID, HTTP-Redirect sign-on URL and
    signing certificates from its SAML metadata (an upload: untrusted).
    Refused: over MAX_METADATA, a DTD or entity (XXE, entity expansion),
    not well-formed, not exactly one identity provider, no HTTP-Redirect
    sign-on service, no signing certificate, more than four. The metadata's
    own signature is not checked: the administrator downloads it from their
    identity provider's console and uploads it here themselves."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise SamlError("Send the identity provider's metadata as XML text.")
    if len(data) > MAX_METADATA:
        raise SamlError(f"The metadata is larger than {MAX_METADATA // 1024} KB: refused.")
    lowered = bytes(data).lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise SamlError("The metadata carries a DTD or an entity declaration: refused.")
    try:
        root = etree.fromstring(bytes(data), parser=_parser())
    except etree.XMLSyntaxError:
        raise SamlError("The metadata is not well-formed XML.") from None
    docinfo = root.getroottree().docinfo
    if docinfo.internalDTD is not None or docinfo.externalDTD is not None or any(True for _ in root.iter(etree.Entity)):
        raise SamlError("The metadata carries a DTD or an entity: refused.")
    md = "{%s}" % NS["md"]
    if root.tag == md + "EntityDescriptor":
        entities = [root]
    elif root.tag == md + "EntitiesDescriptor":
        entities = list(root.iter(md + "EntityDescriptor"))
    else:
        raise SamlError("This is not SAML metadata (no md:EntityDescriptor).")
    idps = [(e, d) for e in entities for d in e.findall(md + "IDPSSODescriptor")]
    if len(idps) != 1:
        raise SamlError("The metadata must describe exactly one identity provider (one IDPSSODescriptor).")
    entity, idp = idps[0]
    entity_id = str(entity.get("entityID") or "").strip()
    if not entity_id or len(entity_id) > MAX_TEXT:
        raise SamlError("The metadata has no usable entityID.")
    sso_url = ""
    for svc in idp.findall(md + "SingleSignOnService"):
        if svc.get("Binding") == BINDING_REDIRECT:
            sso_url = str(svc.get("Location") or "").strip()
            break
    if not sso_url or len(sso_url) > MAX_TEXT:
        raise SamlError("The metadata has no single sign-on service with the HTTP-Redirect binding.")
    pems = []
    for kd in idp.findall(md + "KeyDescriptor"):
        if kd.get("use") not in (None, "signing"):
            continue
        for c in kd.iterfind(".//ds:X509Certificate", namespaces=NS):
            b64 = "".join(str(c.text or "").split())
            if len(b64) > MAX_CERT_FILE:
                raise SamlError("A certificate in the metadata is too large.")
            try:
                cert = x509.load_der_x509_certificate(base64.b64decode(b64, validate=True))
            except (ValueError, TypeError):
                raise SamlError("A signing certificate in the metadata cannot be read.") from None
            pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            if pem not in pems:
                pems.append(pem)
    if not pems:
        raise SamlError("The metadata names no signing certificate.")
    if len(pems) > 4:
        raise SamlError("The metadata names more than four signing certificates.")
    return {"idp_entity_id": entity_id, "idp_sso_url": sso_url, "idp_cert_pem": "".join(pems)}


def cert_summary(certs: List[Any]) -> List[Dict[str, Any]]:
    """What the page shows about each signing certificate (public facts)."""
    from cryptography.hazmat.primitives import hashes
    out = []
    now = _clock()
    for c in certs:
        try:
            until = c.not_valid_after_utc
        except AttributeError:   # older cryptography
            until = c.not_valid_after.replace(tzinfo=timezone.utc)
        out.append({"subject": c.subject.rfc4514_string()[:MAX_TEXT], "not_after": until.strftime("%Y-%m-%d"),
                    "expired": until.timestamp() <= now, "sha256": c.fingerprint(hashes.SHA256()).hex(":").upper()})
    return out


def settings_view() -> Dict[str, Any]:
    """The SAML settings as the Team server page shows them: never more than
    public values (entity IDs, addresses, certificate facts)."""
    env = from_environment()
    stored = _stored()
    vals = {k: (_env(n) if env else (stored.get(k) if isinstance(stored.get(k), str) else "")) for n, k in STORE_KEYS.items()}
    try:
        certs = cert_summary(idp_certs()) if (_env("ZSCALER_SAML_IDP_CERT_FILE") if env else stored.get("idp_cert_pem")) else []
    except SamlError:
        certs = []
    return {"source": "environment" if env else "page", "enabled": enabled(), **{k: vals.get(k, "") for k in STORE_KEYS.values()},
            "certificates": certs, "errors": config_errors() if env else _team_errors() + settings_errors(stored),
            "metadata_path": METADATA_PATH, "acs_path": ACS_PATH, "login_path": LOGIN_PATH}


def save_settings(body: Dict[str, Any], *, by: str = "") -> Dict[str, Any]:
    """Save the Team server page's SAML settings: the identity provider's
    metadata (parsed: see parse_idp_metadata), or its entity ID, sign-on URL
    and signing certificate, plus this server's entity ID and ACS URL; and
    on or off. A value that is filled in must be valid; turning SAML on
    needs every value. Refused when SAML is set by the environment."""
    import team_server
    if from_environment():
        raise SamlError("SAML sign-in is set by this server's environment (ZSCALER_SAML_ENABLED): change it there.")
    new = dict(team_server.saml_settings())
    md = body.get("metadata")
    if md not in (None, ""):
        if not isinstance(md, str):
            raise SamlError("Send the identity provider's metadata as XML text.")
        new.update(parse_idp_metadata(md))
    for key in SETTING_KEYS:
        if key not in body or body[key] is None:
            continue
        v = body[key]
        if not isinstance(v, str):
            raise SamlError(f"{SETTING_LABELS.get(key, key)} must be text.")
        if len(v) > (MAX_CERT_FILE if key == "idp_cert_pem" else MAX_TEXT):
            raise SamlError(f"{SETTING_LABELS.get(key, key)} is too long.")
        new[key] = v.strip()
    if "enabled" in body:
        if not isinstance(body["enabled"], bool):
            raise SamlError("enabled must be true or false.")
        new["enabled"] = body["enabled"]
    errors = settings_errors(new, partial=not new.get("enabled"))
    if errors:
        what = "SAML sign-in cannot be turned on yet: " if new.get("enabled") else "Not saved: "
        raise SamlError(what + "; ".join(errors) + ".")
    team_server.save_saml_settings({k: new[k] for k in SETTING_KEYS + ("enabled",) if k in new}, by=by)
    return settings_view()


def check_settings() -> Dict[str, Any]:
    """Check the settings without signing anybody in and without calling the
    identity provider (no outbound call): every value present and safe, the
    certificates readable and in date, and the request this server would
    send. Returns {ok, problems, certificates, request}."""
    view = settings_view()
    problems = list(view["errors"])
    certs = view["certificates"]
    problems += [f"The signing certificate {c['sha256'][:23]}… expired on {c['not_after']}" for c in certs if c["expired"]]
    request = None
    if not problems:
        request = {"destination": _env("ZSCALER_SAML_IDP_SSO_URL"), "issuer": _env("ZSCALER_SAML_SP_ENTITY_ID"),
                   "acs_url": _env("ZSCALER_SAML_ACS_URL"), "binding": "HTTP-Redirect out, HTTP-POST back"}
    return {"ok": not problems, "problems": problems, "certificates": certs, "request": request, "enabled": view["enabled"]}


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
