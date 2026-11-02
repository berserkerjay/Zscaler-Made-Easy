"""Cloud-6 QA of the sign-in, secret and audit layer: tenant_auth (secret
and token masking, the classic sign-in's Retry-After), sso (ID token
validation, pending sign-ins, settings), security (scrub_dict, the token
file), audit (append-only, owner-only, bounded), safe_files (links, deep
JSON), tenant_profiles (remembered secrets really forgotten, a damaged
store), zia_rate (a damaged state file, a clock set back, bounded holds,
the injected clock), sdk_client (masked errors, the classic session ended)
and tenant_fingerprint. Every test is offline: fake identity provider,
fake credential store, fake clocks, tmp files."""
from __future__ import annotations

import base64
import functools
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import jwt
import pytest

import audit
import safe_files
import security
import sso
import tenant_auth
import tenant_fingerprint
import tenant_profiles
import zia_rate

sys.path.insert(0, os.path.dirname(__file__))
from test_secret_canaries import FakeKeyring  # noqa: E402
from test_sso import CLIENT_ID, ISSUER, _env as _sso_env, _Idp, _login_url_parts, _mock_http  # noqa: E402

SECRET = "S3cr3t-Value-xyz"
CREDS = {"auth_method": "oneapi", "client_id": "cid-123456", "client_secret": SECRET, "vanity_domain": "acme",
         "username": "admin@acme.example", "password": "P@ss w0rd!", "api_key": "abcdefghijkl"}


WEEK = 7 * 24 * 3600   # tenant_auth.RETRY_AFTER_CAP and zia_rate.MAX_HOLD_SECONDS


def _windows(secret, n=8):   # tenant_auth.SECRET_FRAGMENT
    return [secret[i:i + n] for i in range(len(secret) - n + 1)]


# ── tenant_auth: token and secret masking ───────────────────────────────

# The JWT pattern before it was made linear: the oracle for what it must still find.
_OLD_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")


def test_jwt_redaction_takes_linear_time_on_a_hostile_run():
    """ASVS V5.1.5 · CWE-1333 · CWE-400 · WSTG-INPV-12: a long '-eyJ-eyJ…' run (an echoed error page) is redacted in linear time, not quadratic."""
    text = "-eyJ" * 20000   # 80 KB: the old pattern took about 2 s, a megabyte minutes

    started = time.perf_counter()
    tenant_auth.redact_tokens(text)
    took = time.perf_counter() - started

    assert took < 0.5, took


@pytest.mark.parametrize("text", [
    "x eyJhbGciOiJ.eyJzdWIiOiJ.sigsig y", "-eyJabcdef.ghijkl.mn", "aeyJabcdefghi.jklmnop.q", "eyJshort.abcdef.x",
    "eyJabcdef.abcde.x", "eyJabcdef.abcdef", "eyJabcdef.abcdef.", "éeyJabcdef.abcdef.x", "é-eyJabcdef.abcdef.x",
    "a.eyJabcdef.abcdef.sig.eyJghijkl.mnopqr.s", "eyJabc.eyJabcdef.ghijkl.m", "eyJ-eyJabcdef.ghijkl.m",
    "_eyJabcdef.ghijkl.m", "eyJabcdef.ghijkl.m-n eyJopqrst.uvwxyz.", "..eyJabcdef...ghijkl", "",
])
def test_jwt_redaction_finds_exactly_what_the_documented_pattern_finds(text):
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: the linear JWT redaction matches the documented pattern on an oracle table of edge cases."""
    expected = _OLD_JWT.sub("[redacted token]", text)

    got = tenant_auth._JWT_RUN.sub(tenant_auth._redact_jwt_run, text)

    assert got == expected


@pytest.mark.parametrize("text, leaked", [
    ("GET /x?x=1 Authorization: Bearer%20opaqueTokenValue123", "opaqueTokenValue123"),
    ('{"access_token":"opaqueTokenValue123","expires_in":3600}', "opaqueTokenValue123"),
    ("refresh_token=opaqueRefresh456789&x=1", "opaqueRefresh456789"),
    ("id_token%3DopaqueIdToken000111", "opaqueIdToken000111"),
    ("Authorization: Basic " + base64.b64encode(b"someone:hunter2hunter2").decode(), base64.b64encode(b"someone:hunter2hunter2").decode()),
    ("authorization%3A%20Basic%20" + base64.b64encode(b"a:b-secret-c").decode(), base64.b64encode(b"a:b-secret-c").decode()),
])
def test_redact_tokens_masks_encoded_bearers_oauth_token_fields_and_basic_credentials(text, leaked):
    """ASVS V7.1.1 · ASVS V8.3.4 · CWE-532 · WSTG-INFO-05: a URL-encoded bearer, an OAuth token field and HTTP Basic credentials echoed in an error are masked."""
    out = tenant_auth.redact_tokens(text)

    assert leaked not in out and "[redacted" in out


@pytest.mark.parametrize("text", ["Use basic settings for this policy.", "basic configuration is fine", "Basic auth is off",
                                  "a basic policies list", "Bearer of bad news"])
def test_redact_tokens_leaves_ordinary_words_after_basic_alone(text):
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: 'basic' followed by an English word (not base64 of a pair) is left as it is."""
    assert tenant_auth.redact_tokens(text) == text


@pytest.mark.parametrize("pair, field", [(("cid-123456", SECRET), "client_secret"), (("admin@acme.example", "P@ss w0rd!"), "password")])
@pytest.mark.parametrize("enc", [base64.b64encode, base64.urlsafe_b64encode])
@pytest.mark.parametrize("prefix, marker", [("Authorization: Basic ", "[redacted credentials]"), ("cached credentials=", None)])
def test_mask_secrets_masks_basic_credentials_built_from_the_sign_in(pair, field, enc, prefix, marker):
    """ASVS V7.1.1 · ASVS V2.10.4 · CWE-532 · WSTG-INFO-05: base64 of 'id:secret' (client_secret_basic, a classic admin login) echoed in an error is masked."""
    b64 = enc(f"{pair[0]}:{pair[1]}".encode()).decode()
    text = f"401 for request with {prefix}{b64} at token endpoint"

    out = tenant_auth.mask_secrets(text, CREDS)

    assert b64 not in out and b64.rstrip("=") not in out and (marker or f"[redacted {field}]") in out


@pytest.mark.parametrize("form", [
    base64.b64encode(SECRET.encode()).decode(), base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("="),
    "".join(f"%{b:02X}" for b in SECRET.encode()), "".join(f"%{b:02x}" for b in SECRET.encode()),
])
def test_mask_secrets_masks_a_secret_base64_or_with_every_byte_escaped(form):
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: the secret base64-encoded, or percent-encoded byte by byte, is masked like the typed form."""
    out = tenant_auth.mask_secrets(f"echo: secret={form}; done", CREDS)

    assert form not in out and "[redacted client_secret]" in out


@pytest.mark.parametrize("text", [f"…client_secret={SECRET[:10]}…", f"client_secret={SECRET[:8]}", f"…{SECRET[5:]} (truncated)",
                                  f"body {SECRET[3:13]} cut"])
def test_mask_secrets_masks_a_partial_secret_from_a_cut_short_echo(text):
    """ASVS V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: a piece of the secret of 8 or more characters (an echo cut short) is masked too."""
    out = tenant_auth.mask_secrets(text, CREDS)

    assert not any(w in out for w in _windows(SECRET)), out
    assert "[redacted client_secret]" in out


def test_mask_secrets_keeps_text_that_shares_less_than_a_fragment_with_a_secret():
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: text with only a short overlap with the secret (7 characters) is kept as written."""
    text = f"note {SECRET[:7]} and cid-123456"

    assert tenant_auth.mask_secrets(text, CREDS) == text


@pytest.mark.parametrize("header, expected", [({"Retry-After": "9" * 400}, WEEK),
                                              ({"Retry-After": "1e999"}, 1), ({"Retry-After": "0 seconds"}, 1),
                                              ({"Retry-After": "nonsense"}, 2), ({}, 2), (None, 2),
                                              ({"Retry-After": "3300 seconds"}, 3300)])
def test_a_retry_after_header_is_a_bounded_number_never_an_overflow(header, expected):
    """ASVS V5.1.4 · CWE-20 · CWE-190 · WSTG-INPV-13: an absurd Retry-After from the tenant is capped instead of raising OverflowError."""
    assert tenant_auth._retry_after_seconds(header) == expected


# ── sso: ID token validation and the sign-in flow ───────────────────────

def _claims(nonce, **over):
    c = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "email": "person@example.com", "nonce": nonce,
         "iat": 1_700_000_000, "exp": 4_102_444_800}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def _complete(monkeypatch, idp, make):
    """Start a sign-in, answer the code exchange with make(nonce), complete it."""
    _sso_env(monkeypatch)
    _, state, nonce = _login_url_parts(monkeypatch, idp)
    _mock_http(monkeypatch, idp, token_response={"id_token": make(nonce)})
    return sso.complete_login(state, "code")


@pytest.mark.parametrize("drop", ["exp", "iat", "sub"])
def test_an_id_token_without_a_required_claim_is_refused(monkeypatch, drop):
    """ASVS V3.5.3 · ASVS V2.4.1 · CWE-613 · CWE-345 · WSTG-SESS-07: an ID token with no expiry (or no iat or sub) is refused, never a sign-in that never ends."""
    idp = _Idp()

    with pytest.raises(RuntimeError, match="could not be verified"):
        _complete(monkeypatch, idp, lambda n: jwt.encode(_claims(n, **{drop: None}), idp.key, algorithm="RS256", headers={"kid": "k1"}))


def test_an_expired_id_token_is_refused_in_plain_words(monkeypatch):
    """ASVS V3.5.3 · CWE-613 · WSTG-SESS-07: an ID token past its expiry is refused with a plain reason."""
    idp = _Idp()

    with pytest.raises(RuntimeError, match="expired"):
        _complete(monkeypatch, idp, lambda n: jwt.encode(_claims(n, exp=1_000_000_000), idp.key, algorithm="RS256", headers={"kid": "k1"}))


def test_an_id_token_algorithm_other_than_its_keys_is_refused(monkeypatch):
    """ASVS V3.5.3 · CWE-347 · CWE-327 · WSTG-SESS-10: a token whose header picks another algorithm (PS256) than its published key (RS256) is refused."""
    idp = _Idp()

    with pytest.raises(RuntimeError, match="does not match the signing key"):
        _complete(monkeypatch, idp, lambda n: jwt.encode(_claims(n), idp.key, algorithm="PS256", headers={"kid": "k1"}))


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_an_unsigned_or_shared_secret_id_token_is_refused(monkeypatch, alg):
    """ASVS V3.5.3 · CWE-347 · CWE-345 · WSTG-SESS-10: 'none' and a shared-secret algorithm are refused before any key is used."""
    idp = _Idp()
    make = (lambda n: jwt.encode(_claims(n), None, algorithm="none", headers={"kid": "k1"})) if alg == "none" else \
        (lambda n: jwt.encode(_claims(n), "a-shared-secret-of-32-bytes-long!", algorithm="HS256", headers={"kid": "k1"}))

    with pytest.raises(RuntimeError, match="algorithm this server does not accept"):
        _complete(monkeypatch, idp, make)


def test_an_id_token_for_several_audiences_needs_this_server_as_its_authorized_party(monkeypatch):
    """ASVS V3.5.3 · CWE-345 · CWE-287 · WSTG-ATHN-04: an ID token issued to several clients without azp naming this one is refused."""
    idp = _Idp()

    with pytest.raises(RuntimeError, match="another client"):
        _complete(monkeypatch, idp, lambda n: jwt.encode(_claims(n, aud=[CLIENT_ID, "other-client"]), idp.key, algorithm="RS256",
                                                         headers={"kid": "k1"}))


def test_an_id_token_for_several_audiences_with_this_server_as_azp_signs_in(monkeypatch):
    """ASVS V3.5.3 · CWE-345 · WSTG-ATHN-04: the same token with azp set to this server's client id is accepted."""
    idp = _Idp()

    claims = _complete(monkeypatch, idp, lambda n: jwt.encode(_claims(n, aud=[CLIENT_ID, "other"], azp=CLIENT_ID), idp.key,
                                                              algorithm="RS256", headers={"kid": "k1"}))

    assert claims["sub"] == "user-1"


@pytest.mark.parametrize("issuer", ["http://localhost.attacker.example", "http://127.0.0.1.nip.io/oidc", "http://localhost@evil.example/",
                                    "ftp://idp.example.test", "https://"])
def test_a_plain_http_issuer_that_only_starts_like_loopback_is_refused(monkeypatch, issuer):
    """ASVS V9.2.1 · CWE-319 · CWE-20 · WSTG-CRYP-03: http://localhost.attacker.example is not loopback; only https or a loopback host passes."""
    _sso_env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", issuer)

    assert sso.config_errors(), issuer


@pytest.mark.parametrize("issuer", ["https://idp.example.test", "http://localhost:9000/x", "http://[::1]:9000", "http://127.0.0.1"])
def test_https_and_loopback_issuers_are_accepted(monkeypatch, issuer):
    """ASVS V9.2.1 · CWE-319 · WSTG-CRYP-03: https and a plain-http loopback issuer (local testing) stay accepted."""
    _sso_env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", issuer)

    assert sso.config_errors() == []


def test_pending_sign_ins_from_the_open_login_route_are_bounded(monkeypatch):
    """ASVS V11.1.4 · CWE-770 · CWE-400 · WSTG-BUSL-05: the unauthenticated login route cannot grow the pending sign-ins without bound."""
    idp = _Idp()
    _sso_env(monkeypatch)
    _mock_http(monkeypatch, idp)
    monkeypatch.setattr(sso, "MAX_PENDING_LOGINS", 5)

    states = [parse_qs(urlparse(sso.start_login()).query)["state"][0] for _ in range(20)]

    assert len(sso._PENDING_LOGINS) == 5
    assert set(sso._PENDING_LOGINS) == set(states[-5:])   # the newest are kept


def test_a_discovery_document_naming_another_issuer_is_refused(monkeypatch):
    """ASVS V3.5.3 · CWE-346 · WSTG-ATHN-04: OpenID Connect Discovery 4.3, the document must be the configured issuer's own."""
    idp = _Idp()
    idp.discovery_doc["issuer"] = "https://impostor.example.test"
    _sso_env(monkeypatch)
    _mock_http(monkeypatch, idp)

    with pytest.raises(RuntimeError, match="another issuer"):
        sso.start_login()


def test_a_discovery_document_with_a_plain_http_key_set_is_refused(monkeypatch):
    """ASVS V9.2.1 · CWE-319 · CWE-918 · WSTG-CRYP-03: the signing keys are never fetched over plain http from another host."""
    idp = _Idp()
    idp.discovery_doc["jwks_uri"] = "http://idp.example.test/jwks"
    _sso_env(monkeypatch)
    _mock_http(monkeypatch, idp)

    with pytest.raises(RuntimeError, match="plain http"):
        sso.start_login()


def test_an_authorization_endpoint_with_its_own_query_keeps_one_query_string(monkeypatch):
    """ASVS V3.5.3 · CWE-20 · WSTG-ATHN-04: an endpoint that already has '?tenant=x' gets '&', so state and PKCE reach the provider."""
    idp = _Idp()
    idp.discovery_doc["authorization_endpoint"] = f"{ISSUER}/authorize?tenant=x"
    _sso_env(monkeypatch)
    _mock_http(monkeypatch, idp)

    q = parse_qs(urlparse(sso.start_login()).query)

    assert q["tenant"] == ["x"] and q["code_challenge_method"] == ["S256"] and len(q["state"][0]) > 20


@pytest.mark.parametrize("raw, expected", [("inf", 1800), ("nan", 1800), ("-inf", 1800), ("0", 60), ("abc", 1800),
                                           ("100000", 12 * 3600), ("45", 2700)])
def test_the_idle_timeout_setting_is_a_bounded_number(monkeypatch, raw, expected):
    """ASVS V3.3.2 · CWE-20 · CWE-755 · WSTG-SESS-07: ZSCALER_SSO_IDLE_MINUTES=inf no longer raises on every request; it is bounded."""
    monkeypatch.setenv("ZSCALER_SSO_IDLE_MINUTES", raw)

    assert sso.idle_seconds() == expected


def test_a_session_from_an_unverified_email_is_never_a_writer(monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a writer email the identity provider did not verify grants no write."""
    monkeypatch.setenv("ZSCALER_SSO_WRITERS", "boss@example.com")
    sid = sso.create_session({"sub": "u", "email": "boss@example.com", "email_verified": "false"})

    assert sso.is_writer(sso.get_session(sid)) is False


# ── security: scrub_dict and the token file ─────────────────────────────

def test_scrub_dict_keeps_no_character_or_length_of_a_secret():
    """ASVS V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: scrub_dict masks secrets fully, in nested dicts and dicts inside lists."""
    out = security.scrub_dict({"client_secret": SECRET, "nested": {"password": "hunter2hunter2"},
                               "rows": [{"api_key": "abcdefghijkl"}], "client_id": "cid", "empty": ""})

    text = json.dumps(out)
    assert SECRET[:3] not in text and "hunter" not in text and "abc" not in text and "len=" not in text
    assert out["client_id"] == "cid" and out["client_secret"] == "[redacted]"


def test_a_token_file_that_cannot_be_moved_into_place_leaves_no_copy(monkeypatch, tmp_path):
    """ASVS V8.3.6 · CWE-459 · CWE-532 · WSTG-CONF-04: a failed write of ui_token.txt leaves no temporary file holding the token."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", "tok-for-test-0123456789")

    def refuse(*a, **k):
        raise OSError("read-only")
    monkeypatch.setattr(security.os, "replace", refuse)

    assert security.write_ui_token_file(str(tmp_path)) is None
    assert os.listdir(tmp_path) == []


# ── audit: append-only, owner-only, bounded ─────────────────────────────

@pytest.fixture
def audit_log(monkeypatch, tmp_path):
    p = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(p))
    monkeypatch.delenv("DLP_CHECK_AUDIT_MAX_MB", raising=False)
    return p


@pytest.mark.parametrize("raw", ["inf", "nan", "-1", "0", "lots"])
def test_an_audit_size_setting_that_is_not_a_positive_number_keeps_every_line(audit_log, monkeypatch, raw):
    """ASVS V7.3.3 · CWE-779 · CWE-755 · WSTG-CONF-02: MAX_MB=inf never raises, and 0 or less never rolls (loses) the log on every line."""
    monkeypatch.setenv("DLP_CHECK_AUDIT_MAX_MB", raw)

    for i in range(3):
        assert audit.record("probe", n=i) == str(audit_log)

    assert [e["n"] for e in audit.tail(10)] == [0, 1, 2]


def test_audit_size_setting_is_capped(monkeypatch):
    """ASVS V7.3.3 · CWE-400 · WSTG-CONF-02: an enormous MAX_MB is held to MAX_MAX_MB, so the log stays bounded."""
    monkeypatch.setenv("DLP_CHECK_AUDIT_MAX_MB", "1e12")

    assert audit.max_bytes() == int(audit.MAX_MAX_MB * 1024 * 1024)


@pytest.mark.skipif(os.name == "nt", reason="POSIX links")
def test_the_audit_log_is_never_written_through_a_planted_link(audit_log, tmp_path):
    """ASVS V12.3.1 · CWE-59 · CWE-22 · WSTG-ATHZ-01: a symbolic link at the log's name is not followed; its target is untouched."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    os.symlink(victim, audit_log)

    assert audit.record("probe") is None
    assert victim.read_text() == "keep me\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_an_audit_log_made_wider_is_set_back_to_owner_only_on_the_next_line(audit_log):
    """ASVS V7.3.1 · CWE-732 · CWE-276 · WSTG-CONF-09: an audit.log someone chmod-ed 0644 is 0600 again after the next line."""
    audit.record("first")
    os.chmod(audit_log, 0o644)

    audit.record("second")

    assert os.stat(audit_log).st_mode & 0o777 == 0o600


def test_the_audit_log_is_append_only(audit_log):
    """ASVS V7.3.3 · CWE-779 · WSTG-CONF-02: a new line never rewrites the lines before it."""
    audit.record("first")
    before = audit_log.read_bytes()

    audit.record("second")

    assert audit_log.read_bytes().startswith(before)


def test_a_huge_body_key_is_cut_short_and_a_secret_in_a_key_is_masked(audit_log):
    """ASVS V7.1.2 · CWE-779 · CWE-532 · WSTG-INPV-01: a megabyte-long key name is written cut short; a secret pasted as a key is masked."""
    audit.record("api", body={"k" * 100_000: 1, "client_secret": SECRET, f"note {SECRET}": 1})

    line = audit_log.read_text()
    assert len(line) < 2000 and SECRET not in line


@pytest.mark.parametrize("n", [0, -5, "x", None])
def test_audit_tail_of_zero_or_less_is_none_never_the_whole_log(audit_log, n):
    """ASVS V7.3.4 · CWE-20 · CWE-200 · WSTG-INPV-01: tail(0) or a negative count is no entries, not every line of the log."""
    for i in range(3):
        audit.record("probe", n=i)

    assert audit.tail(n) == []


# ── safe_files: links and deep JSON ─────────────────────────────────────

@pytest.mark.skipif(os.name == "nt", reason="POSIX links")
def test_private_open_never_writes_through_a_planted_link(tmp_path):
    """ASVS V12.3.1 · CWE-59 · CWE-367 · WSTG-ATHZ-01: a link planted at the name of an owner-only file is refused, its target untouched."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "store.json"
    os.symlink(victim, link)

    with pytest.raises(OSError):
        with safe_files.private_open(str(link), "w") as f:
            f.write("overwritten")

    assert victim.read_text() == "keep me"


@pytest.mark.skipif(os.name == "nt", reason="POSIX links")
def test_an_atomic_write_replaces_a_planted_link_instead_of_following_it(tmp_path):
    """ASVS V12.3.1 · CWE-59 · CWE-367 · WSTG-ATHZ-01: write_private_atomic replaces a link at the name; the link's target is untouched."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "store.json"
    os.symlink(victim, link)

    safe_files.write_private_atomic(str(link), "new")

    assert victim.read_text() == "keep me" and not os.path.islink(link) and link.read_text() == "new"
    assert os.stat(link).st_mode & 0o777 == 0o600 or os.name == "nt"


def test_strict_json_nested_too_deep_is_a_value_error():
    """ASVS V5.5.3 · CWE-674 · CWE-400 · WSTG-INPV-01: JSON nested past the parser's depth is a ValueError, as documented, not a RecursionError."""
    with pytest.raises(ValueError):
        safe_files.strict_json_loads("[" * 100_000 + "]" * 100_000)


# ── tenant_profiles: remembered secrets really forgotten ────────────────

@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE", raising=False)
    kr = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", kr)
    return kr


def test_deleting_a_profile_kept_in_the_file_also_clears_its_credential_store_entry(store, monkeypatch, tmp_path):
    """ASVS V8.3.8 · ASVS V6.4.1 · CWE-459 · CWE-312 · WSTG-ATHN-06: a profile whose secret moved to the file opt-in leaves no old secret in the credential store when deleted."""
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    store.items[("dlp-check", "acme")] = "OLD-SECRET-FROM-BEFORE"
    (tmp_path / "tenant_profiles.json").write_text(json.dumps(
        {"version": 1, "profiles": {"acme": {"id": "acme", "name": "acme", "client_secret": "NEW-SECRET-IN-FILE"}}}))

    assert tenant_profiles.delete("acme") is True

    assert ("dlp-check", "acme") not in store.items


def test_a_secret_saved_to_the_file_after_the_store_refused_it_leaves_no_older_copy_in_the_store(store, monkeypatch):
    """ASVS V8.3.8 · CWE-459 · CWE-312 · WSTG-ATHN-06: re-saving when the credential store refuses (file opt-in) deletes the store's older secret."""
    tenant_profiles.upsert({"name": "acme"}, client_secret="FIRST-SECRET-0001", remember_secret=True)
    assert store.items[("dlp-check", "acme")] == "FIRST-SECRET-0001"
    store.fail = True
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")

    tenant_profiles.upsert({"name": "acme"}, client_secret="SECOND-SECRET-0002", remember_secret=True, profile_id="acme")

    assert ("dlp-check", "acme") not in store.items


def test_a_credential_store_that_refuses_the_delete_is_overwritten_with_nothing(store):
    """ASVS V8.3.8 · CWE-459 · WSTG-ATHN-06: when the store refuses to delete, the forgotten secret is overwritten so none stays."""
    tenant_profiles.upsert({"name": "acme"}, client_secret="FIRST-SECRET-0001", remember_secret=True)

    def refuse(service, key):
        raise RuntimeError("backend refused")
    store.delete_password = refuse

    tenant_profiles.upsert({"name": "acme"}, remember_secret=False, profile_id="acme")

    assert not store.items.get(("dlp-check", "acme"))


def test_forgetting_a_secret_removes_it_from_the_store_and_the_profile(store, tmp_path):
    """ASVS V8.3.8 · CWE-459 · CWE-312 · WSTG-ATHN-06: unticking 'remember' deletes the secret from the credential store and the file holds no marker."""
    tenant_profiles.upsert({"name": "acme"}, client_secret="FIRST-SECRET-0001", remember_secret=True)

    out = tenant_profiles.upsert({"name": "acme"}, remember_secret=False, profile_id="acme")

    assert not store.items and out["has_secret"] is False
    assert "FIRST-SECRET" not in (tmp_path / "tenant_profiles.json").read_text()


@pytest.mark.parametrize("content", ["[1, 2]", '{"profiles": []}', '{"profiles": {"a": 5, "b": "x"}}', '"text"', "7"])
def test_a_damaged_profile_store_reads_as_empty_never_a_crash(store, tmp_path, content):
    """ASVS V7.4.1 · CWE-755 · CWE-20 · WSTG-ERRH-01: a store that is not this app's JSON shape lists no profiles instead of raising."""
    (tmp_path / "tenant_profiles.json").write_text(content)

    assert tenant_profiles.list_profiles() == []
    assert tenant_profiles.get("a") is None


# ── zia_rate: the state file, the clock, holds ──────────────────────────

@pytest.fixture
def rate(monkeypatch, tmp_path):
    """A fake clock that moves only when zia_rate sleeps, ZIA's documented
    limits, and a state file in tmp."""
    t = [1_800_000_000.0]
    sleeps = []
    monkeypatch.setattr(zia_rate, "_now", lambda: t[0])

    def sleep(s):
        sleeps.append(s)
        t[0] += s
    monkeypatch.setattr(zia_rate, "_sleep", sleep)
    for bucket in zia_rate.DEFAULTS:
        monkeypatch.delenv(f"DLP_CHECK_ZIA_LIMIT_{bucket.upper()}", raising=False)
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(tmp_path / "rate.json"))
    zia_rate.reset()
    return t, sleeps


def _restart(monkeypatch):
    """What a new process sees: no tenants in memory, the file not read yet."""
    monkeypatch.setattr(zia_rate, "_tenants", {"": zia_rate._Tenant()})
    monkeypatch.setattr(zia_rate, "_loaded", [False])


@pytest.mark.parametrize("damage", [
    {"version": 2, "tenants": {"k": {"sent": {"write": ["abc", None, [1], 5]}, "hold_until": "soon", "read_hold_until": {},
                                     "refused": [{"at": "x", "bucket": "write"}, {"bucket": "write"}, 3],
                                     "server": {"write": {"at": "y"}, "read": 4}}}},
    {"version": 2, "tenants": ["not", "a", "dict"]},
    {"version": 2, "tenants": {"k": {"sent": "write", "refused": "x", "server": []}}},
    {"sent": {"write": ["x"]}, "hold_until": "later", "refused": [{"at": None}]},
])
def test_a_damaged_rate_state_file_costs_only_its_bad_entries(rate, monkeypatch, tmp_path, damage):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: a damaged state file never raises in a paced request, a preflight or a hold."""
    (tmp_path / "rate.json").write_text(json.dumps(damage))
    _restart(monkeypatch)

    assert zia_rate.wait("POST", "/dlpDictionaries", key="k") >= 0
    assert zia_rate.forecast({"write": 3}, key="k")["severity"] in ("ok", "warn", "fail")
    assert zia_rate.hold(5, key="k") > 0


def test_a_clock_set_back_never_makes_a_write_wait_as_long_as_the_jump(rate):
    """ASVS V11.1.4 · CWE-682 · CWE-400 · WSTG-BUSL-07: after the clock moves back a day, the next write waits one window at most, not a day."""
    t, sleeps = rate
    zia_rate.wait("POST", "/dlpDictionaries", key="c")
    t[0] -= 86_400

    waited = zia_rate.wait("POST", "/dlpDictionaries", key="c")

    assert waited <= 1.0 * zia_rate.SECOND_MARGIN + 1e-9


@pytest.mark.parametrize("seconds, expected", [(float("inf"), WEEK), (1e300, WEEK),
                                               (float("nan"), 0.0), (-5, 0.0), (30, 30.0), ("12", 12.0), (None, 0.0)])
def test_a_hold_is_bounded_whatever_zia_answered(rate, seconds, expected):
    """ASVS V5.1.4 · CWE-20 · CWE-400 · WSTG-BUSL-05: a hold from an absurd reset header lasts a week at most, never forever, never negative."""
    t, _ = rate

    end = zia_rate.hold(seconds, key="h")

    assert zia_rate.paused_for("h") == pytest.approx(expected)
    assert end != float("inf")


def test_an_infinite_hold_is_never_written_to_the_state_file(rate, tmp_path):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: the state file never holds Infinity, which strict JSON readers refuse."""
    zia_rate.hold(float("inf"), key="h")

    safe_files.strict_json_loads((tmp_path / "rate.json").read_text())


def test_a_hold_survives_a_restart(rate, monkeypatch):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a hold after ZIA refused a write is still there when the app starts again."""
    zia_rate.hold(120, key="r")
    _restart(monkeypatch)

    assert zia_rate.paused_for("r") == pytest.approx(120)


def test_every_wait_sleeps_a_positive_step_through_holds_and_limits(rate):
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-07: pacing never asks to sleep zero or a negative time, through a hold and a full minute bucket."""
    t, sleeps = rate
    zia_rate.hold(7, key="p")
    for _ in range(12):
        zia_rate.wait("POST", "/endpointDlpRules", key="p")

    assert sleeps and all(s > 0 for s in sleeps)


def test_the_wait_message_tells_the_time_by_the_injected_clock(rate):
    """ASVS V7.1.3 · CWE-682 · WSTG-BUSL-07: 'next at HH:MM' comes from the app's clock (_now), the same one the wait is measured by."""
    t, _ = rate
    said = []
    for _ in range(10):
        zia_rate.wait("POST", "/endpointDlpRules", key="m")
    now = t[0]

    zia_rate.wait("POST", "/endpointDlpRules", log=said.append, key="m")

    expected = datetime.fromtimestamp(now + 60).strftime("%H:%M")
    assert said and f"next at {expected}" in said[0]


@pytest.mark.parametrize("value", ["1e999", "inf", "nan", "-inf"])
def test_a_non_finite_rate_limit_header_is_ignored(rate, value):
    """ASVS V5.1.4 · CWE-20 · CWE-190 · WSTG-INPV-13: x-ratelimit headers of 'inf' or '1e999' are ignored, never an OverflowError."""
    zia_rate.note_headers("write", {"x-ratelimit-limit": value, "x-ratelimit-remaining": "5"}, key="hd")

    assert "write" not in getattr(zia_rate._tenants.get("hd"), "server", {})


# ── sdk_client: masked errors, the classic session ended ────────────────

class _Helper:
    def __init__(self):
        self.ended = 0

    def deauthenticate(self):
        self.ended += 1


def test_closing_a_classic_api_client_ends_its_session():
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: closing the classic ZIA API client signs its JSESSIONID session out at ZIA."""
    import sdk_client
    cl = sdk_client.SdkClient("", "", "", "zscaler", auth_method="legacy", username="u", password="p", api_key="abcdefghijkl")
    helper = _Helper()
    cl._zs = tenant_auth.LegacyZiaClient(helper)

    cl.close()

    assert helper.ended == 1 and cl._zs is None


def test_an_sdk_error_that_echoes_a_token_is_returned_and_logged_masked(caplog):
    """ASVS V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: an SDK error echoing 'Bearer <token>' reaches neither the result nor the log."""
    import sdk_client
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eXoifQ.c2lnbmF0dXJlLXZhbHVl"

    data, code = sdk_client._sdk_call(lambda: (None, None, RuntimeError(f"401 for Authorization: Bearer {token}")))

    assert code == 0 and token not in json.dumps(data) and token not in caplog.text


def test_an_sdk_call_without_a_name_that_raises_is_an_error_result_not_a_crash():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a partial (no __name__) that raises gives {'error': ...}, not an AttributeError."""
    import sdk_client

    def boom(x):
        raise RuntimeError(f"bad {x}")

    data, code = sdk_client._sdk_call(functools.partial(boom, 1))

    assert code == 0 and data == {"error": "bad 1"}


def test_a_failed_sign_in_reads_as_its_reason_and_an_echoed_secret_is_masked():
    """ASVS V7.4.1 · CWE-209 · CWE-532 · WSTG-ERRH-01: get() after a failed sign-in says the reason, never a tuple, with the secret masked."""
    import sdk_client
    cl = sdk_client.SdkClient("cid-123456", SECRET, "acme", "zscaler")
    cl.auth = lambda: (False, "the tenant refused the sign-in")

    assert cl.get("/zia/webDlpRules") == ({"error": "the tenant refused the sign-in"}, 0)


def test_a_raw_get_error_that_echoes_the_client_secret_is_masked():
    """ASVS V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: a raw GET whose error repeats the client secret returns it masked."""
    import sdk_client
    cl = sdk_client.SdkClient("cid-123456", SECRET, "acme", "zscaler")

    class _Zs:
        def get_request_executor(self):
            raise RuntimeError(f"form body client_secret={SECRET} rejected")
    cl._zs = _Zs()

    data, code = cl.get("/zia/somethingNotRouted")

    assert code == 0 and SECRET not in json.dumps(data) and "[redacted client_secret]" in data["error"]


# ── tenant_fingerprint ──────────────────────────────────────────────────

def test_a_record_with_a_non_ascii_fingerprint_is_another_tenant_not_a_crash(monkeypatch, tmp_path):
    """ASVS V7.4.1 · CWE-755 · CWE-20 · WSTG-ERRH-01: a damaged record's non-ASCII tenant_fp is compared safely and does not match."""
    monkeypatch.setenv("DLP_CHECK_FINGERPRINT_KEY", str(tmp_path / "fp.key"))
    tenant_fingerprint._reset_cache()
    creds = {"auth_method": "legacy", "cloud": "zscaler", "username": "admin@acme.example", "password": "p", "api_key": "abcdefghijkl"}

    try:
        same = tenant_fingerprint.same_tenant({"tenant_fp": "é" * 16}, creds)
        mine = tenant_fingerprint.same_tenant({"tenant_fp": tenant_fingerprint.fingerprint(creds)}, creds)
    finally:
        tenant_fingerprint._reset_cache()

    assert same is False and mine is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_the_install_fingerprint_key_is_owner_only_and_never_replaced(monkeypatch, tmp_path):
    """ASVS V6.4.1 · CWE-732 · CWE-276 · WSTG-CONF-09: the HMAC key is created 0600 once; a second process keeps the first key."""
    path = tmp_path / "fp.key"
    monkeypatch.setenv("DLP_CHECK_FINGERPRINT_KEY", str(path))
    tenant_fingerprint._reset_cache()
    try:
        first = tenant_fingerprint.install_key()
        tenant_fingerprint._reset_cache()
        assert tenant_fingerprint._create(str(path)) == first
    finally:
        tenant_fingerprint._reset_cache()

    assert os.stat(path).st_mode & 0o777 == 0o600 and len(first) == 32


# ── security: the token comparison ──────────────────────────────────────

def test_the_ui_token_is_compared_with_compare_digest(monkeypatch):
    """ASVS V2.9.1 · CWE-208 · WSTG-ATHN-04: the UI token check goes through secrets.compare_digest on bytes, never ==."""
    monkeypatch.setattr(security, "_ui_token", "the-token-0123456789")
    calls = []
    real = security._secrets.compare_digest
    monkeypatch.setattr(security._secrets, "compare_digest", lambda a, b: calls.append((type(a), type(b))) or real(a, b))

    assert security.ui_token_ok("the-token-0123456789") and not security.ui_token_ok("the-token-012345678X")
    assert calls == [(bytes, bytes), (bytes, bytes)]


# ── tenant_profiles: ids, snapshots, history, the classic upgrade ───────

@pytest.mark.parametrize("given, expected", [("../../etc/passwd", "etc-passwd"), ("A" * 5000, "a" * 48), ("", "acme"),
                                             ("acme-2", "acme-2")])
def test_a_profile_id_from_the_request_is_one_this_app_makes(store, given, expected):
    """ASVS V5.1.3 · CWE-20 · CWE-22 · WSTG-INPV-01: an id that is not a profile id ('../x', 5000 characters) is slugified before it keys the store."""
    out = tenant_profiles.upsert({"name": "acme"}, profile_id=given)

    assert out["id"] == expected and tenant_profiles.get(expected)["id"] == expected


def test_an_existing_profile_with_an_older_long_id_is_still_updated(store, tmp_path):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a stored id longer than today's limit (an older upgrade suffix) keeps working."""
    old = "x" * 48 + "-2"
    (tmp_path / "tenant_profiles.json").write_text(json.dumps({"version": 1, "profiles": {old: {"id": old, "name": "old"}}}))

    out = tenant_profiles.upsert({"notes": "n"}, profile_id=old)

    assert out["id"] == old and out["notes"] == "n"


@pytest.fixture
def snaps(store, monkeypatch):
    monkeypatch.setattr(tenant_profiles, "MAX_SNAPSHOTS_PER_PROFILE", 2)
    tenant_profiles.upsert({"name": "acme"})
    return tenant_profiles


def test_a_profile_keeps_its_newest_snapshots_and_reads_them_back(snaps):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: a profile keeps MAX_SNAPSHOTS_PER_PROFILE snapshots, newest first, and reads each within its limit."""
    ids = [snaps.save_snapshot(f'{{"n": {i}}}', {"saved_at": f"2026-01-0{i + 1}"}, "acme")["id"] for i in range(3)]

    rows = snaps.list_snapshots("acme")

    assert [r["id"] for r in rows] == [ids[2], ids[1]]
    assert snaps.read_snapshot(ids[2], 100) == b'{"n": 2}'
    assert snaps.list_profiles()[0]["snapshots"][0]["id"] == ids[2]


@pytest.mark.parametrize("sid", ["../x", "snap-XYZ", "snap-0123456789abcdef0", 5])
def test_a_snapshot_id_the_app_did_not_make_is_refused(snaps, sid):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: a snapshot id that is not 'snap-<16 hex>' never becomes a path."""
    with pytest.raises(ValueError):
        snaps.read_snapshot(sid, 100)


def test_a_snapshot_too_large_missing_or_unlisted_is_refused_in_plain_words(snaps):
    """ASVS V12.1.1 · CWE-400 · CWE-209 · WSTG-ERRH-01: a snapshot over its limit, deleted from disk or not listed is a plain ValueError."""
    sid = snaps.save_snapshot('{"big": "' + "x" * 100 + '"}', {}, "acme")["id"]

    with pytest.raises(ValueError, match="too large"):
        snaps.read_snapshot(sid, 10)
    os.unlink(snaps.snapshot_path(sid))
    with pytest.raises(ValueError, match="missing"):
        snaps.read_snapshot(sid, 1000)
    with pytest.raises(ValueError, match="No such"):
        snaps.read_snapshot("snap-0000000000000000", 1000)


@pytest.mark.skipif(os.name == "nt", reason="POSIX links")
def test_a_snapshot_file_replaced_by_a_link_is_not_read(snaps, tmp_path):
    """ASVS V12.3.1 · CWE-59 · WSTG-ATHZ-01: a link planted in place of a snapshot file is not followed."""
    sid = snaps.save_snapshot("{}", {}, "acme")["id"]
    secret = tmp_path / "elsewhere.txt"
    secret.write_text("not a snapshot")
    os.unlink(snaps.snapshot_path(sid))
    os.symlink(secret, snaps.snapshot_path(sid))

    with pytest.raises(ValueError, match="missing"):
        snaps.read_snapshot(sid, 1000)


def test_deleting_a_profile_deletes_its_snapshots_and_pov(snaps):
    """ASVS V8.3.8 · CWE-459 · WSTG-CONF-04: a profile's snapshots and POV file go with it."""
    sid = snaps.save_snapshot("{}", {}, "acme")["id"]
    pov = snaps.pov_path("acme")
    safe_files.private_makedirs(os.path.dirname(pov))
    safe_files.write_private_atomic(pov, "{}")

    assert snaps.delete("acme") is True

    assert not os.path.exists(snaps.snapshot_path(sid)) and not os.path.exists(pov) and snaps.list_snapshots() == []
    assert snaps.delete("acme") is False and snaps.delete_snapshot(sid) is False


def test_a_snapshot_is_deleted_on_its_own(snaps):
    """ASVS V8.3.8 · CWE-459 · WSTG-CONF-04: deleting one snapshot removes its file and its listing."""
    sid = snaps.save_snapshot("{}", {}, "")["id"]

    assert snaps.list_snapshots("") and snaps.delete_snapshot(sid) is True

    assert snaps.list_snapshots("") == [] and not os.path.exists(snaps.snapshot_path(sid))


@pytest.mark.parametrize("bad", ["../acme", "", "A", None, "a" * 49])
def test_a_pov_path_needs_a_profile_id(bad):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: only a profile id becomes a POV file name."""
    with pytest.raises(ValueError):
        tenant_profiles.pov_path(bad)


def test_history_keeps_the_last_entries_and_the_queue_mark_is_kept(store, monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: history is bounded at HISTORY_LIMIT; an unknown profile gets None/False."""
    monkeypatch.setattr(tenant_profiles, "HISTORY_LIMIT", 3)
    tenant_profiles.upsert({"name": "acme"})
    for i in range(5):
        out = tenant_profiles.add_history("acme", {"score": i, "states": {"a": "P"}})

    assert [h["score"] for h in out["history"]] == [2, 3, 4] and "states" not in out["last_assessed"]
    assert tenant_profiles.add_history("nobody", {}) is None
    assert tenant_profiles.mark_proposal_queue_migrated("acme") is True and tenant_profiles.get("acme")["proposal_queue_migrated"]
    assert tenant_profiles.mark_proposal_queue_migrated("nobody") is False


def test_a_history_entry_is_compact_and_skips_out_of_scope_checks():
    """ASVS V8.3.4 · CWE-200 · WSTG-INFO-05: a history entry counts in-scope checks and keeps three next steps per baseline."""
    report = {"score": 71, "maturity": "Managed", "metadata": {"assessor": "Jo"},
              "checks": [{"id": "A", "state": "P"}, {"id": "B", "out_of_scope": True}],
              "critical": [{"id": "C"}, {"id": "D", "out_of_scope": True}],
              "journey": {"status": "ok", "stage": 2, "score": 50,
                          "baselines": [{"id": "b", "name": "B", "next_steps": ["1", "2", "3", "4"]}]}}

    e = tenant_profiles.snapshot(report)

    assert (e["checks"], e["critical"], e["assessor"]) == (1, 1, "Jo")
    assert e["journey"]["baselines"][0]["next_steps"] == ["1", "2", "3"]


def test_credentials_from_a_profile_never_carry_the_store_marker():
    """ASVS V2.10.4 · CWE-312 · WSTG-ATHN-06: a masked read's '@keyring' marker is never used as a secret."""
    c = tenant_profiles.creds_from({"client_secret": tenant_profiles.KEYRING_MARK, "password": "pw", "client_id": "cid"})

    assert c["client_secret"] == "" and c["password"] == "pw" and set(c) == set(tenant_auth.CRED_KEYS)


def test_a_classic_profile_named_after_its_login_is_renamed_with_its_secrets(store, tmp_path):
    """ASVS V8.3.4 · CWE-359 · WSTG-INFO-05: a classic-API profile id'd by its admin login moves to 'classic-api-…' with its remembered secrets."""
    store.items[("dlp-check", "admin-corp-example:password")] = "PW-1234567"
    (tmp_path / "tenant_profiles.json").write_text(json.dumps({"version": 1, "profiles": {"admin-corp-example": {
        "id": "admin-corp-example", "name": "admin@corp.example", "auth_method": "legacy", "username": "admin@corp.example",
        "cloud": "zscalertwo", "password": tenant_profiles.KEYRING_MARK}}}))

    rows = tenant_profiles.list_profiles()

    assert [r["id"] for r in rows] == ["classic-api-zscalertwo"] and rows[0]["name"] == "classic API (zscalertwo)"
    assert store.items == {("dlp-check", "classic-api-zscalertwo:password"): "PW-1234567"}
    kept = json.loads((tmp_path / "tenant_profiles.json").read_text())["profiles"]
    assert list(kept) == ["classic-api-zscalertwo"] and "admin" not in kept["classic-api-zscalertwo"]["name"]


def test_a_classic_profile_whose_secret_cannot_be_read_keeps_its_id(store, tmp_path, monkeypatch):
    """ASVS V8.3.8 · CWE-459 · WSTG-ERRH-01: when the credential store cannot be read, the profile keeps its id rather than lose the secret."""
    (tmp_path / "tenant_profiles.json").write_text(json.dumps({"version": 1, "profiles": {"admin-corp-example": {
        "id": "admin-corp-example", "name": "x", "auth_method": "legacy", "username": "admin@corp.example",
        "password": tenant_profiles.KEYRING_MARK}}}))
    monkeypatch.setitem(sys.modules, "keyring", None)

    assert [r["id"] for r in tenant_profiles.list_profiles()] == ["admin-corp-example"]


def test_secret_storage_names_where_a_secret_would_go(monkeypatch):
    """ASVS V2.10.4 · CWE-312 · WSTG-ATHN-06: 'keyring' with a store, 'file' only with the opt-in, else 'none'."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE", raising=False)
    assert tenant_profiles.secret_storage() == "none"
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    assert tenant_profiles.secret_storage() == "file"
    monkeypatch.setitem(sys.modules, "keyring", FakeKeyring())
    assert tenant_profiles.secret_storage() == "keyring"


# ── safe_files: ZIP members ─────────────────────────────────────────────

def _zip(tmp_path, method, data=b"hello world" * 10):
    import zipfile
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w", compression=method) as z:
        z.writestr("m.txt", data)
    return zipfile.ZipFile(p)


@pytest.mark.parametrize("method", ["stored", "deflated"])
def test_a_stored_or_deflated_member_is_read_whole(tmp_path, method):
    """ASVS V12.1.2 · CWE-409 · WSTG-BUSL-09: a stored or deflate member within its limit is read as it is."""
    import zipfile
    z = _zip(tmp_path, zipfile.ZIP_STORED if method == "stored" else zipfile.ZIP_DEFLATED)

    assert safe_files.zip_member(z, z.infolist()[0], 110) == b"hello world" * 10


def test_a_member_compressed_with_another_method_is_refused(tmp_path):
    """ASVS V12.1.2 · CWE-409 · CWE-400 · WSTG-BUSL-09: a BZIP2 member (a decompression bomb vector) is refused, deny by default."""
    import zipfile
    z = _zip(tmp_path, zipfile.ZIP_BZIP2)

    with pytest.raises(safe_files.ArchiveRefused, match="method"):
        safe_files.zip_member(z, z.infolist()[0], 10_000)


@pytest.mark.parametrize("limit, msg", [(109, "larger than 109 bytes"), (0, "larger than 0 bytes")])
def test_a_member_declaring_more_than_its_limit_is_refused(tmp_path, limit, msg):
    """ASVS V12.1.2 · CWE-409 · CWE-400 · WSTG-BUSL-09: a member that declares more than the limit (boundary: one byte over) is refused."""
    import zipfile
    z = _zip(tmp_path, zipfile.ZIP_DEFLATED)

    with pytest.raises(safe_files.ArchiveRefused, match=msg):
        safe_files.zip_member(z, z.infolist()[0], limit)


def test_an_encrypted_member_is_refused(tmp_path):
    """ASVS V12.1.2 · CWE-20 · WSTG-BUSL-09: a password-protected member is refused with what to do."""
    import zipfile
    z = _zip(tmp_path, zipfile.ZIP_STORED)
    info = z.infolist()[0]
    info.flag_bits |= 0x1

    with pytest.raises(safe_files.ArchiveRefused, match="password"):
        safe_files.zip_member(z, info, 10_000)


def test_a_member_whose_header_lies_about_its_size_is_refused_as_damaged(tmp_path):
    """ASVS V12.1.2 · CWE-409 · CWE-354 · WSTG-BUSL-09: a member whose data does not match its header (CRC) is refused, not a 500."""
    import zipfile
    z = _zip(tmp_path, zipfile.ZIP_DEFLATED)
    info = z.infolist()[0]
    info.file_size = 5

    with pytest.raises(safe_files.ArchiveRefused, match="damaged"):
        safe_files.zip_member(z, info, 10_000)


@pytest.mark.parametrize("text", ["NaN", "[Infinity]", '{"a": -Infinity}', "1e400"])
def test_strict_json_refuses_what_json_does_not_allow(text):
    """ASVS V5.5.3 · CWE-20 · WSTG-INPV-01: NaN, Infinity and a number too large for a double are refused."""
    with pytest.raises(ValueError):
        safe_files.strict_json_loads(text)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_private_makedirs_makes_every_new_folder_owner_only(tmp_path):
    """ASVS V8.3.6 · CWE-276 · CWE-732 · WSTG-CONF-09: every folder private_makedirs creates is 0700, the parents too."""
    deep = tmp_path / "a" / "b" / "c"

    safe_files.private_makedirs(str(deep))
    safe_files.private_makedirs(str(deep))   # idempotent

    assert all(os.stat(d).st_mode & 0o777 == 0o700 for d in (tmp_path / "a", tmp_path / "a" / "b", deep))


# ── sdk_client: routes and answer shapes, against a fake SDK ────────────

class _Model:
    def __init__(self, **kw):
        self.kw = kw

    def as_dict(self):
        return dict(self.kw)


class _Plain:
    def __init__(self):
        self.x = 1


class _Node:
    """Any attribute is another node; calling one answers (data, None, None)
    and records the call."""

    def __init__(self, answer, calls, path=""):
        self._answer, self._calls, self._path = answer, calls, path

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _Node(self._answer, self._calls, f"{self._path}.{name}")

    def __call__(self, *args, **kwargs):
        self._calls.append((self._path, args, kwargs))
        return self._answer(self._path, args, kwargs)


def _sdk(answer):
    import sdk_client
    calls = []
    cl = sdk_client.SdkClient("cid-123456", SECRET, "acme", "zscaler")
    cl._zs = _Node(answer, calls)
    cl._route_map = cl._build_route_map()
    return cl, calls


@pytest.mark.parametrize("data, expected, code", [
    ([_Model(a=1), {"b": 2}, _Plain(), 7], [{"a": 1}, {"b": 2}, {"x": 1}, 7], 200),
    (_Model(c=3), {"c": 3}, 200), ({"d": 4}, {"d": 4}, 200), (None, [], 204),
])
def test_an_sdk_answer_becomes_plain_data_and_is_cached(data, expected, code):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: models become dicts, None is an empty 204, and a second read is served from the cache."""
    cl, calls = _sdk(lambda p, a, k: (data, None, None))

    assert cl.get("/zia/webDlpRules") == (expected, code)
    cl.get("/zia/webDlpRules")

    assert len(calls) == 1 and calls[0][0] == ".zia.dlp_web_rules.list_rules"


def test_pac_files_and_saas_tenants_take_their_query_parameters():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: pacFiles pages and casbTenant/lite filters reach the SDK as query parameters."""
    cl, calls = _sdk(lambda p, a, k: ([], None, None))

    cl.get("/zia/pacFiles", {"page": 2, "pageSize": 50})
    cl.get("/zia/casbTenant/lite", {"activeOnly": "TRUE", "appType": "EMAIL"})

    assert calls[0][2] == {"query_params": {"page": 2, "page_size": 50}}
    assert calls[1][2] == {"query_params": {"active_only": True, "app_type": "EMAIL"}}


def test_cloud_app_rules_of_every_type_are_one_list_tagged_by_type():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: Cloud App Control rules listed per type come back as one list, each with its type."""
    from dlp_assessment_full_auto import _CAC_TYPES
    cl, calls = _sdk(lambda p, a, k: ([{"id": a[0]}], None, None) if a[0] == _CAC_TYPES[0] else (None, None, RuntimeError("no")))

    data, code = cl.get("/zia/cloudApplicationRules")

    assert code == 200 and data == [{"id": _CAC_TYPES[0], "type": _CAC_TYPES[0]}]


def test_cloud_app_rules_that_no_type_answers_give_the_first_error():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: when every type fails, the first error is returned, not an empty success."""
    cl, _ = _sdk(lambda p, a, k: (None, None, RuntimeError("refused")))

    assert cl.get("/zia/cloudApplicationRules") == ({"error": "refused"}, 0)


class _Resp:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def get_status(self):
        return self.status

    def get_body(self):
        return self.body


class _Executor:
    def __init__(self, answers):
        self.answers, self.routes = list(answers), []

    def create_request(self, method=None, endpoint=None, *a, params=None, **k):
        self.routes.append(endpoint)
        return {"endpoint": endpoint}, None

    def execute(self, request):
        return self.answers.pop(0)


@pytest.mark.parametrize("answer, expected", [
    ((_Resp(200, {"list": [_Model(a=1)]}), None), ([{"a": 1}], 200)),
    ((_Resp(200, '[{"a": 1}]'), None), ([{"a": 1}], 200)),
    ((_Resp(200, "not json"), None), ("not json", 200)),
    ((_Resp(0, {"k": 1}), None), ({"k": 1}, 200)),
    ((None, None), ([], 204)),
    ((None, RuntimeError("Bearer abcdefghijklmnop refused")), ({"error": "Bearer [redacted token] refused"}, 0)),
])
def test_a_raw_read_for_an_endpoint_the_sdk_lacks_is_plain_data(answer, expected):
    """ASVS V5.1.3 · CWE-20 · CWE-532 · WSTG-INPV-01: a raw GET's body is unwrapped, parsed or kept; its error is masked."""
    import sdk_client
    cl = sdk_client.SdkClient("cid-123456", SECRET, "acme", "zscaler")
    ex = _Executor([answer])
    cl._zs = type("Zs", (), {"get_request_executor": lambda self: ex})()

    assert cl.get("/zia/notInTheSdk") == expected


def test_client_connector_profiles_try_each_route_and_need_oneapi():
    """ASVS V4.1.1 · CWE-284 · WSTG-ATHZ-02: a ZCC profile page skips a 404 route; the classic sign-in is told plainly it has no ZCC."""
    import sdk_client
    cl = sdk_client.SdkClient("cid-123456", SECRET, "acme", "zscaler")
    ex = _Executor([(_Resp(404, None), None), (_Resp(200, {"total": 1}), None)])
    cl._zs = type("Zs", (), {"get_request_executor": lambda self: ex})()

    body, code = cl._zcc_profile_page("/zcc/appProfiles", {"page": 1})

    assert code == 200 and body == {"total": 1} and len(ex.routes) == 2
    legacy = sdk_client.SdkClient("", "", "", "zscaler", auth_method="legacy", username="u", password="p", api_key="abcdefghijkl")
    assert legacy._zcc_profile_page("/zcc/forwardingProfile")[1] == 404


def test_a_vanity_domain_that_is_not_a_dns_name_never_reaches_the_sign_in(monkeypatch):
    """ASVS V5.1.3 · CWE-918 · CWE-20 · WSTG-INPV-19: a vanity domain like 'evil.example/?' fails before any SDK client is built."""
    import sdk_client
    built = []
    monkeypatch.setattr(sdk_client, "ZscalerClient", lambda cfg: built.append(cfg))
    cl = sdk_client.SdkClient("cid-123456", SECRET, "evil.example/?", "zscaler")

    ok, msg = cl.auth()

    assert ok is False and built == [] and SECRET not in msg


def test_a_classic_sign_in_goes_through_the_legacy_helper_and_masks_its_failure(monkeypatch):
    """ASVS V7.4.1 · CWE-532 · WSTG-ERRH-01: the classic sign-in uses build_legacy_sdk_client, and a failure that echoes the password is masked."""
    import sdk_client

    def fail(creds, **kw):
        raise RuntimeError(f"login refused for password={creds['password']}")
    monkeypatch.setattr(tenant_auth, "build_legacy_sdk_client", fail)
    cl = sdk_client.SdkClient("", "", "", "zscaler", auth_method="legacy", username="u", password="Pa55-word-123", api_key="abcdefghijkl")

    ok, msg = cl.auth()

    assert ok is False and "Pa55-word-123" not in msg and "[redacted password]" in msg


def test_an_sdk_client_from_the_environment_carries_the_classic_sign_in(monkeypatch):
    """ASVS V2.10.4 · CWE-798 · WSTG-CONF-02: from_env reads the ZSCALER_* variables, the classic API too."""
    import sdk_client
    monkeypatch.setenv("ZSCALER_AUTH_METHOD", "legacy")
    monkeypatch.setenv("ZSCALER_USERNAME", "u")
    monkeypatch.setenv("ZSCALER_PASSWORD", "p")
    monkeypatch.setenv("ZSCALER_API_KEY", "abcdefghijkl")
    monkeypatch.setenv("ZSCALER_CLOUD", "zscalertwo")

    cl = sdk_client.from_env()

    assert cl._creds["auth_method"] == "legacy" and cl._creds["cloud"] == "zscalertwo" and cl._config["cloud"] == "production"


# ── security: the API rate limiter's clock ──────────────────────────────

def _limited_app():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()

    @app.get("/api/x")
    def x():
        return {"ok": True}
    app.add_middleware(security.RateLimitMiddleware, rps=1, burst=2)
    return TestClient(app)


def test_the_api_rate_limiter_survives_a_clock_that_goes_back(monkeypatch):
    """ASVS V11.1.4 · CWE-682 · CWE-400 · WSTG-BUSL-05: after its clock moves back a day, the limiter refills from then on instead of refusing for a day."""
    t = [100_000.0]
    monkeypatch.setattr(security, "_monotonic", lambda: t[0])
    client = _limited_app()
    assert [client.get("/api/x").status_code for _ in range(3)] == [200, 200, 429]

    t[0] -= 86_400
    client.get("/api/x")
    t[0] += 2

    assert client.get("/api/x").status_code == 200


def test_the_api_rate_limiter_refuses_a_burst_and_refills(monkeypatch):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: a burst past the bucket is 429 with Retry-After; a second later one more call fits."""
    t = [50.0]
    monkeypatch.setattr(security, "_monotonic", lambda: t[0])
    client = _limited_app()

    codes = [client.get("/api/x") for _ in range(3)]
    t[0] += 1.0

    assert [r.status_code for r in codes] == [200, 200, 429] and codes[2].headers["Retry-After"] == "1"
    assert client.get("/api/x").status_code == 200



def _limited_rw_app(client=("127.0.0.1", 50000)):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()

    @app.get("/api/status")
    def status():
        return {"ok": True}

    @app.post("/api/change")
    def change():
        return {"ok": True}
    app.add_middleware(security.RateLimitMiddleware, rps=1, burst=2)
    return TestClient(app, client=client)


def test_the_local_user_reading_pages_is_never_rate_limited(monkeypatch):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: with the token gate off (loopback only), a burst of page reads from this computer is never 429; its writes still are."""
    monkeypatch.setattr(security, "_monotonic", lambda: 10.0)   # no refill
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    c = _limited_rw_app()
    assert {c.get("/api/status", headers={"Host": "127.0.0.1:8000"}).status_code for _ in range(50)} == {200}
    assert [c.post("/api/change", headers={"Host": "127.0.0.1:8000"}).status_code for _ in range(3)] == [200, 200, 429]


def test_reads_from_beyond_loopback_or_a_rebinding_host_still_count(monkeypatch):
    """ASVS V11.1.4 · CWE-770 · CWE-350 · WSTG-BUSL-05: the exemption is the loopback user's only: another address, or a Host that is not a loopback name, is 429 after the burst."""
    monkeypatch.setattr(security, "_monotonic", lambda: 10.0)
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    far = _limited_rw_app(client=("10.66.0.9", 50000))
    assert [far.get("/api/status", headers={"Host": "127.0.0.1:8000"}).status_code for _ in range(3)] == [200, 200, 429]
    near = _limited_rw_app(client=("127.0.0.1", 50001))
    assert [near.get("/api/status", headers={"Host": "evil.example"}).status_code for _ in range(3)] == [200, 200, 429]


def test_with_the_token_gate_on_only_reads_carrying_the_token_are_exempt(monkeypatch):
    """ASVS V11.1.4 · ASVS V2.2.1 · CWE-307 · CWE-770 · WSTG-BUSL-05: reads with the UI token are never 429; the same reads without it, and writes even with it, are limited."""
    monkeypatch.setattr(security, "_monotonic", lambda: 10.0)
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    good = {security.UI_TOKEN_HEADER: security.ui_token(), "Host": "127.0.0.1:8000"}
    c = _limited_rw_app()
    assert {c.get("/api/status", headers=good).status_code for _ in range(50)} == {200}
    assert [c.post("/api/change", headers=good).status_code for _ in range(3)] == [200, 200, 429]
    anon = _limited_rw_app(client=("127.0.0.1", 50002))
    bad = {security.UI_TOKEN_HEADER: "not-the-token", "Host": "127.0.0.1:8000"}
    assert [anon.get("/api/status", headers=bad).status_code for _ in range(3)] == [200, 200, 429]


def test_a_signed_in_read_is_placed_without_raising(monkeypatch):
    """ASVS V11.1.4 · CWE-755: a caller lookup that fails counts the request instead of failing it."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_caller_for", lambda *a: (_ for _ in ()).throw(RuntimeError("store down")))
    monkeypatch.setattr(security, "_monotonic", lambda: 10.0)
    c = _limited_rw_app(client=("127.0.0.1", 50003))
    assert [c.get("/api/status").status_code for _ in range(3)] == [200, 200, 429]