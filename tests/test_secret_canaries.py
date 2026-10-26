"""Secrets never leave through a side door (QA T12).

Canary values stand in for the client secret, the classic API password and
API key, the UI token, the SMTP password and the digest webhook. Every
outbound HTTP request is answered by a fake that echoes the request back
in a 401 body (as a proxy or gateway error page can), so whatever the
Zscaler SDK or the assessment client puts in an exception carries the
secret, verbatim or encoded. Nothing here touches the network: the fake
sits in requests' transport adapter.

Each test's docstring names the control it maps to (OWASP ASVS 4.0.3 L2,
CWE, OWASP Top 10 2021, WSTG)."""
from __future__ import annotations

import json
import os
import smtplib
import stat
import sys

import pytest
import requests
from fastapi.testclient import TestClient
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import MaxRetryError, NewConnectionError

import tenant_auth

# Characters that change under URL and JSON encoding, so an echo of the
# form-encoded OAuth body or the JSON classic sign-in differs from the
# secret as typed.
CLIENT_SECRET = 'CANARYcs7Qx+/=&"\\9'
PASSWORD = 'CANARYpw4Lm+/=%"\\2'
API_KEY = "CANARYak12345678"          # the classic API key: 12+ characters
UI_TOKEN = "CANARYutTok3nQ9w8e7r6t5y"
SMTP_PASSWORD = "CANARYsmtp+/=Pw1"
WEBHOOK_SECRET = "CANARYwhB7c8D9e0F1g2"
SECRETS = {"client_secret": CLIENT_SECRET, "password": PASSWORD, "api_key": API_KEY}

CHANNELS = {k: "zscaler" for k in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it", "endpoint_scan",
                                   "ssl_inspection", "cloud_app_control", "device_control", "workflow_automation")}
SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac", "insights"]
ONEAPI = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclientid0001", "client_secret": CLIENT_SECRET,
          "customer_id": "216196257331281920", "scopes": SCOPES, "channels": CHANNELS, "from_page": True, "assessor": "QA tester",
          "pack_ids": ["fed_policy_pack"], "destination": "https://example.com", "destinations": ["https://example.com"]}
LEGACY = dict(ONEAPI, auth_method="legacy", client_id="", client_secret="", username="admin@acme.example", password=PASSWORD,
              api_key=API_KEY)

# Routes that restart, update or change the server's own mode: not a tenant sign-in.
NOT_SIGN_IN = {"/api/app/update", "/api/app/restart", "/api/write-mode", "/api/auth/logout", "/api/auth/unlock"}


def _forms(secret: str) -> set:
    """The secret as typed, URL/form-encoded (either case of %XX) and JSON-escaped."""
    import re
    from urllib.parse import quote, quote_plus
    forms = {secret, quote(secret, safe=""), quote_plus(secret, safe=""), json.dumps(secret)[1:-1]}
    return forms | {re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), f) for f in forms}


def _leaks(text: str, secrets=None) -> list:
    """Every form of every canary found in `text`, plus any 'CANARY' prefix
    with the first characters of a secret (a partial mask)."""
    text = str(text or "")
    found = [f for s in (secrets or list(SECRETS.values())) for f in _forms(s) if f in text]
    found += [s[:9] for s in (secrets or list(SECRETS.values())) if s[:9] in text]
    return sorted(set(found))


def _reflecting_send(self, request, **kw):
    """requests' transport: a 401 whose body echoes the request (URL, body,
    headers). Never opens a socket."""
    body = request.body.decode("utf-8", "replace") if isinstance(request.body, bytes) else request.body
    r = requests.models.Response()
    r.status_code = 401
    r._content = json.dumps({"error": "invalid_client", "you_sent": body, "url": request.url,
                             "headers": dict(request.headers)}).encode()
    r.headers["Content-Type"] = "application/json"
    r.url, r.request, r.encoding = request.url, request, "utf-8"
    return r


@pytest.fixture
def echo_api(monkeypatch):
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _reflecting_send)
    for k in [k for k in os.environ if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH"]:
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def app_client(echo_api, monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    import dlp_api_server as srv
    monkeypatch.setattr(srv, "_tenant_config_path", lambda: str(tmp_path / "none.json"), raising=False)
    return srv, TestClient(srv.app, raise_server_exceptions=False)


def _sign_in_routes():
    import dlp_api_server as srv
    out = []
    for r in srv.app.routes:
        if "POST" not in getattr(r, "methods", ()) or not r.path.startswith("/api/") or "{" in r.path or r.path in NOT_SIGN_IN:
            continue
        body = r.dependant.body_params
        model = (getattr(body[0], "type_", None) or getattr(getattr(body[0], "field_info", None), "annotation", None)) if body else None
        fields = getattr(model, "model_fields", {}) or {}
        if "client_secret" in fields:
            out.append(r.path)
    return sorted(out)


SIGN_IN_ROUTES = _sign_in_routes()


# ── masking ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("field", tenant_auth.SECRET_KEYS)
@pytest.mark.parametrize("encoding", ["typed", "form", "url", "url-lower", "json"])
def test_mask_secrets_hides_every_encoding_of_every_secret(field, encoding):
    """ASVS V7.1.1 · CWE-209 · CWE-532: a secret echoed in an error is masked as typed, URL/form-encoded and JSON-escaped."""
    import re
    from urllib.parse import quote, quote_plus
    secret = SECRETS[field]
    shown = {"typed": secret, "form": quote_plus(secret, safe=""), "url": quote(secret, safe=""),
             # some encoders write the %XX escapes in lower case
             "url-lower": re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), quote(secret, safe="")),
             "json": json.dumps(secret)[1:-1]}[encoding]
    text = f"Error authenticating: 401, sent {field}={shown}&grant_type=client_credentials"

    masked = tenant_auth.mask_secrets(text, SECRETS)

    assert not _leaks(masked), masked
    assert f"[redacted {field}]" in masked


def test_mask_secrets_leaves_identifiers_and_text_without_secrets_alone():
    """ASVS V7.1.1 · CWE-532: masking is exact (no secret, nothing changed; an identifier is not a secret)."""
    text = "client_id=acmeclientid0001 failed for acme (zscalerten)"

    assert tenant_auth.mask_secrets(text, SECRETS) == text
    assert tenant_auth.mask_secrets(text, {"client_secret": ""}) == text
    assert tenant_auth.mask_secrets("", SECRETS) == ""


def test_oneapi_sign_in_error_shows_no_character_or_length_of_the_secret(echo_api):
    """ASVS V7.1.1 · CWE-209 · WSTG-ERRH-01: a failed OneAPI sign-in names the client id, never part of the secret."""
    import dlp_api_server as srv
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as e:
        srv._build_sdk_client(dict(ONEAPI))

    detail = str(e.value.detail)
    assert e.value.status_code == 401
    assert not _leaks(detail), detail
    assert f"(len={len(CLIENT_SECRET)})" not in detail and CLIENT_SECRET[:3] + "…" not in detail


# ── every sign-in route ─────────────────────────────────────────────────
def test_the_route_table_is_not_empty():
    """ASVS V7.1.1 · CWE-209: the table-driven sweep below covers the sign-in routes (a refactor cannot empty it silently)."""
    assert len(SIGN_IN_ROUTES) >= 60, SIGN_IN_ROUTES
    assert "/api/tenant/check" in SIGN_IN_ROUTES and "/api/assess" in SIGN_IN_ROUTES


@pytest.mark.parametrize("path", SIGN_IN_ROUTES)
@pytest.mark.parametrize("method", ["oneapi", "legacy"])
def test_no_sign_in_route_returns_or_audits_a_secret_the_api_echoed(app_client, path, method, capsys):
    """ASVS V7.1.1 · ASVS V7.4.1 · CWE-209 · CWE-532 · A09:2021 · WSTG-ERRH-01: an echoed secret reaches no HTTP error body, job log, audit line or console print."""
    srv, c = app_client
    import audit
    import pack_jobs
    body = ONEAPI if method == "oneapi" else LEGACY

    r = c.post(path, json=body)
    texts = [r.text]
    job_id = (r.json() or {}).get("job_id") if r.headers.get("content-type", "").startswith("application/json") and isinstance(r.json(), dict) else None
    if job_id:
        job = pack_jobs.get(job_id)
        if job is not None and job.thread is not None:
            job.thread.join(30)
        texts.append(c.get(f"/api/dlp-packs/jobs/{job_id}").text)
    try:
        texts.append(open(audit.path(), encoding="utf-8").read())
    except OSError:
        pass
    out = capsys.readouterr()
    texts += [out.out, out.err]

    leaks = _leaks("\n".join(texts))
    assert not leaks, f"{path} [{method}] -> {r.status_code}: {leaks}"


# ── notifications (digest e-mail and webhook) ───────────────────────────
WEBHOOKS = [
    f"https://hooks.slack.com/services/T0001/B0001/{WEBHOOK_SECRET}",
    f"https://acme.webhook.office.com/webhookb2/{WEBHOOK_SECRET}/IncomingWebhook/abc/def",
    f"https://prod-01.westus.logic.azure.com/workflows/0a1b/triggers/manual/paths/invoke?api-version=2016-06-01&sig={WEBHOOK_SECRET}",
]


@pytest.mark.parametrize("url", WEBHOOKS)
def test_a_webhook_that_cannot_be_reached_is_recorded_without_its_url(monkeypatch, url):
    """ASVS V7.1.1 · ASVS V2.10.4 · CWE-532 · CWE-200: a failed digest webhook keeps the host and the error, never the URL's secret path or signature."""
    import continuous_eval as ce

    def unreachable(self, request, **kw):
        pool = HTTPSConnectionPool(request.url.split("/")[2], 443)
        raise requests.exceptions.ConnectionError(MaxRetryError(pool, request.path_url, NewConnectionError(pool, "Failed to establish a new connection")),
                                                  request=request)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", unreachable)

    res = ce._send_webhook("subject", "body", url)

    assert res["sent"] is False and res["why"].startswith("ConnectionError")
    assert WEBHOOK_SECRET not in json.dumps(res), res
    assert res["host"] == url.split("/")[2]


def test_a_webhook_error_page_that_echoes_the_url_is_scrubbed(monkeypatch):
    """ASVS V7.1.1 · CWE-532: a non-2xx webhook answer that repeats the URL is kept without it."""
    import continuous_eval as ce
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _reflecting_send)

    res = ce._send_webhook("subject", "body", WEBHOOKS[0])

    assert res["sent"] is False and res["status"] == 401
    assert WEBHOOK_SECRET not in json.dumps(res), res


def test_a_successful_webhook_records_no_url(monkeypatch):
    """ASVS V7.1.1 · CWE-532: the happy path records the host and status only."""
    import continuous_eval as ce

    def ok(self, request, **kw):
        r = requests.models.Response()
        r.status_code, r._content, r.request, r.url = 200, b"ok", request, request.url
        return r
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", ok)

    res = ce._send_webhook("subject", "body", WEBHOOKS[2])

    assert res == {"channel": "webhook", "sent": True, "host": WEBHOOKS[2].split("/")[2], "status": 200}


def test_an_smtp_error_that_repeats_the_password_is_recorded_without_it(monkeypatch):
    """ASVS V7.1.1 · ASVS V2.10.4 · CWE-532: a failed digest e-mail never keeps the SMTP password, in any encoding."""
    import continuous_eval as ce

    class Echo:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, **k): pass
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, f"5.7.8 rejected {user} {password} {json.dumps(password)}".encode())
        def send_message(self, m): pass
    monkeypatch.setattr(smtplib, "SMTP", Echo)
    monkeypatch.setenv("DLP_CHECK_SMTP_USER", "mailer")
    monkeypatch.setenv("DLP_CHECK_SMTP_PASSWORD", SMTP_PASSWORD)

    res = ce._send_email("subject", "body", {"host": "smtp.example.invalid", "port": 587, "to": "ops@example.invalid", "from": None, "tls": True})

    assert res["sent"] is False and res["why"].startswith("SMTPAuthenticationError")
    assert not _leaks(res["why"], [SMTP_PASSWORD]), res


# ── the secret store ────────────────────────────────────────────────────
class FakeKeyring:
    def __init__(self, fail=False):
        self.items, self.fail = {}, fail

    def set_password(self, service, key, value):
        if self.fail:
            raise RuntimeError("no backend")
        self.items[(service, key)] = value

    def get_password(self, service, key):
        return self.items.get((service, key))

    def delete_password(self, service, key):
        self.items.pop((service, key), None)


@pytest.fixture
def profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE", raising=False)
    import tenant_profiles as tp
    return tp


@pytest.mark.parametrize("opt_in", [False, True])
def test_the_credential_store_is_the_default_and_wins_over_the_file_opt_in(profiles, monkeypatch, opt_in):
    """ASVS V2.10.4 · ASVS V6.4.1 · CWE-312 · CWE-256: a remembered secret goes to the OS credential store; the profile file holds only a marker."""
    kr = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", kr)
    if opt_in:
        monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")

    out = profiles.upsert({"name": "acme", "vanity_domain": "acme", "client_id": "cid"}, client_secret=CLIENT_SECRET, remember_secret=True)

    assert profiles.secret_storage() == "keyring" and out["has_secret"] is True and "secret_warning" not in out
    raw = open(profiles.store_path(), encoding="utf-8").read()
    assert not _leaks(raw) and profiles.KEYRING_MARK in raw
    assert kr.items[(profiles.KEYRING_SERVICE, "acme")] == CLIENT_SECRET
    assert profiles.get("acme", with_secret=True)["client_secret"] == CLIENT_SECRET


def test_without_a_credential_store_the_secret_is_not_written_anywhere(profiles, monkeypatch):
    """ASVS V2.10.4 · CWE-312 · CWE-256: no usable credential store and no opt-in: not remembered, said so, nothing on disk (fail closed)."""
    monkeypatch.setitem(sys.modules, "keyring", FakeKeyring(fail=True))

    out = profiles.upsert({"name": "acme"}, client_secret=CLIENT_SECRET, password=PASSWORD, api_key=API_KEY, remember_secret=True)

    assert out["secret_warning"] == profiles.NOT_REMEMBERED and out["has_secret"] is False
    folder = os.path.dirname(profiles.store_path())
    assert not _leaks("".join(open(os.path.join(folder, f), encoding="utf-8").read() for f in os.listdir(folder)))


@pytest.mark.parametrize("then", ["forget", "delete", "replace"])
def test_a_forgotten_file_store_secret_is_not_kept_in_the_last_good_copy(profiles, monkeypatch, then):
    """ASVS V8.3.8 · ASVS V2.10.4 · CWE-226 · CWE-459: unticking remember, deleting the profile or replacing the secret leaves no copy of the old one on disk."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    profiles.upsert({"name": "acme", "vanity_domain": "acme", "client_id": "cid"}, client_secret=CLIENT_SECRET, remember_secret=True)
    profiles.upsert({"name": "other", "vanity_domain": "other", "client_id": "cid2"})   # last-good now holds the secret

    if then == "forget":
        profiles.upsert({"name": "acme"}, remember_secret=False)
    elif then == "delete":
        profiles.delete("acme")
    else:
        profiles.upsert({"name": "acme"}, client_secret="the-new-secret-value", remember_secret=True)

    folder = os.path.dirname(profiles.store_path())
    names = sorted(os.listdir(folder))
    assert names == ["tenant_profiles.json", "tenant_profiles.json.last-good"], names
    for n in names:
        assert not _leaks(open(os.path.join(folder, n), encoding="utf-8").read(), [CLIENT_SECRET]), n


def test_a_write_that_forgets_no_secret_keeps_the_previous_version_as_last_good(profiles, monkeypatch):
    """ASVS V8.3.8 · CWE-459: the last-good copy still holds the store as it was before an ordinary write."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    profiles.upsert({"name": "acme", "vanity_domain": "acme", "client_id": "cid"}, client_secret=CLIENT_SECRET, remember_secret=True)

    profiles.upsert({"name": "other", "vanity_domain": "other", "client_id": "cid2"})

    previous = json.load(open(profiles.store_path() + ".last-good", encoding="utf-8"))
    assert list(previous["profiles"]) == ["acme"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("umask", [0o022, 0o000])
def test_secret_and_data_files_are_owner_only_from_the_first_write(monkeypatch, tmp_path, umask):
    """ASVS V8.3.4 · CWE-276 · CWE-732 · A01:2021: the profile store, its last-good copy, the UI token file, the audit log, the digests and the Beacon and SSL coverage histories are created owner-only whatever the umask."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_DIGESTS", str(tmp_path / "digests"))
    import audit
    import beacon
    import continuous_eval as ce
    import security
    import ssl_coverage
    import tenant_profiles as tp
    old = os.umask(umask)
    try:
        tp.upsert({"name": "acme"}, client_secret=CLIENT_SECRET, remember_secret=True)
        tp.upsert({"name": "other"})
        audit.record("qa_probe", note="x")
        security.write_ui_token_file(str(tmp_path))
        ce.write_digest({"id": "20260101-000000", "summary": {}, "notified": []})
        beacon.save_history([{"at": "2026-01-01T00:00:00Z"}], path=str(tmp_path / "beacon_state.json"))
        ssl_coverage.record("acme", {"coverage": {}}, path=str(tmp_path / "ssl_coverage.json"))
    finally:
        os.umask(old)

    loose = {}
    for dp, dn, fn in os.walk(tmp_path):
        for n in dn + fn:
            p = os.path.join(dp, n)
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & 0o077:
                loose[os.path.relpath(p, tmp_path)] = oct(mode)
    assert not loose, loose


# ── self-healing's sign-in reset ────────────────────────────────────────
def test_self_heal_sign_in_reset_logs_and_keeps_nothing_sensitive(monkeypatch, tmp_path, caplog, capsys):
    """ASVS V7.1.1 · ASVS V3.3.1 · CWE-532: dropping a failing cached sign-in records counts only, never the token or a credential."""
    import audit
    import self_heal as sh
    from zscaler.oneapi_oauth_client import OAuth

    class Cached:
        cleared = False
        access_token = "CANARYatAccessToken0001"
        _config = {"client": {"clientId": "acmeclientid0001", "clientSecret": CLIENT_SECRET}}

        def clear_access_token(self):
            Cached.cleared = True
    monkeypatch.setenv("DLP_CHECK_SELF_HEAL_STATE", str(tmp_path / "self_heal.json"))
    monkeypatch.setattr(OAuth, "_instance", Cached(), raising=False)
    monkeypatch.setattr(OAuth, "_last_config", Cached._config, raising=False)
    monkeypatch.setattr(sh, "_AUTH_FAILURES", [])
    now = 1_800_000_000.0   # injected clock
    for _ in range(3):
        sh._AUTH_FAILURES.append(now - 5)
    monkeypatch.setattr(sh, "CHECKS", [("sign_in", "Signing in to Zscaler", lambda: sh.check_sign_in(now=now))])   # this check only
    caplog.set_level("DEBUG")

    run = sh.run("manual")

    res = run["checks"][0]
    assert res["status"] == sh.HEALED and Cached.cleared and OAuth._instance is None
    assert "self_heal_run" in open(audit.path(), encoding="utf-8").read(), "the reset is audited"
    everything = json.dumps([res, run]) + open(audit.path(), encoding="utf-8").read() + caplog.text + "".join(capsys.readouterr())
    assert not _leaks(everything, [CLIENT_SECRET, "CANARYatAccessToken0001"]), everything[-600:]
    assert "acmeclientid0001" not in everything


def test_self_heal_sign_in_check_does_nothing_below_the_threshold(monkeypatch):
    """ASVS V7.1.1 · CWE-532: two failures are not a pattern; nothing is dropped."""
    import self_heal as sh
    monkeypatch.setattr(sh, "_AUTH_FAILURES", [1_800_000_000.0 - 5] * 2)

    res = sh.check_sign_in(now=1_800_000_000.0)

    assert res["status"] == sh.OK and len(sh._AUTH_FAILURES) == 2


# ── Client Connector profile settings (ZCC fleet drift view) ────────────
@pytest.mark.parametrize("path", [
    ("iosPolicy", "passcode"),                 # zcc/models/webpolicy.py IOSPolicy.passcode
    ("policyExtension", "exitPass"),           # zcc/models/secrets_passwords.py
    ("uninstallPass",), ("zpaDisablePass",), ("zdSettingsAccessPass",), ("logoutPass",),
    ("vpnCredentials", "preSharedKey"), ("settings", "private_key"), ("passphrase",), ("uninstallPassword",),
])
def test_zcc_profile_settings_never_carry_a_password_passcode_or_key(path):
    """ASVS V8.3.4 · ASVS V7.1.1 · CWE-200 · CWE-312: the fleet's profile settings show whether a secret is set, never its value."""
    import zcc_fleet as zf
    profile = {"id": 7, "name": "Corp iOS", "strictEnforcement": 1, "bypassApps": ["teams"], "appBypass": {"enabled": True}}
    node = profile
    for k in path[:-1]:
        node = node.setdefault(k, {})
    node[path[-1]] = "CANARYzccSecret0001"

    masked = zf.mask_settings(profile)

    text = json.dumps(masked)
    assert "CANARYzccSecret0001" not in text and '"(set)"' in text
    assert masked["strictEnforcement"] == 1 and masked["bypassApps"] == ["teams"] and masked["appBypass"] == {"enabled": True}


@pytest.mark.parametrize("key", ["bypass", "bypassApps", "addAppBypassToVPNGateway", "compass", "strictEnforcement", "passThroughCount"])
def test_zcc_settings_that_are_not_secrets_stay_visible(key):
    """ASVS V8.3.4 · CWE-200: the secret test is by name and does not hide ordinary settings ("bypass" is not a password)."""
    import zcc_fleet as zf

    assert zf.mask_settings({key: "visible-value"}) == {key: "visible-value"}


# ── the UI token ────────────────────────────────────────────────────────
def _ui_token_on(monkeypatch):
    import security
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_UI_TOKEN", UI_TOKEN)
    monkeypatch.setattr(security, "_ui_token", None)


def _pages():
    import dlp_api_server as srv
    return ["/", "/simple"] + sorted(r.path for r in srv.app.routes
                                     if "GET" in getattr(r, "methods", ()) and r.path.startswith("/report/") and "{" not in r.path)


@pytest.mark.parametrize("page", _pages())
def test_no_html_page_carries_the_ui_token(monkeypatch, page):
    """ASVS V3.1.1 · ASVS V8.3.1 · CWE-598 · CWE-200 · WSTG-INFO-05: a page served to a signed-in browser never embeds the UI token (it lives in an HttpOnly cookie)."""
    _ui_token_on(monkeypatch)
    import dlp_api_server as srv
    c = TestClient(srv.app)
    c.get("/?token=" + UI_TOKEN, follow_redirects=False)   # the launcher's way in: sets the cookie

    r = c.get(page)

    assert r.status_code == 200, page
    assert UI_TOKEN not in r.text


def test_the_ui_token_reaches_no_audit_line_url_or_error_in_any_form_it_is_offered(monkeypatch, tmp_path):
    """ASVS V3.1.1 · ASVS V7.1.1 · CWE-598 · CWE-532 · WSTG-SESS-04: the token offered by URL, header, Bearer, cookie or the unlock box, right or wrong, is never written or echoed."""
    _ui_token_on(monkeypatch)
    import audit
    import dlp_api_server as srv
    c = TestClient(srv.app)
    wrong = UI_TOKEN[:-1] + "X"

    answers = [
        c.get("/?token=" + UI_TOKEN, follow_redirects=False),
        c.get("/?token=" + wrong, follow_redirects=False),
        c.post("/api/auth/unlock", json={"token": UI_TOKEN}),
        c.post("/api/auth/unlock", json={"token": wrong}),
        TestClient(srv.app).post("/api/tenant-profiles", json={"name": "x"}, headers={"X-DLP-Check-Token": wrong}),
        TestClient(srv.app).post("/api/tenant-profiles", json={"name": "x"}, headers={"Authorization": "Bearer " + wrong}),
        TestClient(srv.app).post("/api/rate-check", json={}, headers={"X-DLP-Check-Token": UI_TOKEN}),
        TestClient(srv.app, cookies={"dlpcheck_token": wrong}).post("/api/rate-check", json={}),
    ]

    redirect = answers[0]
    assert redirect.status_code in (302, 303, 307) and UI_TOKEN not in redirect.headers.get("location", "")
    bodies = "\n".join(a.text for a in answers)
    log = open(audit.path(), encoding="utf-8").read()
    assert "auth_denied" in log, "the refusals are audited"
    for token in (UI_TOKEN, wrong):
        assert token not in bodies and token not in log


# ── the git repository ──────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(*args):
    import subprocess
    try:
        return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def _in_git_checkout():
    r = _git("rev-parse", "--is-inside-work-tree")
    return r is not None and r.returncode == 0 and r.stdout.strip() == "true"


def _store_temporaries():
    """Every atomic-write temporary a top-level module creates in the app's
    own folders: tempfile.mkstemp(prefix=..., suffix=..., dir=...) calls."""
    import re
    out = []
    for name in sorted(os.listdir(ROOT)):
        if not name.endswith(".py"):
            continue
        src = open(os.path.join(ROOT, name), encoding="utf-8").read()
        for m in re.finditer(r"mkstemp\(([^)]*)\)", src):
            args = m.group(1)
            if "dir=" not in args:
                continue   # the system temp folder, not the app's
            prefix = re.search(r"prefix=[\"']([^\"']*)[\"']", args)
            suffix = re.search(r"suffix=[\"']([^\"']*)[\"']", args)
            out.append((name, (prefix.group(1) if prefix else "tmp") + "q1w2e3" + (suffix.group(1) if suffix else "")))
    return out


def test_every_store_writer_is_found():
    """SSDF PW.4 · CWE-538: the temporaries table below is built from the code (a refactor cannot empty it silently)."""
    names = [t for _, t in _store_temporaries()]

    assert any(n.startswith(".profiles-") for n in names) and any(n.startswith(".ui_token_") for n in names)


@pytest.mark.skipif(not _in_git_checkout(), reason="needs the git checkout")
@pytest.mark.parametrize("module,temp", _store_temporaries())
def test_a_store_temporary_left_by_a_crash_is_never_committed(module, temp):
    """ASVS V8.3.4 · SSDF PS.1 · CWE-538 · CWE-312: a temporary a crash leaves in the app folder (it can hold a remembered secret or the UI token) is git-ignored."""
    r = _git("check-ignore", "-q", "--no-index", temp)

    assert r is not None and r.returncode == 0, f"{module} writes {temp!r} in the app folder and git would offer to commit it"


SECRET_PATTERNS = {
    "private key block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{40,}",
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub token": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}",
    "Slack token": r"\bxox[abposr]-[0-9A-Za-z-]{10,}",
    "Slack webhook": r"hooks\.slack\.com/services/T[0-9A-Z]{6,}/B[0-9A-Z]{6,}/[0-9A-Za-z]{20,}",
    "Teams webhook": r"webhook\.office\.com/webhookb2/[0-9a-f-]{30,}@",
    "Power Automate signature": r"logic\.azure\.com[^\s\"']*[?&]sig=[A-Za-z0-9_%-]{20,}",
    "Google API key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "Anthropic or OpenAI key": r"\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}",
}
# Deliberate test corpora: synthetic text a DLP engine must catch.
SECRET_SCAN_ALLOW = {("tools/validate_detection.py", "private key block")}


def _tracked_text_files():
    r = _git("ls-files", "-z")
    files = [f for f in r.stdout.split("\0") if f] if r is not None and r.returncode == 0 else []
    binary = (".png", ".ico", ".jpg", ".gif", ".docx", ".xlsx", ".pdf", ".woff", ".woff2", ".zip")
    return [f for f in files if not f.endswith(binary)]


@pytest.mark.skipif(not _in_git_checkout(), reason="needs the git checkout")
def test_no_tracked_file_carries_a_real_looking_credential():
    """SSDF PS.1 · ASVS V2.10.4 · CWE-798 · CWE-540: no committed file (code, *.example, fixtures) holds a private key, cloud token or webhook secret."""
    import re
    pats = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}
    hits = []

    for f in _tracked_text_files():
        try:
            text = open(os.path.join(ROOT, f), encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        hits += [(f, k) for k, p in pats.items() if p.search(text) and (f, k) not in SECRET_SCAN_ALLOW]

    assert not hits, hits


@pytest.mark.skipif(not _in_git_checkout(), reason="needs the git checkout")
@pytest.mark.parametrize("name", ["local_settings.env.example", "local_settings.bat.example", "tenant_config_sample.json"])
def test_example_settings_leave_every_secret_blank_or_a_placeholder(name):
    """ASVS V2.10.4 · CWE-798 · CWE-259: the example settings name each secret but carry no value for it."""
    import re
    text = open(os.path.join(ROOT, name), encoding="utf-8").read()
    if name.endswith(".json"):
        values = [str(v) for k, v in json.loads(text).items() if re.search(r"(?i)secret|password|api_?key|token|webhook", k)]
    else:
        line = re.compile(r"(?im)^[ \t]*(?:#|REM[ \t]+)?[ \t]*(?:set[ \t]+)?[A-Z_]*(?:SECRET|PASSWORD|API_KEY|TOKEN|WEBHOOK)[A-Z_]*=(.*)$")
        values = [m.group(1).strip() for m in line.finditer(text)]

    assert values, f"{name} names no secret: the test would prove nothing"
    assert all(v in ("", "...") or v.startswith(("YOUR_", "https://example.")) for v in values), values


# ── what the browser extension keeps (chrome.storage.session) ───────────
TENANT_SECRETS = {"psk": "CANARYpskTenant0001", "private_key": "CANARYpkTenant0002", "file_password": "CANARYdfpTenant0003"}
PEM = "-----BEGIN PRIVATE KEY-----\n" + TENANT_SECRETS["private_key"] + "\n-----END PRIVATE KEY-----"


def _poisoned(obj):
    """`obj` with the secrets a tenant object can carry added beside its name."""
    return dict(obj, preSharedKey=TENANT_SECRETS["psk"], vpnCredentials=[{"id": 1, "type": "UFQDN", "preSharedKey": TENANT_SECRETS["psk"]}],
                privateKey=PEM, certificate=PEM, debugMode={"allowed": True, "filePassword": TENANT_SECRETS["file_password"]})


def test_the_console_index_the_extension_stores_holds_no_tenant_secret():
    """ASVS V8.2.2 · ASVS V8.3.4 · CWE-922 · CWE-312: the index kept in the extension's session storage carries names and counts only, never a PSK, private key or isolation debug password."""
    import console_index as ci
    from test_console_index import _inventory, _zia, _zia_rules
    rules = _zia_rules()
    for policy, items in rules.items():
        rules[policy] = [_poisoned(dict(r, locations=[_poisoned(x) for x in r.get("locations") or []],
                                        locationGroups=[_poisoned(x) for x in r.get("locationGroups") or []])) for r in items]

    idx = ci.from_inventory(_inventory(), zia=_zia(rules=rules), now=1)

    blob = json.dumps(idx)
    assert idx["objects"], "the index was built"
    assert not [v for v in TENANT_SECRETS.values() if v in blob]
