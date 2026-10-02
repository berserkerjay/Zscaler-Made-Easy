"""The classic ZIA API sign-in (admin username, password, API key) beside
the ZIdentity API client, from every entry point: the credential dict
(tenant_auth), the cloud table, saved profiles, the server's resolution and
validation, the SDK client, the raw-HTTP assessment client and the page."""
from __future__ import annotations

import json
import os
import re

import pytest

import tenant_auth as ta
import zscaler_clouds as zc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY = {"auth_method": "legacy", "cloud": "zscalerten", "username": "api-admin@acme.com", "password": "Pa55word!", "api_key": "aBcDeFgHiJkL"}
ONEAPI = {"cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}


# ---------------------------------------------------------------------------
# The credential dict and the cloud table
# ---------------------------------------------------------------------------

def test_the_method_is_stated_or_inferred_and_completeness_follows_it():
    assert ta.method_of(ONEAPI) == "oneapi" and ta.method_of(LEGACY) == "legacy"
    assert ta.method_of({"username": "u", "api_key": "k"}) == "legacy", "a username without a client id means the classic sign-in"
    assert ta.method_of({"client_id": "c", "username": "u"}) == "oneapi", "a client id wins when nothing is stated"
    for spelling in ("Legacy", "classic", "ZIA", "api_key", "legacy-api"):
        assert ta.normalize_method(spelling) == "legacy", spelling
    for spelling in ("OneAPI", "zidentity", "oauth2", ""):
        assert ta.normalize_method(spelling) in ("oneapi", ""), spelling
    with pytest.raises(ValueError, match="Unknown sign-in method"):
        ta.normalize_method("magic")
    assert ta.complete(ONEAPI) and ta.complete(LEGACY)
    assert ta.missing(dict(LEGACY, api_key="")) == ["api_key"] and ta.missing({"auth_method": "legacy"}) == ["username", "password", "api_key"]
    assert ta.missing({"client_id": "c"}) == ["vanity_domain", "client_secret"]
    n = ta.normalize({"username": " u ", "api_key": "k"})
    assert set(n) == set(ta.CRED_KEYS) and n["username"] == "u" and n["auth_method"] == "legacy"
    # The admin login is never part of a label (user rule 3), and is masked in an identity.
    assert ta.label(LEGACY) == "classic API (zscalerten)" and ta.label(ONEAPI) == "acme (production)"
    assert ta.identity(LEGACY).startswith("username=api") and "api-admin@acme.com" not in ta.identity(LEGACY) and "abc" in ta.identity(ONEAPI) and "abc123456789" not in ta.identity(ONEAPI)


def test_secrets_are_masked_in_text_and_the_environment_and_profiles_fill_blanks():
    text = "refused Pa55word! and aBcDeFgHiJkL and secret-secret-secret"
    masked = ta.mask_secrets(text, dict(LEGACY, client_secret="secret-secret-secret"))
    assert "Pa55word!" not in masked and "aBcDeFgHiJkL" not in masked and "secret-secret-secret" not in masked
    assert masked == "refused [redacted password] and [redacted api_key] and [redacted client_secret]", masked
    # Nothing of a secret survives: no leading or trailing characters, no length.
    assert "Pa5" not in masked and "rd!" not in masked and "aBc" not in masked and "jkL" not in masked and "len=" not in masked
    env = {"ZSCALER_AUTH_METHOD": "legacy", "ZSCALER_CLOUD": "zscalerten", "ZSCALER_USERNAME": "u@acme.com", "ZSCALER_PASSWORD": "p", "ZSCALER_API_KEY": "k"}
    e = ta.from_env(env)
    assert e["auth_method"] == "legacy" and e["username"] == "u@acme.com" and e["cloud"] == "zscalerten" and ta.complete(e)
    merged = ta.merge({"cloud": "zscloud", "username": ""}, e)
    assert merged["cloud"] == "zscloud" and merged["username"] == "u@acme.com", "typed values win, blanks are filled"
    stripped = ta.without_identity(dict(LEGACY, vanity_domain="v"))
    assert stripped["username"] == "" and stripped["password"] == "" and stripped["cloud"] == "zscalerten" and stripped["vanity_domain"] == "v"


def test_the_classic_api_host_follows_the_cloud():
    assert zc.legacy_api_base("zscalerten") == "https://zsapi.zscalerten.net" and zc.legacy_api_base("zscloud.net") == "https://zsapi.zscloud.net"
    assert zc.legacy_api_base("production") == "https://zsapi.zscaler.net", "Commercial without a cloud name means zscaler.net"
    assert zc.legacy_api_base("zscalergov") == "https://zsapi.zscalergov.net" and zc.legacy_api_base("govus") == "https://zsapi.zscalergov.us"
    assert zc.legacy_api_base("beta") == "https://zsapi.zscalerbeta.net" and zc.legacy_cloud_name("admin.zscalerten.net") == "zscalerten"


def test_the_api_key_is_obfuscated_exactly_as_the_sdk_does_it():
    zscaler_utils = pytest.importorskip("zscaler.utils")
    import time
    now_ms = 1_757_980_000_123
    real_time = time.time
    time.time = lambda: now_ms / 1000.0
    try:
        theirs = zscaler_utils.obfuscate_api_key(list(LEGACY["api_key"]))
    finally:
        time.time = real_time
    ts, key = ta.obfuscate_api_key(LEGACY["api_key"], now_ms)
    assert (ts, key) == (theirs["timestamp"], theirs["key"])
    payload = ta.legacy_login_payload("u", "p", LEGACY["api_key"], now_ms)
    assert payload == {"apiKey": key, "username": "u", "password": "p", "timestamp": ts}
    with pytest.raises(ValueError, match="12 characters"):
        ta.obfuscate_api_key("short")


# ---------------------------------------------------------------------------
# The raw-HTTP assessment client
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status, body=None, text="", cookies=None):
        self.status_code, self._body, self.text, self.headers = status, body, text, {}
        self.cookies = cookies or {}

    def json(self):
        return self._body


class _Session:
    """A requests.Session stand-in that behaves like zsapi.<cloud>.net."""

    def __init__(self):
        self.headers, self.cookies, self.calls = {}, {}, []

    def post(self, url, json=None, data=None, headers=None, timeout=None):
        self.calls.append(("POST", url, json))
        if url.endswith("/api/v1/authenticatedSession"):
            body = json or {}
            if body.get("username") == LEGACY["username"] and body.get("password") == LEGACY["password"] and len(body.get("apiKey", "")) == 12 and body.get("timestamp"):
                self.cookies["JSESSIONID"] = "sess-1"
                return _Resp(200, {"authType": "ADMIN_LOGIN", "obfuscateApiKey": True})
            # A refusal that echoes what was sent (the client must mask it).
            return _Resp(401, text='{"code":"AUTHENTICATION_FAILED","message":"Invalid username or password: ' + str(body.get("password")) + '"}')
        return _Resp(404, text="no such route")

    def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url, params))
        if not self.cookies.get("JSESSIONID"):
            return _Resp(401, text="no session")
        if url == "https://zsapi.zscalerten.net/api/v1/webDlpRules":
            return _Resp(200, [{"id": 1, "name": "Rule"}])
        return _Resp(404, text="no such route")

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw.get("json")))
        return _Resp(200, {"ok": True})

    def delete(self, url, timeout=None):
        self.calls.append(("DELETE", url, None))
        return _Resp(204)


def _client(monkeypatch, **over):
    import dlp_assessment_full_auto as fa
    sess = _Session()
    monkeypatch.setattr(fa.requests, "Session", lambda: sess)
    creds = dict(LEGACY, **over)
    c = fa.Client("", "", "", creds["cloud"], "", auth_method=creds["auth_method"], username=creds["username"],
                  password=creds["password"], api_key=creds["api_key"])
    return c, sess


def test_the_assessment_client_signs_in_to_the_classic_api_and_maps_zia_paths(monkeypatch):
    c, sess = _client(monkeypatch)
    assert c.legacy and c.base == "https://zsapi.zscalerten.net"
    assert c.auth() is True and sess.cookies["JSESSIONID"] == "sess-1"
    assert sess.calls[0][1] == "https://zsapi.zscalerten.net/api/v1/authenticatedSession"
    data, status = c.get("/zia/webDlpRules")
    assert status == 200 and data[0]["name"] == "Rule"
    assert sess.calls[-1][1] == "https://zsapi.zscalerten.net/api/v1/webDlpRules", "a /zia/ short path becomes /api/v1/ on the classic host"
    for other in ("/zcc/getDevices", "/zpa/applications", "/zdx/apps", "/zid/users"):
        data, status = c.get(other)
        assert status == 404 and "classic ZIA API sign-in" in data["error"] and data.get("legacy"), other
    assert c.post("/zpa/x", {})[1] == 404 and c.put("/zia/webDlpRules/1", {"a": 1}) == ({"ok": True}, 200)
    assert sess.calls[-1] == ("PUT", "https://zsapi.zscalerten.net/api/v1/webDlpRules/1", {"a": 1})
    c.close()
    assert sess.calls[-1][0] == "DELETE" and c.token is None


def test_a_refused_classic_sign_in_is_reported_without_the_password(monkeypatch):
    c, sess = _client(monkeypatch, password="wrong-password")
    ok = c.auth()
    assert ok is not True and ok[0] is False and "HTTP 401" in ok[1] and "AUTHENTICATION_FAILED" in ok[1]
    assert "wrong-password" not in ok[1] and "[redacted password]" in ok[1], "the password is redacted in the reason"
    assert "wro" not in ok[1] and "len=" not in ok[1], "no characters and no length of the password are shown"
    assert not sess.cookies


def test_the_oneapi_client_is_unchanged(monkeypatch):
    import dlp_assessment_full_auto as fa
    c = fa.Client("id", "sec", "acme", "zscalerten", "")
    assert not c.legacy and c.base == "https://api.zsapi.net" and fa._resolve_ep("/zia/webDlpRules") == "/zia/api/v1/webDlpRules"
    assert fa._resolve_ep("/zia/webDlpRules", legacy=True) == "/api/v1/webDlpRules" and fa._resolve_ep("/zcc/x", legacy=True) is None


# ---------------------------------------------------------------------------
# Profiles, the server's resolution and validation, the SDK client
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setattr("tenant_profiles._keyring", lambda: None)
    for var in ta.ENV.values():
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def test_a_profile_remembers_the_classic_secrets_and_never_shows_them(store):
    import tenant_profiles as tp
    row = tp.upsert({"name": "Acme Legacy", "cloud": "zscalerten", "auth_method": "legacy", "username": LEGACY["username"]},
                    password=LEGACY["password"], api_key=LEGACY["api_key"], remember_secret=True)
    assert row["id"] == "acme-legacy" and row["auth_method"] == "legacy" and row["has_secret"] is True
    assert "Pa55word!" not in json.dumps(row) and "aBcDeFgHiJkL" not in json.dumps(row)
    creds = tp.creds_from(tp.get("acme-legacy", with_secret=True))
    assert creds["password"] == LEGACY["password"] and creds["api_key"] == LEGACY["api_key"] and creds["auth_method"] == "legacy" and ta.complete(creds)
    assert tp.creds_from(tp.get("acme-legacy")) ["password"] == "", "a masked read carries no secret"
    # Only one of the two remembered: not "remembered" for the classic sign-in.
    tp.upsert({"name": "Half"}, password="p", remember_secret=True, profile_id="half")
    assert tp.get("half")["has_secret"] is False
    # Forgetting drops both.
    assert tp.upsert({}, remember_secret=False, profile_id="acme-legacy")["has_secret"] is False
    assert tp.get("acme-legacy", with_secret=True).get("password") is None
    # An older profile with no method stored is read as OneAPI.
    tp.upsert({"name": "Old", "client_id": "cid1"}, client_secret="s", remember_secret=True, profile_id="old")
    assert tp.get("old")["auth_method"] == "oneapi" and tp.get("old")["has_secret"] is True


def test_the_server_resolves_and_validates_both_sign_ins(store, monkeypatch):
    import dlp_api_server as srv
    from fastapi import HTTPException
    creds = srv._tenant_creds(srv.TenantCredsRequest(**LEGACY))
    assert creds["auth_method"] == "legacy" and creds["username"] == LEGACY["username"] and ta.complete(creds)
    v = srv._validate_creds(creds)
    assert v["cloud"] == "zscalerten" and v["api_key"] == LEGACY["api_key"]
    with pytest.raises(HTTPException) as ex:
        srv._validate_creds(dict(LEGACY, api_key=""))
    assert ex.value.status_code == 400 and "api_key is required" in ex.value.detail
    with pytest.raises(HTTPException) as ex:
        srv._validate_creds(dict(LEGACY, auth_method="oneapi"))
    assert "client_id is required" in ex.value.detail
    # The environment supplies the classic sign-in when the form is blank, never mixing a typed id with a stored secret.
    for k, v_ in (("ZSCALER_AUTH_METHOD", "legacy"), ("ZSCALER_CLOUD", "zscloud"), ("ZSCALER_USERNAME", "env@acme.com"), ("ZSCALER_PASSWORD", "envpw"), ("ZSCALER_API_KEY", "envkey123456")):
        monkeypatch.setenv(k, v_)
    e = srv._tenant_creds(srv.TenantCredsRequest())
    assert e["auth_method"] == "legacy" and e["username"] == "env@acme.com" and e["cloud"] == "zscloud"
    form_default = srv._tenant_creds(srv.TenantCredsRequest(auth_method="oneapi"))
    assert form_default["auth_method"] == "legacy" and form_default["username"] == "env@acme.com", \
        "the form's default selector with nothing typed does not override the sign-in the environment has"
    half = srv._tenant_creds(srv.TenantCredsRequest(auth_method="legacy", username="typed@acme.com"))
    assert half["username"] == "env@acme.com", "an incomplete typed sign-in is replaced by the complete one from the environment, id and secrets together"
    typed = srv._tenant_creds(srv.TenantCredsRequest(**LEGACY))
    assert typed["username"] == LEGACY["username"] and typed["cloud"] == "zscalerten", "a complete typed sign-in is used as typed"
    # A saved profile fills the blanks, its remembered secrets included.
    import tenant_profiles as tp
    tp.upsert({"name": "P", "cloud": "zscalerthree", "auth_method": "legacy", "username": "prof@acme.com"}, password="pp", api_key="profkey12345", remember_secret=True, profile_id="p")
    p = srv._tenant_creds(srv.TenantCredsRequest(profile_id="p"))
    assert p["username"] == "prof@acme.com" and p["password"] == "pp" and p["api_key"] == "profkey12345" and p["cloud"] == "zscalerthree"


def test_the_profile_endpoint_saves_the_classic_sign_in(store):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    c = TestClient(srv.app)
    r = c.post("/api/tenant-profiles", json=dict(LEGACY, name="Acme Legacy", remember_secret=True))
    assert r.status_code == 200 and r.json()["auth_method"] == "legacy" and r.json()["username"] == LEGACY["username"] and r.json()["has_secret"] is True
    assert "Pa55word!" not in r.text and "aBcDeFgHiJkL" not in r.text
    got = c.get(f"/api/tenant-profiles/{r.json()['id']}").json()
    assert got["auth_method"] == "legacy" and "password" not in got and "api_key" not in got
    assert c.post("/api/tenant-profiles", json={"name": "x", "auth_method": "magic"}).status_code == 400


def test_the_sdk_client_is_built_through_the_sdk_legacy_helper(monkeypatch):
    import dlp_api_server as srv
    zia_legacy = pytest.importorskip("zscaler.zia.legacy")
    seen = {}

    class Helper:
        def __init__(self, cloud, timeout=240, **kw):
            seen.update(kw, cloud=cloud, timeout=timeout)
            self.request_executor = object()
            self.dlp_dictionary = "dicts"

        def ensure_valid_session(self):
            seen["ensured"] = True

        def deauthenticate(self):
            seen["ended"] = True
    monkeypatch.setattr(zia_legacy, "LegacyZIAClientHelper", Helper)
    client = srv._build_sdk_client(LEGACY)
    assert seen["cloud"] == "zscalerten" and seen["override_url"] == "https://zsapi.zscalerten.net" and seen["timeout"] == srv.SDK_REQUEST_TIMEOUT
    assert seen["username"] == LEGACY["username"] and seen["password"] == LEGACY["password"] and seen["api_key"] == LEGACY["api_key"]
    assert client.use_legacy_client and client.zia.dlp_dictionary == "dicts" and client.authenticate() is True and seen["ensured"]
    endpoint = client.zia.endpoint_dlp_rules      # OneAPI-only in the SDK: built on the helper's executor
    assert type(endpoint).__name__ == "EndpointDLPRulesAPI"
    with pytest.raises(AttributeError, match="ZIA only"):
        client.zpa
    client.close()
    assert seen["ended"]
    # "Commercial" (cloud not named) reaches zscaler.net on the classic API.
    srv._build_sdk_client(dict(LEGACY, cloud="production"))
    assert seen["cloud"] == "zscaler" and seen["override_url"] == "https://zsapi.zscaler.net"


def test_a_refused_classic_sdk_sign_in_is_a_401_without_the_password(monkeypatch):
    import dlp_api_server as srv
    from fastapi import HTTPException
    zia_legacy = pytest.importorskip("zscaler.zia.legacy")

    class Helper:
        def __init__(self, cloud, **kw):
            raise RuntimeError("AUTHENTICATION_FAILED: Invalid username or password Pa55word!")
    monkeypatch.setattr(zia_legacy, "LegacyZIAClientHelper", Helper)
    with pytest.raises(HTTPException) as ex:
        srv._build_sdk_client(LEGACY)
    assert ex.value.status_code == 401 and "zsapi.zscalerten.net" in ex.value.detail and "Pa55word!" not in ex.value.detail
    why = srv._explain_connection_error(ex.value.detail, "legacy")
    assert "username, password or API key" in why["cause"] and "API Key Management" in why["fix"]


def test_the_connection_test_and_the_assessment_accept_the_classic_sign_in(store, monkeypatch, tmp_path):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    from test_pack_channels import TENANTS, add_control_services, make_client
    built = {}

    def build(creds):
        built.update(creds)
        assert creds["auth_method"] == "legacy" and creds["password"] == LEGACY["password"]
        return add_control_services(make_client(casb_tenants=TENANTS))
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    c = TestClient(srv.app)
    r = c.post("/api/tenant/check", json=LEGACY)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auth_method"] == "legacy" and body["tenant_label"] == "classic API (zscalerten)" and any("ZIA only" in p for p in body["problems"])
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["body"]["password"] == "[redacted]" and entry["body"]["api_key"] == "[redacted]" and "Pa55word!" not in log.read_text()
    # The assessment builds the raw client with the classic sign-in.
    made = {}

    class FakeClient:
        def __init__(self, cid, sec, vd, cloud, cust="", **kw):
            made.update(kw, cloud=cloud)
            self.requests_made = 0

        def auth(self):
            return True
    monkeypatch.setattr(srv, "Client", FakeClient)
    r = c.post("/api/assess", json=dict(LEGACY, scopes=["dlp"]))
    assert r.status_code == 200, r.text
    assert made["auth_method"] == "legacy" and made["username"] == LEGACY["username"] and made["api_key"] == LEGACY["api_key"] and made["cloud"] == "zscalerten"
    assert '"auth_method": "legacy"' in r.text and "classic ZIA API" in r.text
    assert c.post("/api/assess", json={"auth_method": "legacy", "username": "u", "scopes": ["dlp"]}).status_code == 400, "an incomplete classic sign-in is refused before the stream opens"


def test_sdk_client_and_mcp_take_the_classic_sign_in_from_the_environment(monkeypatch):
    sdk_client = pytest.importorskip("sdk_client")
    for k, v in (("ZSCALER_AUTH_METHOD", "legacy"), ("ZSCALER_CLOUD", "zscalerten"), ("ZSCALER_USERNAME", "u@acme.com"), ("ZSCALER_PASSWORD", "p"), ("ZSCALER_API_KEY", "k")):
        monkeypatch.setenv(k, v)
    for k in ("ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET", "ZSCALER_VANITY_DOMAIN"):
        monkeypatch.delenv(k, raising=False)
    cl = sdk_client.from_env()
    assert cl._creds["auth_method"] == "legacy" and cl._creds["username"] == "u@acme.com"
    built = {}
    monkeypatch.setattr(ta, "build_legacy_sdk_client", lambda creds, **kw: built.update(creds) or type("Z", (), {"zia": object()})())
    assert cl.auth() is True and built["api_key"] == "k"
    import dlp_mcp_server as mcp  # a hard import: an mcp release that breaks the server must fail here, not skip
    m = mcp._create_client()
    assert m._creds["auth_method"] == "legacy" and m._creds["cloud"] == "zscalerten"


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

def test_the_page_offers_the_sign_in_method_and_sends_every_credential_field():
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert '<select id="authMethod"' in html and 'value="legacy"' in html and 'id="zuser"' in html and 'id="zpass"' in html and 'id="zkey"' in html
    for needle in ("function currentAuthMethod", "function applyAuthMethod", "auth_method: currentAuthMethod()", "username: only('zuser', true)", "password: only('zpass', true)", "api_key: only('zkey', true)",
                   "API Key Management", "...migrateCredBody()"):
        assert needle in html, needle
    assert re.search(r"if \(b\.auth_method === 'legacy'\) \{\s*if \(blank\(b\.username\)\)", html), "validation follows the method"
    assert ".field[hidden] { display: none; }" in html, "a hidden field must not stay visible through the flex rule"
    guide = open(os.path.join(ROOT, "static", "guide.js"), encoding="utf-8").read()
    for needle in ("set('authMethod'", "set('zuser'", "username: _gdVal('zuser')", "api_key: _gdVal('zkey')", "classic ZIA API",
                   "window.GD = GD;"):
        assert needle in guide, needle
    studio = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "auth_method: v('authMethod')" in studio
