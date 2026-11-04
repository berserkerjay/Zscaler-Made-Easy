"""The signed-in tenant (tenant_session.py): one sign-in, kept in server
memory for the person and browser that made it, so switching from the
expert page to Simple mode (or any page) reads the tenant without asking
for the sign-in details again. It ends when unused, at a hard limit, on
sign-out, on a failed sign-in and on another tenant's sign-in; it is never
shared with another browser or person, never returned, logged or written;
writes never use it; the sample tenant is unaffected.

No real tenant and no network: the sign-in and the assessment client are
fakes that validate the credentials as the real factories do."""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security
import sso
import team_routes
import team_server as team
import tenant_profiles
import tenant_session
from dlp_assessment_full_auto import R

SECRET = "CANARYsignedin+/=Q7x9Zk2"
ACME = {"auth_method": "oneapi", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclient0001", "client_secret": SECRET}
BOLT = {"auth_method": "oneapi", "cloud": "zscalerten", "vanity_domain": "bolt", "client_id": "boltclient0001", "client_secret": "bolt-secret-0001"}
ASSESS = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "org_name": "Acme", "assessor": "QA tester"}
ORIGIN = {"Origin": "http://testserver"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, minutes):
        self.t += minutes * 60


class Raw:
    """The assessment client: auth succeeds, every read answers empty."""
    def auth(self):
        return True

    def get(self, endpoint, *a, **k):
        return [], 200

    def close(self):
        pass


@pytest.fixture
def world(monkeypatch, tmp_path):
    w = {"checked": [], "assessed": [], "clock": Clock()}
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))   # no tenant_config.json of this machine
    monkeypatch.setattr(tenant_session, "_clock", w["clock"])

    class Sdk:
        pass

    def build(creds):
        c = srv._validate_creds(creds)     # what the real factory refuses first
        w["checked"].append(dict(c))
        return Sdk()

    def raw(creds):
        c = srv._validate_creds(creds)
        w["assessed"].append(dict(c))
        return Raw()

    monkeypatch.setattr(srv, "_build_sdk_client", build)
    monkeypatch.setattr(srv, "_raw_client", raw)
    monkeypatch.setattr(srv, "_readiness_token_access", lambda client, method: {})
    monkeypatch.setattr(srv, "_close_quietly", lambda client: None)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "DLP", "Check 1", lambda c: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, channels: ([], {}))
    return w


def _assess(client, body=None):
    """Run the assessment stream; (status, events)."""
    out = []
    with client.stream("POST", "/api/assess", json=dict(ASSESS, **(body or {})), headers=ORIGIN) as r:
        if r.status_code != 200:
            r.read()
            return r.status_code, r.json()
        kind = None
        for line in r.iter_lines():
            if line.startswith("event: "):
                kind = line[7:]
            elif line.startswith("data: "):
                out.append((kind, json.loads(line[6:])))
    return 200, out


def _completed(events):
    return any(k == "complete" for k, _ in events)


# ── 1. The owner's bug: Authenticate on the expert page, then Simple mode ──

def test_after_authenticate_simple_mode_assesses_without_the_sign_in_details(world):
    """ASVS V3.2.1 · CWE-287 · WSTG-SESS-01: Authenticate then an assessment that sends no sign-in (Simple mode) signs in with the remembered tenant."""
    page = TestClient(srv.app)
    r = page.post("/api/tenant/check", json=ACME)
    assert r.status_code == 200 and r.json()["signed_in"] is True
    status, events = _assess(page)                 # Simple mode's credBody() is {} here
    assert status == 200 and _completed(events), events
    assert [c["vanity_domain"] for c in world["assessed"]] == ["acme"]
    assert world["assessed"][0]["client_secret"] == SECRET


def test_without_a_sign_in_the_same_request_is_refused_as_before(world):
    """ASVS V4.1.3 · CWE-306 · WSTG-ATHN-04: no sign-in kept and none sent: refused before any client is built (the behaviour this change keeps)."""
    page = TestClient(srv.app)
    status, body = _assess(page)
    assert status == 400 and world["assessed"] == []
    assert page.get("/api/tenant/session").json()["connected"] is False


def test_a_saved_profile_without_a_remembered_secret_uses_the_signed_in_secret(world, monkeypatch, tmp_path):
    """ASVS V2.10.4 · CWE-522 · WSTG-ATHN-07: Simple mode's saved profile with no remembered secret signs in with the secret of the same tenant's sign-in."""
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "p.json"))
    pid = tenant_profiles.upsert({"name": "Acme", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclient0001"})["id"]
    page = TestClient(srv.app)
    assert page.post("/api/tenant/check", json=dict(ACME, profile_id=pid)).status_code == 200
    status, events = _assess(page, {"profile_id": pid})
    assert status == 200 and _completed(events)
    assert world["assessed"][-1]["client_secret"] == SECRET
    st = page.get("/api/tenant/session").json()
    assert st["profile_id"] == pid and st["profile_name"] == "Acme"


def test_another_tenants_profile_never_gets_the_signed_in_secret(world, monkeypatch, tmp_path):
    """ASVS V2.10.4 · CWE-522 · WSTG-ATHN-07: a profile naming another tenant is not completed with the signed-in tenant's secret."""
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "p.json"))
    other = tenant_profiles.upsert({"name": "Bolt", "cloud": "zscalerten", "vanity_domain": "bolt", "client_id": "boltclient0001"})["id"]
    page = TestClient(srv.app)
    assert page.post("/api/tenant/check", json=ACME).status_code == 200
    status, _ = _assess(page, {"profile_id": other})
    assert status == 400 and world["assessed"] == []


def test_typed_details_for_another_tenant_are_used_as_typed(world):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: a request that brings a complete sign-in uses it, never the remembered one."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    status, _ = _assess(page, BOLT)
    assert status == 200 and world["assessed"][-1]["vanity_domain"] == "bolt"


def test_the_assessments_own_sign_in_is_remembered_too(world):
    """ASVS V3.2.1 · CWE-287 · WSTG-SESS-01: a successful assessment sign-in with typed details is kept like Authenticate's."""
    page = TestClient(srv.app)
    status, _ = _assess(page, ACME)
    assert status == 200
    assert page.get("/api/tenant/session").json()["connected"] is True
    status, events = _assess(page)
    assert status == 200 and _completed(events) and len(world["assessed"]) == 2


# ── 2. What GET /api/tenant/session says ─────────────────────────────────

def test_the_session_route_names_the_tenant_and_never_a_credential(world):
    """ASVS V8.3.1 · CWE-200 · WSTG-INFO-05: GET /api/tenant/session gives the label, method and time left, never a secret or client id."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    r = page.get("/api/tenant/session")
    d = r.json()
    assert r.status_code == 200 and d["connected"] is True and d["expired"] is False
    assert d["tenant_label"] == "acme (zscalerten)" and d["auth_method"] == "oneapi"
    assert d["expires_in"] == tenant_session.IDLE_SECONDS and d["offline"] is False
    assert SECRET not in r.text and "acmeclient0001" not in r.text
    assert r.headers["cache-control"] == "no-store"


def test_the_handle_cookie_is_http_only_strict_and_holds_no_credential(world):
    """ASVS V3.4.2 · ASVS V3.4.3 · CWE-1004 · CWE-1275 · WSTG-SESS-02: the browser holds only a random handle in an HttpOnly, SameSite=Strict cookie."""
    page = TestClient(srv.app)
    r = page.post("/api/tenant/check", json=ACME)
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(tenant_session.COOKIE + "=") and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    value = cookie.split(";")[0].split("=", 1)[1]
    assert 32 <= len(value) <= 64 and SECRET not in cookie and "acme" not in value


def test_a_failed_sign_in_sets_no_cookie_and_ends_the_previous_sign_in(world, monkeypatch):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: a sign-in check that fails forgets the tenant signed in before; no silent fall back to it."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)

    def refuse(creds):
        raise srv.HTTPException(status_code=401, detail="invalid_client")
    monkeypatch.setattr(srv, "_build_sdk_client", refuse)
    r = page.post("/api/tenant/check", json=BOLT)
    assert r.status_code == 401 and "set-cookie" not in r.headers
    assert page.get("/api/tenant/session").json()["connected"] is False
    fresh = TestClient(srv.app)
    assert "set-cookie" not in fresh.post("/api/tenant/check", json=BOLT).headers


def test_signing_in_to_another_tenant_replaces_the_first(world):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: one signed-in tenant per person and browser; switching tenant forgets the first."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    page.post("/api/tenant/check", json=BOLT)
    assert page.get("/api/tenant/session").json()["tenant_label"] == "bolt (zscalerten)"
    _assess(page)
    assert world["assessed"][-1]["vanity_domain"] == "bolt"


# ── 3. Expiry and sign-out ───────────────────────────────────────────────

def test_it_ends_after_thirty_idle_minutes_and_says_so_plainly(world):
    """ASVS V3.3.2 · CWE-613 · WSTG-SESS-07: unused for 30 minutes, the sign-in ends, its secret is dropped and the page is told in words."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    world["clock"].advance(29)
    assert page.get("/api/tenant/session").json()["connected"] is True
    world["clock"].advance(1)
    d = page.get("/api/tenant/session").json()
    assert d["connected"] is False and d["expired"] is True and d["ended"] == "idle"
    assert "Sign in again" in d["message"] and "30 minutes without use" in d["message"]
    assert all(e.creds is None for e in tenant_session._STORE.values()), "the secret is gone the moment it ends"
    status, _ = _assess(page)
    assert status == 400 and world["assessed"] == []


def test_use_keeps_it_alive_but_never_past_the_hard_limit(world):
    """ASVS V3.3.2 · ASVS V3.3.4 · CWE-613 · WSTG-SESS-07: each read restarts the idle time; the 8-hour limit ends it however much it is used."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    for _ in range(19):          # a read every 25 minutes: 7h55 of steady use
        world["clock"].advance(25)
        assert page.get("/api/tenant/session").json()["connected"] is True
        assert _assess(page)[0] == 200
    world["clock"].advance(6)    # 8h01 after the sign-in, 6 minutes after the last read
    d = page.get("/api/tenant/session").json()
    assert d["expired"] is True and d["ended"] == "hard" and "8 hours" in d["message"]
    assert _assess(page)[0] == 400


def test_repeating_the_same_sign_in_does_not_extend_the_hard_limit(world):
    """ASVS V3.3.4 · CWE-613 · WSTG-SESS-07: re-checking the same tenant keeps the first sign-in's hard limit."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    for _ in range(19):          # the same sign-in checked again every 25 minutes: 7h55
        world["clock"].advance(25)
        assert page.post("/api/tenant/check", json=ACME).status_code == 200
    # 5 minutes left of the first sign-in's 8 hours, not a fresh 30-minute window.
    assert page.get("/api/tenant/session").json()["expires_in"] == 5 * 60


def test_sign_out_of_the_tenant_forgets_it(world):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: DELETE /api/tenant/session forgets the sign-in; the next read without details is refused."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    r = page.delete("/api/tenant/session", headers=ORIGIN)
    assert r.status_code == 200 and r.json() == {"ok": True, "forgotten": True}
    assert page.get("/api/tenant/session").json()["connected"] is False
    assert _assess(page)[0] == 400 and not tenant_session._STORE


def test_a_server_restart_forgets_it(world):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: the store is process memory only: a new process (cleared store) has nothing."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    tenant_session.clear_all()      # what a restart does
    assert page.get("/api/tenant/session").json()["connected"] is False


# ── 4. Never shared ──────────────────────────────────────────────────────

def test_another_browser_never_uses_it(world):
    """ASVS V3.2.1 · ASVS V4.2.1 · CWE-639 · WSTG-SESS-01: a second browser (no handle cookie) is not signed in and its reads are refused."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    other = TestClient(srv.app)
    assert other.get("/api/tenant/session").json()["connected"] is False
    assert _assess(other)[0] == 400 and world["assessed"] == []


def test_a_guessed_or_malformed_handle_finds_nothing(world):
    """ASVS V3.2.2 · CWE-330 · WSTG-SESS-01: a forged handle of the right shape, or a malformed one, is not a sign-in."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    for forged in ("A" * 43, "x", "../" * 20, "%C3%A9" * 8):
        c = TestClient(srv.app)
        c.cookies.set(tenant_session.COOKIE, forged)
        assert c.get("/api/tenant/session").json()["connected"] is False


def test_outside_a_browser_request_nothing_is_kept_or_used():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: the assistant and background jobs (no request context) neither keep nor use a sign-in."""
    assert tenant_session.remember(dict(ACME), label="acme") is False
    assert tenant_session.for_read() is None and tenant_session.status()["connected"] is False
    assert not tenant_session._STORE


def test_a_remembered_entry_never_prints_its_secret():
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: the in-memory record's repr names the tenant, never a credential."""
    e = tenant_session._Entry("o", dict(ACME), "", "acme (zscalerten)", "oneapi", 0.0)
    assert SECRET not in repr(e) and "acmeclient0001" not in repr(e) and "acme (zscalerten)" in repr(e)


# ── 5. Writes never use it ───────────────────────────────────────────────

def test_a_write_never_uses_the_signed_in_tenant(world, monkeypatch):
    """ASVS V4.1.3 · ASVS V1.4.1 · CWE-862 · WSTG-ATHZ-02: with write mode on and every gate passed, a deploy without its own sign-in is refused in words; signing in never enables writes."""
    monkeypatch.setenv("ENABLE_WRITE_ACTIONS", "YES_I_UNDERSTAND")
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    built = len(world["checked"])
    r = page.post("/api/dlp-packs/apply", json={"pack_ids": ["cjis_policy_pack"], "plan_hash": "a" * 64, "confirm": True,
                                                 "assessor": "QA tester"}, headers=ORIGIN)
    assert r.status_code == 400 and r.json()["detail"] == srv.SIGNED_IN_NOT_FOR_CHANGES
    assert len(world["checked"]) == built, "no client was built for the write"


def test_signing_in_does_not_turn_write_mode_on(world):
    """ASVS V1.4.1 · CWE-269 · WSTG-ATHZ-03: write mode is what it was before the sign-in."""
    page = TestClient(srv.app)
    before = page.get("/api/write-mode").json()["enabled"]
    page.post("/api/tenant/check", json=ACME)
    assert page.get("/api/write-mode").json()["enabled"] is before is False


def test_only_tenant_reads_fall_back_and_no_write_route_is_a_read():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: the fallback is for routes ruled `read`; no tenant write of the safety-gate table is ruled `read`."""
    from test_write_safety_gates import WRITE_CASES
    for _id, method, path, _a, _c in WRITE_CASES:
        rule = team_routes.rule_for(method, path)
        assert rule is not None and rule[0] != team_routes.READ, (method, path, rule)
    assert team_routes.rule_for("POST", "/api/assess")[0] == team_routes.READ
    assert team_routes.rule_for("GET", "/api/tenant/session")[0] == team_routes.SESSION
    assert team_routes.rule_for("DELETE", "/api/tenant/session")[0] == team_routes.SESSION


# ── 6. The sample tenant is unaffected ───────────────────────────────────

def test_the_sample_tenant_is_never_kept_and_still_wins(world):
    """ASVS V4.1.3 · CWE-284 · WSTG-BUSL-01: with the sample in use, a sign-in check keeps nothing and reads use the sample, not a kept tenant."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    assert page.post("/api/offline/sample", json={}, headers=ORIGIN).status_code == 200
    d = page.get("/api/tenant/session").json()
    assert d["offline"] is True
    status, events = _assess(page)
    assert status == 200 and world["assessed"][-1]["client_id"].startswith("offline-")
    page.post("/api/offline/leave", json={}, headers=ORIGIN)
    assert page.get("/api/tenant/session").json()["connected"] is True


# ── 7. No secret anywhere ────────────────────────────────────────────────

def test_the_secret_is_in_no_response_log_file_or_browser_storage(world, capfd):
    """ASVS V7.1.1 · ASVS V8.3.4 · CWE-312 · CWE-532 · WSTG-INFO-05: across sign-in, reads, status and sign-out, the canary secret appears in no response, cookie, log line, audit entry or file."""
    page = TestClient(srv.app)
    seen = []
    seen.append(page.post("/api/tenant/check", json=ACME))
    seen.append(page.get("/api/tenant/session"))
    status, events = _assess(page)
    seen.append(page.delete("/api/tenant/session", headers=ORIGIN))
    texts = [r.text + json.dumps(dict(r.headers)) for r in seen] + [json.dumps(events)]
    texts.append(json.dumps(dict(page.cookies)))
    out, err = capfd.readouterr()
    texts += [out, err]
    for k in ("DLP_CHECK_AUDIT", "DLP_CHECK_PROFILES"):
        folder = os.path.dirname(os.environ[k])
        for root, _dirs, files in os.walk(folder):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    texts.append(f.read().decode("utf-8", "replace"))
    for t in texts:
        assert SECRET not in t


# ── 8. Team server: each person their own ────────────────────────────────

PW = "correct horse battery staple"


@pytest.fixture
def team_world(world, monkeypatch, tmp_path):
    monkeypatch.setenv("ZSCALER_TEAM_MODE", "1")
    monkeypatch.setattr(team, "SCRYPT_LOG_N", 10)
    monkeypatch.setattr(team, "_DUMMY_HASH", None)
    team._FAILURES.clear()
    team._IP_ATTEMPTS.clear()
    team._RESOURCES.clear()
    team._CACHE.update(key=None, data=None)
    sso._SESSIONS.clear()
    a = tenant_profiles.upsert({"name": "Acme", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclient0001"})["id"]
    users = {n: team.create_user(username=n, role="viewer", password=PW) for n in ("vic", "val")}
    for u in users.values():
        team.set_grant(f"user:{u['id']}", a, ["read"])
    yield {"a": a, "users": users}
    sso._SESSIONS.clear()
    team._CACHE.update(key=None, data=None)


def _login(name):
    c = TestClient(srv.app)
    r = c.post("/api/auth/team/login", json={"username": name, "password": PW}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    return c


def test_team_each_person_has_their_own_signed_in_tenant(team_world, world):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: on a team server one person's sign-in is never used by another, even with the same grants and the handle cookie."""
    vic, val = _login("vic"), _login("val")
    r = vic.post("/api/tenant/check", json={"profile_id": team_world["a"], "client_secret": SECRET}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert vic.get("/api/tenant/session").json()["connected"] is True
    status, events = _assess(vic)
    assert status == 200 and _completed(events) and world["assessed"][-1]["client_secret"] == SECRET, events
    # Another person, same grants, even holding vic's handle cookie: nothing.
    val.cookies.set(tenant_session.COOKIE, vic.cookies.get(tenant_session.COOKIE))
    assert val.get("/api/tenant/session").json()["connected"] is False
    status, body = _assess(val)
    assert status == 403 and len(world["assessed"]) == 1


def test_team_a_revoked_grant_stops_the_signed_in_tenant_at_once(team_world, world):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: the person's access to the profile is checked on every read, not only at sign-in."""
    vic = _login("vic")
    vic.post("/api/tenant/check", json={"profile_id": team_world["a"], "client_secret": SECRET}, headers=ORIGIN)
    team.set_grant(f"user:{team_world['users']['vic']['id']}", team_world["a"], [])
    status, body = _assess(vic)
    assert status == 403 and len(world["assessed"]) == 0


def test_team_signing_out_forgets_the_signed_in_tenant(team_world, world):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: signing out of the team server forgets the person's signed-in tenant."""
    vic = _login("vic")
    vic.post("/api/tenant/check", json={"profile_id": team_world["a"], "client_secret": SECRET}, headers=ORIGIN)
    assert tenant_session._STORE
    assert vic.post("/api/auth/logout", headers=ORIGIN).status_code == 200
    assert not tenant_session._STORE


# ── 9. Session fixation: every sign-in gets a new handle ─────────────────

PLANTED = "F" * 43   # a handle another page on this computer could set (cookies are not separated by port)


def _handle(r):
    """The handle a response set, or ''."""
    for v in r.headers.get_list("set-cookie"):
        name, _, rest = v.partition("=")
        if name in (tenant_session.COOKIE, tenant_session.SECURE_COOKIE):
            return rest.split(";")[0]
    return ""


def test_a_planted_handle_is_replaced_at_sign_in_and_finds_nothing(world):
    """ASVS V3.2.1 · CWE-384 · WSTG-SESS-03: a handle the browser brought (planted) is never kept: Authenticate sets a new one, and the planted one reads nothing."""
    page = TestClient(srv.app)
    page.cookies.set(tenant_session.COOKIE, PLANTED, domain="testserver.local", path="/")
    r = page.post("/api/tenant/check", json=ACME)
    new = _handle(r)
    assert r.status_code == 200 and new and new != PLANTED
    attacker = TestClient(srv.app)
    attacker.cookies.set(tenant_session.COOKIE, PLANTED, domain="testserver.local", path="/")
    assert attacker.get("/api/tenant/session").json()["connected"] is False
    assert _assess(attacker)[0] == 400 and world["assessed"] == []
    assert page.get("/api/tenant/session").json()["connected"] is True


def test_an_assessment_sign_in_also_replaces_the_handle(world):
    """ASVS V3.2.1 · CWE-384 · WSTG-SESS-03: the assessment's own sign-in sets a new handle too; the planted one finds nothing."""
    page = TestClient(srv.app)
    page.cookies.set(tenant_session.COOKIE, PLANTED, domain="testserver.local", path="/")
    with page.stream("POST", "/api/assess", json=dict(ASSESS, **ACME), headers=ORIGIN) as r:
        new = _handle(r)
        r.read()
    assert new and new != PLANTED
    attacker = TestClient(srv.app)
    attacker.cookies.set(tenant_session.COOKIE, PLANTED, domain="testserver.local", path="/")
    assert attacker.get("/api/tenant/session").json()["connected"] is False
    assert page.get("/api/tenant/session").json()["connected"] is True


def test_reading_with_the_sign_in_moves_it_to_a_new_handle_and_the_old_one_reads_nothing(world):
    """ASVS V3.2.1 · CWE-384 · WSTG-SESS-03: an assessment that uses the kept sign-in (Simple mode) still works, the browser gets a new handle, and a second client holding the old handle reads nothing."""
    page = TestClient(srv.app)
    old = _handle(page.post("/api/tenant/check", json=ACME))
    status, events = _assess(page)
    assert status == 200 and _completed(events)
    assert page.cookies.get(tenant_session.COOKIE) != old
    assert page.get("/api/tenant/session").json()["connected"] is True
    second = TestClient(srv.app)
    second.cookies.set(tenant_session.COOKIE, old)
    assert second.get("/api/tenant/session").json()["connected"] is False
    assert _assess(second)[0] == 400 and len(world["assessed"]) == 1


def test_a_failed_sign_in_keeps_the_browsers_handle_and_sets_none(world, monkeypatch):
    """ASVS V3.2.1 · CWE-384 · WSTG-SESS-03: a sign-in check that fails sets no new handle (and ends the old sign-in, as before)."""
    page = TestClient(srv.app)
    old = _handle(page.post("/api/tenant/check", json=ACME))

    def refuse(creds):
        raise srv.HTTPException(status_code=401, detail="invalid_client")
    monkeypatch.setattr(srv, "_build_sdk_client", refuse)
    r = page.post("/api/tenant/check", json=ACME)
    assert r.status_code == 401 and _handle(r) == "" and page.cookies.get(tenant_session.COOKIE) == old


# ── 10. Only this app's own page reads with it ───────────────────────────

@pytest.mark.parametrize("headers", [{"Sec-Fetch-Site": "same-site"}, {"Sec-Fetch-Site": "cross-site"}])
def test_a_request_another_page_made_never_reads_with_it(world, headers):
    """ASVS V4.2.2 · CWE-352 · WSTG-SESS-05: a read the browser sent for another site's page (another port of this computer is same-site) does not use the kept sign-in."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    with page.stream("POST", "/api/assess", json=ASSESS, headers=headers) as r:
        r.read()
        assert r.status_code == 400
    assert world["assessed"] == []
    assert _assess(page)[0] == 200      # the app's own page still reads


def test_a_foreign_origin_never_reads_with_it(world):
    """ASVS V4.2.2 · CWE-346 · WSTG-SESS-05: a request whose Origin is not this server's never gets the kept sign-in, even where no CSRF check applies."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    with tenant_session_ctx(page, {"origin": "http://localhost:3000"}) as read:
        assert read() is None
    with tenant_session_ctx(page, {"origin": "http://testserver", "sec-fetch-site": "same-origin"}) as read:
        assert read() is not None


class tenant_session_ctx:
    """Run tenant_session.for_read() as a read route's request with these headers and this client's handle."""
    def __init__(self, client, headers):
        self.client, self.headers = client, headers

    def __enter__(self):
        handle = self.client.cookies.get(tenant_session.COOKIE)
        hdrs = [(b"host", b"testserver"), (b"cookie", f"{tenant_session.COOKIE}={handle}".encode())]
        hdrs += [(k.encode(), v.encode()) for k, v in self.headers.items()]
        scope = {"type": "http", "method": "POST", "path": "/api/assess", "scheme": "http", "headers": hdrs,
                 "server": ("testserver", 80), "client": ("testclient", 50000), "query_string": b"", "root_path": ""}
        self.ctx = {"handle": handle, "fresh": "", "rotated": False, "send_cookie": False, "cookie": tenant_session.COOKIE,
                    "who": "", "scope": scope, "routes": lambda: srv.app.router.routes, "rule": None}
        self.token = tenant_session._REQ.set(self.ctx)
        return tenant_session.for_read

    def __exit__(self, *exc):
        tenant_session._REQ.reset(self.token)


# ── 11. The secret leaves memory when the sign-in ends ──────────────────

def test_an_ended_sign_ins_secret_is_dropped_without_another_request(world):
    """ASVS V3.3.2 · CWE-226 · WSTG-SESS-07: the timer (reap) drops an ended sign-in's secret though nobody asks again, and the timer is running."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    assert tenant_session._REAPER is not None and tenant_session._REAPER.is_alive()
    assert tenant_session.REAP_SECONDS <= 60
    world["clock"].advance(30)
    tenant_session.reap()
    assert [e.creds for e in tenant_session._STORE.values()] == [None]


def test_another_callers_request_drops_an_ended_sign_ins_secret(world):
    """ASVS V3.3.2 · CWE-226 · WSTG-SESS-07: any request sweeps the whole store, not only the asking browser's sign-in."""
    first, second = TestClient(srv.app), TestClient(srv.app)
    first.post("/api/tenant/check", json=ACME)
    world["clock"].advance(20)
    second.post("/api/tenant/check", json=BOLT)
    world["clock"].advance(10)
    assert second.get("/api/tenant/session").json()["connected"] is True
    ended = [e for e in tenant_session._STORE.values() if e.label.startswith("acme")]
    assert len(ended) == 1 and ended[0].creds is None and ended[0].ended == "idle"


# ── 12. A failed assessment sign-in ends it ─────────────────────────────

@pytest.mark.parametrize("failure", ["refused", "raises"])
def test_a_failed_assessment_sign_in_ends_the_signed_in_tenant(world, monkeypatch, failure):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06: an assessment whose own sign-in fails forgets the tenant signed in before; no silent fall back."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)

    class Refused(Raw):
        def auth(self):
            if failure == "raises":
                raise RuntimeError("invalid_client")
            return (False, "invalid_client")
    monkeypatch.setattr(srv, "_raw_client", lambda creds: Refused())
    status, events = _assess(page, BOLT)
    assert status == 200 and any(k == "error" for k, _ in events) and not _completed(events)
    assert page.get("/api/tenant/session").json()["connected"] is False
    assert not tenant_session._STORE


# ── 13. Cookie, CSRF, memory bound, UI token mode ───────────────────────

def test_over_https_the_handle_cookie_is_secure_and_host_only(world):
    """ASVS V3.4.1 · CWE-614 · WSTG-SESS-02: over HTTPS the handle is a Secure, __Host- prefixed cookie; over plain HTTP it is not marked Secure."""
    secure = TestClient(srv.app, base_url="https://testserver")
    r = secure.post("/api/tenant/check", json=ACME, headers={"Origin": "https://testserver"})
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(tenant_session.SECURE_COOKIE + "=") and "; Secure" in cookie and "Path=/" in cookie
    assert "Domain=" not in cookie
    assert secure.get("/api/tenant/session").json()["connected"] is True
    # The unprefixed name (one another page could set) is not read over HTTPS.
    other = TestClient(srv.app, base_url="https://testserver")
    other.cookies.set(tenant_session.COOKIE, secure.cookies.get(tenant_session.SECURE_COOKIE))
    assert other.get("/api/tenant/session").json()["connected"] is False
    plain = TestClient(srv.app).post("/api/tenant/check", json=ACME).headers["set-cookie"]
    assert "Secure" not in plain


@pytest.mark.parametrize("origin", ["http://evil.example", "http://localhost:3000"])
def test_sign_out_from_another_origin_is_refused(world, origin):
    """ASVS V4.2.2 · CWE-352 · WSTG-SESS-05: DELETE /api/tenant/session from another origin (another local port included) is refused and the sign-in stays."""
    page = TestClient(srv.app)
    page.post("/api/tenant/check", json=ACME)
    r = page.delete("/api/tenant/session", headers={"Origin": origin})
    assert r.status_code == 403
    assert page.get("/api/tenant/session").json()["connected"] is True


def test_the_store_is_bounded_and_the_least_recently_used_goes_first(world, monkeypatch):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: memory holds at most MAX_ENTRIES sign-ins; the least recently used one is forgotten first."""
    monkeypatch.setattr(tenant_session, "MAX_ENTRIES", 3)
    pages = []
    for _ in range(6):
        world["clock"].advance(1)
        p = TestClient(srv.app)
        assert p.post("/api/tenant/check", json=ACME).status_code == 200
        pages.append(p)
    assert len(tenant_session._STORE) == 3
    assert [p.get("/api/tenant/session").json()["connected"] for p in pages] == [False] * 3 + [True] * 3


def test_ui_token_mode_binds_it_to_the_token_and_the_browser(world, monkeypatch):
    """ASVS V3.2.1 · ASVS V4.2.1 · CWE-639 · WSTG-SESS-01: with the UI token gate on, the sign-in is used with the token and the handle; no token is a 401, and a new token finds nothing."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "first-ui-token-0123456789")
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)
    monkeypatch.setattr(security, "_ui_token", None)
    page = TestClient(srv.app, headers={"X-DLP-Check-Token": "first-ui-token-0123456789"})
    assert page.post("/api/tenant/check", json=ACME).status_code == 200
    status, events = _assess(page)          # Simple mode: the kept sign-in, then a new handle for it
    assert status == 200 and _completed(events)
    assert page.get("/api/tenant/session").json()["connected"] is True
    handle = page.cookies.get(tenant_session.COOKIE)
    tokenless = TestClient(srv.app)
    tokenless.cookies.set(tenant_session.COOKIE, handle)
    assert tokenless.get("/api/tenant/session").status_code == 401
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "second-ui-token-0123456789")
    monkeypatch.setattr(security, "_ui_token", None)
    later = TestClient(srv.app, headers={"X-DLP-Check-Token": "second-ui-token-0123456789"})
    later.cookies.set(tenant_session.COOKIE, handle)
    assert later.get("/api/tenant/session").json()["connected"] is False
