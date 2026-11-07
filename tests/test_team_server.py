"""Team server mode (team_server.py, team_routes.py, team_api.py,
server_tls.py): off by default, and then the single-user app is exactly as
it was; on, every route has an access rule and is checked server-side
(deny by default), local accounts sign in with scrypt passwords, lockout
and rate limiting are enforced, session cookies are HttpOnly + SameSite=
Strict (+ Secure over HTTPS) and rotate on sign-in, idle and absolute
timeouts end sessions, cross-site changes are refused, SCIM needs its own
hashed bearer token, binding beyond loopback needs HTTPS, the audit log
names the actor and the tenant profile and shows a person only their
tenants' entries, and four-eyes approval needs a different, entitled
person.

No real tenant and no network: the tenant sign-in is faked where a route
would build a client, and the identity provider is never called."""
from __future__ import annotations

import json
import os
import stat
import time

import pytest
from conftest import read_store_text
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Mount

import audit
import change_queue
import dlp_api_server as srv
import security
import server_tls
import sso
import team_routes
import team_server as team
import tenant_profiles

PW = "correct horse battery staple"
ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture
def team_on(monkeypatch):
    monkeypatch.setenv("ZSCALER_TEAM_MODE", "1")
    monkeypatch.setattr(team, "SCRYPT_LOG_N", 10)        # fast hashes in tests; the stored hash carries its own cost
    monkeypatch.setattr(team, "_DUMMY_HASH", None)
    team._FAILURES.clear()
    team._IP_ATTEMPTS.clear()
    team._RESOURCES.clear()
    team._CACHE.update(key=None, data=None)
    sso._SESSIONS.clear()
    yield
    sso._SESSIONS.clear()
    team._CACHE.update(key=None, data=None)


def _refill():
    """The API rate limiter (per address, process-wide) refilled: these
    tests walk hundreds of routes from one test-client address."""
    layer = getattr(srv.app, "middleware_stack", None)
    while layer is not None:
        if isinstance(layer, security.RateLimitMiddleware):
            layer.buckets.clear()
            return
        layer = getattr(layer, "app", None)


def _profile(name, vanity):
    return tenant_profiles.upsert({"name": name, "cloud": "zscalerten", "vanity_domain": vanity, "client_id": f"cid-{name}"})["id"]


def _user(name, role, **kw):
    return team.create_user(username=name, role=role, password=PW, **kw)


def _login(name, password=PW, base="http://testserver"):
    c = TestClient(srv.app, base_url=base)
    r = c.post("/api/auth/team/login", json={"username": name, "password": password}, headers={"Origin": base})
    assert r.status_code == 200, r.text
    return c


@pytest.fixture
def world(team_on):
    a = _profile("Acme", "acme.example")
    b = _profile("Bolt", "bolt.example")
    users = {"root": _user("root", "admin"), "vic": _user("vic", "viewer"), "olga": _user("olga", "operator"),
             "april": _user("april", "approver"), "bea": _user("bea", "approver")}
    team.set_grant(f"user:{users['vic']['id']}", a, ["read"])
    team.set_grant(f"user:{users['olga']['id']}", a, ["read", "plan", "apply"])
    team.set_grant(f"user:{users['april']['id']}", a, ["read", "approve"])
    team.set_grant(f"user:{users['bea']['id']}", b, ["read", "approve"])
    return {"a": a, "b": b, "users": users}


# ── 1. every route has a rule; deny by default ──────────────────────────
def _app_routes():
    for r in srv.app.routes:
        if isinstance(r, APIRoute):
            for m in sorted(r.methods - {"HEAD"}):
                yield m, r.path


def test_every_route_has_an_access_rule_or_is_on_the_public_list():
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: every route the app registers has an entitlement rule (or is explicitly public), and no rule names a route that does not exist."""
    missing = [f"{m} {p}" for m, p in _app_routes() if team_routes.rule_for(m, p) is None]
    assert not missing, f"routes with no team access rule (add them to team_routes.ROUTE_RULES): {missing}"
    registered = {f"{m} {p}" for m, p in _app_routes()}
    stale = sorted(set(team_routes.ROUTE_RULES) - registered)
    assert not stale, stale
    for k, v in team_routes.ROUTE_RULES.items():
        assert v.partition(":")[0] in team_routes.RULES, (k, v)
    mounts = [r.path for r in srv.app.routes if isinstance(r, Mount)]
    assert all(m in team_routes.MOUNT_RULES for m in mounts), mounts


def test_the_public_list_is_only_sign_in_liveness_and_page_shells():
    """ASVS V4.1.5 · CWE-306 · WSTG-ATHN-04: nothing under /api/ is public except signing in, liveness and status."""
    public_api = sorted(k for k, v in team_routes.ROUTE_RULES.items() if v == "public" and " /api/" in k)
    assert public_api == ["GET /api/auth/saml/finish", "GET /api/auth/saml/login", "GET /api/auth/saml/metadata",
                          "GET /api/auth/sso/callback", "GET /api/auth/sso/login", "GET /api/auth/status", "GET /api/ping",
                          "POST /api/auth/logout", "POST /api/auth/saml/acs", "POST /api/auth/team/login",
                          "POST /api/auth/team/passkey/enroll", "POST /api/auth/team/passkey/login", "POST /api/auth/team/passkey/options", "POST /api/auth/unlock"]
    for k, v in team_routes.ROUTE_RULES.items():
        if v == "public":
            assert k.startswith("GET ") or k.split(" ", 1)[1].startswith("/api/auth/"), k


def test_a_route_without_a_rule_is_refused_in_team_mode_only(world, monkeypatch):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: deny by default: a route with no rule is 403 on a team server, even for an administrator, and untouched outside team mode."""
    root = _login("root")
    assert root.get("/api/checks").status_code == 200
    monkeypatch.delitem(team_routes.ROUTE_RULES, "GET /api/checks")
    r = root.get("/api/checks")
    assert r.status_code == 403 and "no access rule" in r.json()["detail"]
    monkeypatch.delenv("ZSCALER_TEAM_MODE")
    assert TestClient(srv.app).get("/api/checks").status_code == 200


@pytest.mark.parametrize("rule", ["session", "read", "plan", "apply", "approve", "admin"])
def test_every_protected_route_refuses_a_caller_who_is_not_signed_in(team_on, rule):
    """ASVS V4.1.1 · CWE-306 · WSTG-ATHZ-01: every non-public route answers 401 to an anonymous caller on a team server, before its handler runs."""
    c = TestClient(srv.app)
    checked = 0
    for key, v in team_routes.ROUTE_RULES.items():
        if v.partition(":")[0] != rule:
            continue
        method, path = key.split(" ", 1)
        url = path.replace("{", "").replace("}", "")
        _refill()
        r = c.request(method, url, headers=ORIGIN, json={} if method != "GET" else None)
        assert r.status_code == 401, (key, r.status_code, r.text[:200])
        checked += 1
    assert checked


def test_admin_routes_refuse_every_other_role(world):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-03: an administrator's route answers 403 to a viewer, an operator and an approver."""
    admin_routes = [k for k, v in team_routes.ROUTE_RULES.items() if v == "admin"]
    for who in ("vic", "olga", "april"):
        c = _login(who)
        for key in admin_routes:
            method, path = key.split(" ", 1)
            _refill()
            r = c.request(method, path.replace("{", "").replace("}", ""), headers=ORIGIN, json={} if method != "GET" else None)
            assert r.status_code == 403, (who, key, r.status_code)


# ── 2. per-tenant-profile entitlements ──────────────────────────────────
class _FakeSdk:
    pass


@pytest.fixture
def fake_signin(monkeypatch):
    seen = []

    def build(creds):
        seen.append(dict(creds))
        return _FakeSdk()
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    monkeypatch.setattr(srv, "_readiness_token_access", lambda client, method: {})
    monkeypatch.setattr(srv, "_close_quietly", lambda client: None)
    return seen


def test_a_viewer_reads_only_the_tenant_profiles_granted(world, fake_signin):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: read on profile A signs in to A; profile B, no profile and typed details for another tenant are refused before any sign-in."""
    vic = _login("vic")
    assert vic.post("/api/tenant/check", json={"profile_id": world["a"]}, headers=ORIGIN).status_code == 200
    assert [c["vanity_domain"] for c in fake_signin] == ["acme.example"]
    r = vic.post("/api/tenant/check", json={"profile_id": world["b"]}, headers=ORIGIN)
    assert r.status_code == 403 and "may not read" in r.json()["detail"]
    r = vic.post("/api/tenant/check", json={"cloud": "zscalerten", "vanity_domain": "bolt.example", "client_id": "x", "client_secret": "y"}, headers=ORIGIN)
    assert r.status_code == 403 and "saved tenant profiles" in r.json()["detail"]
    r = vic.post("/api/tenant/check", json={"profile_id": world["a"], "vanity_domain": "bolt.example"}, headers=ORIGIN)
    assert r.status_code == 403 and "another tenant" in r.json()["detail"]
    assert len(fake_signin) == 1


def test_the_profile_list_and_profile_reads_follow_the_grants(world):
    """ASVS V4.2.1 · CWE-200 · WSTG-ATHZ-04: a person lists and opens only the tenant profiles they may read; an administrator sees all."""
    vic = _login("vic")
    assert [p["id"] for p in vic.get("/api/tenant-profiles").json()["profiles"]] == [world["a"]]
    assert vic.get(f"/api/tenant-profiles/{world['a']}").status_code == 200
    assert vic.get(f"/api/tenant-profiles/{world['b']}").status_code == 403
    root = _login("root")
    assert {p["id"] for p in root.get("/api/tenant-profiles").json()["profiles"]} == {world["a"], world["b"]}
    assert vic.post("/api/tenant-profiles", json={"name": "Evil"}, headers=ORIGIN).status_code == 403


def test_role_caps_the_grant_and_apply_needs_apply_on_that_profile(world, fake_signin, monkeypatch):
    """ASVS V4.2.1 · CWE-285 · WSTG-ATHZ-03: a viewer granted apply still cannot apply (the role caps it); an operator applies only where granted apply."""
    team.set_grant(f"user:{world['users']['vic']['id']}", world["a"], ["read", "apply"])
    vic = _login("vic")
    r = vic.post("/api/dlp-packs/apply", json={"profile_id": world["a"]}, headers=ORIGIN)
    assert r.status_code == 403 and "role" in r.json()["detail"]
    olga = _login("olga")
    r = olga.post("/api/dlp-packs/apply", json={"profile_id": world["b"]}, headers=ORIGIN)
    assert r.status_code == 403 and "may not apply" in r.json()["detail"]
    assert team.actions_on(team.get_user(world["users"]["olga"]["id"]), world["a"]) == {"read", "plan", "apply"}


def test_group_grants_and_the_every_profile_grant(world):
    """ASVS V4.2.1 · CWE-639: a grant to a group reaches its members; '*' reaches every profile; a turned-off account reaches nothing."""
    gid = team.scim_create_group({"displayName": "Readers", "members": [{"value": world["users"]["bea"]["id"]}]}, "/x")["id"]
    team.set_grant(f"group:{gid}", "*", ["read"])
    bea = team.get_user(world["users"]["bea"]["id"])
    assert team.actions_on(bea, world["a"]) == {"read"}
    assert team.profiles_with(bea, "read") is None
    team.update_user(bea["id"], active=False)
    assert team.actions_on(team.get_user(bea["id"]), world["a"]) == set()


def test_reports_and_jobs_are_bound_to_their_maker_and_profile(world):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a stored report opens for its maker and for people who may read its tenant profile, and is 'not found' for anyone else."""
    tok = team.restore({"user": world["users"]["olga"]["id"], "username": "olga", "profile": world["a"], "action": "read"})
    try:
        rid = srv._remember_report("bypass", {"rows": []}, "acme")
    finally:
        team.reset(tok)
    assert _login("olga").get(f"/api/report/bypass/{rid}").status_code == 200
    assert _login("vic").get(f"/api/report/bypass/{rid}").status_code == 200      # read on A
    assert _login("bea").get(f"/api/report/bypass/{rid}").status_code == 404      # read on B only
    assert _login("bea").get("/api/report/bypass/bypass-unknownid").status_code == 404


def test_a_job_carries_its_starters_identity_and_profile(world):
    """ASVS V7.1.3 · CWE-778: a background job started on a team server is bound to its starter, and what it records names them and the profile."""
    import pack_jobs
    tok = team.restore({"user": world["users"]["olga"]["id"], "username": "olga", "profile": world["a"], "action": "read"})
    try:
        job = pack_jobs.start("t", lambda log, cancel: (audit.record("inside_job"), {"ok": True})[1])
    finally:
        team.reset(tok)
    job.thread.join(5)
    assert team.bound(job.id) == (world["users"]["olga"]["id"], world["a"])
    line = [e for e in audit.tail(50) if e.get("event") == "inside_job"][-1]
    assert line["actor"] == "olga" and line["profile"] == world["a"]


# ── 3. sign-in: lockout and rate limit ──────────────────────────────────
def test_lockout_is_enforced_even_with_the_right_password(world, monkeypatch):
    """ASVS V2.2.1 · CWE-307 · WSTG-ATHN-03: five wrong passwords lock the account; the right one is then refused (423) until the lock runs out or an administrator unlocks it."""
    c = TestClient(srv.app)
    for _ in range(team.lockout_attempts()):
        assert c.post("/api/auth/team/login", json={"username": "vic", "password": "wrong password!!"}).status_code == 401
    r = c.post("/api/auth/team/login", json={"username": "vic", "password": PW})
    assert r.status_code == 423 and "locked" in r.json()["detail"] and "set-cookie" not in r.headers
    assert any(e.get("event") == "team_account_locked" for e in audit.tail(100))
    team.unlock_user(world["users"]["vic"]["id"], by="root")
    assert c.post("/api/auth/team/login", json={"username": "vic", "password": PW}).status_code == 200
    # the lock also runs out on its own
    c = TestClient(srv.app)
    for _ in range(team.lockout_attempts()):
        c.post("/api/auth/team/login", json={"username": "olga", "password": "nope nope nope"})
    assert c.post("/api/auth/team/login", json={"username": "olga", "password": PW}).status_code == 423
    later = time.time() + team.lockout_seconds() + 1
    monkeypatch.setattr(team, "_clock", lambda: later)
    assert c.post("/api/auth/team/login", json={"username": "olga", "password": PW}).status_code == 200


def test_unknown_names_answer_like_wrong_passwords_and_lock_too(world):
    """ASVS V2.2.1 · V3.2.4 · CWE-204 · WSTG-IDNT-04: a name with no account gets the same answer as a wrong password, and locks out the same way."""
    c = TestClient(srv.app)
    a = c.post("/api/auth/team/login", json={"username": "nobody", "password": "whatever whatever"}).json()
    b = c.post("/api/auth/team/login", json={"username": "vic", "password": "whatever whatever"}).json()
    assert a == b
    for _ in range(team.lockout_attempts()):
        c.post("/api/auth/team/login", json={"username": "ghost", "password": "x" * 12})
    assert c.post("/api/auth/team/login", json={"username": "ghost", "password": "x" * 12}).status_code == 423


def test_sign_in_attempts_are_rate_limited_per_address(world):
    """ASVS V11.1.4 · CWE-307 · WSTG-ATHN-03: past the per-address limit every sign-in is 429, even a right one."""
    c = TestClient(srv.app)
    for i in range(team.LOGIN_IP_ATTEMPTS):
        c.post("/api/auth/team/login", json={"username": f"n{i}", "password": "x" * 12})
    r = c.post("/api/auth/team/login", json={"username": "root", "password": PW})
    assert r.status_code == 429 and r.headers.get("retry-after")


def test_passwords_are_scrypt_hashes_and_the_policy_holds(world):
    """ASVS V2.4.1 · V2.1.1 · CWE-916 · CWE-521: the store holds an scrypt hash with a salt, never the password; a short password or the user name is refused."""
    raw = read_store_text(team.store_path())
    assert PW not in raw and "scrypt$" in raw
    assert stat.S_IMODE(os.stat(team.store_path()).st_mode) == 0o600
    with pytest.raises(team.TeamError):
        team.create_user(username="short", role="viewer", password="too short")
    with pytest.raises(team.TeamError):
        team.create_user(username="sameasuser1", role="viewer", password="sameasuser1")
    h1, h2 = team.hash_password(PW), team.hash_password(PW)
    assert h1 != h2 and team.verify_password(PW, h1) and not team.verify_password(PW + "x", h1)
    assert not team.verify_password(PW, "scrypt$99$8$1$AAAA$AAAA") and not team.verify_password(PW, "")


# ── 4. sessions and cookies ─────────────────────────────────────────────
def _cookie(resp):
    return [h for k, h in resp.headers.multi_items() if k.lower() == "set-cookie" and h.startswith(security.SSO_SESSION_COOKIE + "=")][0]


def test_session_cookie_is_httponly_strict_and_secure_over_https(world):
    """ASVS V3.4.1 · V3.4.2 · V3.4.3 · CWE-614 · CWE-1004 · CWE-1275 · WSTG-SESS-02: the session cookie is HttpOnly and SameSite=Strict, Secure over HTTPS, and ends with the session."""
    r = TestClient(srv.app).post("/api/auth/team/login", json={"username": "vic", "password": PW})
    ck = _cookie(r).lower()
    assert "httponly" in ck and "samesite=strict" in ck and "secure" not in ck and f"max-age={team.session_seconds()}" in ck
    r = TestClient(srv.app, base_url="https://testserver").post("/api/auth/team/login", json={"username": "vic", "password": PW})
    ck = _cookie(r).lower()
    assert "httponly" in ck and "samesite=strict" in ck and "; secure" in ck


def test_sign_in_rotates_the_session_id(world):
    """ASVS V3.2.1 · CWE-384 · WSTG-SESS-03: signing in again gives a new session id and the old one stops working."""
    c = _login("vic")
    old = c.cookies.get(security.SSO_SESSION_COOKIE)
    c.post("/api/auth/team/login", json={"username": "vic", "password": PW}, headers=ORIGIN)
    new = c.cookies.get(security.SSO_SESSION_COOKIE)
    assert new and new != old and sso.get_session(old) is None
    stale = TestClient(srv.app)
    stale.cookies.set(security.SSO_SESSION_COOKIE, old)
    assert stale.get("/api/checks").status_code == 401


def test_idle_and_absolute_timeouts_end_the_session(world):
    """ASVS V3.3.2 · V3.3.4 · CWE-613 · WSTG-SESS-07: a session unused past the idle limit, or older than the absolute limit, no longer gets in."""
    c = _login("vic")
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    assert c.get("/api/checks").status_code == 200
    sso._SESSIONS[sid]["last_seen"] -= team.idle_seconds() + 1
    assert c.get("/api/checks").status_code == 401
    c = _login("vic")
    sid = c.cookies.get(security.SSO_SESSION_COOKIE)
    sso._SESSIONS[sid]["expires"] = time.time() - 1
    assert c.get("/api/checks").status_code == 401


def test_turning_an_account_off_or_changing_its_role_ends_its_sessions(world):
    """ASVS V3.3.1 · CWE-613: a disabled account or a role change ends the person's sessions at once."""
    c = _login("vic")
    team.update_user(world["users"]["vic"]["id"], role="operator", by="root")
    assert c.get("/api/checks").status_code == 401
    c = _login("vic")
    team.update_user(world["users"]["vic"]["id"], active=False, by="root")
    assert c.get("/api/checks").status_code == 401


def test_the_ui_token_is_refused_in_every_form_on_a_team_server(world, monkeypatch):
    """ASVS V2.10.1 · CWE-287 · WSTG-ATHN-04: the static UI token (header, cookie, address, unlock) does not get in on a team server."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    tok = security.ui_token()
    c = TestClient(srv.app)
    assert c.get("/api/checks", headers={security.UI_TOKEN_HEADER: tok}).status_code == 401
    assert c.get("/api/checks", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert c.post("/api/auth/unlock", json={"token": tok}).status_code == 403
    r = c.get(f"/?token={tok}", follow_redirects=False)
    assert r.status_code == 200 and security.UI_TOKEN_COOKIE not in r.headers.get("set-cookie", "")


# ── 5. CSRF and origin ──────────────────────────────────────────────────
def test_cross_site_and_origin_less_changes_with_a_session_are_refused(world):
    """ASVS V4.2.2 · V13.2.3 · CWE-352 · WSTG-SESS-05: a change carrying the session cookie from another origin, or with no Origin at all, is refused; the same origin passes."""
    c = _login("root")
    body = {"username": "mallory", "role": "admin", "password": PW}
    assert c.post("/api/team/users", json=body, headers={"Origin": "http://evil.example"}).status_code == 403
    assert c.post("/api/team/users", json=body).status_code == 403
    assert c.post("/api/team/users", json=body, headers={"Referer": "http://evil.example/x"}).status_code == 403
    assert team.find_user("mallory") is None
    assert c.post("/api/team/users", json=body, headers=ORIGIN).status_code == 200


# ── 6. SCIM ─────────────────────────────────────────────────────────────
def test_scim_needs_its_bearer_token_which_is_stored_hashed_and_shown_once(world):
    """ASVS V2.10.4 · V3.5.2 · CWE-522 · CWE-287 · WSTG-ATHN-04: SCIM refuses no token, a wrong token and a session cookie; the right token works; the store holds only its SHA-256."""
    root = _login("root")
    anon = TestClient(srv.app)
    assert anon.get("/api/scim/v2/Users").status_code == 401
    r = root.post("/api/team/scim-token", headers=ORIGIN)
    token = r.json()["token"]
    assert r.headers["cache-control"] == "no-store" and len(token) > 40
    raw = read_store_text(team.store_path())
    assert token not in raw and team.hashlib.sha256(token.encode()).hexdigest() in raw
    assert "token" not in json.dumps(root.get("/api/team/overview").json()["scim"]).replace("token_", "").replace('"configured"', "")
    assert anon.get("/api/scim/v2/Users", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert root.get("/api/scim/v2/Users").status_code == 401        # a session is not the SCIM credential
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}
    r = anon.post("/api/scim/v2/Users", headers=h, content=json.dumps({"schemas": [team.SCIM_USER], "userName": "sam@example.com",
                                                                        "emails": [{"value": "sam@example.com", "primary": True}], "roles": [{"value": "operator"}]}))
    assert r.status_code == 201 and r.headers["content-type"].startswith("application/scim+json")
    uid = r.json()["id"]
    assert team.get_user(uid)["role"] == "operator" and not team.get_user(uid)["password"]
    assert anon.get('/api/scim/v2/Users?filter=userName eq "sam@example.com"', headers=h).json()["totalResults"] == 1
    r = anon.post("/api/scim/v2/Users", headers=h, content=json.dumps({"userName": "boss", "roles": [{"value": "admin"}]}))
    assert r.status_code == 400 and team.find_user("boss") is None
    patch = {"schemas": [team.SCIM_PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]}
    assert anon.patch(f"/api/scim/v2/Users/{uid}", headers=h, content=json.dumps(patch)).json()["active"] is False
    g = anon.post("/api/scim/v2/Groups", headers=h, content=json.dumps({"displayName": "Ops", "members": [{"value": uid}]})).json()
    assert g["members"][0]["value"] == uid
    root.request("DELETE", "/api/team/scim-token", headers=ORIGIN)
    assert anon.get("/api/scim/v2/Users", headers=h).status_code == 401
    assert any(e.get("event") == "scim_denied" for e in audit.tail(200))


def test_scim_and_the_team_routes_do_not_exist_outside_team_mode(monkeypatch):
    """ASVS V14.1.1 · CWE-1188: team mode is off by default: SCIM and the team API answer 404 and the default sign-in status is unchanged."""
    monkeypatch.delenv("ZSCALER_TEAM_MODE", raising=False)
    c = TestClient(srv.app)
    assert c.get("/api/scim/v2/Users", headers={"Authorization": "Bearer x"}).status_code == 404
    assert c.post("/api/auth/team/login", json={"username": "a", "password": "b"}).status_code == 404
    assert c.get("/api/team/me").status_code == 404
    st = c.get("/api/auth/status").json()
    assert st == {"required": False, "unlocked": True, "token_file": None, "sso": False}
    assert not team.enabled()


# ── 7. TLS and binding ──────────────────────────────────────────────────
def test_team_mode_binds_beyond_loopback_only_with_https(team_on, monkeypatch, tmp_path):
    """ASVS V9.1.1 · V14.1.1 · CWE-319 · WSTG-CRYP-03: a team server reachable beyond loopback refuses to start without HTTPS, and starts with it."""
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    with pytest.raises(RuntimeError, match="without HTTPS"):
        security.require_safe_bind()
    monkeypatch.setenv("ZSCALER_TLS", "self-signed")
    security.require_safe_bind()
    monkeypatch.setenv("ZSCALER_BIND_HOST", "127.0.0.1")
    monkeypatch.delenv("ZSCALER_TLS")
    security.require_safe_bind()                       # loopback: fine either way
    monkeypatch.setenv("DLP_CHECK_IN_CONTAINER", "1")
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "0.0.0.0")
    with pytest.raises(RuntimeError, match="without HTTPS"):
        security.require_safe_bind()
    monkeypatch.setenv("DLP_CHECK_HOST_BIND", "127.0.0.1")
    security.require_safe_bind()


def test_other_ways_beyond_loopback_still_start_with_a_loud_warning(monkeypatch, capsys):
    """ASVS V14.1.1 · CWE-1188: without team mode the reverse-proxy opt-in still starts as before, with a loud warning that team mode with HTTPS is the supported way."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("ZSCALER_ALLOW_NONLOCAL_BIND", "YES_I_UNDERSTAND")
    security.require_safe_bind()
    err = capsys.readouterr().err
    assert "WARNING" in err and "ZSCALER_TEAM_MODE=1" in err
    monkeypatch.setenv("ZSCALER_BIND_HOST", "127.0.0.1")
    security.require_safe_bind()
    assert "WARNING" not in capsys.readouterr().err


def test_self_signed_certificate_is_made_once_owner_only_with_its_fingerprint(monkeypatch, tmp_path):
    """ASVS V9.2.1 · V6.4.1 · CWE-295 · CWE-732: a self-signed certificate is made with the pinned library, its key is owner-only, its SHA-256 fingerprint is shown, and it is reused."""
    monkeypatch.setenv("ZSCALER_TLS", "self-signed")
    monkeypatch.setenv("DLP_CHECK_TLS_DIR", str(tmp_path / "tls"))
    info = server_tls.ensure()
    assert info["generated"] and info["self_signed"] and len(info["fingerprint"]) == 95
    assert stat.S_IMODE(os.stat(info["key"]).st_mode) == 0o600
    again = server_tls.ensure()
    assert not again["generated"] and again["fingerprint"] == info["fingerprint"]
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(open(info["cert"], "rb").read())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert "localhost" in names
    monkeypatch.setenv("ZSCALER_TLS_CERT", str(tmp_path / "missing.pem"))
    with pytest.raises(RuntimeError):
        server_tls.ensure()


def test_hsts_only_on_a_team_server_over_https(world, monkeypatch):
    """ASVS V14.4.5 · CWE-319 · WSTG-CONF-07: HSTS is sent by a team server answering over HTTPS, never over plain HTTP, never off team mode."""
    assert "strict-transport-security" in TestClient(srv.app, base_url="https://testserver").get("/api/ping").headers
    assert "strict-transport-security" not in TestClient(srv.app).get("/api/ping").headers
    monkeypatch.delenv("ZSCALER_TEAM_MODE")
    assert "strict-transport-security" not in TestClient(srv.app, base_url="https://testserver").get("/api/ping").headers


# ── 8. audit ────────────────────────────────────────────────────────────
def test_audit_entries_name_the_actor_and_profile_and_viewers_see_only_their_tenants(world):
    """ASVS V7.1.3 · V7.2.1 · CWE-778 · CWE-200 · WSTG-ATHZ-04: every call is audited with its actor and tenant profile; a viewer's audit read is filtered to their tenants; refusals are audited."""
    olga = _login("olga")
    olga.post("/api/workspace/notes", json={"profile_id": world["a"], "kind": "rule", "ref": "1", "action": "add_tag", "tag": "x"}, headers=ORIGIN)
    olga.post("/api/workspace/notes", json={"profile_id": world["b"], "kind": "rule", "ref": "1", "action": "add_tag", "tag": "x"}, headers=ORIGIN)
    entries = audit.tail(500)
    mine = [e for e in entries if e.get("event") == "api" and e.get("path") == "/api/workspace/notes"]
    assert mine and all(e["actor"] == "olga" for e in mine) and mine[0]["profile"] == world["a"]
    denied = [e for e in entries if e.get("event") == "team_access_denied"]
    assert denied and denied[-1]["actor"] == "olga"
    synthetic = [{"event": "x", "profile": world["a"]}, {"event": "y", "profile": world["b"]}, {"event": "z"}]
    tok = team.restore({"user": world["users"]["vic"]["id"], "username": "vic", "profile": "", "action": "read"})
    try:
        assert [e["event"] for e in team.filter_audit_entries(synthetic)] == ["x"]
    finally:
        team.reset(tok)
    tok = team.restore({"user": world["users"]["root"]["id"], "username": "root", "profile": "", "action": "read"})
    try:
        assert len(team.filter_audit_entries(synthetic)) == 3
    finally:
        team.reset(tok)


# ── 9. four-eyes with real identities ───────────────────────────────────
def _file_request(world, by, profile):
    user = team.find_user(by)
    tok = team.restore({"user": user["id"], "username": by, "profile": profile, "action": "plan"})
    try:
        return change_queue.file_request(kind="pack_deploy", tenant="acme.example" if profile == world["a"] else "bolt.example",
                                         tenant_label="t", title="t", summary={}, items=[{"kind": "rule", "name": "r", "status": "create"}],
                                         plan_hash="h" * 64 + by, requested_by=by, payload={})
    finally:
        team.reset(tok)


def test_approver_must_differ_from_the_requester_and_be_entitled(world, monkeypatch):
    """ASVS V1.4.1 · V4.1.3 · CWE-654 · CWE-285 · WSTG-BUSL-01: on a team server the requester cannot approve their own change (even an administrator, even with DLP_CHECK_FOUR_EYES=0); another person needs approve on that tenant profile."""
    monkeypatch.setenv("DLP_CHECK_FOUR_EYES", "0")
    assert change_queue.four_eyes_required()
    rec = _file_request(world, "root", world["a"])
    assert rec["profile_id"] == world["a"]
    root = _login("root")
    r = root.post(f"/api/change-queue/{rec['id']}/approve", json={"comment": "mine"}, headers=ORIGIN)
    assert r.status_code == 403 and "four-eyes" in r.json()["detail"]
    assert _login("bea").post(f"/api/change-queue/{rec['id']}/approve", json={}, headers=ORIGIN).status_code == 404   # approve on B only
    assert _login("vic").post(f"/api/change-queue/{rec['id']}/approve", json={}, headers=ORIGIN).status_code == 403   # a viewer
    r = _login("april").post(f"/api/change-queue/{rec['id']}/approve", json={"comment": "ok"}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["request"]["decided_by"] == "april"
    line = [e for e in audit.tail(200) if e.get("event") == "change_request" and e.get("action") == "approved"][-1]
    assert line["actor"] == "april" and line["requested_by"] == "root"


def test_the_queue_lists_only_the_persons_tenant_profiles(world):
    """ASVS V4.2.1 · CWE-200 · WSTG-ATHZ-04: the change queue and its export show a person only the requests of tenant profiles they may read."""
    _file_request(world, "root", world["a"])
    _file_request(world, "root", world["b"])
    assert len(_login("vic").get("/api/change-queue").json()["items"]) == 1
    assert len(_login("bea").get("/api/change-queue").json()["items"]) == 1
    assert len(_login("root").get("/api/change-queue").json()["items"]) == 2
    assert _login("vic").get("/api/change-queue/export?format=json").json()["items"][0]["profile_id"] == world["a"]


# ── 10. administration guards ───────────────────────────────────────────
def test_the_last_administrator_cannot_be_removed_and_scim_never_makes_one(world):
    """ASVS V4.1.3 · CWE-269: the last active administrator cannot be demoted, turned off or deleted; SCIM cannot grant or remove administrator."""
    rid = world["users"]["root"]["id"]
    for fn in (lambda: team.update_user(rid, role="viewer"), lambda: team.update_user(rid, active=False), lambda: team.delete_user(rid)):
        with pytest.raises(team.TeamError):
            fn()
    with pytest.raises(team.ScimError):
        team.scim_delete_user(rid)
    patch = {"schemas": [team.SCIM_PATCH], "Operations": [{"op": "add", "path": "roles", "value": [{"value": "viewer"}]}]}
    team.scim_patch_user(rid, patch, "/x")
    assert team.get_user(rid)["role"] == "admin"


def test_oidc_sign_in_matches_only_a_verified_email_or_a_linked_subject(world):
    """ASVS V2.10.1 · CWE-287 · CWE-290: an identity-provider sign-in reaches an account only through a verified email (then linked to its subject) or that subject."""
    assert team.link_oidc({"sub": "s1", "email": "vic", "email_verified": False}) is None
    team.update_user(world["users"]["vic"]["id"], email="vic@example.com")
    assert team.link_oidc({"sub": "s1", "email": "vic@example.com", "email_verified": True})["username"] == "vic"
    assert team.link_oidc({"sub": "s1"})["username"] == "vic"
    assert team.link_oidc({"sub": "s2", "email": "vic@example.com", "email_verified": True}) is None   # linked to s1 already
    assert team.link_oidc({"sub": "s9", "email": "nobody@example.com", "email_verified": True}) is None
