"""Authentication and session handling, checked over the whole route table.

Every rule that must hold for every endpoint (the UI token gate, the CSRF
Origin/Referer check) is table-driven over `dlp_api_server.app.routes`, so a
new endpoint that is reachable without the token, or that accepts a
cross-site form post, fails CI here. The few routes a browser needs before it
holds the token are pinned below: adding one is a reviewed change to this file.

Mappings: OWASP ASVS 4.0.3 Level 2, OWASP Top 10 2021, CWE, OWASP WSTG.
Deterministic: no sleeps, no network, randomness injected where it matters.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Mount, Route, WebSocketRoute

import dlp_api_server as srv
import security
import sso

TOKEN = "qa-auth-session-token-0123456789"   # test value only, never a real credential
WRONG = "qa-auth-session-token-0123456788"   # same length, last character differs

# Routes a browser may reach before it holds the token, pinned (method, path).
# Everything else needs the token. /report/* pages are covered by a rule
# below (GET-only static HTML, identical with and without the token).
PINNED_UNAUTHENTICATED = {
    ("GET", "/"), ("GET", "/app.css"), ("GET", "/permissions"), ("GET", "/help"), ("GET", "/favicon.ico"),
    ("GET", "/api/ping"), ("GET", "/api/auth/status"), ("POST", "/api/auth/unlock"),
    ("GET", "/api/auth/sso/login"), ("GET", "/api/auth/sso/callback"), ("POST", "/api/auth/logout"),
}
PINNED_EXEMPT_PATHS = {p for _, p in PINNED_UNAUTHENTICATED}
PINNED_EXEMPT_PREFIXES = ("/static/", "/report/")
STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


def _route_table():
    rows = []
    for r in srv.app.routes:
        if isinstance(r, Route):
            for m in sorted((r.methods or set()) - {"HEAD"}):
                rows.append((m, r.path))
    return sorted(rows)


ROUTES = _route_table()
GATED = [r for r in ROUTES if r not in PINNED_UNAUTHENTICATED and not r[1].startswith(PINNED_EXEMPT_PREFIXES)]
REPORT_PAGES = [r for r in ROUTES if r[1].startswith("/report/")]
WRITES = [r for r in ROUTES if r[0] in STATE_CHANGING]


@pytest.fixture(autouse=True)
def _no_process_side_effects(monkeypatch):
    """Fail closed if a refused request ever reaches a handler that restarts
    or updates the app: before the CSRF fix, a post from http://localhost
    reached /api/app/restart and its os._exit ended the test run."""
    import subprocess

    def refuse(*_a, **_k):
        raise AssertionError("a request that should have been refused reached a process-level side effect")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(os, "_exit", refuse)


@pytest.fixture
def gate_on(monkeypatch):
    """UI token gate on with a known token, SSO off."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_UI_TOKEN", TOKEN)
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)
    monkeypatch.setattr(security, "_ui_token", None)
    return TestClient(srv.app)


@pytest.fixture
def gate_off(monkeypatch):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)


def _refill_rate_limit():
    """The per-IP limiter (20/s, burst 60) is not under test here; a test that
    walks the whole route table refills it between calls (as conftest does
    between tests)."""
    layer = getattr(srv.app, "middleware_stack", None)
    while layer is not None:
        if isinstance(layer, security.RateLimitMiddleware):
            layer.buckets.clear()
            return
        layer = getattr(layer, "app", None)


def _asgi(method, path, headers, server=("127.0.0.1", 8000), body=b""):
    """One request straight through the ASGI app with raw header bytes and a
    chosen local address (what uvicorn puts in scope["server"])."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "headers": [(k.lower().encode("latin-1"), v if isinstance(v, bytes) else v.encode("latin-1")) for k, v in headers],
             "client": ("127.0.0.1", 5555), "server": server}
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    try:
        asyncio.run(srv.app(scope, receive, send))
    except Exception:  # noqa: BLE001 - the server error middleware re-raises after sending its 500
        pass
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return status, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


# ── 1. The UI token on every endpoint ──────────────────────────────────

@pytest.mark.parametrize("method,path", GATED, ids=[f"{m} {p}" for m, p in GATED])
def test_every_endpoint_refuses_a_request_without_a_valid_token(gate_on, method, path):
    """ASVS V4.1.1 · V13.1.4 · CWE-306 · A01:2021 · WSTG-ATHN-04: no token, a wrong token in any form, or the token in the URL is a 401 on every non-public route."""
    c = gate_on
    url = _concrete(path)
    attempts = {
        "no token": {},
        "wrong header": {"headers": {security.UI_TOKEN_HEADER: WRONG}},
        "wrong bearer": {"headers": {"Authorization": f"Bearer {WRONG}"}},
        "basic auth": {"headers": {"Authorization": "Basic " + TOKEN}},
        "token in query": {"params": {"token": TOKEN}},
        "token in another cookie": {"cookies": {"token": TOKEN}},
    }
    for name, kw in attempts.items():
        cookies = kw.pop("cookies", None)
        client = TestClient(srv.app, cookies=cookies) if cookies else c
        r = client.request(method, url, **kw)
        assert r.status_code == 401, (name, method, path, r.status_code)
        assert TOKEN not in r.text
    c.cookies.set(security.UI_TOKEN_COOKIE, WRONG)
    assert c.request(method, url).status_code == 401, ("wrong cookie", method, path)
    if method == "GET":
        assert TestClient(srv.app).head(url).status_code == 401, ("HEAD", path)


@pytest.mark.parametrize("form", ["header", "bearer", "cookie"])
def test_the_valid_token_is_accepted_in_a_header_a_bearer_or_the_cookie(gate_on, form):
    """ASVS V3.5.2 · CWE-287 · WSTG-ATHN-04: positive control for the table above, so the 401s are not an always-closed gate."""
    kw = {"header": {"headers": {security.UI_TOKEN_HEADER: TOKEN}},
          "bearer": {"headers": {"Authorization": f"Bearer {TOKEN}"}},
          "cookie": {}}[form]
    c = TestClient(srv.app, cookies={security.UI_TOKEN_COOKIE: TOKEN}) if form == "cookie" else gate_on
    assert c.get("/api/health", **kw).status_code == 200


def test_only_the_pinned_routes_are_reachable_without_the_token(gate_on):
    """ASVS V4.1.5 · V1.4.4 · CWE-862 · A01:2021: deny by default; the routes that answer with no token are exactly the reviewed list."""
    # Arrange
    assert security._UI_AUTH_EXEMPT_PATHS == PINNED_EXEMPT_PATHS
    assert tuple(security._UI_AUTH_EXEMPT_PREFIXES) == PINNED_EXEMPT_PREFIXES
    # Act
    open_routes = set()
    for m, p in ROUTES:
        if p.startswith("/report/"):
            continue
        _refill_rate_limit()
        if gate_on.request(m, _concrete(p), follow_redirects=False).status_code != 401:
            open_routes.add((m, p))
    # Assert
    assert open_routes == PINNED_UNAUTHENTICATED


@pytest.mark.parametrize("method,path", REPORT_PAGES, ids=[f"{m} {p}" for m, p in REPORT_PAGES])
def test_report_pages_are_static_html_that_carry_no_caller_data(gate_on, method, path):
    """ASVS V8.3.1 · CWE-200 · A01:2021: a /report/ route is served without the token, so it must be a GET of the same static HTML for everyone."""
    assert method == "GET", "a non-GET under /report/ would be an unauthenticated action"
    anon = gate_on.get(path)
    authed = TestClient(srv.app, cookies={security.UI_TOKEN_COOKIE: TOKEN}).get(path)
    assert anon.status_code == 200 and anon.headers["content-type"].startswith("text/html")
    assert anon.content == authed.content, "the page must not vary with the caller's credentials"


def test_the_static_mount_holds_only_shipped_assets_and_resists_traversal(gate_on):
    """ASVS V12.5.1 · V12.3.1 · CWE-22 · CWE-552 · WSTG-ATHZ-01: /static/ is public, so it may only hold the app's own assets and never escape its folder."""
    mounts = [r for r in srv.app.routes if isinstance(r, Mount)]
    assert [m.path for m in mounts] == ["/static"]
    allowed = {".html", ".js", ".css", ".svg", ".png", ".webp", ".jpg", ".jpeg", ".gif", ".ico", ".woff2", ".md"}
    for root, _dirs, files in os.walk(srv.STATIC_DIR):
        for f in files:
            full = os.path.join(root, f)
            assert not os.path.islink(full), full
            assert os.path.splitext(f)[1].lower() in allowed, f"unexpected file type served without the token: {full}"
    for probe in ("/static/../security.py", "/static/%2e%2e/security.py", "/static/..%2fsecurity.py", "/static/%2e%2e%2fui_token.txt"):
        r = gate_on.get(probe)
        assert r.status_code in (401, 404), (probe, r.status_code)
        assert "def ui_token" not in r.text


def test_no_websocket_route_exists_because_the_gate_is_http_only(gate_on):
    """ASVS V4.1.1 · CWE-306 · CWE-1385 · WSTG-CLNT-10: UIAuthMiddleware is HTTP middleware; a websocket route would bypass it, so none may exist and a websocket handshake is closed."""
    assert not [r for r in srv.app.routes if isinstance(r, WebSocketRoute)]
    sent = []

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "websocket", "path": "/api/assess/stream", "raw_path": b"/api/assess/stream", "headers": [],
             "query_string": b"", "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8000), "subprotocols": [],
             "scheme": "ws", "root_path": ""}
    asyncio.run(srv.app(scope, receive, send))
    assert sent and sent[0]["type"] == "websocket.close" and not any(m["type"] == "websocket.accept" for m in sent)


def test_event_stream_endpoints_are_in_the_gated_table():
    """ASVS V4.1.1 · CWE-306: every streaming (server-sent events) handler is a gated route, so the table above covers it."""
    import inspect
    sse = [(m, r.path) for r in srv.app.routes if isinstance(r, Route)
           for m in (r.methods or set()) - {"HEAD"}
           if "text/event-stream" in inspect.getsource(r.endpoint)]
    assert sse, "the assessment stream exists"
    assert all(s in GATED for s in sse), sse


# ── 2. Token comparison, strength and rotation ─────────────────────────

@pytest.mark.parametrize("candidate,ok", [
    (TOKEN, True), (f"  {TOKEN}\t", True),
    ("", False), ("   ", False), (None, False), (WRONG, False), (TOKEN[:-1], False), (TOKEN + "x", False),
    (TOKEN.upper(), False), ("é" * len(TOKEN), False), (TOKEN[:-1] + "é", False), ("\x00" + TOKEN, False),
])
def test_token_comparison_is_constant_time_and_exact(monkeypatch, candidate, ok):
    """ASVS V6.2.1 · CWE-208 · CWE-697: the token is compared with secrets.compare_digest on bytes, so it is exact, timing-safe and never raises."""
    monkeypatch.setenv("ZSCALER_UI_TOKEN", TOKEN)
    monkeypatch.setattr(security, "_ui_token", None)
    calls = []
    real = security._secrets.compare_digest

    def spy(a, b):
        calls.append((type(a), type(b)))
        return real(a, b)

    monkeypatch.setattr(security._secrets, "compare_digest", spy)
    assert security.ui_token_ok(candidate) is ok
    if (candidate or "").strip():
        assert calls == [(bytes, bytes)], "compared in constant time, as bytes (str compare_digest raises on non-ASCII)"


@pytest.mark.parametrize("header", [b"\xe9t\xe9", ("é" * 8).encode("latin-1"), b"\xff" * 40])
def test_a_non_ascii_token_is_a_401_that_is_audited_not_a_500(gate_on, monkeypatch, tmp_path, header):
    """ASVS V7.4.1 · V7.2.1 · CWE-755 · CWE-778 · WSTG-ERRH-01: a token with non-ASCII bytes is refused like any wrong token and the attempt is logged."""
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    status, body = _asgi("GET", "/api/health", [("host", "127.0.0.1:8000"), (security.UI_TOKEN_HEADER, header)])
    assert status == 401 and b"token_required" in body
    events = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()]
    assert [e["reason"] for e in events if e["event"] == "auth_denied"] == ["invalid UI token"]


def test_the_ui_token_is_rotated_on_every_restart(monkeypatch):
    """ASVS V3.3.1 · V2.10.2 · CWE-613 · CWE-798: without ZSCALER_UI_TOKEN each server process mints its own token (no default credential), and the previous one stops working."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.delenv("ZSCALER_UI_TOKEN", raising=False)
    minted = iter(["A" * 32, "B" * 32])
    asked = []

    def fake_token_urlsafe(n):
        asked.append(n)
        return next(minted)

    monkeypatch.setattr(security._secrets, "token_urlsafe", fake_token_urlsafe)
    monkeypatch.setattr(security, "_ui_token", None)              # process 1 starts
    first = security.ui_token()
    assert security.ui_token() == first                           # stable for the process's life
    monkeypatch.setattr(security, "_ui_token", None)              # restart
    second = security.ui_token()
    assert first != second and asked == [24, 24], "192 bits of fresh randomness each start"
    old = TestClient(srv.app, cookies={security.UI_TOKEN_COOKIE: first})
    assert old.get("/api/health").status_code == 401
    assert TestClient(srv.app, cookies={security.UI_TOKEN_COOKIE: second}).get("/api/health").status_code == 200


# ── 3. Cookie flags ────────────────────────────────────────────────────

def _flags(set_cookie: str) -> dict:
    parts = [p.strip() for p in set_cookie.split(";")]
    out = {"_name": parts[0].split("=", 1)[0]}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        out[k.lower()] = v.lower() if v else True
    return out


@pytest.mark.parametrize("how", ["launcher_url", "unlock"])
@pytest.mark.parametrize("base_url,headers,secure", [
    ("http://127.0.0.1:8000", {}, False),
    ("https://127.0.0.1:8000", {}, True),
    ("http://127.0.0.1:8000", {"X-Forwarded-Proto": "https"}, True),
])
def test_the_ui_token_cookie_is_httponly_samesite_strict_and_secure_over_https(gate_on, how, base_url, headers, secure):
    """ASVS V3.4.1 · V3.4.2 · V3.4.3 · V3.4.5 · CWE-1004 · CWE-614 · CWE-1275 · WSTG-SESS-02: the token cookie is HttpOnly, SameSite=Strict, Path=/, bounded and Secure when served over HTTPS."""
    c = TestClient(srv.app, base_url=base_url)
    if how == "launcher_url":
        r = c.get(f"/?token={TOKEN}", headers=headers, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/"
    else:
        r = c.post("/api/auth/unlock", json={"token": TOKEN}, headers=headers)
        assert r.status_code == 200
    f = _flags(r.headers["set-cookie"])
    assert f["_name"] == security.UI_TOKEN_COOKIE
    assert f.get("httponly") is True and f.get("samesite") == "strict" and f.get("path") == "/"
    assert 0 < int(f["max-age"]) <= 12 * 3600
    assert bool(f.get("secure")) is secure


def test_a_wrong_token_never_sets_a_cookie(gate_on):
    """ASVS V3.2.1 · CWE-384: a refused token (URL or unlock) gets a 401 and no cookie."""
    assert "set-cookie" not in gate_on.get(f"/?token={WRONG}", follow_redirects=False).headers
    assert "set-cookie" not in gate_on.post("/api/auth/unlock", json={"token": WRONG}).headers


# ── 4. CSRF: cross-site form posts ─────────────────────────────────────

HOSTILE_ORIGINS = ["https://attacker.example", "null", "http://localhost", "http://127.0.0.1",
                   "http://localhost:9999", "http://127.0.0.1:8001"]
FORM_BODIES = {
    "text/plain": (b'{"a":"b"}', "text/plain"),
    "urlencoded": (b"a=b", "application/x-www-form-urlencoded"),
    "multipart": (b"--qa\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--qa--\r\n", "multipart/form-data; boundary=qa"),
}


@pytest.mark.parametrize("method,path", WRITES, ids=[f"{m} {p}" for m, p in WRITES])
def test_every_state_changing_endpoint_refuses_a_cross_site_form_post(gate_on, monkeypatch, method, path):
    """ASVS V4.2.2 · V13.2.3 · CWE-352 · CWE-346 · A01:2021 · WSTG-SESS-05: a form post from any other origin is refused even when the browser attaches the token cookie (another localhost port is same-site)."""
    url = _concrete(path)
    c = TestClient(srv.app, base_url="http://127.0.0.1:8000", cookies={security.UI_TOKEN_COOKIE: TOKEN})
    for origin in HOSTILE_ORIGINS:
        for kind, (body, ctype) in FORM_BODIES.items():
            r = c.request(method, url, content=body, headers={"Origin": origin, "Content-Type": ctype})
            assert r.status_code == 403, (origin, kind, r.status_code)
    r = c.request(method, url, content=b"a=b", headers={"Referer": "https://attacker.example/x", "Content-Type": FORM_BODIES["urlencoded"][1]})
    assert r.status_code == 403, "Referer-only cross-site post"
    if not security.extension_may_post(security.extension_origin(), url):
        r = c.request(method, url, content=b"{}", headers={"Origin": security.extension_origin(), "Content-Type": "text/plain"})
        assert r.status_code == 403, "the extension is trusted for its read-only endpoints only"
    # The same with the gate off (ZSCALER_UI_AUTH=0): the Origin check is then the only defence.
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    r = TestClient(srv.app, base_url="http://127.0.0.1:8000").request(
        method, url, content=b"a=b", headers={"Origin": "https://attacker.example", "Content-Type": FORM_BODIES["urlencoded"][1]})
    assert r.status_code == 403


@pytest.mark.parametrize("origin", ["http://localhost", "http://127.0.0.1", "https://attacker.example", "null"])
def test_cors_grants_no_other_origin_a_credentialed_read(gate_on, origin):
    """ASVS V14.5.3 · CWE-942 · CWE-346 · A05:2021 · WSTG-CLNT-07: no origin other than the server's own gets Access-Control-Allow-Origin, so no other page can read API responses with the cookie."""
    c = TestClient(srv.app, base_url="http://127.0.0.1:8000", cookies={security.UI_TOKEN_COOKIE: TOKEN})
    r = c.get("/api/health", headers={"Origin": origin})
    assert r.status_code == 200 and "access-control-allow-origin" not in r.headers
    pre = c.options("/api/tenant-profiles", headers={"Origin": origin, "Access-Control-Request-Method": "POST",
                                                     "Access-Control-Request-Headers": "content-type"})
    assert pre.headers.get("access-control-allow-origin") != origin


def test_the_trusted_origins_are_only_this_servers_own_port(monkeypatch):
    """ASVS V14.5.3 · CWE-942 · CWE-183: the allowlist names the configured port on localhost and 127.0.0.1, nothing on another port."""
    monkeypatch.setenv("ZSCALER_PORT", "8013")
    assert security._allowed_origins() == {"http://localhost:8013", "http://127.0.0.1:8013"}
    monkeypatch.delenv("ZSCALER_PORT")
    assert security._allowed_origins() == {"http://localhost:8000", "http://127.0.0.1:8000"}


# ── 5. DNS rebinding and the Host header ───────────────────────────────

@pytest.mark.parametrize("host", [
    "attacker.example:8000", "127.0.0.1.nip.io:8000", "127.attacker.example:8000", "127.0.0.1.attacker.example",
    "localhost.attacker.example:8000", "0.0.0.0:8000", "10.0.0.5:8000", "testserver", "testserver:8000",
    "localhost.:8000", "[::ffff:10.0.0.5]:8000",
])
def test_with_the_gate_off_only_loopback_host_names_are_served(gate_off, host):
    """ASVS V14.5.2 · CWE-350 · CWE-346 · WSTG-INPV-17 (DNS rebinding): with ZSCALER_UI_AUTH=0 a Host that is not a loopback name or address is refused before any handler runs."""
    status, body = _asgi("GET", "/api/health", [("host", host)])
    assert status == 403 and b"ZSCALER_UI_AUTH=0" in body
    status, _ = _asgi("POST", "/api/tenant/check", [("host", host), ("origin", f"http://{host}"), ("content-type", "application/json")], body=b"{}")
    assert status == 403


@pytest.mark.parametrize("host", ["localhost:8000", "localhost", "127.0.0.1:8000", "127.1.2.3:8000", "[::1]:8000", "::1"])
def test_with_the_gate_off_loopback_host_names_still_work(gate_off, host):
    """ASVS V14.5.2 · CWE-350 · WSTG-INPV-17: the boundary of the rule above; real loopback names and addresses are served."""
    assert _asgi("GET", "/api/health", [("host", host)])[0] == 200


@pytest.mark.parametrize("host", ["attacker.example:8000", "127.0.0.1.nip.io:8000"])
def test_with_the_gate_on_a_rebound_host_gets_no_data(gate_on, host):
    """ASVS V4.1.1 · CWE-350 · CWE-306: with the token gate on, a page on a rebinding name has no cookie for this server, so it reaches nothing but the public routes, which carry no data."""
    assert _asgi("GET", "/api/health", [("host", host)])[0] == 401
    status, body = _asgi("GET", "/api/auth/status", [("host", host)])
    assert status == 200 and json.loads(body)["unlocked"] is False and TOKEN.encode() not in body


# ── 6. ZSCALER_UI_AUTH=0 beyond loopback ───────────────────────────────

@pytest.mark.parametrize("off", ["0", "false", "no", "off", "OFF", " 0 "])
@pytest.mark.parametrize("bind", ["0.0.0.0", "10.1.2.3", "::", "192.168.1.20", "my-laptop"])
def test_the_gate_cannot_be_turned_off_beyond_loopback(monkeypatch, off, bind):
    """ASVS V1.14.1 · V14.1.3 · CWE-1188 · CWE-306 · A05:2021: with the token gate off the server refuses to start on any non-loopback address, even with the non-local override set."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", off)
    monkeypatch.setenv("ZSCALER_BIND_HOST", bind)
    monkeypatch.setenv("ZSCALER_ALLOW_NONLOCAL_BIND", security.NONLOCAL_BIND_CONFIRM_PHRASE)
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER", raising=False)
    with pytest.raises(RuntimeError, match="ZSCALER_UI_AUTH=0"):
        security.require_safe_bind()


@pytest.mark.parametrize("bind", ["127.0.0.1", "localhost", "::1"])
def test_the_gate_may_be_off_on_loopback(monkeypatch, bind):
    """ASVS V1.14.1 · CWE-1188: the boundary of the rule above; a loopback bind with the gate off starts (documented single-user mode)."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setenv("ZSCALER_BIND_HOST", bind)
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)
    monkeypatch.delenv("DLP_CHECK_IN_CONTAINER", raising=False)
    security.require_safe_bind()


@pytest.mark.parametrize("server", [("10.1.2.3", 8000), ("192.168.0.9", 8000), ("fe80::1", 8000)])
def test_with_the_gate_off_a_connection_on_a_network_address_is_refused(gate_off, server):
    """ASVS V1.14.1 · CWE-306 · CWE-1188: a server started some other way (uvicorn --host 0.0.0.0) with the gate off still serves loopback connections only."""
    assert _asgi("GET", "/api/health", [("host", "localhost:8000")], server=server)[0] == 503


# ── 7. SSO: writers by group, and the login bound to the browser ───────

from test_sso import _Idp, _env as _sso_env, _mock_http, _sign_in  # noqa: E402


@pytest.fixture
def idp():
    return _Idp()


@pytest.mark.parametrize("writers,claims,expected", [
    ("dlp-admins", {"groups": ["dlp-admins"]}, True),
    ("dlp-admins", {"groups": ["DLP-Admins"]}, True),
    ("dlp-admins", {"groups": "dlp-admins"}, True),
    ("dlp-admins", {"groups": ["dlp-readers"]}, False),
    ("dlp-admins", {}, False),
    ("dlp-admins", {"groups": []}, False),
    ("boss@example.com", {"email": "boss@example.com", "email_verified": True}, True),
    ("boss@example.com", {"email": "Boss@Example.com", "email_verified": "true"}, True),
    ("boss@example.com", {"email": "boss@example.com"}, False),
    ("boss@example.com", {"email": "boss@example.com", "email_verified": False}, False),
    ("boss@example.com", {"email": "boss@example.com", "email_verified": "false"}, False),
    ("dlp-admins", {"email": "dlp-admins", "email_verified": False}, False),
])
def test_writers_are_checked_by_group_or_a_verified_email(monkeypatch, idp, writers, claims, expected):
    """ASVS V4.1.3 · V4.2.1 · CWE-290 · CWE-269 · A01:2021 · WSTG-ATHZ-03: only a listed group, or a listed email the identity provider verified, may change the tenant."""
    _sso_env(monkeypatch)
    monkeypatch.setenv("ZSCALER_SSO_WRITERS", writers)
    monkeypatch.setattr(security, "_write_override", None)
    c = _sign_in(monkeypatch, idp, **claims)
    assert c.last_callback.status_code == 303
    assert c.get("/api/auth/status").json()["may_write"] is expected
    r = c.post("/api/write-mode", json={"enable": True, "confirm": security.WRITE_CONFIRM_PHRASE})
    assert (r.status_code == 403 and "ZSCALER_SSO_WRITERS" in r.text) is (not expected), r.text
    monkeypatch.setattr(security, "_write_override", None)


def test_an_sso_callback_completed_in_another_browser_is_refused(monkeypatch, idp):
    """ASVS V4.2.2 · V3.2.1 · CWE-352 · CWE-384 · WSTG-SESS-05 (login CSRF, RFC 6749 §10.12): the state is bound to the browser that started the sign-in."""
    # Arrange: the attacker starts a sign-in and gets a code for their own account
    _sso_env(monkeypatch)
    _mock_http(monkeypatch, idp)
    attacker = TestClient(srv.app)
    q = parse_qs(urlparse(attacker.get("/api/auth/sso/login", follow_redirects=False).headers["location"]).query)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=q["nonce"][0], email="attacker@example.com")})
    # Act: the victim's browser is sent to the callback with the attacker's state and code
    victim = TestClient(srv.app)
    r = victim.get(f"/api/auth/sso/callback?code=abc&state={q['state'][0]}", follow_redirects=False)
    # Assert
    assert r.status_code == 401 and security.SSO_SESSION_COOKIE not in r.headers.get("set-cookie", "")
    assert victim.get("/api/auth/status").json()["unlocked"] is False


@pytest.mark.parametrize("base_url,secure", [("http://testserver", False), ("https://testserver", True)])
def test_the_sso_cookies_are_httponly_lax_and_secure_over_https(monkeypatch, idp, base_url, secure):
    """ASVS V3.4.1 · V3.4.2 · V3.4.3 · CWE-1004 · CWE-614 · WSTG-SESS-02: the login-binding and session cookies are HttpOnly, SameSite=Lax (the IdP redirect is cross-site) and Secure over HTTPS; the binding one is scoped to the callback and short-lived."""
    _sso_env(monkeypatch)
    _mock_http(monkeypatch, idp)
    c = TestClient(srv.app, base_url=base_url)
    login = c.get("/api/auth/sso/login", follow_redirects=False)
    b = _flags(login.headers["set-cookie"])
    assert b["_name"] == security.SSO_LOGIN_COOKIE and b.get("httponly") is True and b.get("samesite") == "lax"
    assert b.get("path") == "/api/auth/sso/callback" and 0 < int(b["max-age"]) <= sso._PENDING_TTL_SECONDS
    assert bool(b.get("secure")) is secure
    q = parse_qs(urlparse(login.headers["location"]).query)
    _mock_http(monkeypatch, idp, token_response={"id_token": idp.make_id_token(nonce=q["nonce"][0])})
    cb = c.get(f"/api/auth/sso/callback?code=abc&state={q['state'][0]}", follow_redirects=False)
    assert cb.status_code == 303
    session = [_flags(v) for k, v in cb.headers.multi_items() if k == "set-cookie" and v.startswith(security.SSO_SESSION_COOKIE)]
    assert len(session) == 1
    s = session[0]
    assert s.get("httponly") is True and s.get("samesite") == "lax" and s.get("path") == "/" and bool(s.get("secure")) is secure


def test_a_failed_unlock_is_audited_as_denied_and_never_credited_to_the_token_holder(gate_on, monkeypatch, tmp_path):
    """ASVS V7.1.3 · V7.2.1 · CWE-778 · CWE-223 · A09:2021 · WSTG-ATHN-03: a wrong token posted to unlock is an auth_denied event by "not signed in", the offered value never written."""
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    assert gate_on.post("/api/auth/unlock", json={"token": WRONG}).status_code == 401
    events = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()]
    denied = [e for e in events if e["event"] == "auth_denied"]
    assert [(e["path"], e["actor"]) for e in denied] == [("/api/auth/unlock", security.NOT_SIGNED_IN)]
    assert {e["actor"] for e in events} == {security.NOT_SIGNED_IN}, "no line credits the attempt to the local UI token"
    assert WRONG not in log.read_text(encoding="utf-8") and TOKEN not in log.read_text(encoding="utf-8")
    # Boundary: a request that does carry the token is still credited to it.
    assert gate_on.post("/api/tenant/check", json={}, headers={security.UI_TOKEN_HEADER: TOKEN}).status_code != 401
    last = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert last["actor"] == security.LOCAL_TOKEN_ACTOR
