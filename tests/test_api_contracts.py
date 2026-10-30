"""API contracts: every FastAPI route of dlp_api_server, walked with malformed
input, answers with a 4xx in the app's error shape and never with a 5xx, a
traceback, an internal path, a secret or an unbounded echo of what was sent.

The walk is table-driven over `app.routes`, so a route added without
validation (a hand-parsed body, a handler that trusts a field's type, an id
it does not check) fails here. Nothing signs in: both sign-in factories are
replaced by fakes that refuse, and no request reaches a handler with valid
credentials and a valid scope at the same time (the happy paths, against the
fake tenant clients, are exercised by each feature's own tests)."""
from __future__ import annotations

import inspect
import json
import re
import typing

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel

import dlp_api_server as srv

SECRET = "contract-secret-Q7xZ-do-not-echo"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
SCOPE = {"scopes": ["dlp", "zia", "zpa", "zcc"], "from_page": True,
         "channels": {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "saas_casb": "zscaler", "email_dlp": "zscaler"}}
HUGE = "A" * 100_000
UNICODE = "‮é中\U0001F600\u0000'\"<script>../..\\"
UNKNOWN_ID = "does-not-exist-0000"
MAX_ERROR_BYTES = 20_000          # an error explains; it never carries the request back
LEAKS = re.compile(r"Traceback \(most recent|File \"/|site-packages|" + re.escape(srv._APP_DIR))

ROUTES = sorted((r for r in srv.app.routes if isinstance(r, APIRoute)), key=lambda r: (r.path, sorted(r.methods)))
ROUTE_IDS = [f"{sorted(r.methods)[0]} {r.path}" for r in ROUTES]


def _table(keep):
    """The routes (and their test ids) a rule applies to, computed from app.routes."""
    rows = [(r, i) for r, i in zip(ROUTES, ROUTE_IDS) if keep(r)]
    return {"argvalues": [r for r, _ in rows], "ids": [i for _, i in rows]}
# Fields whose hostile values must be refused before anything is signed in to.
HOSTILE_FIELDS = ("cloud", "vanity_domain", "auth_method", "customer_id", "client_id")


class _RefusingRawClient:
    def auth(self):
        return False, "refused by the contract test"

    def close(self):
        pass


def _refuse_sdk(creds):
    raise HTTPException(status_code=401, detail="Authentication refused by the contract test.")


@pytest.fixture
def client(monkeypatch, tmp_path):
    """The app with every way out replaced: no sign-in, no restart, no update."""
    import app_update
    monkeypatch.setattr(srv, "_build_sdk_client", _refuse_sdk)
    monkeypatch.setattr(srv, "_raw_client", lambda creds: _RefusingRawClient())
    monkeypatch.setattr(app_update, "schedule_restart", lambda *a, **k: pytest.fail("the walk restarted the server"))
    monkeypatch.setattr(app_update, "update", lambda *a, **k: pytest.fail("the walk ran an update"))
    for var, name in (("DLP_CHECK_PROFILES", "profiles.json"), ("DLP_CHECK_WORKSPACE_NOTES", "notes.json"),
                      ("DLP_CHECK_BEACON_STATE", "beacon.json"), ("DLP_CHECK_USER_PACKS", "user_packs"),
                      ("DLP_CHECK_POSTURE_SETTINGS", "posture_settings.json"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json"),
                      ("DLPCHECK_CHANGE_QUEUE_FILE", "change_requests.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return TestClient(srv.app, raise_server_exceptions=False)


# ── helpers ─────────────────────────────────────────────────────────────

def _kind(annotation) -> str:
    origin = typing.get_origin(annotation)
    if origin is typing.Union:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        return _kind(args[0]) if args else "any"
    if annotation is bool:
        return "bool"
    if annotation in (int, float):
        return "number"
    if annotation is str:
        return "str"
    if annotation in (list, tuple, set) or origin in (list, tuple, set):
        return "list"
    if annotation is dict or origin is dict:
        return "dict"
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return "model"
    return "any"


# A value of the wrong JSON type for each declared kind.
WRONG_TYPE = {"str": {"not": ["a string"]}, "number": "not-a-number", "bool": "maybe", "list": "not-a-list",
              "dict": "not-an-object", "model": 42}


def _body_model(route: APIRoute):
    if route.body_field is None:
        return None
    ann = route.body_field.field_info.annotation
    args = [a for a in typing.get_args(ann) if a is not type(None)] or [ann]
    return args[0] if isinstance(args[0], type) and issubclass(args[0], BaseModel) else None


def _model_fields(route: APIRoute, kind: str, names=None) -> list:
    """The body model's fields of `kind` (only those in `names` when given)."""
    model = _body_model(route)
    if model is None:
        return []
    return [n for n, f in model.model_fields.items() if _kind(f.annotation) == kind and (names is None or n in names)]


def _reads_body_itself(route: APIRoute) -> bool:
    return "_json_object(request)" in inspect.getsource(route.endpoint)


def _path(route: APIRoute, value: str = UNKNOWN_ID) -> str:
    return re.sub(r"\{(\w+)(:\w+)?\}", value, route.path)


def _method(route: APIRoute) -> str:
    return sorted(route.methods)[0]


def _assert_contract(r, what: str) -> None:
    """No 5xx; an error is a JSON {"detail": ...} without a traceback, an
    internal path or the secret, and is small."""
    text = r.text if "json" in r.headers.get("content-type", "") or "text" in r.headers.get("content-type", "") else ""
    assert r.status_code < 500, f"{what}: {r.status_code} {text[:300]}"
    assert SECRET not in text, f"{what}: the response carries the client secret back"
    if r.status_code >= 400:
        assert not LEAKS.search(text), f"{what}: traceback or internal path in {text[:300]}"
        assert len(r.content) <= MAX_ERROR_BYTES, f"{what}: a {len(r.content)}-byte error body"
        body = r.json()
        assert isinstance(body, dict) and "detail" in body, f"{what}: error without detail: {text[:200]}"


# ── the walk: every route, table-driven ─────────────────────────────────

def test_the_walk_covers_every_route():
    """ASVS V5.1.3 · A04:2021 · CWE-20: the contract walk is generated from app.routes, all of them."""
    # Arrange / Act
    walked = set(ROUTE_IDS)
    # Assert
    assert len(walked) == len(ROUTES) >= 250


# A GET without a path id answers 200 on a fresh install, except these, by design:
# SSO is off (404), the notes and proposals need to be told which tenant (400), and the fleet history compare
# needs two saved snapshots (400: a fresh install has none).
NEEDS_CONTEXT = {"/api/auth/sso/login": 404, "/api/auth/sso/callback": 404, "/api/proposals": 400, "/api/workspace/notes": 400,
                 "/api/zcc/fleet/history/compare": 400}


@pytest.mark.parametrize("route", **_table(lambda r: r.methods == {"GET"} and not r.dependant.path_params))
def test_every_get_without_an_id_answers_on_a_fresh_install(client, route):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: the happy path of every parameterless GET is a 2xx (or its documented 4xx) in the app's shape."""
    # Act
    r = client.get(route.path)
    # Assert
    _assert_contract(r, "happy path")
    assert r.status_code == NEEDS_CONTEXT.get(route.path, r.status_code if r.status_code in (200, 204) else 200), r.text[:200]


@pytest.mark.parametrize("route", **_table(lambda r: r.dependant.path_params))
def test_unknown_or_hostile_ids_are_a_4xx(client, route):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: an unknown, hostile or huge path id is a 4xx, never a 5xx."""
    body = {} if _body_model(route) is not None else None
    for label, value in (("unknown", UNKNOWN_ID), ("negative", "-1"), ("unicode", "%E2%80%AE%F0%9F%98%80%00"),
                         ("traversal", "..%2F..%2Fetc%2Fpasswd"), ("huge", "Z" * 4000)):
        # Act
        r = client.request(_method(route), _path(route, value), **({"json": body} if body is not None else {}))
        # Assert
        _assert_contract(r, f"{label} id")
        if label == "unknown" and route.path.startswith("/api/"):
            assert 400 <= r.status_code < 500, f"an unknown id answered {r.status_code}: {r.text[:200]}"


@pytest.mark.parametrize("route", **_table(lambda r: r.dependant.query_params))
def test_query_parameters_of_the_wrong_type_or_size_are_refused_cleanly(client, route):
    """ASVS V5.1.3 · V5.1.4 · A03:2021 · CWE-1287 · WSTG-ERRH-01: a query parameter of the wrong type is a 422, a huge or odd one never a 5xx."""
    params = [(p.name, _kind(p.field_info.annotation)) for p in route.dependant.query_params]
    body = {} if _body_model(route) is not None else None
    path = _path(route)
    for name, kind in params:
        for label, value in (("wrong type", "not-a-number"), ("huge", "Q" * 20_000), ("unicode", UNICODE.replace("\u0000", "")),
                             ("crlf", "a\r\nX-Injected: 1"), ("negative", "-1")):
            if label == "wrong type" and kind not in ("number", "bool"):
                continue
            # Act
            r = client.request(_method(route), path, params={name: value}, **({"json": body} if body is not None else {}))
            # Assert
            _assert_contract(r, f"query {name} {label}")
            assert "x-injected" not in {k.lower() for k in r.headers}, f"query {name}: a header was injected"
            if label == "wrong type":
                assert r.status_code == 422, f"query {name}={value!r} answered {r.status_code}"


@pytest.mark.parametrize("route", **_table(lambda r: _body_model(r) is not None))
def test_a_body_of_the_wrong_shape_is_a_4xx(client, route):
    """ASVS V5.1.4 · A03:2021 · CWE-1287 · WSTG-ERRH-01: a body that is not JSON, not an object, too deep or has a field of the wrong type is refused (4xx) before the handler runs."""
    model, path, method = _body_model(route), _path(route), _method(route)
    raw_bodies = {"not json": b"{not json", "a list": b"[]", "a string": b'"s"', "too deep": b"[" * 5000 + b"]" * 5000}
    for label, raw in raw_bodies.items():
        # Act
        r = client.request(method, path, content=raw, headers={"content-type": "application/json"})
        # Assert
        _assert_contract(r, f"body {label}")
        assert 400 <= r.status_code < 500, f"body {label} answered {r.status_code}"
    for name, field in model.model_fields.items():
        kind = _kind(field.annotation)
        if kind not in WRONG_TYPE:
            continue
        # Act
        r = client.request(method, path, json={**CREDS, name: WRONG_TYPE[kind]})
        # Assert
        _assert_contract(r, f"field {name} ({kind}) of the wrong type")
        assert r.status_code == 422, f"field {name} of the wrong type answered {r.status_code}: {r.text[:200]}"


@pytest.mark.parametrize("route", **_table(lambda r: _model_fields(r, "str", HOSTILE_FIELDS)))
def test_hostile_tenant_fields_are_refused_before_sign_in(client, route):
    """ASVS V5.1.3 · V7.4.1 · A04:2021 · CWE-20 · WSTG-ERRH-01: a huge, unicode or negative cloud, vanity domain, sign-in method or id is a 4xx (or ignored), never a 5xx or an unbounded echo."""
    path, method = _path(route), _method(route)
    for name in _model_fields(route, "str", HOSTILE_FIELDS):
        # Act: one value that is unicode, negative-looking and 100 kB at once
        r = client.request(method, path, json={**CREDS, **SCOPE, name: UNICODE + "-1" + HUGE})
        # Assert
        _assert_contract(r, f"hostile {name}")


@pytest.mark.parametrize("route", **_table(lambda r: _model_fields(r, "number")))
def test_numbers_out_of_range_are_refused_cleanly(client, route):
    """ASVS V5.1.3 · A04:2021 · CWE-1284 · WSTG-ERRH-01: a negative, 64-bit-minimum or 2**70 number in any numeric field is a 4xx (or ignored), never a 5xx."""
    path, method = _path(route), _method(route)
    for name in _model_fields(route, "number"):
        for value in (-1, -(2 ** 63), 2 ** 70):
            # Act
            r = client.request(method, path, json={**CREDS, **SCOPE, name: value})
            # Assert
            _assert_contract(r, f"{name}={value}")


@pytest.mark.parametrize("route", **_table(_reads_body_itself))
def test_a_hand_read_body_that_is_not_a_json_object_is_a_400(client, route):
    """ASVS V5.1.4 · A03:2021 · CWE-1287 · WSTG-ERRH-01: an endpoint that reads its own body answers 400 to invalid JSON, a non-object, an empty body or nesting past the parser's depth."""
    for label, raw in (("not json", b"{not json"), ("a list", b"[]"), ("null", b"null"), ("a number", b"-1"),
                       ("empty", b""), ("too deep", b"[" * 5000 + b"]" * 5000)):
        # Act
        r = client.post(_path(route), content=raw, headers={"content-type": "application/json"})
        # Assert
        _assert_contract(r, f"body {label}")
        assert r.status_code == 400, f"body {label} answered {r.status_code}: {r.text[:200]}"


def test_no_endpoint_parses_its_body_by_hand():
    """ASVS V5.1.4 · A04:2021 · CWE-20: every body is a request model or goes through _json_object (deny by default), so a new route cannot trust an unchecked body."""
    # Arrange
    offenders = []
    for route in ROUTES:
        src = inspect.getsource(route.endpoint)
        # Act
        if re.search(r"request\.(json|body|form|stream)\(\)", src):
            offenders.append(route.path)
    # Assert
    assert offenders == []


# ── regression tests for the findings ───────────────────────────────────

def test_a_422_names_the_field_and_never_echoes_the_body(client):
    """ASVS V7.4.1 · A04:2021 · CWE-209 · WSTG-ERRH-01: a missing or mistyped field is a 422 with loc/msg/type only; the request (client secret included) is not echoed."""
    # Arrange: StopBeforeStartRequest requires start_token; a missing field's `input` used to be the whole body.
    body = {**CREDS, "password": "pw-" + SECRET}
    # Act
    r = client.post("/api/dlp-packs/jobs/stop-before-start", json=body)
    # Assert
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail and all(set(e) == {"type", "loc", "msg"} for e in detail)
    assert detail[0]["loc"] == ["body", "start_token"] and detail[0]["type"] == "missing"
    assert SECRET not in r.text


def test_a_422_for_a_huge_value_stays_small(client):
    """ASVS V7.4.1 · A04:2021 · CWE-405: a 100 kB value of the wrong type is refused without being reflected."""
    # Act
    r = client.post("/api/tenant/check", json={"pack_ids": HUGE, "cloud": [HUGE]})
    # Assert
    assert r.status_code == 422 and len(r.content) < 2000


@pytest.mark.parametrize("field,value", [("cloud", HUGE), ("cloud", "x" * 61), ("auth_method", HUGE)], ids=["cloud-huge", "cloud-61", "method-huge"])
def test_an_error_quoting_a_bad_value_is_bounded(client, field, value):
    """ASVS V7.4.1 · A04:2021 · CWE-405 · WSTG-ERRH-01: a refusal that names the bad value quotes at most a short prefix of it."""
    # Act
    r = client.post("/api/diagnose/zcc", json={**CREDS, **SCOPE, field: value})
    # Assert
    assert r.status_code == 400
    assert len(r.json()["detail"]) <= srv._MAX_DETAIL_CHARS + 1 and value not in r.text


def test_long_http_exception_details_are_cut_but_keep_their_headers():
    """ASVS V7.4.1 · A04:2021 · CWE-405: the HTTPException handler bounds every string of a detail and keeps the exception's headers."""
    import asyncio
    from starlette.exceptions import HTTPException as StarletteHTTPException
    # Arrange
    exc = StarletteHTTPException(status_code=429, detail={"why": "x" * 5000, "items": ["y" * 5000]}, headers={"Retry-After": "1"})
    # Act
    resp = asyncio.run(srv._bounded_http_exception_handler(None, exc))
    # Assert
    body = json.loads(resp.body)
    assert resp.status_code == 429 and resp.headers["retry-after"] == "1"
    assert len(body["detail"]["why"]) == srv._MAX_DETAIL_CHARS + 1 and len(body["detail"]["items"][0]) == srv._MAX_DETAIL_CHARS + 1


@pytest.mark.parametrize("value", ["-1", "not-a-method", HUGE, UNICODE], ids=["negative", "word", "huge", "unicode"])
def test_an_unknown_sign_in_method_is_a_400(client, value):
    """ASVS V5.1.3 · A04:2021 · CWE-755 · WSTG-ERRH-01: an auth_method that is neither oneapi nor legacy is refused with 400 (it was a ValueError, 500, on 46 endpoints)."""
    # Act
    r = client.post("/api/diagnose/zcc", json={**CREDS, **SCOPE, "auth_method": value})
    # Assert
    assert r.status_code == 400 and "Unknown sign-in method" in r.json()["detail"]


def test_a_deeply_nested_body_is_a_400_on_a_model_route(client):
    """ASVS V5.1.4 · A04:2021 · CWE-674 · WSTG-ERRH-01: JSON nested past the parser's depth is a 400; the audit layer no longer fails on it (it was a RecursionError, 500, on every POST)."""
    # Act
    r = client.post("/api/tenant/check", content=b"[" * 5000 + b"]" * 5000, headers={"content-type": "application/json"})
    # Assert
    assert r.status_code == 400


def test_the_audit_layer_records_a_too_deep_body_by_its_size(monkeypatch):
    """ASVS V7.4.1 · A09:2021 · CWE-674: the audit middleware logs an unparseable body as its size and lets the request through."""
    import asyncio
    import audit
    # Arrange
    seen, records = {}, []
    monkeypatch.setattr(audit, "record", lambda *a, **k: records.append(k))

    async def inner(scope, receive, send):
        seen["body"] = (await receive())["body"]
        await send({"type": "http.response.start", "status": 400, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    body = b"[" * 5000 + b"]" * 5000
    msgs = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return msgs.pop(0) if msgs else {"type": "http.disconnect"}

    async def send(message):
        pass

    # Act
    asyncio.run(audit.AuditMiddleware(inner)({"type": "http", "method": "POST", "path": "/api/x", "client": ("127.0.0.1", 1)}, receive, send))
    # Assert
    assert seen["body"] == body and records and records[0]["body"] == f"<{len(body)} bytes>"


# The report endpoints that build from each row's text (xlsx and findings-csv skip a row they cannot use).
HAND_READ = ["/api/compliance", "/api/compliance/drilldown", "/api/compliance/report", "/api/benchmarks", "/api/benchmarks/export",
             "/api/report/docx"]


@pytest.mark.parametrize("path", HAND_READ)
@pytest.mark.parametrize("checks", [["x"], [1, None], [{"id": ["DLP-01"], "status": "FAIL"}], [{"id": "DLP-01", "status": 5}], "not-a-list"],
                         ids=["strings", "scalars", "id-list", "status-int", "not-a-list"])
def test_check_rows_of_the_wrong_shape_are_a_400(client, path, checks):
    """ASVS V5.1.4 · A03:2021 · CWE-1287 · WSTG-ERRH-01: the report endpoints refuse check rows that are not objects with text fields (they were AttributeError / KeyError 500s)."""
    # Act
    r = client.post(path, json={"checks": checks})
    # Assert
    assert r.status_code == 400, r.text[:200]


@pytest.mark.parametrize("path", ["/api/compliance", "/api/benchmarks", "/api/benchmarks/export", "/api/compliance/report", "/api/report/docx"])
def test_a_check_row_missing_fields_and_odd_metadata_still_builds(client, path):
    """ASVS V5.1.4 · A04:2021 · CWE-755: a row without label/detail and a metadata that is not an object are accepted (missing text is ""), never a 500."""
    # Act
    r = client.post(path, json={"checks": [{"id": "DLP-01", "status": "FAIL"}, {}], "metadata": "not-an-object"})
    # Assert
    assert r.status_code == 200, r.text[:200]


def test_a_word_report_accepts_control_characters_and_lone_surrogates(client):
    """ASVS V5.3.1 · A03:2021 · CWE-116: text XML cannot hold is dropped before the Word build (it was a ValueError, 500)."""
    # Arrange
    odd = "Acme\u0000\u0001\u000b\ud800 ‮\U0001F600"
    row = {"id": "DLP-01", "status": "FAIL", "section": odd, "label": odd, "detail": odd}
    # Act
    raw = json.dumps({"checks": [row], "metadata": {"org": odd}}).encode()   # \ud800 travels as its JSON escape
    r = client.post("/api/report/docx", content=raw, headers={"content-type": "application/json"})
    # Assert
    assert r.status_code == 200 and r.content[:2] == b"PK"


def test_the_xml_filter_keeps_tabs_newlines_and_unicode():
    """ASVS V5.3.1 · CWE-116: only the characters XML 1.0 forbids are removed."""
    # Act / Assert
    assert srv._xml_text({"k\u0000": ["a\u0000b\ud800c\t\n‮\U0001F600", 5]}) == {"k": ["abc\t\n‮\U0001F600", 5]}


@pytest.mark.parametrize("path", ["/api/migrate/analyze", "/api/migrate/plan", "/api/migrate/export"])
@pytest.mark.parametrize("rule", [{"id": 1, "name": 5}, {"id": 1, "state": [1]}, {"id": 1, "action": 5}], ids=["name", "state", "action"])
def test_migration_rules_with_non_text_fields_are_a_400(client, path, rule):
    """ASVS V5.1.4 · A03:2021 · CWE-1287: a rule whose name, state or action is not text is refused (it was an AttributeError, 500)."""
    # Act
    r = client.post(path, json={"rules": [rule, {"id": 2, "name": "b", "order": 2}]})
    # Assert
    assert r.status_code == 400 and "must be text" in r.json()["detail"]


@pytest.mark.parametrize("days", [2 ** 70, 10 ** 6, 181])
def test_an_audit_timeline_window_too_long_is_a_400(client, days):
    """ASVS V5.1.3 · A04:2021 · CWE-1284 · WSTG-ERRH-01: more days than ZIA keeps is refused before any date arithmetic (2**70 was an OverflowError, 500)."""
    # Act
    r = client.post("/api/audit-timeline/start", json={"days": days, "include_zia": False})
    # Assert
    assert r.status_code == 400 and "longer than" in r.json()["detail"]


@pytest.mark.parametrize("kw", [{"end": "9999-12-31"}, {"end": "0001-01-01"}])
def test_an_audit_timeline_date_at_the_calendar_edge_is_a_value_error(kw):
    """ASVS V5.1.3 · CWE-1284: a date at year 1 or 9999 is refused in words, not an OverflowError (time injected)."""
    import audit_timeline as at
    # Act / Assert
    with pytest.raises(ValueError, match="edge of the calendar"):
        at.window(**kw, now=1_790_000_000.0)


def test_an_audit_timeline_boundary_window_is_accepted():
    """ASVS V5.1.3 · CWE-1284: exactly MAX_DAYS is still a valid window (boundary, time injected)."""
    import audit_timeline as at
    # Act
    win = at.window(days=at.MAX_DAYS, now=1_790_000_000.0)
    # Assert
    assert win["days"] == at.MAX_DAYS


@pytest.mark.parametrize("scope", ["‮中", "a\r\nX-Injected: 1", "Q" * 5000])
def test_the_checks_export_filename_never_carries_the_scope_text(client, scope):
    """ASVS V5.1.3 · A03:2021 · CWE-113 · WSTG-INPV-15: an unknown scope exports every check under an "all" file name; the caller's text never reaches the header (unicode was a 500)."""
    # Act
    r = client.get("/api/checks/export", params={"scope": scope})
    # Assert
    assert r.status_code == 200 and "zscaler_checks_all_" in r.headers["content-disposition"]
    assert "x-injected" not in {k.lower() for k in r.headers}


def test_the_checks_export_keeps_a_known_scope_in_its_filename(client):
    """ASVS V5.1.3 · CWE-113: a scope the catalogue knows still names the file (no regression)."""
    # Act
    r = client.get("/api/checks/export", params={"scope": "dlp"})
    # Assert
    assert r.status_code == 200 and "zscaler_checks_dlp_" in r.headers["content-disposition"]


@pytest.mark.parametrize("path", ["/api/report/bypass/{rid}", "/api/report/bypass/export/{rid}"])
def test_a_bypass_report_endpoint_refuses_another_kind_of_report_id(client, path):
    """ASVS V5.1.4 · A04:2021 · CWE-843: a compliance report id is not a bypass report: 404 (the export was a KeyError, 500)."""
    # Arrange
    rid = client.post("/api/compliance/report", json={"checks": [{"id": "DLP-01", "status": "FAIL"}]}).json()["report_id"]
    # Act
    r = client.get(path.format(rid=rid))
    # Assert
    assert r.status_code == 404
