"""dlp_api_server.py, cloud-6 QA: bad input on every route, the order of the
gates (UI token / origin / host, then scope, then the write gates, all before
sign-in), the security headers on every answer (the error answers included),
background job ownership, download names, the credential fallback chain
(body, profile, environment, tenant_config.json) and leftovers a merge can
leave (undefined names, duplicate routes or functions).

Nothing here reaches a tenant: the sign-in factories are replaced by fakes
that refuse and record the attempt, sockets are blocked where a handler runs,
and the only tenant that answers is the made-up sample tenant (offline_tenant,
no network code)."""
from __future__ import annotations

import ast
import inspect
import json
import os
import re
import socket
import symtable
import threading
import time
import types
import builtins

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import dlp_api_server as srv
import offline_tenant as ot
import pack_jobs
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_PATH = os.path.join(ROOT, "dlp_api_server.py")
SECRET = "c6-api-secret-Zq81-never-echo"
LIVE = {"cloud": "zscalertwo", "vanity_domain": "acme", "client_id": "acmeclient0001", "client_secret": SECRET,
        "customer_id": "7210000000000"}
ALL_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"]
CHANNELS = {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it",
                                   "ssl_inspection", "cloud_app_control")}
SCOPE = {"scopes": ALL_SCOPES, "channels": CHANNELS, "from_page": True}
SKIP = re.compile(r"/api/(app/update|app/restart|update|restart|shutdown)")
ROUTES = sorted((r for r in srv.app.routes if isinstance(r, APIRoute) and not SKIP.search(r.path)),
                key=lambda r: (r.path, sorted(r.methods)))


def _method(route: APIRoute) -> str:
    return sorted(route.methods)[0]


def _path(route: APIRoute, value: str = "c6-id") -> str:
    return re.sub(r"\{(\w+)(:\w+)?\}", value, route.path)


def _ids(routes):
    return [f"{_method(r)} {r.path}" for r in routes]


BODY_ROUTES = [r for r in ROUTES if r.body_field is not None or "_json_object(request)" in inspect.getsource(r.endpoint)]


class _Refused(Exception):
    pass


@pytest.fixture
def signins(monkeypatch, tmp_path):
    """Every way to sign in to a tenant replaced by a fake that refuses and
    records the attempt; the app's stores in tmp_path; no restart or update."""
    import app_update
    import tenant_auth
    seen = []

    def refuse(*a, **k):
        seen.append("sdk")
        raise HTTPException(status_code=401, detail="Authentication refused by the c6 test.")

    class Raw:
        def auth(self):
            seen.append("raw")
            return False, "refused by the c6 test"

        def close(self):
            pass

    monkeypatch.setattr(srv, "_build_sdk_client", refuse)
    monkeypatch.setattr(srv, "_raw_client", lambda creds: Raw())
    monkeypatch.setattr(tenant_auth, "build_legacy_sdk_client", refuse)
    monkeypatch.setattr(app_update, "schedule_restart", lambda *a, **k: pytest.fail("the test restarted the server"))
    monkeypatch.setattr(app_update, "update", lambda *a, **k: pytest.fail("the test ran an update"))
    for var, name in (("DLP_CHECK_PROFILES", "profiles.json"), ("DLP_CHECK_WORKSPACE_NOTES", "notes.json"),
                      ("DLP_CHECK_BEACON_STATE", "beacon.json"), ("DLP_CHECK_USER_PACKS", "user_packs"),
                      ("DLP_CHECK_POSTURE_SETTINGS", "posture_settings.json"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json"),
                      ("DLPCHECK_CHANGE_QUEUE_FILE", "change_requests.json"), ("DLP_CHECK_AUDIT", "audit.log")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    return seen


@pytest.fixture
def client(signins):
    return TestClient(srv.app, raise_server_exceptions=False)


@pytest.fixture
def sample(tmp_path, monkeypatch):
    """The app on the sample tenant (no network: any socket use fails)."""
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")

    def no_network(*a, **k):
        raise AssertionError("the network was used")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    c = TestClient(srv.app, base_url="http://127.0.0.1", raise_server_exceptions=False)
    assert c.post("/api/offline/sample", json={}).status_code == 200
    return c


def _error_contract(r, what: str) -> None:
    """A 4xx in the app's shape: JSON with a detail, small, no traceback, no secret."""
    assert 400 <= r.status_code < 500, f"{what}: {r.status_code} {r.text[:200]}"
    assert SECRET not in r.text and "Traceback" not in r.text and 'File "/' not in r.text
    assert len(r.content) < 20_000
    assert "detail" in r.json()


# ── 1. Bad input on every route ─────────────────────────────────────────

@pytest.mark.parametrize("route", BODY_ROUTES, ids=_ids(BODY_ROUTES))
def test_a_body_with_nan_or_infinity_is_refused_on_every_route(client, signins, route):
    """ASVS V5.1.4 · A03:2021 · CWE-20 · WSTG-INPV-01: a body with NaN, Infinity or -Infinity (not JSON, RFC 8259) is a 4xx before the handler runs, never a 500 or a sign-in."""
    for raw in (b'{"x": NaN}', b'{"x": [Infinity]}', b'{"x": {"y": -Infinity}}'):
        # Act
        r = client.request(_method(route), _path(route), content=raw, headers={"content-type": "application/json"})
        # Assert
        _error_contract(r, f"{raw!r}")
    assert signins == []


def test_nan_in_a_har_host_count_was_a_500(client):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: a HAR host whose request count is NaN is refused (422 json_invalid); int(NaN) in the batch was a ValueError, 500."""
    # Arrange
    raw = b'{"har_hosts": [{"host": "a.example.com", "requests": NaN, "bytes_sent": Infinity}]}'
    # Act
    r = client.post("/api/path-analyzer/batch/start", content=raw, headers={"content-type": "application/json"})
    # Assert
    assert r.status_code == 422 and r.json()["detail"][0]["type"] == "json_invalid"


def test_nan_in_a_hand_read_body_is_a_400(client):
    """ASVS V5.1.4 · A03:2021 · CWE-20 · WSTG-INPV-01: a handler that reads its own body (_json_object) answers NaN with its plain 400."""
    # Act
    r = client.post("/api/compliance", content=b'{"checks": [{"id": "DLP-01", "status": "FAIL", "n": NaN}]}',
                    headers={"content-type": "application/json"})
    # Assert
    assert r.status_code == 400 and "Invalid JSON" in r.json()["detail"]


def test_plain_finite_numbers_are_still_accepted(client):
    """ASVS V5.1.4 · CWE-20: the strict decoder still takes ordinary numbers, exponents and negatives (boundary)."""
    # Act
    r = client.post("/api/compliance", content=b'{"checks": [{"id": "DLP-01", "status": "FAIL", "n": -1.5e300}]}',
                    headers={"content-type": "application/json"})
    # Assert
    assert r.status_code == 200


def test_the_strict_decoder_rejects_each_non_json_constant():
    """ASVS V5.1.4 · CWE-20: each of NaN, Infinity and -Infinity is a JSONDecodeError (what FastAPI turns into a 422)."""
    for name in ("NaN", "Infinity", "-Infinity"):
        # Act / Assert
        with pytest.raises(json.JSONDecodeError):
            srv._refuse_json_constant(name)


@pytest.mark.parametrize("stats", [{"a": None}, {"seen": "x", "real": None}, {"seen": [1]}, {"seen": True, "open": -5}],
                         ids=["unknown-key", "text-counter", "list-counter", "bool-and-negative"])
def test_a_live_feed_tally_of_the_wrong_shape_is_not_a_500(sample, stats):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-01: the running tally the page sends back is untrusted; a missing or non-numeric counter was a KeyError / TypeError (500)."""
    # Act
    r = sample.post("/api/live-feed", json={**SCOPE, "stats": stats})
    # Assert
    assert r.status_code == 200, r.text[:200]
    assert set(r.json()["stats"]) >= {"seen", "real", "not_real", "fp_tp_ratio"}


def test_the_live_feed_tally_keeps_counters_and_drops_everything_else():
    """ASVS V5.1.3 · CWE-20 · CWE-400: known counters are kept as whole numbers within 0..10**12; extra keys are not echoed back."""
    # Act
    t = srv._live_tally({"seen": 3, "real": 10 ** 20, "open": -2, "not_real": 1.5, "x" * 50: "echo me"})
    # Assert
    assert t == {"seen": 3, "enforced": 0, "monitor": 0, "unknown_action": 0, "open": 0, "real": 10 ** 12, "not_real": 0}
    assert srv._live_tally({}) is None and srv._live_tally(None) is None and srv._live_tally([1]) is None


@pytest.mark.parametrize("route", [r for r in BODY_ROUTES if r.body_field is not None][:400],
                         ids=_ids([r for r in BODY_ROUTES if r.body_field is not None]))
def test_unexpected_fields_never_reach_a_sign_in_or_a_500(client, signins, route):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: an unknown field (deeply nested, huge key) with nothing else is ignored or refused, never a 500, and never signs in."""
    # Act
    r = client.request(_method(route), _path(route), json={"unexpected": {"a": [{"b": [None]}]}, "k" * 300: 1})
    # Assert
    assert r.status_code < 500, r.text[:200]
    assert SECRET not in r.text and "Traceback" not in r.text


def test_a_server_fault_names_no_server_folder(client, monkeypatch):
    """ASVS V7.4.1 · A05:2021 · CWE-209 · WSTG-ERRH-01: a 5xx that quotes an OSError names the app, Python, temp and home folders by role, never by path."""
    # Arrange
    import report_docx
    leak = os.path.join(srv._APP_DIR, "templates", "x.docx")

    def fail(*a, **k):
        raise FileNotFoundError(2, "No such file", leak)
    monkeypatch.setattr(report_docx, "generate_report", fail)
    # Act
    r = client.post("/api/report/docx", json={"checks": [{"id": "DLP-01", "status": "FAIL"}]})
    # Assert
    assert r.status_code == 500 and srv._APP_DIR not in r.text and "<app folder>" in r.json()["detail"]
    assert _hardened(r)


def test_path_scrubbing_covers_each_folder_and_only_server_faults():
    """ASVS V7.4.1 · CWE-209: each server folder (either slash) is replaced, nested details included; a 4xx detail is left as written."""
    # Arrange
    import sys
    import tempfile
    detail = {"a": [f"{srv._APP_DIR}/x", f"{sys.prefix}/lib", f"{tempfile.gettempdir()}/t", os.path.expanduser("~") + "/f"]}
    # Act
    out = srv._scrub_paths(detail)
    # Assert
    assert out == {"a": ["<app folder>/x", "<python>/lib", "<temp>/t", "~/f"]}
    assert srv._scrub_paths(5) == 5


def test_a_har_batch_over_the_cap_is_refused_before_sign_in(client, signins):
    """ASVS V5.1.3 · A04:2021 · CWE-770 · WSTG-BUSL-05: one host more than path_analyzer.BATCH_MAX is a 400 naming the cap (boundary); nothing is signed in to."""
    import path_analyzer
    # Act
    over = client.post("/api/path-analyzer/batch/start", json={**LIVE, **SCOPE, "har_hosts": ["a.example.com"] * (path_analyzer.BATCH_MAX + 1)})
    # Assert
    assert over.status_code == 400 and str(path_analyzer.BATCH_MAX) in over.json()["detail"] and signins == []


def test_a_har_batch_at_the_cap_reaches_the_scope_check(client, signins):
    """ASVS V5.1.3 · CWE-770: exactly BATCH_MAX hosts pass the cap (boundary); with nothing in scope the request is then refused before sign-in."""
    import path_analyzer
    # Act
    r = client.post("/api/path-analyzer/batch/start", json={**LIVE, "scopes": [], "channels": {}, "from_page": True,
                                                            "har_hosts": ["a.example.com"] * path_analyzer.BATCH_MAX})
    # Assert
    assert r.status_code == 400 and str(path_analyzer.BATCH_MAX) not in r.json()["detail"] and signins == []


def test_har_entries_that_name_no_host_are_a_plain_400(client, signins):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: entries whose host is missing, a list, an object, a number, a URL or text are skipped; none left is a 400, never a 500."""
    # Act
    r = client.post("/api/path-analyzer/batch/start", json={**LIVE, **SCOPE, "har_hosts": [
        None, 5, "", "not a host!", "https://a.example/path", {"host": ["x"]}, {"host": {"a": 1}}, {"nohost": 1}]})
    # Assert
    assert r.status_code == 400 and "No hostname" in r.json()["detail"] and signins == []


@pytest.mark.parametrize("odd", [{"methods": {"a": 1}, "schemes": 5}, {"methods": 7, "schemes": True}, {"methods": "GET", "schemes": "https"}],
                         ids=["object-and-number", "number-and-bool", "strings"])
def test_har_methods_and_schemes_that_are_not_lists_are_dropped(odd):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: methods / schemes that are not lists are read as none (a number was a TypeError, 500; "GET" became G, E, T)."""
    # Arrange
    req = srv.PathBatchRequest(har_hosts=[{"host": "a.example.com", **odd}])
    # Act
    _hosts, stats, _skipped = srv._batch_hosts(req)
    # Assert
    assert stats["a.example.com"]["methods"] == [] and stats["a.example.com"]["schemes"] == []


@pytest.mark.parametrize("path,key", [("/api/migrate/optimize", "rules"), ("/api/migrate/upload", "rules"), ("/api/migrate/post", "proposed_rules")])
@pytest.mark.parametrize("field,value", [("action", 5), ("action", ["BLOCK"]), ("state", {"a": 1}), ("name", True)],
                         ids=["action-number", "action-list", "state-object", "name-bool"])
def test_a_migration_rule_whose_text_field_is_not_text_is_a_400(client, signins, path, key, field, value):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: a rule's name, state or action that is not text is a 400 naming the field, before any sign-in (it was an AttributeError, 500)."""
    # Act
    r = client.post(path, json={**LIVE, **SCOPE, key: [{"id": 1, "name": "ok", field: value}]})
    # Assert
    assert r.status_code == 400 and f"{key}[0].{field}" in r.json()["detail"] and signins == []


@pytest.mark.parametrize("exceptions", [{"audit_only_actions": [5]}, {"audit_only_actions": "ALLOW"}, {"pinned": [1]},
                                        {"pinned": {"rule_id": 1, "position": "x"}}, {"skip_rule_ids": 5}, {"skip_rule_ids": [{"a": 1}]}],
                         ids=["action-number", "actions-text", "pinned-list", "position-text", "skip-number", "skip-object"])
def test_evaluate_all_exceptions_of_the_wrong_shape_are_a_400(client, exceptions):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: the optimiser's exceptions are checked (they were AttributeError / ValueError / TypeError 500s)."""
    # Act
    r = client.post("/api/migrate/optimize", json={"rules": [{"id": 1, "name": "r", "action": "ALLOW"}], "exceptions": exceptions})
    # Assert
    assert r.status_code == 400, r.text[:200]


def test_good_evaluate_all_exceptions_are_still_honoured(client):
    """ASVS V5.1.4 · CWE-20: well-formed exceptions (audit-only actions, a pin, a skip list) still optimise (regression)."""
    # Act
    r = client.post("/api/migrate/optimize", json={"rules": [{"id": 1, "name": "a", "action": "ALLOW"}, {"id": 2, "name": "b", "action": "BLOCK"}],
                                                   "exceptions": {"audit_only_actions": ["allow"], "pinned": {"rule_id": 2, "position": 1},
                                                                  "skip_rule_ids": [1]}})
    # Assert
    assert r.status_code == 200, r.text[:200]


@pytest.mark.parametrize("path", ["/api/posture/analyze", "/api/posture/project"])
@pytest.mark.parametrize("value", [[1], {"a": 1}, 5], ids=["list", "object", "number"])
def test_posture_check_rows_with_odd_sections_are_not_a_500(client, path, value):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: a check row whose section or channel is not text is read as text (a list or object was an unhashable TypeError, 500)."""
    # Act
    r = client.post(path, json={"checks": [{"id": "DLP-01", "status": "FAIL", "sec": value, "section": value, "channel": value}]})
    # Assert
    assert r.status_code == 200, r.text[:200]


@pytest.mark.parametrize("body", [{"rules": [{"id": 1, "name": "a"}], "order": [[1]]},
                                  {"rules": [{"id": 1, "name": "a"}], "order": [{"a": 1}]},
                                  {"rules": [{"id": 1, "name": ["a"]}], "order": [1]}],
                         ids=["list-token", "object-token", "list-name"])
def test_a_reorder_token_or_rule_name_that_cannot_be_a_key_is_a_400(client, body):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: an order token that is not an id or a name, or a rule named by a list, is a 400 (unhashable TypeError, 500)."""
    # Act
    r = client.post("/api/migrate/reorder", json=body)
    # Assert
    assert r.status_code == 400, r.text[:200]


def test_reorder_places_named_rules_first_and_keeps_the_rest():
    """ASVS V5.1.3 · CWE-20: oracle: rules named in `order` (by id or name, once each) come first in that order; unknown tokens are listed; the rest keep their order."""
    import asyncio
    # Arrange
    rules = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "c"}]
    # Act
    out = asyncio.run(srv.migrate_reorder(srv.ReorderRequest(rules=rules, order=["c", 1, 1, "zz"])))
    # Assert
    assert [r["id"] for r in out["proposed_rules"]] == [3, 1, 2] and [r["_proposed_order"] for r in out["proposed_rules"]] == [1, 2, 3]
    assert out["count"] == 3 and out["missing_tokens"] == [1, "zz"]


CATALOG = {None: 348, "dlp": 206, "zia": 37, "zpa": 15, "zcc": 26, "genai": 20, "automation": 19, "zdx": 8, "zidentity": 5, "rbac": 12}


def test_the_check_catalog_scopes_add_up_to_the_registries(client):
    """ASVS V1.14.1 · CWE-1059: oracle: each scope of /api/checks lists exactly its registry, and no scope lists everything."""
    # Arrange
    regs = {"dlp": srv.REG, "genai": srv.GENAI_REG, "automation": srv.AUTOMATION_REG, "zdx": srv.ZDX_REG, "zidentity": srv.ZID_REG, "rbac": srv.RBAC_REG}
    for scope in CATALOG:
        # Act
        got = client.get("/api/checks", params={"scope": scope} if scope else {}).json()
        # Assert
        if scope in regs:
            assert {c["id"] for c in got} == {c[0] for c in regs[scope]}
        if scope in ("zia", "zpa", "zcc"):
            assert {c["id"] for c in got} == {c[0] for c in srv.PLATFORM_REG if c[1].startswith(scope.upper())}
    everything = client.get("/api/checks").json()
    assert len(everything) == sum(len(r) for r in (srv.REG, srv.PLATFORM_REG, srv.GENAI_REG, srv.AUTOMATION_REG, srv.ZDX_REG, srv.ZID_REG, srv.RBAC_REG))


@pytest.mark.parametrize("scope", sorted(s for s in CATALOG if s))
@pytest.mark.parametrize("fmt", ["csv", "json", "markdown"])
def test_the_check_catalog_exports_in_every_format_and_scope(client, scope, fmt):
    """ASVS V5.3.1 · A03:2021 · CWE-1236 · WSTG-INPV-01: every scope exports as CSV, JSON and Markdown with an attachment name that is a plain token."""
    # Act
    r = client.get("/api/checks/export", params={"format": fmt, "scope": scope})
    # Assert
    assert r.status_code == 200 and r.content
    cd = r.headers.get("content-disposition", "")
    assert not cd or re.fullmatch(r'attachment; filename="?[A-Za-z0-9._-]+"?', cd), cd


@pytest.mark.parametrize("detail,legacy,cause", [
    ("HTTP 429 Too Many Requests", False, "rate"), ("Resource Access Blocked", False, "block"),
    ("401 Unauthorized", True, "password"), ("403 Forbidden", True, "role"),
    ("ProxyError: tunnel connection failed", True, "classic ZIA API"), ("invalid_client", False, "client"),
    ("SSL: CERTIFICATE_VERIFY_FAILED", False, "TLS"), ("Max retries exceeded: name resolution", False, "reach"),
    ("bad vanity domain", False, "vanity"), ("403 Forbidden", False, "403"), ("something odd", False, "")])
def test_connection_errors_are_explained_by_their_cause(detail, legacy, cause):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: oracle: each sign-in failure maps to a plain cause and fix for the sign-in in use; the raw text is at most 300 characters."""
    # Act
    out = srv._explain_connection_error(detail + " " + "x" * 400, "legacy" if legacy else "oneapi")
    # Assert
    assert out["cause"] and out["fix"] and len(out["raw"]) <= 300
    assert cause.lower() in (out["cause"] + " " + out["fix"]).lower()


def test_local_settings_fill_only_what_the_environment_lacks(monkeypatch, tmp_path):
    """ASVS V14.1.3 · CWE-15 · SSDF PO.5.1: local_settings.env fills unset KEY=VALUE pairs (quotes stripped, comments and junk skipped); a value already set wins."""
    # Arrange
    (tmp_path / "local_settings.env").write_text("# note\nC6_A=\"one\"\nC6_B='two'\njunk line\n=nokey\nC6_SET=file\n", encoding="utf-8")
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    monkeypatch.setenv("C6_SET", "env")
    for k in ("C6_A", "C6_B"):
        monkeypatch.delenv(k, raising=False)
    # Act
    srv._load_local_settings()
    # Assert
    assert (os.environ["C6_A"], os.environ["C6_B"], os.environ["C6_SET"]) == ("one", "two", "env")
    for k in ("C6_A", "C6_B"):
        monkeypatch.delenv(k)


def test_an_unreadable_local_settings_file_is_ignored(monkeypatch, tmp_path):
    """ASVS V14.1.3 · CWE-755: a local_settings.env that cannot be read (a folder by that name) is skipped, never a crash at start."""
    # Arrange
    (tmp_path / "local_settings.env").mkdir()
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    # Act / Assert
    srv._load_local_settings()


def test_har_host_counts_are_bounded_and_odd_fields_dropped():
    """ASVS V5.1.3 · CWE-20 · CWE-400: counts are whole numbers in 0..10**12, methods and schemes keep only known short values, duplicates and URLs are skipped."""
    # Arrange
    req = srv.PathBatchRequest(har_hosts=[{"host": "A.example.com", "requests": 10 ** 30, "uploads": -5, "bytes_sent": True,
                                           "methods": ["GET", "x" * 50, 5, None, "post"], "schemes": ["https", "ftp", None]},
                                          "a.example.com", "https://b.example/x"])
    # Act
    hosts, stats, skipped = srv._batch_hosts(req)
    # Assert
    assert hosts == ["a.example.com"] and skipped == ["https://b.example/x"]
    assert stats["a.example.com"] == {"requests": 10 ** 12, "uploads": 0, "bytes_sent": 0, "methods": ["GET"], "schemes": ["https"]}


# ── 2. Rule order: token / origin / host, then scope, then write gates ──

API_ROUTES = [r for r in ROUTES if r.path.startswith("/api/") and r.path not in security._UI_AUTH_EXEMPT_PATHS
              and not any(r.path.startswith(p) for p in security._UI_AUTH_EXEMPT_PREFIXES)]


@pytest.fixture
def gated(signins, monkeypatch):
    """The UI token gate on, with a known token."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_UI_TOKEN", "c6-ui-token-0123456789abcdef", raising=False)
    monkeypatch.setattr(security, "ui_token_ok", lambda t: t == "c6-ui-token-0123456789abcdef")
    return TestClient(srv.app, raise_server_exceptions=False)


@pytest.mark.parametrize("route", API_ROUTES, ids=_ids(API_ROUTES))
def test_without_the_ui_token_every_api_route_is_a_401_before_anything_runs(gated, signins, route):
    """ASVS V4.1.1 · A01:2021 · CWE-306 · WSTG-ATHN-04: with the UI token gate on, a call without the token is a 401 with the security headers, and nothing is signed in to."""
    # Act
    r = gated.request(_method(route), _path(route), json={**LIVE, **SCOPE})
    # Assert
    assert r.status_code == 401, r.text[:200]
    assert signins == [] and SECRET not in r.text
    assert r.headers.get("x-content-type-options") == "nosniff"


POST_ROUTES = [r for r in ROUTES if _method(r) == "POST"]


@pytest.mark.parametrize("route", POST_ROUTES, ids=_ids(POST_ROUTES))
def test_a_cross_site_post_is_refused_before_anything_runs(client, signins, route):
    """ASVS V4.2.2 · A01:2021 · CWE-352 · WSTG-SESS-05: a POST whose Origin is another site is a 403 on every route, before scope or sign-in."""
    # Act
    r = client.post(_path(route), json={**LIVE, **SCOPE}, headers={"Origin": "https://evil.example"})
    # Assert
    assert r.status_code == 403, r.text[:200]
    assert signins == []


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.evil.example", "localhost.evil.example"])
def test_a_rebound_host_name_is_refused_with_the_token_gate_off(signins, host):
    """ASVS V14.5.3 · A01:2021 · CWE-350 · WSTG-CONF-07: with the UI token off, a Host that is not a loopback name (DNS rebinding) is a 403 before any handler."""
    # Arrange
    c = TestClient(srv.app, base_url=f"http://{host}", raise_server_exceptions=False)
    # Act
    r = c.post("/api/diagnose/zcc", json={**LIVE, **SCOPE})
    # Assert
    assert r.status_code == 403 and signins == []


def _exempt():
    import test_scope_rule_routes as t
    return set(t.EXEMPT)


# The scope table's documented exemptions (an operator-picked pack or check, the sign-in test) may sign in.
SCOPED_POSTS = [r for r in POST_ROUTES if f"POST {r.path}" not in _exempt()]


@pytest.mark.parametrize("route", SCOPED_POSTS, ids=_ids(SCOPED_POSTS))
def test_nothing_in_scope_never_signs_in(client, signins, route):
    """ASVS V4.1.3 · A01:2021 · CWE-863 · WSTG-ATHZ-02: with complete credentials and nothing ticked on the Scope page, no route signs in (only the documented exemptions of the scope table may)."""
    # Act
    r = client.post(_path(route), json={**LIVE, "scopes": [], "channels": {}, "from_page": True})
    # Assert
    assert signins == [], f"signed in with nothing in scope: {r.status_code} {r.text[:200]}"
    assert r.status_code < 500


WRITE_ROUTES = [r for r in POST_ROUTES if re.search(r"_require_tenant_write|require_writer\(\)", inspect.getsource(r.endpoint))]
WRITE_BODY = {**LIVE, **SCOPE, "dry_run": False, "preview": False, "confirm": True, "assessor": "Jane Doe", "plan_hash": "f" * 64,
              "pack_ids": ["cjis_baseline"], "rules": [{"channel": "web", "id": 1}], "deployment_id": "dep-1", "check_id": "DLP-01"}


@pytest.mark.parametrize("gate", ["write mode off", "no confirmation", "no assessor"])
@pytest.mark.parametrize("route", WRITE_ROUTES, ids=_ids(WRITE_ROUTES))
def test_a_write_with_a_gate_missing_never_signs_in(client, signins, monkeypatch, route, gate):
    """ASVS V1.4.1 · ASVS V4.1.5 · A04:2021 · CWE-841 · WSTG-BUSL-06: every tenant write checks write mode, the confirmation and the assessor before it signs in."""
    # Arrange
    body = dict(WRITE_BODY)
    if gate != "write mode off":
        monkeypatch.setenv("ENABLE_WRITE_ACTIONS", "YES_I_UNDERSTAND")
    if gate == "no confirmation":
        body.update(confirm=False, confirm_text="", confirmation="")
    if gate == "no assessor":
        body["assessor"] = ""
    # Act
    r = client.post(_path(route), json=body)
    # Assert
    assert signins == [], f"{gate}: signed in: {r.status_code} {r.text[:200]}"
    assert 400 <= r.status_code < 500


def test_the_write_route_table_is_not_empty():
    """ASVS V1.4.1 · SSDF PW.8.2: the write-gate walk found the write routes (a rename would otherwise empty it silently)."""
    # Assert
    assert len(WRITE_ROUTES) >= 15


# ── 3. Security headers on every answer, errors included ───────────────

def _hardened(r) -> bool:
    h = {k.lower(): v for k, v in r.headers.items()}
    return (h.get("x-content-type-options") == "nosniff" and h.get("x-frame-options") == "DENY"
            and "default-src" in h.get("content-security-policy", ""))


GET_PAGES = [r for r in ROUTES if _method(r) == "GET" and not r.dependant.path_params]


@pytest.mark.parametrize("route", GET_PAGES, ids=_ids(GET_PAGES))
def test_every_page_and_json_answer_has_csp_nosniff_and_frame_denial(client, route):
    """ASVS V14.4.3 · ASVS V14.4.4 · ASVS V14.4.7 · A05:2021 · CWE-1021 · WSTG-CONF-12: every HTML page and JSON answer carries CSP, nosniff and X-Frame-Options DENY."""
    # Act
    r = client.get(route.path)
    # Assert
    assert _hardened(r), dict(r.headers)


def test_an_unhandled_error_500_carries_the_security_headers(client, monkeypatch):
    """ASVS V14.4.3 · ASVS V7.4.1 · A05:2021 · CWE-693 · WSTG-ERRH-01: a 500 (answered outside every middleware) has CSP, nosniff and frame denial, and no traceback."""
    # Arrange
    import guidance

    def boom():
        raise RuntimeError("c6 boom")
    monkeypatch.setattr(guidance, "source_health", boom)
    # Act
    r = client.get("/api/digests")
    # Assert
    assert r.status_code == 500 and _hardened(r)
    assert r.headers.get("cache-control") == "no-store" and "Traceback" not in r.text and "c6 boom" not in r.text


def test_a_rate_limited_429_carries_the_security_headers(monkeypatch):
    """ASVS V14.4.3 · ASVS V11.1.4 · A05:2021 · CWE-693 · WSTG-CONF-12: the rate limiter's 429 (outside the UI token layer) has the security headers; the clock is fixed so the 61st call is the first refused."""
    # Arrange
    fixed = types.SimpleNamespace(**{k: getattr(time, k) for k in dir(time) if not k.startswith("_")})
    fixed.time = lambda: 1_000_000.0
    monkeypatch.setattr(security, "time", fixed)
    c = TestClient(srv.app, client=("10.66.0.61", 50000), raise_server_exceptions=False)
    # Act
    codes = [c.get("/api/c6-no-such-route").status_code for _ in range(61)]
    r = c.get("/api/c6-no-such-route")
    # Assert
    assert codes[:60] == [404] * 60 and codes[60] == 429
    assert r.status_code == 429 and _hardened(r)


def test_a_cors_preflight_carries_the_security_headers(client):
    """ASVS V14.4.3 · ASVS V14.5.3 · A05:2021 · CWE-693 · WSTG-CLNT-07: a CORS preflight answer has the security headers and allows no foreign origin."""
    # Act
    r = client.options("/api/compliance", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    # Assert
    assert _hardened(r) and r.headers.get("access-control-allow-origin") != "https://evil.example"


def test_the_security_header_layer_wraps_everything_but_the_body_cap():
    """ASVS V14.4.3 · A05:2021 · CWE-693: SecurityHeadersMiddleware is just inside the body cap (the outermost layer), so it wraps the rate limiter, CORS and the UI token gate."""
    # Arrange
    order = [m.cls for m in srv.app.user_middleware]
    # Assert
    assert order[0] is security.BodySizeLimitMiddleware and order[1] is security.SecurityHeadersMiddleware


# ── 4. Background jobs: ownership, races, caps ─────────────────────────

@pytest.fixture
def running_job(monkeypatch):
    """A running job registered without a thread (no sleep, no clock)."""
    job = pack_jobs.Job(id="c6job00000001", kind="deploy", label="c6", actor="alice@example.com")
    monkeypatch.setitem(pack_jobs._jobs, job.id, job)
    return job


def test_a_job_cannot_be_stopped_by_someone_else(client, monkeypatch, running_job):
    """ASVS V4.2.1 · A01:2021 · CWE-639 · WSTG-ATHZ-04: under SSO, a deploy started by one person is not stopped by another (403) and keeps running."""
    # Arrange
    monkeypatch.setattr(srv, "_actor", lambda request: "mallory@example.com")
    # Act
    r = client.post(f"/api/dlp-packs/jobs/{running_job.id}/cancel")
    # Assert
    assert r.status_code == 403 and not running_job.cancel.is_set()


def test_the_person_who_started_a_job_can_stop_it(client, monkeypatch, running_job):
    """ASVS V4.2.1 · CWE-639: the starter stops their own job."""
    # Arrange
    monkeypatch.setattr(srv, "_actor", lambda request: "alice@example.com")
    # Act
    r = client.post(f"/api/dlp-packs/jobs/{running_job.id}/cancel")
    # Assert
    assert r.status_code == 200 and r.json()["cancelled"] is True and running_job.cancel.is_set()


def test_a_job_with_no_known_starter_can_still_be_stopped(client, monkeypatch, running_job):
    """ASVS V4.2.1 · CWE-639: a job whose starter is unknown (an older start path) stays stoppable (no lock-out)."""
    # Arrange
    running_job.actor = None
    monkeypatch.setattr(srv, "_actor", lambda request: "bob@example.com")
    # Act
    r = client.post(f"/api/dlp-packs/jobs/{running_job.id}/cancel")
    # Assert
    assert r.status_code == 200 and running_job.cancel.is_set()


def test_without_sso_the_local_actor_stops_its_own_jobs(client, running_job):
    """ASVS V4.2.1 · CWE-639: without SSO every request is the same local actor, so the page still stops what it started (regression)."""
    # Arrange: the page started it (the UI token gate is off in the suite)
    running_job.actor = security.LOCAL_NO_TOKEN_ACTOR
    # Act
    r = client.post(f"/api/dlp-packs/jobs/{running_job.id}/cancel")
    # Assert
    assert r.status_code == 200


def test_unknown_or_hostile_job_ids_are_404(client):
    """ASVS V4.2.1 · A01:2021 · CWE-22 · WSTG-ATHZ-01: a job id that is unknown, a traversal or huge is a 404 on poll, cancel and download."""
    for jid in ("does-not-exist", "..%2F..%2Fetc", "Z" * 3000):
        # Act / Assert
        assert client.get(f"/api/dlp-packs/jobs/{jid}").status_code == 404
        assert client.post(f"/api/dlp-packs/jobs/{jid}/cancel").status_code == 404
        assert client.get(f"/api/dlp-packs/jobs/{jid}/download").status_code == 404


def test_a_job_poll_with_a_negative_or_huge_since_is_clean(client, running_job):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: `since` below 0 is read as 0; a huge one returns no lines; text is a 422."""
    # Arrange
    running_job.log("one")
    # Act
    neg = client.get(f"/api/dlp-packs/jobs/{running_job.id}", params={"since": -5})
    huge = client.get(f"/api/dlp-packs/jobs/{running_job.id}", params={"since": 10 ** 9})
    text = client.get(f"/api/dlp-packs/jobs/{running_job.id}", params={"since": "x"})
    # Assert
    assert neg.status_code == 200 and "one" in json.dumps(neg.json())
    assert huge.status_code == 200 and "one" not in json.dumps(huge.json().get("logs", []))
    assert text.status_code == 422


def test_stop_before_start_refuses_a_malformed_token(client):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a start token that is too short, too long or has odd characters is a 400."""
    for tok in ("short", "x" * 65, "abc def ghij", "../../etc/x"):
        # Act / Assert
        assert client.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": tok}).status_code == 400


def test_a_stop_racing_its_start_is_honoured(monkeypatch, client):
    """ASVS V1.11.3 · CWE-367 · WSTG-BUSL-07: Stop sent before the start answered: the job the start then creates begins cancelled and reads nothing."""
    # Arrange
    ran = []
    monkeypatch.setattr(pack_jobs, "_pending_stops", {})
    monkeypatch.setattr(pack_jobs, "_token_jobs", {})
    token = "c6-race-token-0001"
    # Act
    stop = client.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token})
    gate = threading.Event()

    def fn(log, cancel):
        ran.append(cancel.is_set())
        gate.set()
        return {"status": "stopped"}
    job = pack_jobs.start("path", fn, start_token=token)
    gate.wait(5)
    # Assert
    assert stop.json()["pending"] is True and job.cancel.is_set() and ran == [True]


def _as_person(monkeypatch):
    """Per-user identity as SSO provides it: the X-Test-Actor header names who asks."""
    monkeypatch.setattr(srv, "_actor", lambda request: request.headers.get("X-Test-Actor") or None)


def _held_job(token, actor):
    gate = threading.Event()

    def fn(log, cancel):
        gate.wait(5)
        return {"status": "done"}
    return pack_jobs.start("path", fn, actor=actor, start_token=token), gate


@pytest.mark.parametrize("who,status", [("mallory@example.com", 403), (None, 403), ("alice@example.com", 200)])
def test_stop_before_start_of_an_existing_job_is_only_for_its_starter(monkeypatch, client, who, status):
    """ASVS V4.2.1 · A01:2021 · CWE-639 · WSTG-ATHZ-04: with per-user identity, a start token held by someone else cannot stop alice's running job (403); alice can."""
    # Arrange
    _as_person(monkeypatch)
    monkeypatch.setattr(pack_jobs, "_pending_stops", {})
    monkeypatch.setattr(pack_jobs, "_token_jobs", {})
    token = "c6-owner-token-0001"
    job, gate = _held_job(token, "alice@example.com")
    # Act
    r = client.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}, headers={"X-Test-Actor": who} if who else {})
    stopped = job.cancel.is_set()
    gate.set()
    # Assert
    assert r.status_code == status and stopped is (status == 200)
    if status == 403:
        assert "someone else" in r.json()["detail"]


def test_a_waiting_stop_from_someone_else_does_not_stop_the_job(monkeypatch, client):
    """ASVS V4.2.1 · A01:2021 · CWE-639 · WSTG-ATHZ-04: a Stop mallory sends for alice's token before alice's start answers never makes alice's job begin stopped."""
    # Arrange
    _as_person(monkeypatch)
    monkeypatch.setattr(pack_jobs, "_pending_stops", {})
    monkeypatch.setattr(pack_jobs, "_token_jobs", {})
    token = "c6-owner-token-0002"
    # Act
    stop = client.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}, headers={"X-Test-Actor": "mallory@example.com"})
    job, gate = _held_job(token, "alice@example.com")
    stopped = job.cancel.is_set()
    gate.set()
    # Assert
    assert stop.status_code == 200 and stop.json()["pending"] is True and stopped is False


def test_a_waiting_stop_from_the_starter_is_still_honoured(monkeypatch, client):
    """ASVS V1.11.3 · CWE-367 · WSTG-BUSL-07: alice's own Stop, sent before her start answered, still makes her job begin stopped (the race fix is kept)."""
    # Arrange
    _as_person(monkeypatch)
    monkeypatch.setattr(pack_jobs, "_pending_stops", {})
    monkeypatch.setattr(pack_jobs, "_token_jobs", {})
    token = "c6-owner-token-0003"
    # Act
    client.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}, headers={"X-Test-Actor": "alice@example.com"})
    job, gate = _held_job(token, "alice@example.com")
    stopped = job.cancel.is_set()
    gate.set()
    # Assert
    assert stopped is True


def test_the_in_memory_result_stores_are_capped():
    """ASVS V11.1.4 · A04:2021 · CWE-400 · CWE-770: the HAR batch, Test a list and plan stores keep a bounded number of runs."""
    # Assert
    assert 1 <= srv._PATH_BATCHES_MAX <= 20 and 1 <= srv._BULK_RUNS_MAX <= 20 and 1 <= srv._PLANS_MAX <= 200
    assert pack_jobs.MAX_FINISHED_JOBS <= 500 and pack_jobs.MAX_PENDING_STOPS <= 1024


# ── 5. Downloads: safe names, no traversal ─────────────────────────────

DOWNLOAD_ROUTES = [r for r in ROUTES if _method(r) == "GET" and r.dependant.path_params
                   and re.search(r"Content-Disposition|FileResponse|_attachment\(", inspect.getsource(r.endpoint))]


@pytest.mark.parametrize("route", DOWNLOAD_ROUTES, ids=_ids(DOWNLOAD_ROUTES))
def test_a_download_with_a_traversal_or_header_breaking_id_is_refused(client, route):
    """ASVS V12.3.1 · ASVS V5.1.3 · A01:2021 · CWE-22 · CWE-113 · WSTG-ATHZ-01: an id with ../, a quote, a CR/LF or non-Latin-1 text is a 4xx and never lands in a header."""
    for value in ("..%2F..%2Fetc%2Fpasswd", "a%22%3B%20filename%3D%22x.exe", "a%0D%0AX-C6%3A%201", "%E2%80%AE%F0%9F%98%80"):
        # Act
        r = client.get(_path(route, value))
        # Assert
        assert 400 <= r.status_code < 500, (value, r.status_code)
        assert "x-c6" not in {k.lower() for k in r.headers} and "content-disposition" not in {k.lower() for k in r.headers}


def test_the_download_table_found_the_download_routes():
    """ASVS V12.3.1 · SSDF PW.8.2: the traversal walk covers the downloads (jobs, snapshots, reports, digests)."""
    # Assert
    assert len(DOWNLOAD_ROUTES) >= 12


def test_every_content_disposition_name_is_a_plain_token():
    """ASVS V12.3.1 · A03:2021 · CWE-113 · WSTG-INPV-15: every filename the server writes in Content-Disposition is built from constants, a stamp or a sanitised part (letters, digits, '-', '_', '.')."""
    # Arrange
    src = open(SRC_PATH, encoding="utf-8").read()
    names = re.findall(r'Content-Disposition"\s*:\s*f?[\'"]attachment; filename=\\?"?([^\'"]+)', src)
    # Act: every interpolated part must be one the server builds
    parts = {p for n in names for p in re.findall(r"\{([^}]+)\}", n)}
    allowed = re.compile(r"^(ts|stamp|name|org|which|area|purpose|digest_id|report_id|part_name|filename|fname|fname_base|"
                         r"snapshot_id\[5:\]|out\[\"vendor\"\]|pl\.slugify\(pack_id\) or \"pack\"|pov\.report_filename\(model, fmt\))$")
    # Assert
    assert names and all(allowed.match(p) for p in parts), sorted(p for p in parts if not allowed.match(p))


def test_a_digest_id_reaches_its_header_only_in_its_fixed_form(client):
    """ASVS V12.3.1 · CWE-113: a digest id that is not YYYYMMDD-HHMMSS is a 404 before the Markdown download builds its filename."""
    # Act
    r = client.get('/api/digests/20260101-000000"x', params={"format": "markdown"})
    # Assert
    assert r.status_code == 404 and "content-disposition" not in {k.lower() for k in r.headers}


# ── 6. The credential fallback chain ───────────────────────────────────

@pytest.fixture
def chain(monkeypatch, tmp_path):
    """No environment tenant, no offline tenant, profiles and tenant_config.json in tmp_path."""
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    monkeypatch.setattr(srv, "_offline_creds", lambda: None)
    import tenant_profiles
    tenant_profiles.upsert({"name": "Acme", "cloud": "zscalertwo", "vanity_domain": "acme", "client_id": "profclient01"},
                           client_secret="profile-secret-1", remember_secret=True, profile_id="acme")
    return tmp_path


def _env(monkeypatch, **kv):
    names = {"vanity_domain": "ZSCALER_VANITY_DOMAIN", "client_id": "ZSCALER_CLIENT_ID", "client_secret": "ZSCALER_CLIENT_SECRET",
             "cloud": "ZSCALER_CLOUD"}
    for k, v in kv.items():
        monkeypatch.setenv(names[k], v)


def _cfg(folder, **kv):
    (folder / "tenant_config.json").write_text(json.dumps(kv), encoding="utf-8")


def test_the_body_wins_over_every_other_source(chain, monkeypatch):
    """ASVS V2.10.4 · CWE-522: a complete typed sign-in is used as typed; the profile, environment and file are not consulted."""
    # Arrange
    _env(monkeypatch, vanity_domain="envco", client_id="envclient01", client_secret="env-secret")
    _cfg(chain, vanity_domain="fileco", client_id="fileclient1", client_secret="file-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(vanity_domain="typed", client_id="typedclient", client_secret="typed-secret", profile_id="acme"))
    # Assert
    assert (c["vanity_domain"], c["client_id"], c["client_secret"]) == ("typed", "typedclient", "typed-secret")


def test_the_profile_comes_before_the_environment_and_the_file(chain, monkeypatch):
    """ASVS V2.10.4 · CWE-522: with only a profile chosen, its sign-in (remembered secret included) is used, not the environment's."""
    # Arrange
    _env(monkeypatch, vanity_domain="envco", client_id="envclient01", client_secret="env-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(profile_id="acme"))
    # Assert
    assert (c["vanity_domain"], c["client_id"], c["client_secret"], c["cloud"]) == ("acme", "profclient01", "profile-secret-1", "zscalertwo")


def test_the_environment_comes_before_tenant_config_json(chain, monkeypatch):
    """ASVS V2.10.4 · CWE-522: with nothing typed and no profile, the environment's sign-in is used before the file's."""
    # Arrange
    _env(monkeypatch, vanity_domain="envco", client_id="envclient01", client_secret="env-secret")
    _cfg(chain, vanity_domain="fileco", client_id="fileclient1", client_secret="file-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest())
    # Assert
    assert (c["vanity_domain"], c["client_id"]) == ("envco", "envclient01")


def test_tenant_config_json_is_the_last_resort(chain):
    """ASVS V2.10.4 · CWE-522: with nothing else, tenant_config.json supplies the sign-in."""
    # Arrange
    _cfg(chain, vanity_domain="fileco", client_id="fileclient1", client_secret="file-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest())
    # Assert
    assert (c["vanity_domain"], c["client_id"], c["client_secret"]) == ("fileco", "fileclient1", "file-secret")


@pytest.mark.parametrize("content", ["[1, 2]", "not json", "null", '{"client_id": 5}'], ids=["list", "garbage", "null", "number-id"])
def test_an_odd_tenant_config_json_is_ignored(chain, content):
    """ASVS V5.1.4 · CWE-20 · CWE-755: a tenant_config.json that is not a credentials object is ignored, never a 500."""
    # Arrange
    (chain / "tenant_config.json").write_text(content, encoding="utf-8")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest())
    # Assert
    assert c["client_secret"] == ""


@pytest.mark.parametrize("typed", [{"vanity_domain": "othertenant"}, {"client_id": "otherclient"},
                                   {"vanity_domain": "othertenant", "client_id": "profclient01"}],
                         ids=["other-vanity", "other-client-id", "other-vanity-same-id"])
def test_a_profile_secret_is_never_sent_with_another_tenants_name(chain, typed):
    """ASVS V2.10.4 · ASVS V8.3.4 · A07:2021 · CWE-522 · WSTG-ATHN-07: a typed vanity domain or client id that is not the profile's gets none of the profile's secret (it went to that other tenant's sign-in host)."""
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(profile_id="acme", **typed))
    # Assert
    assert c["client_secret"] != "profile-secret-1"


def test_a_profile_still_fills_its_own_typed_identity(chain):
    """ASVS V2.10.4 · CWE-522: the form sending the profile's own vanity domain and client id (any case) still gets the remembered secret (regression)."""
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(profile_id="acme", vanity_domain="ACME", client_id="profclient01"))
    # Assert
    assert c["client_secret"] == "profile-secret-1"


def test_an_environment_secret_is_never_sent_with_another_typed_vanity_domain(chain, monkeypatch):
    """ASVS V2.10.4 · A07:2021 · CWE-522 · WSTG-ATHN-07: a typed vanity domain that is not the environment's does not borrow the environment's client and secret."""
    # Arrange
    _env(monkeypatch, vanity_domain="envco", client_id="envclient01", client_secret="env-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(vanity_domain="elsewhere"))
    # Assert
    assert c["client_secret"] == "" and c["vanity_domain"] == "elsewhere"


def test_a_file_secret_is_never_sent_with_another_typed_vanity_domain(chain):
    """ASVS V2.10.4 · A07:2021 · CWE-522 · WSTG-ATHN-07: the same for tenant_config.json."""
    # Arrange
    _cfg(chain, vanity_domain="fileco", client_id="fileclient1", client_secret="file-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(vanity_domain="elsewhere"))
    # Assert
    assert c["client_secret"] == ""


def test_a_typed_vanity_domain_that_matches_the_environment_still_uses_it(chain, monkeypatch):
    """ASVS V2.10.4 · CWE-522: typing the environment's own vanity domain keeps the environment sign-in (regression)."""
    # Arrange
    _env(monkeypatch, vanity_domain="envco", client_id="envclient01", client_secret="env-secret")
    # Act
    c = srv._tenant_creds(srv.TenantCredsRequest(vanity_domain="EnvCo"))
    # Assert
    assert c["client_id"] == "envclient01"


def test_a_secret_refused_by_the_pairing_rule_fails_closed_with_a_plain_400(chain, signins, client):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: the request is then incomplete and refused with the missing field before any sign-in."""
    # Act
    r = client.post("/api/diagnose/zcc", json={"profile_id": "acme", "vanity_domain": "othertenant", **SCOPE})
    # Assert
    assert r.status_code == 400 and r.json()["detail"].endswith("is required.") and signins == []


# ── 8. Leftovers a merge can leave ─────────────────────────────────────

def test_pyflakes_finds_no_undefined_or_redefined_name():
    """ASVS V14.2.1 · A06:2021 · CWE-1164 · SSDF PW.7.2: pyflakes reports no undefined name, no redefinition and no duplicate argument in dlp_api_server.py."""
    pyflakes_api = pytest.importorskip("pyflakes.api")
    from pyflakes import reporter
    import io
    # Arrange
    out, err = io.StringIO(), io.StringIO()
    # Act
    pyflakes_api.checkPath(SRC_PATH, reporter.Reporter(out, err))
    # Assert
    bad = [ln for ln in out.getvalue().splitlines() if re.search(r"undefined name|redefinition of|duplicate argument|referenced before", ln)]
    assert bad == [] and err.getvalue() == ""


def test_every_global_a_function_reads_exists():
    """ASVS V14.2.1 · CWE-457 · SSDF PW.7.2: every implicit global any function of dlp_api_server reads is defined at import (symtable), so no route fails with a NameError."""
    # Arrange
    table = symtable.symtable(open(SRC_PATH, encoding="utf-8").read(), SRC_PATH, "exec")
    missing = set()

    def walk(t):
        for s in t.get_symbols():
            if t.get_type() != "module" and s.is_referenced() and (s.is_global() and not s.is_declared_global()) \
                    and not hasattr(srv, s.get_name()) and not hasattr(builtins, s.get_name()):
                missing.add((t.get_name(), s.get_name()))
        for ch in t.get_children():
            walk(ch)
    # Act
    walk(table)
    # Assert
    assert missing == set()


def test_no_route_is_registered_twice():
    """ASVS V14.2.1 · A04:2021 · CWE-561 · SSDF PW.7.2: no method and path is served by two handlers (the later one would be dead code)."""
    # Arrange
    seen, dup = set(), []
    for r in srv.app.routes:
        if isinstance(r, APIRoute):
            for m in r.methods:
                # Act
                key = (m, r.path)
                if key in seen:
                    dup.append(key)
                seen.add(key)
    # Assert
    assert dup == []


def test_no_module_level_function_or_class_is_defined_twice():
    """ASVS V14.2.1 · CWE-561 · SSDF PW.7.2: no top-level def or class shadows an earlier one of the same name."""
    # Arrange
    tree = ast.parse(open(SRC_PATH, encoding="utf-8").read())
    names = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    # Act
    dup = sorted({n for n in names if names.count(n) > 1})
    # Assert
    assert dup == []
