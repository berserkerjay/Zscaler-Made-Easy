"""Tenant API map routes: the plan needs no sign-in, a start is refused (400) before any sign-in unless the confirmed plan is
the one sent, the run reads the signed-in tenant (shared sign-in or the sample) with GET only, keeps no value, audits one
entry of counts, saves sealed per tenant, exports escaped, and every route has its team rule.

Background jobs run synchronously in the request (pack_jobs.start is replaced); nothing contacts a tenant."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import offline_tenant
import pack_jobs
import team_routes
import tenant_api_map as tam
from conftest import audit_events, read_store_text

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "7210000000000"}
CANARY = "route-canary-VALUE-55e1"
ROUTES = ["POST /api/tenant-api-map/plan", "POST /api/tenant-api-map/start", "GET /api/tenant-api-map/saved", "GET /api/tenant-api-map/export/{report_id}",
          "GET /api/tenant-api-map/{report_id}", "POST /api/tenant-api-map/forget", "GET /report/api-map"]


class _Job:
    def __init__(self, result=None, error=None):
        self.id, self.status, self.kind, self.actor = "j1", "done", "apimap", None
        self.result, self.error = result, error


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    """The pace is proved in test_tenant_api_map.py; here a run does not wait between reads."""
    real = tam.Throttle
    monkeypatch.setattr(tam, "Throttle", lambda rps, **k: real(rps, clock=lambda: 0.0, sleeper=lambda s: None))


@pytest.fixture
def client(monkeypatch):
    """A TestClient whose jobs run at once; `jobs` collects their results. The tenant client factory is a scripted fake."""
    jobs = []
    calls = {"signed_in": 0, "gets": []}

    class Fake:
        offline, legacy, customer_id = False, False, "7210000000000"

        def get(self, ep, p=None):
            calls["gets"].append(ep)
            return ([{"id": 1, "name": CANARY, "password": CANARY}], 200) if "webDlpRules" in ep else ({"error": "x", "status": 404}, 404)

        def post(self, *a, **k):
            raise AssertionError("POST")
        put = delete = post

        def close(self):
            pass

    def signed_in(creds):
        calls["signed_in"] += 1
        return Fake()

    def start(kind, fn, **kw):
        out = {}
        try:
            out["result"] = fn(lambda line: None, __import__("threading").Event())
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
        job = _Job(out.get("result"), out.get("error"))
        jobs.append(job)
        return job

    monkeypatch.setattr(srv, "_signed_in_raw", signed_in)
    monkeypatch.setattr(pack_jobs, "start", start)
    c = TestClient(srv.app)
    c.jobs, c.calls = jobs, calls
    return c


def _start_body(**kw):
    plan = tam.plan(["zia"], True)
    body = dict(CREDS, products=["zia"], features_only=True, confirm=True, plan_hash=plan["plan_hash"])
    body.update(kw)
    return body


def test_the_plan_needs_no_sign_in_and_lists_the_reads(client):
    """ASVS V4.1.1: POST plan answers the list, the skips and the hash with no credentials and no client."""
    r = client.post("/api/tenant-api-map/plan", json={"products": ["zia"], "features_only": True})
    assert r.status_code == 200 and client.calls["signed_in"] == 0
    d = r.json()
    assert d["method"] == "GET" and d["count"] == len(d["reads"]) > 10 and d["plan_hash"] and d["skipped"]
    assert all(x["product"] == "zia" for x in d["reads"])


@pytest.mark.parametrize("body,fragment", [
    ({"confirm": False}, "Confirm"), ({"plan_hash": "0" * 24}, "changed"), ({"products": ["nonsense"]}, "None of those products"),
    ({"products": ["zia"] * 30}, "Pick products"),
])
def test_start_is_refused_before_sign_in_unless_the_plan_is_confirmed(client, body, fragment):
    """ASVS V4.2.2 · CWE-285: no confirmation, a stale hash or bad products is a 400 before any sign-in or read."""
    r = client.post("/api/tenant-api-map/start", json=_start_body(**body))
    assert r.status_code == 400 and fragment in r.json()["detail"]
    assert client.calls["signed_in"] == 0 and client.calls["gets"] == []


def test_a_confirmed_start_reads_with_get_only_and_keeps_no_value(client):
    """CWE-532 · ASVS V8.3.4: the run reads the confirmed list through the signed-in client; no canary reaches the result, the audit or the saved file."""
    r = client.post("/api/tenant-api-map/start", json=_start_body())
    assert r.status_code == 200 and client.calls["signed_in"] == 1
    res = client.jobs[-1].result
    assert res["status"] == "done" and res["report_id"].startswith("apimap-") and res["counts"]["present"] == 1
    assert client.calls["gets"] and all(g.startswith("raw:/zia/") for g in client.calls["gets"])
    assert CANARY not in json.dumps(res)
    ev = [e for e in audit_events() if e.get("event") == "tenant_api_map_run"]
    assert len(ev) == 1 and ev[0]["counts"]["present"] == 1 and ev[0]["method"] == "GET" and ev[0]["stopped"] is False
    assert CANARY not in json.dumps(ev) and "secret-secret-secret" not in json.dumps(ev)
    assert CANARY not in read_store_text(tam.history_path())
    saved = client.get("/api/tenant-api-map/saved", params={"tenant": res["tenant_label"]}).json()
    assert len(saved["saved"]) == 1 and saved["map"]["counts"]["present"] == 1


ACME = {"auth_method": "oneapi", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclient0001", "client_secret": "acme-secret-0001"}


class _Raw:
    offline, legacy, customer_id = False, False, ""

    def __init__(self, creds):
        self.creds = creds

    def auth(self):
        return True

    def get(self, ep, p=None):
        return [], 200

    def close(self):
        pass


def test_the_signed_in_tenant_is_used_without_new_credentials(monkeypatch, tmp_path):
    """ASVS V3.2.1 · CWE-287: after one sign-in, a start that sends no credentials reads that tenant (the shared sign-in); with none kept it is refused."""
    import tenant_session
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    made = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv, "_raw_client", lambda creds: (made.append(dict(creds)), _Raw(creds))[1])
    monkeypatch.setattr(pack_jobs, "start", lambda kind, fn, **kw: (fn(lambda l: None, __import__("threading").Event()), _Job())[1])
    c = TestClient(srv.app)
    body = {"products": ["zia"], "features_only": True, "confirm": True, "plan_hash": tam.plan(["zia"], True)["plan_hash"]}
    assert c.post("/api/tenant-api-map/start", json=body).status_code in (400, 401) and made == []
    assert c.post("/api/tenant/check", json=ACME).json()["signed_in"] is True
    made.clear()
    r = c.post("/api/tenant-api-map/start", json=body)
    assert r.status_code == 200 and [m["vanity_domain"] for m in made] == ["acme"] and tenant_session.COOKIE
    tenant_session.forget()


def test_the_sample_tenant_maps_offline_and_never_signs_in(monkeypatch):
    """ASVS V1.1.5: with the sample tenant chosen the run uses the offline client: the real client factory is never reached."""
    out = []
    monkeypatch.setattr(pack_jobs, "start", lambda kind, fn, **kw: (out.append(fn(lambda l: None, __import__("threading").Event())), _Job())[1])
    monkeypatch.setattr(srv, "Client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("a real client was built")))
    c = TestClient(srv.app)
    c.cookies.set(offline_tenant.COOKIE, offline_tenant.SAMPLE)
    plan = tam.plan(None, False)
    r = c.post("/api/tenant-api-map/start", json={"products": [], "features_only": False, "confirm": True, "plan_hash": plan["plan_hash"]})
    assert r.status_code == 200, r.text
    res = out[0]
    assert res["status"] == "done" and res["tenant_label"].startswith("Sample tenant") and res["counts"]["present"] > 150 and res["counts"]["no_permission"] == 1


def test_exports_are_json_and_two_csv_tables_and_unknown_ones_are_refused(client):
    """CWE-1236 · ASVS V5.2.2: JSON and CSV (features or endpoints) download with no-store; anything else is a 400, an unknown id a 404."""
    client.post("/api/tenant-api-map/start", json=_start_body())
    rid = client.jobs[-1].result["report_id"]
    j = client.get(f"/api/tenant-api-map/export/{rid}")
    assert j.status_code == 200 and j.headers["cache-control"] == "no-store" and "attachment" in j.headers["content-disposition"]
    assert json.loads(j.text)["method"] == "GET"
    for what in ("features", "endpoints"):
        c = client.get(f"/api/tenant-api-map/export/{rid}", params={"format": "csv", "what": what})
        assert c.status_code == 200 and c.text.startswith(("feature,", "product,"))
    assert client.get(f"/api/tenant-api-map/export/{rid}", params={"format": "xlsx"}).status_code == 400
    assert client.get(f"/api/tenant-api-map/export/{rid}", params={"format": "csv", "what": "all"}).status_code == 400
    assert client.get("/api/tenant-api-map/export/soc-12345678").status_code == 404
    assert client.get("/api/tenant-api-map/apimap-nope1234").status_code == 404
    assert client.get(f"/api/tenant-api-map/{rid}").json()["report_id"] == rid


def test_forget_needs_confirmation_and_removes_the_saved_maps(client):
    """ASVS V4.2.2: removing saved maps asks for confirm: true; then they are gone."""
    client.post("/api/tenant-api-map/start", json=_start_body())
    label = client.jobs[-1].result["tenant_label"]
    assert client.post("/api/tenant-api-map/forget", json={"tenant": label}).status_code == 400
    assert client.post("/api/tenant-api-map/forget", json={"tenant": label, "confirm": True}).json()["removed"] == 1
    assert client.get("/api/tenant-api-map/saved", params={"tenant": label}).json()["saved"] == []


def test_a_second_map_while_one_runs_is_refused(client):
    """CWE-770: one map at a time per server: a start while another runs is a 409 before any sign-in."""
    assert tam._RUN_LOCK.acquire(blocking=False)
    try:
        r = client.post("/api/tenant-api-map/start", json=_start_body())
    finally:
        tam._RUN_LOCK.release()
    assert r.status_code == 409 and client.calls["signed_in"] == 0


def test_every_route_has_a_team_rule_and_the_right_one():
    """ASVS V4.1.1: each route is classified; a run needs read on the tenant, removing saved maps needs plan, the page shell is public."""
    for key in ROUTES:
        assert key in team_routes.ROUTE_RULES, key
    r = team_routes.ROUTE_RULES
    assert r["POST /api/tenant-api-map/start"] == team_routes.READ and r["POST /api/tenant-api-map/forget"] == team_routes.PLAN
    assert r["GET /report/api-map"] == team_routes.PUBLIC and r["POST /api/tenant-api-map/plan"] == team_routes.SESSION


def test_an_unexpected_field_in_a_request_is_ignored_not_trusted(client):
    """CWE-915: extra fields (a path, a method, a customer id override) change nothing about what is read."""
    r = client.post("/api/tenant-api-map/start", json=_start_body(method="POST", path="/zia/api/v1/adminUsers", paths=["/x"], endpoints=["/y"]))
    assert r.status_code == 200
    assert all(re.match(r"raw:/zia/api/v1/[A-Za-z]", g) for g in client.calls["gets"]) and not any("adminUsers" in g for g in client.calls["gets"])


# ── the assistant tool ───────────────────────────────────────────────
def test_the_assistant_tool_maps_the_sample_offline_and_reads_only_saved_maps_live(monkeypatch):
    """ASVS V8.3.4 · CWE-200: tenant_api_map answers the sample from its offline answers and, live, only the newest saved map (never the tenant); no value in either."""
    import mcp_tools
    out = mcp_tools.run("tenant_api_map", mcp_tools.tenant_api_map, {}, source="sample")
    assert out["tool"] == "tenant_api_map" and out["read_only"] is True and "error" not in out
    data = out["data"]
    assert data["counts"]["present"] > 150 and any(f["feature"] == "Web DLP" and f["verdict"] == "present" for f in data["features"])
    assert data["no_permission_endpoints"] == ["/zia/api/v1/users/auditors"] and "field_names" not in json.dumps(data)
    # Live: nothing saved yet -> how to make one; a saved map -> its features. No client is built either way.
    monkeypatch.setenv("ZSCALER_CLIENT_ID", "abc123456789")
    monkeypatch.setenv("ZSCALER_CLIENT_SECRET", "secret-secret-secret")
    monkeypatch.setenv("ZSCALER_VANITY_DOMAIN", "acme")
    monkeypatch.setattr(srv, "_signed_in_raw", lambda c: (_ for _ in ()).throw(AssertionError("the live tenant was read")))
    monkeypatch.setattr(srv, "Client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("a client was built")))
    none = mcp_tools.run("tenant_api_map", mcp_tools.tenant_api_map, {}, source="live")
    assert none["data"]["saved_maps"] == 0 and "Map this tenant" in none["data"]["how_to"]
    import tenant_auth
    label = tenant_auth.record_label(tenant_auth.normalize(dict(vanity_domain="acme", client_id="abc123456789", client_secret="secret-secret-secret")))
    rep = {"status": "done", "tenant_label": label, "started_at": "2026-11-07T10:00:00+00:00", "rps": 1.0, "counts": {"present": 1}, "sign_in": "OneAPI",
           "features": [{"feature": "Web DLP", "product": "zia", "verdict": "present", "deciding_endpoint": "/zia/api/v1/webDlpRules", "status": 200, "item_count": 1,
                         "detail": "", "info": []}], "endpoints": []}
    tam.save(label, rep)
    got = mcp_tools.run("tenant_api_map", mcp_tools.tenant_api_map, {}, source="live")
    assert got["data"]["features"][0]["feature"] == "Web DLP" and len(got["data"]["saved_maps"]) == 1


def test_the_mcp_server_lists_the_tool_as_read_only():
    """ASVS V13.2.1: the MCP server exposes tenant_api_map with the read-only annotation and no write argument."""
    import asyncio
    import dlp_mcp_server
    tool = {t.name: t for t in asyncio.run(dlp_mcp_server.mcp.list_tools())}["tenant_api_map"]
    assert tool.annotations.read_only_hint is True and set((getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {})["properties"]) == {"source", "snapshot_id"}
