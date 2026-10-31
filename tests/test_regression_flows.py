"""Regression journeys: the flows that worked before the Wave 5 merge still
work end to end, driven through the HTTP API exactly as the pages drive
them, against stateful fake tenants (never a real one).

Covered here because no other test walks the whole journey with the real
handlers and the real sinks (tests/test_write_safety_gates.py stubs the
sinks to prove the gates; the module tests call the functions directly):

- rule migration: status, fetch, analyze, plan, export, post (dry run,
  refused without each gate, then applied in the planned order);
- remediation (one-click fixes): catalog, plan, dry run, refused without
  write mode, then applied with exactly the planned call;
- policy packs: preflight, deploy through the gates, the deployment record,
  undo, deploy again, removal preview and removal through the gates;
- the MCP server: its four tools answer over the MCP tool API.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from typing import Any, Dict, List, Tuple

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

CREDS = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-regression", "client_secret": "regression-secret-x9"}
DLP_SCOPE = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True}
ASSESSOR = "Jane Doe"


@pytest.fixture
def write_mode(monkeypatch):
    """Write mode as the session switch sets it; off until a test turns it on."""
    def turn(on: bool) -> None:
        monkeypatch.setattr(security, "_write_override", bool(on))
    turn(False)
    return turn


# ── Rule migration (rule_migrator through /api/migrate/*) ──────────────

class RawTenant:
    """The raw ZIA client the migration and the fixes use: Web DLP rules,
    an advanced-settings document, and a log of every write."""

    def __init__(self) -> None:
        self.rules: List[Dict[str, Any]] = [
            {"id": 11, "name": "Allow finance uploads", "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW",
             "dlpEngines": [{"id": 1}], "urlCategories": ["FINANCE"]},
            {"id": 12, "name": "Block PCI everywhere", "order": 2, "rank": 7, "state": "ENABLED", "action": "BLOCK",
             "dlpEngines": [{"id": 2}]},
            {"id": 13, "name": "Monitor source code", "order": 3, "rank": 7, "state": "ENABLED", "action": "ALLOW",
             "dlpEngines": [{"id": 3}], "users": [{"id": 5}]},
        ]
        self.writes: List[Tuple[str, str, Any]] = []
        self.signed_in = 0

    def auth(self):
        self.signed_in += 1
        return True

    def close(self) -> None:
        pass

    def get(self, ep: str, params: Any = None):
        path = ep.split("?")[0]
        if path == "/zia/webDlpRules":
            return [dict(r) for r in sorted(self.rules, key=lambda r: r["order"])], 200
        if path.startswith("/zia/webDlpRules/"):
            rid = int(path.rsplit("/", 1)[1])
            hit = [dict(r) for r in self.rules if r["id"] == rid]
            return (hit[0], 200) if hit else ({"message": "not found"}, 404)
        if path == "/zia/advancedSettings":
            return {"enableEvaluateAllRules": False}, 200
        return [], 200

    def put(self, ep: str, body: Any):
        self.writes.append(("PUT", ep, body))
        if ep.startswith("/zia/webDlpRules/"):
            rid = int(ep.rsplit("/", 1)[1])
            for r in self.rules:
                if r["id"] == rid:
                    r.update(body)
                    return dict(r), 200
            return {"message": "not found"}, 404
        return body, 200

    def post(self, ep: str, body: Any):
        self.writes.append(("POST", ep, body))
        if ep == "/zia/webDlpRules":
            rule = dict(body, id=100 + len(self.writes))
            self.rules.append(rule)
            return rule, 200
        return dict(body or {}, id=900 + len(self.writes)), 200

    def delete(self, ep: str, body: Any = None):
        self.writes.append(("DELETE", ep, body))
        return None, 204


@pytest.fixture
def raw_tenant(monkeypatch):
    tenant = RawTenant()
    monkeypatch.setattr(srv, "_raw_client", lambda creds: tenant)
    return tenant


def _migrate_body(**extra: Any) -> Dict[str, Any]:
    return dict(CREDS, **DLP_SCOPE, assessor=ASSESSOR, **extra)


def test_rule_migration_reads_plans_and_exports_without_writing(raw_tenant):
    """SSDF PW.8.2 · CWE-440: the rule migration's read steps (status, fetch, analyze, plan, export) still answer as before and write nothing."""
    c = TestClient(srv.app)
    status = c.post("/api/migrate/status", json=_migrate_body())
    assert status.status_code == 200, status.text
    assert {"current_mode", "mode_source", "recommendation"} <= set(status.json())
    fetched = c.post("/api/migrate/fetch", json=_migrate_body()).json()
    assert fetched["rule_type"] == "web_dlp" and fetched["count"] == 3
    assert [r["id"] for r in fetched["rules"]] == [11, 12, 13]
    analysis = c.post("/api/migrate/analyze", json={"rules": fetched["rules"]})
    assert analysis.status_code == 200 and isinstance(analysis.json(), dict)
    plan = c.post("/api/migrate/plan", json={"rules": fetched["rules"]}).json()
    assert sorted(r["id"] for r in plan["proposed_order"]) == [11, 12, 13]
    as_json = c.post("/api/migrate/export?format=json", json={"rules": fetched["rules"]})
    assert as_json.status_code == 200 and as_json.headers["content-type"].startswith("application/json")
    assert "attachment" in as_json.headers["content-disposition"]
    exported = json.loads(as_json.text)
    rows = exported if isinstance(exported, list) else exported.get("rules") or []
    assert sorted(r["id"] for r in rows) == [11, 12, 13]
    as_csv = c.post("/api/migrate/export?format=csv", json={"rules": fetched["rules"]})
    assert as_csv.status_code == 200 and as_csv.headers["content-type"].startswith("text/csv")
    assert len(list(csv.reader(io.StringIO(as_csv.text)))) >= 4
    assert raw_tenant.writes == []


def test_rule_migration_post_dry_run_writes_nothing(raw_tenant, write_mode):
    """SSDF PW.8.2 · CWE-440: a dry-run post of the migration plan lists every planned call and writes nothing, even in write mode."""
    write_mode(True)
    c = TestClient(srv.app)
    rules = c.post("/api/migrate/fetch", json=_migrate_body()).json()["rules"]
    r = c.post("/api/migrate/post", json=_migrate_body(proposed_rules=rules, dry_run=True, mode="update"))
    assert r.status_code == 200 and r.json()["status"] == "dry_run" and r.json()["total"] == 3
    assert raw_tenant.writes == []


@pytest.mark.parametrize("gate,expect", [("confirm", 400), ("assessor", 400), ("write_mode", 403)])
def test_rule_migration_post_without_a_gate_is_refused_before_sign_in(raw_tenant, write_mode, gate, expect):
    """ASVS V4.1.3 · A01:2021 · CWE-862: a live migration post missing any one gate is refused before sign-in and writes nothing."""
    write_mode(gate != "write_mode")
    body = _migrate_body(proposed_rules=[{"id": 11, "name": "Allow finance uploads"}], dry_run=False, mode="update", confirm=True)
    if gate == "confirm":
        body["confirm"] = False
    if gate == "assessor":
        body["assessor"] = ""
    r = TestClient(srv.app).post("/api/migrate/post", json=body)
    assert r.status_code == expect, r.text
    assert raw_tenant.writes == [] and raw_tenant.signed_in == 0


def test_rule_migration_post_applies_the_planned_order_through_every_gate(raw_tenant, write_mode):
    """SSDF PW.8.2 · CWE-440: with every gate held, the migration posts the planned order and the tenant ends in that order."""
    write_mode(True)
    c = TestClient(srv.app)
    rules = c.post("/api/migrate/fetch", json=_migrate_body()).json()["rules"]
    planned = c.post("/api/migrate/plan", json={"rules": rules}).json()["proposed_order"]
    dry = c.post("/api/migrate/post", json=_migrate_body(proposed_rules=planned, dry_run=True, mode="update"))
    assert dry.status_code == 200, dry.text
    r = c.post("/api/migrate/post", json=_migrate_body(proposed_rules=planned, dry_run=False, mode="update", confirm=True,
                                                         plan_hash=dry.json()["plan_hash"]))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "completed" and out["succeeded_count"] == 3 and out["failed_count"] == 0
    assert [w[0] for w in raw_tenant.writes] == ["PUT"] * 3
    now = [r["id"] for r in sorted(raw_tenant.rules, key=lambda r: r["order"])]
    assert now == [r["id"] for r in planned]


# ── Remediation (one-click fixes) ─────────────────────────────────────

def _criteria(recipe: Dict[str, Any]) -> Dict[str, Any]:
    """A valid answer for every field of a recipe, from its own field specs."""
    out: Dict[str, Any] = {}
    for f in recipe.get("fields") or []:
        t = f.get("type")
        if "default" in f:
            out[f["key"]] = f["default"]
        elif t == "enum":
            out[f["key"]] = f["options"][0]
        elif t == "number":
            out[f["key"]] = f.get("min", 1)
        elif t in ("list", "multiselect", "array"):
            out[f["key"]] = [(f.get("options") or ["Regression"])[0]]
        else:
            out[f["key"]] = "Regression_fix"
    return out


def _destructive_recipe(c: TestClient) -> Dict[str, Any]:
    cat = c.get("/api/remediation/catalog").json()
    recipes = cat["catalog"]
    for r in recipes:
        crit = _criteria(r)
        if r.get("destructive") and c.post("/api/remediation/plan", json=dict(CREDS, check_id=r["check_id"], criteria=crit)).json().get("ok"):
            return dict(r, criteria=crit)
    raise AssertionError("no destructive recipe plans with its own defaults")


def test_remediation_plans_and_dry_runs_without_writing(raw_tenant, write_mode):
    """SSDF PW.8.2 · CWE-440: a fix is planned and dry-run with the exact call it would send, and nothing is written even in write mode."""
    write_mode(True)
    c = TestClient(srv.app)
    recipe = _destructive_recipe(c)
    plan = c.post("/api/remediation/plan", json=dict(CREDS, check_id=recipe["check_id"], criteria=recipe["criteria"])).json()
    assert plan["ok"] and plan["method"] in ("POST", "PUT", "PATCH", "DELETE") and plan["endpoint"].startswith("/")
    dry = c.post("/api/remediation/execute", json=dict(CREDS, check_id=recipe["check_id"], criteria=recipe["criteria"], dry_run=True)).json()
    assert dry["status"] == "dry_run" and dry["endpoint"] == plan["endpoint"] and dry["body"] == plan["body"]
    assert raw_tenant.writes == []


def test_remediation_live_needs_write_mode_and_then_sends_the_planned_call(raw_tenant, write_mode):
    """ASVS V4.1.3 · A01:2021 · CWE-862: a live fix is refused without write mode, and with every gate sends exactly the planned call once."""
    c = TestClient(srv.app)
    recipe = _destructive_recipe(c)
    every_policy = {"scopes": ["dlp", "zia_extras"], "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler"}, "from_page": True}
    body = dict(CREDS, **every_policy, check_id=recipe["check_id"], criteria=recipe["criteria"], dry_run=False, confirm=True, assessor=ASSESSOR)
    assert c.post("/api/remediation/execute", json=body).status_code == 403
    assert c.post("/api/remediation/execute", json=dict(body, confirm=False)).status_code == 400
    assert raw_tenant.writes == [] and raw_tenant.signed_in == 0
    write_mode(True)
    plan = c.post("/api/remediation/plan", json=dict(CREDS, check_id=recipe["check_id"], criteria=recipe["criteria"])).json()
    r = c.post("/api/remediation/execute", json=body)
    assert r.status_code == 200 and r.json()["status"] == "completed", r.text
    method = "PUT" if plan["method"] == "PATCH" else plan["method"]
    assert raw_tenant.writes == [(method, plan["endpoint"], plan["body"])]


# ── Policy packs: deploy, record, undo, removal ───────────────────────

PACK = "zbp_enterprise_baseline"


@pytest.fixture
def sdk_tenant(monkeypatch):
    from test_job_audit import _activates, _tenant
    import pack_removal
    _activates(monkeypatch)
    monkeypatch.setattr(pack_removal, "RETRY_BASE_SECONDS", 0.0)
    monkeypatch.setattr(pack_removal, "_settle", lambda zia, s, log: "ACTIVE")
    tenant = _tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: tenant)
    return tenant


def _objects(tenant) -> Dict[str, int]:
    z = tenant.zia
    return {"dictionaries": len(z.dlp_dictionary.items), "engines": len(z.dlp_engine.items),
            "web": len(z.dlp_web_rules.items), "endpoint": len(z.endpoint_dlp_rules.items),
            "saas": len(z.casb_dlp_rules.items), "email": len(z.outbound_email_dlp_rules.items)}


def _deploy(c: TestClient) -> Dict[str, Any]:
    pre = c.post("/api/dlp-packs/preflight", json=dict(CREDS, pack_ids=[PACK]))
    assert pre.status_code == 200, pre.text
    r = c.post("/api/dlp-packs/apply", json=dict(CREDS, pack_ids=[PACK], plan_hash=pre.json()["plan_hash"], confirm=True,
                                                 verify=False, assessor=ASSESSOR))
    assert r.status_code == 200, r.text
    return r.json()


def test_pack_deploy_is_refused_without_write_mode_and_leaves_the_tenant_alone(sdk_tenant, write_mode):
    """ASVS V4.1.3 · A01:2021 · CWE-862: a pack deploy without write mode is refused (403) and the tenant is unchanged."""
    c = TestClient(srv.app)
    before = _objects(sdk_tenant)
    pre = c.post("/api/dlp-packs/preflight", json=dict(CREDS, pack_ids=[PACK])).json()
    r = c.post("/api/dlp-packs/apply", json=dict(CREDS, pack_ids=[PACK], plan_hash=pre["plan_hash"], confirm=True, verify=False, assessor=ASSESSOR))
    assert r.status_code == 403
    assert _objects(sdk_tenant) == before


def test_pack_deploy_record_and_undo_round_trip(sdk_tenant, write_mode):
    """SSDF PW.8.2 · CWE-440: a pack deployed through the gates is recorded, listed, and its undo returns the tenant to where it was."""
    write_mode(True)
    c = TestClient(srv.app)
    before = _objects(sdk_tenant)
    res = _deploy(c)
    assert res["status"] == "applied"
    after = _objects(sdk_tenant)
    assert after != before and all(after[k] >= before[k] for k in before)
    deps = c.get("/api/deployments").json()["deployments"]
    assert len(deps) == 1 and deps[0]["remaining"] > 0 and PACK in json.dumps(deps[0])
    undo = c.post(f"/api/deployments/{deps[0]['id']}/undo", json=dict(CREDS, confirm=True, assessor=ASSESSOR))
    assert undo.status_code == 200, undo.text
    assert undo.json()["status"] == "undone" and undo.json()["deployment"]["remaining"] == 0
    assert _objects(sdk_tenant) == before


def test_pack_removal_preview_then_apply_through_the_gates(sdk_tenant, write_mode):
    """SSDF PW.8.2 · A01:2021 · CWE-440: a deployed pack's removal is previewed, refused without confirmation, then removes what the pack added."""
    write_mode(True)
    c = TestClient(srv.app)
    before = _objects(sdk_tenant)
    _deploy(c)
    pre = c.post("/api/dlp-packs/removal/preflight", json=dict(CREDS, pack_ids=[PACK]))
    assert pre.status_code == 200, pre.text
    plan_hash = pre.json()["plan_hash"]
    body = dict(CREDS, pack_ids=[PACK], plan_hash=plan_hash, confirm=True, assessor=ASSESSOR)
    assert c.post("/api/dlp-packs/removal/apply", json=dict(body, confirm=False)).status_code == 400
    r = c.post("/api/dlp-packs/removal/apply", json=body)
    assert r.status_code == 200, r.text
    assert _objects(sdk_tenant) == before


# ── The MCP server ────────────────────────────────────────────────────

class _McpTenant:
    """The SDK adapter the MCP server builds: answers every read empty."""

    def __init__(self, **kwargs: Any) -> None:
        self._config = {"cloud": kwargs.get("cloud") or "production"}

    def auth(self):
        return True

    def close(self) -> None:
        pass

    def get(self, ep: str, params: Any = None):
        return [], 200

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **k: ([], 200)


def test_the_mcp_server_tools_answer_over_the_tool_api(monkeypatch):
    """SSDF PW.8.2 · CWE-440: the MCP server's four assessment tools are listed and answer (list, health, one section) with credentials from the environment only."""
    import dlp_mcp_server as m
    monkeypatch.setenv("ZSCALER_VANITY_DOMAIN", "acme")
    monkeypatch.setenv("ZSCALER_CLIENT_ID", "cid-mcp")
    monkeypatch.setenv("ZSCALER_CLIENT_SECRET", "mcp-secret-not-real")
    monkeypatch.setattr(m, "SdkClient", _McpTenant)

    async def run():
        names = sorted(t.name for t in await m.mcp.list_tools())
        checks = await m.mcp.call_tool("list_checks", {})
        health = await m.mcp.call_tool("get_health", {})
        section = await m.mcp.call_tool("run_section", {"section": "CC Portal", "org_name": "Acme"})
        return names, checks, health, section

    names, checks, health, section = asyncio.run(run())
    assert {"get_health", "list_checks", "run_assessment", "run_section"} <= set(names)   # plus the read-only analysis tools (test_mcp_tools)
    as_json = [json.loads(r.content[0].text) for r in (checks, health, section)]
    assert as_json[0]["total_checks"] > 100 and as_json[0]["sections"]
    assert as_json[1]["credentials_configured"] is True and as_json[1]["missing_environment_variables"] == []
    rep = as_json[2]
    assert rep["metadata"]["org"] == "Acme" and rep["checks"] and isinstance(rep["score"], (int, type(None)))
    assert {"score", "maturity", "sections", "checks", "critical", "review", "summary"} <= set(rep)
    assert "mcp-secret-not-real" not in json.dumps(as_json)


# ── Log analyzer: a PAC the evaluator cannot run is still read ────────
# The PAC reading was rebuilt on pac_eval (Wave 5), which refuses regular
# expressions, arrays, loops and switch (fail closed, never run). Before,
# such a PAC was still read from its text: its answers, default, gateways
# and DIRECT conditions. That reading must not be lost.

REFERENCE_STYLE_PAC = r'''function FindProxyForURL(url, host) {
    var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
    var resolved_ip = dnsResolve(host);
    if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0", "255.255.255.0") || privateIP.test(resolved_ip))
        return "DIRECT";
    if (isInNet(resolved_ip, "100.64.0.0", "255.255.0.0"))
        return "DIRECT";
    return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT";
}'''
ARRAY_LOOP_PAC = '''var bypass = ["*.box.com", "intranet.example.com"];
function FindProxyForURL(url, host) {
  for (var i = 0; i < bypass.length; i++) {
    if (shExpMatch(host, bypass[i])) { return "DIRECT"; }
  }
  if (isPlainHostName(host)) return "DIRECT";
  return "PROXY gateway.zscalertwo.net:80; DIRECT";
}'''
SWITCH_PAC = '''function FindProxyForURL(url, host) {
  switch (host) { case "localhost": return "DIRECT"; default: break; }
  if (shExpMatch(host, "*.mega.nz")) return "DIRECT";
  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";
}'''

PAC_CASES = {
    "regular expression": (REFERENCE_STYLE_PAC, "proxy", {("plain host names", "single-label names (intranet)"), ("isInNet", "100.64.0.0")},
                           {"Fail-open: if every listed gateway is unreachable, traffic goes direct"}),
    "array and loop": (ARRAY_LOOP_PAC, "proxy", {("plain host names", "single-label names (intranet)")},
                       {"Zscaler gateway is hard-coded instead of using ${GATEWAY}", "Only one gateway: no failover if that data centre is down"}),
    "switch": (SWITCH_PAC, "proxy", {("shExpMatch", "*.mega.nz")},
               {"Fail-closed: if every listed gateway is unreachable, the browser has no route"}),
}


@pytest.mark.parametrize("construct", sorted(PAC_CASES))
def test_a_pac_the_evaluator_refuses_is_still_read_from_its_text(construct):
    """SSDF PW.8.2 · CWE-440: a PAC using a construct the evaluator refuses still gets its default, gateways, DIRECT conditions and gateway findings, and is never run."""
    import log_analyzer as la
    import pac_eval
    text, default, bypasses, titles = PAC_CASES[construct]
    assert pac_eval.inspect(text)["ok"] is False, "the evaluator refuses this construct (precondition)"
    out = la.analyze_pac("proxy.pac", text)
    s = out["summary"]
    got_titles = {f["title"] for f in out["findings"]}
    assert s["default"] == default and s["returns"] >= 2 and s["gateways"]
    assert bypasses <= {(b["kind"], b["value"]) for b in s["bypasses"]}
    assert titles <= got_titles
    assert "The PAC could not be evaluated safely" in got_titles, "the reader still says the answers were not evaluated"
    assert s["evaluation"]["ok"] is False and s["evaluation"]["samples"] == []


def test_an_evaluable_pac_is_read_by_the_evaluator_alone():
    """SSDF PW.8.2 · CWE-440: a PAC the evaluator understands is not read from its text (no commented-out return becomes a bypass)."""
    import log_analyzer as la
    text = '''function FindProxyForURL(url, host) {
  // if (shExpMatch(host, "*.dropbox.com")) return "DIRECT";
  if (isPlainHostName(host)) return "DIRECT";
  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";
}'''
    s = la.analyze_pac("proxy.pac", text)["summary"]
    assert s["evaluation"]["ok"] is True and s["default"] == "proxy"
    assert {(b["kind"], b["value"]) for b in s["bypasses"]} == {("plain host names", "single-label names (intranet)")}


# ── The browser extension's calls, in the order its side panel makes them ──

def test_the_extension_side_panel_journey_reads_and_exports_from_its_origin(monkeypatch):
    """ASVS V14.5.3 · A01:2021 · CWE-440: from the extension's origin, ping, profiles, console index, notes and an export job with its download still answer what the panel reads."""
    import pack_jobs
    from test_pack_export import ALL_DLP_IN_SCOPE, ReadOnly, _source
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    ro = ReadOnly(_source())
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ro)
    app = TestClient(srv.app)
    made = app.post("/api/tenant-profiles", json=dict(CREDS, name="Acme", remember_secret=True, scopes=ALL_DLP_IN_SCOPE["scopes"],
                                                      channels=ALL_DLP_IN_SCOPE["channels"]))
    assert made.status_code == 200, made.text
    ext = TestClient(srv.app, headers={"Origin": security.extension_origin()})
    assert ext.get("/api/ping").status_code == 200
    profiles = ext.get("/api/tenant-profiles").json()["profiles"]
    pid = profiles[0]["id"]
    assert profiles[0]["name"] == "Acme"
    idx = ext.post("/api/console-index", json={"profile_id": pid, "refresh": False})
    assert idx.status_code == 200, idx.text
    idx = idx.json()
    assert {"counts", "kinds", "objects", "tenant_label"} <= set(idx) and idx["counts"]["rule"] > 0
    assert idx.get("cached_at") or idx.get("read_at")
    rule = next(o for o in idx["objects"] if o["kind"] == "rule")
    notes = ext.get("/api/workspace/notes", params={"tenant": idx["tenant_label"], "kind": "rule", "ref": rule["name"]})
    assert notes.status_code == 200 and "note" in notes.json(), "the panel reads d.note"
    start = ext.post("/api/dlp-packs/export/start", json={"profile_id": pid, "parts": ["rules"], "dictionaries": [], "engines": [],
                                                          "rules": {}, "include_dependencies": True, "format": "json",
                                                          "pack_name": "Console selection"})
    assert start.status_code == 200, start.text
    job = pack_jobs.get(start.json()["job_id"])
    job.thread.join(60)
    snap = ext.get(f"/api/dlp-packs/jobs/{job.id}?since=0").json()
    assert snap["status"] != "running" and snap["result"]["status"] == "ready" and snap["download"], snap
    assert isinstance(snap["logs"], list) and isinstance(snap["next"], int)
    z = ext.get(snap["download"])
    assert z.status_code == 200 and z.headers["content-type"].startswith("application/zip")
    assert 'filename="' in z.headers["content-disposition"]
    assert ro.writes == []


# ── Credential resolution: the cloud a request names is the cloud it gets ──
# _tenant_creds now fills a cloud the body did not send from the profile,
# the environment or tenant_config.json (Wave 5). Every caller that names a
# cloud, and every caller with no source naming one, must get exactly what
# it got before. Table-driven over every request model with sign-in fields.

def _cred_models():
    from pydantic import BaseModel
    out = []
    for name, cls in sorted(vars(srv).items()):
        if isinstance(cls, type) and issubclass(cls, BaseModel) and cls is not BaseModel and {"cloud", "vanity_domain", "client_id"} <= set(cls.model_fields):
            try:
                cls()
            except Exception:  # noqa: BLE001 — a model with a required field is built by its own route's tests
                continue
            out.append(name)
    return out


CRED_MODELS = _cred_models()


@pytest.fixture
def every_source(monkeypatch, tmp_path):
    """A saved profile, the environment and tenant_config.json, each naming a different cloud."""
    import tenant_profiles
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    tenant_profiles.upsert({"name": "p1", "vanity_domain": "prof", "client_id": "cid-prof", "auth_method": "oneapi", "cloud": "zscloud"},
                           client_secret="prof-secret-not-real", remember_secret=True, profile_id="p1")
    monkeypatch.setenv("ZSCALER_VANITY_DOMAIN", "envv")
    monkeypatch.setenv("ZSCALER_CLIENT_ID", "cid-env")
    monkeypatch.setenv("ZSCALER_CLIENT_SECRET", "env-secret-not-real")
    monkeypatch.setenv("ZSCALER_CLOUD", "zscalerthree")
    (tmp_path / "tenant_config.json").write_text(json.dumps({"vanity_domain": "cfgv", "client_id": "cid-cfg", "client_secret": "cfg-secret-not-real",
                                                             "cloud": "zscalerbeta"}), encoding="utf-8")
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    return tmp_path


def test_the_credential_table_covers_the_request_models():
    """SSDF PW.8.2 · CWE-440: the request models below include the assessment, migration, fixes and every tenant-credential body."""
    assert {"AssessRequest", "MigrateRequest", "RemediationExecuteRequest", "TenantCredsRequest", "ScopedTenantCredsRequest"} <= set(CRED_MODELS)


@pytest.mark.parametrize("model", CRED_MODELS)
@pytest.mark.parametrize("with_profile", [False, True])
def test_a_cloud_the_body_names_is_never_replaced(every_source, model, with_profile):
    """ASVS V4.2.1 · CWE-440: a request that names its cloud gets that cloud whatever the profile, environment or tenant_config.json name."""
    cls = getattr(srv, model)
    for identity in ({}, {"vanity_domain": "acme", "client_id": "cid-typed", "client_secret": "typed-secret-not-real"}):
        body = dict(identity, cloud="zscalertwo", **({"profile_id": "p1"} if with_profile and "profile_id" in cls.model_fields else {}))
        assert srv._tenant_creds(cls.model_validate(body))["cloud"] == "zscalertwo", (model, body)


@pytest.mark.parametrize("model", CRED_MODELS)
def test_with_no_source_naming_a_cloud_the_models_default_still_applies(monkeypatch, tmp_path, model):
    """ASVS V4.2.1 · CWE-440: with no profile and no environment or file naming a cloud, an unsent cloud is the model's default, as before."""
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    cls = getattr(srv, model)
    default = cls.model_fields["cloud"].default or ""
    creds = srv._tenant_creds(cls.model_validate({"vanity_domain": "acme", "client_id": "cid-typed", "client_secret": "typed-secret-not-real"}))
    assert creds["cloud"] == default and creds["vanity_domain"] == "acme" and creds["client_id"] == "cid-typed"


HELPER_PAC = '''function isCorp(h) { return dnsDomainIs(h, ".corp.example.com") || isPlainHostName(h); }
function isLoop(h) { return isLoop(h) || shExpMatch(h, "*.loop.example"); }
function FindProxyForURL(url, host) {
  if (isCorp(host)) return "DIRECT";
  if (isLoop(host)) return "DIRECT";
  if (!isCorp(host) && shExpMatch(host, "*.dropbox.com")) return "DIRECT";
  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";
}'''


def test_a_bypass_written_in_a_helper_function_is_still_listed():
    """SSDF PW.8.2 · CWE-440: a DIRECT condition written in a helper function (as the pre-Wave-5 reading listed it) is listed, a negated or recursive helper never loops or lies."""
    import log_analyzer as la
    s = la.analyze_pac("proxy.pac", HELPER_PAC)["summary"]
    assert s["evaluation"]["ok"] is True
    got = {(b["kind"], b["value"]) for b in s["bypasses"]}
    assert ("dnsDomainIs", ".corp.example.com") in got and ("plain host names", "single-label names (intranet)") in got
    assert ("shExpMatch", "*.loop.example") in got and ("shExpMatch", "*.dropbox.com") in got
