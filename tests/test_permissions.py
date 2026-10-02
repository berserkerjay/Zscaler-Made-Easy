"""A client that lacks a permission runs what it can: the plan is built
from what could be listed, the assessment reports the checks it could not
run and what a full scan needs."""
from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

import dlp_api_server as srv
import pack_deploy as pd
import permissions as perm
from dlp_assessment_full_auto import R
from test_pack_channels import add_control_services, make_client


def _pack(pid):
    from dlp_importer import discover_packs
    p = next(p for p in discover_packs() if p["id"] == pid)
    return {"id": p["id"], "dir": p["dir"]}


def test_preflight_plans_what_it_can_when_dictionaries_cannot_be_listed():
    client = add_control_services(make_client())
    client.zia.dlp_dictionary.fail = True
    snap = pd.fetch_tenant(client)
    assert snap["reachable"] and list(snap["unreadable"]) == ["dictionaries"] and snap["errors"]
    rep = pd.preflight(client, [_pack("zbp_source_code_baseline")], writes_enabled=True)
    assert rep["status"] == "warnings", rep["blockers"]
    assert rep["blockers"] == [] and rep["plan_hash"]
    assert any("Could not list the tenant's dictionaries" in w and "DLP Dictionaries" in w for w in rep["warnings"])
    dicts = [i for i in rep["items"] if i["kind"] == "dictionary"]
    customs = [i for i in dicts if (i.get("detail") or {}).get("type") != "clone"]
    clones = [i for i in dicts if (i.get("detail") or {}).get("type") == "clone"]
    assert customs and all(i["status"] == pd.CREATE for i in customs)
    assert all(any(w.startswith("unverified") for w in i.get("warnings", [])) for i in customs)
    # A clone needs its template's id, which an unreadable listing cannot give: blocked, and
    # the engine that uses it is created without that term (the plan names it).
    assert clones and all(i["status"] == pd.BLOCKED_DEPENDENCY for i in clones)
    engines = [i for i in rep["items"] if i["kind"] == "engine"]
    assert engines and all(i["status"] == pd.CREATE for i in engines)
    assert not any(any(w.startswith("unverified") for w in i.get("warnings", [])) for i in engines)


def test_only_a_fully_unreadable_tenant_blocks_the_plan(monkeypatch):
    client = add_control_services(make_client())
    client.zia.dlp_dictionary.fail = True
    monkeypatch.setattr(client.zia.dlp_engine, "list_dlp_engines", lambda: (None, "boom"))
    monkeypatch.setattr(client.zia.dlp_web_rules, "list_rules", lambda: (None, "boom"))
    snap = pd.fetch_tenant(client)
    assert not snap["reachable"] and len(snap["unreadable"]) == 3
    rep = pd.preflight(client, [_pack("zbp_source_code_baseline")], writes_enabled=True)
    assert rep["status"] == "blocked" and "Could not read the tenant" in rep["blockers"][0]


def test_permission_helpers_name_the_permission():
    assert perm.permission_for_endpoint("/zia/dlpDictionaries")["permission"] == "DLP Dictionaries"
    assert perm.permission_for_endpoint("/zcc/webPolicies")["product"] == "Client Connector"
    assert perm.is_denied("Access denied. The API client role does not include this feature.")
    assert perm.is_denied("API credentials lack permission for this resource.") and not perm.is_denied("3 IPS rule(s).")
    assert perm.scope_of_section("ZIA — Firewall") == "zia_extras" and perm.scope_of_section("4 — SSL Policy") == "dlp"
    w = perm.write_permissions_needed(["dictionary", "web", "web"])
    assert [x["permission"] for x in w] == ["DLP Dictionaries (Full)", "Web DLP Rules (Full)"]
    results = [{"id": "FW.1", "section": "ZIA — Firewall", "label": "Rules", "status": "INFO", "detail": "Rules: Not configured or not accessible. Access denied. The API client role does not include this feature."},
               {"id": "4.1", "section": "4 — SSL Policy", "label": "Decrypt", "status": "PASS", "detail": "ok"},
               {"id": "5.1", "section": "5 — Endpoint DLP", "label": "Endpoint", "status": "INFO", "detail": "Endpoint: Not configured or not accessible. This feature is not available on your tenant or is not licensed."}]
    s = perm.assessment_permission_summary(results, ["dlp", "zia_extras"])
    assert s["blocked"] == 1 and s["checks"][0]["id"] == "FW.1" and s["by_scope"] == {"zia_extras": 1}
    need = {n["scope"]: n for n in s["needed_for_full_scan"]}
    assert need["zia_extras"]["blocked_checks"] == 1 and "Firewall" in " ".join(need["zia_extras"]["permissions"]) or need["zia_extras"]["permissions"]
    assert need["dlp"]["blocked_checks"] == 0


class _FakeClient:
    def __init__(self, *a, **k): self.requests_made = 0
    def auth(self): return True


def test_assessment_reports_the_partial_scan(monkeypatch):
    def ok(client): return R(R.PASS, "fine")
    def denied(client): return R(R.INFO, "Firewall: Not configured or not accessible. Access denied. The API client role does not include this feature.")
    checks = [("FW.1", "ZIA — Firewall", "Firewall rules", denied), ("4.1", "4 — SSL Policy", "Decrypt", ok)]
    monkeypatch.setattr(srv, "Client", _FakeClient)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: checks)
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [])
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "scopes": ["dlp", "zia_extras"]}
    complete = None
    with c.stream("POST", "/api/assess", json=body) as r:
        for line in r.iter_lines():
            if line.startswith("data: "):
                d = json.loads(line[6:])
                if "score" in d:
                    complete = d
    assert complete and complete["permissions"]["blocked"] == 1
    assert complete["permissions"]["checks"][0]["id"] == "FW.1"
    assert any(n["scope"] == "zia_extras" and n["blocked_checks"] == 1 for n in complete["permissions"]["needed_for_full_scan"])
    page = c.get("/").text
    assert 'id="permissionsCard"' in page and "renderPermissions(data)" in page
    req = c.get("/api/permissions/required").json()
    assert req["write_permissions"] and req["write_permissions"][0]["permission"].endswith("(Full)") and "partial_note" in req
