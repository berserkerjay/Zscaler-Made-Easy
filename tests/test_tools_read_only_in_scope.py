"""
User rule 1: a run reads only the in-scope portion selected on the Scope
page. Deploy Studio's rule picker (removal inventory), Export from tenant,
DLP efficacy (score, export, corpus test), the ZCC endpoint diagnostics
and every Evaluate All Rules migration step take the Scope page selection,
read only what it puts in scope, and refuse (400, before sign-in) when
nothing they read is in scope (F2-3, F2-4, UR2-2).
"""
from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
from test_path_scope_stop import Tenant
from test_zia_contract import strict_tenant

ROOT = os.path.join(os.path.dirname(__file__), "..")
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
WEB_ONLY = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "endpoint_dlp": "alternative", "saas_casb": "alternative",
                                            "email_dlp": "alternative"}, "from_page": True}
NOTHING = {"scopes": [], "channels": {"web_dlp": "alternative", "endpoint_dlp": "alternative"}, "from_page": True}
DLP_NOT_WEB = {"scopes": ["dlp"], "channels": {"web_dlp": "alternative", "endpoint_dlp": "zscaler"}, "from_page": True}


def _spy(tenant):
    calls = []
    z = tenant.zia
    for svc in ("dlp_web_rules", "endpoint_dlp_rules", "casb_dlp_rules", "outbound_email_dlp_rules", "saas_security_api",
                "casb_tenant", "cloud_applications"):
        obj = getattr(z, svc, None)
        if obj is None:
            continue
        for name in dir(obj):
            if name.startswith("list"):
                fn = getattr(obj, name)

                def wrap(*a, _fn=fn, _n=f"{svc}.{name}", **k):
                    calls.append(_n)
                    return _fn(*a, **k)
                setattr(obj, name, wrap)
    return calls


# --- Deploy Studio: the rule picker and Export from tenant (F2-3) -------------------

def test_the_rule_picker_reads_only_the_dlp_channels_in_scope(monkeypatch):
    tenant = strict_tenant()
    calls = _spy(tenant)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: tenant)
    r = TestClient(srv.app).post("/api/dlp-packs/removal/inventory", json=dict(CREDS, **WEB_ONLY))
    assert r.status_code == 200, r.text
    assert calls and not [x for x in calls if not x.startswith("dlp_web_rules")], calls
    assert {x["channel"] for x in r.json()["rules"]} <= {"web"} and r.json()["channels_in_scope"] == ["web"]


def test_export_from_tenant_reads_only_the_dlp_channels_in_scope(monkeypatch):
    tenant = strict_tenant()
    calls = _spy(tenant)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: tenant)
    c = TestClient(srv.app)
    r = c.post("/api/dlp-packs/export/start", json=dict(CREDS, pack_name="x", **WEB_ONLY))
    assert r.status_code == 200, r.text
    jid = r.json()["job_id"]
    for _ in range(400):
        if c.get(f"/api/dlp-packs/jobs/{jid}").json()["status"] != "running":
            break
        time.sleep(0.05)
    assert calls and not [x for x in calls if not x.startswith("dlp_web_rules")], calls


@pytest.mark.parametrize("path,extra", [
    ("/api/dlp-packs/removal/inventory", {}),
    ("/api/dlp-packs/export/start", {"pack_name": "x"}),
    ("/api/dlp-packs/export/start", {"rules": {"email": "all"}, **WEB_ONLY}),   # a channel out of scope, picked by name
])
@pytest.mark.parametrize("scope", [NOTHING, {}], ids=["nothing-ticked", "nothing-sent"])
def test_deploy_studio_refuses_before_sign_in_when_nothing_is_in_scope(monkeypatch, path, extra, scope):
    def no_sign_in(*a, **k):
        raise AssertionError("signed in to the tenant with nothing in scope")
    monkeypatch.setattr(srv, "_build_sdk_client", no_sign_in)
    body = dict(CREDS, **scope)
    body.update(extra)
    r = TestClient(srv.app).post(path, json=body)
    assert r.status_code == 400 and "scope" in r.json()["detail"].lower(), r.text


# --- DLP efficacy, ZCC diagnostics, the migration wizard (F2-4, UR2-2) ---------------

def _tenant(monkeypatch):
    built, t = [], Tenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or t)
    return TestClient(srv.app), t, built


@pytest.mark.parametrize("path,extra", [
    ("/api/diagnose/zcc", {}),
    ("/api/dlp/efficacy", {}),
    ("/api/dlp/efficacy/export", {"format": "json"}),
    ("/api/dlp/efficacy/test", {"corpus": "4111 1111 1111 1111"}),
    ("/api/migrate/status", {}),
    ("/api/migrate/status/manual", {"mode": "rule_order"}),
    ("/api/migrate/fetch", {}),
    ("/api/migrate/enable", {"dry_run": True}),
    ("/api/migrate/delete-all", {"dry_run": True}),
    ("/api/migrate/post", {"dry_run": True, "proposed_rules": [{"name": "r"}]}),
])
@pytest.mark.parametrize("scope", [NOTHING, {}], ids=["nothing-ticked", "nothing-sent"])
def test_nothing_in_scope_is_refused_before_sign_in(monkeypatch, path, extra, scope):
    t, tenant, built = _tenant(monkeypatch)
    r = t.post(path, json=dict(CREDS, **scope, **extra))
    assert r.status_code == 400 and "not in scope" in r.json()["detail"], r.text
    assert not built and not tenant.requests


@pytest.mark.parametrize("path,extra", [
    ("/api/migrate/status", {}), ("/api/migrate/fetch", {}), ("/api/migrate/enable", {"dry_run": True}),
])
def test_the_migration_needs_inline_web_dlp_on_zscaler(monkeypatch, path, extra):
    t, tenant, built = _tenant(monkeypatch)
    r = t.post(path, json=dict(CREDS, **DLP_NOT_WEB, **extra))
    assert r.status_code == 400 and "Inline Web DLP" in r.json()["detail"], r.text
    assert not built


def test_zcc_diagnostics_run_when_zcc_is_ticked(monkeypatch):
    t, tenant, built = _tenant(monkeypatch)
    r = t.post("/api/diagnose/zcc", json=dict(CREDS, scopes=["zcc"], channels={}, from_page=True))
    assert r.status_code == 200 and built


@pytest.mark.parametrize("path,extra", [("/api/dlp/efficacy", {}), ("/api/dlp/efficacy/test", {"corpus": "4111 1111 1111 1111"})])
def test_efficacy_reads_the_web_dlp_rules_only_when_inline_web_dlp_is_on_zscaler(monkeypatch, path, extra):
    paths = []

    class C:
        def get(self, p, *a, **k):
            paths.append(p)
            return [], 200
    monkeypatch.setattr(srv, "_build_client", lambda req: C())
    t = TestClient(srv.app)
    r = t.post(path, json=dict(CREDS, **DLP_NOT_WEB, **extra))
    assert r.status_code == 200, r.text
    assert "/zia/webDlpRules" not in paths and "/zia/dlpDictionaries" in paths, paths
    if path == "/api/dlp/efficacy":
        d = r.json()
        assert d["rules_read"] is False and d["counts"]["rules"] is None and d["orphans"]["engines_unused_by_rules"] is None
        assert "Not in scope" in d["rules_not_in_scope"]
    paths.clear()
    r = t.post(path, json=dict(CREDS, **WEB_ONLY, **extra))
    assert r.status_code == 200 and "/zia/webDlpRules" in paths, paths


def test_efficacy_without_the_rules_reports_no_orphan_by_rule():
    import dlp_efficacy as de

    class C:
        def get(self, p, *a, **k):
            if p == "/zia/dlpDictionaries":
                return [{"id": 1, "name": "Mine", "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES",
                         "patterns": [{"pattern": "\\bACME-\\d{6}\\b"}]}], 200
            if p == "/zia/dlpEngines":
                return [{"id": 9, "name": "Eng", "customDlpEngine": True, "engineExpression": "((D1.S > 1))"}], 200
            raise AssertionError(f"read {p}")
    a = de.analyze(C(), read_rules=False)
    assert all(x.get("orphan_rule") is None for x in a["dictionaries"] + a["engines"])
    assert not any("rule" in r.lower() and "not referenced" in r.lower() for x in a["engines"] for r in x.get("reasons", []))


def test_the_pages_send_the_scope_page_selection():
    index = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    studio = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    for url in ("/api/dlp/efficacy'", "/api/dlp/efficacy/export'", "/api/dlp/efficacy/test'", "/api/diagnose/zcc'",
                "/api/migrate/status'", "/api/migrate/status/manual'", "/api/migrate/fetch'", "/api/migrate/enable'",
                "/api/migrate/delete-all'", "/api/migrate/post'", "/api/dlp-packs/export/start'"):
        i = index.index(url)
        assert "scopePageSelection()" in index[i:i + 260], url
    assert studio.count("..._dzScope()") == 3
