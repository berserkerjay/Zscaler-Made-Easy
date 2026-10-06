"""The SSL inspection flow and the Bypass report read only what is in scope
on the Scope page (user rule 1), like the Path analyzer and the Data Flow
Map: nothing in scope is refused before sign-in, and a part the Scope page
left out is not read and says "not in scope" (never "nothing here"). The
page sends the Scope page selection with every one of these reads.

No real tenant: a fake that records every request it answers."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import bypass_report
import dlp_api_server as srv
from test_path_scope_stop import Tenant

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
NOTHING = {"scopes": [], "channels": {"ssl_inspection": "alternative", "web_dlp": "alternative"}, "from_page": True}
ZCC_EPS = {"/zcc/webPolicies", "/zcc/forwardingProfiles", "/zcc/trustedNetworks", "/zcc/webAppService"}


def _t(monkeypatch):
    built, c = [], Tenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or c)
    return TestClient(srv.app), c, built


@pytest.mark.parametrize("ep", ["/api/report/ssl-flow", "/api/report/bypass", "/api/report/bypass/export"])
@pytest.mark.parametrize("sel", [NOTHING, {}], ids=["page-nothing", "no-selection"])
def test_nothing_in_scope_is_refused_before_sign_in(monkeypatch, ep, sel):
    t, c, built = _t(monkeypatch)
    r = t.post(ep, json=dict(CREDS, **sel))
    assert r.status_code == 400, r.text[:300]
    assert "in scope" in r.json()["detail"]
    assert not built and not c.requests, c.requests


def test_ssl_flow_needs_ssl_inspection_in_scope(monkeypatch):
    t, c, built = _t(monkeypatch)
    r = t.post("/api/report/ssl-flow", json=dict(CREDS, scopes=["dlp", "zcc"], channels={"email_dlp": "zscaler", "ssl_inspection": "alternative"},
                                                 from_page=True))
    assert r.status_code == 200 and built
    assert "/zia/sslInspectionRules" not in c.requests
    control = next(row for row in r.json()["required_controls"] if row["key"] == "ssl")
    assert control["status"] == "unverified" and control["read_permitted"] is False


def test_ssl_flow_reads_ssl_inspection_as_the_prerequisite_of_web_dlp(monkeypatch):
    # Inline Web DLP on Zscaler needs SSL inspection (channel_scope.PREREQUISITES),
    # so it is in scope when left unticked; explicit Alternative stays excluded.
    t, c, _built = _t(monkeypatch)
    for ssl in ("gap",):
        c.requests.clear()
        r = t.post("/api/report/ssl-flow", json=dict(CREDS, scopes=["dlp"], channels={"web_dlp": "zscaler", "ssl_inspection": ssl},
                                                     from_page=True))
        assert r.status_code == 200, r.text[:300]
        assert {"/zia/sslInspectionRules", "/zia/webDlpRules"} <= set(c.gets())


def test_ssl_flow_reads_no_web_dlp_or_client_connector_out_of_scope(monkeypatch):
    t, c, _built = _t(monkeypatch)
    r = t.post("/api/report/ssl-flow", json=dict(CREDS, scopes=["zia_extras"], channels={"ssl_inspection": "zscaler", "web_dlp": "alternative"},
                                                 from_page=True))
    assert r.status_code == 200, r.text[:300]
    gets = set(c.gets())
    assert "/zia/sslInspectionRules" in gets
    assert "/zia/webDlpRules" not in gets and not (gets & ZCC_EPS), sorted(gets)
    rep = r.json()
    assert set(rep["not_in_scope"]) == {"dlp", "zcc"} and rep["zcc"]["not_in_scope"]
    assert rep["summary"]["dlp_covered"] is None and rep["dlp_rules"] == []
    assert not any(g["type"] in ("ungoverned", "monitor_only", "metadata_only") for g in rep["gaps"]), rep["gaps"]
    assert all(cl["dlp_status"] in ("blind", "blocked", "not_in_scope") for cl in rep["classes"])
    assert not any("No inline DLP rule targets it" in g["detail"] for g in rep["gaps"])
    assert not [d for d in rep["diagnostics"] if "Client Connector" in d["section"]], "not in scope is not 'could not read'"


def test_ssl_flow_with_everything_in_scope_reads_it_all(monkeypatch):
    t, c, _built = _t(monkeypatch)
    r = t.post("/api/report/ssl-flow", json=dict(CREDS, scopes=["dlp", "zcc"], channels={"ssl_inspection": "zscaler", "web_dlp": "zscaler"},
                                                 from_page=True))
    assert r.status_code == 200, r.text[:300]
    gets = set(c.gets())
    assert {"/zia/sslInspectionRules", "/zia/webDlpRules", "/zcc/webPolicies"} <= gets
    assert r.json()["not_in_scope"] == {}


def test_bypass_reads_only_the_sections_in_scope(monkeypatch):
    t, c, _built = _t(monkeypatch)
    r = t.post("/api/report/bypass", json=dict(CREDS, scopes=["zcc"], channels={}, from_page=True))
    assert r.status_code == 200, r.text[:300]
    gets = set(c.gets())
    assert gets and gets <= ZCC_EPS, sorted(gets)
    rep = r.json()
    for key in ("ssl_bypass_rules", "ssl_exemptions", "url_filter_allow", "firewall_allow", "dlp_allow"):
        assert rep["sections"][key]["not_in_scope"] and rep["sections"][key]["count"] == 0, key
        assert key in rep["not_in_scope"]
    assert "zcc" not in rep["not_in_scope"]


def test_bypass_firewall_rules_come_with_the_zia_platform_scope_only(monkeypatch):
    t, c, _built = _t(monkeypatch)
    r = t.post("/api/report/bypass", json=dict(CREDS, scopes=["dlp"], channels={"web_dlp": "zscaler"}, from_page=True))
    assert r.status_code == 200
    gets = set(c.gets())
    assert "/zia/webDlpRules" in gets and "/zia/urlFilteringRules" in gets
    # SSL inspection comes with Inline Web DLP as its prerequisite; the firewall rules do not.
    assert "/zia/sslInspectionRules" in gets
    assert "/zia/firewallFilteringRules" not in gets and not (gets & ZCC_EPS), sorted(gets)
    c.requests.clear()
    r = t.post("/api/report/bypass", json=dict(CREDS, scopes=["zia_extras"], channels={}, from_page=True))
    assert r.status_code == 200 and "/zia/firewallFilteringRules" in set(c.gets())


def test_bypass_scope_is_pure_and_says_why():
    sel = bypass_report.bypass_scope(["dlp"], {"email_dlp": "zscaler", "ssl_inspection": "alternative"})
    assert set(sel["read"]) == {"url"}
    assert "alternative" in sel["read_blocked"]["ssl"].lower() and "ZIA platform" in sel["not_in_scope"]["firewall"]
    # Inline Web DLP on Zscaler brings SSL inspection in as its prerequisite.
    assert set(bypass_report.bypass_scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "gap"})["read"]) == {"url", "dlp", "ssl"}
    assert set(bypass_report.bypass_scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "alternative"})["read"]) == {"url", "dlp"}
    assert bypass_report.bypass_scope([], {})["read"] == []


def test_the_page_sends_the_scope_page_selection_with_each_report_read():
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    for start, end in (("window.__bypassGenerate = async function", "};"), ("window.__sslFlowGenerate = async function", "};"),
                       ("async function runBypassReport()", "\n}\n"), ("async function exportBypass(fmt)", "\n}\n")):
        i = html.index(start)
        block = html[i:html.index(end, i)]
        assert "scopePageSelection()" in block, start
