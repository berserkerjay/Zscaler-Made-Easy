"""Regulatory & Compliance Alignment in its own tab."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _c():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


CHECKS = [{"id": "4.1", "section": "4 — SSL Policy", "label": "Inspection scope", "status": "FAIL", "detail": "No SSL Inspect rules"},
          {"id": "5.3", "section": "5 — Endpoint DLP", "label": "Web DLP rules", "status": "PASS", "detail": "3 active"},
          {"id": "12.1", "section": "12 — Incident Mgmt", "label": "ICAP/IR deployed", "status": "REVIEW", "detail": "verify"}]


def test_compliance_report_is_remembered_and_served_in_its_own_tab():
    c = _c()
    r = c.post("/api/compliance/report", json={"checks": CHECKS, "metadata": {"org": "Acme", "assessor": "J"}, "frameworks": ["PCI_DSS", "HIPAA", "NOPE"]})
    assert r.status_code == 200, r.text
    rid = r.json()["report_id"]
    assert rid.startswith("compliance-")
    rep = c.get(f"/api/compliance/report/{rid}").json()
    assert rep["frameworks_selected"] == ["PCI_DSS", "HIPAA"] and rep["check_count"] == 3 and rep["tenant_label"] == "Acme"
    assert "PCI_DSS" in rep["summary"] and "controls" in rep["drilldown"]["PCI_DSS"] and rep["descriptions"]["PCI_DSS"].startswith("PCI-DSS")
    assert rep["metadata"] == {"org": "Acme", "assessor": "J"}
    md = c.get(f"/api/compliance/export/{rid}?format=markdown")
    assert md.status_code == 200 and "# Regulatory & Compliance Alignment — Acme" in md.text and "## PCI-DSS" in md.text
    csv = c.get(f"/api/compliance/export/{rid}?format=csv").text
    assert csv.startswith("framework,control,status") and "PCI-DSS" in csv
    assert c.get(f"/api/compliance/export/{rid}?format=json").headers["content-type"].startswith("application/json")
    assert c.get("/api/compliance/report/compliance-nope").status_code == 404
    assert c.post("/api/compliance/report", json={"checks": []}).status_code == 400
    page = c.get("/report/compliance?id=x").text
    assert 'id="cpScope"' in page and "/api/compliance/report/" in page and 'class="cp-card"' in page
    # The page itself is reachable without the UI token, like the other report tabs.
    assert TestClient(srv.app).get("/report/compliance").status_code == 200


def test_results_page_launches_the_tab_instead_of_an_inline_drilldown():
    html = _c().get("/").text
    assert "openComplianceTab(" in html and "/api/compliance/report" in html
    assert 'id="drilldownPanel"' not in html and "function renderControls" not in html
