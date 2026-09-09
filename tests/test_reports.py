"""Reports open in their own tab: the server keeps generated reports in
memory, serves them by id, exports from the cache, and serves the page."""
from __future__ import annotations

from fastapi.testclient import TestClient

import dlp_api_server as srv

SAMPLE = {"summary": {"total_bypass_items": 2, "ssl_bypass_rules": 2}, "risk_flags": [], "sections": {
    "ssl_bypass_rules": {"count": 2, "items": [{"id": 1, "name": "A", "action": "DO_NOT_DECRYPT", "state": "ENABLED", "scope": "global"}]}},
    "aggregated": {}, "guidance": ["x"]}


def test_report_cache_page_and_exports():
    c = TestClient(srv.app)
    rid = srv._remember_report("bypass", SAMPLE, "acme (production)")
    assert rid.startswith("bypass-")
    r = c.get(f"/api/report/bypass/{rid}")
    assert r.status_code == 200 and r.json()["tenant_label"] == "acme (production)" and r.json()["report_id"] == rid
    assert c.get("/api/report/bypass/nope").status_code == 404
    page = c.get("/report/bypass?id=" + rid)
    assert page.status_code == 200 and "Back to the assessment" in page.text and "/static/bypass_report.js" in page.text
    csv = c.get(f"/api/report/bypass/export/{rid}?format=csv")
    assert csv.status_code == 200 and "attachment" in csv.headers["content-disposition"]
    js = c.get(f"/api/report/bypass/export/{rid}?format=json")
    assert js.status_code == 200 and js.json()["report_id"] == rid
    assert c.get(f"/api/report/bypass/export/{rid}?format=pdf").status_code == 400
    assert c.get("/api/report/bypass/export/nope?format=csv").status_code == 404
    # The cache is bounded.
    for i in range(srv._REPORTS_MAX + 5):
        srv._remember_report("bypass", SAMPLE)
    assert len(srv._REPORTS) == srv._REPORTS_MAX


def test_index_loads_report_addons():
    c = TestClient(srv.app)
    html = c.get("/").text
    assert '<link rel="stylesheet" href="/static/reports.css?v=' in html
    assert '<script src="/static/bypass_report.js?v=' in html
    st = c.get("/static/guide.js")
    assert st.status_code == 200 and "no-cache" in st.headers.get("cache-control", "")
    assert "openBypassReportTab()" in html and "openToolTab('updates')" in html and "openToolTab('efficacy')" in html
    view = c.get("/report/view?tool=updates")
    assert view.status_code == 200 and "Back to the assessment" in view.text and "__ttApply" in view.text
    assert c.get("/static/tool_tabs.js").status_code == 200
    assert c.get("/static/bypass_report.js").status_code == 200 and c.get("/static/reports.css").status_code == 200


def test_terraform_summary_endpoint():
    c = TestClient(srv.app)
    r = c.get("/api/dlp-packs/healthcare_phi_baseline/terraform")
    assert r.status_code == 200
    d = r.json()
    assert d["committed"] is True and d["path"] == "terraform/healthcare_phi_baseline/"
    names = [f["name"] for f in d["files"]]
    assert "rules.tf" in names and "README.md" in names and all(f["purpose"] for f in d["files"] if f["name"].endswith(".tf"))
    assert d["counts"]["rules"] >= 9 and d["counts"]["channels"].get("email") == 1 and d["provider"] == "zscaler/zia"
    assert c.get("/api/dlp-packs/nope/terraform").status_code == 404
    html = c.get("/").text
    assert "openToolTab('terraform')" in html and "Terraform hand-off" in html
