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
    tabs = c.get("/static/tool_tabs.js")
    assert tabs.status_code == 200
    # The assessment results open in their own tab: progress card first, then the report, both kept on the page.
    assert "results:" in tabs.text and "panels: ['progressCard', 'results']" in tabs.text and "_openResultsPanel" in tabs.text
    assert "openToolTab('results', 'run')" in c.get("/static/guide.js").text
    assert "openToolTab('results', 'view')" in html and "Open in new tab" in html
    assert c.get("/static/bypass_report.js").status_code == 200 and c.get("/static/reports.css").status_code == 200


def test_report_tabs_share_the_app_stylesheet_and_theme():
    """Every report tab loads the assessment page's own stylesheet and the
    shared theme script, so it looks the same and follows the saved theme."""
    c = TestClient(srv.app)
    css = c.get("/app.css")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"] and "no-cache" in css.headers["cache-control"]
    assert "--bg: #0a0e1a" in css.text and "body.theme-light" in css.text and ".hero h1 .accent" in css.text and "<style>" not in css.text
    for path in ("/report/bypass?id=x", "/report/sslflow?id=x", "/report/view?tool=updates", "/report/flow", "/report/dataflow?id=x"):
        html = c.get(path).text
        assert '<link rel="stylesheet" href="/app.css">' in html, path
        assert '<script src="/static/report_theme.js"></script>' in html, path
        assert 'class="hero rp-hero"' in html and 'class="rp-btn" href="/"' in html, path
        assert "prefers-color-scheme" not in html, path
    theme = c.get("/static/report_theme.js")
    assert theme.status_code == 200 and "zassess_theme" in theme.text and "themeToggleBtn" in theme.text
    rcss = c.get("/static/reports.css").text
    assert "prefers-color-scheme" not in rcss and "body.theme-light" in rcss


def test_terraform_summary_endpoint():
    c = TestClient(srv.app)
    r = c.get("/api/dlp-packs/healthcare_phi_baseline/terraform")
    assert r.status_code == 200
    d = r.json()
    assert d["committed"] is True and d["path"] == "terraform/healthcare_phi_baseline/"
    names = [f["name"] for f in d["files"]]
    assert "rules.tf" in names and "README.md" in names and all(f["purpose"] for f in d["files"] if f["name"].endswith(".tf"))
    # Detection only, mirrored to every channel: one rule each on web,
    # endpoint, saas and email; no containment channels.
    assert d["counts"]["rules"] == 44 and d["provider"] == "zscaler/zia"   # 11 web rules and their endpoint, saas and email mirrors: equal counts per channel
    assert {k: v for k, v in d["counts"]["channels"].items()} == {"web": 11, "endpoint": 11, "saas": 11, "email": 11}
    assert not (set(d["counts"]["channels"]) & {"ssl", "cloud_app", "file_type", "url"})
    assert c.get("/api/dlp-packs/nope/terraform").status_code == 404
    html = c.get("/").text
    assert "openToolTab('terraform')" in html and "Terraform hand-off" in html


def test_deploy_flow_has_its_own_tab():
    """The Deploy Policy Packs dependency flow opens in /report/flow, which
    draws the diagram itself from the plan the assessment tab hands it."""
    c = TestClient(srv.app)
    html = c.get("/report/flow").text
    assert '<script src="/static/deploy_studio.js"></script>' in html
    assert '<link rel="stylesheet" href="/static/deploy_studio.css">' in html
    assert "window.__flowApply" in html and "zassess_flow_last" in html and 'id="flSide"' in html
    assert "no-cache" in c.get("/report/flow").headers.get("cache-control", "")
    js = c.get("/static/deploy_studio.js").text
    assert "function _dzFlowOpenTab" in js and "window.open('/report/flow'" in js
    assert "function _dzFlowSyncTab" in js and "window.__flowCurrent" in js
    assert "_dzFlowHtml(items, results, opts)" in js and "standalone" in js
    assert "DZ_FLOW.onTrace" in js
    css = c.get("/static/reports.css").text
    assert "body.flow-page .dz-flow-wrap" in css and ".fl-side" in css


def test_report_sections_open_by_default_and_compliance_never_hides():
    """Every card starts open, results re-open their sections on each run,
    and the compliance card shows every framework when none is ticked."""
    c = TestClient(srv.app)
    html = c.get("/").text
    assert "_setCardOpen(card, h, true);" in html and "function expandResultSections()" in html
    assert "expandResultSections();" in html
    assert "selectedFws = Array.from(document.querySelectorAll('.fw-cb')).map(cb => cb.value);" in html
    # The old early return that hid the card is gone.
    assert "if (selectedFws.length === 0) {\n    document.getElementById('complianceCard').style.display = 'none';\n    return;" not in html
