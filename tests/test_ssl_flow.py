"""SSL Inspection Flow: which SSL rule decides per traffic class, what
inline Web DLP can see, and the gaps in between."""
from __future__ import annotations

from fastapi.testclient import TestClient

import dlp_api_server as srv
import ssl_flow as sf

SSL = [
    {"id": 1, "name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 2, "name": "Exec bypass", "order": 2, "state": "ENABLED", "groups": [{"id": 9, "name": "Execs"}], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 3, "name": "Privacy DNI", "order": 3, "state": "ENABLED", "url_categories": ["FINANCE", "HEALTH"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 4, "name": "DNI file hosts", "order": 4, "state": "ENABLED", "url_categories": ["FILE_HOST"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 5, "name": "Decrypt AI", "order": 5, "state": "ENABLED", "cloud_applications": ["CHATGPT_AI"], "action": {"type": "DECRYPT"}},
    {"id": 6, "name": "Decrypt file hosts", "order": 6, "state": "ENABLED", "url_categories": ["FILE_HOST"], "action": {"type": "DECRYPT"}},
    {"id": 7, "name": "Block anonymizers", "order": 7, "state": "ENABLED", "url_categories": ["ANONYMIZER"], "action": {"type": "BLOCK"}},
    {"id": 8, "name": "Decrypt webmail (off)", "order": 8, "state": "DISABLED", "url_categories": ["WEB_MAIL"], "action": {"type": "DECRYPT"}},
    {"id": 9, "name": "Default SSL Inspection Rule", "order": 99, "state": "ENABLED", "default_rule": True, "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}},
]
DLP = [
    {"id": 10, "name": "Monitor PII everywhere", "order": 1, "state": "ENABLED", "action": "ALLOW", "dlp_engines": [{"id": 1, "name": "PII"}]},
    {"id": 11, "name": "Block SSN to file hosts", "order": 2, "state": "ENABLED", "action": "BLOCK", "url_categories": ["FILE_HOST"], "dlp_engines": [{"id": 2}]},
    {"id": 12, "name": "Block code to AI", "order": 3, "state": "ENABLED", "action": "BLOCK", "cloud_applications": ["CHATGPT_AI", "GEMINI"], "dlp_engines": [{"id": 3}]},
]
CATALOGUE = {"AI_ML": ["CHATGPT_AI", "GEMINI", "CLAUDE"], "FILE_SHARE": ["DROPBOX", "BOX"]}


def _by_key(rep):
    return {c["key"]: c for c in rep["classes"]}


def test_first_match_decides_and_shadowed_decrypt_is_a_gap():
    rep = sf.analyse(SSL, DLP, CATALOGUE, {})
    c = _by_key(rep)
    fs = c["file_share"]
    assert fs["decision"] == "not_inspected" and fs["decided_by"]["name"] == "DNI file hosts"
    assert [r["name"] for r in fs["shadowed"]] == ["Decrypt file hosts"]
    types = {g["type"]: g["severity"] for g in fs["gaps"]}
    assert types == {"blind_spot": "high", "shadowed": "high"}
    # The two DLP rules that target file hosts are listed but blind.
    assert [r["name"] for r in fs["dlp_rules"]] == ["Monitor PII everywhere", "Block SSN to file hosts"] and fs["dlp_status"] == "blind"
    blind = next(g for g in fs["gaps"] if g["type"] == "blind_spot")
    assert "never see the HTTPS content" in blind["detail"] and "Block SSN to file hosts" in blind["detail"]


def test_decrypted_class_with_enforcing_dlp_and_scoped_exemption():
    rep = sf.analyse(SSL, DLP, CATALOGUE, {})
    ai = _by_key(rep)["ai_ml"]
    assert ai["decision"] == "inspected" and ai["decided_by"]["name"] == "Decrypt AI"
    assert ai["dlp_status"] == "enforcing" and "Block code to AI" in [r["name"] for r in ai["dlp_rules"]]
    assert [e["name"] for e in ai["exceptions"]] == ["Exec bypass"]
    assert [g["type"] for g in ai["gaps"]] == ["partial_exemption"]
    # Catalogue resolved the class to its applications.
    assert ai["application_count"] == 3 and "CLAUDE" in ai["applications"]


def test_predefined_exemptions_are_not_catch_all_but_default_rule_is():
    rep = sf.analyse(SSL, DLP, CATALOGUE, {})
    rules = {r["name"]: r for r in rep["ssl_rules"]}
    zre = rules["Zscaler Recommended Exemptions"]
    assert zre["zscaler_maintained"] and not zre["catch_all"]
    assert [r["name"] for r in rep["zscaler_exemptions"]] == ["Zscaler Recommended Exemptions"]
    dflt = rules["Default SSL Inspection Rule"]
    assert dflt["catch_all"] and dflt["default_rule"]
    gen = _by_key(rep)["general"]
    assert gen["decision"] == "not_inspected" and gen["decided_by"]["default_rule"]
    assert gen["gaps"][0]["type"] == "blind_spot"
    # The default rule sorts last whatever its order.
    assert rep["ssl_rules"][-1]["name"] == "Default SSL Inspection Rule"


def test_blocked_privacy_and_disabled_decrypt():
    rep = sf.analyse(SSL, DLP, CATALOGUE, {})
    c = _by_key(rep)
    assert c["remote"]["decision"] == "blocked" and c["remote"]["gaps"] == [] and c["remote"]["dlp_status"] == "blocked"
    assert c["privacy"]["decision"] == "not_inspected" and [g["type"] for g in c["privacy"]["gaps"]] == ["privacy_exemption"]
    assert c["privacy"]["gaps"][0]["severity"] == "info"
    wm = c["webmail"]
    assert {g["type"] for g in wm["gaps"]} == {"blind_spot", "disabled_decrypt"}
    assert wm["disabled_decrypt"][0]["name"] == "Decrypt webmail (off)"
    s = rep["summary"]
    assert s["inspected"] == 1 and s["blocked"] == 1 and s["not_inspected"] == 8 and s["high"] == 8
    assert rep["gaps"][0]["severity"] == "high" and rep["gaps"][-1]["severity"] == "info"


def test_catch_all_decrypt_then_ungoverned_and_monitor_only():
    ssl = [{"id": 1, "name": "Decrypt all", "order": 1, "state": "ENABLED", "action": {"type": "DECRYPT"}}]
    dlp = [{"id": 10, "name": "Monitor to file hosts", "order": 1, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["FILE_HOST"], "dlpEngines": [{"id": 1}]}]
    rep = sf.analyse(ssl, dlp, {}, {})
    c = _by_key(rep)
    assert all(x["decision"] == "inspected" for x in rep["classes"])
    assert c["file_share"]["dlp_status"] == "monitor" and [g["type"] for g in c["file_share"]["gaps"]] == ["monitor_only"]
    assert c["ai_ml"]["dlp_status"] == "none" and [g["type"] for g in c["ai_ml"]["gaps"]] == ["ungoverned"]
    assert c["general"]["dlp_status"] == "none"
    assert rep["summary"]["high"] == 0 and rep["summary"]["not_inspected"] == 0


def test_camel_case_rules_and_no_rules_at_all():
    ssl = [{"id": 1, "name": "DNI social", "order": 1, "state": "ENABLED", "urlCategories": [{"id": "SOCIAL_NETWORKING"}], "action": "DO_NOT_DECRYPT"}]
    rep = sf.analyse(ssl, [], {}, {"SOCIAL_NETWORKING": {"configured_name": "Social Networking"}, "FILE_HOST": {"configured_name": "File Host"}})
    c = _by_key(rep)
    assert c["social"]["decision"] == "not_inspected" and c["social"]["url_category_names"] == ["Social Networking"]
    assert c["file_share"]["decision"] == "no_rule" and c["file_share"]["gaps"][0]["type"] == "blind_spot"
    assert "no SSL rule matches" in c["file_share"]["gaps"][0]["detail"]
    # Category ids the tenant does not expose are dropped when the lookup knows the class.
    assert c["file_share"]["url_categories"] == ["FILE_HOST"]
    empty = sf.analyse([], [], {}, {})
    assert empty["summary"]["not_inspected"] == empty["summary"]["classes"] and empty["summary"]["inspected"] == 0


class _FakeApps:
    def __init__(self, by_class):
        self.by_class = by_class

    def list_cloud_app_policy(self, query_params=None):
        cls = (query_params or {}).get("app_class")
        return [{"app": a, "app_name": a.title()} for a in self.by_class.get(cls, [])], None, None


class FakeCl:
    def __init__(self, routes, apps=None):
        self.routes = routes
        if apps is not None:
            self._zs = type("Z", (), {})()
            self._zs.zia = type("ZIA", (), {})()
            self._zs.zia.cloud_applications = _FakeApps(apps)

    def get(self, endpoint, params=None):
        if endpoint in self.routes:
            return self.routes[endpoint], 200
        return {"error": "not found"}, 404


def test_generate_reads_tenant_and_records_diagnostics():
    cl = FakeCl({"/zia/sslInspectionRules": SSL, "/zia/webDlpRules": DLP,
                 "/zia/urlCategories": [{"id": "FILE_HOST", "configuredName": "File Host"}]}, apps=CATALOGUE)
    rep = sf.generate_ssl_flow_report(cl)
    assert rep["summary"]["ssl_rules"] == 9 and rep["summary"]["catalogue_classes"] == ["AI_ML", "FILE_SHARE"]
    assert rep["diagnostics"] == [] and rep["sources"]["ssl_rules"] == "/zia/sslInspectionRules"
    # Missing catalogue and a failing endpoint are diagnostics, not exceptions.
    cl2 = FakeCl({"/zia/sslInspectionRules": SSL})
    rep2 = sf.generate_ssl_flow_report(cl2)
    sections = {d["section"] for d in rep2["diagnostics"]}
    assert "Web DLP rules" in sections and "cloud application catalogue" in sections
    assert rep2["summary"]["dlp_rules"] == 0


def test_exports_and_endpoints():
    rep = sf.analyse(SSL, DLP, CATALOGUE, {})
    md = sf.to_markdown(rep)
    assert "| File sharing & cloud storage | not inspected | DNI file hosts |" in md and "## Gaps" in md and "[HIGH]" in md
    csv_text = sf.to_csv(rep)
    assert csv_text.startswith("class,decision,decided_by") and "Decrypt AI" in csv_text
    c = TestClient(srv.app)
    rid = srv._remember_report("sslflow", rep, "acme (production)")
    assert rid.startswith("sslflow-")
    r = c.get(f"/api/report/ssl-flow/{rid}")
    assert r.status_code == 200 and r.json()["tenant_label"] == "acme (production)" and r.json()["summary"]["high"] == 8
    assert c.get("/api/report/ssl-flow/nope").status_code == 404
    # A bypass report id is not served as an SSL flow report.
    other = srv._remember_report("bypass", {"summary": {}}, "x")
    assert c.get(f"/api/report/ssl-flow/{other}").status_code == 404
    page = c.get("/report/sslflow?id=" + rid)
    assert page.status_code == 200 and "Back to the assessment" in page.text and "/static/ssl_flow.js" in page.text and "sfRefresh" in page.text
    assert "no-cache" in page.headers.get("cache-control", "")
    for fmt, ctype in (("csv", "text/csv"), ("markdown", "text/markdown"), ("json", "application/json")):
        e = c.get(f"/api/report/ssl-flow/export/{rid}?format={fmt}")
        assert e.status_code == 200 and ctype in e.headers["content-type"] and "attachment" in e.headers["content-disposition"]
    assert c.get(f"/api/report/ssl-flow/export/{rid}?format=pdf").status_code == 400
    assert c.get("/static/ssl_flow.js").status_code == 200
    html = c.get("/").text
    assert "openSslFlowTab()" in html and "SSL Inspection Flow" in html and "__sslFlowGenerate" in html
