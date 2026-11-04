"""SSL coverage: the causes of uninspected traffic from configuration, their
risk and the recovery plan; the protocol-name table and the inspected
shares from Z-Insights (the SDK's own ZInsService against a fake request
executor); scope refusal before sign-in; no secrets; the Excel export; the
local run history; and the page's conventions."""
from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile
from types import SimpleNamespace

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient
from zscaler.zins.zins_service import ZInsService

import dlp_api_server as srv
import insights
import ssl_coverage as sc

ROOT = os.path.join(os.path.dirname(__file__), "..")
SECRET = "secret-secret-secret"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
IN_SCOPE = {"scopes": ["dlp", "zcc", "insights"], "channels": {"ssl_inspection": "zscaler"}, "from_page": True}
NO_INSIGHTS = {"scopes": ["dlp", "zcc"], "channels": {"ssl_inspection": "zscaler"}, "from_page": True}

SSL = [
    {"id": 1, "name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 2, "name": "Exec bypass", "order": 2, "state": "ENABLED", "groups": [{"id": 9, "name": "Execs"}], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 3, "name": "Privacy DNI", "order": 3, "state": "ENABLED", "url_categories": ["FINANCE", "HEALTH"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 4, "name": "DNI file hosts", "order": 4, "state": "ENABLED", "url_categories": ["FILE_HOST"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 5, "name": "DNI chat apps", "order": 5, "state": "ENABLED", "cloud_applications": ["ZOOM", "CHATGPT_AI"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 6, "name": "DNI social, skip all", "order": 6, "state": "ENABLED", "url_categories": ["SOCIAL_NETWORKING"],
     "action": {"type": "DO_NOT_DECRYPT", "doNotDecryptSubActions": {"bypassOtherPolicies": True}}},
    {"id": 7, "name": "Decrypt everything", "order": 7, "state": "ENABLED", "url_categories": ["ANY"], "action": {"type": "DECRYPT"}},
    {"id": 8, "name": "Old exemption (off)", "order": 8, "state": "DISABLED", "url_categories": ["WEB_MAIL"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 9, "name": "Default SSL Inspection Rule", "order": 99, "state": "ENABLED", "default_rule": True, "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}},
]
PROFILES = [{"id": 1, "name": "Default", "bypassApps": [{"name": "Zoom"}], "tunnelBypassDomains": ["*.dropbox.com", "intranet.corp"],
             "bypassIps": [{"ip": "10.0.0.0/8"}]}]
FORWARDING = [{"id": 7, "name": "Remote workers", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED", "actionType": "NONE"},
                                                                               {"networkType": "TRUSTED", "actionType": "TUNNEL"}]}]
PAC = [{"id": 5, "name": "Corp PAC", "pacContent": 'function FindProxyForURL(url, host) { if (shExpMatch(host, "*.wetransfer.com") || dnsDomainIs(host, ".local")) { return "DIRECT"; } return "PROXY ${ZAPP_LOCAL_PROXY}"; }'}]


class FakeCl:
    """The assessment client (`get(endpoint, params)` → (data, status)),
    recording every read."""

    def __init__(self, routes):
        self.routes = routes
        self.reads = []

    def get(self, endpoint, params=None):
        self.reads.append(endpoint)
        if endpoint in self.routes:
            return self.routes[endpoint], 200
        return {"error": "not found"}, 404

    def close(self):
        pass


def tenant_routes():
    return {"/zia/sslInspectionRules": SSL, "/zia/urlCategories": [{"id": "FILE_HOST", "configuredName": "File Host"}],
            "/zcc/webPolicies": PROFILES, "/zcc/forwardingProfiles": FORWARDING, "/zcc/trustedNetworks": [], "/zia/pacFiles": PAC}


# ── Z-Insights answers in the shape each SDK query asks for ─────────────
PROTOCOLS = {"TRANSACTIONS": [{"name": "HTTPS", "total": 600}, {"name": "SSL", "total": 200}, {"name": "HTTP", "total": 200},
                              {"name": "TUNNEL", "total": 30}, {"name": "QUIC_NEW", "total": 20}],
             "BYTES": [{"name": "HTTPS", "total": 9_000_000_000}, {"name": "Tunnel SSL", "total": 1_000_000_000}, {"name": "HTTP", "total": 0}]}
NOW = int(time.time() * 1000)


def _answers():
    return {
        "WebProtocols": lambda v: {"data": {"WEB_TRAFFIC": {"protocols": {"obfuscated": False, "entries": PROTOCOLS[v["trafficUnit"]]}}}},
        "WebTrafficNoGrouping": lambda v: {"data": {"WEB_TRAFFIC": {"no_grouping": {"obfuscated": False, "entries": [
            {"name": "TOTAL", "total": 3e9, "trend": {"trend_start_time": NOW - 3 * 86_400_000, "trend_interval": "DAY", "trend_values": [1e9, 1.5e9, 0.5e9]}}]}}}},
        "ShadowITApps": lambda v: {"data": {"SHADOW_IT": {"apps": {"entries": [
            {"application": "Dropbox", "application_category": "File sharing", "data_consumed": 4_000_000},
            {"application": "ChatGPT", "application_category": "AI", "data_consumed": 2_000_000},
            {"application": "Zoom", "application_category": "Collaboration", "data_consumed": 9_000_000}]}}}},
    }


class FakeExecutor:
    def __init__(self, answers):
        self.answers = answers
        self.sent = []

    def create_request(self, method, url, body, headers):
        return {"body": body}, None

    def execute(self, request):
        body = request["body"]
        self.sent.append(body)
        return SimpleNamespace(get_body=lambda: self.answers[body["operationName"]](body["variables"]),
                               _response=SimpleNamespace(status_code=200, headers={})), None


def sdk(answers=None):
    ex = FakeExecutor(answers or _answers())
    return SimpleNamespace(zins=ZInsService(ex), executor=ex)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(insights, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_SSL_COVERAGE_STATE", str(tmp_path / "ssl_coverage_history.json"))


def _cc():
    import data_flow
    return data_flow.read_client_connector(FakeCl(tenant_routes()), scope=data_flow.path_scope(["dlp", "zcc"], {"ssl_inspection": "zscaler"}))


# ── causes and risk ─────────────────────────────────────────────────────
def test_every_cause_is_found_with_the_rule_or_setting_behind_it():
    rep = sc.analyse(SSL, cc=_cc())
    by = {c["id"]: c for c in rep["causes"]}
    assert set(by) == {"ssl-1", "ssl-2", "ssl-3", "ssl-4", "ssl-5", "ssl-6", "ssl-9", "zcc-domains", "zcc-ips", "zcc-apps", "fwd-7-off", "pac-5"}
    assert "ssl-8" not in by, "a disabled exemption is not a cause"
    assert by["ssl-4"]["source"] == {"setting": "SSL inspection rule", "name": "DNI file hosts", "order": 4, "id": 4, "action": "DO_NOT_DECRYPT"}
    assert by["ssl-4"]["classes"] == ["file_share"] and by["ssl-4"]["console"] == sc.SSL_CONSOLE
    assert by["ssl-2"]["kind"] == "scoped_catch_all" and by["ssl-2"]["scope"] == "groups: 1"
    assert by["ssl-9"]["kind"] == "catch_all"
    assert by["fwd-7-off"]["never_reaches_zscaler"] and "off a trusted network" in by["fwd-7-off"]["what"]
    assert by["pac-5"]["values"] == ["*.wetransfer.com", ".local"] and by["zcc-domains"]["values"] == ["*.dropbox.com", "intranet.corp"]


def test_risk_says_what_is_dangerous_and_what_is_expected():
    by = {c["id"]: c for c in sc.analyse(SSL, cc=_cc())["causes"]}
    assert by["ssl-4"]["risk"] == "high" and "File sharing" in by["ssl-4"]["risk_reason"]
    assert by["ssl-9"]["risk"] == "high" and by["ssl-2"]["risk"] == "high"
    priv = by["ssl-3"]
    assert priv["risk"] == "expected" and "privacy" in priv["risk_reason"] and "expected" in priv["risk_reason"] and priv["safe"] == "keep"
    pinned = by["ssl-1"]
    assert pinned["kind"] == "pinned_exemptions" and pinned["risk"] == "expected" and pinned["safe"] == "no"
    # Zoom is commonly certificate-pinned: kept exempt; ChatGPT is not, and is high (GenAI).
    chat = by["ssl-5"]
    assert chat["risk"] == "high" and chat["safe"] == "test" and "keep ZOOM exempt" in chat["recovery"] and "remove CHATGPT_AI" in chat["recovery"]
    # Social is medium, raised to high by "Bypass other policies".
    assert by["ssl-6"]["bypass_other_policies"] and by["ssl-6"]["risk"] == "high" and "Bypass other policies" in by["ssl-6"]["risk_reason"]
    assert by["zcc-domains"]["risk"] == "high" and "dropbox" in by["zcc-domains"]["risk_reason"]
    assert by["zcc-ips"]["risk"] == "expected", "a private subnet bypass is expected"
    assert by["zcc-apps"]["risk"] == "medium" and by["pac-5"]["risk"] == "high"


def test_the_plan_puts_the_biggest_risk_first_and_documents_what_is_kept():
    rep = sc.analyse(SSL, cc=_cc())
    steps = rep["plan"]["steps"]
    assert [s["n"] for s in steps] == list(range(1, len(steps) + 1))
    risks = [s["risk"] for s in steps]
    assert risks == sorted(risks, key=lambda r: sc.RISK_ORDER[r]), "high before medium before expected"
    assert steps[0]["cause_id"] == "ssl-9", "the catch-all default rule is the biggest reduction"
    last = steps[-1]
    assert last["risk"] == "expected" and last["safe"] == "keep" and "ssl-3" in last["cause_id"] and "ssl-1" in last["cause_id"]
    for s in steps:
        assert s["change"] and s["where"] and s["effect"] and s["safe_label"] and s["safe_note"]
    assert any("root certificate" in p for p in rep["plan"]["prerequisites"])
    s = rep["summary"]
    assert s["by_risk"]["high"] == 8 and s["by_risk"]["expected"] == 3 and s["classes_total"] == 10
    assert rep["headline"].startswith(f"{s['classes_not_inspected']} of 10 kinds of web traffic") and "Start with step 1" in rep["headline"]


def test_a_tenant_that_decrypts_everything_has_nothing_to_fix():
    rules = [SSL[0], {"id": 2, "name": "Decrypt all", "order": 2, "state": "ENABLED", "url_categories": ["ANY"], "action": {"type": "DECRYPT"}}]
    rep = sc.analyse(rules)
    assert [c["id"] for c in rep["causes"]] == ["ssl-1"] and rep["summary"]["by_risk"]["high"] == 0
    assert rep["summary"]["classes_covered"] == 10 and rep["plan"]["steps"][-1]["safe"] == "keep"
    assert "No high-risk cause" in rep["headline"]


# ── protocols: the one mapping table and the shares ─────────────────────
@pytest.mark.parametrize("name,bucket,known", [
    ("HTTPS", "ssl_inspected", True), ("https", "ssl_inspected", True), ("SSL", "ssl_not_inspected", True),
    ("Tunnel SSL", "ssl_not_inspected", True), ("tunnel-ssl", "ssl_not_inspected", True), ("HTTP", "http", True),
    ("HTTP_PROXY", "http", True), ("TUNNEL", "other", True), ("QUIC_NEW", "other", False), ("", "other", False), (None, "other", False)])
def test_protocol_names_map_through_one_table(name, bucket, known):
    assert sc.bucket_of(name) == (bucket, known)


def test_inspected_shares_never_fold_in_other_or_divide_by_zero():
    sp = sc.protocol_split(PROTOCOLS["TRANSACTIONS"])
    assert sp["ssl_total"] == 800 and sp["http_total"] == 200 and sp["other_total"] == 50
    assert sp["ssl_pct"] == 75.0 and sp["http_pct"] == 100.0 and sp["total_pct"] == 80.0
    assert sp["total_pct_if_other_not_inspected"] == round(100 * 800 / 1050, 1)
    assert sp["unrecognised"] == [{"name": "QUIC_NEW", "total": 20.0}], "TUNNEL is known (other); QUIC_NEW is listed back"
    zero = sc.protocol_split([])
    assert zero["ssl_pct"] is None and zero["http_pct"] is None and zero["total_pct"] is None and zero["total_pct_if_other_not_inspected"] is None
    only_other = sc.protocol_split([{"name": "MYSTERY", "total": 5}])
    assert only_other["total_pct"] is None and only_other["total_pct_if_other_not_inspected"] == 0.0
    no_http = sc.protocol_split(PROTOCOLS["BYTES"])
    assert no_http["http_pct"] is None and no_http["ssl_pct"] == 90.0 and no_http["total_pct"] == 90.0
    bad = sc.protocol_split([{"name": "HTTPS", "total": "x"}, {"name": "HTTPS", "total": -1}, "junk", {"name": "HTTPS", "total": 10}])
    assert bad["ssl_total"] == 10 and bad["ssl_pct"] == 100.0


def test_volume_reads_protocols_trend_and_app_bytes_and_ranks_causes():
    t = sdk()
    out = sc.read_volume(t.zins, "7d", log=lambda m: None)
    ops = [b["operationName"] for b in t.executor.sent]
    assert ops == ["WebProtocols", "WebProtocols", "WebTrafficNoGrouping", "ShadowITApps"]
    assert {b["variables"]["trafficUnit"] for b in t.executor.sent[:2]} == {"TRANSACTIONS", "BYTES"}
    assert t.executor.sent[2]["variables"]["trendInterval"] == "DAY" and t.executor.sent[2]["variables"]["includeTrend"] is True
    assert out["status"] == "ok" and out["protocols"]["TRANSACTIONS"]["total_pct"] == 80.0 and len(out["daily"]) == 3
    rep = sc.analyse(SSL, cc=_cc(), volume=out)
    by = {c["id"]: c for c in rep["causes"]}
    assert by["ssl-5"]["volume"]["bytes"] == 11_000_000 and {a["application"] for a in by["ssl-5"]["volume"]["apps"]} == {"Zoom", "ChatGPT"}
    assert by["zcc-domains"]["volume"]["bytes"] == 4_000_000, "*.dropbox.com matches Dropbox"
    assert by["ssl-4"]["volume"]["bytes"] is None and "URL category" in by["ssl-4"]["volume"]["basis"]
    assert rep["summary"]["inspected_pct_bytes"] == 90.0 and rep["headline"].startswith("About 90% of the web traffic")


# ── the server: scope first, the job, exports, history ──────────────────
def _poll(c, jid, timeout=20):
    deadline, since, logs = time.time() + timeout, 0, []
    while time.time() < deadline:
        snap = c.get(f"/api/dlp-packs/jobs/{jid}?since={since}").json()
        logs += snap["logs"]
        since = snap["next"]
        if snap["status"] != "running":
            snap["all_logs"] = logs
            return snap
        time.sleep(0.03)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("body,why", [
    (dict(CREDS, scopes=[], channels={}, from_page=True), "not in scope"),
    (dict(CREDS, scopes=["zcc", "insights"], channels={}, from_page=True), "not in scope"),
    (dict(CREDS, scopes=["dlp"], channels={"ssl_inspection": "alternative"}, from_page=True), "not in scope"),
    (dict(CREDS), "not in scope"),
    (dict(CREDS, window="90d", **IN_SCOPE), "7 days or the last 30 days"),
])
def test_out_of_scope_is_refused_before_anything_is_read(monkeypatch, body, why):
    def no_sign_in(*a, **k):
        raise AssertionError("signed in although refused")
    monkeypatch.setattr(srv, "_build_client", no_sign_in)
    monkeypatch.setattr(srv, "_build_sdk_client", no_sign_in)
    r = TestClient(srv.app).post("/api/ssl-coverage/start", json=body)
    assert r.status_code == 400 and why in r.text and "Nothing was read" in r.text, r.text


def test_the_job_reads_reports_exports_and_keeps_history_without_secrets(monkeypatch):
    cl, t = FakeCl(tenant_routes()), sdk()
    monkeypatch.setattr(srv, "_build_client", lambda req: cl)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    c = TestClient(srv.app)
    r = c.post("/api/ssl-coverage/start", json=dict(CREDS, window="30d", **IN_SCOPE))
    assert r.status_code == 200 and r.json()["kind"] == "sslcoverage", r.text
    snap = _poll(c, r.json()["job_id"])
    assert snap["status"] == "done", snap.get("error")
    res = snap["result"]
    assert res["tenant_label"] == "acme (production)" and res["report_id"].startswith("sslcoverage-")
    assert res["volume"]["available"] and res["volume"]["window"]["key"] == "30d" and "apps" not in res["volume"]
    assert res["volume"]["protocols"]["BYTES"]["ssl_pct"] == 90.0 and res["volume"]["note"] == sc.PROTOCOL_NOTE
    assert res["summary"]["by_risk"]["high"] == 8 and res["plan"]["steps"][0]["cause_id"] == "ssl-9"
    assert any("In scope, from the Scope page" in line for line in snap["all_logs"])
    assert "/zia/sslInspectionRules" in cl.reads and "/zia/pacFiles" in cl.reads and not any("webDlpRules" in e for e in cl.reads)
    assert SECRET not in json.dumps(snap) and SECRET not in read_store_text(os.environ["DLP_CHECK_SSL_COVERAGE_STATE"])
    assert len(res["history"]) == 1 and res["history"][0]["inspected_pct_bytes"] == 90.0
    rid = res["report_id"]
    assert c.get(f"/api/ssl-coverage/{rid}").json()["summary"] == res["summary"]
    x = c.get(f"/api/ssl-coverage/export/{rid}?format=xlsx")
    assert x.status_code == 200 and x.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    z = zipfile.ZipFile(io.BytesIO(x.content))
    sheets = [n for n in z.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", n)]
    assert len(sheets) == 6 and "xl/workbook.xml" in z.namelist()
    wbxml = z.read("xl/workbook.xml").decode()
    for name in ("Summary", "Traffic and inspection", "Causes", "Recovery plan", "Traffic classes", "Run history"):
        assert f'name="{name}"' in wbxml
    text = "".join(z.read(n).decode() for n in sheets)
    assert "DNI file hosts" in text and "QUIC_NEW" in text and "Zscaler Made Easy" in text and SECRET not in text and "<f>" not in text
    js = c.get(f"/api/ssl-coverage/export/{rid}?format=json")
    assert js.status_code == 200 and SECRET not in js.text and "logs" not in json.loads(js.text)
    assert c.get(f"/api/ssl-coverage/export/{rid}?format=pdf").status_code == 400
    assert c.get("/api/ssl-coverage/export/sslcoverage-nope").status_code == 404
    other = srv._remember_report("sslflow", {"summary": {}}, "x")
    assert c.get(f"/api/ssl-coverage/{other}").status_code == 404
    # A second run adds to the trend.
    snap2 = _poll(c, c.post("/api/ssl-coverage/start", json=dict(CREDS, **IN_SCOPE)).json()["job_id"])
    assert len(snap2["result"]["history"]) == 2
    assert len(c.get("/api/ssl-coverage/history?tenant=acme (production)").json()["history"]) == 2


def test_without_insights_in_scope_it_is_configuration_only_and_says_so(monkeypatch):
    cl = FakeCl(tenant_routes())
    monkeypatch.setattr(srv, "_build_client", lambda req: cl)

    def no_sdk(creds):
        raise AssertionError("Insights signed in although not in scope")
    monkeypatch.setattr(srv, "_build_sdk_client", no_sdk)
    c = TestClient(srv.app)
    res = _poll(c, c.post("/api/ssl-coverage/start", json=dict(CREDS, **NO_INSIGHTS)).json()["job_id"])["result"]
    v = res["volume"]
    assert v["available"] is False and "ZIA Insights is not in scope" in v["reason"] and "protocols" not in v
    assert "inspected_pct_bytes" not in res["summary"] and not res["headline"].startswith("About")
    assert all(c_.get("volume") is None for c_ in res["causes"])
    # Switched off on the page: not asked either.
    res2 = _poll(c, c.post("/api/ssl-coverage/start", json=dict(CREDS, include_volume=False, **IN_SCOPE)).json()["job_id"])["result"]
    assert res2["volume"]["reason"] == "Traffic numbers were switched off for this run."
    # ZCC not ticked: no Client Connector or PAC read, and the page says why.
    cl3 = FakeCl(tenant_routes())
    monkeypatch.setattr(srv, "_build_client", lambda req: cl3)
    res3 = _poll(c, c.post("/api/ssl-coverage/start", json=dict(CREDS, scopes=["dlp"], channels={"ssl_inspection": "zscaler"}, from_page=True)).json()["job_id"])["result"]
    assert not any(e.startswith("/zcc") or e == "/zia/pacFiles" for e in cl3.reads) and "zcc" in res3["not_in_scope"]
    assert not any(c_["never_reaches_zscaler"] for c_ in res3["causes"])


def test_stop_before_start_reads_nothing(monkeypatch):
    cl = FakeCl(tenant_routes())
    monkeypatch.setattr(srv, "_build_client", lambda req: cl)
    c = TestClient(srv.app)
    token = "sslcoveragestoptoken1"
    assert c.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}).status_code == 200
    jid = c.post("/api/ssl-coverage/start", json=dict(CREDS, **NO_INSIGHTS), headers={"X-Start-Token": token}).json()["job_id"]
    snap = _poll(c, jid)
    assert snap["status"] == "cancelled" and snap["result"]["stopped"] == sc.STOPPED_REASON and cl.reads == []


def test_history_is_small_per_tenant_and_scrubs_classic_logins(tmp_path):
    p = str(tmp_path / "h.json")
    rep = sc.analyse(SSL)
    for _ in range(sc.HISTORY_KEEP + 5):
        sc.record("acme (production)", rep, p)
    assert len(sc.load_history("acme (production)", p)) == sc.HISTORY_KEEP
    sc.record("admin@acme.example (zscalerten, classic API)", rep, p)
    raw = read_store_text(p)
    assert "admin@acme.example" not in raw and "classic API (zscalerten)" in raw
    assert sc.load_history("nobody", p) == [] and sc.load_history("x", str(tmp_path / "missing.json")) == []
    e = sc.load_history("acme (production)", p)[-1]
    assert set(e) >= {"at", "class_coverage_pct", "by_risk", "by_kind", "inspected_pct_bytes", "plan_steps"}


# ── the page ────────────────────────────────────────────────────────────
def _read_static(name):
    return open(os.path.join(ROOT, "static", name), encoding="utf-8").read()


def test_the_page_is_served_wired_and_explained():
    c = TestClient(srv.app)
    r = c.get("/report/sslcoverage")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = _read_static("report_ssl_coverage.html")
    assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html
    assert '<a class="rp-btn" href="/">← Back to the assessment</a>' in html and '<main class="rp-card">' in html
    assert 'role="status"' in html and 'aria-live="polite"' in html and "<caption" in html
    order = [html.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    style = html[html.index("<style>"):html.index("</style>")]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", style) and "gradient" not in style and "box-shadow" not in style
    assert "/api/ssl-coverage/start" in html and "X-Start-Token" in html and "/api/dlp-packs/jobs/stop-before-start" in html
    assert "<title>SSL coverage — Zscaler Made Easy</title>" in html and "Traffic and inspection" in html
    assert "DLP-Check" not in html
    js = _read_static("explain.js")
    assert "X.sslcoverage = {" in js and "'/report/sslcoverage': 'sslcoverage'" in js and "'sslcoverage'," in js[js.index("DLP_EXPLAIN_ORDER"):]
    assert "group: 'Find the gaps', name: 'SSL coverage'" in js[js.index("X.sslcoverage = {"):][:200]
    idx = _read_static("index.html")
    assert 'onclick="openSslCoverageTab()"' in idx and "function openSslCoverageTab()" in idx
    src = open(os.path.join(ROOT, "dlp_api_server.py"), encoding="utf-8").read()
    stale = src[src.index('request.url.path in ("/", "/app.css"'):]
    assert '"/report/sslcoverage"' in stale[:stale.index(")")], "never served stale"
    g = _read_static("glossary.js")
    for term in ("'ssl inspection'", "'certificate pinning'", "'bypass'", "'decrypt'"):
        assert term in g
    mod = open(os.path.join(ROOT, "ssl_coverage.py"), encoding="utf-8").read()
    assert "PROTOCOL_BUCKETS" in mod
