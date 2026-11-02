"""Traffic insights (ZIA Insights, the Z-Insights GraphQL API): the real
SDK's query code runs against a fake request executor that answers in the
shape each SDK query asks for, so the queries, variables, error handling
(GraphQLAPIError) and partial answers are the SDK's own. Covers time
window validation, scope refusal before sign-in, Stop, empty and partial
windows, no secrets and no user names outside the screen, the rule-hit
helper, the Path analyzer's "recent traffic" note and the page's
conventions."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from zscaler.zins.zins_service import ZInsService

import dlp_api_server as srv
import insights

ROOT = os.path.join(os.path.dirname(__file__), "..")
SECRET = "secret-secret-secret"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
IN_SCOPE = {"scopes": ["insights"], "channels": {}, "from_page": True}
NOW = int(time.time() * 1000)
DAY = insights.DAY_MS
USER = "jane.doe@acme.example"


# ── recorded-shape GraphQL answers, one per SDK operation ─────────────────
def _entries(domain, field, entries, obfuscated=False):
    return {"data": {domain: {field: {"obfuscated": obfuscated, "entries": entries}}}}


def _no_grouping(v):
    total = {None: 1000, "ALLOW": 900, "BLOCK": 100}[v.get("actionFilter")]
    if v.get("trafficUnit") == "BYTES":
        total *= 2048
    return _entries("WEB_TRAFFIC", "no_grouping", [{"name": "TOTAL", "total": total, "trend": None}])


ANSWERS = {
    "WebTrafficNoGrouping": _no_grouping,
    "WebTrafficByLocation": lambda v: _entries("WEB_TRAFFIC", "location", [
        {"name": "HQ", "total": 700, "trend": None}, {"name": "Branch", "total": 300, "trend": None}]),
    "ShadowITApps": lambda v: _entries("SHADOW_IT", "apps", [
        {"application": "Dropbox", "application_category": "File sharing", "risk_index": 4, "computed_risk_index": 4,
         "sanctioned_state": "Unsanctioned", "integration": 0, "data_consumed": 5_000_000, "data_uploaded": 4_000_000,
         "data_downloaded": 1_000_000, "authenticated_users": 12, "unAuthenticated_location_count": 0,
         "last_access_time": NOW - DAY, "vulnerability": None, "undiscovered": False, "custom_risk_index": None},
        {"application": "=HYPERLINK(\"http://x.example\")", "application_category": "Other", "risk_index": 1,
         "data_consumed": 10, "sanctioned_state": "Sanctioned"}]),
    "ShadowITSummary": lambda v: {"data": {"SHADOW_IT": {"shadow_it_summary": {
        "total_upload_bytes": 4_000_000, "total_download_bytes": 1_000_000, "total_apps": 2, "total_bytes": 5_000_000,
        "group_by_app_cat_for_app": {"obfuscated": False, "entries": [{"name": "File sharing", "total": 1, "entries": [{"name": "Dropbox", "total": 1}]}]},
        "group_by_app_cat_for_user_count": {"obfuscated": False, "entries": []},
        "group_by_app_cat_for_upload_bytes": {"obfuscated": False, "entries": []},
        "group_by_app_cat_for_download_bytes": {"obfuscated": False, "entries": []},
        "group_by_app_cat_for_total_bytes": {"obfuscated": False, "entries": [{"name": "File sharing", "total": 5_000_000, "entries": []}]},
        "group_by_risk_index_for_app": {"obfuscated": False, "entries": [{"name": "4", "total": 1}]},
        "group_by_provisioning_status_for_app": {"obfuscated": False, "entries": []},
        "group_by_access_for_app": {"obfuscated": False, "entries": []}}}}},
    "CasbAppReport": lambda v: _entries("SAAS_SECURITY", "casb_app", [{"name": "Box", "total": 42}]),
    "FirewallByAction": lambda v: _entries("ZERO_TRUST_FIREWALL", "action", [{"name": "ALLOW", "total": 50}, {"name": "BLOCK", "total": 5}]),
    "CyberSecurityIncidents": lambda v: _entries("CYBER_SECURITY", "incidents", [
        {"name": USER, "total": 9, "entries": [{"name": "Phishing", "total": 9}]}]),
    "WebThreatClass": lambda v: _entries("WEB_TRAFFIC", "threat_class", [{"name": "Advanced Threats", "total": 14}]),
    "WebThreatSuperCategories": lambda v: _entries("WEB_TRAFFIC", "threat_super_categories", [{"name": "Phishing", "total": 9}]),
    "FirewallByLocation": lambda v: _entries("ZERO_TRUST_FIREWALL", "location_firewall", [{"id": 1, "name": "HQ", "total": 40}]),
    "FirewallNetworkServices": lambda v: _entries("ZERO_TRUST_FIREWALL", "network_service", [{"name": "DNS", "total": 30}]),
    "CyberSecurityByLocation": lambda v: _entries("CYBER_SECURITY", "cyber_security_location", [{"id": 1, "name": "HQ", "total": 6}]),
    "IoTDeviceStats": lambda v: {"data": {"IOT": {"device_stats": {
        "devices_count": 120, "user_devices_count": 80, "iot_devices_count": 25, "server_devices_count": 10, "un_classified_devices_count": 5,
        "entries": [{"classifications": "IP camera", "classification_uuid": "c-1", "category": "IoT", "total": 12}]}}}},
}
EMPTY = {
    "WebTrafficNoGrouping": lambda v: _entries("WEB_TRAFFIC", "no_grouping", []),
    "WebTrafficByLocation": lambda v: _entries("WEB_TRAFFIC", "location", []),
    "ShadowITApps": lambda v: {"data": {"SHADOW_IT": {"apps": {"entries": []}}}},
    "ShadowITSummary": lambda v: {"data": {"SHADOW_IT": {"shadow_it_summary": {"total_apps": 0, "total_bytes": 0}}}},
    "CasbAppReport": lambda v: _entries("SAAS_SECURITY", "casb_app", []),
    "FirewallByAction": lambda v: _entries("ZERO_TRUST_FIREWALL", "action", []),
    "CyberSecurityIncidents": lambda v: _entries("CYBER_SECURITY", "incidents", []),
    "WebThreatClass": lambda v: _entries("WEB_TRAFFIC", "threat_class", []),
    "WebThreatSuperCategories": lambda v: _entries("WEB_TRAFFIC", "threat_super_categories", []),
    "FirewallByLocation": lambda v: _entries("ZERO_TRUST_FIREWALL", "location_firewall", []),
    "FirewallNetworkServices": lambda v: _entries("ZERO_TRUST_FIREWALL", "network_service", []),
    "CyberSecurityByLocation": lambda v: _entries("CYBER_SECURITY", "cyber_security_location", []),
    "IoTDeviceStats": lambda v: {"data": {"IOT": {"device_stats": {"devices_count": 0, "entries": []}}}},
}


class FakeResponse:
    """The SDK response object as zins reads it: get_body() and _response."""

    def __init__(self, body, status=200):
        self._body = body
        self._response = SimpleNamespace(status_code=status, headers={"Content-Type": "application/json"})

    def get_body(self):
        return self._body


class FakeExecutor:
    """Stands in for zscaler.request_executor.RequestExecutor under the
    SDK's own ZInsService: records every GraphQL request it is sent."""

    def __init__(self, answers=None, on_execute=None):
        self.answers = dict(ANSWERS if answers is None else answers)
        self.sent = []
        self.on_execute = on_execute

    def create_request(self, method, url, body, headers):
        assert method == "POST" and url == "/zins/graphql"
        return {"body": body}, None

    def execute(self, request):
        body = request["body"]
        self.sent.append(body)
        if self.on_execute:
            self.on_execute(self, body)
        a = self.answers[body["operationName"]]
        if isinstance(a, Exception):
            return None, a
        return FakeResponse(a(body["variables"]) if callable(a) else a), None

    def ops(self):
        return [b["operationName"] for b in self.sent]


def tenant(answers=None, on_execute=None):
    ex = FakeExecutor(answers, on_execute)
    return SimpleNamespace(zins=ZInsService(ex), executor=ex)


@pytest.fixture(autouse=True)
def _no_pace(monkeypatch):
    monkeypatch.setattr(insights, "PACE_SECONDS", 0.0)


def _read(t, **kw):
    w = insights.window("7d")
    return insights.read(t, w["start_ms"], w["end_ms"], **kw)


# ── the SDK's own queries carry the fields this module reads ──────────────
def test_the_sdk_queries_ask_for_the_fields_the_page_reads():
    t = tenant()
    _read(t)
    q = {b["operationName"]: b["query"] for b in t.executor.sent}
    assert set(q) == set(ANSWERS)
    for op, fields in {"WebTrafficNoGrouping": ("no_grouping", "action_filter", "obfuscated", "name", "total"),
                       "WebTrafficByLocation": ("location", "name", "total"),
                       "ShadowITApps": ("apps",) + insights._APP_TEXT + insights._APP_NUM,
                       "ShadowITSummary": ("shadow_it_summary",) + insights._SUMMARY_TOTALS + tuple(k for k, _ in insights._SUMMARY_GROUPS),
                       "CasbAppReport": ("casb_app", "name", "total"),
                       "FirewallByAction": ("ZERO_TRUST_FIREWALL", "action", "name", "total"),
                       "CyberSecurityIncidents": ("incidents", "categorize_by", "name", "total"),
                       "WebThreatClass": ("threat_class", "name", "total"),
                       "WebThreatSuperCategories": ("threat_super_categories", "name", "total"),
                       "FirewallByLocation": ("location_firewall", "name", "total"),
                       "FirewallNetworkServices": ("network_service", "name", "total"),
                       "CyberSecurityByLocation": ("cyber_security_location", "categorize_by", "name", "total"),
                       "IoTDeviceStats": ("device_stats", "classifications", "category", "total") + insights._IOT_TOTALS}.items():
        for f in fields:
            assert f in q[op], (op, f)
    # Nothing in the SDK groups by URL category or rule, or filters by host.
    allq = " ".join(q.values()).lower()
    assert "url_categor" not in allq and "rule" not in allq and "hostname" not in allq


def test_a_full_read_asks_each_query_once_with_the_window_and_unit():
    t = tenant()
    w = insights.window("24h")
    res = insights.read(t, w["start_ms"], w["end_ms"], traffic_unit="BYTES")
    assert res["status"] == "ok" and res["queries"] == 15 and res["traffic_unit"] == "BYTES"
    assert t.executor.ops().count("WebTrafficNoGrouping") == 3
    for b in t.executor.sent:
        if b["operationName"] == "IoTDeviceStats":   # device counts take no time window (SDK zins/iot.py)
            assert "startTime" not in b["variables"]
            continue
        assert b["variables"]["startTime"] == w["start_ms"] and b["variables"]["endTime"] == w["end_ms"]
    filters = [b["variables"].get("actionFilter") for b in t.executor.sent if b["operationName"] == "WebTrafficNoGrouping"]
    assert filters == [None, "ALLOW", "BLOCK"]
    assert all(b["variables"]["trafficUnit"] == "BYTES" for b in t.executor.sent if b["operationName"].startswith("WebTraffic"))
    inc = [b for b in t.executor.sent if b["operationName"] == "CyberSecurityIncidents"][0]
    assert inc["variables"]["categorizeBy"] == ["USER_ID"] and inc["variables"]["limit"] == insights.USER_LIMIT
    s = res["sections"]
    assert [r["total"] for r in s["web_action"]["rows"]] == [1000 * 2048, 900 * 2048, 100 * 2048]
    assert [r["name"] for r in s["web_action"]["rows"]] == ["All web traffic", "Allowed", "Blocked"]
    assert s["web_location"]["rows"][0] == {"name": "HQ", "total": 700}
    assert s["cloud_apps"]["rows"][0]["application"] == "Dropbox" and s["cloud_apps"]["rows"][0]["data_uploaded"] == 4_000_000
    assert s["shadow_summary"]["summary"]["totals"]["total_apps"] == 2
    assert s["casb_apps"]["rows"] == [{"name": "Box", "total": 42}] and s["fw_action"]["rows"][1] == {"name": "BLOCK", "total": 5}
    assert s["top_users"]["rows"] == [{"name": USER, "total": 9}] and "not traffic" in s["top_users"]["note"]
    assert res["rule_hits"]["available"] is False and {u["key"] for u in res["unavailable"]} == {"url_category", "user_traffic", "rule_hits", "host"}


def test_top_users_off_is_never_asked():
    t = tenant()
    res = _read(t, include_users=False)
    assert "CyberSecurityIncidents" not in t.executor.ops() and res["sections"]["top_users"]["status"] == "skipped"
    assert res["queries"] == 14


# ── time windows ──────────────────────────────────────────────────────────
def test_time_windows_are_checked_before_anything_is_asked():
    ok = insights.validate_window(NOW - 7 * DAY, NOW, NOW)
    assert ok == (NOW - 7 * DAY, NOW)
    bad = [(NOW, NOW - DAY, "ends before"), (NOW - DAY, NOW + DAY, "future"), (NOW - 93 * DAY, NOW, "92 days"),
           (NOW - 181 * DAY, NOW - 170 * DAY, "180 days"), (NOW - 60_000, NOW, "15 minutes"), ("x", NOW, "epoch"),
           (True, NOW, "epoch"), (1.5, NOW, "epoch"), (None, NOW, "epoch"), (-5, NOW, "epoch")]
    for s, e, why in bad:
        with pytest.raises(insights.WindowError, match=why):
            insights.validate_window(s, e, NOW)
    assert insights.window("90d", now_ms=NOW)["start_ms"] == NOW - 90 * DAY
    with pytest.raises(insights.WindowError):
        insights.window("365d")
    assert insights.window(start_ms=NOW - DAY, end_ms=NOW)["label"] == "custom window"
    t = tenant()
    with pytest.raises(insights.WindowError):
        insights.read(t, NOW - 100 * DAY, NOW)
    with pytest.raises(insights.WindowError):
        insights.read(t, NOW - DAY, NOW, traffic_unit="PACKETS")
    assert t.executor.sent == []


# ── GraphQL errors, empty windows, partial and malformed answers ──────────
def test_a_graphql_error_fails_only_its_section_and_says_why():
    answers = dict(ANSWERS, CasbAppReport=lambda v: {"errors": [{"message": "Access denied for SAAS_SECURITY", "path": ["SAAS_SECURITY"],
                                                                  "extensions": {"classification": "FORBIDDEN"}}], "data": None})
    res = _read(tenant(answers))
    c = res["sections"]["casb_apps"]
    assert c["status"] == "error" and "Access denied" in c["error"] and c["classification"] == "FORBIDDEN" and "Z-Insights" in c["hint"]
    assert res["status"] == "partial" and res["sections"]["fw_action"]["status"] == "ok"


def test_every_section_failing_is_an_error_not_a_crash():
    answers = {k: (lambda v: {"errors": [{"message": "Bad request", "extensions": {"classification": "BAD_REQUEST"}}]}) for k in ANSWERS}
    res = _read(tenant(answers))
    assert res["status"] == "error" and all(s["status"] == "error" for s in res["sections"].values())
    assert "shorter or more recent" in res["sections"]["web_location"]["hint"]


def test_a_partial_answer_keeps_its_data_and_says_it_is_partial():
    answers = dict(ANSWERS,
                   WebTrafficByLocation=lambda v: {"errors": [{"message": "Some locations timed out"}],
                                                   "data": {"WEB_TRAFFIC": {"location": {"obfuscated": True, "entries": [{"name": "HQ", "total": 7}]}}}},
                   ShadowITSummary=lambda v: {"errors": [{"message": "group timed out"}],
                                              "data": {"SHADOW_IT": {"shadow_it_summary": {"total_apps": 3}}}})
    res = _read(tenant(answers))
    loc, sm = res["sections"]["web_location"], res["sections"]["shadow_summary"]
    assert loc["status"] == "partial" and loc["rows"] == [{"name": "HQ", "total": 7}] and loc["obfuscated"] is True and "timed out" in loc["error"]
    assert sm["status"] == "partial" and sm["summary"]["totals"]["total_apps"] == 3
    assert res["status"] == "partial"


def test_an_empty_window_is_no_data_not_an_error():
    res = _read(tenant(EMPTY))
    assert res["status"] == "ok"
    assert {k: v["status"] for k, v in res["sections"].items()} == {k: "empty" for k in insights.SECTION_KEYS}


def test_malformed_answers_are_read_defensively():
    answers = dict(ANSWERS,
                   WebTrafficByLocation=lambda v: _entries("WEB_TRAFFIC", "location", ["junk", {"name": "A", "total": "12"}, {"name": "B", "total": "n/a"},
                                                                                       {"name": None, "total": 3}, {"name": "x" * 500, "total": 1}]),
                   CasbAppReport=lambda v: {"data": {"SAAS_SECURITY": None}},
                   FirewallByAction=RuntimeError("connection reset"))
    s = _read(tenant(answers))["sections"]
    assert s["web_location"]["rows"][:2] == [{"name": "A", "total": 12}, {"name": "(unnamed)", "total": 3}]
    assert len(s["web_location"]["rows"][2]["name"]) == insights.NAME_MAX
    assert s["casb_apps"]["status"] == "error" and s["fw_action"]["status"] == "error" and "connection reset" in s["fw_action"]["error"]


# ── Stop and pacing ───────────────────────────────────────────────────────
def test_stop_ends_the_read_between_queries_with_no_partial_result():
    cancel = threading.Event()

    def stop_after_two(ex, body):
        if len(ex.sent) == 2:
            cancel.set()
    t = tenant(on_execute=stop_after_two)
    logs = []
    with pytest.raises(insights.Stopped):
        _read(t, cancel=cancel, log=logs.append)
    assert len(t.executor.sent) == 2 and any(l.startswith("STOPPED") for l in logs)


def test_queries_are_paced_and_the_pause_ends_at_stop():
    slept = []
    _read(tenant(), pace=0.25, sleep=slept.append)
    assert slept == [0.25] * 14
    cancel = threading.Event()
    threading.Timer(0.2, cancel.set).start()
    t0 = time.time()
    t = tenant()
    with pytest.raises(insights.Stopped):
        _read(t, pace=30, cancel=cancel)
    assert time.time() - t0 < 5 and len(t.executor.sent) == 1


# ── no secrets, no user names outside the screen ──────────────────────────
def test_errors_are_scrubbed_and_logs_name_no_user():
    answers = dict(ANSWERS, CasbAppReport=lambda v: {"errors": [{"message": f"token {SECRET} rejected"}]})
    logs = []
    res = _read(tenant(answers), log=logs.append, scrub=lambda s: s.replace(SECRET, "[redacted client_secret]"))
    assert SECRET not in json.dumps(res) and "[redacted client_secret]" in res["sections"]["casb_apps"]["error"]
    text = "\n".join(logs)
    assert USER not in text and "Dropbox" not in text and "shown on screen only" in text


def test_exports_leave_the_users_out_and_are_spreadsheet_safe():
    res = _read(tenant())
    exp = insights.exportable(res)
    assert USER not in json.dumps(exp) and exp["sections"]["top_users"]["status"] == "omitted"
    assert res["sections"]["top_users"]["rows"], "the screen still has them"
    csv_text = insights.to_csv(res)
    assert USER not in csv_text and "Dropbox" in csv_text and "HQ" in csv_text
    assert "'=HYPERLINK" in csv_text and "\n=HYPERLINK" not in csv_text and ",=HYPERLINK" not in csv_text
    assert csv_text.splitlines()[0].split(",") == insights.CSV_COLUMNS


# ── rule hits ─────────────────────────────────────────────────────────────
def test_rule_hits_is_a_pure_map_and_no_data_is_never_unused():
    rows = [{"policy": "URL filtering", "rule": "Block gambling", "hits": 7},
            {"policy": "URL filtering", "rule_name": "Block gambling", "total": 3},
            {"policy": "Firewall", "name": "Allow DNS", "hits": 0},
            {"policy": "Firewall", "rule": "", "hits": 4}, {"rule": "Bad", "hits": "lots"}, {"rule": "Neg", "hits": -1},
            {"rule": "Frac", "hits": 1.5}, "junk"]
    hits = insights.rule_hits(rows)
    assert hits == {("URL filtering", "Block gambling"): 10, ("Firewall", "Allow DNS"): 0}
    assert insights.rule_hits(None) == {} and insights.rule_hits("x") == {}
    assert insights.describe_rule_hits(hits, "URL filtering", "Block gambling", 7) == "Matched 10 times in 7 days."
    assert insights.describe_rule_hits(hits, "Firewall", "Allow DNS", 7) == "0 hits in 7 days: unused."
    assert insights.describe_rule_hits(None, "Firewall", "Allow DNS", 7).startswith("Hits not measured")


# ── the Path analyzer's recent-traffic note ───────────────────────────────
def test_the_path_analyzer_says_recent_traffic_is_not_available_when_insights_is_in_scope():
    import path_analyzer as pa
    from test_path_analyzer import _lookup_client
    import data_flow
    sel = data_flow.full_path_scope_request()
    sc = pa.path_scope(sel["scopes"] + ["insights"], sel["channels"])
    c = _lookup_client()
    rt = pa.analyze(c, "drive.example.com", "off", "windows", scope=sc)["recent_traffic"]
    assert rt["in_scope"] and rt["available"] is False and "host or domain" in rt["reason"] and rt["host"] == "drive.example.com"
    rt2 = pa.analyze(_lookup_client(), "drive.example.com", "off", "windows", scope=pa.full_path_scope())["recent_traffic"]
    assert rt2["in_scope"] is False
    page = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    assert "Recent traffic to this destination" in page and "if (!rt || !rt.in_scope) return '';" in page


# ── the server: scope first, then sign-in, job, Stop, exports ─────────────
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
    (dict(CREDS, scopes=["dlp", "zia_extras"], channels={}, from_page=True), "not in scope"),
    (dict(CREDS, scopes=[], channels={}, from_page=True), "not in scope"),
    (dict(CREDS), "not in scope"),
    (dict(IN_SCOPE, auth_method="legacy", username="admin@acme.example", password="pw-pw-pw-pw", api_key="abcdefghijkl"), "OneAPI"),
    (dict(CREDS, window="365d", **IN_SCOPE), "Unknown time window"),
    (dict(CREDS, start_ms=NOW - 100 * DAY, end_ms=NOW, **IN_SCOPE), "92 days"),
    (dict(CREDS, traffic_unit="PACKETS", **IN_SCOPE), "Traffic unit"),
])
@pytest.mark.parametrize("path", ["/api/insights/start", "/api/insights"])
def test_out_of_scope_or_bad_input_is_refused_before_sign_in(monkeypatch, body, why, path):
    def no_sign_in(creds):
        raise AssertionError("signed in although refused")
    monkeypatch.setattr(srv, "_build_sdk_client", no_sign_in)
    r = TestClient(srv.app).post(path, json=body)
    assert r.status_code == 400 and why in r.text and "Nothing was read" in r.text, r.text


def test_the_job_reads_reports_and_exports_without_users_or_secrets(monkeypatch):
    t = tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    c = TestClient(srv.app)
    r = c.post("/api/insights/start", json=dict(CREDS, window="7d", traffic_unit="TRANSACTIONS", **IN_SCOPE))
    assert r.status_code == 200 and r.json()["kind"] == "insights", r.text
    snap = _poll(c, r.json()["job_id"])
    assert snap["status"] == "done", snap.get("error")
    res = snap["result"]
    assert res["tenant_label"] == "acme (production)" and res["window"]["label"] == "last 7 days"
    assert res["sections"]["top_users"]["rows"][0]["name"] == USER, "shown on screen"
    assert any("In scope, from the Scope page" in l for l in snap["all_logs"])
    assert SECRET not in json.dumps(snap) and USER not in "\n".join(snap["all_logs"])
    rid = res["report_id"]
    assert rid.startswith("insights-") and USER not in json.dumps(srv._REPORTS[rid])
    csv_r = c.get(f"/api/insights/export/{rid}?format=csv")
    assert csv_r.status_code == 200 and csv_r.headers["content-type"].startswith("text/csv") and USER not in csv_r.text and "Dropbox" in csv_r.text
    js = c.get(f"/api/insights/export/{rid}?format=json")
    assert js.status_code == 200 and USER not in js.text and json.loads(js.text)["sections"]["fw_action"]["rows"]
    assert c.get("/api/insights/export/insights-nope").status_code == 404
    assert c.get("/api/insights/export/dataflow-x").status_code == 404
    blocking = c.post("/api/insights", json=dict(CREDS, window="24h", include_users=False, **IN_SCOPE)).json()
    assert blocking["status"] == "ok" and blocking["sections"]["top_users"]["status"] == "skipped"


def test_stop_cancels_the_job_with_nothing_more_asked(monkeypatch):
    monkeypatch.setattr(insights, "PACE_SECONDS", 30.0)
    t = tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    c = TestClient(srv.app)
    jid = c.post("/api/insights/start", json=dict(CREDS, **IN_SCOPE)).json()["job_id"]
    deadline = time.time() + 10
    while not t.executor.sent and time.time() < deadline:
        time.sleep(0.02)
    assert c.post(f"/api/dlp-packs/jobs/{jid}/cancel").json()["cancelled"] is True
    snap = _poll(c, jid)
    assert snap["status"] == "cancelled" and snap["result"]["stopped"] == insights.STOPPED_REASON
    assert len(t.executor.sent) == 1 and "report_id" not in snap["result"]
    assert any("Insights query in flight" in l for l in snap["all_logs"])


def test_stop_before_start_starts_the_job_stopped(monkeypatch):
    t = tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    c = TestClient(srv.app)
    token = "insightsstoptoken01"
    assert c.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}).status_code == 200
    jid = c.post("/api/insights/start", json=dict(CREDS, **IN_SCOPE), headers={"X-Start-Token": token}).json()["job_id"]
    snap = _poll(c, jid)
    assert snap["status"] == "cancelled" and t.executor.sent == []


# ── scope option and page conventions ─────────────────────────────────────
def _read_static(name):
    return open(os.path.join(ROOT, "static", name), encoding="utf-8").read()


def test_the_scope_page_offers_insights_with_its_api_role():
    import data_flow
    import scope_permissions as sp
    html = _read_static("index.html")
    assert '<input type="checkbox" class="scope-cb" value="insights" style="width:auto;cursor:pointer;">' in html
    assert 'class="scope-cb" value="insights" checked' not in html, "traffic data is off unless ticked"
    assert "insights" in data_flow.SCOPE_KEYS and data_flow.SCOPE_LABELS["insights"] == "ZIA Insights (traffic data)"
    p = sp.get_scope_permissions("insights")
    assert p["permissions_read"] and "/zins/graphql" in p["endpoints_used"][0] and "OneAPI" in p["note"]
    assert insights.OUT_OF_SCOPE.startswith("ZIA Insights is not in scope")


def test_the_page_is_served_wired_and_explained():
    c = TestClient(srv.app)
    r = c.get("/report/insights")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = _read_static("report_insights.html")
    assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html
    assert '<a class="rp-btn" href="/">← Back to the assessment</a>' in html and '<main class="rp-card">' in html
    assert 'role="status"' in html and 'aria-live="polite"' in html and "aria-sort" in html and "<caption" in html
    order = [html.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    style = html[html.index("<style>"):html.index("</style>")]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", style) and "gradient" not in style and "box-shadow" not in style
    assert "/api/insights/start" in html and "X-Start-Token" in html and "/api/dlp-packs/jobs/stop-before-start" in html
    assert "<title>Traffic insights — Zscaler Made Easy</title>" in html
    js = _read_static("explain.js")
    assert "X.insights = {" in js and "'/report/insights': 'insights'" in js and "'insights'," in js[js.index("DLP_EXPLAIN_ORDER"):]
    assert js.index("X.insights = {") < js.index("X.digest = {")
    entry = js[js.index("X.insights = {"):]
    assert "group: 'Find the gaps', name: 'Traffic insights'" in entry[:200]
    idx = _read_static("index.html")
    assert idx.index('onclick="openInsightsTab()"') < idx.index('onclick="openDigestTab()"') and "function openInsightsTab()" in idx
    src = open(os.path.join(ROOT, "dlp_api_server.py"), encoding="utf-8").read()
    stale = src[src.index('request.url.path in ("/", "/app.css"'):]
    assert '"/report/insights"' in stale[:stale.index(")")], "never served stale"


def test_the_server_block_sits_before_the_beacon_page():
    src = open(os.path.join(ROOT, "dlp_api_server.py"), encoding="utf-8").read()
    assert src.index('@app.post("/api/insights/start")') < src.index('@app.get("/report/beacon")')
    assert src.index("# ── Traffic insights") < src.index('@app.get("/report/beacon")')
