"""URL tools (url_tools): the URLs export (every URL, domain and IP the
policy names, deduplicated with where each was found) and the custom URL
category analyzer (POST /urlLookup in batches of 100, paced, retried on
429, capped, Stop honoured; no write besides the lookup POST)."""
from __future__ import annotations

import threading
import time

import pytest

import data_flow
import url_tools as ut
from test_xlsx_writer import read_workbook

SECRET = "secret-secret-secret"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
ALL = {k: v for k, v in data_flow.full_path_scope_request().items() if k != "from_page"}
NONE = {"scopes": [], "channels": {}}
ZIA_ONLY = {"scopes": ["zia_extras"], "channels": {}}
PAC = 'function FindProxyForURL(url, host) { if (dnsDomainIs(host, ".corp.example")) { return "DIRECT"; } return "PROXY z:80"; }'


class FakeClient:
    """GETs from `routes`; POST only to /zia/urlLookup, answered by
    `classify` (url -> categories) or the queued `answers`; anything else
    fails the test."""

    def __init__(self, routes, classify=None, answers=None):
        self.routes = routes
        self.classify = classify or {}
        self.answers = list(answers or [])
        self.calls = []
        self.posts = []

    def get(self, endpoint, params=None):
        self.calls.append(("GET", endpoint))
        if endpoint == "/zcc/webPolicies":
            return (self.routes.get(endpoint, []) if (params or {}).get("deviceType") == 3 else [], 200)
        v = self.routes.get(endpoint, ({"error": "not found"}, 404))
        return (v[0], v[1]) if isinstance(v, tuple) else (v, 200)

    def post(self, endpoint, body=None):
        self.calls.append(("POST", endpoint))
        if endpoint != "/zia/urlLookup":
            raise AssertionError(f"a write: POST {endpoint}")
        self.posts.append(list(body))
        if self.answers:
            a = self.answers.pop(0)
            if a is not None:
                return a
        return [{"url": u, "urlClassifications": self.classify.get(u, []),
                 "urlClassificationsWithSecurityAlert": ["PHISHING"] if u == "phish.example" else []} for u in body], 200

    def __getattr__(self, name):
        if name in ("put", "patch", "delete", "zia", "_zs"):
            raise AssertionError(f"a write or SDK call: {name}")
        raise AttributeError(name)


CATEGORIES = [
    {"id": "CUSTOM_01", "configuredName": "Finance apps", "customCategory": True, "superCategory": "BUSINESS_AND_ECONOMY",
     "urls": ["bank.example.com", "https://Bank.example.com/", "pay.example.com/login"], "dbCategorizedUrls": ["news.example"],
     "keywords": ["invoice"], "ipRanges": ["198.51.100.0/24"]},
    {"id": "CUSTOM_02", "configuredName": "Dev tools", "customCategory": True, "superCategory": "USER_DEFINED", "urls": ["git.example"]},
    {"id": "FINANCE", "configuredName": "Finance", "superCategory": "BUSINESS_AND_ECONOMY"},
]
ROUTES = {
    "/zia/urlCategories": CATEGORIES,
    "/zia/urlFilteringRules": [{"id": 1, "name": "Allow finance", "order": 1, "action": "ALLOW", "urlCategories": ["CUSTOM_01"]}],
    "/zia/sslInspectionRules": [{"id": 2, "name": "Do not inspect banks", "order": 1, "action": {"type": "DO_NOT_DECRYPT"},
                                 "urlCategories": ["CUSTOM_01"], "destIpGroups": [{"id": 7, "name": "Bank IPs"}]}],
    "/zia/firewallFilteringRules": [{"id": 3, "name": "Block bad", "order": 1, "action": "BLOCK_DROP",
                                     "destAddresses": ["evil.example.com", "BANK.example.com"], "destIpGroups": [{"id": 7}]}],
    "/zia/ipDestinationGroups": [{"id": 7, "name": "Bank IPs", "type": "DSTN_IP", "addresses": ["203.0.113.0/24"]}],
    "/zia/advancedSettings": {"authBypassUrls": [".login.example"], "kerberosBypassUrls": []},
    "/zcc/webPolicies": [{"id": 1, "name": "Windows default", "deviceType": 3, "bypassDomains": ["bank.example.com"], "ipExclusions": ["10.0.0.0/8"]}],
    "/zcc/forwardingProfiles": [], "/zcc/trustedNetworks": [],
    "/zia/pacFiles": [{"id": 5, "name": "Corp PAC", "pacContent": PAC}],
}


# ── URLs export ────────────────────────────────────────────────────────
def test_the_urls_export_collects_every_source_and_dedupes_with_found_in():
    c = FakeClient(ROUTES)
    src = ut.sources_for(**ALL)
    assert src["read"] == list(ut.SOURCES)
    out = ut.urls_export(c, src, tenant_label="acme (production)")
    assert out["status"] == "ready" and out["errors"] == {}
    book = read_workbook(out["artifact"][2])
    assert list(book) == ["Summary", "URLs", "Occurrences"]
    head = book["URLs"][0]
    assert head == ["Value", "Kind", "Found in", "Sources", "Lists", "Categories", "Rules or profiles", "Times found"]
    rows = {r[0].lower().rstrip("/"): dict(zip(head, r)) for r in book["URLs"][1:]}
    bank = rows["bank.example.com"]
    # The same host twice in a category (scheme and case aside), so twice
    # again through each of the two rules that use it, a firewall rule and
    # Client Connector: one row, found 8 times.
    assert sum(1 for k in rows if "bank.example.com" in k) == 1
    assert bank["Times found"] == "8"
    for src_name in ("Custom URL category", "URL filtering rule", "SSL inspection rule", "Cloud Firewall rule", "Client Connector app profile"):
        assert src_name in bank["Sources"], src_name
    assert "URL filtering rule · URLs · Finance apps · rule Allow finance · Allow" in bank["Found in"]
    assert "SSL inspection rule · URLs · Finance apps · rule Do not inspect banks · Do not decrypt" in bank["Found in"]
    assert rows["pay.example.com/login"]["Kind"] == "URL" and rows["invoice"]["Kind"] == "Keyword"
    assert rows["198.51.100.0/24"]["Kind"] == "IP address or range" and rows["news.example"]["Lists"].startswith("URLs retaining parent category")
    assert "Destination IP group" in rows["203.0.113.0/24"]["Lists"] and "IP destination group" in rows["203.0.113.0/24"]["Sources"]
    assert rows[".login.example"]["Sources"] == "Advanced settings"
    assert rows[".corp.example"]["Found in"] == "PAC file · Sent DIRECT · Corp PAC"
    assert rows["10.0.0.0/8"]["Lists"] == "IP bypass" and rows["evil.example.com"]["Rules or profiles"] == "Block bad"
    assert "git.example" in rows    # an unused custom category is still part of the policy
    occ = book["Occurrences"]
    assert occ[0] == ["Value", "Kind", "Source", "List", "Category", "Rule or profile", "Action"] and len(occ) - 1 == out["occurrences"]
    assert all(m == "GET" for m, _ in c.calls)


def test_the_urls_export_reads_only_what_is_in_scope():
    src = ut.sources_for(**ZIA_ONLY)
    assert set(src["read"]) == {"custom_categories", "url_filtering", "firewall", "advanced_settings"}
    assert "ssl_inspection" in src["not_in_scope"] and "client_connector" in src["not_in_scope"]
    c = FakeClient(ROUTES)
    out = ut.urls_export(c, src)
    eps = [e for _, e in c.calls]
    assert not [e for e in eps if e.startswith("/zcc/") or e in ("/zia/pacFiles", "/zia/sslInspectionRules")], eps
    book = read_workbook(out["artifact"][2])
    summary = dict((r[0], r[1]) for r in book["Summary"][1:])
    assert summary["Not in scope: Client Connector bypasses"].startswith("Not in scope")
    assert ut.sources_for(**NONE)["read"] == []


def test_a_source_that_cannot_be_read_is_named():
    c = FakeClient(dict(ROUTES, **{"/zia/firewallFilteringRules": ({"error": "no"}, 403)}))
    out = ut.urls_export(c, ut.sources_for(**ALL))
    assert out["errors"]["firewall"] == "Permission denied"
    summary = dict((r[0], r[1]) for r in read_workbook(out["artifact"][2])["Summary"][1:])
    assert summary["Could not be read: Cloud Firewall rules and IP destination groups"] == "Permission denied"


# ── Category analyzer ──────────────────────────────────────────────────
LITE = [{"id": "CUSTOM_01", "configuredName": "Finance apps", "customCategory": True, "superCategory": "BUSINESS_AND_ECONOMY"},
        {"id": "CUSTOM_02", "configuredName": "Dev tools", "customCategory": True, "superCategory": "USER_DEFINED"},
        {"id": "CUSTOM_03", "configuredName": "Big list", "customCategory": True, "superCategory": "BUSINESS_AND_ECONOMY"},
        {"id": "FINANCE", "configuredName": "Finance", "superCategory": "BUSINESS_AND_ECONOMY"},
        {"id": "SOCIAL_NETWORKING", "configuredName": "Social networking", "superCategory": "INTERNET_COMMUNICATION"}]
BIG = [f"host{i}.example" for i in range(250)]


def _analyzer_routes():
    return {"/zia/urlCategories/lite": LITE,
            "/zia/urlCategories/CUSTOM_01": {"id": "CUSTOM_01", "urls": ["bank.example.com", "social.example", "new.example", "phish.example",
                                                                         "odd.example"],
                                             "dbCategorizedUrls": ["https://bank.example.com"]},
            "/zia/urlCategories/CUSTOM_02": {"id": "CUSTOM_02", "urls": ["git.example"]},
            "/zia/urlCategories/CUSTOM_03": {"id": "CUSTOM_03", "urls": BIG}}


CLASSIFY = {"bank.example.com": ["FINANCE"], "social.example": ["SOCIAL_NETWORKING"], "new.example": ["MISCELLANEOUS_OR_UNKNOWN"],
            "phish.example": [], "odd.example": ["SOME_NEW_CATEGORY"], "git.example": ["FINANCE"]}


def test_the_analyzer_classifies_each_url():
    c = FakeClient(_analyzer_routes(), CLASSIFY)
    waits = []
    res = ut.analyze_categories(c, picked=["Finance apps", "CUSTOM_02", "NOPE"], sleep=waits.append)
    assert res["status"] == "ready"
    v = {(r["category"], r["url"], r["list"]): r for r in res["rows"]}
    assert v[("Finance apps", "bank.example.com", "URLs")]["verdict"] == "redundant"
    assert v[("Finance apps", "bank.example.com", "URLs")]["zscaler_categories"] == ["Finance"]
    assert v[("Finance apps", "social.example", "URLs")]["verdict"] == "different"
    assert v[("Finance apps", "new.example", "URLs")]["verdict"] == "uncategorised"
    assert v[("Finance apps", "phish.example", "URLs")]["verdict"] == "uncategorised"
    assert v[("Finance apps", "phish.example", "URLs")]["security_alerts"] == ["PHISHING"]
    assert v[("Finance apps", "odd.example", "URLs")]["verdict"] == "categorised"     # its super category is not known
    retain = v[("Finance apps", "https://bank.example.com", "URLs retaining parent category")]
    assert retain["verdict"] == "redundant" and "retain its parent category" in retain["why"]
    assert v[("Dev tools", "git.example", "URLs")]["verdict"] == "different"         # a user-defined custom category overrides
    assert any("NOPE" in n for n in res["notes"]) and res["totals"]["redundant"] == 2
    # One lookup for the distinct URLs (the scheme-only duplicate is asked once); the category list and each picked category read.
    assert c.posts == [["bank.example.com", "social.example", "new.example", "phish.example", "odd.example", "git.example"]]
    gets = [e for m, e in c.calls if m == "GET"]
    assert gets == ["/zia/urlCategories/lite", "/zia/urlCategories/CUSTOM_01", "/zia/urlCategories/CUSTOM_02"]
    assert [m for m, e in c.calls if m == "POST"] == ["POST"] and waits == []
    book = read_workbook(ut.analyzer_workbook(res, tenant_label="acme"))
    assert list(book) == ["Summary", "Per category", "URLs"]
    assert book["URLs"][0][:6] == ["Category", "List", "URL", "Zscaler categories", "Security alert categories", "Verdict"]


def test_lookups_are_batched_paced_and_capped():
    c = FakeClient(_analyzer_routes(), CLASSIFY)
    waits = []
    res = ut.analyze_categories(c, picked=["CUSTOM_03"], sleep=waits.append, pace=1.0)
    assert [len(p) for p in c.posts] == [100, 100, 50]
    assert sum(waits) == pytest.approx(2.0)        # one pace between each pair of requests, none before the first
    assert res["lookup"]["requests"] == 3 and res["totals"]["uncategorised"] == 250
    c2 = FakeClient(_analyzer_routes(), CLASSIFY)
    capped = ut.analyze_categories(c2, picked=["CUSTOM_03"], max_urls=150, sleep=lambda s: None)
    assert [len(p) for p in c2.posts] == [100, 50]
    assert capped["totals"]["not_looked_up"] == 100 and capped["lookup"]["over_cap"] == 100
    assert any(n.startswith("Capped at 150 URLs: 100 more") for n in capped["notes"])
    assert all(r["why"] == "Not looked up: over the cap." for r in capped["rows"] if r["verdict"] == "not_looked_up")
    # The cap can be lowered, never raised.
    c3 = FakeClient(_analyzer_routes(), CLASSIFY)
    ut.analyze_categories(c3, picked=["CUSTOM_03"], max_urls=10 ** 6, sleep=lambda s: None)
    assert sum(len(p) for p in c3.posts) == 250 <= ut.MAX_LOOKUP_URLS


def test_a_429_is_retried_with_a_growing_wait_and_then_given_up():
    rate = ({"error": "rate limited", "status": 429}, 429)
    c = FakeClient(_analyzer_routes(), CLASSIFY, answers=[rate, rate, None])
    waits = []
    res = ut.analyze_categories(c, picked=["CUSTOM_02"], sleep=waits.append, pace=1.0)
    assert len(c.posts) == 3 and res["lookup"]["retries"] == 2 and res["rows"][0]["verdict"] == "different"
    assert sum(waits) == pytest.approx(2.0 + 4.0)
    c2 = FakeClient(_analyzer_routes(), CLASSIFY, answers=[rate] * 4)
    res2 = ut.analyze_categories(c2, picked=["CUSTOM_02"], sleep=lambda s: None)
    assert len(c2.posts) == 1 + ut.RETRIES and res2["rows"][0]["verdict"] == "not_looked_up"
    assert res2["rows"][0]["why"] == "Not looked up: rate limited (HTTP 429) after retries."
    refused = FakeClient(_analyzer_routes(), CLASSIFY, answers=[({"error": "bad"}, 400)])
    res3 = ut.analyze_categories(refused, picked=["CUSTOM_02"], sleep=lambda s: None)
    assert len(refused.posts) == 1 and "HTTP 400" in res3["rows"][0]["why"]


def test_stop_ends_the_analyzer_during_a_wait_and_before_a_request():
    stop = threading.Event()
    c = FakeClient(_analyzer_routes(), CLASSIFY)

    def sleep(s):
        stop.set()      # Stop pressed while waiting between two lookups
    with pytest.raises(ut.Stopped):
        ut.analyze_categories(c, picked=["CUSTOM_03"], sleep=sleep, cancel=stop)
    assert len(c.posts) == 1
    stop2 = threading.Event()
    stop2.set()
    c2 = FakeClient(_analyzer_routes(), CLASSIFY)
    with pytest.raises(ut.Stopped):
        ut.analyze_categories(c2, cancel=stop2)
    assert c2.calls == []


def test_the_analyzer_says_when_the_categories_cannot_be_read():
    c = FakeClient({"/zia/urlCategories/lite": ({"error": "no"}, 403)})
    res = ut.analyze_categories(c, sleep=lambda s: None)
    assert res["status"] == "error" and "Permission denied" in res["error"] and c.posts == []


# ── API ────────────────────────────────────────────────────────────────
def _wait(t, job):
    deadline = time.time() + 20
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("the job never ended")


def _api(monkeypatch, client):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    signed = []

    def sign_in(req):
        signed.append(1)
        return client
    monkeypatch.setattr(srv, "_build_client", sign_in)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no SDK client")))
    monkeypatch.setattr(ut, "PACE_SECONDS", 0.0)
    return TestClient(srv.app), signed


def test_the_api_jobs_serve_their_workbooks(monkeypatch):
    c = FakeClient(dict(ROUTES, **_analyzer_routes()), CLASSIFY)
    t, signed = _api(monkeypatch, c)
    r = t.post("/api/exports/urls/start", json=dict(CREDS, **ALL, from_page=True))
    assert r.status_code == 200 and r.json()["kind"] == "urls_export", r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    d = t.get(snap["download"])
    assert d.status_code == 200 and "URLs" in read_workbook(d.content)
    r = t.post("/api/exports/url-categories/analyze/start", json=dict(CREDS, **ALL, from_page=True, categories=["CUSTOM_02"]))
    assert r.status_code == 200 and r.json()["kind"] == "category_analyzer", r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    assert snap["result"]["rows"][0]["verdict"] == "different" and snap["filename"].startswith("url_category_analysis_acme")
    assert "Per category" in read_workbook(t.get(snap["download"]).content)
    assert SECRET not in str(snap)
    assert {e for m, e in c.calls if m == "POST"} == {"/zia/urlLookup"}


def test_the_api_refuses_before_signing_in(monkeypatch):
    t, signed = _api(monkeypatch, FakeClient(ROUTES))
    r = t.post("/api/exports/urls/start", json=dict(CREDS, **NONE, from_page=True))
    assert r.status_code == 400 and r.json()["detail"] == ut.NOTHING_IN_SCOPE_URLS
    r = t.post("/api/exports/url-categories/analyze/start", json=dict(CREDS, scopes=["zcc"], channels={}, from_page=True))
    assert r.status_code == 400 and r.json()["detail"] == ut.NOTHING_IN_SCOPE_CATS
    r = t.post("/api/exports/url-categories/analyze/start", json=dict(CREDS, **ALL, from_page=True, max_urls=-1))
    assert r.status_code == 400
    assert signed == []


def test_the_plans_listing_reads_no_tenant(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    monkeypatch.setattr(srv, "_PLANS", {})
    rid = srv._remember_plan({"tenant_label": "acme", "packs": [{"id": "cjis", "name": "CJIS"}], "status": "ready"}, "Jane")
    r = TestClient(srv.app).get("/api/exports/plans")
    assert r.status_code == 200 and r.json()["plans"][0]["report_id"] == rid and r.json()["plans"][0]["packs"] == ["CJIS"]
