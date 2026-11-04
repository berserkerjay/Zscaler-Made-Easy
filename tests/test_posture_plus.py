"""Improve my score (posture_plus.py, /report/posture): points gained from
the real score formula, the projected score, the trend with its causes,
score-drop alerts (never sent unless the operator set notifications up and
ticked it), the coverage list, and the history format staying backward
compatible. Nothing here reads a tenant."""
from __future__ import annotations

import json
import os
import re

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient

import continuous_eval as ce
import dlp_api_server as srv
import posture_plus as pp
import security
import tenant_profiles as tp
from dlp_assessment_full_auto import compute

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setenv("DLP_CHECK_POSTURE_SETTINGS", str(tmp_path / "posture_settings.json"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_DIGESTS", str(tmp_path / "digests"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLPCHECK_CHANGE_QUEUE_FILE", str(tmp_path / "change_requests.json"))
    monkeypatch.setenv("DLP_CHECK_GUIDANCE_STATE", str(tmp_path / "guidance_state.json"))
    monkeypatch.setenv("DLP_CHECK_CHECKS_CONFIG", str(tmp_path / "checks_config.json"))
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX", str(tmp_path / "saas_apps.local.json"))
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX_REFRESH", "0")
    for k in ("DLP_CHECK_SMTP_HOST", "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK", "DLP_CHECK_NOTIFY"):
        monkeypatch.delenv(k, raising=False)
    # Standing rule: no notification ever leaves a test run.
    def _never(*a, **k):
        raise AssertionError("a notification was about to be sent")
    monkeypatch.setattr(ce, "_send_email", _never)
    monkeypatch.setattr(ce, "_send_webhook", _never)
    monkeypatch.setattr("requests.post", _never)
    monkeypatch.setattr("bp_crawler.last_summary", lambda: {})
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    # And no tenant read from any posture endpoint.
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("tenant read")))


def _c(cid, sec, label, status, detail=""):
    return {"id": cid, "sec": sec, "label": label, "status": status, "detail": detail}


CHECKS = [
    _c("4.1", "4 — SSL Policy", "Inspection scope", "FAIL", "No SSL inspection rule. Ref: https://help.zscaler.com/zia/about-ssl-inspection"),
    _c("4.3", "4 — SSL Policy", "Rule order", "PASS"),
    _c("A.2", "Ch.A — Inline Web", "SSL+DNI", "FAIL"),
    _c("A.1", "Ch.A — Inline Web", "Rule count", "PASS"),
    _c("1.8", "1 — CC Portal", "Strict Enforcement", "FAIL"),
    _c("8.1", "8 — Pilot Tests", "USB/Removable", "REVIEW"),
    _c("5.10", "5 — Endpoint DLP", "Dictionaries", "PASS"),
    _c("5.12", "5 — Endpoint DLP", "Detection methods", "REVIEW"),
    _c("5.14", "5 — Endpoint DLP", "EDM", "INFO", "EDM: not readable (HTTP 403 on /zia/dlpDictionaries). Access denied. The API client role does not include this feature."),
    _c("12.8", "12 — Incident Mgmt", "NSS/SIEM", "ERROR", "NSS/SIEM: Could not be checked: the tenant did not answer 1 read(s) (rate limited (HTTP 429); /zia/nssFeeds). Run the assessment again later."),
    _c("12.9", "12 — Incident Mgmt", "NSS DLP fields", "ERROR", "NSS DLP fields: Check timed out after 60 seconds; the tenant did not answer in time."),
    _c("MC.4", "Multi-Channel", "Email DLP", "INFO", "Outbound Email DLP is not licensed or not enabled on this tenant (the API answered 404)."),
    _c("MC.6", "Multi-Channel", "Data Discovery", "INFO", "No discovery scan configured."),
    dict(_c("C.1", "Ch.C — SaaS Security", "SaaS tenants", "FAIL"), out_of_scope=True),
]


def _client():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


# ── 1. points gained ───────────────────────────────────────────────────
def test_points_gained_matches_the_recomputed_score():
    rows = [c for c in CHECKS if not c.get("out_of_scope")]
    _secs, now = compute(rows)
    assert pp.score_of(CHECKS) == now == round(3 / 8 * 100)   # 3 configured of 8 scoreable; INFO/ERROR and out of scope excluded
    r = pp.ranking(CHECKS)
    assert r["score"] == now and r["failing"] == 5 and r["scored"] == 8 and r["per_check"] == 12.5
    ids = [f["id"] for f in r["top"]]
    assert sorted(ids) == sorted(["4.1", "A.2", "1.8", "8.1", "5.12"])   # never INFO, ERROR or an out-of-scope check
    for f in r["top"]:
        fixed = [dict(c, status="PASS") if c["id"] == f["id"] else c for c in rows]
        _s, after = compute(fixed)
        assert f["score_after"] == after and f["points"] == after - now, f
        assert f["steps"] and f["steps"][-1].startswith("Run the assessment again")
    # Every check weighs the same, so the order is by effort, then the one-click fix.
    first = r["top"][0]
    assert first["effort"] == "low" and first["one_click"] and first["recipe"]["id"] == "SSL-01"
    assert [f["effort"] for f in r["top"]] == sorted([f["effort"] for f in r["top"]], key=pp.EFFORT_RANK.get)
    by = {f["id"]: f for f in r["top"]}
    assert by["8.1"]["effort"] == "high" and by["1.8"]["effort"] == "medium" and by["5.12"]["effort"] == "low"
    assert by["4.1"]["guidance_url"].startswith("https://help.zscaler.com/") and by["4.1"]["also_fixes"] == ["A.2"]
    # The SSL recipe answers two failing checks: one bundle, its points recomputed too.
    b = r["bundles"][0]
    assert b["recipe"] == "SSL-01" and sorted(b["checks"]) == ["4.1", "A.2"]
    assert b["score_after"] == compute([dict(c, status="PASS") if c["id"] in ("4.1", "A.2") else c for c in rows])[1]
    assert pp.ranking(CHECKS, limit=2)["top"] == r["top"][:2]


def test_nothing_scoreable_has_no_points_and_no_invented_score():
    only_info = [_c("MC.4", "Multi-Channel", "Email DLP", "INFO", "not licensed (404)")]
    r = pp.ranking(only_info)
    assert r["score"] is None and r["top"] == [] and r["per_check"] is None
    p = pp.project(only_info, ["MC.4"])
    assert p["projected"] is None and p["fixed"] == [] and p["ignored"] == ["MC.4"]


# ── 2. projected score ─────────────────────────────────────────────────
def test_projected_score_from_ticked_fixes_and_the_change_queue():
    import change_queue as cq
    rows = [c for c in CHECKS if not c.get("out_of_scope")]
    p = pp.project(CHECKS, ["8.1", "5.10", "nope"])
    assert p["fixed"] == ["8.1"] and p["projected"] == compute([dict(c, status="PASS") if c["id"] == "8.1" else c for c in rows])[1]
    assert p["ignored"] == ["5.10", "nope"]   # already passing or unknown: not a fix
    rec = cq.file_request(kind="fix_recipe", tenant="acme", tenant_label="acme", title="Add SSL rule (check 4.1)", summary={}, items=[],
                          plan_hash="h1", requested_by="alice", payload={"check_id": "4.1", "recipe": "SSL-01", "criteria": {}})
    cq.file_request(kind="pack_deploy", tenant="acme", tenant_label="acme", title="Deploy pack", summary={}, items=[],
                    plan_hash="h2", requested_by="alice", payload={"pack_ids": ["x"]})
    cq.file_request(kind="fix_recipe", tenant="other", tenant_label="other", title="Other tenant", summary={}, items=[],
                    plan_hash="h3", requested_by="alice", payload={"check_id": "A.2"})
    reqs = cq.list_requests("acme", ["pending", "approved"])
    p = pp.project(CHECKS, ["8.1"], reqs)
    assert p["fixed"] == ["4.1", "8.1"] and [x["request"] for x in p["queue"]["counted"]] == [rec["id"]]
    assert p["queue"]["not_counted"][0]["kind"] == "pack_deploy" and "next assessment" in p["queue"]["not_counted"][0]["why"]
    assert p["points"] == p["projected"] - p["score"] == 62 - 38   # 5 of 8 is 62.5, rounded as the engine rounds
    # Through the API: several tenants in the queue, so none is counted until one is chosen.
    c = _client()
    body = {"checks": CHECKS, "selected": ["8.1"]}
    d = c.post("/api/posture/project", json=body).json()
    assert d["queue_tenant"] == "" and d["fixed"] == ["8.1"] and {t["key"] for t in d["queue_tenants"]} == {"acme", "other"}
    d = c.post("/api/posture/project", json=dict(body, queue_tenant="acme")).json()
    assert d["fixed"] == ["4.1", "8.1"]
    d = c.post("/api/posture/project", json=dict(body, queue_tenant="acme", include_queue=False)).json()
    assert d["fixed"] == ["8.1"]


# ── 3. trend with causes ───────────────────────────────────────────────
def _entry(at, score, states):
    return {"at": at, "score": score, "maturity": "x", "checks": len(states), "states": states}


def test_trend_says_which_checks_changed_between_runs():
    h = [_entry("2026-01-01T00:00:00+00:00", 80, {"4.1": "P", "A.2": "P", "1.8": "P", "8.1": "R", "5.10": "F"}),
         {"at": "2026-01-15T00:00:00+00:00", "detection_health": {"incidents": 3}, "continuous_evaluation": True},
         _entry("2026-02-01T00:00:00+00:00", 74, {"4.1": "F", "A.2": "F", "1.8": "R", "8.1": "R", "5.10": "P", "9.9": "E"})]
    t = pp.trend(h, CHECKS)
    assert t["runs"] == 2 and [p["score"] for p in t["points"]] == [80, 74]
    ch = t["changes"][0]
    assert ch["delta"] == -6 and ch["recorded"]
    assert [x["id"] for x in ch["newly_failing"]] == ["1.8", "4.1", "A.2"] and ch["newly_failing"][1]["label"] == "Inspection scope"
    assert [x["id"] for x in ch["newly_passing"]] == ["5.10"] and [x["id"] for x in ch["other"]] == ["9.9"]
    assert ch["sentence"] == "Your score dropped 6 points because these 3 checks started failing and this check started passing."
    assert pp.sentence({"delta": 2, "recorded": True, "newly_passing": [{}]}) == "Your score rose 2 points because this check started passing."


def test_history_stays_backward_compatible(tmp_path):
    # A profile file written before per-check states: entries with no
    # `states`, one with a null score, and the loop's own entries.
    old = {"version": 1, "profiles": {"acme": {"id": "acme", "name": "Acme", "history": [
        {"at": "2025-01-01T00:00:00+00:00", "score": 60, "maturity": "Developing", "checks": 100, "critical": 4, "assessor": "a"},
        {"at": "2025-02-01T00:00:00+00:00", "journey": {"stage": 2, "score": 40}, "continuous_evaluation": True},
        {"at": "2025-03-01T00:00:00+00:00", "score": None, "maturity": "Not assessed", "checks": 0, "critical": 0}]}}}
    (tmp_path / "tenant_profiles.json").write_text(json.dumps(old), encoding="utf-8")
    hist = tp.get("acme")["history"]
    t = pp.trend(hist)
    assert t["runs"] == 2 and t["points"][0]["recorded"] is False
    assert t["changes"][0]["recorded"] is False and t["changes"][0]["delta"] is None
    assert pp.latest_drop(hist) is None
    # A new run is appended with its states; the old ones still load beside it.
    rep = {"score": 50, "maturity": "Developing", "checks": CHECKS, "critical": [], "metadata": {"assessor": "b"}}
    tp.add_history("acme", tp.snapshot(rep))
    hist = tp.get("acme")["history"]
    assert hist[-1]["states"]["4.1"] == "F" and hist[-1]["states"]["5.14"] == "I" and "C.1" not in hist[-1]["states"]
    assert len(hist[-1]["states"]) <= pp.MAX_STATES and "states" not in tp.list_profiles()[0]["last_assessed"]
    t = pp.trend(hist)
    assert t["changes"][0]["recorded"] is False and t["changes"][0]["sentence"].startswith("No score to compare")
    assert "not recorded for the older run" in pp.diff(hist[0], hist[-1])["sentence"]   # 60 (no states) → 50 (states)
    worse = [dict(c, status="FAIL") if c["id"] == "4.3" else c for c in CHECKS]
    tp.add_history("acme", tp.snapshot(dict(rep, score=pp.score_of(worse), checks=worse)))
    newest = pp.trend(tp.get("acme")["history"])["changes"][0]
    assert newest["recorded"] and [x["id"] for x in newest["newly_failing"]] == ["4.3"]
    big = [_c(f"X.{i}", "S", "L", "PASS") for i in range(pp.MAX_STATES + 50)]
    assert len(pp.states_of(big)) == pp.MAX_STATES


# ── 4. score-drop alerts ───────────────────────────────────────────────
def test_alert_threshold_and_settings():
    assert pp.settings() == {"score_drop_points": 5, "notify_score_drop": False}
    assert pp.score_drop(80, 75) == 5 and pp.score_drop(80, 76) is None and pp.score_drop(None, 10) is None
    assert pp.score_drop(80, 77, threshold=3) == 3
    h = [_entry("2026-01-01T00:00:00+00:00", 80, {"4.1": "P"}), _entry("2026-02-01T00:00:00+00:00", 72, {"4.1": "F"})]
    a = pp.latest_drop(h, current=CHECKS)
    assert a["points"] == 8 and a["from"] == 80 and a["to"] == 72 and a["newly_failing"][0]["id"] == "4.1"
    assert pp.latest_drop(h, threshold=9) is None
    assert pp.save_settings({"score_drop_points": "250", "notify_score_drop": "yes"}) == {"score_drop_points": 100, "notify_score_drop": False}
    c = _client()
    r = c.put("/api/posture/settings", json={"score_drop_points": 3, "notify_score_drop": True})
    assert r.status_code == 200 and c.get("/api/posture/settings").json() == {"score_drop_points": 3, "notify_score_drop": True}
    assert "posture_settings" in read_store_text(os.environ["DLP_CHECK_AUDIT"])


def _profile_with_drop():
    p = tp.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "scopes": []},
                  client_secret="secret-secret-secret", remember_secret=True)
    tp.add_history(p["id"], _entry("2026-01-01T00:00:00+00:00", 80, {"4.1": "P", "A.2": "P"}))
    tp.add_history(p["id"], _entry("2026-02-01T00:00:00+00:00", 70, {"4.1": "F", "A.2": "F"}))
    return p["id"]


def test_continuous_evaluation_lists_the_drop_once_and_sends_nothing(monkeypatch):
    pid = _profile_with_drop()
    # Notifications configured, mode "noteworthy": a drop alone must still not send
    # (notify_score_drop is off by default). The senders raise if called.
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "https://example.webhook.office.com/webhookb2/abc")
    d = ce.run_once(build_client=lambda creds: (_ for _ in ()).throw(AssertionError("tenant read")), notify=True)
    t = d["tenants"][0]
    assert t["profile_id"] == pid and t["note"].startswith("nothing in scope")   # nothing read
    a = t["score_alerts"][0]
    assert a["kind"] == "assessment" and a["points"] == 10 and a["threshold"] == 5 and a["notify"] is False
    assert [x["id"] for x in a["newly_failing"]] == ["4.1", "A.2"]
    assert d["summary"]["score_drops"] == 1 and not d["noteworthy"]
    assert d["notified"][0]["channel"] == "none" and d["notified"][0]["sent"] is False
    md = ce.to_markdown(ce.get_digest(d["id"]))
    assert "Score drop:" in md and "80% → 70%" in md and "started failing: 4.1" in md and "1 score drop(s)" in md
    # The banner endpoint shows it; the next loop run does not report it again.
    s = _client().post("/api/posture/summary", json={"checks": CHECKS, "profile_id": pid}).json()
    assert s["alert"]["points"] == 10 and s["digest_alerts"][0]["kind"] == "assessment"
    d2 = ce.run_once(build_client=lambda creds: (_ for _ in ()).throw(AssertionError("tenant read")), notify=False)
    assert d2["tenants"][0]["score_alerts"] == []
    # Turned on: the drop makes the digest noteworthy, so the configured
    # channels would be used. With none configured nothing is sent either.
    monkeypatch.delenv("DLP_CHECK_DIGEST_WEBHOOK")
    pp.save_settings({"score_drop_points": 5, "notify_score_drop": True})
    tp.add_history(pid, _entry("2026-03-01T00:00:00+00:00", 60, {"4.1": "F", "A.2": "F"}))
    d3 = ce.run_once(build_client=lambda creds: (_ for _ in ()).throw(AssertionError("tenant read")), notify=True)
    assert d3["tenants"][0]["score_alerts"][0]["notify"] is True and d3["noteworthy"]
    assert d3["notified"][0]["sent"] is False and "no e-mail or webhook configured" in d3["notified"][0]["why"]


def test_journey_score_drop_from_the_loop():
    t = {"drift": {"score": 40, "previous_score": 55, "measured_at": "now"}}
    a = pp.tenant_alerts(t, [], cfg={"score_drop_points": 5, "notify_score_drop": False})
    assert a[0]["kind"] == "journey" and a[0]["points"] == 15
    assert pp.tenant_alerts({"drift": {"score": 52, "previous_score": 55}}, [], cfg={"score_drop_points": 5, "notify_score_drop": False}) == []
    assert ce._last_journey_score({"history": [{"journey": {"score": 30}}, {"journey": {"score": 45}}, {"score": 1}]}) == 45


# ── 5. coverage ────────────────────────────────────────────────────────
FIXTURE_LOGS = [
    "Reading the tenant: DLP dictionaries (custom and predefined)…",
    "Reading the tenant: Web DLP rules could not be listed: HTTP 403 Forbidden on /zia/webDlpRules",
    "ZIA refused the read of the endpoint DLP rules (rate limit / Resource Access Blocked); waiting 30s before trying again",
    "Console index: dictionaries capped at 300 per kind (41 more not shown)",
    "Reading the tenant: Email DLP rules: 4 found.",
]


def test_coverage_list_from_results_scope_and_fixture_logs():
    rep = {"checks": CHECKS, "hidden_checks": 7,
           "channel_coverage": {"alternative": [{"id": "saas_casb", "name": "SaaS Security", "checks_not_in_scope": 5}], "gaps": [], "hidden": 7}}
    cov = pp.coverage(rep, FIXTURE_LOGS)
    # 13 visible checks; 3 did not run (403, 429, timeout). Not licensed ran and answered.
    assert cov["total"] == 13 and cov["not_ran"] == 3 and cov["pct"] == 77
    assert cov["sentence"].startswith("Coverage: 77% of checks ran (10 of 13).")
    cats = {(g["category"], g["area"]): g for g in cov["items"]}
    perm = cats[("permission", "5 — Endpoint DLP")]
    assert perm["checks"][0]["id"] == "5.14" and "DLP Dictionaries" in perm["fix"] and "ZIdentity > API Clients" in perm["fix"]
    assert ("rate_limit", "12 — Incident Mgmt") in cats and ("timeout", "12 — Incident Mgmt") in cats
    assert cats[("not_licensed", "Multi-Channel")]["checks"][0]["id"] == "MC.4"
    assert not any(x["id"] == "MC.6" for g in cov["items"] for x in g["checks"])   # an answered INFO is not a gap
    assert cats[("scope", "SaaS Security")]["count"] == 5 and cats[("scope", "Selected scopes")]["count"] == 2
    assert "Web DLP Rules" in cats[("permission", "Web DLP")]["fix"]
    assert ("rate_limit", "Tenant reads") in cats and ("capped", "Tenant reads") in cats
    assert not any("Email DLP rules: 4 found" in g["why"] for g in cov["items"])   # an ordinary log line is not a gap
    assert [g["category"] for g in cov["items"]] == sorted((g["category"] for g in cov["items"]), key=list(pp.CATEGORIES).index)
    for g in cov["items"]:
        assert g["area"] and g["what"] and g["why"] and g["fix"]
    assert pp.coverage({})["pct"] is None


# ── API and page ───────────────────────────────────────────────────────
def test_analyze_endpoint_returns_every_part_without_a_tenant_read():
    pid = _profile_with_drop()
    c = _client()
    d = c.post("/api/posture/analyze", json={"checks": CHECKS, "profile_id": pid, "selected": ["4.1"]}).json()
    assert d["ranking"]["score"] == 38 and len(d["ranking"]["top"]) == 5
    assert d["projection"]["fixed"] == ["4.1"] and d["trend"]["runs"] == 2 and d["alert"]["points"] == 10
    assert d["coverage"]["pct"] == 77 and d["settings"]["score_drop_points"] == 5
    assert c.post("/api/posture/analyze", json={"checks": [{"id": "1"}] * 3001}).status_code == 413
    empty = c.post("/api/posture/analyze", json={}).json()
    assert empty["ranking"]["top"] == [] and empty["trend"]["runs"] == 0 and empty["alert"] is None


def test_the_page_is_served_wired_and_explained():
    c = _client()
    r = c.get("/report/posture")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', 'href="/"', "<main", "<h1>",
                   'id="liveRegion" class="sr-only" role="status" aria-live="polite"', '<th scope="col">', "/api/posture/analyze",
                   "/api/posture/project", "/api/posture/settings", "Top 10 fixes that raise your score most", 'id="coverage"', 'id="trend"',
                   "__assessmentReport", "openRemediationWizard", "glossary.js", "Zscaler Made Easy"):
        assert needle in html, needle
    assert "DLP-Check" not in html and "Zscaler Made Easy" in html   # new user-visible text uses the new product name
    order = [html.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    style = html.split("<style>")[1].split("</style>")[0]
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", style) and "gradient" not in style and "box-shadow" not in style
    assert "prefers-reduced-motion" in html and ":focus-visible" in html and 'style="' not in html.split("</style>")[1]
    index = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert 'onclick="openPostureTab()"' in index and "window.open('/report/posture', '_blank')" in index
    explain = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    assert "group: 'Find the gaps', name: 'Improve my score'" in explain and "'/report/posture': 'posture'" in explain
    assert "'compliance', 'posture'" in explain and "['Projected score'," in explain and "['Coverage'," in explain
    glossary = open(os.path.join(ROOT, "static", "glossary.js"), encoding="utf-8").read()
    assert "'projected score':" in glossary and "'coverage':" in glossary and "'score drop':" in glossary
    home = c.get("/").text
    assert "/static/posture_banner.js" in home and home.index("/static/posture_banner.js") < home.index("/static/dashboard.js")
    banner = open(os.path.join(ROOT, "static", "posture_banner.js"), encoding="utf-8").read()
    assert "/api/posture/summary" in banner and "innerHTML" not in banner   # server text is never rendered as HTML
    overview = open(os.path.join(ROOT, "docs", "OVERVIEW.md"), encoding="utf-8").read()
    assert "**Improve my score** (`/report/posture`" in overview


def test_score_alert_settings_live_with_the_other_stores_in_the_container(monkeypatch, tmp_path):
    """ASVS V14.1.1 · CWE-732: the read-only container keeps the score-alert settings on its data volume, beside the proposals store, never in the app folder."""
    # Arrange
    import posture_plus as pp
    monkeypatch.delenv("DLP_CHECK_POSTURE_SETTINGS", raising=False)
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "data" / "proposals.json"))
    # Act
    path = pp.settings_path()
    # Assert
    assert path == str(tmp_path / "data" / "posture_settings.json")


def test_the_score_alert_settings_path_can_still_be_set(monkeypatch, tmp_path):
    """ASVS V14.1.1: an explicit DLP_CHECK_POSTURE_SETTINGS wins over the default folder."""
    import posture_plus as pp
    monkeypatch.setenv("DLP_CHECK_POSTURE_SETTINGS", str(tmp_path / "x.json"))
    assert pp.settings_path() == str(tmp_path / "x.json")
