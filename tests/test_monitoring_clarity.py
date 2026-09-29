"""Monitoring and compliance clarity (UI/UX stage 4): the Digest says what
the six-hour loop covers and when it runs; a framework percentage says
what it is and is never invented; this app's CISA score is labelled as
the app's, not the tenant's; the daily upstream check is explained and
its offline half can be run here."""
from fastapi.testclient import TestClient

import compliance_mapping as cm
import dlp_api_server as srv
import security


def _client():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_framework_alignment_is_a_share_of_mapped_checks_and_never_invented():
    s = cm.get_framework_summary([{"id": "4.1", "status": "FAIL"}, {"id": "A.1", "status": "PASS"}])
    fw = next(iter(s.values()))
    assert fw["alignment_basis"].startswith("share of this assessment's mapped checks that are configured")
    assert fw["scored_count"] >= 1 and fw["alignment_pct"] is not None
    # Nothing scoreable: None and "Not measured", never 100.
    s0 = cm.get_framework_summary([{"id": "4.1", "status": "INFO"}])
    fw0 = next(iter(s0.values()))
    assert fw0["alignment_pct"] is None and fw0["status"] == "Not measured" and fw0["scored_count"] == 0
    # Every consumer copes with None.
    import benchmarks
    rows = benchmarks.frameworks_benchmark([{"id": "4.1", "status": "INFO"}])
    assert rows and all(r["alignment_pct"] is None for r in rows)
    md = benchmarks.to_markdown(benchmarks.benchmark_report({"checks": [{"id": "4.1", "status": "INFO", "section": "4 — SSL Policy", "label": "x"}]}))
    assert "| n/a |" in md and "None%" not in md


def test_the_pages_say_what_the_percentage_is():
    c = _client()
    html = c.get("/").text
    assert "8 major regulatory frameworks" not in html
    assert "share of this assessment's mapped checks that are configured" in html and "not a certification" in html
    assert "${measured ? ` · ${s.alignment_pct}%` : ''}" in html
    comp = c.get("/report/compliance").text
    assert "not a share of the framework's controls met and not a certification" in comp and "not measured: no scoreable mapped check" in comp


def test_digest_says_when_the_loop_runs_and_what_it_covers():
    c = _client()
    d = c.get("/report/digest").text
    assert "Digest</span> — the six-hour loop" in d and "While this app's server is running" in d
    assert "does not run the assessment checks or re-score the tenant" in d and "stops when the server stops" in d
    assert "No tenant was evaluated: no tenant profile remembers its secret" in d and "tile('Tenants evaluated'" in d
    assert "always-on" not in d
    html = c.get("/").text
    assert "always-on loop" not in html and "It does not re-run the assessment." in html
    ex = c.get("/static/explain.js").text
    assert "Digest — the six-hour loop" in ex and "does not re-run the assessment checks" in ex and "always-on" not in ex
    assert "always-on" not in open("GETTING_STARTED.md", encoding="utf-8").read().split("## 4i.")[1].split("\n")[0]
    # A manual run keeps the same bookkeeping as the scheduled one.
    src = open("dlp_api_server.py", encoding="utf-8").read()
    body = src.split("async def digests_run(")[1].split("@app.get")[0]
    assert '_DH_REFRESH_STATE["last_status"] = "ok"' in body and "_dh_refresh_once" not in src


def test_this_apps_cisa_score_is_labelled_as_the_apps_and_the_daily_upstream_check_is_exposed():
    c = _client()
    adv = c.get("/report/advanced").text
    assert "CISA Secure by Design score — for this app, not the tenant" in adv and "says nothing about the customer's Zscaler tenant" in adv
    assert 'id="upstream"' in adv and "not a CISA check, and not a check of any customer tenant" in adv and 'id="advUpCheck"' in adv
    js = c.get("/static/advanced.js").text
    assert "/api/upstream-check" in js and "function renderUp(d)" in js
    ds = c.get("/static/deploy_studio.js").text
    assert "Secure by Design (this pack's objects in the tenant)" in ds and "not a compliance score for the tenant" in ds
    r = c.get("/api/upstream-check")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["offline"] is True and isinstance(d["ok"], bool) and isinstance(d["drift"], list) and isinstance(d["notes"], list)
    assert d["daily"]["not"] == "this is not a CISA check and not a check of the customer's tenant" and "upstream_check.yml" in d["daily"]["where"]
    assert "web" in d["endpoints_checked"] and "saas" in d["endpoints_checked"]
    assert c.get("/api/upstream-check").json()["cached_seconds"] >= 0
