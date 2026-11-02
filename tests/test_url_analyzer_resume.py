"""Custom URL category analyzer beyond 2,000 URLs: a higher per-run cap,
progress, a stop on a rate limit ZIA keeps answering, and Continue from an
in-memory checkpoint bound to the person, the tenant and the categories,
under a total bound. Offline: the fake client of test_url_tools."""
from __future__ import annotations

import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import url_tools as ut  # noqa: E402
from test_url_tools import ALL, CREDS, SECRET, FakeClient, _api, _wait  # noqa: E402

LITE = [{"id": "CUSTOM_09", "configuredName": "Huge list", "customCategory": True, "superCategory": "BUSINESS_AND_ECONOMY"},
        {"id": "FINANCE", "configuredName": "Finance", "superCategory": "BUSINESS_AND_ECONOMY"}]


def routes(n):
    return {"/zia/urlCategories/lite": LITE,
            "/zia/urlCategories/CUSTOM_09": {"id": "CUSTOM_09", "urls": [f"h{i}.example" for i in range(n)],
                                             "dbCategorizedUrls": ["h1.example"]}}


def sent(c):
    return [u for p in c.posts for u in p]


@pytest.fixture(autouse=True)
def fresh_checkpoints(monkeypatch):
    monkeypatch.setattr(ut, "CHECKPOINTS", ut.Checkpoints())


def test_the_per_run_cap_is_above_2000():
    """ASVS V11.1.4 · CWE-770: one run looks up 2,500 URLs (the old cap was 2,000), still 100 per request, and logs its progress."""
    c = FakeClient(routes(2500), {"h1.example": ["FINANCE"]})
    logs = []
    res = ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: None, log=logs.append)
    assert len(sent(c)) == 2500 and max(len(p) for p in c.posts) == ut.BATCH and ut.MAX_LOOKUP_URLS > 2000
    assert res["totals"]["not_looked_up"] == 0 and "resume" not in res and res["lookup"]["remaining"] == 0
    assert any("2,400 of 2,500 URLs done, 96%" in m for m in logs)
    assert ut.MAX_LOOKUP_URLS // ut.BATCH <= ut.HOURLY_REQUESTS      # one run stays under the assumed hourly request limit


def test_continue_looks_up_only_what_is_left_until_done():
    """ASVS V11.1.4 · CWE-400: with a cap of 200, three runs cover 450 URLs; a URL is never sent twice and the last workbook covers all."""
    c = FakeClient(routes(450))
    r1 = ut.analyze_categories(c, picked=["CUSTOM_09"], max_urls=200, sleep=lambda s: None)
    assert len(sent(c)) == 200 and r1["resume"] == {"remaining": 250, "next": 200}
    assert r1["totals"]["not_looked_up"] == 250 and any("Click Continue" in n for n in r1["notes"])
    r2 = ut.analyze_categories(c, picked=["CUSTOM_09"], max_urls=200, sleep=lambda s: None, prior=r1["checkpoint"])
    assert len(sent(c)) == 400 and len(set(sent(c))) == 400 and r2["resume"]["remaining"] == 50
    r3 = ut.analyze_categories(c, picked=["CUSTOM_09"], max_urls=200, sleep=lambda s: None, prior=r2["checkpoint"])
    assert len(sent(c)) == 450 and len(set(sent(c))) == 450 and "resume" not in r3
    assert r3["totals"]["not_looked_up"] == 0 and r3["lookup"]["looked_up_total"] == 450 and r3["lookup"]["looked_up"] == 50
    assert len(r3["rows"]) == 451       # the URL listed twice (URLs and retaining parent) is two rows, one lookup


def test_a_rate_limit_zia_keeps_answering_ends_the_run_and_continue_retries_it():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: after the retries a refused batch stops the run (no hammering); Continue sends it again."""
    rate = ({"error": "rate limited"}, 429)
    c = FakeClient(routes(300), answers=[None] + [rate] * (1 + ut.RETRIES))
    r1 = ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: None)
    assert len(c.posts) == 1 + 1 + ut.RETRIES          # the first batch, then the refused one with its retries: the third is never sent
    assert r1["resume"]["remaining"] == 200
    why = {r["url"]: r["why"] for r in r1["rows"]}
    assert why["h150.example"] == "Not looked up: rate limited (HTTP 429) after retries."
    assert why["h250.example"].startswith("Not looked up yet: ZIA's rate limit")
    c.posts.clear()
    r2 = ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: None, prior=r1["checkpoint"])
    assert sent(c) == [f"h{i}.example" for i in range(100, 300)] and "resume" not in r2


def test_a_refused_lookup_is_not_sent_again_by_continue():
    """ASVS V11.1.4 · CWE-835: a batch refused for another reason (HTTP 400) is recorded and not retried in a loop."""
    c = FakeClient(routes(150), answers=[({"error": "bad"}, 400)])
    r1 = ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: None)
    assert "resume" not in r1 and sum(1 for r in r1["rows"] if "HTTP 400" in r["why"]) == 101


def test_stop_keeps_what_was_looked_up():
    """ASVS V11.1.4 · CWE-404: Stop still ends the run, and the URLs already looked up are in the exception's checkpoint for Continue."""
    stop = threading.Event()
    c = FakeClient(routes(300))
    with pytest.raises(ut.Stopped) as ei:
        ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: stop.set(), cancel=stop)
    cp = ei.value.checkpoint
    assert len(cp["found"]) == 100 and len(c.posts) == 1
    c.posts.clear()
    res = ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: None, prior=cp)
    assert sent(c)[0] == "h100.example" and len(sent(c)) == 200 and res["totals"]["not_looked_up"] == 0


def test_one_analysis_has_a_total_bound(monkeypatch):
    """ASVS V11.1.4 · CWE-770: beyond MAX_TOTAL_URLS distinct URLs nothing is held or looked up; the count is named."""
    monkeypatch.setattr(ut, "MAX_TOTAL_URLS", 120)
    c = FakeClient(routes(300))
    res = ut.analyze_categories(c, picked=["CUSTOM_09"], sleep=lambda s: None)
    assert len(sent(c)) == 120 and res["lookup"]["over_bound"] == 180 and len(res["rows"]) == 121
    assert any("at most 120 distinct URLs: 180 more" in n for n in res["notes"]) and "resume" not in res


def test_checkpoints_are_bound_bounded_and_expire(monkeypatch):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a checkpoint serves only the person, tenant and categories it was made for, expires, and is evicted when full."""
    cps = ut.Checkpoints()
    data = {"found": {"a.example": {"categories": ["FINANCE"], "security_alerts": []}}, "failed": {}}
    tok = cps.put(data, actor="jane", tenant="acme", picked=["CUSTOM_09"], now=0)
    assert cps.get(tok, actor="jane", tenant="acme", picked=["custom_09 "], now=1)["found"] == data["found"]
    assert cps.get(tok, actor="bob", tenant="acme", picked=["CUSTOM_09"], now=1) is None
    assert cps.get(tok, actor="jane", tenant="other", picked=["CUSTOM_09"], now=1) is None
    assert cps.get(tok, actor="jane", tenant="acme", picked=[], now=1) is None
    assert cps.get("../../etc", actor="jane", tenant="acme", picked=["CUSTOM_09"], now=1) is None
    assert cps.get(tok, actor="jane", tenant="acme", picked=["CUSTOM_09"], now=ut.CHECKPOINT_TTL + 1) is None
    toks = [cps.put(data, actor="jane", tenant="acme", picked=[str(i)], now=10) for i in range(ut.CHECKPOINT_MAX + 2)]
    assert cps.get(toks[0], actor="jane", tenant="acme", picked=["0"], now=11) is None
    assert cps.get(toks[-1], actor="jane", tenant="acme", picked=[str(ut.CHECKPOINT_MAX + 1)], now=11) is not None
    monkeypatch.setattr(ut, "CHECKPOINT_URLS", 1)
    big = cps.put({"found": {"x": {}, "y": {}}, "failed": {}}, actor="jane", tenant="acme", picked=["z"], now=12)
    assert cps.get(big, actor="jane", tenant="acme", picked=["z"], now=12) is None


def test_the_api_continues_by_token_and_never_returns_the_checkpoint(monkeypatch):
    """ASVS V8.3.1 · CWE-200 · WSTG-BUSL-01: the job result carries only a token; Continue with it looks up the rest; a bad or foreign token is a 400 before sign-in."""
    monkeypatch.setattr(ut, "MAX_LOOKUP_URLS", 200)
    c = FakeClient(routes(350))
    t, signed = _api(monkeypatch, c)
    body = dict(CREDS, **ALL, from_page=True, categories=["CUSTOM_09"])
    snap = _wait(t, t.post("/api/exports/url-categories/analyze/start", json=body).json()["job_id"])
    res = snap["result"]
    assert snap["status"] == "done" and res["resume"]["remaining"] == 150 and len(res["resume"]["token"]) >= 20
    assert "checkpoint" not in res and "found" not in str(res.get("resume")) and SECRET not in str(snap)
    tok = res["resume"]["token"]
    snap2 = _wait(t, t.post("/api/exports/url-categories/analyze/start", json=dict(body, resume=tok)).json()["job_id"])
    assert snap2["result"]["status"] == "ready" and "resume" not in snap2["result"] and len(set(sent(c))) == 350 == len(sent(c))
    n = len(signed)
    gone = t.post("/api/exports/url-categories/analyze/start", json=dict(body, resume=tok))      # finished: dropped
    assert gone.status_code == 400 and "can no longer be continued" in gone.json()["detail"]
    bad = t.post("/api/exports/url-categories/analyze/start", json=dict(body, resume="x'; DROP"))
    assert bad.status_code == 400
    other = ut.CHECKPOINTS.put({"found": {"q": {}}, "failed": {}}, actor=None, tenant="someone-else", picked=["CUSTOM_09"])
    foreign = t.post("/api/exports/url-categories/analyze/start", json=dict(body, resume=other))
    assert foreign.status_code == 400 and len(signed) == n
