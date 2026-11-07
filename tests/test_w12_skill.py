"""Wave 12 (assistant skill rows): capacity review, incident postmortem, graded answers.

Offline: sample tenant and tmp stores; no sign-in, no network."""
from __future__ import annotations

import asyncio
import json

import pytest

import offline_tenant


def call(tool, /, **args):
    import dlp_mcp_server
    res = asyncio.run(dlp_mcp_server.mcp.call_tool(tool, args))
    return json.loads(res.content[0].text)


@pytest.fixture
def local(tmp_path, monkeypatch):
    for var, name in (("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_WORKSPACE_NOTES", "notes.json"), ("DLP_CHECK_CAPACITY", "cap.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    for k in ("ZSCALER_MCP_PROFILE", "ZSCALER_MCP_SCOPES", "ZSCALER_MCP_CHANNELS", "ZSCALER_CLIENT_SECRET", "ZSCALER_CLIENT_ID",
              "ZSCALER_VANITY_DOMAIN", "ZSCALER_AUTH_METHOD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "ztw,zpa,automation")
    offline_tenant.sample_store(reset=True)
    return tmp_path


def test_headroom_status_bands_and_unknowns():
    """ASVS V5.1.3 · CWE-1284 · WSTG-BUSL-01: headroom is (licensed-used)/licensed; over, low, watch, ok bands; no read or no licensed count is stated, never guessed."""
    import capacity_review as cr
    # Act
    rep = cr.review({"locations": 95, "tunnels": 15, "zpa_segments": 120, "app_connectors": 10, "users": True},
                    {"locations": 100, "tunnels": 20, "zpa_segments": 100, "app_connectors": 100, "users": 5})
    # Assert
    by = {r["metric"]: r for r in rep["rows"]}
    assert (by["locations"]["status"], by["locations"]["headroom_pct"]) == ("low", 5.0)
    assert (by["tunnels"]["status"], by["tunnels"]["headroom_pct"]) == ("ok", 25.0)
    assert by["zpa_segments"]["status"] == "over" and by["app_connectors"]["status"] == "ok"
    assert by["users"]["status"] == "not_read" and rep["flagged"] == ["Locations", "ZPA application segments"]
    assert cr.review({"locations": 3}, {})["rows"][1]["status"] == "no_licensed_count"


def test_entitlements_file_ignores_bad_values_and_exports_are_csv_safe(tmp_path):
    """CWE-1236 · ASVS V5.2.2 · WSTG-INPV-01: bad licensed counts are dropped; a formula-looking value in the export is neutralised; markdown names are escaped."""
    import capacity_review as cr
    f = tmp_path / "e.json"
    f.write_text(json.dumps({"locations": 50, "users": -1, "tunnels": "x", "evil": 9}))
    # Act
    ent = cr.load_entitlements(str(f))
    rep = cr.review({"locations": 1}, ent)
    rep["rows"][0]["label"] = "=HYPERLINK(\"http://x\")"
    # Assert
    assert ent == {"locations": 50}
    assert "'=HYPERLINK" in cr.to_csv(rep) and "[x](" not in cr.to_markdown(rep, "[x](javascript:1)")


def test_capacity_review_tool_counts_the_sample_and_changes_nothing(local):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: the tool reports sample locations and ZPA counts with headroom against the local licensed file; the tenant copy is untouched."""
    (local / "cap.json").write_text(json.dumps({"locations": 10, "zpa_segments": 1000, "app_connectors": 1000}))
    # Act
    out = call("capacity_review", source="sample")
    # Assert
    rows = {r["metric"]: r for r in out["data"]["rows"]}
    assert rows["locations"]["used"] is not None and rows["locations"]["headroom_pct"] is not None
    assert rows["zpa_segments"]["used"] >= 1 and rows["users"]["status"] == "not_read"
    assert offline_tenant.sample_store().writes == 0


def test_capacity_review_is_refused_when_neither_product_is_in_scope(local, monkeypatch):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: with Cloud & Branch Connector and ZPA unticked nothing is read."""
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "automation")
    # Act
    out = call("capacity_review", source="sample")
    # Assert
    assert out["code"] == "not_in_scope"


def test_postmortem_builds_markdown_and_csv_from_the_window(local):
    """ASVS V7.2.1 · CWE-117 · CWE-1236 · WSTG-INPV-01: records in the window are in the timeline, records outside it are not; an injected name is inert in Markdown and neutralised in CSV."""
    import audit
    import postmortem as pm
    import audit_timeline as at
    audit.record("object_write", actor="jane.admin@example.com", action="update", kind="url_filtering_rule", name="=cmd|' /C calc'!A1 [x](javascript:1)",
                 tenant="acme (production)")
    win = at.window(7)
    # Act
    rep = pm.generate(window_=win, deployments=[], audit_entries=audit.tail(1000), title="Outage <b>1</b>")
    md, csv_text = pm.to_markdown(rep), pm.to_csv(rep)
    # Assert
    assert rep["summary"]["events"] >= 1 and rep["people"] == 1
    assert "\\[x\\]" in md and "<b>" not in md and "### Root cause:" in md
    assert "'=cmd" in csv_text
    old = pm.generate(window_=at.window(None, "2020-01-01", "2020-01-02"), deployments=[], audit_entries=audit.tail(1000))
    assert old["summary"]["events"] == 0


def test_postmortem_tool_is_scoped_and_bounded(local, monkeypatch):
    """ASVS V4.1.3 · V5.1.3 · CWE-1284: the tool returns Markdown for a chosen window, refuses a window over 31 days and refuses without Automation in scope."""
    import audit
    audit.record("object_write", actor="a@example.com", action="update", kind="rule", name="Block X", tenant="t")
    # Act
    ok = call("postmortem", title="Week")
    long = call("postmortem", start="2020-01-01")
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "ztw")
    refused = call("postmortem")
    # Assert
    assert ok["data"]["markdown"].startswith("# Week") and ok["data"]["summary"]["events"] >= 1
    assert long["code"] == "bad_input" and refused["code"] == "not_in_scope"


def test_every_answer_is_graded_with_source_tier_and_confidence(local):
    """ASVS V8.3.4 · CWE-1059: each tool answer carries a grade (source tier, confidence, basis, as-of); sample answers are illustrative, local-record answers say so."""
    # Act
    sample = call("ztw_summary", source="sample")
    tl = call("timeline")
    # Assert
    assert sample["grade"]["source_tier"] == "configuration" and sample["grade"]["confidence"] == "illustrative" and sample["grade"]["basis"]
    assert tl["grade"]["source_tier"] == "local_records" and tl["grade"]["confidence"] == "high"


def test_postmortem_route_exports_md_csv_and_rejects_bad_windows():
    """ASVS V4.1.3 · V5.1.3 · CWE-1284 · WSTG-INPV-01: the authenticated route returns the report as Markdown or CSV downloads with no-store, and refuses a bad window or format with a 400."""
    from fastapi.testclient import TestClient
    import dlp_api_server as api
    t = TestClient(api.app)
    # Act
    md = t.post("/api/postmortem", json={"days": 3, "format": "md", "title": "T"})
    csv_r = t.post("/api/postmortem", json={"days": 3, "format": "csv"})
    bad = t.post("/api/postmortem", json={"days": 999})
    fmt = t.post("/api/postmortem", json={"format": "exe"})
    # Assert
    assert md.status_code == 200 and md.text.startswith("# T") and "attachment" in md.headers["content-disposition"]
    assert csv_r.status_code == 200 and csv_r.text.startswith("time,")
    assert bad.status_code == 400 and fmt.status_code == 400


# ── citations, lookup, journal, capacity reads (round 2) ──────────────

@pytest.fixture
def corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_CITATIONS", str(tmp_path / "ex.json"))
    return tmp_path


def test_cite_returns_cached_excerpt_with_source_tier_and_date(corpus):
    """ASVS V8.3.4 · CWE-1059 · WSTG-INFO-08: a topic gives best-practice entries with URL, title, tier, retrieved date and the cached excerpt; no fetch is made."""
    import reference_corpus as rc
    url = "https://help.zscaler.com/zpa/idp-configuration-best-practices"
    (corpus / "ex.json").write_text(json.dumps({url: {"excerpt": "Use SCIM groups, not individuals.", "retrieved": "2026-11-01"}}))
    def boom(*a, **k):
        raise AssertionError("fetched")
    # Act
    out = rc.cite("zpa idp", getter=boom)
    # Assert
    hit = next(c for c in out["citations"] if c["source_url"] == url)
    assert (hit["excerpt"], hit["retrieved"], hit["tier"], hit["excerpt_basis"]) == ("Use SCIM groups, not individuals.", "2026-11-01", "official", "page excerpt (cached)")
    assert out["fetched"] is False and any("Fetching is off" in n for n in out["notes"])


def test_cite_fetch_only_through_allowlisted_zscaler_hosts(corpus):
    """CWE-918 · ASVS V12.6.1 · WSTG-INPV-19: a fetch of a non-Zscaler or non-https host is refused before any request; an allowed host is fetched, the excerpt cached and quoted."""
    import reference_corpus as rc
    calls = []
    def getter(url):
        calls.append(url)
        return b"<html><body><p>Bind access policy rules to SCIM groups and use the smallest app segment scope per application.</p></body></html>", 200, ""
    # Act / Assert: refused hosts
    for bad in ("https://evil.example.com/x", "http://help.zscaler.com/x", "https://learn.microsoft.com/a", "https://help.zscaler.com.evil.example/x"):
        with pytest.raises(rc.CiteError) as e:
            rc.fetch_excerpt(bad, getter)
        assert e.value.status == 403
    assert calls == []
    out = rc.cite("zpa idp", fetch=True, getter=getter)
    official = [c for c in out["citations"] if c["source_url"].startswith("https://help.zscaler.com/")]
    assert official and official[0]["excerpt_basis"] == "page excerpt (cached)" and "SCIM" in official[0]["excerpt"] and official[0]["retrieved"]
    assert all(u.startswith("https://help.zscaler.com/") for u in calls)
    assert any("not a Zscaler help or docs host" in n for n in out["notes"])   # the non-Zscaler entry was refused, not fetched


def test_cite_tool_refuses_fetch_unless_the_operator_allows_it(local, corpus, monkeypatch):
    """CWE-441 · ASVS V4.1.3 · A01:2021: the assistant cannot turn fetching on; without the operator's variable a fetch=true call is refused, and the cached call works."""
    monkeypatch.delenv("ZSCALER_MCP_ALLOW_FETCH", raising=False)
    # Act
    refused = call("cite", topic="zpa idp", fetch=True)
    ok = call("cite", topic="ssl inspection")
    # Assert
    assert refused["code"] == "not_permitted"
    assert ok["data"]["citations"] and ok["grade"]["source_tier"] == "local_records"


def test_cite_by_finding_id_and_route(corpus):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a finding id with no topic cites by the id's words; an empty request is a 400 on the route; the route returns the same citations."""
    from fastapi.testclient import TestClient
    import dlp_api_server as api
    t = TestClient(api.app)
    # Act
    ok = t.post("/api/cite", json={"finding_id": "ssl_inspection"})
    empty = t.post("/api/cite", json={})
    # Assert
    assert ok.status_code == 200 and ok.json()["citations"] and empty.status_code == 400


def test_lookup_answers_from_the_corpus_with_sources_and_says_when_nothing_matches(local):
    """ASVS V8.3.4 · CWE-1059: an SSL question is answered from benchmark guidance and the catalogue, each passage with its source; a question the corpus lacks is answered=false."""
    # Act
    hit = call("lookup", question="how should ssl inspection be set up")
    miss = call("lookup", question="zzzqqq xylophone")
    # Assert
    d = hit["data"]
    assert d["answered"] and all(p["source"] for p in d["passages"]) and any(p["source_url"] for p in d["passages"])
    assert any(p["kind"] == "benchmark guidance" for p in d["passages"])
    assert miss["data"]["answered"] is False


def test_journal_enforces_hypothesis_evidence_conclusion_and_resumes(local, monkeypatch):
    """ASVS V4.1.3 · V8.3.4 · CWE-841 · WSTG-BUSL-01: a conclusion needs evidence, evidence needs a step, `next` says where the case left off, and a new session resumes the same case from the sealed store."""
    # Act
    opened = call("journal_open", title="Why is billing blocked?", source="sample")["data"]["case"]
    cid = opened["id"]
    h = call("journal_add", case_id=cid, kind="hypothesis", content="SSL bypass is missing", source="sample")["data"]["case"]
    sid = h["steps"][0]["id"]
    early = call("journal_add", case_id=cid, kind="conclusion", step_id=sid, content="done", outcome="supported", source="sample")
    orphan = call("journal_add", case_id=cid, kind="evidence", step_id="deadbeef", tool="path_check", content="x", source="sample")
    ev = call("journal_add", case_id=cid, kind="evidence", step_id=sid, tool="path_check", ref="read_at 2026-11-07", content="no bypass rule", source="sample")["data"]["case"]
    mid = ev["next"]
    done = call("journal_add", case_id=cid, kind="conclusion", step_id=sid, outcome="supported", content="add the bypass", source="sample")["data"]["case"]
    call("journal_add", case_id=cid, kind="question", content="Who owns the rule?", source="sample")
    shown = call("journal_show", case_id=cid, source="sample")["data"]["case"]
    listing = call("journal_show", source="sample")["data"]["cases"]
    # Assert
    assert early["code"] == "bad_input" or "evidence" in early["error"]
    assert "no such step" in orphan["error"]
    assert "conclude" in mid and done["steps"][0]["outcome"] == "supported"
    assert shown["open_questions"] == 1 and shown["next"].startswith("Answer question")
    assert [c["id"] for c in listing] == [cid]
    assert offline_tenant.sample_store().writes == 0


def test_journal_store_is_sealed_when_encryption_is_on_and_listed_for_sealing(local, monkeypatch):
    """ASVS V6.1.1 · CWE-311 · CWE-312: the journal file is a store_crypto store (listed for seal_all) and round-trips through store_crypto.load_json."""
    import investigation_journal as ij
    import store_crypto
    monkeypatch.setenv("DLP_CHECK_JOURNAL", str(local / "journal.json"))
    ij.open_case("acme (production)", "Case A", by="jane@example.com")
    # Act
    paths = [e["path"] for e in store_crypto._store_paths()]
    with open(ij.store_path(), encoding="utf-8") as f:
        data = store_crypto.load_json(f)
    # Assert
    assert ij.store_path() in paths and list(data["tenants"]["acme (production)"].values())[0]["title"] == "Case A"


def test_journal_route_opens_adds_and_lists_for_a_named_tenant(local, monkeypatch):
    """ASVS V4.1.3 · V5.1.3 · CWE-20: the route opens a case, adds a hypothesis, lists it, and refuses an unknown action and a bad case id with a 400/404."""
    from fastapi.testclient import TestClient
    import dlp_api_server as api
    monkeypatch.setenv("DLP_CHECK_JOURNAL", str(local / "journal2.json"))
    t = TestClient(api.app)
    # Act
    o = t.post("/api/journal", json={"tenant": "acme (production)", "action": "open", "title": "Outage"})
    cid = o.json()["case"]["id"]
    a = t.post("/api/journal", json={"tenant": "acme (production)", "action": "add", "case_id": cid, "kind": "hypothesis", "content": "H1"})
    g = t.get("/api/journal", params={"tenant": "acme (production)"})
    bad = t.post("/api/journal", json={"tenant": "acme (production)", "action": "drop"})
    missing = t.post("/api/journal", json={"tenant": "acme (production)", "action": "add", "case_id": "abcdef12", "kind": "hypothesis", "content": "x"})
    # Assert
    assert o.status_code == 200 and a.json()["case"]["steps"][0]["hypothesis"] == "H1" and g.json()["cases"][0]["id"] == cid
    assert bad.status_code == 400 and missing.status_code == 404


class _FakeUsers:
    def __init__(self, n):
        self.n = n

    def list_users(self, query_params=None):
        page, size = query_params["page"], query_params["page_size"]
        rows = [{"id": i, "name": f"u{i}"} for i in range(self.n)][(page - 1) * size: page * size]
        return rows, None, None


class _FakeSdk:
    def __init__(self, n):
        class Z:
            user_management = _FakeUsers(n)
        self.zia = Z()


def test_users_are_counted_by_paging_and_never_listed():
    """ASVS V8.3.4 · CWE-359 · WSTG-INPV-01: user counts come from paged reads (1000 a page) and only the number is returned."""
    import capacity_review as cr
    # Act
    n = cr.count_users(_FakeSdk(2500))
    # Assert
    assert n == 2500


def test_subscription_seats_win_over_the_local_file():
    """ASVS V5.1.3 · CWE-1284 · WSTG-BUSL-01: a seat count on an active subscription row is the licensed users; expired rows and bad values are ignored; without one the local file is used and the source is named."""
    import capacity_review as cr
    body = [{"id": "ZIA_BUS", "status": "ACTIVE", "subscribed": True, "licenses": 4000},
            {"id": "ZIA_OLD", "status": "EXPIRED", "licenses": 99999}, {"id": "X", "status": "ACTIVE", "licenses": -5}, "junk"]
    # Act
    seats = cr.subscription_seats(body)
    rep = cr.review({"users": 3900}, {"users": 100000}, seats)
    fallback = cr.review({"users": 3900}, {"users": 4000}, {})
    # Assert
    row = rep["rows"][0]
    assert seats == {"users": 4000} and (row["licensed"], row["licensed_from"], row["status"]) == (4000, "subscriptions", "low")
    assert fallback["rows"][0]["licensed_from"] == "local file"


def test_read_used_reads_only_the_products_in_scope():
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: with only zia_extras ticked, ZPA and Cloud & Branch Connector are never read; users and subscriptions are, GET only."""
    import capacity_review as cr
    import readiness
    class Sdk(_FakeSdk):
        pass
    sdk = Sdk(3)
    seen = []
    orig = readiness._raw_get
    readiness._raw_get = lambda c, p: seen.append(p) or {"state": "ok", "code": 200, "body": [{"id": "ZIA_BUS", "status": "ACTIVE", "licenses": 10}]}
    try:
        # Act
        got = cr.read_used(sdk, {"auth_method": "oneapi", "customer_id": "123456789012345678"}, ["zia_extras"])
    finally:
        readiness._raw_get = orig
    # Assert
    assert got["used"] == {"users": 3} and got["seats"] == {"users": 10} and seen == [readiness.SUBSCRIPTIONS_PATH]


def test_capacity_route_is_refused_before_sign_in_with_nothing_in_scope_and_page_is_served():
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: with none of Cloud & Branch Connector, ZPA or ZIA platform ticked the route is a 400 before any sign-in; the review page is served and builds its table with textContent."""
    from fastapi.testclient import TestClient
    import dlp_api_server as api
    t = TestClient(api.app)
    # Act
    r = t.post("/api/capacity-review", json={"scopes": ["dlp"], "channels": {}, "from_page": True})
    page = t.get("/report/capacity")
    # Assert
    assert r.status_code == 400 and "not in scope" in r.json()["detail"]
    assert page.status_code == 200 and "/api/capacity-review" in page.text and "innerHTML" not in page.text
