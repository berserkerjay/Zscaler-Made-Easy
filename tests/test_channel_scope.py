"""Channel ownership from the Scope page drives the assessment
(channel_scope): only a channel marked Zscaler is read. A channel covered
by an alternative solution, or left unticked (a gap), has its checks
reported as Not in scope and never read; the report still lists the gaps. The declaration rides the assess request, is saved on the
tenant profile, and returns as channel_coverage in the report."""
from __future__ import annotations

import os
import tempfile

from fastapi.testclient import TestClient

import channel_scope as cs
import dlp_api_server as srv
import permissions as perm
import security
from dlp_assessment_full_auto import R


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _all_checks():
    return list(srv.REG) + list(srv.PLATFORM_REG) + list(srv.GENAI_REG) + list(srv.AUTOMATION_REG) + list(srv.ZDX_REG) + list(srv.ZID_REG) + list(srv.RBAC_REG)


def test_every_mapped_check_and_section_exists_in_the_registries():
    ids = {c[0] for c in _all_checks()}
    sections = {c[1] for c in _all_checks()}
    for cid, spec in cs.CHANNEL_CHECKS.items():
        assert cid in cs.CHANNELS, cid
        for check_id in spec["ids"]:
            assert check_id in ids, f"{cid}: {check_id}"
        for sec in spec["sections"]:
            assert any(s == sec or s.startswith(sec) for s in sections), f"{cid}: {sec}"
    # "5 — Endpoint DLP" is the general DLP section despite its name: never whole.
    assert "5 — Endpoint DLP" not in cs.CHANNEL_CHECKS["endpoint_dlp"]["sections"]
    assert "5.1" in cs.CHANNEL_CHECKS["endpoint_dlp"]["ids"]


def test_alternative_and_gap_channels_take_checks_out_of_scope_and_the_order_is_kept():
    checks = [("A.1", "Ch.A — Inline Web", "web rule", None), ("B.1", "Ch.B — Endpoint", "endpoint rule", None),
              ("5.1", "5 — Endpoint DLP", "ZDP install", None), ("5.10", "5 — Endpoint DLP", "Dictionaries", None),
              ("B.2", "Ch.B — Endpoint", "another", None), ("E.1", "GenAI — Discovery", "genai", None)]
    channels = {"endpoint_dlp": {"choice": "alternative", "note": "Purview"}, "web_dlp": {"choice": "zscaler"}, "genai_security": "gap"}
    run, skipped, order = cs.partition(checks, channels)
    assert [c[0] for c in run] == ["A.1", "5.10"]
    assert [r["id"] for r in skipped] == ["B.1", "5.1", "B.2", "E.1"]
    for r in skipped[:3]:
        assert r["out_of_scope"] is True and r["status"] == "INFO" and r["channel"] == "endpoint_dlp"
        assert "Not in scope: Endpoint DLP is covered by an alternative solution (Purview)" in r["detail"]
        assert r["plain"]["found"].startswith("Not read: Endpoint DLP")
    gap = skipped[3]
    assert gap["out_of_scope"] is True and gap["gap"] is True and gap["status"] == "INFO" and gap["channel"] == "genai_security"
    assert "Not in scope: GenAI Security was not ticked on the Scope page" in gap["detail"] and "not read" in gap["detail"]
    merged = cs.merge(order, [{"id": c[0]} for c in run], skipped)
    assert [m["id"] for m in merged] == ["A.1", "B.1", "5.1", "5.10", "B.2", "E.1"], "the findings keep their section order"
    # Nothing declared (an MCP / CLI caller): everything runs. Only zscaler: everything runs.
    assert cs.partition(checks, {})[1] == [] and cs.partition(checks, "nonsense")[1] == []
    assert cs.partition(checks, {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "genai_security": "zscaler"})[1] == []
    # A gap is not read either.
    assert [r["id"] for r in cs.partition(checks, {"web_dlp": "zscaler", "endpoint_dlp": "gap"})[1]] == ["B.1", "5.1", "B.2"]


def test_a_check_shared_with_a_zscaler_channel_still_runs():
    # 8.1 belongs to Endpoint DLP and Device Control.
    checks = [("8.1", "8 — Endpoint", "USB", None)]
    assert cs.partition(checks, {"endpoint_dlp": "zscaler", "device_control": "gap"})[1] == []
    assert cs.partition(checks, {"endpoint_dlp": "gap", "device_control": "zscaler"})[1] == []
    assert [r["channel"] for r in cs.partition(checks, {"endpoint_dlp": "alternative", "device_control": "gap"})[1]] == ["endpoint_dlp"]


def test_in_scope_and_pack_targets_are_the_zscaler_channels_only():
    ch = {"web_dlp": "zscaler", "endpoint_dlp": "gap", "saas_casb": "alternative", "email_dlp": "zscaler", "ssl_inspection": "zscaler"}
    assert cs.in_scope(ch) == ["web_dlp", "email_dlp", "ssl_inspection"]
    assert cs.pack_targets(ch) == ["web", "email"]
    assert cs.pack_targets({}) == [] and cs.in_scope("nonsense") == []


def test_coverage_says_what_was_declared_and_what_it_did():
    channels = {"web_dlp": {"choice": "zscaler"}, "endpoint_dlp": {"choice": "alternative", "note": "Purview"}, "email_dlp": {"choice": "gap"}}
    skipped = [{"channel": "endpoint_dlp"}, {"channel": "endpoint_dlp"}]
    cov = cs.coverage(channels, skipped)
    assert cov["declared"] and cov["not_in_scope"] == 2
    gap_cov = cs.coverage(channels, skipped + [{"channel": "email_dlp"}])
    assert gap_cov["not_in_scope"] == 3 and gap_cov["gaps"][0]["checks_not_in_scope"] == 1
    assert "(Endpoint DLP (Purview); 2 checks not in scope); 1 gap (Email DLP; 1 checks not in scope, not read)." in gap_cov["note"]
    assert [c["name"] for c in cov["zscaler"]] == ["Inline Web DLP"] and [c["name"] for c in cov["gaps"]] == ["Email DLP"]
    assert cov["alternative"][0] == {"id": "endpoint_dlp", "name": "Endpoint DLP", "note": "Purview", "checks_not_in_scope": 2}
    assert "1 on Zscaler (Inline Web DLP); 1 covered by an alternative solution (Endpoint DLP (Purview); 2 checks not in scope); 1 gap (Email DLP)." in cov["note"]
    assert cs.coverage({})["declared"] is False and "every check" in cs.coverage({})["note"]
    # normalize: unknown choices are gaps, custom ids keep their name, strings are choices.
    n = cs.normalize({"web_dlp": "weird", "custom_1": {"choice": "alternative", "name": "Print DLP"}, "": "zscaler", 5: 7})
    assert n == {"web_dlp": {"choice": "gap", "note": "", "name": "Inline Web DLP"}, "custom_1": {"choice": "alternative", "note": "", "name": "Print DLP"}}


def test_not_in_scope_is_its_own_class_outside_the_score_and_the_run_stays_complete():
    rows = [{"id": "1", "status": "PASS", "detail": ""}, {"id": "2", "status": "FAIL", "detail": ""},
            {"id": "3", "status": "INFO", "detail": "Not in scope: ...", "out_of_scope": True}]
    assert perm.classify(rows[2]) == "not_in_scope" and perm.CLASS_LABELS["not_in_scope"] == "Not in scope"
    s = perm.assessment_summary(rows)
    assert s["not_in_scope"] == 1 and s["not_in_scope_ids"] == ["3"] and s["assessed"] == 2 and s["total"] == 3
    assert s["scored"] == 2 and s["score"] == 50 and s["excluded"] == 1 and s["state"] == "complete"


def test_the_assess_stream_reports_the_skipped_checks_and_the_coverage(monkeypatch):
    from test_assess_stream import FakeClient, _events
    calls = []
    checks = [("A.1", "Ch.A — Inline Web", "web", lambda c: (calls.append("A.1"), R(R.PASS, "fine"))[1]),
              ("B.1", "Ch.B — Endpoint", "endpoint", lambda c: (calls.append("B.1"), R(R.FAIL, "missing"))[1]),
              ("B.2", "Ch.B — Endpoint", "endpoint 2", lambda c: (calls.append("B.2"), R(R.PASS, "fine"))[1])]
    monkeypatch.setattr(srv, "Client", FakeClient)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: checks)
    monkeypatch.setattr(srv, "CHECK_TIMEOUT", 2)
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [])
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "scopes": ["dlp"],
            "channels": {"web_dlp": {"choice": "zscaler"}, "endpoint_dlp": {"choice": "alternative", "note": "Purview", "name": "Endpoint DLP"}}}
    with _page().stream("POST", "/api/assess", json=body) as r:
        assert r.status_code == 200
        ev = _events(r)
    assert calls == ["A.1"], "the endpoint checks were never run against the tenant"
    found = [d for k, d in ev if k == "check"]
    assert [d["id"] for d in found][:2] == ["B.1", "B.2"] and all(d["out_of_scope"] for d in found[:2])
    complete = next(d for k, d in ev if k == "complete")
    assert [c["id"] for c in complete["checks"]] == ["A.1", "B.1", "B.2"]
    assert complete["summary"]["not_in_scope"] == 2 and complete["summary"]["assessed"] == 1 and complete["summary"]["state"] == "complete"
    assert complete["score"] == 100 and complete["metadata"]["total_checks"] == 3
    assert complete["channel_coverage"]["not_in_scope"] == 2 and complete["channel_coverage"]["alternative"][0]["note"] == "Purview"
    assert complete["sections"]["Ch.B — Endpoint"]["pct"] is None
    progress = [d for k, d in ev if k == "progress"]
    assert progress[0] == {"total": 3, "completed": 2, "pct": 67} and progress[-1]["completed"] == 3


def test_the_profile_keeps_the_channel_declaration(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("DLP_CHECK_PROFILES", os.path.join(d, "p.json"))
        c = _page()
        r = c.post("/api/tenant-profiles", json={"name": "Acme", "vanity_domain": "acme", "client_id": "abc123456789",
                                                  "channels": {"endpoint_dlp": {"choice": "alternative", "note": "Purview"}, "web_dlp": "zscaler", "x": "bogus"}})
        assert r.status_code == 200, r.text
        got = c.get(f"/api/tenant-profiles/{r.json()['id']}").json()
        assert got["channels"] == {"endpoint_dlp": {"choice": "alternative", "note": "Purview", "name": "Endpoint DLP"},
                                   "web_dlp": {"choice": "zscaler", "note": "", "name": "Inline Web DLP"},
                                   "x": {"choice": "gap", "note": "", "name": "x"}}


def test_the_word_report_prints_the_channel_coverage():
    from report_docx import generate_report
    from dlp_assessment_full_auto import compute, maturity
    rows = [{"id": "1", "sec": "Web", "section": "Web", "label": "a", "status": "PASS", "detail": ""},
            {"id": "2", "sec": "Endpoint", "section": "Endpoint", "label": "b", "status": "INFO", "detail": "Not in scope: Endpoint DLP ...", "out_of_scope": True}]
    cov = cs.coverage({"web_dlp": "zscaler", "endpoint_dlp": {"choice": "alternative", "note": "Purview"}, "email_dlp": "gap"}, [{"channel": "endpoint_dlp"}])
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.docx")
        generate_report(rows, {"org_name": "Acme", "channel_coverage": cov}, path, compute, maturity)
        from docx import Document
        doc = Document(path)
        text = "\n".join(p.text for p in doc.paragraphs) + "\n" + "\n".join(c.text for t in doc.tables for row in t.rows for c in row.cells)
    assert "1 of 2 (1 not in scope)" in text and "1 checks are not in scope: their channel is covered by an alternative solution" in text
    assert "Channel Coverage" in text and "Alternative solution" in text and "Purview" in text and "Email DLP" in text and "Gap" in text


def test_the_page_and_the_dashboard_carry_the_declaration_and_the_class():
    c = _page()
    html = c.get("/").text
    assert "channels: (typeof window.__dbChannelScope === 'function') ? window.__dbChannelScope() : {}" in html
    assert "if (c && c.out_of_scope) return 'not_in_scope';" in html and "not_in_scope_ids" in html
    assert 'id="notScopeStat"' in html and "NOTSCOPE:'Not in scope'" in html and 'data-filter="NOTSCOPE"' in html and ".status-NOTSCOPE {" in html
    assert "not in scope (channels covered outside Zscaler or left unticked, per the Scope page)" in html
    js = c.get("/static/dashboard.js").text
    assert "window.__dbChannelScope = function" in js and "window.__dbChannelsSet = function" in js
    assert "data.channel_coverage" in js and "not in scope" in js and "reported as <em>Not in scope</em>" in js
    assert "the assessment still reads the tenant" not in js and "a gap, not in scope; the tenant is not read for it" in js
    guide = c.get("/static/guide.js").text
    assert "channels: typeof window.__dbChannelScope === 'function' ? window.__dbChannelScope() : {}" in guide
    assert "window.__dbChannelsSet(p.channels)" in guide
