"""Channel ownership from the Scope page drives the assessment
(channel_scope): only a channel on Zscaler (ticked, or a prerequisite of
one) is read. A channel covered by an alternative solution, or left
unticked (a gap), has its checks never read and hidden: no row, no
section, no score, only one line counting them. The declaration rides the
assess request, is saved on the tenant profile, and returns as
channel_coverage in the report."""
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
    # E.1 also reads the Cloud App Control rules: that channel must be ticked too.
    assert [r["id"] for r in cs.partition(checks, {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "genai_security": "zscaler"})[1]] == ["E.1"]
    assert cs.partition(checks, {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "genai_security": "zscaler", "cloud_app_control": "zscaler"})[1] == []
    # A gap is not read either, nor a channel the declaration leaves out (GenAI here).
    assert [r["id"] for r in cs.partition(checks, {"web_dlp": "zscaler", "endpoint_dlp": "gap"})[1]] == ["B.1", "5.1", "B.2", "E.1"]


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
    assert cov["declared"] and cov["not_in_scope"] == 2 and cov["hidden"] == 2
    assert cov["hidden_note"] == "2 checks are outside the selected scope and are not shown."
    gap_cov = cs.coverage(channels, skipped + [{"channel": "email_dlp"}])
    assert gap_cov["hidden"] == 3 and gap_cov["gaps"][0]["checks_not_in_scope"] == 1
    # The note names only what was assessed and why: never a list of what was left out.
    assert cov["note"] == ("Channels assessed on Zscaler, as declared on the Scope page: Inline Web DLP. "
                           "SSL/TLS Inspection: included because Inline Web DLP needs it.")
    for name in ("Endpoint DLP", "Email DLP", "Purview", "gap"):
        assert name not in cov["note"], name
    # Every channel the declaration leaves out is a gap, after the declared ones;
    # SSL inspection is on Zscaler as Inline Web DLP's prerequisite.
    assert [c["name"] for c in cov["zscaler"]] == ["Inline Web DLP", "SSL/TLS Inspection"]
    assert cov["zscaler"][1]["prerequisite_of"] == ["web_dlp"] and cov["zscaler"][1]["declared"] == "gap"
    assert [c["id"] for c in cov["gaps"]] == ["email_dlp"] + [c for c in cs.CHANNELS if c not in ("web_dlp", "endpoint_dlp", "email_dlp", "ssl_inspection")]
    assert cov["alternative"][0] == {"id": "endpoint_dlp", "name": "Endpoint DLP", "note": "Purview", "checks_not_in_scope": 2}
    assert [p["note"] for p in cov["prerequisites"]] == ["SSL/TLS Inspection: included because Inline Web DLP needs it."]
    assert cs.coverage({})["declared"] is False and "every check" in cs.coverage({})["note"] and cs.coverage({})["prerequisites"] == []
    # normalize: unknown choices are gaps, custom ids keep their name, strings are choices.
    n = cs.normalize({"web_dlp": "weird", "custom_1": {"choice": "alternative", "name": "Print DLP"}, "": "zscaler", 5: 7})
    assert n == {"web_dlp": {"choice": "gap", "note": "", "name": "Inline Web DLP"}, "custom_1": {"choice": "alternative", "note": "", "name": "Print DLP"}}


def test_a_check_outside_the_scope_is_hidden_from_the_summary_and_the_run_stays_complete():
    rows = [{"id": "1", "status": "PASS", "detail": ""}, {"id": "2", "status": "FAIL", "detail": ""},
            {"id": "3", "status": "INFO", "detail": "Not in scope: ...", "out_of_scope": True}]
    assert perm.classify(rows[2]) == "not_in_scope"
    s = perm.assessment_summary(rows)
    assert s["total"] == 2 and s["assessed"] == 2 and s["hidden"] == 1 and "not_in_scope" not in s
    assert s["hidden_note"] == "1 check is outside the selected scope and is not shown."
    assert s["scored"] == 2 and s["score"] == 50 and s["excluded"] == 0 and s["state"] == "complete"
    # The ones the assessment already left out are added to the count.
    assert perm.assessment_summary(rows, hidden=4)["hidden"] == 5


def test_the_assess_stream_hides_the_skipped_checks_and_reports_the_coverage(monkeypatch):
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
    assert [d["id"] for d in found] == ["A.1"] and not any(d.get("out_of_scope") for d in found), "a hidden check is never streamed"
    complete = next(d for k, d in ev if k == "complete")
    assert [c["id"] for c in complete["checks"]] == ["A.1"]
    assert complete["hidden_checks"] == 2 and complete["hidden_note"] == "2 checks are outside the selected scope and are not shown."
    assert complete["summary"]["hidden"] == 2 and complete["summary"]["total"] == 1 and complete["summary"]["state"] == "complete"
    assert complete["score"] == 100 and complete["metadata"]["total_checks"] == 1
    assert complete["channel_coverage"]["hidden"] == 2 and complete["channel_coverage"]["alternative"][0]["note"] == "Purview"
    assert "Ch.B — Endpoint" not in complete["sections"] and list(complete["sections"]) == ["Ch.A — Inline Web"]
    progress = [d for k, d in ev if k == "progress"]
    assert progress[0] == {"total": 1, "completed": 0, "pct": 0} and progress[-1]["completed"] == 1


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
    assert "1 of 1" in text and text.count("1 check is outside the selected scope and is not shown.") == 1
    assert "Channel Coverage" in text and "SSL/TLS Inspection: included because Inline Web DLP needs it." in text
    # Nothing that was left out has a row: not the alternative, not the gap, not the check.
    for gone in ("Not in scope", "Alternative solution", "Purview", "Email DLP", "Endpoint DLP"):
        assert gone not in text, gone


def test_the_page_and_the_dashboard_carry_the_declaration_and_hide_what_is_out_of_scope():
    c = _page()
    html = c.get("/").text
    assert "channels: (typeof window.__dbChannelScope === 'function') ? window.__dbChannelScope() : {}" in html
    assert "if (c && c.out_of_scope) return 'not_in_scope';" in html
    # No tile, filter or pill for "Not in scope": the rows are hidden, one line counts them.
    assert 'id="notScopeStat"' not in html and "NOTSCOPE" not in html and 'id="scopeNote"' in html
    assert "function scopeVisible(data)" in html and "scopeVisible(data);" in html and "function renderScopeNote(data, sum)" in html
    assert "checks = (checks || []).filter(c => !(c && c.out_of_scope));" in html
    assert "if (!evt.out_of_scope) partialResults.push(evt);" in html
    assert "outside the selected scope and ${v} not shown." in html
    js = c.get("/static/dashboard.js").text
    assert "window.__dbChannelScope = function" in js and "window.__dbChannelsSet = function" in js
    assert "data.channel_coverage" in js and "cc.prerequisites" in js and "Channels assessed:" in js
    assert "reported as <em>Not in scope</em>" not in js and "a gap, not in scope; the tenant is not read for it and its checks are not shown" in js
    assert "/api/scope/prerequisites" in js and "Assessed as a prerequisite:" in js and 'id="dbChPrereqs"' in js
    guide = c.get("/static/guide.js").text
    assert "channels: typeof window.__dbChannelScope === 'function' ? window.__dbChannelScope() : {}" in guide
    assert "window.__dbChannelsSet(p.channels)" in guide
