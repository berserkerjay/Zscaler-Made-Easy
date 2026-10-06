"""Scope prerequisites and hiding what does not qualify (channel_scope).

When a channel is on Zscaler its hard prerequisites are assessed too, even
when they were not ticked: Inline Web DLP cannot inspect encrypted traffic
without SSL inspection, so ticking Inline Web DLP runs (and reads) the SSL
inspection checks, and the page and the report say why. A check that does
not qualify (neither in scope nor a prerequisite of something in scope) is
not run, not read and not shown anywhere: no row, no section, no score, no
coverage, no report row. One line counts them.

Every tenant here is a recording fake: no real tenant is ever called."""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import channel_scope as cs
import dlp_api_server as srv
import permissions as perm
import security
from dlp_assessment_full_auto import R, compute, maturity

SSL_SECTIONS = ("4 — SSL Policy", "7 — SSL Alignment", "GenAI — SSL Inspection")
CHANNEL_RULES = ("/zia/webDlpRules", "/zia/endPointDlpRules", "/zia/emailDlpRules", "/zia/casbDlpRules", "/zia/casbTenant",
                 "/zia/sslInspectionRules", "/zia/cloudApplicationRules")


class RecordingTenant:
    """Answers every read with an empty list and records the path. Any
    other call (session end, ...) is a no-op."""
    def __init__(self, *a, **k):
        self.requests_made = 0
        self.gets = []

    def auth(self):
        return True

    def get(self, ep, *a, **k):
        self.gets.append(str(ep).split("?", 1)[0])
        self.requests_made += 1
        return [], 200

    def __getattr__(self, name):
        return lambda *a, **k: None


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _assess(monkeypatch, channels, scopes=("dlp",)):
    """Run /api/assess with the real check registry against a recording
    fake tenant. Returns (complete report, check events, paths read)."""
    from test_assess_stream import _events
    tenants = []

    def _make(*a, **k):
        t = RecordingTenant()
        tenants.append(t)
        return t

    monkeypatch.setattr(srv, "Client", _make)
    monkeypatch.setattr(srv, "CHECK_TIMEOUT", 20)
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [])
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret",
            "scopes": list(scopes), "channels": channels}
    with _page().stream("POST", "/api/assess", json=body) as r:
        assert r.status_code == 200, r.read()[:300]
        ev = _events(r)
    complete = next(d for k, d in ev if k == "complete")
    checks = [d for k, d in ev if k == "check"]
    reads = {g for t in tenants for g in t.gets}
    return complete, checks, reads


def _reads_channel(reads, prefix):
    return any(p == prefix or p.startswith(prefix + "/") for p in reads)


# ── The prerequisite map ─────────────────────────────────────────────────

def test_the_prerequisite_map_is_explicit_and_names_known_channels():
    assert ("ssl_inspection" in [p for p, _ in cs.PREREQUISITES["web_dlp"]]), "Inline Web DLP needs SSL inspection"
    for cid, pres in cs.PREREQUISITES.items():
        assert cid in cs.CHANNELS, cid
        for pre, why in pres:
            assert pre in cs.CHANNELS and pre != cid and len(why) > 30, (cid, pre)
    # Derived each time, never written into the saved declaration.
    assert cs.normalize({"web_dlp": "zscaler"}) == {"web_dlp": {"choice": "zscaler", "note": "", "name": "Inline Web DLP"}}
    assert cs.in_scope({"web_dlp": "zscaler"}) == ["web_dlp", "ssl_inspection"]
    assert cs.in_scope({"genai_security": "zscaler"}) == ["genai_security", "ssl_inspection"]
    assert cs.in_scope({"device_control": "zscaler"}) == ["device_control", "endpoint_dlp"]
    assert cs.in_scope({"endpoint_dlp": "zscaler"}) == ["endpoint_dlp"], "Endpoint DLP brings nothing else in"
    # An explicit alternative vendor remains excluded; the prerequisite is visible as unmet.
    alt = cs.effective({"web_dlp": "zscaler", "ssl_inspection": {"choice": "alternative", "note": "Other proxy"}})["ssl_inspection"]
    assert alt["choice"] == "alternative" and alt["blocked"] and alt["required_by"] == ["web_dlp"]
    # Ticked by the operator: no prerequisite note.
    assert cs.prerequisites({"web_dlp": "zscaler", "ssl_inspection": "zscaler"}) == []
    assert cs.prerequisites({}) == [] and cs.in_scope({}) == []


def test_the_prerequisite_note_is_shown():
    pre = cs.prerequisites({"web_dlp": "zscaler"})
    assert [p["note"] for p in pre] == ["SSL/TLS Inspection: included because Inline Web DLP needs it."]
    both = cs.prerequisites({"web_dlp": "zscaler", "genai_security": "zscaler"})
    assert [p["note"] for p in both] == ["SSL/TLS Inspection: included because Inline Web DLP and GenAI Security need it."]
    cov = cs.coverage({"web_dlp": "zscaler"})
    assert "SSL/TLS Inspection: included because Inline Web DLP needs it." in cov["note"]
    # The Scope page reads the one map from the server and says it on the page.
    d = _page().get("/api/scope/prerequisites").json()
    assert d["prerequisites"]["web_dlp"][0]["id"] == "ssl_inspection" and d["prerequisites"]["web_dlp"][0]["name"] == "SSL/TLS Inspection"
    assert "decrypts" in d["prerequisites"]["web_dlp"][0]["reason"]
    js = _page().get("/static/dashboard.js").text
    assert "fetch('/api/scope/prerequisites'" in js and "included because ${info.names.join(' and ')} need" in js
    assert "Assessed as a prerequisite:" in js and "$('dbChPrereqs')" in js
    # And in the results: the Summary card's scope note and the dashboard insight.
    html = _page().get("/").text
    assert "(data && data.channel_coverage && data.channel_coverage.prerequisites)" in html and 'id="scopeNote"' in html
    assert "(cc.prerequisites || []).map(p => p.note)" in js


# ── Inline Web DLP only: SSL inspection is run, shown and read ──────────

def test_web_dlp_only_runs_and_shows_the_ssl_checks_and_reads_their_endpoints(monkeypatch):
    complete, streamed, reads = _assess(monkeypatch, {"web_dlp": {"choice": "zscaler"}})   # SSL/TLS Inspection not ticked
    ids = {c["id"] for c in complete["checks"]}
    sections = {c["section"] for c in complete["checks"]}
    assert {"4 — SSL Policy", "7 — SSL Alignment"} <= sections, sorted(sections)
    assert {"4.1", "4.2", "5.5", "A.2", "MC.12"} <= ids
    assert "/zia/sslInspectionRules" in reads and "/zia/webDlpRules" in reads and "/zia/cloudApplicationRules" in reads
    # Nothing that did not qualify was read: no other channel's rules.
    for ep in ("/zia/endPointDlpRules", "/zia/emailDlpRules", "/zia/casbDlpRules", "/zia/casbTenant"):
        assert not _reads_channel(reads, ep), ep
    assert not any(c.get("out_of_scope") for c in complete["checks"] + streamed)
    assert "Ch.B — Endpoint" not in sections and not any(s.startswith("Ch.D") for s in sections)
    assert [p["note"] for p in complete["channel_coverage"]["prerequisites"]] == ["SSL/TLS Inspection: included because Inline Web DLP needs it."]


def test_the_checks_client_reads_ssl_inspection_for_web_dlp_and_nothing_else():
    rec = RecordingTenant()
    guard = cs.ScopedClient(rec, {"web_dlp": "zscaler"})
    assert guard.get("/zia/sslInspectionRules")[1] == 200 and guard.get("/zia/webDlpRules")[1] == 200
    assert guard.get("/zia/endPointDlpRules")[1] == 0 and guard.get("/zia/emailDlpRules")[1] == 0
    assert rec.gets == ["/zia/sslInspectionRules", "/zia/webDlpRules"]


# ── Endpoint DLP only: no SSL, no Web ────────────────────────────────────

def test_endpoint_dlp_only_retains_ssl_but_never_reads_excluded_web_rules(monkeypatch):
    complete, streamed, reads = _assess(monkeypatch, {"endpoint_dlp": {"choice": "zscaler"}})
    rows = complete["checks"] + streamed
    sections = {c["section"] for c in rows}
    ids = {c["id"] for c in rows}
    assert any(s.startswith(SSL_SECTIONS) for s in sections), sorted(sections)
    assert not any(s.startswith("Ch.A") for s in sections), sorted(sections)
    assert {"4.1", "5.5", "DLP.CTRL.SSL"} <= ids
    assert not ({"A.1", "A.2", "MC.1", "MC.12", "8.5"} & ids)
    assert "B.1" in ids and "5.1" in ids, "Endpoint DLP's own checks run"
    assert _reads_channel(reads, "/zia/sslInspectionRules") and not _reads_channel(reads, "/zia/webDlpRules")
    assert "/zia/endPointDlpRules" in reads
    assert not any(c.get("out_of_scope") for c in rows) and complete["channel_coverage"]["prerequisites"] == []
    assert complete["hidden_checks"] > 0
    for k in ("Ch.A — Inline Web",):
        assert k not in complete["sections"], k


# ── Hidden checks never touch the score ─────────────────────────────────

def test_hidden_checks_do_not_affect_the_score():
    shown = [{"id": "1", "section": "Web", "label": "a", "status": "PASS", "detail": ""},
             {"id": "2", "section": "Web", "label": "b", "status": "FAIL", "detail": ""}]
    # Even a hidden row that says FAIL (or PASS) counts toward nothing.
    hidden = [{"id": "3", "section": "Email", "label": "c", "status": "FAIL", "detail": "", "out_of_scope": True},
              {"id": "4", "section": "Email", "label": "d", "status": "PASS", "detail": "", "out_of_scope": True}]
    assert compute(shown + hidden) == compute(shown) and compute(shown)[1] == 50
    assert "Email" not in compute(shown + hidden)[0]
    a, b = perm.assessment_summary(shown + hidden), perm.assessment_summary(shown)
    for k in ("score", "scored", "total", "assessed", "configured", "action_required", "excluded", "state"):
        assert a[k] == b[k], k
    assert a["hidden"] == 2 and b["hidden"] == 0


def test_hidden_checks_do_not_affect_the_streamed_score(monkeypatch):
    from test_assess_stream import FakeClient, _events
    checks = [("A.1", "Ch.A — Inline Web", "web", lambda c: R(R.PASS, "fine")),
              ("B.1", "Ch.B — Endpoint", "endpoint", lambda c: R(R.FAIL, "would fail if it ran")),
              ("D.2", "Ch.D — Email DLP", "email", lambda c: R(R.FAIL, "would fail if it ran"))]
    monkeypatch.setattr(srv, "Client", FakeClient)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: checks)
    monkeypatch.setattr(srv, "CHECK_TIMEOUT", 2)
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [])
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "scopes": ["dlp"],
            "channels": {"web_dlp": "zscaler"}}
    with _page().stream("POST", "/api/assess", json=body) as r:
        ev = _events(r)
    complete = next(d for k, d in ev if k == "complete")
    assert complete["score"] == 100 and complete["summary"]["score"] == 100 and complete["summary"]["scored"] == 1
    assert complete["summary"]["total"] == 6 and complete["summary"]["excluded"] == 5 and complete["critical"] == []


# ── No report row for a hidden check ────────────────────────────────────

def _report_rows():
    shown = [{"id": "4.1", "sec": "4 — SSL Policy", "section": "4 — SSL Policy", "label": "Inspection scope", "status": "PASS", "detail": "ok"},
             {"id": "A.1", "sec": "Ch.A — Inline Web", "section": "Ch.A — Inline Web", "label": "Rule count", "status": "FAIL", "detail": "none"}]
    hidden = [cs.skipped_result("D.2", "Ch.D — Email DLP", "HIDDENLABELEMAIL", "email_dlp", {"choice": "gap", "name": "Email DLP"}),
              cs.skipped_result("B.5", "Ch.B — Endpoint", "HIDDENLABELENDPOINT", "endpoint_dlp", {"choice": "alternative", "note": "Purview", "name": "Endpoint DLP"})]
    return shown, hidden


def test_the_word_report_has_no_row_for_a_hidden_check():
    from docx import Document
    from report_docx import generate_report
    shown, hidden = _report_rows()
    cov = cs.coverage({"web_dlp": "zscaler", "endpoint_dlp": {"choice": "alternative", "note": "Purview"}}, hidden)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.docx")
        generate_report(shown + hidden, {"org_name": "Acme", "channel_coverage": cov}, path, compute, maturity)
        doc = Document(path)
        text = "\n".join(p.text for p in doc.paragraphs) + "\n" + "\n".join(c.text for t in doc.tables for r in t.rows for c in r.cells)
    for gone in ("HIDDENLABELEMAIL", "HIDDENLABELENDPOINT", "Ch.D — Email DLP", "Ch.B — Endpoint", "Not in scope", "Purview"):
        assert gone not in text, gone
    assert "Inspection scope" in text and "Rule count" in text
    assert "SSL/TLS Inspection: included because Inline Web DLP needs it." in text
    assert text.count("2 checks are outside the selected scope and are not shown.") == 1


def test_the_compliance_mapping_and_benchmarks_have_no_row_for_a_hidden_check():
    import benchmarks
    from compliance_mapping import get_control_drilldown, get_framework_summary
    shown, hidden = _report_rows()
    assert get_framework_summary(shown + hidden) == get_framework_summary(shown)
    drill = get_control_drilldown(shown + hidden)
    assert drill == get_control_drilldown(shown)
    ev = [e["check_id"] for fw in drill.values() for c in fw["controls"] for e in c["evidence"]]
    assert ev and not ({"D.2", "B.5"} & set(ev))
    b1 = benchmarks.benchmark_report({"checks": shown + hidden})
    b2 = benchmarks.benchmark_report({"checks": shown})
    assert b1 == b2
    # The compliance report's own page counts only the checks shown.
    rep = _page().post("/api/compliance/report", json={"checks": shown + hidden}).json()
    got = _page().get(f"/api/compliance/report/{rep['report_id']}").json()
    assert got["check_count"] == 2


def test_the_page_drops_and_counts_an_older_reports_hidden_rows():
    html = _page().get("/").text
    i = html.index("function scopeVisible(data)")
    body = html[i:html.index("function assessmentSummary(data)", i)]
    assert "data.checks.filter(c => !(c && c.out_of_scope))" in body and "data.hidden_checks = (Number(data.hidden_checks) || 0) + dropped;" in body


# ── The one summary line ────────────────────────────────────────────────

@pytest.mark.parametrize("n,line", [(0, ""), (1, "1 check is outside the selected scope and is not shown."),
                                    (12, "12 checks are outside the selected scope and are not shown.")])
def test_the_summary_line_counts_the_hidden_checks(n, line):
    assert cs.hidden_note(n) == line


def test_the_streamed_summary_line_count_matches_what_was_left_out(monkeypatch):
    complete, _streamed, _reads = _assess(monkeypatch, {"web_dlp": {"choice": "zscaler"}})
    import dlp_analysis
    expected = len(dlp_analysis.assessment_checks(srv._get_checks("", ["dlp"]), {"web_dlp": {"choice": "zscaler"}}, ["dlp"])[1])
    assert expected > 0
    assert complete["hidden_checks"] == expected == complete["summary"]["hidden"] == complete["channel_coverage"]["hidden"]
    assert complete["hidden_note"] == f"{expected} checks are outside the selected scope and are not shown."
    assert complete["metadata"]["total_checks"] == len(complete["checks"]) == complete["summary"]["total"]


# ── The other prerequisites ─────────────────────────────────────────────

def test_genai_and_device_control_bring_their_prerequisites():
    checks = srv._get_checks("", ["dlp", "genai"])
    run, _, _ = cs.partition(checks, {"genai_security": "zscaler"})
    ids = {c[0] for c in run}
    assert {"E.2", "AI.5", "AI.6", "4.1"} <= ids, "GenAI's SSL inspection checks run"
    run, _, _ = cs.partition(checks, {"device_control": "zscaler"})
    ids = {c[0] for c in run}
    assert {"8.1", "5.1", "B.1"} <= ids, "Device Control brings Endpoint DLP (ZDP install, its rules)"
    assert not ({"4.1", "A.1"} & ids)
