"""The score and the coverage numbers are truthful (docs/SCORING.md): an
empty scoreable set is "Not assessed", never 100; not-permitted checks
are counted apart from the score; execution completion and coverage are
two numbers; the Word and JSON exports carry the same summary the GUI
shows."""
from __future__ import annotations

import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import permissions as perm
from dlp_assessment_full_auto import NOT_ASSESSED, compute, maturity, pct_text


def _r(id_, status, detail="", sec="DLP"):
    return {"id": id_, "sec": sec, "section": sec, "label": f"check {id_}", "status": status, "detail": detail}


DENIED = "Access denied: the API client's role does not include this feature (HTTP 403)"


def test_an_empty_scoreable_set_is_not_assessed_never_100():
    secs, overall = compute([])
    assert secs == {} and overall is None and maturity(overall) == NOT_ASSESSED and pct_text(overall) == "n/a"
    # A section made only of INFO / denied results: no percentage, no level.
    secs, overall = compute([_r("RBAC.10", "INFO", DENIED, "RBAC — ZIdentity"), _r("RBAC.11", "INFO", "ZIdentity users not accessible.", "RBAC — ZIdentity")])
    assert secs["RBAC — ZIdentity"]["pct"] is None and secs["RBAC — ZIdentity"]["scored"] == 0
    assert overall is None and maturity(overall) == NOT_ASSESSED


def test_the_score_divides_only_over_what_could_be_judged():
    rows = [_r("1", "PASS"), _r("2", "PASS"), _r("3", "FAIL"), _r("4", "REVIEW"), _r("5", "INFO"), _r("6", "INFO", DENIED), _r("7", "ERROR", "Could not complete check")]
    secs, overall = compute(rows)
    assert secs["DLP"]["scored"] == 4 and secs["DLP"]["pct"] == 50 and overall == 50 and maturity(overall) == "Developing"
    s = perm.assessment_summary(rows)
    assert (s["configured"], s["action_required"], s["needs_review"]) == (2, 1, 1)
    assert s["not_permitted"] == 1 and s["not_permitted_ids"] == ["6"] and s["errors"] == 1 and s["informational"] == 1
    assert s["total"] == 7 and s["assessed"] == 6 and s["scored"] == 4 and s["excluded"] == 3
    assert s["score"] == 50 and s["maturity"] == "Developing" and s["state"] == "partial"
    assert s["score_formula"] == perm.SCORE_FORMULA


def test_a_check_that_crashes_is_could_not_be_checked_not_not_configured():
    import dlp_assessment_full_auto as eng

    def boom(client):
        raise KeyError("unexpected API shape")
    rows = eng.run_checks(object(), [("X.1", "DLP", "crashes", boom), ("X.2", "DLP", "fine", lambda c: eng.R(eng.R.PASS, "ok"))])
    assert rows[0]["status"] == "ERROR" and "Could not complete check" in rows[0]["detail"]
    assert perm.classify(rows[0]) == "error"
    s = perm.assessment_summary(rows)
    assert s["errors"] == 1 and s["informational"] == 0 and s["state"] == "partial"


def test_the_cli_report_and_json_show_coverage_and_warn_when_partial(capsys, tmp_path):
    import dlp_assessment_full_auto as eng
    rows = [_r("1", "PASS"), _r("2", "FAIL"), _r("3", "INFO", DENIED), _r("4", "ERROR", "check 4: Could not complete check. boom")]
    eng.report(rows, {"org_name": "Acme"})
    out = capsys.readouterr().out
    assert "Assessed 3 of 4 checks" in out and "1 not permitted" in out and "1 could not be checked" in out
    assert "PARTIAL COVERAGE" in out and f"{len(eng.REG)} checks" not in out
    path = tmp_path / "r.json"
    eng.save(rows, {"org_name": "Acme"}, str(path))
    d = json.loads(path.read_text())
    assert d["metadata"]["checks"] == 4 and d["coverage"]["state"] == "partial" and d["coverage"]["errors"] == 1 and d["coverage"]["not_permitted"] == 1
    # A complete run carries no banner.
    eng.report([_r("1", "PASS"), _r("2", "FAIL")], {"org_name": "Acme"})
    out = capsys.readouterr().out
    assert "Assessed 2 of 2 checks" in out and "PARTIAL COVERAGE" not in out


def test_the_real_run_numbers_reproduce():
    """The audited run: 311 checks — 89 configured, 20 action required, 132 needs review, 70 outside the score, 2 of them not permitted."""
    rows = [_r(f"p{i}", "PASS") for i in range(89)] + [_r(f"f{i}", "FAIL") for i in range(20)] + [_r(f"r{i}", "REVIEW") for i in range(132)]
    rows += [_r(f"i{i}", "INFO") for i in range(68)] + [_r("d1", "INFO", DENIED), _r("d2", "INFO", "HTTP 401 Unauthorized")]
    s = perm.assessment_summary(rows)
    assert s["total"] == 311 and s["assessed"] == 309 and s["not_permitted"] == 2 and s["scored"] == 241 and s["score"] == 37 and s["maturity"] == "Initial"
    assert s["state"] == "partial" and s["excluded"] == 70
    _secs, overall = compute(rows)
    assert overall == 37


def test_every_state_the_interface_distinguishes():
    assert perm.assessment_summary([])["state"] == "unassessed"
    assert perm.assessment_summary([_r("1", "PASS")])["state"] == "complete"
    assert perm.assessment_summary([_r("1", "PASS"), _r("2", "INFO", DENIED)])["state"] == "partial"
    assert perm.assessment_summary([_r("1", "PASS"), _r("2", "ERROR", "Could not complete check")])["state"] == "partial"
    only_info = perm.assessment_summary([_r("1", "INFO"), _r("2", "INFO")])
    assert only_info["state"] == "complete" and only_info["score"] is None and only_info["maturity"] == NOT_ASSESSED
    for r, cls in ((_r("a", "PASS"), "configured"), (_r("b", "FAIL"), "action_required"), (_r("c", "REVIEW"), "needs_review"),
                   (_r("d", "INFO", DENIED), "not_permitted"), (_r("e", "ERROR", "boom"), "error"), (_r("f", "INFO", "not licensed"), "informational")):
        assert perm.classify(r) == cls
    assert set(perm.CLASS_LABELS) == set(perm.CLASSES)


def test_the_word_report_carries_the_same_summary():
    from report_docx import generate_report
    rows = [_r("1", "PASS"), _r("2", "FAIL"), _r("3", "INFO", DENIED), _r("4", "INFO")]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.docx")
        generate_report(rows, {"org_name": "Acme"}, path, compute, maturity)
        from docx import Document
        text = "\n".join(p.text for p in Document(path).paragraphs) + "\n" + "\n".join(c.text for t in Document(path).tables for row in t.rows for c in row.cells)
    assert "3 of 4 (1 not permitted)" in text
    assert "50% — 1 configured of 2 scoreable" in text
    assert "Score = configured ÷ (configured + action required + needs review): 1 ÷ 2" in text
    assert "2 checks are outside the score (1 not permitted, 0 could not be checked, 1 informational)" in text
    assert "3 of 4 checks ran; 1 could not" in text
    # Nothing scoreable: "Not assessed", no invented percentage anywhere.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.docx")
        generate_report([_r("1", "INFO"), _r("2", "INFO")], {"org_name": "Acme"}, path, compute, maturity)
        from docx import Document
        text = "\n".join(p.text for p in Document(path).paragraphs) + "\n".join(c.text for t in Document(path).tables for row in t.rows for c in row.cells)
    assert "Not assessed" in text and "(100%)" not in text and "None%" not in text and "Not measured" in text
    assert "rated: Not assessed (Not assessed)" in text


def test_the_complete_event_carries_the_summary_and_a_null_score_when_nothing_was_scoreable(monkeypatch):
    """The SSE 'complete' payload has the same summary the GUI and the
    exports read; a run whose every check is informational reports
    score null / Not assessed, never 100 / Optimized."""
    from dlp_assessment_full_auto import R
    from test_assess_stream import _run
    checks = [("A.1", "DLP", "only info", lambda c: R(R.INFO, "not licensed")),
              ("A.2", "DLP", "denied", lambda c: R(R.INFO, DENIED))]
    ev = _run(monkeypatch, checks)
    complete = next(d for k, d in ev if k == "complete")
    assert complete["score"] is None and complete["maturity"] == NOT_ASSESSED
    assert complete["summary"]["state"] == "partial" and complete["summary"]["not_permitted"] == 1 and complete["summary"]["scored"] == 0
    assert complete["summary"]["not_permitted_ids"] == ["A.2"] and complete["sections"]["DLP"]["pct"] is None
    # And a run with something to judge: the numbers add up the same way everywhere.
    checks = [("B.1", "Web", "ok", lambda c: R(R.PASS, "fine")), ("B.2", "Web", "gap", lambda c: R(R.FAIL, "missing")),
              ("B.3", "Web", "denied", lambda c: R(R.INFO, DENIED))]
    complete = next(d for k, d in _run(monkeypatch, checks) if k == "complete")
    s = complete["summary"]
    assert complete["score"] == 50 and s["score"] == 50 and s["assessed"] == 2 and s["total"] == 3 and s["not_permitted"] == 1
    assert complete["permissions"]["blocked"] == s["not_permitted"]
    assert complete["sections"]["Web"] == {"total": 3, "pass": 1, "fail": 1, "warn": 0, "info": 1, "scored": 2, "pct": 50}


def test_the_page_never_prints_undefined_and_reads_one_summary():
    c = TestClient(__import__("dlp_api_server").app)
    html = c.get("/").text
    assert "function loadHealthBadge()" in html and "Number.isFinite(n) ? n : '—'" in html and "addEventListener('DOMContentLoaded', loadHealthBadge)" in html
    assert "function assessmentSummary(data)" in html and "function classifyCheck(c)" in html and "'Not assessed'" in html
    assert "window.__dbRunStarted" in html and "window.__dbProgress(evt)" in html
    assert "Not measured" in html and "'Not permitted'" in html and "'Could not be checked'" in html
    assert 'id="coverageNote"' in html
    js = c.get("/static/dashboard.js").text
    assert '<div class="score-num" id="scoreNum">—</div>' in js and "Not assessed yet" in js and "no run in this tab yet" in js
    assert "Previous result · run" in js and "window.__dbRunStarted = function" in js and "window.__dbProgress = function" in js
    assert "Not measured" in js and "assessed · " in js and "'Assessing now" in js
    assert "sections || {}).filter(([, d]) => d.pct !== null" in js
    assert "docs/SCORING.md" in js
    assert os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "SCORING.md"))
