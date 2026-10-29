"""This app's quality and security score (tools/quality_score.py, GET
/api/quality-score, the "Quality and security score" section of Advanced
settings).

The maths runs on made-up records under tests/fixtures/qa/ (not real QA
results; the real ones live in docs/qa/findings/), with a coverage map
injected so the numbers do not move when the suite grows. The findings
records are untrusted input: every hostile shape is refused, fail closed.
"""
from __future__ import annotations

import json
import os
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import dlp_api_server as srv  # noqa: E402
import quality_score as qs  # noqa: E402
import security  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "qa")
RUN = os.path.join(FIX, "test_run.json")
ALL_CONTROLS = sorted({c for a in qs.AREAS for s in a["subs"] for c in s["controls"]})
FULL = {"ALL": ALL_CONTROLS}      # every required control has a test ("ALL" has no prefix)


def _records(case):
    recs, errors = qs.load_findings(os.path.join(FIX, case, "findings"))
    assert errors == []
    return recs


def _run(**over):
    run = qs.load_test_run(RUN)
    run.update(over)
    return run


def _sub(result, key):
    return next(s for a in result["areas"] for s in a["subs"] if s["key"] == key)


def _finding(fid="SBD-INPUT-01", severity="medium", status="open", **extra):
    f = {"id": fid, "title": "Fixture finding", "severity": severity, "status": status, "reason": "Fixture reason"}
    f.update(extra)
    return f


def _record(*findings, area="Fixture", title="Fixture record"):
    return {"area": area, "title": title, "findings": list(findings)}


def _write(d, name, obj):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj))
    return p


# ── The score ────────────────────────────────────────────────────────

def test_the_fixture_scores_as_documented():
    """SSDF PW.8.2 · SSDF RV.1.1: tests 40%, open findings 40%, coverage 20%; areas weighted 25/35/25/15."""
    # Arrange
    recs = _records("full")
    # Act
    r = qs.compute(recs, _run(), FULL)
    # Assert
    assert _sub(r, "regression")["score"] == 99.8           # 0.4*99.5 + 0.4*100 + 0.2*100
    assert _sub(r, "untrusted_input")["score"] == 94.8      # 0.4*95 + 0.4*(100-8) + 20
    assert _sub(r, "traffic_analysis")["score"] == 99.2     # 0.4*100 + 0.4*(100-2) + 20
    assert _sub(r, "write_paths")["based_on"] == ["tests", "coverage"]   # no record: findings left out
    assert [a["score"] for a in r["areas"]] == [99.8, 98.7, 99.7, 100.0]
    assert r["overall"]["raw"] == 99.4 and r["overall"]["score"] == 79      # the run has 10 failed tests: capped at C
    assert r["overall"]["grade"] == "C" and r["overall"]["cap"]["kind"] == "tests" and r["overall"]["cap"]["applied"] is True


def test_fixed_and_accepted_findings_are_recorded_and_not_penalised():
    """SSDF RV.2.2 · SSDF PW.8.2: a fixed or accepted finding is listed with its status and costs nothing."""
    r = qs.compute(_records("full"), _run(), FULL)
    assert _sub(r, "auth_scope_secrets")["findings"] == {"score": 100.0, "open": 0, "fixed": 0, "accepted": 1, "records": ["sbd-auth"]}
    assert r["counts"]["by_severity"]["high"] == {"open": 0, "fixed": 1, "accepted": 0}
    assert [f["id"] for f in r["findings"]][:2] == ["SBD-INPUT-01", "FUNC-PATH-01"]   # open first, by severity
    assert {f["status"] for f in r["findings"]} == {"open", "fixed", "accepted"}


def test_no_findings_at_all_scores_on_tests_and_coverage():
    """SSDF PW.8.2: boundary: no record anywhere; every sub-score is based on tests and coverage only."""
    r = qs.compute([], _run(passed=100, failed=0, files={}), FULL)
    assert r["overall"]["score"] == 100
    assert all("findings" not in s["based_on"] for a in r["areas"] for s in a["subs"])
    assert r["counts"]["findings"] == 0 and r["overall"]["cap"] is None


def test_there_is_no_score_without_a_test_run():
    """SSDF PW.8.2 · CWE-1188: boundary: without docs/qa/test_run.json the score is empty, never a coverage-only number."""
    r = qs.compute(_records("full"), None, FULL)
    assert r["overall"]["score"] is None and r["overall"]["label"] == "No score yet"
    assert all(a["score"] is None for a in r["areas"])
    assert r["counts"]["findings"] == 6


@pytest.mark.parametrize("severity,penalty,cap", [("critical", 40, 39), ("high", 20, 69), ("medium", 8, None), ("low", 2, None), ("info", 0, None)])
def test_each_severity_costs_its_cvss_band_penalty(severity, penalty, cap):
    """SSDF RV.1.2 · CWE-1357: one open finding of each CVSS v3.1 severity costs its penalty; critical and high also cap."""
    # Arrange
    rec = qs.validate_record(_record(_finding(severity=severity)), "sbd-input")
    # Act
    r = qs.compute([rec], _run(passed=100, failed=0, files={}), FULL)
    # Assert
    assert _sub(r, "untrusted_input")["findings"]["score"] == 100 - penalty
    assert (r["overall"]["cap"] or {}).get("limit") == cap


@pytest.mark.parametrize("severity", qs.SEVERITIES)
def test_a_fixed_finding_of_any_severity_costs_nothing(severity):
    """SSDF RV.2.2: boundary: a fixed critical is as free as a fixed info, and no fixed finding caps the score."""
    rec = qs.validate_record(_record(_finding(severity=severity, status="fixed", reason="")), "sbd-input")
    r = qs.compute([rec], _run(passed=100, failed=0, files={}), FULL)
    assert _sub(r, "untrusted_input")["findings"]["score"] == 100
    assert r["overall"]["score"] == 100 and r["overall"]["cap"] is None


def test_an_open_high_caps_the_overall_score_and_says_why():
    """SSDF RV.1.2 · CWE-1357: hard rule: an open high finding caps the overall score at 69, naming the finding."""
    r = qs.compute(_records("open_high"), _run(), FULL)
    cap = r["overall"]["cap"]
    assert r["overall"]["raw"] > 69 and r["overall"]["score"] == 69
    assert cap["applied"] is True and cap["severity"] == "high" and cap["findings"] == ["SBD-WRITES-01"]
    assert "SBD-WRITES-01" in cap["reason"] and "69" in cap["reason"]
    assert r["overall"]["grade"] == "D"


def test_an_open_critical_caps_lower_than_an_open_high():
    """SSDF RV.1.2 · CWE-1357: with a critical and a high open, the critical cap (39) wins."""
    r = qs.compute(_records("open_critical"), _run(), FULL)
    assert r["overall"]["score"] == 39 and r["overall"]["cap"]["severity"] == "critical" and r["overall"]["grade"] == "F"


def test_a_score_already_below_the_cap_is_kept_and_the_cap_still_shown():
    """SSDF RV.1.2: boundary: the cap never raises a score; it is shown as in force but not applied."""
    run = _run(passed=10, failed=90, files={})
    r = qs.compute(_records("open_high"), run, {"ALL": []})
    assert r["overall"]["score"] < 69
    assert r["overall"]["cap"]["applied"] is False and r["overall"]["cap"]["limit"] == 69


def test_the_findings_part_never_goes_below_zero():
    """SSDF RV.1.2: boundary: three open criticals cost 120 points but the part stops at 0."""
    rec = qs.validate_record(_record(*[_finding(f"SBD-INPUT-0{i}", "critical") for i in range(1, 4)]), "sbd-input")
    r = qs.compute([rec], _run(passed=100, failed=0, files={}), FULL)
    assert _sub(r, "untrusted_input")["findings"]["score"] == 0


@pytest.mark.parametrize("score,grade", [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"), (69, "D"), (60, "D"), (59, "F"), (0, "F")])
def test_grade_boundaries(score, grade):
    """SSDF PW.8.2: each grade starts exactly at its documented lower bound."""
    assert qs.grade(score)["grade"] == grade


def test_coverage_counts_a_section_covered_by_any_requirement_inside_it():
    """SSDF PW.8.2 · ASVS V1.1.1: coverage reads the standards mapping; a missing control is named."""
    cov = {"OWASP ASVS 4.0.3": ["V5.1.3"], "CWE": ["CWE-20"], "WCAG 2.2": ["SC 1.4.10"]}
    assert qs._is_covered("ASVS V5.1", qs._covered_names(cov)) and not qs._is_covered("ASVS V5.2", qs._covered_names(cov))
    r = qs.compute([], _run(), cov)
    ui = _sub(r, "ui_a11y")["coverage"]
    assert ui["covered"] == ["WCAG SC 1.4.10"] and "WCAG SC 2.1.1" in ui["missing"]


def test_a_record_with_no_area_still_counts_toward_the_cap():
    """CWE-1357 · SSDF RV.1.2: an open high in a record the formula does not place still caps the score (fail closed)."""
    rec = qs.validate_record(_record(_finding("NEW-CHECK-01", "high")), "new-check")
    r = qs.compute([rec], _run(passed=100, failed=0, files={}), FULL)
    assert r["overall"]["score"] == 69 and r["findings"][0]["area"] == "other"
    assert any("new-check" in w for w in r["warnings"])


# ── Failing tests cap the grade ───────────────────────────────────────

def _failing_run(failed, errors):
    """The fixture run with `failed` failures in every file (and `errors` errors), everything else passing."""
    files = {k: {"passed": v["passed"] + v["failed"], "failed": failed, "skipped": v["skipped"]} for k, v in _run()["files"].items()}
    return _run(passed=sum(v["passed"] for v in files.values()), failed=failed * len(files), errors=errors, files=files)


@pytest.mark.parametrize("failed,errors", [(1, 0), (0, 1), (1, 1)])
def test_any_failed_or_errored_test_caps_the_grade_at_c(failed, errors):
    """SSDF PW.8.2 · SSDF RV.1.1 · CWE-1357: a run with a failed or errored test is never graded above C and never says 'Tests pass'."""
    # Arrange
    run = _failing_run(failed, errors)
    n = run["failed"] + run["errors"]
    # Act
    r = qs.compute([], run, FULL)
    o = r["overall"]
    # Assert
    assert o["raw"] >= 90 and o["score"] == qs.FAILED_TESTS_CAP == 79 and o["grade"] == "C", o
    assert "Tests pass" not in o["meaning"] and o["meaning"].startswith(f"{n} test{'s' if n != 1 else ''} failed"), o["meaning"]
    assert o["cap"]["kind"] == "tests" and o["cap"]["applied"] is True and str(n) in o["cap"]["reason"]


def test_a_run_with_no_failure_keeps_its_grade():
    """SSDF PW.8.2: boundary: zero failed and zero errored tests: no cap, grade A says the tests pass."""
    r = qs.compute([], _failing_run(0, 0), FULL)
    assert r["overall"]["grade"] == "A" and r["overall"]["cap"] is None and r["overall"]["meaning"].startswith("Tests pass")


def test_an_open_high_and_failing_tests_keep_the_lower_cap_and_say_both():
    """SSDF RV.1.2 · CWE-1357: an open high (69) is lower than the failing-tests cap (79): 69 holds and the words still count the failures."""
    r = qs.compute(_records("open_high"), _failing_run(1, 0), FULL)
    o = r["overall"]
    assert o["score"] == 69 and o["cap"]["severity"] == "high" and o["meaning"].startswith("8 tests failed")


# ── Every test file belongs to an area; no glob is dead ─────────────

TESTS_DIR = os.path.join(ROOT, "tests")


def _test_files():
    return sorted(n for n in os.listdir(TESTS_DIR) if n.startswith("test_") and n.endswith(".py"))


def _area_globs():
    return [(s["key"], g) for a in qs.AREAS for s in a["subs"] for g in s["tests"] if g != "*"]


def test_every_test_file_is_in_an_area_or_listed_as_regression_only():
    """SSDF PW.8.2 · CWE-1357: each tests/test_*.py counts toward its area's tests part, or is named as counted by Regression (the whole suite) only."""
    import fnmatch
    pats = [g for _, g in _area_globs()] + list(qs.REGRESSION_ONLY)
    loose = [n for n in _test_files() if not any(fnmatch.fnmatchcase(n, g) for g in pats)]
    assert not loose, f"add these to an area's tests in tools/quality_score.py, or to REGRESSION_ONLY: {loose}"


@pytest.mark.parametrize("sub,pattern", _area_globs() + [("regression-only", g) for g in qs.REGRESSION_ONLY])
def test_no_area_glob_is_dead(sub, pattern):
    """SSDF PW.8.2 · CWE-1164: every test glob of the score matches at least one file (a dead glob silently drops an area's tests)."""
    import fnmatch
    if pattern == "test_glass*.py" and not os.path.exists(os.path.join(ROOT, "static", "glass.css")):
        pytest.skip("the Liquid Glass layer is on its own branch: this glob goes live when it merges")
    assert any(fnmatch.fnmatchcase(n, pattern) for n in _test_files()), (sub, pattern)


def test_a_regression_only_file_is_not_also_in_an_area():
    """SSDF PW.8.2: the regression-only list holds only files no area counts (no stale entry hides a mapped file)."""
    import fnmatch
    both = [g for g in qs.REGRESSION_ONLY if any(fnmatch.fnmatchcase(n, g) and any(fnmatch.fnmatchcase(n, a) for _, a in _area_globs())
                                                  for n in _test_files())]
    assert not both, both


@pytest.mark.parametrize("name,sub", [("test_sbd_writes.py", "write_paths"), ("test_c6_admin_ops.py", "write_paths"),
                                      ("test_sbd_untrusted_input.py", "untrusted_input"), ("test_c6_auth.py", "auth_scope_secrets"),
                                      ("test_qa_func_path.py", "traffic_analysis"), ("test_qa6_builders_lifecycle.py", "builders"),
                                      ("test_c6_ui_core.py", "ui_a11y"), ("test_path_live_motion.py", "motion"),
                                      ("test_flow_motion_models.py", "motion")])
def test_wave_6_test_files_count_toward_their_area(name, sub):
    """SSDF PW.8.2 · CWE-1357: a failure in a Wave 6 QA file lowers the area it tests, not only the whole-suite Regression score."""
    files = {f"tests/{name}": {"passed": 0, "failed": 3, "skipped": 0}}
    r = qs.compute([], _run(passed=0, failed=3, files=files), FULL)
    assert _sub(r, sub)["tests"] == {"score": 0.0, "passed": 0, "failed": 3, "skipped": 0, "files": 1}, name


# ── A mapped record that does not exist is said ─────────────────────

def test_a_mapped_slug_without_a_record_file_is_warned():
    """SSDF PO.3.2 · CWE-1357: a sub-area whose formula names a record that is not there says which one (c6-ui-core had none)."""
    recs = [qs.validate_record(_record(_finding("UI-01", "low", "fixed", reason="")), "ui")]
    r = qs.compute(recs, _run(), FULL)
    warn = [w for w in r["warnings"] if "c6-ui-core" in w]
    assert warn and "c6-ui-ops" in warn[0] and "c6-tooltips" in warn[0], r["warnings"]


def test_every_record_the_formula_names_exists_in_the_repository():
    """SSDF PO.3.2: boundary: on the real records, no sub-area that has records misses one of its named records."""
    recs, errors = qs.load_findings()
    assert errors == []
    r = qs.compute(recs, None, FULL)
    assert not [w for w in r["warnings"] if w.startswith("Named findings record")], r["warnings"]


def test_the_overview_says_the_tests_part_needs_a_recorded_run():
    """SSDF PO.3.2 · CWE-1059: docs/OVERVIEW.md says the score's tests part needs docs/qa/test_run.json (and how to write it) and names every cap."""
    text = open(os.path.join(ROOT, "docs", "OVERVIEW.md"), encoding="utf-8").read()
    para = " ".join(text.split("- **Quality and security score**", 1)[1].split("\n- **", 1)[0].split())
    for needle in ("docs/qa/test_run.json", "--from-junit", "No score yet", f"at {qs.CAPS['critical']}", f"at {qs.CAPS['high']}",
                   f"at {qs.FAILED_TESTS_CAP}"):
        assert needle in para, needle


# ── Hostile findings files ───────────────────────────────────────────

GOOD = _record(_finding())


def _hostile_cases():
    deep = '{"area": "a", "title": "t", "findings": [], "standards": ' + "[" * 50 + "]" * 50 + "}"
    huge = json.dumps(dict(GOOD, standards=["x" * 70] * 4000))
    return {
        "huge file": huge,
        "deep nesting": deep,
        "very deep nesting": "[" * 200000,
        "not an object": "[]",
        "findings not a list": dict(GOOD, findings={"id": "x"}),
        "severity wrong type": _record(_finding(severity=9)),
        "severity unknown": _record(_finding(severity="severe")),
        "status unknown": _record(_finding(status="ignored")),
        "tests_added bool": dict(GOOD, tests_added=True),
        "tests_added string": dict(GOOD, tests_added="3"),
        "tests_added negative": dict(GOOD, tests_added=-1),
        "title not a string": dict(GOOD, title=["t"]),
        "extra root key": dict(GOOD, score=100),
        "extra finding key": _record(_finding(cvss=9.8)),
        "extra check key": dict(GOOD, checks=[{"id": "c", "what": "w", "result": "pass", "html": "<b>"}]),
        "missing finding key": _record({"id": "SBD-INPUT-01", "title": "t", "severity": "low"}),
        "html in record title": dict(GOOD, title='<img src=x onerror="alert(1)">'),
        "html in finding title": _record(_finding(title="Fixture <script>alert(1)</script>")),
        "entity in finding title": _record(_finding(title="Fixture &lt;b&gt;")),
        "control character": _record(_finding(title="Fixture\nInjected: row")),
        "direction override": _record(_finding(title="Fixture \u202egnp.exe")),
        "bad id": _record(_finding(fid="../../etc")),
        "bad cwe": _record(_finding(cwe="CWE-79<x>")),
        "bad commit": _record(_finding(commit="HEAD; rm -rf /")),
        "bad test ref": _record(_finding(test="javascript:alert(1)")),
        "check result unknown": dict(GOOD, checks=[{"id": "c", "what": "w", "result": "maybe"}]),
        "open without a reason": _record(_finding(reason="", fix="")),
        "duplicate id in a file": _record(_finding(), _finding()),
        "duplicate key": '{"area": "a", "area": "b", "title": "t", "findings": []}',
        "NaN": '{"area": "a", "title": "t", "findings": [], "tests_added": NaN}',
        "too many findings": _record(*[_finding(f"SBD-INPUT-{i}") for i in range(qs.MAX_FINDINGS + 1)]),
        "title too long": dict(GOOD, title="t" * 301),
        "not json": "{area: a}",
    }


HOSTILE = _hostile_cases()


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_a_hostile_findings_file_is_refused(tmp_path, case):
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20 · CWE-400 · CWE-674 · CWE-79: a findings file breaking the schema is refused with a reason."""
    # Arrange
    _write(str(tmp_path), "sbd-input.json", HOSTILE[case])
    # Act
    recs, errors = qs.load_findings(str(tmp_path))
    # Assert
    assert recs == [] and len(errors) == 1, (case, errors)
    assert "sbd-input" in errors[0]


@pytest.mark.parametrize("raw,why", [(b"\xef\xbb\xbf{}", "byte-order mark"), (b'{"area": "\xff"}', "not UTF-8")])
def test_a_findings_file_in_another_encoding_is_refused(tmp_path, raw, why):
    """ASVS V5.1.4 · CWE-176: only plain UTF-8 JSON is read."""
    (tmp_path / "ui.json").write_bytes(raw)
    _, errors = qs.load_findings(str(tmp_path))
    assert why in errors[0]


def test_a_finding_id_used_by_two_records_is_refused(tmp_path):
    """ASVS V5.1.3 · CWE-694: one id names one finding across all records."""
    _write(str(tmp_path), "sbd-input.json", GOOD)
    _write(str(tmp_path), "sbd-auth.json", GOOD)
    _, errors = qs.load_findings(str(tmp_path))
    assert any("SBD-INPUT-01" in e and "also in" in e for e in errors)


@pytest.mark.parametrize("name", ["Upper.json", "a b.json", "x" * 45 + ".json", "..json"])
def test_a_findings_file_with_an_odd_name_is_refused(tmp_path, name):
    """ASVS V12.3.1 · CWE-22: a record's file name is its slug: a-z, 0-9 and -, at most 40 characters."""
    _write(str(tmp_path), name, GOOD)
    _, errors = qs.load_findings(str(tmp_path))
    assert len(errors) == 1 and "file name" in errors[0]


def test_a_findings_file_that_is_a_link_is_refused(tmp_path):
    """ASVS V12.3.1 · CWE-59: a symbolic link is never followed out of the findings folder."""
    target = _write(str(tmp_path / "elsewhere"), "real.json", GOOD)
    os.makedirs(tmp_path / "findings")
    os.symlink(target, tmp_path / "findings" / "sbd-input.json")
    _, errors = qs.load_findings(str(tmp_path / "findings"))
    assert "not a regular file" in errors[0]


def test_too_many_findings_files_are_refused(tmp_path):
    """ASVS V12.1.1 · CWE-770: the folder holds at most MAX_FILES records."""
    for i in range(qs.MAX_FILES + 1):
        _write(str(tmp_path), f"r{i}.json", GOOD)
    recs, errors = qs.load_findings(str(tmp_path))
    assert recs == [] and "at most" in errors[0]


@pytest.mark.parametrize("over", [{"passed": -1}, {"failed": "1"}, {"commit": "not-a-sha"}, {"date": "yesterday"},
                                  {"duration_s": "fast"}, {"files": {"../x.py": {"passed": 1, "failed": 0, "skipped": 0}}},
                                  {"files": {"tests/test_x.py": {"passed": 1}}}, {"extra": 1}])
def test_a_hostile_test_run_is_refused(over):
    """ASVS V5.1.3 · CWE-20: docs/qa/test_run.json is checked as strictly as a findings record."""
    run = json.load(open(RUN, encoding="utf-8"))
    run.update(over)
    with pytest.raises(qs.InputError):
        qs.validate_test_run(run)


def test_invalid_input_fails_closed_and_writes_nothing(tmp_path):
    """ASVS V7.4.1 · CWE-636 · SSDF PW.9.1: one bad record stops the build (exit 2); no output is written or overwritten."""
    # Arrange
    fdir = str(tmp_path / "findings")
    _write(fdir, "sbd-input.json", HOSTILE["html in finding title"])
    md, js = tmp_path / "Q.md", tmp_path / "q.json"
    # Act
    rc = qs.main([], findings_dir=fdir, test_run=RUN, out_md=str(md), out_json=str(js), coverage=FULL)
    rc_check = qs.main(["--check"], findings_dir=fdir, test_run=RUN, out_md=str(md), out_json=str(js), coverage=FULL)
    # Assert
    assert rc == 2 and rc_check == 2
    assert not md.exists() and not js.exists()


# ── Escaping in the Markdown ────────────────────────────────────────

def test_record_text_is_inert_in_the_markdown():
    """ASVS V5.3.1 · CWE-116 · CWE-79: a reason or title with HTML, links or table pipes is escaped in QUALITY_SCORE.md."""
    # Arrange
    rec = qs.validate_record(_record(_finding(title="Fixture [click](javascript:alert(1)) | forged cell",
                                              reason="Fixture <img src=x onerror=alert(1)> `code` | x")), "sbd-input")
    # Act
    md = qs.render_md(qs.compute([rec], _run(), FULL))
    # Assert
    assert "<img" not in md and "&lt;img src=x onerror=alert(1)&gt;" in md
    assert "\\[click\\](javascript:alert(1)) \\| forged cell" in md
    assert "](javascript:" not in md.replace("\\](javascript:", "")
    row = next(line for line in md.splitlines() if line.startswith("| SBD-INPUT-01"))
    assert row.count(" | ") == 8 and row.count("\\|") == 2   # nine columns: both pipes escaped, no forged cell


def test_the_markdown_documents_the_formula_the_run_and_every_finding():
    """SSDF PW.8.2 · SSDF PO.3.2: the report names the formula, the weights, the caps, the date and commit and each finding with its CWE/ASVS and status."""
    md = qs.render_md(qs.compute(_records("full"), _run(), FULL))
    for needle in ("**Overall: 79 / 100, grade C (Fair).** 10 tests failed in the recorded run.", "commit `0123456789ab`", "2026-10-29T12:00:00",
                   "| critical | 9.0-10.0 | 40 | 39 |", "| high | 7.0-8.9 | 20 | 69 |", "## How the score is computed",
                   "| SBD-INPUT-02 | Fixture: a name breaks the export | high | CWE-116 | V5.3.1 | fixed |",
                   "| SBD-AUTH-01 | Fixture: the token is long-lived by design | low | CWE-613 | V3.3.1 | accepted |"):
        assert needle in md, needle


# ── --check and --from-junit ─────────────────────────────────────────

def test_check_passes_when_current_and_fails_when_an_input_or_output_changes(tmp_path):
    """SSDF PW.8.2 · SSDF PO.3.2: --check is 0 on fresh outputs and 1 when a record, the run or an output changed."""
    # Arrange
    fdir = str(tmp_path / "findings")
    shutil.copytree(os.path.join(FIX, "full", "findings"), fdir)
    run = str(tmp_path / "test_run.json")
    shutil.copy(RUN, run)
    md, js = str(tmp_path / "Q.md"), str(tmp_path / "q.json")
    kw = dict(findings_dir=fdir, test_run=run, out_md=md, out_json=js, coverage=FULL)
    assert qs.main(["--check"], **kw) == 1                      # no outputs yet: stale
    assert qs.main([], **kw) == 0
    # Act / Assert: current
    assert qs.main(["--check"], **kw) == 0
    # a new record makes both outputs stale
    _write(fdir, "sbd-writes.json", _record(_finding("SBD-WRITES-09", "low")))
    assert qs.main(["--check"], **kw) == 1
    assert qs.main([], **kw) == 0 and qs.main(["--check"], **kw) == 0
    # a new test run too
    data = json.load(open(run, encoding="utf-8"))
    data["failed"] += 1
    _write(str(tmp_path), "test_run.json", data)
    assert qs.main(["--check"], **kw) == 1
    assert qs.main([], **kw) == 0
    # and a hand edit of either output
    with open(md, "a", encoding="utf-8") as f:
        f.write("edited\n")
    assert qs.main(["--check"], **kw) == 1


def test_the_committed_score_is_current():
    """SSDF PW.8.2 · SSDF PO.3.2: docs/QUALITY_SCORE.md and docs/quality_score.json match their inputs (python tools/quality_score.py)."""
    assert qs.main(["--check"]) == 0


def test_from_junit_counts_every_outcome_per_file(tmp_path):
    """SSDF PW.8.2 · Scorecard CI-Tests: the run record comes from pytest's JUnit XML: passed, failed, errors, skipped, per file."""
    # Arrange
    out = tmp_path / "test_run.json"
    # Act
    rc = qs.main(["--from-junit", os.path.join(FIX, "junit.xml"), "--commit", "abcdef123456", "--out", str(out)])
    # Assert
    assert rc == 0
    run = qs.validate_test_run(json.loads(out.read_text()))
    assert (run["passed"], run["failed"], run["errors"], run["skipped"]) == (3, 1, 1, 1)
    assert run["date"] == "2026-10-29T09:15:42" and run["commit"] == "abcdef123456" and run["duration_s"] == 12.3
    assert run["files"]["tests/test_flow_animator.py"] == {"passed": 1, "failed": 1, "skipped": 0}
    assert run["files"]["tests/test_auth_session.py"] == {"passed": 1, "failed": 0, "skipped": 1}


@pytest.mark.parametrize("xml", [
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><testsuite timestamp="2026-10-29T00:00:00"><testcase classname="tests.test_x" name="&b;"/></testsuite>',
    '<?xml version="1.0"?><!DOCTYPE t SYSTEM "file:///etc/passwd"><testsuite/>',
])
def test_from_junit_refuses_a_dtd(tmp_path, xml):
    """ASVS V5.5.2 · CWE-611 · CWE-776: a JUnit file with a DTD or entities is refused before parsing."""
    p = tmp_path / "j.xml"
    p.write_text(xml)
    with pytest.raises(qs.InputError, match="DTD"):
        qs.run_from_junit(str(p), commit="abcdef1", date="2026-10-29")


# ── The route ────────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setattr(srv, "_QUALITY_SCORE_JSON", str(tmp_path / "quality_score.json"))
    monkeypatch.setattr(srv, "_QUALITY_SCORE_MD", str(tmp_path / "QUALITY_SCORE.md"))
    return TestClient(srv.app)


def test_the_route_serves_the_score(client, tmp_path):
    """ASVS V4.1.3 · CWE-200: GET /api/quality-score returns the generated file as is, marked available."""
    result = qs.compute(_records("full"), _run(), FULL)
    (tmp_path / "quality_score.json").write_text(qs.render_json(result), encoding="utf-8")
    r = client.get("/api/quality-score")
    assert r.status_code == 200
    assert r.json()["available"] is True and r.json()["overall"]["score"] == result["overall"]["score"] == 79


@pytest.mark.parametrize("content", [None, "{not json", "[]", '{"schema_version": 2}', "x" * (srv._QUALITY_SCORE_MAX_BYTES + 1)])
def test_a_missing_or_unreadable_score_is_no_score_yet_not_an_error(client, tmp_path, content):
    """ASVS V7.4.1 · CWE-755 · CWE-209: a missing, corrupt, foreign or oversized file answers 200 "available": false, with no detail leaked."""
    if content is not None:
        (tmp_path / "quality_score.json").write_text(content, encoding="utf-8")
    r = client.get("/api/quality-score")
    assert r.status_code == 200
    assert r.json()["available"] is False and r.json()["reason"].startswith("No score yet")
    assert str(tmp_path) not in r.text


def test_the_route_never_follows_a_link(client, tmp_path):
    """ASVS V12.3.1 · CWE-59: a score file replaced by a link to another file is not served."""
    other = tmp_path / "secret.json"
    other.write_text('{"schema_version": 1, "secret": "x"}')
    os.symlink(other, tmp_path / "quality_score.json")
    assert client.get("/api/quality-score").json()["available"] is False


def test_the_markdown_report_is_served_as_plain_text(client, tmp_path):
    """ASVS V14.4.1 · CWE-79 · CWE-116: QUALITY_SCORE.md is text/plain (never rendered as HTML), 404 when missing."""
    assert client.get("/api/quality-score/report.md").status_code == 404
    (tmp_path / "QUALITY_SCORE.md").write_text("# Quality\n<script>alert(1)</script>\n", encoding="utf-8")
    r = client.get("/api/quality-score/report.md")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.parametrize("path", ["/api/quality-score", "/api/quality-score/report.md"])
def test_the_score_routes_are_gated_read_only_and_tenant_free(monkeypatch, path):
    """ASVS V4.1.1 · ASVS V4.1.3 · CWE-306 · CWE-862: the score routes are GET only, behind the UI token like every /api route, and read no tenant."""
    import test_auth_session as auth
    import test_scope_rule_routes as scope
    # Arrange: the route tables
    methods = {m for m, p in auth.ROUTES if p == path}
    # Act: no token
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_UI_TOKEN", auth.TOKEN)
    monkeypatch.setattr(security, "_ui_token", None)
    r = TestClient(srv.app).get(path)
    # Assert
    assert methods == {"GET"} and ("GET", path) in auth.GATED
    assert r.status_code == 401
    assert f"GET {path}" not in scope._route_reaches_a_client_factory()


# ── The page ────────────────────────────────────────────────────────

def _page():
    return open(os.path.join(ROOT, "static", "report_advanced.html"), encoding="utf-8").read()


def test_the_advanced_page_has_the_section_with_accessible_tables():
    """WCAG 2.2 SC 1.3.1 · SC 4.1.3 · SC 2.4.6: the section has a heading, a live status, tables with headers and the report link."""
    html = _page()
    sec = html[html.index('<section id="quality"'):]
    sec = sec[:sec.index("</section>")]
    assert '<h2 class="df-h" id="advQsH">Quality and security score</h2>' in sec
    assert 'role="status" aria-live="polite"' in sec and 'class="adv-qs-chart" aria-hidden="true"' in sec
    assert sec.count('class="df-table"') == 3 and sec.count('scope="col"') == 15
    assert 'href="/api/quality-score/report.md"' in sec and 'href="#quality"' in html
    assert html.index("/static/advanced.js") < html.index("/static/quality_score.js")


def test_the_script_escapes_and_never_writes_style_markup():
    """ASVS V5.3.3 · CWE-79: every interpolated value goes through E() or textContent; bar widths are set on the style object."""
    js = open(os.path.join(ROOT, "static", "quality_score.js"), encoding="utf-8").read()
    assert "style=" not in js and "f.style.width" in js
    assert "eval(" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js
    assert "fetch('/api/quality-score'" in js


# ── In a real browser ───────────────────────────────────────────────

DRIVER = r"""
const [width] = args;
const out = {};
function lum(c) { const m = c.match(/[0-9.]+/g).map(Number); const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); }
for (const theme of ['light', 'dark']) {
  await send('Emulation.setDeviceMetricsOverride', { width: Number(width), height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + '/report/advanced' });
  await until(() => ev(`document.readyState === 'complete'`), 'load');
  await ev(`localStorage.setItem('zassess_theme', '${theme}'), 1`);
  await send('Page.reload');
  await until(() => ev(`document.readyState === 'complete' && !document.getElementById('advQsBody').hidden`), 'the score');
  await until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');
  out[theme] = await ev(`(() => {
    const W = document.documentElement.clientWidth;
    const sec = document.getElementById('quality');
    const bg = el => { for (let e = el; e; e = e.parentElement) { const c = getComputedStyle(e).backgroundColor; const a = c.match(/[0-9.]+/g); if (a && (a.length < 4 || Number(a[3]) > 0.9)) return c; } return 'rgb(0, 0, 0)'; };
    const ratio = el => { const a = ${lum.toString()}(getComputedStyle(el).color), b = ${lum.toString()}(bg(el)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
    const texts = ['#advQsBox .n', '#advQsBox .g', '#advQsBox .adv-qs-meaning', '.adv-qs-val', '#advQsAreas td', '#advQsOpen th', '#advQsCounts td'];
    return {
      light: document.body.classList.contains('theme-light'),
      overflow: document.documentElement.scrollWidth - W,
      sectionRight: Math.round(sec.getBoundingClientRect().right), W,
      score: document.querySelector('#advQsBox .n').textContent,
      grade: document.querySelector('#advQsBox .g').textContent,
      cap: (document.querySelector('#advQsBox .adv-qs-cap') || {}).textContent || '',
      bars: [...document.querySelectorAll('.adv-qs-fill')].map(f => Math.round(f.getBoundingClientRect().width / f.parentElement.getBoundingClientRect().width * 100)),
      rows: document.querySelectorAll('#advQsAreas tbody tr').length,
      openRows: [...document.querySelectorAll('#advQsOpen tbody th')].map(t => t.textContent),
      injected: sec.querySelectorAll('img, script, iframe').length + (window.__qsPwned ? 100 : 0),
      contrast: Object.fromEntries(texts.map(s => [s, Math.round(ratio(document.querySelector(s)) * 100) / 100])),
      text: document.getElementById('advQsText').textContent,
    };
  })()`);
}
await ev(`window.DLP_QS.render({ available: false, reason: 'No score yet: fixture.' }), 1`);
out.missing = await ev(`({ box: document.getElementById('advQsBox').textContent, bodyHidden: document.getElementById('advQsBody').hidden })`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def browser(tmp_path_factory):
    from test_findings_reflow import CDP_PRELUDE, run_in_browser
    tmp = tmp_path_factory.mktemp("quality-score")
    result = qs.compute(_records("open_high"), _run(), FULL)
    # A tampered file (not one the tool would write): markup in a title and a reason must stay text.
    result["findings"][0]["title"] = '<img src=x onerror="window.__qsPwned=1">Fixture title'
    result["findings"][0]["reason"] = "<script>window.__qsPwned=1</script> fixture reason"
    (tmp / "quality_score.json").write_text(qs.render_json(result), encoding="utf-8")
    mp = pytest.MonkeyPatch()
    mp.setattr(srv, "_QUALITY_SCORE_JSON", str(tmp / "quality_score.json"))
    try:
        return run_in_browser(tmp, CDP_PRELUDE + DRIVER, "390", timeout=120), result
    finally:
        mp.undo()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_the_section_reads_and_reflows_at_390px(browser, theme):
    """WCAG 2.2 SC 1.4.10 · SC 1.4.3 · SC 1.1.1 · CWE-79: at 390px in both themes the score, bars and tables fit, read at 4.5:1 and stay text."""
    out, result = browser
    m = out[theme]
    assert m["light"] is (theme == "light")
    assert m["overflow"] == 0 and m["sectionRight"] <= m["W"], m
    assert m["score"] == "69/100" and m["grade"] == "Grade D · Weak" and "SBD-WRITES-01" in m["cap"]
    assert m["rows"] == 9 and len(m["bars"]) == 4 + 4 + 3
    assert abs(m["bars"][0] - result["areas"][0]["score"]) <= 1
    assert m["injected"] == 0 and m["openRows"] == ['SBD-WRITES-01 <img src=x onerror="window.__qsPwned=1">Fixture title']
    assert all(v >= 4.5 for v in m["contrast"].values()), m["contrast"]
    assert m["text"].startswith("Overall 69 of 100 (grade D, Weak).")


def test_the_section_says_no_score_yet_when_the_file_is_missing(browser):
    """WCAG 2.2 SC 4.1.3 · CWE-755: with no score file the section says "No score yet" and hides the tables (no error)."""
    out, _ = browser
    assert "No score yet" in out["missing"]["box"] and out["missing"]["bodyHidden"] is True
