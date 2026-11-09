"""POV progress and the posture score paired inside a POV: the first reading is the start, the latest later one the
end, the score is computed on the server by the assessment's own formula, and the saved POV reopens with where it
stands and what to do next. Local only: no tenant read or write."""
from __future__ import annotations

import pytest

import posture_plus as pp
import pov
from test_pov import _profile, _start, app  # noqa: F401  (the fixture and helpers of the POV tests)


def _c(cid, sec, status):
    return {"id": cid, "sec": sec, "label": cid, "status": status, "detail": ""}


GOOD = [_c(f"A.{i}", "A", "PASS") for i in range(1, 5)]
BAD = GOOD[:2] + [_c("A.8", "A", "FAIL"), _c("A.9", "A", "FAIL")]


def _post(app, pid, checks, **extra):
    return app.post("/api/pov/posture", json=dict({"profile_id": pid, "checks": checks}, **extra))


def test_first_reading_is_the_start_and_the_latest_later_one_the_end(app):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-01: the first posture score of a POV is its start; each later one becomes the end without losing the start, and the change is computed."""
    pid = _profile()
    _start(app, pid)
    first = _post(app, pid, BAD).json()["pov"]
    assert [r["score"] for r in first["posture"]] == [pp.score_of(BAD)] and pov.posture_pair(first)["end"] is None
    second = _post(app, pid, GOOD).json()
    pair = pov.posture_pair(second["pov"])
    assert pair["start"]["score"] == pp.score_of(BAD) and pair["end"]["score"] == pp.score_of(GOOD)
    assert pair["delta"] == pp.score_of(GOOD) - pp.score_of(BAD) > 0 and "at the start" in pair["sentence"]
    third = _post(app, pid, BAD).json()["pov"]
    assert len(third["posture"]) == 3 and pov.posture_pair(third)["start"]["score"] == pp.score_of(BAD)
    assert second["progress"]["posture"]["delta"] == pair["delta"]


def test_the_score_is_computed_on_the_server_never_taken_from_the_page(app):
    """ASVS V5.1.5 · CWE-345 · WSTG-BUSL-03: a score or counts sent beside the results are ignored; only the results decide the stored score."""
    pid = _profile()
    _start(app, pid)
    forged = [dict(c, score=100) for c in BAD]
    r = _post(app, pid, forged, score=100, counts={"pass": 99}).json()["pov"]
    assert r["posture"][0]["score"] == pp.score_of(BAD) != 100 and r["posture"][0]["counts"]["fail"] == 2


def test_results_with_no_scored_check_are_refused_and_a_missing_pov_is_a_404(app):
    """ASVS V7.4.1 · CWE-754: no score is invented from nothing, and a profile without a POV gets a 404, not a record."""
    pid = _profile()
    assert _post(app, pid, GOOD).status_code == 404
    _start(app, pid)
    r = _post(app, pid, [_c("X", "A", "INFO")])
    assert r.status_code == 400 and "no scored check" in r.json()["detail"]
    assert _post(app, pid, []).status_code == 400


def test_reopening_the_saved_pov_says_where_it_stands_and_what_is_next(app):
    """ASVS V11.1.1 · CWE-841: opening a saved POV returns its progress (tests done, criteria met, days, next step) so work resumes where it stopped; a result moves the count."""
    pid = _profile()
    p = _start(app, pid)
    app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"tests": {"url-block": {"status": "pass"}}, "timeline": {"end": "2999-01-01"}}})
    v = app.post("/api/pov/open", json={"profile_id": pid}).json()
    pr = v["progress"]
    assert pr["tests"]["done"] == 1 and pr["tests"]["total"] > 1 and pr["next_step"].startswith("Next test:") and pr["days_left"] > 0
    assert pr["last_saved"] == v["pov"]["updated_at"] and pr["posture"]["start"] is None


def test_posture_travels_with_an_export_import_and_into_the_report(app):
    """ASVS V8.3.1 · CWE-200: the exported POV carries its posture readings (marked imported on import) and the customer report states the pair."""
    pid = _profile()
    _start(app, pid)
    _post(app, pid, BAD)
    _post(app, pid, GOOD)
    cur = pov.require(pid)[1]
    exported = pov.export(cur)
    back = pov.parse_import(__import__("json").dumps(exported))
    assert [r["score"] for r in back["posture"]] == [r["score"] for r in cur["posture"]] and all(r["imported"] for r in back["posture"])
    doc = pov.report_document(pov.report_model(cur, []))
    assert any(s.get("heading") == "Security posture score" and "at the start" in s["paragraphs"][0] for s in doc["sections"])


@pytest.mark.parametrize("bad", [{"score": 101}, {"score": -1}, {"score": True}, {"score": "90"}])
def test_hostile_stored_readings_are_dropped(bad):
    """ASVS V5.1.3 · CWE-20: a posture reading with a score outside 0 to 100 (or not a number) in an imported file is dropped, never kept."""
    assert pov._clean_posture([bad]) == []
