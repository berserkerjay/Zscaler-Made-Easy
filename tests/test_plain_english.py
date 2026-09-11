"""Every finding carries the same four plain-English sentences in every
output: what we found, what it means for the business, what to do, and
the outcome once fixed."""
from __future__ import annotations

import plain_english as pe


def test_explain_gives_four_sentences_per_status():
    fail = pe.explain({"id": "4.1", "sec": "4 — SSL Policy", "label": "Inspection scope", "status": "FAIL",
                       "detail": "SSL inspection is disabled for 3 of 5 locations. Best Practice: decrypt every risky category for every user. Ref: https://help.zscaler.com/x"})
    assert fail["found"].startswith("Inspection scope: action required.") and "3 of 5 locations" in fail["found"]
    assert "Encrypted-traffic inspection" in fail["means"] or fail["means"]
    assert fail["do"] and fail["outcome"] == pe.outcome_for("4.1", "4 — SSL Policy") and "Encrypted traffic is inspected" in fail["outcome"]
    assert fail["best_practice"].startswith("decrypt every risky category")
    ok = pe.explain({"id": "12.4", "section": "12 — Incident Mgmt", "label": "Workflow Automation", "status": "PASS", "detail": "Workflow Automation is licensed and receiving incidents."})
    assert ok["found"].startswith("Workflow Automation is configured the way Zscaler recommends") and "Nothing to change" in ok["means"]
    assert "Every incident reaches an analyst" in ok["outcome"]
    rev = pe.explain({"id": "2.5", "sec": "2 — Bypass Inventory", "label": "Bypass register", "status": "WARN", "detail": "14 bypasses; review each for a business justification."})
    assert rev["found"].startswith("Bypass register needs a person to confirm it.") and rev["do"] and "Every exception is known" in rev["outcome"]
    err = pe.explain({"id": "B.5", "sec": "Ch.B — Endpoint", "label": "Rule count", "status": "ERROR", "detail": "HTTP 403"})
    assert "could not be checked" in err["found"] and "permissions" in err["do"] and "USB, print" in err["outcome"]


def test_every_registered_check_has_a_specific_outcome():
    import guidance
    fallback = 0
    for c in guidance.all_checks():
        if pe.outcome_for(c["id"], c["section"]) == pe.FALLBACK_OUTCOME:
            fallback += 1
    assert fallback == 0, "every section of every registry maps to a business outcome"


def test_enrich_never_breaks_a_result(monkeypatch):
    row = {"id": "X.1", "sec": "Weird", "label": "L", "status": "FAIL", "detail": "d"}
    monkeypatch.setattr(pe, "explain", lambda c: (_ for _ in ()).throw(RuntimeError("boom")))
    out = pe.enrich(row)
    assert out["plain"]["found"] == "L" and out["plain"]["outcome"] == pe.FALLBACK_OUTCOME


def test_results_page_renders_the_four_sentences():
    import os
    html = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "index.html"), encoding="utf-8").read()
    for needle in ('class="check-plain"', "What we found", "What it means for the business", "What to do", "Once fixed", "What this gives the business", 'class="check-raw"', "Technical detail"):
        assert needle in html, needle


def test_word_report_carries_the_four_sentences(tmp_path):
    docx = __import__("pytest").importorskip("docx")
    from dlp_assessment_full_auto import compute, maturity
    from report_docx import generate_report
    results = [pe.enrich(r) for r in [
        {"id": "4.1", "sec": "4 — SSL Policy", "label": "Inspection scope", "status": "FAIL", "detail": "SSL inspection is disabled for 3 of 5 locations. Best Practice: decrypt every risky category."},
        {"id": "2.5", "sec": "2 — Bypass Inventory", "label": "Bypass register", "status": "REVIEW", "detail": "14 bypasses; review each for a business justification."},
        {"id": "12.4", "sec": "12 — Incident Mgmt", "label": "Workflow Automation", "status": "PASS", "detail": "Licensed and receiving incidents."},
    ]]
    out = tmp_path / "r.docx"
    generate_report(results, {"tenant": "acme", "cloud": "zscaler.net"}, str(out), compute, maturity)
    d = docx.Document(str(out))
    text = "\n".join(p.text for p in d.paragraphs) + "\n" + "\n".join(c.text for t in d.tables for row in t.rows for c in row.cells)
    assert "What we found: Inspection scope: action required." in text
    assert "What it means for the business:" in text and "What to do:" in text
    assert "Once fixed: Encrypted traffic is inspected" in text          # critical finding + detailed finding
    assert "Once fixed: Every exception is known" in text                # review table
    assert "What this gives the business: Every incident reaches an analyst" in text   # PASS in detailed findings


def test_digest_names_the_outcome_for_guidance():
    import guidance, continuous_eval
    assert "Encrypted traffic is inspected" in guidance.outcome_for_checks(["4.3", "A.2"])
    md = continuous_eval.to_markdown({"at": "2026-01-01T00:00:00Z", "noteworthy": True,
                                      "summary": {"proposals_new": 0, "proposals_open": 0, "guidance_new": 1, "stale_sources": 0, "tenants_not_active": 0, "drift_changed": 0, "errors": 0},
                                      "guidance": {"raised": [{"title": "T", "url": "https://help.zscaler.com/x", "kind": "reference", "topics": ["SSL"], "checks": ["4.3"], "outcome": "Encrypted traffic is inspected."}]}})
    assert "Once acted on: Encrypted traffic is inspected." in md
