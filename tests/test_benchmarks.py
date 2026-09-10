"""Benchmarks: best-practice alignment, the DLP programme stages, framework
rows and the API/export around them."""
from __future__ import annotations

from fastapi.testclient import TestClient

import benchmarks as bm
import compliance_mapping as cm
import dlp_api_server as srv


def _checks():
    return [
        {"id": "FW.1", "section": "ZIA — Firewall", "label": "Default action", "status": "REVIEW",
         "detail": "Default rule action is ALLOW. Best Practice: Zscaler recommends Block/Drop as the default action. Ref: https://help.zscaler.com/zia/x"},
        {"id": "FW.2", "section": "ZIA — Firewall", "label": "IPS rules", "status": "PASS", "detail": "3 IPS rule(s)."},
        {"id": "4.1", "section": "4 — SSL Policy", "label": "Decrypt rule", "status": "FAIL", "detail": "No decrypt rule."},
        {"id": "4.2", "section": "4 — SSL Policy", "label": "Exemptions", "status": "PASS", "detail": "ok"},
        {"id": "1.1", "section": "1 — CC Portal", "label": "Portal", "status": "PASS", "detail": "ok"},
        {"id": "2.1", "section": "2 — Bypass Inventory", "label": "Inventory", "status": "PASS", "detail": "ok"},
        {"id": "5.1", "section": "5 — Endpoint DLP", "label": "Endpoint rules", "status": "INFO", "detail": "Not licensed"},
        {"id": "12.1", "section": "12 — Incident Mgmt", "label": "Receiver", "status": "FAIL", "detail": "No incident receiver."},
        {"id": "AI.1", "section": "GenAI — Discovery", "label": "AI apps", "status": "PASS", "detail": "ok"},
    ]


def test_best_practice_is_read_inline_or_from_the_curated_fallback():
    bp = bm.best_practice_of(_checks()[0])
    assert bp["inline"] and bp["text"].startswith("Zscaler recommends Block/Drop") and bp["reference"] == "https://help.zscaler.com/zia/x"
    fb = bm.best_practice_of(_checks()[2])
    assert not fb["inline"] and "Decrypt and inspect TLS" in fb["text"] and fb["reference"].startswith("https://")
    assert bm.area_of("ZIA — Firewall") == "ZIA policy" and bm.area_of("4 — SSL Policy") == "SSL inspection"
    assert bm.area_of("Ch.E — GenAI") == "GenAI governance" and bm.area_of("Multi-Channel") == "DLP programme"


def test_best_practice_benchmark_counts_measured_checks_and_lists_deviations():
    b = bm.best_practice_benchmark(_checks())
    assert b["measured"] == 8 and b["aligned"] == 5 and b["deviations"] == 3 and b["not_measured"] == 1
    assert b["pct"] == 62 and b["grade"] == "C"
    areas = {a["area"]: a for a in b["areas"]}
    assert areas["ZIA policy"]["pct"] == 50 and areas["ZIA policy"]["gaps"][0]["id"] == "FW.1"
    assert areas["ZIA policy"]["gaps"][0]["reference"] == "https://help.zscaler.com/zia/x"
    assert areas["SSL inspection"]["gaps"][0]["status"] == "FAIL" and areas["DLP programme"]["not_measured"] == 1
    # FAIL sorts before REVIEW, and checks that state their own best practice before fallbacks.
    assert [a["area"] for a in b["areas"]][:2] == ["ZIA policy", "Client Connector"]


def test_dlp_programme_stages_stop_at_the_first_unmet_stage():
    p = bm.dlp_programme_benchmark(_checks())
    names = [s["name"] for s in p["stages"]]
    assert names == ["Foundation", "Visibility", "Coverage", "Operation", "Response"]
    assert p["stages"][0]["met"] and p["stages"][0]["pct"] == 100
    assert p["stages"][1]["pct"] == 50 and not p["stages"][1]["met"]
    assert p["stage"] == 1 and p["stage_name"] == "Foundation"
    assert p["stages"][4]["todo"][0]["id"] == "12.1"


def test_frameworks_include_nist_csf_and_glba_and_sort_weakest_first():
    assert "NIST_CSF_2" in cm.FRAMEWORK_DESCRIPTIONS and "GLBA" in cm.FRAMEWORK_DESCRIPTIONS
    ctl = cm.get_compliance_for_check("4.1")
    assert any(c.startswith("PR.DS-02") for c in ctl["NIST_CSF_2"]) and any(c.startswith("314.4(c)(3)") for c in ctl["GLBA"])
    rows = bm.frameworks_benchmark(_checks())
    assert rows and rows[0]["alignment_pct"] <= rows[-1]["alignment_pct"]
    assert {"NIST_CSF_2", "GLBA", "PCI_DSS"} <= {r["key"] for r in rows}


def test_benchmarks_api_and_markdown_export():
    c = TestClient(srv.app)
    report = {"score": 61, "maturity": "Developing", "checks": _checks(), "journey": {"status": "pending"}}
    r = c.post("/api/benchmarks", json=report)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["best_practices"]["pct"] == 62 and b["dlp_programme"]["stage"] == 1 and b["journey"] == {"status": "pending"}
    md = c.post("/api/benchmarks/export?format=markdown", json={**report, "metadata": {"org": "Acme"}})
    assert md.status_code == 200 and "Benchmark alignment — Acme" in md.text and "[FW.1] Default action" in md.text
    assert "DLP programme: stage 1 of 5" in md.text
    html = c.get("/").text
    assert 'id="benchmarkCard"' in html and "loadBenchmarks(data)" in html and 'value="NIST_CSF_2"' in html and 'value="GLBA"' in html
