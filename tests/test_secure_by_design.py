"""The CISA Secure by Design score: measured live from the running server
and the app folder, every control with evidence and a next step, shown in
the Advanced settings tab."""
from __future__ import annotations

from fastapi.testclient import TestClient

import dlp_api_server as srv
import secure_by_design as sbd
import security


def _client():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_score_is_measured_from_live_evidence(monkeypatch):
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: True)   # the test session runs with the token gate off; a real install has it on
    d = sbd.evaluate(srv.app)
    assert 0 <= d["score"] <= 100 and d["grade"] in "ABCD" and len(d["checks"]) >= 15
    by = {c["id"]: c for c in d["checks"]}
    for c in d["checks"]:
        assert c["status"] in ("pass", "warn", "fail", "n/a") and c["evidence"] and c["do"] and c["principle"] in d["principles"] and c["pledge"]
    # The controls this repository and server carry are found where they are.
    short = [(c["id"], c["status"], c["evidence"][:120]) for c in d["checks"] if c["status"] not in ("pass", "n/a")]
    assert not short, short
    assert by["ui_token"]["status"] == "pass" and by["writes"]["status"] == "pass" and by["loopback"]["status"] == "pass" and by["debug"]["status"] == "pass"
    assert by["middleware"]["status"] == "pass" and "20 requests/second" in by["middleware"]["evidence"]
    assert by["constructs"]["status"] == "pass" and by["disclosure"]["status"] == "pass" and by["limits"]["status"] == "pass"
    assert by["classes_doc"]["status"] == "pass" and "memory-safe" in by["classes_doc"]["evidence"].lower()
    assert by["cves"]["status"] == "pass" and "CWE" in by["cves"]["evidence"]
    assert by["pins"]["status"] == "pass" and "hashes" in by["pins"]["evidence"] and by["scans"]["status"] == "pass"
    assert by["container"]["status"] == "pass" and by["secrets"]["status"] == "pass" and by["audit"]["status"] == "pass"
    assert by["mfa"]["status"] == "n/a" and d["counts"]["n/a"] == 1
    assert d["score"] >= 90 and d["grade"] == "A"


def test_disclosure_and_cves_fail_without_every_promise(monkeypatch):
    real_read = sbd._read

    def fake_read(path, limit=2_000_000):
        if path.endswith("SECURITY.md"):
            return "# Security policy\n## Reporting a vulnerability\nReport a vulnerability privately.\n## Known limitations\nnone.\n"
        return real_read(path, limit)
    monkeypatch.setattr(sbd, "_read", fake_read)
    d = sbd.evaluate(srv.app)
    by = {c["id"]: c for c in d["checks"]}
    assert by["disclosure"]["status"] == "fail" and "authorization" in by["disclosure"]["evidence"]
    assert by["cves"]["status"] == "fail" and "CWE" in by["cves"]["evidence"]


def test_classes_doc_fails_when_a_class_is_not_covered(monkeypatch):
    real_read = sbd._read

    def fake_read(path, limit=2_000_000):
        if path.endswith("VULNERABILITY_CLASSES.md"):
            return "# Nothing useful here.\n"
        return real_read(path, limit)
    monkeypatch.setattr(sbd, "_read", fake_read)
    d = sbd.evaluate(srv.app)
    by = {c["id"]: c for c in d["checks"]}
    assert by["classes_doc"]["status"] == "fail" and "is missing" in by["classes_doc"]["evidence"]


def test_a_weakened_server_loses_points(monkeypatch):
    base = sbd.evaluate(srv.app)["score"]
    monkeypatch.setattr(security, "is_debug", lambda: True)
    monkeypatch.setattr(security, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setenv("ZSCALER_UPDATE_VERIFY_TLS", "0")
    d = sbd.evaluate(srv.app)
    by = {c["id"]: c for c in d["checks"]}
    assert by["debug"]["status"] == "fail" and "Unset ZSCALER_DEBUG" in by["debug"]["do"]
    assert by["loopback"]["status"] == "fail" and "reverse proxy" in by["loopback"]["do"]
    assert by["tls"]["status"] == "warn" and "CA bundle" in by["tls"]["do"]
    assert d["score"] < base


def test_endpoint_and_advanced_page(monkeypatch):
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: True)
    c = _client()
    r = c.get("/api/secure-by-design")
    assert r.status_code == 200 and r.json()["score"] >= 90 and r.json()["reference"].startswith("https://www.cisa.gov/")
    html = c.get("/report/advanced").text
    assert 'id="sbd"' in html and "CISA Secure by Design score" in html and 'id="advSbdCheck"' in html and "cisa.gov/securebydesign" in html
    js = c.get("/static/advanced.js").text
    assert "/api/secure-by-design" in js and "function renderSbd" in js
