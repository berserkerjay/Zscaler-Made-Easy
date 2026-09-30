"""The CISA Secure by Design score: measured live from the running server
and the app folder, every control with evidence and a next step, shown in
the Advanced settings tab."""
from __future__ import annotations

import os
import re

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
    # shared_path is the one known shortfall: remediation and rule migration write outside pack_ops.
    short = [(c["id"], c["status"], c["evidence"][:120]) for c in d["checks"] if c["status"] not in ("pass", "n/a") and c["id"] != "shared_path"]
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


def test_no_control_claims_a_pass_the_code_contradicts(monkeypatch):
    # remediation.py and rule_migrator.py write to the tenant without pack_ops: the page must say so.
    by = {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}
    sp = by["shared_path"]
    assert sp["status"] == "warn" and "remediation.py" in sp["evidence"] and "rule_migrator.py" in sp["evidence"]
    assert "is the only module that writes" not in sp["evidence"]
    assert "every deploy also needs an approved plan hash" not in by["writes"]["evidence"]
    assert "remediation.py" in by["writes"]["evidence"] and "no plan hash" in by["writes"]["evidence"]
    # With no direct writer left, the pass comes back.
    monkeypatch.setattr(sbd, "_direct_tenant_writers", lambda: {})
    by = {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}
    assert by["shared_path"]["status"] == "pass" and "only module that writes" in by["shared_path"]["evidence"]
    assert "Not every write" not in by["writes"]["evidence"]


def test_what_cannot_be_inspected_is_not_checked_rather_than_passed():
    d = sbd.evaluate(None)
    by = {c["id"]: c for c in d["checks"]}
    assert by["audit"]["status"] == "n/a" and by["audit"]["evidence"].startswith("Not checked")
    assert by["middleware"]["status"] != "pass"
    assert "could not be checked" in d["note"]


def test_plain_text_smtp_costs_the_tls_control(monkeypatch):
    monkeypatch.delenv("ZSCALER_UPDATE_VERIFY_TLS", raising=False)
    monkeypatch.delenv("DLP_CHECK_SMTP_TLS", raising=False)
    monkeypatch.delenv("DLP_CHECK_SMTP_HOST", raising=False)
    assert {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}["tls"]["status"] == "pass"
    monkeypatch.setenv("DLP_CHECK_SMTP_TLS", "0")
    assert {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}["tls"]["status"] == "pass", "no mail server set: nothing is sent"
    monkeypatch.setenv("DLP_CHECK_SMTP_HOST", "smtp.example.test")
    tls = {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}["tls"]
    assert tls["status"] == "warn" and "DLP_CHECK_SMTP_TLS=0" in tls["evidence"] and "unencrypted" in tls["evidence"]


def test_endpoint_and_advanced_page(monkeypatch):
    monkeypatch.setattr(security, "ui_auth_enabled", lambda: True)
    c = _client()
    r = c.get("/api/secure-by-design")
    assert r.status_code == 200 and r.json()["score"] >= 90 and r.json()["reference"].startswith("https://www.cisa.gov/")
    html = c.get("/report/advanced").text
    assert 'id="sbd"' in html and "CISA Secure by Design score" in html and 'id="advSbdCheck"' in html and "cisa.gov/securebydesign" in html
    js = c.get("/static/advanced.js").text
    assert "/api/secure-by-design" in js and "function renderSbd" in js


def test_plain_smtp_is_reported_as_unverified_tls(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_SMTP_HOST", "smtp.example.test")
    by = {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}
    assert by["tls"]["status"] == "pass" and "mail server" in by["tls"]["evidence"]
    monkeypatch.setenv("DLP_CHECK_SMTP_TLS", "0")
    by = {c["id"]: c for c in sbd.evaluate(srv.app)["checks"]}
    assert by["tls"]["status"] == "warn" and "DLP_CHECK_SMTP_TLS=0" in by["tls"]["evidence"]


def test_tls_hints_point_to_a_ca_bundle_and_state_the_risk_of_switching_off():
    """Where users are told about ZSCALER_UPDATE_VERIFY_TLS=0, the CA bundle
    comes first and the risk is said in the same place."""
    import requests
    import zscaler_update_check as uc
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("START_Zscaler_Assessment.bat", "local_settings.env.example"):
        with open(os.path.join(root, name), encoding="utf-8") as f:
            text = re.sub(r"\s*\n\s*(?:REM\b|#)?\s*", " ", f.read())   # comment lines joined into prose
        at = text.index("ZSCALER_UPDATE_VERIFY_TLS=0")
        assert "REQUESTS_CA_BUNDLE" in text[:at] and "last resort" in text[at - 300:at + 300].lower() and "any certificate" in text[at - 300:at + 300], name

    def boom(*a, **k):
        raise requests.exceptions.SSLError("certificate verify failed")
    orig = requests.get
    requests.get = boom
    try:
        _, _, err = uc._safe_get("https://pypi.org/pypi/zscaler-sdk-python/json")
    finally:
        requests.get = orig
    assert "REQUESTS_CA_BUNDLE" in err and "any certificate" in err and err.index("REQUESTS_CA_BUNDLE") < err.index("ZSCALER_UPDATE_VERIFY_TLS=0")
