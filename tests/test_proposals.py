"""Continuous evaluation, phase 2: proposals with evidence and the approval queue."""
from datetime import datetime, timedelta, timezone
from conftest import read_store_text

from fastapi.testclient import TestClient

import proposals as pr
import dlp_api_server as srv
import security


REPORT = {
    "settings": {"promote_window_days": 30, "dead_days": 30, "fp_window_days": 14},
    "rules": [
        {"name": "Old-Monitor", "id": 7003, "channel": "web", "state": "ENABLED", "action": "ALLOW", "promote_rate_pct": 0, "promote_closed": 22, "incidents": 24, "engines": ["Card Data"], "why": "monitor-only; 0% not real"},
        {"name": "Parked", "id": 7009, "channel": "endpoint", "state": "ENABLED", "action": "ALLOW", "last_incident_at": None, "engines": ["US PII"], "why": "enabled but no incident in 30 days"},
        {"name": "Z-US PII-Monitor", "id": 7001, "channel": "web", "state": "ENABLED", "action": "ALLOW", "fp_rate_pct": 67, "fp_closed": 12, "engines": ["US PII"], "why": "67% not real"},
    ],
    "findings": [
        {"kind": "promotable_rule", "name": "Old-Monitor"},
        {"kind": "dead_rule", "name": "Parked"},
        {"kind": "noisy_dictionary", "name": "SSN - High", "rules": ["Z-US PII-Monitor"], "why": ["It carries the noise itself."], "fix": "Exclude ServiceNow.",
         "evidence": {"not_real": 10, "real": 2, "alone": 10, "applications": [["ServiceNow", 8]], "departments": [["IT", 6]]}},
        {"kind": "noisy_rule", "name": "Z-US PII-Monitor"},
    ],
    "delivery": {"path": "cloud", "rules_enabled": 3, "rules_silent": ["Old-Monitor"], "receivers": [{"name": "ZIR"}]},
}


def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))


def test_build_typed_proposals_with_evidence_and_rollback():
    items = {p["kind"] + ":" + p["target"]: p for p in pr.build_proposals(REPORT, "Acme")}
    promo = items["promote_rule:rule:web:Old-Monitor"]
    assert promo["gate"] == "approve_double" and promo["change"] == {"apply": "rule", "rule_id": 7003, "channel": "web", "field": "action", "from": "ALLOW", "to": "CONFIRM"}
    assert promo["rollback"] == {"field": "action", "to": "ALLOW"} and promo["evidence"]["closed"] == 22 and promo["applies_via"] == "phase 3"
    retire = items["retire_rule:rule:endpoint:Parked"]
    assert retire["gate"] == "approve" and retire["change"]["to"] == "DISABLED" and retire["rollback"]["to"] == "ENABLED"
    tune = items["tune_dictionary:dictionary:SSN - High"]
    assert tune["change"] == {"apply": "manual", "kind": "exclude_application", "application": "ServiceNow", "rules": ["Z-US PII-Monitor"]}
    assert tune["evidence"]["alone"] == 10 and "ServiceNow" in tune["title"]
    fwd = items["enable_incident_forwarding:delivery:web:silent"]
    assert fwd["change"]["rules"] == ["Old-Monitor"] and fwd["gate"] == "approve"
    # Stable ids: the same finding on the same tenant is the same proposal.
    assert pr.proposal_id("Acme", "promote_rule", "rule:web:Old-Monitor") == promo["id"] == pr.proposal_id("acme ", "promote_rule", "rule:web:Old-Monitor")


def test_queue_merges_remembers_dismissals_and_snoozes(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    st = pr.refresh_from_report(REPORT, "acme")
    assert st["new"] == 5 and st["total"] == 5
    q = pr.list_queue("acme")
    assert len(q) == 5 and q[0]["gate"] == "approve_double" and all(p["status"] == "open" for p in q)
    promo = next(p for p in q if p["kind"] == "promote_rule")
    # A double gate needs the phrase.
    try:
        pr.decide("acme", promo["id"], "approve", by="J")
        assert False, "approved without the phrase"
    except ValueError as e:
        assert "I UNDERSTAND" in str(e)
    assert pr.decide("acme", promo["id"], "approve", by="J", confirm="i understand")["status"] == "approved"
    retire = next(p for p in q if p["kind"] == "retire_rule")
    assert pr.decide("acme", retire["id"], "dismiss", by="J", note="rule is seasonal")["status"] == "dismissed"
    tune = next(p for p in q if p["kind"] == "tune_dictionary" and p["target"].startswith("dictionary"))
    assert pr.decide("acme", tune["id"], "snooze", days=7)["status"] == "snoozed"
    # The next evaluation raises the same findings: nothing comes back, evidence refreshes, counts stay.
    st2 = pr.refresh_from_report(REPORT, "acme")
    assert st2["new"] == 0 and st2["kept"] == 3 and st2["updated"] == 2
    open_now = pr.list_queue("acme")
    assert {p["kind"] for p in open_now} == {"promote_rule", "tune_dictionary", "enable_incident_forwarding"}
    assert next(p for p in open_now if p["kind"] == "promote_rule")["status"] == "approved"
    assert pr.summary("acme") == {"open": 2, "approved": 1, "snoozed": 1, "dismissed": 1, "applied": 0, "resolved": 0}
    # A finding that disappears resolves its open proposal.
    rep2 = dict(REPORT, findings=[f for f in REPORT["findings"] if f["kind"] != "noisy_rule"])
    st3 = pr.refresh_from_report(rep2, "acme")
    assert st3["resolved"] == 1 and pr.summary("acme")["resolved"] == 1
    # An expired dismissal comes back as open.
    data = pr._read()
    p = data["tenants"]["acme"]["proposals"][retire["id"]]
    p["decided_at"] = (datetime.now(timezone.utc) - timedelta(days=pr.DISMISS_DAYS + 1)).isoformat(timespec="seconds")
    pr._write(data)
    assert next(x for x in pr.list_queue("acme") if x["id"] == retire["id"])["status"] == "open"
    assert "Promote Old-Monitor" in pr.to_markdown("acme", pr.list_queue("acme", include_closed=True))
    # Decisions are audited, without secrets.
    log = read_store_text(tmp_path / "audit.log")
    assert "proposal_decision" in log and "rule is seasonal" in log


def test_endpoints(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    pr.refresh_from_report(REPORT, "acme")
    c = TestClient(srv.app); c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.get("/api/proposals?tenant=acme")
    assert r.status_code == 200 and len(r.json()["items"]) == 5 and r.json()["confirm_phrase"] == "I UNDERSTAND"
    pid = next(p["id"] for p in r.json()["items"] if p["kind"] == "promote_rule")
    bad = c.post(f"/api/proposals/acme/{pid}/decide", json={"decision": "approve"})
    assert bad.status_code == 400 and "I UNDERSTAND" in bad.json()["detail"]
    ok = c.post(f"/api/proposals/acme/{pid}/decide", json={"decision": "approve", "confirm": "I UNDERSTAND", "by": "Jane"})
    # Who decided is set by the server (the signed-in person, or the local token), never the "by" a page sends.
    assert ok.status_code == 200 and ok.json()["status"] == "approved" and ok.json()["decided_by"] == "local, no UI token"
    assert c.post(f"/api/proposals/acme/nope/decide", json={"decision": "dismiss"}).status_code == 400
    assert c.get("/api/proposals?tenant=").status_code == 400
    md = c.get("/api/proposals/export?tenant=acme")
    assert md.status_code == 200 and "# Proposals — acme" in md.text
    assert c.get("/api/proposals/export?tenant=acme&format=json").json()["tenant"] == "acme"
    # The FP/TP Detection Ratio tab renders the queue.
    page = c.get("/report/health").text
    assert "dhProposals" in page and "renderProposals(" in page and "/api/proposals" in c.get("/static/detection_health.js").text
