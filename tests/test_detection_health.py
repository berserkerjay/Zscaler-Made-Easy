"""
Detection Health (continuous evaluation, phase 1): incidents from
Workflow Automation and the analysts' verdicts become per-rule /
engine / dictionary metrics and findings, read-only.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import detection_health as dh
import dlp_api_server as srv
from test_pack_channels import make_client
from test_pack_deploy import Obj

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)


def _inc(iid, rule, engine, dicts, *, days_ago=1, status="CLOSED", resolution="", source="WEB_DLP", app="chatgpt.com", dept="Finance"):
    return {"internalId": iid, "createdAt": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "status": status, "resolution": resolution, "severity": "HIGH", "sourceType": source,
            "matchingPolicies": {"rules": [{"name": rule}], "engines": [{"name": engine}],
                                 "dictionaries": [{"name": d, "matchCount": 3} for d in dicts]},
            "applicationInfo": {"name": app}, "userInfo": {"email": "a@example.com", "department": dept}, "matchCount": 3}


class FakeIncidents:
    def __init__(self, incidents, fail=False):
        self.incidents = incidents
        self.fail = fail
        self.calls = []

    def dlp_incident_search(self, query_params=None, fields=None, time_range=None, **kw):
        self.calls.append((dict(query_params or {}), dict(time_range or {})))
        if self.fail:
            return None, None, {"message": "403 insufficient scope"}
        page = int((query_params or {}).get("page", 1)); size = int((query_params or {}).get("page_size", 100))
        chunk = self.incidents[(page - 1) * size: page * size]
        # Some SDK builds nest the records one level down.
        return type("R", (), {"incidents": [type("I", (), {"incidents": chunk})()]})(), None, None


class FakeZWA:
    def __init__(self, incidents, fail=False):
        self.dlp_incidents = FakeIncidents(incidents, fail)


def _client(incidents, fail=False):
    client = make_client()
    client.zwa = FakeZWA(incidents, fail)
    z = client.zia
    z.dlp_engine.items = [Obj(id=5001, name="US PII", engine_expression="D1.S > 0", description=""),
                          Obj(id=5002, name="Card Data", engine_expression="D2.S > 0", description="")]
    z.dlp_web_rules.items = [
        Obj(id=7001, name="Z-US PII-Monitor", order=1, action="ALLOW", state="ENABLED", dlp_engines=[{"id": 5001}], description="[DLP-Check pack fed_policy_pack v2.0] x"),
        Obj(id=7002, name="Cards-Block", order=2, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 5002}], description=""),
        Obj(id=7003, name="Old-Monitor", order=3, action="ALLOW", state="ENABLED", dlp_engines=[{"id": 5002}], description=""),
        Obj(id=7004, name="Parked-Rule", order=4, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5002}], description="")]
    return client


def test_verdicts_channels_and_normalisation():
    assert dh.verdict("CLOSED", "False Positive", None, dh.DEFAULTS["not_real"]) is False
    assert dh.verdict("Resolved", "", "BUSINESS_JUSTIFIED", dh.DEFAULTS["not_real"]) is False
    assert dh.verdict("CLOSED", "Confirmed leak", None, dh.DEFAULTS["not_real"]) is True
    assert dh.verdict("OPEN", "", None, dh.DEFAULTS["not_real"]) is None
    assert dh.channel_of_incident("ENDPOINT_DLP") == "endpoint" and dh.channel_of_incident("SAAS_API", "OFLCASB_DLP_FILE") == "saas"
    assert dh.channel_of_incident("EMAIL_DLP") == "email" and dh.channel_of_incident("WEB_DLP") == "web"
    n = dh.normalize_incident(_inc("i1", "R", "E", ["D1", "D2"], resolution="False Positive"), dh.DEFAULTS["not_real"])
    assert n["rules"] == ["R"] and n["engines"] == ["E"] and [d["name"] for d in n["dictionaries"]] == ["D1", "D2"]
    assert n["real"] is False and n["channel"] == "web" and n["application"] == "chatgpt.com" and n["department"] == "Finance"
    assert n["user"] == "a@example.com" and n["host"] == "" and n["actions"] == []   # who was transacting is kept (the report never touches disk)


def test_metrics_and_findings():
    incidents = []
    # Z-US PII-Monitor: 12 closed in the last 14 days, 8 not real -> noisy (67%).
    for i in range(12):
        incidents.append(_inc(f"p{i}", "Z-US PII-Monitor", "US PII", ["SSN - High", "Date of Birth"], days_ago=1 + i % 10,
                              resolution="False Positive" if i < 8 else "Confirmed"))
    # Cards-Block: enforcing, 25 closed over 30 days, 1 not real -> healthy (block already).
    for i in range(25):
        incidents.append(_inc(f"c{i}", "Cards-Block", "Card Data", ["Credit Cards - High"], days_ago=1 + i,
                              resolution="Benign" if i == 0 else "Confirmed", source="ENDPOINT_DLP", app="usb"))
    # Old-Monitor: monitor-only, 22 closed over 30 days, 0 not real -> promotable.
    for i in range(22):
        incidents.append(_inc(f"o{i}", "Old-Monitor", "Card Data", ["Credit Cards - High"], days_ago=1 + i, resolution="Confirmed",
                              source="SAAS_API", app="OneDrive"))
    # Two still open on Old-Monitor: no verdict, no effect on the rate.
    incidents += [_inc("o-open1", "Old-Monitor", "Card Data", ["Credit Cards - High"], status="OPEN", source="SAAS_API", app="OneDrive"),
                  _inc("o-open2", "Old-Monitor", "Card Data", ["Credit Cards - High"], status="OPEN", source="SAAS_API", app="OneDrive")]
    normalised = [dh.normalize_incident(i, dh.DEFAULTS["not_real"]) for i in incidents]
    from pack_removal import inventory
    rules = inventory(_client([]))["rules"]
    ev = dh.evaluate(normalised, rules, now=NOW)
    by = {r["name"]: r for r in ev["rules"]}
    assert by["Z-US PII-Monitor"]["status"] == "noisy" and by["Z-US PII-Monitor"]["fp_rate_pct"] == 67 and by["Z-US PII-Monitor"]["tagged"]
    assert by["Old-Monitor"]["status"] == "promotable" and by["Old-Monitor"]["open"] == 2 and by["Old-Monitor"]["promote_rate_pct"] == 0
    assert by["Cards-Block"]["status"] == "healthy" and by["Cards-Block"]["monitor_only"] is False
    assert by["Parked-Rule"]["status"] == "disabled" and by["Parked-Rule"]["incidents"] == 0
    # Dictionaries: the SSN clone carries the noise; the DOB one only ever fires
    # with it, so it is flagged too (phase 2 attributes co-fired noise by match count).
    d = {x["name"]: x for x in ev["dictionaries"]}
    assert d["SSN - High"]["noisy"] and d["SSN - High"]["fp_rate_pct"] == 67 and d["Date of Birth"]["noisy"] and not d["Credit Cards - High"]["noisy"]
    assert {c["name"]: c["incidents"] for c in ev["channels"]} == {"web": 12, "endpoint": 25, "saas": 24}
    kinds = [(f["kind"], f["name"]) for f in ev["findings"]]
    assert ("noisy_rule", "Z-US PII-Monitor") in kinds and ("promotable_rule", "Old-Monitor") in kinds
    assert ("noisy_dictionary", "SSN - High") in kinds and not any(k == "dead_rule" for k, _ in kinds)
    s = ev["summary"]
    assert s["incidents"] == 61 and s["open"] == 2 and s["noisy_rules"] == 1 and s["promotable_rules"] == 1 and s["noisy_dictionaries"] == 2
    # Thresholds are settings: raise the noisy bar and the SSN rule is healthy.
    ev2 = dh.evaluate(normalised, rules, {"fp_rate_pct": 80}, now=NOW)
    assert {r["name"]: r["status"] for r in ev2["rules"]}["Z-US PII-Monitor"] == "healthy"


def test_dead_rules_and_unknown_rules():
    incidents = [_inc("x1", "Renamed-Rule", "US PII", ["SSN - High"], days_ago=2, resolution="Confirmed")]
    normalised = [dh.normalize_incident(i, dh.DEFAULTS["not_real"]) for i in incidents]
    from pack_removal import inventory
    rules = inventory(_client([]))["rules"]
    ev = dh.evaluate(normalised, rules, now=NOW)
    by = {r["name"]: r for r in ev["rules"]}
    assert by["Z-US PII-Monitor"]["status"] == "dead" and by["Cards-Block"]["status"] == "dead"
    assert by["Renamed-Rule"]["status"] == "unknown_rule"
    assert ev["summary"]["dead_rules"] == 3 and any(f["kind"] == "unknown_rule" for f in ev["findings"])


def test_generate_reads_incidents_pages_and_reports_read_problems():
    incidents = [_inc(f"i{i}", "Cards-Block", "Card Data", ["Credit Cards - High"], days_ago=1, resolution="Confirmed") for i in range(150)]
    client = _client(incidents)
    rep = dh.generate(client, days=30)
    assert rep["incident_count"] == 150 and rep["read"] == {"incidents": True, "rules": True} and rep["errors"] == []
    # Incident delivery: the fake tenant's rules forward nowhere, and the report says so.
    d = rep["delivery"]
    assert d["path"] == "none" and d["rules_enabled"] == 3 and set(d["rules_silent"]) == {"Z-US PII-Monitor", "Cards-Block", "Old-Monitor"}
    calls = client.zwa.dlp_incidents.calls
    assert [c[0]["page"] for c in calls] == [1, 2] and calls[0][1]["startTime"] < calls[0][1]["endTime"]
    assert "_created" not in str(rep["rules"][0])
    md = dh.to_markdown(rep, "acme")
    assert "# FP/TP Detection Ratio — acme" in md and "FP/TP ratio 0:1" in md and "| Cards-Block |" in md
    # No Workflow Automation scope: the report still comes back with the rules and says why incidents are missing.
    rep2 = dh.generate(_client([], fail=True), days=7)
    assert rep2["incident_count"] == 0 and rep2["read"]["incidents"] is False and any("insufficient scope" in e for e in rep2["errors"])
    assert {r["name"] for r in rep2["rules"]} >= {"Z-US PII-Monitor", "Cards-Block"}
    rep3 = dh.generate(make_client(), days=7)          # a client without the zwa service at all
    assert any("Workflow Automation" in e for e in rep3["errors"])


def test_detection_health_endpoints(monkeypatch):
    incidents = [_inc(f"i{i}", "Z-US PII-Monitor", "US PII", ["SSN - High"], days_ago=1, resolution="False Positive") for i in range(12)]
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _client(incidents))
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "days": 14}
    r = c.post("/api/detection-health", json=body)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["report_id"].startswith("health-") and rep["summary"]["noisy_rules"] == 1 and rep["tenant_label"].startswith("acme")
    assert c.get(f"/api/detection-health/{rep['report_id']}").json()["incident_count"] == 12
    md = c.get(f"/api/detection-health/export/{rep['report_id']}?format=markdown")
    assert md.status_code == 200 and "FP/TP Detection Ratio" in md.text
    assert c.get("/report/health").status_code == 200
    assert c.get("/api/detection-health/schedule").json()["interval_seconds"] == 6 * 3600


def test_noisy_dictionary_is_explained_with_evidence_pattern_and_definition():
    incidents = []
    # "SSN - High" fires alone, thinly (1 match), from one sanctioned app and one department: 10 not real, 2 real (bulk).
    for i in range(10):
        incidents.append(_inc(f"n{i}", "Z-US PII-Monitor", "US PII", ["SSN - High"], days_ago=1 + i, resolution="False Positive", app="ServiceNow", dept="IT"))
        incidents[-1]["matchingPolicies"]["dictionaries"][0]["matchCount"] = 1
    for i in range(2):
        incidents.append(_inc(f"r{i}", "Z-US PII-Monitor", "US PII", ["SSN - High"], days_ago=1 + i, resolution="Confirmed", app="chatgpt.com", dept="Finance"))
        incidents[-1]["matchingPolicies"]["dictionaries"][0]["matchCount"] = 40
    normalised = [dh.normalize_incident(i, dh.DEFAULTS["not_real"]) for i in incidents]
    from pack_removal import inventory
    rules = inventory(_client([]))["rules"]
    defs = {"SSN - High": {"custom": False, "type": "PATTERNS_AND_PHRASES", "predefined_confidence": "CONFIDENCE_LEVEL_MEDIUM", "phrases": 0, "patterns": 0}}
    ev = dh.evaluate(normalised, rules, now=NOW, definitions=defs)
    d = {x["name"]: x for x in ev["dictionaries"]}["SSN - High"]
    assert d["noisy"] and d["fp_rate_pct"] == 83
    why = " ".join(d["why"])
    assert "only dictionary in 10 of 10" in why and "thin" in why.lower() and "ServiceNow" in why and "IT" in why
    assert "nine-digit numbers" in why and "medium confidence" in why
    assert "Real incidents carry far more matches" in why
    assert d["fix"].startswith("Raise the match count") and "ServiceNow" in d["fix"] and "high-confidence SSN" in d["fix"]
    e = d["evidence"]
    assert e["alone"] == 10 and e["median_matches_not_real"] == 1 and e["median_matches_real"] == 40 and e["applications"][0] == ("ServiceNow", 10)
    f = next(x for x in ev["findings"] if x["kind"] == "noisy_dictionary")
    assert "Why:" in f["text"] and "Fix:" in f["text"] and f["why"] == d["why"]
    md = dh.to_markdown({"summary": ev["summary"], "settings": ev["settings"], "rules": [], "dictionaries": ev["dictionaries"], "findings": [], "days": 30}, "acme")
    assert "Why it is noisy" in md and "ServiceNow" in md
    # A co-fired dictionary is told apart from the one that carries the noise.
    inc2 = [_inc(f"c{i}", "R", "E", ["Date of Birth", "SSN - High"], days_ago=1, resolution="Benign") for i in range(10)]
    for i in inc2:
        i["matchingPolicies"]["dictionaries"][1]["matchCount"] = 9
    ev2 = dh.evaluate([dh.normalize_incident(i, dh.DEFAULTS["not_real"]) for i in inc2], rules, now=NOW)
    dob = {x["name"]: x for x in ev2["dictionaries"]}["Date of Birth"]
    assert "never fired alone" in " ".join(dob["why"]) and "SSN - High" in " ".join(dob["why"]) and "any date matches" in " ".join(dob["why"])


def test_who_what_where_and_the_telemetry_exclusion():
    """Each incident says who was transacting, what triggered and where it
    was going; a destination whose incidents are never real and looks like
    telemetry is proposed for exclusion; the FP/TP ratio is reported."""
    import proposals
    incs = [dict(_inc(f"t{i}", "Z-US PII-Monitor", "E", ["SSN"], status="CLOSED", resolution="False Positive", app="vendor telemetry"),
                 applicationInfo={"name": "vendor telemetry", "url": "https://telemetry.vendor.com/v1/collect"},
                 userInfo={"email": f"u{i % 3}@example.com", "department": "Sales"}, sourceActions=["UPLOAD"]) for i in range(6)]
    incs.append(dict(_inc("r1", "Cards-Block", "E", ["Cards"], status="CLOSED", app="drive.google.com"),
                     applicationInfo={"url": "https://drive.google.com/upload"}, userInfo={"email": "leaker@example.com", "name": "Lee Aker"},
                     contentInfo={"fileName": "cards.xlsx"}))
    incs.append(dict(_inc("m1", "Mail-PII", "E", ["SSN"], status="OPEN", source="EMAIL"), applicationInfo={}, emailInfo={"to": ["x@partner.example", "y@partner.example"]}))
    norm = [dh.normalize_incident(i, dh.DEFAULTS["not_real"]) for i in incs]
    assert norm[0]["user"] == "u0@example.com" and norm[0]["host"] == "telemetry.vendor.com" and norm[0]["path"] == "/v1/collect" and norm[0]["actions"] == ["UPLOAD"]
    assert norm[6]["file"] == "cards.xlsx" and norm[6]["user_name"] == "Lee Aker" and norm[6]["host"] == "drive.google.com"
    assert norm[7]["destination"] == "x@partner.example, y@partner.example" and norm[7]["host"] == "partner.example"
    assert dh.looks_like_telemetry("v10.events.data.microsoft.com") and dh.looks_like_telemetry("app.example", ["/v1/track"]) and not dh.looks_like_telemetry("drive.google.com", ["/upload"])
    ev = dh.evaluate(norm, [], now=NOW)
    dest = {d["name"]: d for d in ev["destinations"]}
    t = dest["telemetry.vendor.com"]
    assert t["telemetry"] and t["exclude"] and t["users"] == 3 and t["incidents"] == 6 and t["real"] == 0 and "UPLOAD" in t["actions"] and "telemetry" in t["why"]
    assert not dest["drive.google.com"]["exclude"] and dest["drive.google.com"]["real"] == 1
    f = next(x for x in ev["findings"] if x["kind"] == "noisy_destination")
    assert f["name"] == "telemetry.vendor.com" and f["proposal"] == "exclude_destination" and "Z-US PII-Monitor" in f["rules"] and "Exclude telemetry.vendor.com" in f["fix"]
    users = {u["name"]: u for u in ev["users"]}
    assert users["leaker@example.com"]["real"] == 1 and users["leaker@example.com"]["display_name"] == "Lee Aker"
    assert users["u0@example.com"]["destinations"][0][0] == "telemetry.vendor.com" and users["u0@example.com"]["department"] == "Sales"
    s = ev["summary"]
    assert s["tp"] == 1 and s["fp"] == 6 and s["fp_tp_ratio"] == "6:1" and s["fp_share_pct"] == 86 and s["excludable_destinations"] == 1 and s["users"] == 5
    r = ev["recent"][0]
    assert r["who"] and r["sent_to"] and r["trigger"] and r["verdict"] in ("real", "not real", "open") and len(ev["recent"]) == 8
    props = proposals.build_proposals(ev, "acme")
    p = next(x for x in props if x["kind"] == "exclude_destination")
    assert p["change"]["host"] == "telemetry.vendor.com" and p["applies_via"] == "manual" and p["label"] == "Exclude destination" and p["evidence"]["telemetry"]
    md = dh.to_markdown({**ev, "days": 30, "incident_count": 8}, "acme")
    assert "## Where it was going" in md and "| telemetry.vendor.com | 6 | 3 |" in md and "## Who is transacting" in md and "| leaker@example.com |" in md
    assert dh._ratio(0, 0) == "–" and dh._ratio(4, 0) == "1:0" and dh._ratio(6, 4) == "3:2"
