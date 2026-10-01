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

NOW = datetime.now(timezone.utc)   # relative to the real clock: fetch_incidents() below queries against it too


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
        pool = self.incidents
        if time_range:
            lo, hi = time_range.get("startTime"), time_range.get("endTime")
            pool = [i for i in pool if not lo or not hi or lo <= i["createdAt"] <= hi]
        page = int((query_params or {}).get("page", 1)); size = int((query_params or {}).get("page_size", 100))
        chunk = pool[(page - 1) * size: page * size]
        # Some SDK builds nest the records one level down; an empty page
        # has no wrapper at all (a real empty result has no leaf to hide).
        wrapped = [type("I", (), {"incidents": chunk})()] if chunk else []
        return type("R", (), {"incidents": wrapped})(), None, None


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
    # Off by default: the timer reads tenants, so it runs only when opted in.
    sched = c.get("/api/detection-health/schedule").json()
    assert sched["enabled"] is False and sched["interval_seconds"] is None


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


def _inc_at(iid, rule, when, *, status="OPEN", resolution="", app="chatgpt.com"):
    """Like _inc but at an exact timestamp, for live-feed polling tests."""
    return {"internalId": iid, "createdAt": when.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "status": status, "resolution": resolution, "severity": "HIGH", "sourceType": "WEB_DLP",
            "matchingPolicies": {"rules": [{"name": rule}], "engines": [{"name": "US PII"}], "dictionaries": [{"name": "SSN", "matchCount": 1}]},
            "applicationInfo": {"name": app}, "userInfo": {"email": "a@example.com", "department": "Finance"}, "matchCount": 1}


def test_poll_incidents_only_returns_what_is_new_and_moves_the_window():
    """The live feed: the first poll (no `since`) looks back a couple of
    minutes, not the whole history; each later poll only returns what
    landed after the last one, and hands back the timestamp to pass in
    next time."""
    now = NOW
    old = _inc_at("old", "Cards-Block", now - timedelta(hours=2))       # well before the first poll's lookback
    a = _inc_at("a", "Cards-Block", now - timedelta(seconds=90))
    b = _inc_at("b", "Old-Monitor", now - timedelta(seconds=30))
    c = _client([old, a, b])

    first = dh.poll_incidents(c, now=now)
    assert [i["id"] for i in first["incidents"]] == ["a", "b"], "only the last two minutes, oldest first"
    assert first["errors"] == []
    next_since = dh._parse_time(first["next_since"])

    later = now + timedelta(seconds=45)
    new_one = _inc_at("d", "Cards-Block", later - timedelta(seconds=5))
    c.zwa.dlp_incidents.incidents.append(new_one)
    second = dh.poll_incidents(c, since=next_since, now=later)
    assert [i["id"] for i in second["incidents"]] == ["d"], "not a, b or old again"


def test_poll_incidents_clamps_a_stale_since_instead_of_backfilling_everything():
    now = NOW
    c = _client([])
    stale = now - timedelta(hours=6)
    dh.poll_incidents(c, since=stale, now=now)
    # The window asked of the API is clamped to LIVE_POLL_CLAMP_SECONDS, not the full 6-hour gap.
    call_start = c.zwa.dlp_incidents.calls[-1][1]["startTime"]
    assert (now - dh._parse_time(call_start)).total_seconds() <= dh.LIVE_POLL_CLAMP_SECONDS + 1


def test_incident_action_reads_the_rules_configured_action_not_a_guess():
    rules_by_name = {"Cards-Block": "BLOCK", "Old-Monitor": "ALLOW", "Z-US PII-Monitor": "ALLOW"}
    enforced = dh.normalize_incident(_inc_at("x", "Cards-Block", NOW), dh.DEFAULTS["not_real"])
    monitor = dh.normalize_incident(_inc_at("y", "Old-Monitor", NOW), dh.DEFAULTS["not_real"])
    unknown = dh.normalize_incident(_inc_at("z", "Renamed-Rule", NOW), dh.DEFAULTS["not_real"])
    assert dh.incident_action(enforced, rules_by_name) == "enforced"
    assert dh.incident_action(monitor, rules_by_name) == "monitor"
    assert dh.incident_action(unknown, rules_by_name) == "unknown"


def test_live_stats_rolls_up_across_polls():
    rules_by_name = {"Cards-Block": "BLOCK", "Old-Monitor": "ALLOW"}
    batch1 = [dh.normalize_incident(_inc_at("1", "Cards-Block", NOW, status="CLOSED", resolution="Confirmed leak"), dh.DEFAULTS["not_real"]),
              dh.normalize_incident(_inc_at("2", "Old-Monitor", NOW, status="CLOSED", resolution="False Positive"), dh.DEFAULTS["not_real"])]
    t1 = dh.live_stats(None, batch1, rules_by_name)
    assert t1 == {"seen": 2, "enforced": 1, "monitor": 1, "unknown_action": 0, "open": 0, "real": 1, "not_real": 1, "fp_tp_ratio": "1:1"}
    batch2 = [dh.normalize_incident(_inc_at("3", "Cards-Block", NOW, status="OPEN"), dh.DEFAULTS["not_real"])]
    t2 = dh.live_stats(t1, batch2, rules_by_name)
    assert t2["seen"] == 3 and t2["enforced"] == 2 and t2["open"] == 1 and t2["fp_tp_ratio"] == "1:1"


def test_the_live_feed_endpoint_polls_and_tells_the_truth_about_coverage(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    real_now = datetime.now(timezone.utc)   # the endpoint has no test hook for "now"; it always reads the wall clock
    c = _client([_inc_at("e1", "Cards-Block", real_now - timedelta(seconds=20))])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: c)
    t = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    r = t.post("/api/live-feed", json=creds)
    assert r.status_code == 200, r.text
    d = r.json()
    assert len(d["incidents"]) == 1 and d["incidents"][0]["id"] == "e1"
    assert d["stats"]["seen"] == 1 and d["stats"]["enforced"] == 1
    assert d["coverage_note"] and "does not" in d["coverage_note"].lower() and "Cloud NSS" in d["coverage_note"]
    assert "next_since" in d and "tenant_label" in d
    # The next poll, with the returned since, sees nothing new.
    r2 = t.post("/api/live-feed", json=dict(creds, since=d["next_since"], stats=d["stats"]))
    assert r2.status_code == 200 and r2.json()["incidents"] == [] and r2.json()["stats"]["seen"] == 1


def test_the_live_feed_page_is_served_wired_and_explained():
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    t = TestClient(srv.app)
    r = t.get("/report/live")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', 'id="lfStart"', 'id="lfStop"', 'id="lfReset"',
                   '/api/live-feed', 'id="lfCoverage"', 'Web Insights / Cloud NSS', 'id="liveRegion" class="sr-only" role="status" aria-live="polite"',
                   '<script src="/static/report_theme.js"></script>', '<script src="/static/explain.js"></script>',
                   'window.opener.migrateCredBody', '/api/tenant-profiles'):
        assert needle in html, needle
    assert html.index("report_theme.js") < html.index("explain.js")
    assert "<h3" not in html and "prefers-color-scheme" not in html
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    assert ".lf-coverage" in css and ".lf-new" in css and "prefers-reduced-motion" in css.split(".lf-new")[1][:300]
    index = open(os.path.join(root, "static", "index.html"), encoding="utf-8").read()
    assert 'onclick="openLiveFeedTab()"' in index and "window.open('/report/live', '_blank')" in index
    explain = open(os.path.join(root, "static", "explain.js"), encoding="utf-8").read()
    assert re.search(r"^  X\.live = \{", explain, re.M) and "'/report/live': 'live'" in explain


class FakeDlpResources:
    """Administration > DLP Incident Receiver / ICAP Server objects."""
    def __init__(self, receivers=None, icap_servers=None):
        self.receivers = receivers if receivers is not None else []
        self.icap_servers = icap_servers if icap_servers is not None else []

    def list_dlp_incident_receiver(self):
        return self.receivers, None, None

    def list_dlp_icap_servers(self):
        return self.icap_servers, None, None


def _rule(name, *, cloud=False, icap=None, enabled=True):
    return Obj(id=hash(name) % 90000, name=name, order=1, action="ALLOW", state="ENABLED" if enabled else "DISABLED",
               dlp_engines=[{"id": 5001}], description="", zscaler_incident_receiver=cloud, icap_server=({"name": icap} if icap else None))


def test_incident_delivery_reads_the_rule_switch_and_the_receiver_objects_separately():
    c = _client([])
    c.zia.dlp_web_rules.items = [_rule("Cloud-Rule", cloud=True), _rule("ICAP-Rule", icap="OnPrem-1"), _rule("Silent-Rule")]
    # No receiver objects at all yet: both switches are on but nothing is actually configured to receive them.
    c.zia.dlp_resources = FakeDlpResources()
    d = dh.incident_delivery(c)
    assert d["rules_cloud"] == 1 and d["rules_icap"] == 1 and d["rules_silent"] == ["Silent-Rule"] and d["path"] == "both"
    assert not d["cloud_receiver_configured"] and not d["icap_receiver_configured"]
    kinds = {m["path"] for m in d["misconfigured"]}
    assert kinds == {"cloud", "icap"}
    cloud_m = next(m for m in d["misconfigured"] if m["path"] == "cloud")
    assert "no Incident Receiver object exists" in cloud_m["text"] and "1 rule" in cloud_m["text"]


def test_incident_delivery_is_not_misconfigured_once_an_active_receiver_exists():
    c = _client([])
    c.zia.dlp_web_rules.items = [_rule("Cloud-Rule", cloud=True)]
    c.zia.dlp_resources = FakeDlpResources(receivers=[{"name": "Primary Receiver", "url": "https://x", "status": "ENABLED"}])
    d = dh.incident_delivery(c)
    assert d["cloud_receiver_configured"] and d["misconfigured"] == [] and d["path"] == "cloud"


def test_incident_delivery_flags_a_disabled_receiver_even_though_one_exists():
    c = _client([])
    c.zia.dlp_web_rules.items = [_rule("Cloud-Rule", cloud=True)]
    c.zia.dlp_resources = FakeDlpResources(receivers=[{"name": "Old Receiver", "url": "https://x", "status": "DISABLED"}])
    d = dh.incident_delivery(c)
    assert not d["cloud_receiver_configured"]
    m = d["misconfigured"][0]
    assert m["path"] == "cloud" and "every configured Incident Receiver is disabled or unhealthy" in m["text"]


def test_the_misconfigured_finding_is_high_severity_and_independent_of_incident_history():
    c = _client([])
    c.zia.dlp_web_rules.items = [_rule("Cloud-Rule", cloud=True)]
    c.zia.dlp_resources = FakeDlpResources()
    rep = dh.generate(c, days=30)
    f = next(x for x in rep["findings"] if x["kind"] == "incident_delivery_misconfigured")
    assert f["severity"] == "high" and "cloud-to-cloud" in f["name"]


def test_the_page_shows_incident_receiver_objects_and_the_misconfiguration_warning():
    js = open("static/detection_health.js", encoding="utf-8").read()
    assert "misconfigured" in js and "Configured but not delivering" in js
    assert "Incident Receiver objects" in js and "no Incident Receiver object configured" in js
    assert "Zscaler Incident Receiver (cloud-to-cloud)" in js and "on-premises Incident Receiver over ICAP" in js
