"""Path Analyzer: a URL, hostname or IP typed by the operator becomes a
live, hop-by-hop path through the tenant with one verdict in plain words
and every point that blocks or impacts the traffic named."""
from __future__ import annotations

import time

import pytest

import path_analyzer as pa
from test_data_flow import ROUTES, _client
from test_ssl_flow import CATALOGUE, FakeCl


class LookupCl(FakeCl):
    """The Data Flow fake plus ZIA's URL lookup: categories per host."""
    LOOKUP = {
        "chat.openai.com": {"urlClassifications": ["AI_ML_APPS"], "application": "CHATGPT_AI"},
        "mail.example.com": {"urlClassifications": ["WEB_MAIL"]},
        "casino.example": {"urlClassifications": ["GAMBLING"]},
        "evil.example": {"urlClassifications": ["MALICIOUS_CONTENT"], "urlClassificationsWithSecurityAlert": ["MALICIOUS_CONTENT"]},
        "203.0.113.10": {"urlClassifications": ["OTHER_MISCELLANEOUS"]},
    }

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.lookups = []
        self.reads = 0

    def get(self, ep, p=None):
        self.reads += 1
        return super().get(ep, p)

    def post(self, ep, body=None):
        self.lookups.append((ep, body))
        assert ep == "/zia/urlLookup"
        return [dict(self.LOOKUP.get(body[0], {"urlClassifications": []}), url=body[0])], 200


def _lookup_client():
    return LookupCl(ROUTES, CATALOGUE)


def test_what_the_user_types_is_understood_or_refused_in_words():
    d = pa.parse_destination("https://drive.google.com/file/d/abc?x=1")
    assert d["host"] == "drive.google.com" and d["kind"] == "url" and d["path"] == "/file/d/abc" and not d["is_ip"]
    assert pa.parse_destination("Dropbox.com")["kind"] == "host" and pa.parse_destination("dropbox.com.")["host"] == "dropbox.com"
    ip = pa.parse_destination("203.0.113.10:8443")
    assert ip["is_ip"] and ip["port"] == 8443 and ip["kind"] == "ip" and not ip["private"]
    assert pa.parse_destination("10.1.2.3")["private"]
    for bad in ("", "not a host", "http://", "just words here"):
        with pytest.raises(ValueError, match="URL, a hostname or an IP address|not a URL"):
            pa.parse_destination(bad)


def test_the_lookup_reads_zias_answer_and_reports_when_it_cannot_run():
    c = _lookup_client()
    lk = pa.lookup_categories(c, "evil.example")
    assert lk["categories"] == ["MALICIOUS_CONTENT"] and lk["security_alerts"] == ["MALICIOUS_CONTENT"] and lk["error"] is None
    assert pa.lookup_categories(c, "chat.openai.com")["application"] == "CHATGPT_AI"
    assert pa.lookup_categories(_client(), "x.example")["error"] == "this client cannot run a URL lookup"

    class Refuses(LookupCl):
        def post(self, ep, body=None):
            return {"error": "forbidden"}, 403
    assert "HTTP 403" in pa.lookup_categories(Refuses(ROUTES, CATALOGUE), "x.example")["error"]


def test_the_verdict_names_what_blocks_or_impacts_the_traffic():
    c = _lookup_client()
    logs = []
    # Gambling: URL filtering blocks it before SSL; the rule is named.
    r = pa.analyze(c, "https://casino.example/play", "off", "windows", log=logs.append)
    v = r["verdict"]
    assert v["outcome"] == "blocked" and v["blocked_by"] == "Block gambling" and v["stops_at"] == "URL filtering"
    assert v["headline"] == "Blocked by URL filtering rule 'Block gambling'." and "no content leaves" in v["summary"]
    assert v["impacts"][0]["status"] == "blocked" and v["impacts"][0]["rule"] == "Block gambling"
    assert r["destination"]["host"] == "casino.example" and "GAMBLING" in v["categories"] and r["fresh_read"] and r["snapshot_for_cache"]
    assert any(l.startswith("Reading Client Connector") for l in logs) and any(l.startswith("Asking ZIA which categories") for l in logs) and logs[-1].startswith("Verdict:")
    assert r["assumptions"] and all(a.endswith(".") for a in r["assumptions"])
    # Webmail: left encrypted by the exemption → blind, the SSL rule named as the impact.
    w = pa.analyze(c, "mail.example.com", "off", "windows")["verdict"]
    assert w["outcome"] == "blind" and not w["content_inspected"] and w["headline"].startswith("Reaches mail.example.com encrypted")
    assert any(i["hop"] == "ssl" and i["rule"] == "No decrypt webmail" and i["status"] == "blind" for i in w["impacts"])
    # ChatGPT: decrypted, app control blocks upload, DLP enforces.
    a = pa.analyze(c, "chat.openai.com", "off", "windows")["verdict"]
    assert a["outcome"] == "enforce" and a["content_inspected"] and a["headline"].startswith("Reaches chat.openai.com decrypted; 2 DLP rule(s) inspect the content and can block it")
    assert any(i["hop"] == "cac" and i["status"] == "blocked" and i["rule"] == "AI no upload" for i in a["impacts"]) and "CHATGPT_AI" in a["applications"]
    # A host the app profile bypasses never reaches Zscaler.
    b = pa.analyze(c, "updates.vendor.com", "off", "windows")["verdict"]
    assert b["outcome"] == "bypassed" and not b["reaches_zscaler"] and b["headline"].startswith("Never reaches Zscaler") and b["stops_at"] == "Client Connector app profile"
    # A security alert from the lookup comes first among the impacts.
    e = pa.analyze(c, "evil.example", "off", "windows")["verdict"]
    assert e["impacts"][0]["status"] == "alert" and "security alert" in e["impacts"][0]["detail"]
    # An IP address is a destination too.
    ip = pa.analyze(c, "203.0.113.10", "off", "windows")
    assert ip["destination"]["is_ip"] and ip["verdict"]["outcome"] in ("enforce", "monitor", "none", "blind")


def test_a_second_destination_reuses_the_tenant_read_and_only_looks_the_host_up():
    c = _lookup_client()
    first = pa.analyze(c, "casino.example", "off", "windows")
    snap = first["snapshot_for_cache"]
    reads_before, lookups_before = c.reads, len(c.lookups)
    second = pa.analyze(c, "mail.example.com", "off", "macos", snapshot=snap)
    assert c.reads == reads_before and len(c.lookups) == lookups_before + 1, "no tenant read, one lookup"
    assert not second["fresh_read"] and "snapshot_for_cache" not in second and second["network"] == "off" and second["platform"] == "macos"
    assert second["verdict"]["outcome"] == "blind"
    # On the trusted network the forwarding profile sends it direct: the same read, a different answer.
    on_net = pa.analyze(c, "mail.example.com", "on", "macos", snapshot=snap)["verdict"]
    assert on_net["outcome"] == "bypassed" and on_net["stops_at"] == "Forwarding profile" and c.reads == reads_before


def test_the_endpoint_runs_as_a_job_and_the_next_run_reuses_the_read(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    c = _lookup_client()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    t = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    assert t.post("/api/path-analyzer/start", json=dict(creds, destination="not a host")).status_code == 400
    r = t.post("/api/path-analyzer/start", json=dict(creds, destination="https://casino.example/x"))
    assert r.status_code == 200 and r.json()["kind"] == "path", r.text
    job = r.json()["job_id"]
    deadline, since, logs = time.time() + 30, 0, []
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}?since={since}").json()
        logs += snap["logs"]; since = snap["next"]
        if snap["status"] != "running":
            break
        time.sleep(0.05)
    assert snap["status"] == "done", snap.get("error")
    res = snap["result"]
    assert res["verdict"]["blocked_by"] == "Block gambling" and res["report_id"].startswith("dataflow-") and res["tenant_label"] == "acme (production)"
    assert any(l.startswith("Reading ZIA policy") for l in logs)
    reads = c.reads
    again = t.post("/api/path-analyzer", json=dict(creds, destination="mail.example.com", report_id=res["report_id"])).json()
    assert again["verdict"]["outcome"] == "blind" and again["report_id"] == res["report_id"] and not again["fresh_read"] and c.reads == reads
    assert any("read a moment ago" in l for l in again["logs"])


def test_the_page_is_served_wired_and_explained():
    import os
    import re
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    t = TestClient(srv.app)
    r = t.get("/report/path")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', 'id="paDest"', 'id="paRun"', 'id="paStop"',
                   '/api/path-analyzer/start', '/api/dlp-packs/jobs/', 'role="log"', 'id="liveRegion" class="sr-only" role="status" aria-live="polite"',
                   '<script src="/static/report_theme.js"></script>', '<script src="/static/explain.js"></script>', '<script src="/static/data_flow.js"></script>',
                   'window.opener.migrateCredBody', '/api/tenant-profiles', 'What blocks this traffic', 'What impacts it on the way', 'Assumptions'):
        assert needle in html, needle
    assert html.index("report_theme.js") < html.index("explain.js") < html.index("data_flow.js")
    assert "<h3" not in html and "prefers-color-scheme" not in html
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    assert ".pa-verdict" in css and ".pa-impact" in css and ".pa-log" in css
    index = open(os.path.join(root, "static", "index.html"), encoding="utf-8").read()
    assert 'onclick="openPathAnalyzerTab()"' in index and "window.open('/report/path', '_blank')" in index
    explain = open(os.path.join(root, "static", "explain.js"), encoding="utf-8").read()
    assert re.search(r"^  X\.path = \{", explain, re.M) and "'/report/path': 'path'" in explain


def test_the_page_shows_the_policy_framework_and_the_assigned_profiles():
    """The page states up front, before any destination is typed, the
    framework every analysis is measured against (Zscaler's own policy
    order, device to incident) — and each result names the assigned
    Client Connector app profile and forwarding profile that decided the
    early hops, not just the object that happened to block the traffic."""
    import os
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html = TestClient(srv.app).get("/report/path").text
    assert 'id="paFramework"' in html and "how Zscaler processes a policy" in html
    assert "renderPolicyEnforcementFlow(document.getElementById('paFrameworkBody'))" in html
    assert "assigned Client Connector app profile" in html and "forwarding profile" in html.lower()
    assert 'Assigned Client Connector app profile' in html and 'Assigned forwarding profile' in html
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    assert ".pa-framework" in css and ".pa-framework > summary:focus-visible" in css


def test_stop_is_honoured_between_read_steps_and_said_in_words():
    c = _lookup_client()
    logs = []
    with pytest.raises(pa.Stopped, match="You clicked Stop"):
        pa.analyze(c, "casino.example", "off", "windows", log=logs.append, cancel=lambda: True)
    assert logs[-1].startswith("STOPPED") and not c.lookups, "stopped before the lookup; nothing else was asked"
    # Not cancelled: the same call completes.
    assert pa.analyze(c, "casino.example", "off", "windows", cancel=lambda: False)["verdict"]["outcome"] == "blocked"
