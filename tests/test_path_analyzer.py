"""Path Analyzer: a URL, hostname or IP typed by the operator becomes a
live, hop-by-hop path through the tenant with one verdict in plain words
and every point that blocks or impacts the traffic named."""
from __future__ import annotations

import shutil
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
    assert "What to do about it, across every channel" in html and "mitigationsHtml(v.mitigations)" in html
    assert ".pa-mitigations" in css and ".pa-mitigation.sev-high" in css


def test_stop_is_honoured_between_read_steps_and_said_in_words():
    c = _lookup_client()
    logs = []
    with pytest.raises(pa.Stopped, match="You clicked Stop"):
        pa.analyze(c, "casino.example", "off", "windows", log=logs.append, cancel=lambda: True)
    assert logs[-1].startswith("STOPPED") and not c.lookups, "stopped before the lookup; nothing else was asked"
    # Not cancelled: the same call completes.
    assert pa.analyze(c, "casino.example", "off", "windows", cancel=lambda: False)["verdict"]["outcome"] == "blocked"


def test_the_mitigation_recommendation_reasons_across_every_channel():
    """recommend_mitigations weighs Endpoint DLP first whenever the web
    path itself sees nothing (bypassed or blind, regardless of why);
    recommends promoting a monitor-only web rule or deploying one when
    the web path does see the content; and only brings in Email or SaaS
    Security API when the destination is actually shaped like webmail or
    a sanctioned cloud app, never as a blanket suggestion."""
    c = _lookup_client()

    # Bypassed: endpoint already covers the device (it's on in this fixture) — informational, not an action.
    b = pa.analyze(c, "updates.vendor.com", "off", "windows")["verdict"]
    assert b["mitigations"][0] == {"rank": 1, "channel": "endpoint", "action": "Endpoint DLP already covers this device",
                                    "why": "This traffic never reaches Zscaler, but Endpoint DLP runs locally regardless of the network path and is already monitor.", "severity": "info"}

    # Blind (SSL exempted): same endpoint reasoning, plus webmail brings in Email DLP since it is off.
    w = pa.analyze(c, "mail.example.com", "off", "windows")["verdict"]
    assert w["mitigations"][0]["channel"] == "endpoint" and w["mitigations"][0]["severity"] == "info"
    email = next(m for m in w["mitigations"] if m["channel"] == "email")
    assert email["action"] == "Onboard Email DLP for this traffic" and "Web Mail" in email["why"] and email["severity"] == "medium"

    # Enforced and decrypted: the web path already covers it; only the low-priority SaaS onboarding is offered.
    e = pa.analyze(c, "chat.openai.com", "off", "windows")["verdict"]
    assert e["mitigations"] == [{"rank": 1, "channel": "saas", "action": "Onboard CHATGPT_AI to SaaS Security API",
                                  "why": "ZIA recognises this as a sanctioned cloud application, but no SaaS Security API rule scans it at rest, so data already stored there is never checked.", "severity": "low"}]

    # Blocked outright: nothing to mitigate.
    blocked = pa.analyze(c, "https://casino.example/play", "off", "windows")["verdict"]
    assert blocked["mitigations"] == []

    # Monitor-only web rule (macOS drops Endpoint DLP, so the web rule is the whole story): promote it.
    m = pa.analyze(c, "updates.vendor.com", "off", "macos")["verdict"]
    assert m["outcome"] == "monitor" and m["mitigations"] == [{"rank": 1, "channel": "web", "action": "Promote 'Bank-Customer PII (Global)-Monitor' from monitor to block",
        "why": "The content is inspected but only logged; once the incidents look right, blocking stops the leak instead of recording it.", "severity": "medium"}]


def test_the_page_draws_the_dlp_chain_live_and_honours_reduced_motion():
    """The live chain from the Data Security Architect reference (#chain)
    sits above the result: inline SVG with bits on requestAnimationFrame,
    a pause / play button, static arrows and no motion when the system
    asks for reduced motion, a text summary for screen readers, and the
    page's own colour tokens so it reads in both themes."""
    import os
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    t = TestClient(srv.app)
    html = t.get("/report/path").text
    for needle in ('<script src="/static/path_motion.js"></script>', 'id="paMotion"', 'id="paMotionBody"', 'href="/reference/data-security-architect#chain"',
                   "renderPathMotion(document.getElementById('paMotionBody'))", "motion.update(null);", "motion.update(res);"):
        assert needle in html, needle
    assert html.index("data_flow.js") < html.index("path_motion.js")
    assert "<h3" not in html
    r = t.get("/static/path_motion.js")
    assert r.status_code == 200
    js = r.text
    for needle in ("requestAnimationFrame", "cancelAnimationFrame", "(prefers-reduced-motion: reduce)", 'aria-controls="pmStage"', 'role="img"',
                   'aria-labelledby="pmTitle"', 'aria-describedby="pmSummary"', 'marker-end="url(#pmArrow)"', "visibilitychange", "IntersectionObserver",
                   "Incident Receiver", "Customer storage", "Storage event", "WA integration", "Workflow Automation", "NSS / Cloud NSS", "SIEM",
                   "Auditor email", "3rd-party ICAP", "DSPM alerts", "never feeds WA", "Dictionaries", "DLP engine", "Channels gate", "≤ 4 engines per rule",
                   "Inline Web DLP rule", "Endpoint DLP rule", "Email DLP rule", "SaaS API DLP rule"):
        assert needle in js, needle
    assert "http://" not in js.replace("http://www.w3.org/2000/svg", "") and "https://" not in js, "no external library or call"
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    pm = css[css.index("/* Path motion"):css.index("/* ── Live DLP Feed")]
    for needle in (".pa-motion", ".pm-svg", ".pm-bit", ".pm-edge.is-broken", ".pm-stop", "@media (prefers-reduced-motion: reduce)", "@media (max-width: 760px)", "overflow-x: auto"):
        assert needle in pm, needle
    assert "var(--accent)" in pm and "var(--pass)" in pm and "var(--fail)" in pm and "#" not in pm, "colours come from the theme tokens"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_the_bits_follow_the_analyzed_path_and_stop_where_it_breaks():
    """pmModel turns an analyzer result into the routes the bits take: the
    reference chain idles on every lane; a result sends them along the
    path it describes and stops them at the link that breaks it."""
    import json
    import os
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c = _lookup_client()
    results = {"idle": None}
    for key, dest, plat in (("bypassed", "updates.vendor.com", "windows"), ("blind", "mail.example.com", "windows"),
                            ("enforce", "chat.openai.com", "windows"), ("blocked", "https://casino.example/play", "windows"),
                            ("monitor", "updates.vendor.com", "macos")):
        r = pa.analyze(c, dest, "off", plat)
        r.pop("snapshot_for_cache", None)
        results[key] = r
    script = (
        "const vm=require('vm'),fs=require('fs');const ctx={window:{}};vm.createContext(ctx);"
        f"vm.runInContext(fs.readFileSync({json.dumps(os.path.join(root, 'static', 'path_motion.js'))},'utf8'),ctx);"
        "const R=JSON.parse(fs.readFileSync(0,'utf8'));const out={};"
        "for(const k of Object.keys(R)){const m=ctx.pmModel(R[k]);out[k]={mode:m.mode,routes:m.routes.map(r=>({edges:r.edges,stop:r.stop,tone:r.tone})),stops:m.stops,summary:m.summary};}"
        "process.stdout.write(JSON.stringify(out));")
    p = subprocess.run(["node", "-e", script], input=json.dumps(results, default=str), capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    m = json.loads(p.stdout)

    idle = m["idle"]
    assert idle["mode"] == "reference" and not idle["stops"]
    edges = {e for r in idle["routes"] for e in r["edges"]}
    for e in ("cap_web>dict", "cap_ep>dict", "cap_mail>dict", "cap_saas>dict", "dict>engine", "engine>r_web", "engine>r_dspm",
              "r_web>logs", "logs>nss", "nss>siem", "r_web>auditor", "r_web>evid", "evid>storage", "storage>event", "event>waint", "waint>wa",
              "r_web>icap", "r_dspm>dspma"):
        assert e in edges, e
    # Only the evidence lane reaches Workflow Automation: telemetry, auditor email, ICAP and DSPM never do.
    for r in idle["routes"]:
        if "waint>wa" in r["edges"]:
            assert any(e.endswith(">evid") for e in r["edges"]) and not any(x in r["edges"] for x in ("logs>nss", "nss>siem"))
    assert not any(e.startswith(("siem>", "nss>wa", "auditor>", "icap>", "dspma>")) for e in edges)

    def web(k):
        return [r for r in m[k]["routes"] if r["edges"][0] == "cap_web>dict"]

    assert web("bypassed")[0]["stop"] == 0 and web("bypassed")[0]["tone"] == "broken" and "Never reaches Zscaler" in m["bypassed"]["summary"][0]
    assert web("blind")[0]["stop"] == 0 and "Left encrypted by SSL inspection rule" in m["blind"]["summary"][0]
    assert web("blocked")[0]["tone"] == "blocked" and "Block gambling" in m["blocked"]["summary"][0]
    enf = web("enforce")
    assert any(r["edges"][-1] == "waint>wa" and r["stop"] is None for r in enf), "a rule with the Incident Receiver carries evidence to WA"
    assert any(r["edges"][-1] == "nss>siem" for r in enf) and any(r["edges"][-1] == "r_web>auditor" for r in enf)
    mon = web("monitor")
    ev = next(r for r in mon if "r_web>evid" in r["edges"])
    assert ev["edges"][ev["stop"]] == "r_web>evid" and ev["tone"] == "broken", "no forwarding: the bits stop before Evidence forwarding"
    assert any("Workflow Automation stays empty" in s for s in m["monitor"]["summary"])
    ep = next(r for r in m["monitor"]["routes"] if r["edges"][0] == "cap_ep>dict")
    assert ep["stop"] == 0, "macOS: Endpoint DLP is not installed, so its content never reaches a dictionary"


def test_the_motion_toggle_is_not_announced_as_pressed_and_destroy_stops_everything():
    """The Pause / Play button's label already says what a press does, so it
    carries no aria-pressed (paused, it would read "Play motion, pressed").
    destroy() must leave nothing that can restart the loop: the button, the
    reduced-motion listener and visibility are all let go."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "path_motion.js"), encoding="utf-8").read()
    toggle = js[js.index('id="pmToggle"') - 40:js.index("</button>", js.index('id="pmToggle"'))]
    assert "aria-pressed" not in toggle and "setAttribute('aria-pressed'" not in js
    destroy = js[js.index("destroy() {"):js.index("window.renderPathMotion")]
    for needle in ("destroyed = true", "btn.removeEventListener('click', onClick)", "reduce.removeEventListener('change', onReduce)",
                   "document.removeEventListener('visibilitychange', onVis)", "io.disconnect()"):
        assert needle in destroy, needle
    assert "function start() { if (!destroyed &&" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_a_stop_on_the_evidence_lane_is_marked_off_the_shared_forwarding_bus():
    """r_web>auditor and r_web>evid run down the same bus. When only the
    evidence lane breaks, its mark (and where its bits pop) must sit on its
    own last stretch into Evidence forwarding, not on the bus beside the
    auditor's live junction."""
    import json
    import os
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = (
        "const vm=require('vm'),fs=require('fs');const ctx={window:{}};vm.createContext(ctx);"
        f"vm.runInContext(fs.readFileSync({json.dumps(os.path.join(root, 'static', 'path_motion.js'))},'utf8'),ctx);"
        # A walker for the bus edges' M x,y H V H paths.
        "function pt(d,len){const t=d.match(/[MHV][^MHV]*/g);let [x,y]=t[0].slice(1).split(',').map(Number);const seg=[];"
        "for(const c of t.slice(1)){const v=+c.slice(1);if(c[0]==='H'){seg.push([x,y,v,y]);x=v}else{seg.push([x,y,x,v]);y=v}}"
        "const L=seg.reduce((a,s)=>a+Math.abs(s[2]-s[0])+Math.abs(s[3]-s[1]),0);if(len==null)return L;"
        "for(const s of seg){const l=Math.abs(s[2]-s[0])+Math.abs(s[3]-s[1]);if(len<=l){const f=l?len/l:0;return [s[0]+(s[2]-s[0])*f,s[1]+(s[3]-s[1])*f]}len-=l}}"
        "const out={};for(const e of ['r_web>evid','r_web>auditor','r_web>icap']){const d=ctx._pmEdgeD(e),L=pt(d);out[e]={L,at:pt(d,ctx._pmStopLen(e,L)),end:pt(d,L)};}"
        "out.bus=ctx._pmEdgeD('r_web>evid').match(/H(\d+)/)[1];"
        "process.stdout.write(JSON.stringify(out));")
    p = subprocess.run(["node", "-e", script], capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    m = json.loads(p.stdout)
    bus = int(m["bus"])
    for e in ("r_web>evid", "r_web>auditor", "r_web>icap"):
        x, y = m[e]["at"]
        assert x > bus + 9 and y == m[e]["end"][1], (e, m[e])  # off the bus by more than the mark's radius, on its own row

