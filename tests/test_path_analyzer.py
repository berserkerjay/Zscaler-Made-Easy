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


FULL = pa.full_path_scope()


def _analyze(*a, **kw):
    """analyze with every part the path reads in scope, unless a test says otherwise."""
    kw.setdefault("scope", FULL)
    return pa.analyze(*a, **kw)


# The Scope page's selection with every part the path reads in scope.
SCOPE_ALL = {"scopes": ["dlp", "zia_extras", "zcc"],
             "channels": {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "saas_casb": "zscaler",
                          "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}}


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
    r = _analyze(c, "https://casino.example/play", "off", "windows", log=logs.append)
    v = r["verdict"]
    assert v["outcome"] == "blocked" and v["blocked_by"] == "Block gambling" and v["stops_at"] == "URL filtering"
    assert v["headline"] == "Blocked by URL filtering rule 'Block gambling'." and "no content leaves" in v["summary"]
    assert v["impacts"][0]["status"] == "blocked" and v["impacts"][0]["rule"] == "Block gambling"
    assert r["destination"]["host"] == "casino.example" and "GAMBLING" in v["categories"] and r["fresh_read"] and r["snapshot_for_cache"]
    assert any(l.startswith("Reading Client Connector") for l in logs) and any(l.startswith("Asking ZIA which categories") for l in logs) and logs[-1].startswith("Verdict:")
    assert r["assumptions"] and all(a.endswith(".") for a in r["assumptions"])
    # Webmail: left encrypted by the exemption → blind, the SSL rule named as the impact.
    w = _analyze(c, "mail.example.com", "off", "windows")["verdict"]
    assert w["outcome"] == "blind" and not w["content_inspected"] and w["headline"].startswith("Reaches mail.example.com encrypted")
    assert any(i["hop"] == "ssl" and i["rule"] == "No decrypt webmail" and i["status"] == "blind" for i in w["impacts"])
    # ChatGPT: decrypted, app control blocks upload, DLP enforces.
    a = _analyze(c, "chat.openai.com", "off", "windows")["verdict"]
    assert a["outcome"] == "enforce" and a["content_inspected"] and a["headline"].startswith("Reaches chat.openai.com decrypted; 2 DLP rule(s) inspect the content and can block it")
    assert any(i["hop"] == "cac" and i["status"] == "blocked" and i["rule"] == "AI no upload" for i in a["impacts"]) and "CHATGPT_AI" in a["applications"]
    # A host the app profile bypasses never reaches Zscaler.
    b = _analyze(c, "updates.vendor.com", "off", "windows")["verdict"]
    assert b["outcome"] == "bypassed" and not b["reaches_zscaler"] and b["headline"].startswith("Never reaches Zscaler") and b["stops_at"] == "Client Connector app profile"
    # A security alert from the lookup comes first among the impacts.
    e = _analyze(c, "evil.example", "off", "windows")["verdict"]
    assert e["impacts"][0]["status"] == "alert" and "security alert" in e["impacts"][0]["detail"]
    # An IP address is a destination too.
    ip = _analyze(c, "203.0.113.10", "off", "windows")
    assert ip["destination"]["is_ip"] and ip["verdict"]["outcome"] in ("enforce", "monitor", "none", "blind")


def test_a_second_destination_reuses_the_tenant_read_and_only_looks_the_host_up():
    c = _lookup_client()
    first = _analyze(c, "casino.example", "off", "windows")
    snap = first["snapshot_for_cache"]
    reads_before, lookups_before = c.reads, len(c.lookups)
    second = _analyze(c, "mail.example.com", "off", "macos", snapshot=snap)
    assert c.reads == reads_before and len(c.lookups) == lookups_before + 1, "no tenant read, one lookup"
    assert not second["fresh_read"] and "snapshot_for_cache" not in second and second["network"] == "off" and second["platform"] == "macos"
    assert second["verdict"]["outcome"] == "blind"
    # On the trusted network the forwarding profile sends it direct: the same read, a different answer.
    on_net = _analyze(c, "mail.example.com", "on", "macos", snapshot=snap)["verdict"]
    assert on_net["outcome"] == "bypassed" and on_net["stops_at"] == "Forwarding profile" and c.reads == reads_before


def test_the_endpoint_runs_as_a_job_and_the_next_run_reuses_the_read(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    c = _lookup_client()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    t = TestClient(srv.app)
    creds = dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}, **SCOPE_ALL)
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
        _analyze(c, "casino.example", "off", "windows", log=logs.append, cancel=lambda: True)
    assert logs[-1].startswith("STOPPED") and not c.lookups, "stopped before the lookup; nothing else was asked"
    # Not cancelled: the same call completes.
    assert _analyze(c, "casino.example", "off", "windows", cancel=lambda: False)["verdict"]["outcome"] == "blocked"


def test_the_mitigation_recommendation_reasons_across_every_channel():
    """recommend_mitigations weighs Endpoint DLP first whenever the web
    path itself sees nothing (bypassed or blind, regardless of why);
    recommends promoting a monitor-only web rule or deploying one when
    the web path does see the content; and only brings in Email or SaaS
    Security API when the destination is actually shaped like webmail or
    a sanctioned cloud app, never as a blanket suggestion."""
    c = _lookup_client()

    # Bypassed: endpoint already covers the device (it's on in this fixture) — informational, not an action.
    b = _analyze(c, "updates.vendor.com", "off", "windows")["verdict"]
    assert b["mitigations"][0] == {"rank": 1, "channel": "endpoint", "action": "Endpoint DLP already covers this device",
                                    "why": "This traffic never reaches Zscaler, but Endpoint DLP runs locally regardless of the network path and is already monitor.", "severity": "info"}

    # Blind (SSL exempted): same endpoint reasoning, plus webmail brings in Email DLP since it is off.
    w = _analyze(c, "mail.example.com", "off", "windows")["verdict"]
    assert w["mitigations"][0]["channel"] == "endpoint" and w["mitigations"][0]["severity"] == "info"
    email = next(m for m in w["mitigations"] if m["channel"] == "email")
    assert email["action"] == "Onboard Email DLP for this traffic" and "Web Mail" in email["why"] and email["severity"] == "medium"

    # Enforced and decrypted: the web path already covers it; only the low-priority SaaS onboarding is offered.
    e = _analyze(c, "chat.openai.com", "off", "windows")["verdict"]
    assert e["mitigations"] == [{"rank": 1, "channel": "saas", "action": "Onboard CHATGPT_AI to SaaS Security API",
                                  "why": "ZIA recognises this as a sanctioned cloud application, but no SaaS Security API rule scans it at rest, so data already stored there is never checked.", "severity": "low"}]

    # Blocked outright: nothing to mitigate.
    blocked = _analyze(c, "https://casino.example/play", "off", "windows")["verdict"]
    assert blocked["mitigations"] == []

    # Monitor-only web rule (macOS drops Endpoint DLP, so the web rule is the whole story): promote it.
    m = _analyze(c, "updates.vendor.com", "off", "macos")["verdict"]
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
                   "renderPathMotion(document.getElementById('paMotionBody'))", "showMotion(null);", "showMotion(res);"):
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
        r = _analyze(c, dest, "off", plat)
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
        r"out.bus=ctx._pmEdgeD('r_web>evid').match(/H(\d+)/)[1];"
        "process.stdout.write(JSON.stringify(out));")
    p = subprocess.run(["node", "-e", script], capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    m = json.loads(p.stdout)
    bus = int(m["bus"])
    for e in ("r_web>evid", "r_web>auditor", "r_web>icap"):
        x, y = m[e]["at"]
        assert x > bus + 9 and y == m[e]["end"][1], (e, m[e])  # off the bus by more than the mark's radius, on its own row



# ── path_motion.js in a stand-in browser (tests/path_motion_dom.js) ────
def _pm_run(script, data=None):
    """Runs `script` under node with the stand-in browser loaded as H, the
    page script's path as PM and `data` as D; returns what it writes as JSON."""
    import json
    import os
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pre = (f"const H=require({json.dumps(os.path.join(root, 'tests', 'path_motion_dom.js'))});"
           f"const PM={json.dumps(os.path.join(root, 'static', 'path_motion.js'))};"
           "const D=JSON.parse(require('fs').readFileSync(0,'utf8'));")
    p = subprocess.run(["node", "-e", pre + script], input=json.dumps(data, default=str), capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def _pm_result(dest, plat):
    import json
    r = _analyze(_lookup_client(), dest, "off", plat)
    r.pop("snapshot_for_cache", None)
    return json.loads(json.dumps(r, default=str))


def _pm_hop(res, key):
    return next(h for h in res["trace"]["hops"] if h["key"] == key)


_needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


@_needs_node
def test_a_broken_evidence_lane_is_drawn_only_where_no_live_link_runs():
    """The monitor result breaks the evidence lane while telemetry (and
    here the auditor email) stay live. All three leave the rule on the same
    stub and run down the same bus, so the broken stroke is drawn only on
    the evidence edge's own stretch: the bus below the auditor junction and
    the run into Evidence forwarding. The live links keep their own look."""
    res = _pm_result("updates.vendor.com", "macos")
    _pm_hop(res, "incident")["notifiers"] = ["Auditor-Rule"]
    out = _pm_run(
        "const w=H.load(PM),c=w.container(),m=w.ctx.renderPathMotion(c);m.update(D);"
        "const e=k=>c.querySelectorAll('.pm-edge').find(p=>p.dataset.edge===k);"
        "const own=c.querySelectorAll('.pm-own').map(p=>({k:p.dataset.own,d:p.getAttribute('d'),cls:p.getAttribute('class'),mk:p.getAttribute('marker-end')}));"
        "const cls=k=>e(k).getAttribute('class');"
        "const geo={both:w.ctx._pmOwnD('r_web>evid',['r_web>logs','r_web>auditor']),logs:w.ctx._pmOwnD('r_web>evid',['r_web>logs']),"
        "none:w.ctx._pmOwnD('r_web>evid',[]),full:w.ctx._pmEdgeD('r_web>evid'),up:w.ctx._pmOwnD('r_saas>auditor',['r_saas>evid'])};"
        "const r={own,evid:cls('r_web>evid'),evidMarker:e('r_web>evid').getAttribute('marker-end'),logs:cls('r_web>logs'),aud:cls('r_web>auditor'),geo};"
        "m.update(null);r.after=c.querySelectorAll('.pm-own').length;r.mk=e('r_web>evid').getAttribute('marker-end');r.split=e('r_web>evid').classList.contains('is-split');"
        "process.stdout.write(JSON.stringify(r));",
        res)
    assert out["own"] == [{"k": "r_web>evid", "d": "M752,147 V222 H780", "cls": "pm-edge pm-own lane-ev is-broken", "mk": "url(#pmArrow)"}], out["own"]
    assert "is-split" in out["evid"] and out["evidMarker"] == "none", "the full edge only carries the bits"
    for k in ("logs", "aud"):
        assert "is-broken" not in out[k] and "is-off" not in out[k], (k, out[k])
    g = out["geo"]
    assert g["both"] == "M752,147 V222 H780" and g["logs"] == "M752,72 V222 H780" and g["none"] == g["full"]
    assert g["up"] == "M752,222 V147 H780", "an edge running up the bus drops the stretch a live sibling below shares"
    assert out["after"] == 0 and out["mk"] == "url(#pmArrow)" and not out["split"], "the reference chain draws every edge whole again"


@_needs_node
def test_the_motion_summary_caps_long_name_lists():
    """The summary is the chain's text alternative (aria-describedby): with
    hundreds of rules it names the first five and says how many more,
    the way the hop detail does."""
    res = _pm_result("chat.openai.com", "windows")
    dlp = _pm_hop(res, "dlp")
    base = dict(dlp["rules"][0])
    dlp["rules"] = [dict(base, name=f"Rule number {i} with a fairly long descriptive name", engines=[f"E{i}-{j}" for j in range(5)],
                         icap_server="icap", incident_receiver=None) for i in range(200)]
    _pm_hop(res, "incident")["notifiers"] = [f"auditor{i}@example.com" for i in range(40)]
    out = _pm_run("const w=H.load(PM);const s=w.ctx.pmModel(D).summary;"
                  "const c=w.container();w.ctx.renderPathMotion(c).update(D);"
                  "process.stdout.write(JSON.stringify({s,len:c.querySelector('#pmSummary').textContent.length,list:w.ctx._pmList(['a','b','c','d','e','f','g'])}));", res)
    assert out["list"] == "a, b, c, d, e, … and 2 more"
    web = out["s"][0]
    assert "200 Web DLP rule(s)" in web and "… and 995 more" in web and "… and 195 more reference more than four engines" in web, web
    assert any("auditor4@example.com, … and 35 more" in s for s in out["s"])
    assert any(s.startswith("Evidence lane: Rule number 0") and "… and 195 more → an ICAP server only" in s for s in out["s"])
    assert all(len(s) < 900 for s in out["s"]), max(len(s) for s in out["s"])
    assert out["len"] < 4000, out["len"]


@_needs_node
def test_rule_and_policy_names_reach_the_page_as_text_never_as_markup():
    """Rule, engine, notifier and policy names come from the tenant and
    flow into the summary list and the stop marks' tooltips: they must be
    escaped, so markup in a name is shown as text and never becomes an
    element (stored XSS from a rule name)."""
    x = '<img src=x id=pwn onerror="window.PWN=1">'
    res = _pm_result("updates.vendor.com", "macos")
    for r in _pm_hop(res, "dlp")["rules"]:
        r["name"] = x
        r["engines"] = [x, x + "2"]
    _pm_hop(res, "incident")["notifiers"] = [x]
    for ch in res["trace"]["channels"].values():
        ch["detail"] = x
    blocked = _pm_result("https://casino.example/play", "windows")
    blocked["verdict"]["stops_at"] = x
    blocked["verdict"]["blocked_by"] = x
    out = _pm_run(
        "const r={};for(const k of ['m','b']){const w=H.load(PM),c=w.container();w.ctx.renderPathMotion(c).update(D[k]);"
        "r[k]={imgs:c.all().filter(e=>e.tag==='img').length,pwn:!!w.ctx.PWN,sum:c.querySelector('#pmSummary').textContent,"
        "titles:c.querySelectorAll('.pm-stop').map(g=>g.querySelector('title').textContent),html:c.querySelector('#pmSummary').innerHTML+c.querySelector('.pm-stops').innerHTML};}"
        "process.stdout.write(JSON.stringify(r));", {"m": res, "b": blocked})
    for k in ("m", "b"):
        o = out[k]
        assert o["imgs"] == 0 and not o["pwn"], (k, o["html"][:400])
        assert x in o["sum"] and any(x in t for t in o["titles"]), k
        assert "<img" not in o["html"] and "&lt;img" in o["html"], k


@_needs_node
def test_reduced_motion_visibility_and_scrolling_start_and_stop_the_frames():
    """Behaviour, not strings: with reduced motion asked for no frame is
    requested and the button offers Play; Play starts the frames and the
    bits move; a hidden page or a chain scrolled off screen requests no
    more frames until it is back; Pause stops them; destroy() lets go."""
    out = _pm_run(
        "const r={};const pos=c=>c.querySelector('.pm-bits').children.map(e=>e.getAttribute('cx')+','+e.getAttribute('cy')).join(';');"
        # Reduced motion: still, until Play.
        "let w=H.load(PM,{reduce:true}),c=w.container(),m=w.ctx.renderPathMotion(c),b=c.querySelector('#pmToggle');"
        "r.reduceStart={pending:w.pending(),req:w.stats.requested,label:b.textContent,note:c.querySelector('#pmMotionNote').textContent};"
        "b.click();r.play={pending:w.pending(),label:b.textContent};w.frames(90);r.bits=c.querySelector('.pm-bits').children.length;"
        "const p0=pos(c);w.frames(5);r.moved=p0!==pos(c);"
        "w.setHidden(true);r.hidden=w.pending();let q=w.stats.requested;w.frames(5);r.hiddenReq=w.stats.requested-q;"
        "w.setHidden(false);r.visible=w.pending();"
        "w.intersect(false);r.off=w.pending();q=w.stats.requested;w.frames(5);r.offReq=w.stats.requested-q;"
        "w.setHidden(false);r.offThenVisible=w.pending();"
        "w.intersect(true);r.on=w.pending();"
        "b.click();r.pause={pending:w.pending(),label:b.textContent,bits:c.querySelector('.pm-bits').children.length};"
        "b.click();m.destroy();r.destroyed=w.pending();b.click();w.setHidden(false);w.intersect(true);r.afterDestroy=w.pending();"
        # No reduced motion: running from the start; the system setting turning on stops it.
        "w=H.load(PM,{reduce:false});c=w.container();w.ctx.renderPathMotion(c);"
        "r.normal={pending:w.pending(),label:c.querySelector('#pmToggle').textContent};"
        "w.mq.matches=true;w.mq.dispatch('change');r.reduceOn={pending:w.pending(),label:c.querySelector('#pmToggle').textContent};"
        "process.stdout.write(JSON.stringify(r));")
    assert out["reduceStart"]["pending"] == 0 and out["reduceStart"]["req"] == 0 and out["reduceStart"]["label"] == "Play motion"
    assert "reduced motion" in out["reduceStart"]["note"]
    assert out["play"] == {"pending": 1, "label": "Pause motion"} and out["bits"] > 0 and out["moved"]
    assert out["hidden"] == 0 and out["hiddenReq"] == 0, "a hidden page requests no frame"
    assert out["visible"] == 1
    assert out["off"] == 0 and out["offReq"] == 0, "off screen: no frame"
    assert out["offThenVisible"] == 0, "visible again but still off screen: still no frame"
    assert out["on"] == 1
    assert out["pause"] == {"pending": 0, "label": "Play motion", "bits": 0}
    assert out["destroyed"] == 0 and out["afterDestroy"] == 0
    assert out["normal"] == {"pending": 1, "label": "Pause motion"}
    assert out["reduceOn"] == {"pending": 0, "label": "Play motion"}


@_needs_node
def test_the_stop_cases_the_changelog_names_are_drawn_where_they_break():
    """No covering Web DLP rule stops the bits at the rule (engine>r_web);
    a covering rule that names no engine stops them there too and says
    which rule; a rule that forwards only to an ICAP server draws the
    evidence lane as assumed, never as a confirmed Incident Receiver path;
    and a rule over the four-engine limit is named."""
    none = _pm_result("chat.openai.com", "windows")
    none["verdict"]["outcome"] = "none"
    no_engine = _pm_result("chat.openai.com", "windows")
    for r in _pm_hop(no_engine, "dlp")["rules"]:
        r["engines"] = []
    icap = _pm_result("chat.openai.com", "windows")
    rules = _pm_hop(icap, "dlp")["rules"]
    for r in rules:
        r["incident_receiver"] = None
        r["icap_server"] = "Third-party ICAP"
    rules[0]["engines"] = ["E1", "E2", "E3", "E4", "E5"]
    out = _pm_run("const w=H.load(PM);const r={};for(const k of Object.keys(D)){const m=w.ctx.pmModel(D[k]);"
                  "r[k]={routes:m.routes.map(x=>({edges:x.edges,stop:x.stop,tone:x.tone})),stops:m.stops,summary:m.summary,extra:m.extra};}"
                  "process.stdout.write(JSON.stringify(r));", {"none": none, "no_engine": no_engine, "icap": icap})

    def web(k):
        # The ChatGPT result also has a Cloud App Control upload block: its ■
        # is a one-edge route of its own (tested below).
        return [r for r in out[k]["routes"] if r["edges"][0] == "cap_web>dict" and r["tone"] != "blocked"]

    n = web("none")
    assert len(n) == 1 and n[0]["stop"] == 2 and n[0]["edges"][2] == "engine>r_web" and n[0]["tone"] == "broken"
    assert out["none"]["stops"][0]["edge"] == "engine>r_web" and "no enabled Web DLP rule" in out["none"]["stops"][0]["reason"]
    ne = web("no_engine")
    names = [r["name"] for r in _pm_hop(no_engine, "dlp")["rules"]]
    assert len(ne) == 1 and ne[0]["stop"] == 2 and ne[0]["tone"] == "broken"
    reason = out["no_engine"]["stops"][0]["reason"]
    assert out["no_engine"]["stops"][0]["edge"] == "engine>r_web" and "name no DLP engine" in reason and all(x in reason for x in names)
    ev = next(r for r in web("icap") if "r_web>evid" in r["edges"])
    assert ev["tone"] == "assumed" and ev["stop"] is None and out["icap"]["extra"]["assumed"] == ["r_web>evid"]
    assert not any(r["edges"][-1] == "waint>wa" and r["tone"] is None for r in web("icap")), "no confirmed path to Workflow Automation"
    assert any(s.startswith("Evidence lane:") and "ICAP server only" in s and "Incident Receiver VM" in s for s in out["icap"]["summary"])
    assert any(r["edges"][-1] == "r_web>icap" for r in web("icap"))
    assert f"{rules[0]['name']} reference more than four engines" in out["icap"]["summary"][0]


@_needs_node
def test_a_browser_without_flatmap_still_gets_the_result_and_the_motion_never_sinks_it():
    """pmModel uses nothing newer than ES2017, so a browser without
    Array.prototype.flatMap still draws the result; and the page calls the
    motion through a guard, so if the picture ever throws, the analysis
    result and its verdict stand and only the picture is hidden."""
    import re
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    res = _pm_result("chat.openai.com", "windows")
    out = _pm_run("const w=H.load(PM,{noFlatMap:true});const ok=w.run('typeof [].flatMap');const c=w.container();const m=w.ctx.renderPathMotion(c).update(D);"
                  "process.stdout.write(JSON.stringify({ok,mode:m.mode,routes:m.routes.length}));", res)
    assert out["ok"] == "undefined" and out["mode"] == "result" and out["routes"] > 3
    html = TestClient(srv.app).get("/report/path").text
    guard = re.search(r"function showMotion\(res\) \{\s*try \{ motion\.update\(res\); \} catch \(e\) \{ document\.getElementById\('paMotion'\)\.hidden = true; \}", html)
    assert guard, "motion.update runs inside its own try/catch"
    assert html.count("motion.update(") == 1, "every call goes through showMotion"
    run = html[html.index("async function run()"):html.index("function fail(")]
    assert run.index("render(res, snap.logs || []);") < run.index("showMotion(res);") < run.index("say(`Verdict:")


def test_the_blocked_mark_is_explained_and_not_drawn_in_a_lane_colour():
    """A blocked stop is drawn as ■, a broken one as ✕: the legend and the
    note name both, and the blocked mark does not share the accent colour of
    the live content lane."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "path_motion.js"), encoding="utf-8").read()
    legend = js[js.index('class="pm-legend"'):js.index("</div>", js.index('class="pm-legend"'))]
    assert "✕</b>where the chain breaks" in legend and "■</b>where policy blocks it" in legend
    assert "a ✕ marks where the chain breaks and a ■ where policy blocks" in js
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    for rule in (".pm-stop.tone-blocked circle {", ".pm-stop.tone-blocked text {", ".pm-edge.is-blocked {"):
        body = css[css.index(rule):css.index("}", css.index(rule))]
        assert "var(--accent)" not in body and "var(--text)" in body, rule


def test_the_chain_text_is_never_scaled_below_legible_sizes():
    """The 1310-unit chain is never drawn narrower than 1270px (a narrower
    window scrolls it), and its smallest text is 11.5 units, so labels,
    subtitles, captions and the 'never feeds WA' notes render at 11px or
    more at every window width."""
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "path_motion.js"), encoding="utf-8").read()
    assert "PM_W_TOTAL = 1150 + PM_W + 10" in js and "PM_W = 150" in js
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    pm = css[css.index("/* Path motion"):css.index("/* ── Live DLP Feed")]
    min_w = int(re.search(r"\.pm-svg \{[^}]*min-width: (\d+)px", pm).group(1))
    assert not re.search(r"@media[^{]*\{[^}]*\.pm-svg \{[^}]*min-width", pm), "no narrower minimum on small screens"
    scale = min_w / 1310
    for sel in (".pm-col", ".pm-node .lbl", ".pm-node .sub", ".pm-note", ".pm-node .tag", ".pm-stop text", ".pm-stop.tone-blocked text", ".pm-x"):
        size = float(re.search(re.escape(sel) + r" \{[^}]*font-size: ([\d.]+)px", pm).group(1))
        assert size * scale >= 11, (sel, size, scale)


# ── No read on page load; unread rules are not "no rule" ──────────────
class _FailingReads(LookupCl):
    """The fixture tenant, but Web DLP answers 429 (rate limited) and
    Endpoint DLP 403: reads that failed, not empty rule lists."""
    FAIL = {"/zia/webDlpRules": ({"error": "rate limited"}, 429), "/zia/endPointDlpRules": ({"error": "forbidden"}, 403)}

    def get(self, ep, p=None):
        if ep in self.FAIL:
            self.reads += 1
            return self.FAIL[ep]
        return super().get(ep, p)


def test_a_link_fills_the_form_in_but_never_starts_a_tenant_read():
    """?d=<host>&run=1 may pre-fill the destination; the analysis (and with
    it the tenant read) starts only from the Analyze button or Enter."""
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html = open(os.path.join(root, "static", "report_path.html"), encoding="utf-8").read()
    script = html[html.rindex("<script"):]
    starters = [ln.strip() for ln in script.splitlines()
                if re.search(r"\brun\(\)|\(run\)|, run\)", ln) and "async function run" not in ln]
    assert starters and all("addEventListener('click', run)" in ln or "e.key === 'Enter'" in ln for ln in starters), starters
    assert "q.get('run')" in script and "paDest').value = q.get('d')" in script


def test_rules_that_could_not_be_read_are_never_reported_as_no_rule():
    """A 429 on the Web DLP rules and a 403 on the Endpoint DLP rules give
    'could not read' (status 'unknown') on the hop, the channel and the
    verdict, never 'no enabled rule', and no mitigation tells the user to
    deploy a rule that may already exist. A reused read keeps the answer."""
    c = _FailingReads(ROUTES, CATALOGUE)
    r = _analyze(c, "chat.openai.com", "off", "windows")
    v, t = r["verdict"], r["trace"]
    assert v["outcome"] == "unknown" and "could not be read" in v["headline"] and "no DLP rule" not in v["headline"]
    dlp = _pm_hop(r, "dlp")
    assert dlp["status"] == "unknown" and "HTTP 429" in dlp["detail"] and "no enabled" not in dlp["detail"]
    assert _pm_hop(r, "incident")["status"] == "unknown"
    ep = t["channels"]["endpoint"]
    assert ep["status"] == "unknown" and "HTTP 403" in ep["detail"] and "No enabled" not in ep["detail"]
    assert t["channels"]["email"]["status"] == "none", "a read that worked still says none"
    assert any(i["status"] == "unknown" and i["hop"] == "dlp" for i in v["impacts"])
    assert not any(m["action"].startswith("Deploy a Web DLP rule") for m in v["mitigations"])
    again = _analyze(c, "chat.openai.com", "off", "windows", snapshot=r["snapshot_for_cache"])
    assert again["verdict"]["outcome"] == "unknown" and again["trace"]["channels"]["endpoint"]["status"] == "unknown"
    # Encrypted traffic with unread rules: still blind, but it does not claim "no rule applies".
    b = _analyze(c, "mail.example.com", "off", "windows")
    assert b["verdict"]["outcome"] == "blind" and "could not be read" in _pm_hop(b, "dlp")["detail"]
    assert b["verdict"]["mitigations"][0]["action"] == "Read the Endpoint DLP rules again"
    # The same tenant with every read answering is unchanged.
    ok = _analyze(_lookup_client(), "chat.openai.com", "off", "windows")
    assert ok["verdict"]["outcome"] == "enforce" and ok["trace"]["channels"]["endpoint"]["status"] != "unknown"


@_needs_node
def test_the_motion_marks_unread_rules_with_a_question_mark_never_a_break():
    import json
    res = _analyze(_FailingReads(ROUTES, CATALOGUE), "chat.openai.com", "off", "windows")
    res.pop("snapshot_for_cache", None)
    res = json.loads(json.dumps(res, default=str))
    out = _pm_run("const w=H.load(PM),c=w.container(),m=w.ctx.renderPathMotion(c);const mo=m.update(D);"
                  "const stops=c.querySelectorAll('.pm-stop').map(g=>({cls:g.getAttribute('class'),mark:g.querySelectorAll('text')[0].textContent}));"
                  "const e=k=>c.querySelectorAll('.pm-edge').find(p=>p.dataset.edge===k).getAttribute('class');"
                  "process.stdout.write(JSON.stringify({stops:mo.stops,marks:stops,web:e('engine>r_web'),ep:e('engine>r_ep'),summary:mo.summary,"
                  "legend:c.querySelectorAll('.pm-legend')[0].textContent}));", res)
    by = {s["edge"]: s for s in out["stops"]}
    assert by["engine>r_web"]["tone"] == "unread" and "Could not be read" in by["engine>r_web"]["reason"]
    assert by["engine>r_ep"]["tone"] == "unread" and "could not be read" in by["engine>r_ep"]["reason"]
    assert "is-unread" in out["web"] and "is-broken" not in out["web"] and "is-unread" in out["ep"]
    unread_marks = [m for m in out["marks"] if "tone-unread" in m["cls"]]
    assert len(unread_marks) == 2 and all(m["mark"] == "?" for m in unread_marks)
    assert not any("no enabled" in s.lower() for s in out["summary"] if s.startswith(("Inline web", "Endpoint DLP")))
    assert "rules that could not be read" in out["legend"]


@_needs_node
def test_a_cloud_app_control_upload_block_gets_its_policy_mark_whatever_the_dlp_outcome():
    """ChatGPT: Cloud App Control 'AI no upload' blocks uploads before DLP.
    With DLP enforcing and with no DLP rule at all, the chain shows a ■ on
    the way in and the text alternative names the rule."""
    enforce = _pm_result("chat.openai.com", "windows")
    none = _pm_result("chat.openai.com", "windows")
    none["verdict"]["outcome"] = "none"
    out = _pm_run("const w=H.load(PM);const r={};for(const k of Object.keys(D)){const m=w.ctx.pmModel(D[k]);r[k]={stops:m.stops,summary:m.summary};}"
                  "process.stdout.write(JSON.stringify(r));", {"enforce": enforce, "none": none})
    for k in ("enforce", "none"):
        blocks = [s for s in out[k]["stops"] if s["tone"] == "blocked"]
        assert len(blocks) == 1 and blocks[0]["edge"] == "cap_web>dict" and "AI no upload" in blocks[0]["reason"], (k, out[k]["stops"])
        assert any(s.startswith("On the way: Cloud App Control 'AI no upload' blocks") for s in out[k]["summary"]), k


@_needs_node
def test_bits_at_a_policy_block_pop_in_the_block_tone_and_amber_is_explained():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    css = open(os.path.join(root, "static", "reports.css"), encoding="utf-8").read()
    assert ".pm-bit.pop.tone-blocked { fill: var(--text); }" in css and ".pm-legend i.lane-assumed { background: var(--warn); }" in css
    res = _pm_result("casino.example", "windows")
    for ch in res["trace"]["channels"].values():   # only the URL filtering block stops bits here
        ch["status"] = "enforce"
    out = _pm_run("const w=H.load(PM),c=w.container(),m=w.ctx.renderPathMotion(c);m.update(D);w.frames(400);"
                  "process.stdout.write(JSON.stringify({bits:c.querySelectorAll('circle').map(b=>b.getAttribute('class')||''),"
                  "legend:c.querySelectorAll('.pm-legend')[0].textContent}));", res)
    pops = [b for b in out["bits"] if "pop" in b]
    assert pops and all("tone-blocked" in b for b in pops), out["bits"]
    assert "assumed, not confirmed" in out["legend"]

