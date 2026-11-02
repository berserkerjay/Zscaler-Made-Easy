"""Live motion for the Path analyzer and Test a list (static/flow_anim.js:
trafficPathModel, trafficPath, listFlowModel, listFlow; bulk_test's tally;
pack_jobs' progress on the job poll).

The models are fed the Path analyzer's own results, produced by the real
evaluation over the fake tenants the other path tests use (no tenant, no
network), and run under node. The players run in the small offline DOM of
tests/path_motion_dom.js, whose animation frames the test drives by hand,
so nothing here sleeps or depends on a clock. The real-browser check is
tests/test_path_live_motion_browser.py.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess

import pytest

import bulk_test as bt
import pack_jobs
from test_path_zia_modules import run as zia_run
from test_path_zpa_workloads import api, zpa_data, Sdk, CHANNELS  # noqa: F401 - `api` is a fixture

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")
ZIA_ORDER = ["zte", "atp", "firewall", "dns", "cac", "url", "ssl", "sandbox", "ftc", "dlp", "fwdctl"]


def _model(res):
    """FA.trafficPathModel(res) under node."""
    script = ("const FA=require(%s);const D=JSON.parse(require('fs').readFileSync(0,'utf8'));"
              "process.stdout.write(JSON.stringify(FA.trafficPathModel(D)));") % json.dumps(os.path.join(ROOT, "static", "flow_anim.js"))
    r = subprocess.run([NODE, "-e", script], input=json.dumps(res, default=str), capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _keys(m):
    return [n["key"] for n in m["nodes"]]


def _node(m, key):
    return next(n for n in m["nodes"] if n["key"] == key)


# ── The model: shape and order of the hops ──────────────────────────
@needs_node
def test_a_device_path_walks_client_connector_zpa_pac_the_exchange_and_every_zia_module_in_order():
    """CWE-684 · WCAG 2.2 SC 1.3.2: device traffic reaches the destination through every step in the analyzer's documented order."""
    # Act
    m = _model(zia_run("chat.openai.com"))
    # Assert
    assert _keys(m) == ["device", "zcc", "zpa", "pac"] + ZIA_ORDER + ["dest"]
    assert m["mode"] == "result" and m["stop"] == -1 and m["traffic"] == "TCP/443 (HTTPS (web))"
    assert _node(m, "zpa")["verdict"] == "out_of_scope" and _node(m, "zpa")["tone"] == "na"
    assert _node(m, "firewall")["rule"] == "Allow web" and _node(m, "firewall")["tone"] == "pass"
    assert all(n["anchor"]["module"] == n["key"] for n in m["nodes"] if n["key"] in ZIA_ORDER[1:])


@needs_node
def test_traffic_zpa_carries_turns_to_the_app_connectors_and_the_app_and_never_meets_zia(api):
    """CWE-684 · ASVS V1.4.4: when ZPA carries the destination the path turns at ZPA to the App Connectors and the private app; no ZIA step is drawn."""
    # Arrange
    api["post"](destination="git.corp.example", scopes=["zpa", "dlp", "zcc"], channels=CHANNELS)
    # Act
    m = _model(api["result"]())
    # Assert
    assert _keys(m) == ["device", "zcc", "zpa", "zpa_connectors", "dest"]
    zpa = _node(m, "zpa")
    assert zpa["verdict"] == "carried" and zpa["rule"] == "Allow corp" and zpa["fork"] == {"text": "ZIA path not taken", "ghost": True}
    assert zpa["anchor"]["module"] == "zpa_access"
    assert [n["lane"] for n in m["nodes"][3:]] == ["zpa", "zpa"] and m["nodes"][-1]["label"] == "Private app"
    assert m["stop"] == -1 and not set(ZIA_ORDER) & set(_keys(m))


@needs_node
def test_traffic_zpa_denies_stops_at_zpa_with_a_block_marker(api):
    """CWE-684 · ASVS V1.4.4: ZPA's access policy denying the destination is the stop, marked block; nothing after it is reached."""
    # Arrange
    api["sdk"] = Sdk(zdata=zpa_data(access=[]))
    api["post"](destination="git.corp.example", scopes=["zpa"])
    # Act
    m = _model(api["result"]())
    # Assert
    assert m["stop"] == _keys(m).index("zpa") and _node(m, "zpa")["mark"] == "block"
    assert m["nodes"][-1]["tone"] == "after" and m["verdict"]["tone"] == "bad"


@needs_node
def test_workload_traffic_goes_through_its_connector_and_skips_client_connector_and_the_pac_file(api):
    """CWE-684 · ASVS V1.4.4: a workload starts at the Cloud or Branch Connector and goes to the Zero Trust Exchange; no Client Connector or PAC step."""
    # Arrange
    api["post"](destination="https://casino.example/x", source="workload", workload={"ip": "10.7.0.1", "tags": "Env=qa", "connector_group": "AWS-US"},
                scopes=["ztw", "dlp", "zcc", "zia_extras"], channels=CHANNELS)
    # Act
    m = _model(api["result"]())
    # Assert
    assert _keys(m)[:3] == ["workload", "connector", "zte"] and _keys(m)[-1] == "dest"
    assert "zcc" not in _keys(m) and "pac" not in _keys(m) and m["source"] == "workload"
    assert _node(m, "connector")["verdict"] == "forwarded" and _node(m, "connector")["anchor"]["module"] == "connector_forwarding"


@needs_node
def test_a_workload_sent_direct_stops_at_the_connector_with_a_bypass_marker(api):
    """CWE-684 · ASVS V1.4.4: a Direct forwarding rule is a bypass at the connector; the destination is reached around Zscaler, not inspected."""
    # Arrange
    api["post"](destination="example.com", source="workload", workload={"tags": "Env=dev"}, scopes=["ztw", "dlp"], channels=CHANNELS)
    # Act
    m = _model(api["result"]())
    # Assert
    assert _keys(m) == ["workload", "connector", "dest"] and m["stop"] == 1
    assert _node(m, "connector")["mark"] == "bypass" and _node(m, "connector")["rule"] == "Dev direct"
    assert m["nodes"][-1]["tone"] == "warn" and "around Zscaler" in m["nodes"][-1]["word"]


@needs_node
def test_a_workload_forwarded_to_zpa_turns_at_zpa(api):
    """CWE-684 · ASVS V1.4.4: a ZPA forwarding rule hands the workload to ZPA, which carries it to the App Connectors and the app."""
    # Arrange
    api["post"](destination="git.corp.example", source="workload", workload={"tags": "VPC:Vpc-id=vpc-1, Env=prod"}, scopes=["ztw", "zpa"])
    # Act
    m = _model(api["result"]())
    # Assert
    assert _keys(m) == ["workload", "connector", "zpa", "zpa_connectors", "dest"] and _node(m, "zpa")["verdict"] == "carried"


@needs_node
def test_a_pac_file_returning_direct_is_a_bypass_marker_and_greys_the_exchange():
    """CWE-684 · ASVS V1.4.4: a PAC DIRECT answer stops the path at the PAC file with a bypass marker; every ZIA step after it is not reached."""
    # Act
    m = _model(zia_run("app.box.com", network="off", platform="macos"))
    # Assert
    stop = _keys(m).index("pac")
    assert m["stop"] == stop and _node(m, "pac")["mark"] == "bypass" and _node(m, "pac")["verdict"] == "bypassed"
    assert all(n["tone"] == "after" and n["word"] == "not reached" for n in m["nodes"][stop + 1:-1])
    assert m["nodes"][-1]["tone"] == "warn" and "not inspected" in m["nodes"][-1]["word"]
    assert _node(m, "zcc")["fork"] is None, "a weak point is not a conditional fork"


@needs_node
def test_traffic_blocked_at_the_cloud_firewall_stops_there_and_never_reaches_the_rest():
    """CWE-684 · ASVS V1.4.4: UDP/443 is blocked by the Cloud Firewall rule; the packet stops there with a block marker and the protocol labels the flow."""
    # Act
    m = _model(zia_run("chat.openai.com", "udp", 443))
    # Assert
    stop = _keys(m).index("firewall")
    assert m["stop"] == stop and _node(m, "firewall")["mark"] == "block" and _node(m, "firewall")["rule"] == "Block QUIC"
    assert all(n["tone"] == "after" for n in m["nodes"][stop + 1:]) and m["nodes"][-1]["word"] == "never reached"
    assert m["traffic"].startswith("UDP/443") and m["verdict"]["tone"] == "bad"


@needs_node
def test_a_conditional_module_shows_a_dashed_fork_and_does_not_stop_the_packet():
    """CWE-684 · ASVS V1.4.4: a block that depends on an unevaluated time window is a fork ("may block"), not a stop; the end stays open."""
    # Act
    m = _model(zia_run("203.0.113.10", "tcp", 3389))
    # Assert
    fw = _node(m, "firewall")
    assert m["stop"] == -1 and fw["mark"] is None and fw["fork"] == {"text": "may block"} and fw["tone"] == "warn"
    assert m["nodes"][-1]["tone"] == "warn"


@needs_node
@pytest.mark.parametrize("verdict,mark", [("isolate", "isolate"), ("caution", "caution")])
def test_an_isolate_or_caution_decision_is_where_the_packet_stops(verdict, mark):
    """CWE-684 · WCAG 2.2 SC 1.4.1: a definite isolate or caution decision is the stop, with its own marker word, not only a colour."""
    # Arrange
    res = copy.deepcopy(zia_run("chat.openai.com"))
    url = next(x for x in res["zia_modules"]["modules"] if x["key"] == "url")
    url.update(verdict=verdict, certainty="definite", rule={"name": "Watch this", "order": 1})
    # Act
    m = _model(res)
    # Assert
    assert m["stop"] == _keys(m).index("url") and _node(m, "url")["mark"] == mark
    assert f"{ {'isolate': 'isolated', 'caution': 'caution'}[verdict]} here" in m["summary"][_keys(m).index("url") + 1]


@needs_node
def test_the_what_if_identity_and_the_conditions_label_the_flow(api):
    """WCAG 2.2 SC 1.1.1 · CWE-684: the identity evaluated in the what-if and the protocol and port name the flow and its text alternative."""
    # Arrange
    api["post"](destination="https://casino.example/x", network="off", platform="macos", protocol="tcp", port=443,
                identity={"user": "jane@acme.example"}, scopes=["zpa", "dlp", "zcc", "zia_extras"], channels=CHANNELS)
    # Act
    m = _model(api["result"]())
    # Assert
    assert m["identity"].startswith("user jane@acme.example") and m["traffic"].startswith("TCP/443")
    assert "(what-if)" in m["summary"][0] and m["whatif"]["identity"] == m["identity"]
    assert _keys(m)[:4] == ["device", "zcc", "zpa", "pac"] and _node(m, "zpa")["verdict"] == "not_matched"


@needs_node
def test_before_any_result_the_reference_path_idles():
    """WCAG 2.2 SC 1.1.1: with no result the reference path is drawn, every step idle, and described in words."""
    # Act
    m = _model(None)
    # Assert
    assert m["mode"] == "reference" and m["stop"] == -1 and len(m["nodes"]) == 16
    assert _keys(m)[:5] == ["device", "zcc", "zpa", "pac", "zte"] and m["nodes"][-1]["key"] == "dest"
    assert all(n["tone"] == "idle" for n in m["nodes"]) and "reference path" in m["summary"][0]


@needs_node
def test_every_step_is_in_the_text_alternative_in_order():
    """WCAG 2.2 SC 1.1.1 · SC 1.3.2: the summary says every step, numbered in the order the packet meets it, then the verdict."""
    # Act
    m = _model(zia_run("chat.openai.com", "udp", 443))
    # Assert
    lines = m["summary"]
    assert len(lines) >= len(m["nodes"]) + 2
    for i, n in enumerate(m["nodes"]):
        assert lines[i + 1].startswith(f"{i + 1}. {n['label']}: "), lines[i + 1]
    assert lines[len(m["nodes"]) + 1].startswith("Verdict: ")


# ── Test a list: the tally on the job poll ──────────────────────────
def test_the_bulk_tally_streams_counts_and_ends_as_the_summary_flow():
    """ASVS V8.3.4 · CWE-200: each progress tally counts rows per result and deciding area only; the last one is the result's flow."""
    # Arrange
    from test_bulk_test import Sleeps, Tenant, FULL
    seen = []
    text = "\n".join(["casino.example", "tv.example", "news.example", "example.com", "mail.example.com"] * 30)
    # Act
    rn = bt.run(Tenant(), bt.parse(text), scope=FULL, sleep=Sleeps(), progress=seen.append)
    # Assert
    flow = rn.summary["flow"]
    assert seen[0]["phase"] == "lookup" and seen[-1] == flow and flow["phase"] == "done"
    assert flow["done"] == flow["total"] == 150 and sum(flow["results"].values()) == 150
    assert sum(sum(v.values()) for v in flow["at"].values()) == 150
    dones = [t["done"] for t in seen]
    assert dones == sorted(dones) and len(seen) <= bt.FLOW_EVERY + 3
    assert flow["results"] == {k: v for k, v in rn.summary["counts"].items() if k in bt.RESULTS and v}
    blob = json.dumps(seen)
    assert "casino" not in blob and "example" not in blob, "counts only: no destination in the tally"


def test_the_job_poll_carries_the_runs_latest_progress():
    """ASVS V8.3.4 · CWE-200: a job's snapshot carries what its run last reported with progress(), and only inside a job."""
    # Arrange
    assert pack_jobs.progress({"done": 1}) is False   # no job on this thread: nothing to set

    def fn(log, cancel):
        pack_jobs.progress({"done": 2, "total": 4})
        pack_jobs.progress({"done": 4, "total": 4})
        return {"status": "done"}
    # Act
    job = pack_jobs.start("bulk-test", fn, label="tally test")
    job.thread.join(timeout=10)
    snap = pack_jobs.snapshot(job)
    # Assert
    assert snap["progress"] == {"done": 4, "total": 4} and snap["status"] == "done"


@needs_node
def test_the_list_flow_model_places_rows_at_the_step_that_decided_them_and_ignores_junk():
    """CWE-20 · CWE-684: rows land at Client Connector, ZPA, a ZIA module, the destination or unverified; bad counts read as zero."""
    # Arrange
    tally = {"done": 9, "total": 12, "phase": "trace", "results": {"blocked": 4, "allowed": 3, "bypassed": 1, "unverified": 1},
             "at": {"url": {"blocked": 3, "allowed": 2}, "firewall": {"blocked": 1}, "client_connector": {"bypassed": 1},
                    "zpa": {"allowed": 1, "blocked": "9"}, "none": {"unverified": 1, "blocked": -5}}}
    script = ("const FA=require(%s);process.stdout.write(JSON.stringify(FA.listFlowModel(%s)));") % (json.dumps(os.path.join(ROOT, "static", "flow_anim.js")), json.dumps(tally))
    # Act
    r = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    m = json.loads(r.stdout)
    # Assert
    by = {b["key"]: b["n"] for b in m["boxes"]}
    assert by == {"client_connector": 1, "zpa": 1, "atp": 0, "firewall": 1, "dns": 0, "cloud_app": 0, "url": 3, "dest": 2, "unverified": 1}
    assert m["totals"]["blocked"] == 4 and m["totals"]["zpa"] == 1 and (m["done"], m["total"]) == (9, 12)


# ── The players, in an offline DOM driven frame by frame ────────────
def _dom(body, reduce=False):
    """Run `body` with FA loaded in tests/path_motion_dom.js; it returns JSON."""
    pre = ("const H=require('./tests/path_motion_dom.js');const w=H.load('./static/flow_anim.js',{reduce:%s});const FA=w.ctx.FA,host=w.container();"
           "const settle=async n=>{for(let i=0;i<n;i++){w.frames(1);await Promise.resolve();await Promise.resolve();}};") % ("true" if reduce else "false")
    script = pre + "(async()=>{const out=await (async()=>{" + body + "})();process.stdout.write(JSON.stringify(out));})().catch(e=>{console.error(e);process.exit(1)});"
    r = subprocess.run([NODE, "-e", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


SAMPLE_PLAY = ("const p=FA.trafficPath(host,FA.trafficPathModel(FA.SAMPLE.traffic),{loop:true,onSelect(n){sel.push(n.key)}});")


@needs_node
def test_packets_travel_the_path_and_stop_at_the_deciding_step():
    """WCAG 2.2 SC 2.2.2: with motion allowed, frames advance, each box lights with its verdict as the packet lands, and it ends at the stop."""
    out = _dom("const sel=[];" + SAMPLE_PLAY + "await settle(600);"
               "const tags=host.querySelectorAll('.tp-tag');"
               "return {frames:+host.getAttribute('data-tp-frames'),pos:p.pos(),playing:p.playing(),btn:host.querySelector('.tp-play').textContent,"
               "url:host.querySelectorAll('.fa-box')[9].getAttribute('class'),tag:tags.map(t=>t.getAttribute('display')+':'+t.textContent),"
               "pkts:host.querySelectorAll('.tp-pkt').length};")
    assert out["frames"] > 100 and out["pos"] == 9 and out["playing"] is True and out["btn"] == "Pause motion"
    assert "stop" in out["url"] and out["tag"] == ["inline:■ blocked"]
    assert out["pkts"] >= 1, "the live stream keeps packets flowing to the stop"


@needs_node
def test_reduced_motion_draws_the_final_picture_without_frames_and_offers_play():
    """WCAG 2.2 SC 2.3.3 · SC 2.2.2: with reduced motion nothing moves: no frame is requested, the final state is drawn, and Play motion starts it on request."""
    out = _dom("const sel=[];" + SAMPLE_PLAY + "const before=w.pending();await settle(50);"
               "const still={pending:before,frames:host.getAttribute('data-tp-frames'),pos:p.pos(),btn:host.querySelector('.tp-play').textContent,"
               "note:host.querySelector('.tp-note').textContent,tag:host.querySelectorAll('.tp-tag')[0].getAttribute('display')};"
               "host.querySelector('.tp-play').click();await settle(30);"
               "return Object.assign(still,{after:+host.getAttribute('data-tp-frames')});", reduce=True)
    assert out["pending"] == 0 and out["frames"] is None and out["pos"] == 9 and out["tag"] == "inline"
    assert out["btn"] == "Play motion" and out["note"].startswith("Motion is off because your system asks for reduced motion")
    assert out["after"] > 0, "Play motion starts it anyway"


@needs_node
def test_motion_stops_while_the_tab_is_hidden_and_resumes_when_shown():
    """WCAG 2.2 SC 2.2.2: a hidden tab requests no animation frame; showing it again resumes the motion."""
    out = _dom("const sel=[];" + SAMPLE_PLAY + "await settle(20);w.setHidden(true);await settle(5);const hidden=w.pending();"
               "w.setHidden(false);const shown=w.pending();return {hidden,shown};")
    assert out["hidden"] == 0 and out["shown"] >= 1


@needs_node
def test_a_box_opens_its_card_on_click_and_on_enter_and_is_a_labelled_button():
    """WCAG 2.2 SC 2.1.1 · SC 4.1.2: every step is a focusable button with a name; click, Enter and Space open its card."""
    out = _dom("const sel=[];" + SAMPLE_PLAY + "const b=host.querySelectorAll('.fa-box');"
               "b[6].dispatch('click');(b[9].listeners.keydown||[]).forEach(f=>f({key:'Enter',preventDefault(){}}));(b[3].listeners.keydown||[]).forEach(f=>f({key:' ',preventDefault(){}}));"
               "return {sel,role:b[9].getAttribute('role'),tab:b[9].getAttribute('tabindex'),label:b[9].getAttribute('aria-label')};")
    assert out["sel"] == ["firewall", "url", "pac"] and out["role"] == "button" and out["tab"] == "0"
    assert out["label"].startswith("10. URL filtering: blocks it, rule Block file sharing, blocked here")


@needs_node
def test_the_stepper_goes_back_and_forward_one_step_at_a_time():
    """WCAG 2.2 SC 2.2.2 · SC 2.1.1: the replay steps back and forward, pauses the motion, and says each step in words."""
    out = _dom("const p=FA.trafficPath(host,FA.trafficPathModel(FA.SAMPLE.traffic),{stepper:true});await settle(5);"
               "host.querySelector('.tp-back').click();const a=p.pos();host.querySelector('.tp-next').click();host.querySelector('.tp-next').click();const b=p.pos();"
               "return {a,b,playing:p.playing(),note:host.querySelector('.tp-note').textContent,speed:host.querySelectorAll('option').length};")
    assert out["a"] == 0 and out["b"] == 2 and out["playing"] is False
    assert out["note"].startswith("Step 3 of 15: ZPA") and out["speed"] == 3


@needs_node
def test_tenant_strings_are_text_never_markup():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: rule names, the destination and the identity from a result are drawn as text, never parsed as markup."""
    out = _dom("const r=JSON.parse(JSON.stringify(FA.SAMPLE.traffic));const x='<img src=x onerror=alert(1)>';"
               "r.destination.host=x;r.whatif.identity_label='<script>alert(1)</script>';r.zia_modules.modules[4].rule.name=x;r.verdict.headline=x;"
               "FA.trafficPath(host,FA.trafficPathModel(r),{loop:true,onSelect(){}});"
               "return {img:host.querySelectorAll('img').length,script:host.querySelectorAll('script').length,text:host.textContent.includes('<img src=x')};")
    assert out == {"img": 0, "script": 0, "text": True}


@needs_node
def test_destroy_stops_the_clock_and_clears_the_picture():
    """WCAG 2.2 SC 2.2.2: a replaced result leaves no animation running on a detached picture."""
    out = _dom("const sel=[];" + SAMPLE_PLAY + "await settle(10);p.destroy();await settle(3);return {pending:w.pending(),html:host.innerHTML};")
    assert out == {"pending": 0, "html": ""}


@needs_node
def test_the_list_flow_climbs_with_each_tally_and_lands_at_once_with_reduced_motion():
    """WCAG 2.2 SC 2.2.2 · SC 1.1.1: counts animate up as tallies arrive (packets fly), say where rows were decided in words, and jump straight there with reduced motion."""
    body = ("const lf=FA.listFlow(host);lf.update({done:5,total:10,phase:'trace',results:{blocked:2,allowed:3},at:{url:{blocked:2,allowed:3}}});"
            "await settle(80);lf.update({done:10,total:10,phase:'done',results:{blocked:4,allowed:5,bypassed:1},at:{url:{blocked:4,allowed:5},client_connector:{bypassed:1}}});"
            "await settle(80);return {frames:+(host.getAttribute('data-lf-frames')||0),tot:host.querySelector('.lf-tot').textContent,"
            "alt:host.querySelector('.lf-alt').textContent,svg:host.querySelectorAll('svg')[0].getAttribute('role')};")
    moving, calm = _dom(body), _dom(body, reduce=True)
    for out in (moving, calm):
        assert out["tot"] == "4 blocked · 5 allowed · 1 bypassed · 0 ZPA" and out["svg"] == "img"
        assert "10 of 10 row(s) tested" in out["alt"] and "URL filtering: 4 row(s): 4 blocked" in out["alt"]
    assert moving["frames"] > 20 and calm["frames"] == 0
