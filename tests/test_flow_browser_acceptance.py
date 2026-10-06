"""Opt-in real-Chrome acceptance of the production UI against offline fixtures.

Run with DLP_RUN_BROWSER_ACCEPTANCE=1 and Node 22 + official Chrome installed.
When explicitly enabled, missing tools or launch failures FAIL (never skip).
No browser is launched during normal unit tests or test collection.
"""
from __future__ import annotations

import json
import ipaddress
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tests/js/flow_browser_acceptance.mjs"
EXPECTED_CASE_IDS = ['BROWSER-FLOW-01-production-workspace-is-interactive', 'BROWSER-FLOW-02-shared-synthetic-input-runs-real-endpoint', 'BROWSER-FLOW-03-guided-next-and-play-use-production-svg', 'BROWSER-FLOW-04-observed-fixture-and-demo-counters-are-isolated', 'BROWSER-FLOW-05-configuration-only-is-not-simulated', 'BROWSER-FLOW-06-mobile-inputs-and-no-horizontal-page-overflow', 'BROWSER-FLOW-07-normal-motion-packets-move-and-restart-clears', 'BROWSER-EMBED-01-parent-production-reference-loads', 'BROWSER-EMBED-02-failed-frame-shows-real-retry-control', 'BROWSER-EMBED-03-retry-loads-real-child-under-production-csp', 'BROWSER-EMBED-04-nested-portfolio-tab-navigation-works', 'BROWSER-EMBED-05-copilot-child-loads-and-inner-tabs-work', 'BROWSER-EMBED-06-switching-parent-tabs-retains-ready-frames', 'BROWSER-DSA-01-all-44-production-players-have-complete-controls', 'BROWSER-DSA-02-guided-demo-waits-for-next', 'BROWSER-DSA-03-play-pause-resume-and-restart-are-real', 'BROWSER-DSA-04-play-all-reaches-terminal-state', 'BROWSER-DSA-05-only-one-player-runs-and-reduced-motion-is-honored', 'BROWSER-SAFETY-01-no-runtime-csp-errors-tenant-writes-or-external-requests']
# Keep the original 19 release-gate cases intact; scope coverage is additive.
LEGACY_CASE_IDS = EXPECTED_CASE_IDS[:]
SCOPE_CASE_IDS = [
    "BROWSER-SCOPE-01-production-scope-navigation-is-read-free",
    "BROWSER-SCOPE-02-gap-prerequisite-is-explained-not-selected",
    "BROWSER-SCOPE-03-alternative-prerequisite-stays-excluded",
    "BROWSER-SCOPE-04-dependent-toggle-clears-and-restores-notes",
    "BROWSER-SCOPE-05-profile-save-keeps-explicit-gap-declaration",
    "BROWSER-SCOPE-06-assessment-hides-rows-and-keeps-prerequisite",
    "BROWSER-SCOPE-07-json-download-matches-visible-totals",
    "BROWSER-SCOPE-08-profile-update-and-reload-preserve-alternative",
    "BROWSER-SCOPE-09-blocked-assessment-never-reads-excluded-ssl",
    "BROWSER-SCOPE-10-excluded-ssl-keeps-unified-path-controls",
]
# The existing safety case remains the final gate and covers all new pages too.
EXPECTED_CASE_IDS = LEGACY_CASE_IDS[:-1] + SCOPE_CASE_IDS + LEGACY_CASE_IDS[-1:]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _chrome():
    configured = os.environ.get("CHROME_BIN")
    if configured and Path(configured).is_file():
        return configured
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    for path in ("/opt/google/chrome/chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                 str(Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe"),
                 str(Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Google/Chrome/Application/chrome.exe")):
        if Path(path).is_file():
            return path
    return None


def _install_loopback_guard(state):
    """Block DNS and TCP egress before importing any production modules."""
    original_dns = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def check(host, operation):
        if host is None:
            return
        if isinstance(host, bytes):
            host = host.decode("ascii", errors="replace")
        allowed = str(host).lower() == "localhost"
        try:
            allowed = allowed or ipaddress.ip_address(str(host).split("%", 1)[0]).is_loopback
        except ValueError:
            pass
        if not allowed:
            state["external_connections"].append({"operation": operation, "host": str(host)})
            raise RuntimeError("External networking is disabled in browser acceptance fixtures")

    def dns(host, *args, **kwargs):
        check(host, "getaddrinfo")
        return original_dns(host, *args, **kwargs)

    def connect(sock, address):
        if isinstance(address, tuple):
            check(address[0], "connect")
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if isinstance(address, tuple):
            check(address[0], "connect_ex")
        return original_connect_ex(sock, address)

    socket.getaddrinfo = dns
    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex


def _install_fixtures(srv, state=None):
    """Replace only external dependency boundaries; all routes/UI are production."""
    import copy
    from datetime import datetime, timezone
    from types import SimpleNamespace
    import tenant_auth

    state = state if state is not None else {"reads": [], "lookups": 0, "live_polls": 0, "writes": 0, "external_connections": []}
    state.setdefault("auth_calls", 0)
    state.setdefault("closed_clients", 0)
    state.setdefault("update_lookups", [])
    state["assessment_registry_count"] = len(srv._get_checks(scopes=["dlp"]))
    dictionary = {"id": 101, "name": "Synthetic test marker", "custom": True,
                  "phrases": [{"phrase": "SYNTHETIC-FLOW-MARKER"}], "patterns": []}
    engine = {"id": 201, "name": "Synthetic marker engine", "engineExpression": "D101.S > 0", "customDlpEngine": True}
    rule = {"id": 301, "name": "Synthetic monitor", "state": "ENABLED", "action": "ALLOW", "order": 1,
            "dlpEngines": [{"id": 201, "name": "Synthetic marker engine"}], "zscalerIncidentReceiver": True}
    routes = {
        "/zia/dlpDictionaries": [dictionary], "/zia/dlpDictionaries/101": dictionary,
        "/zia/dlpEngines": [engine], "/zia/dlpEngines/201": engine,
        "/zia/webDlpRules": [rule], "/zia/endPointDlpRules": [rule],
        "/zia/emailDlpRules": [rule], "/zia/casbDlpRules/all": [rule],
        "/zia/urlFilteringRules": [{"id": 11, "name": "Fixture URL allow", "state": "ENABLED", "action": "ALLOW", "order": 1}],
        "/zia/sslInspectionRules": [{"id": 12, "name": "Fixture SSL decrypt", "state": "ENABLED", "action": {"type": "DECRYPT"}, "order": 1}],
        "/zia/fileTypeRules": [], "/zia/fileTypeControlRules": [], "/zia/urlCategories": [],
        "/zia/cloudApplicationRules": [],
    }

    class Client:
        stop_check = None
        requests_made = 0

        def auth(self):
            state["auth_calls"] += 1
            return True

        def close(self):
            state["closed_clients"] += 1

        def get(self, endpoint, params=None):
            if self.stop_check and self.stop_check():
                import data_flow
                raise data_flow.ReadStopped("Fixture read cancelled")
            state["reads"].append(endpoint)
            self.requests_made += 1
            return (copy.deepcopy(routes[endpoint]), 200) if endpoint in routes else ({"error": "fixture endpoint unavailable"}, 404)

        def post(self, endpoint, payload=None):
            if endpoint == "/zia/urlLookup":
                state["lookups"] += 1
                return [{"urlClassifications": ["OTHER_MISCELLANEOUS"]}], 200
            state["writes"] += 1
            raise AssertionError("A browser acceptance test attempted an unsupported write")

    class Incidents:
        def dlp_incident_search(self, **kwargs):
            state["live_polls"] += 1
            if (kwargs.get("query_params") or {}).get("page", 1) != 1:
                return [], None, None
            incident = {"internalId": "synthetic-live-event-1", "sourceType": "WEB", "status": "OPEN",
                        "createdAt": datetime.now(timezone.utc).isoformat(),
                        "applicationInfo": {"url": "https://example.test/upload"},
                        "matchingPolicies": {"rules": [{"name": "Synthetic monitor"}],
                                             "engines": [{"name": "Synthetic marker engine"}],
                                             "dictionaries": [{"name": "Synthetic test marker", "matchCount": 1}]}}
            return [incident], None, None

    # No real profile/environment secret can enter this fixture process.
    creds = {key: "" for key in tenant_auth.CRED_KEYS}
    creds.update(auth_method="oneapi", cloud="zscaler", vanity_domain="browser-fixture", client_id="synthetic-client",
                 client_secret="synthetic-browser-fixture-secret")
    # Root-page health checks normally discover the remote Git tip, including
    # through git subprocesses that socket guards cannot intercept. Replace
    # that external boundary, not the production health endpoint.
    def fixture_remote_tip(branch="main"):
        state["update_lookups"].append(branch)
        return None

    srv._latest_remote_commit = fixture_remote_tip
    srv._tenant_creds = lambda request: dict(creds)
    srv._build_client = lambda request: Client()
    # Assessments retain the real registry, scope partition, execution, SSE,
    # score and report builders. Only tenant auth/HTTP are replaced.
    srv._raw_client = lambda credentials: Client()
    srv._build_sdk_client = lambda credentials: SimpleNamespace(zwa=SimpleNamespace(dlp_incidents=Incidents()))
    srv._live_rule_actions = lambda *args, **kwargs: {"Synthetic monitor": "ALLOW"}
    srv._live_connector_context = lambda *args, **kwargs: {"status": "out_of_scope", "profiles": [], "note": "Synthetic browser fixture; no device telemetry"}

    @srv.app.get("/__browser_test__/state")
    async def fixture_state():
        return state

    return state


def _serve(port):
    state = {"reads": [], "lookups": 0, "live_polls": 0, "writes": 0, "external_connections": []}
    for key in list(os.environ):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"):
            os.environ.pop(key, None)
    _install_loopback_guard(state)
    import dlp_api_server as srv
    import uvicorn
    _install_fixtures(srv, state)
    # Production middleware/routes/static assets; background tenant/crawler jobs
    # are excluded, as they are not under test and must not leave loopback.
    uvicorn.run(srv.app, host="127.0.0.1", port=port, lifespan="off", access_log=False, log_level="warning")


@pytest.mark.skipif(os.environ.get("DLP_RUN_BROWSER_ACCEPTANCE") != "1", reason="Real-browser acceptance runs only when explicitly enabled")
def test_production_flow_reference_browser_acceptance(tmp_path):
    node, chrome = shutil.which("node"), _chrome()
    assert node, "DLP_RUN_BROWSER_ACCEPTANCE=1 requires Node 22+"
    assert chrome, "DLP_RUN_BROWSER_ACCEPTANCE=1 requires official Chrome/Chromium (set CHROME_BIN)"
    version = subprocess.run([node, "-p", "Number(process.versions.node.split('.')[0]) >= 22 && typeof WebSocket === 'function'"], text=True, capture_output=True, check=True)
    assert version.stdout.strip() == "true", "Use Node 22+ with built-in WebSocket"
    artifacts = Path(os.environ.get("BROWSER_ACCEPTANCE_ARTIFACTS", str(tmp_path / "artifacts"))).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("ZSCALER_", "ZIA_", "ZPA_", "ZCC_", "ZDX_"))
                   and key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy")}
    environment.update(ZSCALER_UI_AUTH="0", ENABLE_WRITE_ACTIONS="", DLP_CHECK_CONTINUOUS_EVAL_HOURS="0",
                       DLP_CHECK_PROFILES=str(tmp_path / "profiles.json"), DLP_CHECK_AUDIT=str(tmp_path / "audit.log"),
                       DLP_CHECK_FINGERPRINT_KEY=str(tmp_path / "fingerprint.key"), DLP_CHECK_ZIA_RATE_STATE=str(tmp_path / "rate.json"),
                       DLP_CHECK_UI_TOKEN_DIR=str(tmp_path), PYTHONDONTWRITEBYTECODE="1")
    (tmp_path / "profiles.json").write_text("{}")
    log = (artifacts / "server.log").open("w")
    server = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve", str(port)], cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        ready = False
        for _ in range(100):
            if server.poll() is not None:
                break
            try:
                with urllib.request.urlopen(base + "/__browser_test__/state", timeout=.3) as response:
                    ready = response.status == 200
                if ready:
                    break
            except (OSError, TimeoutError):
                time.sleep(.1)
        assert ready, "Fixture server did not become ready; see server.log"
        completed = subprocess.run([node, str(DRIVER), chrome, base, str(tmp_path / "chrome"), str(artifacts)],
                                   cwd=ROOT, env=environment, text=True, capture_output=True, timeout=165)
        (artifacts / "driver.stdout").write_text(completed.stdout)
        (artifacts / "driver.stderr").write_text(completed.stderr)
        assert completed.returncode == 0, f"Browser acceptance failed: {completed.stderr[-4000:]} (artifacts: {artifacts})"
        result = json.loads((artifacts / "results.json").read_text())
        assert [case["id"] for case in result["cases"]] == EXPECTED_CASE_IDS, result
        assert all(case["passed"] for case in result["cases"]), result
        assert result["fixture_state"]["writes"] == 0 and not result["fixture_state"]["external_connections"]
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        log.close()


@pytest.mark.parametrize("operation", ["getaddrinfo", "connect", "connect_ex"])
def test_fixture_guard_rejects_remote_before_any_delegate(operation, monkeypatch):
    called = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: called.append("dns"))
    monkeypatch.setattr(socket.socket, "connect", lambda *args: called.append("connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", lambda *args: called.append("connect_ex"))
    state = {"external_connections": []}
    _install_loopback_guard(state)
    with pytest.raises(RuntimeError, match="External networking"):
        if operation == "getaddrinfo":
            socket.getaddrinfo("never-resolve.invalid", 443)
        else:
            getattr(socket.socket, operation)(None, ("203.0.113.99", 443))
    assert called == []
    assert state["external_connections"][0]["operation"] == operation


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_fixture_guard_allows_only_stubbed_loopback_delegates(host, monkeypatch):
    called = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: called.append("dns"))
    monkeypatch.setattr(socket.socket, "connect", lambda *args: called.append("connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", lambda *args: called.append("connect_ex"))
    state = {"external_connections": []}
    _install_loopback_guard(state)
    socket.getaddrinfo(host, 12345)
    socket.socket.connect(None, (host, 12345))
    socket.socket.connect_ex(None, (host, 12345))
    assert called == ["dns", "connect", "connect_ex"] and not state["external_connections"]



_HARNESS_HELPER_CASES = {
    "cold-start-beyond-old-ten-second-cutoff": "let t=0;const r=await waitForDebugger({readActivePort:async()=>{if(t<12000)throw Error('not created');return '9222\\n/browser'},readTargets:async()=>[target],hasExited:()=>false,now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(r.port,9222);assert(t>=12000&&t<30000);",
    "port-file-alone-does-not-prove-ready-page": "let t=0;await waitForDebugger({readActivePort:async()=> '9222',readTargets:async()=>t<2000?[]:[target],hasExited:()=>false,now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(t,2000);",
    "partial-port-metadata-is-retried-before-connect": "let t=0,calls=0;await waitForDebugger({readActivePort:async()=>t<300?'not-ready':'9222',readTargets:async()=>{calls++;return[target]},hasExited:()=>false,now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(calls,1);assert.equal(t,300);",
    "transient-cdp-http-startup-is-retried": "let t=0;await waitForDebugger({readActivePort:async()=> '9222',readTargets:async()=>{if(t<500)throw Error('ECONNREFUSED');return[target]},hasExited:()=>false,now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(t,500);",
    "process-exit-is-reported-without-waiting": "await assert.rejects(waitForDebugger({readActivePort:async()=>'',readTargets:async()=>[],hasExited:()=>true,diagnostic:()=> 'exit 9',sleep:async()=>{throw Error('should not sleep')}}),/Chrome exited.*exit 9/);",
    "startup-remains-bounded": "let t=0;await assert.rejects(waitForDebugger({readActivePort:async()=>'',readTargets:async()=>[],hasExited:()=>false,now:()=>t,sleep:async ms=>{t+=ms},timeoutMs:1000}),/within 1000 ms/);assert.equal(t,1000);",
    "debugger-target-must-remain-loopback": "await assert.rejects(waitForDebugger({readActivePort:async()=> '9222',readTargets:async()=>[{type:'page',webSocketDebuggerUrl:'ws://remote.invalid:9222/devtools/page/1'}],hasExited:()=>false,sleep:async()=>{throw Error('should not retry')}}),/expected loopback/);",
    "moving-target-waits-for-stable-layout": "let t=0,n=0;const points=[{ready:true,x:20,y:100},{ready:true,x:40,y:120},{ready:true,x:40,y:120}];const r=await waitForStablePoint(async()=>points[n++],{now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(n,3);assert.equal(r.x,40);",
    "obscured-target-is-not-accepted": "let t=0,n=0;const r=await waitForStablePoint(async()=>({ready:++n>2,x:40,y:120}),{now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(n,4);assert.equal(r.y,120);",
    "disabled-or-hidden-target-fails-bounded": "let t=0;await assert.rejects(waitForStablePoint(async()=>({ready:false,x:40,y:120,disabled:true}),{now:()=>t,sleep:async ms=>{t+=ms},timeoutMs:300}),/never became stable/);assert.equal(t,300);",
    "late-navigation-scroll-reveals-target-and-resamples": "let t=0,n=0,reveals=0;const points=[{ready:true,x:40,y:550},{ready:false,offscreen:true,x:40,y:2418,hidden:false,disabled:false},{ready:true,x:40,y:550},{ready:true,x:40,y:550}];const r=await waitForStablePoint(async()=>points[n++],{now:()=>t,sleep:async ms=>{t+=ms},reveal:async()=>{reveals++}});assert.equal(reveals,1);assert.equal(n,4);assert.equal(r.y,550);",
    "offscreen-target-recovery-never-bypasses-overlay": "let t=0,reveals=0;await assert.rejects(waitForStablePoint(async()=>reveals?{ready:false,offscreen:false,x:40,y:550,hit:'DIALOG'}:{ready:false,offscreen:true,x:40,y:2418},{now:()=>t,sleep:async ms=>{t+=ms},reveal:async()=>{reveals++},timeoutMs:300}),/never became stable/);assert.equal(reveals,1);assert.equal(t,300);",
    "hidden-offscreen-target-is-not-revealed": "let t=0;await assert.rejects(waitForStablePoint(async()=>({ready:false,offscreen:true,hidden:true,x:40,y:2418}),{now:()=>t,sleep:async ms=>{t+=ms},reveal:async()=>{throw Error('hidden target must not be revealed')},timeoutMs:300}),/never became stable/);assert.equal(t,300);",
    "disabled-offscreen-target-is-not-revealed": "let t=0;await assert.rejects(waitForStablePoint(async()=>({ready:false,offscreen:true,disabled:true,x:40,y:2418}),{now:()=>t,sleep:async ms=>{t+=ms},reveal:async()=>{throw Error('disabled target must not be revealed')},timeoutMs:300}),/never became stable/);assert.equal(t,300);",
    "permanently-offscreen-recovery-is-bounded": "let t=0,reveals=0;await assert.rejects(waitForStablePoint(async()=>({ready:false,offscreen:true,x:40,y:2418}),{now:()=>t,sleep:async ms=>{t+=ms},reveal:async()=>{reveals++},timeoutMs:300}),/never became stable/);assert.equal(t,300);assert.equal(reveals,4);",
    "in-viewport-overlay-is-not-revealed": "let t=0;await assert.rejects(waitForStablePoint(async()=>({ready:false,offscreen:false,x:40,y:550,hit:'DIALOG'}),{now:()=>t,sleep:async ms=>{t+=ms},reveal:async()=>{throw Error('overlay must not trigger reveal')},timeoutMs:300}),/never became stable/);assert.equal(t,300);",
    "equal-geometry-replacement-must-restabilize-identity": "let t=0,n=0;const ids=[1,2,2];const r=await waitForStablePoint(async()=>({ready:true,x:40,y:550,targetId:ids[n++]}),{now:()=>t,sleep:async ms=>{t+=ms}});assert.equal(n,3);assert.equal(r.targetId,2);",
    "continually-replaced-target-never-stabilizes": "let t=0,n=0;await assert.rejects(waitForStablePoint(async()=>({ready:true,x:40,y:550,targetId:++n}),{now:()=>t,sleep:async ms=>{t+=ms},timeoutMs:300}),/never became stable/);assert.equal(t,300);",
    "trusted-down-up-never-count-as-click": "const p=probeFixture();p.fire('pointerdown');p.fire('pointerup');assert.equal(p.store.receipts.action,undefined);assert.deepEqual(p.store.actions.action.events.map(e=>e.type),['pointerdown','pointerup']);",
    "probe-rejects-wrong-target-trusted-click": "const p=probeFixture();p.fire('click',{tagName:'DIV',isConnected:true});assert.equal(p.store.receipts.action,undefined);assert.equal(p.store.actions.action.events[0].matches,false);",
    "probe-rejects-untrusted-then-records-trusted-click": "const p=probeFixture();p.fire('click',p.target,false);assert.equal(p.store.receipts.action,undefined);p.fire('click');assert.equal(p.store.receipts.action.trusted,true);assert.equal(p.store.actions.action.events[0].trusted,false);",
    "probe-survives-replacement-and-rejects-stale-target": "const p=probeFixture();p.doc.current={...p.target,id:'replacement',contains:()=>false};p.target.isConnected=false;p.fire('click',p.target);assert.equal(p.store.receipts.action,undefined);p.fire('click');assert.equal(p.store.receipts.action.targetId,p.store.identify(p.doc.current));assert.equal(p.store.actions.action.events[0].target.connected,false);",
    "probe-records-focus-and-descendant-click": "const p=probeFixture();p.doc.activeElement=p.child;p.fire('focusin',p.child);assert.equal(p.store.receipts.action,undefined);p.fire('click',p.child);assert.equal(p.store.receipts.action.trusted,true);assert.equal(p.store.actions.action.events[0].active.targetId,p.store.identify(p.child));",
    "probe-rejects-disabled-target-and-removes-listeners": "const p=probeFixture();p.target.disabled=true;p.fire('click');assert.equal(p.store.receipts.action,undefined);p.dispose();assert.equal(p.hooks.size,0);assert.equal(p.store.actions.action.events.length,1);",
    "native-pair-is-enqueued-once-before-either-response": "const calls=[],resolve=[];const promise=dispatchNativeClick((method,params)=>{calls.push({method,...params});return new Promise(done=>resolve.push(done));},{x:40,y:550});assert.deepEqual(calls.map(c=>c.type),['mousePressed','mouseReleased']);assert(calls.every(c=>c.method==='Input.dispatchMouseEvent'&&c.x===40&&c.y===550));resolve.forEach(done=>done());await promise;assert.equal(calls.length,2);",
    "native-pair-failure-never-retries-action": "const calls=[];await assert.rejects(dispatchNativeClick((method,params)=>{calls.push(params.type);return params.type==='mousePressed'?Promise.reject(Error('native failure')):Promise.resolve();},{x:40,y:550}),/native failure/);assert.deepEqual(calls,['mousePressed','mouseReleased']);",
    "invalid-target-coordinates-never-click": "let t=0;await assert.rejects(waitForStablePoint(async()=>({ready:true,x:NaN,y:120}),{now:()=>t,sleep:async ms=>{t+=ms},timeoutMs:300}),/never became stable/);",
}


@pytest.mark.parametrize("case", _HARNESS_HELPER_CASES)
def test_browser_orchestration_helpers_without_browser(case):
    node = shutil.which("node")
    assert node, "Node is required for the deterministic harness regression tests"
    prelude = "import assert from 'node:assert/strict';import {waitForDebugger,waitForStablePoint,installNativeClickProbe,dispatchNativeClick} from './tests/js/flow_browser_harness_helpers.mjs';const target={type:'page',webSocketDebuggerUrl:'ws://127.0.0.1:9222/devtools/page/1'};"
    prelude += """
function probeFixture() {
  const hooks=new Map(),child={tagName:'SPAN',isConnected:true};
  const target={tagName:'BUTTON',id:'save',isConnected:true,disabled:false,contains:node=>node===child};
  const doc={current:target,activeElement:target,querySelector:()=>doc.current,
    addEventListener:(type,fn)=>hooks.set(type,fn),removeEventListener:type=>hooks.delete(type)};
  const store={},dispose=installNativeClickProbe(doc,store,'button.save','action');
  const fire=(type,node=doc.current,trusted=true)=>hooks.get(type)({type,target:node,isTrusted:trusted,clientX:40,clientY:550,timeStamp:123});
  return {hooks,child,target,doc,store,dispose,fire};
}
"""
    result = subprocess.run([node, "--input-type=module", "-e", prelude + _HARNESS_HELPER_CASES[case]], cwd=ROOT, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_browser_driver_preserves_assertions_and_requires_trusted_native_clicks():
    source = DRIVER.read_text()
    assert "waitForStablePoint(measure" in source
    assert "trusted === true" in source and "Input.dispatchMouseEvent" in source
    helpers = (ROOT / "tests/js/flow_browser_harness_helpers.mjs").read_text()
    assert helpers.count("type:'mousePressed'") == helpers.count("type:'mouseReleased'") == 1
    assert source.count("await dispatchNativeClick(send,point)") == 1
    assert "event.type === 'click' && record.trusted && matches" in helpers
    assert "last.targetId === previous.targetId" in helpers
    assert "inputActions:" in source and "type:'click-dispatched'" in source
    assert "waitForStablePoint(measure,{sleep,reveal})" in source
    assert "offscreen:sized&&!inViewport" in source
    assert "Emulation.setFocusEmulationEnabled" in source
    assert "failure-state.json" in source
    for bypass in ("--no-sandbox", "--disable-web-security", "Page.setBypassCSP", "ignore-certificate-errors"):
        assert bypass not in source
    assert len(LEGACY_CASE_IDS) == 19
    assert len(EXPECTED_CASE_IDS) == 29
    import re
    assert re.findall(r"await test\('([^']+)'", source) == EXPECTED_CASE_IDS

@pytest.fixture
def browser_fixture_api(monkeypatch, tmp_path):
    """Exercise the acceptance server without sockets or launching a browser."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv

    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setenv("ENABLE_WRITE_ACTIONS", "")
    for attr in ("_latest_remote_commit", "_tenant_creds", "_build_client", "_raw_client",
                 "_build_sdk_client", "_live_rule_actions", "_live_connector_context"):
        monkeypatch.setattr(srv, attr, getattr(srv, attr))
    old_routes = list(srv.app.router.routes)
    state = _install_fixtures(srv)
    try:
        # No context manager: production startup jobs are excluded exactly as
        # in uvicorn's lifespan="off" browser-fixture process.
        yield TestClient(srv.app), srv, state
    finally:
        srv.app.router.routes[:] = old_routes


def _fixture_assessment(page, channels):
    response = page.post("/api/assess", json={"scopes": ["dlp"], "channels": channels,
                                           "org_name": "Synthetic Scope Browser", "assessor": "Synthetic Assessor"})
    assert response.status_code == 200, response.text
    events, kind = [], None
    for line in response.text.splitlines():
        if line.startswith("event: "):
            kind = line[7:]
        elif line.startswith("data: "):
            events.append((kind, json.loads(line[6:])))
    errors = [value for event, value in events if event == "error"]
    assert not errors, errors
    complete = [value for event, value in events if event == "complete"]
    assert len(complete) == 1, events
    return complete[0]


def test_scope_browser_fixture_root_health_never_discovers_remote(browser_fixture_api, monkeypatch):
    import app_update
    page, _srv, state = browser_fixture_api
    delegated = []

    def forbid_remote(*args, **kwargs):
        delegated.append(args)
        raise AssertionError("The browser fixture must not discover a genuine remote")

    def local_git_only(args, **kwargs):
        assert args[0] == "git" and not set(args[1:]) & {"ls-remote", "fetch", "pull", "push", "clone"}, args
        return subprocess.CompletedProcess(args, 0, stdout="main\n", stderr="")

    monkeypatch.setattr(app_update, "github_branch_head", forbid_remote)
    monkeypatch.setattr(subprocess, "run", local_git_only)
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: b"fixture0")
    assert page.get("/").status_code == 200
    response = page.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["latest_commit"] is None
    assert state["update_lookups"] and not delegated
    assert state["reads"] == [] and state["auth_calls"] == 0


def test_scope_browser_fixture_authentication_is_read_free(browser_fixture_api):
    page, _srv, state = browser_fixture_api
    response = page.post("/api/tenant/check", json={})
    assert response.status_code == 200 and response.json()["ok"]
    assert state["reads"] == [] and state["live_polls"] == 0 and state["writes"] == 0


@pytest.mark.parametrize("ssl_choice", ["gap", "alternative"])
def test_scope_browser_fixture_real_registry_and_sse_match_scope(browser_fixture_api, ssl_choice):
    import channel_scope
    page, srv, state = browser_fixture_api
    channels = {"web_dlp": {"choice": "zscaler"}, "ssl_inspection": {"choice": ssl_choice}}
    run, skipped, _order = channel_scope.partition(srv._get_checks(scopes=["dlp"]), channels)
    report = _fixture_assessment(page, channels)
    assert [c["id"] for c in report["checks"]] == [c[0] for c in run]
    assert report["metadata"]["total_checks"] == report["summary"]["total"] == len(run)
    assert report["hidden_checks"] == len(skipped) > 0
    assert len(run) + len(skipped) == state["assessment_registry_count"]
    assert not any(c.get("out_of_scope") for c in report["checks"])
    assert ("/zia/sslInspectionRules" in state["reads"]) == (ssl_choice == "gap")
    assert not any(ep.startswith(("/zia/endPointDlpRules", "/zia/emailDlpRules", "/zia/casbDlpRules")) for ep in state["reads"])
    prereq = next(p for p in report["channel_coverage"]["prerequisites"] if p["id"] == "ssl_inspection")
    assert prereq["declared"] == ssl_choice and prereq["blocked"] == (ssl_choice == "alternative")
    assert state["auth_calls"] == state["closed_clients"] == 1
    assert state["writes"] == 0 and state["external_connections"] == []


@pytest.mark.parametrize("ssl_choice", ["gap", "alternative"])
def test_scope_browser_fixture_profile_roundtrip_keeps_declaration(browser_fixture_api, ssl_choice):
    page, _srv, state = browser_fixture_api
    body = {"name": "Synthetic Scope Browser", "org_name": "Synthetic Scope Browser",
            "scopes": ["dlp"], "remember_secret": False,
            "channels": {"web_dlp": {"choice": "zscaler"},
                         "ssl_inspection": {"choice": ssl_choice, "note": "Synthetic alternative vendor"}}}
    response = page.post("/api/tenant-profiles", json=body)
    assert response.status_code == 200, response.text
    profile_id = response.json()["id"]
    profile = page.get(f"/api/tenant-profiles/{profile_id}").json()
    assert profile["channels"]["ssl_inspection"]["choice"] == ssl_choice
    assert profile["channels"]["ssl_inspection"]["note"] == "Synthetic alternative vendor"
    assert not profile["has_secret"]
    assert not {"required_by", "declared", "blocked"} & profile["channels"]["ssl_inspection"].keys()
    assert state["reads"] == [] and state["auth_calls"] == state["writes"] == 0


def test_scope_browser_fixture_unified_scenario_retains_excluded_controls(browser_fixture_api):
    page, _srv, state = browser_fixture_api
    response = page.post("/api/flow/scenario", json={"scopes": ["dlp"], "from_page": True,
                         "channels": {"web_dlp": {"choice": "zscaler"}, "ssl_inspection": {"choice": "alternative"}},
                         "destination": "https://example.test/upload", "channel": "web", "file_type": "txt",
                         "corpus": "SYNTHETIC-FLOW-MARKER one synthetic record"})
    assert response.status_code == 200, response.text
    report = response.json()
    stages = {stage["key"]: stage for stage in report["stages"]}
    assert {"url", "ssl", "ftc"} <= stages.keys()
    assert stages["ssl"]["status"] in {"out_of_scope", "unverified"}
    assert "/zia/sslInspectionRules" not in state["reads"]
    assert state["writes"] == 0 and state["live_polls"] == 0


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--serve":
    _serve(int(sys.argv[2]))
