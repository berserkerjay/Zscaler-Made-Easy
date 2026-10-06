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
    for path in ("/opt/google/chrome/chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"):
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

        def get(self, endpoint, params=None):
            if self.stop_check and self.stop_check():
                import data_flow
                raise data_flow.ReadStopped("Fixture read cancelled")
            state["reads"].append(endpoint)
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
    creds.update(auth_method="oneapi", cloud="zscaler", vanity_domain="browser-fixture", client_id="synthetic-client")
    srv._tenant_creds = lambda request: dict(creds)
    srv._build_client = lambda request: Client()
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
                                   cwd=ROOT, env=environment, text=True, capture_output=True, timeout=120)
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


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--serve":
    _serve(int(sys.argv[2]))
