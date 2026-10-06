"""Profile API evidence must survive into path analysis and the live view."""
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import data_flow as df
import dlp_api_server as srv
import dlp_assessment_full_auto as fa
from zcc_profiles import read_profiles
from zcc_profiles import read_app_profiles
from test_data_flow import APP_PROFILES, FWD, _client
from test_zcc_paths import _client as wire_client


@pytest.mark.parametrize('wire,expected', [('DEVICE_TYPE_WINDOWS','windows'), ('DEVICE_TYPE_MAC','macos'), ('DEVICE_TYPE_LINUX','linux'), ('DEVICE_TYPE_IOS','ios'), ('DEVICE_TYPE_ANDROID','android')])
def test_tenant_platform_enums_and_nested_forwarding_link(wire, expected):
    class Client:
        def get(self, ep, params=None):
            if ep == '/zcc/webPolicies':
                return [{'id': 164817, 'name': 'Tenant app', 'deviceType': wire, 'forwardingProfileId': None, 'onNetPolicy': {'id': '68585', 'name': 'Tenant forwarding'}}], 200
            if ep == '/zcc/forwardingProfiles':
                return [{'id': '68585', 'name': 'Tenant forwarding', 'enableUnifiedTunnel': False, 'forwardingProfileActions': [{'networkType': 0, 'actionType': 1, 'enablePacketTunnel': 1}], 'unifiedTunnel': [{'networkType': 0, 'actionTypeZIA': 0}]}], 200
            return [], 200
    zcc = df.read_client_connector(Client())
    assert len(zcc['app_profiles']) == 1
    assert zcc['app_profiles'][0]['platform'] == expected
    zia = df.read_zia(_client())
    t = df.trace(df.resolve_destination('example.net', zia), 'off', expected, zcc, zia)
    fwd = next(h for h in t['hops'] if h['key'] == 'forwarding')
    assert fwd['decided_by']['name'] == 'Tenant forwarding'
    assert fwd['mode'] == 'Z-Tunnel 2.0'


def test_every_platform_is_requested_and_partial_failure_preserves_evidence():
    calls = []
    def get(ep, params):
        calls.append(params['deviceType'])
        if params['deviceType'] == 3:
            return {'error': 'denied'}, 403
        return [{'id': 0, 'name': 'Default'}], 200
    profiles, errors, statuses = read_app_profiles(get)
    assert calls == [1, 2, 3, 4, 5]
    assert len(profiles) == 4 and statuses['windows'] == 'unverified' and errors


def test_inactive_and_unlinked_forwarding_profiles_remain_in_inventory():
    zcc = {'app_profiles': [{'id': 1, 'name': 'Inactive', 'platform': 'windows', 'active': False}], 'forwarding_profiles': [{'id': 2, 'name': 'Unlinked', 'actions': {}}], 'pac_files': [{'id': 3, 'name': 'PAC', 'has_content': False}]}
    refs = df.connector_references(zcc)
    assert refs['profiles'][0]['app_profile']['active'] is False
    assert refs['forwarding_profiles'][0]['name'] == 'Unlinked'
    assert refs['pac_files'][0]['has_content'] is False


@pytest.mark.parametrize("wrapper", ["policies", "list", "items", "data", "records"])
def test_profile_wrappers_are_consumed(wrapper):
    body, code = read_profiles(lambda ep, p: ({wrapper: APP_PROFILES}, 200), "profiles")
    assert code == 200 and body == APP_PROFILES


def test_both_inventories_read_all_pages():
    for endpoint in ("/zcc/webPolicies", "/zcc/forwardingProfiles"):
        calls = []
        def get(ep, params):
            calls.append((ep, params))
            batch = [{"id": n} for n in range(100)] if params["page"] == 1 else [{"id": 100}]
            return {"policies": batch, "totalCount": 101}, 200
        body, code = read_profiles(get, endpoint)
        assert code == 200 and len(body) == 101
        assert [p["page"] for _, p in calls] == [1, 2]


@pytest.mark.parametrize("code", [0, 401, 403, 404, 429, 503])
def test_failed_second_page_never_becomes_a_partial_success(code):
    def get(ep, params):
        return ([{"id": n} for n in range(100)], 200) if params["page"] == 1 else ({"error": "unavailable"}, code)
    body, status = read_profiles(get, "profiles")
    assert status == code and body == {"error": "unavailable"}


@pytest.mark.parametrize("body", [{}, {"policies": "bad"}, {"policies": [1]}, {"error": "denied"}, {"policies": [], "totalCount": 1}])
def test_malformed_success_is_unverified(body):
    result, code = read_profiles(lambda ep, params: (body, 200), "profiles")
    assert code == 0 and result["error"]


def test_repeated_full_page_stops_instead_of_claiming_complete():
    calls = []
    def get(ep, params):
        calls.append(params)
        return [{"id": n} for n in range(100)], 200
    result, code = read_profiles(get, "profiles")
    assert code == 0 and "repeated" in result["error"] and len(calls) == 2


def test_new_wire_route_reads_windows_and_forwarding_link():
    cl = wire_client({"/zcc/papi/public/v1/application-profiles": (200, {"policies": APP_PROFILES, "totalCount": 2}),
                      "/zcc/papi/public/v1/webForwardingProfile/listByCompany": (200, FWD)})
    zcc = df.read_client_connector(cl)
    ref = df.connector_references(zcc)["profiles"][0]
    assert ref["app_profile"]["platform"] == "windows"
    assert ref["forwarding_profile"] == {"id": 5, "name": "Corp forwarding"}
    assert ref["networks"]["vpn"]["kind"] == "none"
    assert cl.sess.calls[0].endswith("application-profiles")


def test_permission_denial_does_not_try_legacy_routes():
    cl = wire_client({"/zcc/papi/public/v1/application-profiles": (403, {})})
    data, code = cl.get("/zcc/webPolicies")
    assert code == 403 and len(cl.sess.calls) == 1


def test_nested_sdk_fields_preserve_false_and_profile_ids():
    profile = {"id": 11, "name": "Windows", "device_type": "3", "active": "0", "rule_order": 0,
               "forwarding_profile_id": "5", "policy_extension": json.dumps({"strict_enforcement": "0", "install_endpoint_dlp": "1"})}
    def get(ep, params=None):
        return ({"policies": [profile]} if ep == "/zcc/webPolicies" else []), 200
    p = df.read_client_connector(SimpleNamespace(get=get))["app_profiles"][0]
    assert p["platform"] == "windows" and not p["active"] and not p["strict_enforcement"]
    assert p["priority"] == 0 and p["endpoint_dlp"] and p["forwarding_profile"] == "5"


@pytest.mark.parametrize("reference", [999, None, {"id": 999, "name": "Corp forwarding"}])
def test_unmatched_link_does_not_select_only_forwarding_profile(reference):
    zcc = df.read_client_connector(_client())
    zcc["app_profiles"][0]["forwarding_profile"] = reference
    zcc["forwarding_profiles"] = zcc["forwarding_profiles"][:1]
    ref = df.connector_references(zcc)["profiles"][0]
    assert ref["status"] == "unverified" and ref["forwarding_profile"] is None


def test_zpa_action_never_overwrites_zia_forwarding():
    actions = df.forwarding_actions({"forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "enablePacketTunnel": 0, "actionType": "ZSCALER_TUNNEL_2"}],
                                     "forwardingProfileZpaActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "NONE"}]})
    assert actions["off"]["mode_kind"] == "tunnel"


def test_network_proxy_settings_and_raw_allowlist_are_retained():
    actions = df.forwarding_actions({"forwarding_profile_actions": [{"network_type": "ON_TRUSTED_NETWORK", "action_type": "ENFORCE_PROXY",
                "system_proxy_data": {"pac_url": "https://pac.example/config.pac"}, "password": "do-not-export"}]})
    assert actions["on"]["pac_url"] == "https://pac.example/config.pac"
    assert "do-not-export" not in json.dumps(actions)


def test_live_context_obeys_scope_and_closes_client(monkeypatch):
    cl = _client()
    cl.calls = []
    get = cl.get
    def record(ep, params=None):
        cl.calls.append(ep)
        return get(ep, params)
    cl.get = record
    closed = []
    cl.close = lambda: closed.append(True)
    monkeypatch.setattr(srv, "_raw_client", lambda creds: cl)
    monkeypatch.setattr(srv, "_live_connector_cache", {})
    creds = {"auth_method": "oneapi", "vanity_domain": "test", "cloud": "zscaler", "client_id": "id"}
    out = srv._live_connector_context(creds, [])
    assert out["status"] == "out_of_scope" and not cl.calls
    out = srv._live_connector_context(creds, ["zcc"])
    assert out["status"] == "read" and len(out["profiles"]) == 2 and closed
    assert {ep for ep in cl.calls if "/zia/" in ep} == {"/zia/pacFiles"}
    assert "does not establish" in out["note"]


def test_live_context_cache_separates_tenants(monkeypatch):
    clients = []
    def raw(creds):
        cl = _client()
        clients.append(cl)
        return cl
    monkeypatch.setattr(srv, "_raw_client", raw)
    monkeypatch.setattr(srv, "_live_connector_cache", {})
    base = {"auth_method": "oneapi", "vanity_domain": "test", "cloud": "zscaler", "client_id": "id"}
    a = srv._live_connector_context(base, ["zcc"])
    assert srv._live_connector_context(base, ["zcc"]) is a
    srv._live_connector_context(dict(base, vanity_domain="other"), ["zcc"])
    assert len(clients) == 2


def test_sdk_wire_profile_route_preserves_wrappers(monkeypatch):
    import sdk_client
    calls = []
    class Executor:
        def create_request(self, method, route, body, headers, params):
            calls.append((route, params))
            return route, None
        def execute(self, request):
            return SimpleNamespace(get_status=lambda: 200, get_body=lambda: {"policies": APP_PROFILES, "totalCount": 2}), None
    cl = sdk_client.SdkClient("id", "secret", "tenant", "zscaler")
    cl._zs = SimpleNamespace(get_request_executor=lambda: Executor())
    items, code = cl.get("/zcc/webPolicies")
    assert code == 200 and items == APP_PROFILES and calls[0][0].endswith("application-profiles")


def test_wrapper_is_understood_by_assessment_checks():
    assert fa._ls({"policies": APP_PROFILES, "totalCount": 2}) == APP_PROFILES


def test_failed_app_read_is_not_a_missing_profile_or_enforced_path():
    from test_ssl_flow import FakeCl, CATALOGUE
    from test_data_flow import ROUTES
    cl = FakeCl({k: v for k, v in ROUTES.items() if k != "/zcc/webPolicies"}, CATALOGUE)
    report = df.generate_data_flow_report(cl, None, "windows")
    t = report["traces"][0]
    app = next(h for h in t["hops"] if h["key"] == "zcc")
    assert app["status"] == "unknown" and app["weak_point"] is None
    assert t["conditional"] and t["outcome"] == "unknown"
    import path_analyzer
    v = path_analyzer.derive_verdict(t, {"host": "test.example"}, {})
    assert v["headline"].startswith("Unable to verify") and not v["content_inspected"]


def test_failed_forwarding_read_does_not_make_app_profile_missing():
    from test_ssl_flow import FakeCl, CATALOGUE
    from test_data_flow import ROUTES
    cl = FakeCl({k: v for k, v in ROUTES.items() if k != "/zcc/forwardingProfiles"}, CATALOGUE)
    report = df.generate_data_flow_report(cl, None, "windows")
    t = report["traces"][0]
    assert next(h for h in t["hops"] if h["key"] == "zcc")["status"] == "pass"
    assert next(h for h in t["hops"] if h["key"] == "forwarding")["status"] == "unknown"
    assert t["conditional"] and t["outcome"] == "unknown"


def test_old_profile_snapshots_are_refreshed():
    import path_analyzer
    scope = df.path_scope(["zcc"], {})
    snapshot = {"path_scope": scope["key"], "client_connector": {}}
    assert not path_analyzer.reusable(snapshot, scope)
    snapshot["client_connector"]["profile_schema"] = 4
    assert path_analyzer.reusable(snapshot, scope)


def test_live_endpoint_returns_linked_configuration_even_without_incidents(monkeypatch):
    import detection_health
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv, "_raw_client", lambda creds: _client())
    monkeypatch.setattr(srv, "_build_client", lambda req: _client())
    monkeypatch.setattr(srv, "_live_connector_cache", {})
    monkeypatch.setattr(srv, "_live_rule_actions", lambda *a: {})
    monkeypatch.setattr(detection_health, "poll_incidents", lambda *a: {"incidents": [], "next_since": "2026-10-04T00:00:00Z", "read_at": "2026-10-04T00:00:00Z", "errors": []})
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret",
             "scopes": ["dlp", "zcc"], "channels": {"web_dlp": "zscaler", "workflow_automation": "zscaler"}, "from_page": True}
    response = TestClient(srv.app).post("/api/live-feed", json=creds)
    assert response.status_code == 200, response.text
    context = response.json()["client_connector"]
    assert context["profiles"][0]["forwarding_profile"]["id"] == 5 and context["read_at"]
    assert "does not establish" in context["note"]


def test_live_page_renders_profile_links_and_escapes_api_names(tmp_path):
    import shutil
    if shutil.which("node") is None:
        pytest.skip("Node is required to execute the live page")
    from test_page_stop_is_final import LIVE_HARNESS, _live_script, _node
    context = {"status": "read", "note": "Configuration context only", "profiles": [
        {"app_profile": {"id": 11, "name": "<img src=x onerror=alert(1)>", "platform": "windows"},
         "forwarding_profile": {"id": 5, "name": "Corp forwarding"},
         "networks": {"off": {"mode": "Z-Tunnel 2.0"}}}]}
    harness = LIVE_HARNESS.replace("__SRC__", json.dumps(_live_script()))
    harness = harness.replace("incidents: [], next_since:", "client_connector: " + json.dumps(context) + ", incidents: [], next_since:")
    harness = harness.replace("process.stdout.write(JSON.stringify(out));", "out.html = els.lfBody.innerHTML; process.stdout.write(JSON.stringify(out));")
    html = _node(tmp_path, harness)["html"]
    assert "Corp forwarding (ID 5)" in html and "Z-Tunnel 2.0" in html and "windows" in html
    assert "&lt;img" in html and "<img" not in html
