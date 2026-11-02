"""ASVS V4.1.3 · CWE-284 · OWASP A01:2021: the Path analyzer traces a picked enrolled device and compares two identities, reading only what is in scope.

Device pick (path_device): a user's enrolled devices are looked up in the
Client Connector Portal (one getDevices call filtered by user name; only
when ZCC is ticked on the Scope page and with a OneAPI sign-in), one is
picked (one getDeviceDetails call), and the analysis uses that device's
platform and the app profile the Portal reports for it; what the API does
not give stays "unknown". Compare (path_compare): the same destination for
two what-if identities on one tenant read, step by step, with the step
where the paths diverge marked; CSV (spreadsheet-safe) and JSON exports.

Fakes only (the Data Flow fake for ZIA and Client Connector, a recording
fake of client.zcc.devices); jobs run in the request; no network.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import path_compare as pc
import path_device as pdv
from test_data_flow import ROUTES
from test_path_analyzer import LookupCl
from test_ssl_flow import CATALOGUE

ROOT = Path(__file__).resolve().parents[1]
SECRET = "canary-secret-91c2d7"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
CHANNELS = {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}
SCOPE = {"scopes": ["dlp", "zia_extras", "zcc"], "channels": CHANNELS, "from_page": True}

# A second Windows profile, scoped to Finance and later in order, with its own
# forwarding: the generic trace picks Windows-Corp for any Windows device.
FIN_PROFILE = {"id": 13, "name": "Windows-Finance", "os": "windows", "active": True, "ruleOrder": 2, "forwardingProfileId": 6,
               "strictEnforcement": True, "sslCertInstall": True, "groups": [{"id": 8, "name": "Finance"}]}
SALES_GAMBLING = {"id": 19, "name": "Allow gambling for Sales", "order": 0, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["GAMBLING"],
                  "departments": [{"id": 3, "name": "Sales"}]}

DEVICES = [
    {"udid": "UDID-JANE-WIN", "machineHostname": "JANE-LT", "user": "jane@acme.example", "type": 3, "osVersion": "Windows 11",
     "agentVersion": "4.7.0.61", "registrationState": "Registered", "policyName": "Windows-Finance", "tunnelVersion": "Z-Tunnel 2.0"},
    {"udid": "UDID-JANE-MAC", "machineHostname": "JANE-MBP", "user": "jane@acme.example", "type": 4, "osVersion": "macOS 15",
     "agentVersion": "4.1.0.10", "registrationState": "Registered", "policyName": "Mac-Contractors"},
    {"udid": "UDID-JANE-OLD", "machineHostname": "JANE-OLD", "user": "jane@acme.example", "type": 3, "agentVersion": "4.7.1",
     "registrationState": "Quarantined", "policyName": "A profile that was deleted"},
    {"udid": "UDID-JANE-NONE", "machineHostname": "JANE-VM", "user": "jane@acme.example", "type": 3, "agentVersion": "4.8.0"},
    {"udid": "UDID-BOB", "machineHostname": "BOB-LT", "user": "bob@acme.example", "type": 3, "policyName": "Windows-Corp"},
]


class FakeDevices:
    """client.zcc.devices: list_devices ignores the user filter on purpose
    (it answers everyone), so the module's own guard is what keeps a search
    from becoming a bulk listing."""

    def __init__(self, devices=None, details=None, fail=None):
        self.devices, self.details, self.fail, self.calls = devices if devices is not None else DEVICES, details or {}, fail, []

    def list_devices(self, query_params=None):
        self.calls.append(("list_devices", dict(query_params or {})))
        if self.fail:
            return None, None, Exception(self.fail)
        return copy.deepcopy(self.devices), None, None

    def get_device_details(self, query_params=None):
        self.calls.append(("get_device_details", dict(query_params or {})))
        d = self.details.get((query_params or {}).get("udid"))
        if d is None:
            return None, None, Exception("HTTP 404 Not Found for jane@acme.example")
        return dict(d), None, None


class Sdk:
    def __init__(self, devices=None, **kw):
        self.zcc = type("ZCC", (), {})()
        self.zcc.devices = devices or FakeDevices(**kw)


class SyncJob:
    def __init__(self, kind, result):
        self.id, self.kind, self.status, self.result = "sync-" + kind, kind, "done", result


def _routes():
    r = copy.deepcopy(ROUTES)
    r["/zcc/webPolicies"] = r["/zcc/webPolicies"] + [FIN_PROFILE]
    r["/zia/urlFilteringRules"] = [SALES_GAMBLING] + r["/zia/urlFilteringRules"]
    return r


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Arrange: an isolated app whose client factories are the fakes and whose jobs run in the request."""
    import dlp_api_server as srv
    import pack_jobs
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments")):
        monkeypatch.setenv(var, str(tmp_path / name))
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(srv, "_REPORTS", {})
    jobs = {}

    def start(kind, fn, **k):
        job = SyncJob(kind, fn(lambda line: jobs.setdefault("logs", []).append(line), threading.Event()))
        jobs[job.id] = job
        jobs["last"] = job
        return job
    monkeypatch.setattr(pack_jobs, "start", start)
    monkeypatch.setattr(pack_jobs, "get", lambda jid: jobs.get(jid))
    raw = LookupCl(_routes(), CATALOGUE)
    details = {"UDID-JANE-WIN": {"ziaEnabled": True, "zpaEnabled": 1, "ziaHealth": "Healthy", "deviceTrust": "HIGH_TRUST", "strictEnforcement": 1},
               "UDID-JANE-MAC": {"ziaEnabled": False, "zpaEnabled": True, "deviceTrust": "LOW_TRUST"}}
    state = {"raw": raw, "sdk": Sdk(details=details), "built": [], "jobs": jobs}
    monkeypatch.setattr(srv, "_build_client", lambda req: state["built"].append("raw") or state["raw"])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: state["built"].append("sdk") or state["sdk"])
    c = TestClient(srv.app)
    state["c"] = c
    state["post"] = lambda url, **body: c.post(url, json=dict(CREDS, **SCOPE, **body) if "scopes" not in body else dict(CREDS, from_page=True, **body))
    state["result"] = lambda: jobs["last"].result
    return state


def _find(api, q="jane"):
    r = api["post"]("/api/path-analyzer/devices", device_user=q)
    assert r.status_code == 200, r.text
    return r.json()


def _pick(api, found, host):
    dev = next(d for d in found["devices"] if d["hostname"] == host)
    r = api["post"]("/api/path-analyzer/devices/detail", ref=found["ref"], device_id=dev["id"])
    assert r.status_code == 200, r.text
    return {"ref": found["ref"], "id": dev["id"]}


# ── Looking devices up ─────────────────────────────────────────────────
def test_a_device_search_is_one_filtered_call_and_never_a_bulk_listing(api):
    """ASVS V8.3.1 · CWE-359 · WSTG-ATHZ-02: one getDevices call with the user filter; only the matching user's devices come back, never the UDID."""
    # Act
    found = _find(api, "JANE@acme")
    # Assert
    calls = api["sdk"].zcc.devices.calls
    assert calls == [("list_devices", {"username": "JANE@acme", "page": 1, "page_size": pdv.PAGE_SIZE})]
    assert {d["user"] for d in found["devices"]} == {"jane@acme.example"} and len(found["devices"]) == 4
    assert found["ref"].startswith("pathdev-") and "UDID" not in json.dumps(found)
    win = next(d for d in found["devices"] if d["hostname"] == "JANE-LT")
    assert win["platform"] == "windows" and win["version"] == "4.7.0.61" and win["profile"] == "Windows-Finance" and len(win["id"]) == 20


@pytest.mark.parametrize("body,why", [
    ({"scopes": ["dlp", "zia_extras"], "channels": CHANNELS, "device_user": "jane"}, "not in scope"),
    ({"scopes": ["zcc"], "channels": {}, "device_user": "j"}, "2 to 128"),
    ({"scopes": ["zcc"], "channels": {}, "device_user": "jane\x00"}, "2 to 128"),
])
def test_a_device_search_out_of_scope_or_malformed_is_refused_before_sign_in(api, body, why):
    """ASVS V4.1.3 · V5.1.3 · CWE-20 · WSTG-INPV-01: ZCC not ticked, or a name that is not 2 to 128 printable characters, is a 400 before anything is signed in to."""
    # Act
    r = api["post"]("/api/path-analyzer/devices", **body)
    # Assert
    assert r.status_code == 400 and why in r.json()["detail"] and api["built"] == []


def test_the_classic_zia_api_sign_in_cannot_look_devices_up(api):
    """ASVS V4.1.3 · CWE-284: the classic ZIA API has no Client Connector API: 400 in words, nothing built."""
    # Act
    r = api["c"].post("/api/path-analyzer/devices", json=dict(SCOPE, auth_method="legacy", cloud="zscaler", username="admin@acme.example",
                                                              password="pw-" + SECRET, api_key="k" * 12, device_user="jane"))
    # Assert
    assert r.status_code == 400 and "OneAPI" in r.json()["detail"] and api["built"] == []


def test_a_refused_device_read_is_reported_in_words_without_a_user_name(api):
    """ASVS V7.4.1 · CWE-209: a 403 from the Portal says which permission is missing; no stack trace, no user name."""
    # Arrange
    api["sdk"] = Sdk(devices=FakeDevices(fail="HTTP 403 Forbidden for jane@acme.example"))
    # Act
    found = _find(api)
    # Assert
    assert found["devices"] == [] and "not allowed" in found["error"] and "jane@" not in found["error"]


def test_picking_a_device_reads_only_its_details(api):
    """ASVS V8.3.1 · CWE-200: the pick makes one getDeviceDetails call for that device's UDID; the page gets the details, never the UDID."""
    # Arrange
    found = _find(api)
    dev = next(d for d in found["devices"] if d["hostname"] == "JANE-LT")
    # Act
    r = api["post"]("/api/path-analyzer/devices/detail", ref=found["ref"], device_id=dev["id"])
    # Assert
    assert r.status_code == 200
    d = r.json()["device"]
    assert d["details"] == {"status": "read", "reason": "", "zia": "on", "zpa": "on", "zdx": "unknown", "zia_health": "Healthy", "zpa_health": "",
                            "device_trust": "HIGH_TRUST", "strict_enforcement": "on", "vdi": "unknown"}
    assert api["sdk"].zcc.devices.calls[-1] == ("get_device_details", {"udid": "UDID-JANE-WIN"}) and "UDID" not in r.text


def test_details_the_portal_will_not_give_are_unknown_not_a_crash(api):
    """ASVS V7.4.1 · CWE-755 · CWE-209: a 404 on the details leaves them unread with a reason (no user name); the facts say unknown."""
    # Arrange
    found = _find(api)
    # Act
    pick = _pick(api, found, "JANE-VM")
    import dlp_api_server as srv
    dev = next(d for d in srv._REPORTS[pick["ref"]]["devices"] if d["id"] == pick["id"])
    # Assert
    assert dev["details"]["status"] == "failed" and "HTTP 404" in dev["details"]["reason"] and "jane@" not in dev["details"]["reason"]
    facts = {f["key"]: f for f in pdv.describe(pdv.public(dev))["facts"]}
    assert facts["zia"] == {"key": "zia", "label": "ZIA service", "value": "unknown", "known": False, "source": "device details could not be read"}
    assert facts["network"]["value"] == "unknown" and facts["posture"]["value"] == "unknown" and facts["profile"]["value"] == "unknown"


@pytest.mark.parametrize("pick", [{"ref": "pathdev-nope", "id": "x"}, {"ref": "dataflow-abc", "id": "x"}, {"ref": "", "id": ""}])
def test_a_pick_that_is_not_kept_is_refused_before_sign_in(api, pick):
    """ASVS V4.2.1 · CWE-639: a device reference that is not a kept lookup is a 400; nothing is signed in to."""
    # Act
    r = api["post"]("/api/path-analyzer/devices/detail", ref=pick["ref"], device_id=pick["id"])
    r2 = api["post"]("/api/path-analyzer/start", destination="casino.example", device=pick or {"ref": "x"})
    # Assert
    assert r.status_code == 400 and r2.status_code == 400 and api["built"] == []


def test_a_device_kept_for_one_tenant_never_answers_for_another(api):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a lookup made for tenant acme is refused for tenant other, before sign-in."""
    # Arrange
    found = _find(api)
    dev = found["devices"][0]
    api["built"].clear()
    # Act
    r = api["c"].post("/api/path-analyzer/start", json=dict(CREDS, **SCOPE, vanity_domain="other", destination="casino.example",
                                                            device={"ref": found["ref"], "id": dev["id"]}))
    # Assert
    assert r.status_code == 400 and "no longer kept" in r.json()["detail"] and api["built"] == []


def test_a_device_needs_client_connector_in_scope_and_a_user_device(api):
    """ASVS V4.1.3 · CWE-284: with ZCC not ticked, or for workload traffic, a picked device is a 400 before sign-in."""
    # Arrange
    found = _find(api)
    pick = {"ref": found["ref"], "id": found["devices"][0]["id"]}
    api["built"].clear()
    # Act
    no_zcc = api["post"]("/api/path-analyzer/start", scopes=["dlp", "zia_extras"], channels=CHANNELS, destination="casino.example", device=pick)
    wl = api["post"]("/api/path-analyzer/start", scopes=["dlp", "zcc", "ztw"], channels=CHANNELS, destination="casino.example", device=pick,
                     source="workload", workload={"ip": "10.1.2.3"})
    # Assert
    assert no_zcc.status_code == 400 and "Client Connector" in no_zcc.json()["detail"]
    assert wl.status_code == 400 and "workload" in wl.json()["detail"] and api["built"] == []


# ── The device on the path ─────────────────────────────────────────────
def test_the_trace_follows_the_app_profile_the_portal_reports(api):
    """ASVS V1.4.4 · CWE-284: the device's reported profile decides, not the first profile for the platform; the result says which and why."""
    # Arrange
    found = _find(api)
    pick = _pick(api, found, "JANE-LT")
    # Act
    generic = api["post"]("/api/path-analyzer/start", destination="casino.example", network="off", platform="windows")
    g = api["result"]()
    picked = api["post"]("/api/path-analyzer/start", destination="casino.example", network="off", platform="macos", device=pick, report_id=g["report_id"])
    res = api["result"]()
    # Assert
    assert generic.status_code == picked.status_code == 200
    gz = next(h for h in g["trace"]["hops"] if h["key"] == "zcc")
    pz = next(h for h in res["trace"]["hops"] if h["key"] == "zcc")
    assert gz["decided_by"]["name"] == "Windows-Corp" and pz["decided_by"]["name"] == "Windows-Finance"
    assert res["platform"] == "windows"   # the device's platform, not the select's macos
    dev = res["device"]
    assert dev["app_profile"]["status"] == "portal" and dev["app_profile"]["applied"] == "Windows-Finance" and "reports app profile" in dev["app_profile"]["why"]
    assert dev["forwarding_profile"]["name"] == "Contractor forwarding" and "Windows-Finance" in dev["forwarding_profile"]["why"]
    facts = {f["key"]: f for f in dev["facts"]}
    assert facts["version"]["value"] == "4.7.0.61" and facts["device_trust"]["value"] == "HIGH_TRUST" and facts["zia"]["value"] == "on"
    assert facts["network"] == {"key": "network", "label": "Network right now", "value": "unknown", "known": False, "source": "not given by the API"}
    assert any("The device you picked (Windows, Client Connector 4.7.0.61" in a for a in res["assumptions"])
    assert "UDID" not in json.dumps(res)


def test_the_reported_profile_never_changes_the_kept_read(api):
    """ASVS V1.4.4 · CWE-668: pinning the device's profile works on a copy; the next analysis for any device still sees every profile."""
    # Arrange
    found = _find(api)
    pick = _pick(api, found, "JANE-LT")
    api["post"]("/api/path-analyzer/start", destination="casino.example", device=pick)
    rid = api["result"]()["report_id"]
    # Act
    api["post"]("/api/path-analyzer/start", destination="casino.example", platform="windows", report_id=rid)
    res = api["result"]()
    # Assert
    assert res["report_id"] == rid and next(h for h in res["trace"]["hops"] if h["key"] == "zcc")["decided_by"]["name"] == "Windows-Corp"
    assert "device" not in res


def test_a_profile_the_portal_names_but_nobody_read_stays_unknown(api):
    """CWE-1188 · ASVS V1.4.4: a reported profile not in the read, or no reported profile, leaves the generic choice and says why; a quarantined device is flagged."""
    # Arrange
    found = _find(api)
    gone, none = _pick(api, found, "JANE-OLD"), _pick(api, found, "JANE-VM")
    # Act
    api["post"]("/api/path-analyzer/start", destination="casino.example", device=gone)
    a = api["result"]()
    api["post"]("/api/path-analyzer/start", destination="casino.example", device=none)
    b = api["result"]()
    # Assert
    assert a["device"]["app_profile"]["status"] == "not_found" and "no app profile of that name was read" in a["device"]["app_profile"]["why"]
    assert next(h for h in a["trace"]["hops"] if h["key"] == "zcc")["decided_by"]["name"] == "Windows-Corp"
    assert any(i["hop"] == "device" and "quarantined" in i["detail"] for i in a["verdict"]["impacts"])
    assert b["device"]["app_profile"]["status"] == "unknown" and b["device"]["app_profile"]["why"].startswith("Unknown:")


def test_zia_turned_off_on_the_device_is_a_high_impact(api):
    """ASVS V1.4.4 · CWE-693: the Portal saying ZIA is off on the device is named as a high impact; an unsupported client is named too."""
    # Arrange
    found = _find(api)
    pick = _pick(api, found, "JANE-MBP")
    # Act
    api["post"]("/api/path-analyzer/start", destination="casino.example", device=pick)
    res = api["result"]()
    # Assert
    imp = [i for i in res["verdict"]["impacts"] if i["hop"] == "device"]
    assert any(i["severity"] == "high" and "ZIA is turned off on this device" in i["detail"] for i in imp)
    assert any("older than every release Zscaler supports on macOS" in i["detail"] for i in imp)
    assert res["platform"] == "macos" and res["device"]["app_profile"]["applied"] == "Mac-Contractors"


def test_apply_device_is_pure_and_keeps_the_read():
    """CWE-668: apply_device returns a pinned copy; the read it was given is untouched; out of scope says so."""
    # Arrange
    zcc = {"app_profiles": [{"id": 1, "name": "A", "platform": "windows", "groups": ["G"], "users": [], "active": False}], "not_in_scope": {}}
    before = copy.deepcopy(zcc)
    # Act
    pinned, ctx = pdv.apply_device(zcc, {"platform": "windows", "profile": "a"})
    nis, ctx2 = pdv.apply_device({"app_profiles": [], "not_in_scope": {"zcc": "x"}}, {"platform": "windows", "profile": "a"})
    # Assert
    assert zcc == before and pinned["app_profiles"][0]["groups"] == [] and pinned["app_profiles"][0]["active"] is True
    assert ctx["status"] == "portal" and "inactive" in ctx["why"] and ctx2["status"] == "not_in_scope"


@pytest.mark.parametrize("raw,plat", [({"type": 1}, "ios"), ({"type": "2"}, "android"), ({"type": "DEVICE_TYPE_MACOS"}, "macos"),
                                      ({"type": 5}, "linux"), ({"type": 99}, None), ({}, None)])
def test_the_device_type_names_the_platform(raw, plat):
    """CWE-20: the SDK's device type codes (1 iOS, 2 Android, 3 Windows, 4 macOS, 5 Linux) map to the analyzer's platforms; anything else is unknown."""
    assert pdv.normalize(dict(raw, udid="u"))["platform"] == plat


def test_device_fields_are_bounded():
    """ASVS V5.1.3 · CWE-770: a hostile device record (huge strings) is cut to bounded fields."""
    d = pdv.normalize({"udid": "u" * 9999, "machineHostname": "h" * 9999, "policyName": "p" * 9999, "agentVersion": "9" * 9999})
    assert len(d["hostname"]) == pdv.MAX_TEXT and len(d["profile"]) == pdv.MAX_TEXT and len(d["version"]) == 40 and len(d["udid"]) == 256


# ── Two identities compared ────────────────────────────────────────────
def test_two_identities_diverge_at_the_rule_scoped_to_one_of_them(api):
    """ASVS V4.1.3 · CWE-284: A (department Sales) and B (department Finance) differ at URL filtering; the tenant is read once for both."""
    # Act
    r = api["post"]("/api/path-analyzer/compare/start", destination="casino.example", identity={"department": "Sales"},
                    identity_b={"department": "Finance"})
    res = api["result"]()
    # Assert
    assert r.status_code == 200 and r.json()["kind"] == "path-compare"
    first = next(s for s in res["steps"] if s["first"])
    assert first["key"] == "z:url" and res["first_divergence"] == {"key": "z:url", "label": first["label"]}
    assert first["a"]["rule"] == "Allow gambling for Sales" and first["b"]["rule"] == "Block gambling"
    assert res["a"]["label"] == "A: department Sales" and res["b"]["label"] == "B: department Finance"
    assert "diverge at" in res["headline"] and not res["same_outcome"]
    assert sum(1 for s in res["steps"] if s["first"]) == 1
    reads = [l for l in api["jobs"]["logs"] if l.startswith("Reading Client Connector")]
    assert len(reads) == 1, "B reuses A's tenant read"


def test_two_devices_diverge_at_the_app_profile(api):
    """ASVS V1.4.4 · CWE-284: A on Bob's device (Windows-Corp) and B on Jane's (Windows-Finance) diverge at the Client Connector app profile."""
    # Arrange
    bob = _pick(api, _find(api, "bob"), "BOB-LT")
    jane = _pick(api, _find(api, "jane"), "JANE-LT")
    # Act
    api["post"]("/api/path-analyzer/compare/start", destination="casino.example", device=bob, device_b=jane)
    res = api["result"]()
    # Assert
    first = next(s for s in res["steps"] if s["first"])
    assert first["key"] == "h:zcc" and first["a"]["rule"] == "Windows-Corp" and first["b"]["rule"] == "Windows-Finance"
    assert res["a"]["label"] == "A: device BOB-LT" and res["b"]["device"]["hostname"] == "JANE-LT"


def test_the_same_identity_twice_has_no_divergence():
    """CWE-670: identical results compare as the same path, with no first divergence."""
    res = {"platform": "windows", "trace": {"hops": [{"key": "zcc", "label": "App profile", "status": "pass", "decided_by": {"name": "P"}}]},
           "zia_modules": {"modules": [{"key": "url", "module": "URL filtering", "verdict": "allow", "rule": {"name": "R"}}]},
           "verdict": {"outcome": "enforce", "headline": "Allowed."}}
    out = pc.compare(res, copy.deepcopy(res))
    assert out["first_divergence"] is None and out["differences"] == 0 and out["headline"].startswith("Both identities get the same path")


def test_a_step_on_only_one_path_differs_and_keeps_its_place():
    """CWE-670: a step only B has (ZPA) sits where B has it and counts as a difference."""
    a = {"platform": "windows", "modules": [], "verdict": {"outcome": "enforce"}}
    b = {"platform": "windows", "modules": [{"key": "zpa_segment", "module": "ZPA application segment", "verdict": "matched", "rule": {"name": "Git"}}],
         "verdict": {"outcome": "zpa_allowed"}}
    out = pc.compare(a, b)
    keys = [s["key"] for s in out["steps"]]
    assert keys == ["platform", "m:zpa_segment", "verdict"] and out["first_divergence"]["key"] == "m:zpa_segment"
    assert out["steps"][1]["a"]["outcome"] == pc.ABSENT


def test_compare_checks_identity_b_before_sign_in(api):
    """ASVS V5.1.3 · CWE-20: a bad device for B is a 400 before anything is signed in to or read."""
    # Act
    r = api["post"]("/api/path-analyzer/compare/start", destination="casino.example", device_b={"ref": "pathdev-gone", "id": "x"})
    # Assert
    assert r.status_code == 400 and api["built"] == []


def test_the_comparison_exports_as_safe_csv_and_json(api):
    """ASVS V5.3.4 · CWE-1236: a rule named like a formula is quoted in the CSV; the JSON has the steps and no run log."""
    # Arrange
    api["raw"].routes["/zia/urlFilteringRules"][0]["name"] = '=HYPERLINK("http://evil.example","x")'
    api["post"]("/api/path-analyzer/compare/start", destination="casino.example", identity={"department": "Sales"}, identity_b={"department": "Finance"})
    jid = api["jobs"]["last"].id
    # Act
    csv_r = api["c"].get(f"/api/path-analyzer/compare/{jid}/export?format=csv")
    js = api["c"].get(f"/api/path-analyzer/compare/{jid}/export?format=json")
    gone = api["c"].get("/api/path-analyzer/compare/nope/export")
    # Assert
    assert csv_r.status_code == 200 and csv_r.text.startswith("step,label,a_outcome,a_rule,b_outcome,b_rule,differs,first_divergence")
    assert "'=HYPERLINK" in csv_r.text and ",=HYPERLINK" not in csv_r.text and "attachment" in csv_r.headers["content-disposition"]
    body = js.json()
    assert body["first_divergence"]["key"] == "z:url" and body["destination"] == "casino.example" and "logs" not in body
    assert gone.status_code == 404


def test_compare_csv_rows_name_both_identities():
    """CWE-116: the CSV starts with who A and B are, then one row per step."""
    cmp = pc.compare({"platform": "linux", "verdict": {"outcome": "blocked", "blocked_by": "R"}}, {"platform": "linux", "verdict": {"outcome": "enforce"}})
    rows = pc.rows(cmp)
    assert rows[0]["a_outcome"].startswith("A: anyone") and rows[-1]["first_divergence"] == "yes" and rows[1]["a_outcome"] == "Linux"


# ── The page ───────────────────────────────────────────────────────────
def test_the_page_carries_the_device_and_compare_panels():
    """WCAG 2.2 SC 1.3.1 · SC 4.1.2: the panels, their labelled inputs and the script are on the page; every control has help."""
    import test_c6_tooltips as hh
    html = (ROOT / "static" / "report_path.html").read_text(encoding="utf-8")
    for el in ('id="paDevice"', 'id="paDevQ"', 'id="paDevFind"', 'id="paCompare"', 'id="paCmp_user"', 'id="paCmpDevFind"', 'id="paCmpRun"',
               '/static/path_extras.js', 'PathExtras.afterRender(res, body)'):
        assert el in html, el
    keys = set(hh.CAT["pages"]["/report/path"])
    for sel in ("#paDevQ", "#paDevFind", "#paDevice button[data-dev-pick]", "#paDevClear", "#paCmpRun", "#paCmpCsv", "#paCmpJson",
                "#paProbeRun", "#paProbePort", "#paCompare > summary", "#paDevice > summary"):
        assert sel in keys, sel


NODE_ESCAPE = r"""
const fs = require('fs'), vm = require('vm');
const win = {};
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), { window: win, document: {}, setTimeout, console });
const X = '<img src=x onerror=alert(1)>';
const probe = win.PathExtras._probeHtml({ where: X, at: 1, port: 443, sent: X, dns: { ok: true, addresses: [X], how: X }, tcp: { ok: true, address: X, ms: 1 },
  tls: { attempted: true, ok: true, version: X, cipher: X, trusted: false, trust_error: X, certificate: { read: true, issuer_cn: X, issuer_o: X, subject_cn: X, sans: [X], zscaler: true } },
  comparison: [{ topic: X, predicted: X, observed: X, agrees: false, note: X }] });
const dev = win.PathExtras._deviceSection({ hostname: X, facts: [{ label: X, value: X, known: true, source: X }], app_profile: { applied: X, why: X },
  forwarding_profile: { name: X, mode: X, why: X }, network: { value: X, why: X }, posture: { why: X } });
console.log(JSON.stringify({ probe, dev }));
"""


def test_the_page_script_escapes_every_tenant_and_network_value(tmp_path):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: a certificate name, device name or rule name with markup is drawn as text."""
    node = shutil.which("node")
    if not node:
        pytest.skip("needs node")
    (tmp_path / "esc.js").write_text(NODE_ESCAPE, encoding="utf-8")
    out = json.loads(subprocess.run([node, str(tmp_path / "esc.js"), str(ROOT / "static" / "path_extras.js")], capture_output=True, text=True,
                                    timeout=60, check=True).stdout)
    for html in out.values():
        assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
