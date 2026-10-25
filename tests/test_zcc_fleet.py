"""Client Connector fleet health (zcc_fleet, /api/zcc/fleet/*, /report/fleet):
every heuristic at its boundary, the profile drift diff, the PAC comparison,
the remediation ranking, the configuration-only fallback, the scope refusal
before sign-in, Stop, and that no user or device name reaches a log."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import zcc_fleet as zf

NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
ZCC_SCOPE = {"scopes": ["zcc"], "channels": {}, "from_page": True}


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%d %H:%M:%S")


# ── fixtures: a tenant's profiles, PAC files, devices and service status ──
APP = [
    {"id": 1, "name": "Corp Windows", "device_type": 3, "active": 1, "forwardingProfileId": "5", "strictEnforcement": 1,
     "enableAntiTampering": 1, "uninstallPassword": "hunter2-secret", "disablePassword": "zia-off-pass", "sslCertInstall": 1,
     "installEndpointDlp": 1, "pacUrl": "https://pac.zscalerthree.net/acme/bypass.pac", "packetTunnelExcludeList": "10.0.0.0/8"},
    {"id": 2, "name": "Contractors", "device_type": 3, "active": 1, "forwardingProfileId": "6", "strictEnforcement": 0,
     "enableAntiTampering": 0, "uninstallPassword": "", "disablePassword": "", "sslCertInstall": 0, "installEndpointDlp": 0,
     "pacUrl": "https://pac.zscalerthree.net/acme/contractor.pac", "packetTunnelExcludeList": "8.0.0.0/8"},
    {"id": 3, "name": "Corp Mac", "device_type": 4, "active": 1, "forwardingProfileId": "5", "strictEnforcement": 1,
     "uninstallPassword": "x", "disablePassword": "y", "sslCertInstall": 1, "installEndpointDlp": 1},
]
FWD = [
    {"id": 5, "name": "Corp forwarding", "forwardingProfileActions": [
        {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"},
        {"networkType": "ON_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"}]},
    {"id": 6, "name": "Contractor forwarding", "forwardingProfileActions": [
        {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "NONE"},
        {"networkType": "ON_TRUSTED_NETWORK", "actionType": "NONE"}]},
]
PAC_CORP = """function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";
  if (shExpMatch(host, "*.intranet.acme.com")) return "DIRECT";
  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT";
}"""
PAC_CONTRACTOR = """function FindProxyForURL(url, host) {
  if (isPlainHostName(host)) return "DIRECT";
  if (shExpMatch(host, "*.intranet.acme.com")) return "DIRECT";
  if (dnsDomainIs(host, ".dropbox.com")) return "DIRECT";
  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";
}"""
PACS = [{"id": 11, "name": "bypass.pac", "pacUrl": "https://pac.zscalerthree.net/acme/bypass.pac", "pacContent": PAC_CORP},
        {"id": 12, "name": "contractor.pac", "pacUrl": "https://pac.zscalerthree.net/acme/contractor.pac", "pacContent": PAC_CONTRACTOR}]


def dev(n, user, host, *, typ=3, ver="4.7.2.5", reg="Registered", seen=None, policy="Corp Windows", udid=None):
    return {"user": user, "machineHostname": host, "type": typ, "agentVersion": ver, "registrationState": reg,
            "last_seen_time": seen if seen is not None else ago(hours=1), "policyName": policy, "udid": udid or f"UDID-{n}",
            "osVersion": "Windows 11", "macAddress": "00:11:22:33:44:55"}


DEVICES = [
    dev(1, "alice@acme.com", "ALICE-LT", seen=ago(hours=24)),                         # blind spot at exactly 24 h
    dev(2, "bob@acme.com", "BOB-LT", seen=ago(hours=24, seconds=1)),                  # ZIA off, but 24 h + 1 s: no blind spot
    dev(3, "carol@acme.com", "CAROL-LT", seen=ago(days=31)),                          # exactly 31 days: no ghost
    dev(4, "dave@acme.com", "DAVE-LT", seen=ago(days=31, minutes=1)),                 # 31 days + 1 min: ghost
    dev(5, "erin@acme.com", "ERIN-LT", reg="Quarantined"),
    dev(6, "frank@acme.com", "FRANK-LT", seen=""),                                     # registered, never seen
    dev(7, "gina@acme.com", "GINA-LT", ver="4.5.0.10", policy="Contractors"),        # unsupported (Windows < 4.7), old (2 minor behind)
    dev(8, "gina@acme.com", "GINA-2", ver="4.6.0.1", policy="Contractors"),          # drift, 1 minor behind: not old
    dev(9, "gina@acme.com", "GINA-3", policy="Contractors"),
    dev(10, "henry@acme.com", "HENRY-1"),                                              # the newest Windows version (4.7.2.5)
    dev(11, "henry@acme.com", "HENRY-2"), dev(12, "henry@acme.com", "HENRY-3"), dev(13, "henry@acme.com", "HENRY-4"),  # 4 devices: multi
    dev(14, "ivan@acme.com", "IVAN-MAC", typ=4, ver="4.5.2.1", policy="Corp Mac"),
    dev(15, "judy@acme.com", "JUDY-LT", reg="Removal Pending"),
    dev(16, "ken@acme.com", "KEN-LT", udid="SAME"), dev(17, "ken@acme.com", "KEN-LT2", udid="SAME"),
    dev(18, "lena@acme.com", "LENA-LT", reg="Unregistered", seen=ago(days=90)),        # unregistered: never a ghost
]
SERVICE_CSV_HEAD = '"User","Device type","UDID","Hostname","ZIA Status","ZPA Status","ZDX Status"\n'
SERVICE = {1: ("Inactive", "Inactive", "Active"), 2: ("Inactive", "N/A", "Active"), 3: ("Active", "Active", "Active"),
           7: ("Off", "On", "Off"), 9: ("Active", "Not entitled", "Active"), 10: ("Active", "Active", "Active")}


def service_csv(rows=SERVICE):
    out = SERVICE_CSV_HEAD
    for n, (zia, zpa, zdx) in rows.items():
        d = DEVICES[n - 1]
        out += f'"{d["user"]}","Windows","{d["udid"]}","{d["machineHostname"]}","{zia}","{zpa}","{zdx}"\n'
    return out


NAMES = sorted({d["user"] for d in DEVICES} | {d["machineHostname"] for d in DEVICES})


class Raw:
    """The assessment client: profiles, forwarding profiles, trusted
    networks and PAC files, with a cache like the real Client's."""

    def __init__(self, on_get=None, fwd_code=200):
        self.calls, self.cache, self.on_get, self.fwd_code = [], {}, on_get, fwd_code
        self.closed = False

    def get(self, ep, p=None):
        key = (ep, tuple(sorted((p or {}).items())))
        if key in self.cache:
            return self.cache[key]
        self.calls.append(ep)
        if self.on_get:
            self.on_get(ep)
        p = p or {}
        if ep == "/zcc/webPolicies":
            res = ([x for x in APP if x["device_type"] == p.get("deviceType")], 200)
        elif ep == "/zcc/forwardingProfiles":
            res = (FWD, 200) if self.fwd_code == 200 else ({"error": "forbidden"}, self.fwd_code)
        elif ep == "/zcc/trustedNetworks":
            res = ([], 200)
        elif ep == "/zia/pacFiles":
            res = (PACS, 200)
        else:
            res = ({"error": "no route"}, 404)
        self.cache[key] = res
        return res

    def close(self):
        self.closed = True


class Resp:
    def __init__(self, text, code=200):
        self.content, self.status_code, self.text = text.encode(), code, text


class SDK:
    """zscaler-sdk-python's shape: zcc.devices.list_devices(query_params)
    -> (items, response, error); get_request_executor() for the CSV."""

    def __init__(self, devices=DEVICES, csv_text=None, list_error=None, csv_error=None, on_call=None, model=False):
        self.pages, self.csv_calls, self.on_call = [], 0, on_call
        sdk = self

        class Devices:
            def list_devices(self, query_params=None):
                qp = query_params or {}
                sdk.pages.append(dict(qp))
                if sdk.on_call:
                    sdk.on_call("devices")
                if list_error:
                    return None, None, Exception(list_error)
                size, page = qp["page_size"], qp["page"]
                chunk = devices[(page - 1) * size: page * size]
                if model:
                    from zscaler.zcc.models.devices import Device
                    chunk = [Device(x) for x in chunk]
                return chunk, None, None

        class Executor:
            def create_request(self, method, endpoint, body=None, headers=None, params=None):
                assert method == "GET" and endpoint == zf.SERVICE_STATUS_ENDPOINT
                return {"url": endpoint}, None

            def execute(self, request, response_type=None, return_raw_response=False):
                assert return_raw_response
                sdk.csv_calls += 1
                if sdk.on_call:
                    sdk.on_call("csv")
                if csv_error:
                    return None, Exception(csv_error)
                return Resp(csv_text if csv_text is not None else service_csv()), None

        self.zcc = SimpleNamespace(devices=Devices())
        self._executor = Executor()

    def get_request_executor(self):
        return self._executor


def full_run(sdk=None, raw=None, logs=None, cancel=None):
    logs = logs if logs is not None else []
    return zf.run(raw or Raw(), SDK() if sdk is None else sdk, log=logs.append, cancel=cancel or threading.Event(), label="acme", now=NOW)


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    monkeypatch.setattr(zf, "PAGE_PAUSE_SECONDS", 0.0)


def _hosts(alert):
    return sorted(r["hostname"] for r in alert["rows"])


# ── heuristics at their boundaries ──────────────────────────────────────
def test_blind_spot_counts_exactly_24_hours_and_not_a_second_more():
    a = full_run()["alerts"]["blind_spot"]
    # ALICE-LT at exactly 24 h counts, BOB-LT at 24 h and a second does not; GINA-LT (ZIA off, seen an hour ago) counts.
    assert a["evaluated"] and _hosts(a) == ["ALICE-LT", "GINA-LT"], _hosts(a)


def test_bypass_risk_is_zia_inactive_while_zpa_active():
    a = full_run()["alerts"]["bypass_risk"]
    assert _hosts(a) == ["GINA-LT"]   # BOB-LT: ZIA off but ZPA not applicable; ALICE-LT: ZPA inactive too


def test_ghost_is_more_than_31_days_and_only_registered_devices():
    a = full_run()["alerts"]["ghost"]
    assert _hosts(a) == ["DAVE-LT"]   # CAROL-LT at exactly 31 days and the unregistered LENA-LT are not ghosts


def test_registration_anomalies_name_their_reason():
    rows = {r["hostname"]: r["reason"] for r in full_run()["alerts"]["registration_anomaly"]["rows"]}
    assert rows == {"ERIN-LT": "quarantined", "FRANK-LT": "registered, never seen", "JUDY-LT": "removal pending",
                    "KEN-LT": "device ID registered more than once", "KEN-LT2": "device ID registered more than once"}


def test_multi_device_users_are_more_than_three_devices():
    a = full_run()["alerts"]["multi_device"]
    assert [u["user"] for u in a["rows"]] == ["henry@acme.com"] and a["rows"][0]["devices"] == 4   # gina has 3: not flagged


def test_version_drift_old_and_unsupported_releases():
    al = full_run()["alerts"]
    drift = _hosts(al["version_drift"])
    assert drift == ["GINA-2", "GINA-LT"]   # IVAN-MAC is the newest macOS version, HENRY-1 the newest Windows one
    assert all(r["newest"] == "4.7.2.5" for r in al["version_drift"]["rows"])
    assert _hosts(al["old_version"]) == ["GINA-LT"]          # 4.5 is two minor versions behind 4.7; 4.6 is one
    assert _hosts(al["unsupported_version"]) == ["GINA-2", "GINA-LT"]   # Windows below 4.7 is out of support
    assert al["unsupported_version"]["definition"].startswith("A registered device on a release older than every release")


def test_old_release_on_a_lower_major_version():
    devs = zf.normalize_devices([dev(1, "a@x", "A", ver="3.9.0"), dev(2, "b@x", "B", ver="4.0.1")], [], NOW)
    assert [r["hostname"] for r in zf.device_alerts(devs, False)["old_version"]["rows"]] == ["A"]


def test_kpis_count_active_against_known_status_only():
    k = full_run()["kpis"]
    assert k["devices"] == len(DEVICES) and k["registered"] == 15
    assert k["registration_states"]["quarantined"] == 1 and k["registration_states"]["unregistered"] == 1
    zia = k["services"]["zia"]
    assert (zia["active"], zia["inactive"], zia["percent"]) == (3, 3, 50.0)
    zpa = k["services"]["zpa"]
    assert (zpa["active"], zpa["inactive"], zpa["not_applicable"]) == (3, 1, 2) and zpa["percent"] == 75.0
    assert k["newest"]["Windows"] == "4.7.2.5" and k["os_mix"]["Windows"] == 14


def test_parsers_for_time_registration_and_service_text():
    assert zf.parse_time(1761393600) == datetime(2025, 10, 25, 12, 0, tzinfo=timezone.utc)
    assert zf.parse_time("1761393600000") == datetime(2025, 10, 25, 12, 0, tzinfo=timezone.utc)
    assert zf.parse_time("2026-10-25 11:00:00 GMT") == NOW - timedelta(hours=1)
    assert zf.parse_time("2026-10-25T11:00:00Z") == NOW - timedelta(hours=1)
    assert zf.parse_time("Oct 25, 2026 11:00:00 AM") == NOW - timedelta(hours=1)
    assert zf.parse_time("") is None and zf.parse_time("soon") is None and zf.parse_time(0) is None
    assert [zf.registration(x) for x in ("Registered", "REMOVAL_PENDING", "6", "Unregistered", "removed", "?")] == [
        "registered", "removal_pending", "quarantined", "unregistered", "removed", "unknown"]
    assert [zf.service_state(x) for x in ("ON", "Inactive", "N/A", "Not entitled", "Disconnected", "weird")] == [
        "active", "inactive", "not_applicable", "not_applicable", "inactive", "unknown"]


def test_the_sdk_device_model_fields_are_read():
    """The real zscaler-sdk-python Device model, as list_devices returns it."""
    r = full_run(sdk=SDK(model=True))
    assert r["mode"] == "full" and r["alerts"]["ghost"]["rows"][0]["hostname"] == "DAVE-LT"
    d = next(x for x in r["devices"] if x["hostname"] == "HENRY-1")
    assert d["version"] == "4.7.2.5" and d["platform"] == "Windows" and d["profile"] == "Corp Windows" and d["registration"] == "registered"
    assert "udid" not in d and "macAddress" not in d and d["uid"]


def test_devices_are_paged_with_the_sdk_page_size(monkeypatch):
    monkeypatch.setattr(zf, "DEVICE_PAGE_SIZE", 5)
    sdk = SDK()
    r = full_run(sdk=sdk)
    assert [p["page"] for p in sdk.pages] == [1, 2, 3, 4] and all(p["page_size"] == 5 for p in sdk.pages)
    assert r["kpis"]["devices"] == len(DEVICES) and sdk.csv_calls == 1


# ── profiles, scores, drift and PAC ─────────────────────────────────────
def test_heatmap_checks_and_scores():
    r = full_run()
    p = {x["name"]: x for x in r["profiles"]}
    corp, con, mac = p["Corp Windows"], p["Contractors"], p["Corp Mac"]
    assert all(v["status"] in ("pass", "n/a") for v in corp["checks"].values()), corp["checks"]
    assert corp["score"] == 100.0 and corp["devices"] == 11   # registered only: not the quarantined or pending ones
    st = {k: v["status"] for k, v in con["checks"].items()}
    assert st["off_network_tunnel"] == "fail" and st["on_network_forwarding"] == "warn" and st["strict_enforcement"] == "fail"
    assert st["tamper_passwords"] == "fail" and st["bypass_breadth"] == "fail" and st["pac_direct"] == "fail" and st["endpoint_dlp"] == "warn"
    assert "dropbox" in con["checks"]["pac_direct"]["detail"] and "8.0.0.0/8" in con["checks"]["bypass_breadth"]["detail"]
    assert mac["checks"]["anti_tampering"]["status"] == "n/a" and con["devices"] == 3 and mac["devices"] == 1
    sc = r["scores"]
    assert sc["equal_weight"] == round((corp["score"] + con["score"] + mac["score"]) / 3, 1)
    want = round((corp["score"] * 11 + con["score"] * 3 + mac["score"] * 1) / 15, 1)
    assert sc["device_weighted"] == want and sc["device_weighted_exposure"] == round(100 - want, 1)


def test_profile_drift_is_a_side_by_side_diff_with_secrets_masked():
    r = full_run()
    pids = {p["name"]: p["pid"] for p in r["profiles"]}
    d = zf.diff_from_result(r, pids["Corp Windows"], pids["Contractors"])
    rows = {x["key"]: x for x in d["rows"]}
    assert rows["strictEnforcement"]["a"] == "1" and rows["strictEnforcement"]["b"] == "0" and not rows["strictEnforcement"]["same"]
    assert rows["device_type"]["same"] and d["differences"] == sum(not x["same"] for x in d["rows"])
    assert rows["uninstallPassword"]["a"] == "(set)" and rows["uninstallPassword"]["b"] == "(not set)"
    assert "hunter2" not in str(d) and "zia-off-pass" not in str(d) and "hunter2" not in str(r)
    assert d["unified"].startswith("--- Corp Windows") and '-  "strictEnforcement": 1,' in d["unified"]
    with pytest.raises(KeyError):
        zf.diff_from_result(r, pids["Corp Windows"], "p99")


def test_pac_comparison_lists_direct_entries_per_profile_risky_first():
    m = full_run()["pac"]["matrix"]
    assert [c["name"] for c in m["columns"]] == ["Corp Windows", "Contractors"]
    first = m["rows"][0]
    assert first["value"] == ".dropbox.com" and first["risk"] == "data-channel" and not first["everywhere"]
    shared = next(e for e in m["rows"] if e["value"] == "*.intranet.acme.com")
    assert shared["everywhere"] and len(shared["profiles"]) == 2
    assert m["risky"] == 1 and m["differing"] >= 1
    assert {c["name"]: c["default"] for c in m["columns"]} == {"Corp Windows": "proxy", "Contractors": "proxy"}


def test_remediation_is_ranked_by_impact_times_devices():
    plan = full_run()["plan"]
    assert [x["rank"] for x in plan] == list(range(1, len(plan) + 1))
    assert all(plan[i]["priority"] >= plan[i + 1]["priority"] for i in range(len(plan) - 1))
    # Registration anomalies: impact 2 x 5 devices = 10, then Contractors (3 devices) failing impact-3 checks: 9 each.
    assert (plan[0]["check"], plan[0]["priority"]) == ("registration_anomaly", 10)
    assert [x["priority"] for x in plan[1:4]] == [9, 9, 9] and all("Contractors" in x["title"] for x in plan[1:4])
    blind = next(x for x in plan if x["check"] == "blind_spot")
    assert blind["priority"] == 6 and blind["devices"] == 2 and blind["fix"]
    ghost = next(x for x in plan if x["check"] == "ghost")
    assert ghost["priority"] == 1 and ghost["impact"] == 1
    warn = next(x for x in plan if x["check"] == "on_network_forwarding")
    assert warn["impact"] == 0.5 and warn["priority"] == 1.5
    assert not any("Corp Windows" in x["title"] for x in plan)


# ── fallbacks: never zeros as if healthy ─────────────────────────────────
def test_no_device_permission_falls_back_to_configuration_only():
    logs = []
    r = full_run(sdk=SDK(list_error="HTTP 403 Forbidden"), logs=logs)
    assert r["mode"] == "configuration" and r["kpis"] is None and "not zero" in r["banner"]
    assert "permission" in r["telemetry"]["reason"] and "403" in r["telemetry"]["reason"]
    assert all(not a["evaluated"] and a["count"] is None for a in r["alerts"].values())
    assert r["scores"]["device_weighted"] is None and r["scores"]["equal_weight"] is not None
    assert all(p["devices"] is None for p in r["profiles"])
    assert r["plan"] and all(x["kind"] == "profile" and not x["device_count_known"] for x in r["plan"])
    assert any("falls back to configuration only" in line for line in logs)


def test_no_service_status_shows_devices_but_not_service_activity():
    r = full_run(sdk=SDK(csv_error="429 Too Many Requests"))
    assert r["mode"] == "devices" and r["kpis"]["devices"] == len(DEVICES)
    assert all(v["percent"] is None and not v["available"] for v in r["kpis"]["services"].values())
    assert not r["alerts"]["blind_spot"]["evaluated"] and not r["alerts"]["bypass_risk"]["evaluated"]
    assert r["alerts"]["ghost"]["evaluated"] and "rate limited" in r["telemetry"]["service_reason"]


def test_a_service_file_without_service_columns_is_not_read_as_healthy():
    r = full_run(sdk=SDK(csv_text='"User","Device type","Something"\n"a","b","c"\n'))
    assert r["mode"] == "devices" and r["kpis"]["services"]["zia"]["percent"] is None


def test_classic_sign_in_is_configuration_only():
    r = zf.run(Raw(), None, log=lambda s: None, cancel=threading.Event(), sdk_reason="classic sign-in", now=NOW)
    assert r["mode"] == "configuration" and "classic sign-in" in r["banner"]


def test_unread_forwarding_profiles_are_unknown_not_failed():
    r = full_run(raw=Raw(fwd_code=403))
    p = r["profiles"][0]
    assert p["checks"]["forwarding_linked"]["status"] == "unknown" and p["checks"]["off_network_tunnel"]["status"] == "unknown"


# ── Stop and personal data ───────────────────────────────────────────────
def test_stop_during_the_profile_read_sends_nothing_more():
    ev = threading.Event()
    raw = Raw(on_get=lambda ep: ev.set() if ep == "/zcc/forwardingProfiles" else None)
    sdk = SDK()
    r = full_run(sdk=sdk, raw=raw, cancel=ev)
    assert r["status"] == "stopped" and r["stopped"] == zf.STOPPED_REASON and "profiles" not in r
    assert raw.calls[-1] == "/zcc/forwardingProfiles" and not sdk.pages and not sdk.csv_calls


def test_stop_between_device_pages_reads_no_service_status(monkeypatch):
    monkeypatch.setattr(zf, "DEVICE_PAGE_SIZE", 5)
    ev = threading.Event()
    sdk = SDK(on_call=lambda what: ev.set())
    r = full_run(sdk=sdk, cancel=ev)
    assert r["status"] == "stopped" and len(sdk.pages) == 1 and sdk.csv_calls == 0 and "devices" not in r


def test_no_user_or_device_name_reaches_a_log(caplog):
    logs = []
    with caplog.at_level(logging.DEBUG):
        r = full_run(logs=logs)
        full_run(sdk=SDK(list_error="403 for alice@acme.com"), logs=logs)
    assert r["mode"] == "full" and logs
    text = "\n".join(logs) + "\n" + caplog.text
    leaked = [n for n in NAMES if n.lower() in text.lower()]
    assert not leaked, leaked
    assert "<user>" not in text or "alice" not in text


# ── exports ──────────────────────────────────────────────────────────────
def test_exports_through_csv_safe_and_counts_only_drops_names():
    r = full_run()
    _, plan = zf.export_csv(r, "plan", False)
    assert plan.splitlines()[0].startswith("Rank,Priority,Impact,Devices") and "Contractors" in plan
    _, devices = zf.export_csv(r, "devices", False)
    assert "ALICE-LT" in devices and "alice@acme.com" in devices
    with pytest.raises(ValueError):
        zf.export_csv(r, "devices", True)
    _, summary = zf.export_csv(r, "summary", True)
    assert not [n for n in NAMES if n in summary + plan], "the summary and plan carry counts, not names"
    assert "Blind spots,2" in summary and "Service active %,ZIA,50.0" in summary
    evil = dict(r, plan=[dict(r["plan"][0], title="=HYPERLINK(1)")])
    assert "'=HYPERLINK" in zf.export_csv(evil, "plan", False)[1]


# ── the API ──────────────────────────────────────────────────────────────
def _api(monkeypatch, sdk=None, raw=None):
    built = []
    raw = raw or Raw()

    def build_client(req):
        built.append("client")
        return raw
    monkeypatch.setattr(srv, "_build_client", build_client)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (built.append("sdk"), sdk or SDK())[1])
    return TestClient(srv.app), built, raw


def _follow(t, job_id):
    for _ in range(200):
        snap = t.get(f"/api/dlp-packs/jobs/{job_id}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("scope", [{"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True},
                                   {"scopes": [], "channels": {}, "from_page": True}])
def test_refused_before_sign_in_when_zcc_is_not_in_scope(monkeypatch, scope):
    t, built, _ = _api(monkeypatch)
    r = t.post("/api/zcc/fleet/start", json=dict(CREDS, **scope))
    assert r.status_code == 400 and "not in scope" in r.json()["detail"] and "ZCC" in r.json()["detail"]
    assert not built


def test_the_job_runs_exports_and_diffs(monkeypatch):
    t, built, raw = _api(monkeypatch)
    r = t.post("/api/zcc/fleet/start", json=dict(CREDS, **ZCC_SCOPE))
    assert r.status_code == 200 and r.json()["kind"] == "fleet" and built == ["client", "sdk"]
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["mode"] == "full" and raw.closed
    assert not [n for n in NAMES if n in "\n".join(snap["logs"])]
    jid = snap["job_id"]
    plan = t.get(f"/api/zcc/fleet/{jid}/export?what=plan")
    assert plan.status_code == 200 and plan.headers["content-type"].startswith("text/csv") and "zcc_fleet_plan" in plan.headers["content-disposition"]
    assert t.get(f"/api/zcc/fleet/{jid}/export?what=devices&counts_only=true").status_code == 400
    summ = t.get(f"/api/zcc/fleet/{jid}/export?what=summary&counts_only=true")
    assert summ.status_code == 200 and "_counts_" in summ.headers["content-disposition"] and "alice" not in summ.text
    assert t.get(f"/api/zcc/fleet/{jid}/export?what=plan&format=xlsx").status_code == 400
    pids = [p["pid"] for p in snap["result"]["profiles"]]
    d = t.get(f"/api/zcc/fleet/{jid}/diff?a={pids[0]}&b={pids[1]}")
    assert d.status_code == 200 and d.json()["differences"] > 0
    assert t.get(f"/api/zcc/fleet/{jid}/diff?a={pids[0]}&b=nope").status_code == 400
    assert t.get("/api/zcc/fleet/nope/export").status_code == 404


def test_a_stop_before_the_job_exists_reads_nothing(monkeypatch):
    t, built, raw = _api(monkeypatch)
    token = "fleettoken123"
    assert t.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}).json()["pending"]
    r = t.post("/api/zcc/fleet/start", json=dict(CREDS, **ZCC_SCOPE), headers={"X-Start-Token": token})
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "cancelled" and snap["result"]["status"] == "stopped" and raw.calls == []
    assert any("Stop requested before the run started" in line for line in snap["logs"])


def test_stop_message_says_nothing_more_is_read():
    import pack_jobs
    gate = threading.Event()
    job = pack_jobs.start("fleet", lambda log, cancel: (gate.wait(5), {"status": "stopped", "stopped": "x"})[1])
    assert pack_jobs.cancel(job.id)
    gate.set()
    assert any("nothing more is read" in line for line in job.logs)


def test_classic_sign_in_does_not_build_an_sdk_client(monkeypatch):
    t, built, _ = _api(monkeypatch)
    body = {"auth_method": "legacy", "username": "admin@acme.com", "password": "pw-pw-pw-pw", "api_key": "a" * 12, "cloud": "zscalerthree", **ZCC_SCOPE}
    r = t.post("/api/zcc/fleet/start", json=body)
    assert r.status_code == 200, r.text
    snap = _follow(t, r.json()["job_id"])
    assert built == ["client"] and snap["result"]["mode"] == "configuration" and "classic ZIA API" in snap["result"]["banner"]


def test_the_page_is_served_and_explained():
    t = TestClient(srv.app)
    page = t.get("/report/fleet")
    assert page.status_code == 200 and "Client Connector fleet" in page.text and "/static/zcc_fleet.js" in page.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', 'role="status"', "aria-live"):
        assert needle in page.text, needle
    import os
    js = open(os.path.join(os.path.dirname(srv.__file__), "static", "explain.js"), encoding="utf-8").read()
    assert "'/report/fleet': 'fleet'" in js and "X.fleet = {" in js and "'fleet'" in js.split("DLP_EXPLAIN_ORDER")[1][:600]
