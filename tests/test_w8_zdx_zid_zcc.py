"""ZDX, ZIdentity and Client Connector completion (work package w8 zdx-zid-zcc).

Checks: the ZDX alert history with affected devices counted, application
scores below 66 for 7 days, availability and page fetch time; ZIdentity
admins with broad entitlements and stale admins; Client Connector
process-based and custom IP-based bypass breadth. Reads: the ZDX cloud path
(no device named, private hops masked), a ZDX score analysis (rate-limited,
audited, behind every write gate), one Client Connector device's details
(identifiers hidden, one-time passwords never read into the answer) and the
disable-reason report as counts (no person listed, spreadsheet-safe CSV).
Writes through the Bulk changes engine: ZIdentity group members, Client
Connector app profiles on or off and their DNS and tunnel settings, each
with preview, plan hash, re-read, read-back and Undo. Snapshots keep the
new reads (ids only for devices and members).

Everything runs on the made-up sample tenant (offline_tenant, no network
code) or on small fakes; nothing reaches a tenant or the network."""
from __future__ import annotations

import copy
import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import offline_tenant as ot
import ops_zcc_live as live
import ops_zid_groups as ops_zid   # (the ZIdentity group members module; ops_zid.py is the users and API clients one)
import sample_tenant
import zcc_devices as zd
import zdx_insights as zi
import zscaler_full_checks as zfc
import zscaler_zdx_checks as zx
import zscaler_zidentity_checks as zid

ASSESSOR = "Jane Doe"
LOGINS = [u["loginName"] for u in sample_tenant.ZID_USERS]


@pytest.fixture
def sample(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    zi.reset_rate()
    st = ot.sample_store(reset=True)
    yield st
    ot.sample_store(reset=True)
    zi.reset_rate()


def raw(st):
    return ot.OfflineRawClient(st, ot.creds_for(st))


def sdk(st):
    return ot.OfflineSdkClient(st, ot.creds_for(st))


def check(reg, cid):
    return next(fn for c, _s, _l, fn in reg if c == cid)


class Answers:
    """A raw client answering fixed bodies per short endpoint (anything else 404)."""

    def __init__(self, table):
        self.table = table
        self.asked = []

    def get(self, ep, params=None):
        self.asked.append(ep)
        for key, ans in self.table.items():
            if ep == key or (key.endswith("*") and ep.startswith(key[:-1])):
                return copy.deepcopy(ans)
        return {"error": "not found"}, 404


# ── ZDX checks ─────────────────────────────────────────────────────────

def test_zdx_alert_history_counts_affected_devices_and_never_names_them(sample):
    """ASVS V8.3.4 · CWE-359 · WSTG-INFO-05: the 14-day alert history is judged and the devices each alert touched are counted; no device or person name is in the finding."""
    # Act
    r = check(zx.ZDX_REG, "ZDX.9")(raw(sample))
    # Assert
    assert r.status == "REVIEW" and "2 ZDX alert(s)" in r.detail and "touching 2 device(s)" in r.detail
    for name in ("LKF-LT-0001", "LKF-MBP-0002", "avery", "rowan"):
        assert name not in r.detail
    assert "Best Practice:" in r.detail and "Why it matters:" in r.detail


def test_zdx_scores_flag_only_an_application_that_never_reached_66_in_7_days(sample):
    """ASVS V1.14.1 · CWE-697: an application whose score stayed below 66 all week is named; one that dipped but recovered is not."""
    # Act
    r = check(zx.ZDX_REG, "ZDX.10")(raw(sample))
    # Assert
    assert r.status == "REVIEW" and "1 of 3" in r.detail and "Freight billing" in r.detail
    assert "Microsoft 365" not in r.detail and "Salesforce" not in r.detail


def test_zdx_metrics_flag_low_availability_and_slow_page_fetch(sample):
    """ASVS V1.14.1 · CWE-697: availability under 99% and an average page fetch time over 5 s are named with their values."""
    # Act
    r = check(zx.ZDX_REG, "ZDX.11")(raw(sample))
    # Assert
    assert r.status == "REVIEW" and "Freight billing (97.4%)" in r.detail and "Freight billing (6.0 s)" in r.detail


@pytest.mark.parametrize("cid", ["ZDX.9", "ZDX.10", "ZDX.11"])
def test_zdx_checks_are_not_applicable_when_zdx_is_not_licensed(cid):
    """ASVS V1.14.1 · CWE-754: a tenant without ZDX (HTTP 404) is not applicable, outside the score, never a finding."""
    # Act
    r = check(zx.ZDX_REG, cid)(Answers({}))
    # Assert
    assert r.status == "INFO" and r.detail.startswith("Not applicable")


def test_zdx_untrusted_scores_never_crash_or_count():
    """ASVS V5.1.4 · CWE-1287 · WSTG-INPV-13: NaN, infinity, booleans, text and the -1 "no data" mark in a score trend are ignored."""
    # Arrange
    apps = ([{"id": 1, "name": "A"}], 200)
    bad = ({"metric": "score", "datapoints": [{"value": "NaN"}, {"value": float("inf")}, {"value": True}, {"value": "x"}, {"value": -1}, {"value": 90}]}, 200)
    cl = Answers({"/zdx/administration/apps": apps, "/zdx/apps/1/score": bad})
    # Act
    r = check(zx.ZDX_REG, "ZDX.10")(cl)
    # Assert
    assert r.status == "PASS"


def test_zdx_alert_ids_from_the_tenant_are_checked_before_they_reach_a_path():
    """ASVS V5.1.3 · CWE-22 · WSTG-INPV-12: an alert id with a slash or dots is never put into an API path."""
    # Arrange
    cl = Answers({"/zdx/alerts/historical": ({"alerts": [{"id": "../../zia/x"}, {"id": "7401"}]}, 200),
                  "/zdx/alerts/7401/affected_devices": ({"devices": [{"id": 1}]}, 200)})
    # Act
    check(zx.ZDX_REG, "ZDX.9")(cl)
    # Assert
    assert not any(".." in a for a in cl.asked) and "/zdx/alerts/7401/affected_devices" in cl.asked


# ── ZIdentity checks ───────────────────────────────────────────────────

def test_zid_stale_admin_is_counted_and_not_named(sample):
    """ASVS V4.1.3 · ASVS V8.3.4 · CWE-269 · CWE-359: a disabled account that still holds an admin entitlement fails the check; it is counted, never named."""
    # Act
    r = check(zid.ZID_REG, "ZID.7")(raw(sample))
    # Assert
    assert r.status == "FAIL" and "1 stale admin(s) of 3" in r.detail
    assert not any(n.split("@")[0] in r.detail for n in LOGINS) and "Casey" not in r.detail


def test_zid_broad_entitlements_reads_every_admin_and_flags_many_full_access_admins():
    """ASVS V4.1.3 · CWE-250 · CWE-269: every admin's entitlements are read; full-access roles or three services or more count as broad, and too many broad admins is a finding."""
    # Arrange
    users = [{"id": f"u{i}", "adminEntitlementEnabled": True, "status": True} for i in range(4)]
    sup = [{"roles": [{"name": "Super Admin"}], "service": {"serviceName": "ZIA"}}]
    wide = [{"roles": [{"name": "Viewer"}], "service": {"serviceName": s}} for s in ("ZIA", "ZPA", "ZDX")]
    narrow = [{"roles": [{"name": "Viewer"}], "service": {"serviceName": "ZIA"}}]
    cl = Answers({"/zid/users": ({"records": users}, 200), "/zid/users/u0/admin-entitlements": (sup, 200),
                  "/zid/users/u1/admin-entitlements": (sup, 200), "/zid/users/u2/admin-entitlements": (wide, 200),
                  "/zid/users/u3/admin-entitlements": (narrow, 200)})
    # Act
    r = check(zid.ZID_REG, "ZID.6")(cl)
    # Assert
    assert r.status == "REVIEW" and "3 of 4" in r.detail and "2 with a full-access role" in r.detail and "1 entitled on 3" in r.detail
    assert sum(1 for a in cl.asked if a.endswith("/admin-entitlements")) == 4


def test_zid_entitlement_reads_never_put_an_unsafe_user_id_into_a_path():
    """ASVS V5.1.3 · CWE-22: a user id with a slash is never read as a path."""
    # Arrange
    cl = Answers({"/zid/users": ({"records": [{"id": "../x", "adminEntitlementEnabled": True}]}, 200)})
    # Act
    r = check(zid.ZID_REG, "ZID.6")(cl)
    # Assert
    assert not any(".." in a for a in cl.asked) and r.status == "INFO"


# ── Client Connector bypass breadth ────────────────────────────────────

def test_process_bypass_breadth_flags_wildcards_and_interpreters_only(sample):
    """ASVS V1.14.6 · CWE-183 · CWE-693: a process bypass with a wildcard or a shell, script engine or browser fails; a named program passes."""
    # Act
    r = check(zfc.PLATFORM_REG, "ZCC.27")(raw(sample))
    # Assert
    assert r.status == "FAIL" and "1 of 2" in r.detail and "Contractor tools" in r.detail and "Depot scanner" not in r.detail
    assert zfc.process_bypass_reasons({"fileNames": ["scanagent.exe"], "filePaths": ["C:\\Program Files\\Depot Scan\\"]}) == []
    assert zfc.process_bypass_reasons({"fileNames": [], "filePaths": ["C:\\"]}) == ["a whole drive or system folder is bypassed"]


def test_custom_ip_bypass_breadth_flags_wide_ranges_and_every_port(sample):
    """ASVS V1.14.6 · CWE-183 · CWE-693: a custom IP bypass wider than /16, the whole internet, or every port and protocol on a wide range fails; a /24 on one port passes."""
    # Act
    r = check(zfc.PLATFORM_REG, "ZCC.28")(raw(sample))
    # Assert
    assert r.status == "FAIL" and "Legacy partner network" in r.detail and "Depot printers" not in r.detail
    assert zfc.ip_bypass_reasons({"appDataBlob": [{"ipaddr": "10.20.0.0/20", "port": "", "proto": ""}]}) == ["every port and protocol to 10.20.0.0/20"]
    assert zfc.ip_bypass_reasons({"appDataBlobV6": [{"ipaddr": "::/0"}]}) == ["the whole internet (::/0)"]
    assert zfc.ip_bypass_reasons({"appDataBlob": [{"ipaddr": "not-an-ip"}]}) == []


@pytest.mark.parametrize("cid", ["ZCC.27", "ZCC.28"])
def test_bypass_breadth_is_not_applicable_when_the_feature_is_missing(cid):
    """ASVS V1.14.1 · CWE-754: HTTP 404 (not licensed or enabled) is not applicable, never a finding."""
    # Act
    r = check(zfc.PLATFORM_REG, cid)(Answers({}))
    # Assert
    assert r.status == "INFO" and r.detail.startswith("Not applicable")


# ── ZDX cloud path and score analysis ──────────────────────────────────

def test_cloud_path_names_no_device_and_masks_private_hops_and_mac_addresses(sample):
    """ASVS V8.3.4 · CWE-359 · CWE-200 · WSTG-INFO-05: the measured path names no device or person, private hop addresses are masked, and no MAC address or vendor is returned."""
    # Act
    out = zi.cloudpath(sdk(sample), "3002")
    text = json.dumps(out)
    # Assert
    assert len(out["legs"]) == 3 and out["legs"][0]["from"] == "the device" and out["legs"][2]["to"] == "the application"
    assert "private address" in text and "192.168.1.1" not in text and "198.51.100.1" in text
    for leak in ("LKF-", "gw_mac", "00:00:5e", "Example Networks", "userid", "3101", "3102"):
        assert leak not in text, leak
    assert "slowest leg is the Zscaler service edge to the application" in out["verdict"] and "2.5%" in out["verdict"]


def test_cloud_path_suggests_the_application_matching_the_destination(sample):
    """ASVS V5.1.3 · CWE-20: the application whose name shares a word with the destination is suggested; an unrelated host suggests none."""
    # Act / Assert
    assert zi.apps(sdk(sample), "billing.larkspur-freight.example")["suggested"] == "3002"
    assert zi.apps(sdk(sample), "example.org")["suggested"] is None
    with pytest.raises(zi.InsightError):
        zi.cloudpath(sdk(sample), "3002/../x")


def test_score_analysis_is_rate_limited_and_audited_with_the_actor(sample, tmp_path):
    """ASVS V11.1.4 · ASVS V7.2.2 · CWE-770 · CWE-778 · WSTG-BUSL-05: a second start within 5 minutes is refused before ZDX is asked; every start, refusal and stop is in the audit log with the actor."""
    # Arrange
    client = sdk(sample)
    # Act
    first = zi.start_analysis(client, "3002", tenant_key="t", actor="writer@example.com", assessor=ASSESSOR, now=1_000_000)
    with pytest.raises(zi.RateLimited):
        zi.start_analysis(client, "3002", tenant_key="t", actor="writer@example.com", assessor=ASSESSOR, now=1_000_010)
    later = zi.start_analysis(client, "3002", tenant_key="t", actor="writer@example.com", assessor=ASSESSOR, now=1_000_000 + zi.RCA_MIN_INTERVAL + 1)
    zi.stop_analysis(client, later["analysis_id"], actor="writer@example.com", assessor=ASSESSOR)
    # Assert
    lines = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    events = [x["event"] for x in lines]
    assert first["analysis_id"] and events == ["zdx_analysis_start", "zdx_analysis_refused", "zdx_analysis_start", "zdx_analysis_stop"]
    assert all(x["actor"] == "writer@example.com" and x["assessor"] == ASSESSOR for x in lines)
    posted = [p for p in sample.responses["/zdx/v1/analysis"]["body"]]
    assert len(posted) == 1   # two starts, one stopped (deleted)


def test_the_hourly_cap_holds_even_when_starts_are_spaced(sample):
    """ASVS V11.1.4 · CWE-770: at most RCA_MAX_PER_HOUR starts per tenant in an hour, however they are spaced."""
    # Arrange
    t0 = 2_000_000
    for i in range(zi.RCA_MAX_PER_HOUR):
        assert zi.rate_check("t2", now=t0 + i * zi.RCA_MIN_INTERVAL, record=True) is None
    # Act
    why = zi.rate_check("t2", now=t0 + zi.RCA_MAX_PER_HOUR * zi.RCA_MIN_INTERVAL)
    # Assert
    assert why and "in the last hour" in why
    assert zi.rate_check("other", now=t0) is None


def test_the_analysis_status_answer_is_scrubbed_and_bounded():
    """ASVS V8.3.4 · ASVS V5.1.4 · CWE-359 · CWE-400: personal and secret fields are dropped, strings and lists are capped, depth is bounded."""
    # Arrange
    deep = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
    body = {"status": "DONE", "userName": "x", "email": "y", "hostname": "h", "token": "t", "findings": ["z" * 999] * 80, **deep}
    # Act
    out = zi._safe(body)
    # Assert
    assert set(out) == {"status", "findings", "a"} and len(out["findings"]) == 50 and len(out["findings"][0]) == 300
    assert out["a"]["b"]["c"]["d"] == {"e": None}


# ── Client Connector device details and disable reasons ────────────────

def test_device_details_hide_identifiers_and_never_carry_one_time_passwords(sample):
    """ASVS V8.3.4 · ASVS V8.1.1 · CWE-200 · CWE-312 · WSTG-INFO-05: the serial number and external id are hidden, and the device's OTPs never reach the answer, not even as a count."""
    # Act
    out = zd.device_details(sdk(sample), "LKF-WIN-0001")
    text = json.dumps(out)
    # Assert
    assert out["found"] and any(r["label"] == "Serial number" and r["value"] == "hidden" for r in out["rows"])
    for leak in ("SN-INVENTED", "ext-0001", "000000", "111111", "Otp", "otp", "avery"):
        assert leak not in text, leak


def test_device_details_name_what_needs_a_look(sample):
    """ASVS V1.14.1 · WCAG 2.2 SC 1.4.1: an inactive or failing service, strict enforcement off and low trust are called out in words."""
    # Act
    out = zd.device_details(sdk(sample), "LKF-WIN-0003")
    # Assert
    assert out["summary"].startswith("Needs a look:") and "Strict enforcement" in out["summary"] and "Device trust level" in out["summary"]


@pytest.mark.parametrize("udid", ["", "a/b", "x" * 129, "<script>", "id\nnext"])
def test_device_details_refuse_a_malformed_device_id(sample, udid):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a device id outside the UDID alphabet or length is refused before any read."""
    # Act / Assert
    with pytest.raises(zd.DeviceError):
        zd.device_details(sdk(sample), udid)


def test_disable_reasons_are_counted_and_no_person_is_listed(sample):
    """ASVS V8.3.4 · CWE-359 · WSTG-INFO-05: the disable-reason report becomes counts per reason, device type and service; no user name or email appears, in JSON or CSV."""
    # Act
    counts = zd.disable_reasons(raw(sample))
    text = json.dumps(counts) + zd.disable_reasons_csv(counts)
    # Assert
    assert counts["events"] == 4 and counts["people"] == 3
    assert {"reason": "VPN conflict", "device_type": "Windows", "service": "ZIA", "times": 1, "people": 1} in counts["rows"]
    assert "@" not in text and "jordan" not in text and "ThinkPad" not in text


def test_the_disable_reason_csv_is_safe_for_spreadsheets():
    """ASVS V5.3.10 (formula injection) · CWE-1236 · WSTG-INPV-11: a reason that starts with = + - @ is written so a spreadsheet never runs it."""
    # Arrange
    text = '"User","Device type","Disable reason","Service"\r\n"a@x","Windows","=HYPERLINK(""http://x"")","ZIA"\r\n'
    # Act
    rows = list(csv.reader(io.StringIO(zd.disable_reasons_csv(zd.parse_disable_reasons(text)))))
    # Assert
    assert rows[1][0][0] not in "=+-@" and "HYPERLINK" in rows[1][0]


def test_an_oversized_or_unreadable_disable_reason_report_is_refused():
    """ASVS V5.1.4 · ASVS V12.1.1 · CWE-400 · CWE-20: a report over 5 MB or without a reason column is refused, not half read."""
    # Act / Assert
    with pytest.raises(zd.DeviceError):
        zd.parse_disable_reasons("x" * (zd.MAX_CSV_BYTES + 1))
    with pytest.raises(zd.DeviceError):
        zd.parse_disable_reasons('"User","Device type"\r\n"a","b"\r\n')
    assert zd.parse_disable_reasons("")["rows"] == []


# ── ZIdentity group members (engine) ───────────────────────────────────

ZID_SCOPE = ao.scope_for(["zidentity"], {})


def _apply(client, spec, scope, phrase=None):
    p = ao.plan(client, spec, scope=scope, tenant_label="sample")
    return p, ao.execute(client, spec, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True,
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase, assessor=ASSESSOR)


def test_group_members_preview_writes_nothing_and_asks_for_the_groups_name(sample):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06: the preview reads only; the typed confirmation is the group's name; unknown and disabled accounts are excluded with the reason."""
    # Arrange
    spec = {"type": "zid_group_members", "group": "g-33", "add": [LOGINS[0], LOGINS[2], "nobody@x.example"], "remove": [LOGINS[1]]}
    # Act
    p = ao.plan(sdk(sample), spec, scope=ZID_SCOPE)
    # Assert
    assert sample.writes == 0 and p["status"] == "ready" and p["confirm_phrase"] == "FINANCE TEAM"
    reasons = {u["object"]["name"]: (u["status"], u["reason"]) for u in p["items"]}
    assert reasons[LOGINS[2]] == ("excluded", "the account is disabled") and reasons["nobody@x.example"][0] == "excluded"
    assert any("synced from the identity provider" in w for w in p["warnings"])


def test_group_members_apply_reads_back_and_undo_restores_the_group(sample):
    """ASVS V11.1.1 · ASVS V7.2.2 · CWE-841 · CWE-778: apply re-reads each membership, writes, reads back; Undo is the opposite change and restores the members."""
    # Arrange
    client = sdk(sample)
    before = copy.deepcopy(sample.responses["/ziam/admin/api/v1/groups/g-33/users"]["body"]["records"])
    spec = {"type": "zid_group_members", "group": "g-33", "add": [LOGINS[0]], "remove": [LOGINS[1]]}
    # Act
    _p, r = _apply(client, spec, ZID_SCOPE)
    _p2, r2 = _apply(client, r["inverse"], ZID_SCOPE)
    # Assert
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 2
    assert r["inverse"] == {"type": "zid_group_members", "group": "g-33", "add": [LOGINS[1]], "remove": [LOGINS[0]]}
    assert r2["status"] == "applied"
    assert sorted(x["id"] for x in sample.responses["/ziam/admin/api/v1/groups/g-33/users"]["body"]["records"]) == sorted(x["id"] for x in before)


def test_group_members_without_the_typed_name_or_write_mode_write_nothing(sample):
    """ASVS V4.1.3 · ASVS V11.1.1 · CWE-841 · CWE-862: without write mode it raises; with the wrong typed name it is refused; nothing is written either way."""
    # Arrange
    client = sdk(sample)
    spec = {"type": "zid_group_members", "group": "g-33", "add": [LOGINS[0]]}
    p = ao.plan(client, spec, scope=ZID_SCOPE)
    # Act
    with pytest.raises(PermissionError):
        ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZID_SCOPE, writes_enabled=False, confirm_text="FINANCE TEAM", assessor=ASSESSOR)
    wrong = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZID_SCOPE, writes_enabled=True, confirm_text="FINANCE", assessor=ASSESSOR)
    # Assert
    assert wrong["status"] == "refused" and sample.writes == 0


def test_group_members_out_of_scope_is_refused_before_any_read(sample):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: with ZIdentity not ticked nothing is read."""
    # Arrange
    class Boom:
        def __getattr__(self, name):
            raise AssertionError("read out of scope")
    # Act / Assert
    with pytest.raises(ao.OperationError):
        ao.plan(Boom(), {"type": "zid_group_members", "group": "g-33", "add": [LOGINS[0]]}, scope=ao.scope_for(["zcc"], {}))


def test_group_members_refuses_a_dynamic_group_and_bad_names(sample):
    """ASVS V5.1.3 · CWE-20 · CWE-284: a dynamic group blocks the plan; a malformed sign-in name, too many names, or one name on both sides is refused."""
    # Arrange
    sample.responses["/ziam/admin/api/v1/groups"]["body"]["records"][0]["isDynamicGroup"] = True
    # Act
    p = ao.plan(sdk(sample), {"type": "zid_group_members", "group": "g-33", "add": [LOGINS[0]]}, scope=ZID_SCOPE)
    # Assert
    assert p["status"] == "blocked" and "dynamic group" in p["blockers"][0]
    for bad in ({"add": ["a b<c>"]}, {"add": [f"u{i}@x.example" for i in range(51)]}, {"add": [LOGINS[0]], "remove": [LOGINS[0].upper()]}, {}):
        with pytest.raises(ao.OperationError):
            ops_zid.normalize(dict({"group": "g-33"}, **bad))


def test_group_members_the_same_change_made_meanwhile_is_not_sent_again(sample, monkeypatch):
    """ASVS V11.1.6 · CWE-362 · CWE-367: a membership someone else changed after the re-plan is read again right before the write and not sent again."""
    # Arrange
    client = sdk(sample)
    spec = {"type": "zid_group_members", "group": "g-33", "remove": [LOGINS[1]]}
    p = ao.plan(client, spec, scope=ZID_SCOPE)
    real = ao.plan
    calls = {"n": 0}

    def plan_then_change(*a, **k):
        out = real(*a, **k)
        calls["n"] += 1
        sample.responses["/ziam/admin/api/v1/groups/g-33/users"]["body"]["records"] = []   # removed by someone else
        return out
    monkeypatch.setattr(ao, "plan", plan_then_change)
    # Act
    r = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZID_SCOPE, writes_enabled=True, confirm_text="FINANCE TEAM", assessor=ASSESSOR)
    # Assert
    assert calls["n"] == 1 and r["items"][0]["status"] == "noop" and sample.writes == 0


# ── Client Connector live changes (engine) ─────────────────────────────

ZCC_SCOPE = ao.scope_for(["zcc"], {})


def test_turning_an_app_profile_off_is_live_typed_read_back_and_undone(sample):
    """ASVS V11.1.1 · ASVS V7.2.2 · CWE-841: the profile's name is typed even for one change; the state is read back; Undo turns it on again."""
    # Arrange
    client = sdk(sample)
    spec = {"type": "zcc_app_profile_state", "targets": [{"id": "1203", "platform": "windows", "to": "off"}]}
    # Act
    p, r = _apply(client, spec, ZCC_SCOPE)
    _p2, r2 = _apply(client, r["inverse"], ZCC_SCOPE)
    # Assert
    assert p["confirm_phrase"] == "WINDOWS - CONTRACTORS" and r["status"] == "applied" and r["verification"]["confirmed"] == 1
    assert r2["status"] == "applied" and sample.responses["/zcc/papi/public/v1/application-profiles"]["body"][2]["active"] == 1


def test_app_profile_settings_change_only_allowlisted_fields_and_never_a_password(sample):
    """ASVS V8.1.1 · ASVS V5.1.3 · CWE-200 · CWE-915: only allowlisted DNS and tunnel settings are accepted; a password field is refused before any read."""
    # Act / Assert
    for bad in ({"uninstall_password": "x"}, {"logout_password": "x"}, {"policyToken": "x"}, {"enforce_split_dns": "maybe"},
                {"packet_tunnel_exclude_list": "10.0.0.0/8,<script>"}):
        with pytest.raises(ao.OperationError):
            live.normalize_settings({"profile": "1203", "platform": "windows", "settings": bad})


def test_app_profile_settings_apply_read_back_and_undo(sample):
    """ASVS V11.1.1 · CWE-841: a split DNS and exclusion-list change is previewed with before and after, read back, and Undo puts both values back."""
    # Arrange
    client = sdk(sample)
    spec = {"type": "zcc_app_profile_settings", "profile": "1203", "platform": "windows",
            "settings": {"enforce_split_dns": 1, "packet_tunnel_exclude_list": "10.0.0.0/8"}}
    # Act
    p, r = _apply(client, spec, ZCC_SCOPE)
    _p2, r2 = _apply(client, r["inverse"], ZCC_SCOPE)
    # Assert
    items = {u["field"]: (u["before"], u["after"]) for u in p["items"]}
    assert items == {"enforce_split_dns": (0, 1), "packet_tunnel_exclude_list": ("10.0.0.0/8,192.0.2.0/24", "10.0.0.0/8")}
    assert r["verification"]["confirmed"] == 2 and r2["status"] == "applied"
    pe = sample.responses["/zcc/papi/public/v1/application-profiles"]["body"][2]["policyExtension"]
    assert pe["packetTunnelExcludeList"] == "10.0.0.0/8,192.0.2.0/24" and pe["enforceSplitDNS"] == 0
    assert "No password" in " ".join(p["notes"])


def test_live_changes_out_of_scope_are_refused_before_any_read():
    """ASVS V4.1.3 · CWE-863: with ZCC not ticked nothing is read."""
    # Act / Assert
    for spec in ({"type": "zcc_app_profile_state", "targets": [{"id": "1", "platform": "windows", "to": "on"}]},
                 {"type": "zcc_app_profile_settings", "profile": "1", "settings": {"enforce_split_dns": 1}}):
        with pytest.raises(ao.OperationError):
            ao.plan(object(), spec, scope=ZID_SCOPE)


# ── Routes: gates, scope and rate limit before sign-in ─────────────────

@pytest.fixture
def api(monkeypatch, tmp_path):
    import dlp_api_server as srv
    import security
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setattr(security, "_write_override", True)
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append("sdk") or (_ for _ in ()).throw(AssertionError("signed in")))
    zi.reset_rate()
    yield TestClient(srv.app), built
    zi.reset_rate()


CREDS = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-1", "client_secret": "not-a-real-secret"}


def test_the_score_analysis_route_needs_the_phrase_and_is_rate_limited_before_sign_in(api):
    """ASVS V11.1.4 · ASVS V4.1.3 · CWE-770 · CWE-841 · WSTG-BUSL-05: without START ANALYSIS it is 400, and within the rate limit it is 429, both before signing in."""
    # Arrange
    client, built = api
    body = dict(CREDS, scopes=["zdx"], channels={}, from_page=True, assessor=ASSESSOR, confirm=True, app_id="3002")
    import dlp_api_server as srv
    zi.rate_check(srv._tenant_key(srv._tenant_creds(type("R", (), dict(body, profile_id="", auth_method="", username="", password="", api_key=""))())), record=True)
    # Act
    no_phrase = client.post("/api/zdx/analysis/start", json=dict(body, confirm_text="START"))
    limited = client.post("/api/zdx/analysis/start", json=dict(body, confirm_text="start analysis"))
    # Assert
    assert no_phrase.status_code == 400 and "START ANALYSIS" in no_phrase.json()["detail"]
    assert limited.status_code == 429 and built == []


@pytest.mark.parametrize("path,extra", [("/api/zdx/cloudpath", {"app_id": "3002"}), ("/api/zdx/analysis/status", {"analysis_id": "1"}),
                                        ("/api/zcc/device-details", {"udid": "LKF-WIN-0001"}), ("/api/zcc/disable-reasons", {})])
def test_the_new_read_routes_refuse_an_unticked_product_before_sign_in(api, path, extra):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: each new read is a 400 before sign-in when its product is not ticked on the Scope page."""
    # Arrange
    client, built = api
    # Act
    r = client.post(path, json=dict(CREDS, scopes=["dlp"], channels={}, from_page=True, **extra))
    # Assert
    assert r.status_code == 400 and "not in scope" in r.json()["detail"] and built == []


def test_a_malformed_device_id_is_refused_before_sign_in(api):
    """ASVS V5.1.3 · CWE-20: an invalid UDID is a 400 before signing in."""
    # Arrange
    client, built = api
    # Act
    r = client.post("/api/zcc/device-details", json=dict(CREDS, scopes=["zcc"], channels={}, from_page=True, udid="../x"))
    # Assert
    assert r.status_code == 400 and built == []


# ── Snapshots ──────────────────────────────────────────────────────────

def test_a_snapshot_keeps_the_new_reads_with_ids_only_for_devices_and_members(sample):
    """ASVS V8.3.4 · CWE-359 · CWE-312: the snapshot reads the alert history, per-app scores and metrics, admin entitlements and group members; affected devices and members are kept as ids only."""
    # Act
    cap = ot.capture(raw(sample), ["zdx", "zidentity", "zcc"], {}, lambda m: None)
    resp = cap["responses"]
    # Assert
    for path in ("/zdx/v1/alerts/historical", "/zdx/v1/apps/3002/score", "/zdx/v1/apps/3002/metrics",
                 "/ziam/admin/api/v1/users/u-41/admin-entitlements", "/zcc/papi/public/v1/process-based-apps",
                 "/zcc/papi/public/v1/custom-ip-based-apps"):
        assert path in resp, path
    assert resp["/zdx/v1/alerts/7401/affected_devices"]["body"] == {"devices": [{"id": 3101}, {"id": 3102}], "next_offset": None}
    assert resp["/ziam/admin/api/v1/groups/g-33/users"]["body"] == {"records": [{"id": "u-42"}]}
    assert cap["unread"] == [] and all(ot.valid_path(p) for p in resp)


def test_a_snapshot_reads_nothing_new_for_an_unticked_product(sample):
    """ASVS V4.1.3 · CWE-863: with only ZCC ticked, no ZDX or ZIdentity read is made for the snapshot."""
    # Act
    cap = ot.capture(raw(sample), ["zcc"], {}, lambda m: None)
    # Assert
    assert not any(p.startswith(("/zdx/", "/ziam/")) for p in cap["responses"])
