"""ZPA policy completeness: every ZPA policy type (redirection, privileged
credential and capabilities, browser protection, beside client forwarding,
inspection and isolation), AppProtection inspection profiles and custom
controls, and the infrastructure behind the ZPA diagnostics (application
servers, business continuity, Private Cloud, Branch and Cloud Connectors).

The reader is driven by the SDK-model fake tenant of test_zpa_analysis
(zscaler.zpa.models built from API-shaped JSON); the main assessment checks
by the offline sample tenant (no network). Each template has a case that
fires and a fixed case that does not."""
from __future__ import annotations

import copy
import json

import pytest

import offline_tenant as ot
import sample_tenant
import zpa_analysis as za
import zpa_reader as zr
import zscaler_full_checks as zfc
from test_zpa_analysis import APP, GRP, NOW, SCIM, FakeTenant, _cond, _op, _rule, _seg, clean, messy, read

NEW_TEMPLATES = ("ZPA-IN-01", "ZPA-IN-02", "ZPA-IN-03", "ZPA-CF-01", "ZPA-PR-01", "ZPA-PR-02", "ZPA-PR-03", "ZPA-RD-01",
                 "ZPA-BP-01", "ZPA-IS-01", "ZPA-SV-03", "ZPA-PC-01", "ZPA-BC-01", "ZPA-EC-01")


def _by(out, tid):
    return [f for f in out["findings"] if f["template"] == tid]


def _run(data):
    return za.analyze(read(data), now=NOW)


def _sample_raw():
    st = ot.sample_store()
    return ot.OfflineRawClient(st, ot.creds_for(st))


# ── the reader ────────────────────────────────────────────────────────
def test_every_policy_type_and_new_list_is_read_with_list_methods_only():
    """ASVS V1.4.1 · CWE-284 · WSTG-CONF-05: the four new policy types and eleven new lists are read through SDK list methods, never a write."""
    # Arrange
    t = FakeTenant()
    # Act
    snap = zr.read(t, pace=0)
    # Assert
    ptypes = {c[2][0] for c in t.calls if c[0] == "policies"}
    assert {"redirection", "credential", "capabilities", "clientless"} <= ptypes
    called = {(c[0], c[1]) for c in t.calls}
    for svc, method in (("servers", "list_servers"), ("app_protection", "list_profiles"), ("app_protection", "list_custom_controls"),
                        ("business_continuity", "list_business_continuity_settings"), ("private_cloud", "list_private_clouds"),
                        ("private_cloud_group", "list_cloud_groups"), ("private_cloud_controller", "list_cloud_controllers"),
                        ("branch_connector_group", "list_branch_connector_groups"), ("branch_connectors", "list_branch_connectors"),
                        ("cloud_connector_groups", "list_cloud_connector_groups"), ("cloud_connector_controller", "list_cloud_connectors")):
        assert (svc, method) in called, (svc, method)
    assert not t.writes and all(c[1].startswith("list_") for c in t.calls)
    assert not any(c[0].startswith("policy_group") for c in t.calls), "the policy-group model stays out until it is documented"
    cap = snap["policies"]["capabilities"][0]
    assert cap["capabilities"] == ["CLIPBOARD_COPY", "FILE_DOWNLOAD", "MONITOR_SESSION"]
    assert snap["policies"]["credential"][0]["credential"] == {"id": "cred-1", "name": "plant-admin"}
    assert snap["policies"]["redirection"][0]["service_edge_group_ids"] == ["pse-1"]
    assert snap["policies"]["inspection"][0]["inspection_profile_id"] == "ip1"
    assert snap["inspection_profiles"][0]["monitor_only"] is True
    assert snap["business_continuity"][0]["backup_enabled"] is True


def test_business_continuity_keys_and_connector_fingerprints_are_never_kept():
    """ASVS V8.3.4 · CWE-312 · WSTG-INFO-05: SAML private keys, certificates and enrollment fingerprints are dropped by the reader."""
    # Act
    snap = zr.read(FakeTenant(), pace=0)
    text = json.dumps(snap, default=str)
    # Assert
    for canary in ("canary-bc-key", "canary-bc-cert", "canary-fp", "PRIVATE KEY"):
        assert canary not in text
    assert set(snap["business_continuity"][0]) == {"id", "backup_enabled", "switch_time_enabled", "max_down_time", "max_down_time_unit",
                                                   "new_user_support", "use_existing_idp"}


def test_hostile_values_in_new_fields_are_parsed_defensively():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-12: wrong types and oversized values in the new fields never crash and are capped."""
    # Arrange
    data = messy()
    data["policies"]["capabilities"] = [_rule("cap1", 1, "Odd", "CHECK_CAPABILITIES", privilegedCapabilities={"capabilities": "CLIPBOARD_COPY"}),
                                        _rule("cap2", 2, "Odder", "CHECK_CAPABILITIES", privilegedCapabilities={"capabilities": ["X"] * 500 + [None, 7]}),
                                        _rule("cap3", 3, "Oddest", "CHECK_CAPABILITIES", privilegedCapabilities="all")]
    data["inspection_profiles"] = [{"id": "ip1", "name": "x" * 5000, "globalControlActions": [None, 7, "X:" * 1000],
                                    "predefinedControls": [{"id": "p", "action": None}, {"id": "q", "action": ["PASS"]}]}]
    data["business_continuity"] = [{"id": "bc", "maxAllowedDownTime": "9" * 5000}]
    # Act
    snap = read(data)
    out = za.analyze(snap, now=NOW)
    # Assert
    caps = [r["capabilities"] for r in snap["policies"]["capabilities"]]
    assert caps[0] == ["CLIPBOARD_COPY"] and len(caps[1]) <= 50 and caps[2] is None
    assert snap["inspection_profiles"][0]["monitor_only"] is None and len(snap["inspection_profiles"][0]["name"]) <= 300
    assert len(snap["business_continuity"][0]["max_down_time"]) <= 20
    assert out["counts"]["total"] == len(out["findings"])


# ── the templates: each fires, and a fixed tenant does not ────────────
def test_no_inspect_rule_at_all_is_said_once_for_the_web_segments():
    """ASVS V1.14.5 · CWE-693 · WSTG-CONF-01: web segments with no INSPECT rule at all are one finding naming them."""
    data = messy()
    data["policies"]["inspection"] = []
    out = _run(data)
    assert len(_by(out, "ZPA-IN-01")) == 1 and not _by(out, "ZPA-AS-09")
    assert "Jira" in _by(out, "ZPA-IN-01")[0]["reason"]
    assert not _by(_run(messy()), "ZPA-IN-01"), "an INSPECT rule exists: AS-09 judges segment by segment"


def test_a_monitor_only_profile_is_medium_when_a_rule_uses_it_and_a_blocking_one_is_clean():
    """ASVS V1.14.5 · CWE-693 · WSTG-CONF-01: a PASS-only inspection profile lets attacks through; a profile that blocks is not flagged."""
    out = _run(messy())
    f = _by(out, "ZPA-IN-02")
    assert len(f) == 1 and f[0]["severity"] == "medium" and "Inspect engineering" in f[0]["reason"]
    data = messy()
    data["policies"]["inspection"][0].pop("zpnInspectionProfileId")
    assert _by(_run(data), "ZPA-IN-02")[0]["severity"] == "low"
    data["inspection_profiles"][0]["predefinedControls"] = [{"id": "pc1", "action": "BLOCK"}]
    assert not _by(_run(data), "ZPA-IN-02")


def test_a_custom_control_no_profile_uses_is_flagged():
    """ASVS V1.14.5 · CWE-1164 · WSTG-CONF-01: a custom control attached to no inspection profile inspects nothing."""
    assert [f["object"] for f in _by(_run(messy()), "ZPA-IN-03")] == ["Block admin path"]
    data = messy()
    data["inspection_profiles"][0]["customControls"] = [{"id": "cc1", "action": "BLOCK"}]
    assert not _by(_run(data), "ZPA-IN-03")


def test_client_forwarding_bypass_of_a_sensitive_segment_is_high_conditional_medium_intercept_clean():
    """ASVS V1.4.4 · CWE-284 · WSTG-ATHZ-02: a BYPASS forwarding rule that decides for a sensitive segment skips every ZPA access rule."""
    out = _run(messy())
    by_obj = {f["object"]: f for f in _by(out, "ZPA-CF-01")}
    assert by_obj["Payroll"]["severity"] == "high" and by_obj["RDP jump hosts"]["severity"] == "high"
    assert "Intranet" not in by_obj and "Jira" not in by_obj, "not sensitive: no finding"
    data = messy()
    data["policies"]["client_forwarding"] = [_rule("f0", 1, "Intercept all", "INTERCEPT"), _rule("f1", 2, "Bypass all", "BYPASS")]
    assert not _by(_run(data), "ZPA-CF-01"), "an unconditional Intercept above decides first"
    data["policies"]["client_forwarding"] = [_rule("f1", 1, "Bypass contractors", "BYPASS", _cond(SCIM("g-con")))]
    sev = {f["object"]: f["severity"] for f in _by(_run(data), "ZPA-CF-01")}
    assert sev and set(sev.values()) == {"medium"}


def test_privileged_capabilities_that_move_data_out_are_flagged_and_inspected_transfer_is_not():
    """ASVS V1.4.4 · CWE-200 · WSTG-ATHZ-03: clipboard copy and uninspected file transfer in PRA sessions are findings; inspected transfer is not."""
    f = _by(_run(messy()), "ZPA-PR-01")
    assert len(f) == 1 and f[0]["severity"] == "high" and "clipboard copy" in f[0]["reason"]
    data = messy()
    data["policies"]["capabilities"][0]["conditions"].append(_cond(SCIM("g-eng")))
    assert _by(_run(data), "ZPA-PR-01")[0]["severity"] == "medium"
    data["policies"]["capabilities"][0]["privilegedCapabilities"] = {"capabilities": ["INSPECT_FILE_UPLOAD", "INSPECT_FILE_DOWNLOAD", "RECORD_SESSION"]}
    out = _run(data)
    assert not _by(out, "ZPA-PR-01") and not _by(out, "ZPA-PR-02")


def test_pra_segments_with_no_recording_and_credentials_with_no_user_condition_are_flagged():
    """ASVS V7.1.3 · CWE-778 · WSTG-ATHZ-02: unrecorded privileged sessions and a shared credential for everyone are findings."""
    out = _run(messy())
    assert [f["object"] for f in _by(out, "ZPA-PR-02")] == ["RDP jump hosts"]
    assert [f["object"] for f in _by(out, "ZPA-PR-03")] == ["Shared admin login"]
    data = messy()
    data["policies"]["credential"][0]["conditions"].append(_cond(SCIM("g-eng")))
    assert not _by(_run(data), "ZPA-PR-03")
    data["segments"] = [s for s in data["segments"] if s["id"] != "s-rdp"]
    assert not _by(_run(data), "ZPA-PR-02")


def test_redirection_to_groups_that_cannot_serve_is_flagged_and_a_serving_group_is_clean():
    """ASVS V1.14.1 · CWE-1188 · WSTG-CONF-01: REDIRECT_ALWAYS to an empty group is high, PREFERRED with none medium, a connected edge clean."""
    sev = {f["object"]: f["severity"] for f in _by(_run(messy()), "ZPA-RD-01")}
    assert sev == {"Branch always via PSE": "high", "Prefer a PSE": "medium"}
    data = messy()
    data["policies"]["redirection"] = data["policies"]["redirection"][:1]
    data["service_edges"] = [{"id": "e1", "name": "pse-a", "enabled": True, "serviceEdgeGroupId": "pse-1", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"}]
    assert not _by(_run(data), "ZPA-RD-01")


def test_browser_access_without_isolation_or_protection_is_flagged_and_rules_that_reach_it_clear_it():
    """ASVS V1.4.4 · CWE-200 · WSTG-ATHZ-02: unmanaged browsers reaching a sensitive app with no isolation are high; ISOLATE and MONITOR clear it."""
    out = _run(messy())
    iso = _by(out, "ZPA-IS-01")
    assert [f["object"] for f in iso] == ["Corp wildcard"] and iso[0]["severity"] == "medium"
    assert [f["object"] for f in _by(out, "ZPA-BP-01")] == ["Corp wildcard"]
    data = messy()
    data["segments"].append(_seg("s-hr", "HR portal", ["hr.corp.example"], [(443, 443)], "sg-gen", ["srv-dc1"],
                                 clientlessApps=[{"id": "ca2", "name": "hr", "enabled": True}]))
    data["policies"]["access"].insert(0, _rule("r0", 0, "HR from anywhere", "ALLOW", _cond(APP("s-hr")), _cond(SCIM("g-eng"))))
    assert {f["object"]: f["severity"] for f in _by(_run(data), "ZPA-IS-01")}["HR portal"] == "high", "sensitive: high"
    data = messy()
    data["policies"]["isolation"] = [_rule("iso0", 1, "No isolation", "BYPASS_ISOLATE"), _rule("iso1", 2, "Isolate corp", "ISOLATE", _cond(APP("s-wild")))]
    assert _by(_run(data), "ZPA-IS-01"), "an unconditional bypass above decides first"
    data["policies"]["isolation"] = [_rule("iso1", 1, "Isolate corp", "ISOLATE", _cond(APP("s-wild")))]
    data["policies"]["clientless"] = [_rule("bp1", 1, "Monitor BA", "MONITOR")]
    out = _run(data)
    assert not _by(out, "ZPA-IS-01") and not _by(out, "ZPA-BP-01")


def test_infrastructure_templates_find_idle_servers_dead_private_cloud_and_empty_connector_groups():
    """ASVS V1.14.1 · CWE-1164 · WSTG-CONF-01: an unused server, disconnected controllers, nowhere to fail over and an empty connector group."""
    out = _run(messy())
    assert [f["object"] for f in _by(out, "ZPA-SV-03")] == ["old-db"]
    assert [f["object"] for f in _by(out, "ZPA-PC-01")] == ["Plant floor"]
    assert len(_by(out, "ZPA-BC-01")) == 1
    assert [f["object"] for f in _by(out, "ZPA-EC-01")] == ["Store 12"]
    data = messy()
    data["servers"][0]["appServerGroupIds"] = [{"id": "srv-dc1"}]
    data["private_cloud_controllers"][0]["controlChannelStatus"] = "ZPN_STATUS_AUTHENTICATED"
    data["branch_connectors"] = [{"id": "bc1", "name": "store12-bc", "enabled": True, "branchConnectorGroupId": "bcg1"}]
    out = _run(data)
    assert not any(_by(out, t) for t in ("ZPA-SV-03", "ZPA-PC-01", "ZPA-BC-01", "ZPA-EC-01"))


def test_a_list_that_could_not_be_read_is_not_assessed_never_clean():
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: a failed read leaves its templates "not assessed", never "no finding"."""
    out = za.analyze(read(messy(), fail={"app_protection": "403 forbidden", "branch_connectors": "403", "cloud_connector_controller": "403",
                                         "private_cloud_controller": "403"}), now=NOW)
    status = {c["id"]: c["status"] for c in out["catalog"]}
    assert status["ZPA-IN-02"] == status["ZPA-IN-03"] == status["ZPA-PC-01"] == status["ZPA-BC-01"] == status["ZPA-EC-01"] == "not_assessed"
    assert status["ZPA-CF-01"] == "findings"


def test_the_clean_tenant_has_none_of_the_new_findings():
    """ASVS V1.14.1 · CWE-1164 · WSTG-CONF-01: a well-run tenant with every new list read gives no new finding (no false positive)."""
    out = _run(clean())
    status = {c["id"]: c["status"] for c in out["catalog"]}
    assert all(status[t] == "clean" for t in NEW_TEMPLATES), {t: status[t] for t in NEW_TEMPLATES}


# ── the diagnostics ───────────────────────────────────────────────────
def test_a_diagnosis_walks_every_policy_type_and_the_connector_and_continuity_hops():
    """ASVS V1.4.4 · CWE-284 · WSTG-ATHZ-02: the diagnosis names the first rule of every policy type and the infrastructure that brokers it."""
    snap = read(messy())
    d = za.diagnose(snap, {"client_type": "zpn_client_type_branch_connector"}, "rdp.corp.example", 3389)
    assert {"redirection", "credential", "capabilities", "clientless"} <= set(d["other_policies"])
    assert d["other_policies"]["capabilities"]["rule"]["name"] == "Jump host full transfer"
    hops = {h["key"]: h for h in d["hops"]}
    assert hops["edge_connectors"]["status"] == "warn" and "Store 12" in hops["edge_connectors"]["detail"]
    assert hops["business_continuity"]["status"] == "warn" and "0 of 1" in hops["business_continuity"]["detail"]
    zapp = za.diagnose(snap, {"client_type": "zpn_client_type_zapp"}, "rdp.corp.example", 3389)
    assert "edge_connectors" not in {h["key"] for h in zapp["hops"]}


def test_a_server_group_listing_no_servers_counts_them_from_the_server_list():
    """ASVS V1.4.4 · CWE-754 · WSTG-CONF-01: servers named only by the server list are counted, so the group is not called empty."""
    data = messy()
    data["servers"] = [{"id": "sv2", "name": "static-a", "address": "10.9.9.9", "enabled": True, "appServerGroupIds": [{"id": "srv-static"}]}]
    out = _run(data)
    assert "Static servers" not in {f["object"] for f in _by(out, "ZPA-SV-01")}
    assert "Static servers" in {f["object"] for f in _by(_run(messy()), "ZPA-SV-01")}


# ── the main assessment, the sample tenant and the snapshot ───────────
def test_the_assessment_checks_run_offline_on_the_sample_tenant():
    """ASVS V1.14.1 · CWE-1164 · WSTG-CONF-01: ZPA.16 to ZPA.21 judge the sample tenant's gaps from the same templates."""
    cl = _sample_raw()
    got = {fn.__name__: fn(cl) for fn in (zfc.zpa_16, zfc.zpa_17, zfc.zpa_18, zfc.zpa_19, zfc.zpa_20, zfc.zpa_21)}
    assert got["zpa_17"].status == "FAIL" and "Depot jump hosts" in got["zpa_17"].detail
    assert got["zpa_18"].status == "FAIL" and got["zpa_16"].status == "REVIEW" and got["zpa_19"].status == "REVIEW"
    assert got["zpa_20"].status == "REVIEW" and got["zpa_21"].status == "REVIEW"
    ids = {row[0] for row in zfc.PLATFORM_REG}
    assert {"ZPA.16", "ZPA.17", "ZPA.18", "ZPA.19", "ZPA.20", "ZPA.21"} <= ids


class _Raw:
    """A raw client answering fixed bodies by short path (404 for the rest)."""

    def __init__(self, bodies):
        self.bodies, self.calls = bodies, []

    def get(self, ep, p=None):
        self.calls.append(ep)
        return (self.bodies[ep], 200) if ep in self.bodies else ({"error": "not found"}, 404)


def test_an_unlicensed_feature_is_na_and_an_unused_one_is_na_never_pass():
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: a 404 means not licensed (N/A); no PRA or Browser Access segment means not in use (N/A)."""
    r = zfc.zpa_16(_Raw({}))
    assert r.status == "INFO" and "N/A" in r.detail and "not licensed" in r.detail
    segs = {"list": [_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"])]}
    raw = _Raw({"/zpa/application": segs, "/zpa/policySet/rules/policyType/CAPABILITIES_POLICY": {"list": []},
                "/zpa/policySet/rules/policyType/CREDENTIAL_POLICY": {"list": []}, "/zpa/policySet/rules/ACCESS_POLICY": {"list": []},
                "/zpa/policySet/rules/policyType/ISOLATION_POLICY": {"list": []},
                "/zpa/policySet/rules/policyType/CLIENTLESS_SESSION_PROTECTION_POLICY": {"list": []}})
    assert zfc.zpa_18(raw).status == "INFO" and "not in use" in zfc.zpa_18(raw).detail
    assert zfc.zpa_20(raw).status == "INFO" and "no Browser Access segment" in zfc.zpa_20(raw).detail
    assert all(ep.startswith("/zpa/") for ep in raw.calls)


def test_the_sample_tenant_answers_every_new_read_and_shows_every_new_gap():
    """ASVS V1.14.1 · CWE-1164 · WSTG-CONF-01: every new list is in the sample tenant, so the pages work offline and find the gaps."""
    st = ot.sample_store()
    snap = zr.read(ot.OfflineSdkClient(st, ot.creds_for(st)), pace=0)
    assert all(v["read"] for v in snap["collections"].values()), [k for k, v in snap["collections"].items() if not v["read"]]
    fired = {f["template"] for f in za.analyze(snap)["findings"]}
    assert set(NEW_TEMPLATES) - {"ZPA-PC-01"} <= fired, set(NEW_TEMPLATES) - fired
    paths = sample_tenant.responses()
    for suffix in ("server", "inspectionControls/custom", "businessContinuitySettings", "privateCloudController", "branchConnector",
                   "cloudConnectorGroup", "policySet/rules/policyType/CAPABILITIES_POLICY"):
        assert f"{sample_tenant.ZPA1}/{suffix}" in paths


def test_a_snapshot_reads_the_new_lists_only_when_zpa_is_ticked_and_masks_private_keys():
    """ASVS V8.3.4 · CWE-312 · WSTG-CONF-05: the snapshot plan adds the new ZPA lists under the ZPA scope only; secret-named values are masked."""
    plan = ot.capture_plan(["zpa"])
    for ep in ("/zpa/server", "/zpa/inspectionProfile", "/zpa/businessContinuitySettings", "/zpa/cloudConnector",
               "/zpa/policySet/rules/policyType/REDIRECTION_POLICY", "/zpa/policySet/rules/policyType/CLIENTLESS_SESSION_PROTECTION_POLICY"):
        assert ep in plan
    assert not [ep for ep in ot.capture_plan(["dlp", "zia_extras", "zcc"]) if ep.startswith("/zpa/")]
    scrubbed = ot.scrub({"list": [{"id": "1", "sitespPrivateKey": "-----BEGIN PRIVATE KEY-----x", "sitespSigningPrivateKey": "y",
                                   "sitespCAPrivateKey": "z", "backupEnabled": True}]})
    row = scrubbed["list"][0]
    assert row["sitespPrivateKey"] == row["sitespSigningPrivateKey"] == row["sitespCAPrivateKey"] == "(set)" and row["backupEnabled"] is True


def test_a_saved_snapshot_of_the_sample_keeps_the_new_lists_for_offline_use():
    """ASVS V1.14.1 · CWE-1164 · WSTG-CONF-05: capturing the sample with ZPA ticked keeps every new list, the business continuity one in one call."""
    st = ot.sample_store()
    raw = ot.OfflineRawClient(st, ot.creds_for(st))
    got = ot.capture(raw, ["zpa"], {}, lambda line: None)
    keys = set(got["responses"])
    for suffix in ("server", "businessContinuitySettings", "branchConnectorGroup", "policySet/rules/policyType/CREDENTIAL_POLICY"):
        assert any(k.endswith("/" + suffix) for k in keys), suffix
    assert not got["unread"], got["unread"]


def test_zpa_analysis_is_refused_before_sign_in_when_zpa_is_not_ticked(monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: the Scope rule holds for the new reads: ZPA not ticked is a 400 and nothing is signed in to."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(creds) or None)
    c = TestClient(srv.app)
    c.headers.update(srv._ui_auth_headers() if hasattr(srv, "_ui_auth_headers") else {})
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "216196257331281920",
            "scope": {"scopes": ["dlp"], "channels": {}, "from_page": True}}
    r = c.post("/api/zpa/analysis/start", json=body)
    assert r.status_code in (400, 401, 403) and not built
