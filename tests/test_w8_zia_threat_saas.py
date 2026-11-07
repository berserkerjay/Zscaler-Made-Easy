"""Wave 8, slice `zia-threat-saas`: ZIA threat protection and SaaS Security
hygiene in the scored assessment (zscaler_full_checks THR / UF / SAAS), and
the Cloud Sandbox file hash builder on Bulk changes (ops_zia_sandbox).

Every test is offline: checks read through a small fake or the made-up
sample tenant (offline_tenant), the builder writes to the sample's in-memory
copy or a recording fake. No real tenant, no network, no real clock."""
from __future__ import annotations

import copy
import importlib
import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import admin_ops as ao  # noqa: E402
import channel_scope as cs  # noqa: E402
import offline_tenant as ot  # noqa: E402
import ops_zia_sandbox as zsb  # noqa: E402
import sample_tenant  # noqa: E402
import scope_permissions  # noqa: E402
import zscaler_full_checks as full  # noqa: E402
from dlp_assessment_full_auto import R  # noqa: E402

ZIA = "/zia/api/v1"
IDS = [row[0] for row in full.THREAT_SAAS_REG]
FN = {row[0]: row[3] for row in full.PLATFORM_REG}   # the guarded functions the assessment runs
REAL = {row[0]: row[3] for row in full.THREAT_SAAS_REG}


class Fake:
    """The engine client's read interface: get(ep, params) -> (body, code)."""

    def __init__(self, table=None, default=(None, 404)):
        self.table = dict(table or {})
        self.default = default
        self.reads = []

    def get(self, ep, *a, **k):
        self.reads.append(ep)
        return copy.deepcopy(self.table.get(ep, self.default))


def sample_client():
    st = ot.sample_store(reset=True)
    return ot.OfflineRawClient(st, ot.creds_for(st))


# ── The checks: registered, scoped, scored ──────────────────────────────

def test_every_new_check_is_in_the_zia_platform_registry_and_guarded():
    """ASVS V1.14.1 · CWE-1164: the 18 checks are in PLATFORM_REG under a ZIA section (so the ZIA platform scope runs them) and go through the permission guard."""
    ids = {row[0] for row in full.PLATFORM_REG}
    assert set(IDS) <= ids and len(IDS) == 18
    assert all(row[1].startswith("ZIA — ") for row in full.THREAT_SAAS_REG)
    assert all(getattr(FN[i], "__wrapped__", None) is REAL[i] for i in IDS)


def test_only_zia_platform_runs_them():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the checks run when ZIA platform is ticked and never when only DLP or ZPA is (read only what is in scope)."""
    import dlp_api_server as srv
    assert set(IDS) <= {c[0] for c in srv._get_checks(scopes=["zia_extras"])}
    assert not set(IDS) & {c[0] for c in srv._get_checks(scopes=["dlp", "zpa", "zcc"])}


def test_saas_security_reads_need_the_saas_channel_on_zscaler():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: SaaS Security malware rules, tenant scan state and quarantine templates belong to the SaaS Security channel; a check reading them is skipped (not read) when it is not on Zscaler."""
    assert cs.endpoint_channels("/zia/casbMalwareRules/all") == ("saas_casb",)
    assert cs.endpoint_channels("/zia/quarantineTombstoneTemplate/lite") == ("saas_casb",)
    assert "saas_casb" in cs.endpoint_channels("/zia/casbTenant/scanInfo")
    checks = [r for r in full.PLATFORM_REG if r[0] in ("SAAS.1", "SAAS.2", "SAAS.3", "THR.1")]
    run, skipped, _ = cs.partition(checks, {"web_dlp": "zscaler"})
    assert {r[0] for r in run} == {"THR.1"} and {s["id"] for s in skipped} == {"SAAS.1", "SAAS.2", "SAAS.3"}
    run, skipped, _ = cs.partition(checks, {"saas_casb": "zscaler"})
    assert {r[0] for r in run} == {"SAAS.1", "SAAS.2", "SAAS.3", "THR.1"}


def test_the_sample_tenant_answers_every_new_read_and_finds_its_gaps():
    """ASVS V1.14.1 · CWE-1287: every new check is assessed on the sample tenant (none "not readable"), and the sample's deliberate gaps are found."""
    cl = sample_client()
    got = {i: REAL[i](cl) for i in IDS}
    assert all(r.status in (R.PASS, R.WARN) for r in got.values()), {i: (r.status, r.detail[:80]) for i, r in got.items() if r.status not in (R.PASS, R.WARN)}
    assert {i for i, r in got.items() if r.status == R.WARN} == {"THR.2", "THR.4", "THR.5", "THR.8", "THR.10", "UF.5", "SAAS.1", "SAAS.2", "SAAS.3"}
    assert "Larkspur Google Workspace" in got["SAAS.1"].detail and "Larkspur Box" not in got["SAAS.1"].detail


# Oracles: (check, table that passes, table that fails).
ORACLES = [
    ("THR.1", {"/zia/behavioralAnalysisAdvancedSettings": ({"md5HashValueList": [{"url": "a" * 32, "type": "CUSTOM_FILEHASH_DENY"}]}, 200)},
     {"/zia/behavioralAnalysisAdvancedSettings": ({"md5HashValueList": [{"url": "b" * 32, "type": "CUSTOM_FILEHASH_ALLOW"}]}, 200)}),
    ("THR.2", {"/zia/ipsSignatureRules": ([{"name": "s", "enabled": True}], 200)},
     {"/zia/ipsSignatureRules": ([{"name": "s", "enabled": True, "dynamicValidationRejected": True}], 200)}),
    ("THR.3", {"/zia/mobileAdvanceThreatSettings": ({k: True for k in full._MOBILE_ALL}, 200)},
     {"/zia/mobileAdvanceThreatSettings": (dict({k: True for k in full._MOBILE_ALL}, blockAppsWithMaliciousActivity=False), 200)}),
    ("THR.4", {"/zia/ftpSettings": ({"ftpEnabled": False, "ftpOverHttpEnabled": False}, 200)},
     {"/zia/ftpSettings": ({"ftpEnabled": True, "urlCategories": [], "urls": []}, 200)}),
    ("THR.5", {"/zia/eun": ({"displayReason": True, "supportEmail": "x", "orgPolicyLink": "y", "securityReviewEnabled": True}, 200)},
     {"/zia/eun": ({"displayReason": False, "securityReviewEnabled": True, "supportPhone": "1", "orgPolicyLink": "y"}, 200)}),
    ("THR.6", {"/zia/alertRuleConfiguration/uebaRules": ([{"alertName": "a", "status": "ENABLED"}], 200), "/zia/alertDefinitions": ([], 200)},
     {"/zia/alertRuleConfiguration/uebaRules": ([{"alertName": "a", "status": "DISABLED"}], 200), "/zia/alertDefinitions": ([], 200)}),
    ("THR.8", {"/zia/browserControlSettings": ({"allowAllBrowsers": False, "enableWarnings": True}, 200)},
     {"/zia/browserControlSettings": ({"bypassAllBrowsers": True, "enableWarnings": True}, 200)}),
    ("THR.9", {"/zia/advancedSettings": ({"blockDomainFrontingOnHostHeader": True}, 200)},
     {"/zia/advancedSettings": ({"blockDomainFrontingOnHostHeader": False}, 200)}),
    ("UF.5", {"/zia/advancedUrlFilterAndCloudAppSettings": ({"enforceSafeSearch": True}, 200)},
     {"/zia/advancedUrlFilterAndCloudAppSettings": ({"enforceSafeSearch": False}, 200)}),
    ("UF.6", {"/zia/advancedUrlFilterAndCloudAppSettings": ({"enableNewlyRegisteredDomains": True, "enableDynamicContentCat": True, "considerEmbeddedSites": True}, 200)},
     {"/zia/advancedUrlFilterAndCloudAppSettings": ({"enableNewlyRegisteredDomains": False, "enableDynamicContentCat": True, "considerEmbeddedSites": True}, 200)}),
    ("UF.7", {"/zia/advancedSettings": ({"enableOffice365": True}, 200)}, {"/zia/advancedSettings": ({"enableOffice365": False}, 200)}),
    ("SAAS.1", {"/zia/casbMalwareRules/all": ([{"name": "r", "state": "ENABLED", "cloudAppTenants": [{"id": 1}]}], 200),
                "/zia/casbTenant/lite": ([{"tenantId": 1, "tenantName": "Box"}], 200)},
     {"/zia/casbMalwareRules/all": ([{"name": "r", "state": "DISABLED", "cloudAppTenants": [{"id": 1}]}], 200),
      "/zia/casbTenant/lite": ([{"tenantId": 1, "tenantName": "Box"}], 200)}),
    ("SAAS.2", {"/zia/casbMalwareRules/all": ([{"name": "r", "state": "ENABLED", "action": "OFLCASB_AVP_QUARANTINE", "casbTombstoneTemplate": {"id": 1}}], 200)},
     {"/zia/casbMalwareRules/all": ([{"name": "r", "state": "ENABLED", "action": "OFLCASB_AVP_REPORT_MALWARE"}], 200)}),
    ("SAAS.3", {"/zia/casbTenant/lite": ([{"tenantId": 1, "tenantName": "Box"}], 200),
                "/zia/casbTenant/scanInfo": ([{"tenantId": 1, "scanInfo": {"prev_scan_end_time": 5}}], 200)},
     {"/zia/casbTenant/lite": ([{"tenantId": 1, "tenantName": "Box", "reAuth": True}], 200), "/zia/casbTenant/scanInfo": ([], 200)}),
    ("SAAS.4", {"/zia/cloudToCloudIR/lite": ([{"name": "bucket", "lastValidationMsg": {"errorCode": ""}}], 200)},
     {"/zia/cloudToCloudIR/lite": ([{"name": "bucket", "lastValidationMsg": {"errorCode": "AUTH_FAILED"}}], 200)}),
]


@pytest.mark.parametrize("cid,good,bad", ORACLES, ids=[o[0] for o in ORACLES])
def test_oracle_passes_the_good_tenant_and_flags_the_bad_one(cid, good, bad):
    """ASVS V1.14.1 · CWE-1164 · SSDF PW.8.2: each check passes a tenant that follows the best practice and asks for review on one that does not, with the fix in plain words."""
    ok, ko = REAL[cid](Fake(good)), REAL[cid](Fake(bad))
    assert ok.status == R.PASS, ok.detail
    assert ko.status == R.WARN and "Best Practice:" in ko.detail, ko.detail


LICENSED_404 = ["THR.1", "THR.2", "THR.3", "THR.4", "THR.6", "THR.7", "THR.10", "THR.11", "SAAS.1", "SAAS.2", "SAAS.3", "SAAS.4"]


@pytest.mark.parametrize("cid", LICENSED_404)
def test_a_feature_not_licensed_is_outside_the_score(cid):
    """ASVS V7.4.1 · CWE-754 · CWE-391: a 404 (feature not licensed or not enabled) is INFO saying "not licensed", never a failure or a review."""
    r = REAL[cid](Fake(default=({"code": "NOT_FOUND"}, 404)))
    assert r.status == R.INFO and "not licensed" in r.detail, (cid, r.status, r.detail)


@pytest.mark.parametrize("cid", IDS)
def test_a_refused_read_is_not_permitted_never_judged(cid):
    """ASVS V4.1.3 · CWE-280 · WSTG-ERRH-01: a 403 on any read makes the check "Not permitted" through the guard, whatever the check would have said."""
    import permissions
    r = FN[cid](Fake(default=({"code": "FORBIDDEN"}, 403)))
    row = {"id": cid, "section": "ZIA", "label": cid, "status": r.status, "detail": r.detail}
    assert r.status not in (R.PASS, R.FAIL, R.WARN) and permissions.classify(row) == "not_permitted", (cid, r.status, r.detail)


@pytest.mark.parametrize("cid", IDS)
def test_missing_or_odd_data_never_passes_or_crashes(cid):
    """ASVS V5.1.3 · CWE-20 · CWE-1287: an error answer, an empty object and odd shapes never crash a check and never make it PASS where there is nothing."""
    r = REAL[cid](Fake(default=({"error": "boom"}, 0)))
    assert r.status in (R.INFO, R.WARN), (cid, r.status)
    for body in ([], {}, "text", 7, [1, "x", None]):
        r = REAL[cid](Fake(default=(body, 200)))
        assert isinstance(r, R) and r.status in (R.PASS, R.WARN, R.INFO)


def test_tenant_names_in_findings_are_cleaned_and_capped():
    """ASVS V5.3.1 · CWE-117 · CWE-74: a tenant or rule name with control characters or of any length is shown without the control characters and capped."""
    evil = "Box\x1b[31m\r\n" + "A" * 500
    r = REAL["SAAS.1"](Fake({"/zia/casbMalwareRules/all": ([], 200), "/zia/casbTenant/lite": ([{"tenantId": 9, "tenantName": evil}], 200)}))
    assert r.status == R.WARN and "\x1b" not in r.detail and "\r" not in r.detail and "A" * (full._NAME_MAX + 1) not in r.detail


def test_secret_holding_lists_are_never_read():
    """ASVS V8.3.4 · CWE-200 · CWE-312: the full cloud-to-cloud receiver list (tenant credentials) and the alert webhooks (passwords, tokens) are never read; only the lite list and the UEBA rules are."""
    reads = set()
    for cid in IDS:
        f = Fake(default=([], 200))
        REAL[cid](f)
        reads |= set(f.reads)
    assert "/zia/cloudToCloudIR/lite" in reads
    assert not any(r.rstrip("/") == "/zia/cloudToCloudIR" or "webhooks" in r for r in reads), sorted(reads)


def test_every_read_is_in_the_scope_permissions_and_the_snapshot():
    """ASVS V1.14.1 · CWE-1164: every endpoint a new check reads is listed under ZIA platform in Required API access and saved in a snapshot when ZIA platform is ticked (and only then)."""
    reads = set()
    for cid in IDS:
        f = Fake(default=([], 200))
        REAL[cid](f)
        reads |= set(f.reads)
    used = set(scope_permissions.SCOPE_PERMISSIONS["zia_extras"]["endpoints_used"])
    assert reads - used == set()
    plan = set(ot.capture_plan(["zia_extras"]))
    assert reads - plan - {"/zia/casbTenant/lite"} == set()   # the tenant list is saved with DLP and GenAI already
    assert not {"/zia/casbMalwareRules/all", "/zia/ftpSettings"} & set(ot.capture_plan(["zpa"]))


SAMPLE_MODELS = [
    (f"{ZIA}/ipsSignatureRules", "zia.models.ips_signature_rules", "IPSSignatureRules"),
    (f"{ZIA}/mobileAdvanceThreatSettings", "zia.models.mobile_threat_settings", "MobileAdvancedThreatSettings"),
    (f"{ZIA}/ftpSettings", "zia.models.ftp_control_policy", "FTPControlPolicy"),
    (f"{ZIA}/customFileTypes", "zia.models.custom_file_types", "CustomFileTypes"),
    (f"{ZIA}/riskProfiles/lite", "zia.models.risk_profiles", "RiskProfiles"),
    (f"{ZIA}/adaptiveAccessProfiles", "zia.models.adaptive_access_profiles", "AdaptiveAccessProfile"),
    (f"{ZIA}/advancedUrlFilterAndCloudAppSettings", "zia.models.url_filter_cloud_app_settings", "AdvancedUrlFilterAndCloudAppSettings"),
    (f"{ZIA}/casbMalwareRules/all", "zia.models.casb_malware_rules", "CasbMalwareRules"),
    (f"{ZIA}/quarantineTombstoneTemplate/lite", "zia.models.saas_security_api", "QuarantineTombstoneTemplate"),
    (f"{ZIA}/casbTenant/scanInfo", "zia.models.saas_security_api", "SaaSScanInfo"),
    (f"{ZIA}/cloudToCloudIR/lite", "zia.models.cloud_to_cloud_ir", "CloudToCloudIR"),
    (f"{ZIA}/alertDefinitions", "zia.models.security_ueba_alerts", "AlertDefinition"),
    (f"{ZIA}/behavioralAnalysisAdvancedSettings", "zia.models.sandbox", "BehavioralAnalysisAdvancedSettings"),
    (f"{ZIA}/browserControlSettings", "zia.models.browser_control_settings", "BrowserControlSettings"),
]


@pytest.mark.parametrize("path,module,cls", SAMPLE_MODELS, ids=[m[0].rsplit("/", 1)[-1] for m in SAMPLE_MODELS])
def test_the_sample_answers_speak_the_sdk_models(path, module, cls):
    """ASVS V5.1.3 · CWE-1287 · SSDF PW.4.1: every field of a new sample answer is one the SDK 1.11.3 model reads (no invented field names)."""
    import sdk_wire_fake as wf
    model = getattr(importlib.import_module(f"zscaler.{module}"), cls)
    body = sample_tenant.responses()[path]
    rows = body if isinstance(body, list) else [body]
    assert sorted({f for row in rows for f in wf.unknown_fields(row, model)}) == []


@pytest.mark.parametrize("module,name,path", [
    ("sandbox", "get_behavioral_analysis", "/behavioralAnalysisAdvancedSettings"), ("sandbox", "add_hash_to_custom_list", "/behavioralAnalysisAdvancedSettings"),
    ("sandbox", "get_file_hash_count", "/behavioralAnalysisAdvancedSettings/fileHashCount"), ("ips_signature_rules", "list_ips_signature_rules", "/ipsSignatureRules"),
    ("mobile_threat_settings", "get_mobile_advanced_settings", "/mobileAdvanceThreatSettings"), ("ftp_control_policy", "get_ftp_settings", "/ftpSettings"),
    ("end_user_notification", "get_eun_settings", "/eun"), ("security_ueba_alerts", "list_alert_rule_configurations_ueba_rules", "/alertRuleConfiguration/uebaRules"),
    ("security_ueba_alerts", "list_alert_definitions", "/alertDefinitions"), ("custom_file_types", "list_custom_file_types", "/customFileTypes"),
    ("risk_profiles", "list_risk_profiles_lite", "/riskProfiles/lite"), ("adaptive_access_profiles", "list_adaptive_access_profiles", "/adaptiveAccessProfiles"),
    ("url_filtering", "get_url_and_app_settings", "/advancedUrlFilterAndCloudAppSettings"), ("casb_malware_rules", "list_all_rules", "/casbMalwareRules/all"),
    ("saas_security_api", "list_quarantine_tombstone_lite", "/quarantineTombstoneTemplate/lite"), ("saas_security_api", "list_saas_scan_info", "/casbTenant/scanInfo"),
    ("cloud_to_cloud_ir", "list_cloud_to_cloud_ir_lite", "/cloudToCloudIR/lite"),
])
def test_every_path_is_the_one_the_sdk_calls(module, name, path):
    """SSDF PW.4.1 · CWE-1164: each short path the checks read and the builder writes is the one the installed SDK's method sends (zscaler/zia/<module>.py)."""
    import inspect
    src = inspect.getsource(getattr(importlib.import_module(f"zscaler.zia.{module}"), [c for c in dir(importlib.import_module(f"zscaler.zia.{module}")) if c.endswith("API")][0]))
    fn = re.search(rf"def {name}\(.*?(?=\n    def |\Z)", src, re.S).group(0)
    assert re.search(rf"\n\s*{re.escape(path)}\s*\n", fn), (module, name, path)


# ── The builder: hash validation ────────────────────────────────────────

@pytest.mark.parametrize("raw,ok", [
    ("44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f"), ("  44d88612fea8a8f36de82e1278abb02f\t", "44d88612fea8a8f36de82e1278abb02f"),
    ("44d88612fea8a8f36de82e1278abb02", None), ("44d88612fea8a8f36de82e1278abb02fz", None), ("g" * 32, None), ("0" * 32, None),
    ("a" * 64, None), ("a" * 40, None), ("44d88612fea8a8f36de82e1278abb02f\n", "44d88612fea8a8f36de82e1278abb02f"),
    ("44d88612fea8a8f36de82e1278abb02f\x00", None), ("４４d88612fea8a8f36de82e1278abb02f", None), (None, None), (12345, None), ("x" * 10000, None),
])
def test_only_an_md5_is_accepted(raw, ok):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-1286 · WSTG-INPV-01: a hash is exactly 32 hexadecimal characters (case folded, surrounding spaces trimmed); SHA-1, SHA-256, full-width digits, NUL, junk and huge input are refused with a reason."""
    got, why = zsb.normalize_md5(raw)
    assert got == ok and (why is None) == (ok is not None)
    if raw == "a" * 64:
        assert "MD5 hashes only" in why


def test_a_bad_hash_refuses_the_whole_plan_naming_the_line():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: one bad entry refuses the whole plan (nothing half-planned) and says which line."""
    with pytest.raises(ao.OperationError, match="line 2"):
        zsb.parse_spec({"type": zsb.TYPE, "hashes": ["a" * 32, "nope"]})
    with pytest.raises(ao.OperationError, match="At most"):
        zsb.parse_spec({"type": zsb.TYPE, "hashes": ["a" * 32] * (zsb.MAX_HASHES + 1)})
    with pytest.raises(ao.OperationError):
        zsb.parse_spec({"type": zsb.TYPE, "hashes": "a" * 32})


def test_comments_are_cleaned_and_duplicates_dropped():
    """ASVS V5.1.3 · CWE-117 · CWE-400: a comment loses its control characters and is capped; the same hash twice is planned once."""
    out, undo = zsb.parse_spec({"type": zsb.TYPE, "hashes": [{"md5": "A" * 32, "comment": "x\x07\r\n" + "y" * 500}, "a" * 32]})
    assert not undo and len(out) == 1 and out[0]["comment"].startswith("x") and len(out[0]["comment"]) == zsb.COMMENT_MAX
    assert not re.search(r"[\x00-\x1f]", out[0]["comment"])


# ── The builder: plan, gates, write, read-back, Undo (on the sample) ────

def sample_sdk():
    st = ot.sample_store(reset=True)
    return st, ot.OfflineSdkClient(st, ot.creds_for(st))


def hash_list(st):
    return st.responses[f"{ZIA}/behavioralAnalysisAdvancedSettings"]["body"]["md5HashValueList"]


ZSCOPE = ao.scope_for(["zia_extras"], {})
NEW = "6c14730ff45d686c55bda381b78cb6cc"
OLD = "e9c5e36d0445fb6d6377143ad023feba"


def test_out_of_scope_is_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZIA platform ticked the builder is refused before any read (deny by default)."""
    class NoRead:
        @property
        def zia(self):
            raise AssertionError("read while out of scope")
    with pytest.raises(ao.OperationError, match="ZIA platform"):
        ao.plan(NoRead(), {"type": zsb.TYPE, "hashes": [NEW]}, scope=ao.scope_for(["dlp"], {"web_dlp": "zscaler"}))
    with pytest.raises(ao.OperationError, match="ZIA platform"):
        ao.read_objects(NoRead(), zsb.FAMILY, ao.scope_for(["zpa"], {}))


def test_the_preview_writes_nothing_and_always_asks_for_the_typed_phrase():
    """ASVS V11.1.1 · V4.1.3 · CWE-841 · WSTG-BUSL-06: the preview reads only, a hash already blocked is a no-op, and even one new hash needs the typed phrase."""
    st, cl = sample_sdk()
    before = copy.deepcopy(hash_list(st))
    p = ao.plan(cl, {"type": zsb.TYPE, "hashes": [NEW, OLD]}, scope=ZSCOPE)
    assert hash_list(st) == before and st.writes == 0
    assert p["status"] == "ready" and p["counts"]["change"] == 1 and p["counts"]["noop"] == 1
    assert p["confirm_phrase"] == "BLOCK 1 FILE HASHES" and p["needs_activation"]


def test_an_allow_listed_hash_is_never_touched():
    """ASVS V11.1.1 · CWE-1188 · CWE-284: a hash the tenant allow-lists is excluded with the reason; the builder never turns an allow into a block."""
    st, cl = sample_sdk()
    hash_list(st).append({"url": NEW, "type": "CUSTOM_FILEHASH_ALLOW", "urlComment": "vendor tool"})
    p = ao.plan(cl, {"type": zsb.TYPE, "hashes": [NEW]}, scope=ZSCOPE)
    assert p["counts"]["excluded"] == 1 and p["counts"]["change"] == 0 and "allow list" in p["items"][0]["reason"]


def test_apply_needs_write_mode_and_a_named_assessor():
    """ASVS V4.1.3 · V11.1.1 · CWE-862 · WSTG-ATHZ-02: the engine refuses without write mode or without a named assessor, before any write."""
    st, cl = sample_sdk()
    spec = {"type": zsb.TYPE, "hashes": [NEW]}
    p = ao.plan(cl, spec, scope=ZSCOPE)
    with pytest.raises(PermissionError):
        ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=ZSCOPE, writes_enabled=False, confirm_text=p["confirm_phrase"], assessor="QA")
    with pytest.raises(ao.OperationError):
        ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=ZSCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"], assessor=" ")
    r = ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=ZSCOPE, writes_enabled=True, confirm_text="BLOCK 2 FILE HASHES", assessor="QA")
    assert r["status"] == "refused" and st.writes == 0


def test_a_tenant_change_after_the_preview_writes_nothing():
    """ASVS V11.1.1 · CWE-367 · WSTG-BUSL-06: someone adding the same hash after the preview changes the plan hash, so nothing is written."""
    st, cl = sample_sdk()
    spec = {"type": zsb.TYPE, "hashes": [NEW]}
    p = ao.plan(cl, spec, scope=ZSCOPE)
    hash_list(st).append({"url": NEW, "type": "CUSTOM_FILEHASH_DENY"})
    r = ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=ZSCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"], assessor="QA", settle_seconds=0)
    assert r["status"] == "plan_changed" and st.writes == 0


def test_the_write_rereads_and_conflicts_instead_of_overwriting():
    """ASVS V11.1.1 · CWE-362 · CWE-367: a change between the plan check and the write (re-read right before it) marks the hash as a conflict and sends nothing."""
    st, cl = sample_sdk()
    spec = {"type": zsb.TYPE, "hashes": [NEW]}
    p = ao.plan(cl, spec, scope=ZSCOPE)
    real = zsb.read_list
    calls = {"n": 0}

    def racing(zia):
        calls["n"] += 1
        rows, err = real(zia)
        if calls["n"] == 2:   # the plan check is read 1; the handler's re-read is read 2
            rows = rows + [{"url": NEW, "type": "CUSTOM_FILEHASH_ALLOW", "urlComment": None}]
        return rows, err
    zsb.read_list = racing
    try:
        r = ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=ZSCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"], assessor="QA", settle_seconds=0)
    finally:
        zsb.read_list = real
    assert r["counts_run"]["conflict"] == 1 and r["counts_run"]["applied"] == 0 and st.writes == 0


def test_apply_keeps_every_other_entry_reads_back_and_undo_removes_only_what_was_added():
    """ASVS V11.1.1 · V7.1.3 · CWE-460 · CWE-754: the list is sent back with every other entry untouched plus only the new hash, read back after activation, and Undo removes exactly that hash."""
    st, cl = sample_sdk()
    before = copy.deepcopy(hash_list(st))
    spec = {"type": zsb.TYPE, "hashes": [{"md5": NEW, "comment": "IR-QA"}]}
    p = ao.plan(cl, spec, scope=ZSCOPE)
    r = ao.execute(cl, spec, plan_hash=p["plan_hash"], scope=ZSCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"], assessor="QA", settle_seconds=0)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1 and r["activation"]["activated"]
    assert hash_list(st) == before + [{"url": NEW, "urlComment": "IR-QA", "type": "CUSTOM_FILEHASH_DENY"}]
    inv = r["inverse"]
    assert inv == {"type": zsb.TYPE, "action": "undo", "hashes": [NEW]} and ao.is_undo_only(inv)
    u = ao.plan(cl, inv, scope=ZSCOPE)
    assert u["confirm_phrase"] == "REMOVE 1 FILE HASHES"
    r2 = ao.execute(cl, inv, plan_hash=u["plan_hash"], scope=ZSCOPE, writes_enabled=True, confirm_text=u["confirm_phrase"], assessor="QA", settle_seconds=0)
    assert r2["status"] == "applied" and r2["inverse"] is None and hash_list(st) == before


def test_the_quota_blocks_a_list_that_would_not_fit():
    """ASVS V11.1.4 · CWE-770: when the custom hash quota has no room left the plan is blocked with the reason, not sent to fail."""
    st, cl = sample_sdk()
    st.responses[f"{ZIA}/behavioralAnalysisAdvancedSettings/fileHashCount"]["body"] = {"blockedFileHashesCount": 10000, "remainingFileHashes": 0}
    p = ao.plan(cl, {"type": zsb.TYPE, "hashes": [NEW]}, scope=ZSCOPE)
    assert p["status"] == "blocked" and "quota" in p["blockers"][0]


def test_a_snapshot_refuses_the_write():
    """ASVS V4.1.3 · CWE-284: an opened snapshot is read-only: the hash list write is refused offline and nothing changes."""
    st = ot.OfflineStore("snap-0123456789abcdef", "snapshot", {ot.normalize_path(f"{ZIA}/behavioralAnalysisAdvancedSettings"):
                                                               {"status": 200, "body": {"md5HashValueList": []}}}, {}, writable=False)
    assert st.answer_write("PUT", f"{ZIA}/behavioralAnalysisAdvancedSettings", {"md5HashValueList": [{"url": NEW}]})[0] == 403


# ── Through the API: the gates before sign-in ───────────────────────────

BODY = {"scopes": ["zia_extras"], "channels": {}, "from_page": True, "client_id": "cid", "client_secret": "s3cret-value",
        "vanity_domain": "acme", "cloud": "zscalertwo", "assessor": "Jane Doe"}


def test_the_api_refuses_out_of_scope_before_sign_in_and_runs_every_gate(monkeypatch):
    """ASVS V4.1.3 · V11.1.1 · CWE-863 · CWE-841 · WSTG-ATHZ-02: out of scope is a 400 before any client is built; in scope the apply needs write mode, the typed phrase and the assessor, and the Undo is previewed from the record."""
    import dlp_api_server as srv
    import security
    st, cl = sample_sdk()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or cl)
    c = TestClient(srv.app)
    op = {"type": zsb.TYPE, "hashes": [NEW]}
    r = c.post("/api/operations/preview", json=dict(BODY, scopes=["dlp"], operation=op))
    assert r.status_code == 400 and "ZIA platform" in r.json()["detail"] and built == []
    r = c.post("/api/operations/preview", json=dict(BODY, operation=dict(op, hashes=["not-a-hash"])))
    assert r.status_code == 400 and "MD5" in r.json()["detail"]
    r = c.post("/api/operations/preview", json=dict(BODY, operation=op))
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["confirm_phrase"] == "BLOCK 1 FILE HASHES" and "s3cret" not in r.text
    body = dict(BODY, operation=op, plan_hash=p["plan_hash"], confirm=True, confirm_text=p["confirm_phrase"])
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    assert c.post("/api/operations/apply", json=body).status_code == 403 and st.writes == 0
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(security, "may_write", lambda: True)
    assert c.post("/api/operations/apply", json=dict(body, assessor="")).status_code == 400 and st.writes == 0
    r = c.post("/api/operations/apply", json=dict(body, confirm_text="block it"))
    assert r.status_code >= 400 and "BLOCK 1 FILE HASHES" in r.text and st.writes == 0
    r = c.post("/api/operations/apply", json=body)
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    oid = r.json()["operation_id"]
    assert any(e["url"] == NEW for e in hash_list(st))
    u = c.post(f"/api/operations/{oid}/undo/preview", json=BODY).json()
    assert u["undo_of"] == oid and u["confirm_phrase"] == "REMOVE 1 FILE HASHES"
    r = c.post("/api/operations/apply", json=dict(BODY, operation=u["operation"], plan_hash=u["plan_hash"], confirm=True,
                                                    confirm_text=u["confirm_phrase"], undo_of=oid))
    assert r.status_code == 200 and r.json()["status"] == "applied" and not any(e["url"] == NEW for e in hash_list(st))


def test_an_undo_form_cannot_be_sent_as_an_ordinary_operation(monkeypatch):
    """ASVS V4.1.3 · CWE-639 · CWE-841: the remove form (action undo) is applied only as the Undo of a recorded operation, never on its own."""
    import dlp_api_server as srv
    import security
    st, cl = sample_sdk()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: cl)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(security, "may_write", lambda: True)
    c = TestClient(srv.app)
    op = {"type": zsb.TYPE, "action": "undo", "hashes": [OLD]}
    p = c.post("/api/operations/preview", json=dict(BODY, operation=op)).json()
    r = c.post("/api/operations/apply", json=dict(BODY, operation=op, plan_hash=p.get("plan_hash", ""), confirm=True, confirm_text="REMOVE 1 FILE HASHES"))
    assert r.status_code == 409 and "Undo" in r.json()["detail"] and any(e["url"] == OLD for e in hash_list(st))


# ── The form ────────────────────────────────────────────────────────────

FORM = open(os.path.join(ROOT, "static", "ops_zia_sandbox.js"), encoding="utf-8").read()


def test_the_form_escapes_tenant_text_and_labels_its_field():
    """ASVS V5.3.3 · CWE-79 · WCAG 2.2 SC 1.3.1 · SC 3.3.2 · SC 4.1.3: every value drawn into the form goes through the page's escaper, the field has a label and a live status line, and the form never writes HTML from the server unescaped."""
    for m in re.finditer(r"\$\{([^}]+)\}", FORM):
        expr = m.group(1)
        if re.search(r"res\.|F\.text", expr):
            assert expr.strip().startswith(("E(", "errorsHtml(", "counts")) or "E(" in expr, expr
    assert '<label class="lbl" for="zsbHashes">' in FORM and 'aria-live="polite"' in FORM and "aria-describedby=\"zsbCheck\"" in FORM
    assert "innerHTML = `${errorsHtml(E, res)}" in FORM and "eval(" not in FORM


def test_the_field_has_help_and_the_builder_is_marked_new():
    """WCAG 2.2 SC 3.3.2 · SC 3.3.5: the hash field has a help-catalogue entry saying the format, and What's new marks the builder and the checks under 2026-10-31."""
    cat = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    assert '"#zsbHashes"' in cat and "MD5" in cat[cat.index('"#zsbHashes"'):cat.index('"#zsbHashes"') + 400]
    wn = open(os.path.join(ROOT, "static", "whats_new.js"), encoding="utf-8").read()
    # While 2026-10-31 is one of the newest two releases they are marked; once rotated out (keep: 2) they stay in CHANGELOG.md.
    if '"2026-10-31":' in wn.split('"skipped"')[0]:
        assert '"id": "sandbox-hashes", "release": "2026-10-31"' in wn and '"id": "threat-saas-checks", "release": "2026-10-31"' in wn
    else:
        assert "## 2026-10-31" in open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
        assert '"id": "sandbox-hashes"' not in wn and '"id": "threat-saas-checks"' not in wn
