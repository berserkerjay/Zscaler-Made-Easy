"""The generic unknown-condition guard (rule_fields): every field of the
zscaler-sdk-python 1.11.3 rule models is classified per Path analyzer
module (evaluated, neutral or a named unknown condition), and ANY other
non-empty field on a rule makes that rule's criterion unknown, so a field a
newer API adds is never silently ignored. Fake tenants only, no network."""
from __future__ import annotations

import ast
import copy
import importlib.util
import os
import re

import pytest

import path_whatif
import rule_fields
import zia_path_modules as zpm
import zpa_analysis
import zpa_reader
from test_path_zia_modules import Tenant, hop, mod, run
from zia_module_fixtures import MODULE_ROUTES
from test_data_flow import ROUTES

NEW = "futureCondition"   # a field no SDK model has: what a newer API might add

# Every field of each SDK 1.11.3 model (the __init__ config keys and the
# request_format keys), per Path analyzer module. zpa is the access and
# client forwarding policy rule (PolicySetControllerV1 and V2).
SDK_1_11_3 = {
    "url": ("action blockOverride cbiProfile ciparule departments description deviceGroups deviceTrustLevels "
           "devices endUserNotificationUrl enforceTimeValidity groups httpHeaderActionProfiles "
           "httpHeaderProfiles id labels lastModifiedBy lastModifiedTime locationGroups locations name order "
           "overrideGroups overrideUsers protocols rank requestMethods sizeQuota sourceIpGroups state timeQuota "
           "timeWindows urlCategories urlCategories2 userAgentTypes userRiskScoreLevels users validityEndTime "
           "validityStartTime validityTimeZoneId workloadGroups").split(),
    "cac": ("accessControl actions applications browserEunTemplateId cascadingEnabled cbiProfile "
           "cloudAppInstances cloudAppRiskProfile departments description deviceGroups deviceTrustLevels devices "
           "enforceTimeValidity eunEnabled eunTemplateId formSharingDomainProfiles groups id labels "
           "lastModifiedBy lastModifiedTime locationGroups locations name order predefined rank "
           "sharingDomainProfiles sizeQuota state tenancyProfileIds timeQuota timeWindows type userAgentTypes "
           "userRiskScoreLevels users validityEndTime validityStartTime validityTimeZoneId").split(),
    "ssl": ("accessControl action cloudApplications defaultRule departments description destIpGroups deviceGroups "
           "deviceTrustLevels devices groups id labels lastModifiedBy lastModifiedTime locationGroups locations "
           "name order platforms predefined proxyGateways rank roadWarriorForKerberos sourceIpGroups state "
           "timeWindows urlCategories userAgentTypes users workloadGroups zpaAppSegments").split(),
    "ftc": ("accessControl activeContent capturePCAP cloudApplications departments description deviceGroups "
           "deviceTrustLevels devices fileTypes filteringAction groups id labels lastModifiedBy lastModifiedTime "
           "locationGroups locations maxSize minSize name operation order passwordProtected protocols rank "
           "sizeQuota state timeQuota timeWindows unscannable urlCategories users zpaAppSegments").split(),
    "dlp": ("accessControl action auditor cloudApplications departments description dlpContentLocationsScopes "
           "dlpDownloadScanEnabled dlpEngines eunTemplateId excludedDepartments excludedDomainProfiles "
           "excludedGroups excludedUsers externalAuditorEmail fileTypes groups icapServer id "
           "includedDomainProfiles inspectHttpGetEnabled labels locationGroups locations matchOnly minSize name "
           "notificationTemplate order parentRule protocols rank severity sourceIpGroups state subRules "
           "urlCategories userRiskScoreLevels users withoutContentInspection workloadGroups "
           "zccNotificationsEnabled zpaAppSegments zscalerIncidentReceiver").split(),
    "firewall": ("accessControl action appServiceGroups appServices capturePCAP defaultRule departments description "
                "destAddresses destCountries destIpCategories destIpGroups destIpv6Groups deviceGroups "
                "deviceTrustLevels devices enableFullLogging excludeSrcCountries groups id labels lastModifiedBy "
                "lastModifiedTime locationGroups locations name nwApplicationGroups nwApplications nwServiceGroups "
                "nwServices order predefined rank sourceCountries srcIpGroups srcIps srcIpv6Groups state timeWindows "
                "users workloadGroups zpaAppSegments").split(),
    "dns": ("accessControl action applicationGroups applications blockResponseCode capturePCAP "
           "defaultDnsRuleNameUsed defaultRule departments description destAddresses destCountries "
           "destIpCategories destIpGroups destIpv6Groups deviceGroups devices dnsGateway dnsRuleRequestTypes "
           "ednsEcsObject groups id isWebEunEnabled labels lastModifiedBy lastModifiedTime locationGroups "
           "locations name order predefined protocols rank redirectIp resCategories sourceCountries srcIpGroups "
           "srcIps srcIpv6Groups state timeWindows users zpaIpGroup").split(),
    "sandbox": ("accessControl baPolicyCategories baRuleAction byThreatScore cbiProfile cbiProfileId defaultRule "
               "departments description fileTypes firstTimeEnable firstTimeOperation groups id labels lastModifiedBy "
               "lastModifiedTime locationGroups locations mlActionEnabled name order protocols rank state "
               "urlCategories users zpaAppSegments").split(),
    "atp": ("activeXBlocked activeXCapture adSpywareSitesBlocked adSpywareSitesCapture "
           "alertForUnknownOrSuspiciousC2Traffic anonymizerBlocked anonymizerCapture bitTorrentBlocked "
           "bitTorrentCapture blockCountriesCapture blockedCountries browserExploitsBlocked "
           "browserExploitsCapture cmdCtlServerBlocked cmdCtlServerCapture cmdCtlTrafficBlocked "
           "cmdCtlTrafficCapture cookieStealingBlocked cookieStealingPCAPEnabled cryptoMiningBlocked "
           "cryptoMiningCapture dgaDomainsBlocked dgaDomainsCapture fileFormatVunerabilitesBlocked "
           "fileFormatVunerabilitesCapture googleTalkBlocked googleTalkCapture ircTunnellingBlocked "
           "ircTunnellingCapture knownPhishingSitesBlocked knownPhishingSitesCapture maliciousUrlsCapture "
           "malwareSitesBlocked malwareSitesCapture potentialMaliciousRequestsBlocked "
           "potentialMaliciousRequestsCapture riskTolerance riskToleranceCapture sshTunnellingBlocked "
           "sshTunnellingCapture suspectAdwareSpywareSitesBlocked suspectAdwareSpywareSitesCapture "
           "suspectedPhishingSitesBlocked suspectedPhishingSitesCapture torBlocked torCapture webspamBlocked "
           "webspamCapture").split(),
    "zpa": ("action actionId appConnectorGroups appServerGroups browserPostureName browserPostureProfileId "
           "buttonText conditions creationTime credential credentialPool customMsg defaultRule description "
           "desktopPolicyMappings devicePostureFailureNotificationEnabled disabled extranetDTO extranetEnabled "
           "id microtenantId microtenantName modifiedBy modifiedTime name operator policySetId policyType "
           "postActionTypes postActions priority privilegedCapabilities privilegedPortalCapabilities readOnly "
           "reauthIdleTimeout reauthTimeout restrictionType ruleOrder serviceEdgeGroups url version "
           "zpnInspectionProfileId zpnInspectionProfileName zpnIsolationProfileId zscalerManaged").split(),
}
MODEL_FILES = {
    "url": [("zia/models/url_filtering_rules.py", "URLFilteringRule")],
    "cac": [("zia/models/cloudappcontrol.py", "CloudApplicationControl")],
    "ssl": [("zia/models/ssl_inspection_rules.py", "SSLInspectionRules")],
    "ftc": [("zia/models/filetyperules.py", "FileTypeControlRules")],
    "dlp": [("zia/models/dlp_web_rules.py", "DLPWebRules")],
    "firewall": [("zia/models/cloud_firewall_rules.py", "FirewallRule")],
    "dns": [("zia/models/cloud_firewall_dns_rules.py", "FirewallDNSRules")],
    "sandbox": [("zia/models/sandboxrules.py", "SandboxRules")],
    "atp": [("zia/models/advanced_threat_settings.py", "AdvancedThreatProtectionSettings")],
    "zpa": [("zpa/models/policyset_controller_v1.py", "PolicySetControllerV1"), ("zpa/models/policyset_controller_v2.py", "PolicySetControllerV2")],
}
NAMED = [f for f, _, _ in zpm.UNEVALUATED + zpm.EXCLUDED]


def _sdk_root():
    spec = importlib.util.find_spec("zscaler")
    return os.path.dirname(spec.origin) if spec and spec.origin else None


def _sdk_version():
    try:
        from importlib.metadata import version
        return version("zscaler-sdk-python")
    except Exception:  # noqa: BLE001
        return None


def _model_fields(path, cls):
    """The camelCase fields a model reads from its config or writes in request_format (source read, never run)."""
    src = open(path, encoding="utf-8").read()
    for node in ast.parse(src).body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            seg = ast.get_source_segment(src, node)
            return (set(re.findall(r'config\[\s*"(\w+)"\s*\]', seg)) | set(re.findall(r'"(\w+)"\s+in\s+config', seg))
                    | set(re.findall(r'"(\w+)":\s*(?:self|\[)', seg)))
    raise AssertionError(f"{cls} not found in {path}")


# ── Every SDK field is classified ────────────────────────────────────
@pytest.mark.parametrize("module", sorted(SDK_1_11_3))
def test_every_sdk_1_11_3_model_field_is_classified_for_its_module(module):
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: every field of the SDK 1.11.3 model is evaluated, neutral or a named unknown condition, never unclassified."""
    unclassified = [f for f in SDK_1_11_3[module] if rule_fields.classify(module, f, labelled=NAMED) == "unknown"]
    assert unclassified == []
    assert all(f in MODEL_FILES for f in [module])


@pytest.mark.skipif(_sdk_version() != "1.11.3" or _sdk_root() is None, reason="the field snapshot is checked against SDK 1.11.3 only")
@pytest.mark.parametrize("module", sorted(MODEL_FILES))
def test_the_field_snapshot_is_the_installed_sdk_1_11_3_models(module):
    """ASVS V1.1.2 · CWE-1173: the snapshot above is exactly what the installed SDK 1.11.3 models carry."""
    root = _sdk_root()
    got = set()
    for rel, cls in MODEL_FILES[module]:
        got |= _model_fields(os.path.join(root, rel), cls)
    assert sorted(got) == sorted(SDK_1_11_3[module])


def test_the_classes_do_not_overlap():
    """ASVS V1.1.2 · CWE-1173: a field is evaluated or neutral for a module, never both."""
    for m in rule_fields.MODULES:
        assert not (rule_fields.EVALUATED[m] & rule_fields.NEUTRAL[m]), m


# ── A field this tool does not know is an unknown condition ──────────
@pytest.mark.parametrize("module", [m for m in rule_fields.MODULES if m not in ("atp", "zpa")])
def test_an_unknown_field_is_an_unknown_criterion_in_every_rule_module(module):
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: a synthetic field a newer API might add is an unknown criterion, never ignored."""
    rule = {"id": 1, "name": "r", "order": 1, "state": "ENABLED", NEW: ["X"]}
    crits = zpm.unevaluated(rule, module=module)
    other = [c for c in crits if c["name"] == f"Other condition ({NEW})"]
    assert other and other[0]["state"] == "unknown" and NEW in other[0]["detail"] and "X" in other[0]["detail"]
    assert zpm.unresolved_labels(rule, module) == [f"Other condition ({NEW})"]


@pytest.mark.parametrize("value", [None, "", [], {}, False, 0, "ANY", ["NONE"], {"id": 0, "name": ""}, [{"id": None}]])
def test_an_empty_value_sets_no_condition(value):
    """ASVS V1.1.2 · CWE-1173: an empty, false, zero or ANY value restricts nothing, so it is never an unknown criterion."""
    for module in ("url", "firewall", "dlp"):
        assert rule_fields.other_fields({NEW: value}, module) == []


def test_neutral_metadata_and_evaluated_fields_never_flag_in_any_case_or_spelling():
    """ASVS V1.1.2 · CWE-1173: camelCase, snake_case and capitalisation drift are one field."""
    rule = {"id": 7, "name": "r", "order": 3, "rank": 7, "description": "d", "state": "ENABLED", "lastModifiedTime": 1,
            "last_modified_by": {"id": 1, "name": "a"}, "capturePcap": True, "enable_full_logging": True, "nw_services": [{"id": 1}],
            "dest_ip_groups": [{"id": 2}], "action": "ALLOW"}
    assert rule_fields.other_fields(rule, "firewall") == []
    assert zpm.unevaluated(rule, module="firewall") == []


def test_the_named_conditions_keep_their_words_and_the_firewall_source_is_not_doubled():
    """ASVS V1.1.2 · CWE-1173: a named condition keeps its label; a field the module evaluates itself is not repeated as unknown."""
    rule = {"timeWindows": [{"id": 1, "name": "Night"}], "srcIps": ["10.0.0.1"], "sizeQuota": 1024,
            "sourceCountries": ["COUNTRY_US"], "excludeSrcCountries": True}
    fw = {c["name"]: c for c in zpm.unevaluated(rule, module="firewall")}
    assert fw["Time window"]["detail"].startswith("Applies only to Night")
    assert "Source IP" not in fw   # the firewall evaluates srcIps itself (_crit_source)
    assert fw["Source country"]["detail"].startswith("Does not apply to COUNTRY_US")
    assert "Size quota" in fw and "Other condition (sizeQuota)" not in fw   # a named condition wherever it appears
    url = {c["name"]: c for c in zpm.unevaluated(rule, module="url")}
    assert "Size quota" in url and "Source IP" in url


def test_without_a_module_only_the_named_list_is_checked():
    """ASVS V1.1.2 · CWE-1173: callers that do not name a module (shadowed rules, the console index) keep the earlier behaviour."""
    assert zpm.unevaluated({NEW: ["X"], "users": [{"name": "Ann"}]}) == [
        {"name": "Users", "state": "unknown", "detail": "Applies only to Ann; the trace is for any user."}]


# ── Each module: a rule with an unknown field is never a definite match ─
def _routes(**over):
    r = copy.deepcopy(dict(ROUTES, **MODULE_ROUTES))
    r.update(over)
    return r


def _with_new(rules, name):
    out = copy.deepcopy(rules)
    next(x for x in out if x["name"] == name)[NEW] = ["X"]
    return out


def test_url_filtering_a_matching_block_rule_with_an_unknown_field_is_conditional_not_a_block():
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: the URL block that would decide carries an unknown field, so the block is not asserted."""
    base = run("casino.example", tenant=Tenant(_routes(**{"/zia/firewallDnsRules": []})))
    assert hop(base, "url")["status"] == "blocked"
    r = run("casino.example", tenant=Tenant(_routes(**{"/zia/firewallDnsRules": [],
                                                      "/zia/urlFilteringRules": _with_new(ROUTES["/zia/urlFilteringRules"], "Block gambling")})))
    assert hop(r, "url")["status"] == "conditional"
    assert r["verdict"]["outcome"] != "blocked"


def test_cloud_firewall_a_matching_block_rule_with_an_unknown_field_is_conditional():
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: Allow web with an unknown field no longer decides HTTP definitely."""
    base = mod(run("chat.openai.com", "tcp", 80), "firewall")
    assert base["certainty"] == "definite" and base["rule"]["name"] == "Allow web"
    rules = _with_new(MODULE_ROUTES["/zia/firewallFilteringRules"], "Allow web")
    fw = mod(run("chat.openai.com", "tcp", 80, tenant=Tenant(_routes(**{"/zia/firewallFilteringRules": rules}))), "firewall")
    assert fw["certainty"] == "conditional" and fw["rule"]["default"]
    could = next(c for c in fw["could_override"] if c["name"] == "Allow web")
    assert any(c["name"] == f"Other condition ({NEW})" and c["state"] == "unknown" for c in could["criteria"])


def test_dns_control_a_matching_block_rule_with_an_unknown_field_is_conditional():
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: a DNS block with an unknown field does not end the path."""
    assert mod(run("casino.example"), "dns")["verdict"] == "block"
    rules = _with_new(MODULE_ROUTES["/zia/firewallDnsRules"], "Block gambling lookups")
    dns = mod(run("casino.example", tenant=Tenant(_routes(**{"/zia/firewallDnsRules": rules}))), "dns")
    assert dns["certainty"] == "conditional" and dns["verdict"] == "allow"


def test_sandbox_a_rule_with_an_unknown_field_shows_it_as_unknown():
    """ASVS V1.1.2 · CWE-1173: a Sandbox rule's unknown field is an unknown criterion."""
    rule = copy.deepcopy(MODULE_ROUTES["/zia/sandboxRules"][0])
    rule[NEW] = True
    assert any(c["name"] == f"Other condition ({NEW})" for c in zpm.unevaluated(rule, module="sandbox"))


def test_ssl_inspection_an_unknown_field_on_the_deciding_rule_leaves_decryption_conditional():
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: the catch-all Decrypt rule with an unknown field no longer proves decryption."""
    assert hop(run("chat.openai.com"), "ssl")["status"] == "pass"
    rules = _with_new(ROUTES["/zia/sslInspectionRules"], "Decrypt all")
    r = run("chat.openai.com", tenant=Tenant(_routes(**{"/zia/sslInspectionRules": rules})))
    assert hop(r, "ssl")["status"] == "conditional"


def test_cloud_app_control_an_unknown_field_makes_the_app_rule_a_candidate_only():
    """ASVS V1.1.2 · CWE-1173: a Cloud App Control rule with an unknown field is a candidate, never the decision."""
    class Box(Tenant):
        LOOKUP = dict(Tenant.LOOKUP, **{"box.example": {"urlClassifications": ["FILE_HOST"], "application": "BOX"}})
    assert hop(run("box.example", tenant=Box(_routes())), "cac")["status"] == "warn"
    rules = _with_new(ROUTES["/zia/cloudApplicationRules"], "File share allow all")
    r = run("box.example", tenant=Box(_routes(**{"/zia/cloudApplicationRules": rules})))
    assert hop(r, "cac")["status"] == "conditional"


def test_web_dlp_a_rule_with_an_unknown_field_is_not_an_eligible_rule():
    """ASVS V1.1.2 · CWE-1173: a Web DLP rule with an unknown field is conditional, like an identity-scoped one."""
    rules = copy.deepcopy(ROUTES["/zia/webDlpRules"])
    for x in rules:
        x[NEW] = ["X"]
    r = run("chat.openai.com", tenant=Tenant(_routes(**{"/zia/webDlpRules": rules})))
    assert hop(r, "dlp")["status"] == "conditional"


def test_atp_a_setting_this_tool_does_not_know_that_is_on_makes_atp_conditional():
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: a newer ATP toggle that is on could block: unknown, never ignored."""
    assert mod(run("chat.openai.com"), "atp")["certainty"] == "definite"
    settings = dict(MODULE_ROUTES["/zia/cyberThreatProtection/advancedThreatSettings"], futureThreatBlocked=True, futureThreatCapture=False)
    atp = mod(run("chat.openai.com", tenant=Tenant(_routes(**{"/zia/cyberThreatProtection/advancedThreatSettings": settings}))), "atp")
    assert atp["certainty"] == "conditional"
    assert [c["name"] for c in atp["could_override"]] == ["Other ATP setting (futureThreatBlocked): on"]


def test_atp_content_toggles_are_named_as_run_time_detections():
    """ASVS V1.1.2 · CWE-1173: a known content-based toggle is said, not guessed and not unknown."""
    settings = dict(MODULE_ROUTES["/zia/cyberThreatProtection/advancedThreatSettings"], sshTunnellingBlocked=True)
    atp = mod(run("chat.openai.com", tenant=Tenant(_routes(**{"/zia/cyberThreatProtection/advancedThreatSettings": settings}))), "atp")
    assert atp["certainty"] == "definite" and any("SSH tunnelling" in n for n in atp["notes"])


def test_zpa_an_access_rule_with_an_unknown_field_is_conditional():
    """ASVS V1.1.2 · CWE-1173 · WSTG-BUSL-01: a ZPA access rule with a field the evaluation does not read never matches definitely."""
    raw = {"id": "1", "name": "Allow all", "ruleOrder": "1", "action": "ALLOW", "conditions": [], "description": "",
           "appServerGroups": [{"id": "9"}], "customMsg": "hi"}
    plain = zpa_reader.normalize_rule(raw, 0, "access")
    assert plain["unknown_fields"] == []
    assert zpa_analysis.evaluate_rule(plain, {}, None, None)["status"] == "matched"
    rule = zpa_reader.normalize_rule(dict(raw, **{NEW: ["X"], "extranetEnabled": True}), 0, "access")
    assert sorted(f["label"] for f in rule["unknown_fields"]) == ["Extranet", f"Other condition ({NEW})"]
    ev = zpa_analysis.evaluate_rule(rule, {}, None, None)
    assert ev["status"] == "conditional" and f"Other condition ({NEW})" in ev["depends_on"]


def test_the_what_if_never_settles_an_unknown_field():
    """ASVS V1.1.2 · CWE-1173: an identity that meets a rule's scope still leaves a field this tool does not know open."""
    rule = {"scope_items": {"users": [{"id": 1, "name": "Ann"}]}, "scope": ["users: 1"], "unresolved": [f"Other condition ({NEW})"]}
    state, crit = path_whatif.rule_criteria(rule, {"user": {"id": 1, "name": "Ann"}, "groups": []})
    assert state is None and crit[-1]["state"] == "unknown" and NEW in crit[-1]["name"]
    state, crit = path_whatif.rule_criteria({"scope_items": {}, "unresolved": ["Size quota"]}, None)
    assert state is None and crit[0]["name"] == "unevaluated condition: Size quota"
