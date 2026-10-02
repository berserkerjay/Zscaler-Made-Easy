"""Checks brought in line with current Zscaler guidance and with the field
names the APIs actually return (zscaler-sdk-python 1.11.0): SSL Inspection
actions are objects, Client Connector settings live in policyExtension and
the per-platform policies, Windows 11 also reports version 10.0, and the
reference texts name current dates and pages."""
from __future__ import annotations

import json

import dlp_assessment_full_auto as chk
import zscaler_genai_checks as genai


class FakeCl:
    customer_id = ""

    def __init__(self, routes):
        self.routes = routes

    def get(self, endpoint, params=None):
        ep = endpoint.replace("raw:", "")
        if ep in self.routes:
            return self.routes[ep], 200
        return {"error": "not found"}, 404


# ── SSL Inspection: the action is {"type": ...} ─────────────────────────
SSL_RULES = [
    {"id": 1, "name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True,
     "action": {"type": "DO_NOT_DECRYPT", "doNotDecryptSubActions": {"bypassOtherPolicies": True}}},
    {"id": 2, "name": "Decrypt everything else", "order": 2, "state": "ENABLED",
     "action": {"type": "DECRYPT", "decryptSubActions": {"serverCertificates": "BLOCK", "minServerTLSVersion": "SERVER_TLS_1_2"}}},
    {"id": 3, "name": "Old pilot", "order": 3, "state": "DISABLED", "action": {"type": "DECRYPT"}},
]


def test_ssl_checks_read_the_action_object():
    cl = FakeCl({"/zia/sslInspectionRules": SSL_RULES})
    r = chk.c_4_1(cl)
    assert r.status == chk.R.PASS and "1 enabled Decrypt rule(s), 1 Do Not Decrypt" in r.detail
    assert chk.c_4_13(cl).status == chk.R.PASS
    assert chk.c_7_3(cl).status == chk.R.PASS
    assert chk.c_e2(cl).status == chk.R.PASS
    # The Recommended Exemptions rule is predefined and part of Zscaler's recommended policy: not a finding.
    dni = chk.c_4_5(cl)
    assert dni.status == chk.R.PASS and "No custom Do Not Decrypt" in dni.detail
    assert genai.ai_5(cl).status == chk.R.PASS
    assert genai.ai_6(cl).status == chk.R.PASS


def test_a_broad_do_not_decrypt_rule_above_decrypt_is_caught():
    rules = [{"name": "Exempt all", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}},
             {"name": "Decrypt", "order": 2, "state": "ENABLED", "action": {"type": "DECRYPT"}}]
    r = chk.c_4_3(FakeCl({"/zia/sslInspectionRules": rules}))
    assert r.status == chk.R.FAIL and "shadows" in r.detail
    # A category-scoped exemption does not shadow the decrypt rule.
    rules[0]["urlCategories"] = ["FINANCE"]
    assert chk.c_4_3(FakeCl({"/zia/sslInspectionRules": rules})).status == chk.R.PASS


def test_only_disabled_decrypt_rules_is_no_inspection():
    rules = [{"name": "Decrypt", "state": "DISABLED", "action": {"type": "DECRYPT"}}]
    cl = FakeCl({"/zia/sslInspectionRules": rules})
    assert chk.c_4_1(cl).status == chk.R.FAIL
    assert genai.ai_5(cl).status == chk.R.FAIL


def test_ssl_string_actions_from_old_exports_still_read():
    cl = FakeCl({"/zia/sslInspectionRules": [{"name": "x", "state": "ENABLED", "action": "INSPECT"}]})
    assert chk.c_4_1(cl).status == chk.R.PASS


def test_genai_exemption_of_an_ai_domain_is_a_failure():
    rules = [{"name": "Exempt ChatGPT", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urls": ["chatgpt.com"]}]
    assert genai.ai_6(FakeCl({"/zia/sslInspectionRules": rules})).status == chk.R.FAIL


# ── Client Connector: settings in policyExtension / platform policies ───
def _profile(**ext):
    return {"id": 1, "name": "Corp", "active": 1, "disablePassword": "x", "uninstallPassword": "x",
            "windowsPolicy": {"install_ssl_certs": ext.pop("installCerts", 1)},
            "policyExtension": json.dumps(ext)}


def test_install_endpoint_dlp_is_read_from_policy_extension():
    on = FakeCl({"/zcc/appProfiles": {"list": [_profile(enableZdpService=1)]}})
    r = chk.c_3_2(on)
    assert r.status == chk.R.PASS and "1/1" in r.detail
    assert chk.c_5_1(on).status == chk.R.PASS and chk.c_b1(on).status == chk.R.PASS
    off = FakeCl({"/zcc/appProfiles": {"list": [_profile(enableZdpService=0)]}})
    assert chk.c_3_2(off).status == chk.R.FAIL
    # Not reported at all is a question for the portal, not a failure.
    unknown = FakeCl({"/zcc/appProfiles": {"list": [{"id": 1, "name": "Corp"}]}})
    assert chk.c_3_2(unknown).status == chk.R.WARN


def test_ssl_certificate_install_is_read_from_the_platform_policy():
    assert chk.c_3_3(FakeCl({"/zcc/appProfiles": [_profile(installCerts=1)]})).status == chk.R.PASS
    assert chk.c_3_3(FakeCl({"/zcc/appProfiles": [_profile(installCerts=0)]})).status == chk.R.WARN


def test_dns_exclusion_priority_is_an_app_profile_setting():
    # Zscaler: Prioritize DNS Exclusions over Z-Tunnel 2.0 "is enabled by default in new app profiles and is recommended".
    routes = {"/zcc/forwardingProfiles": [{"id": 5, "name": "fp"}]}
    routes["/zcc/appProfiles"] = [_profile(prioritizeDnsExclusions=1)]
    assert chk.c_1_7(FakeCl(routes)).status == chk.R.PASS
    assert chk.c_2_4(FakeCl(routes)).status == chk.R.PASS
    routes["/zcc/appProfiles"] = [_profile(prioritizeDnsExclusions=0)]
    r = chk.c_1_7(FakeCl(routes))
    assert r.status == chk.R.WARN and "Zscaler recommends it" in r.detail and "Corp" in r.detail
    # It applies only to Client Connector 4.6+ for Windows: a macOS profile is not assessed.
    mac = dict(_profile(prioritizeDnsExclusions=0), device_type=4)
    assert chk.c_1_7(FakeCl({"/zcc/appProfiles": [mac]})).status == chk.R.INFO


def test_z_tunnel_2_is_read_from_the_forwarding_actions():
    fp = {"id": 5, "name": "Corp", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"}]}
    r = chk.c_1_6(FakeCl({"/zcc/forwardingProfiles": [fp]}))
    assert r.status == chk.R.PASS and "1 of 1" in r.detail
    pac = {"id": 6, "name": "PAC", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ENFORCE_PROXY"}]}
    r = chk.c_1_6(FakeCl({"/zcc/forwardingProfiles": [pac]}))
    assert r.status == chk.R.WARN and "Z-Tunnel 2.0" in r.detail


# ── Windows 10: Windows 11 also reports 10.0 ───────────────────────────
def test_windows_11_is_not_counted_as_windows_10():
    devs = [{"osType": "Windows", "osVersion": "10.0.22631"},                 # Windows 11 23H2
            {"osType": "Windows", "osVersion": "Microsoft Windows 11 Enterprise;64 bit"},
            {"osType": "Windows", "osVersion": "10.0.19045"},                 # Windows 10 22H2
            {"osType": "Windows", "osVersion": "Microsoft Windows 10 Pro;64 bit"},
            {"osType": "macOS", "osVersion": "10.15.7"}]
    r = chk.c_6_7(FakeCl({"/zcc/devices": devs}))
    assert r.status == chk.R.WARN and r.detail.startswith("2 Windows 10 device(s)")
    assert "14 October 2025" in r.detail and "Oct 2026" not in r.detail
    assert chk.c_6_7(FakeCl({"/zcc/devices": devs[:2]})).status == chk.R.PASS


# ── SSL decrypt sub-actions (4.14) ──────────────────────────────────────
def test_decrypt_rule_hardening_follows_the_leading_practices_guide():
    good = {"name": "Inspect all", "state": "ENABLED", "action": {"type": "DECRYPT", "decryptSubActions": {
        "serverCertificates": "BLOCK", "ocspCheck": True, "blockUndecrypt": True,
        "minClientTLSVersion": "CLIENT_TLS_1_2", "minServerTLSVersion": "SERVER_TLS_1_2"}}}
    r = chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [good]}))
    assert r.status == chk.R.PASS and r.data == {"rules": 1, "weak": 0}
    weak = {"name": "Legacy decrypt", "state": "ENABLED", "action": {"type": "DECRYPT", "decryptSubActions": {
        "serverCertificates": "PASS_THRU", "ocspCheck": False, "blockUndecrypt": False,
        "minClientTLSVersion": "CLIENT_TLS_1_0", "minServerTLSVersion": "SERVER_TLS_1_2"}}}
    r = chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [good, weak]}))
    assert r.status == chk.R.WARN and r.data == {"rules": 2, "weak": 1}
    for part in ("Legacy decrypt", "PASS_THRU", "OCSP revocation check off", "undecryptable traffic allowed", "CLIENT_TLS_1_0"):
        assert part in r.detail
    assert "SERVER_TLS_1_2" not in r.detail
    # Sub-actions the API did not return are not held against the rule; no decrypt rule is INFO.
    assert chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [{"name": "x", "state": "ENABLED", "action": {"type": "DECRYPT"}}]})).status == chk.R.PASS
    assert chk.c_4_14(FakeCl({"/zia/sslInspectionRules": SSL_RULES[:1]})).status == chk.R.INFO


def test_new_ssl_check_is_registered_once():
    ids = [c[0] for c in chk.REG]
    assert ids.count("4.14") == 1 and len(ids) == len(set(ids))
    assert ids.index("4.14") == ids.index("4.13") + 1


# ── ECH is handled in DNS Control (4.12) ────────────────────────────────
def test_ech_is_suppressed_by_blocking_https_and_svcb_records():
    both = [{"name": "Block ECH", "state": "ENABLED", "action": "BLOCK_WITH_RESPONSE", "dnsRuleRequestTypes": ["HTTPS", "SVCB"]}]
    r = chk.c_4_12(FakeCl({"/zia/firewallDnsRules": both}))
    assert r.status == chk.R.PASS and "Block ECH" in r.detail
    one = [{"name": "Block HTTPS RR", "state": "ENABLED", "action": "BLOCK", "dnsRuleRequestTypes": ["HTTPS"]}]
    assert chk.c_4_12(FakeCl({"/zia/firewallDnsRules": one})).status == chk.R.WARN
    allow = [{"name": "Allow", "state": "ENABLED", "action": "ALLOW", "dnsRuleRequestTypes": ["HTTPS", "SVCB"]}]
    r = chk.c_4_12(FakeCl({"/zia/firewallDnsRules": allow}))
    assert r.status == chk.R.WARN and "best-practices-dns-control-rules" in r.detail
    # An SSL rule whose name merely contains "ech" (e.g. "Technology") no longer passes.
    assert chk.c_4_12(FakeCl({"/zia/sslInspectionRules": [{"name": "Technology", "action": {"type": "DECRYPT"}}]})).status == chk.R.INFO


# ── OCR is a DLP Advanced Settings switch (5.19) ───────────────────────
def test_ocr_is_read_from_dlp_advanced_settings():
    on = FakeCl({"/zia/webDlpGlobalOptions": {"enableInlineDlpOcr": True, "enableCasbOcr": False, "enableEmailDlpOcr": True}})
    r = chk.c_5_19(on)
    assert r.status == chk.R.PASS and "SaaS Security API" in r.detail and r.data["inline_ocr"] is True
    assert chk.c_8_12(on).status == chk.R.PASS and chk.c_b10(on).status == chk.R.PASS
    off = FakeCl({"/zia/webDlpGlobalOptions": {"enableInlineDlpOcr": False}, "/zia/webDlpRules": [{"name": "r", "state": "ENABLED", "ocrEnabled": True}]})
    r = chk.c_5_19(off)
    assert r.status == chk.R.WARN and "image files" in r.detail and "configuring-dlp-advanced-settings" in r.detail


def test_ocr_without_the_global_setting_is_not_a_per_rule_finding():
    rules = [{"name": "r", "state": "ENABLED"}]
    r = chk.c_5_19(FakeCl({"/zia/webDlpRules": rules}))
    assert r.status == chk.R.INFO and "not per rule" in r.detail
    # A leftover per-rule flag proves nothing: it no longer controls OCR (terraform-provider-zia 2.9.0).
    r = chk.c_5_19(FakeCl({"/zia/webDlpRules": [{"name": "r", "state": "ENABLED", "ocrEnabled": True}]}))
    assert r.status == chk.R.INFO and "legacy per-rule ocrEnabled flag" in r.detail
    assert chk.c_8_12(FakeCl({"/zia/webDlpRules": [{"name": "r", "state": "ENABLED", "ocrEnabled": True}]})).status == chk.R.INFO


# ── Evaluate All Rules read from DLP Advanced Settings (5.20) ──────────
DLP_RULES = [{"id": 1, "name": "Monitor PII", "order": 1, "action": "ALLOW", "state": "ENABLED", "dlpEngines": [{"id": 1}]},
             {"id": 2, "name": "Block SSN", "order": 2, "action": "BLOCK", "state": "ENABLED", "dlpEngines": [{"id": 2}]}]


def test_evaluate_all_rules_is_found_in_web_dlp_global_options():
    r = chk.c_5_20(FakeCl({"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": True}, "/zia/webDlpRules": DLP_RULES}))
    assert r.status == chk.R.PASS and "/zia/webDlpGlobalOptions" in r.data["found_via"] and "most restrictive" in r.detail
    r = chk.c_5_20(FakeCl({"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}, "/zia/webDlpRules": DLP_RULES}))
    assert r.status == chk.R.WARN and r.data["evaluate_all"] is False and "deleting all existing inline DLP rules" in r.detail


# ── EDM and IDM from dictionaryType (5.12, 5.14, 5.15) ─────────────────
def test_edm_and_idm_are_recognised_by_dictionary_type():
    dicts = [{"id": 1, "name": "Customer records", "custom": True, "dictionaryType": "EXACT_DATA_MATCH"},
             {"id": 2, "name": "Board papers", "custom": True, "dictionaryType": "INDEXED_DATA_MATCH",
              "idmProfileMatchAccuracyDetails": [{"matchAccuracy": "HEAVY"}]},
             {"id": 3, "name": "Cards", "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES", "patterns": [{"pattern": "x"}]}]
    cl = FakeCl({"/zia/dlpDictionaries": dicts})
    assert chk.c_5_14(cl).status == chk.R.PASS and chk.c_5_15(cl).status == chk.R.PASS
    m = chk.c_5_12(cl)
    assert m.status == chk.R.PASS and "EDM" in m.detail and "IDM" in m.detail
    none = FakeCl({"/zia/dlpDictionaries": dicts[2:]})
    assert "about-exact-data-match" in chk.c_5_14(none).detail and "about-indexed-document-match" in chk.c_5_15(none).detail


# ── Endpoint channels come from Endpoint DLP rules (8.1–8.4) ───────────
def test_endpoint_channels_are_read_from_endpoint_dlp_rules():
    ep = [{"name": "Block USB PII", "state": "ENABLED", "type": "REMOVABLE_MEDIA", "action": "BLOCK"},
          {"name": "Printing", "state": "ENABLED", "dataTransferMethod": "PRINTING", "action": "CONFIRM"},
          {"name": "Shares", "state": "DISABLED", "dataTransferMethod": "NETWORK_DRIVE_TRANSFER"}]
    cl = FakeCl({"/zia/endPointDlpRules": ep, "/zia/webDlpRules": [{"name": "web", "state": "ENABLED", "cloudApplications": []}]})
    assert chk.c_8_1(cl).status == chk.R.PASS and chk.c_b7(cl).status == chk.R.PASS
    assert chk.c_8_2(cl).status == chk.R.PASS
    assert chk.c_8_3(cl).status == chk.R.WARN            # the share rule is disabled
    r = chk.c_8_4(cl)                                    # a web rule's cloudApplications key is not a personal-cloud rule
    assert r.status == chk.R.WARN and "Endpoint DLP" in r.detail
    r = chk.c_8_1(FakeCl({}))
    assert r.status == chk.R.INFO and "not readable" in r.detail


# ── NSS DLP rule field (12.9) ──────────────────────────────────────────
def test_nss_feed_should_name_the_triggered_dlp_rule():
    fmt = "%s{time} %s{dlpeng} %s{dlpdict} %s{dlpmd5} %s{trig_dlprulename}"
    assert chk.c_12_9(FakeCl({"/zia/nssFeeds": [{"name": "SIEM", "feedOutputFormat": fmt}]})).status == chk.R.PASS
    old = fmt.replace("trig_dlprulename", "dlprulename")
    r = chk.c_12_9(FakeCl({"/zia/nssFeeds": [{"name": "SIEM", "feedOutputFormat": old}]}))
    assert r.status == chk.R.WARN and "only for Allow rules" in r.detail
    r = chk.c_12_9(FakeCl({"/zia/nssFeeds": [{"name": "SIEM", "formatString": "%s{time} %s{dlpeng}"}]}))
    assert r.status == chk.R.WARN and "dlpdict" in r.detail and "trig_dlprulename" in r.detail


# ── Client Connector versions and strict enforcement ────────────────────
def test_client_connector_version_is_read_from_agent_version():
    devs = [{"osType": "Windows", "agentVersion": "3.9.0.150"}, {"osType": "Windows", "agentVersion": "4.8.0.1"},
            {"osType": "Linux", "agentVersion": "3.7.2.18"}]
    r = chk.c_6_1(FakeCl({"/zcc/devices": devs}))
    assert r.status == chk.R.FAIL and r.detail.startswith("1 device(s)") and "supported-versions" in r.detail
    assert chk.c_6_1(FakeCl({"/zcc/devices": devs[1:]})).status == chk.R.PASS


def test_strict_enforcement_is_read_from_the_flattened_profile():
    on = {"id": 1, "name": "Corp", "policyExtension": json.dumps({"strictEnforcement": 1})}
    assert chk.c_1_8(FakeCl({"/zcc/appProfiles": [on]})).status == chk.R.PASS
    off = {"id": 2, "name": "BYOD", "strictEnforcement": 0}
    r = chk.c_1_8(FakeCl({"/zcc/appProfiles": [on, off]}))
    assert r.status == chk.R.FAIL and "BYOD" in r.detail
    assert chk.c_1_8(FakeCl({"/zcc/appProfiles": [{"id": 3, "name": "x"}]})).status == chk.R.WARN


# ── Retention, timeout and naming texts match Zscaler's pages ───────────
def test_log_retention_texts_say_six_months_not_thirty_days():
    empty = FakeCl({"/zia/nssFeeds": []})
    for r in (chk.c_12_11(empty), chk.c_e15(empty), genai.ai_16(empty)):
        assert "30 days" not in r.detail and "30-day" not in r.detail and "six" in r.detail
    import zscaler_full_checks as full
    zpa = FakeCl({})
    assert "14 days" in full.zpa_14(zpa).detail and "30 days" not in full.zpa_14(zpa).detail
    t = full.zpa_7(zpa).detail
    assert "15min" not in t and "7 days" in t
    assert "Generative AI and ML Applications" in genai.ai_1(FakeCl({"/zia/urlCategories": []})).detail


# ═══════════════════════════════════════════════════════════════════════
# Second review pass: each case below pins a change made against a cited
# Zscaler help page, SDK 1.11.0 model or Terraform provider document.
# ═══════════════════════════════════════════════════════════════════════
import zcc_evaluation as ze
import saas_email_checks as se
import zscaler_full_checks as full
import zscaler_zdx_checks as zdx
import zscaler_rbac_checks as rbac
import zscaler_zidentity_checks as zid
import zscaler_automation_checks as auto
import rule_migrator as rm

R = chk.R


class RecCl(FakeCl):
    """FakeCl that records the query parameters of every call."""
    def __init__(self, routes):
        super().__init__(routes)
        self.params = {}

    def get(self, endpoint, params=None):
        self.params[endpoint] = params
        return super().get(endpoint, params)


# ── Client Connector bypasses, passwords, telemetry ─────────────────────
def test_bypasses_are_read_from_the_fields_the_app_profile_returns():
    ext = {"vpnGateways": "vpn.corp.example,chatgpt.com", "packetTunnelIncludeList": "0.0.0.0/0", "packetTunnelExcludeList": "10.0.0.0/8\n52.1.0.0/16",
           "packetTunnelDnsExcludeList": "dropbox.com", "sourcePortBasedBypasses": "3389:*"}
    p = {"id": 1, "name": "Corp", "policyExtension": json.dumps(ext), "bypassAppIds": [4, 5]}
    cl = FakeCl({"/zcc/appProfiles": [p]})
    r = chk.c_1_2(cl); assert r.status == R.WARN and "vpn.corp.example" in r.detail
    r = chk.c_1_3(cl); assert r.status == R.PASS and "0.0.0.0/0" in r.detail
    r = chk.c_1_4(cl); assert r.status == R.WARN and r.detail.startswith("2 destination exclusion(s)")
    r = chk.c_1_5(cl); assert r.status == R.WARN and "2 application bypass(es) and 1 port bypass(es)" in r.detail
    reg = chk.c_2_5(cl); assert reg.status == R.WARN and len(reg.data["register"]) == 8   # inclusions are not bypasses
    r = chk.c_2_6(cl); assert r.status == R.FAIL and "chatgpt.com" in r.detail and "dropbox.com" in r.detail
    assert chk.c_2_7(cl).status == R.FAIL
    empty = FakeCl({"/zcc/appProfiles": [{"id": 2, "name": "x"}]})
    assert chk.c_1_2(empty).status == R.PASS and chk.c_1_3(empty).status == R.WARN and chk.c_2_5(empty).status == R.PASS


def test_windows_tamper_passwords_are_read_in_snake_case_and_inactive_profiles_skipped():
    win = {"id": 1, "name": "Win", "device_type": 3, "active": 1, "windowsPolicy": {"disable_password": "x", "uninstall_password": "y"}}
    off = {"id": 2, "name": "Old", "active": 0}
    assert chk.c_1_10(FakeCl({"/zcc/appProfiles": [win, off]})).status == R.PASS
    r = chk.c_1_10(FakeCl({"/zcc/appProfiles": [dict(win, windowsPolicy={"disable_password": "x"})]}))
    assert r.status == R.FAIL and "Win" in r.detail
    # 1.9 reads strict enforcement from the devices, the disable password from the profiles.
    cl = FakeCl({"/zcc/appProfiles": [win], "/zcc/devices": [{"strictEnforcement": 1}, {"strictEnforcement": 1}]})
    assert chk.c_1_9(cl).status == R.PASS
    r = chk.c_1_9(FakeCl({"/zcc/appProfiles": [win], "/zcc/devices": [{"strictEnforcement": 0}]}))
    assert r.status == R.WARN and "without strict enforcement" in r.detail
    r = chk.c_1_8(FakeCl({"/zcc/appProfiles": [win]}))
    assert "STRICTENFORCEMENT=1" in r.detail and "install option" in r.detail


def test_telemetry_is_a_company_setting():
    assert chk.c_1_12(FakeCl({"/zcc/companyInfo": {"enableGlobalZCCTelemetry": True}})).status == R.PASS
    assert chk.c_1_12(FakeCl({"/zcc/companyInfo": {"enableGlobalZCCTelemetry": False}})).status == R.WARN
    assert chk.c_1_12(FakeCl({"/zcc/appProfiles": [{"telemetryEnabled": True}]})).status == R.INFO


def test_ssl_certificate_toggle_ignores_macos_and_says_why():
    mac = {"id": 2, "name": "Mac", "device_type": 4, "macPolicy": {"installCerts": 0}}
    win = {"id": 1, "name": "Win", "device_type": 3, "windowsPolicy": {"install_ssl_certs": 1}}
    r = chk.c_3_3(FakeCl({"/zcc/appProfiles": [win, mac]}))
    assert r.status == R.PASS and "1/1" in r.detail and "Big Sur" in r.detail
    assert chk.c_3_3(FakeCl({"/zcc/appProfiles": [mac]})).status == R.INFO


# ── SSL Inspection against the Leading Practices Guide ──────────────────
DEFAULT_DNI = {"name": "Default SSL Rule", "defaultRule": True, "order": 99, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}
SMART_ISO = {"name": "Smart Isolation One Click Rule", "predefined": True, "order": 1, "state": "ENABLED", "cloudApplications": ["X"],
             "action": {"type": "DECRYPT", "decryptSubActions": {"minClientTLSVersion": "CLIENT_TLS_1_0", "minServerTLSVersion": "SERVER_TLS_1_0"}}}


def test_inspection_scope_needs_a_catch_all_decrypt_rule():
    narrow = {"name": "Decrypt AI", "order": 2, "state": "ENABLED", "urlCategories": ["AI_ML_APPS"], "action": {"type": "DECRYPT"}}
    r = chk.c_4_1(FakeCl({"/zia/sslInspectionRules": [SMART_ISO, narrow, DEFAULT_DNI]}))
    assert r.status == R.WARN and "none inspects everything" in r.detail
    assert chk.c_9_3(FakeCl({"/zia/sslInspectionRules": [SMART_ISO, DEFAULT_DNI]})).status == R.WARN
    allr = {"name": "Inspect All", "order": 3, "state": "ENABLED", "action": {"type": "DECRYPT"}}
    r = chk.c_4_1(FakeCl({"/zia/sslInspectionRules": [SMART_ISO, narrow, allr, DEFAULT_DNI]}))
    assert r.status == R.PASS and "Inspect All" in r.detail
    # E.2: a Decrypt rule on the AI categories covers GenAI even without the catch-all.
    assert chk.c_e2(FakeCl({"/zia/sslInspectionRules": [narrow]})).status == R.PASS
    assert chk.c_e2(FakeCl({"/zia/sslInspectionRules": [SMART_ISO]})).status == R.WARN


def test_rule_order_uses_the_order_field_and_all_scoping_criteria():
    src = {"name": "No SSL for kiosks", "order": 1, "state": "ENABLED", "locationGroups": [{"id": 3}], "action": {"type": "DO_NOT_DECRYPT"}}
    dec = {"name": "Inspect", "order": 2, "state": "ENABLED", "action": {"type": "DECRYPT"}}
    assert chk.c_4_3(FakeCl({"/zia/sslInspectionRules": [dec, src, DEFAULT_DNI]})).status == R.PASS
    broad = {"name": "Exempt all", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}
    r = chk.c_4_3(FakeCl({"/zia/sslInspectionRules": [dec, broad]}))       # listed out of order: order decides
    assert r.status == R.FAIL and "Exempt all" in r.detail


def test_recommended_exemptions_must_be_enabled():
    rec = {"name": "Zscaler Recommended Exemptions", "predefined": True, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}
    assert chk.c_4_4(FakeCl({"/zia/sslInspectionRules": [rec]})).status == R.PASS
    r = chk.c_4_4(FakeCl({"/zia/sslInspectionRules": [dict(rec, state="DISABLED")]}))
    assert r.status == R.WARN and "disabled" in r.detail and chk.c_7_2(FakeCl({"/zia/sslInspectionRules": [dict(rec, state="DISABLED")]})).status == R.WARN


def test_do_not_decrypt_review_leaves_out_zscaler_rules_and_flags_data_loss_destinations():
    fin = {"name": "Exempt finance", "state": "ENABLED", "urlCategories": ["FINANCE", "HEALTH"], "action": {"type": "DO_NOT_DECRYPT"}}
    mail = {"name": "Exempt webmail", "state": "ENABLED", "urlCategories": ["WEBMAIL"], "action": {"type": "DO_NOT_DECRYPT"}}
    broad = {"name": "Exempt all", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}
    r = chk.c_4_5(FakeCl({"/zia/sslInspectionRules": [DEFAULT_DNI, fin]}))
    assert r.status == R.INFO and "Exempt finance" in r.detail and "annually" in r.detail
    assert chk.c_4_5(FakeCl({"/zia/sslInspectionRules": [DEFAULT_DNI, broad]})).status == R.WARN
    assert chk.c_5_5(FakeCl({"/zia/sslInspectionRules": [DEFAULT_DNI, fin]})).status == R.PASS
    r = chk.c_5_5(FakeCl({"/zia/sslInspectionRules": [DEFAULT_DNI, fin, mail]}))
    assert r.status == R.WARN and "Exempt webmail" in r.detail and "Exempt finance" not in r.detail


def test_decrypt_hardening_holds_only_the_catch_all_rule_to_the_full_set():
    weak = {"serverCertificates": "PASS_THRU", "minClientTLSVersion": "CLIENT_TLS_1_0"}
    narrow = {"name": "Legacy bank", "state": "ENABLED", "urls": ["old.bank.example"], "action": {"type": "DECRYPT", "decryptSubActions": weak}}
    good = {"name": "Inspect all", "state": "ENABLED", "action": {"type": "DECRYPT", "decryptSubActions": {"serverCertificates": "BLOCK"}}}
    r = chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [SMART_ISO, narrow, good]}))
    assert r.status == R.INFO and "Legacy bank" in r.detail and "Smart Isolation" not in r.detail
    assert chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [SMART_ISO]})).status == R.INFO


# ── Cloud App Control, tenancy, GenAI categories ────────────────────────
IOT = {"name": "Allow Unauthenticated Traffic for IoT Classifications", "predefined": True, "state": "DISABLED", "type": "WEBMAIL"}


def test_cloud_app_control_counts_enabled_custom_rules_only():
    r = chk.c_4_7(FakeCl({"/zia/cloudApplicationRules": [IOT]}))
    assert r.status == R.WARN and "predefined" in r.detail
    assert full.capp_1(FakeCl({"/zia/cloudApplicationRules": [IOT]})).status == R.WARN
    live = {"name": "Block webmail upload", "state": "ENABLED", "type": "WEBMAIL", "actions": ["DENY_WEBMAIL_UPLOAD"]}
    assert chk.c_4_7(FakeCl({"/zia/cloudApplicationRules": [IOT, live]})).status == R.PASS
    # E.3 wants an AI & ML Applications rule, not any rule.
    assert chk.c_e3(FakeCl({"/zia/cloudApplicationRules": [IOT, live]})).status == R.WARN
    ai = {"name": "AI apps", "state": "ENABLED", "type": "AI_ML", "actions": ["ALLOW_AI_ML_WEB_USE"]}
    r = chk.c_e3(FakeCl({"/zia/cloudApplicationRules": [ai]}))
    assert r.status == R.PASS and "ALLOW_AI_ML_WEB_USE" in r.detail


def test_tenancy_needs_a_rule_that_applies_a_tenant_profile():
    prof = [{"id": 9, "name": "Corp M365", "appType": "MSLOGINSERVICES"}]
    plain = {"name": "Allow OneDrive", "state": "ENABLED", "type": "FILE_SHARE", "applications": ["ONEDRIVE"]}
    r = chk.c_a7(FakeCl({"/zia/cloudApplicationRules": [plain]}))
    assert r.status == R.WARN and "Tenant Profile" in r.detail and "about-tenant-profiles" in r.detail
    r = chk.c_5_18(FakeCl({"/zia/cloudApplicationRules": [plain], "/zia/tenancyRestrictionProfile": prof}))
    assert r.status == R.WARN and "Corp M365" in r.detail and "no enabled Cloud App Control rule uses them" in r.detail
    att = dict(plain, tenancyProfileIds=[{"id": 9}])
    r = chk.c_a7(FakeCl({"/zia/cloudApplicationRules": [att], "/zia/tenancyRestrictionProfile": prof}))
    assert r.status == R.PASS and "Allow OneDrive" in r.detail
    assert full.capp_2(FakeCl({"/zia/cloudApplicationRules": [att], "/zia/tenancyRestrictionProfile": prof})).status == R.PASS
    r = full.capp_2(FakeCl({"/zia/cloudApplicationRules": [plain], "/zia/tenancyRestrictionProfile": prof}))
    assert r.status == R.WARN and "Login Services" in r.detail and "adding-tenant-profiles" in r.detail


def test_genai_categories_count_only_when_a_rule_uses_them():
    cats = [{"id": "CUSTOM_01", "customCategory": True, "configuredName": "Email allowlist"}]
    r = chk.c_e1(FakeCl({"/zia/urlCategories": cats, "/zia/urlFilteringRules": [{"name": "Block webmail", "state": "ENABLED", "action": "BLOCK", "urlCategories": ["CUSTOM_01"]}]}))
    assert r.status == R.WARN and "Generative AI and ML Applications" in r.detail
    url = [{"name": "Caution AI", "state": "ENABLED", "action": "CAUTION", "urlCategories": ["AI_ML_APPS"]}]
    assert chk.c_e1(FakeCl({"/zia/urlCategories": cats, "/zia/urlFilteringRules": url})).status == R.PASS
    assert chk.c_e8(FakeCl({"/zia/urlFilteringRules": url})).status == R.PASS
    assert genai.ai_1(FakeCl({"/zia/urlFilteringRules": url})).status == R.PASS
    assert genai.ai_1(FakeCl({"/zia/urlCategories": cats})).status == R.FAIL


# ── Inline Web DLP rules ────────────────────────────────────────────────
def test_empty_engine_list_means_any_engine_and_file_types_are_checked_on_file_types():
    rules = [{"name": "Any engine", "state": "ENABLED"},
             {"name": "Filter", "state": "ENABLED", "withoutContentInspection": True, "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"]},
             {"name": "PCI", "state": "ENABLED", "dlpEngines": [{"id": 1}], "fileTypes": ["FTCATEGORY_PDF_DOCUMENT", "FTCATEGORY_MS_WORD"]},
             {"name": "By category", "state": "ENABLED", "fileTypeCategories": [{"id": 5}]}]
    r = chk.c_5_9(FakeCl({"/zia/webDlpRules": rules}))
    assert r.status == R.INFO and r.data == {"specific": 1, "any": 2, "no_inspection": 1}
    r = chk.c_a4(FakeCl({"/zia/webDlpRules": rules}))
    assert r.status == R.WARN and "PCI (no Excel, CSV, archives)" in r.detail and "by category" in r.detail
    # 5.13: FTCATEGORY_* enums, not bare PDF/DOCX; a rule on any file type covers them all.
    assert chk.c_5_13(FakeCl({"/zia/webDlpRules": rules})).status == R.PASS
    typed = [{"name": "Docs", "state": "ENABLED", "fileTypes": ["FTCATEGORY_PDF_DOCUMENT", "FTCATEGORY_MS_WORD", "FTCATEGORY_MS_EXCEL", "FTCATEGORY_CSV"]},
             {"name": "Old", "state": "DISABLED"}]
    assert chk.c_5_13(FakeCl({"/zia/webDlpRules": typed})).status == R.PASS
    r = chk.c_5_13(FakeCl({"/zia/webDlpRules": typed[:1] + [{"name": "x", "state": "ENABLED", "fileTypes": ["FTCATEGORY_PDF_DOCUMENT"]}]}))
    assert r.status == R.PASS
    r = chk.c_5_13(FakeCl({"/zia/webDlpRules": [{"name": "x", "state": "ENABLED", "fileTypes": ["PDF", "DOCX"]}]}))
    assert r.status == R.WARN and "Excel" in r.detail and "PDF" not in r.detail.split("Missing:")[1]
    assert chk.c_5_13(FakeCl({"/zia/webDlpRules": [{"name": "x", "state": "ENABLED", "fileTypes": ["FTCATEGORY_ALL_OUTBOUND"]}]})).status == R.PASS


def test_url_allow_rules_do_not_bypass_dlp():
    rules = [{"name": "Allow all", "state": "ENABLED", "action": "ALLOW"}, {"name": "Block hosts", "state": "ENABLED", "action": "BLOCK", "urlCategories": ["FILE_HOST"]},
             {"name": "Old", "state": "DISABLED", "action": "BLOCK", "urlCategories": ["WEBMAIL"]}]
    r = chk.c_5_6(FakeCl({"/zia/urlFilteringRules": rules}))
    assert r.status == R.INFO and "Block hosts" in r.detail and "Old" not in r.detail and "do not bypass DLP" in r.detail
    assert chk.c_5_6(FakeCl({"/zia/urlFilteringRules": rules[:1]})).status == R.PASS


def test_constant_results_are_information_not_a_score():
    empty = FakeCl({})
    for fn in (chk.c_a11, chk.c_a12, chk.c_5_4, chk.c_9_1, chk.c_b4, chk.c_5_22, chk.c_b14):
        r = fn(empty)
        assert r.status == R.INFO, fn.__name__
    assert "endpoints.prod" not in chk.c_5_4(empty).detail
    r = chk.c_a3(FakeCl({"/zia/webDlpRules": [{"name": "a", "state": "ENABLED", "dlpDownloadScanEnabled": True}]}))
    assert r.status == R.INFO and "URL Categories set to Any" in r.detail and "EDM or IDM" in r.detail


def test_confirm_rules_count_only_when_enabled():
    rules = [{"name": "Confirm", "state": "DISABLED", "action": "CONFIRM"}]
    assert chk.c_12_6(FakeCl({"/zia/webDlpRules": rules})).status == R.WARN
    rules[0]["state"] = "ENABLED"
    assert chk.c_12_6(FakeCl({"/zia/webDlpRules": rules})).status == R.PASS


def test_dlp_advanced_settings_exemptions_are_reported():
    g = {"enableInlineDlpOcr": True, "urls": ["partner.example"], "applications": [], "exemptUrlEncodedData": True}
    r = chk.c_5_17(FakeCl({"/zia/webDlpGlobalOptions": g, "/zia/webDlpRules": []}))
    assert r.status == R.WARN and "partner.example" in r.detail and "URL-encoded" in r.detail and "override every DLP rule" in r.detail
    assert chk.c_5_17(FakeCl({"/zia/webDlpGlobalOptions": {"enableInlineDlpOcr": True}, "/zia/webDlpRules": []})).status == R.PASS


def test_evaluate_all_texts_name_the_current_page_and_steps():
    class Boom(FakeCl):
        def get(self, endpoint, params=None):
            raise RuntimeError("down")
    r = chk.c_5_20(Boom({}))
    assert r.status == R.INFO and "Data Security > Common Resources > DLP Advanced Settings" in r.detail and "Policy > Data Loss Prevention" not in r.detail
    plan = rm.generate_migration_plan(DLP_RULES)
    assert plan["zscaler_best_practice_reference"].endswith("configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled")
    text = " ".join(plan["checklist"])
    assert "Delete all existing inline DLP rules" in text and "Account team" in text and "Advanced Settings → DLP" not in text
    st = rm.assess_current_status(FakeCl({"/zia/webDlpRules": DLP_RULES}))
    assert "Administration → Advanced Settings" not in st["recommendation"]
    st = rm.assess_current_status(FakeCl({"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}, "/zia/webDlpRules": DLP_RULES}))
    assert "NOT yet safe" not in st["recommendation"] and "same action" in st["recommendation"]


def test_ml_dictionaries_count_when_an_enabled_rule_uses_them():
    dicts = [{"id": 63, "name": "Financial Statements"}, {"id": 5, "name": "Names (Spain)"}, {"id": 6, "name": "Social Security Number (Spain)"}]
    eng = [{"id": 7, "name": "Finance docs", "engineExpression": "((D63.S > 1))"}, {"id": 8, "name": "PII", "engineExpression": "((D5.S > 1))"}]
    cl = FakeCl({"/zia/dlpDictionaries": dicts, "/zia/dlpEngines": eng, "/zia/webDlpRules": [{"name": "Docs", "state": "ENABLED", "dlpEngines": [{"id": 7}]}]})
    r = chk.c_5_21(cl)
    assert r.status == R.PASS and "Financial Statements" in r.detail
    r = chk.c_5_21(FakeCl({"/zia/dlpDictionaries": dicts, "/zia/dlpEngines": eng, "/zia/webDlpRules": [{"name": "PII", "state": "ENABLED", "dlpEngines": [{"id": 8}]}]}))
    assert r.status == R.WARN and "Names (Spain)" not in r.detail
    assert chk.c_5_21(FakeCl({"/zia/dlpDictionaries": dicts[1:]})).status == R.WARN


# ── Evidence, ICAP, NSS ────────────────────────────────────────────────
def test_incident_receivers_are_read_even_when_the_icap_list_is_empty():
    cl = FakeCl({"/zia/icapServers": [], "/zia/incidentReceiverServers": [{"id": 1, "name": "ZIR"}],
                 "/zia/webDlpRules": [{"name": "PCI", "state": "ENABLED", "zscalerIncidentReceiver": True}]})
    for fn in (chk.c_12_1, chk.c_a14, chk.c_8_6):
        r = fn(cl)
        assert r.status == R.PASS and "1 Incident Receiver(s)" in r.detail, fn.__name__
    assert chk.c_12_3(cl).status == R.PASS and "PCI" in chk.c_12_12(cl).detail
    idle = FakeCl({"/zia/icapServers": [], "/zia/incidentReceiverServers": [{"id": 1}], "/zia/webDlpRules": [{"name": "PCI", "state": "ENABLED"}]})
    r = chk.c_12_1(idle)
    assert r.status == R.WARN and "no enabled DLP rule sends content" in r.detail
    assert chk.c_12_3(idle).status == R.WARN
    ep = FakeCl({"/zia/incidentReceiverServers": [{"id": 1}], "/zia/endPointDlpRules": [{"name": "USB", "state": "ENABLED", "receiver": {"id": 1}}]})
    assert chk.c_12_1(ep).status == R.PASS


def test_secure_icap_is_read_from_the_url_scheme():
    ok = [{"id": 1, "name": "dlp-icap", "url": "icaps://10.0.0.5:11344", "status": "ENABLED"}]
    assert chk.c_12_2(FakeCl({"/zia/icapServers": ok})).status == R.PASS
    clear = [{"id": 2, "name": "old", "url": "icap://10.0.0.6:1344", "status": "ENABLED"}]
    r = chk.c_12_2(FakeCl({"/zia/icapServers": ok + clear}))
    assert r.status == R.FAIL and "old" in r.detail and "dlp-icap" not in r.detail
    assert chk.c_12_2(FakeCl({"/zia/icapServers": [], "/zia/incidentReceiverServers": [{"id": 3}]})).status == R.PASS


def test_nss_checks_read_the_feed_type_and_status():
    fmt = "%s{dlpeng} %s{dlpdict} %s{dlpmd5} %s{trig_dlprulename}"
    fw = {"name": "Firewall", "nssLogType": "FWLOG", "feedStatus": "ENABLED", "feedOutputFormat": "%s{time}"}
    web = {"name": "Web", "nssLogType": "WEBLOG", "feedStatus": "ENABLED", "feedOutputFormat": fmt}
    assert chk.c_12_9(FakeCl({"/zia/nssFeeds": [fw, web]})).status == R.PASS      # the firewall feed is not held to web fields
    r = chk.c_12_9(FakeCl({"/zia/nssFeeds": [fw]}))
    assert r.status == R.INFO and "web-log" in r.detail
    for fn in (chk.c_12_11, chk.c_e15):
        r = fn(FakeCl({"/zia/nssFeeds": [fw]}))
        assert r.status == R.WARN and "FWLOG" in r.detail and "six" in r.detail, fn.__name__
        assert fn(FakeCl({"/zia/nssFeeds": [fw, web]})).status == R.PASS
        assert fn(FakeCl({"/zia/nssFeeds": [dict(web, feedStatus="DISABLED")]})).status == R.WARN
    r = genai.ai_16(FakeCl({"/zia/nssFeeds": [fw]}))
    assert r.status == R.FAIL and "FWLOG" in r.detail
    assert genai.ai_16(FakeCl({"/zia/nssFeeds": [web]})).status == R.PASS
    r = chk.c_12_8(FakeCl({"/zia/nssFeeds": [fw, dict(web, feedStatus="DISABLED")]}))
    assert r.status == R.PASS and "FWLOG 1" in r.detail and "WEBLOG" not in r.detail
    title = [c[2] for c in chk.REG if c[0] == "12.11"][0]
    assert title == "Log retention beyond 180 days (NSS export)"


# ── Endpoint DLP ───────────────────────────────────────────────────────
def test_endpoint_channels_use_the_data_transfer_method():
    rules = [{"name": "Block USB exfil", "state": "ENABLED", "dataTransferMethod": "PRINTING"},
             {"name": "OneDrive app", "state": "ENABLED", "dataTransferMethod": "APPLICATION_FILE_ACCESS", "endPointApplications": ["OneDrive"]},
             {"name": "Blueprint review", "state": "ENABLED", "description": "blueprint files"}]
    cl = FakeCl({"/zia/endPointDlpRules": rules})
    assert chk.c_8_1(cl).status == R.WARN       # a PRINTING rule named "USB" is not a USB rule
    assert chk.c_8_4(cl).status == R.WARN       # Application File Access is not personal cloud storage
    r = chk.c_8_2(cl)
    assert r.status == R.PASS and "Blueprint" not in r.detail
    assert chk.c_b9(FakeCl({"/zia/endPointDlpRules": [{"name": "c", "state": "ENABLED", "dataTransferMethod": "PERSONAL_CLOUD_STORAGE"}]})).status == R.PASS


def test_endpoint_notifications_confirm_and_disable_password():
    rules = [{"name": "Block USB", "state": "ENABLED", "action": "BLOCK", "eunEnabled": False},
             {"name": "Monitor", "state": "ENABLED", "action": "ALLOW"},
             {"name": "Confirm print", "state": "ENABLED", "action": "CONFIRM", "eunEnabled": True, "ucTemplateId": 4}]
    r = chk.c_b11(FakeCl({"/zia/endPointDlpRules": rules, "/zia/dlpNotificationTemplates": [{"id": 1}]}))
    assert r.status == R.WARN and "Block USB" in r.detail and "configuring-endpoint-dlp-policy-rules" in r.detail
    assert chk.c_b11(FakeCl({"/zia/endPointDlpRules": rules[1:]})).status == R.PASS
    r = chk.c_b16(FakeCl({"/zia/endPointDlpRules": rules, "/zia/webDlpRules": []}))
    assert r.status == R.PASS and "Confirm print" in r.detail and "1 with a User Confirmation template" in r.detail
    assert chk.c_b16(FakeCl({"/zia/endPointDlpRules": rules[:2], "/zia/webDlpRules": [{"name": "w", "state": "ENABLED", "action": "CONFIRM"}]})).status == R.WARN
    zdp = {"id": 1, "name": "Endpoint", "policyExtension": json.dumps({"enableZdpService": 1, "zdpDisablePassword": ""}), "disablePassword": "x", "uninstallPassword": "y"}
    r = chk.c_b12(FakeCl({"/zcc/appProfiles": [zdp]}))
    assert r.status == R.FAIL and "Password to Disable Endpoint DLP" in r.detail
    zdp_ok = dict(zdp, policyExtension=json.dumps({"enableZdpService": 1, "zdpDisablePassword": "p"}))
    assert chk.c_b12(FakeCl({"/zcc/appProfiles": [zdp_ok]})).status == R.PASS
    unknown = dict(zdp, policyExtension=json.dumps({"enableZdpService": 1}))
    assert chk.c_b12(FakeCl({"/zcc/appProfiles": [unknown]})).status == R.WARN


# ── Email DLP (MC.4, 8.9) ───────────────────────────────────────────────
def test_email_dlp_presence_reads_the_response_code_and_state():
    class Code(FakeCl):
        def __init__(self, code): super().__init__({}); self.code = code
        def get(self, endpoint, params=None): return {"error": "x"}, self.code
    assert chk.c_mc4(Code(404)).status == R.INFO and chk.c_mc4(Code(403)).status == R.ERROR
    assert chk.c_mc4(FakeCl({"/zia/emailDlpRules": [{"name": "e", "state": "DISABLED"}]})).status == R.WARN
    rules = [{"name": "Encrypt", "state": "ENABLED", "action": "CUSTOMHEADERINSERTION"}]
    assert chk.c_mc4(FakeCl({"/zia/emailDlpRules": rules})).status == R.PASS
    r = chk.c_8_9(FakeCl({"/zia/emailDlpRules": rules}))
    assert r.status == R.PASS and "X-Zscaler" in r.detail and "test email" in r.detail
    assert chk.c_8_9(FakeCl({"/zia/emailDlpRules": [{"name": "m", "state": "ENABLED", "action": "ALLOW"}]})).status == R.WARN


# ── Client Connector versions and macOS ─────────────────────────────────
def test_client_connector_minimum_versions_are_per_platform():
    devs = [{"type": 3, "agentVersion": "4.6.1.2"}, {"type": 3, "agentVersion": "4.7.0.1"}, {"type": 4, "agentVersion": "4.5.1.0"},
            {"type": 4, "agentVersion": "4.5.2.3"}, {"type": 5, "agentVersion": "3.8.0.1"}, {"type": 5, "agentVersion": "3.7.2.18"}, {"type": 5, "agentVersion": "4.2.2.1"}]
    r = chk.c_6_1(FakeCl({"/zcc/devices": devs}))
    assert r.status == R.FAIL and r.detail.startswith("3 device(s)") and "Windows: 1" in r.detail and "macOS: 1" in r.detail and "Linux: 1" in r.detail
    r = ze.z_version_spread(FakeCl({"/zcc/devices": devs}))
    assert r.status == R.WARN and "3 of 7" in r.detail
    # Two builds of one supported release are not "behind".
    same = [{"type": 3, "agentVersion": "4.8.0.1"}, {"type": 3, "agentVersion": "4.8.0.2"}, {"type": 1, "agentVersion": "4.5.1"}]
    assert ze.z_version_spread(FakeCl({"/zcc/devices": same})).status == R.PASS


def test_macos_certificate_text_says_why():
    r = chk.c_10_2(FakeCl({"/zcc/devices": [{"type": 4, "agentVersion": "4.8"}]}))
    assert r.status == R.WARN and "Big Sur" in r.detail and "best-practices-zscaler-client-connector-deployment" in r.detail


# ── Strict Client Connector evaluation (zcc_evaluation) ─────────────────
def test_zcc_passwords_forwarding_trusted_networks_company():
    p = {"id": 1, "name": "Win", "device_type": 3, "active": 1, "uninstallPassword": "x", "disablePassword": "x", "zpaDisablePassword": "x",
         "zdpDisablePassword": "x", "zdxDisablePassword": "x", "exitPassword": "x", "logoutPassword": "x"}
    r = ze.z_disable_passwords(FakeCl({"/zcc/appProfiles": [p]}))
    assert r.status == R.PASS and "Internet Security" not in r.detail
    fp = {"id": 5, "name": "Corp", "forwardingProfileActions": [
        {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2", "primaryTransport": "TLS", "allowTLSFallback": 0,
         "dropIpv6Traffic": 0, "dropIpv6IncludeTrafficInT2": 0, "blockUnreachableDomainsTraffic": 0, "systemProxyData": {"bypassProxyForPrivateIP": 0, "enablePAC": 1}},
        {"networkType": "ON_TRUSTED_NETWORK", "actionType": "NONE", "primaryTransport": "TLS"}]}
    r = ze.z_forwarding_modes(FakeCl({"/zcc/forwardingProfiles": [fp]}))
    assert r.status == R.WARN and "Corp (OFF_TRUSTED_NETWORK): primary transport is TLS" in r.detail and "TLS fallback is off" in r.detail
    assert "ON_TRUSTED_NETWORK): primary transport" not in r.detail      # that network does not tunnel
    r = ze.z_forwarding_hygiene(FakeCl({"/zcc/forwardingProfiles": [fp]}))
    assert r.status == R.WARN and "IPv6" in r.detail and "RFC1918" in r.detail and "PAC" in r.detail and "unreachable" in r.detail
    inline = {"id": 6, "name": "HQ", "forwardingProfileActions": [{"networkType": "ON_TRUSTED_NETWORK", "actionType": "NONE"}],
              "dnsServers": ["10.0.0.1"], "dnsSearchDomains": ["corp.example"]}
    r = ze.z_trusted_networks(FakeCl({"/zcc/forwardingProfiles": [inline], "/zcc/trustedNetworks": []}))
    assert r.status == R.PASS and "1 forwarding profile(s) with inline criteria" in r.detail
    weak = dict(inline, dnsSearchDomains=[])
    r = ze.z_trusted_networks(FakeCl({"/zcc/forwardingProfiles": [weak], "/zcc/trustedNetworks": []}))
    assert r.status == R.FAIL and "HQ (inline, 1 criterion)" in r.detail
    c = {"dlpEnabled": 1, "enableAntiTampering": 1, "enableGlobalZCCTelemetry": 1,
         "webAppConfig": {"slowRolloutZCC": 1, "inactiveDeviceCleanup": 30, "enableFipsMode": 1}}
    r = ze.z_company(FakeCl({"/zcc/companyInfo": c}))
    assert r.status == R.PASS and "FIPS mode on" in r.detail


def test_quic_is_dropped_on_mobile_and_blocked_in_zia_for_desktops():
    ios = {"id": 1, "name": "iPhone", "device_type": 1, "active": 1, "dropQuicTraffic": 0}
    win = {"id": 2, "name": "Win", "device_type": 3, "active": 1}
    r = ze.z_quic(FakeCl({"/zcc/appProfiles": [ios]}))
    assert r.status == R.FAIL and "iPhone" in r.detail
    dns = [{"name": "Block HTTPS RR", "state": "ENABLED", "action": "BLOCK", "dnsRuleRequestTypes": ["HTTPS"]}]
    r = ze.z_quic(FakeCl({"/zcc/appProfiles": [win], "/zia/firewallDnsRules": dns}))
    assert r.status == R.PASS and "HTTPS record type" in r.detail
    assert ze.z_quic(FakeCl({"/zcc/appProfiles": [win]})).status == R.WARN


# ── SaaS Security API and Email DLP ─────────────────────────────────────
class SeCl:
    def __init__(self, routes): self.routes = routes
    def get(self, ep, p=None):
        return (self.routes[ep], 200) if ep in self.routes else ([], 200)


def test_saas_remediation_and_sharing_scope_use_the_api_enums():
    allow = {"name": "a", "type": "OFLCASB_DLP_FILE", "state": "ENABLED", "action": "OFLCASB_DLP_ALLOW", "dlp_engines": [{"id": 1}],
             "collaboration_scope": ["COLLABORATION_SCOPE_EXTERNAL_COLLAB_VIEW"]}
    cl = SeCl({"/zia/casbDlpRules/all": [allow]})
    assert se.c_c7(cl).status == "REVIEW"
    assert se.c_c8(cl).status == "PASS"
    pub = dict(allow, collaboration_scope=["COLLABORATION_SCOPE_PUBLIC"])
    assert se.c_c8(SeCl({"/zia/casbDlpRules/all": [pub]})).status == "PASS"
    internal = dict(allow, collaboration_scope=["COLLABORATION_SCOPE_INTERNAL_COLLAB_VIEW"])
    assert se.c_c8(SeCl({"/zia/casbDlpRules/all": [internal]})).status == "REVIEW"
    q = dict(allow, action="OFLCASB_DLP_QUARANTINE", state="DISABLED")
    r = se.c_c7(SeCl({"/zia/casbDlpRules/all": [allow, q]}))
    assert r.status == "REVIEW" and "disabled" in r.detail


def test_email_rules_filters_custom_headers_notifications_and_ocr():
    base = {"name": "e", "state": "ENABLED", "email_tenants": [{"id": 1}]}
    cl = SeCl({"/zia/emailDlpRules": [dict(base, withoutContentInspection=True, action="ALLOW")]})
    r = se.c_d3(cl)
    assert r.status == "INFO" and "without content inspection" in r.detail and "match nothing" not in r.detail
    assert se.c_d3(SeCl({"/zia/emailDlpRules": [dict(base, action="ALLOW")]})).status == "FAIL"
    r = se.c_d5(SeCl({"/zia/emailDlpRules": [dict(base, action="CUSTOMHEADERINSERTION", customHeader="X-Zscaler-Encrypt:1")]}))
    assert r.status == "PASS" and "X-Zscaler-Block:1" in r.detail and "Exchange only" in r.detail
    r = se.c_d5(SeCl({"/zia/emailDlpRules": [dict(base, action="ALLOW")]}))
    assert r.status == "REVIEW" and "ALLOW" in r.detail
    r = se.c_d7(SeCl({"/zia/emailDlpRules": [dict(base, notificationTemplate={"id": 1})]}))
    assert r.status == "REVIEW" and "only one of auditor and template" in r.detail
    assert se.c_d7(SeCl({"/zia/emailDlpRules": [dict(base, receiver={"id": 3})]})).status == "PASS"
    r = se.c_d8(SeCl({"/zia/emailDlpRules": [base]}))
    assert "internal and external recipients" not in r.detail and "trusted partners" in r.detail
    rules = {"/zia/emailDlpRules": [base]}
    assert se.c_d9(SeCl(dict(rules, **{"/zia/webDlpGlobalOptions": {"enableEmailDlpOcr": False}}))).status == "REVIEW"
    assert se.c_d9(SeCl(dict(rules, **{"/zia/webDlpGlobalOptions": {"enableEmailDlpOcr": True}}))).status == "PASS"
    assert se.c_d9(SeCl(rules)).status == "INFO"


# ── GenAI (AI.x) ───────────────────────────────────────────────────────
def test_genai_rules_are_found_by_target_not_by_the_letters_ai():
    webmail = {"name": "Block Webmail uploads", "state": "ENABLED", "action": "BLOCK", "urlCategories": ["WEBMAIL"]}
    ai = {"name": "Caution tools", "state": "ENABLED", "action": "CAUTION", "urlCategories": ["AI_ML_APPS"], "deviceTrustLevels": ["HIGH_TRUST"]}
    assert genai.ai_2(FakeCl({"/zia/urlFilteringRules": [webmail]})).status == R.WARN
    assert genai.ai_2(FakeCl({"/zia/urlFilteringRules": [webmail, ai]})).status == R.PASS
    assert genai.ai_7(FakeCl({"/zia/webDlpRules": [dict(webmail, name="Email domain detail")]})).status == R.FAIL
    assert genai.ai_20(FakeCl({"/zia/urlFilteringRules": [ai]})).status == R.PASS
    assert genai.ai_20(FakeCl({"/zia/urlFilteringRules": [dict(ai, deviceTrustLevels=["ANY", "HIGH_TRUST"])]})).status == R.WARN
    cac = [{"name": "Neutral name", "type": "AI_ML", "state": "ENABLED", "actions": ["CAUTION_AI_ML_WEB_USE"]},
           {"name": "Email ai", "type": "WEBMAIL", "state": "ENABLED"}]
    r = genai.ai_3(FakeCl({"/zia/cloudApplicationRules": cac}))
    assert r.status == R.PASS and r.detail.startswith("1 AI & ML")
    r = genai.ai_8(FakeCl({"/zia/cloudApplicationRules": cac}))
    assert r.status == R.PASS and "Caution" in r.detail
    assert genai.ai_8(FakeCl({"/zia/webDlpRules": [{"name": "AI", "state": "ENABLED", "action": "CAUTION", "urlCategories": ["AI_ML_APPS"]}]})).status == R.WARN


def test_genai_ssl_exemption_tenant_profiles_and_texts():
    dni = [{"name": "Exempt GenAI", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["AI_ML_APPS"]}]
    assert genai.ai_6(FakeCl({"/zia/sslInspectionRules": dni})).status == R.FAIL
    profs = [{"id": 1, "name": "Tenant A", "appType": "MSLOGINSERVICES"}, {"id": 2, "name": "GPT", "appType": "CHATGPT_AI"}]
    r = genai.ai_14(FakeCl({"/zia/tenancyRestrictionProfile": profs, "/zia/cloudApplicationRules": [{"type": "AI_ML", "state": "ENABLED", "tenancyProfileIds": [{"id": 2}]}]}))
    assert r.status == R.PASS and "1 attached" in r.detail
    assert genai.ai_14(FakeCl({"/zia/tenancyRestrictionProfile": [{"id": 3, "name": "Microsoft corp", "appType": "SLACK"}]})).status == R.WARN
    t = genai.ai_15(FakeCl({})).detail
    assert "WebSocket" in t and "Copilot Chat only" in t and "configuring-advanced-policy-settings" in t
    assert "Zero Trust Browser" in genai.ai_4(FakeCl({})).detail and "Zero Trust Browser" in genai.ai_19(FakeCl({})).detail


# ── Platform checks (zscaler_full_checks) ───────────────────────────────
def test_firewall_ips_malware_atp_and_file_type_checks():
    ips = [{"name": "Default Cloud IPS Rule", "defaultRule": True, "state": "ENABLED", "action": "BYPASS_IPS"}]
    assert full.fw_4(FakeCl({"/zia/firewallIpsRules": ips})).status == R.WARN
    assert full.fw_4(FakeCl({"/zia/firewallIpsRules": [dict(ips[0], action="BLOCK_DROP")]})).status == R.PASS
    svcs = [{"name": "HTTP", "type": "STANDARD"}, {"name": "App", "type": "CUSTOM"}]
    assert full.fw_7(FakeCl({"/zia/networkServices": svcs[:1]})).status == R.INFO
    assert "1 custom of 2" in full.fw_7(FakeCl({"/zia/networkServices": svcs})).detail
    fw = [{"name": "Recommended Firewall Rule", "predefined": True, "state": "ENABLED", "order": 5, "action": "ALLOW", "nwServices": [{"name": "HTTP"}]},
          {"name": "Allow RDP", "state": "ENABLED", "order": 2, "action": "ALLOW", "groups": [{"id": 1}], "nwServices": [{"name": "RDP"}], "destIpGroups": [{"id": 2}]},
          {"name": "Allow any", "state": "ENABLED", "order": 3, "action": "ALLOW", "users": [{"id": 1}]},
          {"name": "Old", "state": "DISABLED", "order": 1, "action": "ALLOW"}]
    r = full.fw_8(FakeCl({"/zia/firewallFilteringRules": fw}))
    assert r.status == R.WARN and "Allow any" in r.detail and "Allow RDP" not in r.detail and "Recommended" not in r.detail and "Old" not in r.detail
    atp = {"riskTolerance": 50, "torBlocked": False, "cmdCtlServerBlocked": True}
    r = full.sec_4(FakeCl({"/zia/cyberThreatProtection/advancedThreatSettings": atp}))
    assert r.status == R.WARN and "Page Risk tolerance 50" in r.detail and "torBlocked" in r.detail
    assert full.sec_4(FakeCl({"/zia/cyberThreatProtection/advancedThreatSettings": {"riskTolerance": 35, "torBlocked": True}})).status == R.PASS
    ft = [{"name": "Caution exe", "state": "ENABLED", "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"], "filteringAction": "CAUTION", "operation": "DOWNLOAD"},
          {"name": "Block exe up", "state": "ENABLED", "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"], "filteringAction": "BLOCK", "operation": "UPLOAD"}]
    assert full.sec_5(FakeCl({"/zia/fileTypeRules": ft})).status == R.PASS
    assert full.sec_5(FakeCl({"/zia/fileTypeRules": [dict(ft[0], filteringAction="ALLOW")]})).status == R.WARN


def test_recommended_firewall_block_rules():
    rules = [{"name": "Block Malicious IPs and Domains", "predefined": True, "state": "ENABLED", "order": 1, "action": "BLOCK_DROP"},
             {"name": "Block QUIC", "state": "ENABLED", "order": 2, "action": "BLOCK_DROP", "nwServices": [{"name": "QUIC"}]},
             {"name": "Allow web", "state": "ENABLED", "order": 3, "action": "ALLOW", "nwServices": [{"name": "HTTPS"}]}]
    r = full.fw_9(FakeCl({"/zia/firewallFilteringRules": rules}))
    assert r.status == R.PASS and "QUIC blocked" in r.detail and "ICMP" in r.detail
    rules[0]["state"] = "DISABLED"
    assert full.fw_9(FakeCl({"/zia/firewallFilteringRules": rules})).status == R.FAIL
    rules[0]["state"] = "ENABLED"; rules[1]["order"] = 9
    r = full.fw_9(FakeCl({"/zia/firewallFilteringRules": rules}))
    assert r.status == R.WARN and "sits below a custom Allow rule" in r.detail


def test_url_filtering_checks_count_enabled_rules_and_security_categories():
    assert full.url_1(FakeCl({"/zia/urlFilteringRules": [{"name": "x", "state": "DISABLED"}]})).status == R.FAIL
    assert "Advanced Threat Protection" in full.url_1(FakeCl({})).detail
    cats = [{"id": "ADULT_THEMES"}, {"id": "ANONYMIZER", "superCategory": "SECURITY"}]
    assert full.url_2(FakeCl({"/zia/urlCategories": cats})).status == R.WARN
    rules = [{"name": "Caution", "state": "ENABLED", "action": "CAUTION", "urlCategories": ["ANONYMIZER"]}]
    r = full.url_3(FakeCl({"/zia/urlFilteringRules": rules, "/zia/urlCategories": cats}))
    assert r.status == R.WARN and "Malware, phishing, botnet and cryptomining are blocked by Advanced Threat Protection" in r.detail
    rules.append({"name": "Security block", "state": "ENABLED", "action": "BLOCK", "urlCategories": ["ANONYMIZER"]})
    assert full.url_3(FakeCl({"/zia/urlFilteringRules": rules, "/zia/urlCategories": cats})).status == R.PASS


def test_bandwidth_locations_audit_log_and_cloud_app_settings():
    bw = FakeCl({"/zia/bandwidthControlRules": [{"name": "b", "state": "ENABLED"}], "/zia/locations": [{"name": "HQ", "upBandwidth": 0, "dnBandwidth": 0}]})
    r = full.bw_1(bw)
    assert r.status == R.WARN and "never apply" in r.detail and "remote Client Connector users" in r.detail and "inspection throughput" not in r.detail
    r = full.loc_6(FakeCl({"/zia/locations": [{"name": "Branch", "ofwEnabled": False}, {"name": "HQ", "ofwEnabled": True, "ipsControl": True}]}))
    assert r.status == R.WARN and "Branch" in r.detail and "HQ" not in r.detail
    assert full.usr_5(FakeCl({"/zia/nssFeeds": [{"nssLogType": "ADMIN_AUDIT", "feedStatus": "ENABLED"}]})).status == R.PASS
    assert full.usr_5(FakeCl({"/zia/auditlogEntryReport": {"status": "COMPLETE"}})).status == R.INFO
    assert full.capp_5(FakeCl({"/zia/advancedSettings": {"cascadeUrlFiltering": True}})).status == R.WARN
    assert full.capp_5(FakeCl({"/zia/advancedSettings": {"cascadeUrlFiltering": False}})).status == R.PASS
    doh = [{"name": "Block DoH", "type": "DNS_OVER_HTTPS", "state": "ENABLED", "actions": ["DENY_DNS_OVER_HTTPS_USE"]}]
    assert full.capp_4(FakeCl({"/zia/cloudApplicationRules": doh})).status == R.PASS
    assert full.capp_4(FakeCl({"/zia/cloudApplicationRules": [IOT]})).status == R.WARN
    ssl = [{"name": "Decrypt all", "state": "ENABLED", "action": {"type": "DECRYPT"}}]
    assert full.capp_3(FakeCl({"/zia/sslInspectionRules": ssl})).status == R.PASS
    clash = ssl + [{"name": "Exempt Dropbox", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "cloudApplications": ["DROPBOX"]}]
    cac = [{"name": "Block DB upload", "state": "ENABLED", "type": "FILE_SHARE", "applications": ["DROPBOX"], "actions": ["DENY_FILE_SHARE_UPLOAD"]}]
    r = full.capp_3(FakeCl({"/zia/sslInspectionRules": clash, "/zia/cloudApplicationRules": cac}))
    assert r.status == R.WARN and "DROPBOX" in r.detail


def test_zpa_status_segments_certificates_and_texts():
    con = {"list": [{"name": "c1", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"}, {"name": "c2", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"}]}
    assert full.zpa_4(FakeCl({"/zpa/connector": con})).status == R.PASS
    assert full.zpa_4(FakeCl({"/zpa/connector": {"list": [{"name": "c1"}]}})).status == R.INFO
    assert "licenses connectors as pairs" not in full.zpa_4(FakeCl({})).detail and "N+1" in full.zpa_4(FakeCl({})).detail
    assert full.zpa_8(FakeCl({"/zpa/serviceEdge": {"list": [{"controlChannelStatus": "ZPN_STATUS_DISCONNECTED"}]}})).status == R.FAIL
    seg = {"list": [{"name": "DNS", "enabled": True, "tcpPortRanges": ["53", "53"], "domainNames": ["10.0.0.0/8"], "healthReporting": "CONTINUOUS"}]}
    r = full.zpa_1(FakeCl({"/zpa/application": seg}))
    assert r.status == R.WARN and "port 53" in r.detail and "/16 or wider" in r.detail and "Continuous" in r.detail
    ok = {"list": [{"name": "Intranet", "enabled": True, "tcpPortRanges": ["443", "443"], "domainNames": ["intranet.corp"], "healthReporting": "ON_ACCESS"}]}
    assert full.zpa_1(FakeCl({"/zpa/application": ok})).status == R.PASS
    assert full.zpa_3(FakeCl({"/zpa/serverGroup": {"list": [{"name": "sg", "dynamicDiscovery": False}]}})).status == R.INFO
    assert full.zpa_10(FakeCl({})).status == R.INFO and "Browser Access" in full.zpa_10(FakeCl({})).detail
    assert full.zpa_10(FakeCl({"/zpa/certificate": {"list": [{"name": "old", "validToInEpochSec": 1}]}})).status == R.WARN
    r = full.zpa_15(FakeCl({}))
    assert r.status == R.INFO and "pre-Windows-logon" in r.detail and "CI/CD" not in r.detail


def test_client_connector_platform_checks_read_the_api_shapes():
    pol = [{"enableFailOpen": 0, "enableWebSecOnProxyUnreachable": 1, "enableWebSecOnTunnelFailure": 0, "captivePortalWebSecDisableMinutes": 10}]
    r = full.zcc_3(FakeCl({"/zcc/failOpenPolicy": pol}))
    assert r.status == R.INFO and "Z-Tunnel failover: Direct Internet Access" in r.detail and "recommends fail-closed" not in r.detail
    fp = [{"name": "Corp", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "NONE"}, {"networkType": "ON_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"}]}]
    r = full.zcc_6(FakeCl({"/zcc/forwardingProfiles": fp}))
    assert r.status == R.WARN and "Corp (off)" in r.detail
    nets = [{"networkName": "HQ", "dnsSearchDomains": ["corp.example"]}, {"networkName": "Lab", "trustedSubnets": ["10.9.0.0/16"]}]
    r = full.zcc_18(FakeCl({"/zcc/trustedNetworks": nets}))
    assert r.status == R.PASS and "DNS search domain" in r.detail and "network range" in r.detail
    assert full.zcc_18(FakeCl({"/zcc/trustedNetworks": [{"networkName": "Dyn", "hostnames": ["x"]}]})).status == R.WARN
    assert "SSID" not in full.zcc_1(FakeCl({})).detail


# ── ZDX, RBAC, Authentication Service, automation ───────────────────────
def test_zdx_reads_wrapped_lists_and_a_longer_window():
    assert zdx.zdx_alert_triggered(FakeCl({"/zdx/alerts/ongoing": {"next_offset": None, "alerts": []}})).status == R.PASS
    assert zdx.zdx_alert_triggered(FakeCl({"/zdx/alerts/ongoing": {"alerts": [{"id": 1}, {"id": 2}]}})).detail.startswith("2 ZDX alert")
    assert zdx.zdx_inventory_software(FakeCl({"/zdx/inventory/software": {"software": []}})).status == R.INFO
    cl = RecCl({"/zdx/administration/apps": []})
    r = zdx.zdx_admin_apps(cl)
    assert cl.params["/zdx/administration/apps"] == {"since": 24} and "last 24 hours" in r.detail and "configured" not in r.detail
    r = zdx.zdx_troubleshoot(FakeCl({"/zdx/troubleshooting/devices": {"devices": [{"id": 1}]}}))
    assert r.status == R.PASS and "1 active device" in r.detail and "deep-path" not in r.detail
    assert [c[2] for c in zdx.ZDX_REG if c[0] == "ZDX.8"] == ["ZDX device telemetry reachable"]


def test_rbac_and_identity_checks_read_the_model_fields():
    rules = [{"conditions": [{"operands": [{"objectType": "APP_GROUP"}, {"objectType": "SCIM_GROUP"}]}]}]
    r = rbac.rbac_zpa_policies_group_bound(FakeCl({"/zpa/policySet/rules/ACCESS_POLICY": rules}))
    assert r.status == R.PASS and "All 1" in r.detail
    rules[0]["conditions"][0]["operands"].append({"objectType": "SAML"})
    assert rbac.rbac_zpa_policies_group_bound(FakeCl({"/zpa/policySet/rules/ACCESS_POLICY": rules})).status == R.WARN
    users = [{"loginName": "a", "adminEntitlementEnabled": True}, {"loginName": "b", "adminEntitlementEnabled": True}, {"loginName": "c"}]
    assert rbac.rbac_zid_admin_redundancy(FakeCl({"/zid/users": users})).status == R.PASS
    assert zid.zid_admin_coverage(FakeCl({"/zid/users": users})).status == R.PASS
    assert zid.zid_admin_coverage(FakeCl({"/zid/users": users[1:]})).status == R.WARN
    r = rbac.rbac_zia_sso_federated(FakeCl({"/zia/authSettings": {"orgAuthType": "SAFECHANNEL_DIR"}}))
    assert r.status == R.WARN and "Authentication Service" in r.detail
    assert rbac.rbac_zia_sso_federated(FakeCl({"/zia/authSettings": {"orgAuthType": "SAML"}})).status == R.PASS
    r = rbac.rbac_zia_mfa_required(FakeCl({}))
    assert r.status == R.INFO and "Authentication Methods" in r.detail
    sync = {"ziaLastSyncTime": 1700000000, "ziaInitialSyncDone": True, "zpaInitialSyncDone": True, "zpaSyncErrorCode": 0}
    assert rbac.rbac_zcc_idp_sync(FakeCl({"/zcc/adminUsersSyncInfo": sync})).status == R.PASS
    assert rbac.rbac_zcc_idp_sync(FakeCl({"/zcc/adminUsersSyncInfo": dict(sync, ziaSyncErrorCode=12)})).status == R.WARN
    admins = [{"userName": "a"}, {"userName": "b", "disabled": True}]
    r = rbac.rbac_zia_admin_count(FakeCl({"/zia/adminUsers": admins, "/zia/users": [{"adminUser": True}] * 5}))
    assert r.status == R.WARN and "Only 1" in r.detail


def test_automation_checks_rank_audit_log_and_duplicate_names():
    roles = [{"name": "Admin", "rank": 0}, {"name": "Ops", "rank": 1}, {"name": "Read", "rank": 7}]
    assert "super-admin: 1" in auto.auto_iac_1(FakeCl({"/zia/adminRoles": roles})).detail
    assert auto.auto_ans_2(FakeCl({"/zia/nssFeeds": [{"nssLogType": "ADMIN_AUDIT", "feedStatus": "ENABLED"}]})).status == R.PASS
    r = auto.auto_ans_2(FakeCl({"/zia/auditlogEntryReport": {"status": "COMPLETE"}}))
    assert r.status == R.INFO and "6 months" in r.detail
    assert [c[2] for c in auto.AUTOMATION_REG if c[0] == "AUTO-ANS-02"] == ["Admin audit log kept beyond ZIA's 6 months"]
    dup = [{"id": 1, "name": "Same"}, {"id": 2, "name": "Same"}]
    r = auto.auto_tf_5(FakeCl({"/zia/webDlpRules": dup}))
    assert r.status == R.INFO and "import collisions" not in r.detail and "do not break import" in r.detail


def test_new_checks_are_registered_once():
    ids = [c[0] for c in chk.REG]
    assert ids.count("D.9") == 1 and ids.index("D.9") == ids.index("D.8") + 1 and len(ids) == len(set(ids))
    pids = [c[0] for c in full.PLATFORM_REG]
    for new, after in (("FW.9", "FW.8"), ("LOC.6", "LOC.5"), ("CA.4", "CA.3"), ("CA.5", "CA.4")):
        assert pids.count(new) == 1 and pids.index(new) == pids.index(after) + 1
    assert len(pids) == len(set(pids))
