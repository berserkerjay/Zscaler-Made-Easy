"""Strict Client Connector evaluation: every profile field Zscaler's
guidance names, forwarding profiles, trusted networks, fail-open, privacy,
company, devices and the DLP notification templates."""
import json

import zcc_evaluation as ze
from dlp_assessment_full_auto import REG, R


class FakeCl:
    customer_id = ""

    def __init__(self, routes):
        self.routes = routes

    def get(self, path, params=None):
        if path in self.routes:
            return self.routes[path], 200
        return {"error": "not found", "path": path}, 404


GOOD_PROFILE = {"id": 1, "name": "Corp-Win", "device_type": 3, "active": 1, "enableAntiTampering": 1, "uninstallPassword": "x", "disablePassword": "x",
                "ziaDisablePassword": "x", "zpaDisablePassword": "x", "zdpDisablePassword": "x", "zdxDisablePassword": "x", "exitPassword": "x", "logoutPassword": "x",
                "logLevel": "Info", "dropQuicTraffic": 1, "strictEnforcement": 1, "zccAppFailOpenPolicy": 0, "enableZCCRevert": 0,
                "interceptZIATrafficAllAdapters": 1, "reactivateWebSecurityMinutes": 30, "sendDisableServiceReason": 1,
                "policyExtension": json.dumps({"packetTunnelExcludeList": "10.0.0.0/8,192.168.0.0/16", "prioritizeDnsExclusions": 0})}
BAD_PROFILE = {"id": 2, "name": "Contractors", "device_type": 4, "active": True, "enableAntiTampering": 0, "uninstallPassword": "", "disablePassword": "x",
               "logLevel": "Debug", "dropQuicTraffic": 0, "strictEnforcement": 1, "zccAppFailOpenPolicy": 1, "enableZCCRevert": 1, "zccRevertPassword": "",
               "interceptZIATrafficAllAdapters": 0, "vpnGateways": [{"name": f"gw{i}"} for i in range(7)], "reactivateWebSecurityMinutes": 480,
               "allowZiaDisableWithoutPassword": 1, "policyExtension": {"packetTunnelExcludeList": "0.0.0.0/0", "prioritizeDnsExclusions": 1}}
FWD_GOOD = {"id": 5, "name": "Corp", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"}, {"networkType": "ON_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"}],
            "primaryTransport": "DTLS", "allowTLSFallback": 1, "enableLWFDriver": 1, "dropIpv6Traffic": 1, "bypassProxyForPrivateIP": 1, "blockUnreachableDomainsTraffic": 1}
FWD_BAD = {"id": 6, "name": "Legacy", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ENFORCE_PROXY"}, {"networkType": "ON_TRUSTED_NETWORK", "actionType": "NONE"}],
           "primaryTransport": "TLS", "allowTLSFallback": 0, "enableLWFDriver": 0, "dropIpv6Traffic": 0, "dropIpv6IncludeTrafficInT2": 0, "bypassProxyForPrivateIP": 0, "enablePAC": 1, "pacURL": "http://pac"}
NETS = [{"id": 1, "networkName": "HQ", "dnsServers": ["10.1.1.1"], "dnsSearchDomains": ["corp.local"]}, {"id": 2, "networkName": "Branch", "trustedGateways": ["10.2.0.1"]}]
FAILOPEN = {"enableFailOpen": 1, "enableWebSecOnTunnelFailure": 0, "captivePortalWebSecDisableMinutes": 30, "enableStrictEnforcementPrompt": 1}
COMPANY = {"dlpEnabled": 0, "enableAntiTampering": 1, "slowRolloutZCC": 0, "enableGlobalZCCTelemetry": 1, "inactiveDeviceCleanup": 0}
PRIVACY = {"collectUserInfo": 0, "collectMachineHostname": 1, "enablePacketCapture": 1, "restrictRemotePacketCapture": 0, "exportLogsForNonAdmin": 1}
DEVICES = [{"id": i, "registrationState": "REGISTERED", "strictEnforcement": 1 if i < 7 else 0, "antiTamperingStatus": 1, "tunnelVersion": "2.0" if i else "1.0",
            "zdpEnabled": 1, "agentVersion": "4.5.0.1" if i < 3 else ("4.4.0.1" if i < 5 else "4.1.0.1")} for i in range(10)]
TEMPLATES = [{"id": 1, "name": "Auditor", "tlsEnabled": True, "attachContent": False, "subject": "DLP ${RULENAME}", "htmlMessage": "<p>${USER} ${ENGINES}</p>", "plainTextMessage": "${USER}"},
             {"id": 2, "name": "Legacy", "tlsEnabled": False, "attachContent": True, "subject": "", "htmlMessage": "<p>match</p>", "plainTextMessage": ""}]
RULES = [{"id": 1, "name": "Block-PCI", "state": "ENABLED", "action": "BLOCK", "notificationTemplate": {"id": 1}},
         {"id": 2, "name": "Block-PII", "state": "ENABLED", "action": {"type": "BLOCK"}}, {"id": 3, "name": "Monitor", "state": "ENABLED", "action": "ALLOW"}]


def _cl(profiles=(GOOD_PROFILE, BAD_PROFILE), fwd=(FWD_GOOD, FWD_BAD), **extra):
    routes = {"/zcc/appProfiles": {"list": list(profiles)}, "/zcc/forwardingProfiles": list(fwd), "/zcc/trustedNetworks": NETS,
              "/zcc/failOpenPolicy": [FAILOPEN], "/zcc/companyInfo": COMPANY, "/zcc/privacyInfo": PRIVACY, "/zcc/devices": DEVICES,
              "/zia/dlpNotificationTemplates": TEMPLATES, "/zia/webDlpRules": RULES}
    routes.update(extra)
    return FakeCl(routes)


def test_flatten_reads_policy_extension_and_platform_codes():
    f = ze.flatten_profile(BAD_PROFILE)
    assert f["packetTunnelExcludeList"] == "0.0.0.0/0" and ze._plat(f) == "macOS"
    g = ze.flatten_profile(GOOD_PROFILE)
    assert g["packetTunnelExcludeList"].startswith("10.") and ze._plat(g) == "Windows" and ze._v(g, "uninstall_password") == "x"


def test_profile_checks_name_the_profile_and_the_setting():
    cl = _cl()
    r = ze.z_anti_tampering(cl); assert r.status == R.FAIL and "Contractors (macOS)" in r.detail and "best-practices-zscaler-client-connector-deployment" in r.detail
    r = ze.z_disable_passwords(cl); assert r.status == R.FAIL and "Contractors" in r.detail and "uninstall" in r.detail and "Corp-Win" not in r.detail.split(";")[0]
    r = ze.z_log_level(cl); assert r.status == R.WARN and "debug" in r.detail.lower()
    r = ze.z_quic(cl); assert r.status == R.FAIL and "QUIC" in r.detail and "Contractors" in r.detail
    r = ze.z_fail_open(cl); assert r.status == R.FAIL and "tunnel failure" in r.detail and "30 minutes" in r.detail
    r = ze.z_revert(cl); assert r.status == R.FAIL and "revert" in r.detail
    r = ze.z_adapters(cl); assert r.status == R.WARN and "all adapters" in r.detail and "7 VPN gateway" in r.detail
    r = ze.z_disable_window(cl); assert r.status == R.FAIL and "480 minutes" in r.detail and "without a password" in r.detail
    r = ze.z_bypass_hygiene(cl); assert r.status == R.FAIL and "0.0.0.0/0" in r.detail and "DNS exclusions" in r.detail
    # A tenant with only the good profile passes every profile check.
    good = _cl(profiles=(GOOD_PROFILE,), fwd=(FWD_GOOD,))
    for fn in (ze.z_anti_tampering, ze.z_disable_passwords, ze.z_log_level, ze.z_quic, ze.z_revert, ze.z_adapters, ze.z_disable_window, ze.z_bypass_hygiene):
        assert fn(good).status == R.PASS, fn.__name__


def test_forwarding_trusted_network_company_privacy_devices_and_templates():
    cl = _cl()
    r = ze.z_forwarding_modes(cl); assert r.status == R.FAIL and "Legacy" in r.detail and "PAC" in r.detail and "TLS fallback" in r.detail
    assert ze.z_forwarding_modes(_cl(fwd=(FWD_GOOD,))).status == R.PASS
    r = ze.z_forwarding_hygiene(cl); assert r.status == R.WARN and "IPv6" in r.detail and "RFC1918" in r.detail
    r = ze.z_trusted_networks(cl); assert r.status == R.FAIL and "Branch (1 criterion)" in r.detail and "HQ" not in r.detail
    r = ze.z_company(cl); assert r.status == R.FAIL and "Endpoint Data Protection" in r.detail and "phased" in r.detail and "inactive devices" in r.detail
    r = ze.z_privacy(cl); assert r.status == R.WARN and "user information" in r.detail and "packet capture" in r.detail and "export" in r.detail
    r = ze.z_device_fleet(cl); assert r.status == R.FAIL and "3 of 10" in r.detail and "Z-Tunnel 1.0" in r.detail
    r = ze.z_version_spread(cl); assert r.status == R.WARN and "5 of 10" in r.detail
    r = ze.z_notification_templates(cl)
    assert r.status == R.FAIL and "Legacy: TLS off" in r.detail and "attaches the matched content" in r.detail and "Block-PII" in r.detail and "Auditor" not in r.detail.split("Legacy")[0]
    # Unreadable endpoints degrade to INFO / the resolver's explanation, never raise.
    empty = FakeCl({})
    assert ze.z_anti_tampering(empty).status == R.INFO and "not readable" in ze.z_anti_tampering(empty).detail
    assert ze.z_company(empty).status == R.INFO and ze.z_device_fleet(empty).status == R.INFO and ze.z_notification_templates(empty).status == R.INFO


def test_checks_are_registered_in_their_sections():
    ids = [e[0] for e in REG]
    assert "1.15" in ids and "1.28" in ids and "6.9" in ids and "12.15" in ids
    assert ids.index("1.28") < ids.index("2.1") and ids.index("6.9") < ids.index("7.1") and ids.index("12.15") < ids.index("A.1")
    assert len({e[0] for e in REG}) == len(REG)
