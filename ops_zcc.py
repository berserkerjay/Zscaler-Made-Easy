"""Client Connector profiles on the Bulk changes engine (admin_ops plugins).

Two operation types on /report/operations, under "Build new":

  zcc_profile_build   a forwarding profile (best practice, portal default,
                      or an existing one picked) and a Windows or macOS app
                      profile (best practice or portal default) linked to
                      it. Every setting is an item with its value, the
                      portal default and what it does in plain words. The
                      forwarding profile is created first, then the app
                      profile; if the app profile is refused, the new
                      forwarding profile is deleted again. Each profile is
                      checked again right before it is created, every
                      setting is read back, and both are created disabled
                      unless the operator turns them on. Undo deletes what
                      the build created (as a zcc_profile_delete).
  zcc_profile_delete  delete an app or forwarding profile. The typed
                      confirmation is the profile's name; a profile in use is
                      refused (an enabled app profile; a forwarding profile
                      an app profile on any platform links to).

The engine (admin_ops) supplies the scope check before any read, the plan
hash and the re-plan before writing, write mode, the writer, assessor and
typed-confirmation gates, the record, the audit log and Undo.

install_commands builds the MSI, EXE or macOS install command and a .bat or
.command script for a chosen app profile (the Client Connector fleet page);
tokens and passwords are masked unless the caller reveals them, and nothing
is logged or stored.

API calls (zscaler-sdk-python 1.11.3, zscaler/zcc), verified there:

    forwarding_profile.list_by_company       GET    /zcc/papi/public/v1/webForwardingProfile/listByCompany
    forwarding_profile.update_forwarding_profile
                                             POST   /zcc/papi/public/v1/webForwardingProfile/edit
    forwarding_profile.delete_forwarding_profile
                                             DELETE /zcc/papi/public/v1/webForwardingProfile/{id}/delete
    web_policy.list_by_company               GET    /zcc/papi/public/v1/web/policy/listByCompany (device_type)
    web_policy.web_policy_edit               PUT    /zcc/papi/public/v1/web/policy/edit
    web_policy.delete_web_policy             DELETE /zcc/papi/public/v1/web/policy/{id}/delete
    web_app_service.list_by_company          GET    /zcc/papi/public/v1/webAppService/listByCompany
    application_profiles.get_application_profile
                                             GET    /zcc/papi/public/v1/application-profiles/{id} (policyToken)

The SDK has every call this needs, so no raw OneAPI path is used. The SDK's
ZCC serializer (zcc._serialize.zcc_to_wire) passes the camelCase portal
payload through unchanged (a test checks it). Assumed, not verifiable without
a tenant (see ASSUMED): that POST /webForwardingProfile/edit with id "-1"
creates a profile and answers its id; that PUT /web/policy/edit without an
id creates an app profile; that ZCC answers HTTP 200 with success "false"
when it rejects a body; that both endpoints need the full portal-shaped body
built here (field names from the SDK models where they are declared, the
rest from the portal's own payload); that a new profile goes last
(ruleOrder = profiles on that platform + 1); and the install options of the
Client Connector installers.

Secrets: tamper-protection passwords are not set here (set them in the
Client Connector Portal); install tokens and passwords are masked in every
answer unless revealed, and none is logged, audited or recorded.
"""
from __future__ import annotations

import copy
import json
import re
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao

LogFn = Optional[Callable[[str], None]]

BASE = "/zcc/papi/public/v1"
PAGE_SIZE = 100
MAX_PAGES = 20
NAME_MAX = 64
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,63}$")
MAX_TARGETS = 2            # a delete removes at most an app profile and its forwarding profile

ASSUMED = [
    "POST /webForwardingProfile/edit with id \"-1\" creates a forwarding profile and answers its id (the SDK documents the call as an update).",
    "PUT /web/policy/edit without an id creates an app profile (the SDK documents it as add or update).",
    "ZCC answers HTTP 200 with success \"false\" when it rejects a body; that answer is treated as a refusal.",
    "Both create calls need the full portal-shaped body built here; field names are the SDK models' where the models declare them.",
    "A new app profile is put last: its rule order is the number of profiles on that platform plus one.",
    "An inactive forwarding profile can be linked to an app profile.",
    "The installer options (MSI properties, EXE and macOS installbuilder.sh flags) are those Zscaler documents for Client Connector.",
]


class BuilderError(ao.OperationError):
    """A spec this builder refuses, in words."""


# ---------------------------------------------------------------------------
# Platforms and networks
# ---------------------------------------------------------------------------

PLATFORMS: Dict[str, Dict[str, Any]] = {
    "windows": {"label": "Windows", "device_type": 3, "policy_key": "windowsPolicy"},
    "macos": {"label": "macOS", "device_type": 4, "policy_key": "macPolicy"},
}
# Every platform an app profile can exist on (for the in-use check of a forwarding profile).
ALL_DEVICE_TYPES = {"ios": 1, "android": 2, "windows": 3, "macos": 4, "linux": 5}
# Network types in forwardingProfileActions / forwardingProfileZpaActions / unifiedTunnel.
NETWORKS = ((0, "trusted network"), (1, "VPN-trusted network"), (2, "off-trusted network"), (3, "split VPN-trusted network"))


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def _norm_key(k: Any) -> str:
    return str(k).replace("_", "").lower()


def _get(obj: Any, *path: str) -> Any:
    """A field of a profile as read back, whatever the casing (the wire's
    camelCase or the SDK model's snake_case)."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        want = _norm_key(key)
        cur = next((v for k, v in cur.items() if _norm_key(k) == want), None)
    return cur


def _list(obj: Any, key: str) -> List[Dict[str, Any]]:
    v = _get(obj, key)
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _json_eq(a: Any, b: Any) -> bool:
    def load(x):
        if isinstance(x, str):
            try:
                return json.loads(x)
            except ValueError:
                return x
        return x
    la, lb = load(a), load(b)
    if isinstance(la, dict) and isinstance(lb, dict):
        return {_norm_key(k): _num(v) if _num(v) is not None else v for k, v in la.items()} == \
               {_norm_key(k): _num(v) if _num(v) is not None else v for k, v in lb.items()}
    return la == lb


# ---------------------------------------------------------------------------
# The full portal-shaped forwarding profile body (portal defaults)
# ---------------------------------------------------------------------------

def _system_proxy(enable_pac: int, proxy_action: int) -> Dict[str, Any]:
    return {"bypassProxyForPrivateIP": 0, "enableAutoDetect": 0, "enablePAC": enable_pac, "enableProxyServer": 0, "pacURL": "",
            "pacDataPath": "", "performGPUpdate": 0, "proxyAction": proxy_action, "proxyServerAddress": "", "proxyServerPort": ""}


def _zia_action(network: int) -> Dict[str, Any]:
    a: Dict[str, Any] = {
        "actionType": 2, "enablePacketTunnel": 0, "blockUnreachableDomainsTraffic": "0", "dropIpv6Traffic": 0,
        "dropIpv6TrafficInIpv6Network": 0, "primaryTransport": 1, "UDPTimeout": 9, "DTLSTimeout": 9, "TLSTimeout": 5,
        "mtuForZadapter": "0", "allowTLSFallback": 1, "pathMtuDiscovery": 1, "tunnel2FallbackType": 0,
        "useTunnel2ForProxiedWebTraffic": 0, "useTunnel2ForUnencryptedWebTraffic": 0, "redirectWebTraffic": 0,
        "dropIpv6IncludeTrafficInT2": 0, "customPac": "", "systemProxyData": _system_proxy(1, 1),
        "latencyBasedZenEnablement": "0", "zenProbeInterval": 60, "zenProbeSampleSize": 5, "zenThresholdLimit": 2,
        "latencyBasedServerEnablement": 0, "lbsProbeInterval": 30, "lbsProbeSampleSize": 5, "lbsThresholdLimit": 1,
        "useZIABCCOnTunnel2Failures": 0, "latencyBasedServerMTEnablement": 0, "networkType": network,
    }
    if network:
        a["isSameAsOnTrustedNetwork"] = True
    return a


def _unified(network: int) -> Dict[str, Any]:
    u: Dict[str, Any] = {
        "blockUnreachableDomainsTraffic": "0", "dropIpv6Traffic": 0, "dropIpv6TrafficInIpv6Network": 0, "primaryTransport": 1,
        "DTLSTimeout": 9, "TLSTimeout": 5, "mtuForZadapter": "0", "allowTLSFallback": 1, "pathMtuDiscovery": 1,
        "tunnel2FallbackType": 4, "redirectWebTraffic": 0, "dropIpv6IncludeTrafficInT2": 0, "sendTrustedNetworkResultToZpa": 0,
        "systemProxyData": _system_proxy(0, 0), "networkType": network,
    }
    if network:
        u["sameAsOnTrusted"] = 0 if network == 1 else 1
    u["actionTypeZIA"] = 0 if network == 1 else 1
    u["actionTypeZPA"] = 0 if network == 1 else 1
    return u


def _zpa_action(network: int) -> Dict[str, Any]:
    z: Dict[str, Any] = {
        "actionType": 0 if network == 1 else 1, "primaryTransport": 0, "DTLSTimeout": 9, "TLSTimeout": 5, "mtuForZadapter": "0",
        "partnerInfo": {"primaryTransport": 0, "mtuForZadapter": 0}, "latencyBasedServerEnablement": "0", "lbsProbeSampleSize": 5,
        "lbsThresholdLimit": 1, "lbsProbeInterval": 30, "latencyBasedServerMTEnablement": "0", "networkType": network,
    }
    if network:
        z["isSameAsOnTrustedNetwork"] = network != 1
    return z


def forwarding_body(name: str) -> Dict[str, Any]:
    """A forwarding profile as the portal creates it with its defaults
    (Tunnel with local proxy for ZIA on every network; ZPA tunnel except on
    VPN-trusted networks), id "-1" (create), disabled."""
    return {
        "id": "-1", "name": name, "active": 0, "addCondition": "", "conditionType": 1, "dnsServers": "", "dnsSearchDomains": "",
        "hostname": "", "resolvedIpsForHostname": "", "trustedSubnets": "", "trustedGateways": "", "trustedDhcpServers": "",
        "trustedEgressIps": "", "enableUnifiedTunnel": 0,
        "forwardingProfileActions": [_zia_action(n) for n, _ in NETWORKS],
        "unifiedTunnel": [_unified(n) for n, _ in NETWORKS],
        "enableLWFDriver": 1, "enableAllDefaultAdaptersTN": 0, "enableSplitVpnTN": 0, "skipTrustedCriteriaMatch": 0,
        "forwardingProfileZpaActions": [_zpa_action(n) for n, _ in NETWORKS],
        "predefinedTrustedNetworks": False, "trustedNetworkIds": [], "predefinedTnAll": False,
    }


# ---------------------------------------------------------------------------
# The full portal-shaped app profile body (portal defaults)
# ---------------------------------------------------------------------------

_DHCP121 = '{"trusted":1,"offTrusted":1,"vpnTrusted":1,"splitVpnTrusted":1}'
_ALL_NETWORKS_OFF = '{"trusted":0,"vpnTrusted":0,"offTrusted":0,"splitVpnTrusted":0}'
_CAPTIVE = ('{"automaticCapture":1,"enableCaptivePortalDetection":1,"enableFailOpen":1,'
            '"captivePortalWebSecDisableMinutes":10,"enableEmbeddedCaptivePortal":0}')
_DDIL = ('{"ddilEnabled":0,"businessContinuityActivationDomain":"","businessContinuityTestModeEnabled":0,'
         '"zpaBccRSAPubKeyName":"","zpaBccRSAPubKey":""}')
_ZDX_LITE = '{"localMetrics":1,"endToEndDiagnostics":{"trusted":0,"vpnTrusted":0,"offTrusted":0,"splitVpnTrusted":0}}'
_EXCLUDE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255", "169.254.0.0/16"]
_EXCLUDE_V6 = ["[FF00::/8]", "[FE80::/10]", "[FC00::/7]"]


def _policy_extension() -> Dict[str, Any]:
    return {
        "vpnGateways": "", "partnerDomains": "", "zccFailCloseSettingsIpBypasses": "", "zccFailCloseSettingsLockdownOnTunnelProcessExit": "1",
        "zccFailCloseSettingsExitUninstallPassword": "", "zccFailCloseSettingsAppByPassIds": [], "userAllowedToAddPartner": "1",
        "followGlobalForPartnerLogin": "1", "followGlobalForZpaReauth": "1", "zpaReauthConfig": None, "zpaAutoReauthTimeout": 30,
        "followGlobalForPacketCapture": "1", "enableLocalPacketCapture": "0", "enableLocalPacketCaptureV2": 1, "enableZaisService": 0,
        "exitPassword": "", "followRoutingTable": "1", "useDefaultAdapterForDNS": "1", "updateDnsSearchOrder": "1",
        "useZscalerNotificationFramework": "0", "switchFocusToNotification": "0", "fallbackToGatewayDomain": "1", "useProxyPortForT1": "0",
        "useProxyPortForT2": "0", "allowPacExclusionsOnly": "0", "useWsaPollForZpa": "0", "enableZCCRevert": "0", "zccRevertPassword": "",
        "zpaAuthExpOnSleep": 0, "zpaAuthExpOnSysRestart": 0, "zpaAuthExpOnNetIpChange": 0, "instantForceZPAReauthStateUpdate": 0,
        "zpaAuthExpOnWinLogonSession": 0, "enableSetProxyOnVPNAdapters": 1, "disableDNSRouteExclusion": 0, "packetTunnelIncludeListForIPv6": "",
        "interceptZIATrafficAllAdapters": 0, "enableAntiTampering": 0, "reactivateAntiTamperingTime": 0,
        "zpaAuthExpSessionLockStateMinTimeInSecond": "0", "zpaAuthExpOnWinSessionLock": 0, "sourcePortBasedBypasses": "3389:*",
        "enforceSplitDNS": 0, "dropQuicTraffic": 0, "zdpDisablePassword": "", "useV8JsEngine": "1", "zdDisablePassword": "",
        "zdxDisablePassword": "", "zpaDisablePassword": "", "advanceZpaReauth": False, "bypassDNSTrafficUsingUDPProxy": "0",
        "reconnectTunOnWakeup": "0", "enableCustomTheme": 0, "switchToModernUI": 2, "deleteDHCPOption121Routes": _DHCP121,
        "machineIdpAuth": False, "nonce": "", "packetTunnelDnsExcludeList": "", "packetTunnelDnsIncludeList": "",
        "packetTunnelExcludeList": ",".join(_EXCLUDE_V4), "packetTunnelExcludeListForIPv6": ",".join(_EXCLUDE_V6),
        "packetTunnelIncludeList": "0.0.0.0/0", "truncateLargeUDPDNSResponse": 0, "overrideATCmdByPolicy": 0,
        "purgeKerberosPreferredDCCache": 0, "rscModeOnAllAdapters": 0, "enableAdapterHardwareOffloading": 0,
        "supportZPASearchDomainsInTRP": 0, "prioritizeDnsExclusions": 1,
        "generateCliPasswordContract": {"enableCli": False, "allowZpaDisableWithoutPassword": True, "allowZiaDisableWithoutPassword": True,
                                        "allowZdxDisableWithoutPassword": True},
        "locationRulesetPolicies": {"splitVpnTrusted": {"id": 0}, "vpnTrusted": {"id": 0}},
        "ddilConfig": _DDIL, "zccAppFailOpenPolicy": 0, "zccTunnelFailPolicy": 0, "allowClientCertCachingForWebView2": "0",
        "showConfirmationDialogForCachedCert": "0", "zccFailCloseSettingsLockdownOnFirewallError": "0",
        "zccFailCloseSettingsLockdownOnDriverError": "0", "enableFlowBasedTunnel": "0", "oneIdMTDeviceAuthEnabled": "0",
        "preventAutoReauthDuringDeviceLock": "0", "clientConnectorUiLanguage": 0, "enableNetworkTrafficProcessMapping": 0,
        "useEndPointLocationForDCSelection": "0", "recacheSystemProxy": "0", "enableLocationPolicyOverride": 0, "blockPrivateRelay": "0",
        "enableAutomaticPacketCapture": "0", "enableAPCforCriticalSections": "1", "enableAPCforOtherSections": "1",
        "enablePCAdditionalSpace": "1", "pcAdditionalSpace": "512", "enableCustomProxyDetection": "0", "enableCrashReporting": "0",
        "ddilEnabled": 0, "businessContinuityActivationDomain": "", "businessContinuityTestModeEnabled": 0, "zpaBccRSAPubKeyName": "",
        "zpaBccRSAPubKey": "", "zdxLiteConfigObj": _ZDX_LITE,
    }


def _windows_policy() -> Dict[str, Any]:
    return {
        "cacheSystemProxy": "0", "disable_password": "", "disableLoopBackRestriction": "0", "removeExemptedContainers": "1",
        "disableParallelIpv4andIpv6": "-1", "flowLoggerConfig": "", "domainProfileDetectionConfig": _ALL_NETWORKS_OFF,
        "zpaReauthConfig": _ALL_NETWORKS_OFF, "allInboundTrafficConfig": "", "install_ssl_certs": 0, "triggerDomainProfleDetection": 0,
        "logout_password": "", "overrideWPAD": 0, "pacDataPath": "", "pacType": 1, "prioritizeIPv4": 0, "restartWinHttpSvc": 0,
        "sccmConfig": None, "uninstall_password": "", "wfpDriver": 0, "captivePortalConfig": _CAPTIVE,
        "installWindowsFirewallInboundRule": "1", "forceLocationRefreshSccm": 0, "wfpMtr": 0, "enableCustomProxyDetection": "0",
        "enableZscalerFirewall": "0", "captivePortalUrlId": 1,
    }


def _mac_policy() -> Dict[str, Any]:
    return {
        "addIfscopeRoute": "0", "clearArpCache": "0", "enableZscalerFirewall": "0", "persistentZscalerFirewall": "0",
        "dnsPriorityOrderingForTrustedDnsCriteria": "0", "dnsPriorityOrdering": "State:/Network/Service/com.cisco.anyconnect/DNS",
        "browserAuthType": -1, "useDefaultBrowser": 0, "cacheSystemProxy": "0", "disable_password": "", "install_ssl_certs": 0,
        "logout_password": "", "uninstall_password": "", "captivePortalConfig": _CAPTIVE, "enableApplicationBasedBypass": "0",
        "dnsWithoutProxyRedirection": "0",
    }


def app_body(platform: str, name: str, *, rule_order: int, forwarding_profile_id: Any = 0) -> Dict[str, Any]:
    """An app profile as the portal creates it with its defaults, disabled
    ("active": "0"), linked to `forwarding_profile_id`."""
    p = PLATFORMS[platform]
    body: Dict[str, Any] = {
        "ruleOrder": rule_order, "name": name, "groups": [], "users": [], "appServiceIds": [], "groupAll": 0, "description": "",
        "pac_url": "", "registryPath": "", "logMode": -1, "logLevel": 0, "logFileSize": 100, "reactivateWebSecurityMinutes": 0,
        "tunnelZappTraffic": 0, "active": "0", "mdm": 0, "passcode": "", "exit_password": "", "sendDisableServiceReason": 0,
        "highlightActiveControl": 0, "pacType": 1, "pacDataPath": "", "reauth_period": 8, "disableLoopBackRestriction": 0,
        "removeExemptedContainers": 1, "overrideWPAD": 0, "restartWinHttpSvc": 0, "flowLoggerConfig": None,
        "domainProfileDetectionConfig": None, "allInboundTrafficConfig": None, "disableParallelIpv4AndIPv6": -1, "enforced": 0,
        "bypass_mms_apps": 0, "quota_in_roaming": 0, "wifi_ssid": "", "limit": "1", "billing_day": "1", "allowed_apps": "",
        "custom_text": "", "bypass_android_apps": [], "clearArpCache": 0, "enableZscalerFirewall": 0, "persistentZscalerFirewall": 0,
        "dnsPriorityOrdering": ["State:/Network/Service/com.cisco.anyconnect/DNS"], "installWindowsFirewallInboundRule": "1",
        "forceLocationRefreshSccm": 0, "wfpMtr": 0, "enableLocalPacketCaptureTabValue": 1,
        "captivePortalUrlId": [{"label": "Zscaler", "value": 1}],
        "clientConnectorUiLanguageSelected": [{"label": "Use System Language", "value": 0}],
        "policyExtension": _policy_extension(),
        "refreshKerberosToken": 0, "bypassCustomAppIds": [], "prioritizeDnsExclusions": "1", "allowZpaDisableWithoutPassword": False,
        "allowZiaDisableWithoutPassword": False, "allowZdxDisableWithoutPassword": False, "dnsWithoutProxyRedirection": "0",
        "useDefaultAdapterForDNS": "1", "updateDnsSearchOrder": "1", "enforceSplitDNS": "0", "disableDNSRouteExclusion": "0",
        "enableSetProxyOnVPNAdapters": "0", "dropQuicTraffic": "0", "followRoutingTable": "1",
        "ruleOrderSelectedOption": {"label": str(rule_order), "value": rule_order},
        "billingDaySelectedOption": {"label": "1", "value": "1"},
        "forwardingProfileId": forwarding_profile_id, "ziaPostureProfile": [], "usersOption": 0, "usersSelected": [],
        "deviceGroupsOption": 0, "deviceGroups": [], "deviceGroupsSelected": [], "notificationTemplateSelected": [], "registryName": "",
        "machineTokenOption": 0, "machineTokenSelectedOption": 0, "zpaAuthExpSessionLockStateMinTimeInSecond": "1",
        "forceZpaAuthenticationToExpire": [], "logModeSelected": {"label": "Default (Current-Debug)", "value": -1},
        "ipv6ModeSelected": {"label": "IPv6Native", "value": 4}, "flowLoggingSelected": [], "blockDomainSelected": [],
        "zpaReauthConfig": [], "zpaAutoReauthTimeout": [{"label": "30", "value": 30}], "endToEndDiagnosticsSelected": [],
        "blockInboundTrafficSelected": [], "enableCaptivePortalDetection": 1, "enableFailOpen": 1, "captivePortalWebSecDisableMinutes": 10,
        "localMetrics": 1, "endToEndDiagnostics": {"trusted": 0, "vpnTrusted": 0, "offTrusted": 0, "splitVpnTrusted": 0},
        "reactivateAntiTamperingTime": 0, "ziaDRMethod": {"label": "Policy Based Access (Web only)", "value": 2}, "vpnGateways": [],
        "partnerDomains": [], "zccFailCloseSettingsIpBypasses": [], "zccFailCloseSettingsLockdownOnTunnelProcessExit": 1,
        "zccFailCloseSettingsExitUninstallPassword": "", "userAllowedToAddPartner": 0, "followGlobalForPartnerLogin": "1",
        "followGlobalForZpaReauth": "1", "followGlobalForPacketCapture": "1", "enableLocalPacketCapture": "0",
        "enableLocalPacketCaptureV2": [{"label": "NPCAP", "value": 1}], "packetTunnelIncludeList": ["0.0.0.0/0"],
        "packetTunnelExcludeList": list(_EXCLUDE_V4), "packetTunnelIncludeListForIPv6": [], "packetTunnelExcludeListForIPv6": list(_EXCLUDE_V6),
        "packetTunnelDnsIncludeList": [], "packetTunnelDnsExcludeList": [], "sourcePortBasedBypasses": ["3389:*"], "useV8JsEngine": "1",
        "disableParallelIpv4andIpv6": "-1", "device_type": p["device_type"],
        p["policy_key"]: _windows_policy() if platform == "windows" else _mac_policy(),
        "enableZCCRevert": False,
        "disasterRecovery": {"allowZiaTest": False, "allowZpaTest": False, "enableZiaDR": False, "enableZpaDR": False, "ziaDRMethod": 2,
                             "ziaCustomDbUrl": "", "useZiaGlobalDb": True, "ziaDomainName": "", "ziaRSAPubKeyName": "", "ziaRSAPubKey": "",
                             "zpaDomainName": "", "zpaRSAPubKeyName": "", "zpaRSAPubKey": ""},
        "customDNS": [], "enableCustomProxyDetection": "0", "clientConnectorUiLanguage": 0, "oneIdMTDeviceAuthEnabled": "0",
        "preventAutoReauthDuringDeviceLock": "0", "instantForceZPAReauthStateUpdate": 0, "enableNetworkTrafficProcessMapping": 0,
        "useEndPointLocationForDCSelection": "0", "recacheSystemProxy": "0", "enableLocationPolicyOverride": 0, "vpnTrusted": [],
        "splitVpnTrusted": [], "trusted": [], "offTrusted": [], "blockPrivateRelay": "0", "enableCrashReporting": "0",
        "enableAutomaticPacketCapture": "0", "enableAPCforCriticalSections": "1", "enableAPCforOtherSections": "1",
        "enablePCAdditionalSpace": "1", "pcAdditionalSpace": [{"label": "1GB", "value": "1024"}], "appServiceCustomIdsSelected": [],
        "bypassAppIds": [], "bypassMacAppIds": [], "zccFailCloseSettingsAppByPassSelected": [], "zccFailCloseSettingsAppByPassIds": [],
        "switchToModernUISelected": [{"label": "Follow Global Setting", "value": "2"}],
        "browserAuthType": {"label": "FOLLOW_GLOBAL_CONFIG", "value": -1}, "useDefaultBrowser": 0,
    }
    return body


# ---------------------------------------------------------------------------
# Settings: value, portal default, plain-English explanation, apply, verify
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Setting:
    key: str
    label: str
    category: str
    value: str
    portal_default: str
    explain: str
    apply: Callable[[Dict[str, Any], Dict[str, Any]], None]
    verify: Callable[[Dict[str, Any], Dict[str, Any]], Optional[bool]]
    impact: str = "info"            # "caution" is shown as a warning chip
    default: bool = True            # ticked when the template is chosen
    apps: Tuple[str, ...] = ()      # IP-based app definitions this setting needs (resolved in the tenant by name)

    def meta(self) -> Dict[str, Any]:
        return {"key": self.key, "label": self.label, "category": self.category, "value": self.value,
                "portal_default": self.portal_default, "explain": self.explain, "impact": self.impact, "default": self.default,
                "apps": list(self.apps)}


def _zia(b):
    return _list(b, "forwardingProfileActions")


def _zpa(b):
    return _list(b, "forwardingProfileZpaActions")


def _every(rows: List[Dict[str, Any]], test: Callable[[Dict[str, Any]], bool]) -> Optional[bool]:
    if len(rows) < len(NETWORKS):
        return False
    return all(test(r) for r in rows)


def _is(v: Any, want: float) -> bool:
    return _num(v) == want


def _set_all(rows: List[Dict[str, Any]], **fields: Any) -> None:
    for r in rows:
        r.update(fields)


def _fwd_tunnel(b, _c):
    _set_all(b["forwardingProfileActions"], actionType=1, enablePacketTunnel=1)


def _fwd_no_pac(b, _c):
    for a in b["forwardingProfileActions"]:
        a["systemProxy"] = 0
        a["systemProxyData"]["enablePAC"] = 0


def _fwd_zpa_vpn(b, _c):
    for a in b["forwardingProfileZpaActions"]:
        if a["networkType"] == 1:
            a["actionType"], a["isSameAsOnTrustedNetwork"] = 1, False


def _fwd_zpa_lbs(b, _c):
    _set_all(b["forwardingProfileZpaActions"], latencyBasedServerEnablement=1, latencyBasedServerMTEnablement=1)


FWD_SETTINGS: List[Setting] = [
    Setting("zia_tunnel", "ZIA: tunnel on every network type", "ZIA forwarding", "Tunnel (Z-Tunnel 2.0), on all four network types",
            "Tunnel with local proxy",
            "Client Connector sends the device's internet traffic to ZIA through its own tunnel on trusted, VPN-trusted, off-trusted and "
            "split VPN-trusted networks, so traffic is inspected wherever the device is.",
            _fwd_tunnel, lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "actionType"), 1) and _is(_get(a, "enablePacketTunnel"), 1))),
    Setting("redirect_web", "Redirect web traffic to the listening proxy", "ZIA forwarding", "On, every network", "Off",
            "Web traffic that an app sends to a proxy is taken into Client Connector's listening proxy, so proxy-aware apps are still "
            "inspected instead of going around the tunnel.",
            lambda b, c: _set_all(b["forwardingProfileActions"], redirectWebTraffic=1),
            lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "redirectWebTraffic"), 1))),
    Setting("tunnel2_proxied", "Use Z-Tunnel 2.0 for proxied web traffic", "ZIA forwarding", "On, every network", "Off",
            "Proxied web traffic also travels in Z-Tunnel 2.0 (the full packet tunnel) instead of the older Z-Tunnel 1.0, so one tunnel "
            "carries everything.",
            lambda b, c: _set_all(b["forwardingProfileActions"], useTunnel2ForProxiedWebTraffic=1),
            lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "useTunnel2ForProxiedWebTraffic"), 1))),
    Setting("drop_ipv6", "Drop IPv6 traffic on dual-stack networks", "ZIA forwarding", "On", "Off",
            "Where a network has both IPv4 and IPv6, IPv6 traffic is dropped so it falls back to IPv4 and goes through the tunnel instead "
            "of around it.",
            lambda b, c: _set_all(b["forwardingProfileActions"], dropIpv6Traffic=1),
            lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "dropIpv6Traffic"), 1)), impact="caution"),
    Setting("drop_ipv6_only", "Drop IPv6 traffic on IPv6-only networks", "ZIA forwarding", "On", "Off",
            "Also drops IPv6 traffic where the network has only IPv6. A device on such a network cannot reach IPv6-only destinations, so "
            "check the customer has no IPv6-only sites first.",
            lambda b, c: _set_all(b["forwardingProfileActions"], dropIpv6TrafficInIpv6Network=1),
            lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "dropIpv6TrafficInIpv6Network"), 1)), impact="caution"),
    Setting("latency_zen", "Latency-based ZEN selection", "ZIA forwarding", "On (probe every 60 seconds, 5 samples, threshold 2)", "Off",
            "Client Connector measures the delay to nearby Zscaler service edges (ZENs) and moves to a faster one when the current one "
            "slows down, instead of staying with the closest by location.",
            lambda b, c: _set_all(b["forwardingProfileActions"], latencyBasedZenEnablement=1),
            lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "latencyBasedZenEnablement"), 1))),
    Setting("system_pac_off", "System proxy: no automatic configuration script", "ZIA forwarding", "PAC off", "PAC on",
            "Client Connector does not write a PAC script into the computer's proxy settings. In tunnel mode the tunnel carries the "
            "traffic, so a system PAC would only add a second, conflicting path.",
            _fwd_no_pac, lambda p, c: _every(_zia(p), lambda a: _is(_get(a, "systemProxyData", "enablePAC"), 0))),
    Setting("zpa_vpn_trusted", "ZPA on VPN-trusted networks", "ZPA forwarding", "Tunnel", "None",
            "Private-app traffic still goes through ZPA when the device is on a trusted VPN. With the portal default, nothing goes to ZPA "
            "on a VPN-trusted network.",
            _fwd_zpa_vpn, lambda p, c: any(_is(_get(a, "networkType"), 1) and _is(_get(a, "actionType"), 1) for a in _zpa(p))),
    Setting("zpa_latency", "ZPA latency-based server selection", "ZPA forwarding", "On, every network (also for Microtenants)", "Off",
            "Client Connector picks the ZPA service edge with the lowest delay instead of the closest by location.",
            _fwd_zpa_lbs, lambda p, c: _every(_zpa(p), lambda a: _is(_get(a, "latencyBasedServerEnablement"), 1)
                                              and _is(_get(a, "latencyBasedServerMTEnablement"), 1))),
]
FWD_BY_KEY = {s.key: s for s in FWD_SETTINGS}

FWD_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "best_practice": {"label": "Best practice", "settings": [s.key for s in FWD_SETTINGS],
                      "describe": "Tunnel on every network type, the listening-proxy redirect, Z-Tunnel 2.0, IPv6 dropped, latency-based "
                                  "ZEN selection, no system PAC, ZPA on VPN-trusted networks and ZPA latency-based selection."},
    "portal_default": {"label": "Portal default", "settings": [],
                       "describe": "What the Client Connector Portal creates when you add a forwarding profile and save without changes."},
    "existing": {"label": "An existing forwarding profile", "settings": [],
                 "describe": "Link the new app profile to a forwarding profile the tenant already has; nothing is created for it."},
}

# IP-based app bypass: definitions are looked up in the tenant by name, never by a fixed id.
WIN_BYPASS = ("Microsoft Teams", "Zoom Meetings", "Microsoft SharePoint", "Microsoft Exchange", "Microsoft 365",
              "Windows 365 & Azure Virtual Desktop")
MAC_BYPASS = ("Microsoft Teams", "Zoom Meetings", "Windows 365 & Azure Virtual Desktop")
_DOMAIN_DETECT = '{"trusted":0,"vpnTrusted":1,"offTrusted":1,"splitVpnTrusted":1}'
_REAUTH_ALL = '{"trusted":1,"vpnTrusted":1,"offTrusted":1,"splitVpnTrusted":1}'


def _pol(b: Dict[str, Any]) -> Dict[str, Any]:
    return b.get("windowsPolicy") if "windowsPolicy" in b else b["macPolicy"]


def _ext(b: Dict[str, Any]) -> Dict[str, Any]:
    return b["policyExtension"]


def _top_or_policy(p: Dict[str, Any], key: str) -> Any:
    v = _get(p, key)
    if v is None:
        v = _get(p, "windowsPolicy", key)
    if v is None:
        v = _get(p, "macPolicy", key)
    return v


def _apply_ssl(b, c):
    _pol(b)["install_ssl_certs"] = 1
    b["install_ssl_certs"] = 1


def _apply_wfp(b, c):
    b["windowsPolicy"]["wfpDriver"] = 1
    b["wfpDriver"] = 1


def _apply_ipv4(b, c):
    b["windowsPolicy"]["prioritizeIPv4"] = 1
    b["prioritizeIPv4"] = 1


def _apply_parallel(b, c):
    b["disableParallelIpv4AndIPv6"] = 0
    b["disableParallelIpv4andIpv6"] = "0"
    b["windowsPolicy"]["disableParallelIpv4andIpv6"] = "0"


def _apply_domain_detect(b, c):
    b["windowsPolicy"]["triggerDomainProfleDetection"] = 1
    b["triggerDomainProfleDetection"] = 1
    b["windowsPolicy"]["domainProfileDetectionConfig"] = _DOMAIN_DETECT


def _apply_dns_all(b, c):
    _ext(b)["packetTunnelDnsIncludeList"] = "*"
    b["packetTunnelDnsIncludeList"] = ["*"]


def _apply_bypass(b, c):
    b["appServiceIds"] = list(c.get("app_ids") or [])


def _verify_bypass(p, c):
    got = sorted(str(x) for x in (_get(p, "appServiceIds") or []))
    return got == sorted(str(x) for x in (c.get("app_ids") or []))


def _apply_reauth(b, c):
    _ext(b)["followGlobalForZpaReauth"] = "0"
    b["followGlobalForZpaReauth"] = "0"
    _ext(b)["zpaAutoReauthTimeout"] = 30
    b["zpaAutoReauthTimeout"] = [{"label": "30", "value": 30}]
    _ext(b)["zpaReauthConfig"] = _REAUTH_ALL


def _apply_reauth_notice(b, c):
    _ext(b)["advanceZpaReauth"] = True
    _ext(b)["advanceZpaReauthTime"] = 30


def _apply_capture(b, c):
    _ext(b)["enableLocalPacketCapture"] = "1"
    b["enableLocalPacketCapture"] = "1"
    _ext(b)["enableLocalPacketCaptureV2"] = 1


def _apply_capture_extras_off(b, c):
    for k in ("enableAPCforCriticalSections", "enableAPCforOtherSections", "enablePCAdditionalSpace"):
        _ext(b)[k] = "0"
        b[k] = "0"
    _ext(b)["pcAdditionalSpace"] = "0"
    b["pcAdditionalSpace"] = []


def _ext_is(key: str, want: float) -> Callable[[Dict[str, Any], Dict[str, Any]], Optional[bool]]:
    return lambda p, c: _is(_get(p, "policyExtension", key), want)


_SSL = ("install_ssl_cert", "Install the Zscaler root certificate", "Security", "On", "Off",
        "Client Connector installs the Zscaler root certificate on the device, so SSL inspection works without a separate certificate "
        "roll-out.")
_NOTIFY = ("notification_framework", "Use the Zscaler notification framework", "User experience", "On", "Off",
           "Client Connector shows its messages through the Zscaler notification framework.")
_FOCUS = ("switch_focus", "Bring notifications to the front", "User experience", "On", "Off",
          "Client Connector notifications open in front of other windows so users see them.")
_DNS_ALL = ("dns_include_all", "Domain inclusions: all domains (*)", "Network", "*", "(empty)",
            "The Z-Tunnel 2.0 domain inclusion list is set to every domain, so Client Connector handles DNS for all of them.")
_ALL_USERS = ("all_users", "Apply to all users", "Assignment", "All users", "No users or groups",
              "The profile matches every user instead of named users or groups. It changes nothing while the profile is disabled; once "
              "enabled it applies to everyone who reaches its rule order.")
_REAUTH = ("auto_zpa_reauth", "Automatically attempt ZPA re-authentication", "ZPA", "On, every network type, 30 minutes before expiry",
           "Follow the global setting",
           "Client Connector re-authenticates ZPA on its own before the session expires, on every network type, instead of following "
           "the Platform Settings value.")


def _s(t: Tuple[str, ...], apply, verify, **kw) -> Setting:
    return Setting(*t, apply=apply, verify=verify, **kw)


WINDOWS_SETTINGS: List[Setting] = [
    _s(_SSL, _apply_ssl, lambda p, c: _is(_top_or_policy(p, "install_ssl_certs"), 1)),
    Setting("wfp_driver", "Install the Windows Filtering Platform driver", "Security", "On", "Off",
            "Installs the WFP driver Client Connector needs for packet-level features such as process-based bypasses, flow logging and "
            "local packet capture.", _apply_wfp, lambda p, c: _is(_top_or_policy(p, "wfpDriver"), 1)),
    Setting("enable_cli", "Enable the Zscaler command line", "Security", "On", "Off",
            "Allows Client Connector's command-line tool on the device, for troubleshooting. Turning a service off without a password "
            "stays at its default.",
            lambda b, c: _ext(b)["generateCliPasswordContract"].update(enableCli=True),
            lambda p, c: _get(p, "policyExtension", "generateCliPasswordContract", "enableCli") in (True, 1, "1", "true")),
    Setting("prioritize_ipv4", "Prefer IPv4 over IPv6", "Network", "On", "Off",
            "When a destination can be reached over both IPv4 and IPv6, Client Connector uses IPv4.",
            _apply_ipv4, lambda p, c: _is(_top_or_policy(p, "prioritizeIPv4"), 1)),
    Setting("parallel_ipv4_ipv6", "Disable parallel IPv4 and IPv6: set explicitly", "Network", "0", "-1 (default)",
            "Writes the explicit value 0 instead of the portal's \"default\" (-1), so the behaviour does not change if the default does.",
            _apply_parallel, lambda p, c: _is(_get(p, "disableParallelIpv4AndIPv6"), 0) or _is(_top_or_policy(p, "disableParallelIpv4andIpv6"), 0)),
    Setting("domain_profile_detection", "Trigger domain profile detection", "Network", "On: VPN-trusted, off-trusted and split VPN",
            "Off", "Windows re-checks whether it is on the company domain when the device is on a VPN-trusted, off-trusted or split "
            "VPN-trusted network, so domain policies apply correctly.",
            _apply_domain_detect, lambda p, c: _is(_top_or_policy(p, "triggerDomainProfleDetection"), 1)),
    _s(_DNS_ALL, _apply_dns_all, lambda p, c: _get(p, "policyExtension", "packetTunnelDnsIncludeList") == "*"),
    Setting("app_bypass", "Bypass IP-based applications", "Network", ", ".join(WIN_BYPASS), "None",
            "Calls and meetings of these apps go straight to the app's own servers instead of through the tunnel, which keeps audio and "
            "video smooth. Their traffic is not inspected, which is the usual trade-off for real-time media.",
            _apply_bypass, _verify_bypass, impact="caution", apps=WIN_BYPASS),
    _s(_NOTIFY, lambda b, c: _ext(b).update(useZscalerNotificationFramework="1"), _ext_is("useZscalerNotificationFramework", 1)),
    _s(_FOCUS, lambda b, c: _ext(b).update(switchFocusToNotification="1"), _ext_is("switchFocusToNotification", 1)),
    Setting("zpa_reauth_notice", "Warn 30 minutes before ZPA sign-in expires", "User experience", "On, 30 minutes", "Off",
            "Users are told 30 minutes before their ZPA authentication runs out, so they can sign in again before private apps stop "
            "working.", _apply_reauth_notice,
            lambda p, c: _get(p, "policyExtension", "advanceZpaReauth") in (True, 1, "1", "true")),
    _s(_ALL_USERS, lambda b, c: b.update(groupAll=1), lambda p, c: _is(_get(p, "groupAll"), 1), impact="caution"),
    _s(_REAUTH, _apply_reauth, lambda p, c: _is(_get(p, "policyExtension", "followGlobalForZpaReauth"), 0)),
]

MACOS_SETTINGS: List[Setting] = [
    _s(_SSL, _apply_ssl, lambda p, c: _is(_top_or_policy(p, "install_ssl_certs"), 1)),
    Setting("block_private_relay", "Block iCloud Private Relay", "Security", "On", "Off",
            "Blocks Apple's iCloud Private Relay, which would otherwise carry Safari traffic around the Zscaler tunnel.",
            lambda b, c: (_ext(b).update(blockPrivateRelay="1"), b.update(blockPrivateRelay="1")),
            _ext_is("blockPrivateRelay", 1)),
    Setting("fail_open_on_tunnel_exit", "Do not lock down traffic when the tunnel process exits", "Security", "Off (no lockdown)",
            "On (lockdown)", "If the Client Connector tunnel process stops, traffic is not blocked. This keeps users working but leaves "
            "traffic uninspected until the tunnel is back, so it is offered unticked.",
            lambda b, c: (_ext(b).update(zccFailCloseSettingsLockdownOnTunnelProcessExit="0"),
                          b.update(zccFailCloseSettingsLockdownOnTunnelProcessExit=0)),
            _ext_is("zccFailCloseSettingsLockdownOnTunnelProcessExit", 0), impact="caution", default=False),
    _s(_DNS_ALL, _apply_dns_all, lambda p, c: _get(p, "policyExtension", "packetTunnelDnsIncludeList") == "*"),
    Setting("dns_exclusions_not_first", "Prioritize DNS exclusions: off", "Network", "Off", "On",
            "DNS exclusions no longer win over inclusions, so the all-domains inclusion above takes effect.",
            lambda b, c: (_ext(b).update(prioritizeDnsExclusions=0), b.update(prioritizeDnsExclusions="0")),
            _ext_is("prioritizeDnsExclusions", 0)),
    Setting("flow_based_tunnel", "Flow-based tunnel", "Network", "On", "Off",
            "Turns on the flow-based tunnel option for macOS.",
            lambda b, c: _ext(b).update(enableFlowBasedTunnel="1"), _ext_is("enableFlowBasedTunnel", 1)),
    Setting("reconnect_on_wake", "Reconnect the tunnel when the Mac wakes", "Network", "On", "Off",
            "The tunnel is rebuilt as soon as the Mac wakes from sleep, so users are not left without protection or private apps.",
            lambda b, c: _ext(b).update(reconnectTunOnWakeup="1"), _ext_is("reconnectTunOnWakeup", 1)),
    Setting("app_bypass", "Bypass IP-based applications", "Network", ", ".join(MAC_BYPASS), "None",
            "Calls and meetings of these apps go straight to the app's own servers instead of through the tunnel, which keeps audio and "
            "video smooth. Their traffic is not inspected, which is the usual trade-off for real-time media.",
            _apply_bypass, _verify_bypass, impact="caution", apps=MAC_BYPASS),
    _s(_NOTIFY, lambda b, c: _ext(b).update(useZscalerNotificationFramework="1"), _ext_is("useZscalerNotificationFramework", 1)),
    _s(_FOCUS, lambda b, c: _ext(b).update(switchFocusToNotification="1"), _ext_is("switchFocusToNotification", 1)),
    Setting("reactivate_zia", "Turn Internet security back on after 60 minutes", "User experience", "60 minutes", "Never (0)",
            "If a user turns Internet security (ZIA) off, Client Connector turns it back on after an hour.",
            lambda b, c: b.update(reactivateWebSecurityMinutes="60"), lambda p, c: _is(_get(p, "reactivateWebSecurityMinutes"), 60)),
    Setting("local_packet_capture", "Allow local packet capture", "Troubleshooting", "On", "Off",
            "Users or support can start a packet capture from Client Connector when troubleshooting.",
            _apply_capture, _ext_is("enableLocalPacketCapture", 1)),
    Setting("packet_capture_extras_off", "Automatic packet capture extras: off", "Troubleshooting", "Off",
            "On (with extra capture space)", "Turns off automatic packet capture and the extra disk space it reserves.",
            _apply_capture_extras_off, _ext_is("enableAPCforCriticalSections", 0)),
    _s(_ALL_USERS, lambda b, c: b.update(groupAll=1), lambda p, c: _is(_get(p, "groupAll"), 1), impact="caution"),
    _s(_REAUTH, _apply_reauth, lambda p, c: _is(_get(p, "policyExtension", "followGlobalForZpaReauth"), 0)),
]
APP_SETTINGS: Dict[str, List[Setting]] = {"windows": WINDOWS_SETTINGS, "macos": MACOS_SETTINGS}

APP_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "best_practice": {"label": "Best practice",
                      "describe": {"windows": "Root certificate and WFP driver, the command line, IPv4 first, domain profile detection, DNS for all "
                                              "domains, the Microsoft 365, Teams, Zoom and Azure Virtual Desktop bypass, notifications, the ZPA "
                                              "re-authentication notice and automatic re-authentication, applied to all users.",
                                   "macos": "Root certificate, iCloud Private Relay blocked, DNS for all domains, flow-based tunnel, reconnect on "
                                            "wake, the Teams, Zoom and Azure Virtual Desktop bypass, notifications, Internet security back on "
                                            "after an hour, local packet capture and automatic ZPA re-authentication, applied to all users."}},
    "portal_default": {"label": "Portal default",
                       "describe": {"windows": "What the Client Connector Portal creates when you add a Windows profile and save without changes.",
                                    "macos": "What the Client Connector Portal creates when you add a macOS profile and save without changes."}},
}
NOT_SET_HERE = [
    "Tamper protection passwords (logout, exit, uninstall, turning ZIA, ZPA or ZDX off) are not set here, so no password travels "
    "through this app: set them in the Client Connector Portal after the profile is created.",
    "The modern Client Connector user interface and notification templates are tenant-specific or ignored by the API: choose them in "
    "the Client Connector Portal.",
]


def _template_keys(kind: str, template: str, platform: str) -> List[str]:
    if kind == "forwarding":
        return list(FWD_TEMPLATES[template]["settings"])
    return [s.key for s in APP_SETTINGS[platform] if s.default] if template == "best_practice" else []


def catalog() -> Dict[str, Any]:
    """Everything the page shows before any tenant is read: platforms,
    templates, every setting with its value, portal default and meaning."""
    return {
        "platforms": [{"id": k, "label": v["label"], "device_type": v["device_type"]} for k, v in PLATFORMS.items()],
        "forwarding": {"templates": [{"id": k, "label": v["label"], "describe": v["describe"], "settings": list(v["settings"])}
                                     for k, v in FWD_TEMPLATES.items()],
                       "settings": [s.meta() for s in FWD_SETTINGS]},
        "app": {p: {"templates": [{"id": k, "label": v["label"], "describe": v["describe"][p], "settings": _template_keys("app", k, p)}
                                  for k, v in APP_TEMPLATES.items()],
                    "settings": [s.meta() for s in APP_SETTINGS[p]]} for p in PLATFORMS},
        "not_set_here": list(NOT_SET_HERE),
        "assumed": list(ASSUMED),
        "install": install_catalog(),
        "api": API_CALLS,
    }


API_CALLS = {
    "list_forwarding": {"sdk": "zcc.forwarding_profile.list_by_company", "method": "GET", "path": f"{BASE}/webForwardingProfile/listByCompany"},
    "create_forwarding": {"sdk": "zcc.forwarding_profile.update_forwarding_profile", "method": "POST", "path": f"{BASE}/webForwardingProfile/edit"},
    "delete_forwarding": {"sdk": "zcc.forwarding_profile.delete_forwarding_profile", "method": "DELETE", "path": f"{BASE}/webForwardingProfile/{{id}}/delete"},
    "list_app": {"sdk": "zcc.web_policy.list_by_company", "method": "GET", "path": f"{BASE}/web/policy/listByCompany"},
    "create_app": {"sdk": "zcc.web_policy.web_policy_edit", "method": "PUT", "path": f"{BASE}/web/policy/edit"},
    "delete_app": {"sdk": "zcc.web_policy.delete_web_policy", "method": "DELETE", "path": f"{BASE}/web/policy/{{id}}/delete"},
    "list_app_services": {"sdk": "zcc.web_app_service.list_by_company", "method": "GET", "path": f"{BASE}/webAppService/listByCompany"},
    "get_app_profile": {"sdk": "zcc.application_profiles.get_application_profile", "method": "GET", "path": f"{BASE}/application-profiles/{{id}}"},
}


# ---------------------------------------------------------------------------
# Spec validation (before any sign-in)
# ---------------------------------------------------------------------------

def check_name(name: Any, what: str) -> str:
    n = str(name or "").strip()
    if not n:
        raise BuilderError(f"Give the {what} a name.")
    if len(n) > NAME_MAX or not NAME_RE.match(n):
        raise BuilderError(f"The {what} name may use letters, digits, spaces and . _ ( ) - (at most {NAME_MAX} characters, starting with "
                           "a letter or digit).")
    return n


def _keys(raw: Any, allowed: Dict[str, Setting], default: List[str], what: str) -> List[str]:
    if raw is None:
        return list(default)
    if not isinstance(raw, list) or any(not isinstance(k, str) for k in raw):
        raise BuilderError(f"{what} must be a list of setting keys.")
    unknown = sorted({k for k in raw if k not in allowed})
    if unknown:
        raise BuilderError(f"Unknown {what}: {', '.join(unknown[:5])}.")
    order = list(allowed)
    return [k for k in order if k in set(raw)]


def normalize_spec(spec: Any) -> Dict[str, Any]:
    """The build spec, checked and in canonical form; BuilderError in words."""
    if not isinstance(spec, dict):
        raise BuilderError("The build is missing: pick a platform and templates first.")
    platform = str(spec.get("platform") or "").lower()
    if platform not in PLATFORMS:
        raise BuilderError("Pick the platform: Windows or macOS.")
    fwd = spec.get("forwarding") if isinstance(spec.get("forwarding"), dict) else {}
    app = spec.get("app") if isinstance(spec.get("app"), dict) else {}
    ftpl = str(fwd.get("template") or "best_practice")
    if ftpl not in FWD_TEMPLATES:
        raise BuilderError("Pick the forwarding profile: best practice, portal default or an existing one.")
    atpl = str(app.get("template") or "best_practice")
    if atpl not in APP_TEMPLATES:
        raise BuilderError("Pick the app profile template: best practice or portal default.")
    out_fwd: Dict[str, Any] = {"template": ftpl}
    if ftpl == "existing":
        fid = str(fwd.get("id") or "").strip()
        if not re.fullmatch(r"\d{1,19}", fid):
            raise BuilderError("Pick the existing forwarding profile to link to.")
        out_fwd["id"] = fid
    else:
        out_fwd["name"] = check_name(fwd.get("name"), "forwarding profile")
        out_fwd["settings"] = _keys(fwd.get("settings"), FWD_BY_KEY, _template_keys("forwarding", ftpl, platform), "forwarding settings")
    by_key = {s.key: s for s in APP_SETTINGS[platform]}
    out_app = {"template": atpl, "name": check_name(app.get("name"), "app profile"),
               "settings": _keys(app.get("settings"), by_key, _template_keys("app", atpl, platform), "app profile settings")}
    if ftpl != "existing" and out_fwd["name"].lower() == out_app["name"].lower():
        pass   # different object types may share a name; allowed
    return {"platform": platform, "forwarding": out_fwd, "app": out_app, "enable": spec.get("enable") is True}


def normalize_delete(spec: Any) -> Dict[str, Any]:
    if not isinstance(spec, dict) or not isinstance(spec.get("targets"), list) or not spec["targets"]:
        raise BuilderError("Pick the profile to delete.")
    if len(spec["targets"]) > MAX_TARGETS:
        raise BuilderError(f"At most {MAX_TARGETS} profiles per delete (an app profile and its forwarding profile).")
    out = []
    for t in spec["targets"]:
        if not isinstance(t, dict):
            raise BuilderError("Each profile to delete names its kind, id and name.")
        kind = str(t.get("kind") or "")
        if kind not in ("app", "forwarding"):
            raise BuilderError("A profile to delete is an app profile or a forwarding profile.")
        pid = str(t.get("id") or "").strip()
        if not re.fullmatch(r"\d{1,19}", pid):
            raise BuilderError("A profile to delete needs its id.")
        row = {"kind": kind, "id": pid, "name": str(t.get("name") or "").strip()[:NAME_MAX * 2]}
        if not row["name"]:
            raise BuilderError("A profile to delete needs its name, as it is in the tenant.")
        if kind == "app":
            plat = str(t.get("platform") or "").lower()
            if plat not in ALL_DEVICE_TYPES:
                raise BuilderError("An app profile to delete needs its platform.")
            row["platform"] = plat
        out.append(row)
    # app profiles first, so a forwarding profile is free when its turn comes
    out.sort(key=lambda r: 0 if r["kind"] == "app" else 1)
    return {"targets": out}




# ---------------------------------------------------------------------------
# Reads (SDK service calls; the wire body where the SDK hands it back)
# ---------------------------------------------------------------------------

Stopped = ao.Stopped


STOPPED_REASON = "You clicked Stop, so nothing more was read or sent to the tenant."


def _check_stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise Stopped(STOPPED_REASON)


def _plain(x: Any) -> Dict[str, Any]:
    if isinstance(x, dict):
        return dict(x)
    fn = getattr(x, "as_dict", None)
    if callable(fn):
        try:
            d = fn()
            return d if isinstance(d, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _wire(resp: Any) -> Any:
    fn = getattr(resp, "get_body", None)
    if not callable(fn):
        return None
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


def _wire_items(body: Any) -> Optional[List[Dict[str, Any]]]:
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)]
    if isinstance(body, dict):
        for key in ("policies", "list", "items", "data", "records"):
            if isinstance(body.get(key), list):
                return [x for x in body[key] if isinstance(x, dict)]
    return None


def _err_text(err: Any) -> str:
    import pack_ops as ops
    return ops.describe_error(err)[:300]


def _read_all(fn: Callable[..., Any], query: Dict[str, Any], cancel) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every page of an SDK list call: (rows, error). The wire body is used
    when the SDK hands it back, so nested settings survive the model."""
    rows: List[Dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        _check_stop(cancel)
        try:
            ret = fn(query_params=dict(query, page=page, page_size=PAGE_SIZE))
        except Exception as e:  # noqa: BLE001 — a refusal is reported, never raised
            return rows, f"{type(e).__name__}: {str(e)[:200]}"
        items, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
        if err:
            return rows, _err_text(err)
        batch = _wire_items(_wire(resp))
        if batch is None:
            batch = [_plain(x) for x in (items or [])]
        rows.extend(batch)
        if len(batch) < PAGE_SIZE:
            return rows, None
    return rows, f"more than {MAX_PAGES * PAGE_SIZE} profiles: the list was not read to the end"


def _zcc(sdk: Any) -> Any:
    z = getattr(sdk, "zcc", None)
    if z is None:
        raise BuilderError("This sign-in has no Client Connector API. Sign in with a OneAPI API client.")
    return z


def read_forwarding(sdk: Any, cancel=None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    return _read_all(_zcc(sdk).forwarding_profile.list_by_company, {}, cancel)


def read_apps(sdk: Any, platform: str, cancel=None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    return _read_all(_zcc(sdk).web_policy.list_by_company, {"device_type": platform}, cancel)


def read_app_services(sdk: Any, cancel=None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    return _read_all(_zcc(sdk).web_app_service.list_by_company, {}, cancel)


def _ref(v: Any) -> str:
    """An id as text, the same however the API spelled it: 123, "123",
    " 123 " and 123.0 are all "123" (so an in-use check never misses a link)."""
    if v is None or isinstance(v, bool):
        return ""
    s = str(v).strip()
    m = re.fullmatch(r"(\d+)\.0*", s)
    return m.group(1) if m else s


def _id(row: Dict[str, Any]) -> str:
    return _ref(_get(row, "id"))


def _name(row: Dict[str, Any]) -> str:
    return str(_get(row, "name") or "")


def _active(row: Dict[str, Any]) -> bool:
    v = _get(row, "active")
    return str(v).strip().lower() in ("1", "true", "1.0")


def profile_summary(row: Dict[str, Any], kind: str, platform: str = "") -> Dict[str, Any]:
    out = {"kind": kind, "id": _id(row), "name": _name(row), "active": _active(row)}
    if kind == "app":
        out["platform"] = platform
        out["rule_order"] = _get(row, "ruleOrder")
        fid = _get(row, "forwardingProfileId")
        out["forwarding_profile_id"] = "" if _ref(fid) in ("", "0") else _ref(fid)
    return out


def inventory(sdk: Any, *, log: LogFn = None, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """The forwarding profiles and the Windows and macOS app profiles, read-only
    (names, ids, state and links; never a setting value or a secret)."""
    say = log or (lambda m: None)
    out: Dict[str, Any] = {"forwarding": [], "app": {}, "errors": {}}
    say("Reading the forwarding profiles…")
    rows, err = read_forwarding(sdk, cancel)
    if err:
        out["errors"]["forwarding"] = err
    out["forwarding"] = sorted((profile_summary(r, "forwarding") for r in rows), key=lambda r: r["name"].lower())
    for plat in PLATFORMS:
        say(f"Reading the {PLATFORMS[plat]['label']} app profiles…")
        rows, err = read_apps(sdk, plat, cancel)
        if err:
            out["errors"][f"app_{plat}"] = err
        out["app"][plat] = sorted((profile_summary(r, "app", plat) for r in rows), key=lambda r: (_num(r.get("rule_order")) or 0, r["name"].lower()))
    used: Dict[str, int] = {}
    for plat in PLATFORMS:
        for a in out["app"][plat]:
            if a["forwarding_profile_id"]:
                used[a["forwarding_profile_id"]] = used.get(a["forwarding_profile_id"], 0) + 1
    for f in out["forwarding"]:
        f["used_by"] = used.get(f["id"], 0)
    say(f"{len(out['forwarding'])} forwarding profile(s), " + ", ".join(f"{len(out['app'][p])} {PLATFORMS[p]['label']} app profile(s)" for p in PLATFORMS) + ".")
    return out


def build_bodies(spec: Dict[str, Any], *, rule_order: int, ctx: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """The forwarding profile body (None when an existing one is linked) and
    the app profile body, with the chosen settings applied."""
    plat = spec["platform"]
    fwd_body = None
    if spec["forwarding"]["template"] != "existing":
        fwd_body = forwarding_body(spec["forwarding"]["name"])
        for k in spec["forwarding"]["settings"]:
            FWD_BY_KEY[k].apply(fwd_body, ctx)
        if spec["enable"]:
            fwd_body["active"] = 1
    by_key = {s.key: s for s in APP_SETTINGS[plat]}
    body = app_body(plat, spec["app"]["name"], rule_order=rule_order,
                    forwarding_profile_id=int(spec["forwarding"]["id"]) if spec["forwarding"]["template"] == "existing" else 0)
    for k in spec["app"]["settings"]:
        by_key[k].apply(body, ctx)
    if spec["enable"]:
        body["active"] = "1"
    return fwd_body, body


# ---------------------------------------------------------------------------
# The Bulk changes plugins (admin_ops.register): build, and delete / Undo
# ---------------------------------------------------------------------------

BUILD = "zcc_profile_build"
DELETE = "zcc_profile_delete"
FAMILY = "zcc_profiles"
NOT_IN_SCOPE = "Not in scope: tick ZCC (Client Connector) on the Scope page, then try again. Nothing was read."
ROLLED_BACK = "rolled_back"


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """Client Connector profiles are read and changed only when ZCC is ticked on the Scope page."""
    return None if "zcc" in (scope.get("scopes") or []) else NOT_IN_SCOPE


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """What the forms pick from: the templates and every setting (no tenant
    read), and the profiles the tenant has (names, ids, state, links)."""
    inv = inventory(client, log=say, cancel=cancel)
    return {"catalog": catalog(), "inventory": inv, "errors": {f"zcc_{k}": v for k, v in inv["errors"].items()}}


def _call(fn: Callable[..., Any], *args: Any, op: str, kind: str, name: str, log: LogFn, kw: Optional[Dict[str, Any]] = None):
    """One SDK write through pack_ops.call (retries, rate pacing, Stop, the
    run's fatal refusals), ZCC's success "false" read as a refusal, and one
    object_write audit entry."""
    import pack_ops as ops

    def sdk_call(*a: Any, **k: Any) -> Any:
        ret = fn(*a, **k)
        if not isinstance(ret, tuple) or len(ret) < 3:
            return ret
        data, resp, err = ret[:3]
        if err:
            return ret
        why = _rejected(resp, data)
        if why:
            return (None, resp, why)
        body = _wire(resp)
        rid = _get(body, "id") if isinstance(body, dict) else None
        if rid is None:
            rid = _get(_plain(data), "id") if data is not None else None
        return ({"id": rid}, resp, None)

    out = ops.call(sdk_call, *args, op=op, kind=kind, name=name, log=log, kw=kw)
    ops._audit_write(op, kind, out.id if op == "create" else (args[0] if args else None), name, None, out)
    return out


def _fresh_id(v: Any) -> str:
    return "" if v in (None, "", "-1", -1, 0, "0") else str(v)


def _read_fail(run: Any, units: List[Dict[str, Any]], err: str, what: str) -> None:
    halt = ao._read_halt(err)
    if halt:
        run.halt = halt
        run.mark(units, "skipped", f"not attempted: {halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again right before the write: {err}"[:300])
        run.counts["failed"] += 1


# ── build ─────────────────────────────────────────────────────────────

def plan_build(client: Any, spec: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Preview a build: reads only. One item per setting (its value, the
    portal default and what it does; unticked settings are listed as
    excluded) and one per profile created; the forwarding profile is one
    write group, the app profile another that depends on it."""
    spec = dict(normalize_spec(spec), type=BUILD)
    plat = spec["platform"]
    plabel = PLATFORMS[plat]["label"]
    blockers: List[str] = []
    warnings: List[str] = []
    say("Reading the forwarding profiles…")
    fwds, ferr = read_forwarding(client, cancel)
    if ferr:
        blockers.append(f"The forwarding profiles could not be read ({ferr}), so the preview cannot check names or the link.")
    say(f"Reading the {plabel} app profiles…")
    apps, aerr = read_apps(client, plat, cancel)
    if aerr:
        blockers.append(f"The {plabel} app profiles could not be read ({aerr}), so the preview cannot check the name.")
    ctx: Dict[str, Any] = {"app_ids": [], "app_missing": []}
    by_key = {s.key: s for s in APP_SETTINGS[plat]}
    wanted = [a for k in spec["app"]["settings"] for a in by_key[k].apps]
    if wanted:
        say("Reading the IP-based application definitions the bypass names…")
        svcs, serr = read_app_services(client, cancel)
        if serr:
            blockers.append(f"The IP-based application definitions could not be read ({serr}); untick the bypass or try again.")
        found: Dict[str, str] = {}
        for s in svcs:
            n = str(_get(s, "appName") or _get(s, "name") or "").strip().lower()
            if n and _id(s):
                found.setdefault(n, _id(s))
        for a in wanted:
            hit = found.get(a.lower())
            if hit is None:
                ctx["app_missing"].append(a)
            else:
                ctx["app_ids"].append(int(hit) if hit.isdigit() else hit)
        if not serr and ctx["app_missing"]:
            warnings.append("Not in this tenant, so not bypassed: " + ", ".join(ctx["app_missing"]) + ".")
        if not serr and not ctx["app_ids"]:
            spec["app"]["settings"] = [k for k in spec["app"]["settings"] if k != "app_bypass"]
            warnings.append("None of the bypass applications exists in this tenant, so the bypass is left out.")
    app_name = spec["app"]["name"]
    if any(_name(a).strip().lower() == app_name.lower() for a in apps):
        blockers.append(f"An app profile named \"{app_name}\" already exists on {plabel}: choose another name.")
    create_fwd = spec["forwarding"]["template"] != "existing"
    if create_fwd:
        fwd_name, fwd_id = spec["forwarding"]["name"], ""
        if any(_name(f).strip().lower() == fwd_name.lower() for f in fwds):
            blockers.append(f"A forwarding profile named \"{fwd_name}\" already exists: choose another name, or link to it instead.")
    else:
        fwd_id = spec["forwarding"]["id"]
        hit = next((f for f in fwds if _id(f) == fwd_id), None)
        if hit is None and not ferr:
            blockers.append("The forwarding profile picked is not in the tenant any more: read the profiles again and pick another.")
        fwd_name = _name(hit) if hit else fwd_id
    rule_order = len(apps) + 1
    fwd_body, body = build_bodies(spec, rule_order=rule_order, ctx=ctx)
    state = "enabled" if spec["enable"] else "disabled"
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    fobj = {"type": "zcc_forwarding_profile", "name": fwd_name}
    if create_fwd:
        items.append(ao._unit("fwd", "g_fwd", "zcc_forwarding_profile", fobj, "exists", False, True, value=state,
                              reason=f"Created first, {state}: the app profile links to it."))
        chosen = set(spec["forwarding"]["settings"])
        for s in FWD_SETTINGS:
            on = s.key in chosen
            items.append(ao._unit(f"fwd:{s.key}", "g_fwd", "zcc_setting", fobj, s.label, s.portal_default, s.value if on else s.portal_default,
                                  status="change" if on else "excluded", reason=s.explain if on else "Unticked: stays at the portal default."))
        groups.append({"key": "g_fwd", "handler": "zcc_create_forwarding", "target": {"name": fwd_name, "body": fwd_body}})
    aobj = {"type": "zcc_app_profile", "name": app_name, "platform": plat}
    dep = ["fwd"] if create_fwd else []
    items.append(ao._unit("app", "g_app", "zcc_app_profile", aobj, "exists", False, True, value=state, depends_on=dep,
                          reason=f"{plabel} app profile, {state}, rule order {rule_order}, linked to the forwarding profile \"{fwd_name}\"."))
    chosen = set(spec["app"]["settings"])
    for s in APP_SETTINGS[plat]:
        on = s.key in chosen
        reason = s.explain if on else "Unticked: stays at the portal default."
        if s.key == "app_bypass" and ctx["app_missing"] and on:
            reason += " Not in this tenant, left out: " + ", ".join(ctx["app_missing"]) + "."
        items.append(ao._unit(f"app:{s.key}", "g_app", "zcc_setting", aobj, s.label, s.portal_default, s.value if on else s.portal_default,
                              status="change" if on else "excluded", reason=reason, depends_on=dep))
    groups.append({"key": "g_app", "handler": "zcc_create_app", "target": {
        "name": app_name, "platform": plat, "app_ids": list(ctx["app_ids"]), "enable": spec["enable"],
        "forwarding": {"create": create_fwd, "id": fwd_id, "name": fwd_name}, "body": body}})
    calls = []
    if create_fwd:
        c = API_CALLS["create_forwarding"]
        calls.append(f"Step {len(calls) + 1}: {c['method']} {c['path']} (SDK {c['sdk']}) creates the forwarding profile \"{fwd_name}\", {state}.")
    c = API_CALLS["create_app"]
    calls.append(f"Step {len(calls) + 1}: {c['method']} {c['path']} (SDK {c['sdk']}) creates the {plabel} app profile \"{app_name}\", "
                 f"{state}, linked to {'the id step 1 answers' if create_fwd else 'forwarding profile ' + fwd_id}.")
    if create_fwd:
        c = API_CALLS["delete_forwarding"]
        calls.append(f"Only if step 2 is refused: {c['method']} {c['path']} (SDK {c['sdk']}) deletes the new forwarding profile again, so "
                     "nothing half-built stays behind.")
    calls.append(f"Then both profiles are read back ({API_CALLS['list_forwarding']['sdk']}, {API_CALLS['list_app']['sdk']}) and every "
                 "setting is compared.")
    if spec["enable"]:
        warnings.append("The profiles are created enabled: devices that match the app profile's rule order get it as soon as it is "
                        "saved. Leave this off to review the profiles in the portal first.")
    plat_title = f"the {plabel} app profile \"{app_name}\""
    title = (f"Create the forwarding profile \"{fwd_name}\" and {plat_title} linked to it" if create_fwd else
             f"Create {plat_title}, linked to the forwarding profile \"{fwd_name}\"")
    return {"type": BUILD, "product": "zcc", "title": title, "spec": spec, "items": items, "groups": groups, "warnings": warnings,
            "blockers": blockers, "notes": calls + ["Each profile is checked again right before it is created; a name someone took "
                                                    "meanwhile stops it and nothing is overwritten."] + NOT_SET_HERE,
            "confirm_phrase": f"CREATE {app_name.upper()}", "assumed": list(ASSUMED)}


def _h_create_forwarding(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    import pack_ops as ops
    t = g["target"]
    rows, err = read_forwarding(run.client)
    if err:
        return _read_fail(run, units, err, "the forwarding profiles")
    if _find_by_name(rows, t["name"]):
        run.mark(units, "conflict", f"a forwarding profile named \"{t['name']}\" appeared since the preview; nothing was created")
        return
    out = _call(_zcc(run.client).forwarding_profile.update_forwarding_profile, op="create", kind="zcc_forwarding_profile", name=t["name"],
                log=run.log, kw=copy.deepcopy(t["body"]))
    fid = _fresh_id(out.id) if out.ok else ""
    if out.ok and not fid:
        rows, err = read_forwarding(run.client)
        hits = _find_by_name(rows, t["name"]) if not err else []
        fid = _id(hits[0]) if len(hits) == 1 else ""
        if not fid:
            out = ops.Outcome(False, error="the forwarding profile was accepted but its id could not be found, so nothing was linked to it; "
                                           f"check the Client Connector Portal for \"{t['name']}\"")
    if run.outcome(units, out, "create"):
        run.created.append({"type": "zcc_forwarding_profile", "id": fid, "name": t["name"]})
        for u in units:
            u["object"] = dict(u["object"], id=fid)
        run.log(f"[Client Connector] forwarding profile \"{t['name']}\": created (id {fid})")


def _rollback(run: Any, t: Dict[str, Any], why: str) -> None:
    """The app profile was not created: delete the forwarding profile this
    run created for it, and say so on its items."""
    if not t["forwarding"]["create"]:
        return
    made = next((c for c in run.created if c.get("type") == "zcc_forwarding_profile"), None)
    if not made or not made.get("id"):
        return
    run.log(f"[Client Connector] the app profile was not created ({why}); deleting the forwarding profile \"{made['name']}\" again…")
    out = _call(_zcc(run.client).forwarding_profile.delete_forwarding_profile, made["id"], op="delete", kind="zcc_forwarding_profile",
                name=made["name"], log=run.log)
    fwd_units = [u for u in run.p["items"] if u["group"] == "g_fwd" and u["status"] == "applied"]
    if out.ok:
        run.created.remove(made)
        run.counts["created"] = max(0, run.counts["created"] - 1)
        run.counts["deleted"] += 1
        run.mark(fwd_units, ROLLED_BACK, "created, then deleted again because the app profile was not created: nothing half-built stays")
        run.log(f"[Client Connector] forwarding profile \"{made['name']}\": deleted again")
    else:
        for u in fwd_units:
            u["reason"] = (f"created, but deleting it again after the app profile failed was refused ({out.error}): delete "
                           f"\"{made['name']}\" in the Client Connector Portal or with Undo")
        run.log(f"[Client Connector] forwarding profile \"{made['name']}\" could not be deleted again: {out.error}")


def _h_create_app(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    import pack_ops as ops
    t = g["target"]
    fwd = t["forwarding"]
    if fwd["create"]:
        fid = str((run.units.get("fwd") or {}).get("object", {}).get("id") or "")
    else:
        rows, err = read_forwarding(run.client)
        if err:
            return _read_fail(run, units, err, "the forwarding profiles")
        if not any(_id(r) == fwd["id"] for r in rows):
            run.mark(units, "conflict", "the forwarding profile it links to is gone since the preview; nothing was created")
            return
        fid = fwd["id"]
    rows, err = read_apps(run.client, t["platform"])
    if err:
        _read_fail(run, units, err, "the app profiles")
        return _rollback(run, t, "the app profiles could not be read again")
    if _find_by_name(rows, t["name"]):
        run.mark(units, "conflict", f"an app profile named \"{t['name']}\" appeared since the preview; nothing was created")
        return _rollback(run, t, "its name was taken meanwhile")
    body = copy.deepcopy(t["body"])
    body["forwardingProfileId"] = int(fid) if fid.isdigit() else fid
    out = _call(_zcc(run.client).web_policy.web_policy_edit, op="create", kind="zcc_app_profile", name=t["name"], log=run.log, kw=body)
    aid = _fresh_id(out.id) if out.ok else ""
    if out.ok and not aid:
        rows, err = read_apps(run.client, t["platform"])
        hits = _find_by_name(rows, t["name"]) if not err else []
        aid = _id(hits[0]) if len(hits) == 1 else ""
        if not aid:
            out = ops.Outcome(False, error="the app profile was accepted but could not be found by its name afterwards; check the "
                                           f"Client Connector Portal for \"{t['name']}\"")
    if run.outcome(units, out, "create"):
        run.created.append({"type": "zcc_app_profile", "id": aid, "name": t["name"], "platform": t["platform"]})
        for u in units:
            u["object"] = dict(u["object"], id=aid)
        run.log(f"[Client Connector] app profile \"{t['name']}\": created (id {aid})")
    else:
        _rollback(run, t, out.error or "refused")


def _setting_for(u: Dict[str, Any], plat: str) -> Optional[Setting]:
    side, _, key = u["key"].partition(":")
    pool = FWD_SETTINGS if side == "fwd" else APP_SETTINGS.get(plat, [])
    return next((s for s in pool if s.key == key), None)


def verify_build(run: Any) -> Dict[str, Any]:
    """Read both profiles back and compare every applied setting, the link
    and the state."""
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    if not applied:
        return out
    spec = run.p["spec"]
    plat = spec["platform"]
    gapp = next((g for g in run.p["groups"] if g["key"] == "g_app"), {"target": {}})
    ctx = {"app_ids": gapp["target"].get("app_ids") or []}
    frow = arow = None
    ferr = aerr = None
    if any(u["group"] == "g_fwd" for u in applied):
        rows, ferr = read_forwarding(run.client)
        fid = str((run.units.get("fwd") or {}).get("object", {}).get("id") or "")
        frow = next((r for r in rows if _id(r) == fid), None)
    if any(u["group"] == "g_app" for u in applied):
        rows, aerr = read_apps(run.client, plat)
        aid = str((run.units.get("app") or {}).get("object", {}).get("id") or "")
        arow = next((r for r in rows if aid and _id(r) == aid), None)
    for u in applied:
        row = frow if u["group"] == "g_fwd" else arow
        label = f"{u['object'].get('name')}: {u['field'] if u['kind'] == 'zcc_setting' else 'exists'}"
        if row is None:
            u["verified"] = None
        elif u["kind"] == "zcc_setting":
            s = _setting_for(u, plat)
            try:
                u["verified"] = s.verify(row, ctx) if s else None
            except Exception:  # noqa: BLE001 — a shape the check does not know is "could not be checked"
                u["verified"] = None
        elif u["kind"] == "zcc_app_profile":
            fwd = gapp["target"].get("forwarding") or {}
            fid = str((run.units.get("fwd") or {}).get("object", {}).get("id") or fwd.get("id") or "")
            u["verified"] = _ref(_get(row, "forwardingProfileId")) == fid and _active(row) == bool(spec.get("enable"))
        else:
            u["verified"] = True
        out["checked"] += 1
        if u["verified"] is True:
            out["confirmed"] += 1
        elif u["verified"] is False:
            out["mismatched"].append(label)
        else:
            out["unread"].append(label + (f" ({ferr or aerr})" if (ferr or aerr) else ""))
    return out


def inverse_build(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Undo of a build: delete what it created (the app profile first),
    previewed, confirmed with the typed name and guarded like any delete."""
    made = [u for u in result.get("items") or [] if u.get("status") == "applied" and u.get("field") == "exists"
            and u.get("kind") in ("zcc_app_profile", "zcc_forwarding_profile") and (u.get("object") or {}).get("id")]
    if not made:
        return None
    targets = []
    for u in sorted(made, key=lambda u: 0 if u["kind"] == "zcc_app_profile" else 1):
        o = u["object"]
        t = {"kind": "app" if u["kind"] == "zcc_app_profile" else "forwarding", "id": str(o["id"]), "name": o["name"]}
        if t["kind"] == "app":
            t["platform"] = o.get("platform") or result.get("spec", {}).get("platform")
        targets.append(t)
    return {"type": DELETE, "targets": targets}


# ── delete (and the Undo of a build) ─────────────────────────────────

def _target_check(t: Dict[str, Any], fwds: List[Dict[str, Any]], ferr: Optional[str], apps: Dict[str, List[Dict[str, Any]]],
                  aerr: Dict[str, str], deleting_apps: set) -> Tuple[str, str]:
    """(status, reason) of one profile to delete: change, noop (already
    gone) or blocked, with why."""
    if t["kind"] == "app":
        err = aerr.get(t["platform"])
        row = next((r for r in apps.get(t["platform"], []) if _id(r) == t["id"]), None)
        if err:
            return "blocked", f"the {t['platform']} app profiles could not be read ({err})"
        if row is None:
            return "noop", "already gone"
        if _name(row) != t["name"]:
            return "blocked", f"its name is now \"{_name(row)}\", not \"{t['name']}\""
        if _active(row):
            return "blocked", "it is enabled, so devices may use it: disable it in the Client Connector Portal first"
        return "change", ""
    row = next((r for r in fwds if _id(r) == t["id"]), None)
    if ferr:
        return "blocked", f"the forwarding profiles could not be read ({ferr})"
    if row is None:
        return "noop", "already gone"
    if _name(row) != t["name"]:
        return "blocked", f"its name is now \"{_name(row)}\", not \"{t['name']}\""
    if aerr:
        return "blocked", "the app profiles could not all be read, so it cannot be shown to be unused"
    users = [(p, _name(a)) for p, rs in apps.items() for a in rs
             if _ref(_get(a, "forwardingProfileId")) == t["id"] and _id(a) not in deleting_apps]
    if users:
        return "blocked", "it is in use by " + ", ".join(f"{n} ({p})" for p, n in users[:5]) + (" and more" if len(users) > 5 else "")
    return "change", ""


def plan_delete(client: Any, spec: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Preview a delete: reads only. Refused while a profile is in use (a
    forwarding profile an app profile on any platform links to, other than
    one deleted first in the same run; an app profile that is enabled). The
    typed confirmation is the first profile's name."""
    spec = dict(normalize_delete(spec), type=DELETE)
    say("Reading the forwarding profiles…")
    fwds, ferr = read_forwarding(client, cancel)
    say("Reading the app profiles on every platform (a forwarding profile in use is never deleted)…")
    apps, aerr = _app_rows_everywhere(client, cancel)
    deleting = {t["id"] for t in spec["targets"] if t["kind"] == "app"}
    items, groups, blockers = [], [], []
    app_key = None
    for i, t in enumerate(spec["targets"]):
        status, reason = _target_check(t, fwds, ferr, apps, aerr, deleting)
        kind = "zcc_app_profile" if t["kind"] == "app" else "zcc_forwarding_profile"
        obj = {"type": kind, "id": t["id"], "name": t["name"], **({"platform": t["platform"]} if t["kind"] == "app" else {})}
        dep = [app_key] if t["kind"] == "forwarding" and app_key else []
        items.append(ao._unit(f"t{i}", f"g{i}", kind, obj, "exists", True, False, status="excluded" if status == "blocked" else status,
                              reason=reason, depends_on=dep))
        if t["kind"] == "app":
            app_key = f"t{i}"
        if status == "blocked":
            blockers.append(f"\"{t['name']}\": {reason}.")
        groups.append({"key": f"g{i}", "handler": "zcc_delete_profile", "target": dict(t)})
    names = " and ".join(f"the {'app' if t['kind'] == 'app' else 'forwarding'} profile \"{t['name']}\"" for t in spec["targets"])
    notes = [f"{API_CALLS['delete_app' if t['kind'] == 'app' else 'delete_forwarding']['method']} "
             f"{API_CALLS['delete_app' if t['kind'] == 'app' else 'delete_forwarding']['path'].replace('{id}', t['id'])} "
             f"(SDK {API_CALLS['delete_app' if t['kind'] == 'app' else 'delete_forwarding']['sdk']}) deletes \"{t['name']}\"."
             for t in spec["targets"]]
    notes += ["Each profile is read again right before it is deleted; one that changed or came into use meanwhile is left alone.",
              "A deleted profile cannot be brought back from here: build it again if needed."]
    return {"type": DELETE, "product": "zcc", "title": f"Delete {names}", "spec": spec, "items": items, "groups": groups,
            "blockers": blockers, "warnings": [], "notes": notes, "confirm_phrase": spec["targets"][0]["name"].upper()}


def _h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fwds, ferr = ([], None)
    if t["kind"] == "forwarding":
        fwds, ferr = read_forwarding(run.client)
        apps, aerr = _app_rows_everywhere(run.client, None)
    else:
        rows, err = read_apps(run.client, t["platform"])
        apps, aerr = {t["platform"]: rows}, ({t["platform"]: err} if err else {})
    err = ferr or next(iter(aerr.values()), None)
    if err and ao._read_halt(err):
        return _read_fail(run, units, err, "the profiles")
    deleted_apps = {str(u["object"].get("id")) for u in run.p["items"] if u["kind"] == "zcc_app_profile" and u["status"] == "applied"}
    status, reason = _target_check(t, fwds, ferr, apps, aerr, deleted_apps)
    if status == "noop":
        run.mark(units, "noop", "already gone")
        return
    if status != "change":
        run.mark(units, "conflict", f"left alone: {reason} (it changed since the preview)")
        return
    label = "app" if t["kind"] == "app" else "forwarding"
    fn = _zcc(run.client).web_policy.delete_web_policy if t["kind"] == "app" else _zcc(run.client).forwarding_profile.delete_forwarding_profile
    out = _call(fn, t["id"], op="delete", kind=f"zcc_{label}_profile", name=t["name"], log=run.log)
    if run.outcome(units, out, "delete"):
        run.log(f"[Client Connector] {label} profile \"{t['name']}\": deleted")


def verify_delete(run: Any) -> Dict[str, Any]:
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    cache: Dict[str, Tuple[List[Dict[str, Any]], Optional[str]]] = {}
    for u in applied:
        o = u["object"]
        key = o.get("platform") or "forwarding"
        if key not in cache:
            cache[key] = read_apps(run.client, key) if o.get("platform") else read_forwarding(run.client)
        rows, err = cache[key]
        out["checked"] += 1
        if err:
            u["verified"] = None
            out["unread"].append(f"{o.get('name')}: {err}")
            continue
        u["verified"] = not any(_id(r) == str(o.get("id")) for r in rows)
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o.get('name')}: still listed")
    return out


def _app_rows_everywhere(sdk: Any, cancel) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    rows, errors = {}, {}
    for plat in ALL_DEVICE_TYPES:
        r, err = read_apps(sdk, plat, cancel)
        rows[plat] = r
        if err:
            errors[plat] = err
    return rows, errors


def _find_by_name(rows: List[Dict[str, Any]], name: str) -> List[Dict[str, Any]]:
    return [r for r in rows if _name(r).strip().lower() == name.strip().lower()]


def _rejected(resp: Any, data: Any) -> Optional[str]:
    """ZCC's HTTP 200 with success "false" (assumed), as a refusal."""
    for body in (_wire(resp), _plain(data) if data is not None else None):
        if isinstance(body, dict) and str(_get(body, "success")).strip().lower() == "false":
            msg = _get(body, "errorMessage") or _get(body, "message") or ""
            return "ZCC rejected the request (HTTP 200, success false)" + (f": {str(msg)[:200]}" if msg else "")
    return None


_HINT_BUILD = ("A forwarding profile and a Windows or macOS app profile from a best-practice or portal-default template, every setting with "
               "its portal default and what it does; created disabled, the app profile linked to the forwarding profile. Needs ZCC ticked.")
_HINT_DELETE = ("Delete an app or forwarding profile: you type its name, and a profile in use (an enabled app profile, or a forwarding "
                "profile an app profile links to) is refused. Needs ZCC ticked.")

ao.register(BUILD, family=FAMILY, product="zcc", label="Client Connector profiles", hint=_HINT_BUILD, in_scope=in_scope,
            plan=plan_build, read_objects=read_objects, handlers={"zcc_create_forwarding": _h_create_forwarding, "zcc_create_app": _h_create_app},
            verify=verify_build, inverse=inverse_build, script="ops_zcc.js")
ao.register(DELETE, family=FAMILY, product="zcc", label="Delete a Client Connector profile", hint=_HINT_DELETE, in_scope=in_scope,
            plan=plan_delete, read_objects=read_objects, handlers={"zcc_delete_profile": _h_delete}, verify=verify_delete,
            inverse=None, script="ops_zcc.js")


# ---------------------------------------------------------------------------
# Install command builder
# ---------------------------------------------------------------------------

def _cloud_names() -> List[str]:
    import zscaler_clouds
    return [k for k in zscaler_clouds.CLOUDS if k != "production"]


# (key, MSI property, EXE flag, macOS flag, type, label, help, secret)
_P = Tuple[str, Optional[str], Optional[str], Optional[str], str, str, str, bool]
INSTALL_PARAMS: List[_P] = [
    ("cloudName", "CLOUDNAME", "cloudName", "cloudName", "cloud", "Cloud name",
     "The Zscaler cloud without .net (for example zscalertwo). Needed with strict enforcement.", False),
    ("userDomain", "USERDOMAIN", "userDomain", "userDomain", "text", "User domain",
     "The company's sign-in domain, so users go straight to single sign-on instead of typing it.", False),
    ("policyToken", "POLICYTOKEN", "policyToken", "policyToken", "secret", "Policy token",
     "The app profile's token: the profile applies before the user enrolls. Read from the chosen app profile; masked unless you reveal it.", True),
    ("deviceToken", "DEVICETOKEN", "deviceToken", "deviceToken", "secret", "Device token",
     "Only when the Client Connector Portal is the identity provider (ZIA only). Masked unless you reveal it.", True),
    ("userName", "UNAME", "userName", "userName", "text", "User name",
     "The user to enroll, without the domain. Needs the user domain.", False),
    ("strictEnforcement", "STRICTENFORCEMENT", "strictEnforcement", "strictEnforcement", "toggle", "Strict enforcement",
     "Blocks internet access until the user enrolls. Needs the cloud name and the policy token.", False),
    ("enableAntiTampering", "ENABLEANTITAMPERING", "enableAntiTampering", None, "toggle", "Anti-tampering",
     "Stops users from stopping or changing the Zscaler services.", False),
    ("hideAppUIOnLaunch", "HIDEAPPUIONLAUNCH", "hideAppUIOnLaunch", "hideAppUIOnLaunch", "toggle", "Hide the window before enrollment",
     "Keeps the Client Connector window hidden until the user enrolls.", False),
    ("launchTray", "LAUNCHTRAY", "launchTray", "launchTray", "toggle_on", "Start Client Connector after install",
     "On by default; turn it off to install without starting the app.", False),
    ("externalRedirect", "EXTERNALREDIRECT", "externalRedirect", "externalRedirect", "toggle", "Sign in in the default browser",
     "Users authenticate in their own browser instead of the embedded window.", False),
    ("vdi", "VDI", "vdi", None, "toggle", "Virtual desktop install", "Marks the install as a virtual desktop (Citrix, Horizon, AVD).", False),
    ("uninstallPassword", "UNINSTALLPASSWORDCMDLINE", "uninstallPasswordCmdLine", None, "secret", "Uninstall password",
     "Allows a silent uninstall later; must match the app profile's uninstall password. Masked unless you reveal it.", True),
]
INSTALLER_TYPES = {"windows": ("msi", "exe"), "macos": ("app",)}
_SAFE_PATH = re.compile(r"^[A-Za-z0-9 ._()\-\\/:]{1,200}$")
# What an installer value may not hold (CWE-78): quotes, including the
# typographic ones PowerShell treats as quotes (U+2018-U+201F), cmd.exe's
# % ^ & | < >, PowerShell's ` and $, line breaks and NUL. Control, format
# and line/paragraph separator characters are refused by category.
_UNSAFE_VALUE = re.compile("[\"\r\n\x00%`$<>|&^\u2018-\u201f]")
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
# A value left unquoted on a Windows command line: nothing cmd.exe or PowerShell reads specially (; , ' @ # { } ( ) and
# spaces are quoted; * is left bare, as neither shell expands it for a program's argument, so the mask stays ********).
_BARE_ARG = re.compile(r"[A-Za-z0-9._*\-\\/:]+")
MASK = "********"


def install_catalog() -> Dict[str, Any]:
    return {"clouds": _cloud_names(), "installer_types": {k: list(v) for k, v in INSTALLER_TYPES.items()},
            "params": [{"key": k, "msi": m, "exe": e, "mac": mac, "type": t, "label": lbl, "help": h, "secret": s}
                       for k, m, e, mac, t, lbl, h, s in INSTALL_PARAMS]}


def _collect(platform: str, installer: str, values: Dict[str, Any]) -> Tuple[List[Tuple[str, str, bool]], List[str]]:
    """[(flag, value, secret)] in catalog order, and the problems."""
    out: List[Tuple[str, str, bool]] = []
    errors: List[str] = []
    for key, msi, exe, mac, typ, label, _h, secret in INSTALL_PARAMS:
        flag = mac if platform == "macos" else (msi if installer == "msi" else exe)
        if not flag:
            continue
        raw = values.get(key)
        if typ == "toggle":
            if raw is True or raw == "1":
                out.append((flag, "1", False))
            continue
        if typ == "toggle_on":
            if raw is False or raw == "0":
                out.append((flag, "0", False))
            continue
        if raw is not None and (isinstance(raw, bool) or not isinstance(raw, (str, int))):
            errors.append(f"{label}: give it as text.")
            continue
        val = "" if raw is None else str(raw).strip()
        if not val:
            continue
        if len(val) > 256 or _UNSAFE_VALUE.search(val) or any(unicodedata.category(ch) in _UNSAFE_CATEGORIES for ch in val):
            errors.append(f"{label}: quotes (also typographic ones), line breaks, control characters and the characters "
                          "% ` $ < > | & ^ cannot be passed to the installer.")
            continue
        if typ == "cloud":
            v = val.lower()
            if "." in v:
                errors.append(f"{label}: leave out .net (use {v.split('.')[0]}).")
                continue
            if v not in _cloud_names():
                errors.append(f"{label}: {val} is not a Zscaler cloud ({', '.join(_cloud_names())}).")
                continue
            val = v
        out.append((flag, val, secret))
    return out, errors


def _check_rules(platform: str, values: Dict[str, Any], params: List[Tuple[str, str, bool]]) -> Tuple[List[str], List[str]]:
    have = {f.lower(): v for f, v, _ in params}
    errors, warnings = [], []
    strict = have.get("strictenforcement") == "1"
    if strict and "cloudname" not in have:
        errors.append("Strict enforcement needs the cloud name.")
    if strict and "policytoken" not in have:
        errors.append("Strict enforcement needs the policy token (pick the app profile).")
    if ("uname" in have or "username" in have) and "userdomain" not in have:
        errors.append("The user name needs the user domain.")
    if "userdomain" not in have and "cloudname" not in have:
        warnings.append("Neither the user domain nor the cloud name is set: users see the full enrollment wizard.")
    return errors, warnings


def _win_quote(v: str) -> str:
    """A value for the cmd.exe or PowerShell command line: left bare only
    when every character is one neither shell gives a meaning to, else in
    double quotes (the values never hold a quote, % ` $ or a typographic
    quote PowerShell would close the string on; _collect refuses them)."""
    return v if _BARE_ARG.fullmatch(v) else f'"{v}"'


def _sh_quote(v: str) -> str:
    return "'" + v.replace("'", "'\\''") + "'"


def install_commands(platform: str, installer: str, values: Any, *, installer_name: str = "", reveal: bool = False,
                     now: Optional[datetime] = None) -> Dict[str, Any]:
    """The install command and a script for the platform. Every secret
    (tokens, passwords) is shown as ******** unless `reveal` is True; the
    answer says which values were masked. Nothing is logged or stored."""
    platform = str(platform or "").lower()
    if platform not in INSTALLER_TYPES:
        raise BuilderError("Pick the platform: Windows or macOS.")
    installer = str(installer or INSTALLER_TYPES[platform][0]).lower()
    if installer not in INSTALLER_TYPES[platform]:
        raise BuilderError(f"For {PLATFORMS[platform]['label']} the installer is " + " or ".join(x.upper() for x in INSTALLER_TYPES[platform]) + ".")
    values = values if isinstance(values, dict) else {}
    default_name = {"msi": "Zscaler-windows-installer-x64.msi", "exe": "Zscaler-windows-installer.exe", "app": "Zscaler-osx-installer.app"}[installer]
    name = str(installer_name or default_name).strip()
    if not _SAFE_PATH.match(name):
        raise BuilderError("The installer file name may use letters, digits, spaces and . _ ( ) - \\ / : only.")
    params, errors = _collect(platform, installer, values)
    rule_errors, warnings = _check_rules(platform, values, params)
    errors += rule_errors
    masked = [f for f, _v, s in params if s]

    def shown(v: str, secret: bool) -> str:
        return v if (reveal or not secret) else MASK

    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    if platform == "macos":
        exe = f"{name.rstrip('/')}/Contents/MacOS/installbuilder.sh"
        args = " ".join(f"--{f} {_sh_quote(shown(v, s))}" for f, v, s in params)
        command = f"sudo /bin/sh {_sh_quote(exe)} --mode unattended" + (f" {args}" if args else "")
        script = "\n".join([
            "#!/bin/bash",
            f"# Client Connector install for macOS, built {stamp}.",
            "# Put this file next to the installer app, then double-click it (or run: bash <this file>).",
            "# Values shown as ******** were masked: reveal them on the builder page before saving this script." if masked and not reveal else "#",
            "set -u",
            'cd "$(dirname "$0")"',
            f"APP={_sh_quote(name)}",
            '[ -e "$APP/Contents/MacOS/installbuilder.sh" ] || { echo "Installer not found: $APP"; exit 1; }',
            'echo "Installing Client Connector (you will be asked for an administrator password)..."',
            'sudo /bin/sh "$APP/Contents/MacOS/installbuilder.sh" --mode unattended' + (f" {args}" if args else ""),
            "RESULT=$?",
            'if [ $RESULT -eq 0 ]; then echo "Installed."; else echo "The installer ended with code $RESULT."; fi',
            'read -r -p "Press Enter to close" _',
            "exit $RESULT", ""])
        script_name = "install_client_connector.command"
    elif installer == "msi":
        args = " ".join(f"{f}={_win_quote(shown(v, s))}" for f, v, s in params)
        command = f"msiexec /i {_win_quote(name)} /qn /L*V \"%TEMP%\\ZCC_Install.log\"" + (f" {args}" if args else "")
        script_args = " ".join(f'{f}="{shown(v, s)}"' for f, v, s in params)
        script = "\r\n".join(_bat(stamp, name, 'msiexec /i "%INSTALLER%" /qn /L*V "%TEMP%\\ZCC_Install.log"'
                                    + (f" {script_args}" if script_args else ""), masked and not reveal)) + "\r\n"
        script_name = "install_client_connector.bat"
    else:
        args = " ".join(f"--{f} {_win_quote(shown(v, s))}" for f, v, s in params)
        command = f"{_win_quote(name)} --mode unattended --unattendedmodeui none" + (f" {args}" if args else "")
        script_args = " ".join(f'--{f} "{shown(v, s)}"' for f, v, s in params)
        script = "\r\n".join(_bat(stamp, name, '"%INSTALLER%" --mode unattended --unattendedmodeui none'
                                    + (f" {script_args}" if script_args else ""), masked and not reveal)) + "\r\n"
        script_name = "install_client_connector.bat"
    return {"platform": platform, "installer": installer, "installer_name": name, "command": command, "script": script,
            "script_name": script_name, "masked": masked if not reveal else [], "revealed": bool(reveal and masked),
            "errors": errors, "warnings": warnings, "parameters": [{"flag": f, "value": shown(v, s), "secret": s} for f, v, s in params]}


def _bat(stamp: str, name: str, run: str, masked: bool) -> List[str]:
    return [
        "@echo off",
        f"REM Client Connector install for Windows, built {stamp}.",
        "REM Put this file next to the installer and run it as administrator.",
        "REM Values shown as ******** were masked: reveal them on the builder page before saving this script." if masked else "REM",
        "net session >nul 2>&1",
        "if %errorlevel% neq 0 (echo Run this as administrator. & pause & exit /b 1)",
        f'set "INSTALLER=%~dp0{name}"',
        'if not exist "%INSTALLER%" (echo Installer not found: %INSTALLER% & pause & exit /b 1)',
        "echo Installing Client Connector...",
        run,
        "set RESULT=%errorlevel%",
        "if %RESULT% equ 0 (echo Installed.) else if %RESULT% equ 3010 (echo Installed: restart the computer.) else (echo The installer ended with code %RESULT%.)",
        "pause",
        "exit /b %RESULT%",
    ]


def policy_token(sdk: Any, profile_id: str) -> Tuple[Optional[str], Optional[str]]:
    """The app profile's policy token (SDK application_profiles.get_application_profile),
    or (None, why). Never logged."""
    if not re.fullmatch(r"\d{1,19}", str(profile_id or "")):
        return None, "Pick the app profile."
    try:
        ret = _zcc(sdk).application_profiles.get_application_profile(str(profile_id))
    except Exception as e:  # noqa: BLE001
        return None, f"The app profile could not be read ({type(e).__name__})."
    data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        return None, f"The app profile could not be read ({_err_text(err)[:120]})."
    for body in (_wire(resp), _plain(data)):
        tok = _get(body, "policyToken") if isinstance(body, dict) else None
        if tok:
            return str(tok), None
    return None, "This app profile has no policy token."
