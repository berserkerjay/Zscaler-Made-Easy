"""The sample tenant: a made-up company's Zscaler configuration, to try the
app without a tenant.

Larkspur Freight is fictitious (its domain is larkspur-freight.example,
reserved for examples by RFC 2606). Every object below is invented for
this app; nothing here was read from a real tenant. The data is shaped
like the Zscaler APIs answer it (camelCase JSON, as the raw-HTTP client
and the SDK's own response parsing see it), keyed by the OneAPI path the
two clients ask for, so every reader of the app works on it unchanged
(offline_tenant serves it).

What it covers, on purpose with the gaps an assessment should find:
  - DLP: predefined and custom dictionaries, predefined and custom engines,
    rules on every channel (Inline Web, Endpoint, SaaS, Email), one of them
    monitor-only, one disabled, a GenAI upload block, a notification
    template, an incident receiver;
  - ZIA: URL filtering, URL categories (one custom), SSL inspection with a
    broad do-not-decrypt exemption, Cloud Firewall (filtering, DNS, IPS),
    Cloud App Control per rule type, File Type Control, PAC files,
    locations, advanced settings, admins and roles;
  - Client Connector: app profiles per platform (one without strict
    enforcement and with a bypass), forwarding profiles (one leaves traffic
    direct on a trusted network), trusted networks, devices;
  - ZPA: application segments (one with a wildcard domain), segment,
    server and connector groups, App Connectors (one disconnected), an
    IdP, posture profiles, access and timeout policies;
  - ZDX: monitored applications, devices, departments, locations;
  - ZIdentity: users, groups, resource servers.

The fixtures in tests/ (test_data_flow.py, test_pack_channels.py) gave the
shapes; the values are new.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List

COMPANY = "Larkspur Freight"
DOMAIN = "larkspur-freight.example"
LABEL = "Sample tenant: Larkspur Freight"
# The ZPA customer id the sample's paths are built with (any alphanumeric id;
# offline_tenant replaces it by {customerId} before looking a path up).
CUSTOMER_ID = "72000000000000001"

ZIA = "/zia/api/v1"
ZCC = "/zcc/papi/public/v1"
ZPA1 = "/zpa/mgmtconfig/v1/admin/customers/{customerId}"
ZPA2 = "/zpa/mgmtconfig/v2/admin/customers/{customerId}"
ZDX = "/zdx/v1"
ZID = "/ziam/admin/api/v1"

# What the sample's URL lookup answers (POST /urlLookup), host → categories.
URL_LOOKUP: Dict[str, List[str]] = {
    "chat.openai.com": ["AI_ML_APPS"], "chatgpt.com": ["AI_ML_APPS"], "gemini.google.com": ["AI_ML_APPS"],
    "www.dropbox.com": ["FILE_HOST"], "dropbox.com": ["FILE_HOST"], "wetransfer.com": ["FILE_HOST"],
    "drive.google.com": ["ONLINE_STORAGE"], "www.box.com": ["ONLINE_STORAGE"], "app.box.com": ["ONLINE_STORAGE"],
    "mail.google.com": ["WEB_MAIL"], "outlook.office.com": ["WEB_MAIL"],
    "www.bank.example": ["FINANCE"], "online-casino.example": ["GAMBLING"],
    "portal.harborline-logistics.example": ["CUSTOM_01"], "github.com": ["PROFESSIONAL_SERVICES"],
    "pastebin.com": ["OTHER_MISCELLANEOUS"], "example.com": ["OTHER_MISCELLANEOUS"],
}


def _ref(i: int, name: str) -> Dict[str, Any]:
    return {"id": i, "name": name}


def _zpa(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"totalPages": "1", "totalCount": str(len(items)), "list": items}


# ── DLP ───────────────────────────────────────────────────────────────
DICTIONARIES = [
    {"id": 1, "name": "Social Security Numbers (US)", "description": "Predefined: US Social Security numbers.", "custom": False,
     "dictionaryType": "PATTERNS_AND_PHRASES", "nameL10nTag": True, "predefinedClone": False, "confidenceThreshold": "CONFIDENCE_LEVEL_HIGH",
     "thresholdType": "VIOLATION_COUNT_ONLY", "phrases": [], "patterns": [], "predefinedPhrases": [], "includeSsnNumbers": True},
    {"id": 2, "name": "Credit Cards", "description": "Predefined: payment card numbers that pass the Luhn check.", "custom": False,
     "dictionaryType": "PATTERNS_AND_PHRASES", "nameL10nTag": True, "confidenceThreshold": "CONFIDENCE_LEVEL_HIGH", "includeBinNumbers": True,
     "thresholdType": "VIOLATION_COUNT_ONLY", "phrases": [], "patterns": []},
    {"id": 3, "name": "ABA Bank Routing Numbers", "description": "Predefined: US bank routing numbers.", "custom": False,
     "dictionaryType": "PATTERNS_AND_PHRASES", "nameL10nTag": True, "confidenceThreshold": "CONFIDENCE_LEVEL_MEDIUM", "phrases": [], "patterns": []},
    {"id": 4, "name": "Medical Information", "description": "Predefined: diagnoses, treatments and medical terms.", "custom": False,
     "dictionaryType": "PATTERNS_AND_PHRASES", "nameL10nTag": True, "confidenceThreshold": "CONFIDENCE_LEVEL_MEDIUM", "phrases": [], "patterns": []},
    {"id": 1001, "name": "Larkspur Shipment Manifests", "description": "Phrases on Larkspur's shipping manifests and bills of lading.",
     "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES", "confidenceThreshold": "CONFIDENCE_LEVEL_MEDIUM",
     "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "bill of lading"}, {"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "consignee manifest"},
                 {"action": "PHRASE_COUNT_TYPE_UNIQUE", "phrase": "larkspur confidential"}],
     "patterns": [{"action": "PATTERN_COUNT_TYPE_UNIQUE", "pattern": "LKF-[0-9]{8}"}], "proximity": 0},
    {"id": 1002, "name": "Larkspur Customer Account Numbers", "description": "Customer account numbers (LC- followed by ten digits).",
     "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES", "confidenceThreshold": "CONFIDENCE_LEVEL_HIGH",
     "phrases": [], "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "LC-[0-9]{10}"}], "proximity": 0},
    {"id": 1003, "name": "Larkspur Source Code Markers", "description": "Copyright headers in Larkspur's own code.",
     "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES", "confidenceThreshold": "CONFIDENCE_LEVEL_LOW",
     "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "copyright larkspur freight"}], "patterns": [], "proximity": 0},
]

ENGINES = [
    {"id": 60, "name": "PCI", "predefinedEngineName": "PCI", "description": "Predefined: payment card data.", "customDlpEngine": False,
     "engineExpression": "((D2.S > 0))"},
    {"id": 61, "name": "HIPAA", "predefinedEngineName": "HIPAA", "description": "Predefined: protected health information.", "customDlpEngine": False,
     "engineExpression": "((D1.S > 0) AND (D4.S > 0))"},
    {"id": 62, "name": "GLBA", "predefinedEngineName": "GLBA", "description": "Predefined: financial customer data.", "customDlpEngine": False,
     "engineExpression": "((D1.S > 0) AND (D3.S > 0))"},
    {"id": 70, "name": "Larkspur Customer Data", "description": "Customer account numbers in bulk, or with a payment card.",
     "customDlpEngine": True, "engineExpression": "((D1002.S > 4) OR ((D1002.S > 0) AND (D2.S > 0)))"},
    {"id": 71, "name": "Larkspur Shipping Documents", "description": "Manifests and bills of lading.",
     "customDlpEngine": True, "engineExpression": "((D1001.S > 1))"},
    {"id": 72, "name": "Larkspur Source Code", "description": "Larkspur's own source code (copyright headers).",
     "customDlpEngine": True, "engineExpression": "((D1003.S > 0))"},
]

NOTIFICATION_TEMPLATES = [
    {"id": 9, "name": "Larkspur DLP notice", "subject": "A file you sent was held for review", "attachContent": False,
     "tlsEnabled": True, "plainTextMessage": "Your upload matched a data protection rule. Contact the service desk.",
     "htmlMessage": "<p>Your upload matched a data protection rule. Contact the service desk.</p>"},
]
INCIDENT_RECEIVERS = [{"id": 3, "name": "Larkspur incident receiver", "url": "https://dlp-receiver.larkspur-freight.example", "status": "ENABLED"}]
ICAP_SERVERS: List[Dict[str, Any]] = []

WEB_DLP_RULES = [
    {"id": 101, "order": 1, "rank": 7, "name": "Block card data to GenAI", "description": "Payment card data never goes to AI apps.",
     "state": "ENABLED", "action": "BLOCK", "protocols": ["ANY_RULE"], "dlpEngines": [_ref(60, "PCI")], "cloudApplications": ["CHATGPT_AI", "GOOGLE_GEMINI"],
     "fileTypes": [], "severity": "RULE_SEVERITY_HIGH", "zscalerIncidentReceiver": True, "notificationTemplate": _ref(9, "Larkspur DLP notice"),
     "withoutContentInspection": False, "matchOnly": False, "minSize": 0, "zccNotificationsEnabled": True},
    {"id": 102, "order": 2, "rank": 7, "name": "Customer data - monitor", "description": "Watch customer account numbers before blocking.",
     "state": "ENABLED", "action": "ALLOW", "protocols": ["ANY_RULE"], "dlpEngines": [_ref(70, "Larkspur Customer Data")],
     "fileTypes": [], "severity": "RULE_SEVERITY_MEDIUM", "zscalerIncidentReceiver": True, "withoutContentInspection": False, "matchOnly": False},
    {"id": 103, "order": 3, "rank": 7, "name": "Shipping documents to file shares", "description": "Manifests uploaded to file sharing sites.",
     "state": "ENABLED", "action": "ALLOW", "protocols": ["HTTPS_RULE", "HTTP_RULE"], "dlpEngines": [_ref(71, "Larkspur Shipping Documents")],
     "urlCategories": [{"id": "FILE_HOST"}, {"id": "ONLINE_STORAGE"}], "fileTypes": [], "severity": "RULE_SEVERITY_LOW", "zscalerIncidentReceiver": False,
     "withoutContentInspection": False, "matchOnly": False},
    {"id": 104, "order": 4, "rank": 7, "name": "Health data - block (draft)", "description": "Draft rule, never switched on.",
     "state": "DISABLED", "action": "BLOCK", "protocols": ["ANY_RULE"], "dlpEngines": [_ref(61, "HIPAA")], "fileTypes": [],
     "severity": "RULE_SEVERITY_HIGH", "zscalerIncidentReceiver": True, "withoutContentInspection": False, "matchOnly": False},
    {"id": 105, "order": 5, "rank": 7, "name": "Source code to the web", "description": "Larkspur source code leaving through any site.",
     "state": "ENABLED", "action": "BLOCK", "protocols": ["ANY_RULE"], "dlpEngines": [_ref(72, "Larkspur Source Code")], "fileTypes": [],
     "severity": "RULE_SEVERITY_HIGH", "zscalerIncidentReceiver": True, "withoutContentInspection": False, "matchOnly": False},
]

ENDPOINT_DLP_RULES = [
    {"id": 201, "order": 1, "rank": 7, "name": "Customer data to USB - monitor", "state": "ENABLED", "action": "ALLOW",
     "dlpEngines": [_ref(70, "Larkspur Customer Data")], "severity": "RULE_SEVERITY_MEDIUM", "zscalerIncidentReceiver": True,
     "endpointDlpDestinations": ["REMOVABLE_MEDIA"], "fileTypes": []},
    {"id": 202, "order": 2, "rank": 7, "name": "Card data to printers", "state": "DISABLED", "action": "BLOCK",
     "dlpEngines": [_ref(60, "PCI")], "severity": "RULE_SEVERITY_HIGH", "zscalerIncidentReceiver": True,
     "endpointDlpDestinations": ["PRINTER"], "fileTypes": []},
]

EMAIL_DLP_RULES = [
    {"id": 301, "order": 1, "rank": 7, "name": "Card data in outbound mail", "state": "ENABLED", "action": "BLOCK",
     "dlpEngines": [_ref(60, "PCI")], "severity": "RULE_SEVERITY_HIGH", "zscalerIncidentReceiver": True},
]

CASB_TENANTS = [
    {"tenantId": 501, "tenantName": "Larkspur Box", "saasApplication": "BOX", "status": ["ACTIVE"], "enterpriseTenantId": "lkf-box"},
    {"tenantId": 502, "tenantName": "Larkspur Google Workspace", "saasApplication": "GOOGLE_DRIVE", "status": ["ACTIVE"], "enterpriseTenantId": "lkf-gws"},
    {"tenantId": 503, "tenantName": "Larkspur Microsoft 365 Mail", "saasApplication": "OFFICE_365", "status": ["ACTIVE"], "enterpriseTenantId": "lkf-m365"},
]
SAAS_DLP_RULES = [
    {"id": 401, "order": 1, "rank": 7, "name": "Shared files with customer data", "type": "OFLCASB_DLP_FILE", "state": "ENABLED",
     "action": "OFLCASB_DLP_REPORT_INCIDENT", "dlpEngines": [_ref(70, "Larkspur Customer Data")], "severity": "RULE_SEVERITY_MEDIUM",
     "bucketOwner": "", "collaborationScope": ["ANY"], "cloudAppTenants": [{"id": 501, "name": "Larkspur Box"}, {"id": 502, "name": "Larkspur Google Workspace"}]},
    {"id": 402, "order": 1, "rank": 7, "name": "Mailbox scan for card data", "type": "OFLCASB_DLP_EMAIL", "state": "ENABLED",
     "action": "OFLCASB_DLP_REPORT_INCIDENT", "dlpEngines": [_ref(60, "PCI")], "severity": "RULE_SEVERITY_HIGH",
     "cloudAppTenants": [{"id": 503, "name": "Larkspur Microsoft 365 Mail"}]},
]

# ── ZIA policy ────────────────────────────────────────────────────────
URL_CATEGORIES = [
    {"id": "AI_ML_APPS", "configuredName": "AI and ML Applications", "superCategory": "INFORMATION_TECHNOLOGY", "customCategory": False, "urls": [], "dbCategorizedUrls": []},
    {"id": "FILE_HOST", "configuredName": "File Host", "superCategory": "INFORMATION_TECHNOLOGY", "customCategory": False, "urls": [], "dbCategorizedUrls": []},
    {"id": "ONLINE_STORAGE", "configuredName": "Online Storage", "superCategory": "INFORMATION_TECHNOLOGY", "customCategory": False, "urls": [], "dbCategorizedUrls": []},
    {"id": "WEB_MAIL", "configuredName": "Web Mail", "superCategory": "INTERNET_COMMUNICATION", "customCategory": False, "urls": [], "dbCategorizedUrls": []},
    {"id": "FINANCE", "configuredName": "Finance", "superCategory": "BUSINESS_AND_ECONOMY", "customCategory": False, "urls": [], "dbCategorizedUrls": []},
    {"id": "GAMBLING", "configuredName": "Gambling", "superCategory": "GAMBLING", "customCategory": False, "urls": [], "dbCategorizedUrls": []},
    {"id": "CUSTOM_01", "configuredName": "Larkspur partner portals", "superCategory": "USER_DEFINED", "customCategory": True,
     "urls": ["portal.harborline-logistics.example", ".partners.larkspur-freight.example"], "dbCategorizedUrls": [], "description": "Carrier and broker portals."},
]
URL_FILTERING_RULES = [
    {"id": 601, "order": 1, "rank": 7, "name": "Block gambling", "state": "ENABLED", "action": "BLOCK", "urlCategories": ["GAMBLING"],
     "protocols": ["ANY_RULE"], "requestMethods": [], "blockOverride": False},
    {"id": 602, "order": 2, "rank": 7, "name": "Caution on personal file hosts", "state": "ENABLED", "action": "CAUTION",
     "urlCategories": ["FILE_HOST"], "protocols": ["ANY_RULE"], "requestMethods": []},
    {"id": 603, "order": 3, "rank": 7, "name": "Allow partner portals", "state": "ENABLED", "action": "ALLOW", "urlCategories": ["CUSTOM_01"],
     "protocols": ["ANY_RULE"], "requestMethods": []},
]
SSL_RULES = [
    {"id": 701, "order": 1, "rank": 7, "name": "Zscaler Recommended Exemptions", "state": "ENABLED", "predefined": True, "defaultRule": False,
     "action": {"type": "DO_NOT_DECRYPT", "doNotDecryptSubActions": {"bypassOtherPolicies": False}}, "urlCategories": ["FINANCE"]},
    {"id": 702, "order": 2, "rank": 7, "name": "Do not decrypt webmail", "state": "ENABLED",
     "action": {"type": "DO_NOT_DECRYPT", "doNotDecryptSubActions": {"bypassOtherPolicies": True}}, "urlCategories": ["WEB_MAIL"]},
    {"id": 703, "order": 3, "rank": 7, "name": "Decrypt everything else", "state": "ENABLED", "defaultRule": True,
     "action": {"type": "DECRYPT", "decryptSubActions": {"serverCertificates": "BLOCK", "ocspCheck": True, "minClientTLSVersion": "CLIENT_TLS_1_2",
                                                     "minServerTLSVersion": "SERVER_TLS_1_2"}},
     "urlCategories": ["ANY"]},
]
FIREWALL_RULES = [
    {"id": 801, "order": 1, "rank": 7, "name": "Block QUIC to force inspection", "state": "ENABLED", "action": "BLOCK_DROP",
     "nwServices": [_ref(41, "QUIC")], "destCountries": []},
    {"id": 802, "order": 2, "rank": 7, "name": "Allow office traffic", "state": "ENABLED", "action": "ALLOW", "nwServices": [], "destCountries": []},
    {"id": 803, "order": 127, "rank": 7, "name": "Default Firewall Filtering Rule", "state": "ENABLED", "action": "ALLOW", "defaultRule": True,
     "predefined": True},
]
FIREWALL_DNS_RULES = [{"id": 811, "order": 1, "rank": 7, "name": "Block DNS tunnels", "state": "ENABLED", "action": "BLOCK",
                       "applications": ["DNS_TUNNELS"]}]
FIREWALL_IPS_RULES = [{"id": 821, "order": 1, "rank": 7, "name": "Default IPS rule", "state": "ENABLED", "action": "ALLOW",
                       "defaultRule": True, "threatCategories": []}]
NETWORK_SERVICES = [{"id": 41, "name": "QUIC", "type": "PREDEFINED", "destUdpPorts": [{"start": 443, "end": 443}]}]
CAC_RULES = {
    "AI_ML": [{"id": 901, "order": 1, "rank": 7, "name": "GenAI: allow use, block uploads", "state": "ENABLED", "type": "AI_ML",
               "applications": ["CHATGPT_AI", "GOOGLE_GEMINI"], "actions": ["ALLOW_AI_ML_WEB_USE", "BLOCK_AI_ML_UPLOAD"]}],
    "FILE_SHARE": [{"id": 902, "order": 1, "rank": 7, "name": "File sharing: allow all", "state": "ENABLED", "type": "FILE_SHARE",
                    "applications": ["DROPBOX", "WETRANSFER"], "actions": ["ALLOW_FILE_SHARE_VIEW", "ALLOW_FILE_SHARE_UPLOAD"]}],
    "WEBMAIL": [{"id": 903, "order": 1, "rank": 7, "name": "Personal webmail: no attachments", "state": "ENABLED", "type": "WEBMAIL",
                 "applications": ["GMAIL"], "actions": ["ALLOW_WEBMAIL_VIEW", "BLOCK_WEBMAIL_ATTACHMENT_SEND"]}],
}
FILE_TYPE_RULES = [
    {"id": 951, "order": 1, "rank": 7, "name": "Block archives to file shares", "state": "ENABLED", "filteringAction": "BLOCK",
     "operation": "UPLOAD", "fileTypes": ["FTCATEGORY_ZIP", "FTCATEGORY_RAR"], "cloudAppClasses": ["FILE_SHARE"], "protocols": ["ANY_RULE"]},
]
PAC_CONTENT = ('function FindProxyForURL(url, host) {\n'
               '  if (isPlainHostName(host) || dnsDomainIs(host, ".larkspur-freight.example")) { return "DIRECT"; }\n'
               '  if (shExpMatch(host, "*.harborline-logistics.example")) { return "DIRECT"; }\n'
               '  return "PROXY ${GATEWAY_FX}:80; PROXY ${SECONDARY_GATEWAY_FX}:80; DIRECT";\n}\n')
PAC_FILES = [{"id": 31, "name": "larkspur.pac", "domain": DOMAIN, "pacUrl": "https://pac.zscaler.net/larkspur/larkspur.pac",
              "pacContent": PAC_CONTENT, "pacVersionStatus": "DEPLOYED", "pacVersion": 3, "editable": True}]
LOCATIONS = [
    {"id": 1101, "name": "Larkspur HQ (Portland)", "country": "UNITED_STATES", "tz": "UNITED_STATES_AMERICA_LOS_ANGELES",
     "sslScanEnabled": True, "authRequired": True, "xffForwardEnabled": True, "surrogateIP": True, "ofwEnabled": True, "ipsControl": True,
     "aupEnabled": False, "cautionEnabled": False, "ipAddresses": ["198.51.100.10"], "profile": "CORPORATE"},
    {"id": 1102, "name": "Larkspur Depot (Reno)", "country": "UNITED_STATES", "tz": "UNITED_STATES_AMERICA_LOS_ANGELES",
     "sslScanEnabled": False, "authRequired": False, "xffForwardEnabled": False, "surrogateIP": False, "ofwEnabled": True, "ipsControl": False,
     "ipAddresses": ["203.0.113.20"], "profile": "SERVER"},
]
ADVANCED_SETTINGS = {"enableDnsResolutionOnTransparentProxy": False, "enableOffice365": True, "logInternalIp": True,
                     "enforceSurrogateIpForWindowsApp": True, "trackHttpTunnelOnHttpPorts": True, "blockHttpTunnelOnNonHttpPorts": True,
                     "blockDomainFrontingOnHostHeader": True, "zscalerClientConnector1AndPacRoadWarriorInFirewall": True,
                     "cascadeUrlFiltering": True, "enablePolicyForUnauthenticatedTraffic": False, "dlpEvaluateAllRules": False}
AUTH_SETTINGS = {"orgAuthType": "SAFECHANNEL_DIR", "oneTimeAuth": "OTP_DISABLED", "samlEnabled": True, "kerberosEnabled": False,
                 "authFrequency": "DAILY_COOKIE", "autoProvision": True, "directorySyncMigrateToScimEnabled": True}
ADMIN_ROLES = [{"id": 1, "name": "Super Admin", "rank": 7, "roleType": "ORG_ADMIN", "policyAccess": "READ_WRITE"},
               {"id": 2, "name": "DLP Auditor", "rank": 7, "roleType": "ORG_ADMIN", "policyAccess": "READ_ONLY"}]
ADMIN_USERS = [{"id": 11, "loginName": "it-admin@larkspur-freight.example", "userName": "IT Admin", "email": "it-admin@larkspur-freight.example",
                "role": _ref(1, "Super Admin"), "adminScopeType": "ORGANIZATION", "isPasswordLoginAllowed": False, "disabled": False},
               {"id": 12, "loginName": "auditor@larkspur-freight.example", "userName": "DLP Auditor", "email": "auditor@larkspur-freight.example",
                "role": _ref(2, "DLP Auditor"), "adminScopeType": "ORGANIZATION", "isPasswordLoginAllowed": True, "disabled": False}]
DEPARTMENTS = [_ref(21, "Operations"), _ref(22, "Finance"), _ref(23, "Engineering"), _ref(24, "Customer Service")]
GROUPS = [_ref(31, "All Staff"), _ref(32, "Drivers"), _ref(33, "Finance Team"), _ref(34, "Developers")]
USERS = [{"id": 41, "name": "Avery Quinn", "email": "avery.quinn@larkspur-freight.example", "department": _ref(22, "Finance"), "groups": [_ref(33, "Finance Team")]},
         {"id": 42, "name": "Rowan Ellis", "email": "rowan.ellis@larkspur-freight.example", "department": _ref(23, "Engineering"), "groups": [_ref(34, "Developers")]},
         {"id": 43, "name": "Jordan Blake", "email": "jordan.blake@larkspur-freight.example", "department": _ref(21, "Operations"), "groups": [_ref(32, "Drivers")]}]
RULE_LABELS = [{"id": 51, "name": "Data protection", "description": "Rules owned by the data protection team."}]
NSS_FEEDS = [{"id": 61, "name": "Web logs to SIEM", "feedStatus": "ENABLED", "nssLogType": "WEBLOG"}]
ISOLATION_PROFILES = [{"id": "iso-1", "name": "Larkspur isolation", "url": "https://isolation.example/larkspur", "defaultProfile": True}]

# ── Client Connector ──────────────────────────────────────────────────
APP_PROFILES = [
    {"id": 1201, "name": "Windows - Corporate", "deviceType": 3, "active": 1, "ruleOrder": 1, "forwardingProfileId": 1301,
     "strictEnforcement": 1, "installEndpointDlp": 1, "sslCertInstall": 1, "disableLoopBackRestriction": 0, "logLevel": 0,
     "hostnameBypassForIpv4": [".larkspur-freight.example"], "ipExclusions": ["10.0.0.0/8"], "groups": [], "users": []},
    {"id": 1202, "name": "macOS - Corporate", "deviceType": 4, "active": 1, "ruleOrder": 1, "forwardingProfileId": 1301,
     "strictEnforcement": 1, "installEndpointDlp": 0, "sslCertInstall": 1, "groups": [], "users": []},
    {"id": 1203, "name": "Windows - Contractors", "deviceType": 3, "active": 1, "ruleOrder": 2, "forwardingProfileId": 1302,
     "strictEnforcement": 0, "installEndpointDlp": 0, "sslCertInstall": 1, "hostnameBypassForIpv4": ["*.dropbox.com"],
     "appBypassCustom": [{"name": "Freight tracker", "path": "tracker.exe"}], "groups": [_ref(32, "Drivers")], "users": []},
    {"id": 1204, "name": "iOS - Drivers", "deviceType": 1, "active": 1, "ruleOrder": 1, "forwardingProfileId": 1301,
     "strictEnforcement": 0, "sslCertInstall": 1, "groups": [_ref(32, "Drivers")], "users": []},
]
FORWARDING_PROFILES = [
    {"id": 1301, "name": "Corporate tunnel", "active": "1", "trustedNetworkIds": [1401], "forwardingProfileActions": [
        {"networkType": "ON_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2", "tunnelType": "ZSCALER_TUNNEL_2"},
        {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2", "tunnelType": "ZSCALER_TUNNEL_2"},
        {"networkType": "VPN_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2", "tunnelType": "ZSCALER_TUNNEL_2"}]},
    {"id": 1302, "name": "Contractor - direct at the depot", "active": "1", "trustedNetworkIds": [1402], "forwardingProfileActions": [
        {"networkType": "ON_TRUSTED_NETWORK", "actionType": "NONE", "tunnelType": "NONE"},
        {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ENFORCE_PROXY", "tunnelType": "ENFORCE_PROXY",
         "customPac": "https://pac.zscaler.net/larkspur/larkspur.pac"}]},
]
TRUSTED_NETWORKS = [{"id": 1401, "networkName": "Larkspur HQ", "name": "Larkspur HQ", "dnsServers": ["10.10.0.53"], "dnsSearchDomains": [DOMAIN], "active": True},
                    {"id": 1402, "networkName": "Reno depot", "name": "Reno depot", "dnsServers": ["10.20.0.53"], "active": True}]
DEVICES = [
    {"udid": "LKF-WIN-0001", "machineHostname": "LKF-LT-0001", "user": "avery.quinn@larkspur-freight.example", "type": 3, "osVersion": "Windows 11",
     "agentVersion": "4.5.0.334", "registrationState": "Registered", "companyName": COMPANY, "policyName": "Windows - Corporate", "zappArch": "x64",
     "lastSeenTime": "2026-10-27 18:05:11", "tunnelVersion": "Z-Tunnel 2.0"},
    {"udid": "LKF-MAC-0002", "machineHostname": "LKF-MBP-0002", "user": "rowan.ellis@larkspur-freight.example", "type": 4, "osVersion": "macOS 15.1",
     "agentVersion": "4.4.0.208", "registrationState": "Registered", "companyName": COMPANY, "policyName": "macOS - Corporate", "lastSeenTime": "2026-10-28 08:40:02",
     "tunnelVersion": "Z-Tunnel 2.0"},
    {"udid": "LKF-WIN-0003", "machineHostname": "LKF-CT-0003", "user": "jordan.blake@larkspur-freight.example", "type": 3, "osVersion": "Windows 10",
     "agentVersion": "4.2.0.198", "registrationState": "Registered", "companyName": COMPANY, "policyName": "Windows - Contractors", "lastSeenTime": "2026-10-20 07:12:44",
     "tunnelVersion": "Z-Tunnel 1.0"},
]
FAIL_OPEN = [{"id": 1, "enableFailOpen": 1, "enableCaptivePortalDetection": 1, "captivePortalWebSecDisableMinutes": 10,
              "enableStrictEnforcementPrompt": 0, "tunnelFailureRetryCount": 25}]
COMPANY_INFO = {"orgName": COMPANY, "companyId": "lkf-001", "zdxEnabled": True, "zpaEnabled": True}

# ── ZPA ───────────────────────────────────────────────────────────────
SEGMENT_GROUPS = [{"id": "2101", "name": "Finance apps", "enabled": True, "applications": [{"id": "2201", "name": "Freight billing"}]},
                  {"id": "2102", "name": "All internal (broad)", "enabled": True, "applications": [{"id": "2202", "name": "Everything internal"}]}]
SERVER_GROUPS = [{"id": "2301", "name": "Portland data centre", "enabled": True, "dynamicDiscovery": True,
                  "appConnectorGroups": [{"id": "2401", "name": "Portland connectors"}], "applications": [{"id": "2201", "name": "Freight billing"}]},
                 {"id": "2302", "name": "Reno depot servers", "enabled": True, "dynamicDiscovery": True,
                  "appConnectorGroups": [{"id": "2402", "name": "Reno connectors"}], "applications": [{"id": "2202", "name": "Everything internal"}]}]
CONNECTOR_GROUPS = [{"id": "2401", "name": "Portland connectors", "enabled": True, "location": "Portland, OR", "upgradeDay": "SUNDAY",
                     "versionProfileName": "Default", "connectors": [{"id": "2501", "name": "pdx-conn-1"}, {"id": "2502", "name": "pdx-conn-2"}]},
                    {"id": "2402", "name": "Reno connectors", "enabled": True, "location": "Reno, NV", "upgradeDay": "SUNDAY",
                     "versionProfileName": "Default", "connectors": [{"id": "2503", "name": "rno-conn-1"}]}]
CONNECTORS = [
    {"id": "2501", "name": "pdx-conn-1", "enabled": True, "appConnectorGroupId": "2401", "appConnectorGroupName": "Portland connectors",
     "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED", "currentVersion": "24.302.1", "expectedVersion": "24.302.1", "upgradeStatus": "COMPLETE"},
    {"id": "2502", "name": "pdx-conn-2", "enabled": True, "appConnectorGroupId": "2401", "appConnectorGroupName": "Portland connectors",
     "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED", "currentVersion": "24.302.1", "expectedVersion": "24.302.1", "upgradeStatus": "COMPLETE"},
    {"id": "2503", "name": "rno-conn-1", "enabled": True, "appConnectorGroupId": "2402", "appConnectorGroupName": "Reno connectors",
     "controlChannelStatus": "ZPN_STATUS_DISCONNECTED", "currentVersion": "23.120.4", "expectedVersion": "24.302.1", "upgradeStatus": "FAILED"},
]
SEGMENTS = [
    {"id": "2201", "name": "Freight billing", "enabled": True, "domainNames": ["billing.larkspur-freight.example"],
     "tcpPortRanges": ["443", "443"], "udpPortRanges": [], "segmentGroupId": "2101", "segmentGroupName": "Finance apps",
     "serverGroups": [{"id": "2301", "name": "Portland data centre"}], "bypassType": "NEVER", "healthReporting": "ON_ACCESS",
     "doubleEncrypt": False, "isCnameEnabled": True, "icmpAccessType": "NONE"},
    {"id": "2202", "name": "Everything internal", "enabled": True, "domainNames": ["*.larkspur-freight.example", "10.20.0.0/16"],
     "tcpPortRanges": ["1", "65535"], "udpPortRanges": ["1", "65535"], "segmentGroupId": "2102", "segmentGroupName": "All internal (broad)",
     "serverGroups": [{"id": "2302", "name": "Reno depot servers"}], "bypassType": "NEVER", "healthReporting": "ON_ACCESS",
     "doubleEncrypt": False, "isCnameEnabled": True, "icmpAccessType": "PING"},
]
IDPS = [{"id": "2601", "name": "Larkspur Okta", "enabled": True, "ssoType": ["USER"], "scimEnabled": True, "idpEntityId": "https://idp.larkspur-freight.example"}]
SAML_ATTRIBUTES = [{"id": "2611", "name": "Department_Larkspur Okta", "idpId": "2601", "idpName": "Larkspur Okta", "samlName": "department", "userAttribute": True}]
POSTURE_PROFILES = [{"id": "2701", "name": "CrowdStrike running", "postureUdid": "a1b2c3d4-0000-4000-8000-000000002701", "postureType": "CROWDSTRIKE_ZTA_DEVICE_OS_SCORE", "platform": "windows,mac"},
                    {"id": "2702", "name": "Disk encrypted", "postureUdid": "a1b2c3d4-0000-4000-8000-000000002702", "postureType": "FULL_DISK_ENCRYPTION", "platform": "windows,mac"}]
ZPA_TRUSTED_NETWORKS = [{"id": "2801", "name": "Larkspur HQ", "networkId": "b2c3d4e5-0000-4000-8000-000000002801", "domain": DOMAIN}]
MACHINE_GROUPS: List[Dict[str, Any]] = []
ACCESS_RULES = [
    {"id": "2901", "name": "Finance users to billing", "ruleOrder": "1", "priority": "1", "action": "ALLOW", "policyType": "1",
     "conditions": [{"id": "c1", "operator": "OR", "operands": [{"id": "o1", "objectType": "APP_GROUP", "lhs": "id", "rhs": "2101", "name": "Finance apps"}]},
                    {"id": "c2", "operator": "OR", "operands": [{"id": "o2", "objectType": "POSTURE", "lhs": "a1b2c3d4-0000-4000-8000-000000002702", "rhs": "true", "name": "Disk encrypted"}]},
                    {"id": "c3", "operator": "OR", "operands": [{"id": "o3", "objectType": "SAML", "lhs": "2611", "rhs": "Finance", "name": "Department_Larkspur Okta"}]}]},
    {"id": "2902", "name": "Everyone to everything internal", "ruleOrder": "2", "priority": "2", "action": "ALLOW", "policyType": "1",
     "conditions": [{"id": "c4", "operator": "OR", "operands": [{"id": "o4", "objectType": "APP_GROUP", "lhs": "id", "rhs": "2102", "name": "All internal (broad)"}]}]},
    {"id": "2903", "name": "Default deny", "ruleOrder": "3", "priority": "3", "action": "DENY", "policyType": "1", "conditions": []},
]
TIMEOUT_RULES = [{"id": "2951", "name": "Re-authenticate daily", "ruleOrder": "1", "action": "RE_AUTH", "reauthTimeout": "86400",
                  "reauthIdleTimeout": "1800", "policyType": "2", "conditions": []}]

# ── ZDX and ZIdentity ─────────────────────────────────────────────────
ZDX_APPS = [{"id": 3001, "name": "Microsoft 365", "score": 82.0, "mostImpactedRegion": {"id": "us-west", "name": "US West"}, "totalUsers": 140},
            {"id": 3002, "name": "Freight billing", "score": 64.0, "mostImpactedRegion": {"id": "us-west", "name": "US West"}, "totalUsers": 35},
            {"id": 3003, "name": "Salesforce", "score": 91.0, "totalUsers": 60}]
ZDX_DEVICES = [{"id": 3101, "name": "LKF-LT-0001", "userid": 41}, {"id": 3102, "name": "LKF-MBP-0002", "userid": 42}]
ZID_USERS = [{"id": "u-41", "loginName": "avery.quinn@larkspur-freight.example", "displayName": "Avery Quinn", "status": True},
             {"id": "u-42", "loginName": "rowan.ellis@larkspur-freight.example", "displayName": "Rowan Ellis", "status": True}]
ZID_GROUPS = [{"id": "g-33", "name": "Finance Team", "source": "SCIM"}, {"id": "g-34", "name": "Developers", "source": "SCIM"}]
ZID_RESOURCE_SERVERS = [{"id": "rs-1", "name": "ZIA", "primaryAud": "https://api.zscaler.com"}]


def responses() -> Dict[str, Any]:
    """Every answer of the sample tenant: {OneAPI path: JSON body}. A fresh
    deep copy each time, so changing one sample never changes another."""
    r: Dict[str, Any] = {
        f"{ZIA}/dlpDictionaries": DICTIONARIES,
        f"{ZIA}/dlpEngines": ENGINES,
        f"{ZIA}/dlpNotificationTemplates": NOTIFICATION_TEMPLATES,
        f"{ZIA}/incidentReceiverServers": INCIDENT_RECEIVERS,
        f"{ZIA}/icapServers": ICAP_SERVERS,
        f"{ZIA}/webDlpRules": WEB_DLP_RULES,
        f"{ZIA}/endPointDlpRules": ENDPOINT_DLP_RULES,
        f"{ZIA}/emailDlpRules": EMAIL_DLP_RULES,
        f"{ZIA}/casbDlpRules/all": SAAS_DLP_RULES,
        f"{ZIA}/casbDlpRules": SAAS_DLP_RULES,
        f"{ZIA}/casbTenant/lite": CASB_TENANTS,
        f"{ZIA}/urlCategories": URL_CATEGORIES,
        f"{ZIA}/urlFilteringRules": URL_FILTERING_RULES,
        f"{ZIA}/sslInspectionRules": SSL_RULES,
        f"{ZIA}/firewallFilteringRules": FIREWALL_RULES,
        f"{ZIA}/firewallDnsRules": FIREWALL_DNS_RULES,
        f"{ZIA}/firewallIpsRules": FIREWALL_IPS_RULES,
        f"{ZIA}/networkServices": NETWORK_SERVICES,
        f"{ZIA}/ipDestinationGroups": [], f"{ZIA}/ipSourceGroups": [],
        f"{ZIA}/fileTypeRules": FILE_TYPE_RULES,
        f"{ZIA}/pacFiles": PAC_FILES,
        f"{ZIA}/locations": LOCATIONS,
        f"{ZIA}/advancedSettings": ADVANCED_SETTINGS,
        f"{ZIA}/authSettings": AUTH_SETTINGS,
        f"{ZIA}/adminRoles": ADMIN_ROLES,
        f"{ZIA}/adminUsers": ADMIN_USERS,
        f"{ZIA}/departments": DEPARTMENTS,
        f"{ZIA}/groups": GROUPS,
        f"{ZIA}/users": USERS,
        f"{ZIA}/ruleLabels": RULE_LABELS,
        f"{ZIA}/nssFeeds": NSS_FEEDS,
        f"{ZIA}/browserIsolation/profiles": ISOLATION_PROFILES,
        f"{ZIA}/sandboxRules": [], f"{ZIA}/bandwidthClasses": [], f"{ZIA}/bandwidthControlRules": [],
        f"{ZIA}/tenancyRestrictionProfile": [], f"{ZIA}/greTunnels": [], f"{ZIA}/staticIP": [], f"{ZIA}/vpnCredentials": [],
        f"{ZIA}/status": {"status": "ACTIVE"},
        f"{ZIA}/cyberThreatProtection/advancedThreatSettings": {"riskTolerance": 40, "cmdCtlServerBlocked": True, "malwareSitesBlocked": True,
                                                                "knownPhishingSitesBlocked": True, "suspectAdwareSpywareSitesBlocked": True},
        f"{ZIA}/cyberThreatProtection/malwareSettings": {"virusBlocked": True, "unwantedApplicationsBlocked": True, "trojanBlocked": True,
                                                         "wormBlocked": True, "ransomwareBlocked": True, "spywareBlocked": True},
        # Client Connector (first candidate of each short endpoint, see dlp_assessment_full_auto._ZCC_MAP)
        f"{ZCC}/application-profiles": APP_PROFILES,
        f"{ZCC}/web/policy/listByCompany": APP_PROFILES,
        f"{ZCC}/webForwardingProfile/listByCompany": FORWARDING_PROFILES,
        f"{ZCC}/webTrustedNetwork/listByCompany": {"trustedNetworkContracts": TRUSTED_NETWORKS, "totalCount": len(TRUSTED_NETWORKS)},
        f"{ZCC}/getDevices": DEVICES,
        f"{ZCC}/webFailOpenPolicy/listByCompany": FAIL_OPEN,
        f"{ZCC}/getCompanyInfo": COMPANY_INFO,
        f"{ZCC}/getPacFiles": [], f"{ZCC}/webAppService/listByCompany": [], f"{ZCC}/webBypassAppConfig/listByCompany": [],
        f"{ZCC}/getAdminUsers": [], f"{ZCC}/getAdminRoles": [], f"{ZCC}/webDeviceGroups/listByCompany": [],
        f"{ZCC}/getZpaGroupEntitlements": {"zpaEnableForAll": True}, f"{ZCC}/getZdxGroupEntitlements": {"zdxEnableForAll": True},
        # ZPA
        f"{ZPA1}/application": _zpa(SEGMENTS),
        f"{ZPA1}/segmentGroup": _zpa(SEGMENT_GROUPS),
        f"{ZPA1}/serverGroup": _zpa(SERVER_GROUPS),
        f"{ZPA1}/appConnectorGroup": _zpa(CONNECTOR_GROUPS),
        f"{ZPA1}/connector": _zpa(CONNECTORS),
        f"{ZPA1}/serviceEdgeGroup": _zpa([]), f"{ZPA1}/serviceEdge": _zpa([]),
        f"{ZPA2}/idp": _zpa(IDPS),
        f"{ZPA2}/samlAttribute": _zpa(SAML_ATTRIBUTES),
        f"{ZPA2}/posture": _zpa(POSTURE_PROFILES),
        f"{ZPA2}/network": _zpa(ZPA_TRUSTED_NETWORKS),
        f"{ZPA1}/machineGroup": _zpa(MACHINE_GROUPS),
        f"{ZPA1}/certificate": _zpa([]), f"{ZPA2}/lssConfig": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/ACCESS_POLICY": _zpa(ACCESS_RULES),
        f"{ZPA1}/policySet/rules/policyType/TIMEOUT_POLICY": _zpa(TIMEOUT_RULES),
        f"{ZPA1}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/INSPECTION_POLICY": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/ISOLATION_POLICY": _zpa([]),
        # ZDX
        f"{ZDX}/apps": ZDX_APPS, f"{ZDX}/devices": {"devices": ZDX_DEVICES, "next_offset": None},
        f"{ZDX}/administration/departments": [{"id": 21, "name": "Operations"}, {"id": 22, "name": "Finance"}],
        f"{ZDX}/administration/locations": [{"id": 1101, "name": "Larkspur HQ (Portland)"}],
        # ZIdentity
        f"{ZID}/users": {"records": ZID_USERS, "results_total": len(ZID_USERS)},
        f"{ZID}/groups": {"records": ZID_GROUPS, "results_total": len(ZID_GROUPS)},
        f"{ZID}/resource-servers": {"records": ZID_RESOURCE_SERVERS, "results_total": len(ZID_RESOURCE_SERVERS)},
    }
    for rule_type, rules in CAC_RULES.items():
        r[f"{ZIA}/webApplicationRules/{rule_type}"] = rules
    return copy.deepcopy(r)


def meta() -> Dict[str, Any]:
    """What the sample says about itself (the banner, the status, records)."""
    return {"kind": "sample", "company": COMPANY, "tenant_label": LABEL, "saved_at": "",
            "scopes": ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"],
            "channels": {}}


def url_lookup(urls: List[str]) -> List[Dict[str, Any]]:
    """The sample's answer to POST /urlLookup: each URL's categories from
    URL_LOOKUP (by host, then its parent domains), else Miscellaneous."""
    out = []
    for u in urls[:100]:
        host = str(u or "").strip().lower()
        host = host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        cats = None
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cats = URL_LOOKUP.get(".".join(parts[i:]))
            if cats:
                break
        if not cats and (host.endswith("." + DOMAIN) or host == DOMAIN):
            cats = ["CORPORATE_MARKETING"]
        out.append({"url": str(u)[:300], "urlClassifications": list(cats or ["OTHER_MISCELLANEOUS"]),
                    "urlClassificationsWithSecurityAlert": []})
    return out
