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
    IdP, posture profiles, access and timeout policies, and its
    administration (admins, roles, API keys, a break-glass account,
    microtenants, a provisioning key, PRA credentials and approvals);
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
ZPA_PRA = "/zpa/waap-pra-config/v1/admin/customers/{customerId}"
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
     "dlpEngines": [_ref(70, "Larkspur Customer Data")], "severity": "RULE_SEVERITY_MEDIUM", "receiver": _ref(3, "Larkspur incident receiver"),
     "fileTypes": []},
    {"id": 202, "order": 2, "rank": 7, "name": "Card data to printers", "state": "DISABLED", "action": "BLOCK",
     "dlpEngines": [_ref(60, "PCI")], "severity": "RULE_SEVERITY_HIGH", "receiver": _ref(3, "Larkspur incident receiver"),
     "fileTypes": []},
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
    # An Inspect rule with its own certificate choice, for the SSL certificate manager (Build new) to show and move.
    {"id": 705, "order": 3, "rank": 7, "name": "Inspect partner portals", "state": "ENABLED", "urlCategories": ["CUSTOM_01"],
     "action": {"type": "DECRYPT", "overrideDefaultCertificate": False,
                "decryptSubActions": {"serverCertificates": "BLOCK", "ocspCheck": True, "minClientTLSVersion": "CLIENT_TLS_1_2"}}},
    {"id": 703, "order": 4, "rank": 7, "name": "Decrypt everything else", "state": "ENABLED", "defaultRule": True,
     "action": {"type": "DECRYPT", "decryptSubActions": {"serverCertificates": "BLOCK", "ocspCheck": True, "minClientTLSVersion": "CLIENT_TLS_1_2",
                                                     "minServerTLSVersion": "SERVER_TLS_1_2"}},
     "urlCategories": ["ANY"]},
]
FIREWALL_RULES = [
    {"id": 801, "order": 1, "rank": 7, "name": "Block QUIC to force inspection", "state": "ENABLED", "action": "BLOCK_DROP",
     "nwServices": [_ref(41, "QUIC")], "destCountries": []},
    # ZIA's predefined Office 365 One Click rule (advanced settings
    # enableOffice365): its only criterion is the Zscaler-managed app
    # service group OFFICE365, whose members the API never returns.
    {"id": 804, "order": 2, "rank": 7, "name": "Office 365 One Click Rule", "state": "ENABLED", "action": "ALLOW", "predefined": True,
     "appServiceGroups": [_ref(361, "OFFICE365")]},
    {"id": 802, "order": 3, "rank": 7, "name": "Allow office traffic", "state": "ENABLED", "action": "ALLOW", "nwServices": [], "destCountries": []},
    {"id": 803, "order": 127, "rank": 7, "name": "Default Firewall Filtering Rule", "state": "ENABLED", "action": "ALLOW", "defaultRule": True,
     "predefined": True},
]
FIREWALL_DNS_RULES = [{"id": 811, "order": 1, "rank": 7, "name": "Block DNS tunnels", "state": "ENABLED", "action": "BLOCK",
                       "applications": ["DNS_TUNNELS"]}]
FIREWALL_IPS_RULES = [{"id": 821, "order": 1, "rank": 7, "name": "Default IPS rule", "state": "ENABLED", "action": "ALLOW",
                       "defaultRule": True, "threatCategories": []}]
# A short excerpt of Microsoft's published Microsoft 365 endpoint list
# (the Office 365 IP Address and URL web service, worldwide instance), in
# its own format, so the sample's Office 365 One Click rule can be matched
# (app_services.sample_list). Used only for the sample tenant and only when
# no real list is kept; it is not complete and may be out of date. A real
# tenant is matched only with the list fetched or imported in Advanced
# settings.
M365_ENDPOINTS_EXCERPT = [
    {"id": 1, "serviceArea": "Exchange", "serviceAreaDisplayName": "Exchange Online", "category": "Optimize", "required": True, "expressRoute": True,
     "urls": ["outlook.cloud.microsoft", "outlook.office.com", "outlook.office365.com"],
     "ips": ["13.107.6.152/31", "13.107.18.10/31", "13.107.128.0/22", "23.103.160.0/20", "40.96.0.0/13", "40.104.0.0/15", "52.96.0.0/14",
             "131.253.33.215/32", "132.245.0.0/16", "150.171.32.0/22", "204.79.197.215/32", "2603:1006::/40", "2603:1016::/36",
             "2603:1026::/36", "2603:1036::/36", "2603:1046::/36", "2603:1056::/36", "2620:1ec:4::152/128", "2620:1ec:4::153/128"],
     "tcpPorts": "80,443", "udpPorts": "443"},
    {"id": 31, "serviceArea": "SharePoint", "serviceAreaDisplayName": "SharePoint Online and OneDrive for Business", "category": "Optimize",
     "required": True, "expressRoute": True, "urls": ["<tenant>.sharepoint.com", "<tenant>-my.sharepoint.com"],
     "ips": ["13.107.136.0/22", "40.108.128.0/17", "52.104.0.0/14", "104.146.128.0/17", "150.171.40.0/22", "2603:1061:1300::/40",
             "2620:1ec:8f8::/46", "2620:1ec:908::/46"], "tcpPorts": "443,80"},
    {"id": 12, "serviceArea": "Skype", "serviceAreaDisplayName": "Skype for Business Online and Microsoft Teams", "category": "Allow",
     "required": True, "expressRoute": True, "urls": ["*.lync.com", "*.teams.microsoft.com", "teams.microsoft.com"],
     "ips": ["13.107.64.0/18", "52.112.0.0/14", "52.122.0.0/15", "2603:1063::/38"], "tcpPorts": "443,80"},
    {"id": 56, "serviceArea": "Common", "serviceAreaDisplayName": "Microsoft 365 Common and Office Online", "category": "Allow",
     "required": True, "expressRoute": True,
     "urls": ["*.auth.microsoft.com", "*.msftidentity.com", "*.msidentity.com", "account.activedirectory.windowsazure.com",
              "graph.microsoft.com", "login.microsoft.com", "login.microsoftonline.com", "login.windows.net"],
     "ips": ["20.20.32.0/19", "20.190.128.0/18", "20.231.128.0/19", "40.126.0.0/18", "2603:1006:2000::/48", "2603:1007:200::/48"],
     "tcpPorts": "443,80"},
]

# Proxy chaining, forwarding and cloud app instances (the rule editor: ops_rule_editor, ops_zia_objects).
FORWARDING_RULES = [{"id": 841, "order": 1, "rank": 7, "name": "Partner portal direct", "state": "ENABLED", "type": "FORWARDING",
                     "forwardMethod": "DIRECT", "destAddresses": ["portal.harborline-logistics.example"]}]
PROXIES = [{"id": 851, "name": "Harborline egress proxy", "type": "PROXYCHAIN", "address": "proxy.larkspur-freight.example", "port": 8080,
            "insertXauHeader": False, "base64EncodeXauHeader": False, "description": "Partner egress"}]
PROXY_GATEWAYS = [{"id": 861, "name": "Harborline gateway", "type": "PROXYCHAIN", "primaryProxy": {"id": 851, "name": "Harborline egress proxy"},
                   "failClosed": True}]
CLOUD_APP_INSTANCES = [{"instanceId": 871, "instanceName": "Larkspur SharePoint", "instanceType": "SHAREPOINTONLINE",
                        "instanceIdentifiers": [{"instanceIdentifier": "larkspurfreight.sharepoint.com", "identifierType": "URL",
                                                 "instanceIdentifierName": "larkspurfreight.sharepoint.com"}]}]
TIME_WINDOWS = [{"id": 881, "name": "Work hours", "startTime": 480, "endTime": 1080, "dayOfWeek": ["MON", "TUE", "WED", "THU", "FRI"]}]
NETWORK_SERVICES = [{"id": 41, "name": "QUIC", "type": "PREDEFINED", "destUdpPorts": [{"start": 443, "end": 443}]}]
CAC_RULES = {
    "AI_ML": [{"id": 901, "order": 1, "rank": 7, "name": "GenAI: allow use, block uploads", "state": "ENABLED", "type": "AI_ML",
               "applications": ["CHATGPT_AI", "GOOGLE_GEMINI"], "actions": ["ALLOW_AI_ML_WEB_USE", "BLOCK_AI_ML_UPLOAD"]}],
    "FILE_SHARE": [{"id": 902, "order": 1, "rank": 7, "name": "File sharing: allow all", "state": "ENABLED", "type": "FILE_SHARE",
                    "applications": ["DROPBOX", "WETRANSFER"], "actions": ["ALLOW_FILE_SHARE_VIEW", "ALLOW_FILE_SHARE_UPLOAD"]}],
    "WEBMAIL": [{"id": 903, "order": 1, "rank": 7, "name": "Personal webmail: no attachments", "state": "ENABLED", "type": "WEBMAIL",
                 "applications": ["GMAIL"], "actions": ["ALLOW_WEBMAIL_VIEW", "BLOCK_WEBMAIL_ATTACHMENT_SEND"]}],
}
# Every Cloud App Control rule type the readers list (dlp_assessment_full_auto._CAC_TYPES):
# a type with no rule answers an empty list, as the API does.
CAC_RULE_TYPES = ("AI_ML", "BUSINESS_PRODUCTIVITY", "CONSUMER", "CUSTOM_CAPP", "DNS_OVER_HTTPS", "ENTERPRISE_COLLABORATION", "FILE_SHARE",
                  "FINANCE", "HEALTH_CARE", "HOSTING_PROVIDER", "HUMAN_RESOURCES", "INSTANT_MESSAGING", "IT_SERVICES", "LEGAL",
                  "SALES_AND_MARKETING", "SOCIAL_NETWORKING", "STREAMING_MEDIA", "SYSTEM_AND_DEVELOPMENT", "WEBMAIL")
FILE_TYPE_RULES = [
    {"id": 951, "order": 1, "rank": 7, "name": "Block archives to file shares", "state": "ENABLED", "filteringAction": "BLOCK",
     "operation": "UPLOAD", "fileTypes": ["FTCATEGORY_ZIP", "FTCATEGORY_RAR"], "cloudApplications": ["DROPBOX", "WETRANSFER"], "protocols": ["ANY_RULE"]},
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
                     "cascadeUrlFiltering": True, "enablePolicyForUnauthenticatedTraffic": False,
                     # Admin ranking off: rules are evaluated by rule order (admin_rank).
                     "enableAdminRankAccess": False}
# Evaluate All Rules is a DLP global option (zscaler/zia/models/web_dlp_global_options.py), off here.
WEB_DLP_GLOBAL_OPTIONS = {"enableEvaluateAllDlpRules": False, "enableInlineDlpOcr": False, "enableEmailDlpOcr": False, "enableCasbOcr": False,
                          "exemptUrlEncodedData": False}
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
# Governance and audit (zscaler-sdk-python 1.11.3 zia/models: system_audit.ConfigAudit,
# admin_roles.PasswordExpiry, remoteassistance.RemoteAssistance,
# alert_subscriptions.AlertSubscriptions, nss_servers.Nssservers,
# nss_collectors.NssCollectors; /subscriptions rows as readiness.parse_subscriptions
# reads them). The config audit grades one item poorly and one NSS VM is
# unhealthy, so the governance checks have something to say.
CONFIG_AUDIT = {"overallGrade": "B", "highAvailabilityGrade": "A", "greTunnelGrade": "C", "userPerformanceGrade": "A", "otherGrade": "A",
                "authFrequencyGrade": "A", "pacFileGrade": "A", "pacfileSizeGrade": "A", "office365Flag": True, "office365Grade": "A",
                "ipVisibilityGrade": "B", "reportTimestamp": 1792994400000, "dataPresent": True,
                "greTunnelRecommendedConfiguration": "Add a backup GRE tunnel to a second data centre for Larkspur HQ (Portland)."}
PASSWORD_EXPIRY = {"passwordExpirationEnabled": True, "passwordExpiryDays": 90}
REMOTE_ASSISTANCE = {"viewOnlyUntil": 0, "fullAccessUntil": 0, "usernameObfuscated": True, "deviceInfoObfuscate": True}
ALERT_SUBSCRIPTIONS = [{"id": 71, "description": "Security operations", "email": "secops@larkspur-freight.example",
                        "pt0Severities": ["CRITICAL"], "secureSeverities": ["CRITICAL", "MAJOR"], "manageSeverities": [],
                        "complySeverities": [], "systemSeverities": ["CRITICAL", "MAJOR"], "deleted": False}]
NSS_SERVERS = [{"id": 81, "name": "nss-web-portland-1", "status": "ENABLED", "state": "HEALTHY", "type": "NSS_FOR_WEB"},
               {"id": 82, "name": "nss-fw-portland-1", "status": "ENABLED", "state": "UNHEALTHY", "type": "NSS_FOR_FIREWALL"}]
NSS_COLLECTORS: list = []
SUBSCRIPTIONS = [{"id": s, "status": "ACTIVE", "subscribed": True} for s in
                 ("ZIA_TENANT", "URL_FILTER", "ZIA_SSL", "ZIA_ATP", "Z_FIREWALL_BASIC", "ZDLP_WEB", "Z_DLP_ENDPOINT", "Z_CASB",
                  "Z_LOGFEED", "Z_CLOUD_NSS_WEB", "ZSCALER_CLIENT_CONNECTOR", "Z_ZDX_STD")]
ISOLATION_PROFILES = [{"id": "iso-1", "name": "Larkspur isolation", "url": "https://isolation.example/larkspur", "defaultProfile": True}]

# ── Client Connector ──────────────────────────────────────────────────
# As the Client Connector API answers an app profile (zscaler/zcc/models/webpolicy.py):
# the platform is device_type (1 iOS, 3 Windows, 4 macOS), the certificate switch
# install_ssl_certs sits in the platform policy, and Install Endpoint DLP
# (enableZdpService) and the destination exclusions (packetTunnelExcludeList,
# comma-separated) in policyExtension. strictEnforcement is not in the SDK's
# WebPolicy model (assumed: the readers ask for it, and a device reports it).
APP_PROFILES = [
    {"id": 1201, "name": "Windows - Corporate", "device_type": 3, "active": 1, "ruleOrder": 1, "forwardingProfileId": 1301,
     "strictEnforcement": 1, "logLevel": 0, "windowsPolicy": {"install_ssl_certs": 1, "disableLoopBackRestriction": 0},
     "policyExtension": {"enableZdpService": "1", "packetTunnelExcludeList": "10.0.0.0/8"}, "groups": [], "users": []},
    {"id": 1202, "name": "macOS - Corporate", "device_type": 4, "active": 1, "ruleOrder": 1, "forwardingProfileId": 1301,
     "strictEnforcement": 1, "macPolicy": {"installCerts": 1}, "policyExtension": {"enableZdpService": "0"}, "groups": [], "users": []},
    {"id": 1203, "name": "Windows - Contractors", "device_type": 3, "active": 1, "ruleOrder": 2, "forwardingProfileId": 1302,
     "strictEnforcement": 0, "windowsPolicy": {"install_ssl_certs": 1},
     "policyExtension": {"enableZdpService": "0", "packetTunnelExcludeList": "10.0.0.0/8,192.0.2.0/24"},
     "bypassCustomAppIds": ["5001"], "groups": [_ref(32, "Drivers")], "users": []},
    {"id": 1204, "name": "iOS - Drivers", "device_type": 1, "active": 1, "ruleOrder": 1, "forwardingProfileId": 1301,
     "strictEnforcement": 0, "groups": [_ref(32, "Drivers")], "users": []},
]
# The custom IP-based application the contractors' profile bypasses
# (bypassCustomAppIds; zscaler/zcc/models/custom_ip_base_apps.py).
CUSTOM_IP_APPS = [{"id": 5001, "appName": "Depot handheld sync", "active": True,
                   "appDataBlob": [{"proto": "TCP", "port": "443", "ipaddr": "198.51.100.0/24", "fqdn": ""}]}]
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
# The per-device service status (GET .../downloadServiceStatus, a CSV the SDK's DevicesAPI.download_service_status
# fetches; it starts "User","Device type"). The other column names are assumed from the Client Connector Portal's
# Service Status export. The contractor laptop has ZIA off while ZPA is on: the fleet page's bypass risk.
SERVICE_STATUS_CSV = (
    '"User","Device type","UDID","Hostname","Zscaler Client Connector Version","Registration State","ZIA Enabled","ZIA Health",'
    '"ZPA Enabled","ZPA Health","ZDX Enabled","ZDX Health","Last Seen Connected to ZIA"\n'
    '"avery.quinn@larkspur-freight.example","Windows","LKF-WIN-0001","LKF-LT-0001","4.5.0.334","Registered","true","Active",'
    '"true","Active","true","Active","2026-10-27 18:05:11 GMT"\n'
    '"rowan.ellis@larkspur-freight.example","macOS","LKF-MAC-0002","LKF-MBP-0002","4.4.0.208","Registered","true","Active",'
    '"true","Active","false","Inactive","2026-10-28 08:40:02 GMT"\n'
    '"jordan.blake@larkspur-freight.example","Windows","LKF-WIN-0003","LKF-CT-0003","4.2.0.198","Registered","true","Inactive",'
    '"true","Active","true","Inactive","2026-10-20 07:12:44 GMT"\n'
)
FAIL_OPEN = [{"id": 1, "enableFailOpen": 1, "enableCaptivePortalDetection": 1, "captivePortalWebSecDisableMinutes": 10,
              "enableStrictEnforcementPrompt": 0, "tunnelFailureRetryCount": 25}]
# zscaler/zcc/models/company_info.py: zpnEnabled is ZPA, upmEnabled is ZDX, proxyEnabled is ZIA.
COMPANY_INFO = {"businessName": COMPANY, "orgId": 7200001, "proxyEnabled": 1, "zpnEnabled": 1, "upmEnabled": 1, "dlpEnabled": 1,
                "zadEnabled": 0, "enableGlobalZCCTelemetry": 1}
WEB_PRIVACY_INFO = {"id": 1, "active": "1", "collectUserInfo": "1", "collectMachineHostname": "1", "collectZdxLocation": "1",
                    "enablePacketCapture": "0", "disableCrashlytics": "0", "exportLogsForNonAdmin": "0"}
DEVICE_CLEANUP = {"id": 1, "active": 1, "autoRemovalDays": 30, "autoPurgeDays": 60, "deviceExceedLimit": 16}

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
# Tenant health (tenant_health.py): the SSL inspection intermediate CA
# certificates (certExpDate, epoch seconds) and the ZPA enrollment
# certificates (validToInEpochSec), all far from expiry so the sample stays
# healthy whatever the date; names and dates only, no certificate body.
ZIA_CA_CERTIFICATES = [
    {"id": 1, "name": "Zscaler Intermediate CA Certificate", "type": "ZSCALER", "region": "GLOBAL", "status": "ENABLED",
     "defaultCertificate": False, "certStartDate": 1735689600, "certExpDate": 2082758400},
    {"id": 2, "name": "Larkspur SSL Inspection CA", "type": "CUSTOM_SW", "region": "GLOBAL", "status": "ENABLED",
     "defaultCertificate": True, "certStartDate": 1767225600, "certExpDate": 2019686400},
]
ZPA_ENROLLMENT_CERTIFICATES = [
    {"id": "2601", "name": "Root", "validFromInEpochSec": "1609459200", "validToInEpochSec": "2240611200"},
    {"id": "2602", "name": "Connector", "validFromInEpochSec": "1609459200", "validToInEpochSec": "2082758400"},
    {"id": "2603", "name": "Service Edge", "validFromInEpochSec": "1609459200", "validToInEpochSec": "2082758400"},
    {"id": "2604", "name": "Client", "validFromInEpochSec": "1609459200", "validToInEpochSec": "2082758400"},
]
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
# A ZPA admin role (zscaler/zpa/models/role_controller.py), as the readiness check reads it.
ZPA_ROLES = [{"id": "2991", "name": "ZPA read only", "classPermissionGroups": [{"classPermissions": [
    {"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "VIEW_ONLY"}},
    {"classType": {"friendlyName": "Policy"}, "permission": {"type": "VIEW_ONLY"}}]}]}]
ZPA_ROLES += [
    {"id": "2990", "name": "Super Admin", "systemRole": True, "classPermissionGroups": [{"classPermissions": [
        {"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "FULL"}},
        {"classType": {"friendlyName": "Policy"}, "permission": {"type": "FULL"}},
        {"classType": {"friendlyName": "Administrator"}, "permission": {"type": "FULL"}}]}]},
    {"id": "2992", "name": "App segment operator", "customRole": True, "classPermissionGroups": [{"classPermissions": [
        {"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "FULL"}},
        {"classType": {"friendlyName": "Policy"}, "permission": {"type": "VIEW_ONLY"}}]}]}]
# ZPA administration (zscaler/zpa/models: administrator_controller, api_keys,
# emergency_access, microtenants, provisioning_keys, pra_credential,
# pra_cred_pool_controller, pra_approval), with the gaps the RBAC checks find:
# admin login is not SSO-only, one local admin has no second factor, the
# Terraform API key has full access, a provisioning key allows 100 enrolments,
# a PRA credential was last reset in 2025, an approval stands until 2030 and
# one microtenant has no admin of its own. No secret value is in the sample.
ZPA_MICROTENANTS = [{"id": "2961", "name": "Cold Chain", "enabled": True, "criteriaAttribute": "AuthDomain",
                     "criteriaAttributeValues": ["coldchain." + "larkspur-freight.example"], "privilegedApprovalsEnabled": False},
                    {"id": "2962", "name": "Air Cargo", "enabled": True, "criteriaAttribute": "AuthDomain",
                     "criteriaAttributeValues": ["air." + "larkspur-freight.example"], "privilegedApprovalsEnabled": True}]
ZPA_ADMINS = [
    {"id": "2971", "username": "avery.quinn@larkspur-freight.example", "displayName": "Avery Quinn", "isEnabled": True,
     "localLoginDisabled": True, "twoFactorAuthEnabled": False, "role": {"id": "2990", "name": "Super Admin"}, "microtenantId": "0"},
    {"id": "2972", "username": "rowan.ellis@larkspur-freight.example", "displayName": "Rowan Ellis", "isEnabled": True,
     "localLoginDisabled": False, "twoFactorAuthEnabled": False, "role": {"id": "2990", "name": "Super Admin"}, "microtenantId": "0"},
    {"id": "2973", "username": "sam.okafor@larkspur-freight.example", "displayName": "Sam Okafor", "isEnabled": True,
     "localLoginDisabled": True, "twoFactorAuthEnabled": True, "role": {"id": "2992", "name": "App segment operator"}, "microtenantId": "2961",
     "microtenantName": "Cold Chain"},
    {"id": "2974", "username": "jules.marsh@larkspur-freight.example", "displayName": "Jules Marsh", "isEnabled": True,
     "localLoginDisabled": True, "twoFactorAuthEnabled": True, "role": {"id": "2991", "name": "ZPA read only"}, "microtenantId": "0"},
    {"id": "2975", "username": "former.admin@larkspur-freight.example", "displayName": "Former admin", "isEnabled": False,
     "localLoginDisabled": False, "twoFactorAuthEnabled": False, "role": {"id": "2990", "name": "Super Admin"}, "microtenantId": "0"}]
ZPA_API_KEYS = [{"id": "2981", "name": "terraform-ci", "enabled": True, "roleId": "2990", "readOnly": False, "tokenExpiryTimeInSec": "3600",
                 "clientId": "lkf-terraform-ci", "creationTime": "1735689600"},
                {"id": "2982", "name": "siem-export", "enabled": True, "roleId": "2991", "readOnly": True, "tokenExpiryTimeInSec": "3600",
                 "clientId": "lkf-siem-export", "creationTime": "1735689600"}]
ZPA_SSO_OPTIONS = {"ssologinonly": False}
ZPA_EMERGENCY_USERS = [{"userId": "2985", "emailId": "breakglass@larkspur-freight.example", "firstName": "Break", "lastName": "Glass",
                        "userStatus": "ACTIVE", "lastLoginTime": "1735689600", "activatedOn": "1735689600"}]
ZPA_PROVISIONING_KEYS = [{"id": "2986", "name": "Portland DC connectors", "enabled": True, "maxUsage": "100", "usageCount": "2",
                          "zcomponentId": "2401", "zcomponentName": "Portland connectors", "creationTime": "1735689600"}]
ZPA_PRA_CREDENTIALS = [{"id": "2987", "name": "Yard server admin", "credentialType": "USERNAME_PASSWORD",
                        "lastCredentialResetTime": "1735689600", "creationTime": "1735689600"}]
ZPA_PRA_APPROVALS = [{"id": "2988", "emailIds": ["vendor.support@larkspur-freight.example"], "status": "ACTIVE",
                      "startTime": "1767225600", "endTime": "1893456000", "applications": [{"id": "2201", "name": "Freight billing"}],
                      "workingHours": {"days": ["MON", "TUE", "WED", "THU", "FRI"], "startTime": "08:00", "endTime": "18:00",
                                       "timeZone": "America/Los_Angeles"}}]
TIMEOUT_RULES = [{"id": "2951", "name": "Re-authenticate daily", "ruleOrder": "1", "action": "RE_AUTH", "reauthTimeout": "86400",
                  "reauthIdleTimeout": "1800", "policyType": "2", "conditions": []}]

# ── ZDX and ZIdentity ─────────────────────────────────────────────────
# The ZDX API answers in snake_case (zscaler/zdx/models/applications.py).
ZDX_APPS = [{"id": 3001, "name": "Microsoft 365", "score": 82.0, "most_impacted_region": {"id": "us-west", "country": "United States"}, "total_users": 140},
            {"id": 3002, "name": "Freight billing", "score": 64.0, "most_impacted_region": {"id": "us-west", "country": "United States"}, "total_users": 35},
            {"id": 3003, "name": "Salesforce", "score": 91.0, "total_users": 60}]
ZDX_DEVICES = [{"id": 3101, "name": "LKF-LT-0001", "userid": 41}, {"id": 3102, "name": "LKF-MBP-0002", "userid": 42}]
ZID_USERS = [{"id": "u-41", "loginName": "avery.quinn@larkspur-freight.example", "displayName": "Avery Quinn", "status": True},
             {"id": "u-42", "loginName": "rowan.ellis@larkspur-freight.example", "displayName": "Rowan Ellis", "status": True}]
ZID_GROUPS = [{"id": "g-33", "name": "Finance Team", "source": "SCIM"}, {"id": "g-34", "name": "Developers", "source": "SCIM"}]
ZID_RESOURCE_SERVERS = [{"id": "rs-1", "name": "ZIA", "primaryAud": "https://api.zscaler.com", "defaultApi": True,
                         "serviceScopes": [{"service": {"id": "svc-zia", "name": "ZIA", "displayName": "ZIA"},
                                            "scopes": [{"id": "sc-zia-ro", "name": "zs:config:zia:larkspur:Read Only"},
                                                       {"id": "sc-zia-sa", "name": "zs:config:zia:larkspur:Super Admin"}]}]}]
# API clients (zscaler/zid/models/api_client.py); their secrets list carries ids and dates only, never a value.
ZID_API_CLIENTS = [{"id": "ac-51", "name": "Larkspur reporting", "description": "Monthly report export", "status": True,
                    "accessTokenLifeTime": 3600, "clientAuthentication": {"authType": "SECRET"},
                    "clientResources": [{"id": "rs-1", "name": "ZIA", "defaultApi": True,
                                         "selectedScopes": [{"id": "sc-zia-ro", "name": "zs:config:zia:larkspur:Read Only"}]}]}]
# Earlier versions of the hosted PAC file (zscaler/zia/pac_files.py get_pac_file: every version).
PAC_VERSIONS = [{"id": 31, "name": "larkspur.pac", "domain": "larkspur-freight.example", "pacVersion": 1, "pacVersionStatus": "LKG",
                 "pacCommitMessage": "First version", "pacContent": 'function FindProxyForURL(url, host) {\n  return "PROXY ${GATEWAY_FX}:80; DIRECT";\n}\n'},
                {"id": 31, "name": "larkspur.pac", "domain": "larkspur-freight.example", "pacVersion": 2, "pacVersionStatus": "STAGE",
                 "pacCommitMessage": "Partner portal direct (staged)", "pacContent": None}]


# ── What the builders read (Build new, the POV build) ──────────────────
# The catalogues a tenant carries and a builder plans against, so every
# Build new type and the POV build can make its full plan and dry run on
# the sample (a rehearsal: nothing is ever written from it). Shapes as the
# APIs answer them, the same lists tests/sdk_wire_fake.py checks against
# the installed SDK's models (zscaler/zia/url_categories.py
# list_categories_lite, cloud_firewall.list_network_apps,
# cloud_applications.list_cloud_app_policy, dns_gatways.list_dns_gateways,
# intermediate_certificates.list_ready_to_use; zscaler/zpa/
# enrollment_certificates, provisioning, app_protection; zscaler/aiguard/
# policies, policy_match_rules, llm_providers). The ZDX configuration API is
# not in the SDK: its shapes are ops_zdx's (assumed there).
AIG = "/aiguard/v1"
ZDX_CONFIG = f"{ZDX}/config"
INTERMEDIATE_CERTIFICATES = [
    {"id": 50, "name": "Zscaler Intermediate CA", "defaultCertificate": True, "status": "ENABLED", "type": "ZSCALER"},
    {"id": 52, "name": "Larkspur Issuing CA 2026", "status": "ENABLED", "type": "CUSTOM"}]
ROOT_CERTIFICATES = [{"id": 11, "name": "Larkspur AI Guard CA"}]
DNS_GATEWAYS = [{"id": 9, "name": "Zscaler Trusted Resolver", "natZtrGateway": True}]
SUBSCRIPTIONS = [{"id": "ZIA_BUS", "status": "ACTIVE", "subscribed": True}, {"id": "ZS_DP_GEN_AI", "status": "ACTIVE", "subscribed": True}]
URL_APP_SETTINGS = {"enableChatGptPrompt": False, "enableMicrosoftCoPilotPrompt": False, "enableGeminiPrompt": False, "enableClaudePrompt": False,
                    "enableMsftO365": True, "enforceSafeSearch": True}
ENROLLMENT_CERTS = [{"id": "8001", "name": "Connector"}, {"id": "8002", "name": "Service Edge"}]
OWASP_VERSIONS = ["OWASP_CRS/3.3.0", "OWASP_CRS/4.8.0"]
OWASP_CONTROLS = [
    {"id": "70001", "name": "Preprocessors", "defaultGroup": True, "predefinedInspectionControls": [
        {"id": "70011", "name": "Multipart request body failed strict validation", "action": "BLOCK", "defaultAction": "BLOCK",
         "controlType": "PREDEFINED", "protocolType": "HTTP", "paranoiaLevel": "1", "severity": "CRITICAL"}]},
    {"id": "70002", "name": "Environment and port scanners", "defaultGroup": True, "predefinedInspectionControls": [
        {"id": "70021", "name": "Found User-Agent associated with security scanner", "action": "BLOCK", "defaultAction": "BLOCK",
         "controlType": "PREDEFINED", "protocolType": "HTTP", "paranoiaLevel": "1", "severity": "CRITICAL"}]}]
ZDX_SUPPORTED = [{"provider": "MICROSOFT_LOGIN", "name": "Microsoft Login", "host": "login.microsoftonline.com"},
                 {"provider": "OUTLOOK", "name": "Outlook", "host": "outlook.office365.com"},
                 {"provider": "MICROSOFT_TEAMS", "name": "Microsoft Teams", "host": "teams.microsoft.com"},
                 {"provider": "SHAREPOINT", "name": "SharePoint", "host": "<prefix>.sharepoint.com"},
                 {"provider": "ONEDRIVE", "name": "OneDrive", "host": "<prefix>-my.sharepoint.com"},
                 {"provider": "ZOOM", "name": "Zoom", "host": "<prefix>.zoom.us"},
                 {"provider": "BOX", "name": "Box", "host": "app.box.com"}]
ZDX_COLLECTIONS = [{"id": 1, "name": "Custom Apps Collection", "type": "END_USER"}]
ZDX_CONFIG_APPS = [{"id": 3002, "name": "Freight billing", "type": "CUSTOM", "active": True, "collection": {"id": 1, "name": "Custom Apps Collection"}}]
ZDX_MONITORS = [{"id": 3201, "name": "Freight billing Web", "type": "WEB", "active": True, "class": "CUSTOM", "url": f"https://billing.{DOMAIN}/",
                 "application": {"id": 3002, "name": "Freight billing"}, "frequencyInSeconds": 300}]
AIGUARD_PROVIDERS = [{"id": 1, "name": "Default OpenAI Provider"}, {"id": 2, "name": "Default Anthropic Provider"}]


def builder_catalogues() -> Dict[str, Any]:
    """{path: body} of what the builders read and the rest of the sample
    does not carry: every URL category, network application and cloud
    application the ZIA baseline names (ops_zia_baseline.CATALOG, Zscaler's
    published names) plus the custom category, the Trusted Resolver, two
    ready-to-use intermediate certificates, ZPA's enrollment certificates
    and predefined OWASP controls, the ZDX configuration, ZIA's proxy
    chaining objects and AI Guard's lists (empty: nothing built yet)."""
    import ops_zia_baseline as zb   # its catalogue names what a tenant carries; imported here, not at load (no cycle)
    cats = sorted({c for r in zb.CATALOG for c in r["fields"].get("url_categories", [])} | {c["id"] for c in URL_CATEGORIES if not c["customCategory"]})
    nw = sorted({a for r in zb.CATALOG for a in r["fields"].get("nw_applications", [])})
    cloud = sorted({a for r in zb.CATALOG for a in r["fields"].get("applications", []) if r["area"] == "cac"})
    lite = [{"id": c} for c in cats] + [{"id": c["id"], "configuredName": c["configuredName"], "customCategory": True}
                                         for c in URL_CATEGORIES if c["customCategory"]]
    return {
        f"{ZIA}/urlCategories/lite": lite,
        f"{ZIA}/networkApplications": [{"id": a} for a in nw],
        # No app class on the rows: a read for one class (ssl_flow, pack_channels) answers "no data", as before.
        f"{ZIA}/cloudApplications/policy": [{"app": a} for a in cloud],
        f"{ZIA}/dnsGateways": DNS_GATEWAYS,
        f"{ZIA}/intermediateCaCertificate/readyToUse": INTERMEDIATE_CERTIFICATES,
        f"{ZIA}/rootCertificates": ROOT_CERTIFICATES,
        f"{ZIA}/proxies": [], f"{ZIA}/proxyGateways": [], f"{ZIA}/forwardingRules": [],
        f"{ZIA}/advancedUrlFilterAndCloudAppSettings": URL_APP_SETTINGS,
        f"{ZIA}/subscriptions": SUBSCRIPTIONS,
        f"{ZPA1}/enrollmentCert": _zpa(ENROLLMENT_CERTS), f"{ZPA2}/enrollmentCert": _zpa(ENROLLMENT_CERTS),
        f"{ZPA1}/associationType/SERVICE_EDGE_GRP/provisioningKey": _zpa([]),
        f"{ZPA1}/inspectionControls/predefined/versions": OWASP_VERSIONS,
        f"{ZPA1}/inspectionControls/predefined": OWASP_CONTROLS,
        f"{ZPA1}/clientlessCertificate/issued": _zpa([]),
        f"{ZDX_CONFIG}/applications": {"items": ZDX_CONFIG_APPS},
        f"{ZDX_CONFIG}/applications/supported": ZDX_SUPPORTED,
        f"{ZDX_CONFIG}/monitors": ZDX_MONITORS,
        f"{ZDX_CONFIG}/collections": ZDX_COLLECTIONS,
        f"{AIG}/detections/policies": {"items": []},
        f"{AIG}/detections/policy-match-rules": {"items": []},
        f"{AIG}/llm-providers": {"items": AIGUARD_PROVIDERS},
    }


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
        f"{ZIA}/forwardingRules": FORWARDING_RULES, f"{ZIA}/proxies": PROXIES, f"{ZIA}/proxyGateways": PROXY_GATEWAYS,
        f"{ZIA}/cloudApplicationInstances": CLOUD_APP_INSTANCES, f"{ZIA}/timeWindows": TIME_WINDOWS,
        f"{ZIA}/ipDestinationGroups": [], f"{ZIA}/ipSourceGroups": [],
        f"{ZIA}/fileTypeRules": FILE_TYPE_RULES,
        f"{ZIA}/pacFiles": PAC_FILES,
        f"{ZIA}/locations": LOCATIONS,
        f"{ZIA}/advancedSettings": ADVANCED_SETTINGS,
        f"{ZIA}/webDlpGlobalOptions": WEB_DLP_GLOBAL_OPTIONS,
        f"{ZIA}/security/advanced": {"blacklistUrls": ["malware-drop.example"]},
        f"{ZIA}/security": {"whitelistUrls": ["portal.harborline-logistics.example"]},
        f"{ZIA}/cyberThreatProtection/maliciousUrls": {"maliciousUrls": ["malware-drop.example"]},
        f"{ZIA}/cyberThreatProtection/securityExceptions": {"bypassUrls": []},
        f"{ZIA}/networkServiceGroups": [], f"{ZIA}/networkApplicationGroups": [], f"{ZIA}/locations/groups": [],
        f"{ZIA}/browserControlSettings": {"pluginCheckFrequency": "DAILY", "bypassAllBrowsers": False, "allowAllBrowsers": True,
                                          "enableWarnings": True, "enableSmartBrowserIsolation": False, "blockedChromeVersions": []},
        f"{ZIA}/authSettings": AUTH_SETTINGS,
        f"{ZIA}/adminRoles": ADMIN_ROLES,
        f"{ZIA}/adminUsers": ADMIN_USERS,
        f"{ZIA}/departments": DEPARTMENTS,
        f"{ZIA}/groups": GROUPS,
        f"{ZIA}/users": USERS,
        f"{ZIA}/ruleLabels": RULE_LABELS,
        f"{ZIA}/nssFeeds": NSS_FEEDS,
        f"{ZIA}/nssServers": NSS_SERVERS,
        f"{ZIA}/nssCollectors": NSS_COLLECTORS,
        f"{ZIA}/configAudit": CONFIG_AUDIT,
        f"{ZIA}/passwordExpiry/settings": PASSWORD_EXPIRY,
        f"{ZIA}/remoteAssistance": REMOTE_ASSISTANCE,
        f"{ZIA}/alertSubscriptions": ALERT_SUBSCRIPTIONS,
        f"{ZIA}/subscriptions": SUBSCRIPTIONS,
        f"{ZIA}/browserIsolation/profiles": ISOLATION_PROFILES,
        f"{ZIA}/sandboxRules": [], f"{ZIA}/bandwidthClasses": [], f"{ZIA}/bandwidthControlRules": [],
        f"{ZIA}/tenancyRestrictionProfile": [], f"{ZIA}/greTunnels": [], f"{ZIA}/staticIP": [], f"{ZIA}/vpnCredentials": [],
        f"{ZIA}/status": {"status": "ACTIVE"},
        f"{ZIA}/intermediateCaCertificate": ZIA_CA_CERTIFICATES,
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
        f"{ZCC}/downloadServiceStatus": SERVICE_STATUS_CSV,
        f"{ZCC}/webFailOpenPolicy/listByCompany": FAIL_OPEN,
        f"{ZCC}/getCompanyInfo": COMPANY_INFO,
        f"{ZCC}/getWebPrivacyInfo": WEB_PRIVACY_INFO, f"{ZCC}/getDeviceCleanupInfo": DEVICE_CLEANUP,
        f"{ZCC}/getAdminUsersSyncInfo": {"id": 1, "ziaInitialSyncDone": 1, "ziaLastSyncTime": "2026-10-28 02:00:00", "ziaSyncErrorCode": 0, "ziaSyncStatus": 1,
                                             "zpaInitialSyncDone": 1, "zpaLastSyncTime": "2026-10-28 02:00:00", "zpaSyncErrorCode": 0, "zpaSyncStatus": 1},
        f"{ZCC}/getPacFiles": [], f"{ZCC}/webAppService/listByCompany": [], f"{ZCC}/webBypassAppConfig/listByCompany": [],
        f"{ZCC}/custom-ip-based-apps": {"customAppContracts": CUSTOM_IP_APPS}, f"{ZCC}/predefined-ip-based-apps": {"appServiceContracts": []},
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
        f"{ZPA1}/certificate": _zpa([]), f"{ZPA2}/lssConfig": _zpa([]), f"{ZPA2}/clientlessCertificate/issued": _zpa([]),
        f"{ZPA1}/inspectionProfile": _zpa([]), f"{ZPA1}/isolation/profiles": _zpa([]), f"{ZPA1}/browserProtectionProfile": _zpa([]),
        f"{ZPA1}/praConsole": _zpa([]), f"{ZPA1}/praPortal": _zpa([]), f"{ZPA1}/userPortal": _zpa([]),
        f"{ZPA1}/associationType/CONNECTOR_GRP/provisioningKey": _zpa(ZPA_PROVISIONING_KEYS),
        f"{ZPA1}/associationType/SERVICE_EDGE_GRP/provisioningKey": _zpa([]),
        f"{ZPA1}/roles": _zpa(ZPA_ROLES),
        f"{ZPA1}/administrators": _zpa(ZPA_ADMINS),
        f"{ZPA1}/v2/ssoLoginOptions": ZPA_SSO_OPTIONS,
        f"{ZPA1}/apiKeys": _zpa(ZPA_API_KEYS),
        f"{ZPA1}/emergencyAccess/users": _zpa(ZPA_EMERGENCY_USERS),
        f"{ZPA1}/microtenants": _zpa(ZPA_MICROTENANTS),
        f"{ZPA1}/credential": _zpa(ZPA_PRA_CREDENTIALS),
        f"{ZPA_PRA}/credential-pool": _zpa([]),
        f"{ZPA1}/approval": _zpa(ZPA_PRA_APPROVALS),
        f"{ZPA2}/enrollmentCert": _zpa(ZPA_ENROLLMENT_CERTIFICATES),
        f"{ZPA1}/clientSetting": {"enrollmentCertId": "2604", "enrollmentCertName": "Client", "singningCertExpiryInEpochSec": "2082758400"},
        f"{ZPA1}/policySet/rules/policyType/ACCESS_POLICY": _zpa(ACCESS_RULES),
        f"{ZPA1}/policySet/rules/policyType/TIMEOUT_POLICY": _zpa(TIMEOUT_RULES),
        f"{ZPA1}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/INSPECTION_POLICY": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/ISOLATION_POLICY": _zpa([]),
        # ZDX
        f"{ZDX}/apps": ZDX_APPS, f"{ZDX}/devices": {"devices": ZDX_DEVICES, "next_offset": None},
        f"{ZDX}/administration/departments": [{"id": 21, "name": "Operations"}, {"id": 22, "name": "Finance"}],
        f"{ZDX}/administration/locations": [{"id": 1101, "name": "Larkspur HQ (Portland)"}],
        f"{ZDX}/alerts/ongoing": {"alerts": [], "next_offset": None},
        f"{ZDX}/inventory/software": {"software": [{"software_key": "zscaler-client-connector", "software_name": "Zscaler Client Connector",
                                                    "vendor": "Zscaler", "software_group": "Security", "software_install_type": "MSI",
                                                    "user_total": 3, "device_total": 3}], "next_offset": None},
        # ZIdentity
        f"{ZID}/users": {"records": ZID_USERS, "results_total": len(ZID_USERS)},
        f"{ZID}/groups": {"records": ZID_GROUPS, "results_total": len(ZID_GROUPS)},
        f"{ZID}/resource-servers": {"records": ZID_RESOURCE_SERVERS, "results_total": len(ZID_RESOURCE_SERVERS)},
        f"{ZID}/api-clients": {"records": ZID_API_CLIENTS, "results_total": len(ZID_API_CLIENTS)},
        f"{ZID}/api-clients/ac-51/secrets": [{"id": "sec-1", "createdAt": 1767225600, "expiresAt": 1798761600}],
        f"{ZIA}/pacFiles/31/version": [dict(v, pacContent=v["pacContent"] or PAC_CONTENT) for v in PAC_VERSIONS] + [dict(PAC_FILES[0])],
    }
    for rule_type in CAC_RULE_TYPES:
        r[f"{ZIA}/webApplicationRules/{rule_type}"] = CAC_RULES.get(rule_type, [])
    for path, body in builder_catalogues().items():
        r.setdefault(path, body)
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
