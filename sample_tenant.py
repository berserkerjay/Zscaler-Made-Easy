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
    locations, advanced settings, admins and roles, forwarding control
    (proxy chaining, ZPA and dedicated IP gateways, GRE tunnels and VIPs,
    data centre exclusions, IPv6, NAT control, a Virtual Service Edge
    cluster, a DNS gateway), the threat protection settings (Sandbox hash
    list, IPS signatures, mobile, FTP, notifications, alerts, risk profiles)
    and SaaS Security malware scanning;
  - Client Connector: app profiles per platform (one without strict
    enforcement and with a bypass), forwarding profiles (one leaves traffic
    direct on a trusted network), trusted networks, devices;
  - ZPA: application segments (one with a wildcard domain, a Privileged
    Remote Access one and a Browser Access one), segment, server and
    connector groups, App Connectors (one disconnected), an IdP, posture
    profiles, access, timeout, client forwarding (a bypass), redirection,
    privileged credential and capabilities policies, an inspection profile
    that only monitors, an unattached custom control, an application server
    in no group, business continuity with no Private Cloud Controller, and
    Branch and Cloud Connector groups (one empty), and its administration
    (admins, roles, API keys, a break-glass account, microtenants, a
    provisioning key, PRA credentials and approvals);
  - ZDX: monitored applications, devices, departments, locations;
  - ZIdentity: users, groups, resource servers;
  - ZIA Insights: one answer per Traffic insights query (aggregates only),
    the cloud application list and the licences, with high-risk
    unsanctioned apps carrying traffic and sanctioned SaaS apps with no
    SaaS Security API tenant.
  - Cloud & Branch Connector: two connector groups (one with a single
    connector, the other on two software versions), forwarding rules (one
    sends backups DIRECT), a gateway that does not fail closed, a location
    without IPS, changes waiting to be activated, admins, roles, an old
    provisioning API key (its value is a placeholder, masked on every read)
    and an AWS account.
  - AI Guard: a detect-only detection policy that inspects prompts but not
    answers, two policy match rules (one off), LLM providers, two LLM
    applications (one keeps prompts unencrypted, one has no credential) and
    credential metadata; a made-up detector for "Test a prompt";
  - Workflow Automation: DLP incidents (open, closed as false positive,
    closed as real), their triggers, change history and tickets, and the
    admin audit log. Incident times are relative to when the sample opens.
  - ZDX extras: the alert history with affected devices, a week of
    application scores and metrics (one application never reaches a good
    score) and one CloudPath; ZIdentity extras: per-admin entitlements (one
    Super Admin on four services, one disabled account still holding an
    admin entitlement) and group members.

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
ZTW = "/ztw/api/v1"
AIG = "/aiguard/v1"
ZWA = "/zwa/dlp/v1"

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
# Forwarding and traffic path (zia_forwarding, the FWD.* checks and the Path
# analyzer's Forwarding control step), with the gaps an assessment should
# find: a proxy-chaining gateway with no secondary proxy that does not fail
# closed, a connector rule sending a named host direct, an open-ended data
# centre exclusion, a GRE tunnel whose two VIPs share a data centre, IPv6
# off, a one-node Virtual Service Edge cluster and a DNS gateway with no
# secondary resolver. Addresses are from the documentation ranges (RFC 5737).
PROXY_GATEWAYS = [{"id": 1601, "name": "Partner audit proxy", "type": "PROXYCHAIN", "failClosed": False,
                   "primaryProxy": {"id": 1611, "name": "Harborline audit proxy"}}]
ZPA_GATEWAYS = [{"id": 1621, "name": "Anchor to Portland", "type": "ZPA", "zpaServerGroup": {"externalId": "2301", "name": "Portland data centre"},
                 "zpaAppSegments": [{"externalId": "2201", "name": "Freight billing"}]}]
FORWARDING_RULES = [
    {"id": 1631, "order": 1, "rank": 7, "name": "Chain partner portal", "type": "FORWARDING", "state": "ENABLED", "forwardMethod": "PROXYCHAIN",
     "destAddresses": ["portal.harborline-logistics.example"], "proxyGateway": {"id": 1601, "name": "Partner audit proxy"}},
    {"id": 1632, "order": 2, "rank": 7, "name": "Anchor billing via ZPA", "type": "FORWARDING", "state": "ENABLED", "forwardMethod": "ZPA",
     "zpaAppSegments": [{"externalId": "2201", "name": "Freight billing"}], "zpaGateway": {"id": 1621, "name": "Anchor to Portland"}},
    {"id": 1633, "order": 3, "rank": 7, "name": "Depot updates direct", "type": "EC_RDR", "state": "ENABLED", "forwardMethod": "DIRECT",
     "destAddresses": ["updates.scanner-vendor.example"]},
    {"id": 1634, "order": -1, "rank": 7, "name": "Default Forwarding Rule", "type": "FORWARDING", "state": "ENABLED", "forwardMethod": "DIRECT",
     "defaultRule": True},
]
DATACENTERS = [{"id": 1641, "name": "SEA1", "city": "Seattle"}, {"id": 1642, "name": "SJC4", "city": "San Jose"},
               {"id": 1643, "name": "LAX1", "city": "Los Angeles"}]
DC_EXCLUSIONS = [{"dcid": 1643, "dcName": {"id": 1643, "name": "LAX1"}, "description": "Spring maintenance", "expired": True,
                  "startTime": 1774000000, "endTime": 1774600000},
                 {"dcid": 1642, "dcName": {"id": 1642, "name": "SJC4"}, "description": "Latency complaints", "expired": False,
                  "startTime": 1790000000}]
GRE_TUNNELS = [
    {"id": 1651, "sourceIp": "198.51.100.10", "comment": "Portland HQ", "withinCountry": True,
     "primaryDestVip": {"id": 1661, "virtualIp": "203.0.113.101", "datacenter": "SEA1"},
     "secondaryDestVip": {"id": 1662, "virtualIp": "203.0.113.111", "datacenter": "SJC4"}},
    {"id": 1652, "sourceIp": "203.0.113.20", "comment": "Reno depot", "withinCountry": True,
     "primaryDestVip": {"id": 1663, "virtualIp": "203.0.113.112"},
     "secondaryDestVip": {"id": 1664, "virtualIp": "203.0.113.113"}},
]
VIPS = [{"cloudName": "zscaler.example", "region": "North America", "country": "United States", "city": "Seattle", "dataCenter": "SEA1",
         "greIps": ["203.0.113.101", "203.0.113.102"]},
        {"cloudName": "zscaler.example", "region": "North America", "country": "United States", "city": "San Jose", "dataCenter": "SJC4",
         "greIps": ["203.0.113.111", "203.0.113.112", "203.0.113.113"]}]
DEDICATED_IP_GATEWAYS = [{"id": 1671, "name": "Larkspur egress", "default": True,
                          "primaryDataCenter": {"id": 1641, "name": "SEA1"}, "secondaryDataCenter": {"id": 1642, "name": "SJC4"}}]
DNAT_RULES = [{"id": 1681, "order": 1, "rank": 7, "name": "Scanner relay", "state": "ENABLED", "destAddresses": ["relay.larkspur-freight.example"],
               "redirectIp": "198.51.100.40", "redirectPort": 8443}]
VZEN_CLUSTERS = [{"id": 1691, "name": "Portland VSE", "status": "ENABLED", "type": "VZEN",
                  "virtualZenNodes": [{"id": 1692, "name": "pdx-vse-1"}]}]
VZEN_NODES = [{"id": 1692, "name": "pdx-vse-1", "status": "ENABLED", "inProduction": True, "clusterName": "Portland VSE",
               "deploymentMode": "CLUSTER", "type": "VZEN"}]
DNS_GATEWAYS = [{"id": 1701, "name": "Depot resolver", "dnsGatewayType": "CUSTOM", "primaryIpOrFqdn": "198.51.100.53",
                 "failureBehavior": "FAIL_RET_ERR", "autoCreated": False}]
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
                  {"id": "2102", "name": "All internal (broad)", "enabled": True, "applications": [{"id": "2202", "name": "Everything internal"},
                                                                                                   {"id": "2205", "name": "Depot jump hosts"},
                                                                                                   {"id": "2206", "name": "Driver portal"}]}]
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
    # A Privileged Remote Access segment (RDP to the depot's jump hosts) and a
    # Browser Access segment that drivers open from their own phones.
    {"id": "2205", "name": "Depot jump hosts", "enabled": True, "domainNames": ["jump.depot.larkspur-freight.example"],
     "tcpPortRanges": ["3389", "3389"], "udpPortRanges": [], "segmentGroupId": "2102", "segmentGroupName": "All internal (broad)",
     "serverGroups": [{"id": "2302", "name": "Reno depot servers"}], "bypassType": "NEVER", "healthReporting": "ON_ACCESS",
     "doubleEncrypt": False, "commonAppsDto": {"appsConfig": [{"name": "Depot jump hosts", "appTypes": ["SECURE_REMOTE_ACCESS"]}]},
     "praApps": [{"id": "2213", "name": "Depot jump hosts", "enabled": True}]},
    {"id": "2206", "name": "Driver portal", "enabled": True, "domainNames": ["drivers.larkspur-freight.example"],
     "tcpPortRanges": ["443", "443"], "udpPortRanges": [], "segmentGroupId": "2102", "segmentGroupName": "All internal (broad)",
     "serverGroups": [{"id": "2301", "name": "Portland data centre"}], "bypassType": "NEVER", "healthReporting": "ON_ACCESS",
     "doubleEncrypt": False, "commonAppsDto": {"appsConfig": [{"name": "Driver portal", "appTypes": ["BROWSER_ACCESS"]}]},
     "clientlessApps": [{"id": "2214", "name": "Driver portal", "enabled": True, "applicationPort": "443", "applicationProtocol": "HTTPS"}]},
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
# The other ZPA policies, each with a gap the ZPA analysis finds.
CLIENT_FORWARDING_RULES = [{"id": "2961", "name": "Bypass depot jump hosts", "ruleOrder": "1", "action": "BYPASS", "policyType": "3",
                            "conditions": [{"id": "c5", "operator": "OR", "operands": [{"id": "o5", "objectType": "APP", "lhs": "id", "rhs": "2205", "name": "Depot jump hosts"}]}]}]
CAPABILITIES_RULES = [{"id": "2971", "name": "Depot admins file transfer", "ruleOrder": "1", "action": "CHECK_CAPABILITIES",
                       "conditions": [{"id": "c6", "operator": "OR", "operands": [{"id": "o6", "objectType": "APP", "lhs": "id", "rhs": "2205", "name": "Depot jump hosts"}]}],
                       "privilegedCapabilities": {"capabilities": ["CLIPBOARD_COPY", "CLIPBOARD_PASTE", "FILE_DOWNLOAD", "INSPECT_FILE_UPLOAD"]}}]
# The credential rule names the credential by reference only (no secret in the sample).
CREDENTIAL_RULES = [{"id": "2981", "name": "Depot shared login", "ruleOrder": "1", "action": "INJECT_CREDENTIALS",
                     "conditions": [{"id": "c7", "operator": "OR", "operands": [{"id": "o7", "objectType": "CONSOLE", "lhs": "id", "rhs": "3001", "name": "Depot jump console"}]}],
                     "credential": {"id": "3011", "name": "depot-admin"}}]
REDIRECTION_RULES = [{"id": "2985", "name": "Reno via the local service edge", "ruleOrder": "1", "action": "REDIRECT_PREFERRED",
                      "serviceEdgeGroups": [{"id": "2851", "name": "Reno edge (retired)"}],
                      "conditions": [{"id": "c8", "operator": "OR", "operands": [{"id": "o8", "objectType": "CLIENT_TYPE", "lhs": "id", "rhs": "zpn_client_type_zapp"}]}]}]
INSPECTION_PROFILES = [{"id": "3021", "name": "Larkspur OWASP (monitor)", "paranoiaLevel": "1",
                        "globalControlActions": ["PREDEFINED:PASS", "CUSTOM:NONE", "OVERRIDE_ACTION:COMMON"],
                        "predefinedControls": [{"id": "3022", "name": "SQL injection", "action": "PASS"}, {"id": "3023", "name": "Cross-site scripting", "action": "PASS"}]}]
CUSTOM_CONTROLS = [{"id": "3031", "name": "Block manifest export path", "action": "BLOCK", "defaultAction": "BLOCK", "severity": "HIGH",
                    "controlType": "CUSTOM", "associatedInspectionProfileNames": []}]
APP_SERVERS = [{"id": "3041", "name": "rno-billing-old", "address": "10.20.4.15", "enabled": True, "appServerGroupIds": []}]
# Business continuity is set up, but no Private Cloud Controller is deployed.
BUSINESS_CONTINUITY = [{"id": "3051", "backupEnabled": False, "switchTimeEnabled": True, "maxAllowedDownTime": "60", "maxAllowedDownTimeUnit": "MINUTES",
                        "newUserSupport": False, "useExistingIdp": True}]
BRANCH_CONNECTOR_GROUPS = [{"id": "3061", "name": "Reno depot branch", "enabled": True}]
BRANCH_CONNECTORS = [{"id": "3062", "name": "rno-bc-1", "enabled": True, "branchConnectorGroupId": "3061", "branchConnectorGroupName": "Reno depot branch"}]
CLOUD_CONNECTOR_GROUPS = [{"id": "3071", "name": "AWS us-west-2", "enabled": True, "ziaCloud": "zscalertwo.net"}]
CLOUD_CONNECTORS: List[Dict[str, Any]] = []

# ── ZDX and ZIdentity ─────────────────────────────────────────────────
# The ZDX API answers in snake_case (zscaler/zdx/models/applications.py).
ZDX_APPS = [{"id": 3001, "name": "Microsoft 365", "score": 82.0, "most_impacted_region": {"id": "us-west", "country": "United States"}, "total_users": 140},
            {"id": 3002, "name": "Freight billing", "score": 64.0, "most_impacted_region": {"id": "us-west", "country": "United States"}, "total_users": 35},
            {"id": 3003, "name": "Salesforce", "score": 91.0, "total_users": 60}]
ZDX_DEVICES = [{"id": 3101, "name": "LKF-LT-0001", "userid": 41}, {"id": 3102, "name": "LKF-MBP-0002", "userid": 42}]
ZID_USERS = [{"id": "u-41", "loginName": "avery.quinn@larkspur-freight.example", "displayName": "Avery Quinn", "status": True,
              "adminEntitlementEnabled": True, "serviceEntitlementEnabled": True},
             {"id": "u-42", "loginName": "rowan.ellis@larkspur-freight.example", "displayName": "Rowan Ellis", "status": True,
              "adminEntitlementEnabled": True, "serviceEntitlementEnabled": True},
             # A disabled account that still holds an admin entitlement: the stale-admin check finds it.
             {"id": "u-43", "loginName": "casey.morgan@larkspur-freight.example", "displayName": "Casey Morgan", "status": False,
              "adminEntitlementEnabled": True, "serviceEntitlementEnabled": False}]
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
# The Trusted Resolver gateway the ZIA baseline's DNS rule needs, beside the forwarding
# checks' custom gateway above (one list: the sample is one tenant).
DNS_GATEWAYS = DNS_GATEWAYS + [{"id": 9, "name": "Zscaler Trusted Resolver", "natZtrGateway": True}]
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


# Threat protection and SaaS Security hygiene (zscaler_full_checks THR / UF / SAAS),
# shaped like the SDK 1.11.3 models (zscaler/zia/models/<module>.py). The
# hashes are MD5s of made-up strings, not of any real file. Gaps on purpose:
# native FTP open to any site, no security review requests, SafeSearch off,
# an unused risk profile, two SaaS tenants without a malware rule, a malware
# rule that only reports.
SANDBOX_HASHES = {"md5HashValueList": [
    {"url": "e9c5e36d0445fb6d6377143ad023feba", "urlComment": "IR-2026-014 loader (made up)", "type": "CUSTOM_FILEHASH_DENY"},
    {"url": "a37ece551f269b16351c64133d9aa8a4", "urlComment": "IR-2026-019 macro (made up)", "type": "CUSTOM_FILEHASH_DENY"}]}
SANDBOX_HASH_COUNT = {"blockedFileHashesCount": 2, "remainingFileHashes": 9998}   # field names assumed (not modelled by the SDK)
IPS_SIGNATURES = [
    {"id": 7101, "name": "LKF track freight-portal scanner", "ruleText": "alert tcp any any -> any 443 (msg:\"sample\"; sid:9000001;)",
     "description": "Made-up signature", "category": "CUSTOM", "enabled": True, "deleted": False, "dynamicValidationRejected": False},
    {"id": 7102, "name": "LKF legacy beacon", "ruleText": "alert tcp any any -> any any (msg:\"old\"; sid:9000002;)",
     "description": "Made-up signature", "category": "CUSTOM", "enabled": False, "deleted": False, "dynamicValidationRejected": True}]
MOBILE_THREAT = {"blockAppsWithMaliciousActivity": True, "blockAppsWithKnownVulnerabilities": True, "blockAppsSendingUnencryptedUserCredentials": True,
                 "blockAppsSendingLocationInfo": False, "blockAppsSendingPersonallyIdentifiableInfo": True, "blockAppsSendingDeviceIdentifier": False,
                 "blockAppsCommunicatingWithAdWebsites": False, "blockAppsCommunicatingWithRemoteUnknownServers": True}
FTP_SETTINGS = {"ftpOverHttpEnabled": True, "ftpEnabled": True, "urlCategories": [], "urls": []}
EUN_SETTINGS = {"notificationType": "DEFAULT", "displayReason": True, "displayCompName": True, "displayCompLogo": False,
                "supportEmail": f"it-help@{DOMAIN}", "orgPolicyLink": f"https://intranet.{DOMAIN}/acceptable-use",
                "urlCatReviewEnabled": True, "securityReviewEnabled": False, "webDlpReviewEnabled": True, "aupFrequency": "NEVER"}
UEBA_RULES: List[Dict[str, Any]] = []
ALERT_DEFINITIONS = [{"id": 8101, "alertName": "Upload volume spike", "status": "ENABLED", "severity": "HIGH", "interval": "DAILY", "trafficChangePercent": 300}]
CUSTOM_FILE_TYPES = [{"id": 8201, "name": "Larkspur manifest", "description": "In-house shipping manifest", "extension": "lkm", "fileTypeId": 2001}]
RISK_PROFILES = [{"id": 8301, "profileName": "High-risk SaaS"}]
ADAPTIVE_ACCESS_PROFILES = [{"id": 8401, "name": "Elevated user risk", "type": "USER_RISK", "aapIndex": 1, "deleted": False}]
URL_APP_SETTINGS = {"enableDynamicContentCat": True, "considerEmbeddedSites": True, "enforceSafeSearch": False, "enableUcaasZoom": True,
                    "enableUcaasLogMeIn": False, "enableUcaasRingCentral": False, "enableUcaasWebex": True, "enableUcaasTalkdesk": False,
                    "enableChatGptPrompt": False, "enableMicrosoftCoPilotPrompt": False, "enableGeminiPrompt": False, "enablePOEPrompt": False,
                    "enableMetaPrompt": False, "enablePerPlexityPrompt": False, "blockSkype": False, "enableNewlyRegisteredDomains": True,
                    "enableBlockOverrideForNonAuthUser": False, "enableCIPACompliance": False}
CASB_MALWARE_RULES = [
    {"id": 8501, "order": 1, "name": "Box malware scan", "type": "OFLCASB_AVP_FILE", "state": "ENABLED", "action": "OFLCASB_AVP_REPORT_MALWARE",
     "cloudAppTenants": [{"id": 501, "name": "Larkspur Box"}]}]
TOMBSTONE_TEMPLATES = [{"id": 8601, "name": "Larkspur quarantine notice", "description": "Tells the owner the file was quarantined"}]
SAAS_SCAN_INFO = [
    {"tenantName": "Larkspur Box", "tenantId": 501, "saasApplication": "BOX",
     "scanInfo": {"cur_scan_start_time": 1793232000, "prev_scan_end_time": 1793145600, "scan_reset_num": 0}, "scanAction": "SCAN"},
    {"tenantName": "Larkspur Google Workspace", "tenantId": 502, "saasApplication": "GOOGLE_DRIVE",
     "scanInfo": {"cur_scan_start_time": 1793232000, "prev_scan_end_time": 1793145600, "scan_reset_num": 0}, "scanAction": "SCAN"}]
C2C_RECEIVERS = [{"id": 8701, "name": "Larkspur DLP incident bucket", "status": "ACTIVE", "lastValidationMsg": {"errorMsg": "", "errorCode": ""}}]

# ZIA Insights (Z-Insights GraphQL, POST /zins/graphql): one answer per SDK
# operation, in the shape zscaler/zins/*.py reads (offline the time window is
# not applied). Aggregates, and the per-user incidents of the sample's own
# made-up people (never kept in a snapshot of a real tenant).
# The gaps on purpose: WeTransfer, MEGA and Pastebin are unsanctioned, high
# risk and carry traffic; Slack and Salesforce are sanctioned with traffic but
# no SaaS Security API tenant; ChatGPT's sanction state is not stated.
CLOUD_APPS = [{"id": 2100 + i, "name": n} for i, n in enumerate(
    ("Box", "Google Drive", "Microsoft OneDrive", "Slack", "Salesforce", "WeTransfer", "MEGA", "Pastebin", "Dropbox", "ChatGPT", "Zoom"))]
_APPS = [  # application, category, risk index, sanctioned state, bytes up, bytes down, users
    ("Box", "File Share", 1, "Sanctioned", 9_400_000_000, 21_000_000_000, 140),
    ("Google Drive", "File Share", 2, "Sanctioned", 2_100_000_000, 6_800_000_000, 85),
    ("Microsoft OneDrive", "File Share", 1, "Sanctioned", 5_300_000_000, 12_000_000_000, 150),
    ("Slack", "Enterprise Collaboration", 2, "Sanctioned", 1_200_000_000, 3_900_000_000, 120),
    ("Salesforce", "Sales and Marketing", 1, "Sanctioned", 640_000_000, 2_700_000_000, 60),
    ("WeTransfer", "File Share", 5, "Unsanctioned", 3_800_000_000, 120_000_000, 14),
    ("MEGA", "File Share", 5, "Unsanctioned", 1_600_000_000, 900_000_000, 6),
    ("Pastebin", "Consumer", 4, "Unsanctioned", 4_000_000, 9_000_000, 9),
    ("Dropbox", "File Share", 3, "Unsanctioned", 260_000_000, 410_000_000, 11),
    ("ChatGPT", "System and Development", 4, "", 52_000_000, 310_000_000, 48),
    ("Zoom", "Enterprise Collaboration", 2, "Sanctioned", 300_000_000, 8_200_000_000, 130),
]
SHADOW_IT_APPS = [{"application": a, "application_category": c, "risk_index": r, "computed_risk_index": r, "sanctioned_state": st,
                   "integration": 0, "data_consumed": up + down, "data_uploaded": up, "data_downloaded": down, "authenticated_users": u,
                   "unAuthenticated_location_count": 0, "last_access_time": 1793404800000, "vulnerability": None, "undiscovered": False,
                   "custom_risk_index": None} for a, c, r, st, up, down, u in _APPS]


def _zins(domain: str, field: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"data": {domain: {field: {"obfuscated": False, "entries": entries}}}}


def _nt(*pairs: Any) -> List[Dict[str, Any]]:
    return [{"name": n, "total": t} for n, t in pairs]


ZINS = {
    "WebTrafficNoGrouping": _zins("WEB_TRAFFIC", "no_grouping", _nt(("TOTAL", 4_820_000))),
    "WebTrafficByLocation": _zins("WEB_TRAFFIC", "location", _nt(("Larkspur HQ (Portland)", 3_100_000), ("Reno depot", 1_200_000), ("Road warriors", 520_000))),
    "WebThreatClass": _zins("WEB_TRAFFIC", "threat_class", _nt(("Advanced Threats", 412), ("Viruses and spyware", 96), ("Behavioral analysis", 31))),
    "WebThreatSuperCategories": _zins("WEB_TRAFFIC", "threat_super_categories", _nt(("Phishing", 288), ("Malicious content", 154), ("Botnet callback", 97))),
    "ShadowITApps": _zins("SHADOW_IT", "apps", SHADOW_IT_APPS),
    "ShadowITSummary": {"data": {"SHADOW_IT": {"shadow_it_summary": {
        "total_apps": len(_APPS), "total_upload_bytes": sum(x[4] for x in _APPS), "total_download_bytes": sum(x[5] for x in _APPS),
        "total_bytes": sum(x[4] + x[5] for x in _APPS),
        "group_by_risk_index_for_app": {"obfuscated": False, "entries": _nt(("1", 3), ("2", 4), ("3", 1), ("4", 2), ("5", 2))},
        "group_by_app_cat_for_app": {"obfuscated": False, "entries": _nt(("File Share", 6), ("Enterprise Collaboration", 2), ("Consumer", 1),
                                                                          ("Sales and Marketing", 1), ("System and Development", 1))}}}}},
    "CasbAppReport": _zins("SAAS_SECURITY", "casb_app", _nt(("Box", 1840), ("Google Drive", 920), ("Microsoft OneDrive", 1310))),
    "FirewallByAction": _zins("ZERO_TRUST_FIREWALL", "action", _nt(("ALLOW", 920_000), ("BLOCK", 41_000))),
    "FirewallByLocation": _zins("ZERO_TRUST_FIREWALL", "location_firewall",
                                [{"id": 1101, "name": "Larkspur HQ (Portland)", "total": 690_000}, {"id": 1102, "name": "Reno depot", "total": 271_000}]),
    "FirewallNetworkServices": _zins("ZERO_TRUST_FIREWALL", "network_service", _nt(("DNS", 510_000), ("HTTPS", 300_000), ("NTP", 92_000), ("SSH", 1_900))),
    "CyberSecurityByLocation": _zins("CYBER_SECURITY", "cyber_security_location",
                                     [{"id": 1101, "name": "Larkspur HQ (Portland)", "total": 61}, {"id": 1102, "name": "Reno depot", "total": 23}]),
    # Made-up people of the made-up company (ZID_USERS): the page shows them on screen only.
    "CyberSecurityIncidents": _zins("CYBER_SECURITY", "incidents", _nt(("avery.quinn@larkspur-freight.example", 12),
                                                                       ("rowan.ellis@larkspur-freight.example", 5))),
    "IoTDeviceStats": {"data": {"IOT": {"device_stats": {
        "devices_count": 412, "user_devices_count": 57, "iot_devices_count": 96, "server_devices_count": 18, "un_classified_devices_count": 11,
        "entries": [{"classifications": "IP camera", "classification_uuid": "lkf-iot-1", "category": "IoT", "total": 38},
                    {"classifications": "Label printer", "classification_uuid": "lkf-iot-2", "category": "IoT", "total": 31},
                    {"classifications": "Handheld scanner", "classification_uuid": "lkf-iot-3", "category": "IoT", "total": 27}]}}}},
}
# The licences (GET /subscriptions, organization_information.get_subscriptions):
# ids as readiness.SKU_INFO knows them.
SUBSCRIPTIONS = [{"id": sid, "subscribed": True, "status": "ACTIVE", "endDate": 1830297600000} for sid in (
    "ZIA_TENANT", "URL_FILTER", "ZMAN_WEB_2_0", "ZIA_SSL", "ZIA_ATP", "ZSEC_WEB_ABA", "Z_FIREWALL_BASIC", "Z_API", "ZDLP_WEB",
    "Z_DLP_ENDPOINT", "ZS_DP_GEN_AI", "ZS_DP_EMAIL", "Z_CASB", "Z_WORKFLOW_AUTOMATION", "Z_CLOUD_NSS_WEB", "ZIA_ISO_STD",
    "ZSCALER_CLIENT_CONNECTOR", "Z_ZDX_STD")]


# ── Cloud & Branch Connector (ZTW) ──────────────────────────────────────
# Shapes from zscaler/ztw/models (ecgroup.py, forwarding_rules.py,
# forwarding_gateways.py, location_management.py, location_templates.py,
# activation.py, admin_users.py, admin_roles.py, api_keys.py,
# public_cloud_info.py, workload_groups.py). Times are epoch seconds.
EC_GROUPS = [
    {"id": 4101, "name": "Larkspur AWS us-west-2", "deployType": "CLOUD", "platform": "AWS", "formFactor": "SMALL", "status": ["ENABLED"],
     "location": {"id": 4301, "name": "AWS-us-west-2-vpc-larkspur"}, "upgradeDayOfWeek": "SUNDAY", "upgradeStartTime": {"hour": 2, "minute": 0},
     "tunnelMode": "ENCRYPTED",
     "ecVMs": [{"id": 4111, "name": "lkf-cc-usw2-a", "buildVersion": "24.3.12", "operationalStatus": "ACTIVE", "status": ["ACTIVE"], "upgradeStatus": "UPGRADED"},
               {"id": 4112, "name": "lkf-cc-usw2-b", "buildVersion": "24.2.30", "operationalStatus": "ACTIVE", "status": ["ACTIVE"], "upgradeStatus": "UPGRADE_FAILED"}]},
    {"id": 4102, "name": "Larkspur Branch Tacoma", "deployType": "BRANCH", "platform": "VMWARE", "formFactor": "SMALL", "status": ["ENABLED"],
     "location": {"id": 4302, "name": "BC-Tacoma-yard"}, "upgradeDayOfWeek": "SATURDAY", "upgradeStartTime": {"hour": 23, "minute": 0},
     "ecVMs": [{"id": 4121, "name": "lkf-bc-tacoma-1", "buildVersion": "24.3.12", "operationalStatus": "ACTIVE", "status": ["ACTIVE"], "upgradeStatus": "UPGRADED"}]},
]
ZTW_WORKLOAD_GROUPS = [
    {"id": 4201, "name": "Billing servers", "expressionJson": {"operator": "AND", "expressionContainers": [
        {"tagType": "VPC", "operator": "AND", "tagContainer": {"operator": "AND", "tags": [{"key": "Vpc-id", "value": "vpc-0larkspur1"}]}},
        {"tagType": "ATTR", "operator": "AND", "tagContainer": {"operator": "AND", "tags": [{"key": "App", "value": "billing"}]}}]}},
    {"id": 4202, "name": "Backup agents", "expressionJson": {"operator": "AND", "expressionContainers": [
        {"tagType": "ATTR", "operator": "AND", "tagContainer": {"operator": "AND", "tags": [{"key": "Role", "value": "backup"}]}}]}},
]
ZTW_FORWARDING_RULES = [
    {"id": 4401, "name": "Billing to ZPA", "order": 1, "rank": 7, "state": "ENABLED", "type": "EC_RDR", "forwardMethod": "ZPA",
     "srcWorkloadGroups": [{"id": 4201, "name": "Billing servers"}], "zpaAppSegments": [{"id": 4501, "name": "Freight billing", "externalId": "2201"}]},
    {"id": 4402, "name": "Backups direct to S3", "order": 2, "rank": 7, "state": "ENABLED", "type": "EC_RDR", "forwardMethod": "DIRECT",
     "srcWorkloadGroups": [{"id": 4202, "name": "Backup agents"}], "destAddresses": ["52.218.128.0/17"],
     "description": "Nightly backups to the S3 bucket; decided by IT in 2025."},
    {"id": 4403, "name": "Default Cloud Connector forwarding", "order": -1, "rank": 7, "state": "ENABLED", "type": "EC_RDR", "forwardMethod": "ZIA",
     "proxyGateway": {"id": 4601, "name": "Larkspur ZIA gateway"}},
]
ZTW_GATEWAYS = [{"id": 4601, "name": "Larkspur ZIA gateway", "failClosed": False, "primaryType": "AUTO", "secondaryType": "AUTO",
                 "description": "Default gateway for the AWS and branch connectors.", "lastModifiedTime": 1761000000}]
ZTW_LOCATIONS = [
    {"id": 4301, "name": "AWS-us-west-2-vpc-larkspur", "ecLocation": True, "ofwEnabled": True, "ipsControl": True, "xffForwardEnabled": True,
     "authRequired": False, "sslScanEnabled": True, "publicCloudAccountId": {"id": 4801, "name": "larkspur-prod"}, "ipAddresses": ["198.51.100.40"]},
    {"id": 4302, "name": "BC-Tacoma-yard", "ecLocation": True, "ofwEnabled": True, "ipsControl": False, "xffForwardEnabled": True,
     "authRequired": False, "ipAddresses": ["203.0.113.20"], "vpnCredentials": [{"id": 4311, "type": "UFQDN", "fqdn": "tacoma@larkspur-freight.example",
                                                                               "preSharedKey": "sample-not-a-real-key"}]},
]
ZTW_LOCATION_TEMPLATES = [{"id": 4701, "name": "Larkspur cloud template", "desc": "For new cloud connector locations.", "editable": True,
                           "template": {"templatePrefix": "lkf", "xffForwardEnabled": True, "authRequired": False, "ofwEnabled": True, "ipsControl": True,
                                        "aupEnabled": False, "cautionEnabled": False, "surrogateIP": False}}]
ZTW_ACTIVATION = {"orgEditStatus": "EDITS_PRESENT", "orgLastActivateStatus": "CAC_ACTV_UI", "adminActivateStatus": "ADM_EDITING"}
ZTW_ADMIN_ROLES = [{"id": 4901, "name": "Super Admin", "roleType": "EDGE_CONNECTOR_ADMIN", "policyAccess": "READ_WRITE", "isAuditor": False, "rank": 7},
                   {"id": 4902, "name": "Connector auditor", "roleType": "EDGE_CONNECTOR_ADMIN", "policyAccess": "READ_ONLY", "isAuditor": True, "rank": 7}]
ZTW_ADMIN_USERS = [{"id": 4911, "loginName": "it-admin@larkspur-freight.example", "userName": "IT Admin", "email": "it-admin@larkspur-freight.example",
                    "role": {"id": 4901, "name": "Super Admin"}, "disabled": False, "isPasswordLoginAllowed": False},
                   {"id": 4912, "loginName": "cloud-ops@larkspur-freight.example", "userName": "Cloud Ops", "email": "cloud-ops@larkspur-freight.example",
                    "role": {"id": 4901, "name": "Super Admin"}, "disabled": False, "isPasswordLoginAllowed": True}]
ZTW_API_KEYS = [{"id": 4951, "keyValue": "sample-placeholder-not-a-key", "enabled": True, "partner": False, "permissions": ["PROVISIONING"],
                 "lastModifiedTime": 1690000000, "lastModifiedBy": {"id": 4911, "name": "IT Admin"}}]
ZTW_ACCOUNT_DETAILS = [{"id": 4801, "awsAccountId": "000000000000", "awsRoleName": "LarkspurCloudConnectorRole", "externalId": "sample-external-id"}]
ZTW_PUBLIC_CLOUD_INFO = [{"id": 4801, "name": "larkspur-prod", "cloudType": "AWS", "permissionStatus": "VALID",
                          "regionStatus": [{"id": 1, "name": "us-west-2", "cloudType": "AWS", "status": True},
                                           {"id": 2, "name": "us-east-1", "cloudType": "AWS", "status": False}],
                          "accountGroups": [{"id": 4851, "name": "Production"}]}]

# DLP indexes (zia/models/dlp_resources.py): one EDM schema whose last upload
# failed, one IDM profile whose schedule is off and that is a year old.
EDM_SCHEMAS = [{"schemaId": 8101, "projectName": "Larkspur customer accounts", "revision": 3, "fileUploadStatus": "FAILED",
                "schemaActive": True, "origColCount": 6, "cellsUsed": 120000, "lastModifiedTime": 1767225600}]
IDM_PROFILES = [{"profileId": 8201, "profileName": "Bill of lading template", "profileType": "LOCAL", "uploadStatus": "IDM_PROF_UPLOAD_COMPLETED",
                 "scheduleDisabled": True, "numDocuments": 14, "lastModifiedTime": 1730419200}]

# Privileged Remote Access (zpa/models/pra_portal.py, pra_console.py): a portal
# with no user notification and a console whose app segment was deleted.
PRA_PORTALS = [{"id": "2701", "name": "LKF admin portal", "enabled": True, "domain": "admin.larkspur-freight.example",
                "userNotificationEnabled": False, "userPortalName": ""}]
PRA_CONSOLES = [{"id": "2711", "name": "Billing server RDP", "enabled": True,
                 "praApplication": {"appId": "2299", "name": "Billing server (deleted)"}, "praPortals": [{"id": "2701", "name": "LKF admin portal"}]}]


# ── AI Guard (zscaler/aiguard/models: camelCase as the API answers; lists in an {"items": [...]} envelope) ──
AIG_POLICIES = [
    {"id": 7101, "name": "LKF GenAI monitor", "description": "Prompts to GenAI apps, detect only",
     "inputDetectorPolicies": [
         {"detector": "prompt_injection", "enabled": True, "severity": "HIGH", "configuration": {"action": "DETECT"}},
         {"detector": "pii", "enabled": True, "severity": "MEDIUM",
          "configuration": {"action": "DETECT", "entities": [{"entityType": "US_SSN", "action": "DETECT"},
                                                             {"entityType": "CREDIT_CARD", "action": "DETECT"}]}},
         {"detector": "malicious_url", "enabled": True, "severity": "HIGH", "configuration": {"action": "DETECT"}}],
     "outputDetectorPolicies": []},
]
AIG_RULES = [
    {"id": 7201, "name": "LKF OpenAI prompts", "policyId": 7101, "enabled": True, "ruleOrder": 1,
     "matchCriteria": {"type": "APPLICATION", "llmProviders": [{"llmProvider": "Default OpenAI Provider", "llmProviderModels": []}]}},
    {"id": 7202, "name": "LKF Gemini prompts (paused)", "policyId": 7101, "enabled": False, "ruleOrder": 2,
     "matchCriteria": {"type": "APPLICATION", "llmProviders": [{"llmProvider": "Default Google Gemini Provider", "llmProviderModels": []}]}},
]
AIG_PROVIDERS = [{"id": 7301, "name": "Default OpenAI Provider"}, {"id": 7302, "name": "Default Google Gemini Provider"},
                 {"id": 7303, "name": "Default Anthropic Provider"}, {"id": 7304, "name": "Default Microsoft 365 Copilot Provider"}]
AIG_APPLICATIONS = [
    {"id": 7401, "name": "Freight quote chatbot", "ownerEmail": "avery.quinn@larkspur-freight.example", "createTimeMillis": 1767225600000,
     "updateTimeMillis": 1777593600000, "applicationSettings": {"includeEventContents": True, "encryptEventContents": False}},
    {"id": 7402, "name": "Dispatch assistant", "ownerEmail": "rowan.ellis@larkspur-freight.example", "createTimeMillis": 1772323200000,
     "updateTimeMillis": 1772323200000, "applicationSettings": {"includeEventContents": False, "encryptEventContents": False}},
]
# Metadata only, as the SDK model (llm_application_credentials.py) has no secret field.
AIG_APP_CREDENTIALS = [
    {"id": 7501, "applicationId": 7401, "providerId": 7301, "providerCredentialsId": 7601, "name": "Quote chatbot to OpenAI",
     "mode": "PROXY", "createTimeMillis": 1767225600000, "updateTimeMillis": 1767225600000},
]

# A made-up detector for "Test a prompt" on the sample: keyword rules only,
# so the answer is the same every time. Never a real AI Guard verdict.
_AIG_DETECT = (("prompt_injection", ("ignore all previous instructions", "developer mode", "system prompt")),
               ("pii", ("ssn ", "987-65-43", "4111 1111 1111 1111")),
               ("malicious_url", ("malware-drop.example",)),
               ("source_code", ("def ", "return ")))


def aiguard_detect(content: str, direction: str, policy_id: Any = None) -> Dict[str, Any]:
    """The sample's answer to AI Guard's execute-policy: the shape of
    ExecuteDetectionsPolicyResponse (aiguard/models/policy_detection.py),
    every detector of the sample policy DETECT only (it is monitor mode)."""
    text = str(content or "").lower()
    responses = {}
    for name, words in _AIG_DETECT:
        hit = any(w in text for w in words)
        responses[name] = {"triggered": hit, "action": "DETECT" if hit else "ALLOW", "severity": "HIGH" if hit and name != "source_code" else
                           ("LOW" if hit else "NONE"), "latency": 12, "details": {"note": "made-up sample detector"}}
    hit = any(v["triggered"] for v in responses.values())
    return {"transactionId": "sample-0001", "statusCode": 200, "action": "DETECT" if hit else "ALLOW",
            "severity": "HIGH" if hit else "NONE", "direction": str(direction or "IN"), "detectorErrorCount": 0,
            "detectorResponses": responses, "throttlingDetails": []}


# ── Workflow Automation DLP incidents (zscaler/zwa/models/incident_details.py) ──
# (id, days ago, channel, rule, engine, dictionary, matches, host, status, resolution, ticket?)
_INCIDENTS = (
    ("1-152-LKF-0001", 2, "WEB", "Customer data - monitor", "Larkspur Customer Data", "Larkspur Customer Account Numbers", 4,
     "telemetry.vendor-metrics.example", "OPEN", "", False),
    ("1-152-LKF-0002", 3, "WEB", "Customer data - monitor", "Larkspur Customer Data", "Larkspur Customer Account Numbers", 3,
     "telemetry.vendor-metrics.example", "OPEN", "", False),
    ("1-152-LKF-0003", 5, "WEB", "Customer data - monitor", "Larkspur Customer Data", "Larkspur Customer Account Numbers", 5,
     "telemetry.vendor-metrics.example", "CLOSED", "FALSE_POSITIVE", False),
    ("1-152-LKF-0004", 6, "WEB", "Block card data to GenAI", "PCI", "Credit Cards", 2, "chatgpt.com", "CLOSED", "TRUE_POSITIVE", True),
    ("1-152-LKF-0005", 9, "ENDPOINT", "Customer data to USB - monitor", "Larkspur Customer Data", "Larkspur Customer Account Numbers", 12,
     "", "OPEN", "", True),
    ("1-152-LKF-0006", 12, "SAAS", "Shared files with customer data", "Larkspur Customer Data", "Larkspur Customer Account Numbers", 7,
     "drive.google.com", "OPEN", "", False),
    ("1-152-LKF-0007", 20, "EMAIL", "Card data in outbound mail", "PCI", "Credit Cards", 1, "", "CLOSED", "FALSE_POSITIVE", False),
    ("1-152-LKF-0008", 40, "WEB", "Source code to the web", "Larkspur Source Code", "Larkspur Source Code Markers", 9, "pastebin.com",
     "OPEN", "", False),
)


def _iso(days_ago: float) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def zwa_answers() -> Dict[str, Any]:
    """The Workflow Automation part of the sample, keyed by path: the incident
    list (searched with POST .../incidents/search, one per GET
    .../incidents/{id}), each incident's triggers, change history and
    tickets, and the admin audit log (POST .../customer/audit). Made up."""
    out: Dict[str, Any] = {}
    incs = []
    for (iid, ago, ch, rule, engine, dic, n, host, status, res, ticket) in _INCIDENTS:
        inc = {"id": iid, "internalId": iid, "transactionId": f"tx-{iid[-4:]}", "integrationType": "INLINE" if ch != "SAAS" else "API",
               "sourceType": ch, "sourceSubType": {"WEB": "INLINE_WEB", "ENDPOINT": "REMOVABLE_MEDIA", "SAAS": "GOOGLE_DRIVE",
                                                   "EMAIL": "SMTP"}[ch],
               "sourceActions": ["ALLOW" if "monitor" in rule.lower() or ch == "SAAS" else "BLOCK"],
               "severity": "HIGH" if n >= 5 else "MEDIUM", "priority": "P2", "matchCount": n,
               "createdAt": _iso(ago), "lastUpdatedAt": _iso(max(ago - 1, 0)), "sourceFirstObservedAt": _iso(ago), "sourceLastObservedAt": _iso(ago),
               "metadataFileUrl": "https://evidence.larkspur-freight.example/meta/" + iid, "status": status, "resolution": res, "closedCode": res,
               "assignedAdmin": "dlp-analyst@larkspur-freight.example",
               "labels": [{"key": "team", "value": "dlp"}], "notes": [{"body": "Analyst note about the customer record", "createdBy": "analyst"}]
               if status == "CLOSED" else [],
               "matchingPolicies": {"rules": [{"name": rule}], "engines": [{"name": engine}],
                                    "dictionaries": [{"name": dic, "matchCount": n, "nameMatchCount": n}]},
               "userInfo": {"name": "Sample User", "email": "sample.user@larkspur-freight.example", "department": "Operations"},
               "applicationInfo": {"url": f"https://{host}/upload" if host else "", "name": host or ("USB drive" if ch == "ENDPOINT" else "Outbound mail"),
                                   "hostnameOrApplication": host, "category": "Web" if host else ""},
               "contentInfo": {"fileName": "customer-export.csv", "fileType": "CSV"},
               "networkInfo": {"clientIP": "10.20.30.40"},
               "dlpIncidentTickets": ([{"ticketType": "SERVICENOW", "ticketingSystemName": "ServiceNow", "projectName": "DLP",
                                        "ticketInfo": {"ticketId": "INC00" + iid[-4:], "state": "In progress",
                                                       "ticketUrl": "https://tickets.larkspur-freight.example/" + iid}}] if ticket else [])}
        incs.append(inc)
        out[f"{ZWA}/incidents/{iid}/triggers"] = {"rules": [{"name": rule, "matchCount": n}], "engines": [{"name": engine, "matchCount": n}],
                                                  "dictionaries": [{"name": dic, "matchCount": n}],
                                                  "matchedContent": "THIS IS SAMPLE EVIDENCE AND MUST NEVER BE SHOWN"}
        hist = [f"Incident created by rule {rule}"] + ([f"Status changed from OPEN to CLOSED ({res}) by dlp-analyst@larkspur-freight.example"]
                                                       if status == "CLOSED" else [])
        out[f"{ZWA}/incidents/{iid}/change-history"] = {"incidentId": iid, "startDate": _iso(ago), "endDate": _iso(0), "changeHistory": hist}
        out[f"{ZWA}/incidents/{iid}/tickets"] = {"tickets": inc["dlpIncidentTickets"]}
    out[f"{ZWA}/incidents"] = incs
    out[f"{ZWA}/customer/audit"] = {"logs": [
        {"time": _iso(1), "adminName": "dlp-analyst@larkspur-freight.example", "action": {"action": "UPDATE"}, "module": "Incidents",
         "resource": "Incident 1-152-LKF-0003"},
        {"time": _iso(4), "adminName": "it-admin@larkspur-freight.example", "action": {"action": "CREATE"}, "module": "Workflows",
         "resource": "Workflow: notify the manager"},
        {"time": _iso(8), "adminName": "it-admin@larkspur-freight.example", "action": {"action": "UPDATE"}, "module": "Integrations",
         "resource": "ServiceNow integration"}]}
    return out


def _ent(service: str, role: str, scope: str = "Organization") -> Dict[str, Any]:
    """One admin entitlement as ZIdentity answers it (zscaler/zid/models/user_entitlement.py Entitlement)."""
    return {"roles": [{"id": f"r-{role.lower().replace(' ', '-')}", "name": role, "displayName": role}],
            "service": {"id": f"s-{service.lower()}", "serviceName": service, "cloudName": "zscalertwo.net", "orgName": COMPANY},
            "scope": {"id": f"sc-{scope.lower()}", "name": scope, "displayName": scope}}


# Per-admin entitlements (GET /users/{id}/admin-entitlements): one admin is
# Super Admin on four services (broad), one is a read-only auditor on ZIA.
ZID_ADMIN_ENTITLEMENTS = {
    "u-41": [_ent("ZIA", "Super Admin"), _ent("ZPA", "Super Admin"), _ent("ZDX", "Super Admin"), _ent("ZCC", "Super Admin")],
    "u-42": [_ent("ZIA", "Auditor")],
    "u-43": [_ent("ZIA", "Policy Admin")],
}
ZID_GROUP_MEMBERS = {"g-33": ["u-42"], "g-34": ["u-41"]}

# ── ZDX history, scores, metrics, cloud path ─────────────────────────
ZDX_ALERTS_HISTORY = [
    {"id": "7401", "rule_name": "Freight billing score below 50", "severity": "critical", "alert_type": "APP_SCORE", "alert_status": "ENDED",
     "application": {"id": 3002, "name": "Freight billing"}, "started_on": 1792915200, "ended_on": 1792929600,
     "locations": [{"id": 1101, "name": "Larkspur HQ (Portland)"}], "departments": [], "geolocations": []},
    {"id": "7402", "rule_name": "Wi-Fi signal weak", "severity": "warning", "alert_type": "DEVICE_WIFI", "alert_status": "ENDED",
     "started_on": 1793001600, "ended_on": 1793008800, "locations": [], "departments": [], "geolocations": []},
]
ZDX_AFFECTED_DEVICES = {"7401": [{"id": 3101, "name": "LKF-LT-0001", "userid": 41}, {"id": 3102, "name": "LKF-MBP-0002", "userid": 42}],
                        "7402": [{"id": 3102, "name": "LKF-MBP-0002", "userid": 42}]}


def _trend(values: List[float], metric: str = "score", unit: str = "") -> Dict[str, Any]:
    start = 1792540800   # one point a day for a week (made-up epoch seconds)
    return {"metric": metric, "unit": unit, "datapoints": [{"timestamp": start + i * 86400, "value": v} for i, v in enumerate(values)]}


# Freight billing never reaches 66 all week (the score check finds it);
# its availability and page fetch time are poor too (the metrics check).
ZDX_SCORES = {3001: _trend([80, 84, 79, 83, 82, 81, 85]), 3002: _trend([61, 63, 58, 64, 60, 62, 65]), 3003: _trend([90, 92, 91, 89, 93, 90, 91])}
ZDX_METRICS = {3001: [_trend([1800, 1700, 1900, 1750, 1820, 1780, 1690], "pft", "ms"), _trend([100, 100, 99.9, 100, 100, 100, 100], "availability", "%")],
               3002: [_trend([6100, 5900, 6400, 5800, 6200, 6000, 5950], "pft", "ms"), _trend([97, 98, 96, 98, 97, 99, 97], "availability", "%")],
               3003: [_trend([1200, 1100, 1250, 1180, 1220, 1150, 1170], "pft", "ms"), _trend([100, 100, 100, 100, 100, 100, 100], "availability", "%")]}
# The CloudPath probe of Freight billing on one device, and the path it measured
# (zscaler/zdx/models/devices.py DeviceCloudPathProbesHopData / CloudPath / Hops).
ZDX_CLOUDPATH_PROBES = [{"id": 9101, "name": "Freight billing CloudPath", "num_probes": 24,
                         "avg_latencies": [{"leg_src": "client", "leg_dst": "egress", "latency": 4.1}]}]
ZDX_CLOUDPATH = [{"timestamp": 1793001600, "cloudpath": [
    {"src": "client", "dst": "egress", "num_hops": 2, "latency": 4.1, "loss": 0.0, "num_unresp_hops": 0, "tunnel_type": "",
     "hops": [{"ip": "192.168.1.1", "gw_mac": "00:00:5e:00:53:01", "gw_mac_vendor": "Example Networks", "pkt_sent": 10, "pkt_rcvd": 10,
               "latency_min": 1.2, "latency_max": 3.0, "latency_avg": 1.9, "latency_diff": 1.9},
              {"ip": "198.51.100.1", "pkt_sent": 10, "pkt_rcvd": 10, "latency_min": 3.0, "latency_max": 5.4, "latency_avg": 4.1, "latency_diff": 2.2}]},
    {"src": "egress", "dst": "zen", "num_hops": 4, "latency": 18.6, "loss": 0.0, "num_unresp_hops": 1, "tunnel_type": "ZTUNNEL_2_0",
     "hops": [{"ip": "198.51.100.9", "pkt_sent": 10, "pkt_rcvd": 10, "latency_avg": 9.8},
              {"ip": "203.0.113.70", "pkt_sent": 10, "pkt_rcvd": 10, "latency_avg": 18.6}]},
    {"src": "zen", "dst": "app", "num_hops": 9, "latency": 96.3, "loss": 2.5, "num_unresp_hops": 3, "tunnel_type": "",
     "hops": [{"ip": "203.0.113.80", "pkt_sent": 10, "pkt_rcvd": 10, "latency_avg": 21.0},
              {"ip": "203.0.113.141", "pkt_sent": 10, "pkt_rcvd": 9, "latency_avg": 96.3}]}]}]

# ── Client Connector: process-based and custom IP-based bypass apps ───
# One narrow process bypass and one broad one (a wildcard and interpreters);
# one narrow custom IP app and one that bypasses a /8 on every port.
ZCC_PROCESS_APPS = {"appIdentities": [
    {"id": 6001, "appName": "Depot scanner agent", "fileNames": ["scanagent.exe"], "filePaths": ["C:\\Program Files\\Depot Scan\\"],
     "matchingCriteria": 1},
    {"id": 6002, "appName": "Contractor tools", "fileNames": ["powershell.exe", "python.exe", "*.exe"], "filePaths": [], "matchingCriteria": 1}]}
ZCC_CUSTOM_IP_APPS = {"customAppContracts": [
    {"id": 5001, "appName": "Depot printers", "active": True, "uid": "c-5001",
     "appDataBlob": [{"proto": "TCP", "port": "9100", "ipaddr": "10.20.30.0/24", "fqdn": ""}]},
    {"id": 5002, "appName": "Legacy partner network", "active": True, "uid": "c-5002",
     "appDataBlob": [{"proto": "", "port": "", "ipaddr": "10.0.0.0/8", "fqdn": ""}, {"proto": "UDP", "port": "1-65535", "ipaddr": "0.0.0.0/0", "fqdn": ""}]}]}
# getDeviceDetails per udid (zscaler/zcc/models/devices.py DeviceDetails); the OTPs
# and identifiers are invented and are never shown by the app.
ZCC_DEVICE_DETAILS = {
    "LKF-WIN-0001": {"id": 1, "internal_model": "Latitude 7440", "serialNumber": "SN-INVENTED-0001", "externalDeviceId": "ext-0001",
                     "ziaEnabled": 1, "ziaHealth": "Active", "zpaEnabled": 1, "zpaHealth": "Active", "zpaLastSeenTime": "2026-10-27 18:05:11",
                     "zdxEnabled": 1, "zdxHealth": "Active", "zdxLastSeenTime": "2026-10-27 18:04:00", "zdEnabled": 0, "zdpEnabled": 1,
                     "zdpHealth": "Active", "zdpVersion": "4.5.0.12", "strictEnforcement": 1, "antiTamperingStatus": "ON", "vdi": 0,
                     "zccTunnelVersion": "Z-Tunnel 2.0", "zccUpgradeStatus": "UP_TO_DATE", "expectedZCCVersion": "4.5.0.334",
                     "zccLoggedInUserType": "USER", "deviceTrust": "HIGH", "deviceOtpArray": ["000000", "111111"]},
    "LKF-WIN-0003": {"id": 3, "internal_model": "ThinkPad T14", "serialNumber": "SN-INVENTED-0003", "ziaEnabled": 1, "ziaHealth": "Inactive",
                     "zpaEnabled": 0, "zdxEnabled": 1, "zdxHealth": "Error", "strictEnforcement": 0, "antiTamperingStatus": "OFF",
                     "zccTunnelVersion": "Z-Tunnel 1.0", "zccUpgradeStatus": "PENDING", "expectedZCCVersion": "4.5.0.334",
                     "deviceTrust": "LOW", "deviceOtpArray": ["222222"]},
}
# downloadDisableReasons (CSV; the header the SDK checks for begins "User","Device type").
ZCC_DISABLE_REASONS_CSV = (
    '"User","Device type","Device model","Disable reason","Disable time","Service"\r\n'
    '"avery.quinn@larkspur-freight.example","Windows","Latitude 7440","Troubleshooting a site","2026-10-21 09:12:00","ZIA"\r\n'
    '"jordan.blake@larkspur-freight.example","Windows","ThinkPad T14","VPN conflict","2026-10-22 14:30:00","ZIA"\r\n'
    '"jordan.blake@larkspur-freight.example","Windows","ThinkPad T14","VPN conflict","2026-10-25 08:02:00","ZPA"\r\n'
    '"rowan.ellis@larkspur-freight.example","macOS","MacBook Pro","Slow network","2026-10-26 16:45:00","ZIA"\r\n')


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
        f"{ZIA}/tenancyRestrictionProfile": [], f"{ZIA}/greTunnels": GRE_TUNNELS, f"{ZIA}/staticIP": [], f"{ZIA}/vpnCredentials": [],
        f"{ZIA}/forwardingRules": FORWARDING_RULES, f"{ZIA}/proxyGateways": PROXY_GATEWAYS, f"{ZIA}/zpaGateways": ZPA_GATEWAYS,
        f"{ZIA}/datacenters": DATACENTERS, f"{ZIA}/dcExclusions": DC_EXCLUSIONS, f"{ZIA}/vips": VIPS,
        f"{ZIA}/ipv6config": {"id": 1, "ipV6Enabled": False, "natPrefixes": []}, f"{ZIA}/ipv6config/nat64prefix": [],
        f"{ZIA}/dedicatedIPGateways/lite": DEDICATED_IP_GATEWAYS, f"{ZIA}/dnatRules": DNAT_RULES,
        f"{ZIA}/virtualZenClusters": VZEN_CLUSTERS, f"{ZIA}/virtualZenNodes": VZEN_NODES, f"{ZIA}/dnsGateways": DNS_GATEWAYS,
        f"{ZIA}/status": {"status": "ACTIVE"},
        f"{ZIA}/intermediateCaCertificate": ZIA_CA_CERTIFICATES,
        f"{ZIA}/cyberThreatProtection/advancedThreatSettings": {"riskTolerance": 40, "cmdCtlServerBlocked": True, "malwareSitesBlocked": True,
                                                                "knownPhishingSitesBlocked": True, "suspectAdwareSpywareSitesBlocked": True},
        f"{ZIA}/cyberThreatProtection/malwareSettings": {"virusBlocked": True, "unwantedApplicationsBlocked": True, "trojanBlocked": True,
                                                         "wormBlocked": True, "ransomwareBlocked": True, "spywareBlocked": True},
        # Threat protection and SaaS Security hygiene
        f"{ZIA}/behavioralAnalysisAdvancedSettings": SANDBOX_HASHES,
        f"{ZIA}/behavioralAnalysisAdvancedSettings/fileHashCount": SANDBOX_HASH_COUNT,
        f"{ZIA}/ipsSignatureRules": IPS_SIGNATURES,
        f"{ZIA}/mobileAdvanceThreatSettings": MOBILE_THREAT,
        f"{ZIA}/ftpSettings": FTP_SETTINGS,
        f"{ZIA}/eun": EUN_SETTINGS,
        f"{ZIA}/alertRuleConfiguration/uebaRules": UEBA_RULES,
        f"{ZIA}/alertDefinitions": ALERT_DEFINITIONS,
        f"{ZIA}/customFileTypes": CUSTOM_FILE_TYPES,
        f"{ZIA}/riskProfiles/lite": RISK_PROFILES,
        f"{ZIA}/adaptiveAccessProfiles": ADAPTIVE_ACCESS_PROFILES,
        f"{ZIA}/advancedUrlFilterAndCloudAppSettings": URL_APP_SETTINGS,
        f"{ZIA}/casbMalwareRules/all": CASB_MALWARE_RULES,
        f"{ZIA}/quarantineTombstoneTemplate/lite": TOMBSTONE_TEMPLATES,
        f"{ZIA}/casbTenant/scanInfo": SAAS_SCAN_INFO,
        f"{ZIA}/cloudToCloudIR/lite": C2C_RECEIVERS,
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
        f"{ZPA1}/inspectionProfile": _zpa(INSPECTION_PROFILES), f"{ZPA1}/isolation/profiles": _zpa([]), f"{ZPA1}/browserProtectionProfile": _zpa([]),
        f"{ZPA1}/inspectionControls/custom": _zpa(CUSTOM_CONTROLS), f"{ZPA1}/server": _zpa(APP_SERVERS),
        f"{ZPA1}/businessContinuitySettings": _zpa(BUSINESS_CONTINUITY),
        f"{ZPA1}/privateCloud": _zpa([]), f"{ZPA1}/privateCloudControllerGroup": _zpa([]), f"{ZPA1}/privateCloudController": _zpa([]),
        f"{ZPA1}/branchConnectorGroup": _zpa(BRANCH_CONNECTOR_GROUPS), f"{ZPA1}/branchConnector": _zpa(BRANCH_CONNECTORS),
        f"{ZPA1}/cloudConnectorGroup": _zpa(CLOUD_CONNECTOR_GROUPS), f"{ZPA1}/cloudConnector": _zpa(CLOUD_CONNECTORS),
        f"{ZPA1}/praConsole": _zpa(PRA_CONSOLES), f"{ZPA1}/praPortal": _zpa(PRA_PORTALS), f"{ZPA1}/userPortal": _zpa([]),
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
        f"{ZPA1}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY": _zpa(CLIENT_FORWARDING_RULES),
        f"{ZPA1}/policySet/rules/policyType/INSPECTION_POLICY": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/ISOLATION_POLICY": _zpa([]),
        f"{ZPA1}/policySet/rules/policyType/REDIRECTION_POLICY": _zpa(REDIRECTION_RULES),
        f"{ZPA1}/policySet/rules/policyType/CREDENTIAL_POLICY": _zpa(CREDENTIAL_RULES),
        f"{ZPA1}/policySet/rules/policyType/CAPABILITIES_POLICY": _zpa(CAPABILITIES_RULES),
        f"{ZPA1}/policySet/rules/policyType/CLIENTLESS_SESSION_PROTECTION_POLICY": _zpa([]),
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
        # Cloud & Branch Connector (ztw_overview.PATHS)
        f"{ZTW}/ecgroup": EC_GROUPS, f"{ZTW}/ecRules/ecRdr": ZTW_FORWARDING_RULES, f"{ZTW}/workloadGroups": ZTW_WORKLOAD_GROUPS,
        f"{ZTW}/ipSourceGroups": [], f"{ZTW}/ipDestinationGroups": [], f"{ZTW}/gateways": ZTW_GATEWAYS,
        f"{ZTW}/location": ZTW_LOCATIONS, f"{ZTW}/locationTemplate": ZTW_LOCATION_TEMPLATES, f"{ZTW}/ecAdminActivateStatus": ZTW_ACTIVATION,
        f"{ZTW}/adminRoles": ZTW_ADMIN_ROLES, f"{ZTW}/adminUsers": ZTW_ADMIN_USERS, f"{ZTW}/apiKeys": ZTW_API_KEYS,
        f"{ZTW}/publicCloudAccountDetails": ZTW_ACCOUNT_DETAILS, f"{ZTW}/publicCloudInfo": ZTW_PUBLIC_CLOUD_INFO,
        # AI Guard
        f"{AIG}/detections/policies": {"items": AIG_POLICIES},
        f"{AIG}/detections/policy-match-rules": {"items": AIG_RULES},
        f"{AIG}/llm-providers": {"items": AIG_PROVIDERS},
        f"{AIG}/llm-applications": {"items": AIG_APPLICATIONS},
        f"{AIG}/llm-application-credentials": {"items": AIG_APP_CREDENTIALS},
        # ZIA DLP indexes (zia/dlp_resources.py: list_edm_schemas, list_dlp_idm_profiles)
        f"{ZIA}/dlpExactDataMatchSchemas": EDM_SCHEMAS,
        f"{ZIA}/idmprofile": IDM_PROFILES,
        # ZDX alert history (14 days) and the application scores and metrics of the week
        f"{ZDX}/alerts/historical": {"alerts": ZDX_ALERTS_HISTORY, "next_offset": None},
        f"{ZDX}/analysis": [],
        # Client Connector bypass apps
        f"{ZCC}/process-based-apps": ZCC_PROCESS_APPS,
        f"{ZCC}/custom-ip-based-apps": ZCC_CUSTOM_IP_APPS,
    }
    r[f"{ZIA}/cloudApplications/lite"] = CLOUD_APPS
    r[f"{ZIA}/subscriptions"] = SUBSCRIPTIONS
    for op, body in ZINS.items():
        r[f"/zins/graphql/{op}"] = body
    r.update(zwa_answers())
    for aid, devs in ZDX_AFFECTED_DEVICES.items():
        r[f"{ZDX}/alerts/{aid}/affected_devices"] = {"devices": devs, "next_offset": None}
    for app_id, trend in ZDX_SCORES.items():
        r[f"{ZDX}/apps/{app_id}/score"] = trend
        r[f"{ZDX}/apps/{app_id}/metrics"] = ZDX_METRICS.get(app_id, [])
    for dev in ZDX_DEVICES:
        r[f"{ZDX}/devices/{dev['id']}/apps/3002/cloudpath-probes"] = ZDX_CLOUDPATH_PROBES
        r[f"{ZDX}/devices/{dev['id']}/apps/3002/cloudpath-probes/9101/cloudpath"] = ZDX_CLOUDPATH
    for uid, ents in ZID_ADMIN_ENTITLEMENTS.items():
        r[f"{ZID}/users/{uid}/admin-entitlements"] = ents
    users = {u["id"]: u for u in ZID_USERS}
    for gid, members in ZID_GROUP_MEMBERS.items():
        recs = [{k: users[m][k] for k in ("id", "loginName", "displayName", "status")} for m in members]
        r[f"{ZID}/groups/{gid}/users"] = {"records": recs, "results_total": len(recs)}
    # getDeviceDetails answers one device per udid query (offline_tenant picks it from this list).
    r[f"{ZCC}/getDeviceDetails"] = [dict(det, udid=udid) for udid, det in ZCC_DEVICE_DETAILS.items()]
    r[f"{ZCC}/downloadDisableReasons"] = ZCC_DISABLE_REASONS_CSV
    for rule_type in CAC_RULE_TYPES:
        r[f"{ZIA}/webApplicationRules/{rule_type}"] = CAC_RULES.get(rule_type, [])
    r.update(other_products())
    for path, body in builder_catalogues().items():
        r.setdefault(path, body)
    return copy.deepcopy(r)


# ── Other Zscaler products (other_products.py): ZTB, EASM, ZBI, ZCell, ZMS.
# Wire shapes as the SDK's response envelopes expect them (oneapi_response):
# ZTB {"result": {...: [...]}} in snake_case, EASM {"results": [...]}, ZBI a
# list, ZCell {"content": [...]} or one object, ZMS GraphQL {"data": {...}}
# (offline, a query is answered from /zms/graphql/<operationName>). Made up,
# with some things to fix so every check has something to show. No secret:
# the provisioning keys and site secret are absent, as the app drops them.
OP_ZTB2, OP_ZTB3 = "/ztb/api/v2", "/ztb/api/v3"
OP_EASM = "/easm/easm-ui/v1"
OP_ZBI = "/bi/api/v1"
OP_ZCELL = "/zcell/config/api/v1/customers/{zcellCustomerId}"
OP_ZMS = "/zms/graphql"
EASM_ORG = "org-larkspur-0001"


def _gql(field: str, nodes: Any, page: bool = True) -> Dict[str, Any]:
    if not page:
        return {"data": {field: nodes}}
    return {"data": {field: {"nodes": nodes, "pageInfo": {"pageNumber": 1, "pageSize": 500, "totalCount": len(nodes), "totalPages": 1}}}}


def other_products() -> Dict[str, Any]:
    """The sample's answers for the five other products (other_products.py)."""
    day = 86400
    now = 1793404800   # 2026-10-31 00:00 UTC, fixed so the sample reads the same every day
    return {
        f"{OP_ZTB2}/Site": {"result": {"count": 3, "sites": [
            {"id": "site-1", "name": "pdx-depot", "display_name": "Portland depot", "site_status": "online", "gateway_type": "hardware",
             "template_id": "tpl-1", "clusters": [{"cluster_id": "c1"}, {"cluster_id": "c2"}]},
            {"id": "site-2", "name": "sea-yard", "display_name": "Seattle yard", "site_status": "online", "gateway_type": "hardware",
             "template_id": "tpl-1", "clusters": [{"cluster_id": "c3"}]},
            {"id": "site-3", "name": "boi-dock", "display_name": "Boise dock", "site_status": "offline", "gateway_type": "virtual",
             "template_id": "", "clusters": [{"cluster_id": "c4"}]}]}},
        f"{OP_ZTB3}/templates": {"result": {"count": 1, "templates": [
            {"id": "tpl-1", "name": "Depot standard", "deployment_type": "ha", "platform_type": "hardware", "is_default": True,
             "sites_count": 2, "nat_enabled": True, "dhcp_service": "server"}]}},
        f"{OP_ZTB2}/groups": {"result": {"count": 2, "groups": [
            {"group_id": "g1", "name": "scanners", "display_name": "Handheld scanners", "type": "device", "members_count": 41, "policy_count": 2},
            {"group_id": "g2", "name": "cameras", "display_name": "Yard cameras", "type": "device", "members_count": 12, "policy_count": 1}]}},
        f"{OP_ZTB2}/alarm": {"result": {"totalAlarmsCount": 2, "alarms": [
            {"alarm_id": "a1", "site_name": "Boise dock", "severity": "critical", "status": "open", "service": "gateway",
             "description": "Gateway unreachable for more than 15 minutes", "recommended_action": "Check the uplink and power",
             "created_at": now - 3 * day},
            {"alarm_id": "a2", "site_name": "Portland depot", "severity": "low", "status": "acknowledged", "service": "dhcp",
             "description": "DHCP pool 80% used", "recommended_action": "Widen the pool", "created_at": now - 9 * day}]}},
        f"{OP_ZTB3}/api-key-auth/list": {"count": 2, "rows": [
            {"id": "k1", "name": "terraform-ci", "created_at": now - 500 * day},
            {"id": "k2", "name": "siem-export", "created_at": now - 40 * day}]},
        f"{OP_ZTB3}/CloudGateway/hubs": {"result": [
            {"location": "us-west", "location_display_name": "US West (Hillsboro)", "region": "us-west-2", "sites": ["site-1", "site-2"],
             "cluster_info": {"cluster_name": "hub-west", "gateways": [{"gateway_name": "hub-west-a"}, {"gateway_name": "hub-west-b"}]}}]},
        f"{OP_ZTB3}/device/operating-systems": {"result": [
            {"os_name": "Android", "devices": 41, "versions": [{"version": "13", "devices": 30}, {"version": "12", "devices": 11}]},
            {"os_name": "Embedded Linux", "devices": 12, "versions": [{"version": "4.19", "devices": 12}]}]},
        f"{OP_ZTB3}/ransomware-kill/state": {"result": {"state": "green"}},
        f"{OP_EASM}/organizations": {"results": [{"id": EASM_ORG, "name": COMPANY}], "total_results": 1},
        f"{OP_EASM}/organizations/{EASM_ORG}/findings": {"results": [
            {"id": "f1", "name": "Outdated web server with known vulnerabilities", "category": "Vulnerable software", "risk_level": "Critical",
             "impacted_asset_name": f"tracking.{DOMAIN}", "status": "open", "first_seen": now - 40 * day, "cisa_likelihood": "high",
             "epss_likelihood": 0.81},
            {"id": "f2", "name": "TLS certificate expires within 30 days", "category": "Certificates", "risk_level": "Medium",
             "impacted_asset_name": f"portal.{DOMAIN}", "status": "open", "first_seen": now - 5 * day},
            {"id": "f3", "name": "Remote desktop exposed to the internet", "category": "Exposed services", "risk_level": "High",
             "impacted_asset_name": f"rdp.{DOMAIN}", "status": "remediated", "first_seen": now - 90 * day}], "total_results": 3},
        f"{OP_EASM}/organizations/{EASM_ORG}/lookalike-domains": {"results": [
            {"lookalike_raw": "larksupr-freight.example", "original_domain": DOMAIN, "is_registered": True, "risk_category": "High",
             "deception_method": "Transposition", "status": "open"},
            {"lookalike_raw": "larkspur-freiqht.example", "original_domain": DOMAIN, "is_registered": False, "risk_category": "Low",
             "deception_method": "Homoglyph", "status": "open"}], "total_results": 2},
        f"{OP_ZBI}/customapps": [
            {"id": 1, "name": "Larkspur dispatch", "associatedAppCategory": "Business", "signatures": [{"type": "DOMAIN", "matchLevel": "EXACT", "value": f"dispatch.{DOMAIN}"}]},
            {"id": 2, "name": "Fleet telematics", "associatedAppCategory": "Business", "signatures": []}],
        f"{OP_ZBI}/reports/customapps": [
            {"id": 11, "name": "Monthly SaaS use", "sub_type": "OVERVIEW", "enabled": True, "status": "ACTIVE",
             "schedule_params": {"frequency": "MONTHLY", "timezone": "America/Los_Angeles"},
             "delivery_information": {"delivery_method": "EMAIL", "emails": ["it-leads@larkspur-freight.example"]}}],
        f"{OP_ZBI}/report/all": {"reportType": "APPLICATION", "reports": [{"fileName": "saas-use-2026-09.csv", "reportType": "APPLICATION"}]},
        OP_ZCELL: {"id": "zc-72000001", "name": COMPANY, "isActivated": True, "zia": {"orgId": 7200001, "cloudName": "zscalertwo"},
                   "zpa": None, "totalSims": 60, "activeSims": 42, "inactiveSims": 18},
        f"{OP_ZCELL}/regions": [{"region": "us-west", "configured": True}, {"region": "us-east", "configured": False}],
        f"{OP_ZCELL}/sim-location-groups": {"content": [
            {"id": "lg1", "name": "Portland depot geofence", "trackedDevices": ["sim-a", "sim-b", "sim-c"]},
            {"id": "lg2", "name": "Seattle yard geofence", "trackedDevices": ["sim-d"]}], "totalElements": 2, "totalPages": 1},
        f"{OP_ZCELL}/anomaly-policy": {"content": [
            {"id": "ap1", "policyName": "Trailer left depot", "policyType": "GEOFENCE", "enabled": True, "runningStatus": "RUNNING",
             "violations": 2, "jsonData": {"alerts": [{"alertType": "EMAIL", "recipients": ["fleet-ops@larkspur-freight.example"]}]}},
            {"id": "ap2", "policyName": "Night-time movement", "policyType": "GEOFENCE", "enabled": True, "runningStatus": "RUNNING",
             "violations": 0, "jsonData": {"alerts": []}}], "totalElements": 2, "totalPages": 1},
        f"{OP_ZCELL}/sim/analytics/summary": {"total": 60, "used": 44, "active": 42, "inactive": 18},
        f"{OP_ZMS}/ListAgents": _gql("agents", [
            {"name": "db-pdx-01", "eyezId": "e1", "connectionStatus": "CONNECTED", "agentType": "SERVER", "hostOs": "Ubuntu 22.04",
             "currentSoftwareVersion": "2.4.1", "upgradeStatus": "UP_TO_DATE", "agentGroupName": "Databases", "adminStatus": "ENABLED"},
            {"name": "app-pdx-02", "eyezId": "e2", "connectionStatus": "CONNECTED", "agentType": "SERVER", "hostOs": "Windows Server 2022",
             "currentSoftwareVersion": "2.4.1", "upgradeStatus": "UP_TO_DATE", "agentGroupName": "App servers", "adminStatus": "ENABLED"},
            {"name": "legacy-ftp", "eyezId": "e3", "connectionStatus": "DISCONNECTED", "agentType": "SERVER", "hostOs": "CentOS 7",
             "currentSoftwareVersion": "2.1.0", "upgradeStatus": "OUTDATED", "agentGroupName": "App servers", "adminStatus": "ENABLED"}]),
        f"{OP_ZMS}/AgentConnectionStatusStats": _gql("agentConnectionStatusStatistics", {"totalCount": 3, "totalPercentage": 100, "agentStatuses": [
            {"agentType": "SERVER", "connectionStatus": "CONNECTED", "count": 2, "percentage": 66.7},
            {"agentType": "SERVER", "connectionStatus": "DISCONNECTED", "count": 1, "percentage": 33.3}]}, page=False),
        f"{OP_ZMS}/AgentVersionStats": _gql("agentVersionStatistics", {"totalCount": 3, "totalPercentage": 100, "agentVersions": [
            {"agentType": "SERVER", "version": "2.4.1", "count": 2, "percentage": 66.7},
            {"agentType": "SERVER", "version": "2.1.0", "count": 1, "percentage": 33.3}]}, page=False),
        f"{OP_ZMS}/ListAgentGroups": _gql("agentGroups", [
            {"name": "Databases", "eyezId": "g1", "agentGroupType": "SERVER", "agentCount": 1, "tamperProtectionStatus": "ENABLED",
             "agentAutoUpgrade": True, "policyStatus": "ENFORCED", "versionProfileName": "Stable"},
            {"name": "App servers", "eyezId": "g2", "agentGroupType": "SERVER", "agentCount": 2, "tamperProtectionStatus": "DISABLED",
             "agentAutoUpgrade": False, "policyStatus": "MONITOR", "versionProfileName": "Stable"}]),
        f"{OP_ZMS}/ListNonces": _gql("nonces", [
            {"eyezId": "n1", "name": "db-rollout", "maxUsage": 5, "usageCount": 1, "agentGroupName": "Databases", "product": "ZMS"},
            {"eyezId": "n2", "name": "anything-goes", "maxUsage": 0, "usageCount": 2, "agentGroupName": "App servers", "product": "ZMS"}]),
        f"{OP_ZMS}/ListPolicyRules": _gql("policyRules", [
            {"id": "r1", "name": "App to database", "action": "ALLOW", "priority": 1, "sourceTargetType": "APP_ZONE",
             "destinationTargetType": "APP_ZONE", "lastHit": "2026-10-30T22:10:00Z"},
            {"id": "r2", "name": "Block FTP from anywhere", "action": "BLOCK", "priority": 2, "sourceTargetType": "ANY",
             "destinationTargetType": "RESOURCE_GROUP", "lastHit": ""}]),
        f"{OP_ZMS}/ListDefaultPolicyRules": _gql("defaultPolicyRules", [
            {"id": "d1", "name": "Default inbound", "action": "ALLOW", "direction": "INBOUND", "scopeType": "GLOBAL"},
            {"id": "d2", "name": "Default outbound", "action": "ALLOW", "direction": "OUTBOUND", "scopeType": "GLOBAL"}]),
        f"{OP_ZMS}/ResourceProtectionStatus": _gql("resourceProtectionStatus", [
            {"protectedPercentage": 66.7, "protectedResourcesCount": 2, "unprotectedResourcesCount": 1, "totalResources": 3}]),
        f"{OP_ZMS}/ListAppZones": _gql("appZones", [{"id": "z1", "appZoneName": "Dispatch", "memberCount": 2}]),
        f"{OP_ZMS}/ListResourceGroups": _gql("resourceGroups", [
            {"id": "rg1", "name": "Databases", "type": "MANAGED", "resourceMemberCount": 1},
            {"id": "rg2", "name": "Legacy file transfer", "type": "UNMANAGED", "resourceMemberCount": 1}]),
    }


def meta() -> Dict[str, Any]:
    """What the sample says about itself (the banner, the status, records)."""
    return {"kind": "sample", "company": COMPANY, "tenant_label": LABEL, "saved_at": "",
            "scopes": ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac", "insights", "ztw", "aiguard"],
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
