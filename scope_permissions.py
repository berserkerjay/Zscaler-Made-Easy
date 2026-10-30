#!/usr/bin/env python3
"""
Minimum OneAPI permissions required per assessment scope
=========================================================

Maps each scope checkbox in the GUI to the minimum set of API role
permissions (granted in ZIdentity → API Clients → Role) that the
underlying checks need to read.

Sources
-------
- Endpoint paths in zscaler-sdk-python (/zscaler/zia, /zscaler/zcc,
  /zscaler/zpa, /zscaler/zdx, /zscaler/zid).
- Permission names from the ZIdentity admin portal role-builder UI.
- Subscription/feature-license caveats from
  https://help.zscaler.com/zidentity/about-roles.

NOTE: This module returns DATA only. It does not check the tenant's
current role assignment — that's a separate flow. The point is to
answer the question "what do I need to grant before running this?"
"""
from __future__ import annotations

from typing import Any, Dict


# Per-scope minimum permission set. Each entry maps a scope key
# (matches the GUI's <input class="scope-cb" value="..."> values)
# to a structured requirement document.
SCOPE_PERMISSIONS: Dict[str, Dict[str, Any]] = {

    "dlp": {
        "label": "DLP assessment",
        "description": "All 170 DLP-specific checks (Inline Web DLP, engines, dictionaries, ICAP, EDM).",
        "service": "ZIA",
        "permissions_read": [
            "Web DLP Rules",
            "DLP Engines",
            "DLP Dictionaries",
            "DLP Notification Templates",
            "ICAP Servers",
            "Incident Receiver Servers",
            "IDM Profiles",
            "EDM Schemas",
            "Cloud Apps Risk",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/webDlpRules",
            "/zia/dlpEngines",
            "/zia/dlpDictionaries",
            "/zia/dlpNotificationTemplates",
            "/zia/icapServers",
            "/zia/incidentReceiverServers",
            "/zia/idmprofile",
            "/zia/dlpExactDataMatchSchemas",
        ],
        "license_required": "Standard ZIA license. EDM/IDM features require Advanced DLP add-on.",
        "customer_id_needed": False,
    },

    "zia_extras": {
        "label": "ZIA platform",
        "description": "Cloud firewall, URL filtering, SSL inspection, locations, traffic forwarding, security policy, sandbox.",
        "service": "ZIA",
        "permissions_read": [
            "Cloud Firewall Rules",
            "Cloud Firewall DNS Rules",
            "URL Filtering Rules",
            "URL Categories",
            "SSL Inspection Rules",
            "Cloud Applications",
            "Cloud App Control",
            "Locations",
            "GRE Tunnels",
            "IPSec VPN Credentials",
            "Static IPs",
            "Sandbox Reports",
            "Sandbox Rules",
            "Security Policy Settings",
            "Advanced Threat Protection",
            "Network Services and IP Groups",
            "Bandwidth Control",
            "Browser Control Settings",
            "Authentication Settings",
            "User Management",
            "Admin Roles",
            "Admin Users",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/firewallFilteringRules", "/zia/firewallDnsRules",
            "/zia/urlFilteringRules", "/zia/urlCategories",
            "/zia/sslInspectionRules", "/zia/cloudApplications",
            "/zia/locations", "/zia/greTunnels",
            "/zia/vpnCredentials", "/zia/staticIP",
            "/zia/security",
            "/zia/users", "/zia/adminRoles",
            "/zia/browserIsolation/profiles", "/zia/browserControlSettings",
            "/zia/webApplicationRules",
            # The Path analyzer's ZIA modules (zia_path_modules.READS).
            "/zia/cyberThreatProtection/advancedThreatSettings", "/zia/cyberThreatProtection/securityExceptions",
            "/zia/cyberThreatProtection/maliciousUrls", "/zia/security/advanced", "/zia/sandboxRules",
            "/zia/networkServices", "/zia/networkServiceGroups", "/zia/networkApplicationGroups",
            "/zia/ipDestinationGroups", "/zia/ipSourceGroups",
        ],
        "license_required": "Standard ZIA license.",
        "customer_id_needed": False,
    },

    "zpa": {
        "label": "ZPA",
        "description": "App segments, App Connectors, segment groups, server groups, access policy, posture profiles.",
        "service": "ZPA",
        "permissions_read": [
            "Application Segments",
            "Segment Groups",
            "Server Groups",
            "App Connectors",
            "App Connector Groups",
            "Service Edges",
            "Service Edge Groups",
            "Access Policy",
            "Timeout Policy",
            "Posture Profiles",
            "Trusted Networks",
            "SAML Attributes",
            "SCIM Groups",
            "IDP Configuration",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zpa/application", "/zpa/appConnectorGroup",
            "/zpa/segmentGroup", "/zpa/serverGroup",
            "/zpa/policySet/rules", "/zpa/posture",
            "/zpa/idp", "/zpa/samlAttribute", "/zpa/scimgroup",
            "/zpa/cbiconfig/profiles", "/zpa/cbiconfig/banners", "/zpa/cbiconfig/certificates", "/zpa/cbiconfig/regions",
            "/zpa/isolation/profiles", "/zpa/managedBrowserProfile",
            "/zpa/browserProtectionProfile", "/zpa/praPortal", "/zpa/praConsole", "/zpa/userPortal",
        ],
        "license_required": "ZPA subscription.",
        "customer_id_needed": True,
        "customer_id_note": "ZPA endpoints embed the Customer ID in the URL path. Configure it on the API client AND enter it in the assessment tool's Customer ID field.",
    },

    "zcc": {
        "label": "ZCC / Mobile Portal",
        "description": "Devices, app profiles, forwarding profiles, trusted networks, fail-open, posture, admins, entitlements.",
        "service": "ZCC",
        "permissions_read": [
            "ZCC Portal Access",
            "Devices (Read)",
            "Web Policies / App Profiles",
            "Forwarding Profiles",
            "Trusted Networks",
            "Fail Open Policy",
            "Web App Service",
            "Privacy Info",
            "Company Info",
            "ZCC Admin Users",
            "ZCC Admin Roles",
            "Group Entitlements (ZDX/ZPA)",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zcc/getDevices", "/zcc/application-profiles", "/zcc/web/policy/listByCompany",
            "/zcc/webForwardingProfile/listByCompany",
            "/zcc/webTrustedNetwork/listByCompany",
            "/zcc/webFailOpenPolicy/listByCompany",
            "/zcc/webAppService/listByCompany",
            "/zcc/getWebPrivacyInfo",
            "/zcc/getCompanyInfo",
            "/zcc/getAdminUsers", "/zcc/getAdminRoles",
            "/zcc/getZdxGroupEntitlements",
            "/zcc/getZpaGroupEntitlements",
        ],
        "license_required": "ZCC Portal access (included with ZIA/ZPA subscriptions in most plans).",
        "customer_id_needed": False,
    },

    "genai": {
        "label": "GenAI & prompts",
        "description": "AI/ML controls, GenAI app categorization, prompt-leak risk surfaces.",
        "service": "ZIA",
        "permissions_read": [
            "URL Categories",
            "Cloud Applications",
            "Cloud App Control",
            "AI/ML Controls",
            "Web DLP Rules",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/urlCategories", "/zia/cloudApplications",
            "/zia/webApplicationRules", "/zia/webDlpRules",
        ],
        "license_required": "Cloud App Control + AI Security add-on for full GenAI coverage; basic checks work with Standard ZIA.",
        "customer_id_needed": False,
    },

    "automation": {
        "label": "Automation readiness",
        "description": "Validates tenant readiness for Zscaler SDKs / Terraform / Ansible (github.com/zscaler).",
        "service": "ZIA + ZPA + ZCC",
        "permissions_read": [
            "Audit Logs (CRITICAL — needed to detect IaC change traceability)",
            "Web DLP Rules",
            "URL Filtering Rules",
            "Cloud Firewall Rules",
            "SSL Inspection Rules",
            "Locations",
            "Admin Roles",
            "Sandbox Reports",
            "ZPA Application Segments",
            "ZCC Portal Access",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/auditlogEntryReport", "/zia/status",
            "/zia/webDlpRules", "/zia/urlFilteringRules",
            "/zia/firewallFilteringRules", "/zia/sslInspectionRules",
            "/zia/locations", "/zia/adminRoles", "/zia/ruleLabels",
            "/zia/sandbox/report/quota",
            "/zpa/appConnectorGroup", "/zpa/application",
            "/zcc/companyInfo", "/zcc/devices",
        ],
        "license_required": "Standard ZIA + ZPA + ZCC. Audit log access is the critical gate.",
        "customer_id_needed": True,
        "customer_id_note": "Several Automation checks reach into ZPA — Customer ID required for those to PASS.",
    },

    "zdx": {
        "label": "ZDX",
        "description": "Digital Experience: monitored apps, locations, departments, alerts, inventory, troubleshooting.",
        "service": "ZDX",
        "permissions_read": [
            "ZDX Apps",
            "ZDX Locations",
            "ZDX Departments",
            "ZDX Alerts (rules + ongoing)",
            "ZDX Inventory",
            "ZDX Reports",
            "ZDX Troubleshooting (deep-path)",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zdx/administration/apps",
            "/zdx/administration/locations",
            "/zdx/administration/departments",
            "/zdx/alerts/rules", "/zdx/alerts/ongoing",
            "/zdx/inventory/software",
            "/zdx/reports", "/zdx/troubleshooting/devices",
        ],
        "license_required": "ZDX subscription required. Without it, every ZDX check returns INFO (not a failure — graceful degradation).",
        "customer_id_needed": False,
    },

    "zidentity": {
        "label": "ZIdentity",
        "description": "Users, groups, resource servers, user entitlements, admin redundancy.",
        "service": "ZIdentity",
        "permissions_read": [
            "Users",
            "Groups",
            "Resource Servers",
            "User Entitlements",
            "Admin Roles",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zid/users", "/zid/groups",
            "/zid/resourceServers",
        ],
        "license_required": "ZIdentity is included with all OneAPI tenants. The API role you use to authenticate already lives here.",
        "customer_id_needed": False,
        "note": "ZIdentity scope is meta — the API client itself lives in ZIdentity. You'll need 'ZIdentity Admin' to read the directory it's a member of.",
    },

    "rbac": {
        "label": "RBAC",
        "description": "Role-based access control hygiene: ZIA admin roles and admins, Client Connector portal admins and roles, ZPA access policy bound to groups, ZIdentity admin redundancy.",
        "service": "ZIA + ZCC + ZPA + ZIdentity",
        "permissions_read": [
            "Admin Roles",
            "Admin Users",
            "Authentication Settings",
            "ZCC Admin Users",
            "ZCC Admin Roles",
            "Access Policy",
            "Users",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/adminRoles", "/zia/adminUsers", "/zia/authSettings",
            "/zcc/adminRoles", "/zcc/adminUsers", "/zcc/adminUsersSyncInfo",
            "/zpa/policySet/rules/ACCESS_POLICY",
            "/zid/users",
        ],
        "license_required": "Standard ZIA license; the ZCC, ZPA and ZIdentity checks need those products.",
        "customer_id_needed": True,
        "customer_id_note": "One RBAC check reads the ZPA access policy, which needs the ZPA customer ID.",
    },

    "insights": {
        "label": "ZIA Insights (traffic data)",
        "description": "Traffic insights page: web traffic by action and location, cloud applications (Shadow IT), SaaS security (CASB) by application, firewall traffic by action, and the users with the most security incidents. Traffic numbers, not configuration; no assessment check reads them.",
        "service": "ZIA (Z-Insights)",
        "permissions_read": [
            "Z-Insights / Insights analytics (read) on the API client's role",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zins/graphql (WEB_TRAFFIC, SHADOW_IT, SAAS_SECURITY, ZERO_TRUST_FIREWALL, CYBER_SECURITY)",
        ],
        "license_required": "Standard ZIA license for web and firewall traffic; Shadow IT and SaaS security sections show data only where the tenant has Cloud App Control and CASB.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only: the classic ZIA API sign-in cannot read Z-Insights. Shows customer traffic data, so it is off unless ticked.",
    },

    "aiguard": {
        "label": "AI Guard",
        "description": "Zscaler AI Guard: whether it is licensed and reachable, and the Bulk changes builders that route GenAI apps through it and turn a compliance profile into an AI Guard detection policy. Not part of the assessment's checks.",
        "service": "AI Guard (OneAPI) and ZIA",
        "permissions_read": [
            "AI Guard: detection policies, policy match rules and LLM providers (read)",
            "ZIA: proxies and proxy gateways, root certificates, forwarding control (read; ZIA platform ticked)",
        ],
        "permissions_write": [
            "Only with write mode on and a confirmed Bulk changes plan: AI Guard detection policies and policy match rules; ZIA root certificates, proxies, IP destination groups, forwarding, SSL inspection, Cloud Firewall, URL filtering and Cloud App Control rules, and the URL and Cloud App Control settings (prompt capture)",
        ],
        "endpoints_used": [
            "/aiguard/v1/detections/policies", "/aiguard/v1/detections/policy-match-rules", "/aiguard/v1/llm-providers",
            "/zia/api/v1/proxies", "/zia/api/v1/proxyGateways", "/zia/api/v1/rootCertificates (assumed path)", "/zia/api/v1/forwardingRules",
        ],
        "license_required": "An AI Guard subscription linked to the ZIA tenant (Zscaler Support links them); GenAI prompt capture in ZIA needs the Gen AI Security subscription.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only: the classic ZIA API sign-in has no AI Guard. The proxy gateway cannot be created through the API; the builder says how to make it in the ZIA portal.",
    },
    "ztw": {
        "label": "Cloud & Branch Connector",
        "description": "Path analyzer, traffic from a workload: the Cloud & Branch Connector traffic forwarding rules, workload groups, connector groups and IP source and destination groups, to say where a workload's traffic goes (ZIA, ZPA, direct, local switch, proxy chaining or drop). No assessment check reads them.",
        "service": "Cloud & Branch Connector (ZTW)",
        "permissions_read": [
            "Cloud & Branch Connector (read) on the API client's role: forwarding control, workload groups, connector groups, IP groups",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/ztw/api/v1/ecRules/ecRdr", "/ztw/api/v1/workloadGroups", "/ztw/api/v1/ecgroup",
            "/ztw/api/v1/ipSourceGroups", "/ztw/api/v1/ipDestinationGroups",
        ],
        "license_required": "Cloud Connector or Branch Connector subscription.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only: the classic ZIA API sign-in cannot read Cloud & Branch Connector. Off unless ticked.",
    },

    "compliance": {
        "label": "Compliance",
        "description": "Maps assessment results to NIST 800-53/171, SOC 2, GDPR, HIPAA, PCI-DSS, ISO 27001, CIS frameworks.",
        "service": "ZIA + ZPA + ZCC (composite)",
        "permissions_read": [
            "Same as the scopes you select alongside Compliance — this scope is purely a mapping layer over the others.",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "(none — operates on results from the other scopes)",
        ],
        "license_required": "No additional license. Compliance mapping runs entirely client-side after the other scopes complete.",
        "customer_id_needed": False,
    },
}


# Notes that apply across all scopes — the GUI will render them once
# at the top of the modal so each scope card stays compact.
GLOBAL_NOTES = [
    "All checks are READ-ONLY. The assessment never modifies your tenant unless you explicitly trigger Step 3b (Delete) or Step 5 (Post) in the Migration Wizard, which require the writes-enabled launcher AND the ENABLE_WRITE_ACTIONS env var.",
    "OneAPI clients are created in the ZIdentity admin portal at https://admin.zidentity.net/ → API Clients → Add. Pick 'Service Account', then assign a Role with the permissions listed below.",
    "Zscaler best practice: create one API role per use case (e.g. 'assessment-readonly', 'terraform-readonly', 'ansible-executor') rather than reusing super-admin. The assessment tool only needs the read permissions listed.",
    "If a scope returns 'Not Configured / N/A' for everything, the most likely cause is a missing permission on the API role. Grant the listed permissions and re-run.",
]


def get_scope_permissions(scope_key: str) -> Dict[str, Any]:
    """Return the requirement document for a single scope, or {} if unknown."""
    return SCOPE_PERMISSIONS.get(scope_key, {})


def get_all_permissions() -> Dict[str, Any]:
    """Return the full catalog plus global notes."""
    return {
        "global_notes": GLOBAL_NOTES,
        "portal_url": "https://admin.zidentity.net/",
        "scopes": SCOPE_PERMISSIONS,
    }
