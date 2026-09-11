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

from typing import Any, Dict, List


# Per-scope minimum permission set. Each entry maps a scope key
# (matches the GUI's <input class="scope-cb" value="..."> values)
# to a structured requirement document.
SCOPE_PERMISSIONS: Dict[str, Dict[str, Any]] = {

    "dlp": {
        "label": "DLP Assessment",
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
        "label": "ZIA Platform",
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
            "Security Policy Settings",
            "Advanced Threat Protection",
            "Bandwidth Control",
            "Browser Control Settings",
            "Authentication Settings",
            "User Management",
            "Admin Roles",
            "Admin Users",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/firewallRules", "/zia/firewallDnsRules",
            "/zia/urlFilteringRules", "/zia/urlCategories",
            "/zia/sslInspectionRules", "/zia/cloudApplications",
            "/zia/locations", "/zia/greTunnels",
            "/zia/vpnCredentials", "/zia/staticIps",
            "/zia/sandbox/report", "/zia/security",
            "/zia/users", "/zia/adminRoles",
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
            "/zcc/getDevices", "/zcc/web/policy/listByCompany",
            "/zcc/webForwardingProfile/listByCompany",
            "/zcc/webTrustedNetwork/listByCompany",
            "/zcc/webFailOpenPolicy/listByCompany",
            "/zcc/webAppService/listByCompany",
            "/zcc/webPrivacyInfo/listByCompany",
            "/zcc/getCompanyInfo",
            "/zcc/getAdminUsers", "/zcc/getAdminRoles",
            "/zcc/getZdxGroupEntitlements",
            "/zcc/getZpaGroupEntitlements",
        ],
        "license_required": "ZCC Portal access (included with ZIA/ZPA subscriptions in most plans).",
        "customer_id_needed": False,
    },

    "genai": {
        "label": "GenAI & Prompts",
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
            "/zia/cloudAppControl", "/zia/webDlpRules",
        ],
        "license_required": "Cloud App Control + AI Security add-on for full GenAI coverage; basic checks work with Standard ZIA.",
        "customer_id_needed": False,
    },

    "automation": {
        "label": "Automation Readiness",
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
            "/zia/firewallRules", "/zia/sslInspectionRules",
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
            "/zid/resourceServers", "/zid/userEntitlement",
        ],
        "license_required": "ZIdentity is included with all OneAPI tenants. The API role you use to authenticate already lives here.",
        "customer_id_needed": False,
        "note": "ZIdentity scope is meta — the API client itself lives in ZIdentity. You'll need 'ZIdentity Admin' to read the directory it's a member of.",
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
