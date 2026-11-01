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
            "Endpoint DLP Resources and Resource Groups (read; check B.17, with Endpoint DLP on Zscaler)",
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
            "/zia/endPointDlpRules",
            # Endpoint DLP resource groups and resources, per channel (B.17; zia/endpoint_dlp_resource_groups.py,
            # zia/dlp_endpoint_resource.py): read only with Endpoint DLP marked Zscaler.
            "/zia/endPointDlpResourceGroups/PRINTING", "/zia/endPointDlpResourceGroups/REMOVABLE_DRIVE_TRANSFER",
            "/zia/endPointDlpResourceGroups/NETWORK_DRIVE_TRANSFER", "/zia/endPointDlpResourceGroups/PERSONAL_CLOUD_STORAGE",
            "/zia/dlpEndpointResource/PRINTING", "/zia/dlpEndpointResource/REMOVABLE_DRIVE_TRANSFER",
            "/zia/dlpEndpointResource/NETWORK_DRIVE_TRANSFER", "/zia/dlpEndpointResource/PERSONAL_CLOUD_STORAGE",
            "/zwa/dlp/v1/incidents/search and /zwa/dlp/v1/customer/audit (POST reads; only when Workflow Automation is marked Zscaler)",
            "/zwa/dlp/v1/incidents/{id}, /triggers, /change-history, /tickets (incident drill-down; never /evidence)",
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
            "Forwarding Control (rules, proxy, ZPA, dedicated IP and DNS gateways, NAT control, IPv6, data centres, Virtual Service Edges)",
            "Bandwidth Control",
            "Browser Control Settings",
            "Authentication Settings",
            "User Management",
            "Admin Roles",
            "Admin Users",
            "Reports (System Audit Report; assumed name)",
            "Alerts (alert subscriptions; assumed name)",
            "NSS Configuration (NSS servers, collectors and feeds)",
            "Organization (subscriptions; assumed name)",
            "Hosted PAC Files",
            "Sandbox Settings",
            "Custom IPS Signatures",
            "Mobile Malware Protection",
            "FTP Control",
            "End User Notifications",
            "Alerts (UEBA)",
            "Custom File Types",
            "Cloud App Risk Profiles",
            "Adaptive Access Profiles",
            "URL & Cloud App Control Advanced Settings",
            "SaaS Security API (malware rules, tenants, quarantine templates)",
            "Cloud-to-Cloud Incident Forwarding",
            "Partner Integrations (read; names, types and enabled state only, THR.12)",
            "Traffic Capture Policy (read; GOV.9)",
            "Time Intervals (read; FW.10)",
        ],
        "permissions_write": [
            "Only with write mode on and a confirmed Bulk changes plan: User Management (users, groups, departments) and Hosted PAC Files",
            "Only with write mode on and a confirmed Bulk changes plan (Fix rows from Test a list, IP destination group change, ATP allow "
            "and deny lists): IP destination groups, Cloud Firewall and DNS Control rules, and the security policy allow and deny lists",
        ],
        "endpoints_used": [
            "/zia/firewallFilteringRules", "/zia/firewallDnsRules",
            "/zia/users", "/zia/groups", "/zia/departments", "/zia/pacFiles",
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
            "/zia/ipDestinationGroups", "/zia/ipSourceGroups", "/zia/advancedUrlFilterAndCloudAppSettings",
            # Governance and audit (zscaler_full_checks GOV.*).
            "/zia/configAudit", "/zia/alertSubscriptions", "/zia/nssServers", "/zia/nssCollectors", "/zia/nssFeeds",
            "/zia/subscriptions",
            # Forwarding and traffic path (zia_forwarding: the FWD.* checks
            # and the Path analyzer's Forwarding control step).
            "/zia/forwardingRules", "/zia/proxyGateways", "/zia/zpaGateways", "/zia/datacenters", "/zia/dcExclusions",
            "/zia/vips", "/zia/ipv6config", "/zia/ipv6config/nat64prefix", "/zia/dedicatedIPGateways/lite", "/zia/dnatRules",
            "/zia/virtualZenClusters", "/zia/virtualZenNodes", "/zia/dnsGateways",
            # Threat protection and SaaS Security hygiene (zscaler_full_checks THR / UF / SAAS).
            # The SaaS Security reads also need SaaS Security marked Zscaler on the Scope page.
            "/zia/behavioralAnalysisAdvancedSettings", "/zia/behavioralAnalysisAdvancedSettings/fileHashCount",
            "/zia/ipsSignatureRules", "/zia/mobileAdvanceThreatSettings", "/zia/ftpSettings", "/zia/eun",
            "/zia/alertRuleConfiguration/uebaRules", "/zia/alertDefinitions", "/zia/customFileTypes",
            "/zia/riskProfiles/lite", "/zia/adaptiveAccessProfiles",
            "/zia/advancedSettings", "/zia/casbMalwareRules/all", "/zia/quarantineTombstoneTemplate/lite",
            "/zia/casbTenant/lite", "/zia/casbTenant/scanInfo", "/zia/cloudToCloudIR/lite",
            # Coverage checks (2026-11-01): partner integrations (metadata only), traffic capture rules, time intervals.
            "/zia/integrationPartners", "/zia/trafficCaptureRules", "/zia/timeIntervals",
        ],
        "license_required": "Standard ZIA license. The NSS checks are N/A without an NSS or Cloud NSS subscription. Custom IPS signatures need Advanced Cloud Firewall; Mobile Malware Protection, "
                            "SaaS Security API (malware scanning) and Cloud Sandbox are separate subscriptions: without them those checks say \"not licensed\".",
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
            "Client Forwarding, Redirection, Isolation and Inspection Policies",
            "Privileged Credential and Capabilities Policies",
            "Browser Protection Policy",
            "AppProtection Profiles and Custom Controls",
            "Application Servers",
            "Business Continuity, Private Cloud and Private Cloud Controllers",
            "Branch Connectors and Cloud Connectors",
            "App Connector and Service Edge schedules (auto-delete), Version Profiles (HLT.5, HLT.6)",
            "ZIA cloud configuration availability (yes/no only; the configuration itself holds ZIA credentials and is never read, ZPA.22)",
            "User Portal Acceptable Use Policy and User Portal Links (ZPA.23, ZPA.24)",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zpa/server", "/zpa/inspectionProfile", "/zpa/inspectionControls/custom", "/zpa/businessContinuitySettings",
            "/zpa/privateCloud", "/zpa/privateCloudControllerGroup", "/zpa/privateCloudController",
            "/zpa/branchConnectorGroup", "/zpa/branchConnector", "/zpa/cloudConnectorGroup", "/zpa/cloudConnector",
            "/zpa/application", "/zpa/appConnectorGroup",
            "/zpa/segmentGroup", "/zpa/serverGroup",
            "/zpa/policySet/rules", "/zpa/posture",
            "/zpa/idp", "/zpa/samlAttribute", "/zpa/scimgroup",
            "/zpa/cbiconfig/profiles", "/zpa/cbiconfig/banners", "/zpa/cbiconfig/certificates", "/zpa/cbiconfig/regions",
            "/zpa/isolation/profiles", "/zpa/managedBrowserProfile",
            "/zpa/browserProtectionProfile", "/zpa/praPortal", "/zpa/praConsole", "/zpa/userPortal",
            # Coverage checks (2026-11-01).
            "/zpa/connectorSchedule", "/zpa/serviceEdgeSchedule", "/zpa/serviceEdge", "/zpa/visible/versionProfiles",
            "/zpa/config/isZiaCloudConfigAvailable", "/zpa/userportal/aup", "/zpa/userPortalLink",
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
            "Process-based and custom IP-based bypass apps",
            "Device details and the disable-reason report",
        ],
        "permissions_write": [
            "App Profiles (turn on or off, DNS and tunnel settings; only from Bulk changes, in write mode)",
        ],
        "endpoints_used": [
            "/zcc/process-based-apps", "/zcc/custom-ip-based-apps",
            "/zcc/getDeviceDetails", "/zcc/downloadDisableReasons",
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
            "ZDX Alert history and affected devices",
            "ZDX Application score and metrics",
            "ZDX Device CloudPath probes",
        ],
        "permissions_write": [
            "ZDX Score analysis (start and stop; only with write mode, the assessor and START ANALYSIS)",
        ],
        "endpoints_used": [
            "/zdx/alerts/historical", "/zdx/alerts/{id}/affected_devices",
            "/zdx/apps/{id}/score", "/zdx/apps/{id}/metrics",
            "/zdx/devices/{id}/apps/{id}/cloudpath-probes", "/zdx/analysis",
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
            "API Clients (Bulk changes: the clients and their scopes; never a secret's value)",
            "Admin entitlements (per admin)",
            "Group members",
        ],
        "permissions_write": [
            "Only with write mode on and a confirmed Bulk changes plan: Users (create, disable, enable, delete) and API Clients "
            "(create, rotate a secret, disable, enable, delete). Grant them only to the API client that makes these changes: least privilege.",
            "Group members (add and remove; only from Bulk changes, in write mode)",
        ],
        "endpoints_used": [
            "/zid/users", "/zid/groups",
            "/zid/resourceServers",
            "/ziam/admin/api/v1/api-clients", "/ziam/admin/api/v1/api-clients/{id}/secrets",
            "/zid/users/{id}/admin-entitlements", "/zid/groups/{id}/users",
        ],
        "license_required": "ZIdentity is included with all OneAPI tenants. The API role you use to authenticate already lives here.",
        "customer_id_needed": False,
        "note": "ZIdentity scope is meta — the API client itself lives in ZIdentity. You'll need 'ZIdentity Admin' to read the directory it's a member of.",
    },

    "rbac": {
        "label": "RBAC",
        "description": "Role-based access control hygiene: ZIA admin roles and admins, admin password expiry, Zscaler Support remote assistance, Client Connector portal admins and roles, ZPA access policy bound to groups, ZPA administration (admins, roles, admin SSO, API keys, emergency access, microtenants, provisioning keys, Privileged Remote Access credentials and approvals; with ZPA ticked too), ZIdentity admin redundancy. Key, password and credential values are never read into results.",
        "service": "ZIA + ZCC + ZPA + ZIdentity",
        "permissions_read": [
            "Admin Roles",
            "Admin Users",
            "Authentication Settings",
            "Remote Assistance (assumed name)",
            "ZCC Admin Users",
            "ZCC Admin Roles",
            "Access Policy",
            "Users",
            "ZPA Administrators",
            "ZPA Roles",
            "ZPA Admin SSO Settings",
            "ZPA API Keys",
            "ZPA Emergency Access",
            "ZPA Microtenants",
            "ZPA Provisioning Keys",
            "ZPA Privileged Credentials",
            "ZPA Privileged Approvals",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zia/adminRoles", "/zia/adminUsers", "/zia/authSettings",
            "/zia/passwordExpiry/settings", "/zia/remoteAssistance",
            "/zcc/adminRoles", "/zcc/adminUsers", "/zcc/adminUsersSyncInfo",
            "/zpa/policySet/rules/ACCESS_POLICY",
            "/zpa/administrators", "/zpa/roles", "/zpa/ssoLoginOptions", "/zpa/apiKeys", "/zpa/emergencyAccess/users",
            "/zpa/microtenants", "/zpa/associationType/CONNECTOR_GRP/provisioningKey",
            "/zpa/associationType/SERVICE_EDGE_GRP/provisioningKey", "/zpa/credential", "/zpa/credential-pool", "/zpa/approval",
            "/zid/users",
        ],
        "license_required": "Standard ZIA license; the ZCC, ZPA and ZIdentity checks need those products. Microtenants and Privileged Remote Access need those ZPA features; without them those checks say N/A.",
        "customer_id_needed": True,
        "customer_id_note": "The ZPA RBAC checks (access policy and ZPA administration) need the ZPA customer ID, and ZPA ticked on the Scope page.",
    },

    "insights": {
        "label": "ZIA Insights (traffic data)",
        "description": "Traffic insights page: web traffic by action and location, web threats by class and super-category, cloud applications (Shadow IT), SaaS security (CASB) by application, firewall traffic by action, location and network service, security incidents by location, IoT device counts, and the users with the most security incidents. The Insights assessment checks (high-risk unsanctioned apps with traffic, SaaS apps with traffic but no SaaS Security API tenant) and the cloud application sanction change in Bulk changes read it too. Traffic numbers (aggregates), not configuration.",
        "service": "ZIA (Z-Insights)",
        "permissions_read": [
            "Z-Insights / Insights analytics (read) on the API client's role",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/zins/graphql (WEB_TRAFFIC, SHADOW_IT, SAAS_SECURITY, ZERO_TRUST_FIREWALL, CYBER_SECURITY, IOT)",
            "/zia/subscriptions (licences, for the Insights checks)",
            "/zia/casbTenant/lite (SaaS Security API tenants, for the SaaS coverage check; only when the SaaS channel is on Zscaler)",
            "/zia/cloudApplications/lite (the cloud application list, for the sanction change)",
        ],
        "license_required": "Standard ZIA license for web and firewall traffic; Shadow IT and SaaS security sections show data only where the tenant has Cloud App Control and CASB.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only: the classic ZIA API sign-in cannot read Z-Insights. Shows customer traffic data, so it is off unless ticked.",
    },

    "aiguard": {
        "label": "AI Guard",
        "description": "Zscaler AI Guard: whether it is licensed and reachable, seven scored assessment checks (AIG.1 to AIG.7: detection policy in use, prompt injection, block mode, answers inspected, stored prompts encrypted, application credentials, provider credentials current), the AI Guard page (policies, match rules, LLM applications, credential metadata and Test a prompt with synthetic prompts) and the Bulk changes builders that route GenAI apps through it and turn a compliance profile into an AI Guard detection policy.",
        "service": "AI Guard (OneAPI) and ZIA",
        "permissions_read": [
            "AI Guard: detection policies, policy match rules, LLM providers, LLM applications, LLM application credentials and LLM provider credentials (read; credential metadata only: names and dates, never a key)",
            "Test a prompt only: an AI Guard API key in the server's AIGUARD_API_KEY (policy detection is not on OneAPI)",
            "ZIA: proxies and proxy gateways, root certificates, forwarding control (read; ZIA platform ticked)",
        ],
        "permissions_write": [
            "Only with write mode on and a confirmed Bulk changes plan: AI Guard detection policies and policy match rules; ZIA root certificates, proxies, IP destination groups, forwarding, SSL inspection, Cloud Firewall, URL filtering and Cloud App Control rules, and the URL and Cloud App Control settings (prompt capture)",
        ],
        "endpoints_used": [
            "/aiguard/v1/detections/policies", "/aiguard/v1/detections/policy-match-rules", "/aiguard/v1/llm-providers",
            "/aiguard/v1/llm-applications", "/aiguard/v1/llm-application-credentials", "/aiguard/v1/llm-provider-credentials",
            "/v1/detection/execute-policy at api.<cloud>.zseclipse.net (Test a prompt, synthetic prompts only)",
            "/zia/api/v1/proxies", "/zia/api/v1/proxyGateways", "/zia/api/v1/rootCertificates (assumed path)", "/zia/api/v1/forwardingRules",
        ],
        "license_required": "An AI Guard subscription linked to the ZIA tenant (Zscaler Support links them); GenAI prompt capture in ZIA needs the Gen AI Security subscription.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only: the classic ZIA API sign-in has no AI Guard. The proxy gateway cannot be created through the API; the builder says how to make it in the ZIA portal.",
    },
    "ztw": {
        "label": "Cloud & Branch Connector",
        "description": "The Cloud & Branch Connector page and eight assessment checks (ZTW.1 to ZTW.8): connector groups and their connectors (redundancy, health, software versions), traffic forwarding rules (workload traffic sent DIRECT), forwarding gateways (fail closed), connector locations and templates (firewall and IPS), the activation status, admins, roles and provisioning API keys (counted; key values and provisioning URLs are never read into a result), and public cloud accounts. Also the Path analyzer's traffic from a workload: where a workload's traffic goes (ZIA, ZPA, direct, local switch, proxy chaining or drop).",
        "service": "Cloud & Branch Connector (ZTW)",
        "permissions_read": [
            "Cloud & Branch Connector (read) on the API client's role: connector groups, forwarding control, gateways, workload groups, IP groups, locations and location templates, activation status, admin management, API key management, public cloud accounts",
        ],
        "permissions_write": [],
        "endpoints_used": [
            "/ztw/api/v1/ecgroup", "/ztw/api/v1/ecRules/ecRdr", "/ztw/api/v1/workloadGroups",
            "/ztw/api/v1/ipSourceGroups", "/ztw/api/v1/ipDestinationGroups", "/ztw/api/v1/gateways",
            "/ztw/api/v1/location", "/ztw/api/v1/locationTemplate", "/ztw/api/v1/ecAdminActivateStatus",
            "/ztw/api/v1/adminRoles", "/ztw/api/v1/adminUsers", "/ztw/api/v1/apiKeys",
            "/ztw/api/v1/publicCloudAccountDetails", "/ztw/api/v1/publicCloudInfo",
        ],
        "license_required": "Cloud Connector or Branch Connector subscription (without one the checks say not applicable).",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only: the classic ZIA API sign-in cannot read Cloud & Branch Connector. Off unless ticked. Read-only: nothing is activated, no key is regenerated, no provisioning URL is read.",
    },

    # The other Zscaler products (other_products.py): read-only, off unless ticked.
    "ztb": {
        "label": "Zero Trust Branch",
        "description": "Other products page and the ZTB assessment checks: sites, site templates, groups, alarms, API key names and ages, cloud gateway hubs, device operating systems (counts) and the ransomware kill switch state. Read-only.",
        "service": "Zero Trust Branch (ZTB, OneAPI)",
        "permissions_read": ["Zero Trust Branch (read) on the API client's role: sites, templates, groups, alarms, API keys, cloud gateways, devices"],
        "permissions_write": [],
        "endpoints_used": ["/ztb/api/v2/Site/", "/ztb/api/v3/templates", "/ztb/api/v2/groups", "/ztb/api/v2/alarm",
                           "/ztb/api/v3/api-key-auth/list", "/ztb/api/v3/CloudGateway/hubs", "/ztb/api/v3/device/operating-systems",
                           "/ztb/api/v3/ransomware-kill/state/"],
        "license_required": "Zero Trust Branch (Zero Trust SD-WAN) subscription.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only. API key values, site secrets and tokens are never read into a result. Off unless ticked.",
    },
    "easm": {
        "label": "External attack surface (EASM)",
        "description": "Other products page and the EASM assessment checks: organizations, findings on internet-facing assets and lookalike domains. Read-only.",
        "service": "External attack surface management (EASM, OneAPI)",
        "permissions_read": ["EASM (read) on the API client's role: organizations, findings, lookalike domains"],
        "permissions_write": [],
        "endpoints_used": ["/easm/easm-ui/v1/organizations", "/easm/easm-ui/v1/organizations/{org}/findings",
                           "/easm/easm-ui/v1/organizations/{org}/lookalike-domains"],
        "license_required": "Zscaler External Attack Surface Management subscription.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only. At most 10 organizations are read. Off unless ticked.",
    },
    "zbi": {
        "label": "Business Insights",
        "description": "Other products page and the Business Insights assessment checks: custom applications, scheduled report configurations (recipients counted, never listed) and generated reports. Read-only.",
        "service": "Business Insights (ZBI, OneAPI)",
        "permissions_read": ["Business Insights (read) on the API client's role: custom applications, report configurations, reports"],
        "permissions_write": [],
        "endpoints_used": ["/bi/api/v1/customapps", "/bi/api/v1/reports/customapps", "/bi/api/v1/report/all"],
        "license_required": "Zscaler Business Insights subscription.",
        "customer_id_needed": False,
        "note": "OneAPI (ZIdentity) API clients only. Off unless ticked.",
    },
    "zcell": {
        "label": "Zero Trust Cellular",
        "description": "Other products page and the Zero Trust Cellular assessment checks: account settings, regions, SIM location groups (SIMs counted), anomaly policies of the last 30 days (recipients counted) and the SIM summary (counts only). Read-only; no SIM, ICCID or location is read.",
        "service": "Zero Trust Cellular (ZCell, OneAPI)",
        "permissions_read": ["Zero Trust Cellular (read) on the API client's role: customer, regions, SIM location groups, anomaly policies, SIM analytics"],
        "permissions_write": [],
        "endpoints_used": ["/zcell/config/api/v1/customers/{id}", "/zcell/config/api/v1/customers/{id}/regions",
                           "/zcell/config/api/v1/customers/{id}/sim-location-groups", "/zcell/config/api/v1/customers/{id}/anomaly-policy",
                           "/zcell/config/api/v1/customers/{id}/sim/analytics/summary"],
        "license_required": "Zscaler Zero Trust Cellular subscription.",
        "customer_id_needed": True,
        "customer_id_note": "The ZCell customer ID (shown in the Zero Trust Cellular admin portal), given on the Other products page.",
        "note": "OneAPI (ZIdentity) API clients only. Off unless ticked.",
    },
    "zms": {
        "label": "Microsegmentation",
        "description": "Other products page and the Microsegmentation assessment checks: agents, agent connection and version statistics, agent groups, provisioning keys (names and usage, never the key), policy rules, default rules, resource protection, app zones and resource groups. Read-only; agent group TOTP secrets are never read.",
        "service": "Microsegmentation (ZMS, OneAPI GraphQL)",
        "permissions_read": ["Microsegmentation (read) on the API client's role: agents, agent groups, provisioning keys, policy rules, resources, app zones"],
        "permissions_write": [],
        "endpoints_used": ["/zms/graphql (queries: ListAgents, AgentConnectionStatusStats, AgentVersionStats, ListAgentGroups, ListNonces, "
                           "ListPolicyRules, ListDefaultPolicyRules, ResourceProtectionStatus, ListAppZones, ListResourceGroups)"],
        "license_required": "Zscaler Microsegmentation (Workload Segmentation) subscription.",
        "customer_id_needed": True,
        "customer_id_note": "The Microsegmentation customer ID; the ZPA customer ID is used when none is given (assumed).",
        "note": "OneAPI (ZIdentity) API clients only. Reads are GraphQL queries sent as POST; no mutation is ever sent. Off unless ticked.",
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
