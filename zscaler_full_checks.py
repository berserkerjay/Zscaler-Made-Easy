#!/usr/bin/env python3
"""
Zscaler Full Platform Assessment Checks
=========================================
Comprehensive checks across ALL Zscaler services:
  - ZIA: Firewall, URL Filtering, Security, Bandwidth, Cloud Apps
  - ZPA: App Segments, Connectors, Policies, Service Edges
  - ZCC: Devices, Forwarding, Trusted Networks
  - User & Admin Management, Locations, GRE/VPN

These extend the DLP checks in dlp_assessment_full_auto.py.
Import and append to REG to run a full platform assessment.
"""

import json

# Reuse the Result class and helpers from the main engine
from dlp_assessment_full_auto import R, _ls, _g


# ═══════════════════════════════════════════════════════════════════════
# ZIA — FIREWALL
# ═══════════════════════════════════════════════════════════════════════

def fw_1(cl):
    """Cloud Firewall rules exist"""
    d, c = cl.get("/zia/firewallRules")
    r = _ls(d) if c in (200, 204) else []
    if not r:
        return R(R.WARN, "No cloud firewall rules configured. Best Practice: Zscaler recommends implementing cloud firewall rules with a default deny-all policy for regulated environments. Rules should control non-web traffic (SSH, RDP, FTP) that bypasses URL filtering. Ref: Firewall Deployment and Operations Guide.")
    en = [x for x in r if x.get("state", "").upper() == "ENABLED"]
    return R(R.PASS, f"{len(en)} active of {len(r)} firewall rule(s).")

def fw_2(cl):
    """Firewall default rule action"""
    d, c = cl.get("/zia/firewallRules")
    r = _ls(d) if c in (200, 204) else []
    default = [x for x in r if "default" in (x.get("name") or "").lower()]
    if default:
        act = default[0].get("action", "?")
        if act.upper() in ("BLOCK_DROP", "BLOCK_RESET", "DROP"):
            return R(R.PASS, f"Default rule action: {act}. Aligns with Zscaler best practice of deny-all default posture.")
        return R(R.WARN, f"Default rule action is {act}. Best Practice: Zscaler recommends Block/Drop as the default action, especially for regulated industries (healthcare, finance). An allow-all default should only be used for guest networks.")
    return R(R.WARN, "No default firewall rule found. Best Practice: Ensure the Zscaler default firewall rules are intact. Do not modify the first 4 default rules including the 'Recommended Firewall Rule'.")

def fw_3(cl):
    """DNS control rules"""
    d, c = cl.get("/zia/dnsRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} DNS control rule(s).") if r else R(R.WARN, "No DNS control rules. Best Practice: Configure DNS control rules to prevent DNS-based data exfiltration and enforce DNS resolution through Zscaler. DNS tunneling is a common exfiltration vector.")

def fw_4(cl):
    """IPS rules configured"""
    d, c = cl.get("/zia/ipsRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} IPS rule(s).") if r else R(R.WARN, "No IPS rules. Best Practice: Enable IPS (Intrusion Prevention System) to detect and block exploits, C2 callbacks, and lateral movement. IPS requires SSL inspection to be effective on encrypted traffic. Ref: IPS Control Deployment and Operations Guide.")

def fw_5(cl):
    """IP destination groups"""
    d, c = cl.get("/zia/ipDestinationGroups")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} IP destination group(s).") if r else R(R.WARN, "No IP destination groups defined. Best Practice: Define IP destination groups to create granular firewall rules. Group known-good and known-bad destinations for cleaner policy management.")

def fw_6(cl):
    """IP source groups"""
    d, c = cl.get("/zia/ipSourceGroups")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} IP source group(s).") if r else R(R.WARN, "No IP source groups defined. Best Practice: Use IP source groups to scope firewall rules to specific network segments or office locations.")

def fw_7(cl):
    """Network services defined"""
    d, c = cl.get("/zia/networkServices")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} network service(s).") if r else R(R.WARN, "No custom network services. Best Practice: Define network services for protocols your organization uses. Zscaler recommends ranking network service rules higher than network application rules to prevent unnecessary packet pass-through.")

def fw_8(cl):
    """Firewall rule ordering"""
    d, c = cl.get("/zia/firewallRules")
    r = _ls(d) if c in (200, 204) else []
    if len(r) < 2:
        return R(R.PASS, "Single or no rules — no ordering issues.")
    for i, rule in enumerate(r):
        a = (rule.get("action") or "").upper()
        broad = not rule.get("srcIpGroups") and not rule.get("destIpGroups") and not rule.get("departments")
        if a == "ALLOW" and broad and i < len(r) - 1:
            return R(R.WARN, f"Broad ALLOW at position {i+1} may shadow later rules. Best Practice: Zscaler processes firewall rules top-to-bottom, first match wins. Place specific deny rules above broad allow rules. Never modify the first 4 default rules. Add custom rules after 'Recommended Firewall Rule'.")
    return R(R.PASS, f"Firewall rule order appears valid ({len(r)} rules). Rules follow Zscaler's recommended top-to-bottom precedence.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — URL FILTERING (extended)
# ═══════════════════════════════════════════════════════════════════════

def url_1(cl):
    """URL filtering rules exist"""
    d, c = cl.get("/zia/urlFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} URL filtering rule(s).") if r else R(R.FAIL, "No URL filtering rules — all web traffic unfiltered. Best Practice: URL filtering is a foundational ZIA policy. At minimum, block Security Risk categories (malware, phishing, botnets) and Adult Content. Use Cloud App Control for SaaS-specific rules. Ref: ZIA Policy Leading Practices Guide.")

def url_2(cl):
    """URL categories defined"""
    d, c = cl.get("/zia/urlCategories")
    cats = _ls(d) if c in (200, 204) else []
    custom = [x for x in cats if x.get("customCategory")]
    if not cats:
        return R(R.WARN, "No URL categories accessible. Best Practice: Use Zscaler's predefined URL categories plus custom categories for organization-specific sites (e.g., sanctioned SaaS apps, internal domains).")
    return R(R.PASS, f"{len(cats)} categories ({len(custom)} custom). Best Practice: Leverage custom URL categories to group sanctioned/unsanctioned apps for granular policy control.")

def url_3(cl):
    """Malicious/security categories blocked"""
    d, c = cl.get("/zia/urlFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    block = [x for x in r if (x.get("action") or "").upper() in ("BLOCK", "CAUTION")]
    return R(R.PASS, f"{len(block)} block/caution rule(s).") if block else R(R.WARN, "No URL block rules found. Best Practice: Zscaler recommends blocking high-risk URL categories (Malware, Phishing, Spyware, Cryptomining, Unauthorized Communication). Place the most specific block rules at the top of the policy.")

def url_4(cl):
    """URL filter rule scoping"""
    d, c = cl.get("/zia/urlFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    scoped = [x for x in r if x.get("departments") or x.get("groups") or x.get("users")]
    return R(R.PASS, f"{len(scoped)}/{len(r)} rule(s) scoped to users/groups.") if scoped else R(R.WARN, "All URL rules globally scoped. Best Practice: Scope URL filtering rules by department or user group for differentiated access. Cloud App Control policies take precedence over URL Filtering — use CAC for SaaS-specific exceptions.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — SECURITY / MALWARE / ATP
# ═══════════════════════════════════════════════════════════════════════

def sec_1(cl):
    """Security blacklist/whitelist"""
    bl, c1 = cl.get("/zia/security/advanced")
    if c1 not in (200, 204):
        bl, c1 = cl.get("/zia/security/advanced/blacklistUrls")
    urls = _ls(bl) if c1 in (200, 204) else (bl.get("blacklistUrls", []) if isinstance(bl, dict) else [])
    return R(R.PASS, f"{len(urls)} URL(s) on security blacklist.") if urls else R(R.WARN, "Security blacklist empty. Best Practice: Maintain a curated blacklist of known-malicious URLs from threat intelligence feeds. Complement with Zscaler's built-in threat categories for defense-in-depth.")

def sec_2(cl):
    """Sandbox rules"""
    d, c = cl.get("/zia/sandboxRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} sandbox rule(s).") if r else R(R.WARN, "No sandbox rules — unknown files not detonated. Best Practice: Enable Cloud Sandbox to detonate unknown executables, Office docs, and PDFs before delivery. Sandbox requires SSL inspection to scan encrypted downloads. Apply to all users, not just high-risk groups. Ref: Advanced Sandbox Deployment and Operations Guide.")

def sec_3(cl):
    """Malware protection check"""
    d, c = cl.get("/zia/malwareProtection")
    if c in (200, 204):
        if isinstance(d, dict):
            en = d.get("enabled", d.get("malwareProtectionEnabled"))
            return R(R.PASS, "Malware protection enabled. Aligns with Zscaler's Single Scan Multi-Action architecture.") if en else R(R.WARN, "Malware protection disabled. Best Practice: Enable inline malware protection — it runs as part of Zscaler's Single Scan Multi-Action engine with zero additional latency. Covers ransomware, spyware, and antivirus.")
        return R(R.PASS, "Malware protection settings accessible.")
    return R(R.WARN, "Cannot access malware protection settings. Best Practice: Ensure malware protection is enabled. It is a core component of Zscaler's threat protection stack alongside ATP and Sandbox.")

def sec_4(cl):
    """ATP settings"""
    d, c = cl.get("/zia/atpSettings")
    if c == 404:
        d, c = cl.get("/zia/advancedThreatProtection")
    if c in (200, 204):
        return R(R.PASS, "ATP settings configured. Advanced Threat Protection provides IPS-level inspection for web traffic.")
    return R(R.WARN, "ATP settings not accessible. Best Practice: Enable Advanced Threat Protection (ATP) for real-time detection of botnets, C2 callbacks, cross-site scripting, and known exploits. ATP is most effective when combined with SSL inspection for encrypted traffic visibility.")

def sec_5(cl):
    """File type control"""
    d, c = cl.get("/zia/fileTypeControlRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} file type control rule(s).") if r else R(R.WARN, "No file type control rules. Best Practice: Block high-risk file types (EXE, SCR, BAT, PS1, VBS, DLL) from untrusted categories. Allow specific file types only for sanctioned download sources.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — BANDWIDTH CONTROL
# ═══════════════════════════════════════════════════════════════════════

def bw_1(cl):
    """Bandwidth control rules"""
    d, c = cl.get("/zia/bandwidthControlRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} bandwidth control rule(s).") if r else R(R.WARN, "No bandwidth control rules. Best Practice: Use bandwidth control to throttle non-business streaming (YouTube, Netflix) and prioritize business-critical SaaS (M365, Salesforce). Prevents bandwidth-hungry apps from degrading security inspection throughput.")

def bw_2(cl):
    """Bandwidth classes defined"""
    d, c = cl.get("/zia/bandwidthClasses")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} bandwidth class(es).") if r else R(R.WARN, "No bandwidth classes defined. Best Practice: Define bandwidth classes (e.g., Business Critical, General, Streaming, Non-Business) to enforce QoS-style policies through the Zscaler cloud.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — LOCATIONS & TRAFFIC
# ═══════════════════════════════════════════════════════════════════════

def loc_1(cl):
    """Locations configured"""
    d, c = cl.get("/zia/locations")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} location(s) configured.") if r else R(R.WARN, "No locations configured. Note: Locations are required for office/branch traffic forwarding via GRE or IPsec tunnels. ZCC-only deployments (roaming users) may not need locations. If you have offices forwarding traffic to Zscaler, define locations for policy granularity.")

def loc_2(cl):
    """Sub-locations"""
    d, c = cl.get("/zia/locations")
    locs = _ls(d) if c in (200, 204) else []
    subs = [x for x in locs if x.get("parentId") or x.get("parentLocationId")]
    return R(R.PASS, f"{len(subs)} sub-location(s).") if subs else R(R.WARN, "No sub-locations — flat topology. Best Practice: Use sub-locations to segment guest Wi-Fi, IoT networks, and server VLANs with different security policies. Guest Wi-Fi should have an allow-all default after blocking malicious content.")

def loc_3(cl):
    """GRE tunnels"""
    d, c = cl.get("/zia/greTunnels")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} GRE tunnel(s).") if r else R(R.WARN, "No GRE tunnels. Note: GRE/IPsec tunnels are used for office and branch traffic forwarding. Not needed if all users are on ZCC (Client Connector). If you have branch offices, configure redundant GRE tunnels to the nearest Zscaler data centers.")

def loc_4(cl):
    """Static IPs"""
    d, c = cl.get("/zia/staticIPs")
    if c == 404:
        d, c = cl.get("/zia/trafficForwarding/staticIP")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} static IP(s).") if r else R(R.WARN, "No static IPs configured. Note: Static IPs are used for location-based traffic forwarding. Not needed for ZCC-only deployments.")

def loc_5(cl):
    """VPN credentials"""
    d, c = cl.get("/zia/vpnCredentials")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} VPN credential(s).") if r else R(R.WARN, "No VPN credentials — no site-to-site tunnels. Note: IPsec VPN credentials are used for branch office traffic forwarding. Not needed for ZCC-only deployments.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — USER & ADMIN MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════

def usr_1(cl):
    """Users provisioned"""
    d, c = cl.get("/zia/users")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} user(s) provisioned.") if r else R(R.WARN, "No users found in ZIA. Best Practice: Provision users via SCIM or directory sync (AD/Azure AD/Okta) for identity-based policy enforcement. Without users, policies can only apply globally. Ref: User Provisioning and Authentication Guide.")

def usr_2(cl):
    """User groups"""
    d, c = cl.get("/zia/groups")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} user group(s).") if r else R(R.WARN, "No user groups. Best Practice: Sync user groups from your IdP to scope policies by role (e.g., Finance gets stricter DLP, Developers get broader access). Groups are essential for granular URL filtering, DLP, and firewall rules.")

def usr_3(cl):
    """Departments"""
    d, c = cl.get("/zia/departments")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} department(s).") if r else R(R.WARN, "No departments defined. Best Practice: Departments enable policy differentiation by business unit. Sync from directory services for accurate, automated membership.")

def usr_4(cl):
    """Admin roles segregation"""
    d, c = cl.get("/zia/adminRoles")
    if c == 404:
        d, c = cl.get("/zia/adminAndRoleManagement")
    r = _ls(d) if c in (200, 204) else []
    ro = [x for x in r if x.get("isReadOnly") or "read" in (x.get("name") or "").lower()]
    if len(r) >= 3:
        return R(R.PASS, f"{len(r)} role(s), {len(ro)} read-only. Good separation of duties.")
    if len(r) >= 2:
        return R(R.PASS, f"{len(r)} role(s), {len(ro)} read-only.")
    return R(R.WARN, f"Only {len(r)} admin role(s). Best Practice: Implement role segregation with at minimum: Super Admin (full), Security Admin (policy), Read-Only Auditor, and DLP Incident Reviewer roles. Separation of duties is critical for compliance (SOC2, ISO 27001).")

def usr_5(cl):
    """Admin audit logging"""
    d, c = cl.get("/zia/auditlogEntryReport")
    if c in (200, 204):
        return R(R.PASS, "Audit logging accessible. Admin changes are tracked for compliance.")
    return R(R.WARN, "Audit log not accessible via API. Best Practice: Regularly review admin audit logs for unauthorized configuration changes. Export to SIEM for retention beyond 30 days.")

def usr_6(cl):
    """Rule labels for organization"""
    d, c = cl.get("/zia/ruleLabels")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} rule label(s) for policy organization.") if r else R(R.WARN, "No rule labels. Best Practice: Use rule labels to tag policies by project, compliance requirement, or business unit. Labels make it easier to audit and manage policies at scale.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — CLOUD APPLICATIONS
# ═══════════════════════════════════════════════════════════════════════

def capp_1(cl):
    """Cloud App Control rules"""
    d, c = cl.get("/zia/cloudApplicationRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} cloud app control rule(s).") if r else R(R.WARN, "No cloud app control rules — SaaS apps unmanaged. Best Practice: Cloud App Control is Zscaler's inline CASB. Use it to control granular actions (upload, download, share, post) per SaaS app. CAC policies take precedence over URL Filtering — use CAC for SaaS governance. Periodically review shadow IT reports monthly and update sanctioned/unsanctioned app lists. Ref: Cloud App Control Deployment and Operations Guide.")

def capp_2(cl):
    """Tenancy restriction profiles"""
    d, c = cl.get("/zia/tenancyRestrictionProfile")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} tenancy restriction profile(s).") if r else R(R.WARN, "No tenancy restrictions — personal SaaS accounts unrestricted. Best Practice: Configure tenant restrictions to prevent users from accessing personal instances of M365, Google Workspace, Slack, etc. This prevents data exfiltration to personal accounts while still allowing corporate access. Create Tenant Profiles specifying allowed tenants and associate them with CAC rules.")

def capp_3(cl):
    """Cloud app SSL policy"""
    d, c = cl.get("/zia/cloudApplicationSslPolicy")
    if c == 404:
        d, c = cl.get("/zia/cloudApplicationRules")
    r = _ls(d) if c in (200, 204) else []
    ssl_rules = [x for x in r if x.get("sslInspection") or x.get("sslInspectionEnabled")]
    return R(R.PASS, f"{len(ssl_rules)} SSL-inspected cloud app rule(s).") if ssl_rules else R(R.WARN, "No cloud app SSL inspection. Best Practice: SSL inspection must be enabled for Cloud App Control to inspect encrypted SaaS traffic. Without SSL inspection, Zscaler can only see the domain, not the specific actions (upload, download, share) within the application.")


# ═══════════════════════════════════════════════════════════════════════
# ZPA — APPLICATION ACCESS
# ═══════════════════════════════════════════════════════════════════════

def zpa_1(cl):
    """ZPA application segments"""
    d, c = cl.get("/zpa/applicationSegments")
    if c == 404: d, c = cl.get("/zpa/application")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    en = [x for x in r if x.get("enabled")]
    return R(R.PASS, f"{len(en)} enabled of {len(r)} app segment(s).") if r else R(R.WARN, "No ZPA app segments — private access not configured. Best Practice: Define application segments for each private application or group of related apps. Use specific ports/protocols rather than wildcard ranges. Start with common apps (intranet, ERP, dev tools) and expand using Application Discovery. Ref: ZPA Leading Practices Guide.")

def zpa_2(cl):
    """ZPA segment groups"""
    d, c = cl.get("/zpa/segmentGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} segment group(s).") if r else R(R.WARN, "No segment groups. Best Practice: Group related application segments together for easier policy management. Organize by business function (HR apps, Finance apps, Dev tools) or environment (Production, Staging).")

def zpa_3(cl):
    """ZPA server groups"""
    d, c = cl.get("/zpa/serverGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} server group(s).") if r else R(R.WARN, "No server groups. Best Practice: Server groups define which App Connectors can reach which applications. Create server groups per data center or network zone for proper segmentation.")

def zpa_4(cl):
    """App connectors health"""
    d, c = cl.get("/zpa/connector")
    if c == 404: d, c = cl.get("/zpa/appConnectors")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    healthy = [x for x in r if (x.get("runtimeStatus") or x.get("status") or "").upper() == "ONLINE"]
    if not r:
        return R(R.WARN, "No app connectors found. Best Practice: Deploy App Connectors on the same subnet as the applications they serve. Always deploy in pairs (minimum 2 per connector group) for high availability. Zscaler licenses connectors as pairs. Ref: App Connector Deployment and Operations Guide.")
    if not healthy:
        return R(R.FAIL, f"All {len(r)} connectors offline! Immediate action required — private app access is down. Check connector VM health, outbound connectivity to ZPA cloud, and enrollment status.")
    if len(healthy) < len(r):
        return R(R.WARN, f"{len(healthy)}/{len(r)} connectors online. {len(r)-len(healthy)} connector(s) offline — investigate to maintain redundancy. Best Practice: Each connector group should have at least 2 healthy connectors.")
    return R(R.PASS, f"{len(healthy)}/{len(r)} connectors online. Meets Zscaler HA best practice.")

def zpa_5(cl):
    """App connector groups"""
    d, c = cl.get("/zpa/appConnectorGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} connector group(s).") if r else R(R.WARN, "No connector groups. Best Practice: Organize connectors into groups by data center or network zone. Each group should contain at least 2 connectors for redundancy. Deploy across availability zones where possible.")

def zpa_6(cl):
    """ZPA access policies"""
    d, c = cl.get("/zpa/policySet/rules/GLOBAL_POLICY")
    if c == 404: d, c = cl.get("/zpa/policySet/rules")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", d.get("rules", [])))
    return R(R.PASS, f"{len(r)} access policy rule(s).") if r else R(R.WARN, "No ZPA access policies. Best Practice: Define access policies based on user identity, group, device posture, and network context. Follow least-privilege: deny by default and explicitly allow only required app segments per user group. ZPA evaluates rules top-to-bottom. Ref: Access Policy Deployment and Operations Guide.")

def zpa_7(cl):
    """ZPA timeout policies"""
    d, c = cl.get("/zpa/policySet/rules/TIMEOUT_POLICY")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", d.get("rules", [])))
    return R(R.PASS, f"{len(r)} timeout policy rule(s).") if r else R(R.WARN, "No timeout policies — default 15min idle timeout applies. Best Practice: Configure timeout policies per application type. Long-running sessions (RDP, SSH) may need extended timeouts. Short timeouts for web apps improve security by forcing re-authentication.")

def zpa_8(cl):
    """Service edges"""
    d, c = cl.get("/zpa/serviceEdge")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    healthy = [x for x in r if (x.get("runtimeStatus") or x.get("status") or "").upper() == "ONLINE"]
    if not r:
        return R(R.WARN, "No service edges. Note: Private Service Edges are optional — they provide local ZPA brokering for branch offices with poor internet. Required for universal ZTNA (server-to-server) use cases.")
    if not healthy:
        return R(R.FAIL, f"All {len(r)} service edges offline! Private brokering is down.")
    return R(R.PASS, f"{len(healthy)}/{len(r)} service edge(s) online.")

def zpa_9(cl):
    """Service edge groups"""
    d, c = cl.get("/zpa/serviceEdgeGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} service edge group(s).") if r else R(R.WARN, "No service edge groups. Note: Service edge groups are needed only if you deploy Private Service Edges for local ZPA brokering.")

def zpa_10(cl):
    """ZPA certificates"""
    d, c = cl.get("/zpa/certificate")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} certificate(s) enrolled.") if r else R(R.WARN, "No ZPA certificates. Best Practice: Enroll certificates for App Connectors and Service Edges. Use auto-enrollment where possible to avoid expiration issues.")

def zpa_11(cl):
    """Identity providers configured"""
    d, c = cl.get("/zpa/idp")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} IdP(s) configured.") if r else R(R.WARN, "No identity providers — ZPA access not user-aware. Best Practice: Integrate at least one IdP (Azure AD, Okta, Ping) for user authentication. ZPA requires identity context to enforce access policies. SAML-based SSO is recommended.")

def zpa_12(cl):
    """Posture profiles (device trust)"""
    d, c = cl.get("/zpa/postureProfile")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} posture profile(s) for device trust.") if r else R(R.WARN, "No posture profiles — no device trust checks. Best Practice: Configure posture profiles to verify device compliance before granting access: firewall enabled, disk encrypted, domain-joined, OS version, running endpoint protection. Link posture profiles to access policies for zero trust device validation.")

def zpa_13(cl):
    """ZPA trusted networks"""
    d, c = cl.get("/zpa/trustedNetwork")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} trusted network(s).") if r else R(R.WARN, "No trusted networks. Best Practice: Define trusted networks (corporate Wi-Fi, VPN) to allow differentiated access policies — e.g., more permissive access from trusted office networks vs. stricter from public Wi-Fi.")

def zpa_14(cl):
    """LSS (Log Streaming) configured"""
    d, c = cl.get("/zpa/lssConfig")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} LSS config(s) — ZPA logs streaming.") if r else R(R.WARN, "No LSS — ZPA logs not streamed to SIEM. Best Practice: Configure Log Streaming Service (LSS) to send ZPA user activity, connector status, and audit logs to your SIEM. Without LSS, ZPA logs are retained only 30 days in the portal. Ref: SIEM and ZPA Integration Deployment and Operations Guide.")

def zpa_15(cl):
    """Machine groups (for machine-based access)"""
    d, c = cl.get("/zpa/machineGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} machine group(s).") if r else R(R.WARN, "No machine groups. Note: Machine groups enable server-to-server (workload) access without user identity. Needed for automated processes, CI/CD pipelines, and service accounts accessing private apps.")


# ═══════════════════════════════════════════════════════════════════════
# ZCC — DEVICE MANAGEMENT (extended)
# ═══════════════════════════════════════════════════════════════════════

def zcc_1(cl):
    """ZCC trusted networks"""
    d, c = cl.get("/zcc/trustedNetworks")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} trusted network(s) for ZCC.") if r else R(R.WARN, "No ZCC trusted networks. Best Practice: Define trusted networks (corporate office SSIDs/subnets) so ZCC can apply different forwarding behavior on-network vs. off-network. On trusted networks, ZCC can forward to local ZPA Private Service Edges instead of public ZPA cloud.")

def zcc_2(cl):
    """ZCC web policy"""
    d, c = cl.get("/zcc/webPolicies")
    if c == 404: d, c = cl.get("/zcc/webPolicy")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} ZCC web policy/policies.") if r else R(R.WARN, "No ZCC web policies. Best Practice: Configure web policies to control ZCC behavior — enforce proxy settings, configure captive portal detection, and manage the user experience during ZCC enrollment and updates.")

def zcc_3(cl):
    """ZCC fail-open policy"""
    d, c = cl.get("/zcc/failOpenPolicy")
    if c in (200, 204):
        if isinstance(d, dict):
            fo = d.get("enabled", d.get("failOpenEnabled"))
            if fo:
                return R(R.WARN, "Fail-open ENABLED — traffic bypasses Zscaler on failure. Best Practice: Zscaler recommends fail-closed (fail-open disabled) for strict security postures. Fail-open should only be used in environments where internet availability is more critical than security enforcement (e.g., retail POS). Evaluate risk tolerance before enabling.")
            return R(R.PASS, "Fail-open disabled — traffic blocked on Zscaler failure. Aligns with zero trust best practice of fail-closed.")
        return R(R.PASS, "Fail-open policy accessible.")
    return R(R.WARN, "Cannot access fail-open policy. Best Practice: Review fail-open settings in the ZCC admin portal. Fail-closed (default) is recommended for most environments.")

def zcc_4(cl):
    """ZCC device count and platforms"""
    d, c = cl.get("/zcc/devices")
    devs = _ls(d) if c in (200, 204) else []
    if not devs:
        return R(R.WARN, "No devices reporting to ZCC. Best Practice: All managed endpoints should have ZCC installed with Z-Tunnel 2.0 enabled, strict enforcement on, and tamper protection (disable/uninstall passwords) configured. Ref: Zscaler Client Connector Deployment and Operations Guide.")
    plat = {}
    for dv in devs[:500]:
        o = (dv.get("osType") or dv.get("platform") or "?").lower()
        plat[o] = plat.get(o, 0) + 1
    return R(R.PASS, f"{len(devs)} device(s): {', '.join(f'{v}x{k}' for k,v in sorted(plat.items(), key=lambda x: -x[1]))}")

def zcc_5(cl):
    """Company info"""
    d, c = cl.get("/zcc/companyInfo")
    if c in (200, 204) and isinstance(d, dict):
        name = d.get("companyName", d.get("name", "?"))
        return R(R.PASS, f"Company: {name}")
    return R(R.WARN, "Cannot retrieve company info. Note: This may indicate the ZCC API scope is not enabled for this API client. Verify API role includes ZCC read permissions.")


# ═══════════════════════════════════════════════════════════════════════
# FULL PLATFORM REGISTRY
# ═══════════════════════════════════════════════════════════════════════

PLATFORM_REG = [
    # ZIA — Firewall
    ("FW.1", "ZIA — Firewall", "Firewall rules", fw_1),
    ("FW.2", "ZIA — Firewall", "Default rule action", fw_2),
    ("FW.3", "ZIA — Firewall", "DNS control rules", fw_3),
    ("FW.4", "ZIA — Firewall", "IPS rules", fw_4),
    ("FW.5", "ZIA — Firewall", "IP destination groups", fw_5),
    ("FW.6", "ZIA — Firewall", "IP source groups", fw_6),
    ("FW.7", "ZIA — Firewall", "Network services", fw_7),
    ("FW.8", "ZIA — Firewall", "Rule ordering", fw_8),

    # ZIA — URL Filtering
    ("UF.1", "ZIA — URL Filtering", "URL filter rules", url_1),
    ("UF.2", "ZIA — URL Filtering", "URL categories", url_2),
    ("UF.3", "ZIA — URL Filtering", "Block/caution rules", url_3),
    ("UF.4", "ZIA — URL Filtering", "Rule scoping", url_4),

    # ZIA — Security / ATP
    ("SEC.1", "ZIA — Security", "Security blacklist", sec_1),
    ("SEC.2", "ZIA — Security", "Sandbox rules", sec_2),
    ("SEC.3", "ZIA — Security", "Malware protection", sec_3),
    ("SEC.4", "ZIA — Security", "ATP settings", sec_4),
    ("SEC.5", "ZIA — Security", "File type control", sec_5),

    # ZIA — Bandwidth
    ("BW.1", "ZIA — Bandwidth", "Bandwidth rules", bw_1),
    ("BW.2", "ZIA — Bandwidth", "Bandwidth classes", bw_2),

    # ZIA — Locations
    ("LOC.1", "ZIA — Locations", "Locations configured", loc_1),
    ("LOC.2", "ZIA — Locations", "Sub-locations", loc_2),
    ("LOC.3", "ZIA — Locations", "GRE tunnels", loc_3),
    ("LOC.4", "ZIA — Locations", "Static IPs", loc_4),
    ("LOC.5", "ZIA — Locations", "VPN credentials", loc_5),

    # ZIA — User & Admin
    ("USR.1", "ZIA — Users & Admin", "Users provisioned", usr_1),
    ("USR.2", "ZIA — Users & Admin", "User groups", usr_2),
    ("USR.3", "ZIA — Users & Admin", "Departments", usr_3),
    ("USR.4", "ZIA — Users & Admin", "Admin role segregation", usr_4),
    ("USR.5", "ZIA — Users & Admin", "Audit logging", usr_5),
    ("USR.6", "ZIA — Users & Admin", "Rule labels", usr_6),

    # ZIA — Cloud Apps
    ("CA.1", "ZIA — Cloud Apps", "Cloud app control", capp_1),
    ("CA.2", "ZIA — Cloud Apps", "Tenancy restrictions", capp_2),
    ("CA.3", "ZIA — Cloud Apps", "Cloud app SSL", capp_3),

    # ZPA — Application Access
    ("ZPA.1", "ZPA — App Access", "Application segments", zpa_1),
    ("ZPA.2", "ZPA — App Access", "Segment groups", zpa_2),
    ("ZPA.3", "ZPA — App Access", "Server groups", zpa_3),
    ("ZPA.4", "ZPA — App Access", "Connector health", zpa_4),
    ("ZPA.5", "ZPA — App Access", "Connector groups", zpa_5),
    ("ZPA.6", "ZPA — App Access", "Access policies", zpa_6),
    ("ZPA.7", "ZPA — App Access", "Timeout policies", zpa_7),
    ("ZPA.8", "ZPA — App Access", "Service edges", zpa_8),
    ("ZPA.9", "ZPA — App Access", "Service edge groups", zpa_9),
    ("ZPA.10", "ZPA — App Access", "Certificates", zpa_10),
    ("ZPA.11", "ZPA — App Access", "Identity providers", zpa_11),
    ("ZPA.12", "ZPA — App Access", "Posture profiles", zpa_12),
    ("ZPA.13", "ZPA — App Access", "Trusted networks", zpa_13),
    ("ZPA.14", "ZPA — App Access", "Log streaming (LSS)", zpa_14),
    ("ZPA.15", "ZPA — App Access", "Machine groups", zpa_15),

    # ZCC — Device Management
    ("ZCC.1", "ZCC — Devices", "Trusted networks", zcc_1),
    ("ZCC.2", "ZCC — Devices", "Web policies", zcc_2),
    ("ZCC.3", "ZCC — Devices", "Fail-open policy", zcc_3),
    ("ZCC.4", "ZCC — Devices", "Device inventory", zcc_4),
    ("ZCC.5", "ZCC — Devices", "Company info", zcc_5),
]
