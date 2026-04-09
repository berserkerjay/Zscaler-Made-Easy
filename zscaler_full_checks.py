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
        return R(R.WARN, "No cloud firewall rules configured.")
    en = [x for x in r if x.get("state", "").upper() == "ENABLED"]
    return R(R.PASS, f"{len(en)} active of {len(r)} firewall rule(s).")

def fw_2(cl):
    """Firewall default rule action"""
    d, c = cl.get("/zia/firewallRules")
    r = _ls(d) if c in (200, 204) else []
    default = [x for x in r if "default" in (x.get("name") or "").lower()]
    if default:
        act = default[0].get("action", "?")
        return R(R.PASS, f"Default rule action: {act}") if act.upper() in ("BLOCK_DROP", "BLOCK_RESET", "DROP") else R(R.WARN, f"Default rule action is {act} — consider Block/Drop.")
    return R(R.WARN, "No default firewall rule found.")

def fw_3(cl):
    """DNS control rules"""
    d, c = cl.get("/zia/dnsRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} DNS control rule(s).") if r else R(R.WARN, "No DNS control rules.")

def fw_4(cl):
    """IPS rules configured"""
    d, c = cl.get("/zia/ipsRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} IPS rule(s).") if r else R(R.WARN, "No IPS rules — threat detection limited.")

def fw_5(cl):
    """IP destination groups"""
    d, c = cl.get("/zia/ipDestinationGroups")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} IP destination group(s).") if r else R(R.WARN, "No IP destination groups defined.")

def fw_6(cl):
    """IP source groups"""
    d, c = cl.get("/zia/ipSourceGroups")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} IP source group(s).") if r else R(R.WARN, "No IP source groups defined.")

def fw_7(cl):
    """Network services defined"""
    d, c = cl.get("/zia/networkServices")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} network service(s).") if r else R(R.WARN, "No custom network services.")

def fw_8(cl):
    """Firewall rule ordering"""
    d, c = cl.get("/zia/firewallRules")
    r = _ls(d) if c in (200, 204) else []
    if len(r) < 2:
        return R(R.PASS, "Single or no rules — no ordering issues.")
    # Check if broad allow is above specific block
    for i, rule in enumerate(r):
        a = (rule.get("action") or "").upper()
        broad = not rule.get("srcIpGroups") and not rule.get("destIpGroups") and not rule.get("departments")
        if a == "ALLOW" and broad and i < len(r) - 1:
            return R(R.WARN, f"Broad ALLOW at position {i+1} may shadow later rules.")
    return R(R.PASS, f"Firewall rule order appears valid ({len(r)} rules).")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — URL FILTERING (extended)
# ═══════════════════════════════════════════════════════════════════════

def url_1(cl):
    """URL filtering rules exist"""
    d, c = cl.get("/zia/urlFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} URL filtering rule(s).") if r else R(R.FAIL, "No URL filtering rules — all web traffic unfiltered.")

def url_2(cl):
    """URL categories defined"""
    d, c = cl.get("/zia/urlCategories")
    cats = _ls(d) if c in (200, 204) else []
    custom = [x for x in cats if x.get("customCategory")]
    return R(R.PASS, f"{len(cats)} categories ({len(custom)} custom).") if cats else R(R.WARN, "No URL categories.")

def url_3(cl):
    """Malicious/security categories blocked"""
    d, c = cl.get("/zia/urlFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    block = [x for x in r if (x.get("action") or "").upper() in ("BLOCK", "CAUTION")]
    return R(R.PASS, f"{len(block)} block/caution rule(s).") if block else R(R.WARN, "No URL block rules found.")

def url_4(cl):
    """URL filter rule scoping"""
    d, c = cl.get("/zia/urlFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    scoped = [x for x in r if x.get("departments") or x.get("groups") or x.get("users")]
    return R(R.PASS, f"{len(scoped)}/{len(r)} rule(s) scoped to users/groups.") if scoped else R(R.WARN, "All URL rules globally scoped.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — SECURITY / MALWARE / ATP
# ═══════════════════════════════════════════════════════════════════════

def sec_1(cl):
    """Security blacklist/whitelist"""
    bl, c1 = cl.get("/zia/security/advanced")
    if c1 not in (200, 204):
        bl, c1 = cl.get("/zia/security/advanced/blacklistUrls")
    urls = _ls(bl) if c1 in (200, 204) else (bl.get("blacklistUrls", []) if isinstance(bl, dict) else [])
    return R(R.PASS, f"{len(urls)} URL(s) on security blacklist.") if urls else R(R.WARN, "Security blacklist empty.")

def sec_2(cl):
    """Sandbox rules"""
    d, c = cl.get("/zia/sandboxRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} sandbox rule(s).") if r else R(R.WARN, "No sandbox rules — unknown files not detonated.")

def sec_3(cl):
    """Malware protection check"""
    d, c = cl.get("/zia/malwareProtection")
    if c in (200, 204):
        if isinstance(d, dict):
            en = d.get("enabled", d.get("malwareProtectionEnabled"))
            return R(R.PASS, "Malware protection enabled.") if en else R(R.WARN, "Malware protection disabled.")
        return R(R.PASS, "Malware protection settings accessible.")
    return R(R.WARN, "Cannot access malware protection settings.")

def sec_4(cl):
    """ATP settings"""
    d, c = cl.get("/zia/atpSettings")
    if c == 404:
        d, c = cl.get("/zia/advancedThreatProtection")
    if c in (200, 204):
        return R(R.PASS, "ATP settings configured.")
    return R(R.WARN, "ATP settings not accessible.")

def sec_5(cl):
    """File type control"""
    d, c = cl.get("/zia/fileTypeControlRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} file type control rule(s).") if r else R(R.WARN, "No file type control rules.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — BANDWIDTH CONTROL
# ═══════════════════════════════════════════════════════════════════════

def bw_1(cl):
    """Bandwidth control rules"""
    d, c = cl.get("/zia/bandwidthControlRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} bandwidth control rule(s).") if r else R(R.WARN, "No bandwidth control rules.")

def bw_2(cl):
    """Bandwidth classes defined"""
    d, c = cl.get("/zia/bandwidthClasses")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} bandwidth class(es).") if r else R(R.WARN, "No bandwidth classes defined.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — LOCATIONS & TRAFFIC
# ═══════════════════════════════════════════════════════════════════════

def loc_1(cl):
    """Locations configured"""
    d, c = cl.get("/zia/locations")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} location(s) configured.") if r else R(R.WARN, "No locations configured.")

def loc_2(cl):
    """Sub-locations"""
    d, c = cl.get("/zia/locations")
    locs = _ls(d) if c in (200, 204) else []
    subs = [x for x in locs if x.get("parentId") or x.get("parentLocationId")]
    return R(R.PASS, f"{len(subs)} sub-location(s).") if subs else R(R.WARN, "No sub-locations — flat topology.")

def loc_3(cl):
    """GRE tunnels"""
    d, c = cl.get("/zia/greTunnels")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} GRE tunnel(s).") if r else R(R.WARN, "No GRE tunnels.")

def loc_4(cl):
    """Static IPs"""
    d, c = cl.get("/zia/staticIPs")
    if c == 404:
        d, c = cl.get("/zia/trafficForwarding/staticIP")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} static IP(s).") if r else R(R.WARN, "No static IPs configured.")

def loc_5(cl):
    """VPN credentials"""
    d, c = cl.get("/zia/vpnCredentials")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} VPN credential(s).") if r else R(R.WARN, "No VPN credentials — no site-to-site tunnels.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — USER & ADMIN MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════

def usr_1(cl):
    """Users provisioned"""
    d, c = cl.get("/zia/users")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} user(s) provisioned.") if r else R(R.WARN, "No users found in ZIA.")

def usr_2(cl):
    """User groups"""
    d, c = cl.get("/zia/groups")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} user group(s).") if r else R(R.WARN, "No user groups — can't scope policies.")

def usr_3(cl):
    """Departments"""
    d, c = cl.get("/zia/departments")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} department(s).") if r else R(R.WARN, "No departments defined.")

def usr_4(cl):
    """Admin roles segregation"""
    d, c = cl.get("/zia/adminRoles")
    if c == 404:
        d, c = cl.get("/zia/adminAndRoleManagement")
    r = _ls(d) if c in (200, 204) else []
    ro = [x for x in r if x.get("isReadOnly") or "read" in (x.get("name") or "").lower()]
    return R(R.PASS, f"{len(r)} role(s), {len(ro)} read-only.") if len(r) >= 2 else R(R.WARN, f"Only {len(r)} admin role(s) — add role segregation.")

def usr_5(cl):
    """Admin audit logging"""
    d, c = cl.get("/zia/auditlogEntryReport")
    if c in (200, 204):
        return R(R.PASS, "Audit logging accessible.")
    return R(R.WARN, "Audit log not accessible via API.")

def usr_6(cl):
    """Rule labels for organization"""
    d, c = cl.get("/zia/ruleLabels")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} rule label(s) for policy organization.") if r else R(R.WARN, "No rule labels — policies may be disorganized.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — CLOUD APPLICATIONS
# ═══════════════════════════════════════════════════════════════════════

def capp_1(cl):
    """Cloud App Control rules"""
    d, c = cl.get("/zia/cloudApplicationRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} cloud app control rule(s).") if r else R(R.WARN, "No cloud app control rules — SaaS apps unmanaged.")

def capp_2(cl):
    """Tenancy restriction profiles"""
    d, c = cl.get("/zia/tenancyRestrictionProfile")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} tenancy restriction profile(s).") if r else R(R.WARN, "No tenancy restrictions — personal SaaS accounts unrestricted.")

def capp_3(cl):
    """Cloud app SSL policy"""
    d, c = cl.get("/zia/cloudApplicationSslPolicy")
    if c == 404:
        d, c = cl.get("/zia/cloudApplicationRules")
    r = _ls(d) if c in (200, 204) else []
    ssl_rules = [x for x in r if x.get("sslInspection") or x.get("sslInspectionEnabled")]
    return R(R.PASS, f"{len(ssl_rules)} SSL-inspected cloud app rule(s).") if ssl_rules else R(R.WARN, "No cloud app SSL inspection.")


# ═══════════════════════════════════════════════════════════════════════
# ZPA — APPLICATION ACCESS
# ═══════════════════════════════════════════════════════════════════════

def zpa_1(cl):
    """ZPA application segments"""
    d, c = cl.get("/zpa/applicationSegments")
    if c == 404:
        d, c = cl.get("/zpa/application")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    en = [x for x in r if x.get("enabled")]
    return R(R.PASS, f"{len(en)} enabled of {len(r)} app segment(s).") if r else R(R.WARN, "No ZPA app segments — private access not configured.")

def zpa_2(cl):
    """ZPA segment groups"""
    d, c = cl.get("/zpa/segmentGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} segment group(s).") if r else R(R.WARN, "No segment groups.")

def zpa_3(cl):
    """ZPA server groups"""
    d, c = cl.get("/zpa/serverGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} server group(s).") if r else R(R.WARN, "No server groups.")

def zpa_4(cl):
    """App connectors health"""
    d, c = cl.get("/zpa/connector")
    if c == 404:
        d, c = cl.get("/zpa/appConnectors")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    healthy = [x for x in r if (x.get("runtimeStatus") or x.get("status") or "").upper() == "ONLINE"]
    if not r:
        return R(R.WARN, "No app connectors found.")
    return R(R.PASS, f"{len(healthy)}/{len(r)} connectors online.") if healthy else R(R.FAIL, f"All {len(r)} connectors offline!")

def zpa_5(cl):
    """App connector groups"""
    d, c = cl.get("/zpa/appConnectorGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} connector group(s).") if r else R(R.WARN, "No connector groups.")

def zpa_6(cl):
    """ZPA access policies"""
    d, c = cl.get("/zpa/policySet/rules/GLOBAL_POLICY")
    if c == 404:
        d, c = cl.get("/zpa/policySet/rules")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", d.get("rules", [])))
    return R(R.PASS, f"{len(r)} access policy rule(s).") if r else R(R.WARN, "No ZPA access policies.")

def zpa_7(cl):
    """ZPA timeout policies"""
    d, c = cl.get("/zpa/policySet/rules/TIMEOUT_POLICY")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", d.get("rules", [])))
    return R(R.PASS, f"{len(r)} timeout policy rule(s).") if r else R(R.WARN, "No timeout policies — default 15min idle timeout applies.")

def zpa_8(cl):
    """Service edges"""
    d, c = cl.get("/zpa/serviceEdge")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    healthy = [x for x in r if (x.get("runtimeStatus") or x.get("status") or "").upper() == "ONLINE"]
    if not r:
        return R(R.WARN, "No service edges.")
    return R(R.PASS, f"{len(healthy)}/{len(r)} service edge(s) online.") if healthy else R(R.FAIL, f"All {len(r)} service edges offline!")

def zpa_9(cl):
    """Service edge groups"""
    d, c = cl.get("/zpa/serviceEdgeGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} service edge group(s).") if r else R(R.WARN, "No service edge groups.")

def zpa_10(cl):
    """ZPA certificates"""
    d, c = cl.get("/zpa/certificate")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} certificate(s) enrolled.") if r else R(R.WARN, "No ZPA certificates.")

def zpa_11(cl):
    """Identity providers configured"""
    d, c = cl.get("/zpa/idp")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} IdP(s) configured.") if r else R(R.WARN, "No identity providers — ZPA access not user-aware.")

def zpa_12(cl):
    """Posture profiles (device trust)"""
    d, c = cl.get("/zpa/postureProfile")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} posture profile(s) for device trust.") if r else R(R.WARN, "No posture profiles — no device trust checks.")

def zpa_13(cl):
    """ZPA trusted networks"""
    d, c = cl.get("/zpa/trustedNetwork")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} trusted network(s).") if r else R(R.WARN, "No trusted networks.")

def zpa_14(cl):
    """LSS (Log Streaming) configured"""
    d, c = cl.get("/zpa/lssConfig")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} LSS config(s) — ZPA logs streaming.") if r else R(R.WARN, "No LSS — ZPA logs not streamed to SIEM.")

def zpa_15(cl):
    """Machine groups (for machine-based access)"""
    d, c = cl.get("/zpa/machineGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} machine group(s).") if r else R(R.WARN, "No machine groups.")


# ═══════════════════════════════════════════════════════════════════════
# ZCC — DEVICE MANAGEMENT (extended)
# ═══════════════════════════════════════════════════════════════════════

def zcc_1(cl):
    """ZCC trusted networks"""
    d, c = cl.get("/zcc/trustedNetworks")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} trusted network(s) for ZCC.") if r else R(R.WARN, "No ZCC trusted networks.")

def zcc_2(cl):
    """ZCC web policy"""
    d, c = cl.get("/zcc/webPolicies")
    if c == 404:
        d, c = cl.get("/zcc/webPolicy")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} ZCC web policy/policies.") if r else R(R.WARN, "No ZCC web policies.")

def zcc_3(cl):
    """ZCC fail-open policy"""
    d, c = cl.get("/zcc/failOpenPolicy")
    if c in (200, 204):
        if isinstance(d, dict):
            fo = d.get("enabled", d.get("failOpenEnabled"))
            return R(R.WARN, "Fail-open ENABLED — traffic bypasses Zscaler on failure.") if fo else R(R.PASS, "Fail-open disabled — traffic blocked on failure.")
        return R(R.PASS, "Fail-open policy accessible.")
    return R(R.WARN, "Cannot access fail-open policy.")

def zcc_4(cl):
    """ZCC device count and platforms"""
    d, c = cl.get("/zcc/devices")
    devs = _ls(d) if c in (200, 204) else []
    if not devs:
        return R(R.WARN, "No devices reporting.")
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
    return R(R.WARN, "Cannot retrieve company info.")


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
