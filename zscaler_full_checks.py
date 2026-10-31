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

# Reuse the Result class and helpers from the main engine
import re
from dlp_assessment_full_auto import (R, _ls, _fv, _names, _enabled, _truthy, _cac_live, _cac_rules_all_types, _tenancy,
                                      _ssl_enabled, _ssl_action, _SSL_INSPECT, _SSL_DNI)

_FW_BP = " Ref: https://help.zscaler.com/zia/best-practices-firewall-control-policy"
_POLICY_GUIDE = " Ref: https://help.zscaler.com/zscaler-deployments-operations/zia-policy-leading-practices-guide"
_ZPA_GUIDE = " Ref: https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide"


# ── A refused read is never judged ────────────────────────────────────
# The guard (_ReadLog, permission_guarded, guard_registry) lives in the engine,
# whose own registry runs through it too; it is re-exported here for the
# platform, GenAI, automation, ZDX, ZIdentity and RBAC registries.
from dlp_assessment_full_auto import _REFUSED, _ReadLog, _not_permitted, permission_guarded, guard_registry  # noqa: E402,F401


def _items(cl, path):
    d, c = cl.get(path)
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict):
        r = _ls(d.get("list", []))
    return [x for x in r if isinstance(x, dict)], c


def _by_order(r):
    def o(x):
        try:
            return int(_fv(x, "order") or 0)
        except (TypeError, ValueError):
            return 0
    return sorted(r, key=o)


def _builtin(x):
    return _truthy(_fv(x, "predefined")) or _truthy(_fv(x, "defaultRule"))


# ═══════════════════════════════════════════════════════════════════════
# ZIA — FIREWALL
# ═══════════════════════════════════════════════════════════════════════

def fw_1(cl):
    """Cloud Firewall rules exist"""
    d, c = cl.get("/zia/firewallFilteringRules")
    r = _ls(d) if c in (200, 204) else []
    if not r:
        return R(R.WARN, "No cloud firewall rules configured. Best Practice: Zscaler recommends implementing cloud firewall rules with a default deny-all policy for regulated environments. Rules should control non-web traffic (SSH, RDP, FTP) that bypasses URL filtering. Ref: Firewall Deployment and Operations Guide.")
    en = [x for x in r if x.get("state", "").upper() == "ENABLED"]
    return R(R.PASS, f"{len(en)} active of {len(r)} firewall rule(s).")

def fw_2(cl):
    """Firewall default rule action"""
    r, c = _items(cl, "/zia/firewallFilteringRules")
    # The predefined rule says so (defaultRule); a rule merely named "...default..." is a fallback.
    default = [x for x in r if _truthy(_fv(x, "defaultRule"))] or [x for x in r if "default" in str(x.get("name") or "").lower()]
    if default:
        act = str(_fv(default[0], "action") or "?")
        # Firewall filtering actions: ALLOW, BLOCK_DROP, BLOCK_RESET, BLOCK_ICMP, EVAL_NWAPP (ZIA API reference; assumed, the SDK does not list them).
        if act.upper().startswith("BLOCK"):
            return R(R.PASS, f"Default rule action: {act}. Aligns with Zscaler best practice of deny-all default posture.")
        return R(R.WARN, f"Default rule action is {act}. Best Practice: Zscaler recommends enabling the Default Firewall Filtering Rule with the Block action and the lowest rule order, so anything no rule allows is dropped. Ref: https://help.zscaler.com/zia/best-practices-firewall-control-policy")
    return R(R.WARN, "No default firewall rule found. Best Practice: Enable the predefined Default Firewall Filtering Rule with the Block action at the lowest rule order, and keep the Recommended Firewall Rule as a narrow Allow for HTTP, HTTPS and DNS. Ref: https://help.zscaler.com/zia/best-practices-firewall-control-policy")

def fw_3(cl):
    """DNS control rules"""
    d, c = cl.get("/zia/firewallDnsRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} DNS control rule(s).") if r else R(R.WARN, "No DNS control rules. Best Practice: Configure DNS control rules to prevent DNS-based data exfiltration and enforce DNS resolution through Zscaler. DNS tunneling is a common exfiltration vector.")

def fw_4(cl):
    """IPS rules configured: the Default Cloud IPS Rule blocks"""
    r, c = _items(cl, "/zia/firewallIpsRules")
    if not r:
        return R(R.WARN, "No IPS rules. Best Practice: Enable IPS (Intrusion Prevention System) to detect and block exploits, C2 callbacks, and lateral movement. IPS requires SSL inspection to be effective on encrypted traffic. Requires Advanced Firewall." + _FW_BP)
    # Zscaler provides a Default Cloud IPS Rule that cannot be deleted; what matters is that it blocks.
    dflt = [x for x in r if _truthy(_fv(x, "defaultRule"))] or [x for x in r if "default" in str(x.get("name") or "").lower()]
    act = lambda x: str(_fv(x, "action") or "").upper()
    scope = ("users", "groups", "departments", "locations", "locationGroups")
    bypass = [str(x.get("name", "?")) for x in r if x not in dflt and _enabled(x) and act(x) in ("ALLOW", "BYPASS_IPS") and not any(_fv(x, k) for k in scope)]
    tail = (f" Unscoped Allow/Bypass IPS rule(s) above it: {', '.join(bypass[:4])}." if bypass else "")
    bp = " Best Practice: enable the predefined Default Cloud IPS Rule with the Block action at the lowest rule order; scope any exclusions (e.g. security researchers) in higher-order rules. Requires Advanced Firewall."
    if not dflt:
        return R(R.WARN, f"{len(r)} IPS rule(s), but the Default Cloud IPS Rule was not found." + tail + bp + _FW_BP)
    d0 = dflt[0]
    if _enabled(d0) and act(d0) in ("BLOCK_DROP", "BLOCK_RESET", "BLOCK"):
        return (R(R.WARN, f"The Default Cloud IPS Rule blocks ({act(d0)})." + tail + bp + _FW_BP) if bypass
                else R(R.PASS, f"The Default Cloud IPS Rule is enabled with {act(d0)}; {len(r)} IPS rule(s)."))
    return R(R.WARN, f"The Default Cloud IPS Rule is {'disabled' if not _enabled(d0) else act(d0) or 'not blocking'}." + tail + bp + _FW_BP)

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
    r, c = _items(cl, "/zia/networkServices")
    # The list includes Zscaler's STANDARD and PREDEFINED services; only CUSTOM ones are the tenant's own.
    custom = [x for x in r if str(_fv(x, "type") or "").upper() == "CUSTOM"]
    if custom:
        return R(R.PASS, f"{len(custom)} custom of {len(r)} network service(s).")
    return R(R.INFO, f"No custom network services ({len(r)} standard or predefined). Zscaler does not require custom services; define them for protocols your organization uses that no predefined service covers. Zscaler recommends ranking network service rules higher than network application rules to prevent unnecessary packet pass-through.")

_FW_CONDITIONS = ("users", "groups", "departments", "srcIps", "srcIpGroups", "destAddresses", "destIpGroups", "destIpCategories", "destCountries",
                  "nwServices", "nwServiceGroups", "nwApplications", "nwApplicationGroups", "appServices", "appServiceGroups", "locations", "locationGroups")


def fw_8(cl):
    """Firewall rule ordering: Allow rules built from at least three conditions"""
    r, c = _items(cl, "/zia/firewallFilteringRules")
    live = [x for x in _by_order(r) if _enabled(x) and not _builtin(x)]
    weak = []
    for x in live:
        if str(_fv(x, "action") or "").upper() != "ALLOW":
            continue
        conds = [k for k in _FW_CONDITIONS if _fv(x, k)]
        if len(conds) < 3 or set(conds) <= {"nwApplications", "nwApplicationGroups"}:
            weak.append(f"{x.get('name', '?')} (order {x.get('order', '?')}: {', '.join(conds) or 'no condition'})")
    if weak:
        return R(R.WARN, f"{len(weak)} enabled Allow rule(s) have fewer than three conditions or match only on network applications: {'; '.join(weak[:4])}. Best Practice: Zscaler processes firewall rules top-to-bottom, first match wins; build every Allow rule from at least three conditions and place specific deny rules above broad allow rules." + _FW_BP)
    return R(R.PASS, f"Firewall rule order appears valid ({len(live)} enabled custom rule(s)): every Allow rule has at least three conditions.")

def fw_9(cl):
    """Recommended block rules: malicious IPs and domains, QUIC, ICMP, SMB"""
    r, c = _items(cl, "/zia/firewallFilteringRules")
    if not r:
        return R(R.INFO, "No firewall rules to check (FW.1).")
    ordered = _by_order(r)
    live = [x for x in ordered if _enabled(x)]
    blocks = [x for x in live if str(_fv(x, "action") or "").upper().startswith("BLOCK")]
    svc = lambda x: " ".join(_names(_fv(x, "nwServices")) + _names(_fv(x, "nwServiceGroups")))
    fails, warns, ok = [], [], []
    mal = [x for x in r if "malicious" in str(x.get("name") or "").lower()]
    if not mal:
        warns.append("the predefined 'Block Malicious IPs and Domains' rule was not found")
    elif not any(_enabled(x) for x in mal):
        fails.append("the predefined 'Block Malicious IPs and Domains' rule is disabled")
    else:
        ok.append("Block Malicious IPs and Domains is on")
    quic = [x for x in blocks if "QUIC" in svc(x)]
    first_allow = next((i for i, x in enumerate(live) if str(_fv(x, "action") or "").upper() == "ALLOW" and not _builtin(x)), None)
    if not quic:
        warns.append("no enabled Block rule for the QUIC network service (add UDP 80 to it as well)")
    elif first_allow is not None and live.index(quic[0]) > first_allow:
        warns.append(f"the QUIC block rule '{quic[0].get('name', '?')}' sits below a custom Allow rule; QUIC block rules must precede admin-defined allow rules")
    else:
        ok.append("QUIC blocked")
    info = [p for p, k in (("ICMP", "ICMP"), ("SMB", "SMB")) if not any(k in svc(x) for x in blocks)]
    note = (f" Consider also Block rules for {' and '.join(info)} (Zscaler's firewall best-practice table)." if info else "")
    ref = _FW_BP + " ; https://help.zscaler.com/zia/managing-quic-protocol"
    if fails:
        return R(R.FAIL, "; ".join(fails + warns) + "." + note + ref)
    if warns:
        msg = "; ".join(warns)
        return R(R.WARN, msg[:1].upper() + msg[1:] + "." + note + ref)
    return R(R.PASS, ", ".join(ok) + "." + note)


# ═══════════════════════════════════════════════════════════════════════
# ZIA — URL FILTERING (extended)
# ═══════════════════════════════════════════════════════════════════════

def url_1(cl):
    """URL filtering rules exist"""
    r, c = _items(cl, "/zia/urlFilteringRules")
    on = [x for x in r if str(_fv(x, "state") or "").upper() == "ENABLED"]
    return R(R.PASS, f"{len(on)} enabled of {len(r)} URL filtering rule(s).") if on else R(R.FAIL, "No enabled URL Filtering rules; the unwritten default rule allows everything. Best Practice: follow Zscaler's Global > Specific > Global baseline: custom exception Allow, custom Block, a Global Security-based Block (Newly Registered and Observed Domains, Anonymizer, Peer-to-Peer, Spyware/Adware, ...), user-group rules, then Global Category Blocks such as adult content. Malware, phishing and botnets are handled by Advanced Threat Protection." + _POLICY_GUIDE)

def url_2(cl):
    """URL categories defined"""
    cats, c = _items(cl, "/zia/urlCategories")
    custom = [x for x in cats if _truthy(_fv(x, "customCategory"))]
    if not cats:
        return R(R.WARN, "No URL categories accessible. Best Practice: Use Zscaler's predefined URL categories plus custom categories for organization-specific sites (e.g., sanctioned SaaS apps, internal domains).")
    bp = " Best Practice: maintain a Custom Exceptions category (FQDNs to allow that policy would otherwise block) and a Custom Blocks category, used in the first two URL Filtering rules. Up to 64 custom categories are allowed." + _POLICY_GUIDE
    if not custom:
        return R(R.WARN, f"No custom URL categories ({len(cats)} predefined)." + bp)
    rules, _ = _items(cl, "/zia/urlFilteringRules")
    used = {n for x in rules for n in _names(_fv(x, "urlCategories"))}
    idle = [str(x.get("configuredName") or x.get("id")) for x in custom if str(x.get("id")).upper() not in used and rules]
    return R(R.PASS, f"{len(cats)} categories ({len(custom)} custom)." + (f" Not used by any URL Filtering rule: {', '.join(idle[:4])}." if idle else ""))

def url_3(cl):
    """Security URL categories blocked"""
    r, c = _items(cl, "/zia/urlFilteringRules")
    block = [x for x in r if _enabled(x) and str(_fv(x, "action") or "").upper() == "BLOCK"]
    bp = (" Best Practice: Add a Global Security-based Block rule near the top covering Newly Registered and Observed Domains, Newly Revived Domains, Peer-to-Peer Site, Anonymizer,"
          " Computer Hacking, Copyright Infringement, Custom Encrypted Content, Other Security and Spyware/Adware. Malware, phishing, botnet and cryptomining are blocked by"
          " Advanced Threat Protection, not URL categories." + _POLICY_GUIDE)
    if not block:
        return R(R.WARN, "No enabled URL Filtering Block rule (Caution warns and then lets the user through)." + bp)
    cats, _ = _items(cl, "/zia/urlCategories")
    sec = {str(x.get("id")).upper() for x in cats if str(_fv(x, "superCategory") or "").upper() == "SECURITY"}
    hit = {n for x in block for n in _names(_fv(x, "urlCategories"))} & sec
    if sec and not hit:
        return R(R.WARN, f"{len(block)} enabled Block rule(s), but none covers the Security super category." + bp)
    return R(R.PASS, f"{len(block)} enabled Block rule(s)" + (f", covering {len(hit)} Security category(ies)." if hit else "."))

def url_4(cl):
    """URL filter rule scoping"""
    r, c = _items(cl, "/zia/urlFilteringRules")
    scoped = [x for x in r if x.get("departments") or x.get("groups") or x.get("users")]
    return R(R.PASS, f"{len(scoped)}/{len(r)} rule(s) scoped to users/groups.") if scoped else R(R.WARN, "All URL rules globally scoped. Best Practice: Scope URL filtering rules by department or user group for differentiated access. By default, the Cloud App Control policy takes precedence over the URL Filtering policy — use CAC for SaaS-specific exceptions, and keep Cascading to URL Filtering disabled (CA.5).")

# ═══════════════════════════════════════════════════════════════════════
# ZIA — SECURITY / MALWARE / ATP
# ═══════════════════════════════════════════════════════════════════════

def sec_1(cl):
    """Security blacklist/whitelist"""
    bl, c1 = cl.get("/zia/security/advanced")
    urls = (bl.get("blacklistUrls") or []) if c1 in (200, 204) and isinstance(bl, dict) else []
    return R(R.PASS, f"{len(urls)} URL(s) on security blacklist.") if urls else R(R.WARN, "Security blacklist empty. Best Practice: Maintain a curated blacklist of known-malicious URLs from threat intelligence feeds. Complement with Zscaler's built-in threat categories for defense-in-depth.")

def sec_2(cl):
    """Sandbox rules"""
    d, c = cl.get("/zia/sandboxRules")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} sandbox rule(s).") if r else R(R.WARN, "No sandbox rules — unknown files not detonated. Best Practice: Enable Cloud Sandbox to detonate unknown executables, Office docs, and PDFs before delivery. Sandbox requires SSL inspection to scan encrypted downloads. Apply to all users, not just high-risk groups. Ref: Advanced Sandbox Deployment and Operations Guide.")

_MALWARE_BLOCKED = ("virusBlocked", "trojanBlocked", "wormBlocked", "ransomwareBlocked", "remoteAccessToolBlocked", "unwantedApplicationsBlocked", "adwareBlocked", "spywareBlocked")


def sec_3(cl):
    """Malware protection check"""
    d, c = cl.get("/zia/cyberThreatProtection/malwareSettings")
    ref = " Ref: https://help.zscaler.com/zia/configuring-malware-protection-policy"
    if c in (200, 204) and isinstance(d, dict):
        # MalwareSettings has only per-category *Blocked / *Capture booleans (zscaler-sdk-python malware_protection_settings.py).
        off = [k for k in _MALWARE_BLOCKED if _fv(d, k) is not None and not _truthy(_fv(d, k))]
        seen = [k for k in _MALWARE_BLOCKED if _fv(d, k) is not None]
        if off:
            return R(R.WARN, f"Malware Protection does not block: {', '.join(off)}. Zscaler recommends not changing the default Malware Protection settings (all categories blocked)." + ref)
        if seen:
            return R(R.PASS, f"Malware Protection blocks all {len(seen)} categories reported ({', '.join(k.replace('Blocked', '') for k in seen)}).")
        return R(R.INFO, "Malware Protection settings are readable but report no category; check them in the portal." + ref)
    return R(R.WARN, "Cannot access malware protection settings. Best Practice: Ensure malware protection is enabled. It is a core component of Zscaler's threat protection stack alongside ATP and Sandbox." + ref)

_ATP_BLOCKED = ("cmdCtlServerBlocked", "cmdCtlTrafficBlocked", "malwareSitesBlocked", "activeXBlocked", "browserExploitsBlocked", "fileFormatVunerabilitesBlocked",
                "knownPhishingSitesBlocked", "suspectedPhishingSitesBlocked", "suspectAdwareSpywareSitesBlocked", "webspamBlocked", "ircTunnellingBlocked",
                "anonymizerBlocked", "cookieStealingBlocked", "potentialMaliciousRequestsBlocked", "dgaDomainsBlocked", "bitTorrentBlocked", "torBlocked")


def sec_4(cl):
    """ATP settings against Zscaler's recommended Advanced Threat Protection policy"""
    d, c = cl.get("/zia/cyberThreatProtection/advancedThreatSettings")
    ref = " Ref: https://help.zscaler.com/zia/recommended-advanced-threat-protection-policy"
    bp = " Zscaler's recommended ATP policy: Page Risk 35; Botnet, Malicious Active Content, Fraud, Unauthorized Communication and XSS protection: Block all; BitTorrent and Tor: Block."
    if c in (200, 204) and isinstance(d, dict):
        issues = []
        risk = _fv(d, "riskTolerance")
        try:
            if risk is not None and int(risk) > 35:
                issues.append(f"Page Risk tolerance {int(risk)} (recommended 35)")
        except (TypeError, ValueError):
            pass
        off = [k for k in _ATP_BLOCKED if _fv(d, k) is not None and not _truthy(_fv(d, k))]
        if off:
            issues.append("not blocked: " + ", ".join(off[:8]) + (f" and {len(off) - 8} more" if len(off) > 8 else ""))
        if issues:
            return R(R.WARN, "ATP settings are weaker than Zscaler's recommendation: " + "; ".join(issues) + "." + bp + ref)
        return R(R.PASS, "ATP settings match Zscaler's recommended policy where the API reports them (Page Risk at or below 35, the threat categories blocked).")
    return R(R.WARN, "ATP settings not accessible. Best Practice: Enable Advanced Threat Protection (ATP) for real-time detection of botnets, C2 callbacks, cross-site scripting, and known exploits. ATP is most effective when combined with SSL inspection for encrypted traffic visibility." + ref)

def sec_5(cl):
    """File type control against Zscaler's recommended policy"""
    r, c = _items(cl, "/zia/fileTypeRules")
    ref = " Ref: https://help.zscaler.com/zia/recommended-file-type-control-policy"
    bp = " Zscaler's recommended File Type Control policy: Caution on Executable downloads from any URL category, Block on Executable uploads to any URL category; with Advanced Sandbox, quarantine first-time executable downloads."
    on = [x for x in r if _enabled(x)]
    if not on:
        return R(R.WARN, "No enabled file type control rules." + bp + ref)
    def exe(x): return any("EXE" in n or "EXECUTABLE" in n for n in _names(_fv(x, "fileTypes")))
    def act(x): return str(_fv(x, "filteringAction") or _fv(x, "action") or "").upper()
    def ops(x): return {str(o).upper() for o in (_fv(x, "operation") if isinstance(_fv(x, "operation"), list) else [_fv(x, "operation")]) if o}
    down = [x for x in on if exe(x) and act(x) in ("CAUTION", "BLOCK") and (not ops(x) or ops(x) & {"DOWNLOAD", "UPLOAD_DOWNLOAD"})]
    up = [x for x in on if exe(x) and act(x) == "BLOCK" and (not ops(x) or ops(x) & {"UPLOAD", "UPLOAD_DOWNLOAD"})]
    miss = ([] if down else ["no Caution or Block on executable downloads"]) + ([] if up else ["no Block on executable uploads"])
    if miss:
        return R(R.WARN, f"{len(on)} enabled file type rule(s), but " + " and ".join(miss) + "." + bp + ref)
    return R(R.PASS, f"{len(on)} enabled file type rule(s), including Caution or Block on executable downloads and Block on executable uploads.")

# ═══════════════════════════════════════════════════════════════════════
# ZIA — BANDWIDTH CONTROL
# ═══════════════════════════════════════════════════════════════════════

def bw_1(cl):
    """Bandwidth control rules and location limits"""
    r, c = _items(cl, "/zia/bandwidthControlRules")
    ref = " Bandwidth Control applies only to traffic from known locations with upload and download limits set (Zscaler suggests 70-80% of the link). It does not apply to remote Client Connector users. Ref: https://help.zscaler.com/zia/about-bandwidth-control"
    if not r:
        return R(R.WARN, "No bandwidth control rules. Best Practice: Use bandwidth control to throttle non-business streaming (YouTube, Netflix) and prioritize business-critical SaaS (M365, Salesforce)." + ref)
    on = [x for x in r if _enabled(x)]
    locs, _ = _items(cl, "/zia/locations")
    def num(v):
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0
    limited = [x for x in locs if num(_fv(x, "upBandwidth")) > 0 and num(_fv(x, "dnBandwidth")) > 0]
    if on and locs and not limited:
        return R(R.WARN, f"{len(on)} enabled bandwidth rule(s), but no location has upload and download limits (upBandwidth / dnBandwidth 0 means no Bandwidth Control enforcement), so the rules never apply." + ref)
    return R(R.PASS, f"{len(r)} bandwidth control rule(s)" + (f"; {len(limited)} location(s) with bandwidth limits." if locs else "."))

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
    d, c = cl.get("/zia/staticIP")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} static IP(s).") if r else R(R.WARN, "No static IPs configured. Note: Static IPs are used for location-based traffic forwarding. Not needed for ZCC-only deployments.")

def loc_5(cl):
    """VPN credentials"""
    d, c = cl.get("/zia/vpnCredentials")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} VPN credential(s).") if r else R(R.WARN, "No VPN credentials — no site-to-site tunnels. Note: IPsec VPN credentials are used for branch office traffic forwarding. Not needed for ZCC-only deployments.")


def loc_6(cl):
    """Firewall and IPS enabled per location"""
    locs, c = _items(cl, "/zia/locations")
    if not locs:
        return R(R.INFO, "No locations to check (LOC.1).")
    nofw = [str(x.get("name", "?")) for x in locs if _fv(x, "ofwEnabled") is not None and not _truthy(_fv(x, "ofwEnabled"))]
    noips = [str(x.get("name", "?")) for x in locs if _truthy(_fv(x, "ofwEnabled")) and _fv(x, "ipsControl") is not None and not _truthy(_fv(x, "ipsControl"))]
    if nofw or noips:
        parts = ([f"Firewall off on {len(nofw)} location(s): {', '.join(nofw[:5])}"] if nofw else []) + ([f"IPS Control off on {len(noips)}: {', '.join(noips[:5])}"] if noips else [])
        return R(R.WARN, "; ".join(parts) + ". Firewall, DNS and IPS rules do not apply to these locations. Enable Firewall (and IPS Control) on each location and sublocation that needs them." + _POLICY_GUIDE)
    return R(R.PASS, f"Firewall (and IPS where reported) enabled on all {len(locs)} location(s).")


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
    r = _ls(d) if c in (200, 204) else []
    ro = [x for x in r if x.get("isReadOnly") or "read" in (x.get("name") or "").lower()]
    if len(r) >= 3:
        return R(R.PASS, f"{len(r)} role(s), {len(ro)} read-only. Good separation of duties.")
    if len(r) >= 2:
        return R(R.PASS, f"{len(r)} role(s), {len(ro)} read-only.")
    return R(R.WARN, f"Only {len(r)} admin role(s). Best Practice: Implement role segregation with at minimum: Super Admin (full), Security Admin (policy), Read-Only Auditor, and DLP Incident Reviewer roles. Separation of duties is critical for compliance (SOC2, ISO 27001).")

def usr_5(cl):
    """Admin audit log exported (Admin Audit NSS feed)"""
    # GET /auditlogEntryReport only returns the status of a report someone
    # requested (it needs the statusId of a POST); ZIA always records admin
    # actions, so what is worth checking is whether they are exported.
    feeds, c = _items(cl, "/zia/nssFeeds")
    aud = [f for f in feeds if str(_fv(f, "nssLogType") or "").upper() == "ADMIN_AUDIT" and str(_fv(f, "feedStatus") or "ENABLED").upper() == "ENABLED"]
    if aud:
        return R(R.PASS, f"{len(aud)} enabled Admin Audit Cloud NSS feed(s): admin and API changes reach the SIEM beyond ZIA's six-month audit log.")
    return R(R.INFO, "ZIA records every admin and API change and keeps audit logs for up to 6 months. Stream them to your SIEM with a Cloud NSS Admin Audit feed to keep them longer and alert on changes. Ref: https://help.zscaler.com/zia/about-audit-logs")

def usr_6(cl):
    """Rule labels for organization"""
    d, c = cl.get("/zia/ruleLabels")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} rule label(s) for policy organization.") if r else R(R.WARN, "No rule labels. Best Practice: Use rule labels to tag policies by project, compliance requirement, or business unit. Labels make it easier to audit and manage policies at scale.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — GOVERNANCE AND AUDIT
# ═══════════════════════════════════════════════════════════════════════
# Zscaler's own configuration audit, alert subscriptions and the NSS VMs,
# each read once (GET only) and checked against the organisation's
# subscriptions so a feature the tenant does not own is N/A, not a gap.
# Paths from zscaler-sdk-python 1.11.3: system_audit.get_config_audit
# (/configAudit), alert_subscriptions.list_alert_subscriptions
# (/alertSubscriptions), nss_servers.list_nss_servers (/nssServers),
# nss_collectors.list_collectors (/nssCollectors), cloud_nss.list_nss_feed
# (/nssFeeds) and organization_information.get_subscriptions (/subscriptions).
# Recipients and admin names are counted, never listed.

import re as _re   # noqa: E402
import time as _time   # noqa: E402

# Control characters, and the zero-width and bidi overrides that make text read differently from what it is.
_GOV_CTRL = _re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]+")
_LOG_SKUS = ("Z_LOGFEED", "Z_CLOUD_NSS_WEB")   # SKU ids as readiness.SKU_INFO names them (assumed: the SDK lists no SKU names)


def _gov_text(v, limit=200):
    """Tenant text made short and inert: control characters out, spaces
    collapsed, capped. Escaping for HTML, Markdown, CSV and the rest is the
    output's job; this keeps a long or odd value from swamping a finding."""
    t = " ".join(_GOV_CTRL.sub(" ", str(v if v is not None else "")).split())
    return t if len(t) <= limit else t[: limit - 1] + "…"


_SKU_ID = _re.compile(r"[A-Z0-9_]{2,64}")


def _subscriptions(cl):
    """The organisation's active SKU ids, or None when the subscriptions
    could not be read (then nothing is marked N/A on their account).
    organization_information.get_subscriptions reads GET /subscriptions;
    the body is assumed to be a list of {id, status, subscribed, ...} (the
    SDK models one object). Parsed here, not with readiness, which decodes
    unverified token claims and is kept out of every other module."""
    d, c = cl.get("/zia/subscriptions")
    if c != 200:
        return None
    rows = d if isinstance(d, list) else (d.get("list") if isinstance(d, dict) else None)
    if not isinstance(rows, list):
        return None
    seen, active = 0, set()
    for r in rows[:300]:
        sid = r.get("id") if isinstance(r, dict) else None
        if not isinstance(sid, str) or not _SKU_ID.fullmatch(sid):
            continue
        seen += 1
        status = str(r.get("status") or "").upper()
        if r.get("subscribed") is not False and "EXPIRED" not in status and "CANCEL" not in status:
            active.add(sid)
    return active if seen else None   # nothing understood: no evidence a feature is missing


def _not_licensed(feature):
    return R(R.INFO, f"N/A: {feature} is not licensed on this tenant (no active subscription for it), so there is nothing to check.")


# Zscaler's configuration audit: field → (plain name, recommended-config field).
# Grades are assumed to be letters (A best … F worst) or words (GOOD, POOR):
# the SDK model (zia/models/system_audit.py ConfigAudit) declares the fields
# but not their values.
_AUDIT_ITEMS = {
    "highAvailabilityGrade": ("High availability", None),
    "greTunnelGrade": ("GRE tunnels", "greTunnelRecommendedConfiguration"),
    "authFrequencyGrade": ("Authentication frequency", "authFrequencyRecommendedConfiguration"),
    "pacFileGrade": ("PAC file", "pacFileRecommendedConfiguration"),
    "pacfileSizeGrade": ("PAC file size", "pacFileSizeRecommendedConfiguration"),
    "office365Grade": ("Microsoft 365 one-click", "office365RecommendedConfiguration"),
    "ipVisibilityGrade": ("Client IP visibility", "ipVisibilityRecommendedConfiguration"),
    "userPerformanceGrade": ("User performance", None),
    "otherGrade": ("Other settings", None),
}
_GOOD_WORDS = {"GOOD", "EXCELLENT", "PASS", "OK", "OPTIMAL", "GREEN"}
_BAD_WORDS = {"POOR", "BAD", "FAIL", "FAILED", "WARN", "WARNING", "CRITICAL", "RED", "NEEDS_IMPROVEMENT", "AVERAGE", "FAIR"}


def _grade(v):
    """'good', 'bad' or None (not graded / not understood) for one audit grade (assumed scale)."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return "good" if v >= 80 else "bad"   # assumed: a 0-100 score
    g = str(v).strip().upper().replace(" ", "_")
    if not g or g in ("NA", "N/A", "NONE", "NOT_APPLICABLE", "UNKNOWN"):
        return None
    if g in _GOOD_WORDS or g[0] in "AB" and len(g) <= 2:
        return "good"
    if g in _BAD_WORDS or g[0] in "CDEF" and len(g) <= 2:
        return "bad"
    return None


def _config_audit(cl):
    """The configuration audit report as one dict, or (None, why)."""
    d, c = cl.get("/zia/configAudit")
    if c not in (200, 204):
        return None, f"The configuration audit report could not be read (HTTP {c}); reading it needs the Reports functional scope on the API role."
    rows = [x for x in (d if isinstance(d, list) else [d]) if isinstance(x, dict) and not x.get("error")]
    rep = rows[0] if rows else None
    if not rep or _fv(rep, "dataPresent") is False:
        return None, "Zscaler has no configuration audit report for this tenant yet (no data present). It appears under Analytics > System Audit Report once ZIA has enough traffic."
    return rep, ""


def _audit_items(rep, fields):
    bad, good, ungraded = [], [], []
    for f in fields:
        name, rec_field = _AUDIT_ITEMS[f]
        v = _fv(rep, f)
        g = _grade(v)
        if g == "bad":
            rec = _gov_text(_fv(rep, rec_field), 160).rstrip(" .;") if rec_field and _fv(rep, rec_field) else ""
            bad.append(f"{name} (grade {_gov_text(v, 12)})" + (f": {rec}" if rec else ""))
        elif g == "good":
            good.append(f"{name} ({_gov_text(v, 12)})")
        elif v not in (None, ""):
            ungraded.append(name)
    return bad, good, ungraded


def _audit_when(rep):
    ts = _fv(rep, "reportTimestamp")
    if isinstance(ts, (int, float)) and not isinstance(ts, bool) and 0 < ts < 32503680000 * 1000:
        ts = ts / 1000.0 if ts > 1e11 else float(ts)
        return " (report of " + _time.strftime("%Y-%m-%d", _time.gmtime(ts)) + ")"
    return ""


def gov_1(cl):
    """Zscaler's configuration audit: overall grade"""
    rep, why = _config_audit(cl)
    if rep is None:
        return R(R.INFO, why)
    g = _fv(rep, "overallGrade")
    bad, _good, _u = _audit_items(rep, list(_AUDIT_ITEMS))
    verdict = _grade(g)
    when = _audit_when(rep)
    if verdict == "good" and not bad:
        return R(R.PASS, f"Zscaler's own configuration audit grades this tenant {_gov_text(g, 12)} overall{when}, with no item graded poorly.")
    if verdict is None and not bad:
        return R(R.INFO, f"Zscaler's configuration audit reports no overall grade the app understands{when}. Review it under Analytics > System Audit Report.")
    return R(R.WARN, f"Zscaler's own configuration audit grades this tenant {_gov_text(g, 12) or 'without an overall grade'}{when}; {len(bad)} item(s) graded poorly: "
                     + "; ".join(bad[:6]) + ". Best Practice: work through each poorly graded item in Analytics > System Audit Report: it is Zscaler's own view of where the tenant departs from its recommended configuration."
                     " Ref: https://help.zscaler.com/zia/about-system-audit-report")


def _gov_audit(cl, fields, topic, fix):
    rep, why = _config_audit(cl)
    if rep is None:
        return R(R.INFO, why)
    bad, good, ungraded = _audit_items(rep, fields)
    when = _audit_when(rep)
    if bad:
        return R(R.WARN, f"Zscaler's configuration audit grades {topic} poorly{when}: " + "; ".join(bad) + f". Best Practice: {fix} Ref: https://help.zscaler.com/zia/about-system-audit-report")
    if good:
        return R(R.PASS, f"Zscaler's configuration audit grades {topic} well{when}: " + ", ".join(good) + ".")
    return R(R.INFO, f"Zscaler's configuration audit does not grade {topic} on this tenant{when}" + (f" (grades not understood: {', '.join(ungraded)})" if ungraded else "") + ".")


def gov_2(cl):
    """Configuration audit: high availability and GRE tunnels"""
    return _gov_audit(cl, ["highAvailabilityGrade", "greTunnelGrade"], "high availability and the GRE tunnels",
                      "give every location a primary and a backup tunnel to two different Zscaler data centres, as the audit recommends, so one data centre outage does not cut the office off.")


def gov_3(cl):
    """Configuration audit: authentication frequency"""
    return _gov_audit(cl, ["authFrequencyGrade"], "the authentication frequency",
                      "authenticate users no more often than needed (the audit's recommended frequency): too often costs users time, too rarely leaves stale identities on policy decisions.")


def gov_4(cl):
    """Configuration audit: PAC files"""
    return _gov_audit(cl, ["pacFileGrade", "pacfileSizeGrade"], "the PAC files",
                      "keep PAC files small and simple and send traffic to Zscaler with a fallback, as the audit recommends: a large or broken PAC file slows every browser and can send traffic direct.")


def gov_5(cl):
    """Configuration audit: Microsoft 365, IP visibility and performance"""
    return _gov_audit(cl, ["office365Grade", "ipVisibilityGrade", "userPerformanceGrade", "otherGrade"], "Microsoft 365, client IP visibility and user performance",
                      "turn on Microsoft 365 one-click configuration and make sure the client IP reaches Zscaler (X-Forwarded-For or a tunnel), so policy and logs see the real user and Microsoft 365 traffic takes the fast path.")


def gov_6(cl):
    """Alert subscriptions reach someone"""
    subs, c = _items(cl, "/zia/alertSubscriptions")
    if c not in (200, 204):
        return R(R.INFO, f"Alert subscriptions could not be read (HTTP {c}).")
    live = [s for s in subs if not _truthy(_fv(s, "deleted"))]
    sev_fields = ("pt0Severities", "secureSeverities", "manageSeverities", "complySeverities", "systemSeverities")
    covered = {f for s in live for f in sev_fields if isinstance(_fv(s, f), list) and _fv(s, f)}
    recipients = {str(_fv(s, "email") or "").strip().lower() for s in live if _fv(s, "email")}
    if not live:
        return R(R.WARN, "No alert subscription is set up: nobody is e-mailed when ZIA raises a security, compliance or system alert. "
                         "Best Practice: subscribe a monitored team mailbox to Critical and Major alerts of every class (Patient 0, Secure, Manage, Comply, System) under Administration > Alerts."
                         " Ref: https://help.zscaler.com/zia/about-alert-subscriptions")
    names = {"pt0Severities": "Patient 0", "secureSeverities": "Secure", "manageSeverities": "Manage", "complySeverities": "Comply", "systemSeverities": "System"}
    missing = [names[f] for f in sev_fields if f not in covered]
    who = f"{len(live)} alert subscription(s) to {len(recipients)} recipient(s)"
    if missing:
        return R(R.WARN, f"{who}, but no subscription covers these alert classes: {', '.join(missing)}. "
                         "Best Practice: make sure every alert class (Patient 0, Secure, Manage, Comply, System) reaches a monitored mailbox, at least for Critical and Major severities."
                         " Ref: https://help.zscaler.com/zia/about-alert-subscriptions")
    if len(recipients) < 2:
        return R(R.WARN, f"{who}: every alert goes to one address. Best Practice: send alerts to a team mailbox or at least two recipients, so an alert is not lost when one person is away.")
    return R(R.PASS, f"{who}, covering every alert class.")


def _nss_state(x):
    """'up', 'down' or 'unknown' for one NSS server. status is ENABLED,
    DISABLED, DISABLED_BY_SERVICE_PROVIDER, NOT_PROVISIONED_IN_SERVICE_PROVIDER
    or IN_TRIAL (nss_servers.add_nss_server docstring); state is assumed to be
    HEALTHY or UNHEALTHY (the SDK does not list its values)."""
    status = str(_fv(x, "status") or "").upper()
    state = str(_fv(x, "state") or "").upper()
    if status and status not in ("ENABLED", "IN_TRIAL"):
        return "down"
    if "UNHEALTHY" in state or state in ("DOWN", "DISCONNECTED", "OFFLINE", "ERROR"):
        return "down"
    if state in ("HEALTHY", "UP", "CONNECTED", "ONLINE"):
        return "up"
    return "unknown"


def gov_7(cl):
    """NSS servers (VMs) are enabled and healthy"""
    servers, c = _items(cl, "/zia/nssServers")
    if c not in (200, 204):
        return R(R.INFO, f"NSS servers could not be read (HTTP {c}).")
    subs = _subscriptions(cl)
    if not servers:
        if subs is not None and not (subs & set(_LOG_SKUS)):
            return _not_licensed("Nanolog Streaming Service (NSS)")
        return R(R.INFO, "No NSS server (VM) is registered on this tenant. If logs are streamed with Cloud NSS instead, there is no VM to watch; see the log streaming check.")
    down = [x for x in servers if _nss_state(x) == "down"]
    unknown = [x for x in servers if _nss_state(x) == "unknown"]
    if down:
        return R(R.WARN, f"{len(down)} of {len(servers)} NSS server(s) are disabled or unhealthy: the feeds they carry stop reaching the SIEM, and ZIA keeps the logs only in its own store. "
                         "Best Practice: bring every NSS VM back to Enabled and healthy (check its connection to the Zscaler cloud and to the SIEM), and run two NSS VMs per feed type for redundancy."
                         " Ref: https://help.zscaler.com/zia/about-nss-servers")
    if unknown:
        return R(R.INFO, f"{len(servers)} NSS server(s) enabled; {len(unknown)} report no health state, so the app cannot say whether they stream. Check them under Administration > Nanolog Streaming Service.")
    return R(R.PASS, f"All {len(servers)} NSS server(s) are enabled and healthy.")


def gov_8(cl):
    """Logs leave ZIA: a healthy NSS server, a Cloud NSS feed or an NSS collector"""
    servers, sc = _items(cl, "/zia/nssServers")
    feeds, fc = _items(cl, "/zia/nssFeeds")
    collectors, cc = _items(cl, "/zia/nssCollectors")
    if sc not in (200, 204) and fc not in (200, 204) and cc not in (200, 204):
        return R(R.INFO, f"NSS servers, feeds and collectors could not be read (HTTP {sc}, {fc}, {cc}).")
    up = [x for x in servers if _nss_state(x) != "down"]
    live_feeds = [f for f in feeds if str(_fv(f, "feedStatus") or "ENABLED").upper() == "ENABLED"]
    live_coll = [x for x in collectors if str(_fv(x, "status") or "ENABLED").upper() in ("ENABLED", "ACTIVE", "UP", "HEALTHY")]
    if live_feeds or up or live_coll:
        parts = [f"{len(live_feeds)} enabled Cloud NSS feed(s)", f"{len(up)} NSS server(s) not reported down", f"{len(live_coll)} NSS collector(s)"]
        if servers and not up:
            return R(R.WARN, "; ".join(parts) + f". Every one of the {len(servers)} NSS server(s) is down, so the feeds they carry do not stream.")
        return R(R.PASS, "Logs leave ZIA for a SIEM: " + "; ".join(parts) + ".")
    subs = _subscriptions(cl)
    if subs is not None and not (subs & set(_LOG_SKUS)):
        return _not_licensed("Nanolog Streaming Service (NSS and Cloud NSS)")
    return R(R.WARN, "No log stream leaves ZIA: no enabled Cloud NSS feed, no healthy NSS server and no NSS collector. ZIA keeps web logs for 6 months and nobody outside the console sees them. "
                     "Best Practice: stream web, firewall, DNS, DLP and admin audit logs to your SIEM with Cloud NSS (or NSS VMs) so incidents are correlated and logs outlive ZIA's retention."
                     " Ref: https://help.zscaler.com/zia/about-nanolog-streaming-service")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — CLOUD APPLICATIONS
# ═══════════════════════════════════════════════════════════════════════

def capp_1(cl):
    """Cloud App Control rules"""
    d, c = cl.get("/zia/cloudApplicationRules")
    r = _ls(d) if c in (200, 204) else []
    live = _cac_live(r)
    bp = " Best Practice: Cloud App Control is Zscaler's inline CASB. Use it to control granular actions (upload, download, share, post) per SaaS app. CAC policies take precedence over URL Filtering — use CAC for SaaS governance. Periodically review shadow IT reports monthly and update sanctioned/unsanctioned app lists. Ref: https://help.zscaler.com/zia/about-cloud-app-control"
    if live:
        return R(R.PASS, f"{len(live)} enabled cloud app control rule(s).")
    if r:
        return R(R.WARN, "Only Zscaler's predefined rules (disabled by default) or disabled rules exist, so no Cloud App Control rule is in force." + bp)
    return R(R.WARN, "No cloud app control rules — SaaS apps unmanaged." + bp)

def capp_2(cl):
    """Tenancy restriction profiles attached to Cloud App Control rules"""
    return _tenancy(cl, " Zscaler inserts the tenant-restriction headers only when the profile is associated with a Cloud App Control rule. Select the app's login service"
                        " (e.g. Microsoft Login Services, Google Login Services, Webex Login Services) in an SSL Inspection rule so the traffic is decrypted. For YouTube and AWS,"
                        " add an explicit block rule for other tenants. Supported apps include Microsoft Login Services, Google, Slack, Dropbox, GitHub, ChatGPT, Claude, Zoom,"
                        " Webex, AWS, GCP and YouTube. Ref: https://help.zscaler.com/zia/adding-tenant-profiles")

def capp_3(cl):
    """Cloud app SSL policy: the controlled apps are decrypted"""
    # Neither /cloudApplications/sslPolicy nor Cloud App Control rules carry an SSL field;
    # decryption is decided by SSL Inspection rules (cloudApplications criterion).
    d, c = cl.get("/zia/sslInspectionRules")
    ssl = [x for x in (_ls(d) if c in (200, 204) else []) if isinstance(x, dict) and _ssl_enabled(x)]
    ref = " Ref: https://help.zscaler.com/zia/adding-tenant-profiles"
    if c not in (200, 204):
        return R(R.INFO, f"SSL Inspection rules are not readable (HTTP {c}); check that the controlled cloud apps are decrypted." + ref)
    dec = [x for x in ssl if _ssl_action(x) in _SSL_INSPECT and (_names(_fv(x, "cloudApplications")) or not (_fv(x, "urlCategories") or _fv(x, "cloudApplications")))]
    cac = _cac_live(_cac_rules_all_types(cl))
    controlled = {a for r in cac if any(str(x).upper().startswith("DENY_") for x in (_fv(r, "actions") or [])) or _fv(r, "tenancyProfileIds")
                  for a in _names(_fv(r, "applications"))}
    dni_apps = {a for x in ssl if _ssl_action(x) in _SSL_DNI for a in _names(_fv(x, "cloudApplications"))}
    clash = sorted(controlled & dni_apps)
    bp = " Granular controls (upload, post) and tenant profiles need SSL inspection: \"SSL inspection is necessary for the additional feature to work.\""
    if clash:
        return R(R.WARN, f"Do Not Decrypt rules exempt apps that Cloud App Control restricts: {', '.join(clash[:5])}; those controls cannot apply." + bp + ref)
    if dec:
        return R(R.PASS, f"{len(dec)} enabled Decrypt rule(s) cover all traffic or name cloud apps, so Cloud App Control can see the actions inside them.")
    return R(R.WARN, "No enabled Decrypt rule covers all traffic or names cloud apps." + bp + ref)

def capp_4(cl):
    """DNS over HTTPS services blocked in Cloud App Control"""
    rules = [r for r in _cac_live(_cac_rules_all_types(cl)) if str(_fv(r, "type") or "").upper() == "DNS_OVER_HTTPS"]
    deny = [r for r in rules if any(str(a).upper().startswith("DENY") or "BLOCK" in str(a).upper() for a in (_fv(r, "actions") or []))]
    if deny:
        return R(R.PASS, f"{len(deny)} enabled DNS over HTTPS Cloud App Control rule(s) block DoH services: {', '.join(str(r.get('name', '?')) for r in deny[:3])}.")
    return R(R.WARN, "No enabled Cloud App Control rule blocks DNS over HTTPS services. If you use Zscaler DNS Control, Zscaler recommends blocking DNS over HTTPS services so DNS requests are captured by DNS Control." + _POLICY_GUIDE)


def capp_5(cl):
    """Cascading to URL Filtering disabled"""
    d, c = cl.get("/zia/advancedSettings")
    if c not in (200, 204) or not isinstance(d, dict):
        return R(R.INFO, f"Advanced Settings are not readable (HTTP {c}); check Cascading to URL Filtering in the portal." + _POLICY_GUIDE)
    cas = [str(r.get("name", "?")) for r in _cac_live(_cac_rules_all_types(cl)) if _truthy(_fv(r, "cascadingEnabled"))]
    tail = (f" {len(cas)} enabled Cloud App Control rule(s) also cascade: {', '.join(cas[:4])}." if cas else "")
    if _truthy(_fv(d, "cascadeUrlFiltering")):
        return R(R.WARN, "Cascading to URL Filtering is enabled. Zscaler recommends Disable: it is a global option that sends traffic Cloud App Control allowed on to URL Filtering, and \"often causes more issues than it resolves\"; by default an app explicitly allowed by Cloud App Control skips URL Filtering." + tail + _POLICY_GUIDE)
    return (R(R.WARN, "Cascading to URL Filtering is off globally." + tail + " Review why those rules cascade." + _POLICY_GUIDE) if cas
            else R(R.PASS, "Cascading to URL Filtering is disabled, as Zscaler recommends."))


# ═══════════════════════════════════════════════════════════════════════
# ZPA — APPLICATION ACCESS
# ═══════════════════════════════════════════════════════════════════════

def zpa_1(cl):
    """ZPA application segments"""
    r, c = _items(cl, "/zpa/application")
    en = [x for x in r if x.get("enabled")]
    if not r:
        return R(R.WARN, "No ZPA app segments — private access not configured. Best Practice: Define application segments for each private application or group of related apps. Use specific ports/protocols rather than wildcard ranges. Start with common apps (intranet, ERP, dev tools) and expand using Application Discovery." + _ZPA_GUIDE)
    import re as _re
    def ports(x):
        # tcpPortRanges is a flat list of from/to pairs (["53", "53", "80", "443"]);
        # tcpPortRange is a list of {from, to} (zscaler-sdk-python ApplicationSegment).
        vals = [str(v) for v in (_fv(x, "tcpPortRanges") or [])]
        out = [(int(a), int(b)) for a, b in zip(vals[0::2], vals[1::2]) if a.isdigit() and b.isdigit()]
        for p in (_fv(x, "tcpPortRange") or []):
            if isinstance(p, dict) and str(p.get("from", "")).isdigit():
                out.append((int(p["from"]), int(p.get("to") or p["from"])))
        return out
    dns = [str(x.get("name", "?")) for x in r if any(a <= 53 <= b for a, b in ports(x))]
    def big(dn):
        m = _re.search(r"/(\d+)$", str(dn))
        return bool(m) and int(m.group(1)) <= 16
    wide = [str(x.get("name", "?")) for x in r if any(big(dn) for dn in (_fv(x, "domainNames") or []))]
    hr = [str(x.get("name", "?")) for x in r if str(_fv(x, "healthReporting") or "").upper() in ("NONE", "CONTINUOUS")]
    issues = ([f"TCP port 53 in {', '.join(dns[:3])}"] if dns else []) + ([f"/16 or wider IP ranges in {', '.join(wide[:3])}"] if wide else []) + ([f"health reporting None or Continuous in {', '.join(hr[:3])} (review; 6k targets per connector group)"] if hr else [])
    if issues:
        return R(R.WARN, f"{len(en)} enabled of {len(r)} app segment(s); " + "; ".join(issues) + ". Best Practice: do not send DNS through ZPA; avoid large IP ranges and use wildcard domains with a time limit; review health reporting None/Continuous." + _ZPA_GUIDE)
    return R(R.PASS, f"{len(en)} enabled of {len(r)} app segment(s).")

def zpa_2(cl):
    """ZPA segment groups"""
    d, c = cl.get("/zpa/segmentGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} segment group(s).") if r else R(R.WARN, "No segment groups. Best Practice: Group related application segments together for easier policy management. Organize by business function (HR apps, Finance apps, Dev tools) or environment (Production, Staging).")

def zpa_3(cl):
    """ZPA server groups"""
    r, c = _items(cl, "/zpa/serverGroup")
    if not r:
        return R(R.WARN, "No server groups. Best Practice: Server groups define which App Connectors can reach which applications. Create server groups per data center or network zone for proper segmentation.")
    manual = [str(x.get("name", "?")) for x in r if _fv(x, "dynamicDiscovery") is not None and not _truthy(_fv(x, "dynamicDiscovery"))]
    if manual:
        return R(R.INFO, f"{len(r)} server group(s); {len(manual)} list servers manually: {', '.join(manual[:4])}. Zscaler recommends dynamic server discovery in server groups by default; confirm why these do not use it." + _ZPA_GUIDE)
    return R(R.PASS, f"{len(r)} server group(s).")

_ZPN_UP = "ZPN_STATUS_AUTHENTICATED"


def _zpn_status(x):
    """Connector and Private Service Edge status is controlChannelStatus
    (ZPN_STATUS_AUTHENTICATED / ZPN_STATUS_DISCONNECTED — zscaler-sdk-python
    zpa/models/app_connectors.py, service_edges.py)."""
    return str(_fv(x, "controlChannelStatus") or "").upper()


def zpa_4(cl):
    """App connectors health"""
    r, c = _items(cl, "/zpa/connector")
    bp = " Best Practice: Size each App Connector group for N+1 redundancy: one App Connector handles up to 500 Mbps, so add connectors for throughput plus one spare. Keep connectors in a group at the same location (same latitude/longitude), and use one group per logical application domain (a VPC, a data center)." + _ZPA_GUIDE
    if not r:
        return R(R.WARN, "No app connectors found." + bp)
    if not any(_zpn_status(x) for x in r):
        return R(R.INFO, f"{len(r)} connector(s); their status (controlChannelStatus) is not reported, so health cannot be checked here.")
    healthy = [x for x in r if _zpn_status(x) == _ZPN_UP]
    if not healthy:
        return R(R.FAIL, f"All {len(r)} connectors offline! Immediate action required — private app access is down. Check connector VM health, outbound connectivity to ZPA cloud, and enrollment status.")
    if len(healthy) < len(r):
        return R(R.WARN, f"{len(healthy)}/{len(r)} connectors online. {len(r)-len(healthy)} connector(s) offline — investigate to maintain N+1 redundancy." + bp)
    return R(R.PASS, f"{len(healthy)}/{len(r)} connectors online.")

def zpa_5(cl):
    """App connector groups"""
    r, c = _items(cl, "/zpa/appConnectorGroup")
    bp = " Best Practice: Size each App Connector group for N+1 redundancy: one App Connector handles up to 500 Mbps, so add connectors for throughput plus one spare. Keep connectors in a group at the same location (same latitude/longitude), and use one group per logical application domain (a VPC, a data center)." + _ZPA_GUIDE
    if not r:
        return R(R.WARN, "No connector groups." + bp)
    spread = []
    for g in r:
        locs = {(str(_fv(x, "latitude") or ""), str(_fv(x, "longitude") or "")) for x in (_fv(g, "connectors") or []) if isinstance(x, dict) and _fv(x, "latitude") is not None}
        if len(locs) > 1:
            spread.append(str(g.get("name", "?")))
    if spread:
        return R(R.WARN, f"{len(r)} connector group(s); connectors in {', '.join(spread[:4])} are at different locations (latitude/longitude)." + bp)
    return R(R.PASS, f"{len(r)} connector group(s).")

def zpa_6(cl):
    """ZPA access policies"""
    d, c = cl.get("/zpa/policySet/rules/ACCESS_POLICY")   # the access policy set (there is no GLOBAL_POLICY type)
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", d.get("rules", [])))
    return R(R.PASS, f"{len(r)} access policy rule(s).") if r else R(R.WARN, "No ZPA access policies. Best Practice: Define access policies based on user identity, group, device posture, and network context. Follow least-privilege: deny by default and explicitly allow only required app segments per user group. ZPA evaluates rules top-to-bottom. Ref: Access Policy Deployment and Operations Guide.")

def zpa_7(cl):
    """ZPA timeout policies"""
    d, c = cl.get("/zpa/policySet/rules/TIMEOUT_POLICY")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", d.get("rules", [])))
    return R(R.PASS, f"{len(r)} timeout policy rule(s).") if r else R(R.WARN, "No timeout policy rules — the default rule applies: users re-authenticate every 7 days and sessions never end on an idle timeout. Ref: https://help.zscaler.com/zpa/about-timeout-policy. Best Practice: Configure timeout policies per application type. Long-running sessions (RDP, SSH) may need extended timeouts. Short timeouts for web apps improve security by forcing re-authentication.")

def zpa_8(cl):
    """Service edges"""
    r, c = _items(cl, "/zpa/serviceEdge")
    if not r:
        return R(R.WARN, "No service edges. Note: Private Service Edges are optional — they provide local ZPA brokering for branch offices with poor internet. Required for universal ZTNA (server-to-server) use cases.")
    if not any(_zpn_status(x) for x in r):
        return R(R.INFO, f"{len(r)} service edge(s); their status (controlChannelStatus) is not reported, so health cannot be checked here.")
    healthy = [x for x in r if _zpn_status(x) == _ZPN_UP]
    if not healthy:
        return R(R.FAIL, f"All {len(r)} service edges offline! Private brokering is down.")
    if len(healthy) < len(r):
        return R(R.WARN, f"{len(healthy)}/{len(r)} service edge(s) online. {len(r) - len(healthy)} offline — investigate to keep local brokering redundant.")
    return R(R.PASS, f"{len(healthy)}/{len(r)} service edge(s) online.")

def zpa_9(cl):
    """Service edge groups"""
    d, c = cl.get("/zpa/serviceEdgeGroup")
    r = _ls(d) if c in (200, 204) else []
    if not r and isinstance(d, dict): r = _ls(d.get("list", []))
    return R(R.PASS, f"{len(r)} service edge group(s).") if r else R(R.WARN, "No service edge groups. Note: Service edge groups are needed only if you deploy Private Service Edges for local ZPA brokering.")

def zpa_10(cl):
    """ZPA web server certificates (Browser Access, AppProtection, Isolation, PRA)"""
    r, c = _items(cl, "/zpa/certificate")
    ref = " Ref: https://help.zscaler.com/zpa/about-browser-access-certificates"
    if not r:
        return R(R.INFO, "No web server certificates; needed only for Browser Access, AppProtection, Isolation or PRA apps." + ref)
    import time as _t
    now = _t.time()
    soon = []
    for x in r:
        try:
            end = float(_fv(x, "validToInEpochSec") or 0)
        except (TypeError, ValueError):
            end = 0
        if end and end - now < 30 * 86400:
            soon.append(f"{x.get('name', '?')} ({'expired' if end < now else 'expires within 30 days'})")
    if soon:
        return R(R.WARN, f"{len(soon)} of {len(r)} web server certificate(s) expired or expiring: {', '.join(soon[:4])}. Renew them before Browser Access apps break." + ref)
    return R(R.PASS, f"{len(r)} web server certificate(s), none expiring within 30 days.")

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
    return R(R.PASS, f"{len(r)} LSS config(s) — ZPA logs streaming.") if r else R(R.WARN, "No LSS — ZPA logs not streamed to SIEM. Best Practice: Configure Log Streaming Service (LSS) to send ZPA user activity, connector status, and audit logs to your SIEM. Without LSS, ZPA keeps user activity, user status and App Connector logs for a rolling 14 days (audit logs six months). Ref: https://help.zscaler.com/zpa/about-log-streaming-service")

# ── ZPA policy completeness (zpa_analysis templates over the same reads) ──
# Short ZPA paths as dlp_assessment_full_auto._resolve_ep maps them (v1 by
# default); the list methods behind them are zpa_reader.COLLECTIONS. Each
# check names its paths inline, so the Scope map (beacon_scope) sees them.
_ZPA_PAGE = {"page": 1, "pagesize": 500}   # one page of the documented maximum, as offline_tenant._read_zpa asks


def _zpa_lists(cl, eps):
    """({key: raw list or None}, {key: HTTP code}) for {key: short path}."""
    lists, codes = {}, {}
    for k, ep in eps.items():
        d, c = cl.get(ep) if ep == "/zpa/businessContinuitySettings" else cl.get(ep, dict(_ZPA_PAGE))
        codes[k] = c
        if c in (200, 204):
            r = _ls(d) if c == 200 else []
            if not r and isinstance(d, dict):
                r = _ls(d.get("list", []))
            lists[k] = [x for x in r if isinstance(x, dict)]
        else:
            lists[k] = None
    return lists, codes


def _zpa_verdict(label, findings, skipped, codes, eps, bp, na=None):
    """One check result from zpa_analysis findings: FAIL on a high finding,
    REVIEW on others, PASS when assessed and clean, INFO (N/A) when the
    feature answered 404 (not licensed) or `na` says it is not in use."""
    if na:
        return R(R.INFO, f"{label}: N/A — {na}")
    nf = [k for k in eps if codes.get(k) == 404]
    if skipped and nf:
        return R(R.INFO, f"{label}: N/A — the tenant answered 404 for {', '.join(sorted(eps[k] for k in nf))}, so the feature is not licensed or not enabled.")
    if skipped and not findings:
        return R(R.INFO, f"{label}: not assessed — {', '.join(sorted(eps[k] for k in eps if codes.get(k) not in (200, 204)))} could not be read.")
    if not findings:
        return R(R.PASS, f"{label}: nothing found." + bp)
    worst = R.FAIL if any(f["severity"] == "high" for f in findings) else R.WARN
    head = "; ".join(f["reason"].rstrip(".") for f in findings[:3])
    more = f" (and {len(findings) - 3} more)" if len(findings) > 3 else ""
    return R(worst, f"{len(findings)} finding(s): {head}{more}. Fix: {findings[0]['fix']}" + bp,
             {"findings": [{k: f[k] for k in ("template", "severity", "object", "reason", "fix")} for f in findings[:50]]})


def _zpa_run(cl, eps, ids):
    import zpa_analysis
    lists, codes = _zpa_lists(cl, eps)
    snap = zpa_analysis.snapshot_from_lists(lists)
    findings, skipped = zpa_analysis.run_templates(snap, ids)
    return snap, findings, skipped, codes


def zpa_16(cl):
    """ZPA inspection (AppProtection): every web segment inspected, profiles that block, custom controls attached"""
    keys = {"segments": "/zpa/application", "policy:inspection": "/zpa/policySet/rules/policyType/INSPECTION_POLICY", "inspection_profiles": "/zpa/inspectionProfile", "custom_controls": "/zpa/inspectionControls/custom"}
    snap, f, sk, codes = _zpa_run(cl, keys, ["ZPA-IN-01", "ZPA-AS-09", "ZPA-IN-02", "ZPA-IN-03"])
    return _zpa_verdict("AppProtection inspection", f, sk, codes, keys,
                        " Best Practice: inspect every private web application with Zscaler's predefined OWASP controls, monitor first, then block." + _ZPA_GUIDE)


def zpa_17(cl):
    """ZPA client forwarding: no BYPASS of sensitive segments"""
    keys = {"segments": "/zpa/application", "policy:client_forwarding": "/zpa/policySet/rules/policyType/CLIENT_FORWARDING_POLICY"}
    snap, f, sk, codes = _zpa_run(cl, keys, ["ZPA-CF-01"])
    return _zpa_verdict("Client forwarding bypass", f, sk, codes, keys,
                        " Best Practice: keep client forwarding on Intercept for every application segment that holds sensitive data; a bypassed segment skips every ZPA access rule." + _ZPA_GUIDE)


def zpa_18(cl):
    """ZPA Privileged Remote Access: capabilities (clipboard, file transfer, recording) and credentials"""
    keys = {"segments": "/zpa/application", "policy:capabilities": "/zpa/policySet/rules/policyType/CAPABILITIES_POLICY", "policy:credential": "/zpa/policySet/rules/policyType/CREDENTIAL_POLICY"}
    snap, f, sk, codes = _zpa_run(cl, keys, ["ZPA-PR-01", "ZPA-PR-02", "ZPA-PR-03"])
    pra = [s for s in snap.get("segments") or [] if (s.get("flags") or {}).get("pra")]
    in_use = pra or (snap["policies"].get("capabilities") or []) or (snap["policies"].get("credential") or [])
    na = None if in_use or snap.get("segments") is None else "no Privileged Remote Access segment or privileged policy rule, so PRA is not in use."
    return _zpa_verdict("Privileged Remote Access", f, sk, codes, keys,
                        " Best Practice: record privileged sessions, keep clipboard copy off and send file transfers through the ZIA sandbox, and give stored credentials to named admin groups only. Ref: https://help.zscaler.com/zpa/about-privileged-capabilities-policy", na)


def zpa_19(cl):
    """ZPA redirection policy: Private Service Edge groups that can serve"""
    keys = {"policy:redirection": "/zpa/policySet/rules/policyType/REDIRECTION_POLICY", "service_edge_groups": "/zpa/serviceEdgeGroup", "service_edges": "/zpa/serviceEdge"}
    snap, f, sk, codes = _zpa_run(cl, keys, ["ZPA-RD-01"])
    na = "no redirection rule, so every client uses the public ZPA cloud." if snap["policies"].get("redirection") == [] else None
    return _zpa_verdict("Redirection policy", f, sk, codes, keys,
                        " Best Practice: redirect only to Private Service Edge groups with at least two connected edges; prefer REDIRECT_PREFERRED so users fall back to the public cloud." + _ZPA_GUIDE, na)


def zpa_20(cl):
    """ZPA Browser Access from unmanaged devices: isolation and browser protection"""
    keys = {"segments": "/zpa/application", "policy:access": "/zpa/policySet/rules/ACCESS_POLICY", "policy:isolation": "/zpa/policySet/rules/policyType/ISOLATION_POLICY", "policy:clientless": "/zpa/policySet/rules/policyType/CLIENTLESS_SESSION_PROTECTION_POLICY"}
    snap, f, sk, codes = _zpa_run(cl, keys, ["ZPA-IS-01", "ZPA-BP-01"])
    ba = [s for s in snap.get("segments") or [] if (s.get("flags") or {}).get("browser_access")]
    na = None if ba or snap.get("segments") is None else "no Browser Access segment, so no unmanaged-device access to protect."
    return _zpa_verdict("Unmanaged-device access", f, sk, codes, keys,
                        " Best Practice: isolate Browser Access applications reached from unmanaged devices (block download, upload and copy) and monitor their sessions with browser protection." + _ZPA_GUIDE, na)


def zpa_21(cl):
    """ZPA business continuity and Private Cloud Controllers"""
    keys = {"business_continuity": "/zpa/businessContinuitySettings", "private_cloud_groups": "/zpa/privateCloudControllerGroup", "private_cloud_controllers": "/zpa/privateCloudController"}
    snap, f, sk, codes = _zpa_run(cl, keys, ["ZPA-PC-01", "ZPA-BC-01"])
    na = None
    if snap.get("business_continuity") == [] and snap.get("private_cloud_groups") in ([], None):
        na = "business continuity is not set up (optional: it keeps private applications reachable when the ZPA cloud is not)."
    return _zpa_verdict("Business continuity", f, sk, codes, keys,
                        " Best Practice: deploy at least two Private Cloud Controllers per Private Cloud site and keep them connected. Ref: https://help.zscaler.com/zpa/about-business-continuity", na)


def zpa_15(cl):
    """Machine groups (machine tunnels, pre-Windows-logon access)"""
    r, c = _items(cl, "/zpa/machineGroup")
    return R(R.PASS, f"{len(r)} machine group(s).") if r else R(R.INFO, "No machine groups. Machine groups are needed only for machine tunnels: pre-Windows-logon access from Client Connector devices to internal apps such as Active Directory. Zscaler recommends one machine group per machine provisioning key. Ref: https://help.zscaler.com/zpa/about-machine-groups")

# ═══════════════════════════════════════════════════════════════════════
# TENANT HEALTH (tenant_health.py): activation, certificate expiry, empty groups
# ═══════════════════════════════════════════════════════════════════════

def _health():
    import time as _t
    import tenant_health as th
    warn, crit = th.thresholds()
    return th, _t.time(), warn, crit


def _cert_result(th, certs, warn, crit, what, steps, ref):
    """One certificate list as a result: FAIL for an expired or critical
    one, WARN within the warning threshold, PASS otherwise."""
    if not certs:
        return R(R.INFO, f"No {what} in the tenant." + ref)
    item = th._cert_item("x", "", what, certs, warn, crit, steps)
    fix = (" Fix: " + " ".join(steps[:2])) if item["status"] != "ok" else ""
    status = {"critical": R.FAIL, "warning": R.WARN}.get(item["status"], R.PASS)
    return R(status, f"{len(certs)} {what}: {item['summary']}{fix}" + ref)


def hlt_1(cl):
    """ZIA changes saved but not activated (GET /status)"""
    import tenant_health as th
    d, c = cl.get("/zia/status")
    if c not in (200, 204):
        return R(R.INFO, f"The activation status could not be read (HTTP {c}).")
    a = th.activation(d)
    if a["state"] == "active":
        return R(R.PASS, "Every saved change is activated (ZIA reports ACTIVE).")
    if a["state"] in ("pending", "in_progress"):
        return R(R.WARN, ("Changes are saved in ZIA but not activated (PENDING): they are not live. " if a["state"] == "pending"
                          else "ZIA is activating changes right now (INPROGRESS). ") + th.ACTIVATION_DEPLOY_NOTE
                 + " Fix: in the ZIA Admin Portal open Activation, review the pending changes (the audit log names who made them), then Activate.")
    return R(R.INFO, "ZIA answered with an activation status this app does not know.")


def hlt_2(cl):
    """SSL inspection intermediate CA certificates expiring (certExpDate)"""
    th, now, warn, crit = _health()
    r, c = _items(cl, "/zia/intermediateCaCertificate")
    if c not in (200, 204):
        return R(R.INFO, f"The SSL inspection certificates could not be read (HTTP {c}).")
    return _cert_result(th, th.zia_certificates(r, now, warn, crit), warn, crit, "SSL inspection intermediate certificate(s)",
                        th.ZIA_CERT_STEPS, " Ref: https://help.zscaler.com/zia/about-intermediate-ca-certificates")


def hlt_3(cl):
    """ZPA enrollment certificates expiring (App Connectors and Service Edges enroll with them)"""
    th, now, warn, crit = _health()
    r, c = _items(cl, "/zpa/enrollmentCert")
    if c not in (200, 204):
        return R(R.INFO, f"The ZPA enrollment certificates could not be read (HTTP {c}).")
    certs = th.zpa_certificates(r, now, warn, crit)
    if any(x["state"] != "ok" for x in certs):
        conns, _c1 = _items(cl, "/zpa/connector")
        groups, _c2 = _items(cl, "/zpa/appConnectorGroup")
        used = th.enrolled_counts(conns, [], groups, certs)
        for x in certs:
            x.update(used.get(x["name"], {}))
    return _cert_result(th, certs, warn, crit, "ZPA enrollment certificate(s)", th.ZPA_ENROLL_STEPS,
                        " Ref: https://help.zscaler.com/zpa/about-enrollment-certificates")


def hlt_4(cl):
    """App Connector groups with no connector"""
    import tenant_health as th
    r, c = _items(cl, "/zpa/appConnectorGroup")
    if not r:
        return R(R.INFO, "No App Connector groups to check.")
    empty = th.empty_groups(r)
    if empty:
        return R(R.WARN, f"{len(empty)} of {len(r)} App Connector group(s) have no connector: {', '.join(empty[:5])}"
                         f"{' and more' if len(empty) > 5 else ''}. An application served only by them cannot be reached. "
                         "Fix: enroll at least two connectors into each (N+1), move its server groups to a group with connectors, "
                         "or delete it if nothing uses it." + _ZPA_GUIDE)
    return R(R.PASS, f"Every one of the {len(r)} App Connector group(s) has at least one connector.")


# ═══════════════════════════════════════════════════════════════════════
# ZCC — DEVICE MANAGEMENT (extended)
# ═══════════════════════════════════════════════════════════════════════

def zcc_1(cl):
    """ZCC trusted networks"""
    d, c = cl.get("/zcc/trustedNetworks")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} trusted network(s) for ZCC.") if r else R(R.WARN, "No ZCC trusted networks. Best Practice: Define trusted networks (DNS Server, DNS Search Domains, Network Range, Default Gateway, DHCP Server, Egress IP) so ZCC can apply different forwarding behavior on-network vs. off-network. Ref: https://help.zscaler.com/zscaler-client-connector/configuring-trusted-networks-zscaler-client-connector")

def zcc_2(cl):
    """ZCC web policy"""
    d, c = cl.get("/zcc/webPolicies")
    if c == 404: d, c = cl.get("/zcc/webPolicy")
    r = _ls(d) if c in (200, 204) else []
    return R(R.PASS, f"{len(r)} ZCC web policy/policies.") if r else R(R.WARN, "No ZCC web policies. Best Practice: Configure web policies to control ZCC behavior — enforce proxy settings, configure captive portal detection, and manage the user experience during ZCC enrollment and updates.")

def zcc_3(cl):
    """ZCC fail-open policy"""
    d, c = cl.get("/zcc/failOpenPolicy")
    ref = " Ref: https://help.zscaler.com/zscaler-client-connector/configuring-fail-open-settings-zscaler-client-connector"
    if c not in (200, 204):
        return R(R.WARN, "Cannot access fail-open policy. Review the failover settings in the Client Connector portal." + ref)
    # webFailOpenPolicy/listByCompany returns a list of FailOpenPolicy objects (zscaler-sdk-python zcc/fail_open_policy.py).
    pols = [x for x in _ls(d) if isinstance(x, dict)]
    if not pols:
        return R(R.INFO, "The fail-open policy reports no settings." + ref)
    p = pols[0]
    def mode(k):
        v = _fv(p, k)
        return "not reported" if v is None else ("Direct Internet Access" if not _truthy(v) else "Disable Internet Access")
    parts = [f"ZIA Cloud Not Reachable: {mode('enableWebSecOnProxyUnreachable')}", f"Z-Tunnel failover: {mode('enableWebSecOnTunnelFailure')}"]
    if _fv(p, "enableFailOpen") is not None:
        parts.append(f"fail open {'on' if _truthy(_fv(p, 'enableFailOpen')) else 'off'}")
    if _fv(p, "enableCaptivePortalDetection") is not None:
        parts.append(f"captive-portal detection {'on' if _truthy(_fv(p, 'enableCaptivePortalDetection')) else 'off'}")
    if _fv(p, "captivePortalWebSecDisableMinutes") is not None:
        parts.append(f"captive-portal window {_fv(p, 'captivePortalWebSecDisableMinutes')} minute(s)")
    if _fv(p, "enableStrictEnforcementPrompt") is not None:
        parts.append(f"strict-enforcement prompt {'on' if _truthy(_fv(p, 'enableStrictEnforcementPrompt')) else 'off'}")
    return R(R.INFO, "Failover settings: " + "; ".join(parts) + ". 'Disable Internet Access' blocks HTTP/HTTPS only; give users enough captive-portal minutes to complete the portal. On Client Connector 4.6+ for Windows and 4.8+ for macOS the app profile's failover settings (zccAppFailOpenPolicy / zccTunnelFailPolicy) take precedence (see 1.19)." + ref)

def zcc_4(cl):
    """ZCC device count and platforms"""
    d, c = cl.get("/zcc/devices")
    devs = _ls(d) if c in (200, 204) else []
    if not devs:
        return R(R.WARN, "No devices reporting to ZCC. Best Practice: All managed endpoints should have ZCC installed with Z-Tunnel 2.0 enabled, strict enforcement on, and tamper protection (disable/uninstall passwords) configured. Ref: Zscaler Client Connector Deployment and Operations Guide.")
    plat = {}
    for dv in devs[:500]:
        o = str(dv.get("osType") or dv.get("platform") or "?").lower()   # the API reports osType as a number
        plat[o] = plat.get(o, 0) + 1
    return R(R.PASS, f"{len(devs)} device(s): {', '.join(f'{v}x{k}' for k,v in sorted(plat.items(), key=lambda x: -x[1]))}")

def zcc_5(cl):
    """Company info"""
    d, c = cl.get("/zcc/companyInfo")
    if c in (200, 204) and isinstance(d, dict):
        # getCompanyInfo names the company businessName (zscaler/zcc/models/company_info.py, SDK 1.11.3).
        name = d.get("businessName") or d.get("companyName") or d.get("name") or "?"
        return R(R.PASS, f"Company: {name}")
    return R(R.WARN, "Cannot retrieve company info. Note: This may indicate the ZCC API scope is not enabled for this API client. Verify API role includes ZCC read permissions.")


def zcc_6(cl):
    """ZCC forwarding profiles (PAC / tunnel mode) per network"""
    d, c = cl.get("/zcc/forwardingProfiles")
    profiles = [p for p in (_ls(d) if c in (200, 204) else []) if isinstance(p, dict)]
    if not profiles:
        return R(R.WARN, "No ZCC forwarding profiles. Best Practice: Define at least one forwarding profile mapping each OS/group to a tunnel method (Z-Tunnel 2.0, Packet Filter Based, or PAC). Z-Tunnel 2.0 is recommended for full traffic coverage. Ref: ZCC Deployment Guide - Forwarding Profiles.")
    try:
        from data_flow import forwarding_actions
    except Exception:  # noqa: BLE001
        forwarding_actions = lambda p: {}
    # The mode is forwardingProfileActions[].actionType per network (SDK zcc/models/forwardingprofile.py).
    counts, none_nets, z2 = {}, [], 0
    for p in profiles:
        acts = forwarding_actions(p)
        if any(a.get("mode_label") == "Z-Tunnel 2.0" for a in acts.values()):
            z2 += 1
        for net, a in acts.items():
            counts[a.get("mode_label", "?")] = counts.get(a.get("mode_label", "?"), 0) + 1
            if a.get("mode_kind") == "none":
                none_nets.append(f"{p.get('name', '?')} ({net})")
    distrib = ", ".join(f"{v} network(s) {k}" for k, v in counts.items()) or "no network actions reported"
    ref = " Ref: https://help.zscaler.com/zscaler-client-connector/best-practices-deploying-z-tunnel-2.0"
    if none_nets:
        off = [n for n in none_nets if n.endswith("(off)") or n.endswith("(any)")]
        return R(R.WARN, f"{len(profiles)} forwarding profile(s): {distrib}. Forwarding is None on {', '.join(none_nets[:5])}" + (" — off-trusted devices go direct" if off else "") + ". Best Practice: forward every network through Z-Tunnel 2.0." + ref)
    if not z2:
        return R(R.WARN, f"{len(profiles)} forwarding profile(s): {distrib}; none uses Z-Tunnel 2.0." + ref)
    return R(R.PASS, f"{len(profiles)} forwarding profile(s), {z2} with Z-Tunnel 2.0: {distrib}.")

def zcc_7(cl):
    """ZCC machine tunnel policy (ZPA device-level access)"""
    d, c = cl.get("/zcc/machineTunnel")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Machine Tunnel API not accessible. Not Configured / N/A — may require ZPA subscription + machine-tunnel feature.")
    if not items:
        return R(R.INFO, "No machine tunnel policies defined. Note: Machine tunnels let services on a device reach ZPA apps before user login. Optional feature — configure if you have pre-logon / server workloads that need ZPA access.")
    return R(R.PASS, f"{len(items)} machine tunnel policy/policies. Best Practice: Ensure machine tunnel is scoped to device groups that actually need pre-logon ZPA access.")


def zcc_8(cl):
    """ZCC app profiles — posture + install requirements"""
    d, c = cl.get("/zcc/webPolicies")
    policies = _ls(d) if c in (200, 204) else []
    if not policies:
        return R(R.WARN, "No ZCC app profiles (policies). Best Practice: Each user population needs an app profile defining tunnel behavior, logging, PAC URL, enforcement options, and posture requirements. At minimum, define default + per-OS profiles.")
    total = len(policies)
    with_posture = 0
    strict_enforce = 0
    tamper_protect = 0
    for p in policies:
        posture = p.get("devicePosture") or p.get("postureProfileId") or p.get("postureProfile")
        if posture: with_posture += 1
        if p.get("strictEnforcement") or p.get("strict_enforcement"): strict_enforce += 1
        if (p.get("uninstallPassword") or p.get("disablePassword")
            or p.get("logoutPassword") or p.get("tamperProtection")): tamper_protect += 1
    parts = []
    parts.append(f"{with_posture}/{total} with posture")
    parts.append(f"{strict_enforce}/{total} strict-enforcement")
    parts.append(f"{tamper_protect}/{total} tamper-protected")
    if with_posture == 0:
        return R(R.WARN, f"{total} app profile(s): {', '.join(parts)}. Best Practice: Apply device posture profiles (OS version, disk encryption, AV running, domain joined) to block non-compliant devices from enrolling.")
    if strict_enforce < total:
        return R(R.WARN, f"{total} app profile(s): {', '.join(parts)}. Best Practice: Enable strict enforcement on all profiles — prevents users from disabling ZCC or editing forwarding settings.")
    return R(R.PASS, f"{total} app profile(s): {', '.join(parts)}.")


def zcc_9(cl):
    """ZCC posture profiles defined"""
    d, c = cl.get("/zcc/postureProfiles")
    items = _ls(d) if c in (200, 204) else []
    if not items:
        return R(R.WARN, "No posture profiles defined. Best Practice: Define posture profiles to enforce device compliance (OS version, antivirus running, disk encryption, firewall on, domain-joined). Posture profiles gate ZCC enrollment and ZPA access — critical for zero-trust.")
    return R(R.PASS, f"{len(items)} posture profile(s) configured.")


def zcc_10(cl):
    """ZCC ZPN module modes (ZIA/ZPA/ZDX/Deception enabled per tenant)"""
    d, c = cl.get("/zcc/zpnModuleMode")
    items = _ls(d) if c in (200, 204) else []
    if not items:
        return R(R.INFO, "ZPN module mode config not available. If you use a multi-service ZCC (ZIA+ZPA+ZDX), verify each module is enabled per profile in the admin portal.")
    modes = set()
    for it in items:
        for k in it.keys():
            kl = k.lower()
            if "zia" in kl or "zpa" in kl or "zdx" in kl or "deception" in kl:
                if it.get(k): modes.add(k)
    return R(R.PASS, f"{len(items)} ZPN module-mode config(s). Modules enabled: {', '.join(sorted(modes)) if modes else '(unspecified)'}.")


def zcc_11(cl):
    """ZCC device enrollment state & version distribution"""
    d, c = cl.get("/zcc/devices")
    devs = _ls(d) if c in (200, 204) else []
    if not devs:
        return R(R.INFO, "No devices to analyze enrollment state.")
    total = len(devs)
    # Enrollment state
    registered = 0
    removed = 0
    tamperd = 0
    versions: dict = {}
    stale = 0
    import time as _t
    now = _t.time()
    for dv in devs[:2000]:
        state = str(dv.get("registrationState") or dv.get("state") or "").upper()
        if "REMOV" in state or "UNREGISTER" in state: removed += 1
        elif "REGISTER" in state or "ACTIVE" in state: registered += 1
        if dv.get("tamperDetected") or dv.get("tampered"): tamperd += 1
        v = dv.get("zappVersion") or dv.get("agentVersion") or dv.get("version") or "?"
        versions[v] = versions.get(v, 0) + 1
        # Stale: lastSeen > 30 days ago
        ls = dv.get("lastSeen") or dv.get("lastSeenTime") or 0
        if isinstance(ls, (int, float)) and ls > 0:
            if ls > 1e12: ls = ls / 1000.0  # ms → s
            if now - ls > 30 * 86400: stale += 1
    top3 = sorted(versions.items(), key=lambda x: -x[1])[:3]
    ver_str = ", ".join(f"{v}:{n}" for v, n in top3) if top3 else "?"
    notes = []
    if removed: notes.append(f"{removed} REMOVED/unregistered")
    if tamperd: notes.append(f"{tamperd} tamper-detected")
    if stale:   notes.append(f"{stale} not seen in 30+ days")
    status = R.WARN if (removed or tamperd or stale > total * 0.2) else R.PASS
    detail = f"{total} device(s): {registered} registered"
    if notes: detail += f", {', '.join(notes)}"
    detail += f". Top versions: {ver_str}."
    if tamperd:
        detail += " Best Practice: Investigate tamper-detected devices immediately — they may have had ZCC forcibly removed."
    elif removed > total * 0.1:
        detail += " Best Practice: Clean up stale/unregistered devices; high count inflates the inventory and can mask real issues."
    elif stale > total * 0.2:
        detail += " Best Practice: Over 20% of devices haven't checked in in 30+ days — retire or re-enroll them."
    return R(status, detail)


def zcc_12(cl):
    """ZCC PAC files"""
    d, c = cl.get("/zcc/pacFiles")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "PAC files API not accessible on this role.")
    if not items:
        return R(R.INFO, "No PAC files defined. Note: PAC files are used by forwarding profiles set to 'PAC' mode. If all your profiles use Z-Tunnel 2.0, no PAC is needed.")
    return R(R.PASS, f"{len(items)} PAC file(s) configured.")


def zcc_13(cl):
    """ZCC privacy info — what ZCC reports back"""
    d, c = cl.get("/zcc/privacyInfo")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Privacy info API not accessible.")
    if not items:
        return R(R.WARN, "Privacy info not configured. Best Practice: Review privacy settings so end users can see what telemetry ZCC reports — important for GDPR / works-council compliance.")
    return R(R.PASS, f"Privacy info configured across {len(items)} profile(s).")


def zcc_14(cl):
    """ZCC app bypass configuration"""
    d, c = cl.get("/zcc/appBypass")
    items = _ls(d) if c in (200, 204) else []
    if not items:
        return R(R.INFO, "No app-bypass config. Note: If ZCC tunnels break a specific app (e.g., VPN client, virtualization tool), add it to the app-bypass list. Should stay as small as possible — prefer domain/URL bypass over app-level bypass.")
    total_apps = 0
    for it in items:
        for field in ("bypassAppList", "apps", "bypassApps", "applicationBypass"):
            if isinstance(it.get(field), list):
                total_apps += len(it[field])
    return R(R.PASS, f"{len(items)} app-bypass config(s) covering ~{total_apps} app(s). Review quarterly to remove unneeded entries.")


def zcc_15(cl):
    """ZCC browser protection profiles"""
    d, c = cl.get("/zcc/browserProtection")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Browser Protection API not accessible — may not be licensed on this tenant.")
    if not items:
        return R(R.INFO, "No browser protection profiles. Optional feature — enables ZCC to protect against browser-level threats (phishing, unsafe downloads) in addition to tunnel-level inspection.")
    return R(R.PASS, f"{len(items)} browser protection profile(s) configured.")


def zcc_16(cl):
    """ZCC device cleanup policy (auto-unenroll stale endpoints)"""
    d, c = cl.get("/zcc/deviceCleanup")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Device cleanup API not accessible.")
    if not items:
        return R(R.WARN, "No device cleanup policy. Best Practice: Configure auto-cleanup to unenroll devices not seen in N days (typically 90). Without this, retired laptops and reimaged hosts accumulate forever and inflate the license count.")
    return R(R.PASS, f"{len(items)} device cleanup policy/policies — stale endpoints will auto-retire.")


def zcc_17(cl):
    """ZCC device groups for policy targeting"""
    d, c = cl.get("/zcc/deviceGroups")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Device groups API not accessible.")
    if not items:
        return R(R.INFO, "No device groups. Best Practice: Create device groups (by OS, department, risk tier) for granular policy targeting. Device groups let you apply stricter posture / tighter tunnels to specific device populations.")
    return R(R.PASS, f"{len(items)} device group(s) — usable for policy targeting.")


def zcc_18(cl):
    """ZCC trusted networks — structure check (not just count)"""
    d, c = cl.get("/zcc/trustedNetworks")
    items = [x for x in (_ls(d) if c in (200, 204) else []) if isinstance(x, dict)]
    ref = " Ref: https://help.zscaler.com/zscaler-client-connector/configuring-trusted-networks-zscaler-client-connector"
    if not items:
        return R(R.WARN, "No trusted networks defined. Best Practice: Define trusted networks by DNS Server, DNS Search Domains, Network Range, Default Gateway, DHCP Server or Egress IP so ZCC behaves differently on-network vs off-network (e.g., skip tunnel on-net, full tunnel off-net)." + ref)
    crit = {"DNS server": ("dnsServers", "dns"), "DNS search domain": ("dnsSearchDomains",), "hostname and IP": ("hostnames", "hostname", "resolvedIpsForHostname"),
            "network range": ("trustedSubnets",), "default gateway": ("trustedGateways",), "DHCP server": ("trustedDhcpServers",), "egress IP": ("trustedEgressIps",), "SSID": ("ssids", "wifiSsids")}
    per = [(x, [k for k, names in crit.items() if _fv(x, *names)]) for x in items]
    counts = {k: sum(1 for _, ks in per if k in ks) for k in crit}
    none = [str(x.get("networkName") or x.get("name") or x.get("id")) for x, ks in per if not ks]
    dyn = [str(x.get("networkName") or x.get("name") or x.get("id")) for x, ks in per if ks == ["hostname and IP"]]
    conds = sorted({str(_fv(x, "conditionType")) for x in items if _fv(x, "conditionType") is not None})
    detail = f"{len(items)} trusted network(s): " + ", ".join(f"{v} with {k}" for k, v in counts.items() if v) + (f" (condition type {', '.join(conds)})" if conds else "") + ". "
    if none:
        return R(R.WARN, detail + f"No criterion on {', '.join(none[:4])}. Best Practice: Trusted-network detection needs at least one criterion; Zscaler recommends static properties such as DNS Server and DNS Search Domains (hostname and IP resolution is dynamic)." + ref)
    if dyn:
        return R(R.WARN, detail + f"{', '.join(dyn[:4])} rely only on Hostname and IP, which is dynamic; add a static criterion such as DNS Server or DNS Search Domains." + ref)
    return R(R.PASS, detail)

def zcc_19(cl):
    """ZCC last posture fields (what posture info is being collected)"""
    d, c = cl.get("/zcc/lastPostureFields")
    if c == 200 and isinstance(d, (dict, list)):
        fields = d if isinstance(d, list) else (d.get("fields") or d.get("postureFields") or list(d.keys()))
        if fields:
            return R(R.PASS, f"Posture collection fields active: {len(fields) if isinstance(fields, list) else 'configured'}.")
    return R(R.INFO, "Last posture fields API not exposing data. If you rely on ZCC posture collection, verify the posture profiles are configured.")


def zcc_21(cl):
    """ZCC admin users enrolled in the Mobile Portal"""
    d, c = cl.get("/zcc/adminUsers")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Admin Users API not accessible. Grant 'View Admin' on the API role.")
    if not items:
        return R(R.WARN, "No ZCC admin users. Best Practice: At least two admins should be enrolled for redundancy — one-admin tenants break when that admin leaves.")
    return R(R.PASS, f"{len(items)} ZCC admin user(s). Note: periodically prune ex-employees from this list — orphaned admins are an audit finding.")


def zcc_22(cl):
    """ZCC admin roles (least-privilege verification)"""
    d, c = cl.get("/zcc/adminRoles")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Admin Roles API not accessible.")
    if not items:
        return R(R.WARN, "No ZCC admin roles defined. Best Practice: Define at least 'ZCC Read-Only' and 'ZCC Admin' roles so operators can see devices without being able to remove them.")
    return R(R.PASS, f"{len(items)} ZCC admin role(s). Ensure read-only roles exist for SOC / helpdesk users.")


def zcc_23(cl):
    """ZCC admin users sync info — SSO / IdP sync health"""
    d, c = cl.get("/zcc/adminUsersSyncInfo")
    if c in (401, 403):
        return R(R.INFO, "Admin sync info not accessible.")
    if c != 200:
        return R(R.INFO, f"Admin sync info endpoint returned HTTP {c}.")
    if isinstance(d, dict):
        last = d.get("lastSync") or d.get("lastSyncTime") or d.get("syncedAt")
        return R(R.PASS, f"Admin sync info reachable (last sync: {last or 'unspecified'}). Best Practice: ZCC admins should be federated to your IdP (Azure AD / Okta) and sync daily.")
    return R(R.PASS, "Admin sync info reachable.")


def zcc_24(cl):
    """ZDX group entitlements (ZDX feature licensing on ZCC)"""
    d, c = cl.get("/zcc/zdxEntitlements")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX entitlements not accessible — may not have ZDX subscription.")
    if not items:
        return R(R.INFO, "No ZDX group entitlements defined. If ZDX is licensed, create group entitlements to control which users can see ZDX data.")
    return R(R.PASS, f"{len(items)} ZDX group entitlement(s) configured.")


def zcc_25(cl):
    """ZPA group entitlements (ZPA feature licensing on ZCC)"""
    d, c = cl.get("/zcc/zpaEntitlements")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZPA entitlements not accessible — may not have ZPA subscription.")
    if not items:
        return R(R.INFO, "No ZPA group entitlements defined. If ZPA is licensed, create group entitlements for least-privilege app access.")
    return R(R.PASS, f"{len(items)} ZPA group entitlement(s) configured.")


def zcc_26(cl):
    """ZCC web app service exclusions"""
    d, c = cl.get("/zcc/webAppService")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Web App Service API not accessible.")
    if not items:
        return R(R.INFO, "No web app service exclusions. Note: Used to carve out specific web apps from ZCC processing. Keep this list empty unless there's a specific compatibility issue.")
    return R(R.WARN, f"{len(items)} web app service exclusion(s). Best Practice: Each exclusion is a blind spot — review quarterly and remove any that are no longer needed.")


def zcc_20(cl):
    """ZCC company info — enrollment auth method"""
    d, c = cl.get("/zcc/companyInfo")
    if c != 200 or not isinstance(d, dict):
        return R(R.INFO, "Company info not accessible for enrollment-auth check.")
    auth = (d.get("authMethod") or d.get("enrollmentAuthMethod") or "").upper()
    if not auth:
        return R(R.INFO, "Enrollment auth method not exposed. Manual check: ZIA Admin → ZCC → Mobile Portal → Enrollment.")
    if "SAML" in auth or "ADFS" in auth or "AZURE" in auth or "OKTA" in auth:
        return R(R.PASS, f"ZCC enrollment uses federated SSO: {auth}. Aligns with best practice.")
    if "HOSTED" in auth or "BASIC" in auth or "LOCAL" in auth:
        return R(R.WARN, f"ZCC enrollment auth: {auth}. Best Practice: Use SAML / IdP-federated enrollment so ZCC install is gated by corporate SSO + MFA, not Zscaler-hosted local accounts.")
    return R(R.INFO, f"ZCC enrollment auth: {auth}.")


# ═══════════════════════════════════════════════════════════════════════
# ZIA — FORWARDING AND TRAFFIC PATH
# ═══════════════════════════════════════════════════════════════════════
# The analysis is zia_forwarding's (shared with the Path analyzer's
# Forwarding control step); every path below is in zscaler-sdk-python
# 1.11.3 (see zia_forwarding). Not applicable (INFO, unscored) when the
# feature is not licensed (HTTP 404) or not used (an empty list).

import zia_forwarding as _zf  # noqa: E402

_FWD_REF = " Ref: https://help.zscaler.com/zia/about-forwarding-control"
_NA = "Not applicable: "


def _fwd_rows(cl, path, label):
    """(rows, None) or (None, R) when the list cannot be judged: not
    licensed (404, N/A) or not readable."""
    d, c = cl.get(path)
    if c in (200, 204):
        rows = _ls(d) if c == 200 else []
        if not rows and isinstance(d, dict) and not d.get("error"):
            rows = _ls(d.get("list", []))
        return [x for x in rows if isinstance(x, dict)], None
    if c == 404:
        return None, R(R.INFO, f"{_NA}{label} is not licensed or not enabled on this tenant (the API answered 404).")
    from dlp_assessment_full_auto import _explain
    return None, _explain(label, c, path)


def fwd_1(cl):
    """Forwarding rules that send traffic around ZIA (DIRECT)"""
    rules, bad = _fwd_rows(cl, "/zia/forwardingRules", "Forwarding control rules")
    if bad:
        return bad
    if not rules:
        return R(R.INFO, _NA + "no forwarding control rules were returned, so every location and connector uses ZIA's default forwarding.")
    zia_rules = [r for r in rules if _zf.is_zia_rule(r)]
    b = _zf.direct_bypasses(rules)
    why = (" Why it matters: traffic a connector sends DIRECT never reaches ZIA, so no URL filtering, SSL inspection, threat protection "
           "or DLP applies to it.")
    if b["broad"]:
        return R(R.FAIL, f"{len(b['broad'])} enabled Cloud or Branch Connector forwarding rule(s) send traffic DIRECT with no destination named: "
                 f"{_zf.short(b['broad'])}." + why + " Best Practice: forward to ZIA by default and keep DIRECT for named destinations "
                 "that cannot be proxied (for example update services), each with a documented reason." + _FWD_REF)
    if b["narrow"]:
        return R(R.WARN, f"{len(b['narrow'])} enabled connector forwarding rule(s) send named destinations DIRECT, around ZIA: {_zf.short(b['narrow'])}."
                 + why + " Best Practice: review each DIRECT destination once a quarter and remove those that ZIA can inspect." + _FWD_REF)
    return R(R.PASS, f"{len(rules)} forwarding rule(s) ({len(zia_rules)} ZIA); none sends connector traffic DIRECT around ZIA.")


def fwd_2(cl):
    """Proxy chaining has a gateway and a fallback proxy"""
    rules, bad = _fwd_rows(cl, "/zia/forwardingRules", "Forwarding control rules")
    if bad:
        return bad
    chain = [r for r in rules if _zf.enabled(r) and _zf.method(r) == _zf.PROXYCHAIN]
    if not chain:
        return R(R.INFO, _NA + "no enabled forwarding rule chains traffic to another proxy.")
    gws, gbad = _fwd_rows(cl, "/zia/proxyGateways", "Proxy gateways")
    p = _zf.proxy_chain_findings(chain, gws)
    why = (" Why it matters: proxy chaining hands traffic to a third-party proxy; with one proxy and no fallback, an outage of that proxy "
           "either stops the traffic or lets it out without the chained control.")
    fix = " Best Practice: give every proxy gateway a secondary proxy, and decide on purpose whether it fails closed." + _FWD_REF
    if p["no_gateway"]:
        return R(R.FAIL, f"{len(p['no_gateway'])} proxy-chaining rule(s) name no proxy gateway, or one that does not exist: {_zf.short(p['no_gateway'])}."
                 + why + fix)
    if p["unknown"]:
        return R(R.INFO, f"{len(chain)} proxy-chaining rule(s), but the proxy gateways could not be read, so their fallback is not known. "
                 + (gbad.detail if gbad else ""))
    if p["fail_open"]:
        return R(R.FAIL, f"{len(p['fail_open'])} proxy-chaining rule(s) use a gateway with no secondary proxy that does not fail closed: "
                 f"{_zf.short(p['fail_open'])}." + why + fix)
    if p["no_fallback"]:
        return R(R.WARN, f"{len(p['no_fallback'])} proxy-chaining rule(s) use a gateway with no secondary proxy (it fails closed, so users lose "
                 f"access while the proxy is down): {_zf.short(p['no_fallback'])}." + why + fix)
    return R(R.PASS, f"All {len(chain)} proxy-chaining rule(s) use a gateway with a secondary proxy.")


def fwd_3(cl):
    """ZPA gateways serve the forwarding rules that use them"""
    gws, bad = _fwd_rows(cl, "/zia/zpaGateways", "ZPA gateways")
    if bad:
        return bad
    rules, rbad = _fwd_rows(cl, "/zia/forwardingRules", "Forwarding control rules")
    rules = rules or []
    zrules = [r for r in rules if _zf.enabled(r) and _zf.method(r) == _zf.ZPA]
    if not gws and not zrules:
        return R(R.INFO, _NA + "no ZPA gateway is configured in ZIA and no forwarding rule sends traffic to ZPA (source IP anchoring is not used).")
    z = _zf.zpa_gateway_findings(rules, gws)
    why = (" Why it matters: a ZPA gateway sends ZIA traffic through ZPA (source IP anchoring) so a SaaS application sees the customer's own "
           "egress address; a gateway with no server group or segment, or a rule with no gateway, breaks access to that application.")
    fix = " Best Practice: give each ZPA gateway a server group and the application segments it anchors, and remove gateways no rule uses." + _FWD_REF
    broken = z["no_server_group"] + z["no_segments"] + z["rule_no_gateway"]
    if broken:
        parts = ([f"no server group: {_zf.short(z['no_server_group'])}"] if z["no_server_group"] else []) + \
                ([f"no application segment: {_zf.short(z['no_segments'])}"] if z["no_segments"] else []) + \
                ([f"ZPA rule(s) with no gateway: {_zf.short(z['rule_no_gateway'])}"] if z["rule_no_gateway"] else [])
        return R(R.FAIL, "ZPA forwarding is incomplete; " + "; ".join(parts) + "." + why + fix)
    if z["unused"] and not rbad:
        return R(R.WARN, f"{len(z['unused'])} ZPA gateway(s) are not used by any enabled forwarding rule: {_zf.short(z['unused'])}." + why + fix)
    return R(R.PASS, f"{len(gws)} ZPA gateway(s), each with a server group and application segments, used by {len(zrules)} forwarding rule(s).")


def fwd_4(cl):
    """Data centre exclusions in force"""
    rows, bad = _fwd_rows(cl, "/zia/dcExclusions", "Data centre exclusions")
    if bad:
        return bad
    act = _zf.active_exclusions(rows)
    if not act:
        return R(R.PASS, f"No data centre exclusion is in force ({len(rows)} recorded, none active); tunnels may use every Zscaler data centre.")
    long_ = [x["name"] + (" (no end date)" if x["days"] is None else f" ({x['days']} days)") for x in act if x["long"]]
    why = (" Why it matters: an excluded data centre takes down the IPsec tunnels that end there and moves them to their secondary; left in "
           "place, the sites lose their redundancy and may be sent to a farther data centre.")
    fix = " Best Practice: exclude a data centre only for a planned event, with an end date, and remove it afterwards." + \
          " Ref: https://help.zscaler.com/zia/about-data-center-exclusion"
    if long_:
        return R(R.WARN, f"{len(act)} data centre exclusion(s) in force; open-ended or longer than {_zf.LONG_EXCLUSION_DAYS} days: {_zf.short(long_)}." + why + fix)
    return R(R.WARN, f"{len(act)} data centre exclusion(s) in force, each with an end date: {_zf.short([x['name'] for x in act])}." + why + fix)


def fwd_5(cl):
    """GRE tunnels use diverse data centres (primary and secondary VIP)"""
    tunnels, bad = _fwd_rows(cl, "/zia/greTunnels", "GRE tunnels")
    if bad:
        return bad
    if not tunnels:
        return R(R.INFO, _NA + "no GRE tunnels are configured (sites use IPsec, a connector or Client Connector).")
    vips, _vbad = _fwd_rows(cl, "/zia/vips", "Zscaler public VIPs")
    g = _zf.gre_diversity(tunnels, vips)
    why = (" Why it matters: a GRE tunnel's secondary VIP is its failover; in the same data centre as the primary (or missing), one data "
           "centre outage takes the site off the internet or out of inspection.")
    fix = (" Best Practice: give every GRE tunnel a primary and a secondary VIP in two different data centres (the recommended VIP list "
           "for the tunnel's source IP offers them)." + " Ref: https://help.zscaler.com/zia/about-gre-tunnels")
    bad_ = g["no_secondary"] + g["same_dc"]
    if bad_:
        parts = ([f"no secondary VIP: {_zf.short(g['no_secondary'])}"] if g["no_secondary"] else []) + \
                ([f"both VIPs in one data centre: {_zf.short(g['same_dc'])}"] if g["same_dc"] else [])
        return R(R.FAIL, f"{len(bad_)} of {len(tunnels)} GRE tunnel(s) have no data centre diversity; " + "; ".join(parts) + "." + why + fix)
    if g["unknown_dc"]:
        return R(R.WARN, f"{len(g['unknown_dc'])} GRE tunnel(s) have two VIPs whose data centres could not be placed: {_zf.short(g['unknown_dc'])}."
                 + why + fix)
    return R(R.PASS, f"All {len(tunnels)} GRE tunnel(s) have a secondary VIP in a different data centre.")


def fwd_6(cl):
    """IPv6 traffic is handled by ZIA"""
    d, c = cl.get("/zia/ipv6config")
    if c == 404:
        return R(R.INFO, _NA + "IPv6 configuration is not available on this tenant (the API answered 404).")
    if c not in (200, 204):
        from dlp_assessment_full_auto import _explain
        return _explain("IPv6 configuration", c, "/zia/ipv6config")
    on = _zf.ipv6_state(d)
    locs, _lb = _fwd_rows(cl, "/zia/locations", "Locations")
    v6_locs = [_zf.name_of(x) for x in locs or [] if _fv(x, "ipv6Enabled")]
    why = (" Why it matters: IPv6 traffic that ZIA does not process leaves the site uninspected when the network and the destination "
           "both speak IPv6, which most large SaaS services do.")
    fix = (" Best Practice: turn on IPv6 in ZIA and on the locations that carry it, with a NAT64 prefix for IPv6-only clients, or block "
           "IPv6 at the site edge." + " Ref: https://help.zscaler.com/zia/about-ipv6-configuration")
    if on is None:
        return R(R.INFO, "The IPv6 configuration was read but says nothing about whether IPv6 is on.")
    if not on:
        if v6_locs:
            return R(R.FAIL, f"IPv6 is off in ZIA, but {len(v6_locs)} location(s) are set to carry IPv6: {_zf.short(v6_locs)}." + why + fix)
        if locs:
            return R(R.WARN, f"IPv6 is off in ZIA and {len(locs)} location(s) forward traffic; their IPv6 traffic is not processed unless the site "
                     "blocks IPv6 at its edge." + why + fix)
        return R(R.INFO, _NA + "IPv6 is off in ZIA and no location forwards traffic (Client Connector only).")
    nat, _nb = _fwd_rows(cl, "/zia/ipv6config/nat64prefix", "NAT64 prefixes")
    if nat is not None and not nat:
        return R(R.WARN, "IPv6 is on in ZIA, but no NAT64 prefix is configured, so IPv6-only clients cannot reach IPv4-only destinations." + fix)
    return R(R.PASS, "IPv6 is on in ZIA" + (f", with {len(nat)} NAT64 prefix(es)" if nat else "") + (f"; {len(v6_locs)} location(s) carry IPv6." if v6_locs else "."))


def fwd_7(cl):
    """Dedicated IP gateways have a secondary data centre"""
    gws, bad = _fwd_rows(cl, "/zia/dedicatedIPGateways/lite", "Dedicated IP gateways")
    if bad:
        return bad
    if not gws:
        return R(R.INFO, _NA + "no dedicated IP gateway is configured (the Dedicated IP subscription is not used).")
    d = _zf.dedicated_ip_findings(gws)
    why = (" Why it matters: a dedicated IP gateway gives traffic a fixed egress address that SaaS allow-lists trust; with one data centre, "
           "an outage there leaves that traffic on a shared address the application refuses.")
    fix = " Best Practice: give every dedicated IP gateway a secondary data centre different from the primary." + _FWD_REF
    if d["no_secondary"] or d["same_dc"]:
        parts = ([f"no secondary: {_zf.short(d['no_secondary'])}"] if d["no_secondary"] else []) + \
                ([f"secondary in the same data centre: {_zf.short(d['same_dc'])}"] if d["same_dc"] else [])
        return R(R.WARN, "Dedicated IP gateway(s) without data centre failover; " + "; ".join(parts) + "." + why + fix)
    return R(R.PASS, f"All {len(gws)} dedicated IP gateway(s) have a secondary data centre.")


def fwd_8(cl):
    """NAT control (destination NAT) rules are scoped"""
    rules, bad = _fwd_rows(cl, "/zia/dnatRules", "NAT control rules")
    if bad:
        return bad
    if not [r for r in rules if not (_fv(r, "defaultRule") or _fv(r, "predefined"))]:
        return R(R.INFO, _NA + "no NAT control (destination NAT) rule is configured.")
    n = _zf.dnat_findings(rules)
    why = (" Why it matters: a NAT control rule rewrites where traffic goes; with no destination named it redirects everything in its "
           "scope, which silently breaks or reroutes traffic.")
    fix = " Best Practice: name the destination addresses, groups or services each NAT control rule applies to, and its redirect target." + \
          " Ref: https://help.zscaler.com/zia/about-nat-control"
    if n["no_target"]:
        return R(R.FAIL, f"{len(n['no_target'])} enabled NAT control rule(s) redirect to no address or name: {_zf.short(n['no_target'])}." + why + fix)
    if n["broad"]:
        return R(R.WARN, f"{len(n['broad'])} enabled NAT control rule(s) name no destination: {_zf.short(n['broad'])}." + why + fix)
    return R(R.PASS, f"{len(n['ok'])} enabled NAT control rule(s), each scoped to named destinations with a redirect target.")


def fwd_9(cl):
    """Virtual Service Edge clusters have two working nodes"""
    clusters, bad = _fwd_rows(cl, "/zia/virtualZenClusters", "Virtual Service Edge clusters")
    if bad:
        return bad
    nodes, nbad = _fwd_rows(cl, "/zia/virtualZenNodes", "Virtual Service Edge nodes")
    nodes = nodes or []
    if not clusters and not nodes:
        return R(R.INFO, _NA + "no Virtual Service Edge is deployed (the Virtual Service Edge subscription is not used).")
    v = _zf.vzen_findings(clusters, nodes)
    why = (" Why it matters: a Virtual Service Edge inspects a site's traffic on the customer's own hardware; a cluster with one working "
           "node, or a node on its own, is a single point of failure for every user behind it.")
    fix = " Best Practice: run each Virtual Service Edge cluster with at least two enabled, in-production nodes behind its load balancer." + \
          " Ref: https://help.zscaler.com/zia/about-virtual-service-edges"
    if v["thin"] or v["standalone"]:
        parts = ([f"clusters with fewer than two working nodes: {_zf.short(v['thin'])}"] if v["thin"] else []) + \
                ([f"nodes in no cluster: {_zf.short(v['standalone'])}"] if v["standalone"] else [])
        return R(R.FAIL if v["thin"] else R.WARN, "Virtual Service Edge redundancy is missing; " + "; ".join(parts) + "." + why + fix)
    if v["down"]:
        return R(R.WARN, f"{len(v['down'])} Virtual Service Edge node(s) are disabled or not in production: {_zf.short(v['down'])}." + why + fix)
    return R(R.PASS, f"{len(clusters)} Virtual Service Edge cluster(s), each with at least two working nodes.")


def fwd_10(cl):
    """DNS gateways fail over to a secondary resolver"""
    gws, bad = _fwd_rows(cl, "/zia/dnsGateways", "DNS gateways")
    if bad:
        return bad
    gws = [g for g in gws if not _fv(g, "autoCreated")] or gws
    if not gws:
        return R(R.INFO, _NA + "no DNS gateway is configured (DNS Control does not redirect to another resolver).")
    g = _zf.dns_gateway_findings(gws)
    why = (" Why it matters: a DNS Control rule that redirects lookups to a DNS gateway depends on that resolver; with no secondary, an "
           "outage of one resolver stops name resolution for everyone the rule covers.")
    fix = " Best Practice: give every DNS gateway a secondary resolver and choose its failure behaviour on purpose." + \
          " Ref: https://help.zscaler.com/zia/about-dns-gateways"
    if g["no_secondary_fail"]:
        return R(R.FAIL, f"{len(g['no_secondary_fail'])} DNS gateway(s) have no secondary resolver and fail with an error: "
                 f"{_zf.short(g['no_secondary_fail'])}." + why + fix)
    if g["no_secondary"]:
        return R(R.WARN, f"{len(g['no_secondary'])} DNS gateway(s) have no secondary resolver: {_zf.short(g['no_secondary'])}." + why + fix)
    return R(R.PASS, f"All {len(gws)} DNS gateway(s) have a secondary resolver.")


# ZIA — THREAT PROTECTION AND SAAS SECURITY HYGIENE
# ═══════════════════════════════════════════════════════════════════════
# Every path below is verified against zscaler-sdk-python 1.11.3
# (zscaler/zia/<module>.py and models/<module>.py); a field the SDK does
# not model is marked "assumed". A 404 answer means the feature is not
# licensed or not enabled on the tenant: the check says so as INFO (outside
# the score), never as a failure. A 401/403 is "Not permitted" (guard_registry).

_THREAT_REF = " Ref: https://help.zscaler.com/zia/policy-leading-practices-guide"
_SAAS_REF = " Ref: https://help.zscaler.com/zia/about-saas-security-api"
_NAME_MAX = 60
_SHOW = 5


def _nm(x, *keys):
    """An object's name for a finding: the first non-empty of `keys`,
    without control characters and capped (tenant text is untrusted)."""
    for k in keys or ("name",):
        v = _fv(x, k)
        if v not in (None, ""):
            s = "".join(ch for ch in str(v) if ch.isprintable())
            return s[:_NAME_MAX] + ("…" if len(s) > _NAME_MAX else "")
    return "?"


def _few(names):
    names = list(names)
    return ", ".join(names[:_SHOW]) + (f" and {len(names) - _SHOW} more" if len(names) > _SHOW else "")


def _unlicensed(what, c):
    """INFO for a 404 (feature not licensed or not enabled), else None."""
    if c == 404:
        return R(R.INFO, f"{what} is not licensed or not enabled on this tenant (the API answered 404), so it is not assessed.")
    return None


def _one(cl, path):
    """(dict body or None, code) of a settings object."""
    d, c = cl.get(path)
    return (d if c in (200, 204) and isinstance(d, dict) and not isinstance(d.get("error"), str) else None), c


def thr_1(cl):
    """Cloud Sandbox custom file hash list: no allow-listed hash skips the sandbox"""
    # sandbox.get_behavioral_analysis: GET /behavioralAnalysisAdvancedSettings,
    # md5HashValueList [{url (the MD5), urlComment, type CUSTOM_FILEHASH_DENY | CUSTOM_FILEHASH_ALLOW}].
    d, c = _one(cl, "/zia/behavioralAnalysisAdvancedSettings")
    na = _unlicensed("Cloud Sandbox", c)
    if na:
        return na
    if d is None:
        return R(R.INFO, f"The Cloud Sandbox file hash list is not readable (HTTP {c}); check it under Policy > Sandbox > Behavioral Analysis." + _THREAT_REF)
    rows = [x for x in _ls(d.get("md5HashValueList") or []) if isinstance(x, dict)]
    allow = [x for x in rows if str(_fv(x, "type") or "").upper() == "CUSTOM_FILEHASH_ALLOW"]
    deny = [x for x in rows if str(_fv(x, "type") or "").upper() != "CUSTOM_FILEHASH_ALLOW"]
    # sandbox.get_file_hash_count: GET .../fileHashCount; its field names are
    # not modelled by the SDK (assumed: blockedFileHashesCount, remainingFileHashes).
    q, qc = _one(cl, "/zia/behavioralAnalysisAdvancedSettings/fileHashCount")
    tail = ""
    try:
        used, left = int((q or {}).get("blockedFileHashesCount")), int((q or {}).get("remainingFileHashes"))
        if used + left > 0 and left / (used + left) < 0.1:
            tail = f" The custom hash quota is nearly full ({used} used, {left} left): remove hashes that are now in Zscaler's own threat feeds."
    except (TypeError, ValueError):
        pass
    why = " Why it matters: an allow-listed hash is never sent to the sandbox, so a file that was safe once and later trojanised passes unchecked."
    if allow:
        return R(R.WARN, f"{len(allow)} file hash(es) are allow-listed and skip Cloud Sandbox analysis ({len(deny)} blocked)." + why + tail
                 + " Best Practice: keep the allow list empty or short, with a comment and an owner per hash; prefer a scoped Sandbox rule exception." + _THREAT_REF,
                 data={"allowed": len(allow), "blocked": len(deny)})
    if tail:
        return R(R.WARN, f"{len(deny)} file hash(es) blocked by the Cloud Sandbox custom list." + tail + " Best Practice: review the list each quarter." + _THREAT_REF)
    if deny:
        return R(R.PASS, f"{len(deny)} known-bad file hash(es) are blocked by the Cloud Sandbox custom list and none is allow-listed.", data={"blocked": len(deny)})
    return R(R.INFO, "The Cloud Sandbox custom hash list is empty. That is fine when nothing is known to be bad; add the MD5 of files your incident response "
                     "confirms as malicious so they are blocked at once (Bulk changes > Sandbox file hashes adds them after a preview)." + _THREAT_REF)


def thr_2(cl):
    """Custom IPS signatures are valid and enabled"""
    # ips_signature_rules.list_ips_signature_rules: GET /ipsSignatureRules
    # (enabled, dynamicValidationRejected, disabledFromZSCM; SDK model).
    r, c = _items(cl, "/zia/ipsSignatureRules")
    na = _unlicensed("Custom IPS signatures (Advanced Cloud Firewall with IPS)", c)
    if na:
        return na
    if c not in (200, 204):
        return R(R.INFO, f"Custom IPS signatures are not readable (HTTP {c})." + _FW_BP)
    live = [x for x in r if not _truthy(_fv(x, "deleted"))]
    if not live:
        return R(R.INFO, "No custom IPS signatures. Zscaler's own signatures protect every tenant; custom ones are optional, for threats your team tracks itself." + _FW_BP)
    rejected = [_nm(x) for x in live if _truthy(_fv(x, "dynamicValidationRejected")) or _truthy(_fv(x, "disabledFromZSCM"))]
    off = [_nm(x) for x in live if _fv(x, "enabled") is not None and not _truthy(_fv(x, "enabled"))]
    if rejected:
        return R(R.WARN, f"{len(rejected)} custom IPS signature(s) were rejected by Zscaler's validation or disabled by Zscaler: {_few(rejected)}. They detect nothing."
                 " Why it matters: the team believes these threats are covered. Best Practice: fix the rule text (Validate in the portal) or delete the signature." + _FW_BP)
    if off:
        return R(R.WARN, f"{len(off)} of {len(live)} custom IPS signature(s) are disabled: {_few(off)}. Best Practice: enable them or delete the ones no longer needed, so the list says what is enforced." + _FW_BP)
    return R(R.PASS, f"{len(live)} custom IPS signature(s), all enabled and accepted by validation.")


_MOBILE_KEY = ("blockAppsWithMaliciousActivity", "blockAppsWithKnownVulnerabilities", "blockAppsSendingUnencryptedUserCredentials")
_MOBILE_ALL = _MOBILE_KEY + ("blockAppsSendingLocationInfo", "blockAppsSendingPersonallyIdentifiableInfo", "blockAppsSendingDeviceIdentifier",
                             "blockAppsCommunicatingWithAdWebsites", "blockAppsCommunicatingWithRemoteUnknownServers")
_MOBILE_LABEL = {"blockAppsWithMaliciousActivity": "with malicious activity", "blockAppsWithKnownVulnerabilities": "with known vulnerabilities",
                 "blockAppsSendingUnencryptedUserCredentials": "sending passwords unencrypted", "blockAppsSendingLocationInfo": "sending location",
                 "blockAppsSendingPersonallyIdentifiableInfo": "sending personal data", "blockAppsSendingDeviceIdentifier": "sending the device id",
                 "blockAppsCommunicatingWithAdWebsites": "talking to ad sites", "blockAppsCommunicatingWithRemoteUnknownServers": "talking to unknown servers"}


def thr_3(cl):
    """Mobile malware protection blocks malicious and leaky apps"""
    # mobile_threat_settings.get_mobile_advanced_settings: GET /mobileAdvanceThreatSettings (SDK model fields).
    d, c = _one(cl, "/zia/mobileAdvanceThreatSettings")
    na = _unlicensed("Mobile Malware Protection", c)
    if na:
        return na
    if d is None:
        return R(R.INFO, f"Mobile Malware Protection settings are not readable (HTTP {c})." + _THREAT_REF)
    key_off = [k for k in _MOBILE_KEY if not _truthy(_fv(d, k))]
    other_off = [k for k in _MOBILE_ALL[3:] if _fv(d, k) is not None and not _truthy(_fv(d, k))]
    plain = lambda ks: ", ".join(_MOBILE_LABEL.get(k, k) for k in ks)
    if key_off:
        return R(R.WARN, f"Mobile Malware Protection does not block apps: {plain(key_off)}. Why it matters: a phone app with known malware or one that sends passwords "
                 "in clear text is a way into the organisation. Best Practice: block malicious, known-vulnerable and clear-text-credential apps for every mobile user." + _THREAT_REF)
    if other_off:
        return R(R.PASS, f"Mobile Malware Protection blocks malicious, vulnerable and clear-text-credential apps; privacy controls left off: {plain(other_off)} (a privacy choice, not a gap).")
    return R(R.PASS, "Mobile Malware Protection blocks every app category it offers.")


def thr_4(cl):
    """FTP control: native FTP and FTP over HTTP are off or limited"""
    # ftp_control_policy.get_ftp_settings: GET /ftpSettings (ftpOverHttpEnabled, ftpEnabled, urlCategories, urls; SDK model).
    d, c = _one(cl, "/zia/ftpSettings")
    na = _unlicensed("FTP Control", c)
    if na:
        return na
    if d is None:
        return R(R.INFO, f"FTP Control settings are not readable (HTTP {c})." + _THREAT_REF)
    native, over_http = _truthy(_fv(d, "ftpEnabled")), _truthy(_fv(d, "ftpOverHttpEnabled"))
    limited = bool(_names(_fv(d, "urlCategories")) or _ls(_fv(d, "urls") or []))
    why = " Why it matters: FTP sends files without the inspection HTTPS gets, which makes it an easy way to take data out or bring malware in."
    if native and not limited:
        return R(R.WARN, "Native FTP is allowed to any site." + why + " Best Practice: turn native FTP off, or allow it only to the URL categories or sites the business needs." + _THREAT_REF)
    if native or over_http:
        return R(R.PASS, "FTP is " + ("allowed only to listed sites or categories" if native else "allowed over HTTP only") + ", so it is limited.")
    return R(R.PASS, "Native FTP and FTP over HTTP are both off.")


def thr_5(cl):
    """End-user notifications explain blocks and offer a way to ask for review"""
    # end_user_notification.get_eun_settings: GET /eun. The SDK has no model
    # for it (its get_eun_settings names an undefined class); the camelCase
    # field names follow the attributes its update docstring lists (assumed).
    d, c = _one(cl, "/zia/eun")
    if d is None:
        return R(R.INFO, f"End-user notification settings are not readable (HTTP {c})." + _THREAT_REF)
    gaps = []
    if _fv(d, "displayReason") is not None and not _truthy(_fv(d, "displayReason")):
        gaps.append("the reason for a block is not shown")
    if not any(_fv(d, k) for k in ("supportEmail", "supportPhone")):
        gaps.append("no IT support contact")
    if str(_fv(d, "notificationType") or "DEFAULT").upper() == "DEFAULT" and not _fv(d, "orgPolicyLink"):
        gaps.append("no link to the organisation's policy")
    if _fv(d, "securityReviewEnabled") is not None and not _truthy(_fv(d, "securityReviewEnabled")):
        gaps.append("users cannot ask for a review of a security block")
    if gaps:
        return R(R.WARN, "End-user notifications: " + "; ".join(gaps) + ". Why it matters: a block that says nothing becomes a help-desk ticket or a workaround."
                 " Best Practice: show the reason, the company name, a support contact and the policy link, and turn on the review requests." + _THREAT_REF)
    return R(R.PASS, "End-user notifications show the reason, a support contact and the policy, and users can ask for a review.")


def thr_6(cl):
    """Security alerts (UEBA) are defined and on"""
    # security_ueba_alerts.list_alert_rule_configurations_ueba_rules:
    # GET /alertRuleConfiguration/uebaRules; list_alert_definitions: GET
    # /alertDefinitions (status; its values are not enumerated: "ENABLED" assumed).
    # The webhooks list (it holds passwords and tokens) is never read.
    r, c = _items(cl, "/zia/alertRuleConfiguration/uebaRules")
    na = _unlicensed("Security alerts (UEBA)", c)
    if na:
        return na
    defs, c2 = _items(cl, "/zia/alertDefinitions")
    if c not in (200, 204) and c2 not in (200, 204):
        return R(R.INFO, f"Security alert rules are not readable (HTTP {c})." + _THREAT_REF)
    def on(x):
        s = _fv(x, "status")
        return not _truthy(_fv(x, "deleted")) and (s is None or str(s).upper() in ("ENABLED", "ACTIVE", "TRUE", "1"))
    live = [x for x in r + defs if on(x)]
    if not live:
        return R(R.WARN, "No security alert rule is on. Why it matters: unusual behaviour (a user suddenly uploading far more, many blocks in a row) is only seen if someone looks."
                 " Best Practice: turn on the UEBA alert rules and send them to the SOC by email or webhook." + _THREAT_REF)
    return R(R.PASS, f"{len(live)} security alert rule(s) are on.")


def thr_7(cl):
    """Custom file types are defined for the files only your business uses"""
    # custom_file_types.list_custom_file_types: GET /customFileTypes (name, extension; SDK model).
    r, c = _items(cl, "/zia/customFileTypes")
    na = _unlicensed("Custom file types", c)
    if na:
        return na
    if c not in (200, 204):
        return R(R.INFO, f"Custom file types are not readable (HTTP {c})." + _THREAT_REF)
    if r:
        return R(R.PASS, f"{len(r)} custom file type(s) defined (e.g. {_few(_nm(x) for x in r)}); use them in File Type Control and Sandbox rules.")
    return R(R.INFO, "No custom file types. Zscaler recognises hundreds of file types; add a custom one only for an in-house format (by extension) you need to control.")


def thr_8(cl):
    """Browser Control blocks outdated browsers and warns users"""
    # browser_control_settings.get_browser_control_settings: GET /browserControlSettings (SDK model fields).
    d, c = _one(cl, "/zia/browserControlSettings")
    if d is None:
        return R(R.INFO, f"Browser Control settings are not readable (HTTP {c}).")
    ref = " Ref: https://help.zscaler.com/zia/configuring-browser-control-policy"
    blocked = [k for k in ("blockedChromeVersions", "blockedFirefoxVersions", "blockedSafariVersions", "blockedInternetExplorerVersions", "blockedOperaVersions")
               if _ls(_fv(d, k) or [])]
    gaps = []
    if _truthy(_fv(d, "bypassAllBrowsers")):
        gaps.append("every browser bypasses Browser Control")
    elif _truthy(_fv(d, "allowAllBrowsers")) and not blocked:
        gaps.append("every browser version is allowed, however old")
    if _fv(d, "enableWarnings") is not None and not _truthy(_fv(d, "enableWarnings")):
        gaps.append("users are not warned about a vulnerable browser or plug-in")
    if gaps:
        return R(R.WARN, "Browser Control: " + "; ".join(gaps) + ". Why it matters: an unpatched browser is the most common way malware gets onto a laptop."
                 " Best Practice: block browser versions with known exploits, warn users about outdated plug-ins, and keep bypasses to named applications." + ref)
    return R(R.PASS, "Browser Control is on: " + (f"old versions are blocked for {len(blocked)} browser(s)" if blocked else "it does not allow every browser") + " and users are warned.")


def thr_9(cl):
    """Domain fronting is blocked"""
    # advanced_settings: blockDomainFrontingOnHostHeader, domainFrontingBypassUrlCategories (SDK model).
    d, c = _one(cl, "/zia/advancedSettings")
    if d is None:
        return R(R.INFO, f"Advanced Settings are not readable (HTTP {c}); check domain fronting in the portal." + _POLICY_GUIDE)
    bypass = _names(_fv(d, "domainFrontingBypassUrlCategories"))
    if not _truthy(_fv(d, "blockDomainFrontingOnHostHeader")):
        return R(R.WARN, "Domain fronting is not blocked. Why it matters: malware and evasion tools hide their real destination behind an allowed CDN name, so URL filtering sees the wrong site."
                 " Best Practice: under Advanced Settings turn on blocking domain fronting when the HTTP host header differs from the TLS server name, with bypasses only for categories that need it." + _POLICY_GUIDE)
    if len(bypass) > 5:
        return R(R.WARN, f"Domain fronting is blocked, but {len(bypass)} URL categories bypass the block. Best Practice: keep the bypass to the few categories that need it." + _POLICY_GUIDE)
    return R(R.PASS, "Domain fronting is blocked" + (f" ({len(bypass)} category bypass(es))." if bypass else "."))


def thr_10(cl):
    """Cloud app risk profiles are used by Cloud App Control"""
    # risk_profiles.list_risk_profiles_lite: GET /riskProfiles/lite (id, profileName;
    # SDK model). Cloud App Control rules reference one as cloudAppRiskProfile (cloudappcontrol model).
    r, c = _items(cl, "/zia/riskProfiles/lite")
    na = _unlicensed("Cloud app risk profiles", c)
    if na:
        return na
    if c not in (200, 204):
        return R(R.INFO, f"Cloud app risk profiles are not readable (HTTP {c})." + _THREAT_REF)
    if not r:
        return R(R.INFO, "No cloud app risk profiles. A risk profile (for example: no MFA, known data breach, weak TLS) lets one Cloud App Control rule block every risky app at once,"
                         " including new ones. Best Practice: create one and use it in a Cloud App Control rule." + _THREAT_REF)
    used = {str(_fv(_fv(x, "cloudAppRiskProfile") or {}, "id") or "") for x in _cac_live(_cac_rules_all_types(cl))}
    unused = [_nm(x, "profileName", "name") for x in r if str(_fv(x, "id") or "") not in used]
    if len(unused) == len(r):
        return R(R.WARN, f"{len(r)} cloud app risk profile(s), but no enabled Cloud App Control rule uses one: {_few(unused)}. A profile does nothing until a rule uses it."
                 " Best Practice: add a Cloud App Control rule that blocks or isolates apps matching the profile." + _THREAT_REF)
    return R(R.PASS, f"{len(r) - len(unused)} of {len(r)} cloud app risk profile(s) are used by an enabled Cloud App Control rule.")


def thr_11(cl):
    """Adaptive access profiles (user and device risk) are available to policy"""
    # adaptive_access_profiles.list_adaptive_access_profiles: GET /adaptiveAccessProfiles (id, name, deleted; SDK model).
    r, c = _items(cl, "/zia/adaptiveAccessProfiles")
    na = _unlicensed("Adaptive access", c)
    if na:
        return na
    if c not in (200, 204):
        return R(R.INFO, f"Adaptive access profiles are not readable (HTTP {c}).")
    live = [x for x in r if not _truthy(_fv(x, "deleted"))]
    if live:
        return R(R.PASS, f"{len(live)} adaptive access profile(s) can tighten policy for a risky user or device.")
    return R(R.INFO, "No adaptive access profiles. With them, a user or device whose risk rises (for example after many blocked threats) can be moved to a stricter policy automatically."
                     " Define them in the Authentication Service (formerly ZIdentity) when that subscription is present.")


def uf_5(cl):
    """SafeSearch is enforced"""
    # url_filtering.get_url_and_app_settings: GET /advancedUrlFilterAndCloudAppSettings (enforceSafeSearch, enableCIPACompliance; SDK model).
    d, c = _one(cl, "/zia/advancedUrlFilterAndCloudAppSettings")
    if d is None:
        return R(R.INFO, f"URL and Cloud App Control advanced settings are not readable (HTTP {c}); check SafeSearch in the portal." + _POLICY_GUIDE)
    if _truthy(_fv(d, "enableCIPACompliance")):
        return R(R.PASS, "The CIPA Compliance rule is on; it enforces safe search results itself.")
    if not _truthy(_fv(d, "enforceSafeSearch")):
        return R(R.WARN, "SafeSearch is not enforced. Why it matters: image and video search results can show adult or malicious content even when the sites themselves are blocked."
                 " Best Practice: turn on Enforce SafeSearch in URL & Cloud App Control advanced settings (it needs SSL inspection of the search engines)." + _POLICY_GUIDE)
    return R(R.PASS, "SafeSearch is enforced for search engines.")


def uf_6(cl):
    """Newly registered domains and AI/ML content categorisation are on"""
    d, c = _one(cl, "/zia/advancedUrlFilterAndCloudAppSettings")
    if d is None:
        return R(R.INFO, f"URL and Cloud App Control advanced settings are not readable (HTTP {c})." + _POLICY_GUIDE)
    off = [lab for k, lab in (("enableNewlyRegisteredDomains", "block newly registered domains"), ("enableDynamicContentCat", "AI/ML dynamic content categorisation"),
                              ("considerEmbeddedSites", "filtering of sites opened through translation services"))
           if not _truthy(_fv(d, k))]
    if _truthy(_fv(d, "enableCIPACompliance")):
        return R(R.INFO, "The CIPA Compliance rule is on; Zscaler then handles newly registered domains and content categorisation itself.")
    if "block newly registered domains" in off:
        return R(R.WARN, "Off: " + ", ".join(off) + ". Why it matters: most phishing and malware sites are only days old, before any reputation list knows them."
                 " Best Practice: turn these on in URL & Cloud App Control advanced settings." + _POLICY_GUIDE)
    if off:
        return R(R.WARN, "Off: " + ", ".join(off) + ". Best Practice: turn these on so uncategorised and translated pages are still filtered." + _POLICY_GUIDE)
    return R(R.PASS, "Newly registered domains, dynamic content categorisation and translated sites are all handled.")


def uf_7(cl):
    """Microsoft 365 one-click configuration is on"""
    # advanced_settings.enableOffice365 (SDK model); the URL settings' enableMsftO365
    # is listed by the SDK's update docstring but not modelled (assumed).
    d, c = _one(cl, "/zia/advancedSettings")
    u, _ = _one(cl, "/zia/advancedUrlFilterAndCloudAppSettings")
    if d is None and u is None:
        return R(R.INFO, f"Advanced Settings are not readable (HTTP {c}); check Microsoft 365 one-click configuration in the portal." + _POLICY_GUIDE)
    if _truthy(_fv(d or {}, "enableOffice365")) or _truthy(_fv(u or {}, "enableOffice365", "enableMsftO365")):
        return R(R.PASS, "Microsoft 365 one-click configuration is on: Microsoft 365 traffic follows Microsoft's network guidance automatically.")
    return R(R.WARN, "Microsoft 365 one-click configuration is off. Why it matters: without it, Teams calls and Outlook can be slowed by inspection Microsoft says to skip, and"
             " admins add hand-made bypasses that drift. Best Practice: turn on the one-click Microsoft 365 configuration, then keep only the exceptions you need." + _POLICY_GUIDE)


# ── SaaS Security (data at rest): read only when SaaS Security is on Zscaler
def _active_tenants(cl):
    d, c = cl.get("/zia/casbTenant/lite", {"activeOnly": "true"})
    rows = [x for x in (_ls(d) if c in (200, 204) else []) if isinstance(x, dict) and not _truthy(_fv(x, "tenantDeleted"))]
    return rows, c


def _malware_rules(cl):
    # casb_malware_rules.list_all_rules: GET /casbMalwareRules/all (type, state, action, cloudAppTenants; SDK model).
    return _items(cl, "/zia/casbMalwareRules/all")


def saas_1(cl):
    """Every SaaS tenant has a malware scanning rule"""
    rules, c = _malware_rules(cl)
    na = _unlicensed("SaaS Security API malware scanning", c)
    if na:
        return na
    if c not in (200, 204):
        return R(R.INFO, f"SaaS Security malware rules are not readable (HTTP {c})." + _SAAS_REF)
    tenants, tc = _active_tenants(cl)
    if not tenants:
        return R(R.INFO, "No active SaaS application tenant is onboarded, so there is nothing to scan for malware yet." + _SAAS_REF)
    covered = {str(_fv(t, "id")) for r in rules if _enabled(r) for t in _ls(_fv(r, "cloudAppTenants") or []) if isinstance(t, dict)}
    bare = [_nm(t, "tenantName") for t in tenants if str(_fv(t, "tenantId", "id")) not in covered]
    if bare:
        return R(R.WARN, f"{len(bare)} of {len(tenants)} SaaS tenant(s) have no enabled malware rule: {_few(bare)}. Why it matters: malware uploaded to a shared drive or mailbox spreads "
                 "to everyone who opens it, and inline inspection never sees files shared inside the SaaS app. Best Practice: add a SaaS Security malware rule for each tenant." + _SAAS_REF,
                 data={"uncovered": len(bare)})
    return R(R.PASS, f"All {len(tenants)} active SaaS tenant(s) have an enabled malware rule.")


def saas_2(cl):
    """Malware found in SaaS is quarantined, with a tombstone"""
    rules, c = _malware_rules(cl)
    na = _unlicensed("SaaS Security API malware scanning", c)
    if na:
        return na
    live = [r for r in rules if _enabled(r)]
    if c not in (200, 204) or not live:
        return R(R.INFO, "No enabled SaaS Security malware rule to review." + _SAAS_REF)
    # Only OFLCASB_AVP_REPORT_MALWARE is named by the SDK; any action with QUARANTINE in it is assumed to quarantine.
    report = [_nm(r) for r in live if "QUARANTINE" not in str(_fv(r, "action") or "").upper()]
    tmpl, tcode = _items(cl, "/zia/quarantineTombstoneTemplate/lite")
    no_tomb = [_nm(r) for r in live if "QUARANTINE" in str(_fv(r, "action") or "").upper() and not _fv(r, "casbTombstoneTemplate")]
    if report:
        return R(R.WARN, f"{len(report)} malware rule(s) only report what they find: {_few(report)}. The file stays shared until someone acts."
                 " Best Practice: quarantine malware found at rest, with a tombstone file that tells the owner why." + _SAAS_REF)
    if no_tomb:
        return R(R.WARN, f"{len(no_tomb)} quarantine rule(s) leave no tombstone: {_few(no_tomb)}" + (f" ({len(tmpl)} template(s) exist)." if tmpl else " (no tombstone template exists).")
                 + " Best Practice: attach a tombstone template so the file owner learns what happened instead of opening a ticket." + _SAAS_REF)
    return R(R.PASS, f"{len(live)} malware rule(s) quarantine what they find, each with a tombstone.")


def saas_3(cl):
    """SaaS tenants are healthy and scanning"""
    # saas_security_api.list_saas_scan_info: GET /casbTenant/scanInfo (tenantName,
    # scanInfo {cur_scan_start_time, prev_scan_end_time, scan_reset_num}); CasbTenant reAuth (SDK models).
    tenants, tc = _active_tenants(cl)
    na = _unlicensed("SaaS Security API", tc)
    if na:
        return na
    if not tenants:
        return R(R.INFO, "No active SaaS application tenant is onboarded." + _SAAS_REF)
    reauth = [_nm(t, "tenantName") for t in tenants if _truthy(_fv(t, "reAuth"))]
    scans, sc = _items(cl, "/zia/casbTenant/scanInfo")
    never = []
    if sc in (200, 204):
        by_id = {str(_fv(s, "tenantId")): s for s in scans}
        for t in tenants:
            info = _fv(by_id.get(str(_fv(t, "tenantId", "id"))) or {}, "scanInfo") or {}
            if not (_fv(info, "prev_scan_end_time") or _fv(info, "cur_scan_start_time")):
                never.append(_nm(t, "tenantName"))
    if reauth:
        return R(R.WARN, f"{len(reauth)} SaaS tenant(s) need to be authorised again: {_few(reauth)}. Nothing in them is scanned until then."
                 " Best Practice: re-authorise the tenant under Administration > SaaS Application Tenants." + _SAAS_REF)
    if never:
        return R(R.WARN, f"{len(never)} SaaS tenant(s) show no completed or running scan: {_few(never)}. Best Practice: confirm a malware or DLP rule covers them and the scan has started." + _SAAS_REF)
    return R(R.PASS, f"All {len(tenants)} active SaaS tenant(s) are authorised" + (" and scanning." if sc in (200, 204) else "."))


def saas_4(cl):
    """Cloud-to-cloud incident forwarding receivers are valid"""
    # cloud_to_cloud_ir.list_cloud_to_cloud_ir_lite: GET /cloudToCloudIR/lite (id, name, status,
    # lastValidationMsg {errorMsg, errorCode}; SDK model). The full list holds tenant
    # credentials (tenantAuthorizationInfo) and is never read.
    r, c = _items(cl, "/zia/cloudToCloudIR/lite")
    na = _unlicensed("Cloud-to-cloud incident forwarding", c)
    if na:
        return na
    if c not in (200, 204):
        return R(R.INFO, f"Cloud-to-cloud incident receivers are not readable (HTTP {c})." + _SAAS_REF)
    if not r:
        return R(R.INFO, "No cloud-to-cloud incident receiver. DLP incidents then stay in the Zscaler console; a receiver (an S3 bucket, a Slack or Teams channel...) brings them to the team that acts on them.")
    bad = [_nm(x) for x in r if _fv(_fv(x, "lastValidationMsg") or {}, "errorCode") not in (None, "", 0, "0", "NONE", "SUCCESS")]
    if bad:
        return R(R.WARN, f"{len(bad)} cloud-to-cloud incident receiver(s) failed their last validation: {_few(bad)}. Incidents sent to them are lost."
                 " Best Practice: validate the receiver again and fix its credentials or destination." + _SAAS_REF)
    return R(R.PASS, f"{len(r)} cloud-to-cloud incident receiver(s), none failing validation.")


THREAT_SAAS_REG = [
    ("THR.1", "ZIA — Security", "Sandbox file hash list", thr_1),
    ("THR.2", "ZIA — Security", "Custom IPS signatures", thr_2),
    ("THR.3", "ZIA — Security", "Mobile malware protection", thr_3),
    ("THR.4", "ZIA — Security", "FTP control", thr_4),
    ("THR.5", "ZIA — Security", "End-user notifications", thr_5),
    ("THR.6", "ZIA — Security", "Security alerts (UEBA)", thr_6),
    ("THR.7", "ZIA — Security", "Custom file types", thr_7),
    ("THR.8", "ZIA — Security", "Browser Control", thr_8),
    ("THR.9", "ZIA — Security", "Domain fronting blocked", thr_9),
    ("THR.10", "ZIA — Security", "Cloud app risk profiles in use", thr_10),
    ("THR.11", "ZIA — Security", "Adaptive access profiles", thr_11),
    ("UF.5", "ZIA — URL Filtering", "SafeSearch enforced", uf_5),
    ("UF.6", "ZIA — URL Filtering", "Newly registered domains and AI/ML categorisation", uf_6),
    ("UF.7", "ZIA — URL Filtering", "Microsoft 365 one-click configuration", uf_7),
    ("SAAS.1", "ZIA — SaaS Security", "SaaS tenants with a malware rule", saas_1),
    ("SAAS.2", "ZIA — SaaS Security", "Malware quarantined with a tombstone", saas_2),
    ("SAAS.3", "ZIA — SaaS Security", "SaaS tenants authorised and scanning", saas_3),
    ("SAAS.4", "ZIA — SaaS Security", "Cloud-to-cloud incident receivers", saas_4),
]


# ZTW — CLOUD & BRANCH CONNECTOR (ztw_overview holds the logic, shared
# with the Cloud & Branch Connector page; the REST paths are the SDK's,
# zscaler/ztw/*.py 1.11.3). Not licensed or not deployed is INFO (N/A).
# ═══════════════════════════════════════════════════════════════════════

def _ztw(cid):
    import ztw_overview as zo
    fn, keys = next((f, k) for i, f, k in zo.CHECKS if i == cid)

    def check(cl):
        data, codes = zo.from_rest(cl, keys)
        if codes.get("ec_groups") == 404:
            return R(R.INFO, "Cloud & Branch Connector is not licensed or not enabled on this tenant (the API answered 404): not applicable.")
        st, detail, _objs = fn(data)
        return R({"PASS": R.PASS, "FAIL": R.FAIL, "REVIEW": R.WARN}.get(st, R.INFO), detail)
    check.__name__ = "ztw_" + cid.split(".")[1]
    check.__doc__ = zo.WHAT[cid][0]
    return check


ztw_1, ztw_2, ztw_3, ztw_4, ztw_5, ztw_6, ztw_7, ztw_8 = (_ztw(f"ZTW.{n}") for n in range(1, 9))


# ═══════════════════════════════════════════════════════════════════════
# FULL PLATFORM REGISTRY
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
# ZIA INSIGHTS — Shadow IT and SaaS security (traffic, not configuration)
# ═══════════════════════════════════════════════════════════════════════
# Read only when ZIA Insights is ticked on the Scope page (_get_checks runs
# the "Insights —" sections for that key alone). The numbers come from the
# SDK's own Z-Insights queries (zscaler/zins/shadow_it.py get_apps) sent as a
# POST to /zins/graphql through the assessment client (insights.zins_over):
# a read, aggregated per application, last 30 days. Application names and
# byte counts only; no user, device or host is read.
_INS_WINDOW = "30d"
_INS_APP_LIMIT = 500           # applications asked per check (assumed accepted by Z-Insights; the SDK states no maximum)
_INS_HIGH_RISK = 4             # risk index 1 (low) to 5 (high): 4 and 5 are high (SDK zia/shadow_it_report.py lists 1-5; the direction is assumed)
_INS_NAMES = 8                 # application names quoted in a detail
_INS_REF = " Ref: https://help.zscaler.com/zia/about-shadow-it-report"
_CASB_SKUS = ("Z_CASB", "Z_CASB_BASIC")   # readiness.SKU_INFO (subscription ids assumed as seen on tenants)
# Shadow IT application name (lower case) -> the SaaS Security API saasApplication
# values a tenant of that app carries. ASSUMED: the SDK lists neither side's values.
_SAAS_API_APPS = {
    "box": ("BOX",), "dropbox": ("DROPBOX",), "google drive": ("GOOGLE_DRIVE", "GOOGLE_WORKSPACE", "GSUITE"),
    "gmail": ("GMAIL", "GOOGLE_WORKSPACE", "GSUITE"), "microsoft onedrive": ("ONEDRIVE", "OFFICE_365", "MICROSOFT_365"),
    "onedrive": ("ONEDRIVE", "OFFICE_365", "MICROSOFT_365"), "sharepoint online": ("SHAREPOINT", "OFFICE_365", "MICROSOFT_365"),
    "microsoft sharepoint": ("SHAREPOINT", "OFFICE_365", "MICROSOFT_365"), "microsoft teams": ("MS_TEAMS", "OFFICE_365", "MICROSOFT_365"),
    "exchange online": ("EXCHANGE", "OFFICE_365", "MICROSOFT_365"), "outlook": ("EXCHANGE", "OFFICE_365", "MICROSOFT_365"),
    "slack": ("SLACK",), "salesforce": ("SALESFORCE",), "servicenow": ("SERVICENOW",), "github": ("GITHUB",),
    "confluence": ("CONFLUENCE", "ATLASSIAN"), "jira": ("JIRA", "ATLASSIAN"), "zoom": ("ZOOM",), "webex": ("WEBEX",),
    "workday": ("WORKDAY",), "egnyte": ("EGNYTE",), "citrix sharefile": ("SHAREFILE",), "amazon s3": ("AMAZON_S3", "AWS_S3"),
}


def _ins_apps(cl):
    """(Shadow IT application rows, None) for the last 30 days, or (None, R)
    when Insights could not answer: not permitted, classic sign-in, refused."""
    import insights
    w = insights.window(_INS_WINDOW)
    try:
        data, _resp, err = insights.zins_over(cl).shadow_it.get_apps(start_time=w["start_ms"], end_time=w["end_ms"], limit=_INS_APP_LIMIT)
    except Exception as ex:  # noqa: BLE001 — never crash the run
        return None, R(R.ERROR, f"ZIA Insights could not be asked for the Shadow IT applications ({type(ex).__name__}).")
    if err is not None:
        status = getattr(err, "status", None)
        msg = insights._text(err)[:160]
        if status in (401, 403) or getattr(err, "classification", None) in ("UNAUTHORIZED", "FORBIDDEN"):
            return None, R(R.INFO, f"Not permitted: ZIA Insights refused the Shadow IT read (HTTP {status or 403}). Access denied — grant the "
                                   "API client's role Z-Insights read access in ZIdentity and run the assessment again.")
        if "classic ZIA API" in msg or status == 404:
            return None, R(R.INFO, "N/A: ZIA Insights is not available on this sign-in or tenant (it needs a OneAPI API client and Insights). "
                                   "Nothing was judged.")
        return None, R(R.ERROR, f"ZIA Insights did not answer the Shadow IT read: {msg or 'no reason given'}.")
    return insights.app_rows(data, _INS_APP_LIMIT), None


def _ins_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _ins_list(rows):
    rows = sorted(rows, key=lambda r: -(r.get("data_consumed") or 0))
    names = ", ".join(f"{r['application']} (risk {int(r.get('risk_index') or 0)}, {_ins_bytes(r.get('data_consumed'))})" for r in rows[:_INS_NAMES])
    more = f" and {len(rows) - _INS_NAMES} more" if len(rows) > _INS_NAMES else ""
    return names + more


def _ins_traffic(r):
    return (r.get("data_consumed") or 0) > 0 or (r.get("data_uploaded") or 0) > 0


def _ins_high(r):
    return int(r.get("risk_index") or r.get("computed_risk_index") or 0) >= _INS_HIGH_RISK


def ins_1(cl):
    """High-risk unsanctioned cloud applications still carry traffic"""
    import insights
    rows, bad = _ins_apps(cl)
    if bad:
        return bad
    if not rows:
        return R(R.INFO, "N/A: ZIA Insights reported no cloud application traffic in the last 30 days (Shadow IT may not be licensed "
                         "or no traffic was seen), so there is nothing to judge." + _INS_REF)
    hits = [r for r in rows if insights.sanction_of(r.get("sanctioned_state")) == insights.UNSANCTIONED and _ins_high(r) and _ins_traffic(r)]
    up = sum(r.get("data_uploaded") or 0 for r in hits)
    data = {"apps": len(hits), "uploaded_bytes": up, "names": [r["application"] for r in hits[:50]]}
    if hits:
        return R(R.FAIL, f"{len(hits)} high-risk cloud application(s) you marked unsanctioned still carried traffic in the last 30 days "
                         f"({_ins_bytes(up)} uploaded): {_ins_list(hits)}. Marking an app unsanctioned only labels it; traffic flows until a "
                         "Cloud App Control or URL filtering rule blocks or isolates it. Best Practice: block or isolate every unsanctioned "
                         "application with a risk index of 4 or 5 in Cloud App Control (Block, or Isolate where viewing is needed), and "
                         "review the Shadow IT report monthly." + _INS_REF, data)
    return R(R.PASS, f"No high-risk unsanctioned cloud application carried traffic in the last 30 days ({len(rows)} application(s) "
                     "with traffic reviewed).", data)


def ins_2(cl):
    """High-risk cloud applications with traffic but no sanction decision"""
    import insights
    rows, bad = _ins_apps(cl)
    if bad:
        return bad
    if not rows:
        return R(R.INFO, "N/A: ZIA Insights reported no cloud application traffic in the last 30 days, so there is nothing to judge." + _INS_REF)
    hits = [r for r in rows if insights.sanction_of(r.get("sanctioned_state")) is None and _ins_high(r) and _ins_traffic(r)]
    data = {"apps": len(hits), "names": [r["application"] for r in hits[:50]]}
    if hits:
        return R(R.WARN, f"{len(hits)} high-risk cloud application(s) carried traffic in the last 30 days with no sanction decision "
                         f"(neither sanctioned nor unsanctioned): {_ins_list(hits)}. Nobody has decided whether the business may use "
                         "them. Best Practice: review each one with its business owner, then mark it sanctioned (and protect it) or "
                         "unsanctioned (and block or isolate it). Bulk changes can set the state for many apps at once." + _INS_REF, data)
    return R(R.PASS, "Every high-risk cloud application with traffic in the last 30 days has a sanction decision.", data)


def _casb_licensed(cl):
    """True / False from the licences, None when they cannot be read."""
    d, c = cl.get("/zia/subscriptions")
    rows = d if isinstance(d, list) else (d.get("list") if isinstance(d, dict) and isinstance(d.get("list"), list) else None)
    if c not in (200, 204) or rows is None:
        return None
    ids = {str(x.get("id") or "") for x in rows if isinstance(x, dict) and x.get("subscribed") is not False}
    return bool(ids & set(_CASB_SKUS))


def ins_3(cl):
    """Sanctioned SaaS applications with traffic but no SaaS Security API tenant"""
    import insights
    lic = _casb_licensed(cl)
    if lic is False:
        return R(R.INFO, "N/A: the tenant has no CASB (SaaS Security API) subscription, so a SaaS application cannot be connected for "
                         "data-at-rest DLP. Nothing was judged." + _INS_REF)
    rows, bad = _ins_apps(cl)
    if bad:
        return bad
    sanctioned = [r for r in rows or [] if insights.sanction_of(r.get("sanctioned_state")) == insights.SANCTIONED and _ins_traffic(r)]
    connectable = [r for r in sanctioned if str(r["application"]).strip().lower() in _SAAS_API_APPS]
    if not connectable:
        return R(R.INFO, "N/A: no sanctioned application with traffic in the last 30 days is one the SaaS Security API connects to, "
                         "so there is nothing to judge." + _INS_REF)
    d, c = cl.get("/zia/casbTenant/lite")
    if c == 0 and isinstance(d, dict) and d.get("error") in ("not in scope", "required evidence unavailable"):
        return R(R.INFO, "N/A: the SaaS Security API channel is not marked as run on Zscaler on the Scope page, so its tenants were not "
                         "read and this was not judged.")
    if c not in (200, 204):
        return R(R.ERROR, f"The SaaS Security API tenants could not be read (HTTP {c}), so coverage cannot be judged.")
    have = set()
    for t in _ls(d):
        if isinstance(t, dict):
            if isinstance(t.get("status"), list) and t["status"] and not any(str(s).upper() == "ACTIVE" for s in t["status"]):
                continue
            have.add(str(t.get("saasApplication") or t.get("saas_application") or "").upper())
    gaps = [r for r in connectable if not set(_SAAS_API_APPS[str(r["application"]).strip().lower()]) & have]
    data = {"apps": len(gaps), "names": [r["application"] for r in gaps[:50]], "tenants": len(have)}
    if gaps:
        return R(R.FAIL, f"{len(gaps)} sanctioned SaaS application(s) carried traffic in the last 30 days but have no active SaaS Security "
                         f"API tenant, so files already stored in them are never scanned by SaaS DLP: {_ins_list(gaps)}. Best Practice: "
                         "connect every sanctioned SaaS application that holds company data as a SaaS Security API tenant (Administration "
                         "> SaaS Application Tenants) and add a SaaS Security DLP rule for it." + _INS_REF, data)
    return R(R.PASS, f"Every sanctioned SaaS application with traffic that the SaaS Security API supports ({len(connectable)}) has an "
                     "active SaaS Security API tenant.", data)


# ═══════════════════════════════════════════════════════════════════════
# ZCC — bypass breadth: process-based and custom IP-based apps (2026-10-31)
# ═══════════════════════════════════════════════════════════════════════
# SDK 1.11.3 (verified): process_based_apps.get_process_based_apps  GET /zcc/papi/public/v1/process-based-apps   {appIdentities: [{appName, fileNames, filePaths, matchingCriteria}]}
#                        custom_ip_base_apps.get_custom_ip_base_apps GET /zcc/papi/public/v1/custom-ip-based-apps {customAppContracts: [{appName, appDataBlob[{proto, port, ipaddr, fqdn}], appDataBlobV6}]}

# Programs whose traffic, once bypassed, carries anything a user or malware sends.
_BROAD_PROCESSES = {"powershell.exe", "pwsh.exe", "pwsh", "cmd.exe", "python.exe", "pythonw.exe", "python", "python3", "wscript.exe",
                    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bash", "sh", "zsh", "node.exe", "node", "java.exe",
                    "javaw.exe", "java", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "safari", "google chrome",
                    "curl.exe", "curl", "wget", "wget.exe", "svchost.exe", "explorer.exe", "ssh", "ssh.exe"}
_BROAD_PATHS = re.compile(r"^(?:[a-z]:\\?|[a-z]:\\users\\?|[a-z]:\\program files(?: \(x86\))?\\?|/|/applications/?|/usr/?|/usr/bin/?|/users/?)$", re.I)


def _zcc_list(d, key):
    if isinstance(d, dict) and isinstance(d.get(key), list):
        return [x for x in d[key] if isinstance(x, dict)]
    return [x for x in _ls(d) if isinstance(x, dict)] if not isinstance(d, dict) else []


def process_bypass_reasons(app):
    """Why one process-based bypass app is broad (a list of plain reasons, empty when it is narrow)."""
    why = []
    names = [str(x).strip() for x in (app.get("fileNames") or []) if str(x).strip()][:200] if isinstance(app.get("fileNames"), list) else []
    paths = [str(x).strip() for x in (app.get("filePaths") or []) if str(x).strip()][:200] if isinstance(app.get("filePaths"), list) else []
    if any("*" in n or "?" in n for n in names) or any("*" in p for p in paths):
        why.append("a wildcard matches any program")
    hits = sorted({n.lower() for n in names if n.lower() in _BROAD_PROCESSES})
    if hits:
        why.append("bypasses a shell, script engine, browser or remote tool (" + ", ".join(hits[:5]) + ")")
    if any(_BROAD_PATHS.match(p.rstrip()) for p in paths):
        why.append("a whole drive or system folder is bypassed")
    return why


def zcc_27(cl):
    """Process-based bypass apps — breadth"""
    d, c = cl.get("/zcc/process-based-apps")
    if c == 404:
        return R(R.INFO, "Not applicable: process-based apps are not available on this tenant (the feature may not be licensed or enabled).")
    if c in (401, 403):
        return R(R.INFO, "Process-based apps API not accessible on this role.")
    if c not in (200, 204):
        return R(R.INFO, f"Process-based apps returned HTTP {c}.")
    apps = _zcc_list(d, "appIdentities")
    if not apps:
        return R(R.PASS, "No process-based bypass app is defined: no program's traffic skips Client Connector.")
    broad = [(str(a.get("appName") or a.get("id"))[:80], process_bypass_reasons(a)) for a in apps]
    broad = [(n, w) for n, w in broad if w]
    if broad:
        detail = "; ".join(f"{n}: {', '.join(w)}" for n, w in broad[:10])
        return R(R.FAIL, f"{len(broad)} of {len(apps)} process-based bypass app(s) are broad — {detail}. "
                         "Why it matters: everything these programs send leaves the device without inspection, so a script, a browser or "
                         "malware run through them carries data past every DLP and threat control. "
                         "Best Practice: bypass a program by its full path (and signature where the portal offers it), never by wildcard, and never "
                         "a shell, script engine, browser or remote-access tool; prefer a destination bypass for the one service that breaks "
                         "(Client Connector Portal > App Profiles > Bypass > Process-based applications).",
                 {"broad": len(broad), "apps": len(apps)})
    return R(R.PASS, f"{len(apps)} process-based bypass app(s), each narrow (named programs, no wildcard, no shell or browser).",
             {"broad": 0, "apps": len(apps)})


def _every_port(port):
    p = str(port or "").strip().replace(" ", "")
    return p in ("", "*", "any", "all", "0-65535", "1-65535", "0", "0-0")


def ip_bypass_reasons(app):
    """Why one custom IP-based bypass app is broad."""
    import ipaddress
    why = set()
    rows = []
    for key in ("appDataBlob", "appDataBlobV6"):
        if isinstance(app.get(key), list):
            rows.extend(x for x in app[key][:500] if isinstance(x, dict))
    for r in rows:
        raw = str(r.get("ipaddr") or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        limit = 16 if net.version == 4 else 48
        if net.prefixlen == 0:
            why.add("the whole internet (" + str(net) + ")")
        elif net.prefixlen < limit:
            why.add(f"a range wider than /{limit} ({net})")
        elif _every_port(r.get("port")) and not str(r.get("proto") or "").strip() and net.prefixlen < (24 if net.version == 4 else 64):
            why.add(f"every port and protocol to {net}")
    return sorted(why)


def zcc_28(cl):
    """Custom IP-based bypass apps — breadth"""
    d, c = cl.get("/zcc/custom-ip-based-apps")
    if c == 404:
        return R(R.INFO, "Not applicable: custom IP-based apps are not available on this tenant (the feature may not be licensed or enabled).")
    if c in (401, 403):
        return R(R.INFO, "Custom IP-based apps API not accessible on this role.")
    if c not in (200, 204):
        return R(R.INFO, f"Custom IP-based apps returned HTTP {c}.")
    apps = _zcc_list(d, "customAppContracts")
    if not apps:
        return R(R.PASS, "No custom IP-based bypass app is defined.")
    broad = [(str(a.get("appName") or a.get("id"))[:80], ip_bypass_reasons(a)) for a in apps]
    broad = [(n, w) for n, w in broad if w]
    if broad:
        detail = "; ".join(f"{n}: {', '.join(w[:3])}" for n, w in broad[:10])
        return R(R.FAIL, f"{len(broad)} of {len(apps)} custom IP-based bypass app(s) are broad — {detail}. "
                         "Why it matters: traffic to these addresses leaves the tunnel uninspected; a wide range or every port turns one "
                         "exception into a way around the whole security stack. "
                         "Best Practice: list the exact host addresses, protocol and port the application needs (a /24 or narrower), and "
                         "review the list every quarter (Client Connector Portal > App Profiles > Bypass > Custom IP-based applications).",
                 {"broad": len(broad), "apps": len(apps)})
    return R(R.PASS, f"{len(apps)} custom IP-based bypass app(s), each limited to narrow ranges or named ports.", {"broad": 0, "apps": len(apps)})


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
    ("FW.9", "ZIA — Firewall", "Recommended block rules (malicious, QUIC)", fw_9),

    # ZIA — URL Filtering
    ("UF.1", "ZIA — URL Filtering", "URL filter rules", url_1),
    ("UF.2", "ZIA — URL Filtering", "URL categories", url_2),
    ("UF.3", "ZIA — URL Filtering", "Security categories blocked", url_3),
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
    ("LOC.6", "ZIA — Locations", "Firewall and IPS per location", loc_6),

    # ZIA — Forwarding and traffic path (zia_forwarding)
    ("FWD.1", "ZIA — Forwarding", "Forwarding rules that bypass ZIA (DIRECT)", fwd_1),
    ("FWD.2", "ZIA — Forwarding", "Proxy chaining gateway and fallback", fwd_2),
    ("FWD.3", "ZIA — Forwarding", "ZPA gateways (source IP anchoring)", fwd_3),
    ("FWD.4", "ZIA — Forwarding", "Data centre exclusions in force", fwd_4),
    ("FWD.5", "ZIA — Forwarding", "GRE tunnel data centre diversity", fwd_5),
    ("FWD.6", "ZIA — Forwarding", "IPv6 handled by ZIA", fwd_6),
    ("FWD.7", "ZIA — Forwarding", "Dedicated IP gateway failover", fwd_7),
    ("FWD.8", "ZIA — Forwarding", "NAT control rules scoped", fwd_8),
    ("FWD.9", "ZIA — Forwarding", "Virtual Service Edge redundancy", fwd_9),
    ("FWD.10", "ZIA — Forwarding", "DNS gateway failover", fwd_10),

    # ZIA — User & Admin
    ("USR.1", "ZIA — Users & Admin", "Users provisioned", usr_1),
    ("USR.2", "ZIA — Users & Admin", "User groups", usr_2),
    ("USR.3", "ZIA — Users & Admin", "Departments", usr_3),
    ("USR.4", "ZIA — Users & Admin", "Admin role segregation", usr_4),
    ("USR.5", "ZIA — Users & Admin", "Audit log exported (NSS)", usr_5),
    ("USR.6", "ZIA — Users & Admin", "Rule labels", usr_6),

    # ZIA — Governance and audit
    ("GOV.1", "ZIA — Governance", "Zscaler configuration audit: overall grade", gov_1),
    ("GOV.2", "ZIA — Governance", "Configuration audit: high availability and GRE tunnels", gov_2),
    ("GOV.3", "ZIA — Governance", "Configuration audit: authentication frequency", gov_3),
    ("GOV.4", "ZIA — Governance", "Configuration audit: PAC files", gov_4),
    ("GOV.5", "ZIA — Governance", "Configuration audit: Microsoft 365, IP visibility and performance", gov_5),
    ("GOV.6", "ZIA — Governance", "Alert subscriptions reach a team", gov_6),
    ("GOV.7", "ZIA — Governance", "NSS servers (VMs) enabled and healthy", gov_7),
    ("GOV.8", "ZIA — Governance", "Logs streamed out of ZIA (NSS or Cloud NSS)", gov_8),

    # ZIA — Cloud Apps
    ("CA.1", "ZIA — Cloud Apps", "Cloud app control", capp_1),
    ("CA.2", "ZIA — Cloud Apps", "Tenancy restrictions", capp_2),
    ("CA.3", "ZIA — Cloud Apps", "Cloud app SSL", capp_3),
    ("CA.4", "ZIA — Cloud Apps", "DNS over HTTPS blocked", capp_4),
    ("CA.5", "ZIA — Cloud Apps", "Cascading to URL Filtering off", capp_5),

    # ZIA — Tenant health (tenant_health.py)
    ("HLT.1", "ZIA — Tenant health", "Changes waiting for activation", hlt_1),
    ("HLT.2", "ZIA — Tenant health", "SSL inspection certificate expiry", hlt_2),
    # ZIA Insights — traffic (only with ZIA Insights ticked on the Scope page)
    ("INS.1", "Insights — Shadow IT", "High-risk unsanctioned apps still carry traffic", ins_1),
    ("INS.2", "Insights — Shadow IT", "High-risk apps with no sanction decision", ins_2),
    ("INS.3", "Insights — SaaS Security", "Sanctioned SaaS apps with no SaaS Security API tenant", ins_3),

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
    ("ZPA.10", "ZPA — App Access", "Web server certificates", zpa_10),
    ("ZPA.11", "ZPA — App Access", "Identity providers", zpa_11),
    ("ZPA.12", "ZPA — App Access", "Posture profiles", zpa_12),
    ("ZPA.13", "ZPA — App Access", "Trusted networks", zpa_13),
    ("ZPA.14", "ZPA — App Access", "Log streaming (LSS)", zpa_14),
    ("ZPA.15", "ZPA — App Access", "Machine groups", zpa_15),
    ("ZPA.16", "ZPA — App Access", "AppProtection inspection coverage", zpa_16),
    ("ZPA.17", "ZPA — App Access", "Client forwarding bypass of sensitive segments", zpa_17),
    ("ZPA.18", "ZPA — App Access", "Privileged Remote Access capabilities and credentials", zpa_18),
    ("ZPA.19", "ZPA — App Access", "Redirection policy", zpa_19),
    ("ZPA.20", "ZPA — App Access", "Unmanaged-device access: isolation and browser protection", zpa_20),
    ("ZPA.21", "ZPA — App Access", "Business continuity and Private Cloud Controllers", zpa_21),

    # ZPA — Tenant health (tenant_health.py)
    ("HLT.3", "ZPA — Tenant health", "Enrollment certificate expiry", hlt_3),
    ("HLT.4", "ZPA — Tenant health", "App Connector groups with no connector", hlt_4),

    # ZCC — Device Management / Mobile Portal
    ("ZCC.1",  "ZCC — Devices",          "Trusted networks",                    zcc_1),
    ("ZCC.2",  "ZCC — Devices",          "Web policies (legacy)",               zcc_2),
    ("ZCC.3",  "ZCC — Devices",          "Fail-open policy",                    zcc_3),
    ("ZCC.4",  "ZCC — Devices",          "Device inventory + platform mix",     zcc_4),
    ("ZCC.5",  "ZCC — Devices",          "Company info",                        zcc_5),
    ("ZCC.6",  "ZCC — Mobile Portal",    "Forwarding profiles + tunnel modes",  zcc_6),
    ("ZCC.7",  "ZCC — Mobile Portal",    "Machine tunnel policy (pre-logon)",   zcc_7),
    ("ZCC.8",  "ZCC — Mobile Portal",    "App profiles — posture + enforcement", zcc_8),
    ("ZCC.9",  "ZCC — Mobile Portal",    "Posture profiles defined",            zcc_9),
    ("ZCC.10", "ZCC — Mobile Portal",    "ZPN module modes (ZIA/ZPA/ZDX)",      zcc_10),
    ("ZCC.11", "ZCC — Mobile Portal",    "Enrollment + version + stale devices", zcc_11),
    ("ZCC.12", "ZCC — Mobile Portal",    "PAC files",                           zcc_12),
    ("ZCC.13", "ZCC — Mobile Portal",    "Privacy info (GDPR readiness)",       zcc_13),
    ("ZCC.14", "ZCC — Mobile Portal",    "App bypass configuration",            zcc_14),
    ("ZCC.15", "ZCC — Mobile Portal",    "Browser protection profiles",         zcc_15),
    ("ZCC.16", "ZCC — Mobile Portal",    "Device cleanup policy",               zcc_16),
    ("ZCC.17", "ZCC — Mobile Portal",    "Device groups for policy targeting",  zcc_17),
    ("ZCC.18", "ZCC — Mobile Portal",    "Trusted networks — detection methods", zcc_18),
    ("ZCC.19", "ZCC — Mobile Portal",    "Posture field collection",            zcc_19),
    ("ZCC.20", "ZCC — Mobile Portal",    "Enrollment authentication method",    zcc_20),
    ("ZCC.21", "ZCC — Mobile Portal",    "Admin users (redundancy + hygiene)",  zcc_21),
    ("ZCC.22", "ZCC — Mobile Portal",    "Admin roles (least privilege)",       zcc_22),
    ("ZCC.23", "ZCC — Mobile Portal",    "Admin user sync info (IdP health)",   zcc_23),
    ("ZCC.24", "ZCC — Mobile Portal",    "ZDX group entitlements",              zcc_24),
    ("ZCC.25", "ZCC — Mobile Portal",    "ZPA group entitlements",              zcc_25),
    ("ZCC.26", "ZCC — Mobile Portal",    "Web app service exclusions",          zcc_26),

    # ZTW — Cloud & Branch Connector (Scope page key "ztw")
    ("ZTW.1", "ZTW — Cloud & Branch Connector", "Connector groups have two or more connectors", ztw_1),
    ("ZTW.2", "ZTW — Cloud & Branch Connector", "Connectors serving, on one software version", ztw_2),
    ("ZTW.3", "ZTW — Cloud & Branch Connector", "Workload traffic not sent DIRECT", ztw_3),
    ("ZTW.4", "ZTW — Cloud & Branch Connector", "Forwarding gateways fail closed", ztw_4),
    ("ZTW.5", "ZTW — Cloud & Branch Connector", "Configuration changes activated", ztw_5),
    ("ZTW.6", "ZTW — Cloud & Branch Connector", "Connector locations: firewall and IPS on", ztw_6),
    ("ZTW.7", "ZTW — Cloud & Branch Connector", "Connector admins and roles", ztw_7),
    ("ZTW.8", "ZTW — Cloud & Branch Connector", "Provisioning API keys rotated", ztw_8),
    ("ZCC.27", "ZCC — Mobile Portal",    "Process-based bypass apps — breadth",  zcc_27),
    ("ZCC.28", "ZCC — Mobile Portal",    "Custom IP-based bypass apps — breadth", zcc_28),
]
PLATFORM_REG = PLATFORM_REG + THREAT_SAAS_REG   # threat protection and SaaS Security hygiene (above)
PLATFORM_REG = guard_registry(PLATFORM_REG)

# ═══════════════════════════════════════════════════════════════════════
# ZPA — BROWSER ACCESS, ISOLATION AND PRIVILEGED REMOTE ACCESS
# (promoted from the Browser security page, browser_security._zpa_findings)
# ═══════════════════════════════════════════════════════════════════════
_BA_REF = " Ref: https://help.zscaler.com/zpa/about-browser-access"
_PRA_REF = " Ref: https://help.zscaler.com/zpa/about-privileged-remote-access"


def _zpa_list(cl, ep):
    d, c = cl.get(ep)
    items = _ls(d) if c in (200, 204) else []
    if not items and isinstance(d, dict):
        items = _ls(d.get("list", []))
    return [x for x in items if isinstance(x, dict)], c


def zpa_ba_1(cl):
    """Browser Access apps are reached by an access rule

    A Browser Access segment (clientlessApps) that no enabled access rule
    reaches publishes web apps nobody can use, or was left behind when the
    app moved (browser_security BS-A1; zpa_analysis._reaches decides)."""
    import zpa_analysis
    import zpa_reader as zr
    segs, c = _zpa_list(cl, "/zpa/application")
    if c not in (200, 204):
        return R(R.INFO, f"The ZPA application segments could not be read (HTTP {c}), so Browser Access was not assessed.")
    ba = [s for s in segs if s.get("clientlessApps") and str(s.get("enabled", True)).lower() != "false"]
    if not ba:
        return R(R.INFO, "No enabled Browser Access application segment: nothing to check (N/A).")
    rules, rc = _zpa_list(cl, "/zpa/policySet/rules/ACCESS_POLICY")
    if rc not in (200, 204):
        return R(R.INFO, f"The ZPA access policy could not be read (HTTP {rc}), so it is not known who reaches the Browser Access apps.")
    norm = [zr.normalize_rule(r, i, "access") for i, r in enumerate(rules)]
    enabled = [r for r in norm if not r.get("disabled")]
    lonely = []
    for s in ba:
        n = zr.normalize_segment(s)
        if not any(zpa_analysis._reaches(r, {"id": n["id"], "segment_group_id": n["segment_group_id"]}) for r in enabled):
            lonely.append(n["name"])
    if lonely:
        return R(R.WARN, f"{len(lonely)} of {len(ba)} Browser Access segment(s) are reached by no enabled access rule: {', '.join(lonely[:5])}. "
                 "Nobody can use them, or they were left behind when the app moved. Fix: add each to an access rule for the users who need "
                 "it (ideally with a managed-browser or posture condition), or disable it." + _BA_REF)
    return R(R.PASS, f"All {len(ba)} Browser Access segment(s) are reached by an enabled access rule.")


def zpa_ba_2(cl):
    """ZPA isolation rules name an isolation profile (browser_security BS-R3)"""
    rules, c = _zpa_list(cl, "/zpa/policySet/rules/policyType/ISOLATION_POLICY")
    if c == 404:
        return R(R.INFO, "ZPA isolation (Zero Trust Browser for private apps) is not licensed or not enabled on this tenant (N/A).")
    if c not in (200, 204):
        return R(R.INFO, f"The ZPA isolation policy could not be read (HTTP {c}).")
    iso = [r for r in rules if str(r.get("action") or "").upper() == "ISOLATE" and str(r.get("disabled", "0")) not in ("1", "true", "True")]
    if not iso:
        return R(R.INFO, "No enabled ZPA isolation rule: nothing to check (N/A).")
    bare = [str(r.get("name") or r.get("id")) for r in iso if not (r.get("zpnIsolationProfileId") or r.get("zpn_isolation_profile_id"))]
    if bare:
        return R(R.FAIL, f"{len(bare)} ZPA isolation rule(s) isolate but name no isolation profile: {', '.join(bare[:5])}. The isolation they "
                 "promise has no controls (copy and paste, upload, download, printing) behind it. Fix: edit each rule in ZPA (Policies → "
                 "Isolation) and pick its isolation profile.")
    return R(R.PASS, f"All {len(iso)} ZPA isolation rule(s) name an isolation profile.")


def zpa_ba_3(cl):
    """Privileged Remote Access portals tell users the session is privileged

    PRA's user notification (userNotificationEnabled) shows a notice when a
    privileged session starts; without it, users of a monitored admin path
    are not told (browser_security.normalize_pra_portal)."""
    portals, c = _zpa_list(cl, "/zpa/praPortal")
    if c == 404:
        return R(R.INFO, "Privileged Remote Access is not licensed or not enabled on this tenant (N/A).")
    if c not in (200, 204):
        return R(R.INFO, f"The Privileged Remote Access portals could not be read (HTTP {c}).")
    on = [p for p in portals if str(p.get("enabled", True)).lower() != "false"]
    if not on:
        return R(R.INFO, "No enabled Privileged Remote Access portal: nothing to check (N/A).")
    quiet = [str(p.get("name") or p.get("id")) for p in on if str(p.get("userNotificationEnabled", False)).lower() != "true"]
    if quiet:
        return R(R.WARN, f"{len(quiet)} of {len(on)} Privileged Remote Access portal(s) show no user notification: {', '.join(quiet[:5])}. "
                 "People starting a privileged session are not told it is monitored and recorded. Fix: turn on User Notification for "
                 "each portal in ZPA (Privileged Remote Access → Portals)." + _PRA_REF)
    return R(R.PASS, f"All {len(on)} Privileged Remote Access portal(s) show the user notification.")


def zpa_ba_4(cl):
    """Privileged Remote Access consoles point at an enabled app segment and portal"""
    consoles, c = _zpa_list(cl, "/zpa/praConsole")
    if c == 404:
        return R(R.INFO, "Privileged Remote Access is not licensed or not enabled on this tenant (N/A).")
    if c not in (200, 204):
        return R(R.INFO, f"The Privileged Remote Access consoles could not be read (HTTP {c}).")
    on = [x for x in consoles if str(x.get("enabled", True)).lower() != "false"]
    if not on:
        return R(R.INFO, "No enabled Privileged Remote Access console: nothing to check (N/A).")
    segs, sc = _zpa_list(cl, "/zpa/application")
    portals, pc = _zpa_list(cl, "/zpa/praPortal")
    if sc not in (200, 204) or pc not in (200, 204):
        return R(R.INFO, "The app segments or PRA portals could not be read, so the consoles' targets were not checked.")
    live_segs = {str(s.get("id")) for s in segs if str(s.get("enabled", True)).lower() != "false"}
    live_portals = {str(p.get("id")) for p in portals if str(p.get("enabled", True)).lower() != "false"}
    broken = []
    for x in on:
        app = x.get("praApplication") if isinstance(x.get("praApplication"), dict) else {}
        pids = [str(p.get("id")) for p in (x.get("praPortals") or []) if isinstance(p, dict)]
        if str(app.get("appId") or "") not in live_segs or not any(p in live_portals for p in pids):
            broken.append(str(x.get("name") or x.get("id")))
    if broken:
        return R(R.WARN, f"{len(broken)} Privileged Remote Access console(s) point at a disabled or missing app segment or portal: "
                 f"{', '.join(broken[:5])}. They cannot be used, and they keep an admin path documented that no longer works. Fix: point "
                 "each at an enabled segment and portal, or delete it." + _PRA_REF)
    return R(R.PASS, f"All {len(on)} Privileged Remote Access console(s) point at an enabled app segment and portal.")


# ZPA — Browser Access, isolation and PRA (promoted from the Browser security page)
PLATFORM_REG = PLATFORM_REG + guard_registry([
    ("ZPA.BA1", "ZPA — Browser Access & PRA", "Browser Access apps reached by an access rule", zpa_ba_1),
    ("ZPA.BA2", "ZPA — Browser Access & PRA", "Isolation rules name an isolation profile", zpa_ba_2),
    ("ZPA.BA3", "ZPA — Browser Access & PRA", "PRA portals show the user notification", zpa_ba_3),
    ("ZPA.BA4", "ZPA — Browser Access & PRA", "PRA consoles point at an enabled segment and portal", zpa_ba_4),
])


# ═══════════════════════════════════════════════════════════════════════
# DLP — EDM AND IDM INDEXES (zia/dlp_resources.py: list_edm_schemas GET
# /dlpExactDataMatchSchemas, list_dlp_idm_profiles GET /idmprofile)
# ═══════════════════════════════════════════════════════════════════════
_EDM_REF = " Ref: https://help.zscaler.com/zia/about-exact-data-match"
_IDM_REF = " Ref: https://help.zscaler.com/zia/about-indexed-document-match"
INDEX_STALE_DAYS = 180
_GOOD_UPLOAD = ("COMPLETED", "SUCCESS", "DONE", "UPLOADED", "IDM_PROF_UPLOAD_COMPLETED")


def _epoch(v):
    """Seconds since 1970 from a ZIA time (seconds or milliseconds); None when absent."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    return n / 1000.0 if n > 1e11 else n


def dlp_idx_1(cl):
    """EDM schemas are indexed without errors"""
    items, c = _items(cl, "/zia/dlpExactDataMatchSchemas")
    if c == 404:
        return R(R.INFO, "Exact Data Match is not licensed or not enabled on this tenant (N/A).")
    if c not in (200, 204):
        return R(R.INFO, f"The EDM schemas could not be read (HTTP {c}).")
    if not items:
        return R(R.INFO, "No EDM schema: nothing to check here (check 5.14 says whether EDM should be used).")
    bad = [str(x.get("projectName") or x.get("schemaId")) for x in items
           if str(x.get("fileUploadStatus") or "").upper() in ("FAILED", "ERROR", "FAILURE") or str(x.get("schemaActive", True)).lower() == "false"]
    if bad:
        return R(R.FAIL, f"{len(bad)} of {len(items)} EDM schema(s) failed their last index upload or are inactive: {', '.join(bad[:5])}. An "
                 "engine that uses them matches nothing new, so the records they protect leave unnoticed. Fix: re-run the Index Tool upload "
                 "for each schema and check its status in ZIA (Administration → DLP Resources → Exact Data Match)." + _EDM_REF)
    return R(R.PASS, f"All {len(items)} EDM schema(s) are active and indexed.")


def dlp_idx_2(cl):
    """IDM profiles are indexed and re-indexed on a schedule"""
    items, c = _items(cl, "/zia/idmprofile")
    if c == 404:
        return R(R.INFO, "Indexed Document Match is not licensed or not enabled on this tenant (N/A).")
    if c not in (200, 204):
        return R(R.INFO, f"The IDM profiles could not be read (HTTP {c}).")
    if not items:
        return R(R.INFO, "No IDM profile: nothing to check here (check 5.15 says whether IDM should be used).")
    failed = [str(x.get("profileName") or x.get("profileId")) for x in items
              if x.get("uploadStatus") and not any(g in str(x.get("uploadStatus")).upper() for g in _GOOD_UPLOAD)]
    unscheduled = [str(x.get("profileName") or x.get("profileId")) for x in items if str(x.get("scheduleDisabled", False)).lower() == "true"]
    if failed:
        return R(R.FAIL, f"{len(failed)} IDM profile(s) did not finish indexing: {', '.join(failed[:5])}. Their documents are not "
                 "fingerprinted, so copies leave unnoticed. Fix: re-run the index in the Index Tool and check the profile's status." + _IDM_REF)
    if unscheduled:
        return R(R.WARN, f"{len(unscheduled)} of {len(items)} IDM profile(s) have their re-index schedule turned off: {', '.join(unscheduled[:5])}. "
                 "New versions of the protected documents are never fingerprinted. Fix: turn the schedule on (daily or weekly) in the "
                 "profile." + _IDM_REF)
    return R(R.PASS, f"All {len(items)} IDM profile(s) are indexed and re-index on a schedule.")


def dlp_idx_3(cl):
    """EDM and IDM indexes were refreshed in the last 180 days"""
    import time
    edm, ec = _items(cl, "/zia/dlpExactDataMatchSchemas")
    idm, ic = _items(cl, "/zia/idmprofile")
    rows = ([(str(x.get("projectName") or x.get("schemaId")), _epoch(x.get("lastModifiedTime"))) for x in edm] if ec in (200, 204) else []) + \
           ([(str(x.get("profileName") or x.get("profileId")), _epoch(x.get("lastModifiedTime"))) for x in idm] if ic in (200, 204) else [])
    if not rows:
        return R(R.INFO, "No EDM schema or IDM profile could be read: nothing to check (N/A).")
    cut = time.time() - INDEX_STALE_DAYS * 86400
    old = [n for n, t in rows if t is not None and t < cut]
    if old:
        return R(R.WARN, f"{len(old)} of {len(rows)} index(es) were last refreshed more than {INDEX_STALE_DAYS} days ago: {', '.join(old[:5])}. "
                 "Records and documents added since are not protected. Fix: refresh them from the Index Tool, ideally on a schedule.")
    return R(R.PASS, f"All {len(rows)} EDM and IDM index(es) were refreshed in the last {INDEX_STALE_DAYS} days.")


# ═══════════════════════════════════════════════════════════════════════
# DLP — WORKFLOW AUTOMATION INCIDENTS (promoted from Detection health; read
# with the incident search, a POST that changes nothing, through the Scope
# page's channel guard: channel_scope.ScopedClient.post_read)
# ═══════════════════════════════════════════════════════════════════════
ZWA_WINDOW_DAYS = 30
ZWA_TRIAGE_DAYS = 7
ZWA_FP_PCT = 40
ZWA_FP_MIN = 10
_ZWA_REF = " Ref: https://help.zscaler.com/workflow-automation/about-dlp-incidents"


def _zwa_incidents(cl):
    """(incidents of the last ZWA_WINDOW_DAYS as detection_health
    normalises them, None or why they could not be read). At most 5 pages."""
    import time
    from datetime import datetime, timedelta, timezone
    import detection_health as dh
    # Kept on the client of this run only (never keyed by id(): a later run's client could reuse the id).
    try:
        hit = vars(cl).get("_zme_zwa_incidents")
    except TypeError:
        hit = None
    if hit and time.time() - hit[0] < 120:
        return hit[1], hit[2]
    post = getattr(cl, "post_read", None)
    if not callable(post):
        return [], "Workflow Automation incidents are read only when the Scope page marks Workflow Automation as run on Zscaler."
    end = datetime.now(timezone.utc)
    tr = {"startTime": (end - timedelta(days=ZWA_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "endTime": end.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    out, why = [], None
    for page in range(1, 6):
        d, c = post(f"/zwa/dlp/v1/incidents/search?page={page}&pageSize=100", {"fields": [], "timeRange": tr})
        if c not in (200, 204):
            why = (d or {}).get("message") if isinstance(d, dict) and c == 0 else f"HTTP {c}"
            if c in (401, 403):
                why = f"HTTP {c}"
            break
        leaves = dh._flatten(d if isinstance(d, dict) else {})
        out.extend(dh.normalize_incident(x, dh.DEFAULTS["not_real"]) for x in leaves)
        if len(leaves) < 100:
            break
    try:
        vars(cl)["_zme_zwa_incidents"] = (time.time(), out, why)
    except TypeError:
        pass
    return out, why


def _zwa_unread(why):
    if str(why or "").endswith(("401", "403")):
        return R(R.INFO, f"The Workflow Automation incidents were refused to the API client ({why}): grant it Workflow Automation read access.")
    return R(R.INFO, f"The Workflow Automation incidents could not be read: {why}")


def zwa_1(cl):
    """DLP incidents reach Workflow Automation"""
    incs, why = _zwa_incidents(cl)
    if why:
        return _zwa_unread(why)
    if not incs:
        return R(R.WARN, f"No DLP incident reached Workflow Automation in the last {ZWA_WINDOW_DAYS} days. Either nothing matched (unlikely "
                 "for an organisation of any size) or the rules do not send incidents to it. Fix: check that the DLP rules name the incident "
                 "receiver (cloud-to-cloud or ICAP) and that Workflow Automation is linked to ZIA; Detection health shows how incidents reach "
                 "it." + _ZWA_REF)
    chans = sorted({i["channel"] for i in incs if i.get("channel")})
    return R(R.PASS, f"{len(incs)} DLP incident(s) reached Workflow Automation in the last {ZWA_WINDOW_DAYS} days ({', '.join(chans[:6])}).")


def zwa_2(cl):
    """Open DLP incidents are triaged within 7 days"""
    from datetime import datetime, timedelta, timezone
    incs, why = _zwa_incidents(cl)
    if why:
        return _zwa_unread(why)
    if not incs:
        return R(R.INFO, "No incident in the window: nothing to triage (N/A).")
    cut = datetime.now(timezone.utc) - timedelta(days=ZWA_TRIAGE_DAYS)
    open_ = [i for i in incs if str(i.get("status") or "").upper() not in ("CLOSED", "RESOLVED")]
    old = [i for i in open_ if i.get("_created") and i["_created"] < cut]
    if old:
        return R(R.WARN, f"{len(old)} of {len(open_)} open DLP incident(s) are older than {ZWA_TRIAGE_DAYS} days. A leak that nobody looks at "
                 "for a week is a leak that cannot be stopped. Fix: assign them to an analyst, close the false positives (Detection health → "
                 "Close as false positives) and set a triage target in Workflow Automation." + _ZWA_REF)
    return R(R.PASS, f"No open DLP incident is older than {ZWA_TRIAGE_DAYS} days ({len(open_)} open, {len(incs) - len(open_)} closed).")


def zwa_3(cl):
    """The false-positive rate of closed DLP incidents is under 40%"""
    incs, why = _zwa_incidents(cl)
    if why:
        return _zwa_unread(why)
    closed = [i for i in incs if i.get("real") is not None]
    if len(closed) < ZWA_FP_MIN:
        return R(R.INFO, f"{len(closed)} closed incident(s) with a verdict in the window: fewer than {ZWA_FP_MIN}, too few to judge the "
                 "false-positive rate (N/A).")
    fp = sum(1 for i in closed if i["real"] is False)
    pct = round(fp * 100 / len(closed))
    if pct >= ZWA_FP_PCT:
        return R(R.WARN, f"{pct}% of {len(closed)} closed DLP incidents were false positives. Analysts spend most of their time on noise, and "
                 "real leaks wait. Fix: open Detection health to see which rules, dictionaries and destinations carry the noise, and tune or "
                 "exclude them.")
    return R(R.PASS, f"{pct}% of {len(closed)} closed DLP incidents were false positives (under {ZWA_FP_PCT}%).")


def zwa_4(cl):
    """Workflow Automation's admin audit log is readable"""
    post = getattr(cl, "post_read", None)
    if not callable(post):
        return R(R.INFO, "Read only when the Scope page marks Workflow Automation as run on Zscaler.")
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    d, c = post("/zwa/dlp/v1/customer/audit?page=1&pageSize=100",
                {"fields": [], "timeRange": {"startTime": (end - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                             "endTime": end.strftime("%Y-%m-%dT%H:%M:%S.000Z")}})
    if c in (401, 403):
        return R(R.WARN, f"The Workflow Automation audit log was refused to the API client (HTTP {c}): who closed or changed an incident "
                 "cannot be reviewed from here. Fix: give the API client's role Workflow Automation audit-log read access.")
    if c not in (200, 204):
        return R(R.INFO, f"The Workflow Automation audit log could not be read (HTTP {c}).")
    n = len(d.get("logs") or []) if isinstance(d, dict) else 0
    return R(R.PASS, f"The Workflow Automation audit log is readable: {n} admin action(s) in the last 7 days.")


DLP_EXTRA_REG = [
    ("DLP.IDX1", "DLP — EDM and IDM indexes", "EDM schemas indexed without errors", dlp_idx_1),
    ("DLP.IDX2", "DLP — EDM and IDM indexes", "IDM profiles indexed and scheduled", dlp_idx_2),
    ("DLP.IDX3", "DLP — EDM and IDM indexes", "Indexes refreshed in the last 180 days", dlp_idx_3),
    ("ZWA.1", "DLP — Workflow Automation incidents", "Incidents reach Workflow Automation", zwa_1),
    ("ZWA.2", "DLP — Workflow Automation incidents", "Open incidents triaged within 7 days", zwa_2),
    ("ZWA.3", "DLP — Workflow Automation incidents", "False-positive rate under 40%", zwa_3),
    ("ZWA.4", "DLP — Workflow Automation incidents", "Workflow Automation audit log readable", zwa_4),
]
DLP_EXTRA_REG = guard_registry(DLP_EXTRA_REG)

