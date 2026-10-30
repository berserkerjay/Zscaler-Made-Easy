"""Compliance profiles: one compliance choice that drives the ZIA security
baseline (its tier, overlay, the rules it adds and the rules it requires),
the DLP policy packs offered, the AI Guard detection profile and the
compliance pack (compliance_pack.py).

Two kinds of profile:

* Federal profiles, each with its own control catalogue and a cited source:
  FedRAMP Moderate and High (NIST SP 800-53 Rev. 5 controls, selected by
  the NIST SP 800-53B baselines), CMMC Level 2 (the CMMC practices, which
  are the NIST SP 800-171 Rev. 2 requirements), Federal Zero Trust (OMB
  M-22-09 actions and CISA Zero Trust Maturity Model v2.0 functions), IRS
  Publication 1075 (federal tax information) and GovRAMP Moderate.
* Framework profiles: the nine compliance overlays the ZIA baseline already
  had (HIPAA, HITRUST, NIST 800-53, NIST 800-171, PCI DSS, CJIS, SOX, FERPA,
  GDPR). They keep the operator's tier and cite the overlay's area-level
  controls, as before; picking one also sets the packs and the AI Guard
  profile.

Every rule mapped
-----------------
A rule the baseline or a policy pack creates is mapped rule -> objective ->
the profile's controls (RULE_OBJECTIVES, pack_rule_objective), or carries a
reason code (REASONS) saying why no control of the profile applies. A rule
with neither is a defect: mapping() raises, and the tests fail.

What is sourced and what is assumed
-----------------------------------
Each control names the document it comes from (SOURCES). A control whose id,
title or baseline membership is not verified against that document, or
whose link to a rule is an interpretation the source does not state, has
`assumed: True` and an `assumed_why`; assumed() lists them all, and every
export shows the flag. Rule -> objective links are this app's reading of
what a rule does (written beside each rule in RULE_OBJECTIVES).

Pure: nothing here reads or writes a tenant.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
SOURCES: Dict[str, Dict[str, str]] = {
    "sp80053": {"title": "NIST SP 800-53 Rev. 5, Security and Privacy Controls", "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
    "sp80053b": {"title": "NIST SP 800-53B, Control Baselines (Low, Moderate, High)", "url": "https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final"},
    "fedramp": {"title": "FedRAMP Rev. 5 baselines (built on NIST SP 800-53B)", "url": "https://www.fedramp.gov/"},
    "sp800171": {"title": "NIST SP 800-171 Rev. 2, Protecting CUI in Nonfederal Systems", "url": "https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final"},
    "cmmc": {"title": "CMMC Program, 32 CFR Part 170, and the DoD CMMC Assessment Guide, Level 2",
             "url": "https://dodcio.defense.gov/CMMC/Resources-Documentation/"},
    "m2209": {"title": "OMB M-22-09, Moving the U.S. Government Toward Zero Trust Cybersecurity Principles",
              "url": "https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf"},
    "ztmm": {"title": "CISA Zero Trust Maturity Model, Version 2.0", "url": "https://www.cisa.gov/zero-trust-maturity-model"},
    "pub1075": {"title": "IRS Publication 1075 (Rev. 11-2021), Tax Information Security Guidelines", "url": "https://www.irs.gov/pub/irs-pdf/p1075.pdf"},
    "irc6103": {"title": "26 U.S.C. 6103, Confidentiality and disclosure of returns and return information",
                "url": "https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title26-section6103"},
    "govramp": {"title": "GovRAMP (formerly StateRAMP) security program and baselines", "url": "https://govramp.org/"},
}

# ---------------------------------------------------------------------------
# Reason codes: why a rule maps to no control of the profile
# ---------------------------------------------------------------------------
REASONS: Dict[str, str] = {
    "OPERATIONAL": "Needed for the network to work (an allow rule the default deny relies on); it carries out no control by itself.",
    "NOT_IN_SCOPE_FOR_PROFILE": "Supports a business choice (bandwidth, productivity) that this profile's source does not ask for.",
    "VENDOR_DEFAULT": "Zscaler's recommended practice; no control of this profile requires it.",
    "PRIVACY_EXCEPTION": "A deliberate exemption from inspection for privacy: it narrows monitoring, so it is listed for the assessor and not "
                         "credited to a control.",
    "CAUTION_ONLY": "A caution page warns the user and lets them continue: it is not credited to an enforcement control.",
    "ALLOWS_TRAFFIC": "The rule's action (as chosen in the review) lets the traffic through, so it carries out none of its controls.",
    "NOT_CREATED": "Switched off in the review: the build does not create it.",
}

# ---------------------------------------------------------------------------
# Objectives: what a rule is for, in words a control can be matched to.
# `domains` are compliance_mapping.CONTROL_DOMAINS keys (used by the
# framework profiles, whose controls are per area).
# ---------------------------------------------------------------------------
OBJECTIVES: Dict[str, Dict[str, Any]] = {
    "web_risk_block": {"label": "Block risky web destinations at the boundary", "domains": ("url_filtering",)},
    "malicious_code": {"label": "Detect and stop malicious code", "domains": ("malware_threat",)},
    "mobile_code": {"label": "Control mobile code (ActiveX, browser exploits)", "domains": ("malware_threat",)},
    "spam_phishing": {"label": "Protect against spam and phishing", "domains": ("malware_threat",)},
    "deny_by_default": {"label": "Deny network traffic by default, allow by exception", "domains": ("firewall",)},
    "least_functionality": {"label": "Prohibit nonessential protocols and services (P2P, tunnels, anonymisers)", "domains": ("firewall",)},
    "boundary_restrict": {"label": "Restrict connections across the boundary to approved destinations", "domains": ("firewall",)},
    "boundary_monitoring": {"label": "Monitor inbound and outbound traffic for attacks (command and control)", "domains": ("firewall", "malware_threat")},
    "encrypted_visibility": {"label": "Keep encrypted traffic from bypassing inspection", "domains": ("ssl_inspection",)},
    "protective_dns": {"label": "Use a protective DNS resolver; stop DNS tunnelling", "domains": ("firewall", "malware_threat")},
    "encrypted_dns": {"label": "Inspect DNS over HTTPS (encrypted DNS)", "domains": ("firewall",)},
    "external_systems": {"label": "Restrict the use of external systems (personal webmail, unapproved apps)", "domains": ("dlp", "url_filtering")},
    "public_posting": {"label": "Control information posted to publicly accessible systems", "domains": ("dlp",)},
    "data_flow_enforce": {"label": "Enforce approved flows of sensitive data (block exfiltration)", "domains": ("dlp",)},
    "data_flow_detect": {"label": "Detect and record sensitive data leaving (DLP monitoring)", "domains": ("dlp",)},
    "isolation": {"label": "Isolate unknown web content from the endpoint", "domains": ("url_filtering",)},
    "software_restriction": {"label": "Prevent unauthorised software downloads and scripts", "domains": ("malware_threat",)},
}

# Every ZIA baseline rule (ops_zia_baseline.CATALOG key) and Advanced Threat
# Protection setting: its objective, or a reason code when it has none. A
# test fails when a catalog rule is missing here.
RULE_OBJECTIVES: Dict[str, Dict[str, str]] = {
    # Cloud Firewall
    "fw.geo_out": {"objective": "boundary_restrict"}, "fw.geo_in": {"objective": "boundary_restrict"},
    "fw.quic": {"objective": "encrypted_visibility", "why": "QUIC cannot be decrypted: blocking it makes browsers fall back to inspectable TLS."},
    "fw.allow_web": {"reason": "OPERATIONAL"}, "fw.allow_ntp": {"reason": "OPERATIONAL"},
    "fw.collab": {"reason": "OPERATIONAL"}, "fw.enterprise": {"reason": "OPERATIONAL"},
    "fw.p2p": {"objective": "least_functionality"}, "fw.tunnels": {"objective": "least_functionality"},
    "fw.default_deny": {"objective": "deny_by_default"},
    # URL filtering
    "url.legal": {"objective": "web_risk_block"}, "url.privacy": {"objective": "web_risk_block"},
    "url.security": {"objective": "web_risk_block"}, "url.security_global": {"objective": "web_risk_block"},
    "url.misc": {"objective": "isolation"},
    "url.bandwidth": {"reason": "NOT_IN_SCOPE_FOR_PROFILE"}, "url.productivity": {"reason": "NOT_IN_SCOPE_FOR_PROFILE"},
    "url.filehost_webmail": {"objective": "external_systems"},
    "url.new_domains": {"objective": "web_risk_block"},
    "url.remote_access": {"objective": "least_functionality"},
    "url.genai": {"objective": "external_systems"},
    "url.translation": {"objective": "data_flow_enforce", "why": "Text pasted into a public translation service flows to a system not authorised for it."},
    "url.p2p": {"objective": "least_functionality"},
    # SSL inspection
    "ssl.exempt_health": {"reason": "PRIVACY_EXCEPTION"}, "ssl.exempt_finance": {"reason": "PRIVACY_EXCEPTION"},
    "ssl.exempt_fhg": {"reason": "PRIVACY_EXCEPTION"},
    "ssl.catch_all": {"objective": "encrypted_visibility"},
    # Sandbox
    "sb.office_pdf": {"objective": "malicious_code"}, "sb.executables": {"objective": "malicious_code"}, "sb.archives": {"objective": "malicious_code"},
    # DNS Control
    "dns.tunnels_critical": {"objective": "protective_dns"}, "dns.tunnels_high": {"objective": "protective_dns"},
    "dns.doh": {"objective": "encrypted_dns"}, "dns.geo": {"objective": "protective_dns"}, "dns.resolver": {"objective": "protective_dns"},
    # File Type Control
    "ftc.db_upload": {"objective": "data_flow_enforce"},
    "ftc.pw_archives": {"objective": "encrypted_visibility", "why": "A password-protected archive cannot be inspected: blocking it keeps it from bypassing the flow controls."},
    "ftc.exe_download": {"objective": "software_restriction"}, "ftc.scripts": {"objective": "software_restriction"},
    # Cloud App Control
    "cac.fileshare_view": {"objective": "external_systems"}, "cac.social_view": {"objective": "public_posting"},
    "cac.genai_noupload": {"objective": "data_flow_enforce"}, "cac.slack_noupload": {"objective": "data_flow_enforce"},
    "cac.doh": {"objective": "encrypted_dns"}, "cac.fileshare": {"objective": "external_systems"},
    "cac.im": {"objective": "external_systems"}, "cac.social": {"objective": "public_posting"},
    "cac.webmail": {"objective": "external_systems"}, "cac.streaming": {"reason": "NOT_IN_SCOPE_FOR_PROFILE"},
    "cac.collab": {"objective": "external_systems"}, "cac.ai_ml": {"objective": "external_systems"},
    # Advanced Threat Protection settings (ops_zia_baseline.ATP_SETTINGS)
    "atp.cmd_ctl_server_blocked": {"objective": "boundary_monitoring"}, "atp.cmd_ctl_traffic_blocked": {"objective": "boundary_monitoring"},
    "atp.malware_sites_blocked": {"objective": "malicious_code"}, "atp.active_x_blocked": {"objective": "mobile_code"},
    "atp.browser_exploits_blocked": {"objective": "mobile_code"}, "atp.file_format_vunerabilites_blocked": {"objective": "malicious_code"},
    "atp.known_phishing_sites_blocked": {"objective": "spam_phishing"}, "atp.suspected_phishing_sites_blocked": {"objective": "spam_phishing"},
    "atp.suspect_adware_spyware_sites_blocked": {"objective": "malicious_code"}, "atp.ad_spyware_sites_blocked": {"objective": "malicious_code"},
    "atp.webspam_blocked": {"objective": "spam_phishing"}, "atp.crypto_mining_blocked": {"objective": "malicious_code"},
    "atp.irc_tunnelling_blocked": {"objective": "least_functionality"}, "atp.anonymizer_blocked": {"objective": "least_functionality"},
    "atp.cookie_stealing_blocked": {"objective": "malicious_code"}, "atp.potential_malicious_requests_blocked": {"objective": "malicious_code"},
    "atp.bit_torrent_blocked": {"objective": "least_functionality"}, "atp.tor_blocked": {"objective": "least_functionality"},
    "atp.ssh_tunnelling_blocked": {"objective": "least_functionality"}, "atp.dga_domains_blocked": {"objective": "protective_dns"},
}

# ---------------------------------------------------------------------------
# Controls. baseline: SP 800-53B membership (L, M, H) for 800-53 controls.
# ---------------------------------------------------------------------------


def _c(cid: str, title: str, source: str, baseline: str = "", assumed: str = "") -> Dict[str, Any]:
    return {"id": cid, "title": title, "source": source, "baseline": baseline, "assumed": bool(assumed), "assumed_why": assumed}


C53: Dict[str, Dict[str, Any]] = {c["id"]: c for c in (
    _c("AC-2", "Account Management", "sp80053", "L M H"),
    _c("AC-3", "Access Enforcement", "sp80053", "L M H"),
    _c("AC-4", "Information Flow Enforcement", "sp80053", "M H"),
    _c("AC-4(4)", "Information Flow Enforcement | Flow Control of Encrypted Information", "sp80053", "H"),
    _c("AC-6", "Least Privilege", "sp80053", "M H"),
    _c("AC-17", "Remote Access", "sp80053", "L M H"),
    _c("AC-19", "Access Control for Mobile Devices", "sp80053", "L M H"),
    _c("AC-20", "Use of External Systems", "sp80053", "L M H"),
    _c("AC-22", "Publicly Accessible Content", "sp80053", "L M H"),
    _c("AU-2", "Event Logging", "sp80053", "L M H"),
    _c("AU-6", "Audit Record Review, Analysis, and Reporting", "sp80053", "L M H"),
    _c("AU-12", "Audit Record Generation", "sp80053", "L M H"),
    _c("CM-2", "Baseline Configuration", "sp80053", "L M H"),
    _c("CM-6", "Configuration Settings", "sp80053", "L M H"),
    _c("CM-7", "Least Functionality", "sp80053", "L M H"),
    _c("CM-11", "User-installed Software", "sp80053", "L M H"),
    _c("IA-2", "Identification and Authentication (Organizational Users)", "sp80053", "L M H"),
    _c("IR-4", "Incident Handling", "sp80053", "L M H"),
    _c("IR-5", "Incident Monitoring", "sp80053", "L M H"),
    _c("IR-6", "Incident Reporting", "sp80053", "L M H"),
    _c("MP-7", "Media Use", "sp80053", "L M H"),
    _c("RA-3", "Risk Assessment", "sp80053", "L M H"),
    _c("SC-7", "Boundary Protection", "sp80053", "L M H"),
    _c("SC-7(5)", "Boundary Protection | Deny by Default — Allow by Exception", "sp80053", "M H"),
    _c("SC-18", "Mobile Code", "sp80053", "M H"),
    _c("SC-21", "Secure Name/Address Resolution Service (Recursive or Caching Resolver)", "sp80053", "L M H",
       assumed="SC-21 asks the resolver to verify the origin and integrity of answers (DNSSEC); whether the Zscaler Trusted Resolver "
               "validates DNSSEC is not confirmed here, so crediting the DNS redirect to SC-21 is assumed."),
    _c("SI-3", "Malicious Code Protection", "sp80053", "L M H"),
    _c("SI-4", "System Monitoring", "sp80053", "L M H"),
    _c("SI-4(4)", "System Monitoring | Inbound and Outbound Communications Traffic", "sp80053", "M H"),
    _c("SI-4(10)", "System Monitoring | Visibility of Encrypted Communications", "sp80053", "H"),
    _c("SI-8", "Spam Protection", "sp80053", "M H"),
)}

# NIST SP 800-171 Rev. 2 requirements as CMMC Level 2 practices (Level 1
# practices keep their L1 ids inside Level 2).
CMMC: Dict[str, Dict[str, Any]] = {c["id"]: c for c in (
    _c("AC.L1-3.1.1", "Authorized Access Control (SP 800-171 3.1.1)", "cmmc"),
    _c("AC.L2-3.1.3", "Control CUI Flow (SP 800-171 3.1.3)", "cmmc"),
    _c("AC.L2-3.1.5", "Least Privilege (SP 800-171 3.1.5)", "cmmc"),
    _c("AC.L2-3.1.7", "Privileged Functions (SP 800-171 3.1.7)", "cmmc"),
    _c("AC.L2-3.1.12", "Control Remote Access (SP 800-171 3.1.12)", "cmmc"),
    _c("AC.L2-3.1.14", "Remote Access Routing (SP 800-171 3.1.14)", "cmmc"),
    _c("AC.L1-3.1.20", "External Connections (SP 800-171 3.1.20)", "cmmc"),
    _c("AC.L1-3.1.22", "Control Public Information (SP 800-171 3.1.22)", "cmmc"),
    _c("AU.L2-3.3.1", "System Auditing (SP 800-171 3.3.1)", "cmmc"),
    _c("AU.L2-3.3.2", "User Accountability (SP 800-171 3.3.2)", "cmmc"),
    _c("AU.L2-3.3.5", "Audit Correlation (SP 800-171 3.3.5)", "cmmc"),
    _c("CM.L2-3.4.1", "System Baselining (SP 800-171 3.4.1)", "cmmc"),
    _c("CM.L2-3.4.2", "Security Configuration Enforcement (SP 800-171 3.4.2)", "cmmc"),
    _c("CM.L2-3.4.6", "Least Functionality (SP 800-171 3.4.6)", "cmmc"),
    _c("CM.L2-3.4.7", "Nonessential Functionality (SP 800-171 3.4.7)", "cmmc"),
    _c("CM.L2-3.4.8", "Application Execution Policy (SP 800-171 3.4.8)", "cmmc"),
    _c("CM.L2-3.4.9", "User-Installed Software (SP 800-171 3.4.9)", "cmmc"),
    _c("IA.L2-3.5.3", "Multifactor Authentication (SP 800-171 3.5.3)", "cmmc"),
    _c("IR.L2-3.6.1", "Incident Handling (SP 800-171 3.6.1)", "cmmc"),
    _c("IR.L2-3.6.2", "Incident Reporting (SP 800-171 3.6.2)", "cmmc"),
    _c("MP.L2-3.8.7", "Removable Media (SP 800-171 3.8.7)", "cmmc"),
    _c("MP.L2-3.8.8", "Shared Media (SP 800-171 3.8.8)", "cmmc"),
    _c("RA.L2-3.11.1", "Risk Assessments (SP 800-171 3.11.1)", "cmmc"),
    _c("SC.L1-3.13.1", "Boundary Protection (SP 800-171 3.13.1)", "cmmc"),
    _c("SC.L2-3.13.6", "Network Communication by Exception (SP 800-171 3.13.6)", "cmmc"),
    _c("SC.L2-3.13.13", "Mobile Code (SP 800-171 3.13.13)", "cmmc"),
    _c("SI.L1-3.14.2", "Malicious Code Protection (SP 800-171 3.14.2)", "cmmc"),
    _c("SI.L1-3.14.5", "System & File Scanning (SP 800-171 3.14.5)", "cmmc"),
    _c("SI.L2-3.14.6", "Monitor Communications for Attacks (SP 800-171 3.14.6)", "cmmc"),
    _c("SI.L2-3.14.7", "Identify Unauthorized Use (SP 800-171 3.14.7)", "cmmc"),
)}

# OMB M-22-09 section III actions (by pillar) and CISA ZTMM v2.0 functions.
_ZT_SECTION = ("The pillar letters follow M-22-09 section III (A Identity, B Devices, C Networks, D Applications and Workloads, E Data); "
               "the summary of each action is this app's, not a quotation.")
ZT: Dict[str, Dict[str, Any]] = {c["id"]: c for c in (
    _c("M-22-09 III.A", "Identity: agency-managed identities, phishing-resistant MFA", "m2209"),
    _c("M-22-09 III.B", "Devices: a complete inventory; detect and respond to incidents on devices", "m2209"),
    _c("M-22-09 III.C", "Networks: resolve DNS with encrypted DNS where supported; encrypt HTTP traffic; isolate environments", "m2209"),
    _c("M-22-09 III.E", "Data: categorise sensitive data; automate security monitoring and enforcement; log and share data access",
       "m2209", assumed="The Data actions are summarised from memory of the memorandum; check the wording against section III.E."),
    _c("ZTMM Identity", "Identity pillar: authentication and access management", "ztmm"),
    _c("ZTMM Devices: Policy Enforcement & Compliance Monitoring", "Devices pillar: Policy Enforcement & Compliance Monitoring", "ztmm"),
    _c("ZTMM Devices: Device Threat Protection", "Devices pillar: Device Threat Protection", "ztmm",
       assumed="Crediting web malware and phishing blocking to the Devices pillar's threat protection function is this app's reading."),
    _c("ZTMM Networks: Network Segmentation", "Networks pillar: Network Segmentation", "ztmm"),
    _c("ZTMM Networks: Network Traffic Management", "Networks pillar: Network Traffic Management", "ztmm"),
    _c("ZTMM Networks: Traffic Encryption", "Networks pillar: Traffic Encryption", "ztmm"),
    _c("ZTMM Networks: Visibility and Analytics", "Networks pillar: Visibility and Analytics capability", "ztmm"),
    _c("ZTMM Applications: Application Threat Protections", "Applications and Workloads pillar: Application Threat Protections", "ztmm",
       assumed="Crediting web content isolation to Application Threat Protections is this app's reading."),
    _c("ZTMM Data: Data Access", "Data pillar: Data Access", "ztmm"),
    _c("ZTMM Data: Visibility and Analytics", "Data pillar: Visibility and Analytics capability", "ztmm"),
    _c("ZTMM Cross-cutting: Automation and Orchestration", "Cross-cutting capability: Automation and Orchestration", "ztmm",
       assumed="Crediting incident response checks to Automation and Orchestration is this app's reading."),
)}
for _z in ZT.values():
    if _z["source"] == "m2209" and not _z["assumed"]:
        _z["note"] = _ZT_SECTION

IRS_STATUTE = _c("IRC 6103(p)(4)", "Safeguards an agency must keep to receive FTI (26 U.S.C. 6103(p)(4))", "irc6103")

# ---------------------------------------------------------------------------
# Objective -> controls per federal control set
# ---------------------------------------------------------------------------
MOD_MAP: Dict[str, List[str]] = {
    "web_risk_block": ["SC-7"], "malicious_code": ["SI-3"], "mobile_code": ["SC-18"], "spam_phishing": ["SI-8", "SI-3"],
    "deny_by_default": ["SC-7(5)"], "least_functionality": ["CM-7"], "boundary_restrict": ["SC-7"],
    "boundary_monitoring": ["SI-4", "SI-4(4)"], "encrypted_visibility": ["SI-4(4)"], "protective_dns": ["SC-7", "SC-21"],
    "encrypted_dns": ["SI-4(4)"], "external_systems": ["AC-20", "AC-4"], "public_posting": ["AC-22"], "data_flow_enforce": ["AC-4"],
    "data_flow_detect": ["SI-4(4)", "AU-12"], "isolation": ["SC-7"], "software_restriction": ["CM-11", "CM-7"],
}
HIGH_MAP = dict(MOD_MAP, encrypted_visibility=["SI-4(4)", "SI-4(10)", "AC-4(4)"])
DOMAIN_53: Dict[str, List[str]] = {
    "zpa_zero_trust": ["AC-3", "AC-6", "AC-17", "IA-2"], "identity_admin": ["AC-2", "AC-6", "IA-2"],
    "logging_monitoring": ["AU-2", "AU-6", "AU-12", "SI-4"], "incident_response": ["IR-4", "IR-5", "IR-6"],
    "device_compliance": ["CM-2", "CM-6", "CM-7"], "endpoint_dlp": ["MP-7", "AC-19"], "ai_governance": ["RA-3", "AC-4"],
}
CMMC_MAP: Dict[str, List[str]] = {
    "web_risk_block": ["SC.L1-3.13.1"], "malicious_code": ["SI.L1-3.14.2", "SI.L1-3.14.5"], "mobile_code": ["SC.L2-3.13.13"],
    "spam_phishing": ["SI.L1-3.14.2"], "deny_by_default": ["SC.L2-3.13.6"], "least_functionality": ["CM.L2-3.4.7", "CM.L2-3.4.6"],
    "boundary_restrict": ["SC.L1-3.13.1"], "boundary_monitoring": ["SI.L2-3.14.6"], "encrypted_visibility": ["SI.L2-3.14.6"],
    "protective_dns": ["SC.L1-3.13.1"], "encrypted_dns": ["SI.L2-3.14.6"], "external_systems": ["AC.L1-3.1.20"],
    "public_posting": ["AC.L1-3.1.22"], "data_flow_enforce": ["AC.L2-3.1.3"], "data_flow_detect": ["SI.L2-3.14.6", "SI.L2-3.14.7", "AU.L2-3.3.1"],
    "isolation": ["SC.L1-3.13.1"], "software_restriction": ["CM.L2-3.4.8", "CM.L2-3.4.9"],
}
DOMAIN_CMMC: Dict[str, List[str]] = {
    "zpa_zero_trust": ["AC.L1-3.1.1", "AC.L2-3.1.5", "AC.L2-3.1.12", "AC.L2-3.1.14", "IA.L2-3.5.3"],
    "identity_admin": ["AC.L2-3.1.5", "AC.L2-3.1.7", "IA.L2-3.5.3"],
    "logging_monitoring": ["AU.L2-3.3.1", "AU.L2-3.3.2", "AU.L2-3.3.5", "SI.L2-3.14.6"],
    "incident_response": ["IR.L2-3.6.1", "IR.L2-3.6.2"], "device_compliance": ["CM.L2-3.4.1", "CM.L2-3.4.2"],
    "endpoint_dlp": ["MP.L2-3.8.7", "MP.L2-3.8.8"], "ai_governance": ["RA.L2-3.11.1", "AC.L2-3.1.3"],
}
ZT_MAP: Dict[str, List[str]] = {
    "web_risk_block": ["ZTMM Networks: Network Traffic Management"],
    "malicious_code": ["ZTMM Devices: Device Threat Protection"], "mobile_code": ["ZTMM Devices: Device Threat Protection"],
    "spam_phishing": ["ZTMM Devices: Device Threat Protection"],
    "deny_by_default": ["ZTMM Networks: Network Traffic Management", "ZTMM Networks: Network Segmentation"],
    "least_functionality": ["ZTMM Networks: Network Traffic Management"], "boundary_restrict": ["ZTMM Networks: Network Traffic Management"],
    "boundary_monitoring": ["ZTMM Networks: Visibility and Analytics"], "encrypted_visibility": ["ZTMM Networks: Visibility and Analytics"],
    "protective_dns": ["M-22-09 III.C", "ZTMM Networks: Network Traffic Management"],
    "encrypted_dns": ["M-22-09 III.C", "ZTMM Networks: Traffic Encryption"],
    "external_systems": ["ZTMM Data: Data Access"], "public_posting": ["ZTMM Data: Data Access"],
    "data_flow_enforce": ["M-22-09 III.E", "ZTMM Data: Data Access"],
    "data_flow_detect": ["M-22-09 III.E", "ZTMM Data: Visibility and Analytics"],
    "isolation": ["ZTMM Applications: Application Threat Protections"],
    "software_restriction": ["ZTMM Devices: Policy Enforcement & Compliance Monitoring"],
}
DOMAIN_ZT: Dict[str, List[str]] = {
    "zpa_zero_trust": ["M-22-09 III.A", "ZTMM Identity", "ZTMM Networks: Network Segmentation"],
    "identity_admin": ["M-22-09 III.A", "ZTMM Identity"], "logging_monitoring": ["ZTMM Networks: Visibility and Analytics"],
    "device_compliance": ["M-22-09 III.B", "ZTMM Devices: Policy Enforcement & Compliance Monitoring"],
    "endpoint_dlp": ["ZTMM Data: Data Access"], "incident_response": ["ZTMM Cross-cutting: Automation and Orchestration"],
    "ai_governance": ["M-22-09 III.E"],
}
IRS_MAP = dict(MOD_MAP, data_flow_enforce=["AC-4", "IRC 6103(p)(4)"], data_flow_detect=["SI-4(4)", "AU-12", "IRC 6103(p)(4)"])

# Pub 1075 tailors the NIST SP 800-53 Rev. 5 controls with IRS parameters.
# The base controls of the Moderate baseline are taken as in Pub 1075; the
# enhancements below are not confirmed against the publication here.
_IRS_ENHANCEMENTS_UNVERIFIED = {"SI-4(4)", "SC-7(5)", "SC-18", "SI-8"}

# ---------------------------------------------------------------------------
# The profiles
# ---------------------------------------------------------------------------
FEDERAL = "federal"
FRAMEWORK = "framework"

PROFILES: Dict[str, Dict[str, Any]] = {
    "FEDRAMP_MOD": {
        "label": "FedRAMP Moderate", "kind": FEDERAL, "group": "Federal and public sector",
        "what": "Cloud services for federal agencies at the Moderate impact level: NIST SP 800-53 Rev. 5 controls of the SP 800-53B "
                "Moderate baseline.",
        "sources": ["sp80053", "sp80053b", "fedramp"], "control_set": "sp80053", "map": MOD_MAP, "domain_map": DOMAIN_53,
        "tier": "strict", "tier_why": "SC-7(5) (deny by default, allow by exception) is in the Moderate baseline; of the four tiers only Strict "
                                      "has the firewall default deny.",
        "overlay": "NIST_800_53",
        "require": {"fw.default_deny": "SC-7(5)"},
        "add": {},
        "packs": ["fed_policy_pack"], "aiguard": "NIST_800_53",
        "reuses": "The Strict tier's rules, unchanged apart from the rule it requires (the firewall default deny).",
    },
    "FEDRAMP_HIGH": {
        "label": "FedRAMP High", "kind": FEDERAL, "group": "Federal and public sector",
        "what": "Cloud services for federal agencies at the High impact level: the Moderate controls plus the High-only AC-4(4) (flow control "
                "of encrypted information) and SI-4(10) (visibility of encrypted communications).",
        "sources": ["sp80053", "sp80053b", "fedramp"], "control_set": "sp80053", "map": HIGH_MAP, "domain_map": DOMAIN_53,
        "tier": "strict", "tier_why": "SC-7(5) needs the firewall default deny, which only Strict has; AC-4(4) and SI-4(10) need all TLS "
                                      "inspected, which Strict does with no privacy exemptions.",
        "overlay": "NIST_800_53",
        "require": {"fw.default_deny": "SC-7(5)", "ssl.catch_all": "AC-4(4), SI-4(10)", "fw.quic": "AC-4(4)",
                    "ftc.pw_archives": "AC-4(4)"},
        "forbid": {"ssl.exempt_health": "AC-4(4)", "ssl.exempt_finance": "AC-4(4)", "ssl.exempt_fhg": "AC-4(4)"},
        "add": {},
        "packs": ["fed_policy_pack"], "aiguard": "NIST_800_53",
        "reuses": "The Strict tier's rules; the SSL catch-all, the QUIC block and the password-protected archive block are required "
                  "(AC-4(4): encrypted information must not bypass the flow controls), and the SSL privacy exemptions are left out.",
    },
    "CMMC_L2": {
        "label": "CMMC Level 2", "kind": FEDERAL, "group": "Federal and public sector",
        "what": "Defense contractors handling Controlled Unclassified Information (CUI): the 110 NIST SP 800-171 Rev. 2 requirements as "
                "CMMC Level 2 practices.",
        "sources": ["cmmc", "sp800171"], "control_set": "cmmc", "map": CMMC_MAP, "domain_map": DOMAIN_CMMC,
        "tier": "strict", "tier_why": "SC.L2-3.13.6 (network communication by exception) needs the firewall default deny, which only Strict has.",
        "overlay": "NIST_800_171",
        "require": {"fw.default_deny": "SC.L2-3.13.6"},
        "add": {"url.translation": {"action": "BLOCK", "control": "AC.L2-3.1.3",
                                    "why": "CUI pasted into a public translation service flows to a system not authorised for CUI (control CUI flow)."}},
        "packs": ["fed_policy_pack"], "aiguard": "NIST_800_171",
        "reuses": "The Strict tier's rules, plus a block of public translation services (AC.L2-3.1.3) and the required default deny.",
    },
    "FED_ZT": {
        "label": "Federal Zero Trust (OMB M-22-09 / CISA ZTMM)", "kind": FEDERAL, "group": "Federal and public sector",
        "what": "Federal civilian agencies moving to zero trust: OMB M-22-09 actions and the CISA Zero Trust Maturity Model v2.0 pillars "
                "and functions.",
        "sources": ["m2209", "ztmm"], "control_set": "zt", "map": ZT_MAP, "domain_map": DOMAIN_ZT,
        "tier": "strict", "tier_why": "Least privilege on the network (deny by default) and inspection of all traffic are only in Strict.",
        "overlay": "NIST_800_53",
        "require": {"fw.default_deny": "ZTMM Networks: Network Traffic Management", "dns.doh": "M-22-09 III.C",
                    "dns.resolver": "M-22-09 III.C"},
        "add": {},
        "packs": ["fed_policy_pack"], "aiguard": "NIST_800_53",
        "reuses": "The Strict tier's rules; the DNS over HTTPS inspection and the Trusted Resolver redirect are required (M-22-09's encrypted "
                  "DNS action keeps DNS encrypted, so it must reach a resolver the agency controls and be inspected).",
    },
    "IRS_1075": {
        "label": "IRS Publication 1075 (federal tax information)", "kind": FEDERAL, "group": "Federal and public sector",
        "what": "Agencies and contractors receiving federal tax information (FTI): the NIST SP 800-53 Rev. 5 controls as IRS Publication 1075 "
                "tailors them, and the safeguards of 26 U.S.C. 6103(p)(4).",
        "sources": ["pub1075", "irc6103", "sp80053"], "control_set": "irs", "map": IRS_MAP, "domain_map": DOMAIN_53,
        "tier": "strict", "tier_why": "Publication 1075 applies the Moderate baseline, whose SC-7(5) needs the default deny only Strict has.",
        "overlay": "NIST_800_53",
        "require": {"fw.default_deny": "SC-7(5)", "cac.webmail": "AC-20, IRC 6103(p)(4)"},
        "add": {"url.translation": {"action": "BLOCK", "control": "AC-4, IRC 6103(p)(4)",
                                    "why": "FTI pasted into a public translation service is disclosed to a party 26 U.S.C. 6103 does not authorise."}},
        "packs": ["irs_fti_pack", "zbp_enterprise_baseline"], "aiguard": "IRS_1075",
        "reuses": "The Strict tier's rules, plus a block of public translation services; the personal webmail block is required. The FTI "
                  "DLP pack adds the FTI markings dictionary.",
    },
    "GOVRAMP": {
        "label": "GovRAMP Moderate", "kind": FEDERAL, "group": "Federal and public sector",
        "what": "Cloud services for state and local governments: GovRAMP Moderate, built on the NIST SP 800-53 Rev. 5 Moderate baseline.",
        "sources": ["govramp", "sp80053", "sp80053b"], "control_set": "sp80053", "map": MOD_MAP, "domain_map": DOMAIN_53,
        "tier": "strict", "tier_why": "Reuses FedRAMP Moderate: SC-7(5) needs the default deny only Strict has.",
        "overlay": "NIST_800_53",
        "require": {"fw.default_deny": "SC-7(5)"},
        "add": {},
        "packs": ["zbp_enterprise_baseline"], "aiguard": "NIST_800_53",
        "reuses": "FedRAMP Moderate's rules and control catalogue unchanged: GovRAMP Moderate is taken as the SP 800-53 Rev. 5 Moderate "
                  "selection. Add the CJIS or FTI pack when the agency handles that data.",
        "assumed": "GovRAMP's own Moderate control list is not checked here; it is taken as the NIST SP 800-53B Moderate baseline.",
    },
}

# The framework profiles: the existing overlays as one choice.
_FW = {
    "HIPAA": ("HIPAA", "Healthcare", ["healthcare_phi_baseline"], "HIPAA"),
    "HITRUST": ("HITRUST CSF", "Healthcare", ["healthcare_phi_baseline"], "HITRUST"),
    "PCI": ("PCI DSS", "Financial services", ["global_banking_baseline"], "PCI"),
    "SOX": ("SOX", "Financial services", ["global_banking_baseline"], "SOX"),
    "FERPA": ("FERPA", "Education", ["zbp_enterprise_baseline"], "FERPA"),
    "CJIS": ("CJIS Security Policy", "Federal and public sector", ["cjis_policy_pack"], "CJIS"),
    "NIST_800_53": ("NIST SP 800-53", "Any industry", ["fed_policy_pack"], "NIST_800_53"),
    "NIST_800_171": ("NIST SP 800-171", "Any industry", ["fed_policy_pack"], "NIST_800_171"),
    "GDPR": ("GDPR", "Any industry", ["zbp_enterprise_baseline"], "GDPR"),
}
for _k, (_label, _group, _packs, _aig) in _FW.items():
    PROFILES[_k] = {"label": _label, "kind": FRAMEWORK, "group": _group,
                    "what": f"The {_label} overlay: cites the {_label} controls each baseline area supports. The tier stays your choice.",
                    "sources": [], "control_set": "overlay", "tier": None, "tier_why": "", "overlay": _k, "require": {}, "add": {},
                    "packs": _packs, "aiguard": _aig,
                    "reuses": "Whatever tier you pick, unchanged: the overlay adds the area-level controls and changes no rule."}

FEDERAL_KEYS = tuple(k for k, p in PROFILES.items() if p["kind"] == FEDERAL)
GROUP_ORDER = ("Federal and public sector", "Healthcare", "Financial services", "Education", "Any industry")


class ProfileError(ValueError):
    """An unknown compliance profile, or a rule this module cannot map."""


def get(key: Any) -> Optional[Dict[str, Any]]:
    k = str(key or "").strip().upper()
    return PROFILES.get(k)


def key_of(key: Any) -> str:
    """The profile key, or '' for none; ProfileError for an unknown key."""
    k = str(key or "").strip().upper()
    if not k:
        return ""
    if k not in PROFILES:
        raise ProfileError(f"Unknown compliance profile '{str(key)[:40]}'. Use one of: {', '.join(PROFILES)}.")
    return k


def _registry(profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    cs = profile["control_set"]
    if cs == "cmmc":
        return CMMC
    if cs == "zt":
        return ZT
    if cs == "irs":
        out = {}
        for cid, c in C53.items():
            x = dict(c, source="pub1075", also=["sp80053"])
            if cid in _IRS_ENHANCEMENTS_UNVERIFIED and not x["assumed"]:
                x["assumed"] = True
                x["assumed_why"] = "Not confirmed here that Publication 1075 selects this enhancement; it is in the SP 800-53B Moderate baseline."
            out[cid] = x
        out[IRS_STATUTE["id"]] = dict(IRS_STATUTE)
        return out
    return C53


def _source(sid: str) -> Dict[str, str]:
    return dict(SOURCES[sid], id=sid)


def control(profile_key: str, cid: str) -> Dict[str, Any]:
    p = PROFILES[profile_key]
    c = copy.deepcopy(_registry(p)[cid])
    if profile_key == "GOVRAMP" and not c["assumed"]:
        c["assumed"], c["assumed_why"] = True, PROFILES["GOVRAMP"]["assumed"]
    c["source_ref"] = _source(c["source"])
    return c


def controls(profile_key: str) -> List[Dict[str, Any]]:
    """The profile's control catalogue: every control a rule or an
    assessment area maps to, with its source and assumed flag."""
    p = PROFILES[profile_key]
    if p["control_set"] == "overlay":
        return _overlay_catalogue(profile_key)
    ids: List[str] = []
    for lst in list(p["map"].values()) + list(p["domain_map"].values()):
        for cid in lst:
            if cid not in ids:
                ids.append(cid)
    return [control(profile_key, cid) for cid in ids]


def _overlay_catalogue(profile_key: str) -> List[Dict[str, Any]]:
    import ops_zia_baseline as zb
    out: List[Dict[str, Any]] = []
    seen = set()
    domains = sorted({d for o in OBJECTIVES.values() for d in o["domains"]})
    for ov in zb.overlay_controls(domains, [PROFILES[profile_key]["overlay"]]):
        for cid in ov["controls"]:
            if cid not in seen:
                seen.add(cid)
                out.append({"id": cid, "title": "", "source": ov["source"]["id"], "source_ref": ov["source"], "baseline": "",
                            "assumed": False, "assumed_why": "", "area_level": True})
    return out


def objective_controls(profile_key: str, objective: str) -> List[Dict[str, Any]]:
    p = PROFILES[profile_key]
    if p["control_set"] == "overlay":
        import ops_zia_baseline as zb
        out = []
        for ov in zb.overlay_controls(list(OBJECTIVES[objective]["domains"]), [p["overlay"]]):
            out += [{"id": cid, "title": "", "source": ov["source"]["id"], "source_ref": ov["source"], "assumed": False,
                     "assumed_why": "", "area_level": True} for cid in ov["controls"]]
        return out
    return [control(profile_key, cid) for cid in p["map"].get(objective, [])]


# ---------------------------------------------------------------------------
# Mapping one rule
# ---------------------------------------------------------------------------
_ENFORCING = ("BLOCK", "DENY", "DECRYPT", "QUARANTINE", "ISOLATE", "REDIR")


def _acts(action: Any) -> List[str]:
    if isinstance(action, list):
        return [str(a or "") for a in action]
    if isinstance(action, dict):
        return [str(action.get("type") or "")]
    return [str(action or "")]


def _enforces(action: Any) -> bool:
    return any(a.startswith(_ENFORCING) for a in _acts(action))


def _caution_only(action: Any) -> bool:
    acts = _acts(action)
    return any(a.startswith("CAUTION") for a in acts) and not _enforces(action)


def map_rule(profile_key: str, key: str, *, action: Any = None, on: bool = True) -> Dict[str, Any]:
    """{objective, objective_label, controls, reason, reason_text} for a
    baseline rule (CATALOG key) or an ATP setting ('atp.<key>'), with the
    action it will carry. ProfileError for a rule with no entry."""
    entry = RULE_OBJECTIVES.get(key)
    if entry is None:
        raise ProfileError(f"The rule {key!r} has no objective and no reason code (compliance_profiles.RULE_OBJECTIVES).")
    return _finish_map(profile_key, entry.get("objective") or "", entry.get("reason") or "", action, on, entry.get("why") or "")


def _finish_map(profile_key: str, objective: str, reason: str, action: Any, on: bool, why: str = "") -> Dict[str, Any]:
    out = {"objective": objective, "objective_label": OBJECTIVES[objective]["label"] if objective else "", "controls": [],
           "reason": "", "reason_text": "", "why": why}
    if not on:
        reason = "NOT_CREATED"
    elif reason == "" and action is not None and not _enforces(action):
        reason = "CAUTION_ONLY" if _caution_only(action) else "ALLOWS_TRAFFIC"
    if reason:
        out["reason"], out["reason_text"] = reason, REASONS[reason]
        return out
    ctrls = objective_controls(profile_key, objective)
    if not ctrls:
        out["reason"], out["reason_text"] = "NOT_IN_SCOPE_FOR_PROFILE", REASONS["NOT_IN_SCOPE_FOR_PROFILE"]
        return out
    out["controls"] = ctrls
    return out


def pack_rule_objective(rule: Dict[str, Any]) -> str:
    """A DLP pack rule's objective: enforcement when it blocks, detection
    (monitor, report an incident) otherwise."""
    acts = _acts(rule.get("action"))
    return "data_flow_enforce" if any("BLOCK" in a or a.startswith("DENY") for a in acts) else "data_flow_detect"


def map_pack_rule(profile_key: str, rule: Dict[str, Any]) -> Dict[str, Any]:
    """A pack rule ships DISABLED: its controls are what it carries out once
    enabled (the export says so)."""
    return _finish_map(profile_key, pack_rule_objective(rule), "", "BLOCK", True)


# ---------------------------------------------------------------------------
# The profile applied to a baseline spec
# ---------------------------------------------------------------------------

def applies(profile_key: str, spec_tier: str) -> Dict[str, Any]:
    """What the profile changes in a baseline of `spec_tier`: rules it adds
    ({key: action}), rules it requires on ({key: control}), rules it
    leaves out ({key: control}) and a warning when the tier is not the
    profile's."""
    p = PROFILES[profile_key]
    warn = ""
    if p["tier"] and spec_tier and spec_tier != p["tier"] and spec_tier != "captured":
        warn = (f"{p['label']} builds on the {p['tier'].capitalize()} tier ({p['tier_why']}). This build uses {spec_tier.capitalize()}: "
                f"the rules {p['tier'].capitalize()} has and {spec_tier.capitalize()} lacks are not built, and their controls are not met.")
    return {"add": {k: v["action"] for k, v in p.get("add", {}).items()}, "add_why": {k: v for k, v in p.get("add", {}).items()},
            "require": dict(p.get("require", {})), "forbid": dict(p.get("forbid", {})), "tier_warning": warn}


def summary(profile_key: str) -> Dict[str, Any]:
    """What picking the profile does, in plain words and as data: the tier,
    the overlay, rule changes, the packs offered, the AI Guard profile and
    what the compliance pack holds."""
    import ai_guard as ag
    import ops_zia_baseline as zb
    p = PROFILES[profile_key]
    from dlp_importer import discover_packs
    have = {x["id"]: x.get("name") or x["id"] for x in discover_packs()}
    ap = ag.PROFILES.get(p["aiguard"], {})
    adds = [{"key": k, "title": zb.CATALOG_BY_KEY[k]["title"], "action": v["action"], "control": v["control"], "why": v["why"]}
            for k, v in p.get("add", {}).items()]
    req = [{"key": k, "title": zb.CATALOG_BY_KEY[k]["title"], "control": c} for k, c in p.get("require", {}).items()]
    forbid = [{"key": k, "title": zb.CATALOG_BY_KEY[k]["title"], "control": c} for k, c in p.get("forbid", {}).items()]
    lines = []
    if p["tier"]:
        lines.append(f"Baseline tier: {p['tier'].capitalize()}. {p['tier_why']}")
    else:
        lines.append("Baseline tier: unchanged (your choice).")
    lines.append(f"Overlay: {zb.OVERLAYS[p['overlay']]['label']} (each rule also shows the controls of this profile).")
    for a in adds:
        lines.append(f"Adds the rule {zb.CATALOG_BY_KEY[a['key']]['suffix']} ({a['action'].lower()}): {a['why']} ({a['control']}).")
    for r in req:
        lines.append(f"Requires {r['title']} (always on, {r['control']}).")
    for f in forbid:
        lines.append(f"Leaves out {f['title']} ({f['control']}).")
    packs = [{"id": pid, "name": have.get(pid, pid), "available": pid in have} for pid in p["packs"]]
    lines.append("DLP policy packs offered: " + ", ".join(x["name"] for x in packs) + ".")
    lines.append(f"AI Guard detection profile: {ap.get('name', p['aiguard'])} (Monitor by default).")
    lines.append("Compliance pack: control mapping report, policy export, test plan by control and synthetic DLP test files; "
                 "local files only, nothing is written to the tenant.")
    return {"key": profile_key, "label": p["label"], "kind": p["kind"], "group": p["group"], "what": p["what"],
            "sources": [_source(s) for s in p["sources"]], "tier": p["tier"], "tier_why": p["tier_why"], "overlay": p["overlay"],
            "adds": adds, "requires": req, "forbids": forbid, "packs": packs, "aiguard": p["aiguard"],
            "aiguard_name": ap.get("name", p["aiguard"]), "reuses": p["reuses"], "assumed_profile": p.get("assumed", ""),
            "lines": lines, "control_count": len(controls(profile_key)),
            "assumed_controls": [c["id"] for c in controls(profile_key) if c.get("assumed")]}


def catalog() -> Dict[str, Any]:
    """Every profile for a form, grouped; nothing read from a tenant."""
    rows = []
    for k, p in PROFILES.items():
        rows.append({"key": k, "label": p["label"], "kind": p["kind"], "group": p["group"], "what": p["what"], "tier": p["tier"],
                     "overlay": p["overlay"], "aiguard": p["aiguard"], "packs": list(p["packs"])})
    rows.sort(key=lambda r: (GROUP_ORDER.index(r["group"]) if r["group"] in GROUP_ORDER else 99, r["kind"] != FEDERAL))
    return {"profiles": rows, "groups": list(GROUP_ORDER), "reasons": REASONS,
            "objectives": {k: v["label"] for k, v in OBJECTIVES.items()}}


def assumed() -> List[Dict[str, str]]:
    """Every assumed control (and profile-level assumption), for the report."""
    out = []
    for k, p in PROFILES.items():
        if p["kind"] != FEDERAL:
            continue
        for c in controls(k):
            if c.get("assumed"):
                out.append({"profile": k, "control": c["id"], "why": c["assumed_why"]})
    return out


# ---------------------------------------------------------------------------
# Every rule mapped: baseline review rows, ATP settings and pack rules
# ---------------------------------------------------------------------------

def _pack_rules(pack_id: str) -> Tuple[str, List[Dict[str, Any]]]:
    from dlp_importer import discover_packs
    import pack_library
    pk = next((x for x in discover_packs() if x["id"] == pack_id), None)
    if not pk:
        return pack_id, []
    bundle = pack_library.pack_bundle(pk["dir"])
    return pk.get("name") or pack_id, list(bundle.get("policies") or [])


def mapping(profile_key: str, review: Optional[Dict[str, Any]] = None, *, packs: Optional[Sequence[str]] = None,
            include_atp: bool = True) -> Dict[str, Any]:
    """Every rule of the build mapped: the baseline's rules (from
    ops_zia_baseline.review), the ATP settings and each offered pack's DLP
    rules. Each row has controls or a reason code; ProfileError when one
    has neither (never returned silently)."""
    p = PROFILES[profile_key]
    rows: List[Dict[str, Any]] = []
    if review is not None:
        for r in review.get("rules") or []:
            m = map_rule(profile_key, r["key"], action=r["action"], on=r["on"]) if r["key"] in RULE_OBJECTIVES else \
                _finish_map(profile_key, "", "VENDOR_DEFAULT", r["action"], r["on"])   # a captured framework's own rule
            rows.append({"source": "ZIA baseline", "area": r["area_label"], "key": r["key"], "name": r["name"], "title": r["title"],
                         "action": r["action"], "on": r["on"], "created": r["on"], "state": "", **m,
                         "profile_note": r.get("profile_note", "")})
        if include_atp:
            for s in review.get("atp") or []:
                act = "BLOCK" if s["value"] else "ALLOW"
                m = map_rule(profile_key, "atp." + s["key"], action=act)
                rows.append({"source": "ZIA baseline", "area": "Advanced Threat Protection", "key": "atp." + s["key"], "name": s["label"],
                             "title": s["label"], "action": act, "on": True, "created": False, "state": "setting", **m, "profile_note": ""})
    for pid in (p["packs"] if packs is None else packs):
        pname, rules = _pack_rules(pid)
        for r in rules:
            m = map_pack_rule(profile_key, r)
            rows.append({"source": f"Policy pack: {pname}", "pack": pid, "area": f"DLP ({r.get('channel') or 'web'})", "key": f"{pid}:{r.get('name')}",
                         "name": r.get("name"), "title": r.get("description") or "", "action": r.get("action"), "on": True, "created": True,
                         "state": r.get("state") or "DISABLED", "engines": list(r.get("engines") or []), **m,
                         "profile_note": "Ships disabled and monitor-only: the controls apply once you enable it."})
    bad = [r["name"] for r in rows if not r["controls"] and not r["reason"]]
    if bad:
        raise ProfileError(f"Rules with neither a control nor a reason code: {', '.join(map(str, bad[:5]))}.")
    mapped = sum(1 for r in rows if r["controls"])
    return {"profile": profile_key, "label": p["label"], "rows": rows,
            "counts": {"rules": len(rows), "mapped": mapped, "reasoned": len(rows) - mapped,
                       "assumed": sum(1 for r in rows if any(c.get("assumed") for c in r["controls"]))}}


# ---------------------------------------------------------------------------
# An existing tenant's assessment read against a profile (Compliance page)
# ---------------------------------------------------------------------------

def _domains_for_check(check_id: str) -> List[str]:
    import compliance_mapping as cm
    out: List[str] = []
    for prefix, doms in cm.CHECK_DOMAIN_MAP.items():
        if str(check_id).startswith(prefix):
            for d in doms:
                if d not in out:
                    out.append(d)
    return out


def domain_controls(profile_key: str, domain: str) -> List[str]:
    p = PROFILES[profile_key]
    if p["control_set"] == "overlay":
        import ops_zia_baseline as zb
        return [c for ov in zb.overlay_controls([domain], [p["overlay"]]) for c in ov["controls"]]
    ids: List[str] = []
    for obj, o in OBJECTIVES.items():
        if domain in o["domains"]:
            for cid in p["map"].get(obj, []):
                if cid not in ids:
                    ids.append(cid)
    for cid in p["domain_map"].get(domain, []):
        if cid not in ids:
            ids.append(cid)
    return ids


MAX_RESULTS = 5000


def assessment_view(profile_key: str, results: Any) -> Dict[str, Any]:
    """Per control of the profile: Met / Partially met / Not met / Not
    tested from the assessment checks that back it, as the Compliance page
    does for its frameworks. Untrusted input: only id, status and label
    are read, each capped."""
    import channel_scope
    if not isinstance(results, list):
        raise ProfileError("results must be a list of assessment checks.")
    results = [r for r in results[:MAX_RESULTS] if isinstance(r, dict)]
    results, _ = channel_scope.visible(results)
    by_ctrl: Dict[str, List[Dict[str, str]]] = {}
    for r in results:
        cid = str(r.get("id") or "")[:40]
        st = str(r.get("status") or "")[:12].upper()
        for d in _domains_for_check(cid):
            for c in domain_controls(profile_key, d):
                lst = by_ctrl.setdefault(c, [])
                if not any(e["check_id"] == cid for e in lst):
                    lst.append({"check_id": cid, "status": st, "label": str(r.get("label") or "")[:200]})
    cat = {c["id"]: c for c in controls(profile_key)}
    rows = []
    for cid, ev in by_ctrl.items():
        p_ = sum(1 for e in ev if e["status"] == "PASS")
        f_ = sum(1 for e in ev if e["status"] == "FAIL")
        rv = sum(1 for e in ev if e["status"] == "REVIEW")
        scored = p_ + f_ + rv
        if not scored:
            status = "Not tested"
        elif not f_ and not rv:
            status = "Met"
        elif f_ and (not p_ or f_ > scored * 0.5):
            status = "Not met"
        else:
            status = "Partially met"
        c = cat.get(cid, {"id": cid, "title": "", "assumed": False, "assumed_why": ""})
        rows.append({"control": cid, "title": c.get("title", ""), "status": status, "assumed": bool(c.get("assumed")),
                     "assumed_why": c.get("assumed_why", ""), "passing": p_, "failing": f_, "review": rv,
                     "evidence": sorted(ev, key=lambda e: ({"FAIL": 0, "REVIEW": 1, "PASS": 2}.get(e["status"], 3), e["check_id"]))[:50]})
    order = {"Not met": 0, "Partially met": 1, "Met": 2, "Not tested": 3}
    rows.sort(key=lambda x: (order[x["status"]], x["control"]))
    not_backed = [c for c in cat if c not in by_ctrl]
    return {"profile": profile_key, "label": PROFILES[profile_key]["label"], "controls": rows,
            "counts": {k: sum(1 for x in rows if x["status"] == k) for k in order},
            "not_assessed": not_backed,
            "note": "Read from this assessment's checks, mapped through each check's control areas to the profile's controls. A control "
                    "the checks do not reach is listed as not assessed, not as met."}


__all__ = ["PROFILES", "SOURCES", "REASONS", "OBJECTIVES", "RULE_OBJECTIVES", "catalog", "summary", "mapping", "map_rule",
           "map_pack_rule", "applies", "controls", "assumed", "assessment_view", "get", "key_of", "ProfileError", "FEDERAL_KEYS"]
