#!/usr/bin/env python3
"""
Zscaler Configuration → Compliance Framework Mapping
======================================================
Maps each assessment check (DLP, ZIA, ZPA, ZCC, GenAI) to the relevant
controls in major regulatory and compliance frameworks.

Frameworks covered:
  - NIST SP 800-53 Rev 5 (Federal security controls)
  - NIST SP 800-171 Rev 3 (CUI / DFARS)
  - SOC 2 (AICPA Trust Services Criteria)
  - GDPR (EU General Data Protection Regulation)
  - HIPAA (Health Insurance Portability and Accountability Act)
  - PCI-DSS v4.0 (Payment Card Industry)
  - ISO/IEC 27001:2022 (Information Security Management)
  - CIS Controls v8 (Center for Internet Security)

Mapping is based on Zscaler-published compliance documentation and
common control alignment patterns. Each check ID maps to a list of
control identifiers across frameworks.

Usage:
    from compliance_mapping import get_compliance_for_check, get_framework_summary
    controls = get_compliance_for_check("4.1")
    summary = get_framework_summary(results)  # results from an assessment
"""

# Control families that broadly apply to Zscaler's security capabilities
FRAMEWORK_DESCRIPTIONS = {
    "NIST_800_53": "NIST SP 800-53 Rev 5 — Security and Privacy Controls for Federal Information Systems",
    "NIST_800_171": "NIST SP 800-171 Rev 3 — Protecting Controlled Unclassified Information (CUI)",
    "SOC_2": "SOC 2 — AICPA Trust Services Criteria (Security, Availability, Confidentiality, Processing Integrity, Privacy)",
    "GDPR": "EU General Data Protection Regulation (Regulation 2016/679)",
    "HIPAA": "Health Insurance Portability and Accountability Act — Security Rule (45 CFR Part 164 Subpart C)",
    "PCI_DSS": "PCI-DSS v4.0 — Payment Card Industry Data Security Standard",
    "ISO_27001": "ISO/IEC 27001:2022 — Information Security Management Systems",
    "CIS": "CIS Controls v8 — Center for Internet Security",
}

# Mapping of check categories to compliance controls
# Format: {control_pattern_keyword: {framework: [control_ids]}}
CONTROL_DOMAINS = {
    "ssl_inspection": {
        "NIST_800_53": ["SC-8 (Transmission Confidentiality)", "SC-13 (Cryptographic Protection)", "SI-4 (System Monitoring)"],
        "NIST_800_171": ["3.13.8 (Cryptographic Protection)", "3.13.11 (Cryptographic Mechanisms)", "3.14.6 (System Monitoring)"],
        "SOC_2": ["CC6.1 (Logical Access Controls)", "CC6.7 (Restrict Movement of Information)", "CC7.2 (System Monitoring)"],
        "GDPR": ["Art. 32 (Security of Processing)", "Art. 5(1)(f) (Integrity & Confidentiality)"],
        "HIPAA": ["§164.312(e)(1) (Transmission Security)", "§164.312(e)(2)(ii) (Encryption)"],
        "PCI_DSS": ["4.2.1 (Strong Cryptography in Transit)", "11.5.1 (Intrusion Detection)"],
        "ISO_27001": ["A.5.10 (Acceptable Use)", "A.8.20 (Networks Security)", "A.8.24 (Use of Cryptography)"],
        "CIS": ["13.10 (Encrypt Sensitive Data in Transit)", "13.6 (Collect Network Traffic Flow Logs)"],
    },
    "dlp": {
        "NIST_800_53": ["AC-4 (Information Flow Enforcement)", "SC-7 (Boundary Protection)", "MP-5 (Media Transport)", "AU-12 (Audit Generation)"],
        "NIST_800_171": ["3.1.3 (Information Flow Control)", "3.1.20 (External Connections)", "3.13.1 (Boundary Protection)"],
        "SOC_2": ["CC6.7 (Restrict Movement of Information)", "C1.1 (Confidential Information)", "P4.1 (Use, Retention, Disposal)"],
        "GDPR": ["Art. 5(1)(f) (Integrity & Confidentiality)", "Art. 32 (Security of Processing)", "Art. 25 (Privacy by Design)"],
        "HIPAA": ["§164.308(a)(4) (Information Access Management)", "§164.312(b) (Audit Controls)", "§164.312(c) (Integrity)"],
        "PCI_DSS": ["3.5 (Protect Stored PAN)", "4.2 (PAN in Transit)", "10.2 (Audit Logs)"],
        "ISO_27001": ["A.5.34 (Privacy & PII Protection)", "A.8.12 (Data Leakage Prevention)", "A.8.10 (Information Deletion)"],
        "CIS": ["3.13 (Deploy DLP)", "3.3 (Configure Data Access Control Lists)"],
    },
    "url_filtering": {
        "NIST_800_53": ["AC-4 (Information Flow Enforcement)", "SC-7 (Boundary Protection)", "SC-7(8) (Route Traffic to Authenticated Proxy)"],
        "NIST_800_171": ["3.1.3 (Information Flow Control)", "3.1.20 (External System Connections)", "3.13.1 (Boundary Protection)"],
        "SOC_2": ["CC6.6 (Logical Access)", "CC6.8 (Prevent/Detect Unauthorized Software)"],
        "GDPR": ["Art. 32 (Security of Processing)"],
        "HIPAA": ["§164.308(a)(4) (Information Access Management)"],
        "PCI_DSS": ["1.4 (Network Security Controls)", "5.4 (Anti-Phishing)"],
        "ISO_27001": ["A.8.20 (Networks Security)", "A.8.21 (Security of Network Services)", "A.8.22 (Web Filtering)"],
        "CIS": ["9.3 (Maintain and Enforce Network-Based URL Filters)"],
    },
    "firewall": {
        "NIST_800_53": ["SC-7 (Boundary Protection)", "AC-4 (Information Flow Enforcement)", "CA-3 (System Interconnections)"],
        "NIST_800_171": ["3.13.1 (Boundary Protection)", "3.13.5 (Public-Access System Components)", "3.13.6 (Deny Network Communications by Default)"],
        "SOC_2": ["CC6.6 (Logical Access)", "CC6.7 (Restrict Information Movement)"],
        "GDPR": ["Art. 32 (Security of Processing)"],
        "HIPAA": ["§164.312(e)(1) (Transmission Security)"],
        "PCI_DSS": ["1.2 (Network Security Configuration)", "1.3 (Network Access Configuration)", "1.4 (Network Security Controls)"],
        "ISO_27001": ["A.8.20 (Networks Security)", "A.8.22 (Segregation in Networks)"],
        "CIS": ["12.2 (Establish and Maintain Network Architecture)", "13.4 (Perform Traffic Filtering Between Network Segments)"],
    },
    "zpa_zero_trust": {
        "NIST_800_53": ["AC-3 (Access Enforcement)", "AC-6 (Least Privilege)", "AC-17 (Remote Access)", "IA-2 (Identification)"],
        "NIST_800_171": ["3.1.1 (Limit Access)", "3.1.2 (Limit Transactions)", "3.1.12 (Monitor Remote Access)", "3.5.3 (Multifactor)"],
        "SOC_2": ["CC6.1 (Logical Access)", "CC6.2 (User Provisioning)", "CC6.3 (Authorization)", "CC6.6 (Logical Access)"],
        "GDPR": ["Art. 32 (Security of Processing)", "Art. 5(1)(c) (Data Minimisation)"],
        "HIPAA": ["§164.308(a)(3) (Workforce Security)", "§164.308(a)(4) (Information Access Management)", "§164.312(a)(1) (Access Control)"],
        "PCI_DSS": ["7.2 (Define Access Needs)", "7.3 (Restrict Access)", "8.3 (Strong Authentication)"],
        "ISO_27001": ["A.5.15 (Access Control)", "A.5.18 (Access Rights)", "A.8.2 (Privileged Access Rights)"],
        "CIS": ["6.7 (Centralize Access Control)", "6.8 (Define and Maintain Role-Based Access Control)", "12.7 (Ensure Remote Devices Use VPN/ZTNA)"],
    },
    "logging_monitoring": {
        "NIST_800_53": ["AU-2 (Audit Events)", "AU-3 (Audit Records Content)", "AU-6 (Audit Review)", "AU-12 (Audit Generation)", "SI-4 (System Monitoring)"],
        "NIST_800_171": ["3.3.1 (Audit Logs)", "3.3.2 (Audit Reduction)", "3.3.5 (Correlate Audit Records)", "3.14.6 (System Monitoring)"],
        "SOC_2": ["CC4.1 (Monitoring Activities)", "CC7.1 (System Monitoring)", "CC7.2 (Anomaly Detection)", "CC7.3 (Incident Response)"],
        "GDPR": ["Art. 30 (Records of Processing)", "Art. 33 (Breach Notification)"],
        "HIPAA": ["§164.308(a)(1)(ii)(D) (Information System Activity Review)", "§164.312(b) (Audit Controls)"],
        "PCI_DSS": ["10.2 (Audit Logs)", "10.5 (Log Retention 1 Year)", "10.7 (Time Synchronization)"],
        "ISO_27001": ["A.8.15 (Logging)", "A.8.16 (Monitoring Activities)", "A.5.25 (Assessment of Information Security Events)"],
        "CIS": ["8.1 (Establish Audit Log Management)", "8.5 (Collect Detailed Audit Logs)", "8.10 (Retain Audit Logs)"],
    },
    "endpoint_dlp": {
        "NIST_800_53": ["MP-5 (Media Transport)", "MP-7 (Media Use)", "AC-19 (Mobile Device Access Control)", "SC-7 (Boundary Protection)"],
        "NIST_800_171": ["3.8.7 (Removable Media)", "3.8.8 (Removable Media Use)", "3.13.1 (Boundary Protection)"],
        "SOC_2": ["CC6.7 (Restrict Movement)", "CC6.8 (Prevent Unauthorized Software)", "C1.1 (Confidential Information)"],
        "GDPR": ["Art. 32 (Security of Processing)"],
        "HIPAA": ["§164.310(d) (Device and Media Controls)", "§164.310(d)(1) (Disposal)"],
        "PCI_DSS": ["3.5 (Protect Stored PAN)", "9.7 (Removable Media)"],
        "ISO_27001": ["A.8.7 (Protection Against Malware)", "A.8.9 (Configuration Management)", "A.8.12 (Data Leakage)"],
        "CIS": ["3.6 (Encrypt Data on End-User Devices)", "10.5 (Enable Anti-Exploitation)"],
    },
    "malware_threat": {
        "NIST_800_53": ["SI-3 (Malicious Code Protection)", "SI-4 (System Monitoring)", "SI-7 (Software Integrity)"],
        "NIST_800_171": ["3.14.1 (Flaw Remediation)", "3.14.2 (Malicious Code Protection)", "3.14.4 (Update Malicious Code Protection)"],
        "SOC_2": ["CC6.8 (Prevent Unauthorized Software)", "CC7.2 (Anomaly Detection)"],
        "GDPR": ["Art. 32 (Security of Processing)"],
        "HIPAA": ["§164.308(a)(5)(ii)(B) (Protection from Malicious Software)"],
        "PCI_DSS": ["5.2 (Anti-Malware Mechanisms)", "5.3 (Protection from Malware)", "5.4 (Anti-Phishing)"],
        "ISO_27001": ["A.8.7 (Protection Against Malware)"],
        "CIS": ["10.1 (Deploy Anti-Malware)", "10.2 (Centrally Manage Anti-Malware)", "10.7 (Anti-Phishing)"],
    },
    "identity_admin": {
        "NIST_800_53": ["AC-2 (Account Management)", "AC-5 (Separation of Duties)", "AC-6 (Least Privilege)", "IA-2 (Identification)"],
        "NIST_800_171": ["3.1.4 (Separation of Duties)", "3.1.5 (Least Privilege)", "3.1.6 (Non-Privileged Accounts for Non-Security Functions)"],
        "SOC_2": ["CC6.1 (Logical Access)", "CC6.2 (User Provisioning)", "CC6.3 (Authorization)"],
        "GDPR": ["Art. 32 (Security of Processing)", "Art. 25 (Privacy by Design)"],
        "HIPAA": ["§164.308(a)(3) (Workforce Security)", "§164.308(a)(4) (Information Access Management)"],
        "PCI_DSS": ["7.1 (Access Control)", "7.2 (Define Access Needs)", "8.2 (Identify Users)"],
        "ISO_27001": ["A.5.16 (Identity Management)", "A.5.18 (Access Rights)", "A.8.2 (Privileged Access)"],
        "CIS": ["5.1 (Establish Account Management Process)", "6.7 (Centralize Access Control)"],
    },
    "incident_response": {
        "NIST_800_53": ["IR-4 (Incident Handling)", "IR-5 (Incident Monitoring)", "IR-6 (Incident Reporting)", "IR-7 (Incident Response Assistance)"],
        "NIST_800_171": ["3.6.1 (Incident Handling Capability)", "3.6.2 (Track, Document, Report Incidents)", "3.6.3 (Test Incident Response)"],
        "SOC_2": ["CC7.3 (Incident Response)", "CC7.4 (Incident Recovery)", "CC7.5 (Recovery Procedures)"],
        "GDPR": ["Art. 33 (Breach Notification 72hr)", "Art. 34 (Communication to Data Subject)"],
        "HIPAA": ["§164.308(a)(6) (Security Incident Procedures)"],
        "PCI_DSS": ["12.10 (Incident Response Plan)", "12.10.1 (Incident Response Procedures)"],
        "ISO_27001": ["A.5.24 (Incident Management Planning)", "A.5.25 (Event Assessment)", "A.5.26 (Incident Response)"],
        "CIS": ["17.1 (Designate Incident Response Personnel)", "17.4 (Establish Incident Response Plans)"],
    },
    "ai_governance": {
        "NIST_800_53": ["RA-3 (Risk Assessment)", "PM-9 (Risk Management Strategy)", "AC-4 (Information Flow)", "SI-7 (Software Integrity)"],
        "NIST_800_171": ["3.1.3 (Information Flow Control)", "3.11.1 (Risk Assessment)"],
        "SOC_2": ["CC3.1 (Risk Identification)", "CC3.2 (Risk Assessment)", "C1.1 (Confidential Information)"],
        "GDPR": ["Art. 22 (Automated Decision-Making)", "Art. 25 (Privacy by Design)", "Art. 35 (Data Protection Impact Assessment)"],
        "HIPAA": ["§164.308(a)(1)(ii)(A) (Risk Analysis)", "§164.308(a)(8) (Evaluation)"],
        "PCI_DSS": ["12.3.1 (Risk Assessment for Critical Technologies)"],
        "ISO_27001": ["A.5.7 (Threat Intelligence)", "A.5.34 (PII Protection)", "A.8.27 (Secure System Architecture)"],
        "CIS": ["3.1 (Establish Data Management Process)", "3.13 (Deploy DLP)"],
        "_FRAMEWORK_NOTE": "EU AI Act, NIST AI RMF, and OWASP LLM Top 10 also apply specifically to GenAI controls.",
    },
    "device_compliance": {
        "NIST_800_53": ["CM-2 (Baseline Configuration)", "CM-7 (Least Functionality)", "AC-19 (Mobile Devices)", "SI-4 (Monitoring)"],
        "NIST_800_171": ["3.4.1 (Baseline Configuration)", "3.4.6 (Least Functionality)", "3.7.5 (Monitor Maintenance)"],
        "SOC_2": ["CC6.8 (Prevent Unauthorized Software)", "CC7.1 (System Monitoring)"],
        "GDPR": ["Art. 32 (Security of Processing)"],
        "HIPAA": ["§164.310(c) (Workstation Security)", "§164.310(d) (Device Controls)"],
        "PCI_DSS": ["1.4.5 (NSC for User Devices)", "8.4 (MFA for All Access)"],
        "ISO_27001": ["A.8.1 (User Endpoint Devices)", "A.5.9 (Inventory)", "A.8.9 (Configuration Management)"],
        "CIS": ["1.1 (Establish Device Inventory)", "4.1 (Establish Secure Configuration Process)"],
    },
}

# Map check ID prefixes/keywords to their primary control domains
# Each check can map to multiple domains
CHECK_DOMAIN_MAP = {
    # DLP checks (1.x — 12.x, A.x, B.x, E.x, MC.x)
    "ssl": ["ssl_inspection"],          # checks with "SSL" in section
    "4.": ["ssl_inspection"],
    "7.": ["ssl_inspection"],
    "5.": ["dlp", "endpoint_dlp"],      # Endpoint DLP section
    "MC.": ["dlp"],
    "A.": ["dlp", "url_filtering"],
    "B.": ["endpoint_dlp"],
    "E.": ["ai_governance", "dlp"],
    "12.": ["incident_response", "logging_monitoring"],
    "1.": ["device_compliance", "endpoint_dlp"],
    "2.": ["url_filtering"],
    "3.": ["endpoint_dlp"],
    "6.": ["device_compliance"],
    "8.": ["dlp", "endpoint_dlp"],
    "9.": ["logging_monitoring"],
    "10.": ["device_compliance"],
    # Platform checks
    "FW.": ["firewall"],
    "UF.": ["url_filtering"],
    "SEC.": ["malware_threat"],
    "BW.": ["firewall"],
    "LOC.": ["firewall", "device_compliance"],
    "USR.": ["identity_admin", "logging_monitoring"],
    "CA.": ["url_filtering", "dlp"],
    "ZPA.": ["zpa_zero_trust"],
    "ZCC.": ["device_compliance", "endpoint_dlp"],
    # GenAI checks
    "AI.": ["ai_governance", "dlp"],
}


def get_compliance_for_check(check_id: str) -> dict:
    """
    Get the compliance mapping for a single check.
    Returns: { "NIST_800_53": [...], "GDPR": [...], ... }
    """
    domains = []
    for prefix, mapped_domains in CHECK_DOMAIN_MAP.items():
        if check_id.startswith(prefix):
            for d in mapped_domains:
                if d not in domains:
                    domains.append(d)

    if not domains:
        return {}

    # Combine controls from all matching domains
    out = {}
    for d in domains:
        ctrls = CONTROL_DOMAINS.get(d, {})
        for fw, controls in ctrls.items():
            if fw.startswith("_"):
                continue
            existing = out.setdefault(fw, [])
            for c in controls:
                if c not in existing:
                    existing.append(c)
    return out


def get_framework_summary(results: list) -> dict:
    """
    Summarize compliance posture across all assessment results.

    Returns:
      {
        "NIST_800_53": {
            "controls_addressed": [...],
            "covered_count": N,
            "passing_count": N,
            "failing_count": N,
            "status": "Aligned" | "Partial" | "Gaps"
        },
        ...
      }
    """
    fw_status = {}

    for r in results:
        cid = r.get("id", "")
        status = r.get("status", "")
        mapping = get_compliance_for_check(cid)

        for fw, controls in mapping.items():
            data = fw_status.setdefault(fw, {
                "controls_addressed": set(),
                "covered_count": 0,
                "passing_count": 0,
                "failing_count": 0,
                "review_count": 0,
                "info_count": 0,
            })
            for c in controls:
                data["controls_addressed"].add(c)
            data["covered_count"] += 1
            if status == "PASS":
                data["passing_count"] += 1
            elif status == "FAIL":
                data["failing_count"] += 1
            elif status == "REVIEW":
                data["review_count"] += 1
            else:
                data["info_count"] += 1

    # Convert sets to sorted lists, compute status
    out = {}
    for fw, data in fw_status.items():
        scored = data["covered_count"] - data["info_count"]
        passing = data["passing_count"]
        failing = data["failing_count"]
        if failing > scored * 0.25:
            status = "Gaps"
        elif passing >= scored * 0.75 and failing == 0:
            status = "Aligned"
        else:
            status = "Partial"
        out[fw] = {
            "framework": fw,
            "name": FRAMEWORK_DESCRIPTIONS.get(fw, fw),
            "controls_addressed": sorted(data["controls_addressed"]),
            "control_count": len(data["controls_addressed"]),
            "covered_count": data["covered_count"],
            "passing_count": passing,
            "failing_count": failing,
            "review_count": data["review_count"],
            "info_count": data["info_count"],
            "status": status,
            "alignment_pct": round(passing / scored * 100) if scored else 100,
        }
    return out


def list_supported_frameworks() -> list:
    """Return list of supported compliance frameworks."""
    return [{"key": k, "name": v} for k, v in FRAMEWORK_DESCRIPTIONS.items()]
