"""The vertical a tenant profile belongs to decides what the app suggests.

A tenant profile carries an industry and the policy packs that apply. This
module turns that into a scope: which compliance frameworks to show,
which packs to measure the journey against and to offer first, and a
one-line reason. Anything outside the scope is not hidden for good, only
folded away: the operator can always widen it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

INDUSTRIES = ["Healthcare", "Federal", "State & local government", "Law enforcement (CJIS)", "Financial services",
              "Education", "Manufacturing", "Technology", "Other"]

# Frameworks per industry, most relevant first. Keys are compliance_mapping keys.
INDUSTRY_FRAMEWORKS: Dict[str, List[str]] = {
    "Healthcare": ["HIPAA", "NIST_CSF_2", "SOC_2", "NIST_800_53"],
    "Federal": ["NIST_800_53", "NIST_800_171", "CMMC_L2", "NIST_CSF_2"],
    "State & local government": ["NIST_800_53", "NIST_CSF_2", "CIS", "NIST_800_171"],
    "Law enforcement (CJIS)": ["NIST_800_53", "NIST_CSF_2", "CIS"],
    "Financial services": ["PCI_DSS", "GLBA", "SOC_2", "GDPR", "ISO_27001"],
    "Education": ["NIST_CSF_2", "CIS", "SOC_2"],
    "Manufacturing": ["NIST_CSF_2", "ISO_27001", "NIST_800_171", "CIS"],
    "Technology": ["SOC_2", "ISO_27001", "GDPR", "NIST_CSF_2"],
}

# Policy packs per industry, the one to start with first.
INDUSTRY_PACKS: Dict[str, List[str]] = {
    "Healthcare": ["healthcare_phi_baseline", "zbp_enterprise_baseline"],
    "Federal": ["fed_policy_pack"],
    "State & local government": ["fed_policy_pack", "cjis_policy_pack"],
    "Law enforcement (CJIS)": ["cjis_policy_pack"],
    "Financial services": ["global_banking_baseline", "zbp_enterprise_baseline"],
    "Education": ["zbp_enterprise_baseline"],
    "Manufacturing": ["zbp_enterprise_baseline", "zbp_source_code_baseline"],
    "Technology": ["zbp_enterprise_baseline", "zbp_source_code_baseline"],
}

REASON = {
    "Healthcare": "HIPAA covered entities and business associates: PHI detection, breach-notification tiers, HIPAA and NIST CSF controls.",
    "Federal": "Federal agencies and the defense industrial base: CUI, FOUO, ITAR; NIST SP 800-53 / 800-171 and CMMC controls.",
    "State & local government": "State and local agencies handling federal data and criminal-justice information.",
    "Law enforcement (CJIS)": "Agencies handling Criminal Justice Information under the CJIS Security Policy.",
    "Financial services": "Banks, issuers and processors: cardholder data, payment instructions, customer PII; PCI DSS and GLBA controls.",
    "Education": "Institutions handling student and staff PII with limited compliance mandates.",
    "Manufacturing": "Design data, ITAR-controlled technical data and source code alongside corporate PII.",
    "Technology": "Source code, customer data and credentials; SOC 2 and ISO 27001 attestations.",
}


def normalize_industry(industry: Any) -> str:
    s = str(industry or "").strip()
    for i in INDUSTRIES:
        if i.lower() == s.lower():
            return i
    low = s.lower()
    if "health" in low or "hipaa" in low or "hospital" in low:
        return "Healthcare"
    if "cjis" in low or "police" in low or "law enforcement" in low:
        return "Law enforcement (CJIS)"
    if "fed" in low or "dod" in low or "defense" in low:
        return "Federal"
    if "bank" in low or "financ" in low or "insurance" in low or "payment" in low:
        return "Financial services"
    if "state" in low or "local" in low or "municipal" in low or "county" in low:
        return "State & local government"
    if "educat" in low or "school" in low or "universit" in low:
        return "Education"
    if "manufact" in low:
        return "Manufacturing"
    if "tech" in low or "software" in low or "saas" in low:
        return "Technology"
    return "Other" if s else ""


def scope_for(profile: Optional[Dict[str, Any]], *, all_frameworks: Optional[List[str]] = None,
              all_packs: Optional[List[str]] = None) -> Dict[str, Any]:
    """{industry, frameworks, packs, packs_from, reason, scoped}. With no
    industry (or Other) nothing is narrowed: every framework and pack."""
    industry = normalize_industry((profile or {}).get("industry"))
    chosen_packs = [str(p) for p in ((profile or {}).get("baseline_packs") or []) if p]
    frameworks = list(INDUSTRY_FRAMEWORKS.get(industry) or [])
    packs = chosen_packs or list(INDUSTRY_PACKS.get(industry) or [])
    if all_frameworks is not None:
        frameworks = [f for f in frameworks if f in all_frameworks] or (list(all_frameworks) if not industry or industry == "Other" else frameworks)
    if all_packs is not None:
        packs = [p for p in packs if p in all_packs] or (list(all_packs) if not industry or industry == "Other" else packs)
    scoped = bool(industry and industry != "Other")
    return {"industry": industry, "frameworks": frameworks, "packs": packs, "packs_from": "profile" if chosen_packs else ("industry" if scoped else "all"),
            "reason": REASON.get(industry, "No industry on the profile: every framework and pack is shown."), "scoped": scoped}
