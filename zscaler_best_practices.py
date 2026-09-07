#!/usr/bin/env python3
"""
Curated Zscaler Best-Practices + Leading-Practices reference list.

Scope now spans MULTIPLE sources, each with a credibility tier from
bp_sources.py:

  - help.zscaler.com           Tier 1 Official      (credibility 100)
  - www.zscaler.com/blogs      Tier 1 Official      (credibility 100)
  - developer.zscaler.com      Tier 1 Official      (credibility 100)
  - github.com/zscaler          Tier 1 Official      (credibility 100)
  - registry.terraform.io       Tier 2 Authoritative (credibility  80)
  - learn.microsoft.com         Tier 2 Authoritative (credibility  80)
  - docs.aws.amazon.com         Tier 2 Authoritative (credibility  80)
  - community.zscaler.com       Tier 3 Community     (credibility  60)

Each entry carries:
  key         unique identifier
  service     ZIA | ZPA | ZCC | ZDX | ZIdentity | Deception | Deployment | Other
  title       display title
  url         canonical URL
  topics      keyword list used by lookup_by_topic()
  source      source id from bp_sources.SOURCES
  credibility integer 0-100 (inherits from the source)

This is the authoritative source the rest of the app uses when it needs
to link to a specific Zscaler best-practice article — report generator,
GUI library modal, and any future tooling.

Not a live fetch — static list curated by the user. Add / edit entries
here; every consumer re-renders from this module.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List

try:
    from bp_sources import credibility_for, get_source
except Exception:
    # Defensive fallback so this module keeps working even if bp_sources
    # is missing — everything gets tagged as the old help.zscaler.com default.
    def credibility_for(_source_id: str) -> int:
        return 100
    def get_source(_source_id: str) -> Dict[str, Any]:
        return {}


def _tag(entry: Dict[str, Any], source_id: str = "help_zscaler") -> Dict[str, Any]:
    """Apply `source` + `credibility` + `tier` to an entry if missing."""
    entry.setdefault("source", source_id)
    src = get_source(entry["source"])
    entry.setdefault("credibility", src.get("credibility", credibility_for(entry["source"])))
    entry.setdefault("tier", src.get("tier", "official"))
    return entry


BEST_PRACTICES: List[Dict[str, Any]] = [
    # ─── ZPA ─────────────────────────────────────────────────────
    {
        "key": "zpa_leading_practices",
        "service": "ZPA",
        "title": "ZPA Leading Practices Guide",
        "url": "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide",
        "topics": ["zpa", "private_access", "zero_trust", "app_segments"],
    },
    {
        "key": "zpa_idp_config",
        "service": "ZPA",
        "title": "IdP Configuration Best Practices (ZPA)",
        "url": "https://help.zscaler.com/zpa/idp-configuration-best-practices",
        "topics": ["zpa", "idp", "saml", "identity", "sso"],
    },

    # ─── ZIA Policy & Core ───────────────────────────────────────
    {
        "key": "zia_policy_leading",
        "service": "ZIA",
        "title": "ZIA Policy Leading Practices Guide",
        "url": "https://help.zscaler.com/zscaler-deployments-operations/zia-policy-leading-practices-guide",
        "topics": ["zia", "policy", "dlp", "url", "rules"],
    },
    {
        "key": "zia_ssl_leading",
        "service": "ZIA",
        "title": "ZIA SSL Inspection Leading Practices Guide",
        "url": "https://help.zscaler.com/zscaler-deployments-operations/zia-ssl-inspection-leading-practices-guide",
        "topics": ["ssl", "tls", "inspection", "decrypt"],
    },
    {
        "key": "zia_ssl_rollout",
        "service": "ZIA",
        "title": "Best Practices for Testing and Rolling Out SSL/TLS Inspection",
        "url": "https://help.zscaler.com/zia/best-practices-testing-and-rolling-out-ssltls-inspection",
        "topics": ["ssl", "tls", "rollout", "pilot"],
    },
    {
        "key": "zia_firewall",
        "service": "ZIA",
        "title": "Best Practices for Firewall Control Policy",
        "url": "https://help.zscaler.com/zia/best-practices-firewall-control-policy",
        "topics": ["firewall", "fw", "policy"],
    },
    {
        "key": "zia_dns_rules",
        "service": "ZIA",
        "title": "Best Practices for DNS Control Rules",
        "url": "https://help.zscaler.com/zia/best-practices-dns-control-rules",
        "topics": ["dns"],
    },

    # ─── Traffic Forwarding ─────────────────────────────────────
    {
        "key": "zia_forwarding",
        "service": "ZIA",
        "title": "Best Practices for Traffic Forwarding",
        "url": "https://help.zscaler.com/zia/best-practices-traffic-forwarding",
        "topics": ["forwarding", "traffic", "gre", "ipsec", "pac"],
    },
    {
        "key": "zia_gre",
        "service": "ZIA",
        "title": "Best Practices for Deploying GRE Tunnels",
        "url": "https://help.zscaler.com/zia/best-practices-deploying-gre-tunnels",
        "topics": ["gre", "tunnel", "forwarding"],
    },
    {
        "key": "zia_pac",
        "service": "ZIA",
        "title": "Best Practices for Writing PAC Files",
        "url": "https://help.zscaler.com/zia/best-practices-writing-pac-files",
        "topics": ["pac", "forwarding"],
    },

    # ─── ZCC / Mobile Portal ────────────────────────────────────
    {
        "key": "zcc_deployment",
        "service": "ZCC",
        "title": "Best Practices for Zscaler Client Connector Deployment",
        "url": "https://help.zscaler.com/zscaler-client-connector/best-practices-zscaler-client-connector-deployment",
        "topics": ["zcc", "deployment"],
    },
    {
        "key": "zcc_ztunnel2",
        "service": "ZCC",
        "title": "Best Practices for Deploying Z-Tunnel 2.0",
        "url": "https://help.zscaler.com/zscaler-client-connector/best-practices-deploying-z-tunnel-2.0",
        "topics": ["zcc", "ztunnel", "z-tunnel", "tunnel"],
    },
    {
        "key": "zcc_bypass",
        "service": "ZCC",
        "title": "Best Practices for Adding Bypasses for Z-Tunnel 2.0",
        "url": "https://help.zscaler.com/zscaler-client-connector/best-practices-adding-bypasses-z-tunnel-2.0",
        "topics": ["zcc", "bypass", "ztunnel"],
    },
    {
        "key": "zcc_pac",
        "service": "ZCC",
        "title": "Best Practices for Using PAC Files with Zscaler Client Connector",
        "url": "https://help.zscaler.com/zscaler-client-connector/best-practices-using-pac-files-zscaler-client-connector",
        "topics": ["zcc", "pac"],
    },
    {
        "key": "zcc_updates",
        "service": "ZCC",
        "title": "Best Practices for Updating Latest Versions of Zscaler Client Connector",
        "url": "https://help.zscaler.com/zscaler-client-connector/best-practices-updating-latest-version-zscaler-client-connector-application",
        "topics": ["zcc", "update", "version"],
    },
    {
        "key": "zcc_vpn_interop",
        "service": "ZCC",
        "title": "Best Practices for Zscaler Client Connector and VPN Client Interoperability",
        "url": "https://help.zscaler.com/zscaler-client-connector/best-practices-zscaler-client-connector-and-vpn-client-interoperability",
        "topics": ["zcc", "vpn"],
    },

    # ─── Deception ───────────────────────────────────────────────
    {
        "key": "deception_network",
        "service": "Deception",
        "title": "Best Practice Guide for Network Decoys",
        "url": "https://help.zscaler.com/deception/best-practice-guide-network-decoys",
        "topics": ["deception", "decoy"],
    },
    {
        "key": "deception_threat_intel",
        "service": "Deception",
        "title": "Best Practice Guide for Threat Intelligence Decoys",
        "url": "https://help.zscaler.com/deception/best-practice-guide-threat-intelligence-decoys",
        "topics": ["deception", "threat", "intel"],
    },
    {
        "key": "deception_ad",
        "service": "Deception",
        "title": "Best Practice Guide for Active Directory Decoys",
        "url": "https://help.zscaler.com/deception/best-practice-guide-active-directory-decoys",
        "topics": ["deception", "ad", "active_directory"],
    },
    {
        "key": "deception_landmine",
        "service": "Deception",
        "title": "Best Practice Guide for Landmine Decoys",
        "url": "https://help.zscaler.com/deception/best-practice-guide-landmine-decoys",
        "topics": ["deception", "landmine"],
    },
    {
        "key": "deception_containment",
        "service": "Deception",
        "title": "Best Practice Guide for Using Containment Integrations",
        "url": "https://help.zscaler.com/deception/best-practice-guide-using-containment-integrations",
        "topics": ["deception", "containment", "integration"],
    },

    # ─── Honorable mention — close-but-not-titled ──────────────
    {
        "key": "zia_quic",
        "service": "ZIA",
        "title": "Managing the QUIC Protocol (recommends block-QUIC as a best practice)",
        "url": "https://help.zscaler.com/zia/managing-quic-protocol",
        "topics": ["quic", "udp"],
        "note": "Not titled 'Best Practices' but recommends a best-practice action (block QUIC).",
    },

    # ─── Tier 1 Official — Zscaler Blogs (www.zscaler.com) ──────
    {
        "key": "blog_zt_architecture",
        "service": "ZPA",
        "title": "Zero Trust Architecture Guide (Zscaler blog)",
        "url": "https://www.zscaler.com/resources/security-terms-glossary/what-is-zero-trust-architecture",
        "topics": ["zero_trust", "architecture", "zpa"],
        "source": "zscaler_blogs",
    },
    {
        "key": "blog_ssl_inspection_why",
        "service": "ZIA",
        "title": "Why SSL Inspection Matters (Zscaler blog)",
        "url": "https://www.zscaler.com/blogs/product-insights/why-ssl-inspection-matters",
        "topics": ["ssl", "tls", "inspection"],
        "source": "zscaler_blogs",
    },

    # ─── Tier 1 Official — Developer Portal ─────────────────────
    {
        "key": "dev_oneapi_overview",
        "service": "Other",
        "title": "OneAPI Overview & Auth Best Practices",
        "url": "https://developer.zscaler.com/oneapi",
        "topics": ["oneapi", "api", "auth", "oauth"],
        "source": "zscaler_developer",
    },
    {
        "key": "dev_zia_api_ref",
        "service": "ZIA",
        "title": "ZIA API Reference (developer.zscaler.com)",
        "url": "https://developer.zscaler.com/docs/zia",
        "topics": ["zia", "api", "sdk"],
        "source": "zscaler_developer",
    },
    {
        "key": "dev_zpa_api_ref",
        "service": "ZPA",
        "title": "ZPA API Reference (developer.zscaler.com)",
        "url": "https://developer.zscaler.com/docs/zpa",
        "topics": ["zpa", "api", "sdk"],
        "source": "zscaler_developer",
    },

    # ─── Tier 1 Official — Zscaler GitHub org ───────────────────
    {
        "key": "gh_sdk_python",
        "service": "Other",
        "title": "zscaler-sdk-python (official SDK, README + examples)",
        "url": "https://github.com/zscaler/zscaler-sdk-python",
        "topics": ["sdk", "python", "api"],
        "source": "zscaler_github",
    },
    {
        "key": "gh_terraform_zia",
        "service": "ZIA",
        "title": "terraform-provider-zia (official Terraform provider)",
        "url": "https://github.com/zscaler/terraform-provider-zia",
        "topics": ["zia", "terraform", "iac"],
        "source": "zscaler_github",
    },
    {
        "key": "gh_terraform_zpa",
        "service": "ZPA",
        "title": "terraform-provider-zpa (official Terraform provider)",
        "url": "https://github.com/zscaler/terraform-provider-zpa",
        "topics": ["zpa", "terraform", "iac"],
        "source": "zscaler_github",
    },
    {
        "key": "gh_zpcc_ansible",
        "service": "Other",
        "title": "zscaler.zpcc Ansible Collection (official)",
        "url": "https://github.com/zscaler/zpcc-ansible",
        "topics": ["ansible", "iac", "automation"],
        "source": "zscaler_github",
    },

    # ─── Tier 2 Authoritative — Terraform Registry ──────────────
    {
        "key": "tf_zia_provider",
        "service": "ZIA",
        "title": "Zscaler ZIA Terraform Provider — resource-level best practices",
        "url": "https://registry.terraform.io/providers/zscaler/zia/latest/docs",
        "topics": ["zia", "terraform", "iac"],
        "source": "terraform_registry",
    },
    {
        "key": "tf_zpa_provider",
        "service": "ZPA",
        "title": "Zscaler ZPA Terraform Provider — resource-level best practices",
        "url": "https://registry.terraform.io/providers/zscaler/zpa/latest/docs",
        "topics": ["zpa", "terraform", "iac"],
        "source": "terraform_registry",
    },

    # ─── Tier 2 Authoritative — Microsoft Learn ─────────────────
    {
        "key": "mslearn_zpa_sso",
        "service": "ZPA",
        "title": "Configure Zscaler Private Access SSO with Microsoft Entra ID",
        "url": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/zscalerprivateaccess-tutorial",
        "topics": ["zpa", "entra", "azure_ad", "sso", "saml", "idp"],
        "source": "ms_learn",
    },
    {
        "key": "mslearn_zia_sso",
        "service": "ZIA",
        "title": "Configure Zscaler (ZIA) SSO with Microsoft Entra ID",
        "url": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/zscaler-tutorial",
        "topics": ["zia", "entra", "azure_ad", "sso", "saml", "idp"],
        "source": "ms_learn",
    },
    {
        "key": "mslearn_zpa_scim",
        "service": "ZPA",
        "title": "Configure Zscaler Private Access Provisioning (SCIM) with Entra ID",
        "url": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/zscalerprivateaccess-provisioning-tutorial",
        "topics": ["zpa", "scim", "entra", "provisioning"],
        "source": "ms_learn",
    },

    # ─── Tier 2 Authoritative — AWS Documentation ───────────────
    {
        "key": "aws_zpa_connector",
        "service": "ZPA",
        "title": "AWS Prescriptive Guidance — Integrate ZPA with AWS (App Connector placement)",
        "url": "https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/zscaler-private-access-zpa-integration-with-aws.html",
        "topics": ["zpa", "aws", "connector", "cloud"],
        "source": "aws_docs",
    },

    # ─── Tier 2 Authoritative — SIEM (Splunk) ───────────────────
    {
        "key": "splunk_zia_nss_deployment",
        "service": "ZIA",
        "title": "Best Practices for ZIA NSS + Splunk Deployment",
        "url": "https://help.zscaler.com/zia/best-practices-deploying-nss-servers",
        "topics": ["zia", "nss", "splunk", "siem", "logs"],
        "source": "help_zscaler",
    },
    {
        "key": "splunkbase_zscaler_ta",
        "service": "ZIA",
        "title": "Zscaler Technology Add-On for Splunk (Splunkbase)",
        "url": "https://splunkbase.splunk.com/app/3866",
        "topics": ["splunk", "siem", "cim", "logs", "zia", "zpa"],
        "source": "splunkbase",
    },
    {
        "key": "splunkbase_zscaler_app",
        "service": "ZIA",
        "title": "Zscaler App for Splunk (dashboards + ES content)",
        "url": "https://splunkbase.splunk.com/app/3719",
        "topics": ["splunk", "dashboard", "es", "zia"],
        "source": "splunkbase",
    },
    {
        "key": "splunk_lantern_zscaler",
        "service": "Other",
        "title": "Splunk Lantern — Zscaler use-case recipes",
        "url": "https://lantern.splunk.com/Search?q=zscaler",
        "topics": ["splunk", "lantern", "recipes", "siem"],
        "source": "splunk_lantern",
    },

    # ─── Tier 2 Authoritative — EDR (CrowdStrike) ───────────────
    {
        "key": "cs_zscaler_partner",
        "service": "ZPA",
        "title": "CrowdStrike + Zscaler Partner Integration Overview",
        "url": "https://www.crowdstrike.com/partners/zscaler/",
        "topics": ["crowdstrike", "falcon", "edr", "zpa", "zia"],
        "source": "crowdstrike_integrations",
    },
    {
        "key": "zs_crowdstrike_ztna",
        "service": "ZPA",
        "title": "ZPA + CrowdStrike Falcon ZTA (device-posture integration)",
        "url": "https://help.zscaler.com/zpa/integration-guide-crowdstrike",
        "topics": ["zpa", "crowdstrike", "ztna", "posture", "device_trust"],
        "source": "help_zscaler",
    },

    # ─── Tier 2 Authoritative — IdP (Okta, Ping) ────────────────
    {
        "key": "okta_zpa_sso",
        "service": "ZPA",
        "title": "Okta SSO + SCIM Integration with Zscaler Private Access",
        "url": "https://help.zscaler.com/zpa/configuring-idp-okta",
        "topics": ["zpa", "okta", "sso", "saml", "scim", "idp"],
        "source": "help_zscaler",
    },
    {
        "key": "okta_zia_sso",
        "service": "ZIA",
        "title": "Okta SSO Integration with Zscaler Internet Access",
        "url": "https://help.zscaler.com/zia/configuring-okta-idp-sso-zscaler",
        "topics": ["zia", "okta", "sso", "saml", "idp"],
        "source": "help_zscaler",
    },
    {
        "key": "ping_zpa_sso",
        "service": "ZPA",
        "title": "PingFederate SSO Integration with ZPA",
        "url": "https://help.zscaler.com/zpa/configuring-pingfederate-idp",
        "topics": ["zpa", "ping", "pingfederate", "sso", "saml", "idp"],
        "source": "help_zscaler",
    },

    # ─── Tier 3 Community — Zscaler Community ───────────────────
    {
        "key": "community_best_practices",
        "service": "Other",
        "title": "Zscaler Community — Best Practices topic",
        "url": "https://community.zscaler.com/s/topic/best-practices",
        "topics": ["community", "best_practices"],
        "source": "zscaler_community",
        "note": "Mixed authorship; validate individual posts' authors before adopting.",
    },
    {
        "key": "community_zcc_troubleshooting",
        "service": "ZCC",
        "title": "Zscaler Community — ZCC troubleshooting playbook",
        "url": "https://community.zscaler.com/s/topic/zscaler-client-connector",
        "topics": ["zcc", "troubleshooting", "client_connector"],
        "source": "zscaler_community",
    },
]

# Backfill source/credibility/tier on every curated entry. Entries that
# don't declare a `source` default to help_zscaler (the original scope).
BEST_PRACTICES = [_tag(e, e.get("source", "help_zscaler")) for e in BEST_PRACTICES]


def _discovered_store_path() -> str:
    """Writable location for crawler-discovered entries that persist
    across sessions. Mirrors the update-checker's cache location so
    everything sits under one per-user data dir."""
    import sys
    try:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
            d = os.path.join(base, "ZscalerAssessment")
        elif sys.platform == "darwin":
            d = os.path.expanduser("~/Library/Caches/ZscalerAssessment")
        else:
            d = os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
                             "zscaler_assessment")
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(d, "bp_discovered.json")


def _load_discovered() -> List[Dict[str, Any]]:
    import json
    try:
        with open(_discovered_store_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("entries", []) if isinstance(data, dict) else []
    except Exception:
        return []


def save_discovered(new_entries: List[Dict[str, Any]]) -> int:
    """Merge crawler-discovered entries into the persisted store.
    Deduplicates by URL against both the curated list and previously
    saved discoveries. Returns the count actually appended."""
    import json, time
    if not new_entries:
        return 0
    curated_urls = {e["url"] for e in BEST_PRACTICES}
    existing = _load_discovered()
    existing_urls = {e["url"] for e in existing}
    added = []
    for e in new_entries:
        url = e.get("url")
        if not url or url in curated_urls or url in existing_urls:
            continue
        source_id = e.get("source") or e.get("source_id") or "help_zscaler"
        src_meta = get_source(source_id)
        # Defensive copy of just the fields we care about
        added.append({
            "key":     e.get("key") or f"discovered_{len(existing) + len(added) + 1}",
            "service": e.get("service", "Other"),
            "title":   e.get("title", ""),
            "url":     url,
            "topics":  e.get("topics", []),
            "source":  source_id,
            "credibility": int(e.get("credibility", src_meta.get("credibility", 0))),
            "tier":    e.get("tier", src_meta.get("tier", "unverified")),
            "discovered": True,
            "first_seen": e.get("first_seen") or time.time(),
        })
    if not added:
        return 0
    merged = existing + added
    try:
        with open(_discovered_store_path(), "w", encoding="utf-8") as f:
            json.dump({"entries": merged, "updated_at": time.time()}, f, indent=2)
    except Exception:
        pass
    return len(added)


def reset_discovered() -> bool:
    """Wipe the persisted discovery store — drops back to curated-only."""
    try:
        p = _discovered_store_path()
        if os.path.exists(p):
            os.remove(p)
        return True
    except Exception:
        return False


def _merged_catalog() -> List[Dict[str, Any]]:
    """Curated + any previously-crawled discoveries, deduplicated.
    Discovered entries persisted before the multi-source refactor may
    be missing source/credibility/tier — _tag() backfills them from
    bp_sources so the UI can render a badge even for legacy discoveries."""
    discovered = _load_discovered()
    by_url = {e["url"]: e for e in BEST_PRACTICES}
    for d in discovered:
        if d.get("url") and d["url"] not in by_url:
            by_url[d["url"]] = _tag(dict(d), d.get("source", "help_zscaler"))
    return list(by_url.values())


def lookup_by_topic(topic: str) -> Dict[str, Any]:
    """Return the first best-practice entry whose topic list matches.
    Case-insensitive, underscore-insensitive substring match.
    Used by report_docx._resolve_best_practice."""
    t = (topic or "").lower().replace("-", "_").replace(" ", "_")
    if not t:
        return {}
    for entry in _merged_catalog():
        for topic_kw in entry.get("topics", []):
            if topic_kw == t or topic_kw in t or t in topic_kw:
                return entry
    return {}


def list_all(service: str = "") -> List[Dict[str, Any]]:
    """Return the merged (curated + discovered) list, optionally
    filtered by service name (case-insensitive)."""
    entries = _merged_catalog()
    if not service:
        return entries
    s = service.lower()
    return [e for e in entries if e.get("service", "").lower() == s]


def services() -> List[str]:
    seen = []
    for e in BEST_PRACTICES:
        svc = e.get("service", "")
        if svc and svc not in seen:
            seen.append(svc)
    return seen
