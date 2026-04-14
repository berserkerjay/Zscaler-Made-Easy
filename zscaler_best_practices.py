#!/usr/bin/env python3
"""
Curated Zscaler Best-Practices + Leading-Practices reference list.
Scope: titles explicitly containing "Best Practices" or "Leading Practices"
on help.zscaler.com.

This is the authoritative source the rest of the app uses when it needs
to link to a specific Zscaler best-practice article — report generator,
GUI library modal, and any future tooling.

Not a live fetch — static list curated by the user. Add / edit entries
here; every consumer re-renders from this module.
"""
from __future__ import annotations
from typing import Any, Dict, List


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
]


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
        # Defensive copy of just the fields we care about
        added.append({
            "key":     e.get("key") or f"discovered_{len(existing) + len(added) + 1}",
            "service": e.get("service", "Other"),
            "title":   e.get("title", ""),
            "url":     url,
            "topics":  e.get("topics", []),
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
    """Curated + any previously-crawled discoveries, deduplicated."""
    discovered = _load_discovered()
    by_url = {e["url"]: e for e in BEST_PRACTICES}
    for d in discovered:
        if d.get("url") and d["url"] not in by_url:
            by_url[d["url"]] = d
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
