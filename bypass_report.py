#!/usr/bin/env python3
"""
Zscaler Bypass / Non-Inspected Traffic Inventory
=================================================
Queries ZIA + ZCC and produces an inventory of everything that is
currently EXEMPTED from Zscaler inspection and / or bypassing the
Zscaler platform entirely. Auditors, DLP owners, and SecOps teams
need this cleanly itemized because:

  - Every bypass is a blind spot. Auditors ask for a documented list.
  - Malicious apps / domains sometimes get added to bypass lists and
    are forgotten. This inventory surfaces them.
  - Compliance frameworks (PCI-DSS 11.3, NIST AC-4, HIPAA 164.312)
    require documented exceptions with business justification.

Sections produced
-----------------
  1. SSL Inspection — rules that skip decryption
  2. SSL Inspection — exempted URL categories & domains
  3. URL Filtering — ALLOW rules (bypass URL filtering)
  4. Firewall — ALLOW rules (bypass firewall inspection)
  5. DLP — ALLOW / BYPASS rules (bypass DLP)
  6. ZCC App Bypass — applications excluded from ZCC tunnel
  7. ZCC IP / Trusted Networks — IPs / networks where ZCC disables
  8. ZCC Process Bypass — processes excluded from ZCC tunnel
  9. ZCC Domain Bypass — domains excluded from ZCC tunnel

Each entry includes: source rule id, name, scope (users/groups/
locations), scope-specificity marker, and the action that causes
the bypass. This is READ-ONLY: no writes to the tenant.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


BYPASS_ACTIONS = {
    # SSL inspection
    "DO_NOT_DECRYPT", "DO_NOT_INSPECT", "BYPASS", "BYPASS_OTHER_CATEGORIES",
    # URL / Firewall / DLP
    "ALLOW", "PERMIT", "BYPASS_FIREWALL", "BYPASS_DLP",
}


def _rules_to_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("list", "data", "items", "rules"):
            if isinstance(data.get(k), list):
                return data[k]
    return []


def _scope_summary(r: Dict[str, Any]) -> str:
    """Render a concise scope string for a rule."""
    parts = []
    for field, label in [
        ("users", "users"),
        ("groups", "groups"),
        ("departments", "depts"),
        ("locations", "locations"),
        ("srcIpGroups", "srcIpGrps"),
        ("destIpGroups", "dstIpGrps"),
    ]:
        v = r.get(field)
        if v:
            parts.append(f"{label}:{len(v)}")
    if not parts:
        return "global (unscoped)"
    return ", ".join(parts)


def _action_of(r: Dict[str, Any]) -> str:
    return (r.get("action") or "").upper().replace(" ", "_")


def _normalize_rule(r: Dict[str, Any], source: str) -> Dict[str, Any]:
    return {
        "source": source,
        "id": r.get("id"),
        "name": (r.get("name") or "").strip() or f"Rule {r.get('id')}",
        "action": _action_of(r),
        "state": (r.get("state") or "ENABLED").upper(),
        "scope": _scope_summary(r),
        "url_categories": (r.get("urlCategories") or [])[:20],
        "cloud_applications": (r.get("cloudApplications") or [])[:20],
        "dest_ips": (r.get("destIps") or r.get("destIpGroups") or [])[:20],
        "order": r.get("order"),
        "description": (r.get("description") or "")[:300],
    }


# ── Section fetchers ─────────────────────────────────────────────────

def _fetch_ssl_bypass(client) -> Dict[str, Any]:
    """SSL inspection rules with non-decrypt action."""
    data, code = client.get("/zia/sslInspectionRules")
    rules = _rules_to_list(data) if code == 200 else []
    non_inspect = [_normalize_rule(r, "ssl_inspection_rule")
                   for r in rules if _action_of(r) in BYPASS_ACTIONS]
    return {
        "count": len(non_inspect),
        "total_ssl_rules": len(rules),
        "endpoint": "/zia/sslInspectionRules",
        "http_status": code,
        "items": non_inspect,
    }


def _fetch_ssl_exemptions(client) -> Dict[str, Any]:
    """Exempted URL categories / hosts from SSL inspection."""
    out = {"items": [], "endpoints_probed": []}
    candidates = [
        ("/zia/sslInspectionSettings", "global"),
        ("/zia/advancedSettings", "advanced"),
        ("/zia/exemptedUrls", "exempted_urls"),
        ("/zia/sslInspectionExemptedUrls", "exempted_urls_ssl"),
    ]
    for ep, label in candidates:
        try:
            data, code = client.get(ep)
        except Exception:
            continue
        out["endpoints_probed"].append({"endpoint": ep, "status": code})
        if code != 200 or not isinstance(data, (dict, list)):
            continue
        if isinstance(data, list):
            for item in data:
                out["items"].append({"source": ep, "label": label, "value": str(item)[:300]})
        else:
            # Walk dict for any key hinting at exemption/bypass/white-list
            for k, v in data.items():
                kl = k.lower()
                if any(t in kl for t in ("exempt", "bypass", "whitelist", "donotinspect", "do_not")):
                    if isinstance(v, list):
                        for item in v:
                            out["items"].append({
                                "source": ep, "field": k,
                                "value": item if isinstance(item, (str, int)) else json.dumps(item)[:300],
                            })
                    else:
                        out["items"].append({"source": ep, "field": k, "value": str(v)[:300]})
    out["count"] = len(out["items"])
    return out


def _fetch_urlfilter_bypass(client) -> Dict[str, Any]:
    data, code = client.get("/zia/urlFilteringRules")
    rules = _rules_to_list(data) if code == 200 else []
    allow = [_normalize_rule(r, "url_filtering_rule")
             for r in rules if _action_of(r) in BYPASS_ACTIONS]
    return {
        "count": len(allow),
        "total_rules": len(rules),
        "endpoint": "/zia/urlFilteringRules",
        "http_status": code,
        "items": allow,
    }


def _fetch_firewall_bypass(client) -> Dict[str, Any]:
    data, code = client.get("/zia/firewallRules")
    rules = _rules_to_list(data) if code == 200 else []
    allow = [_normalize_rule(r, "firewall_rule")
             for r in rules if _action_of(r) in BYPASS_ACTIONS]
    return {
        "count": len(allow),
        "total_rules": len(rules),
        "endpoint": "/zia/firewallRules",
        "http_status": code,
        "items": allow,
    }


def _fetch_dlp_bypass(client) -> Dict[str, Any]:
    data, code = client.get("/zia/webDlpRules")
    rules = _rules_to_list(data) if code == 200 else []
    allow = [_normalize_rule(r, "web_dlp_rule")
             for r in rules if _action_of(r) in BYPASS_ACTIONS]
    return {
        "count": len(allow),
        "total_rules": len(rules),
        "endpoint": "/zia/webDlpRules",
        "http_status": code,
        "items": allow,
    }


def _fetch_zcc_bypasses(client) -> Dict[str, Any]:
    """ZCC forwarding profile bypass lists: apps, processes, IPs, domains, trusted nets."""
    data, code = client.get("/zcc/forwardingProfiles")
    profiles = _rules_to_list(data) if code == 200 else []

    apps, processes, ips, domains, trusted = [], [], [], [], []
    for p in profiles:
        pname = p.get("name") or f"Profile {p.get('id', '?')}"
        pid = p.get("id")
        # Different deployments expose these under different keys; try common ones
        for field in ("bypassAppList", "applicationBypass", "appBypass", "bypassApps"):
            v = p.get(field)
            if isinstance(v, list):
                for a in v:
                    apps.append({
                        "profile_id": pid, "profile": pname,
                        "name": a.get("name") if isinstance(a, dict) else str(a),
                        "path": a.get("path") if isinstance(a, dict) else None,
                        "os": a.get("os") if isinstance(a, dict) else None,
                        "raw_field": field,
                    })
        for field in ("bypassProcessList", "processBypass", "bypassProcesses"):
            v = p.get(field)
            if isinstance(v, list):
                for a in v:
                    processes.append({
                        "profile_id": pid, "profile": pname,
                        "name": a.get("name") if isinstance(a, dict) else str(a),
                        "raw_field": field,
                    })
        for field in ("bypassIpList", "ipBypass", "bypassIps", "bypassSubnets"):
            v = p.get(field)
            if isinstance(v, list):
                for a in v:
                    ips.append({
                        "profile_id": pid, "profile": pname,
                        "value": a.get("ip") if isinstance(a, dict) else str(a),
                        "raw_field": field,
                    })
        for field in ("bypassUrls", "bypassDomains", "domainBypass", "bypassHostnames"):
            v = p.get(field)
            if isinstance(v, list):
                for a in v:
                    domains.append({
                        "profile_id": pid, "profile": pname,
                        "value": a if isinstance(a, str) else (a.get("name") or a.get("url") or str(a)),
                        "raw_field": field,
                    })
        for field in ("trustedNetworks", "trustedNetworkList", "onNetworkTrusted"):
            v = p.get(field)
            if isinstance(v, list):
                for a in v:
                    trusted.append({
                        "profile_id": pid, "profile": pname,
                        "value": a if isinstance(a, str) else (a.get("name") or a.get("ssid") or str(a)[:200]),
                        "raw_field": field,
                    })

    return {
        "endpoint": "/zcc/forwardingProfiles",
        "http_status": code,
        "profile_count": len(profiles),
        "apps": {"count": len(apps), "items": apps},
        "processes": {"count": len(processes), "items": processes},
        "ips": {"count": len(ips), "items": ips},
        "domains": {"count": len(domains), "items": domains},
        "trusted_networks": {"count": len(trusted), "items": trusted},
    }


# ── Top-level report generator ───────────────────────────────────────

def generate_bypass_report(client) -> Dict[str, Any]:
    """Produce the full bypass inventory. Read-only."""
    start = datetime.now(timezone.utc)
    sections = {}

    try: sections["ssl_bypass_rules"] = _fetch_ssl_bypass(client)
    except Exception as e: sections["ssl_bypass_rules"] = {"error": str(e)[:200]}

    try: sections["ssl_exemptions"] = _fetch_ssl_exemptions(client)
    except Exception as e: sections["ssl_exemptions"] = {"error": str(e)[:200]}

    try: sections["url_filter_allow"] = _fetch_urlfilter_bypass(client)
    except Exception as e: sections["url_filter_allow"] = {"error": str(e)[:200]}

    try: sections["firewall_allow"] = _fetch_firewall_bypass(client)
    except Exception as e: sections["firewall_allow"] = {"error": str(e)[:200]}

    try: sections["dlp_allow"] = _fetch_dlp_bypass(client)
    except Exception as e: sections["dlp_allow"] = {"error": str(e)[:200]}

    try: sections["zcc"] = _fetch_zcc_bypasses(client)
    except Exception as e: sections["zcc"] = {"error": str(e)[:200]}

    # Summary counts
    summary = {
        "ssl_bypass_rules":  sections["ssl_bypass_rules"].get("count", 0),
        "ssl_exemptions":    sections["ssl_exemptions"].get("count", 0),
        "url_filter_allow":  sections["url_filter_allow"].get("count", 0),
        "firewall_allow":    sections["firewall_allow"].get("count", 0),
        "dlp_allow":         sections["dlp_allow"].get("count", 0),
        "zcc_apps":          sections["zcc"].get("apps", {}).get("count", 0),
        "zcc_processes":     sections["zcc"].get("processes", {}).get("count", 0),
        "zcc_ips":           sections["zcc"].get("ips", {}).get("count", 0),
        "zcc_domains":       sections["zcc"].get("domains", {}).get("count", 0),
        "zcc_trusted_nets":  sections["zcc"].get("trusted_networks", {}).get("count", 0),
    }
    summary["total_bypass_items"] = sum(v for v in summary.values() if isinstance(v, int))

    # Risk-flag: rules with action=BYPASS that are globally scoped (no user/group/location)
    risky = []
    for key in ("ssl_bypass_rules", "url_filter_allow", "firewall_allow", "dlp_allow"):
        for item in sections[key].get("items") or []:
            if item.get("scope", "").startswith("global") and item.get("state") == "ENABLED":
                risky.append({
                    "source": item["source"],
                    "id": item["id"],
                    "name": item["name"],
                    "action": item["action"],
                    "reason": "Globally-scoped bypass rule — applies to everyone.",
                })

    return {
        "generated_at": start.isoformat(),
        "elapsed_seconds": round((datetime.now(timezone.utc) - start).total_seconds(), 2),
        "summary": summary,
        "risk_flags": risky,
        "sections": sections,
        "guidance": [
            "Document business justification for every bypass — auditors expect this.",
            "Periodically (quarterly minimum) review the bypass list. Remove anything without a current owner.",
            "Prefer category-level exemptions over domain/IP level — easier to audit and rotate.",
            "Globally-scoped bypass rules are higher risk. Scope to users/groups/locations when possible.",
            "ZCC app/process bypass should be a last resort — prefer domain/URL bypass that still traverses the tunnel.",
            "SSL inspection exemptions should match legitimate use cases (banking, healthcare portals) — not arbitrary user requests.",
        ],
    }


# ── Exporters ────────────────────────────────────────────────────────

def to_csv(report: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Section", "Source", "ID", "Name", "Action", "State", "Scope",
                "URL Categories", "Cloud Apps", "Description"])
    for key, label in [
        ("ssl_bypass_rules", "SSL Bypass"),
        ("url_filter_allow", "URL Filter ALLOW"),
        ("firewall_allow",   "Firewall ALLOW"),
        ("dlp_allow",        "DLP ALLOW/BYPASS"),
    ]:
        sec = report["sections"].get(key, {})
        for it in sec.get("items", []) or []:
            w.writerow([
                label, it.get("source", ""), it.get("id", ""), it.get("name", ""),
                it.get("action", ""), it.get("state", ""), it.get("scope", ""),
                "|".join(str(x) for x in (it.get("url_categories") or [])[:10]),
                "|".join(str(x) for x in (it.get("cloud_applications") or [])[:10]),
                (it.get("description") or "")[:200],
            ])
    # SSL exemptions (flat items)
    for it in (report["sections"].get("ssl_exemptions", {}) or {}).get("items", []) or []:
        w.writerow([
            "SSL Exemption", it.get("source", ""), "", it.get("field", "") or it.get("label", ""),
            "", "", "", "", "", str(it.get("value", ""))[:200],
        ])
    # ZCC sections
    zcc = report["sections"].get("zcc", {}) or {}
    for subkey, label in [
        ("apps", "ZCC App Bypass"),
        ("processes", "ZCC Process Bypass"),
        ("ips", "ZCC IP Bypass"),
        ("domains", "ZCC Domain Bypass"),
        ("trusted_networks", "ZCC Trusted Network"),
    ]:
        for it in (zcc.get(subkey, {}) or {}).get("items", []) or []:
            w.writerow([
                label, it.get("profile", ""), it.get("profile_id", ""),
                it.get("name") or it.get("value", ""),
                "", "", "",
                "", "", it.get("raw_field", ""),
            ])
    return buf.getvalue()


def to_markdown(report: Dict[str, Any]) -> str:
    out = []
    out.append(f"# Zscaler Bypass / Non-Inspected Traffic Inventory\n")
    out.append(f"_Generated: {report['generated_at']} (took {report['elapsed_seconds']}s)_\n")
    s = report["summary"]
    out.append("## Summary\n")
    out.append(f"- SSL bypass rules: **{s['ssl_bypass_rules']}**")
    out.append(f"- SSL exemptions (categories/URLs): **{s['ssl_exemptions']}**")
    out.append(f"- URL Filter ALLOW rules: **{s['url_filter_allow']}**")
    out.append(f"- Firewall ALLOW rules: **{s['firewall_allow']}**")
    out.append(f"- DLP ALLOW/BYPASS rules: **{s['dlp_allow']}**")
    out.append(f"- ZCC — app bypass: **{s['zcc_apps']}**, process bypass: **{s['zcc_processes']}**, IP bypass: **{s['zcc_ips']}**, domain bypass: **{s['zcc_domains']}**, trusted networks: **{s['zcc_trusted_nets']}**")
    out.append(f"- **Total bypass items: {s['total_bypass_items']}**\n")

    if report.get("risk_flags"):
        out.append("## ⚠ Risk Flags\n")
        for r in report["risk_flags"]:
            out.append(f"- **{r['name']}** ({r['source']} #{r['id']}, action `{r['action']}`) — {r['reason']}")
        out.append("")

    def _items_table(items, fields):
        if not items:
            return "_No items._\n"
        lines = ["| " + " | ".join(fields) + " |", "|" + "|".join(["---"] * len(fields)) + "|"]
        for it in items:
            row = []
            for f in fields:
                v = it.get(f)
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v[:5])
                row.append(str(v or "").replace("|", "\\|")[:80])
            lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines) + "\n"

    sec_map = [
        ("ssl_bypass_rules", "SSL Inspection Bypass Rules"),
        ("url_filter_allow", "URL Filtering ALLOW Rules"),
        ("firewall_allow",   "Firewall ALLOW Rules"),
        ("dlp_allow",        "DLP ALLOW / BYPASS Rules"),
    ]
    for key, label in sec_map:
        sec = report["sections"].get(key) or {}
        out.append(f"## {label} ({sec.get('count', 0)} of {sec.get('total_ssl_rules') or sec.get('total_rules') or '?'})\n")
        out.append(_items_table(sec.get("items") or [],
                                ["id", "name", "action", "state", "scope", "url_categories"]))

    exm = report["sections"].get("ssl_exemptions") or {}
    out.append(f"## SSL Exemptions / Do-Not-Inspect ({exm.get('count', 0)})\n")
    out.append(_items_table(exm.get("items") or [], ["source", "field", "value"]))

    zcc = report["sections"].get("zcc") or {}
    for sub, label in [
        ("apps", "ZCC App Bypass"),
        ("processes", "ZCC Process Bypass"),
        ("ips", "ZCC IP Bypass"),
        ("domains", "ZCC Domain Bypass"),
        ("trusted_networks", "ZCC Trusted Networks"),
    ]:
        s2 = (zcc.get(sub) or {})
        out.append(f"## {label} ({s2.get('count', 0)})\n")
        out.append(_items_table(s2.get("items") or [], ["profile", "name", "value", "raw_field"]))

    out.append("## Guidance\n")
    for g in report.get("guidance", []):
        out.append(f"- {g}")

    return "\n".join(out)
