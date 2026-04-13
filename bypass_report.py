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
    """
    Normalize a rule's action to an upper-case string.
    ZIA SSL inspection rules expose `action` as a *dict* like
      {"type": "DO_NOT_DECRYPT", "sslInterceptionCert": {...}}
    while most other rule types expose it as a plain string.
    Handle both.
    """
    a = r.get("action")
    if isinstance(a, dict):
        a = a.get("type") or a.get("name") or a.get("actionType") or ""
    if not isinstance(a, str):
        a = str(a) if a is not None else ""
    return a.upper().replace(" ", "_")


def _extract_names(items):
    """Normalize a list of raw rule items that may be strings, ids, or
    {id, name} dicts. Returns a list of human-readable strings. Full
    list — no truncation — since auditors need every entry.
    """
    out = []
    for x in items or []:
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, int):
            out.append(str(x))
        elif isinstance(x, dict):
            out.append(x.get("name") or x.get("url") or x.get("id") or str(x))
        else:
            out.append(str(x))
    return out


def _normalize_rule(r: Dict[str, Any], source: str) -> Dict[str, Any]:
    return {
        "source": source,
        "id": r.get("id"),
        "name": (r.get("name") or "").strip() or f"Rule {r.get('id')}",
        "action": _action_of(r),
        "state": (r.get("state") or "ENABLED").upper(),
        "scope": _scope_summary(r),
        # FULL lists — no truncation. Auditors need to see every item
        # that is being exempted from inspection.
        "url_categories":         _extract_names(r.get("urlCategories")),
        "urls":                   _extract_names(r.get("urls")),
        "cloud_applications":     _extract_names(r.get("cloudApplications")),
        "cloud_app_categories":   _extract_names(r.get("cloudApplicationCategories")),
        "dest_ips":               _extract_names(r.get("destIps")),
        "dest_ip_groups":         _extract_names(r.get("destIpGroups")),
        "dest_ip_categories":     _extract_names(r.get("destIpCategories")),
        "file_types":             _extract_names(r.get("fileTypes")),
        "protocols":              _extract_names(r.get("protocols")),
        "order":                  r.get("order"),
        "description":            (r.get("description") or ""),
    }


# ── URL category lookup (for inheritance expansion) ──────────────────

def _fetch_url_category_lookup(client) -> Dict[str, Dict[str, Any]]:
    """
    Fetch every URL category from /zia/urlCategories and return a
    lookup map keyed by BOTH id and configuredName → full category
    metadata (urls list, dbCategorizedUrls list, type, superCategory).

    Custom categories have enumerable URLs; predefined (Zscaler-
    maintained) categories don't carry URLs in the API response but
    we still note them so the report can say 'FINANCE (predefined)
    is exempt — Zscaler maintains the URL list internally'.
    """
    lookup: Dict[str, Dict[str, Any]] = {}
    try:
        data, code = client.get("/zia/urlCategories")
        cats = _rules_to_list(data) if code == 200 else []
    except Exception:
        cats = []
    for cat in cats:
        if not isinstance(cat, dict):
            continue
        urls          = list(cat.get("urls") or [])
        db_urls       = list(cat.get("dbCategorizedUrls") or [])
        keywords      = list(cat.get("keywords") or [])
        is_custom     = bool(cat.get("customCategory") or cat.get("custom"))
        cat_type      = cat.get("type") or ("CUSTOM" if is_custom else "PREDEFINED")
        entry = {
            "id":             cat.get("id"),
            "configured_name": cat.get("configuredName") or cat.get("name"),
            "name":           cat.get("name") or cat.get("configuredName"),
            "super_category": cat.get("superCategory"),
            "type":           str(cat_type).upper(),
            "custom":         is_custom,
            "urls":           urls,
            "db_urls":        db_urls,
            "keywords":       keywords,
            "url_count":      len(urls),
            "db_url_count":   len(db_urls),
        }
        for key_field in ("id", "configuredName", "name"):
            k = cat.get(key_field)
            if k:
                lookup[str(k)] = entry
    return lookup


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
    """
    ZCC bypass lists live in MULTIPLE places:
      - /zcc/webPolicies          (app profiles — the main bypass container)
      - /zcc/forwardingProfiles   (forwarding profiles)
      - /zcc/trustedNetworks      (dedicated trusted networks collection)
      - /zcc/webAppService        (web app service exclusions)

    Instead of hardcoding every possible field name, this walks every
    dict/list in each profile and classifies anything whose key contains
    a bypass/exclude/trust token. Much more resilient to schema drift.
    """
    apps, processes, ips, domains, trusted = [], [], [], [], []
    endpoints_probed = []
    profile_count = 0

    APP_FIELDS     = ("bypassapp", "applicationbypass", "appbypass", "bypassapps", "appexclude")
    PROCESS_FIELDS = ("bypassprocess", "processbypass", "bypassprocesses", "processexclude")
    IP_FIELDS      = ("bypassip", "ipbypass", "bypassips", "bypasssubnet", "ipexclude", "destinationexclude", "nonzscalerdestinations")
    DOMAIN_FIELDS  = ("bypassurl", "bypassdomain", "domainbypass", "bypasshostname", "bypasshostnames", "hostbypass", "exempteddomain", "hostnamebypassforipv4", "hostnamebypassforipv6", "bypassforipv4", "bypassforipv6", "tunnelbypass")
    TRUSTED_FIELDS = ("trustednetwork", "trustednetworklist", "onnetworktrusted", "trustedtlsnetwork")

    def _classify_and_append(profile_ctx, key, value):
        """Route a (key, value) pair into the correct bucket based on keyword."""
        kl = key.lower().replace("_", "").replace("-", "")
        # Skip non-list values that don't look like bypass lists
        if not isinstance(value, list):
            return False
        # Filter out empty lists
        if not value:
            return False

        target_bucket = None
        if any(t in kl for t in APP_FIELDS):
            target_bucket = apps
            entry_maker = lambda v: {
                "name": v.get("name") if isinstance(v, dict) else str(v),
                "path": v.get("path") if isinstance(v, dict) else None,
                "os":   v.get("os") if isinstance(v, dict) else None,
                "value": v.get("name") if isinstance(v, dict) else str(v),
            }
        elif any(t in kl for t in PROCESS_FIELDS):
            target_bucket = processes
            entry_maker = lambda v: {
                "name": v.get("name") if isinstance(v, dict) else str(v),
                "value": v.get("name") if isinstance(v, dict) else str(v),
            }
        elif any(t in kl for t in IP_FIELDS):
            target_bucket = ips
            entry_maker = lambda v: {
                "value": v.get("ip") if isinstance(v, dict) else str(v),
            }
        elif any(t in kl for t in TRUSTED_FIELDS):
            target_bucket = trusted
            entry_maker = lambda v: {
                "value": v if isinstance(v, str) else (v.get("name") or v.get("ssid") or json.dumps(v)[:200]),
            }
        elif any(t in kl for t in DOMAIN_FIELDS):
            target_bucket = domains
            entry_maker = lambda v: {
                "value": v if isinstance(v, str) else (v.get("name") or v.get("url") or v.get("domain") or str(v)),
            }
        else:
            return False

        for v in value:
            entry = {"profile_id": profile_ctx["id"], "profile": profile_ctx["name"],
                     "profile_endpoint": profile_ctx["endpoint"], "raw_field": key}
            entry.update(entry_maker(v))
            target_bucket.append(entry)
        return True

    def _walk_profile(profile, endpoint):
        """Recursively walk a profile dict, classifying any list under a bypass-ish key."""
        pname = profile.get("name") or profile.get("policyName") or profile.get("profileName") or f"Profile {profile.get('id', '?')}"
        pid = profile.get("id")
        ctx = {"id": pid, "name": pname, "endpoint": endpoint}
        for k, v in profile.items():
            if not isinstance(k, str):
                continue
            if _classify_and_append(ctx, k, v):
                continue
            # Descend one level into nested dicts (ZCC wraps some settings)
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if isinstance(k2, str):
                        _classify_and_append(ctx, k2, v2)

    # Probe every known ZCC profile-bearing endpoint
    for ep in ("/zcc/webPolicies", "/zcc/forwardingProfiles",
               "/zcc/trustedNetworks", "/zcc/webAppService"):
        try:
            data, code = client.get(ep)
        except Exception as e:
            endpoints_probed.append({"endpoint": ep, "status": 0, "error": str(e)[:150]})
            continue
        endpoints_probed.append({"endpoint": ep, "status": code,
                                 "item_count": len(_rules_to_list(data)) if code == 200 else 0})
        if code != 200:
            continue
        items = _rules_to_list(data)
        profile_count += len(items)
        for prof in items:
            if isinstance(prof, dict):
                _walk_profile(prof, ep)

    return {
        "endpoints_probed": endpoints_probed,
        "profile_count": profile_count,
        "apps": {"count": len(apps), "items": apps},
        "processes": {"count": len(processes), "items": processes},
        "ips": {"count": len(ips), "items": ips},
        "domains": {"count": len(domains), "items": domains},
        "trusted_networks": {"count": len(trusted), "items": trusted},
    }


# ── Aggregator: consolidated bypass universe ─────────────────────────

def _aggregate_bypasses(sections: Dict[str, Any], url_cat_lookup: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Merge URL / cloud-app / category / IP references across ALL bypass
    sections into a single deduplicated list per dimension.

    For each item we track which rule(s) caused the exemption so auditors
    can trace an entry back to the source rule.

    When url_cat_lookup is provided, every URL category referenced by a
    bypass rule is ALSO expanded into its constituent URLs (for custom
    categories — predefined categories are noted with a marker).
    """
    def _mk():
        return {}  # token -> {count, rules:[{source, id, name, action}, ...]}

    url_categories   = _mk()
    urls             = _mk()
    inherited_urls   = _mk()   # URLs inherited from URL categories
    category_expand  = []      # [{category, type, urls[], rules_referencing[]}]
    cloud_apps       = _mk()
    cloud_app_cats   = _mk()
    dest_ips         = _mk()
    dest_ip_groups   = _mk()
    file_types       = _mk()

    zcc = sections.get("zcc") or {}
    zcc_apps         = _mk()
    zcc_processes    = _mk()
    zcc_ips          = _mk()
    zcc_domains      = _mk()
    zcc_trusted_nets = _mk()

    def _push(bucket, token, ctx):
        if token in (None, ""):
            return
        key = str(token).strip()
        if not key:
            return
        entry = bucket.setdefault(key, {"value": key, "count": 0, "rules": []})
        entry["count"] += 1
        # De-dup the rule list by (source, id) to avoid noise when the same rule has many items
        sig = (ctx.get("source"), ctx.get("id"))
        if sig not in {(r.get("source"), r.get("id")) for r in entry["rules"]}:
            entry["rules"].append(ctx)

    for section_key in ("ssl_bypass_rules", "url_filter_allow", "firewall_allow", "dlp_allow"):
        sec = sections.get(section_key) or {}
        for rule in sec.get("items") or []:
            if not isinstance(rule, dict):
                continue
            ctx = {
                "source": rule.get("source", section_key),
                "id": rule.get("id"),
                "name": rule.get("name"),
                "action": rule.get("action"),
                "state": rule.get("state"),
            }
            for token in rule.get("url_categories") or []:
                _push(url_categories, token, ctx)
                # Expand category → inherited URLs if we have the lookup
                if url_cat_lookup:
                    cat = url_cat_lookup.get(str(token))
                    if cat:
                        entry = {
                            "category":        cat.get("configured_name") or cat.get("name") or str(token),
                            "category_id":     cat.get("id"),
                            "configured_name": cat.get("configured_name"),
                            "ref_token":       str(token),  # how the rule actually referred to it
                            "type":            cat.get("type"),
                            "super_category":  cat.get("super_category"),
                            "is_custom":       cat.get("custom"),
                            "url_count":       (cat.get("url_count") or 0) + (cat.get("db_url_count") or 0),
                            "urls":            cat.get("urls"),
                            "db_urls":         cat.get("db_urls"),
                            "keywords":        cat.get("keywords"),
                            "referenced_by_rule": ctx,
                        }
                        category_expand.append(entry)
                        # Push each URL into the inherited_urls bucket with
                        # a context that tags which category + rule exempted it.
                        inherited_ctx = {**ctx,
                                         "via_category": entry["category"],
                                         "category_type": entry["type"]}
                        for u in cat.get("urls") or []:
                            _push(inherited_urls, u, inherited_ctx)
                        for u in cat.get("db_urls") or []:
                            _push(inherited_urls, u, {**inherited_ctx, "db_categorized": True})
                    else:
                        # Predefined Zscaler category — note that URL list is Zscaler-maintained
                        category_expand.append({
                            "category": str(token),
                            "type": "PREDEFINED_OR_UNKNOWN",
                            "note": "Zscaler maintains the URL list for this category — not enumerable via API.",
                            "referenced_by_rule": ctx,
                        })
            for token in rule.get("urls") or []:                 _push(urls, token, ctx)
            for token in rule.get("cloud_applications") or []:   _push(cloud_apps, token, ctx)
            for token in rule.get("cloud_app_categories") or []: _push(cloud_app_cats, token, ctx)
            for token in rule.get("dest_ips") or []:             _push(dest_ips, token, ctx)
            for token in rule.get("dest_ip_groups") or []:       _push(dest_ip_groups, token, ctx)
            for token in rule.get("file_types") or []:           _push(file_types, token, ctx)

    # Include SSL exemption values (they aren't tied to a rule — use source endpoint as ctx)
    for item in (sections.get("ssl_exemptions") or {}).get("items") or []:
        if not isinstance(item, dict):
            continue
        value = item.get("value") or item.get("url") or ""
        field = (item.get("field") or "").lower()
        src = item.get("source") or "ssl_exemption"
        ctx = {"source": src, "id": None, "name": f"SSL exemption ({field})",
               "action": "EXEMPT", "state": "ACTIVE"}
        if "category" in field or "cat" in field:
            _push(url_categories, value, ctx)
        elif "ip" in field:
            _push(dest_ips, value, ctx)
        else:
            _push(urls, value, ctx)

    # ZCC bypasses
    def _zcc_push(sub, bucket, value_key="value", name_key=None):
        items = (zcc.get(sub) or {}).get("items") or []
        for it in items:
            if not isinstance(it, dict):
                continue
            value = it.get(value_key) or it.get("name") or ""
            if name_key and not value:
                value = it.get(name_key) or ""
            ctx = {"source": f"zcc.{sub}", "id": it.get("profile_id"),
                   "name": f"ZCC profile: {it.get('profile', '?')}",
                   "action": "ZCC_BYPASS", "state": "ENABLED"}
            _push(bucket, value, ctx)

    _zcc_push("apps",             zcc_apps,         value_key="name")
    _zcc_push("processes",        zcc_processes,    value_key="name")
    _zcc_push("ips",              zcc_ips)
    _zcc_push("domains",          zcc_domains)
    _zcc_push("trusted_networks", zcc_trusted_nets)

    def _as_list(bucket):
        # Sort by count desc, then value
        items = sorted(bucket.values(), key=lambda x: (-x["count"], x["value"]))
        return {"count": len(items), "items": items}

    return {
        "url_categories":      _as_list(url_categories),
        "urls":                _as_list(urls),
        "inherited_urls":      _as_list(inherited_urls),   # URLs pulled in via a category reference
        "category_expansion":  category_expand,             # per-category expansion detail
        "cloud_applications":  _as_list(cloud_apps),
        "cloud_app_categories":_as_list(cloud_app_cats),
        "dest_ips":            _as_list(dest_ips),
        "dest_ip_groups":      _as_list(dest_ip_groups),
        "file_types":          _as_list(file_types),
        "zcc_apps":            _as_list(zcc_apps),
        "zcc_processes":       _as_list(zcc_processes),
        "zcc_ips":             _as_list(zcc_ips),
        "zcc_domains":         _as_list(zcc_domains),
        "zcc_trusted_networks":_as_list(zcc_trusted_nets),
    }


# ── Top-level report generator ───────────────────────────────────────

def generate_bypass_report(client) -> Dict[str, Any]:
    """Produce the full bypass inventory. Read-only.

    Every section is independently wrapped so a single failing endpoint
    never prevents the whole report from returning. The top-level is
    also wrapped — if anything unexpected goes wrong, we still return a
    valid (degraded) report with a diagnostics field so the GUI can
    render something useful.
    """
    import traceback as _tb
    start = datetime.now(timezone.utc)
    sections: Dict[str, Any] = {}
    diagnostics: List[Dict[str, Any]] = []

    def _safe(name, fn):
        try:
            return fn()
        except Exception as e:
            diagnostics.append({
                "section": name,
                "error_type": type(e).__name__,
                "error": str(e)[:300],
                "traceback_last": (_tb.format_exc().splitlines() or [""])[-1][:200],
            })
            return {"error": str(e)[:200], "items": [], "count": 0}

    sections["ssl_bypass_rules"] = _safe("ssl_bypass_rules", lambda: _fetch_ssl_bypass(client))
    sections["ssl_exemptions"]   = _safe("ssl_exemptions",   lambda: _fetch_ssl_exemptions(client))
    sections["url_filter_allow"] = _safe("url_filter_allow", lambda: _fetch_urlfilter_bypass(client))
    sections["firewall_allow"]   = _safe("firewall_allow",   lambda: _fetch_firewall_bypass(client))
    sections["dlp_allow"]        = _safe("dlp_allow",        lambda: _fetch_dlp_bypass(client))
    sections["zcc"]              = _safe("zcc",              lambda: _fetch_zcc_bypasses(client))

    # Fetch URL category catalog once — used to expand category refs in
    # bypass rules into their inherited URLs.
    url_cat_lookup = _safe("url_category_lookup", lambda: _fetch_url_category_lookup(client))
    if isinstance(url_cat_lookup, dict) and "error" in url_cat_lookup:
        url_cat_lookup = {}
    sections["url_category_catalog_count"] = len(url_cat_lookup or {})

    # Summary counts — defensively guard every lookup
    def _count(section_key, nested_key=None):
        try:
            sec = sections.get(section_key, {}) or {}
            if nested_key:
                return int((sec.get(nested_key, {}) or {}).get("count", 0) or 0)
            return int(sec.get("count", 0) or 0)
        except Exception:
            return 0

    summary = {
        "ssl_bypass_rules":  _count("ssl_bypass_rules"),
        "ssl_exemptions":    _count("ssl_exemptions"),
        "url_filter_allow":  _count("url_filter_allow"),
        "firewall_allow":    _count("firewall_allow"),
        "dlp_allow":         _count("dlp_allow"),
        "zcc_apps":          _count("zcc", "apps"),
        "zcc_processes":     _count("zcc", "processes"),
        "zcc_ips":           _count("zcc", "ips"),
        "zcc_domains":       _count("zcc", "domains"),
        "zcc_trusted_nets":  _count("zcc", "trusted_networks"),
    }
    summary["total_bypass_items"] = sum(v for v in summary.values() if isinstance(v, int))

    # Aggregated bypass universe — one consolidated list of every URL,
    # cloud app, category, and IP exempted from inspection ANYWHERE in
    # the tenant. Auditors ask for this exact artifact.
    # URL category references are expanded into their inherited URLs.
    aggregated = _aggregate_bypasses(sections, url_cat_lookup or {})

    # Risk-flag: rules with action=BYPASS that are globally scoped
    risky: List[Dict[str, Any]] = []
    try:
        for key in ("ssl_bypass_rules", "url_filter_allow", "firewall_allow", "dlp_allow"):
            for item in (sections.get(key, {}) or {}).get("items") or []:
                if not isinstance(item, dict):
                    continue
                if str(item.get("scope", "")).startswith("global") and item.get("state") == "ENABLED":
                    risky.append({
                        "source": item.get("source", "?"),
                        "id": item.get("id"),
                        "name": item.get("name", "?"),
                        "action": item.get("action", "?"),
                        "reason": "Globally-scoped bypass rule — applies to everyone.",
                    })
    except Exception as e:
        diagnostics.append({"section": "risk_flags", "error_type": type(e).__name__, "error": str(e)[:200]})

    return {
        "generated_at": start.isoformat(),
        "elapsed_seconds": round((datetime.now(timezone.utc) - start).total_seconds(), 2),
        "report_version": 3,
        "summary": summary,
        "risk_flags": risky,
        "aggregated": aggregated,    # consolidated global lists of bypassed items
        "sections": sections,
        "diagnostics": diagnostics,  # empty list = clean run; populated = something failed per-section
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
    """
    CSV export — one row per (rule, bypassed-item) so every URL /
    cloud-app / category / IP shows on its own line. Auditors can
    filter / pivot this in Excel directly.
    """
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "Section", "Rule Source", "Rule ID", "Rule Name", "Action", "State",
        "Scope", "Bypassed Dimension", "Bypassed Value",
        "Inherited From Category", "Category Type", "Description",
    ])

    def _emit_rule_dim(section_label, it, dim_label, values, via_category="", cat_type=""):
        if not values:
            w.writerow([section_label, it.get("source", ""), it.get("id", ""),
                        it.get("name", ""), it.get("action", ""), it.get("state", ""),
                        it.get("scope", ""), dim_label, "", via_category, cat_type,
                        (it.get("description") or "")[:300]])
            return
        for v in values:
            w.writerow([section_label, it.get("source", ""), it.get("id", ""),
                        it.get("name", ""), it.get("action", ""), it.get("state", ""),
                        it.get("scope", ""), dim_label, str(v)[:300],
                        via_category, cat_type,
                        (it.get("description") or "")[:300]])

    # Build a lookup keyed by EVERY possible reference form auditors may
    # see in a rule — id, configured_name, display name.
    cat_lookup_map = {}
    for cat_entry in (report.get("aggregated", {}) or {}).get("category_expansion", []) or []:
        for alias in (
            cat_entry.get("category"),
            cat_entry.get("category_id"),
            cat_entry.get("configured_name"),
            cat_entry.get("ref_token"),
        ):
            if alias:
                cat_lookup_map[str(alias)] = cat_entry

    for key, label in [
        ("ssl_bypass_rules", "SSL Bypass"),
        ("url_filter_allow", "URL Filter ALLOW"),
        ("firewall_allow",   "Firewall ALLOW"),
        ("dlp_allow",        "DLP ALLOW/BYPASS"),
    ]:
        sec = (report.get("sections") or {}).get(key, {}) or {}
        for it in sec.get("items", []) or []:
            if not isinstance(it, dict):
                continue
            dimensions = [
                ("URL Category",        it.get("url_categories")),
                ("URL",                 it.get("urls")),
                ("Cloud Application",   it.get("cloud_applications")),
                ("Cloud App Category",  it.get("cloud_app_categories")),
                ("Destination IP",      it.get("dest_ips")),
                ("Destination IP Group",it.get("dest_ip_groups")),
                ("File Type",           it.get("file_types")),
                ("Protocol",            it.get("protocols")),
            ]
            emitted = False
            for dim_label, values in dimensions:
                if values:
                    emitted = True
                    _emit_rule_dim(label, it, dim_label, values)
                    # Emit INHERITED URLs for each URL category ref
                    if dim_label == "URL Category":
                        for cat_ref in values:
                            cat_info = cat_lookup_map.get(str(cat_ref))
                            if cat_info:
                                all_urls = (cat_info.get("urls") or []) + (cat_info.get("db_urls") or [])
                                for u in all_urls:
                                    _emit_rule_dim(label, it, "Inherited URL (from category)",
                                                   [u],
                                                   via_category=cat_info.get("category", ""),
                                                   cat_type=cat_info.get("type", ""))
            if not emitted:
                _emit_rule_dim(label, it, "Scope-only (no dimensional bypass)", [""])

    # SSL exemptions (flat items)
    for it in (report["sections"].get("ssl_exemptions", {}) or {}).get("items", []) or []:
        w.writerow([
            "SSL Exemption", it.get("source", ""), "", it.get("field", "") or it.get("label", ""),
            "", "", "", "Exempted Value", str(it.get("value", ""))[:300], "", "", "",
        ])

    # ZCC sections
    zcc = report["sections"].get("zcc", {}) or {}
    for subkey, label in [
        ("apps",             "ZCC App Bypass"),
        ("processes",        "ZCC Process Bypass"),
        ("ips",              "ZCC IP Bypass"),
        ("domains",          "ZCC Domain Bypass"),
        ("trusted_networks", "ZCC Trusted Network"),
    ]:
        for it in (zcc.get(subkey, {}) or {}).get("items", []) or []:
            w.writerow([
                label, it.get("profile", ""), it.get("profile_id", ""),
                it.get("name") or it.get("value", ""),
                "", "", "",
                subkey, str(it.get("value") or it.get("name") or "")[:300],
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

    # Aggregated lists — auditors most want this
    agg = report.get("aggregated") or {}
    out.append("## Aggregated Bypass Universe\n")
    out.append("_Every URL, cloud app, category, and IP exempted from Zscaler inspection ANYWHERE in the tenant — deduplicated and traced to the rule that caused the exemption._\n")

    def _agg_block(title, key, value_label="Value"):
        bucket = agg.get(key) or {}
        items = bucket.get("items") or []
        out.append(f"### {title} ({bucket.get('count', 0)})\n")
        if not items:
            out.append("_No items._\n")
            return
        out.append(f"| # | {value_label} | Referenced by rule(s) |")
        out.append("|---|---|---|")
        for idx, it in enumerate(items, 1):
            rules_str = ", ".join(
                f"{r.get('source','?')}#{r.get('id','?')} '{r.get('name','?')}'"
                for r in (it.get("rules") or [])[:6]
            )
            if len(it.get("rules") or []) > 6:
                rules_str += f", +{len(it['rules']) - 6} more"
            out.append(f"| {idx} | `{str(it.get('value',''))[:120]}` | {rules_str} |")
        out.append("")

    _agg_block("All Bypassed URL Categories", "url_categories", "URL Category")
    _agg_block("All Explicitly Bypassed URLs", "urls", "URL")
    _agg_block("All INHERITED URLs (from URL categories)", "inherited_urls", "URL (via category)")
    _agg_block("All Bypassed Cloud Applications", "cloud_applications", "Cloud App")
    _agg_block("All Bypassed Cloud App Categories", "cloud_app_categories", "Cloud App Category")
    _agg_block("All Bypassed Destination IPs", "dest_ips", "IP / CIDR")
    _agg_block("All Bypassed Destination IP Groups", "dest_ip_groups", "IP Group")
    _agg_block("ZCC — Bypassed Apps", "zcc_apps", "App")
    _agg_block("ZCC — Bypassed Processes", "zcc_processes", "Process")
    _agg_block("ZCC — Bypassed IPs", "zcc_ips", "IP / CIDR")
    _agg_block("ZCC — Bypassed Domains", "zcc_domains", "Domain")
    _agg_block("ZCC — Trusted Networks", "zcc_trusted_networks", "Network")

    # Category expansion detail
    cats = agg.get("category_expansion") or []
    if cats:
        out.append("## URL Category Expansion Detail\n")
        out.append("_Per-category breakdown showing which URLs each referenced category contributes to the effective bypass list._\n")
        for cat in cats[:100]:
            typ = cat.get("type", "?")
            urls = cat.get("urls") or []
            db_urls = cat.get("db_urls") or []
            keywords = cat.get("keywords") or []
            ref = cat.get("referenced_by_rule", {}) or {}
            out.append(f"### {cat.get('category')} [{typ}]")
            out.append(f"_Referenced by `{ref.get('source','?')}#{ref.get('id','?')}` — **{ref.get('name','?')}** (action `{ref.get('action','?')}`)_")
            if "note" in cat:
                out.append(f"> {cat['note']}\n")
            if urls:
                out.append(f"**URLs ({len(urls)}):**")
                for u in urls[:200]: out.append(f"- `{u}`")
                if len(urls) > 200: out.append(f"- _...and {len(urls) - 200} more_")
            if db_urls:
                out.append(f"\n**DB-Categorized URLs ({len(db_urls)}):**")
                for u in db_urls[:200]: out.append(f"- `{u}`")
                if len(db_urls) > 200: out.append(f"- _...and {len(db_urls) - 200} more_")
            if keywords:
                out.append(f"\n**Keywords ({len(keywords)}):** {', '.join(f'`{k}`' for k in keywords[:50])}")
            out.append("")
        if len(cats) > 100:
            out.append(f"_...and {len(cats) - 100} more categories. See JSON export for the complete list._\n")

    out.append("## Guidance\n")
    for g in report.get("guidance", []):
        out.append(f"- {g}")

    return "\n".join(out)
