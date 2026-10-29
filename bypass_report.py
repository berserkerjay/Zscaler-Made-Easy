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

import csv_safe
import io
import json
import md_safe
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


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
        #
        # URL-ish fields come under many names across rule types:
        #   URL filter rules: urlCategories + urls
        #   SSL inspection:   destinations + urls + urlCategories
        #   Firewall rules:   destCountries + destIpGroups (no URL typically)
        #   DLP rules:        urlCategories + urls
        # We sweep all known URL-ish fields into `urls` for a unified view.
        "url_categories":         _extract_names(r.get("urlCategories")),
        "urls":                   _extract_names(r.get("urls"))
                                   + _extract_names(r.get("destinations"))
                                   + _extract_names(r.get("destinationUrls"))
                                   + _extract_names(r.get("destinationHostNames"))
                                   + _extract_names(r.get("hostnames"))
                                   + _extract_names(r.get("domains"))
                                   + _extract_names(r.get("fqdns"))
                                   + _extract_names(r.get("exemptedUrls")),
        "cloud_applications":     _extract_names(r.get("cloudApplications"))
                                   + _extract_names(r.get("applications")),
        "cloud_app_categories":   _extract_names(r.get("cloudApplicationCategories")),
        "dest_ips":               _extract_names(r.get("destIps"))
                                   + _extract_names(r.get("destinationIps"))
                                   + _extract_names(r.get("destCidrs")),
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

def _read_list(client, endpoint: str) -> tuple:
    """(items, status) of a list endpoint. A status other than 200 (or 204,
    nothing there) raises: an unreadable rule list is "could not be read",
    never "no bypass" (the section's diagnostic says why)."""
    data, code = client.get(endpoint)
    if code == 204:
        return [], code
    if code != 200:
        err = data.get("error") or data.get("message") if isinstance(data, dict) else ""
        raise RuntimeError(f"HTTP {code} from {endpoint}" + (f": {str(err)[:160]}" if err else "") + "; the section could not be read")
    return _rules_to_list(data), code


def _fetch_ssl_bypass(client) -> Dict[str, Any]:
    """SSL inspection rules with non-decrypt action."""
    rules, code = _read_list(client, "/zia/sslInspectionRules")
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
        ("/zia/advancedSettings", "advanced"),
    ]
    for ep, label in candidates:
        data, code = client.get(ep)
        out["endpoints_probed"].append({"endpoint": ep, "status": code})
        if code != 200:
            raise RuntimeError(f"HTTP {code} from {ep}; the SSL exemption settings could not be read")
        if not isinstance(data, (dict, list)):
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
                    elif isinstance(v, str) and v.strip():
                        # A switch (enableEvaluatePolicyOnGlobalSSLBypass: false), a
                        # number or nothing is a setting, not an exempted value.
                        out["items"].append({"source": ep, "field": k, "value": v[:300]})
    out["count"] = len(out["items"])
    return out


def _fetch_urlfilter_bypass(client) -> Dict[str, Any]:
    rules, code = _read_list(client, "/zia/urlFilteringRules")
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
    rules, code = _read_list(client, "/zia/firewallFilteringRules")
    allow = [_normalize_rule(r, "firewall_rule")
             for r in rules if _action_of(r) in BYPASS_ACTIONS]
    return {
        "count": len(allow),
        "total_rules": len(rules),
        "endpoint": "/zia/firewallFilteringRules",
        "http_status": code,
        "items": allow,
    }


def _fetch_dlp_bypass(client) -> Dict[str, Any]:
    rules, code = _read_list(client, "/zia/webDlpRules")
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

    # ── Build a consolidated "All URLs Bypassed" bucket — this is what
    # most auditors actually want: one flat list combining every URL
    # that is exempted, whether explicit (in a rule's urls field),
    # inherited via a URL category, or bypassed at the ZCC layer.
    all_urls = _mk()
    def _merge_into_all(bucket_src, origin_tag):
        for value, entry in bucket_src.items():
            for rule_ctx in entry.get("rules") or []:
                _push(all_urls, value, {**rule_ctx, "origin": origin_tag})
    _merge_into_all(urls,           "explicit (rule)")
    _merge_into_all(inherited_urls, "inherited (category)")
    _merge_into_all(zcc_domains,    "zcc (domain bypass)")

    return {
        "all_urls_bypassed":   _as_list(all_urls),          # ← consolidated URL list
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

# What each section reads, keyed as data_flow.PATH_SECTIONS keys the parts
# of the tenant ("firewall" is this report's own: the firewall filtering
# rules, in scope with the ZIA platform scope).
SECTION_PARTS = {"ssl_bypass_rules": "ssl", "ssl_exemptions": "ssl", "url_filter_allow": "url",
                 "firewall_allow": "firewall", "dlp_allow": "dlp", "zcc": "zcc"}
NOTHING_IN_SCOPE = ("Nothing the Bypass report reads is in scope — on the Scope page tick ZCC, DLP or ZIA platform "
                    "and mark the channels you run on Zscaler, then run the report again.")


def bypass_scope(scopes: Any, channels: Any) -> Dict[str, Any]:
    """What the Bypass report may read for the Scope page's selection:
    data_flow.path_scope (SSL inspection, URL filtering, Web DLP, Client
    Connector) plus the firewall filtering rules when the ZIA platform
    scope is ticked. Returns {read, not_in_scope, key, summary}. Pure:
    never reads a tenant."""
    import data_flow
    sel = data_flow.path_scope(scopes, channels)
    parts = set(SECTION_PARTS.values())
    read = [k for k in sel["read"] if k in parts]
    out = {k: v for k, v in sel["not_in_scope"].items() if k in parts}
    if "zia_extras" in sel["scopes"]:
        read.append("firewall")
    else:
        out["firewall"] = "Not in scope: ZIA platform is not ticked on the Scope page, so the firewall filtering rules were not read."
    return {"read": read, "not_in_scope": out, "key": ",".join(sorted(read)), "scopes": sel["scopes"], "channels": sel["channels"], "declaration": channels, "read_blocked": sel.get("read_blocked", {}), "required_controls": sel.get("required_controls", []),
            "summary": NOTHING_IN_SCOPE if not read else "Reads only what is in scope on the Scope page."}


def generate_bypass_report(client, scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Produce the bypass inventory. Read-only.

    `scope` (bypass_scope of the Scope page's selection) limits what is
    read: a section whose part is not in its `read` is not read and says
    `not_in_scope` (never an empty "nothing here"). Without `scope` every
    section is read (tools, tests). Raises ValueError when nothing is in
    scope.

    Every section is independently wrapped so a single failing endpoint
    never prevents the whole report from returning. The top-level is
    also wrapped — if anything unexpected goes wrong, we still return a
    valid (degraded) report with a diagnostics field so the GUI can
    render something useful.
    """
    import traceback as _tb
    start = datetime.now(timezone.utc)
    import dlp_analysis
    client = dlp_analysis.read_once(client)
    required_controls = dlp_analysis.inspect(client, (scope or {}).get("scopes", []), (scope or {}).get("declaration", {}))
    blocked = (scope or {}).get("read_blocked") or {}
    sections: Dict[str, Any] = {}
    diagnostics: List[Dict[str, Any]] = []
    parts = set(SECTION_PARTS.values())
    read = parts if scope is None else {k for k in (scope.get("read") or []) if k in parts}
    why = {} if scope is None else dict(scope.get("not_in_scope") or {})
    if not read:
        raise ValueError(NOTHING_IN_SCOPE)

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

    fetchers = {"ssl_bypass_rules": _fetch_ssl_bypass, "ssl_exemptions": _fetch_ssl_exemptions, "url_filter_allow": _fetch_urlfilter_bypass,
                "firewall_allow": _fetch_firewall_bypass, "dlp_allow": _fetch_dlp_bypass, "zcc": _fetch_zcc_bypasses}
    not_in_scope: Dict[str, str] = {}
    for key, fetch in fetchers.items():
        part = SECTION_PARTS[key]
        if part in blocked:
            sections[key] = {"status": "unverified", "error": blocked[part], "items": [], "count": None}
            diagnostics.append({"section": key, "error": blocked[part], "error_type": "unmet_dependency"})
        elif part in read:
            sections[key] = _safe(key, lambda fetch=fetch: fetch(client))
            if sections[key].get("error") and not sections[key].get("status"):
                sections[key]["status"] = "unverified"
            probed = sections[key].get("endpoints_probed") if key == "zcc" else None
            if probed and not any(int(p.get("status") or 0) == 200 for p in probed):
                sections[key]["status"] = "unverified"
                diagnostics.append({"section": key, "error_type": "unreadable",
                                    "error": "No Client Connector endpoint answered (" + ", ".join(f"{p.get('endpoint')}: {p.get('status')}" for p in probed)[:240] + ")"})
        else:
            not_in_scope[key] = why.get(part) or "Not in scope on the Scope page, so it was not read."
            sections[key] = {"not_in_scope": not_in_scope[key], "items": [], "count": 0}

    # Fetch URL category catalog once — used to expand category refs in
    # bypass rules into their inherited URLs (only when a ZIA rule section is read).
    if read & {"ssl", "url", "firewall", "dlp"}:
        url_cat_lookup = _safe("url_category_lookup", lambda: _fetch_url_category_lookup(client))
    else:
        url_cat_lookup = {}
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
        "generated_at": start.isoformat(), "required_controls": required_controls,
        "elapsed_seconds": round((datetime.now(timezone.utc) - start).total_seconds(), 2),
        "report_version": 3,
        "summary": summary,
        "risk_flags": risky,
        "aggregated": aggregated,    # consolidated global lists of bypassed items
        "sections": sections,
        "diagnostics": diagnostics,  # empty list = clean run; populated = something failed per-section
        "not_in_scope": not_in_scope,  # section -> why it was not read (the Scope page left it out)
        **({"scope": {"read": sorted(read), "source": scope.get("source") or "", "key": scope.get("key") or ""}} if scope is not None else {}),
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
    w = csv_safe.writer(buf)
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
    out.append("# Zscaler Bypass / Non-Inspected Traffic Inventory\n")
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
            out.append(f"- **{md_safe.text(r['name'])}** ({md_safe.text(r['source'])} #{md_safe.text(r['id'])}, "
                       f"action {md_safe.code(r['action'])}) — {md_safe.text(r['reason'])}")
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
                row.append(md_safe.text(v or "", 80))   # tenant values: inert text, pipes escaped
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
                f"{md_safe.text(r.get('source', '?'))}#{md_safe.text(r.get('id', '?'))} '{md_safe.text(r.get('name', '?'))}'"
                for r in (it.get("rules") or [])[:6]
            )
            if len(it.get("rules") or []) > 6:
                rules_str += f", +{len(it['rules']) - 6} more"
            out.append(f"| {idx} | {md_safe.cell_code(it.get('value', ''), 120)} | {rules_str} |")
        out.append("")

    _agg_block("ALL URLs Bypassed (explicit + inherited + ZCC domain bypass)", "all_urls_bypassed", "URL")
    _agg_block("All Bypassed URL Categories", "url_categories", "URL Category")
    _agg_block("Explicitly-Listed URLs (from rule.urls / destinations / hostnames)", "urls", "URL")
    _agg_block("INHERITED URLs (from URL Categories)", "inherited_urls", "URL (via category)")
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
            # Category names, rule names, URLs and keywords are tenant text: inert.
            out.append(f"### {md_safe.text(cat.get('category'))} [{md_safe.text(typ)}]")
            where = f"{ref.get('source', '?')}#{ref.get('id', '?')}"
            out.append(f"_Referenced by {md_safe.code(where)} — **{md_safe.text(ref.get('name', '?'))}** "
                       f"(action {md_safe.code(ref.get('action', '?'))})_")
            if "note" in cat:
                out.append(f"> {md_safe.text(cat['note'])}\n")
            if urls:
                out.append(f"**URLs ({len(urls)}):**")
                for u in urls[:200]: out.append(f"- {md_safe.code(u, 300)}")
                if len(urls) > 200: out.append(f"- _...and {len(urls) - 200} more_")
            if db_urls:
                out.append(f"\n**DB-Categorized URLs ({len(db_urls)}):**")
                for u in db_urls[:200]: out.append(f"- {md_safe.code(u, 300)}")
                if len(db_urls) > 200: out.append(f"- _...and {len(db_urls) - 200} more_")
            if keywords:
                out.append(f"\n**Keywords ({len(keywords)}):** {', '.join(md_safe.code(k, 120) for k in keywords[:50])}")
            out.append("")
        if len(cats) > 100:
            out.append(f"_...and {len(cats) - 100} more categories. See JSON export for the complete list._\n")

    out.append("## Guidance\n")
    for g in report.get("guidance", []):
        out.append(f"- {g}")

    import dlp_analysis
    out.extend(dlp_analysis.markdown(report))
    return "\n".join(out)


# ── Word document export ─────────────────────────────────────────────

def to_docx(report: Dict[str, Any], output_path: str) -> str:
    """
    Render the bypass inventory as a Word document with Zscaler branding
    (accent blue #236BF5) matching the main assessment report style.

    Structure:
      1. Cover heading + generated-at + summary chip counts
      2. Risk flags (if any) — red callout box
      3. Aggregated Bypass Universe — the consolidated ALL-URLs-Bypassed
         list plus per-dimension breakdowns
      4. Per-section rule tables (SSL bypass, URL ALLOW, FW ALLOW, DLP allow)
      5. SSL exemptions (flat table)
      6. ZCC bypass sections (apps, processes, IPs, domains, trusted)
      7. URL Category Expansion Detail (shows inherited URLs per category)
      8. Guidance / best practices

    Returns the output path so callers can re-send it as a FileResponse.
    Raises ImportError if python-docx isn't installed.
    """
    from docx import Document
    from docx.shared import RGBColor

    ACCENT = RGBColor(0x23, 0x6B, 0xF5)   # Zscaler blue
    RED    = RGBColor(0xDC, 0x26, 0x26)
    AMBER  = RGBColor(0xF5, 0x9E, 0x0B)
    DIM    = RGBColor(0x64, 0x74, 0x8B)

    def _safe_style(doc, candidates):
        for name in candidates:
            try:
                return doc.styles[name]
            except KeyError:
                continue
        return None

    import xlsx_writer
    report = xlsx_writer.clean_tree(report)   # python-docx refuses XML-illegal characters
    doc = Document()

    # ── Cover ────────────────────────────────────────────────────
    h = doc.add_heading("Zscaler Bypass / Non-Inspected Traffic Inventory", level=0)
    if h.runs:
        h.runs[0].font.color.rgb = ACCENT
    p = doc.add_paragraph()
    p.add_run(f"Generated: {report.get('generated_at','?')}").font.color.rgb = DIM
    p.add_run(f"   ·   Scan time: {report.get('elapsed_seconds', 0)}s").font.color.rgb = DIM

    # ── Summary chips ────────────────────────────────────────────
    summary = report.get("summary") or {}
    s_table = doc.add_table(rows=1, cols=2)
    s_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Table Grid"])
    s_table.rows[0].cells[0].text = "Dimension"
    s_table.rows[0].cells[1].text = "Count"
    for c in s_table.rows[0].cells:
        if c.paragraphs[0].runs:
            c.paragraphs[0].runs[0].bold = True
    dim_labels = [
        ("ssl_bypass_rules",  "SSL Inspection Bypass Rules"),
        ("ssl_exemptions",    "SSL Exemptions (categories/URLs)"),
        ("url_filter_allow",  "URL Filtering ALLOW Rules"),
        ("firewall_allow",    "Firewall ALLOW Rules"),
        ("dlp_allow",         "DLP ALLOW / BYPASS Rules"),
        ("zcc_apps",          "ZCC — Bypassed Apps"),
        ("zcc_processes",     "ZCC — Bypassed Processes"),
        ("zcc_ips",           "ZCC — Bypassed IPs"),
        ("zcc_domains",       "ZCC — Bypassed Domains"),
        ("zcc_trusted_nets",  "ZCC — Trusted Networks"),
    ]
    for key, label in dim_labels:
        r = s_table.add_row()
        r.cells[0].text = label
        r.cells[1].text = str(summary.get(key, 0))
    r = s_table.add_row()
    r.cells[0].text = "TOTAL BYPASS ITEMS"
    r.cells[1].text = str(summary.get("total_bypass_items", 0))
    for c in r.cells:
        if c.paragraphs[0].runs:
            c.paragraphs[0].runs[0].bold = True
            c.paragraphs[0].runs[0].font.color.rgb = ACCENT

    doc.add_paragraph()

    # ── Risk flags ───────────────────────────────────────────────
    risks = report.get("risk_flags") or []
    if risks:
        doc.add_heading(f"Risk Flags ({len(risks)})", level=1)
        warn = doc.add_paragraph()
        wrun = warn.add_run(
            "Globally-scoped enabled bypass rules apply to every user. Auditors "
            "flag these first — review for business justification and consider "
            "scoping to specific users / groups / locations."
        )
        wrun.font.color.rgb = RED
        wrun.bold = True
        for rf in risks:
            p = doc.add_paragraph(style="List Bullet")
            p.add_run(f"{rf.get('name','?')} ").bold = True
            p.add_run(
                f"— {rf.get('source','?')} #{rf.get('id','?')}, "
                f"action {rf.get('action','?')}. {rf.get('reason','')}"
            )

    # ── Aggregated Bypass Universe ───────────────────────────────
    agg = report.get("aggregated") or {}
    doc.add_heading("Aggregated Bypass Universe", level=1)
    intro = doc.add_paragraph()
    intro.add_run(
        "Every URL, cloud app, category, and IP exempted from Zscaler "
        "inspection anywhere in the tenant — deduplicated and traced to "
        "the rule that caused the exemption. URL category references are "
        "expanded into their constituent URLs."
    ).italic = True

    def _add_agg_table(heading, bucket_key, value_label):
        bucket = agg.get(bucket_key) or {}
        items = bucket.get("items") or []
        doc.add_heading(f"{heading} ({len(items)})", level=2)
        if not items:
            doc.add_paragraph("(no items)").runs[0].font.color.rgb = DIM
            return
        t = doc.add_table(rows=1, cols=4)
        t.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Table Grid"])
        t.rows[0].cells[0].text = "#"
        t.rows[0].cells[1].text = value_label
        t.rows[0].cells[2].text = "Refs"
        t.rows[0].cells[3].text = "Referenced by (source#id)"
        for c in t.rows[0].cells:
            if c.paragraphs[0].runs:
                c.paragraphs[0].runs[0].bold = True
        for i, it in enumerate(items[:500], 1):
            row = t.add_row()
            row.cells[0].text = str(i)
            row.cells[1].text = str(it.get("value", ""))[:200]
            row.cells[2].text = str(it.get("count", 0))
            refs = (it.get("rules") or [])[:6]
            refs_str = ", ".join(
                f"{(r.get('source') or '?').split('.')[-1]}#{r.get('id','?')}"
                for r in refs
            )
            if len(it.get("rules") or []) > 6:
                refs_str += f" (+{len(it['rules']) - 6} more)"
            row.cells[3].text = refs_str
        if len(items) > 500:
            doc.add_paragraph(f"…and {len(items) - 500} more (see JSON/CSV export for the complete list).").runs[0].font.color.rgb = DIM

    _add_agg_table("ALL URLs Bypassed (explicit + inherited + ZCC domain bypass)", "all_urls_bypassed", "URL")
    _add_agg_table("Bypassed URL Categories", "url_categories", "Category")
    _add_agg_table("Explicitly-Listed URLs (from rule.urls / destinations / hostnames)", "urls", "URL")
    _add_agg_table("Inherited URLs (from URL Categories)", "inherited_urls", "URL (via category)")
    _add_agg_table("Bypassed Cloud Applications", "cloud_applications", "Cloud App")
    _add_agg_table("Bypassed Cloud App Categories", "cloud_app_categories", "Category")
    _add_agg_table("Bypassed Destination IPs", "dest_ips", "IP / CIDR")
    _add_agg_table("Bypassed Destination IP Groups", "dest_ip_groups", "Group")

    doc.add_page_break()

    # ── Per-section rule tables ──────────────────────────────────
    doc.add_heading("Rule-Level Detail by Section", level=1)
    rule_sections = [
        ("ssl_bypass_rules", "SSL Inspection Bypass Rules"),
        ("url_filter_allow", "URL Filtering ALLOW Rules"),
        ("firewall_allow",   "Firewall ALLOW Rules"),
        ("dlp_allow",        "DLP ALLOW / BYPASS Rules"),
    ]
    for key, label in rule_sections:
        sec = (report.get("sections") or {}).get(key) or {}
        items = sec.get("items") or []
        count_display = f"{len(items)}"
        total = sec.get("total_rules") or sec.get("total_ssl_rules")
        if total is not None:
            count_display = f"{len(items)} of {total}"
        doc.add_heading(f"{label} ({count_display})", level=2)
        if not items:
            doc.add_paragraph("(no items)").runs[0].font.color.rgb = DIM
            continue
        t = doc.add_table(rows=1, cols=5)
        t.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Table Grid"])
        headers = ["Rule ID", "Name", "Action", "State", "Scope"]
        for i, h_label in enumerate(headers):
            t.rows[0].cells[i].text = h_label
            if t.rows[0].cells[i].paragraphs[0].runs:
                t.rows[0].cells[i].paragraphs[0].runs[0].bold = True
        for it in items[:200]:
            row = t.add_row()
            row.cells[0].text = str(it.get("id", ""))
            row.cells[1].text = str(it.get("name", ""))[:120]
            row.cells[2].text = str(it.get("action", ""))
            row.cells[3].text = str(it.get("state", ""))
            row.cells[4].text = str(it.get("scope", ""))[:80]
        if len(items) > 200:
            doc.add_paragraph(f"…and {len(items) - 200} more.").runs[0].font.color.rgb = DIM

    # ── SSL Exemptions (flat) ────────────────────────────────────
    exm = (report.get("sections") or {}).get("ssl_exemptions") or {}
    exm_items = exm.get("items") or []
    doc.add_heading(f"SSL Exemptions / Do-Not-Inspect ({len(exm_items)})", level=2)
    if exm_items:
        t = doc.add_table(rows=1, cols=3)
        t.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Table Grid"])
        for i, h_label in enumerate(["Source Endpoint", "Field", "Value"]):
            t.rows[0].cells[i].text = h_label
            if t.rows[0].cells[i].paragraphs[0].runs:
                t.rows[0].cells[i].paragraphs[0].runs[0].bold = True
        for it in exm_items[:200]:
            row = t.add_row()
            row.cells[0].text = str(it.get("source", ""))[:80]
            row.cells[1].text = str(it.get("field", "") or it.get("label", ""))
            row.cells[2].text = str(it.get("value", ""))[:200]
    else:
        doc.add_paragraph("(none)").runs[0].font.color.rgb = DIM

    # ── ZCC bypasses ─────────────────────────────────────────────
    zcc = (report.get("sections") or {}).get("zcc") or {}
    doc.add_heading("ZCC / Mobile Portal Bypass Lists", level=1)
    zcc_sections = [
        ("apps",             "App Bypass",         ["profile", "name", "path", "os"]),
        ("processes",        "Process Bypass",     ["profile", "name"]),
        ("ips",              "IP Bypass",          ["profile", "value"]),
        ("domains",          "Domain Bypass",      ["profile", "value"]),
        ("trusted_networks", "Trusted Networks",   ["profile", "value"]),
    ]
    for subkey, label, cols in zcc_sections:
        sub = (zcc.get(subkey) or {})
        items = sub.get("items") or []
        doc.add_heading(f"ZCC — {label} ({len(items)})", level=2)
        if not items:
            doc.add_paragraph("(no items)").runs[0].font.color.rgb = DIM
            continue
        t = doc.add_table(rows=1, cols=len(cols))
        t.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Table Grid"])
        for i, col in enumerate(cols):
            t.rows[0].cells[i].text = col.replace("_", " ").title()
            if t.rows[0].cells[i].paragraphs[0].runs:
                t.rows[0].cells[i].paragraphs[0].runs[0].bold = True
        for it in items[:200]:
            row = t.add_row()
            for i, col in enumerate(cols):
                row.cells[i].text = str(it.get(col, ""))[:150]

    # ── Per-category expansion detail ────────────────────────────
    cats = (agg.get("category_expansion") or [])
    if cats:
        doc.add_page_break()
        doc.add_heading("URL Category Expansion Detail", level=1)
        doc.add_paragraph(
            "Per-category breakdown showing which URLs each referenced "
            "category contributes to the effective bypass list. Custom "
            "categories enumerate their URLs; predefined (Zscaler-maintained) "
            "categories are marked and their URL lists are not API-accessible."
        ).runs[0].italic = True
        for cat in cats[:100]:
            doc.add_heading(f"{cat.get('category','?')}  [{cat.get('type','?')}]", level=3)
            rule = cat.get("referenced_by_rule") or {}
            p = doc.add_paragraph()
            p.add_run(
                f"Referenced by {rule.get('source','?')}#{rule.get('id','?')} — "
                f"{rule.get('name','?')} (action {rule.get('action','?')})"
            ).font.color.rgb = DIM
            if cat.get("note"):
                np = doc.add_paragraph(cat["note"])
                if np.runs:
                    np.runs[0].font.color.rgb = AMBER
            urls = (cat.get("urls") or []) + (cat.get("db_urls") or [])
            if urls:
                p = doc.add_paragraph()
                p.add_run(f"URLs ({len(urls)}): ").bold = True
                p.add_run(", ".join(urls[:80]))
                if len(urls) > 80:
                    p.add_run(f"  …and {len(urls) - 80} more").italic = True
            kws = cat.get("keywords") or []
            if kws:
                p = doc.add_paragraph()
                p.add_run(f"Keywords ({len(kws)}): ").bold = True
                p.add_run(", ".join(str(k) for k in kws[:50]))
        if len(cats) > 100:
            doc.add_paragraph(f"…and {len(cats) - 100} more categories (see JSON export for the complete list).").runs[0].font.color.rgb = DIM

    # ── Guidance ─────────────────────────────────────────────────
    doc.add_heading("Guidance", level=1)
    for g in (report.get("guidance") or []):
        doc.add_paragraph(g, style="List Bullet")

    doc.save(output_path)
    return output_path
