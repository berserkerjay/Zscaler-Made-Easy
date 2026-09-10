"""Data Flow Map: the exact path a transaction takes through the tenant.

For a destination (a cloud application, a URL category or a hostname) and
a device context (platform, on or off a trusted network), the tracer walks
every hop the tenant's configuration puts in the way and says what
happens at each one, using the same objects the portal uses:

  device ─ Client Connector app profile (bypasses, Endpoint DLP, cert)
         ─ forwarding profile for that network (tunnel / PAC / none)
         ─ PAC file (DIRECT statements)
         ─ ZIA SSL inspection (decrypt / leave encrypted / block)
         ─ URL filtering (allow / block / caution / isolate)
         ─ Cloud App Control (per-action controls for the app)
         ─ File Type Control (upload of bulk formats)
         ─ Inline Web DLP (which rules see the content, monitor or enforce)

and, beside it, the channels that do not ride the tunnel: Endpoint DLP on
the device, SaaS Security API at rest, Outbound Email DLP.

Every hop carries the rule that decided it and, when it weakens the
policy set, a weak point with a severity and a fix. Policy packs are
overlaid: for each pack, which of its rules sit on the path and whether
they are enforcing, monitoring, disabled or missing.

Read-only. The schema of Client Connector profiles varies by tenant and
version, so the profile readers are keyword based (like bypass_report)
and the raw value is kept next to every interpretation.
"""
from __future__ import annotations

import fnmatch
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from bypass_report import _fetch_url_category_lookup, _fetch_zcc_bypasses, _rules_to_list
from ssl_flow import (TRAFFIC_CLASSES, _fetch_app_catalogue, _fetch_rules, _matches, _names, _scope, _sort_key,
                      _upper, normalize_dlp_rule, normalize_ssl_rule)

# ── Contexts ──────────────────────────────────────────────────────────
NETWORKS = [
    {"key": "off", "label": "Off network (remote)", "what": "Not on a trusted network and no VPN: the forwarding profile's off-trusted-network action applies."},
    {"key": "on", "label": "On trusted network (office)", "what": "The device sees a trusted network: the on-trusted-network action applies (often tunnel, sometimes none with a GRE/IPsec site tunnel)."},
    {"key": "vpn", "label": "On VPN", "what": "A VPN trusted network is detected: the VPN action applies."},
]
PLATFORMS = ["windows", "macos", "ios", "android", "linux"]

DECRYPT_ACTIONS = {"DECRYPT"}
NO_DECRYPT_ACTIONS = {"DO_NOT_DECRYPT", "DO_NOT_INSPECT", "BYPASS"}
BLOCK_ACTIONS = {"BLOCK", "BLOCK_RESET", "DROP"}

UPLOAD_VERBS = ("UPLOAD", "SHARE", "SEND", "ATTACHMENT_SEND", "POST", "EDIT", "CREATE")


# ── Client Connector readers ──────────────────────────────────────────
def _hostname_of(dest: str) -> str:
    d = (dest or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    return d.split("/")[0].split(":")[0]


def _domain_hit(patterns: Iterable[str], host: str) -> Optional[str]:
    if not host:
        return None
    for p in patterns:
        pat = str(p or "").strip().lower()
        if not pat:
            continue
        pat_host = _hostname_of(pat)
        if fnmatch.fnmatch(host, pat_host) or host == pat_host.lstrip("*.") or host.endswith("." + pat_host.lstrip("*.")):
            return str(p)
    return None


_MODE_RULES = [
    (re.compile(r"tunnel.*2|z ?tunnel ?2|packet|ztunnel2|tunnel2", re.I), "Z-Tunnel 2.0", "tunnel"),
    (re.compile(r"local ?proxy|twlp|tunnel.*proxy", re.I), "Tunnel with local proxy", "tunnel"),
    (re.compile(r"tunnel.*1|ztunnel1|tunnel1|^tunnel$", re.I), "Z-Tunnel 1.0", "tunnel"),
    (re.compile(r"enforce.*proxy|proxy.*enforce|\bpac\b", re.I), "Enforce proxy (PAC)", "pac"),
    (re.compile(r"^none$|^off$|disable|no ?forward|direct", re.I), "None (direct)", "none"),
]
# Numeric codes seen in the Client Connector portal API.
_MODE_CODES = {"0": ("None (direct)", "none"), "1": ("Z-Tunnel 1.0", "tunnel"), "2": ("Enforce proxy (PAC)", "pac"),
               "3": ("Tunnel with local proxy", "tunnel"), "4": ("Z-Tunnel 2.0", "tunnel")}


def classify_mode(raw: Any) -> Tuple[str, str]:
    """('Z-Tunnel 2.0', 'tunnel') from whatever the profile says."""
    s = str(raw if raw is not None else "").strip()
    if s in _MODE_CODES:
        return _MODE_CODES[s]
    for rx, label, kind in _MODE_RULES:
        if rx.search(s):
            return label, kind
    return (f"unknown ({s})" if s else "not set"), "unknown"


_NET_RULES = [(re.compile(r"vpn", re.I), "vpn"), (re.compile(r"off|untrust|not ?trust", re.I), "off"), (re.compile(r"on|trust", re.I), "on")]
_NET_CODES = {"0": "off", "1": "on", "2": "vpn"}


def classify_network(raw: Any) -> str:
    s = str(raw if raw is not None else "").strip()
    if s in _NET_CODES:
        return _NET_CODES[s]
    for rx, key in _NET_RULES:
        if rx.search(s):
            return key
    return "any"


def forwarding_actions(profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """{network key: {mode_label, mode_kind, raw}} from a forwarding
    profile, reading any list of dicts that pairs a network type with a
    tunnel/action/proxy setting. A profile with a single top-level mode
    applies it to every network."""
    out: Dict[str, Dict[str, Any]] = {}
    for k, v in profile.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v) and re.search(r"action|forward|network|tunnel", str(k), re.I):
            for entry in v:
                net_raw = next((entry[kk] for kk in entry if re.search(r"network", str(kk), re.I)), None)
                mode_raw = next((entry[kk] for kk in entry if re.search(r"tunnel|action|forward|proxy|mode", str(kk), re.I) and not re.search(r"network|dns|timeout|port|id$", str(kk), re.I)), None)
                if mode_raw is None:
                    continue
                label, kind = classify_mode(mode_raw)
                out[classify_network(net_raw)] = {"mode_label": label, "mode_kind": kind, "raw": {"network": net_raw, "mode": mode_raw}}
    if not out:
        for kk in profile:
            if re.search(r"tunnel|forward|mode", str(kk), re.I) and not isinstance(profile[kk], (list, dict)) and profile[kk] not in (None, ""):
                label, kind = classify_mode(profile[kk])
                if kind != "unknown":
                    out["any"] = {"mode_label": label, "mode_kind": kind, "raw": {"field": kk, "mode": profile[kk]}}
                    break
    return out


def read_client_connector(client) -> Dict[str, Any]:
    """App profiles, forwarding profiles, trusted networks and PAC files in
    one normalised structure. Errors are recorded, never raised."""
    out: Dict[str, Any] = {"app_profiles": [], "forwarding_profiles": [], "trusted_networks": [], "pac_files": [], "errors": []}
    try:
        data, code = client.get("/zcc/webPolicies")
        if code != 200:
            out["errors"].append(f"/zcc/webPolicies: HTTP {code}")
        for p in _rules_to_list(data) if code == 200 else []:
            if not isinstance(p, dict):
                continue
            plat = str(p.get("os") or p.get("platform") or p.get("osType") or p.get("device_type") or "").lower()
            plat = {"win": "windows", "windows": "windows", "mac": "macos", "macos": "macos", "osx": "macos", "ios": "ios", "android": "android", "linux": "linux"}.get(plat, plat or "all")
            domains, apps, processes, ips, vpn = [], [], [], [], []
            for k, v in p.items():
                kl = str(k).lower()
                if not isinstance(v, list) or not v:
                    continue
                vals = [x.get("name") or x.get("url") or x.get("domain") or x.get("ip") or x.get("path") or json.dumps(x)[:80] if isinstance(x, dict) else str(x) for x in v]
                if re.search(r"vpn", kl):
                    vpn += vals
                elif re.search(r"process", kl):
                    processes += vals
                elif re.search(r"bypassapp|appbypass|applicationbypass|predefinedbypass|custombypass", kl):
                    apps += vals
                elif re.search(r"ipexclu|excludeip|bypassip|ipbypass|destinationexclu|nonzscaler", kl):
                    ips += vals
                elif re.search(r"domain|hostname|bypassurl|url|tunnelbypass", kl) and re.search(r"bypass|exclu|exempt", kl):
                    domains += vals
            out["app_profiles"].append({
                "id": p.get("id"), "name": p.get("name") or p.get("policyName") or f"Profile {p.get('id', '?')}",
                "platform": plat, "active": bool(p.get("active", True)), "priority": p.get("ruleOrder") or p.get("priority"),
                "forwarding_profile": p.get("forwardingProfileName") or p.get("forwardingProfileId") or p.get("forwardingProfile"),
                "pac_url": p.get("pacUrl") or p.get("customPacUrl") or p.get("pac_url"),
                "strict_enforcement": bool(p.get("strictEnforcement") or p.get("strictMode")),
                "endpoint_dlp": bool(p.get("installEndpointDlp") or p.get("endpointDlpEnabled") or p.get("zdpEnabled")),
                "ssl_cert": bool(p.get("sslCertInstall") or p.get("installSslCert") or p.get("sslCertificateEnabled")),
                "bypass": {"domains": domains, "apps": apps, "processes": processes, "ips": ips, "vpn_gateways": vpn},
                "groups": _names(p.get("groups") or p.get("groupNames") or []),
            })
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"/zcc/webPolicies: {e}")
    try:
        data, code = client.get("/zcc/forwardingProfiles")
        if code != 200:
            out["errors"].append(f"/zcc/forwardingProfiles: HTTP {code}")
        for p in _rules_to_list(data) if code == 200 else []:
            if isinstance(p, dict):
                out["forwarding_profiles"].append({"id": p.get("id"), "name": p.get("name") or f"Forwarding profile {p.get('id', '?')}",
                                                   "actions": forwarding_actions(p),
                                                   "trusted_networks": _names(p.get("trustedNetworks") or p.get("trustedNetworkNames") or []),
                                                   "pac_url": p.get("pacUrl") or p.get("customPacUrl") or p.get("forwardingProfilePacUrl")})
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"/zcc/forwardingProfiles: {e}")
    try:
        data, code = client.get("/zcc/trustedNetworks")
        for t in _rules_to_list(data) if code == 200 else []:
            if isinstance(t, dict):
                out["trusted_networks"].append({"id": t.get("id"), "name": t.get("name") or t.get("networkName"),
                                                "conditions": {k: v for k, v in t.items() if re.search(r"dns|ssid|ip|hostname|server|condition", str(k), re.I) and v}})
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"/zcc/trustedNetworks: {e}")
    try:
        data, code = client.get("/zia/pacFiles")
        for f in _rules_to_list(data) if code in (200, 204) else []:
            if isinstance(f, dict):
                content = str(f.get("pacContent") or f.get("content") or f.get("pacScript") or "")
                out["pac_files"].append({"id": f.get("id"), "name": f.get("name"), "url": f.get("pacUrl") or f.get("url"),
                                         "direct_hosts": _pac_direct_hosts(content), "has_content": bool(content)})
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"/zia/pacFiles: {e}")
    return out


_PAC_LINE = re.compile(r"(shExpMatch|dnsDomainIs|localHostOrDomainIs|isInNet)\s*\(\s*\w+\s*,\s*[\"']([^\"']+)[\"']", re.I)


def _pac_direct_hosts(content: str) -> List[str]:
    """Hostname patterns a PAC file sends DIRECT (never to Zscaler)."""
    out: List[str] = []
    if not content:
        return out
    for block in re.split(r"\breturn\b", content):
        pass
    for m in re.finditer(r"if\s*\((?P<cond>[^{]*)\)\s*\{?\s*return\s+[\"']DIRECT[\"']", content, re.I | re.S):
        for h in _PAC_LINE.finditer(m.group("cond")):
            out.append(h.group(2))
    return sorted(set(out))


# ── ZIA readers ───────────────────────────────────────────────────────
def _norm_generic(r: Dict[str, Any]) -> Dict[str, Any]:
    """URL filtering / File Type Control / Cloud App Control rule → common shape."""
    action = r.get("action")
    if isinstance(action, dict):
        action = action.get("type") or action.get("name")
    actions = [str(a).upper() for a in (r.get("actions") or [])]
    state = str(r.get("state") or "ENABLED").upper()
    return {
        "id": r.get("id"), "name": r.get("name") or f"rule {r.get('id')}", "order": r.get("order"), "rank": r.get("rank"),
        "state": state, "enabled": state == "ENABLED",
        "action": str(action or r.get("filteringAction") or r.get("filtering_action") or "").upper(), "actions": actions,
        "url_categories": _upper(_names(r.get("urlCategories") or r.get("url_categories") or [])),
        "cloud_applications": _upper(_names(r.get("applications") or r.get("cloudApplications") or r.get("cloud_applications") or [])),
        "app_classes": _upper(_names(r.get("cloudAppClasses") or r.get("cloud_app_classes") or [])),
        "type": str(r.get("type") or "").upper(),
        "file_types": _upper(_names(r.get("fileTypes") or r.get("file_types") or [])),
        "operation": str(r.get("operation") or "").upper(),
        "request_methods": _upper(_names(r.get("requestMethods") or r.get("request_methods") or [])),
        "scope": _scope(r), "scoped": bool(_scope(r)),
        "protocols": _upper(_names(r.get("protocols") or [])),
    }


def read_zia(client) -> Dict[str, Any]:
    diagnostics: List[Dict[str, Any]] = []
    z: Dict[str, Any] = {"diagnostics": diagnostics}
    z["ssl"] = sorted((normalize_ssl_rule(r) for r in _fetch_rules(client, "/zia/sslInspectionRules", diagnostics, "SSL inspection rules")), key=_sort_key)
    z["dlp"] = [normalize_dlp_rule(r) for r in _fetch_rules(client, "/zia/webDlpRules", diagnostics, "Web DLP rules")]
    z["url"] = [_norm_generic(r) for r in _fetch_rules(client, "/zia/urlFilteringRules", diagnostics, "URL filtering rules")]
    z["cac"] = [_norm_generic(r) for r in _fetch_rules(client, "/zia/cloudApplicationRules", diagnostics, "Cloud App Control rules")]
    z["ftc"] = [_norm_generic(r) for r in _fetch_rules(client, "/zia/fileTypeControlRules", diagnostics, "File Type Control rules")]
    for key, ep, label in (("endpoint", "/zia/endpointDlpRules", "Endpoint DLP rules"), ("saas", "/zia/casbDlpRules", "SaaS Security API DLP rules"),
                           ("email", "/zia/emailDlpRules", "Outbound Email DLP rules")):
        rules = _fetch_rules(client, ep, diagnostics, label)
        z[key] = [{"id": r.get("id"), "name": r.get("name"), "state": str(r.get("state") or "ENABLED").upper(),
                   "action": str((r.get("action") or {}).get("type") if isinstance(r.get("action"), dict) else r.get("action") or "").upper(),
                   "engines": _names(r.get("dlpEngines") or r.get("dlp_engines") or r.get("engines") or [])} for r in rules if isinstance(r, dict)]
    classes = {cls for k in TRAFFIC_CLASSES for cls in k["app_classes"]}
    z["catalogue"] = _fetch_app_catalogue(client, classes, diagnostics)
    try:
        z["categories"] = _fetch_url_category_lookup(client)
    except Exception as e:  # noqa: BLE001
        z["categories"] = {}
        diagnostics.append({"section": "URL categories", "endpoint": "/zia/urlCategories", "error_type": type(e).__name__, "error": str(e)[:200]})
    for r in z["dlp"] + z["url"] + z["cac"] + z["ftc"] + z["ssl"]:
        r.setdefault("order", None)
    return z


# ── Destination resolution ────────────────────────────────────────────
def resolve_destination(dest: str, zia: Dict[str, Any]) -> Dict[str, Any]:
    """A cloud app name, a URL category id/name, a traffic class key or a
    hostname → {label, kind, categories, applications, app_classes, host}."""
    d = (dest or "").strip()
    du = d.upper().replace(" ", "_")
    for k in TRAFFIC_CLASSES:
        if d.lower() == k["key"] or d.lower() == k["label"].lower():
            apps = sorted({a for cls in k["app_classes"] for a in zia.get("catalogue", {}).get(cls, [])})
            return {"label": k["label"], "kind": "class", "categories": list(k["url_categories"]), "applications": apps,
                    "app_classes": list(k["app_classes"]), "host": "", "why": k.get("why", ""), "class": k["key"]}
    cats = zia.get("categories") or {}
    if du in cats or d in cats:
        c = cats.get(du) or cats.get(d)
        cid = c.get("id") or du
        return {"label": c.get("configured_name") or c.get("name") or du, "kind": "category", "categories": [str(cid).upper()],
                "applications": [], "app_classes": [], "host": "", "class": ""}
    for cls, apps in (zia.get("catalogue") or {}).items():
        if du in apps:
            return {"label": d, "kind": "application", "categories": [], "applications": [du], "app_classes": [cls], "host": "", "class": ""}
    if "." in d:
        host = _hostname_of(d)
        matched_cats = []
        for key, c in cats.items():
            if not isinstance(c, dict):
                continue
            if _domain_hit(list(c.get("urls") or []) + list(c.get("db_categorized_urls") or c.get("dbCategorizedUrls") or []), host):
                matched_cats.append(str(c.get("id") or key).upper())
        return {"label": host, "kind": "host", "categories": sorted(set(matched_cats)), "applications": [], "app_classes": [], "host": host, "class": ""}
    return {"label": d, "kind": "unknown", "categories": [du] if du else [], "applications": [du] if du else [], "app_classes": [], "host": "", "class": ""}


# ── Matching helpers ──────────────────────────────────────────────────
def _generic_matches(rule: Dict[str, Any], dest: Dict[str, Any]) -> Optional[str]:
    cats = set(dest["categories"]); apps = set(dest["applications"]); classes = set(dest["app_classes"])
    if rule["cloud_applications"] and apps & set(rule["cloud_applications"]):
        return "application"
    if rule["app_classes"] and classes & set(rule["app_classes"]):
        return "application class"
    if rule["url_categories"]:
        if cats & set(rule["url_categories"]):
            return "URL category"
        if "ANY" in rule["url_categories"] or "ALL" in rule["url_categories"]:
            return "any category"
        return None
    if not rule["cloud_applications"] and not rule["app_classes"] and not rule["url_categories"]:
        return "catch-all"
    return None


def _cac_matches(rule: Dict[str, Any], dest: Dict[str, Any]) -> Optional[str]:
    apps = set(dest["applications"]); classes = set(dest["app_classes"])
    if rule["cloud_applications"] and apps & set(rule["cloud_applications"]):
        return "application"
    if rule["app_classes"] and classes & set(rule["app_classes"]):
        return "application class"
    if rule["type"] and rule["type"] in classes and not rule["cloud_applications"]:
        return "application type"
    return None


def _hop(key: str, label: str, status: str, decided_by: Optional[Dict[str, Any]], detail: str,
         weak: Optional[Dict[str, Any]] = None, **extra) -> Dict[str, Any]:
    h = {"key": key, "label": label, "status": status, "decided_by": decided_by, "detail": detail, "weak_point": weak}
    h.update(extra)
    return h


def _weak(severity: str, title: str, fix: str) -> Dict[str, Any]:
    return {"severity": severity, "title": title, "fix": fix}


# ── The trace ─────────────────────────────────────────────────────────
def trace(dest: Dict[str, Any], network: str, platform: str, zcc: Dict[str, Any], zia: Dict[str, Any],
          packs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Pure: destination + context + tenant snapshot → hops, channels, packs."""
    hops: List[Dict[str, Any]] = []
    host = dest.get("host") or ""
    reaches_zscaler = True
    decrypted = False
    ends = None

    # 1. Client Connector app profile
    profiles = [p for p in zcc.get("app_profiles", []) if p.get("active", True) and (p["platform"] in (platform, "all", ""))]
    prof = sorted(profiles, key=lambda p: (p.get("priority") is None, p.get("priority") or 0))[0] if profiles else None
    if not prof:
        hops.append(_hop("zcc", "Client Connector app profile", "unknown", None,
                         f"No app profile found for {platform}; either Client Connector is not deployed to this platform or the profile list could not be read"
                         + (f" ({'; '.join(zcc.get('errors') or [])})" if zcc.get("errors") else "") + ".",
                         _weak("medium", "No Client Connector profile for this platform", "Deploy Client Connector with an app profile for this platform, or confirm the device reaches ZIA another way (GRE/IPsec site, PAC).")))
    else:
        b = prof["bypass"]
        hit_domain = _domain_hit(b["domains"], host) if host else None
        hit_app = next((a for a in b["apps"] if dest["label"].lower() in str(a).lower() or str(a).lower() in dest["label"].lower()), None) if dest["kind"] in ("application", "unknown") else None
        notes = []
        if not prof["strict_enforcement"]:
            notes.append("strict enforcement off (a user can disable the client)")
        if not prof["ssl_cert"]:
            notes.append("Zscaler root certificate not pushed by this profile (decryption fails unless deployed by MDM)")
        if hit_domain or hit_app:
            reaches_zscaler = False
            ends = "zcc"
            hops.append(_hop("zcc", "Client Connector app profile", "bypass", {"name": prof["name"], "id": prof["id"]},
                             f"'{prof['name']}' bypasses this destination ({'domain ' + hit_domain if hit_domain else 'application ' + str(hit_app)}): the traffic leaves the device directly and never reaches Zscaler.",
                             _weak("high", "Bypassed at the client", "Remove the bypass from the app profile, or accept that only Endpoint DLP can see this traffic and make sure it is enabled."),
                             profile=prof["name"], notes=notes))
        else:
            n_bypass = sum(len(v) for v in b.values())
            hops.append(_hop("zcc", "Client Connector app profile", "pass", {"name": prof["name"], "id": prof["id"]},
                             f"'{prof['name']}' ({prof['platform']}) forwards this destination; {n_bypass} bypass entries on the profile do not match it."
                             + (" Notes: " + "; ".join(notes) + "." if notes else ""),
                             _weak("medium", "Client can be disabled by the user", "Turn on strict enforcement (and a tamper/uninstall password) so a user cannot switch the client off.") if not prof["strict_enforcement"] else None,
                             profile=prof["name"], notes=notes))

    # 2. Forwarding profile
    fwd = None
    if prof:
        ref = prof.get("forwarding_profile")
        fps = zcc.get("forwarding_profiles", [])
        fwd = next((f for f in fps if ref is not None and (str(f.get("id")) == str(ref) or str(f.get("name")) == str(ref))), None) or (fps[0] if len(fps) == 1 else None)
    mode_kind = "tunnel"
    if reaches_zscaler:
        if not fwd:
            hops.append(_hop("forwarding", "Forwarding profile", "unknown", None,
                             "No forwarding profile could be matched to the app profile; assuming a tunnel. Check Administration > Forwarding Profile in the Client Connector portal.",
                             None))
        else:
            act = fwd["actions"].get(network) or fwd["actions"].get("any") or {}
            mode_kind = act.get("mode_kind", "unknown")
            label = act.get("mode_label", "not set")
            net_label = next(n["label"] for n in NETWORKS if n["key"] == network)
            if mode_kind == "none":
                reaches_zscaler = False; ends = "forwarding"
                hops.append(_hop("forwarding", "Forwarding profile", "bypass", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}' sets '{label}' for {net_label}: web traffic is not forwarded by the client on this network. Unless the site has a GRE/IPsec tunnel or a system PAC, it goes direct.",
                                 _weak("high" if network == "off" else "medium", f"No forwarding on {net_label.lower()}",
                                       "Set the forwarding action to Z-Tunnel 2.0 (or Tunnel with local proxy) for this network, or confirm the site tunnel covers it."),
                                 mode=label, raw=act.get("raw")))
            elif mode_kind == "pac":
                hops.append(_hop("forwarding", "Forwarding profile", "warn", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}' sets '{label}' for {net_label}: only proxied traffic reaches Zscaler; anything the PAC returns DIRECT for, and non-browser traffic, does not.",
                                 _weak("medium", "PAC-based forwarding", "Move to Z-Tunnel 2.0 so every port and protocol is forwarded, not just what the PAC catches."),
                                 mode=label, raw=act.get("raw")))
            elif mode_kind == "unknown":
                hops.append(_hop("forwarding", "Forwarding profile", "unknown", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}': the mode for {net_label} could not be interpreted ({label}). Raw value kept for review.", None, mode=label, raw=act.get("raw")))
            else:
                hops.append(_hop("forwarding", "Forwarding profile", "pass", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}' sets '{label}' for {net_label}: all traffic is tunnelled to ZIA.", None, mode=label, raw=act.get("raw")))

    # 3. PAC file DIRECT statements
    if reaches_zscaler and (mode_kind == "pac" or (prof and prof.get("pac_url")) or (fwd and fwd.get("pac_url"))):
        direct = []
        for f in zcc.get("pac_files", []):
            hit = _domain_hit(f.get("direct_hosts") or [], host) if host else None
            if hit:
                direct.append((f, hit))
        if direct:
            reaches_zscaler = False; ends = "pac"
            f, hit = direct[0]
            hops.append(_hop("pac", "PAC file", "bypass", {"name": f.get("name"), "id": f.get("id")},
                             f"PAC '{f.get('name')}' returns DIRECT for {hit}: the browser connects without Zscaler.",
                             _weak("high", "PAC sends this destination DIRECT", "Remove the DIRECT clause or narrow it; Zscaler recommends returning the ZIA proxy for everything except RFC1918 and explicit local hosts.")))
        else:
            pacs = zcc.get("pac_files", [])
            hops.append(_hop("pac", "PAC file", "pass", None,
                             f"{len(pacs)} PAC file(s) read; none sends this destination DIRECT" + (" (host-level check needs a hostname)." if not host else "."), None))

    if not reaches_zscaler:
        hops.append(_hop("zia", "ZIA", "skipped", None, "Never reached: nothing below applies to this traffic.", None))
    else:
        # 4. SSL inspection
        cats = dest["categories"]; apps = dest["applications"]
        klass = {"catch_all": dest["kind"] == "class" and dest.get("class") == "general", "key": dest.get("class") or "custom"}
        matching = [(r, _matches(r, klass, cats, apps)) for r in zia["ssl"] if r["enabled"]]
        matching = [(r, h) for r, h in matching if h]
        decided = next((r for r, h in matching if not r["scoped"]), None)
        exceptions = [r for r, h in matching if r["scoped"] and r is not decided]
        if decided is None:
            hops.append(_hop("ssl", "SSL inspection", "blind", None, "No enabled SSL inspection rule matches: the traffic is passed through encrypted and inline DLP cannot see its content.",
                             _weak("high", "Not decrypted", "Add a DECRYPT rule for this traffic (or a catch-all decrypt rule after Zscaler Recommended Exemptions).")))
        elif decided["decision"] == "inspected":
            decrypted = True
            hops.append(_hop("ssl", "SSL inspection", "pass", {"name": decided["name"], "id": decided["id"], "order": decided["order"]},
                             f"'{decided['name']}' (order {decided['order']}) decrypts this traffic." + (f" Scoped exemptions ahead of it: {', '.join(e['name'] for e in exceptions)}." if exceptions else ""),
                             _weak("medium", "Some users are exempt from decryption", "Confirm each exempted group is intended; Endpoint DLP should cover them.") if exceptions else None))
        elif decided["decision"] == "blocked":
            ends = "ssl"
            hops.append(_hop("ssl", "SSL inspection", "blocked", {"name": decided["name"], "id": decided["id"], "order": decided["order"]},
                             f"'{decided['name']}' blocks this traffic at the TLS handshake; nothing leaves.", None))
        else:
            hops.append(_hop("ssl", "SSL inspection", "blind", {"name": decided["name"], "id": decided["id"], "order": decided["order"]},
                             f"'{decided['name']}' (order {decided['order']}, {decided['action']}) leaves this traffic encrypted: inline DLP sees only the destination, not the content.",
                             _weak("high" if dest.get("class") not in ("privacy",) else "info", "Left encrypted",
                                   "Move a DECRYPT rule above this exemption, or narrow the exemption to the categories it is meant for.")))

        # 5. URL filtering
        if ends != "ssl":
            url_rules = sorted([r for r in zia["url"] if r["enabled"]], key=lambda r: (r.get("order") is None, r.get("order") or 0))
            hit = next(((r, m) for r in url_rules for m in [_generic_matches(r, dest)] if m and not r["scoped"]), None)
            if hit:
                r, m = hit
                if r["action"] in BLOCK_ACTIONS:
                    ends = "url"
                    hops.append(_hop("url", "URL filtering", "blocked", {"name": r["name"], "id": r["id"], "order": r["order"]},
                                     f"'{r['name']}' blocks it (matched on {m}).", None))
                else:
                    hops.append(_hop("url", "URL filtering", "pass" if r["action"] in ("ALLOW",) else "warn", {"name": r["name"], "id": r["id"], "order": r["order"]},
                                     f"'{r['name']}' → {r['action'] or 'ALLOW'} (matched on {m})" + (f", methods {', '.join(r['request_methods'])}" if r["request_methods"] else "") + ".",
                                     None))
            else:
                hops.append(_hop("url", "URL filtering", "pass", None, "No URL filtering rule matches; the default action applies (ALLOW unless the default rule was changed).", None))

        # 6. Cloud App Control
        if ends not in ("ssl", "url"):
            cac = [(r, _cac_matches(r, dest)) for r in zia["cac"] if r["enabled"]]
            cac = [(r, m) for r, m in cac if m]
            if not decrypted and cac:
                hops.append(_hop("cac", "Cloud App Control", "blind", {"name": cac[0][0]["name"], "id": cac[0][0]["id"]},
                                 f"{len(cac)} rule(s) target this application ('{cac[0][0]['name']}' …) but without decryption Zscaler cannot tell upload from browse: the per-action controls do not apply.",
                                 _weak("high", "App controls need decryption", "Decrypt this application class so upload/share/post controls take effect.")))
            elif cac:
                r, m = cac[0]
                blocks = [a for a in r["actions"] if any(v in a for v in UPLOAD_VERBS) and (a.startswith("BLOCK") or a.startswith("ISOLATE"))]
                allows = [a for a in r["actions"] if any(v in a for v in UPLOAD_VERBS) and a.startswith("ALLOW")]
                if blocks:
                    hops.append(_hop("cac", "Cloud App Control", "blocked", {"name": r["name"], "id": r["id"]},
                                     f"'{r['name']}' (matched on {m}) blocks {', '.join(b.replace('BLOCK_', '').lower() for b in blocks)}; other actions allowed.", None, actions=r["actions"]))
                else:
                    hops.append(_hop("cac", "Cloud App Control", "warn" if allows else "pass", {"name": r["name"], "id": r["id"]},
                                     f"'{r['name']}' (matched on {m}) allows {', '.join(a.replace('ALLOW_', '').lower() for a in allows) or 'the actions it lists'}: uploads are not stopped here, so content inspection is the last line.",
                                     _weak("medium", "Uploads allowed by app control", "Block upload/share on personal instances of this application, or use tenancy restrictions.") if allows else None, actions=r["actions"]))
            else:
                hops.append(_hop("cac", "Cloud App Control", "none", None, "No Cloud App Control rule targets this application; every action is allowed unless URL filtering or DLP stops it.",
                                 _weak("medium", "No app-level control", "Add a Cloud App Control rule for this application class (block upload/share on unsanctioned instances).") if dest["app_classes"] or dest["applications"] else None))

        # 7. File Type Control
        if ends not in ("ssl", "url"):
            ftc = [(r, _generic_matches(r, dest)) for r in zia["ftc"] if r["enabled"] and r["operation"] in ("UPLOAD", "", "ANY")]
            ftc = [(r, m) for r, m in ftc if m]
            if ftc:
                r, m = ftc[0]
                hops.append(_hop("ftc", "File Type Control", "blocked" if r["action"] in BLOCK_ACTIONS else "warn", {"name": r["name"], "id": r["id"]},
                                 f"'{r['name']}' → {r['action']} for {', '.join(t.replace('FTCATEGORY_', '').lower() for t in r['file_types'][:6])}{'…' if len(r['file_types']) > 6 else ''} on upload (matched on {m}).", None))
            else:
                hops.append(_hop("ftc", "File Type Control", "none", None, "No File Type Control rule limits uploads here; bulk formats (spreadsheets, archives, databases) rely on DLP alone.", None))

        # 8. Inline Web DLP
        if ends not in ("ssl", "url"):
            covering = []
            for r in zia["dlp"]:
                if not r["enabled"]:
                    continue
                if r["catch_all"] or (set(r["url_categories"]) & set(cats)) or (set(r["cloud_applications"]) & set(apps)):
                    covering.append(r)
            if not decrypted:
                hops.append(_hop("dlp", "Inline Web DLP", "blind", None,
                                 f"{len(covering)} enabled Web DLP rule(s) would apply, but the content is encrypted: engines never see it." if covering else "Encrypted, and no Web DLP rule applies either.",
                                 _weak("high", "Inline DLP is blind here", "Decrypt this traffic first; the DLP rules are in place but cannot run.") if covering else _weak("high", "Blind and ungoverned", "Decrypt this traffic and deploy a policy pack so a Web DLP rule covers it.")))
            elif not covering:
                hops.append(_hop("dlp", "Inline Web DLP", "none", None, "Decrypted, but no enabled Web DLP rule targets this traffic.",
                                 _weak("medium", "Ungoverned", "Deploy a policy pack (Deploy Policy Packs) or scope a Web DLP rule to this traffic; start in monitor mode.")))
            else:
                enforcing = [r for r in covering if r["enforcing"]]
                content = [r for r in covering if not r["without_content_inspection"]]
                status = "enforce" if enforcing else "monitor"
                hops.append(_hop("dlp", "Inline Web DLP", status, {"name": covering[0]["name"], "id": covering[0]["id"]},
                                 f"{len(covering)} rule(s) see this content: " + ", ".join(f"{r['name']} ({r['action']})" for r in covering[:5]) + ("…" if len(covering) > 5 else "")
                                 + (" None inspects content (without-content-inspection set)." if not content else ""),
                                 _weak("low", "Monitor only", "Once tuned, move the high-confidence rules to BLOCK.") if not enforcing else (_weak("medium", "Rules run without content inspection", "Clear the without-content-inspection flag on at least one rule with an engine.") if not content else None),
                                 rules=[{"name": r["name"], "action": r["action"], "enforcing": r["enforcing"], "engines": r.get("engines") or []} for r in covering]))

    # Parallel channels
    channels = {}
    ep = [r for r in zia.get("endpoint", []) if r["state"] == "ENABLED"]
    edlp_on = bool(prof and prof.get("endpoint_dlp"))
    channels["endpoint"] = {"label": "Endpoint DLP (on the device)", "status": ("enforce" if any(r["action"] in ("BLOCK", "CONFIRM") for r in ep) else "monitor") if (ep and edlp_on) else ("none" if not ep else "off"),
                            "detail": (f"{len(ep)} enabled rule(s)" + ("; the app profile installs Endpoint DLP." if edlp_on else "; but the app profile does not install Endpoint DLP, so they never run on this device.")) if ep else "No enabled Endpoint DLP rules.",
                            "weak_point": None if (ep and edlp_on) else _weak("high" if not reaches_zscaler else "medium", "Endpoint DLP not active on this device" if ep else "No Endpoint DLP rules",
                                                                            "Enable 'Install Endpoint DLP' on the app profile" if ep else "Deploy a pack with Endpoint DLP rules; it is the only control that sees bypassed traffic."),
                            "rules": [r["name"] for r in ep]}
    sa = [r for r in zia.get("saas", []) if r["state"] == "ENABLED"]
    channels["saas"] = {"label": "SaaS Security API (at rest)", "status": "monitor" if sa and all("REPORT" in r["action"] or r["action"] == "OFLCASB_DLP_ALLOW" for r in sa) else ("enforce" if sa else "none"),
                        "detail": f"{len(sa)} enabled rule(s) scan onboarded tenants at rest." if sa else "No enabled SaaS Security API DLP rules: data already in sanctioned SaaS is not scanned.",
                        "weak_point": None if sa else _weak("low", "No at-rest scanning", "Onboard the corporate SaaS tenants and deploy a pack with a SaaS file rule."), "rules": [r["name"] for r in sa]}
    em = [r for r in zia.get("email", []) if r["state"] == "ENABLED"]
    channels["email"] = {"label": "Outbound Email DLP", "status": "enforce" if any(r["action"] in ("BLOCK", "CUSTOMHEADERINSERTION") for r in em) else ("monitor" if em else "none"),
                         "detail": f"{len(em)} enabled rule(s) on outbound mail." if em else "No enabled Email DLP rules: mail leaves uninspected.",
                         "weak_point": None if em else _weak("medium", "Email not covered", "Onboard the Microsoft 365 / Gmail tenant and deploy a pack with an email rule."), "rules": [r["name"] for r in em]}

    # Policy pack overlay
    pack_rows = []
    for pk in packs or []:
        rows = []
        for pol in pk.get("policies", []):
            ch = pol.get("channel", "web")
            name = pol["name"]
            found = None
            pool = {"web": zia["dlp"], "endpoint": zia.get("endpoint", []), "saas": zia.get("saas", []), "email": zia.get("email", []),
                    "ssl": zia["ssl"], "url": zia["url"], "cloud_app": zia["cac"], "file_type": zia["ftc"]}.get(ch, [])
            for r in pool:
                if str(r.get("name")) == name:
                    found = r; break
            if not found:
                state = "missing"
            else:
                st = str(found.get("state") or "").upper()
                if st != "ENABLED":
                    state = "disabled"
                else:
                    act = str(found.get("action") or "").upper()
                    if ch == "web":
                        state = "enforcing" if found.get("enforcing") else "monitoring"
                    elif ch == "ssl":
                        state = "enforcing" if found.get("decision") == "inspected" else "monitoring"
                    elif ch == "cloud_app":
                        state = "enforcing" if any(a.startswith(("BLOCK", "ISOLATE")) for a in found.get("actions", [])) else "monitoring"
                    else:
                        state = "enforcing" if act in ("BLOCK", "CONFIRM", "CAUTION", "ISOLATE", "CUSTOMHEADERINSERTION") or (act.startswith("OFLCASB") and "REPORT" not in act and "ALLOW" not in act) else "monitoring"
            on_path = any(h["key"] in ("dlp", "ssl", "url", "cac", "ftc") and h.get("decided_by") and h["decided_by"].get("name") == name for h in hops) \
                or (ch == "web" and any(name == rr["name"] for h in hops if h["key"] == "dlp" for rr in h.get("rules", []))) \
                or (ch in ("endpoint", "saas", "email") and name in channels[ch]["rules"])
            rows.append({"name": name, "channel": ch, "state": state, "on_path": on_path})
        counts = {}
        for r in rows:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        weak = None
        if counts.get("missing"):
            weak = f"{counts['missing']} rule(s) not deployed"
        elif counts.get("disabled"):
            weak = f"{counts['disabled']} rule(s) still disabled"
        elif not any(r["on_path"] for r in rows if r["channel"] == "web") and reaches_zscaler and decrypted:
            weak = "no rule of this pack sees this traffic"
        pack_rows.append({"id": pk["id"], "name": pk.get("name") or pk["id"], "rules": rows, "counts": counts, "weak_point": weak,
                          "coverage": "enforcing" if counts.get("enforcing") and not counts.get("missing") else ("monitoring" if counts.get("monitoring") and not counts.get("missing") else ("partial" if counts.get("enforcing") or counts.get("monitoring") else ("deployed" if not counts.get("missing") else "missing")))})

    weak_points = [dict(h["weak_point"], hop=h["key"], hop_label=h["label"]) for h in hops if h.get("weak_point")]
    weak_points += [dict(c["weak_point"], hop=k, hop_label=c["label"]) for k, c in channels.items() if c.get("weak_point")]
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    weak_points.sort(key=lambda w: sev_order.get(w["severity"], 9))
    outcome = ("bypassed" if not reaches_zscaler else "blocked" if ends in ("ssl", "url") else
               "blind" if not decrypted else next((h["status"] for h in hops if h["key"] == "dlp"), "none"))
    return {"destination": dest, "network": network, "platform": platform, "hops": hops, "channels": channels, "packs": pack_rows,
            "weak_points": weak_points, "outcome": outcome, "reaches_zscaler": reaches_zscaler, "decrypted": decrypted}


# ── Report ────────────────────────────────────────────────────────────
def load_packs() -> List[Dict[str, Any]]:
    try:
        from dlp_importer import discover_packs
        out = []
        for p in discover_packs():
            try:
                pols = json.load(open(f"{p['dir']}/configs/dlp_policies.json", encoding="utf-8"))
            except Exception:  # noqa: BLE001
                pols = []
            out.append({"id": p["id"], "name": p.get("name") or p["id"], "policies": [{"name": x.get("name"), "channel": x.get("channel", "web")} for x in pols]})
        return out
    except Exception:  # noqa: BLE001
        return []


def generate_data_flow_report(client, destinations: Optional[Sequence[str]] = None, platform: str = "windows") -> Dict[str, Any]:
    """Read the tenant once, trace every traffic class (or the given
    destinations) for every network context, and summarise."""
    zcc = read_client_connector(client)
    zia = read_zia(client)
    packs = load_packs()
    dests = list(destinations) if destinations else [k["key"] for k in TRAFFIC_CLASSES]
    traces = []
    for d in dests:
        rd = resolve_destination(d, zia)
        for net in NETWORKS:
            traces.append(trace(rd, net["key"], platform, zcc, zia, packs))
    summary = {
        "destinations": len(dests), "traces": len(traces),
        "bypassed": sum(1 for t in traces if not t["reaches_zscaler"]),
        "blind": sum(1 for t in traces if t["reaches_zscaler"] and not t["decrypted"] and t["outcome"] not in ("blocked",)),
        "enforced": sum(1 for t in traces if t["outcome"] == "enforce"),
        "monitored": sum(1 for t in traces if t["outcome"] == "monitor"),
        "high": sum(1 for t in traces for w in t["weak_points"] if w["severity"] == "high"),
        "app_profiles": len(zcc["app_profiles"]), "forwarding_profiles": len(zcc["forwarding_profiles"]),
        "trusted_networks": len(zcc["trusted_networks"]), "pac_files": len(zcc["pac_files"]),
    }
    return {"summary": summary, "platform": platform, "networks": NETWORKS, "platforms": PLATFORMS,
            "destinations": [{"key": k["key"], "label": k["label"], "why": k.get("why", "")} for k in TRAFFIC_CLASSES],
            "traces": traces, "client_connector": zcc, "packs": [{"id": p["id"], "name": p["name"], "rules": len(p["policies"])} for p in packs],
            "diagnostics": zia.get("diagnostics", []) + [{"section": "Client Connector", "error": e} for e in zcc.get("errors", [])],
            "snapshot": {"zia": {k: zia[k] for k in ("ssl", "dlp", "url", "cac", "ftc", "endpoint", "saas", "email", "catalogue")},
                         "categories": {k: {"id": v.get("id"), "name": v.get("configured_name") or v.get("name"), "urls": v.get("urls"), "db_categorized_urls": v.get("db_categorized_urls") or v.get("dbCategorizedUrls")}
                                        for k, v in (zia.get("categories") or {}).items() if isinstance(v, dict)}},
            "sources": {"client_connector": "/zcc/webPolicies, /zcc/forwardingProfiles, /zcc/trustedNetworks", "pac": "/zia/pacFiles",
                        "zia": "/zia/sslInspectionRules, /zia/urlFilteringRules, /zia/cloudApplicationRules, /zia/fileTypeControlRules, /zia/webDlpRules, /zia/endpointDlpRules, /zia/casbDlpRules, /zia/emailDlpRules, /zia/cloudApplications/policy, /zia/urlCategories"}}


def trace_from_report(report: Dict[str, Any], destination: str, network: str, platform: str) -> Dict[str, Any]:
    """Trace a destination the user typed against a stored report (no tenant call)."""
    zia = dict(report["snapshot"]["zia"])
    zia["categories"] = report["snapshot"].get("categories") or {}
    for r in zia.get("dlp", []):
        r.setdefault("enforcing", str(r.get("action", "")).upper() in ("BLOCK", "CONFIRM", "ICAP_RESPONSE"))
        r.setdefault("without_content_inspection", False)
    rd = resolve_destination(destination, zia)
    if network not in {n["key"] for n in NETWORKS}:
        network = "off"
    return trace(rd, network, platform if platform in PLATFORMS else "windows", report["client_connector"], zia, load_packs())


def to_markdown(report: Dict[str, Any], label: str = "") -> str:
    s = report["summary"]
    lines = [f"# Data Flow Map{' — ' + label if label else ''}", "",
             f"{s['traces']} paths traced ({s['destinations']} destinations × {len(report['networks'])} network contexts, {report['platform']}). "
             f"Bypassed before Zscaler: {s['bypassed']}. Encrypted/blind: {s['blind']}. Enforced: {s['enforced']}. Monitored: {s['monitored']}. High-severity weak points: {s['high']}.", ""]
    for t in report["traces"]:
        net = next(n["label"] for n in NETWORKS if n["key"] == t["network"])
        lines.append(f"## {t['destination']['label']} · {net} → {t['outcome']}")
        for h in t["hops"]:
            lines.append(f"- **{h['label']}** [{h['status']}] {h['detail']}")
            if h.get("weak_point"):
                lines.append(f"  - Weak point ({h['weak_point']['severity']}): {h['weak_point']['title']} — {h['weak_point']['fix']}")
        for k, c in t["channels"].items():
            lines.append(f"- *{c['label']}* [{c['status']}] {c['detail']}")
        for p in t["packs"]:
            lines.append(f"- Pack {p['name']}: {p['coverage']}" + (f" — {p['weak_point']}" if p.get("weak_point") else ""))
        lines.append("")
    return "\n".join(lines)
