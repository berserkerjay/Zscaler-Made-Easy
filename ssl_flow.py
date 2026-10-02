"""
SSL Inspection Flow — what is decrypted, what is not, and where inline
Web DLP goes blind.

Inline Web DLP only sees the content of HTTPS traffic that SSL
inspection decrypts. This module walks the tenant's SSL inspection
rules in order for a fixed set of DLP-relevant traffic classes (file
sharing, webmail, generative AI, social, collaboration, forums,
uncategorised sites, privacy exemptions, everything else), decides what
happens to each class (decrypted / not decrypted / blocked / no rule),
maps the inline Web DLP rules that target the same traffic, and turns
the mismatches into gaps a junior engineer can act on.

Read-only. Works with sdk_client.Client (`.get(endpoint)` returning
`(data, status)`); rule dicts may be snake_case (SDK models) or
camelCase (raw API) — every field read here accepts both.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from bypass_report import _fetch_url_category_lookup, _rules_to_list

# ── Traffic classes ───────────────────────────────────────────────────
# url_categories: ZIA predefined URL category ids that carry the class.
# app_classes: Cloud application classes (Cloud App Control catalogue)
# whose applications carry the class. Both lists are matched against the
# tenant's rules; ids the tenant does not expose are dropped at run time.
TRAFFIC_CLASSES: List[Dict[str, Any]] = [
    {"key": "file_share", "label": "File sharing & cloud storage", "relevance": "high",
     "url_categories": ["FILE_HOST", "ONLINE_STORAGE", "SHAREWARE_DOWNLOAD"],
     "app_classes": ["FILE_SHARE"],
     "why": "Bulk document uploads (Dropbox, Box, WeTransfer, personal OneDrive/Google Drive) are the most common exfiltration path inline DLP is expected to catch."},
    {"key": "webmail", "label": "Personal webmail", "relevance": "high",
     "url_categories": ["WEB_MAIL", "WEBMAIL", "EMAIL_HOST"],
     "app_classes": ["WEB_MAIL", "WEBMAIL"],
     "why": "Attachments and pasted content sent from personal mail accounts bypass corporate email DLP entirely; only inline Web DLP sees them."},
    {"key": "ai_ml", "label": "Generative AI & ML apps", "relevance": "high",
     "url_categories": ["AI_ML_APPS", "GENERAL_AI_ML"],
     "app_classes": ["AI_ML"],
     "why": "Prompts and file uploads to ChatGPT, Gemini, Claude, Copilot and similar are content the business usually wants monitored or blocked."},
    {"key": "social", "label": "Social networking", "relevance": "medium",
     "url_categories": ["SOCIAL_NETWORKING"],
     "app_classes": ["SOCIAL_NETWORKING"],
     "why": "Posts, direct messages and uploads to social platforms are a frequent source of accidental disclosure."},
    {"key": "collab", "label": "Collaboration & messaging", "relevance": "medium",
     "url_categories": ["ONLINE_CHAT", "INSTANT_MESSAGING", "OTHER_INTERNET_COMMUNICATION"],
     "app_classes": ["ENTERPRISE_COLLABORATION", "INSTANT_MESSAGING"],
     "why": "Slack, Teams, Discord, WhatsApp Web and similar carry files and pasted secrets; sanctioned instances are normally scoped with tenant restrictions rather than exempted."},
    {"key": "forums", "label": "Blogs, forums & paste sites", "relevance": "medium",
     "url_categories": ["BLOG", "DISCUSSION_FORUMS", "OTHER_SOCIETY_AND_LIFESTYLE"],
     "app_classes": [],
     "why": "Pastebin-style sites and forums are where code, keys and internal documents get shared for 'help'."},
    {"key": "unknown", "label": "Uncategorised & new domains", "relevance": "high",
     "url_categories": ["OTHER_MISCELLANEOUS", "MISCELLANEOUS_OR_UNKNOWN", "NEWLY_REG_DOMAINS", "NEWLY_REVIVED_DOMAINS"],
     "app_classes": [],
     "why": "Sites Zscaler has not categorised yet are exactly where a determined user or malware stages an upload; leaving them encrypted hides that traffic from DLP."},
    {"key": "remote", "label": "Remote access, anonymizers & P2P", "relevance": "medium",
     "url_categories": ["REMOTE_ACCESS_TOOLS", "ANONYMIZER", "P2P_COMMUNICATION", "DNS_OVER_HTTPS"],
     "app_classes": ["DNS_OVER_HTTPS"],
     "why": "Tunnelling and proxy services move data out of sight of every other control; these are normally blocked outright rather than decrypted."},
    {"key": "privacy", "label": "Finance, health & government", "relevance": "privacy",
     "url_categories": ["FINANCE", "TRADING_BROKARAGE_INSURANCE", "HEALTH", "OTHER_HEALTH", "GOVERNMENT", "OTHER_GOVERNMENT_AND_POLITICS"],
     "app_classes": ["FINANCE", "HEALTH_CARE"],
     "why": "Commonly left encrypted for employee privacy. That is a business decision, but it should be written down and the traffic should be covered by Endpoint DLP or CASB where the data is regulated."},
    {"key": "general", "label": "All other web traffic", "relevance": "medium", "catch_all": True,
     "url_categories": [], "app_classes": [],
     "why": "Everything that no specific rule targets. The catch-all decrypt rule (or the default rule) decides whether inline DLP sees ordinary web forms and uploads."},
]

DECRYPT_ACTIONS = {"DECRYPT", "INSPECT", "SSL_INSPECT"}
NO_DECRYPT_ACTIONS = {"DO_NOT_DECRYPT", "DO_NOT_INSPECT", "SSL_DO_NOT_INSPECT", "EXEMPT", "BYPASS"}
BLOCK_ACTIONS = {"BLOCK", "BLOCK_TRAFFIC"}

SCOPE_FIELDS = [
    ("users", "users"), ("groups", "groups"), ("departments", "departments"),
    ("locations", "locations"), ("location_groups", "location groups"), ("locationGroups", "location groups"),
    ("devices", "devices"), ("device_groups", "device groups"), ("deviceGroups", "device groups"),
    ("device_trust_levels", "device trust levels"), ("deviceTrustLevels", "device trust levels"),
    ("platforms", "platforms"), ("user_agent_types", "user agents"), ("userAgentTypes", "user agents"),
    ("source_ip_groups", "source IP groups"), ("sourceIpGroups", "source IP groups"), ("srcIpGroups", "source IP groups"),
    ("time_windows", "time windows"), ("timeWindows", "time windows"),
    ("workload_groups", "workload groups"), ("workloadGroups", "workload groups"),
    ("zpa_app_segments", "ZPA app segments"), ("zpaAppSegments", "ZPA app segments"),
]
TARGET_FIELDS = [
    ("url_categories", "urlCategories"), ("cloud_applications", "cloudApplications"),
    ("dest_ip_groups", "destIpGroups"), ("destinations", "destinations"), ("urls", "urls"),
]


# ── Field helpers (snake_case SDK dicts or camelCase raw dicts) ───────

def _f(r: Dict[str, Any], *names: str, default: Any = None) -> Any:
    for n in names:
        if n in r and r[n] is not None:
            return r[n]
    return default


def _names(items: Any) -> List[str]:
    out: List[str] = []
    for x in items or []:
        if isinstance(x, dict):
            v = x.get("name") or x.get("id") or x.get("url")
            if v is not None:
                out.append(str(v))
        elif x is not None:
            out.append(str(x))
    return out


def _upper(items: Iterable[str]) -> List[str]:
    return [str(x).upper() for x in items]


def _action_type(r: Dict[str, Any]) -> str:
    a = r.get("action")
    if isinstance(a, dict):
        a = a.get("type") or a.get("name") or a.get("actionType") or ""
    return str(a or "").upper().replace(" ", "_")


def _bool(v: Any) -> bool:
    return v is True or str(v).lower() in ("true", "1", "yes")


def _scope(r: Dict[str, Any]) -> List[str]:
    """Human scope parts ('groups:2', ...) — empty means everyone."""
    seen: Dict[str, int] = {}
    for field, label in SCOPE_FIELDS:
        v = r.get(field)
        if isinstance(v, list) and v:
            seen[label] = max(seen.get(label, 0), len(v))
    return [f"{label}: {n}" for label, n in seen.items()]


def _decision_of(action: str) -> str:
    if action in DECRYPT_ACTIONS:
        return "inspected"
    if action in BLOCK_ACTIONS:
        return "blocked"
    if action in NO_DECRYPT_ACTIONS:
        return "not_inspected"
    return "not_inspected"


# ── Rule normalisation ────────────────────────────────────────────────

def normalize_ssl_rule(r: Dict[str, Any]) -> Dict[str, Any]:
    cats = _upper(_names(_f(r, "url_categories", "urlCategories", default=[])))
    apps = _upper(_names(_f(r, "cloud_applications", "cloudApplications", default=[])))
    other_targets = sum(len(_names(_f(r, a, b, default=[]))) for a, b in TARGET_FIELDS[2:])
    any_cat = "ANY" in cats
    cats = [c for c in cats if c not in ("ANY", "NONE")]
    action = _action_type(r)
    predefined = _bool(_f(r, "predefined", default=False))
    default_rule = _bool(_f(r, "default_rule", "defaultRule", default=False))
    name = str(_f(r, "name", default="") or "").strip() or f"Rule {r.get('id')}"
    state = str(_f(r, "state", default="ENABLED") or "ENABLED").upper()
    explicit = bool(cats or apps or other_targets)
    return {
        "id": r.get("id"),
        "name": name,
        "order": _f(r, "order", default=None),
        "rank": _f(r, "rank", default=None),
        "state": state,
        "enabled": state == "ENABLED",
        "action": action,
        "decision": _decision_of(action),
        "url_categories": cats,
        "cloud_applications": apps,
        "other_targets": other_targets,
        "scope": _scope(r),
        "scoped": bool(_scope(r)),
        "predefined": predefined,
        "default_rule": default_rule,
        # A rule with no explicit targets matches every destination —
        # except Zscaler's predefined exemption lists, whose targets are
        # maintained by Zscaler and are not exposed in the API.
        "catch_all": not explicit and (any_cat or default_rule or not predefined),
        "zscaler_maintained": predefined and not explicit and not default_rule and not any_cat,
        "description": str(_f(r, "description", default="") or "")[:300],
    }


def normalize_dlp_rule(r: Dict[str, Any]) -> Dict[str, Any]:
    cats = _upper(_names(_f(r, "url_categories", "urlCategories", default=[])))
    apps = _upper(_names(_f(r, "cloud_applications", "cloudApplications", default=[])))
    cats = [c for c in cats if c not in ("ANY", "NONE")]
    engines = _names(_f(r, "dlp_engines", "dlpEngines", default=[]))
    action = _action_type(r)
    state = str(_f(r, "state", default="ENABLED") or "ENABLED").upper()
    name = str(_f(r, "name", default="") or "").strip() or f"Rule {r.get('id')}"
    ref = lambda *keys: _ref_name(_f(r, *keys, default=None))  # noqa: E731
    return {
        "id": r.get("id"),
        "name": name,
        "order": _f(r, "order", default=None),
        "state": state,
        "enabled": state == "ENABLED",
        "action": action,
        "enforcing": action in ("BLOCK", "ISOLATE", "CONFIRM", "CAUTION"),
        "url_categories": cats,
        "cloud_applications": apps,
        "catch_all": not cats and not apps,
        "engines": engines,
        "without_content_inspection": _bool(_f(r, "without_content_inspection", "withoutContentInspection", default=False)),
        "scope": _scope(r),
        "parent_rule": _f(r, "parent_rule", "parentRule", default=None),
        "protocols": _upper(_names(_f(r, "protocols", default=[]))),
        # What happens after a match: the incident and notification path.
        "incident_receiver": _bool(_f(r, "zscaler_incident_receiver", "zscalerIncidentReceiver", default=False)),
        "icap_server": ref("icap_server", "icapServer"),
        "notification_template": ref("notification_template", "notificationTemplate"),
        "auditor": ref("auditor"),
        "external_auditor_email": _f(r, "external_auditor_email", "externalAuditorEmail", default=None) or None,
        "severity": str(_f(r, "severity", default="") or "").upper() or None,
    }


def _ref_name(v: Any) -> Optional[str]:
    """A referenced object ({id, name}), a bare name, or nothing → its name."""
    if isinstance(v, dict):
        return str(v.get("name") or v.get("id") or "") or None
    return (str(v) if v not in (None, "", 0) else None)


def _sort_key(rule: Dict[str, Any]) -> Tuple[int, int, int]:
    o = rule.get("order")
    try:
        o = int(o)
    except (TypeError, ValueError):
        o = 10 ** 6
    # The default rule is always evaluated last whatever its order says.
    return (1 if rule.get("default_rule") else 0, o, int(rule.get("id") or 0))


# ── Tenant reads ─────────────────────────────────────────────────────

def _fetch_rules(client, endpoint: str, diagnostics: List[Dict[str, Any]], label: str) -> List[Dict[str, Any]]:
    try:
        data, code = client.get(endpoint)
    except Exception as e:  # noqa: BLE001
        diagnostics.append({"section": label, "endpoint": endpoint, "error_type": type(e).__name__, "error": str(e)[:300]})
        return []
    if code not in (200, 204):
        err = data.get("error") if isinstance(data, dict) else ""
        diagnostics.append({"section": label, "endpoint": endpoint, "error_type": f"HTTP {code}", "error": str(err or "")[:300]})
        return []
    return [r for r in _rules_to_list(data) if isinstance(r, dict)]


def _fetch_app_catalogue(client, classes: Iterable[str], diagnostics: List[Dict[str, Any]],
                         cancel: Optional[Callable[[], bool]] = None) -> Dict[str, List[str]]:
    """Cloud application identifiers per application class, from the
    tenant's Cloud App Control catalogue. Missing catalogue → {} and a
    diagnostic (matching then relies on URL categories only). `cancel()`
    is asked before each class's page: once true nothing more is asked
    (the caller says the read stopped)."""
    out: Dict[str, List[str]] = {}
    zs = getattr(client, "_zs", None)
    svc = getattr(getattr(zs, "zia", None), "cloud_applications", None) if zs is not None else None
    if svc is None or not hasattr(svc, "list_cloud_app_policy"):
        diagnostics.append({"section": "cloud application catalogue", "endpoint": "/zia/cloudApplications/policy",
                            "error_type": "unavailable", "error": "the SDK client does not expose cloud_applications; rules were matched on URL categories only"})
        return out
    for cls in sorted(set(classes)):
        if cancel is not None and cancel():
            break
        try:
            res = svc.list_cloud_app_policy(query_params={"app_class": cls, "page_size": 1000})
            data, err = (res[0], res[2]) if isinstance(res, tuple) and len(res) == 3 else (res, None)
            if err:
                raise RuntimeError(str(err))
            apps = []
            for a in data or []:
                if hasattr(a, "as_dict"):
                    a = a.as_dict()
                if not isinstance(a, dict):
                    continue
                ident = a.get("app") or a.get("app_name") or a.get("appName") or a.get("name")
                if ident:
                    apps.append(str(ident).upper())
            if apps:
                out[cls] = sorted(set(apps))
        except Exception as e:  # noqa: BLE001
            diagnostics.append({"section": f"cloud applications ({cls})", "endpoint": "/zia/cloudApplications/policy",
                                "error_type": type(e).__name__, "error": str(e)[:200]})
    return out


# ── Matching ─────────────────────────────────────────────────────────

def _rule_hits(rule: Dict[str, Any], cats: List[str], apps: List[str]) -> Dict[str, Any]:
    hit_cats = sorted(set(rule["url_categories"]) & set(cats))
    hit_apps = sorted(set(rule["cloud_applications"]) & set(apps))
    return {"categories": hit_cats, "applications": hit_apps, "explicit": bool(hit_cats or hit_apps)}


def _matches(rule: Dict[str, Any], klass: Dict[str, Any], cats: List[str], apps: List[str]) -> Optional[Dict[str, Any]]:
    """Does this SSL rule apply to the traffic class? Returns the hit
    (why) or None. Catch-all rules apply to every class; explicit rules
    only where their categories/applications overlap."""
    if rule["catch_all"]:
        return {"categories": [], "applications": [], "explicit": False, "catch_all": True}
    if klass.get("catch_all"):
        return None
    h = _rule_hits(rule, cats, apps)
    return dict(h, catch_all=False) if h["explicit"] else None


def _dlp_covers(rule: Dict[str, Any], klass: Dict[str, Any], cats: List[str], apps: List[str]) -> bool:
    if rule["catch_all"]:
        return True
    if klass.get("catch_all"):
        return False
    return _rule_hits(rule, cats, apps)["explicit"]


def _short(rule: Dict[str, Any], hit: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    d = {k: rule.get(k) for k in ("id", "name", "order", "action", "decision", "state", "scope", "predefined", "default_rule", "catch_all", "zscaler_maintained")}
    if hit is not None:
        d["matched_on"] = hit
    return d


def analyse(ssl_rules: List[Dict[str, Any]], dlp_rules: List[Dict[str, Any]],
            catalogue: Optional[Dict[str, List[str]]] = None,
            category_lookup: Optional[Dict[str, Any]] = None,
            dlp_in_scope: bool = True) -> Dict[str, Any]:
    """Pure function: normalised rule dicts in, report body out. With
    `dlp_in_scope` false the Web DLP rules were not read (not in scope on
    the Scope page): no class is said to lack a DLP rule, and its DLP
    status is "not in scope"."""
    catalogue = catalogue or {}
    ssl = sorted((normalize_ssl_rule(r) for r in ssl_rules), key=_sort_key)
    dlp = sorted((normalize_dlp_rule(r) for r in dlp_rules), key=lambda r: (int(r["order"]) if str(r.get("order") or "").lstrip("-").isdigit() else 10 ** 6, int(r.get("id") or 0)))
    enabled_ssl = [r for r in ssl if r["enabled"]]
    enabled_dlp = [r for r in dlp if r["enabled"]]
    known_cats = set(category_lookup.keys()) if category_lookup else set()

    classes_out: List[Dict[str, Any]] = []
    all_gaps: List[Dict[str, Any]] = []
    for klass in TRAFFIC_CLASSES:
        cats = [c for c in klass["url_categories"] if not known_cats or c in known_cats]
        if not cats and klass["url_categories"] and known_cats:
            # None of the ids exist in this tenant's catalogue: keep them so a
            # rule that names them still matches, but say so.
            cats = list(klass["url_categories"])
        apps = sorted({a for cls in klass["app_classes"] for a in catalogue.get(cls, [])})
        matching: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        for r in enabled_ssl:
            hit = _matches(r, klass, cats, apps)
            if hit:
                matching.append((r, hit))
        decided_by = None
        exceptions: List[Dict[str, Any]] = []
        for r, hit in matching:
            if r["scoped"]:
                exceptions.append(_short(r, hit))
                continue
            decided_by = _short(r, hit)
            break
        decision = decided_by["decision"] if decided_by else "no_rule"
        after = []
        if decided_by:
            passed = False
            for r, hit in matching:
                if passed and not r["scoped"]:
                    after.append(_short(r, hit))
                if r["id"] == decided_by["id"]:
                    passed = True
        shadowed_decrypt = [r for r in after if r["decision"] == "inspected"]
        disabled_decrypt = [_short(r) for r in ssl if not r["enabled"] and r["decision"] == "inspected" and _matches(r, klass, cats, apps)]
        exemptions = [e for e in exceptions if e["decision"] != "inspected"]

        covering = [r for r in enabled_dlp if _dlp_covers(r, klass, cats, apps)]
        dlp_short = [{k: r.get(k) for k in ("id", "name", "order", "action", "enforcing", "catch_all", "without_content_inspection", "scope", "engines")} for r in covering]
        enforcing = any(r["enforcing"] for r in covering)
        content = [r for r in covering if not r["without_content_inspection"]]

        gaps: List[Dict[str, Any]] = []
        label = klass["label"]
        rel = klass["relevance"]
        if not dlp_in_scope:
            dlp_note_none = " Web DLP is not in scope on the Scope page, so its rules were not read."
        else:
            dlp_note_none = " No inline DLP rule targets it either."
        if decision in ("not_inspected", "no_rule"):
            if rel == "privacy":
                gaps.append({"type": "privacy_exemption", "severity": "info",
                             "title": f"{label}: not decrypted (privacy exemption)",
                             "detail": (f"Left encrypted by '{decided_by['name']}'." if decided_by else "No SSL rule decrypts this traffic.")
                                       + " Inline DLP cannot see content here; that is usual, but it should be a documented decision.",
                             "fix": "Record the exemption in the DLP standard and cover regulated data on these sites with Endpoint DLP or CASB instead."})
            else:
                sev = "high" if rel == "high" or covering else "medium"
                who = (f"'{decided_by['name']}' (order {decided_by['order']}, {decided_by['action']})" if decided_by
                       else "no SSL rule matches, so the traffic is passed through encrypted")
                dlp_note = (f" {len(covering)} inline DLP rule(s) target this traffic but never see the HTTPS content: "
                            + ", ".join(r["name"] for r in covering[:4]) + ("…" if len(covering) > 4 else "")) if covering else dlp_note_none
                gaps.append({"type": "blind_spot", "severity": sev,
                             "title": f"{label}: encrypted, inline DLP is blind",
                             "detail": f"Decided by {who}.{dlp_note}",
                             "fix": ("Add or reorder a DECRYPT rule for this traffic ahead of the exemption" if decided_by
                                     else "Add a DECRYPT rule for this traffic (or enable a catch-all decrypt rule)")
                                    + "; keep Zscaler Recommended Exemptions for certificate-pinned apps only."})
        elif decision == "inspected" and dlp_in_scope:
            if not covering:
                gaps.append({"type": "ungoverned", "severity": "medium" if rel != "privacy" else "low",
                             "title": f"{label}: decrypted, but no inline DLP rule applies",
                             "detail": f"'{decided_by['name']}' decrypts this traffic, so content is visible, yet no enabled Web DLP rule targets it.",
                             "fix": "Deploy a baseline pack (Deploy Policy Packs) or add a Web DLP rule scoped to these categories/applications; start in monitor mode."})
            elif not enforcing:
                gaps.append({"type": "monitor_only", "severity": "low",
                             "title": f"{label}: visible to DLP, monitor only",
                             "detail": f"{len(covering)} inline DLP rule(s) apply but none block, confirm or isolate.",
                             "fix": "Fine while tuning. Once false positives are understood, move the high-confidence rules to BLOCK (journey stage: Enforcement)."})
            if covering and not content:
                gaps.append({"type": "metadata_only", "severity": "low",
                             "title": f"{label}: DLP rules run without content inspection",
                             "detail": "Every covering rule has 'without content inspection' set, so engines never scan the payload.",
                             "fix": "Clear the without-content-inspection flag on at least one rule with an engine."})
        elif decision == "blocked":
            pass  # blocked at SSL; nothing leaves, nothing to inspect.

        if shadowed_decrypt and decision != "inspected":
            gaps.append({"type": "shadowed", "severity": "high",
                         "title": f"{label}: a DECRYPT rule is shadowed",
                         "detail": f"'{decided_by['name']}' (order {decided_by['order']}) matches first; the decrypt rule(s) "
                                   + ", ".join(f"'{r['name']}' (order {r['order']})" for r in shadowed_decrypt) + " never run for this traffic.",
                         "fix": "Move the DECRYPT rule above the exemption, or narrow the exemption to the categories it is meant for."})
        if exemptions and decision == "inspected" and rel != "privacy":
            gaps.append({"type": "partial_exemption", "severity": "medium",
                         "title": f"{label}: decrypted for most users, exempt for some",
                         "detail": "Scoped exemption(s) run before the decrypt rule: "
                                   + "; ".join(f"'{e['name']}' ({', '.join(e['scope'])})" for e in exemptions),
                         "fix": "Confirm every exempted group is intended (executives and IT are the usual surprises) and that Endpoint DLP covers them."})
        if disabled_decrypt and decision != "inspected":
            gaps.append({"type": "disabled_decrypt", "severity": "info",
                         "title": f"{label}: a matching DECRYPT rule exists but is disabled",
                         "detail": ", ".join(f"'{r['name']}'" for r in disabled_decrypt) + " would decrypt this traffic once enabled.",
                         "fix": "Enable it after confirming the certificate is deployed to endpoints (check 3.3 / 4.2)."})
        for g in gaps:
            g["class"] = klass["key"]
            g["class_label"] = label
            g["class_index"] = len(classes_out)
        all_gaps.extend(gaps)

        classes_out.append({
            "key": klass["key"], "label": label, "why": klass["why"], "relevance": rel,
            "catch_all": bool(klass.get("catch_all")),
            "url_categories": cats,
            "url_category_names": [((category_lookup or {}).get(c) or {}).get("configured_name") or c for c in cats],
            "applications": apps, "application_count": len(apps),
            "app_classes": klass["app_classes"],
            "decision": decision,
            "decided_by": decided_by,
            "exceptions": exceptions,
            "shadowed": shadowed_decrypt,
            "disabled_decrypt": disabled_decrypt,
            "dlp_rules": dlp_short,
            "dlp_enforcing": enforcing,
            "dlp_status": ("blind" if decision in ("not_inspected", "no_rule") else
                           "blocked" if decision == "blocked" else
                           "not_in_scope" if not dlp_in_scope else
                           "none" if not covering else "enforcing" if enforcing else "monitor"),
            "gaps": gaps,
        })

    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    all_gaps.sort(key=lambda g: (sev_rank.get(g["severity"], 9), g["class_index"]))
    zscaler_exemptions = [_short(r) for r in ssl if r["zscaler_maintained"]]
    counts = {d: sum(1 for c in classes_out if c["decision"] == d) for d in ("inspected", "not_inspected", "blocked", "no_rule")}
    summary = {
        "classes": len(classes_out),
        "inspected": counts["inspected"],
        "not_inspected": counts["not_inspected"] + counts["no_rule"],
        "blocked": counts["blocked"],
        "dlp_covered": sum(1 for c in classes_out if c["decision"] == "inspected" and c["dlp_rules"]) if dlp_in_scope else None,
        "gaps": len(all_gaps),
        "high": sum(1 for g in all_gaps if g["severity"] == "high"),
        "medium": sum(1 for g in all_gaps if g["severity"] == "medium"),
        "low": sum(1 for g in all_gaps if g["severity"] == "low"),
        "ssl_rules": len(ssl), "ssl_rules_enabled": len(enabled_ssl),
        "ssl_decrypt_rules": sum(1 for r in enabled_ssl if r["decision"] == "inspected"),
        "ssl_exempt_rules": sum(1 for r in enabled_ssl if r["decision"] == "not_inspected"),
        "dlp_rules": len(dlp), "dlp_rules_enabled": len(enabled_dlp),
        "catalogue_classes": sorted(catalogue.keys()),
    }
    return {
        "summary": summary,
        "classes": classes_out,
        "gaps": all_gaps,
        "ssl_rules": ssl,
        "dlp_rules": dlp,
        "zscaler_exemptions": zscaler_exemptions,
        "guidance": [
            "Inline Web DLP only inspects HTTPS content that an SSL inspection DECRYPT rule has opened. A DO_NOT_DECRYPT rule, or no matching rule, makes DLP blind for that traffic.",
            "SSL rules are evaluated top-down, first match wins. A broad exemption above a decrypt rule silently shadows it.",
            "Keep 'Zscaler Recommended Exemptions' enabled for certificate-pinned applications; add your own exemptions by category, not by broad group, and document each one.",
            "Once a class is decrypted, the inline DLP rule that targets it decides the outcome: monitor first, then block.",
        ],
    }


ZCC_KINDS = (("apps", "application"), ("processes", "process"), ("domains", "domain"), ("ips", "IP / subnet"), ("trusted_networks", "trusted network"))


def zcc_bypass_summary(client) -> Dict[str, Any]:
    """Client Connector bypasses, read live from the app / forwarding
    profiles: traffic sent around the Zscaler tunnel never reaches ZIA,
    so no SSL rule and no inline DLP rule ever sees it. Same reader as the
    Bypass report (bypass_report._fetch_zcc_bypasses)."""
    out: Dict[str, Any] = {"available": False, "profiles": 0, "total": 0, "counts": {}, "items": [], "endpoints": [], "error": None}
    try:
        from bypass_report import _fetch_zcc_bypasses
        z = _fetch_zcc_bypasses(client)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:200]
        return out
    out["endpoints"] = z.get("endpoints_probed") or []
    out["profiles"] = z.get("profile_count") or 0
    reachable = any(int(e.get("status") or 0) == 200 for e in out["endpoints"])
    out["available"] = reachable
    if not reachable:
        errs = [f"{e.get('endpoint')}: {e.get('error') or 'HTTP ' + str(e.get('status'))}" for e in out["endpoints"]]
        out["error"] = "Client Connector profiles could not be read (" + "; ".join(errs)[:300] + ")"
    items: List[Dict[str, Any]] = []
    for key, label in ZCC_KINDS:
        sec = z.get(key) or {}
        out["counts"][key] = int(sec.get("count") or 0)
        for it in (sec.get("items") or []):
            items.append({"kind": key, "kind_label": label, "profile": it.get("profile"), "value": it.get("value") or it.get("name"),
                          "detail": it.get("path") or it.get("os") or ""})
    out["total"] = sum(out["counts"].values())
    out["items"] = items[:200]
    return out


def zcc_gap(zcc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The gap entry for Client Connector bypasses, when there are any."""
    if not zcc.get("available") or not zcc.get("total"):
        return None
    c = zcc["counts"]
    parts = [f"{c[k]} {lbl}{'' if c[k] == 1 else 's'}" for k, lbl in ZCC_KINDS if c.get(k)]
    return {"type": "zcc_bypass", "severity": "high", "class": "zcc", "class_label": "Client Connector bypasses", "class_index": -1,
            "title": "Client Connector bypasses: traffic that never reaches Zscaler",
            "detail": f"{zcc['profiles']} profile(s) send traffic around the tunnel: " + ", ".join(parts)
                      + ". Nothing sent this way is decrypted or inspected, whatever the SSL and DLP rules say; trusted networks switch the tunnel off entirely.",
            "fix": "Open the Bypass report for every entry and keep only the bypasses that are required (certificate-pinned or latency-critical apps). "
                   "Cover bypassed destinations with Endpoint DLP or a SaaS Security API scan, and review trusted-network definitions."}


# The sections this report reads, keyed as data_flow.PATH_SECTIONS keys
# them: the SSL inspection rules ("ssl"), the Web DLP rules ("dlp") and the
# Client Connector bypasses ("zcc"). The URL categories and the cloud
# application catalogue are read only to place traffic for the SSL rules.
SECTIONS = ("ssl", "dlp", "zcc")
NOTHING_IN_SCOPE = ("Nothing the SSL inspection flow reads is in scope — it walks the SSL inspection rules: on the Scope page "
                    "tick DLP or ZIA platform and mark SSL inspection as Zscaler, then run it again.")


def generate_ssl_flow_report(client, scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read the tenant and build the report. Never raises for a missing
    section; problems are listed under diagnostics. `scope` (data_flow.
    path_scope of the Scope page's selection) limits what is read: a
    section not in its `read` is not read, and the report says so under
    `not_in_scope`. Without `scope` every section is read (tools, tests).
    Raises ValueError when the SSL inspection rules are not in scope."""
    read = set(SECTIONS) if scope is None else {k for k in (scope.get("read") or []) if k in SECTIONS}
    why = {} if scope is None else {k: v for k, v in (scope.get("not_in_scope") or {}).items() if k in SECTIONS}
    if "ssl" not in read:
        raise ValueError(NOTHING_IN_SCOPE)
    diagnostics: List[Dict[str, Any]] = []
    ssl_rules = _fetch_rules(client, "/zia/sslInspectionRules", diagnostics, "SSL inspection rules")
    dlp_rules = _fetch_rules(client, "/zia/webDlpRules", diagnostics, "Web DLP rules") if "dlp" in read else []
    classes = {cls for k in TRAFFIC_CLASSES for cls in k["app_classes"]}
    catalogue = _fetch_app_catalogue(client, classes, diagnostics)
    try:
        lookup = _fetch_url_category_lookup(client)
    except Exception as e:  # noqa: BLE001
        lookup = {}
        diagnostics.append({"section": "URL categories", "endpoint": "/zia/urlCategories", "error_type": type(e).__name__, "error": str(e)[:200]})
    report = analyse(ssl_rules, dlp_rules, catalogue, lookup, dlp_in_scope="dlp" in read)
    if "zcc" in read:
        zcc = zcc_bypass_summary(client)
    else:
        zcc = {"available": False, "profiles": 0, "total": 0, "counts": {}, "items": [], "endpoints": [], "error": None,
               "not_in_scope": why.get("zcc") or "Not in scope: ZCC is not ticked on the Scope page, so the Client Connector profiles were not read."}
    report["zcc"] = zcc
    if zcc.get("error"):
        diagnostics.append({"section": "Client Connector bypasses", "endpoint": "/zcc/webPolicies", "error_type": "unavailable", "error": zcc["error"]})
    gap = zcc_gap(zcc)
    if gap:
        report["gaps"].insert(0, gap)
        s = report["summary"]
        s["gaps"] = s.get("gaps", 0) + 1
        s["high"] = s.get("high", 0) + 1
    report["summary"]["zcc_bypasses"] = zcc.get("total", 0)
    report["diagnostics"] = diagnostics
    report["not_in_scope"] = {k: why.get(k) or "Not in scope on the Scope page, so it was not read." for k in SECTIONS if k not in read}
    if scope is not None:
        report["scope"] = {"read": sorted(read), "source": scope.get("source") or "", "key": scope.get("key") or ""}
    report["sources"] = {"ssl_rules": "/zia/sslInspectionRules", "dlp_rules": "/zia/webDlpRules",
                         "applications": "/zia/cloudApplications/policy", "url_categories": "/zia/urlCategories",
                         "zcc_bypasses": "/zcc/webPolicies, /zcc/forwardingProfiles, /zcc/trustedNetworks, /zcc/webAppService"}
    return report


# ── Exports ──────────────────────────────────────────────────────────

def to_csv(report: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["class", "decision", "decided_by", "ssl_action", "ssl_order", "dlp_rules", "dlp_status", "gap_severity", "gap", "fix"])
    for c in report.get("classes", []):
        d = c.get("decided_by") or {}
        gaps = c.get("gaps") or [{}]
        for g in gaps:
            w.writerow([c["label"], c["decision"], d.get("name", ""), d.get("action", ""), d.get("order", ""),
                        "; ".join(r["name"] for r in c.get("dlp_rules", [])), c.get("dlp_status", ""),
                        g.get("severity", ""), g.get("title", ""), g.get("fix", "")])
    return buf.getvalue()


def to_markdown(report: Dict[str, Any]) -> str:
    s = report.get("summary", {})
    lines = ["# SSL Inspection Flow — inline DLP visibility", ""]
    if report.get("tenant_label"):
        lines.append(f"Tenant: {report['tenant_label']}  ")
    if report.get("generated_at"):
        lines.append(f"Generated: {report['generated_at']}")
    lines += ["", f"Traffic classes: {s.get('classes', 0)} · decrypted: {s.get('inspected', 0)} · not decrypted: {s.get('not_inspected', 0)} · blocked: {s.get('blocked', 0)} · gaps: {s.get('gaps', 0)} ({s.get('high', 0)} high)", ""]
    lines += ["| Traffic | SSL decision | Decided by | Inline DLP | Status |", "|---|---|---|---|---|"]
    for c in report.get("classes", []):
        d = c.get("decided_by") or {}
        lines.append(f"| {c['label']} | {c['decision'].replace('_', ' ')} | {d.get('name', '—')} | {', '.join(r['name'] for r in c.get('dlp_rules', [])) or '—'} | {c.get('dlp_status', '')} |")
    zcc = report.get("zcc") or {}
    if zcc.get("available"):
        c = zcc.get("counts") or {}
        lines += ["", f"Client Connector bypasses (never reach Zscaler): {zcc.get('total', 0)} across {zcc.get('profiles', 0)} profile(s) — "
                  + ", ".join(f"{c.get(k, 0)} {lbl}" for k, lbl in ZCC_KINDS)]
    lines += ["", "## Gaps", ""]
    if not report.get("gaps"):
        lines.append("No gaps found.")
    for g in report.get("gaps", []):
        lines += [f"- **[{g['severity'].upper()}] {g['title']}** — {g['detail']}", f"  - Fix: {g['fix']}"]
    lines += ["", "## SSL inspection rules (evaluation order)", "", "| Order | Rule | Action | State | Targets | Scope |", "|---|---|---|---|---|---|"]
    for r in report.get("ssl_rules", []):
        targets = ("everything" if r["catch_all"] else "Zscaler-maintained list" if r["zscaler_maintained"] else
                   ", ".join(r["url_categories"][:6] + r["cloud_applications"][:6]) + (" …" if len(r["url_categories"]) + len(r["cloud_applications"]) > 12 else ""))
        lines.append(f"| {r.get('order', '')} | {r['name']} | {r['action']} | {r['state']} | {targets} | {', '.join(r['scope']) or 'everyone'} |")
    return "\n".join(lines) + "\n"
