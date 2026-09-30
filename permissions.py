"""Permissions: run what the API client is allowed to run, and say exactly
what a full scan or a configuration change would need.

An API client that lacks a role never stops the tool: each check answers
INFO with the reason, each report section records a diagnostic, and a
plan is built from whatever the tenant would list. This module names the
missing permission for each of those, so the results say "grant X for a
full scan" instead of leaving a hole.

Permission names are the OneAPI / ZIdentity role permissions as the
portal labels them (see scope_permissions.SCOPE_PERMISSIONS)."""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from scope_permissions import SCOPE_PERMISSIONS

# What the assessment's own error texts look like when a call is refused.
_DENIED_RE = re.compile(r"lack permission|Access denied|does not include this feature|HTTP 40[13]\b|status.: ?40[13]|Forbidden|Unauthorized", re.I)

# Endpoint prefix -> (product, portal permission). Longest prefix wins.
ENDPOINT_PERMISSIONS: Dict[str, Dict[str, str]] = {
    "/zia/dlpDictionaries": {"product": "ZIA", "permission": "DLP Dictionaries"},
    "/zia/dlpEngines": {"product": "ZIA", "permission": "DLP Engines"},
    "/zia/webDlpRules": {"product": "ZIA", "permission": "Web DLP Rules"},
    "/zia/endPointDlpRules": {"product": "ZIA", "permission": "Endpoint DLP Rules"},
    "/zia/casbDlpRules": {"product": "ZIA", "permission": "SaaS Security API DLP Rules"},
    "/zia/emailDlpRules": {"product": "ZIA", "permission": "Email DLP Rules"},
    "/zia/dlpNotificationTemplates": {"product": "ZIA", "permission": "DLP Notification Templates"},
    "/zia/icapServers": {"product": "ZIA", "permission": "ICAP Servers"},
    "/zia/incidentReceiver": {"product": "ZIA", "permission": "Incident Receiver Servers"},
    "/zia/sslInspectionRules": {"product": "ZIA", "permission": "SSL Inspection Policy"},
    "/zia/urlFilteringRules": {"product": "ZIA", "permission": "URL Filtering Policy"},
    "/zia/urlCategories": {"product": "ZIA", "permission": "URL Categories"},
    "/zia/cloudApplicationRules": {"product": "ZIA", "permission": "Cloud App Control Policy"},
    "/zia/cloudApplications": {"product": "ZIA", "permission": "Cloud Applications"},
    "/zia/webApplicationRules": {"product": "ZIA", "permission": "Cloud App Control Policy"},
    "/zia/firewall": {"product": "ZIA", "permission": "Firewall Control Policy"},
    "/zia/adminUsers": {"product": "ZIA", "permission": "Administrator Management"},
    "/zia/fileTypeRules": {"product": "ZIA", "permission": "File Type Control Policy"},
    "/zia/firewallFilteringRules": {"product": "ZIA", "permission": "Firewall Control Policy"},
    "/zia/locations": {"product": "ZIA", "permission": "Locations"},
    "/zia/users": {"product": "ZIA", "permission": "User Management"},
    "/zia/groups": {"product": "ZIA", "permission": "User Management"},
    "/zia/departments": {"product": "ZIA", "permission": "User Management"},
    "/zia/adminRoles": {"product": "ZIA", "permission": "Administrator Management"},
    "/zia/pacFiles": {"product": "ZIA", "permission": "PAC Files"},
    "/zia/ruleLabels": {"product": "ZIA", "permission": "Rule Labels"},
    "/zia/advancedSettings": {"product": "ZIA", "permission": "Advanced Settings"},
    "/zia/nss": {"product": "ZIA", "permission": "NSS Configuration"},
    "/zia/saasSecurity": {"product": "ZIA", "permission": "SaaS Security API"},
    "/zcc/": {"product": "Client Connector", "permission": "Client Connector portal (read)"},
    "/zpa/": {"product": "ZPA", "permission": "ZPA read-only role"},
    "/zdx/": {"product": "ZDX", "permission": "ZDX read-only role"},
    "/zid/": {"product": "ZIdentity", "permission": "ZIdentity read-only role"},
}

# What a configuration change needs, per object kind the tool writes.
WRITE_PERMISSIONS: Dict[str, Dict[str, str]] = {
    "dictionary": {"product": "ZIA", "permission": "DLP Dictionaries (Full)", "what": "create the pack's dictionaries"},
    "engine": {"product": "ZIA", "permission": "DLP Engines (Full)", "what": "create the pack's engines"},
    "web": {"product": "ZIA", "permission": "Web DLP Rules (Full)", "what": "create Inline Web DLP rules"},
    "endpoint": {"product": "ZIA", "permission": "Endpoint DLP Rules (Full)", "what": "create Endpoint DLP rules and application groups"},
    "saas": {"product": "ZIA", "permission": "SaaS Security API DLP Rules (Full)", "what": "create SaaS Security API rules"},
    "email": {"product": "ZIA", "permission": "Email DLP Rules (Full)", "what": "create Outbound Email DLP rules"},
    "cloud_app": {"product": "ZIA", "permission": "Cloud App Control Policy (Full)", "what": "create Cloud App Control rules"},
    "file_type": {"product": "ZIA", "permission": "File Type Control Policy (Full)", "what": "create File Type Control rules"},
    "url": {"product": "ZIA", "permission": "URL Filtering Policy (Full)", "what": "create URL Filtering rules"},
    "ssl": {"product": "ZIA", "permission": "SSL Inspection Policy (Full)", "what": "create SSL Inspection rules"},
    "activation": {"product": "ZIA", "permission": "Activation", "what": "activate changes (the tool never does this; an admin does)"},
}

# Assessment section prefix -> scope key of scope_permissions.
_SECTION_SCOPE = [
    ("ZIA —", "zia_extras"), ("ZCC —", "zcc"), ("ZPA —", "zpa"), ("GenAI", "genai"), ("Automation", "automation"),
    ("ZDX", "zdx"), ("ZIdentity", "zidentity"), ("RBAC — ZIA", "zia_extras"), ("RBAC — ZCC", "zcc"), ("RBAC — ZPA", "zpa"),
    ("RBAC", "zidentity"),
]


def permission_for_endpoint(endpoint: str) -> Dict[str, str]:
    ep = str(endpoint or "")
    best = ""
    for prefix in ENDPOINT_PERMISSIONS:
        if ep.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    if best:
        return dict(ENDPOINT_PERMISSIONS[best], endpoint=ep)
    prod = "ZIA" if ep.startswith("/zia/") else ep.strip("/").split("/")[0].upper() if ep else "?"
    return {"product": prod, "permission": f"read access to {ep or 'the endpoint'}", "endpoint": ep}


def is_denied(detail: str) -> bool:
    """True when a check or section failed for lack of permission."""
    return bool(_DENIED_RE.search(str(detail or "")))


def scope_of_section(section: str) -> str:
    s = str(section or "")
    for prefix, scope in _SECTION_SCOPE:
        if s.startswith(prefix):
            return scope
    return "dlp"


def assessment_permission_summary(results: Iterable[Dict[str, Any]], scopes: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Which checks could not run for lack of permission, and what to
    grant for a full scan (per scope, from the permissions catalogue)."""
    denied = []
    for r in results:
        if str(r.get("status")) in ("INFO", "ERROR") and is_denied(r.get("detail")):
            denied.append({"id": r.get("id"), "label": r.get("label"), "section": r.get("section") or r.get("sec"),
                           "scope": scope_of_section(r.get("section") or r.get("sec") or "")})
    by_scope: Dict[str, int] = {}
    for d in denied:
        by_scope[d["scope"]] = by_scope.get(d["scope"], 0) + 1
    wanted = list(scopes or []) or list(by_scope)
    needed = []
    for key in wanted:
        sp = SCOPE_PERMISSIONS.get(key)
        if not sp:
            continue
        needed.append({"scope": key, "label": sp.get("label", key), "service": sp.get("service", ""),
                       "permissions": list(sp.get("permissions_read") or []), "blocked_checks": by_scope.get(key, 0),
                       "license": sp.get("license_required", "")})
    return {"blocked": len(denied), "checks": denied[:60], "by_scope": by_scope, "needed_for_full_scan": needed,
            "note": ("The checks below could not run because the API client's role does not include their feature. Everything else ran. "
                     "Grant the listed permissions (ZIdentity > API Clients > role) and run again for a full scan.") if denied else
                    "Every check the API client was allowed to run did run."}


# ── One vocabulary for what a check result means ──────────────────────
# The engine records four statuses (PASS, FAIL, REVIEW, INFO; ERROR is an
# INFO the check itself raised). The GUI, the exports and the score need
# one more distinction inside INFO/ERROR: a check the API client was not
# allowed to run is "not permitted" — coverage the tenant owner can
# restore by granting a permission — while a feature that is simply not
# licensed or not in use is "informational". Both are outside the score.
CLASSES = ("configured", "action_required", "needs_review", "not_permitted", "not_in_scope", "error", "informational")
CLASS_LABELS = {"configured": "Configured", "action_required": "Action required", "needs_review": "Needs review",
                "not_permitted": "Not permitted", "not_in_scope": "Not in scope", "error": "Could not be checked",
                "informational": "Not configured"}
SCORE_FORMULA = "configured ÷ (configured + action required + needs review)"


def classify(result: Dict[str, Any]) -> str:
    """The class of one check result (CLASSES)."""
    # A check whose channel the customer declared covered elsewhere (the
    # Scope page, channel_scope) was never run: not in scope, outside the score.
    if result.get("out_of_scope"):
        return "not_in_scope"
    st = str(result.get("status") or "").upper()
    if st == "PASS":
        return "configured"
    if st == "FAIL":
        return "action_required"
    if st == "REVIEW":
        return "needs_review"
    if st in ("INFO", "ERROR") and is_denied(result.get("detail")):
        return "not_permitted"
    if st == "ERROR":
        return "error"
    return "informational"


def assessment_summary(results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Execution completion and measurable coverage as separate numbers,
    from the same results the score is built on, so every surface (the
    tiles, the summary card, the Word and JSON exports) says the same
    thing. `assessed` is what the API client was allowed to run;
    `scored` is what the score divides over; `score` is None — "Not
    assessed" — when nothing was scoreable, never 100."""
    from dlp_assessment_full_auto import maturity
    rows = list(results)
    counts = {c: 0 for c in CLASSES}
    not_permitted_ids: List[Any] = []
    not_in_scope_ids: List[Any] = []
    for r in rows:
        c = classify(r)
        counts[c] += 1
        if c == "not_permitted":
            not_permitted_ids.append(r.get("id"))
        elif c == "not_in_scope":
            not_in_scope_ids.append(r.get("id"))
    total = len(rows)
    scored = counts["configured"] + counts["action_required"] + counts["needs_review"]
    score = round(counts["configured"] / scored * 100) if scored else None
    excluded = counts["not_permitted"] + counts["not_in_scope"] + counts["error"] + counts["informational"]
    # Not-in-scope checks were left out on purpose: the run is still complete.
    if total == 0:
        state = "unassessed"
    elif counts["not_permitted"] or counts["error"]:
        state = "partial"
    else:
        state = "complete"
    return {
        "total": total,
        "assessed": total - counts["not_permitted"] - counts["not_in_scope"],
        "not_permitted": counts["not_permitted"],
        "not_permitted_ids": not_permitted_ids,
        "not_in_scope": counts["not_in_scope"],
        "not_in_scope_ids": not_in_scope_ids,
        "errors": counts["error"],
        "informational": counts["informational"],
        "configured": counts["configured"],
        "action_required": counts["action_required"],
        "needs_review": counts["needs_review"],
        "scored": scored,
        "excluded": excluded,
        "score": score,
        "maturity": maturity(score),
        "state": state,
        "score_formula": SCORE_FORMULA,
    }


def write_permissions_needed(kinds: Iterable[str]) -> List[Dict[str, str]]:
    """What a configuration change of these kinds needs."""
    out = []
    seen = set()
    for k in kinds:
        w = WRITE_PERMISSIONS.get(str(k))
        if w and w["permission"] not in seen:
            seen.add(w["permission"]); out.append(dict(w, kind=str(k)))
    return out


def report_permission_diagnostics(diagnostics: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Diagnostics of a report (bypass, SSL flow, data flow) that were
    permission refusals, each with the permission to grant."""
    out = []
    for d in diagnostics or []:
        text = f"{d.get('error_type') or ''} {d.get('error') or ''}"
        if is_denied(text):
            out.append(dict(permission_for_endpoint(d.get("endpoint") or ""), section=d.get("section")))
    return out
