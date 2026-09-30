"""SaaS Security (CASB DLP) and Email DLP as scored channels.

The assessment scored Inline Web (Ch.A), Endpoint (Ch.B) and GenAI (Ch.E)
as sections of their own, while SaaS and Email only had a presence check
each inside Multi-Channel, so neither ever showed a score. These two
sections read the tenant the same way the deploy does (the SaaS application
tenant list, ZIA's email-tenant filter, the SaaS Security API DLP rules and
the Email DLP rules) and grade what is there.

Read-only: every call is a GET. Each check returns the assessment's R
result (PASS / FAIL / REVIEW / INFO / ERROR).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

SAAS = "Ch.C — SaaS Security"
EMAIL = "Ch.D — Email DLP"

# SaaS Security API rule types that scan data at rest in the application.
_FILE_TYPES = ("OFLCASB_DLP_FILE",)
_MONITOR_SAAS = {"OFLCASB_DLP_REPORT_INCIDENT", "REPORT_INCIDENT", "ALLOW", ""}
_ENFORCING_EMAIL = {"BLOCK", "QUARANTINE"}


def _R():
    import dlp_assessment_full_auto as a
    return a.R


def _ls(d: Any) -> List[Dict[str, Any]]:
    import dlp_assessment_full_auto as a
    return [x for x in a._ls(d) if isinstance(x, dict)]


def _f(x: Dict[str, Any], *names: str, default: Any = None) -> Any:
    for n in names:
        if n in x and x[n] is not None:
            return x[n]
    return default


def _ids(v: Any) -> List[str]:
    out = []
    for e in v or []:
        i = e.get("id") if isinstance(e, dict) else e
        if i is not None:
            out.append(str(i))
    return out


def _fetch(cl, path: str, params: Optional[Dict[str, str]] = None) -> Tuple[List[Dict[str, Any]], int]:
    d, c = cl.get(path, params) if params else cl.get(path)
    return (_ls(d) if c in (200, 204) else []), c


def _saas_rules(cl) -> Tuple[List[Dict[str, Any]], int]:
    return _fetch(cl, "/zia/casbDlpRules/all")


def _email_rules(cl) -> Tuple[List[Dict[str, Any]], int]:
    return _fetch(cl, "/zia/emailDlpRules")


def _tenants(cl) -> Tuple[List[Dict[str, Any]], int]:
    return _fetch(cl, "/zia/casbTenant/lite", {"activeOnly": "true"})


def _email_tenants(cl) -> Tuple[List[Dict[str, Any]], int]:
    """Exchange, Gmail and secure email gateway tenants: ZIA's own
    app_type=EMAIL list, plus any tenant whose application says email."""
    rows, code = _fetch(cl, "/zia/casbTenant/lite", {"activeOnly": "true", "appType": "EMAIL"})
    ids = {str(_f(t, "tenant_id", "tenantId", "id")) for t in rows}
    try:
        import pack_channels as pc
        more, _ = _tenants(cl)
        for t in more:
            app = str(_f(t, "saas_application", "saasApplication", default="") or "").upper()
            tid = str(_f(t, "tenant_id", "tenantId", "id"))
            if tid not in ids and pc._is_email_tenant({"app": app}):
                rows.append(t); ids.add(tid)
    except Exception:  # noqa: BLE001 — the typed list alone still answers
        pass
    return rows, code


def _unavailable(code: int, what: str):
    R = _R()
    if code == 404:
        return R(R.INFO, f"{what} is not licensed or not enabled on this tenant (the API answered 404).")
    if code in (401, 403):
        return R(R.ERROR, f"The API client's role cannot read {what} (HTTP {code}); grant it read access to see this score.")
    return R(R.ERROR, f"{what} could not be read (HTTP {code}).")


def _tenant_names(rows: Sequence[Dict[str, Any]], limit: int = 4) -> str:
    names = [f"{_f(t, 'tenant_name', 'tenantName', 'name', default='?')} ({_f(t, 'saas_application', 'saasApplication', default='?')})" for t in rows]
    return ", ".join(names[:limit]) + (f" and {len(names) - limit} more" if len(names) > limit else "")


# ── Ch.C — SaaS Security ───────────────────────────────────────────────

def c_c1(cl):
    """Check C.1 (Ch.C — SaaS Security): SaaS applications onboarded."""
    R = _R()
    rows, code = _tenants(cl)
    if code not in (200, 204):
        return _unavailable(code, "the SaaS application tenant list")
    if not rows:
        return R(R.FAIL, "No SaaS application tenant is onboarded (Administration > SaaS Application Tenants), so no data at rest in SaaS is scanned.")
    return R(R.PASS, f"{len(rows)} SaaS application tenant(s) onboarded: {_tenant_names(rows)}.")


def c_c2(cl):
    """Check C.2 (Ch.C — SaaS Security): SaaS DLP rules."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.FAIL, "No SaaS Security API DLP rules: onboarded applications are not scanned for sensitive data.")
    return R(R.PASS, f"{len(rules)} SaaS Security API DLP rule(s).")


def c_c3(cl):
    """Check C.3 (Ch.C — SaaS Security): Every onboarded application has a rule."""
    R = _R()
    tenants, tcode = _tenants(cl)
    rules, rcode = _saas_rules(cl)
    if tcode not in (200, 204) or rcode not in (200, 204):
        return _unavailable(rcode if rcode not in (200, 204) else tcode, "SaaS tenants or rules")
    if not tenants:
        return R(R.INFO, "No SaaS application tenant is onboarded yet (C.1).")
    covered = set()
    any_unscoped = False
    for r in rules:
        ids = _ids(_f(r, "cloud_app_tenants", "cloudAppTenants", "tenants", default=[]))
        covered.update(ids)
        any_unscoped = any_unscoped or not ids
    missing = [t for t in tenants if str(_f(t, "tenant_id", "tenantId", "id")) not in covered]
    if not rules:
        return R(R.FAIL, f"None of the {len(tenants)} onboarded application(s) has a DLP rule.")
    if missing and not any_unscoped:
        return R(R.FAIL, f"{len(missing)} onboarded application(s) have no DLP rule: {_tenant_names(missing)}.")
    return R(R.PASS, f"Every onboarded application ({len(tenants)}) is covered by at least one SaaS DLP rule.")


def c_c4(cl):
    """Check C.4 (Ch.C — SaaS Security): Files at rest are scanned."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    types = sorted({str(_f(r, "type", "rule_type", "ruleType", default="")) for r in rules} - {""})
    if any(t in _FILE_TYPES for t in types):
        return R(R.PASS, f"File scanning rules present (rule types: {', '.join(types)}).")
    if not rules:
        return R(R.FAIL, "No SaaS DLP rules, so files stored in SaaS applications are not scanned.")
    return R(R.WARN, f"No file (OFLCASB_DLP_FILE) rule: rule types present are {', '.join(types) or 'unknown'}. Files at rest in storage apps are not scanned.")


def c_c5(cl):
    """Check C.5 (Ch.C — SaaS Security): Rules carry DLP engines."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.INFO, "No SaaS DLP rules to check (C.2).")
    bare = [str(_f(r, "name", default="?")) for r in rules if not _ids(_f(r, "dlp_engines", "dlpEngines", default=[]))]
    if bare:
        return R(R.FAIL, f"{len(bare)} SaaS DLP rule(s) have no DLP engine and match nothing: {', '.join(bare[:4])}.")
    return R(R.PASS, f"All {len(rules)} SaaS DLP rule(s) carry DLP engines.")


def c_c6(cl):
    """Check C.6 (Ch.C — SaaS Security): Rules are enabled."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.INFO, "No SaaS DLP rules to check (C.2).")
    on = [r for r in rules if str(_f(r, "state", default="")).upper() == "ENABLED"]
    if not on:
        return R(R.FAIL, f"All {len(rules)} SaaS DLP rule(s) are disabled: nothing is scanned yet. Enable them once reviewed.")
    return R(R.PASS if len(on) == len(rules) else R.WARN, f"{len(on)} of {len(rules)} SaaS DLP rule(s) enabled.")


def c_c7(cl):
    """Check C.7 (Ch.C — SaaS Security): Remediation beyond reporting."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.INFO, "No SaaS DLP rules to check (C.2).")
    acts = sorted({str(_f(r, "action", default="")) for r in rules})
    enforcing = [a for a in acts if a.upper() not in _MONITOR_SAAS]
    if enforcing:
        return R(R.PASS, f"Remediation in use: {', '.join(enforcing)}.")
    return R(R.WARN, "Every SaaS DLP rule only reports incidents. Once incidents are reviewed, add remediation (quarantine, remove sharing) for the highest-risk data.")


def c_c8(cl):
    """Check C.8 (Ch.C — SaaS Security): External and public sharing covered."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.INFO, "No SaaS DLP rules to check (C.2).")
    scopes = {str(s).upper() for r in rules for s in (_f(r, "collaboration_scope", "collaborationScope", default=[]) or [])}
    if not scopes or scopes & {"ANY", "EXTERNAL_COLLAB_VIEW", "EXTERNAL_COLLAB_EDIT", "PUBLIC_COLLAB_VIEW", "PUBLIC_COLLAB_EDIT", "EXTERNAL", "PUBLIC"}:
        return R(R.PASS, "SaaS DLP rules cover externally and publicly shared content.")
    return R(R.WARN, f"SaaS DLP rules only cover {', '.join(sorted(scopes))}: externally or publicly shared files, the main exposure, are not scanned.")


# ── Ch.D — Email DLP ───────────────────────────────────────────────────

def c_d1(cl):
    """Check D.1 (Ch.D — Email DLP): Email tenant onboarded."""
    R = _R()
    rows, code = _email_tenants(cl)
    if code not in (200, 204) and not rows:
        return _unavailable(code, "the email tenant list")
    if not rows:
        return R(R.FAIL, "No Exchange, Gmail or secure email gateway tenant is onboarded (Administration > SaaS Application Tenants). "
                         "ZIA requires one for every Email DLP rule, so no Email DLP rule can exist until it is onboarded.")
    return R(R.PASS, f"Email tenant(s): {_tenant_names(rows)}.")


def c_d2(cl):
    """Check D.2 (Ch.D — Email DLP): Email DLP rules."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.FAIL, "No Email DLP rules: outbound email is not inspected for sensitive data.")
    return R(R.PASS, f"{len(rules)} Email DLP rule(s).")


def c_d3(cl):
    """Check D.3 (Ch.D — Email DLP): Rules carry DLP engines."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    bare = [str(_f(r, "name", default="?")) for r in rules if not _ids(_f(r, "dlp_engines", "dlpEngines", default=[]))]
    if bare:
        return R(R.FAIL, f"{len(bare)} Email DLP rule(s) have no DLP engine and match nothing: {', '.join(bare[:4])}.")
    return R(R.PASS, f"All {len(rules)} Email DLP rule(s) carry DLP engines.")


def c_d4(cl):
    """Check D.4 (Ch.D — Email DLP): Rules are enabled."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    on = [r for r in rules if str(_f(r, "state", default="")).upper() == "ENABLED"]
    if not on:
        return R(R.FAIL, f"All {len(rules)} Email DLP rule(s) are disabled: outbound email is not inspected yet.")
    return R(R.PASS if len(on) == len(rules) else R.WARN, f"{len(on)} of {len(rules)} Email DLP rule(s) enabled.")


def c_d5(cl):
    """Check D.5 (Ch.D — Email DLP): Enforcement beyond monitoring."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    acts = sorted({str(_f(r, "action", default="")).upper() for r in rules})
    if set(acts) & _ENFORCING_EMAIL:
        return R(R.PASS, f"Enforcing actions in use: {', '.join(a for a in acts if a in _ENFORCING_EMAIL)}.")
    return R(R.WARN, "Every Email DLP rule only monitors (ALLOW). Once incidents are reviewed, block or quarantine the highest-risk data leaving by email.")


def c_d6(cl):
    """Check D.6 (Ch.D — Email DLP): Rules apply to the mail tenant."""
    R = _R()
    rules, code = _email_rules(cl)
    tenants, _ = _email_tenants(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    ids = {str(_f(t, "tenant_id", "tenantId", "id")) for t in tenants}
    scoped = [r for r in rules if _ids(_f(r, "email_tenants", "emailTenants", default=[]))]
    stale = [str(_f(r, "name", default="?")) for r in scoped if ids and not set(_ids(_f(r, "email_tenants", "emailTenants"))) & ids]
    if stale:
        return R(R.FAIL, f"{len(stale)} Email DLP rule(s) point at email tenants that are no longer onboarded: {', '.join(stale[:4])}.")
    if len(scoped) < len(rules):
        bare = [str(_f(r, "name", default="?")) for r in rules if not _ids(_f(r, "email_tenants", "emailTenants", default=[]))]
        return R(R.WARN, f"{len(bare)} Email DLP rule(s) name no email tenant: {', '.join(bare[:4])}. ZIA requires one; set the mail tenant on them.")
    return R(R.PASS, f"{len(scoped)} of {len(rules)} Email DLP rule(s) are scoped to onboarded email tenants.")


def c_d7(cl):
    """Check D.7 (Ch.D — Email DLP): Incidents reach someone."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    told = [r for r in rules if _f(r, "auditor", "external_auditor_email", "externalAuditorEmail", "notification_template", "notificationTemplate")]
    if told:
        return R(R.PASS, f"{len(told)} of {len(rules)} Email DLP rule(s) notify an auditor or use a notification template.")
    return R(R.WARN, "No Email DLP rule notifies an auditor or uses a notification template: incidents are only in the logs.")


def c_d8(cl):
    """Check D.8 (Ch.D — Email DLP): Recipient scoping."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    scoped = [r for r in rules if _f(r, "email_recipient_profiles", "emailRecipientProfiles") or _f(r, "included_domain_profiles", "includedDomainProfiles")]
    if scoped:
        return R(R.PASS, f"{len(scoped)} Email DLP rule(s) distinguish recipients (recipient or domain profiles).")
    return R(R.INFO, "No Email DLP rule uses recipient or domain profiles: internal and external recipients are treated the same.")


CHECKS: List[Tuple[str, str, str, Any]] = [
    ("C.1", SAAS, "SaaS applications onboarded", c_c1),
    ("C.2", SAAS, "SaaS DLP rules", c_c2),
    ("C.3", SAAS, "Every onboarded app has a rule", c_c3),
    ("C.4", SAAS, "Files at rest scanned", c_c4),
    ("C.5", SAAS, "Rules carry DLP engines", c_c5),
    ("C.6", SAAS, "Rules enabled", c_c6),
    ("C.7", SAAS, "Remediation beyond reporting", c_c7),
    ("C.8", SAAS, "External and public sharing covered", c_c8),
    ("D.1", EMAIL, "Email tenant onboarded", c_d1),
    ("D.2", EMAIL, "Email DLP rules", c_d2),
    ("D.3", EMAIL, "Rules carry DLP engines", c_d3),
    ("D.4", EMAIL, "Rules enabled", c_d4),
    ("D.5", EMAIL, "Enforcement beyond monitoring", c_d5),
    ("D.6", EMAIL, "Rules apply to the mail tenant", c_d6),
    ("D.7", EMAIL, "Incidents reach someone", c_d7),
    ("D.8", EMAIL, "Recipient scoping", c_d8),
]


def splice(reg: List[Tuple[str, str, str, Any]]) -> List[Tuple[str, str, str, Any]]:
    """Insert the two sections after Ch.B — Endpoint (before Ch.E — GenAI)."""
    if any(r[0] == "C.1" for r in reg):
        return reg
    out, done = [], False
    for r in reg:
        if not done and str(r[1]).startswith("Ch.E"):
            out.extend(CHECKS); done = True
        out.append(r)
    if not done:
        out.extend(CHECKS)
    return out
