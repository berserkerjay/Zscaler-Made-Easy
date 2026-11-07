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

import functools
from typing import Any, Dict, List, Optional, Sequence, Tuple

SAAS = "Ch.C — SaaS Security"
EMAIL = "Ch.D — Email DLP"

# SaaS Security API rule types that scan data at rest in the application.
_FILE_TYPES = ("OFLCASB_DLP_FILE",)
# Actions that change nothing in the application: report, allow, or only
# notify the user (terraform zia_casb_dlp_rules action values).
_MONITOR_SAAS = {"OFLCASB_DLP_REPORT_INCIDENT", "OFLCASB_DLP_ALLOW", "OFLCASB_DLP_NOTIFY_END_USER", "REPORT_INCIDENT", "ALLOW", ""}
# Rule types where sharing applies, so the collaboration scope matters.
_SHARING_TYPES = ("OFLCASB_DLP_FILE", "OFLCASB_DLP_COLLAB", "OFLCASB_DLP_STORAGE", "OFLCASB_DLP_REPO")
# Custom Header Insertion enforces through the mail server (X-Zscaler-* headers);
# native_zscaler._EMAIL_ACTIONS spells it CUSTOMHEADERINSERTION.
_ENFORCING_EMAIL = {"BLOCK", "QUARANTINE", "CUSTOMHEADERINSERTION", "CUSTOM_HEADER_INSERTION"}


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


def _email_tenants(cl, with_rules: bool = False) -> Tuple[List[Dict[str, Any]], int]:
    """Onboarded email tenants (Exchange, Gmail, secure email gateway), decided
    by email_tenants.onboarded_email_tenants, the same function the pack deploy
    uses: ZIA's own appType=EMAIL list, any active tenant whose application says
    email and, with `with_rules`, the tenants existing Email DLP rules use. Each
    row has id, name, app and found_by. Reads only; a failed read of any
    source leaves the others to answer."""
    import email_tenants as et
    rows, code = _fetch(cl, "/zia/casbTenant/lite", {"activeOnly": "true", "appType": "EMAIL"})
    try:
        active, _ = _tenants(cl)
    except Exception:  # noqa: BLE001 — the typed list alone still answers
        active = []
    rules: List[Dict[str, Any]] = []
    if with_rules:
        try:
            rules, _ = _email_rules(cl)
        except Exception:  # noqa: BLE001 — a 404 here must not break the check
            rules = []
    return et.onboarded_email_tenants(active, rows, rules), code


def _on(rules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enabled rules only: a disabled rule scans and enforces nothing."""
    return [r for r in rules if str(_f(r, "state", default="")).upper() == "ENABLED"]


def _unavailable(code: int, what: str):
    R = _R()
    if code == 404:
        return R(R.INFO, f"{what} is not licensed or not enabled on this tenant (the API answered 404).")
    if code in (401, 403):
        return R(R.ERROR, f"The API client's role cannot read {what} (HTTP {code}); grant it read access to see this score.")
    return R(R.ERROR, f"{what} could not be read (HTTP {code}).")


def _tenant_names(rows: Sequence[Dict[str, Any]], limit: int = 4) -> str:
    names = [f"{_f(t, 'tenant_name', 'tenantName', 'name', default='?')} ({_f(t, 'saas_application', 'saasApplication', 'app', default='?')})" for t in rows]
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
    def missing_for(rs):
        covered, any_unscoped = set(), False
        for r in rs:
            ids = _ids(_f(r, "cloud_app_tenants", "cloudAppTenants", "tenants", default=[]))
            covered.update(ids)
            any_unscoped = any_unscoped or not ids
        return [] if (rs and any_unscoped) else [t for t in tenants if str(_f(t, "tenant_id", "tenantId", "id")) not in covered]
    if not rules:
        return R(R.FAIL, f"None of the {len(tenants)} onboarded application(s) has a DLP rule.")
    missing = missing_for(_on(rules))
    if missing and not missing_for(rules):
        return R(R.WARN, f"{len(missing)} onboarded application(s) are covered only by disabled rules (see C.6): {_tenant_names(missing)}.")
    if missing:
        return R(R.FAIL, f"{len(missing)} onboarded application(s) have no enabled DLP rule: {_tenant_names(missing)}.")
    return R(R.PASS, f"Every onboarded application ({len(tenants)}) is covered by at least one enabled SaaS DLP rule.")


def c_c4(cl):
    """Check C.4 (Ch.C — SaaS Security): Files at rest are scanned."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    def types_of(rs):
        return sorted({str(_f(r, "type", "rule_type", "ruleType", default="")) for r in rs} - {""})
    types = types_of(_on(rules))
    if any(t in _FILE_TYPES for t in types):
        return R(R.PASS, f"Enabled file scanning rules present (rule types: {', '.join(types)}).")
    if not rules:
        return R(R.FAIL, "No SaaS DLP rules, so files stored in SaaS applications are not scanned.")
    if any(t in _FILE_TYPES for t in types_of(rules)):
        return R(R.WARN, "Files at rest are covered only by disabled OFLCASB_DLP_FILE rules (see C.6), so nothing is scanned yet.")
    return R(R.WARN, f"No enabled file (OFLCASB_DLP_FILE) rule: enabled rule types are {', '.join(types) or 'none'}. Files at rest in storage apps are not scanned.")


def c_c5(cl):
    """Check C.5 (Ch.C — SaaS Security): Rules carry DLP engines."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.INFO, "No SaaS DLP rules to check (C.2).")
    on = _on(rules)
    if not on:
        return R(R.INFO, "No enabled SaaS DLP rule to check (see C.6).")
    bare = [str(_f(r, "name", default="?")) for r in on if not _ids(_f(r, "dlp_engines", "dlpEngines", default=[]))]
    if bare:
        return R(R.FAIL, f"{len(bare)} enabled SaaS DLP rule(s) have no DLP engine and match nothing: {', '.join(bare[:4])}.")
    return R(R.PASS, f"All {len(on)} enabled SaaS DLP rule(s) carry DLP engines.")


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
    def enforcing(rs):
        return [a for a in sorted({str(_f(r, "action", default="")) for r in rs}) if a.upper() not in _MONITOR_SAAS]
    live = enforcing(_on(rules))
    if live:
        return R(R.PASS, f"Remediation in use: {', '.join(live)}.")
    if enforcing(rules):
        return R(R.WARN, f"Remediation ({', '.join(enforcing(rules))}) is set only on disabled rules (see C.6); the enabled rules only report, allow or notify.")
    return R(R.WARN, "Every SaaS DLP rule only reports incidents, allows or notifies the user. Once incidents are reviewed, add remediation (quarantine, remove external or public sharing, revoke share) for the highest-risk data.")


def c_c8(cl):
    """Check C.8 (Ch.C — SaaS Security): External and public sharing covered."""
    R = _R()
    rules, code = _saas_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "SaaS Security API DLP rules")
    if not rules:
        return R(R.INFO, "No SaaS DLP rules to check (C.2).")
    # collaborationScope values carry the COLLABORATION_SCOPE_ prefix
    # (COLLABORATION_SCOPE_EXTERNAL_COLLAB_VIEW, COLLABORATION_SCOPE_PUBLIC …;
    # terraform zia_casb_dlp_rules, zscaler-sdk-python zia/casb_dlp_rules.py).
    def ext(s):
        return s == "ANY" or "EXTERNAL" in s or s.endswith("_PUBLIC") or s == "PUBLIC"

    def covers(rs):
        sharing = [r for r in rs if str(_f(r, "type", "rule_type", "ruleType", default="")).upper() in _SHARING_TYPES
                   or not _f(r, "type", "rule_type", "ruleType")]
        scopes = [{str(s).upper() for s in (_f(r, "collaboration_scope", "collaborationScope", default=[]) or [])} for r in sharing]
        ok = bool(sharing) and any(not sc or any(ext(s) for s in sc) for sc in scopes)
        return ok, sorted(set().union(*scopes)) if scopes else []
    ok, scopes = covers(_on(rules))
    if ok:
        return R(R.PASS, "Enabled SaaS DLP rules cover externally and publicly shared content.")
    if covers(rules)[0]:
        return R(R.WARN, "External and public sharing are covered only by disabled rules (see C.6).")
    return R(R.WARN, f"Enabled SaaS DLP rules only cover {', '.join(scopes) or 'no sharing scope'}: externally or publicly shared files, the main exposure, are not scanned.")


# ── Ch.D — Email DLP ───────────────────────────────────────────────────

def c_d1(cl):
    """Check D.1 (Ch.D — Email DLP): Email tenant onboarded."""
    R = _R()
    rows, code = _email_tenants(cl, with_rules=True)
    if code not in (200, 204) and not rows:
        return _unavailable(code, "the email tenant list")
    if not rows:
        return R(R.FAIL, "No Exchange, Gmail or secure email gateway tenant is onboarded (Data Security > Email DLP > Email Tenants). "
                         "Adding an email tenant is the first step of Outbound Email DLP: it makes Zscaler the smart host your mail server sends outbound mail to. "
                         "ZIA requires one for every Email DLP rule, so no Email DLP rule can exist until it is onboarded. Ref: https://help.zscaler.com/zia/adding-email-tenants")
    how = "; ".join(f"{t['name']}: {t['found_by']}" for t in rows[:4]) + (f"; and {len(rows) - 4} more" if len(rows) > 4 else "")
    return R(R.PASS, f"Email tenant(s): {_tenant_names(rows)}. Found by: {how}.")


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
    # A rule with withoutContentInspection uses no engine by design: it filters
    # on file type, size, users or recipients (SDK outbound_email_dlp_rules).
    noci = [r for r in rules if _f(r, "without_content_inspection", "withoutContentInspection") is True]
    bare = [str(_f(r, "name", default="?")) for r in rules if r not in noci and not _ids(_f(r, "dlp_engines", "dlpEngines", default=[]))]
    filt = (f" {len(noci)} rule(s) run without content inspection (filter by file type, size, users or recipients)." if noci else "")
    if bare:
        return R(R.FAIL, f"{len(bare)} Email DLP rule(s) inspect content but name no DLP engine: {', '.join(bare[:4])}. Select the engines, or set None to use the rule as a filter."
                         + filt + " Ref: https://help.zscaler.com/zia/configuring-outbound-email-policy-rules")
    if noci and len(noci) == len(rules):
        return R(R.INFO, filt.strip())
    return R(R.PASS, f"All {len(rules) - len(noci)} content-inspecting Email DLP rule(s) carry DLP engines." + filt)


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
    hdr = [r for r in rules if _f(r, "custom_header", "customHeader")]
    note = (" Block and Quarantine take effect only if the mail server's transport or mail-flow rules act on the X-Zscaler-Block:1 and"
            " X-Zscaler-Quarantine:1 headers; Quarantine is available for Microsoft Exchange only. Ref: https://help.zscaler.com/zia/configuring-outbound-email-policy-rules")
    if set(acts) & _ENFORCING_EMAIL or hdr:
        used = [a for a in acts if a in _ENFORCING_EMAIL]
        if hdr and not set(acts) & {"CUSTOMHEADERINSERTION", "CUSTOM_HEADER_INSERTION"}:
            used.append("custom header")
        return R(R.PASS, f"Enforcing actions in use: {', '.join(used)}." + note)
    return R(R.WARN, f"No Email DLP rule enforces: the actions in use are {', '.join(a or 'none' for a in acts)}. Once incidents are reviewed, block, quarantine or add a custom header (for example to encrypt) for the highest-risk data leaving by email." + note)


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
    # A notification needs both an auditor and a template ("If you do not
    # select an auditor and notification template, the Zscaler service
    # doesn't send a notification for this rule"). An Incident Receiver
    # (receiver) also hands incidents to someone.
    def aud(r):
        return _f(r, "auditor", "external_auditor_email", "externalAuditorEmail")

    def tpl(r):
        return _f(r, "notification_template", "notificationTemplate")
    told = [r for r in rules if aud(r) and tpl(r)]
    recv = [r for r in rules if _f(r, "receiver", "zscaler_incident_receiver", "zscalerIncidentReceiver")]
    half = [str(_f(r, "name", default="?")) for r in rules if r not in told and (aud(r) or tpl(r))]
    tail = (f" {len(half)} rule(s) set only one of auditor and template, so they send nothing: {', '.join(half[:3])}." if half else "")
    ref = " Ref: https://help.zscaler.com/zia/configuring-outbound-email-policy-rules"
    if told or recv:
        return R(R.PASS, f"{len(told)} Email DLP rule(s) email an auditor, {len(recv)} forward incidents to an Incident Receiver." + tail)
    return R(R.WARN, "No Email DLP rule notifies an auditor (auditor and notification template both set) or forwards to an Incident Receiver: incidents are only in the logs." + tail + ref)


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
    return R(R.INFO, "No Email DLP rule uses Email Recipient Profiles or Email Recipient Domain Profiles: every external recipient gets the same action. "
                     "Best Practice: use recipient or domain profiles to allow sensitive data to trusted partners and block it for everyone else (policy is evaluated per recipient). "
                     "Ref: https://help.zscaler.com/zia/understanding-outbound-email-policy-enforcement")


def c_d9(cl):
    """Check D.9 (Ch.D — Email DLP): Images in email are scanned.

    Outbound Email DLP has its own OCR switch in DLP Advanced Settings
    (/webDlpGlobalOptions enableEmailDlpOcr — zscaler-sdk-python 1.11.0).
    If OCR options are not enabled, DLP rules don't apply to image files."""
    R = _R()
    rules, code = _email_rules(cl)
    if code not in (200, 204):
        return _unavailable(code, "Email DLP rules")
    if not rules:
        return R(R.INFO, "No Email DLP rules to check (D.2).")
    g, gc = cl.get("/zia/webDlpGlobalOptions")
    ref = " Ref: https://help.zscaler.com/zia/configuring-dlp-advanced-settings"
    if gc != 200 or not isinstance(g, dict) or "enableEmailDlpOcr" not in g:
        return R(R.INFO, "The Outbound Email DLP OCR setting is not readable here; check DLP Advanced Settings > Optical Character Recognition > Outbound Email DLP." + ref)
    if g.get("enableEmailDlpOcr") in (True, 1, "1", "true", "True"):
        return R(R.PASS, "OCR is on for Outbound Email DLP: text in image attachments is scanned.")
    return R(R.WARN, "OCR is off for Outbound Email DLP (DLP Advanced Settings > Optical Character Recognition): image attachments (PNG, JPEG, TIFF, BMP) are not scanned." + ref)


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
    ("D.9", EMAIL, "Images in email are scanned", c_d9),
]


def _guarded(fn: Any, label: str) -> Any:
    """`fn` through zscaler_full_checks' permission guard: a check that also
    reads a list the role was refused (D.6's tenants, C.3's rules) is "Not
    permitted", never PASS. Imported when the check runs: the engine imports
    this module while it is still being loaded."""
    @functools.wraps(fn)
    def check(cl):
        import zscaler_full_checks as zf
        return zf.permission_guarded(fn, label)(cl)
    return check


def splice(reg: List[Tuple[str, str, str, Any]]) -> List[Tuple[str, str, str, Any]]:
    """Insert the two sections after Ch.B — Endpoint (before Ch.E — GenAI)."""
    if any(r[0] == "C.1" for r in reg):
        return reg
    guarded = [(cid, sec, label, _guarded(fn, label)) for cid, sec, label, fn in CHECKS]
    out, done = [], False
    for r in reg:
        if not done and str(r[1]).startswith("Ch.E"):
            out.extend(guarded); done = True
        out.append(r)
    if not done:
        out.extend(guarded)
    return out
