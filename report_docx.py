#!/usr/bin/env python3
"""
Zscaler Made Easy — Word Document Report Generator
=====================================================
Generates a professional .docx report from assessment results.

Usage:
    from report_docx import generate_report
    generate_report(results, cfg, "report.docx")

Or standalone:
    python report_docx.py smoes_report.json
"""

import json
import os
import sys
from datetime import datetime

try:
    from docx import Document
    from docx.shared import Pt, Cm, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
except ImportError:
    print("Install python-docx:  pip install python-docx")
    sys.exit(1)


# ── Zscaler Brand Colors ─────────────────────────────────────────────
# Sourced from Zscaler brand guidelines and public brand assets

ZS_BLUE = RGBColor(0x23, 0x6B, 0xF5)        # Dodger Blue (primary)
ZS_ELECTRIC = RGBColor(0x00, 0x9C, 0xDA)    # Electric Blue
ZS_MIDNIGHT = RGBColor(0x01, 0x26, 0x73)    # Midnight Blue (deep)
ZS_AQUA = RGBColor(0x6B, 0xFF, 0xB3)        # Aquamarine (accent)
ZS_WHITE = RGBColor(0xFF, 0xFF, 0xFF)
ZS_DARK_TEXT = RGBColor(0x1A, 0x1A, 0x2E)
ZS_GREY = RGBColor(0x55, 0x55, 0x55)
ZS_LIGHT_GREY = RGBColor(0x99, 0x99, 0x99)

# Status colors (Zscaler-aligned palette)
COLORS = {
    "PASS": RGBColor(0x10, 0x9E, 0x5F),    # success green
    "FAIL": RGBColor(0xD9, 0x21, 0x2C),    # critical red
    "REVIEW": RGBColor(0xE0, 0x82, 0x10),  # amber
    "INFO": ZS_LIGHT_GREY,
    "ERROR": ZS_LIGHT_GREY,
}

# Hex equivalents for cell shading
ZS_BLUE_HEX = "236BF5"
ZS_MIDNIGHT_HEX = "012673"
ZS_LIGHT_BG_HEX = "F4F8FF"

STATUS_LABELS = {
    "PASS": "Configured",
    "FAIL": "Action Required",
    "REVIEW": "Needs Review",
    "INFO": "Not Configured / N/A",
    "ERROR": "Not Configured / N/A",
}


# ── Helpers ──────────────────────────────────────────────────────────

def _parse_detail_for_bp(detail: str):
    """
    Split a check's detail string into (as_is, best_practice).
    Many checks follow the convention:
        "<current state sentence>. Best Practice: <guidance>."
    We split on 'Best Practice:' (case-insensitive) and clean both sides.
    If the sentinel isn't present, the whole string is treated as as_is.
    """
    if not detail:
        return "", ""
    import re
    m = re.split(r"\bBest\s+Practice\s*[:\-–]\s*", detail, maxsplit=1, flags=re.IGNORECASE)
    if len(m) == 2:
        as_is = m[0].strip().rstrip(".") + "."
        bp = m[1].strip()
        # Strip a trailing 'Ref:' note from best-practice text so it
        # renders cleanly — we surface it separately in the recommendation.
        bp = re.split(r"\s*Ref\s*[:]\s*", bp, maxsplit=1, flags=re.IGNORECASE)[0].strip()
        return as_is, bp
    return detail.strip(), ""


# Per-section / per-check fallback best-practice text + Zscaler help-
# center link. Used when a check's detail string didn't carry a 'Best
# Practice:' suffix (so _parse_detail_for_bp returned an empty bp).
# The keys are matched as case-insensitive substrings against the
# check's section AND label, so a single entry covers many checks.
_BP_FALLBACKS = [
    # (match-substring, best-practice text, help-center URL)
    ("ssl",
     "Decrypt and inspect TLS traffic for everything except a documented "
     "exempt list (banking, healthcare, certain government domains). "
     "Without TLS inspection, the majority of modern threats remain hidden.",
     "https://help.zscaler.com/zia/about-ssl-inspection"),

    ("dlp",
     "Define DLP engines + dictionaries for every regulated data class your "
     "policy covers (PII, PCI, PHI, IP). Apply Inline Web DLP rules with "
     "explicit user/group scoping and prefer Evaluate-All-Rules mode for "
     "comprehensive coverage.",
     "https://help.zscaler.com/zia/about-data-loss-prevention"),

    ("firewall",
     "Default Cloud Firewall rule should be DENY. Allow rules must specify "
     "users / groups / locations + destination categories. Avoid global "
     "ANY-ANY allows. Enable IPS profiles on every cloud-firewall rule.",
     "https://help.zscaler.com/zia/about-cloud-firewall-rules"),

    ("url filter",
     "Block known-bad and high-risk URL categories at the default rule. "
     "Allow rules should be scoped to specific user populations with "
     "documented business justification.",
     "https://help.zscaler.com/zia/about-url-filtering-policy"),

    ("sandbox",
     "Enable Cloud Sandbox for unknown executables, archives, and "
     "documents. Default action should be BLOCK pending sandbox verdict, "
     "not ALLOW. Configure quarantine workflow for medium-confidence verdicts.",
     "https://help.zscaler.com/zia/about-cloud-sandbox"),

    ("location",
     "Define one Location per office / branch / remote-aggregation point so "
     "policy can be scoped geographically. Configure both primary and "
     "secondary GRE/IPSec tunnels per location for failover.",
     "https://help.zscaler.com/zia/about-locations"),

    ("admin",
     "Apply least-privilege admin roles. Separate read-only auditor roles "
     "from change-capable admin roles. Federate admin login to your IdP "
     "with MFA enforced.",
     "https://help.zscaler.com/zia/about-admin-management"),

    ("zpa",
     "Use the smallest possible App Segment scope per application. Bind "
     "Access Policy rules to SCIM groups (not individuals). Apply Posture "
     "Profiles for any device-trust enforcement.",
     "https://help.zscaler.com/zpa/about-application-segments"),

    ("zcc",
     "Enforce strict-enforcement on app profiles, enable tamper protection "
     "(uninstall password), require posture profile for enrollment, and "
     "auto-cleanup devices not seen in 90 days.",
     "https://help.zscaler.com/zscaler-client-connector/about-zscaler-client-connector-app-profiles"),

    ("genai",
     "Categorize internal-approved AI services with explicit URL/cloud-app "
     "rules. Apply DLP engines (PII, IP, source code) to every outbound "
     "prompt. Block unsanctioned GenAI tools rather than alerting only.",
     "https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control"),

    ("automation", "API client roles should be scoped per use case "
     "(read-only auditor vs IaC executor). Audit log retention should be "
     "≥ 90 days for reliable change-tracking by Terraform / Ansible runs.",
     "https://github.com/zscaler"),

    ("zdx", "Enable ZDX monitoring for every business-critical app (top 10 "
     "minimum). Configure alert rules so the SOC sees app-score degradation "
     "before users open tickets.",
     "https://help.zscaler.com/zdx/about-zdx"),

    ("zidentity", "Federate ZIdentity to your corporate IdP with MFA "
     "required for every admin login. Bind roles to groups, not individual "
     "users, so offboarding is automatic via IdP group membership.",
     "https://help.zscaler.com/zidentity"),
]


def _resolve_best_practice(label: str, section: str, check_id: str) -> str:
    """Pick the most specific fallback BP text + link for a check that
    didn't carry inline 'Best Practice:' guidance in its detail string.

    Best-practice URLs come from zscaler_best_practices.BEST_PRACTICES
    (the curated Zscaler help-portal reference list) so the references
    stay authoritative instead of drifting against hardcoded strings.
    """
    try:
        from zscaler_best_practices import lookup_by_topic
    except Exception:
        lookup_by_topic = lambda _t: {}

    haystack = " ".join((label or "", section or "", check_id or "")).lower()
    for needle, text, _fallback_url in _BP_FALLBACKS:
        if needle in haystack:
            # Prefer the curated Zscaler URL if our topic-map has one
            bp = lookup_by_topic(needle)
            url = bp.get("url") or _fallback_url
            return f"{text} Reference: {url}"
    return (
        "Apply the Zscaler-recommended baseline for this control. Reference "
        "https://help.zscaler.com/zscaler-deployments-operations for the "
        "deployment-and-operations guide covering this feature area."
    )


# Admin-portal remediation paths per section keyword. These tell the
# auditor exactly WHERE in the Zscaler admin UI to make the change.
# Keyed the same way as _BP_FALLBACKS — case-insensitive substring on
# (label + section + check_id).
_REMEDIATION_PATHS = [
    # (match-substring, admin-portal path, API hint or None)
    ("ssl",
     "ZIA Admin → Policy → SSL Inspection → Add Rule (or edit Default Rule). "
     "Set Action = Inspect, attach URL categories to inspect, add exempt URL list.",
     "POST /zia/sslInspectionRules with {name, description, action:{type:DECRYPT}, "
     "urlCategories:[...], state:ENABLED, order, rank}"),

    ("dlp",
     "ZIA Admin → Policy → Data Loss Prevention → DLP Rules → Add. "
     "Attach DLP Engines (PCI, PII, Source Code, etc.), scope to users/groups, "
     "choose action (ALERT → BLOCK after validation).",
     "POST /zia/webDlpRules with {name, description, action, dlpEngines:[...], "
     "users/groups, state, order, rank}"),

    ("firewall",
     "ZIA Admin → Policy → Firewall Control → Access Policy → Add Rule. "
     "Default rule action = BLOCK_DROP. Scoped allow rules must specify "
     "users/groups + destination categories. Enable IPS profile on every rule.",
     "POST /zia/firewallRules with {name, description, action:BLOCK_DROP, "
     "nwApplications:[...], destCountries:[...], state:ENABLED, order}"),

    ("url filter",
     "ZIA Admin → Policy → URL & Cloud App Control → URL Filtering → Add Rule. "
     "Block MALICIOUS_SITES, UNKNOWN, NEWLY_REG_DOMAINS at the default rule. "
     "Allow rules should be scoped with documented justification.",
     "POST /zia/urlFilteringRules with {name, description, action, "
     "urlCategories:[...], state, order}"),

    ("sandbox",
     "ZIA Admin → Policy → Advanced Threat Protection → Sandbox Policy → "
     "Set File Types = ALL_EXECUTABLES + ARCHIVES + DOCUMENTS. "
     "Action = BLOCK_PENDING_VERDICT. Configure quarantine per file-class risk.",
     "PUT /zia/sandboxSettings"),

    ("location",
     "ZIA Admin → Administration → Locations → Add Location. Define office "
     "IP ranges, assign per-location forwarding method (GRE/IPSec/ZCC), apply "
     "appropriate policy groups. Redundant tunnels for BCP.",
     "POST /zia/locations + POST /zia/vpnCredentials or /zia/greTunnels"),

    ("admin",
     "ZIdentity Admin → API Clients → Role → Edit. Create dedicated roles "
     "('Auditor Read-Only', 'Rule Editor', 'Super-Admin') with minimum scope "
     "per use case. Federate admin login to Okta/Azure AD/Ping with MFA.",
     "Role/MFA changes are not API-accessible — use the ZIdentity admin UI."),

    ("zpa",
     "ZPA Admin → Policy → Access Policy → Add Rule. Bind conditions to "
     "SCIM_GROUP (not individual users). Attach Posture Profile for device "
     "trust. Set App Segment TCP/UDP port ranges explicitly.",
     "POST /zpa/policySet/{id}/rule with conditions:[{operands:[{objectType:SCIM_GROUP, ...}]}]"),

    ("zcc",
     "ZIA Admin → ZCC → App Profiles → Add (or edit existing). Enable strict "
     "enforcement, tamper-protection password, Z-Tunnel 2.0, attach a "
     "Posture Profile. Require MFA via ZIdentity for enrollment.",
     "PUT /zcc/papi/public/v1/web/policy/edit (update profile)"),

    ("genai",
     "ZIA Admin → Policy → URL & Cloud App Control → Cloud App Control → AI "
     "Applications. Allow sanctioned providers only; block 'Generative AI' "
     "category for all other apps. Attach DLP engines to outbound prompt traffic.",
     "POST /zia/cloudAppControlRules + DLP engine bindings on /zia/webDlpRules"),

    ("automation",
     "ZIdentity Admin → API Clients → Add per-use-case client (terraform-reader, "
     "ansible-executor). Grant minimum role. ZIA Admin → Activity → Audit Log "
     "Retention → set ≥ 90 days.",
     "Use the ZIdentity admin UI for roles; audit retention via /zia/auditlogSettings."),

    ("zdx",
     "ZDX Admin → Configuration → Applications → Add monitored app (O365, "
     "Salesforce, Zoom, ServiceNow). Configure probe cadence. Alerts → Rules "
     "→ add threshold rules on app-score degradation.",
     "POST /zdx/administration/apps + POST /zdx/alerts/rules"),

    ("zidentity",
     "ZIdentity Admin → Users → Federate to your IdP (SAML/SCIM). Groups → "
     "Add groups from IdP. Resource Servers → grant API-client access. "
     "Bind roles to groups, not individual users.",
     "Configured via ZIdentity admin UI + SCIM sync from IdP."),

    ("rbac",
     "ZIdentity Admin → Roles → Least-privilege per use case. "
     "Users → enforce SSO. Authentication → require MFA for admin logins. "
     "Audit Log → review role assignments quarterly.",
     "Role changes via ZIdentity admin UI; audit history via /zia/auditlogEntryReport."),
]


def _resolve_remediation(label: str, section: str, check_id: str) -> tuple:
    """Return (portal_path, api_hint) for this check. Prefers a
    registered remediation recipe (exact endpoint + field list),
    falls back to the per-section portal-path map."""
    # 1. Registered recipe takes precedence — tells us the exact API call
    try:
        from remediation import get_recipe
        recipe = get_recipe(check_id)
        if recipe:
            fields = [f.get("label", f.get("key", "")) for f in recipe.get("fields", [])]
            api_hint = f"{recipe['method']} {recipe['endpoint']} with {{{', '.join(fields)}}}"
            portal_hint = (
                f"Use the tool's 🔧 Remediate button on this finding, OR apply via API. "
                f"Recipe: '{recipe.get('label', '')}' — fields required: "
                f"{', '.join(fields)}."
            )
            return (portal_hint, api_hint)
    except Exception:
        pass
    # 2. Fall back to section-keyword path map
    haystack = " ".join((label or "", section or "", check_id or "")).lower()
    for needle, path, api in _REMEDIATION_PATHS:
        if needle in haystack:
            return (path, api or "")
    return (
        "Review this control with the feature owner; document any "
        "deviation from Zscaler best practice with business justification.",
        "",
    )


def _generate_why_it_matters(check_id: str, label: str, as_is: str, best_practice: str, section: str = "") -> str:
    """
    Produce a business-impact 'why it matters' sentence. Explains the
    risk/cost of the current configuration in terms of security,
    compliance, and operational outcomes — not the remediation step.
    """
    low = (as_is or "").lower()
    lab = (label or "").lower()
    sec = (section or "").lower()

    # Security-critical feature disabled
    if any(t in low for t in ("disabled", "not configured", "no cloud firewall",
                              "no dlp", "no engine", "no url filter", "no ssl")):
        if "ssl" in lab or "tls" in lab:
            return ("Encrypted-traffic inspection is the single highest-value Zscaler control. "
                    "Without it, threats hiding in HTTPS (most modern malware, data exfil, C2) "
                    "bypass every other security layer.")
        if "dlp" in lab or "dlp" in sec:
            return ("Data can leave the organization unnoticed. Audit-framework mappings "
                    "(PCI 10, HIPAA 164.312, GDPR Art. 32) explicitly require DLP controls on "
                    "outbound traffic — this check gates that capability.")
        if "firewall" in lab:
            return ("Non-web traffic (SSH, RDP, FTP, arbitrary TCP/UDP) bypasses URL filtering. "
                    "Without cloud firewall rules, those protocols aren't controlled at all — "
                    "a common exfiltration and lateral-movement vector.")
        if "sandbox" in lab:
            return ("Zero-day / unknown-hash files traverse the gateway uninspected. Critical "
                    "for targeted-attack resilience and auditor-requested malware analysis.")
        if "audit" in lab or "log" in lab:
            return ("Without audit-log access the tool can't validate other checks and auditors "
                    "can't trace changes. Typically a quick role permission fix.")
        return (f"'{label}' is a baseline Zscaler control. With it disabled/missing, the "
                "protection it provides is not in effect for any user.")

    # Globally scoped / overbroad
    if any(t in low for t in ("globally scoped", "default action", "default rule",
                              "overbroad", "no scope", "unscoped", "applied globally",
                              "no engines")):
        return ("A globally-scoped rule applies to everyone — low-privilege users get the same "
                "treatment as administrators. Scoping reduces false-positive noise and enforces "
                "least privilege. Also an auditor flag: compliance frameworks require "
                "role-based segmentation.")

    # Missing descriptions / owners / documentation
    if any(t in low for t in ("no description", "no owner", "not documented")):
        return ("Rules without descriptions or owners become orphaned. Within 6–12 months "
                "no one knows why they exist, so they're either kept forever (compounding noise) "
                "or removed blindly (breaking something). Audit frameworks require documented "
                "rationale for every control.")

    # Bypass / exemption
    if "bypass" in low or "exempt" in low or "allow" in low:
        return ("Every bypass is a documented blind spot. Auditors require a business-"
                "justification record for each exemption. Untracked bypasses often get "
                "weaponized by attackers who spot patterns in category/URL bypass lists.")

    # Alert-only / audit-only / partial rollout
    if any(t in low for t in ("alert only", "audit only", "log only", "partial", "some")):
        return ("An alert-only rule generates SIEM noise but doesn't protect users. Until the "
                "rule is moved to enforce/block, the coverage you expect is not actually in "
                "effect. Plan a migration window with owner sign-off.")

    # Review / verify needed
    if any(t in low for t in ("review", "verify", "validate", "confirm")):
        return ("This check can't be auto-validated — a human needs to confirm the setting "
                "matches your organization's policy. Skipping review is the #1 source of audit "
                "findings ('control existed but no one reviewed it').")

    # Fail-open / tamper / stale
    if "fail open" in low or "failopen" in low or "fail-open" in low:
        return ("Fail-open means traffic bypasses Zscaler when the agent can't reach the cloud. "
                "For strict-security tenants (regulated industries, zero-trust), fail-closed is "
                "mandatory — fail-open becomes an attacker's on-demand bypass.")
    if "tamper" in low or "uninstall" in low:
        return ("If users can uninstall or disable ZCC, the security posture is effectively "
                "voluntary. Tamper protection (uninstall password, strict enforcement) is "
                "required for enforceable compliance claims.")
    if "stale" in low or "not seen" in low or "unregister" in low:
        return ("Stale device records inflate the license count, hide compromised-device "
                "indicators, and make inventory auditing unreliable. Clean them up periodically.")

    # Fallback: explain the control
    if best_practice:
        bp_first = best_practice.split(".")[0]
        return (f"{bp_first}. This is the Zscaler-recommended baseline; deviations should be "
                "documented with business justification.")
    return ("This configuration deviates from Zscaler's documented best practice. "
            "Deviations increase the probability of missed threats, audit findings, or "
            "operational incidents. Review and either align with best practice or document "
            "the exception.")


def _generate_recommendation(check_id: str, label: str, as_is: str, best_practice: str) -> str:
    """
    Produce an actionable next-step recommendation based on pattern-matching
    the As-Is text against known misconfiguration signals.
    Falls back to a generic 'review against best practice' when no
    specific pattern matches.
    """
    low = (as_is or "").lower()

    # Extract the first concrete instruction from the best-practice text
    bp_first = (best_practice or "").split(".")[0].strip() if best_practice else ""

    # Pattern: feature missing / not configured / no X
    if any(t in low for t in ("not configured", "no cloud firewall", "no url filter", "no dlp",
                              "no rules", "no locations", "no admin role", "no engine",
                              "not enabled", "not set", "disabled", "no policy", "not applied",
                              "not deployed", "missing")):
        base = f"Configure {label}."
        if bp_first:
            return f"{base} Align with Zscaler best practice: {bp_first}."
        return base + " Follow Zscaler deployment guidance for this feature."

    # Pattern: partially scoped — rule exists but global / missing scope
    if any(t in low for t in ("globally scoped", "default action", "default rule", "no engines",
                              "overbroad", "no scope", "unscoped", "applied globally",
                              "unlimited", "no limit", "no description", "no owner")):
        return (
            f"Tighten scope on {label}. "
            f"{bp_first + '. ' if bp_first else ''}"
            f"Add user/group/location scoping, tag with a rule label, and document owner."
        )

    # Pattern: review / verify / needs human judgment (the detail already says so)
    if any(t in low for t in ("review", "verify", "validate", "confirm", "investigate")):
        if bp_first:
            return f"Review {label} against: {bp_first}. Document the outcome and re-run the assessment."
        return f"Review {label} with the feature owner. Document the outcome and re-run."

    # Pattern: count-based signal (e.g. "3 rules in review state")
    if any(t in low for t in ("some", "partial", "audit", "alert only", "log only")):
        return (
            f"Complete the rollout of {label}. "
            f"Move alert/log-only rules to enforcement after the validation window. "
            f"{bp_first + '.' if bp_first else ''}"
        )

    # Fallback: generic recommendation citing the best-practice text
    if bp_first:
        return f"Validate {label} against Zscaler best practice: {bp_first}."
    return f"Manually verify {label} and document the rationale. Re-run the assessment after any change."


def _plain_for(r: dict) -> dict:
    """The four plain-English sentences for a result: the ones the server
    attached (so the Word report says exactly what the results tab said),
    or freshly generated for a result that came from an older run."""
    pl = r.get("plain")
    if isinstance(pl, dict) and pl.get("found"):
        return pl
    try:
        import plain_english
        return plain_english.explain(r)
    except Exception:  # noqa: BLE001 - never let the explanation break the report
        return {"found": r.get("label", ""), "means": "", "do": "", "outcome": ""}


def _add_plain_block(doc, r: dict, indent=None, size=None):
    """Write the plain-English block under a finding: what we found, what it
    means for the business, what to do, and the outcome once fixed (or what
    a configured control gives the business)."""
    pl = _plain_for(r)
    status = str(r.get("status") or "").upper()
    lines = [("What we found: ", pl.get("found", ""))]
    if status != "PASS" and pl.get("means"):
        lines.append(("What it means for the business: ", pl["means"]))
    if status != "PASS" and pl.get("do"):
        lines.append(("What to do: ", pl["do"]))
    lines.append(("What this gives the business: " if status == "PASS" else "Once fixed: ", pl.get("outcome", "")))
    for head, text in lines:
        if not text:
            continue
        p = doc.add_paragraph()
        if indent is not None:
            p.paragraph_format.left_indent = indent
        p.paragraph_format.space_after = Pt(2)
        rh = p.add_run(head)
        rh.bold = True
        rt = p.add_run(text)
        if size is not None:
            rh.font.size = size
            rt.font.size = size
    if lines:
        p.paragraph_format.space_after = Pt(8)


def _safe_style(doc, preferred_names):
    """Return the first style name from preferred_names that exists in doc, else 'Table Grid' (always present)."""
    available = {s.name for s in doc.styles}
    for name in preferred_names:
        if name in available:
            return name
    return "Table Grid" if "Table Grid" in available else None

def _style_header_row(row, bg_hex="236BF5", fg_color=None):
    """Apply Zscaler-blue header styling to a table row."""
    for cell in row.cells:
        _set_cell_shading(cell, bg_hex)
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
                if fg_color:
                    run.font.color.rgb = fg_color

def _set_cell_shading(cell, color_hex):
    """Set background color on a table cell."""
    shading = cell._element.get_or_add_tcPr()
    shading_elem = shading.makeelement(qn("w:shd"), {
        qn("w:val"): "clear",
        qn("w:color"): "auto",
        qn("w:fill"): color_hex,
    })
    shading.append(shading_elem)


def _add_styled_row(table, cells_data):
    """Add a row with optional coloring."""
    row = table.add_row()
    for i, (text, bold, color) in enumerate(cells_data):
        cell = row.cells[i]
        p = cell.paragraphs[0]
        run = p.add_run(str(text))
        run.font.size = Pt(9)
        if bold:
            run.bold = True
        if color:
            run.font.color.rgb = color
    return row


# ── Main Generator ───────────────────────────────────────────────────

def _xml_safe(obj):
    """A copy of ``obj`` whose strings hold only characters XML can carry.
    Check details quote tenant names and uploaded text; one control
    character in them would make python-docx refuse the whole report."""
    from xlsx_writer import clean_text
    if isinstance(obj, str):
        return clean_text(obj)
    if isinstance(obj, dict):
        return {k: _xml_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_xml_safe(v) for v in obj]
    return obj


def generate_report(results, cfg, output_path, compute_fn=None, maturity_fn=None, template_path=None):
    """
    Generate a Word document report from assessment results.

    Args:
        results: List of check result dicts with id, sec, label, status, detail
        cfg: Config dict with org_name, assessor, cloud
        output_path: Path for the .docx file
        compute_fn: Optional compute function (imported from engine)
        maturity_fn: Optional maturity function (imported from engine)
        template_path: Optional path to a .docx template to use as the base.
                       If provided, the report appends content into the template's
                       layout, preserving header/footer/styles. Auto-detects
                       'zscaler_template.docx' in the same folder as this file.
    """
    results, cfg = _xml_safe(results or []), _xml_safe(cfg or {})
    # Import compute/maturity if not provided
    if compute_fn is None or maturity_fn is None:
        from dlp_assessment_full_auto import compute, maturity
        compute_fn = compute_fn or compute
        maturity_fn = maturity_fn or maturity

    # A check outside the selected scope (its channel neither on Zscaler nor
    # a prerequisite of one) has no row, no section and no score here: only
    # its count, in one line (channel_scope.hidden_note). `hidden_checks`
    # is what the assessment already left out; an older report that still
    # carries "Not in scope" rows has them dropped and counted here.
    import channel_scope
    import xlsx_writer
    # Tenant text (rule names in a detail) may carry characters XML cannot:
    # python-docx refuses them, so clean the inputs once, here.
    results, cfg = xlsx_writer.clean_tree(list(results or [])), xlsx_writer.clean_tree(dict(cfg or {}))
    results, dropped = channel_scope.visible(results)
    try:
        hidden = max(0, int((cfg or {}).get("hidden_checks") or 0)) + dropped
    except (TypeError, ValueError):
        hidden = dropped
    hidden_line = channel_scope.hidden_note(hidden)

    secs, overall = compute_fn(results)
    mat = maturity_fn(overall)
    # The same coverage vocabulary the GUI shows (permissions.assessment_summary):
    # execution (assessed / not permitted) apart from the score's denominator.
    try:
        from permissions import assessment_summary
        cov = assessment_summary(results, hidden=hidden)
    except Exception:  # noqa: BLE001
        cov = None
    overall_text = "Not assessed" if overall is None else f"{overall}%"

    # Use the Zscaler template if available
    if template_path is None:
        default_template = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_template.docx")
        if os.path.exists(default_template):
            template_path = default_template

    if template_path and os.path.exists(template_path):
        doc = Document(template_path)
        # Clear template body content but keep styles/headers/footers/margins
        for elem in list(doc.element.body):
            if elem.tag.endswith('}p') or elem.tag.endswith('}tbl'):
                doc.element.body.remove(elem)
    else:
        doc = Document()

    # ── Styles ────────────────────────────────────────────────────
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)

    # ── Title Page ────────────────────────────────────────────────
    doc.add_paragraph()  # spacer
    title = doc.add_heading("Zscaler Made Easy Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph()
    meta_table = doc.add_table(rows=0, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Organization", cfg.get("org_name", "Unknown")),
        ("Assessor", cfg.get("assessor", "Unknown")),
        ("Cloud", cfg.get("cloud", "Unknown")),
        ("Date", datetime.now().strftime("%B %d, %Y")),
        ("Total Checks", str(len(results))),
        ("Assessed", (f"{cov['assessed']} of {cov['total']}"
                      + (f" ({cov['not_permitted']} not permitted)" if cov["not_permitted"] else "")) if cov else str(len(results))),
        ("Overall Score", overall_text + (f" — {cov['configured']} configured of {cov['scored']} scoreable" if cov and cov["scored"] else "")),
        ("Maturity Level", mat),
    ]
    for label, value in meta_data:
        row = meta_table.add_row()
        row.cells[0].paragraphs[0].add_run(label).bold = True
        row.cells[1].text = value

    doc.add_page_break()

    # ── Executive Summary ─────────────────────────────────────────
    doc.add_heading("Executive Summary", level=1)

    counts = {"PASS": 0, "FAIL": 0, "REVIEW": 0, "INFO": 0}
    for r in results:
        st = r["status"]
        if st in counts:
            counts[st] += 1
        elif st == "ERROR":
            counts["INFO"] += 1

    summary = doc.add_paragraph()
    summary.add_run(f"The assessment of the Zscaler platform for {cfg.get('org_name', 'the organization')} "
                    f"evaluated {len(results)} configuration checks across all deployed Zscaler services. ")
    summary.add_run(f"The overall maturity score is {overall_text} ({mat}). ").bold = True
    if cov:
        summary.add_run(f"Score = {cov['score_formula']}: {cov['configured']} ÷ {cov['scored']}. "
                        f"{cov['excluded']} checks are outside the score ({cov['not_permitted']} not permitted, "
                        f"{cov['errors']} could not be checked, {cov['informational']} informational). ")
        if cov["not_permitted"]:
            summary.add_run(f"The assessment is partial: {cov['assessed']} of {cov['total']} checks ran; "
                            f"{cov['not_permitted']} could not because the API client's role does not include their feature. ")
    if hidden_line:
        summary.add_run(hidden_line + " ")

    summary2 = doc.add_paragraph()
    summary2.add_run("Configured correctly: ").bold = True
    summary2.add_run(f"{counts['PASS']} checks. ")
    summary2.add_run("Action required: ").bold = True
    summary2.add_run(f"{counts['FAIL']} checks. ")
    summary2.add_run("Needs review: ").bold = True
    summary2.add_run(f"{counts['REVIEW']} checks. ")
    summary2.add_run("Not configured/N/A: ").bold = True
    summary2.add_run(f"{counts['INFO']} checks" + (f" (of which {cov['not_permitted']} not permitted, {cov['errors']} could not be checked)." if cov else "."))

    # ── Channel coverage (the Scope page's declaration) ───────────
    # Only what was assessed: the channels on Zscaler, each prerequisite
    # with why it was added. What was left out is the one count in the
    # Executive Summary (hidden_line), never a list.
    chcov = cfg.get("channel_coverage") if isinstance(cfg, dict) else None
    if isinstance(chcov, dict) and chcov.get("declared"):
        doc.add_heading("Channel Coverage", level=2)
        doc.add_paragraph(str(chcov.get("note") or ""))
        rows = [r for r in (chcov.get("zscaler") or []) if isinstance(r, dict)]
        if rows:
            ch_table = doc.add_table(rows=1, cols=3)
            ch_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
            for i, h in enumerate(["Channel", "Assessed because", "Note"]):
                cell = ch_table.rows[0].cells[i]
                cell.text = h
                cell.paragraphs[0].runs[0].bold = True
            pre = {str(p.get("id")): p for p in (chcov.get("prerequisites") or []) if isinstance(p, dict)}
            for row in rows:
                cells = ch_table.add_row().cells
                cells[0].text = str(row.get("name") or row.get("id") or "")
                p = pre.get(str(row.get("id")))
                if p or row.get("prerequisite_of"):
                    cells[1].text = "Prerequisite: " + (str(p.get("note")) if p else "needed by a channel in scope")
                    cells[2].text = " ".join(p.get("reasons") or []) if p else ""
                else:
                    cells[1].text = "Ticked as Zscaler on the Scope page"
                    cells[2].text = str(row.get("note") or "")
        doc.add_paragraph()

    # ── Maturity Model Explanation ────────────────────────────────
    doc.add_heading("Maturity Model & Scoring Methodology", level=2)
    doc.add_paragraph(
        "This assessment uses a five-tier maturity model adapted from the Zscaler "
        "Zero Trust Maturity Framework. The overall score is calculated as the "
        "percentage of evaluable checks that pass, where evaluable checks are those "
        "where the corresponding feature is licensed and accessible via API. Features "
        "marked 'Not Configured / N/A' are excluded from scoring, since they represent "
        "capabilities not currently in use rather than failures."
    )

    mat_table = doc.add_table(rows=1, cols=3)
    mat_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
    mat_headers = ["Score Range", "Maturity Level", "Description"]
    for i, h in enumerate(mat_headers):
        cell = mat_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True

    mat_data = [
        ("0 – 24%", "Ad Hoc",
         "No formal program. Configurations are inconsistent or missing entirely. "
         "Significant exposure to data loss, threats, and compliance gaps. Immediate "
         "remediation needed for foundational security controls."),
        ("25 – 49%", "Initial",
         "Basic security controls in place but not standardized across the organization. "
         "Coverage is partial; key features (DLP, SSL inspection, MFA enforcement) may "
         "be missing or only applied to subsets of users."),
        ("50 – 74%", "Developing",
         "Most foundational controls are configured. Policy framework exists but "
         "consistency, scoping, and tuning need work. Some advanced features in pilot "
         "or limited rollout."),
        ("75 – 89%", "Managed",
         "Strong configuration baseline aligned with Zscaler best practices. Most "
         "policies properly scoped to users/groups. Comprehensive logging in place. "
         "Minor gaps remain in advanced features."),
        ("90 – 100%", "Optimized",
         "Comprehensive, well-tuned configuration matching Zscaler leading practices. "
         "Full coverage across all licensed services. Continuous monitoring, automated "
         "incident response, and integration with SIEM/SOAR. Mature zero trust posture."),
    ]
    current_band = mat
    for score_range, level, desc in mat_data:
        row = mat_table.add_row()
        row.cells[0].text = score_range
        row.cells[1].text = level
        row.cells[2].text = desc
        # Highlight the current maturity level
        if level == current_band:
            for cell in row.cells:
                cell.paragraphs[0].runs[0].bold = True

    doc.add_paragraph()
    you_are = doc.add_paragraph()
    you_are.add_run("Your organization is currently rated: ").italic = True
    your_run = you_are.add_run(f"{mat} ({overall_text})")
    your_run.bold = True
    if overall is None:
        your_run.font.color.rgb = COLORS.get("INFO", COLORS["REVIEW"])
    elif overall >= 75:
        your_run.font.color.rgb = COLORS["PASS"]
    elif overall >= 50:
        your_run.font.color.rgb = COLORS["REVIEW"]
    else:
        your_run.font.color.rgb = COLORS["FAIL"]

    # ── Status Definitions ────────────────────────────────────────
    doc.add_heading("Finding Status Definitions", level=2)
    sd_table = doc.add_table(rows=1, cols=4)
    sd_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
    sd_headers = ["Finding Name", "Best Practice", "Actual Configuration", "Why It Matters"]
    for i, h in enumerate(sd_headers):
        cell = sd_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
    sd_data = [
        (
            "Configured",
            "Feature enabled and scoped per Zscaler deployment guidance. "
            "Relevant controls active across users/locations.",
            "The tenant returned the expected settings and the check "
            "passed all validation rules.",
            "No action required. Keep monitoring — re-run the assessment "
            "periodically to catch drift."
        ),
        (
            "Action Required",
            "Feature is a Zscaler core best practice (SSL inspection, DLP "
            "dictionaries/engines, cloud firewall, etc.) and must be "
            "configured for baseline posture.",
            "Feature is disabled, not configured, or set in a way that "
            "defeats its protection (e.g. default-allow, bypass rules "
            "globally scoped, empty rule list).",
            "Critical gap — fix before next audit cycle. Address these "
            "findings first; they drive the largest impact on the "
            "overall score."
        ),
        (
            "Needs Review",
            "Feature should be deliberately scoped and periodically "
            "reviewed — typically rule ordering, engine tuning, "
            "exception lists, and logging retention.",
            "Feature is present but partial: some scope missing, some "
            "values default, exceptions in place that could not be "
            "auto-validated.",
            "Human judgment required. Schedule a review with the feature "
            "owner; the configuration may be intentional but warrants "
            "documentation and periodic re-review."
        ),
        (
            "Not Configured / N/A",
            "Feature is optional for many environments (e.g. ICAP, "
            "specific GenAI modules) or requires a subscription/licensing "
            "not present on every tenant.",
            "Endpoint returned 404/403 or the feature returned empty. "
            "The assessment could not read it — not confirmed absent, "
            "not confirmed present.",
            "Excluded from scoring. If the feature IS licensed, grant "
            "the API role read access and re-run. If it is not in scope, "
            "no action needed."
        ),
    ]
    for status, bp, asis, means in sd_data:
        row = sd_table.add_row()
        row.cells[0].text = status
        row.cells[0].paragraphs[0].runs[0].bold = True
        row.cells[1].text = bp
        row.cells[2].text = asis
        row.cells[3].text = means

    doc.add_page_break()

    # ── Score Summary Table ───────────────────────────────────────
    doc.add_heading("Scorecard by Section", level=2)

    score_table = doc.add_table(rows=1, cols=6)
    score_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
    headers = ["Section", "Score", "Configured", "Action Req.", "Review", "N/A"]
    for i, h in enumerate(headers):
        cell = score_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True

    for sec_name, data in secs.items():
        row = score_table.add_row()
        row.cells[0].text = sec_name
        pct = data.get("pct")
        row.cells[1].text = "Not measured" if pct is None else f"{pct}%"
        # Color the score
        run = row.cells[1].paragraphs[0].runs[0]
        if pct is None:
            run.font.color.rgb = COLORS.get("INFO", COLORS["REVIEW"])
        elif pct >= 75:
            run.font.color.rgb = COLORS["PASS"]
        elif pct >= 50:
            run.font.color.rgb = COLORS["REVIEW"]
        else:
            run.font.color.rgb = COLORS["FAIL"]
        row.cells[2].text = str(data["pass"])
        row.cells[3].text = str(data["fail"])
        row.cells[4].text = str(data["warn"])
        row.cells[5].text = str(data.get("info", 0))

    doc.add_page_break()

    # ── Critical Findings ─────────────────────────────────────────
    fails = [r for r in results if r["status"] == "FAIL"]
    if fails:
        doc.add_heading("Critical Findings — Immediate Action Required", level=1)
        for r in fails:
            p = doc.add_paragraph()
            run = p.add_run(f"{r['id']} — {r['label']}")
            run.bold = True
            run.font.color.rgb = COLORS["FAIL"]
            detail = doc.add_paragraph(r["detail"], style="List Bullet")
            detail.paragraph_format.space_after = Pt(6)
            _add_plain_block(doc, r)
        doc.add_page_break()

    # ── Review Items ──────────────────────────────────────────────
    reviews = [r for r in results if r["status"] == "REVIEW"]
    if reviews:
        doc.add_heading("Items Requiring Review", level=1)
        doc.add_paragraph(
            f"The following {len(reviews)} item(s) were detected but require manual "
            f"verification or organizational context to determine if action is needed. "
            f"Each row compares the current configuration to Zscaler best practice "
            f"and produces a specific recommended next step."
        )

        # Structured 5-column table:
        #   Finding Name | Best Practice | Actual | Why It Matters | Remediation Steps
        rv_table = doc.add_table(rows=1, cols=5)
        rv_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
        rv_headers = ["Finding Name", "Best Practice", "Actual Configuration", "Why It Matters", "Remediation Steps"]
        for i, h in enumerate(rv_headers):
            cell = rv_table.rows[0].cells[i]
            cell.text = h
            cell.paragraphs[0].runs[0].bold = True

        for r in reviews:
            as_is, best_practice = _parse_detail_for_bp(r.get("detail", ""))
            why_matters = _generate_why_it_matters(
                check_id=r.get("id", ""),
                label=r.get("label", ""),
                as_is=as_is,
                best_practice=best_practice,
                section=r.get("sec") or r.get("section") or "",
            )
            section_txt = r.get("sec") or r.get("section") or ""
            resolved_bp = best_practice or _resolve_best_practice(
                r.get("label", ""), section_txt, r.get("id", "")
            )
            portal_path, api_hint = _resolve_remediation(
                r.get("label", ""), section_txt, r.get("id", "")
            )
            row = rv_table.add_row()
            # Column 0: Finding Name (id + label)
            name_cell = row.cells[0]
            name_cell.text = ""
            np = name_cell.paragraphs[0]
            np.add_run(f"{r.get('id', '')}\n").bold = True
            np.add_run(r.get("label", ""))
            # Column 1: Best Practice
            row.cells[1].text = resolved_bp
            # Column 2: Actual Configuration
            row.cells[2].text = as_is or "(not specified)"
            # Column 3: Why It Matters (bold)
            why_cell = row.cells[3]
            why_cell.text = ""
            wp = why_cell.paragraphs[0]
            why_run = wp.add_run(why_matters)
            why_run.bold = True
            wp2 = why_cell.add_paragraph()
            wp2.add_run("Once fixed: ").bold = True
            wp2.add_run(_plain_for(r).get("outcome", ""))
            # Column 4: Remediation Steps — portal path + optional API hint
            rem_cell = row.cells[4]
            rem_cell.text = ""
            rp = rem_cell.paragraphs[0]
            rp.add_run("Admin portal: ").bold = True
            rp.add_run(portal_path)
            if api_hint:
                rp2 = rem_cell.add_paragraph()
                rp2.add_run("API: ").bold = True
                rp2.add_run(api_hint)
        doc.add_page_break()

    # ── Detailed Findings by Section ──────────────────────────────
    doc.add_heading("Detailed Findings", level=1)

    current_sec = ""
    for r in results:
        # Support both 'sec' and 'section' keys for backwards compatibility
        r_sec = r.get("sec") or r.get("section") or "Other"
        if r_sec != current_sec:
            current_sec = r_sec
            doc.add_heading(current_sec, level=2)

            # Section summary
            if current_sec in secs:
                sd = secs[current_sec]
                sp = doc.add_paragraph()
                sp.add_run(f"Score: {'not measured (no scoreable check)' if sd.get('pct') is None else str(sd['pct']) + '%'} — ")
                sp.add_run(f"{sd['pass']} configured, {sd['fail']} action required, "
                          f"{sd['warn']} review, {sd.get('info',0)} N/A")
                sp.paragraph_format.space_after = Pt(12)

        # Individual check
        p = doc.add_paragraph()
        status = r["status"]
        label = STATUS_LABELS.get(status, status)
        color = COLORS.get(status, RGBColor(0, 0, 0))

        run_id = p.add_run(f"[{r['id']}] ")
        run_id.font.size = Pt(9)
        run_id.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

        run_status = p.add_run(f"{label}  ")
        run_status.bold = True
        run_status.font.color.rgb = color
        run_status.font.size = Pt(9)

        run_label = p.add_run(f"{r['label']}")
        run_label.font.size = Pt(10)

        if r.get("detail"):
            detail_p = doc.add_paragraph()
            detail_p.paragraph_format.left_indent = Cm(1)
            detail_p.paragraph_format.space_after = Pt(4)
            run_d = detail_p.add_run(r["detail"])
            run_d.font.size = Pt(9)
            run_d.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
        _add_plain_block(doc, r, indent=Cm(1), size=Pt(9))

    # ── Not Configured Summary ────────────────────────────────────
    infos = [r for r in results if r["status"] in ("INFO", "ERROR")]
    if infos:
        doc.add_page_break()
        doc.add_heading("Features Not Configured or Not Licensed", level=1)
        p = doc.add_paragraph(
            f"The following {len(infos)} feature(s) were not accessible during the assessment. "
            f"This may indicate the feature is not licensed, not configured, or the API client "
            f"role does not have permission to read this data."
        )
        doc.add_paragraph()

        nc_table = doc.add_table(rows=1, cols=3)
        nc_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
        nc_table.rows[0].cells[0].text = "Check"
        nc_table.rows[0].cells[1].text = "Feature"
        nc_table.rows[0].cells[2].text = "Detail"
        for cell in nc_table.rows[0].cells:
            cell.paragraphs[0].runs[0].bold = True

        for r in infos:
            row = nc_table.add_row()
            row.cells[0].text = r["id"]
            row.cells[1].text = r["label"]
            # Truncate long details for table
            detail = r.get("detail", "")
            row.cells[2].text = detail[:120] + ("..." if len(detail) > 120 else "")
            for cell in row.cells:
                for p in cell.paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(8)

    # ── Compliance Framework Mapping ──────────────────────────────
    try:
        from compliance_mapping import get_framework_summary, FRAMEWORK_DESCRIPTIONS
        fw_summary = get_framework_summary(results)
        if fw_summary:
            doc.add_page_break()
            doc.add_heading("Regulatory & Compliance Framework Alignment", level=1)
            doc.add_paragraph(
                "The following compliance frameworks have controls addressed by this "
                "Zscaler configuration assessment. Each framework's alignment status is "
                "calculated from the relevant checks that map to its controls."
            )

            fw_table = doc.add_table(rows=1, cols=4)
            fw_table.style = _safe_style(doc, ["Light Grid Accent 1", "Light List Accent 1", "Light Grid", "Table Grid"])
            fw_headers = ["Framework", "Status", "Alignment", "Controls Addressed"]
            for i, h in enumerate(fw_headers):
                cell = fw_table.rows[0].cells[i]
                cell.text = h
                cell.paragraphs[0].runs[0].bold = True

            for fw_key, summary in sorted(fw_summary.items()):
                row = fw_table.add_row()
                row.cells[0].text = FRAMEWORK_DESCRIPTIONS.get(fw_key, fw_key).split(" — ")[0]
                row.cells[1].text = summary["status"]
                # Color status
                stat_run = row.cells[1].paragraphs[0].runs[0]
                stat_run.bold = True
                if summary["status"] == "Aligned":
                    stat_run.font.color.rgb = COLORS["PASS"]
                elif summary["status"] == "Partial":
                    stat_run.font.color.rgb = COLORS["REVIEW"]
                else:
                    stat_run.font.color.rgb = COLORS["FAIL"]
                row.cells[2].text = (f"{summary['alignment_pct']}% ({summary['passing_count']}/{summary['covered_count'] - summary['info_count']} mapped checks configured)"
                                     if summary.get("alignment_pct") is not None else "Not measured (no scoreable mapped check)")
                row.cells[3].text = f"{summary['control_count']} control(s)"

            # Detailed framework breakdown
            doc.add_paragraph()
            doc.add_heading("Detailed Control Mapping by Framework", level=2)
            for fw_key, summary in sorted(fw_summary.items()):
                doc.add_heading(FRAMEWORK_DESCRIPTIONS.get(fw_key, fw_key), level=3)
                p = doc.add_paragraph()
                p.add_run("Status: ").bold = True
                stat_text = p.add_run(f"{summary['status']} ({summary['alignment_pct']}% of mapped checks configured)" if summary.get("alignment_pct") is not None else f"{summary['status']}")
                stat_text.bold = True
                if summary["status"] == "Aligned":
                    stat_text.font.color.rgb = COLORS["PASS"]
                elif summary["status"] == "Partial":
                    stat_text.font.color.rgb = COLORS["REVIEW"]
                else:
                    stat_text.font.color.rgb = COLORS["FAIL"]

                p2 = doc.add_paragraph()
                p2.add_run("Findings: ").bold = True
                p2.add_run(f"{summary['passing_count']} configured, {summary['failing_count']} action required, "
                           f"{summary['review_count']} need review, {summary['info_count']} N/A")

                p3 = doc.add_paragraph()
                p3.add_run("Controls Addressed:").bold = True
                ctrl_p = doc.add_paragraph()
                ctrl_p.paragraph_format.left_indent = Cm(0.5)
                ctrl_p.add_run(", ".join(summary["controls_addressed"])).font.size = Pt(9)
    except Exception:  # noqa: BLE001 - a compliance-mapping failure must not break the report
        pass

    # ── Footer ────────────────────────────────────────────────────
    doc.add_page_break()
    doc.add_heading("About This Assessment", level=1)
    doc.add_paragraph(
        "This report was generated by the Zscaler Made Easy Automation Engine. "
        "All checks are performed via the Zscaler OneAPI using read-only API calls. "
        "No configuration changes were made during the assessment."
    )
    doc.add_paragraph(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    doc.add_paragraph(f"Engine version: 3.0 | Total checks: {len(results)}")

    # ── Save ──────────────────────────────────────────────────────
    doc.save(output_path)
    return output_path


# ── CLI Usage ────────────────────────────────────────────────────────

# ── POV customer report (pov.report_document) ───────────────────────

def pov_report(rep):
    """A POV customer report as .docx bytes, on the same template, styles
    and header colours as the assessment report: title, summary, details,
    then each section's paragraphs, table, bullets and sub-items."""
    import io
    rep = _xml_safe(rep or {})
    template = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_template.docx")
    if os.path.exists(template):
        doc = Document(template)
        for elem in list(doc.element.body):
            if elem.tag.endswith('}p') or elem.tag.endswith('}tbl'):
                doc.element.body.remove(elem)
    else:
        doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)
    doc.add_heading(rep.get("title") or "Proof of value", level=0)
    if rep.get("summary"):
        doc.add_paragraph(rep["summary"])
    meta = doc.add_table(rows=0, cols=2)
    meta.style = _safe_style(doc, ["Table Grid"])
    for label, value in rep.get("details") or []:
        row = meta.add_row()
        row.cells[0].paragraphs[0].add_run(str(label)).bold = True
        row.cells[1].text = str(value)
    bullet = _safe_style(doc, ["List Bullet"]) if "List Bullet" in {s.name for s in doc.styles} else None
    for sec in rep.get("sections") or []:
        doc.add_heading(sec.get("heading") or "", level=1)
        for p in sec.get("paragraphs") or []:
            doc.add_paragraph(str(p))
        t = sec.get("table")
        if t:
            table = doc.add_table(rows=1, cols=len(t["columns"]))
            table.style = _safe_style(doc, ["Table Grid"])
            for i, h in enumerate(t["columns"]):
                table.rows[0].cells[i].text = str(h)
            _style_header_row(table.rows[0], ZS_BLUE_HEX, ZS_WHITE)
            for r in t["rows"]:
                _add_styled_row(table, [(v, False, COLORS["PASS"] if v == "Pass" or v == "Met" else COLORS["FAIL"] if v in ("Fail", "Not met") else None)
                                        for v in r])
        for item in sec.get("items") or []:
            doc.add_heading(str(item.get("title") or ""), level=2)
            for b in item.get("bullets") or []:
                doc.add_paragraph(str(b), style=bullet)
        for b in sec.get("bullets") or []:
            doc.add_paragraph(str(b), style=bullet)
        if sec.get("note"):
            doc.add_paragraph(str(sec["note"]))
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python report_docx.py <report.json> [output.docx]")
        sys.exit(1)

    json_path = sys.argv[1]
    with open(json_path) as f:
        data = json.load(f)

    results = data.get("checks", [])
    cfg = dict(data.get("metadata", {}) or {})
    for k in ("channel_coverage", "hidden_checks"):
        if k in data:
            cfg[k] = data[k]
    output = sys.argv[2] if len(sys.argv) > 2 else json_path.replace(".json", ".docx")

    generate_report(results, cfg, output)
    print(f"Report saved: {output}")

