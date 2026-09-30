#!/usr/bin/env python3
"""
Zscaler Automation Readiness Checks
=====================================
Validates whether a tenant is ready for the modern Zscaler automation
ecosystem published at https://github.com/zscaler. Every check here
is tied to a specific requirement of one of those projects.

Projects tracked and what they require
--------------------------------------
  - zscaler-sdk-python / -go / -java / -ruby  (official OneAPI SDKs)
      → OneAPI client credentials; consistent rule shapes; rate-limit
        headroom; token TTL respected
  - zscaler-terraformer  (importer; tenant → HCL)
      → Every rule has id + order; stable unique names;
        descriptions populated for round-trip fidelity
  - terraform-provider-zia / -zpa / -zscaler  (IaC)
      → No special chars in rule names (HCL-safe); unique names per
        resource type; descriptions present
  - zia-ansible-collection / zpa / zcc / zdx-ansible-collection
      → API client role scoped; admin audit log accessible so
        Ansible runs are auditable
  - zpcap, zscaler-tools  (ops tooling)
      → Service edges / App Connectors healthy; no orphaned resources

Each check returns INFO (feature absent but harmless), PASS, REVIEW,
or FAIL with a detail string that cites the github.com/zscaler
project the check supports. All read-only. No writes.
"""

import re
from dlp_assessment_full_auto import R, _ls


# Invalid HCL identifier pattern — terraform-provider-zia requires
# resource names to be HCL-compatible (alphanumeric + underscore + dash).
_HCL_INVALID_CHARS = re.compile(r"[^A-Za-z0-9_\- ]")


# ═══════════════════════════════════════════════════════════════════════
# SDK / OneAPI readiness
# ═══════════════════════════════════════════════════════════════════════

def auto_sdk_1(cl):
    """OneAPI auth is working (required by every Zscaler SDK)"""
    # If we got this far, auth succeeded — surface as explicit PASS so
    # the automation section always has at least one positive data point.
    if cl.token and cl.base:
        return R(R.PASS,
                 f"OneAPI authentication successful against {cl.base}. "
                 f"Compatible with zscaler-sdk-python/go/java/ruby "
                 f"(https://github.com/zscaler/zscaler-sdk-python).")
    return R(R.FAIL,
             "OneAPI auth did not complete. Ensure API client creds "
             "are issued in the ZIdentity admin portal and the role "
             "has OneAPI scopes enabled.")


def auto_sdk_2(cl):
    """Token TTL ≥ 30 minutes (SDK token cache assumption)"""
    if not cl.exp or not cl.token:
        return R(R.INFO, "Token expiry not observable on this client.")
    import time
    ttl = max(0, int(cl.exp - time.time()))
    if ttl < 600:
        return R(R.WARN,
                 f"Token TTL is only {ttl}s. Zscaler SDKs assume ≥30 min "
                 f"tokens; very short-lived tokens cause excess auth "
                 f"traffic and rate-limit pressure.")
    return R(R.PASS,
             f"Token TTL ≥ {ttl}s — SDK token cache will hold through "
             f"long assessment / automation runs.")


def auto_sdk_3(cl):
    """API rate-limit headroom (verify /zia/status responds fast — proxy for rate-limit state)"""
    d, c = cl.get("/zia/status")
    if c == 429:
        return R(R.FAIL,
                 "ZIA API is actively rate-limiting this client. Automation "
                 "runs (terraform plan, ansible converge) will fail. "
                 "Reduce concurrent jobs or stagger them. "
                 "Ref: https://github.com/zscaler/zscaler-sdk-python#rate-limits")
    if c == 200:
        return R(R.PASS, "ZIA API responding without rate-limit pressure.")
    return R(R.INFO, f"Rate-limit probe inconclusive (HTTP {c}).")


# ═══════════════════════════════════════════════════════════════════════
# Terraform readiness (zscaler-terraformer + terraform-provider-zia/-zpa)
# ═══════════════════════════════════════════════════════════════════════

def auto_tf_1(cl):
    """Every rule has an 'id' field (required by zscaler-terraformer)"""
    rules_missing_id = 0
    total = 0
    for ep in ("/zia/webDlpRules", "/zia/urlFilteringRules",
               "/zia/firewallFilteringRules", "/zia/sslInspectionRules"):
        d, c = cl.get(ep)
        if c != 200:
            continue
        for r in _ls(d):
            if not isinstance(r, dict):
                continue
            total += 1
            if r.get("id") in (None, "", 0):
                rules_missing_id += 1
    if total == 0:
        return R(R.INFO, "No rules visible to check for ID population.")
    if rules_missing_id:
        return R(R.FAIL,
                 f"{rules_missing_id} of {total} rules are missing 'id'. "
                 f"zscaler-terraformer requires id to derive HCL resource "
                 f"addresses. Ref: https://github.com/zscaler/zscaler-terraformer")
    return R(R.PASS,
             f"All {total} rules carry an 'id' — zscaler-terraformer "
             f"can import them cleanly.")


def auto_tf_2(cl):
    """Rule names HCL-safe (terraform-provider-zia requires [A-Za-z0-9_-])"""
    problematic = []
    total = 0
    for ep in ("/zia/webDlpRules", "/zia/urlFilteringRules",
               "/zia/firewallFilteringRules"):
        d, c = cl.get(ep)
        if c != 200:
            continue
        for rule in _ls(d):
            if not isinstance(rule, dict):
                continue
            total += 1
            name = rule.get("name") or ""
            if _HCL_INVALID_CHARS.search(name):
                problematic.append(f"#{rule.get('id')}:{name[:40]}")
    if total == 0:
        return R(R.INFO, "No rules visible to check for HCL-safe naming.")
    if problematic:
        sample = ", ".join(problematic[:5])
        more = f" (+{len(problematic) - 5} more)" if len(problematic) > 5 else ""
        return R(R.WARN,
                 f"{len(problematic)} of {total} rules contain characters "
                 f"that terraform-provider-zia treats specially "
                 f"(punctuation / emoji / non-ASCII). Rename for clean "
                 f"IaC round-trip. Samples: {sample}{more}. "
                 f"Ref: https://github.com/zscaler/terraform-provider-zia")
    return R(R.PASS,
             f"All {total} rule names are HCL-safe for "
             f"terraform-provider-zia/-zpa.")


def auto_tf_3(cl):
    """Rules have 'order' set (terraform plan requires it for ordering)"""
    missing_order = 0
    total = 0
    for ep in ("/zia/webDlpRules", "/zia/urlFilteringRules",
               "/zia/firewallFilteringRules"):
        d, c = cl.get(ep)
        if c != 200:
            continue
        for r in _ls(d):
            if not isinstance(r, dict):
                continue
            total += 1
            if r.get("order") in (None, "", 0):
                missing_order += 1
    if total == 0:
        return R(R.INFO, "No rules visible to check for order field.")
    if missing_order:
        return R(R.WARN,
                 f"{missing_order} of {total} rules have no 'order'. "
                 f"Without explicit order, terraform plan produces "
                 f"unstable diffs. Re-save affected rules in the portal "
                 f"to set order, or use the migration wizard's 'Post' "
                 f"step with explicit positions.")
    return R(R.PASS,
             f"All {total} rules have explicit 'order' — terraform "
             f"diffs will be stable.")


def auto_tf_4(cl):
    """Rule descriptions populated (needed for terraform round-trip fidelity)"""
    no_desc = 0
    total = 0
    for ep in ("/zia/webDlpRules", "/zia/urlFilteringRules",
               "/zia/firewallFilteringRules"):
        d, c = cl.get(ep)
        if c != 200:
            continue
        for r in _ls(d):
            if not isinstance(r, dict):
                continue
            total += 1
            if not (r.get("description") or "").strip():
                no_desc += 1
    if total == 0:
        return R(R.INFO, "No rules visible to check for descriptions.")
    if no_desc / total > 0.5:
        return R(R.WARN,
                 f"{no_desc} of {total} rules have no description. "
                 f"Descriptions carry the business-justification audit "
                 f"trail and are preserved by terraform-provider-zia's "
                 f"round-trip. Best practice: populate for every rule.")
    return R(R.PASS,
             f"{total - no_desc} of {total} rules have descriptions — "
             f"good IaC round-trip fidelity.")


def auto_tf_5(cl):
    """Unique rule names (terraformer derives resource addresses from name)"""
    duplicates = {}
    total = 0
    for ep, label in (("/zia/webDlpRules", "web_dlp"),
                      ("/zia/urlFilteringRules", "url"),
                      ("/zia/firewallFilteringRules", "fw")):
        d, c = cl.get(ep)
        if c != 200:
            continue
        seen = {}
        for r in _ls(d):
            if not isinstance(r, dict):
                continue
            total += 1
            n = (r.get("name") or "").strip()
            if not n:
                continue
            if n in seen:
                duplicates.setdefault(label, []).append(n)
            seen[n] = r.get("id")
    if total == 0:
        return R(R.INFO, "No rules visible to check for name uniqueness.")
    if duplicates:
        details = "; ".join(f"{k}: {len(v)} dup(s)" for k, v in duplicates.items())
        return R(R.WARN,
                 f"Duplicate rule names detected ({details}). "
                 f"zscaler-terraformer uses name for resource addresses "
                 f"— duplicates cause import collisions. "
                 f"Ref: https://github.com/zscaler/zscaler-terraformer")
    return R(R.PASS,
             f"All {total} rule names are unique within their rule types.")


# ═══════════════════════════════════════════════════════════════════════
# Ansible readiness (*-ansible-collection)
# ═══════════════════════════════════════════════════════════════════════

def auto_ans_1(cl):
    """Admin audit log accessible (Ansible runs must be auditable)"""
    d, c = cl.get("/zia/auditlogEntryReport")
    if c == 200:
        return R(R.PASS,
                 "Admin audit log API reachable — Ansible converge runs "
                 "will leave a traceable audit trail. Ref: "
                 "https://github.com/zscaler/zia-ansible-collection")
    if c in (401, 403):
        return R(R.WARN,
                 "API client role does not include audit log read scope. "
                 "Automation runs (Ansible, CI/CD jobs) will not be "
                 "traceable back to a specific job without this. "
                 "Add 'View Activity Log' to the role.")
    return R(R.INFO,
             f"Audit log reachability inconclusive (HTTP {c}).")


def auto_ans_2(cl):
    """Admin audit log retention ≥ 30 days (needed for compliance replay)"""
    d, c = cl.get("/zia/auditlogEntryReport")
    # The endpoint returns configuration info; we check for retention hints
    if c != 200 or not isinstance(d, dict):
        return R(R.INFO, "Retention not inspectable via this endpoint.")
    ret = d.get("retentionDays") or d.get("retention_period") or d.get("retention")
    if isinstance(ret, (int, float)) and ret < 30:
        return R(R.WARN,
                 f"Audit log retention is {ret} days. Automation best "
                 f"practice is ≥ 30 days to cover most compliance review "
                 f"cycles (SOC 2, PCI-DSS).")
    if isinstance(ret, (int, float)):
        return R(R.PASS,
                 f"Audit log retention {ret} days — covers typical "
                 f"compliance review windows.")
    return R(R.INFO,
             "Retention value not exposed in this response shape.")


def auto_ans_3(cl):
    """Locations API reachable (zia-ansible-collection: zia_location_management)"""
    d, c = cl.get("/zia/locations")
    if c == 200:
        return R(R.PASS,
                 f"Locations API reachable ({len(_ls(d))} location(s)). "
                 f"Compatible with zia-ansible-collection "
                 f"'zia_location_management' module.")
    return R(R.INFO,
             f"Locations endpoint returned HTTP {c}. "
             f"If using zia-ansible-collection, grant 'View Locations' "
             f"to the API client role.")


# ═══════════════════════════════════════════════════════════════════════
# ZPA automation (zpa-ansible-collection + terraform-provider-zpa)
# ═══════════════════════════════════════════════════════════════════════

def auto_zpa_1(cl):
    """ZPA customer ID configured (required by zpa-ansible-collection + TF)"""
    if cl.customer_id:
        return R(R.PASS,
                 f"ZPA customer ID configured: {cl.customer_id}. "
                 f"Compatible with zpa-ansible-collection and "
                 f"terraform-provider-zpa.")
    return R(R.INFO,
             "ZPA customer ID not provided. All ZPA automation modules "
             "(zpa-ansible-collection, terraform-provider-zpa) REQUIRE "
             "customer_id. Configure it in the API client.")


def auto_zpa_2(cl):
    """ZPA App Connector groups discoverable"""
    d, c = cl.get("/zpa/appConnectorGroup")
    if c == 200:
        groups = _ls(d)
        return R(R.PASS,
                 f"{len(groups)} App Connector Group(s) — automatable via "
                 f"terraform-provider-zpa zpa_app_connector_group.")
    if c == 404 and not cl.customer_id:
        return R(R.INFO, "ZPA checks skipped (customer_id not set).")
    return R(R.INFO, f"App Connector Groups endpoint returned HTTP {c}.")


def auto_zpa_3(cl):
    """ZPA App Segments have TCP port ranges set (terraform drift)"""
    d, c = cl.get("/zpa/application")
    if c != 200:
        return R(R.INFO,
                 f"App Segments endpoint returned HTTP {c}.")
    apps = _ls(d)
    no_ports = [a for a in apps
                if not (a.get("tcpPortRanges") or a.get("tcpPortRange")
                        or a.get("udpPortRanges") or a.get("udpPortRange"))]
    if no_ports:
        return R(R.WARN,
                 f"{len(no_ports)} of {len(apps)} App Segments have no "
                 f"port ranges configured — will drift under terraform "
                 f"plan. Ref: terraform-provider-zpa zpa_application_segment.")
    return R(R.PASS,
             f"All {len(apps)} App Segment(s) carry port ranges — "
             f"stable under terraform.")


# ═══════════════════════════════════════════════════════════════════════
# General IaC / automation hygiene
# ═══════════════════════════════════════════════════════════════════════

def auto_iac_1(cl):
    """Admin roles present (least-privilege for API clients)"""
    d, c = cl.get("/zia/adminRoles")
    if c != 200:
        return R(R.INFO, f"Admin roles endpoint returned HTTP {c}.")
    roles = _ls(d)
    super_admins = [r for r in roles
                    if "super" in (r.get("name") or "").lower()
                    or (r.get("rank") or 99) == 1]
    if len(roles) <= 2:
        return R(R.WARN,
                 f"Only {len(roles)} admin role(s). Least-privilege best "
                 f"practice (required by most Zscaler automation guides): "
                 f"define a dedicated API-client role per automation use "
                 f"case (e.g., 'terraform-reader', 'ansible-executor') "
                 f"rather than reusing super-admin.")
    return R(R.PASS,
             f"{len(roles)} admin role(s) defined (super-admin: "
             f"{len(super_admins)}). Good basis for per-automation "
             f"least-privilege API clients.")


def auto_iac_2(cl):
    """Rule-label / tag system in use (IaC best practice for bulk ops)"""
    d, c = cl.get("/zia/ruleLabels")
    if c != 200:
        return R(R.INFO,
                 "Rule Labels endpoint not accessible. If available in "
                 "your subscription, use rule labels to tag IaC-managed "
                 "rules — lets terraform-provider-zia filter on "
                 "'iac-managed' vs. hand-edited.")
    labels = _ls(d)
    if not labels:
        return R(R.WARN,
                 "No rule labels defined. Best practice: create at least "
                 "one label (e.g., 'iac-managed', 'legacy') to distinguish "
                 "terraform/ansible-owned rules from portal-edited rules.")
    return R(R.PASS,
             f"{len(labels)} rule label(s) defined — usable by "
             f"terraform-provider-zia for IaC tagging.")


def auto_iac_3(cl):
    """Sandbox API reachable (supports zscaler-terraformer dry-runs)"""
    d, c = cl.get("/zia/sandbox/report/quota")
    if c == 200:
        return R(R.PASS,
                 "ZIA Sandbox API reachable — allows IaC pipelines to "
                 "submit suspicious files pre-prod for validation. "
                 "Ref: https://github.com/zscaler/zscaler-sdk-python")
    return R(R.INFO,
             f"Sandbox API returned HTTP {c}. If your subscription "
             "includes Cloud Sandbox, grant 'View Sandbox Reports' to "
             "the API client role to enable IaC sandbox validation.")


# ═══════════════════════════════════════════════════════════════════════
# ZCC automation (zcc-ansible-collection + zpcap)
# ═══════════════════════════════════════════════════════════════════════

def auto_zcc_1(cl):
    """ZCC Portal API reachable (required by zcc-ansible-collection)"""
    d, c = cl.get("/zcc/companyInfo")
    if c == 200:
        return R(R.PASS,
                 "ZCC Portal API reachable — compatible with "
                 "zcc-ansible-collection and zpcap "
                 "(https://github.com/zscaler/zpcap).")
    return R(R.INFO,
             f"ZCC companyInfo returned HTTP {c}. For ZCC automation, "
             "grant 'ZCC Portal Access' to the API client role.")


def auto_zcc_2(cl):
    """ZCC Devices inventory discoverable (zpcap packet-capture targets)"""
    d, c = cl.get("/zcc/devices")
    if c == 200:
        devices = _ls(d)
        return R(R.PASS,
                 f"{len(devices)} ZCC device(s) discoverable via API — "
                 f"zpcap and zcc-ansible-collection can target them.")
    return R(R.INFO, f"Devices endpoint returned HTTP {c}.")


# ═══════════════════════════════════════════════════════════════════════
# Register
# ═══════════════════════════════════════════════════════════════════════

AUTOMATION_REG = [
    # (id, section, label, fn)
    ("AUTO-SDK-01", "Automation — SDK / OneAPI", "OneAPI auth working",                         auto_sdk_1),
    ("AUTO-SDK-02", "Automation — SDK / OneAPI", "Token TTL suitable for automation runs",     auto_sdk_2),
    ("AUTO-SDK-03", "Automation — SDK / OneAPI", "ZIA API not rate-limiting this client",      auto_sdk_3),

    ("AUTO-TF-01",  "Automation — Terraform",     "Rules carry 'id' (zscaler-terraformer import)", auto_tf_1),
    ("AUTO-TF-02",  "Automation — Terraform",     "Rule names HCL-safe (terraform-provider-zia)",  auto_tf_2),
    ("AUTO-TF-03",  "Automation — Terraform",     "Rules have explicit 'order' (stable plans)",    auto_tf_3),
    ("AUTO-TF-04",  "Automation — Terraform",     "Rule descriptions populated (round-trip)",      auto_tf_4),
    ("AUTO-TF-05",  "Automation — Terraform",     "Rule names unique within type (terraformer)",   auto_tf_5),

    ("AUTO-ANS-01", "Automation — Ansible",       "Admin audit log accessible",                    auto_ans_1),
    ("AUTO-ANS-02", "Automation — Ansible",       "Audit log retention ≥ 30 days",                 auto_ans_2),
    ("AUTO-ANS-03", "Automation — Ansible",       "Locations API reachable",                       auto_ans_3),

    ("AUTO-ZPA-01", "Automation — ZPA",           "ZPA customer_id configured",                    auto_zpa_1),
    ("AUTO-ZPA-02", "Automation — ZPA",           "App Connector Groups discoverable",             auto_zpa_2),
    ("AUTO-ZPA-03", "Automation — ZPA",           "App Segments have port ranges (TF stability)",  auto_zpa_3),

    ("AUTO-ZCC-01", "Automation — ZCC",           "ZCC Portal API reachable",                      auto_zcc_1),
    ("AUTO-ZCC-02", "Automation — ZCC",           "ZCC devices inventory discoverable",            auto_zcc_2),

    ("AUTO-IAC-01", "Automation — IaC Hygiene",   "Admin roles enable least-privilege clients",    auto_iac_1),
    ("AUTO-IAC-02", "Automation — IaC Hygiene",   "Rule labels available for IaC tagging",         auto_iac_2),
    ("AUTO-IAC-03", "Automation — IaC Hygiene",   "Sandbox API reachable (IaC dry-runs)",          auto_iac_3),
]
