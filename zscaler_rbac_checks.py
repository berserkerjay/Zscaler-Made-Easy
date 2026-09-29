#!/usr/bin/env python3
"""
Zscaler Role-Based Access Control (RBAC) Checks
=================================================
Validates admin / user / role hygiene across the Zscaler platform
to meet least-privilege + separation-of-duty controls required by
SOC 2 CC6.1, NIST 800-53 AC-2 / AC-5 / AC-6, PCI-DSS 7.x, HIPAA
164.308(a)(3), and ISO 27001 A.5.15–A.5.18.

Scopes covered:
  - ZIA admin roles + admin users
  - ZCC Mobile Portal admin roles + users
  - ZPA access policy (bound to groups vs individuals)
  - ZIdentity directory (role assignments, admin redundancy)

All checks read-only. None modify the tenant.
"""
import time
from dlp_assessment_full_auto import R, _ls


# ─────────────────────────────────────────────────────────────────
# ZIA admin-role hygiene
# ─────────────────────────────────────────────────────────────────

def rbac_zia_roles_count(cl):
    """ZIA has more than just one super-admin role"""
    d, c = cl.get("/zia/adminRoles")
    roles = _ls(d) if c == 200 else []
    if c != 200:
        return R(R.INFO, f"ZIA admin roles endpoint returned HTTP {c}.")
    if not roles:
        return R(R.WARN, "No custom ZIA admin roles defined. Best Practice: Define at least 'auditor (read-only)' and 'operator (change-capable)' roles in addition to the built-in super-admin. Assigning super-admin to automation API clients violates least-privilege.")
    if len(roles) < 2:
        return R(R.WARN, f"Only {len(roles)} ZIA admin role(s). Best Practice: Minimum 2 roles — a read-only auditor role and a change-capable admin role.")
    return R(R.PASS, f"{len(roles)} ZIA admin role(s) defined.")


def rbac_zia_readonly_exists(cl):
    """A read-only ZIA admin role exists"""
    d, c = cl.get("/zia/adminRoles")
    roles = _ls(d) if c == 200 else []
    if c != 200:
        return R(R.INFO, f"ZIA admin roles not accessible (HTTP {c}).")
    readonly = [r for r in roles if any(t in (r.get("name") or "").lower()
                                        for t in ("read", "audit", "viewer", "observer"))]
    if not readonly:
        return R(R.WARN, "No read-only admin role found. Best Practice: Create a 'Auditor' or 'Read-Only' role for SOC analysts and auditors — grants visibility without change authority. Critical for SOC 2 CC6.1 separation of duty.")
    return R(R.PASS, f"{len(readonly)} read-only admin role(s) present.")


def rbac_zia_admin_count(cl):
    """Admin count: enough for BCP but not over-provisioned"""
    d, c = cl.get("/zia/users")
    users = _ls(d) if c == 200 else []
    if c != 200:
        return R(R.INFO, f"Users endpoint returned HTTP {c}.")
    admins = [u for u in users
              if any((r.get("name") if isinstance(r, dict) else str(r)).lower().startswith(("admin", "super"))
                     for r in (u.get("adminUser") and [u.get("role", {})] or []))]
    # Different shape: some tenants expose /zia/admins separately
    if not admins:
        dd, cc = cl.get("/zia/admins")
        admins = _ls(dd) if cc == 200 else []
    if not admins:
        return R(R.INFO, "Admin count endpoint shape not recognized on this tenant.")
    if len(admins) < 2:
        return R(R.WARN, f"Only {len(admins)} admin user(s). Best Practice: Minimum 2 admins for business continuity — single-admin tenants lock out when that admin leaves / loses MFA.")
    if len(admins) > 20:
        return R(R.WARN, f"{len(admins)} admin users — that's a lot. Best Practice: Audit admin list quarterly; remove former employees and contractors. Over-provisioned admin accounts are the #1 audit finding.")
    return R(R.PASS, f"{len(admins)} admin user(s) — within reasonable BCP range.")


def rbac_zia_sso_federated(cl):
    """Admin login federated to IdP (SAML/SSO), not local accounts"""
    d, c = cl.get("/zia/authSettings")
    if c != 200:
        d, c = cl.get("/zia/authenticationSettings")
    if c != 200 or not isinstance(d, dict):
        return R(R.INFO, "Authentication settings endpoint not exposed on this tenant.")
    auth_type = str(d.get("authType") or d.get("authenticationType") or "").upper()
    if "SAML" in auth_type or "SSO" in auth_type:
        return R(R.PASS, f"Admin auth uses SAML/SSO ({auth_type}). Aligns with zero-trust + audit best practice.")
    if "LOCAL" in auth_type or "HOSTED" in auth_type or auth_type == "":
        return R(R.WARN, f"Admin auth: {auth_type or 'UNSPECIFIED'}. Best Practice: Federate admin login to your corporate IdP (Okta, Azure AD, Ping) with MFA enforced. Local/hosted accounts bypass enterprise password policy + MFA.")
    return R(R.INFO, f"Admin auth type: {auth_type}. Verify MFA is enforced.")


def rbac_zia_mfa_required(cl):
    """MFA required for admin logins"""
    d, c = cl.get("/zia/authSettings")
    if c != 200:
        d, c = cl.get("/zia/authenticationSettings")
    if c != 200 or not isinstance(d, dict):
        return R(R.INFO, "MFA status not inspectable via this endpoint.")
    for key in ("mfaEnabled", "mfaRequired", "requireMfa", "twoFactorAuthEnabled", "tfaEnabled"):
        if key in d:
            if d[key]:
                return R(R.PASS, f"MFA is enabled for admin login ({key}).")
            return R(R.WARN, f"MFA is DISABLED for admin login ({key}=false). Best Practice: Require MFA for every admin — a stolen password without MFA is instant super-admin access. PCI-DSS 8.4 mandates MFA for administrative access to the CDE.")
    return R(R.INFO, "MFA toggle not exposed on this endpoint. Verify in ZIA Admin → Authentication Settings.")


# ─────────────────────────────────────────────────────────────────
# ZCC admin-role hygiene
# ─────────────────────────────────────────────────────────────────

def rbac_zcc_admin_count(cl):
    """ZCC admin user count for BCP"""
    d, c = cl.get("/zcc/adminUsers")
    admins = _ls(d) if c == 200 else []
    if c in (401, 403):
        return R(R.INFO, "ZCC admin users API not accessible — role lacks ZCC read.")
    if not admins:
        return R(R.WARN, "No ZCC admin users enrolled. Best Practice: At least 2 admins for BCP.")
    if len(admins) < 2:
        return R(R.WARN, f"Only {len(admins)} ZCC admin(s). Best Practice: Minimum 2 for BCP.")
    return R(R.PASS, f"{len(admins)} ZCC admin(s).")


def rbac_zcc_role_split(cl):
    """ZCC has distinct roles (not all super-admin)"""
    d, c = cl.get("/zcc/adminRoles")
    roles = _ls(d) if c == 200 else []
    if c in (401, 403):
        return R(R.INFO, "ZCC admin roles API not accessible.")
    if len(roles) < 2:
        return R(R.WARN, f"{len(roles)} ZCC admin role(s). Best Practice: Define 'ZCC Read-Only' and 'ZCC Admin' as separate roles so SOC/helpdesk can see devices without being able to remove them.")
    return R(R.PASS, f"{len(roles)} ZCC admin role(s) defined.")


def rbac_zcc_idp_sync(cl):
    """ZCC admin sync to IdP is healthy"""
    d, c = cl.get("/zcc/adminUsersSyncInfo")
    if c in (401, 403):
        return R(R.INFO, "ZCC admin sync info not accessible.")
    if c != 200:
        return R(R.INFO, f"Sync info endpoint returned HTTP {c}.")
    if isinstance(d, dict):
        last = d.get("lastSync") or d.get("lastSyncTime")
        if last:
            return R(R.PASS, f"ZCC admin sync active (last: {last}). Groups flow from IdP → least privilege follows membership changes automatically.")
    return R(R.INFO, "Sync info shape not recognized; verify IdP binding in ZCC admin portal.")


# ─────────────────────────────────────────────────────────────────
# ZPA access-policy RBAC
# ─────────────────────────────────────────────────────────────────

def rbac_zpa_policies_group_bound(cl):
    """ZPA access policies bound to SCIM/groups, not individuals"""
    d, c = cl.get("/zpa/policySet/rules/ACCESS_POLICY")
    if c not in (200, 204):
        # Some tenants use a different path
        d, c = cl.get("/zpa/policySet/rules")
    rules = _ls(d) if c == 200 else []
    if c not in (200, 204):
        return R(R.INFO, f"ZPA access policy endpoint returned HTTP {c}.")
    if not rules:
        return R(R.INFO, "No ZPA access policy rules to evaluate.")
    group_bound = 0
    user_bound = 0
    for r in rules:
        conds = r.get("conditions") or []
        # Walk operands for OBJECT_TYPE of SCIM_GROUP vs USER
        for cond in conds:
            for op in (cond.get("operands") or []):
                otype = str(op.get("objectType", "")).upper()
                if "SCIM_GROUP" in otype or "GROUP" in otype:
                    group_bound += 1
                elif otype == "USER" or otype.endswith("_USER"):
                    user_bound += 1
    total_binds = group_bound + user_bound
    if total_binds == 0:
        return R(R.INFO, "ZPA rule conditions don't expose group/user bindings via this endpoint.")
    if user_bound > 0:
        return R(R.WARN, f"{user_bound} ZPA rule condition(s) bind to individual USERs (vs {group_bound} group bindings). Best Practice: Bind to SCIM_GROUP only. Per-user bindings don't survive offboarding cleanly and inflate rule count.")
    return R(R.PASS, f"All {group_bound} ZPA rule bindings are group-based. Aligns with role-based access control.")


# ─────────────────────────────────────────────────────────────────
# ZIdentity directory RBAC
# ─────────────────────────────────────────────────────────────────

def rbac_zid_admin_redundancy(cl):
    """ZIdentity has at least 2 admin-tagged users"""
    d, c = cl.get("/zid/users")
    users = _ls(d) if c == 200 else []
    if c in (401, 403):
        return R(R.INFO, "ZIdentity users not accessible.")
    if not users:
        return R(R.INFO, "ZIdentity directory appears empty.")
    def _is_admin(u):
        for r in (u.get("roles") or u.get("groups") or []):
            if "admin" in str(r).lower():
                return True
        return False
    admins = [u for u in users if _is_admin(u)]
    if len(admins) < 2:
        return R(R.WARN, f"Only {len(admins)} admin-tagged ZIdentity user(s). Best Practice: Maintain ≥ 2 admins for BCP.")
    return R(R.PASS, f"{len(admins)} admin-tagged ZIdentity user(s) — BCP redundancy in place.")


def rbac_zid_group_based(cl):
    """ZIdentity entitlements are group-based, not per-user"""
    d, c = cl.get("/zid/userEntitlement")
    items = _ls(d) if c == 200 else []
    if c in (401, 403):
        return R(R.INFO, "User entitlements not accessible.")
    if not items:
        return R(R.PASS, "No individual-user entitlements returned — best practice of group-only binding is in force.")
    return R(R.WARN, f"{len(items)} individual-user entitlement(s) found. Best Practice: Prefer group-based role assignments — per-user entitlements don't survive offboarding cleanly.")


def rbac_zid_stale_admins(cl):
    """Stale admin accounts (last login > 90 days)"""
    d, c = cl.get("/zid/users")
    users = _ls(d) if c == 200 else []
    if c in (401, 403) or not users:
        return R(R.INFO, "Cannot enumerate users for staleness check.")
    now = time.time()
    stale = 0
    for u in users:
        last = u.get("lastLogin") or u.get("lastLoginTime") or u.get("lastSeen") or 0
        if isinstance(last, (int, float)) and last > 0:
            if last > 1e12:
                last = last / 1000.0
            if now - last > 90 * 86400:
                stale += 1
    if stale:
        return R(R.WARN, f"{stale} admin/user account(s) haven't logged in in 90+ days. Best Practice: Disable or remove — dormant admin accounts are the #1 path into a breach (no one notices when they're used). NIST 800-53 AC-2(3).")
    return R(R.PASS, "No stale admin accounts detected in the last 90 days.")


# ─────────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────────

RBAC_REG = [
    ("RBAC.1",  "RBAC — ZIA",       "Multiple admin roles (least privilege)",       rbac_zia_roles_count),
    ("RBAC.2",  "RBAC — ZIA",       "Read-only auditor role exists",                rbac_zia_readonly_exists),
    ("RBAC.3",  "RBAC — ZIA",       "Admin count (BCP + not over-provisioned)",     rbac_zia_admin_count),
    ("RBAC.4",  "RBAC — ZIA",       "SSO / IdP federation for admin login",         rbac_zia_sso_federated),
    ("RBAC.5",  "RBAC — ZIA",       "MFA required for admin login",                 rbac_zia_mfa_required),
    ("RBAC.6",  "RBAC — ZCC",       "ZCC admin count (BCP)",                        rbac_zcc_admin_count),
    ("RBAC.7",  "RBAC — ZCC",       "ZCC role split (read-only vs admin)",          rbac_zcc_role_split),
    ("RBAC.8",  "RBAC — ZCC",       "ZCC admin IdP sync healthy",                   rbac_zcc_idp_sync),
    ("RBAC.9",  "RBAC — ZPA",       "Access policies group-bound (not per-user)",   rbac_zpa_policies_group_bound),
    ("RBAC.10", "RBAC — ZIdentity", "Admin redundancy (BCP)",                       rbac_zid_admin_redundancy),
    ("RBAC.11", "RBAC — ZIdentity", "Group-based entitlements (no per-user)",       rbac_zid_group_based),
    ("RBAC.12", "RBAC — ZIdentity", "Stale admin accounts (> 90 days no login)",    rbac_zid_stale_admins),
]
