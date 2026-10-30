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
from zscaler_full_checks import guard_registry
from dlp_assessment_full_auto import R, _ls

_now = time.time   # the clock, injectable in tests


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
    # ZIA user records have adminUser but no role, so the admin list is read
    # directly, enabled admins only (AdminUser.disabled — zscaler-sdk-python
    # zia/models/admin_users.py).
    dd, cc = cl.get("/zia/adminUsers")
    if cc != 200:
        return R(R.INFO, f"Admin users endpoint returned HTTP {cc}.")
    admins = [a for a in _ls(dd) if isinstance(a, dict) and not a.get("disabled")]
    if not admins:
        return R(R.INFO, "No enabled admin user is listed on this tenant.")
    if len(admins) < 2:
        return R(R.WARN, f"Only {len(admins)} admin user(s). Best Practice: Minimum 2 admins for business continuity — single-admin tenants lock out when that admin leaves / loses MFA.")
    if len(admins) > 20:
        return R(R.WARN, f"{len(admins)} admin users — that's a lot. Best Practice: Audit admin list quarterly; remove former employees and contractors. Over-provisioned admin accounts are the #1 audit finding.")
    return R(R.PASS, f"{len(admins)} admin user(s) — within reasonable BCP range.")


def rbac_zia_sso_federated(cl):
    """End-user authentication type, and where admin SSO is set

    /authSettings holds the organisation's end-user authentication settings
    (orgAuthType, "User authentication type" — zscaler-sdk-python
    zia/models/authentication_settings.py); it does not cover admin login.
    ZIA admins are users in Authentication Service (formerly ZIdentity) with
    a ZIA entitlement, and admin SSO is configured there."""
    admin_note = (" Admin login is handled by Authentication Service (formerly ZIdentity); verify an external IdP is configured under"
                  " Administration > Authentication. Ref: https://help.zscaler.com/zia/about-administrators")
    d, c = cl.get("/zia/authSettings")
    if c != 200 or not isinstance(d, dict):
        return R(R.INFO, "Authentication settings endpoint not exposed on this tenant." + admin_note)
    auth_type = str(d.get("orgAuthType") or d.get("org_auth_type") or "").upper()
    if not auth_type:
        return R(R.INFO, "The end-user authentication type (orgAuthType) is not reported." + admin_note)
    if "SAML" in auth_type:
        return R(R.PASS, f"End users authenticate with {auth_type}." + admin_note)
    return R(R.WARN, f"End-user authentication type is {auth_type}. Best Practice: authenticate users through your corporate IdP (SAML) with MFA enforced." + admin_note)


def rbac_zia_mfa_required(cl):
    """MFA required for admin logins"""
    # /authSettings has no MFA field: admin MFA is enforced by Authentication Service.
    return R(R.INFO, "Admin MFA is enforced by Authentication Service (formerly ZIdentity) and is required by default for all admins. Verify it is still enabled under"
                     " Administration > Authentication > Authentication Methods, and that no admin has Skip Second Factor Authentication set."
                     " Ref: https://help.zscaler.com/authentication-service/configuring-multi-factor-authentication")


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
    # AdminUserSyncInfo (zscaler-sdk-python zcc/models/admin_user.py): the
    # Client Connector portal syncing its admin users from ZIA and ZPA.
    if isinstance(d, dict):
        parts, errs, pending = [], [], []
        for svc, pre in (("ZIA", "zia"), ("ZPA", "zpa")):
            last, done, err = d.get(pre + "LastSyncTime"), d.get(pre + "InitialSyncDone"), d.get(pre + "SyncErrorCode")
            if last is None and done is None and err is None:
                continue
            parts.append(f"{svc} last sync {last or 'never'} ({d.get(pre + 'SyncStatus') or 'status not reported'})")
            if err not in (None, "", 0, "0"):
                errs.append(f"{svc} error code {err}")
            elif done is False:
                pending.append(svc)
        if errs:
            return R(R.WARN, f"Client Connector admin sync from ZIA/ZPA reports errors: {', '.join(errs)}. " + "; ".join(parts) + ".")
        if pending:
            return R(R.WARN, f"The initial admin sync from {', '.join(pending)} to the Client Connector portal has not completed. " + "; ".join(parts) + ".")
        if parts:
            return R(R.PASS, "The Client Connector portal syncs its admin users from ZIA and ZPA without errors: " + "; ".join(parts) + ".")
    return R(R.INFO, "Admin sync info does not report ZIA or ZPA sync fields; check it in the Client Connector portal.")


# ─────────────────────────────────────────────────────────────────
# ZPA access-policy RBAC
# ─────────────────────────────────────────────────────────────────

def rbac_zpa_policies_group_bound(cl):
    """ZPA access policies bound to SCIM/groups, not individuals"""
    d, c = cl.get("/zpa/policySet/rules/ACCESS_POLICY")
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
                # ZPA operands have no USER type: SCIM_GROUP binds a group, SAML and
                # SCIM bind an attribute (email, userName …), which may be one user.
                # APP_GROUP, MACHINE_GRP, *_CONNECTOR_GROUP etc. are not identities.
                otype = str(op.get("objectType", "")).upper()
                if otype == "SCIM_GROUP":
                    group_bound += 1
                elif otype in ("SAML", "SCIM"):
                    user_bound += 1
    total_binds = group_bound + user_bound
    if total_binds == 0:
        return R(R.INFO, "ZPA rule conditions don't expose group/user bindings via this endpoint.")
    if user_bound > 0:
        return R(R.WARN, f"{user_bound} ZPA rule condition(s) bind to a SAML or SCIM attribute (vs {group_bound} SCIM group bindings); review them for per-user bindings (for example an email or userName). Best Practice: Bind to SCIM_GROUP where possible. Per-user bindings don't survive offboarding cleanly and inflate rule count.")
    return R(R.PASS, f"All {group_bound} ZPA identity bindings are SCIM group-based. Aligns with role-based access control.")


# ─────────────────────────────────────────────────────────────────
# ZIdentity directory RBAC
# ─────────────────────────────────────────────────────────────────

def rbac_zid_admin_redundancy(cl):
    """ZIdentity has at least 2 admin-tagged users"""
    d, c = cl.get("/zid/users")
    users = _ls(d) if c == 200 else []
    if c in (401, 403):
        return R(R.INFO, "Authentication Service (formerly ZIdentity) users not accessible.")
    if not users:
        return R(R.INFO, "The Authentication Service (formerly ZIdentity) directory appears empty.")
    # UserRecord has adminEntitlementEnabled, not roles or groups (zscaler-sdk-python zid/models/users.py).
    admins = [u for u in users if isinstance(u, dict) and u.get("adminEntitlementEnabled") and str(u.get("status", "")).lower() not in ("false", "disabled", "inactive")]
    if len(admins) < 2:
        return R(R.WARN, f"Only {len(admins)} active admin user(s) in Authentication Service (formerly ZIdentity). Best Practice: Maintain ≥ 2 admins for BCP.")
    return R(R.PASS, f"{len(admins)} active admin user(s) in Authentication Service (formerly ZIdentity) — BCP redundancy in place.")


def rbac_zid_group_based(cl):
    """ZIdentity entitlements are group-based, not per-user"""
    return R(R.INFO, "Authentication Service (formerly ZIdentity) lists entitlements per user (/users/{id}/service-entitlements), not for the whole tenant, so group-only binding is not assessed here. "
                     "Best Practice: Prefer group-based role assignments — per-user entitlements don't survive offboarding cleanly. Review them under Administration > Authentication in the Zscaler Admin Console.")


def rbac_zid_stale_admins(cl):
    """Stale admin accounts (last login > 90 days)"""
    d, c = cl.get("/zid/users")
    users = _ls(d) if c == 200 else []
    if c in (401, 403) or not users:
        return R(R.INFO, "Cannot enumerate users for staleness check.")
    now = _now()
    stale = reported = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        # UserRecord (zscaler-sdk-python 1.11.3 zid/models/users.py) has no
        # last-login field; these names are read when an API reports them.
        last = u.get("lastLogin") or u.get("lastLoginTime") or u.get("lastSeen") or 0
        if isinstance(last, (int, float)) and not isinstance(last, bool) and last > 0:
            reported += 1
            if last > 1e12:
                last = last / 1000.0
            if now - last > 90 * 86400:
                stale += 1
    if not reported:
        # No login time at all is no evidence: never "no stale accounts".
        return R(R.INFO, f"The Authentication Service (formerly ZIdentity) user list ({len(users)} user(s)) reports no last-login time, so stale admin accounts "
                         "cannot be found from the API. Review last sign-in under Administration > Authentication, or in your IdP.")
    if stale:
        return R(R.WARN, f"{stale} admin/user account(s) haven't logged in in 90+ days. Best Practice: Disable or remove — dormant admin accounts are the #1 path into a breach (no one notices when they're used). NIST 800-53 AC-2(3).")
    return R(R.PASS, f"No stale accounts: all {reported} account(s) that report a last login signed in within the last 90 days.")


# ─────────────────────────────────────────────────────────────────
# Register
# ─────────────────────────────────────────────────────────────────

RBAC_REG = [
    ("RBAC.1",  "RBAC — ZIA",       "Multiple admin roles (least privilege)",       rbac_zia_roles_count),
    ("RBAC.2",  "RBAC — ZIA",       "Read-only auditor role exists",                rbac_zia_readonly_exists),
    ("RBAC.3",  "RBAC — ZIA",       "Admin count (BCP + not over-provisioned)",     rbac_zia_admin_count),
    ("RBAC.4",  "RBAC — ZIA",       "End-user authentication type",                 rbac_zia_sso_federated),
    ("RBAC.5",  "RBAC — ZIA",       "MFA required for admin login",                 rbac_zia_mfa_required),
    ("RBAC.6",  "RBAC — ZCC",       "ZCC admin count (BCP)",                        rbac_zcc_admin_count),
    ("RBAC.7",  "RBAC — ZCC",       "ZCC role split (read-only vs admin)",          rbac_zcc_role_split),
    ("RBAC.8",  "RBAC — ZCC",       "ZCC admin sync from ZIA/ZPA healthy",          rbac_zcc_idp_sync),
    ("RBAC.9",  "RBAC — ZPA",       "Access policies group-bound (not per-user)",   rbac_zpa_policies_group_bound),
    ("RBAC.10", "RBAC — ZIdentity", "Admin redundancy (BCP)",                       rbac_zid_admin_redundancy),
    ("RBAC.11", "RBAC — ZIdentity", "Group-based entitlements (no per-user)",       rbac_zid_group_based),
    ("RBAC.12", "RBAC — ZIdentity", "Stale admin accounts (> 90 days no login)",    rbac_zid_stale_admins),
]
RBAC_REG = guard_registry(RBAC_REG)   # a refused read (HTTP 401/403) is "Not permitted", never judged
