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
  - ZPA administration: admins, roles, admin SSO, API keys, emergency
    access, microtenants, provisioning keys, PRA credentials and approvals
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
# ZPA administration: admins, roles, admin SSO, API keys, break-glass
# accounts, microtenants, provisioning keys and Privileged Remote Access
# ─────────────────────────────────────────────────────────────────
# Paths and fields from zscaler-sdk-python 1.11.3 (zscaler/zpa/):
#   administrator_controller.list_administrators  /administrators         models/administrator_controller.py
#   role_controller.list_roles                     /roles                  models/role_controller.py
#   admin_sso_controller.get_sso_controller        /v2/ssoLoginOptions     (a dict, {"ssologinonly": bool})
#   api_keys.list_api_keys                         /apiKeys                models/api_keys.py
#   emergency_access.list_users                    /emergencyAccess/users  models/emergency_access.py
#   microtenants.list_microtenants                 /microtenants           models/microtenants.py
#   provisioning.list_provisioning_keys            /associationType/{CONNECTOR_GRP|SERVICE_EDGE_GRP}/provisioningKey
#   pra_credential.list_credentials                /credential             models/pra_credential.py
#   pra_credential_pool.list_credential_pool       /credential-pool (waap-pra-config service)
#   pra_approval.list_approval                     /approval               models/pra_approval.py
# Every list is scrubbed as it is read (offline_tenant.scrub): a password,
# client secret, token or provisioning key value never reaches a check, a
# result or a log. Admins are people: they are counted, never listed.

# The endpoints, named once for tests and the snapshot list; the checks
# write them out as literals, which is how beacon_scope finds what a check reads.
ZPA_ADMINS = "/zpa/administrators"
ZPA_ROLES = "/zpa/roles"
ZPA_SSO = "/zpa/ssoLoginOptions"
ZPA_API_KEYS = "/zpa/apiKeys"
ZPA_EMERGENCY = "/zpa/emergencyAccess/users"
ZPA_MICROTENANTS = "/zpa/microtenants"
ZPA_PROV_KEYS = ("/zpa/associationType/CONNECTOR_GRP/provisioningKey", "/zpa/associationType/SERVICE_EDGE_GRP/provisioningKey")
ZPA_PRA_CREDENTIALS = "/zpa/credential"
ZPA_PRA_POOLS = "/zpa/credential-pool"
ZPA_PRA_APPROVALS = "/zpa/approval"

_ZPA_PAGES = 10            # at most 10 pages of 500 per list
_MAX_MICROTENANTS = 20     # per-microtenant reads are capped
_DAY = 86400
_NOT_LICENSED = (400, 404, 405)


def _zpa_rows(cl, ep, extra=None):
    """Every row of a ZPA list (paged, bounded), scrubbed of secret values.
    (rows, HTTP status of the first page)."""
    from offline_tenant import scrub
    rows, first = [], None
    for page in range(1, _ZPA_PAGES + 1):
        params = {"page": page, "pagesize": 500}
        params.update(extra or {})
        d, c = cl.get(ep, params)
        if first is None:
            first = c
        if c not in (200, 204):
            break
        items = [x for x in _ls(d) if isinstance(x, dict)] if c == 200 else []
        rows.extend(scrub(items))
        try:
            total = int(d.get("totalPages") or 1) if isinstance(d, dict) else 1
        except (TypeError, ValueError):
            total = 1
        if page >= total or not items:
            break
    return rows, first


def _not_read(label, code):
    if code in (401, 403):
        return R(R.INFO, f"{label}: not permitted (HTTP {code}). Access denied — the API client's role cannot read this; it is not judged.")
    if code in _NOT_LICENSED:
        return R(R.INFO, f"{label}: not available on this tenant (HTTP {code}); Not licensed or not in use. N/A.")
    return R(R.INFO, f"{label}: not readable (HTTP {code}).")


def _truthy(v):
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _epoch(v):
    """Seconds since 1970 from a ZPA time (epoch seconds or milliseconds, as a
    number or text); None when it is not one."""
    if isinstance(v, bool) or v in (None, ""):
        return None
    try:
        t = float(v)
    except (TypeError, ValueError):
        return None
    if t <= 0:
        return None
    return t / 1000.0 if t > 1e12 else t


def _role_classes(role):
    """{class: FULL|VIEW_ONLY|NONE} of a ZPA role, as readiness reads it."""
    import readiness
    return readiness._zpa_classes(role)


def _role_kind(role):
    """"full", "read_only" or "custom" for a ZPA role. From its permission
    classes when listed; else from its name (assumed: Zscaler's built-in
    full-access role names say "super" or "full", read-only ones "read",
    "view" or "audit")."""
    import re
    classes = _role_classes(role)
    name = str(role.get("name") or "")
    if classes:
        if all(v == "FULL" for v in classes.values()):
            return "full"
        if not any(v == "FULL" for v in classes.values()):
            return "read_only"
        return "custom"
    if re.search(r"super|full", name, re.I):
        return "full"
    if re.search(r"read|view|audit", name, re.I):
        return "read_only"
    return "custom"


def _role_id(obj):
    """The role an admin or API key holds. The SDK keeps an admin's `role` as
    the API sends it (assumed: {"id", "name"}) and an API key's `roleId`."""
    r = obj.get("role")
    if isinstance(r, dict):
        return str(r.get("id") or r.get("name") or "")
    return str(obj.get("roleId") or r or "")


def _roles_by_id(cl):
    roles, c = _zpa_rows(cl, "/zpa/roles")
    return {str(r.get("id")): r for r in roles if r.get("id") is not None}, c


def _enabled_admins(rows):
    # isEnabled false or isDeleted true: not an active admin (models/administrator_controller.py).
    return [a for a in rows if not _truthy(a.get("isDeleted")) and a.get("isEnabled") is not False
            and str(a.get("isEnabled")).lower() != "false"]


def rbac_zpa_admin_count(cl):
    """Enough ZPA admins for continuity, and not too many"""
    rows, c = _zpa_rows(cl, "/zpa/administrators")
    if c not in (200, 204):
        return _not_read("ZPA administrators", c)
    admins = _enabled_admins(rows)
    if not admins:
        return R(R.INFO, "No enabled ZPA administrator is listed (admins may sign in through Authentication Service only).")
    if len(admins) < 2:
        return R(R.WARN, f"Only {len(admins)} enabled ZPA administrator. Best Practice: Keep at least 2 named admins (plus a break-glass account) so the tenant is not locked out when one person leaves or loses their second factor.")
    if len(admins) > 20:
        return R(R.WARN, f"{len(admins)} enabled ZPA administrators. Best Practice: Review the list every quarter and remove people who have left or no longer need it; every extra admin is another account that can open private applications to the internet.")
    return R(R.PASS, f"{len(admins)} enabled ZPA administrators: enough for continuity, not over-provisioned.")


def rbac_zpa_admin_mfa(cl):
    """ZPA admins who sign in locally use a second factor"""
    rows, c = _zpa_rows(cl, "/zpa/administrators")
    if c not in (200, 204):
        return _not_read("ZPA administrators", c)
    admins = _enabled_admins(rows)
    local = [a for a in admins if not _truthy(a.get("localLoginDisabled"))]
    if not admins:
        return R(R.INFO, "No enabled ZPA administrator is listed, so local sign-in cannot be judged.")
    if not local:
        return R(R.PASS, f"None of the {len(admins)} enabled ZPA administrators can sign in with a local password: all go through SSO.")
    no_mfa = [a for a in local if not _truthy(a.get("twoFactorAuthEnabled"))]
    if no_mfa:
        return R(R.FAIL, f"{len(no_mfa)} of {len(local)} ZPA administrator(s) who can sign in with a local password have no second factor. Best Practice: Turn on two-factor authentication for every local admin, or disable local login so they sign in through your IdP with MFA.")
    return R(R.PASS, f"All {len(local)} ZPA administrator(s) who can sign in with a local password use a second factor.")


def rbac_zpa_sso_only(cl):
    """ZPA admin sign-in goes through SSO"""
    d, c = cl.get("/zpa/ssoLoginOptions")
    if c not in (200, 204) or not isinstance(d, dict):
        return _not_read("ZPA admin SSO login options", c) if c not in (200, 204) else R(R.INFO, "ZPA admin SSO login options returned no settings.")
    # The SDK documents the key as "ssologinonly"; other spellings are read too (assumed).
    val = next((d[k] for k in ("ssologinonly", "ssoLoginOnly", "sso_login_only") if k in d), None)
    if val is None:
        return R(R.INFO, "ZPA admin SSO login options do not report whether sign-in is SSO-only.")
    if _truthy(val):
        return R(R.PASS, "ZPA admins can sign in through SSO only: admin access follows your IdP's MFA and offboarding.")
    return R(R.WARN, "ZPA admins can still sign in with a local password. Best Practice: Turn on SSO login only, so admin access follows your IdP's MFA and offboarding, and keep an emergency access account for when the IdP is down.")


def rbac_zpa_super_admin_share(cl):
    """Few ZPA admins hold a full-access role"""
    rows, c = _zpa_rows(cl, "/zpa/administrators")
    if c not in (200, 204):
        return _not_read("ZPA administrators", c)
    roles, rc = _roles_by_id(cl)
    if rc not in (200, 204):
        return _not_read("ZPA roles", rc)
    admins = _enabled_admins(rows)
    if not admins:
        return R(R.INFO, "No enabled ZPA administrator is listed, so role assignments cannot be judged.")
    known = [a for a in admins if _role_id(a) in roles]
    if not known:
        return R(R.INFO, f"The roles of the {len(admins)} enabled ZPA administrator(s) are not reported in a form that can be matched to the role list.")
    full = [a for a in known if _role_kind(roles[_role_id(a)]) == "full"]
    if len(full) > 3 and len(full) * 2 > len(known):
        return R(R.WARN, f"{len(full)} of {len(known)} ZPA administrators hold a full-access role. Best Practice: Keep full access to 2 or 3 people and give everyone else a role scoped to what they run (for example app segments only, or read-only).")
    return R(R.PASS, f"{len(full)} of {len(known)} ZPA administrators hold a full-access role.")


def rbac_zpa_least_privilege_roles(cl):
    """ZPA has a read-only role and scoped roles"""
    roles, c = _roles_by_id(cl)
    if c not in (200, 204):
        return _not_read("ZPA roles", c)
    if not roles:
        return R(R.INFO, "No ZPA roles are listed.")
    kinds = [_role_kind(r) for r in roles.values()]
    ro, custom = kinds.count("read_only"), kinds.count("custom")
    if not ro:
        return R(R.WARN, f"None of the {len(roles)} ZPA role(s) is read-only. Best Practice: Create a read-only role for auditors, the SOC and automation that only reads, so they can see ZPA without being able to change access.")
    if not custom and len(roles) < 3:
        return R(R.WARN, f"{len(roles)} ZPA role(s), {ro} read-only and none scoped to a task. Best Practice: Add roles scoped to what each team runs (app segments, connectors, policy) instead of full access.")
    return R(R.PASS, f"{len(roles)} ZPA role(s): {ro} read-only, {custom} scoped to a task.")


def rbac_zpa_api_keys(cl):
    """ZPA API keys: least privilege and short-lived tokens"""
    keys, c = _zpa_rows(cl, "/zpa/apiKeys")
    if c not in (200, 204):
        return _not_read("ZPA API keys", c)
    live = [k for k in keys if k.get("enabled") is not False and str(k.get("enabled")).lower() != "false"]
    if not live:
        return R(R.PASS, "No enabled ZPA API key: automation uses OneAPI clients (or none).")
    roles, _rc = _roles_by_id(cl)
    full = [k for k in live if _role_id(k) in roles and _role_kind(roles[_role_id(k)]) == "full" and not _truthy(k.get("readOnly"))]
    long_lived = []
    for k in live:
        try:
            if int(k.get("tokenExpiryTimeInSec") or 0) > _DAY:
                long_lived.append(k)
        except (TypeError, ValueError):
            pass
    issues = []
    if full:
        issues.append(f"{len(full)} hold a full-access role")
    if long_lived:
        issues.append(f"{len(long_lived)} issue tokens valid for more than a day")
    if issues:
        return R(R.WARN, f"{len(live)} enabled ZPA API key(s): " + " and ".join(issues) + ". Best Practice: Give each key a read-only or task-scoped role, keep token lifetimes to an hour or less, and move automation to OneAPI clients.")
    return R(R.PASS, f"{len(live)} enabled ZPA API key(s), none with full access and none with tokens valid for more than a day.")


def rbac_zpa_emergency_access(cl):
    """A ZPA break-glass account exists and is kept dormant"""
    d, c = cl.get("/zpa/emergencyAccess/users")
    if c not in (200, 204):
        return _not_read("ZPA emergency access accounts", c)
    from offline_tenant import scrub
    users = scrub([x for x in _ls(d) if isinstance(x, dict)]) if c == 200 else []
    if not users:
        return R(R.WARN, "No ZPA emergency access (break-glass) account. Best Practice: Keep one or two emergency access accounts that do not depend on your IdP, so ZPA can still be administered when the IdP is down.")
    # userStatus values are not enumerated by the SDK (assumed: ACTIVE when usable).
    active = [u for u in users if str(u.get("userStatus") or "").upper() in ("ACTIVE", "ACTIVATED", "ENABLED")]
    now = _now()
    recent = [u for u in users if (_epoch(u.get("lastLoginTime")) or 0) > now - 30 * _DAY]
    if len(active) > 3:
        return R(R.WARN, f"{len(active)} of {len(users)} ZPA emergency access accounts are active. Best Practice: Keep at most 2 or 3, activate one only when needed, and deactivate it afterwards.")
    if recent:
        return R(R.WARN, f"{len(recent)} ZPA emergency access account(s) signed in during the last 30 days. Best Practice: A break-glass account is for outages only; confirm each sign-in was an emergency, then rotate its password.")
    return R(R.PASS, f"{len(users)} ZPA emergency access account(s), {len(active)} active, none used in the last 30 days.")


def rbac_zpa_microtenant_admins(cl):
    """Each ZPA microtenant has its own administrators"""
    mts, c = _zpa_rows(cl, "/zpa/microtenants")
    if c not in (200, 204):
        return _not_read("ZPA microtenants", c)
    mts = [m for m in mts if m.get("enabled") is not False and str(m.get("enabled")).lower() != "false"
           and str(m.get("name") or "").strip().lower() != "default"]
    if not mts:
        return R(R.INFO, "No ZPA microtenant is in use; Not licensed or not in use. N/A.")
    without, read = [], 0
    for m in mts[:_MAX_MICROTENANTS]:
        mid = str(m.get("id") or "")
        if not mid:
            continue
        # Per-microtenant read (query parameter microtenantId, as the SDK passes it).
        # Rows are kept only when they name this microtenant, whether or not the
        # API filtered them itself (assumed: each admin row carries microtenantId).
        rows, rc = _zpa_rows(cl, "/zpa/administrators", {"microtenantId": mid})
        if rc not in (200, 204):
            continue
        read += 1
        own = [a for a in _enabled_admins(rows) if str(a.get("microtenantId") or "") == mid]
        if not own:
            without.append(str(m.get("name") or mid)[:60])
    if not read:
        return R(R.INFO, f"{len(mts)} ZPA microtenant(s), but their administrators could not be read.")
    more = f" (the first {_MAX_MICROTENANTS} of {len(mts)} were read)" if len(mts) > _MAX_MICROTENANTS else ""
    if without:
        return R(R.WARN, f"{len(without)} of {read} ZPA microtenant(s) have no administrator of their own{more}: {', '.join(without[:10])}. Best Practice: Give each microtenant its own scoped admins so a business unit's team does not need parent-tenant rights.")
    return R(R.PASS, f"All {read} ZPA microtenant(s) read have their own administrators{more}.")


def rbac_zpa_provisioning_keys(cl):
    """ZPA provisioning keys are capped and not left unused"""
    keys, codes = [], []
    for ep in ("/zpa/associationType/CONNECTOR_GRP/provisioningKey", "/zpa/associationType/SERVICE_EDGE_GRP/provisioningKey"):
        rows, c = _zpa_rows(cl, ep)
        codes.append(c)
        keys.extend(rows)
    if not any(c in (200, 204) for c in codes):
        return _not_read("ZPA provisioning keys", codes[0])
    live = [k for k in keys if k.get("enabled") is not False and str(k.get("enabled")).lower() != "false"]
    if not live:
        return R(R.PASS, "No enabled ZPA provisioning key: no App Connector or Service Edge can enrol with an old key.")
    now = _now()
    uncapped, unused = [], []
    for k in live:
        try:
            mx, used = int(k.get("maxUsage") or 0), int(k.get("usageCount") or 0)
        except (TypeError, ValueError):
            continue
        if mx > 50 and mx > used + 20:
            uncapped.append(k)
        made = _epoch(k.get("creationTime"))
        if used == 0 and made and now - made > 30 * _DAY:
            unused.append(k)
    issues = []
    if uncapped:
        issues.append(f"{len(uncapped)} allow more than 50 enrolments and have at least 20 left")
    if unused:
        issues.append(f"{len(unused)} were never used in the 30+ days since they were made")
    if issues:
        return R(R.WARN, f"{len(live)} enabled ZPA provisioning key(s): " + " and ".join(issues) + ". Best Practice: Set the maximum usage to the number of connectors you will enrol, and disable or delete a key once enrolment is done; a leaked key enrols a rogue connector.")
    return R(R.PASS, f"{len(live)} enabled ZPA provisioning key(s), each capped near the enrolments it needs and in use.")


def rbac_zpa_pra_credentials(cl):
    """PRA credentials are pooled and rotated"""
    creds, c = _zpa_rows(cl, "/zpa/credential")
    if c not in (200, 204):
        return _not_read("Privileged Remote Access credentials", c)
    if not creds:
        return R(R.INFO, "No Privileged Remote Access credential is stored; Not licensed or not in use. N/A.")
    now = _now()
    # lastCredentialResetTime (models/pra_credential.py), assumed epoch seconds.
    stale = [x for x in creds if (_epoch(x.get("lastCredentialResetTime")) or _epoch(x.get("creationTime")) or now) < now - 90 * _DAY]
    pools, pc = _zpa_rows(cl, "/zpa/credential-pool")
    pooled = sum(1 for p in pools if p.get("credentials") or str(p.get("credentialMappingCount") or "0") not in ("0", ""))
    issues = []
    if stale:
        issues.append(f"{len(stale)} not reset in more than 90 days")
    if pc in (200, 204) and not pooled:
        issues.append("none is in a credential pool")
    if issues:
        return R(R.WARN, f"{len(creds)} Privileged Remote Access credential(s): " + " and ".join(issues) + ". Best Practice: Rotate stored privileged credentials at least every 90 days and group them into credential pools, so each console uses a pool instead of one shared password.")
    return R(R.PASS, f"{len(creds)} Privileged Remote Access credential(s), all reset within 90 days" + (f", {pooled} pool(s) in use." if pc in (200, 204) else "."))


def rbac_zpa_pra_standing_approvals(cl):
    """No standing Privileged Remote Access approvals"""
    rows, c = _zpa_rows(cl, "/zpa/approval")
    if c not in (200, 204):
        return _not_read("Privileged Remote Access approvals", c)
    if not rows:
        return R(R.INFO, "No Privileged Remote Access approval is set; Not licensed or not in use. N/A.")
    now = _now()
    standing, expired = 0, 0
    for a in rows:
        # status: INVALID, ACTIVE, FUTURE, EXPIRED; startTime / endTime in UNIX seconds (zpa/pra_approval.py).
        status = str(a.get("status") or "").upper()
        start, end = _epoch(a.get("startTime")), _epoch(a.get("endTime"))
        if status == "EXPIRED" or (end and end < now):
            expired += 1
            continue
        if end and (end - (start or now)) > 30 * _DAY:
            standing += 1
    if standing:
        return R(R.WARN, f"{standing} of {len(rows)} Privileged Remote Access approval(s) stay open for more than 30 days. Best Practice: Approve privileged access just in time, for hours or days, so standing access to servers does not outlive the task."
                 + (f" {expired} expired approval(s) can also be removed." if expired else ""))
    return R(R.PASS, f"{len(rows)} Privileged Remote Access approval(s), none open for more than 30 days" + (f"; {expired} expired one(s) can be removed." if expired else "."))


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
    ("RBAC.13", "RBAC — ZPA",       "ZPA admin count (continuity, not over-provisioned)", rbac_zpa_admin_count),
    ("RBAC.14", "RBAC — ZPA",       "ZPA local admins use a second factor",         rbac_zpa_admin_mfa),
    ("RBAC.15", "RBAC — ZPA",       "ZPA admin sign-in is SSO only",                rbac_zpa_sso_only),
    ("RBAC.16", "RBAC — ZPA",       "Few ZPA admins hold full access",              rbac_zpa_super_admin_share),
    ("RBAC.17", "RBAC — ZPA",       "ZPA read-only and scoped roles exist",         rbac_zpa_least_privilege_roles),
    ("RBAC.18", "RBAC — ZPA",       "ZPA API keys least privilege, short tokens",   rbac_zpa_api_keys),
    ("RBAC.19", "RBAC — ZPA",       "ZPA break-glass account set up and dormant",   rbac_zpa_emergency_access),
    ("RBAC.20", "RBAC — ZPA",       "Each ZPA microtenant has its own admins",      rbac_zpa_microtenant_admins),
    ("RBAC.21", "RBAC — ZPA",       "ZPA provisioning keys capped and in use",      rbac_zpa_provisioning_keys),
    ("RBAC.22", "RBAC — ZPA",       "PRA credentials pooled and rotated",           rbac_zpa_pra_credentials),
    ("RBAC.23", "RBAC — ZPA",       "No standing PRA approvals",                    rbac_zpa_pra_standing_approvals),
]
RBAC_REG = guard_registry(RBAC_REG)   # a refused read (HTTP 401/403) is "Not permitted", never judged
