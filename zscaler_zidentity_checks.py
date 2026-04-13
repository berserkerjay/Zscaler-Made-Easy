#!/usr/bin/env python3
"""
Zscaler Identity (ZIdentity) Assessment Checks
================================================
Checks for the ZIdentity API surface used by the ZIdentity admin
portal at https://admin.zidentity.net/. The ZIdentity service
manages users, groups, resource servers, and user entitlements for
OneAPI authentication.

Modules (from zscaler-sdk-python/zscaler/zid/):
  - users                — directory of user accounts
  - groups               — logical groupings for role binding
  - resource_servers     — the ZIA/ZPA/ZDX/ZCC resources OneAPI can authenticate against
  - user_entitlement     — per-user entitlements (role assignments)

All checks are read-only.
"""

from dlp_assessment_full_auto import R, _ls, _g


def zid_users(cl):
    """ZIdentity user directory"""
    d, c = cl.get("/zid/users")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZIdentity users endpoint not accessible — API role may not include ZIdentity scope.")
    if not items:
        return R(R.WARN, "No ZIdentity users. If you use federated SSO to IdP (Azure AD / Okta), users should sync here. Empty means the IdP connector isn't running.")
    return R(R.PASS, f"{len(items)} user(s) in ZIdentity directory.")


def zid_groups(cl):
    """ZIdentity groups for role binding"""
    d, c = cl.get("/zid/groups")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZIdentity groups endpoint not accessible.")
    if not items:
        return R(R.WARN, "No ZIdentity groups. Best Practice: Bind roles to groups (not individual users) so role changes follow IdP group membership — no drift, no leftover access when someone leaves a team.")
    return R(R.PASS, f"{len(items)} group(s) defined in ZIdentity.")


def zid_resource_servers(cl):
    """ZIdentity resource servers — which Zscaler services OneAPI can reach"""
    d, c = cl.get("/zid/resourceServers")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Resource servers endpoint not accessible.")
    if not items:
        return R(R.WARN, "No resource servers configured in ZIdentity. OneAPI clients need a resource server mapping to reach ZIA/ZPA/ZDX/ZCC — this should NOT be empty on a working tenant.")
    services = [
        str(r.get("serviceName") or r.get("resourceType") or r.get("name") or "?")
        for r in items
    ]
    return R(R.PASS, f"{len(items)} resource server(s): {', '.join(services[:10])}.")


def zid_user_entitlements(cl):
    """ZIdentity user entitlements (role assignments per user)"""
    d, c = cl.get("/zid/userEntitlement")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "User entitlements endpoint not accessible.")
    if not items:
        return R(R.INFO, "No user entitlements returned. If all your role assignments are group-based (best practice), individual-user entitlements can legitimately be empty.")
    return R(R.WARN, f"{len(items)} individual-user entitlement(s) found. Best Practice: Prefer group-based role assignments — per-user entitlements don't survive offboarding cleanly.")


def zid_admin_coverage(cl):
    """ZIdentity admin role coverage — at least 2 admins for BCP"""
    d, c = cl.get("/zid/users")
    users = _ls(d) if c in (200, 204) else []
    admin_users = [
        u for u in users
        if any("admin" in str(r).lower() for r in (u.get("roles") or u.get("groups") or []))
    ]
    if c in (401, 403) or not users:
        return R(R.INFO, "Cannot enumerate users for admin coverage check.")
    if len(admin_users) < 2:
        return R(R.WARN, f"Only {len(admin_users)} admin-tagged user(s). Best Practice: Maintain at least 2 admins for business continuity — single-admin tenants lock out when that admin leaves or loses MFA.")
    return R(R.PASS, f"{len(admin_users)} admin-tagged user(s) — BCP redundancy in place.")


ZID_REG = [
    ("ZID.1", "ZIdentity — Directory",    "Users",                       zid_users),
    ("ZID.2", "ZIdentity — Directory",    "Groups",                      zid_groups),
    ("ZID.3", "ZIdentity — Authorization","Resource servers",            zid_resource_servers),
    ("ZID.4", "ZIdentity — Authorization","User entitlements",           zid_user_entitlements),
    ("ZID.5", "ZIdentity — Directory",    "Admin redundancy (BCP)",      zid_admin_coverage),
]
