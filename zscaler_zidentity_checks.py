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
  - user_entitlement     — per-user entitlements (role assignments): the
                           admin entitlements of every admin are read for
                           ZID.6 (broad) and ZID.7 (stale)

All checks are read-only. People are counted, never listed.
"""

from zscaler_full_checks import guard_registry
from dlp_assessment_full_auto import R, _ls


def zid_users(cl):
    """ZIdentity user directory"""
    d, c = cl.get("/zid/users")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Authentication Service (formerly ZIdentity) users endpoint not accessible — API role may not include that scope.")
    if not items:
        return R(R.WARN, "No users in Authentication Service (formerly ZIdentity). If you use federated SSO to IdP (Azure AD / Okta), users should sync here. Empty means the IdP connector isn't running.")
    return R(R.PASS, f"{len(items)} user(s) in the Authentication Service (formerly ZIdentity) directory.")


def zid_groups(cl):
    """ZIdentity groups for role binding"""
    d, c = cl.get("/zid/groups")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Authentication Service (formerly ZIdentity) groups endpoint not accessible.")
    if not items:
        return R(R.WARN, "No groups in Authentication Service (formerly ZIdentity). Best Practice: Bind roles to groups (not individual users) so role changes follow IdP group membership — no drift, no leftover access when someone leaves a team.")
    return R(R.PASS, f"{len(items)} group(s) defined in Authentication Service (formerly ZIdentity).")


def zid_resource_servers(cl):
    """ZIdentity resource servers — which Zscaler services OneAPI can reach"""
    d, c = cl.get("/zid/resourceServers")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "Resource servers endpoint not accessible.")
    if not items:
        return R(R.WARN, "No resource servers configured in Authentication Service (formerly ZIdentity). OneAPI clients need a resource server mapping to reach ZIA/ZPA/ZDX/ZCC — this should NOT be empty on a working tenant.")
    services = [
        str(r.get("serviceName") or r.get("resourceType") or r.get("name") or "?")
        for r in items
    ]
    return R(R.PASS, f"{len(items)} resource server(s): {', '.join(services[:10])}.")


def zid_user_entitlements(cl):
    """ZIdentity user entitlements (role assignments per user)"""
    return R(R.INFO, "Authentication Service (formerly ZIdentity) lists entitlements per user (/users/{id}/service-entitlements), not for the whole tenant. "
                     "Best Practice: Prefer group-based role assignments — per-user entitlements don't survive offboarding cleanly. Review them under Administration > Authentication in the Zscaler Admin Console.")


def zid_admin_coverage(cl):
    """ZIdentity admin role coverage — at least 2 admins for BCP"""
    d, c = cl.get("/zid/users")
    users = _ls(d) if c in (200, 204) else []
    # UserRecord carries adminEntitlementEnabled; it has no roles or groups
    # field (zscaler-sdk-python 1.11.0 zid/models/users.py).
    admin_users = [
        u for u in users
        if isinstance(u, dict) and u.get("adminEntitlementEnabled") and str(u.get("status", "")).lower() not in ("false", "disabled", "inactive")
    ]
    if c in (401, 403) or not users:
        return R(R.INFO, "Cannot enumerate users for admin coverage check.")
    if len(admin_users) < 2:
        return R(R.WARN, f"Only {len(admin_users)} active admin user(s) in Authentication Service (formerly ZIdentity). Best Practice: Maintain at least 2 admins for business continuity — single-admin tenants lock out when that admin leaves or loses MFA.")
    return R(R.PASS, f"{len(admin_users)} active admin user(s) — BCP redundancy in place.")


# ═══════════════════════════════════════════════════════════════════════
# Per-admin entitlements (2026-10-31)
# ═══════════════════════════════════════════════════════════════════════
# SDK 1.11.3 (verified): user_entitlement.get_admin_entitlement
#   GET /ziam/admin/api/v1/users/{id}/admin-entitlements  → [{roles[{id,name,displayName}], service{serviceName,…}, scope{…}}]
# UserRecord (zid/models/users.py) has status and adminEntitlementEnabled but
# no last sign-in time; the time fields read below are assumed and used only
# when the tenant sends them. People are counted, never listed.

MAX_ADMINS = 100
STALE_DAYS = 90
BROAD_SERVICES = 3        # entitled on this many services or more is broad
_BROAD_ROLE = ("super admin", "superadmin", "full access", "full admin", "administrator", "owner", "root")
_LAST_SIGN_IN = ("lastLoginTime", "lastLogin", "lastSignInTime", "last_login_time")   # assumed field names


def _active(u):
    return str(u.get("status", True)).strip().lower() not in ("false", "0", "disabled", "inactive", "suspended", "deleted")


def _admins(cl):
    d, c = cl.get("/zid/users")
    if c not in (200, 204):
        return None, c
    users = [u for u in _ls(d) if isinstance(u, dict) and u.get("adminEntitlementEnabled") is True]
    return users[:MAX_ADMINS], c


def _uid(u):
    v = str(u.get("id") or "")
    return v if v and len(v) <= 64 and all(ch.isalnum() or ch in "-_." for ch in v) else ""


def _entitlements(cl, uid):
    d, c = cl.get(f"/zid/users/{uid}/admin-entitlements")
    if c not in (200, 204):
        return None
    if isinstance(d, dict):
        for k in ("entitlements", "records", "list"):
            if isinstance(d.get(k), list):
                d = d[k]
                break
    return [e for e in (d if isinstance(d, list) else []) if isinstance(e, dict)][:50]


def broad_reason(ents):
    """Why one admin's entitlements are broad, or ''."""
    services = set()
    for e in ents:
        svc = e.get("service") if isinstance(e.get("service"), dict) else {}
        name = str(svc.get("serviceName") or svc.get("service_name") or svc.get("id") or "")[:40]
        if name:
            services.add(name.upper())
        for r in (e.get("roles") if isinstance(e.get("roles"), list) else [])[:20]:
            rn = str((r or {}).get("name") or (r or {}).get("displayName") or "").strip().lower() if isinstance(r, dict) else ""
            if any(w == rn or w in rn for w in _BROAD_ROLE):
                return "full-access role"
    if len(services) >= BROAD_SERVICES:
        return "many services"
    return ""


def _when(v):
    import time
    if v in (None, "", 0):
        return None
    try:
        f = float(v)
        return f / 1000.0 if f > 1e11 else f
    except (TypeError, ValueError):
        pass
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")[:32]).timestamp()
    except ValueError:
        return None


def zid_admin_broad_entitlements(cl):
    """Admins with broad entitlements (a full-access role, or many services)"""
    admins, c = _admins(cl)
    if admins is None:
        if c == 404:
            return R(R.INFO, "Not applicable: the Authentication Service (formerly ZIdentity) user list is not available on this tenant.")
        return R(R.INFO, "Cannot enumerate Authentication Service (formerly ZIdentity) users, so admin entitlements were not read.")
    if not admins:
        return R(R.INFO, "No user holds an admin entitlement in the Authentication Service (formerly ZIdentity).")
    broad = {"full-access role": 0, "many services": 0}
    read = unread = 0
    for u in admins:
        uid = _uid(u)
        ents = _entitlements(cl, uid) if uid else None
        if ents is None:
            unread += 1
            continue
        read += 1
        why = broad_reason(ents)
        if why:
            broad[why] += 1
    gap = f" The entitlements of {unread} admin(s) could not be read." if unread else ""
    n = broad["full-access role"] + broad["many services"]
    if not read:
        return R(R.INFO, "The admin entitlements could not be read (the API role may not include it)." + gap)
    if n and n > max(2, read // 3):
        return R(R.WARN, f"{n} of {read} admin(s) have broad entitlements ({broad['full-access role']} with a full-access role, "
                         f"{broad['many services']} entitled on {BROAD_SERVICES} or more services).{gap} "
                         "Why it matters: every full-access admin can change or switch off security on every product; one stolen session is a tenant-wide incident. "
                         "Best Practice: keep two or three break-glass Super Admins, give everyone else a role scoped to the one product and task they do, "
                         "and review the list every quarter (Administration > Authentication > Admin entitlements).",
                 {"broad": n, "read": read})
    return R(R.PASS, f"{n} of {read} admin(s) have broad entitlements, within the two or three break-glass admins a tenant needs.{gap}",
             {"broad": n, "read": read})


def zid_admin_stale(cl):
    """Stale admins: a disabled account, or no sign-in for 90 days, that still holds an admin entitlement"""
    import time
    admins, c = _admins(cl)
    if admins is None:
        if c == 404:
            return R(R.INFO, "Not applicable: the Authentication Service (formerly ZIdentity) user list is not available on this tenant.")
        return R(R.INFO, "Cannot enumerate Authentication Service (formerly ZIdentity) users for the stale-admin check.")
    if not admins:
        return R(R.INFO, "No user holds an admin entitlement in the Authentication Service (formerly ZIdentity).")
    now = time.time()
    disabled = sum(1 for u in admins if not _active(u))
    idle = 0
    seen = 0
    for u in admins:
        if not _active(u):
            continue
        t = next((_when(u.get(k)) for k in _LAST_SIGN_IN if u.get(k) not in (None, "")), None)
        if t is not None:
            seen += 1
            if now - t > STALE_DAYS * 86400:
                idle += 1
    note = "" if seen else " The directory does not say when admins last signed in, so only disabled accounts are counted."
    if disabled or idle:
        return R(R.FAIL, f"{disabled + idle} stale admin(s) of {len(admins)}: {disabled} disabled account(s) and {idle} not signed in for "
                         f"{STALE_DAYS} days still hold an admin entitlement.{note} "
                         "Why it matters: an admin entitlement left on an unused account is a way in nobody watches; it is how former staff and stolen accounts keep access. "
                         "Best Practice: remove the admin entitlement when an account is disabled or unused for 90 days, and make it part of the leaver process.",
                 {"stale": disabled + idle, "disabled": disabled, "idle": idle, "admins": len(admins)})
    return R(R.PASS, f"No stale admin: every one of the {len(admins)} admin(s) is active" + (f" and signed in within {STALE_DAYS} days." if seen else ".") + note)


ZID_REG = [
    ("ZID.1", "ZIdentity — Directory",    "Users",                       zid_users),
    ("ZID.2", "ZIdentity — Directory",    "Groups",                      zid_groups),
    ("ZID.3", "ZIdentity — Authorization","Resource servers",            zid_resource_servers),
    ("ZID.4", "ZIdentity — Authorization","User entitlements",           zid_user_entitlements),
    ("ZID.5", "ZIdentity — Directory",    "Admin redundancy (BCP)",      zid_admin_coverage),
    ("ZID.6", "ZIdentity — Authorization","Admins with broad entitlements", zid_admin_broad_entitlements),
    ("ZID.7", "ZIdentity — Authorization","Stale admins still entitled",  zid_admin_stale),
]
ZID_REG = guard_registry(ZID_REG)   # a refused read (HTTP 401/403) is "Not permitted", never judged
