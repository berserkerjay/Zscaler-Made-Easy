"""The team server's own routes (team_server.py): sign-in with a local
account, the administrator's account and access management, and the SCIM
2.0 provisioning endpoint. Registered on the app by dlp_api_server; every
one answers 404 unless team mode is on, and every one has its access rule
in team_routes.py (enforced by team_server.TeamAccessMiddleware).
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

import audit
import safe_files
import security
import sso
import team_server as team

SCIM_BASE = "/api/scim/v2"
SCIM_MEDIA = "application/scim+json"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def _on() -> None:
    if not team.enabled():
        raise HTTPException(status_code=404, detail="This server is not a team server (ZSCALER_TEAM_MODE is off).")


async def _body(request: Request) -> Dict[str, Any]:
    try:
        raw = await request.body()
        data = safe_files.strict_json_loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(status_code=400, detail="Send a JSON object.")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Send a JSON object.")
    return data


def _fail(e: team.TeamError):
    raise HTTPException(status_code=e.status, detail=str(e))


def _me() -> Dict[str, Any]:
    u = team.current_user()
    if not u:
        raise HTTPException(status_code=401, detail="Sign in required.")
    return u


def _page(name: str) -> HTMLResponse:
    path = os.path.join(STATIC_DIR, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})
    except OSError:
        raise HTTPException(status_code=404, detail="page missing")


def status_fields(request: Request) -> Dict[str, Any]:
    """What /api/auth/status says on a team server: who is signed in, their
    role and whether they may change anything; the sign-in page's address."""
    session = security.sso_session(request)
    u = team.session_user(session)
    return {"required": True, "unlocked": u is not None, "token_file": None, "sso": True, "team": True,
            "user": u.get("username") if u else None, "role": u.get("role") if u else None,
            "may_write": bool(u and "apply" in team.ROLE_ACTIONS.get(str(u.get("role")), ())),
            "is_admin": bool(u and u.get("role") == "admin"),
            "sso_login_url": "/login", "logout_url": "/api/auth/logout",
            "oidc": sso.sso_enabled(), "oidc_login_url": "/api/auth/sso/login" if sso.sso_enabled() else None}


def register(app: FastAPI) -> None:

    @app.get("/login")
    async def team_login_page():
        """The team server's sign-in page (static/login.html). Off team mode the
        page says there is no account to sign in to (its calls answer 404)."""
        return _page("login.html")

    @app.get("/report/team")
    async def team_admin_page():
        """The team server's administration page (static/report_team.html):
        accounts, roles, per-tenant access, SCIM and HTTPS. Off team mode it
        says how to turn team mode on (every call it makes answers 404)."""
        return _page("report_team.html")

    @app.post("/api/auth/team/login")
    async def team_login(request: Request):
        """Sign in with a local account: user name and password. Rate
        limited per address, locked after too many wrong passwords (enforced:
        a locked account is refused even with the right password), and a
        new session id every time (the browser's earlier one ends). Audited,
        success and failure alike; the password is never written anywhere."""
        _on()
        data = await _body(request)
        client = request.client.host if request.client else "?"
        name = str(data.get("username") or "")[:200]
        try:
            u = team.authenticate(name, data.get("password"), client)
        except team.LoginRefused as e:
            audit.record("team_login_failed", actor=security.NOT_SIGNED_IN, attempted_user=team.normalize_username(name)[:100],
                         reason=e.reason, client=client)
            headers = {"Retry-After": "60"} if e.status in (423, 429) else None
            return JSONResponse({"detail": str(e)}, status_code=e.status, headers=headers)
        sid = team.start_session(u, via="password", previous_sid=request.cookies.get(security.SSO_SESSION_COOKIE))
        resp = JSONResponse({"ok": True, "user": u.get("username"), "role": u.get("role")})
        security.set_session_cookie(resp, request, sid)
        audit.record("team_login", actor=u.get("username"), via="password", role=u.get("role"), client=client)
        return resp

    @app.get("/api/team/me")
    async def team_me():
        """Who is signed in, their role and what they may do on which tenant profile."""
        _on()
        u = _me()
        import tenant_profiles
        rows = []
        for p in tenant_profiles.list_profiles():
            acts = sorted(team.actions_on(u, p.get("id"), team.current_token_groups()), key=team.ACTIONS.index)
            if acts:
                rows.append({"profile": p.get("id"), "name": p.get("name") or p.get("org_name") or p.get("id"), "actions": acts})
        return {"user": team.public_user(u), "role_actions": list(team.ROLE_ACTIONS.get(str(u.get("role")), ())),
                "profiles": rows, "idle_minutes": team.idle_seconds() // 60, "session_hours": round(team.session_seconds() / 3600, 2)}

    @app.post("/api/team/me/password")
    async def team_me_password(request: Request):
        """Change your own password: the current one, then the new one. Every
        session of yours ends (sign in again)."""
        _on()
        u = _me()
        data = await _body(request)
        if not u.get("password") or not team.verify_password(str(data.get("current") or ""), u.get("password")):
            audit.record("team_password_change_refused", reason="the current password was wrong")
            raise HTTPException(status_code=403, detail="The current password is not right.")
        try:
            team.set_password(u["id"], data.get("new"), by=u.get("username"))
        except team.TeamError as e:
            _fail(e)
        resp = JSONResponse({"ok": True, "signed_out": True})
        security.clear_session_cookie(resp, request)
        return resp

    @app.get("/api/team/overview")
    async def team_overview():
        """Everything the administration page shows: accounts (never a password
        hash), groups, grants, tenant profiles, the SCIM token's state (never
        the token) and HTTPS (its fingerprint)."""
        _on()
        import server_tls
        import tenant_profiles
        return {"users": team.list_users(), "groups": team.list_groups(), "grants": team.list_grants(),
                "profiles": [{"id": p.get("id"), "name": p.get("name") or p.get("org_name") or p.get("id")} for p in tenant_profiles.list_profiles()],
                "roles": [{"id": r, "label": team.ROLE_LABELS[r], "actions": list(team.ROLE_ACTIONS[r])} for r in team.ROLES],
                "actions": list(team.ACTIONS), "scim": dict(team.scim_status(), base_path=SCIM_BASE), "tls": server_tls.status(),
                "settings": {"idle_minutes": team.idle_seconds() // 60, "session_hours": round(team.session_seconds() / 3600, 2),
                             "lockout_attempts": team.lockout_attempts(), "lockout_minutes": team.lockout_seconds() // 60,
                             "min_password": team.MIN_PASSWORD, "oidc": sso.sso_enabled()}}

    @app.post("/api/team/users")
    async def team_user_create(request: Request):
        """Create an account: user name, role, and a password (or none, for
        someone who signs in through the identity provider only)."""
        _on()
        data = await _body(request)
        try:
            u = team.create_user(username=data.get("username"), role=data.get("role") or "viewer", password=data.get("password") or None,
                                 display_name=data.get("display_name") or "", email=data.get("email") or "", by=security.current_actor())
        except team.TeamError as e:
            _fail(e)
        return {"user": team.public_user(u)}

    @app.post("/api/team/users/{user_id}")
    async def team_user_update(user_id: str, request: Request):
        """Change an account's role, display name, email, or turn it off or on.
        A role change or turning it off ends its sessions at once."""
        _on()
        data = await _body(request)
        me = _me()
        if user_id == me.get("id") and (data.get("active") is False or (data.get("role") not in (None, "admin"))):
            raise HTTPException(status_code=409, detail="You cannot turn off or demote your own account; ask another administrator.")
        try:
            u = team.update_user(user_id, by=me.get("username"), role=data.get("role"), active=data.get("active"),
                                 display_name=data.get("display_name"), email=data.get("email"))
        except team.TeamError as e:
            _fail(e)
        return {"user": team.public_user(u)}

    @app.delete("/api/team/users/{user_id}")
    async def team_user_delete(user_id: str):
        """Delete an account and its grants; its sessions end."""
        _on()
        me = _me()
        if user_id == me.get("id"):
            raise HTTPException(status_code=409, detail="You cannot delete your own account.")
        try:
            team.delete_user(user_id, by=me.get("username"))
        except team.TeamError as e:
            _fail(e)
        return {"deleted": user_id}

    @app.post("/api/team/users/{user_id}/password")
    async def team_user_password(user_id: str, request: Request):
        """Set an account's password (an administrator's reset). Its sessions end."""
        _on()
        data = await _body(request)
        try:
            team.set_password(user_id, data.get("password"), by=security.current_actor())
        except team.TeamError as e:
            _fail(e)
        return {"ok": True}

    @app.post("/api/team/users/{user_id}/unlock")
    async def team_user_unlock(user_id: str):
        """Unlock an account locked after too many wrong passwords."""
        _on()
        try:
            team.unlock_user(user_id, by=security.current_actor())
        except team.TeamError as e:
            _fail(e)
        return {"ok": True}

    @app.post("/api/team/grants")
    async def team_grant(request: Request):
        """Give a user or group exactly these actions (read, plan, apply,
        approve) on one tenant profile, or "*" for every profile. An empty
        list takes the grant away."""
        _on()
        data = await _body(request)
        try:
            rec = team.set_grant(data.get("principal"), data.get("profile"), data.get("actions"), by=security.current_actor())
        except team.TeamError as e:
            _fail(e)
        return {"grant": rec}

    @app.post("/api/team/scim-token")
    async def team_scim_token():
        """Make a new SCIM bearer token. It is shown this once and kept only as
        its SHA-256; the one before stops working."""
        _on()
        token = team.scim_new_token(by=security.current_actor())
        return JSONResponse({"token": token, "shown_once": True, "base_path": SCIM_BASE},
                            headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @app.delete("/api/team/scim-token")
    async def team_scim_revoke():
        """Revoke the SCIM bearer token: provisioning stops until a new one is made."""
        _on()
        team.scim_revoke(by=security.current_actor())
        return {"ok": True}

    # ── SCIM 2.0 (RFC 7643, RFC 7644) ──
    def _scim(fn, *args, status: int = 200):
        _on()
        try:
            out = fn(*args)
        except team.ScimError as e:
            return JSONResponse(e.body(), status_code=e.status, media_type=SCIM_MEDIA)
        if out is None:
            return Response(status_code=204)
        return JSONResponse(out, status_code=status, media_type=SCIM_MEDIA)

    async def _scim_body(request: Request) -> Any:
        try:
            raw = await request.body()
            return safe_files.strict_json_loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None

    def _bad_json():
        return JSONResponse(team.ScimError(400, "The body is not valid JSON.", "invalidSyntax").body(), status_code=400, media_type=SCIM_MEDIA)

    @app.get(SCIM_BASE + "/ServiceProviderConfig")
    async def scim_spc():
        """SCIM: what this provider supports."""
        return _scim(team.scim_service_provider_config, SCIM_BASE)

    @app.get(SCIM_BASE + "/ResourceTypes")
    async def scim_types():
        """SCIM: the resource types (User, Group)."""
        return _scim(team.scim_resource_types, SCIM_BASE)

    @app.get(SCIM_BASE + "/Schemas")
    async def scim_schemas():
        """SCIM: the schemas in use (the core User and Group)."""
        return _scim(lambda: {"schemas": [team.SCIM_LIST], "totalResults": 2, "startIndex": 1, "itemsPerPage": 2,
                              "Resources": [{"id": team.SCIM_USER, "name": "User"}, {"id": team.SCIM_GROUP, "name": "Group"}]})

    @app.get(SCIM_BASE + "/Users")
    async def scim_users(filter: str = "", startIndex: int = 1, count: Optional[int] = None):  # noqa: A002 - the SCIM parameter name
        """SCIM: list users (filter: userName, externalId or emails.value eq "...")."""
        return _scim(team.scim_list_users, SCIM_BASE, filter, startIndex, count)

    @app.post(SCIM_BASE + "/Users")
    async def scim_user_create(request: Request):
        """SCIM: provision a user (a viewer, operator or approver; never an administrator). No password: they sign in through SSO."""
        body = await _scim_body(request)
        return _bad_json() if body is None else _scim(team.scim_create_user, body, SCIM_BASE, status=201)

    @app.get(SCIM_BASE + "/Users/{scim_id}")
    async def scim_user_get(scim_id: str):
        """SCIM: one user."""
        return _scim(team.scim_get_user, scim_id, SCIM_BASE)

    @app.put(SCIM_BASE + "/Users/{scim_id}")
    async def scim_user_put(scim_id: str, request: Request):
        """SCIM: replace a user (active false turns the account off and ends its sessions)."""
        body = await _scim_body(request)
        return _bad_json() if body is None else _scim(team.scim_replace_user, scim_id, body, SCIM_BASE)

    @app.patch(SCIM_BASE + "/Users/{scim_id}")
    async def scim_user_patch(scim_id: str, request: Request):
        """SCIM: change a user (add or replace active, displayName, userName, emails, externalId, roles)."""
        body = await _scim_body(request)
        return _bad_json() if body is None else _scim(team.scim_patch_user, scim_id, body, SCIM_BASE)

    @app.delete(SCIM_BASE + "/Users/{scim_id}")
    async def scim_user_delete(scim_id: str):
        """SCIM: deprovision a user (an administrator is removed on the server itself)."""
        return _scim(team.scim_delete_user, scim_id)

    @app.get(SCIM_BASE + "/Groups")
    async def scim_groups(filter: str = "", startIndex: int = 1, count: Optional[int] = None):  # noqa: A002
        """SCIM: list groups (filter: displayName or externalId eq "...")."""
        return _scim(team.scim_list_groups, SCIM_BASE, filter, startIndex, count)

    @app.post(SCIM_BASE + "/Groups")
    async def scim_group_create(request: Request):
        """SCIM: provision a group (grants to it are given on the Team server page)."""
        body = await _scim_body(request)
        return _bad_json() if body is None else _scim(team.scim_create_group, body, SCIM_BASE, status=201)

    @app.get(SCIM_BASE + "/Groups/{scim_id}")
    async def scim_group_get(scim_id: str):
        """SCIM: one group with its members."""
        return _scim(team.scim_get_group, scim_id, SCIM_BASE)

    @app.put(SCIM_BASE + "/Groups/{scim_id}")
    async def scim_group_put(scim_id: str, request: Request):
        """SCIM: replace a group (name and members)."""
        body = await _scim_body(request)
        return _bad_json() if body is None else _scim(team.scim_replace_group, scim_id, body, SCIM_BASE)

    @app.patch(SCIM_BASE + "/Groups/{scim_id}")
    async def scim_group_patch(scim_id: str, request: Request):
        """SCIM: add, remove or replace members, or rename a group."""
        body = await _scim_body(request)
        return _bad_json() if body is None else _scim(team.scim_patch_group, scim_id, body, SCIM_BASE)

    @app.delete(SCIM_BASE + "/Groups/{scim_id}")
    async def scim_group_delete(scim_id: str):
        """SCIM: remove a group and its grants."""
        return _scim(team.scim_delete_group, scim_id)


def register_resolvers() -> None:
    """Which tenant profiles a stored record named in a request belongs to,
    for the access check (team_server.TeamAccessMiddleware): change
    requests, deployments, bulk-change operations, saved snapshots and
    proposal queues. Unknown record: None (refused as not found)."""

    def change_request(rid: str, _params) -> Optional[set]:
        import change_queue
        rec = change_queue.get(rid)
        return team.record_profiles(rec) if rec else None

    def deployment(dep_id: str, _params) -> Optional[set]:
        import deployments
        rec = deployments.get(dep_id)
        return team.record_profiles(rec) if rec else None

    def operation(op_id: str, _params) -> Optional[set]:
        import deployments
        rec = deployments.get_operation(op_id)
        return team.record_profiles(rec) if rec else None

    def snapshot(snapshot_id: str, _params) -> Optional[set]:
        import tenant_profiles
        for row in tenant_profiles.list_snapshots(None):
            if row.get("id") == snapshot_id:
                return {row["profile_id"]} if row.get("profile_id") else None
        return None

    def tenant_key(tenant: str, _params) -> Optional[set]:
        import proposals
        return team.profiles_for_keys([proposals.tenant_key(tenant)]) or None

    team.register_resolver("rid", change_request)
    team.register_resolver("dep_id", deployment)
    team.register_resolver("op_id", operation)
    team.register_resolver("snapshot_id", snapshot)
    team.register_resolver("tenant", tenant_key)
