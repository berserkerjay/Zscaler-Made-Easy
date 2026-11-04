"""The team server's own routes (team_server.py): sign-in with a local
account, the administrator's account and access management, and the SCIM
2.0 provisioning endpoint. Registered on the app by dlp_api_server; every
one answers 404 unless team mode is on, and every one has its access rule
in team_routes.py (enforced by team_server.TeamAccessMiddleware).
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

import audit
import safe_files
import security
import sso
import sso_saml
import store_crypto
import team_passkeys
import team_server as team

SCIM_BASE = "/api/scim/v2"
SCIM_MEDIA = "application/scim+json"
RECENT_SIGN_IN_SECONDS = 300   # adding a passkey to an account with no password needs a sign-in this recent
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


async def _saml_form(request: Request) -> Optional[Dict[str, list]]:
    """The SAML assertion consumer service's body: an HTML form post
    (application/x-www-form-urlencoded, the HTTP-POST binding), not JSON.
    Size-capped and parsed strictly as ASCII, at most ten fields. None:
    too large; ValueError: not a URL-encoded form."""
    from urllib.parse import parse_qs
    raw = await request.body()
    if len(raw) > sso_saml.MAX_RESPONSE_B64 + 8192:
        return None
    try:
        return parse_qs(raw.decode("ascii"), keep_blank_values=True, strict_parsing=False, max_num_fields=10)
    except UnicodeDecodeError:
        raise ValueError("not ASCII") from None


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
    return {**session_clock(session if u else None), "required": True, "unlocked": u is not None, "token_file": None, "sso": True, "team": True,
            "user": u.get("username") if u else None, "role": u.get("role") if u else None,
            "may_write": bool(u and "apply" in team.ROLE_ACTIONS.get(str(u.get("role")), ())),
            "is_admin": bool(u and u.get("role") == "admin"),
            "password_change_required": team.must_change_password(u),
            "sso_login_url": "/login", "logout_url": "/api/auth/logout",
            "oidc": sso.sso_enabled(), "oidc_login_url": "/api/auth/sso/login" if sso.sso_enabled() else None,
            "saml": sso_saml.enabled(), "saml_login_url": sso_saml.LOGIN_PATH if sso_saml.enabled() else None,
            "passkeys": team_passkeys.enabled()}


def session_clock(session: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """For the idle-timeout warning (ui_auth.js): how long this session may
    sit unused, and how long until it ends whatever happens."""
    if not session:
        return {}
    import time as _t
    idle = session.get("idle") or sso.idle_seconds()
    return {"idle_seconds": int(idle), "expires_in": max(0, int(float(session.get("expires") or 0) - _t.time()))}


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
        step = team.second_factor_needed(u)
        if step:
            # The password was right, but no session yet: the account's
            # passkey answers next (or, when passkeys are required, one is added).
            try:
                nxt = team_passkeys.second_factor_options(u) if step == "passkey" else team_passkeys.enrollment_options(u)
            except team_passkeys.PasskeyError:
                if step == "passkey":
                    # Fail closed: an account with a passkey never falls back to its password alone.
                    audit.record("team_login_failed", actor=security.NOT_SIGNED_IN, attempted_user=u.get("username"),
                                 reason="the account has a passkey but passkeys are not set up", client=client)
                    return JSONResponse({"detail": "This account has a passkey, but passkeys are not set up on this server "
                                                   "(ZSCALER_TEAM_PASSKEY_ORIGIN), so it cannot sign in with a password alone. "
                                                   "An administrator can set that again, or run python team_server.py "
                                                   "remove-passkeys <user name> on the server (a lost device)."}, status_code=503)
                audit.record("team_login_failed", actor=security.NOT_SIGNED_IN, attempted_user=u.get("username"),
                             reason="a passkey is required but passkeys are not set up", client=client)
                return JSONResponse({"detail": "This server asks for a passkey after the password, but passkeys are not set up on it "
                                               "(ZSCALER_TEAM_PASSKEY_ORIGIN). An administrator can set that again, or run "
                                               "python team_server.py require-passkey off on the server."}, status_code=503)
            audit.record("team_login_password_ok", actor=u.get("username"), next=step, client=client)
            return JSONResponse({"ok": False, "next": "passkey" if step == "passkey" else "enroll_passkey", "user": u.get("username"),
                                 "ceremony": nxt["ceremony"], "options": nxt["options"]}, headers={"Cache-Control": "no-store"})
        sid = team.start_session(u, via="password", previous_sid=request.cookies.get(security.SSO_SESSION_COOKIE))
        must = team.must_change_password(u)
        resp = JSONResponse({"ok": True, "user": u.get("username"), "role": u.get("role"), "must_change_password": must})
        security.set_session_cookie(resp, request, sid)
        audit.record("team_login", actor=u.get("username"), via="password", role=u.get("role"), client=client,
                     **({"must_change_password": True} if must else {}))
        return resp

    @app.post("/api/auth/team/passkey/enroll")
    async def team_passkey_enroll(request: Request):
        """Finish a password sign-in on a server that requires passkeys, for
        an account that has none yet: the enrollment ceremony the password
        step returned, the browser's new passkey and a name for it. The
        passkey is verified and stored, then the account gets a fresh session.
        Rate limited, counted towards the lockout when it fails, audited."""
        _on()
        data = await _body(request)
        client = request.client.host if request.client else "?"
        try:
            u = team_passkeys.finish_enrollment(data.get("ceremony"), data.get("credential"), data.get("name"), client)
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)
        except team.LoginRefused as e:
            audit.record("team_login_failed", actor=security.NOT_SIGNED_IN, via="passkey enrollment", reason=e.reason, client=client)
            headers = {"Retry-After": "60"} if e.status in (423, 429) else None
            return JSONResponse({"detail": str(e)}, status_code=e.status, headers=headers)
        sid = team.start_session(u, via="password+passkey", previous_sid=request.cookies.get(security.SSO_SESSION_COOKIE))
        resp = JSONResponse({"ok": True, "user": u.get("username"), "role": u.get("role")})
        security.set_session_cookie(resp, request, sid)
        audit.record("team_login", actor=u.get("username"), via="password+passkey", enrolled=True, role=u.get("role"), client=client)
        return resp

    # ── SAML 2.0 sign-in (sso_saml.py; team servers only) ───────────────
    def _saml_on() -> None:
        _on()
        if not sso_saml.enabled():
            raise HTTPException(status_code=404, detail="SAML sign-in is not turned on on this server.")

    def _saml_refused(request: Request, reason: str, status: int = 401) -> HTMLResponse:
        import html as _html
        client = request.client.host if request.client else "?"
        if status in (400, 401, 413):
            team._ip_allowed(client)   # a refused response counts towards this address's sign-in limit
        audit.record("team_login_failed", actor=security.NOT_SIGNED_IN, via="saml", reason=reason[:300], client=client)
        return HTMLResponse(f"<!doctype html><title>Sign-in refused</title><p>SAML sign-in refused: {_html.escape(reason)}</p>"
                            '<p><a href="/login">Back to the sign-in page</a></p>', status_code=status)

    @app.get(sso_saml.LOGIN_PATH)
    async def saml_login(request: Request):
        """Start a SAML 2.0 sign-in: send the browser to the identity
        provider with an AuthnRequest (HTTP-Redirect binding), and a cookie
        that ties the answer to this browser."""
        _saml_on()
        if not team._ip_allowed("start:" + (request.client.host if request.client else "?"), team.START_IP_ATTEMPTS):
            # Each start fills a capped map of pending requests: limit them per address.
            raise HTTPException(status_code=429, detail="Too many sign-ins started from this address: wait a few minutes.",
                                headers={"Retry-After": "60"})
        binding = sso_saml.new_binding()
        try:
            url = sso_saml.start_login(binding)
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
        resp = RedirectResponse(url, status_code=302)
        resp.set_cookie(sso_saml.LOGIN_COOKIE, binding, httponly=True, samesite="lax", secure=security._https(request),
                        path=sso_saml.COOKIE_PATH, max_age=sso_saml.PENDING_TTL_SECONDS)
        return resp

    @app.post(sso_saml.ACS_PATH)
    async def saml_acs(request: Request):
        """The assertion consumer service: the identity provider's browser
        POST (HTTP-POST binding). The response is verified in full
        (sso_saml.verify_response) and then handed, with a one-time code, to
        /api/auth/saml/finish in the browser that started the sign-in. This
        POST comes from the identity provider's page, so it is the one
        change exempt from the Origin check; it signs nobody in by itself."""
        _saml_on()
        if team.ip_blocked(request.client.host if request.client else "?"):
            return _saml_refused(request, "too many refused sign-ins from this address: wait a few minutes and try again", 429)
        try:
            form = await _saml_form(request)
        except ValueError:
            return _saml_refused(request, "the form is not URL-encoded text", 400)
        if form is None:
            return _saml_refused(request, "the SAML response is too large", 413)
        relay = (form.get("RelayState") or [""])[0]
        if not relay:
            # Every sign-in this server starts sends a RelayState; the answer must carry it back.
            return _saml_refused(request, "the SAML response has no RelayState: start the sign-in again from the sign-in page")
        try:
            xml = sso_saml.decode_post((form.get("SAMLResponse") or [""])[0])
            claims = sso_saml.verify_response(xml, relay_state=relay)
        except sso_saml.SamlError as e:
            return _saml_refused(request, str(e))
        except RuntimeError as e:
            return _saml_refused(request, str(e), 500)
        code = sso_saml.new_handoff(claims)
        return RedirectResponse(f"{sso_saml.FINISH_PATH}?h={code}", status_code=303)

    @app.get(sso_saml.FINISH_PATH)
    async def saml_finish(request: Request, h: str = ""):
        """Finish a verified SAML sign-in in the browser that started it (its
        cookie must match): the account it belongs to (team_server.link_saml)
        gets a fresh session, capped by the identity provider's
        SessionNotOnOrAfter. No account, a turned-off account, or a person in
        none of ZSCALER_SAML_ALLOWED_GROUPS is refused. Audited."""
        _saml_on()
        try:
            claims = sso_saml.redeem_handoff(h[:200], request.cookies.get(sso_saml.LOGIN_COOKIE) or "")
        except sso_saml.SamlError as e:
            return _saml_refused(request, str(e))
        who = str(claims.get("email") or claims.get("sub") or "unknown")[:200]
        if not sso_saml.sign_in_allowed(claims):
            return _saml_refused(request, f"{who} is not in a group allowed to use this server (ZSCALER_SAML_ALLOWED_GROUPS)", 403)
        try:
            member = team.link_saml(claims)
        except team.TeamError as e:
            return _saml_refused(request, str(e), e.status)
        if member is None:
            return _saml_refused(request, f"{who} has no active account on this team server. Ask an administrator to add you, "
                                          "or to provision you through SCIM.", 403)
        if team.is_locked(member):
            return _saml_refused(request, team.LOCKED, 423)
        import time as _t
        until = claims.get("session_not_on_or_after")
        sid = team.start_session(member, via="saml", previous_sid=request.cookies.get(security.SSO_SESSION_COOKIE),
                                 token_groups=claims.get("groups") or [],
                                 max_seconds=(until - _t.time()) if isinstance(until, (int, float)) else None)
        resp = RedirectResponse("/", status_code=303)
        security.set_session_cookie(resp, request, sid)
        resp.delete_cookie(sso_saml.LOGIN_COOKIE, path=sso_saml.COOKIE_PATH, httponly=True, samesite="lax", secure=security._https(request))
        audit.record("team_login", actor=member.get("username"), via="saml", role=member.get("role"),
                     subject=str(claims.get("sub"))[:200], client=request.client.host if request.client else "?")
        return resp

    @app.get(sso_saml.METADATA_PATH)
    async def saml_metadata():
        """This server's SAML service provider metadata (entity ID, ACS URL,
        signed assertions wanted), for setting up the identity provider."""
        _saml_on()
        return Response(sso_saml.sp_metadata_xml(), media_type="application/samlmetadata+xml")

    # ── passkeys (team_passkeys.py) ──────────────────────────────────────
    def _pk_fail(e: "team_passkeys.PasskeyError"):
        raise HTTPException(status_code=e.status, detail=str(e))

    @app.post("/api/auth/team/passkey/options")
    async def team_passkey_options(request: Request):
        """Start a passkey sign-in: a one-use challenge for the browser's
        navigator.credentials.get() (no user name: the passkey names its account).
        Limited per address: each challenge fills a capped shared map."""
        _on()
        if not team._ip_allowed("start:" + (request.client.host if request.client else "?"), team.START_IP_ATTEMPTS):
            raise HTTPException(status_code=429, detail="Too many sign-ins started from this address: wait a few minutes.",
                                headers={"Retry-After": "60"})
        try:
            return team_passkeys.authentication_options()
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)

    @app.post("/api/auth/team/passkey/login")
    async def team_passkey_login(request: Request):
        """Sign in with a passkey: the challenge's ceremony id and the
        browser's assertion. The same call finishes a password sign-in whose
        account has a passkey (the ceremony is bound to that account). Rate
        limited per address, refused for a locked or turned-off account, a
        failed passkey counts towards the lockout, a new session id every
        time. Audited."""
        _on()
        data = await _body(request)
        client = request.client.host if request.client else "?"
        try:
            u = team_passkeys.authenticate(data.get("ceremony"), data.get("credential"), client)
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)
        except team.LoginRefused as e:
            audit.record("team_login_failed", actor=security.NOT_SIGNED_IN, via="passkey", reason=e.reason, client=client)
            headers = {"Retry-After": "60"} if e.status in (423, 429) else None
            return JSONResponse({"detail": str(e)}, status_code=e.status, headers=headers)
        via = u.pop("_via", "passkey")
        sid = team.start_session(u, via=via, previous_sid=request.cookies.get(security.SSO_SESSION_COOKIE))
        resp = JSONResponse({"ok": True, "user": u.get("username"), "role": u.get("role")})
        security.set_session_cookie(resp, request, sid)
        audit.record("team_login", actor=u.get("username"), via=via, role=u.get("role"), client=client)
        return resp

    @app.post("/api/team/me/passkeys/options")
    async def team_me_passkey_options(request: Request):
        """Start adding a passkey to your account: your current password
        first (when the account has one), then a one-use challenge for
        navigator.credentials.create()."""
        _on()
        u = _me()
        data = await _body(request)
        if u.get("password") and not team.verify_password(str(data.get("current") or ""), u.get("password")):
            audit.record("team_passkey_refused", reason="the current password was wrong")
            raise HTTPException(status_code=403, detail="The current password is not right.")
        if not u.get("password"):
            # No password to ask for (an SSO or SAML account): the sign-in itself must be recent,
            # so a stolen older session cannot add a lasting way in.
            s = sso.get_session(request.cookies.get(security.SSO_SESSION_COOKIE)) or {}
            if not team._clock() - float(s.get("created") or 0) <= RECENT_SIGN_IN_SECONDS:
                audit.record("team_passkey_refused", reason="the sign-in is not recent")
                raise HTTPException(status_code=403, detail="Sign out and sign in again, then add the passkey within "
                                                            f"{RECENT_SIGN_IN_SECONDS // 60} minutes.")
        try:
            return {"options": team_passkeys.registration_options(u, request.cookies.get(security.SSO_SESSION_COOKIE))}
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)

    @app.post("/api/team/me/passkeys")
    async def team_me_passkey_add(request: Request):
        """Finish adding a passkey: the browser's registration response, and a name for it."""
        _on()
        u = _me()
        data = await _body(request)
        try:
            pk = team_passkeys.register(u, request.cookies.get(security.SSO_SESSION_COOKIE), data.get("credential"), data.get("name"))
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)
        return {"passkey": pk}

    @app.delete("/api/team/me/passkeys/{passkey_id}")
    async def team_me_passkey_remove(passkey_id: str):
        """Remove one of your passkeys."""
        _on()
        u = _me()
        try:
            team_passkeys.remove(u["id"], passkey_id, by=u.get("username"))
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)
        return {"removed": True}

    @app.delete("/api/team/users/{user_id}/passkeys")
    async def team_user_passkeys_remove(user_id: str):
        """Remove every passkey of an account (a lost or stolen device)."""
        _on()
        try:
            n = team_passkeys.remove_all(user_id, by=security.current_actor())
        except team_passkeys.PasskeyError as e:
            _pk_fail(e)
        return {"removed": n}

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
        people = [{"principal": f"user:{x['id']}", "name": x["username"]} for x in team.list_users() if x["active"] and x["id"] != u.get("id")]
        people += [{"principal": f"group:{g['id']}", "name": f"group: {g['display_name']}"} for g in team.list_groups()]
        return {"user": team.public_user(u), "role_actions": list(team.ROLE_ACTIONS.get(str(u.get("role")), ())), "people": people,
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
        if isinstance(data.get("new"), str) and data.get("new") == data.get("current"):
            raise HTTPException(status_code=400, detail="Choose a password different from the current one.")
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
                "stores": store_crypto.status(), "fips": store_crypto.fips_status(),
                "settings": {"idle_minutes": team.idle_seconds() // 60, "session_hours": round(team.session_seconds() / 3600, 2),
                             "lockout_attempts": team.lockout_attempts(), "lockout_minutes": team.lockout_seconds() // 60,
                             "min_password": team.MIN_PASSWORD, "oidc": sso.sso_enabled(), "saml": sso_saml.enabled(),
                             "passkeys": team_passkeys.status()},
                "sign_in": _sign_in_view()}

    def _sign_in_view() -> Dict[str, Any]:
        return {"saml": sso_saml.settings_view(), "require_passkey": team.require_passkey(), "passkeys": team_passkeys.status()}

    @app.post("/api/team/sign-in")
    async def team_sign_in_settings(request: Request):
        """Change how people sign in (the Team server page's Sign-in section):
        {"saml": {metadata | idp_entity_id, idp_sso_url, idp_cert_pem,
        sp_entity_id, acs_url, email_attribute, groups_attribute,
        allowed_groups, enabled}} and/or {"require_passkey": true|false}.
        The metadata is an upload: size-capped, no DTDs or entities. Turning
        SAML on needs every value; requiring passkeys needs passkeys set up.
        Local team server settings only, never a tenant. Audited."""
        _on()
        data = await _body(request)
        by = security.current_actor()
        if "saml" in data:
            if not isinstance(data["saml"], dict):
                raise HTTPException(status_code=400, detail="saml must be an object.")
            try:
                sso_saml.save_settings(data["saml"], by=by)
            except sso_saml.SamlError as e:
                raise HTTPException(status_code=400, detail=str(e))
        if "require_passkey" in data:
            try:
                team.set_require_passkey(data["require_passkey"], by=by)
            except team.TeamError as e:
                _fail(e)
        return _sign_in_view()

    @app.post("/api/team/sign-in/test-saml")
    async def team_sign_in_test_saml():
        """Check the SAML settings without signing anybody in and without
        calling the identity provider: every value present and safe, the
        certificates readable and in date, and the request this server sends."""
        _on()
        return sso_saml.check_settings()

    @app.post("/api/team/users")
    async def team_user_create(request: Request):
        """Create an account: user name, role, and a password (or none, for
        someone who signs in through the identity provider only)."""
        _on()
        data = await _body(request)
        try:
            # A password an administrator types is theirs, not the new person's:
            # its owner chooses their own at first sign-in.
            u = team.create_user(username=data.get("username"), role=data.get("role") or "viewer", password=data.get("password") or None,
                                 display_name=data.get("display_name") or "", email=data.get("email") or "", by=security.current_actor(),
                                 must_change=True)
        except team.TeamError as e:
            _fail(e)
        return {"user": team.public_user(u)}

    @app.post("/api/team/users/{user_id}")
    async def team_user_update(user_id: str, request: Request):
        """Change an account's role, display name, email, or turn it off or on.
        A role change or turning it off ends its sessions at once.
        `allow_saml_link: true` lets the account's next SAML sign-in (within
        team_server.SAML_LINK_SECONDS) link to it: needed for administrator
        accounts, which are never linked by their email alone."""
        _on()
        data = await _body(request)
        me = _me()
        if user_id == me.get("id") and (data.get("active") is False or (data.get("role") not in (None, "admin"))):
            raise HTTPException(status_code=409, detail="You cannot turn off or demote your own account; ask another administrator.")
        try:
            u = team.update_user(user_id, by=me.get("username"), role=data.get("role"), active=data.get("active"),
                                 display_name=data.get("display_name"), email=data.get("email"),
                                 allow_saml_link=data.get("allow_saml_link"))
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
        """Set an account's password (an administrator's reset). Its sessions
        end, and its owner must choose their own password at the next sign-in."""
        _on()
        data = await _body(request)
        try:
            me = team.current_user() or {}
            team.set_password(user_id, data.get("password"), by=security.current_actor(), must_change=user_id != me.get("id"))
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

    @app.get("/api/team/share")
    async def team_share_get(kind: str = "", id: str = ""):  # noqa: A002 - the query name the page uses
        """Who owns a template or saved plan and whom it is shared with."""
        _on()
        try:
            if not team.may_use(kind, id):
                raise HTTPException(status_code=404, detail="Not found, or not yours to see.")
            rec = team.sharing(kind, id) or {}
        except team.TeamError as e:
            _fail(e)
        return {"kind": kind, "id": id, "owner": rec.get("owner"), "principals": rec.get("principals") or []}

    @app.post("/api/team/share")
    async def team_share_set(request: Request):
        """Share a template or saved plan with users and groups (owner or
        administrator only). A shared plan still opens only for people who
        may read its tenant profile."""
        _on()
        data = await _body(request)
        try:
            rec = team.share(str(data.get("kind") or ""), data.get("id"), data.get("principals"), by=security.current_actor())
        except team.TeamError as e:
            _fail(e)
        return {"sharing": rec}

    @app.post("/api/team/store-key/rotate")
    async def team_store_key_rotate():
        """Rotate the store encryption key: a new key, every store re-sealed
        with it, then the old key forgotten. Audited. 409 when encryption is off."""
        _on()
        if not store_crypto.enabled():
            raise HTTPException(status_code=409, detail="Store encryption is off: the server was started with DLP_CHECK_STORE_ENCRYPTION=0. Remove that setting (on is the default) and start again.")
        try:
            out = store_crypto.rotate()
        except store_crypto.StoreLocked as e:
            raise HTTPException(status_code=409, detail=f"Rotation stopped, both keys kept: {e}")
        return {"new_key": out["new_key"], "files": len(out["files"]), "kept_in": out["kept_in"],
                "old_keys_kept": len(out.get("old_keys_kept") or [])}

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
        """A proposal queue's key, or a tenant label a local history is kept
        under (Client Connector fleet history, SSL coverage history): the
        profile the history was kept for, else the profiles of that label."""
        import proposals
        out = set(team.profiles_for_keys([proposals.tenant_key(tenant)]))
        try:
            import zcc_fleet_history
            pid = zcc_fleet_history.profile_of(tenant)
            if pid:
                out.add(pid)
        except Exception:  # noqa: BLE001 - an unreadable history names no profile
            pass
        out |= team.profiles_for_label(tenant)
        return out or None

    def backup(backup_id: str, _params) -> Optional[dict]:
        import config_backup as cb
        meta = cb.backup_meta(backup_id)
        if meta is None:
            return None
        return {"profiles": team.record_profiles(meta), "owner": meta.get("owner_id") or ""}

    def template(template_id: str, _params) -> Optional[dict]:
        import config_backup as cb
        if cb.TEMPLATE_ID.match(str(template_id or "")):
            meta = cb.template_meta(template_id)
            if meta is None:
                return None
            return {"profiles": team.record_profiles(meta), "owner": meta.get("owner_id") or "", "share": "template"}
        # A POV template (pov.py) is a plan with no tenant in it: its owner,
        # whom it is shared with, or (made before team mode) anyone signed in.
        rec = team.sharing("template", template_id) if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", str(template_id or "")) else None
        if not rec:
            import pov
            return {"profiles": set(), "anyone": True} if any(t.get("id") == template_id for t in pov.list_templates()) else None
        return {"profiles": set(), "owner": rec.get("owner") or "", "share": "template"}

    def saved_report(name: str, _params) -> Optional[dict]:
        import traffic_logs
        meta = traffic_logs.saved_meta(name)
        if meta is None:
            return None
        return {"profiles": team.record_profiles(meta), "owner": meta.get("owner_id") or ""}

    team.register_resolver("backup_id", backup)
    team.register_resolver("template_id", template)
    team.register_resolver("saved_name", saved_report)
    team.register_resolver("rid", change_request)
    team.register_resolver("dep_id", deployment)
    team.register_resolver("op_id", operation)
    team.register_resolver("snapshot_id", snapshot)
    team.register_resolver("tenant", tenant_key)
