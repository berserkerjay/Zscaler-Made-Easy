#!/usr/bin/env python3
"""
Zscaler Assessment API Server + Web GUI
=========================================
FastAPI server with SSE streaming and a web frontend.

Run:
    python dlp_api_server.py
    # Open http://localhost:8000 in your browser

Endpoints:
    GET  /                   — Web GUI
    POST /api/assess         — Run assessment (SSE stream)
    POST /api/assess/json    — Run assessment (JSON response)
    POST /api/report/docx    — Generate Word doc from results
    GET  /api/health         — Health check
    GET  /api/checks         — List all check IDs/labels
"""

import json, asyncio, os, re, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from starlette.background import BackgroundTask


def _unlink_quietly(path: str) -> None:
    """Remove a temporary report file; a missing file is not an error."""
    try:
        os.unlink(path)
    except OSError:
        pass
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse, HTMLResponse, Response, PlainTextResponse, RedirectResponse

import tenant_auth
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Security hardening (secure-by-design controls) ───────────────────
from security import (
    ALLOWED_ORIGINS,
    SecurityHeadersMiddleware,
    OriginCheckMiddleware,
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    get_bind_host, get_port, get_max_body_bytes, is_debug,
    validate_cloud, validate_vanity, validate_credential, validate_customer_id,
    mask_secret, writes_enabled,
)

# ── Import the assessment engine ─────────────────────────────────────
import importlib.util

ENGINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_assessment_full_auto.py")
spec = importlib.util.spec_from_file_location("engine", ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

Client = engine.Client
REG = engine.REG
R = engine.R
compute = engine.compute
maturity = engine.maturity

# Try to load platform checks
PLATFORM_REG = []
GENAI_REG = []
try:
    CHECKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_full_checks.py")
    cspec = importlib.util.spec_from_file_location("full_checks", CHECKS_PATH)
    full_checks = importlib.util.module_from_spec(cspec)
    cspec.loader.exec_module(full_checks)
    PLATFORM_REG = full_checks.PLATFORM_REG
except Exception:
    pass
try:
    GENAI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_genai_checks.py")
    gspec = importlib.util.spec_from_file_location("genai_checks", GENAI_PATH)
    genai_checks = importlib.util.module_from_spec(gspec)
    gspec.loader.exec_module(genai_checks)
    GENAI_REG = genai_checks.GENAI_REG
except Exception:
    pass

# Automation-readiness checks (github.com/zscaler ecosystem: SDKs,
# terraform providers, ansible collections, zscaler-terraformer).
AUTOMATION_REG = []
try:
    AUTO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_automation_checks.py")
    aspec = importlib.util.spec_from_file_location("automation_checks", AUTO_PATH)
    auto_checks = importlib.util.module_from_spec(aspec)
    aspec.loader.exec_module(auto_checks)
    AUTOMATION_REG = auto_checks.AUTOMATION_REG
except Exception:
    pass

# ZDX — Digital Experience
ZDX_REG = []
try:
    ZDX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_zdx_checks.py")
    zspec = importlib.util.spec_from_file_location("zdx_checks", ZDX_PATH)
    zdx_mod = importlib.util.module_from_spec(zspec)
    zspec.loader.exec_module(zdx_mod)
    ZDX_REG = zdx_mod.ZDX_REG
except Exception:
    pass

# ZIdentity — users/groups/resource-servers/entitlements
ZID_REG = []
try:
    ZID_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_zidentity_checks.py")
    idspec = importlib.util.spec_from_file_location("zidentity_checks", ZID_PATH)
    zid_mod = importlib.util.module_from_spec(idspec)
    idspec.loader.exec_module(zid_mod)
    ZID_REG = zid_mod.ZID_REG
except Exception:
    pass

# RBAC checks — admin roles / SSO / MFA / group-binding across all scopes
RBAC_REG = []
try:
    RBAC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zscaler_rbac_checks.py")
    rbspec = importlib.util.spec_from_file_location("rbac_checks", RBAC_PATH)
    rbac_mod = importlib.util.module_from_spec(rbspec)
    rbspec.loader.exec_module(rbac_mod)
    RBAC_REG = rbac_mod.RBAC_REG
except Exception:
    pass

# ── FastAPI App ──────────────────────────────────────────────────────

app = FastAPI(
    title="Zscaler Platform Assessment",
    version="3.0",
    description="Full-auto assessment engine via OneAPI.",
)

# Order matters: outermost first → body-size → rate-limit → origin → headers → gzip → CORS.
# Body size and rate limit reject early before doing any real work.
app.add_middleware(BodySizeLimitMiddleware, max_bytes=get_max_body_bytes())
app.add_middleware(RateLimitMiddleware, rps=20, burst=60)
app.add_middleware(OriginCheckMiddleware)
import security as _security
import audit as _audit
app.add_middleware(_audit.AuditMiddleware, writes_enabled=writes_enabled)   # innermost: sees the final status of every write call
app.add_middleware(_security.UIAuthMiddleware)   # inside the headers layer: a 401 still carries the security headers
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1024)

# SSO (sso.py) is off by default; ZSCALER_SSO_ENABLED turns it on. Fail
# closed at import time rather than starting half-configured — that
# would silently leave the static-token shortcuts as the only way in
# while claiming SSO is required.
import sso as _sso
_sso.require_configured()

# A server bound beyond loopback needs its own front-door authentication;
# the UI token alone is a bearer secret, not MFA. Fail closed here too.
_security.require_safe_bind()


@app.middleware("http")
async def _no_stale_static(request, call_next):
    """The GUI is updated in place by UPDATE_Zscaler_Assessment.bat; make
    browsers revalidate every static file so an update shows up on the next
    load instead of after a hard refresh."""
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path in ("/", "/app.css", "/report/view", "/report/bypass", "/report/sslflow", "/report/flow", "/report/dataflow", "/report/advanced", "/report/health", "/report/compliance", "/report/evalall", "/report/path", "/report/live", "/report/vendor", "/report/beacon"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate, max-age=0"
    return response
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED_ORIGINS),  # No wildcard. Localhost only.
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    max_age=3600,
)


# ── Generic exception handler — never leak stack traces ────────────
@app.exception_handler(Exception)
async def _safe_exception_handler(request: Request, exc: Exception):
    """Catch-all so internal errors never expose tracebacks to the client."""
    if isinstance(exc, HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    if is_debug():
        import traceback
        return JSONResponse(
            {"detail": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc()},
            status_code=500,
        )
    # In normal mode, return a generic message — log details server-side only
    # (server.log carries the traceback so the failure can be reported).
    import traceback
    print(f"[error] {type(exc).__name__} on {request.method} {request.url.path}: {exc}\n{traceback.format_exc()}")
    return JSONResponse(
        {"detail": f"Internal error ({type(exc).__name__}). The traceback is in server.log next to the app; run with ZSCALER_DEBUG=1 to see it here."},
        status_code=500,
    )

# Serve static files (web GUI)
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(_APP_DIR, "static")

# Assessment run tuning. Checks run on ASSESS_WORKERS threads that share one
# request pacer (see dlp_assessment_full_auto.Client); a check still running
# after CHECK_TIMEOUT seconds is reported as timed out and the run moves on.
ASSESS_WORKERS = max(1, min(16, int(os.environ.get("ASSESS_WORKERS", "6") or 6)))
CHECK_TIMEOUT = max(15, int(os.environ.get("ASSESS_CHECK_TIMEOUT", "60") or 60))
JOURNEY_TIMEOUT = max(30, int(os.environ.get("ASSESS_JOURNEY_TIMEOUT", "180") or 180))


def _load_local_settings() -> None:
    """local_settings.env next to the app (git-ignored): KEY=VALUE lines for
    REQUESTS_CA_BUNDLE, HTTPS_PROXY, ZSCALER_* and the like. Values already
    in the environment win. The .bat launchers do the same with
    local_settings.bat; this covers running the server directly."""
    path = os.path.join(_APP_DIR, "local_settings.env")
    if not os.path.exists(path):
        return
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except OSError:
        pass


_load_local_settings()


def _tls_status() -> Dict[str, Any]:
    """What the operator needs to know about TLS inspection and proxies."""
    ca = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or ""
    return {
        "ca_bundle": ca,
        "ca_bundle_exists": bool(ca) and os.path.exists(ca),
        "https_proxy": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
        "local_settings_bat": os.path.exists(os.path.join(_APP_DIR, "local_settings.bat")),
        "local_settings_env": os.path.exists(os.path.join(_APP_DIR, "local_settings.env")),
    }
PACKS_ROOT = _APP_DIR
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# GUI add-ons: standalone assets under static/ that extend the single-file
# GUI without editing index.html. Each is injected into the served page only
# if the file exists — a <link> before </head>, a <script> before </body>.
# Scripts run after index.html's inline script, so they can replace legacy
# functions by redefining them. Same-origin, so the CSP ('self') allows them.
GUI_ADDONS = [
    ("deploy_studio.css", "style"),
    ("guide.css", "style"),
    ("reports.css", "style"),
    ("dashboard.css", "style"),
    ("icons.js", "script"),         # first: the symbol set every page and add-on draws its icons from
    ("ui_auth.js", "script"),       # the in-app unlock and notice dialogs the fetch wrapper and the guide use
    ("rate_gate.js", "script"),     # the rate-limit check every deploy and delete confirms with
    ("deploy_studio.js", "script"),
    ("explain.js", "script"),
    ("guide.js", "script"),
    ("update_beacon.js", "script"),  # checks for updates in the background and shows a notice when one is out
    ("eval_all.js", "script"),
    ("bypass_report.js", "script"),
    ("tool_tabs.js", "script"),
    ("dashboard.js", "script"),     # last: wraps showResults / renderChecks / resetForm
]


def _inject_gui_addons(html: str) -> str:
    """Insert the add-on tags at the document's real </head> and </body>.

    index.html's inline script builds other HTML documents inside template
    literals, so the strings "</head>" and "</body>" also occur INSIDE the
    JavaScript. The document's own </head> is always the first occurrence
    (it precedes every script) and its own </body> is always the last
    (nothing follows it), so anchor on those — a naive first-match replace
    of </body> lands inside the script, truncates it, and kills the app."""
    for name, kind in GUI_ADDONS:
        path = os.path.join(STATIC_DIR, name)
        if not os.path.exists(path):
            continue
        # Cache-buster: the file's mtime, so a browser that cached the old
        # add-on after an update fetches the new one without Ctrl+F5.
        v = int(os.path.getmtime(path))
        if kind == "style":
            tag, pos = f'<link rel="stylesheet" href="/static/{name}?v={v}">\n', html.find("</head>")
        else:
            tag, pos = f'<script src="/static/{name}?v={v}"></script>\n', html.rfind("</body>")
        if pos >= 0:
            html = html[:pos] + tag + html[pos:]
    return html


# ── Request Models ───────────────────────────────────────────────────

class AssessRequest(BaseModel):
    """Body of /api/assess: who is assessing which tenant, with its credentials
    (a ZIdentity API client, or the classic ZIA API's username, password and
    API key with auth_method="legacy"; see tenant_auth)."""
    org_name: str = "Unknown"
    assessor: str = "Unknown"
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    auth_method: str = ""      # "oneapi" (default) or "legacy"
    username: str = ""         # classic ZIA API sign-in
    password: str = ""
    api_key: str = ""
    scope: str = "full"  # legacy single scope, kept for compatibility
    scopes: list[str] = []  # new: list of scope keys (dlp, zia_extras, zpa, zcc)
    customer_id: str = ""  # Optional ZPA customer ID
    profile_id: str = ""   # Saved tenant profile: fills blanks, records history
    # The Scope page's channel ownership: {id: {choice: zscaler|alternative|gap, note, name}}.
    # A channel covered by an alternative solution has its checks reported as
    # not in scope instead of read from the tenant (channel_scope).
    channels: Dict[str, Any] = {}


class TenantProfileRequest(BaseModel):
    """Body for saving a tenant profile (customer details, scopes, packs, optional remembered secrets)."""
    id: str = ""
    name: str = ""
    org_name: str = ""
    assessor: str = ""
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    auth_method: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    remember_secret: bool = False
    customer_id: str = ""
    industry: str = ""
    baseline_packs: list[str] = []
    scopes: list[str] = []
    frameworks: list[str] = []
    channels: Dict[str, Any] = {}   # the Scope page's channel ownership (channel_scope.normalize)
    notes: str = ""


class UpdateCheckRequest(BaseModel):
    """Body of the Zscaler update check: which sources to refresh and how."""
    only: Optional[list[str]] = None  # subset of source keys
    reset: bool = False               # wipe cache first
    skip_tls_verify: bool = False     # corporate TLS MITM bypass (opt-in per request)


# ── Routes ────────────────────────────────────────────────────────────

class UnlockRequest(BaseModel):
    """Body of /api/unlock: the UI token typed by the operator."""
    token: str = ""


@app.get("/api/ping")
async def ping():
    """Liveness only (no version, no paths): what the launcher polls."""
    return {"ok": True}


@app.get("/api/auth/status")
async def auth_status(request: Request):
    """Whether this server asks for a UI token, whether this browser has
    it, and whether sign-in is through SSO instead (then also who is
    signed in and whether they may change the tenant)."""
    if not _sso.sso_enabled():
        return {"required": _security.ui_auth_enabled(), "unlocked": _security.ui_request_ok(request),
                "token_file": _security.UI_TOKEN_FILE if _security.ui_auth_enabled() else None,
                "sso": False}
    session = _security.sso_session(request)
    return {"required": True, "unlocked": session is not None, "token_file": None, "sso": True,
            "user": (session.get("email") or session.get("sub")) if session else None,
            "may_write": _sso.is_writer(session) if session else False,
            "sso_login_url": "/api/auth/sso/login", "logout_url": "/api/auth/logout"}


@app.post("/api/auth/unlock")
async def auth_unlock(req: UnlockRequest, request: Request):
    """Exchange the UI token for the cookie the page uses from then on.
    Refused when SSO is enabled: the cookie is only minted by a
    completed identity-provider login, never by a pasted token."""
    if not _security.ui_auth_enabled():
        return {"ok": True, "required": False}
    if _sso.sso_enabled():
        raise HTTPException(status_code=403, detail="This server requires SSO sign-in. Use the Sign in button, not a pasted token.")
    if not _security.ui_token_ok(req.token):
        raise HTTPException(status_code=401, detail="That UI token is not valid for this server. Read ui_token.txt next to the app (or the console) and try again.")
    resp = JSONResponse({"ok": True, "required": True})
    _security.set_ui_cookie(resp, request)
    return resp


@app.get("/api/auth/sso/login")
async def sso_login():
    """Start an OpenID Connect sign-in: redirect to the identity provider."""
    if not _sso.sso_enabled():
        raise HTTPException(status_code=404, detail="SSO is not enabled on this server.")
    try:
        url = _sso.start_login()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not start SSO sign-in: {e}")
    return RedirectResponse(url, status_code=302)


@app.get("/api/auth/sso/callback")
async def sso_callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    """Where the identity provider sends the browser back. On success,
    starts a session for this person (sso.create_session) and sets a
    cookie holding only its random id. With ZSCALER_SSO_ALLOWED_GROUPS
    set, a person in none of those groups is refused (and audited).
    `error`/`error_description` and any exception text are
    attacker-influenceable (query params, or echoed from the token
    response) and are HTML-escaped before display."""
    import html as _html
    if not _sso.sso_enabled():
        raise HTTPException(status_code=404, detail="SSO is not enabled on this server.")
    if error:
        return HTMLResponse(f"<p>Sign-in was not completed: {_html.escape(error_description or error)}</p>", status_code=401)
    try:
        claims = _sso.complete_login(state, code)
    except Exception as e:
        return HTMLResponse(f"<p>Sign-in failed: could not verify the identity provider's response ({_html.escape(str(e))}).</p>", status_code=401)
    who = str(claims.get("email") or claims.get("sub") or "unknown")
    if not _sso.sign_in_allowed(claims):
        has_groups = bool(_sso.claim_groups(claims))
        _audit.record("sso_login_refused", actor=who, email=claims.get("email"), subject=claims.get("sub"),
                      groups=_sso.claim_groups(claims), reason="not in any group listed in ZSCALER_SSO_ALLOWED_GROUPS"
                      if has_groups else f"the ID token has no '{_sso.groups_claim()}' claim, so no allowed group could be matched")
        return HTMLResponse(
            f"<p>Sign-in refused: {_html.escape(who)} is not in a group allowed to use this server. Ask the person who runs it "
            "to add you to one of the groups in ZSCALER_SSO_ALLOWED_GROUPS"
            + ("" if has_groups else f", and to have the identity provider send the '{_html.escape(_sso.groups_claim())}' claim") + ".</p>",
            status_code=403)
    session_id = _sso.create_session(claims)
    resp = RedirectResponse("/", status_code=303)
    _security.set_session_cookie(resp, request, session_id)
    _audit.record("sso_login", actor=who, email=claims.get("email"), subject=claims.get("sub"), groups=_sso.claim_groups(claims))
    return resp


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    """Sign out (SSO only): end this browser's session on the server and
    clear its cookie. Audited. Works even after the session has expired,
    so the cookie is always cleared."""
    if not _sso.sso_enabled():
        raise HTTPException(status_code=404, detail="Sign out is only used with SSO; this server uses the UI token.")
    ended = _sso.end_session(request.cookies.get(_security.SSO_SESSION_COOKIE))
    _audit.record("sso_logout", actor=_security.current_actor() if ended else "not signed in",
                  ended=bool(ended), client=request.client.host if request.client else "?")
    resp = JSONResponse({"ok": True, "signed_out": bool(ended), "sso_login_url": "/api/auth/sso/login"})
    _security.clear_session_cookie(resp, request)
    return resp


@app.get("/")
async def serve_gui():
    """Serve the web GUI.
    Forces revalidation on every page load so users always get the
    latest UI after running UPDATE_Zscaler_Assessment.bat — no more
    'Ctrl+F5 to clear cache' surprises.
    """
    index = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index):
        return JSONResponse({"error": "GUI not found. Place index.html in static/"}, status_code=404)
    headers = {"Cache-Control": "no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"}
    try:
        with open(index, "r", encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return FileResponse(index, headers=headers)
    return HTMLResponse(_inject_gui_addons(html), headers=headers)


@app.get("/app.css")
async def serve_app_css():
    """The GUI's own stylesheet (the first <style> block of index.html), so
    the report tabs (/report/bypass, /report/sslflow, /report/view) look
    exactly like the assessment page: same tokens, fonts, theme, buttons."""
    from fastapi.responses import Response
    index = os.path.join(STATIC_DIR, "index.html")
    css = ""
    try:
        with open(index, "r", encoding="utf-8") as f:
            html = f.read()
        start = html.find("<style>")
        end = html.find("</style>", start)
        if start >= 0 and end > start:
            css = html[start + len("<style>"):end]
    except OSError:
        css = ""
    return Response(content=css, media_type="text/css",
                    headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Guided Auto-Remediation ──────────────────────────────────────
# Takes a finding + user-supplied criteria and generates the API
# call that would fix it. Read-only by default (dry_run=True);
# live writes gated by ENABLE_WRITE_ACTIONS env var per standard
# policy. See remediation.py for recipe catalog.

class RemediationPlanRequest(BaseModel):
    """Body for a remediation plan: tenant credentials plus the findings to plan for."""
    # Tenant fields (duplicated rather than inheriting MigrateRequest so
    # this class is defined ahead of MigrateRequest without a forward-ref).
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""
    check_id: str = ""
    criteria: dict = {}


class RemediationExecuteRequest(BaseModel):
    """Body for executing an approved remediation plan."""
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""
    check_id: str = ""
    criteria: dict = {}
    dry_run: bool = True


@app.get("/api/remediation/catalog")
async def remediation_catalog():
    """List the remediations available + their input schemas."""
    try:
        from remediation import get_catalog
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"remediation unavailable: {e}")
    return {"catalog": get_catalog()}


@app.post("/api/remediation/plan")
async def remediation_plan(req: RemediationPlanRequest):
    """Build the planned API call without sending. Returns endpoint,
    method, body, and any validation errors against the field spec."""
    try:
        from remediation import plan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"remediation unavailable: {e}")
    result = await asyncio.to_thread(plan, req.check_id, req.criteria)
    return result


@app.post("/api/remediation/execute")
async def remediation_execute(req: RemediationExecuteRequest):
    """Plan + optionally execute. dry_run=True returns the plan only;
    dry_run=False requires ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND."""
    try:
        from remediation import execute
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"remediation unavailable: {e}")
    if not req.dry_run:
        _security.require_writer()
    client = await asyncio.to_thread(_build_client, req)
    result = await asyncio.to_thread(execute, client, req.check_id, req.criteria, req.dry_run)
    return result


# ─────────────────────────────────────────────────────────────────
# Tenant-credentials request model + client factory.
#
# Defined up here (instead of next to the rule-migration block where
# the rest of this class family lives) because MULTIPLE endpoints
# above the migration block accept a MigrateRequest as their body —
# specifically /api/diagnose/zcc, /api/dlp/efficacy, and
# /api/dlp/efficacy/test. In plain Python, class-inheritance and
# function annotations are evaluated at import time, so the base
# class must exist before any referencing line is parsed. Moving
# these definitions up eliminates the NameError that otherwise fires
# on `class DlpEfficacyCorpusRequest(MigrateRequest)`.
# ─────────────────────────────────────────────────────────────────
class MigrateRequest(BaseModel):
    """Tenant credentials for the Evaluate-All migration endpoints."""
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""
    auth_method: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    profile_id: str = ""
    # Inline Web DLP only — this tool's migration is scoped to the DLP
    # Web Rules inline policy. Other rule types (SSL, URL, firewall,
    # Cloud App) have different best-practice ordering rules and are
    # out of scope here.
    rule_type: str = "web_dlp"


def _raw_client(creds: Dict[str, str]):
    """The raw-HTTP assessment client for validated credentials, either
    sign-in (tenant_auth). Not yet signed in."""
    return Client(creds["client_id"], creds["client_secret"], creds["vanity_domain"], creds["cloud"], creds["customer_id"],
                  auth_method=creds["auth_method"], username=creds["username"], password=creds["password"], api_key=creds["api_key"])


def _build_client(req: "MigrateRequest"):
    """Build an authenticated Client from a migration request.
    Validates every input first; never echoes a secret in any error.
    """
    creds = _validate_creds(_tenant_creds(req))
    client = _raw_client(creds)
    auth_result = client.auth()
    if auth_result is not True:
        # auth_result is (False, "<reason>"). Sanitize: strip any echo of a secret.
        reason = ""
        if isinstance(auth_result, tuple) and len(auth_result) == 2:
            reason = str(auth_result[1])
        reason = tenant_auth.mask_secrets(reason, creds)
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed for {tenant_auth.identity(creds)}: {reason[:200]}",
        )
    return client


@app.post("/api/diagnose/zcc")
async def diagnose_zcc(req: MigrateRequest):
    """Probe every ZCC endpoint the assessment relies on and return
    per-endpoint HTTP status + response-key count + a likely-cause
    hint. Lets users see what's readable vs blocked vs not-exposed."""
    client = await asyncio.to_thread(_build_client, req)
    ZCC_ENDPOINTS = [
        ("/zcc/companyInfo",         "Company info"),
        ("/zcc/adminUsers",          "Admin users"),
        ("/zcc/adminRoles",          "Admin roles"),
        ("/zcc/adminUsersSyncInfo",  "Admin IdP sync info"),
        ("/zcc/devices",             "Device inventory"),
        ("/zcc/webPolicies",         "App profiles (web policies)"),
        ("/zcc/forwardingProfiles",  "Forwarding profiles"),
        ("/zcc/trustedNetworks",     "Trusted networks"),
        ("/zcc/failOpenPolicy",      "Fail-open policy"),
        ("/zcc/webAppService",       "Web app service exclusions"),
        ("/zcc/privacyInfo",         "Privacy info"),
        ("/zcc/zdxEntitlements",     "ZDX entitlements"),
        ("/zcc/zpaEntitlements",     "ZPA entitlements"),
        ("/zcc/machineTunnel",       "Machine tunnel (speculative — may not exist on your tenant)"),
        ("/zcc/browserProtection",   "Browser protection (speculative — license-gated)"),
        ("/zcc/pacFiles",            "PAC files (speculative)"),
        ("/zcc/deviceGroups",        "Device groups (speculative)"),
        ("/zcc/postureProfiles",     "Posture profiles"),
        ("/zcc/appBypass",           "App bypass"),
        ("/zcc/deviceCleanup",       "Device cleanup"),
        ("/zcc/zpnModuleMode",       "ZPN module modes"),
    ]
    def _probe():
        out = []
        for ep, label in ZCC_ENDPOINTS:
            try:
                data, code = client.get(ep)
            except Exception as e:
                out.append({"endpoint": ep, "label": label, "status": 0,
                            "error": f"{type(e).__name__}: {str(e)[:150]}",
                            "likely_cause": "Network / client error"})
                continue
            if isinstance(data, list):
                items = len(data); keys = None
            elif isinstance(data, dict):
                items = None
                keys = list(data.keys())[:20]
            else:
                items = None; keys = None
            cause = ""
            if code == 200:
                cause = "OK — data readable."
            elif code == 204:
                cause = "OK but empty — endpoint reachable, no items defined."
            elif code in (401, 403):
                cause = "API role lacks read permission for this ZCC feature. Grant the scope in ZIdentity → Role."
            elif code == 404:
                cause = "Endpoint not found — feature not licensed, not deployed, or not exposed on your OneAPI version."
            elif code == 429:
                cause = "Rate-limited. Retry after a short delay."
            elif code in (500, 502, 503, 504):
                cause = "Upstream ZCC service error; try again shortly."
            else:
                cause = f"HTTP {code} — inspect 'error' field."
            rec = {"endpoint": ep, "label": label, "status": code,
                   "items": items, "keys": keys, "likely_cause": cause}
            if isinstance(data, dict) and code != 200 and data.get("error"):
                rec["error"] = str(data["error"])[:200]
            out.append(rec)
        return out

    attempts = await asyncio.to_thread(_probe)
    summary = {
        "total":      len(attempts),
        "readable":   sum(1 for a in attempts if a["status"] in (200, 204)),
        "forbidden":  sum(1 for a in attempts if a["status"] in (401, 403)),
        "not_found":  sum(1 for a in attempts if a["status"] == 404),
        "error":      sum(1 for a in attempts if a["status"] not in (200, 204, 401, 403, 404)),
    }
    return {"summary": summary, "attempts": attempts}


@app.get("/api/best-practices")
async def best_practices_list(service: Optional[str] = None):
    """Return the curated Zscaler best-practices / leading-practices
    reference list (all help.zscaler.com articles). Optional ?service=
    filter (ZIA / ZPA / ZCC / Deception)."""
    try:
        from zscaler_best_practices import list_all, services
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"best-practices module unavailable: {e}")
    try:
        from bp_crawler import last_summary
        last_crawl = last_summary()
    except Exception:
        last_crawl = {}
    return {
        "entries": list_all(service or ""),
        "services": services(),
        "discovered_count": sum(1 for e in list_all(service or "") if e.get("discovered")),
        "last_crawl": last_crawl,
        "crawl_running": bool(_BP_CRAWL_PROGRESS.get("running")),
        "last_refreshed_at": _BP_REFRESH_STATE.get("last_refreshed_at"),
        "last_refresh_status": _BP_REFRESH_STATE.get("last_status"),
        "last_refresh_error": _BP_REFRESH_STATE.get("last_error"),
        "next_refresh_at": _BP_REFRESH_STATE.get("next_refresh_at"),
        "auto_refresh_enabled": _BP_REFRESH_STATE.get("enabled", True),
    }


class BPCrawlRequest(BaseModel):
    """Body of the best-practice crawl: force a refresh, optionally skip TLS verification."""
    force: bool = False
    skip_tls_verify: bool = False


# Progress of the crawl in flight, for GET /api/best-practices/crawl/status.
_BP_CRAWL_PROGRESS: Dict[str, Any] = {"running": False}
_BP_CRAWL_LOCK = asyncio.Lock()


def _bp_progress(d: Dict[str, Any]) -> None:
    _BP_CRAWL_PROGRESS.update(d)
    _BP_CRAWL_PROGRESS["running"] = True
    _BP_CRAWL_PROGRESS["updated_at"] = time.time()


async def _bp_run_crawl(force: bool, skip_tls_verify: bool) -> Dict[str, Any]:
    """Crawl, persist discoveries, update the shared state. One crawl at
    a time: a second caller waits for the first and reuses its result."""
    from bp_crawler import crawl
    from zscaler_best_practices import save_discovered
    async with _BP_CRAWL_LOCK:
        _BP_CRAWL_PROGRESS.clear()
        _BP_CRAWL_PROGRESS.update({"running": True, "started_at": time.time(), "phase": "start", "source": "", "pages": 0, "found": 0})
        try:
            result = await asyncio.to_thread(crawl, skip_tls_verify, force, None, _bp_progress)
            # Promote newly-discovered entries into the persistent library
            # so the curated + discovered catalog survives restarts.
            new_entries = result.get("new_entries") or []
            from zscaler_best_practices import _load_discovered
            before = {e.get("url") for e in _load_discovered()}
            added = await asyncio.to_thread(save_discovered, new_entries) if new_entries else 0
            result["added_to_library"] = added
            result["added_entries"] = [e for e in new_entries if e.get("url") not in before][:200]
            _BP_REFRESH_STATE["last_refreshed_at"] = time.time()
            _BP_REFRESH_STATE["last_status"] = "error" if result.get("error") else "ok"
            _BP_REFRESH_STATE["last_error"] = result.get("error")
            return result
        finally:
            _BP_CRAWL_PROGRESS["running"] = False
            _BP_CRAWL_PROGRESS["finished_at"] = time.time()


@app.post("/api/best-practices/crawl")
async def best_practices_crawl(req: BPCrawlRequest):
    """Update the library: read every source in bp_sources.py (sitemaps
    first, page walk as fallback) for Best/Leading-Practice articles,
    add the new ones to the persistent library and report what happened
    per source. The button always crawls live; force=false only reuses a
    result younger than 24h (what the background refresh does).
    skip_tls_verify=true opts into the corporate-TLS-MITM bypass."""
    try:
        import bp_crawler  # noqa: F401
        import zscaler_best_practices  # noqa: F401
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bp_crawler unavailable: {e}")
    return await _bp_run_crawl(req.force, req.skip_tls_verify)


@app.get("/api/best-practices/crawl/status")
async def best_practices_crawl_status():
    """Progress of the crawl in flight (phase, source, pages fetched,
    articles found) so the library page can show what it is doing."""
    return dict(_BP_CRAWL_PROGRESS)


# ── Best-practices auto-refresh scheduler ────────────────────────────────
# The library is "dynamic": on startup we kick off a background crawl
# if the cache is stale, and we then schedule periodic refreshes so
# newly-published Zscaler best-practice articles surface without any
# manual /api/best-practices/crawl call.
_BP_REFRESH_INTERVAL_SECONDS = 6 * 3600   # 6h — well under the 24h crawler cache,
                                          # so a fresh poll happens within a day
                                          # but we don't re-hit sources too often.
_BP_REFRESH_STATE: Dict[str, Any] = {
    "enabled": True,
    "last_refreshed_at": None,
    "last_status": None,
    "last_error": None,
    "next_refresh_at": None,
    "interval_seconds": _BP_REFRESH_INTERVAL_SECONDS,
}


async def _bp_auto_refresh_loop() -> None:
    """Background task: crawl all BP sources, persist new discoveries,
    then sleep until the next interval. Respects the crawler's own
    24h cache (force=False) so we're not hammering sources."""
    # First run: small startup delay so app finish booting cleanly
    # before we kick off potentially slow HTTP fetches.
    await asyncio.sleep(10)
    while _BP_REFRESH_STATE.get("enabled", True):
        try:
            # force=False honors the 24h cache → if something else
            # already crawled today this is effectively a no-op. A crawl
            # that reached nothing is not cached, so the next tick retries.
            await _bp_run_crawl(False, False)
        except Exception as e:
            _BP_REFRESH_STATE["last_status"] = "error"
            _BP_REFRESH_STATE["last_error"] = str(e)[:200]
        next_at = time.time() + _BP_REFRESH_INTERVAL_SECONDS
        _BP_REFRESH_STATE["next_refresh_at"] = next_at
        try:
            await asyncio.sleep(_BP_REFRESH_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            break


@app.on_event("startup")
async def _start_bp_refresh() -> None:
    """Kick off the background auto-refresh task on app startup.
    Runs forever; dies cleanly when the process exits."""
    # Only enable when the module deps are importable — a deployment
    # that strips bp_crawler shouldn't crash on boot.
    try:
        import bp_crawler  # noqa: F401
        import zscaler_best_practices  # noqa: F401
        asyncio.create_task(_bp_auto_refresh_loop())
    except Exception:
        _BP_REFRESH_STATE["enabled"] = False
        _BP_REFRESH_STATE["last_status"] = "disabled"


# ── DLP Policy Pack Management ─────────────────────────────────────────
# Generic import/verify/list for any DLP pack (fed, custom, uploaded).

@app.get("/api/dlp-packs")
async def dlp_packs_list():
    """Discover all DLP policy packs in the project directory."""
    try:
        from dlp_importer import discover_packs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_importer unavailable: {e}")
    packs = discover_packs()
    return {"packs": packs}


@app.get("/api/dlp-packs/{pack_id}")
async def dlp_pack_detail(pack_id: str):
    """Return full contents summary of a specific pack."""
    try:
        from dlp_importer import discover_packs, load_pack_contents
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_importer unavailable: {e}")
    packs = {p["id"]: p for p in discover_packs()}
    if pack_id not in packs:
        raise HTTPException(status_code=404, detail=f"Pack '{pack_id}' not found")
    return load_pack_contents(packs[pack_id]["dir"])


class TenantCredsRequest(BaseModel):
    """Tenant credentials for pack operations. All optional in the body —
    when blank the server falls back to ZSCALER_* environment variables,
    then to tenant_config.json next to this file. Either sign-in
    (tenant_auth): a ZIdentity API client, or the classic ZIA API's
    username, password and API key with auth_method="legacy"."""
    cloud: str = ""
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    auth_method: str = ""
    username: str = ""
    password: str = ""
    api_key: str = ""
    # Saved tenant profile: blanks above are filled from it (including a
    # remembered secret), so the operator can switch tenants without retyping.
    profile_id: str = ""
    # The assessor's name (Scope assessment). A pack deploy names only this
    # in the provenance tag it writes and in its deployment record; blank
    # falls back to the saved profile's assessor.
    assessor: str = ""


class DLPPackImportRequest(TenantCredsRequest):
    """Body of the single-pack import endpoint: tenant credentials, options and the reviewed plan hash."""
    use_rank_0: bool = False
    apply_tweaks: bool = True
    verify: bool = True
    plan_hash: str = ""   # the hash of the plan the caller reviewed; without it the endpoint only returns the plan


class DLPPackDeployRequest(TenantCredsRequest):
    """Body of preflight / apply / journey: the packs to deploy, options and channel choices."""
    pack_ids: List[str] = []
    use_rank_0: bool = False
    apply_tweaks: bool = True
    verify: bool = True
    # Converge mode: overwrite baseline objects the customer changed. Off by
    # default and never chosen for the user; the journey check reports them.
    restore_drift: bool = False
    # Per pack: which DLP channels to deploy into (web, endpoint, saas,
    # email). A pack not listed is deployed exactly as packed. A chosen
    # channel the pack has no rule for gets monitor-only extension rules
    # carrying the pack's engines, one disabled rule per engine on every
    # channel (Endpoint DLP on removable media); a deselected channel is
    # skipped.
    channel_targets: Dict[str, List[str]] = {}
    # Terraform hand-off only: "static" never reads the tenant (credentials
    # are ignored); "gap" needs them; "" decides by whether they are present.
    mode: str = ""
    # apply-only: the hash of the plan the user approved, plus explicit consent
    plan_hash: str = ""
    confirm: bool = False


class DeploymentUndoRequest(TenantCredsRequest):
    """Body of a deployment undo: tenant credentials and the confirmation flag."""
    confirm: bool = False


class PackRemovalRequest(TenantCredsRequest):
    """Body of a pack removal: which packs (or everything), the previewed plan hash, confirmation."""
    pack_ids: List[str] = []
    plan_hash: str = ""
    confirm: bool = False
    all: bool = False      # everything DLP-Check ever put in the tenant, not just the listed packs
    rules: List[Dict[str, Any]] = []   # pick mode: the rules ({channel, id}) to remove with their engines and dictionaries
    deployment_id: str = ""            # undo mode: what one recorded deployment created


def _writes_disabled_msg() -> str:
    """The read-only refusal, with the way to turn writes on where this
    server runs (container, Windows, Mac/Linux)."""
    from security import write_enable_hint
    return f"Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND. To turn them on, {write_enable_hint()}."


def _tenant_creds(req: Any) -> Dict[str, str]:
    """Resolve credentials: request body → saved profile → environment →
    tenant_config.json. Every key of tenant_auth.CRED_KEYS is present and
    `auth_method` is resolved. A source is used only while the credentials
    are still incomplete for their sign-in, and never mixes a typed
    identity with a stored secret."""
    creds = {k: str(getattr(req, k, "") or "").strip() for k in tenant_auth.CRED_KEYS}
    if not tenant_auth.started(creds):
        # Nothing typed for a tenant: the source that has the sign-in decides
        # its method (the form always sends its selector, OneAPI by default).
        creds["auth_method"] = ""
    creds = _fill_from_profile(creds, getattr(req, "profile_id", ""))
    if not tenant_auth.complete(creds):
        env = tenant_auth.from_env()
        if tenant_auth.complete(env):
            creds = tenant_auth.merge(tenant_auth.without_identity(creds), env)
    if not tenant_auth.complete(creds):
        cfg_path = os.path.join(_APP_DIR, "tenant_config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f) or {}
                if tenant_auth.complete(cfg):
                    creds = tenant_auth.merge(tenant_auth.without_identity(creds), cfg)
            except Exception:
                pass
    return tenant_auth.normalize(creds)


def _assessor(req: Any) -> str:
    """The assessor's name for a pack deploy: the request's, else the saved
    profile's, else blank (the tag then says DLP-Check). Sanitized as the
    tag carries it (pack_deploy.assessor_name: no brackets or line breaks,
    at most 40 bytes), so the deployment record names the same person."""
    import pack_deploy
    name = pack_deploy.assessor_name(getattr(req, "assessor", "") or "")
    if name:
        return name
    pid = getattr(req, "profile_id", "") or ""
    if pid:
        try:
            import tenant_profiles
            return pack_deploy.assessor_name((tenant_profiles.get(pid) or {}).get("assessor") or "")
        except Exception:  # noqa: BLE001 — a missing profile only loses the name
            return ""
    return ""


def _tenant_key(c: Dict[str, Any]) -> str:
    """The tenant's API client as zia_rate's opaque key (a hash): the rate
    state's key, and what a deployment record keeps so classic-API tenants
    on one cloud (one label, 'classic API (cloud)') stay apart."""
    import zia_rate
    c = tenant_auth.normalize(c)
    return zia_rate.key_for(c["cloud"], c["vanity_domain"] or c.get("username"), c["client_id"] or c.get("username"))


def _same_tenant(rec: Dict[str, Any], creds: Dict[str, Any]) -> bool:
    """Whether a deployment record was made in the tenant these credentials
    point at: its label (current or older form) and, when recorded, its
    opaque tenant key."""
    if rec.get("tenant_label") and rec["tenant_label"] not in tenant_auth.record_labels(creds):
        return False
    return not rec.get("tenant_key") or rec["tenant_key"] == _tenant_key(creds)


def _fill_from_profile(creds: Dict[str, str], profile_id: str) -> Dict[str, str]:
    """Fill blank credential fields from a saved tenant profile (the
    remembered secrets included). Typed values always win."""
    if not profile_id:
        return creds
    try:
        import tenant_profiles
        prof = tenant_profiles.get(profile_id, with_secret=True)
    except Exception:
        prof = None
    if not prof:
        return creds
    return tenant_auth.merge(creds, tenant_profiles.creds_from(prof))


def _validate_creds(creds: Dict[str, str]) -> Dict[str, str]:
    """Validate every field the sign-in uses (400 with the field's name
    otherwise) and return the checked dict. Nothing is echoed."""
    c = tenant_auth.normalize(creds)
    c["cloud"] = validate_cloud(c["cloud"] or "production")
    c["vanity_domain"] = validate_vanity(c["vanity_domain"])
    c["customer_id"] = validate_customer_id(c["customer_id"]) if c["customer_id"] else ""
    if c["auth_method"] == tenant_auth.LEGACY:
        for key in ("username", "password", "api_key"):
            c[key] = validate_credential(key, c[key], required=True)
    else:
        c["client_id"] = validate_credential("client_id", c["client_id"], required=True)
        c["client_secret"] = validate_credential("client_secret", c["client_secret"], required=True)
        if not c["vanity_domain"]:
            raise HTTPException(status_code=400, detail="vanity_domain is required for OneAPI authentication.")
    return c


def zscaler_clouds_legacy_host(cloud: str) -> str:
    """The classic ZIA API host for a cloud, for messages."""
    import zscaler_clouds
    try:
        return zscaler_clouds.legacy_api_base(cloud).replace("https://", "")
    except ValueError:
        return "zsapi.<cloud>.net"


def _oneapi_cloud(cloud: str) -> Optional[str]:
    """Map the GUI's cloud names onto the OneAPI `cloud` setting. Commercial
    production tenants must NOT send a cloud value (the SDK builds the
    Zidentity URL from the vanity domain alone); only beta and the
    FedRAMP clouds need one."""
    import zscaler_clouds
    try:
        return zscaler_clouds.environment(cloud)
    except ValueError:
        return None


# How long one request to the tenant may take, and how long the SDK may
# wait on a rate-limit answer before giving up (it then raises, and the
# shared execution path stops the run with the reason in words).
SDK_REQUEST_TIMEOUT = 90       # seconds per request, including the SDK's own retries
SDK_MAX_RETRIES = 2            # the SDK's retries on 429 / 503 / the portal's edit lock
SDK_MAX_RETRY_SECONDS = 30     # a Retry-After longer than this is not waited for


def _build_sdk_client(creds: Dict[str, str]):
    """Build an authenticated zscaler-sdk-python client (the object with
    `.zia.*` services the importer and planner require): the OneAPI client
    for a ZIdentity API client, the SDK's legacy ZIA client for the classic
    sign-in (tenant_auth). Validates every input and never echoes a secret
    in an error."""
    import zia_rate
    c = _validate_creds(creds)
    cloud, vd, cid, sec = c["cloud"], c["vanity_domain"], c["client_id"], c["client_secret"]
    # The tenant's API client, for ZIA's rate limits: its requests, holds and
    # refusals are counted apart from any other tenant's.
    rate_key = _tenant_key(c)
    # As the deployment log names the tenant (tenant_auth.record_label: never
    # the classic API's admin login or a stale vanity domain), then the
    # labels older records carry, so the rate forecast still counts them.
    rate_label = tenant_auth.record_labels(c)
    if c["auth_method"] == tenant_auth.LEGACY:
        try:
            return zia_rate.attach_client(tenant_auth.build_legacy_sdk_client(c, timeout=SDK_REQUEST_TIMEOUT), rate_key, rate_label)
        except ImportError:
            raise HTTPException(status_code=503, detail="zscaler-sdk-python is not installed. Run: pip install -r requirements.txt")
        except Exception as e:  # noqa: BLE001 — the helper signs in as it is built
            reason = tenant_auth.mask_secrets(str(e), c)[:200]
            raise HTTPException(status_code=401, detail=f"Authentication failed for {tenant_auth.identity(c)} on the classic ZIA API "
                                                        f"({zscaler_clouds_legacy_host(cloud)}): {reason}")
    try:
        from zscaler import ZscalerClient
    except ImportError:
        raise HTTPException(status_code=503, detail="zscaler-sdk-python is not installed. Run: pip install -r requirements.txt")
    config: Dict[str, Any] = {"clientId": cid, "clientSecret": sec, "vanityDomain": vd,
                              # Bounded waits: without these the SDK has no HTTP timeout at all
                              # and sleeps for as long as ZIA's Retry-After says (up to an hour
                              # on the hourly limit), which looks like a hang. Past the cap the
                              # SDK raises and pack_ops stops the run with the reason in words.
                              "requestTimeout": SDK_REQUEST_TIMEOUT,
                              "rateLimit": {"maxRetries": SDK_MAX_RETRIES, "maxRetrySeconds": SDK_MAX_RETRY_SECONDS}}
    oneapi_cloud = _oneapi_cloud(cloud)
    if oneapi_cloud:
        config["cloud"] = oneapi_cloud
    try:
        client = ZscalerClient(config)
        auth = getattr(client, "authenticate", None)
        if callable(auth):
            auth()
    except Exception as e:
        reason = str(e).replace(sec, mask_secret(sec))[:200]
        raise HTTPException(status_code=401, detail=f"Authentication failed for client_id={mask_secret(cid)}: {reason}")
    # Every ZIA answer on this client's session feeds the next preflight's rate-limit check.
    return zia_rate.attach_client(client, rate_key, rate_label)


def _keyed(client, fn, *args):
    """Run `fn` with the client's tenant key, so its waits and holds draw on
    that tenant's ZIA rate limits (a deploy or removal job thread)."""
    import pack_jobs
    import zia_rate
    key = zia_rate.key_of(client)
    job = pack_jobs.current()
    if job is not None:
        job.rate_key = key
    with zia_rate.using(key):
        return fn(*args)


def _actor(request: Request) -> Optional[str]:
    """Who asked for a deploy / removal / hand-off, for its audit entries:
    security.current_actor(request) once per-user identity provides it,
    None until then. Never fails the request."""
    fn = getattr(_security, "current_actor", None)
    if fn is None:
        return None
    try:
        who = fn(request)
    except Exception:  # noqa: BLE001
        return None
    return str(who)[:200] if who else None


def _as_actor(actor: Optional[str], fn, *args):
    """Run a synchronous deploy or removal with `actor` on its audit entries
    (a job carries its actor itself)."""
    import pack_ops
    with pack_ops.audit_scope(actor=actor):
        return fn(*args)


def _resolve_pack_ids(pack_ids: List[str]) -> List[Dict[str, Any]]:
    """Map requested ids onto discovered packs. Ids are only ever matched
    against the discovery list, so a request can't name an arbitrary path."""
    from dlp_importer import discover_packs
    known = {p["id"]: p for p in discover_packs()}
    unknown = [pid for pid in pack_ids if pid not in known]
    if unknown:
        raise HTTPException(status_code=404, detail=f"Unknown pack(s): {', '.join(unknown)}")
    return [{"id": pid, "dir": known[pid]["dir"]} for pid in pack_ids]


class PackFromTenantRequest(TenantCredsRequest):
    """Rebuild a pack from the tenant's own Anchor/Signal dictionaries."""
    name_filter: str = ""      # substring/regex the dictionary names must match ("" = every custom dictionary)
    prefix: str = "SRC-"       # engine name prefix
    threshold: int = 4         # Signal matches the engine needs (> N)
    html_threshold: int = 3
    confirm: bool = False      # False = preview only; True = write the pack's configs


def _regenerate_terraform(pack_id: str, pack_dir: str) -> str:
    """Keep the Terraform workspace in step with the rewritten pack: the
    committed terraform/<pack> for a shipped pack on a local install, or
    beside the pack (as for uploads) for a copy rebuilt in the library."""
    try:
        import pack_terraform
        files = pack_terraform.generate({"id": pack_id, "dir": pack_dir})
        shipped = os.path.realpath(os.path.dirname(pack_dir)) == os.path.realpath(_APP_DIR)
        out_dir = os.path.join(_APP_DIR, "terraform", pack_id) if shipped else os.path.join(pack_dir, "terraform")
        pack_terraform.write_workspace(files, out_dir)
        return "regenerated"
    except Exception as ex:  # noqa: BLE001
        return f"not regenerated ({str(ex)[:120]}); run: python pack_terraform.py {pack_id} --out terraform"


def _writable_pack_dir(pack_id: str, pack_dir: str) -> str:
    """The folder a rebuild may write: the pack's own, or, where that is
    read-only (the container's app folder), a copy of it in the pack
    library under the same id, made once."""
    configs = os.path.join(pack_dir, "configs")
    if os.access(configs if os.path.isdir(configs) else pack_dir, os.W_OK):
        return pack_dir
    import shutil
    from pack_library import user_packs_dir
    lib = user_packs_dir()
    dst = os.path.join(lib, pack_id)
    if not os.path.isdir(dst):
        os.makedirs(lib, exist_ok=True)
        shutil.copytree(pack_dir, dst, ignore=shutil.ignore_patterns("terraform", "__pycache__", "*.pyc"))
    return dst


@app.post("/api/dlp-packs/{pack_id}/from-tenant")
async def dlp_pack_from_tenant(pack_id: str, req: PackFromTenantRequest):
    """Pull the tenant's source-code dictionaries (an Anchor and a Signal
    per language, paired by name) and rebuild the pack from them: the
    dictionaries keep their tenant names, each language gets one engine
    ((Signal > N) AND (Anchor > 0)), the pack's rules reference the new
    engines and the old pack dictionaries/engines are dropped. Read-only
    against the tenant. Preview unless `confirm` is true; writing the pack
    on disk is allowed only while nobody but this computer can reach the
    server (a localhost bind, or the container published on loopback).
    Where the shipped pack's folder is read-only (the container), the
    rebuilt pack is written to the pack library under the same id and
    replaces the shipped one; removing it there restores the shipped pack."""
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", pack_id or ""):
        raise HTTPException(status_code=400, detail="Invalid pack id.")
    if req.confirm and not _security.only_this_computer_can_reach():
        raise HTTPException(status_code=403, detail="Rewriting a pack from the web UI is only allowed while nobody but this computer can reach the server "
                                                    "(bound to localhost, or the container published on this computer's loopback).")
    pack = _resolve_pack_ids([pack_id])[0]
    if req.confirm:
        pack = dict(pack, dir=await asyncio.to_thread(_writable_pack_dir, pack_id, pack["dir"]))
    import pack_from_tenant
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    res = await asyncio.to_thread(
        pack_from_tenant.rebuild_from_tenant, client, pack["dir"], name_filter=req.name_filter[:200], prefix=req.prefix[:40],
        threshold=max(0, min(999, req.threshold)), html_threshold=max(0, min(999, req.html_threshold)), dry_run=not req.confirm)
    if res.get("status") == "written":
        res["terraform"] = await asyncio.to_thread(_regenerate_terraform, pack_id, pack["dir"])
    return res


@app.post("/api/dlp-packs/preflight")
async def dlp_packs_preflight(req: DLPPackDeployRequest):
    """Plan a deployment of one or more packs WITHOUT writing anything.
    Cross-references the packs against each other and the live tenant:
    dependency resolution, conflicts, existing objects that would be
    reused rather than overwritten, rule-order and enforcement impact,
    and modifications to existing tenant objects. Returns a plan_hash
    that /apply requires, so approval is bound to exactly this plan."""
    try:
        import pack_deploy
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_deploy unavailable: {e}")
    if not req.pack_ids:
        raise HTTPException(status_code=400, detail="Select at least one pack.")
    packs = _resolve_pack_ids(req.pack_ids)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    report = await asyncio.to_thread(
        pack_deploy.preflight, client, packs,
        use_rank_0=req.use_rank_0, apply_tweaks=req.apply_tweaks, writes_enabled=writes_enabled(),
        restore_drift=req.restore_drift, channel_targets=req.channel_targets or None,
    )
    out = pack_deploy.public_report(report)
    out["writes_enabled"] = writes_enabled()
    out["tenant_label"] = tenant_auth.record_label(creds)
    return out


# ── FP/TP Detection Ratio (continuous evaluation, phase 1) ──────────────────
class DetectionHealthRequest(TenantCredsRequest):
    """Body of a FP/TP Detection Ratio run: the window in days and threshold overrides."""
    days: int = 30
    settings: Dict[str, Any] = {}     # threshold overrides, see detection_health.DEFAULTS


@app.post("/api/detection-health")
async def detection_health_generate(req: DetectionHealthRequest):
    """What the tenant's DLP rules actually do: Workflow Automation
    incidents and the analysts' verdicts become per-rule, engine,
    dictionary, channel and application metrics (false-positive rate,
    dead rules, promotable monitor rules, noisy dictionaries) plus how
    incidents reach Workflow Automation (cloud-to-cloud or an ICAP
    Incident Receiver). Read-only; carries report_id for
    /report/health?id=... and the exports."""
    try:
        import detection_health
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"detection_health unavailable: {e}")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    days = max(1, min(int(req.days or 30), 180))
    logs: list = []
    report = await asyncio.to_thread(lambda: detection_health.generate(client, days=days, settings=req.settings or None, log=logs.append))
    report["logs"] = logs
    report["tenant_key"] = creds.get("vanity_domain") or "unknown"
    report["profile_id"] = getattr(req, "profile_id", "") or ""   # lets the tab apply proposals with the profile's remembered secret
    try:
        import proposals
        report["proposals"] = proposals.refresh_from_report(report, report["tenant_key"])
    except Exception as e:  # noqa: BLE001
        report["proposals"] = {"error": str(e)[:200]}
    rid = _remember_report("health", report, tenant_auth.record_label(creds))
    return _REPORTS[rid]


# ── Live feed (continuous evaluation, live view) ───────────────────────
# What this genuinely shows live: Workflow Automation's own DLP incident
# stream, polled on a moving window. It is not every ZIA transaction —
# see the coverage note the endpoint always returns.
_LIVE_RULES_TTL_SECONDS = 90
_live_rules_cache: Dict[str, Any] = {}   # tenant key -> (expires_at, {rule name: action})
LIVE_FEED_COVERAGE_NOTE = (
    "This feed shows Workflow Automation's DLP-matched incidents only — the user, the rule and dictionaries that "
    "matched, and the destination, live as they land. It does not cover URL Filtering, Cloud App Control or "
    "Firewall & DNS Control decisions that never trip a DLP rule; that wider transaction log is Web Insights / "
    "Cloud NSS, a feed to your own log store (Splunk, S3, a syslog receiver) that this app does not read."
)


def _live_rule_actions(client, tenant_key: str) -> Dict[str, str]:
    """rule name -> configured action, cached briefly per tenant so a
    poll every few seconds does not re-read the whole rule inventory
    every time; rule actions do not change that often."""
    import time as _time
    import detection_health
    now = _time.time()
    cached = _live_rules_cache.get(tenant_key)
    if cached and cached[0] > now:
        return cached[1]
    m = detection_health.rule_actions(client)
    _live_rules_cache[tenant_key] = (now + _LIVE_RULES_TTL_SECONDS, m)
    return m


class LiveFeedRequest(TenantCredsRequest):
    """One poll of the live DLP incident feed. `since` is the ISO
    timestamp `next_since` from the previous poll (blank starts a new
    feed, looking back two minutes); `stats` is the running tally this
    endpoint returned last time, echoed back so the server stays
    stateless between polls."""
    since: str = ""
    stats: Dict[str, Any] = {}


@app.post("/api/live-feed")
async def live_feed_poll(req: LiveFeedRequest):
    """Workflow Automation DLP incidents created since the last poll,
    normalised, with a running session tally (seen, enforced vs
    monitor-only by the matched rule's real configured action, and the
    FP/TP split among the ones already closed) and a plain statement of
    what this feed does and does not cover. Read-only."""
    try:
        import detection_health
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"detection_health unavailable: {e}")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = tenant_auth.label(creds)
    since = None
    if req.since:
        try:
            since = datetime.fromisoformat(req.since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="'since' is not a valid timestamp; leave it blank to start a new feed.")
    poll = await asyncio.to_thread(detection_health.poll_incidents, client, since)
    rules_by_name = await asyncio.to_thread(_live_rule_actions, client, creds.get("vanity_domain") or label)
    for i in poll["incidents"]:
        i["enforcement"] = detection_health.incident_action(i, rules_by_name)   # "enforced" | "monitor" | "unknown", from the rule's real action
    stats = detection_health.live_stats(req.stats or None, poll["incidents"], rules_by_name)
    return {"incidents": poll["incidents"], "next_since": poll["next_since"], "errors": poll["errors"], "stats": stats,
            "tenant_label": label, "read_at": poll["read_at"], "coverage_note": LIVE_FEED_COVERAGE_NOTE}


# ── Proposals: the approval queue (continuous evaluation, phase 2) ────────
class ProposalDecision(BaseModel):
    """A person's decision on a continuous-evaluation proposal (approve, dismiss, snooze, reopen)."""
    decision: str            # approve | dismiss | snooze | reopen
    note: str = ""
    by: str = ""             # accepted from older pages but ignored: the server sets who decided (security.current_actor)
    days: int = 14           # snooze length
    confirm: str = ""        # the confirm phrase for approve_double gates


@app.get("/api/proposals")
async def proposals_list(tenant: str = "", include_closed: bool = False):
    """The queue for one tenant (vanity domain): open and approved
    proposals, or everything with include_closed."""
    import proposals
    if not tenant.strip():
        raise HTTPException(status_code=400, detail="tenant (vanity domain) is required")
    return {"tenant": proposals.tenant_key(tenant), "items": proposals.list_queue(tenant, include_closed=include_closed),
            "summary": proposals.summary(tenant), "confirm_phrase": proposals.CONFIRM_PHRASE, "dismiss_days": proposals.DISMISS_DAYS}


@app.get("/api/proposals/export")
async def proposals_export(tenant: str = "", format: str = "markdown"):
    """Download the proposal queue of one tenant as Markdown or JSON."""
    import proposals
    items = proposals.list_queue(tenant, include_closed=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if format == "json":
        return JSONResponse({"tenant": proposals.tenant_key(tenant), "items": items}, headers={"Content-Disposition": f'attachment; filename="proposals_{stamp}.json"'})
    return PlainTextResponse(proposals.to_markdown(proposals.tenant_key(tenant), items), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="proposals_{stamp}.md"'})


@app.post("/api/proposals/{tenant}/{pid}/decide")
async def proposals_decide(tenant: str, pid: str, req: ProposalDecision):
    """A person decides: approve (a double gate needs the confirm phrase),
    dismiss (remembered 30 days), snooze (days), reopen. Recorded in audit.log
    with who decided: the signed-in person (or "local UI token"), never a
    name the page sends."""
    import proposals
    by = (_security.current_actor() or "")[:80]
    try:
        out = proposals.decide(tenant, pid, req.decision, by=by, note=req.note[:500], days=req.days, confirm=req.confirm)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # A guidance proposal (new article mapped to checks) applies by recording
    # the article as a reference in checks_config.json: no tenant write.
    if req.decision == "approve" and out.get("applies_via") == "guidance":
        import guidance
        try:
            rec = guidance.record_approval(out, by=by)
            out = proposals.set_status(tenant, pid, "applied", by=by,
                                       note=f"reference recorded for {len(rec['checks'])} check(s) in checks_config.json; ships with the next app update") or out
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    return out


class ProposalApplyRequest(TenantCredsRequest):
    """Body for applying or rolling back a proposal: tenant credentials and confirmation."""
    by: str = ""             # accepted from older pages but ignored: the server sets who (security.current_actor)
    confirm: bool = False


def _proposal_client(req: ProposalApplyRequest):
    creds = _tenant_creds(req)
    if not (creds.get("client_id") and creds.get("client_secret")):
        raise HTTPException(status_code=400, detail="Tenant credentials are needed to touch the tenant: open FP/TP Detection Ratio from the assessment page (its credentials are used), or select a tenant profile that remembers its secret.")
    return _build_sdk_client(creds)


@app.post("/api/proposals/{tenant}/{pid}/preview")
async def proposals_preview(tenant: str, pid: str, req: ProposalApplyRequest, direction: str = "apply"):
    """Re-read the rules an approved proposal touches and show exactly what
    would change (or what a rollback would restore). Read-only."""
    import proposal_apply
    client = await asyncio.to_thread(_proposal_client, req)
    try:
        return await asyncio.to_thread(proposal_apply.preview, client, tenant, pid, direction="rollback" if direction == "rollback" else "apply")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/proposals/{tenant}/{pid}/apply")
async def proposals_apply(tenant: str, pid: str, req: ProposalApplyRequest):
    """Apply an approved proposal through the deploy path: write gate,
    re-read, update, read-back, recorded way back. Nothing is activated."""
    _security.require_writer()
    import proposal_apply
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Applying requires explicit confirmation (confirm=true).")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    client = await asyncio.to_thread(_proposal_client, req)
    logs: list = []
    by = (_security.current_actor() or "")[:80]
    try:
        out = await asyncio.to_thread(lambda: proposal_apply.apply(client, tenant, pid, writes_enabled=True, by=by, log=logs.append))
    except (ValueError, PermissionError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    out["logs"] = logs
    return out


@app.post("/api/proposals/{tenant}/{pid}/rollback")
async def proposals_rollback(tenant: str, pid: str, req: ProposalApplyRequest):
    """Put back the value the rule had before the proposal was applied,
    with the same re-read and read-back."""
    _security.require_writer()
    import proposal_apply
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Rolling back requires explicit confirmation (confirm=true).")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    client = await asyncio.to_thread(_proposal_client, req)
    logs: list = []
    by = (_security.current_actor() or "")[:80]
    try:
        out = await asyncio.to_thread(lambda: proposal_apply.rollback(client, tenant, pid, writes_enabled=True, by=by, log=logs.append))
    except (ValueError, PermissionError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    out["logs"] = logs
    return out


# ── Continuous evaluation, phases 4 and 5: digests, guidance sources, SaaS matrix ──
class DigestRunRequest(BaseModel):
    """Body for running the continuous evaluation once: whether to send notifications."""
    notify: bool = True


@app.get("/api/digests")
async def digests_list():
    """The digests the loop wrote (newest first), the schedule, the
    notification settings (no secrets) and the state of the watched sources."""
    import continuous_eval
    import guidance
    health = guidance.source_health()
    return {"digests": continuous_eval.list_digests(), "schedule": dict(_DH_REFRESH_STATE), "notifications": continuous_eval.notification_settings(),
            "sources": {"watched": sum(1 for h in health if h["watched"]), "stale": [h for h in health if h["stale"]]},
            "checks_config": guidance.config_summary(), "guidance_queue": __import__("proposals").summary(guidance.APP_TENANT)}


@app.post("/api/digests/run")
async def digests_run(req: DigestRunRequest):
    """Run the loop now (the same run the schedule makes)."""
    try:
        d = await asyncio.to_thread(_continuous_eval_once, req.notify)
    except Exception as e:  # noqa: BLE001
        _DH_REFRESH_STATE["last_status"] = "error"
        _DH_REFRESH_STATE["last_error"] = str(e)[:200]
        _DH_REFRESH_STATE["last_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        raise HTTPException(status_code=500, detail=f"the evaluation failed: {type(e).__name__}: {str(e)[:200]}")
    # The same bookkeeping the scheduled run does, so the Digest tab's
    # "Last run" and its status are right after a manual run too.
    _DH_REFRESH_STATE["last_status"] = "ok"
    _DH_REFRESH_STATE["last_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"ok": True, "digest": d}


@app.get("/api/digests/{digest_id}")
async def digests_get(digest_id: str, format: str = "json"):
    """One continuous-evaluation digest, as JSON or Markdown."""
    import continuous_eval
    d = continuous_eval.get_digest(digest_id)
    if not d:
        raise HTTPException(status_code=404, detail="digest not found")
    if format == "markdown":
        return PlainTextResponse(continuous_eval.to_markdown(d), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="digest-{digest_id}.md"'})
    return d


@app.get("/api/guidance/sources")
async def guidance_sources():
    """Every watched source with its tier, what it can affect, when it last answered and whether it is stale."""
    import guidance
    return {"sources": guidance.source_health(), "stale_days": guidance.STALE_DAYS, "topics": [{"id": t["id"], "label": t["label"]} for t in guidance.TOPICS]}


@app.get("/api/saas-apps")
async def saas_apps():
    """The SaaS tenant capability matrix (application, type, capabilities)."""
    import saas_matrix
    m = saas_matrix.load()
    return {k: m.get(k) for k in ("source", "updated_at", "refreshed_from_pages", "types", "applications", "path", "new_since_seed")}


@app.get("/report/digest")
async def report_digest_page():
    """The digest tab: what the loop found, the queue, the sources, the schedule (static/report_digest.html)."""
    page = os.path.join(STATIC_DIR, "report_digest.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/api/detection-health/schedule")
async def detection_health_schedule():
    """State of the 6-hour FP/TP Detection Ratio refresh for tenant profiles
    that remember their secret."""
    return dict(_DH_REFRESH_STATE)


@app.get("/api/detection-health/export/{report_id}")
async def detection_health_export(report_id: str, format: str = "markdown"):
    """Download a FP/TP Detection Ratio report (Markdown, JSON or Word) while it is still in memory."""
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("health-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    if format == "json":
        return JSONResponse(rep, headers={"Content-Disposition": f'attachment; filename="detection-health-{report_id}.json"'})
    from detection_health import to_markdown
    md = to_markdown(rep, rep.get("tenant_label", ""))
    return Response(md, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="detection-health-{report_id}.md"'})


@app.get("/api/detection-health/{report_id}")
async def detection_health_get(report_id: str):
    """One FP/TP Detection Ratio report, while it is still in memory."""
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("health-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.get("/report/health")
async def report_health_page():
    """Standalone tab for FP/TP Detection Ratio (static/report_health.html)."""
    page = os.path.join(STATIC_DIR, "report_health.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# Every 6 hours while this server process runs, for each tenant profile that
# remembers its secret, continuous_eval.run_once reads FP/TP Detection Ratio,
# the SaaS tenants and the packs' drift (never the assessment checks or the
# score) and writes a digest. Same cadence as the best-practices refresh;
# nothing is written to any tenant. The loop dies with the process: a
# schedule that must survive it is Task Scheduler / cron running
# continuous_eval.py --once.
_DH_REFRESH_INTERVAL_SECONDS = 6 * 3600
_DH_REFRESH_STATE: Dict[str, Any] = {"enabled": True, "interval_seconds": _DH_REFRESH_INTERVAL_SECONDS, "last_run_at": None,
                                     "next_run_at": None, "last_status": None, "profiles": {},
                                     "runs_while": "this server process is running"}


def _continuous_eval_once(notify: bool = True) -> Dict[str, Any]:
    """One run of the continuous evaluation (guidance, FP/TP Detection Ratio,
    SaaS tenants, drift, digest, notifications). Keeps the per-profile
    state the FP/TP Detection Ratio tab shows."""
    import continuous_eval
    d = continuous_eval.run_once(build_client=_build_sdk_client, notify=notify)
    for t in d.get("tenants") or []:
        dh = t.get("detection_health") or {}
        _DH_REFRESH_STATE["profiles"][t["profile_id"]] = {"at": d.get("at"), "status": "error" if t.get("errors") else "ok",
                                                          "incidents": dh.get("incidents"), "errors": len(t.get("errors") or []),
                                                          "error": "; ".join(t.get("errors") or [])[:200] or None}
    _DH_REFRESH_STATE["last_digest"] = d.get("id")
    _DH_REFRESH_STATE["last_noteworthy"] = d.get("noteworthy")
    return d


async def _dh_auto_refresh_loop() -> None:
    await asyncio.sleep(30)
    while _DH_REFRESH_STATE.get("enabled", True):
        try:
            await asyncio.to_thread(_continuous_eval_once)
            _DH_REFRESH_STATE["last_status"] = "ok"
        except Exception as e:  # noqa: BLE001
            _DH_REFRESH_STATE["last_status"] = "error"
            _DH_REFRESH_STATE["last_error"] = str(e)[:200]
        _DH_REFRESH_STATE["last_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _DH_REFRESH_STATE["next_run_at"] = time.time() + _DH_REFRESH_INTERVAL_SECONDS
        try:
            await asyncio.sleep(_DH_REFRESH_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            break


@app.on_event("startup")
async def _start_dh_refresh() -> None:
    try:
        import detection_health  # noqa: F401
        import tenant_profiles  # noqa: F401
        asyncio.create_task(_dh_auto_refresh_loop())
    except Exception:
        _DH_REFRESH_STATE["enabled"] = False
        _DH_REFRESH_STATE["last_status"] = "disabled"


def _deployment_for_removal(req: "PackRemovalRequest", creds: Dict[str, str]) -> Dict[str, Any]:
    """The recorded deployment a removal names, checked against the tenant
    the credentials point at."""
    import deployments
    rec = deployments.get(req.deployment_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Deployment not found.")
    label = tenant_auth.record_label(creds)
    if not _same_tenant(rec, creds):
        where = rec.get("tenant_label") or "another tenant"
        if where == label:
            where = f"another {label} tenant"
        raise HTTPException(status_code=409, detail=f"This deployment was made in {where}, but the current credentials are for {label}. Switch tenant first.")
    return rec


class RateCheckRequest(TenantCredsRequest):
    """A write about to be sent: how many requests of each ZIA rate-limit
    bucket (write, delete, endpoint_rules, cloud_app, activate)."""
    counts: Dict[str, int] = {}
    profile_id: str = ""


@app.post("/api/rate-check")
async def rate_check(req: RateCheckRequest):
    """Will these requests succeed at ZIA's rate limits for this tenant?
    The same check as the preflight's, for any deploy or delete: the
    verdict, the API plan and the tenant's track record. Reads only the
    app's own record; nothing is sent to ZIA."""
    import zia_rate
    key, label = "", None
    try:
        c = _validate_creds(_tenant_creds(req))
        key = _tenant_key(c)
        label = tenant_auth.record_labels(c)
    except HTTPException:
        pass   # no tenant to tell apart: the unkeyed record still applies
    counts = {k: max(0, min(int(v or 0), 5000)) for k, v in (req.counts or {}).items() if k in zia_rate.DEFAULTS and k != "read"}
    f = await asyncio.to_thread(zia_rate.forecast, counts, key=key, tenant_label=label)
    f["detail"] = zia_rate.history_text(f)
    return f


@app.post("/api/dlp-packs/removal/preflight")
async def dlp_pack_removal_preflight(req: PackRemovalRequest):
    """Find what a deployed pack or baseline put into the tenant — by its
    DLP-Check provenance tag and by the names it defines — and preview a
    methodical removal: rules, then endpoint application groups, then
    engines, then dictionaries. Objects a surviving rule or engine still
    uses, and every predefined dictionary, are kept and reported. Returns
    a plan_hash the apply step must echo. Read-only."""
    try:
        import pack_removal
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_removal unavailable: {e}")
    if not req.pack_ids and not req.rules and not req.deployment_id:
        raise HTTPException(status_code=400, detail="Select at least one pack, pick the rules, or name the deployment to remove.")
    packs = _resolve_pack_ids(req.pack_ids) if req.pack_ids else []
    creds = _tenant_creds(req)
    rec = _deployment_for_removal(req, creds) if req.deployment_id else None
    client = await asyncio.to_thread(_build_sdk_client, creds)
    if rec is not None:
        out = await asyncio.to_thread(lambda: pack_removal.plan_removal_deployment(client, rec))
    elif req.rules:
        out = await asyncio.to_thread(lambda: pack_removal.plan_removal_selected(client, req.rules))
    else:
        out = await asyncio.to_thread(lambda: pack_removal.plan_removal(client, packs, everything=bool(req.all)))
    out["writes_enabled"] = writes_enabled()
    out["tenant_label"] = tenant_auth.record_label(creds)
    return out


@app.post("/api/dlp-packs/removal/inventory")
async def dlp_pack_removal_inventory(req: TenantCredsRequest):
    """Every DLP rule the tenant has on every channel (web, endpoint, SaaS,
    email) with its state, engines and DLP-Check provenance, so the
    operator can pick the leftovers to remove. Read-only."""
    try:
        import pack_removal
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_removal unavailable: {e}")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(pack_removal.inventory, client)
    out["writes_enabled"] = writes_enabled()
    out["tenant_label"] = tenant_auth.record_label(creds)
    return out


@app.post("/api/dlp-packs/removal/apply")
async def dlp_pack_removal_apply(req: PackRemovalRequest, request: Request):
    """Remove what the preflight found, in reverse dependency order. Needs
    write mode, confirm=true and the plan_hash from a matching preflight;
    if the tenant changed since the preview the removal is refused as
    stale. Activates, waits for ZIA to report ACTIVE, then re-reads the
    tenant: `verification` says whether anything of the pack(s) is still
    there. Several pack_ids remove every selected pack in one pass."""
    _security.require_writer()
    try:
        import pack_removal  # noqa: F401 — availability check; the run is in _run_removal
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_removal unavailable: {e}")
    if not req.pack_ids and not req.rules and not req.deployment_id:
        raise HTTPException(status_code=400, detail="Select at least one pack, pick the rules, or name the deployment to remove.")
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Removal requires explicit confirmation (confirm=true).")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    packs = _resolve_pack_ids(req.pack_ids) if req.pack_ids else []
    creds = _tenant_creds(req)
    rec = _deployment_for_removal(req, creds) if req.deployment_id else None
    client = await asyncio.to_thread(_build_sdk_client, creds)
    result = await asyncio.to_thread(_as_actor, _actor(request), _run_removal, client, req, rec, packs, None, None)
    if result.get("status") == "blocked":
        raise HTTPException(status_code=403, detail="; ".join(result.get("blockers") or ["Removal blocked."]))
    if result.get("status") == "stale":
        raise HTTPException(status_code=409, detail="; ".join(result.get("blockers") or ["The removal plan is stale; run the preview again."]))
    return result


def _run_removal(client, req: PackRemovalRequest, rec, packs, log, cancel) -> Dict[str, Any]:
    """The removal itself, shared by the request that waits for it and the
    background job the browser follows. Blocked and stale plans come back
    as results (status `blocked` / `stale` with `blockers`), not errors."""
    import pack_removal
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    if rec is not None:
        result = pack_removal.remove_deployment(client, rec, plan_hash=req.plan_hash, writes_enabled=True, log=_log, cancel=cancel)
        if result.get("status") not in ("blocked", "stale"):
            import deployments
            updated = deployments.mark_undo(rec["id"], result.get("results") or [], complete=bool((result.get("verification") or {}).get("clean")))
            result["deployment"] = deployments.summary(updated) if updated else None
    elif req.rules:
        result = pack_removal.remove_selected(client, req.rules, plan_hash=req.plan_hash, writes_enabled=True, log=_log, cancel=cancel)
    else:
        result = pack_removal.remove(client, packs, plan_hash=req.plan_hash, writes_enabled=True, log=_log, cancel=cancel, everything=bool(req.all))
    result["logs"] = logs
    if result.get("status") in ("blocked", "stale"):
        result["message"] = "; ".join(result.get("blockers") or [
            "Removal blocked." if result["status"] == "blocked" else "The removal plan is stale; run the preview again."])
    return result


@app.post("/api/dlp-packs/removal/apply/start")
async def dlp_pack_removal_apply_start(req: PackRemovalRequest, request: Request):
    """Start the same removal as /removal/apply as a background job and
    return its id at once. Poll GET /api/dlp-packs/jobs/{job_id} for the
    log as it is written and the result when it finishes; POST
    /api/dlp-packs/jobs/{job_id}/cancel stops the remaining deletes."""
    _security.require_writer()
    import pack_jobs
    if not req.pack_ids and not req.rules and not req.deployment_id:
        raise HTTPException(status_code=400, detail="Select at least one pack, pick the rules, or name the deployment to remove.")
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Removal requires explicit confirmation (confirm=true).")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    packs = _resolve_pack_ids(req.pack_ids) if req.pack_ids else []
    creds = _tenant_creds(req)
    rec = _deployment_for_removal(req, creds) if req.deployment_id else None
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = "undo " + rec["id"] if rec else ("everything" if req.all else ", ".join(req.pack_ids) or f"{len(req.rules)} rule(s)")
    job = pack_jobs.start("removal", lambda log, cancel: _keyed(client, _run_removal, client, req, rec, packs, log, cancel), label=label,
                           actor=_actor(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/dlp-packs/jobs/{job_id}")
async def dlp_pack_job(job_id: str, since: int = 0):
    """A running or finished deploy / removal job: its status, elapsed
    seconds, the log lines from `since` on (and `next`, the index to ask
    for next time) and, once finished, the same result the request-and-
    wait endpoint would have returned."""
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job. Jobs are kept for an hour after they finish; start the run again.")
    return pack_jobs.snapshot(job, since=max(0, int(since or 0)))


@app.post("/api/dlp-packs/jobs/{job_id}/cancel")
async def dlp_pack_job_cancel(job_id: str):
    """Stop a running job after the write in flight. Nothing more is sent
    to the tenant; activation and the read-back still run so what was
    written is live and recorded."""
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")
    return {"job_id": job.id, "cancelled": pack_jobs.cancel(job_id), "status": job.status}


def _explain_connection_error(detail: str, method: str = "oneapi") -> Dict[str, Any]:
    """Turn an auth/network failure into a plain-language cause and fix,
    worded for the sign-in in use (tenant_auth: oneapi or legacy)."""
    d = str(detail or "")
    low = d.lower()
    legacy = method == tenant_auth.LEGACY
    import re as _re
    # A 403 and a 429 look alike in a log and call for opposite fixes, so
    # each is named by its number first. "Resource Access Blocked" is a 403
    # ZIA gives when the client is blocked, not a rate limit.
    if _re.search(r"\b429\b", low) or "too many requests" in low or "rate limit" in low:
        cause = "HTTP 429 — ZIA is rate-limiting this API client (too many requests in the window). The credentials and permissions are not the problem."
        fix = ("Wait a minute and click Authenticate again. If it keeps happening, another tool or a running assessment is using this "
               "API client's request budget: let it finish, or give this app its own API client.")
    elif "resource access blocked" in low:
        cause = ("HTTP 403 — ZIA blocked the API client's access (Resource Access Blocked). Not a rate limit: either the client's admin "
                 "role lost access to DLP dictionaries, engines or rules, or ZIA blocked the client after a burst of refused requests.")
        fix = ("Wait a few minutes and click Authenticate again. If it still fails, check the client's role in ZIA Administration > "
               "Role Management: DLP Dictionaries & Engines and DLP Policy must be readable (and writable, to deploy packs).")
    elif legacy and ("401" in low or "unauthorized" in low or "authentication failed" in low or "auth_failed" in low or "invalid" in low and "credential" in low):
        cause = "Zscaler rejected the admin username, password or API key."
        fix = ("Check the username (the admin's sign-in email) and password against the ZIA Admin Portal, and copy the API key from "
               "Administration > API Key Management (12 characters; it must be the key of this tenant). The admin must be allowed to "
               "sign in through the API. If the tenant has moved to ZIdentity, use the OneAPI sign-in instead.")
    elif legacy and ("403" in low or "forbidden" in low):
        cause = "HTTP 403 — the admin signed in but is not allowed to read this tenant's DLP configuration (a permission, not a rate limit)."
        fix = "In ZIA Administration > Role Management, give the admin's role read (and, to deploy packs, write) access to DLP policy, dictionaries and engines."
    elif legacy and ("tunnel connection failed" in low or "proxyerror" in low or "max retries" in low or "name resolution" in low or "nodename" in low):
        cause = "This machine could not reach the classic ZIA API at all (network, proxy or DNS)."
        fix = ("The classic API lives at zsapi.<cloud>.net (zsapi.zscalerten.net for a tenant on zscalerten.net): pick the tenant's actual "
               "cloud in the Zscaler Cloud field, allow outbound HTTPS to it, and set HTTPS_PROXY if you are behind a corporate proxy.")
    elif "invalid_client" in low or "401" in low or "unauthorized" in low or "authentication failed" in low and "connect" not in low:
        cause = "Zscaler rejected the client ID or client secret."
        fix = ("Check the client ID for typos. The secret is shown only once when the API client is created; if you copied it later, "
               "generate a new secret in ZIdentity > Integration > API Clients and paste it fresh.")
    elif "certificate" in low or "ssl" in low or "tls" in low:
        tls = _tls_status()
        cause = "The connection to Zscaler was intercepted by TLS inspection (usually Zscaler Client Connector or a proxy on this machine)."
        fix = ("Export your organisation's root CA certificate as a .pem file, then put "
               "set REQUESTS_CA_BUNDLE=C:\\path\\to\\root-ca.pem in local_settings.bat next to the app (copy local_settings.bat.example; "
               "it is git-ignored, so it survives updates and fresh clones) and restart the server. "
               + ("A CA bundle is configured but the file does not exist: " + tls["ca_bundle"] if tls["ca_bundle"] and not tls["ca_bundle_exists"]
                  else ("No CA bundle is configured right now." if not tls["ca_bundle"] else "")))
    elif "tunnel connection failed" in low or "proxyerror" in low or "max retries" in low or "name resolution" in low or "nodename" in low:
        cause = "This machine could not reach Zscaler's login service at all (network, proxy or DNS)."
        fix = ("Confirm the vanity domain is the short name from your login URL (acme for acme.zslogin.net). "
               "If you are behind a corporate proxy, set HTTPS_PROXY in START_Zscaler_Assessment.bat. "
               "Check that outbound HTTPS to *.zslogin.net and api.zsapi.net is allowed.")
    elif "vanity" in low:
        cause = "The vanity domain is not valid."
        fix = "Enter only the short name that appears before .zslogin.net in your admin login URL, for example acme."
    elif "403" in low or "forbidden" in low or "scope" in low:
        cause = "HTTP 403 — the credentials are valid but the API client is not allowed to read this tenant (a permission, not a rate limit)."
        fix = ("In ZIdentity, open the API client and make sure a ZIA API resource and a role with read access to DLP "
               "dictionaries, engines and rules are assigned.")
    else:
        cause = "The connection failed."
        fix = ("Re-check the cloud, admin username, password and API key at the top of the page, then try again." if legacy
               else "Re-check cloud, vanity domain, client ID and client secret at the top of the page, then try again.")
    return {"cause": cause, "fix": fix, "raw": d[:300]}


@app.post("/api/tenant/check")
async def tenant_check(req: TenantCredsRequest):
    """Read-only connection test for the Start-here panel: authenticates,
    counts DLP dictionaries, engines and the Web, Endpoint, SaaS and Email
    DLP rules, and explains any
    failure in plain language with what to do next."""
    creds = _tenant_creds(req)
    label = tenant_auth.label(creds)
    method = creds["auth_method"]
    try:
        client = await asyncio.to_thread(_build_sdk_client, creds)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail={"tenant_label": label, "auth_method": method, **_explain_connection_error(e.detail, method)})

    def probe() -> Dict[str, Any]:
        from pack_channels import _nx
        z = client.zia
        out: Dict[str, Any] = {"ok": True, "tenant_label": label, "auth_method": method, "problems": []}
        if method == tenant_auth.LEGACY:
            out["problems"].append("Signed in through the classic ZIA API: ZIA only. ZPA, Client Connector and ZDX checks need a ZIdentity API client.")
        dicts, err = _nx(z.dlp_dictionary.list_dicts())
        if err:
            raise RuntimeError(str(err))
        items = list(dicts or [])
        custom = sum(1 for d in items if getattr(d, "custom", False) or (isinstance(d, dict) and d.get("custom")))
        out["dictionaries"] = len(items)
        out["custom_dictionaries"] = custom
        out["predefined_dictionaries"] = len(items) - custom
        engines, err = _nx(z.dlp_engine.list_dlp_engines_lite())
        out["engines"] = 0 if err else len(engines or [])
        if err:
            out["problems"].append("DLP engines could not be listed; the role may lack engine read access.")
        rules, err = _nx(z.dlp_web_rules.list_rules())
        out["web_rules"] = 0 if err else len(rules or [])
        if err:
            out["problems"].append("Web DLP rules could not be listed; the role may lack DLP policy read access.")
        # The other DLP channels, so the operator sees the whole DLP policy
        # before deploying into it. None = could not be read (said in problems).
        import pack_channels as pc
        for ch, key, name in ((pc.ENDPOINT, "endpoint_rules", "Endpoint DLP"), (pc.SAAS, "saas_rules", "SaaS Security API DLP"),
                              (pc.EMAIL, "email_rules", "Email DLP")):
            n, cerr = pc.count_rules(z, ch)
            out[key] = n
            if cerr:
                out["problems"].append(f"{name} rules could not be listed; the role may lack read access to them or the tenant has no subscription for them.")
        return out

    try:
        return await asyncio.to_thread(probe)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"tenant_label": label, "auth_method": method,
                                                     **_explain_connection_error(tenant_auth.mask_secrets(str(e), creds), method)})


# ---------------------------------------------------------------------------
# Write mode (Deploy Studio switch)
# ---------------------------------------------------------------------------

class WriteModeRequest(BaseModel):
    """Body of the write-mode toggle: enable or disable, with the confirmation phrase."""
    enable: bool = True
    confirm: str = ""


@app.get("/api/write-mode")
async def write_mode_get():
    """Whether deploys are allowed right now, where that comes from
    (environment, this session, or the read-only default), and whether
    the operator may switch it from the browser (localhost binds only)."""
    from security import write_mode_status
    return write_mode_status()


@app.post("/api/write-mode")
async def write_mode_set(req: WriteModeRequest):
    """Switch write mode for this server process. Enabling needs the typed
    confirmation phrase and a localhost bind; the setting is not persisted."""
    from security import set_write_mode
    if req.enable:
        _security.require_writer()
    try:
        out = set_write_mode(req.enable, req.confirm)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
    print(f"[write-mode] {'ENABLED' if out['enabled'] else 'disabled'} from the GUI ({out['source']})")
    return out


# ---------------------------------------------------------------------------
# Tenant profiles
# ---------------------------------------------------------------------------

@app.get("/api/tenant-profiles")
async def tenant_profiles_list():
    """Saved tenant profiles (secrets never returned; has_secret says
    whether one is remembered) with each tenant's last assessment."""
    import tenant_profiles
    return {"profiles": tenant_profiles.list_profiles(), "store": os.path.basename(tenant_profiles.store_path())}


@app.get("/api/vertical-scope")
async def vertical_scope(profile_id: str = "", industry: str = ""):
    """What the profile's industry (or an industry name) narrows the app to:
    the compliance frameworks to show, the policy packs to measure and
    offer first, and why. Nothing is hidden for good; the operator can
    widen it."""
    import vertical
    from compliance_mapping import FRAMEWORK_DESCRIPTIONS
    from dlp_importer import discover_packs
    profile = None
    if profile_id:
        import tenant_profiles
        profile = tenant_profiles.get(profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail=f"No tenant profile '{profile_id}'.")
    if industry:
        profile = dict(profile or {}, industry=industry)
    packs = discover_packs()
    scope = vertical.scope_for(profile, all_frameworks=list(FRAMEWORK_DESCRIPTIONS), all_packs=[p["id"] for p in packs])
    names = {p["id"]: p.get("name") or p["id"] for p in packs}
    scope["pack_names"] = [names.get(pid, pid) for pid in scope["packs"]]
    # The industry's own packs, whatever the profile ticked: what the form
    # falls back to when every pack is unticked again.
    scope["industry_packs"] = [pid for pid in (vertical.INDUSTRY_PACKS.get(scope["industry"]) or []) if pid in names]
    scope["industries"] = vertical.INDUSTRIES
    return scope


@app.get("/api/tenant-profiles/{profile_id}")
async def tenant_profile_get(profile_id: str):
    """One saved tenant profile (secrets never returned)."""
    import tenant_profiles
    p = tenant_profiles.get(profile_id)
    if not p:
        raise HTTPException(status_code=404, detail=f"No tenant profile '{profile_id}'.")
    return p


@app.post("/api/tenant-profiles")
async def tenant_profile_save(req: TenantProfileRequest):
    """Create or update a profile. The secret is stored only with
    remember_secret=true (owner-only local file); a blank secret keeps the
    one already remembered, remember_secret=false forgets it."""
    import tenant_profiles
    if not (req.name or req.org_name or req.vanity_domain):
        raise HTTPException(status_code=400, detail="A profile needs at least a name, an organisation or a vanity domain.")
    cloud = validate_cloud(req.cloud or "production")
    vd = validate_vanity(req.vanity_domain) if req.vanity_domain else ""
    cid = validate_credential("client_id", req.client_id, required=False) if req.client_id else ""
    sec = validate_credential("client_secret", req.client_secret, required=False) if req.client_secret else ""
    cust = validate_customer_id(req.customer_id) if req.customer_id else ""
    try:
        method = tenant_auth.normalize_method(req.auth_method)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    user = validate_credential("username", req.username, required=False) if req.username else ""
    password = validate_credential("password", req.password, required=False) if req.password else ""
    api_key = validate_credential("api_key", req.api_key, required=False) if req.api_key else ""
    if not method:
        method = tenant_auth.method_of({"client_id": cid, "username": user, "api_key": api_key})
    fields = {
        "name": req.name or req.org_name or vd or user, "org_name": req.org_name, "assessor": req.assessor,
        "cloud": cloud, "vanity_domain": vd, "client_id": cid, "customer_id": cust,
        "auth_method": method, "username": user,
        "industry": req.industry, "baseline_packs": [str(b) for b in req.baseline_packs],
        "scopes": [str(x) for x in req.scopes], "frameworks": [str(x) for x in req.frameworks], "notes": req.notes[:2000],
        "channels": __import__("channel_scope").normalize(req.channels),
    }
    return tenant_profiles.upsert(fields, client_secret=sec, password=password, api_key=api_key,
                                  remember_secret=req.remember_secret, profile_id=req.id)


@app.delete("/api/tenant-profiles/{profile_id}")
async def tenant_profile_delete(profile_id: str):
    """Delete a saved tenant profile."""
    import tenant_profiles
    if not tenant_profiles.delete(profile_id):
        raise HTTPException(status_code=404, detail=f"No tenant profile '{profile_id}'.")
    return {"deleted": profile_id}


def _journey_packs(pack_ids: List[str]) -> List[Dict[str, Any]]:
    import pack_deploy
    from dlp_importer import discover_packs
    if pack_ids:
        return _resolve_pack_ids(pack_ids)
    return [{"id": p["id"], "dir": p["dir"]} for p in discover_packs() if pack_deploy.baseline_meta(p, p["id"])]


def _journey_for(client, packs: List[Dict[str, Any]], use_rank_0: bool = False,
                 channel_targets: Optional[Dict[str, List[str]]] = None,
                 progress: Optional[Any] = None) -> Dict[str, Any]:
    """Read-only journey check: one preflight per policy pack (so each
    pack is measured on its own), rolled up with pack_deploy.journey.
    `channel_targets` measures the pack as the operator chose to deploy
    it (extension rules count, skipped channels do not). The tenant is
    read once for every pack (superset of their needs); `progress(i, n,
    pack_id)` is called before each pack is measured."""
    import pack_deploy
    import pack_channels as pc
    rows: List[Dict[str, Any]] = []
    tenant = None
    blockers: List[str] = []
    cache: Dict[str, Any] = {}
    try:
        merged = pack_deploy.merge_sources(pack_deploy.load_sources(packs, {}))
        cache["need"] = pc.needs(i["definition"] for i in merged["policy"].values())
    except Exception:  # noqa: BLE001 — fall back to per-pack needs
        cache = {}
    for i, pk in enumerate(packs):
        if progress is not None:
            try:
                progress(i, len(packs), pk["id"])
            except Exception:  # noqa: BLE001
                pass
        ct = {pk["id"]: (channel_targets or {})[pk["id"]]} if (channel_targets or {}).get(pk["id"]) is not None else None
        rep = pack_deploy.preflight(client, [pk], use_rank_0=use_rank_0, apply_tweaks=False, writes_enabled=None, channel_targets=ct,
                                    tenant_cache=cache)
        j = pack_deploy.journey(rep)
        rows.extend(j["baselines"])
        tenant = j.get("tenant") or tenant
        blockers.extend(j.get("blockers") or [])
    combined = {"baselines": rows, "tenant": tenant, "blockers": blockers,
                "tenant_mode": None, "plan_hash": "", "elapsed_seconds": None}
    out = pack_deploy.journey(combined)
    out["blockers"] = blockers
    return out


@app.post("/api/dlp-packs/journey")
@app.post("/api/dlp-packs/baseline-status")   # older name, same answer
async def dlp_packs_journey(req: DLPPackDeployRequest):
    """Where is this tenant on the data-governance journey? For every
    policy pack (or the ones in pack_ids), every object is placed as
    missing / deployed / monitoring / enforcing / customized / relaxed /
    blocked, the stage ladder (Foundation → Policies deployed →
    Visibility → Containment → Enforcement) is evaluated and the concrete
    next steps are listed. Read-only: nothing is written and the write
    gate is not needed."""
    try:
        import pack_deploy  # noqa: F401
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_deploy unavailable: {e}")
    pack_ids = list(req.pack_ids)
    if not pack_ids and req.profile_id:
        try:
            import tenant_profiles
            pack_ids = list((tenant_profiles.get(req.profile_id) or {}).get("baseline_packs") or [])
        except Exception:
            pack_ids = []
    packs = _journey_packs(pack_ids)
    if not packs:
        raise HTTPException(status_code=404, detail="No policy packs found (pack.json needs a \"policy pack\" section).")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(_journey_for, client, packs, req.use_rank_0, req.channel_targets or None)
    out["tenant_label"] = tenant_auth.record_label(creds)
    return out


@app.get("/api/dlp-packs/{pack_id}/terraform")
async def dlp_pack_terraform_summary(pack_id: str):
    """What the Terraform hand-off for one pack contains: the files of the
    committed workspace (terraform/<pack>/, validated in CI), their
    purpose, resource counts and the README. Read-only."""
    packs = {p["id"]: p for p in __import__("dlp_importer").discover_packs()}
    if pack_id not in packs:
        raise HTTPException(status_code=404, detail=f"Unknown pack '{pack_id}'.")
    import pack_terraform
    purpose = {
        "terraform.tf": "Terraform and provider version pins (zscaler/zia ~> 4.8), optional remote backend.",
        "providers.tf": "Provider block; credentials come from variables or ZSCALER_* environment variables.",
        "variables.tf": "Inputs: credentials, rule starting order, admin rank, activation, tenant ids per channel; typed, described, validated.",
        "locals.tf": "The managed dictionaries, engines and rules as lists (the outputs read them).",
        "terraform.tfvars.example": "Copy to terraform.tfvars and fill in (git-ignored).",
        "dictionaries.tf": "DLP dictionaries (custom ones as resources, predefined ones as data lookups).",
        "engines.tf": "DLP engines with their expressions referencing the dictionaries above.",
        "rules.tf": "Every rule of the pack: Web/Endpoint/SaaS/Email DLP and the containment rules.",
        "imports.tf": "Gap mode only: import blocks adopting objects that already exist in the tenant.",
        "activation.tf": "Activates the pending ZIA configuration after apply.",
        "outputs.tf": "IDs and names of everything created, each output described.",
        "README.md": "Requirements, inputs, outputs, state and lock file, how to verify and review, gap summary.",
        ".gitignore": "Keeps state, tfvars and .terraform/ out of git.",
        ".terraform.lock.hcl": "Provider checksum lock (committed).",
    }
    tf_dir = os.path.join(_APP_DIR, "terraform", pack_id)
    files = []
    readme = ""
    if os.path.isdir(tf_dir):
        for name in sorted(os.listdir(tf_dir)):
            path = os.path.join(tf_dir, name)
            if os.path.isfile(path):
                files.append({"name": name, "bytes": os.path.getsize(path), "purpose": purpose.get(name, "")})
        rp = os.path.join(tf_dir, "README.md")
        if os.path.exists(rp):
            readme = open(rp, encoding="utf-8").read()
    src = pack_terraform.load_pack({"id": pack_id, "dir": packs[pack_id]["dir"]})
    channels: Dict[str, int] = {}
    for pol in src["policies"]:
        ch = str(pol.get("channel") or "web").lower()
        channels[ch] = channels.get(ch, 0) + 1
    return {
        "pack_id": pack_id, "name": packs[pack_id].get("name", pack_id), "baseline": bool(packs[pack_id].get("baseline")),
        "committed": bool(files), "path": f"terraform/{pack_id}/", "files": files, "readme": readme,
        "provider": pack_terraform.PROVIDER_SOURCE, "provider_version": pack_terraform.PROVIDER_VERSION,
        "terraform_version": pack_terraform.TERRAFORM_VERSION,
        "counts": {"dictionaries": len(src["dictionaries"]), "engines": len(src["engines"]), "rules": len(src["policies"]),
                   "app_groups": len(src.get("app_groups") or []), "channels": channels},
    }


@app.post("/api/dlp-packs/terraform")
async def dlp_packs_terraform(req: DLPPackDeployRequest):
    """Download a Terraform workspace (zip, one folder per pack) for the
    official zscaler/zia provider. With tenant credentials the workspace is
    generated in GAP mode: a preflight runs first and every object that
    already exists gets an import block, so the first `terraform plan`
    shows exactly what closes the gap. Without credentials (empty
    client_id) the workspace is static. Read-only — nothing is written."""
    try:
        import pack_deploy  # noqa: F401 — availability check; the run is in _run_terraform
        import pack_terraform  # noqa: F401
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_terraform unavailable: {e}")
    if not req.pack_ids:
        raise HTTPException(status_code=400, detail="Select at least one pack.")
    packs = _resolve_pack_ids(req.pack_ids)
    creds, client = await _terraform_client(req)
    result = await asyncio.to_thread(_run_terraform, client, creds, req, packs, None, None)
    name, media, data = result["artifact"]
    return Response(content=data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "X-DLP-Check-Mode": result["mode"]})


async def _terraform_client(req: DLPPackDeployRequest):
    """The credentials and, for gap mode, the signed-in SDK client of a
    Terraform hand-off request. Static mode never touches the tenant."""
    creds = _tenant_creds(req)
    if req.mode == "static":
        creds = tenant_auth.without_identity(creds)
    elif req.mode == "gap" and not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail="Gap mode needs the tenant credentials; choose static mode or fill in the tenant details.")
    client = await asyncio.to_thread(_build_sdk_client, creds) if tenant_auth.complete(creds) else None
    return creds, client


def _run_terraform(client, creds: Dict[str, str], req: DLPPackDeployRequest, packs, log, cancel) -> Dict[str, Any]:
    """The hand-off itself, shared by the request that waits for it and the
    background job the browser follows: in gap mode one read of the
    tenant (logged step by step) and a plan, then one workspace per pack,
    zipped. The zip travels as the result's `artifact`."""
    import pack_deploy
    import pack_terraform
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    report = None
    mode = "static"
    gap: Dict[str, int] = {}
    if client is not None:
        mode = "gap"
        _log(f"Gap mode: reading {tenant_auth.record_label(creds)} so the workspace imports what already exists and creates only the rest.")
        full = pack_deploy.preflight(client, packs, use_rank_0=req.use_rank_0, apply_tweaks=False, writes_enabled=None,
                                     channel_targets=req.channel_targets or None, log=_log)
        report = pack_deploy.public_report(full)
        report["tenant_label"] = tenant_auth.record_label(creds)
        for it in report.get("items") or []:
            if it.get("kind") == "tweak":
                continue
            gap[it.get("status") or "?"] = gap.get(it.get("status") or "?", 0) + 1
        _log("Plan: " + ", ".join(f"{n} {status}" for status, n in sorted(gap.items())) + ".")
    else:
        _log("Static mode: no tenant read; the workspace describes the whole pack.")
    workspaces = {}
    by = _assessor(req)       # resolved once: every pack in the workspace names the same assessor
    for p in packs:
        if cancel is not None and cancel.is_set():
            _log("Stopped before the workspace was built.")
            return {"status": "stopped", "stopped": "You clicked Stop.", "mode": mode, "packs": list(workspaces), "logs": logs}
        _log(f"Generating the Terraform workspace for {p.get('name') or p['id']}…")
        files = pack_terraform.generate(p, report=pack_terraform.split_report(report, p["id"]) if report else None,
                                        channel_targets=(req.channel_targets or {}).get(p["id"]), assessor=by)
        workspaces[p["id"]] = files
        _log(f"  {len(files)} files" + (", imports.tf included" if "imports.tf" in files else "") + ".")
    data = pack_terraform.zip_workspaces(workspaces)
    name = f"dlp-check-terraform-{mode}-{'-'.join(req.pack_ids)[:60]}.zip"
    _log(f"Ready: {name} ({len(data) // 1024} KB).")
    return {"status": "ready", "mode": mode, "filename": name, "bytes": len(data), "packs": list(workspaces), "gap": gap,
            "tenant_label": tenant_auth.record_label(creds) if client is not None else "", "logs": logs,
            "artifact": (name, "application/zip", data)}


@app.post("/api/dlp-packs/terraform/start")
async def dlp_packs_terraform_start(req: DLPPackDeployRequest, request: Request):
    """Start the same Terraform hand-off as /terraform as a background job
    and return its id at once; poll GET /api/dlp-packs/jobs/{job_id} for
    the log (in gap mode the tenant read, step by step) and, once it is
    done, fetch the zip from the `download` path the snapshot names."""
    import pack_jobs
    if not req.pack_ids:
        raise HTTPException(status_code=400, detail="Select at least one pack.")
    packs = _resolve_pack_ids(req.pack_ids)
    creds, client = await _terraform_client(req)
    job = pack_jobs.start("terraform", lambda log, cancel: _run_terraform(client, creds, req, packs, log, cancel), label=", ".join(req.pack_ids),
                           actor=_actor(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


class PackExportRequest(TenantCredsRequest):
    """Body of Export from tenant as a pack: which rules (rule ids per
    channel, or "all"; empty means every DLP rule on every channel) and
    the name the pack gets."""
    customer_id: str = ""
    rules: Dict[str, Any] = {}
    pack_name: str = ""


def _run_pack_export(client, creds: Dict[str, str], req: PackExportRequest, selection, log, cancel) -> Dict[str, Any]:
    """Read the tenant and build the pack (pack_export), zipped. The zip
    travels as the result's `artifact`; the JSON result says what is in it
    and what could not be exported."""
    import pack_export
    c = tenant_auth.normalize(creds)
    # The pack names the tenant, never the admin who signed in (the classic API's label is its username).
    # The classic API's label is 'classic API (cloud)' (tenant_auth.record_label), never a stale vanity domain.
    label = tenant_auth.record_label(c)
    log(f"Exporting from {label}: the rules, the engines they use and the dictionaries those engines use. Nothing is written to the tenant.")
    res = pack_export.export_pack(client, selection=selection, name=req.pack_name[:120], tenant_label=label, log=log, cancel=cancel)
    if res["status"] != "ready":
        return dict(res, tenant_label=label)
    pack = res["pack"]
    name, data = pack_export.zip_pack(pack)
    log(f"Ready: {name} ({max(1, len(data) // 1024)} KB).")
    v = res["validation"]
    return {"status": "ready", "filename": name, "bytes": len(data), "tenant_label": label, "pack_name": pack["meta"]["name"],
            "counts": pack["meta"]["counts"], "not_exported": pack["meta"]["not_exported"], "warnings": pack["warnings"],
            "validation": {"ok": v["ok"], "problems": v["problems"], "warnings": v["warnings"]},
            "artifact": (name, "application/zip", data)}


@app.post("/api/dlp-packs/export/start")
async def dlp_packs_export_start(req: PackExportRequest, request: Request):
    """Export from tenant as a pack, as a background job: the tenant's DLP
    rules (all of them, or the ones picked per channel) with every engine
    they use and every dictionary those engines use, in the layout Deploy
    Policy Packs and the pack library read. Read-only, so it needs neither
    write mode nor the writer check. Poll GET /api/dlp-packs/jobs/{job_id}
    for the log; the finished job's `download` path serves the zip."""
    import pack_export
    import pack_jobs
    try:
        selection = pack_export.normalize_selection(req.rules or None)
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    creds = _tenant_creds(req)
    if not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail="Fill in the tenant details (or pick a saved tenant) to export its rules.")
    client = await asyncio.to_thread(_build_sdk_client, creds)
    job = pack_jobs.start("export", lambda log, cancel: _keyed(client, _run_pack_export, client, creds, req, selection, log, cancel),
                          label=req.pack_name[:60] or tenant_auth.record_label(creds), actor=_actor(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/dlp-packs/jobs/{job_id}/download")
async def dlp_pack_job_download(job_id: str):
    """The file a finished job produced (a Terraform workspace zip, or an
    exported pack)."""
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job. Jobs are kept for an hour after they finish; start the hand-off again.")
    if job.artifact is None:
        raise HTTPException(status_code=409, detail="This job has no file to download" + (" yet; it is still running." if job.status == pack_jobs.RUNNING else "."))
    name, media, data = job.artifact
    return Response(content=data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "X-DLP-Check-Mode": str((job.result or {}).get("mode") or "")})


@app.post("/api/dlp-packs/apply")
async def dlp_packs_apply(req: DLPPackDeployRequest, request: Request):
    """Execute an approved plan. Requires confirm=true and the plan_hash
    returned by /preflight. If the tenant or selection changed since
    approval the response is 409 with status 'plan_changed' and nothing
    is written. Blocked or failed items never stop the others."""
    _security.require_writer()
    try:
        import pack_deploy  # noqa: F401 — availability check; the run is in _run_apply
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_deploy unavailable: {e}")
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Deployment requires explicit confirmation (confirm=true).")
    if not req.plan_hash:
        raise HTTPException(status_code=400, detail="plan_hash is required — run /api/dlp-packs/preflight first.")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    packs = _resolve_pack_ids(req.pack_ids)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    result = await asyncio.to_thread(_as_actor, _actor(request), _run_apply, client, creds, req, packs, None, None)
    if result.get("status") in ("plan_changed", "blocked"):
        return JSONResponse(result, status_code=409)
    return result


def _run_apply(client, creds: Dict[str, str], req: DLPPackDeployRequest, packs, log, cancel) -> Dict[str, Any]:
    """The deployment itself, shared by the request that waits for it and
    the background job the browser follows: the approved plan through
    pack_deploy.apply (the shared execution path), then the record that
    makes it undoable. `log` receives each line as it is written; `cancel`
    is the operator's Stop."""
    import pack_deploy
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    by = _assessor(req)       # resolved once: the tags and the record name the same assessor
    result = pack_deploy.apply(client, packs, plan_hash=req.plan_hash, use_rank_0=req.use_rank_0, apply_tweaks=req.apply_tweaks,
                               verify=req.verify, writes_enabled=True, restore_drift=req.restore_drift,
                               channel_targets=req.channel_targets or None, log=_log, cancel=cancel, assessor=by)
    result["logs"] = logs
    if result.get("status") in ("plan_changed", "blocked"):
        return result
    # Remember what was created so the deployment can be undone later.
    try:
        import deployments
        rec = deployments.from_apply(result, tenant_label=tenant_auth.record_label(creds),
                                     packs=list(req.pack_ids), options={"use_rank_0": req.use_rank_0, "apply_tweaks": req.apply_tweaks,
                                                                        "restore_drift": req.restore_drift},
                                     channel_targets=req.channel_targets or {}, by=by, tenant_key=_tenant_key(creds))
        if rec:
            deployments.add(rec)
            result["deployment_id"] = rec["id"]
            result["deployment"] = deployments.summary(rec)
    except Exception as e:  # noqa: BLE001 — a bookkeeping failure must not hide a successful deploy
        result["deployment_error"] = f"the deployment was not recorded for undo: {str(e)[:200]}"
    return result


@app.post("/api/dlp-packs/apply/start")
async def dlp_packs_apply_start(req: DLPPackDeployRequest, request: Request):
    """Start the same deployment as /apply as a background job and return
    its id at once, so the browser can show the log while the tenant is
    written to (a pack is minutes of API calls, activation and read-back).
    Poll GET /api/dlp-packs/jobs/{job_id}; POST .../cancel stops the
    remaining writes. The checks are the same as /apply: confirm, the
    plan_hash from /preflight, write mode."""
    _security.require_writer()
    import pack_jobs
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Deployment requires explicit confirmation (confirm=true).")
    if not req.plan_hash:
        raise HTTPException(status_code=400, detail="plan_hash is required — run /api/dlp-packs/preflight first.")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    packs = _resolve_pack_ids(req.pack_ids)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    job = pack_jobs.start("deploy", lambda log, cancel: _keyed(client, _run_apply, client, creds, req, packs, log, cancel), label=", ".join(req.pack_ids),
                           actor=_actor(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/deployments")
async def dlp_deployments_list(tenant_label: Optional[str] = None):
    """Deployments made from this app (newest first): what was created,
    in which tenant, and whether it was undone."""
    import deployments
    return {"deployments": deployments.list_all(tenant_label), "writes_enabled": writes_enabled()}


@app.post("/api/deployments/{dep_id}/undo")
async def dlp_deployment_undo(dep_id: str, req: DeploymentUndoRequest, request: Request):
    """Delete what a recorded deployment created (rules, endpoint
    application groups, engines, dictionaries, in that order). Only
    objects this tool created are removed, and only while the tenant still
    lists the id under the name we gave it. Needs write mode and
    confirm=true. Changes still need activation in ZIA."""
    _security.require_writer()
    import deployments
    import pack_deploy
    rec = deployments.get(dep_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Deployment not found.")
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Undo requires explicit confirmation (confirm=true).")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    creds = _tenant_creds(req)
    label = tenant_auth.record_label(creds)
    if not _same_tenant(rec, creds):
        where = rec.get("tenant_label") or "another tenant"
        if where == label:
            where = f"another {label} tenant"
        raise HTTPException(status_code=409, detail=f"This deployment was made in {where}, but the current credentials are for {label}. Switch tenant first.")
    client = await asyncio.to_thread(_build_sdk_client, creds)
    logs: list = []
    result = await asyncio.to_thread(_as_actor, _actor(request), lambda: pack_deploy.undo(client, rec, writes_enabled=True, log=logs.append))
    result["logs"] = logs
    updated = deployments.mark_undo(dep_id, result.get("results") or [], complete=bool(result.get("complete")))
    result["deployment"] = deployments.summary(updated) if updated else None
    return result


@app.post("/api/dlp-packs/{pack_id}/import")
async def dlp_pack_import(pack_id: str, req: DLPPackImportRequest, request: Request):
    """Single-pack deploy for scripts, through the same shared path as Deploy
    Policy Packs (pack_deploy.preflight + apply → pack_ops). Without a
    `plan_hash` the endpoint only plans and returns the plan to review;
    with the hash of that plan it deploys. Nothing is written otherwise."""
    _security.require_writer()
    import pack_deploy
    pack = _resolve_pack_ids([pack_id])[0]
    client = await asyncio.to_thread(_build_sdk_client, _tenant_creds(req))
    if not req.plan_hash:
        report = await asyncio.to_thread(lambda: pack_deploy.preflight(client, [pack], use_rank_0=req.use_rank_0, apply_tweaks=req.apply_tweaks,
                                                                       writes_enabled=writes_enabled()))
        public = pack_deploy.public_report(report)
        public["status"] = "plan"
        public["message"] = ("This is the plan. Nothing was written. To deploy it, call this endpoint again with "
                             "plan_hash set to the value below, or use Deploy Policy Packs in the app.")
        return public
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    logs: list = []
    by = _assessor(req)       # resolved once: the tags and the record name the same assessor
    result = await asyncio.to_thread(_as_actor, _actor(request), lambda: pack_deploy.apply(client, [pack], plan_hash=req.plan_hash, use_rank_0=req.use_rank_0,
                                                               apply_tweaks=req.apply_tweaks, verify=req.verify, writes_enabled=True,
                                                               log=logs.append, assessor=by))
    result["logs"] = logs
    if result.get("status") == "applied" and result.get("summary", {}).get("created"):
        try:
            import deployments
            creds = _tenant_creds(req)
            deployments.add(deployments.from_apply(result, tenant_label=tenant_auth.record_label(creds), packs=[pack["id"]],
                                                   options={"use_rank_0": req.use_rank_0, "apply_tweaks": req.apply_tweaks}, channel_targets={},
                                                   by=by, tenant_key=_tenant_key(creds)))
        except Exception as e:  # noqa: BLE001 — the deployment happened; only the record failed
            result.setdefault("warnings", []).append(f"The deployment was not recorded for undo: {e}")
    return result


@app.post("/api/dlp-packs/{pack_id}/verify")
async def dlp_pack_verify(pack_id: str, req: TenantCredsRequest = TenantCredsRequest()):
    """Is everything this pack defines in the tenant? Read-only, answered by
    the same planner that plans a deploy (pack_deploy.verify_pack)."""
    import pack_deploy
    pack = _resolve_pack_ids([pack_id])[0]
    client = await asyncio.to_thread(_build_sdk_client, _tenant_creds(req))
    return await asyncio.to_thread(pack_deploy.verify_pack, client, pack)


class DLPPackUploadRequest(BaseModel):
    """Older single-call pack upload: the three JSON lists in one body."""
    pack_name: str
    dictionaries: Optional[List[Dict[str, Any]]] = None
    engines: Optional[List[Dict[str, Any]]] = None
    policies: Optional[List[Dict[str, Any]]] = None


def _pack_library_writes_allowed() -> bool:
    """Adding or removing packs writes to the app's own disk. Allowed when
    the server only answers this machine (localhost bind) or when the UI
    token gate is on, so a network-exposed server still needs the token."""
    return get_bind_host() in ("127.0.0.1", "localhost", "::1") or _security.ui_auth_enabled()


def _require_pack_library_writes() -> None:
    if not _pack_library_writes_allowed():
        raise HTTPException(status_code=403, detail="Adding or removing packs is only allowed when the server is bound to localhost or the UI token is enabled (ZSCALER_UI_AUTH).")


@app.post("/api/dlp-packs/upload")
async def dlp_pack_upload(req: DLPPackUploadRequest):
    """Older single-call upload: the three JSON lists in one body. Kept for
    scripts; the Advanced settings tab uses /api/pack-library/upload."""
    _require_pack_library_writes()
    import pack_library as pl
    bundle = {"name": req.pack_name, "dictionaries": req.dictionaries or [], "engines": req.engines or [], "policies": req.policies or []}
    try:
        pack = pl.assemble_pack([{"name": "pack.json", "content": json.dumps({**bundle, "bundle": True})}], pack_name=req.pack_name)
        saved = pl.save_pack(pack, root=PACKS_ROOT)
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"id": saved["id"], "dir": saved["dir"], "files_saved": saved["validation"]["counts"], "metadata": {k: saved.get(k) for k in ("name", "version", "description")}}


class PackUploadFile(BaseModel):
    """One uploaded file: its name, content and encoding (base64 for ZIPs)."""
    name: str
    content: str
    encoding: Optional[str] = None      # "base64" for ZIPs; text otherwise


class PackLibraryUploadRequest(BaseModel):
    """Body of a pack-library upload: the files plus an optional name, id and description."""
    files: List[PackUploadFile]
    pack_name: str = ""
    pack_id: str = ""
    description: str = ""


def _pack_library_status() -> Dict[str, Any]:
    import pack_library as pl
    return {
        "writes_allowed": _pack_library_writes_allowed(),
        "bind_host": get_bind_host(),
        "ui_auth": _security.ui_auth_enabled(),
        "user_packs_dir": pl.user_packs_dir(PACKS_ROOT),
        "packs_root": PACKS_ROOT,
        "max_upload_mb": pl.MAX_UPLOAD_BYTES // (1024 * 1024),
        "env": {"DLP_CHECK_USER_PACKS": os.environ.get("DLP_CHECK_USER_PACKS") or "",
                "ZSCALER_UI_AUTH": os.environ.get("ZSCALER_UI_AUTH") or "",
                "ZSCALER_BIND_HOST": os.environ.get("ZSCALER_BIND_HOST") or "",
                "ZSCALER_WRITES": os.environ.get("ZSCALER_WRITES") or ""},
        "writes_to_tenant": _security.writes_enabled(),
    }


@app.get("/api/pack-library")
async def pack_library_list():
    """Every policy pack the app knows: built-in and uploaded, with counts."""
    import pack_library as pl
    out = pl.library(PACKS_ROOT)
    out.update(_pack_library_status())
    return out


@app.post("/api/pack-library/preview")
async def pack_library_preview(req: PackLibraryUploadRequest):
    """Parse and validate an upload without saving it: what it contains,
    what would block it, what to watch."""
    import pack_library as pl
    import pack_channels as _pc
    try:
        pack = pl.assemble_pack([f.model_dump() for f in req.files], pack_name=req.pack_name, description=req.description)
    except ValueError as e:
        return {"ok": False, "problems": [str(e)], "warnings": [], "counts": {}, "channels": []}
    v = pl.validate_pack(pack)
    slug = pl.pack_slug(req.pack_id or pack["meta"].get("name") or "")
    if slug and pl._pack_id_taken(slug, PACKS_ROOT):
        v["ok"] = False
        v["problems"].append(f"a pack with id '{slug}' already exists; choose another id or remove that pack first")
    v.update({
        "pack_id": slug, "name": pack["meta"].get("name"), "description": pack["meta"].get("description"),
        "format": pack.get("format"), "sources": pack.get("sources"),
        "dictionaries": [{"name": d.get("name"), "clone": bool(d.get("predefined_clone")), "template": d.get("dict_template_name"),
                          "patterns": len(d.get("patterns") or []), "phrases": len(d.get("phrases") or []), "proximity": d.get("proximity") or 0}
                         for d in pack.get("dictionaries") or [] if isinstance(d, dict)],
        "engines": [{"name": e.get("name"), "expression": e.get("expression")} for e in pack.get("engines") or [] if isinstance(e, dict)],
        "policies": [{"name": p.get("name"), "channel": _pc.channel_of(p), "action": p.get("action") if not isinstance(p.get("action"), dict) else (p["action"].get("type") or "action"),
                      "state": p.get("state", "ENABLED"), "engines": p.get("engines") or [], "sub_rules": len(p.get("sub_rules") or [])}
                     for p in pack.get("policies") or [] if isinstance(p, dict)],
        "app_groups": [g.get("name") for g in pack.get("app_groups") or [] if isinstance(g, dict)],
    })
    return v


@app.post("/api/pack-library/upload")
async def pack_library_upload(req: PackLibraryUploadRequest):
    """Add a pack to the library from JSON, Terraform or a ZIP. It is then
    an ordinary pack: Deploy Policy Packs, the Data Flow Map, the
    Terraform hand-off and the validator all list it."""
    _require_pack_library_writes()
    import pack_library as pl
    try:
        pack = pl.assemble_pack([f.model_dump() for f in req.files], pack_name=req.pack_name, description=req.description)
        saved = pl.save_pack(pack, pack_id=req.pack_id, root=PACKS_ROOT)
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # The pack is transcribed to Terraform right away (static mode: no
    # tenant read) and the workspace is kept beside the pack, so the
    # customer gets the same policy in a vendor-neutral, reviewable form.
    terraform = _transcribe_pack_to_terraform(saved["id"], saved["dir"])
    return {"ok": True, "pack": {k: saved.get(k) for k in ("id", "name", "version", "description", "dictionaries", "engines", "policies", "app_groups", "channels", "source")},
            "validation": saved["validation"], "dir": saved["dir"], "terraform": terraform}


def _transcribe_pack_to_terraform(pack_id: str, pack_dir: str) -> Dict[str, Any]:
    """Render the static Terraform workspace for one pack into
    <pack_dir>/terraform/. Returns what was written, or the error."""
    try:
        import pack_terraform
        files = pack_terraform.generate({"id": pack_id, "dir": pack_dir})
        out_dir = os.path.join(pack_dir, "terraform")
        pack_terraform.write_workspace(files, out_dir)
        resources = sum(len(re.findall(r'(?m)^resource "', body)) for body in files.values())
        data_sources = sum(len(re.findall(r'(?m)^data "', body)) for body in files.values())
        return {"ok": True, "dir": out_dir, "files": sorted(files), "resources": resources, "data_sources": data_sources,
                "download": f"/api/pack-library/{pack_id}/terraform.zip", "mode": "static"}
    except Exception as e:  # noqa: BLE001 - the pack is saved; the transcription failure is reported, not fatal
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


@app.get("/api/pack-library/{pack_id}/terraform.zip")
async def pack_library_terraform(pack_id: str, assessor: str = "", profile_id: str = ""):
    """The pack as a Terraform workspace for the official zscaler/zia
    provider, static mode (no tenant read), for any pack in the library.
    Gap mode (imports of what already exists) is the Terraform hand-off.
    `assessor` (else the saved profile's, by `profile_id`) is the name the
    provenance tags carry; DLP-Check only when no assessor is named."""
    import pack_library as pl
    import pack_terraform
    pack = _resolve_pack_ids([pack_id])[0]
    from types import SimpleNamespace
    by = _assessor(SimpleNamespace(assessor=assessor, profile_id=profile_id))
    files = await asyncio.to_thread(lambda: pack_terraform.generate(pack, assessor=by))
    data = pack_terraform.zip_workspaces({pack["id"]: files})
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{pl.slugify(pack_id) or "pack"}-terraform.zip"', "X-DLP-Check-Mode": "static"})


@app.post("/api/pack-library/{pack_id}/remove")
async def pack_library_delete(pack_id: str):
    """Remove an uploaded pack. Built-in packs are not removable here."""
    _require_pack_library_writes()
    import pack_library as pl
    try:
        removed = pl.delete_pack(pack_id, root=PACKS_ROOT)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"ok": True, "removed": removed}


@app.get("/api/pack-library/{pack_id}/bundle")
async def pack_library_bundle(pack_id: str):
    """One JSON file holding a pack: the upload format, and the starting
    point for a customer's own pack."""
    import pack_library as pl
    pack = _resolve_pack_ids([pack_id])[0]
    body = json.dumps(pl.pack_bundle(pack["dir"]), indent=2)
    return Response(content=body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{pl.slugify(pack_id) or "pack"}.json"'})


# The daily upstream contract check (the SDK, the Terraform provider and
# Zscaler's API reference against what the app sends) runs in GitHub
# Actions at 06:23 UTC (.github/workflows/upstream_check.yml) and files an
# `upstream-drift` issue on drift. This server cannot read that run; what
# it can do is the same check's offline part — the installed SDK and the
# committed Terraform against the payloads the shipped packs produce —
# on demand, in well under a second, cached for an hour.
_UPSTREAM_CACHE: Dict[str, Any] = {"at": 0.0, "report": None}
_UPSTREAM_CACHE_SECONDS = 3600


@app.get("/api/upstream-check")
async def upstream_check_offline(refresh: bool = False):
    """The offline half of the daily upstream contract check, run on this
    server now (or within the last hour): findings, the installed SDK
    version, the provider pin, and where the daily online run lives."""
    import upstream_check
    now = time.time()
    if refresh or not _UPSTREAM_CACHE["report"] or now - _UPSTREAM_CACHE["at"] > _UPSTREAM_CACHE_SECONDS:
        try:
            rep = await asyncio.to_thread(upstream_check.run, True)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"the offline upstream check failed: {type(e).__name__}: {str(e)[:200]}")
        _UPSTREAM_CACHE["report"] = rep
        _UPSTREAM_CACHE["at"] = now
    rep = _UPSTREAM_CACHE["report"]
    findings = rep.get("findings") or []
    return {"generated": rep.get("generated"), "offline": True, "cached_seconds": int(now - _UPSTREAM_CACHE["at"]),
            "ok": not any(f.get("level") == "drift" for f in findings),
            "drift": [f for f in findings if f.get("level") == "drift"], "notes": [f for f in findings if f.get("level") != "drift"],
            "sdk_installed": ((rep.get("sdk") or {}).get("installed") or {}).get("version"),
            "terraform_pinned": (rep.get("terraform") or {}).get("pinned"),
            "endpoints_checked": sorted(((rep.get("app") or {}).get("payload_keys") or {}).keys()),
            "daily": {"where": "GitHub Actions, .github/workflows/upstream_check.yml", "schedule": "06:23 UTC daily and on demand",
                      "covers": "the online half too: PyPI's latest SDK release diffed on the modules the app calls, the 2.x prerelease's service definition, the provider's latest version, schema and docs, and Zscaler's API reference",
                      "result": "drift opens or updates one issue labelled upstream-drift in the repository and fails the job; a clean day closes it. This server does not read that run.",
                      "not": "this is not a CISA check and not a check of the customer's tenant"},
            "beacon": {"where": "/report/beacon", "what": "the same check's online half, run on this server on a timer, with what changed since the last run"}}


# ── Beacon: what changed in the SDK, the API and Terraform ─────────────
# beacon.py runs the upstream check's watchers (SDK, API, Terraform) on
# this server and keeps the last 30 snapshots with what changed between
# them. A timer runs the online watchers every DLP_CHECK_BEACON_HOURS
# (default 24; 0 turns it off) while this server process runs; it never
# runs the tenant API watch, which needs credentials and is started from
# the Beacon tab. Nothing is written to any tenant: the watch is GET only.
_BEACON_DEFAULT_HOURS = 24.0
_BEACON_STATUS_REFRESH_SECONDS = 3600   # /api/beacon/status?refresh=1 starts an online run at most this often


def _beacon_hours() -> float:
    """DLP_CHECK_BEACON_HOURS as a number of hours; blank, invalid or
    negative falls back to the default with a line in the log."""
    raw = (os.environ.get("DLP_CHECK_BEACON_HOURS") or "").strip()
    if not raw:
        return _BEACON_DEFAULT_HOURS
    try:
        hours = float(raw)
    except ValueError:
        print(f"[beacon] DLP_CHECK_BEACON_HOURS={raw!r} is not a number; using {_BEACON_DEFAULT_HOURS:g} hours.")
        return _BEACON_DEFAULT_HOURS
    if hours < 0:
        print(f"[beacon] DLP_CHECK_BEACON_HOURS={raw!r} is negative; using {_BEACON_DEFAULT_HOURS:g} hours (0 turns the timer off).")
        return _BEACON_DEFAULT_HOURS
    return hours


_BEACON_STATE: Dict[str, Any] = {"enabled": False, "interval_hours": None, "last_run_at": None, "last_status": None, "last_error": None,
                                 "next_run_at": None, "running": False, "running_since": None, "running_trigger": None,
                                 "runs_while": "this server process is running", "covers": "SDK, API and Terraform (never the tenant API watch)"}


def _beacon_run_locked(online: bool, trigger: str, client: Any = None, label: str = "") -> Optional[Dict[str, Any]]:
    """One Beacon run by a caller that already holds beacon.RUN_LOCK; the
    lock is released here, whatever happens. Keeps the timer state."""
    import beacon
    _BEACON_STATE.update({"running": True, "running_since": datetime.now(timezone.utc).isoformat(timespec="seconds"), "running_trigger": trigger})
    try:
        snap = beacon.run(online=online, tenant_client=client, tenant_label=label, trigger=trigger)
        _BEACON_STATE.update({"last_status": "error" if snap.get("error") else "ok", "last_error": snap.get("error")})
        return snap
    except Exception as e:  # noqa: BLE001 — a failed run is reported on the tab, never raised into the server
        _BEACON_STATE.update({"last_status": "error", "last_error": f"{type(e).__name__}: {str(e)[:200]}"})
        return None
    finally:
        _BEACON_STATE.update({"running": False, "running_since": None, "running_trigger": None,
                              "last_run_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        beacon.RUN_LOCK.release()


def _beacon_run_blocking(online: bool, trigger: str) -> Optional[Dict[str, Any]]:
    """One upstream-only run, or None when another run is in progress."""
    import beacon
    if not beacon.RUN_LOCK.acquire(blocking=False):
        return None
    return _beacon_run_locked(online, trigger)


def _beacon_start_background(online: bool, trigger: str, client: Any = None, label: str = "") -> bool:
    """Start a run on its own thread; False when one is already running."""
    import beacon
    import threading
    if not beacon.RUN_LOCK.acquire(blocking=False):
        return False
    try:
        threading.Thread(target=_beacon_run_locked, args=(online, trigger, client, label), name="beacon-run", daemon=True).start()
    except Exception:
        beacon.RUN_LOCK.release()
        raise
    return True


def _beacon_last_online_age(history: List[Dict[str, Any]]) -> Optional[float]:
    """Seconds since the newest online run, or None when there is none."""
    for s in reversed(history):
        if s.get("online"):
            try:
                return max(0.0, time.time() - datetime.fromisoformat(str(s.get("at"))).timestamp())
            except ValueError:
                return None
    return None


async def _beacon_loop() -> None:
    """The timer: the online upstream watchers every N hours. The first run
    waits until the newest online snapshot is N hours old (at least a
    minute after startup), so a restart does not re-fetch everything."""
    import beacon
    interval = _BEACON_STATE["interval_hours"] * 3600
    try:
        age = _beacon_last_online_age(await asyncio.to_thread(beacon.load_history))
    except Exception:  # noqa: BLE001
        age = None
    delay = max(60.0, interval - age) if age is not None else 60.0
    while _BEACON_STATE.get("enabled"):
        _BEACON_STATE["next_run_at"] = datetime.fromtimestamp(time.time() + delay, timezone.utc).isoformat(timespec="seconds")
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            break
        try:
            await asyncio.to_thread(_beacon_run_blocking, True, "timer")
        except Exception as e:  # noqa: BLE001 — the timer never takes the server down
            _BEACON_STATE.update({"last_status": "error", "last_error": f"{type(e).__name__}: {str(e)[:200]}"})
        delay = interval


@app.on_event("startup")
async def _start_beacon() -> None:
    hours = _beacon_hours()
    _BEACON_STATE["interval_hours"] = hours
    if hours <= 0:
        _BEACON_STATE.update({"enabled": False, "last_status": "disabled", "next_run_at": None})
        return
    try:
        import beacon  # noqa: F401
        _BEACON_STATE["enabled"] = True
        asyncio.create_task(_beacon_loop())
    except Exception:  # noqa: BLE001
        _BEACON_STATE.update({"enabled": False, "last_status": "disabled"})


def _beacon_timer() -> Dict[str, Any]:
    t = dict(_BEACON_STATE)
    if t.get("interval_hours") is None:
        t["interval_hours"] = _beacon_hours()   # the startup hook has not run (tests, a bare import)
    t["setting"] = "DLP_CHECK_BEACON_HOURS (0 turns the timer off)"
    return t


class BeaconRunRequest(TenantCredsRequest):
    """Body of POST /api/beacon/run. `online` reads PyPI, the Terraform
    registry, the provider's docs and Zscaler's pages (false: the installed
    SDK and the committed Terraform only). `tenant_watch` also GETs every
    endpoint the app reads from the tenant the credentials name (blank
    fields fall back to the saved profile, the environment or
    tenant_config.json, like every tenant call)."""
    online: bool = True
    tenant_watch: bool = False
    customer_id: str = ""   # ZPA endpoints are probed only with one


@app.get("/api/beacon")
async def beacon_get():
    """The latest Beacon snapshot, what changed since the run before it,
    the history (newest first) and the timer."""
    import beacon
    history = await asyncio.to_thread(beacon.load_history)
    latest = history[-1] if history else None
    return {"latest": latest, "diff": (latest or {}).get("diff"), "history": beacon.history_rows(history),
            "running": _BEACON_STATE["running"] or beacon.RUN_LOCK.locked(), "running_since": _BEACON_STATE["running_since"],
            "timer": _beacon_timer(), "state_file": beacon.state_path(), "keep": beacon.HISTORY_KEEP}


@app.get("/api/beacon/status")
async def beacon_status(refresh: bool = False):
    """Short form for a notice: the current SDK / API / Terraform drift, the
    count of changes since the previous run and where the details are.
    Reads the kept snapshot only; `refresh` starts an online run in the
    background when the newest online one is over an hour old."""
    import beacon
    history = await asyncio.to_thread(beacon.load_history)
    started = False
    if refresh:
        age = _beacon_last_online_age(history)
        if age is None or age > _BEACON_STATUS_REFRESH_SECONDS:
            started = _beacon_start_background(True, "status")
    latest = history[-1] if history else None
    online = next((s for s in reversed(history) if s.get("online")), None)
    diff = (latest or {}).get("diff") or {}
    drift = (online or latest or {}).get("drift") or []
    import hashlib
    key = hashlib.sha256("\n".join(sorted(f"{d.get('watcher')}|{d.get('text')}" for d in drift)).encode("utf-8")).hexdigest()[:16] if drift else ""
    return {"at": (latest or {}).get("at"), "online_at": (online or {}).get("at"), "drift": drift, "drift_key": key,
            "changes": len(diff.get("changes") or []), "summary": (diff.get("summary") or [None])[0],
            "running": _BEACON_STATE["running"] or beacon.RUN_LOCK.locked(), "started": started, "details": "/report/beacon",
            "next_run_at": _BEACON_STATE.get("next_run_at")}


@app.post("/api/beacon/run")
async def beacon_run(req: BeaconRunRequest):
    """Start a Beacon run in the background; GET /api/beacon shows it when
    it is done. With `tenant_watch`, the credentials are checked and signed
    in first (a refusal is answered here, secrets masked) and the tenant
    is then only read: GET, about one request a second."""
    import beacon
    if _BEACON_STATE["running"] or beacon.RUN_LOCK.locked():
        raise HTTPException(status_code=409, detail=f"A Beacon run is already in progress (started {_BEACON_STATE.get('running_since') or 'just now'}); wait for it to finish.")
    client, label = None, ""
    if req.tenant_watch:
        client = await asyncio.to_thread(_build_client, req)   # validates every field; 400/401 without echoing a secret
        label = tenant_auth.label(_tenant_creds(req))
    if not _beacon_start_background(bool(req.online), "manual", client, label):
        if client is not None:
            client.close()
        raise HTTPException(status_code=409, detail="A Beacon run is already in progress; wait for it to finish.")
    return {"started": True, "online": bool(req.online), "tenant_watch": bool(req.tenant_watch), "tenant": label or None,
            "endpoints": len(beacon.tenant_endpoints()) if req.tenant_watch else 0}


@app.get("/report/beacon")
async def report_beacon_page():
    """Standalone tab for Beacon (static/report_beacon.html)."""
    page = os.path.join(STATIC_DIR, "report_beacon.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/api/secure-by-design")
async def secure_by_design_score():
    """How this app measures against CISA's Secure by Design principles and
    pledge goals, read live from the running server and the app folder:
    a score, and every control with its status, evidence and next step."""
    try:
        import secure_by_design
        return await asyncio.to_thread(secure_by_design.evaluate, app)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Secure by Design check failed: {e}")


@app.get("/report/advanced")
async def report_advanced_page():
    """Advanced settings tab (static/report_advanced.html): the policy pack
    library and how this server is configured."""
    page = os.path.join(STATIC_DIR, "report_advanced.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/report/deploy-flow")
async def report_deploy_flow_page():
    """How a deployment and a removal work, step by step, for someone who
    has never seen the code (static/deploy_flow.html)."""
    page = os.path.join(STATIC_DIR, "deploy_flow.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/permissions")
async def serve_permissions_page():
    """Standalone HTML view of the Required API Access catalog.
    Renders the same data as /api/permissions/required but as a full
    page so the GUI's quick-link button can target="_blank" and open
    it in a new browser tab (per user request).
    """
    try:
        from scope_permissions import get_all_permissions
        import html as _html
        data = get_all_permissions()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    def esc(s):
        return _html.escape(str(s or ""))

    notes_html = "".join(
        f'<li>{esc(n)}</li>' for n in data.get("global_notes", [])
    )
    cards_html = []
    for key, s in (data.get("scopes") or {}).items():
        reads = "".join(
            f'<li><code>{esc(p)}</code></li>'
            for p in (s.get("permissions_read") or [])
        )
        endpoints = "".join(
            f'<code class="endpoint">{esc(e)}</code> '
            for e in (s.get("endpoints_used") or [])
        )
        customer_id_note = ""
        if s.get("customer_id_needed"):
            customer_id_note = (
                f'<div class="warn-box"><strong>⚠ Customer ID required</strong>'
                f'{" — " + esc(s.get("customer_id_note", "")) if s.get("customer_id_note") else ""}</div>'
            )
        note_block = f'<div class="note"><em>{esc(s.get("note", ""))}</em></div>' if s.get("note") else ""
        cards_html.append(f"""
        <section class="card" aria-labelledby="scope-{esc(key)}">
          <header>
            <h2 id="scope-{esc(key)}">{esc(s.get("label", key))} <span class="service">· {esc(s.get("service", ""))}</span></h2>
            <code class="scope-key">scope={esc(key)}</code>
          </header>
          <p class="desc">{esc(s.get("description", ""))}</p>
          <div class="grid">
            <div>
              <h3>Minimum READ permissions</h3>
              <ul class="perms">{reads or '<li class="muted">(none specific)</li>'}</ul>
            </div>
            <div>
              <h3>Endpoints used</h3>
              <div class="endpoints" tabindex="0" aria-label="Endpoints used by this scope">{endpoints or '<span class="muted">(composite — no direct endpoints)</span>'}</div>
            </div>
          </div>
          <div class="license"><strong>License / subscription:</strong> {esc(s.get("license_required", "—"))}</div>
          {customer_id_note}
          {note_block}
        </section>
        """)

    portal = data.get("portal_url", "https://admin.zidentity.net/")
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Required API Access · Zscaler Platform Assessment</title>
<style>
  :root {{
    --bg: #0a0e1a;
    --card: #1e293b;
    --border: rgba(148,163,184,0.2);
    --text: #f1f5f9;
    --dim: #94a3b8;
    --accent: #3b82f6;
    --warn: #f59e0b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html {{ color-scheme: dark; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.55;
    padding: 2rem 1rem; min-height: 100vh;
  }}
  :focus-visible {{ outline: 3px solid var(--accent); outline-offset: 2px; border-radius: 4px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 2rem; margin-bottom: 0.4rem; }}
  h1 .accent {{ color: var(--accent); }}
  .lead {{ color: var(--dim); margin-bottom: 1.5rem; }}
  .notes {{ background: rgba(59,130,246,0.06); border: 1px solid rgba(59,130,246,0.3);
           border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }}
  .notes h2 {{ font-size: 1rem; margin-bottom: 0.5rem; }}
  .notes ol {{ margin-left: 1.4rem; color: var(--dim); font-size: 0.92rem; line-height: 1.65; }}
  .notes ol li {{ margin-bottom: 0.35rem; }}
  .portal-link {{ color: var(--accent); }}
  .card {{
    background: rgba(30,41,59,0.5); border: 1px solid var(--border);
    border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: 0.8rem;
  }}
  .card header {{ display: flex; justify-content: space-between; align-items: center;
                 flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.4rem; }}
  .card h2 {{ font-size: 1.05rem; }}
  .card h3 {{ font-size: 0.85rem; margin-bottom: 0.35rem; color: var(--accent); }}
  .service {{ color: var(--dim); font-size: 0.85rem; font-weight: 400; }}
  .scope-key {{ color: var(--accent); font-size: 0.78rem; }}
  .desc {{ color: var(--dim); font-size: 0.9rem; margin-bottom: 0.7rem; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 0.6rem; }}
  @media (max-width: 720px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  .perms {{ list-style: none; font-size: 0.85rem; }}
  .perms li {{ margin-bottom: 0.15rem; }}
  .perms code {{ background: rgba(59,130,246,0.08); padding: 0.1rem 0.4rem;
                border-radius: 3px; font-size: 0.82rem; }}
  .endpoints {{ max-height: 180px; overflow-y: auto; line-height: 1.8; }}
  .endpoint {{ background: rgba(148,163,184,0.1); color: var(--dim);
             padding: 0.1rem 0.35rem; border-radius: 3px;
             font-size: 0.75rem; display: inline-block;
             margin: 0.1rem 0.15rem 0.1rem 0; }}
  .license {{ font-size: 0.85rem; color: var(--dim); margin-top: 0.4rem; }}
  .license strong {{ color: var(--text); }}
  .warn-box {{ margin-top: 0.5rem; padding: 0.45rem 0.6rem;
              background: rgba(245,158,11,0.08);
              border-left: 3px solid var(--warn);
              border-radius: 4px; font-size: 0.82rem; }}
  .note {{ margin-top: 0.4rem; color: var(--dim); font-size: 0.82rem; }}
  .muted {{ color: var(--dim); }}
  .print-btn {{
    float: right; margin-bottom: 1rem;
    background: #2563eb; color: white; border: 0;
    padding: 0.5rem 1rem; font-size: 0.85rem;
    border-radius: 6px; cursor: pointer;
  }}
  @media print {{ .print-btn {{ display: none; }} body {{ background: white; color: black; }} }}
</style>
</head>
<body>
<main class="container" role="main">
  <button class="print-btn" onclick="window.print()" aria-label="Print this page">🖨 Print</button>
  <h1><span class="accent">Required API Access</span> per Assessment Scope</h1>
  <p class="lead">Minimum OneAPI role permissions to grant on the API client before running each assessment scope. All checks are read-only.</p>
  <div class="notes">
    <h2>Before you start</h2>
    <ol>{notes_html}</ol>
    <p style="margin-top:0.5rem;font-size:0.88rem;">
      <strong>ZIdentity admin portal:</strong>
      <a href="{esc(portal)}" target="_blank" rel="noopener noreferrer" class="portal-link">{esc(portal)} ↗</a>
    </p>
  </div>
  {''.join(cards_html)}
</main>
</body>
</html>"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=page, headers={"Cache-Control": "no-cache, must-revalidate"})


@app.get("/api/permissions/required")
async def permissions_required():
    """Return the minimum OneAPI role permissions required per scope.
    Read-only; no tenant data involved. Used by the GUI's 'Required
    API Access' quick-link modal so users can set up the API role
    correctly before running an assessment."""
    try:
        from scope_permissions import get_all_permissions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"scope_permissions unavailable: {e}")
    out = dict(get_all_permissions())
    try:
        import permissions as _perm
        out["write_permissions"] = _perm.write_permissions_needed(_perm.WRITE_PERMISSIONS.keys())
        out["partial_note"] = ("A client that lacks a permission does not stop the tool: the checks, report sections and plan items it "
                               "cannot read are marked as not permitted and everything else runs. The assessment results list what a "
                               "full scan would need; a preflight lists what a verified plan would need.")
    except Exception:  # noqa: BLE001
        pass
    return out


@app.get("/api/branding")
async def branding_manifest():
    """Report which optional branding assets are present in
    static/branding/ so the GUI can decide which backdrops to render.
    Only checks file existence — does NOT read or transmit contents."""
    branding_dir = os.path.join(STATIC_DIR, "branding")
    def exists(fname: str) -> bool:
        try:
            p = os.path.join(branding_dir, fname)
            return os.path.isfile(p) and os.path.getsize(p) > 0
        except Exception:
            return False
    return {
        "logo_svg":      exists("logo.svg"),
        "logo_png":      exists("logo.png"),
        "portrait_jpg":  exists("portrait.jpg"),
        "portrait_png":  exists("portrait.png"),
        "favicon":       exists("favicon.ico"),
    }


@app.get("/favicon.ico")
async def favicon():
    """Return empty favicon to silence browser 404s."""
    from fastapi.responses import Response
    return Response(status_code=204)


@app.get("/api/health")
async def health():
    """Liveness plus the running git commit, so a user can see they are on the latest code."""
    # Surface the running git commit so users can verify they're on latest code.
    commit = "unknown"
    try:
        import subprocess
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).decode().strip()
    except Exception:
        pass
    in_container = os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1"
    if commit == "unknown" and in_container:
        # No .git in the image: the build records its commit instead.
        commit = os.environ.get("DLP_CHECK_BUILD_COMMIT", "").strip() or "unknown"
    hb = _health_branch()
    return {
        "status": "ok",
        "dlp_checks": len(REG),
        "platform_checks": len(PLATFORM_REG),
        "genai_checks": len(GENAI_REG),
        "automation_checks": len(AUTOMATION_REG),
        "zdx_checks": len(ZDX_REG),
        "zidentity_checks": len(ZID_REG),
        "rbac_checks": len(RBAC_REG),
        "total_checks": len(REG) + len(PLATFORM_REG) + len(GENAI_REG) + len(AUTOMATION_REG) + len(ZDX_REG) + len(ZID_REG) + len(RBAC_REG),
        "version": "3.0",
        "git_commit": commit,
        "expected_min_commit": "870c737",
        # Where this server runs from, so the operator can find the folder
        # for the update / install / stop scripts without guessing.
        "app_dir": _APP_DIR,
        "is_git_checkout": _is_git_checkout(),
        "in_container": in_container,
        "tls": _tls_status(),
        # The branch this install is on (main unless it was switched from the
        # Update app card) and what it can be switched to; latest_commit is
        # GitHub's tip of that same branch, so "update available" is honest.
        "branch": hb,
        "branches": _branch_choices(),
        "latest_commit": _latest_remote_commit(hb),
        "latest_commit_error": _latest_error(hb),
    }


# GitHub's tip per branch: {branch: {"at", "sha", "error"}}, cached 10 minutes.
_LATEST: Dict[str, Dict[str, Any]] = {}


def _latest_entry(branch: str) -> Dict[str, Any]:
    return _LATEST.setdefault(branch, {"at": 0.0, "sha": None, "error": None})


def _latest_error(branch: str) -> Optional[str]:
    return (_LATEST.get(branch) or {}).get("error")


def _health_branch() -> str:
    """The branch an update applies to by default: the checked-out one
    when it is an allowed branch, else main."""
    try:
        import app_update
        return app_update.resolve_branch(_APP_DIR, None)
    except Exception:  # noqa: BLE001
        return "main"


def _branch_choices() -> List[Dict[str, Any]]:
    try:
        import app_update
        return app_update.branch_choices(_APP_DIR)
    except Exception:  # noqa: BLE001
        return []


def _is_git_checkout() -> bool:
    """Ask git whether it manages the app folder (a .git directory, a
    worktree's .git file, or a folder inside a checkout all count)."""
    try:
        import app_update
        return app_update.is_checkout(_APP_DIR)
    except Exception:
        return os.path.exists(os.path.join(_APP_DIR, ".git"))


def _latest_remote_commit(branch: str = "main") -> Optional[str]:
    """Short sha of origin/<branch> on GitHub (best effort, cached 10
    minutes per branch), so the GUI can say whether this install is
    behind. When the check fails the reason is kept for the GUI. The
    branch is one of app_update.BRANCHES; anything else is an error, not
    a git argument."""
    import subprocess, time as _t
    import app_update
    try:
        branch = app_update.valid_branch(branch)
    except ValueError as e:
        _LATEST[str(branch)] = {"at": _t.time(), "sha": None, "error": str(e)}
        return None
    entry = _latest_entry(branch)
    if _t.time() - entry["at"] < 600:
        return entry["sha"]
    entry["at"] = _t.time()
    sha, err = None, None
    if app_update.in_container() or not os.path.exists(os.path.join(_APP_DIR, ".git")):
        # No git checkout here (the container image, or a ZIP copy): ask
        # GitHub's REST API instead, with a read-only token when one is set
        # (the repository is private, so without one GitHub answers 404).
        sha, err = app_update.github_branch_head(branch)
        entry["sha"], entry["error"] = sha, err
        return sha
    try:
        cp = subprocess.run(["git", "ls-remote", "origin", "-h", f"refs/heads/{branch}"], cwd=_APP_DIR,
                            capture_output=True, text=True, timeout=8, env=app_update.git_env())
        if cp.returncode == 0 and cp.stdout.strip():
            sha = cp.stdout.split()[0][:7]
        else:
            lines = [ln.strip() for ln in (cp.stderr or cp.stdout or "").splitlines() if ln.strip()]
            fatal = [ln for ln in lines if ln.lower().startswith("fatal:")]
            err = (fatal[0] if fatal else (lines[0] if lines else "git ls-remote failed"))[:200]
            err += app_update._auth_hint(err)
    except FileNotFoundError:
        err = "git is not installed or not on PATH for the server process"
    except subprocess.TimeoutExpired:
        err = "GitHub did not answer within 8 seconds (network, proxy or TLS inspection)"
    except Exception as e:  # noqa: BLE001
        err = str(e)[:200]
    entry["sha"] = sha
    entry["error"] = err
    return sha


# ── Update the app from the web UI ─────────────────────────────────────────────
# Same as UPDATE_Zscaler_Assessment.bat, without a command prompt: pull
# the chosen branch fast-forward (main, or the one the install is on),
# install requirements, restart the server. Localhost only (like write
# mode); every request also passes the origin check. The branch is one
# of app_update.BRANCHES — validated here, before it goes near git.

def _update_allowed() -> None:
    from security import get_bind_host
    if get_bind_host() not in ("127.0.0.1", "localhost", "::1"):
        raise HTTPException(status_code=403, detail="Updating from the web UI is only allowed when the server is bound to localhost.")


def _update_branch(requested: Optional[str]) -> str:
    import app_update
    try:
        return app_update.resolve_branch(_APP_DIR, requested)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/app/update/status")
async def app_update_status(refresh: bool = False, branch: Optional[str] = None):
    """Current build, whether GitHub's `branch` (the one the install is
    on by default) is ahead, the branches an update may switch to, and
    whether a pull would be refused (hand-edited files, not a checkout,
    no git)."""
    import app_update
    target = _update_branch(branch)
    if refresh:
        _LATEST.pop(target, None)
    remote = await asyncio.to_thread(_latest_remote_commit, target)
    st = await asyncio.to_thread(app_update.status, _APP_DIR, remote, target)
    st["remote_error"] = _latest_error(target)
    st["restart_command"] = app_update.restart_command(_APP_DIR)
    return st


class AppUpdateRequest(BaseModel):
    branch: Optional[str] = None   # one of app_update.BRANCHES; default: the branch the install is on


@app.post("/api/app/update")
async def app_update_run(req: Optional[AppUpdateRequest] = None):
    """Fetch, switch to the chosen branch if asked, pull --ff-only,
    install requirements. Reports every step; nothing is deleted or
    overwritten."""
    _update_allowed()
    import app_update
    if app_update.in_container():
        raise HTTPException(status_code=409, detail=app_update.CONTAINER_UPDATE_HELP)
    target = _update_branch(req.branch if req else None)
    result = await asyncio.to_thread(app_update.update, _APP_DIR, branch=target)
    _LATEST.pop(target, None)
    return result


@app.post("/api/app/restart")
async def app_restart():
    """Relaunch the server through the start script and exit this process.
    The page polls /api/health until the new process answers."""
    _update_allowed()
    import app_update
    return await asyncio.to_thread(app_update.schedule_restart, _APP_DIR)


@app.get("/api/checks")
async def list_checks(scope: Optional[str] = None):
    """List all check IDs, sections, and labels. Optional scope filter: dlp, zia, zpa, zcc, genai, automation."""
    if scope == "dlp":
        all_checks = list(REG)
    elif scope == "zia":
        all_checks = [c for c in PLATFORM_REG if c[1].startswith("ZIA")]
    elif scope == "zpa":
        all_checks = [c for c in PLATFORM_REG if c[1].startswith("ZPA")]
    elif scope == "zcc":
        all_checks = [c for c in PLATFORM_REG if c[1].startswith("ZCC")]
    elif scope == "genai":
        all_checks = list(GENAI_REG)
    elif scope == "automation":
        all_checks = list(AUTOMATION_REG)
    elif scope == "zdx":
        all_checks = list(ZDX_REG)
    elif scope == "zidentity":
        all_checks = list(ZID_REG)
    elif scope == "rbac":
        all_checks = list(RBAC_REG)
    else:
        all_checks = list(REG) + PLATFORM_REG + GENAI_REG + list(AUTOMATION_REG) + list(ZDX_REG) + list(ZID_REG) + list(RBAC_REG)

    # Try to enrich with compliance mappings
    try:
        from compliance_mapping import get_compliance_for_check
        return [
            {
                "id": id,
                "section": sec,
                "label": label,
                "compliance": get_compliance_for_check(id),
            }
            for id, sec, label, _ in all_checks
        ]
    except Exception:
        return [{"id": id, "section": sec, "label": label} for id, sec, label, _ in all_checks]


@app.get("/api/checks/export")
async def export_checks(format: str = "csv", scope: Optional[str] = None):
    """Export the full check catalog as CSV, JSON, or Markdown."""
    if scope == "dlp":
        all_checks = list(REG)
    elif scope == "zia":
        all_checks = [c for c in PLATFORM_REG if c[1].startswith("ZIA")]
    elif scope == "zpa":
        all_checks = [c for c in PLATFORM_REG if c[1].startswith("ZPA")]
    elif scope == "zcc":
        all_checks = [c for c in PLATFORM_REG if c[1].startswith("ZCC")]
    elif scope == "genai":
        all_checks = list(GENAI_REG)
    elif scope == "automation":
        all_checks = list(AUTOMATION_REG)
    elif scope == "zdx":
        all_checks = list(ZDX_REG)
    elif scope == "zidentity":
        all_checks = list(ZID_REG)
    elif scope == "rbac":
        all_checks = list(RBAC_REG)
    else:
        all_checks = list(REG) + PLATFORM_REG + GENAI_REG + list(AUTOMATION_REG) + list(ZDX_REG) + list(ZID_REG) + list(RBAC_REG)

    try:
        from compliance_mapping import get_compliance_for_check
    except Exception:
        get_compliance_for_check = lambda x: {}

    suffix = scope or "all"
    fname_base = f"zscaler_checks_{suffix}_{datetime.now().strftime('%Y%m%d')}"

    if format == "json":
        data = [
            {
                "id": id, "section": sec, "label": label,
                "compliance": get_compliance_for_check(id),
            }
            for id, sec, label, _ in all_checks
        ]
        from fastapi.responses import Response
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname_base}.json"'},
        )
    elif format == "md":
        lines = [f"# Zscaler Assessment Checks ({suffix})\n",
                 f"Total: {len(all_checks)} checks\n",
                 f"Generated: {datetime.now().strftime('%Y-%m-%d')}\n",
                 "\n| Check ID | Section | Description | Frameworks |",
                 "|----------|---------|-------------|------------|"]
        for id, sec, label, _ in all_checks:
            comp = get_compliance_for_check(id)
            fw_list = ", ".join(sorted(comp.keys())) if comp else ""
            lines.append(f"| {id} | {sec} | {label} | {fw_list} |")
        from fastapi.responses import Response
        return Response(
            content="\n".join(lines),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{fname_base}.md"'},
        )
    else:  # CSV (default)
        import csv, io
        buf = io.StringIO()
        # Determine all framework keys
        fw_keys = []
        try:
            from compliance_mapping import FRAMEWORK_DESCRIPTIONS
            fw_keys = sorted(FRAMEWORK_DESCRIPTIONS.keys())
        except Exception:
            pass
        writer = csv.writer(buf)
        writer.writerow(["Check ID", "Section", "Description"] + fw_keys)
        for id, sec, label, _ in all_checks:
            comp = get_compliance_for_check(id)
            row = [id, sec, label]
            for fw in fw_keys:
                row.append("; ".join(comp.get(fw, [])))
            writer.writerow(row)
        from fastapi.responses import Response
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{fname_base}.csv"'},
        )


@app.get("/api/frameworks")
async def list_frameworks():
    """List supported compliance frameworks."""
    try:
        from compliance_mapping import list_supported_frameworks
        return list_supported_frameworks()
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/compliance")
async def compliance_summary(request: Request):
    """Return compliance framework alignment summary from assessment results."""
    try:
        from compliance_mapping import get_framework_summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"compliance_mapping not available: {e}")
    data = await request.json()
    results = data.get("checks", [])
    if not results:
        raise HTTPException(status_code=400, detail="No checks in request body")
    return get_framework_summary(results)


@app.post("/api/compliance/drilldown")
async def compliance_drilldown(request: Request):
    """Return per-control drilldown showing met/partially met/not met with evidence."""
    try:
        from compliance_mapping import get_control_drilldown
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"compliance_mapping not available: {e}")
    data = await request.json()
    results = data.get("checks", [])
    if not results:
        raise HTTPException(status_code=400, detail="No checks in request body")
    return get_control_drilldown(results)


@app.post("/api/compliance/report")
async def compliance_report(request: Request):
    """Remember an assessment's compliance view so it can open in its own
    tab (/report/compliance?id=...): the framework summary, the control
    drilldown and the frameworks the assessment page had selected."""
    try:
        from compliance_mapping import get_framework_summary, get_control_drilldown, FRAMEWORK_DESCRIPTIONS
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"compliance_mapping not available: {e}")
    data = await request.json()
    results = data.get("checks", [])
    if not results:
        raise HTTPException(status_code=400, detail="No checks in request body")
    selected = [str(k) for k in (data.get("frameworks") or []) if str(k) in FRAMEWORK_DESCRIPTIONS]
    meta = data.get("metadata") or {}
    rep = {"summary": get_framework_summary(results), "drilldown": get_control_drilldown(results),
           "descriptions": dict(FRAMEWORK_DESCRIPTIONS), "frameworks_selected": selected, "check_count": len(results),
           "metadata": {k: meta.get(k) for k in ("org", "assessor", "vanity_domain", "cloud", "date") if meta.get(k)}}
    rid = _remember_report("compliance", rep, str(meta.get("org") or meta.get("vanity_domain") or ""))
    return {"report_id": rid}


@app.get("/api/compliance/report/{report_id}")
async def compliance_report_get(report_id: str):
    """One compliance report, while it is still in memory."""
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("compliance-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.get("/api/compliance/export/{report_id}")
async def compliance_report_export(report_id: str, format: str = "markdown"):
    """Download a compliance report as Markdown, JSON or Word."""
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("compliance-"):
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if format == "json":
        return JSONResponse(rep, headers={"Content-Disposition": f'attachment; filename="compliance_alignment_{stamp}.json"'})
    keys = rep.get("frameworks_selected") or list(rep.get("summary") or {})
    if format == "csv":
        import csv, io
        buf = io.StringIO(); w = csv.writer(buf)
        w.writerow(["framework", "control", "status", "passing", "failing", "review", "not_applicable", "evidence_check_ids"])
        for k in keys:
            d = (rep.get("drilldown") or {}).get(k) or {}
            for c in d.get("controls") or []:
                w.writerow([d.get("framework_name") or k, c.get("control"), c.get("status"), c.get("passing_count"), c.get("failing_count"),
                            c.get("review_count"), c.get("info_count"), " ".join(str(e.get("check_id")) for e in (c.get("evidence") or []))])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="compliance_alignment_{stamp}.csv"'})
    lines = [f"# Regulatory & Compliance Alignment{' — ' + rep['tenant_label'] if rep.get('tenant_label') else ''}", "",
             f"{rep.get('check_count', 0)} checks mapped. Generated {rep.get('generated_at', '')}.", ""]
    for k in keys:
        sm = (rep.get("summary") or {}).get(k) or {}
        d = (rep.get("drilldown") or {}).get(k) or {}
        pct = sm.get("alignment_pct")
        lines += [f"## {sm.get('name') or k}", "", f"**{sm.get('status', '?')}** — {'not measured' if pct is None else f'{pct}% of mapped checks configured'}, {sm.get('control_count', 0)} controls"
                  + (f": {d.get('met', 0)} met, {d.get('partially_met', 0)} partially met, {d.get('not_met', 0)} not met, {d.get('not_tested', 0)} not tested" if d else ""), ""]
        for c in d.get("controls") or []:
            lines.append(f"- **{c.get('control')}** — {c.get('status')} ({c.get('passing_count', 0)} passing, {c.get('failing_count', 0)} failing, {c.get('review_count', 0)} review)")
            for e in (c.get("evidence") or [])[:8]:
                lines.append(f"  - [{e.get('status')}] {e.get('check_id')} {e.get('label')}{': ' + str(e.get('detail'))[:160] if e.get('detail') else ''}")
        lines.append("")
    return PlainTextResponse("\n".join(lines), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="compliance_alignment_{stamp}.md"'})


@app.get("/report/evalall")
async def report_evalall_page():
    """Evaluate All Rules: the decision flow with the tie-breaker (static/report_evalall.html)."""
    page = os.path.join(STATIC_DIR, "report_evalall.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/report/logs")
async def report_logs_page():
    """Log Analyzer in its own tab: Client Connector log bundles and PAC files (static/report_logs.html)."""
    page = os.path.join(STATIC_DIR, "report_logs.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/help")
async def help_page():
    """Every function of the app explained in plain English (static/help.html)."""
    page = os.path.join(STATIC_DIR, "help.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class LogAnalyzeRequest(BaseModel):
    """Body of the log analyser: the uploaded Client Connector logs or PAC files."""
    files: List[PackUploadFile]


@app.get("/api/logs/catalogue")
async def logs_catalogue():
    """What the Log Analyzer looks for, and the upload limit, for the page."""
    import log_analyzer
    return {"checked": log_analyzer.catalogue(), "max_body_mb": get_max_body_bytes() // (1024 * 1024),
            "accepts": ["Client Connector Export Logs ZIP", ".log / .txt files", ".tar / .tgz / .gz bundles", "PAC files (.pac, .dat, .js)"]}


@app.post("/api/logs/analyze")
async def logs_analyze(req: LogAnalyzeRequest):
    """Analyse uploaded Client Connector logs and PAC files in memory.
    Nothing is written to disk; evidence lines are redacted of secrets."""
    import log_analyzer
    try:
        # Off the event loop: a large (or hostile) upload must not hold up every other request.
        return await asyncio.to_thread(log_analyzer.analyze, [f.model_dump() for f in req.files])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Migrate from another DLP (vendor_migrate) ──────────────────────────
class VendorMigrateInventoryRequest(BaseModel):
    """The vendor and the uploaded policy export."""
    vendor: str = "symantec"
    export: PackUploadFile


class VendorMigrateCompileRequest(BaseModel):
    """The export again (the decisions are bound to its SHA-256) and the
    reviewed decisions: either the JSON object or an uploaded file."""
    vendor: str = "symantec"
    export: PackUploadFile
    decisions: Dict[str, Any]


@app.get("/api/vendor-migrate/vendors")
async def vendor_migrate_vendors():
    """The source vendors the page offers, and the upload limit."""
    import vendor_migrate
    return {"vendors": vendor_migrate.vendors(), "max_body_mb": get_max_body_bytes() // (1024 * 1024),
            "provider_version": vendor_migrate.PROVIDER_VERSION}


@app.post("/api/vendor-migrate/inventory")
async def vendor_migrate_inventory(req: VendorMigrateInventoryRequest):
    """Inventory an export in memory: every policy with its id and name,
    the export's SHA-256, and a decisions template to review. Read-only."""
    import vendor_migrate
    try:
        return vendor_migrate.inventory_upload(req.vendor, req.export.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/vendor-migrate/compile")
async def vendor_migrate_compile(req: VendorMigrateCompileRequest):
    """Compile reviewed decisions against the export, fail-closed: the
    report always, the Terraform (every rule DISABLED) only when nothing
    is blocked. Nothing is written to the tenant or to disk."""
    import vendor_migrate
    try:
        return vendor_migrate.compile_upload(req.vendor, req.export.model_dump(), req.decisions)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/vendor-migrate/workspace")
async def vendor_migrate_workspace(req: VendorMigrateCompileRequest):
    """The compiled migration as a Terraform workspace (.zip): the same file
    layout as the pack hand-off (terraform.tf, providers.tf, variables.tf,
    dictionaries.tf, engines.tf, rules.tf, locals.tf, outputs.tf, README.md,
    .gitignore, terraform.tfvars.example), fmt-clean HCL, with the
    migration report beside it. 409 with the report while anything is
    blocked. Nothing is written to the tenant or to disk."""
    import vendor_migrate
    try:
        out = vendor_migrate.compile_upload(req.vendor, req.export.model_dump(), req.decisions)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not out.get("terraform"):
        raise HTTPException(status_code=409, detail={"cause": "Blocked: answer the questions in the migration report, then compile again.",
                                                     "report": out.get("report")})
    data = vendor_migrate.workspace_zip(out)
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="dlp-check-{out["vendor"]}-migration-terraform.zip"'})


@app.get("/report/vendor")
async def report_vendor_page():
    """Migrate from another DLP in its own tab (static/report_vendor.html)."""
    page = os.path.join(STATIC_DIR, "report_vendor.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/report/compliance")
async def report_compliance_page():
    """Standalone tab for Regulatory & Compliance Alignment (static/report_compliance.html)."""
    page = os.path.join(STATIC_DIR, "report_compliance.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.post("/api/benchmarks")
async def benchmarks_report(request: Request):
    """Best-practice alignment per area (with each deviation's guidance and
    article), the DLP programme stages, framework rows and the journey,
    computed from an assessment report (the `complete` payload or a saved
    JSON)."""
    import benchmarks
    data = await request.json()
    if not isinstance(data, dict) or not data.get("checks"):
        raise HTTPException(status_code=400, detail="No checks in request body")
    return benchmarks.benchmark_report(data)


@app.post("/api/benchmarks/export")
async def benchmarks_export(request: Request, format: str = "markdown"):
    """The same benchmarks as Markdown (default) or JSON, for a customer note."""
    import benchmarks
    data = await request.json()
    if not isinstance(data, dict) or not data.get("checks"):
        raise HTTPException(status_code=400, detail="No checks in request body")
    b = benchmarks.benchmark_report(data)
    org = str((data.get("metadata") or {}).get("org") or "")
    ts = datetime.now().strftime("%Y%m%d")
    if format == "json":
        return Response(content=json.dumps(b, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_benchmarks_{ts}.json"})
    return Response(content=benchmarks.to_markdown(b, org), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_benchmarks_{ts}.md"})


# ═════════════════════════════════════════════════════════════════
# Rule Migration API (Evaluate All Rules mode)
# ═════════════════════════════════════════════════════════════════
# MigrateRequest + _build_client are defined earlier in the file now
# (just above the /api/diagnose/zcc endpoint) so classes which
# inherit from MigrateRequest above the rule-migration block don't
# crash on import. See the comment next to the earlier definition.


# ── DLP Efficacy: dictionary + engine quality scoring ────────────────
# Declared here (not at the top of the route table) because
# DlpEfficacyCorpusRequest inherits from MigrateRequest, which is
# defined just above. Moving this block earlier caused a NameError
# at import time.
class DlpEfficacyCorpusRequest(MigrateRequest):
    """Body of a DLP efficacy corpus test: tenant credentials and the sample text."""
    # User-supplied sample text. Module caps at 256 KB before regex.
    corpus: str = ""
    max_dicts: int = 200


@app.post("/api/dlp/efficacy")
async def dlp_efficacy(req: MigrateRequest):
    """Score every custom DLP dictionary and engine on the tenant.

    Static analysis only — no user content, no outbound calls beyond
    the three read-only endpoints the assessment already uses
    (/zia/dlpDictionaries, /zia/dlpEngines, /zia/webDlpRules).

    Returns per-item 0–100 score + letter grade + specific reasons
    + remediation steps, plus orphan detection and tenant-wide
    efficacy averages."""
    try:
        from dlp_efficacy import analyze
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_efficacy unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(analyze, client)


class DlpEfficacyExportRequest(MigrateRequest):
    """Body of a DLP efficacy export: tenant credentials and the output format."""
    # csv | json | markdown | docx
    format: str = "csv"


@app.post("/api/dlp/efficacy/export")
async def dlp_efficacy_export(req: DlpEfficacyExportRequest):
    """Run the efficacy analysis and return it as a downloadable file.

    Formats: csv (Excel-friendly flat table), json (full nuance graph),
    markdown (pasteable report), docx (reviewer-friendly Word doc with
    color-coded FP risk bands).
    """
    try:
        from dlp_efficacy import analyze, export
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_efficacy unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    analysis = await asyncio.to_thread(analyze, client)
    try:
        body, mime, filename = await asyncio.to_thread(export, analysis, req.format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        # python-docx missing, etc.
        raise HTTPException(status_code=501, detail=str(e))
    from fastapi.responses import Response
    return Response(
        content=body,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/dlp/efficacy/test")
async def dlp_efficacy_corpus_test(req: DlpEfficacyCorpusRequest):
    """Test a user-supplied text sample against every custom
    dictionary's phrases + regex patterns. Runs locally with stdlib
    re — the corpus never leaves this server, never reaches Zscaler,
    never leaves this machine. 256 KB hard cap on input."""
    try:
        from dlp_efficacy import corpus_test
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_efficacy unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(
        corpus_test, client, req.corpus or "", int(req.max_dicts or 200)
    )


# ── Step 1: Assess Current Status ─────────────────────────────────
@app.post("/api/migrate/status")
async def migrate_status(req: MigrateRequest):
    """Step 1: Determine whether tenant is in First-Match-Wins or Evaluate All Rules mode."""
    try:
        from rule_migrator import assess_current_status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    client = await asyncio.to_thread(_build_client, req)
    result = await asyncio.to_thread(assess_current_status, client)
    result["mode_source"] = "auto_detected" if result.get("found_via") else "api_unknown"
    return result


class ManualModeRequest(MigrateRequest):
    """Body for recording the tenant's rule-evaluation mode by hand."""
    mode: str = ""   # "rule_order" | "evaluate_all_rules"


@app.post("/api/migrate/status/manual")
async def migrate_status_manual(req: ManualModeRequest):
    """Step 1 override: accept the user's manual declaration of the current mode
    when the API doesn't expose the toggle (account-level feature flag). Returns
    the same shape as /api/migrate/status so the wizard keeps working."""
    try:
        from rule_migrator import assess_current_status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    m = (req.mode or "").strip().lower()
    if m not in ("rule_order", "evaluate_all_rules"):
        raise HTTPException(status_code=400,
                            detail="mode must be 'rule_order' or 'evaluate_all_rules'")
    client = await asyncio.to_thread(_build_client, req)
    # Still run the real assessment (to get rule counts, posture) but OVERRIDE the mode.
    base = await asyncio.to_thread(assess_current_status, client)
    evaluate_all = (m == "evaluate_all_rules")
    base["evaluate_all_enabled"] = evaluate_all
    base["current_mode"] = "Evaluate All Rules" if evaluate_all else "Rule Order"
    base["mode_source"] = "manual_declaration"
    base["found_via"] = "user-declared (API does not expose this flag in your tenant)"
    base["ready_to_migrate"] = not evaluate_all
    if evaluate_all:
        base["recommendation"] = "✅ You declared this tenant is in Evaluate All Rules mode. No migration needed — focus on ongoing rule tuning."
    else:
        from rule_migrator import _SWITCH
        base["recommendation"] = "You declared this tenant is in Rule Order mode. " + _SWITCH
    return base


# ── Step 2: Download Current Rules ────────────────────────────────
@app.post("/api/migrate/fetch")
async def migrate_fetch(req: MigrateRequest):
    """Step 2: Download the current Inline Web DLP rules."""
    try:
        from rule_migrator import fetch_current_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    client = await asyncio.to_thread(_build_client, req)
    rules = await asyncio.to_thread(fetch_current_rules, client, "web_dlp")
    return {"rule_type": "web_dlp", "count": len(rules), "rules": rules}


# ── Step 3: Optimize with Exceptions ─────────────────────────────
class OptimizeRequest(BaseModel):
    """Body of the Evaluate-All optimiser: the rules and the exceptions to keep."""
    rules: list[dict] = []
    exceptions: dict = {}


@app.post("/api/migrate/optimize")
async def migrate_optimize(req: OptimizeRequest):
    """Step 3: Generate optimized ordering for Evaluate All Rules, with user exceptions."""
    try:
        from rule_migrator import optimize_for_eval_all_with_exceptions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.rules:
        raise HTTPException(status_code=400, detail="No rules provided.")
    return await asyncio.to_thread(optimize_for_eval_all_with_exceptions, req.rules, req.exceptions)


# ── Step 4: Enable Evaluate All Rules ────────────────────────────
class EnableRequest(MigrateRequest):
    """Body for enabling Evaluate All Rules (dry run by default)."""
    dry_run: bool = True


@app.post("/api/migrate/enable")
async def migrate_enable(req: EnableRequest):
    """Step 4: Enable Evaluate All Rules in ZIA Advanced Settings (dry-run by default)."""
    try:
        from rule_migrator import enable_evaluate_all_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.dry_run:
        _security.require_writer()
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(enable_evaluate_all_rules, client, req.dry_run)


# ── Step 4b: Delete All Existing Rules (gated) ───────────────────────
class DeleteAllRequest(MigrateRequest):
    """Body for deleting every Web DLP rule (dry run by default)."""
    dry_run: bool = True


@app.post("/api/migrate/delete-all")
async def migrate_delete_all(req: DeleteAllRequest):
    """Step 4b (optional): Delete every Inline Web DLP rule. Destructive — gated."""
    try:
        from rule_migrator import delete_all_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.dry_run:
        _security.require_writer()
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(delete_all_rules, client, req.dry_run)


# ── Step 5: Post New Rule Order ──────────────────────────────────
class PostRequest(MigrateRequest):
    """Body for posting a proposed rule set (dry run by default; create, update or auto)."""
    proposed_rules: list[dict] = []
    dry_run: bool = True
    mode: str = "auto"  # "auto" | "create" | "update"


@app.post("/api/migrate/post")
async def migrate_post(req: PostRequest):
    """Step 5: Post the optimized rule ordering back to Zscaler (dry-run by default).

    mode=auto    → PUT existing rules, POST new ones
    mode=create  → always POST (use after delete-all)
    mode=update  → always PUT (re-order in place, ids preserved)
    """
    try:
        from rule_migrator import post_new_rule_order
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.proposed_rules:
        raise HTTPException(status_code=400, detail="No proposed_rules provided.")
    if not req.dry_run:
        _security.require_writer()
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(post_new_rule_order, client, req.proposed_rules, req.dry_run, req.mode)


# ── Upload rules (from a JSON backup file) ───────────────────────────────
class UploadRulesRequest(BaseModel):
    """Body for uploading a rule set to analyse."""
    rules: list[dict] = []


@app.post("/api/migrate/upload")
async def migrate_upload(req: UploadRulesRequest):
    """Accept a previously-saved (or hand-edited) JSON rule list and return it
    normalized + analyzed. Pair with /api/migrate/optimize for re-ordering or
    /api/migrate/post (mode=create) to push to a freshly-emptied tenant."""
    try:
        from rule_migrator import analyze_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.rules:
        raise HTTPException(status_code=400, detail="No rules in upload.")
    return {
        "count": len(req.rules),
        "rules": req.rules,
        "analysis": analyze_rules(req.rules),
    }


# ── Manual reorder (accept any explicit ordering) ────────────────────────────────
class ReorderRequest(BaseModel):
    """Body for reordering the tenant's Web DLP rules."""
    rules: list[dict] = []
    order: list = []  # list of rule IDs (or names) in desired order


@app.post("/api/migrate/reorder")
async def migrate_reorder(req: ReorderRequest):
    """Re-order an in-memory rule list by an explicit ID/name sequence the user picked in the GUI."""
    if not req.rules or not req.order:
        raise HTTPException(status_code=400, detail="rules and order are required.")
    by_id = {str(r.get("id")): r for r in req.rules if r.get("id") is not None}
    by_name = {r.get("name"): r for r in req.rules if r.get("name")}
    out, missing = [], []
    seen = set()
    for token in req.order:
        key = str(token)
        rule = by_id.get(key) or by_name.get(token)
        if rule and id(rule) not in seen:
            out.append(rule)
            seen.add(id(rule))
        else:
            missing.append(token)
    # Append any rules the user didn't explicitly position (preserve them at the end)
    for r in req.rules:
        if id(r) not in seen:
            out.append(r)
    for i, r in enumerate(out, 1):
        r["_proposed_order"] = i
    return {
        "count": len(out),
        "proposed_rules": out,
        "missing_tokens": missing,
    }


@app.post("/api/migrate/analyze")
async def migrate_analyze(request: Request):
    """Analyze rules for Evaluate All Rules migration issues."""
    try:
        from rule_migrator import analyze_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    data = await request.json()
    rules = data.get("rules", [])
    if not rules:
        raise HTTPException(status_code=400, detail="No rules provided in request body.")
    return analyze_rules(rules)


@app.post("/api/migrate/plan")
async def migrate_plan(request: Request):
    """Generate full migration plan: analysis, reordered rules, diff, checklist."""
    try:
        from rule_migrator import generate_migration_plan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    data = await request.json()
    rules = data.get("rules", [])
    if not rules:
        raise HTTPException(status_code=400, detail="No rules provided in request body.")
    return generate_migration_plan(rules)


@app.post("/api/migrate/export")
async def migrate_export(request: Request, format: str = "json"):
    """Export proposed rule order as importable JSON or CSV."""
    try:
        from rule_migrator import generate_migration_plan, export_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    data = await request.json()
    rules = data.get("rules", [])
    if not rules:
        raise HTTPException(status_code=400, detail="No rules provided in request body.")
    plan = generate_migration_plan(rules)
    content = export_rules(plan["proposed_order"], format=format)
    from fastapi.responses import Response
    mime = "application/json" if format == "json" else "text/csv"
    ext = "json" if format == "json" else "csv"
    fname = f"zscaler_eval_all_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    return Response(
        content=content,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


def _get_checks(scope: str = "dlp", scopes: list = None):
    """Get the check list for the given scope or list of scopes."""
    if scopes:
        # New checkbox-style scope selection
        out = []
        seen = set()
        if "dlp" in scopes:
            for c in REG:
                if c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "zia_extras" in scopes:
            for c in PLATFORM_REG:
                if c[1].startswith("ZIA") and c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "zpa" in scopes:
            for c in PLATFORM_REG:
                if c[1].startswith("ZPA") and c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "zcc" in scopes:
            for c in PLATFORM_REG:
                if c[1].startswith("ZCC") and c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "genai" in scopes:
            for c in GENAI_REG:
                if c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "automation" in scopes:
            for c in AUTOMATION_REG:
                if c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "zdx" in scopes:
            for c in ZDX_REG:
                if c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "zidentity" in scopes:
            for c in ZID_REG:
                if c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        if "rbac" in scopes:
            for c in RBAC_REG:
                if c[0] not in seen:
                    seen.add(c[0]); out.append(c)
        return out
    # Legacy scope string
    if scope == "full" or scope == "all":
        return list(REG) + PLATFORM_REG + list(AUTOMATION_REG) + list(ZDX_REG) + list(ZID_REG) + list(RBAC_REG)
    elif scope == "automation":
        return list(AUTOMATION_REG)
    elif scope == "zdx":
        return list(ZDX_REG)
    elif scope == "zidentity":
        return list(ZID_REG)
    elif scope == "rbac":
        return list(RBAC_REG)
    elif scope == "zia":
        return list(REG) + [c for c in PLATFORM_REG if c[1].startswith("ZIA")]
    elif scope == "zpa":
        return [c for c in PLATFORM_REG if c[1].startswith("ZPA")]
    elif scope == "zcc":
        return [c for c in PLATFORM_REG if c[1].startswith("ZCC")]
    return list(REG)  # dlp default


@app.post("/api/assess")
async def assess_stream(req: AssessRequest):
    """Run assessment with SSE streaming."""
    # A saved profile fills whatever the form left blank (remembered secrets
    # included) and names the organisation; the environment and
    # tenant_config.json follow, as for every other endpoint.
    profile = None
    if req.profile_id:
        try:
            import tenant_profiles
            profile = tenant_profiles.get(req.profile_id, with_secret=True)
        except Exception:
            profile = None
        if profile:
            req.org_name = req.org_name if req.org_name not in ("", "Unknown") else (profile.get("org_name") or req.org_name)
    # Validate inputs BEFORE the SSE stream opens so failures return 400, not 200+stream
    creds = _validate_creds(_tenant_creds(req))
    cloud, vd = creds["cloud"], creds["vanity_domain"]
    checks = _get_checks(req.scope, req.scopes)
    # The Scope page's channel ownership: a channel covered by an alternative
    # solution has its checks reported as not in scope instead of read
    # (channel_scope); the rest run. The findings keep their section order.
    import channel_scope as _chs
    checks, skipped_checks, check_order = _chs.partition(checks, req.channels)
    total_all = len(checks) + len(skipped_checks)
    # The journey (pack deficiencies) is measured against the profile's
    # packs, or the packs of its industry when none are ticked.
    import vertical as _vertical
    _scope = _vertical.scope_for(profile, all_packs=[p["id"] for p in __import__("dlp_importer").discover_packs()])
    journey_pack_ids = list(_scope["packs"]) if _scope["scoped"] else [str(b) for b in (profile or {}).get("baseline_packs") or []]

    async def event_generator():
        results = []
        try:
            yield _sse("auth", {"status": "authenticating", "auth_method": creds["auth_method"]})

            client = _raw_client(creds)
            auth_result = await asyncio.to_thread(client.auth)

            if auth_result is not True:
                reason = ""
                if isinstance(auth_result, tuple) and len(auth_result) == 2:
                    reason = str(auth_result[1])
                reason = tenant_auth.mask_secrets(reason or "", creds)
                yield _sse("error", {"message": f"Authentication failed: {reason[:200]}"})
                return

            yield _sse("auth", {"status": "ok", "auth_method": creds["auth_method"],
                                "note": ("Signed in through the classic ZIA API: ZIA checks only; ZPA, Client Connector and ZDX checks "
                                         "are reported as not available.") if creds["auth_method"] == tenant_auth.LEGACY else ""})
            for skipped in skipped_checks:
                yield _sse("check", skipped)
            yield _sse("progress", {"total": total_all, "completed": len(skipped_checks),
                                    "pct": round(len(skipped_checks) / max(total_all, 1) * 100)})

            # Checks run on a small pool of threads (the API's rate limit is
            # shared by the Client's pacer), each result is streamed the moment
            # it lands, and a check that is still running after CHECK_TIMEOUT
            # is reported as timed out without holding up the others. The
            # pool is per run, so a thread stuck in a black-holed request can
            # never starve the next run.
            # NOTE: no loop variable here may be named `sec` — that shadows the
            # outer `sec` (client_secret) through Python's closure rules.
            loop = asyncio.get_running_loop()
            inbox: asyncio.Queue = asyncio.Queue()
            started: Dict[int, float] = {}

            def _run_one(idx, check_id, section, label, fn):
                started[idx] = time.time()
                try:
                    r = fn(client)
                except Exception as ex:  # noqa: BLE001
                    r = R(R.ERROR, f"{label}: Could not complete check. {str(ex)[:120]}")  # "Could not be checked", never "Not configured"
                loop.call_soon_threadsafe(inbox.put_nowait, (idx, r))

            pool = ThreadPoolExecutor(max_workers=ASSESS_WORKERS, thread_name_prefix="assess")
            for idx, chk in enumerate(checks):
                pool.submit(_run_one, idx, *chk)
            done: Dict[int, Dict[str, Any]] = {}
            last_keepalive = time.time()
            run_started = time.time()

            def _finish(idx, r):
                check_id, section, label, _fn = checks[idx]
                if not hasattr(r, "status") or not hasattr(r, "detail"):
                    r = R(R.ERROR, f"{label}: Invalid check result.")
                result = {"id": check_id, "section": section, "label": label,
                          "status": str(r.status), "detail": str(r.detail)[:500]}
                try:
                    import plain_english
                    plain_english.enrich(result)      # what we found / what it means / what to do / outcome
                except Exception:  # noqa: BLE001
                    pass
                done[idx] = result
                return result

            while len(done) < len(checks):
                landed = []
                try:
                    landed.append(await asyncio.wait_for(inbox.get(), timeout=1.0))
                except asyncio.TimeoutError:
                    pass
                while not inbox.empty():
                    landed.append(inbox.get_nowait())
                now = time.time()
                fresh = [_finish(idx, r) for idx, r in landed if idx not in done]
                for idx, t0 in list(started.items()):
                    if idx not in done and now - t0 > CHECK_TIMEOUT:
                        fresh.append(_finish(idx, R(R.ERROR, f"{checks[idx][2]}: Check timed out after {CHECK_TIMEOUT} seconds; the tenant did not answer in time.")))
                try:
                    for result in fresh:
                        yield _sse("check", result)
                    if fresh:
                        yield _sse("progress", {
                            "total": total_all, "completed": len(done) + len(skipped_checks),
                            "pct": round((len(done) + len(skipped_checks)) / max(total_all, 1) * 100),
                            "current": f"{fresh[-1]['id']}: {fresh[-1]['label']}",
                            "running": len([i for i in started if i not in done]),
                            "elapsed": round(now - run_started),
                        })
                    if now - last_keepalive > 10:
                        yield ": keepalive\n\n"
                        last_keepalive = now
                except Exception:
                    # Client disconnected; just keep collecting results
                    pass
            pool.shutdown(wait=False, cancel_futures=True)
            results = _chs.merge(check_order, [done[i] for i in range(len(checks))], skipped_checks)

            # Results first: the report goes out as soon as the checks are
            # in. The data-governance journey (one read-only preflight per
            # baseline pack) follows as its own event so nobody waits on it.
            want_journey = bool(_journey_packs(journey_pack_ids)) and (
                not req.scopes or "dlp" in req.scopes or req.scope in ("full", "dlp"))

            try:
                secs, overall = compute(results)
            except Exception:  # noqa: BLE001
                secs, overall = {}, None   # nothing measurable: "Not assessed", never an invented number

            report = {
                "metadata": {
                    "tool": "Zscaler Platform Assessment",
                    "version": "3.0",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "org": req.org_name,
                    "assessor": req.assessor,
                    "cloud": req.cloud,
                    "total_checks": total_all,
                    "scope": ",".join(req.scopes) if req.scopes else req.scope,
                    "elapsed_seconds": round(time.time() - run_started, 1),
                    "api_requests": getattr(client, "requests_made", None),
                },
                "score": overall,
                "maturity": maturity(overall),
                "sections": secs,
                "checks": results,
                "critical": [r for r in results if r["status"] == "FAIL"],
                "review": [r for r in results if r["status"] == "REVIEW"],
                "journey": {"status": "pending"} if want_journey else None,
                "profile": None,
                # The Scope page's declaration and what it did (channel_scope.coverage).
                "channel_coverage": _chs.coverage(req.channels, skipped_checks),
            }

            def _record_history(rep):
                if not profile:
                    return None
                try:
                    import tenant_profiles
                    updated = tenant_profiles.add_history(profile["id"], tenant_profiles.snapshot(rep))
                    if updated:
                        return {"id": updated["id"], "name": updated.get("name"),
                                "history": (updated.get("history") or [])[-12:]}
                except Exception:  # noqa: BLE001 — history is best effort
                    return None
                return None

            # Partial scans are reported as such: which checks the API client
            # was not allowed to run, and what to grant for a full scan.
            try:
                import permissions as _perm
                report["permissions"] = _perm.assessment_permission_summary(results, req.scopes or [req.scope])
            except Exception:  # noqa: BLE001
                report["permissions"] = None
            # Execution vs coverage, one vocabulary for every surface: how many
            # checks ran, how many the client was not permitted to run, what the
            # score divides over (permissions.assessment_summary; docs/SCORING.md).
            try:
                report["summary"] = _perm.assessment_summary(results)
            except Exception:  # noqa: BLE001
                report["summary"] = None
            if not want_journey:
                report["profile"] = _record_history(report)
            report["scope"] = _scope   # the profile's industry: frameworks and packs the suggestions are limited to
            yield _sse("complete", report)

            if want_journey:
                journey = None
                try:
                    packs = _journey_packs(journey_pack_ids)
                    yield _sse("progress", {"total": total_all, "completed": total_all, "pct": 100,
                                            "current": f"Data governance journey: measuring the tenant against {len(packs)} policy packs"})
                    sdk = await asyncio.to_thread(_build_sdk_client, creds)
                    notes: asyncio.Queue = asyncio.Queue()

                    def _note(i, n, pack_id):
                        loop.call_soon_threadsafe(notes.put_nowait, (i, n, pack_id))

                    task = loop.run_in_executor(None, lambda: _journey_for(sdk, packs, progress=_note))
                    deadline = time.time() + JOURNEY_TIMEOUT
                    while not task.done():
                        if time.time() > deadline:
                            raise TimeoutError(f"the journey measurement did not finish within {JOURNEY_TIMEOUT} seconds")
                        try:
                            i, n, pack_id = await asyncio.wait_for(notes.get(), timeout=5.0)
                            yield _sse("progress", {"total": total_all, "completed": total_all, "pct": 100,
                                                    "current": f"Data governance journey: {pack_id} ({i + 1} of {n})", "journey": True})
                        except asyncio.TimeoutError:
                            yield ": keepalive\n\n"
                    journey = task.result()
                    journey["tenant_label"] = tenant_auth.record_label(creds)
                except Exception as ex:  # noqa: BLE001
                    journey = {"status": "error", "error": tenant_auth.mask_secrets(str(ex), creds)[:200]}
                report["journey"] = journey
                report["profile"] = _record_history(report)
                yield _sse("journey", {"journey": journey, "profile": report["profile"]})

        except Exception as e:
            # Catch-all: never let the generator crash the stream
            yield _sse("error", {"message": f"Server error: {str(e)[:200]}"})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/api/report/docx")
async def generate_docx(request: Request):
    """Generate a Word doc from assessment results."""
    import traceback as _tb
    try:
        from report_docx import generate_report
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"python-docx not installed: {e}. Run: pip install python-docx")

    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON in request body: {e}")

    results = data.get("checks", [])
    cfg = dict(data.get("metadata") or {})
    # The Scope page's channel declaration rides along for the Channel Coverage section.
    if isinstance(data.get("channel_coverage"), dict):
        cfg["channel_coverage"] = data["channel_coverage"]

    if not results:
        raise HTTPException(status_code=400, detail="No checks in request body — cannot generate report.")

    try:
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name
        generate_report(results, cfg, tmp_path, compute, maturity)
    except Exception as e:
        # Surface the real error to the browser instead of a generic 500
        tb = _tb.format_exc()
        print(f"\n=== Word generation failed ===\n{tb}===\n", flush=True)
        raise HTTPException(status_code=500, detail=f"Word generation error: {type(e).__name__}: {str(e)[:300]}")

    org = re.sub(r"[^A-Za-z0-9_-]+", "_", str(cfg.get("org", "report"))).strip("_")[:60] or "report"
    # The temp file holds the whole assessment: remove it once it has been sent.
    return FileResponse(tmp_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        filename=f"zscaler_{org}_{datetime.now().strftime('%Y%m%d')}.docx",
                        background=BackgroundTask(_unlink_quietly, tmp_path))


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


# ── Bypass / Non-Inspected Traffic Inventory ────────────────────────────────────
# Generated reports are kept in memory (last 20) so a report can open in
# its own tab and be exported without sending credentials again.
_REPORTS: Dict[str, Dict[str, Any]] = {}
_REPORTS_MAX = 20


def _remember_report(kind: str, report: Dict[str, Any], label: str = "") -> str:
    import secrets
    rid = f"{kind}-{secrets.token_urlsafe(9)}"
    report = dict(report)
    report["report_id"] = rid
    report["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if label:
        report["tenant_label"] = label
    _REPORTS[rid] = report
    while len(_REPORTS) > _REPORTS_MAX:
        _REPORTS.pop(next(iter(_REPORTS)))
    return rid


@app.get("/report/view")
async def report_view_page():
    """Standalone tab that mirrors a tool dialog (see static/report_view.html)."""
    page = os.path.join(STATIC_DIR, "report_view.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Reference pages ──────────────────────────────────────────────────
# Self-contained HTML references an engineer keeps next to the tool (the
# data-security portfolio framework, the AI security frameworks, how the
# framework machine fits together). Served from static/reference/ under
# their own routes so the sidebar can open them like any other page. They
# carry their own inline scripts and styles; nothing external is loaded
# (the app's Content-Security-Policy applies to them too).
REFERENCE_PAGES: List[Dict[str, str]] = [
    {"slug": "data-security-portfolio-framework", "name": "Data Security Portfolio Framework",
     "blurb": "Zscaler's data-security portfolio as an operating program: coverage, proposal story, proof-of-value plan."},
    {"slug": "ai-security-framework", "name": "Public AI Security Framework",
     "blurb": "AI security controls as an operating model: coverage by phase, a customer-ready story, a testable proof plan."},
    {"slug": "genai-security-framework", "name": "Public GenAI Security Framework",
     "blurb": "The generative-AI subset of the AI security framework, with the same story builder and proof plan."},
    {"slug": "framework-machine", "name": "The Framework Machine",
     "blurb": "How the framework pages are built and kept portable: the six components, the assembly line, the setup order."},
    {"slug": "data-security-architect", "name": "Data Security Architect",
     "blurb": "Zscaler's data-security reference architecture: every DLP channel's flow, dictionaries and engines, evidence to Workflow Automation, setup sequences, symptom walkbacks."},
]
_REFERENCE_DIR = os.path.join(STATIC_DIR, "reference")


@app.get("/api/reference")
async def reference_list():
    """The reference pages the sidebar offers, with their routes."""
    out = []
    for p in REFERENCE_PAGES:
        path = os.path.join(_REFERENCE_DIR, f"{p['slug']}.html")
        out.append({**p, "href": f"/reference/{p['slug']}", "available": os.path.exists(path),
                    "bytes": os.path.getsize(path) if os.path.exists(path) else 0})
    return {"pages": out}


@app.get("/reference/{slug}")
async def reference_page(slug: str):
    """One reference page, by its slug in REFERENCE_PAGES (never an
    arbitrary path)."""
    page = next((p for p in REFERENCE_PAGES if p["slug"] == slug), None)
    if page is None:
        raise HTTPException(status_code=404, detail="No such reference page.")
    path = os.path.join(_REFERENCE_DIR, f"{slug}.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="reference page missing")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    # Every tab can return to the assessment page: the shared theme script
    # adds a "Back to the assessment" button to a page that has no link home.
    tag = '<script src="/static/report_theme.js"></script>\n'
    pos = html.rfind("</body>")
    html = html[:pos] + tag + html[pos:] if pos >= 0 else html + tag
    return HTMLResponse(html, headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/report/flow")
async def report_flow_page():
    """Standalone tab for the Deploy Policy Packs dependency flow (static/report_flow.html).
    The page draws the diagram itself from the plan the assessment tab hands it."""
    page = os.path.join(STATIC_DIR, "report_flow.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/report/bypass")
async def report_bypass_page():
    """Standalone tab for the bypass report (see static/report_bypass.html)."""
    page = os.path.join(STATIC_DIR, "report_bypass.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/api/report/bypass/{report_id}")
async def report_bypass_get(report_id: str):
    """One bypass inventory report, while it is still in memory."""
    rep = _REPORTS.get(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.get("/api/report/bypass/export/{report_id}")
async def report_bypass_export_cached(report_id: str, format: str = "csv"):
    rep = _REPORTS.get(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    return await _bypass_export_response(rep, format)


@app.post("/api/report/bypass")
async def report_bypass(req: MigrateRequest):
    """Generate the bypass-inventory report (JSON). Read-only. The response
    carries report_id for /report/bypass?id=... and the export links."""
    try:
        from bypass_report import generate_bypass_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bypass_report unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_bypass_report, client)
    rid = _remember_report("bypass", report, f"{req.vanity_domain or '?'} ({req.cloud or 'production'})")
    return _REPORTS[rid]


class BypassExportRequest(MigrateRequest):
    format: str = "csv"  # csv | markdown | json | docx


async def _bypass_export_response(report: Dict[str, Any], fmt: str):
    from bypass_report import to_csv, to_markdown
    from fastapi.responses import Response, FileResponse
    fmt = (fmt or "csv").lower()
    if fmt not in ("csv", "markdown", "md", "json", "docx", "word", "doc"):
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "csv":
        return Response(content=to_csv(report), media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.csv"})
    if fmt in ("markdown", "md"):
        return Response(content=to_markdown(report), media_type="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.md"})
    if fmt in ("docx", "word", "doc"):
        try:
            from bypass_report import to_docx
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"python-docx not installed: {e}. Run: pip install python-docx")
        # A private, unpredictable temp file (owner-only), removed once sent.
        fd, output_path = tempfile.mkstemp(suffix=".docx", prefix="zscaler_bypass_")
        os.close(fd)
        try:
            await asyncio.to_thread(to_docx, report, output_path)
        except ImportError as e:
            _unlink_quietly(output_path)
            raise HTTPException(status_code=500, detail=f"python-docx missing: {e}. Run: pip install python-docx")
        except Exception as e:
            _unlink_quietly(output_path)
            raise HTTPException(status_code=500, detail=f"Word generation failed: {type(e).__name__}: {str(e)[:300]}")
        return FileResponse(output_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            filename=f"zscaler_bypass_{ts}.docx", background=BackgroundTask(_unlink_quietly, output_path))
    return Response(content=json.dumps(report, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.json"})


# ── Data Flow Map (the exact path a transaction takes through the tenant) ──────
class DataFlowRequest(MigrateRequest):
    destinations: List[str] = []      # traffic-class keys, app names, category ids or hostnames; [] = every traffic class
    platform: str = "windows"


class DataFlowTraceRequest(BaseModel):
    destination: str = ""
    network: str = "off"
    platform: str = "windows"


@app.get("/report/dataflow")
async def report_dataflow_page():
    """Standalone tab for the Data Flow Map (static/report_dataflow.html)."""
    page = os.path.join(STATIC_DIR, "report_dataflow.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.post("/api/report/data-flow")
async def report_data_flow(req: DataFlowRequest):
    """Trace every traffic class (or the given destinations) through the
    tenant: Client Connector app profile and forwarding profile, PAC, then
    the data security controls in ZIA's request order (Understanding
    Policy Enforcement): Cloud App Control (before URL Filtering), URL
    filtering, SSL inspection, File Type Control, Web DLP and what happens
    after a match (logs, Incident Receiver, Workflow Automation), plus the
    endpoint, SaaS and email channels, with each policy pack's coverage
    on the path. Controls that are not data-leak controls are not traced.
    Read-only; carries report_id for /report/dataflow?id=... and the
    exports."""
    try:
        from data_flow import generate_data_flow_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"data_flow unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    plat = req.platform if req.platform in ("windows", "macos", "ios", "android", "linux") else "windows"
    dests = [str(d)[:200] for d in (req.destinations or [])][:40]
    try:
        report = await asyncio.to_thread(generate_data_flow_report, client, dests or None, plat)
    except Exception as e:  # noqa: BLE001
        # The tracer's own failure is not a secret: name it so the tab can
        # say what went wrong instead of "internal error".
        import traceback
        print(f"[error] data flow map: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"The tracer failed ({type(e).__name__}: {str(e)[:300]}). The full traceback is in server.log; please report it.")
    rid = _remember_report("dataflow", report, f"{req.vanity_domain or '?'} ({req.cloud or 'production'})")
    return _REPORTS[rid]


# ── Live DLP Feed ────────────────────────────────────────────────────
@app.get("/report/live")
async def report_live_page():
    """Standalone tab for the Live DLP Feed (static/report_live.html)."""
    page = os.path.join(STATIC_DIR, "report_live.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Path Analyzer ─────────────────────────────────────────────────────
@app.get("/report/path")
async def report_path_page():
    """Standalone tab for the Path Analyzer (static/report_path.html)."""
    page = os.path.join(STATIC_DIR, "report_path.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class PathAnalyzerRequest(MigrateRequest):
    """Body of the Path Analyzer: what the user would type, the network the
    device is on, the platform, and optionally the id of a tenant read to
    reuse (a Data Flow Map or an earlier analysis)."""
    destination: str = ""
    network: str = "off"
    platform: str = "windows"
    report_id: str = ""


def _run_path_analysis(client, req: PathAnalyzerRequest, snapshot, label: str, log, cancel) -> Dict[str, Any]:
    """The analysis itself, shared by the job the page follows and the
    waiting endpoint. A fresh tenant read is remembered as a Data Flow
    Map report so the next destination reuses it (`report_id`)."""
    import path_analyzer
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    out = path_analyzer.analyze(client, req.destination, req.network, req.platform, snapshot=snapshot, log=_log,
                                cancel=(lambda: cancel.is_set()) if cancel is not None else None)
    cache = out.pop("snapshot_for_cache", None)
    if cache is not None:
        rid = _remember_report("dataflow", {"summary": {}, "platform": out["platform"], "networks": path_analyzer.NETWORKS, "platforms": path_analyzer.PLATFORMS,
                                            "destinations": [], "traces": [], "packs": [], "diagnostics": cache.get("diagnostics") or [],
                                            "client_connector": cache["client_connector"], "snapshot": cache["snapshot"], "sources": {}}, label)
        out["report_id"] = rid
    else:
        out["report_id"] = req.report_id
    out["tenant_label"] = label
    out["logs"] = logs
    return out


async def _path_analysis_inputs(req: PathAnalyzerRequest):
    import path_analyzer
    try:
        path_analyzer.parse_destination(req.destination)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    snapshot = _REPORTS.get(req.report_id) if req.report_id and req.report_id.startswith("dataflow-") else None
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    return client, snapshot, tenant_auth.label(creds)


@app.post("/api/path-analyzer/start")
async def path_analyzer_start(req: PathAnalyzerRequest):
    """Start the Path Analyzer as a job the page follows (the first run
    reads the tenant, a minute of API calls; later runs reuse that read
    through `report_id` and only look the destination up). Poll
    GET /api/dlp-packs/jobs/{job_id}."""
    import pack_jobs
    client, snapshot, label = await _path_analysis_inputs(req)
    job = pack_jobs.start("path", lambda log, cancel: _run_path_analysis(client, req, snapshot, label, log, cancel), label=req.destination[:80])
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/path-analyzer")
async def path_analyzer_run(req: PathAnalyzerRequest):
    """The same analysis, waited for (for scripts)."""
    client, snapshot, label = await _path_analysis_inputs(req)
    return await asyncio.to_thread(_run_path_analysis, client, req, snapshot, label, None, None)


@app.get("/api/report/data-flow/{report_id}")
async def report_data_flow_get(report_id: str):
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("dataflow-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.post("/api/report/data-flow/{report_id}/trace")
async def report_data_flow_trace(report_id: str, req: DataFlowTraceRequest):
    """Trace one destination the user typed (app, category or hostname)
    against the stored tenant snapshot; no tenant call."""
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("dataflow-"):
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    from data_flow import trace_from_report
    if not req.destination.strip():
        raise HTTPException(status_code=400, detail="Enter a cloud application, URL category or hostname.")
    return await asyncio.to_thread(trace_from_report, rep, req.destination.strip()[:200], req.network, req.platform)


@app.get("/api/report/data-flow/export/{report_id}")
async def report_data_flow_export(report_id: str, format: str = "markdown"):
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("dataflow-"):
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    from data_flow import to_markdown as df_md
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    if (format or "").lower() == "json":
        return Response(content=json.dumps(rep, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_dataflow_{ts}.json"})
    return Response(content=df_md(rep, rep.get("tenant_label", "")), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_dataflow_{ts}.md"})


# ── SSL Inspection Flow (what inline DLP can and cannot see) ───────────────────
@app.get("/report/sslflow")
async def report_sslflow_page():
    """Standalone tab for the SSL inspection flow diagram (static/report_sslflow.html)."""
    page = os.path.join(STATIC_DIR, "report_sslflow.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.post("/api/report/ssl-flow")
async def report_ssl_flow(req: MigrateRequest):
    """Walk the SSL inspection rules per DLP-relevant traffic class, map the
    inline Web DLP rules over them and list the gaps. Read-only; the
    response carries report_id for /report/sslflow?id=... and exports."""
    try:
        from ssl_flow import generate_ssl_flow_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ssl_flow unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_ssl_flow_report, client)
    rid = _remember_report("sslflow", report, f"{req.vanity_domain or '?'} ({req.cloud or 'production'})")
    return _REPORTS[rid]


@app.get("/api/report/ssl-flow/{report_id}")
async def report_ssl_flow_get(report_id: str):
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("sslflow-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.get("/api/report/ssl-flow/export/{report_id}")
async def report_ssl_flow_export(report_id: str, format: str = "csv"):
    from fastapi.responses import Response
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("sslflow-"):
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    from ssl_flow import to_csv as sf_csv, to_markdown as sf_md
    fmt = (format or "csv").lower()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "csv":
        return Response(content=sf_csv(rep), media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_ssl_flow_{ts}.csv"})
    if fmt in ("markdown", "md"):
        return Response(content=sf_md(rep), media_type="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_ssl_flow_{ts}.md"})
    if fmt == "json":
        return Response(content=json.dumps(rep, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_ssl_flow_{ts}.json"})
    raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")


@app.post("/api/report/bypass/export")
async def report_bypass_export(req: BypassExportRequest):
    """Generate and download the bypass report in csv / markdown / json / docx."""
    try:
        from bypass_report import generate_bypass_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bypass_report unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_bypass_report, client)
    return await _bypass_export_response(report, req.format)


# ── Updates: check for new Zscaler APIs / SDK / best practices ──────────────────
@app.get("/api/updates/sources")
async def updates_sources():
    """Enumerate the sources the update-checker monitors."""
    try:
        from zscaler_update_check import SOURCES
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"update checker unavailable: {e}")
    return [
        {"key": s["key"], "name": s["name"], "importance": s.get("importance"),
         "type": s["type"], "why": s.get("why", ""),
         "url": s.get("url") or (f"https://pypi.org/project/{s['package']}/" if s.get("package") else None)}
        for s in SOURCES
    ]


@app.post("/api/updates/check")
async def updates_check(req: UpdateCheckRequest):
    """
    Check Zscaler upstream sources (SDK on PyPI + help-center pages)
    for changes since the last time this was run. Returns a per-source
    status: new | changed | unchanged | error.

    Fetches are allowlisted to pypi.org and help.zscaler.com. No
    credentials are required for this endpoint.
    """
    try:
        from zscaler_update_check import check_for_updates, reset_cache
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"update checker unavailable: {e}")
    if req.reset:
        await asyncio.to_thread(reset_cache)
    return await asyncio.to_thread(check_for_updates, False, req.only, req.skip_tls_verify)


@app.post("/api/updates/reset-cache")
async def updates_reset():
    """Clear the last-seen cache — next check reports every source as 'new'."""
    try:
        from zscaler_update_check import reset_cache
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"update checker unavailable: {e}")
    ok = await asyncio.to_thread(reset_cache)
    return {"ok": bool(ok)}


def _port_problem(host: str, port: int) -> Optional[str]:
    """Why the server could not listen on host:port, in plain words, or
    None when the address is free. Checked before uvicorn starts, because
    uvicorn reports a taken port as a bare errno and exits on its own."""
    import errno
    import socket
    try:
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, 10048):
            return (f"port {port} on {host} is already in use. Another copy of the app is probably running "
                    f"(STOP_Zscaler_Assessment.bat or ./stop.sh stops it), or set ZSCALER_PORT to a free port and start again.")
        if e.errno in (errno.EADDRNOTAVAIL, errno.EACCES, 10049, 10013):
            return (f"{host}:{port} cannot be used: {e.strerror or e}. Check ZSCALER_BIND_HOST (an address this machine owns; "
                    f"127.0.0.1 is the default) and ZSCALER_PORT (ports below 1024 need administrator rights).")
        return f"{host}:{port} cannot be used: {e}"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    """Start the web server the way the launchers, the installer's
    `dlp-check` command and the container do.

    Configuration is read from the environment (ZSCALER_BIND_HOST,
    ZSCALER_PORT, ZSCALER_UI_AUTH, ZSCALER_OPEN_BROWSER, ZSCALER_DEBUG;
    see security.py). Returns the process exit code: 0 when the server
    stopped normally, 2 when it could not start (the port is taken, the
    address cannot be bound, the token file cannot be written), with the
    reason printed in plain words instead of a traceback."""
    import uvicorn

    host = get_bind_host()
    port = get_port()
    print("\n  Zscaler Platform Assessment")
    problem = _port_problem(host, port)
    if problem:
        print(f"\n  Could not start: {problem}\n", file=sys.stderr)
        return 2
    # Inside the container the server listens on 0.0.0.0 and docker-compose
    # publishes it on the host's 127.0.0.1 only, so the address a person
    # opens is localhost, not 0.0.0.0 (which is not an address to browse to).
    in_container = os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1"
    # In a container the address a person opens uses the host's port, which
    # can differ from the port inside (DLP_CHECK_HOST_PORT, e.g. 8001 when a
    # local install already has 8000).
    shown_port = port
    if in_container:
        hp = os.environ.get("DLP_CHECK_HOST_PORT", "").strip()
        if hp.isdigit() and 0 < int(hp) < 65536:
            shown_port = int(hp)
    open_url = f"http://{('localhost' if host == '127.0.0.1' or (in_container and host == '0.0.0.0') else host)}:{shown_port}/"
    if _sso.sso_enabled():
        # Each person signs in at the identity provider; the static UI token
        # is refused, so it is neither printed nor written to ui_token.txt.
        print("  Sign-in: through your identity provider (SSO); the UI token is not used.")
    elif _security.ui_auth_enabled():
        try:
            token_path = _security.write_ui_token_file(os.environ.get("DLP_CHECK_UI_TOKEN_DIR") or _APP_DIR)
        except OSError as e:
            print(f"  Could not write the UI token file ({e}). The token is printed below; set DLP_CHECK_UI_TOKEN_DIR to a writable folder to keep a copy.")
            token_path = None
        open_url += f"?token={_security.ui_token()}"
        print(f"  UI token: {_security.ui_token()}")
        print(f"  (also in {token_path or 'ui_token.txt'}; the launcher opens the browser with it, anyone else gets 401)")
    print(f"  Open {open_url} in your browser\n")
    if os.environ.get("ZSCALER_OPEN_BROWSER", "").strip().lower() in ("1", "true", "yes"):
        try:
            import threading
            import webbrowser
            threading.Timer(1.5, lambda: webbrowser.open(open_url)).start()
        except Exception:  # noqa: BLE001 - a browser that cannot open never stops the server
            pass
    if in_container and host == "0.0.0.0":
        print(f"  (inside the container the server listens on every address; docker-compose.yml publishes it on 127.0.0.1:{shown_port} of this machine only)\n")
    elif host != "127.0.0.1":
        print("  ⚠  WARNING: bound to a non-loopback address — anyone on the network")
        print(f"     can reach this server. Currently listening on {host}:{port}.")
        print("     Set ZSCALER_BIND_HOST=127.0.0.1 (default) to restrict to localhost.\n")
    try:
        if not is_debug():
            # Suppress access log spam in production mode (one line per request)
            uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
        else:
            uvicorn.run(app, host=host, port=port, log_level="info")
    except OSError as e:
        if getattr(e, "errno", None) in (48, 98, 10048) or "address already in use" in str(e).lower():
            print(f"\n  Could not start: port {port} on {host} is already in use.\n"
                  f"  Another copy of the app is probably running (STOP_Zscaler_Assessment or stop.sh stops it),\n"
                  f"  or set ZSCALER_PORT to a free port and start again.", file=sys.stderr)
        else:
            print(f"\n  Could not start the server on {host}:{port}: {e}\n"
                  f"  Check ZSCALER_BIND_HOST (an address this machine owns) and ZSCALER_PORT (1-65535).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
