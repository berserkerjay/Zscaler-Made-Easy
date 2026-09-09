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

import json, asyncio, os, re, tempfile, time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse, HTMLResponse, Response
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
    mask_secret, scrub_dict, writes_enabled,
)

# ── Import the assessment engine ─────────────────────────────────────
import importlib.util, sys

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
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def _no_stale_static(request, call_next):
    """The GUI is updated in place by UPDATE_Zscaler_Assessment.bat; make
    browsers revalidate every static file so an update shows up on the next
    load instead of after a hard refresh."""
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path in ("/", "/report/view", "/report/bypass"):
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
    # In normal mode, return a generic message — log details server-side only.
    print(f"[error] {type(exc).__name__} on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        {"detail": "Internal error. Run with ZSCALER_DEBUG=1 for details."},
        status_code=500,
    )

# Serve static files (web GUI)
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(_APP_DIR, "static")
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
    ("deploy_studio.js", "script"),
    ("guide.js", "script"),
    ("bypass_report.js", "script"),
    ("tool_tabs.js", "script"),
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
            tag, anchor, pos = f'<link rel="stylesheet" href="/static/{name}?v={v}">\n', "</head>", html.find("</head>")
        else:
            tag, anchor, pos = f'<script src="/static/{name}?v={v}"></script>\n', "</body>", html.rfind("</body>")
        if pos >= 0:
            html = html[:pos] + tag + html[pos:]
    return html


# ── Request Models ───────────────────────────────────────────────────

class AssessRequest(BaseModel):
    org_name: str = "Unknown"
    assessor: str = "Unknown"
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = "full"  # legacy single scope, kept for compatibility
    scopes: list[str] = []  # new: list of scope keys (dlp, zia_extras, zpa, zcc)
    customer_id: str = ""  # Optional ZPA customer ID
    profile_id: str = ""   # Saved tenant profile: fills blanks, records history


class TenantProfileRequest(BaseModel):
    id: str = ""
    name: str = ""
    org_name: str = ""
    assessor: str = ""
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    remember_secret: bool = False
    customer_id: str = ""
    industry: str = ""
    baseline_packs: list[str] = []
    scopes: list[str] = []
    frameworks: list[str] = []
    notes: str = ""


class UpdateCheckRequest(BaseModel):
    only: Optional[list[str]] = None  # subset of source keys
    reset: bool = False               # wipe cache first
    skip_tls_verify: bool = False     # corporate TLS MITM bypass (opt-in per request)


# ── Routes ────────────────────────────────────────────────────────────

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


# ── Text-prompt command interface ────────────────────────────────
# Lets the GUI accept natural-language-ish input and dispatch it to
# one of the explicit actions in commands.COMMAND_CATALOG.

class CommandParseRequest(BaseModel):
    text: str = ""
    # Opt-in LLM parsing (default off).
    # For kind=ollama / openai → endpoint MUST be loopback (enforced
    # in llm_parser.py).
    # For kind=anthropic → endpoint MUST be api.anthropic.com and
    # llm_api_key is required. Sends the user's query to Anthropic's
    # Messages API. The user explicitly opts into this in the GUI.
    use_llm: bool = False
    llm_endpoint: str = "http://localhost:11434/api/chat"
    llm_model: str = "llama3.1"
    llm_kind: str = "ollama"   # "ollama" | "openai" | "anthropic"
    llm_api_key: str = ""      # required when llm_kind == "anthropic"


# ── Guided Auto-Remediation ──────────────────────────────────────
# Takes a finding + user-supplied criteria and generates the API
# call that would fix it. Read-only by default (dry_run=True);
# live writes gated by ENABLE_WRITE_ACTIONS env var per standard
# policy. See remediation.py for recipe catalog.

class RemediationPlanRequest(BaseModel):
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
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""
    # Inline Web DLP only — this tool's migration is scoped to the DLP
    # Web Rules inline policy. Other rule types (SSL, URL, firewall,
    # Cloud App) have different best-practice ordering rules and are
    # out of scope here.
    rule_type: str = "web_dlp"


def _build_client(req: "MigrateRequest"):
    """Build an authenticated Client from a migration request.
    Validates every input first; never echoes the secret in any error.
    """
    cloud = validate_cloud(req.cloud)
    vd = validate_vanity(req.vanity_domain)
    cid = validate_credential("client_id", req.client_id, required=True)
    sec = validate_credential("client_secret", req.client_secret, required=True)
    cust = validate_customer_id(req.customer_id)

    client = Client(cid, sec, vd, cloud, cust)
    auth_result = client.auth()
    if auth_result is not True:
        # auth_result is (False, "<reason>"). Sanitize: strip any echo of the secret.
        reason = ""
        if isinstance(auth_result, tuple) and len(auth_result) == 2:
            reason = str(auth_result[1])
        reason = reason.replace(sec, mask_secret(sec)) if sec else reason
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed for client_id={mask_secret(cid)}: {reason[:200]}",
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
    return {
        "entries": list_all(service or ""),
        "services": services(),
        "last_refreshed_at": _BP_REFRESH_STATE.get("last_refreshed_at"),
        "last_refresh_status": _BP_REFRESH_STATE.get("last_status"),
        "last_refresh_error": _BP_REFRESH_STATE.get("last_error"),
        "next_refresh_at": _BP_REFRESH_STATE.get("next_refresh_at"),
        "auto_refresh_enabled": _BP_REFRESH_STATE.get("enabled", True),
    }


class BPCrawlRequest(BaseModel):
    force: bool = False
    skip_tls_verify: bool = False


@app.post("/api/best-practices/crawl")
async def best_practices_crawl(req: BPCrawlRequest):
    """Crawl every source in bp_sources.py for new Best/Leading-Practice
    articles and report any NEW ones beyond the curated catalog. Results
    are cached for 24h; force=true bypasses the cache. skip_tls_verify=true
    opts into the corporate-TLS-MITM bypass (same behavior as the update
    checker)."""
    try:
        from bp_crawler import crawl
        from zscaler_best_practices import save_discovered
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bp_crawler unavailable: {e}")
    result = await asyncio.to_thread(crawl, req.skip_tls_verify, req.force)
    # Auto-promote newly-discovered entries into the persistent library
    # so the curated + discovered catalog survives subsequent sessions.
    new_entries = result.get("new_entries") or []
    added = await asyncio.to_thread(save_discovered, new_entries)
    result["added_to_library"] = added
    # Update the shared refresh state so /api/best-practices reflects
    # this manual crawl's timestamp + status.
    _BP_REFRESH_STATE["last_refreshed_at"] = time.time()
    _BP_REFRESH_STATE["last_status"] = "ok" if not result.get("error") else "error"
    _BP_REFRESH_STATE["last_error"] = result.get("error")
    return result


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
            from bp_crawler import crawl
            from zscaler_best_practices import save_discovered
            # force=False honors the 24h cache → if something else
            # already crawled today this is effectively a no-op.
            result = await asyncio.to_thread(crawl, False, False)
            new_entries = result.get("new_entries") or []
            if new_entries:
                await asyncio.to_thread(save_discovered, new_entries)
            _BP_REFRESH_STATE["last_refreshed_at"] = time.time()
            _BP_REFRESH_STATE["last_status"] = "ok"
            _BP_REFRESH_STATE["last_error"] = None
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
        from dlp_importer import discover_packs, load_pack_contents
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
    then to tenant_config.json next to this file."""
    cloud: str = ""
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    # Saved tenant profile: blanks above are filled from it (including a
    # remembered secret), so the operator can switch tenants without retyping.
    profile_id: str = ""


class DLPPackImportRequest(TenantCredsRequest):
    use_rank_0: bool = False
    apply_tweaks: bool = True
    verify: bool = True


class DLPPackDeployRequest(TenantCredsRequest):
    pack_ids: List[str] = []
    use_rank_0: bool = False
    apply_tweaks: bool = True
    verify: bool = True
    # Converge mode: overwrite baseline objects the customer changed. Off by
    # default and never chosen for the user; the journey check reports them.
    restore_drift: bool = False
    # apply-only: the hash of the plan the user approved, plus explicit consent
    plan_hash: str = ""
    confirm: bool = False


_WRITES_DISABLED_MSG = (
    "Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND. "
    "Relaunch via START_Zscaler_Assessment_WRITES_ENABLED.bat."
)


def _tenant_creds(req: TenantCredsRequest) -> Dict[str, str]:
    """Resolve credentials: request body → environment → tenant_config.json."""
    creds = {
        "cloud": req.cloud, "vanity_domain": req.vanity_domain,
        "client_id": req.client_id, "client_secret": req.client_secret,
    }
    creds = _fill_from_profile(creds, getattr(req, "profile_id", ""))
    if not (creds["client_id"] and creds["client_secret"]):
        creds = {
            "cloud": creds["cloud"] or os.environ.get("ZSCALER_CLOUD", ""),
            "vanity_domain": creds["vanity_domain"] or os.environ.get("ZSCALER_VANITY_DOMAIN", ""),
            "client_id": os.environ.get("ZSCALER_CLIENT_ID", ""),
            "client_secret": os.environ.get("ZSCALER_CLIENT_SECRET", ""),
        }
    if not (creds["client_id"] and creds["client_secret"]):
        cfg_path = os.path.join(_APP_DIR, "tenant_config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f) or {}
                creds = {k: (creds[k] or str(cfg.get(k, ""))) for k in creds}
            except Exception:
                pass
    return creds


def _fill_from_profile(creds: Dict[str, str], profile_id: str) -> Dict[str, str]:
    """Fill blank credential fields from a saved tenant profile (the
    remembered secret included). Typed values always win."""
    if not profile_id:
        return creds
    try:
        import tenant_profiles
        prof = tenant_profiles.get(profile_id, with_secret=True)
    except Exception:
        prof = None
    if not prof:
        return creds
    pc = tenant_profiles.creds_from(prof)
    return {k: (creds.get(k) or pc.get(k, "")) for k in set(creds) | {"cloud", "vanity_domain", "client_id", "client_secret"}}


def _oneapi_cloud(cloud: str) -> Optional[str]:
    """Map the GUI's cloud names onto the OneAPI `cloud` setting. Commercial
    production tenants must NOT send a cloud value (the SDK builds the
    Zidentity URL from the vanity domain alone); only beta and the
    FedRAMP clouds need one."""
    c = (cloud or "").strip().lower()
    if c in ("beta", "zscalerbeta", "zspreview"):
        return "beta"
    if c in ("gov", "zscalergov"):
        return "gov"
    if c == "govus":
        return "govus"
    return None


def _build_sdk_client(creds: Dict[str, str]):
    """Build an authenticated zscaler-sdk-python OneAPI client (the object
    with `.zia.*` services the importer and planner require). Validates
    every input and never echoes the secret in an error."""
    cloud = validate_cloud(creds.get("cloud") or "production")
    vd = validate_vanity(creds.get("vanity_domain", ""))
    cid = validate_credential("client_id", creds.get("client_id", ""), required=True)
    sec = validate_credential("client_secret", creds.get("client_secret", ""), required=True)
    if not vd:
        raise HTTPException(status_code=400, detail="vanity_domain is required for OneAPI authentication.")
    try:
        from zscaler import ZscalerClient
    except ImportError:
        raise HTTPException(status_code=503, detail="zscaler-sdk-python is not installed. Run: pip install -r requirements.txt")
    config: Dict[str, Any] = {"clientId": cid, "clientSecret": sec, "vanityDomain": vd}
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
    return client


def _resolve_pack_ids(pack_ids: List[str]) -> List[Dict[str, Any]]:
    """Map requested ids onto discovered packs. Ids are only ever matched
    against the discovery list, so a request can't name an arbitrary path."""
    from dlp_importer import discover_packs
    known = {p["id"]: p for p in discover_packs()}
    unknown = [pid for pid in pack_ids if pid not in known]
    if unknown:
        raise HTTPException(status_code=404, detail=f"Unknown pack(s): {', '.join(unknown)}")
    return [{"id": pid, "dir": known[pid]["dir"]} for pid in pack_ids]


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
        restore_drift=req.restore_drift,
    )
    out = pack_deploy.public_report(report)
    out["writes_enabled"] = writes_enabled()
    out["tenant_label"] = f"{creds.get('vanity_domain') or '?'} ({creds.get('cloud') or 'production'})"
    return out


def _explain_connection_error(detail: str) -> Dict[str, Any]:
    """Turn an auth/network failure into a plain-language cause and fix."""
    d = str(detail or "")
    low = d.lower()
    if "invalid_client" in low or "401" in low or "unauthorized" in low or "authentication failed" in low and "connect" not in low:
        cause = "Zscaler rejected the client ID or client secret."
        fix = ("Check the client ID for typos. The secret is shown only once when the API client is created; if you copied it later, "
               "generate a new secret in ZIdentity > Integration > API Clients and paste it fresh.")
    elif "certificate" in low or "ssl" in low or "tls" in low:
        cause = "The connection to Zscaler was intercepted by TLS inspection (usually Zscaler Client Connector or a proxy on this machine)."
        fix = ("Export your organisation's root CA certificate as a .pem file and start the tool with "
               "REQUESTS_CA_BUNDLE=<path to that file>, or run from a machine that is not being inspected.")
    elif "tunnel connection failed" in low or "proxyerror" in low or "max retries" in low or "name resolution" in low or "nodename" in low:
        cause = "This machine could not reach Zscaler's login service at all (network, proxy or DNS)."
        fix = ("Confirm the vanity domain is the short name from your login URL (acme for acme.zslogin.net). "
               "If you are behind a corporate proxy, set HTTPS_PROXY in START_Zscaler_Assessment.bat. "
               "Check that outbound HTTPS to *.zslogin.net and api.zsapi.net is allowed.")
    elif "vanity" in low:
        cause = "The vanity domain is not valid."
        fix = "Enter only the short name that appears before .zslogin.net in your admin login URL, for example acme."
    elif "403" in low or "forbidden" in low or "scope" in low:
        cause = "The credentials are valid but the API client is not allowed to read this tenant."
        fix = ("In ZIdentity, open the API client and make sure a ZIA API resource and a role with read access to DLP "
               "dictionaries, engines and rules are assigned.")
    else:
        cause = "The connection failed."
        fix = "Re-check cloud, vanity domain, client ID and client secret at the top of the page, then try again."
    return {"cause": cause, "fix": fix, "raw": d[:300]}


@app.post("/api/tenant/check")
async def tenant_check(req: TenantCredsRequest):
    """Read-only connection test for the Start-here panel: authenticates,
    counts DLP dictionaries, engines and web DLP rules, and explains any
    failure in plain language with what to do next."""
    creds = _tenant_creds(req)
    label = f"{creds.get('vanity_domain') or '?'} ({creds.get('cloud') or 'production'})"
    try:
        client = await asyncio.to_thread(_build_sdk_client, creds)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail={"tenant_label": label, **_explain_connection_error(e.detail)})

    def probe() -> Dict[str, Any]:
        from pack_channels import _nx
        z = client.zia
        out: Dict[str, Any] = {"ok": True, "tenant_label": label, "problems": []}
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
        return out

    try:
        return await asyncio.to_thread(probe)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"tenant_label": label, **_explain_connection_error(str(e))})


# ---------------------------------------------------------------------------
# Write mode (Deploy Studio switch)
# ---------------------------------------------------------------------------

class WriteModeRequest(BaseModel):
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


@app.get("/api/tenant-profiles/{profile_id}")
async def tenant_profile_get(profile_id: str):
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
    fields = {
        "name": req.name or req.org_name or vd, "org_name": req.org_name, "assessor": req.assessor,
        "cloud": cloud, "vanity_domain": vd, "client_id": cid, "customer_id": cust,
        "industry": req.industry, "baseline_packs": [str(b) for b in req.baseline_packs],
        "scopes": [str(x) for x in req.scopes], "frameworks": [str(x) for x in req.frameworks], "notes": req.notes[:2000],
    }
    return tenant_profiles.upsert(fields, client_secret=sec, remember_secret=req.remember_secret, profile_id=req.id)


@app.delete("/api/tenant-profiles/{profile_id}")
async def tenant_profile_delete(profile_id: str):
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


def _journey_for(client, packs: List[Dict[str, Any]], use_rank_0: bool = False) -> Dict[str, Any]:
    """Read-only journey check: one preflight per baseline pack (so each
    pack is measured on its own), rolled up with pack_deploy.journey."""
    import pack_deploy
    rows: List[Dict[str, Any]] = []
    tenant = None
    blockers: List[str] = []
    for pk in packs:
        rep = pack_deploy.preflight(client, [pk], use_rank_0=use_rank_0, apply_tweaks=False, writes_enabled=None)
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
    baseline pack (or the ones in pack_ids), every object is placed as
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
        raise HTTPException(status_code=404, detail="No baseline packs found (pack.json needs a \"baseline\" section).")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(_journey_for, client, packs, req.use_rank_0)
    out["tenant_label"] = f"{creds.get('vanity_domain') or '?'} ({creds.get('cloud') or 'production'})"
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
        "versions.tf": "Terraform and provider version pins (zscaler/zia ~> 4.8).",
        "provider.tf": "Provider block; credentials come from variables or ZSCALER_* environment variables.",
        "variables.tf": "Inputs: credentials, rule starting order, admin rank, activation, tenant-specific IDs.",
        "terraform.tfvars.example": "Copy to terraform.tfvars and fill in (git-ignored).",
        "dictionaries.tf": "DLP dictionaries (custom ones as resources, predefined ones as data lookups).",
        "engines.tf": "DLP engines with their expressions referencing the dictionaries above.",
        "rules.tf": "Every rule of the pack: Web/Endpoint/SaaS/Email DLP and the containment rules.",
        "imports.tf": "Gap mode only: import blocks adopting objects that already exist in the tenant.",
        "activation.tf": "Activates the pending ZIA configuration after apply.",
        "outputs.tf": "IDs and names of everything created.",
        "README.md": "How to run it, ordering notes, gap summary.",
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
        import pack_deploy
        import pack_terraform
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_terraform unavailable: {e}")
    if not req.pack_ids:
        raise HTTPException(status_code=400, detail="Select at least one pack.")
    packs = _resolve_pack_ids(req.pack_ids)
    report = None
    mode = "static"
    creds = _tenant_creds(req)
    if creds.get("client_id"):
        client = await asyncio.to_thread(_build_sdk_client, creds)
        full = await asyncio.to_thread(
            pack_deploy.preflight, client, packs,
            use_rank_0=req.use_rank_0, apply_tweaks=False, writes_enabled=None,
        )
        report = pack_deploy.public_report(full)
        report["tenant_label"] = f"{creds.get('vanity_domain') or '?'} ({creds.get('cloud') or 'production'})"
        mode = "gap"
    workspaces = {}
    for p in packs:
        files = await asyncio.to_thread(
            pack_terraform.generate, p,
            report=pack_terraform.split_report(report, p["id"]) if report else None,
        )
        workspaces[p["id"]] = files
    data = pack_terraform.zip_workspaces(workspaces)
    name = f"dlp-check-terraform-{mode}-{'-'.join(req.pack_ids)[:60]}.zip"
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "X-DLP-Check-Mode": mode})


@app.post("/api/dlp-packs/apply")
async def dlp_packs_apply(req: DLPPackDeployRequest):
    """Execute an approved plan. Requires confirm=true and the plan_hash
    returned by /preflight. If the tenant or selection changed since
    approval the response is 409 with status 'plan_changed' and nothing
    is written. Blocked or failed items never stop the others."""
    try:
        import pack_deploy
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_deploy unavailable: {e}")
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Deployment requires explicit confirmation (confirm=true).")
    if not req.plan_hash:
        raise HTTPException(status_code=400, detail="plan_hash is required — run /api/dlp-packs/preflight first.")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_WRITES_DISABLED_MSG)
    packs = _resolve_pack_ids(req.pack_ids)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)

    logs: list = []
    result = await asyncio.to_thread(
        pack_deploy.apply, client, packs,
        plan_hash=req.plan_hash, use_rank_0=req.use_rank_0, apply_tweaks=req.apply_tweaks,
        verify=req.verify, writes_enabled=True, restore_drift=req.restore_drift, log=logs.append,
    )
    result["logs"] = logs
    if result.get("status") in ("plan_changed", "blocked"):
        return JSONResponse(result, status_code=409)
    return result


@app.post("/api/dlp-packs/{pack_id}/import")
async def dlp_pack_import(pack_id: str, req: DLPPackImportRequest):
    """Single-pack import (legacy path). Prefer /api/dlp-packs/preflight
    + /apply, which cross-reference packs and require approval."""
    try:
        from dlp_importer import run_full_import
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_importer unavailable: {e}")
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_WRITES_DISABLED_MSG)
    pack = _resolve_pack_ids([pack_id])[0]
    client = await asyncio.to_thread(_build_sdk_client, _tenant_creds(req))

    logs: list = []
    result = await asyncio.to_thread(
        run_full_import, client, pack["dir"],
        use_rank_0=req.use_rank_0, apply_tweaks=req.apply_tweaks,
        verify=req.verify, log=logs.append,
    )
    result["logs"] = logs
    return result


@app.post("/api/dlp-packs/{pack_id}/verify")
async def dlp_pack_verify(pack_id: str, req: TenantCredsRequest = TenantCredsRequest()):
    """Verify deployed tenant state matches a pack's definitions (read-only)."""
    try:
        from dlp_importer import verify_deployment
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_importer unavailable: {e}")
    pack = _resolve_pack_ids([pack_id])[0]
    client = await asyncio.to_thread(_build_sdk_client, _tenant_creds(req))
    return await asyncio.to_thread(verify_deployment, client.zia, pack["dir"])


class DLPPackUploadRequest(BaseModel):
    pack_name: str
    dictionaries: Optional[List[Dict[str, Any]]] = None
    engines: Optional[List[Dict[str, Any]]] = None
    policies: Optional[List[Dict[str, Any]]] = None


@app.post("/api/dlp-packs/upload")
async def dlp_pack_upload(req: DLPPackUploadRequest):
    """Create a new DLP pack from uploaded JSON definitions. Persists
    to disk so it survives server restarts."""
    slug = re.sub(r"[^a-z0-9_]+", "_", req.pack_name.lower().strip()).strip("_")
    if not slug:
        raise HTTPException(status_code=400, detail="Invalid pack name")
    pack_dir = os.path.join(PACKS_ROOT, slug)
    if os.path.exists(pack_dir):
        raise HTTPException(status_code=409, detail=f"Pack '{slug}' already exists")
    configs_dir = os.path.join(pack_dir, "configs")
    os.makedirs(configs_dir, exist_ok=True)
    saved = {}
    for fname, data in [
        ("dlp_dictionaries.json", req.dictionaries),
        ("dlp_engines.json", req.engines),
        ("dlp_policies.json", req.policies),
    ]:
        if data:
            with open(os.path.join(configs_dir, fname), "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            saved[fname] = len(data)
    # Write pack.json metadata
    meta = {"name": req.pack_name, "version": "1.0", "description": f"Uploaded pack: {req.pack_name}"}
    with open(os.path.join(pack_dir, "pack.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return {"id": slug, "dir": pack_dir, "files_saved": saved, "metadata": meta}


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
              <div class="endpoints">{endpoints or '<span class="muted">(composite — no direct endpoints)</span>'}</div>
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
    background: var(--accent); color: white; border: 0;
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
    return get_all_permissions()


@app.get("/api/llm/status")
async def llm_status():
    """Probe the local Ollama instance. Reports whether it's running
    and which models are available so the GUI can pre-fill the picker.
    Loopback-only — calls 127.0.0.1:11434 directly."""
    import requests
    try:
        r = requests.get("http://127.0.0.1:11434/api/tags", timeout=3)
        if r.status_code == 200:
            data = r.json()
            models = [m.get("name") for m in (data.get("models") or []) if m.get("name")]
            return {
                "ollama_running": True,
                "models": models,
                "model_count": len(models),
                "recommended_model": next(
                    (m for m in models if m.startswith(("llama3.1", "llama3.2", "qwen2.5", "phi3"))),
                    (models[0] if models else None),
                ),
                "endpoint": "http://127.0.0.1:11434/api/chat",
            }
    except Exception as e:
        return {
            "ollama_running": False,
            "models": [],
            "error": f"{type(e).__name__}: {str(e)[:100]}",
            "hint": "Install Ollama from https://ollama.com/download, then `ollama pull llama3.2:3b`.",
        }
    return {"ollama_running": False, "models": []}


@app.get("/api/commands")
async def commands_catalog():
    """Return the list of supported commands so the GUI can render
    autocomplete + help without hardcoding."""
    try:
        from commands import COMMAND_CATALOG
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"commands module unavailable: {e}")
    return {"catalog": COMMAND_CATALOG}


class LlmValidateRequest(BaseModel):
    llm_kind: str = "ollama"        # "ollama" | "openai" | "anthropic"
    llm_endpoint: str = ""
    llm_model: str = ""
    llm_api_key: str = ""


@app.post("/api/llm/validate")
async def llm_validate(req: LlmValidateRequest):
    """Probe the configured LLM with a one-token request to confirm the
    integration works. Returns ok=true on success or a specific error
    message if model ID / API key / endpoint / network is wrong.
    Same loopback / allowlist rules as the real parse endpoint."""
    kind = req.llm_kind or "ollama"
    if kind == "anthropic":
        endpoint = req.llm_endpoint or "https://api.anthropic.com/v1/messages"
        model = req.llm_model or "claude-haiku-4-5-20251001"
        api_key = req.llm_api_key or ""
        if not api_key:
            return {"ok": False, "error": "API key required for Anthropic provider."}
        try:
            from llm_parser import _is_allowed_endpoint, _call_anthropic
            if not _is_allowed_endpoint(endpoint, kind):
                return {"ok": False, "error": f"Endpoint refused by allowlist: {endpoint}"}
            raw = await asyncio.to_thread(
                _call_anthropic, endpoint, model,
                "You are a test probe. Respond with exactly the word: OK",
                "ping", api_key,
            )
            return {"ok": True, "provider": "anthropic", "model": model,
                    "response_preview": (raw or "")[:80]}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:250]}"}

    if kind == "openai_cloud":
        endpoint = req.llm_endpoint or "https://api.openai.com/v1/chat/completions"
        model = req.llm_model or "gpt-4o-mini"
        api_key = req.llm_api_key or ""
        if not api_key:
            return {"ok": False, "error": "API key required for OpenAI provider."}
        try:
            from llm_parser import _is_allowed_endpoint, _call_openai_compatible
            if not _is_allowed_endpoint(endpoint, kind):
                return {"ok": False, "error": f"Endpoint refused by allowlist: {endpoint}"}
            raw = await asyncio.to_thread(
                _call_openai_compatible, endpoint, model,
                'You are a test probe. Respond with JSON: {"status":"ok"}',
                "ping", api_key,
            )
            return {"ok": True, "provider": "openai", "model": model,
                    "response_preview": (raw or "")[:80]}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:250]}"}

    if kind == "ollama":
        endpoint = req.llm_endpoint or "http://localhost:11434/api/chat"
        model = req.llm_model or "llama3.2:3b"
        try:
            from llm_parser import _is_allowed_endpoint, _call_ollama
            if not _is_allowed_endpoint(endpoint, kind):
                return {"ok": False, "error": f"Endpoint refused: must be loopback for Ollama."}
            raw = await asyncio.to_thread(
                _call_ollama, endpoint, model,
                "You are a test probe. Respond with exactly: OK",
                "ping",
            )
            return {"ok": True, "provider": "ollama", "model": model, "response_preview": (raw or "")[:80]}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:250]}"}
    return {"ok": False, "error": f"Unknown kind: {kind}"}


@app.post("/api/commands/parse")
async def commands_parse(req: CommandParseRequest):
    """Parse arbitrary user text into a structured action.

    Default path (use_llm=false) is purely deterministic — never runs
    user code, never calls an LLM, never leaves the machine.

    Opt-in path (use_llm=true) routes the query through a LOCAL LLM
    on a loopback endpoint (Ollama / llama.cpp / LM Studio). The LLM
    result is schema-validated against the command catalog and FALLS
    BACK to the deterministic parser on any error, parsing failure,
    or non-allowlisted action/scope."""
    try:
        from commands import parse, to_dict
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"commands module unavailable: {e}")

    raw = (req.text or "")[:500]

    if req.use_llm:
        try:
            from llm_parser import parse_with_llm
        except Exception as e:
            # Module unavailable — fall back to deterministic parser
            result = await asyncio.to_thread(parse, raw)
            result.suggestion = (result.suggestion or "") + f" [LLM module unavailable: {e}]"
            return to_dict(result)
        result = await asyncio.to_thread(
            parse_with_llm, raw,
            req.llm_endpoint, req.llm_model, req.llm_kind, req.llm_api_key,
        )
        d = to_dict(result)
        d["parser"] = "llm"  # tag so GUI can display which path was used
        d["llm_kind"] = req.llm_kind
        return d

    result = await asyncio.to_thread(parse, raw)
    d = to_dict(result)
    d["parser"] = "deterministic"
    return d


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
        "is_git_checkout": os.path.isdir(os.path.join(_APP_DIR, ".git")),
        "latest_commit": _latest_remote_commit(),
    }


_LATEST: Dict[str, Any] = {"at": 0.0, "sha": None}


def _latest_remote_commit() -> Optional[str]:
    """Short sha of origin/main on GitHub (best effort, cached 10 minutes),
    so the GUI can say whether this install is behind."""
    import subprocess, time as _t
    if _t.time() - _LATEST["at"] < 600:
        return _LATEST["sha"]
    _LATEST["at"] = _t.time()
    try:
        out = subprocess.check_output(["git", "ls-remote", "origin", "-h", "refs/heads/main"],
                                      cwd=_APP_DIR, stderr=subprocess.DEVNULL, timeout=4).decode()
        sha = out.split()[0][:7] if out.strip() else None
    except Exception:
        sha = None
    _LATEST["sha"] = sha
    return sha


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
    never reaches any LLM. 256 KB hard cap on input."""
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
    mode: str = ""   # "rule_order" | "evaluate_all_rules"


@app.post("/api/migrate/status/manual")
async def migrate_status_manual(req: ManualModeRequest):
    """Step 1 override: accept the user's manual declaration of the current mode
    when the API doesn't expose the toggle (account-level feature flag). Returns
    the same shape as /api/migrate/status so the wizard keeps working."""
    try:
        from rule_migrator import assess_current_status, fetch_current_rules, reorder_for_eval_all
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
    base["found_via"] = f"user-declared (API does not expose this flag in your tenant)"
    base["ready_to_migrate"] = not evaluate_all
    if evaluate_all:
        base["recommendation"] = "✅ You declared this tenant is in Evaluate All Rules mode. No migration needed — focus on ongoing rule tuning."
    elif base.get("order_already_safe_for_eval_all"):
        base["recommendation"] = "You declared this tenant is in Rule Order mode. Rule order is already optimal for Evaluate All — safe to enable the feature with low risk."
    else:
        base["recommendation"] = "You declared this tenant is in Rule Order mode. Rule order is NOT yet safe for Evaluate All — run Step 3 (Optimize) before enabling."
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
    dry_run: bool = True


@app.post("/api/migrate/enable")
async def migrate_enable(req: EnableRequest):
    """Step 4: Enable Evaluate All Rules in ZIA Advanced Settings (dry-run by default)."""
    try:
        from rule_migrator import enable_evaluate_all_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(enable_evaluate_all_rules, client, req.dry_run)


# ── Step 4b: Delete All Existing Rules (gated) ───────────────────────
class DeleteAllRequest(MigrateRequest):
    dry_run: bool = True


@app.post("/api/migrate/delete-all")
async def migrate_delete_all(req: DeleteAllRequest):
    """Step 4b (optional): Delete every Inline Web DLP rule. Destructive — gated."""
    try:
        from rule_migrator import delete_all_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(delete_all_rules, client, req.dry_run)


# ── Step 5: Post New Rule Order ──────────────────────────────────
class PostRequest(MigrateRequest):
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
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(post_new_rule_order, client, req.proposed_rules, req.dry_run, req.mode)


# ── Upload rules (from a JSON backup file) ───────────────────────────────
class UploadRulesRequest(BaseModel):
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
    # A saved profile fills whatever the form left blank (a remembered secret included).
    profile = None
    if req.profile_id:
        try:
            import tenant_profiles
            profile = tenant_profiles.get(req.profile_id, with_secret=True)
        except Exception:
            profile = None
        if profile:
            pc = tenant_profiles.creds_from(profile)
            req.cloud = req.cloud or pc["cloud"]
            req.vanity_domain = req.vanity_domain or pc["vanity_domain"]
            req.client_id = req.client_id or pc["client_id"]
            req.client_secret = req.client_secret or pc["client_secret"]
            req.customer_id = req.customer_id or pc["customer_id"]
            req.org_name = req.org_name if req.org_name not in ("", "Unknown") else (profile.get("org_name") or req.org_name)
    # Validate inputs BEFORE the SSE stream opens so failures return 400, not 200+stream
    cloud = validate_cloud(req.cloud)
    vd = validate_vanity(req.vanity_domain)
    cid = validate_credential("client_id", req.client_id, required=True)
    sec = validate_credential("client_secret", req.client_secret, required=True)
    cust = validate_customer_id(req.customer_id)
    checks = _get_checks(req.scope, req.scopes)
    journey_pack_ids = [str(b) for b in (profile or {}).get("baseline_packs") or []]

    async def event_generator():
        results = []
        try:
            yield _sse("auth", {"status": "authenticating"})

            client = Client(cid, sec, vd, cloud, cust)
            auth_result = await asyncio.to_thread(client.auth)

            if auth_result is not True:
                reason = ""
                if isinstance(auth_result, tuple) and len(auth_result) == 2:
                    reason = str(auth_result[1])
                reason = (reason or "").replace(sec, mask_secret(sec)) if sec else reason
                yield _sse("error", {"message": f"Authentication failed: {reason[:200]}"})
                return

            yield _sse("auth", {"status": "ok"})
            yield _sse("progress", {"total": len(checks), "completed": 0, "pct": 0})

            # NOTE: the loop tuple variable must NOT be named `sec` — that
            # shadows the outer `sec` (client_secret) and Python's
            # closure rules then make every earlier reference to `sec`
            # in this generator raise UnboundLocalError.
            for i, (check_id, section, label, fn) in enumerate(checks):
                # Bulletproof: every check runs in its own try/except with hard timeout
                try:
                    r = await asyncio.wait_for(asyncio.to_thread(fn, client), timeout=60)
                except asyncio.TimeoutError:
                    r = R(R.INFO, f"{label}: Check timed out after 60 seconds.")
                except Exception as ex:
                    r = R(R.INFO, f"{label}: Could not complete check. {str(ex)[:120]}")

                # Defensive: ensure r has expected shape
                if not hasattr(r, 'status') or not hasattr(r, 'detail'):
                    r = R(R.INFO, f"{label}: Invalid check result.")

                result = {
                    "id": check_id, "section": section, "label": label,
                    "status": str(r.status), "detail": str(r.detail)[:500],
                }
                results.append(result)

                # Yield check + progress, skipping if client disconnected
                try:
                    yield _sse("check", result)
                    yield _sse("progress", {
                        "total": len(checks),
                        "completed": i + 1,
                        "pct": round((i + 1) / len(checks) * 100),
                        "current": f"{check_id}: {label}",
                    })
                    # Periodic keepalive every 10 checks
                    if (i + 1) % 10 == 0:
                        yield ": keepalive\n\n"
                except Exception:
                    # Client disconnected; just keep collecting results
                    pass

            # Data-governance journey: where the tenant stands against every
            # baseline pack. Read-only, best effort; never fails the assessment.
            journey = None
            if not req.scopes or "dlp" in req.scopes or req.scope in ("full", "dlp"):
                try:
                    yield _sse("progress", {"total": len(checks), "completed": len(checks), "pct": 100,
                                            "current": "Data governance journey: measuring the tenant against the baselines"})
                    packs = _journey_packs(journey_pack_ids)
                    if packs:
                        sdk = await asyncio.to_thread(_build_sdk_client, {"cloud": cloud, "vanity_domain": vd, "client_id": cid, "client_secret": sec})
                        journey = await asyncio.wait_for(asyncio.to_thread(_journey_for, sdk, packs), timeout=180)
                        journey["tenant_label"] = f"{vd} ({cloud})"
                except Exception as ex:  # noqa: BLE001
                    journey = {"status": "error", "error": str(ex).replace(sec, mask_secret(sec))[:200] if sec else str(ex)[:200]}

            # Always send the complete event, even if some checks failed
            try:
                secs, overall = compute(results)
            except Exception as e:
                secs, overall = {}, 0

            report = {
                "metadata": {
                    "tool": "Zscaler Platform Assessment",
                    "version": "3.0",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "org": req.org_name,
                    "assessor": req.assessor,
                    "cloud": req.cloud,
                    "total_checks": len(checks),
                    "scope": ",".join(req.scopes) if req.scopes else req.scope,
                },
                "score": overall,
                "maturity": maturity(overall),
                "sections": secs,
                "checks": results,
                "critical": [r for r in results if r["status"] == "FAIL"],
                "review": [r for r in results if r["status"] == "REVIEW"],
                "journey": journey,
                "profile": None,
            }
            if profile:
                try:
                    import tenant_profiles
                    updated = tenant_profiles.add_history(profile["id"], tenant_profiles.snapshot(report))
                    if updated:
                        report["profile"] = {"id": updated["id"], "name": updated.get("name"),
                                             "history": (updated.get("history") or [])[-12:]}
                except Exception:  # noqa: BLE001 — history is best effort
                    pass

            yield _sse("complete", report)

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
    cfg = data.get("metadata", {})

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

    org = cfg.get("org", "report").replace(" ", "_")
    return FileResponse(tmp_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        filename=f"zscaler_{org}_{datetime.now().strftime('%Y%m%d')}.docx")


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
        output_path = os.path.join(tempfile.gettempdir(), f"zscaler_bypass_{ts}.docx")
        try:
            await asyncio.to_thread(to_docx, report, output_path)
        except ImportError as e:
            raise HTTPException(status_code=500, detail=f"python-docx missing: {e}. Run: pip install python-docx")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Word generation failed: {type(e).__name__}: {str(e)[:300]}")
        return FileResponse(output_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            filename=f"zscaler_bypass_{ts}.docx")
    return Response(content=json.dumps(report, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.json"})


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


if __name__ == "__main__":
    import uvicorn
    host = get_bind_host()
    port = get_port()
    print("\n  Zscaler Platform Assessment")
    print(f"  Open http://{('localhost' if host == '127.0.0.1' else host)}:{port} in your browser\n")
    if host != "127.0.0.1":
        print("  ⚠  WARNING: bound to a non-loopback address — anyone on the network")
        print(f"     can reach this server. Currently listening on {host}:{port}.")
        print("     Set ZSCALER_BIND_HOST=127.0.0.1 (default) to restrict to localhost.\n")
    if not is_debug():
        # Suppress access log spam in production mode (one line per request)
        uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
    else:
        uvicorn.run(app, host=host, port=port, log_level="info")
