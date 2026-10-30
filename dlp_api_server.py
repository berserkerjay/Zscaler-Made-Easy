#!/usr/bin/env python3
"""
Zscaler Made Easy API Server + Web GUI
========================================
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

import json, asyncio, os, re, sys, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from starlette.background import BackgroundTask


def _unlink_quietly(path: str) -> None:
    """Remove a temporary report file; a missing file is not an error."""
    try:
        os.unlink(path)
    except OSError:
        pass
from typing import Any, Dict, List, Optional, Tuple, Union

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse, HTMLResponse, Response, PlainTextResponse, RedirectResponse

import tenant_auth
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

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
    title="Zscaler Made Easy",
    version="3.0",
    description="Full-auto assessment engine via OneAPI.",
)


# ── Request bodies are strict JSON (RFC 8259) ───────────────────────
# Python's decoder also takes NaN, Infinity and -Infinity, which are not
# JSON: a float field then held NaN and int(NaN) / int(inf) in a handler
# was a ValueError / OverflowError (500). Every body, a request model's
# or one a handler reads itself (_json_object), is decoded here; such a
# literal is a decode error, so a 422 (json_invalid) or 400 before any
# handler runs.
from fastapi.routing import APIRoute as _APIRoute


def _refuse_json_constant(name: str) -> Any:
    raise json.JSONDecodeError(f"{name} is not valid JSON", name, 0)


class _StrictJSONRequest(Request):
    async def json(self) -> Any:
        if not hasattr(self, "_json"):
            self._json = json.loads(await self.body(), parse_constant=_refuse_json_constant)
        return self._json


class _StrictJSONRoute(_APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def strict_handler(request: Request):
            return await handler(_StrictJSONRequest(request.scope, request.receive))
        return strict_handler


app.router.route_class = _StrictJSONRoute

# Starlette runs the middleware added LAST as the outermost. The body-size
# cap is added at the very end of this block (after CORS) so it wraps
# everything: no other layer, the audit log included, buffers a body before
# the cap has been applied to it. The rate limiter is added just before it,
# so it runs ahead of the UI token check: a flood of unauthenticated calls is
# throttled before each one can write an "auth_denied" audit line.
app.add_middleware(OriginCheckMiddleware)
import security as _security
import audit as _audit
app.add_middleware(_audit.AuditMiddleware, writes_enabled=writes_enabled)   # innermost: sees the final status of every write call
app.add_middleware(_security.UIAuthMiddleware)   # inside the headers layer: a 401 still carries the security headers
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
    """The GUI is updated in place by UPDATE_Zscaler_Made_Easy.bat; make
    browsers revalidate every static file so an update shows up on the next
    load instead of after a hard refresh."""
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path in ("/", "/app.css", "/report/view", "/report/bypass", "/report/sslflow", "/report/flow", "/report/dataflow", "/report/advanced", "/report/health", "/report/compliance", "/report/evalall", "/report/path", "/report/live", "/report/vendor", "/report/beacon", "/report/deploy-flow", "/report/operations", "/report/exports", "/report/motion", "/simple", "/report/fleet", "/report/zpa", "/report/device-posture", "/report/queue", "/report/insights", "/report/shadow", "/report/audit", "/report/self-heal", "/report/todo", "/report/posture", "/report/sslcoverage", "/report/browser", "/report/pov"):
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
# The browser's offline tenant (the sample or a snapshot, offline_tenant.py), for _tenant_creds.
import offline_tenant as _offline_src
app.add_middleware(_offline_src.SourceMiddleware)
app.add_middleware(RateLimitMiddleware, rps=20, burst=60)
# Just inside the body cap: every answer the other layers make (the rate
# limiter's 429, a CORS preflight, the UI token's 401) carries CSP, nosniff
# and frame denial. It reads no request body. A 500 is answered outside
# every middleware (Starlette's ServerErrorMiddleware), so
# _safe_exception_handler sets the same headers itself.
app.add_middleware(SecurityHeadersMiddleware)
# Outermost: caps declared and streamed (chunked) request bodies before any
# other layer reads them (see BodySizeLimitMiddleware).
app.add_middleware(BodySizeLimitMiddleware, max_bytes=get_max_body_bytes())


# ── Generic exception handler — never leak stack traces ────────────
_LOG_LINE_MAX = 2000      # characters of one traceback entry (or the message) written to server.log
_LOG_TRACE_MAX = 32768    # characters of one whole traceback


def _hardened(response: Response, request: Request) -> Response:
    """`response` with the headers SecurityHeadersMiddleware sets, for an
    answer made outside every middleware (an unhandled exception's 500)."""
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
    h.setdefault("Content-Security-Policy", _security.CONTENT_SECURITY_POLICY)
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def _safe_exception_handler(request: Request, exc: Exception):
    """Catch-all so internal errors never expose tracebacks to the client."""
    return _hardened(_internal_error(request, exc), request)


def _internal_error(request: Request, exc: Exception) -> Response:
    if isinstance(exc, HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    if is_debug():
        import traceback
        return JSONResponse(
            {"detail": tenant_auth.redact_tokens(f"{type(exc).__name__}: {exc}"), "trace": tenant_auth.redact_tokens(traceback.format_exc())},
            status_code=500,
        )
    # In normal mode, return a generic message — log details server-side only
    # (server.log carries the traceback so the failure can be reported).
    # Bounded: an exception quoting a request value (a 10 MB field) must not
    # write tens of megabytes to server.log per call.
    import traceback
    parts = traceback.format_exception(type(exc), exc, exc.__traceback__)
    trace = "".join(p if len(p) <= _LOG_LINE_MAX else p[:_LOG_LINE_MAX] + " … [cut]\n" for p in parts)
    if len(trace) > _LOG_TRACE_MAX:
        trace = trace[:_LOG_TRACE_MAX // 2] + "\n… [cut] …\n" + trace[-_LOG_TRACE_MAX // 2:]
    what = str(exc)
    # server.log is a file on disk: an access token or session id the
    # exception repeated is masked by shape before it is written.
    print(tenant_auth.redact_tokens(f"[error] {type(exc).__name__} on {request.method} {request.url.path[:300]}: {what[:_LOG_LINE_MAX]}\n{trace}"))
    return JSONResponse(
        {"detail": f"Internal error ({type(exc).__name__}). The traceback is in server.log next to the app; run with ZSCALER_DEBUG=1 to see it here."},
        status_code=500,
    )


# ── Error bodies never echo the request back ───────────────────────
# FastAPI's 422 lists each invalid field with its `input`: for a missing
# field that is the whole body, client_secret and password included, and a
# 200 kB field comes back as a 200 kB error. A refusal says which field and
# why (`loc`, `msg`, `type`: what the pages read) and nothing the caller
# sent; any string in an HTTPException detail is cut to _MAX_DETAIL_CHARS so
# a message quoting a bad value cannot reflect an unbounded one.
_MAX_DETAIL_CHARS = 1000
_MAX_LOC_CHARS = 100


def _bounded(value: Any, limit: int = _MAX_DETAIL_CHARS) -> Any:
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…"
    if isinstance(value, dict):
        return {(_bounded(k, _MAX_LOC_CHARS) if isinstance(k, str) else k): _bounded(v, limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_bounded(v, limit) for v in value]
    return value


from fastapi.exceptions import RequestValidationError as _RequestValidationError
from starlette.exceptions import HTTPException as _StarletteHTTPException
from fastapi.exception_handlers import http_exception_handler as _default_http_exception_handler


@app.exception_handler(_RequestValidationError)
async def _validation_error_handler(request: Request, exc: _RequestValidationError):
    """422 with each problem's loc / msg / type only (never `input`, `ctx` or `url`)."""
    errors = [{"type": str(e.get("type", "")), "loc": [_bounded(p, _MAX_LOC_CHARS) for p in e.get("loc", ())],
               "msg": _bounded(str(e.get("msg", "")))} for e in exc.errors()[:50]]
    return JSONResponse({"detail": errors}, status_code=422)


def _server_paths() -> List[Tuple[str, str]]:
    """(folder, how an error names it), longest first: the app folder, the
    Python install, the temporary folder and the home folder."""
    pairs = [(_APP_DIR, "<app folder>"), (sys.prefix, "<python>"), (getattr(sys, "base_prefix", sys.prefix), "<python>"),
             (tempfile.gettempdir(), "<temp>"), (os.path.expanduser("~"), "~")]
    out = []
    for folder, name in pairs:
        if folder and len(folder) > 1:
            out.extend([(folder, name), (folder.replace("\\", "/"), name)])
    return sorted(set(out), key=lambda p: -len(p[0]))


def _scrub_paths(value: Any) -> Any:
    """`value` with every server folder named by its role, not its path: a
    5xx detail quoting an exception (an OSError, an ImportError) must not
    tell the caller where the app, Python or the user's files live."""
    if isinstance(value, str):
        for folder, name in _server_paths():
            value = value.replace(folder, name)
        return value
    if isinstance(value, dict):
        return {k: _scrub_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_paths(v) for v in value]
    return value


@app.exception_handler(_StarletteHTTPException)
async def _bounded_http_exception_handler(request: Request, exc: _StarletteHTTPException):
    """Every HTTPException, its detail's strings bounded (headers such as
    Retry-After kept); a server fault's (5xx) detail names no server folder."""
    detail = _bounded(_scrub_paths(exc.detail) if exc.status_code >= 500 else exc.detail)
    if detail != exc.detail:
        exc = _StarletteHTTPException(status_code=exc.status_code, detail=detail, headers=exc.headers)
    return await _default_http_exception_handler(request, exc)


async def _json_object(request: Request) -> Dict[str, Any]:
    """The body of an endpoint that reads it itself (no request model), as a
    JSON object; 400 for a body that is not JSON or not an object (deny by
    default: such a body never reaches the handler's .get())."""
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001 - not JSON, not UTF-8, nested past the parser's depth
        raise HTTPException(status_code=400, detail="Invalid JSON in request body: send a JSON object.")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid request body: send a JSON object.")
    return data


def _object_list(data: Dict[str, Any], key: str, missing: str) -> List[Dict[str, Any]]:
    """`data[key]` as a non-empty list of JSON objects; 400 (`missing` when absent or empty) otherwise."""
    items = data.get(key)
    if not items:
        raise HTTPException(status_code=400, detail=missing)
    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        raise HTTPException(status_code=400, detail=f"`{key}` must be a list of JSON objects.")
    return items


# The text fields of an assessment check row (the `complete` payload the
# report endpoints take back): each is text, and a missing or null one is "".
_CHECK_TEXT_KEYS = ("id", "section", "label", "status", "detail")


def _check_rows(data: Dict[str, Any], missing: str) -> List[Dict[str, Any]]:
    """`data["checks"]` as check rows whose text fields are strings (filled
    with "" when absent or null); 400 naming the first field that is not text."""
    rows = _object_list(data, "checks", missing)
    for i, row in enumerate(rows):
        for k in _CHECK_TEXT_KEYS:
            if row.get(k) is None:
                row[k] = ""
            elif not isinstance(row[k], str):
                raise HTTPException(status_code=400, detail=f"`checks[{i}].{k}` must be text.")
    return rows


_XML_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_text(value: Any) -> Any:
    """`value` with every string stripped of the characters XML 1.0 cannot
    hold (control characters, lone surrogates): a Word document is XML, and
    one such character in a check or metadata field made the build fail (500)."""
    if isinstance(value, str):
        return _XML_UNSAFE.sub("", value)
    if isinstance(value, dict):
        return {_xml_text(k): _xml_text(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_xml_text(v) for v in value]
    return value


def _rule_rows(data: Dict[str, Any], missing: str) -> List[Dict[str, Any]]:
    """`data["rules"]` (the Evaluate All Rules migration's DLP rules) as
    objects whose name, state and action are text or absent; 400 otherwise."""
    return _rule_text_fields(_object_list(data, "rules", missing), "rules")


def _rule_text_fields(rows: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    """`rows` when each rule's name, state and action (what rule_migrator
    reads as text) are text or absent; 400 naming the first that is not."""
    for i, row in enumerate(rows):
        for k in ("name", "state", "action"):
            if row.get(k) is not None and not isinstance(row[k], str):
                raise HTTPException(status_code=400, detail=f"`{key}[{i}].{k}` must be text.")
    return rows


def _eval_all_exceptions(exc: Dict[str, Any]) -> Dict[str, Any]:
    """The optimiser's exceptions, checked: audit_only_actions a list of
    text, pinned an object whose position is a whole number, skip_rule_ids
    a list of ids (text or numbers). 400 otherwise."""
    actions = exc.get("audit_only_actions")
    if actions is not None and not (isinstance(actions, list) and all(isinstance(a, str) for a in actions)):
        raise HTTPException(status_code=400, detail="`exceptions.audit_only_actions` must be a list of actions (text).")
    pinned = exc.get("pinned")
    if pinned is not None:
        pos = pinned.get("position") if isinstance(pinned, dict) else None
        if not isinstance(pinned, dict) or (pos is not None and not (isinstance(pos, int) and not isinstance(pos, bool))):
            raise HTTPException(status_code=400, detail="`exceptions.pinned` must be {rule_id, position} with a whole-number position.")
    skip = exc.get("skip_rule_ids")
    if skip is not None and not (isinstance(skip, list) and all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in skip)):
        raise HTTPException(status_code=400, detail="`exceptions.skip_rule_ids` must be a list of rule ids.")
    return exc

@app.exception_handler(RecursionError)
async def _json_too_deep_handler(request: Request, exc: RecursionError):
    """A request body nested deeper than the JSON decoder goes (routes that
    read request.json() themselves) is the caller's error: 400, not 500."""
    if "decoding a JSON" in str(exc):
        return JSONResponse({"detail": "The JSON body is nested too deeply."}, status_code=400)
    return await _safe_exception_handler(request, exc)


# Assessment results posted back for a report view or export: an assessment
# has a few hundred checks (report_exports.MAX_CHECKS bounds the workbook);
# more is refused, and the work runs off the event loop.
def _require_report_size(results: Any) -> None:
    import report_exports
    if isinstance(results, list) and len(results) > report_exports.MAX_CHECKS:
        raise HTTPException(status_code=413, detail=f"Too many checks in one report ({len(results)}; at most {report_exports.MAX_CHECKS}).")


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
# A "head-script" goes before </head> instead: it runs before the first paint.
GUI_ADDONS = [
    ("deploy_studio.css", "style"),
    ("guide.css", "style"),
    ("reports.css", "style"),
    ("dashboard.css", "style"),
    ("hover_help.css", "style"),
    ("glass.css", "style"),         # the glass effect (also @imported by reports.css): last, so it layers over the others
    ("glass.js", "head-script"),    # in <head>: the viewer's glass on/off choice is on <html> before the first paint
    ("icons.js", "script"),         # first: the symbol set every page and add-on draws its icons from
    ("ui_auth.js", "script"),       # the in-app unlock and notice dialogs the fetch wrapper and the guide use
    ("rate_gate.js", "script"),     # the rate-limit check every deploy and delete confirms with
    ("deploy_studio.js", "script"),
    ("explain.js", "script"),
    ("find_anything.js", "script"),  # Find anything (Ctrl/Cmd+J): pages, glossary terms, tenant objects, findings
    ("offline_tenant.js", "script"),  # the sample tenant and snapshots, beside the tenant profiles (guide.js draws them)
    ("guide.js", "script"),
    ("readiness.js", "script"),     # the readiness summary after sign-in; greys out what this API client cannot do
    ("update_beacon.js", "script"),  # checks for updates in the background and shows a notice when one is out
    ("eval_all.js", "script"),
    ("bypass_report.js", "script"),
    ("tool_tabs.js", "script"),
    ("simple_entry.js", "script"),   # the "Try Simple mode" banner and the deep links from /simple
    ("posture_banner.js", "script"),  # the coverage line and the score-drop banner on the results (posture_plus)
    ("whats_new.js", "script"),     # the * after each new feature's label (the newest two releases), with its legend
    ("help_catalog.js", "script"),  # the words of Help on hover, per page and control
    ("hover_help.js", "script"),    # Help on hover: a pop-up for every control (watches for new ones)
    ("sidebar_order.js", "script"),  # drag / Alt+arrow reordering of the sidebar; dashboard.js starts it
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
        elif kind == "head-script":
            tag, pos = f'<script src="/static/{name}?v={v}"></script>\n', html.find("</head>")
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
    # Legacy single scope, kept for MCP / CLI callers that set it on purpose.
    # Left unset with no `scopes`, the request is refused: nothing is assessed
    # unless it was put in scope.
    scope: str = "full"
    scopes: list[str] = []  # list of scope keys (dlp, zia_extras, zpa, zcc, ...): the Scope page's choice
    customer_id: str = ""  # Optional ZPA customer ID
    profile_id: str = ""   # Saved tenant profile: fills blanks, records history
    # The Scope page's channel ownership: {id: {choice: zscaler|alternative|gap, note, name}}.
    # Only a Zscaler channel is read; an alternative or a gap has its checks
    # reported as not in scope instead of read from the tenant (channel_scope).
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
        _security._audit_denied(request, "auth_denied", "the UI token offered to unlock was not valid")
        raise HTTPException(status_code=401, detail="That UI token is not valid for this server. Read ui_token.txt next to the app (or the console) and try again.")
    resp = JSONResponse({"ok": True, "required": True})
    _security.set_ui_cookie(resp, request)
    return resp


@app.get("/api/auth/sso/login")
async def sso_login(request: Request):
    """Start an OpenID Connect sign-in: redirect to the identity provider,
    with a cookie that binds the sign-in to this browser."""
    if not _sso.sso_enabled():
        raise HTTPException(status_code=404, detail="SSO is not enabled on this server.")
    binding = _sso.new_login_binding()
    try:
        url = _sso.start_login(binding)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not start SSO sign-in: {e}")
    resp = RedirectResponse(url, status_code=302)
    _security.set_login_cookie(resp, request, binding)
    return resp


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
        claims = _sso.complete_login(state, code, request.cookies.get(_security.SSO_LOGIN_COOKIE) or "")
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
    _security.clear_login_cookie(resp, request)
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
    latest UI after running UPDATE_Zscaler_Made_Easy.bat — no more
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
    confirm: bool = False      # dry_run=false needs confirm=true, the assessor, a writer and write mode
    assessor: str = ""
    profile_id: str = ""
    scopes: List[str] = []     # the Scope page selection (user rule 1): a live fix writes only a policy in scope
    channels: Dict[str, Any] = {}
    from_page: bool = False


# The rule policy (admin_ops.POLICIES) each fix recipe writes in; "Add
# description" writes in the policy of the rule type it names.
_REMEDIATION_POLICY = {"FW-01": "firewall", "URL-01": "url_filtering", "SSL-01": "ssl_inspection", "DLP-01": "web_dlp"}
_REMEDIATION_RULE_TYPE_POLICY = {"webDlpRules": "web_dlp", "urlFilteringRules": "url_filtering",
                                 "firewallFilteringRules": "firewall", "sslInspectionRules": "ssl_inspection"}


def _require_recipe_in_scope(check_id: Any, criteria: Any, selection: Any, what: str = "Applying a remediation") -> None:
    """A fix recipe reads and writes one ZIA rule policy: it must be in scope
    on the Scope page (the Bulk changes rule, admin_ops.scope_for), else 400
    before sign-in. A recipe whose policy is not known is refused (deny by
    default). `selection` is any body carrying the Scope page selection
    (scopes, channels, from_page, profile_id; see _scope_selection). Used by
    the direct apply (POST /api/remediation/execute) and by the change queue
    when a fix recipe is filed and when it is applied, so neither path can
    write a policy the Scope page left out."""
    import admin_ops
    import remediation
    rid = str((remediation.get_recipe(str(check_id or "")) or {}).get("check_id") or "")
    criteria = criteria if isinstance(criteria, dict) else {}
    pol = _REMEDIATION_RULE_TYPE_POLICY.get(str(criteria.get("rule_type") or "")) if rid == "RULE-DESC" else _REMEDIATION_POLICY.get(rid)
    if not pol:
        raise HTTPException(status_code=400, detail=f"{what}: this fix's rule policy is not known, so it cannot be checked "
                                                    "against the Scope page. Nothing was read or written.")
    sc, ch, _source = _scope_selection(selection)
    scope = admin_ops.scope_for(sc, ch)
    if pol not in scope["policies"]:
        label = admin_ops.POLICIES[pol]["label"]
        why = str((scope.get("not_in_scope") or {}).get(pol) or "")
        raise HTTPException(status_code=400, detail=f"{what} is not in scope: {label} is not in scope on the Scope page. "
                                                    + (f"{why} " if why else "") + "Nothing was read or written.")


def _require_remediation_in_scope(req: "RemediationExecuteRequest") -> None:
    """The direct apply's Scope check (_require_recipe_in_scope on the request's own fix)."""
    _require_recipe_in_scope(req.check_id, req.criteria, req)


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
    dry_run=False needs a writer, confirm=true, the assessor's name and
    write mode, all checked before the tenant is signed in to."""
    try:
        from remediation import execute
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"remediation unavailable: {e}")
    if not req.dry_run:
        _require_tenant_write(req, confirmed=req.confirm, what="Applying a remediation")
        _require_remediation_in_scope(req)
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
    # What is in scope (user rule 1): the Scope page's ticked `scopes` and
    # channel declaration (`channels`), else (nothing sent and `from_page`
    # false) the chosen profile's saved selection (_scope_selection). Every
    # endpoint that reads the tenant with this body checks it before sign-in
    # (_require_in_scope); nothing in scope is refused (400).
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


def _raw_client(creds: Dict[str, str]):
    """The raw-HTTP assessment client for validated credentials, either
    sign-in (tenant_auth). Not yet signed in. Offline credentials (the
    sample tenant, a snapshot) get the offline client, which has no network
    code (offline_tenant)."""
    off = _offline_client(creds, "raw")
    if off is not None:
        return off
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
    hint. Lets users see what's readable vs blocked vs not-exposed.
    Only when ZCC is in scope on the Scope page (else 400, nothing read)."""
    _require_in_scope(req, "zcc", "ZCC endpoint diagnostics")
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
    confirm: bool = False  # deploying (plan_hash given) needs confirm=true too


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
    all: bool = False      # everything Zscaler Made Easy ever put in the tenant, not just the listed packs
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
    try:   # an unknown sign-in method is the caller's mistake: 400 here, never a ValueError (500) further in
        tenant_auth.normalize_method(getattr(req, "auth_method", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    off = _offline_creds()   # the sample tenant or an opened snapshot (offline_tenant): never the form's, a profile's or the server's
    if off is not None:
        return off
    creds = {k: str(getattr(req, k, "") or "").strip() for k in tenant_auth.CRED_KEYS}
    # A cloud the body did not send is the model's default ("production"),
    # not a typed value: the profile, environment or tenant_config.json
    # names the cloud, and the default applies only when none does.
    sent = getattr(req, "model_fields_set", None)
    default_cloud = ""
    if sent is not None and "cloud" not in sent:
        default_cloud, creds["cloud"] = creds["cloud"], ""
    if not tenant_auth.started(creds):
        # Nothing typed for a tenant: the source that has the sign-in decides
        # its method (the form always sends its selector, OneAPI by default).
        creds["auth_method"] = ""
    creds = _fill_from_profile(creds, getattr(req, "profile_id", ""))
    if not tenant_auth.complete(creds):
        env = tenant_auth.from_env()
        base = tenant_auth.without_identity(creds)
        if tenant_auth.complete(env) and _same_sign_in(base, env):
            creds = tenant_auth.merge(base, env)
    if not tenant_auth.complete(creds):
        cfg_path = os.path.join(_APP_DIR, "tenant_config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f) or {}
                base = tenant_auth.without_identity(creds)
                if isinstance(cfg, dict) and tenant_auth.complete(cfg) and _same_sign_in(base, cfg):
                    creds = tenant_auth.merge(base, cfg)
            except Exception:
                pass
    creds = tenant_auth.normalize(creds)
    if not creds["cloud"] and default_cloud:
        creds["cloud"] = default_cloud
    return creds


def _assessor(req: Any) -> str:
    """The assessor's name for a pack deploy: the request's, else the saved
    profile's, else blank (a deploy then refuses: _require_assessor). Sanitized as the
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


ASSESSOR_REQUIRED = ("Enter the assessor's name (Scope assessment → Assessor name) before pushing a policy pack. "
                     "Every object a pack creates names the assessor in its description, never Zscaler Made Easy.")
ASSESSOR_NOT_TOOL = ("The assessor's name must name the person who assesses and deploys the pack, not the tool "
                     "(no \"Zscaler Made Easy\" in any spelling): it is part of every pushed object's description.")


def _require_assessor(req: Any) -> str:
    """The assessor's name, or a 400 before anything is read or written:
    a pack push (deploy, single-pack import, Terraform hand-off) always
    names the assessor in the objects it creates, never Zscaler Made Easy."""
    import pack_deploy
    given = getattr(req, "assessor", "") or ""
    if not str(given).strip():
        pid = getattr(req, "profile_id", "") or ""
        if pid:
            try:
                import tenant_profiles
                given = (tenant_profiles.get(pid) or {}).get("assessor") or ""
            except Exception:  # noqa: BLE001 — a missing profile only loses the name
                given = ""
    if pack_deploy.is_tool_name(given):
        # The tool's own name, in any spelling (pack_deploy.TOOL_NAME_PATTERN, the
        # rule the Terraform CLI and var.assessor apply): refused, never rewritten.
        raise HTTPException(status_code=400, detail=ASSESSOR_NOT_TOOL)
    name = _assessor(req)
    if not name:
        raise HTTPException(status_code=400, detail=ASSESSOR_REQUIRED)
    return name


TENANT_WRITE_ASSESSOR_REQUIRED = ("Enter the assessor's name (Scope assessment → Assessor name) before changing the tenant: "
                                  "every change to a tenant is made in the name of the person who assesses it.")


def _require_write_assessor(req: Any) -> str:
    """_require_assessor for any tenant write, with a message that is not
    about packs. The name falls back to the saved profile's assessor."""
    try:
        return _require_assessor(req)
    except HTTPException as e:
        if e.detail == ASSESSOR_REQUIRED:
            raise HTTPException(status_code=400, detail=TENANT_WRITE_ASSESSOR_REQUIRED)
        raise


def _require_tenant_write(req: Any, *, confirmed: bool, what: str) -> str:
    """Every refusal a tenant write makes before it signs in (deny by
    default, fail closed): a writer (SSO), the explicit confirmation, the
    assessor's name and write mode. Returns the assessor's name."""
    _security.require_writer()
    if confirmed is not True:
        raise HTTPException(status_code=400, detail=f"{what} requires explicit confirmation (confirm=true).")
    by = _require_write_assessor(req)
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    return by


def _tenant_key(c: Dict[str, Any]) -> str:
    """The tenant's key in zia_rate's state (opaque): the vanity domain and
    API client's hash for OneAPI, the keyed fingerprint for the classic API
    (tenant_fingerprint), so classic-API tenants on one cloud (one label,
    'classic API (cloud)') stay apart. Never shown."""
    import tenant_fingerprint
    return tenant_fingerprint.tenant_key(c)


def _record_ids(c: Dict[str, Any]) -> Dict[str, str]:
    """What a deployment record keeps to tell its tenant apart (never shown):
    the classic API's fingerprint, or OneAPI's opaque key."""
    import tenant_fingerprint
    return tenant_fingerprint.record_ids(c)


def _same_tenant(rec: Dict[str, Any], creds: Dict[str, Any]) -> bool:
    """Whether a deployment record was made in the tenant these credentials
    point at (tenant_fingerprint.same_tenant): its label (current or older
    form), then its fingerprint or opaque key when it has one."""
    import tenant_fingerprint
    return tenant_fingerprint.same_tenant(rec, creds)


def _require_same_tenant(rec: Dict[str, Any], creds: Dict[str, Any]) -> None:
    """409 when the record was made in another tenant (undo and removal)."""
    if _same_tenant(rec, creds):
        return
    label = tenant_auth.record_label(creds)
    where = rec.get("tenant_label") or "another tenant"
    if where == label:
        where = f"another {label} tenant"
    raise HTTPException(status_code=409, detail=f"This deployment was made in {where}, but the current credentials are for {label}. Switch tenant first.")


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
    stored = tenant_profiles.creds_from(prof)
    if not _same_sign_in(creds, stored):
        return creds
    return tenant_auth.merge(creds, stored)


def _same_sign_in(typed: Dict[str, Any], stored: Dict[str, Any]) -> bool:
    """Whether a stored sign-in (a profile, the environment, tenant_config.json)
    may fill the blanks of `typed`: no typed vanity domain, client id or
    admin username names another tenant than the stored one. A stored
    secret is only ever sent with its own identity, to its own tenant's
    sign-in host (the vanity domain decides the ZIdentity host); typing
    another tenant's name leaves it unused (fail closed: the sign-in is
    then incomplete and refused with the missing field)."""
    t, s = tenant_auth.normalize(typed), tenant_auth.normalize(stored)
    for key, fold in (("vanity_domain", True), ("client_id", False), ("username", True)):
        a, b = t[key], s[key]
        if fold:
            a, b = a.casefold(), b.casefold()
        if a and b and a != b:
            return False
    return True


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
    in an error. Offline credentials (the sample tenant, a snapshot) get
    the offline client before anything else: it has no network code."""
    import zia_rate
    off = _offline_client(creds, "sdk")
    if off is not None:
        return off
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
            return zia_rate.attach_client(tenant_auth.build_legacy_sdk_client(c, timeout=SDK_REQUEST_TIMEOUT, max_retries=SDK_MAX_RETRIES,
                                                                             max_retry_seconds=SDK_MAX_RETRY_SECONDS),
                                          rate_key, rate_label)
        except ImportError:
            raise HTTPException(status_code=503, detail="zscaler-sdk-python is not installed. Run: pip install -r requirements.txt")
        except Exception as e:  # noqa: BLE001 — the helper signs in as it is built
            _note_auth_failure()
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
    if c.get("customer_id"):
        # ZPA services build their paths from it (/zpa/mgmtconfig/v1/admin/customers/{customerId}).
        config["customerId"] = c["customer_id"]
    tenant_auth.bound_sdk_sign_in()   # the SDK's token request has no timeout of its own
    try:
        client = ZscalerClient(config)
        auth = getattr(client, "authenticate", None)
        if callable(auth):
            auth()
    except Exception as e:
        _note_auth_failure()
        reason = tenant_auth.mask_secrets(str(e), c)[:200]   # no character or length of the secret, in any encoding
        raise HTTPException(status_code=401, detail=f"Authentication failed for client_id={mask_secret(cid)}: {reason}")
    # Every ZIA answer on this client's session feeds the next preflight's rate-limit check.
    return zia_rate.attach_client(client, rate_key, rate_label)


def _note_auth_failure() -> None:
    """Self-healing counts sign-in failures (no detail, never a secret) to drop a cached sign-in that keeps failing."""
    try:
        import self_heal
        self_heal.note_auth_failure()
    except Exception:  # noqa: BLE001
        pass


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
    name_filter: str = ""      # literal, case-insensitive substring the dictionary names contain (^ starts with, $ ends with; never a regex; "" = every custom dictionary)
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
    # The server keeps its own copy: Plan (PDF) / Plan (Excel) render from it, never from the page.
    out["report_id"] = _remember_plan(out, _assessor(req))
    _cq_remember("pack_deploy", out, req, creds)   # lets "Request approval" file exactly this plan
    return out


# ── FP/TP Detection Ratio (continuous evaluation, phase 1) ──────────────────
class DetectionHealthRequest(TenantCredsRequest):
    """Body of a FP/TP Detection Ratio run: the window in days, threshold
    overrides and what is in scope (the Scope page's ticked `scopes` and
    channel declaration `channels`, else, with neither and `from_page`
    false, the chosen profile's saved selection)."""
    days: int = 30
    settings: Dict[str, Any] = {}     # threshold overrides, see detection_health.DEFAULTS
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


DH_NOTHING_IN_SCOPE = ("Nothing the FP/TP Detection Ratio reads is in scope — on the Scope page tick DLP and mark at least one DLP "
                       "channel (Inline Web, Endpoint, SaaS Security, Email) as run on Zscaler, then run it again.")
DH_WA_ALTERNATIVE = ("Workflow Automation is covered by another product on the Scope page, so its incidents (the FP/TP Detection "
                     "Ratio's input) are not read and the ratio is not measured.")
LIVE_NOTHING_IN_SCOPE = ("Nothing the live feed reads is in scope — it shows Workflow Automation's DLP incidents: on the Scope page "
                         "tick DLP and mark Workflow Automation as run on Zscaler, then start the feed again.")


def _dlp_read_scope(req: Any) -> Dict[str, Any]:
    """What a DLP read started from a page (FP/TP Detection Ratio, live
    feed) may read: continuous_eval.profile_scope of _scope_selection, as
    the scheduled loop reads a profile, plus where it came from. Never
    reads a tenant."""
    import continuous_eval
    import data_flow
    sc, ch, source = _scope_selection(req)
    # Only the Scope page's own keys count, exactly as every other tenant
    # read checks them (_require_in_scope): profile_scope's lenient
    # spelling ("DLP", " dlp") is for hand-edited saved profiles in the
    # loop, and must not put a request in scope here (fail closed).
    sc = [s for s in sc if s in data_flow.SCOPE_KEYS]
    import dlp_analysis
    out = continuous_eval.profile_scope({"scopes": sc, "channels": dlp_analysis.channels(ch, sc)})
    out["required_controls"] = dlp_analysis.requirements(sc, ch)
    out["source"] = source
    return out


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
    # Only what the Scope page puts in scope is read (user rule 1), as the
    # scheduled loop reads a profile: the rules of the DLP channels marked
    # Zscaler, and Workflow Automation's incidents only when it is marked
    # Zscaler. Nothing in scope is refused here, before signing in.
    sc = _dlp_read_scope(req)
    if not sc["dlp"] or not sc["pack_channels"]:
        raise HTTPException(status_code=400, detail=DH_NOTHING_IN_SCOPE)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    days = max(1, min(int(req.days or 30), 180))
    logs: list = []
    if sc["source"]:
        logs.append(f"In scope, from {sc['source']}: the DLP rules on {', '.join(sc['pack_channels'])}"
                    + ("" if sc["read_incidents"] else "; Workflow Automation is not marked as run on Zscaler, so its incidents are not read") + ".")
    # An SDK error that echoes the sign-in's secret never reaches the report or its log.
    scrub = lambda text: tenant_auth.mask_secrets(str(text), creds)  # noqa: E731
    report = await asyncio.to_thread(lambda: detection_health.generate(client, days=days, settings=req.settings or None,
                                                                       log=lambda m: logs.append(scrub(m)), scrub=scrub,
                                                                       channels=list(sc["pack_channels"]), read_incidents=bool(sc["read_incidents"])))
    import dlp_analysis
    raw = await asyncio.to_thread(_build_client, req)
    requested_scopes, requested_channels, _ = _scope_selection(req)
    report["required_controls"] = await asyncio.to_thread(dlp_analysis.inspect, raw, requested_scopes, requested_channels)
    report["logs"] = logs
    report["scope"] = {"scopes": sc["scopes"], "pack_channels": list(sc["pack_channels"]), "read_incidents": bool(sc["read_incidents"]),
                       "source": sc["source"]}
    report["profile_id"] = getattr(req, "profile_id", "") or ""   # lets the tab apply proposals with the profile's remembered secret
    # The proposal queue's key: the vanity domain for OneAPI, an opaque
    # fingerprint key for the classic API (never a vanity domain left in
    # the form); proposals queued under that stale domain move to it.
    import continuous_eval
    report["tenant_key"] = continuous_eval._proposal_key_migrated(creds, report["profile_id"])
    try:
        import proposals
        if (report.get("read") or {}).get("incidents", True) is False:
            # Incidents not read are not "no incident": as in the loop, only
            # what the rules alone show is proposed, and nothing raised when
            # incidents were read is resolved.
            report["proposals"] = proposals.merge(report["tenant_key"], proposals.build_proposals(report, report["tenant_key"]), resolve_missing=False)
        else:
            report["proposals"] = proposals.refresh_from_report(report, report["tenant_key"])
    except Exception as e:  # noqa: BLE001
        report["proposals"] = {"error": scrub(e)[:200]}
    rid = _remember_report("health", report, tenant_auth.record_label(creds))
    return _REPORTS[rid]


# ── Live feed (continuous evaluation, live view) ───────────────────────
# What this genuinely shows live: Workflow Automation's own DLP incident
# stream, polled on a moving window. It is not every ZIA transaction —
# see the coverage note the endpoint always returns.
_LIVE_RULES_TTL_SECONDS = 90
_live_rules_cache: Dict[str, Any] = {}   # tenant key -> (expires_at, {rule name: action})
_live_connector_cache: Dict[str, Any] = {}
LIVE_FEED_COVERAGE_NOTE = (
    "This feed shows Workflow Automation's DLP-matched incidents only — the user, the rule and dictionaries that "
    "matched, and the destination, live as they land. It does not cover URL Filtering, Cloud App Control or "
    "Firewall & DNS Control decisions that never trip a DLP rule; that wider transaction log is Web Insights / "
    "Cloud NSS, a feed to your own log store (Splunk, S3, a syslog receiver) that this app does not read."
)


def _live_rule_actions(client, tenant_key: str, channels: Optional[List[str]] = None) -> Dict[str, str]:
    """rule name -> configured action, cached briefly per tenant and per
    set of in-scope channels so a poll every few seconds does not re-read
    the rule inventory every time (rule actions do not change that often)
    and a changed Scope page is read afresh. Only the rules of `channels`
    (the DLP channels in scope) are read; none in scope reads nothing."""
    import time as _time
    import detection_health
    chans = sorted({str(c) for c in (channels or [])})
    if not chans:
        return {}
    key = f"{tenant_key}|{','.join(chans)}"
    now = _time.time()
    cached = _live_rules_cache.get(key)
    if cached and cached[0] > now:
        return cached[1]
    m = detection_health.rule_actions(client, channels=chans)
    _live_rules_cache[key] = (now + _LIVE_RULES_TTL_SECONDS, m)
    return m


def _live_connector_context(creds, scopes):
    """Briefly cached, tenant-separated profile references; only when ZCC is in scope."""
    import data_flow
    import time as _time
    import tenant_fingerprint
    if "zcc" not in scopes:
        return {"status": "out_of_scope", "profiles": [], "errors": [],
                "note": "Client Connector profiles were not read because ZCC is not in scope."}
    key = tenant_fingerprint.proposal_key(creds, tenant_auth.record_label(creds))
    now = _time.time()
    cached = _live_connector_cache.get(key)
    if cached and cached[0] > now:
        return cached[1]
    raw = _raw_client(creds)
    try:
        # PAC inventory is part of connector routing context; no policy reads.
        scope = data_flow.path_scope(["zcc"], {})
        zcc = data_flow.read_client_connector(raw, scope=scope)
        result = data_flow.connector_references(zcc)
        result["status"] = "unverified" if result["errors"] else "read"
        result["read_at"] = datetime.now(timezone.utc).isoformat()
        # A failed read is not cached, so the next poll can recover.
        if not result["errors"]:
            if len(_live_connector_cache) >= 128:
                _live_connector_cache.clear()
            _live_connector_cache[key] = (now + _LIVE_RULES_TTL_SECONDS, result)
        return result
    finally:
        _close_quietly(raw)


class LiveFeedRequest(TenantCredsRequest):
    """One poll of the live DLP incident feed. `since` is the ISO
    timestamp `next_since` from the previous poll (blank starts a new
    feed, looking back two minutes); `stats` is the running tally this
    endpoint returned last time, echoed back so the server stays
    stateless between polls."""
    since: str = ""
    stats: Dict[str, Any] = {}
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


_LIVE_TALLY_KEYS = ("seen", "enforced", "monitor", "unknown_action", "open", "real", "not_real")


def _live_tally(stats: Any) -> Optional[Dict[str, int]]:
    """The running tally the page sends back (untrusted): its counters as
    whole numbers from 0 to 10**12 (anything else is 0), None to start a
    new one. A missing or non-numeric counter was a KeyError / TypeError (500)."""
    if not isinstance(stats, dict) or not stats:
        return None
    num = lambda v: max(0, min(v, 10 ** 12)) if isinstance(v, int) and not isinstance(v, bool) else 0  # noqa: E731
    return {k: num(stats.get(k)) for k in _LIVE_TALLY_KEYS}


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
    since = None
    if req.since:
        try:
            since = datetime.fromisoformat(req.since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="'since' is not a valid timestamp; leave it blank to start a new feed.")
    # Only what the Scope page puts in scope is read (user rule 1): the
    # incidents only with DLP ticked and Workflow Automation marked
    # Zscaler, the rule actions only of the DLP channels marked Zscaler.
    # Nothing in scope is refused here, before signing in.
    sc = _dlp_read_scope(req)
    if not sc["dlp"]:
        raise HTTPException(status_code=400, detail=LIVE_NOTHING_IN_SCOPE)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = tenant_auth.record_label(creds)   # never the classic API's admin login (user rule 3)
    # An SDK error that echoes the sign-in's secret never reaches the feed.
    poll = (await asyncio.to_thread(detection_health.poll_incidents, client, since,
                                    scrub=lambda text: tenant_auth.mask_secrets(str(text), creds))) if sc["read_incidents"] else {"incidents": [], "next_since": req.since, "errors": [DH_WA_ALTERNATIVE], "read_at": datetime.now(timezone.utc).isoformat()}
    import tenant_fingerprint
    # The rule cache's key names no classic-API tenant by a vanity domain or
    # its admin login (an opaque fingerprint key), and keeps two classic
    # tenants on one cloud apart.
    rules_by_name = await asyncio.to_thread(_live_rule_actions, client, tenant_fingerprint.proposal_key(creds, label), list(sc["pack_channels"]))
    for i in poll["incidents"]:
        i["enforcement"] = detection_health.incident_action(i, rules_by_name)   # "enforced" | "monitor" | "unknown", from the rule's real action
        i["action_source"] = "current_rule_configuration"
        i["event_enforcement"] = "unknown"  # current configuration is not event-time proof
    import dlp_analysis
    requested_scopes, requested_channels, _ = _scope_selection(req)
    raw = await asyncio.to_thread(_build_client, req)
    required_controls = await asyncio.to_thread(dlp_analysis.inspect, raw, requested_scopes, requested_channels)
    stats = detection_health.live_stats(_live_tally(req.stats), poll["incidents"], rules_by_name)
    connector = await asyncio.to_thread(_live_connector_context, creds, sc["scopes"])
    return {"incidents": poll["incidents"], "next_since": poll["next_since"], "errors": poll["errors"], "stats": stats,
            "tenant_label": label, "read_at": poll["read_at"], "coverage_note": LIVE_FEED_COVERAGE_NOTE,
            "client_connector": connector, "required_controls": required_controls, "read": {"incidents": bool(sc["read_incidents"])}}


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


# ── Team change queue: change requests with four-eyes approval ────────────
# A deploy plan, a selective removal plan or a fix recipe someone prepared
# but did not apply, filed for another writer to approve (change_queue.py).
# Who files, approves, rejects, withdraws or applies is always the server's
# view of the caller (_actor), never a name sent by the page. Applying runs
# the existing apply path (_run_apply, _run_removal, remediation.execute)
# as a job the page follows at /api/dlp-packs/jobs/{id}.
_CQ_PLANS: Dict[str, Dict[str, Any]] = {}     # plan_hash -> a preflight this server just produced
_CQ_PLANS_LOCK = threading.Lock()
_CQ_PLAN_TTL = 3600.0
_CQ_PLAN_MAX = 64
_CQ_WRITE_STATUSES = ("create", "modify", "restore")


def _cq_tenant(creds: Dict[str, str]) -> Tuple[str, str]:
    """(queue key, label) of the tenant these credentials sign in to: the
    proposal queue's key (the vanity domain for OneAPI, an opaque
    fingerprint for the classic API) and the label shown on screen."""
    import proposals
    import tenant_fingerprint
    label = tenant_auth.record_label(creds)
    return proposals.tenant_key(tenant_fingerprint.proposal_key(creds, label)), label


def _cq_deploy_params(req: Any) -> Dict[str, Any]:
    return {"pack_ids": sorted(req.pack_ids or []), "use_rank_0": bool(req.use_rank_0), "apply_tweaks": bool(req.apply_tweaks),
            "restore_drift": bool(req.restore_drift),
            "channel_targets": {k: sorted(v or []) for k, v in sorted((req.channel_targets or {}).items())}}


def _cq_removal_params(req: Any) -> Dict[str, Any]:
    rules = [{"kind": str(r.get("kind") or "policy"), "channel": str(r.get("channel") or ""), "id": str(r.get("id"))}
             for r in (req.rules or []) if isinstance(r, dict) and r.get("id") is not None]
    return {"rules": sorted(rules, key=lambda r: (r["kind"], r["channel"], r["id"]))}


def _cq_remember(kind: str, report: Dict[str, Any], req: Any, creds: Dict[str, str]) -> None:
    """Keep a preflight (deploy) or removal preview this server produced,
    so filing it as a change request needs no second tenant read and the
    approver sees exactly what the server planned, never what a page says
    it planned. Never fails the preflight."""
    try:
        h = str(report.get("plan_hash") or "")
        if not h:
            return
        tk, label = _cq_tenant(creds)
        params = _cq_deploy_params(req) if kind == "pack_deploy" else _cq_removal_params(req)
        now = time.time()
        with _CQ_PLANS_LOCK:
            for k in [k for k, v in _CQ_PLANS.items() if now - v["at"] > _CQ_PLAN_TTL]:
                _CQ_PLANS.pop(k, None)
            while len(_CQ_PLANS) >= _CQ_PLAN_MAX:
                _CQ_PLANS.pop(min(_CQ_PLANS, key=lambda k: _CQ_PLANS[k]["at"]), None)
            _CQ_PLANS[h] = {"at": now, "kind": kind, "tenant": tk, "label": label, "params": params, "report": report}
    except Exception:  # noqa: BLE001 — a filing then re-reads the tenant instead
        pass


def _cq_cached(plan_hash: str, kind: str, tenant: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    with _CQ_PLANS_LOCK:
        hit = _CQ_PLANS.get(plan_hash or "")
        if hit and hit["kind"] == kind and hit["tenant"] == tenant and hit["params"] == params and time.time() - hit["at"] <= _CQ_PLAN_TTL:
            return hit["report"]
    return None


def _cq_by(request: Request) -> str:
    return _actor(request) or _security.current_actor() or "unknown"


def _cq_fail(e: Exception):
    import change_queue
    if isinstance(e, change_queue.QueueError):
        raise HTTPException(status_code=e.status, detail=str(e))
    raise e


class ChangeRequestDeploy(DLPPackDeployRequest):
    """File a Deploy policy packs plan: the preflight's packs, options,
    channel targets and plan_hash, plus a title and a first comment."""
    title: str = ""
    note: str = ""


class ChangeRequestRemoval(PackRemovalRequest):
    """File a selective removal plan: the picked rules and the preview's plan_hash."""
    title: str = ""
    note: str = ""


class ChangeRequestRecipe(TenantCredsRequest):
    """File a fix recipe: the check, the recipe parameters, a title and a
    first comment, plus the Scope page selection (the recipe's rule policy
    must be in scope to be filed, as for the direct apply)."""
    check_id: str = ""
    criteria: Dict[str, Any] = {}
    title: str = ""
    note: str = ""
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


class ChangeRequestDecision(BaseModel):
    """Approve, reject, withdraw or comment: the comment only. Who does it is the server's view of the caller."""
    comment: str = ""
    by: str = ""      # ignored if a page sends it: the server names the actor


class ChangeRequestApply(TenantCredsRequest):
    """Apply an approved request: the tenant credentials and the typed
    confirmation phrase, plus the Scope page selection (a fix recipe's rule
    policy must still be in scope when it is applied)."""
    confirm: str = ""
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


@app.post("/api/change-queue/deploy")
async def change_queue_file_deploy(req: ChangeRequestDeploy, request: Request):
    """File a policy-pack deploy plan as a pending change request. The plan
    is the one this server's preflight produced for that plan_hash (kept
    for an hour), else the preflight is run again and must give the same
    plan_hash. Writes nothing to the tenant; needs no writer rights."""
    import change_queue
    import pack_deploy
    if not req.pack_ids:
        raise HTTPException(status_code=400, detail="Select at least one pack.")
    if not req.plan_hash:
        raise HTTPException(status_code=400, detail="Run the preflight first: a change request carries the plan_hash of the plan it asks for.")
    packs = _resolve_pack_ids(req.pack_ids)
    creds = _tenant_creds(req)
    tk, label = _cq_tenant(creds)
    params = _cq_deploy_params(req)
    report = _cq_cached(req.plan_hash, "pack_deploy", tk, params)
    if report is None:
        client = await asyncio.to_thread(_build_sdk_client, creds)
        report = pack_deploy.public_report(await asyncio.to_thread(
            pack_deploy.preflight, client, packs, use_rank_0=req.use_rank_0, apply_tweaks=req.apply_tweaks, writes_enabled=writes_enabled(),
            restore_drift=req.restore_drift, channel_targets=req.channel_targets or None))
        if report.get("plan_hash") != req.plan_hash:
            raise HTTPException(status_code=409, detail="The tenant changed since your preflight: run the preflight again and request approval for the new plan.")
    if report.get("status") == "blocked":
        raise HTTPException(status_code=409, detail="This plan is blocked: " + " ".join(report.get("blockers") or []) + " Resolve the blockers before requesting approval.")
    all_items = report.get("items") or []
    items = [{"kind": i.get("kind"), "name": i.get("name"), "status": i.get("status"),
              "channel": (i.get("detail") or {}).get("channel") if i.get("kind") == "policy" else None,
              "note": str(i.get("reason") or "")[:200]} for i in all_items if i.get("status") in _CQ_WRITE_STATUSES]
    if not items:
        raise HTTPException(status_code=409, detail="Nothing to write: every object of this plan already exists or is skipped, so there is nothing to approve.")
    summary: Dict[str, int] = {}
    for i in all_items:
        summary[str(i.get("status"))] = summary.get(str(i.get("status")), 0) + 1
    try:
        rec = change_queue.file_request(
            kind="pack_deploy", tenant=tk, tenant_label=label,
            title=req.title or f"Deploy {', '.join(params['pack_ids'])}: {len(items)} change(s)", summary=summary, items=items,
            plan_hash=req.plan_hash, requested_by=_cq_by(request), note=req.note, payload=dict(params, verify=bool(req.verify)))
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)
    return {"request": rec}


@app.post("/api/change-queue/removal")
async def change_queue_file_removal(req: ChangeRequestRemoval, request: Request):
    """File a selective removal plan (rules picked in Deploy policy packs and
    the engines and dictionaries only they use) as a pending change request,
    bound to the removal preview's plan_hash. Writes nothing."""
    import change_queue
    import pack_removal
    if not req.rules:
        raise HTTPException(status_code=400, detail="Pick the rules to remove first.")
    if not req.plan_hash:
        raise HTTPException(status_code=400, detail="Preview the removal first: a change request carries the plan_hash of the plan it asks for.")
    creds = _tenant_creds(req)
    tk, label = _cq_tenant(creds)
    params = _cq_removal_params(req)
    report = _cq_cached(req.plan_hash, "pack_removal", tk, params)
    if report is None:
        client = await asyncio.to_thread(_build_sdk_client, creds)
        report = await asyncio.to_thread(lambda: pack_removal.plan_removal_selected(client, req.rules))
        if report.get("plan_hash") != req.plan_hash:
            raise HTTPException(status_code=409, detail="The tenant changed since your preview: preview the removal again and request approval for the new plan.")
    all_items = report.get("items") or []
    items = [{"kind": i.get("kind"), "name": i.get("name"), "status": i.get("status"), "channel": i.get("channel"),
              "note": str(i.get("keep") or "")[:200]} for i in all_items if i.get("status") in ("remove", "keep")]
    if not any(i["status"] == "remove" for i in items):
        raise HTTPException(status_code=409, detail="Nothing to remove in this plan, so there is nothing to approve.")
    summary: Dict[str, int] = {}
    for i in items:
        summary[i["status"]] = summary.get(i["status"], 0) + 1
    try:
        rec = change_queue.file_request(
            kind="pack_removal", tenant=tk, tenant_label=label,
            title=req.title or f"Remove {summary.get('remove', 0)} object(s) from {label}", summary=summary, items=items,
            plan_hash=req.plan_hash, requested_by=_cq_by(request), note=req.note, payload=params)
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)
    return {"request": rec}


@app.post("/api/change-queue/recipe")
async def change_queue_file_recipe(req: ChangeRequestRecipe, request: Request):
    """File a fix recipe (check id + recipe + parameters) as a pending change
    request. The planned call is built here (remediation.plan, no tenant
    read); its hash is the request's plan_hash."""
    import change_queue
    import remediation
    creds = _validate_creds(_tenant_creds(req))
    tk, label = _cq_tenant(creds)
    criteria = {str(k)[:64]: v for k, v in (req.criteria or {}).items()}
    _require_recipe_in_scope(req.check_id, criteria, req, what="Requesting approval for a fix")
    plan = remediation.plan(req.check_id, criteria)
    if not plan.get("ok"):
        raise HTTPException(status_code=400, detail="The recipe's parameters are not valid: " + " ".join(plan.get("errors") or []))
    recipe = remediation.get_recipe(req.check_id) or {}
    try:
        rec = change_queue.file_request(
            kind="fix_recipe", tenant=tk, tenant_label=label,
            title=req.title or f"{plan.get('recipe_label')} (check {req.check_id})",
            summary={"api_call": 1, "write": 1 if plan.get("destructive") else 0},
            items=[{"method": plan.get("method"), "endpoint": plan.get("endpoint"), "body": plan.get("body"), "status": "send",
                    "kind": "call", "name": plan.get("recipe_label"), **({"note": plan["note"]} if plan.get("note") else {})}],
            plan_hash=change_queue.recipe_plan_hash(req.check_id, plan), requested_by=_cq_by(request), note=req.note,
            payload={"check_id": req.check_id, "recipe": recipe.get("check_id"), "criteria": criteria})
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)
    return {"request": rec}


@app.get("/api/change-queue")
async def change_queue_list(request: Request, tenant: str = "", status: str = ""):
    """The queue (newest first), with who is looking and what they may do:
    the four-eyes setting, whether SSO is on, whether the viewer is a writer
    and whether write mode is on."""
    import change_queue
    statuses = [s for s in (status or "").split(",") if s in change_queue.STATUSES] or None
    items = change_queue.list_requests(tenant, statuses)
    return {"items": items, "counts": change_queue.counts(tenant), "settings": change_queue.settings(),
            "viewer": {"actor": _cq_by(request), "may_write": _security.may_write(), "sso": _sso.sso_enabled()},
            "writes_enabled": writes_enabled(), "statuses": list(change_queue.STATUSES)}


@app.get("/api/change-queue/export")
async def change_queue_export(tenant: str = "", format: str = "markdown"):
    """Download the queue as JSON, Markdown or Excel (format=xlsx: requests,
    items, approvals, comments, history; change_queue.rows is the shared row
    shape). `tenant` narrows every format to that tenant's requests."""
    import change_queue
    items = change_queue.list_requests(tenant)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if format == "xlsx":
        import report_exports
        data = await asyncio.to_thread(change_queue.to_xlsx, items, tenant=tenant)
        return _attachment(data, report_exports.XLSX, f"change_queue_{stamp}.xlsx")
    if format == "json":
        return JSONResponse({"exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tenant": tenant or None,
                             "items": items, "rows": change_queue.rows(items)},
                            headers={"Content-Disposition": f'attachment; filename="change_queue_{stamp}.json"'})
    return PlainTextResponse(change_queue.to_markdown(items), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="change_queue_{stamp}.md"'})


@app.get("/api/change-queue/{rid}")
async def change_queue_get(rid: str):
    import change_queue
    rec = change_queue.get(rid)
    if not rec:
        raise HTTPException(status_code=404, detail="Change request not found.")
    return {"request": rec}


@app.post("/api/change-queue/{rid}/approve")
async def change_queue_approve(rid: str, req: ChangeRequestDecision, request: Request):
    """Approve a pending request: writers only, and (four-eyes) not the requester."""
    _security.require_writer()
    import change_queue
    try:
        return {"request": change_queue.decide(rid, "approve", by=_cq_by(request), comment=req.comment)}
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)


@app.post("/api/change-queue/{rid}/reject")
async def change_queue_reject(rid: str, req: ChangeRequestDecision, request: Request):
    """Reject a pending request with a comment: writers only."""
    _security.require_writer()
    import change_queue
    try:
        return {"request": change_queue.decide(rid, "reject", by=_cq_by(request), comment=req.comment)}
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)


@app.post("/api/change-queue/{rid}/withdraw")
async def change_queue_withdraw(rid: str, req: ChangeRequestDecision, request: Request):
    """The requester withdraws a pending or approved request."""
    import change_queue
    try:
        return {"request": change_queue.withdraw(rid, by=_cq_by(request), comment=req.comment)}
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)


@app.post("/api/change-queue/{rid}/comment")
async def change_queue_comment(rid: str, req: ChangeRequestDecision, request: Request):
    """Add a comment to a request (anyone who can open the queue)."""
    import change_queue
    try:
        return {"request": change_queue.comment(rid, by=_cq_by(request), text=req.comment)}
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)


def _cq_outcome(kind: str, result: Dict[str, Any]) -> Tuple[str, str]:
    """(queue status, note) for what the apply path returned."""
    import change_queue
    st = str(result.get("status") or "")
    if st in ("plan_changed", "stale"):
        return "stale", change_queue.STALE_MESSAGE
    ok = {"pack_deploy": ("applied",), "pack_removal": ("removed", "nothing"), "fix_recipe": ("completed",)}.get(kind, ())
    if st in ok:
        return "applied", ""
    why = result.get("message") or result.get("error") or result.get("reason") or "; ".join(result.get("blockers") or []) or st
    return "failed", str(why)[:300]


def _cq_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """What the request keeps of an apply's result: the outcome and its counts, no logs or tenant objects."""
    keep = ("status", "summary", "message", "deployment_id", "http_status", "error", "reason", "blockers", "expected_hash", "current_hash",
            "activation_required", "complete")
    return {k: result[k] for k in keep if k in result and result[k] not in (None, "", [], {})}


def _cq_recipe_run(client, rec: Dict[str, Any], log) -> Dict[str, Any]:
    """A fix recipe through remediation.execute, after re-planning it: a
    different plan (the recipe changed since it was requested) is stale."""
    import change_queue
    import remediation
    p = rec.get("payload") or {}
    log("Re-planning the recipe and checking it against the approved plan…")
    plan = remediation.plan(p.get("check_id"), p.get("criteria") or {})
    if not plan.get("ok") or change_queue.recipe_plan_hash(p.get("check_id"), plan) != rec.get("plan_hash"):
        log("The planned call differs from the approved one: nothing was sent.")
        return {"status": "stale", "message": change_queue.STALE_MESSAGE}
    log(f"Sending {plan.get('method')} {plan.get('endpoint')}…")
    out = remediation.execute(client, p.get("check_id"), p.get("criteria") or {}, dry_run=False)
    log(f"Result: {out.get('status')}" + (f" (HTTP {out.get('http_status')})" if out.get("http_status") else ""))
    return out


@app.post("/api/change-queue/{rid}/apply")
async def change_queue_apply(rid: str, req: ChangeRequestApply, request: Request):
    """Apply an approved request through the existing apply path, as a job
    (poll GET /api/dlp-packs/jobs/{job_id}). Writers only, write mode on,
    the typed confirmation phrase, and the credentials of the tenant the
    request was filed for. The apply re-runs the preflight first and stops,
    marking the request stale, when its plan_hash no longer matches."""
    _security.require_writer()
    import change_queue
    import pack_jobs
    rec = change_queue.get(rid)
    if not rec:
        raise HTTPException(status_code=404, detail="Change request not found.")
    if rec.get("status") != "approved":
        raise HTTPException(status_code=409, detail=f"Only an approved request can be applied; this one is {rec.get('status')}.")
    if not _security.typed_phrase_matches(req.confirm, change_queue.CONFIRM_PHRASE):
        raise HTTPException(status_code=400, detail=f'Type "{change_queue.CONFIRM_PHRASE}" to confirm the apply.')
    if rec.get("kind") == "pack_deploy":
        _require_assessor(req)
    else:
        _require_write_assessor(req)
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    if rec.get("kind") == "fix_recipe":   # the recipe's rule policy must still be in scope (user rule 1), before sign-in
        _p = rec.get("payload") or {}
        _require_recipe_in_scope(_p.get("check_id"), _p.get("criteria") or {}, req, what="Applying this fix")
    creds = _tenant_creds(req)
    tk, label = _cq_tenant(creds)
    if tk != rec.get("tenant"):
        raise HTTPException(status_code=409, detail=f"This request was filed for {rec.get('tenant_label') or rec.get('tenant')}, but the credentials are for {label}. Switch tenant first.")
    by = _cq_by(request)
    kind = rec.get("kind")
    p = rec.get("payload") or {}
    if kind == "pack_deploy":
        _require_assessor(req)
        dreq = DLPPackDeployRequest(**{k: getattr(req, k) for k in TenantCredsRequest.model_fields},
                                    pack_ids=list(p.get("pack_ids") or []), use_rank_0=bool(p.get("use_rank_0")),
                                    apply_tweaks=bool(p.get("apply_tweaks", True)), restore_drift=bool(p.get("restore_drift")),
                                    verify=bool(p.get("verify", True)), channel_targets=p.get("channel_targets") or {},
                                    plan_hash=rec["plan_hash"], confirm=True)
        packs = _resolve_pack_ids(dreq.pack_ids)
        client = await asyncio.to_thread(_build_sdk_client, creds)
        job_kind, run = "deploy", (lambda log, cancel: _keyed(client, _run_apply, client, creds, dreq, packs, log, cancel))
    elif kind == "pack_removal":
        rreq = PackRemovalRequest(**{k: getattr(req, k) for k in TenantCredsRequest.model_fields},
                                  rules=list(p.get("rules") or []), plan_hash=rec["plan_hash"], confirm=True)
        client = await asyncio.to_thread(_build_sdk_client, creds)
        job_kind, run = "removal", (lambda log, cancel: _keyed(client, _run_removal, client, rreq, None, [], log, cancel))
    elif kind == "fix_recipe":
        client = await asyncio.to_thread(_build_client, req)
        job_kind, run = "remediation", (lambda log, cancel: _cq_recipe_run(client, rec, log))
    else:
        raise HTTPException(status_code=400, detail=f"Unknown change request kind: {kind}")

    def _job_running(jid: str) -> bool:
        j = pack_jobs.get(jid)
        return j is not None and j.status == "running"

    try:
        change_queue.begin_apply(rid, by=by, job_running=_job_running)
    except Exception as e:  # noqa: BLE001
        _cq_fail(e)

    def fn(log, cancel):
        log(f"Change request {rid}: {rec.get('title')} (requested by {rec.get('requested_by')}, approved by {rec.get('decided_by')}).")
        try:
            result = run(log, cancel)
        except Exception as e:  # noqa: BLE001 — recorded, then reported by the job
            change_queue.finish_apply(rid, by=by, status="failed", result={"status": "error", "error": f"{type(e).__name__}: {str(e)[:200]}"})
            raise
        if result.get("busy"):   # another run held the tenant: nothing was read or written, the request stays approved
            log(str(result.get("message") or "Another run holds the tenant; nothing was written."))
            result["change_request"] = change_queue.release(rid, by=by, reason=str(result.get("message") or "busy"))
            return result
        status, note = _cq_outcome(kind, result)
        if status == "stale":
            log(change_queue.STALE_MESSAGE)
        result["change_request"] = change_queue.finish_apply(rid, by=by, status=status, result=_cq_result(result), note=note)
        return result

    try:
        job = pack_jobs.start(job_kind, fn, label=f"change request {rid}", actor=by, start_token=_start_token(request))
    except Exception as e:  # noqa: BLE001
        change_queue.release(rid, by=by, reason=str(e))
        raise
    change_queue.set_job(rid, job.id)
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "request_id": rid}


@app.get("/report/queue")
async def report_queue_page():
    """Standalone tab for the change queue (static/report_queue.html)."""
    page = os.path.join(STATIC_DIR, "report_queue.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


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


def _proposal_client(req: ProposalApplyRequest, tenant: str):
    """The SDK client for previewing, applying or rolling back a proposal
    queued under `tenant`, or an error before anything is read: 400 without
    complete credentials (OneAPI or the classic API), 409 when the signed-in
    tenant is not the one the proposal was raised for (its proposal key)."""
    import proposals
    import tenant_fingerprint
    creds = _tenant_creds(req)
    if not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail="Tenant credentials are needed to touch the tenant: open FP/TP Detection Ratio from the assessment page (its sign-in is used, OneAPI or classic API), or select a tenant profile that remembers its secret.")
    mine = proposals.tenant_key(tenant_fingerprint.proposal_key(creds, getattr(req, "profile_id", "") or ""))
    if proposals.tenant_key(tenant) != mine:
        raise HTTPException(status_code=409, detail=f"This proposal was raised for another tenant, but the current credentials are for {tenant_auth.record_label(creds)}. Switch tenant first.")
    return _build_sdk_client(creds)


@app.post("/api/proposals/{tenant}/{pid}/preview")
async def proposals_preview(tenant: str, pid: str, req: ProposalApplyRequest, direction: str = "apply"):
    """Re-read the rules an approved proposal touches and show exactly what
    would change (or what a rollback would restore). Read-only."""
    import proposal_apply
    client = await asyncio.to_thread(_proposal_client, req, tenant)
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
    _require_tenant_write(req, confirmed=req.confirm, what="Applying")
    client = await asyncio.to_thread(_proposal_client, req, tenant)
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
    _require_tenant_write(req, confirmed=req.confirm, what="Rolling back")
    client = await asyncio.to_thread(_proposal_client, req, tenant)
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
    notifications = continuous_eval.notification_settings()
    if _DH_REFRESH_STATE.get("interval_hours") is not None:   # what the timer started with, decided (and logged) once at startup
        notifications["interval_hours"] = _DH_REFRESH_STATE["interval_hours"]
    return {"digests": continuous_eval.list_digests(), "schedule": dict(_DH_REFRESH_STATE), "notifications": notifications,
            "sources": {"watched": sum(1 for h in health if h["watched"]), "stale": [h for h in health if h["stale"]]},
            "checks_config": guidance.config_summary(), "guidance_queue": __import__("proposals").summary(guidance.APP_TENANT)}


@app.post("/api/digests/run")
async def digests_run(req: DigestRunRequest):
    """Run the loop now (the same run the schedule makes). One run at a
    time: a second click, another tab or the timer firing meanwhile gets
    409, so the tenants are not read twice against the API rate limit."""
    try:
        d = await asyncio.to_thread(_continuous_eval_once, req.notify)
    except LoopRunInProgress as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:  # noqa: BLE001
        _DH_REFRESH_STATE["last_status"] = "error"
        _DH_REFRESH_STATE["last_error"] = str(e)[:200]
        _DH_REFRESH_STATE["last_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        raise HTTPException(status_code=500, detail=f"the evaluation failed: {type(e).__name__}: {str(e)[:200]}")
    # The same bookkeeping the scheduled run does (_continuous_eval_once), so
    # the Digest tab's "Last run" and its status are right after a manual run too.
    return {"ok": True, "digest": d, "status": _DH_REFRESH_STATE.get("last_status"), "errors": __import__("continuous_eval").run_errors(d)}


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


# ── ZPA analysis and ZPA diagnostics (read-only) ─────────────────────
# zpa_reader reads the ZPA configuration once (paced, Stop-able); the
# templates and the diagnostics in zpa_analysis are pure functions over
# that read, kept as a "zpa-" report so a second diagnosis needs no read.
ZPA_NEEDS_ONEAPI = ("ZPA analysis needs a ZIdentity (OneAPI) API client: the classic ZIA API reaches ZIA only. "
                    "Sign in with an API client that has a ZPA role, then run it again. Nothing was read.")
ZPA_NEEDS_CUSTOMER_ID = ("ZPA analysis needs the ZPA customer ID (Connect to the tenant → Customer ID, or the saved profile): "
                         "every ZPA API path carries it. Nothing was read.")


class ZpaAnalysisRequest(MigrateRequest):
    """Body of the ZPA analysis: tenant credentials (with the ZPA customer
    id) and the Scope page selection; refused (400) before sign-in unless
    ZPA is ticked (user rule 1)."""


class ZpaDiagnoseRequest(MigrateRequest):
    """Body of a ZPA diagnosis: the user context (any field left out means
    "any"), the destination and port, and the id of the read to reuse
    (`report_id`, from the analysis). Without a usable report id the
    tenant is read first, as a job."""
    report_id: str = ""
    destination: str = ""
    port: str = ""
    protocol: str = "tcp"
    user: Dict[str, Any] = {}


@app.get("/report/zpa")
async def report_zpa_page():
    """ZPA analysis (static/report_zpa.html): the templates' findings and the diagnostics."""
    page = os.path.join(STATIC_DIR, "report_zpa.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


def _zpa_scope(req: Any, what: str) -> Dict[str, Any]:
    """ZPA ticked on the Scope page, else 400 before anything is signed in to or read."""
    return _require_in_scope(req, "zpa", what)


async def _zpa_client(req: Any):
    """(client, tenant label) for a ZPA read: OneAPI with a customer id,
    both refused (400) before sign-in."""
    creds = _tenant_creds(req)
    if creds.get("auth_method") == tenant_auth.LEGACY:
        raise HTTPException(status_code=400, detail=ZPA_NEEDS_ONEAPI)
    if not validate_customer_id(creds.get("customer_id") or ""):
        raise HTTPException(status_code=400, detail=ZPA_NEEDS_CUSTOMER_ID)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    return client, tenant_auth.record_label(creds), creds


def _zpa_report(rid: str) -> Optional[Dict[str, Any]]:
    rep = _REPORTS.get(rid or "")
    return rep if rep and str(rid).startswith("zpa-") else None


def _zpa_public(rep: Dict[str, Any]) -> Dict[str, Any]:
    """A stored ZPA report as the page gets it: everything but the raw read."""
    return {k: v for k, v in rep.items() if k != "snapshot"}


def _run_zpa_read(client, label: str, creds: Dict[str, Any], log, cancel, scope: Dict[str, Any]) -> Dict[str, Any]:
    """Read ZPA once and run every template. Stop ends the run as stopped:
    nothing more is read, nothing is kept and no partial result is returned."""
    import zpa_analysis
    import zpa_overview
    import zpa_reader
    logs: list = []

    def _log(line: str) -> None:
        line = tenant_auth.mask_secrets(str(line), creds)
        logs.append(line)
        if log:
            log(line)

    if scope.get("source"):
        _log(f"In scope, from {scope['source']}: ZPA.")
    try:
        snap = zpa_reader.read(client, log=_log, cancel=cancel)
    except zpa_reader.Stopped as e:
        return {"stopped": str(e), "status": "stopped", "tenant_label": label, "logs": logs}
    except zpa_reader.ReadError as e:
        raise RuntimeError(tenant_auth.mask_secrets(str(e), creds))
    if cancel is not None and cancel.is_set():
        _log("STOPPED — you clicked Stop; the ZPA read was abandoned and is not kept.")
        return {"stopped": zpa_reader.STOPPED_REASON, "status": "stopped", "tenant_label": label, "logs": logs}
    for v in (snap.get("collections") or {}).values():
        if v.get("error"):
            v["error"] = tenant_auth.mask_secrets(v["error"], creds)
    analysis = zpa_analysis.analyze(snap)
    readable = zpa_reader.readable(snap)
    report = {"kind": "zpa", "snapshot": snap, "summary": zpa_reader.summary(snap), "collections": snap.get("collections") or {},
              "readable": readable, "choices": zpa_analysis.choices(snap), "read_at": snap.get("read_at"),
              "overview": zpa_overview.overview(snap, analysis),
              "findings": analysis["findings"], "catalog": analysis["catalog"], "counts": analysis["counts"],
              "not_assessed": analysis["not_assessed"], "assumptions": zpa_analysis.ASSUMPTIONS}
    rid = _remember_report("zpa", report, label)
    _log(f"Analysis done: {analysis['counts']['total']} finding(s) from {analysis['counts']['assessed']} of "
         f"{analysis['counts']['templates']} templates.")
    out = _zpa_public(_REPORTS[rid])
    out["logs"] = logs
    return out


@app.post("/api/zpa/analysis/start")
async def zpa_analysis_start(req: ZpaAnalysisRequest, request: Request):
    """Read the ZPA configuration (only when ZPA is ticked on the Scope page)
    and run every ZPA template, as a job the page follows: findings,
    catalog and counts, kept as report `zpa-…` for diagnoses and exports.
    Read-only. Poll GET /api/dlp-packs/jobs/{job_id}; Stop ends it with
    nothing more read."""
    import pack_jobs
    scope = _zpa_scope(req, "ZPA analysis")          # before signing in (user rule 1)
    client, label, creds = await _zpa_client(req)
    job = pack_jobs.start("zpa", lambda log, cancel: _run_zpa_read(client, label, creds, log, cancel, scope), label="ZPA analysis",
                          actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


def _zpa_diagnosis(rep: Dict[str, Any], req: ZpaDiagnoseRequest) -> Dict[str, Any]:
    import zpa_analysis
    try:
        out = zpa_analysis.diagnose(rep["snapshot"], req.user or {}, req.destination, req.port, req.protocol)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    out["report_id"] = rep.get("report_id")
    out["tenant_label"] = rep.get("tenant_label")
    out["read_at"] = rep.get("read_at")
    return out


@app.post("/api/zpa/diagnose")
async def zpa_diagnose(req: ZpaDiagnoseRequest, request: Request):
    """Which app segment, server and connector groups and access rule decide
    for one user context and destination. With the `report_id` of an
    earlier ZPA read the answer comes at once ({status: done, result}), no
    tenant call; otherwise ZPA is read first as a job ({job_id}) whose
    result carries the analysis and the diagnosis. ZPA must be ticked on
    the Scope page either way (400 otherwise)."""
    import pack_jobs
    import zpa_analysis
    scope = _zpa_scope(req, "ZPA diagnostics")
    try:
        zpa_analysis.parse_destination(req.destination, req.port, req.protocol)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    rep = _zpa_report(req.report_id)
    if rep is not None:
        return {"status": "done", "result": await asyncio.to_thread(_zpa_diagnosis, rep, req)}
    client, label, creds = await _zpa_client(req)

    def run(log, cancel):
        out = _run_zpa_read(client, label, creds, log, cancel, scope)
        if out.get("stopped"):
            return out
        stored = _zpa_report(out.get("report_id"))
        if stored is None:
            return out
        try:
            out["diagnosis"] = _zpa_diagnosis(stored, req)
        except HTTPException as e:
            out["diagnosis_error"] = str(e.detail)
        return out
    job = pack_jobs.start("zpa", run, label=f"ZPA diagnosis {req.destination[:60]}", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/zpa/report/{report_id}")
async def zpa_report_get(report_id: str):
    rep = _zpa_report(report_id)
    if rep is None:
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs). Run the ZPA analysis again.")
    return _zpa_public(rep)


@app.get("/api/zpa/report/{report_id}/export")
async def zpa_report_export(report_id: str, format: str = "csv", severity: str = ""):
    """The findings as CSV (every cell through csv_safe), the findings,
    catalog and counts as JSON, or the whole overview as Excel (format=xlsx:
    KPIs, every inventory table, findings, map connections, what was not
    read; no cell is a formula); `severity` (comma-separated) filters the
    findings."""
    import io
    import csv_safe
    rep = _zpa_report(report_id)
    if rep is None:
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    sev = {s.strip().lower() for s in (severity or "").split(",") if s.strip()}
    findings = [f for f in rep.get("findings") or [] if not sev or f.get("severity") in sev]
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    fmt = (format or "csv").lower()
    if fmt == "json":
        body = {"tenant_label": rep.get("tenant_label"), "generated_at": rep.get("generated_at"), "counts": rep.get("counts"),
                "severity_filter": sorted(sev), "findings": findings, "catalog": rep.get("catalog"), "assumptions": rep.get("assumptions")}
        return Response(content=json.dumps(body, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=zpa_analysis_{ts}.json"})
    if fmt == "xlsx":
        import report_exports
        import zpa_overview
        data = await asyncio.to_thread(zpa_overview.workbook, rep["snapshot"], {"findings": rep.get("findings"), "catalog": rep.get("catalog")},
                                       tenant_label=rep.get("tenant_label") or "", read_at=rep.get("read_at"), findings=findings)
        return _attachment(data, report_exports.XLSX, f"zpa_overview_{report_exports.safe_filename_part(rep.get('tenant_label') or 'tenant')}_{ts}.xlsx")
    if fmt != "csv":
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt[:20]}")
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(["severity", "template", "title", "object_type", "object", "reason", "fix"])
    for f in findings:
        w.writerow([f.get("severity"), f.get("template"), f.get("title"), f.get("object_type"), f.get("object"), f.get("reason"), f.get("fix")])
    return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=zpa_analysis_{ts}.csv"})


# ── Browser security (read-only): Zero Trust Browser isolation, ZPA browser
# side and ZIA Browser Control (browser_security). ZIA is read when ZIA
# platform is ticked, ZPA when ZPA is; kept as report "browser-…" for the
# Excel and JSON exports. Never holds the raw read or any secret.
class BrowserSecurityRequest(MigrateRequest):
    """Body of the browser security read: tenant credentials (with the ZPA
    customer id when ZPA is ticked) and the Scope page selection; refused
    (400) before sign-in unless ZIA platform or ZPA is ticked."""


@app.get("/report/browser")
async def report_browser_page():
    """Browser security (static/report_browser.html)."""
    page = os.path.join(STATIC_DIR, "report_browser.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


def _browser_inputs(req: BrowserSecurityRequest) -> Tuple[Dict[str, Any], Dict[str, str], str]:
    """(scope, creds, why ZPA is skipped) for a browser security read; 400
    before anything is signed in to or read when nothing it reads is in
    scope, or when only ZPA is and it cannot be read (user rule 1)."""
    import browser_security as bs
    sc, ch, source = _scope_selection(req)
    scope = bs.scope_for(sc, ch)
    if not scope["read"]:
        raise HTTPException(status_code=400, detail=bs.NOTHING_IN_SCOPE)
    scope["source"] = source
    creds = _tenant_creds(req)
    zpa_blocked = ""
    if scope["zpa"]:
        if creds.get("auth_method") == tenant_auth.LEGACY:
            zpa_blocked = bs.ZPA_NEEDS_ONEAPI
        elif not validate_customer_id(creds.get("customer_id") or ""):
            zpa_blocked = bs.ZPA_NEEDS_CUSTOMER_ID
        if zpa_blocked and not scope["zia"]:
            raise HTTPException(status_code=400, detail=f"{zpa_blocked} Nothing was read.")
    return scope, creds, zpa_blocked


def _run_browser_security(client, label: str, creds: Dict[str, Any], scope: Dict[str, Any], zpa_blocked: str, log, cancel) -> Dict[str, Any]:
    """Read only what `scope` puts in scope and analyse it. Stop ends the run
    as stopped: nothing more is read and no partial result is kept."""
    import browser_security as bs
    logs: List[str] = []

    def _log(line: str) -> None:
        line = tenant_auth.mask_secrets(str(line), creds)
        logs.append(line)
        if log:
            log(line)

    _log(f"Reading {label}. Nothing is written to the tenant. " + (f"In scope, from {scope['source']}: " if scope.get("source") else "") + scope["summary"])
    if zpa_blocked:
        _log(f"ZPA is not read: {zpa_blocked}")
    try:
        out = bs.run(client, scope, log=_log, cancel=cancel, zpa_blocked=zpa_blocked)
    except bs.Stopped:
        _log("STOPPED — you clicked Stop; nothing more was read and no partial result is kept.")
        return {"stopped": bs.STOPPED_REASON, "status": "stopped", "tenant_label": label, "logs": logs}
    if cancel is not None and cancel.is_set():
        return {"stopped": bs.STOPPED_REASON, "status": "stopped", "tenant_label": label, "logs": logs}
    for sec in (out.get("sections") or {}).values():
        if sec.get("error"):
            sec["error"] = tenant_auth.mask_secrets(str(sec["error"]), creds)
    rid = _remember_report("browser", dict(out, kind="browser"), label)
    _log(f"Done: {out['counts']['total']} finding(s).")
    return dict(_REPORTS[rid], status="done", logs=logs)


@app.post("/api/browser-security/start")
async def browser_security_start(req: BrowserSecurityRequest, request: Request):
    """Read the browser security configuration in scope (ZIA isolation
    profiles, Browser Control and the rules that isolate; ZPA isolation
    controls, Browser Access, managed browsers, PRA and user portals) as a
    job the page follows, and analyse it. Read-only. Poll GET
    /api/dlp-packs/jobs/{job_id}; Stop ends it with nothing more read."""
    import pack_jobs
    scope, creds, zpa_blocked = _browser_inputs(req)   # before signing in (user rule 1)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("browser", lambda log, cancel: _run_browser_security(client, label, creds, scope, zpa_blocked, log, cancel),
                          label=f"Browser security {label}"[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


def _browser_report(rid: str) -> Dict[str, Any]:
    rep = _REPORTS.get(rid or "")
    if not rep or not str(rid).startswith("browser-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs). Read it again.")
    return rep


@app.get("/api/browser-security/report/{report_id}")
async def browser_security_report(report_id: str):
    return _browser_report(report_id)


@app.get("/api/browser-security/report/{report_id}/export")
async def browser_security_export(report_id: str, format: str = "xlsx"):
    """The browser security report as Excel (xlsx_writer) or JSON."""
    import browser_security as bs
    import xlsx_writer
    rep = _browser_report(report_id)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    fmt = (format or "xlsx").lower()
    if fmt == "json":
        return Response(content=json.dumps(bs.scrub(rep), indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=browser_security_{ts}.json"})
    if fmt != "xlsx":
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt[:20]}")
    data = await asyncio.to_thread(bs.workbook, rep)
    return Response(content=data, media_type=xlsx_writer.MEDIA_TYPE,
                    headers={"Content-Disposition": f"attachment; filename=browser_security_{ts}.xlsx"})


# ── Device posture (read-only) ───────────────────────────────────────
# device_posture reads ZPA through zpa_reader (plus the Client Connector
# trusted networks when Client Connector is in scope too), classifies the
# posture profiles, links them to the access rules and says each rule's
# conditions in plain words. Kept as a "posture-" report for the exports.
@app.get("/report/device-posture")
async def report_device_posture_page():
    """Device posture (static/report_device_posture.html)."""
    page = os.path.join(STATIC_DIR, "report_device_posture.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


def _posture_report(rid: str) -> Optional[Dict[str, Any]]:
    rep = _REPORTS.get(rid or "")
    return rep if rep and str(rid).startswith("posture-") else None


def _run_device_posture(client, label: str, creds: Dict[str, Any], log, cancel, scope: Dict[str, Any], zcc: bool) -> Dict[str, Any]:
    """Read ZPA once (and the Client Connector trusted networks with `zcc`),
    then build the device posture report. Stop ends it as stopped with
    nothing more read and nothing kept."""
    import device_posture
    import zpa_reader
    logs: list = []

    def _log(line: str) -> None:
        line = tenant_auth.mask_secrets(str(line), creds)
        logs.append(line)
        if log:
            log(line)

    if scope.get("source"):
        _log(f"In scope, from {scope['source']}: ZPA{' and Client Connector' if zcc else ''}.")
    try:
        snap, raw, zout = device_posture.read(client, log=_log, cancel=cancel, zcc=zcc)
    except zpa_reader.Stopped as e:
        return {"stopped": str(e), "status": "stopped", "tenant_label": label, "logs": logs}
    except zpa_reader.ReadError as e:
        raise RuntimeError(tenant_auth.mask_secrets(str(e), creds))
    if cancel is not None and cancel.is_set():
        _log("STOPPED — you clicked Stop; the ZPA read was abandoned and is not kept.")
        return {"stopped": zpa_reader.STOPPED_REASON, "status": "stopped", "tenant_label": label, "logs": logs}
    cols = snap.get("collections") or {}
    for v in cols.values():
        if v.get("error"):
            v["error"] = tenant_auth.mask_secrets(v["error"], creds)
    zout["reason"] = tenant_auth.mask_secrets(zout.get("reason") or "", creds)
    rep = device_posture.analyze(snap, raw.get("posture_profiles"), raw.get("trusted_networks"), zout)
    report = dict(rep, kind="posture", read_at=snap.get("read_at"), collections=cols, readable=zpa_reader.readable(snap))
    rid = _remember_report("posture", report, label)
    _log(f"Done: {rep['counts']['profiles']} posture profile(s), {rep['counts']['access_rules']} access rule(s), "
         f"{rep['counts']['findings']} finding(s).")
    out = dict(_REPORTS[rid])
    out["logs"] = logs
    return out


@app.post("/api/device-posture/start")
async def device_posture_start(req: ZpaAnalysisRequest, request: Request):
    """Read the ZPA posture profiles, trusted networks and access rules
    (only when ZPA is ticked on the Scope page; the Client Connector
    trusted networks too when Client Connector is ticked) as a job the page
    follows. Read-only. Poll GET /api/dlp-packs/jobs/{job_id}."""
    import pack_jobs
    scope = _zpa_scope(req, "Device posture")          # before signing in (user rule 1)
    zcc = "zcc" in (scope.get("scopes") or [])
    client, label, creds = await _zpa_client(req)
    job = pack_jobs.start("posture", lambda log, cancel: _run_device_posture(client, label, creds, log, cancel, scope, zcc),
                          label="Device posture", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/device-posture/report/{report_id}")
async def device_posture_report(report_id: str):
    rep = _posture_report(report_id)
    if rep is None:
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs). Read device posture again.")
    return rep


@app.get("/api/device-posture/report/{report_id}/export")
async def device_posture_export(report_id: str, format: str = "xlsx"):
    """The report as an Excel workbook (profiles, families, usage, findings,
    access rules with readable conditions) or as JSON."""
    import device_posture
    import xlsx_writer
    rep = _posture_report(report_id)
    if rep is None:
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    fmt = (format or "xlsx").lower()
    if fmt == "json":
        body = {k: v for k, v in rep.items() if k != "collections"}
        return Response(content=json.dumps(body, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=device_posture_{ts}.json"})
    if fmt != "xlsx":
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt[:20]}")
    data = await asyncio.to_thread(device_posture.workbook, rep)
    return Response(content=data, media_type=xlsx_writer.MEDIA_TYPE,
                    headers={"Content-Disposition": f"attachment; filename=device_posture_{ts}.xlsx"})


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
    """State of the opt-in FP/TP Detection Ratio refresh (the continuous
    evaluation timer, DLP_CHECK_CONTINUOUS_EVAL_HOURS; off by default)."""
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


# Off unless the operator opts in: every tenant read counts against the
# ZIA API rate limit, and nothing reads a tenant until the operator runs it.
# With DLP_CHECK_CONTINUOUS_EVAL_HOURS > 0 (unset or 0: off), every N hours
# while this server process runs, continuous_eval.run_once reads, for each
# tenant profile that remembers its secret and only what that profile's
# Scope page puts in scope, FP/TP Detection Ratio, the SaaS tenants and the
# ticked packs' drift (never the assessment checks or the score) and writes
# a digest. Run the loop now (POST /api/digests/run) and
# continuous_eval.py --once are the explicit runs. Nothing is written to any
# tenant. The loop dies with the process: a schedule that must survive it
# is Task Scheduler / cron running continuous_eval.py --once.
_DH_REFRESH_STATE: Dict[str, Any] = {"enabled": False, "interval_seconds": None, "interval_hours": None, "last_run_at": None,
                                     "next_run_at": None, "last_status": None, "profiles": {},
                                     "runs_while": "this server process is running",
                                     "setting": "DLP_CHECK_CONTINUOUS_EVAL_HOURS (unset or 0: off; runs only when you click Run the loop now)"}


def _continuous_eval_hours() -> float:
    """DLP_CHECK_CONTINUOUS_EVAL_HOURS as hours; 0 (the default) is off."""
    import continuous_eval
    return continuous_eval.interval_hours()


# A run of the loop is already reading the tenants. continuous_eval.run_once
# also takes a cross-process file lock (digests/.loop.lock), so a run here
# and RUN_Continuous_Evaluation.bat / continuous_eval.py --once in another
# process never overlap either: whichever starts second gets this.
from continuous_eval import LoopRunInProgress  # noqa: E402

_LOOP_RUN_LOCK = threading.Lock()


def _continuous_eval_once(notify: bool = True) -> Dict[str, Any]:
    """One run of the continuous evaluation (guidance, FP/TP Detection Ratio,
    SaaS tenants, drift, digest, notifications). Keeps the per-profile
    state the FP/TP Detection Ratio tab shows, and the run's status: "ok"
    only when nothing failed, "partial" when a section or a tenant read did
    (a 429, say). Only one run at a time: every tenant read counts against
    the ZIA API rate limit, so an overlapping run raises LoopRunInProgress."""
    if not _LOOP_RUN_LOCK.acquire(blocking=False):
        raise LoopRunInProgress("a run of the loop is already in progress; wait for it to finish")
    try:
        return _continuous_eval_locked(notify)
    finally:
        _LOOP_RUN_LOCK.release()


def _continuous_eval_locked(notify: bool) -> Dict[str, Any]:
    import continuous_eval
    d = continuous_eval.run_once(build_client=_build_sdk_client, notify=notify)
    for t in d.get("tenants") or []:
        dh = t.get("detection_health") or {}
        _DH_REFRESH_STATE["profiles"][t["profile_id"]] = {"at": d.get("at"), "status": "error" if t.get("errors") else ("not in scope" if t.get("note") else "ok"),
                                                          "incidents": dh.get("incidents"), "errors": len(t.get("errors") or []),
                                                          "error": "; ".join(t.get("errors") or [])[:200] or None}
    _DH_REFRESH_STATE["last_digest"] = d.get("id")
    _DH_REFRESH_STATE["last_noteworthy"] = d.get("noteworthy")
    errors = continuous_eval.run_errors(d)
    _DH_REFRESH_STATE["last_status"] = "partial" if errors else "ok"
    _DH_REFRESH_STATE["last_error"] = (f"{errors} error(s) in the run; see the digest" if errors else None)
    _DH_REFRESH_STATE["last_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return d


async def _dh_auto_refresh_loop() -> None:
    interval = _DH_REFRESH_STATE["interval_seconds"]
    _DH_REFRESH_STATE["next_run_at"] = time.time() + 30
    try:
        await asyncio.sleep(30)
    except asyncio.CancelledError:
        return
    while _DH_REFRESH_STATE.get("enabled"):
        try:
            await asyncio.to_thread(_continuous_eval_once)   # sets last_status / last_run_at
        except LoopRunInProgress:
            pass   # a manual run is reading the tenants right now: this pass is skipped
        except Exception as e:  # noqa: BLE001
            _DH_REFRESH_STATE["last_status"] = "error"
            _DH_REFRESH_STATE["last_error"] = str(e)[:200]
            _DH_REFRESH_STATE["last_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _DH_REFRESH_STATE["next_run_at"] = time.time() + interval
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break


@app.on_event("startup")
async def _start_dh_refresh() -> None:
    try:
        hours = _continuous_eval_hours()   # logs a value it cannot use, once
    except Exception:  # noqa: BLE001  # a setting that cannot be read leaves the timer off; it never stops the app
        hours = 0.0
    _DH_REFRESH_STATE["interval_hours"] = hours
    if hours <= 0:
        _DH_REFRESH_STATE.update({"enabled": False, "interval_seconds": None, "next_run_at": None, "last_status": _DH_REFRESH_STATE.get("last_status") or "off"})
        return
    try:
        import detection_health  # noqa: F401
        import tenant_profiles  # noqa: F401
        _DH_REFRESH_STATE.update({"enabled": True, "interval_seconds": hours * 3600})
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
    _require_same_tenant(rec, creds)
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
    Zscaler Made Easy provenance tag and by the names it defines — and preview a
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
        _cq_remember("pack_removal", out, req, creds)   # lets "Request approval" file exactly this plan
    else:
        out = await asyncio.to_thread(lambda: pack_removal.plan_removal(client, packs, everything=bool(req.all)))
    out["writes_enabled"] = writes_enabled()
    out["tenant_label"] = tenant_auth.record_label(creds)
    return out


class ScopedTenantCredsRequest(TenantCredsRequest):
    """Tenant credentials plus what is in scope: the Scope page's ticked
    `scopes` and channel declaration (`channels`), else (nothing sent and
    `from_page` false) the chosen profile's saved selection."""
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


@app.post("/api/dlp-packs/removal/inventory")
async def dlp_pack_removal_inventory(req: ScopedTenantCredsRequest):
    """Every DLP rule the tenant has on the DLP channels in scope (DLP
    ticked and the channel marked Zscaler on the Scope page: web,
    endpoint, SaaS, email) with its state, engines and provenance, so the
    operator can pick the leftovers to remove. Read-only; nothing in scope
    is refused (400) before sign-in (user rule 1)."""
    try:
        import pack_removal
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pack_removal unavailable: {e}")
    channels = _pack_channels_in_scope(req, "The rule picker")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(pack_removal.inventory, client, channels)
    out["channels_in_scope"] = channels
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
    _require_tenant_write(req, confirmed=req.confirm, what="Removal")
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
        if result.get("status") not in ("blocked", "stale", "stopped"):
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
    _require_tenant_write(req, confirmed=req.confirm, what="Removal")
    packs = _resolve_pack_ids(req.pack_ids) if req.pack_ids else []
    creds = _tenant_creds(req)
    rec = _deployment_for_removal(req, creds) if req.deployment_id else None
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = "undo " + rec["id"] if rec else ("everything" if req.all else ", ".join(req.pack_ids) or f"{len(req.rules)} rule(s)")
    job = pack_jobs.start("removal", lambda log, cancel: _keyed(client, _run_removal, client, req, rec, packs, log, cancel), label=label,
                           actor=_actor(request), start_token=_start_token(request))
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


def _start_token(request: Request) -> Optional[str]:
    """The page's name for a job start (X-Start-Token), so a Stop pressed
    before the start answers still reaches the job (pack_jobs.stop_before_start)."""
    import pack_jobs
    return pack_jobs.valid_start_token(request.headers.get("X-Start-Token"))


class StopBeforeStartRequest(BaseModel):
    start_token: str


@app.post("/api/dlp-packs/jobs/stop-before-start")
async def dlp_pack_job_stop_before_start(req: StopBeforeStartRequest, request: Request):
    """Stop pressed while a start request (deploy, removal, export,
    Terraform hand-off, path analysis) is still signing in, so there is no
    job id yet. The job that start creates begins with its cancel set and
    reads or writes nothing; one that already exists is cancelled now.
    As /cancel: only the person who started a job can stop it (403)."""
    import pack_jobs
    try:
        return pack_jobs.stop_before_start(req.start_token, actor=_actor(request))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/dlp-packs/jobs/{job_id}/cancel")
async def dlp_pack_job_cancel(job_id: str, request: Request):
    """Stop a running job after the write in flight. Nothing more is sent
    to the tenant; activation and the read-back still run so what was
    written is live and recorded. The browser extension may stop only the
    read-only export it started itself, never a deploy, removal or any
    other job (security.EXTENSION_POST_PATHS)."""
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job.")
    if _security.from_extension(request) and not (job.kind in _security.EXTENSION_JOB_KINDS and job.started_by == "extension"):
        raise HTTPException(status_code=403, detail="The browser extension may stop only the export it started. Stop this job in Zscaler Made Easy.")
    _require_job_owner(job, request)
    return {"job_id": job.id, "cancelled": pack_jobs.cancel(job_id), "status": job.status}


def _require_job_owner(job: Any, request: Request) -> None:
    """403 when the job was started by someone else (SSO: each person is
    their own actor; without SSO every request is the same local actor, so
    nothing changes). A job whose starter is unknown stays stoppable."""
    owner = getattr(job, "actor", None)
    if owner and _actor(request) != owner:
        raise HTTPException(status_code=403, detail="This job was started by someone else; only the person who started it can stop it.")


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
               "If you are behind a corporate proxy, set HTTPS_PROXY in START_Zscaler_Made_Easy.bat. "
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


def _close_quietly(client: Any) -> None:
    """Close a tenant client (ends a classic ZIA API session); best effort."""
    close = getattr(client, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001
            pass


_UNANSWERED_WORDS = {429: "rate limited (HTTP 429)", 502: "unavailable (HTTP 502)", 503: "unavailable (HTTP 503)",
                     504: "unavailable (HTTP 504)", 0: "no answer (timed out or unreachable)"}


def _unanswered_result(r: Any, label: str, unanswered: List[Tuple[str, int]]) -> Any:
    """A check built on a read the tenant did not answer (rate limited,
    unavailable, timed out) judged nothing: it is "Could not be checked"
    (ERROR, outside the score, the run partial), never "Configured", "Not
    configured" or an empty tenant ("0 devices", "No PAC files")."""
    if not unanswered or str(getattr(r, "status", "")) == str(R.ERROR):
        return r
    codes = sorted({c for _ep, c in unanswered})
    why = ", ".join(_UNANSWERED_WORDS.get(c, f"HTTP {c}") for c in codes)
    eps = ", ".join(sorted({ep.split("?", 1)[0] for ep, _c in unanswered}))[:160]
    return R(R.ERROR, f"{label}: Could not be checked: the tenant did not answer {len(unanswered)} read(s) ({why}; {eps}). "
                      "Run the assessment again later.", getattr(r, "data", None))


def _close_when_done(client: Any):
    """A done-callback for the thread still using `client`: ends its
    session once that thread has stopped (never under a running read)."""
    def _cb(fut):
        if not fut.cancelled():
            fut.exception()   # retrieved, so an error is not logged as unhandled
        threading.Thread(target=_close_quietly, args=(client,), name="journey-close", daemon=True).start()
    return _cb


def _stop_reads(client: Any) -> None:
    """Tell the checks' client the run is over: the checks still running
    send no further request (no next endpoint, no 429 retry). Queued
    checks are cancelled by the pool itself."""
    stop = getattr(client, "stop", None)
    if callable(stop):
        try:
            stop()
        except Exception:  # noqa: BLE001
            pass


async def _end_checks_session(client: Any, pool: Any, running: set) -> None:
    """End the assessment checks' session. When no check thread is still
    using it, at once; otherwise (a check past its timeout, or a stream
    closed mid-run) in the background once those threads are done, so no
    running read is cut off and nothing waits on a stuck request."""
    if client is None:
        return
    if pool is None or not running:
        await asyncio.to_thread(_close_quietly, client)
        return

    def _later():
        pool.shutdown(wait=True)
        _close_quietly(client)
    threading.Thread(target=_later, name="assess-close", daemon=True).start()


@app.post("/api/tenant/check")
async def tenant_check(req: TenantCredsRequest):
    """Sign-in test for Authenticate: obtains the token (or, for the classic
    ZIA API, the session) and nothing else. It never lists or counts
    anything in the tenant: every read counts against the tenant's ZIA API
    rate limit, so the tenant is read only by an assessment the operator
    runs, for what they put in scope. A failure is explained in plain
    language with what to do next."""
    creds = _tenant_creds(req)
    label = tenant_auth.record_label(creds)   # never the classic API's admin login (user rule 3)
    method = creds["auth_method"]
    try:
        client = await asyncio.to_thread(_build_sdk_client, creds)   # signs in as it is built; no listing
        # What the sign-in token says (products and role names; decoded, never
        # verified, never returned): readiness.py. Reads nothing from the tenant.
        access = _readiness_token_access(client, method)
        # Sign-in only: end the session at once (the classic ZIA API keeps
        # an admin session open until it idles out otherwise).
        await asyncio.to_thread(_close_quietly, client)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail={"tenant_label": label, "auth_method": method, **_explain_connection_error(e.detail, method)})
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"tenant_label": label, "auth_method": method,
                                                     **_explain_connection_error(tenant_auth.mask_secrets(str(e), creds), method)})
    out: Dict[str, Any] = {"ok": True, "tenant_label": label, "auth_method": method, "problems": [], "access": access}
    if method == tenant_auth.LEGACY:
        out["problems"].append("Signed in through the classic ZIA API: ZIA only. ZPA, Client Connector and ZDX checks need a ZIdentity API client.")
    return out


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
    return {"profiles": tenant_profiles.list_profiles(), "store": os.path.basename(tenant_profiles.store_path()),
            "unfiled_snapshots": tenant_profiles.list_snapshots("")}


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
    if not (req.name or req.org_name or req.vanity_domain or req.username):
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
    if method == tenant_auth.LEGACY:
        # The classic API signs in with an admin login and no vanity domain:
        # one left in the form is not kept, and neither it nor the login
        # names the profile (user rule 3).
        default_name = tenant_auth.record_label({"auth_method": method, "cloud": cloud})
        # A name (or organisation) that is the admin login or the discarded
        # vanity domain is replaced too, as the guide may still pre-fill it.
        leaks = {"username": user, "vanity_domain": req.vanity_domain or ""}
        name = req.name if not tenant_profiles.classic_name_leaks(leaks, req.name) else ""
        org_name = req.org_name if not tenant_profiles.classic_name_leaks(leaks, req.org_name) else ""
        vd = ""
    else:
        default_name = vd or user
        name, org_name = req.name, req.org_name
    fields = {
        "name": name or org_name or default_name, "org_name": org_name, "assessor": req.assessor,
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


# ── Offline tenants: the sample tenant and saved snapshots ─────────────
# (offline_tenant.py, sample_tenant.py; snapshots are kept beside the
# tenant profiles, tenant_profiles.py.) "Try with a sample tenant" and
# "Open a snapshot" set a cookie for this browser; while it is set,
# _tenant_creds answers with offline credentials and the client factories
# (_raw_client, _build_sdk_client) hand out the offline clients, which
# have no network code: every page works on it and nothing reaches a
# tenant. "Leave" clears it. A snapshot is saved from a read-only, scoped
# tenant read with no credentials in it, owner-only.
import offline_tenant as _offline   # its SourceMiddleware is added with the other layers, inside the size cap


def _offline_creds() -> Optional[Dict[str, str]]:
    """This request's offline credentials (None: the live tenant); 409 when
    its offline tenant is no longer open (fail closed, never the live one)."""
    try:
        return _offline.current_creds()
    except _offline.OfflineError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


def _offline_client(creds: Dict[str, str], kind: str):
    """The offline client for offline credentials, None for real ones."""
    try:
        return _offline.client_for(creds, kind)
    except _offline.OfflineError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


def _offline_answer(request: Request, body: Dict[str, Any], source: Optional[str]) -> JSONResponse:
    """`body` as JSON, with this browser's offline tenant set (or cleared)."""
    resp = JSONResponse(body)
    if source:
        # Secure whenever the page came over HTTPS, a TLS reverse proxy included
        # (X-Forwarded-Proto), the same rule as the UI token cookie (security._https).
        resp.set_cookie(_offline.COOKIE, source, httponly=True, samesite="strict", secure=_security._https(request), path="/")
    else:
        resp.delete_cookie(_offline.COOKIE, path="/")
    return resp


class OfflineSampleRequest(BaseModel):
    """Open the sample tenant; `reset` throws away its in-memory changes."""
    reset: bool = False


class SnapshotFileRequest(BaseModel):
    """A snapshot file chosen in the browser: its text (checked as untrusted)."""
    name: str = ""
    content: str


class SnapshotCompareRequest(ScopedTenantCredsRequest):
    """Compare a saved (or opened) snapshot with the live tenant."""
    snapshot_id: str = ""


@app.get("/api/offline/status")
async def offline_status():
    """Which tenant this browser uses: the live one, the sample tenant or a
    snapshot (with its label and when it was read). Reads nothing."""
    return _offline.status()


@app.post("/api/offline/sample")
async def offline_sample(req: OfflineSampleRequest, request: Request):
    """Use the sample tenant (Larkspur Freight, made up) in this browser.
    Nothing here is real; its changes stay in this server's memory."""
    st = await asyncio.to_thread(_offline.sample_store, req.reset)
    return _offline_answer(request, st.describe(), st.id)


@app.post("/api/offline/leave")
async def offline_leave(request: Request):
    """Back to the live tenant in this browser (the sample or snapshot is closed here)."""
    return _offline_answer(request, {"mode": "live"}, None)


@app.post("/api/tenant-profiles/snapshots/open-file")
async def snapshot_open_file(req: SnapshotFileRequest, request: Request):
    """Open a snapshot file chosen in the browser, offline and read-only. The
    file is untrusted: size, nesting depth, schema and every path are
    checked, and nothing in it names a file, an id or a credential."""
    try:
        st = await asyncio.to_thread(_offline.open_document, req.content)
    except _offline.OfflineError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    return _offline_answer(request, st.describe(), st.id)


@app.post("/api/tenant-profiles/snapshots/{snapshot_id}/open")
async def snapshot_open(snapshot_id: str, request: Request):
    """Open a saved snapshot (listed with its tenant profile), offline and read-only."""
    try:
        st = await asyncio.to_thread(_offline.open_saved, snapshot_id)
    except _offline.OfflineError as e:
        raise HTTPException(status_code=404 if e.status == 404 else e.status, detail=str(e))
    return _offline_answer(request, st.describe(), st.id)


@app.get("/api/tenant-profiles/snapshots/{snapshot_id}/download")
async def snapshot_download(snapshot_id: str):
    """A saved snapshot as a file, to open on another computer."""
    import tenant_profiles
    try:
        raw = await asyncio.to_thread(tenant_profiles.read_snapshot, snapshot_id, _offline.MAX_SNAPSHOT_BYTES)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return Response(raw, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="zscaler-snapshot-{snapshot_id[5:]}.json"'})


@app.post("/api/tenant-profiles/snapshots/{snapshot_id}/delete")
async def snapshot_delete(snapshot_id: str, request: Request):
    """Delete a saved snapshot (the file and its place in the profile list)."""
    import tenant_profiles
    try:
        ok = tenant_profiles.delete_snapshot(snapshot_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="No such snapshot.")
    _offline.forget(snapshot_id)
    in_use = _offline.current_source() == snapshot_id
    return _offline_answer(request, {"deleted": snapshot_id, "mode": "live" if in_use else _offline.status().get("mode")},
                           None if in_use else _offline.current_source())


def _snapshot_live(req: Any, what: str) -> Tuple[Dict[str, str], List[str], Dict[str, Any]]:
    """The live tenant's credentials and the Scope page selection for a
    snapshot read (before any sign-in): 400 when nothing it reads is in scope."""
    sc, ch, _source = _scope_selection(req)
    scopes = [s for s in sc if s in _offline.KNOWN_SCOPES]
    if not _offline.capture_plan(scopes):
        raise HTTPException(status_code=400, detail=f"{what}: nothing is in scope. On the Scope page tick what to keep "
                                                    "(DLP, ZIA platform, ZPA, Client Connector, ZDX or ZIdentity). Nothing was read.")
    with _offline.using(None):   # always the live tenant
        creds = _tenant_creds(req)
    if not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail=f"Fill in the tenant details (or pick a saved tenant) for {what.lower()}.")
    return creds, scopes, ch


def _signed_in_raw(creds: Dict[str, str]):
    """The live raw-HTTP client, signed in (401 in words otherwise; no secret echoed)."""
    c = _validate_creds(creds)
    client = _raw_client(c)
    ok = client.auth()
    if ok is not True:
        reason = tenant_auth.mask_secrets(str(ok[1]) if isinstance(ok, tuple) and len(ok) == 2 else "", c)
        raise HTTPException(status_code=401, detail=f"Authentication failed for {tenant_auth.identity(c)}: {reason[:200]}")
    return client


@app.post("/api/tenant-profiles/snapshots/save/start")
async def snapshot_save_start(req: ScopedTenantCredsRequest, request: Request):
    """Save a snapshot of the live tenant, as a background job: a read-only
    read of only what is in scope on the Scope page, kept beside the tenant
    profile as an owner-only file with no credentials in it. Poll
    GET /api/dlp-packs/jobs/{job_id}."""
    import pack_jobs
    import tenant_profiles
    if _offline.current_source():
        raise HTTPException(status_code=409, detail="This browser is using the sample tenant or a snapshot. Choose Leave first, then save "
                                                    "a snapshot of your own tenant.")
    creds, scopes, channels = _snapshot_live(req, "Save a snapshot")
    client = await asyncio.to_thread(_signed_in_raw, creds)
    label = tenant_auth.record_label(creds)
    profile_id = req.profile_id if (req.profile_id and tenant_profiles.get(req.profile_id)) else ""

    def run(log, cancel):
        try:
            got = _offline.capture(client, scopes, channels, log, cancel)
        finally:
            client.close()
        if got["stopped"]:
            return {"stopped": True}
        if not got["responses"]:
            raise RuntimeError("Nothing could be read from the tenant, so no snapshot was saved.")
        meta = {"tenant_label": label, "saved_at": _offline._now(), "auth_method": creds["auth_method"], "scopes": scopes,
                "channels": __import__("channel_scope").normalize(channels), "counts": got["counts"], "unread": got["unread"]}
        text = _offline.dumps(_offline.build_snapshot(got["responses"], meta))
        if len(text.encode("utf-8")) > _offline.MAX_SNAPSHOT_BYTES:
            raise RuntimeError("The tenant read is larger than a snapshot may be; untick some scopes and save again.")
        entry = tenant_profiles.save_snapshot(text, {"saved_at": meta["saved_at"], "tenant_label": label, "scopes": scopes,
                                                     "counts": got["counts"]}, profile_id)
        log(f"Snapshot saved: {got['counts']['answers']} lists, {got['counts']['objects']} objects, no credentials.")
        return {"snapshot": entry, "counts": got["counts"], "unread": got["unread"][:50]}

    job = pack_jobs.start("snapshot", run, label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id}


@app.post("/api/tenant-profiles/snapshots/compare/start")
async def snapshot_compare_start(req: SnapshotCompareRequest, request: Request):
    """Compare a snapshot with the live tenant, as a background job: the
    live tenant is read (read-only, only what is in scope) and every list
    the two have in common is compared: objects added, removed, changed."""
    import pack_jobs
    sid = str(req.snapshot_id or "")
    if sid == _offline.SAMPLE or not _offline.SOURCE_RE.match(sid):
        raise HTTPException(status_code=404, detail="Pick a saved or opened snapshot to compare.")
    old = await asyncio.to_thread(_offline.store, sid)
    if old is None:
        raise HTTPException(status_code=404, detail="That snapshot is not open or saved any more.")
    creds, scopes, channels = _snapshot_live(req, "Compare with the live tenant")
    client = await asyncio.to_thread(_signed_in_raw, creds)
    label = tenant_auth.record_label(creds)

    def run(log, cancel):
        try:
            got = _offline.capture(client, scopes, channels, log, cancel)
        finally:
            client.close()
        if got["stopped"]:
            return {"stopped": True}
        diff = _offline.compare(old.responses, got["responses"])
        log(f"Compared {diff['compared']} lists: {diff['totals']['added']} added, {diff['totals']['removed']} removed, "
            f"{diff['totals']['changed']} changed.")
        return dict(diff, snapshot=old.describe(), live_label=label, unread=got["unread"][:50])

    job = pack_jobs.start("snapshot-compare", run, label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id}


def _journey_packs(pack_ids: List[str]) -> List[Dict[str, Any]]:
    import pack_deploy
    from dlp_importer import discover_packs
    if pack_ids:
        return _resolve_pack_ids(pack_ids)
    return [{"id": p["id"], "dir": p["dir"]} for p in discover_packs() if pack_deploy.baseline_meta(p, p["id"])]


def _journey_scope(pack_ids: List[str], channels: Any) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    """The packs and channels the assessment's journey may measure: only
    the packs chosen on the profile (never every installed pack), each on
    its own DLP channels that the Scope page marks Zscaler. A pack with no
    such channel is left out, so nothing out of scope is read. Reads local
    pack files only."""
    import channel_scope
    import pack_channels as pc
    import pack_deploy
    from dlp_importer import discover_packs
    targets = channel_scope.pack_targets(channels)
    if not pack_ids or not targets:
        return [], {}
    known = {p["id"]: p for p in discover_packs()}
    packs: List[Dict[str, Any]] = []
    chosen: Dict[str, List[str]] = {}
    for pid in pack_ids:
        if pid not in known or pid in chosen:
            continue
        pk = {"id": pid, "dir": known[pid]["dir"]}
        try:
            own = {pc.channel_of(p) for p in pack_deploy.load_sources([pk])[0]["policies"]}
        except Exception:  # noqa: BLE001 — an unreadable pack is not measured
            continue
        mine = [c for c in pc.DLP_CHANNELS if c in own and c in targets]
        if mine:
            packs.append(pk)
            chosen[pid] = mine
    return packs, chosen


class JourneyStopped(Exception):
    """The run the journey belongs to has ended (stream closed, timed out)."""


_PLAIN = (str, bytes, int, float, bool, type(None), dict, list, tuple, set)


class _StopAware:
    """Wraps an SDK client so that every call made through it (every
    tenant read) first checks `stop`: once the run has ended, the next read
    raises JourneyStopped instead of reaching the tenant."""

    def __init__(self, target: Any, stop: Any):
        object.__setattr__(self, "_t", target)
        object.__setattr__(self, "_stop", stop)

    def __getattr__(self, name):
        val = getattr(self._t, name)
        if isinstance(val, _PLAIN):
            return val
        if callable(val) and not isinstance(val, type):
            stop = self._stop

            def call(*a, **k):
                if stop.is_set():
                    raise JourneyStopped("the run ended; no further tenant read")
                import zia_rate
                try:
                    # A Stop while the read waits for ZIA's read limit: not sent.
                    with zia_rate.stopping_on(stop.is_set):
                        out = val(*a, **k)
                except zia_rate.Cancelled:
                    raise JourneyStopped("the run ended while a read waited for ZIA's rate limit; it was not sent") from None
                return out
            return call
        return _StopAware(val, self._stop)

    def __setattr__(self, name, value):
        setattr(self._t, name, value)


def _journey_for(client, packs: List[Dict[str, Any]], use_rank_0: bool = False,
                 channel_targets: Optional[Dict[str, List[str]]] = None,
                 progress: Optional[Any] = None, stop: Optional[Any] = None) -> Dict[str, Any]:
    """Read-only journey check: one preflight per policy pack (so each
    pack is measured on its own), rolled up with pack_deploy.journey.
    `channel_targets` measures the pack as the operator chose to deploy
    it (extension rules count, skipped channels do not). The tenant is
    read once for every pack (superset of their needs); `progress(i, n,
    pack_id)` is called before each pack is measured. `stop` (an Event):
    once set, no further tenant read is made (JourneyStopped)."""
    import pack_deploy
    import pack_channels as pc
    if stop is not None:
        client = _StopAware(client, stop)
    rows: List[Dict[str, Any]] = []
    tenant = None
    blockers: List[str] = []
    # With channel targets (the assessment's journey), only the channels in
    # scope are read: Web DLP rules too are left alone when web is not one.
    cache: Dict[str, Any] = {"only_channels": channel_targets is not None}
    try:
        merged = pack_deploy.merge_sources(pack_deploy.load_sources(packs, channel_targets or {}))
        cache["need"] = pc.needs(i["definition"] for i in merged["policy"].values())
    except Exception:  # noqa: BLE001 — fall back to per-pack needs
        cache.pop("need", None)
    for i, pk in enumerate(packs):
        if stop is not None and stop.is_set():
            raise JourneyStopped("the run ended; no further tenant read")
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
    try:
        out = await asyncio.to_thread(_journey_for, client, packs, req.use_rank_0, req.channel_targets or None)
    finally:   # end the session (a classic ZIA API one stays open otherwise)
        await asyncio.to_thread(_close_quietly, client)
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
    _require_assessor(req)
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
        # Stop also ends this read: nothing more is read (user rule 4).
        full = pack_deploy.preflight(client, packs, use_rank_0=req.use_rank_0, apply_tweaks=False, writes_enabled=None,
                                     channel_targets=req.channel_targets or None, log=_log, cancel=cancel)
        if full.get("status") == "stopped" or (cancel is not None and cancel.is_set()):
            _log("Stopped before the workspace was built.")
            return {"status": "stopped", "stopped": "You clicked Stop.", "mode": mode, "packs": [], "logs": logs}
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
    name = f"zscaler-made-easy-terraform-{mode}-{'-'.join(req.pack_ids)[:60]}.zip"
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
    _require_assessor(req)
    packs = _resolve_pack_ids(req.pack_ids)
    creds, client = await _terraform_client(req)
    job = pack_jobs.start("terraform", lambda log, cancel: _run_terraform(client, creds, req, packs, log, cancel), label=", ".join(req.pack_ids),
                           actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


class PackExportRequest(ScopedTenantCredsRequest):
    """Body of Export from tenant as a pack: which rules (rule ids per
    channel, or "all"; empty means every DLP rule on every channel in
    scope), the name the pack gets and what is in scope on the Scope page
    (only those channels are read).

    `parts` picks what is exported: dictionaries, engines and/or rules
    (empty: rules, as before), and/or "framework": the ZIA policy
    framework (ops_zia_baseline.capture: URL filtering, Cloud Firewall, SSL
    inspection, Sandbox, DNS Control and File Type Control rules in scope). `dictionaries` and `engines` pick custom
    ones by id ("all" or omitted: every custom one).
    `include_dependencies` (default on) brings what the picked engines and
    rules use; off, that is named, not copied. `format` is json (the pack),
    terraform (a workspace for the zscaler/zia provider) or both."""
    customer_id: str = ""
    rules: Dict[str, Any] = {}
    pack_name: str = ""
    parts: List[str] = []
    dictionaries: Any = None
    engines: Any = None
    include_dependencies: bool = True
    format: str = "json"


def _run_pack_export(client, creds: Dict[str, str], req: PackExportRequest, selection, log, cancel,
                     framework_areas: Optional[List[str]] = None) -> Dict[str, Any]:
    """Read the tenant and build the pack (pack_export), zipped. The zip
    travels as the result's `artifact`; the JSON result says what is in it
    and what could not be exported."""
    import pack_export
    c = tenant_auth.normalize(creds)
    # The pack names the tenant, never the admin who signed in (the classic API's label is its username).
    # The classic API's label is 'classic API (cloud)' (tenant_auth.record_label), never a stale vanity domain.
    label = tenant_auth.record_label(c)
    parts = pack_export.normalize_parts(req.parts)
    fmt = pack_export.normalize_format(req.format)
    if parts == ("rules",) and req.include_dependencies:
        log(f"Exporting from {label}: the rules, the engines they use and the dictionaries those engines use. Nothing is written to the tenant.")
    else:
        log(f"Exporting from {label}: {', '.join(parts)}" + (" with what they use" if req.include_dependencies else " only (what they use is named, not copied)")
            + ". Nothing is written to the tenant.")
    res = pack_export.export_pack(client, selection=selection, name=req.pack_name[:120], tenant_label=label, log=log, cancel=cancel,
                                  parts=parts, dictionaries=req.dictionaries, engines=req.engines,
                                  include_dependencies=req.include_dependencies, framework_areas=framework_areas or ())
    if res["status"] != "ready":
        return dict(res, tenant_label=label)
    pack = res["pack"]
    if fmt != "json":
        log("Writing the Terraform workspace (zscaler/zia provider)…")
    name, data, part_files = pack_export.zip_export(pack, fmt, _assessor(req))
    if cancel is not None and cancel.is_set():   # Stop said no pack is produced; keep that promise
        return {"status": "stopped", "stopped": "You clicked Stop.", "tenant_label": label}
    log(f"Ready: {name} ({max(1, len(data) // 1024)} KB).")
    v = res["validation"]
    return {"status": "ready", "filename": name, "bytes": len(data), "tenant_label": label, "pack_name": pack["meta"]["name"],
            "format": fmt, "parts": list(parts), "dependencies_included": bool(req.include_dependencies),
            "part_files": part_files, "referenced_only": pack["meta"].get("referenced_only") or {},
            "assessor_named": bool(_assessor(req)),
            "counts": pack["meta"]["counts"], "not_exported": pack["meta"]["not_exported"], "warnings": pack["warnings"],
            "framework_counts": (pack.get("framework") or {}).get("counts"),
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
    import pack_deploy
    import pack_jobs
    try:
        selection = pack_export.normalize_selection(req.rules or None)
        parts = pack_export.normalize_parts(req.parts)
        fmt = pack_export.normalize_format(req.format)
        dict_pick = pack_export.normalize_object_pick(req.dictionaries, "dictionaries")
        engine_pick = pack_export.normalize_object_pick(req.engines, "engines")
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    # The ZIA policy framework part reads only the rule areas in scope (ops_zia_baseline.capture_scope).
    framework_areas: List[str] = []
    if pack_export.FRAMEWORK in parts:
        import ops_zia_baseline
        sc, ch, _src = _scope_selection(req)
        framework_areas = ops_zia_baseline.capture_scope(sc, ch)
        if not framework_areas:
            raise HTTPException(status_code=400, detail="The ZIA policy framework is not in scope on the Scope page: tick ZIA platform "
                                                        "(Cloud Firewall, Sandbox, DNS Control) or DLP (URL filtering, File Type Control, "
                                                        "SSL inspection when marked Zscaler). Nothing was read.")
        parts = tuple(p for p in parts if p != pack_export.FRAMEWORK)
    if parts == ("rules",) and pack_export.nothing_picked(selection) and not framework_areas:   # nothing to read the tenant for
        raise HTTPException(status_code=400, detail=pack_export.NOTHING_PICKED)
    if (("rules" not in parts or pack_export.nothing_picked(selection)) and ("dictionaries" not in parts or dict_pick == set())
            and ("engines" not in parts or engine_pick == set()) and not framework_areas):
        raise HTTPException(status_code=400, detail=pack_export.NOTHING_IN_PARTS)
    if fmt != "json" and pack_deploy.is_tool_name(req.assessor):
        # Terraform tags every object with the assessor: never the tool's own name.
        raise HTTPException(status_code=400, detail=ASSESSOR_NOT_TOOL)
    # Only the channels in scope on the Scope page are read (user rule 1).
    in_scope = _pack_channels_in_scope(req, "Export from tenant") if parts else []
    if "rules" not in parts:
        selection = {}
    elif selection is None:
        selection = {ch: None for ch in in_scope}
    else:
        out = sorted(ch for ch, ids in selection.items() if ch not in in_scope and (ids is None or ids))
        if out:
            raise HTTPException(status_code=400, detail=f"Not in scope on the Scope page: {', '.join(out)} DLP rules. Mark the channel as Zscaler, "
                                                        "or leave its rules out of the export. Nothing was read.")
        selection = {ch: ids for ch, ids in selection.items() if ch in in_scope}
    creds = _tenant_creds(req)
    if not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail="Fill in the tenant details (or pick a saved tenant) to export its rules.")
    client = await asyncio.to_thread(_build_sdk_client, creds)
    job = pack_jobs.start("export", lambda log, cancel: _keyed(client, _run_pack_export, client, creds, req, selection, log, cancel,
                                                               framework_areas),
                          label=req.pack_name[:60] or tenant_auth.record_label(creds), actor=_actor(request),
                          start_token=_start_token(request))
    if _security.from_extension(request):
        job.started_by = "extension"   # the one job kind the extension may stop
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/dlp-packs/jobs/{job_id}/download")
async def dlp_pack_job_download(job_id: str, file: str = ""):
    """The file a finished job produced (a Terraform workspace zip, or an
    exported pack). With `file`, only that part of an export (one of the
    result's part_files: the dictionaries, engines or rules, as JSON or
    Terraform)."""
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job. Jobs are kept for an hour after they finish; start the hand-off again.")
    if job.artifact is None:
        raise HTTPException(status_code=409, detail="This job has no file to download" + (" yet; it is still running." if job.status == pack_jobs.RUNNING else "."))
    name, media, data = job.artifact
    if file:
        import pack_export
        entry = next((f for f in ((job.result or {}).get("part_files") or []) if f.get("path") == file), None)
        member = pack_export.zip_member(data, file) if entry else None
        if member is None:
            raise HTTPException(status_code=404, detail="That file is not one of this export's parts.")
        # <pack>-<part>.json or <pack>-<part>.tf
        slug = file.split("/", 1)[0].removesuffix("-terraform")
        ext = "tf" if entry.get("format") == "terraform" else "json"
        part_name = f"{slug}-{entry.get('part')}.{ext}"
        part_media = "application/json" if ext == "json" else "text/plain; charset=utf-8"
        return Response(content=member, media_type=part_media, headers={"Content-Disposition": f'attachment; filename="{part_name}"'})
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
    _require_assessor(req)
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
    if result.get("status") in ("plan_changed", "blocked", "stopped"):
        return result
    # Remember what was created so the deployment can be undone later.
    try:
        import deployments
        rec = deployments.from_apply(result, tenant_label=tenant_auth.record_label(creds),
                                     packs=list(req.pack_ids), options={"use_rank_0": req.use_rank_0, "apply_tweaks": req.apply_tweaks,
                                                                        "restore_drift": req.restore_drift},
                                     channel_targets=req.channel_targets or {}, by=by, **_record_ids(creds))
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
    _require_assessor(req)
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    packs = _resolve_pack_ids(req.pack_ids)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    job = pack_jobs.start("deploy", lambda log, cancel: _keyed(client, _run_apply, client, creds, req, packs, log, cancel), label=", ".join(req.pack_ids),
                           actor=_actor(request), start_token=_start_token(request))
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
    _require_tenant_write(req, confirmed=req.confirm, what="Undo")
    creds = _tenant_creds(req)
    _require_same_tenant(rec, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    logs: list = []
    result = await asyncio.to_thread(_as_actor, _actor(request), lambda: pack_deploy.undo(client, rec, writes_enabled=True, log=logs.append))
    result["logs"] = logs
    # A run refused as busy read and wrote nothing: the record keeps its last undo.
    updated = rec if result.get("busy") else deployments.mark_undo(dep_id, result.get("results") or [], complete=bool(result.get("complete")))
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
    # A deploying call needs confirm=true, the assessor's name and write mode
    # before the tenant is signed in to.
    by = ""
    if req.plan_hash:
        by = _require_assessor(req)
        if req.confirm is not True:
            raise HTTPException(status_code=400, detail="Deployment requires explicit confirmation (confirm=true).")
        if not writes_enabled():
            raise HTTPException(status_code=403, detail=_writes_disabled_msg())
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
    result = await asyncio.to_thread(_as_actor, _actor(request), lambda: pack_deploy.apply(client, [pack], plan_hash=req.plan_hash, use_rank_0=req.use_rank_0,
                                                               apply_tweaks=req.apply_tweaks, verify=req.verify, writes_enabled=True,
                                                               log=logs.append, assessor=by))
    result["logs"] = logs
    # A partial deploy created objects too: record whatever was created (as
    # Deploy Policy Packs does), or it could never be undone.
    if result.get("status") not in ("plan_changed", "blocked", "stopped"):
        try:
            import deployments
            creds = _tenant_creds(req)
            rec = deployments.from_apply(result, tenant_label=tenant_auth.record_label(creds), packs=[pack["id"]],
                                         options={"use_rank_0": req.use_rank_0, "apply_tweaks": req.apply_tweaks}, channel_targets={},
                                         by=by, **_record_ids(creds))
            if rec:   # None when nothing was created
                deployments.add(rec)
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
    # Off the event loop, as every upload parser is: a large pack must not hold up every other request.
    return await asyncio.to_thread(_dlp_pack_upload, req)


def _dlp_pack_upload(req: DLPPackUploadRequest) -> Dict[str, Any]:
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
    what would block it, what to watch. Off the event loop (a large upload
    must not hold up every other request)."""
    return await asyncio.to_thread(_pack_library_preview, req)


def _pack_library_preview(req: PackLibraryUploadRequest) -> Dict[str, Any]:
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
    Terraform hand-off and the validator all list it. Off the event loop
    (a large upload must not hold up every other request)."""
    _require_pack_library_writes()
    return await asyncio.to_thread(_pack_library_upload, req)


def _pack_library_upload(req: PackLibraryUploadRequest) -> Dict[str, Any]:
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


# ── Excel and PDF exports (report_exports, on the in-house xlsx_writer / pdf_writer) ──
# Read-only: the assessment workbook is built from the results the page
# holds (as the Word report is), the DLP inventory from a read of the
# channels in scope, and the deployment plan from the server's own copy
# of a preflight (never from JSON the page posts).
_PLANS: Dict[str, Dict[str, Any]] = {}
_PLANS_MAX = 10
_PLAN_ID_RE = re.compile(r"plan-[A-Za-z0-9_-]{8,40}")


def _remember_plan(report: Dict[str, Any], assessor: str = "") -> str:
    """Keep a preflight report (the public one: no credentials, no
    internal state) for the plan exports; the last _PLANS_MAX are kept."""
    import copy
    import secrets
    rid = f"plan-{secrets.token_urlsafe(12)}"
    rep = copy.deepcopy(report)
    rep.update(report_id=rid, assessor=assessor or "", generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    _PLANS[rid] = rep
    while len(_PLANS) > _PLANS_MAX:
        _PLANS.pop(next(iter(_PLANS)))
    return rid


def _attachment(data: bytes, media: str, filename: str) -> Response:
    return Response(content=data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})


@app.post("/api/report/xlsx")
async def generate_xlsx(request: Request):
    """The assessment results as an Excel workbook (Summary, Findings,
    Frameworks, Compliance mapping, Best practices), from the same body
    as /api/report/docx. Scores are recomputed here from the checks."""
    import report_exports
    data = await _json_object(request)
    if not data.get("checks"):
        raise HTTPException(status_code=400, detail="No checks in request body — cannot build the workbook.")
    try:
        body = await asyncio.to_thread(report_exports.assessment_workbook, data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _attachment(body, report_exports.XLSX, report_exports.assessment_filename(data))


def _run_inventory_xlsx(client, creds: Dict[str, str], channels: List[str], log, cancel) -> Dict[str, Any]:
    """Read the dictionaries, engines and the rules of the channels in
    scope (pack_export.read_tenant) and build the DLP inventory workbook."""
    import pack_channels as pc
    import pack_export
    import report_exports
    label = tenant_auth.record_label(tenant_auth.normalize(creds))
    log(f"DLP inventory of {label}: dictionaries, engines and the {', '.join(pc.label(ch) for ch in channels)} rules. "
        "Nothing is written to the tenant.")
    snap = pack_export.read_tenant(client, channels=channels, log=log, cancel=cancel)
    if snap.get("stopped"):
        return {"status": "stopped", "stopped": "You clicked Stop.", "tenant_label": label}
    if snap.get("refused"):
        return {"status": "error", "error": f"ZIA refused the {snap['refused']['what']} for its rate limit; no workbook was made. "
                                            "Wait a few minutes and try again.", "tenant_label": label}
    data = report_exports.inventory_workbook(snap, tenant_label=label, channels=channels)
    if cancel is not None and cancel.is_set():
        return {"status": "stopped", "stopped": "You clicked Stop.", "tenant_label": label}
    name = report_exports.inventory_filename(label)
    log(f"Ready: {name} ({max(1, len(data) // 1024)} KB).")
    return {"status": "ready", "filename": name, "bytes": len(data), "tenant_label": label, "channels": channels,
            "counts": {"dictionaries": len(snap.get("dictionaries") or []), "engines": len(snap.get("engines") or []),
                       "rules": {ch: len(rs) for ch, rs in (snap.get("rules") or {}).items()}},
            "errors": dict(snap.get("errors") or {}), "artifact": (name, report_exports.XLSX, data)}


@app.post("/api/dlp-packs/inventory/start")
async def dlp_packs_inventory_start(req: ScopedTenantCredsRequest, request: Request):
    """DLP inventory (Excel) as a background job: the tenant's DLP
    dictionaries, engines and the rules of the DLP channels in scope, with
    who uses what. Read-only (no write mode, no writer check). Poll GET
    /api/dlp-packs/jobs/{job_id}; the finished job's `download` path
    serves the workbook."""
    import pack_jobs
    channels = _pack_channels_in_scope(req, "The DLP inventory")
    creds = _tenant_creds(req)
    if not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail="Fill in the tenant details (or pick a saved tenant) to list its DLP objects.")
    client = await asyncio.to_thread(_build_sdk_client, creds)
    job = pack_jobs.start("inventory", lambda log, cancel: _keyed(client, _run_inventory_xlsx, client, creds, channels, log, cancel),
                          label=tenant_auth.record_label(creds), actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/dlp-packs/plan/{report_id}/export")
async def dlp_packs_plan_export(report_id: str, format: str = "pdf", page: str = "a4"):
    """A Deploy policy packs preflight as a plan for change approval: PDF
    (A4 or Letter) or Excel, rendered from the server's copy of that
    preflight (kept in memory for the last few preflights)."""
    import report_exports
    rep = _PLANS.get(report_id) if _PLAN_ID_RE.fullmatch(report_id or "") else None
    if rep is None:
        raise HTTPException(status_code=404, detail="Plan not found or expired (the last few preflights are kept in memory "
                                                    "while the server runs). Run the preflight again.")
    fmt = (format or "").lower()
    if fmt == "pdf":
        size = {"a4": "A4", "letter": "LETTER"}.get((page or "").lower())
        if size is None:
            raise HTTPException(status_code=400, detail="page must be a4 or letter.")
        body = await asyncio.to_thread(report_exports.plan_pdf, rep, size)
        return _attachment(body, report_exports.PDF, report_exports.plan_filename(rep, "pdf"))
    if fmt == "xlsx":
        body = await asyncio.to_thread(report_exports.plan_workbook, rep)
        return _attachment(body, report_exports.XLSX, report_exports.plan_filename(rep, "xlsx"))
    raise HTTPException(status_code=400, detail="format must be pdf or xlsx.")


# ── Policy exports, the URLs export and the custom URL category analyzer ──
# (policy_exports, url_tools). Read-only: GET requests, plus the URL
# lookup's POST, which changes nothing in the tenant (the analyzer only).
# Each refuses (400) before signing in when nothing it reads is in scope.
@app.get("/report/exports")
async def report_exports_page():
    """Policy exports (static/report_exports.html): every export the app
    has in one place, with the policy, URLs and category analyzer jobs."""
    page = os.path.join(STATIC_DIR, "report_exports.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class PolicyExportRequest(ScopedTenantCredsRequest):
    """Body of the policy exports: tenant credentials, what is in scope,
    the policies (policy_exports.POLICIES keys; empty: every one in scope)
    and the format (xlsx, or pdf for the review copy; `page` a4 or letter).
    Export options (the workbooks; policy_exports.options): `columns`
    {sheet key: headers to keep}, `layout` flat | rows, `separator`
    newline | comma | semicolon. The defaults give the workbook as before."""
    policies: List[str] = []
    format: str = "xlsx"
    page: str = "a4"
    columns: Dict[str, List[str]] = {}
    layout: str = "flat"
    separator: str = "newline"


def _stopped_result(label: str, reason: str, log) -> Dict[str, Any]:
    if log:
        log("STOPPED — you clicked Stop; nothing more was read and no file was made.")
    return {"status": "stopped", "stopped": reason, "tenant_label": label}


def _run_policy_exports(client, scope: Dict[str, Any], policies: List[str], fmt: str, page: str, label: str, log, cancel,
                        opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    import policy_exports as pe
    log(f"Exporting from {label}: {', '.join(pe.POLICIES[k]['label'] for k in policies)} as {fmt.upper()}. Nothing is written to the tenant. {scope['summary']}")
    try:
        out = pe.run(client, scope, policies, fmt, tenant_label=label, log=log, cancel=cancel, page_size=page, opts=opts)
    except pe.Stopped as e:
        return _stopped_result(label, str(e), log)
    if cancel is not None and cancel.is_set():
        return _stopped_result(label, pe.STOPPED_REASON, log)
    out["tenant_label"] = label
    out["not_in_scope"] = scope.get("asked_not_in_scope") or {}
    return out


@app.post("/api/exports/policies/start")
async def exports_policies_start(req: PolicyExportRequest, request: Request):
    """One workbook (or PDF review copy) per policy: URL filtering, Cloud
    App Control, SSL inspection, Cloud Firewall, File Type Control, every
    rule in order with names, the shadowed-rule findings per rule.
    Read-only. Poll GET /api/dlp-packs/jobs/{job_id}; the finished job's
    `download` serves the file (a zip when several policies)."""
    import pack_jobs
    import policy_exports as pe
    fmt = (req.format or "").strip().lower()
    if fmt not in pe.FORMATS:
        raise HTTPException(status_code=400, detail="format must be xlsx or pdf.")
    page = {"a4": "A4", "letter": "LETTER"}.get((req.page or "a4").strip().lower())
    if page is None:
        raise HTTPException(status_code=400, detail="page must be a4 or letter.")
    try:
        opts = pe.options(req.columns, req.layout, req.separator)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    sc, ch, source = _scope_selection(req)
    scope = pe.scope_for(sc, ch)
    if not scope["read"]:
        raise HTTPException(status_code=400, detail=pe.NOTHING_IN_SCOPE)
    try:
        policies, why = pe.pick(scope, req.policies)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not policies:
        raise HTTPException(status_code=400, detail="None of the policies picked is in scope on the Scope page: "
                                                    + " ".join(f"{pe.POLICIES[k]['label']}: {v}" for k, v in why.items()) + " Nothing was read.")
    scope["asked_not_in_scope"] = why
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("policy_export", lambda log, cancel: _run_policy_exports(client, scope, policies, fmt, page, label, log, cancel, opts),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "policies": policies, "not_in_scope": why}


def _run_urls_export(client, sources: Dict[str, Any], label: str, log, cancel) -> Dict[str, Any]:
    import url_tools as ut
    log(f"Collecting every URL the policy of {label} names. Nothing is written to the tenant. {sources['summary']}")
    try:
        out = ut.urls_export(client, sources, tenant_label=label, log=log, cancel=cancel)
    except ut.Stopped as e:
        return _stopped_result(label, str(e), log)
    if cancel is not None and cancel.is_set():
        return _stopped_result(label, ut.STOPPED_REASON, log)
    out["tenant_label"] = label
    return out


@app.post("/api/exports/urls/start")
async def exports_urls_start(req: ScopedTenantCredsRequest, request: Request):
    """The URLs export: every URL, domain, IP and keyword the policy in
    scope names (custom URL categories, URL filtering and SSL inspection
    rules through them, Cloud Firewall destinations, Advanced settings
    bypass lists, Client Connector bypasses, PAC DIRECT hosts) in one
    deduplicated workbook. Read-only (GET only). Poll the job; download
    the workbook from its `download`."""
    import pack_jobs
    import url_tools as ut
    sc, ch, source = _scope_selection(req)
    sources = ut.sources_for(sc, ch)
    if not sources["read"]:
        raise HTTPException(status_code=400, detail=ut.NOTHING_IN_SCOPE_URLS)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("urls_export", lambda log, cancel: _run_urls_export(client, sources, label, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "sources": sources["read"], "not_in_scope": sources["not_in_scope"]}


class CategoryAnalyzerRequest(ScopedTenantCredsRequest):
    """Body of the custom URL category analyzer: the categories to analyse
    (ids or names; empty: every custom one) and at most how many URLs to
    look up (capped at url_tools.MAX_LOOKUP_URLS)."""
    categories: List[str] = []
    max_urls: int = 0


def _run_category_analyzer(client, req: CategoryAnalyzerRequest, label: str, log, cancel) -> Dict[str, Any]:
    import url_tools as ut
    from policy_exports import safe_part
    log(f"Analysing the custom URL categories of {label}. {ut.LOOKUP_NOTE}")
    try:
        res = ut.analyze_categories(client, picked=req.categories, max_urls=req.max_urls or ut.MAX_LOOKUP_URLS, log=log, cancel=cancel)
    except ut.Stopped as e:
        return _stopped_result(label, str(e), log)
    if cancel is not None and cancel.is_set():
        return _stopped_result(label, ut.STOPPED_REASON, log)
    res["tenant_label"] = label
    if res.get("status") != "ready":
        return res
    data = ut.analyzer_workbook(res, tenant_label=label)
    name = f"url_category_analysis_{safe_part(label)}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.xlsx"
    res.update(filename=name, artifact=(name, ut.XLSX, data))
    res["rows"] = res["rows"][:500]   # the page shows the first 500; the workbook has them all
    return res


@app.post("/api/exports/url-categories/analyze/start")
async def exports_category_analyzer_start(req: CategoryAnalyzerRequest, request: Request):
    """For every custom URL category (or the ones picked), the categories
    Zscaler itself assigns to each of its URLs (POST /urlLookup, 100 URLs
    per request, paced, retried on 429, capped), with a verdict per URL:
    redundant, categorised differently, not categorised. The lookup is a
    POST that changes nothing; everything else is GET. Poll the job;
    download the workbook from its `download`."""
    import pack_jobs
    import url_tools as ut
    sc, ch, source = _scope_selection(req)
    if not ut.analyzer_in_scope(sc, ch)["in_scope"]:
        raise HTTPException(status_code=400, detail=ut.NOTHING_IN_SCOPE_CATS)
    if req.max_urls < 0:
        raise HTTPException(status_code=400, detail="max_urls must be 0 (the default cap) or more.")
    if len(req.categories) > 500:
        raise HTTPException(status_code=400, detail="Pick at most 500 categories.")
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("category_analyzer", lambda log, cancel: _run_category_analyzer(client, req, label, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/exports/plans")
async def exports_plans():
    """The deployment plans kept in memory (the last few preflights), for
    the Policy exports page's plan PDF / Excel buttons. No tenant read."""
    return {"plans": [{"report_id": rid, "tenant_label": p.get("tenant_label") or "", "generated_at": p.get("generated_at") or "",
                       "packs": [str(x.get("name") or x.get("id")) for x in p.get("packs") or [] if isinstance(x, dict)],
                       "status": p.get("status") or ""} for rid, p in reversed(list(_PLANS.items()))]}


# ── Configuration exports: locations and Client Connector profiles ──
# (config_exports), with the policy exports' options. Read-only (GET).
# Each refuses (400) before signing in when it is not in scope or an
# option is wrong.
@app.get("/api/exports/columns")
async def exports_columns():
    """The columns each export's main sheet can carry, the layouts and the
    separators, for the Policy exports page's options. No tenant read."""
    import policy_exports as pe
    return {"columns": pe.column_catalogue(), "identity": list(pe.IDENTITY_COLUMNS), "layouts": list(pe.LAYOUTS),
            "separators": list(pe.SEPARATORS), "defaults": pe.DEFAULT_OPTIONS}


class ConfigExportRequest(ScopedTenantCredsRequest):
    """Body of the locations and Client Connector exports: credentials,
    what is in scope and the export options (as PolicyExportRequest)."""
    columns: Dict[str, List[str]] = {}
    layout: str = "flat"
    separator: str = "newline"


def _export_options(req: ConfigExportRequest) -> Dict[str, Any]:
    import policy_exports as pe
    try:
        return pe.options(req.columns, req.layout, req.separator)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _run_config_export(fn, kind_label: str, client, scope: Dict[str, Any], label: str, opts: Dict[str, Any], log, cancel) -> Dict[str, Any]:
    import config_exports as ce
    log(f"Exporting the {kind_label} of {label}. Nothing is written to the tenant. {scope['summary']}")
    try:
        out = fn(client, scope, tenant_label=label, log=log, cancel=cancel, opts=opts)
    except ce.Stopped as e:
        return _stopped_result(label, str(e), log)
    if cancel is not None and cancel.is_set():
        return _stopped_result(label, ce.STOPPED_REASON, log)
    out["tenant_label"] = label
    return out


@app.post("/api/exports/locations/start")
async def exports_locations_start(req: ConfigExportRequest, request: Request):
    """Locations and sub-locations with their settings, the location
    groups, and which URL filtering, Cloud Firewall, SSL inspection, File
    Type Control and Web DLP rules use each (those in scope). Needs ZIA
    platform in scope. IP addresses and VPN credentials are counted, never
    listed. Read-only. Poll GET /api/dlp-packs/jobs/{job_id}."""
    import config_exports as ce
    import pack_jobs
    opts = _export_options(req)
    sc, ch, source = _scope_selection(req)
    scope = ce.locations_scope(sc, ch)
    if not scope["in_scope"]:
        raise HTTPException(status_code=400, detail=ce.NOTHING_IN_SCOPE_LOCATIONS)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("locations_export", lambda log, cancel: _run_config_export(ce.locations_export, "locations", client, scope, label, opts, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "usage": scope["usage"], "not_in_scope": scope["not_in_scope"]}


@app.post("/api/exports/client-connector/start")
async def exports_client_connector_start(req: ConfigExportRequest, request: Request):
    """Client Connector app profiles and forwarding profiles with their
    settings (no password, passcode, token or key), PAC files, and which
    profile uses which forwarding profile and PAC URL. Needs ZCC in scope.
    Read-only. Poll GET /api/dlp-packs/jobs/{job_id}."""
    import config_exports as ce
    import pack_jobs
    opts = _export_options(req)
    sc, ch, source = _scope_selection(req)
    scope = ce.zcc_scope(sc, ch)
    if not scope["in_scope"]:
        raise HTTPException(status_code=400, detail=ce.NOTHING_IN_SCOPE_ZCC)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("client_connector_export",
                          lambda log, cancel: _run_config_export(ce.client_connector_export, "Client Connector profiles", client, scope, label, opts, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/pack-library/{pack_id}/terraform.zip")
async def pack_library_terraform(pack_id: str, assessor: str = "", profile_id: str = ""):
    """The pack as a Terraform workspace for the official zscaler/zia
    provider, static mode (no tenant read), for any pack in the library.
    Gap mode (imports of what already exists) is the Terraform hand-off.
    `assessor` (else the saved profile's, by `profile_id`) is the name the
    provenance tags carry; refused (400) when no assessor is named."""
    import pack_library as pl
    import pack_terraform
    pack = _resolve_pack_ids([pack_id])[0]
    from types import SimpleNamespace
    by = _require_assessor(SimpleNamespace(assessor=assessor, profile_id=profile_id))
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


# ── Bulk changes (admin_ops) ─────────────────────────────────────────
# Mass enable / disable of ZIA rules, rule reordering, custom URL
# category changes and ZPA segment domain moves, through the same gates as
# a policy pack deploy: preview (reads only) → plan_hash → write mode, a
# writer, confirm and the typed phrase → apply through pack_ops (conflict
# guard per item, activation, read-back) → a record with its Undo.
@app.get("/report/operations")
async def report_operations_page():
    """Bulk changes (static/report_operations.html)."""
    page = os.path.join(STATIC_DIR, "report_operations.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class OperationCredsRequest(ScopedTenantCredsRequest):
    """Tenant credentials of a bulk change, with the ZPA customer ID the
    page sends (a ZPA type or family is refused before sign-in without it,
    _ops_zpa_gate); blank falls back to the saved profile's."""
    customer_id: str = ""


class OperationObjectsRequest(OperationCredsRequest):
    """Body of the object picker: what to list (rules, url_categories or zpa_segments)."""
    family: str = "rules"


class OperationRequest(OperationCredsRequest):
    """Body of a bulk change: the operation (admin_ops spec) and, to apply
    it, the previewed plan_hash, confirm=true and, above ten changes, the
    typed phrase. `undo_of` names the operation an Undo reverses."""
    operation: Dict[str, Any] = {}
    plan_hash: str = ""
    confirm: bool = False
    confirm_text: str = ""
    undo_of: str = ""
    # The Client Connector builder's typed tamper passwords
    # ({uninstall_password, disable_password, logout_password}): beside the
    # operation, never in it; taken off the request before sign-in and held
    # only for that preview or apply (ops_zcc.passwords_in_flight).
    tamper_passwords: Dict[str, str] = {}


OPS_ASSESSOR_REQUIRED = ("Enter the assessor's name (Scope assessment → Assessor name, or the field on this page) before applying a "
                         "bulk change: the change record and any object it creates name the assessor.")


def _ops_scope(req: Any, what: Any) -> Dict[str, Any]:
    """admin_ops.scope_for of the Scope page's selection; 400 before any
    sign-in when `what` (a family or an operation) is not in scope."""
    import admin_ops
    sc, ch, source = _scope_selection(req)
    scope = admin_ops.scope_for(sc, ch)
    scope["source"] = source
    try:
        admin_ops.require_scope(what, scope)
    except admin_ops.OperationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return scope


OPS_ZPA_NEEDS_ONEAPI = ("ZPA bulk changes need a ZIdentity (OneAPI) API client: the classic ZIA API reaches ZIA only. "
                        "Sign in with an API client that has a ZPA role, then run it again. Nothing was read.")
OPS_ZPA_NEEDS_CUSTOMER_ID = ("ZPA bulk changes need the ZPA customer ID (Connect to the tenant → Customer ID, or the saved profile): "
                             "every ZPA API path carries it. Nothing was read.")


def _ops_zpa_gate(what: Any, creds: Dict[str, str]) -> None:
    """A ZPA bulk change, builder type or family needs a OneAPI sign-in and
    the ZPA customer ID: 400 before any sign-in otherwise (a client without
    the customer ID would call /customers/None/...)."""
    import admin_ops
    if admin_ops.product_of(what) != "zpa":
        return
    if creds.get("auth_method") == tenant_auth.LEGACY:
        raise HTTPException(status_code=400, detail=OPS_ZPA_NEEDS_ONEAPI)
    if not validate_customer_id(creds.get("customer_id") or ""):
        raise HTTPException(status_code=400, detail=OPS_ZPA_NEEDS_CUSTOMER_ID)


def _ops_assessor(req: Any) -> str:
    try:
        return _require_assessor(req)
    except HTTPException as e:
        if e.detail == ASSESSOR_REQUIRED:
            raise HTTPException(status_code=400, detail=OPS_ASSESSOR_REQUIRED)
        raise


def _run_ops_objects(client, family: str, scope: Dict[str, Any], label: str, log, cancel) -> Dict[str, Any]:
    import admin_ops
    say = log or (lambda m: None)
    say(f"Reading {label}. Nothing is written to the tenant.")
    try:
        out = admin_ops.read_objects(client, family, scope, log=say, cancel=cancel)
    except admin_ops.Stopped as e:
        return {"status": "stopped", "stopped": str(e), "tenant_label": label}
    except admin_ops.OperationError as e:
        return {"status": "refused", "message": str(e), "tenant_label": label}
    out.update(status="done", tenant_label=label, writes_enabled=writes_enabled(), scope_source=scope.get("source") or "")
    return out


def _ops_passwords(req: OperationRequest) -> Dict[str, str]:
    """The typed tamper passwords, checked before sign-in and taken off the
    request, so nothing that keeps the request (a job, an error) keeps
    them. 400 for passwords sent with another operation or not valid; the
    refusal never repeats a value."""
    import ops_zcc
    raw = req.tamper_passwords or {}
    req.tamper_passwords = {}
    if not raw or not any(v not in (None, "") for v in raw.values()):
        return {}
    if not isinstance(req.operation, dict) or req.operation.get("type") != ops_zcc.BUILD:
        raise HTTPException(status_code=400, detail="Passwords are taken only by the Client Connector profile builder. Nothing was read.")
    try:
        return ops_zcc.check_passwords(raw)
    except ops_zcc.BuilderError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _with_passwords(passwords: Dict[str, str], fn, *args):
    """fn(*args) with the typed passwords in flight for this thread, and the
    passwords dropped when it returns."""
    import ops_zcc
    try:
        with ops_zcc.passwords_in_flight(passwords):
            return fn(*args)
    finally:
        passwords.clear()


def _run_ops_preview(client, req: OperationRequest, scope: Dict[str, Any], label: str, log, cancel) -> Dict[str, Any]:
    import admin_ops
    say = log or (lambda m: None)
    say(f"Previewing on {label}. Nothing is written to the tenant.")
    try:
        prepared = admin_ops.plan(client, req.operation, scope=scope, tenant_label=label, log=say, cancel=cancel)
    except admin_ops.Stopped as e:
        return {"status": "stopped", "stopped": str(e), "tenant_label": label}
    except admin_ops.OperationError as e:
        return {"status": "refused", "message": str(e), "tenant_label": label}
    prepared.update(writes_enabled=writes_enabled(), undo_of=req.undo_of or None, sanction=admin_ops.SANCTION_NOTE)
    say(f"Preview ready: {prepared['counts']['change']} change(s), {prepared['counts']['noop']} already as asked, "
        f"{prepared['counts']['excluded']} excluded.")
    return prepared


def _run_ops_apply(client, creds: Dict[str, str], req: OperationRequest, scope: Dict[str, Any], by: str, actor: Optional[str],
                   log, cancel) -> Dict[str, Any]:
    import admin_ops
    label = tenant_auth.record_label(creds)
    try:
        result = admin_ops.execute(client, req.operation, plan_hash=req.plan_hash, scope=scope, writes_enabled=True,
                                   confirm_text=req.confirm_text, assessor=by, tenant_label=label, log=log, cancel=cancel)
    except admin_ops.OperationError as e:
        return {"status": "refused", "message": str(e), "tenant_label": label}
    result["writes_enabled"] = True
    try:
        rec = admin_ops.record(result, by=by, actor=actor, undo_of=req.undo_of, tenant_ids=_record_ids(creds))
        if rec:
            result["operation_id"] = rec["id"]
    except Exception as e:  # noqa: BLE001 — a bookkeeping failure must not hide what was applied
        result["record_error"] = f"the change was not recorded for undo: {str(e)[:200]}"
    return result


def _ops_apply_gate(req: OperationRequest) -> Tuple[Dict[str, Any], str]:
    """Every refusal before signing in: writer, confirm, plan_hash, the
    assessor, write mode, scope, the record an Undo names."""
    _security.require_writer()
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Applying a bulk change requires explicit confirmation (confirm=true).")
    if not req.plan_hash:
        raise HTTPException(status_code=400, detail="plan_hash is required — preview the operation first.")
    if not isinstance(req.operation, dict) or not req.operation.get("type"):
        raise HTTPException(status_code=400, detail="operation is required (the one that was previewed).")
    by = _ops_assessor(req)
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    scope = _ops_scope(req, req.operation)
    import admin_ops
    if admin_ops.is_undo_only(req.operation) and not req.undo_of:
        raise HTTPException(status_code=409, detail="This is the form of an Undo: it is applied only as the Undo of a recorded operation "
                                                    "(Undo on that operation, then apply its preview). Nothing was written.")
    if req.undo_of:
        import deployments
        rec = deployments.get_operation(req.undo_of)
        if not rec:
            raise HTTPException(status_code=404, detail="The operation to undo is not recorded.")
        if rec.get("undone_by"):
            raise HTTPException(status_code=409, detail=f"This operation was already undone (by {rec['undone_by']}).")
        # An Undo applies exactly the inverse that was recorded and previewed, never
        # another operation under its name (which would also mark this one undone).
        if not rec.get("inverse") or admin_ops._canonical(rec["inverse"]) != admin_ops._canonical(req.operation):
            raise HTTPException(status_code=409, detail="This is not the Undo recorded for that operation: preview its Undo again "
                                                        "and apply that. Nothing was written.")
    return scope, by


@app.post("/api/operations/objects/start")
async def operations_objects_start(req: OperationObjectsRequest, request: Request):
    """List what a bulk change can pick (rules per policy in scope, custom
    URL categories, ZPA segments) as a job. Read-only."""
    import pack_jobs
    scope = _ops_scope(req, req.family)
    creds = _tenant_creds(req)
    _ops_zpa_gate(req.family, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("ops_objects", lambda log, cancel: _keyed(client, _run_ops_objects, client, req.family, scope, label, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/operations/objects")
async def operations_objects(req: OperationObjectsRequest):
    """The same list, waited for (for scripts)."""
    scope = _ops_scope(req, req.family)
    creds = _tenant_creds(req)
    _ops_zpa_gate(req.family, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(_keyed, client, _run_ops_objects, client, req.family, scope, tenant_auth.record_label(creds), None, None)
    if out.get("status") == "refused":
        raise HTTPException(status_code=400, detail=out["message"])
    return out


@app.post("/api/operations/preview/start")
async def operations_preview_start(req: OperationRequest, request: Request):
    """Preview a bulk change as a job: per-item before and after, no-ops and
    exclusions, impact, plan_hash. Reads only; nothing is written."""
    import pack_jobs
    scope = _ops_scope(req, req.operation)
    pw = _ops_passwords(req)
    creds = _tenant_creds(req)
    _ops_zpa_gate(req.operation, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("ops_preview", lambda log, cancel: _with_passwords(pw, _keyed, client, _run_ops_preview, client, req, scope, label, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/operations/preview")
async def operations_preview(req: OperationRequest):
    """The same preview, waited for (for scripts)."""
    scope = _ops_scope(req, req.operation)
    pw = _ops_passwords(req)
    creds = _tenant_creds(req)
    _ops_zpa_gate(req.operation, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(_with_passwords, pw, _keyed, client, _run_ops_preview, client, req, scope, tenant_auth.record_label(creds), None, None)
    if out.get("status") == "refused":
        raise HTTPException(status_code=400, detail=out["message"])
    return out


@app.post("/api/operations/apply/start")
async def operations_apply_start(req: OperationRequest, request: Request):
    """Apply a previewed bulk change as a job the page follows. Needs a
    writer, write mode, confirm=true, the previewed plan_hash (a tenant
    that moved since gives status plan_changed and writes nothing) and,
    above ten changes, the typed phrase. Stop ends the writes; what was
    written is activated, read back and recorded."""
    import pack_jobs
    scope, by = _ops_apply_gate(req)
    pw = _ops_passwords(req)
    creds = _tenant_creds(req)
    _ops_zpa_gate(req.operation, creds)
    if req.undo_of:
        import deployments
        _require_same_tenant(deployments.get_operation(req.undo_of) or {}, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    actor = _actor(request)
    job = pack_jobs.start("ops_apply", lambda log, cancel: _with_passwords(pw, _keyed, client, _run_ops_apply, client, creds, req, scope, by, actor, log, cancel),
                          label=str((req.operation or {}).get("type") or "")[:80], actor=actor, start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/operations/apply")
async def operations_apply(req: OperationRequest, request: Request):
    """The same apply, waited for (for scripts). 409 when the tenant moved
    since the preview or the plan is blocked."""
    scope, by = _ops_apply_gate(req)
    pw = _ops_passwords(req)
    creds = _tenant_creds(req)
    _ops_zpa_gate(req.operation, creds)
    if req.undo_of:
        import deployments
        _require_same_tenant(deployments.get_operation(req.undo_of) or {}, creds)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    actor = _actor(request)
    result = await asyncio.to_thread(_as_actor, actor, _with_passwords, pw, _keyed, client, _run_ops_apply, client, creds, req, scope, by, actor, None, None)
    if result.get("status") in ("plan_changed", "blocked"):
        return JSONResponse(result, status_code=409)
    if result.get("status") == "refused":
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result


@app.get("/api/operations")
async def operations_list(tenant_label: Optional[str] = None):
    """Bulk changes applied from this app (newest first), with Undo where offered."""
    import deployments
    return {"operations": deployments.list_operations(tenant_label), "writes_enabled": writes_enabled()}


@app.get("/api/operations/plugins")
async def operations_plugins():
    """The builder types registered on the Bulk changes engine (admin_ops.register):
    type, label, hint, group and the page script for each; read-only."""
    import admin_ops
    return {"plugins": admin_ops.plugin_catalog()}


class OneTimeKeyRequest(BaseModel):
    """The token a ZPA build's result names for its new provisioning key."""
    token: str = ""


@app.post("/api/operations/zpa/provisioning-key")
async def operations_zpa_provisioning_key(req: OneTimeKeyRequest, request: Request):
    """The provisioning key a ZPA build (ops_zpa) just created, once: held in
    memory only, for ten minutes, for the person who ran the build, and gone
    after this answer. Reaches no tenant; never logged, stored or exported."""
    import ops_zpa
    _security.require_writer()
    got = ops_zpa.reveal(req.token, actor=_actor(request))
    if not got:
        raise HTTPException(status_code=404, detail="No key to show: a provisioning key is shown once, within ten minutes of the build, "
                                                    "to the person who ran it. Copy it from the ZPA Admin Portal instead.")
    return JSONResponse(got, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.get("/api/operations/{op_id}")
async def operations_get(op_id: str):
    """One recorded bulk change: every item with its before, after and status, and its inverse."""
    import deployments
    rec = deployments.get_operation(op_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Operation not found.")
    return {k: v for k, v in rec.items() if k not in ("tenant_key", "tenant_fp")}


async def _ops_undo_inputs(op_id: str, req: OperationCredsRequest):
    import deployments
    rec = deployments.get_operation(op_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Operation not found.")
    if not rec.get("inverse"):
        raise HTTPException(status_code=409, detail="This operation applied nothing that can be reversed.")
    if rec.get("undone_by"):
        raise HTTPException(status_code=409, detail=f"This operation was already undone (by {rec['undone_by']}).")
    body = OperationRequest(**{**req.model_dump(), "operation": rec["inverse"], "undo_of": op_id})
    scope = _ops_scope(body, body.operation)
    creds = _tenant_creds(body)
    _ops_zpa_gate(body.operation, creds)
    _require_same_tenant(rec, creds)
    return body, scope, creds


@app.post("/api/operations/{op_id}/undo/preview/start")
async def operations_undo_preview_start(op_id: str, req: OperationCredsRequest, request: Request):
    """Undo builds the inverse of what the operation applied and previews it
    like any other operation (its own plan_hash and confirmation); it is
    applied through /api/operations/apply with undo_of. Read-only."""
    import pack_jobs
    body, scope, creds = await _ops_undo_inputs(op_id, req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("ops_preview", lambda log, cancel: _keyed(client, _run_ops_preview, client, body, scope, label, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "operation": body.operation, "undo_of": op_id}


@app.post("/api/operations/{op_id}/undo/preview")
async def operations_undo_preview(op_id: str, req: OperationCredsRequest):
    """The same Undo preview, waited for (for scripts)."""
    body, scope, creds = await _ops_undo_inputs(op_id, req)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    out = await asyncio.to_thread(_keyed, client, _run_ops_preview, client, body, scope, tenant_auth.record_label(creds), None, None)
    if out.get("status") == "refused":
        raise HTTPException(status_code=400, detail=out["message"])
    out["operation"] = body.operation
    return out


def _ops_preview_job(job_id: str) -> Dict[str, Any]:
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None or job.kind != "ops_preview":
        raise HTTPException(status_code=404, detail="No such preview. Previews are kept for an hour; preview again.")
    res = job.result or {}
    if not res.get("plan_hash"):
        raise HTTPException(status_code=409, detail="This preview has no plan" + (" yet; it is still running." if job.status == pack_jobs.RUNNING else "."))
    return res


@app.get("/api/operations/jobs/{job_id}/plan.pdf")
async def operations_plan_pdf(job_id: str, page_size: str = "A4"):
    """A finished preview as a printable plan for change approval (pdf_writer)."""
    import report_exports
    res = _ops_preview_job(job_id)
    size = page_size if page_size in ("A4", "Letter") else "A4"
    body = await asyncio.to_thread(report_exports.operation_pdf, res, size)
    return _attachment(body, report_exports.PDF, report_exports.operation_filename(res, "pdf"))


@app.get("/api/operations/jobs/{job_id}/request")
async def operations_request(job_id: str):
    """A finished preview as a request object (kind, title, items with
    before and after, plan_hash) for a shared approval queue."""
    import admin_ops
    return admin_ops.to_request(_ops_preview_job(job_id))


# ── Browser extension (companion) ────────────────────────────────────
BROWSER_EXTENSION_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_extension")


def browser_extension_zip() -> bytes:
    """browser_extension/ as a zip with one folder, ready to unzip and load
    unpacked in Chrome or Edge. Only the extension's own files: no
    symlinks, nothing hidden, nothing outside the folder."""
    import io as _io
    import zipfile as _zip
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(BROWSER_EXTENSION_DIR):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if name.startswith(".") or os.path.islink(full):
                    continue
                rel = os.path.relpath(full, BROWSER_EXTENSION_DIR).replace(os.sep, "/")
                z.write(full, f"zscaler-made-easy-extension/{rel}")
    return buf.getvalue()


@app.get("/api/browser-extension.zip")
async def browser_extension_download():
    """The companion browser extension (browser_extension/): unzip it and
    load it unpacked from chrome://extensions or edge://extensions. It
    holds no credentials; it opens this app's pages."""
    if not os.path.isfile(os.path.join(BROWSER_EXTENSION_DIR, "manifest.json")):
        raise HTTPException(status_code=404, detail="The browser extension is not part of this install.")
    data = await asyncio.to_thread(browser_extension_zip)
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="zscaler-made-easy-extension.zip"'})


class ConsoleIndexRequest(ScopedTenantCredsRequest):
    """Body of the browser extension's console index: which tenant (a saved
    profile, or what this server is configured with) and whether to read
    it again instead of using the last read (kept 30 minutes)."""
    refresh: bool = False


@app.post("/api/console-index")
async def console_index(req: ConsoleIndexRequest):
    """What Zscaler Made Easy knows about each object of the ZIA admin console, for
    the companion extension's badges and side panel: DLP dictionaries,
    engines and rules (what they use, what uses them, the pack that created
    them, findings), and, where in scope, the URL filtering, Cloud App
    Control, SSL inspection, Cloud Firewall and File Type Control rules
    with shadowed-rule findings, the URL categories and the objects those
    rules reference (locations, departments, groups, labels, network
    services, IP groups) with how many rules use each. Read-only; only what
    the Scope page puts in scope is read; the last read per tenant and
    scope is reused for 30 minutes unless `refresh`."""
    import console_index as ci
    zscope = _console_zia_scope(req)
    try:
        channels = _pack_channels_in_scope(req, "The tenant object index (Find anything and the browser extension)")
    except HTTPException as e:
        # No DLP channel in scope: the ZIA policies alone still make an index.
        if e.status_code != 400 or not (zscope["scope"]["read"] or zscope["ftc"]):
            raise
        channels = []
    creds = _tenant_creds(req)
    if not tenant_auth.complete(creds):
        raise HTTPException(status_code=400, detail="Pick a saved tenant (or configure one on this server) for the extension to read.")
    key = ci.cache_key(getattr(req, "profile_id", "") or "", list(channels) + [f"zia:{k}" for k in zscope["scope"]["read"]]
                       + (["zia:ftc"] if zscope["ftc"] else []))
    if not req.refresh:
        hit = ci.cache_get(key)
        # Typed credentials share the "server" key: an index kept for another
        # tenant never answers for this one (it is read again instead).
        if hit is not None and hit.get("tenant_label") and _same_tenant(hit, creds):
            return hit
    client = await asyncio.to_thread(_build_sdk_client, creds) if channels else None
    zia, zia_note = await asyncio.to_thread(_console_zia, req, zscope)
    if not channels and zia is None:
        raise HTTPException(status_code=502, detail=f"Could not read the ZIA policies in scope ({zia_note}).")
    shadow = ci.shadow_by_channel(zia["findings"]) if zia else None
    out = await asyncio.to_thread(lambda: ci.build(client, channels, tenant_label=tenant_auth.record_label(creds), shadow=shadow, zia=zia))
    if out.get("status") != "ready":
        raise HTTPException(status_code=502, detail="; ".join(out.get("blockers") or ["Could not read the tenant."]))
    out["shadow"] = zia_note
    ci.cache_put(key, out)
    return dict(out, cached_at=None)


def _console_zia_scope(req: Any) -> Dict[str, Any]:
    """What the console index may read beyond DLP: the shadowed-rule
    analysis' scope (shadow_rules.scope_for) and whether the File Type
    Control rules are in scope (data_flow.path_scope). Never reads."""
    import data_flow
    import shadow_rules
    sc, ch, _source = _scope_selection(req)
    return {"scope": shadow_rules.scope_for(sc, ch), "ftc": "ftc" in data_flow.path_scope(sc, ch)["read"]}


def _console_zia(req: Any, zscope: Dict[str, Any]):
    """The ZIA part of the console index (console_index.zia_read: the rules
    of every policy in scope, the URL categories, the shadowed-rule
    findings): (read or None, a note). Read-only; only what the Scope page
    allows; a failure leaves the index without it and says why."""
    import console_index as ci
    try:
        if not zscope["scope"]["read"] and not zscope["ftc"]:
            return None, "not in scope"
        raw = _build_client(req)
        res = ci.zia_read(raw, zscope["scope"], ftc=zscope["ftc"])
        return res, f"{len(res.get('findings') or [])} finding(s)"
    except Exception as e:  # noqa: BLE001 - the index is still useful without them
        return None, f"not available: {str(e)[:160]}"


def _cached_index_tenant(profile_id: str, vanity_domain: str, cloud: str, auth_method: str) -> Optional[str]:
    """The tenant label a kept console index must carry to answer the page:
    the sample tenant's or opened snapshot's, the saved profile's (as it is
    now, so an edited profile never gets its old tenant's index), the typed
    OneAPI sign-in's (vanity domain and cloud), else the server's own
    tenant. None (nothing answers) for a profile that is gone and for a
    typed classic-API sign-in, whose label cannot tell two classic tenants
    on one cloud apart (its admin login is never sent in a URL): Load
    tenant objects reads and checks it instead. Never reads the tenant."""
    off = _offline_creds()
    if off:
        return tenant_auth.record_label(off)
    if (profile_id or "").strip():
        import tenant_profiles
        prof = tenant_profiles.get(profile_id.strip())
        return tenant_auth.record_label(tenant_profiles.creds_from(prof)) if prof else None
    try:
        method = tenant_auth.normalize_method(auth_method)
    except ValueError:
        raise HTTPException(status_code=400, detail="auth_method must be oneapi or legacy.")
    if method == tenant_auth.LEGACY:
        return None
    if (vanity_domain or "").strip():
        return tenant_auth.record_label({"vanity_domain": validate_vanity(vanity_domain.strip()),
                                         "cloud": validate_cloud(cloud.strip()) if (cloud or "").strip() else "", "auth_method": method})
    env = tenant_auth.from_env()
    return tenant_auth.record_label(env) if tenant_auth.complete(env) else None


@app.get("/api/console-index/cached")
async def console_index_cached(profile_id: str = "", vanity_domain: str = "", cloud: str = "", auth_method: str = ""):
    """The last console index this server read for a tenant profile (or for
    the server's own tenant), whatever scope it was read with, while it is
    kept (30 minutes), and only when it was read for the tenant the page
    is signed in to (typed sign-ins of every tenant share one bucket; a
    profile may have been edited since). Never reads the tenant: Find
    anything searches it as you type, and only its Load tenant objects
    button reads (POST /api/console-index, with the Scope page's selection)."""
    import console_index as ci
    label = _cached_index_tenant(profile_id, vanity_domain, cloud, auth_method)
    hit = ci.cache_latest(profile_id, tenant_label=label) if label else None
    return {"index": hit, "profile_id": profile_id or ""}


# ── Workspace notes: tags, comments and to-dos on any object ──────────────
# Local notes in this app's own store (workspace_notes.py), per tenant label;
# never a tenant write. Every call needs the UI token like every other
# (security.UIAuthMiddleware); who wrote a note is the server's view of the
# caller (_actor), never a name the page sends; every change is in the audit
# log. The browser extension may read notes (GET) but never write them: these
# paths are not in security.EXTENSION_POST_PATHS.
class WorkspaceNoteRequest(BaseModel):
    """One change to the note on (tenant, kind, ref). The tenant is its
    label, or the saved profile / sign-in it belongs to (no secret is sent)."""
    tenant: str = ""
    profile_id: str = ""
    vanity_domain: str = ""
    cloud: str = ""
    auth_method: str = ""
    kind: str = ""
    ref: str = ""
    label: str = ""
    href: str = ""
    action: str = ""
    tags: List[str] = []
    tag: str = ""
    text: str = ""
    item_id: str = ""
    done: bool = True


def _notes_tenant(tenant: str = "", profile_id: str = "", vanity_domain: str = "", cloud: str = "", auth_method: str = "") -> str:
    """The tenant label a note is kept under: the one given, else the sample
    tenant's or opened snapshot's (this browser's offline tenant), else the
    saved profile's, else the sign-in's (vanity domain and cloud), else this
    server's configured tenant. Never reads the tenant."""
    import tenant_profiles
    import workspace_notes as wn
    if (tenant or "").strip():
        return wn.clean_tenant(tenant)
    creds: Dict[str, Any] = {}
    off = _offline_creds()   # the sample tenant or an opened snapshot: its notes are its own, never a profile's or the server's
    if off:
        creds = off
    elif (profile_id or "").strip():
        p = tenant_profiles.get(profile_id.strip())
        if not p:
            raise wn.NotesError("that tenant profile no longer exists; pick another", 404)
        creds = tenant_profiles.creds_from(p)
    elif (vanity_domain or "").strip() or (auth_method or "").strip().lower() in ("legacy", "classic"):
        creds = {"vanity_domain": vanity_domain, "cloud": cloud, "auth_method": auth_method}
    else:
        env = tenant_auth.from_env()
        if not tenant_auth.complete(env):
            raise wn.NotesError("pick a tenant first: notes are kept per tenant")
        creds = env
    try:
        return wn.clean_tenant(tenant_auth.record_label(creds))
    except ValueError as e:
        raise wn.NotesError(str(e)[:200])


def _notes_call(fn, *args, **kwargs):
    import workspace_notes as wn
    try:
        return fn(*args, **kwargs)
    except wn.NotesError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


@app.get("/api/workspace/notes")
async def workspace_notes_get(tenant: str = "", profile_id: str = "", vanity_domain: str = "", cloud: str = "", auth_method: str = "",
                              kind: str = "", ref: str = "", tag: str = "", all_tenants: bool = False):
    """The note on one object (kind and ref given), or every note of a
    tenant (optionally with one tag), or with all_tenants every note of
    every tenant, for the To-do list. Read-only, local."""
    import workspace_notes as wn
    if all_tenants:
        return {"tenant": None, "notes": _notes_call(wn.list_notes, None, tag=tag), "tenants": wn.tenants(), "limits": _notes_limits()}
    label = _notes_call(_notes_tenant, tenant, profile_id, vanity_domain, cloud, auth_method)
    if kind or ref:
        return {"tenant": label, "note": _notes_call(wn.get, label, kind, ref), "limits": _notes_limits()}
    return {"tenant": label, "notes": _notes_call(wn.list_notes, label, tag=tag), "limits": _notes_limits()}


def _notes_limits() -> Dict[str, int]:
    import workspace_notes as wn
    return {"tags": wn.MAX_TAGS, "tag_length": wn.MAX_TAG_LEN, "comment_length": wn.MAX_COMMENT_LEN, "todo_length": wn.MAX_TODO_LEN,
            "comments": wn.MAX_COMMENTS, "todos": wn.MAX_TODOS, "notes_per_tenant": wn.MAX_NOTES_PER_TENANT}


@app.post("/api/workspace/notes")
async def workspace_notes_post(req: WorkspaceNoteRequest, request: Request):
    """Add or remove a tag, a comment or a to-do on one object, or tick a
    to-do done. A local write to this app's store, recorded with who made it."""
    import workspace_notes as wn
    label = _notes_call(_notes_tenant, req.tenant, req.profile_id, req.vanity_domain, req.cloud, req.auth_method)
    note = _notes_call(wn.apply, label, req.kind, req.ref, req.action, by=_cq_by(request), label=req.label, href=req.href,
                       tags=req.tags, tag=req.tag, text=req.text, item_id=req.item_id, done=req.done)
    return {"tenant": label, "note": note}


@app.delete("/api/workspace/notes")
async def workspace_notes_delete(request: Request, kind: str, ref: str, tenant: str = "", profile_id: str = "",
                                 vanity_domain: str = "", cloud: str = "", auth_method: str = ""):
    """Remove every tag, comment and to-do on one object."""
    import workspace_notes as wn
    label = _notes_call(_notes_tenant, tenant, profile_id, vanity_domain, cloud, auth_method)
    gone = _notes_call(wn.delete, label, kind, ref, by=_cq_by(request))
    if not gone:
        raise HTTPException(status_code=404, detail="There is no note on this object.")
    return {"tenant": label, "deleted": True}


@app.get("/report/todo")
async def report_todo_page():
    """Standalone tab for the To-do list (static/report_todo.html)."""
    page = os.path.join(STATIC_DIR, "report_todo.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


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


# The operator's Stop for the tenant API watch (POST /api/beacon/stop):
# checked before every endpoint and inside a request, so nothing more is
# read once it is set (user rule 4). Cleared when a run starts.
_BEACON_STOP = threading.Event()


def _beacon_run_locked(online: bool, trigger: str, client: Any = None, label: str = "",
                       scope: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """One Beacon run by a caller that already holds beacon.RUN_LOCK; the
    lock is released here, whatever happens. Keeps the timer state. A
    tenant watch reads only `scope`'s endpoints (beacon_scope.select)."""
    import beacon
    _BEACON_STATE.update({"running": True, "running_since": datetime.now(timezone.utc).isoformat(timespec="seconds"), "running_trigger": trigger})
    try:
        if client is not None:
            snap = beacon.run(online=online, tenant_client=client, tenant_label=label, trigger=trigger, tenant_scope=scope,
                              stop=_BEACON_STOP.is_set)
        else:
            snap = beacon.run(online=online, tenant_client=None, tenant_label=label, trigger=trigger)
        problem = beacon.watch_problem(snap.get("tenant"))   # read nothing: error; stopped early: partial
        if snap.get("error"):
            status, err = "error", snap["error"]
        elif problem:
            status, err = problem
        else:
            status, err = "ok", None
        _BEACON_STATE.update({"last_status": status, "last_error": err})
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


def _beacon_start_background(online: bool, trigger: str, client: Any = None, label: str = "",
                             scope: Optional[Dict[str, Any]] = None) -> bool:
    """Start a run on its own thread; False when one is already running."""
    import beacon
    import threading
    if not beacon.RUN_LOCK.acquire(blocking=False):
        return False
    _BEACON_STOP.clear()   # a Stop meant for an earlier run never ends this one
    try:
        threading.Thread(target=_beacon_run_locked, args=(online, trigger, client, label, scope), name="beacon-run", daemon=True).start()
    except Exception:
        beacon.RUN_LOCK.release()
        raise
    return True


def _beacon_running() -> bool:
    """Whether a Beacon run is in progress. A status read samples this
    before it loads the history: a run that saves its snapshot and ends
    while the history is read would otherwise be reported finished with
    the history from before it (a poller then stops on a missing run)."""
    import beacon
    return bool(_BEACON_STATE["running"] or beacon.RUN_LOCK.locked())


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
    SDK and the committed Terraform only). `tenant_watch` also GETs, from
    the tenant the credentials name (blank fields fall back to the saved
    profile, the environment or tenant_config.json, like every tenant
    call), only the endpoints that belong to what is in scope: `scopes`
    (the Scope page's ticked .scope-cb keys) and `channels` (its channel
    declaration; only "zscaler" counts). When the body carries neither,
    the profile's saved scopes and channels are used, unless `from_page`
    says the Scope page's ticks are known (then empty is empty); with
    nothing in scope the watch is refused (400), never widened to every
    endpoint."""
    online: bool = True
    tenant_watch: bool = False
    customer_id: str = ""   # ZPA endpoints are probed only with one
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False   # the Scope page's ticks are known: nothing ticked is nothing in scope


class BeaconScopeRequest(TenantCredsRequest):
    """Body of POST /api/beacon/scope: the same selection and credential
    fields as a run, so the preview judges the sign-in the run will use."""
    customer_id: str = ""
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


def _beacon_readable(sel: Dict[str, Any], req: Any) -> None:
    """400 when the sign-in these credentials resolve to (without signing
    in) can read none of the endpoints in scope: the classic ZIA API
    sign-in with only non-ZIA scopes, or only ZPA without a customer id."""
    import beacon_scope
    try:
        creds = _tenant_creds(req)
    except Exception:  # noqa: BLE001 — bad credentials are refused by the sign-in itself
        return
    why = beacon_scope.nothing_readable(sel, creds.get("auth_method") == tenant_auth.LEGACY, creds.get("customer_id") or "")
    if why:
        raise HTTPException(status_code=400, detail=why)


def _beacon_scope(scopes: Any, channels: Any, profile_id: str = "", from_page: bool = False) -> Dict[str, Any]:
    """What the tenant API watch would read: the page's selection, else
    (only when the page sent nothing at all and does not know the Scope
    page's ticks) the saved profile's. The two are never mixed, so the
    profile cannot widen what the page chose, and every scope unticked on
    the Scope page is nothing in scope, not the profile's selection.
    Raises HTTPException 400 when nothing is in scope. Never reads a
    tenant."""
    import beacon_scope
    src = []
    sc = beacon_scope.normalize_scopes(scopes)
    ch = _channel_declaration(channels)
    if sc or ch or from_page:
        src.append("the Scope page")
    elif profile_id:
        try:
            import tenant_profiles
            prof = tenant_profiles.get(profile_id) or {}
        except Exception:  # noqa: BLE001 — an unreadable profile store is no selection
            prof = {}
        sc = beacon_scope.normalize_scopes(prof.get("scopes"))
        ch = _channel_declaration(prof.get("channels"))
        if sc or ch:
            src.append(f"the saved profile {prof.get('name') or profile_id}")
    if not sc and not ch:
        raise HTTPException(status_code=400, detail=beacon_scope.NOTHING_IN_SCOPE)
    sel = beacon_scope.select(sc, ch)
    sel["source"] = " and ".join(src)
    if not sel["endpoints"]:
        chosen = sel["summary"].split(" for ", 1)[-1] if sel["scopes"] else ""
        raise HTTPException(status_code=400, detail=beacon_scope.NOTHING_IN_SCOPE + (
            f" What is chosen ({chosen}) reads no tenant endpoint the watch covers." if chosen else ""))
    return sel


@app.get("/api/beacon")
async def beacon_get():
    """The latest Beacon snapshot, what changed since the run before it,
    the history (newest first) and the timer."""
    import beacon
    running = _beacon_running()   # before the read: a run that ends during it still says running, so the page reads again
    history = await asyncio.to_thread(beacon.load_history)
    latest = history[-1] if history else None
    return {"latest": latest, "diff": (latest or {}).get("diff"), "history": beacon.history_rows(history),
            "running": running or _beacon_running(), "running_since": _BEACON_STATE["running_since"],
            "timer": _beacon_timer(), "state_file": beacon.state_path(), "keep": beacon.HISTORY_KEEP}


@app.get("/api/beacon/status")
async def beacon_status(refresh: bool = False):
    """Short form for a notice: SDK / API / Terraform drift confirmed by two
    consecutive comparable runs, the current count, changes since the
    previous run and where the details are. A first detection stays on the
    Beacon details page but does not raise the global banner.
    Reads the kept snapshot only; `refresh` starts an online run in the
    background when the newest online one is over an hour old."""
    import beacon
    running = _beacon_running()   # before the read, as GET /api/beacon
    history = await asyncio.to_thread(beacon.load_history)
    started = False
    if refresh:
        age = _beacon_last_online_age(history)
        if age is None or age > _BEACON_STATUS_REFRESH_SECONDS:
            started = _beacon_start_background(True, "status")
    latest = history[-1] if history else None
    online = next((s for s in reversed(history) if s.get("online")), None)
    diff = (latest or {}).get("diff") or {}
    source = online or latest or {}
    current = source.get("drift") or []
    # Snapshots written before persistence gating have no such field. Do not
    # resurrect their one-run findings as banners after an upgrade.
    drift = source.get("persistent_drift") or []
    import hashlib
    key = hashlib.sha256("\n".join(sorted(f"{d.get('watcher')}|{d.get('text')}" for d in drift)).encode("utf-8")).hexdigest()[:16] if drift else ""
    return {"at": (latest or {}).get("at"), "online_at": (online or {}).get("at"), "drift": drift, "drift_key": key,
            "current_drift": len(current), "pending_confirmation": max(0, len(current) - len(drift)),
            "changes": len(diff.get("changes") or []), "summary": (diff.get("summary") or [None])[0],
            "running": running or _beacon_running(), "started": started, "details": "/report/beacon",
            "next_run_at": _BEACON_STATE.get("next_run_at")}


@app.post("/api/beacon/run")
async def beacon_run(req: BeaconRunRequest):
    """Start a Beacon run in the background; GET /api/beacon shows it when
    it is done. With `tenant_watch`, what is in scope is worked out first
    (nothing in scope: 400, before any sign-in), then the credentials are
    checked and signed in (a refusal is answered here, secrets masked) and
    the tenant is only read: GET, about one request a second, and only
    the endpoints in scope."""
    import beacon
    import beacon_scope
    if _BEACON_STATE["running"] or beacon.RUN_LOCK.locked():
        raise HTTPException(status_code=409, detail=f"A Beacon run is already in progress (started {_BEACON_STATE.get('running_since') or 'just now'}); wait for it to finish.")
    client, label, sel = None, "", None
    if req.tenant_watch:
        sel = await asyncio.to_thread(_beacon_scope, req.scopes, req.channels, req.profile_id, req.from_page)
        await asyncio.to_thread(_beacon_readable, sel, req)   # nothing readable with this sign-in: 400, no sign-in
        client = await asyncio.to_thread(_build_client, req)   # validates every field; 400/401 without echoing a secret
        label = tenant_auth.record_label(_tenant_creds(req))   # never the classic API's admin login (user rule 3)
    if not _beacon_start_background(bool(req.online), "manual", client, label, sel):
        if client is not None:
            client.close()
        raise HTTPException(status_code=409, detail="A Beacon run is already in progress; wait for it to finish.")
    return {"started": True, "online": bool(req.online), "tenant_watch": bool(req.tenant_watch), "tenant": label or None,
            "endpoints": len(sel["endpoints"]) if sel else 0,
            "scope": beacon_scope.describe(sel, sel["source"]) if sel else None}


@app.post("/api/beacon/stop")
async def beacon_stop():
    """Stop the running tenant API watch: no further endpoint is read and
    a request waiting out ZIA's rate limit is not sent. What was read is
    kept as a watch that stopped early. The upstream watchers are not
    tenant reads and finish on their own."""
    import beacon
    running = bool(_BEACON_STATE["running"] or beacon.RUN_LOCK.locked())
    if running:
        _BEACON_STOP.set()
    return {"stopping": running, "running": running}


@app.post("/api/beacon/scope")
async def beacon_scope_preview(req: BeaconScopeRequest):
    """What the tenant API watch would read for this selection (the Scope
    page's, else the profile's): how many endpoints, for which scopes and
    channels, and which are not in scope. The same checks as a run with
    the same body, including whether the sign-in it resolves to (typed,
    profile, environment or tenant_config.json; never signed in to) can
    read any of it. Reads no tenant."""
    import beacon_scope
    try:
        sel = await asyncio.to_thread(_beacon_scope, req.scopes, req.channels, req.profile_id, req.from_page)
        await asyncio.to_thread(_beacon_readable, sel, req)
    except HTTPException as e:
        return {"ok": False, "detail": e.detail, "endpoints": 0}
    return {"ok": True, **beacon_scope.describe(sel, sel["source"])}


# ── Traffic insights (ZIA Insights, the Z-Insights GraphQL API) ─────────
# Read-only traffic numbers (insights.py), only with ZIA Insights ticked on
# the Scope page and a OneAPI sign-in; both refused (400) before signing in.
class InsightsRequest(ScopedTenantCredsRequest):
    """Body of POST /api/insights/start and /api/insights: the window (a
    preset such as "7d", or start_ms and end_ms in epoch milliseconds),
    the traffic unit (TRANSACTIONS or BYTES) and whether to ask for the
    users with the most security incidents (shown on screen only)."""
    window: str = "7d"
    start_ms: Optional[int] = None
    end_ms: Optional[int] = None
    traffic_unit: str = "TRANSACTIONS"
    include_users: bool = True


def _insights_inputs(req: InsightsRequest) -> Dict[str, Any]:
    """Scope, sign-in method, window and unit checked, in that order,
    before anything is signed in to (user rule 1). Returns {creds, window,
    unit, label, source}."""
    import insights
    sel = _require_in_scope(req, "insights", "Traffic insights")
    creds = _tenant_creds(req)
    if tenant_auth.normalize(creds)["auth_method"] == tenant_auth.LEGACY:
        raise HTTPException(status_code=400, detail=insights.LEGACY_REFUSED)
    try:
        win = insights.window(req.window, req.start_ms, req.end_ms)
    except insights.WindowError as e:
        raise HTTPException(status_code=400, detail=f"{e} Nothing was read.")
    unit = str(req.traffic_unit or "TRANSACTIONS").strip().upper()
    if unit not in insights.TRAFFIC_UNITS:
        raise HTTPException(status_code=400, detail="Traffic unit must be TRANSACTIONS or BYTES. Nothing was read.")
    return {"creds": creds, "window": win, "unit": unit, "label": tenant_auth.record_label(creds), "source": sel["source"]}


def _run_insights(client, req: InsightsRequest, inp: Dict[str, Any], log, cancel) -> Dict[str, Any]:
    """The Insights read, shared by the job and the waiting endpoint. Stop
    ends it as stopped with no partial result. The kept report (exports)
    never holds the per-user rows."""
    import insights
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    win = inp["window"]
    if inp.get("source"):
        _log(f"In scope, from {inp['source']}: ZIA Insights (traffic data), {win['label']}.")
    try:
        out = insights.read(client, win["start_ms"], win["end_ms"], traffic_unit=inp["unit"], include_users=bool(req.include_users),
                            log=_log, cancel=cancel, scrub=lambda s: tenant_auth.mask_secrets(s, inp["creds"]))
    except insights.Stopped as e:
        return {"stopped": str(e), "status": "stopped", "tenant_label": inp["label"], "logs": logs}
    finally:
        _close_quietly(client)
    out["window"]["label"] = win["label"]
    out["tenant_label"] = inp["label"]
    out["report_id"] = _remember_report("insights", insights.exportable(out), inp["label"])
    out["logs"] = logs
    return out


@app.get("/report/insights")
async def report_insights_page():
    """Standalone tab for Traffic insights (static/report_insights.html)."""
    page = os.path.join(STATIC_DIR, "report_insights.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.post("/api/insights/start")
async def insights_start(req: InsightsRequest, request: Request):
    """Start the Traffic insights read as a job the page follows (poll GET
    /api/dlp-packs/jobs/{job_id}); Stop ends it with nothing more asked.
    Refused (400) before sign-in when ZIA Insights is not in scope, the
    sign-in is the classic ZIA API, or the window is not one Insights takes."""
    import pack_jobs
    inp = _insights_inputs(req)
    client = await asyncio.to_thread(_build_sdk_client, inp["creds"])
    job = pack_jobs.start("insights", lambda log, cancel: _run_insights(client, req, inp, log, cancel), label=inp["window"]["label"],
                          actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/insights")
async def insights_run(req: InsightsRequest):
    """The same read, waited for (for scripts)."""
    inp = _insights_inputs(req)
    client = await asyncio.to_thread(_build_sdk_client, inp["creds"])
    return await asyncio.to_thread(_run_insights, client, req, inp, None, None)


@app.get("/api/insights/export/{report_id}")
async def insights_export(report_id: str, format: str = "csv"):
    """A kept Traffic insights read as CSV (csv_safe) or JSON, without the
    per-user rows, which are shown on screen only."""
    import insights
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("insights-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    if (format or "").lower() == "json":
        return Response(content=json.dumps(insights.exportable(rep), indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_insights_{ts}.json"})
    return Response(content=insights.to_csv(rep), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_insights_{ts}.csv"})


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


_QUALITY_SCORE_JSON = os.path.join(_APP_DIR, "docs", "quality_score.json")
_QUALITY_SCORE_MD = os.path.join(_APP_DIR, "docs", "QUALITY_SCORE.md")
_QUALITY_SCORE_MAX_BYTES = 4 * 1024 * 1024


def _quality_score_bytes(path: str) -> Optional[bytes]:
    """A generated score file's bytes, or None when it is missing, not a
    regular file (a link or a device is refused) or larger than the cap."""
    import stat as _stat
    try:
        if not _stat.S_ISREG(os.lstat(path).st_mode):
            return None
        with open(path, "rb") as f:
            raw = f.read(_QUALITY_SCORE_MAX_BYTES + 1)
    except OSError:
        return None
    return raw if len(raw) <= _QUALITY_SCORE_MAX_BYTES else None


@app.get("/api/quality-score")
async def quality_score():
    """This app's quality and security score (docs/quality_score.json, built
    by tools/quality_score.py from the QA findings records, the last full
    test run and the standards mapping). Read-only; reads no tenant. A
    missing or unreadable file is {"available": false}, never an error."""
    raw = _quality_score_bytes(_QUALITY_SCORE_JSON)
    if raw is None:
        return {"available": False, "reason": "No score yet: docs/quality_score.json is not there. Build it with python tools/quality_score.py."}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        data = None
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return {"available": False, "reason": "No score yet: docs/quality_score.json could not be read. Rebuild it with python tools/quality_score.py."}
    return {**data, "available": True}


@app.get("/api/quality-score/report.md")
async def quality_score_report():
    """docs/QUALITY_SCORE.md as plain text (never rendered as HTML), read-only."""
    raw = _quality_score_bytes(_QUALITY_SCORE_MD)
    if raw is None:
        raise HTTPException(status_code=404, detail="No score report yet: build it with python tools/quality_score.py.")
    return Response(content=raw, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": 'inline; filename="QUALITY_SCORE.md"', "Cache-Control": "no-store"})


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
async def serve_permissions_page(request: Request):
    """Standalone HTML view of the Required API Access catalog.
    Renders the same data as /api/permissions/required but as a full
    page so the GUI's quick-link button can target="_blank" and open
    it in a new browser tab (per user request).

    The page is reachable without the UI token (security._UI_AUTH_EXEMPT_PATHS),
    so its live readiness part (a tenant's name, roles and licences) is
    rendered only for a caller who passes the token or sign-in gate
    (security.ui_request_ok); anyone else gets the catalogue alone."""
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
    import readiness as _rd
    signed_in = _security.ui_request_ok(request)   # deny by default: no tenant data on a public page
    latest = _readiness_latest() if signed_in else []
    live_html = _rd.html_section(latest, locked=not signed_in)
    verdict = {f["key"]: f for f in (latest[0].get("scopes") or [])} if latest else {}
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
          {_rd.scope_badge(verdict.get(key))}
        </section>
        """)

    portal = data.get("portal_url", "https://admin.zidentity.net/")
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Required API access · Zscaler Made Easy</title>
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
  .grid {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 1rem; margin-bottom: 0.6rem; }}
  @media (max-width: 720px) {{ .grid {{ grid-template-columns: minmax(0, 1fr); }} }}
  /* Reflow (WCAG 1.4.10): a long permission or endpoint path breaks inside its column at 320px. */
  .perms code, .endpoint, .scope-key {{ overflow-wrap: anywhere; }}
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
  .rd {{ margin-bottom: 1.5rem; }}
  .rd h2 {{ font-size: 1.25rem; margin-bottom: 0.3rem; }}
  .rd h3 {{ font-size: 1.05rem; margin-bottom: 0.4rem; }}
  .rd h4 {{ font-size: 0.92rem; margin: 0.8rem 0 0.35rem; }}
  .rd-card {{ border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: 0.8rem; }}
  .rd-wrap {{ overflow-x: auto; max-width: 100%; margin: 0.5rem 0; }}
  .rd-t {{ width: 100%; border-collapse: collapse; font-size: 0.84rem; }}
  .rd-t caption {{ text-align: left; color: var(--dim); font-size: 0.8rem; padding-bottom: 0.3rem; }}
  .rd-t th, .rd-t td {{ text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  .rd-t thead th {{ color: var(--dim); font-size: 0.75rem; }}
  .rd-chip {{ display: inline-block; font-size: 0.74rem; font-weight: 700; padding: 0.05rem 0.45rem; border-radius: 999px; border: 1px solid var(--border); white-space: nowrap; }}
  .rd-chip.none, .rd-chip.blocked, .rd-chip.not_licensed {{ border-color: var(--warn); background: color-mix(in srgb, var(--warn) 18%, transparent); }}
  .rd-chip.read_only, .rd-chip.partial {{ border-color: var(--warn); }}
  .rd-chip.write, .rd-chip.read {{ border-color: var(--accent); }}
  .rd-kind {{ color: var(--dim); font-size: 0.75rem; margin-left: 0.4rem; }}
  .rd-gaps {{ list-style: none; font-size: 0.86rem; }}
  .rd-gaps li {{ border-left: 3px solid var(--warn); padding: 0.35rem 0.6rem; margin-bottom: 0.4rem; }}
  .rd-note, .rd-flags, .rd-empty, .rd-ok {{ color: var(--dim); font-size: 0.84rem; margin: 0.3rem 0; }}
  .rd-steps summary {{ cursor: pointer; color: var(--accent); font-size: 0.82rem; margin-top: 0.2rem; }}
  .rd-steps ol {{ margin: 0.3rem 0 0 1.3rem; font-size: 0.82rem; }}
  .rd-badge {{ margin-top: 0.5rem; padding: 0.45rem 0.6rem; border-left: 3px solid var(--border); border-radius: 4px; font-size: 0.82rem; }}
  .rd-badge.bad {{ border-left-color: var(--warn); background: color-mix(in srgb, var(--warn) 8%, transparent); }}
  .rd-badge.good {{ border-left-color: var(--accent); }}
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
  <h1><span class="accent">Required API access</span> per assessment scope</h1>
  <p class="lead">What this API client can do right now (from the last readiness check), then the minimum OneAPI role permissions to grant before running each assessment scope. All checks are read-only.</p>
  <div class="notes">
    <h2>Before you start</h2>
    <ol>{notes_html}</ol>
    <p style="margin-top:0.5rem;font-size:0.88rem;">
      <strong>ZIdentity admin portal:</strong>
      <a href="{esc(portal)}" target="_blank" rel="noopener noreferrer" class="portal-link">{esc(portal)} ↗</a>
    </p>
  </div>
  {live_html}
  {''.join(cards_html)}
</main>
</body>
</html>"""
    from fastapi.responses import HTMLResponse
    # With live answers in it the page carries tenant data: never kept in a cache.
    return HTMLResponse(content=page, headers={"Cache-Control": "no-store" if latest else "no-cache, must-revalidate"})


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
        import readiness as _rd
        out["readiness"] = _rd.catalog()
        out["partial_note"] = ("A client that lacks a permission does not stop the tool: the checks, report sections and plan items it "
                               "cannot read are marked as not permitted and everything else runs. The assessment results list what a "
                               "full scan would need; a preflight lists what a verified plan would need.")
    except Exception:  # noqa: BLE001
        pass
    return out


# ── Readiness: what this API client can do here (readiness.py) ─────────────────
# Shown on Start right after sign-in and, in full, on Required API access
# (/permissions). The token is decoded for display only; reads are only for
# what is in scope; the latest answers are kept in memory, never on disk.
READINESS_WHAT = "The readiness check"
import collections as _collections
_READINESS: "_collections.OrderedDict[str, Dict[str, Any]]" = _collections.OrderedDict()
_READINESS_MAX = 8


def _readiness_token_access(client: Any, method: str) -> Dict[str, Any]:
    """The sign-in token's products and role names (readiness.token_access); never raises."""
    try:
        import readiness
        return readiness.token_access(client, method)
    except Exception:  # noqa: BLE001 — display only: a failure here never fails the sign-in
        return {"ok": False, "why": "The access token could not be read.", "products": [], "scopes": []}


def _readiness_latest() -> List[Dict[str, Any]]:
    """The latest readiness answers, newest first (memory only)."""
    return [dict(v) for v in reversed(list(_READINESS.values()))]


class ReadinessRequest(ScopedTenantCredsRequest):
    """Tenant credentials and the Scope page selection: readiness reads only
    the products in scope (else 400 before sign-in). `customer_id` is the
    ZPA customer ID (ZPA roles are read only with one)."""
    customer_id: str = ""


@app.post("/api/readiness/start")
async def readiness_start(req: ReadinessRequest, request: Request):
    """Start the readiness check as a job the page follows: the access
    token's products and roles (decoded, not verified), then for the
    products in scope only the ZIA licences and API role, Client Connector
    company info and roles, ZPA roles, and one ZDX and one Z-Insights call.
    Read-only. Refused (400) before sign-in when nothing it reads is in
    scope. Poll GET /api/dlp-packs/jobs/{job_id}."""
    import pack_jobs
    import readiness
    sc, _ch, _src = _scope_selection(req)   # user rule 1: nothing read out of scope
    if not readiness.in_scope_products(sc):
        raise HTTPException(status_code=400, detail=f"{READINESS_WHAT} is not in scope: on the Scope page tick at least one of DLP, ZIA platform, "
                                                    "ZPA, ZCC, ZDX or ZIA Insights, then run it again. Nothing was read.")
    creds = _tenant_creds(req)
    creds["customer_id"] = validate_customer_id(req.customer_id) if req.customer_id else (creds.get("customer_id") or "")
    label = tenant_auth.record_label(creds)
    method = creds["auth_method"]
    client = await asyncio.to_thread(_build_sdk_client, creds)

    def fn(log, cancel):
        try:
            out = readiness.run(client, sc, auth_method=method, customer_id=creds.get("customer_id", ""), log=log, cancel=cancel, label=label)
        finally:
            _close_quietly(client)
        if out.get("status") == "done":
            _READINESS.pop(label, None)
            _READINESS[label] = out
            while len(_READINESS) > _READINESS_MAX:
                _READINESS.popitem(last=False)
        return out
    job = pack_jobs.start("readiness", fn, label="Readiness check", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/readiness/latest")
async def readiness_latest():
    """The latest readiness answers this server holds (memory only, newest
    first, at most 8 tenants). No tenant call."""
    return {"results": _readiness_latest()}


@app.get("/api/readiness/catalog")
async def readiness_catalog():
    """What every Scope page key and every write feature needs: product,
    ZIA permission and licence (readiness.catalog). No tenant call."""
    import readiness
    return readiness.catalog()


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
        if getattr(sys, "frozen", False):
            raise LookupError("the standalone edition has no .git: the build records its commit")
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
    if commit == "unknown" and (in_container or getattr(sys, "frozen", False)):
        # No .git in the image or the standalone edition: the build records its commit instead.
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
# Same as UPDATE_Zscaler_Made_Easy.bat, without a command prompt: pull
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
    if app_update.in_container() or app_update.in_standalone():
        raise HTTPException(status_code=409, detail=app_update.CONTAINER_UPDATE_HELP if app_update.in_container() else app_update.STANDALONE_UPDATE_HELP)
    target = _update_branch(req.branch if req else None)
    result = await asyncio.to_thread(app_update.update, _APP_DIR, branch=target)
    _LATEST.pop(target, None)
    # The app's own code changed (or tried to): the audit log says who, which
    # branch, from which build to which, and whether it worked.
    _audit.record("app_update", actor=_security.current_actor(), branch=target, ok=bool(result.get("ok")),
                  updated=bool(result.get("updated")), before=result.get("before"), after=result.get("after"))
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

    # Only a scope the catalogue knows names the file: anything else exported every check, and a
    # caller's text never goes into the Content-Disposition header (non-Latin-1 text there was a 500).
    suffix = scope if scope in ("dlp", "zia", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac") else "all"
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
        lines = [f"# Zscaler Made Easy Checks ({suffix})\n",
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
        import io
        import csv_safe
        buf = io.StringIO()
        # Determine all framework keys
        fw_keys = []
        try:
            from compliance_mapping import FRAMEWORK_DESCRIPTIONS
            fw_keys = sorted(FRAMEWORK_DESCRIPTIONS.keys())
        except Exception:
            pass
        writer = csv_safe.writer(buf)
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
    data = await _json_object(request)
    results = _check_rows(data, "No checks in request body")
    _require_report_size(results)
    return await asyncio.to_thread(get_framework_summary, results)


@app.post("/api/compliance/drilldown")
async def compliance_drilldown(request: Request):
    """Return per-control drilldown showing met/partially met/not met with evidence."""
    try:
        from compliance_mapping import get_control_drilldown
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"compliance_mapping not available: {e}")
    data = await _json_object(request)
    results = _check_rows(data, "No checks in request body")
    _require_report_size(results)
    return await asyncio.to_thread(get_control_drilldown, results)


@app.post("/api/compliance/report")
async def compliance_report(request: Request):
    """Remember an assessment's compliance view so it can open in its own
    tab (/report/compliance?id=...): the framework summary, the control
    drilldown and the frameworks the assessment page had selected."""
    try:
        from compliance_mapping import get_framework_summary, get_control_drilldown, FRAMEWORK_DESCRIPTIONS
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"compliance_mapping not available: {e}")
    data = await _json_object(request)
    results = _check_rows(data, "No checks in request body")
    selected = [str(k) for k in (data.get("frameworks") or []) if str(k) in FRAMEWORK_DESCRIPTIONS]
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    _require_report_size(results)
    summary, drilldown = await asyncio.to_thread(lambda: (get_framework_summary(results), get_control_drilldown(results)))
    rep = {"summary": summary, "drilldown": drilldown,
           "descriptions": dict(FRAMEWORK_DESCRIPTIONS), "frameworks_selected": selected,
           "check_count": len(__import__("channel_scope").visible(results)[0]),   # checks outside the scope are hidden
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
        import io
        import csv_safe
        buf = io.StringIO(); w = csv_safe.writer(buf)
        w.writerow(["framework", "control", "status", "passing", "failing", "review", "not_applicable", "evidence_check_ids"])
        for k in keys:
            d = (rep.get("drilldown") or {}).get(k) or {}
            for c in d.get("controls") or []:
                w.writerow([d.get("framework_name") or k, c.get("control"), c.get("status"), c.get("passing_count"), c.get("failing_count"),
                            c.get("review_count"), c.get("info_count"), " ".join(str(e.get("check_id")) for e in (c.get("evidence") or []))])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="compliance_alignment_{stamp}.csv"'})
    import md_safe
    rep = md_safe.escape_data(rep)   # evidence details name tenant objects: inert text in the Markdown
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
    the export's SHA-256, and a decisions template to review. Read-only.
    Off the event loop (a large export must not hold up every other request)."""
    import vendor_migrate
    try:
        return await asyncio.to_thread(vendor_migrate.inventory_upload, req.vendor, req.export.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/vendor-migrate/compile")
async def vendor_migrate_compile(req: VendorMigrateCompileRequest):
    """Compile reviewed decisions against the export, fail-closed: the
    report always, the Terraform (every rule DISABLED) only when nothing
    is blocked. Nothing is written to the tenant or to disk."""
    import vendor_migrate
    try:
        return await asyncio.to_thread(vendor_migrate.compile_upload, req.vendor, req.export.model_dump(), req.decisions)
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
        out = await asyncio.to_thread(vendor_migrate.compile_upload, req.vendor, req.export.model_dump(), req.decisions)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not out.get("terraform"):
        raise HTTPException(status_code=409, detail={"cause": "Blocked: answer the questions in the migration report, then compile again.",
                                                     "report": out.get("report")})
    data = vendor_migrate.workspace_zip(out)
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="zscaler-made-easy-{out["vendor"]}-migration-terraform.zip"'})


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
    data = await _json_object(request)
    _require_report_size(_check_rows(data, "No checks in request body"))
    return await asyncio.to_thread(benchmarks.benchmark_report, data)


@app.post("/api/benchmarks/export")
async def benchmarks_export(request: Request, format: str = "markdown"):
    """The same benchmarks as Markdown (default) or JSON, for a customer note."""
    import benchmarks
    data = await _json_object(request)
    _require_report_size(_check_rows(data, "No checks in request body"))
    b = await asyncio.to_thread(benchmarks.benchmark_report, data)
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    org = str(meta.get("org") or "")
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
    the read-only endpoints the assessment already uses
    (/zia/dlpDictionaries, /zia/dlpEngines, and /zia/webDlpRules only when
    Inline Web DLP is marked Zscaler on the Scope page). DLP must be ticked
    on the Scope page (else 400, nothing read).

    Returns per-item 0–100 score + letter grade + specific reasons
    + remediation steps, plus orphan detection and tenant-wide
    efficacy averages."""
    try:
        from dlp_efficacy import analyze
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_efficacy unavailable: {e}")
    sel = _require_in_scope(req, "dlp", "DLP efficacy")
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(analyze, client, "web_dlp" in sel["on_zscaler"])
    import dlp_analysis
    report["required_controls"] = await asyncio.to_thread(dlp_analysis.inspect, client, sel["scopes"], sel["channels"])
    return report


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
    sel = _require_in_scope(req, "dlp", "DLP efficacy")
    client = await asyncio.to_thread(_build_client, req)
    analysis = await asyncio.to_thread(analyze, client, "web_dlp" in sel["on_zscaler"])
    import dlp_analysis
    analysis["required_controls"] = await asyncio.to_thread(dlp_analysis.inspect, client, sel["scopes"], sel["channels"])
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
    never leaves this machine. 256 KB hard cap on input. The tenant is
    still signed in to and read for the dictionaries and engines (and the
    Web DLP rules when Inline Web DLP is marked Zscaler), so DLP must be
    ticked on the Scope page (else 400, nothing read)."""
    try:
        from dlp_efficacy import corpus_test
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dlp_efficacy unavailable: {e}")
    sel = _require_in_scope(req, "dlp", "The DLP corpus test")
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(
        corpus_test, client, req.corpus or "", int(req.max_dicts or 200), "web_dlp" in sel["on_zscaler"]
    )
    import dlp_analysis
    report["required_controls"] = await asyncio.to_thread(dlp_analysis.inspect, client, sel["scopes"], sel["channels"])
    return report


# ── Step 1: Assess Current Status ─────────────────────────────────
# Every step that signs in reads (or writes) the Inline Web DLP rules: DLP
# ticked and Inline Web DLP marked Zscaler on the Scope page, else 400.
MIGRATE_WHAT = "The Evaluate All Rules migration (Inline Web DLP rules)"

@app.post("/api/migrate/status")
async def migrate_status(req: MigrateRequest):
    """Step 1: Determine whether tenant is in First-Match-Wins or Evaluate All Rules mode."""
    try:
        from rule_migrator import assess_current_status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    _require_in_scope(req, "dlp", MIGRATE_WHAT, "web_dlp")   # user rule 1: nothing read out of scope
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
    _require_in_scope(req, "dlp", MIGRATE_WHAT, "web_dlp")   # user rule 1: nothing read out of scope
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
    _require_in_scope(req, "dlp", MIGRATE_WHAT, "web_dlp")   # user rule 1: nothing read out of scope
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
    rules = _rule_text_fields(req.rules, "rules")
    return await asyncio.to_thread(optimize_for_eval_all_with_exceptions, rules, _eval_all_exceptions(req.exceptions))


# ── Step 4: Enable Evaluate All Rules ────────────────────────────
class EnableRequest(MigrateRequest):
    """Body for enabling Evaluate All Rules (dry run by default; dry_run=false
    needs confirm=true, the assessor, a writer and write mode)."""
    dry_run: bool = True
    confirm: bool = False
    assessor: str = ""


@app.post("/api/migrate/enable")
async def migrate_enable(req: EnableRequest):
    """Step 4: Enable Evaluate All Rules in ZIA Advanced Settings (dry-run by default)."""
    try:
        from rule_migrator import enable_evaluate_all_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.dry_run:
        _require_tenant_write(req, confirmed=req.confirm, what="Enabling Evaluate All Rules")
    _require_in_scope(req, "dlp", MIGRATE_WHAT, "web_dlp")   # user rule 1: nothing read out of scope
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(enable_evaluate_all_rules, client, req.dry_run)


# ── Step 4b: Delete All Existing Rules (gated) ───────────────────────
class DeleteAllRequest(MigrateRequest):
    """Body for deleting every Web DLP rule (dry run by default; dry_run=false
    needs confirm=true, the assessor, a writer, write mode and the dry
    run's plan_hash)."""
    dry_run: bool = True
    confirm: bool = False
    assessor: str = ""
    plan_hash: str = ""


@app.post("/api/migrate/delete-all")
async def migrate_delete_all(req: DeleteAllRequest):
    """Step 4b (optional): Delete every Inline Web DLP rule. Destructive — gated."""
    try:
        from rule_migrator import delete_all_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if not req.dry_run:
        _require_tenant_write(req, confirmed=req.confirm, what="Deleting every Inline Web DLP rule")
        _require_migrate_plan_hash(req)
    _require_in_scope(req, "dlp", MIGRATE_WHAT, "web_dlp")   # user rule 1: nothing read out of scope
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(delete_all_rules, client, req.dry_run, None if req.dry_run else req.plan_hash)


def _require_migrate_plan_hash(req: Any) -> None:
    """A live migration write deletes or overwrites exactly what its dry run
    showed: 400 before sign-in without the dry run's plan_hash."""
    if not str(getattr(req, "plan_hash", "") or "").strip():
        raise HTTPException(status_code=400, detail="plan_hash is required: run the dry run first and apply what it showed. Nothing was written.")


# ── Step 5: Post New Rule Order ──────────────────────────────────
class PostRequest(MigrateRequest):
    """Body for posting a proposed rule set (dry run by default; create, update or auto)."""
    proposed_rules: list[dict] = []
    dry_run: bool = True
    mode: str = "auto"  # "auto" | "create" | "update"
    confirm: bool = False   # dry_run=false needs confirm=true, the assessor, a writer, write mode and the dry run's plan_hash
    assessor: str = ""
    plan_hash: str = ""


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
    _rule_text_fields(req.proposed_rules, "proposed_rules")
    from rule_migrator import POST_MODES
    if req.mode not in POST_MODES:   # refused before any gate or sign-in, never read as "update"
        raise HTTPException(status_code=400, detail=f"mode must be one of {', '.join(POST_MODES)}. Nothing was read or written.")
    if not req.dry_run:
        _require_tenant_write(req, confirmed=req.confirm, what="Posting rules to the tenant")
        _require_migrate_plan_hash(req)
    _require_in_scope(req, "dlp", MIGRATE_WHAT, "web_dlp")   # user rule 1: nothing read out of scope
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(post_new_rule_order, client, req.proposed_rules, req.dry_run, req.mode,
                                   None if req.dry_run else req.plan_hash)


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
    _rule_text_fields(req.rules, "rules")
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
    _rule_text_fields(req.rules, "rules")   # a name is a lookup key: text only
    if not all(isinstance(t, (str, int)) and not isinstance(t, bool) for t in req.order):
        raise HTTPException(status_code=400, detail="`order` must list rule ids or names (text or numbers).")
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
    data = await _json_object(request)
    rules = _rule_rows(data, "No rules provided in request body.")
    return analyze_rules(rules)


@app.post("/api/migrate/plan")
async def migrate_plan(request: Request):
    """Generate full migration plan: analysis, reordered rules, diff, checklist."""
    try:
        from rule_migrator import generate_migration_plan
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    data = await _json_object(request)
    rules = _rule_rows(data, "No rules provided in request body.")
    return generate_migration_plan(rules)


@app.post("/api/migrate/export")
async def migrate_export(request: Request, format: str = "json"):
    """Export proposed rule order as importable JSON or CSV."""
    try:
        from rule_migrator import generate_migration_plan, export_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"rule_migrator not available: {e}")
    if format not in ("json", "csv"):   # any other value was an empty CSV file
        raise HTTPException(status_code=400, detail="format must be json or csv.")
    data = await _json_object(request)
    rules = _rule_rows(data, "No rules provided in request body.")
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


# The legacy single `scope` values _get_checks knows (MCP / CLI callers).
_LEGACY_SCOPES = frozenset({"full", "all", "automation", "zdx", "zidentity", "rbac", "zia", "zpa", "zcc", "dlp"})
_LEGACY_DLP_SCOPES = frozenset({"full", "all", "zia", "dlp"})   # legacy scopes whose checks include the DLP ones


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


@app.get("/api/scope/prerequisites")
async def scope_prerequisites():
    """The channel prerequisites (channel_scope.PREREQUISITES) the Scope
    page shows: ticking a channel on Zscaler assesses these too. Static:
    never reads a tenant."""
    import channel_scope
    return {"prerequisites": {cid: [{"id": pre, "name": channel_scope.CHANNELS.get(pre, pre), "reason": why} for pre, why in pres]
                              for cid, pres in channel_scope.PREREQUISITES.items()},
            "names": dict(channel_scope.CHANNELS), "required_dlp_note": __import__("dlp_analysis").NOTE}


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
    # Nothing is assessed unless it was put in scope: no `scopes` and no
    # legacy `scope` set on purpose (an MCP or CLI caller) is refused, never
    # read as "everything".
    # A legacy `scope` must name a scope, and `scopes` must select a known
    # one: an empty, blank or unknown choice is refused before any sign-in,
    # never read as the DLP default.
    _nothing = "Nothing to assess: choose what to assess on the Scope page, then run the assessment."
    if not req.scopes and ("scope" not in req.model_fields_set or str(req.scope or "").strip() not in _LEGACY_SCOPES):
        raise HTTPException(status_code=400, detail=_nothing)
    # Validate inputs BEFORE the SSE stream opens so failures return 400, not 200+stream
    creds = _validate_creds(_tenant_creds(req))
    if _offline.is_offline_creds(creds):
        # The sample tenant or a snapshot: its run is never kept in a real profile's history.
        profile = None
        req.org_name = (_offline.store_for_creds(creds).meta.get("company") or req.org_name) if req.org_name in ("", "Unknown") else req.org_name
    cloud, vd = creds["cloud"], creds["vanity_domain"]
    checks = _get_checks(str(req.scope or "").strip(), req.scopes)
    if not checks:
        raise HTTPException(status_code=400, detail=_nothing)
    # The Scope page's channel ownership: only a channel on Zscaler (ticked,
    # or a prerequisite of one: SSL inspection for Inline Web DLP) is read;
    # an alternative's or a gap's checks are not run and not shown, only
    # counted (channel_scope: hidden, outside the score and the coverage).
    import channel_scope as _chs
    import dlp_analysis
    analysis_scopes = list(req.scopes) if req.scopes else ({"full": ["dlp", "zia_extras", "zpa", "zcc", "automation", "zdx", "zidentity", "rbac"], "all": ["dlp", "zia_extras", "zpa", "zcc", "automation", "zdx", "zidentity", "rbac"], "zia": ["dlp", "zia_extras"]}.get(str(req.scope or "").strip(), [str(req.scope or "").strip()]))
    checks, skipped_checks, analysis_channels = dlp_analysis.assessment_checks(checks, req.channels, analysis_scopes)
    if not checks:
        # Every check in the chosen scopes belongs to a channel that is not
        # ticked: signing in would read nothing, so say what to tick instead.
        names = sorted({str(r.get("channel_name") or _chs.CHANNELS.get(r.get("channel"), r.get("channel")) or "") for r in skipped_checks} - {""})
        raise HTTPException(status_code=400, detail=(
            "Nothing to assess: every check in the chosen scope belongs to a channel that is not ticked as Zscaler on the "
            f"Scope page ({', '.join(names) or 'none ticked'}). Tick the channel, then run the assessment."))
    total_all = len(checks)   # the hidden checks are not part of the run's numbers
    # The profile's industry: the frameworks and packs the suggestions are limited to.
    import vertical as _vertical
    _scope = _vertical.scope_for(profile, all_packs=[p["id"] for p in __import__("dlp_importer").discover_packs()])
    # The journey (pack deficiencies) reads the tenant too, so it runs only
    # when DLP is in scope, only for the packs ticked on the profile (never
    # a default set) and only on their channels marked Zscaler.
    journey_pack_ids = [str(b) for b in (profile or {}).get("baseline_packs") or [] if b]
    try:
        dlp_in_scope = ("dlp" in req.scopes) if req.scopes else (str(req.scope or "").strip() in _LEGACY_DLP_SCOPES)
        journey_packs, journey_targets = _journey_scope(journey_pack_ids, req.channels) if dlp_in_scope else ([], {})
    except Exception:  # noqa: BLE001 — no journey rather than a failed run
        journey_packs, journey_targets = [], {}

    async def event_generator():
        results = []
        client = None
        pool = None
        running: set = set()   # checks whose thread has started and not yet returned
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
            yield _sse("progress", {"total": total_all, "completed": 0, "pct": 0})

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

            # The checks read through the channel guard: a GET of an unticked
            # channel's configuration is refused without touching the tenant.
            scoped_client = dlp_analysis.ScopedClient(dlp_analysis.read_once(client), analysis_channels, analysis_scopes)

            def _run_one(idx, check_id, section, label, fn):
                started[idx] = time.time()
                running.add(idx)
                try:
                    scoped_client.begin()
                    r = fn(scoped_client)
                    r = _unanswered_result(r, label, scoped_client.unanswered())
                except Exception as ex:  # noqa: BLE001
                    r = R(R.ERROR, f"{label}: Could not complete check. {str(ex)[:120]}")  # "Could not be checked", never "Not configured"
                finally:
                    running.discard(idx)
                loop.call_soon_threadsafe(inbox.put_nowait, (idx, r))

            pool = ThreadPoolExecutor(max_workers=ASSESS_WORKERS, thread_name_prefix="assess")
            for idx, chk in enumerate(checks):
                pool.submit(_run_one, idx, *chk)
            # Whatever ends this stream (results in, the browser gone, Stop),
            # the checks still queued are cancelled: no tenant read is made
            # once nobody is listening (the finally around the loop below).
            done: Dict[int, Dict[str, Any]] = {}
            last_keepalive = time.time()
            run_started = time.time()

            def _finish(idx, r):
                check_id, section, label, _fn = checks[idx]
                if not hasattr(r, "status") or not hasattr(r, "detail"):
                    r = R(R.ERROR, f"{label}: Invalid check result.")
                result = {"id": check_id, "section": section, "label": label,
                          "status": str(r.status), "detail": str(r.detail)[:500]}
                if isinstance(getattr(r, "data", None), dict) and r.data.get("required_control"):
                    result["required_control"] = r.data["required_control"]
                if str(check_id).startswith("AI."):
                    try:   # a GenAI finding AI Guard addresses links to its Bulk changes builder
                        import zscaler_genai_checks
                        link = zscaler_genai_checks.tool_link(check_id, result["status"])
                        if link:
                            result["tool"] = link
                    except Exception:  # noqa: BLE001 — a link never breaks a result
                        pass
                try:
                    import plain_english
                    plain_english.enrich(result)      # what we found / what it means / what to do / outcome
                except Exception:  # noqa: BLE001
                    pass
                done[idx] = result
                return result

            try:
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
                                "total": total_all, "completed": len(done),
                                "pct": round(len(done) / max(total_all, 1) * 100),
                                "current": f"{fresh[-1]['id']}: {fresh[-1]['label']}",
                                "running": len([i for i in started if i not in done]),
                                "elapsed": round(now - run_started),
                            })
                        if now - last_keepalive > 10:
                            yield ": keepalive\n\n"
                            last_keepalive = now
                    except Exception:  # noqa: BLE001 — a failed write; a disconnect closes the generator (finally below)
                        pass
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
                _stop_reads(client)   # a check still running (timed out, or Stop) reads nothing more
            # The checks' own session ends as soon as the checks are in (a
            # classic ZIA API admin session stays open otherwise).
            api_requests = getattr(client, "requests_made", None)
            await _end_checks_session(client, pool, running)
            client = None
            results = [done[i] for i in range(len(checks))]   # the checks keep their section order

            # Results first: the report goes out as soon as the checks are
            # in. The data-governance journey (one read-only preflight per
            # chosen pack, on its channels in scope) follows as its own event
            # so nobody waits on it.
            want_journey = bool(journey_packs)

            try:
                secs, overall = compute(results)
            except Exception:  # noqa: BLE001
                secs, overall = {}, None   # nothing measurable: "Not assessed", never an invented number

            report = {
                "metadata": {
                    "tool": "Zscaler Made Easy",
                    "version": "3.0",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "org": req.org_name,
                    "assessor": req.assessor,
                    "cloud": req.cloud,
                    "total_checks": total_all,
                    "scope": ",".join(req.scopes) if req.scopes else req.scope,
                    "elapsed_seconds": round(time.time() - run_started, 1),
                    "api_requests": api_requests,
                },
                "score": overall,
                "maturity": maturity(overall),
                "sections": secs,
                "checks": results,
                "critical": [r for r in results if r["status"] == "FAIL"],
                "review": [r for r in results if r["status"] == "REVIEW"],
                "journey": {"status": "pending"} if want_journey else None,
                "profile": None,
                # The Scope page's declaration and what it did (channel_scope.coverage):
                # the prerequisites added, and the hidden checks as one count.
                "channel_coverage": _chs.coverage(req.channels, skipped_checks),
                "required_controls": [r["required_control"] for r in results if r.get("required_control")],
                "required_controls_note": dlp_analysis.NOTE if dlp_analysis.active(analysis_scopes) else "",
                "hidden_checks": len(skipped_checks),
                "hidden_note": _chs.hidden_note(len(skipped_checks)),
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
                report["summary"] = _perm.assessment_summary(results, hidden=len(skipped_checks))
            except Exception:  # noqa: BLE001
                report["summary"] = None
            if not want_journey:
                report["profile"] = _record_history(report)
            report["scope"] = _scope   # the profile's industry: frameworks and packs the suggestions are limited to
            yield _sse("complete", report)

            if want_journey:
                journey = None
                sdk = None
                task = None
                stop = threading.Event()   # set when the run ends: the journey makes no further tenant read
                try:
                    packs = journey_packs
                    yield _sse("progress", {"total": total_all, "completed": total_all, "pct": 100,
                                            "current": f"Data governance journey: measuring the tenant against {len(packs)} policy packs"})
                    sdk = await asyncio.to_thread(_build_sdk_client, creds)
                    notes: asyncio.Queue = asyncio.Queue()

                    def _note(i, n, pack_id):
                        loop.call_soon_threadsafe(notes.put_nowait, (i, n, pack_id))

                    task = loop.run_in_executor(None, lambda: _journey_for(sdk, packs, channel_targets=journey_targets, progress=_note, stop=stop))
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
                finally:
                    # Timed out, failed or nobody listening: the journey stops
                    # before its next tenant read, and its session (a classic
                    # ZIA API one stays open otherwise) is ended only once the
                    # journey thread has stopped using it.
                    stop.set()
                    if sdk is not None:
                        if task is not None and not task.done():
                            task.add_done_callback(_close_when_done(sdk))
                        else:
                            await asyncio.to_thread(_close_quietly, sdk)
                report["journey"] = journey
                report["profile"] = _record_history(report)
                yield _sse("journey", {"journey": journey, "profile": report["profile"]})

        except Exception as e:
            # Catch-all: never let the generator crash the stream
            yield _sse("error", {"message": f"Server error: {str(e)[:200]}"})
        finally:
            # Failed sign-in, error or the browser gone: the checks' session
            # is still ended (once no check thread is using it).
            if pool is not None:
                pool.shutdown(wait=False, cancel_futures=True)
            if client is not None:
                _stop_reads(client)
                await _end_checks_session(client, pool, running)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


# python-docx appends each paragraph after scanning the body, so the time a
# document takes grows with the square of its length: 4,000 checks took
# 70 s (2,000: 22 s, off the event loop). An assessment has a few hundred;
# more than this is refused.
_DOCX_MAX_CHECKS = 1000


WORD_REPORT_FAILED = "The Word report could not be built; the server log says why."


@app.post("/api/report/docx")
async def generate_docx(request: Request):
    """Generate a Word doc from assessment results (at most _DOCX_MAX_CHECKS
    checks; built off the event loop)."""
    import traceback as _tb
    try:
        from report_docx import generate_report
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"python-docx not installed: {e}. Run: pip install python-docx")

    data = _xml_text(await _json_object(request))
    results = _check_rows(data, "No checks in request body — cannot generate report.")
    cfg = dict(data["metadata"]) if isinstance(data.get("metadata"), dict) else {}
    # The Scope page's channel declaration rides along for the Channel Coverage
    # section, and the count of the checks hidden as outside the scope.
    if isinstance(data.get("channel_coverage"), dict):
        cfg["channel_coverage"] = data["channel_coverage"]
    if data.get("hidden_checks"):
        cfg["hidden_checks"] = data.get("hidden_checks")

    if len(results) > _DOCX_MAX_CHECKS:
        raise HTTPException(status_code=413, detail=f"Too many results ({len(results)}); "
                                                    f"a Word report holds at most {_DOCX_MAX_CHECKS} checks.")

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name
        await asyncio.to_thread(generate_report, results, cfg, tmp_path, compute, maturity)
    except Exception as e:
        if tmp_path:
            _unlink_quietly(tmp_path)   # a failed report leaves no copy of the assessment behind
        # The traceback stays in the server log; the browser gets plain words
        # (an exception's text can quote the posted assessment, CWE-209).
        tb = _tb.format_exc()
        print(f"\n=== Word generation failed ===\n{tb}===\n", flush=True)
        raise HTTPException(status_code=500, detail=WORD_REPORT_FAILED)

    org = re.sub(r"[^A-Za-z0-9_-]+", "_", str(cfg.get("org", "report"))).strip("_")[:60] or "report"
    # The temp file holds the whole assessment: remove it once it has been sent.
    return FileResponse(tmp_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        filename=f"zscaler_{org}_{datetime.now().strftime('%Y%m%d')}.docx",
                        background=BackgroundTask(_unlink_quietly, tmp_path))


_CSV_STATUS = {"FAIL": "Fix this", "REVIEW": "Needs a look", "PASS": "Good"}


@app.post("/api/report/findings-csv")
async def findings_csv(request: Request):
    """The assessment's findings as a spreadsheet (CSV that opens in Excel):
    one row per check, the ones to fix first, in the plain words the
    findings carry (what we found, what it means, what to do). Built from
    the results the page already holds, like /api/report/docx; reads no
    tenant. Every cell goes through csv_safe, so a rule or check name that
    starts with = + - @ is shown as text, never run as a formula."""
    import io
    import csv_safe
    import channel_scope
    data = await _json_object(request)
    results = data.get("checks")
    if not isinstance(results, list) or not results:
        raise HTTPException(status_code=400, detail="No checks in request body — cannot make the spreadsheet.")
    shown, _hidden = channel_scope.visible(results)
    order = {"FAIL": 0, "REVIEW": 1}
    rows = sorted((r for r in shown if isinstance(r, dict)), key=lambda r: order.get(str(r.get("status")), 2 if str(r.get("status")) != "PASS" else 3))
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(["Status", "Check", "Area", "Finding", "What we found", "What it means", "What to do", "Technical detail"])
    for r in rows:
        p = r.get("plain") if isinstance(r.get("plain"), dict) else {}
        st = str(r.get("status") or "")
        w.writerow([_CSV_STATUS.get(st, "Not checked" if st == "ERROR" else "For your information"), str(r.get("id") or ""), str(r.get("section") or ""),
                    str(r.get("label") or ""), str(p.get("found") or ""), str(p.get("means") or ""), str(p.get("do") or ""), str(r.get("detail") or "")[:500]])
    meta = (data or {}).get("metadata") or {}
    org = re.sub(r"[^A-Za-z0-9_-]+", "_", str(meta.get("org", "report") if isinstance(meta, dict) else "report")).strip("_")[:60] or "report"
    # A byte-order mark so Excel reads the file as UTF-8.
    stamp = datetime.now().strftime("%Y%m%d")
    return PlainTextResponse("\ufeff" + buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="zscaler_{org}_{stamp}_findings.csv"'})


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


# ── Client Connector fleet health (zcc_fleet) ─────────────────────────────────
FLEET_WHAT = "Client Connector fleet health"


@app.get("/report/fleet")
async def report_fleet_page():
    """Standalone tab for Client Connector fleet health (static/report_fleet.html)."""
    page = os.path.join(STATIC_DIR, "report_fleet.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class ZccFleetRequest(ScopedTenantCredsRequest):
    """Tenant credentials and the Scope page selection; the fleet is read
    only when ZCC is ticked there (else 400 before sign-in)."""


def _zcc_fleet_clients(req: ZccFleetRequest, creds: Dict[str, str]):
    """Sign in: the assessment client (profiles, PAC, through the paced
    readers) and, for a OneAPI sign-in, the SDK client the enrolled devices
    are read with. A classic ZIA sign-in has no Client Connector API, and an
    SDK sign-in that fails leaves the run configuration only, with the
    reason (never a secret)."""
    client = _build_client(req)
    if creds.get("auth_method") == tenant_auth.LEGACY:
        return client, None, "The classic ZIA API sign-in cannot read Client Connector devices; sign in with a OneAPI API client to see the fleet."
    try:
        return client, _build_sdk_client(creds), ""
    except HTTPException as e:
        return client, None, tenant_auth.mask_secrets(str(e.detail), creds)[:240]


@app.post("/api/zcc/fleet/start")
async def zcc_fleet_start(req: ZccFleetRequest, request: Request):
    """Start Client Connector fleet health as a job the page follows: the
    app and forwarding profiles, PAC files, enrolled devices and their
    service status, read-only and paced, then the analysis. Refused (400)
    before sign-in when ZCC is not in scope. Stop ends it with nothing more
    read and no partial result. Poll GET /api/dlp-packs/jobs/{job_id}."""
    import pack_jobs
    import zcc_fleet
    _require_in_scope(req, "zcc", FLEET_WHAT)   # user rule 1: nothing read out of scope
    creds = _tenant_creds(req)
    label = tenant_auth.record_label(creds)
    client, sdk, why = await asyncio.to_thread(_zcc_fleet_clients, req, creds)

    def fn(log, cancel):
        try:
            return zcc_fleet.run(client, sdk, log=log, cancel=cancel, label=label, sdk_reason=why)
        finally:
            _close_quietly(client)
    job = pack_jobs.start("fleet", fn, label="Client Connector fleet", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


def _fleet_result(job_id: str) -> Dict[str, Any]:
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None or job.kind != "fleet":
        raise HTTPException(status_code=404, detail="No such fleet run. Runs are kept for an hour after they finish; run it again.")
    res = job.result or {}
    if job.status != pack_jobs.DONE or res.get("status") != "done":
        raise HTTPException(status_code=409, detail="This fleet run has not finished (or was stopped); nothing to show.")
    return res


@app.get("/api/zcc/fleet/{job_id}/diff")
async def zcc_fleet_diff(job_id: str, a: str = "", b: str = ""):
    """Side-by-side settings and the JSON diff of two app profiles of a
    finished run (secrets masked). No tenant call."""
    import zcc_fleet
    try:
        return zcc_fleet.diff_from_result(_fleet_result(job_id), a, b)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=str(e.args[0] if e.args else e))


@app.get("/api/zcc/fleet/{job_id}/export")
async def zcc_fleet_export(job_id: str, what: str = "plan", counts_only: bool = False, format: str = "csv"):
    """The remediation plan, the device table or the summary of a finished
    run as CSV (csv_safe), or everything as one Excel workbook (format=xlsx:
    summary, versions, operating systems, stale devices, devices, alerts,
    plan; `what` is then ignored). counts_only leaves every user and host
    name out (the CSV device table is then refused; the workbook leaves the
    device sheet empty and counts the stale devices per platform)."""
    import zcc_fleet
    res = _fleet_result(job_id)
    fmt = (format or "csv").lower()
    if fmt == "xlsx":
        import report_exports
        stem, data = await asyncio.to_thread(zcc_fleet.export_xlsx, res, counts_only)
        return _attachment(data, report_exports.XLSX, f"{stem}_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx")
    if fmt != "csv":
        raise HTTPException(status_code=400, detail="format must be csv or xlsx.")
    try:
        stem, text = zcc_fleet.export_csv(res, (what or "").lower(), counts_only)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    name = f"{stem}{'_counts' if counts_only else ''}_{ts}.csv"
    return Response(content=text, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f"attachment; filename={name}"})


class ZccInstallRequest(ScopedTenantCredsRequest):
    """The Client Connector install command builder (ops_zcc.install_commands):
    platform, installer type, the installer's options and, to fill in the
    policy token, the app profile's id (app_profile_id) (read only when ZCC is in scope).
    Tokens and passwords come back masked unless `reveal` is true."""
    platform: str = "windows"
    installer: str = ""
    installer_name: str = ""
    values: Dict[str, Optional[Any]] = {}
    app_profile_id: str = ""
    reveal: bool = False


@app.get("/api/zcc/install/catalog")
async def zcc_install_catalog():
    """The installer options the install command builder offers (no tenant call)."""
    import ops_zcc
    return ops_zcc.install_catalog()


@app.post("/api/zcc/install")
async def zcc_install(req: ZccInstallRequest):
    """MSI, EXE or macOS install command and a .bat / .command script. With
    app_profile_id, the app profile's policy token is read (SDK
    zcc.application_profiles.get_application_profile), only when ZCC is in
    scope (400 before sign-in otherwise). Secrets are masked unless reveal is
    true; nothing here is logged or stored (the audit line drops token and
    password keys)."""
    import ops_zcc
    values = {k: v for k, v in (req.values or {}).items() if isinstance(k, str) and len(k) <= 40}
    token_note = ""
    if req.app_profile_id:
        _require_in_scope(req, "zcc", "Reading the app profile's policy token")   # user rule 1: nothing read out of scope
        creds = _tenant_creds(req)
        if creds.get("auth_method") == tenant_auth.LEGACY:
            raise HTTPException(status_code=400, detail="The classic ZIA API sign-in has no Client Connector API; sign in with a OneAPI API client.")
        sdk = await asyncio.to_thread(_build_sdk_client, creds)
        try:
            token, why = await asyncio.to_thread(ops_zcc.policy_token, sdk, req.app_profile_id)
        finally:
            _close_quietly(sdk)
        if token:
            values["policyToken"] = token
        else:
            token_note = why or ""
    try:
        out = ops_zcc.install_commands(req.platform, req.installer, values, installer_name=req.installer_name, reveal=req.reveal)
    except ops_zcc.BuilderError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if token_note:
        out["warnings"].insert(0, token_note)
    return JSONResponse(out, headers={"Cache-Control": "no-store"})


class ZccOtpRequest(ScopedTenantCredsRequest):
    """One device's Client Connector one-time passwords (zcc_otp): the
    enrolled user, the device's host name or UDID, the assessor and the
    typed confirmation "SHOW OTP <device>"."""
    user: str = ""
    device: str = ""
    confirm_text: str = ""


ZCC_OTP_WHAT = "Client Connector one-time passwords"
ZCC_OTP_ASSESSOR = ("Enter the assessor's name before showing a one-time password: the audit log names the person who asked "
                    "for it. Nothing was read.")


@app.post("/api/zcc/otp")
async def zcc_otp_show(req: ZccOtpRequest, request: Request):
    """A device's one-time passwords (uninstall, turn a service off, exit,
    as the API provides them) for help-desk use: a sensitive read guarded
    like a write. Refused before sign-in unless ZCC is in scope, the caller
    may change the tenant, the assessor is named, "SHOW OTP <device>" is
    typed and the rate limit allows it. The values are in this answer only
    (no-store): never logged, stored or cached; the audit entry names who,
    when and which device, never a value (zcc_otp)."""
    import pack_deploy
    import zcc_otp
    _require_in_scope(req, "zcc", ZCC_OTP_WHAT)   # user rule 1: nothing read out of scope
    _security.require_writer()
    if pack_deploy.is_tool_name(getattr(req, "assessor", "") or ""):
        raise HTTPException(status_code=400, detail=ASSESSOR_NOT_TOOL)
    by = _assessor(req)
    if not by:
        raise HTTPException(status_code=400, detail=ZCC_OTP_ASSESSOR)
    try:
        user = zcc_otp.clean(req.user, "enrolled user name")
        device = zcc_otp.clean(req.device, "device's host name or UDID")
    except zcc_otp.OtpError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    want = zcc_otp.phrase(device)
    if not _security.typed_phrase_matches(req.confirm_text, want):
        raise HTTPException(status_code=400, detail=f"Type {want} to confirm. Nothing was read.")
    actor = _actor(request)
    creds = _tenant_creds(req)
    label = tenant_auth.record_label(creds)
    if creds.get("auth_method") == tenant_auth.LEGACY:
        raise HTTPException(status_code=400, detail="The classic ZIA API sign-in has no Client Connector API; sign in with a OneAPI API client.")
    wait = zcc_otp.LIMITER.take(actor or "local")
    if wait:
        zcc_otp.audit("rate_limited", actor=actor, by=by, tenant=label, device=device, reason=f"retry after {wait}s")
        raise HTTPException(status_code=429, detail=f"Too many one-time password requests: try again in {wait} seconds. Nothing was read.",
                            headers={"Retry-After": str(wait)})
    sdk = await asyncio.to_thread(_build_sdk_client, creds)
    try:
        out = await asyncio.to_thread(zcc_otp.retrieve, sdk, user, device)
    except zcc_otp.OtpError as e:
        zcc_otp.audit("refused" if e.status < 500 else "failed", actor=actor, by=by, tenant=label, device=device, reason=str(e))
        raise HTTPException(status_code=e.status, detail=str(e))
    finally:
        _close_quietly(sdk)
    zcc_otp.audit("shown", actor=actor, by=by, tenant=label, device=out["device"]["hostname"], ref=out["device"]["ref"],
                  kinds=[o["key"] for o in out["otps"]])
    return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.get("/report/view")
async def report_view_page():
    """Standalone tab that mirrors a tool dialog (see static/report_view.html)."""
    page = os.path.join(STATIC_DIR, "report_view.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Reference pages ──────────────────────────────────────────────────
# Bundled HTML references an engineer keeps next to the tool (the
# data-security portfolio framework, the AI security frameworks, how the
# framework machine fits together). Served from static/reference/ under
# their own routes so the sidebar can open them like any other page. They
# carry their own inline scripts and styles, with allowlisted same-origin
# child routes for the two embedded frameworks; nothing external is loaded
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
# Served with every bundled reference document (static/reference/reference_a11y.js).
_REFERENCE_A11Y = '<script src="/static/reference/reference_a11y.js"></script>\n'


@app.get("/api/reference")
async def reference_list():
    """The reference pages the sidebar offers, with their routes."""
    out = []
    for p in REFERENCE_PAGES:
        path = os.path.join(_REFERENCE_DIR, f"{p['slug']}.html")
        out.append({**p, "href": f"/reference/{p['slug']}", "available": os.path.exists(path),
                    "bytes": os.path.getsize(path) if os.path.exists(path) else 0})
    return {"pages": out}


# Only these bundled documents may be embedded by our own pages. Every
# other page retains the global DENY / frame-ancestors 'none' policy.
_REFERENCE_EMBEDS = {
    "portfolio-map": "portfolio-map.html",
    "copilot-readiness": "copilot-readiness.html",
}


@app.get("/reference/embed/{slug}")
async def reference_embed_page(slug: str):
    filename = _REFERENCE_EMBEDS.get(slug)
    if filename is None:
        raise HTTPException(status_code=404, detail="No such embedded reference.")
    path = os.path.join(_REFERENCE_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Embedded reference missing.")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    # Capture script failures before any bundled script executes. The child
    # reports readiness only after its own content and controls initialize.
    bridge = (f'<meta name="dlp-reference-embed" content="{slug}">'
              '<script src="/static/reference/reference_embed_child.js"></script>' + _REFERENCE_A11Y)
    charset = re.search(r"<meta\s+charset=[^>]+>", html, re.IGNORECASE)
    pos = charset.end() if charset else 0
    html = html[:pos] + bridge + html[pos:]
    return HTMLResponse(html, headers={
        "Cache-Control": "no-cache, must-revalidate, max-age=0",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Security-Policy": _security.CONTENT_SECURITY_POLICY.replace(
            "frame-ancestors 'none'", "frame-ancestors 'self'"),
    })


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
    # The accessibility layer (WCAG 2.2 AA) closes the gaps of the bundled
    # documents: language, names, keyboard, targets, focus, reflow, contrast.
    tag = '<script src="/static/report_theme.js"></script>\n' + _REFERENCE_A11Y
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
    if not rep or not report_id.startswith("bypass-"):   # another kind's report id is not a bypass report
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.get("/api/report/bypass/export/{report_id}")
async def report_bypass_export_cached(report_id: str, format: str = "csv"):
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("bypass-"):
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    return await _bypass_export_response(rep, format)


def _report_label(req: Any) -> str:
    """How a kept report names its tenant: tenant_auth.record_label of the
    resolved sign-in, so a classic-API tenant is 'classic API (cloud)' and
    neither its admin login nor a vanity domain left in the form (the page
    sends the field whatever the sign-in) reaches the report or its exports
    (user rule 3)."""
    return tenant_auth.record_label(_tenant_creds(req))


class ScopedReportRequest(MigrateRequest):
    """A report that reads the tenant (Bypass, SSL inspection flow): what
    is in scope, as for the Path analyzer and the Data Flow Map — the Scope
    page's ticked `scopes` and channel declaration (`channels`), else
    (nothing sent and `from_page` false) the chosen profile's saved
    selection. Nothing in scope is refused before sign-in (user rule 1)."""
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


def _bypass_report_scope(req: Any) -> Dict[str, Any]:
    """What the Bypass report may read (bypass_report.bypass_scope of
    _scope_selection); HTTPException 400 when nothing is in scope. Never
    reads a tenant."""
    import bypass_report
    sc, ch, source = _scope_selection(req)
    sel = bypass_report.bypass_scope(sc, ch)
    if not sel["read"]:
        raise HTTPException(status_code=400, detail=bypass_report.NOTHING_IN_SCOPE)
    sel["source"] = source
    return sel


def _ssl_flow_scope(req: Any) -> Dict[str, Any]:
    """What the SSL inspection flow may read (data_flow.path_scope of
    _scope_selection). It walks the SSL inspection rules, so it is refused
    (400) unless they are in scope. Never reads a tenant."""
    import data_flow
    import ssl_flow
    sc, ch, source = _scope_selection(req)
    sel = data_flow.path_scope(sc, ch)
    if "ssl" not in sel["read"] and not sel.get("required_controls"):
        raise HTTPException(status_code=400, detail=ssl_flow.NOTHING_IN_SCOPE)
    sel["source"] = source
    return sel


@app.post("/api/report/bypass")
async def report_bypass(req: ScopedReportRequest):
    """Generate the bypass-inventory report (JSON). Read-only, and only
    what is in scope on the Scope page is read. The response carries
    report_id for /report/bypass?id=... and the export links."""
    try:
        from bypass_report import generate_bypass_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bypass_report unavailable: {e}")
    scope = _bypass_report_scope(req)   # refused here, before signing in, when nothing is in scope
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_bypass_report, client, scope)
    rid = _remember_report("bypass", report, _report_label(req))
    return _REPORTS[rid]


class BypassExportRequest(ScopedReportRequest):
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
        except Exception:
            _unlink_quietly(output_path)
            # As /api/report/docx: the traceback (which can quote the bypass
            # report's tenant data) stays in the server log, CWE-209.
            import traceback as _tb_bypass
            print(f"\n=== Word generation failed (bypass report) ===\n{_tb_bypass.format_exc()}===\n", flush=True)
            raise HTTPException(status_code=500, detail=WORD_REPORT_FAILED)
        return FileResponse(output_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            filename=f"zscaler_bypass_{ts}.docx", background=BackgroundTask(_unlink_quietly, output_path))
    return Response(content=json.dumps(report, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.json"})


# ── Data Flow Map (the exact path a transaction takes through the tenant) ──────
class DataFlowRequest(MigrateRequest):
    """Body of the Data Flow Map. What is in scope, as for the Path
    analyzer: the Scope page's ticked `scopes` and channel declaration
    (`channels`), else (nothing sent and `from_page` false) the chosen
    profile's saved selection; nothing in scope is refused before sign-in."""
    destinations: List[str] = []      # traffic-class keys, app names, category ids or hostnames; [] = every traffic class
    platform: str = "windows"
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


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
        import data_flow
        from data_flow import generate_data_flow_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"data_flow unavailable: {e}")
    # Only what the Scope page puts in scope is read (user rule 1); nothing
    # in scope is refused here, before signing in.
    scope = _path_scope(req, data_flow.MAP_NOTHING_IN_SCOPE)
    client = await asyncio.to_thread(_build_client, req)
    plat = req.platform if req.platform in ("windows", "macos", "ios", "android", "linux") else "windows"
    dests = [str(d)[:200] for d in (req.destinations or [])][:40]
    try:
        report = await asyncio.to_thread(lambda: generate_data_flow_report(client, dests or None, plat, scope=scope))
    except Exception as e:  # noqa: BLE001
        # The tracer's own failure is not a secret: name it so the tab can
        # say what went wrong instead of "internal error".
        import traceback
        print(f"[error] data flow map: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"The tracer failed ({type(e).__name__}: {str(e)[:300]}). The full traceback is in server.log; please report it.")
    rid = _remember_report("dataflow", report, _report_label(req))
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


# ── Path analyzer: HAR import (batch of hosts) ────────────────────────
# The page parses the HAR file in the browser (static/har_parse.js): the
# file never leaves it. Only host names, request counts, HTTP methods,
# schemes and upload amounts are sent here (`har_hosts`, which the audit
# log records by size only); cookies, headers, URL paths and bodies stay
# in the browser. The tenant is read once and every host is traced
# against that read (path_analyzer.analyze_batch). Read-only; Stop ends
# it between hosts.
_PATH_BATCHES: Dict[str, Dict[str, Any]] = {}
_PATH_BATCHES_MAX = 4
_HAR_METHOD = re.compile(r"^[A-Z]{1,12}$")


class PathBatchRequest(ScopedTenantCredsRequest):
    """Body of the HAR batch: the hosts (each a name, or {host, requests,
    uploads, bytes_sent, methods, schemes} with the counts the page took
    from the HAR file; nothing else is read from an entry), the network,
    the platform and optionally the id of a tenant read to reuse."""
    har_hosts: List[Any] = []
    network: str = "off"
    platform: str = "windows"
    report_id: str = ""


def _batch_hosts(req: PathBatchRequest) -> Tuple[List[str], Dict[str, Dict[str, Any]], List[str]]:
    """(valid hosts in order, {host: counts}, names that are not a hostname
    or IP address). 400 for none, or more than path_analyzer.BATCH_MAX."""
    import path_analyzer
    hosts: List[str] = []
    stats: Dict[str, Dict[str, Any]] = {}
    skipped: List[str] = []
    if len(req.har_hosts) > path_analyzer.BATCH_MAX:
        raise HTTPException(status_code=400, detail=f"At most {path_analyzer.BATCH_MAX} hosts are analyzed per run; {len(req.har_hosts)} were sent.")
    # Each count and list is checked for its type (deny by default): a value of
    # another type, NaN or Infinity counts as nothing, never a 500. Over HTTP
    # NaN and Infinity never get here (_StrictJSONRoute refuses the body, 422);
    # only callers inside the process can pass them, and this stays the guard.
    num = lambda v: max(0, min(int(v), 10 ** 12)) if (isinstance(v, int) or (isinstance(v, float) and abs(v) < float("inf"))) and not isinstance(v, bool) else 0  # noqa: E731
    for item in req.har_hosts:
        raw = item.get("host") if isinstance(item, dict) else item
        name = str(raw or "").strip()[:260]
        try:
            d = path_analyzer.parse_destination(name)
        except ValueError:
            skipped.append(name[:80])
            continue
        if d["kind"] == "url" or d["host"] in stats:
            if d["kind"] == "url":
                skipped.append(name[:80])
            continue
        h = d["host"]
        hosts.append(h)
        it = item if isinstance(item, dict) else {}
        listed = lambda v: v[:100] if isinstance(v, list) else []  # noqa: E731 — anything else names no method or scheme
        stats[h] = {"requests": num(it.get("requests")), "uploads": num(it.get("uploads")), "bytes_sent": num(it.get("bytes_sent")),
                    "methods": [m for m in listed(it.get("methods")) if isinstance(m, str) and _HAR_METHOD.match(m)][:12],
                    "schemes": [s for s in listed(it.get("schemes")) if isinstance(s, str) and s in ("http", "https", "ws", "wss")][:4]}
    if not hosts:
        raise HTTPException(status_code=400, detail="No hostname or IP address to analyze: the HAR file named none the analyzer can read.")
    return hosts, stats, skipped


def _run_path_batch(client, req: PathBatchRequest, hosts, stats, skipped, snapshot, label: str, log, cancel, scope) -> Dict[str, Any]:
    """The batch job: analyze_batch, the fresh read kept as a Data Flow Map
    report for the next run (same scope only), the full analyses kept here
    for the page's row click and the exports."""
    import pack_jobs
    import path_analyzer
    if scope.get("source"):
        log(f"In scope, from {scope['source']}: {scope['summary']}")
    if skipped:
        log(f"{len(skipped)} name(s) are not a hostname or IP address and were skipped.")
    out = path_analyzer.analyze_batch(client, hosts, req.network, req.platform, scope=scope, snapshot=snapshot, log=log, cancel=cancel, stats=stats)
    cache = out.pop("snapshot_for_cache", None)
    rid = req.report_id if snapshot is not None else ""
    if cache is not None:
        rows = out["rows"]
        summary = {"destinations": len(rows), "traces": len(rows), "bypassed": sum(r["outcome_key"] == "bypassed" for r in rows),
                   "blind": sum(r["outcome_key"] == "blind" for r in rows), "enforced": sum(r["outcome_key"] == "enforce" for r in rows),
                   "monitored": sum(r["outcome_key"] == "monitor" for r in rows), "high": 0}
        first = next(iter(out["analyses"].values()), {})
        rid = _remember_report("dataflow", {"summary": summary, "platform": req.platform,
                                            "networks": [n for n in path_analyzer.NETWORKS if n["key"] == first.get("network", req.network)],
                                            "platforms": path_analyzer.PLATFORMS, "destinations": [a["destination"] for a in out["analyses"].values()],
                                            "traces": [a["trace"] for a in out["analyses"].values()], "packs": [],
                                            "required_controls": first.get("required_controls", []), "diagnostics": cache.get("diagnostics") or [],
                                            "client_connector": cache["client_connector"], "snapshot": cache["snapshot"], "sources": {},
                                            "path_scope": cache.get("path_scope")}, label)
    analyses = out.pop("analyses")
    for a in analyses.values():
        a["report_id"] = rid
        a["tenant_label"] = label
        a["logs"] = []
    job = pack_jobs.current()
    batch_id = job.id if job is not None else ""
    counts: Dict[str, int] = {}
    for r in out["rows"]:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    result = {"rows": out["rows"], "errors": out["errors"], "skipped": skipped, "not_analyzed": out["not_analyzed"], "stopped": out["stopped"],
              "status": "stopped" if out["stopped"] else "done", "report_id": rid, "tenant_label": label, "network": req.network,
              "platform": req.platform, "batch_id": batch_id, "counts": counts, "fresh_read": out["fresh_read"] and cache is not None,
              "scope": {"summary": scope.get("summary"), "key": scope.get("key")}, "read_at": time.time()}
    if batch_id:
        _PATH_BATCHES[batch_id] = {"analyses": analyses, "result": result}
        while len(_PATH_BATCHES) > _PATH_BATCHES_MAX:
            _PATH_BATCHES.pop(next(iter(_PATH_BATCHES)))
    return result


@app.post("/api/path-analyzer/batch/start")
async def path_analyzer_batch_start(req: PathBatchRequest, request: Request):
    """Start the Path analyzer for every host of a HAR file as a job the
    page follows (poll GET /api/dlp-packs/jobs/{job_id}). Only what is in
    scope on the Scope page is read, once for all hosts (or the read named
    by `report_id`, when it was made for the same scope and tenant). Stop
    ends it between hosts: the hosts done are kept, the rest listed as not
    analyzed. Read-only."""
    import pack_jobs
    hosts, stats, skipped = _batch_hosts(req)
    scope = _path_scope(req)   # before signing in: nothing in scope reads nothing
    creds = _tenant_creds(req)
    snapshot = _kept_path_read(req.report_id, scope, creds, req.platform)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("path-batch", lambda log, cancel: _run_path_batch(client, req, hosts, stats, skipped, snapshot, label, log, cancel, scope),
                          label=f"{len(hosts)} host(s) from a HAR file", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "hosts": len(hosts), "skipped": len(skipped)}


def _path_batch(job_id: str) -> Dict[str, Any]:
    b = _PATH_BATCHES.get(job_id)
    if b is None:
        raise HTTPException(status_code=404, detail="That HAR analysis is no longer kept (the last few are kept while the server runs). Analyze the file again.")
    return b


@app.get("/api/path-analyzer/batch/{job_id}/host")
async def path_analyzer_batch_host(job_id: str, host: str = ""):
    """One host's full analysis from a finished HAR batch (no tenant call)."""
    a = _path_batch(job_id)["analyses"].get(str(host or "").strip().lower())
    if a is None:
        raise HTTPException(status_code=404, detail="That host was not analyzed in this run.")
    return a


_BATCH_COLUMNS = ("host", "requests", "uploads", "bytes_sent", "methods", "outcome", "stops_at", "deciding_rule", "dlp_rules", "categories", "headline")


@app.get("/api/path-analyzer/batch/{job_id}/export")
async def path_analyzer_batch_export(job_id: str, format: str = "csv"):
    """The HAR batch results as CSV (spreadsheet-safe, csv_safe) or JSON."""
    import csv_safe
    import io
    res = _path_batch(job_id)["result"]
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    if (format or "").lower() == "json":
        body = {k: res.get(k) for k in ("tenant_label", "network", "platform", "counts", "rows", "not_analyzed", "skipped", "errors", "stopped", "scope")}
        return Response(content=json.dumps(body, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=path_har_{ts}.json"})
    buf = io.StringIO()
    w = csv_safe.dict_writer(buf, list(_BATCH_COLUMNS))
    w.writeheader()
    for r in res.get("rows") or []:
        w.writerow({k: ("; ".join(map(str, r.get(k) or [])) if isinstance(r.get(k), list) else r.get(k, "")) for k in _BATCH_COLUMNS})
    for h in res.get("not_analyzed") or []:
        w.writerow({"host": h, "outcome": "not analyzed (stopped)"})
    return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=path_har_{ts}.csv"})


# ── Path analyzer: Test a list (bulk_test) ─────────────────────────────
# The Path analyzer page's "Test a list" view: a CSV of destinations
# (IPs, hosts, URLs, CIDR blocks and ranges, with optional port, protocol,
# source IP, location, country, category, user, label and the expected
# block or allow) is parsed here before sign-in (an untrusted file: size,
# line and row caps), then every row is traced against one tenant read
# (only what is in scope) with ZIA's URL lookup a hundred per request:
# ZPA first when ZPA is ticked (one ZPA read, as /api/path-analyzer/full
# reads it), then every ZIA module for the row's protocol and port.
# The `text` field is recorded in the audit log by its size only.
# Read-only; "Fix selected" only prepares a Bulk changes URL category
# operation, which writes nothing without its own four gates.
_BULK_RUNS: Dict[str, Any] = {}
_BULK_RUNS_MAX = 2


class BulkTestRequest(ScopedTenantCredsRequest):
    """Body of Test a list: the list as text (a CSV file read in the
    browser, or pasted), the network and platform, whether to ask ZIA's
    URL lookup, its request limit for this run, and optionally the ids of
    the tenant and ZPA reads to reuse."""
    text: str = ""
    network: str = "off"
    platform: str = "windows"
    lookup: bool = True
    max_lookup_requests: int = 400
    report_id: str = ""
    zpa_report_id: str = ""
    customer_id: str = ""   # ZPA's customer ID (as the Path analyzer's body carries it)


class BulkFixRequest(ScopedTenantCredsRequest):
    """Body of Fix selected: 1-based row numbers, or an area (url, dns,
    cloud_app), and whether the destinations are to be blocked or allowed."""
    rows: List[int] = []
    area: str = ""
    purpose: str = "block"


def _bulk_parse(req: BulkTestRequest):
    import bulk_test
    if not 1 <= req.max_lookup_requests <= bulk_test.MAX_LOOKUP_REQUESTS:
        raise HTTPException(status_code=400, detail=f"max_lookup_requests must be 1 to {bulk_test.MAX_LOOKUP_REQUESTS}.")
    try:
        return bulk_test.parse(req.text)
    except bulk_test.ListError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _bulk_zpa_inputs(req: BulkTestRequest, creds: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """(ZPA ticked, why it cannot be read, a kept ZPA read for this tenant)
    as /api/path-analyzer/full decides them; never reads a tenant."""
    sc, _ch, _src = _scope_selection(req)
    if "zpa" not in sc:
        return False, "", None
    problem = ""
    if creds.get("auth_method") == tenant_auth.LEGACY:
        problem = "ZPA was not read: the classic ZIA API sign-in reaches ZIA only, so whether ZPA carries each row is unknown."
    elif not validate_customer_id(creds.get("customer_id") or ""):
        problem = "ZPA was not read: the ZPA customer ID is missing (Connect to the tenant → Customer ID), so whether ZPA carries each row is unknown."
    return True, problem, (_path_kept(req.zpa_report_id, "pathzpa", creds) if not problem else None)


def _run_bulk_test(client, req: BulkTestRequest, parsed, snapshot, label: str, log, cancel, scope: Dict[str, Any],
                   zpa: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    import bulk_test
    import pack_jobs
    import path_analyzer
    if scope.get("source"):
        log(f"In scope, from {scope['source']}: {scope['summary']}" + (" ZPA." if zpa else ""))
    rn = bulk_test.run(client, parsed, scope=scope, network=req.network, platform=req.platform, snapshot=snapshot, tenant_label=label,
                       lookup=req.lookup, max_lookup_requests=req.max_lookup_requests, log=log, cancel=cancel, zpa=zpa,
                       progress=pack_jobs.progress)
    s = rn.summary
    cache = s.pop("snapshot_for_cache", None)
    zcache = s.pop("zpa_for_cache", None)
    zrid = (zpa or {}).get("report_id") or ""
    if zcache is not None:
        mask = (zpa or {}).get("mask") or (lambda x: x)
        for v in (zcache["snapshot"].get("collections") or {}).values():
            if v.get("error"):
                v["error"] = mask(v["error"])
        zrid = _remember_report("pathzpa", {"kind": "pathzpa", "snapshot": zcache["snapshot"], "profiles": zcache["profiles"]}, label)
    rid = req.report_id if snapshot is not None else ""
    if cache is not None:
        rid = _remember_report("dataflow", {"summary": {"destinations": 0, "traces": 0, "bypassed": 0, "blind": 0, "enforced": 0, "monitored": 0, "high": 0},
                                            "platform": req.platform, "networks": [n for n in path_analyzer.NETWORKS if n["key"] == req.network],
                                            "platforms": path_analyzer.PLATFORMS, "destinations": [], "traces": [], "packs": [], "required_controls": [],
                                            "diagnostics": cache.get("diagnostics") or [], "client_connector": cache["client_connector"],
                                            "snapshot": cache["snapshot"], "sources": {}, "path_scope": cache.get("path_scope")}, label)
    job = pack_jobs.current()
    run_id = job.id if job is not None else ""
    result = dict(s, status="stopped" if s.get("stopped") else "done", report_id=rid, zpa_report_id=zrid, run_id=run_id, read_at=time.time())
    if run_id:
        _BULK_RUNS[run_id] = rn
        while len(_BULK_RUNS) > _BULK_RUNS_MAX:
            _BULK_RUNS.pop(next(iter(_BULK_RUNS)))
    return result


@app.post("/api/bulk-test/start")
async def bulk_test_start(req: BulkTestRequest, request: Request):
    """Test a list of destinations as a job the page follows (poll GET
    /api/dlp-packs/jobs/{job_id}). The list is parsed before sign-in (400
    for one that cannot be tested); only what is in scope on the Scope
    page is read, once for every row (or the read `report_id` names, when
    it was made for the same scope and tenant): ZPA first when it is ticked
    (or the ZPA read `zpa_report_id` names, for the same tenant), then ZIA.
    Stop keeps the rows tested. Read-only: the URL lookup is a POST that
    changes nothing."""
    import data_flow
    import pack_jobs
    parsed = await asyncio.to_thread(_bulk_parse, req)
    sc, ch, src = _scope_selection(req)   # before signing in: nothing in scope reads nothing
    scope = data_flow.path_scope(sc, ch)
    scope["source"] = src
    if not scope["read"] and "zpa" not in sc:
        raise HTTPException(status_code=400, detail=PATH_NOTHING)
    creds = _tenant_creds(req)
    zpa_on, zpa_problem, zpa_kept = _bulk_zpa_inputs(req, creds)
    if not scope["read"] and zpa_problem:
        raise HTTPException(status_code=400, detail=zpa_problem.replace("ZPA was not read: ", "ZPA cannot be read: ") + " Nothing was read.")
    snapshot = _kept_path_read(req.report_id, scope, creds, req.platform) if scope["read"] else None
    client = await asyncio.to_thread(_build_client, req) if scope["read"] else None
    label = tenant_auth.record_label(creds)
    zpa: Optional[Dict[str, Any]] = None
    if zpa_on and zpa_problem:
        zpa = {"problem": zpa_problem}
    elif zpa_kept is not None:
        zpa = {"snapshot": zpa_kept["snapshot"], "profiles": zpa_kept["profiles"], "report_id": zpa_kept["report_id"]}
    elif zpa_on:
        sdk = await asyncio.to_thread(_build_sdk_client, creds)
        zpa = {"client": sdk, "mask": lambda x: tenant_auth.mask_secrets(str(x), creds)}
    job = pack_jobs.start("bulk-test", lambda log, cancel: _run_bulk_test(client, req, parsed, snapshot, label, log, cancel, scope, zpa),
                          label=f"{len(parsed)} destination(s) from a list", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "rows": len(parsed), "skipped": parsed.skipped_count}


def _bulk_run(job_id: str):
    rn = _BULK_RUNS.get(str(job_id))
    if rn is None:
        raise HTTPException(status_code=404, detail="That list's results are no longer kept (the last two are kept while the server runs). Test the list again.")
    return rn


@app.get("/api/bulk-test/{job_id}/export")
async def bulk_test_export(job_id: str, format: str = "csv", rows: str = "all"):
    """A tested list as CSV (every row, spreadsheet-safe through csv_safe)
    or Excel (xlsx_writer; the results sheet holds the first 100,000 rows):
    all rows, the flagged ones or the ones not as expected. No tenant call."""
    import bulk_test
    rn = _bulk_run(job_id)
    which = rows if rows in bulk_test.ROW_FILTERS else None
    fmt = (format or "").lower()
    if which is None or fmt not in ("csv", "xlsx"):
        raise HTTPException(status_code=400, detail="format is csv or xlsx; rows is all, flagged or unmet.")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    name = f"path_list_{which}_{ts}"
    if fmt == "xlsx":
        data, _cut = await asyncio.to_thread(bulk_test.workbook, rn, which)
        import xlsx_writer
        return Response(content=data, media_type=xlsx_writer.MEDIA_TYPE, headers={"Content-Disposition": f"attachment; filename={name}.xlsx"})
    return StreamingResponse(bulk_test.csv_lines(rn, which), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f"attachment; filename={name}.csv"})


@app.get("/api/bulk-test/{job_id}/list")
async def bulk_test_area_list(job_id: str, area: str = "", purpose: str = "block"):
    """The destinations to paste for one area (atp, firewall, url, dns,
    client_connector, cloud_app) and purpose (block or allow), one per
    line, as plain text. No tenant call."""
    import bulk_test
    rn = _bulk_run(job_id)
    if area not in bulk_test.AREA_KEYS or purpose not in ("block", "allow"):
        raise HTTPException(status_code=400, detail=f"area is one of {', '.join(bulk_test.AREA_KEYS)}; purpose is block or allow.")
    lines = bulk_test.area_list(rn, area, purpose)
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""), headers={"Content-Disposition": f"attachment; filename=path_list_{area}_{purpose}.txt"})


@app.post("/api/bulk-test/{job_id}/fix")
async def bulk_test_fix(job_id: str, req: BulkFixRequest):
    """Fix selected: the chosen destinations as a URL category operation
    for the Bulk changes page to preview (it opens with /report/operations
    ?fix=<id>). Refused (400) when custom URL categories are not in scope.
    Writes nothing: Bulk changes applies only in write mode, for a writer,
    with the assessor's name and the typed confirmation."""
    import bulk_test
    _ops_scope(req, "url_categories")
    rn = _bulk_run(job_id)
    try:
        rec = bulk_test.fix_handoff(rn, rows=req.rows, area=req.area, purpose=req.purpose)
    except bulk_test.ListError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"fix_id": rec["id"], "urls": len(rec["urls"]), "excluded": rec["excluded"], "over_limit": rec["over_limit"],
            "open": f"/report/operations?fix={rec['id']}", "note": rec["note"]}


@app.get("/api/bulk-test/fix/{fix_id}")
async def bulk_test_fix_get(fix_id: str):
    """A Fix selected hand-off for the Bulk changes page (kept an hour)."""
    import bulk_test
    rec = bulk_test.get_fix(fix_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="That hand-off is no longer kept (an hour). Pick the rows again on the Path analyzer's Test a list view.")
    return {k: rec[k] for k in ("urls", "excluded", "over_limit", "purpose", "note")}


# ── Audit timeline ────────────────────────────────────────────────────
@app.get("/report/audit")
async def report_audit_page():
    """Audit timeline (static/report_audit.html): ZIA's admin audit log
    merged with Zscaler Made Easy's deployments and its own audit log."""
    page = os.path.join(STATIC_DIR, "report_audit.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class AuditTimelineRequest(ScopedTenantCredsRequest):
    """Body of the audit timeline: the window (`days` back from now, or
    `start` / `end` dates) and whether to read ZIA's admin audit log
    (`include_zia`; needs Automation readiness in scope on the Scope page)."""
    days: int = 7
    start: str = ""
    end: str = ""
    include_zia: bool = True


def _run_audit_timeline(client, win: Dict[str, Any], include_zia: bool, label: str, labels, log, cancel) -> Dict[str, Any]:
    """Read ZIA's audit log report (when asked), Zscaler Made Easy's deployment
    records and its audit log, and merge them (audit_timeline.build)."""
    import audit_timeline as at
    import data_flow
    import deployments
    import pack_deploy
    zia = None
    if include_zia:
        try:
            with data_flow.stop_on(client, cancel):
                zia = at.read_zia_audit(client, win["start_ms"], win["end_ms"], log=log, cancel=cancel)
        except at.Stopped as e:
            log("STOPPED — you clicked Stop; nothing more was asked of ZIA. Nothing is ever written by this page.")
            return {"stopped": str(e), "status": "stopped", "tenant_label": label}
        if zia.get("error"):
            log(zia["error"])
    log("Reading Zscaler Made Easy's deployment records and its own audit log…")
    deps = deployments.list_all()
    entries = _audit.tail(50000)
    out = at.build(window_=win, zia=zia, deployments=deps, audit_entries=entries, labels=labels, known_packs=pack_deploy.library_ids(),
                   tenant_label=label, zia_requested=include_zia,
                   zia_reason="" if include_zia else "The ZIA admin audit log was not read (you chose Zscaler Made Easy's own records only).")
    log(f"{out['summary']['events']} event(s) in the window; {out['summary']['foreign_changes']} change(s) by someone else to objects Zscaler Made Easy created.")
    return out


@app.post("/api/audit-timeline/start")
async def audit_timeline_start(req: AuditTimelineRequest, request: Request):
    """Start the audit timeline as a job the page follows (poll GET
    /api/dlp-packs/jobs/{job_id}). ZIA's admin audit log is read only with
    `include_zia` and Automation readiness in scope (its permissions list
    /zia/auditlogEntryReport, scope_permissions.py); otherwise the request
    is refused (400) before anything is signed in to. Reading it creates an
    audit log report (POST /auditlogEntryReport): that changes no
    configuration, so it is a read here and needs no write mode. Stop ends
    the job with nothing more asked of ZIA."""
    import audit_timeline as at
    import pack_jobs
    try:
        win = at.window(req.days, req.start, req.end)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    client, label, labels = None, "", None
    if req.include_zia:
        _require_in_scope(req, "automation", "The ZIA admin audit log")   # user rule 1: before any sign-in
        creds = _tenant_creds(req)
        client = await asyncio.to_thread(_build_client, req)
        label, labels = tenant_auth.record_label(creds), list(tenant_auth.record_labels(creds))
    job = pack_jobs.start("audit-timeline", lambda log, cancel: _run_audit_timeline(client, win, req.include_zia, label, labels, log, cancel),
                          label=f"audit timeline, {win['days']:g} day(s)", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "window": {k: win[k] for k in ("start", "end", "days")}}


@app.get("/api/audit-timeline/{job_id}/export")
async def audit_timeline_export(job_id: str, format: str = "csv"):
    """A finished timeline as CSV (spreadsheet-safe, csv_safe) or JSON
    (every event with its raw ZIA row, pre / post values and diff)."""
    import audit_timeline as at
    import pack_jobs
    job = pack_jobs.get(job_id)
    if job is None or job.kind != "audit-timeline" or not isinstance(job.result, dict) or "events" not in job.result:
        raise HTTPException(status_code=404, detail="That timeline is no longer kept (jobs are kept for an hour). Build it again.")
    res = job.result
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    if (format or "").lower() == "json":
        return Response(content=json.dumps(res, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=audit_timeline_{ts}.json"})
    return Response(content=at.to_csv(res["events"]), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=audit_timeline_{ts}.csv"})


# ── Flow animator ─────────────────────────────────────────────────────
@app.get("/report/motion")
async def report_motion_page():
    """Flow animator (static/report_motion.html): the path, DLP decision,
    deployment, live-incident and reference-architecture flows animated
    from results the other pages produce. Reads nothing on its own."""
    page = os.path.join(STATIC_DIR, "report_motion.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Shadowed rules ────────────────────────────────────────────────────
@app.get("/report/shadow")
async def report_shadow_page():
    """Shadowed rules (static/report_shadow.html): rules that can never
    match or never act, per policy type, read live from the tenant."""
    page = os.path.join(STATIC_DIR, "report_shadow.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Simple mode ───────────────────────────────────────────────────────
@app.get("/simple")
async def simple_mode_page():
    """Simple mode (static/simple.html): seven big tasks in plain words, each
    a short wizard over the same endpoints the expert pages use. Anything
    that would change the tenant is handed to the expert page's own flow
    (write mode, preview, confirmation); this page never writes."""
    page = os.path.join(STATIC_DIR, "simple.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="simple mode page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


class ShadowRulesRequest(ScopedTenantCredsRequest):
    """Body of the shadowed-rule analysis: tenant credentials, what is in
    scope (the Scope page's `scopes` and `channels`, else the profile's
    saved selection) and, optionally, the Inline Web DLP evaluation mode
    when the operator knows it: "" reads it from DLP Advanced Settings,
    "rule_order" or "evaluate_all" declares it (the API does not expose
    the setting on every tenant)."""
    web_dlp_mode: str = ""


_SHADOW_MODES = ("", "rule_order", "evaluate_all", "evaluate_all_rules")


def _shadow_inputs(req: ShadowRulesRequest) -> Dict[str, Any]:
    """What the analysis may read (shadow_rules.scope_for of the Scope
    page's selection). 400 before signing in when the mode is not one we
    know or when nothing it reads is in scope (user rule 1)."""
    import shadow_rules
    if str(req.web_dlp_mode or "").strip().lower() not in _SHADOW_MODES:
        raise HTTPException(status_code=400, detail="web_dlp_mode must be empty (read it from the tenant), 'rule_order' or 'evaluate_all'.")
    sc, ch, source = _scope_selection(req)
    scope = shadow_rules.scope_for(sc, ch)
    if not scope["read"]:
        raise HTTPException(status_code=400, detail=shadow_rules.NOTHING_IN_SCOPE)
    scope["source"] = source
    return scope


def _run_shadow_rules(client, req: ShadowRulesRequest, scope: Dict[str, Any], label: str, log, cancel) -> Dict[str, Any]:
    """Read only what `scope` puts in scope and analyse it (shadow_rules).
    Read-only: GET requests only. Stop (`cancel`) ends the run as stopped:
    nothing more is read and no partial result is returned."""
    import shadow_rules
    logs: List[str] = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    _log(f"Reading {label}. Nothing is written to the tenant. " + (f"In scope, from {scope['source']}: " if scope.get("source") else "") + scope["summary"])
    try:
        out = shadow_rules.run(client, scope, declared_mode=req.web_dlp_mode, log=_log, cancel=cancel)
    except shadow_rules.Stopped as e:
        _log("STOPPED — you clicked Stop; nothing more was read and no partial result is kept.")
        return {"stopped": str(e), "status": "stopped", "tenant_label": label, "logs": logs}
    if cancel is not None and cancel.is_set():
        _log("STOPPED — you clicked Stop; the analysis was abandoned.")
        return {"stopped": shadow_rules.STOPPED_REASON, "status": "stopped", "tenant_label": label, "logs": logs}
    out.update(status="done", tenant_label=label, generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), logs=logs)
    return out


@app.post("/api/shadow-rules/start")
async def shadow_rules_start(req: ShadowRulesRequest, request: Request):
    """Find the rules that can never match or never act (shadowed, after a
    catch-all, duplicate, superseded, disabled, naming objects that no
    longer exist), per policy type in scope, as a job the page follows.
    Poll GET /api/dlp-packs/jobs/{job_id}; the result is {findings,
    counts_by_policy, read_errors, not_in_scope, mode, ...}. Read-only."""
    import pack_jobs
    scope = _shadow_inputs(req)   # before signing in: nothing in scope reads nothing
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    label = tenant_auth.record_label(creds)
    job = pack_jobs.start("shadow", lambda log, cancel: _run_shadow_rules(client, req, scope, label, log, cancel),
                          label=label[:80], actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/shadow-rules")
async def shadow_rules_run(req: ShadowRulesRequest):
    """The same analysis, waited for (for scripts)."""
    scope = _shadow_inputs(req)
    creds = _tenant_creds(req)
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(_run_shadow_rules, client, req, scope, tenant_auth.record_label(creds), None, None)


@app.get("/api/shadow-rules/jobs/{job_id}/export")
async def shadow_rules_export(job_id: str, format: str = "csv"):
    """A finished analysis's findings as CSV (every cell through csv_safe)
    or as the JSON result."""
    import pack_jobs
    import shadow_rules
    job = pack_jobs.get(job_id)
    if job is None or job.kind != "shadow":
        raise HTTPException(status_code=404, detail="No such analysis. Results are kept for an hour after they finish; run it again.")
    res = job.result or {}
    if res.get("status") != "done":
        raise HTTPException(status_code=409, detail="This analysis has no result to export" + (" yet; it is still running." if job.status == pack_jobs.RUNNING else "."))
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    if (format or "").lower() == "json":
        body = {k: v for k, v in res.items() if k != "logs"}
        return Response(content=json.dumps(body, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=shadowed_rules_{ts}.json"})
    return Response(content=shadow_rules.to_csv(res), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=shadowed_rules_{ts}.csv"})


# ── Posture: improve my score, projected score, trend, alerts, coverage ──
# Pure computation (posture_plus.py) on the results the page already holds,
# the tenant profile's history and the team change queue on this server.
# Nothing here reads or writes a tenant.
@app.get("/report/posture")
async def report_posture_page():
    """Improve my score (static/report_posture.html): the fixes that raise
    the score most, the projected score, the trend with its causes and what
    the last assessment could not check. Reads nothing from the tenant."""
    page = os.path.join(STATIC_DIR, "report_posture.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


# ── Self-healing (self_heal.py) ───────────────────────────────────────
# Layer 1: the app repairs itself (stuck jobs, damaged stores, permissions,
# stale locks, rate holds, cached sign-ins, disk space, version) at startup,
# on a light timer (DLP_CHECK_SELF_HEAL_MINUTES, default 10, 0 off) and on
# demand; nothing is written to the tenant. Layer 2: the tenant heals back
# to what was approved: a scan (read-only, DLP in scope) raises heal
# proposals; each is applied only when a person clicks Heal, through the
# proposal apply path (write mode, re-read, typed confirmation, read-back,
# rollback). Automatic application is refused in this version.
@app.get("/report/self-heal")
async def report_self_heal_page():
    """Self-healing (static/report_self_heal.html): what the app fixed by itself, and the tenant settings that drifted."""
    page = os.path.join(STATIC_DIR, "report_self_heal.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


_POSTURE_MAX_CHECKS = 3000


class PostureRequest(BaseModel):
    """The results the page holds (checks, hidden_checks, channel_coverage),
    the tenant profile whose history to use, the fixes ticked on the page,
    and whether (and for which tenant) to count fixes staged in the change queue."""
    checks: List[Dict[str, Any]] = []
    hidden_checks: int = 0
    channel_coverage: Optional[Dict[str, Any]] = None
    profile_id: str = ""
    selected: List[str] = []
    include_queue: bool = True
    queue_tenant: str = ""
    logs: List[str] = []
    limit: int = 10


def _posture_checks(req: PostureRequest) -> List[Dict[str, Any]]:
    if len(req.checks or []) > _POSTURE_MAX_CHECKS:
        raise HTTPException(status_code=413, detail=f"Too many results ({len(req.checks)}); at most {_POSTURE_MAX_CHECKS}.")
    out = []
    for c in req.checks or []:
        if not isinstance(c, dict):
            continue
        row = {k: c.get(k) for k in ("id", "sec", "section", "label", "status", "out_of_scope", "channel") if c.get(k) is not None}
        for k in ("sec", "section", "channel"):   # grouped and counted by: text, never a list or an object (unhashable, 500)
            if k in row:
                row[k] = str(row[k])[:120]
        if "out_of_scope" in row:
            row["out_of_scope"] = row["out_of_scope"] is True
        row["id"] = str(row.get("id") or "")[:32]
        row["label"] = str(row.get("label") or "")[:200]
        row["status"] = str(row.get("status") or "").upper()[:10]
        row["detail"] = str(c.get("detail") or "")[:600]
        plain = c.get("plain")
        if isinstance(plain, dict) and plain.get("do"):
            row["plain"] = {"do": str(plain.get("do"))[:1200]}
        if row["id"]:
            out.append(row)
    return out


def _posture_history(profile_id: str) -> List[Dict[str, Any]]:
    if not profile_id:
        return []
    try:
        import tenant_profiles
        return list((tenant_profiles.get(str(profile_id)[:80]) or {}).get("history") or [])
    except Exception:  # noqa: BLE001
        return []


def _posture_queue(req: PostureRequest) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]], str]:
    """(open requests of the chosen tenant, the tenants with open requests, the tenant used)."""
    if not req.include_queue:
        return [], [], ""
    try:
        import change_queue
        items = change_queue.list_requests("", ["pending", "approved"])
    except Exception:  # noqa: BLE001
        return [], [], ""
    tenants: Dict[str, str] = {}
    for r in items:
        tenants.setdefault(str(r.get("tenant")), str(r.get("tenant_label") or r.get("tenant")))
    chosen = str(req.queue_tenant or "").strip().lower()
    if not chosen and len(tenants) == 1:
        chosen = next(iter(tenants))
    return ([r for r in items if str(r.get("tenant")) == chosen] if chosen else [],
            [{"key": k, "label": v} for k, v in sorted(tenants.items(), key=lambda kv: kv[1])], chosen)


def _posture_digest_alerts(profile_id: str) -> List[Dict[str, Any]]:
    """The score-drop alerts the latest digest raised for this profile."""
    if not profile_id:
        return []
    try:
        import continuous_eval
        last = continuous_eval.list_digests(1)
        d = continuous_eval.get_digest(str(last[0]["id"])) if last else None
    except Exception:  # noqa: BLE001
        return []
    out = []
    for t in (d or {}).get("tenants") or []:
        if t.get("profile_id") == profile_id:
            out.extend(dict(a, digest=d.get("id")) for a in t.get("score_alerts") or [])
    return out


@app.post("/api/posture/analyze")
async def posture_analyze(req: PostureRequest):
    """Everything the Improve my score page shows, from the results sent:
    the ranked fixes, the projected score (ticked fixes and staged fix
    recipes), the trend from the profile's history, the score-drop alert
    and the coverage list. No tenant read."""
    import posture_plus as pp
    checks = _posture_checks(req)
    history = _posture_history(req.profile_id)
    queue, queue_tenants, chosen = _posture_queue(req)
    report = {"checks": checks, "hidden_checks": req.hidden_checks, "channel_coverage": req.channel_coverage or {}}
    cfg = pp.settings()
    return {"ranking": pp.ranking(checks, limit=max(1, min(50, int(req.limit or 10)))),
            "projection": pp.project(checks, req.selected, queue),
            "queue": {"tenants": queue_tenants, "tenant": chosen},
            "trend": pp.trend(history, checks),
            "alert": pp.latest_drop(history, cfg["score_drop_points"], checks),
            "digest_alerts": _posture_digest_alerts(req.profile_id),
            "coverage": pp.coverage(report, (req.logs or [])[:2000]),
            "settings": cfg}


@app.post("/api/posture/project")
async def posture_project(req: PostureRequest):
    """The score after the ticked fixes and the staged fix recipes (no tenant read)."""
    import posture_plus as pp
    queue, queue_tenants, chosen = _posture_queue(req)
    return dict(pp.project(_posture_checks(req), req.selected, queue), queue_tenants=queue_tenants, queue_tenant=chosen)


@app.post("/api/posture/summary")
async def posture_summary(req: PostureRequest):
    """The main page's coverage line and score-drop banner (no tenant read)."""
    import posture_plus as pp
    checks = _posture_checks(req)
    history = _posture_history(req.profile_id)
    cov = pp.coverage({"checks": checks, "hidden_checks": req.hidden_checks, "channel_coverage": req.channel_coverage or {}})
    cfg = pp.settings()
    return {"coverage": {k: cov[k] for k in ("total", "ran", "not_ran", "pct", "hidden", "sentence", "by_category")},
            "alert": pp.latest_drop(history, cfg["score_drop_points"], checks),
            "digest_alerts": _posture_digest_alerts(req.profile_id), "settings": cfg}


class PostureSettings(BaseModel):
    """The score-drop alert: threshold in points, and whether a drop alone may make the digest send a notification."""
    score_drop_points: int = 5
    notify_score_drop: bool = False


@app.get("/api/posture/settings")
async def posture_settings_get():
    import posture_plus as pp
    return pp.settings()


@app.put("/api/posture/settings")
async def posture_settings_put(req: PostureSettings, request: Request):
    """Save the score-drop alert settings (a local file next to the app;
    nothing is sent anywhere). A server-wide setting, so under SSO only a
    listed writer may change it."""
    import posture_plus as pp
    _security.require_writer()
    saved = await asyncio.to_thread(pp.save_settings, req.model_dump())
    _audit.record("posture_settings", actor=_actor(request) or _security.current_actor(), **saved)
    return saved
@app.get("/api/self-heal")
async def self_heal_status():
    """The last self-healing run (each check: ok / healed / needs you, what
    was done, the next step), the settings and how many tenant heal
    proposals are open. Local data only: nothing is read from a tenant."""
    import self_heal
    return await asyncio.to_thread(self_heal.overview)


@app.post("/api/self-heal/run")
async def self_heal_run(request: Request):
    """Run the app's self-healing checks now. Repairs local files and jobs
    only; never touches a tenant. Audited (self_heal_run, with who asked)."""
    import self_heal
    return await asyncio.to_thread(self_heal.run, "manual", _actor(request) or _security.current_actor())


async def _self_heal_loop(minutes: float) -> None:
    import self_heal
    try:
        await asyncio.sleep(5)
        await asyncio.to_thread(self_heal.run, "startup")
        while True:
            await asyncio.sleep(minutes * 60)
            await asyncio.to_thread(self_heal.run, "timer")
    except asyncio.CancelledError:
        return
    except Exception:  # noqa: BLE001 - the timer never takes the server down
        return


@app.on_event("startup")
async def _start_self_heal() -> None:
    try:
        import self_heal
        self_heal.mark_started()
        minutes = self_heal.interval_minutes()
        if minutes > 0:
            asyncio.create_task(_self_heal_loop(minutes))
    except Exception:  # noqa: BLE001 - self-healing never stops the app starting
        pass


class SelfHealScanRequest(ScopedTenantCredsRequest):
    """Scan the tenant for settings that drifted from what was approved: the
    packs to measure (else the profile's ticked packs, else the packs this
    app deployed to the tenant), and whether to read who changed them from
    ZIA's admin audit log (needs Automation readiness in scope)."""
    pack_ids: List[str] = []
    include_who: bool = False
    days: int = 7


class SelfHealHealRequest(ScopedTenantCredsRequest):
    """Heal selected drifts: the heal proposal ids and the typed confirmation phrase."""
    ids: List[str] = []
    confirm: str = ""


class SelfHealAcceptRequest(ScopedTenantCredsRequest):
    """Accept a drift (stop proposing it): the heal proposal id and an optional note."""
    id: str = ""
    note: str = ""


def _self_heal_tenant(req: Any) -> Tuple[List[str], Dict[str, str], str, str]:
    """(DLP channels in scope, credentials, queue key, label). The DLP scope
    is checked first: nothing in scope is refused (400) before anything is
    signed in to or read (user rule 1)."""
    channels = _pack_channels_in_scope(req, "Self-healing for the tenant")
    creds = _tenant_creds(req)
    tk, label = _cq_tenant(creds)
    return channels, creds, tk, label


def _self_heal_packs(req: SelfHealScanRequest, channels: List[str], label: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    """The packs to measure: the request's, else the profile's ticked packs,
    else the packs this app deployed to this tenant; each on its own DLP
    channels that are in scope (_journey_scope)."""
    import deployments
    ids = [str(x) for x in req.pack_ids or [] if x]
    if not ids and req.profile_id:
        try:
            import tenant_profiles
            ids = [str(x) for x in (tenant_profiles.get(req.profile_id) or {}).get("baseline_packs") or [] if x]
        except Exception:  # noqa: BLE001
            ids = []
    if not ids:
        seen: List[str] = []
        for r in deployments.list_all(label):
            for pid in r.get("packs") or []:
                if pid not in seen:
                    seen.append(pid)
        ids = seen
    _sc, ch, _src = _scope_selection(req)
    return _journey_scope(ids, ch)


def _self_heal_scan_job(client, packs, targets, channels, casb, tk, labels, include_who, days, log, cancel) -> Dict[str, Any]:
    import self_heal
    import zia_rate
    who = None
    with zia_rate.using_client(client):
        if include_who:
            import audit_timeline as at
            import data_flow
            import deployments
            import pack_deploy
            win = at.window(max(1, min(int(days or 7), 30)))
            try:
                with data_flow.stop_on(client, cancel):
                    z = at.read_zia_audit(client, win["start_ms"], win["end_ms"], log=log, cancel=cancel)
                created = [c for r in deployments.list_all() for c in at._created(r)]
                who = at.zia_events(((z or {}).get("csv") or {}).get("rows") or [], created, [], pack_deploy.library_ids())
                if z.get("error"):
                    log(f"Who changed it: {z['error']}")
            except at.Stopped:
                log("STOPPED — you clicked Stop; nothing more was read. Nothing is ever written by a scan.")
                return {"stopped": "stopped before the scan", "status": "stopped"}
        if cancel.is_set():
            return {"stopped": "stopped before the scan", "status": "stopped"}
        log("Reading the ticked packs' objects from the tenant (read-only)…")
        res = self_heal.scan(client, packs, tenant_key=tk, labels=labels, channels=channels, channel_targets=targets,
                             casb=casb, who_events=who, log=log)
    res["view"] = self_heal.tenant_view(tk)
    res.pop("items", None)
    return res


@app.post("/api/self-heal/tenant/scan")
async def self_heal_tenant_scan(req: SelfHealScanRequest, request: Request):
    """Compare the tenant with what was approved and raise a heal proposal
    for every setting that drifted back. A job (poll GET
    /api/dlp-packs/jobs/{id}). Read-only: nothing is written to the tenant.
    DLP must be in scope (400 before any sign-in otherwise); who changed it
    is read from ZIA's admin audit log only with include_who and Automation
    readiness in scope."""
    import channel_scope
    import pack_jobs
    channels, creds, tk, label = _self_heal_tenant(req)
    if req.include_who:
        _require_in_scope(req, "automation", "Who changed it (ZIA's admin audit log)")
    packs, targets = _self_heal_packs(req, channels, label)
    if not packs:
        raise HTTPException(status_code=400, detail=("No policy pack to measure: tick the packs you approved on the tenant profile, or deploy one, "
                                                     "and mark its DLP channels as Zscaler on the Scope page. Nothing was read."))
    _sc, ch, _src = _scope_selection(req)
    casb = "saas_casb" in channel_scope.in_scope(ch)
    client = await asyncio.to_thread(_build_sdk_client, creds)
    labels = list(tenant_auth.record_labels(creds))

    def fn(log, cancel):
        try:
            return _self_heal_scan_job(client, packs, targets, channels, casb, tk, labels, req.include_who, req.days, log, cancel)
        finally:
            _close_quietly(client)
    job = pack_jobs.start("self-heal-scan", fn, label=f"self-healing scan, {len(packs)} pack(s)", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind, "tenant": tk, "tenant_label": label, "packs": [p["id"] for p in packs]}


@app.post("/api/self-heal/tenant/view")
async def self_heal_tenant_view(req: ScopedTenantCredsRequest):
    """The tenant's heal proposals, last scan and accepted drifts (local
    data; nothing is signed in to or read). DLP must be in scope, like the drift step."""
    import self_heal
    _channels, _creds, tk, label = _self_heal_tenant(req)
    out = await asyncio.to_thread(self_heal.tenant_view, tk)
    out["tenant_label"] = label
    out["writes_enabled"] = writes_enabled()
    return out


@app.post("/api/self-heal/tenant/heal")
async def self_heal_tenant_heal(req: SelfHealHealRequest, request: Request):
    """Heal the selected drifts, one by one, through the proposal apply path:
    each is approved with the typed confirmation, then applied (write mode,
    a preview that re-reads the rule and refuses when it moved again, the
    update, read-back, recorded rollback). Only one-click heals (a rule's
    state or action) on DLP channels in scope; nothing else is written."""
    import proposal_apply
    import proposals
    channels, creds, tk, label = _self_heal_tenant(req)
    _security.require_writer()
    if not writes_enabled():
        raise HTTPException(status_code=403, detail=_writes_disabled_msg())
    if not _security.typed_phrase_matches(req.confirm, proposals.CONFIRM_PHRASE):
        raise HTTPException(status_code=400, detail=f'Healing changes the tenant: type "{proposals.CONFIRM_PHRASE}" to confirm.')
    _require_write_assessor(req)
    ids = [str(x) for x in req.ids or [] if x][:50]
    if not ids:
        raise HTTPException(status_code=400, detail="Select at least one drift to heal.")
    todo, results = [], []
    for pid in ids:
        p = proposals.get(tk, pid)
        why = ("not found (scan again)" if not p else "not a heal proposal" if p.get("kind") != "heal_drift"
               else "made by hand, not from here (follow its steps)" if (p.get("change") or {}).get("apply") != "rule"
               else f"its channel ({p.get('channel')}) is not in scope on the Scope page" if p.get("channel") not in channels
               else f"it is {p.get('status')}" if p.get("status") not in ("open", "approved") else "")
        if why:
            results.append({"id": pid, "ok": False, "status": "refused", "why": why})
        else:
            todo.append(p)
    by = (_actor(request) or _security.current_actor() or "")[:80]
    if todo:
        client = await asyncio.to_thread(_build_sdk_client, creds)
        try:
            for p in todo:
                try:
                    if p.get("status") == "open":
                        proposals.decide(tk, p["id"], "approve", by=by, note="heal", confirm=req.confirm)
                    logs: List[str] = []
                    out = await asyncio.to_thread(lambda: proposal_apply.apply(client, tk, p["id"], writes_enabled=True, by=by, log=logs.append))
                    results.append({"id": p["id"], "ok": bool(out.get("ok")), "status": out.get("status"), "title": p.get("title"),
                                    "results": out.get("results"), "activation": out.get("activation"), "logs": logs})
                except (ValueError, PermissionError) as e:
                    results.append({"id": p["id"], "ok": False, "status": "refused", "title": p.get("title"), "why": str(e)[:300]})
        finally:
            await asyncio.to_thread(_close_quietly, client)
    _audit.record("self_heal_heal", tenant=label, by=by, healed=[r["id"] for r in results if r.get("ok")],
                  refused=[r["id"] for r in results if not r.get("ok")])
    import self_heal
    return {"results": results, "healed": sum(1 for r in results if r.get("ok")), "view": self_heal.tenant_view(tk),
            "undo": "Each healed item can be rolled back from the proposal queue (Roll back), with the same re-read and read-back."}


@app.post("/api/self-heal/tenant/accept")
async def self_heal_tenant_accept(req: SelfHealAcceptRequest, request: Request):
    """Accepted - stop proposing: the current value becomes the approved one
    for this tenant and the heal proposal is dismissed. Audited. Nothing is
    read from or written to the tenant."""
    import self_heal
    _channels, _creds, tk, label = _self_heal_tenant(req)
    by = (_actor(request) or _security.current_actor() or "")[:80]
    try:
        await asyncio.to_thread(self_heal.accept, tk, req.id, by=by, note=req.note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    out = await asyncio.to_thread(self_heal.tenant_view, tk)
    out["tenant_label"] = label
    return out


@app.post("/api/self-heal/tenant/auto-apply")
async def self_heal_auto_apply():
    """Applying heals without a person is not enabled in this version, whatever DLP_CHECK_SELF_HEAL_AUTO_APPLY says."""
    import self_heal
    raise HTTPException(status_code=403, detail=self_heal.auto_apply()["why"])


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
    """Body of the Path analyzer (POST /api/path-analyzer/start and the
    waited-for POST /api/path-analyzer): what the user would type, the
    network the device is on, the platform, the traffic (protocol and
    port), the what-if identity, where the traffic comes from (a user
    device, or a workload behind a Cloud or Branch Connector), the ids of
    the tenant reads to reuse, and what is in scope: the Scope page's
    ticked `scopes` and its channel declaration (`channels`, {id: choice}).
    With neither, and `from_page` false, the chosen profile's saved
    selection is used; with nothing in scope the request is refused before
    anything is read."""
    destination: str = ""
    network: str = "off"
    platform: str = "windows"
    report_id: str = ""            # the ZIA (and Client Connector) read to reuse
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False
    # The traffic (zia_path_modules.traffic_context, the one place it is
    # checked, before sign-in): protocol "tcp", "udp" or "" (the URL's
    # scheme decides, else TCP); port 1-65535 as a number or a numeric
    # string, or nothing (the URL's port, else its scheme's, else 443).
    protocol: str = ""
    port: Optional[Union[str, int]] = None
    identity: Dict[str, Any] = {}  # what-if: {user, group, department, location} (path_whatif)
    source: str = "device"         # "device" (Client Connector) or "workload" (Cloud or Branch Connector)
    workload: Dict[str, Any] = {}  # ip, tags, workload_group, connector_group (workload_path.workload_input)
    zpa_report_id: str = ""        # the ZPA read to reuse
    ztw_report_id: str = ""        # the Cloud & Branch Connector read to reuse

    @field_validator("protocol", mode="before")
    @classmethod
    def _protocol(cls, v: Any) -> Any:
        return v.strip().lower()[:8] if isinstance(v, str) else ("" if v is None else v)

    @field_validator("port", mode="before")
    @classmethod
    def _port(cls, v: Any) -> Any:
        # A number or a numeric string becomes an int; another scalar is
        # kept as text so the route refuses it in words (400); a list or an
        # object is the wrong type (422).
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        if isinstance(v, int) and not isinstance(v, bool):
            return v
        if isinstance(v, str) and v.strip().isdigit() and len(v.strip()) <= 6:
            return int(v.strip())
        return str(v)[:12] if isinstance(v, (str, bool, float)) else v


class FlowScenarioRequest(MigrateRequest):
    """One explicit local test/configuration scenario; never generates traffic."""
    scenario_id: str = ""
    channel: str = "web"
    destination: str = ""
    operation: str = ""
    file_type: str = ""
    network: str = "off"
    platform: str = "windows"
    corpus: str = ""


@app.post("/api/flow/scenario")
async def flow_scenario(req: FlowScenarioRequest, request: Request):
    """Compose scoped read-only configuration and optional local simulation.

    No incident polling, traffic submission, tenant writes or old-browser
    result joins happen as a side effect. Excluded stages stay visible.
    """
    import scenario_flow
    import channel_scope
    import data_flow
    import dlp_efficacy
    import corpus_engines
    import path_analyzer
    import tenant_fingerprint
    try:
        context = scenario_flow.normalize_input(req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    sc, ch, source = _scope_selection(req)
    import dlp_analysis
    analysis_channels = dlp_analysis.channels(ch, sc)
    allowed = channel_scope.in_scope(analysis_channels)
    selected_key, endpoint, _ = scenario_flow.CHANNELS[context["channel"]]
    scope = data_flow.path_scope(sc, ch)
    scope["source"] = source
    scope.update(scopes=sc, required_controls=dlp_analysis.requirements(sc, ch, tested_channel=context["channel"]), channel_enabled="dlp" in sc and selected_key in allowed,
                 workflow_enabled="workflow_automation" in allowed)
    # Keep the complete scope identity distinct from the tracer's read key.
    response_scope = dict(scope, key=scenario_flow.scope_key(sc, ch))
    needs_path = context["channel"] == "web" and bool(context["destination"]) and bool(scope["read"])
    needs_dlp = "dlp" in sc
    if needs_path:
        try:
            path_analyzer.parse_destination(context["destination"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    if not needs_path and not needs_dlp:
        return scenario_flow.build_result(context, tenant_key="not-read", scope=response_scope)
    creds = _tenant_creds(req)
    client = dlp_analysis.read_once(await asyncio.to_thread(_build_client, req))
    tenant_key = tenant_fingerprint.proposal_key(creds, tenant_auth.record_label(creds))
    cancel = threading.Event()

    def run():
        response_scope["required_controls"] = dlp_analysis.inspect(client, sc, ch, tested_channel=context["channel"])
        path = None
        path_error = None
        if needs_path:
            try:
                path = path_analyzer.analyze(client, context["destination"], context["network"], context["platform"],
                                             scope=scope, context=context, cancel=cancel)
                path.pop("snapshot_for_cache", None)
            except ValueError:
                raise
            except Exception as exc:
                path_error = {"section": "path", "status": "unverified", "reason": "Path read failed: " + type(exc).__name__}
        rule_read = {"source": endpoint, "status": "out_of_scope", "items": [], "reason": "Selected channel is not in scope"}
        if scope["channel_enabled"]:
            rule_read = dlp_efficacy.read_collection(client, endpoint)
        corpus = None
        if needs_dlp:
            if context["corpus"].strip():
                corpus = dlp_efficacy.corpus_test(client, context["corpus"], read_rules=False,
                                                channel_rules=rule_read["items"], rules_evidence=rule_read, channel=context["channel"])
            else:
                dr = dlp_efficacy.read_collection(client, "/zia/dlpDictionaries")
                er = dlp_efficacy.read_collection(client, "/zia/dlpEngines")
                names = {int(x["id"]): str(x.get("name") or x["id"]) for x in dr["items"] if str(x.get("id", "")).isdigit()}
                evidence = {key: {k: v for k, v in value.items() if k != "items"} for key, value in (("dictionaries", dr), ("engines", er), ("rules", rule_read))}
                corpus = {"mode": "configuration", "channel": context["channel"], "results": [], "predefined": [],
                          "engines": corpus_engines.engine_results(er["items"], rule_read["items"], {}, names),
                          "rules": [corpus_engines.rule_reference(r) for r in rule_read["items"]], "read_evidence": evidence,
                          "errors": [{"section": key, **value} for key, value in evidence.items() if value["status"] == "unverified"]}
        result = scenario_flow.build_result(context, tenant_key=tenant_key, scope=response_scope, corpus=corpus, path=path, rules_evidence=rule_read)
        if path_error:
            result["errors"].append(path_error)
            result["execution_status"] = "partial"
            result["summary"] = "Path configuration could not be read. Available local detector results do not establish traffic routing or enforcement."
        return result
    async def watch_disconnect():
        while not cancel.is_set():
            if await request.is_disconnected():
                cancel.set()
                return
            await asyncio.sleep(0.1)

    def cancellable_run():
        with data_flow.stop_on(client, cancel):
            return run()

    watcher = asyncio.create_task(watch_disconnect())
    try:
        return await asyncio.to_thread(cancellable_run)
    except dlp_efficacy.CorpusReadStopped:
        raise HTTPException(status_code=499, detail="Scenario cancelled; no further configuration reads were started")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        cancel.set()
        watcher.cancel()


def _channel_declaration(raw: Any) -> Dict[str, Any]:
    """A channel declaration as sent: any non-empty object counts, even one
    whose entries cannot be read (channel_scope.effective then makes every
    channel a gap); never "nothing declared", which narrows nothing."""
    return raw if isinstance(raw, dict) and raw else {}


def _scope_selection(req: Any) -> Tuple[List[str], Dict[str, Any], str]:
    """The Scope page selection a tenant read honours: (scopes, channels,
    source). The page's selection (`scopes`, `channels`, `from_page`),
    else (only when the page sent nothing at all and does not know the
    Scope page's ticks) the saved profile's. The two are never mixed, so
    the profile cannot widen what the page chose. Never reads a tenant."""
    sc = [str(x) for x in (getattr(req, "scopes", None) or [])]
    ch = _channel_declaration(getattr(req, "channels", None))
    source = ""
    pid = getattr(req, "profile_id", "") or ""
    if sc or ch or getattr(req, "from_page", False):
        source = "the Scope page"
    elif pid:
        try:
            import tenant_profiles
            prof = tenant_profiles.get(pid) or {}
        except Exception:  # noqa: BLE001 — an unreadable profile store is no selection
            prof = {}
        sc = [str(x) for x in (prof.get("scopes") or [])]
        ch = _channel_declaration(prof.get("channels"))
        if sc or ch:
            source = f"the saved profile {prof.get('name') or pid}"
    return sc, ch, source


def _require_in_scope(req: Any, scope: str, what: str, channel: str = "") -> Dict[str, Any]:
    """The Scope page selection (_scope_selection) for a tool that reads
    only when `scope` is ticked and, with `channel`, that channel is marked
    Zscaler; else HTTPException 400 before anything is signed in to or read
    (user rule 1). Returns {scopes, channels, source, on_zscaler}."""
    import channel_scope
    import data_flow
    sc, ch, source = _scope_selection(req)
    on = channel_scope.in_scope(ch)
    label = data_flow.SCOPE_LABELS.get(scope, scope)
    if scope not in sc:
        raise HTTPException(status_code=400, detail=f"{what} is not in scope: on the Scope page tick {label}, then run it again. Nothing was read.")
    if channel and channel not in on:
        name = channel_scope.CHANNELS.get(channel, channel)
        raise HTTPException(status_code=400, detail=f"{what} is not in scope: on the Scope page mark {name} as Zscaler, then run it again. Nothing was read.")
    return {"scopes": sc, "channels": ch, "source": source, "on_zscaler": on}


def _pack_channels_in_scope(req: Any, what: str) -> List[str]:
    """The pack channels (web / endpoint / saas / email) the Scope page puts
    in scope: DLP ticked and the channel marked Zscaler. 400 when none is."""
    import channel_scope
    sel = _require_in_scope(req, "dlp", what)
    targets = channel_scope.pack_targets(sel["channels"])
    if not targets:
        raise HTTPException(status_code=400, detail=f"{what} is not in scope: on the Scope page mark at least one DLP channel "
                                                    "(Inline Web, Endpoint, SaaS or Email DLP) as Zscaler. Nothing was read.")
    return targets


def _path_scope(req: Any, nothing: str = "") -> Dict[str, Any]:
    """What the Path analyzer (or the Data Flow Map, which reads through
    the same tracer) may read: data_flow.path_scope of _scope_selection.
    Raises HTTPException 400 (`nothing`, else the analyzer's message) when
    nothing it reads is in scope. Never reads a tenant."""
    import data_flow
    sc, ch, source = _scope_selection(req)
    sel = data_flow.path_scope(sc, ch)
    if not sel["read"]:
        raise HTTPException(status_code=400, detail=nothing or data_flow.NOTHING_IN_SCOPE)
    sel["source"] = source
    return sel


def _run_path_analysis(client, req: PathAnalyzerRequest, snapshot, label: str, log, cancel, scope: Dict[str, Any]) -> Dict[str, Any]:
    """The analysis itself, shared by the job the page follows and the
    waiting endpoint. Reads only what `scope` puts in scope. A fresh
    tenant read is remembered as a Data Flow Map report, stamped with its
    scope, so the next destination reuses it only for the same scope
    (`report_id`). Stop (`cancel`) ends the job as stopped: nothing more
    is read, nothing is kept and no partial result is returned."""
    import path_analyzer
    logs: list = []

    def _log(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    if scope.get("source"):
        _log(f"In scope, from {scope['source']}: {scope['summary']}")
    try:
        out = path_analyzer.analyze(client, req.destination, req.network, req.platform, scope=scope, snapshot=snapshot, log=_log, cancel=cancel,
                                    protocol=req.protocol or None, port=req.port, identity=req.identity)
    except path_analyzer.Stopped as e:
        return {"stopped": str(e), "status": "stopped", "tenant_label": label, "destination": req.destination, "logs": logs}
    if cancel is not None and cancel.is_set():
        # Stop arrived as the last step finished: the run still ends as
        # stopped, and the read is not kept for the next destination.
        _log("STOPPED — you clicked Stop; the analysis was abandoned and its read is not kept.")
        return {"stopped": path_analyzer.STOPPED_REASON, "status": "stopped", "tenant_label": label, "destination": req.destination, "logs": logs}
    cache = out.pop("snapshot_for_cache", None)
    if cache is not None:
        tr = out.get("trace") or {}
        summary = {"destinations": 1, "traces": 1, "bypassed": int(not tr.get("reaches_zscaler", True)),
                   "blind": int(tr.get("outcome") == "blind"), "enforced": int(tr.get("outcome") == "enforce"),
                   "monitored": int(tr.get("outcome") == "monitor"), "high": sum(w.get("severity") == "high" for w in tr.get("weak_points", []))}
        rid = _remember_report("dataflow", {"summary": summary, "platform": out["platform"],
                                            "networks": [n for n in path_analyzer.NETWORKS if n["key"] == out["network"]], "platforms": path_analyzer.PLATFORMS,
                                            "destinations": [out["destination"]], "traces": [tr], "packs": [], "required_controls": out.get("required_controls", []), "diagnostics": cache.get("diagnostics") or [],
                                            "client_connector": cache["client_connector"], "snapshot": cache["snapshot"], "sources": {},
                                            "path_scope": cache.get("path_scope")}, label)
        out["report_id"] = rid
    else:
        out["report_id"] = req.report_id
    out["tenant_label"] = label
    out["logs"] = logs
    return out


def _kept_path_read(report_id: str, scope: Dict[str, Any], creds: Dict[str, str], platform: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The kept tenant read `report_id` names, only when it may answer this
    request: made for exactly this scope (path_analyzer.reusable) and in
    the tenant these credentials point at (tenant_fingerprint.same_tenant,
    the label required). Otherwise None and the tenant is read again: a
    read kept for one tenant never answers for another."""
    import path_analyzer
    import tenant_fingerprint
    snap = _REPORTS.get(report_id) if report_id and report_id.startswith("dataflow-") else None
    if snap is None or not snap.get("tenant_label") or not tenant_fingerprint.same_tenant(snap, creds):
        return None
    ok = path_analyzer.reusable(snap, scope) if platform is None else path_analyzer.reusable(snap, scope, platform)
    return snap if ok else None


async def _path_analysis_inputs(req: PathAnalyzerRequest):
    import path_analyzer
    try:
        import zia_path_modules
        zia_path_modules.traffic_context(path_analyzer.parse_destination(req.destination), req.protocol[:8], req.port)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    scope = _path_scope(req)   # before signing in: nothing in scope reads nothing
    creds = _tenant_creds(req)
    snapshot = _kept_path_read(req.report_id, scope, creds)   # a read for another scope or tenant is never reused
    client = await asyncio.to_thread(_build_client, req)
    return client, snapshot, tenant_auth.record_label(creds), scope   # never the classic API's admin login (user rule 3)


# ── POV planner (pov.py): one proof of value per tenant profile ─────────
# Local: the POV lives in the tenant profile's folder (tenant_profiles.
# pov_path) and is bound to the profile's tenant. Prove it and the Insights
# counts read the tenant through the Path analyzer and Traffic insights
# readers (scope gate first, read-only, Stop); nothing here writes to a
# tenant. Every change to the POV is in the audit log with who made it.
class PovRequest(TenantCredsRequest):
    """A POV call: the tenant profile it belongs to (profile_id) and, for
    the call that needs it, the intake, the changes and the revision they
    are made on, an imported file, a template name or the report format.
    Sign-in details typed on the assessment page may come too: they must
    name the profile's tenant."""
    intake: Dict[str, Any] = {}
    template_id: str = ""
    rev: Optional[int] = None
    changes: Dict[str, Any] = {}
    content: str = ""
    replace: bool = False
    confirm: bool = False
    format: str = "pdf"
    name: str = ""
    description: str = ""


class PovProveRequest(PathAnalyzerRequest):
    """Prove it: the runbook test whose destination the Path analyzer
    traces (its own destination, or `destination` to try another one)."""
    test_id: str = ""


class PovInsightsRequest(InsightsRequest):
    """The Insights counts a POV records: the window, as Traffic insights takes it."""


def _pov_call(fn, *args, **kwargs):
    import pov
    try:
        return fn(*args, **kwargs)
    except pov.PovError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    except ValueError as e:   # a refusal in words (an untrusted import, a value out of range), never a 500
        raise HTTPException(status_code=400, detail=str(e)[:300])


def _pov_typed(req: Any) -> Dict[str, str]:
    """The sign-in details the request typed itself (never a profile's or
    the server's): its tenant must be the profile's (when it names one),
    and its secrets are masked out of anything the POV keeps."""
    typed = {k: str(getattr(req, k, "") or "").strip() for k in ("auth_method", "cloud", "vanity_domain", "username", "client_secret", "password", "api_key")}
    try:
        tenant_auth.normalize_method(typed["auth_method"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return tenant_auth.normalize(typed)


def _pov_view(b: Dict[str, str], p: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    import pov
    return {"tenant_label": b["label"], "pov": p, "templates": pov.list_templates()}


@app.get("/report/pov")
async def report_pov_page():
    """Standalone tab for the POV planner (static/report_pov.html)."""
    page = os.path.join(STATIC_DIR, "report_pov.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.get("/api/pov/catalog")
async def pov_catalog():
    """What the planner draws: products, vertical presets, the runbook,
    the test kit and the saved templates. No tenant data."""
    import pov
    return dict(pov.catalog(), templates=pov.list_templates())


@app.post("/api/pov/open")
async def pov_open(req: PovRequest):
    """The profile's POV, or none yet. Local, never reads the tenant."""
    import pov
    b, p = _pov_call(pov.get, req.profile_id, _pov_typed(req))
    return _pov_view(b, p)


@app.post("/api/pov/create")
async def pov_create(req: PovRequest, request: Request):
    """Start the profile's POV from the intake (and a template)."""
    import pov
    p = _pov_call(pov.create, req.profile_id, _pov_typed(req), req.intake, by=_cq_by(request), template_id=req.template_id)
    return _pov_view(p["tenant"], p)


@app.post("/api/pov/update")
async def pov_update(req: PovRequest, request: Request):
    """Save changes to parts of the POV made on revision `rev`."""
    import pov
    p = _pov_call(pov.update, req.profile_id, _pov_typed(req), req.rev, req.changes, by=_cq_by(request))
    return _pov_view(p["tenant"], p)


@app.post("/api/pov/delete")
async def pov_delete(req: PovRequest, request: Request):
    """Delete the profile's POV (confirm=true)."""
    import pov
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Deleting a POV needs confirm=true; export it first to keep a copy.")
    if not _pov_call(pov.delete, req.profile_id, _pov_typed(req), by=_cq_by(request)):
        raise HTTPException(status_code=404, detail="This tenant profile has no POV.")
    return {"deleted": True}


@app.post("/api/pov/export")
async def pov_export(req: PovRequest):
    """The POV as a JSON file (no secret is ever in a POV)."""
    import pov
    import report_exports
    _b, p = _pov_call(pov.require, req.profile_id, _pov_typed(req))
    name = report_exports.safe_filename_part((p.get("intake") or {}).get("customer"), "customer", 40)
    return Response(content=json.dumps(pov.export(p), indent=1, ensure_ascii=False), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=zscaler_pov_{name}.json"})


@app.post("/api/pov/import")
async def pov_import(req: PovRequest, request: Request):
    """Import an exported POV file into the profile (an untrusted upload:
    size, JSON, depth, format and every field checked, off the event loop).
    A file made for another tenant is refused."""
    import pov
    p = await asyncio.to_thread(_pov_call, pov.import_pov, req.profile_id, _pov_typed(req), req.content, replace=bool(req.replace),
                                by=_cq_by(request))
    return _pov_view(p["tenant"], p)


@app.post("/api/pov/report")
async def pov_report(req: PovRequest):
    """The customer report (Word or PDF) from what actually ran: tests with
    a result, the criteria, the evidence, and the changes this app's
    deployment and bulk-change records show for the tenant since the POV
    started. Local: reads no tenant."""
    import pov
    import tenant_profiles
    fmt = (req.format or "pdf").lower()
    if fmt not in ("pdf", "docx"):
        raise HTTPException(status_code=400, detail="The report format must be pdf or docx.")
    _b, p = _pov_call(pov.require, req.profile_id, _pov_typed(req))
    creds = tenant_profiles.creds_from(tenant_profiles.get(req.profile_id) or {})
    model = pov.report_model(p, await asyncio.to_thread(pov.changes_made, creds, str(p.get("created_at") or "")))
    data = await asyncio.to_thread(pov.report_docx if fmt == "docx" else pov.report_pdf, model)
    media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if fmt == "docx" else "application/pdf"
    return Response(content=data, media_type=media, headers={"Content-Disposition": f"attachment; filename={pov.report_filename(model, fmt)}"})


@app.post("/api/pov/templates")
async def pov_template_save(req: PovRequest, request: Request):
    """Save the POV's plan (vertical, products, criteria) as a template:
    never the customer, the domain, the tenant, results or notes."""
    import pov
    _b, p = _pov_call(pov.require, req.profile_id, _pov_typed(req))
    t = _pov_call(pov.save_template, p, req.name, req.description, by=_cq_by(request))
    return {"template": t, "templates": pov.list_templates()}


@app.delete("/api/pov/templates/{template_id}")
async def pov_template_delete(template_id: str, request: Request):
    import pov
    if not _pov_call(pov.delete_template, template_id, by=_cq_by(request)):
        raise HTTPException(status_code=404, detail="No such template.")
    return {"deleted": True, "templates": pov.list_templates()}


@app.get("/api/pov/kit/{file_id}")
async def pov_kit_file(file_id: str):
    """One test kit file: synthetic DLP records, the EICAR test string or a
    unique harmless PDF. Never real data."""
    import pov
    data, media, name = _pov_call(pov.kit_file, file_id)
    return Response(content=data, media_type=media, headers={"Content-Disposition": f"attachment; filename={name}",
                                                              "Cache-Control": "no-store"})


@app.post("/api/pov/prove/start")
async def pov_prove_start(req: PovProveRequest, request: Request):
    """Prove it: the Path analyzer's verdict for a runbook test's
    destination (the same read-only, scope-gated analysis as
    /api/path-analyzer/start), recorded on the test as evidence with
    whether the configuration gives the expected result."""
    import pack_jobs
    import pov
    test = pov.RUNBOOK_BY_ID.get(req.test_id)
    if test is None:
        raise HTTPException(status_code=404, detail="Unknown runbook test.")
    if not (req.vanity_domain or req.username):
        req.cloud = ""   # nothing typed: the profile's cloud, not this model's "production" default
    req.destination = (req.destination or "").strip() or test["destination"]
    if not req.destination:
        raise HTTPException(status_code=400, detail=test["prove_note"] or "This test has no web destination for the Path analyzer.")
    _path_scope(req)   # nothing in scope: 400 before anything else (user rule 1)
    creds = _tenant_creds(req)
    _pov_call(pov.require, req.profile_id, creds)   # the POV and the sign-in name the same tenant, before sign-in
    client, snapshot, label, scope = await _path_analysis_inputs(req)
    by = _cq_by(request)

    def run(log, cancel):
        out = _run_path_analysis(client, req, snapshot, label, log, cancel, scope)
        if out.get("verdict") and not out.get("stopped"):
            try:
                p = pov.add_system_evidence(req.profile_id, creds, test["id"], pov.prove_evidence(test, out), by=by)
                out["pov_rev"], out["evidence"] = p["rev"], p["tests"][test["id"]]["evidence"][-1]
            except pov.PovError as e:   # the verdict stands; why it was not recorded is said
                out["pov_error"] = str(e)
        return out
    job = pack_jobs.start("path", run, label=f"POV {test['id']}", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/pov/insights/start")
async def pov_insights_start(req: PovInsightsRequest, request: Request):
    """The Insights counts for the POV's tests (the Traffic insights read,
    without the per-user rows), recorded on the POV as counts only."""
    import pack_jobs
    import pov
    req.include_users = False
    inp = _insights_inputs(req)
    _pov_call(pov.require, req.profile_id, inp["creds"])
    client = await asyncio.to_thread(_build_sdk_client, inp["creds"])
    by = _cq_by(request)

    def run(log, cancel):
        out = _run_insights(client, req, inp, log, cancel)
        if out.get("sections") and not out.get("stopped"):
            try:
                p = pov.add_insights(req.profile_id, inp["creds"], pov.insights_counts(out, inp["window"]["label"]), by=by)
                out["pov_rev"], out["counts"] = p["rev"], p["insights"][-1]["counts"]
            except pov.PovError as e:
                out["pov_error"] = str(e)
        return out
    job = pack_jobs.start("insights", run, label=f"POV {inp['window']['label']}", actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


# ── Path analyzer: one analysis, ZPA first, then ZIA ──────────────────
# POST /api/path-analyzer/start (a job the page, Simple mode and scripts
# follow) and POST /api/path-analyzer (the same, waited for) take one body
# (PathAnalyzerRequest). For a user device, ZPA is evaluated first (ZPA
# ticked): a destination ZPA carries never reaches ZIA, so ZIA is not
# traced; otherwise the ZIA path is traced (_run_path_analysis: Client
# Connector, forwarding, the PAC file evaluated, every ZIA module in order,
# the what-if) with the ZPA stage in front. For a workload (Cloud & Branch
# Connector ticked), the connector forwarding rules decide first, then ZIA
# or ZPA. Read-only; every part is read only when in scope.
PATH_NOTHING = ("Nothing the Path analyzer reads is in scope — on the Scope page tick ZPA, ZCC, DLP or ZIA platform "
                "and mark the channels you run on Zscaler, then analyze again.")
PATH_WORKLOAD_NOT_IN_SCOPE = ("Workload traffic is not in scope: on the Scope page tick Cloud & Branch Connector, then analyze again. "
                              "Nothing was read.")
PATH_WORKLOAD_NEEDS_ONEAPI = ("Workload traffic needs a ZIdentity (OneAPI) API client: the classic ZIA API reaches ZIA only. "
                              "Sign in with an API client that has a Cloud & Branch Connector role. Nothing was read.")


def _path_kept(rid: str, kind: str, creds: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """A ZPA or connector read kept from an earlier analysis, only for the same tenant."""
    import tenant_fingerprint
    rep = _REPORTS.get(rid or "") if (rid or "").startswith(kind + "-") else None
    if rep is None or not rep.get("tenant_label") or not tenant_fingerprint.same_tenant(rep, creds):
        return None
    return rep


def _path_inputs(req: PathAnalyzerRequest) -> Dict[str, Any]:
    """Everything decided before sign-in: the destination and its traffic
    (protocol and port), the scope of each part, the workload.
    HTTPException 400 for nothing in scope or a bad input; never reads a
    tenant."""
    import data_flow
    import path_analyzer
    import workload_path
    import zia_path_modules
    import zpa_path
    source = (req.source or "device").strip().lower()
    if source not in ("device", "workload"):
        raise HTTPException(status_code=400, detail="Traffic comes from a user device or a workload.")
    try:
        pdest = path_analyzer.parse_destination(req.destination)
        zia_path_modules.traffic_context(pdest, req.protocol, req.port)   # the one check of protocol and port
        d = zpa_path.destination(req.destination, req.port, req.protocol)
        w = workload_path.workload_input(req.workload) if source == "workload" else None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    sc, ch, src = _scope_selection(req)
    scope = data_flow.path_scope(sc, ch)
    scope["source"] = src
    if source == "workload":
        if "ztw" not in sc:
            raise HTTPException(status_code=400, detail=PATH_WORKLOAD_NOT_IN_SCOPE)
        # Client Connector is not on a workload's path: those hops are not read.
        nis = dict(scope["not_in_scope"])
        for k in ("zcc", "pac"):
            nis[k] = "Not on this path: workload traffic is forwarded by a Cloud or Branch Connector, not by Client Connector."
        read = [k for k in scope["read"] if k not in ("zcc", "pac")]
        scope = dict(scope, read=read, not_in_scope=nis, key=scope["key"] + "|workload",
                     summary=("Reads only what is in scope on the Scope page: " + ", ".join(data_flow.PATH_SECTIONS[k][0] for k in read) + "."
                              if read else "No ZIA policy is in scope."))
    zpa_on = "zpa" in sc
    if source == "device" and not scope["read"] and not zpa_on:
        raise HTTPException(status_code=400, detail=PATH_NOTHING)
    creds = _tenant_creds(req)
    oneapi = creds.get("auth_method") != tenant_auth.LEGACY
    if source == "workload" and not oneapi:
        raise HTTPException(status_code=400, detail=PATH_WORKLOAD_NEEDS_ONEAPI)
    zpa_problem = ""
    if zpa_on and not oneapi:
        zpa_problem = "ZPA was not read: the classic ZIA API sign-in reaches ZIA only, so whether ZPA carries this destination is unknown."
    elif zpa_on and not validate_customer_id(creds.get("customer_id") or ""):
        zpa_problem = "ZPA was not read: the ZPA customer ID is missing (Connect to the tenant → Customer ID), so whether ZPA carries this destination is unknown."
    if source == "device" and not scope["read"] and zpa_problem:
        raise HTTPException(status_code=400, detail=zpa_problem.replace("ZPA was not read: ", "ZPA cannot be read: ") + " Nothing was read.")
    zpa_kept = _path_kept("" if zpa_problem else req.zpa_report_id, "pathzpa", creds) if zpa_on else None
    ztw_kept = _path_kept(req.ztw_report_id, "pathztw", creds) if source == "workload" else None
    return {"source": source, "pdest": pdest, "d": d, "w": w, "scope": scope, "zpa_on": zpa_on, "zpa_problem": zpa_problem,
            "creds": creds, "label": tenant_auth.record_label(creds), "zia_kept": _kept_path_read(req.report_id, scope, creds) if scope["read"] else None,
            "zpa_kept": zpa_kept, "ztw_kept": ztw_kept,
            "need_sdk": (zpa_on and not zpa_problem and zpa_kept is None) or (source == "workload" and ztw_kept is None)}


def _run_path(inp: Dict[str, Any], req: PathAnalyzerRequest, raw_client, sdk_client, log, cancel) -> Dict[str, Any]:
    """The analysis: connector and ZPA stages, then ZIA when it applies.
    Stop ends it as stopped with nothing more read and no partial result."""
    import path_analyzer
    import workload_path
    import zpa_analysis
    import zpa_path
    logs: list = []
    creds, label, d, pd = inp["creds"], inp["label"], inp["d"], inp["pdest"]

    def _log(line: str) -> None:
        line = tenant_auth.mask_secrets(str(line), creds)
        logs.append(line)
        if log:
            log(line)

    def stopped() -> Dict[str, Any]:
        _log("STOPPED — you clicked Stop; the analysis was abandoned and nothing more was read. Nothing is ever written by this page.")
        return {"stopped": path_analyzer.STOPPED_REASON, "status": "stopped", "tenant_label": label, "destination": req.destination, "logs": logs}

    scope = inp["scope"]
    sc = {"summary": scope["summary"], "read": list(scope["read"]), "not_in_scope": dict(scope["not_in_scope"]), "key": scope["key"],
          "scopes": list(scope.get("scopes") or []), "channels": dict(scope.get("channels") or {})}
    if scope.get("source"):
        _log(f"In scope, from {scope['source']}: {scope['summary']}" + (" ZPA." if inp["zpa_on"] else "")
             + (" Cloud & Branch Connector." if inp["source"] == "workload" else ""))
    out_ids: Dict[str, str] = {}
    # 1. The connector read (workload traffic)
    ztw = None
    if inp["source"] == "workload":
        if inp["ztw_kept"] is not None:
            ztw = inp["ztw_kept"]["snapshot"]
            out_ids["ztw_report_id"] = inp["ztw_kept"]["report_id"]
            _log("Using the Cloud & Branch Connector configuration read a moment ago (Fresh read reads it again).")
        else:
            try:
                ztw = workload_path.read(sdk_client, log=_log, cancel=cancel)
            except workload_path.Stopped:
                return stopped()
            except zpa_path.ReadError as e:
                raise RuntimeError(tenant_auth.mask_secrets(str(e), creds))
            for v in ztw["collections"].values():
                if v.get("error"):
                    v["error"] = tenant_auth.mask_secrets(v["error"], creds)
            out_ids["ztw_report_id"] = _remember_report("pathztw", {"kind": "pathztw", "snapshot": ztw}, label)
    # 2. The ZPA read
    zsnap, profiles, zst = None, None, None
    if inp["zpa_on"]:
        if inp["zpa_problem"]:
            zst = zpa_path.not_read(inp["zpa_problem"])
            _log(inp["zpa_problem"])
        elif inp["zpa_kept"] is not None:
            zsnap, profiles = inp["zpa_kept"]["snapshot"], inp["zpa_kept"]["profiles"]
            out_ids["zpa_report_id"] = inp["zpa_kept"]["report_id"]
            _log("Using the ZPA configuration read a moment ago (Fresh read reads it again).")
        else:
            _log("Reading ZPA first: application segments, client forwarding and access policies…")
            try:
                zsnap, profiles = zpa_path.read(sdk_client, log=_log, cancel=cancel)
            except zpa_path.Stopped:
                return stopped()
            except zpa_path.ReadError as e:
                zst = zpa_path.not_read("ZPA could not be read (" + tenant_auth.mask_secrets(str(e), creds)[:160] + "), so whether ZPA carries this destination is unknown.")
            if zsnap is not None:
                for v in (zsnap.get("collections") or {}).values():
                    if v.get("error"):
                        v["error"] = tenant_auth.mask_secrets(v["error"], creds)
                out_ids["zpa_report_id"] = _remember_report("pathzpa", {"kind": "pathzpa", "snapshot": zsnap, "profiles": profiles}, label)
    if cancel is not None and cancel.is_set():
        return stopped()
    zpa_not_in_scope = [] if inp["zpa_on"] else [{"hop": "zpa", "label": "ZPA", "detail": "Not in scope: ZPA is not ticked on the Scope page, so whether ZPA carries this destination was not assessed."}]

    def zia(pre_hops, modules, impacts, assumptions, note):
        """The ZIA path with the earlier stages in front, or 'not in scope'."""
        if not scope["read"]:
            res = zpa_path.standalone(pre_hops, modules, outcome="out_of_scope", headline=f"Reaches ZIA; what ZIA does with {pd['host']} is not assessed: no ZIA part is in scope.",
                                      summary=(note + " Put ZIA policy in scope on the Scope page and analyze again to assess it.").strip(), dest=pd,
                                      network=req.network, platform=req.platform, scope=sc, impacts=impacts, assumptions=assumptions,
                                      stops_at=None, blocked_by=None, reaches_zscaler=True)
            res["verdict"]["not_in_scope"] = [{"hop": "zia", "label": "ZIA policy", "detail": "Not in scope: no ZIA policy section is ticked on the Scope page."}]
            return res
        _log("Tracing the ZIA path…")
        res = _run_path_analysis(raw_client, req, inp["zia_kept"], label, _log, cancel, scope)
        if res.get("stopped"):
            return res
        return zpa_path.merge(res, pre_hops, modules, impacts, assumptions, note)

    def finish(res):
        if res.get("stopped"):
            res["logs"] = logs
            return res
        res.setdefault("tenant_label", label)
        res.update(out_ids, source=inp["source"], logs=logs)
        v = res.get("verdict") or {}
        v["not_in_scope"] = list(v.get("not_in_scope") or []) + zpa_not_in_scope
        _log(f"Verdict: {v.get('headline', '')}")
        return res

    # 3. Workload: the connector decides first
    if inp["source"] == "workload":
        w = inp["w"]
        seg = None
        if zsnap is not None:
            sm = zpa_analysis.match_segment(zsnap, d)
            seg = zpa_analysis._Index(zsnap).segments.get(sm["match"]["id"]) if sm["match"] else None
        wl = workload_path.evaluate(ztw, w, d, seg, zsnap is not None)
        mods, hops, impacts = list(wl["modules"]), list(wl["hops"]), list(wl["impacts"])
        assumptions = list(workload_path.ASSUMPTIONS)
        rule = (wl.get("rule") or {}).get("name")
        go = wl["go"]
        if go in ("direct", "local", "proxy", "drop"):
            words = {"direct": "sends it direct to the internet", "local": "switches it locally between workloads", "proxy": "chains it to another proxy",
                     "drop": "drops it"}[go]
            outcome = "blocked" if go == "drop" else "bypassed"
            imp = {"hop": "connector", "label": "Connector forwarding", "status": "blocked" if go == "drop" else "bypass", "rule": rule,
                   "severity": "high" if go in ("direct", "proxy") else "info", "detail": f"Forwarding rule “{rule}” {words}.",
                   "fix": "Forward this workload traffic to ZIA so it is inspected." if go in ("direct", "proxy") else None}
            res = zpa_path.standalone(hops, mods, outcome=outcome, headline=f"The connector {words}: forwarding rule “{rule}”." if rule else f"The connector {words}.",
                                      summary="Neither ZIA nor ZPA sees this traffic." if go != "drop" else "The connection never leaves the connector.",
                                      dest=pd, network=req.network, platform=req.platform, scope=sc, impacts=[imp] + impacts, assumptions=assumptions,
                                      stops_at="Connector forwarding", blocked_by=rule, reaches_zscaler=False,
                                      mitigations=[{"rank": 1, "channel": "web", "action": "Forward this workload traffic to ZIA", "severity": "high",
                                                    "why": "Traffic the connector sends direct or to another proxy is never inspected by ZIA, so no DLP rule can see it."}]
                                      if go in ("direct", "proxy") else [])
            return finish(res)
        if go == "zpa":
            if zsnap is None:
                res = zpa_path.standalone(hops + (zst or zpa_path.not_read("Not in scope: ZPA is not ticked on the Scope page.", "out_of_scope"))["hops"],
                                          mods, outcome="out_of_scope", headline=f"The connector forwards {pd['host']} to ZPA; ZPA is not assessed.",
                                          summary=(zst or {}).get("reason") or "Tick ZPA on the Scope page and analyze again to see whether ZPA allows it.",
                                          dest=pd, network=req.network, platform=req.platform, scope=sc, impacts=impacts, assumptions=assumptions,
                                          stops_at=None, blocked_by=None, reaches_zscaler=True)
                return finish(res)
            st = zpa_path.stage(zsnap, d, source="workload", profiles=profiles)
            if st.get("outcome") == "not_zpa":
                st.update(outcome="zpa_denied", headline=f"The connector forwards {pd['host']} to ZPA, but no ZPA application segment matches it: ZPA cannot carry it.",
                          summary=st.get("summary") or "")
            res = zpa_path.standalone(hops + st["hops"], mods + st["modules"], outcome=st["outcome"], headline=st["headline"], summary=st["summary"],
                                      dest=pd, network=req.network, platform=req.platform, scope=sc, impacts=impacts + st["impacts"],
                                      assumptions=assumptions + [a for a in st["assumptions"] if "Client Connector" not in a and "posture" not in a],
                                      stops_at="ZPA" if st["outcome"] == "zpa_denied" else None, blocked_by=(st.get("scenarios", {}).get("none") or {}).get("rule"),
                                      reaches_zscaler=True, mitigations=zpa_path.zpa_mitigations(st))
            return finish(res)
        note = wl["headline"] if go == "zia" else "Where the connector sends this traffic is not certain (see Connector forwarding); if it goes to ZIA:"
        res = zia(hops, mods, impacts, assumptions, note)
        if not res.get("stopped"):
            t = res.get("trace") or {}
            t["hops"] = [dict(h, status="na", detail="Not on this path: workload traffic is forwarded by a Cloud or Branch Connector, not by Client Connector.",
                              why="workload traffic", weak_point=None)
                         if h.get("key") in ("zcc", "forwarding", "pac") and h.get("status") == "out_of_scope" else h for h in t.get("hops") or []]
            v = res.get("verdict") or {}
            v["not_in_scope"] = [x for x in v.get("not_in_scope") or [] if x.get("hop") not in ("zcc", "forwarding", "pac")]
            v["impacts"] = [x for x in v.get("impacts") or [] if x.get("hop") not in ("zcc", "forwarding", "pac")]
            res["assumptions"] = [a for a in res.get("assumptions") or [] if not a.startswith("Browser traffic over HTTPS from a managed device")]
            ec = wl.get("connector_group") or {}
            if ec.get("location"):
                res["assumptions"].append(f"ZIA sees this traffic at the connector group's location “{ec['location']}”; location-scoped rules are named where they apply.")
        return finish(res)

    # 4. User device: ZPA first
    if zst is None and zsnap is not None:
        _log("Placing the destination in ZPA: application segment, bypass, client forwarding, access policy…")
        zst = zpa_path.stage(zsnap, d, network=req.network, platform=req.platform, profiles=profiles)
        _log("ZPA: " + zst["headline"])
    if zst is not None and zst.get("carries") is True:
        res = zpa_path.standalone(zst["hops"], zst["modules"], outcome=zst["outcome"], headline=zst["headline"], summary=zst["summary"],
                                  dest=pd, network=req.network, platform=req.platform, scope=sc, impacts=zst["impacts"], assumptions=zst["assumptions"],
                                  stops_at="ZPA" if zst["outcome"] == "zpa_denied" else None,
                                  blocked_by=next((m["rule"]["name"] for m in zst["modules"] if m["key"] == "zpa_access" and m["rule"]), None)
                                  if zst["outcome"] == "zpa_denied" else None,
                                  reaches_zscaler=True, mitigations=zpa_path.zpa_mitigations(zst))
        return finish(res)
    if zst is None:
        return finish(zia([], [], [], [], ""))
    note = {"not_zpa": "ZPA does not carry it (no application segment matches), so it is internet traffic:",
            "outside": "ZPA does not carry it: " + zst.get("headline", "") + " So it is internet traffic:",
            "zpa_conditional": "ZPA may carry it (see ZPA below); when it does not:", "not_read": zst.get("reason", "")}.get(zst.get("outcome"), "")
    return finish(zia(zst["hops"], zst["modules"], zst.get("impacts") or [], zst.get("assumptions") or [], note))


async def _path_clients(inp: Dict[str, Any], req: PathAnalyzerRequest):
    """Sign in only to what this analysis reads: the ZIA client when a ZIA
    or Client Connector part is in scope, the OneAPI SDK client when ZPA
    or the connector must be read (never the classic API's admin login)."""
    raw_client = await asyncio.to_thread(_build_client, req) if inp["scope"]["read"] else None
    sdk_client = await asyncio.to_thread(_build_sdk_client, inp["creds"]) if inp["need_sdk"] else None
    return raw_client, sdk_client


@app.post("/api/path-analyzer/start")
async def path_analyzer_start(req: PathAnalyzerRequest, request: Request):
    """Start the Path analyzer as a job the page follows: ZPA first (ZPA
    ticked), workload traffic through its connector (Cloud & Branch
    Connector ticked), then the ZIA path (only the parts in scope on the
    Scope page). The first run reads the tenant; later runs reuse that read
    through `report_id`, `zpa_report_id` and `ztw_report_id` and only look
    the destination up. 400 before sign-in for nothing in scope or a bad
    input. Poll GET /api/dlp-packs/jobs/{job_id}; Stop ends it with nothing
    more read. Nothing is written."""
    import pack_jobs
    inp = _path_inputs(req)
    raw_client, sdk_client = await _path_clients(inp, req)
    job = pack_jobs.start("path", lambda log, cancel: _run_path(inp, req, raw_client, sdk_client, log, cancel), label=req.destination[:80],
                          actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.post("/api/path-analyzer")
async def path_analyzer_run(req: PathAnalyzerRequest):
    """The same analysis, waited for (for scripts)."""
    inp = _path_inputs(req)
    raw_client, sdk_client = await _path_clients(inp, req)
    return await asyncio.to_thread(_run_path, inp, req, raw_client, sdk_client, None, None)


class PathIdentityRequest(MigrateRequest):
    """Look one user, group, department or location up in ZIA by name, for
    the Path analyzer's what-if. Read only when ZIA platform is ticked on
    the Scope page; one page of at most path_whatif.SEARCH_LIMIT answers."""
    kind: str = "user"
    query: str = ""
    scopes: List[str] = []
    channels: Dict[str, Any] = {}
    from_page: bool = False


@app.post("/api/path-analyzer/identities")
async def path_analyzer_identities(req: PathIdentityRequest):
    """Search ZIA's users, groups, departments or locations by name (never a
    bulk listing). 400 before signing in when ZIA platform is not in scope,
    the kind is unknown or the query is not 2 to 64 characters."""
    import path_whatif
    _require_in_scope(req, "zia_extras", "Looking up users, groups and locations")
    if req.kind not in path_whatif.SEARCH_KINDS:
        raise HTTPException(status_code=400, detail=f"Search for one of: {', '.join(path_whatif.SEARCH_KINDS)}. Nothing was read.")
    if path_whatif.valid_query(req.query) is None:
        raise HTTPException(status_code=400, detail="Type 2 to 64 characters to search. Nothing was read.")
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(path_whatif.search_identities, client, req.kind, req.query)


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
async def report_ssl_flow(req: ScopedReportRequest):
    """Walk the SSL inspection rules per DLP-relevant traffic class, map the
    inline Web DLP rules over them and list the gaps. Read-only, and only
    what is in scope on the Scope page is read (Web DLP rules and Client
    Connector bypasses only when in scope); the response carries report_id
    for /report/sslflow?id=... and exports."""
    try:
        from ssl_flow import generate_ssl_flow_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ssl_flow unavailable: {e}")
    scope = _ssl_flow_scope(req)   # refused here, before signing in, when the SSL rules are not in scope
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_ssl_flow_report, client, scope)
    rid = _remember_report("sslflow", report, _report_label(req))
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

# ── SSL coverage (ssl_coverage.py): what is not inspected, why, and the fix ──
# Read-only. Refused (400) before sign-in unless the SSL inspection rules
# are in scope; Client Connector, PAC files and ZIA Insights traffic numbers
# are read only when they are in scope too.
class SslCoverageRequest(ScopedTenantCredsRequest):
    """Body of POST /api/ssl-coverage/start: the window for the traffic
    numbers ("7d" or "30d") and whether to ask ZIA Insights for them."""
    window: str = "7d"
    include_volume: bool = True


def _ssl_coverage_inputs(req: SslCoverageRequest) -> Dict[str, Any]:
    """Scope, window and the traffic-number plan, checked before anything
    is signed in to (user rule 1). Never reads a tenant."""
    import data_flow
    import ssl_coverage
    sc, ch, source = _scope_selection(req)
    sel = data_flow.path_scope(sc, ch)
    if "ssl" not in sel["read"]:
        raise HTTPException(status_code=400, detail=ssl_coverage.OUT_OF_SCOPE)
    sel["source"] = source
    window = str(req.window or "7d").strip()
    if window not in ssl_coverage.WINDOWS:
        raise HTTPException(status_code=400, detail="The window must be the last 7 days or the last 30 days. Nothing was read.")
    creds = _tenant_creds(req)
    plan = {"ask": False, "window": window, "reason": ""}
    if not req.include_volume:
        plan["reason"] = "Traffic numbers were switched off for this run."
    elif "insights" not in sc:
        plan["reason"] = ("ZIA Insights is not in scope on the Scope page, so traffic numbers were not asked for: "
                          "the causes and the plan below come from configuration only.")
    elif tenant_auth.normalize(creds)["auth_method"] == tenant_auth.LEGACY:
        plan["reason"] = "Traffic numbers need a OneAPI API client: the classic ZIA API sign-in cannot read ZIA Insights."
    else:
        plan["ask"] = True
    return {"scope": sel, "creds": creds, "label": tenant_auth.record_label(creds), "volume": plan}


def _ssl_coverage_clients(req: SslCoverageRequest, inp: Dict[str, Any]):
    """The assessment client (rules, profiles, PAC) and, when traffic
    numbers are asked for, the SDK client for ZIA Insights. A failing SDK
    sign-in leaves configuration only, with the reason (never a secret)."""
    client = _build_client(req)
    if not inp["volume"]["ask"]:
        return client, None
    try:
        return client, _build_sdk_client(inp["creds"])
    except HTTPException as e:
        inp["volume"].update(ask=False, reason="ZIA Insights could not be signed in to: " + tenant_auth.mask_secrets(str(e.detail), inp["creds"])[:240])
        return client, None


def _run_ssl_coverage(client, sdk, inp: Dict[str, Any], log, cancel) -> Dict[str, Any]:
    import ssl_coverage
    try:
        rep = ssl_coverage.run(client, inp["scope"], zins=getattr(sdk, "zins", None), volume_plan=inp["volume"], log=log, cancel=cancel,
                               scrub=lambda s: tenant_auth.mask_secrets(s, inp["creds"]))
    finally:
        _close_quietly(client)
    if rep.get("stopped"):
        return dict(rep, tenant_label=inp["label"])
    try:
        rep["history"] = ssl_coverage.record(inp["label"], rep)
    except Exception as e:  # noqa: BLE001 — history is best effort
        rep["history"] = ssl_coverage.load_history(inp["label"])
        rep["history_error"] = f"This run could not be added to the history ({type(e).__name__})."
    rid = _remember_report("sslcoverage", rep, inp["label"])
    return _REPORTS[rid]


@app.get("/report/sslcoverage")
async def report_sslcoverage_page():
    """Standalone tab for SSL coverage (static/report_ssl_coverage.html)."""
    page = os.path.join(STATIC_DIR, "report_ssl_coverage.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="report page missing")
    with open(page, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read(), headers={"Cache-Control": "no-cache, must-revalidate, max-age=0"})


@app.post("/api/ssl-coverage/start")
async def ssl_coverage_start(req: SslCoverageRequest, request: Request):
    """Start the SSL coverage read as a job the page follows (poll GET
    /api/dlp-packs/jobs/{job_id}). Refused (400) before sign-in when the
    SSL inspection rules are not in scope. Stop ends it with nothing more
    read and no partial result."""
    import pack_jobs
    inp = _ssl_coverage_inputs(req)
    client, sdk = await asyncio.to_thread(_ssl_coverage_clients, req, inp)
    job = pack_jobs.start("sslcoverage", lambda log, cancel: _run_ssl_coverage(client, sdk, inp, log, cancel), label="SSL coverage",
                          actor=_actor(request), start_token=_start_token(request))
    return {"job_id": job.id, "status": job.status, "kind": job.kind}


@app.get("/api/ssl-coverage/history")
async def ssl_coverage_history(tenant: str = ""):
    """The kept run summaries for a tenant label (no tenant call)."""
    import ssl_coverage
    return {"tenant": tenant[:120], "history": await asyncio.to_thread(ssl_coverage.load_history, tenant[:120])}


@app.get("/api/ssl-coverage/{report_id}")
async def ssl_coverage_get(report_id: str):
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("sslcoverage-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    return rep


@app.get("/api/ssl-coverage/export/{report_id}")
async def ssl_coverage_export(report_id: str, format: str = "xlsx"):
    """A kept SSL coverage run as Excel (causes, plan, traffic, history) or JSON."""
    import ssl_coverage
    import xlsx_writer
    rep = _REPORTS.get(report_id)
    if not rep or not report_id.startswith("sslcoverage-"):
        raise HTTPException(status_code=404, detail="Report not found or expired (reports live in memory while the server runs).")
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    fmt = (format or "xlsx").lower()
    if fmt == "json":
        body = {k: v for k, v in rep.items() if k != "logs"}
        return Response(content=json.dumps(body, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=zscaler_ssl_coverage_{ts}.json"})
    if fmt != "xlsx":
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt[:20]}")
    data = await asyncio.to_thread(ssl_coverage.to_xlsx, rep)
    return Response(content=data, media_type=xlsx_writer.MEDIA_TYPE,
                    headers={"Content-Disposition": f"attachment; filename=zscaler_ssl_coverage_{ts}.xlsx"})



@app.post("/api/report/bypass/export")
async def report_bypass_export(req: BypassExportRequest):
    """Generate and download the bypass report in csv / markdown / json /
    docx; only what is in scope on the Scope page is read."""
    try:
        from bypass_report import generate_bypass_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bypass_report unavailable: {e}")
    scope = _bypass_report_scope(req)
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_bypass_report, client, scope)
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
                    f"(STOP_Zscaler_Made_Easy.bat or ./stop.sh stops it), or set ZSCALER_PORT to a free port and start again.")
        if e.errno in (errno.EADDRNOTAVAIL, errno.EACCES, 10049, 10013):
            return (f"{host}:{port} cannot be used: {e.strerror or e}. Check ZSCALER_BIND_HOST (an address this machine owns; "
                    f"127.0.0.1 is the default) and ZSCALER_PORT (ports below 1024 need administrator rights).")
        return f"{host}:{port} cannot be used: {e}"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    """Start the web server the way the launchers, the installer's
    `zscaler-made-easy` command and the container do.

    Configuration is read from the environment (ZSCALER_BIND_HOST,
    ZSCALER_PORT, ZSCALER_UI_AUTH, ZSCALER_OPEN_BROWSER, ZSCALER_DEBUG;
    see security.py). Returns the process exit code: 0 when the server
    stopped normally, 2 when it could not start (the port is taken, the
    address cannot be bound, the token file cannot be written), with the
    reason printed in plain words instead of a traceback."""
    import uvicorn

    host = get_bind_host()
    port = get_port()
    print("\n  Zscaler Made Easy")
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
                  f"  Another copy of the app is probably running (STOP_Zscaler_Made_Easy or stop.sh stops it),\n"
                  f"  or set ZSCALER_PORT to a free port and start again.", file=sys.stderr)
        else:
            print(f"\n  Could not start the server on {host}:{port}: {e}\n"
                  f"  Check ZSCALER_BIND_HOST (an address this machine owns) and ZSCALER_PORT (1-65535).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
