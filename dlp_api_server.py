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

import json, asyncio, os, tempfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
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
    mask_secret, scrub_dict,
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
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


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


class UpdateCheckRequest(BaseModel):
    only: Optional[list[str]] = None  # subset of source keys
    reset: bool = False               # wipe cache first
    skip_tls_verify: bool = False     # corporate TLS MITM bypass (opt-in per request)


# ── Routes ───────────────────────────────────────────────────────────

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
    return FileResponse(
        index,
        headers={
            "Cache-Control": "no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


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


# ── Guided Auto-Remediation ────────────────────────────────────
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
    }


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


# ═══════════════════════════════════════════════════════════════════
# Rule Migration API (Evaluate All Rules mode)
# ═══════════════════════════════════════════════════════════════════

class MigrateRequest(BaseModel):
    cloud: str = "production"
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""
    # Inline Web DLP only — this tool's migration is scoped to the DLP Web Rules
    # inline policy. Other rule types (SSL, URL, firewall, Cloud App) have
    # different best-practice ordering rules and are out of scope here.
    rule_type: str = "web_dlp"


def _build_client(req: MigrateRequest):
    """Build an authenticated Client from a migration request.
    Validates every input first; never includes the secret in any error message.
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


# ── Step 2: Download Current Rules ───────────────────────────────
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


# ── Step 4b: Delete All Existing Rules (gated) ───────────────────
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


# ── Upload rules (from a JSON backup file) ───────────────────────
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


# ── Manual reorder (accept any explicit ordering) ────────────────
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
    # Validate inputs BEFORE the SSE stream opens so failures return 400, not 200+stream
    cloud = validate_cloud(req.cloud)
    vd = validate_vanity(req.vanity_domain)
    cid = validate_credential("client_id", req.client_id, required=True)
    sec = validate_credential("client_secret", req.client_secret, required=True)
    cust = validate_customer_id(req.customer_id)
    checks = _get_checks(req.scope, req.scopes)

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
            }

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


# ── Bypass / Non-Inspected Traffic Inventory ────────────────────────
@app.post("/api/report/bypass")
async def report_bypass(req: MigrateRequest):
    """Generate the bypass-inventory report (JSON). Read-only."""
    try:
        from bypass_report import generate_bypass_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bypass_report unavailable: {e}")
    client = await asyncio.to_thread(_build_client, req)
    return await asyncio.to_thread(generate_bypass_report, client)


class BypassExportRequest(MigrateRequest):
    format: str = "csv"  # csv | markdown | json | docx


@app.post("/api/report/bypass/export")
async def report_bypass_export(req: BypassExportRequest):
    """Generate and download the bypass report in csv / markdown / json / docx."""
    try:
        from bypass_report import generate_bypass_report, to_csv, to_markdown
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"bypass_report unavailable: {e}")
    fmt = (req.format or "csv").lower()
    if fmt not in ("csv", "markdown", "md", "json", "docx", "word", "doc"):
        raise HTTPException(status_code=400, detail=f"Unsupported format: {req.format}")
    client = await asyncio.to_thread(_build_client, req)
    report = await asyncio.to_thread(generate_bypass_report, client)

    from fastapi.responses import Response, FileResponse
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "csv":
        return Response(
            content=to_csv(report),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.csv"},
        )
    if fmt in ("markdown", "md"):
        return Response(
            content=to_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.md"},
        )
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
        return FileResponse(
            output_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=f"zscaler_bypass_{ts}.docx",
        )
    # json
    return Response(
        content=json.dumps(report, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=zscaler_bypass_{ts}.json"},
    )


# ── Updates: check for new Zscaler APIs / SDK / best practices ──────
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
