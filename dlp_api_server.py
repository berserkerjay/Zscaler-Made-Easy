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
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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

# ── FastAPI App ──────────────────────────────────────────────────────

app = FastAPI(
    title="Zscaler Platform Assessment",
    version="3.0",
    description="Full-auto assessment engine via OneAPI.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


# ── Routes ───────────────────────────────────────────────────────────

@app.get("/")
async def serve_gui():
    """Serve the web GUI."""
    index = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return JSONResponse({"error": "GUI not found. Place index.html in static/"}, status_code=404)


@app.get("/favicon.ico")
async def favicon():
    """Return empty favicon to silence browser 404s."""
    from fastapi.responses import Response
    return Response(status_code=204)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "dlp_checks": len(REG),
        "platform_checks": len(PLATFORM_REG),
        "genai_checks": len(GENAI_REG),
        "total_checks": len(REG) + len(PLATFORM_REG) + len(GENAI_REG),
        "version": "3.0",
    }


@app.get("/api/checks")
async def list_checks():
    all_checks = list(REG) + PLATFORM_REG + GENAI_REG
    return [{"id": id, "section": sec, "label": label} for id, sec, label, _ in all_checks]


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
        return out
    # Legacy scope string
    if scope == "full" or scope == "all":
        return list(REG) + PLATFORM_REG
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
    checks = _get_checks(req.scope, req.scopes)

    async def event_generator():
        results = []
        try:
            yield _sse("auth", {"status": "authenticating"})

            client = Client(req.client_id, req.client_secret, req.vanity_domain, req.cloud, req.customer_id)
            auth_result = await asyncio.to_thread(client.auth)

            if auth_result is not True:
                yield _sse("error", {"message": f"Authentication failed: {auth_result}"})
                return

            yield _sse("auth", {"status": "ok"})
            yield _sse("progress", {"total": len(checks), "completed": 0, "pct": 0})

            for i, (check_id, sec, label, fn) in enumerate(checks):
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
                    "id": check_id, "section": sec, "label": label,
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


if __name__ == "__main__":
    import uvicorn
    print("\n  Zscaler Platform Assessment")
    print("  Open http://localhost:8000 in your browser\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
