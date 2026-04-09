#!/usr/bin/env python3
"""
DLP Assessment API Server
==========================
FastAPI wrapper around the full-auto DLP assessment engine.
Streams real-time progress via Server-Sent Events (SSE).

Install:
    pip install fastapi uvicorn requests

Run:
    uvicorn dlp_api_server:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    POST /api/assess         — Run full assessment (SSE stream)
    POST /api/assess/json    — Run full assessment (JSON response, no streaming)
    GET  /api/health         — Health check
    GET  /api/checks         — List all check IDs/labels
"""

import json, time, asyncio, uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

# ── Import the assessment engine ──────────────────────────────────────
# This imports everything from the full-auto script sitting alongside
# If you renamed the engine file, update this import
import importlib.util, sys, os

ENGINE_PATH = os.path.join(os.path.dirname(__file__), "dlp_assessment_full_auto.py")
spec = importlib.util.spec_from_file_location("engine", ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

# Pull what we need from the engine
Client = engine.Client
REG = engine.REG
R = engine.R
compute = engine.compute
maturity = engine.maturity


# ── FastAPI App ───────────────────────────────────────────────────────

app = FastAPI(
    title="Zscaler DLP Assessment API",
    version="3.0",
    description="Full-auto DLP assessment engine via OneAPI. Zero manual checks.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ─────────────────────────────────────────

class AssessRequest(BaseModel):
    org_name: str
    assessor: str
    cloud: str = "zscloud"
    vanity_domain: str
    client_id: str
    client_secret: str


class CheckResult(BaseModel):
    id: str
    section: str
    label: str
    status: str
    detail: str


class AssessResponse(BaseModel):
    metadata: dict
    score: int
    maturity: str
    sections: dict
    checks: list[CheckResult]
    critical: list[dict]
    review: list[dict]


# ── In-memory assessment store (for polling fallback) ─────────────────

assessments: dict = {}


# ── Health Check ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "engine_checks": len(REG), "version": "3.0"}


# ── List all checks ──────────────────────────────────────────────────

@app.get("/api/checks")
async def list_checks():
    return [{"id": id, "section": sec, "label": label} for id, sec, label, _ in REG]


# ── SSE Streaming Assessment ─────────────────────────────────────────

@app.post("/api/assess")
async def assess_stream(req: AssessRequest):
    """
    Run assessment with Server-Sent Events streaming.
    Each check result is streamed as it completes.
    Final event contains the full scored report.
    
    Usage from JS:
        const es = new EventSource(...)  // or fetch with ReadableStream
        // Events: "auth", "progress", "check", "complete", "error"
    """
    async def event_generator():
        # Authenticate
        yield _sse("auth", {"status": "authenticating"})

        client = Client(req.client_id, req.client_secret, req.vanity_domain, req.cloud)
        auth_result = client.auth()

        if auth_result is not True:
            yield _sse("error", {"message": f"Authentication failed: {auth_result}"})
            return

        yield _sse("auth", {"status": "ok"})
        yield _sse("progress", {"total": len(REG), "completed": 0, "pct": 0})

        # Run checks
        results = []
        for i, (check_id, sec, label, fn) in enumerate(REG):
            try:
                # Run in thread pool to not block the event loop
                r = await asyncio.to_thread(fn, client)
            except Exception as ex:
                r = R(R.ERROR, str(ex))

            result = {
                "id": check_id,
                "section": sec,
                "label": label,
                "status": r.status,
                "detail": r.detail,
            }
            results.append(result)

            yield _sse("check", result)
            yield _sse("progress", {
                "total": len(REG),
                "completed": i + 1,
                "pct": round((i + 1) / len(REG) * 100),
                "current": f"{check_id}: {label}",
            })

        # Compute final report
        secs, overall = compute(results)
        report = {
            "metadata": {
                "tool": "DLP Assessment Full Auto API",
                "version": "3.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "org": req.org_name,
                "assessor": req.assessor,
                "cloud": req.cloud,
                "total_checks": len(REG),
            },
            "score": overall,
            "maturity": maturity(overall),
            "sections": secs,
            "checks": results,
            "critical": [r for r in results if r["status"] == "FAIL"],
            "review": [r for r in results if r["status"] == "REVIEW"],
        }

        yield _sse("complete", report)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── JSON (non-streaming) Assessment ──────────────────────────────────

@app.post("/api/assess/json", response_model=AssessResponse)
async def assess_json(req: AssessRequest):
    """
    Run full assessment and return complete JSON response.
    No streaming — waits for all checks to finish.
    Better for programmatic/cURL usage.
    """
    client = Client(req.client_id, req.client_secret, req.vanity_domain, req.cloud)
    auth_result = client.auth()

    if auth_result is not True:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {auth_result}")

    results = []
    for check_id, sec, label, fn in REG:
        try:
            r = await asyncio.to_thread(fn, client)
        except Exception as ex:
            r = R(R.ERROR, str(ex))
        results.append({
            "id": check_id, "section": sec, "label": label,
            "status": r.status, "detail": r.detail,
        })

    secs, overall = compute(results)
    return {
        "metadata": {
            "tool": "DLP Assessment Full Auto API",
            "version": "3.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "org": req.org_name,
            "assessor": req.assessor,
            "cloud": req.cloud,
            "total_checks": len(REG),
        },
        "score": overall,
        "maturity": maturity(overall),
        "sections": secs,
        "checks": [CheckResult(**r) for r in results],
        "critical": [r for r in results if r["status"] == "FAIL"],
        "review": [r for r in results if r["status"] == "REVIEW"],
    }


# ── SSE Helper ────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    """Format a Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


# ── Run directly ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
