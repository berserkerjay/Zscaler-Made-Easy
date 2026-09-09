#!/usr/bin/env python3
"""
Security hardening for the Zscaler Assessment API server.

Implements secure-by-design controls aligned with CISA's
"Secure by Design" principles:

  - Default to localhost-only binding (no network exposure unless
    operator opts in via env var).
  - Strict CORS (no wildcard).
  - Origin/Referer enforcement on state-changing requests
    (CSRF defense for browser-borne attacks).
  - Security response headers (X-Content-Type-Options, X-Frame-Options,
    Referrer-Policy, Permissions-Policy, Cache-Control on API responses).
  - Request body size limit (DoS defense).
  - Generic exception handler — never leak stack traces to clients.
  - Input validation helpers (cloud allowlist, hostname pattern,
    credential length caps).
  - Secret masking helper for log/error messages.

Optional hardening (env-toggled):
  ZSCALER_BIND_HOST    (default 127.0.0.1)  — set to 0.0.0.0 to expose
  ZSCALER_PORT         (default 8000)
  ZSCALER_MAX_BODY_MB  (default 10)         — reject larger uploads
  ZSCALER_DEBUG        (default 0)          — 1 to surface tracebacks
  ENABLE_WRITE_ACTIONS                       — must equal "YES_I_UNDERSTAND"
                                               for any rule write/delete
"""
from __future__ import annotations

import os
import re
import time
from typing import Iterable, Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# Known good Zscaler clouds — anything else is rejected to prevent SSRF
# (an attacker injecting a custom "cloud" value to make the server
# fetch from an arbitrary host).
ALLOWED_CLOUDS = {
    "production", "zscloud", "zscaler", "zscalerone",
    "zscalertwo", "zscalerthree", "zscalerten", "zspreview", "zscalerbeta",
    # OneAPI / Zidentity environment names (provider docs: beta, gov, govus)
    "beta", "gov", "govus", "zscalergov",
}

# Browser-borne origins we trust for state-changing requests: this
# server's own address only (the default port and the configured
# ZSCALER_PORT, so a GUI on another port is not rejected with 403).
def _allowed_origins() -> set:
    out = {"http://localhost:8000", "http://127.0.0.1:8000", "http://localhost", "http://127.0.0.1"}
    try:
        port = int(os.environ.get("ZSCALER_PORT", "8000"))
        out |= {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
    except ValueError:
        pass
    return out


ALLOWED_ORIGINS = _allowed_origins()

# Hostname pattern for vanity_domain (RFC-1123 label, dot-separated).
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

# Credential length caps — hard enough that a junk paste fails fast,
# loose enough not to clip a legit value.
MAX_CRED_LEN = 256
MAX_VANITY_LEN = 253           # full DNS name limit
MAX_CUSTOMER_ID_LEN = 64


# ── Configuration helpers ────────────────────────────────────────────────────

def get_bind_host() -> str:
    """Default: localhost only. Operator must explicitly opt in."""
    return os.environ.get("ZSCALER_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"


def get_port() -> int:
    try:
        return int(os.environ.get("ZSCALER_PORT", "8000"))
    except ValueError:
        return 8000


def get_max_body_bytes() -> int:
    try:
        mb = int(os.environ.get("ZSCALER_MAX_BODY_MB", "10"))
    except ValueError:
        mb = 10
    return max(1, min(mb, 100)) * 1024 * 1024  # 1MB..100MB


def is_debug() -> bool:
    return os.environ.get("ZSCALER_DEBUG", "0").strip() in ("1", "true", "yes")


WRITE_CONFIRM_PHRASE = "YES_I_UNDERSTAND"
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
# Session override set from the GUI (Deploy Studio > Enable write mode).
# Only honoured while the server is bound to localhost, and never
# persisted: a restart returns to whatever the environment says.
_write_override: "bool | None" = None


def writes_enabled() -> bool:
    if _write_override is not None:
        return _write_override
    return os.environ.get("ENABLE_WRITE_ACTIONS") == WRITE_CONFIRM_PHRASE


def write_mode_status() -> dict:
    """What the GUI shows: whether writes are on, where that comes from,
    and whether the operator may toggle it from the browser."""
    env_on = os.environ.get("ENABLE_WRITE_ACTIONS") == WRITE_CONFIRM_PHRASE
    local = get_bind_host() in _LOCAL_HOSTS
    return {
        "enabled": writes_enabled(),
        "source": ("session" if _write_override is not None else ("environment" if env_on else "default")),
        "bind_host": get_bind_host(),
        "can_toggle": local,
        "confirm_phrase": WRITE_CONFIRM_PHRASE,
        "reason": ("" if local else
                   f"The server is bound to {get_bind_host()}, so write mode can only be enabled by starting it with "
                   f"ENABLE_WRITE_ACTIONS={WRITE_CONFIRM_PHRASE} (START_Zscaler_Assessment_WRITES_ENABLED.bat)."),
    }


def set_write_mode(enable: bool, confirm: str = "") -> dict:
    """Toggle writes for this server process. Enabling needs the typed
    confirmation phrase and a localhost bind; disabling is always allowed.
    Raises ValueError with a plain-language reason."""
    global _write_override
    if not enable:
        _write_override = False
        return write_mode_status()
    if get_bind_host() not in _LOCAL_HOSTS:
        raise ValueError(write_mode_status()["reason"])
    if (confirm or "").strip() != WRITE_CONFIRM_PHRASE:
        raise ValueError(f"Type {WRITE_CONFIRM_PHRASE} exactly to enable write mode.")
    _write_override = True
    return write_mode_status()


# ── Validation helpers ───────────────────────────────────────────────────────

def validate_cloud(cloud: str) -> str:
    cloud = (cloud or "production").strip().lower()
    if cloud not in ALLOWED_CLOUDS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid cloud '{cloud}'. Allowed: {sorted(ALLOWED_CLOUDS)}",
        )
    return cloud


def validate_vanity(vd: str) -> str:
    vd = (vd or "").strip()
    if not vd:
        return ""  # caller decides if required
    if len(vd) > MAX_VANITY_LEN or not _HOST_RE.match(vd):
        raise HTTPException(status_code=400, detail="Invalid vanity domain.")
    return vd


def validate_credential(name: str, value: str, required: bool = True) -> str:
    value = value or ""
    if required and not value.strip():
        raise HTTPException(status_code=400, detail=f"{name} is required.")
    if len(value) > MAX_CRED_LEN:
        raise HTTPException(status_code=400, detail=f"{name} too long.")
    # Block obvious control characters that would never appear in a real cred
    if any(ord(c) < 0x20 and c not in ("\t",) for c in value):
        raise HTTPException(status_code=400, detail=f"{name} contains invalid characters.")
    return value


def validate_customer_id(cid: str) -> str:
    cid = (cid or "").strip()
    if cid and (len(cid) > MAX_CUSTOMER_ID_LEN or not cid.isalnum()):
        raise HTTPException(status_code=400, detail="Invalid customer ID.")
    return cid


def mask_secret(value: Optional[str], keep: int = 3) -> str:
    """Render a credential safely for logs / errors."""
    if not value:
        return "<empty>"
    s = str(value)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}…{s[-keep:]} (len={len(s)})"


def scrub_dict(d: dict, secret_keys: Iterable[str] = ("client_secret", "secret", "password", "token", "api_key")) -> dict:
    """Return a copy of d with secret values masked. Use before logging."""
    secret_keys = {k.lower() for k in secret_keys}
    out = {}
    for k, v in (d or {}).items():
        if isinstance(v, dict):
            out[k] = scrub_dict(v, secret_keys)
        elif k.lower() in secret_keys:
            out[k] = mask_secret(v)
        else:
            out[k] = v
    return out


# ── Middleware ────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply hardening headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
        # Content-Security-Policy — prevents inline-script injection from
        # taking over the GUI and blocks every external network fetch.
        # 'unsafe-inline' on style + script is required because the app
        # ships its UI as inline <style> + <script> in index.html; any
        # CSP tightening past that requires externalizing those blocks.
        # img-src 'self' data: = same-origin images + inline data URIs
        # only (covers the SVG favicon and the /static/branding/ files).
        # connect-src 'self' = API calls scoped to the same origin.
        h.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        # Don't cache API responses — they may carry assessment data
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
            h["Pragma"] = "no-cache"
        return response


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """
    CSRF defense: state-changing requests (POST/PUT/DELETE) from a browser
    must originate from a trusted origin. Non-browser callers (no Origin
    header) are allowed (they cannot be tricked by cross-site requests).
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    async def dispatch(self, request: Request, call_next):
        if request.method not in self.SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin:
                if origin.lower() not in ALLOWED_ORIGINS:
                    return JSONResponse(
                        {"detail": f"Origin not allowed: {origin}"},
                        status_code=403,
                    )
            else:
                # No Origin → check Referer if present
                ref = request.headers.get("referer")
                if ref:
                    p = urlparse(ref)
                    base = f"{p.scheme}://{p.netloc}".lower()
                    if base and base not in ALLOWED_ORIGINS:
                        return JSONResponse(
                            {"detail": f"Referer not allowed: {base}"},
                            status_code=403,
                        )
        return await call_next(request)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured cap."""

    def __init__(self, app: ASGIApp, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return JSONResponse(
                {"detail": f"Request body too large (max {self.max_bytes} bytes)."},
                status_code=413,
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Tiny in-process token-bucket per client IP. Defends against runaway
    scripts hammering the API. Not a substitute for a real WAF, but
    sufficient for a single-user desktop tool.
    """

    def __init__(self, app: ASGIApp, rps: int = 20, burst: int = 60):
        super().__init__(app)
        self.rps = rps
        self.burst = burst
        self.buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_ts)

    async def dispatch(self, request: Request, call_next):
        # Only rate-limit /api/* — static is local
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        tokens, last = self.buckets.get(ip, (float(self.burst), now))
        # Refill
        tokens = min(self.burst, tokens + (now - last) * self.rps)
        if tokens < 1:
            return JSONResponse(
                {"detail": "Rate limit exceeded. Slow down."},
                status_code=429,
                headers={"Retry-After": "1"},
            )
        self.buckets[ip] = (tokens - 1, now)
        # Periodic cleanup
        if len(self.buckets) > 1024:
            cutoff = now - 300
            self.buckets = {k: v for k, v in self.buckets.items() if v[1] > cutoff}
        return await call_next(request)
