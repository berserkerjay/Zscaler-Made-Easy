#!/usr/bin/env python3
"""
Security hardening for the Zscaler Made Easy API server.

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
  ZSCALER_SSO_ENABLED  (default 0)          — require an OpenID Connect
                                               sign-in per person (see
                                               sso.py) instead of the
                                               static UI token, which is
                                               then refused in every form
  ZSCALER_ALLOW_NONLOCAL_BIND                — must equal "YES_I_UNDERSTAND"
                                               to start a local install
                                               bound beyond loopback without
                                               SSO fully configured (the UI
                                               token gate must still be on;
                                               require_safe_bind). Not used
                                               in the container.
"""
from __future__ import annotations

import contextvars
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
# Every cloud a tenant can live on, and its aliases (zscaler_clouds.py is the one table).
import zscaler_clouds as _clouds
ALLOWED_CLOUDS = set(_clouds.ALLOWED)

# Browser-borne origins we trust for state-changing requests and CORS: this
# server's own address on its configured port only (ZSCALER_PORT, default
# 8000). Never another port: a page served by any other local web server
# (port 80 included) is same-site with this one, so its requests carry the
# SameSite=Strict token cookie, and trusting its origin would let it read
# and drive the API. A page this server served on another port or host name
# is still trusted by OriginCheckMiddleware's same-origin rule.
def _allowed_origins() -> set:
    port = get_port() if os.environ.get("ZSCALER_PORT", "").strip() else DEFAULT_PORT
    return {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}


# The companion browser extension (browser_extension/, its ID fixed by the
# public key in its manifest) may POST to these read-only endpoints only:
# the console index and Export from tenant (and Stop on its own job). It is
# trusted for nothing else, so no write can ever come from it. Set
# DLP_CHECK_EXTENSION_ID to another ID for a repacked build, or to "off".
EXTENSION_ID = "febekapiipbdccnkbelfpajhillaplbe"
EXTENSION_POST_PATHS = ("/api/console-index", "/api/dlp-packs/export/start")
_EXTENSION_CANCEL = re.compile(r"^/api/dlp-packs/jobs/[A-Za-z0-9_-]{1,64}/cancel$")


def extension_origin() -> str:
    v = (os.environ.get("DLP_CHECK_EXTENSION_ID") or EXTENSION_ID).strip().lower()
    if v in ("", "off", "0", "none") or not re.fullmatch(r"[a-p]{32}", v):
        return ""
    return f"chrome-extension://{v}"


def extension_may_post(origin: str, path: str) -> bool:
    """The extension's origin, on one of its read-only endpoints. `path` is
    the path the router matches (the request scope's "path"), compared
    exactly: no trailing newline, slash or other variant is the same path."""
    ext = extension_origin()
    return bool(ext) and origin == ext and (path in EXTENSION_POST_PATHS or bool(_EXTENSION_CANCEL.fullmatch(path)))


def from_extension(request: Request) -> bool:
    """Did this request come from the companion extension's origin (its
    Origin header, or its Referer when a browser sent no Origin)? Endpoints
    the extension may call use it to narrow what it may do there further."""
    ext = extension_origin()
    if not ext:
        return False
    origin = request.headers.get("origin")
    if origin:
        return origin.lower().rstrip("/") == ext
    p = urlparse(request.headers.get("referer") or "")
    return f"{p.scheme}://{p.netloc}".lower() == ext


# The jobs the extension starts (Export from tenant): the only ones it may Stop.
EXTENSION_JOB_KINDS = ("export",)



# Hostname pattern for vanity_domain (RFC-1123 label, dot-separated).
_HOST_RE = _clouds.VANITY_RE   # the one vanity-domain pattern (zscaler_clouds.token_url checks it too)

# Credential length caps — hard enough that a junk paste fails fast,
# loose enough not to clip a legit value.
MAX_CRED_LEN = 256
MAX_VANITY_LEN = 253           # full DNS name limit
MAX_CUSTOMER_ID_LEN = 64


# ── Configuration helpers ────────────────────────────────────────────────────

def get_bind_host() -> str:
    """Default: localhost only. Operator must explicitly opt in."""
    return os.environ.get("ZSCALER_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"


DEFAULT_PORT = 8000


def get_port() -> int:
    """The TCP port to listen on: ZSCALER_PORT when it is a whole number
    from 1 to 65535, otherwise 8000 with a warning on stderr (the app
    keeps starting rather than failing on a typo in a start script)."""
    raw = os.environ.get("ZSCALER_PORT", str(DEFAULT_PORT)).strip()
    try:
        port = int(raw)
        if not 1 <= port <= 65535:
            raise ValueError(port)
        return port
    except ValueError:
        import sys
        print(f"  ZSCALER_PORT={raw!r} is not a port number between 1 and 65535; using {DEFAULT_PORT}.", file=sys.stderr)
        return DEFAULT_PORT


ALLOWED_ORIGINS = _allowed_origins()


def get_max_body_bytes() -> int:
    """Request body cap in bytes: ZSCALER_MAX_BODY_MB clamped to 1-100 MB (default 10)."""
    try:
        mb = int(os.environ.get("ZSCALER_MAX_BODY_MB", "10"))
    except ValueError:
        mb = 10
    return max(1, min(mb, 100)) * 1024 * 1024  # 1MB..100MB


def is_debug() -> bool:
    """True when ZSCALER_DEBUG is set: tracebacks and request logs are shown."""
    return os.environ.get("ZSCALER_DEBUG", "0").strip() in ("1", "true", "yes")


WRITE_CONFIRM_PHRASE = "YES_I_UNDERSTAND"
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
# Session override set from the GUI (Deploy Studio > Enable write mode).
# Only honoured while the server is reachable from this computer alone
# (bound to localhost, or a container published on the host's loopback),
# and never persisted: a restart returns to whatever the environment says.
_write_override: "bool | None" = None


def writes_enabled() -> bool:
    """May this server change a tenant? The session toggle wins; otherwise
    ENABLE_WRITE_ACTIONS must equal the confirmation phrase."""
    if _write_override is not None:
        return _write_override
    return os.environ.get("ENABLE_WRITE_ACTIONS") == WRITE_CONFIRM_PHRASE


def typed_phrase_matches(typed: object, phrase: object) -> bool:
    """Is `typed` the confirmation `phrase` a write asks for? Surrounding
    spaces are ignored and letters compare case-insensitively, one character
    for one character: a character matches only when it is the same, or its
    upper AND lower case forms are the same (so 'e' matches 'E', 'é' 'É').
    Deliberately no NFKC or other compatibility folding: a look-alike that
    str.upper() alone would turn into the phrase (dotless 'ı', long 'ſ',
    the 'ﬁ' ligature) or that NFKC would (full-width letters and digits,
    the Kelvin sign) is refused, so the phrase is typed as it is shown.
    Only canonical composition (NFC) is applied, so an accent typed as a
    combining mark is the same character. An empty, blank or non-text
    phrase or answer never matches: there is no way past by sending nothing."""
    import unicodedata
    if not isinstance(typed, str) or not isinstance(phrase, str):
        return False
    want = unicodedata.normalize("NFC", phrase).strip()
    got = unicodedata.normalize("NFC", typed).strip()
    if not want or len(got) != len(want):
        return False
    return all(a == b or (a.upper() == b.upper() and a.lower() == b.lower()) for a, b in zip(got, want))


def write_enable_hint() -> str:
    """How to start the server with writes on, for where it runs: the
    container (a .env setting), Windows (the start script) or Mac/Linux."""
    if os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1":
        return (f"put ENABLE_WRITE_ACTIONS={WRITE_CONFIRM_PHRASE} in the .env file next to docker-compose.yml on the computer "
                "that runs Docker, then run: docker compose up -d (the container restarts with writes on; remove the line "
                "and run it again to go back to read-only)")
    import sys
    if getattr(sys, "frozen", False):
        return (f"turn on write mode with the switch in the app (type {WRITE_CONFIRM_PHRASE} to confirm): the standalone edition starts "
                "read-only every time and ignores ENABLE_WRITE_ACTIONS")
    if os.name == "nt":
        return "start the server with START_Zscaler_Made_Easy_WRITES_ENABLED.bat"
    return f"start the server with: ENABLE_WRITE_ACTIONS={WRITE_CONFIRM_PHRASE} ./start.sh"


def _published_on_loopback() -> bool:
    """Inside the container the server listens on 0.0.0.0, but what reaches
    it from outside is the host address docker-compose.yml publishes it on.
    The compose file passes that same address in (DLP_CHECK_HOST_BIND, also
    used by its ports: line), so the container knows it is reachable from
    the host's loopback only. Unset, or anything but loopback, is no."""
    return (os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1"
            and os.environ.get("DLP_CHECK_HOST_BIND", "").strip() in _LOCAL_HOSTS)


def _toggle_allowed() -> bool:
    """May write mode be switched from the browser? Only while nobody but
    this computer can reach the server."""
    return get_bind_host() in _LOCAL_HOSTS or _published_on_loopback()


def only_this_computer_can_reach() -> bool:
    """True when the server listens on loopback, or is the container
    published on the host's loopback: the same rule for every change the
    browser may make on this machine (write mode, rewriting a pack)."""
    return _toggle_allowed()


def write_mode_status() -> dict:
    """What the GUI shows: whether writes are on, where that comes from,
    and whether the operator may toggle it from the browser."""
    env_on = os.environ.get("ENABLE_WRITE_ACTIONS") == WRITE_CONFIRM_PHRASE
    local = _toggle_allowed()
    return {
        "enabled": writes_enabled(),
        "source": ("session" if _write_override is not None else ("environment" if env_on else "default")),
        "bind_host": get_bind_host(),
        "can_toggle": local,
        "confirm_phrase": WRITE_CONFIRM_PHRASE,
        "how_to_enable": write_enable_hint(),
        "reason": ("" if local else
                   (f"The app runs in a container that is not published on this computer's loopback only "
                    f"(DLP_CHECK_HOST_BIND={os.environ.get('DLP_CHECK_HOST_BIND', '').strip() or 'unset'}), so write mode is not switched "
                    f"from the browser: {write_enable_hint()}."
                    if os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1" else
                    f"The server is bound to {get_bind_host()}, so write mode can only be enabled at start: {write_enable_hint()}.")),
    }


NONLOCAL_BIND_CONFIRM_PHRASE = "YES_I_UNDERSTAND"


def _sso_ready() -> bool:
    import sso as _sso
    return ui_auth_enabled() and _sso.sso_enabled() and not _sso.config_errors()


def require_safe_bind() -> None:
    """Fail closed at startup: a server reachable beyond this computer
    needs its own authentication in front of it — the UI token is a
    bearer secret, not multi-factor authentication (see SECURITY.md).

    In the container (DLP_CHECK_IN_CONTAINER=1) the server always listens
    on 0.0.0.0 inside; what decides who can reach it is the host address
    docker-compose.yml publishes it on (DLP_CHECK_HOST_BIND, loopback by
    default). Loopback starts; anything else starts only with SSO fully
    configured.

    Outside the container: a loopback bind always starts. A wider bind
    with ZSCALER_UI_AUTH=0 is always refused. Otherwise it needs SSO fully
    configured (sso.py), or the operator explicitly accepting the risk
    with ZSCALER_ALLOW_NONLOCAL_BIND=YES_I_UNDERSTAND because they already
    have their own authenticating reverse proxy in front of it. Called
    once at server startup; a variable changed afterwards takes effect
    on the next restart, the same as ENABLE_WRITE_ACTIONS."""
    host = get_bind_host()
    if host not in _LOCAL_HOSTS and not ui_auth_enabled() and not _sso_ready():
        # Checked first, container included: inside the container the server
        # listens on 0.0.0.0, so with the token gate off any process that can
        # reach the container (another container on the same Docker network,
        # anything on the host) could drive the API with no credential.
        raise RuntimeError(
            f"Refusing to start bound to {host}: ZSCALER_UI_AUTH=0 turns off the UI token gate entirely, so "
            "anyone who can reach this server could use the API with no credential at all. Remove ZSCALER_UI_AUTH=0, "
            "or bind to 127.0.0.1 (ZSCALER_BIND_HOST, the default; the container always listens beyond loopback "
            "inside, so there the token gate must stay on)."
        )
    if os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1":
        published = os.environ.get("DLP_CHECK_HOST_BIND", "").strip() or "127.0.0.1"
        if host in _LOCAL_HOSTS or published in _LOCAL_HOSTS or _sso_ready():
            return
        raise RuntimeError(
            f"Refusing to start: the container is published on {published} (DLP_CHECK_HOST_BIND), so other computers "
            "can reach it, and no identity-provider sign-in is configured. Either configure SSO (ZSCALER_SSO_ENABLED=1 "
            "plus every ZSCALER_SSO_* setting, see SECURITY.md), or publish on this computer's loopback only "
            "(DLP_CHECK_HOST_BIND=127.0.0.1, the default)."
        )
    if host in _LOCAL_HOSTS:
        return
    if not ui_auth_enabled():
        raise RuntimeError(
            f"Refusing to start bound to {host}: ZSCALER_UI_AUTH=0 turns off the UI token gate entirely, so "
            "anyone who can reach this host could use the API with no credential at all. Remove ZSCALER_UI_AUTH=0, "
            "or bind to 127.0.0.1 (ZSCALER_BIND_HOST, the default)."
        )
    if (os.environ.get("ZSCALER_ALLOW_NONLOCAL_BIND", "").strip() == NONLOCAL_BIND_CONFIRM_PHRASE):
        return
    if not _sso_ready():
        raise RuntimeError(
            f"Refusing to start bound to {host}: no identity-provider sign-in is configured (ZSCALER_SSO_ENABLED), "
            "so the UI token is the only guard, and it is a bearer secret, not multi-factor authentication. Set "
            "ZSCALER_SSO_ENABLED and every ZSCALER_SSO_* variable so sign-in is required first, or set "
            "ZSCALER_ALLOW_NONLOCAL_BIND=YES_I_UNDERSTAND if you understand the risk and already have your own "
            "authenticating reverse proxy (with TLS) in front of this server."
        )


def set_write_mode(enable: bool, confirm: str = "") -> dict:
    """Toggle writes for this server process. Enabling needs the typed
    confirmation phrase and a server only this computer can reach (a
    localhost bind, or a container published on the host's loopback);
    disabling is always allowed.
    Raises ValueError with a plain-language reason."""
    global _write_override
    if not enable:
        _write_override = False
        return write_mode_status()
    if not _toggle_allowed():
        raise ValueError(write_mode_status()["reason"])
    if (confirm or "").strip() != WRITE_CONFIRM_PHRASE:
        raise ValueError(f"Type {WRITE_CONFIRM_PHRASE} exactly to enable write mode.")
    _write_override = True
    return write_mode_status()


# ── Validation helpers ───────────────────────────────────────────────────────

def validate_cloud(cloud: str) -> str:
    """The tenant's cloud as the app stores it (zscalerten, zscalergov, ...),
    accepting every spelling zscaler_clouds knows; 400 with the accepted
    names when it is not a Zscaler cloud."""
    try:
        return _clouds.normalize(cloud)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def validate_vanity(vd: str) -> str:
    """The vanity domain (a DNS name, at most 253 characters); "" when blank, 400 when malformed."""
    vd = (vd or "").strip()
    if not vd:
        return ""  # caller decides if required
    if len(vd) > MAX_VANITY_LEN or not _HOST_RE.match(vd):
        raise HTTPException(status_code=400, detail="Invalid vanity domain.")
    return vd


def validate_credential(name: str, value: str, required: bool = True) -> str:
    """A client id or secret: present when required, at most 256 characters,
    no control characters; 400 otherwise. The value is never echoed."""
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
    """The ZPA customer id: alphanumeric, at most 64 characters; 400 otherwise."""
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
    """Return a copy of d with secret values replaced by '[redacted]'. Use
    before logging. No character and no length of a secret is kept
    (mask_secret's partial form is for identifiers such as a client id),
    and dicts inside lists are scrubbed too."""
    secret_keys = {k.lower() for k in secret_keys}

    def one(v):
        if isinstance(v, dict):
            return scrub_dict(v, secret_keys)
        if isinstance(v, (list, tuple)):
            return [one(x) for x in v]
        return v
    out = {}
    for k, v in (d or {}).items():
        if str(k).lower() in secret_keys:
            out[k] = "[redacted]" if v not in (None, "") else v
        else:
            out[k] = one(v)
    return out


# ── Middleware ────────────────────────────────────────────────────────────────

CONTENT_SECURITY_POLICY = (
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
        h.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
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

    @staticmethod
    def _trusted(origin: str, request: Request) -> bool:
        """The allowlist, or the page the server itself served: a browser
        sends Origin equal to scheme://Host for a same-origin request, so
        the app works on any port or host name it is reached at (a spare
        port, the machine name, a container mapping) while a page on
        another origin, another local port included, is still refused."""
        o = origin.lower().rstrip("/")
        if o in ALLOWED_ORIGINS:
            return True
        # The router's own path (scope["path"]), not request.url.path: the URL
        # parser drops tabs and newlines, so the two can differ.
        if extension_may_post(o, request.scope.get("path") or ""):
            return True
        host = (request.headers.get("host") or "").lower()
        return bool(host) and o == f"{request.url.scheme}://{host}"

    async def dispatch(self, request: Request, call_next):
        if request.method not in self.SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin:
                if not self._trusted(origin, request):
                    return JSONResponse(
                        {"detail": f"Origin not allowed: {origin}. Open the app at the address the server printed (the launcher does), or set ZSCALER_PORT to the port you use."},
                        status_code=403,
                    )
            else:
                # No Origin → check Referer if present
                ref = request.headers.get("referer")
                if ref:
                    p = urlparse(ref)
                    base = f"{p.scheme}://{p.netloc}".lower()
                    if base and not self._trusted(base, request):
                        return JSONResponse(
                            {"detail": f"Referer not allowed: {base}"},
                            status_code=403,
                        )
        return await call_next(request)


class _BodyTooLarge(Exception):
    """Raised from the wrapped receive() once a body passes the cap."""


class BodySizeLimitMiddleware:
    """Cap every request body at `max_bytes`, whether or not it declares a
    Content-Length. A declared length over the cap is refused before a byte
    is read; a chunked (Transfer-Encoding) or understated body is counted
    as it streams in and cut off the moment it passes the cap, so nothing
    downstream (the audit log, JSON parsing, an upload handler) ever holds
    more than the cap in memory. Pure ASGI, and added outermost, so it runs
    before every other middleware."""

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    def _too_large(self, scope, size: int) -> JSONResponse:
        # A security event in its own right (resource exhaustion attempt or a
        # misbehaving client): recorded with method, path, client and size,
        # never the body. This layer is outside the audit middleware, which
        # therefore never sees the request.
        try:
            import audit as _audit
            client = scope.get("client") or ("?", 0)
            _audit.record("request_too_large", method=scope.get("method"), path=scope.get("path"),
                          client=str(client[0]), bytes=size, limit=self.max_bytes)
        except Exception:  # noqa: BLE001 — logging never blocks the refusal
            pass
        return JSONResponse({"detail": f"Request body too large (max {self.max_bytes} bytes)."}, status_code=413)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in (scope.get("headers") or [])}
        declared = headers.get(b"content-length", b"").decode("latin-1").strip()
        if declared:
            if not declared.isdigit():
                await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
                return
            if int(declared) > self.max_bytes:
                await self._too_large(scope, int(declared))(scope, receive, send)
                return
        seen = 0
        started = False

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await self._too_large(scope, seen)(scope, receive, send)


_monotonic = time.monotonic   # the rate limiter's clock (tests replace it)


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
        now = _monotonic()
        tokens, last = self.buckets.get(ip, (float(self.burst), now))
        # Refill. A monotonic clock, and never a negative refill: with the wall
        # clock, setting it back a day refused every call for a day (429).
        tokens = min(self.burst, tokens + max(0.0, now - last) * self.rps)
        if tokens < 1:
            self.buckets[ip] = (tokens, now)   # a "last" ahead of the clock is moved back to it
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


# ── UI access token ───────────────────────────────────────────────────────────
# The web UI and API are for the person who started the server. A random
# token is minted per process (or taken from ZSCALER_UI_TOKEN); the launcher
# opens the browser with it, the page stores it in an HttpOnly cookie, and
# every other request must carry it (cookie, X-DLP-Check-Token header or a
# Bearer token). Without it, another process or user on the same machine
# gets 401 instead of the tenant. ZSCALER_UI_AUTH=0 disables it (not
# recommended; documented for kiosk-style single-user setups).
import secrets as _secrets

UI_TOKEN_COOKIE = "dlpcheck_token"
UI_TOKEN_HEADER = "X-DLP-Check-Token"
UI_TOKEN_FILE = "ui_token.txt"
SSO_SESSION_COOKIE = "dlpcheck_session"   # with SSO on: the per-person session id (sso.py), never the UI token
SSO_LOGIN_COOKIE = "dlpcheck_sso_login"   # with SSO on: ties a sign-in's state to the browser that started it
SSO_CALLBACK_PATH = "/api/auth/sso/callback"
_ui_token: "str | None" = None
# Paths a browser needs before it can present the token: the page itself,
# its assets, the standalone report pages (they then call the API with the
# cookie) and the unlock/status/ping calls.
_UI_AUTH_EXEMPT_PREFIXES = ("/static/", "/report/")
_UI_AUTH_EXEMPT_PATHS = {"/", "/app.css", "/permissions", "/help", "/api/auth/status", "/api/auth/unlock", "/api/ping", "/favicon.ico",
                          "/api/auth/sso/login", "/api/auth/sso/callback", "/api/auth/logout"}
# Who is making the request being handled, set by UIAuthMiddleware and
# read by the audit log and the writer check: {"actor", "session"}.
_CALLER: "contextvars.ContextVar[Optional[dict]]" = contextvars.ContextVar("dlp_check_caller", default=None)
LOCAL_TOKEN_ACTOR = "local UI token"
LOCAL_NO_TOKEN_ACTOR = "local, no UI token"
NO_REQUEST_ACTOR = "the app itself (no signed-in request)"
NOT_SIGNED_IN = "not signed in"


def ui_auth_enabled() -> bool:
    """True unless ZSCALER_UI_AUTH is 0/false/no/off: every caller must present the UI token."""
    return os.environ.get("ZSCALER_UI_AUTH", "1").strip().lower() not in ("0", "false", "no", "off")


def ui_token() -> str:
    """The token for this process (stable for its lifetime)."""
    global _ui_token
    if _ui_token is None:
        _ui_token = (os.environ.get("ZSCALER_UI_TOKEN") or "").strip() or _secrets.token_urlsafe(24)
    return _ui_token


def ui_token_ok(candidate: Optional[str]) -> bool:
    """Constant-time comparison of a presented token with this process's token.
    Compared as UTF-8 bytes: compare_digest on str raises TypeError for any
    non-ASCII character, which a header or cookie can carry, and that would
    turn a wrong token into an unaudited 500 instead of a 401."""
    c = (candidate or "").strip()
    return bool(c) and _secrets.compare_digest(c.encode("utf-8", "surrogateescape"), ui_token().encode("utf-8", "surrogateescape"))


def write_ui_token_file(app_dir: str) -> Optional[str]:
    """Write the token next to the app (owner-only) so the launcher can open
    the browser with it. Returns the path, or None when it could not be written."""
    if not ui_auth_enabled():
        return None
    path = os.path.join(app_dir, UI_TOKEN_FILE)
    tmp = None
    try:
        import tempfile
        fd, tmp = tempfile.mkstemp(prefix=".ui_token_", dir=app_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(ui_token())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        tmp = None
        return path
    except OSError:
        return None
    finally:
        if tmp is not None:   # a failed write leaves no copy of the token behind (CWE-459)
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _token_from_request(request: Request) -> Optional[str]:
    h = request.headers.get(UI_TOKEN_HEADER)
    if h:
        return h
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:]
    return request.cookies.get(UI_TOKEN_COOKIE)


def _gate_on() -> bool:
    """The gate is on unless ZSCALER_UI_AUTH=0; SSO on always means sign-in first."""
    import sso as _sso
    return ui_auth_enabled() or _sso.sso_enabled()


def sso_session(request: Request) -> Optional[dict]:
    """With SSO on: this browser's live session (sso.get_session), or None."""
    import sso as _sso
    if not _sso.sso_enabled():
        return None
    return _sso.get_session(request.cookies.get(SSO_SESSION_COOKIE))


def ui_request_ok(request: Request) -> bool:
    """Is this request allowed through the gate? With SSO on only a live
    signed-in session counts: the static UI token is refused in every
    form. Otherwise the UI token (header, Bearer or cookie)."""
    import sso as _sso
    if _sso.sso_enabled():
        return sso_session(request) is not None
    return (not ui_auth_enabled()) or ui_token_ok(_token_from_request(request))


def _https(request: Request) -> bool:
    return request.url.scheme == "https" or (request.headers.get("x-forwarded-proto") or "").lower() == "https"


def set_ui_cookie(response, request: Request) -> None:
    """Attach the token cookie: HttpOnly, SameSite=Strict, Secure when the
    page itself came over HTTPS (a reverse proxy in front of the server)."""
    response.set_cookie(UI_TOKEN_COOKIE, ui_token(), httponly=True, samesite="strict", secure=_https(request), path="/", max_age=12 * 3600)


def set_session_cookie(response, request: Request, session_id: str) -> None:
    """Attach an SSO session cookie: only the random session id, HttpOnly,
    SameSite=Lax (the browser arrives from the identity provider), Secure
    over HTTPS."""
    response.set_cookie(SSO_SESSION_COOKIE, session_id, httponly=True, samesite="lax", secure=_https(request), path="/", max_age=12 * 3600)


def set_login_cookie(response, request: Request, binding: str) -> None:
    """Attach the sign-in binding cookie (sso.new_login_binding): HttpOnly,
    SameSite=Lax (the identity provider's redirect back is a cross-site
    top-level GET), Secure over HTTPS, sent to the callback only, and gone
    when the pending sign-in would expire anyway."""
    import sso as _sso
    response.set_cookie(SSO_LOGIN_COOKIE, binding, httponly=True, samesite="lax", secure=_https(request),
                        path=SSO_CALLBACK_PATH, max_age=_sso._PENDING_TTL_SECONDS)


def clear_login_cookie(response, request: Request) -> None:
    response.delete_cookie(SSO_LOGIN_COOKIE, path=SSO_CALLBACK_PATH, httponly=True, samesite="lax", secure=_https(request))


def clear_session_cookie(response, request: Request) -> None:
    response.delete_cookie(SSO_SESSION_COOKIE, path="/", httponly=True, samesite="lax", secure=_https(request))


def current_actor(request: Optional[Request] = None) -> Optional[str]:
    """Who a request is from, for the audit log and a proposal's `by`: the
    signed-in email (or subject) under SSO, otherwise "local UI token"
    (or "local, no UI token" with the gate off). With `request`, read from
    that request (None under SSO when it carries no live session);
    without, the request being handled now (UIAuthMiddleware), or
    "the app itself" outside any request."""
    if request is not None:
        caller = _caller_for(request, sso_session(request))
        return None if caller["actor"] == NOT_SIGNED_IN else caller["actor"]
    caller = _CALLER.get()
    return (caller or {}).get("actor") or NO_REQUEST_ACTOR


def _caller_for(request: Request, session: Optional[dict]) -> dict:
    import sso as _sso
    if _sso.sso_enabled():
        who = (session or {}).get("email") or (session or {}).get("sub")
        return {"actor": str(who) if who else NOT_SIGNED_IN, "session": session}
    return {"actor": LOCAL_TOKEN_ACTOR if ui_auth_enabled() else LOCAL_NO_TOKEN_ACTOR, "session": None}


def may_write() -> bool:
    """May the person making this request change the tenant? Always yes
    without SSO or without ZSCALER_SSO_WRITERS; otherwise only the
    listed groups and email addresses."""
    import sso as _sso
    if not _sso.sso_enabled() or not _sso.writers():
        return True
    return _sso.is_writer((_CALLER.get() or {}).get("session"))


def require_writer() -> None:
    """403 with a plain reason when this person may not change the tenant
    (sso.is_writer). Called by every endpoint that writes to the tenant,
    before its write-mode check."""
    if not may_write():
        raise HTTPException(status_code=403, detail=(
            f"You are signed in as {current_actor()}, who may not change the tenant on this server: only the users and "
            "groups listed in ZSCALER_SSO_WRITERS may turn on write mode, deploy, remove, import, undo, or apply and roll "
            "back proposals. You can still assess, read and preview. Ask the person who runs this server to add you."))


def _audit_denied(request: Request, event: str, reason: str) -> None:
    """Write a rejected sign-in to the audit log. This middleware sits
    outside AuditMiddleware, so its own 401s would otherwise go unrecorded.
    The token that was offered is never written."""
    import audit as _audit
    _audit.record(event, actor=NOT_SIGNED_IN, method=request.method, path=request.url.path,
                  client=request.client.host if request.client else "?", reason=reason)


_TEST_CLIENT_HOST = "testserver"   # Starlette's in-process TestClient; never a real socket


def _loopback_host_header(request: Request) -> bool:
    """True when the Host header names this computer's loopback: "localhost"
    or a loopback IP address literal (127.0.0.0/8, ::1), what a browser sends
    for http://localhost:<port>/. A DNS name is never trusted for looking like
    one (127.0.0.1.nip.io, 127.attacker.example): a rebinding attacker picks
    the name. The test client's "testserver" counts only on the in-process
    transport, whose scope["server"] carries that name instead of an IP."""
    import ipaddress
    host = (request.headers.get("host") or "").strip().lower()
    if not host:
        return True          # HTTP/1.0 without Host: not a browser, and not reachable by rebinding
    if host.startswith("["):
        name = host[1:host.find("]")] if "]" in host else host
    else:
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if name == "localhost":
        return True
    if name == _TEST_CLIENT_HOST:
        server = request.scope.get("server") or ("",)
        return bool(server) and server[0] == _TEST_CLIENT_HOST
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _arrived_beyond_loopback(request: Request) -> bool:
    """True when the connection came in on a non-loopback IP address of
    this machine (scope["server"]); False for loopback, a host name such as
    the test client's, or a Unix socket."""
    import ipaddress
    server = request.scope.get("server")
    if not server or not isinstance(server, (tuple, list)) or not server[0]:
        return False
    try:
        return not ipaddress.ip_address(str(server[0]).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class UIAuthMiddleware(BaseHTTPMiddleware):
    """Require the UI token on every request except the ones a browser
    needs to obtain it. `/?token=...` (what the launcher opens) sets the
    cookie and redirects to `/` so the token never stays in the URL —
    unless SSO is enabled (sso.py), in which case the static token is
    refused in every form (header, Bearer, cookie, ?token= and unlock):
    only a per-person session from a completed identity-provider login
    (/api/auth/sso/callback) gets in. Also records who each request is
    from (current_actor) for the audit log and the writer check."""

    async def dispatch(self, request: Request, call_next):
        caller = _caller_for(request, sso_session(request))
        if caller["actor"] == LOCAL_TOKEN_ACTOR and not ui_token_ok(_token_from_request(request)):
            # A public route (unlock, status, a page) reached without the token:
            # the audit log must not credit it to the token holder.
            caller = {"actor": NOT_SIGNED_IN, "session": None}
        token = _CALLER.set(caller)
        try:
            return await self._dispatch(request, call_next)
        finally:
            _CALLER.reset(token)

    async def _dispatch(self, request: Request, call_next):
        if not _gate_on():
            # The startup check reads ZSCALER_BIND_HOST; a server started some
            # other way (uvicorn --host 0.0.0.0) is caught here: with the token
            # gate off, only a request that arrived on a loopback address is
            # served. scope["server"] is the local address the connection came
            # in on; a non-IP name (the test client's "testserver") or a Unix
            # socket is local by construction.
            if not _loopback_host_header(request):
                # DNS rebinding: a web page whose own name resolves to
                # 127.0.0.1 would otherwise drive an unauthenticated API.
                _audit_denied(request, "auth_denied", "ZSCALER_UI_AUTH=0 and the Host header is not a loopback name")
                return JSONResponse({"detail": "UI authentication is turned off (ZSCALER_UI_AUTH=0), so only http://localhost, "
                                               "127.0.0.1 or [::1] may be used to reach this server."}, status_code=403)
            if _arrived_beyond_loopback(request):
                _audit_denied(request, "auth_denied", "ZSCALER_UI_AUTH=0 and the request arrived on a network address")
                return JSONResponse({"detail": "UI authentication is turned off (ZSCALER_UI_AUTH=0), so this server only answers "
                                               "on this computer's loopback address. Turn the UI token back on to serve the network."},
                                    status_code=503)
            return await call_next(request)
        import sso as _sso
        path = request.url.path
        if path == "/" and request.query_params.get("token") and not _sso.sso_enabled():
            from fastapi.responses import RedirectResponse
            if ui_token_ok(request.query_params.get("token")):
                resp = RedirectResponse("/", status_code=303)
                set_ui_cookie(resp, request)
                return resp
            _audit_denied(request, "auth_denied", "the UI token in the address was not valid")
            return JSONResponse({"detail": "That UI token is not valid for this server. Read ui_token.txt next to the app (or the console) and try again.",
                                 "token_required": True}, status_code=401)
        if path in _UI_AUTH_EXEMPT_PATHS or any(path.startswith(p) for p in _UI_AUTH_EXEMPT_PREFIXES):
            resp = await call_next(request)
            if path == "/api/auth/sso/callback" and resp.status_code == 401:
                # A GET, so AuditMiddleware skips it; a failed sign-in is still a security event.
                _audit_denied(request, "sso_login_failed", "the identity provider sign-in was not completed or could not be verified")
            return resp
        if ui_request_ok(request):
            return await call_next(request)
        offered = _token_from_request(request)
        _audit_denied(request, "auth_denied",
                      ("a UI token was offered, but this server requires SSO sign-in" if _sso.sso_enabled() else "invalid UI token")
                      if offered else "no UI token or sign-in")
        if _sso.sso_enabled():
            return JSONResponse({"detail": "Sign in required.", "token_required": True, "sso_required": True,
                                 "sso_login_url": "/api/auth/sso/login"}, status_code=401)
        return JSONResponse({"detail": "UI token required. Open the app from the launcher, or paste the token from ui_token.txt (next to the app) into the unlock box.",
                             "token_required": True}, status_code=401)
