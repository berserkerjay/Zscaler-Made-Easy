"""Audit log: one line per API call that can change something.

Every non-GET request to /api/* is appended to audit.log (JSON lines,
owner-only, git-ignored; path in DLP_CHECK_AUDIT) with the time, method,
path, status, duration, caller address, who made the call (`actor`: the
signed-in email under SSO, otherwise "local UI token"), whether write
mode was on, and a redacted view of the request body (keys that look like secrets or tokens
are dropped, long values truncated; for a classic-API sign-in the admin
login and any vanity domain sent with it are dropped too, user rule 3). Write-mode toggles and updates go
through the same log. Nothing here is ever sent anywhere; the file is
evidence for the operator and the customer.

The log is capped by size: past DLP_CHECK_AUDIT_MAX_MB (default 20) the
oldest half is rolled to audit.log.1. A line that cannot be written is
reported on stderr (logger.error), never silently dropped."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Dict, Optional

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCK = threading.Lock()
_SECRET_KEY = re.compile(r"secret|token|password|passwd|credential|authorization|cookie|api_?key|private_?key", re.I)
# The classic ZIA API signs in with an admin login (`username`), and a
# vanity domain sent alongside it is stale form data: neither may appear in
# a record (user rule 3). A OneAPI vanity domain is the tenant's name and stays.
_IDENTITY_KEY = re.compile(r"^(user_?name|login|admin_?login)$", re.I)
_VANITY_KEY = re.compile(r"^vanity_?domain$", re.I)
# Fields that carry uploaded customer content (log bundles, PAC files, policy
# exports, DLP test corpora and evidence): never written to the audit log,
# not even a prefix; the log keeps that the field was sent and its size.
_CONTENT_KEY = re.compile(r"^(content|corpus|export|text|samples?|evidence|raw|payload)$", re.I)
_MAX_VALUE = 200
_MAX_KEYS = 40
logger = logging.getLogger("dlp_check.audit")


def path() -> str:
    return os.environ.get("DLP_CHECK_AUDIT") or os.path.join(_APP_DIR, "audit.log")


def _omitted(v: Any) -> str:
    """What the audit log says in place of uploaded content: its size only."""
    if isinstance(v, str):
        return f"[omitted: {len(v)} chars]"
    if isinstance(v, (list, dict)):
        return f"[omitted: {len(v)} items]"
    return "[omitted]"


def redact(value: Any, depth: int = 0) -> Any:
    """Copy a request body with secret-looking keys removed and values shortened."""
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        classic = _is_classic(value)
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_KEYS:
                out["…"] = f"{len(value) - _MAX_KEYS} more keys"
                break
            if _SECRET_KEY.search(str(k)) or _IDENTITY_KEY.search(str(k)) or (classic and _VANITY_KEY.search(str(k))):
                out[str(k)] = "[redacted]"
            elif _CONTENT_KEY.match(str(k)):
                out[str(k)] = _omitted(v)
            else:
                out[str(k)] = redact(v, depth + 1)
        return out
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value[:20]] + (["…"] if len(value) > 20 else [])
    if isinstance(value, str):
        return value if len(value) <= _MAX_VALUE else value[:_MAX_VALUE] + "…"
    return value


def _is_classic(d: Dict[str, Any]) -> bool:
    """True when the dict is a classic-API (legacy) sign-in: the stated
    method, or the one tenant_auth infers (a username or API key and no
    client id). An unknown method is treated as classic, so in doubt the
    vanity domain is dropped rather than kept."""
    if not any(k in d for k in ("auth_method", "username", "api_key")):
        return False
    try:
        import tenant_auth
        return tenant_auth.method_of({k: str(d.get(k) or "") for k in ("auth_method", "username", "api_key", "client_id")}) == tenant_auth.LEGACY
    except ValueError:
        return True
    except Exception:  # noqa: BLE001
        return bool(d.get("username") or d.get("api_key")) and not d.get("client_id")


def _actor() -> str:
    """Who the request being handled is from (security.current_actor)."""
    try:
        import security
        return security.current_actor()
    except Exception:  # noqa: BLE001
        return "unknown"


def report_failure(what: str, error: Any) -> None:
    """Say loudly that an audit line was lost: always on stderr, and
    through logger.error too when logging is set up."""
    msg = f"AUDIT LOG WRITE FAILED: {what} was not recorded in {path()} ({error})."
    if logger.hasHandlers():
        logger.error(msg)
    try:
        print(msg, file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001
        pass


def record(event: str, **fields: Any) -> Optional[str]:
    """Append one event, with the actor (who made the call) unless the
    caller names one. Returns the path written, or None when the log
    could not be written (never raises; auditing must not break a call,
    but the failure is reported on stderr)."""
    entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, "actor": fields.pop("actor", None) or _actor()}
    entry.update({k: redact(v) for k, v in fields.items()})
    line = json.dumps(entry, default=str, separators=(",", ":")) + "\n"
    p = path()
    try:
        with _LOCK:
            _rotate_if_needed(p)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
        return p
    except OSError as e:
        report_failure(f"the '{event}' event", e)
        return None


def _rotate_if_needed(p: str) -> None:
    try:
        limit = int(float(os.environ.get("DLP_CHECK_AUDIT_MAX_MB", "20") or 20) * 1024 * 1024)
    except ValueError:
        limit = 20 * 1024 * 1024
    try:
        if os.path.getsize(p) < limit:
            return
    except OSError:
        return
    try:
        os.replace(p, p + ".1")
    except OSError:
        pass


def tail(n: int = 200) -> list:
    """The last n entries (for the operator; never exposed without the UI token)."""
    p = path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


class AuditMiddleware:
    """ASGI middleware: log every non-GET /api/* call with its outcome.
    Reads the body once and replays it to the app."""

    def __init__(self, app, writes_enabled=None):
        self.app = app
        self.writes_enabled = writes_enabled or (lambda: None)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") in ("GET", "HEAD", "OPTIONS") or not scope.get("path", "").startswith("/api/"):
            await self.app(scope, receive, send)
            return
        body = b""
        more = True
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
        parsed: Any = None
        if body:
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                parsed = f"<{len(body)} bytes>"
        replayed = {"done": False}

        async def replay():
            if not replayed["done"]:
                replayed["done"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            # A streaming response keeps polling receive() to notice a real
            # disconnect; hand that through instead of faking one.
            return await receive()

        status = {"code": None}
        started = time.time()

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                status["code"] = message.get("status")
            await send(message)

        try:
            await self.app(scope, replay, send_wrapper)
        finally:
            client = scope.get("client") or ("?", 0)
            try:
                wm = self.writes_enabled()
            except Exception:  # noqa: BLE001
                wm = None
            record("api", method=scope.get("method"), path=scope.get("path"), status=status["code"],
                   ms=round((time.time() - started) * 1000), client=f"{client[0]}", write_mode=wm, body=parsed)
