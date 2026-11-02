"""Audit log: one line per API call that can change something.

Every non-GET request to /api/* is appended to audit.log (JSON lines,
owner-only, git-ignored; path in DLP_CHECK_AUDIT) with the time, method,
path, status, duration, caller address, who made the call (`actor`: the
signed-in email under SSO, the account's user name on a team server,
otherwise "local UI token"; on a team server also the tenant `profile` the
request named), whether write
mode was on, and a redacted view of the request body (keys that look like secrets or tokens
are dropped, long values truncated; for a classic-API sign-in the admin
login and any vanity domain sent with it are dropped too, user rule 3). Write-mode toggles and updates go
through the same log. Nothing here is ever sent anywhere; the file is
evidence for the operator and the customer.

The log is append-only and capped by size: past DLP_CHECK_AUDIT_MAX_MB
(default 20, at most 1024; anything but a positive number is the default)
the log is rolled to audit.log.1, so at most two files of that size are
kept. It is written owner-only (0600, tightened again on every line) and
never through a symbolic link planted at its name. A line that cannot be
written is reported on stderr (logger.error), never silently dropped."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Dict, Optional
import store_crypto

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCK = threading.Lock()
_SECRET_KEY = re.compile(r"secret|token|password|passwd|credential|authorization|cookie|api_?key|private_?key", re.I)
# The classic ZIA API signs in with an admin login (`username`), and a
# vanity domain sent alongside it is stale form data: neither may appear in
# a record (user rule 3). A OneAPI vanity domain is the tenant's name and stays.
_IDENTITY_KEY = re.compile(r"^(user_?name|login|admin_?login)$", re.I)
_VANITY_KEY = re.compile(r"^vanity_?domain$", re.I)
# Fields that carry uploaded customer content (log bundles, PAC files, policy
# exports, DLP test corpora and evidence, the hosts a HAR file named): never
# written to the audit log, not even a prefix; the log keeps that the field
# was sent and its size.
_CONTENT_KEY = re.compile(r"^(content|corpus|export|text|samples?|evidence|raw|payload|har_hosts)$", re.I)
_MAX_VALUE = 200
_MAX_KEYS = 40
_MAX_KEY = 64          # a key name is the caller's text too: a megabyte-long one is not written whole (CWE-779)
FILE_MODE = 0o600
DEFAULT_MAX_MB = 20.0
MAX_MAX_MB = 1024.0
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


def _secret_values(value: Any, depth: int = 0) -> list:
    """The text values under secret-named keys of a request body (a typed
    client secret, password or API key), so a copy of one pasted into
    another field (a note, a customer name) is masked there too."""
    out: list = []
    if depth > 4:
        return out
    if isinstance(value, dict):
        for k, v in list(value.items())[:_MAX_KEYS]:
            if isinstance(v, str) and len(v.strip()) >= 6 and _SECRET_KEY.search(str(k)):
                out.append(v.strip())
            elif isinstance(v, (dict, list)):
                out += _secret_values(v, depth + 1)
    elif isinstance(value, list):
        for v in value[:20]:
            out += _secret_values(v, depth + 1)
    return out


def _mask_values(text: str, secrets: tuple) -> str:
    if not secrets:
        return text
    import tenant_auth
    for sv in secrets:
        for form in sorted(tenant_auth.secret_forms(sv), key=len, reverse=True):
            if form in text:
                text = text.replace(form, "[redacted]")
    return text


def redact(value: Any, depth: int = 0, secrets: tuple = ()) -> Any:
    """Copy a request body with secret-looking keys removed and values
    shortened; the body's own secret values are masked wherever else they
    appear (`secrets`, found by _secret_values when not given)."""
    if depth == 0 and not secrets:
        secrets = tuple(_secret_values(value))
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        classic = _is_classic(value)
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_KEYS:
                out["…"] = f"{len(value) - _MAX_KEYS} more keys"
                break
            name = _key_name(k, secrets)
            if _SECRET_KEY.search(str(k)) or _IDENTITY_KEY.search(str(k)) or (classic and _VANITY_KEY.search(str(k))):
                out[name] = "[redacted]"
            elif _CONTENT_KEY.match(str(k)):
                out[name] = _omitted(v)
            else:
                out[name] = redact(v, depth + 1, secrets)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, depth + 1, secrets) for v in value[:20]] + (["…"] if len(value) > 20 else [])
    if isinstance(value, str):
        value = _mask_values(value, secrets)
        return value if len(value) <= _MAX_VALUE else value[:_MAX_VALUE] + "…"
    return value


def _key_name(k: Any, secrets: tuple) -> str:
    """A body key as the log writes it: secrets masked, at most _MAX_KEY characters."""
    name = _mask_values(str(k), secrets)
    return name if len(name) <= _MAX_KEY else name[:_MAX_KEY] + "…"


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
    """Who the request being handled is from (security.current_actor). On a
    team server, a background job a person started is theirs too: its
    entries name them (the job carries their team context, team_server)."""
    try:
        import security
        who = security.current_actor()
        if who == security.NO_REQUEST_ACTOR:
            team = _team_ctx()
            if team and team.get("username"):
                return str(team["username"])
        return who
    except Exception:  # noqa: BLE001
        return "unknown"


def _team_ctx() -> Optional[Dict[str, Any]]:
    try:
        import team_server
        return team_server.context() if team_server.enabled() else None
    except Exception:  # noqa: BLE001
        return None


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
    # On a team server every entry made for a request that named a tenant
    # profile says which, so a person sees only the entries of the tenant
    # profiles they may read (team_server.filter_audit_entries).
    team = _team_ctx()
    if team and team.get("profile") and "profile" not in fields:
        entry["profile"] = str(team["profile"])[:64]
    secrets = tuple(_secret_values(fields))
    entry.update({k: redact(v, 0, secrets) for k, v in fields.items()})
    line = store_crypto.seal_text(json.dumps(entry, default=str, separators=(",", ":"))) + "\n"
    p = path()
    try:
        with _LOCK:
            _rotate_if_needed(p)
            # Append-only, never through a link planted at the log's name
            # (CWE-59), and owner-only even when the file was made wider.
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), FILE_MODE)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                if hasattr(os, "fchmod"):
                    try:
                        os.fchmod(f.fileno(), FILE_MODE)
                    except OSError:
                        pass
                f.write(line)
        return p
    except OSError as e:
        report_failure(f"the '{event}' event", e)
        return None


def max_bytes() -> int:
    """The size past which the log is rolled to audit.log.1:
    DLP_CHECK_AUDIT_MAX_MB, default 20. A value that is not a positive
    finite number is the default (0 would roll, and so lose, the history on
    every line; 'inf' would raise); at most MAX_MAX_MB."""
    import math
    try:
        mb = float(os.environ.get("DLP_CHECK_AUDIT_MAX_MB", "") or DEFAULT_MAX_MB)
    except ValueError:
        mb = DEFAULT_MAX_MB
    if not math.isfinite(mb) or mb <= 0:
        mb = DEFAULT_MAX_MB
    return max(1, int(min(mb, MAX_MAX_MB) * 1024 * 1024))


def _rotate_if_needed(p: str) -> None:
    limit = max_bytes()
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
    """The last n entries (for the operator; never exposed without the UI
    token). n of 0 or less is none, never the whole log."""
    p = path()
    try:
        n = int(n)
    except (TypeError, ValueError):
        return []
    if n <= 0:
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(store_crypto.open_text(ln.rstrip("\n"))))
        except (ValueError, store_crypto.StoreLocked):
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
            except (ValueError, UnicodeDecodeError, RecursionError):
                # RecursionError: JSON nested too deep to decode. The call is
                # still recorded (by size) and the app answers it with a 400.
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
