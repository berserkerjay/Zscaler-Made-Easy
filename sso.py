"""Optional SSO (OpenID Connect, Authorization Code + PKCE) — off by
default, an opt-in front door that replaces the static UI token with a
sign-in per person. security.UIAuthMiddleware still gates every request;
with SSO on it asks for a signed-in session instead of the UI token.

Off (ZSCALER_SSO_ENABLED unset): none of this runs, nothing changes.
On but incompletely configured: the server refuses to start rather
than silently falling back to the static-token shortcuts, which would
defeat the point of turning it on. On and configured: any standards-
compliant OpenID Connect provider works (Okta, Entra ID / Azure AD,
Google Workspace, Auth0, Keycloak, ...) — no vendor-specific code.

    ZSCALER_SSO_ENABLED       "1" turns this on; unset/"0" leaves the
                              server exactly as it was.
    ZSCALER_SSO_ISSUER        e.g. https://your-org.okta.com/oauth2/default
    ZSCALER_SSO_CLIENT_ID     from the identity provider's app registration
    ZSCALER_SSO_CLIENT_SECRET from the same registration
    ZSCALER_SSO_REDIRECT_URL  must exactly match what's registered there,
                              e.g. http://localhost:8000/api/auth/sso/callback
    ZSCALER_SSO_SCOPES        optional, default "openid email profile"
    ZSCALER_SSO_IDLE_MINUTES  optional, default 30: a session unused this
                              long ends (every session ends after 12 hours)
    ZSCALER_SSO_GROUPS_CLAIM  optional, default "groups": the ID token
                              claim that lists the person's groups
    ZSCALER_SSO_ALLOWED_GROUPS optional, comma-separated: only people in
                              one of these groups may sign in
    ZSCALER_SSO_WRITERS       optional, comma-separated groups or email
                              addresses: only they may change the tenant
                              (write mode, deploy, removal, import, undo,
                              proposal apply and rollback)

Each sign-in gets its own random session id, kept in memory on the
server with who signed in (sub, email, groups); the browser's cookie
carries only that id. A restart of the server signs everyone out.

This is meant for the container / server deployment, run by more than
one person behind a shared URL. The desktop launcher's `?token=...`
shortcut is a local, single-operator convenience that this feature
turns off once SSO is on (see security.py) — the two are not meant to
be used together.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import jwt
import requests

REQUIRED_ENV = ("ZSCALER_SSO_ISSUER", "ZSCALER_SSO_CLIENT_ID", "ZSCALER_SSO_CLIENT_SECRET", "ZSCALER_SSO_REDIRECT_URL")

_DISCOVERY_CACHE: Dict[str, Dict[str, Any]] = {}
_JWKS_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 3600
_PENDING_LOGINS: Dict[str, Dict[str, Any]] = {}   # state -> {nonce, verifier, at}
_PENDING_TTL_SECONDS = 600
_HTTP_TIMEOUT = 10
_SESSIONS: Dict[str, Dict[str, Any]] = {}          # session id -> {sub, email, groups, created, last_seen, expires}
_SESSIONS_LOCK = threading.Lock()
SESSION_MAX_SECONDS = 12 * 3600


def sso_enabled() -> bool:
    return os.environ.get("ZSCALER_SSO_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")


def config_errors() -> List[str]:
    """What's missing to actually use SSO now that it's switched on. Empty means ready."""
    if not sso_enabled():
        return []
    errors = [f"{name} is not set" for name in REQUIRED_ENV if not os.environ.get(name, "").strip()]
    issuer = os.environ.get("ZSCALER_SSO_ISSUER", "").strip()
    if issuer and not issuer.startswith("https://") and not any(
        issuer.startswith(f"http://{h}") for h in ("127.0.0.1", "localhost", "[::1]")
    ):
        errors.append("ZSCALER_SSO_ISSUER must be https:// (a plain http:// identity provider can be spoofed on the network)")
    return errors


def require_configured() -> None:
    """Fail closed: called at server startup and again before every login
    attempt, so a variable removed after boot is caught too."""
    errors = config_errors()
    if errors:
        raise RuntimeError(
            "ZSCALER_SSO_ENABLED is set but SSO is not fully configured: " + "; ".join(errors) +
            ". Set every ZSCALER_SSO_* variable, or unset ZSCALER_SSO_ENABLED to run without SSO."
        )


def _issuer() -> str:
    return os.environ.get("ZSCALER_SSO_ISSUER", "").rstrip("/")


def _scopes() -> str:
    return os.environ.get("ZSCALER_SSO_SCOPES", "openid email profile")


def _cached(cache: Dict[str, Dict[str, Any]], key: str):
    entry = cache.get(key)
    if entry and entry["at"] > time.time() - _CACHE_TTL_SECONDS:
        return entry["value"]
    return None


def discovery() -> Dict[str, Any]:
    """The issuer's OpenID Connect discovery document, cached for an hour."""
    issuer = _issuer()
    cached = _cached(_DISCOVERY_CACHE, issuer)
    if cached is not None:
        return cached
    r = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=_HTTP_TIMEOUT)
    r.raise_for_status()
    doc = r.json()
    missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if k not in doc]
    if missing:
        raise RuntimeError(f"The identity provider's discovery document is missing {', '.join(missing)}.")
    _DISCOVERY_CACHE[issuer] = {"value": doc, "at": time.time()}
    return doc


def jwks() -> List[Dict[str, Any]]:
    uri = discovery()["jwks_uri"]
    cached = _cached(_JWKS_CACHE, uri)
    if cached is not None:
        return cached
    r = requests.get(uri, timeout=_HTTP_TIMEOUT)
    r.raise_for_status()
    keys = r.json().get("keys", [])
    _JWKS_CACHE[uri] = {"value": keys, "at": time.time()}
    return keys


def _pkce_pair() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _sweep_pending() -> None:
    cutoff = time.time() - _PENDING_TTL_SECONDS
    for state in [s for s, v in _PENDING_LOGINS.items() if v["at"] < cutoff]:
        _PENDING_LOGINS.pop(state, None)


def start_login() -> str:
    """Build the redirect to the identity provider and remember the
    state/nonce/PKCE verifier server-side until the callback arrives.
    Returns the URL to send the browser to."""
    require_configured()
    _sweep_pending()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    _PENDING_LOGINS[state] = {"nonce": nonce, "verifier": verifier, "at": time.time()}
    params = {
        "response_type": "code",
        "client_id": os.environ["ZSCALER_SSO_CLIENT_ID"],
        "redirect_uri": os.environ["ZSCALER_SSO_REDIRECT_URL"],
        "scope": _scopes(),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return discovery()["authorization_endpoint"] + "?" + urlencode(params)


def complete_login(state: str, code: str) -> Dict[str, Any]:
    """Exchange the authorization code for tokens and verify the ID
    token's signature, issuer, audience and nonce. Returns the verified
    claims (sub, email, ...) on success. Raises on any failure — every
    failure here means the login did not happen; nothing is granted."""
    require_configured()
    _sweep_pending()
    pending = _PENDING_LOGINS.pop(state, None)
    if pending is None:
        raise RuntimeError("This sign-in attempt was not recognised (it may have expired — try again).")
    doc = discovery()
    resp = requests.post(doc["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": os.environ["ZSCALER_SSO_REDIRECT_URL"],
        "client_id": os.environ["ZSCALER_SSO_CLIENT_ID"],
        "client_secret": os.environ["ZSCALER_SSO_CLIENT_SECRET"],
        "code_verifier": pending["verifier"],
    }, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    id_token = resp.json().get("id_token")
    if not id_token:
        raise RuntimeError("The identity provider did not return an ID token.")
    header = jwt.get_unverified_header(id_token)
    key = next((k for k in jwks() if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise RuntimeError("The ID token's signing key is not in the identity provider's published key set.")
    claims = jwt.decode(
        id_token, jwt.PyJWK(key).key, algorithms=[header.get("alg", "RS256")],
        audience=os.environ["ZSCALER_SSO_CLIENT_ID"], issuer=_issuer(),
    )
    if claims.get("nonce") != pending["nonce"]:
        raise RuntimeError("The ID token's nonce does not match this sign-in attempt.")
    return claims


# ── Per-person sessions ───────────────────────────────────────────────

def idle_seconds() -> int:
    """How long a session may sit unused: ZSCALER_SSO_IDLE_MINUTES (default 30)."""
    try:
        minutes = float(os.environ.get("ZSCALER_SSO_IDLE_MINUTES", "30") or 30)
    except ValueError:
        minutes = 30
    return int(max(1.0, minutes) * 60)


def _csv_env(name: str) -> List[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def groups_claim() -> str:
    return os.environ.get("ZSCALER_SSO_GROUPS_CLAIM", "groups").strip() or "groups"


def claim_groups(claims: Dict[str, Any]) -> List[str]:
    """The groups the ID token lists (the ZSCALER_SSO_GROUPS_CLAIM claim); [] when it has none."""
    value = claims.get(groups_claim())
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [str(g).strip() for g in value if str(g).strip()]


def allowed_groups() -> List[str]:
    return _csv_env("ZSCALER_SSO_ALLOWED_GROUPS")


def writers() -> List[str]:
    return _csv_env("ZSCALER_SSO_WRITERS")


def sign_in_allowed(claims: Dict[str, Any]) -> bool:
    """With ZSCALER_SSO_ALLOWED_GROUPS set, the person must be in at least
    one of those groups. Unset: everyone the identity provider signs in."""
    allowed = {g.lower() for g in allowed_groups()}
    if not allowed:
        return True
    return any(g.lower() in allowed for g in claim_groups(claims))


def is_writer(session: Optional[Dict[str, Any]]) -> bool:
    """With ZSCALER_SSO_WRITERS set, only a session whose email or one of
    whose groups is listed may change the tenant. Unset: everyone."""
    wanted = {w.lower() for w in writers()}
    if not wanted:
        return True
    if not session:
        return False
    mine = {str(g).lower() for g in session.get("groups") or []}
    if session.get("email"):
        mine.add(str(session["email"]).lower())
    return bool(wanted & mine)


def _sweep_sessions(now: float) -> None:
    idle = idle_seconds()
    for sid in [k for k, v in _SESSIONS.items() if now >= v["expires"] or now - v["last_seen"] > idle]:
        _SESSIONS.pop(sid, None)


def create_session(claims: Dict[str, Any]) -> str:
    """Start a session for a verified sign-in. Returns its random id (the cookie's only content)."""
    now = time.time()
    sid = secrets.token_urlsafe(32)
    with _SESSIONS_LOCK:
        _sweep_sessions(now)
        _SESSIONS[sid] = {"sub": claims.get("sub"), "email": claims.get("email"), "groups": claim_groups(claims),
                          "created": now, "last_seen": now, "expires": now + SESSION_MAX_SECONDS}
    return sid


def get_session(sid: Optional[str]) -> Optional[Dict[str, Any]]:
    """The live session for this id, its last-seen time refreshed; None
    when unknown, past 12 hours, or idle longer than the idle timeout."""
    if not sid:
        return None
    now = time.time()
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(sid)
        if s is None:
            return None
        if now >= s["expires"] or now - s["last_seen"] > idle_seconds():
            _SESSIONS.pop(sid, None)
            return None
        s["last_seen"] = now
        return dict(s)


def end_session(sid: Optional[str]) -> Optional[Dict[str, Any]]:
    """Sign out: forget the session. Returns what it was, or None."""
    if not sid:
        return None
    with _SESSIONS_LOCK:
        return _SESSIONS.pop(sid, None)
