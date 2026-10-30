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
import math
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import jwt
import requests

REQUIRED_ENV = ("ZSCALER_SSO_ISSUER", "ZSCALER_SSO_CLIENT_ID", "ZSCALER_SSO_CLIENT_SECRET", "ZSCALER_SSO_REDIRECT_URL")

_DISCOVERY_CACHE: Dict[str, Dict[str, Any]] = {}
_JWKS_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 3600
_PENDING_LOGINS: Dict[str, Dict[str, Any]] = {}   # state -> {nonce, verifier, at, binding}
_PENDING_LOCK = threading.Lock()
_PENDING_TTL_SECONDS = 600
# /api/auth/sso/login needs no sign-in, so every call to it would otherwise
# add a pending login for ten minutes, without bound (CWE-770): past this
# many, the oldest is dropped.
MAX_PENDING_LOGINS = 1000
# The ID token must be signed with a public-key algorithm the identity
# provider's key set publishes. Never 'none', and never a shared-secret
# algorithm (HS256...) that a public key could be fed to (CWE-347).
ID_TOKEN_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
_KEY_TYPES = ("RSA", "EC", "OKP")
# The claims OpenID Connect Core 3.1.3.7 makes an ID token carry; one
# without an expiry would be a sign-in that never ends.
REQUIRED_CLAIMS = ("iss", "aud", "sub", "exp", "iat")
CLOCK_SKEW_SECONDS = 60
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
    if issuer and not secure_url(issuer):
        errors.append("ZSCALER_SSO_ISSUER must be https:// (a plain http:// identity provider can be spoofed on the network)")
    return errors


_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "::1")


def secure_url(url: Any) -> bool:
    """https://, or plain http:// to this computer's loopback only: the host
    itself is compared, so http://localhost.attacker.example is not loopback."""
    try:
        u = urlparse(str(url or "").strip())
        host = (u.hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    return u.scheme == "https" or (u.scheme == "http" and host in _LOOPBACK_NAMES)


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
    if not isinstance(doc, dict):
        raise RuntimeError("The identity provider's discovery document is not a JSON object.")
    missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if k not in doc]
    if missing:
        raise RuntimeError(f"The identity provider's discovery document is missing {', '.join(missing)}.")
    # OpenID Connect Discovery 4.3: the document is the configured issuer's own.
    if doc.get("issuer") is not None and str(doc["issuer"]).rstrip("/") != issuer:
        raise RuntimeError("The identity provider's discovery document names another issuer than ZSCALER_SSO_ISSUER.")
    insecure = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not secure_url(doc[k])]
    if insecure:
        raise RuntimeError(f"The identity provider's discovery document gives a plain http:// address for {', '.join(insecure)}.")
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
    """Drop expired pending logins, then the oldest past MAX_PENDING_LOGINS.
    Called with _PENDING_LOCK held."""
    cutoff = time.time() - _PENDING_TTL_SECONDS
    for state in [s for s, v in _PENDING_LOGINS.items() if v["at"] < cutoff]:
        _PENDING_LOGINS.pop(state, None)
    extra = len(_PENDING_LOGINS) - (MAX_PENDING_LOGINS - 1)
    if extra > 0:
        for state in sorted(_PENDING_LOGINS, key=lambda k: _PENDING_LOGINS[k]["at"])[:extra]:
            _PENDING_LOGINS.pop(state, None)


def new_login_binding() -> str:
    """A random value the server sets in a cookie on the browser that starts
    a sign-in (security.set_login_cookie); start_login and complete_login tie
    the state to it, so a callback URL replayed in another browser is refused
    (login CSRF, RFC 6749 section 10.12)."""
    return secrets.token_urlsafe(32)


def start_login(binding: Optional[str] = None) -> str:
    """Build the redirect to the identity provider and remember the
    state/nonce/PKCE verifier server-side until the callback arrives,
    bound to `binding` (the browser's login cookie) when given.
    Returns the URL to send the browser to."""
    require_configured()
    endpoint = discovery()["authorization_endpoint"]
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    with _PENDING_LOCK:
        _sweep_pending()
        _PENDING_LOGINS[state] = {"nonce": nonce, "verifier": verifier, "at": time.time(), "binding": binding}
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
    return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)


def complete_login(state: str, code: str, binding: Optional[str] = None) -> Dict[str, Any]:
    """Exchange the authorization code for tokens and verify the ID
    token's signature, issuer, audience and nonce. A sign-in started with a
    binding completes only with the same binding (the same browser). Returns
    the verified claims (sub, email, ...) on success. Raises on any failure —
    every failure here means the login did not happen; nothing is granted."""
    require_configured()
    with _PENDING_LOCK:
        _sweep_pending()
        pending = _PENDING_LOGINS.pop(str(state or ""), None)
    if pending is None:
        raise RuntimeError("This sign-in attempt was not recognised (it may have expired — try again).")
    expected = pending.get("binding")
    if expected is not None and not secrets.compare_digest(str(binding or "").encode(), str(expected).encode()):
        raise RuntimeError("This sign-in was started in another browser (or its sign-in cookie is missing) — start it again here.")
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
    return verify_id_token(id_token, pending["nonce"])


def verify_id_token(id_token: str, nonce: str) -> Dict[str, Any]:
    """The claims of an ID token from the configured identity provider, or a
    RuntimeError. Checked: the algorithm (a public-key one from
    ID_TOKEN_ALGORITHMS, the same as its key's), the signature against the
    provider's published key, the issuer, the audience (and `azp` when it
    names several), the expiry and issue time (REQUIRED_CLAIMS, with
    CLOCK_SKEW_SECONDS of leeway) and the nonce of this sign-in."""
    client_id = os.environ["ZSCALER_SSO_CLIENT_ID"]
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise RuntimeError("The identity provider's ID token is not a signed JSON Web Token.") from None
    alg = header.get("alg")
    if alg not in ID_TOKEN_ALGORITHMS:
        raise RuntimeError(f"The ID token is signed with an algorithm this server does not accept ({str(alg)[:20]!r}): "
                           "only a public-key signature from the identity provider's key set is.")
    key = next((k for k in jwks() if isinstance(k, dict) and k.get("kid") == header.get("kid")), None)
    if key is None:
        raise RuntimeError("The ID token's signing key is not in the identity provider's published key set.")
    if key.get("kty") not in _KEY_TYPES or (key.get("alg") and key.get("alg") != alg) or key.get("use", "sig") != "sig":
        raise RuntimeError("The ID token's algorithm does not match the signing key the identity provider published.")
    try:
        claims = jwt.decode(
            id_token, jwt.PyJWK(key, algorithm=alg).key, algorithms=[alg],
            audience=client_id, issuer=_issuer(), leeway=CLOCK_SKEW_SECONDS,
            options={"require": list(REQUIRED_CLAIMS), "verify_signature": True, "verify_exp": True,
                     "verify_iat": True, "verify_aud": True, "verify_iss": True},
        )
    except jwt.ExpiredSignatureError:
        raise RuntimeError("The ID token has expired; sign in again.") from None
    except jwt.PyJWTError as e:
        raise RuntimeError(f"The ID token could not be verified ({type(e).__name__}).") from None
    aud = claims.get("aud")
    several = isinstance(aud, list) and len(aud) > 1
    if (several or "azp" in claims) and claims.get("azp") != client_id:
        raise RuntimeError("The ID token was issued to another client (its authorized party is not this server).")
    if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"].encode(), str(nonce).encode()):
        raise RuntimeError("The ID token's nonce does not match this sign-in attempt.")
    return claims


# ── Per-person sessions ───────────────────────────────────────────────

def idle_seconds() -> int:
    """How long a session may sit unused: ZSCALER_SSO_IDLE_MINUTES (default 30)."""
    try:
        minutes = float(os.environ.get("ZSCALER_SSO_IDLE_MINUTES", "30") or 30)
    except ValueError:
        minutes = 30
    if not math.isfinite(minutes):
        minutes = 30   # 'inf' or 'nan' is a typo, not a session that never idles out (and int(inf) raises)
    return int(min(max(1.0, minutes), SESSION_MAX_SECONDS / 60) * 60)


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


def email_verified(claims: Dict[str, Any]) -> bool:
    """True only when the ID token says the identity provider verified the
    email (email_verified true, or "true" from providers that send strings).
    Absent or false: the email is whatever the person typed and grants nothing."""
    v = claims.get("email_verified")
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def is_writer(session: Optional[Dict[str, Any]]) -> bool:
    """With ZSCALER_SSO_WRITERS set, only a session one of whose groups is
    listed, or whose verified email is listed, may change the tenant. An
    email the identity provider did not verify never counts: on many
    providers a user can set it to anyone's address. Unset: everyone."""
    wanted = {w.lower() for w in writers()}
    if not wanted:
        return True
    if not session:
        return False
    mine = {str(g).lower() for g in session.get("groups") or []}
    if session.get("email") and session.get("email_verified") is True:
        mine.add(str(session["email"]).lower())
    return bool(wanted & mine)


def _idle_of(s: Dict[str, Any]) -> float:
    """A session's own idle limit (a team server session carries its own,
    team_server.idle_seconds), else ZSCALER_SSO_IDLE_MINUTES."""
    v = s.get("idle")
    return float(v) if isinstance(v, (int, float)) and v > 0 else float(idle_seconds())


def _sweep_sessions(now: float) -> None:
    for sid in [k for k, v in _SESSIONS.items() if now >= v["expires"] or now - v["last_seen"] > _idle_of(v)]:
        _SESSIONS.pop(sid, None)


def create_session(claims: Dict[str, Any], *, team_user: Optional[str] = None, via: str = "oidc",
                   groups: Optional[List[str]] = None, idle: Optional[int] = None, max_seconds: Optional[int] = None) -> str:
    """Start a session for a verified sign-in. Returns its random id (the
    cookie's only content). A team server session (team_server.start_session)
    names its account (`team_user`), how it signed in (`via`: password or
    oidc) and its own idle and absolute limits."""
    now = time.time()
    sid = secrets.token_urlsafe(32)
    entry = {"sub": claims.get("sub"), "email": claims.get("email"), "email_verified": email_verified(claims),
             "groups": list(groups) if groups is not None else claim_groups(claims),
             "created": now, "last_seen": now,
             "expires": now + min(SESSION_MAX_SECONDS, int(max_seconds or SESSION_MAX_SECONDS))}
    if team_user:
        entry.update(team_user=str(team_user), via=via, idle=int(idle or idle_seconds()))
    with _SESSIONS_LOCK:
        _sweep_sessions(now)
        _SESSIONS[sid] = entry
    return sid


def end_sessions_for(team_user: str) -> int:
    """End every session of one team server account (a password change, a
    role change, a disabled or deleted account). Returns how many ended."""
    with _SESSIONS_LOCK:
        gone = [k for k, v in _SESSIONS.items() if team_user and v.get("team_user") == team_user]
        for k in gone:
            _SESSIONS.pop(k, None)
    return len(gone)


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
        if now >= s["expires"] or now - s["last_seen"] > _idle_of(s):
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
