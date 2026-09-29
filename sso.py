"""Optional SSO (OpenID Connect, Authorization Code + PKCE) — off by
default, an opt-in front door onto the UI token cookie security.py
already gates every request with. Enabling it does not add a second
enforcement mechanism: security.ui_request_ok() is unchanged, and every
request is still checked against the same cookie. All this module
changes is how that cookie gets minted — instead of a static token
pasted in or carried on a URL, the operator must complete a login at
the configured identity provider first.

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
import time
from typing import Any, Dict, List, Tuple
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
