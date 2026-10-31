"""Passkeys (WebAuthn) for team server accounts: a person registers a
passkey after signing in, then signs in with it instead of a password.
OFF unless team mode is on AND ZSCALER_TEAM_PASSKEY_ORIGIN is set.

    ZSCALER_TEAM_PASSKEY_ORIGIN  the exact address people open the server
                                 at, e.g. https://zme.example.com (https://,
                                 or http://localhost on one computer)
    ZSCALER_TEAM_PASSKEY_RP_ID   optional: the relying party ID, the origin's
                                 host name (default) or a parent domain of it
    ZSCALER_TEAM_PASSKEY_RP_NAME optional: the name the authenticator shows

The ceremonies are verified by py_webauthn (the `webauthn` package; no
hand-made cryptography): the challenge (random, one use, five minutes),
the origin (exactly ZSCALER_TEAM_PASSKEY_ORIGIN), the RP ID hash (exactly
the RP ID), user presence AND user verification (PIN or biometric, so a
passkey is two factors in one), the signature with the registered public
key and the signature counter (a counter that does not go up is refused:
a cloned authenticator). The origin and RP ID come from configuration,
never from the request's Host header. A passkey sign-in is refused for an
account that is turned off or locked, rate limited per address like a
password sign-in, and audited.

Each account keeps at most MAX_PASSKEYS passkeys in the team store (the
credential ID, public key, counter, name and dates: no secret; the private
key never leaves the authenticator). Registering one needs the account's
current password when it has one (a stolen session alone cannot add a
way in); an administrator can remove a person's passkeys (a lost device).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import team_server as team

MAX_PASSKEYS = 10
CHALLENGE_TTL_SECONDS = 300
MAX_PENDING = 1000
MAX_CREDENTIAL_JSON = 32 * 1024
MAX_NAME = 60
TIMEOUT_MS = 120000

_LOCK = threading.Lock()
_PENDING: Dict[str, Dict[str, Any]] = {}   # ceremony key -> {challenge, kind, uid, at}


class PasskeyError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def configured() -> bool:
    return bool(_env("ZSCALER_TEAM_PASSKEY_ORIGIN"))


def enabled() -> bool:
    return team.enabled() and configured() and not config_errors()


def origin() -> str:
    return _env("ZSCALER_TEAM_PASSKEY_ORIGIN").rstrip("/")


def rp_id() -> str:
    return (_env("ZSCALER_TEAM_PASSKEY_RP_ID") or (urlparse(origin()).hostname or "")).lower()


def rp_name() -> str:
    return team._clean(_env("ZSCALER_TEAM_PASSKEY_RP_NAME") or "Zscaler Made Easy", 64)


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def config_errors() -> List[str]:
    """What is wrong with the passkey settings (empty: fine, or not set)."""
    if not configured():
        return []
    errors: List[str] = []
    try:
        u = urlparse(origin())
        host = (u.hostname or "").lower()
    except ValueError:
        return ["ZSCALER_TEAM_PASSKEY_ORIGIN is not a web address"]
    if u.path not in ("", "/") or u.query or u.fragment or u.username or u.password:
        errors.append("ZSCALER_TEAM_PASSKEY_ORIGIN must be only scheme://host[:port], e.g. https://zme.example.com")
    if not host or _is_ip(host):
        errors.append("ZSCALER_TEAM_PASSKEY_ORIGIN must name a host (passkeys do not work on an IP address)")
    elif not (u.scheme == "https" or (u.scheme == "http" and host == "localhost")):
        errors.append("ZSCALER_TEAM_PASSKEY_ORIGIN must be https:// (plain http:// only for localhost)")
    rid = rp_id()
    if host and rid and not (host == rid or host.endswith("." + rid)):
        errors.append("ZSCALER_TEAM_PASSKEY_RP_ID must be the origin's host name or a parent domain of it")
    if rid and (_is_ip(rid) or "." not in rid and rid != "localhost"):
        errors.append("ZSCALER_TEAM_PASSKEY_RP_ID must be a domain name")
    return errors


def require_configured() -> None:
    errors = config_errors()
    if errors:
        raise RuntimeError("ZSCALER_TEAM_PASSKEY_ORIGIN is set but passkeys are not configured correctly: " + "; ".join(errors) +
                           ". Fix it, or unset ZSCALER_TEAM_PASSKEY_ORIGIN.")


def _on() -> None:
    if not team.enabled() or not configured():
        raise PasskeyError("Passkeys are not set up on this server (ZSCALER_TEAM_PASSKEY_ORIGIN).", 404)
    require_configured()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    s = str(s or "")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _algs():
    from webauthn.helpers.cose import COSEAlgorithmIdentifier as A
    import store_crypto
    algs = [A.ECDSA_SHA_256, A.EDDSA, A.RSASSA_PSS_SHA_256, A.RSASSA_PKCS1_v1_5_SHA_256]
    if store_crypto.fips_mode():
        algs = [a for a in algs if a != A.EDDSA]
    return algs


def _sweep(now: float) -> None:
    for k in [k for k, v in _PENDING.items() if now - v["at"] > CHALLENGE_TTL_SECONDS]:
        _PENDING.pop(k, None)
    extra = len(_PENDING) - (MAX_PENDING - 1)
    if extra > 0:
        for k in sorted(_PENDING, key=lambda key: _PENDING[key]["at"])[:extra]:
            _PENDING.pop(k, None)


def _remember(key: str, entry: Dict[str, Any]) -> None:
    now = team._clock()
    with _LOCK:
        _sweep(now)
        _PENDING[key] = {**entry, "at": now}


def _take(key: str) -> Optional[Dict[str, Any]]:
    now = team._clock()
    with _LOCK:
        _sweep(now)
        return _PENDING.pop(key, None)


def _session_key(sid: Any) -> str:
    return "reg:" + hashlib.sha256(str(sid or "").encode()).hexdigest()


def _credential(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise PasskeyError("Send the passkey response as a JSON object.")
    try:
        size = len(json.dumps(raw))
    except (TypeError, ValueError):
        raise PasskeyError("Send the passkey response as a JSON object.") from None
    if size > MAX_CREDENTIAL_JSON:
        raise PasskeyError("The passkey response is too large.")
    return raw


def _user_handle(uid: str) -> bytes:
    """The account's WebAuthn user handle: random, created once, no
    personal data in it (WebAuthn 14.6.1)."""
    with team._LOCK:
        data = team._read()
        rec = data["users"].get(uid)
        if not isinstance(rec, dict):
            raise PasskeyError("No such account.", 404)
        handle = rec.get("webauthn_handle")
        if not handle:
            handle = _b64u(secrets.token_bytes(32))
            rec["webauthn_handle"] = handle
            team._write(data)
    return _unb64u(handle)


# ── registration (a signed-in person adds a passkey) ────────────────────
def registration_options(user: Dict[str, Any], sid: Any) -> Dict[str, Any]:
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                          ResidentKeyRequirement, UserVerificationRequirement)
    _on()
    if len(user.get("passkeys") or []) >= MAX_PASSKEYS:
        raise PasskeyError(f"This account already has {MAX_PASSKEYS} passkeys: remove one first.", 409)
    challenge = secrets.token_bytes(32)
    opts = generate_registration_options(
        rp_id=rp_id(), rp_name=rp_name(), user_name=str(user.get("username") or ""), user_id=_user_handle(user["id"]),
        user_display_name=str(user.get("display_name") or user.get("username") or ""), challenge=challenge, timeout=TIMEOUT_MS,
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED,
                                                               user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=_unb64u(k["id"])) for k in user.get("passkeys") or []
                             if isinstance(k, dict) and k.get("id")],
        supported_pub_key_algs=_algs())
    _remember(_session_key(sid), {"challenge": challenge, "kind": "reg", "uid": user["id"]})
    return json.loads(options_to_json(opts))


def register(user: Dict[str, Any], sid: Any, credential: Any, name: Any = "") -> Dict[str, Any]:
    """Verify a registration response for the ceremony this session started
    and store the passkey. Returns the stored passkey as the page shows it."""
    from webauthn import verify_registration_response
    from webauthn.helpers.exceptions import WebAuthnException
    _on()
    cred = _credential(credential)
    pending = _take(_session_key(sid))
    if not pending or pending.get("kind") != "reg" or pending.get("uid") != user.get("id"):
        raise PasskeyError("This passkey registration was not started here, or it expired: start again.")
    try:
        v = verify_registration_response(credential=cred, expected_challenge=pending["challenge"], expected_rp_id=rp_id(),
                                         expected_origin=origin(), require_user_presence=True, require_user_verification=True,
                                         supported_pub_key_algs=_algs())
    except (WebAuthnException, ValueError, TypeError, KeyError) as e:
        team._audit("team_passkey_refused", actor=user.get("username"), user=user.get("username"), reason=type(e).__name__)
        raise PasskeyError("The passkey could not be verified (wrong site, expired challenge, or no PIN/biometric check). "
                           "Try again.") from None
    cid = _b64u(v.credential_id)
    label = team._clean(name, MAX_NAME) or "Passkey"
    now = team._now_iso()
    with team._LOCK:
        data = team._read()
        for other in data["users"].values():
            if isinstance(other, dict) and any(isinstance(k, dict) and k.get("id") == cid for k in other.get("passkeys") or []):
                raise PasskeyError("This passkey is already registered.", 409)
        rec = data["users"].get(user["id"])
        if not isinstance(rec, dict):
            raise PasskeyError("No such account.", 404)
        keys = [k for k in rec.get("passkeys") or [] if isinstance(k, dict)]
        if len(keys) >= MAX_PASSKEYS:
            raise PasskeyError(f"This account already has {MAX_PASSKEYS} passkeys: remove one first.", 409)
        entry = {"id": cid, "public_key": _b64u(v.credential_public_key), "sign_count": int(v.sign_count),
                 "name": label, "created": now, "last_used": None, "aaguid": str(v.aaguid)[:64],
                 "backed_up": bool(v.credential_backed_up), "device_type": str(getattr(v.credential_device_type, "value", ""))[:32]}
        rec["passkeys"] = keys + [entry]
        rec["updated"] = now
        team._write(data)
    team._audit("team_passkey_registered", actor=user.get("username"), user=user.get("username"), passkey=label)
    return {"id": cid, "name": label, "created": now}


def remove(uid: str, cred_id: Any, *, by: str = "") -> bool:
    cid = str(cred_id or "")
    with team._LOCK:
        data = team._read()
        rec = data["users"].get(uid)
        if not isinstance(rec, dict):
            raise PasskeyError("No such account.", 404)
        keys = [k for k in rec.get("passkeys") or [] if isinstance(k, dict)]
        kept = [k for k in keys if k.get("id") != cid]
        if len(kept) == len(keys):
            raise PasskeyError("No such passkey on this account.", 404)
        rec["passkeys"] = kept
        rec["updated"] = team._now_iso()
        team._write(data)
    team._audit("team_passkey_removed", actor=by or None, user=rec.get("username"))
    return True


def remove_all(uid: str, *, by: str = "") -> int:
    with team._LOCK:
        data = team._read()
        rec = data["users"].get(uid)
        if not isinstance(rec, dict):
            raise PasskeyError("No such account.", 404)
        n = len(rec.get("passkeys") or [])
        rec["passkeys"] = []
        rec["updated"] = team._now_iso()
        team._write(data)
    team._audit("team_passkeys_removed", actor=by or None, user=rec.get("username"), count=n)
    return n


# ── sign-in (no user name: a discoverable credential) ───────────────────
def authentication_options() -> Dict[str, Any]:
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import UserVerificationRequirement
    _on()
    challenge = secrets.token_bytes(32)
    opts = generate_authentication_options(rp_id=rp_id(), challenge=challenge, timeout=TIMEOUT_MS,
                                           user_verification=UserVerificationRequirement.REQUIRED)
    ceremony = secrets.token_urlsafe(24)
    _remember("auth:" + ceremony, {"challenge": challenge, "kind": "auth"})
    return {"ceremony": ceremony, "options": json.loads(options_to_json(opts))}


GENERIC_FAILURE = "That passkey did not sign you in to an account on this server."


def authenticate(ceremony: Any, credential: Any, client_ip: str) -> Dict[str, Any]:
    """Verify a sign-in assertion and return the account. Raises
    team.LoginRefused (401, 423 or 429) with a message that never says
    which part failed or whether the passkey is known."""
    from webauthn import verify_authentication_response
    from webauthn.helpers.exceptions import WebAuthnException
    _on()
    if not team._ip_allowed(client_ip or "?"):
        raise team.LoginRefused("Too many sign-in attempts from this address. Wait a few minutes and try again.", 429, "rate limited")
    try:
        cred = _credential(credential)
    except PasskeyError:
        raise team.LoginRefused(GENERIC_FAILURE, 401, "malformed passkey response") from None
    pending = _take("auth:" + str(ceremony or "")[:100])
    if not pending or pending.get("kind") != "auth":
        raise team.LoginRefused("This passkey sign-in expired or was already used: try again.", 401, "unknown or expired challenge")
    cid = str(cred.get("id") or cred.get("rawId") or "")[:1024]
    owner, key = None, None
    for u in team._read()["users"].values():
        if not isinstance(u, dict):
            continue
        for k in u.get("passkeys") or []:
            if isinstance(k, dict) and cid and k.get("id") == cid:
                owner, key = u, k
                break
        if owner:
            break
    if owner is None or key is None:
        raise team.LoginRefused(GENERIC_FAILURE, 401, "unknown passkey")
    handle = (cred.get("response") or {}).get("userHandle") if isinstance(cred.get("response"), dict) else None
    if handle and (not owner.get("webauthn_handle") or not secrets.compare_digest(str(handle).rstrip("="), str(owner["webauthn_handle"]))):
        raise team.LoginRefused(GENERIC_FAILURE, 401, "user handle does not match the passkey's account")
    try:
        v = verify_authentication_response(credential=cred, expected_challenge=pending["challenge"], expected_rp_id=rp_id(),
                                           expected_origin=origin(), credential_public_key=_unb64u(key["public_key"]),
                                           credential_current_sign_count=int(key.get("sign_count") or 0),
                                           require_user_verification=True)
    except (WebAuthnException, ValueError, TypeError, KeyError) as e:
        reason = "signature counter did not increase (possible cloned authenticator)" if "sign count" in str(e) else f"verification failed ({type(e).__name__})"
        if "sign count" in str(e):
            team._audit("team_passkey_counter_alarm", actor=owner.get("username"), user=owner.get("username"), client=client_ip)
        raise team.LoginRefused(GENERIC_FAILURE, 401, reason) from None
    if float(owner.get("locked_until") or 0) > team._clock():
        raise team.LoginRefused(team.LOCKED, 423, "account locked")
    if not owner.get("active"):
        raise team.LoginRefused(GENERIC_FAILURE, 401, "account turned off")
    with team._LOCK:
        data = team._read()
        rec = data["users"].get(owner["id"])
        if isinstance(rec, dict):
            for k in rec.get("passkeys") or []:
                if isinstance(k, dict) and k.get("id") == cid:
                    k["sign_count"] = int(v.new_sign_count)
                    k["last_used"] = team._now_iso()
                    k["backed_up"] = bool(v.credential_backed_up)
            team._write(data)
    return team.get_user(owner["id"]) or owner


def reset() -> None:
    with _LOCK:
        _PENDING.clear()


def status() -> Dict[str, Any]:
    return {"enabled": enabled(), "configured": configured(), "rp_id": rp_id() if configured() else None,
            "origin": origin() if configured() else None, "errors": config_errors()}

