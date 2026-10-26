"""A classic-API tenant's fingerprint: how two classic-API tenants on one
cloud are told apart without naming either.

The classic ZIA API signs in with an admin login and no vanity domain, and
neither may be shown or stored (tenant_auth.record_label names such a
tenant only 'classic API (cloud)'). Every classic-API tenant on a cloud so
shares one label. What tells them apart is a keyed, one-way fingerprint:

    HMAC-SHA256(install key, "classic|<cloud>|<admin login, lower-case>")

truncated to 16 hex characters. Without the install's key it cannot be
computed from a known login, and it cannot be turned back into the login
or the domain. It is kept in each deployment record (`tenant_fp`) and is
the classic-API tenant's key in the rate state (zia_rate), never shown in
the UI or returned by the API.

The key is 32 random bytes, created once per install in
`tenant_fingerprint.key` next to the deployment records (owner-only,
git-ignored; the container keeps it on /data), or at
DLP_CHECK_FINGERPRINT_KEY. The app keeps no other persistent secret (the UI
token is per process), so this file is its own.

OneAPI tenants are told apart by their vanity domain and API client as
before (zia_rate.key_for); they get no fingerprint.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
import threading
from typing import Any, Dict, Optional, Tuple

import tenant_auth
import safe_files

KEY_FILE = "tenant_fingerprint.key"
LENGTH = 16
_lock = threading.Lock()
_cache: Dict[str, bytes] = {}


def key_path() -> str:
    """DLP_CHECK_FINGERPRINT_KEY, else next to the deployment records."""
    env = (os.environ.get("DLP_CHECK_FINGERPRINT_KEY") or "").strip()
    if env:
        return env
    import deployments
    return os.path.join(os.path.dirname(os.path.abspath(deployments.store_path())), KEY_FILE)


def _read(path: str) -> Optional[bytes]:
    try:
        with open(path, "r", encoding="ascii") as f:
            raw = bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return None
    return raw if len(raw) >= 32 else None


def _create(path: str) -> Optional[bytes]:
    """Write a new key atomically and owner-only. When another process got
    there first, its key wins."""
    d = os.path.dirname(path) or "."
    try:
        safe_files.private_makedirs(d)
        fd, tmp = tempfile.mkstemp(prefix=".fingerprint-", dir=d)
    except OSError:
        return None
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secrets.token_hex(32))
        try:
            os.link(tmp, path)          # never replaces a key that is already there
        except FileExistsError:
            pass
        except OSError:
            if not os.path.exists(path):
                os.replace(tmp, path)
    except OSError:
        return None
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return _read(path)


def install_key() -> Optional[bytes]:
    """The install's key, created on first use; None when it can be neither
    read nor written (a read-only install: classic-API tenants are then
    not told apart, as before)."""
    path = key_path()
    with _lock:
        if path in _cache:
            return _cache[path]
        key = _read(path)
        if key is None and not os.path.exists(path):
            key = _create(path)
        if key is not None:
            _cache[path] = key
        return key


def fingerprint(creds: Dict[str, Any]) -> str:
    """The classic-API tenant's fingerprint (16 hex characters), or "" for
    OneAPI credentials, a classic sign-in with no login, or no key."""
    c = tenant_auth.normalize(creds)
    if c["auth_method"] != tenant_auth.LEGACY or not c["username"]:
        return ""
    key = install_key()
    if key is None:
        return ""
    msg = f"classic|{(c['cloud'] or 'production').lower()}|{c['username'].lower()}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:LENGTH]


def tenant_key(creds: Dict[str, Any]) -> str:
    """The tenant's key in the rate state and in a OneAPI deployment record:
    zia_rate.key_for(cloud, vanity domain, client id) for OneAPI, the
    fingerprint for the classic API (a per-cloud key that names nobody
    when there is no fingerprint)."""
    import zia_rate
    c = tenant_auth.normalize(creds)
    if c["auth_method"] == tenant_auth.LEGACY:
        return fingerprint(c) or zia_rate.key_for(c["cloud"] or "production", "classic API", "")
    return zia_rate.key_for(c["cloud"], c["vanity_domain"] or c["username"], c["client_id"] or c["username"])


def proposal_key(creds: Dict[str, Any], fallback: str = "") -> str:
    """The tenant's key in the proposal queue (proposals.json and the
    FP/TP Detection Ratio report's tenant_key): the vanity domain for
    OneAPI, as before; for the classic API, which signs in with an admin
    login and no vanity domain, "classic-<fingerprint>" (a vanity domain
    left in the form or profile is never used), else `fallback` (a
    profile id), else a per-cloud key that names nobody."""
    c = tenant_auth.normalize(creds)
    if c["auth_method"] == tenant_auth.LEGACY:
        fp = fingerprint(c)
        return f"classic-{fp}" if fp else (fallback or f"classic-{(c['cloud'] or 'production').lower()}")
    return c["vanity_domain"] or fallback or "unknown"


def proposal_key_aliases(creds: Dict[str, Any], fallback: str = "") -> Tuple[str, ...]:
    """Keys a classic-API tenant's proposals were queued under before
    proposal_key (its stale vanity domain, or the profile id): read once
    to move them, never written again."""
    c = tenant_auth.normalize(creds)
    if c["auth_method"] != tenant_auth.LEGACY:
        return ()
    new = proposal_key(c, fallback)
    return tuple(k for k in dict.fromkeys([c["vanity_domain"] or fallback]) if k and k != new)


def legacy_unkeyed_key(creds: Dict[str, Any]) -> str:
    """The plain hash records of classic-API tenants carried as `tenant_key`
    before the fingerprint (cloud, vanity domain or login, login). Only
    compared, never written again."""
    import zia_rate
    c = tenant_auth.normalize(creds)
    return zia_rate.key_for(c["cloud"], c["vanity_domain"] or c["username"], c["client_id"] or c["username"])


def record_ids(creds: Dict[str, Any]) -> Dict[str, str]:
    """What a deployment record keeps to tell its tenant apart:
    {'tenant_fp': …} for the classic API, {'tenant_key': …} for OneAPI."""
    c = tenant_auth.normalize(creds)
    if c["auth_method"] == tenant_auth.LEGACY:
        fp = fingerprint(c)
        return {"tenant_fp": fp} if fp else {}
    key = tenant_key(c)
    return {"tenant_key": key} if key else {}


def same_tenant(rec: Dict[str, Any], creds: Dict[str, Any]) -> bool:
    """Whether a deployment record was made in the tenant these credentials
    point at: its label (current or older form), then its fingerprint when
    it has one (the current credentials must give the same), else its
    opaque key when it has one, else the label alone (records written
    before tenants were told apart)."""
    c = tenant_auth.normalize(creds)
    if rec.get("tenant_label") and rec["tenant_label"] not in tenant_auth.record_labels(c):
        return False
    fp = rec.get("tenant_fp")
    if fp:
        mine = fingerprint(c)
        return bool(mine) and hmac.compare_digest(str(fp), mine)
    key = rec.get("tenant_key")
    if not key:
        return True
    if key == tenant_key(c):
        return True
    return c["auth_method"] == tenant_auth.LEGACY and key == legacy_unkeyed_key(c)


def _reset_cache() -> None:
    """Forget the cached key (tests)."""
    with _lock:
        _cache.clear()
