"""Encryption at rest for the app's own local stores (optional; off by
default, when every store stays the plain owner-only JSON it always was).

    DLP_CHECK_STORE_ENCRYPTION=1   seal every store this app writes from now
                                   on: tenant profiles (their metadata; the
                                   secrets have their own store), saved
                                   snapshots, the change queue, proposals,
                                   deployment and bulk-change records,
                                   workspace notes, POVs and their templates,
                                   the team server's accounts and the audit
                                   log (line by line)
    DLP_CHECK_STORE_KEY_FILE       where the key file is kept when the OS
                                   credential store is not available
                                   (default store_keys.json beside the data,
                                   owner-only, 0600)
    DLP_CHECK_FIPS_MODE=1          only FIPS-approved algorithms in the app's
                                   own choices (fips_status says which)

Format: one line "ZMEENC1:<key id>:<base64 of 12-byte nonce + AES-256-GCM
ciphertext and tag>" per sealed text, with "zme-store-v1" as associated
data. AES-256-GCM comes from the `cryptography` package the app already
pins; nothing here is hand-made cryptography. A file written before
encryption was turned on is still read, and sealed on its next write
(seal_all seals them all at once). A sealed file is read whether or not the
setting is on, as long as its key is there: turning the setting off never
locks data away.

The key is 32 random bytes, kept in the operating system's credential store
(Windows Credential Manager, macOS Keychain) through `keyring` where that
is installed, else in the owner-only key file. rotate() makes a new key,
re-seals every store with it, and only then forgets the old one.
"""
from __future__ import annotations

import base64
import glob
import json
import os
import secrets
import threading
from typing import Any, Callable, Dict, List, Optional

PREFIX = "ZMEENC1:"
AAD = b"zme-store-v1"
KEYRING_SERVICE = "dlp-check"
_LOCK = threading.RLock()


class StoreLocked(RuntimeError):
    """A sealed store whose key is not available here."""


def enabled() -> bool:
    return os.environ.get("DLP_CHECK_STORE_ENCRYPTION", "0").strip().lower() in ("1", "true", "yes", "on")


def fips_mode() -> bool:
    return os.environ.get("DLP_CHECK_FIPS_MODE", "0").strip().lower() in ("1", "true", "yes", "on")


def _data_dir() -> str:
    try:
        import tenant_profiles
        return os.path.dirname(os.path.abspath(tenant_profiles.store_path()))
    except Exception:  # noqa: BLE001
        return os.path.dirname(os.path.abspath(__file__))


def key_file() -> str:
    return os.environ.get("DLP_CHECK_STORE_KEY_FILE") or os.path.join(_data_dir(), "store_keys.json")


# ── the key ring: {"current": id, "keys": {id: base64 key}} ─────────────
def _keyring():
    try:
        import keyring  # type: ignore
        if keyring is None:
            return None
        keyring.get_keyring()
        return keyring
    except Exception:  # noqa: BLE001
        return None


def _load_ring() -> Dict[str, Any]:
    kr = _keyring()
    if kr is not None:
        try:
            raw = kr.get_password(KEYRING_SERVICE, "store-keys")
            if raw:
                ring = json.loads(raw)
                if isinstance(ring, dict) and isinstance(ring.get("keys"), dict):
                    return ring
        except Exception:  # noqa: BLE001 - fall back to the file
            pass
    try:
        with open(key_file(), "r", encoding="utf-8") as f:
            ring = json.load(f)
        if isinstance(ring, dict) and isinstance(ring.get("keys"), dict):
            return ring
    except (OSError, ValueError):
        pass
    return {"current": "", "keys": {}}


def _save_ring(ring: Dict[str, Any]) -> str:
    """Keep the ring in the credential store when there is one (the file is
    then removed), else in the owner-only key file. Returns where."""
    text = json.dumps(ring, sort_keys=True)
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(KEYRING_SERVICE, "store-keys", text)
            try:
                os.unlink(key_file())
            except OSError:
                pass
            return "credential store"
        except Exception:  # noqa: BLE001
            pass
    import safe_files
    safe_files.write_private_atomic(key_file(), text)
    return "key file"


def _new_key_id() -> str:
    return secrets.token_hex(4)


def _current(create: bool = True) -> Optional[Dict[str, Any]]:
    with _LOCK:
        ring = _load_ring()
        if ring.get("current") in ring["keys"]:
            return ring
        if not create:
            return None
        kid = _new_key_id()
        ring = {"current": kid, "keys": {kid: base64.b64encode(secrets.token_bytes(32)).decode("ascii")}}
        _save_ring(ring)
        return ring


def _aesgcm(key_b64: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(base64.b64decode(key_b64))


# ── sealing ─────────────────────────────────────────────────────────────
def is_sealed(text: Any) -> bool:
    return isinstance(text, str) and text.startswith(PREFIX)


def _seal_with(text: str, kid: str, key_b64: str) -> str:
    nonce = secrets.token_bytes(12)
    ct = _aesgcm(key_b64).encrypt(nonce, text.encode("utf-8"), AAD)
    return f"{PREFIX}{kid}:" + base64.b64encode(nonce + ct).decode("ascii")


def seal_text(text: str) -> str:
    """`text` sealed with the current key when encryption is on; as it is otherwise."""
    if not enabled():
        return text
    ring = _current(create=True)
    return _seal_with(text, ring["current"], ring["keys"][ring["current"]])


def open_text(text: Any) -> str:
    """The plain text of what a store read: a sealed text is opened with its
    key (StoreLocked when that key is not here, or the text was altered);
    anything else is returned as it is."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if not is_sealed(text):
        return text
    body = text.strip()[len(PREFIX):]
    kid, _, blob = body.partition(":")
    ring = _load_ring()
    key = ring["keys"].get(kid)
    if not key:
        raise StoreLocked(f"This store is encrypted with key {kid[:8]}, which is not available on this computer.")
    try:
        raw = base64.b64decode(blob, validate=True)
        from cryptography.exceptions import InvalidTag
        try:
            return _aesgcm(key).decrypt(raw[:12], raw[12:], AAD).decode("utf-8")
        except InvalidTag:
            raise StoreLocked("This store's encrypted content was altered or damaged (its authentication tag does not match).") from None
    except (ValueError, TypeError) as e:
        raise StoreLocked(f"This store's encrypted content is damaged ({type(e).__name__}).") from None


def open_bytes(raw: bytes) -> bytes:
    """open_text for bytes (self_heal reads stores as bytes)."""
    if raw[:len(PREFIX)] != PREFIX.encode("ascii"):
        return raw
    return open_text(raw.decode("ascii", "replace")).encode("utf-8")


def load_json(f) -> Any:
    """json.load for a store file that may be sealed."""
    return json.loads(open_text(f.read()))


def dump_json(data: Any, f, **kw: Any) -> None:
    """json.dump for a store file, sealed when encryption is on."""
    f.write(seal_text(json.dumps(data, **kw)))


# ── every store, for seal_all and rotate ────────────────────────────────
def _store_paths() -> List[Dict[str, Any]]:
    """Each store file: {path, lines} (lines: the audit log, sealed line by line)."""
    out: List[Dict[str, Any]] = []

    def add(path: Optional[str], lines: bool = False) -> None:
        if path:
            for p in (path, path + ".last-good"):
                if os.path.isfile(p):
                    out.append({"path": p, "lines": lines})
    for mod, fn in (("tenant_profiles", "store_path"), ("change_queue", "store_path"), ("proposals", "store_path"),
                    ("deployments", "store_path"), ("workspace_notes", "store_path"), ("team_server", "store_path")):
        try:
            add(getattr(__import__(mod), fn)())
        except Exception:  # noqa: BLE001 - a store that cannot say where it is has nothing to seal
            pass
    try:
        import tenant_profiles
        for p in glob.glob(os.path.join(tenant_profiles.snapshots_dir(), "snap-*.json")):
            add(p)
        for p in glob.glob(os.path.join(os.path.dirname(os.path.abspath(tenant_profiles.store_path())), tenant_profiles.POV_DIR, "*.json")):
            add(p)
    except Exception:  # noqa: BLE001
        pass
    try:
        import pov
        add(pov._templates_path())
    except Exception:  # noqa: BLE001
        pass
    try:
        import audit
        add(audit.path(), lines=True)
        add(audit.path() + ".1", lines=True)
    except Exception:  # noqa: BLE001
        pass
    seen, uniq = set(), []
    for e in out:
        if e["path"] not in seen:
            seen.add(e["path"])
            uniq.append(e)
    return uniq


def _reseal_file(path: str, lines: bool, seal: Callable[[str], str]) -> None:
    import safe_files
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if lines:
        new = "".join(seal(open_text(ln.rstrip("\n"))) + "\n" for ln in text.splitlines() if ln.strip())
    else:
        new = seal(open_text(text))
    safe_files.write_private_atomic(path, new)


def seal_all() -> Dict[str, Any]:
    """Seal every store now with the current key (turning encryption on for
    data written before). Returns the files sealed."""
    if not enabled():
        raise RuntimeError("Store encryption is off (DLP_CHECK_STORE_ENCRYPTION).")
    ring = _current(create=True)
    kid, key = ring["current"], ring["keys"][ring["current"]]
    done = []
    with _LOCK:
        for e in _store_paths():
            _reseal_file(e["path"], e["lines"], lambda t: _seal_with(t, kid, key))
            done.append(os.path.basename(e["path"]))
    _audit("store_encryption_sealed", files=len(done), key=kid)
    return {"key": kid, "files": done}


def rotate() -> Dict[str, Any]:
    """Make a new key, re-seal every store with it, then forget the old key.
    A store that cannot be opened stops the rotation before any key is
    forgotten (both keys stay, so nothing is lost)."""
    with _LOCK:
        ring = _current(create=True)
        old = ring["current"]
        kid = _new_key_id()
        while kid in ring["keys"]:
            kid = _new_key_id()
        ring["keys"][kid] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        _save_ring(ring)                          # both keys held while re-sealing
        key = ring["keys"][kid]
        done = []
        for e in _store_paths():
            _reseal_file(e["path"], e["lines"], lambda t: _seal_with(t, kid, key))
            done.append(os.path.basename(e["path"]))
        ring = {"current": kid, "keys": {kid: key}}
        where = _save_ring(ring)
    _audit("store_key_rotated", old_key=old, new_key=kid, files=len(done), kept_in=where)
    return {"old_key": old, "new_key": kid, "files": done, "kept_in": where}


def status() -> Dict[str, Any]:
    ring = _load_ring()
    return {"enabled": enabled(), "key": ring.get("current") or None, "keys_held": len(ring["keys"]),
            "kept_in": "credential store" if _keyring() is not None else "key file", "algorithm": "AES-256-GCM"}


def _audit(event: str, **fields: Any) -> None:
    try:
        import audit
        audit.record(event, **fields)
    except Exception:  # noqa: BLE001
        pass


# ── FIPS mode ───────────────────────────────────────────────────────────
FIPS_ID_TOKEN_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
FIPS_TLS_CIPHERS = "ECDHE+AESGCM:DHE+AESGCM:!aNULL:!eNULL:!CHACHA20"


def _platform_fips() -> Optional[bool]:
    try:
        with open("/proc/sys/crypto/fips_enabled", "r", encoding="ascii") as f:
            return f.read().strip() == "1"
    except OSError:
        return None


def fips_status() -> Dict[str, Any]:
    """What FIPS mode changes in this app, and the honest limit of it."""
    import ssl
    return {
        "on": fips_mode(),
        "restricted": [
            "Passwords: PBKDF2-HMAC-SHA256 (NIST SP 800-132, 600,000 iterations) instead of scrypt; an scrypt hash is refused until an administrator resets that password",
            "Stores at rest: AES-256-GCM (FIPS 197, SP 800-38D)",
            "Identity-provider tokens: RSA, RSA-PSS and ECDSA signatures only (no EdDSA)",
            "HTTPS: TLS 1.2 or later, ECDHE/DHE with AES-GCM only (no ChaCha20)",
            "Certificates this app makes: ECDSA P-256 with SHA-256",
            "Tokens and hashes: SHA-256; random values from the operating system's generator",
        ],
        "platform_fips_enabled": _platform_fips(),
        "openssl": ssl.OPENSSL_VERSION,
        "honest_note": ("FIPS mode limits the algorithms this app chooses. It does not make the app FIPS 140-3 validated: the Python "
                        "interpreter and the OpenSSL and cryptography builds it runs on are not a validated module unless your "
                        "platform provides one and runs in FIPS mode (for example a FIPS-enabled RHEL with its validated OpenSSL)."),
    }
