"""Encryption at rest for the app's own local stores: ON by default.

    DLP_CHECK_STORE_ENCRYPTION     unset (the default) or 1: seal every store
                                   this app writes: tenant profiles (their
                                   metadata; the secrets have their own
                                   store), saved snapshots, the change queue,
                                   proposals, deployment and bulk-change
                                   records, workspace notes, POVs and their
                                   templates, the team server's accounts, the
                                   audit log (line by line), configuration
                                   backups with their index, templates and
                                   per-profile configuration caches,
                                   scheduled sync jobs, the Client Connector
                                   fleet history, the SSL coverage history,
                                   the Tenant API maps and saved traffic log
                                   reports.
                                   0 (or off/false/no): the opt-out; stores
                                   are written as the plain owner-only JSON
                                   they always were (sealed files still
                                   read; `unseal-all` turns them back).
    DLP_CHECK_STORE_KEY_FILE       where the key file is kept when the OS
                                   credential store is not available (Linux,
                                   the container, a headless server; default
                                   store_keys.json beside the data, owner-only,
                                   0600). When set, the key is always kept in
                                   that file (never moved to the credential
                                   store, never deleted): put it on another
                                   volume so a copy of the data alone does
                                   not carry the key
    DLP_CHECK_FIPS_MODE=1          only FIPS-approved algorithms in the app's
                                   own choices (fips_status says which)

Format: one line "ZMEENC1:<key id>:<base64 of 12-byte nonce + AES-256-GCM
ciphertext and tag>" per sealed text, with "zme-store-v1" as associated
data. AES-256-GCM comes from the `cryptography` package the app already
pins; nothing here is hand-made cryptography. A sealed file is read whether
or not the setting is on, as long as its key is there: turning the setting
off never locks data away.

Upgrading: stores written by a version where encryption was off are sealed
once, at the first start (migrate): a verified owner-only backup of every
plain file is taken first, each file is sealed atomically, read back and
compared with the backup, and a journal records each step so an interrupted
migration resumes where it stopped on the next start. Only when every file
reads back is the backup removed, so no plain copy is left behind. A file
that does not read back is put back from the backup and the migration stops
(nothing is lost; the app reads plain files as before).

The key is 32 random bytes, kept in the operating system's credential store
(Windows Credential Manager, macOS Keychain) through `keyring` where that
is installed and answers, else in the owner-only key file (the container
keeps it on its /data volume, as it keeps its other owner-only files). A key
is only ever used once it reads back from where it was kept, and a key ring
that exists but cannot be read is never replaced by a new one. rotate()
makes a new key, re-seals every store with it, and only then forgets the
old one. When the default is on but no key can be kept anywhere, stores stay
plain and status() and the start-up message say why; with an explicit
DLP_CHECK_STORE_ENCRYPTION=1 that is an error instead.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import secrets
import shutil
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional, Tuple

PREFIX = "ZMEENC1:"
AAD = b"zme-store-v1"
KEYRING_SERVICE = "dlp-check"
_LOCK = threading.RLock()


SETTING = "DLP_CHECK_STORE_ENCRYPTION"
_OFF = ("0", "false", "no", "off")
_ON = ("1", "true", "yes", "on")


class StoreLocked(RuntimeError):
    """A sealed store whose key is not available here."""


class KeyUnavailable(RuntimeError):
    """No store key can be made or kept here (or a key ring exists that cannot be read)."""


class StoreBusy(RuntimeError):
    """Another process of the app is changing the store key or re-sealing the stores; nothing was changed."""


def enabled() -> bool:
    """On unless the operator opted out with DLP_CHECK_STORE_ENCRYPTION=0
    (secure by default; any value that is not an opt-out word counts as on)."""
    return os.environ.get(SETTING, "").strip().lower() not in _OFF


def explicitly_on() -> bool:
    """The operator asked for encryption (=1), rather than taking the default."""
    return os.environ.get(SETTING, "").strip().lower() in _ON


def opted_out() -> bool:
    return not enabled()


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


def key_file_chosen() -> bool:
    """The operator named the key file (DLP_CHECK_STORE_KEY_FILE): the key is
    then kept there, never moved to the credential store, and never deleted."""
    return bool(os.environ.get("DLP_CHECK_STORE_KEY_FILE", "").strip())


# ── the key ring: {"current": id, "keys": {id: base64 key}} ─────────────
def _keyring():
    try:
        import keyring  # type: ignore
        if keyring is None:
            return None
        backend = keyring.get_keyring()
        try:
            from keyring.backends import fail  # type: ignore
            if isinstance(backend, fail.Keyring):
                return None            # keyring installed with no usable backend (a headless Linux): the key file
        except Exception:  # noqa: BLE001
            pass
        return keyring
    except Exception:  # noqa: BLE001
        return None


def _read_keyring_ring(kr) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(ring, problem) from the credential store: (None, None) when it holds
    no ring, a problem when it could not be read or holds something else."""
    try:
        raw = kr.get_password(KEYRING_SERVICE, "store-keys")
    except Exception as e:  # noqa: BLE001 - a locked or broken credential store
        return None, f"the credential store could not be read ({type(e).__name__})"
    if not raw:
        return None, None
    try:
        ring = json.loads(raw)
    except ValueError:
        return None, "the credential store's store key entry is damaged"
    if isinstance(ring, dict) and isinstance(ring.get("keys"), dict):
        return ring, None
    return None, "the credential store's store key entry is damaged"


def _read_file_ring() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(ring, problem) from the key file: (None, None) when there is no file."""
    try:
        with open(key_file(), "r", encoding="utf-8") as f:
            ring = json.load(f)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as e:
        return None, f"the key file {key_file()} could not be read ({type(e).__name__})"
    if isinstance(ring, dict) and isinstance(ring.get("keys"), dict):
        return ring, None
    return None, f"the key file {key_file()} is damaged"


def _load_ring_checked() -> Tuple[Dict[str, Any], List[str]]:
    """Every key this computer holds, from the credential store AND the key
    file (a key kept in either still opens what it sealed), plus what could
    not be read. The credential store's current key wins."""
    problems: List[str] = []
    rings: List[Dict[str, Any]] = []
    kr = _keyring()
    if kr is not None:
        ring, problem = _read_keyring_ring(kr)
        if problem:
            problems.append(problem)
        if ring:
            rings.append(ring)
    ring, problem = _read_file_ring()
    if problem:
        problems.append(problem)
    if ring:
        rings.append(ring)
    merged: Dict[str, Any] = {"current": "", "keys": {}}
    for r in reversed(rings):              # the file first, so the credential store's entries win
        merged["keys"].update({str(k): v for k, v in r["keys"].items() if isinstance(v, str)})
    for r in rings:
        if r.get("current") in merged["keys"]:
            merged["current"] = r["current"]
            break
    return merged, problems


def _load_ring() -> Dict[str, Any]:
    return _load_ring_checked()[0]


def _save_ring(ring: Dict[str, Any]) -> str:
    """Keep the ring in the credential store when there is one and it reads
    the ring back (the file is then removed), else in the owner-only key
    file, read back too. Returns where. KeyUnavailable when neither keeps it."""
    text = json.dumps(ring, sort_keys=True)
    kr = None if key_file_chosen() else _keyring()
    if kr is not None:
        try:
            kr.set_password(KEYRING_SERVICE, "store-keys", text)
            if kr.get_password(KEYRING_SERVICE, "store-keys") == text:
                try:
                    os.unlink(key_file())
                except OSError:
                    pass
                return "credential store"
        except Exception:  # noqa: BLE001 - no usable backend: the key file below
            pass
    import safe_files
    try:
        safe_files.write_private_atomic(key_file(), text)
        with open(key_file(), "r", encoding="utf-8") as f:
            if f.read() != text:
                raise OSError("the key file did not read back")
    except OSError as e:
        raise KeyUnavailable(f"the store key could not be kept in the credential store or in {key_file()} ({e})") from None
    return "key file"


def _new_key_id() -> str:
    return secrets.token_hex(4)


# ── one key change at a time, across processes ──────────────────────────
# Making the first key, a rotation, the one-time migration and seal-all /
# unseal-all each read the key ring, rewrite stores and save the ring again.
# Two app processes on one data folder (a second server, the CLI next to a
# running server) doing that at once could each keep a different key, and
# the stores one sealed would not open with the ring the other saved. An OS
# file lock in the data folder (released by the OS if the process dies, so a
# crash never leaves it held) lets one go at a time: the other waits up to
# LOCK_WAIT_SECONDS, then stops with StoreBusy before changing anything.
LOCK_NAME = ".store_crypto.lock"
LOCK_WAIT_SECONDS = 30.0
_clock = time.monotonic
_sleep = time.sleep
_HELD = {"depth": 0, "file": None}


def lock_path() -> str:
    return os.path.join(_data_dir(), LOCK_NAME)


def read_only_problem(e: OSError) -> str:
    return (f"the data folder {_data_dir()} cannot be written ({e.strerror or type(e).__name__}), so no store key "
            "can be made or kept there and nothing is saved there; mount a writable data folder "
            "(the container's /data volume) to keep settings, encrypted")


def _try_lock(f) -> bool:
    try:
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(f) -> None:
    try:
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    f.close()


@contextmanager
def _exclusive(what: str, wait: Optional[float] = None):
    """Hold the data folder's store lock for `what` (re-entrant in this
    process; threads are kept apart by _LOCK). `wait`: seconds to wait for
    another process (default LOCK_WAIT_SECONDS; 0 refuses at once)."""
    with _LOCK:
        if _HELD["depth"] == 0:
            try:
                os.makedirs(_data_dir(), exist_ok=True)
                fd = os.open(lock_path(), os.O_RDWR | os.O_CREAT, 0o600)   # owner-only from the first write, like every file here
            except OSError as e:
                # A data folder that cannot be written (a read-only container
                # with no volume mounted, a read-only share): no key can be
                # made or kept there either, so say that, never an OSError.
                raise KeyUnavailable(read_only_problem(e)) from None
            try:
                os.chmod(lock_path(), 0o600)
            except OSError:
                pass
            f = os.fdopen(fd, "a+")
            deadline = _clock() + max(0.0, float(LOCK_WAIT_SECONDS if wait is None else wait))
            while not _try_lock(f):
                if _clock() >= deadline:
                    f.close()
                    raise StoreBusy(f"Another copy of the app is changing the store key or re-sealing the stores, so this {what} "
                                    "was not started and nothing was changed. Try again once it has finished.")
                _sleep(0.2)
            _HELD["file"] = f
        _HELD["depth"] += 1
        try:
            yield
        finally:
            _HELD["depth"] -= 1
            if _HELD["depth"] == 0:
                f, _HELD["file"] = _HELD["file"], None
                _unlock(f)


def _current(create: bool = True) -> Optional[Dict[str, Any]]:
    """The key ring with a current key. A new key is made only when none
    exists anywhere and nothing that might hold one failed to read (a locked
    credential store or a damaged key file is never overwritten), and it is
    used only once it reads back from where it was kept."""
    with _LOCK:
        ring, problems = _load_ring_checked()
        if ring.get("current") in ring["keys"]:
            return ring
        if not create:
            return None
        with _exclusive("new store key"):
            # Another process may have made the key while this one waited: use it.
            ring, problems = _load_ring_checked()
            if ring.get("current") in ring["keys"]:
                return ring
            if problems:
                raise KeyUnavailable("No new store key was made because " + "; ".join(problems)
                                     + ". Fix that (unlock the credential store, or restore the key file) and start again.")
            kid = _new_key_id()
            while kid in ring["keys"]:
                kid = _new_key_id()
            ring["keys"][kid] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            ring["current"] = kid
            _save_ring(ring)
            again = _load_ring()
            if again["keys"].get(kid) != ring["keys"][kid]:
                raise KeyUnavailable("The new store key did not read back from where it was kept, so it was not used.")
            return again if again.get("current") == kid else dict(again, current=kid)


_KEY_PROBLEM: Dict[str, Optional[str]] = {"problem": None}


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
    """`text` sealed with the current key when encryption is on; as it is
    otherwise. When encryption is on only by default and no key can be kept
    here, the text stays plain (status() and the start-up message say why);
    an explicit DLP_CHECK_STORE_ENCRYPTION=1 raises KeyUnavailable instead."""
    if not enabled():
        return text
    try:
        ring = _current(create=True)
    except KeyUnavailable as e:
        _KEY_PROBLEM["problem"] = str(e)
        if explicitly_on():
            raise
        return text
    _KEY_PROBLEM["problem"] = None
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
                    ("deployments", "store_path"), ("workspace_notes", "store_path"), ("investigation_journal", "store_path"), ("block_page_theme", "store_path"), ("team_server", "store_path"),
                    ("sync_jobs", "store_path"), ("zcc_fleet_history", "history_path"), ("ssl_coverage", "history_path"),
                    ("tenant_api_map", "history_path")):
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
    # Stores made of many files: configuration backups (index, bk-*, tpl-*,
    # cache-*) and saved traffic log reports.
    for mod in ("config_backup", "traffic_logs"):
        try:
            for p in getattr(__import__(mod), "store_files")():
                add(p)
        except Exception:  # noqa: BLE001 - a store that cannot list itself has nothing to seal
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
    # The damaged copies self-healing moved aside (<store>.corrupt-<time>,
    # never deleted): a plain one is sealed like its store, and a rotation
    # re-seals them too, so none is left plain or under a forgotten key. One
    # that does not open (a damaged sealed file) is left as it is ("copy").
    for e in list(uniq):
        for c in sorted(glob.glob(glob.escape(e["path"]) + ".corrupt-*")):
            if c not in seen and os.path.isfile(c):
                seen.add(c)
                uniq.append({"path": c, "lines": e["lines"], "copy": True})
    return uniq


def _key_ids_in(text: str, lines: bool) -> set:
    """The key ids a store file's sealed text (or lines) names."""
    parts = [ln for ln in text.splitlines() if ln.strip()] if lines else [text]
    return {p.strip()[len(PREFIX):].partition(":")[0] for p in parts if is_sealed(p.strip())}


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
    done = []
    with _exclusive("seal-all"):
        ring = _current(create=True)
        kid, key = ring["current"], ring["keys"][ring["current"]]
        for e in _store_paths():
            try:
                _reseal_file(e["path"], e["lines"], lambda t: _seal_with(t, kid, key))
            except (StoreLocked, UnicodeDecodeError):
                if not e.get("copy"):
                    raise
                continue                          # a damaged copy self-healing kept: left as it is
            done.append(os.path.basename(e["path"]))
    _audit("store_encryption_sealed", files=len(done), key=kid)
    return {"key": kid, "files": done}


def rotate(wait: Optional[float] = None) -> Dict[str, Any]:
    """Make a new key, re-seal every store with it, then forget the old key.
    A store that cannot be opened stops the rotation before any key is
    forgotten (both keys stay, so nothing is lost). One at a time across
    processes (_exclusive): a second rotation waits, or stops with StoreBusy."""
    with _exclusive("key rotation", wait):
        ring = _current(create=True)
        old = ring["current"]
        kid = _new_key_id()
        while kid in ring["keys"]:
            kid = _new_key_id()
        ring["keys"][kid] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        _save_ring(ring)                          # both keys held while re-sealing
        key = ring["keys"][kid]
        if _load_ring()["keys"].get(kid) != key:
            raise KeyUnavailable("The new store key did not read back from where it was kept; nothing was re-sealed.")
        done = []
        for e in _store_paths():
            try:
                _reseal_file(e["path"], e["lines"], lambda t: _seal_with(t, kid, key))
            except (StoreLocked, UnicodeDecodeError):
                if not e.get("copy"):
                    raise
                continue                          # a damaged copy: left as it is; the re-check below keeps its key
            done.append(os.path.basename(e["path"]))
        # Before any key is forgotten, every store file (and every copy) is
        # read again: a key some file still names (a damaged copy, or a write
        # that raced the re-seal) is kept, so nothing becomes unreadable.
        still = set()
        for e in _store_paths():
            try:
                still |= _key_ids_in(_read_text(e["path"]), e["lines"])
            except (OSError, UnicodeDecodeError):
                continue
        kept_old = sorted(k for k in still if k != kid and k in ring["keys"])
        ring = {"current": kid, "keys": dict({kid: key}, **{k: ring["keys"][k] for k in kept_old})}
        where = _save_ring(ring)
    _audit("store_key_rotated", old_key=old, new_key=kid, files=len(done), kept_in=where, old_keys_kept=len(kept_old))
    return {"old_key": old, "new_key": kid, "files": done, "kept_in": where, "old_keys_kept": kept_old}


# ── the one-time migration of plain stores (upgrades) ───────────────────
MIGRATION_FILE = "store_encryption_migration.json"
BACKUP_DIR = "store-encryption-backup"
STALE_TMP_SECONDS = 3600


class MigrationStopped(RuntimeError):
    """The migration stopped safely: what was sealed reads back, the rest is still plain, the backup is kept."""


def migration_path() -> str:
    return os.path.join(_data_dir(), MIGRATION_FILE)


def backup_dir() -> str:
    return os.path.join(_data_dir(), BACKUP_DIR)


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _plain_view(text: str, lines: bool) -> str:
    """What a store file holds, opened: the audit log line by line (blank
    lines dropped, as re-sealing drops them), any other file whole."""
    if lines:
        return "".join(open_text(ln.rstrip("\n")) + "\n" for ln in text.splitlines() if ln.strip())
    return open_text(text)


def _fully_sealed(text: str, lines: bool) -> bool:
    if lines:
        return all(is_sealed(ln) for ln in text.splitlines() if ln.strip())
    return is_sealed(text) or not text.strip()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def plain_stores() -> List[Dict[str, Any]]:
    """Every store file that still holds plain text (in whole or, for the
    audit log, in some lines)."""
    out = []
    for e in _store_paths():
        try:
            if not _fully_sealed(_read_text(e["path"]), e["lines"]):
                out.append(e)
        except (OSError, UnicodeDecodeError):
            continue          # unreadable here: self-healing reports it; never sealed blind
    return out


def _load_journal() -> Optional[Dict[str, Any]]:
    try:
        with open(migration_path(), "r", encoding="utf-8") as f:
            j = json.load(f)
        return j if isinstance(j, dict) else None
    except (OSError, ValueError):
        return None


def _save_journal(journal: Dict[str, Any]) -> None:
    import safe_files
    safe_files.write_private_atomic(migration_path(), json.dumps(journal, indent=1, sort_keys=True))


# The temporary names the stores' own atomic writes use besides
# ".<file>.<random>.tmp" (tenant_profiles, deployments, change_queue,
# workspace_notes, sync_jobs, self_heal), looked for in the data folder and
# beside every store, whether or not that store's file exists now.
_TEMP_PATTERNS = (".profiles-*", ".deployments-*", ".change_requests.*.tmp", ".workspace_notes.*.tmp", ".sync_jobs.*.tmp",
                  ".selfheal-*.tmp")


def _temp_files() -> List[str]:
    """Every temporary copy a crashed write could have left beside a store."""
    found = set()
    places = [(_data_dir(), None)] + [os.path.split(e["path"]) for e in _store_paths()]
    for folder, base in places:
        pats = list(_TEMP_PATTERNS) + (["." + glob.escape(base) + ".*.tmp"] if base else [])
        for pat in pats:
            found |= {t for t in glob.glob(os.path.join(glob.escape(folder), pat)) if os.path.isfile(t)}
    return sorted(found)


def _remove_stale_temp_files(now: float) -> int:
    """A crash in the middle of a write can leave a plain temporary copy
    beside a store (".<store>.<random>.tmp", ".profiles-<random>",
    ".deployments-<random>", ".selfheal-<random>.tmp"); one older than an
    hour is no write in progress, so it goes too (no plain copy stays).
    Run at every start, not only by the migration."""
    gone = 0
    for t in _temp_files():
        try:
            if now - os.path.getmtime(t) > STALE_TMP_SECONDS:
                os.unlink(t)
                gone += 1
        except OSError:
            pass
    return gone


def _seal_one(path: str, rec: Dict[str, Any], kid: str, key: str) -> None:
    """Seal one plain store file in place (atomic), then read it back: it
    must be fully sealed and open to exactly what the backup holds; if not,
    the backup is put back and the migration stops."""
    import safe_files
    lines = bool(rec.get("lines"))
    text = _read_text(path)
    want = _plain_view(_read_text(os.path.join(backup_dir(), rec["backup"])), lines)
    if _plain_view(text, lines) != want:
        raise MigrationStopped(f"{os.path.basename(path)} changed after its backup was taken; nothing of it was sealed")
    if lines:
        new = "".join(_seal_with(open_text(ln.rstrip("\n")), kid, key) + "\n" for ln in text.splitlines() if ln.strip())
    else:
        new = _seal_with(open_text(text), kid, key)
    safe_files.write_private_atomic(path, new)
    back = _read_text(path)
    try:
        ok = _fully_sealed(back, lines) and _plain_view(back, lines) == want
    except StoreLocked:
        ok = False
    if not ok:
        safe_files.write_private_atomic(path, _read_text(os.path.join(backup_dir(), rec["backup"])))
        raise MigrationStopped(f"{os.path.basename(path)} did not read back after sealing; it was put back from the backup")


def _backup_files() -> List[str]:
    """The plain copies in the migration's backup folder."""
    try:
        return sorted(os.listdir(backup_dir()))
    except OSError:
        return []


def _drop_sealed_backups(files: Dict[str, Dict[str, Any]]) -> None:
    for rec in files.values():
        if rec.get("sealed") and rec.get("backup"):
            try:
                os.unlink(os.path.join(backup_dir(), rec["backup"]))
            except OSError:
                pass


def migrate(now: Optional[Callable[[], float]] = None) -> Dict[str, Any]:
    """Seal every store that is still plain, once, safely: a verified backup
    first, then each file sealed atomically and read back, with a journal so
    an interrupted run resumes on the next start. The backup is removed only
    when every file reads back. Returns {status, files, key, message}:
    status is off | nothing | done | no_key | stopped."""
    clock = now or time.time
    if not enabled():
        return {"status": "off", "files": 0, "message": ""}
    import safe_files
    with _exclusive("encryption of the stores"):
        _remove_stale_temp_files(clock())        # at every start: a plain temporary copy a crash left (older than an hour)
        journal = _load_journal() or {}
        resuming = journal.get("state") == "in_progress"
        todo = plain_stores()
        if not todo and not resuming:
            return {"status": "nothing", "files": 0, "message": ""}
        try:
            ring = _current(create=True)
        except KeyUnavailable as e:
            _KEY_PROBLEM["problem"] = str(e)
            return {"status": "no_key", "files": 0, "error": str(e),
                    "message": f"Store encryption: the stores stay unencrypted for now: {e}"}
        kid, key = ring["current"], ring["keys"][ring["current"]]
        files: Dict[str, Dict[str, Any]] = dict(journal.get("files") or {}) if resuming else {}
        bdir = backup_dir()
        safe_files.private_makedirs(bdir)
        # 1. A verified owner-only backup of every plain file, before anything is sealed.
        try:
            for e in todo:
                path = e["path"]
                text = _read_text(path)
                rec = files.get(path)
                if rec and rec.get("sha256") == _sha(text) and os.path.isfile(os.path.join(bdir, rec["backup"])):
                    rec["sealed"] = False
                    continue
                name = (rec or {}).get("backup") or f"{len(files):04d}-{os.path.basename(path)}"
                safe_files.write_private_atomic(os.path.join(bdir, name), text)
                if _sha(_read_text(os.path.join(bdir, name))) != _sha(text):
                    raise MigrationStopped(f"the backup of {os.path.basename(path)} did not read back")
                files[path] = {"backup": name, "sha256": _sha(text), "lines": bool(e["lines"]), "sealed": False}
        except (MigrationStopped, OSError, UnicodeDecodeError) as err:
            if not resuming:
                shutil.rmtree(bdir, ignore_errors=True)   # nothing sealed yet: the stores themselves are the plain copy
            return {"status": "stopped", "files": 0, "key": kid, "error": str(err),
                    "message": (f"Store encryption: existing stores were not encrypted ({err}); nothing was changed, they stay "
                                "plain and readable, and it is tried again at the next start.")}
        journal = {"state": "in_progress", "key": kid, "backup_dir": bdir, "files": files,
                   "started": journal.get("started") if resuming else int(clock())}
        _save_journal(journal)
        # 2. Seal each file; the journal records each one, so a rerun resumes.
        stopped = None
        for path, rec in files.items():
            if rec.get("sealed"):
                continue
            try:
                if not os.path.isfile(path):
                    rec["sealed"] = True          # removed since (a deleted snapshot): nothing to seal
                elif _fully_sealed(_read_text(path), bool(rec.get("lines"))):
                    _plain_view(_read_text(path), bool(rec.get("lines")))   # sealed already (an interrupted run, or a write since): it must open
                    rec["sealed"] = True
                else:
                    _seal_one(path, rec, kid, key)
                    rec["sealed"] = True
            except (MigrationStopped, StoreLocked, OSError, UnicodeDecodeError) as err:
                stopped = str(err)
                break
            _save_journal(journal)
        if stopped:
            # The backup of a file that is sealed and read back is no longer
            # needed: it goes, so only the files still plain have a plain copy.
            _drop_sealed_backups(files)
            journal["last_error"] = stopped
            _save_journal(journal)
            left = _backup_files()
            _audit("store_encryption_migration_stopped", files=len(files), reason=stopped[:200], plaintext_backup_files=len(left))
            return {"status": "stopped", "files": sum(1 for r in files.values() if r.get("sealed")), "key": kid, "error": stopped,
                    "plaintext_backup_files": len(left),
                    "message": ("Store encryption: the one-time encryption of existing stores stopped (" + stopped + "). Nothing was lost: "
                                f"the files not yet encrypted are still plain and readable, and {bdir} keeps an UNENCRYPTED backup "
                                f"of them ({len(left)} file(s)) until the migration finishes. It carries on at the next start.")}
        # 3. Every file reads back: remove the backup, the stale temporary copies and the per-file journal.
        shutil.rmtree(bdir, ignore_errors=True)
        if os.path.exists(bdir):
            err = f"the backup folder {bdir} could not be removed"
            journal["last_error"] = err
            _save_journal(journal)
            _audit("store_encryption_migration_stopped", files=len(files), reason=err, plaintext_backup_files=len(_backup_files()))
            return {"status": "stopped", "files": len(files), "key": kid, "error": err, "plaintext_backup_files": len(_backup_files()),
                    "message": (f"Store encryption: every store is encrypted, but {err}: it still holds UNENCRYPTED copies. "
                                "Remove it by hand, or it is tried again at the next start.")}
        _remove_stale_temp_files(clock())
        n = len(files)
        _save_journal({"state": "done", "key": kid, "files": n, "finished": int(clock())})
    where = status()["kept_in"]
    _audit("store_encryption_migrated", files=n, key=kid, kept_in=where)
    return {"status": "done", "files": n, "key": kid, "kept_in": where,
            "message": (f"Store encryption is now on by default: {n} existing store file(s) were encrypted (AES-256-GCM, key kept in the "
                        f"{where}). A verified backup was taken first and removed once every file read back. "
                        "To opt out, set DLP_CHECK_STORE_ENCRYPTION=0 (INSTALL.md, \"Encrypted stores\").")}


def unseal_all() -> Dict[str, Any]:
    """The opt-out's second half: every sealed store turned back into plain
    owner-only JSON (each file atomically, read back). Only with
    DLP_CHECK_STORE_ENCRYPTION=0, or the next write would seal it again."""
    if enabled():
        raise RuntimeError("Store encryption is on. Set DLP_CHECK_STORE_ENCRYPTION=0 first, then run unseal-all.")
    import safe_files
    done = []
    with _exclusive("unseal-all"):
        for e in _store_paths():
            text = _read_text(e["path"])
            if not any(is_sealed(ln) for ln in (text.splitlines() if e["lines"] else [text])):
                continue
            try:
                plain = _plain_view(text, e["lines"])     # StoreLocked stops here, before this file is touched
            except StoreLocked:
                if not e.get("copy"):
                    raise
                continue                                  # a damaged copy self-healing kept: left as it is
            safe_files.write_private_atomic(e["path"], plain)
            if _read_text(e["path"]) != plain:
                raise OSError(f"{os.path.basename(e['path'])} did not read back")
            done.append(os.path.basename(e["path"]))
    _audit("store_encryption_unsealed", files=len(done))
    return {"files": done}


def migration_status() -> Dict[str, Any]:
    j = _load_journal() or {}
    out = {"state": j.get("state") or "none"}
    if j.get("state") == "done":
        out.update(files=j.get("files"), finished=j.get("finished"))
    elif j.get("state") == "in_progress":
        out.update(files=len(j.get("files") or {}), sealed=sum(1 for r in (j.get("files") or {}).values() if r.get("sealed")),
                   last_error=j.get("last_error"), backup_dir=j.get("backup_dir"))
    left = _backup_files()
    if left:
        out.update(plaintext_backup_files=len(left), backup_dir=backup_dir(),
                   plaintext_backup=(f"{backup_dir()} holds an UNENCRYPTED backup of {len(left)} store file(s) until the "
                                     "one-time encryption finishes"))
    return out


def startup(log: Callable[[str], None] = print) -> Dict[str, Any]:
    """What the server runs once before it serves: the migration, with one
    plain message. Never stops the app."""
    if not enabled():
        log("  Store encryption: off (DLP_CHECK_STORE_ENCRYPTION=0); stores are written as plain owner-only files.")
        return {"status": "off"}
    try:
        out = migrate()
    except KeyUnavailable as e:
        _KEY_PROBLEM["problem"] = str(e)
        log(f"  Store encryption: no store key here: {e}.")
        return {"status": "no_key", "error": str(e)}
    except Exception as e:  # noqa: BLE001 - the app still reads plain and sealed stores
        log(f"  Store encryption: the stores could not be encrypted now ({type(e).__name__}); they stay readable and it is tried again at the next start.")
        return {"status": "error"}
    if out.get("message"):
        log("  " + out["message"])
    return out


def _where_kept() -> str:
    """Where the key ring IS ("credential store" or "key file"), read, not
    guessed; where a new one would go when there is none yet."""
    kr = _keyring()
    if kr is not None and not key_file_chosen():
        ring, _problem = _read_keyring_ring(kr)
        if ring:
            return "credential store"
    if os.path.isfile(key_file()):
        return "key file"
    return "credential store" if kr is not None and not key_file_chosen() else "key file"


def health_view() -> Dict[str, Any]:
    """What /api/health says about store encryption: cheap (no credential
    store or key file is read), so a polled health check never touches them."""
    problem = _KEY_PROBLEM["problem"]
    return {"enabled": enabled(), "sealing": enabled() and not problem, "problem": problem}


def status() -> Dict[str, Any]:
    ring = _load_ring()
    problem = _KEY_PROBLEM["problem"]
    where = _where_kept()
    return {"enabled": enabled(), "default": not os.environ.get(SETTING, "").strip(), "key": ring.get("current") or None,
            "keys_held": len(ring["keys"]), "kept_in": where,
            "key_file": key_file() if where == "key file" else None, "algorithm": "AES-256-GCM",
            "sealing": enabled() and not problem, "problem": problem, "migration": migration_status()}


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
            "HTTPS: ECDHE/DHE with AES-GCM only for TLS 1.2 (no ChaCha20); the TLS 1.3 suites are the platform OpenSSL's, which a FIPS OpenSSL limits to AES-GCM",
            "Certificates this app makes: ECDSA P-256 with SHA-256",
            "Tokens and hashes: SHA-256; random values from the operating system's generator",
        ],
        "platform_fips_enabled": _platform_fips(),
        "openssl": ssl.OPENSSL_VERSION,
        "honest_note": ("FIPS mode limits the algorithms this app chooses. It does not make the app FIPS 140-3 validated: the Python "
                        "interpreter and the OpenSSL and cryptography builds it runs on are not a validated module unless your "
                        "platform provides one and runs in FIPS mode (for example a FIPS-enabled RHEL with its validated OpenSSL)."),
    }


def _cli(argv: Optional[List[str]] = None) -> int:
    """python store_crypto.py status | migrate | seal-all | rotate | unseal-all | fips"""
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else ""
    if cmd == "status":
        print(json.dumps(status(), indent=1))
    elif cmd == "fips":
        print(json.dumps(fips_status(), indent=1))
    elif cmd == "migrate":
        out = migrate()
        print(out.get("message") or {"off": "Store encryption is off (DLP_CHECK_STORE_ENCRYPTION=0).",
                                     "nothing": "Every store is already encrypted."}.get(out["status"], out["status"]))
        return 0 if out["status"] in ("off", "nothing", "done") else 1
    elif cmd == "unseal-all":
        out = unseal_all()
        print(f"Turned {len(out['files'])} encrypted store file(s) back into plain owner-only files.")
    elif cmd == "seal-all":
        out = seal_all()
        print(f"Sealed {len(out['files'])} store file(s) with key {out['key']}.")
    elif cmd == "rotate":
        out = rotate()
        print(f"Rotated the store key {out['old_key']} -> {out['new_key']}; re-sealed {len(out['files'])} file(s); kept in the {out['kept_in']}.")
    else:
        print(_cli.__doc__)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - command line
    raise SystemExit(_cli())
