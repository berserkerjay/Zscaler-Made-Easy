#!/usr/bin/env python3
"""
Tenant profiles — one saved record per customer tenant, so a consultant
who looks after many tenants can switch between them and see each one's
history on the data-governance journey.

A profile holds what the tenant form asks for (organisation, assessor,
cloud, vanity domain, client ID, optional ZPA customer ID, scopes,
frameworks), engagement context (industry, which baseline packs apply,
notes) and a HISTORY of assessments: date, score, maturity, each check's
state (`states`, for the score trend), and the journey stage/score per
baseline. The client secret is stored only when
the operator ticks "remember the secret on this laptop"; it is never
returned by the API (only ``has_secret``).

Storage: ``tenant_profiles.json`` next to the app (git-ignored), or the
path in ``DLP_CHECK_PROFILES``. Written with owner-only permissions.

Snapshots: a saved tenant read (offline_tenant.py, "Save a snapshot") is a
file in ``tenant_snapshots/`` beside the profile store (folder 0700, file
0600, named by the app: ``snap-<16 hex>.json``), listed with the profile it
was read for (``snapshots`` of each profile; ``unfiled_snapshots`` for a
read made without a profile). It holds API answers only, never a
credential, and is deleted with its profile.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import safe_files

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCK = threading.Lock()
HISTORY_LIMIT = 50

PROFILE_FIELDS = ("name", "org_name", "assessor", "cloud", "vanity_domain", "client_id", "customer_id",
                  "auth_method", "username",
                  "industry", "baseline_packs", "scopes", "frameworks", "channels", "notes")
# The remembered secrets: the OneAPI client secret, and the password and
# API key of the classic ZIA sign-in. Each is kept in the credential store
# (or the owner-only file) under its own key; the profile holds a marker.
SECRET_FIELD = "client_secret"
SECRET_FIELDS = ("client_secret", "password", "api_key")


def store_path() -> str:
    return os.environ.get("DLP_CHECK_PROFILES") or os.path.join(_APP_DIR, "tenant_profiles.json")


# A profile's POV (pov.py) lives in the profile's folder: povs/<profile id>.json
# beside this store, owner-only. It goes with its profile (delete).
POV_DIR = "povs"
_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


def pov_path(profile_id: str) -> str:
    """The file that holds the profile's POV; ValueError for an id that is
    not a profile id (nothing from a request becomes a path unchecked)."""
    if not isinstance(profile_id, str) or not _PROFILE_ID_RE.match(profile_id):
        raise ValueError("not a tenant profile id")
    return os.path.join(os.path.dirname(os.path.abspath(store_path())), POV_DIR, f"{profile_id}.json")


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s[:48] or "tenant"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read() -> Dict[str, Any]:
    p = store_path()
    if not os.path.exists(p):
        return {"version": 1, "profiles": {}}
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:
        return {"version": 1, "profiles": {}}
    data.setdefault("version", 1)
    data.setdefault("profiles", {})
    if not isinstance(data.get("snapshots", {}), dict):
        data["snapshots"] = {}   # not a snapshot list this app wrote: ignored, never a crash (its files are left alone)
    if _upgrade_classic_profiles(data):
        _write(data)
    return data


def _is_classic(p: Dict[str, Any]) -> bool:
    try:
        import tenant_auth
        return tenant_auth.method_of(p) == tenant_auth.LEGACY
    except Exception:  # noqa: BLE001
        return False


def classic_leaks(p: Dict[str, Any]) -> set:
    """What must never name a classic-API profile (user rule 3): its admin
    login and a vanity domain left in it, as typed and as slugs."""
    out = set()
    for v in (p.get("username"), p.get("vanity_domain")):
        v = str(v or "").strip().lower()
        if v:
            out.update({v, slugify(v)})
    return out


def classic_name_leaks(p: Dict[str, Any], name: Any) -> bool:
    """True when `name` is a classic-API profile's admin login or stale
    vanity domain (as typed or slugified)."""
    n = str(name or "").strip().lower()
    leaks = classic_leaks(p)
    return bool(n) and (n in leaks or slugify(n) in leaks)


def _classic_default_name(p: Dict[str, Any]) -> str:
    import tenant_auth
    return tenant_auth.record_label({"auth_method": tenant_auth.LEGACY, "cloud": p.get("cloud") or ""})


def _upgrade_classic_profiles(data: Dict[str, Any]) -> bool:
    """Classic-API profiles saved before this release were named, and their
    id slugified, from the admin login (or a vanity domain left in the
    form). Rename them to 'classic API (<cloud>)' and move them, with their
    remembered secrets and the proposal queue kept under the old id, to an
    id derived from that name. Returns whether anything changed."""
    changed = False
    profiles = data["profiles"]
    for pid in list(profiles):
        p = profiles[pid]
        if not isinstance(p, dict) or not _is_classic(p):
            continue
        if classic_name_leaks(p, p.get("name")):
            p["name"] = _classic_default_name(p)
            changed = True
        if not classic_name_leaks(p, pid):
            continue
        base = slugify(p.get("name") if not classic_name_leaks(p, p.get("name")) else _classic_default_name(p))
        new, n = base, 2
        while new in profiles or classic_name_leaks(p, new):
            new, n = f"{base}-{n}", n + 1
        secrets: Dict[str, str] = {}
        for field in SECRET_FIELDS:
            if p.get(field) == KEYRING_MARK:
                sec = _load_secret(pid, field)
                if sec is None:     # the credential store cannot be read now: keep the id rather than lose the secret
                    secrets = {}
                    new = ""
                    break
                secrets[field] = sec
        if not new:
            continue
        for field, sec in secrets.items():
            p[field] = _store_secret(new, sec, field)
            if p[field] == KEYRING_MARK:
                _forget_secret(pid, KEYRING_MARK, field)
        p["id"] = new
        profiles[new] = p
        del profiles[pid]
        changed = True
        others = {str(x).strip().lower() for q in profiles.values() if q is not p for x in (q.get("id"), q.get("vanity_domain")) if x}
        if not p.get("vanity_domain") and not p.get("proposal_queue_migrated") and pid.lower() not in others:
            # Before this release the loop queued such a profile's
            # proposals under its id (unless another profile claims it).
            try:
                import proposals
                proposals.rekey(pid, new)
            except Exception:  # noqa: BLE001
                pass
    return changed


def _write(data: Dict[str, Any]) -> None:
    p = store_path()
    d = os.path.dirname(p) or "."
    safe_files.private_makedirs(d)
    fd, tmp = tempfile.mkstemp(prefix=".profiles-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        _keep_last_good(p)
        os.replace(tmp, p)
        _forget_in_last_good(p, data)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _plain_secrets(data: Dict[str, Any]) -> set:
    """The secrets a store holds in plain text (DLP_CHECK_SECRET_STORE=file):
    every remembered secret that is not the credential-store marker."""
    out = set()
    for p in (data.get("profiles") or {}).values() if isinstance(data, dict) else []:
        if isinstance(p, dict):
            out |= {str(p[f]) for f in SECRET_FIELDS if p.get(f) and p.get(f) != KEYRING_MARK}
    return out


def _forget_in_last_good(path: str, data: Dict[str, Any]) -> None:
    """The last-good copy is the store before this write. When this write
    forgot a secret (remember unticked, a new secret, a deleted profile),
    that copy would keep it on disk: it is then refreshed from the store as
    written now, so a forgotten secret is gone from both files."""
    lg = path + ".last-good"
    try:
        with open(lg, "r", encoding="utf-8") as f:
            old = json.load(f)
    except (OSError, ValueError):
        return
    if not (_plain_secrets(old) - _plain_secrets(data)):
        return
    try:
        import self_heal
        with open(path, "rb") as f:
            self_heal._atomic_write_bytes(lg, f.read())
    except Exception:  # noqa: BLE001 - fail closed: no copy rather than one holding a forgotten secret
        try:
            os.unlink(lg)
        except OSError:
            pass


def masked(p: Dict[str, Any], *, with_history: bool = True) -> Dict[str, Any]:
    """Public view: never carries the secret."""
    out = {k: p.get(k) for k in ("id", "created_at", "updated_at") + PROFILE_FIELDS}
    out["auth_method"] = str(p.get("auth_method") or "") or ("legacy" if (p.get("username") and not p.get("client_id")) else "oneapi")
    # "Remembered" means what the profile's sign-in needs: the client secret,
    # or both the password and the API key of the classic sign-in.
    out["has_secret"] = (bool(p.get("password") and p.get("api_key")) if out["auth_method"] == "legacy" else bool(p.get(SECRET_FIELD)))
    out["proposal_queue_migrated"] = bool(p.get("proposal_queue_migrated"))
    hist = list(p.get("history") or [])
    out["last_assessed"] = {k: v for k, v in hist[-1].items() if k != "states"} if hist and isinstance(hist[-1], dict) else (hist[-1] if hist else None)
    if with_history:
        out["history"] = hist
    return out


def list_profiles() -> List[Dict[str, Any]]:
    with _LOCK:
        data = _read()
    snaps = _snapshot_rows(data)
    rows = [dict(masked(p, with_history=False), snapshots=[s for s in snaps if s.get("profile_id") == p.get("id")])
            for p in data["profiles"].values()]
    rows.sort(key=lambda r: (r.get("name") or "").lower())
    return rows


# ── Secret storage ────────────────────────────────────────────────────
# A remembered secret goes to the operating system's credential store
# through the `keyring` package (Windows Credential Manager / DPAPI, macOS
# Keychain); the profile file then holds only a marker. keyring is pinned by
# hash in requirements.lock for Windows and macOS only; on Linux and in the
# container it is not installed. Without a usable credential store (or when
# it refuses the secret) the secret is written to the owner-only profile
# file ONLY when the operator chose that explicitly with
# DLP_CHECK_SECRET_STORE=file; otherwise it is not remembered and the save
# says so (secret_warning). Never a silent plaintext fallback. Secrets saved
# in the file by older versions still load.
KEYRING_SERVICE = "dlp-check"
KEYRING_MARK = "@keyring"
FILE_STORE_OPT_IN = "DLP_CHECK_SECRET_STORE"


def file_store_allowed() -> bool:
    """True when the operator explicitly allowed plaintext secrets in the
    owner-only profile file (DLP_CHECK_SECRET_STORE=file)."""
    return os.environ.get(FILE_STORE_OPT_IN, "").strip().lower() == "file"


def _keyring():
    try:
        import keyring  # type: ignore
        return keyring
    except Exception:  # noqa: BLE001
        return None


def secret_storage() -> str:
    """Where a remembered secret would be kept on this machine: 'keyring',
    'file' (only with DLP_CHECK_SECRET_STORE=file) or 'none' (not remembered)."""
    if _keyring() is not None:
        return "keyring"
    return "file" if file_store_allowed() else "none"


NOT_REMEMBERED = ("The secret was not remembered: this machine has no usable credential store (the keyring package or its "
                  "backend is missing, as in the container). It is used for this session only. To keep it anyway in the "
                  "owner-only profile file, start the app with DLP_CHECK_SECRET_STORE=file.")


def _keyring_key(profile_id: str, field: str) -> str:
    """The credential-store key: the profile id alone for the client secret
    (as older versions stored it), `<id>:<field>` for the others."""
    return profile_id if field == SECRET_FIELD else f"{profile_id}:{field}"


def _store_secret(profile_id: str, secret: str, field: str = SECRET_FIELD) -> Optional[str]:
    """What the profile file holds for a remembered secret: the keyring
    marker, the secret itself (only with DLP_CHECK_SECRET_STORE=file), or
    None when it cannot be remembered safely."""
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(KEYRING_SERVICE, _keyring_key(profile_id, field), secret)
            return KEYRING_MARK
        except Exception:  # noqa: BLE001 — no usable backend
            pass
    return secret if file_store_allowed() else None


def _load_secret(profile_id: str, field: str = SECRET_FIELD) -> Optional[str]:
    kr = _keyring()
    if kr is None:
        return None
    try:
        return kr.get_password(KEYRING_SERVICE, _keyring_key(profile_id, field))
    except Exception:  # noqa: BLE001
        return None


def _forget_secret(profile_id: str, stored: Optional[str], field: str = SECRET_FIELD) -> None:
    if stored != KEYRING_MARK:
        return
    kr = _keyring()
    if kr is None:
        return
    try:
        kr.delete_password(KEYRING_SERVICE, _keyring_key(profile_id, field))
    except Exception:  # noqa: BLE001
        pass


def get(profile_id: str, *, with_secret: bool = False) -> Optional[Dict[str, Any]]:
    with _LOCK:
        data = _read()
    p = data["profiles"].get(profile_id)
    if not p:
        return None
    if not with_secret:
        return masked(p)
    out = dict(p)
    for field in SECRET_FIELDS:
        if out.get(field) == KEYRING_MARK:
            out[field] = _load_secret(profile_id, field) or ""
    return out


def upsert(fields: Dict[str, Any], *, client_secret: str = "", remember_secret: bool = False,
           profile_id: str = "", password: str = "", api_key: str = "") -> Dict[str, Any]:
    """Create or update. A blank secret keeps the one previously remembered
    for that field; remember_secret=False forgets every secret. `password`
    and `api_key` are the classic ZIA sign-in's secrets."""
    given = {"client_secret": client_secret, "password": password, "api_key": api_key}
    with _LOCK:
        data = _read()
        pid = profile_id or slugify(fields.get("name") or fields.get("org_name") or fields.get("vanity_domain") or "")
        p = data["profiles"].get(pid) or {"id": pid, "created_at": _now(), "history": []}
        for k in PROFILE_FIELDS:
            if k in fields and fields[k] is not None:
                p[k] = fields[k]
        p.setdefault("name", p.get("org_name") or pid)
        not_kept = []
        for field in SECRET_FIELDS:
            if remember_secret:
                if given[field]:
                    stored = _store_secret(pid, given[field], field)
                    if stored is None:
                        not_kept.append(field)
                        _forget_secret(pid, p.get(field), field)
                        p.pop(field, None)
                    else:
                        p[field] = stored
            else:
                _forget_secret(pid, p.get(field), field)
                p.pop(field, None)
        p["updated_at"] = _now()
        data["profiles"][pid] = p
        _write(data)
        out = masked(p)
        if not_kept:
            out["secret_warning"] = NOT_REMEMBERED
            out["secret_not_remembered"] = not_kept
        return out


def delete(profile_id: str) -> bool:
    with _LOCK:
        data = _read()
        if profile_id not in data["profiles"]:
            return False
        p = data["profiles"][profile_id]
        for field in SECRET_FIELDS:
            _forget_secret(profile_id, p.get(field), field)
        del data["profiles"][profile_id]
        for sid, ref in list((data.get("snapshots") or {}).items()):
            if isinstance(ref, dict) and ref.get("profile_id") == profile_id:   # its snapshots go with it
                _unlink_snapshot(sid)
                data["snapshots"].pop(sid, None)
        _write(data)
    try:   # the profile's POV (and its last-good copy) goes with it
        path = pov_path(profile_id)
    except ValueError:
        return True
    for f in (path, path + ".last-good"):
        try:
            os.unlink(f)
        except OSError:
            pass
    return True


def mark_proposal_queue_migrated(profile_id: str) -> bool:
    """Record that a classic-API profile's pre-release proposal queue was
    looked at (continuous_eval._proposal_key_migrated), so it is moved at
    most once."""
    with _LOCK:
        data = _read()
        p = data["profiles"].get(profile_id)
        if not p:
            return False
        p["proposal_queue_migrated"] = True
        _write(data)
        return True


def add_history(profile_id: str, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Append an assessment/journey snapshot; keeps the last HISTORY_LIMIT."""
    with _LOCK:
        data = _read()
        p = data["profiles"].get(profile_id)
        if not p:
            return None
        entry = dict(entry)
        entry.setdefault("at", _now())
        hist = list(p.get("history") or [])
        hist.append(entry)
        p["history"] = hist[-HISTORY_LIMIT:]
        p["updated_at"] = _now()
        _write(data)
        return masked(p)


def snapshot(report: Dict[str, Any]) -> Dict[str, Any]:
    """Compact history entry from an assessment report (with optional journey)."""
    j = report.get("journey") or {}
    entry: Dict[str, Any] = {
        "at": _now(),
        "score": report.get("score"),
        "maturity": report.get("maturity"),
        "checks": len([c for c in (report.get("checks") or []) if not (isinstance(c, dict) and c.get("out_of_scope"))]),
        "critical": len([c for c in (report.get("critical") or []) if not (isinstance(c, dict) and c.get("out_of_scope"))]),
        "assessor": (report.get("metadata") or {}).get("assessor"),
    }
    # Per-check states ({id: P|F|R|I|E}, bounded), so the score trend can say
    # which checks started or stopped failing between runs (posture_plus).
    # Entries recorded before this have none and still load.
    try:
        import posture_plus
        entry["states"] = posture_plus.states_of(report.get("checks") or [])
    except Exception:  # noqa: BLE001 — history without states rather than none
        pass
    if j and j.get("status") != "error":
        entry["journey"] = {
            "status": j.get("status"), "stage": j.get("stage"), "score": j.get("score"),
            "baselines": [{"id": b.get("id"), "name": b.get("name"), "stage": b.get("stage"),
                           "stage_name": b.get("stage_name"), "score": b.get("score"), "state": b.get("state"),
                           "next_steps": (b.get("next_steps") or [])[:3]}
                          for b in (j.get("baselines") or [])],
        }
    return entry


def creds_from(profile: Dict[str, Any]) -> Dict[str, str]:
    """The credential dict (tenant_auth.CRED_KEYS) a profile read with
    `with_secret=True` carries; the same nine keys for both sign-ins."""
    out = {
        "auth_method": str(profile.get("auth_method") or ""),
        "cloud": str(profile.get("cloud") or ""),
        "vanity_domain": str(profile.get("vanity_domain") or ""),
        "client_id": str(profile.get("client_id") or ""),
        "client_secret": str(profile.get(SECRET_FIELD) or ""),
        "customer_id": str(profile.get("customer_id") or ""),
        "username": str(profile.get("username") or ""),
        "password": str(profile.get("password") or ""),
        "api_key": str(profile.get("api_key") or ""),
    }
    for field in SECRET_FIELDS:
        if out[field] == KEYRING_MARK:   # a masked read: the marker is not a secret
            out[field] = ""
    return out


def _keep_last_good(path: str) -> None:
    """The store as it was, kept as a last-good copy (self_heal) before it is replaced."""
    try:
        import self_heal
        self_heal.keep_last_good(path)
    except Exception:  # noqa: BLE001 - never stops a write
        pass


# ── Snapshots (offline_tenant.py) ─────────────────────────────────────
SNAPSHOT_DIR = "tenant_snapshots"
MAX_SNAPSHOTS_PER_PROFILE = 20
SNAPSHOT_ID = re.compile(r"^snap-[0-9a-f]{16}$")
_SNAPSHOT_FIELDS = ("saved_at", "tenant_label", "scopes", "counts", "bytes", "profile_name")


def snapshots_dir() -> str:
    """tenant_snapshots/ beside the profile store."""
    return os.path.join(os.path.dirname(os.path.abspath(store_path())), SNAPSHOT_DIR)


def snapshot_path(snapshot_id: str) -> str:
    """The file of a snapshot id the app made; ValueError for any other text."""
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID.match(snapshot_id):
        raise ValueError("No such snapshot.")
    return os.path.join(snapshots_dir(), snapshot_id + ".json")


def _unlink_snapshot(snapshot_id: str) -> None:
    try:
        os.unlink(snapshot_path(snapshot_id))
    except (OSError, ValueError):
        pass


def _snapshot_rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for sid, ref in (data.get("snapshots") or {}).items():
        if isinstance(ref, dict) and SNAPSHOT_ID.match(str(sid)):
            rows.append(dict({k: ref.get(k) for k in _SNAPSHOT_FIELDS}, id=sid, profile_id=ref.get("profile_id") or ""))
    rows.sort(key=lambda r: str(r.get("saved_at") or ""), reverse=True)
    return rows


def list_snapshots(profile_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Saved snapshots, newest first; with `profile_id` ("" for those made
    without a profile) only that profile's."""
    with _LOCK:
        data = _read()
    rows = _snapshot_rows(data)
    return rows if profile_id is None else [r for r in rows if r["profile_id"] == profile_id]


def save_snapshot(text: str, entry: Dict[str, Any], profile_id: str = "") -> Dict[str, Any]:
    """Write a snapshot (owner-only) under a new id the app makes and list
    it with its profile. A profile keeps its newest MAX_SNAPSHOTS_PER_PROFILE."""
    import secrets
    sid = "snap-" + secrets.token_hex(8)
    with _LOCK:
        data = _read()
        pid = profile_id if profile_id in data["profiles"] else ""
        safe_files.private_makedirs(snapshots_dir())
        safe_files.write_private_atomic(snapshot_path(sid), text)
        ref = {k: entry.get(k) for k in _SNAPSHOT_FIELDS}
        ref.update(profile_id=pid, bytes=len(text.encode("utf-8")))
        if pid:
            ref["profile_name"] = data["profiles"][pid].get("name") or pid
        snaps = data.setdefault("snapshots", {})
        snaps[sid] = ref
        mine = sorted((k for k, v in snaps.items() if isinstance(v, dict) and v.get("profile_id") == pid),
                      key=lambda k: str(snaps[k].get("saved_at") or ""))
        for old in mine[:-MAX_SNAPSHOTS_PER_PROFILE]:
            _unlink_snapshot(old)
            snaps.pop(old, None)
        _write(data)
    return dict(ref, id=sid)


def read_snapshot(snapshot_id: str, limit: int) -> bytes:
    """The bytes of a saved snapshot (at most `limit`); ValueError when it
    is not listed, missing or too large."""
    path = snapshot_path(snapshot_id)
    with _LOCK:
        if snapshot_id not in (_read().get("snapshots") or {}):
            raise ValueError("No such snapshot.")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as f:
            raw = f.read(limit + 1)
    except OSError:
        raise ValueError("The snapshot file is missing.")
    if len(raw) > limit:
        raise ValueError("The snapshot file is too large.")
    return raw


def delete_snapshot(snapshot_id: str) -> bool:
    snapshot_path(snapshot_id)
    with _LOCK:
        data = _read()
        if snapshot_id not in (data.get("snapshots") or {}):
            return False
        _unlink_snapshot(snapshot_id)
        data["snapshots"].pop(snapshot_id, None)
        _write(data)
        return True
