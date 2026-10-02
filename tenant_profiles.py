#!/usr/bin/env python3
"""
Tenant profiles — one saved record per customer tenant, so a consultant
who looks after many tenants can switch between them and see each one's
history on the data-governance journey.

A profile holds what the tenant form asks for (organisation, assessor,
cloud, vanity domain, client ID, optional ZPA customer ID, scopes,
frameworks), engagement context (industry, which baseline packs apply,
notes) and a HISTORY of assessments: date, score, maturity, and the
journey stage/score per baseline. The client secret is stored only when
the operator ticks "remember the secret on this laptop"; it is never
returned by the API (only ``has_secret``).

Storage: ``tenant_profiles.json`` next to the app (git-ignored), or the
path in ``DLP_CHECK_PROFILES``. Written with owner-only permissions.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".profiles-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def masked(p: Dict[str, Any], *, with_history: bool = True) -> Dict[str, Any]:
    """Public view: never carries the secret."""
    out = {k: p.get(k) for k in ("id", "created_at", "updated_at") + PROFILE_FIELDS}
    out["auth_method"] = str(p.get("auth_method") or "") or ("legacy" if (p.get("username") and not p.get("client_id")) else "oneapi")
    # "Remembered" means what the profile's sign-in needs: the client secret,
    # or both the password and the API key of the classic sign-in.
    out["has_secret"] = (bool(p.get("password") and p.get("api_key")) if out["auth_method"] == "legacy" else bool(p.get(SECRET_FIELD)))
    out["proposal_queue_migrated"] = bool(p.get("proposal_queue_migrated"))
    hist = list(p.get("history") or [])
    out["last_assessed"] = hist[-1] if hist else None
    if with_history:
        out["history"] = hist
    return out


def list_profiles() -> List[Dict[str, Any]]:
    with _LOCK:
        data = _read()
    rows = [masked(p, with_history=False) for p in data["profiles"].values()]
    rows.sort(key=lambda r: (r.get("name") or "").lower())
    return rows


# ── Secret storage ────────────────────────────────────────────────────
# A remembered secret goes to the operating system's credential store
# through the `keyring` package (Windows Credential Manager / DPAPI, macOS
# Keychain); the profile file then holds only a marker. keyring is pinned by
# hash in requirements.lock for Windows and macOS only; on Linux and in the
# container it is not installed and the secret is stored in the owner-only
# profile file, as it is when the store refuses it.
KEYRING_SERVICE = "dlp-check"
KEYRING_MARK = "@keyring"


def _keyring():
    try:
        import keyring  # type: ignore
        return keyring
    except Exception:  # noqa: BLE001
        return None


def secret_storage() -> str:
    """'keyring' or 'file': where a remembered secret is kept on this machine."""
    return "keyring" if _keyring() is not None else "file"


def _keyring_key(profile_id: str, field: str) -> str:
    """The credential-store key: the profile id alone for the client secret
    (as older versions stored it), `<id>:<field>` for the others."""
    return profile_id if field == SECRET_FIELD else f"{profile_id}:{field}"


def _store_secret(profile_id: str, secret: str, field: str = SECRET_FIELD) -> str:
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(KEYRING_SERVICE, _keyring_key(profile_id, field), secret)
            return KEYRING_MARK
        except Exception:  # noqa: BLE001 — no usable backend: fall back to the file
            pass
    return secret


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
        for field in SECRET_FIELDS:
            if remember_secret:
                if given[field]:
                    p[field] = _store_secret(pid, given[field], field)
            else:
                _forget_secret(pid, p.get(field), field)
                p.pop(field, None)
        p["updated_at"] = _now()
        data["profiles"][pid] = p
        _write(data)
        return masked(p)


def delete(profile_id: str) -> bool:
    with _LOCK:
        data = _read()
        if profile_id not in data["profiles"]:
            return False
        p = data["profiles"][profile_id]
        for field in SECRET_FIELDS:
            _forget_secret(profile_id, p.get(field), field)
        del data["profiles"][profile_id]
        _write(data)
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
        "checks": len(report.get("checks") or []),
        "critical": len(report.get("critical") or []),
        "assessor": (report.get("metadata") or {}).get("assessor"),
    }
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
