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
                  "industry", "baseline_packs", "scopes", "frameworks", "notes")
SECRET_FIELD = "client_secret"


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
    return data


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
    out["has_secret"] = bool(p.get(SECRET_FIELD))
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


def get(profile_id: str, *, with_secret: bool = False) -> Optional[Dict[str, Any]]:
    with _LOCK:
        data = _read()
    p = data["profiles"].get(profile_id)
    if not p:
        return None
    return dict(p) if with_secret else masked(p)


def upsert(fields: Dict[str, Any], *, client_secret: str = "", remember_secret: bool = False,
           profile_id: str = "") -> Dict[str, Any]:
    """Create or update. Blank secret keeps a previously remembered one;
    remember_secret=False forgets it."""
    with _LOCK:
        data = _read()
        pid = profile_id or slugify(fields.get("name") or fields.get("org_name") or fields.get("vanity_domain") or "")
        p = data["profiles"].get(pid) or {"id": pid, "created_at": _now(), "history": []}
        for k in PROFILE_FIELDS:
            if k in fields and fields[k] is not None:
                p[k] = fields[k]
        p.setdefault("name", p.get("org_name") or pid)
        if remember_secret:
            if client_secret:
                p[SECRET_FIELD] = client_secret
        else:
            p.pop(SECRET_FIELD, None)
        p["updated_at"] = _now()
        data["profiles"][pid] = p
        _write(data)
        return masked(p)


def delete(profile_id: str) -> bool:
    with _LOCK:
        data = _read()
        if profile_id not in data["profiles"]:
            return False
        del data["profiles"][profile_id]
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
    return {
        "cloud": str(profile.get("cloud") or ""),
        "vanity_domain": str(profile.get("vanity_domain") or ""),
        "client_id": str(profile.get("client_id") or ""),
        "client_secret": str(profile.get(SECRET_FIELD) or ""),
        "customer_id": str(profile.get("customer_id") or ""),
    }
