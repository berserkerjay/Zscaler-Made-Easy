"""
Deployment records: what Deploy Policy Packs created in which tenant, so
a deployment can be undone later.

One record per apply that wrote something. It lists every object this
tool CREATED (kind, channel, name, tenant id, parent for sub-rules).
Objects that were reused, modified or restored are recorded for the
report but are never touched by an undo: they existed before, or their
previous content is not known.

The store is a JSON file next to the app (git-ignored, owner-only
permissions), the same convention as tenant_profiles.json.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
LIMIT = 200
UNDOABLE_KINDS = ("policy", "app_group", "engine", "dictionary")


def store_path() -> str:
    return os.environ.get("DLP_CHECK_DEPLOYMENTS") or os.path.join(_APP_DIR, "deployments.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read() -> Dict[str, Any]:
    p = store_path()
    if not os.path.exists(p):
        return {"version": 1, "deployments": []}
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:
        return {"version": 1, "deployments": []}
    data.setdefault("version", 1)
    data.setdefault("deployments", [])
    return data


def _write(data: Dict[str, Any]) -> None:
    p = store_path()
    d = os.path.dirname(p) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".deployments-", dir=d)
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


def from_apply(result: Dict[str, Any], *, tenant_label: str, packs: List[str], options: Dict[str, Any],
               channel_targets: Optional[Dict[str, Any]] = None, by: str = "") -> Optional[Dict[str, Any]]:
    """Build a record from an apply() result. None when nothing was created."""
    created: List[Dict[str, Any]] = []
    other: List[Dict[str, Any]] = []
    for r in result.get("results") or []:
        entry = {"kind": r.get("kind"), "name": r.get("name"), "id": r.get("id"), "channel": r.get("channel"),
                 "parent_id": r.get("parent_id"), "status": r.get("status")}
        if r.get("status") == "created" and r.get("id") is not None and r.get("kind") in UNDOABLE_KINDS:
            created.append(entry)
        elif r.get("status") in ("restored", "modified", "reused"):
            other.append(entry)
    if not created:
        return None
    return {
        "id": f"dep-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}",
        "at": _now(),
        "tenant_label": tenant_label,
        "by": by or "",          # the assessor's name, nothing else about who signed in
        "packs": list(packs),
        "options": dict(options or {}),
        "channel_targets": dict(channel_targets or {}),
        "status": result.get("status"),
        "created": created,
        "other": other,
        "undone_at": None,
        "undo": None,
    }


def add(record: Dict[str, Any]) -> Dict[str, Any]:
    data = _read()
    data["deployments"].append(record)
    data["deployments"] = data["deployments"][-LIMIT:]
    _write(data)
    return record


def list_all(tenant_label: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = list(_read()["deployments"])
    if tenant_label:
        rows = [r for r in rows if r.get("tenant_label") == tenant_label]
    rows.sort(key=lambda r: r.get("at") or "", reverse=True)
    return [summary(r) for r in rows]


def get(dep_id: str) -> Optional[Dict[str, Any]]:
    for r in _read()["deployments"]:
        if r.get("id") == dep_id:
            return r
    return None


def summary(r: Dict[str, Any]) -> Dict[str, Any]:
    created = r.get("created") or []
    remaining = [c for c in created if not c.get("undone")]
    by_kind: Dict[str, int] = {}
    for c in created:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
    return {
        "id": r["id"], "at": r.get("at"), "tenant_label": r.get("tenant_label"), "by": r.get("by") or "", "packs": r.get("packs") or [],
        "channel_targets": r.get("channel_targets") or {}, "status": r.get("status"),
        "created": len(created), "created_by_kind": by_kind, "remaining": len(remaining),
        "undone_at": r.get("undone_at"), "undo": r.get("undo"),
        "items": created,
    }


def mark_undo(dep_id: str, results: List[Dict[str, Any]], *, complete: bool) -> Optional[Dict[str, Any]]:
    """Store the outcome of an undo: each created item that was deleted is
    flagged so a second undo only retries what is left."""
    data = _read()
    for r in data["deployments"]:
        if r.get("id") != dep_id:
            continue
        deleted = {(x.get("kind"), str(x.get("id"))) for x in results if x.get("status") in ("deleted", "gone")}
        for c in r.get("created") or []:
            if (c.get("kind"), str(c.get("id"))) in deleted:
                c["undone"] = True
        r["undo"] = {"at": _now(), "results": results, "complete": complete}
        if complete:
            r["undone_at"] = _now()
        _write(data)
        return r
    return None
