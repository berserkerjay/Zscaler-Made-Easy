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
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import safe_files

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
LIMIT = 200
UNDOABLE_KINDS = ("policy", "app_group", "engine", "dictionary")
# One read-modify-write of the store at a time: two runs finishing together
# (a deploy and an undo, two background jobs) must not lose a record.
_LOCK = threading.RLock()


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
    # A file of another shape (hand-edited, truncated, an older layout) is
    # read as far as it is records, never as a crash of every page using it.
    if not isinstance(data, dict):
        return {"version": 1, "deployments": []}
    data.setdefault("version", 1)
    for key in ("deployments", "operations"):
        rows = data.get(key)
        if key in data or key == "deployments":
            data[key] = [r for r in rows if isinstance(r, dict) and r.get("id") is not None] if isinstance(rows, list) else []
    return data


def _write(data: Dict[str, Any]) -> None:
    p = store_path()
    d = os.path.dirname(p) or "."
    safe_files.private_makedirs(d)
    fd, tmp = tempfile.mkstemp(prefix=".deployments-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        _keep_last_good(p)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def from_apply(result: Dict[str, Any], *, tenant_label: str, packs: List[str], options: Dict[str, Any],
               channel_targets: Optional[Dict[str, Any]] = None, by: str = "", tenant_key: str = "", tenant_fp: str = "") -> Optional[Dict[str, Any]]:
    """Build a record from an apply() result. None when nothing was created."""
    created: List[Dict[str, Any]] = []
    other: List[Dict[str, Any]] = []
    for r in result.get("results") or []:
        entry = {"kind": r.get("kind"), "name": r.get("name"), "id": r.get("id"), "channel": r.get("channel"),
                 "parent_id": r.get("parent_id"), "status": r.get("status")}
        if r.get("status") == "created" and r.get("id") is not None and r.get("kind") in UNDOABLE_KINDS:
            created.append(entry)
        elif r.get("status") in ("restored", "modified", "reused"):
            if r.get("kind") == "tweak":
                # what Undo needs to put an existing dictionary's confidence back
                entry.update({k: r.get(k) for k in ("dictionary", "field", "before", "after")})
            other.append(entry)
    if not created:
        return None
    rec = {
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
    # What tells the tenant apart, never shown (summary leaves both out):
    # a classic-API tenant's keyed fingerprint (tenant_fingerprint: every
    # classic-API tenant on a cloud shares the label 'classic API (cloud)',
    # and the fingerprint names neither the admin login nor the domain),
    # or a OneAPI tenant's opaque rate key (zia_rate.key_for).
    if tenant_fp:
        rec["tenant_fp"] = str(tenant_fp)
    elif tenant_key:
        rec["tenant_key"] = str(tenant_key)
    return rec


def add(record: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(record, dict) or not record.get("id"):
        raise ValueError("not a deployment record")
    with _LOCK:
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
    created = [c for c in (r.get("created") or []) if isinstance(c, dict)]
    remaining = [c for c in created if not c.get("undone")]
    by_kind: Dict[str, int] = {}
    for c in created:
        by_kind[str(c.get("kind"))] = by_kind.get(str(c.get("kind")), 0) + 1
    return {
        "id": r.get("id"), "at": r.get("at"), "tenant_label": r.get("tenant_label"), "by": r.get("by") or "", "packs": r.get("packs") or [],
        "channel_targets": r.get("channel_targets") or {}, "status": r.get("status"),
        "created": len(created), "created_by_kind": by_kind, "remaining": len(remaining),
        "undone_at": r.get("undone_at"), "undo": r.get("undo"),
        "items": created,
    }


def mark_undo(dep_id: str, results: List[Dict[str, Any]], *, complete: bool) -> Optional[Dict[str, Any]]:
    """Store the outcome of an undo: each created item that was deleted is
    flagged so a second undo only retries what is left."""
    with _LOCK:
        data = _read()
        for r in data["deployments"]:
            if r.get("id") != dep_id:
                continue
            deleted = {(x.get("kind"), str(x.get("id"))) for x in results if isinstance(x, dict) and x.get("status") in ("deleted", "gone")}
            for c in r.get("created") or []:
                if isinstance(c, dict) and (c.get("kind"), str(c.get("id"))) in deleted:
                    c["undone"] = True
            r["undo"] = {"at": _now(), "results": results, "complete": complete}
            if complete:
                r["undone_at"] = _now()
            _write(data)
            return r
    return None


# ---------------------------------------------------------------------------
# Administrative operations (admin_ops: Bulk changes)
# ---------------------------------------------------------------------------
#
# A bulk change (rule state or order, custom URL categories, ZPA application
# segments) is not a deployment: it creates nothing a pack undo could
# delete. Its record sits beside the deployments in the same file, under
# "operations", written with the same helpers (owner-only, atomic). The
# record keeps what each item was before and after and the operation that
# reverses what was applied; an Undo previews that operation and runs it
# through the same preview, confirmation and conflict guard as any other.

OPERATION_LIMIT = 200


def add_operation(record: Dict[str, Any]) -> Dict[str, Any]:
    with _LOCK:
        data = _read()
        ops = data.setdefault("operations", [])
        ops.append(record)
        data["operations"] = ops[-OPERATION_LIMIT:]
        _write(data)
    return record


def get_operation(op_id: str) -> Optional[Dict[str, Any]]:
    for r in _read().get("operations") or []:
        if r.get("id") == op_id:
            return r
    return None


def operation_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    return {k: r.get(k) for k in ("id", "at", "tenant_label", "by", "actor", "type", "title", "status", "plan_hash", "counts",
                                  "undo_of", "undone_by", "undone_at", "product")} | {"can_undo": bool(r.get("inverse")) and not r.get("undone_by")}


def list_operations(tenant_label: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = list(_read().get("operations") or [])
    if tenant_label:
        rows = [r for r in rows if r.get("tenant_label") == tenant_label]
    rows.sort(key=lambda r: r.get("at") or "", reverse=True)
    return [operation_summary(r) for r in rows]


def mark_operation_undone(op_id: str, undo_id: str, *, complete: bool) -> Optional[Dict[str, Any]]:
    """The operation `op_id` was reversed by the operation `undo_id` (in full
    when `complete`; otherwise the undo is recorded and Undo stays offered)."""
    with _LOCK:
        data = _read()
        for r in data.get("operations") or []:
            if r.get("id") != op_id:
                continue
            r.setdefault("undo_runs", []).append({"at": _now(), "operation": undo_id, "complete": complete})
            if complete:
                r["undone_by"], r["undone_at"] = undo_id, _now()
            _write(data)
            return r
    return None


def new_operation_id() -> str:
    return f"op-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"


def _keep_last_good(path: str) -> None:
    """The store as it was, kept as a last-good copy (self_heal) before it is replaced."""
    try:
        import self_heal
        self_heal.keep_last_good(path)
    except Exception:  # noqa: BLE001 - never stops a write
        pass
