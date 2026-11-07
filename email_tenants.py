"""One answer to "which email tenants are onboarded?".

Pure and read-only: it takes rows that were already read (active SaaS
tenants, ZIA's own appType=EMAIL list, and the Email DLP rules) and returns
the onboarded email tenants. Check D.1 and the pack deploy both use it, so
they cannot disagree.

Sources, in order of precedence for `found_by`:
  - "Zscaler email list": the appType=EMAIL list (Exchange, Gmail, SEG).
  - "application name": an active tenant whose application name says email.
  - "used by Email DLP rule <name>": a tenant an existing Email DLP rule is
    scoped to (on a live tenant casbTenant/lite listed only SharePoint while
    an Email DLP rule used the Exchange tenant).
Deleted tenants (tenantDeleted) are dropped from every source.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

BY_LIST = "Zscaler email list"
BY_NAME = "application name"
BY_RULE = "used by Email DLP rule"


def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    """A field from a dict or SDK object, trying each spelling (camelCase and snake_case)."""
    if obj is None:
        return default
    d = obj
    if not isinstance(obj, dict):
        for fn in ("as_dict", "to_dict"):
            f = getattr(obj, fn, None)
            if callable(f):
                try:
                    d = f()
                except Exception:  # noqa: BLE001
                    d = None
                break
    if isinstance(d, dict):
        for k in keys:
            if d.get(k) is not None:
                return d[k]
    for k in keys:
        v = getattr(obj, k, None)
        if v is not None:
            return v
    return default


def _truthy(v: Any) -> bool:
    return v.strip().lower() in ("true", "1", "yes") if isinstance(v, str) else bool(v)


def is_email_app(app: str) -> bool:
    """Does an application name say email? One keyword list, kept in pack_channels."""
    import pack_channels as pc  # at call time: pack_channels imports this module
    return pc._is_email_tenant({"app": str(app or "").upper()})


def _row(t: Any) -> Optional[Dict[str, Any]]:
    tid = _get(t, "tenant_id", "tenantId", "id")
    if tid is None or _truthy(_get(t, "tenant_deleted", "tenantDeleted")):
        return None
    name = str(_get(t, "tenant_name", "tenantName", "name", default="") or "").strip()
    app = str(_get(t, "saas_application", "saasApplication", "app", default="") or "").upper()
    return {"id": tid, "name": name or str(tid), "app": app}


def onboarded_email_tenants(active_tenants: Iterable[Any] = (), email_list: Iterable[Any] = (),
                            email_rules: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    """The onboarded email tenants, each {id, name, app, found_by}."""
    out: Dict[str, Dict[str, Any]] = {}

    def add(row: Optional[Dict[str, Any]], how: str) -> None:
        if row is not None and str(row["id"]) not in out:
            out[str(row["id"])] = dict(row, found_by=how)

    deleted = set()
    for t in list(active_tenants or []) + list(email_list or []):
        if _truthy(_get(t, "tenant_deleted", "tenantDeleted")):
            tid = _get(t, "tenant_id", "tenantId", "id")
            if tid is not None:
                deleted.add(str(tid))
    for t in email_list or []:
        add(_row(t), BY_LIST)
    for t in active_tenants or []:
        r = _row(t)
        if r is not None and is_email_app(r["app"]):
            add(r, BY_NAME)
    for rule in email_rules or []:
        rname = str(_get(rule, "name", default="") or "").strip()
        for t in (_get(rule, "email_tenants", "emailTenants", default=[]) or []):
            r = _row(t if isinstance(t, dict) or hasattr(t, "__dict__") else {"id": t})
            if r is not None and str(r["id"]) not in deleted:
                r["app"] = r["app"] or "EMAIL"
                add(r, f"{BY_RULE} {rname}".rstrip())
    return [t for t in out.values() if str(t["id"]) not in deleted]
