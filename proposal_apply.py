"""Continuous evaluation, phase 3: apply an approved proposal to the tenant.

A proposal (proposals.py) names one change to one or more rules: a field
(`action`, `state`, `zscaler_incident_receiver`), the value it had when
the evidence was gathered (`from`) and the value to set (`to`). Applying
it goes through the same door as a deployment: the server's write gate,
a preview that re-reads the rule and refuses when the tenant moved since
the proposal was raised, the update, a read-back that proves the field
now holds the value, and a recorded way back. Rolling back replays the
same steps with the previous value. Every step is written to audit.log
and to the proposal's history.

Nothing here activates the change: ZIA keeps it pending until an admin
clicks Activate in the portal, the same as a deployment.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pack_channels as pc
import proposals

# Keys a rule carries when read that the API does not take back on update.
_READ_ONLY = {"id", "last_modified_time", "last_modified_by", "created_by", "modified_by", "modified_time",
              "lastModifiedTime", "lastModifiedBy", "createdBy", "modifiedBy", "modifiedTime", "access_control", "accessControl",
              "parent_rule", "parentRule", "sub_rules", "subRules"}
# Fields a proposal may change, and how a value is normalised for comparison.
FIELDS = {"action": lambda v: str(v or "").upper(), "state": lambda v: str(v or "").upper(),
          "zscaler_incident_receiver": lambda v: bool(v) if v is not None else None}
_CAMEL = {"zscaler_incident_receiver": "zscalerIncidentReceiver"}


def _svc(client, channel: str):
    zia = getattr(client, "zia", client)
    spec = pc.CHANNELS.get(channel)
    if not spec:
        raise ValueError(f"unknown channel '{channel}'")
    svc = getattr(zia, spec["service"], None)
    if svc is None:
        raise ValueError(f"the API client has no {pc.label(channel)} service")
    return zia, svc


def _list(svc) -> Tuple[List[Any], Optional[str]]:
    lister = getattr(svc, "list_all_rules", None) or getattr(svc, "list_rules", None)
    if lister is None:
        return [], "the service cannot list rules"
    try:
        data, err = pc._nx(lister())
    except Exception as e:  # noqa: BLE001
        return [], str(e)
    return list(data or []), (str(err) if err else None)


def read_rule(client, channel: str, *, rule_id: Any = None, name: str = "") -> Tuple[Optional[Any], Optional[str]]:
    """The tenant's rule, by id first, then by name. (object, error)."""
    _zia, svc = _svc(client, channel)
    rows, err = _list(svc)
    if err and not rows:
        return None, f"could not read {pc.label(channel)} rules: {err}"
    for r in rows:
        if rule_id is not None and str(pc._field(r, "id")) == str(rule_id):
            return r, None
    for r in rows:
        if name and str(pc._field(r, "name") or "") == name:
            return r, None
    return None, f"{pc.label(channel)} rule {name or rule_id!r} no longer exists in the tenant"


def current_value(rule: Any, field: str) -> Any:
    v = pc._field(rule, field, _CAMEL.get(field, field))
    return FIELDS[field](v) if field in FIELDS else v


def _body_from(rule: Any) -> Dict[str, Any]:
    if hasattr(rule, "as_dict"):
        d = dict(rule.as_dict())
    elif isinstance(rule, dict):
        d = dict(rule)
    else:
        d = {k: v for k, v in vars(rule).items()}
    return {k: v for k, v in d.items() if k not in _READ_ONLY and not str(k).startswith("_") and v is not None}


def _targets(p: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The rules a proposal touches: one (rule_id / name) or several (names)."""
    c = p.get("change") or {}
    channel = c.get("channel") or p.get("channel") or pc.WEB
    if c.get("rules"):
        return [{"channel": channel, "name": n, "rule_id": None} for n in c["rules"]]
    return [{"channel": channel, "name": p.get("rule") or "", "rule_id": c.get("rule_id")}]


def preview(client, tenant: str, pid: str, *, direction: str = "apply") -> Dict[str, Any]:
    """Re-read every rule the proposal touches and say what would change.
    direction: apply (change.to) or rollback (the recorded before value)."""
    p = proposals.get(tenant, pid)
    if not p:
        raise ValueError("proposal not found")
    c = p.get("change") or {}
    if c.get("apply") != "rule" or c.get("field") not in FIELDS:
        raise ValueError("this proposal is made in the ZIA portal, not from here (the app applies rule action, state and incident forwarding only)")
    field = c["field"]
    norm = FIELDS[field]
    steps: List[Dict[str, Any]] = []
    ok = True
    for t in _targets(p):
        rule, err = read_rule(client, t["channel"], rule_id=t["rule_id"], name=t["name"])
        row: Dict[str, Any] = {"channel": t["channel"], "channel_label": pc.label(t["channel"]), "name": t["name"] or (pc._field(rule, "name") if rule else ""),
                               "rule_id": pc._field(rule, "id") if rule else t["rule_id"], "field": field}
        if err:
            row.update({"ok": False, "why": err})
            ok = False
            steps.append(row)
            continue
        now = current_value(rule, field)
        if direction == "apply":
            want = norm(c.get("to"))
            expected = norm(c.get("from")) if c.get("from") is not None else None
            row.update({"current": now, "to": want, "expected": expected})
            if now == want:
                row.update({"ok": True, "noop": True, "why": f"{field} is already {want}"})
            elif expected is not None and now != expected:
                row.update({"ok": False, "why": f"{field} is {now} in the tenant, not {expected} as when the proposal was raised; refresh FP/TP Detection Ratio and decide again"})
                ok = False
            else:
                row.update({"ok": True})
        else:
            before = ((p.get("applied") or {}).get("before") or {}).get(str(row["rule_id"])) if p.get("applied") else None
            want = norm(before) if before is not None else norm((p.get("rollback") or {}).get("to"))
            row.update({"current": now, "to": want})
            if want is None:
                row.update({"ok": False, "why": "no recorded value to roll back to"})
                ok = False
            elif now == want:
                row.update({"ok": True, "noop": True, "why": f"{field} is already {want}"})
            else:
                row.update({"ok": True})
        steps.append(row)
    return {"proposal": {k: p.get(k) for k in ("id", "kind", "label", "title", "status", "gate", "expected_effect", "rollback")},
            "direction": direction, "field": field, "ok": ok, "steps": steps,
            "changes": sum(1 for s in steps if s.get("ok") and not s.get("noop")),
            "note": "Nothing is activated by the app: after the change, an admin activates in the ZIA Admin Portal."}


def _set_field(client, channel: str, rule: Any, field: str, value: Any) -> Tuple[Optional[Any], Optional[str]]:
    zia, _svc_ = _svc(client, channel)
    body = _body_from(rule)
    body[field] = value
    body.pop(_CAMEL.get(field, ""), None)
    # The same shared path as a pack deploy: retries, normalised outcome.
    import pack_ops as ops
    out = ops.update(zia, "policy", pc._field(rule, "id"), body, channel=channel, name=str(pc._field(rule, "name", default="") or ""))
    if not out.ok:
        return None, out.as_error()
    return out.data, None


def _execute(client, tenant: str, pid: str, *, direction: str, writes_enabled: Optional[bool], by: str, log=None) -> Dict[str, Any]:
    # The change's writes draw on the client's own tenant's ZIA rate limits.
    import zia_rate
    with zia_rate.using_client(client):
        return _execute_keyed(client, tenant, pid, direction=direction, writes_enabled=writes_enabled, by=by, log=log)


def _execute_keyed(client, tenant: str, pid: str, *, direction: str, writes_enabled: Optional[bool], by: str, log=None) -> Dict[str, Any]:
    if writes_enabled is False:
        raise PermissionError("write mode is off: enable it in Deploy Policy Packs or start the server with writes enabled")
    pv = preview(client, tenant, pid, direction=direction)
    p = proposals.get(tenant, pid) or {}
    if direction == "apply" and p.get("status") != "approved":
        raise ValueError(f"the proposal is {p.get('status')}, not approved; approve it in the queue first")
    if direction == "rollback" and p.get("status") not in ("applied", "failed"):
        raise ValueError(f"the proposal is {p.get('status')}; only an applied change can be rolled back")
    if not pv["ok"]:
        bad = "; ".join(s.get("why", "") for s in pv["steps"] if not s.get("ok"))
        proposals.set_status(tenant, pid, p.get("status") or "approved", note=f"{direction} refused: {bad}", by=by)
        raise ValueError(f"{direction} refused: {bad}")
    field = pv["field"]
    results: List[Dict[str, Any]] = []
    before: Dict[str, Any] = {}
    failed = False
    for s in pv["steps"]:
        row = dict(s)
        if s.get("noop"):
            row["result"] = "unchanged"
            results.append(row)
            continue
        rule, err = read_rule(client, s["channel"], rule_id=s["rule_id"], name=s["name"])
        if err:
            row.update({"result": "failed", "why": err}); failed = True; results.append(row); continue
        before[str(s["rule_id"])] = current_value(rule, field)
        if log:
            log(f"{direction}: {pc.label(s['channel'])} rule '{s['name']}' {field} {row['current']} → {row['to']}")
        _data, err = _set_field(client, s["channel"], rule, field, s["to"])
        if err:
            row.update({"result": "failed", "why": err}); failed = True; results.append(row); continue
        # Read back: the tenant must now hold the value.
        again, err = read_rule(client, s["channel"], rule_id=s["rule_id"], name=s["name"])
        got = current_value(again, field) if again else None
        if err or got != s["to"]:
            row.update({"result": "failed", "why": err or f"read-back shows {field} = {got}, expected {s['to']}", "read_back": got}); failed = True
        else:
            row.update({"result": "changed", "read_back": got, "verified": True})
        results.append(row)
    changed = sum(1 for r in results if r.get("result") == "changed")
    status = ("failed" if failed else ("applied" if direction == "apply" else "rolled_back"))
    fields: Dict[str, Any] = {"by": by, "note": f"{direction}: {changed} rule(s) changed" + (", some failed" if failed else "")}
    if direction == "apply":
        prev = p.get("applied") or {}
        fields["applied"] = {"at": proposals._now(), "by": by, "field": field, "before": {**(prev.get("before") or {}), **before}, "results": results}
    else:
        fields["rolled_back"] = {"at": proposals._now(), "by": by, "field": field, "results": results}
    rec = proposals.set_status(tenant, pid, status, **fields)
    try:
        import audit
        audit.record(f"proposal_{direction}", tenant=proposals.tenant_key(tenant), proposal=pid, kind=p.get("kind"), target=p.get("target"),
                     by=by, status=status, changed=changed, failed=failed)
    except Exception as e:  # noqa: BLE001 - the change is made; the lost audit line is reported loudly
        import audit
        audit.report_failure(f"the {direction} of proposal {pid}", e)
    return {"ok": not failed, "status": status, "field": field, "results": results, "changed": changed, "proposal": rec,
            "activation": "Pending in ZIA until an admin clicks Activate in the ZIA Admin Portal."}


def apply(client, tenant: str, pid: str, *, writes_enabled: Optional[bool] = None, by: str = "", log=None) -> Dict[str, Any]:
    return _execute(client, tenant, pid, direction="apply", writes_enabled=writes_enabled, by=by, log=log)


def rollback(client, tenant: str, pid: str, *, writes_enabled: Optional[bool] = None, by: str = "", log=None) -> Dict[str, Any]:
    return _execute(client, tenant, pid, direction="rollback", writes_enabled=writes_enabled, by=by, log=log)
