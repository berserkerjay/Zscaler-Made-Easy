"""Activate pending ZIA changes, on the Bulk changes engine (admin_ops plugin).

One operation type on /report/operations, under "Day-to-day admin":

  zia_activation  ZIA keeps every saved change pending until it is
                  activated. The plan reads ZIA's activation status and lists
                  it: PENDING can be activated, with "ACTIVATE" typed every
                  time; ACTIVE (nothing pending) and INPROGRESS (an
                  activation already running) are refused; a status that
                  cannot be read, or one this app does not know, is unknown
                  and nothing is planned (never taken for pending). There is
                  no Undo: an activation cannot be taken back, and the
                  preview says so.

The engine supplies the scope check before any read (any ZIA area ticked on
the Scope page), the plan hash and the re-plan before writing (activated
meanwhile, the hash differs and nothing is sent), write mode, the writer,
the named assessor, the typed confirmation, the record and the audit log
with the actor. This module re-reads the status right before the activation
and reads it back after. The plan activates as its own step
(activation_step), so the engine adds no second activation.

ZIA calls, verified against zscaler-sdk-python 1.11.3 (zia/activate.py,
ActivationAPI.status: GET /status; ActivationAPI.activate: POST
/status/activate; the Activation model has one field, status). They are sent
through pack_channels.activation_status / pack_channels.activate (the raw
request every policy pack deploy activates with, the same two paths), and
the activation through pack_ops.activate_once (ZIA's activation rate limit
waited out, Stop honoured).
ASSUMED (the SDK has no enumeration and this was not checked against a live
tenant): the status values ACTIVE, PENDING and INPROGRESS; which pending
changes an activation by this API client makes live (treated as every
change saved and not yet active, whoever saved it, so the preview warns so).
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional

import admin_ops as ao
import pack_channels as pc
import pack_ops as ops

TYPE = "zia_activation"
FAMILY = "zia_activation_status"
SCRIPT = "ops_zia_admin.js"
PHRASE = "ACTIVATE"
SETTLE_SECONDS = 45.0
# assumed: ZIA's activation status values (the SDK's Activation model has no enumeration).
PENDING, ACTIVE, INPROGRESS = "PENDING", "ACTIVE", "INPROGRESS"
KNOWN = (PENDING, ACTIVE, INPROGRESS)
ZIA_AREAS = ("dlp", "zia_extras")

NOT_IN_SCOPE = ("Not in scope: ZIA activation needs a ZIA area ticked on the Scope page (DLP or ZIA platform), so ZIA's activation "
                "status is not read.")
NO_UNDO = ("Cannot be undone: an activation makes the pending changes live for users at once, and ZIA has no way to take an "
           "activation back. Undo each change instead (its own Undo, then activate again).")
WHOSE = ("Activation makes every change saved in ZIA and not yet active live, whoever saved it (the ZIA Admin Portal, another "
         "tool or this app): check with the other admins first (assumed: the SDK does not say whose changes it activates).")
REFUSED_ACTIVE = "Nothing is pending: ZIA reports ACTIVE, so there is nothing to activate."
REFUSED_INPROGRESS = "An activation is already in progress in ZIA. Wait a minute, then preview again."
WHAT = ("ZIA keeps a saved change pending until it is activated. This activates what is pending; it reads ZIA's activation "
        "status first and refuses when nothing is pending.")

LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    given = set(scope.get("scopes") or [])
    return None if scope.get("policies") or given & set(ZIA_AREAS) else NOT_IN_SCOPE


def read_status(zia: Any) -> str:
    """ZIA's activation status, one of KNOWN; OperationError when it cannot be read or is not known (unknown, never pending)."""
    status, err = pc.activation_status(zia)
    if err:
        why = ao._read_halt(err) or str(err)[:200]
        raise ao.OperationError(f"ZIA's activation status could not be read ({why}), so it is unknown. Nothing was planned.")
    s = str(status or "").strip().upper()
    if s not in KNOWN:
        shown = "".join(ch for ch in s[:40] if ch.isprintable()) or "no status"
        raise ao.OperationError(f"ZIA answered an activation status this app does not know ('{shown}'), so it is unknown. "
                                "Nothing was planned; activate in the ZIA Admin Portal.")
    return s


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """ZIA's activation status for the form (read-only)."""
    say("Reading ZIA's activation status…")
    try:
        status = read_status(client.zia)
    except ao.OperationError as e:
        return {"status": "", "pending": False, "errors": {"activation_status": str(e)}, "note": WHAT, "no_undo": NO_UNDO, "whose": WHOSE}
    return {"status": status, "pending": status == PENDING, "errors": {}, "note": WHAT, "no_undo": NO_UNDO, "whose": WHOSE}


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    extra = sorted(k for k in spec if k != "type")
    if extra:
        raise ao.OperationError(f"An activation takes no settings ({', '.join(str(k)[:20] for k in extra[:3])} given).")
    return {"type": TYPE}


def _obj() -> Dict[str, Any]:
    return {"type": "zia_activation", "policy_label": "ZIA activation", "id": None, "name": "Pending ZIA changes"}


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    say("Reading ZIA's activation status…")
    status = read_status(client.zia)
    ao._check_stop(cancel)
    P: Dict[str, Any] = {"type": TYPE, "product": "zia", "title": "Activate pending ZIA changes", "spec": n, "items": [], "groups": [],
                         "warnings": [], "blockers": [], "activation_step": True, "undo_note": NO_UNDO,
                         "impact": [{"status": status, "detail": {PENDING: "ZIA reports changes saved and still pending: not live for users yet.",
                                                                  ACTIVE: "ZIA reports nothing pending.",
                                                                  INPROGRESS: "ZIA is activating already."}[status]}],
                         "notes": ["Reads GET /status, then sends POST /status/activate (SDK activate.status / activate.activate), "
                                   "then reads the status back.", NO_UNDO]}
    if status == PENDING:
        P["items"].append(ao._unit("activate", "activate", "zia_activation", _obj(), "status", PENDING, ACTIVE, value="pending",
                                   reason="makes every pending change live; cannot be undone"))
        P["groups"].append({"key": "activate", "handler": "zia_activate", "target": {"status": PENDING}})
        P["warnings"] = [NO_UNDO, WHOSE]
        P["confirm_always"] = PHRASE
        return P
    P["items"].append(ao._unit("activate", "activate", "zia_activation", _obj(), "status", status, ACTIVE, status="excluded",
                               reason="nothing is pending" if status == ACTIVE else "an activation is already in progress"))
    P["blockers"].append(REFUSED_ACTIVE if status == ACTIVE else REFUSED_INPROGRESS)
    return P


def h_activate(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Re-read the status; still PENDING, activate once (pack_ops.activate_once)."""
    try:
        now = read_status(run.zia)
    except ao.OperationError as e:
        halt = ao._read_halt(str(e))
        if halt:
            run.halt = halt
            run.mark(units, "skipped", f"not attempted: {halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the activation status again before activating: {e}"[:300])
            run.counts["failed"] += 1
        return
    if now != PENDING:
        run.mark(units, "conflict", f"ZIA now reports {now} (changed since the preview); nothing was sent")
        run.counts["skipped"] += len(units)
        return
    run.log("Activating the pending ZIA changes…")
    act = ops.activate_once(run.zia, run.log)
    run.p["activation_step_result"] = {k: act.get(k) for k in ("activated", "status", "error")}
    if act.get("activated"):
        run.mark(units, "applied", "activated")
        run.counts["modified"] += 1
        run.log("[ZIA] pending changes activated")
    elif act.get("stopped"):
        run.mark(units, "skipped", f"not sent: {ops.ACTIVATION_STOPPED}")
    else:
        run.mark(units, "failed", "", error=f"ZIA did not activate: {str(act.get('error') or 'no reason given')[:200]}. The changes stay pending.")
        run.counts["failed"] += 1


HANDLERS = {"zia_activate": h_activate}


def verify(run: Any) -> Dict[str, Any]:
    """Read the status back (waiting up to SETTLE_SECONDS while ZIA activates): ACTIVE confirms it."""
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    units = [u for u in run.p["items"] if u["status"] == "applied"]
    if not units:
        return out
    status = pc.wait_active(run.zia, SETTLE_SECONDS, run.log)
    s = str(status or "").upper()
    out["checked"] = len(units)
    if s == ACTIVE:
        out["confirmed"] = len(units)
        ok: Optional[bool] = True
    elif s == INPROGRESS:
        out["checked"] = 0
        out["unread"].append("ZIA is still activating; read the status again in a minute.")
        ok = None
    elif not s:
        out["checked"] = 0
        out["unread"].append("ZIA's activation status could not be read back.")
        ok = None
    else:
        out["mismatched"].append(f"ZIA still reports {s[:40]} after the activation.")
        ok = False
    for u in units:
        u["verified"] = ok
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """None: an activation cannot be taken back (the preview says so)."""
    return None


ao.register(TYPE, family=FAMILY, product="zia", label="Activate pending ZIA changes", plan=plan, read_objects=read_objects,
            in_scope=in_scope, handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT, group="Day-to-day admin",
            hint=("Reads ZIA's activation status and activates what is pending, with ACTIVATE typed. Refused when nothing is pending. "
                  "No Undo: an activation cannot be taken back. Needs DLP or ZIA platform ticked on the Scope page."))
