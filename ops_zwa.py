"""Close Workflow Automation incidents as false positives, on the Bulk
changes engine (admin_ops.register).

One operation type, opened from Detection health (a noisy rule or a noisy
destination) or with a list of incident ids:

  zwa_close_false_positives  close the chosen OPEN incidents with resolution
                             code FALSE_POSITIVE, a resolution label and a
                             note that names the assessor who approved it
                             (zscaler/zwa/dlp_incidents.py incident_close),
                             then label each one with who closed it
                             (assign_labels).

Planned from the tenant as it is now (each incident is read again, metadata
only: its evidence is never read), previewed item by item, approved by its
plan hash, applied through the same four gates as every bulk change (write
mode, a writer, a named assessor and the typed phrase, asked whatever the
count), each incident read again right before its write (one that someone
closed or changed since the preview is a conflict, never overwritten), read
back, recorded in the audit log with the actor.

Undo: Workflow Automation has no API to reopen an incident. The inverse
records the reversal on each incident it closed (a label and a note naming
who reversed it, incident_notes and assign_labels) and says that the reopen
itself is a step in the Workflow Automation portal; it is previewed and
confirmed like any other change.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import admin_ops as ao
import pack_ops as ops
import zwa_incidents as zi

TYPE = "zwa_close_false_positives"
FAMILY = "zwa_incidents"
HANDLER = "zwa_incident_step"
MAX_INCIDENTS = 100
NOTE_MAX = 300
RESOLUTION_CODE = "FALSE_POSITIVE"         # the one value the SDK documents for incident_close
LABEL_KEY = "zme-fp-close"
CLOSED_BY_KEY = "zme-closed-by"
NO_REOPEN = ("Workflow Automation has no API to reopen an incident: Undo records the reversal on each incident (a label and a note "
             "naming who reversed it) and the reopen itself is done in the Workflow Automation portal.")
_SAFE_NOTE = re.compile(r"[^\w .,;:()'/@+-]")


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """DLP ticked and Workflow Automation marked Zscaler on the Scope page."""
    import continuous_eval
    import dlp_analysis
    scopes = [str(x) for x in scope.get("scopes") or []]
    # As the Detection health read decides (dlp_analysis.channels): with DLP ticked, Workflow Automation is
    # required evidence and counts as Zscaler unless the Scope page marks it as another product.
    sc = continuous_eval.profile_scope({"scopes": scopes, "channels": dlp_analysis.channels(scope.get("channels") or {}, scopes)})
    if not sc["dlp"] or not sc["read_incidents"]:
        return ("Closing Workflow Automation incidents is not in scope: on the Scope page tick DLP and mark Workflow Automation as run "
                "on Zscaler. Nothing was read.")
    return None


def _note(raw: Any) -> str:
    """The operator's optional reason, as plain text (no markup, no control
    characters, capped)."""
    return _SAFE_NOTE.sub("", str(raw or ""))[:NOTE_MAX].strip()


def _ids(spec: Dict[str, Any]) -> List[str]:
    raw = spec.get("incident_ids")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ao.OperationError("incident_ids must be a list of incident ids.")
    if len(raw) > MAX_INCIDENTS:
        raise ao.OperationError(f"Close at most {MAX_INCIDENTS} incidents at once.")
    out: List[str] = []
    for x in raw:
        try:
            iid = zi.clean_id(x)
        except ValueError as e:
            raise ao.OperationError(str(e)) from None
        if iid not in out:
            out.append(iid)
    return out


def _dlp(client: Any) -> Any:
    try:
        return zi.api(client)
    except zi.Unavailable as e:
        raise ao.OperationError(str(e)) from None


def _unit(P: Dict[str, Any], key: str, iid: str, *, status: str = "change", reason: str = "", before: str = "", after: str = "",
          field: str = "status", step: Optional[Dict[str, Any]] = None) -> None:
    obj = {"type": "DLP incident", "kind": "zwa_incident", "name": iid, "id": iid}
    P["items"].append(ao._unit(key, f"g_{key}", "zwa_incident", obj, field, before, after, status=status, reason=reason))
    if status == "change" and step is not None:
        P["groups"].append({"key": f"g_{key}", "handler": HANDLER, "target": dict(step, id=iid, key=key)})


def _new(title: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": TYPE, "product": "zwa", "title": title, "spec": spec, "items": [], "groups": [], "warnings": [], "blockers": [],
            "notes": [], "impact": [], "apply_note": "Workflow Automation applies each change as it is saved; there is no activation step."}


def _done(P: Dict[str, Any], verb: str) -> Dict[str, Any]:
    n = sum(1 for u in P["items"] if u["status"] == "change")
    P["confirm_always"] = f"{verb} {n} INCIDENT{'' if n == 1 else 'S'}" if n else ""
    return P


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    if spec.get("action") == "undo":
        return _plan_undo(client, spec, say, cancel)
    ids = _ids(spec)
    rule = str(spec.get("rule") or "").strip()[:200]
    host = str(spec.get("host") or "").strip().lower()[:253]
    try:
        days = max(1, min(int(spec.get("days") or 30), 180))
    except (TypeError, ValueError):
        raise ao.OperationError("days must be a whole number from 1 to 180.") from None
    if not ids and not rule and not host:
        raise ao.OperationError("Name the incidents to close: incident ids, or a rule or destination host from Detection health.")
    _dlp(client)
    note = _note(spec.get("note"))
    what = (f"rule {rule}" if rule else "") + (" and " if rule and host else "") + (f"destination {host}" if host else "")
    P = _new(f"Close {'the chosen' if ids else 'the open'} DLP incidents as false positives" + (f" ({what})" if what and not ids else ""), spec)
    if not ids:
        say(f"Reading the Workflow Automation incidents of the last {days} day(s) for {what} (metadata only)…")
        found, errors = zi.open_incidents(client, days=days, rule=rule, host=host, limit=MAX_INCIDENTS)
        if errors and not found:
            P["blockers"].append("The incidents could not be read: " + "; ".join(zi.text(e) for e in errors[:2]))
        elif errors:
            P["warnings"].append("Only part of the incidents was read: " + zi.text(errors[0]))
        ids = [f["id"] for f in found]
        if not ids and not P["blockers"]:
            P["warnings"].append(f"No open incident of {what} in the last {days} day(s).")
    say(f"Reading {len(ids)} incident(s) again, one by one (metadata only; the evidence is never read)…")
    for i, iid in enumerate(ids):
        ao._check_stop(cancel)
        key = f"i{i}"
        summ, err = zi.details(client, iid)
        if summ is None:
            halt = ao._read_halt(err)
            if halt:
                P["blockers"].append(f"Reading the incidents stopped: {halt}")
                break
            _unit(P, key, iid, status="excluded", reason="not found" if err == "not found" else f"could not be read: {zi.text(err, 120)}")
            continue
        status = summ["status"] or "OPEN"
        if not zi.is_open(summ):
            _unit(P, key, iid, status="noop", reason=f"already {status.lower()}" + (f" ({summ['resolution']})" if summ["resolution"] else ""),
                  before=status, after="unchanged")
            continue
        rules = ", ".join(summ["rules"][:2]) or "no rule named"
        _unit(P, key, iid, before=status, after=f"CLOSED ({RESOLUTION_CODE})",
              step={"op": "close", "expect": status, "rules": rules, "note": note})
    n = sum(1 for u in P["items"] if u["status"] == "change")
    if n:
        P["impact"].append(f"{n} incident(s) leave the analysts' open queue, closed as false positives; the rule that raised them is unchanged.")
    P["notes"].append("Each closed incident gets a note naming the assessor who approved this change, and a label with who closed it.")
    P["notes"].append("Only incident metadata is read; the evidence (the content that matched) is never fetched.")
    P["warnings"].append(NO_REOPEN)
    return _done(P, "CLOSE")


def _plan_undo(client: Any, spec: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    steps = spec.get("incidents")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_INCIDENTS:
        raise ao.OperationError(f"An Undo lists 1 to {MAX_INCIDENTS} incidents.")
    ids = _ids({"incident_ids": [s.get("id") if isinstance(s, dict) else s for s in steps]})
    _dlp(client)
    P = _new(f"Undo: record the reversal of {len(ids)} false-positive closure(s)", spec)
    say("Reading each incident the Undo touches (metadata only)…")
    for i, iid in enumerate(ids):
        ao._check_stop(cancel)
        key = f"u{i}"
        summ, err = zi.details(client, iid)
        if summ is None:
            _unit(P, key, iid, status="excluded", field="reversal record", reason="not found" if err == "not found" else f"could not be read: {zi.text(err, 120)}")
        elif zi.is_open(summ):
            _unit(P, key, iid, status="noop", field="reversal record", reason="already open again", before=summ["status"], after="unchanged")
        elif str(summ["closed_code"] or summ["resolution"]).upper() != RESOLUTION_CODE:
            _unit(P, key, iid, status="excluded", field="reversal record",
                  reason=f"closed since with another resolution ({summ['closed_code'] or summ['resolution'] or 'none'}): left as it is")
        else:
            _unit(P, key, iid, field="reversal record", before=f"CLOSED ({RESOLUTION_CODE})",
                  after=f"label {LABEL_KEY}=reverted and a note naming you; reopen it in the portal",
                  step={"op": "revert", "expect": summ["status"]})
    P["warnings"].append(NO_REOPEN)
    return _done(P, "RECORD")


def _not_read(run: Any, units: List[Dict[str, Any]], err: Optional[str]) -> None:
    halt = ao._read_halt(err)
    if halt:
        run.halt = halt
        run.mark(units, "skipped", f"not attempted: {halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read the incident again before the change: {zi.text(err)}")
        run.counts["failed"] += 1


def _actor(run: Any) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(run.assessor or "the assessor"))[:120]


def _h_step(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    iid, u = t["id"], units[0]
    dlp = zi.api(run.client)
    summ, err = zi.details(run.client, iid)
    if summ is None:
        _not_read(run, units, err)
        return
    if summ["status"] != t["expect"]:
        run.mark(units, "conflict", f"changed in Workflow Automation since the preview (status is {summ['status'] or 'empty'} now); left as it is")
        return
    who = _actor(run)
    if t["op"] == "close":
        extra = f" Reason: {t['note']}." if t.get("note") else ""
        note = (f"Closed as a false positive by {who} with Zscaler Made Easy (Bulk changes, from Detection health; rule: {t.get('rules')}).{extra}")[:1000]
        out = ops.update(dlp, "zwa_incident", iid, {"resolution_code": RESOLUTION_CODE, "resolution_label": {"key": LABEL_KEY, "value": "false-positive"},
                                                    "notes": note}, name=iid, log=run.log, action="close")
        if run.outcome(units, out, "update"):
            lab = ops.update(dlp, "zwa_incident", iid, {"labels": [{"key": CLOSED_BY_KEY, "value": who[:60]}]}, name=iid, log=run.log, action="labels")
            if not lab.ok:
                run.log(f"{iid}: closed, but the '{CLOSED_BY_KEY}' label was not added ({zi.text(lab.error, 120)}); the note names {who}.")
            u["check"] = {"status": "CLOSED"}
            u["undo"] = {"id": iid}
    else:
        note = (f"Closure as a false positive reversed by {who} with Zscaler Made Easy (Undo). Reopen this incident in the Workflow "
                "Automation portal: the API cannot reopen it.")
        out = ops.update(dlp, "zwa_incident", iid, {"notes": note}, name=iid, log=run.log, action="notes")
        if run.outcome(units, out, "update"):
            lab = ops.update(dlp, "zwa_incident", iid, {"labels": [{"key": LABEL_KEY, "value": "reverted"}]}, name=iid, log=run.log, action="labels")
            if not lab.ok:
                run.log(f"{iid}: the note was added, but the '{LABEL_KEY}=reverted' label was not ({zi.text(lab.error, 120)}).")
            u["check"] = {"label": f"{LABEL_KEY}=reverted"} if lab.ok else {}


def _verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for u in run.p["items"]:
        if u["status"] != "applied":
            continue
        out["checked"] += 1
        iid = u["object"]["id"]
        summ, err = zi.details(run.client, iid)
        if summ is None:
            out["unread"].append(f"{iid}: {zi.text(err, 120)}")
            u["verified"] = None
            continue
        want = u.get("check") or {}
        if "status" in want:
            ok = not zi.is_open(summ)
        elif "label" in want:
            k, v = want["label"].split("=", 1)
            ok = any(lab.get("key") == k and lab.get("value") == v for lab in summ["labels"])
        else:
            ok = True
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{iid}: not as written when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if (result.get("spec") or {}).get("action") == "undo":
        return None
    steps = [u["undo"] for u in result.get("items") or [] if u.get("status") == "applied" and u.get("undo")]
    return {"type": TYPE, "action": "undo", "incidents": steps} if steps else None


def read_objects(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """The open incidents of the last 30 days the page can pick from (metadata only)."""
    _dlp(client)
    found, errors = zi.open_incidents(client, days=30, limit=MAX_INCIDENTS, log=say)
    return {"incidents": found, "errors": [zi.text(e) for e in errors[:3]], "max": MAX_INCIDENTS, "no_reopen": NO_REOPEN,
            "verified": list(zi.VERIFIED), "assumed": list(zi.ASSUMED)}


ao.register(TYPE, family=FAMILY, product="zwa", label="Close DLP incidents as false positives",
            hint="Close the open Workflow Automation incidents of a noisy rule or destination (or a list of incident ids) as false positives, "
                 "with a note naming the assessor. Metadata only: the evidence is never read. Needs DLP ticked and Workflow Automation "
                 "marked Zscaler.",
            in_scope=in_scope, plan=plan, read_objects=read_objects, handlers={HANDLER: _h_step}, verify=_verify, inverse=_inverse,
            group="Incidents", script="ops_zwa.js")
