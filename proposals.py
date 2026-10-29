"""Continuous evaluation, phase 2: proposals and the approval queue.

A FP/TP Detection Ratio report says what the tenant's rules actually do. This
module turns its findings into *proposals*: small typed records that
name one change, the evidence behind it, the expected effect and the way
back. A person approves, dismisses or snoozes each one in the queue;
nothing here writes to a tenant (phase 3 applies approved proposals
through the deploy path).

Proposal ids are stable (kind + target + tenant), so a proposal raised
again by the next evaluation merges into the existing one: an open
proposal keeps its date and gets fresh evidence, a dismissed one stays
dismissed for DISMISS_DAYS, a snoozed one stays quiet until its date, an
approved one waits for phase 3.

The queue lives in proposals.json next to the app (git-ignored), keyed
by tenant. Every decision is recorded in audit.log.
"""
from __future__ import annotations

import md_safe
import contextlib
import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

STORE_FILE = "proposals.json"
DISMISS_DAYS = 30
SNOOZE_DAYS_DEFAULT = 14
_LOCK = threading.RLock()
MAX_SNOOZE_DAYS = 365

try:  # POSIX
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore

# Gates: "approve" is one click; "approve_double" also needs the confirm
# phrase, because the change makes the tenant stricter for users.
GATES = {
    "promote_rule": "approve_double",
    "restore_drift": "approve_double",
    "retire_rule": "approve",
    "tune_dictionary": "approve",
    "exclude_destination": "approve",
    "enable_incident_forwarding": "approve",
    "extend_coverage": "approve",
    "reauthorise_tenant": "approve",
    "update_check": "approve",
    # Self-healing: put back a setting that drifted from what was approved.
    "heal_drift": "approve_double",
}
CONFIRM_PHRASE = "I UNDERSTAND"
KIND_LABELS = {
    "promote_rule": "Promote rule", "retire_rule": "Retire rule", "tune_dictionary": "Tune dictionary",
    "enable_incident_forwarding": "Forward incidents", "extend_coverage": "Extend coverage",
    "reauthorise_tenant": "Re-authorise tenant", "update_check": "Update check", "restore_drift": "Restore drift",
    "exclude_destination": "Exclude destination", "heal_drift": "Heal drift",
}


def store_path() -> str:
    return os.environ.get("DLPCHECK_PROPOSALS_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), STORE_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read() -> Dict[str, Any]:
    p = store_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("tenants"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "tenants": {}}


@contextlib.contextmanager
def _locked():
    """This process's lock, then an exclusive lock on <store>.lock, so a
    read-modify-write never interleaves with another server process."""
    with _LOCK:
        p = store_path()
        fd = None
        if fcntl is not None:
            try:
                fd = os.open(p + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:   # a read-only folder: the thread lock still holds
                if fd is not None:
                    os.close(fd)
                fd = None
        try:
            yield
        finally:
            if fd is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)


def _write(data: Dict[str, Any]) -> None:
    """Owner-only from the first byte and atomic: <store>.tmp (git-ignored)
    created afresh (O_EXCL, O_NOFOLLOW, 0600: a stale file or a planted
    link is removed first and never followed), flushed, then renamed over
    the store. Callers hold _locked(), so one writer uses the name at a time."""
    p = store_path()
    tmp = p + ".tmp"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)   # a crash's leftover, or a link: the link itself goes, never its target
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        _keep_last_good(p)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _keep_last_good(path: str) -> None:
    """The queue as it was, kept as a last-good copy (self_heal) before it is replaced."""
    try:
        import self_heal
        self_heal.keep_last_good(path)
    except Exception:  # noqa: BLE001 - never stops a write
        pass


def tenant_key(label: Any) -> str:
    return str(label or "").strip().lower() or "unknown"


def proposal_id(tenant: str, kind: str, target: str) -> str:
    return "p-" + hashlib.sha256(f"{tenant_key(tenant)}|{kind}|{target}".encode("utf-8")).hexdigest()[:12]


# ── building proposals from a FP/TP Detection Ratio report ─────────────────
def _rule_by_name(rep: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {str(r.get("name")): r for r in (rep.get("rules") or [])}


def build_proposals(rep: Dict[str, Any], tenant: str) -> List[Dict[str, Any]]:
    """Typed proposals from a FP/TP Detection Ratio report. Pure."""
    s = rep.get("settings") or {}
    rules = _rule_by_name(rep)
    out: List[Dict[str, Any]] = []

    def add(kind: str, target: str, title: str, change: Dict[str, Any], evidence: Dict[str, Any], expected: str, rollback: Dict[str, Any], **extra):
        p = {"id": proposal_id(tenant, kind, target), "tenant": tenant_key(tenant), "kind": kind, "label": KIND_LABELS.get(kind, kind),
             "target": target, "title": title, "change": change, "evidence": evidence, "expected_effect": expected, "rollback": rollback,
             "gate": GATES.get(kind, "approve"), "applies_via": "phase 3" if change.get("apply") == "rule" else "manual"}
        p.update(extra)
        out.append(p)

    for f in rep.get("findings") or []:
        kind = f.get("kind")
        if kind == "promotable_rule":
            r = rules.get(f.get("name")) or {}
            to = "CONFIRM" if str(r.get("action") or "").upper() in ("ALLOW", "ALERT", "MONITOR") else "BLOCK"
            add("promote_rule", f"rule:{r.get('channel')}:{f.get('name')}",
                f"Promote {f['name']} from monitor to {to.lower()}",
                {"apply": "rule", "rule_id": r.get("id"), "channel": r.get("channel"), "field": "action", "from": r.get("action"), "to": to},
                {"fp_rate_pct": r.get("promote_rate_pct"), "closed": r.get("promote_closed"), "window_days": s.get("promote_window_days"),
                 "incidents": r.get("incidents"), "engines": r.get("engines"), "why": r.get("why")},
                f"Users hitting {f['name']} are {'asked to justify' if to == 'CONFIRM' else 'blocked'} instead of only logged; incident volume stays the same.",
                {"field": "action", "to": r.get("action")}, channel=r.get("channel"), rule=f.get("name"))
        elif kind == "dead_rule":
            r = rules.get(f.get("name")) or {}
            add("retire_rule", f"rule:{r.get('channel')}:{f.get('name')}",
                f"Disable {f['name']}: no incident in {s.get('dead_days')} days",
                {"apply": "rule", "rule_id": r.get("id"), "channel": r.get("channel"), "field": "state", "from": r.get("state"), "to": "DISABLED"},
                {"last_incident_at": r.get("last_incident_at"), "dead_days": s.get("dead_days"), "engines": r.get("engines"), "why": r.get("why")},
                "One rule fewer to evaluate and maintain; nothing that fires today is lost.",
                {"field": "state", "to": r.get("state") or "ENABLED"}, channel=r.get("channel"), rule=f.get("name"))
        elif kind == "noisy_dictionary":
            ev = f.get("evidence") or {}
            apps = ev.get("applications") or []
            top_app = apps[0] if apps and apps[0][1] >= max(2, (ev.get("not_real") or 0) // 2) else None
            change = ({"apply": "manual", "kind": "exclude_application", "application": top_app[0], "rules": f.get("rules") or []}
                      if top_app else {"apply": "manual", "kind": "raise_match_count", "dictionary": f.get("name")})
            add("tune_dictionary", f"dictionary:{f.get('name')}",
                f"Tune dictionary {f['name']}" + (f": exclude {top_app[0]}" if top_app else ": raise the match count"),
                change, {"fp_rate_pct": None, "why": f.get("why"), "fix": f.get("fix"), **{k: ev.get(k) for k in ("not_real", "real", "alone", "co_fired", "median_matches_not_real", "median_matches_real", "applications", "departments") if k in ev}},
                "Fewer not-real incidents from this dictionary; real ones (bulk matches) still fire.",
                {"note": "Undo the dictionary or rule edit in the ZIA portal; the proposal keeps the setting it changed."}, dictionary=f.get("name"))
        elif kind == "noisy_destination":
            ev = f.get("evidence") or {}
            add("exclude_destination", f"destination:{f.get('name')}",
                f"Exclude {f['name']} from DLP inspection" + (" (telemetry / public content)" if ev.get("telemetry") else " (never a real incident)"),
                {"apply": "manual", "kind": "exclude_destination", "host": f.get("name"), "rules": f.get("rules") or []},
                {"incidents": ev.get("incidents"), "users": ev.get("users"), "not_real": ev.get("not_real"), "real": ev.get("real"), "closed": ev.get("closed"),
                 "telemetry": ev.get("telemetry"), "applications": ev.get("applications"), "why": f.get("why"), "fix": f.get("fix")},
                "Incidents from a destination that never carries sensitive data stop; the rules keep inspecting everything else, so no coverage is lost.",
                {"note": "Remove the host from the excluded URL category or domain list in the ZIA portal."}, destination=f.get("name"))
        elif kind == "noisy_rule":
            r = rules.get(f.get("name")) or {}
            add("tune_dictionary", f"rule:{r.get('channel')}:{f.get('name')}",
                f"Tune the dictionaries behind {f['name']} ({r.get('fp_rate_pct')}% not real)",
                {"apply": "manual", "kind": "review_engine", "engines": r.get("engines") or []},
                {"fp_rate_pct": r.get("fp_rate_pct"), "closed": r.get("fp_closed"), "window_days": s.get("fp_window_days"), "why": r.get("why")},
                "The rule's incidents become worth an analyst's time.", {"note": "Revert the engine or dictionary edit."}, channel=r.get("channel"), rule=f.get("name"))
        elif kind == "no_incident_delivery":
            d = rep.get("delivery") or {}
            add("enable_incident_forwarding", "delivery:web",
                "Forward Web DLP matches to the Incident Receiver",
                {"apply": "rule", "channel": "web", "field": "zscaler_incident_receiver", "to": True, "rules": d.get("rules_silent") or []},
                {"rules_enabled": d.get("rules_enabled"), "rules_silent": d.get("rules_silent"), "receivers": d.get("receivers"), "icap_servers": d.get("icap_servers")},
                "Every match reaches Workflow Automation as an incident with the file, so verdicts exist to learn from.",
                {"field": "zscaler_incident_receiver", "to": False})
    d = rep.get("delivery") or {}
    silent = d.get("rules_silent") or []
    if silent and d.get("path") in ("cloud", "icap", "both") and not any(p["kind"] == "enable_incident_forwarding" for p in out):
        add("enable_incident_forwarding", "delivery:web:silent",
            f"{len(silent)} enabled Web DLP rule(s) forward nowhere",
            {"apply": "rule", "channel": "web", "field": "zscaler_incident_receiver", "to": True, "rules": silent},
            {"rules_silent": silent, "path": d.get("path")},
            "Matches on these rules reach Workflow Automation like the others.", {"field": "zscaler_incident_receiver", "to": False})
    return out


# ── the queue ──────────────────────────────────────────────────────────
def _active(p: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    """Is this stored proposal still holding (not expired dismissal / snooze)?"""
    now = now or datetime.now(timezone.utc)
    st = p.get("status")
    if st == "dismissed":
        try:
            return datetime.fromisoformat(p.get("decided_at")) + timedelta(days=DISMISS_DAYS) > now
        except (TypeError, ValueError):
            return False
    if st == "snoozed":
        try:
            return datetime.fromisoformat(p.get("snoozed_until")) > now
        except (TypeError, ValueError):
            return False
    return True


def merge(tenant: str, fresh: List[Dict[str, Any]], *, source: str = "detection_health", resolve_missing: bool = True) -> Dict[str, Any]:
    """Merge freshly built proposals into the tenant's queue. Returns
    {new, updated, resolved, kept, total}. With resolve_missing, an open
    proposal from the same source that is not in `fresh` is resolved (the
    signal went away); guidance proposals pass False, because an article
    is raised once and stays until a person decides."""
    tk = tenant_key(tenant)
    now = _now()
    stats = {"new": 0, "updated": 0, "resolved": 0, "kept": 0}
    with _locked():
        data = _read()
        q = data["tenants"].setdefault(tk, {"proposals": {}, "updated_at": now})
        store = q["proposals"]
        seen = set()
        for p in fresh:
            pid = p["id"]
            seen.add(pid)
            cur = store.get(pid)
            if cur and _active(cur):
                cur.update({k: v for k, v in p.items() if k in ("title", "change", "evidence", "expected_effect", "rollback", "gate", "applies_via")})
                cur["last_seen_at"] = now
                cur["times_seen"] = int(cur.get("times_seen") or 1) + 1
                stats["updated" if cur.get("status") == "open" else "kept"] += 1
            else:
                store[pid] = dict(p, status="open", created_at=now, last_seen_at=now, times_seen=1, source=source, history=[])
                stats["new"] += 1
        # An open proposal the evaluation no longer raises is resolved: the
        # signal went away (the rule was tuned, the dictionary fixed…).
        for pid, cur in (list(store.items()) if resolve_missing else []):
            if pid not in seen and cur.get("status") == "open" and cur.get("source") == source:
                cur["status"] = "resolved"; cur["decided_at"] = now; cur["note"] = "no longer raised by the evaluation"
                stats["resolved"] += 1
        q["updated_at"] = now
        _write(data)
        stats["total"] = len(store)
    return stats


def rekey(old: str, new: str) -> int:
    """Move the queue kept under `old` to `new` (a classic-API tenant once
    keyed by a stale vanity domain). Ids are recomputed for the new key so
    the next run merges into them; a decision already taken (dismissed,
    snoozed, approved, applied) is kept, and a proposal already under the
    new key wins. Returns how many proposals moved."""
    ok, nk = tenant_key(old), tenant_key(new)
    if not old or ok == nk:
        return 0
    with _locked():
        data = _read()
        q = data["tenants"].pop(ok, None)
        if not q:
            return 0
        dest = data["tenants"].setdefault(nk, {"proposals": {}, "updated_at": _now()})
        moved = 0
        for p in (q.get("proposals") or {}).values():
            nid = proposal_id(nk, str(p.get("kind") or ""), str(p.get("target") or "")) if p.get("kind") else p.get("id")
            if nid in dest["proposals"]:
                continue
            dest["proposals"][nid] = dict(p, id=nid, tenant=nk)
            moved += 1
        dest["updated_at"] = _now()
        _write(data)
    return moved


def refresh_from_report(rep: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    return merge(tenant, build_proposals(rep, tenant))


def list_queue(tenant: str, *, include_closed: bool = False) -> List[Dict[str, Any]]:
    with _LOCK:
        data = _read()
        q = data["tenants"].get(tenant_key(tenant)) or {"proposals": {}}
        items = list(q["proposals"].values())
    now = datetime.now(timezone.utc)
    out = []
    for p in items:
        if p.get("status") in ("dismissed", "snoozed") and not _active(p, now):
            p = dict(p, status="open", note=(p.get("note") or "") + " (snooze/dismissal expired)")
        if not include_closed and p.get("status") not in ("open", "approved"):
            continue
        out.append(p)
    order = {"approved": 0, "open": 1, "snoozed": 2, "applied": 3, "dismissed": 4, "resolved": 5}
    gate_order = {"approve_double": 0, "approve": 1}
    out.sort(key=lambda p: (order.get(p.get("status"), 9), gate_order.get(p.get("gate"), 9), p.get("created_at") or ""))
    return out


def summary(tenant: str) -> Dict[str, int]:
    with _LOCK:
        q = (_read()["tenants"].get(tenant_key(tenant)) or {"proposals": {}})["proposals"]
    now = datetime.now(timezone.utc)
    c = {"open": 0, "approved": 0, "snoozed": 0, "dismissed": 0, "applied": 0, "resolved": 0}
    for p in q.values():
        st = p.get("status")
        if st in ("dismissed", "snoozed") and not _active(p, now):
            st = "open"
        c[st] = c.get(st, 0) + 1
    return c


# Decisions a proposal's status does not allow (an approval is never replayed:
# an applied change is rolled back first, then it can be approved again).
_DECISION_REFUSED = {
    ("*", "applied"): "this change is applied: roll it back from the queue first (an applied change is not decided again)",
    ("approve", "approved"): "this proposal is already approved",
    ("approve", "resolved"): "this proposal is resolved (the evaluation no longer raises it), so there is nothing to approve",
}


def decide(tenant: str, pid: str, decision: str, *, by: str = "", note: str = "", days: int = SNOOZE_DAYS_DEFAULT, confirm: str = "") -> Dict[str, Any]:
    """approve | dismiss | snooze | reopen. Raises ValueError with a
    message the GUI can show."""
    decision = (decision or "").lower()
    if decision not in ("approve", "dismiss", "snooze", "reopen"):
        raise ValueError("decision must be approve, dismiss, snooze or reopen")
    if decision == "snooze":
        try:
            days = int(days or SNOOZE_DAYS_DEFAULT)
        except (TypeError, ValueError):
            raise ValueError("snooze days must be a whole number") from None
        days = min(MAX_SNOOZE_DAYS, max(1, days))
    with _locked():
        data = _read()
        q = data["tenants"].get(tenant_key(tenant)) or {}
        p = (q.get("proposals") or {}).get(pid)
        if not p:
            raise ValueError("proposal not found (the queue may have been refreshed; reload)")
        st = p.get("status")
        if st in ("dismissed", "snoozed") and not _active(p):
            st = "open"   # an expired dismissal or snooze is open again (list_queue shows it so)
        why = _DECISION_REFUSED.get((decision, st)) or (_DECISION_REFUSED.get(("*", st)))
        if why:
            raise ValueError(why)
        if decision == "approve" and p.get("gate") == "approve_double" and (confirm or "").strip().upper() != CONFIRM_PHRASE:
            raise ValueError(f'this change makes the tenant stricter for users: type "{CONFIRM_PHRASE}" to approve it')
        now = _now()
        p.setdefault("history", []).append({"at": now, "decision": decision, "by": by, "note": note})
        p["decided_at"] = now; p["decided_by"] = by; p["note"] = note
        if decision == "approve":
            p["status"] = "approved"
        elif decision == "dismiss":
            p["status"] = "dismissed"
        elif decision == "snooze":
            p["status"] = "snoozed"
            p["snoozed_until"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
        else:
            p["status"] = "open"; p.pop("snoozed_until", None)
        q["updated_at"] = now
        _write(data)
        result = dict(p)
    try:
        import audit
        audit.record("proposal_decision", tenant=tenant_key(tenant), proposal=pid, kind=p.get("kind"), target=p.get("target"), decision=decision, by=by, note=note)
    except Exception as e:  # noqa: BLE001 - the decision stands; the lost audit line is reported loudly
        import audit
        audit.report_failure(f"the decision '{decision}' on proposal {pid}", e)
    return result


def get(tenant: str, pid: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        q = _read()["tenants"].get(tenant_key(tenant)) or {}
        p = (q.get("proposals") or {}).get(pid)
        return dict(p) if p else None


def set_status(tenant: str, pid: str, status: str, **fields: Any) -> Optional[Dict[str, Any]]:
    """Phase 3 hook: mark a proposal applied / failed / rolled back."""
    with _locked():
        data = _read()
        q = data["tenants"].get(tenant_key(tenant)) or {}
        p = (q.get("proposals") or {}).get(pid)
        if not p:
            return None
        p["status"] = status
        p.update(fields)
        p.setdefault("history", []).append({"at": _now(), "decision": status, **{k: v for k, v in fields.items() if k in ("note", "by")}})
        _write(data)
        return dict(p)


def to_markdown(tenant: str, items: List[Dict[str, Any]]) -> str:
    lines = [f"# Proposals — {md_safe.text(tenant)}", ""]
    if not items:
        lines.append("Nothing open.")
    for p in items:
        t = md_safe.text
        lines.append(f"## [{t(p.get('status'))}] {t(p.get('title'))}")
        lines.append(f"- Kind: {t(p.get('label'))} · gate: {t(p.get('gate'))} · first raised {t(p.get('created_at'))} · seen {t(p.get('times_seen', 1))}×")
        lines.append(f"- Change: {md_safe.code(json.dumps(p.get('change')))}")
        lines.append(f"- Expected: {t(p.get('expected_effect'))}")
        lines.append(f"- Rollback: {md_safe.code(json.dumps(p.get('rollback')))}")
        lines.append(f"- Evidence: {md_safe.code(json.dumps(p.get('evidence')), 600)}")
        lines.append("")
    return "\n".join(lines)
