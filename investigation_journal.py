"""Guided investigation journal: hypothesis -> evidence -> conclusion, resumable.

A case is a list of steps. Each step states a hypothesis, collects evidence
(a reference to a tool result: the tool's name, when it was read and a short
note, never the result itself) and ends in a conclusion (supported, rejected
or inconclusive). A case also keeps open questions. `show` says where the
case left off (`next`), so a later conversation resumes it.

Built on workspace_notes: the same tenant labels, text cleaning and limits,
the same owner-only atomic sealed store (store_crypto), and each case is
mirrored there as a note (kind "case") with a comment when it is opened and
when a step is concluded, so the app's own pages show it. Local only: nothing
here reaches a tenant.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import safe_files
import store_crypto
import workspace_notes as wn

STORE_FILE = "investigation_journal.json"
MAX_CASES = 200
MAX_STEPS = 50
MAX_EVIDENCE = 20
MAX_QUESTIONS = 30
MAX_TEXT = 1000
OUTCOMES = ("supported", "rejected", "inconclusive")
KINDS = ("hypothesis", "evidence", "conclusion", "question", "answer")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_ID_RE = re.compile(r"^[a-f0-9]{8}$")
_LOCK = threading.Lock()


class JournalError(wn.NotesError):
    pass


def store_path() -> str:
    env = os.environ.get("DLP_CHECK_JOURNAL")
    return env or os.path.join(os.path.dirname(os.path.abspath(wn.store_path())), STORE_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read() -> Dict[str, Any]:
    try:
        with open(store_path(), "r", encoding="utf-8") as f:
            data = store_crypto.load_json(f)
        if isinstance(data, dict) and isinstance(data.get("tenants"), dict):
            return data
    except (OSError, ValueError, RecursionError):
        pass
    return {"version": 1, "tenants": {}}


def _write(data: Dict[str, Any]) -> None:
    p = store_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    safe_files.private_makedirs(folder)
    fd, tmp = tempfile.mkstemp(prefix=".investigation_journal.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            store_crypto.dump_json(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _text(value: Any, what: str, limit: int = MAX_TEXT) -> str:
    s = wn._clean(value, limit)
    if not s:
        raise JournalError(f"say what the {what} is")
    return s


def _mirror(tenant: str, case: Dict[str, Any], text: str, by: str) -> None:
    with contextlib.suppress(Exception):   # the journal stands; the mirrored note is a convenience
        wn.apply(tenant, "case", "case-" + case["id"], "add_comment", by=by, label=case["title"][:wn.MAX_LABEL_LEN], text=text[:wn.MAX_COMMENT_LEN])


def _case(data: Dict[str, Any], tenant: str, case_id: str) -> Dict[str, Any]:
    if not _ID_RE.match(str(case_id or "")):
        raise JournalError("case_id is the 8-character id journal_open gave", 400)
    c = (data["tenants"].get(tenant) or {}).get(case_id)
    if not isinstance(c, dict):
        raise JournalError("There is no such case for this tenant.", 404)
    return c


def open_case(tenant: str, title: str, *, by: str) -> Dict[str, Any]:
    tenant = wn.clean_tenant(tenant)
    title = _text(title, "case title", 200)
    if not by:
        raise JournalError("could not tell who is writing", 401)
    with _LOCK:
        data = _read()
        cases = data["tenants"].setdefault(tenant, {})
        if len(cases) >= MAX_CASES:
            raise JournalError(f"at most {MAX_CASES} cases per tenant", 409)
        cid = secrets.token_hex(4)
        case = {"id": cid, "title": title, "status": "open", "opened_at": _now(), "opened_by": by, "steps": [], "questions": []}
        cases[cid] = case
        _write(data)
    _mirror(tenant, case, f"Investigation opened: {title}", by)
    return view(case)


def _step(case: Dict[str, Any], step_id: str) -> Dict[str, Any]:
    for s in case["steps"]:
        if s["id"] == step_id:
            return s
    raise JournalError("There is no such step in this case; journal_show lists them.", 404)


def add(tenant: str, case_id: str, kind: str, text: str = "", *, by: str, step_id: str = "", tool: str = "", ref: str = "",
        outcome: str = "") -> Dict[str, Any]:
    """Add one entry. hypothesis: starts a step. evidence: needs step_id and
    the tool whose result it cites (`ref`: e.g. its read_at or a short quote).
    conclusion: needs step_id, at least one piece of evidence and an outcome.
    question / answer: an open question, or its answer (step_id = question id)."""
    tenant = wn.clean_tenant(tenant)
    if kind not in KINDS:
        raise JournalError(f"kind is one of {', '.join(KINDS)}")
    if not by:
        raise JournalError("could not tell who is writing", 401)
    body = _text(text, kind)
    mirror = ""
    with _LOCK:
        data = _read()
        case = _case(data, tenant, case_id)
        if case["status"] == "closed":
            raise JournalError("This case is closed.", 409)
        if kind == "hypothesis":
            if len(case["steps"]) >= MAX_STEPS:
                raise JournalError(f"at most {MAX_STEPS} steps per case", 409)
            case["steps"].append({"id": secrets.token_hex(4), "hypothesis": body, "evidence": [], "conclusion": None, "outcome": None, "at": _now(), "by": by})
        elif kind == "evidence":
            step = _step(case, step_id)
            if step["conclusion"]:
                raise JournalError("That step is concluded; start a new hypothesis.", 409)
            if not _TOOL_RE.match(str(tool or "")):
                raise JournalError("name the tool whose result this is (for example path_check)")
            if len(step["evidence"]) >= MAX_EVIDENCE:
                raise JournalError(f"at most {MAX_EVIDENCE} pieces of evidence per step", 409)
            step["evidence"].append({"tool": tool, "ref": wn._clean(ref, 200), "note": body, "at": _now(), "by": by})
        elif kind == "conclusion":
            step = _step(case, step_id)
            if outcome not in OUTCOMES:
                raise JournalError(f"outcome is one of {', '.join(OUTCOMES)}")
            if not step["evidence"]:
                raise JournalError("A conclusion needs evidence: add what a tool showed first.", 409)
            step.update(conclusion=body, outcome=outcome, concluded_at=_now())
            mirror = f"{outcome.capitalize()}: {step['hypothesis']} -> {body}"
        elif kind == "question":
            if len(case["questions"]) >= MAX_QUESTIONS:
                raise JournalError(f"at most {MAX_QUESTIONS} questions per case", 409)
            case["questions"].append({"id": secrets.token_hex(4), "text": body, "answer": None, "at": _now(), "by": by})
        else:
            q = next((x for x in case["questions"] if x["id"] == step_id), None)
            if q is None:
                raise JournalError("There is no such question; journal_show lists them.", 404)
            q["answer"] = body
        case["updated_at"] = _now()
        _write(data)
        out = view(case)
    if mirror:
        _mirror(tenant, case, mirror, by)
    return out


def view(case: Dict[str, Any]) -> Dict[str, Any]:
    """The case and where it left off: `next` is the first thing still to do."""
    nxt = "Add a hypothesis."
    for s in case["steps"]:
        if not s["evidence"]:
            nxt = f"Step {s['id']}: gather evidence for the hypothesis (run a tool, then add its result as evidence)."
            break
        if not s["conclusion"]:
            nxt = f"Step {s['id']}: conclude (supported, rejected or inconclusive)."
            break
    else:
        openq = [q for q in case["questions"] if not q["answer"]]
        if openq:
            nxt = f"Answer question {openq[0]['id']}: {openq[0]['text'][:120]}"
        elif case["steps"]:
            nxt = "All steps are concluded: add a new hypothesis or close the case."
    return {**case, "next": nxt, "open_questions": sum(1 for q in case["questions"] if not q["answer"])}


def show(tenant: str, case_id: str = "") -> Dict[str, Any]:
    tenant = wn.clean_tenant(tenant)
    data = _read()
    if not case_id:
        cases = sorted((data["tenants"].get(tenant) or {}).values(), key=lambda c: c.get("updated_at") or c.get("opened_at") or "", reverse=True)
        return {"cases": [{"id": c["id"], "title": c["title"], "status": c["status"], "steps": len(c["steps"]),
                           "opened_at": c["opened_at"], "next": view(c)["next"]} for c in cases[:50]]}
    return {"case": view(_case(data, tenant, case_id))}
