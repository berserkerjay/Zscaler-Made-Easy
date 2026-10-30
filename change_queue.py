"""The team change queue: change requests and four-eyes approval.

A change request is a change someone prepared but did not apply: a
policy-pack deploy plan (from Deploy policy packs' preflight), a selective
removal plan (from the rule picker's preview), or a fix recipe (from Review
& remediate's preview). It is filed in a shared queue on this server, a
writer other than the requester approves or rejects it, and an approved
request is applied through the app's existing apply path (dlp_api_server
runs it; nothing here writes to a tenant).

Each request keeps what it will change (the counts and the item list the
preflight produced), who asked (`requested_by`: the signed-in person the
server saw, never a name sent by the page), the plan_hash the preflight
gave, the comments and the history of every step. Applying re-checks the
plan against the tenant as it is then; a different plan_hash marks the
request stale ("request again").

Four-eyes: with DLP_CHECK_FOUR_EYES on (the default) the approver must be
a different person than the requester. Without SSO everyone using the
server is the same "local UI token", so approving needs SSO or the setting
off (DLP_CHECK_FOUR_EYES=0, a single-person install).

The queue lives in change_requests.json next to proposals.json (the same
folder, so /data in the container; git-ignored), owner-only, replaced
atomically, and guarded by a lock file so two server processes (or two
threads) never lose each other's writes. Every step is recorded in the
audit log with the actor.
"""
from __future__ import annotations

import md_safe
import contextlib
import hashlib
import json
import os
import secrets
import tempfile
import threading
import unicodedata
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

import safe_files
import store_crypto

try:  # POSIX
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore
try:  # Windows
    import msvcrt  # type: ignore
except ImportError:
    msvcrt = None  # type: ignore

STORE_FILE = "change_requests.json"
_LOCK = threading.RLock()

KINDS = {
    "pack_deploy": "Deploy policy packs",
    "pack_removal": "Remove selected rules",
    "fix_recipe": "Fix recipe",
}
STATUSES = ("pending", "approved", "rejected", "applied", "failed", "stale", "withdrawn")
OPEN_STATUSES = ("pending", "approved")
# The typed confirmation an apply needs: the same phrase as approving a
# stricter proposal (proposals.CONFIRM_PHRASE).
CONFIRM_PHRASE = "I UNDERSTAND"
MAX_ITEMS = 500
MAX_COMMENT = 1000
MAX_COMMENTS = 200
STALE_MESSAGE = "stale: the tenant changed since it was requested; request again"


class QueueError(ValueError):
    """A refusal the page can show as it is. `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


# ── settings ────────────────────────────────────────────────────────────
def _team_on() -> bool:
    try:
        import team_server
        return team_server.enabled()
    except Exception:  # noqa: BLE001
        return False


def four_eyes_required() -> bool:
    """True unless DLP_CHECK_FOUR_EYES is 0/false/no/off. Always true on a
    team server: there everyone is a named person, so the setting cannot
    turn the second pair of eyes off."""
    if _team_on():
        return True
    return os.environ.get("DLP_CHECK_FOUR_EYES", "1").strip().lower() not in ("0", "false", "no", "off")


def settings() -> Dict[str, Any]:
    """What the page shows about four-eyes: the setting, where it comes
    from, and whether it can work here (it needs SSO: without it everyone
    is the same local identity)."""
    try:
        import sso
        sso_on = sso.sso_enabled()
    except Exception:  # noqa: BLE001
        sso_on = False
    req = four_eyes_required()
    raw = os.environ.get("DLP_CHECK_FOUR_EYES")
    note = ""
    if _team_on():
        return {"four_eyes": True, "setting": "ZSCALER_TEAM_MODE", "value": "team server: always on", "sso": True, "team": True,
                "note": "Team server: the person who approves must be another signed-in person than the one who asked, with the "
                        "approve right on the request's tenant profile; DLP_CHECK_FOUR_EYES cannot turn this off.",
                "confirm_phrase": CONFIRM_PHRASE}
    if req and not sso_on:
        note = ("Four-eyes approval needs SSO: without it everyone using this server is the same \"local UI token\", so "
                "nobody can approve a request they filed. Turn on SSO (ZSCALER_SSO_ENABLED) so each person signs in, or set "
                "DLP_CHECK_FOUR_EYES=0 for a single-person install.")
    elif not req:
        note = "Four-eyes is off (DLP_CHECK_FOUR_EYES=0): the requester may approve their own request. Use this only on a single-person install."
    return {"four_eyes": req, "setting": "DLP_CHECK_FOUR_EYES", "value": raw if raw is not None else "(unset: on)",
            "sso": sso_on, "note": note, "confirm_phrase": CONFIRM_PHRASE}


# ── the store ───────────────────────────────────────────────────────────
def store_path() -> str:
    """change_requests.json beside the proposals store (DLPCHECK_PROPOSALS_FILE's
    folder, /data in the container), or DLPCHECK_CHANGE_QUEUE_FILE."""
    env = os.environ.get("DLPCHECK_CHANGE_QUEUE_FILE")
    if env:
        return env
    try:
        import proposals
        folder = os.path.dirname(proposals.store_path())
    except Exception:  # noqa: BLE001
        folder = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(folder, STORE_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_HELD = threading.local()   # how deep this thread is inside _locked()


@contextlib.contextmanager
def _locked() -> Iterator[None]:
    """This process's lock, then an exclusive lock on <store>.lock, so a
    read-modify-write never interleaves with another thread or process.
    Re-entrant: a nested call in the same thread only counts depth (a
    second lock on a new descriptor of the same file would wait on this
    thread's own lock forever)."""
    with _LOCK:
        depth = getattr(_HELD, "depth", 0)
        if depth:
            _HELD.depth = depth + 1
            try:
                yield
            finally:
                _HELD.depth = depth
            return
        p = store_path()
        safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)) or ".")
        fd = os.open(p + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        _HELD.depth = 1
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            yield
        finally:
            _HELD.depth = 0
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no cover - Windows
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)


def _read() -> Dict[str, Any]:
    try:
        with open(store_path(), "r", encoding="utf-8") as f:
            data = store_crypto.load_json(f)
        if isinstance(data, dict) and isinstance(data.get("requests"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "requests": {}}


def _write(data: Dict[str, Any]) -> None:
    """Owner-only, atomic: a unique temporary file in the same folder,
    flushed, then renamed over the store."""
    p = store_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".change_requests.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            store_crypto.dump_json(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        _keep_last_good(p)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _audit(action: str, rec: Dict[str, Any], by: str, **extra: Any) -> None:
    try:
        import audit
        audit.record("change_request", actor=by or None, action=action, request=rec.get("id"), kind=rec.get("kind"),
                     tenant=rec.get("tenant_label") or rec.get("tenant"), status=rec.get("status"),
                     plan_hash=(rec.get("plan_hash") or "")[:16], requested_by=rec.get("requested_by"), **extra)
    except Exception as e:  # noqa: BLE001 - the step stands; the lost audit line is reported loudly
        try:
            import audit
            audit.report_failure(f"the change request step '{action}' on {rec.get('id')}", e)
        except Exception:  # noqa: BLE001
            pass


def _mutate(rid: str, fn: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    with _locked():
        data = _read()
        rec = data["requests"].get(rid)
        if not rec:
            raise QueueError("change request not found (it may have been removed; reload the queue)", 404)
        fn(rec)
        rec["updated_at"] = _now()
        _write(data)
        return json.loads(json.dumps(rec))


def _person_key(who: Any) -> str:
    """One spelling per person: NFKC (full-width and compatibility forms
    fold to plain letters) and case-folded."""
    return unicodedata.normalize("NFKC", str(who or "")).strip().casefold()


def _same_person(a: Any, b: Any) -> bool:
    return _person_key(a) == _person_key(b)


def _need_actor(by: Any) -> str:
    """The server's view of who is acting; a step nobody can be named for is refused."""
    who = str(by or "").strip()
    if not who:
        raise QueueError("could not tell who you are (sign in again)", 401)
    return who


def approval_digest(rec: Dict[str, Any]) -> str:
    """sha256 over what an approval approves: the kind, the tenant, the
    plan_hash and the stored payload the apply runs from. Recorded when a
    request is approved and checked again before it is applied, so an
    approval never carries over to a different plan or payload."""
    core = {"kind": rec.get("kind"), "tenant": rec.get("tenant"), "plan_hash": rec.get("plan_hash"), "payload": rec.get("payload") or {}}
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _history(rec: Dict[str, Any], action: str, by: str, **fields: Any) -> None:
    hist = rec.setdefault("history", [])
    hist.append({"at": _now(), "action": action, "by": by, **{k: v for k, v in fields.items() if v not in (None, "")}})
    if action == "commented":
        # Comments are capped (MAX_COMMENTS); so are their history lines, or
        # repeated comments would grow the record (and every write of the
        # store) without bound. Decisions are never dropped; the audit log
        # keeps every comment event.
        said = [i for i, h in enumerate(hist) if h.get("action") == "commented"]
        for i in reversed(said[:max(0, len(said) - MAX_COMMENTS)]):
            del hist[i]


def _clean_text(text: Any, limit: int = MAX_COMMENT) -> str:
    s = "".join(ch for ch in str(text or "") if ch == "\n" or ch >= " ").strip()
    return s[:limit]


# ── plan hash for a recipe (it has no preflight of its own) ─────────────
def recipe_plan_hash(check_id: str, plan: Dict[str, Any]) -> str:
    """The hash of a fix recipe's planned call: method, endpoint and body.
    A recipe preview does not read the tenant, so this only changes when
    the recipe or the parameters change."""
    core = {"check_id": str(check_id), "method": plan.get("method"), "endpoint": plan.get("endpoint"), "body": plan.get("body")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode("utf-8")).hexdigest()


# ── filing ──────────────────────────────────────────────────────────────
def file_request(*, kind: str, tenant: str, tenant_label: str, title: str, summary: Dict[str, Any], items: List[Dict[str, Any]],
                 plan_hash: str, requested_by: str, payload: Dict[str, Any], note: str = "") -> Dict[str, Any]:
    """Save a pending change request. `requested_by` is the server's view
    of the caller (dlp_api_server._actor), never a page field."""
    if kind not in KINDS:
        raise QueueError(f"unknown change request kind: {kind}", 400)
    if not plan_hash:
        raise QueueError("a change request needs the plan_hash of a preflight: run the preflight (or preview) first", 400)
    if not requested_by:
        raise QueueError("could not tell who is filing this request (sign in again)", 401)
    now = _now()
    rec: Dict[str, Any] = {
        "id": "cr-" + secrets.token_hex(6), "tenant": str(tenant or "unknown").strip().lower(), "tenant_label": str(tenant_label or ""),
        "kind": kind, "kind_label": KINDS[kind], "title": _clean_text(title, 200) or KINDS[kind],
        "summary": dict(summary or {}), "items": list(items or [])[:MAX_ITEMS], "items_total": len(items or []),
        "plan_hash": str(plan_hash), "payload": dict(payload or {}),
        "requested_by": str(requested_by), "requested_at": now, "updated_at": now, "status": "pending",
        "comments": [], "history": [],
    }
    if _team_on():
        # A team server names the tenant profile the request was filed for, so
        # only people with a right on that profile see, approve or apply it.
        import team_server
        if team_server.current_profile():
            rec["profile_id"] = team_server.current_profile()
    first = _clean_text(note)
    if first:
        rec["comments"].append({"at": now, "by": rec["requested_by"], "text": first})
    _history(rec, "filed", rec["requested_by"])
    with _locked():
        data = _read()
        for other in data["requests"].values():
            if (other.get("status") in OPEN_STATUSES and other.get("tenant") == rec["tenant"] and other.get("kind") == kind
                    and other.get("plan_hash") == rec["plan_hash"]):
                raise QueueError(f"this plan is already in the queue as {other.get('id')} ({other.get('status')}, "
                                 f"requested by {other.get('requested_by')})")
        data["requests"][rec["id"]] = rec
        _write(data)
    _audit("filed", rec, rec["requested_by"], title=rec["title"], items=rec["items_total"])
    return json.loads(json.dumps(rec))


# ── reading ─────────────────────────────────────────────────────────────
def get(rid: str) -> Optional[Dict[str, Any]]:
    with _locked():
        rec = _read()["requests"].get(rid)
        return json.loads(json.dumps(rec)) if rec else None


def list_requests(tenant: str = "", statuses: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Newest first; `tenant` (a tenant key) and `statuses` narrow it."""
    with _locked():
        items = list(_read()["requests"].values())
    tk = str(tenant or "").strip().lower()
    out = [r for r in items if (not tk or r.get("tenant") == tk) and (not statuses or r.get("status") in statuses)]
    out.sort(key=lambda r: r.get("requested_at") or "", reverse=True)
    return out


def counts(tenant: str = "") -> Dict[str, int]:
    c = {s: 0 for s in STATUSES}
    for r in list_requests(tenant):
        c[r.get("status")] = c.get(r.get("status"), 0) + 1
    return c


# ── decisions ───────────────────────────────────────────────────────────
def decide(rid: str, decision: str, *, by: str, comment: str = "") -> Dict[str, Any]:
    """approve | reject a pending request. The caller has checked that `by`
    is a writer; this enforces four-eyes."""
    decision = (decision or "").lower()
    if decision not in ("approve", "reject"):
        raise QueueError("decision must be approve or reject", 400)
    by = _need_actor(by)
    text = _clean_text(comment)
    if decision == "reject" and not text:
        raise QueueError("say why in a comment when you reject a request", 400)

    def fn(rec: Dict[str, Any]) -> None:
        if rec.get("status") != "pending":
            raise QueueError(f"only a pending request can be {decision}d; this one is {rec.get('status')}")
        if _team_on():
            # Checked by the access rule already (approve on the request's
            # tenant profile); again here, where the decision is made.
            import team_server
            profs = team_server.record_profiles(rec)
            if team_server.context() is not None and not any(team_server.may("approve", p) for p in profs):
                raise QueueError(f"{by} may not approve or reject requests for this tenant profile on this team server.", 403)
        if decision == "approve" and four_eyes_required() and _is_local_identity(by):
            # Without SSO every caller is a local identity (with or without the
            # UI token, or the app itself): none of them is a second person.
            raise QueueError(
                f"four-eyes: {by} is not a signed-in person, so it cannot be the second pair of eyes. Turn on SSO so each "
                "person signs in, or set DLP_CHECK_FOUR_EYES=0 for a single-person install.", 403)
        if decision == "approve" and four_eyes_required() and _same_person(by, rec.get("requested_by")):
            raise QueueError(
                f"four-eyes: {by} filed this request, so another person must approve it. "
                + ("Without SSO everyone using this server is the same local identity: turn on SSO, or set DLP_CHECK_FOUR_EYES=0 "
                   "for a single-person install." if _is_local_identity(by) else "Ask another writer to review it."), 403)
        rec["status"] = "approved" if decision == "approve" else "rejected"
        rec["decided_by"] = by
        rec["decided_at"] = _now()
        if decision == "approve":
            rec["approved_digest"] = approval_digest(rec)
        if text:
            _add_comment(rec, by, text)
        _history(rec, "approved" if decision == "approve" else "rejected", by, comment=text)

    rec = _mutate(rid, fn)
    _audit("approved" if decision == "approve" else "rejected", rec, by, four_eyes=four_eyes_required(), comment=text)
    return rec


_NOT_A_PERSON = ("unknown",)


def _is_local_identity(who: Any) -> bool:
    """A caller that is not one signed-in person: the local UI token, the
    local server without one, the app itself, or no name at all."""
    names = set(_NOT_A_PERSON)
    try:
        import security
        names |= {security.LOCAL_TOKEN_ACTOR, security.LOCAL_NO_TOKEN_ACTOR, security.NO_REQUEST_ACTOR}
    except Exception:  # noqa: BLE001
        names |= {"local UI token", "local, no UI token"}
    key = _person_key(who)
    return not key or key in {_person_key(n) for n in names}


def _add_comment(rec: Dict[str, Any], by: str, text: str) -> None:
    c = rec.setdefault("comments", [])
    c.append({"at": _now(), "by": by, "text": text})
    del c[: max(0, len(c) - MAX_COMMENTS)]


def comment(rid: str, *, by: str, text: str) -> Dict[str, Any]:
    t = _clean_text(text)
    if not t:
        raise QueueError("the comment is empty", 400)
    by = _need_actor(by)
    rec = _mutate(rid, lambda r: (_add_comment(r, by, t), _history(r, "commented", by)))
    _audit("commented", rec, by)
    return rec


def withdraw(rid: str, *, by: str, comment: str = "") -> Dict[str, Any]:
    """The requester takes back a pending or approved request."""
    by = _need_actor(by)
    text = _clean_text(comment)

    def fn(rec: Dict[str, Any]) -> None:
        if rec.get("status") not in OPEN_STATUSES:
            raise QueueError(f"only a pending or approved request can be withdrawn; this one is {rec.get('status')}")
        if rec.get("applying"):
            raise QueueError("this request is being applied right now; it cannot be withdrawn")
        if not _same_person(by, rec.get("requested_by")):
            raise QueueError(f"only the requester ({rec.get('requested_by')}) can withdraw this request; a writer can reject it instead", 403)
        rec["status"] = "withdrawn"
        if text:
            _add_comment(rec, by, text)
        _history(rec, "withdrawn", by, comment=text)

    rec = _mutate(rid, fn)
    _audit("withdrawn", rec, by)
    return rec


# ── applying ────────────────────────────────────────────────────────────
def begin_apply(rid: str, *, by: str, job_running: Optional[Callable[[str], bool]] = None) -> Dict[str, Any]:
    """Claim an approved request for one apply run. A second apply while
    the first one's job is still running is refused, and so is a request
    whose kind, tenant, plan_hash or payload is not the one approved."""
    by = _need_actor(by)

    def fn(rec: Dict[str, Any]) -> None:
        if rec.get("status") != "approved":
            raise QueueError(f"only an approved request can be applied; this one is {rec.get('status')}")
        # A request approved before approved_digest existed has none: it still applies (its
        # plan_hash is re-checked against the tenant by the apply path, as it always was).
        if not rec.get("decided_by") or ("approved_digest" in rec and rec["approved_digest"] != approval_digest(rec)):
            raise QueueError("this request is not the one that was approved (its plan or payload changed after the approval); "
                             "request it again")
        cur = rec.get("applying") or {}
        if cur:
            jid = str(cur.get("job_id") or "")
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(cur.get("since")))).total_seconds()
            except (TypeError, ValueError):
                age = 1e9
            # Claimed a moment ago and its job not started yet, or its job still running.
            busy = (not jid and age < 120) or (bool(jid) and (job_running is None or job_running(jid)))
            if busy:
                raise QueueError(f"{cur.get('by')} is applying this request right now (since {cur.get('since')})")
        rec["applying"] = {"by": by, "since": _now(), "job_id": ""}
        _history(rec, "apply_started", by)

    rec = _mutate(rid, fn)
    _audit("apply_started", rec, by)
    return rec


def set_job(rid: str, job_id: str) -> None:
    def fn(rec: Dict[str, Any]) -> None:
        if rec.get("applying"):
            rec["applying"]["job_id"] = job_id
    with contextlib.suppress(QueueError):
        _mutate(rid, fn)


def release(rid: str, *, by: str, reason: str) -> Optional[Dict[str, Any]]:
    """Give the claim back without a result (the run never started)."""
    def fn(rec: Dict[str, Any]) -> None:
        rec.pop("applying", None)
        _history(rec, "apply_not_started", by, note=_clean_text(reason, 300))
    try:
        rec = _mutate(rid, fn)
    except QueueError:
        return None
    _audit("apply_not_started", rec, by, reason=_clean_text(reason, 300))
    return rec


def finish_apply(rid: str, *, by: str, status: str, result: Dict[str, Any], note: str = "") -> Optional[Dict[str, Any]]:
    """Record how an apply ended: applied, failed or stale."""
    if status not in ("applied", "failed", "stale"):
        raise QueueError(f"an apply ends applied, failed or stale, not {status}", 400)

    def fn(rec: Dict[str, Any]) -> None:
        if rec.get("status") != "approved" or not rec.get("applying"):
            # Only the run that claimed it (begin_apply) ends it, once: a
            # finished request is never re-marked.
            raise QueueError(f"this request is {rec.get('status')} and not being applied")
        rec.pop("applying", None)
        rec["status"] = status
        rec["applied_by"] = by
        rec["applied_at"] = _now()
        rec["result"] = dict(result or {})
        _history(rec, status, by, note=_clean_text(note, 300))

    try:
        rec = _mutate(rid, fn)
    except QueueError:
        return None
    _audit(status, rec, by, result=rec.get("result"), note=_clean_text(note, 300))
    return rec


# ── exports ─────────────────────────────────────────────────────────────
ROW_COLUMNS = ["id", "status", "kind", "title", "tenant", "requested_by", "requested_at", "decided_by", "decided_at",
               "applied_by", "applied_at", "plan_hash", "changes", "items", "comments"]


def rows(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One flat row per request (ROW_COLUMNS): the hook the Excel and PDF
    exports build on, so every format says the same thing."""
    out = []
    for r in items:
        s = r.get("summary") or {}
        out.append({
            "id": r.get("id"), "status": r.get("status"), "kind": r.get("kind_label") or r.get("kind"), "title": r.get("title"),
            "tenant": r.get("tenant_label") or r.get("tenant"), "requested_by": r.get("requested_by"), "requested_at": r.get("requested_at"),
            "decided_by": r.get("decided_by") or "", "decided_at": r.get("decided_at") or "",
            "applied_by": r.get("applied_by") or "", "applied_at": r.get("applied_at") or "", "plan_hash": r.get("plan_hash") or "",
            "changes": ", ".join(f"{k} {v}" for k, v in s.items() if isinstance(v, (int, float)) and v),
            "items": int(r.get("items_total") or len(r.get("items") or [])),
            "comments": " | ".join(f"{c.get('by')}: {c.get('text')}" for c in (r.get("comments") or [])),
        })
    return out


def _item_line(i: Dict[str, Any]) -> str:
    if i.get("method"):
        return f"{i.get('method')} {i.get('endpoint')}" + (f" — {i['note']}" if i.get("note") else "")
    bits = [str(i.get("status") or ""), str(i.get("kind") or ""), str(i.get("name") or "")]
    if i.get("channel"):
        bits.append(f"({i['channel']})")
    if i.get("note"):
        bits.append(f"— {i['note']}")
    return " ".join(b for b in bits if b)


def to_markdown(items: List[Dict[str, Any]], *, title: str = "Change queue") -> str:
    # Titles, names, people and comments are free text: inert in the Markdown.
    items, title = md_safe.escape_data(items), md_safe.text(title)
    lines = [f"# {title}", "", f"Exported {_now()}. {len(items)} request(s).", ""]
    if not items:
        lines.append("No change requests.")
    for r in items:
        lines.append(f"## [{r.get('status')}] {r.get('title')}")
        lines.append(f"- Id: {r.get('id')} · {r.get('kind_label') or r.get('kind')} · tenant {r.get('tenant_label') or r.get('tenant')}")
        lines.append(f"- Requested by {r.get('requested_by')} at {r.get('requested_at')}")
        if r.get("decided_by"):
            lines.append(f"- Decided by {r.get('decided_by')} at {r.get('decided_at')}")
        if r.get("applied_by"):
            lines.append(f"- Applied by {r.get('applied_by')} at {r.get('applied_at')}: {(r.get('result') or {}).get('status', '')}")
        lines.append(f"- Plan hash: `{r.get('plan_hash')}`")
        s = r.get("summary") or {}
        if s:
            lines.append("- Changes: " + ", ".join(f"{k} {v}" for k, v in s.items()))
        its = r.get("items") or []
        if its:
            lines.append("- Items:")
            lines.extend(f"  - {_item_line(i)}" for i in its[:200])
            if len(its) > 200:
                lines.append(f"  - … {len(its) - 200} more")
        for c in r.get("comments") or []:
            lines.append(f"- Comment by {c.get('by')} at {c.get('at')}: {c.get('text')}")
        lines.append("")
    return "\n".join(lines)


ROW_LABELS = {"id": "Request", "status": "Status", "kind": "Kind", "title": "Title", "tenant": "Tenant", "requested_by": "Requested by",
              "requested_at": "Requested at", "decided_by": "Decided by", "decided_at": "Decided at", "applied_by": "Applied by",
              "applied_at": "Applied at", "plan_hash": "Plan hash", "changes": "What it changes", "items": "Items", "comments": "Comments"}


def to_xlsx(items: List[Dict[str, Any]], *, tenant: str = "") -> bytes:
    """The queue as an Excel workbook: Requests (rows(), the same columns
    as the JSON export), Items, Approvals, Comments and History. The names
    are the ones the queue page shows (requester, approver, who applied,
    who commented); the stored payload is not exported. Built with
    xlsx_writer: no cell is ever a formula."""
    import xlsx_writer
    wb = xlsx_writer.Workbook(title="Change queue", subject=tenant or "all tenants", creator="Zscaler Made Easy")
    req = wb.add_sheet("Requests", columns=[ROW_LABELS[c] for c in ROW_COLUMNS])
    for r in rows(items):
        req.append([r[c] for c in ROW_COLUMNS])
    if not items:
        req.append([f"No change requests{' for this tenant' if tenant else ''}."])
    its = wb.add_sheet("Items", columns=["Request", "Title", "Change", "Kind", "Name", "Channel", "Note", "Method", "Endpoint", "Body"])
    apr = wb.add_sheet("Approvals", columns=["Request", "Title", "Status", "Requested by", "Requested at", "Decision", "Decided by",
                                             "Decided at", "Applied by", "Applied at", "Result"])
    com = wb.add_sheet("Comments", columns=["Request", "When", "Who", "Comment"])
    his = wb.add_sheet("Request history", columns=["Request", "When", "Step", "Who", "Comment or note"])
    for r in items:
        rid, title = r.get("id"), r.get("title")
        for i in r.get("items") or []:
            body = i.get("body")
            its.append([rid, title, i.get("status"), i.get("kind"), i.get("name"), i.get("channel"), i.get("note"), i.get("method"),
                        i.get("endpoint"), json.dumps(body, indent=1, default=str)[:4000] if body is not None else None])
        total = int(r.get("items_total") or 0)
        if total > len(r.get("items") or []):
            its.append([rid, title, f"… {total - len(r.get('items') or [])} more items were not kept with the request"])
        decision = {"approved": "Approved", "rejected": "Rejected"}.get(r.get("status"), "")
        if r.get("decided_by") and not decision:
            decision = "Approved"   # applied, failed or stale after an approval
        res = r.get("result") or {}
        apr.append([rid, title, r.get("status"), r.get("requested_by"), r.get("requested_at"), decision, r.get("decided_by") or "",
                    r.get("decided_at") or "", r.get("applied_by") or "", r.get("applied_at") or "",
                    " — ".join(str(x) for x in (res.get("status"), res.get("message") or res.get("error")) if x)])
        for c in r.get("comments") or []:
            com.append([rid, c.get("at"), c.get("by"), c.get("text")])
        for h in r.get("history") or []:
            his.append([rid, h.get("at"), h.get("action"), h.get("by"), h.get("comment") or h.get("note") or ""])
    return wb.to_bytes()


def _keep_last_good(path: str) -> None:
    """The store as it was, kept as a last-good copy (self_heal) before it is replaced."""
    try:
        import self_heal
        self_heal.keep_last_good(path)
    except Exception:  # noqa: BLE001 - never stops a write
        pass
