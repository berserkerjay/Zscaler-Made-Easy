"""Workspace notes: tags, comments and to-dos on any object, per tenant.

An object is anything the app can name for a tenant: a DLP rule, engine or
dictionary, a URL filtering or firewall rule, a URL category, a location
(the console index's kinds), an assessment finding (kind "finding", its
check id) or a page of the app (kind "page"). A note is keyed by
(tenant label, kind, ref): the tenant label is tenant_auth.record_label's
"acme (production)", `ref` is the object's id or name as the app keys it
(for a console-index object, its key, e.g. "rule:web:Block SSN").

These are local notes in the app's own store, never a tenant write. The
store is workspace_notes.json beside the tenant profiles (so /data in the
container; DLP_CHECK_WORKSPACE_NOTES overrides it), owner-only (0600),
replaced atomically and guarded by a lock file so two server processes
never lose each other's writes, the same convention as change_queue.py.

Nothing from a request ever becomes a file name: tenants, kinds and refs
are dictionary keys inside the one store, and a note's id is a hash. Every
field is validated and capped (MAX_*), so a page cannot grow the store
without bound. Every change is recorded in the audit log with who made it
(the server's view of the caller); the text of a comment or to-do is not,
because it may hold customer data.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import safe_files

try:  # POSIX
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore
try:  # Windows
    import msvcrt  # type: ignore
except ImportError:
    msvcrt = None  # type: ignore

STORE_FILE = "workspace_notes.json"
_LOCK = threading.RLock()

MAX_TENANTS = 100
MAX_TENANT_LEN = 200
MAX_NOTES_PER_TENANT = 2000
MAX_KIND_LEN = 40
MAX_REF_LEN = 300
MAX_LABEL_LEN = 300
MAX_HREF_LEN = 300
MAX_TAGS = 20
MAX_TAG_LEN = 40
MAX_COMMENTS = 100
MAX_COMMENT_LEN = 2000
MAX_TODOS = 100
MAX_TODO_LEN = 500
# The whole store, as compact JSON. The caps above multiply out to far more
# (tenants x notes x comments): every change rewrites the store under one
# lock, so a store of hundreds of megabytes would stall every note request.
MAX_STORE_BYTES = 8 * 1024 * 1024

ACTIONS = ("set_tags", "add_tag", "remove_tag", "add_comment", "delete_comment", "add_todo", "set_todo", "delete_todo")
_GROWS = ("set_tags", "add_tag", "add_comment", "add_todo")   # the changes that can make the store bigger

_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,%d}$" % (MAX_KIND_LEN - 1))
# A tag: a word, then words, spaces and a few separators (no quotes, no
# slashes at the start, no control characters).
_TAG_RE = re.compile(r"^[^\W_][\w .:+#/-]*$", re.UNICODE)
# A link back into this app: a same-origin path, never another site.
_HREF_RE = re.compile(r"^/(?!/)[A-Za-z0-9_\-./?=&%#]*$")
_ITEM_ID_RE = re.compile(r"^[a-f0-9]{8,32}$")


class NotesError(ValueError):
    """A refusal the page can show as it is. `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── the store ───────────────────────────────────────────────────────────
def store_path() -> str:
    """workspace_notes.json beside the tenant profiles (DLP_CHECK_PROFILES's
    folder, /data in the container), or DLP_CHECK_WORKSPACE_NOTES."""
    env = os.environ.get("DLP_CHECK_WORKSPACE_NOTES")
    if env:
        return env
    try:
        import tenant_profiles
        folder = os.path.dirname(os.path.abspath(tenant_profiles.store_path()))
    except Exception:  # noqa: BLE001
        folder = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(folder, STORE_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextlib.contextmanager
def _locked() -> Iterator[None]:
    """This process's lock, then an exclusive lock on <store>.lock, so a
    read-modify-write never interleaves with another thread or process."""
    with _LOCK:
        p = store_path()
        safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)) or ".")
        fd = os.open(p + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no cover - Windows
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)


def _read() -> Dict[str, Any]:
    """The store, with anything not of the store's shape left out (a
    hand-edited or damaged file never breaks a read): tenants map to
    buckets, buckets hold notes, notes are objects with list fields."""
    try:
        with open(store_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("tenants"), dict):
            data["tenants"] = {t: _bucket_shape(b) for t, b in data["tenants"].items() if isinstance(t, str) and isinstance(b, dict)}
            return data
    except (OSError, ValueError, RecursionError):
        pass
    return {"version": 1, "tenants": {}}


def _bucket_shape(bucket: Dict[str, Any]) -> Dict[str, Any]:
    notes = bucket.get("notes")
    kept = {}
    for nid, note in (notes.items() if isinstance(notes, dict) else []):
        if isinstance(note, dict):
            for key in ("tags", "comments", "todos"):
                items = note.get(key)
                note[key] = [x for x in items if isinstance(x, (str if key == "tags" else dict))] if isinstance(items, list) else []
            kept[nid] = note
    return dict(bucket, notes=kept)


def _write(data: Dict[str, Any]) -> None:
    """Owner-only, atomic: a unique temporary file in the same folder,
    flushed, then renamed over the store."""
    p = store_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".workspace_notes.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with contextlib.suppress(Exception):   # a last-good copy for self_heal; never stops a write
            import self_heal
            self_heal.keep_last_good(p)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ── validation ──────────────────────────────────────────────────────────
# Never kept in a note: C1 control characters, the line and paragraph
# separators, and the bidirectional overrides and isolates that can make
# text read differently from what it is (CWE-451, "Trojan Source").
_INVISIBLE = {chr(c) for c in range(0x80, 0xA0)} | {"\u2028", "\u2029"} | {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}


def _clean(text: Any, limit: int, *, multiline: bool = False) -> str:
    """Printable text only (a newline kept where `multiline`), trimmed;
    longer than `limit` is refused rather than silently cut."""
    s = "".join(ch for ch in str(text if text is not None else "")
                if (multiline and ch == "\n") or (ch >= " " and ch != "\x7f" and ch not in _INVISIBLE))
    s = s.strip()
    if len(s) > limit:
        raise NotesError(f"too long: at most {limit} characters")
    return s


def clean_tenant(tenant: Any) -> str:
    t = _clean(tenant, MAX_TENANT_LEN)
    if not t:
        raise NotesError("pick a tenant first: notes are kept per tenant")
    return t


def clean_kind(kind: Any) -> str:
    k = str(kind or "").strip().lower()
    if not _KIND_RE.match(k):
        raise NotesError("kind must be a short lower-case word such as rule, dictionary, url_category, finding or page")
    return k


def clean_ref(ref: Any) -> str:
    r = _clean(ref, MAX_REF_LEN)
    if not r:
        raise NotesError("say which object the note is on (its id or name)")
    return r


def clean_tag(tag: Any) -> str:
    t = re.sub(r"\s+", " ", _clean(tag, MAX_TAG_LEN))
    if not t or not _TAG_RE.match(t):
        raise NotesError(f"a tag is a word or short phrase of up to {MAX_TAG_LEN} letters, digits, spaces and - _ . : + # /")
    return t


def clean_href(href: Any) -> str:
    h = _clean(href, MAX_HREF_LEN)
    if h and not _HREF_RE.match(h):
        raise NotesError("a link must be a path in this app, such as /report/shadow")
    return h


def note_id(kind: str, ref: str) -> str:
    """A note's id: a hash of (kind, ref), safe in a URL and never a path."""
    return hashlib.sha256(f"{kind}\x00{ref}".encode("utf-8")).hexdigest()[:32]


def _copy(x: Any) -> Any:
    return json.loads(json.dumps(x))


def _empty(note: Dict[str, Any]) -> bool:
    return not (note.get("tags") or note.get("comments") or note.get("todos"))


def _audit(action: str, tenant: str, kind: str, ref: str, by: str, **extra: Any) -> None:
    try:
        import audit
        audit.record("workspace_note", actor=by or None, action=action, tenant=tenant, kind=kind, ref=ref[:120], **extra)
    except Exception as e:  # noqa: BLE001 - the note stands; the lost audit line is reported loudly
        try:
            import audit
            audit.report_failure(f"the workspace note step '{action}'", e)
        except Exception:  # noqa: BLE001
            pass


# ── reading ─────────────────────────────────────────────────────────────
def get(tenant: str, kind: str, ref: str) -> Optional[Dict[str, Any]]:
    tenant, kind, ref = clean_tenant(tenant), clean_kind(kind), clean_ref(ref)
    with _LOCK:
        note = ((_read()["tenants"].get(tenant) or {}).get("notes") or {}).get(note_id(kind, ref))
    return dict(_copy(note), tenant=tenant) if note else None


def list_notes(tenant: Optional[str] = None, *, tag: str = "", kind: str = "") -> List[Dict[str, Any]]:
    """Every note of one tenant (or of every tenant when `tenant` is None),
    most recently changed first, optionally only those with `tag` or of `kind`."""
    with _LOCK:
        data = _read()
    want = clean_tenant(tenant) if tenant is not None else None
    tag_l = str(tag or "").strip().lower()
    out = []
    for t, bucket in data["tenants"].items():
        if want is not None and t != want:
            continue
        for note in (bucket.get("notes") or {}).values():
            if tag_l and tag_l not in [x.lower() for x in note.get("tags") or []]:
                continue
            if kind and note.get("kind") != kind:
                continue
            out.append(dict(_copy(note), tenant=t))
    out.sort(key=lambda n: n.get("updated_at") or "", reverse=True)
    return out


def tenants() -> List[Dict[str, Any]]:
    """The tenants that have notes, with counts and their tags."""
    with _LOCK:
        data = _read()
    out = []
    for t, bucket in sorted(data["tenants"].items(), key=lambda kv: kv[0].lower()):
        notes = list((bucket.get("notes") or {}).values())
        if not notes:
            continue
        tags = sorted({x for n in notes for x in n.get("tags") or []}, key=str.lower)
        out.append({"tenant": t, "notes": len(notes), "tags": tags,
                    "open_todos": sum(1 for n in notes for d in n.get("todos") or [] if not d.get("done"))})
    return out


# ── changing ────────────────────────────────────────────────────────────
def apply(tenant: str, kind: str, ref: str, action: str, *, by: str, label: str = "", href: str = "",
          tags: Optional[List[Any]] = None, tag: str = "", text: str = "", item_id: str = "", done: bool = True) -> Optional[Dict[str, Any]]:
    """One change to the note on (tenant, kind, ref), created on first use.
    Returns the note, or None when the change left it empty (it is then
    removed). `by` is the server's view of the caller, never a page field."""
    tenant, kind, ref = clean_tenant(tenant), clean_kind(kind), clean_ref(ref)
    if action not in ACTIONS:
        raise NotesError(f"unknown action: say one of {', '.join(ACTIONS)}")
    if not by:
        raise NotesError("could not tell who is writing this note (sign in again)", 401)
    label = _clean(label, MAX_LABEL_LEN)
    href = clean_href(href)
    nid = note_id(kind, ref)
    with _locked():
        data = _read()
        bucket = data["tenants"].get(tenant)
        if bucket is None:
            if len(data["tenants"]) >= MAX_TENANTS:
                raise NotesError(f"notes are kept for at most {MAX_TENANTS} tenants; delete the notes of a tenant you no longer work on", 409)
            bucket = data["tenants"][tenant] = {"notes": {}}
        notes = bucket.setdefault("notes", {})
        note = notes.get(nid)
        if note is None:
            if action in ("remove_tag", "delete_comment", "set_todo", "delete_todo"):
                raise NotesError("there is no note on this object", 404)
            if len(notes) >= MAX_NOTES_PER_TENANT:
                raise NotesError(f"a tenant holds at most {MAX_NOTES_PER_TENANT} notes; delete notes you no longer need", 409)
            note = {"id": nid, "kind": kind, "ref": ref, "label": label or ref, "href": href, "tags": [], "comments": [], "todos": [],
                    "created_at": _now(), "created_by": by}
        else:
            note = _copy(note)
        if label:
            note["label"] = label
        if href:
            note["href"] = href
        extra: Dict[str, Any] = {}
        if action == "set_tags":
            raw = list(tags or [])
            if len(raw) > MAX_TAGS:
                raise NotesError(f"at most {MAX_TAGS} tags on one object")
            seen: List[str] = []
            for t in raw:
                c = clean_tag(t)
                if c.lower() not in [s.lower() for s in seen]:
                    seen.append(c)
            note["tags"] = seen
            extra["tags"] = seen
        elif action == "add_tag":
            c = clean_tag(tag)
            if c.lower() not in [s.lower() for s in note["tags"]]:
                if len(note["tags"]) >= MAX_TAGS:
                    raise NotesError(f"at most {MAX_TAGS} tags on one object")
                note["tags"].append(c)
            extra["tag"] = c
        elif action == "remove_tag":
            c = str(tag or "").strip().lower()
            note["tags"] = [t for t in note["tags"] if t.lower() != c]
            extra["tag"] = str(tag or "")[:MAX_TAG_LEN]
        elif action in ("add_comment", "add_todo"):
            limit, key, cap = (MAX_COMMENT_LEN, "comments", MAX_COMMENTS) if action == "add_comment" else (MAX_TODO_LEN, "todos", MAX_TODOS)
            body = _clean(text, limit, multiline=action == "add_comment")
            if not body:
                raise NotesError("write something first")
            if len(note[key]) >= cap:
                raise NotesError(f"at most {cap} {'comments' if key == 'comments' else 'to-dos'} on one object; delete old ones first", 409)
            item = {"id": secrets.token_hex(8), "text": body, "at": _now(), "by": by}
            if key == "todos":
                item["done"] = False
            note[key].append(item)
            extra["item"] = item["id"]
        else:  # delete_comment, set_todo, delete_todo
            iid = str(item_id or "")
            if not _ITEM_ID_RE.match(iid):
                raise NotesError("say which comment or to-do (its id)")
            key = "comments" if action == "delete_comment" else "todos"
            hit = next((x for x in note[key] if x.get("id") == iid), None)
            if hit is None:
                raise NotesError("that comment or to-do is gone (reload)", 404)
            if action == "set_todo":
                hit["done"] = bool(done)
                if hit["done"]:
                    hit["done_at"], hit["done_by"] = _now(), by
                else:
                    hit.pop("done_at", None)
                    hit.pop("done_by", None)
                extra["done"] = hit["done"]
            else:
                note[key] = [x for x in note[key] if x.get("id") != iid]
            extra["item"] = iid
        note["updated_at"], note["updated_by"] = _now(), by
        if _empty(note):
            notes.pop(nid, None)
            if not notes:
                data["tenants"].pop(tenant, None)
            result = None
        else:
            notes[nid] = note
            result = dict(_copy(note), tenant=tenant)
        if action in _GROWS and len(json.dumps(data, separators=(",", ":"))) > MAX_STORE_BYTES:
            raise NotesError(f"the notes store is full ({MAX_STORE_BYTES // (1024 * 1024)} MB); delete notes or comments you no longer need", 413)
        _write(data)
    _audit(action, tenant, kind, ref, by, **extra)
    return result


def delete(tenant: str, kind: str, ref: str, *, by: str) -> bool:
    """Remove the whole note on (tenant, kind, ref). False when there was none."""
    tenant, kind, ref = clean_tenant(tenant), clean_kind(kind), clean_ref(ref)
    if not by:
        raise NotesError("could not tell who is deleting this note (sign in again)", 401)
    with _locked():
        data = _read()
        bucket = data["tenants"].get(tenant) or {}
        gone = (bucket.get("notes") or {}).pop(note_id(kind, ref), None)
        if gone is None:
            return False
        if not bucket.get("notes"):
            data["tenants"].pop(tenant, None)
        _write(data)
    _audit("delete_note", tenant, kind, ref, by)
    return True
