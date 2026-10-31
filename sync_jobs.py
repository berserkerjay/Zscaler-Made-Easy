"""Scheduled sync, done safely: plans for a person to approve, never an
unattended write.

A sync job names a source (a saved tenant profile, or a snapshot saved
beside the profiles; a template once a template provider is registered,
see register_template_source), one to MAX_TARGETS target tenant profiles,
what to keep in step (resource groups: ZIA Cloud Firewall rules, ZIA URL
filtering rules, the ZPA access policy; optionally only the rules carrying
a rule label, or whose name starts with a prefix) and how often to run
(never on its own, or every 1, 4, 12, 24 or 168 hours).

Each run only READS. It reads the source once (rules as rows with names,
not ids: rule_csv's format), then for every target reads the target and
plans the change that would make it match (the Bulk changes engine's
plan: adds, updates, and, only when the job says so, deletes of rules
within the same selection that the source does not have). A plan with
something to change is filed in the change queue (change_queue.py) as a
pending request with its plan hash, requested by the job's owner (or by
whoever clicked Run now), so another writer approves it (four-eyes). A
newer run's plan for the same job, target and policy marks the older open
request stale. Nothing is applied here: an approved request is applied
from the queue by a named writer, through write mode, the assessor's
name, the typed confirmation, a fresh plan whose hash must still match
(else the request is marked stale and nothing is written), the read-back
and the Undo of the Bulk changes engine.

The boundary with snapshot diff and restore (another part of the app):
    source_snapshot(client, groups, selection, say)   -> snapshot
    target_plan(snapshot, policy, client, scope, job)  -> prepared plan
A different diff can stand in for target_plan as long as it returns an
admin_ops prepared operation (plan_hash, items, spec).

Jobs and their history live in sync_jobs.json beside change_requests.json
(owner-only, replaced atomically, guarded like the queue's store). Every
create, delete, run and filing is in the audit log with the actor. Runs
read only what each profile's saved Scope page selection puts in scope;
a target that does not have the job's policy in scope is reported and
not read. The server's timer (dlp_api_server) starts due jobs; one run at
a time.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

import safe_files

try:  # POSIX
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore

STORE_FILE = "sync_jobs.json"
MAX_JOBS = 50
MAX_TARGETS = 10
HISTORY_KEEP = 50
INTERVALS = (0, 1, 4, 12, 24, 168)        # hours; 0 = only when someone clicks Run now
GROUPS: Dict[str, Dict[str, str]] = {
    "zia_firewall": {"policy": "firewall", "label": "ZIA Cloud Firewall rules"},
    "zia_url_filtering": {"policy": "url_filtering", "label": "ZIA URL filtering rules"},
    "zpa_access": {"policy": "zpa_access", "label": "ZPA access policy rules"},
}
SOURCE_KINDS = ("profile", "snapshot", "template")
_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_SELECT = re.compile(r"^[^\x00-\x1f\x7f]{0,128}$")
_JOB_ID = re.compile(r"^sj-[0-9a-f]{12}$")
_LOCK = threading.RLock()
_RUNNING: Dict[str, str] = {}     # job id -> run id, in this process
_RUN_GUARD = threading.Lock()


class SyncError(ValueError):
    """A refusal the page can show as it is; `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: Optional[datetime]) -> Optional[str]:
    return t.isoformat(timespec="seconds") if t else None


def _parse(t: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(t))
    except (TypeError, ValueError):
        return None


# ── the store ───────────────────────────────────────────────────────────
def store_path() -> str:
    env = os.environ.get("DLPCHECK_SYNC_JOBS_FILE")
    if env:
        return env
    try:
        import change_queue
        return os.path.join(os.path.dirname(os.path.abspath(change_queue.store_path())), STORE_FILE)
    except Exception:  # noqa: BLE001
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), STORE_FILE)


@contextlib.contextmanager
def _locked() -> Iterator[None]:
    with _LOCK:
        p = store_path()
        safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)) or ".")
        fd = os.open(p + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _read() -> Dict[str, Any]:
    try:
        with open(store_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("jobs"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "jobs": {}}


def _write(data: Dict[str, Any]) -> None:
    p = store_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".sync_jobs.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _audit(action: str, job: Dict[str, Any], by: str, **extra: Any) -> None:
    try:
        import audit
        audit.record("sync_job", actor=by or None, action=action, job=job.get("id"), name=job.get("name"), **extra)
    except Exception as e:  # noqa: BLE001
        with contextlib.suppress(Exception):
            import audit
            audit.report_failure(f"the sync job step '{action}' on {job.get('id')}", e)


def _copy(x: Any) -> Any:
    return json.loads(json.dumps(x))


# ── jobs ────────────────────────────────────────────────────────────────
def _profiles() -> Dict[str, Dict[str, Any]]:
    import tenant_profiles
    return {str(p.get("id")): p for p in tenant_profiles.list_profiles()}


def _snapshots() -> Dict[str, Dict[str, Any]]:
    import tenant_profiles
    return {str(s.get("id")): s for s in tenant_profiles.list_snapshots()}


_TEMPLATE_SOURCE: Dict[str, Callable[..., Any]] = {}


def register_template_source(list_fn: Callable[[], List[Dict[str, Any]]], client_fn: Callable[[str], Any]) -> None:
    """Let jobs use templates as their source: `list_fn()` lists {id, name,
    scopes}, `client_fn(id)` returns a read-only SDK-shaped client over the
    template (an offline_tenant client). Until a provider registers, a
    template source is refused."""
    _TEMPLATE_SOURCE["list"], _TEMPLATE_SOURCE["client"] = list_fn, client_fn


def _templates() -> Dict[str, Dict[str, Any]]:
    fn = _TEMPLATE_SOURCE.get("list")
    if not fn:
        return {}
    try:
        return {str(t.get("id")): t for t in fn() or [] if isinstance(t, dict)}
    except Exception:  # noqa: BLE001
        return {}


def sources() -> Dict[str, Any]:
    """What the page can offer as a source and a target (no secrets)."""
    profs = _profiles()
    return {"profiles": [{"id": k, "name": p.get("name") or k, "tenant": p.get("vanity_domain") or "", "has_secret": bool(p.get("has_secret")),
                          "scopes": list(p.get("scopes") or []) if isinstance(p.get("scopes"), list) else []} for k, p in profs.items()],
            "snapshots": [{"id": k, "label": s.get("tenant_label") or k, "saved_at": s.get("saved_at"), "scopes": s.get("scopes") or []}
                          for k, s in _snapshots().items()],
            "templates": [{"id": k, "name": t.get("name") or k} for k, t in _templates().items()],
            "groups": [{"id": k, **v} for k, v in GROUPS.items()], "intervals": list(INTERVALS),
            "templates_available": bool(_TEMPLATE_SOURCE)}


def _clean(fields: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(fields, dict):
        raise SyncError("The job must be an object.")
    name = str(fields.get("name") or "").strip()
    if not _NAME.match(name):
        raise SyncError("Give the job a name (at most 80 characters, no control characters).")
    src = fields.get("source") if isinstance(fields.get("source"), dict) else {}
    kind, sid = str(src.get("kind") or ""), str(src.get("id") or "")
    if kind not in SOURCE_KINDS:
        raise SyncError("Pick the source: a tenant profile, a saved snapshot or a template.")
    if kind == "profile":
        p = _profiles().get(sid)
        if not p:
            raise SyncError("The source profile does not exist.")
        if not p.get("has_secret"):
            raise SyncError("The source profile does not remember its secret, so a scheduled run cannot sign in to it.")
    elif kind == "snapshot":
        if sid not in _snapshots():
            raise SyncError("The source snapshot does not exist.")
    elif sid not in _templates():
        raise SyncError("Templates are not available as a source in this version." if not _TEMPLATE_SOURCE else "The source template does not exist.")
    targets = fields.get("targets")
    if not isinstance(targets, list) or not targets:
        raise SyncError("Pick at least one target tenant profile.")
    targets = [str(t) for t in targets]
    if len(targets) > MAX_TARGETS:
        raise SyncError(f"At most {MAX_TARGETS} target profiles per job.")
    if len(set(targets)) != len(targets):
        raise SyncError("A target profile is listed twice.")
    profs = _profiles()
    for t in targets:
        if t not in profs:
            raise SyncError("A target profile does not exist.")
        if not profs[t].get("has_secret"):
            raise SyncError(f"The target profile {profs[t].get('name') or t} does not remember its secret, so a run cannot sign in to it.")
        if kind == "profile" and t == sid:
            raise SyncError("The source cannot also be a target.")
    groups = fields.get("groups")
    if not isinstance(groups, list) or not groups or any(g not in GROUPS for g in groups):
        raise SyncError(f"Pick what to keep in step: {', '.join(GROUPS)}.")
    label, prefix = str(fields.get("label") or "").strip(), str(fields.get("prefix") or "")
    if not _SELECT.match(label) or not _SELECT.match(prefix):
        raise SyncError("The label and the prefix are at most 128 characters, with no control characters.")
    if label and groups == ["zpa_access"]:
        raise SyncError("ZPA access rules have no rule labels: select them by name prefix instead.")
    try:
        interval = int(fields.get("interval_hours") or 0)
    except (TypeError, ValueError):
        interval = -1
    if interval not in INTERVALS:
        raise SyncError(f"How often: one of {', '.join(str(i) for i in INTERVALS)} hours (0: only when you click Run now).")
    return {"name": name, "source": {"kind": kind, "id": sid}, "targets": targets, "groups": sorted(set(groups), key=list(GROUPS).index),
            "label": label, "prefix": prefix, "include_deletes": fields.get("include_deletes") is True,
            "new_rules_enabled": fields.get("new_rules_enabled") is True, "interval_hours": interval}


def create_job(fields: Dict[str, Any], *, by: str) -> Dict[str, Any]:
    """Save a job. `by` is the server's view of the caller (its owner)."""
    if not str(by or "").strip():
        raise SyncError("Could not tell who you are (sign in again).", 401)
    job = _clean(fields)
    now = _now()
    job.update(id="sj-" + secrets.token_hex(6), created_by=str(by), created_at=_iso(now), updated_at=_iso(now), enabled=True,
               last_run_at=None, next_run_at=_iso(now + timedelta(hours=job["interval_hours"])) if job["interval_hours"] else None,
               history=[])
    with _locked():
        data = _read()
        if len(data["jobs"]) >= MAX_JOBS:
            raise SyncError(f"At most {MAX_JOBS} sync jobs; delete one first.", 409)
        data["jobs"][job["id"]] = job
        _write(data)
    _audit("created", job, by, source=job["source"], targets=job["targets"], groups=job["groups"], interval_hours=job["interval_hours"],
           include_deletes=job["include_deletes"])
    return _copy(job)


def list_jobs() -> List[Dict[str, Any]]:
    with _locked():
        jobs = list(_read()["jobs"].values())
    jobs.sort(key=lambda j: str(j.get("created_at") or ""), reverse=True)
    for j in jobs:
        j["running"] = j.get("id") in _RUNNING
    return jobs


def get_job(jid: str) -> Optional[Dict[str, Any]]:
    if not isinstance(jid, str) or not _JOB_ID.match(jid):
        return None
    with _locked():
        j = _read()["jobs"].get(jid)
    if j:
        j["running"] = jid in _RUNNING
    return j


def _mutate(jid: str, fn: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    if not isinstance(jid, str) or not _JOB_ID.match(jid):
        raise SyncError("No such sync job.", 404)
    with _locked():
        data = _read()
        job = data["jobs"].get(jid)
        if not job:
            raise SyncError("No such sync job (it may have been deleted; reload).", 404)
        fn(job)
        job["updated_at"] = _iso(_now())
        _write(data)
        return _copy(job)


def set_enabled(jid: str, enabled: bool, *, by: str) -> Dict[str, Any]:
    def fn(job: Dict[str, Any]) -> None:
        job["enabled"] = bool(enabled)
        if enabled and job.get("interval_hours"):
            job["next_run_at"] = _iso(_now() + timedelta(hours=int(job["interval_hours"])))
    job = _mutate(jid, fn)
    _audit("enabled" if enabled else "paused", job, by)
    return job


def delete_job(jid: str, *, by: str) -> Dict[str, Any]:
    if jid in _RUNNING:
        raise SyncError("This job is running right now; wait for the run to finish.", 409)
    with _locked():
        data = _read()
        job = data["jobs"].pop(jid, None) if isinstance(jid, str) else None
        if not job:
            raise SyncError("No such sync job.", 404)
        _write(data)
    _audit("deleted", job, by)
    return job


def due_jobs(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    now = now or _now()
    out = []
    for j in list_jobs():
        nxt = _parse(j.get("next_run_at"))
        if j.get("enabled") and j.get("interval_hours") and nxt and nxt <= now and not j.get("running"):
            out.append(j)
    return out


# ── the boundary: source snapshot -> target plan ────────────────────────
def source_snapshot(client: Any, groups: Sequence[str], selection: Dict[str, Any], say: Callable[[str], None],
                    cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read the source (read-only) and keep the selected rules as rows with
    names (rule_csv's format), per policy: {policies: {policy: {rows, total}}}."""
    import ops_rule_csv as orc
    out: Dict[str, Any] = {"policies": {}, "errors": {}}
    prefix, label = str(selection.get("prefix") or ""), str(selection.get("label") or "")
    for g in groups:
        policy = GROUPS[g]["policy"]
        try:
            rules = orc.read_rules(client, policy, cancel)
        except Exception as e:  # noqa: BLE001 - reported per policy
            out["errors"][policy] = str(e)[:300]
            continue
        names = orc.Names(client, say, cancel)
        orc.seed_names(policy, rules, names)
        picked = [r for r in rules if not orc._is_default(policy, r) and not orc.lock_reason(policy, r)
                  and orc._filter_match(policy, r, {"prefix": prefix, "label": label}, names)]
        rows = orc.export_rows(policy, picked, names)
        for r in rows:
            r["order"] = ""       # a sync keeps each target's own order: new rules go to the bottom, above the Default rule
        out["policies"][policy] = {"rows": rows, "total": len(rules)}
        say(f"Source {GROUPS[g]['label']}: {len(rows)} of {len(rules)} rules selected.")
    return out


def target_plan(snapshot: Dict[str, Any], policy: str, client: Any, scope: Dict[str, Any], job: Dict[str, Any],
                say: Callable[[str], None], cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """The change that makes the target's selected rules match the source:
    a Bulk changes plan (admin_ops.plan) of the CSV import type, read-only."""
    import admin_ops
    import ops_rule_csv as orc
    import rule_csv as rc
    rows = (snapshot.get("policies", {}).get(policy) or {}).get("rows") or []
    spec = {"type": orc.type_for(policy), "policy": policy, "csv": rc.to_csv(policy, rows),
            "remove_missing": bool(job.get("include_deletes")), "new_rules_enabled": bool(job.get("new_rules_enabled")),
            "filter": {"label": job.get("label") or "", "prefix": job.get("prefix") or ""}}
    if not rows and not job.get("include_deletes"):
        return {"status": "nothing_to_do", "counts": {"change": 0}, "items": [], "spec": spec, "plan_hash": "", "warnings": []}
    if not rows:
        # An empty source with deletes on would plan to delete every selected rule of the target: refused outright.
        raise admin_ops.OperationError("The source has no selected rules, so nothing is planned (with deletes on, an empty source would remove "
                                       "every selected rule of the target).")
    return admin_ops.plan(client, spec, scope=scope, log=say, cancel=cancel)


# ── a run ───────────────────────────────────────────────────────────────
def profile_scope(profile: Dict[str, Any]) -> Dict[str, Any]:
    """admin_ops.scope_for the profile's saved Scope page selection."""
    import admin_ops
    raw = profile.get("scopes")
    sc = [s.strip() for s in raw.split(",")] if isinstance(raw, str) else [str(s) for s in raw] if isinstance(raw, (list, tuple)) else []
    ch = profile.get("channels") if isinstance(profile.get("channels"), dict) else {}
    return admin_ops.scope_for([s for s in sc if s], ch)


def _policy_in_scope(scope: Dict[str, Any], policy: str) -> Optional[str]:
    import admin_ops
    import ops_rule_csv as orc
    try:
        admin_ops.require_scope({"type": orc.type_for(policy), "policy": policy}, scope)
        return None
    except admin_ops.OperationError as e:
        return str(e)


def queue_items(prepared: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The plan's changes in the queue's item shape (status, kind, name, note)."""
    verbs = {"rule_add": "add", "rule_update": "update", "rule_delete": "delete", "rule_move": "move"}
    out = []
    for u in prepared.get("items") or []:
        if u.get("status") != "change":
            continue
        note = ""
        if isinstance(u.get("after"), dict) and isinstance(u.get("before"), dict):
            note = "; ".join(f"{k}: {u['before'].get(k, '')} → {v}" for k, v in u["after"].items())
        elif isinstance(u.get("after"), dict):
            note = "; ".join(f"{k}: {v}" for k, v in u["after"].items())
        elif u.get("kind") == "rule_move":
            note = f"position {u.get('before')} → {u.get('after')}" if not isinstance(u.get("before"), list) else "new order"
        out.append({"status": verbs.get(u.get("kind"), u.get("kind")), "kind": (u.get("object") or {}).get("policy_label") or "",
                    "name": (u.get("object") or {}).get("name") or "", "note": (note or u.get("reason") or "")[:400]})
    return out


def _supersede(job_id: str, target: str, policy: str, keep_hash: str, by: str) -> List[str]:
    """Mark an older open request of this job, target and policy stale."""
    import change_queue
    out = []
    for r in change_queue.list_requests(statuses=list(change_queue.OPEN_STATUSES)):
        p = r.get("payload") or {}
        if (r.get("kind") == "admin_operation" and p.get("job_id") == job_id and p.get("target_profile") == target
                and p.get("policy") == policy and r.get("plan_hash") != keep_hash and not r.get("applying")):
            if change_queue.supersede(r["id"], by=by, reason="a newer sync run planned this target again"):
                out.append(r["id"])
    return out


class Deps:
    """What a run needs from the server: build_client(creds) -> SDK client,
    tenant_key(creds) -> (queue key, label), notify(subject, body) -> list."""

    def __init__(self, build_client: Callable[[Dict[str, str]], Any], tenant_key: Callable[[Dict[str, str]], Tuple[str, str]],
                 notify: Optional[Callable[[str, str], List[Dict[str, Any]]]] = None):
        self.build_client = build_client
        self.tenant_key = tenant_key
        self.notify = notify


def _close(client: Any) -> None:
    fn = getattr(client, "close", None)
    if callable(fn):
        with contextlib.suppress(Exception):
            fn()


def _source_client(job: Dict[str, Any], deps: Deps) -> Tuple[Any, Dict[str, Any], str]:
    """(client, scope, label) of the job's source; SyncError when unusable."""
    import tenant_profiles
    src = job["source"]
    if src["kind"] == "profile":
        full = tenant_profiles.get(src["id"], with_secret=True)
        if not full:
            raise SyncError("the source profile no longer exists")
        if not any(full.get(f) for f in tenant_profiles.SECRET_FIELDS):
            raise SyncError("the source profile does not remember its secret")
        return deps.build_client(tenant_profiles.creds_from(full)), profile_scope(full), str(full.get("name") or src["id"])
    if src["kind"] == "snapshot":
        import admin_ops
        import offline_tenant as ot
        try:
            st = ot.open_saved(src["id"])
        except Exception as e:  # noqa: BLE001
            raise SyncError(f"the source snapshot cannot be opened: {str(e)[:200]}") from None
        meta = st.meta
        return ot.OfflineSdkClient(st, ot.creds_for(st)), admin_ops.scope_for(list(meta.get("scopes") or []), dict(meta.get("channels") or {})), st.label
    fn = _TEMPLATE_SOURCE.get("client")
    if not fn:
        raise SyncError("templates are not available as a source in this version")
    import admin_ops
    t = _templates().get(src["id"]) or {}
    return fn(src["id"]), admin_ops.scope_for(list(t.get("scopes") or []), dict(t.get("channels") or {})), str(t.get("name") or src["id"])


def run_job(jid: str, *, trigger: str, by: str, deps: Deps, say: Optional[Callable[[str], None]] = None,
            cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Run a job once: read, plan, file. Never writes to a tenant. Returns
    the run record (also kept in the job's history)."""
    import change_queue
    import tenant_profiles
    log = say or (lambda m: None)
    job = get_job(jid)
    if not job:
        raise SyncError("No such sync job.", 404)
    # A scheduled run files its plans in the owner's name (so another writer
    # approves them); Run now files them in the clicker's name.
    by = str(job.get("created_by") or "") if trigger == "schedule" else (str(by or "").strip() or str(job.get("created_by") or ""))
    with _RUN_GUARD:
        if jid in _RUNNING:
            raise SyncError("This job is already running.", 409)
        run_id = "run-" + secrets.token_hex(5)
        _RUNNING[jid] = run_id
    started = _now()
    run: Dict[str, Any] = {"id": run_id, "at": _iso(started), "trigger": trigger, "by": by, "targets": [], "source": None, "errors": []}
    filed: List[Dict[str, Any]] = []
    try:
        log(f"Sync job '{job['name']}': reading the source. Nothing is written to any tenant.")
        src_client = None
        try:
            src_client, src_scope, src_label = _source_client(job, deps)
            run["source"] = src_label
            groups = []
            for g in job["groups"]:
                why = _policy_in_scope(src_scope, GROUPS[g]["policy"])
                if why:
                    run["errors"].append(f"source: {GROUPS[g]['label']} not in scope: {why}")
                else:
                    groups.append(g)
            snap = source_snapshot(src_client, groups, {"label": job.get("label"), "prefix": job.get("prefix")}, log, cancel)
            for p, e in snap["errors"].items():
                run["errors"].append(f"source {p}: {e}")
        except SyncError as e:
            run["errors"].append(f"source: {e}")
            snap = {"policies": {}}
        except Exception as e:  # noqa: BLE001
            run["errors"].append(f"source: {type(e).__name__}: {str(e)[:200]}")
            snap = {"policies": {}}
        finally:
            if src_client is not None:
                _close(src_client)
        for pid in job["targets"]:
            if cancel is not None and cancel.is_set():
                run["errors"].append("stopped before every target was read")
                break
            run["targets"].extend(_run_target(job, pid, snap, deps, by, run_id, log, cancel, filed))
    finally:
        with _RUN_GUARD:
            _RUNNING.pop(jid, None)
    run["finished_at"] = _iso(_now())
    run["filed"] = [f["id"] for f in filed]
    run["status"] = "error" if run["errors"] and not run["targets"] else ("planned" if filed else ("partial" if run["errors"] or any(
        t["status"] == "error" for t in run["targets"]) else "in_sync"))
    if filed and deps.notify is not None:
        run["notified"] = _notify(job, run, filed, deps)

    def record(j: Dict[str, Any]) -> None:
        j["last_run_at"] = run["at"]
        if j.get("interval_hours"):
            j["next_run_at"] = _iso(_now() + timedelta(hours=int(j["interval_hours"])))
        j["history"] = ([run] + list(j.get("history") or []))[:HISTORY_KEEP]
    with contextlib.suppress(SyncError):
        _mutate(jid, record)
    _audit("run", job, by, run=run_id, trigger=trigger, status=run["status"], filed=run["filed"],
           targets=[{k: t.get(k) for k in ("profile", "policy", "status", "request")} for t in run["targets"]])
    return run


def _run_target(job: Dict[str, Any], pid: str, snap: Dict[str, Any], deps: Deps, by: str, run_id: str, log: Callable[[str], None],
                cancel: Optional[threading.Event], filed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    import change_queue
    import tenant_profiles
    out: List[Dict[str, Any]] = []
    full = tenant_profiles.get(pid, with_secret=True)
    name = str((full or {}).get("name") or pid)
    pols = [GROUPS[g]["policy"] for g in job["groups"]]

    def rec(policy: str, status: str, **kw: Any) -> None:
        out.append(dict({"profile": pid, "profile_name": name, "policy": policy, "status": status}, **kw))

    if not full:
        for p in pols:
            rec(p, "error", message="the target profile no longer exists")
        return out
    scope = profile_scope(full)
    todo = []
    for p in pols:
        why = _policy_in_scope(scope, p)
        if why:
            rec(p, "not_in_scope", message=f"not read: {why}")
        elif p not in snap.get("policies", {}):
            rec(p, "error", message="the source could not be read for this policy")
        else:
            todo.append(p)
    if not todo:
        return out
    client = None
    try:
        creds = tenant_profiles.creds_from(full)
        client = deps.build_client(creds)
        tk, label = deps.tenant_key(creds)
    except Exception as e:  # noqa: BLE001
        msg = _scrub(f"{type(e).__name__}: {str(e)[:200]}", full)
        for p in todo:
            rec(p, "error", message=f"sign-in: {msg}")
        if client is not None:
            _close(client)
        return out
    try:
        for p in todo:
            log(f"Target {name}: planning {p}…")
            try:
                prep = target_plan(snap, p, client, scope, job, log, cancel)
            except Exception as e:  # noqa: BLE001
                rec(p, "error", message=_scrub(str(e)[:300], full))
                continue
            counts = prep.get("csv_counts") or {}
            if prep.get("status") == "nothing_to_do" or not (prep.get("counts") or {}).get("change"):
                stale = _supersede(job["id"], pid, p, "", by)
                rec(p, "in_sync", message="nothing to change", superseded=stale, excluded=(prep.get("counts") or {}).get("excluded", 0))
                continue
            if prep.get("status") == "blocked":
                rec(p, "error", message="; ".join(prep.get("blockers") or [])[:300])
                continue
            stale = _supersede(job["id"], pid, p, prep["plan_hash"], by)
            payload = {"operation": prep["spec"], "confirm_phrase": prep.get("confirm_phrase") or "", "product": prep.get("product"),
                       "source": "sync", "job_id": job["id"], "job_name": job["name"], "run_id": run_id, "target_profile": pid, "policy": p}
            title = f"Sync '{job['name']}': {GROUPS[_group_of(p)]['label']} → {label}"
            summary = {"add": counts.get("rule_add", 0), "update": counts.get("rule_update", 0), "move": counts.get("rule_move", 0),
                       "delete": counts.get("rule_delete", 0), "excluded": (prep.get("counts") or {}).get("excluded", 0)}
            try:
                req = change_queue.file_request(kind="admin_operation", tenant=tk, tenant_label=label, title=title, summary=summary,
                                                items=queue_items(prep), plan_hash=prep["plan_hash"], requested_by=by,
                                                payload=payload, note=f"Planned by sync job '{job['name']}' ({run_id}). Nothing was written; "
                                                                      "approve it, then apply it from the queue.")
            except change_queue.QueueError as e:
                if "already in the queue" in str(e):
                    rec(p, "unchanged", message=str(e)[:300], plan_hash=prep["plan_hash"], counts=summary, superseded=stale)
                else:
                    rec(p, "error", message=str(e)[:300])
                continue
            filed.append(req)
            rec(p, "planned", request=req["id"], plan_hash=prep["plan_hash"], counts=summary, superseded=stale, label=label)
            log(f"Target {name}: {p} plan filed as {req['id']} for approval.")
    finally:
        _close(client)
    return out


def _group_of(policy: str) -> str:
    return next(g for g, v in GROUPS.items() if v["policy"] == policy)


def _scrub(text: str, profile: Dict[str, Any]) -> str:
    """A sign-in or read error with the profile's secrets taken out."""
    import tenant_profiles
    for f in tenant_profiles.SECRET_FIELDS:
        v = str(profile.get(f) or "")
        if len(v) >= 4 and v != getattr(tenant_profiles, "KEYRING_MARK", None):
            text = text.replace(v, "[secret]")
    return text


def _notify(job: Dict[str, Any], run: Dict[str, Any], filed: List[Dict[str, Any]], deps: Deps) -> List[Dict[str, Any]]:
    """One message through the digest's e-mail / webhook settings, when set:
    names, counts and request ids; no plan contents or secrets."""
    import md_safe
    subject = f"Zscaler Made Easy sync: {len(filed)} plan(s) of '{md_safe.text(job['name'])}' waiting for approval"
    lines = [f"Sync job **{md_safe.text(job['name'])}** ran ({run['trigger']}) at {run['at']}. Nothing was written to any tenant.", ""]
    for t in run["targets"]:
        if t.get("status") == "planned":
            c = t.get("counts") or {}
            lines.append(f"- {md_safe.text(t.get('label') or t.get('profile_name'))}: {md_safe.text(t['policy'])}: {c.get('add', 0)} add, "
                         f"{c.get('update', 0)} update, {c.get('move', 0)} move, {c.get('delete', 0)} delete — request {t.get('request')}")
    lines += ["", "Open the change queue to review, approve and apply (four-eyes)."]
    try:
        return deps.notify(subject, "\n".join(lines)) or []
    except Exception as e:  # noqa: BLE001
        return [{"channel": "none", "sent": False, "why": f"{type(e).__name__}"}]


def notify_via_digest(subject: str, body: str) -> List[Dict[str, Any]]:
    """Send through the continuous evaluation's notification settings
    (DLP_CHECK_NOTIFY not 'never', e-mail and/or webhook configured)."""
    import continuous_eval as ce
    cfg = ce.notification_settings()
    if cfg["mode"] == "never":
        return [{"channel": "none", "sent": False, "why": "DLP_CHECK_NOTIFY=never"}]
    out = []
    if cfg["email"]["configured"]:
        out.append(ce._send_email(subject, body, cfg["email"]))
    if cfg["webhook"]["configured"]:
        out.append(ce._send_webhook(subject, body, os.environ.get("DLP_CHECK_DIGEST_WEBHOOK", "").strip()))
    return out or [{"channel": "none", "sent": False, "why": "no e-mail or webhook configured"}]
