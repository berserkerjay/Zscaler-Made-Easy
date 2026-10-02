"""Background jobs for the long tenant operations (deploy, removal, undo).

A deploy of one pack is 70-odd API writes, an activation, a wait for ZIA
to report ACTIVE and a full read-back: minutes, sometimes ten. Run as one
HTTP request the browser sees nothing until the end, which looks like a
hang. A job runs the same function in a thread and keeps its log lines
as they are written; the browser starts it, polls for the new lines (and
the elapsed time), and receives the result when the job finishes. The
operator's Stop sets the job's cancel event, which pack_ops run control
turns into "not attempted" for every remaining write.

Jobs live in this process only (the tool is single-user). Finished jobs
are kept for an hour so a page that was reloaded can still show them.

A job outlives both its HTTP request (whose audit entry only says "200",
the job was queued) and its hour in memory, so every job leaves one
`job_finished` entry in the audit log when it ends, however it ends: who
asked (when known), the tenant, the plan, the final status, the counts,
the activation, whether it was cancelled and how long it took. The run
inside the job adds what it knows through note() (pack_ops.audited_run).
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# Statuses a job moves through. `running` → one of the final three.
RUNNING, DONE, FAILED, CANCELLED = "running", "done", "failed", "cancelled"

KEEP_SECONDS = 3600.0     # finished jobs stay this long
MAX_LOG_LINES = 5000      # a runaway log is cut at the top, never grows unbounded

JobFn = Callable[[Callable[[str], None], threading.Event], Dict[str, Any]]

logger = logging.getLogger("dlp_check.jobs")


@dataclass
class Job:
    id: str
    kind: str
    label: str = ""
    status: str = RUNNING
    started: float = field(default_factory=time.time)
    finished: Optional[float] = None
    logs: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    # A file the job produced (a Terraform workspace zip): (filename, media type, bytes),
    # served by the download endpoint; never part of the JSON snapshot.
    artifact: Optional[Tuple[str, str, bytes]] = None
    cancel: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    # Who started it (the start endpoint's actor), when known.
    actor: Optional[str] = None
    # The tenant's ZIA rate-limit key, once the run inside knows it
    # (dlp_api_server._keyed), so the snapshot can say when a pause ends.
    rate_key: Optional[str] = None
    # What the run inside reported for the audit entry (note()): tenant,
    # plan_hash, counts, activation, stopped.
    audit: Dict[str, Any] = field(default_factory=dict)

    def log(self, line: str) -> None:
        with self.lock:
            self.logs.append(str(line))
            if len(self.logs) > MAX_LOG_LINES:
                del self.logs[: len(self.logs) - MAX_LOG_LINES]

    def elapsed(self) -> float:
        return round((self.finished or time.time()) - self.started, 1)


_jobs: Dict[str, Job] = {}
_registry_lock = threading.Lock()
_here = threading.local()   # the job the current thread is running, if any


def current() -> Optional[Job]:
    """The job this thread is running (inside its `fn`), or None."""
    return getattr(_here, "job", None)


def note(**fields: Any) -> bool:
    """Add what the run knows (tenant, plan_hash, counts...) to the current
    job's `job_finished` entry. False when this thread runs no job, so the
    caller writes its own entry instead."""
    job = current()
    if job is None:
        return False
    with job.lock:
        job.audit.update({k: v for k, v in fields.items() if v is not None})
    return True


def write_audit(event: str, **fields: Any) -> None:
    """One audit entry through audit.record (redacted, owner-only, rotated).
    A failure to write it is logged as an error, never raised: auditing
    must not fail a deploy or a removal, least of all one already done."""
    try:
        import audit
        if audit.record(event, **fields) is None:
            logger.error("AUDIT WRITE FAILED: could not append the %s entry to %s", event, audit.path())
    except Exception as e:  # noqa: BLE001
        logger.error("AUDIT WRITE FAILED: the %s entry was not written: %s", event, f"{type(e).__name__}: {str(e)[:200]}")


def start(kind: str, fn: JobFn, *, label: str = "", actor: Optional[str] = None) -> Job:
    """Run `fn(log, cancel)` in a daemon thread and return the job at once.
    `fn` returns the result dict; an exception becomes status `failed`
    with the message. A `cancel` set before `fn` returns is reported as
    `cancelled` when the function honoured it (its result says `stopped`).
    `actor` is who asked for the job, for its audit entry. That entry is
    written before the final status is published, so a poller that sees
    the job end also finds it in the audit log."""
    prune()
    job = Job(id=uuid.uuid4().hex[:12], kind=kind, label=label, actor=actor or None)
    with _registry_lock:
        _jobs[job.id] = job

    def _run() -> None:
        final = FAILED
        _here.job = job
        try:
            result = fn(job.log, job.cancel)
            with job.lock:
                job.result = result if isinstance(result, dict) else {"result": result}
                # A produced file travels beside the JSON result, never inside it.
                artifact = job.result.pop("artifact", None)
                if isinstance(artifact, tuple) and len(artifact) == 3:
                    job.artifact = artifact
            final = CANCELLED if (job.cancel.is_set() and (job.result or {}).get("stopped")) else DONE
        except Exception as e:  # noqa: BLE001 — the job reports, never crashes the server
            with job.lock:
                job.error = f"{type(e).__name__}: {str(e)[:300]}"
            job.log(f"The run stopped with an error: {job.error}")
        finally:
            _here.job = None
            job.finished = time.time()
            _audit_finished(job, final)
            with job.lock:
                job.status = final

    threading.Thread(target=_run, name=f"job-{kind}-{job.id}", daemon=True).start()
    return job


_NO_WRITES = {"created": 0, "updated": 0, "deleted": 0, "skipped": 0, "failed": 0, "unchanged": 0}


def _audit_finished(job: Job, final: str) -> None:
    """The job's one `job_finished` audit entry. Counts, tenant, plan and
    activation come from the run inside (note()); a job whose run said
    nothing (a Terraform hand-off writes nothing to the tenant) reports
    zero writes and the tenant its result names."""
    try:
        with job.lock:
            info = dict(job.audit)
            result = dict(job.result or {})
        stopped = info.pop("stopped", None) or result.get("stopped")
        error = job.error or info.pop("error", None)
        for k in ("error", "cancelled"):   # the job's own ending decides these
            info.pop(k, None)
        write_audit(
            "job_finished", job_id=job.id, kind=job.kind, label=job.label, actor=job.actor,
            tenant=info.pop("tenant", None) or result.get("tenant_label") or None,
            plan_hash=info.pop("plan_hash", None) or result.get("plan_hash") or None,
            status=final, result_status=info.pop("result_status", None) or result.get("status"),
            counts=info.pop("counts", None) or dict(_NO_WRITES), activation=info.pop("activation", None),
            cancelled=final == CANCELLED, cancel_requested=job.cancel.is_set(),
            stopped=str(stopped)[:200] if stopped else None, error=error,
            duration_seconds=round((job.finished or time.time()) - job.started, 1), **info)
    except Exception as e:  # noqa: BLE001 — the audit entry never breaks the job's ending
        logger.error("AUDIT WRITE FAILED: job %s: %s", job.id, f"{type(e).__name__}: {str(e)[:200]}")


def get(job_id: str) -> Optional[Job]:
    with _registry_lock:
        return _jobs.get(job_id)


def cancel(job_id: str) -> bool:
    """Ask a running job to stop after the write in flight. True when the
    job exists and was still running."""
    job = get(job_id)
    if job is None or job.status != RUNNING:
        return False
    job.cancel.set()
    if job.kind == "export":   # read-only: nothing is written or activated
        job.log("Stop requested: the read in flight finishes, nothing more is read and no pack is produced.")
    else:
        job.log("Stop requested: the write in flight finishes, nothing more is sent; activation and the read-back still run.")
    return True


def snapshot(job: Job, since: int = 0) -> Dict[str, Any]:
    """What the browser polls: status, elapsed seconds, the log lines from
    index `since` on and the index to ask for next; the result (or the
    error) once the job has finished."""
    with job.lock:
        lines = job.logs[max(0, since):]
        out: Dict[str, Any] = {
            "job_id": job.id, "kind": job.kind, "label": job.label, "status": job.status,
            "elapsed_seconds": job.elapsed(), "logs": lines, "next": len(job.logs), "cancel_requested": job.cancel.is_set(),
        }
        rate_key, running = job.rate_key, job.status == RUNNING
    if running and rate_key is not None:
        # Paused for ZIA's rate limit: how long until it sends again, so the
        # window counts down instead of looking stuck.
        try:
            import zia_rate
            left = zia_rate.paused_for(rate_key)
        except Exception:  # noqa: BLE001 - the poll must never fail over this
            left = 0.0
        if left > 0:
            out["paused_seconds"] = round(left)
            out["paused_until"] = round(time.time() + left)
    with job.lock:
        if out["status"] != RUNNING:   # the status this snapshot reports
            out["result"] = job.result
            out["error"] = job.error
            if job.artifact is not None:
                out["download"] = f"/api/dlp-packs/jobs/{job.id}/download"
                out["filename"] = job.artifact[0]
                out["bytes"] = len(job.artifact[2])
    return out


def prune(now: Optional[float] = None) -> int:
    """Drop finished jobs older than KEEP_SECONDS. Returns how many."""
    now = now or time.time()
    with _registry_lock:
        old = [k for k, j in _jobs.items() if j.finished and now - j.finished > KEEP_SECONDS]
        for k in old:
            del _jobs[k]
    return len(old)


def running() -> List[Job]:
    with _registry_lock:
        return [j for j in _jobs.values() if j.status == RUNNING]
