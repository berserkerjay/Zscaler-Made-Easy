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
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Statuses a job moves through. `running` → one of the final three.
RUNNING, DONE, FAILED, CANCELLED = "running", "done", "failed", "cancelled"

KEEP_SECONDS = 3600.0     # finished jobs stay this long
MAX_LOG_LINES = 5000      # a runaway log is cut at the top, never grows unbounded

JobFn = Callable[[Callable[[str], None], threading.Event], Dict[str, Any]]


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
    cancel: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, line: str) -> None:
        with self.lock:
            self.logs.append(str(line))
            if len(self.logs) > MAX_LOG_LINES:
                del self.logs[: len(self.logs) - MAX_LOG_LINES]

    def elapsed(self) -> float:
        return round((self.finished or time.time()) - self.started, 1)


_jobs: Dict[str, Job] = {}
_registry_lock = threading.Lock()


def start(kind: str, fn: JobFn, *, label: str = "") -> Job:
    """Run `fn(log, cancel)` in a daemon thread and return the job at once.
    `fn` returns the result dict; an exception becomes status `failed`
    with the message. A `cancel` set before `fn` returns is reported as
    `cancelled` when the function honoured it (its result says `stopped`)."""
    prune()
    job = Job(id=uuid.uuid4().hex[:12], kind=kind, label=label)
    with _registry_lock:
        _jobs[job.id] = job

    def _run() -> None:
        try:
            result = fn(job.log, job.cancel)
            with job.lock:
                job.result = result if isinstance(result, dict) else {"result": result}
                job.status = CANCELLED if (job.cancel.is_set() and (job.result or {}).get("stopped")) else DONE
        except Exception as e:  # noqa: BLE001 — the job reports, never crashes the server
            with job.lock:
                job.error = f"{type(e).__name__}: {str(e)[:300]}"
                job.status = FAILED
            job.log(f"The run stopped with an error: {job.error}")
        finally:
            job.finished = time.time()

    threading.Thread(target=_run, name=f"job-{kind}-{job.id}", daemon=True).start()
    return job


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
        if job.status != RUNNING:
            out["result"] = job.result
            out["error"] = job.error
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
