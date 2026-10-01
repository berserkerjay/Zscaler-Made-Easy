"""A run paused for ZIA's rate limit says when it sends again.

"The timer isn't resuming when the threshold is met": the removal window
showed "Working…" and a climbing elapsed time for the whole 54-minute pause
after "Resource Access Blocked", with no sign of when it would go on. The
job snapshot now carries the seconds left on the tenant's hold, and Deploy
Studio counts down to it."""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pack_jobs
import zia_rate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_paused_for_is_the_tenants_own_hold():
    zia_rate.hold(120, key="tenant-a")
    assert 115 < zia_rate.paused_for("tenant-a") <= 120
    assert zia_rate.paused_for("tenant-b") == 0.0, "another tenant's pause is not this one's"
    assert zia_rate.paused_for() == 0.0


def _run_keyed_job(client, release):
    import dlp_api_server as srv
    seen = {}

    def fn(log, cancel):
        return srv._keyed(client, _body, log, cancel)

    def _body(log, cancel):
        seen["key"] = zia_rate.current_key()
        release.wait(5)
        return {"ok": True}

    return pack_jobs.start("removal", fn, label="test"), seen


def test_a_running_job_reports_the_pause_and_stops_once_it_is_over():
    client = SimpleNamespace(_zia_rate_key="tenant-c")
    release = threading.Event()
    job, seen = _run_keyed_job(client, release)
    for _ in range(200):
        if job.rate_key:
            break
        time.sleep(0.01)
    assert job.rate_key == "tenant-c" and seen["key"] == "tenant-c", "_keyed stamps the tenant on the job"

    assert "paused_seconds" not in pack_jobs.snapshot(job), "no pause, no countdown"
    zia_rate.hold(300, key="tenant-c")
    snap = pack_jobs.snapshot(job)
    assert 295 <= snap["paused_seconds"] <= 300 and snap["paused_until"] > time.time() + 290
    zia_rate.hold(600, key="someone-else")
    assert snap["paused_seconds"] <= 300

    release.set()
    for _ in range(300):
        if job.status != pack_jobs.RUNNING:
            break
        time.sleep(0.01)
    done = pack_jobs.snapshot(job)
    assert done["status"] == pack_jobs.DONE and "paused_seconds" not in done and done["result"] == {"ok": True}


def test_deploy_studio_counts_down_to_the_resume_time():
    js = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "snap.paused_seconds > 0 ? Date.now() + snap.paused_seconds * 1000" in js
    phase = js[js.index("function _dzJobPhase(J)"):js.index("function _dzJobUpdate(")]
    assert "Paused for ZIA's rate limit — resumes at ${at} (in ${_dzMMSS(left)})" in phase
    assert "/pausing the whole run|rate limit is still resetting/" in phase, "the log line alone also reads as paused"
    tick = js[js.index("function _dzJobTick()"):js.index("async function _dzCancelJob()")]
    assert "J.pausedEnd" in tick and "_dzJobPhase(J)" in tick, "the countdown moves every second"
