"""The assessment stream: checks run in parallel, a stuck check is reported
without holding the run, results go out before the journey, and the journey
lands as its own event."""
from __future__ import annotations

import json
import threading
import time

from fastapi.testclient import TestClient

import dlp_api_server as srv
from dlp_assessment_full_auto import R, _RateLimiter


class FakeClient:
    def __init__(self, *a, **k):
        self.requests_made = 0

    def auth(self):
        return True


def _events(resp):
    out = []
    kind = None
    for line in resp.iter_lines():
        if line.startswith("event: "):
            kind = line[7:]
        elif line.startswith("data: "):
            out.append((kind, json.loads(line[6:])))
    return out


def _run(monkeypatch, checks, *, journey=False, timeout=2):
    monkeypatch.setattr(srv, "Client", FakeClient)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: checks)
    monkeypatch.setattr(srv, "CHECK_TIMEOUT", timeout)
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [{"id": "p1", "dir": "x"}] if journey else [])
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "scopes": ["dlp"]}
    with c.stream("POST", "/api/assess", json=body) as r:
        assert r.status_code == 200
        return _events(r)


def test_checks_run_in_parallel_and_a_stuck_check_does_not_hold_the_run(monkeypatch):
    seen = []
    lock = threading.Lock()

    def slow(client):
        time.sleep(0.4)
        with lock:
            seen.append(threading.current_thread().name)
        return R(R.PASS, "fine")

    def stuck(client):
        time.sleep(30)
        return R(R.PASS, "never")

    checks = [(f"c{i}", "sec", f"Check {i}", slow) for i in range(6)] + [("stuck", "sec", "Stuck check", stuck)]
    t0 = time.time()
    ev = _run(monkeypatch, checks)
    elapsed = time.time() - t0
    kinds = [k for k, _ in ev]
    assert kinds.count("check") == 7 and kinds[-1] == "complete"
    # Six 0.4 s checks on 6 workers plus a 2 s timeout: well under the 2.4 s + 30 s a serial run would take.
    assert elapsed < 6, elapsed
    assert len(set(seen)) > 1, "checks did not run on more than one thread"
    stuck_ev = next(d for k, d in ev if k == "check" and d["id"] == "stuck")
    assert stuck_ev["status"] == "INFO" and "timed out" in stuck_ev["detail"]
    complete = next(d for k, d in ev if k == "complete")
    assert [c["id"] for c in complete["checks"]] == [c[0] for c in checks]   # original order kept
    assert complete["journey"] is None and complete["metadata"]["elapsed_seconds"] >= 0
    prog = [d for k, d in ev if k == "progress" and d.get("completed")]
    assert prog[-1]["completed"] == 7 and prog[-1]["pct"] == 100


def test_results_go_out_before_the_journey_which_lands_as_its_own_event(monkeypatch):
    def quick(client):
        return R(R.PASS, "ok")

    calls = []

    def fake_journey(sdk, packs, progress=None, **kw):
        progress(0, 1, "p1")
        time.sleep(0.2)
        calls.append(packs)
        return {"status": "in_progress", "stage": 2, "score": 40, "baselines": [], "stages": [], "blockers": []}

    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv, "_journey_for", fake_journey)
    ev = _run(monkeypatch, [("c1", "sec", "Check 1", quick)], journey=True)
    kinds = [k for k, _ in ev]
    assert kinds.index("complete") < kinds.index("journey")
    complete = next(d for k, d in ev if k == "complete")
    assert complete["journey"] == {"status": "pending"}
    j = next(d for k, d in ev if k == "journey")
    assert j["journey"]["stage"] == 2 and j["journey"]["tenant_label"] == "acme (production)"
    assert any(d.get("journey") and "p1 (1 of 1)" in d.get("current", "") for k, d in ev if k == "progress")
    assert calls == [[{"id": "p1", "dir": "x"}]]


def test_journey_failure_is_reported_not_fatal(monkeypatch):
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())

    def boom(sdk, packs, progress=None, **kw):
        raise RuntimeError("tenant said no secret-secret-secret")

    monkeypatch.setattr(srv, "_journey_for", boom)
    ev = _run(monkeypatch, [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))], journey=True)
    j = next(d for k, d in ev if k == "journey")["journey"]
    assert j["status"] == "error" and "secret-secret-secret" not in j["error"]


def test_rate_limiter_paces_threads_and_holds_everyone_after_a_429():
    lim = _RateLimiter(0.05)
    stamps = []
    lock = threading.Lock()

    def worker():
        for _ in range(5):
            lim.wait()
            with lock:
                stamps.append(time.time())

    ts = [threading.Thread(target=worker) for _ in range(4)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    stamps.sort()
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert min(gaps) >= 0.04, min(gaps)                 # never two requests inside the gap
    assert time.time() - t0 >= 19 * 0.05                # 20 requests take at least 19 gaps
    lim.pause(0.3)
    t1 = time.time()
    lim.wait()
    assert time.time() - t1 >= 0.25                    # the pause holds the next request


def test_preflight_reads_the_tenant_once_per_journey(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")   # exercise the full channel set
    import pack_deploy as pd
    from test_pack_channels import add_control_services, make_client
    from dlp_importer import discover_packs
    packs = [{"id": p["id"], "dir": p["dir"]} for p in discover_packs() if p["id"] in ("zbp_enterprise_baseline", "zbp_source_code_baseline")]
    client = add_control_services(make_client())
    real = pd.fetch_tenant
    calls = []

    def counting(cl, need=None):
        calls.append(need)
        return real(cl, need)

    monkeypatch.setattr(pd, "fetch_tenant", counting)
    out = srv._journey_for(client, packs, progress=lambda i, n, pid: None)
    assert len(calls) == 1, len(calls)
    assert calls[0]["channels"] >= {"web", "cloud_app", "ssl"}   # the union of both packs' needs
    assert len(out["baselines"]) == 2
