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
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, channels: ([{"id": "p1", "dir": "x"}], {"p1": ["web"]}) if journey else ([], {}))
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
    assert stuck_ev["status"] == "ERROR" and "timed out" in stuck_ev["detail"]
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
        assert kw["channel_targets"] == {"p1": ["web"]}, "the journey is measured only on the channels in scope"
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

    def counting(cl, need=None, log=None):
        calls.append(need)
        return real(cl, need)

    monkeypatch.setattr(pd, "fetch_tenant", counting)
    out = srv._journey_for(client, packs, progress=lambda i, n, pid: None)
    assert len(calls) == 1, len(calls)
    assert calls[0]["channels"] >= {"web"}   # packs are detection-only; the union of both packs' needs
    assert len(out["baselines"]) == 2


def _stream(body):
    c = TestClient(srv.app)
    with c.stream("POST", "/api/assess", json=body) as r:
        return r.status_code, (_events(r) if r.status_code == 200 else r.read())


CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}


def test_nothing_in_scope_is_refused_never_read_as_everything(monkeypatch):
    built = []
    monkeypatch.setattr(srv, "Client", lambda *a, **k: built.append(1) or FakeClient())
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    status, body = _stream(dict(CREDS))
    assert status == 400 and b"Scope page" in body and built == [], "no scopes: refused before the tenant is signed in to"
    status, body = _stream(dict(CREDS, scopes=[]))
    assert status == 400 and built == []
    # An MCP / CLI caller that sets the legacy scope on purpose still runs.
    status, ev = _stream(dict(CREDS, scope="dlp"))
    assert status == 200 and any(k == "complete" for k, _ in ev)


def _profile_with_packs(monkeypatch, tmp_path, packs, scopes=("dlp",)):
    import tenant_profiles
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "p.json"))
    p = tenant_profiles.upsert({"name": "Acme", "vanity_domain": "acme", "client_id": "abc123456789", "baseline_packs": list(packs),
                                "scopes": list(scopes), "industry": "Financial Services"})
    return p["id"]


def test_the_journey_reads_only_the_chosen_packs_on_channels_in_scope(monkeypatch, tmp_path):
    seen = []

    def fake_journey(sdk, packs, progress=None, channel_targets=None, **kw):
        seen.append(([p["id"] for p in packs], channel_targets))
        return {"status": "in_progress", "stage": 1, "score": 10, "baselines": [], "stages": [], "blockers": []}

    monkeypatch.setattr(srv, "Client", FakeClient)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv, "_journey_for", fake_journey)
    web_only = {"web_dlp": "zscaler", "endpoint_dlp": "gap", "email_dlp": "alternative", "saas_casb": "gap"}
    # No pack ticked on the profile: no journey, never "every installed pack".
    pid = _profile_with_packs(monkeypatch, tmp_path, [])
    status, ev = _stream(dict(CREDS, scopes=["dlp"], profile_id=pid, channels=web_only))
    assert status == 200 and not any(k == "journey" for k, _ in ev) and seen == []
    assert next(d for k, d in ev if k == "complete")["journey"] is None
    # A ticked pack: measured on its channels marked Zscaler only.
    pid = _profile_with_packs(monkeypatch, tmp_path, ["zbp_enterprise_baseline"])
    status, ev = _stream(dict(CREDS, scopes=["dlp"], profile_id=pid, channels=web_only))
    assert status == 200 and any(k == "journey" for k, _ in ev)
    assert seen == [(["zbp_enterprise_baseline"], {"zbp_enterprise_baseline": ["web"]})]
    # DLP not in scope, or no DLP channel on Zscaler: no journey.
    seen.clear()
    _stream(dict(CREDS, scopes=["zia_extras"], profile_id=pid, channels=web_only))
    _stream(dict(CREDS, scopes=["dlp"], profile_id=pid, channels={"web_dlp": "gap", "ssl_inspection": "zscaler"}))
    _stream(dict(CREDS, scopes=["dlp"], profile_id=pid))
    assert seen == []


def test_journey_scope_limits_packs_and_channels():
    packs, targets = srv._journey_scope(["zbp_enterprise_baseline", "no_such_pack"], {"web_dlp": "zscaler", "endpoint_dlp": "gap"})
    assert [p["id"] for p in packs] == ["zbp_enterprise_baseline"] and targets == {"zbp_enterprise_baseline": ["web"]}
    assert srv._journey_scope([], {"web_dlp": "zscaler"}) == ([], {})
    assert srv._journey_scope(["zbp_enterprise_baseline"], {}) == ([], {})


def test_the_preflight_reads_only_the_channels_in_scope(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")
    import pack_deploy as pd
    from test_pack_channels import add_control_services, make_client
    packs, targets = srv._journey_scope(["zbp_enterprise_baseline"], {"web_dlp": "zscaler"})
    client = add_control_services(make_client())
    real = pd.fetch_tenant
    calls = []

    def counting(cl, need=None, log=None):
        calls.append(need)
        return real(cl, need)

    monkeypatch.setattr(pd, "fetch_tenant", counting)
    srv._journey_for(client, packs, channel_targets=targets, progress=lambda i, n, pid: None)
    assert len(calls) == 1 and calls[0]["channels"] <= {"web"}, calls[0]
