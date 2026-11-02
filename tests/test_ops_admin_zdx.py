"""ZDX deep trace and the read-only ZDX views (ops_zdx_trace) on the Bulk
changes engine. Fakes only (tests/admin_fakes.py): no network, no clock
(the follow's sleep is injected), state in tmp_path."""
from __future__ import annotations

import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zdx_trace as zt  # noqa: E402
from admin_fakes import ZdxClient  # noqa: E402

ZDX = ao.scope_for(["zdx"], {})
NO_ZDX = ao.scope_for(["zpa", "zcc"], {})
ASSESSOR = "Jane Doe"
DEV = "132559212"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(zt, "_STARTS", {})
    ao.load_plugins()
    return tmp_path


def apply(c, spec, phrase=None):
    p = ao.plan(c, spec, scope=ZDX, tenant_label="acme")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZDX, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") if phrase is None else phrase)
    return p, r


START = {"type": zt.T_START, "device_id": DEV, "session_name": "slow teams", "session_length_minutes": 15, "probe_device": True,
         "app_id": "3", "web_probe_id": "41", "cloudpath_probe_id": "42", "user": "jdoe@acme.com"}


@pytest.mark.parametrize("spec", [START, {"type": zt.T_STOP, "device_id": DEV, "trace_id": "1"}])
def test_zdx_not_ticked_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZDX ticked a deep trace is neither started nor read."""
    c = ZdxClient()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec, scope=NO_ZDX)
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.read_objects(c, zt.FAMILY, NO_ZDX)
    assert c.tenant.reads == [] and c.tenant.writes == []


def test_start_sends_the_apis_options_and_undo_stops_it():
    """ASVS V1.4.1 · CWE-841: payload oracle: start_deeptrace gets exactly the SDK's keyword options; read back; Undo stops the trace."""
    c = ZdxClient()
    p, r = apply(c, START)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1 and p["confirm_phrase"] == ""
    verb, dev, kw = c.tenant.writes[0]
    assert (verb, dev) == ("start", DEV) and kw == {"session_name": "slow teams", "session_length_minutes": 15, "probe_device": True,
                                                    "app_id": "3", "web_probe_id": "41", "cloudpath_probe_id": "42"}
    inv = r["inverse"]
    assert inv["type"] == zt.T_STOP and ao.is_undo_only(inv)
    _p, r2 = apply(c, inv)
    assert r2["status"] == "applied" and c.tenant.traces[DEV] == {}


def test_a_running_trace_blocks_another_and_the_start_limit_holds():
    """ASVS V11.1.4 · V13.4.1 · CWE-770 · CWE-799: one trace per device at a time; a device cooldown and a per-tenant hourly limit."""
    c = ZdxClient()
    apply(c, START)
    p = ao.plan(c, dict(START, session_name="again"), scope=ZDX)
    assert p["status"] == "blocked" and any("already running" in b for b in p["blockers"])
    c.tenant.traces[DEV].clear()
    p = ao.plan(c, dict(START, session_name="again"), scope=ZDX)
    assert p["status"] == "blocked" and any("seconds ago" in b for b in p["blockers"])
    zt._STARTS.clear()
    for i in range(zt.START_LIMIT):
        zt._note_start(c, f"9{i}")
    assert "in the last hour" in (zt.limit_reason(c, DEV) or "")
    assert zt.limit_reason(c, DEV, now=__import__("time").time() + 3601) is None


@pytest.mark.parametrize("bad", [{"session_length_minutes": 10}, {"session_length_minutes": True}, {"session_name": "<x>"}, {"session_name": ""},
                                 {"device_id": "../1"}, {"probe_device": "yes"}, {"app_id": None, "web_probe_id": "41"}])
def test_bad_options_are_refused_before_a_read(bad):
    """ASVS V5.1.3 · CWE-20: lengths other than 5, 15, 30, 60, bad names, ids and probes without their app are refused before a read."""
    c = ZdxClient()
    with pytest.raises(ao.OperationError):
        ao.plan(c, dict(START, **bad), scope=ZDX)
    assert c.tenant.reads == []


def test_a_probe_that_is_not_the_apps_is_blocked():
    """ASVS V1.4.1 · CWE-20: a Web probe id that is not one of the application's probes on that device blocks the plan."""
    p = ao.plan(ZdxClient(), dict(START, web_probe_id="999"), scope=ZDX)
    assert p["status"] == "blocked"


def test_stop_always_asks_the_phrase_and_has_no_undo():
    """ASVS V4.1.3 · CWE-352: stopping deletes the trace and its data: DELETE DEEP TRACE is always asked; no Undo."""
    c = ZdxClient()
    _p, r = apply(c, START)
    tid = r["created"][0]["trace_id"]
    spec = {"type": zt.T_STOP, "device_id": DEV, "trace_id": tid}
    p = ao.plan(c, spec, scope=ZDX)
    assert p["confirm_phrase"] == "DELETE DEEP TRACE" and p["notes"][0].startswith("No Undo")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZDX, writes_enabled=True, assessor=ASSESSOR, confirm_text="")
    assert r["status"] == "refused" and tid in c.tenant.traces[DEV]
    _p, r = apply(c, spec)
    assert r["status"] == "applied" and r["inverse"] is None


# ── follow: bounded polling ────────────────────────────────────────────

def test_follow_stops_at_the_poll_limit_however_long_the_trace_runs():
    """ASVS V13.4.1 · CWE-400 · CWE-835: a trace that never ends is read at most MAX_POLLS times, and never more than asked."""
    c = ZdxClient()
    _p, r = apply(c, START)
    tid = r["created"][0]["trace_id"]
    naps = []
    out = zt.follow(c, DEV, tid, max_polls=1000, interval=0.001, sleep=naps.append)
    assert out["timed_out"] is True and out["polls"] == zt.MAX_POLLS and len(naps) == zt.MAX_POLLS - 1
    assert all(n >= zt.MIN_INTERVAL for n in naps)
    out = zt.follow(c, DEV, tid, max_polls=3, sleep=lambda s: None)
    assert out["polls"] == 3


def test_follow_ends_with_the_results_when_the_trace_completes():
    """ASVS V11.1.1 · CWE-754: in progress, then completed: the follow ends and fetches the results, read-only."""
    c = ZdxClient()
    _p, r = apply(c, START)
    tid = r["created"][0]["trace_id"]
    writes = list(c.tenant.writes)
    c.tenant.status_script = ["in_progress", "in_progress", "completed"]
    out = zt.follow(c, DEV, tid, sleep=lambda s: None)
    assert out["final"] and out["status"] == "completed" and out["polls"] == 3 and out["results"]["web_probe_metrics"]
    assert c.tenant.writes == writes


def test_follow_stops_on_stop_and_on_repeated_errors():
    """ASVS V11.1.4 · CWE-400: Stop ends the follow at once; three read errors in a row end it too."""
    c = ZdxClient()
    _p, r = apply(c, START)
    tid = r["created"][0]["trace_id"]
    ev = threading.Event()
    ev.set()
    assert zt.follow(c, DEV, tid, cancel=ev)["status"] == "stopped"
    c.zdx.troubleshooting.get_deeptrace = lambda d, t: (None, None, "HTTP 503")
    out = zt.follow(c, DEV, tid, sleep=lambda s: None)
    assert out["status"] == "unreadable" and out["polls"] == zt.MAX_ERRORS_IN_A_ROW


# ── read-only views ────────────────────────────────────────────────────

def test_the_read_only_views_read_and_never_write():
    """ASVS V4.1.3 · CWE-200: app scores, user lookup, device search, device health and per-device app performance only read."""
    c = ZdxClient()
    objs = ao.read_objects(c, zt.FAMILY, ZDX)
    assert objs["apps"][0] == {"id": "3", "name": "Microsoft 365", "score": 71, "users": None, "most_impacted_region": ""}
    assert zt.lookup(c, "users", {"user": "jdoe"})["users"][0]["devices"][0]["id"] == DEV
    assert zt.lookup(c, "devices", {"user": "jdoe@acme.com"})["devices"][0]["id"] == DEV
    h = zt.lookup(c, "health", {"device_id": DEV})
    assert h["device"]["name"] == "JDOE-LT" and h["health_metrics"][0]["category"] == "cpu"
    assert zt.lookup(c, "device_app", {"device_id": DEV, "app_id": "3"})["performance"]["score"] == 71
    assert zt.lookup(c, "app_score", {"app_id": "3"})["score"]["metric"] == "score"
    assert zt.lookup(c, "probes", {"device_id": DEV, "app_id": "3"})["web_probes"] == [{"id": "41", "name": "M365 web"}]
    assert c.tenant.writes == []
    for what, q in (("users", {"user": "x"}), ("devices", {"user": "not-an-email"}), ("health", {"device_id": "a/b"}), ("nope", {"device_id": "1"})):
        with pytest.raises(ao.OperationError):
            zt.lookup(c, what, q)


def test_a_huge_answer_is_cut_to_size():
    """ASVS V12.1.1 · CWE-400: tenant answers shown on the page are capped in rows, depth and text."""
    big = {"rows": [{"t": "x" * 5000}] * 5000}
    out = zt._cap(big)
    assert len(out["rows"]) == zt.MAX_ROWS and len(out["rows"][0]["t"]) == 500
