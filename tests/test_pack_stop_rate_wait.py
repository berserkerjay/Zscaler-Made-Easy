"""Stop really stops a policy pack's writes and an export's reads, also
while they wait for ZIA's rate limit or for a retry.

- A write inside a deploy / removal run (pack_ops.call under run_scope)
  that waits for ZIA's rate limit is not sent once Stop is pressed: the
  wait ends within a step and the write comes back STOPPED.
- A write retried after a transient refusal (503) is not retried once
  Stop is pressed during the backoff.
- The run's activation is not sent again after a rate-refused activation
  once Stop is pressed, and an activation still waiting for the rate
  limit when Stop is pressed is not sent.
- An export read (pack_export) and a journey read (_StopAware) waiting for
  ZIA's read limit are not sent once Stop is pressed.

Fakes only: a fake clock under zia_rate, fake SDK calls and sessions.
"""
from __future__ import annotations

import threading

import pytest

import pack_channels as pc
import pack_export
import pack_ops as ops
import zia_rate

URL = "https://zsapi.zscaler.net/api/v1/dlpDictionaries"


@pytest.fixture
def clock(monkeypatch):
    """A fake clock: zia_rate's sleeps advance it and record each step;
    `on_sleep` runs at every sleep (a test presses Stop there)."""
    state = {"t": 1_000_000.0, "slept": [], "on_sleep": None}

    def sleep(s):
        state["slept"].append(s)
        state["t"] += s
        if state["on_sleep"]:
            state["on_sleep"]()
    monkeypatch.setattr(zia_rate, "_now", lambda: state["t"])
    monkeypatch.setattr(zia_rate, "_sleep", sleep)
    return state


def test_a_write_waiting_for_the_rate_limit_is_not_sent_after_stop(monkeypatch, clock):
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_WRITE", "1/m")
    cancel = threading.Event()
    sent = []

    def fn(name):
        sent.append(name)
        return {"id": len(sent)}

    clock["on_sleep"] = cancel.set   # Stop is pressed while the second write waits
    with ops.run_scope(cancel):
        first = ops.call(fn, "first", op="create", kind="dictionary", name="first")
        second = ops.call(fn, "second", op="create", kind="dictionary", name="second")
        third = ops.call(fn, "third", op="create", kind="dictionary", name="third")
        assert ops.stop_reason() == ops.CANCELLED_REASON
    assert first.ok and sent == ["first"], "nothing is sent after Stop"
    assert second.code == ops.STOPPED and not second.ok and third.code == ops.STOPPED
    assert sum(clock["slept"]) <= zia_rate.CANCEL_STEP, "the wait ends within a step, not after the whole minute"


def test_an_endpoint_rule_waiting_for_its_hourly_limit_is_not_sent_after_stop(monkeypatch, clock):
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_ENDPOINT_RULES", "1/h")
    cancel = threading.Event()
    sent = []
    clock["on_sleep"] = cancel.set
    with ops.run_scope(cancel):
        ops.call(lambda: sent.append(1) or {"id": 1}, op="create", kind="policy", channel="endpoint", name="a")
        out = ops.call(lambda: sent.append(2) or {"id": 2}, op="create", kind="policy", channel="endpoint", name="b")
    assert sent == [1] and out.code == ops.STOPPED
    assert sum(clock["slept"]) < 5


def test_a_stop_pressed_during_a_transient_retry_backoff_sends_no_retry(monkeypatch):
    cancel = threading.Event()
    sent = []

    def fn():
        sent.append(1)
        if len(sent) == 1:
            raise RuntimeError("503 Service Unavailable")
        return {"id": 1}

    monkeypatch.setattr(ops, "_sleep", lambda s: cancel.set())
    with ops.run_scope(cancel):
        out = ops.call(fn, op="create", kind="dictionary", name="a")
    assert sent == [1], "the retry is not sent after Stop"
    assert out.code == ops.STOPPED and not out.ok


def test_a_write_outside_a_run_still_waits_and_is_sent(monkeypatch, clock):
    """No run, no Stop: pacing is unchanged (a proposal's single change)."""
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_WRITE", "1/m")
    sent = []
    assert ops.call(lambda: sent.append(1) or {"id": 1}, op="update", kind="dictionary", name="a").ok
    assert ops.call(lambda: sent.append(2) or {"id": 2}, op="update", kind="dictionary", name="b").ok
    assert sent == [1, 2] and sum(clock["slept"]) >= 59


def test_a_cancel_set_while_the_sdk_sends_through_a_paced_session_is_stopped_not_failed(monkeypatch, clock):
    """The SDK turns an exception from the session into an error answer:
    a write cancelled inside it is still reported STOPPED, not failed."""
    cancel = threading.Event()

    def fn():
        cancel.set()
        try:
            with zia_rate.stopping_on(cancel.is_set):
                zia_rate.wait("POST", "/dlpDictionaries")
        except zia_rate.Cancelled as e:
            return None, None, f"Cancelled: {e}"
        return {"id": 1}, None, None

    with ops.run_scope(cancel):
        out = ops.call(fn, op="create", kind="dictionary", name="a")
    assert out.code == ops.STOPPED


def test_a_rate_refused_activation_is_not_sent_again_after_stop(monkeypatch):
    cancel = threading.Event()
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": False, "error": "429 Too Many Requests"}))
    monkeypatch.setattr(ops, "_sleep", lambda s: cancel.set())
    logs = []
    with ops.run_scope(cancel):
        act = ops.activate_once(object(), logs.append)
    assert acts == [1], "no activation is sent after Stop"
    assert not act.get("activated") and any("Stop" in l for l in logs)


def test_an_activation_waiting_for_the_rate_limit_is_not_sent_when_stop_is_pressed_during_the_wait(monkeypatch, clock):
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_ACTIVATE", "1/h")
    zia_rate.wait("POST", "/status/activate")   # the hour's one activation is used
    cancel = threading.Event()
    posts = []

    def raw(zia, method, path, body=None):
        if method == "POST":
            posts.append(path)
        return {"status": "ACTIVE"}, None
    monkeypatch.setattr(pc, "raw_request", raw)
    clock["on_sleep"] = cancel.set
    logs = []
    with ops.run_scope(cancel):
        act = ops.activate_once(object(), logs.append)
    assert posts == [] and not act.get("activated")
    assert sum(clock["slept"]) < 5


def test_the_activation_after_an_earlier_stop_is_still_sent_on_purpose_and_logged(monkeypatch):
    """What was written before Stop is activated (documented): deliberate, and said."""
    cancel = threading.Event()
    cancel.set()
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    logs = []
    with ops.run_scope(cancel):
        ops.call(lambda: None, op="create", kind="dictionary", name="x")   # the run sees the Stop
        act = ops.activate_once(object(), logs.append)
    assert acts == [1] and act["activated"]
    assert any("written before Stop" in l for l in logs)


class _Session:
    def __init__(self):
        self.sent = []

    def send(self, request, **kw):
        self.sent.append(request.url)
        return "ok"


class _Req:
    method = "GET"
    url = URL


def test_an_export_read_waiting_for_the_read_limit_is_not_sent_after_stop(monkeypatch, clock):
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_READ", "1/m")
    s = _Session()
    zia_rate._pace_session(s, "")
    s.send(_Req())   # the minute's one read
    cancel = threading.Event()
    clock["on_sleep"] = cancel.set

    def fn():
        s.send(_Req())
        return [], None
    data, err, rate = pack_export._read("DLP dictionaries", fn, lambda m: None, cancel)
    assert s.sent == [URL], "the read is not sent after Stop"
    assert sum(clock["slept"]) <= zia_rate.CANCEL_STEP and not rate


def test_read_tenant_stops_when_stop_is_pressed_during_a_paced_read(monkeypatch, clock):
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_READ", "1/m")
    s = _Session()
    zia_rate._pace_session(s, "")
    cancel = threading.Event()
    clock["on_sleep"] = cancel.set

    class Dicts:
        def list_dicts(self):
            s.send(_Req())
            return [], None, None

    class Engines:
        def list_dlp_engines(self):
            s.send(_Req())
            return [], None, None

    class Zia:
        dlp_dictionary = Dicts()
        dlp_engine = Engines()

    class Client:
        zia = Zia()
    snap = pack_export.read_tenant(Client(), channels=(), cancel=cancel)
    assert snap["stopped"] and s.sent == [URL], "the engines read waited, Stop was pressed, it was not sent"


def test_a_journey_read_waiting_for_the_read_limit_is_not_sent_after_stop(monkeypatch, clock):
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_READ", "1/m")
    s = _Session()
    zia_rate._pace_session(s, "")
    s.send(_Req())
    stop = threading.Event()
    clock["on_sleep"] = stop.set

    class Sdk:
        def list_dicts(self):
            s.send(_Req())
            return [], None, None
    wrapped = srv._StopAware(Sdk(), stop)
    with pytest.raises(srv.JourneyStopped):
        wrapped.list_dicts()
    assert s.sent == [URL]


def test_stopping_on_keeps_the_outer_stop_hook():
    outer = threading.Event()
    inner = threading.Event()
    with zia_rate.stopping_on(outer.is_set), zia_rate.stopping_on(inner.is_set):
        assert not zia_rate.stop_requested()
        outer.set()
        assert zia_rate.stop_requested(), "an inner scope never hides the outer Stop"
    assert not zia_rate.stop_requested()


def test_waiting_for_active_after_stop_does_not_poll_the_tenant(monkeypatch):
    """After Stop the run does not keep asking ZIA for the activation status
    (up to settle_seconds of GETs every 3 s)."""
    import time as _t
    cancel = threading.Event()
    cancel.set()
    gets = []
    monkeypatch.setattr(pc, "activation_status", lambda zia: (gets.append(1) or ("PENDING", None)))
    monkeypatch.setattr(_t, "sleep", lambda s: None)
    with ops.run_scope(cancel):
        assert pc.wait_active(object(), 45.0) is None
    assert gets == []


def test_a_stop_pressed_while_waiting_for_active_ends_the_polling(monkeypatch):
    import time as _t
    cancel = threading.Event()
    gets, slept = [], []
    monkeypatch.setattr(pc, "activation_status", lambda zia: (gets.append(1) or ("PENDING", None)))

    def sleep(s):
        slept.append(s)
        cancel.set()
    monkeypatch.setattr(_t, "sleep", sleep)
    with ops.run_scope(cancel):
        assert pc.wait_active(object(), 45.0) == "PENDING"
    assert gets == [1] and sum(slept) <= 0.5


def test_waiting_for_active_outside_a_stopped_run_still_polls(monkeypatch):
    import time as _t
    answers = iter(["PENDING", "ACTIVE"])
    monkeypatch.setattr(pc, "activation_status", lambda zia: (next(answers), None))
    monkeypatch.setattr(_t, "sleep", lambda s: None)
    assert pc.wait_active(object(), 45.0) == "ACTIVE"
    with ops.run_scope(threading.Event()):
        answers = iter(["PENDING", "ACTIVE"])
        monkeypatch.setattr(pc, "activation_status", lambda zia: (next(answers), None))
        assert pc.wait_active(object(), 45.0) == "ACTIVE"


def test_a_stoppable_wait_sleeps_a_hold_through_once_in_steps(monkeypatch):
    """Like an unstoppable wait, a wait in Stop-able steps ends once the
    hold's whole length is slept, whatever the clock says meanwhile (it
    never sleeps the same hold again and again)."""
    slept = []
    monkeypatch.setattr(zia_rate, "_now", lambda: 1_000_000.0)   # a clock that does not move
    monkeypatch.setattr(zia_rate, "_sleep", slept.append)
    zia_rate.hold(600)
    with zia_rate.stopping_on(lambda: False):
        zia_rate.wait("POST", "/dlpDictionaries")
    assert abs(sum(slept) - 600) < 1e-6 and max(slept) <= zia_rate.CANCEL_STEP
