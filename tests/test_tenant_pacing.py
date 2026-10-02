"""One tenant is paced as one: every Client of the same tenant (one per
request or job, as dlp_api_server._raw_client builds them) shares a send
gap and a 429 hold; a ZIA write is counted once against ZIA's write limit
however long the client's own pacer held it; and ZIA's Retry-After
("0 seconds") is read on writes as on reads. Fakes only: no tenant is
called."""
from __future__ import annotations

import threading
import time

import pytest
from requests.adapters import BaseAdapter
from requests.models import Response

import dlp_assessment_full_auto as full
import zia_rate


class _Adapter(BaseAdapter):
    def __init__(self, answer, log):
        super().__init__()
        self.answer, self.log = answer, log

    def send(self, request, **kwargs):
        code, headers = self.answer(request)
        r = Response()
        r.request, r._content, r.status_code = request, b"[]", code
        r.headers.update(headers)
        self.log.append((time.time(), request.method, request.url, code))
        return r

    def close(self):
        pass


def _client(answer, log, vd="acme.com"):
    c = full.Client("cid-123456", "secret-secret", vd, "zscaler")
    c.sess.mount("https://", _Adapter(answer, log))
    c.token, c.exp = "t", time.time() + 3600
    return c


def test_a_429_seen_by_one_client_holds_every_client_of_the_same_tenant():
    # Two jobs on one tenant: client A is refused with Retry-After: 2, and
    # client B (a separate Client, same tenant) sends nothing until it passed.
    log = []
    first = [True]

    def answer(req):
        if first[0] and req.url.endswith("/webDlpRules"):
            first[0] = False
            return 429, {"Retry-After": "2"}
        return 200, {}

    a, b = _client(answer, log), _client(answer, log)
    assert a.rate_key == b.rate_key and a is not b
    ta = threading.Thread(target=lambda: a.get("/zia/webDlpRules"))
    ta.start()
    deadline = time.time() + 5
    while not log and time.time() < deadline:
        time.sleep(0.01)
    assert log and log[0][3] == 429
    assert b.get("/zia/dlpEngines")[1] == 200
    ta.join()
    refused_at = log[0][0]
    later = log[1:]
    assert len(later) == 2
    assert all(at - refused_at >= 1.9 for at, *_ in later), [(round(at - refused_at, 2), u) for at, _, u, _ in later]


def test_another_tenant_is_not_held_by_a_429():
    log = []
    a = _client(lambda r: (200, {}), log)
    other = _client(lambda r: (200, {}), log, vd="other.com")
    assert a.rate_key != other.rate_key
    a._limiter.pause(5)
    t0 = time.time()
    assert other.get("/zia/dlpEngines")[1] == 200
    assert time.time() - t0 < 1


def test_clients_of_one_tenant_share_the_send_gap():
    # Non-ZIA reads have no other pacing: two jobs on one tenant together
    # keep the client's gap, not twice its rate.
    log = []
    a, b = _client(lambda r: (200, {}), log), _client(lambda r: (200, {}), log)
    for c in (a, b):
        c._limiter.min_gap = 0.2
        c.customer_id = "123"
    eps = ["/zpa/application", "/zpa/segmentGroup", "/zpa/server", "/zpa/serverGroup"]
    ts = [threading.Thread(target=lambda c=c, ep=ep: c.get(ep)) for c in (a, b) for ep in eps]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    stamps = sorted(at for at, *_ in log)
    assert len(stamps) == 8
    gaps = [y - x for x, y in zip(stamps, stamps[1:])]
    assert min(gaps) >= 0.18, gaps


def test_a_write_held_by_the_clients_pacer_is_counted_once(monkeypatch):
    # The client's own pacer holds the write longer than a paced mark lives
    # (5 s on ZIA's clock): the write is still counted once, not twice.
    log = []
    c = _client(lambda r: (200, {}), log)
    clock = [1_000_000.0]
    monkeypatch.setattr(zia_rate, "_now", lambda: clock[0])
    real_wait = c._limiter.wait

    def held_wait(stop=None):
        clock[0] += 8   # an 8 s hold after another thread's 429
        return real_wait(stop)

    monkeypatch.setattr(c._limiter, "wait", held_wait)
    zia_rate.reset()
    assert c.post("/zia/webDlpRules", {"name": "x"})[1] == 200
    assert [m for _, m, _, _ in log] == ["POST"]
    assert len(zia_rate._t(c.rate_key).sent["write"]) == 1, list(zia_rate._t(c.rate_key).sent["write"])


@pytest.mark.parametrize("value, seconds", [("0 seconds", 1), ("12 seconds", 12), ("7", 7), ("soon", 5),
                                            ("900", 30), (None, 5)])
def test_retry_after_is_read_as_zia_sends_it(value, seconds):
    assert full._retry_after({} if value is None else {"Retry-After": value}) == seconds


def test_a_write_429_with_zias_retry_after_is_waited_out_and_retried(monkeypatch):
    log = []
    naps = []
    monkeypatch.setattr(full, "_nap", lambda seconds, stop=None: naps.append(seconds) or True)
    answers = iter([(429, {"Retry-After": "0 seconds"}), (200, {})])
    c = _client(lambda r: next(answers), log)
    before = time.time()
    res = c.post("/zia/urlLookup", ["example.com"])
    assert res[1] == 200, res
    assert [m for _, m, _, _ in log] == ["POST", "POST"]
    assert naps and naps[0] >= 1
    # The hold is the tenant's: every thread and job on it waits too.
    assert c._limiter._gate.pause_until >= before + 1


def test_a_write_still_refused_after_its_retries_is_reported_as_rate_limited(monkeypatch):
    log = []
    monkeypatch.setattr(full, "_nap", lambda seconds, stop=None: True)
    c = _client(lambda r: (429, {"Retry-After": "0 seconds"}), log)
    assert c.post("/zia/urlLookup", ["example.com"]) == ({"error": "rate limited", "status": 429}, 429)
    assert len(log) == 4
