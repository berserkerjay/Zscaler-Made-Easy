"""Classic-API tenants (RS-2): the SDK's legacy helper must not retry a 429
by itself with ZIA's whole Retry-After, must not send after Stop, and must
send through the paced session zia_rate.attach_client gives it.

Only fakes: the SDK helper signs in through a patched authenticate() and
every request is answered by a fake transport adapter; no tenant is called.
"""
import threading

import pytest
import requests
from requests.models import Response

import pack_ops as ops
import tenant_auth
import zia_rate

L = pytest.importorskip("zscaler.zia.legacy")

CREDS = {"auth_method": "legacy", "cloud": "zscalertwo", "username": "admin@acme.com",
         "password": "pw-123456789", "api_key": "a" * 12}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(tmp_path / "rate.json"))
    zia_rate.reset()
    monkeypatch.setattr(zia_rate, "_sleep", lambda s: None)

    def fake_authenticate(self):
        self.session_id = "sid"
        self.auth_details = {"passwordExpiryTime": 0}

    monkeypatch.setattr(L.LegacyZIAClientHelper, "authenticate", fake_authenticate)
    monkeypatch.setattr(L.LegacyZIAClientHelper, "ensure_valid_session", lambda self: None)
    # The SDK's own retry sleep must never run any more.
    monkeypatch.setattr(L, "sleep", lambda s: pytest.fail(f"the SDK slept {s}s by itself"))
    # Nothing may leave through the module-level requests.request either.
    monkeypatch.setattr(L.requests, "request", lambda *a, **k: pytest.fail("sent outside the paced session"))
    yield
    zia_rate.reset()


class Wire:
    """A fake transport: answers in order, records what was sent."""

    def __init__(self, monkeypatch, *answers):
        self.answers = list(answers)
        self.sent = []
        wire = self

        def send(adapter, request, **kw):
            wire.sent.append((request.method, request.url))
            status, headers, body = wire.answers.pop(0) if wire.answers else (200, {}, b"{}")
            r = Response()
            r.status_code, r.url, r.request = status, request.url, request
            r.headers.update({"Content-Type": "application/json", **headers})
            r._content = body
            return r
        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)


def _client(**kw):
    return tenant_auth.build_legacy_sdk_client(CREDS, **kw)


HOURLY_429 = (429, {"Retry-After": "3300 seconds"}, b'{"message":"Rate Limit (400/HOUR) exceeded"}')
SHORT_429 = (429, {"Retry-After": "2 seconds"}, b'{"message":"Rate Limit (1/SECOND) exceeded"}')
OK = (200, {}, b'{"id": 1}')


def test_a_long_retry_after_is_not_slept_and_nothing_is_sent_again(monkeypatch):
    """The finding's repro: a 429 with Retry-After 3300 s. Before the fix
    the SDK slept 3300 s and POSTed again; now one POST, no sleep, and the
    OneAPI client's RetryTooLong answer that pack_ops already handles."""
    wire = Wire(monkeypatch, HOURLY_429, OK)
    slept = []
    monkeypatch.setattr(tenant_auth, "_sleep", slept.append)
    helper = _client()._helper
    cancel = threading.Event()
    with ops.run_scope(cancel):
        out = ops.call(lambda: helper.send("POST", "/api/v1/dlpDictionaries", json={"name": "d"}),
                       op="create", kind="dictionary", name="d")
    assert [m for m, _ in wire.sent] == ["POST"]
    assert slept == []
    assert not out.ok and "Retry wait time 3300 seconds exceeds configured maxRetrySeconds 30" in out.error


def test_stop_during_a_short_rate_wait_sends_nothing_more(monkeypatch):
    """A short 429 is waited out in steps; Stop during that wait ends it and
    the request is not sent again."""
    wire = Wire(monkeypatch, SHORT_429, OK)
    cancel = threading.Event()
    slept = []
    monkeypatch.setattr(tenant_auth, "_sleep", lambda s: (slept.append(s), cancel.set()))
    helper = _client()._helper
    with ops.run_scope(cancel):
        out = ops.call(lambda: helper.send("POST", "/api/v1/dlpDictionaries", json={"name": "d"}),
                       op="create", kind="dictionary", name="d")
    assert [m for m, _ in wire.sent] == ["POST"]
    assert slept and all(s <= 0.5 for s in slept)
    assert not out.ok


def test_stop_hook_ends_the_wait_and_blocks_the_send(monkeypatch):
    wire = Wire(monkeypatch, SHORT_429, OK)
    stop = threading.Event()
    monkeypatch.setattr(tenant_auth, "_sleep", lambda s: stop.set())
    helper = _client()._helper
    with zia_rate.stopping_on(stop.is_set):
        with pytest.raises(zia_rate.Cancelled):
            helper.send("GET", "/api/v1/dlpDictionaries")
        with pytest.raises(zia_rate.Cancelled):
            helper.send("GET", "/api/v1/dlpEngines")
    assert [u for _, u in wire.sent] == ["https://zsapi.zscalertwo.net/api/v1/dlpDictionaries"]


def test_a_short_429_is_waited_out_within_the_cap_and_retried(monkeypatch):
    wire = Wire(monkeypatch, SHORT_429, OK)
    slept = []
    monkeypatch.setattr(tenant_auth, "_sleep", slept.append)
    resp, info = _client()._helper.send("GET", "/api/v1/dlpDictionaries")
    assert resp.status_code == 200 and len(wire.sent) == 2
    assert sum(slept) == pytest.approx(2.0)


def test_retries_are_bounded(monkeypatch):
    wire = Wire(monkeypatch, SHORT_429, SHORT_429, SHORT_429, SHORT_429, OK)
    monkeypatch.setattr(tenant_auth, "_sleep", lambda s: None)
    with pytest.raises(Exception):
        _client(max_retries=2)._helper.send("GET", "/api/v1/dlpDictionaries")
    assert len(wire.sent) == 3


def test_attach_client_paces_classic_reads_at_the_read_bucket(monkeypatch):
    """zia_rate.attach_client now hooks the classic client: each request
    goes through _pace_session (zia_rate.wait with the tenant key)."""
    Wire(monkeypatch, OK, OK)
    paced = []
    real_wait = zia_rate.wait
    monkeypatch.setattr(zia_rate, "wait", lambda method, path="", *a, **k: (paced.append((method, path, k.get("key"))),
                                                                           real_wait(method, path, *a, **k))[1])
    client = zia_rate.attach_client(_client(), "tenant-key", ("classic API (zscalertwo)",))
    client.zia._helper.send("GET", "/api/v1/dlpDictionaries")
    client.zia._helper.send("GET", "/api/v1/dlpEngines")
    assert paced == [("GET", "/dlpDictionaries", "tenant-key"), ("GET", "/dlpEngines", "tenant-key")]
    assert zia_rate.bucket_of("GET", "/dlpDictionaries") == "read"


def test_the_sdk_services_go_through_the_new_send(monkeypatch):
    """A real SDK service on the classic client (what the packs call) reaches
    the replaced send, not the SDK's own loop."""
    wire = Wire(monkeypatch, HOURLY_429)
    monkeypatch.setattr(tenant_auth, "_sleep", lambda s: pytest.fail("no wait for an hourly refusal"))
    client = _client()
    data, resp, err = client.zia.dlp_dictionary.list_dicts()
    assert err is not None and "Retry wait time 3300" in str(err)
    assert len(wire.sent) == 1


def test_the_server_builds_the_classic_client_with_the_oneapi_caps(monkeypatch):
    import dlp_api_server as srv
    Wire(monkeypatch)
    seen = {}
    real = tenant_auth.build_legacy_sdk_client
    monkeypatch.setattr(tenant_auth, "build_legacy_sdk_client", lambda c, **kw: (seen.update(kw), real(c, **kw))[1])
    client = srv._build_sdk_client(CREDS)
    assert seen["max_retry_seconds"] == srv.SDK_MAX_RETRY_SECONDS and seen["max_retries"] == srv.SDK_MAX_RETRIES
    assert getattr(client._helper._dlp_check_session, "_zia_rate_paced", False)
