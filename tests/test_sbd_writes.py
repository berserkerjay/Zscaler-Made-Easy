"""Secure by Design: every path that changes a tenant (Wave 6, sbd-writes).

Table-driven over every write route (test_write_safety_gates.WRITE_CASES)
and every Bulk changes / Build new operation type (admin_ops.types()), so a
new route or plugin that breaks one of these rules fails CI:

* the four gates (write mode, writer, named assessor, confirmation) and the
  Scope page are checked before the tenant client is built, for every type;
  a type whose product is not ticked reads nothing (a tripwire client);
* every plugin re-plans before writing (plan_changed writes nothing), reads
  back, and offers an Undo or is listed as irreversible with the reason;
* typed phrases compare case-insensitively, never through a Unicode
  look-alike (decided: no NFKC; security.typed_phrase_matches), and a
  blank phrase never switches the confirmation off;
* defaults create nothing enabled or enforcing unless the operator chose it
  (plugins, remediation recipes; a recipe that leaves the state out is
  planned DISABLED); every AI Guard plan with a change asks its phrase
  (monitor-only too: nothing it writes is created disabled), Undo included;
* an Undo applies only the recorded inverse of its operation, once; the
  Undo-only forms (revert / undo) are refused as ordinary operations;
* two applies at once write once (pack_ops.tenant_run), a refused busy run
  is audited and a queued request stays approved;
* a create answered by a timeout or 5xx is not resent unless a read by
  name shows it absent (pack_ops.call, and the raw client's POST);
* a run that fails half way reports exactly what was written;
* whole-object updates (deploy confidence tweaks, proposal rollbacks, the
  migration wizard's delete-all and post) are re-checked against the
  tenant right before they are sent;
* the ZPA provisioning key reaches no sink (canary) and is revealed once,
  to the person whose run made it, on the job and the synchronous route;
* every write and refusal is on the audit log with its actor, no secret.

Everything runs against fakes (tests/zpa_fake.py, the recording world of
test_write_safety_gates, the plugin tests' fakes): no tenant, no network.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import threading
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import dlp_api_server as srv  # noqa: E402
import ops_zpa  # noqa: E402
import pack_ops as ops  # noqa: E402
import security  # noqa: E402
import sso  # noqa: E402
import zpa_reader  # noqa: E402
from zpa_fake import CANARY_KEY, Client as ZpaClient  # noqa: E402

CREDS = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-123", "client_secret": "not-a-real-secret",
         "customer_id": "7210000000000"}   # a ZPA bulk change needs it before sign-in (C6-ZPA-05)
ASSESSOR = "Jane Doe"
WRITER = {"sub": "w-1", "email": "writer@example.com", "groups": ["dlp-writers"]}
WRITER_2 = {"sub": "w-2", "email": "second@example.com", "groups": ["dlp-writers"]}
ZPA_SCOPE = {"scopes": ["zpa"], "channels": {}, "from_page": True}
BUILD = {"type": "zpa_connector_group", "prefix": "pov1"}


class Live:
    """SSO on with a writer list, write mode on, and every tenant client the
    app builds is one shared fake ZPA tenant (`builds` counts sign-ins)."""

    def __init__(self, monkeypatch):
        self.mp = monkeypatch
        self.zpa = ZpaClient()
        self.builds: List[str] = []
        monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: self.builds.append("sdk") or self.zpa)

    def client(self, who: Dict[str, Any] = WRITER) -> TestClient:
        c = TestClient(srv.app)
        c.cookies.set(security.SSO_SESSION_COOKIE, sso.create_session(dict(who)))
        return c

    def body(self, **extra: Any) -> Dict[str, Any]:
        return dict(CREDS, **ZPA_SCOPE, assessor=ASSESSOR, **extra)

    def preview(self, op: Dict[str, Any], who: Dict[str, Any] = WRITER) -> Dict[str, Any]:
        r = self.client(who).post("/api/operations/preview", json=self.body(operation=op))
        assert r.status_code == 200, r.text
        return r.json()

    def apply(self, op: Dict[str, Any], who: Dict[str, Any] = WRITER, **extra: Any):
        p = self.preview(op, who)
        body = self.body(operation=op, plan_hash=p["plan_hash"], confirm=True, confirm_text=p.get("confirm_phrase") or "")
        body.update(extra)
        return self.client(who).post("/api/operations/apply", json=body)


@pytest.fixture
def live(monkeypatch, tmp_path):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "1")
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", "https://idp.example.test/oauth2/default")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_ID", "client-123")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_SECRET", "not-a-real-secret")
    monkeypatch.setenv("ZSCALER_SSO_REDIRECT_URL", "http://testserver/api/auth/sso/callback")
    monkeypatch.setenv("ZSCALER_SSO_WRITERS", "dlp-writers")
    monkeypatch.setattr(sso, "_SESSIONS", {})
    monkeypatch.setattr(security, "_write_override", True)
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    ao.load_plugins()
    return Live(monkeypatch)


# ---------------------------------------------------------------------------
# Undo applies only the inverse it previewed, once
# ---------------------------------------------------------------------------

def test_undo_of_refuses_an_operation_that_is_not_the_recorded_inverse(live):
    """ASVS V11.1.1 · V4.1.3 · CWE-840 · CWE-345 · A04:2021: an apply naming undo_of must carry exactly that operation's recorded inverse; another operation is refused and nothing is written or marked undone."""
    # Arrange
    import deployments
    first = live.apply(BUILD)
    assert first.status_code == 200, first.text
    op_id = first.json()["operation_id"]
    live.zpa.tenant.writes.clear()
    # Act: a different operation (a second build) sent as the "undo" of the first
    r = live.apply({"type": "zpa_connector_group", "prefix": "pov2"}, undo_of=op_id)
    # Assert
    assert r.status_code in (400, 409), r.text
    assert live.zpa.tenant.writes == []
    assert not (deployments.get_operation(op_id) or {}).get("undone_by")


def test_an_operation_already_undone_cannot_be_undone_again(live):
    """ASVS V11.1.1 · CWE-841 · A04:2021: once an operation is undone, a second apply with the same undo_of is refused before signing in."""
    # Arrange
    first = live.apply(BUILD)
    op_id = first.json()["operation_id"]
    prev = live.client().post(f"/api/operations/{op_id}/undo/preview", json=live.body())
    assert prev.status_code == 200, prev.text
    inv, ph = prev.json()["operation"], prev.json()["plan_hash"]
    done = live.client().post("/api/operations/apply", json=live.body(operation=inv, plan_hash=ph, confirm=True, undo_of=op_id,
                                                                      confirm_text=prev.json().get("confirm_phrase") or ""))
    assert done.status_code == 200 and done.json()["status"] == "applied", done.text
    live.builds.clear()
    # Act
    again = live.client().post("/api/operations/apply", json=live.body(operation=inv, plan_hash=ph, confirm=True, undo_of=op_id,
                                                                       confirm_text=prev.json().get("confirm_phrase") or ""))
    # Assert
    assert again.status_code == 409, again.text
    assert live.builds == []


# ---------------------------------------------------------------------------
# The provisioning key is revealed only to who ran the build
# ---------------------------------------------------------------------------

def test_a_key_from_a_synchronous_apply_is_bound_to_the_person_who_ran_it(live):
    """ASVS V4.2.1 · V8.3.4 · CWE-639 · CWE-200 · A01:2021: the provisioning key of a build applied through the synchronous route is revealed to its runner only, never to another writer holding the token."""
    # Arrange
    r = live.apply(BUILD, who=WRITER)
    assert r.status_code == 200, r.text
    token = r.json()["one_time_secrets"][0]["token"]
    # Act
    other = live.client(WRITER_2).post("/api/operations/zpa/provisioning-key", json={"token": token})
    mine = live.client(WRITER).post("/api/operations/zpa/provisioning-key", json={"token": token})
    # Assert
    assert other.status_code == 404 and CANARY_KEY not in other.text
    assert mine.status_code == 200 and mine.json()["provisioning_key"] == CANARY_KEY
    assert mine.headers.get("cache-control") == "no-store"


# ---------------------------------------------------------------------------
# Typed confirmation: case-insensitive, never empty, never a look-alike
# ---------------------------------------------------------------------------

import test_write_safety_gates as gates  # noqa: E402
from test_write_safety_gates import world  # noqa: E402,F401  (the recording world: sinks stubbed, SSO writer list)

_REAL_UNDO = __import__("pack_deploy").undo   # taken before the world fixture stubs it

# (typed, accepted?) for the phrase "I UNDERSTAND". No NFKC: what str.upper()
# or NFKC would fold into the phrase is refused.
LOOKALIKES = [
    ("I UNDERSTAND", True), ("i understand", True), ("  I Understand  ", True),
    ("ı understand", False),                       # dotless i: upper() gives I
    ("I UNDERſTAND", False),                       # long s: upper() gives S
    ("Ｉ ＵＮＤＥＲＳＴＡＮＤ", False),   # full-width (NFKC folds it)
    ("І UNDERSTAND", False),                       # Cyrillic I
    ("I UNDERSTAND​", False),                      # zero-width space
    ("I  UNDERSTAND", False), ("", False), ("   ", False), ("I UNDERSTAN", False),
]


@pytest.mark.parametrize("typed,ok", LOOKALIKES, ids=[repr(t) for t, _ in LOOKALIKES])
def test_typed_phrase_matches_is_case_insensitive_and_refuses_lookalikes(typed, ok):
    """ASVS V11.1.1 · V5.1.4 · CWE-176 · CWE-1289 · A04:2021: a typed phrase matches case-insensitively, never through Unicode case folding or NFKC look-alikes."""
    # Act / Assert
    assert security.typed_phrase_matches(typed, "I UNDERSTAND") is ok


@pytest.mark.parametrize("phrase", ["", "   ", None, 7])
def test_an_empty_or_missing_phrase_never_matches(phrase):
    """ASVS V11.1.1 · CWE-1289 · CWE-287: a blank, missing or non-text phrase matches nothing, not even blank input (fail closed)."""
    for typed in ("", "   ", None, phrase):
        assert security.typed_phrase_matches(typed, phrase) is False


PHRASE_CASES = [c for c in gates.WRITE_CASES if c[4] == gates.PHRASE]


@pytest.mark.parametrize("case", PHRASE_CASES, ids=[c[0] for c in PHRASE_CASES])
@pytest.mark.parametrize("typed", ["ı understand", "I UNDERſTAND"], ids=["dotless-i", "long-s"])
def test_every_typed_phrase_route_refuses_a_unicode_lookalike(world, case, typed):
    """ASVS V11.1.1 · V4.1.3 · CWE-176 · CWE-841 · A04:2021: each route that asks for a typed phrase refuses a look-alike that str.upper() would accept, before signing in, and writes nothing."""
    # Arrange
    _id, method, _route, arrange, _kind = case
    world.write_mode(True)
    url, body = arrange(world)
    body["confirm"] = typed
    # Act
    r = world.client(gates.WRITER).request(method, url, json=body)
    # Assert
    assert r.status_code == 400, (url, r.status_code, r.text[:300])
    assert world.touched() == [] and world.built == []


@pytest.mark.parametrize("case", PHRASE_CASES, ids=[c[0] for c in PHRASE_CASES])
def test_every_typed_phrase_route_accepts_the_phrase_in_lower_case(world, case):
    """ASVS V11.1.1 · CWE-841: positive control: the phrase typed in lower case with spaces around it is accepted (case-insensitive by design)."""
    # Arrange
    _id, method, _route, arrange, _kind = case
    world.write_mode(True)
    url, body = arrange(world)
    body["confirm"] = "  " + gates.PHRASE.lower() + " "
    # Act
    r = world.client(gates.WRITER).request(method, url, json=body)
    # Assert
    assert r.status_code == 200, r.text[:300]
    assert world.sinks


def _prepared(phrase: str, changes: int = 3) -> Dict[str, Any]:
    return {"confirm_phrase": phrase, "counts": {"change": changes}}


@pytest.mark.parametrize("typed,ok", [("delete pov1", True), (" DELETE POV1 ", True), ("DELETE POV1", True),
                                      ("DELETE POᴠ1", False), ("DELETE ＰOV1", False), ("DELETE POV１", False),
                                      ("", False), ("  ", False), (None, False)])
def test_operation_confirmation_compares_like_every_other_typed_phrase(typed, ok):
    """ASVS V11.1.1 · CWE-176 · CWE-1289: a Bulk changes / Build new plan's own phrase (confirm_always) is checked with the same rule: full-width digits or letters (NFKC look-alikes) are refused."""
    # Act
    why = ao.check_confirmation(_prepared("DELETE POV1"), typed)
    # Assert
    assert (why is None) is ok


def test_a_count_phrase_rejects_a_long_s_lookalike():
    """ASVS V11.1.1 · CWE-176: 'APPLY 12 CHANGEſ' (long s, which str.upper() turns into S) does not confirm 12 changes."""
    # Arrange
    prepared = _prepared(ao.confirm_phrase(12), changes=12)
    # Act / Assert
    assert ao.check_confirmation(prepared, "apply 12 changes") is None
    assert ao.check_confirmation(prepared, "apply 12 changeſ") is not None


# ---------------------------------------------------------------------------
# Concurrency: two applies of the same plan at once write once
# ---------------------------------------------------------------------------

def _hold_first_create(zpa_client: ZpaClient):
    """Make the fake's first connector-group create wait until released:
    (entered, release, calls). Deterministic: events, no sleeps."""
    svc = zpa_client.zpa.app_connector_groups
    real = svc.add_connector_group
    entered, release, calls = threading.Event(), threading.Event(), []

    def add(**kw):
        calls.append(kw.get("name"))
        if len(calls) == 1:
            entered.set()
            release.wait(10)
        return real(**kw)
    svc.add_connector_group = add
    return entered, release, calls


def test_two_applies_of_the_same_plan_at_once_send_one_create(monkeypatch):
    """ASVS V11.1.6 · V1.11.3 · CWE-362 · CWE-367 · A04:2021: while one apply of a plan is writing, a second apply of the same plan on the same tenant writes nothing (refused as busy), so each object is created once."""
    # Arrange
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    ao.load_plugins()
    scope = ao.scope_for(["zpa"], {})
    client = ZpaClient()
    client._zia_rate_key = "tenant-acme"
    entered, release, calls = _hold_first_create(client)
    plan = ao.plan(client, BUILD, scope=scope, tenant_label="acme")
    kw = dict(plan_hash=plan["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme")
    first: Dict[str, Any] = {}
    t = threading.Thread(target=lambda: first.update(ao.execute(client, BUILD, **kw)))
    t.start()
    assert entered.wait(10)
    # Act: the same plan again while the first is between its re-check and its write
    second = ao.execute(client, BUILD, **kw)
    release.set()
    t.join(10)
    # Assert
    assert calls == ["pov1-connector-group"], calls
    assert second["status"] == "blocked" and second.get("busy") is True and second["items"] == []
    assert first["status"] == "applied"


def test_the_run_lock_is_per_tenant_and_released_after_the_run(monkeypatch):
    """ASVS V11.1.6 · CWE-667 · CWE-833: the run lock never blocks another tenant and is released when a run ends, also when it raises."""
    # Arrange
    a, b = SimpleNamespace(_zia_rate_key="tenant-a"), SimpleNamespace(_zia_rate_key="tenant-b")
    # Act / Assert
    with ops.tenant_run(a) as got_a:
        assert got_a is True
        with ops.tenant_run(b) as got_b:
            assert got_b is True
        with ops.tenant_run(SimpleNamespace(_zia_rate_key="tenant-a")) as again:
            assert again is False
    with pytest.raises(RuntimeError):
        with ops.tenant_run(a):
            raise RuntimeError("boom")
    with ops.tenant_run(a) as after:
        assert after is True


# A deployment whose confidence tweak raised one existing dictionary from
# LOW to HIGH; the tenant still holds HIGH, so its Undo would PUT it back.
TWEAK_RECORD = {"id": "dep-tweak", "created": [], "other": [
    {"kind": "tweak", "status": "modified", "id": 55, "name": "QA Dict", "dictionary": "QA Dict", "field": "confidence_threshold",
     "before": "CONFIDENCE_LEVEL_LOW", "after": "CONFIDENCE_LEVEL_HIGH"}]}


def _tweaked_tenant():
    from test_pack_deploy import FakeClient, Obj
    return FakeClient(dicts=[Obj(id=55, name="QA Dict", custom=True, confidence_threshold="CONFIDENCE_LEVEL_HIGH")])


@pytest.mark.parametrize("runner", ["deploy", "removal", "operation", "undo"])
def test_every_write_run_refuses_while_another_run_holds_the_tenant(monkeypatch, runner):
    """ASVS V11.1.6 · CWE-362 · A04:2021: a pack deploy, a removal, a bulk change and a deployment Undo each refuse to start (status blocked, busy, nothing read or written) while another write run holds the same tenant."""
    # Arrange
    import pack_deploy
    import pack_removal
    writes: List[str] = []
    client = gates.Recorder(writes)   # answers every attribute, so its tenant key is given through zia_rate.key_of
    tweaked = _tweaked_tenant()       # the Undo's tenant: a dictionary its tweak would put back
    holder = SimpleNamespace(_zia_rate_key="tenant-acme")
    monkeypatch.setattr(pack_deploy, "preflight", lambda *a, **k: pytest.fail("read the tenant while busy"))
    monkeypatch.setattr(pack_removal, "_execute_run", lambda *a, **k: pytest.fail("ran while busy"))
    monkeypatch.setattr(ao, "_execute", lambda *a, **k: pytest.fail("ran while busy"))
    import zia_rate
    monkeypatch.setattr(zia_rate, "key_of", lambda c: "tenant-acme")
    call = {"deploy": lambda: pack_deploy.apply(client, [], plan_hash="h", writes_enabled=True),
            "removal": lambda: pack_removal.remove(client, [], plan_hash="h", writes_enabled=True),
            "operation": lambda: ao.execute(client, BUILD, plan_hash="h", scope={}, writes_enabled=True, assessor=ASSESSOR),
            "undo": lambda: pack_deploy.undo(tweaked, copy.deepcopy(TWEAK_RECORD), writes_enabled=True, settle_seconds=0)}[runner]
    # Act
    with ops.tenant_run(holder) as got:
        assert got
        out = call()
    # Assert
    assert out["status"] == "blocked" and out.get("busy") is True, out
    assert writes == [] and tweaked.zia.dlp_dictionary.updated == []
    assert not [r for r in out.get("results") or [] if r.get("status") == "restored"]


def test_a_deployment_undo_on_a_busy_tenant_puts_nothing_and_is_audited(world, monkeypatch):
    """ASVS V11.1.6 · V7.1.3 · CWE-362 · A04:2021: POST /api/deployments/{id}/undo while another run holds the tenant answers blocked, sends no dictionary PUT and leaves a run_refused audit entry."""
    # Arrange
    import audit
    import deployments
    import zia_rate
    monkeypatch.setattr(__import__("pack_deploy"), "undo", _REAL_UNDO)   # the world stubs it; this test needs the real one
    world.write_mode(True)
    tenant = _tweaked_tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: tenant)
    monkeypatch.setattr(zia_rate, "key_of", lambda c: "tenant-acme")
    rec = deployments.from_apply({"results": [{"kind": "dictionary", "name": "QA Created", "id": 9001, "status": "created"},
                                              {"kind": "tweak", "name": "QA Dict", "id": 55, "status": "modified", "dictionary": "QA Dict",
                                               "field": "confidence_threshold", "before": "CONFIDENCE_LEVEL_LOW",
                                               "after": "CONFIDENCE_LEVEL_HIGH"}]},
                                 tenant_label=gates.tenant_auth.record_label(world.creds()), packs=[gates.PACK], options={}, by=ASSESSOR,
                                 **srv._record_ids(world.creds()))
    deployments.add(rec)
    # Act
    with ops.tenant_run(SimpleNamespace(_zia_rate_key="tenant-acme")) as got:
        assert got
        r = world.client(WRITER).post(f"/api/deployments/{rec['id']}/undo", json=gates._b(confirm=True))
    # Assert
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "blocked" and out.get("busy") is True
    assert tenant.zia.dlp_dictionary.updated == []
    refused = [e for e in audit.tail(50) if e.get("event") == "run_refused" and e.get("run") == "undo"]
    assert len(refused) == 1 and refused[0]["actor"] == WRITER["email"] and "not-a-real-secret" not in json.dumps(refused[0])
    assert (deployments.get(rec["id"]) or {}).get("undo") is None   # nothing ran, so the record keeps no undo outcome


def test_a_deployment_undo_restores_its_tweak_and_removes_under_one_hold(monkeypatch):
    """ASVS V11.1.6 · CWE-667 · CWE-833: an Undo holds the tenant once for its tweak PUT and its removal (never deadlocks on its own lock) and releases it afterwards."""
    # Arrange
    import pack_deploy
    import zia_rate
    monkeypatch.setattr(zia_rate, "key_of", lambda c: "tenant-acme")
    monkeypatch.setattr(ops, "activate_once", lambda zia, log=None: {"activated": True, "status": "ACTIVE"})
    tenant = _tweaked_tenant()
    held_during_put: List[bool] = []
    real_update = tenant.zia.dlp_dictionary.update_dict

    def update(id_, **kw):
        with ops.tenant_run(SimpleNamespace(_zia_rate_key="tenant-acme")) as other:
            held_during_put.append(not other)
        return real_update(id_, **kw)
    tenant.zia.dlp_dictionary.update_dict = update
    # Act
    out = pack_deploy.undo(tenant, copy.deepcopy(TWEAK_RECORD), writes_enabled=True, settle_seconds=0)
    # Assert
    assert [r["status"] for r in out["results"] if r["kind"] == "tweak"] == ["restored"], out
    assert held_during_put == [True] and out.get("busy") is not True
    with ops.tenant_run(SimpleNamespace(_zia_rate_key="tenant-acme")) as after:
        assert after is True


def test_a_refused_busy_run_is_on_the_audit_log_with_its_actor(monkeypatch, tmp_path):
    """ASVS V7.1.3 · V7.2.2 · CWE-778 · A09:2021: a write run refused because the tenant is busy leaves a run_refused audit entry naming the actor, the run and the plan, and no secret."""
    # Arrange
    import audit
    holder = SimpleNamespace(_zia_rate_key="tenant-acme", _zia_rate_label="acme (zscalerten)")
    client = SimpleNamespace(_zia_rate_key="tenant-acme", _zia_rate_label="acme (zscalerten)")
    # Act
    with ops.tenant_run(holder), ops.audit_scope(actor="writer@example.com"):
        out = ao.execute(client, BUILD, plan_hash="h" * 64, scope={}, writes_enabled=True, assessor=ASSESSOR, confirm_text="x")
    # Assert
    entries = [e for e in audit.tail(50) if e.get("event") == "run_refused"]
    assert out.get("busy") and len(entries) == 1
    e = entries[0]
    assert e["actor"] == "writer@example.com" and e["run"] == "operation" and e["tenant"] == "acme (zscalerten)"
    assert e["plan_hash"] == "h" * 64 and "not-a-real-secret" not in json.dumps(e)


def test_a_queued_request_refused_as_busy_stays_approved(world, monkeypatch):
    """ASVS V11.1.1 · CWE-841 · A04:2021: an approved change request whose apply found the tenant busy is not burnt as failed: nothing was written and it stays approved to apply again."""
    # Arrange
    import change_queue
    import pack_deploy
    world.write_mode(True)
    url, body = [c for c in gates.WRITE_CASES if c[0] == "queue-apply-deploy"][0][3](world)
    rid = url.split("/")[3]
    monkeypatch.setattr(pack_deploy, "apply", lambda *a, **k: ops.busy_result(plan_hash=gates.HASH))
    # Act
    r = world.client(gates.WRITER).post(url, json=body)
    # Assert
    assert r.status_code == 200, r.text
    rec = change_queue.get(rid)
    assert rec["status"] == "approved" and not rec.get("applying"), rec.get("status")
    assert world.touched() == []


# ---------------------------------------------------------------------------
# Retries: a create that timed out is never sent again blind
# ---------------------------------------------------------------------------

READ_NAME = gates.READ_NAME


class TimeoutTenant:
    """Any product root (ZIA, ZPA, ZDX, AI Guard): every write answers a
    gateway timeout (HTTP 504: it may have been applied), every read answers
    empty. `seq` is the order of reads (R) and writes (W) sent."""

    def __init__(self, seq: List[str], path=()):
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "path", path)

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return TimeoutTenant(self.seq, self.path + (name,))

    def __setattr__(self, name, value):
        pass

    def __call__(self, *args, **kwargs):
        name = self.path[-1] if self.path else ""
        if name == "create_request":      # the raw request: the method decides
            return ((str(args[0]).upper() if args else "GET"), None)
        if name == "execute" and args and args[0] == "GET":
            self.seq.append("R")
            return ([], None)
        if name != "execute" and READ_NAME.search(name):
            self.seq.append("R")
            return ([], None, None)
        self.seq.append("W")
        return (None, "HTTP 504 Gateway Timeout") if name == "execute" else (None, None, "HTTP 504 Gateway Timeout")


def _create_kinds() -> List[tuple]:
    import pack_channels as pc
    kinds = [("dictionary", None), ("engine", None), ("app_group", None), ("url_category", None), ("zpa_segment", None),
             ("zdx_app", None), ("zdx_probe", None), ("zdx_collection", None)]
    kinds += [(k, None) for k in ops.AIGUARD_ZIA_KINDS if k != "url_app_settings"] + [(k, None) for k in ops.AIGUARD_KINDS]
    kinds += [(k, None) for k in ops.ZPA_KINDS]
    kinds += [("policy", ch) for ch in list(pc.CHANNELS) + list(ops.ADMIN_RULE_SERVICES)]
    return kinds


CREATE_KINDS = _create_kinds()


@pytest.mark.parametrize("kind,channel", CREATE_KINDS, ids=[f"{k}-{c}" if c else k for k, c in CREATE_KINDS])
def test_a_create_that_timed_out_is_never_resent_without_a_check_by_name(kind, channel):
    """ASVS V11.1.6 · V1.11.3 · CWE-694 · CWE-837 · A04:2021: for every object kind the shared path creates, a create answered by a timeout (it may have been applied) is sent again only after a read by name found no such object; otherwise it is not resent."""
    # Arrange
    seq: List[str] = []
    payload = {"name": "QA object", "custom_phrase_match_type": "MATCH_ANY", "dictionary_type": "PATTERNS_AND_PHRASES", "type": "WEBMAIL"}
    # Act
    out = ops.create(TimeoutTenant(seq), kind, payload, channel=channel, name="QA object")
    # Assert
    assert not out.ok
    assert "W" in seq, seq
    assert "WW" not in "".join(seq), f"{kind}/{channel}: a timed-out create was sent again blind: {seq}"


def test_a_timed_out_create_found_by_name_is_reused_not_sent_again():
    """ASVS V11.1.6 · CWE-694: when the read by name finds the object a timed-out create made, it is used (its id) and the create is not sent again."""
    # Arrange
    made: List[str] = []

    def add(**kw):
        made.append(kw["name"])
        return (None, None, "HTTP 504 Gateway Timeout")
    # Act
    out = ops.call(add, op="create", kind="zpa_segment", name="QA", kw={"name": "QA"}, exists=lambda: "seg-1" if made else None)
    # Assert
    assert out.ok and out.id == "seg-1" and made == ["QA"]


def test_a_create_refused_for_the_rate_limit_is_still_retried():
    """ASVS V11.1.6 · CWE-694: positive control: a 429 means the create was never processed, so it is retried as before."""
    # Arrange
    calls: List[int] = []

    def add(**kw):
        calls.append(1)
        return (None, None, "HTTP 429 Too Many Requests") if len(calls) == 1 else ({"id": 7, "name": "QA"}, None, None)
    # Act
    out = ops.call(add, op="create", kind="zpa_segment", name="QA", kw={"name": "QA"})
    # Assert
    assert out.ok and out.id == 7 and len(calls) == 2


def test_an_update_that_timed_out_is_still_retried():
    """ASVS V11.1.6 · CWE-694: positive control: an update (PUT, idempotent) after a timeout is retried as before."""
    calls: List[int] = []

    def upd(*a, **kw):
        calls.append(1)
        return (None, None, "HTTP 504 Gateway Timeout") if len(calls) == 1 else ({"id": 7}, None, None)
    out = ops.call(upd, 7, op="update", kind="zpa_segment", name="QA", kw={"name": "QA"})
    assert out.ok and len(calls) == 2


# ---------------------------------------------------------------------------
# Every AI Guard plan with a change asks for its typed phrase, whatever the
# count and the mode (nothing it writes is created disabled), Undo included
# ---------------------------------------------------------------------------

@pytest.fixture
def aig(monkeypatch):
    import pack_channels as pc
    import test_ops_aiguard as t_aig
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    return t_aig


@pytest.mark.parametrize("spec_name", ["ROUTE", "POLICY_BLOCK"])
def test_an_ai_guard_plan_that_turns_enforcement_on_needs_the_typed_phrase(aig, spec_name):
    """ASVS V11.1.1 · V1.4.1 · CWE-1188 · CWE-841 · A04:2021: AI Guard routing (it creates ENABLED ZIA rules: SSL Inspect at the top, Allow above Block, forwarding) and a blocking detection policy ask for the typed phrase whatever the count, as the ZIA baseline does; confirm=true alone writes nothing."""
    # Arrange
    f = aig.Fake(proxy=True, gateway=True)
    spec = aig.ROUTE if spec_name == "ROUTE" else dict(aig.POLICY, mode="block")
    p = aig.preview(f, spec)
    assert p["status"] == "ready" and p["counts"]["change"] <= ao.CONFIRM_ABOVE
    # Act
    refused = ao.execute(f, spec, plan_hash=p["plan_hash"], scope=aig.FULL, writes_enabled=True, assessor=ASSESSOR, confirm_text="",
                         settle_seconds=0)
    # Assert
    assert p["confirm_phrase"], "an enforcing AI Guard plan names a typed phrase"
    assert refused["status"] == "refused" and not [w for w in f.t.writes if w[1] in ("add", "update", "delete")]


def test_a_monitor_only_ai_guard_policy_still_asks_for_its_phrase(aig):
    """ASVS V11.1.1 · CWE-1188 · CWE-841: the detection policy in its default monitor mode (detect only) is still live once saved, so it asks for its typed phrase whatever the count, and an execute with no phrase is refused with no write."""
    # Arrange
    f = aig.Fake()
    p = aig.preview(f, aig.POLICY)
    # Act
    refused = ao.execute(f, aig.POLICY, plan_hash=p["plan_hash"], scope=aig.FULL, writes_enabled=True, assessor=ASSESSOR, confirm_text="",
                         settle_seconds=0)
    # Assert
    assert p["spec"].get("mode", "monitor") == "monitor" and p["confirm_phrase"].startswith("APPLY ")
    assert refused["status"] == "refused" and not [w for w in f.t.writes if w[1] in ("add", "update", "delete")]


@pytest.mark.parametrize("spec_name", ["ROUTE", "POLICY"])
def test_an_ai_guard_undo_plan_asks_for_its_phrase_and_refuses_a_blank_one(aig, spec_name):
    """ASVS V11.1.1 · V1.4.1 · CWE-841 · A04:2021: the Undo plan of an applied AI Guard change (it deletes live rules) asks for its typed phrase too; an execute with a blank phrase is refused and writes nothing."""
    # Arrange
    f = aig.Fake(proxy=True, gateway=True)
    spec = getattr(aig, spec_name)
    done = aig.apply(f, spec)
    assert done["status"] == "applied" and done["inverse"], done.get("status")
    inverse = done["inverse"]
    before = len(f.t.writes)
    p = aig.preview(f, inverse)
    # Act
    refused = ao.execute(f, inverse, plan_hash=p["plan_hash"], scope=aig.FULL, writes_enabled=True, assessor=ASSESSOR, confirm_text="",
                         settle_seconds=0)
    # Assert
    assert p["counts"]["change"] > 0 and p["confirm_phrase"].startswith("APPLY ")
    assert refused["status"] == "refused" and not [w for w in f.t.writes[before:] if w[1] in ("add", "update", "delete")]


# ---------------------------------------------------------------------------
# Every operation type: gates, scope, re-plan, read-back, Undo, defaults
# ---------------------------------------------------------------------------

ao.load_plugins()
ALL_TYPES = list(ao.types())
EVERYTHING = {"scopes": ["dlp", "zia_extras", "zpa", "zcc", "zdx", "aiguard", "zidentity"],
              "channels": {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "cloud_app_control", "ssl_inspection")},
              "from_page": True}
# The Scope page keys that put each product in scope.
PRODUCT_KEYS = {"zia": ("dlp", "zia_extras"), "zpa": ("zpa",), "zcc": ("zcc",), "zdx": ("zdx",), "aiguard": ("aiguard",),
                "zidentity": ("zidentity",)}
BUILTIN_PRODUCT = {"rule_state": "zia", "reorder": "zia", "url_categories": "zia", "zpa_domains": "zpa"}


def _product(t: str) -> str:
    return BUILTIN_PRODUCT.get(t) or ao.PLUGINS[t]["product"]


def _without_product(t: str) -> Dict[str, Any]:
    keys = PRODUCT_KEYS[_product(t)] + (("aiguard",) if t.startswith("aiguard_") else ())
    return dict(EVERYTHING, scopes=[s for s in EVERYTHING["scopes"] if s not in keys])


def _op_body(t: str, scope: Dict[str, Any] = EVERYTHING, **extra: Any) -> Dict[str, Any]:
    return dict(CREDS, **scope, assessor=gates.ASSESSOR, operation={"type": t}, plan_hash=gates.HASH, confirm=True,
                confirm_text="APPLY", **extra)


def test_every_operation_type_is_known_to_these_tables():
    """ASVS V1.4.1 · CWE-1059: every Bulk changes / Build new type maps to a product with Scope page keys, so the tables below cover a new one."""
    assert len(ALL_TYPES) >= 17
    for t in ALL_TYPES:
        assert _product(t) in PRODUCT_KEYS, t


@pytest.mark.parametrize("route", ["/api/operations/apply", "/api/operations/apply/start"])
@pytest.mark.parametrize("t", ALL_TYPES)
def test_every_operation_type_with_every_gate_held_reaches_the_write(world, t, route):
    """ASVS V1.4.1 · CWE-862 · A01:2021: positive control per operation type: with the four gates held the apply reaches the write path."""
    world.write_mode(True)
    r = world.client(gates.WRITER).post(route, json=_op_body(t))
    assert r.status_code == 200, r.text[:300]
    assert world.sinks == ["admin_ops.execute"] and world.built


OP_GATES = ["write-mode-off", "not-a-writer", "not-signed-in", "assessor-blank", "assessor-is-the-tool", "confirm-false",
            "plan-hash-missing"]


@pytest.mark.parametrize("gate", OP_GATES)
@pytest.mark.parametrize("t", ALL_TYPES)
def test_every_operation_type_is_refused_before_sign_in_when_any_gate_is_missing(world, t, gate):
    """ASVS V4.1.3 · V11.1.1 · CWE-862 · CWE-841 · A01:2021: for every operation type, any one gate missing refuses the apply before the tenant client is built, and nothing is written."""
    # Arrange
    world.write_mode(gate != "write-mode-off")
    who = {"not-a-writer": gates.READER, "not-signed-in": None}.get(gate, gates.WRITER)
    body = _op_body(t)
    if gate == "assessor-blank":
        body["assessor"] = "  "
    elif gate == "assessor-is-the-tool":
        body["assessor"] = "Zscaler Made Easy"
    elif gate == "confirm-false":
        body["confirm"] = False
    elif gate == "plan-hash-missing":
        body["plan_hash"] = ""
    # Act
    r = world.client(who).post("/api/operations/apply", json=body)
    # Assert
    assert 400 <= r.status_code < 500, (t, gate, r.status_code, r.text[:200])
    assert world.built == [] and world.touched() == []


@pytest.mark.parametrize("route", ["/api/operations/preview", "/api/operations/preview/start", "/api/operations/apply",
                                   "/api/operations/apply/start"])
@pytest.mark.parametrize("t", ALL_TYPES)
def test_every_operation_type_out_of_scope_is_refused_before_sign_in(world, t, route):
    """ASVS V4.1.3 · V4.2.1 · CWE-863 · WSTG-ATHZ-02 · A01:2021: an operation whose product is not ticked on the Scope page is refused (400) before the tenant client is built, whatever else is ticked."""
    world.write_mode(True)
    r = world.client(gates.WRITER).post(route, json=_op_body(t, _without_product(t)))
    assert r.status_code == 400, (t, route, r.status_code, r.text[:200])
    assert world.built == [] and world.touched() == []


FAMILIES = sorted({"rules", "url_categories", "zpa_segments"} | set(ao.PLUGIN_FAMILIES))
FAMILY_TYPE = {f: next(t for t in ao.PLUGINS if ao.PLUGINS[t]["family"] == f) for f in ao.PLUGIN_FAMILIES}
FAMILY_TYPE.update({"rules": "rule_state", "url_categories": "url_categories", "zpa_segments": "zpa_domains"})


@pytest.mark.parametrize("route", ["/api/operations/objects", "/api/operations/objects/start"])
@pytest.mark.parametrize("family", FAMILIES)
def test_every_object_picker_out_of_scope_is_refused_before_sign_in(world, family, route):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the object picker of every family is refused before sign-in when its product is not ticked."""
    body = dict(CREDS, **_without_product(FAMILY_TYPE[family]), family=family)
    r = world.client(gates.WRITER).post(route, json=body)
    assert r.status_code == 400, (family, r.status_code, r.text[:200])
    assert world.built == []


class Tripwire:
    """A tenant client that fails the test on any use: nothing may be read."""

    def __getattr__(self, name):
        if name.startswith("__") or name.startswith("_zia_rate"):   # the app's own stamps (tenant key, label), not a read
            raise AttributeError(name)
        pytest.fail(f"the tenant was read before the scope check ({name})")


@pytest.mark.parametrize("t", ALL_TYPES)
def test_every_operation_type_out_of_scope_reads_nothing(t):
    """ASVS V4.1.3 · CWE-863 · A01:2021: planning, applying or listing an operation type out of scope raises before the client is touched (user rule 1)."""
    sel = _without_product(t)
    scope = ao.scope_for(sel["scopes"], sel["channels"])
    with pytest.raises(ao.OperationError):
        ao.plan(Tripwire(), {"type": t}, scope=scope)
    with pytest.raises(ao.OperationError):
        ao.execute(Tripwire(), {"type": t}, plan_hash=gates.HASH, scope=scope, writes_enabled=True, assessor=ASSESSOR)
    fam = ao.PLUGINS[t]["family"] if t in ao.PLUGINS else {"rule_state": "rules", "reorder": "rules"}.get(t, FAMILY_TYPE.get(t, t))
    if fam in FAMILIES:
        with pytest.raises(ao.OperationError):
            ao.read_objects(Tripwire(), fam, scope)


@pytest.mark.parametrize("t", sorted(ao.PLUGINS))
def test_every_plugin_re_plans_before_writing_and_a_moved_tenant_writes_nothing(monkeypatch, t):
    """ASVS V11.1.1 · V1.11.3 · CWE-367 · CWE-841 · A04:2021: for every plugin type the apply plans again from the tenant; a different plan hash (the tenant moved) gives plan_changed and no handler runs."""
    # Arrange
    sel = EVERYTHING
    scope = ao.scope_for(sel["scopes"], sel["channels"])
    calls = {"plan": 0}

    def fake_plan(client, spec, scope, say, cancel):
        calls["plan"] += 1
        return {"type": t, "product": ao.PLUGINS[t]["product"], "title": "QA", "spec": spec,
                "items": [ao._unit("k", "g", "qa", {"name": "QA"}, "state", f"before-{calls['plan']}", "after")],
                "groups": [{"key": "g", "handler": "qa_tripwire", "target": {}}]}
    monkeypatch.setitem(ao.PLUGINS, t, dict(ao.PLUGINS[t], plan=fake_plan))
    monkeypatch.setitem(ao.PLUGIN_HANDLERS, "qa_tripwire", lambda run, g, units: pytest.fail("wrote although the tenant moved"))
    preview = ao.plan(SimpleNamespace(zia=None, zpa=None), {"type": t}, scope=scope)
    # Act
    out = ao.execute(SimpleNamespace(zia=None, zpa=None), {"type": t}, plan_hash=preview["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR)
    # Assert
    assert calls["plan"] == 2 and out["status"] == "plan_changed" and out["items"] == []


IRREVERSIBLE = {"zcc_profile_delete": "a deleted Client Connector profile cannot be brought back from the API; the plan says so and asks its name typed"}


@pytest.mark.parametrize("t", sorted(ao.PLUGINS))
def test_every_plugin_reads_back_and_offers_an_undo_or_says_why_not(t):
    """ASVS V11.1.1 · V7.1.3 · CWE-754 · A04:2021: every plugin type registers a read-back (verify) and an inverse for Undo, unless it is listed as irreversible with the reason."""
    p = ao.PLUGINS[t]
    assert callable(p["verify"]), f"{t}: no read-back"
    assert callable(p["inverse"]) or t in IRREVERSIBLE, f"{t}: no Undo and not listed as irreversible"


def _zcc_default():
    import ops_zcc
    return ops_zcc.normalize_spec({"platform": "windows", "forwarding": {"template": "best_practice", "name": "QA fwd"},
                                   "app": {"template": "best_practice", "name": "QA app"}})["enable"] is False


def _baseline_default():
    import ops_zia_baseline
    return ops_zia_baseline.normalize({"type": "zia_baseline"})["enable_rules"] is False


def _zpa_segments_default():
    c = ZpaClient()
    c.tenant.add("connector_group", {"name": "pov1-connector-group", "enabled": True})
    scope = ao.scope_for(["zpa"], {})
    p = ao.plan(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "443"}}, scope=scope)
    segs = [g["target"] for g in p["groups"] if g["target"].get("kind") == "segment"]
    return bool(segs) and all((s.get("desired") or {}).get("enabled") is False for s in segs)


def _aiguard_policy_default():
    import test_ops_aiguard as t_aig
    spec = {k: v for k, v in t_aig.POLICY.items() if k != "mode"}
    p = t_aig.preview(t_aig.Fake(), spec)
    return p["status"] == "ready" and "Monitor" in p["title"]


def _rule_edit_default():
    import ops_rule_editor
    n = ops_rule_editor.normalize({"type": "rule_edit", "action": "create", "policy": "url_filtering",
                                   "fields": {"name": "QA", "action": "BLOCK", "url_categories": ["GAMBLING"]}})
    return n["enabled"] is False


def _config_restore_default():
    """A clone from a backup creates its rules and segments disabled unless
    the operator ticks 'keep each rule's state' (ops_config_restore)."""
    import config_backup as cb
    import ops_config_restore as ocr
    rule = {"id": 10, "name": "R", "order": 1, "state": "ENABLED", "action": "BLOCK"}
    seg = {"id": "601", "name": "S", "enabled": True, "domain_names": ["a.example"]}
    src = {"zia.url_filtering_rules": [rule], "zpa.application_segments": [seg]}
    tgt = {"zia.url_filtering_rules": [], "zpa.application_segments": []}
    ok = True
    for t, key, field, off in (("config_restore_zia", "zia.url_filtering_rules", "state", "DISABLED"),
                               ("config_restore_zpa", "zpa.application_segments", "enabled", False)):
        p = ocr.build_plan(src, ocr.DocReader(tgt), ocr.check_spec({"type": t, "source": {"backup": "bk-" + "0" * 16}, "mode": "add_missing",
                                                                   "target": "other", "target_profile_id": "qa"}, t.rsplit("_", 1)[1]),
                           t.rsplit("_", 1)[1])
        made = [g["target"]["desired"] for g in p["groups"] if g["handler"] == "cfg_create" and g["target"]["type"] == key]
        ok = ok and bool(made) and all(m.get(field) == off for m in made)
    return ok and bool(cb.BY_KEY)


def _rules_csv_default():
    """A new ZIA rule from a file is planned DISABLED, even when the row says ENABLED."""
    from fake_rule_tenant import client
    _st, c = client()
    text = "name,state,action\r\nQA new rule,ENABLED,BLOCK_DROP\r\n"
    p = ao.plan(c, {"type": "zia_rules_csv", "policy": "firewall", "csv": text}, scope=ao.scope_for(["zia_extras"], {}))
    adds = [g["target"] for g in p["groups"] if g["handler"] == "rcsv_create"]
    return len(adds) == 1 and adds[0]["values"]["state"] == "DISABLED"


def _zpa_access_csv_default():
    """A new ZPA access rule (it cannot be created disabled) is left out unless the operator ticks 'create new rules enabled'."""
    from fake_rule_tenant import client
    _st, c = client()
    text = "name,action,segment_groups\r\nQA new access,ALLOW,Finance apps\r\n"
    p = ao.plan(c, {"type": "zpa_access_csv", "policy": "zpa_access", "csv": text}, scope=ao.scope_for(["zpa"], {}))
    return not p["groups"] and any(u["kind"] == "rule_add" and u["status"] == "excluded" for u in p["items"])


def _zid_user_default():
    import ops_zid
    n = ops_zid.normalize_users({"changes": [{"action": "create", "login_name": "qa@example.com", "display_name": "QA"}]})
    return n["changes"][0]["enable"] is False and ops_zid.user_create_payload(n["changes"][0])["status"] is False


def _zid_client_default():
    import ops_zid
    n = ops_zid.normalize_clients({"action": "create", "name": "QA", "scopes": [{"resource": "r", "scope": "s"}]})
    return n["enable"] is False and ops_zid.client_create_payload(dict(n, resources=[]))["status"] is False


# How each type that creates or changes enforcement keeps it off unless the
# operator chose it; or why "off" does not apply. A new type must be listed.
DEFAULT_OFF: Dict[str, Any] = {
    "zia_rules_csv": _rules_csv_default,
    "zpa_access_csv": _zpa_access_csv_default,
    "zcc_profile_build": _zcc_default,
    "zia_baseline": _baseline_default,
    "zpa_app_segments": _zpa_segments_default,
    "aiguard_detection_policy": _aiguard_policy_default,
    "aiguard_routing": "routing is the change asked for; its ENABLED rules need the typed phrase every time (test above)",
    "zpa_connector_group": "an App Connector group and its key route no traffic by themselves",
    "zpa_policies": "rules over segments created disabled decide nothing until a segment is enabled",
    "zdx_probes": "probes measure only; they never allow or block traffic",
    "ssl_certificate_move": "moves the intermediate certificate; asks its typed phrase every time (always=True)",
    "rule_state": "the operator picks ENABLED or DISABLED explicitly, per operation",
    "reorder": "changes order only; no rule is created or enabled",
    "url_categories": "custom URL category content; no rule is created or enabled",
    "zpa_domains": "domains only; a clone keeps its source segment's state so domains moved to it keep working (accepted)",
    "zdx_probe_state": "the operator picks on or off explicitly, per target",
    "zcc_profile_delete": "deletes profiles only; creates and enables nothing",
    "zdx_probe_delete": "deletes apps and probes (or turns them off) only",
    "zpa_prefix_delete": "deletes the prefixed objects only; creates and enables nothing",
    "rule_edit": _rule_edit_default,
    "zpa_segment_edit": "edits one existing segment; the operator picks enabled or not, and any change to an enabled segment needs the typed phrase",
    "app_object_edit": "cloud app instances and tenancy profiles decide nothing until a Cloud App Control rule uses them",
    "proxy_chain_edit": "a proxy forwards nothing until a gateway and a forwarding rule (created disabled) use it",
    "config_restore_zia": _config_restore_default,
    "config_restore_zpa": _config_restore_default,
    "config_restore_zcc": "Client Connector trusted networks, forwarding profiles and settings carry no on/off state; app profiles are never written",
    "zia_directory": "users, groups and departments: membership only, no policy rule is created or enabled; no password is set",
    "zia_pac": "a new version is created STAGED; a new PAC file has a new URL nothing uses yet; switching the active version is the change asked for",
    "zid_users": _zid_user_default,
    "zid_api_clients": _zid_client_default,
}


@pytest.mark.parametrize("t", ALL_TYPES)
def test_every_operation_type_creates_nothing_enforcing_unless_asked(monkeypatch, t):
    """ASVS V4.1.3 · V11.1.1 · CWE-1188 · CWE-276 · A05:2021: each operation type's defaults create nothing enabled or enforcing unless the operator chose it (checked), or the type is listed with why that does not apply."""
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)   # no pacing waits against the fake
    assert t in DEFAULT_OFF, f"{t}: say how its defaults stay off (DEFAULT_OFF)"
    rule = DEFAULT_OFF[t]
    if callable(rule):
        assert rule() is True, t
    else:
        assert len(rule) >= 20


# ---------------------------------------------------------------------------
# Partial failure: the result says exactly what was written
# ---------------------------------------------------------------------------

def test_a_run_that_fails_half_way_says_exactly_what_was_written_and_undoes_only_that(monkeypatch, tmp_path):
    """ASVS V11.1.1 · V7.1.3 · CWE-754 · CWE-460 · A04:2021: when the second of three writes fails, the first is reported applied, the second failed with its error, the third (which depends on it) not attempted; the record and the Undo carry only what was applied."""
    # Arrange
    t = "zpa_connector_group"
    scope = ao.scope_for(["zpa"], {})
    sent: List[str] = []

    def fake_plan(client, spec, scope, say, cancel):
        items = [ao._unit(k, f"g{k}", "qa", {"name": k, "id": k}, "exists", False, True, depends_on=dep)
                 for k, dep in (("a", []), ("b", []), ("c", ["b"]))]
        return {"type": t, "product": "zpa", "title": "QA", "spec": spec, "items": items,
                "groups": [{"key": f"g{k}", "handler": "qa_write", "target": {"k": k}} for k in "abc"]}

    def handler(run, g, units):
        k = g["target"]["k"]
        sent.append(k)
        run.outcome(units, ops.Outcome(ok=False, error="HTTP 400: refused") if k == "b" else ops.Outcome(ok=True, id=k), "create")
        if k != "b":
            run.created.append({"type": "qa", "id": k, "name": k})
    monkeypatch.setitem(ao.PLUGINS, t, dict(ao.PLUGINS[t], plan=fake_plan, verify=None,
                                            inverse=lambda r: {"type": t, "undo": [c["id"] for c in r["created"]]}))
    monkeypatch.setitem(ao.PLUGIN_HANDLERS, "qa_write", handler)
    client = SimpleNamespace(zia=None, zpa=None)
    p = ao.plan(client, {"type": t}, scope=scope)
    # Act
    r = ao.execute(client, {"type": t}, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR)
    rec = ao.record(r, by=ASSESSOR)
    # Assert
    st = {u["key"]: u["status"] for u in r["items"]}
    assert sent == ["a", "b"] and st == {"a": "applied", "b": "failed", "c": "skipped"}
    assert r["status"] == "partial" and r["summary"]["created"] == 1 and r["summary"]["failed"] == 1 and r["summary"]["skipped"] == 1
    assert next(u for u in r["items"] if u["key"] == "b")["error"] == "HTTP 400: refused"
    assert "depends on" in next(u for u in r["items"] if u["key"] == "c")["reason"]
    assert rec["inverse"] == {"type": t, "undo": ["a"]} and [u["key"] for u in rec["items"] if u["status"] == "applied"] == ["a"]


# ---------------------------------------------------------------------------
# The provisioning key through every sink (canary), on the job route
# ---------------------------------------------------------------------------

def test_the_provisioning_key_reaches_no_sink_on_the_job_route_and_is_shown_once(live, monkeypatch, tmp_path, caplog):
    """ASVS V8.3.4 · V7.1.1 · V8.2.2 · CWE-532 · CWE-312 · CWE-200 · A09:2021: a build run as a job: the key ZPA returns is in no start answer, job snapshot or log, operation record or list, Undo preview, audit log, store file or server log; it is revealed once, to the runner only."""
    # Arrange
    import logging
    import pack_jobs
    caplog.set_level(logging.DEBUG)
    real_start = pack_jobs.start

    def start_and_finish(*a, **k):
        job = real_start(*a, **k)
        job.thread.join(20)
        return job
    monkeypatch.setattr(pack_jobs, "start", start_and_finish)
    c = live.client(WRITER)
    p = live.preview(BUILD)
    # Act
    start = c.post("/api/operations/apply/start", json=live.body(operation=BUILD, plan_hash=p["plan_hash"], confirm=True))
    snap = c.get(f"/api/dlp-packs/jobs/{start.json()['job_id']}")
    result = snap.json()["result"]
    op_id = result["operation_id"]
    listing, record = c.get("/api/operations"), c.get(f"/api/operations/{op_id}")
    undo = c.post(f"/api/operations/{op_id}/undo/preview", json=live.body())
    token = result["one_time_secrets"][0]["token"]
    other = live.client(WRITER_2).post("/api/operations/zpa/provisioning-key", json={"token": token})
    shown = c.post("/api/operations/zpa/provisioning-key", json={"token": token})
    again = c.post("/api/operations/zpa/provisioning-key", json={"token": token})
    # Assert
    files = ""
    for root in {os.path.dirname(os.environ["DLP_CHECK_AUDIT"]), str(tmp_path)}:
        for dirpath, _dirs, names in os.walk(root):
            for n in names:
                with open(os.path.join(dirpath, n), "rb") as f:
                    files += f.read().decode("utf-8", "replace")
    sinks = {"start": start.text, "job": snap.text, "list": listing.text, "record": record.text, "undo preview": undo.text,
             "refused reveal": other.text, "files (audit log, stores)": files, "server log": caplog.text}
    leaked = [k for k, v in sinks.items() if CANARY_KEY in v or "CANARY-PROVISIONING" in v]
    assert leaked == [], leaked
    assert "audit.log" in os.listdir(os.path.dirname(os.environ["DLP_CHECK_AUDIT"])) and '"event":"admin_operation"' in files
    assert other.status_code == 404
    assert shown.status_code == 200 and shown.json()["provisioning_key"] == CANARY_KEY and shown.headers["cache-control"] == "no-store"
    assert again.status_code == 404


# ---------------------------------------------------------------------------
# Undo-only operations (they delete by id) are accepted only as a recorded Undo
# ---------------------------------------------------------------------------

def test_a_revert_cannot_delete_an_object_the_app_never_created(live):
    """ASVS V4.1.3 · V11.1.1 · CWE-840 · CWE-285 · A01:2021: a revert spec (the shape of an Undo, which deletes by id) sent as an ordinary operation, without undo_of, is refused: an Undo deletes only what a recorded operation of this app created."""
    # Arrange: the customer's own segment, never created by this app
    seg = live.zpa.tenant.add("segment", {"name": "Customer ERP", "domainNames": ["erp.example.com"], "enabled": True})
    spec = {"type": "zpa_domains", "action": "revert", "deltas": [],
            "delete_segments": [{"id": seg["id"], "name": "Customer ERP", "domains": ["erp.example.com"]}]}
    # Act
    r = live.apply(spec)
    # Assert
    assert r.status_code == 409, r.text[:300]
    assert live.zpa.tenant.by_name("segment", "Customer ERP") is not None and live.zpa.tenant.writes == []


UNDO_SHAPES = [
    {"type": "url_categories", "action": "revert", "deltas": [], "delete_categories": [{"id": 1, "name": "x", "urls": ["a.example.com"]}]},
    {"type": "zpa_domains", "action": "revert", "deltas": [], "delete_segments": [{"id": "1", "name": "x", "domains": ["a.example.com"]}]},
    {"type": "zia_baseline", "action": "revert", "steps": [{"op": "delete", "area": "firewall", "id": 1, "name": "x"}]},
    {"type": "aiguard_routing", "action": "undo", "steps": [{"kind": "firewall_rule", "op": "delete", "id": "1", "name": "AIG-x"}]},
    {"type": "aiguard_detection_policy", "action": "undo", "steps": [{"kind": "aiguard_rule", "op": "delete", "id": "1", "name": "AIG-x"}]},
    {"type": "zpa_prefix_delete", "prefix": "pov1", "undo": True, "select": [], "restore": []},
    {"type": "zia_directory", "action": "undo", "changes": [{"kind": "user", "action": "delete", "id": "41"}]},
    {"type": "zia_pac", "action": "undo", "delete": {"id": "61", "name": "corp.pac"}},
    {"type": "zid_users", "action": "undo", "changes": [{"action": "delete", "id": "u-1"}]},
    {"type": "zid_api_clients", "action": "undo", "delete": {"id": "c-1", "name": "Reporting"}},
]


@pytest.mark.parametrize("spec", UNDO_SHAPES, ids=[s["type"] for s in UNDO_SHAPES])
def test_every_undo_shape_is_refused_without_its_recorded_operation(world, spec):
    """ASVS V4.1.3 · V11.1.1 · CWE-840 · A01:2021: for every operation type with an Undo-only form, that form is applied only with undo_of naming the recorded operation, and is refused before sign-in otherwise."""
    world.write_mode(True)
    body = dict(_op_body(spec["type"]), operation=spec)
    r = world.client(gates.WRITER).post("/api/operations/apply", json=body)
    assert r.status_code == 409, r.text[:300]
    assert world.built == [] and world.touched() == []


def test_every_plugin_inverse_is_an_undo_shape_or_an_ordinary_guarded_type():
    """ASVS V1.4.1 · CWE-840: the forms an Undo uses are known: a new plugin whose inverse is a new undo-only form must be added to admin_ops.is_undo_only."""
    for s in UNDO_SHAPES:
        assert ao.is_undo_only(s), s
    for t in ALL_TYPES:
        assert not ao.is_undo_only({"type": t}), t


@pytest.mark.parametrize("own", [{"confirm_phrase": "  ", "confirm_always": "DELETE QA"}, {"confirm_phrase": None, "confirm_always": " delete qa "},
                                 {"confirm_phrase": "\t\n", "confirm_always": "DELETE QA"}])
def test_a_blank_own_phrase_never_hides_the_always_phrase(monkeypatch, own):
    """ASVS V11.1.1 · CWE-1289 · CWE-841: a plugin plan whose confirm_phrase is blank but whose confirm_always names a phrase asks for that phrase; a blank value never switches the typed confirmation off."""
    # Arrange
    t = "zpa_prefix_delete"

    def fake_plan(client, spec, scope, say, cancel):
        return dict({"type": t, "product": "zpa", "title": "QA", "spec": spec,
                     "items": [ao._unit("k", "g", "qa", {"name": "QA"}, "exists", True, False)],
                     "groups": [{"key": "g", "handler": "qa_tripwire", "target": {}}]}, **own)
    monkeypatch.setitem(ao.PLUGINS, t, dict(ao.PLUGINS[t], plan=fake_plan))
    monkeypatch.setitem(ao.PLUGIN_HANDLERS, "qa_tripwire", lambda run, g, units: pytest.fail("written without the typed phrase"))
    scope = ao.scope_for(["zpa"], {})
    client = SimpleNamespace(zia=None, zpa=None)
    p = ao.plan(client, {"type": t}, scope=scope)
    # Act
    out = ao.execute(client, {"type": t}, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR, confirm_text="")
    # Assert
    assert p["confirm_phrase"] == "DELETE QA" and out["status"] == "refused"


# ---------------------------------------------------------------------------
# Remediation recipes create rules disabled unless the operator picks enabled
# ---------------------------------------------------------------------------

import remediation  # noqa: E402

STATE_RECIPES = [r["check_id"] for r in remediation.REMEDIATIONS if any(f["key"] == "state" for f in r.get("fields") or [])]


@pytest.mark.parametrize("check_id", STATE_RECIPES)
def test_every_remediation_recipe_offers_its_rule_disabled_by_default(check_id):
    """ASVS V4.1.3 · V11.1.1 · CWE-1188 · CWE-276 · A05:2021: a recipe that creates a rule pre-selects DISABLED in its form, so an enforcing rule (a BLOCK_DROP firewall rule at order 1) is created only when the operator picks ENABLED."""
    field = next(f for f in remediation.get_recipe(check_id)["fields"] if f["key"] == "state")
    assert field["default"] == "DISABLED"


@pytest.mark.parametrize("check_id", STATE_RECIPES)
def test_a_remediation_without_a_state_gets_disabled_never_left_to_the_tenant(check_id):
    """ASVS V5.1.3 · V4.1.3 · CWE-1188 · CWE-20: a request that leaves the rule state out (a script) gets the secure default DISABLED; the state is never left for ZIA to choose, and an explicit ENABLED is honoured."""
    recipe = remediation.get_recipe(check_id)
    criteria = {f["key"]: (f.get("default") if f.get("default") not in (None, "") else ("1" if f.get("type") == "number" else "QA"))
                for f in recipe["fields"] if f["key"] != "state"}
    p = remediation.plan(check_id, criteria)
    assert p["ok"] and p["body"]["state"] == "DISABLED", p
    assert remediation.plan(check_id, dict(criteria, state="ENABLED"))["body"]["state"] == "ENABLED"
    assert remediation.plan(check_id, dict(criteria, state="DISABLED"))["body"]["state"] == "DISABLED"


# ---------------------------------------------------------------------------
# Rule migration: the live run writes only what its dry run showed
# ---------------------------------------------------------------------------

import rule_migrator as rm  # noqa: E402


class RawTenant:
    """The raw ZIA client of the migration wizard: Web DLP rules, and every write recorded."""

    def __init__(self, rules):
        self.rules = [dict(r) for r in rules]
        self.writes: List[tuple] = []

    def get(self, ep):
        if ep == "/zia/status":
            return {"status": "ACTIVE"}, 200
        return [dict(r) for r in self.rules], 200

    def delete(self, ep, body=None):
        self.writes.append(("DELETE", ep))
        return None, 204

    def put(self, ep, body=None):
        self.writes.append(("PUT", ep))
        return dict(body or {}), 200

    def post(self, ep, body=None):
        if ep != "/zia/status/activate":
            self.writes.append(("POST", ep))
        return {"id": 99}, 200


RULES = [{"id": 1, "name": "Block PCI", "order": 1, "state": "ENABLED", "action": "BLOCK"},
         {"id": 2, "name": "Monitor PII", "order": 2, "state": "ENABLED", "action": "ALLOW"}]


def test_delete_all_refuses_when_the_tenant_changed_since_its_dry_run(monkeypatch):
    """ASVS V11.1.1 · V1.11.3 · CWE-367 · CWE-841 · A04:2021: delete-all deletes only the rule set its dry run listed: a rule added since (someone else's) gives plan_changed and nothing is deleted."""
    # Arrange
    c = RawTenant(RULES)
    dry = rm.delete_all_rules(c, dry_run=True)
    c.rules.append({"id": 3, "name": "Created by a colleague", "order": 3, "state": "ENABLED", "action": "BLOCK"})
    monkeypatch.setattr(security, "_write_override", True)
    # Act
    out = rm.delete_all_rules(c, dry_run=False, plan_hash=dry["plan_hash"])
    # Assert
    assert out["status"] == "plan_changed" and c.writes == []


def test_delete_all_with_an_unchanged_tenant_deletes_what_the_dry_run_listed(monkeypatch):
    """ASVS V11.1.1 · CWE-841: positive control: the same rule set as the dry run is deleted."""
    c = RawTenant(RULES)
    dry = rm.delete_all_rules(c, dry_run=True)
    monkeypatch.setattr(security, "_write_override", True)
    out = rm.delete_all_rules(c, dry_run=False, plan_hash=dry["plan_hash"])
    assert out["status"] == "completed" and c.writes == [("DELETE", "/zia/webDlpRules/1"), ("DELETE", "/zia/webDlpRules/2")]


def test_posting_a_rule_order_refuses_when_a_rule_changed_since_its_dry_run(monkeypatch):
    """ASVS V11.1.1 · V1.11.3 · CWE-367 · CWE-841 · A04:2021: a live post (PUT of whole rules) after a rule was edited in the tenant since the dry run gives plan_changed: a colleague's change is never overwritten."""
    # Arrange
    c = RawTenant(RULES)
    proposed = [dict(RULES[1]), dict(RULES[0])]
    dry = rm.post_new_rule_order(c, proposed, dry_run=True, mode="update")
    c.rules[0]["action"] = "BLOCK_WITH_NOTIFICATION"
    monkeypatch.setattr(security, "_write_override", True)
    # Act
    out = rm.post_new_rule_order(c, proposed, dry_run=False, mode="update", plan_hash=dry["plan_hash"])
    # Assert
    assert out["status"] == "plan_changed" and c.writes == []
    same = RawTenant(RULES)
    ok = rm.post_new_rule_order(same, proposed, dry_run=False, mode="update",
                                plan_hash=rm.post_new_rule_order(same, proposed, dry_run=True, mode="update")["plan_hash"])
    assert ok["status"] == "completed" and same.writes == [("PUT", "/zia/webDlpRules/2"), ("PUT", "/zia/webDlpRules/1")]


@pytest.mark.parametrize("case_id", ["migrate-delete-all", "migrate-post"])
def test_a_live_migration_write_needs_the_dry_runs_plan_hash_before_sign_in(world, case_id):
    """ASVS V11.1.1 · CWE-841 · A04:2021: a live delete-all or post without the dry run's plan_hash is refused before the tenant is signed in to."""
    world.write_mode(True)
    url, body = [c for c in gates.WRITE_CASES if c[0] == case_id][0][3](world)
    body.pop("plan_hash", None)
    r = world.client(gates.WRITER).post(url, json=body)
    assert r.status_code == 400 and "plan_hash" in r.text, r.text[:300]
    assert world.built == [] and world.touched() == []


# ---------------------------------------------------------------------------
# Pack deploy: a whole-object update is re-read right before it is sent
# ---------------------------------------------------------------------------

def _tweak_world(tmp_path):
    import test_pack_deploy as tpd
    pack = tpd.write_pack(tmp_path, "tw", dicts=[tpd._dict("TD")],
                          meta={"confidence_tweaks": [{"name": "MEDICAL", "target_confidence": "CONFIDENCE_LEVEL_LOW", "label": "Medical → Low"}]})
    medical = tpd.Obj(id=3, name="MEDICAL", custom=False, confidence_threshold="CONFIDENCE_LEVEL_HIGH", dictionary_type="PATTERNS_AND_PHRASES",
                      custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", proximity=50, hierarchical_identifiers=["MED_TERMS"])
    return tpd, pack, tpd.FakeClient(dicts=[medical])


def test_a_dictionary_tweak_never_overwrites_a_change_made_during_the_run(tmp_path):
    """ASVS V11.1.1 · V1.11.3 · CWE-367 · CWE-362 · A04:2021: the confidence tweak PUTs the whole dictionary; when a colleague changed it after the re-plan (while the run was writing), it is re-read, found changed and left alone (skipped with the reason), never overwritten."""
    # Arrange
    import pack_deploy as pd
    tpd, pack, client = _tweak_world(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    dicts = client.zia.dlp_dictionary
    real_add = dicts.add_dict

    def add_while_a_colleague_edits(*a, **k):   # during phase 1, someone narrows MEDICAL's proximity in the portal
        i = next(n for n, d in enumerate(dicts.items) if d.name == "MEDICAL")
        dicts.items[i] = tpd.Obj(**dict(dicts.items[i].as_dict(), proximity=10))   # a new answer, as the API gives
        return real_add(*a, **k)
    dicts.add_dict = add_while_a_colleague_edits
    # Act
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)
    # Assert
    assert [u for u in dicts.updated if u["id"] == 3] == [], "the colleague's change was overwritten"
    tw = next(r for r in res["results"] if r.get("kind") == "tweak")
    assert tw["status"] == "skipped" and "changed in the tenant" in tw["reason"]
    assert next(d for d in dicts.items if d.name == "MEDICAL").proximity == 10


def test_a_dictionary_tweak_on_an_unchanged_dictionary_is_applied(tmp_path):
    """ASVS V11.1.1 · CWE-367: positive control: with nothing changed since the re-plan the tweak is applied as before."""
    import pack_deploy as pd
    tpd, pack, client = _tweak_world(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)
    assert res["summary"].get("modified") == 1 and client.zia.dlp_dictionary.updated[-1]["confidence_threshold"] == "CONFIDENCE_LEVEL_LOW"


# ---------------------------------------------------------------------------
# Audit log: every write attempt and every refusal, with its actor, no secret
# ---------------------------------------------------------------------------

AUDIT_CASES = [(c, g) for c in gates.WRITE_CASES for g in ("allowed", "write-mode-off", "confirm-missing")]


@pytest.mark.parametrize("case,gate", AUDIT_CASES, ids=[f"{c[0]}-{g}" for c, g in AUDIT_CASES])
def test_every_write_and_every_refusal_is_on_the_audit_log_with_its_actor_and_no_secret(world, case, gate):
    """ASVS V7.1.3 · V7.1.1 · V7.2.2 · CWE-778 · CWE-532 · A09:2021: each tenant-write route leaves an audit entry for the call, whether applied or refused: path, status, write mode and the signed-in actor; the client secret is never in the log."""
    # Arrange
    import audit
    _id, method, _route, arrange, _kind = case
    world.write_mode(gate != "write-mode-off")
    url, body = arrange(world)
    if gate == "confirm-missing":
        body.pop("confirm", None)
    # Act
    r = world.client(gates.WRITER).request(method, url, json=body)
    # Assert
    entries = [e for e in audit.tail(500) if e.get("event") == "api" and e.get("path") == url]
    assert entries, f"{url}: no audit entry"
    e = entries[-1]
    assert e["status"] == r.status_code and e["actor"] == gates.WRITER["email"] and e["write_mode"] is (gate != "write-mode-off")
    with open(audit.path(), encoding="utf-8") as f:
        assert "not-a-real-secret" not in f.read()


# ---------------------------------------------------------------------------
# Proposals: the stricter approval phrase, and a rollback that is TOCTOU-safe
# ---------------------------------------------------------------------------

def _promo(tmp_path, monkeypatch):
    import proposals as pr
    from test_proposals import REPORT, _store
    _store(tmp_path, monkeypatch)
    pr.refresh_from_report(REPORT, "acme")
    return pr, {p["kind"] + ":" + p["target"]: p for p in pr.list_queue("acme")}["promote_rule:rule:web:Old-Monitor"]


@pytest.mark.parametrize("typed", ["ı understand", "I UNDERſTAND", ""])
def test_a_stricter_proposal_is_not_approved_with_a_lookalike_phrase(tmp_path, monkeypatch, typed):
    """ASVS V11.1.1 · CWE-176 · CWE-841: approving a proposal that makes the tenant stricter needs the typed phrase under the same rule as every other: no Unicode look-alike."""
    pr, promo = _promo(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="I UNDERSTAND"):
        pr.decide("acme", promo["id"], "approve", by="jane", confirm=typed)
    assert pr.get("acme", promo["id"])["status"] == "open"
    assert pr.decide("acme", promo["id"], "approve", by="jane", confirm=" i understand ")["status"] == "approved"


def test_a_rollback_never_overwrites_a_value_someone_set_after_the_apply(tmp_path, monkeypatch):
    """ASVS V11.1.1 · V1.11.3 · CWE-367 · CWE-841 · A04:2021: a rollback puts the old value back only while the rule still holds the value the apply set; a colleague's later change (CONFIRM → BLOCK) is kept and the rollback is refused."""
    # Arrange
    import proposal_apply as pa
    from test_proposal_apply import _client
    pr, promo = _promo(tmp_path, monkeypatch)
    pr.decide("acme", promo["id"], "approve", by="jane", confirm="I UNDERSTAND")
    client = _client()
    assert pa.apply(client, "acme", promo["id"], writes_enabled=True, by="jane")["status"] == "applied"
    rule = client.zia.dlp_web_rules.items[0]
    rule.action = "BLOCK"                 # a colleague tightened it further after the apply
    sent = len(client.zia.dlp_web_rules.updated)
    # Act
    pv = pa.preview(client, "acme", promo["id"], direction="rollback")
    with pytest.raises(ValueError, match="refused"):
        pa.rollback(client, "acme", promo["id"], writes_enabled=True, by="jane")
    # Assert
    assert not pv["ok"] and "BLOCK" in pv["steps"][0]["why"]
    assert len(client.zia.dlp_web_rules.updated) == sent and client.zia.dlp_web_rules.items[0].action == "BLOCK"


# ---------------------------------------------------------------------------
# The raw client (remediation, rule migration): a POST is never resent blind
# ---------------------------------------------------------------------------

def _raw(answers):
    """A raw-HTTP client whose session answers from `answers` (an exception
    to raise or a status code), counting what is sent. No network."""
    import time as _time
    import requests
    import dlp_assessment_full_auto as full
    c = full.Client("cid-123456", "secret-secret", "acme.com", "zscaler")
    c.token, c.exp = "t", _time.time() + 3600
    sent: List[str] = []

    def request(method, url, **kw):
        sent.append(method)
        a = answers.pop(0)
        if isinstance(a, BaseException):
            raise a
        r = requests.Response()
        r.status_code, r._content = a, b'{"id": 7}'
        return r
    c.sess.request = request
    return c, sent


@pytest.mark.parametrize("first", ["read-timeout", "connection-reset", "502", "504"])
def test_the_raw_client_never_resends_a_post_that_may_have_been_applied(first):
    """ASVS V11.1.6 · CWE-694 · CWE-837 · A04:2021: a POST (a create: remediation, the migration wizard) answered by a read timeout, a reset connection or a 502/504 may have been applied, so it is not sent again; the answer says so."""
    import requests
    a = {"read-timeout": requests.exceptions.ReadTimeout("read timed out"),
         "connection-reset": requests.exceptions.ConnectionError("Connection aborted: connection reset by peer"),
         "502": 502, "504": 504}[first]
    c, sent = _raw([a, 201])
    data, code = c.post("/zia/firewallFilteringRules", {"name": "QA"})
    assert sent == ["POST"], sent
    assert code != 201 and "not sent again" in str(data.get("error"))


def test_the_raw_client_still_retries_what_cannot_have_been_applied():
    """ASVS V11.1.6 · CWE-694: positive control: a POST whose connection was never made (connect timeout) and a PUT after a read timeout (idempotent) are retried as before."""
    import requests
    c, sent = _raw([requests.exceptions.ConnectTimeout("connect timed out"), 201])
    assert c.post("/zia/firewallFilteringRules", {"name": "QA"})[1] == 201 and sent == ["POST", "POST"]
    c, sent = _raw([requests.exceptions.ReadTimeout("read timed out"), 200])
    assert c.put("/zia/webDlpRules/7", {"name": "QA"})[1] == 200 and sent == ["PUT", "PUT"]
