"""The day-to-day admin routes: the Browser Access certificate upload, the
read-only lookups, the bounded deep trace follow, and the whole flow of a
certificate rotation and a deep trace through the app's own gates (preview,
plan hash, apply as a job, record, Undo). Fakes only: no tenant, no network."""
from __future__ import annotations

import json
import logging
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dlp_api_server as srv  # noqa: E402
import ops_zdx_trace as zt  # noqa: E402
import ops_zpa_admin as za  # noqa: E402
import pack_jobs  # noqa: E402
import security  # noqa: E402
import zpa_reader  # noqa: E402
from admin_fakes import ZdxClient, ZpaClient  # noqa: E402
from test_ops_admin_zpa import key_lines, make_cert  # noqa: E402

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "7210000000000"}


def scope(*s):
    return {"scopes": list(s), "channels": {}, "from_page": True}


@pytest.fixture()
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(za, "_CERTS", {})
    monkeypatch.setattr(zt, "_STARTS", {})
    real_start = pack_jobs.start

    def start_and_finish(*a, **k):
        job = real_start(*a, **k)
        job.thread.join(20)
        return job
    monkeypatch.setattr(pack_jobs, "start", start_and_finish)
    return TestClient(srv.app)


def test_the_upload_needs_write_mode_and_never_answers_the_key(api, monkeypatch):
    """ASVS V8.3.4 · V4.1.3 · CWE-200 · CWE-525: refused (403) while write mode is off; on, it answers a token and facts with no-store, never the key."""
    pem, kp = make_cert()
    monkeypatch.setattr(security, "_write_override", False)
    r = api.post("/api/operations/zpa/ba-certificate", json={"cert_pem": pem, "private_key": kp})
    assert r.status_code == 403 and za._CERTS == {}
    monkeypatch.setattr(security, "_write_override", True)
    r = api.post("/api/operations/zpa/ba-certificate", json={"cert_pem": pem, "private_key": kp})
    assert r.status_code == 200 and "no-store" in r.headers["cache-control"] and r.json()["token"]
    assert all(ln not in r.text for ln in key_lines(kp)) and "PRIVATE" not in r.text


@pytest.mark.parametrize("body", [{"cert_pem": "x", "private_key": "y"}, {"cert_pem": ["a"], "private_key": "b"}, {"cert_pem": "A" * 70000, "private_key": "b"}])
def test_a_bad_upload_is_refused_without_echoing_it(api, monkeypatch, body):
    """ASVS V5.1.3 · V7.4.1 · CWE-209 · CWE-20: a malformed, mistyped or oversized upload is refused and the answer never repeats it."""
    monkeypatch.setattr(security, "_write_override", True)
    r = api.post("/api/operations/zpa/ba-certificate", json=body)
    assert r.status_code in (400, 422) and "AAAAAAAAAA" not in r.text and za._CERTS == {}


def test_an_unknown_lookup_is_refused_before_sign_in(api, monkeypatch):
    """ASVS V4.1.3 · CWE-285: a family that has no lookup is a 400 before any client is built."""
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1))
    r = api.post("/api/operations/lookup", json=dict(CREDS, **scope("zpa", "zcc", "zdx"), family="zpa_objects", what="devices"))
    assert r.status_code == 400 and built == []


def test_an_undo_form_cannot_be_applied_as_an_ordinary_change(api, monkeypatch):
    """ASVS V4.1.3 · CWE-639 · CWE-284: a delete in the Undo's form, naming objects by id, is refused (409) unless it is that recorded Undo."""
    monkeypatch.setattr(security, "_write_override", True)
    op = {"type": "zpa_infra_delete", "undo": True, "targets": [{"kind": "provisioning_key", "id": "1", "name": "k", "key_type": "connector"}]}
    r = api.post("/api/operations/apply", json=dict(CREDS, **scope("zpa"), operation=op, plan_hash="0" * 64, confirm=True, assessor="Jane"))
    assert r.status_code == 409


def test_a_certificate_rotation_through_the_routes_and_its_undo(api, monkeypatch, tmp_path, caplog):
    """ASVS V8.3.4 · V7.1.1 · V1.4.1 · CWE-532 · CWE-841: upload, preview, apply as a job, record, Undo; the key is in no answer, job log,
    record or audit entry (the audit log's request record included)."""
    caplog.set_level(logging.DEBUG)
    c = ZpaClient()
    s = c.tenant.seed()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: c)
    monkeypatch.setattr(security, "_write_override", True)
    pem, kp = make_cert(("wiki.example.com",))
    up = api.post("/api/operations/zpa/ba-certificate", json={"cert_pem": pem, "private_key": kp}).json()
    op = {"type": "zpa_ba_certificate", "upload_token": up["token"], "name": "wiki-2027", "assign": [{"segment_id": s["seg"]["id"], "app_id": "6001"}]}
    prev = api.post("/api/operations/preview", json=dict(CREDS, **scope("zpa"), operation=op))
    assert prev.status_code == 200 and prev.json()["status"] == "ready", prev.text
    started = api.post("/api/operations/apply/start", json=dict(CREDS, **scope("zpa"), operation=op, plan_hash=prev.json()["plan_hash"],
                                                                confirm=True, assessor="Jane Doe"))
    snap = api.get(f"/api/dlp-packs/jobs/{started.json()['job_id']}")
    res = snap.json()["result"]
    assert res["status"] == "applied" and res["operation_id"]
    undo = api.post(f"/api/operations/{res['operation_id']}/undo/preview", json=dict(CREDS, **scope("zpa")))
    assert undo.status_code == 200 and undo.json()["status"] == "ready"
    done = api.post("/api/operations/apply", json=dict(CREDS, **scope("zpa"), operation=undo.json()["operation"], plan_hash=undo.json()["plan_hash"],
                                                       confirm=True, assessor="Jane Doe", undo_of=res["operation_id"]))
    assert done.status_code == 200 and done.json()["status"] == "applied"
    history = api.get("/api/operations").text + api.get(f"/api/operations/{res['operation_id']}").text
    files = "".join((tmp_path / f).read_text(encoding="utf-8") for f in os.listdir(tmp_path) if (tmp_path / f).is_file())
    parts = {"prev": prev.text, "snap": snap.text, "undo": undo.text, "done": done.text, "history": history, "files": files, "log": caplog.text}
    leaks = {k: [ln for ln in key_lines(kp) if ln in v][:1] + (["PRIVATE KEY"] if "PRIVATE KEY" in v else []) for k, v in parts.items()}
    assert not {k: v for k, v in leaks.items() if v}, sorted(k for k, v in leaks.items() if v)


def test_a_deep_trace_lookup_and_a_bounded_follow_through_the_routes(api, monkeypatch):
    """ASVS V13.4.1 · CWE-400 · CWE-835: the lookup answers devices; the follow job ends within MAX_POLLS reads of a trace that never ends."""
    c = ZdxClient()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: c)
    monkeypatch.setattr(zt, "DEFAULT_INTERVAL", 0.0)
    monkeypatch.setattr(zt, "MIN_INTERVAL", 0.0)
    c.tenant.traces["132559212"]["77"] = {"trace_id": "77", "status": "in_progress"}
    r = api.post("/api/operations/lookup", json=dict(CREDS, **scope("zdx"), family="zdx_trace", what="devices", user="jdoe@acme.com"))
    assert r.status_code == 200 and r.json()["devices"][0]["id"] == "132559212"
    f = api.post("/api/operations/zdx/deeptrace/follow/start", json=dict(CREDS, **scope("zdx"), device_id="132559212", trace_id="77"))
    snap = api.get(f"/api/dlp-packs/jobs/{f.json()['job_id']}").json()
    assert snap["result"]["timed_out"] is True and snap["result"]["polls"] == zt.MAX_POLLS
    assert c.tenant.reads.count("trace") == zt.MAX_POLLS and c.tenant.writes == []
    bad = api.post("/api/operations/zdx/deeptrace/follow/start", json=dict(CREDS, **scope("zdx"), device_id="../1", trace_id="77"))
    assert bad.status_code == 400


def test_a_list_is_matched_through_the_lookup_route(api, monkeypatch):
    """ASVS V5.1.3 · CWE-20: the page's pasted list reaches the matcher; an oversized list is refused (400) before the devices are read."""
    from admin_fakes import ZccClient
    c = ZccClient()
    c.tenant.seed()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: c)
    r = api.post("/api/operations/lookup", json=dict(CREDS, **scope("zcc"), family="zcc_admin", what="match", text="jdoe@acme.com\nNOPE-PC", mode="remove"))
    assert r.status_code == 200 and r.json()["counts"]["planned"] == 1 and r.json()["not_found"] == [{"entry": "NOPE-PC"}]
    big = api.post("/api/operations/lookup", json=dict(CREDS, **scope("zcc"), family="zcc_admin", what="match", text="a\n" * 600000))
    assert big.status_code in (400, 413)
