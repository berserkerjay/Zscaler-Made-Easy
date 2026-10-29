"""Cloud QA wave 6, scope-offline: snapshots and the sample tenant
(offline_tenant.py, sample_tenant.py), readiness (readiness.py), the scope
and permission maps (permissions.py, scope_permissions.py) and the Scope
page's channel logic (channel_scope.py, beacon_scope.py).

Every test uses fakes or the made-up sample tenant: no network, no real
clock (time is injected), no randomness that a result depends on, no file
outside tmp_path. Each docstring's first line names the controls it checks
(OWASP ASVS 4.0.3 L2, OWASP Top 10 2021, CWE, OWASP WSTG, WCAG 2.2, SSDF).
Zscaler API details are checked against the installed SDK (zscaler 1.11.3)."""
from __future__ import annotations

import copy
import importlib
import json
import os
import re
import socket
import sys
import types
from typing import Any, Dict, List

import pytest

import beacon_scope as bs
import channel_scope as cs
import offline_tenant as ot
import permissions
import readiness as rd
import sample_tenant
import scope_permissions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = 1_800_000_000.0   # injected clock (2027-01-15)
ZCC = "/zcc/papi/public/v1"
ZPA1 = "/zpa/mgmtconfig/v1/admin/customers/{customerId}"
SDK = os.path.dirname(importlib.import_module("zscaler").__file__)


@pytest.fixture(autouse=True)
def _isolated_offline_state(monkeypatch):
    """Arrange for every test: a private table of open offline tenants (the
    module keeps one per server), and no socket can be opened."""
    from collections import OrderedDict
    monkeypatch.setattr(ot, "_OPEN", OrderedDict())

    def _no_network(*a, **k):
        raise AssertionError("a test opened a network connection")
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)


def _snapshot_store(responses: Dict[str, Any], sid: str = "snap-00000000000000c6") -> ot.OfflineStore:
    st = ot.OfflineStore(sid, "snapshot", {p: {"status": 200, "body": b} for p, b in responses.items()}, {"tenant_label": "Acme"})
    return ot.register(st)


def _doc(responses: Dict[str, Any], meta: Any = None) -> str:
    return ot.dumps(ot.build_snapshot({p: {"status": 200, "body": b} for p, b in responses.items()}, meta or {"tenant_label": "Acme"}))


# ── Snapshots: secret fields are never kept ──────────────────────────────

# camelCase secret fields of the SDK models (zscaler/zcc/models/secrets_otp.py,
# zcc/models/devices.py, zia/models/cloud_to_cloud_ir.py, zid/models/api_client.py,
# aiguard/models/llm_provider_credentials.py, ztb/models/app_connector_config.py,
# zpa/models/enrollment_certificates.py).
SDK_SECRET_FIELDS = ["deviceOtpArray", "exitOtp", "logoutOtp", "uninstallOtp", "revertOtp", "zpaDisableOtp", "ziaDisableOtp",
                     "zdxDisableOtp", "zdpDisableOtp", "deceptionSettingsOtp", "antiTemperingDisableOtp", "credJson", "tempAuthCode",
                     "keyValue", "apiCredentials", "provisionKey", "zrsaencryptedsessionkey"]


@pytest.mark.parametrize("field", SDK_SECRET_FIELDS)
def test_a_snapshot_never_keeps_an_otp_or_stored_credential(field):
    """ASVS V8.3.4 · ASVS V6.1.1 · CWE-312 · CWE-200 · A02:2021 · WSTG-CRYP-03: a Client Connector OTP or a stored credential under an SDK field name is saved only as set / not set."""
    secret = "CANARY-otp-4711-q8w7e6"
    body = [{"udid": "LKF-1", "machineHostname": "LT-1", field: [secret] if field.endswith("Array") else secret}]

    text = _doc({f"{ZCC}/getDevices": body})

    assert secret not in text
    assert json.loads(text)["responses"][f"{ZCC}/getDevices"]["body"][0][field] == "(set)"


def test_an_otp_switch_that_is_not_an_otp_keeps_its_value():
    """ASVS V8.3.4 · CWE-200 · CWE-1287: a boolean switch whose name only mentions OTP (enableSeparateOtpForDevice) is kept, so masking stays precise."""
    body = {"enableSeparateOtpForDevice": True, "antiTamperingOtpSupportVisibility": 1, "sendDefaultPolicyForInvalidPolicyToken": False}

    out = ot.scrub(body)

    assert out == body


def test_compare_never_shows_a_live_secret_of_an_object_with_no_id_or_name():
    """ASVS V8.3.4 · CWE-200 · CWE-532 · A04:2021: the live answer is not scrubbed when read, so an unnamed object's own JSON (its key and its name in the comparison) must be scrubbed first."""
    secret = "CANARY-psk-live-55aa"
    old = {"/zia/api/v1/vpnCredentials": {"status": 200, "body": []}}
    new = {"/zia/api/v1/vpnCredentials": {"status": 200, "body": [{"type": "UFQDN", "preSharedKey": secret}]}}

    diff = ot.compare(old, new)

    assert diff["totals"]["added"] == 1
    assert secret not in json.dumps(diff)


def test_every_compare_row_has_the_same_shape():
    """ASVS V13.1.1 · CWE-1287: a settings object that changed is reported with counts, like a list row, so every consumer reads one shape."""
    old = {"/zia/api/v1/advancedSettings": {"status": 200, "body": {"logInternalIp": True}}}
    new = {"/zia/api/v1/advancedSettings": {"status": 200, "body": {"logInternalIp": False}}}

    rows = ot.compare(old, new)["lists"]

    assert rows and rows[0]["counts"] == {"added": 0, "removed": 0, "changed": 1}


def test_a_snapshot_keeps_the_channel_declaration_it_was_saved_with():
    """ASVS V7.1.1 · CWE-1287 · CWE-20: the declaration the save sends (channel_scope.normalize, {choice, note, name}) is recorded as the choices, notes and names dropped."""
    declared = cs.normalize({"web_dlp": "zscaler", "email_dlp": {"choice": "alternative", "note": "<b>other vendor</b>"}})

    meta = json.loads(_doc({"/zia/api/v1/webDlpRules": []}, {"tenant_label": "Acme", "channels": declared}))["meta"]

    assert meta["channels"] == {"web_dlp": "zscaler", "email_dlp": "alternative"}


def test_an_opened_snapshot_can_never_take_the_sample_tenants_id():
    """ASVS V4.1.3 · CWE-706 · CWE-20: a snapshot opened with the id "sample" gets a fresh id, so it can never replace the sample tenant."""
    sample = ot.sample_store()

    st = ot.open_document(_doc({"/zia/api/v1/webDlpRules": []}), ot.SAMPLE)

    assert st.id.startswith("file-") and ot.sample_store() is sample and ot.sample_store().kind == ot.SAMPLE


# ── Snapshots: untrusted files ───────────────────────────────────────────

@pytest.mark.parametrize("raw,why", [
    (b"\xff\xfe{}", "UTF-8"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "meta": {}, "responses": {"/zia/a": {"status": 200, "body": NaN}}}', "valid JSON"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 2, "meta": {}, "responses": {}}', "version"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "meta": {}, "responses": {}}', "no tenant answers"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "responses": {"/zia/a": {"status": 404, "body": 1}}}', "unexpected status"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "responses": {"/zia/a": {"status": true, "body": 1}}}', "unexpected status"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "responses": {"/zia/a": {"body": 1}}}', "not in the snapshot format"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "responses": {"/zia/a": [1]}}', "not in the snapshot format"),
    ('{"format": "zscaler-made-easy-snapshot", "version": 1, "responses": []}', "no tenant answers"),
    ('[]', "not a Zscaler Made Easy snapshot"),
])
def test_a_malformed_snapshot_is_refused_in_words(raw, why):
    """ASVS V5.1.3 · ASVS V7.4.1 · CWE-20 · CWE-209 · WSTG-INPV-13: a malformed file is refused with a plain reason (no traceback), boundary statuses and types included."""
    with pytest.raises(ot.SnapshotInvalid) as e:
        ot.parse_snapshot(raw)

    assert why in str(e.value) and e.value.status == 400 and "Traceback" not in str(e.value)


def test_a_snapshot_that_is_not_text_or_bytes_is_refused():
    """ASVS V5.1.3 · CWE-20: anything but text or bytes is refused before parsing."""
    with pytest.raises(ot.SnapshotInvalid, match="not a file"):
        ot.parse_snapshot({"format": ot.FORMAT})


def test_a_snapshot_with_too_many_answers_is_refused(monkeypatch):
    """ASVS V12.1.1 · CWE-770 · CWE-400: more API answers than the cap is refused; the cap itself is accepted."""
    monkeypatch.setattr(ot, "MAX_PATHS", 2)
    ok = _doc({"/zia/api/v1/a": [], "/zia/api/v1/b": []})
    too_many = _doc({"/zia/api/v1/a": [], "/zia/api/v1/b": [], "/zia/api/v1/c": []})

    responses, _ = ot.parse_snapshot(ok)

    assert len(responses) == 2
    with pytest.raises(ot.SnapshotInvalid, match="more than 2 answers"):
        ot.parse_snapshot(too_many)


@pytest.mark.parametrize("path", ["/zia/api/v1/../../etc/passwd", "/zia//x", "/zia/x?y=1", "zia/x", "/other/x", "/zia/" + "a" * 301,
                                  "/zia/x\u2028", "/zia/x\\y", "/zia/%2e%2e/x", "C:\\zia\\x"])
def test_a_snapshot_answer_under_any_non_api_path_is_refused(path):
    """ASVS V12.3.1 · CWE-22 · CWE-20 · WSTG-ATHZ-01: traversal, doubled slashes, queries, encodings and other services are not API paths; the file is refused."""
    raw = json.dumps({"format": ot.FORMAT, "version": 1, "responses": {path: {"status": 200, "body": []}}})

    with pytest.raises(ot.SnapshotInvalid, match="not a Zscaler API path"):
        ot.parse_snapshot(raw)


def test_hostile_meta_text_is_cleaned_and_unknown_scopes_dropped():
    """ASVS V5.1.3 · ASVS V5.3.1 · CWE-117 · CWE-74: control characters are removed, text is bounded, and only known scopes and counts are kept."""
    meta = {"tenant_label": "Acme\x00\x1b[31m\nInc" + "x" * 500, "scopes": ["dlp", "../x", 5, "zpa"], "counts": {"answers": 3, "BAD": 1, "objects": -1, "x": True},
            "unread": ["a\nb"] * 300, "auth_method": "evil"}

    out = ot._clean_meta(meta)

    assert "\x00" not in out["tenant_label"] and "\n" not in out["tenant_label"] and len(out["tenant_label"]) <= 200
    assert out["scopes"] == ["dlp", "zpa"] and out["counts"] == {"answers": 3} and len(out["unread"]) == 200
    assert out["auth_method"] == "oneapi"


def test_an_opened_snapshot_is_labelled_once():
    """ASVS V7.1.1 · CWE-451: an opened snapshot is named "Snapshot of ..." exactly once, and one with no label is still named."""
    a = ot.open_document(_doc({"/zia/api/v1/x": []}, {"tenant_label": "Snapshot of Acme"}))
    b = ot.open_document(_doc({"/zia/api/v1/x": []}, {"profile_name": "p"}))

    assert a.label == "Snapshot of Acme" and b.label == "Snapshot of Offline snapshot"


def test_the_open_snapshots_held_in_memory_are_bounded_and_the_sample_kept(monkeypatch):
    """ASVS V11.1.4 · CWE-770 · CWE-400: at most MAX_OPEN snapshots stay in memory (the oldest goes); the sample is never evicted."""
    monkeypatch.setattr(ot, "MAX_OPEN", 2)
    ot.sample_store()
    ids = [ot.open_document(_doc({"/zia/api/v1/x": []})).id for _ in range(3)]

    assert set(ot._OPEN) == {ot.SAMPLE, ids[1], ids[2]}
    ot.forget(ot.SAMPLE)
    assert ot.SAMPLE in ot._OPEN


# ── Offline clients: answers, writes, no network ─────────────────────────

def test_a_write_on_a_snapshot_is_refused_and_changes_nothing():
    """ASVS V4.1.1 · CWE-284 · CWE-841 · WSTG-ATHZ-02: POST, PUT, PATCH and DELETE on an opened snapshot answer 403 READ_ONLY; the answer table is unchanged."""
    st = _snapshot_store({"/zia/api/v1/webDlpRules": [{"id": 1, "name": "r"}]})
    before = copy.deepcopy(st.responses)

    answers = [st.answer_write(m, "/zia/api/v1/webDlpRules" + ("/1" if m != "POST" else ""), {"name": "x"})
               for m in ("POST", "PUT", "PATCH", "DELETE")]

    assert all(s == 403 and b["code"] == "READ_ONLY" for s, b in answers)
    assert st.responses == before and st.writes == 0


def test_a_sample_write_never_aliases_the_callers_payload():
    """ASVS V1.4.1 · CWE-374 · CWE-668: the sample keeps its own copy of a posted or updated object; changing the caller's payload later changes nothing in the tenant."""
    st = ot.sample_store(reset=True)
    payload = {"name": "New rule", "dlpEngines": [{"id": 60}]}

    status, created = st.answer_write("POST", "/zia/api/v1/webDlpRules", payload)
    payload["dlpEngines"].append({"id": 999})
    update = {"protocols": ["ANY_RULE"]}
    st.answer_write("PUT", f"/zia/api/v1/webDlpRules/{created['id']}", update)
    update["protocols"].append("FTP_RULE")

    _, stored = st.answer_get(f"/zia/api/v1/webDlpRules/{created['id']}")
    assert status == 200 and stored["dlpEngines"] == [{"id": 60}] and stored["protocols"] == ["ANY_RULE"]


def test_a_sample_put_keeps_the_objects_own_id_and_delete_removes_it():
    """ASVS V4.2.1 · CWE-639 · CWE-915: an update cannot change an object's id; a delete removes only that object; an unknown id is not modelled."""
    st = ot.sample_store(reset=True)

    st.answer_write("PUT", "/zia/api/v1/webDlpRules/101", {"id": 4242, "name": "renamed"})
    _, renamed = st.answer_get("/zia/api/v1/webDlpRules/101")
    deleted, _ = st.answer_write("DELETE", "/zia/api/v1/webDlpRules/102")
    missing, body = st.answer_write("DELETE", "/zia/api/v1/webDlpRules/424242")

    assert renamed["id"] == 101 and renamed["name"] == "renamed"
    assert deleted == 204 and st.answer_get("/zia/api/v1/webDlpRules/102")[0] == 404
    assert missing == 400 and body["code"] == "NOT_MODELLED"


def test_a_sample_zpa_post_gets_a_text_id_like_the_zpa_api():
    """ASVS V5.1.3 · CWE-1287: ZPA ids are strings in the ZPA API, ZIA ids numbers; a new sample object follows its product."""
    st = ot.sample_store(reset=True)

    _, zpa = st.answer_write("POST", "/zpa/mgmtconfig/v1/admin/customers/72000000000000001/segmentGroup", {"name": "g"})
    _, zia = st.answer_write("POST", "/zia/api/v1/ruleLabels", {"name": "l"})

    assert isinstance(zpa["id"], str) and isinstance(zia["id"], int)


@pytest.mark.parametrize("params,expected", [({"page": 2}, []), ({"pageNumber": "3"}, []), ({"page": "x"}, None), ({"page": 0}, None),
                                             ({"page": "9" * 5000}, None)])
def test_offline_pagination_is_bounded_and_never_raises(params, expected):
    """ASVS V5.1.3 · CWE-20 · CWE-400 · CWE-755: a later page is empty, an unreadable or huge page number reads as the first page; nothing raises."""
    st = ot.sample_store(reset=True)

    status, body = st.answer_get("/zia/api/v1/webDlpRules", params)

    assert status == 200 and (body == expected if expected is not None else len(body) == len(sample_tenant.WEB_DLP_RULES))


def test_the_platform_filter_reads_the_apis_device_type_field():
    """ASVS V5.1.3 · CWE-1287: app profiles carry device_type (zscaler/zcc/models/webpolicy.py); a deviceType query returns only that platform's profiles."""
    st = _snapshot_store({f"{ZCC}/application-profiles": [{"id": 1, "device_type": 3}, {"id": 2, "device_type": 4}]})

    _, windows = st.answer_get(f"{ZCC}/application-profiles", {"deviceType": 3})

    assert [p["id"] for p in windows] == [1]


def test_the_raw_offline_client_answers_reads_and_refuses_writes_without_a_socket():
    """ASVS V1.14.1 · CWE-653 · CWE-441 · WSTG-INPV-19: OfflineRawClient resolves short endpoints from the table, refuses a snapshot write in words and opens no socket."""
    st = _snapshot_store({"/zia/api/v1/webDlpRules": [{"id": 1}]})
    cl = ot.OfflineRawClient(st, ot.creds_for(st))

    rules, code = cl.get("/zia/webDlpRules")
    missing, miss_code = cl.get("/zia/urlFilteringRules")
    refused, w_code = cl.post("/zia/webDlpRules", {"name": "x"})
    text, t_code = cl.get_text("/zia/webDlpRules", max_bytes=4)

    assert (code, rules) == (200, [{"id": 1}]) and miss_code == 404 and "Not in this snapshot" in missing["message"]
    assert w_code == 403 and refused["code"] == "READ_ONLY" and (t_code, text) == (200, '[{"i')


def test_a_stopped_raw_offline_client_reads_nothing_more():
    """ASVS V11.1.7 · CWE-400: Stop (or a stop check that raises) is honoured on the next read; a raising check never crashes the read."""
    st = _snapshot_store({"/zia/api/v1/webDlpRules": []})
    cl = ot.OfflineRawClient(st, ot.creds_for(st))
    cl.stop_check = lambda: (_ for _ in ()).throw(RuntimeError("x"))
    _, before = cl.get("/zia/webDlpRules")

    cl.stop()
    body, code = cl.get("/zia/webDlpRules")

    assert before == 200 and code != 200 and cl.auth() is True and cl.close() is None


def test_the_sdk_offline_client_refuses_a_snapshot_write_as_an_sdk_error():
    """ASVS V4.1.1 · CWE-284 · CWE-841: an SDK add on a snapshot returns (None, response, error) with HTTP 403; nothing is sent and nothing changes."""
    st = _snapshot_store({"/zia/api/v1/ruleLabels": [{"id": 1, "name": "a"}]})
    client = ot.OfflineSdkClient(st, ot.creds_for(st))

    result, _resp, err = client.zia.rule_labels.add_label(name="b")

    assert result is None and getattr(err, "status", None) == 403 and len(st.responses["/zia/api/v1/ruleLabels"]["body"]) == 1


def test_every_sdk_service_of_the_offline_client_builds_without_a_network():
    """ASVS V1.14.1 · CWE-653: every product the SDK client offers is built over the in-memory executor; sign-in and sign-out do nothing."""
    st = ot.sample_store(reset=True)

    with ot.OfflineSdkClient(st, ot.creds_for(st)) as client:
        services = [client.zia, client.zpa, client.zcc, client.zdx, client.zid, client.zidentity, client.zins, client.zwa, client.ztw]

    assert all(s is not None for s in services) and client.authenticate() is None and client.deauthenticate() is None
    assert client.zia is services[0]   # built once


def test_the_executor_routes_every_service_and_keeps_its_headers():
    """ASVS V1.14.1 · CWE-653: the in-memory executor names each service from the URL like the SDK's, and its header and session hooks do nothing on the network."""
    ex = ot.OfflineExecutor(ot.sample_store(reset=True))

    kinds = [ex.get_service_type(u) for u in ("/ziam/admin/api/v1/users", "/zia/api/v1/x", "/ztw/api/v1/x", "/zcc/x", "/zdx/v1/x", "/zwa/x", "/zpa/x",
                                              "/mgmtconfig/v1/x", "/zins/x", "/other")]
    ex.set_custom_headers({"X-A": "1"})
    got = ex.get_custom_headers()
    ex.clear_custom_headers()

    assert kinds == ["ziam", "zia", "ztw", "zcc", "zdx", "zwa", "zpa", "zpa", "zins", "zia"]
    assert got == {"X-A": "1"} and ex.get_custom_headers() == {} and ex.get_default_headers() == {}
    assert ex.set_session(object()) is None and ex.deauthenticate() is None and ex.has_mutations_occurred() is False


def test_offline_credentials_name_a_domain_that_never_resolves_and_carry_no_secret():
    """ASVS V2.10.4 · ASVS V14.3.3 · CWE-798 · CWE-918: offline credentials point at .offline.invalid (RFC 6761) and hold only a fixed non-secret marker."""
    st = ot.sample_store()

    creds = ot.creds_for(st)

    assert creds["vanity_domain"].endswith(".offline.invalid") and creds["client_secret"] == ot.OFFLINE_SECRET
    assert ot.is_offline_creds(creds) and not ot.is_offline_creds({"client_id": "offline-x", "vanity_domain": "acme"})
    assert not ot.is_offline_creds("offline-sample") and ot.store_for_creds({"client_id": "abc"}) is None


def test_offline_credentials_for_a_closed_snapshot_fail_closed():
    """ASVS V1.4.1 · CWE-636 · CWE-441: credentials naming a snapshot that is no longer open raise a 409 in words, never fall back to a live tenant."""
    creds = {"client_id": "offline-file-00000000000000aa", "vanity_domain": "x.offline.invalid"}

    with pytest.raises(ot.OfflineError) as e:
        ot.client_for(creds, "raw")

    assert e.value.status == 409 and "no longer open" in str(e.value)


def test_the_request_context_names_the_offline_tenant_only_inside_using():
    """ASVS V1.4.1 · CWE-488 · CWE-668: the offline tenant is per request (a context variable) and is cleared after it."""
    ot.sample_store()

    with ot.using(ot.SAMPLE):
        inside = (ot.current_source(), ot.status()["mode"], ot.current_creds()["client_id"])
    outside = (ot.current_source(), ot.status(), ot.current_creds())

    assert inside == (ot.SAMPLE, ot.SAMPLE, "offline-sample") and outside == (None, {"mode": "live"}, None)


def test_status_says_gone_when_the_snapshot_was_closed():
    """ASVS V7.4.1 · CWE-636: a request naming a closed snapshot is told it is gone (and current_creds refuses), never served the live tenant."""
    with ot.using("file-00000000000000ab"):
        status = ot.status()
        with pytest.raises(ot.OfflineError):
            ot.current_creds()

    assert status["mode"] == "gone" and "no longer open" in status["message"]


@pytest.mark.parametrize("header,expected", [("zme_tenant_source=sample", "sample"), ("a=1; zme_tenant_source=snap-0123456789abcdef", "snap-0123456789abcdef"),
                                             ("zme_tenant_source=../x", None), ("zme_tenant_source=\"sample\"; x", "sample"), ("x=1", None), ("", None),
                                             ("zme_tenant_source=SAMPLE", None), ('zme_tenant_source="unterminated', None),
                                             ("zme_tenant_source=sample\n", "sample"), ("zme_tenant_source=snap-0123456789abcdef0", None),
                                             ("xzme_tenant_source=sample", None), ("zme_tenant_source", None)])
def test_only_an_exact_offline_id_in_the_cookie_is_honoured(header, expected):
    """ASVS V5.1.3 · CWE-20 · CWE-565 · WSTG-SESS-02: the cookie names an offline tenant only with an exact id; anything else is the live tenant."""
    assert ot.source_from_cookie_header(header) == expected


@pytest.mark.parametrize("header", ['pref={"a": 1}; zme_tenant_source=sample', "a=b c; zme_tenant_source=sample", "x; zme_tenant_source=sample",
                                    'a="x; zme_tenant_source=sample', "zme_tenant_source=sample; broken"])
def test_another_apps_malformed_cookie_never_drops_the_offline_choice(header):
    """ASVS V1.4.1 · CWE-636 · CWE-20 · WSTG-SESS-02: a neighbouring cookie the strict parser cannot read (JSON, a space, no "=") must not put a browser that chose the sample back on the live tenant."""
    assert ot.source_from_cookie_header(header) == "sample"


def test_an_offline_id_with_a_trailing_newline_is_no_id():
    """ASVS V5.1.3 · CWE-20 · CWE-625: the id pattern is anchored at the very end ("$" would also accept a trailing newline)."""
    assert ot.store("sample\n") is None and not ot.SOURCE_RE.match("snap-0123456789abcdef\n")


def test_the_middleware_sets_the_offline_tenant_for_its_request_only():
    """ASVS V1.4.1 · CWE-488: SourceMiddleware puts the cookie's tenant in the request's own context and resets it after; non-HTTP scopes pass through."""
    import asyncio
    seen = []

    async def app(scope, receive, send):
        seen.append(ot.current_source())
    mw = ot.SourceMiddleware(app)

    asyncio.run(mw({"type": "http", "headers": [(b"cookie", b"zme_tenant_source=sample")]}, None, None))
    asyncio.run(mw({"type": "lifespan"}, None, None))

    assert seen == ["sample", None] and ot.current_source() is None


def test_the_record_label_of_offline_credentials():
    """ASVS V7.1.1 · CWE-451: records name the sample as the sample and an open snapshot by its label."""
    st = ot.open_document(_doc({"/zia/api/v1/x": []}, {"tenant_label": "Acme"}))

    assert ot.label_for({"client_id": f"offline-{st.id}"}) == "Snapshot of Acme"
    assert ot.label_for({"client_id": "offline-sample"}) == "Sample tenant: Larkspur Freight"
    assert ot.label_for({"client_id": "offline-file-ffffffffffffffff"}) == "Offline snapshot"


def test_a_saved_snapshot_is_reopened_from_its_file_after_a_restart(monkeypatch):
    """ASVS V1.14.1 · CWE-20: a saved snapshot that is not in memory is opened again (parsed as untrusted) from its file; a missing one is none."""
    import tenant_profiles
    raw = _doc({"/zia/api/v1/x": [1]}).encode()
    monkeypatch.setattr(tenant_profiles, "read_snapshot", lambda sid, limit: raw if sid == "snap-00000000000000c6" else (_ for _ in ()).throw(ValueError("No such snapshot.")))

    st = ot.store("snap-00000000000000c6")

    assert st is not None and st.answer_get("/zia/api/v1/x") == (200, [1]) and ot.store("snap-00000000000000c7") is None
    assert ot.store("../etc") is None and ot.store(7) is None


# ── Snapshot capture: only what is in scope ──────────────────────────────

class _LiveFake:
    """A 'live tenant' read through OfflineRawClient over a copy of the sample."""

    def __init__(self, extra: Dict[str, Any] = None):
        responses = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()}
        for p, b in (extra or {}).items():
            responses[p] = {"status": 200, "body": b}
        self.store = ot.OfflineStore("snap-00000000000000ee", "snapshot", responses, {})
        self.client = ot.OfflineRawClient(self.store, {})
        self.seen: List[str] = []
        real = self.store.answer_get

        def spy(url, params=None):
            self.seen.append(ot.normalize_path(url))
            return real(url, params)
        self.store.answer_get = spy


def test_capture_reads_only_the_ticked_scopes_and_gets_only():
    """ASVS V4.1.3 · CWE-285 · CWE-863 · WSTG-ATHZ-02: with only ZDX ticked, the snapshot read touches ZDX paths and nothing else, with GETs only."""
    live = _LiveFake()

    got = ot.capture(live.client, ["zdx"], {}, lambda m: None)

    assert got["responses"] and all(p.startswith("/zdx/") for p in got["responses"]) and all(p.startswith("/zdx/") for p in live.seen)
    assert live.store.writes == 0 and got["stopped"] is False


def test_capture_honours_an_unticked_channel():
    """ASVS V4.1.3 · CWE-863: a channel marked as another vendor's is not read for the snapshot (the Scope page's channel guard)."""
    live = _LiveFake()

    ot.capture(live.client, ["dlp"], {"web_dlp": "zscaler", "email_dlp": "alternative"}, lambda m: None)

    assert "/zia/api/v1/emailDlpRules" not in live.seen and "/zia/api/v1/webDlpRules" in live.seen


def test_capture_stops_before_the_next_read_and_saves_nothing():
    """ASVS V11.1.7 · CWE-400: Stop ends the read at once; the result says stopped."""
    import threading
    live = _LiveFake()
    cancel = threading.Event()
    cancel.set()

    got = ot.capture(live.client, ["dlp"], {}, lambda m: None, cancel)

    assert got["stopped"] is True and live.seen == []


def test_capture_counts_unread_lists_and_unknown_scopes_read_nothing():
    """ASVS V7.4.1 · CWE-755: a list the tenant cannot answer is named with its status; an unknown scope reads nothing."""
    live = _LiveFake()
    live.store.responses.pop("/zia/api/v1/ruleLabels")

    got = ot.capture(live.client, ["zia_extras", "nope"], {}, lambda m: None)
    nothing = ot.capture(live.client, ["nope"], {}, lambda m: None)

    assert "/zia/ruleLabels: HTTP 404" in got["unread"] and got["counts"]["not_read"] >= 1
    assert nothing["responses"] == {} and ot.capture_plan(["nope"]) == []


def test_capture_reads_every_zpa_page_up_to_the_cap(monkeypatch):
    """ASVS V12.1.1 · CWE-770 · CWE-400: a paginated ZPA list is read page by page and never beyond MAX_LIST_PAGES."""
    monkeypatch.setattr(ot, "MAX_LIST_PAGES", 3)
    calls = []

    class Guard:
        def get(self, ep, params=None):
            calls.append(params["page"])
            return {"totalPages": "99", "list": [{"id": str(params["page"])}]}, 200

    body, code = ot._read_zpa(Guard(), "/zpa/application")

    assert code == 200 and calls == [1, 2, 3] and [x["id"] for x in body["list"]] == ["1", "2", "3"]


def test_a_failed_zpa_or_zia_page_keeps_what_was_read():
    """ASVS V7.4.1 · CWE-755: a later page that fails keeps the earlier pages; a first page that fails is reported as it is."""
    class Guard:
        def __init__(self, fail_on):
            self.fail_on = fail_on

        def get(self, ep, params=None):
            page = params.get("page")
            if page == self.fail_on:
                return {"error": "x"}, 503
            return ({"totalPages": "5", "list": [page]} if ep.startswith("/zpa/") else [page] * 1000), 200

    assert ot._read_zpa(Guard(2), "/zpa/application")[0]["list"] == [1]
    assert ot._read_zpa(Guard(1), "/zpa/application")[1] == 503
    assert len(ot._read_zia_pages(Guard(3), "/zia/users")[0]) == 2000
    assert ot._read_zia_pages(Guard(1), "/zia/users")[1] == 503


# ── The sample tenant: API shapes, coverage, determinism ─────────────────

# Fields ZIA or Client Connector answer that the SDK 1.11.3 model does not
# declare (not the sample's invention): an Email DLP rule's incident forwarding
# and rank (tests/test_qa6_builders_lifecycle.py keeps them through a heal), and
# strict enforcement on an app profile (assumed: the readers ask for it).
SAMPLE_SDK_GAPS = {"WebPolicy.strictEnforcement", "OutboundEmailDlpRules.rank", "OutboundEmailDlpRules.zscalerIncidentReceiver"}
SAMPLE_MODELS = [
    (f"{ZCC}/application-profiles", "zcc.models.webpolicy", "WebPolicy"),
    (f"{ZCC}/webForwardingProfile/listByCompany", "zcc.models.forwardingprofile", "ForwardingProfile"),
    (f"{ZCC}/getCompanyInfo", "zcc.models.company_info", "CompanyInfo"),
    (f"{ZCC}/getWebPrivacyInfo", "zcc.models.webprivacy", "WebPrivacy"),
    (f"{ZCC}/webFailOpenPolicy/listByCompany", "zcc.models.failopenpolicy", "FailOpenPolicy"),
    ("/zia/api/v1/endPointDlpRules", "zia.models.endpoint_dlp_rules", "EndpointDlpRules"),
    ("/zia/api/v1/emailDlpRules", "zia.models.outbound_email_dlp_rules", "OutboundEmailDlpRules"),
    ("/zia/api/v1/fileTypeRules", "zia.models.filetyperules", "FileTypeControlRules"),
    ("/zia/api/v1/advancedSettings", "zia.models.advanced_settings", "AdvancedSettings"),
    ("/zia/api/v1/webDlpGlobalOptions", "zia.models.web_dlp_global_options", "WebDlpGlobalOptions"),
    ("/zia/api/v1/casbDlpRules", "zia.models.casb_dlp_rules", "CasbdDlpRules"),
    ("/zia/api/v1/locations", "zia.models.location_management", "LocationManagement"),
    ("/zia/api/v1/adminUsers", "zia.models.admin_users", "AdminUser"),
    ("/zdx/v1/apps", "zdx.models.applications", "ActiveApplications"),
    ("/zdx/v1/inventory/software", "zdx.models.software_inventory", "DeviceSoftwareInventory"),
    (f"{ZPA1}/application", "zpa.models.application_segment", "ApplicationSegments"),
    (f"{ZPA1}/connector", "zpa.models.app_connectors", "AppConnectorController"),
    ("/zpa/mgmtconfig/v2/admin/customers/{customerId}/posture", "zpa.models.posture_profiles", "PostureProfile"),
    ("/ziam/admin/api/v1/users", "zid.models.users", "UserRecord"),
    (f"{ZPA1}/roles", "zpa.models.role_controller", "RoleController"),
    ("/zia/api/v1/browserControlSettings", "zia.models.browser_control_settings", "BrowserControlSettings"),
]


def _rows(body: Any) -> List[Any]:
    if isinstance(body, dict):
        for k in ("list", "records", "software", "trustedNetworkContracts"):
            if isinstance(body.get(k), list):
                return body[k]
        return [body]
    return body


@pytest.mark.parametrize("path,module,cls", SAMPLE_MODELS, ids=[m[0].rsplit("/", 1)[-1] for m in SAMPLE_MODELS])
def test_the_sample_tenant_speaks_the_sdk_models_field_names(path, module, cls):
    """ASVS V5.1.3 · CWE-1287 · CWE-440 · SSDF PW.4.1: every field of a sample answer is one the SDK's model reads (snake_case where the API is: ZDX, device_type, install_ssl_certs)."""
    import sdk_wire_fake as wf
    model = getattr(importlib.import_module(f"zscaler.{module}"), cls)
    body = sample_tenant.responses()[path]

    unknown = sorted({f for row in _rows(body) for f in wf.unknown_fields(row, model)} - SAMPLE_SDK_GAPS)

    assert unknown == []


def test_the_sample_answers_every_cloud_app_control_rule_type_the_readers_list():
    """ASVS V5.1.3 · CWE-1287: each rule type of dlp_assessment_full_auto._CAC_TYPES has an answer (an empty list where the sample has no rule), as the API answers."""
    import dlp_assessment_full_auto as dl
    r = sample_tenant.responses()

    missing = [t for t in dl._CAC_TYPES if f"/zia/api/v1/webApplicationRules/{t}" not in r]

    assert missing == [] and set(sample_tenant.CAC_RULE_TYPES) == set(dl._CAC_TYPES)


@pytest.mark.parametrize("ep", ["/zia/webDlpGlobalOptions", "/zia/security/advanced", "/zcc/privacyInfo", "/zcc/deviceCleanup",
                                "/zcc/adminUsersSyncInfo", "/zdx/alerts/ongoing", "/zdx/inventory/software",
                                # the Path analyzer's ZIA modules and the ZPA readers (SDK-documented paths)
                                "/zia/security", "/zia/cyberThreatProtection/maliciousUrls", "/zia/cyberThreatProtection/securityExceptions",
                                "/zia/networkServiceGroups", "/zia/networkApplicationGroups", "/zia/browserControlSettings", "/zia/locations/groups",
                                "/zpa/inspectionProfile", "/zpa/isolation/profiles", "/zpa/praConsole", "/zpa/praPortal", "/zpa/userPortal",
                                "/zpa/browserProtectionProfile", "/zpa/roles"])
def test_the_sample_answers_the_reads_the_checks_make(ep):
    """ASVS V1.14.1 · CWE-1287: every SDK-documented endpoint an assessment check reads has an answer on the sample, so the check is assessed, not "not readable"."""
    st = ot.sample_store(reset=True)
    cl = ot.OfflineRawClient(st, ot.creds_for(st))

    _, code = cl.get(ep)

    assert code == 200


def test_readiness_reads_the_client_connector_switches_on_the_sample():
    """ASVS V1.14.1 · CWE-1287: the sample's company info uses the SDK's field names (zpnEnabled, upmEnabled, proxyEnabled), so the readiness check shows its switches."""
    st = ot.sample_store(reset=True)
    client = ot.OfflineSdkClient(st, ot.creds_for(st))

    probe = rd.read(client, ["zcc"], now=NOW)["probes"]["ZCC"]

    assert probe["flags"]["ZPA enabled"] is True and probe["flags"]["ZDX enabled"] is True and probe["flags"]["ZIA enabled"] is True


def test_the_sample_says_evaluate_all_rules_where_the_api_does():
    """ASVS V5.1.3 · CWE-1287: Evaluate All Rules is a DLP global option (enableEvaluateAllDlpRules), not an advanced setting."""
    r = sample_tenant.responses()

    assert r["/zia/api/v1/webDlpGlobalOptions"]["enableEvaluateAllDlpRules"] is False
    assert not any("EvaluateAll" in k for k in r["/zia/api/v1/advancedSettings"])


def test_the_sample_is_deterministic_and_each_copy_is_its_own():
    """ASVS V1.14.1 · CWE-330 · CWE-668: the sample is the same every time (no clock, no randomness), and one copy's change never reaches another or the shipped data."""
    a, b = sample_tenant.responses(), sample_tenant.responses()

    a["/zia/api/v1/webDlpRules"].append({"id": 1})

    assert b == sample_tenant.responses() and len(b["/zia/api/v1/webDlpRules"]) == len(sample_tenant.WEB_DLP_RULES)
    assert sample_tenant.meta() == sample_tenant.meta() and json.dumps(b, sort_keys=True) == json.dumps(sample_tenant.responses(), sort_keys=True)


def test_every_sample_path_is_a_valid_snapshot_path_and_names_no_real_domain():
    """ASVS V12.3.1 · CWE-22 · CWE-200: every sample path is a valid API path, and every e-mail and host is under a reserved example domain or Zscaler's own."""
    r = sample_tenant.responses()
    text = json.dumps(r)

    assert all(ot.valid_path(ot.normalize_path(p)) for p in r)
    emails = set(re.findall(r"[\w.+-]+@([\w.-]+)", text))
    assert emails <= {sample_tenant.DOMAIN}


def test_every_ticked_scope_of_the_sample_has_data():
    """ASVS V1.14.1 · CWE-1287: every scope the sample says it covers captures at least one list, so every page has data."""
    live = _LiveFake()

    empty = [s for s in sample_tenant.meta()["scopes"] if ot.capture_plan([s]) and not ot.capture(live.client, [s], {}, lambda m: None)["responses"]]

    assert empty == []


@pytest.mark.parametrize("urls,expected", [
    (["https://chat.openai.com/c/1"], ["AI_ML_APPS"]), (["files.dropbox.com"], ["FILE_HOST"]),
    (["billing.larkspur-freight.example:8443/x"], ["CORPORATE_MARKETING"]), (["unknown.test"], ["OTHER_MISCELLANEOUS"]),
    ([""], ["OTHER_MISCELLANEOUS"]), ([None], ["OTHER_MISCELLANEOUS"]), (["xn--bcher-kva.example"], ["OTHER_MISCELLANEOUS"]),
    (["[2001:db8::1]"], ["OTHER_MISCELLANEOUS"]),
])
def test_the_sample_url_lookup_oracle(urls, expected):
    """ASVS V5.1.3 · CWE-20: the sample's URL lookup answers by host and parent domain, unicode/IDN, IPv6 and empty input included; never raises."""
    out = sample_tenant.url_lookup(urls)

    assert out[0]["urlClassifications"] == expected


def test_the_sample_url_lookup_is_bounded():
    """ASVS V12.1.1 · CWE-770 · CWE-400: at most 100 URLs are answered, each echoed at most 300 characters."""
    out = sample_tenant.url_lookup(["a" * 1000] * 500)

    assert len(out) == 100 and len(out[0]["url"]) == 300


# ── Readiness: verdicts for every role, licence and scope ────────────────

class _Resp:
    def __init__(self, body: Any, code: int = 200):
        self.body, self.code = body, code

    def get_body(self):
        return self.body

    def get_status(self):
        return self.code


class _Err(Exception):
    def __init__(self, code: int):
        super().__init__(f"HTTP {code}")
        self.status_code = code


def _b64(obj: Any) -> str:
    import base64
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _jwt(service_info: Any) -> str:
    return _b64({"alg": "RS256"}) + "." + _b64({"service-info": service_info}) + ".sig"


TOKEN = _jwt([{"prd": "ZIA", "ext": {"rnm": "API role", "rid": "4711"}}, {"prd": "ZPA", "ext": {"rnm": "ZPA API", "rid": "216"}},
              {"prd": "ZCC", "ext": {"rnm": "ZCC RO", "rid": "9"}}, {"prd": "ZDX", "ext": {"rnm": "ZDX"}}])


def _client(role: Any, subs: Any, *, zpa_roles: Any = None, deny_subs: bool = False):
    ns = types.SimpleNamespace

    def ok(body):
        return lambda *a, **k: (None, _Resp(body), None)
    client = ns(_auth_token=TOKEN)
    client.zia = ns(admin_roles=ns(get_role=ok(role), list_roles=ok([dict(role or {}, id=4711)])))
    client.zcc = ns(company=ns(get_company_info=ok({})), admin_user=ns(list_admin_roles=ok([])))
    client.zpa = ns(role_controller=ns(list_roles=ok(zpa_roles if zpa_roles is not None else [])))
    client.zdx = ns(admin=ns(list_departments=ok([])))

    class Ex:
        def create_request(self, *a, **k):
            return a, None

        def execute(self, request):
            return (_Resp(None, 403), _Err(403)) if deny_subs else (_Resp(subs), None)
    client.get_request_executor = lambda: Ex()
    return client


def _role(level: str, policy: str = None, features: bool = True) -> Dict[str, Any]:
    return {"id": 4711, "name": "API role", "policyAccess": policy or level,
            "featurePermissions": {k: level for k in rd.ZIA_PERMS} if features else {}}


ROLES = {"full": _role("READ_WRITE"), "read": _role("READ_ONLY"), "none": _role("NONE"),
         "policy_rw": _role("", "READ_WRITE", features=False), "policy_ro": _role("", "READ_ONLY", features=False)}
ALL_SKUS = [{"id": s, "subscribed": True} for s in ("ZDLP_WEB", "Z_DLP_ENDPOINT", "Z_CASB", "ZS_DP_EMAIL", "ZS_DP_GEN_AI")]
LICENCES = {"all": ALL_SKUS, "no_dlp": [{"id": "URL_FILTER", "subscribed": True}], "empty": [], "denied": None}

# Oracle: (role, licence) -> (dlp scope, web write kind, email write kind, Deploy policy packs).
VERDICTS = {
    ("full", "all"): ("ok", "ok", "ok", "ok"),
    ("read", "all"): ("ok", "read_only", "read_only", "read_only"),
    ("none", "all"): ("blocked", "blocked", "blocked", "blocked"),
    ("policy_rw", "all"): ("ok", "ok", "ok", "ok"),
    ("policy_ro", "all"): ("ok", "read_only", "read_only", "read_only"),
    ("full", "no_dlp"): ("not_licensed", "not_licensed", "not_licensed", "not_licensed"),
    # A read-only role is reported before a missing licence for a write kind
    # that has a permission to check (tests/test_qa6_verdicts_reports.py).
    ("read", "no_dlp"): ("not_licensed", "read_only", "not_licensed", "read_only"),
    ("none", "no_dlp"): ("blocked", "blocked", "blocked", "blocked"),
    ("full", "empty"): ("ok", "ok", "ok", "ok"),
    ("read", "empty"): ("ok", "read_only", "read_only", "read_only"),
    ("full", "denied"): ("ok", "ok", "ok", "ok"),
    ("policy_ro", "denied"): ("ok", "read_only", "read_only", "read_only"),
}


@pytest.mark.parametrize("role,licence", list(VERDICTS), ids=[f"{r}-{l}" for r, l in VERDICTS])
def test_readiness_verdict_oracle_for_role_and_licence(role, licence):
    """ASVS V1.4.4 · ASVS V4.1.3 · CWE-284 · CWE-1059: the DLP scope, the web and email write kinds and Deploy policy packs follow the role's feature permissions (else its policy access) and the licence list (an empty or unreadable one greys nothing out)."""
    client = _client(ROLES[role], LICENCES[licence], deny_subs=LICENCES[licence] is None)

    out = rd.evaluate(rd.read(client, ["dlp"], now=NOW))
    scopes = {f["key"]: f["status"] for f in out["scopes"]}
    kinds = {f["key"]: f["status"] for f in out["write_kinds"]}
    writes = {f["key"]: f["status"] for f in out["writes"]}

    assert (scopes["dlp"], kinds["web"], kinds["email"], writes["deploy_packs"]) == VERDICTS[(role, licence)]


@pytest.mark.parametrize("scope", list(rd.SCOPE_FEATURES))
def test_a_scope_that_is_not_ticked_is_never_said_to_work(scope):
    """ASVS V1.4.4 · CWE-284 · CWE-1059: with nothing ticked and no token listing, no Scope page key reads "Will work" on no evidence."""
    client = _client(ROLES["full"], ALL_SKUS)
    client._auth_token = None

    out = rd.evaluate(rd.read(client, [], now=NOW))

    status = {f["key"]: f["status"] for f in out["scopes"]}[scope]
    assert status in ("not_in_scope", "unknown", "blocked")


def test_readiness_finds_the_zpa_role_in_the_sdks_envelope():
    """ASVS V1.4.4 · CWE-1287 · CWE-284: zpa.role_controller.list_roles's body is {"list": [...]}; the API client's view-only ZPA role is found there, so moving segments is said to be read only."""
    roles = {"totalPages": "1", "list": [{"id": "216", "name": "ZPA API", "classPermissionGroups": [
        {"classPermissions": [{"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "VIEW_ONLY"}}]}]}]}
    client = _client(ROLES["full"], ALL_SKUS, zpa_roles=roles)

    facts = rd.read(client, ["zpa"], customer_id="7210000000000", now=NOW)
    writes = {f["key"]: f for f in rd.evaluate(facts)["writes"]}

    assert facts["probes"]["ZPA"]["role_found"] is True and facts["probes"]["ZPA"]["classes"] == {"Application Segment": "VIEW_ONLY"}
    assert writes["zpa_segment_moves"]["status"] == "read_only"


def test_readiness_finds_the_zpa_role_through_the_real_sdk_service():
    """ASVS V1.4.4 · CWE-1287 · SSDF PW.4.1: through the SDK's own ZPA service (offline executor), the role list answer is read as the SDK hands it over."""
    roles = {"totalPages": "1", "list": [{"id": "216", "name": "ZPA API", "classPermissionGroups": []}]}
    st = _snapshot_store({f"{ZPA1}/roles": roles})
    client = ot.OfflineSdkClient(st, ot.creds_for(st))
    client._auth_token = TOKEN

    probe = rd.read(client, ["zpa"], customer_id="7210000000000", now=NOW)["probes"]["ZPA"]

    assert probe["responds"] is True and probe["role_found"] is True


@pytest.mark.parametrize("end", [10 ** 400, -(10 ** 400), float("inf"), float("nan"), 0, True, "2027-01-01"])
def test_a_hostile_licence_end_date_is_no_date_and_never_raises(end):
    """ASVS V5.1.4 · CWE-190 · CWE-755 · WSTG-INPV-13: an end date too large for a float, negative, infinite, NaN, zero, boolean or text is no date; nothing raises."""
    rows = rd.parse_subscriptions([{"id": "ZDLP_WEB", "subscribed": True, "endDate": end}], now=NOW)

    assert rows[0]["ends_on"] is None and rows[0]["ending_soon"] is False


@pytest.mark.parametrize("end,soon", [(NOW + 20 * 86400, True), (NOW + 22 * 86400, False), ((NOW + 5 * 86400) * 1000, True), (NOW - 86400, False)])
def test_a_licence_ending_within_21_days_is_flagged(end, soon):
    """ASVS V1.4.4 · CWE-1059: the "ends soon" boundary is 21 days, in seconds or milliseconds; an ended licence is not "soon"."""
    rows = rd.parse_subscriptions([{"id": "ZDLP_WEB", "subscribed": True, "endDate": end}], now=NOW)

    assert rows[0]["ending_soon"] is soon


@pytest.mark.parametrize("token,why", [
    ("a." + "A" * 13700 + ".c", "too large"),
    ("a.!!!.c", "not a JSON Web Token"),
    ("a.A.c", "could not be decoded"),
    ("a." + _b64(["x"]) + ".c", "not an object"),
    ("a." + __import__("base64").urlsafe_b64encode(b"\xff\xfe").decode().rstrip("=") + ".c", "could not be decoded"),
])
def test_token_decode_limits_say_why_without_quoting_the_token(token, why):
    """ASVS V5.1.4 · ASVS V3.5.3 · CWE-20 · CWE-400 · CWE-209: an oversized, non-base64, non-UTF-8 or non-object payload is refused in words that quote nothing from the token."""
    out = rd.decode_claims(token)

    assert out["ok"] is False and why in out["why"] and token[2:40] not in out["why"]


def test_token_lists_are_bounded():
    """ASVS V12.1.1 · CWE-770: at most MAX_SERVICES products and MAX_SCOPES scopes are kept from a token; duplicates once."""
    many = [{"prd": f"P{i}"} for i in range(100)] + [{"prd": "ZIA"}, {"prd": "zia"}]
    token = _b64({}) + "." + _b64({"service-info": many, "scp": [f"s{i}" for i in range(500)]}) + ".x"

    out = rd.decode_claims(token)

    assert len(out["products"]) == rd.MAX_SERVICES and len(out["scopes"]) == rd.MAX_SCOPES


def test_the_readiness_html_escapes_every_tenant_value():
    """ASVS V5.3.3 · CWE-79 · A03:2021 · WSTG-INPV-02: a role name, licence id, flag and summary from the tenant are escaped in the /permissions block."""
    evil = '"><script>alert(1)</script>'
    result = {"tenant_label": evil, "summary": evil, "checked_at": evil, "products": [{"label": evil, "access": evil, "role": evil, "responds": True, "why": evil, "steps": [evil]}],
              "licences": {"read": True, "rows": [{"area": evil, "name": evil, "id": evil, "active": False, "status": evil, "ends_on": evil, "ending_soon": True}],
                           "zcc_flags": {evil: True}},
              "scopes": [{"label": evil, "status": "blocked", "why": evil, "notes": [evil], "steps": [evil], "kind": "scope"}], "writes": [], "token": {"ok": False, "why": evil}}

    html = rd.html_section([result]) + rd.scope_badge({"status": evil, "why": evil, "steps": [evil]})

    assert "<script>" not in html and "&lt;script&gt;" in html


# ── Scope and permission maps ────────────────────────────────────────────

def _scope_page_keys() -> set:
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    return set(re.findall(r'class="scope-cb" value="([a-z_]+)"', html))


def test_every_scope_page_key_has_a_required_access_card():
    """ASVS V1.4.4 · ASVS V14.1.1 · CWE-1059 · SSDF PW.1.1: every Scope page checkbox has its minimum permissions on Required API access (rbac had none)."""
    keys = _scope_page_keys()

    missing = sorted(keys - set(scope_permissions.SCOPE_PERMISSIONS))

    assert keys and missing == []


def test_the_permissions_page_shows_the_rbac_card():
    """WCAG 2.2 SC 1.3.1 · ASVS V1.4.4 · CWE-1059: /permissions draws a card for RBAC with its endpoints."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv

    page = TestClient(srv.app).get("/permissions").text

    assert 'id="scope-rbac"' in page and "/zia/adminRoles" in page


@pytest.mark.parametrize("key", sorted(scope_permissions.SCOPE_PERMISSIONS))
def test_every_scope_permission_entry_is_complete(key):
    """ASVS V1.4.4 · CWE-1059: each scope's entry names a label, a service, its read permissions, its endpoints and its licence."""
    sp = scope_permissions.get_scope_permissions(key)

    assert sp["label"] and sp["service"] and sp["permissions_read"] and sp["endpoints_used"] and sp["license_required"]
    assert isinstance(sp["customer_id_needed"], bool) and (not sp["customer_id_needed"] or "customer_id_note" in sp)


def test_rbac_checks_that_could_not_run_count_under_the_rbac_scope():
    """ASVS V1.4.4 · CWE-1059: every RBAC section runs under the rbac checkbox, so a refused RBAC check is counted there and its permissions listed."""
    results = [{"id": "RBAC.1", "section": "RBAC — ZIA Roles", "status": "INFO", "detail": "HTTP 403"},
               {"id": "RBAC.8", "section": "RBAC — ZCC Admins", "status": "INFO", "detail": "Access denied"}]

    out = permissions.assessment_permission_summary(results, ["rbac"])

    assert out["by_scope"] == {"rbac": 2} and out["needed_for_full_scan"][0]["scope"] == "rbac"
    assert out["needed_for_full_scan"][0]["blocked_checks"] == 2


@pytest.mark.parametrize("section,scope", [("ZIA — Firewall", "zia_extras"), ("ZCC — Mobile", "zcc"), ("ZPA — App Segments", "zpa"),
                                           ("GenAI — Prompt", "genai"), ("Automation — Terraform", "automation"), ("ZDX — Alerts", "zdx"),
                                           ("ZIdentity — Directory", "zidentity"), ("RBAC — ZIA", "rbac"), ("RBAC — ZPA", "rbac"),
                                           ("RBAC — ZIdentity", "rbac"), ("Ch.E — GenAI", "dlp"), ("", "dlp"), (None, "dlp")])
def test_every_assessment_section_maps_to_its_scope_page_key(section, scope):
    """ASVS V1.4.4 · CWE-1059: the section-to-scope oracle matches the registries each Scope page key runs."""
    assert permissions.scope_of_section(section) == scope


def test_every_section_of_every_registry_maps_to_a_scope_that_runs_it():
    """ASVS V1.4.4 · CWE-1059 · SSDF PW.1.1: for every check of every scope's registry, scope_of_section names that scope (DLP's channel sections stay dlp)."""
    wrong = []
    for scope, regs in bs.SCOPE_REGISTRIES.items():
        for module, attr, prefix in regs:
            for chk in bs._registry(module, attr):
                section = str(chk[1])
                if prefix and not section.startswith(prefix):
                    continue
                if permissions.scope_of_section(section) != scope:
                    wrong.append((scope, section))

    assert sorted(set(wrong)) == []


def test_every_write_kind_maps_to_a_readiness_need_and_a_permission():
    """ASVS V1.4.4 · CWE-1059: every write kind has a portal permission, a readiness need, and write_permissions_needed names each permission once."""
    kinds = list(permissions.WRITE_PERMISSIONS)

    needed = permissions.write_permissions_needed(kinds + ["dictionary", "nope", 7])

    assert set(kinds) == set(rd.WRITE_KINDS) and [n["kind"] for n in needed] == kinds


def test_every_zia_permission_listed_is_documented_by_the_sdk_or_a_named_alias():
    """ASVS V1.14.6 · SSDF PW.4.1 · CWE-1104: every ZIA feature-permission key readiness lists is in the SDK's admin_roles docs, except the two split spellings it accepts as aliases only."""
    doc = open(os.path.join(SDK, "zia", "admin_roles.py"), encoding="utf-8").read()
    aliases = {"URL_FILTERING_CONTROL", "CLOUD_APP_CONTROL"}

    undocumented = {k for k in rd.ZIA_PERMS if f"`{k}`" not in doc}
    first_spellings = {alts[0] for s in list(rd.SCOPE_FEATURES.values()) + list(rd.WRITE_KINDS.values()) for alts in s.get("needs", []) + s.get("optional", [])}

    assert undocumented == aliases and not (aliases & first_spellings)


@pytest.mark.parametrize("ep,product", [("/zia/incidentReceiverServers", "ZIA"), ("/zia/firewallFilteringRules", "ZIA"), ("/zcc/getDevices", "Client Connector"),
                                        ("/ztw/api/v1/x", "ZTW"), ("", "?"), (None, "?"), ("/zia/unknownThing", "ZIA")])
def test_the_permission_for_an_endpoint_is_the_longest_prefix(ep, product):
    """ASVS V1.4.4 · CWE-1059: an endpoint names its product and permission by the longest matching prefix; an unknown one names a read of itself."""
    out = permissions.permission_for_endpoint(ep)

    assert out["product"] == product and out["endpoint"] == str(ep or "")


def test_report_diagnostics_name_the_permission_only_for_refusals():
    """ASVS V7.4.1 · CWE-1059: a report diagnostic that was a refusal names its permission; any other failure is not one."""
    diags = [{"endpoint": "/zia/sslInspectionRules", "error": "HTTP 403", "section": "ssl"}, {"endpoint": "/zia/x", "error": "HTTP 500"}]

    out = permissions.report_permission_diagnostics(diags)

    assert out == [{"product": "ZIA", "permission": "SSL Inspection Policy", "endpoint": "/zia/sslInspectionRules", "section": "ssl"}]


def test_the_assessment_summary_counts_hidden_checks_and_never_scores_nothing():
    """ASVS V1.4.4 · CWE-1059: hidden (out-of-scope) checks are counted only as hidden; with nothing scoreable the score is None, never 100."""
    results = [{"id": "1", "status": "INFO", "detail": "x", "out_of_scope": True}, {"id": "2", "status": "INFO", "detail": "HTTP 403"}]

    out = permissions.assessment_summary(results, hidden="junk")

    assert out["hidden"] == 1 and out["score"] is None and out["state"] == "partial" and out["not_permitted_ids"] == ["2"]


# ── Channel scope: the "marked Zscaler" logic ────────────────────────────

@pytest.mark.parametrize("value,choice", [("zscaler", "zscaler"), (" ZSCALER ", "zscaler"), ({"choice": "Zscaler"}, "zscaler"), ("alternative", "alternative"),
                                          ("gap", "gap"), ("yes", "gap"), (True, "gap"), (None, "gap"), ({"choice": ["zscaler"]}, "gap"), ({}, "gap")])
def test_only_a_channel_marked_zscaler_is_read(value, choice):
    """ASVS V4.1.3 · ASVS V5.1.3 · CWE-863 · CWE-20: only the word zscaler (any case or spacing) puts a Scope page channel on Zscaler; anything else is a gap, never read."""
    out = cs.effective({"web_dlp": value})

    assert out["web_dlp"]["choice"] == choice
    assert ("web_dlp" in cs.in_scope({"web_dlp": value})) is (choice == "zscaler")


def test_a_channel_marked_zscaler_brings_its_prerequisite_with_the_reason():
    """ASVS V4.1.3 · CWE-863: Inline Web DLP on Zscaler puts SSL inspection in scope (declared gap), with who needs it and why; GenAI adds itself to the same prerequisite."""
    out = cs.effective({"web_dlp": "zscaler", "genai_security": "zscaler"})

    ssl = out["ssl_inspection"]
    assert ssl["choice"] == "zscaler" and ssl["declared"] == "gap" and ssl["required_by"] == ["web_dlp", "genai_security"] and len(ssl["reasons"]) == 2


def test_an_alternative_prerequisite_stays_excluded_and_is_reported():
    """ASVS V4.1.3 · CWE-863 · CWE-636: a prerequisite marked as another vendor's is never silently read; its endpoints stay refused and the note says why."""
    decl = {"device_control": "zscaler", "endpoint_dlp": "alternative"}

    out = cs.effective(decl)
    client = cs.ScopedClient(types.SimpleNamespace(get=lambda ep, *a, **k: ([], 200)), decl)

    assert out["endpoint_dlp"]["choice"] == "alternative" and out["endpoint_dlp"]["blocked"] is True
    assert client.get("/zia/endPointDlpRules")[1] == 0 and "unmet prerequisite" in cs.prerequisites(decl)[0]["note"]


def test_a_sent_name_never_renames_a_scope_page_channel():
    """ASVS V5.1.3 · CWE-451 · CWE-20: the name a request sends for a fixed Scope page channel is ignored (the report names what was assessed); a custom channel keeps its own, bounded."""
    out = cs.normalize({"ssl_inspection": {"choice": "alternative", "name": "Nothing to see here"}, "custom_1": {"choice": "gap", "name": "P" * 200}})

    assert out["ssl_inspection"]["name"] == "SSL/TLS Inspection" and out["custom_1"]["name"] == "P" * 80
    assert "Nothing to see" not in cs.prerequisites({"web_dlp": "zscaler", "ssl_inspection": {"choice": "alternative", "name": "Nothing to see"}})[0]["note"]


def test_a_channel_ticked_zscaler_is_not_marked_as_a_prerequisite():
    """ASVS V7.1.1 · CWE-1059: SSL inspection ticked by the operator carries no "included because" note."""
    assert cs.prerequisites({"web_dlp": "zscaler", "ssl_inspection": "zscaler"}) == []


@pytest.mark.parametrize("declaration,narrowed", [(None, False), ({}, False), ([], False), ({"": "zscaler"}, True), ({"custom_x": None}, True),
                                                  ({"web_dlp": None}, True)])
def test_what_counts_as_a_declaration(declaration, narrowed):
    """ASVS V4.1.3 · CWE-863 · CWE-636: no declaration narrows nothing; any non-empty dict is a declaration (unreadable entries included), so every channel is then a gap unless marked."""
    out = cs.effective(declaration)

    assert bool(out) is narrowed
    if narrowed:
        assert all(v["choice"] == "gap" for v in out.values())


def test_a_check_of_a_channel_on_zscaler_runs_and_one_reading_an_unticked_channel_does_not():
    """ASVS V4.1.3 · CWE-863: partition runs a check of a Zscaler channel, skips (INFO, out of scope) one whose channel is a gap, and merges them back in order."""
    def chk(i, s):
        return (i, s, "label", lambda cl: None)
    checks = [chk("A.1", "Ch.A — Inline Web"), chk("D.2", "Ch.D — Email DLP"), chk("1.1", "1 — CC Portal")]

    run, skipped, order = cs.partition(checks, {"web_dlp": "zscaler"})
    merged = cs.merge(order, [{"id": c[0]} for c in run], skipped)

    assert [c[0] for c in run] == ["A.1", "1.1"] and skipped[0]["id"] == "D.2" and skipped[0]["out_of_scope"] and skipped[0]["gap"]
    assert [m["id"] for m in merged] == ["A.1", "D.2", "1.1"]


def test_a_skipped_check_of_an_alternative_channel_says_so_with_its_note():
    """ASVS V7.1.1 · CWE-1059: a check skipped for an alternative channel names the channel and the operator's note, outside the score."""
    out = cs.skipped_result("D.2", "Ch.D — Email DLP", "x", "email_dlp", {"choice": "alternative", "note": "Vendor X", "name": "Email DLP"})

    assert "covered by an alternative solution (Vendor X)" in out["detail"] and out["status"] == "INFO" and "gap" not in out


def test_the_scoped_client_can_be_copied():
    """ASVS V5.1.3 · CWE-674 · CWE-755: copying the channel guard (before its __init__ state exists) raises nothing and the copy still guards."""
    inner = types.SimpleNamespace(get=lambda ep, *a, **k: ([], 200), name="inner")
    guard = cs.ScopedClient(inner, {"web_dlp": "zscaler"})

    twin = copy.copy(guard)

    assert twin.name == "inner" and twin.get("/zia/emailDlpRules")[1] == 0 and twin.get("/zia/webDlpRules")[1] == 200


def test_the_scoped_client_records_only_unanswered_reads_of_its_thread():
    """ASVS V7.4.1 · CWE-755: a read the tenant did not answer (429, 5xx, 0) is recorded for the running check; an answer is not; a malformed answer never raises."""
    answers = {"/a": ([], 429), "/b": ([], 200), "/c": None}
    guard = cs.ScopedClient(types.SimpleNamespace(get=lambda ep, *a, **k: answers[ep]), {})

    guard.begin()
    for ep in answers:
        guard.get(ep)

    assert guard.unanswered() == [("/a", 429)]


@pytest.mark.parametrize("n,line", [(0, ""), (None, ""), ("x", ""), (-3, ""), (1, "1 check is outside the selected scope and is not shown."),
                                    (2, "2 checks are outside the selected scope and are not shown.")])
def test_the_hidden_note_oracle(n, line):
    """WCAG 2.2 SC 3.3.2 · CWE-1059: one plain line stands for the hidden checks, singular and plural, and nothing for none or junk."""
    assert cs.hidden_note(n) == line


def test_coverage_names_only_what_was_assessed():
    """ASVS V7.1.1 · CWE-1059: the report's note names the ticked channels and the prerequisites; the left-out ones are one count."""
    skipped = [{"channel": "email_dlp"}, {"channel": "email_dlp"}]

    out = cs.coverage({"web_dlp": "zscaler"}, skipped)
    none = cs.coverage({}, [])

    assert "Inline Web DLP" in out["note"] and "SSL/TLS Inspection: included because" in out["note"] and out["hidden"] == 2
    assert {r["id"]: r["checks_not_in_scope"] for r in out["gaps"]}["email_dlp"] == 2 and none["declared"] is False


@pytest.mark.parametrize("ep,chans", [("/zia/webDlpRules", ("web_dlp",)), ("raw:/zia/webDlpRules/5?x=1", ("web_dlp",)),
                                      ("/zia/webDlpRulesX", ()), ("/zia/casbTenant/lite", ("saas_casb", "email_dlp")), (None, ())])
def test_endpoint_channel_oracle(ep, chans):
    """ASVS V4.1.3 · CWE-863 · CWE-22: an endpoint holds a channel's configuration only on an exact path or a sub-path (never a longer name)."""
    assert cs.endpoint_channels(ep) == chans


def test_pack_targets_never_include_a_prerequisite():
    """ASVS V4.1.3 · CWE-841: a policy pack targets only the channels explicitly marked Zscaler, never one added as a prerequisite."""
    assert cs.pack_targets({"web_dlp": "zscaler", "device_control": "zscaler", "email_dlp": "alternative"}) == ["web"]


# ── Beacon's watch: only what is in scope ────────────────────────────────

def test_the_watch_reads_no_channel_left_out_of_the_declaration():
    """ASVS V4.1.3 · CWE-863: the page sends only the channels marked Zscaler or alternative; the watch treats every other channel as a gap."""
    decl = bs.declaration({"web_dlp": "zscaler"})

    assert decl["email_dlp"]["choice"] == "gap" and decl["ssl_inspection"]["choice"] == "zscaler"
    assert bs.zscaler_channels({"web_dlp": "zscaler"}) == ["web_dlp", "ssl_inspection"]


def test_the_watch_scope_inputs_are_normalised():
    """ASVS V5.1.3 · CWE-20: unknown scopes and non-list input are dropped; the Scope page's order is kept."""
    assert bs.normalize_scopes(["zpa", "dlp", "x", 5]) == ["dlp", "zpa"] and bs.normalize_scopes("dlp") == []
    assert bs.has_selection([], {"web_dlp": "zscaler"}) and not bs.has_selection(["x"], None)


def test_the_watch_summary_oracle():
    """WCAG 2.2 SC 3.3.2 · CWE-1059: the one-line summary names the scopes, DLP's channels in short, singular and plural."""
    assert bs.summary(["dlp", "zcc"], ["web_dlp", "email_dlp"], 12) == "12 endpoints for DLP (Web, Email), ZCC"
    assert bs.summary(["zcc"], ["web_dlp"], 1) == "1 endpoint for ZCC, channels on Zscaler: Web"
    assert bs.summary([], [], 0) == "0 endpoints for nothing in scope"


def test_the_watch_refuses_when_nothing_in_scope_is_readable_with_this_sign_in():
    """ASVS V4.1.3 · CWE-863 · CWE-636: a classic sign-in cannot read ZPA, nor any sign-in without a customer id; with nothing readable the watch refuses before sign-in."""
    sel = {"endpoints": {"/zpa/application": []}, "summary": "1 endpoint for ZPA"}

    assert "can be read" in bs.nothing_readable(sel, legacy=True, customer_id="1")
    assert "customer id" in bs.nothing_readable(sel, legacy=False, customer_id="")
    assert bs.nothing_readable(sel, legacy=False, customer_id="1") == "" and bs.nothing_readable({"endpoints": {}}, False, "") == ""


def test_the_watch_never_reads_an_unticked_channels_rules():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: with DLP ticked and only Inline Web DLP on Zscaler, the Email, Endpoint and SaaS DLP rules are not read."""
    sel = bs.select(["dlp"], {"web_dlp": "zscaler"})

    read = set(sel["endpoints"])
    assert "/zia/webDlpRules" in read and not read & {"/zia/emailDlpRules", "/zia/endPointDlpRules", "/zia/casbDlpRules"}
    assert set(bs.describe(sel)["read"]) == read


def test_the_endpoint_literal_pattern_takes_endpoints_not_bases():
    """ASVS V5.1.3 · CWE-1333 · CWE-20: the endpoint pattern matches a whole endpoint, never a base ("/zia/") or a trailing slash, in linear time."""
    pat = bs._ENDPOINT_LITERAL

    assert pat.fullmatch("/zia/urlFilteringRules") and not pat.fullmatch("/zia/") and not pat.fullmatch("/zpa/mgmtconfig/")
    assert not pat.fullmatch("/zia/" + "a/" * 5000)   # linear, no catastrophic backtracking


def _cycle_a(cl):
    return _cycle_b(cl) or cl.get("/zia/webDlpRules")


def _cycle_b(cl):
    return _cycle_a(cl) or cl.get("/zia/dlpEngines")


def test_function_endpoints_follows_helpers_once_and_ignores_code_without_source():
    """ASVS V5.1.3 · CWE-674 · CWE-835: a check's helpers are followed once each, even when they call each other, and code without source (a builtin) reads nothing."""
    eps = bs.function_endpoints(_cycle_a)

    assert eps == {"/zia/webDlpRules", "/zia/dlpEngines"} and bs.function_endpoints(len) == set()


# ── Branch coverage: offline answers ─────────────────────────────────────

@pytest.mark.parametrize("url,key", [("https://api.zsapi.net/zia/api/v1/x?y=1#f", "/zia/api/v1/x"), ("https://host", "/"), ("//zia//api/", "/zia/api"),
                                     ("/zpa/mgmtconfig/v1/admin/customers/123/application", f"{ZPA1}/application"), (None, ""), ("/", "/")])
def test_normalize_path_oracle(url, key):
    """ASVS V5.1.3 · CWE-20 · CWE-918: a request URL's table key drops scheme, host, query and fragment, folds doubled and trailing slashes, and names the ZPA customer id."""
    assert ot.normalize_path(url) == key


def test_a_later_page_of_an_envelope_keeps_its_shape():
    """ASVS V5.1.3 · CWE-1287: page 2 of a ZPA or ZIdentity envelope is the same envelope with an empty list; a scalar answer is itself."""
    st = _snapshot_store({f"{ZPA1}/application": {"totalPages": "1", "list": [{"id": "1"}]}, "/zia/api/v1/status": {"status": "ACTIVE"}})

    _, zpa = st.answer_get(f"{ZPA1}/application", {"page": 2})

    assert zpa == {"totalPages": "1", "list": []} and ot._empty_page("x") == "x" and ot._empty_page({"status": "A"}) == {"status": "A"}


def test_the_offline_table_answers_v1_for_v2_lite_for_the_list_and_text_bodies():
    """ASVS V1.14.1 · CWE-1287: a ZPA v2 path finds its v1 answer (and back), a /lite list its full list, and a text answer (a PAC file) its text."""
    st = _snapshot_store({f"{ZPA1}/idp": {"list": []}, "/zia/api/v1/casbTenant": [{"tenantId": 5}]})
    st.responses["/zia/api/v1/pacFiles/31/text"] = {"status": 200, "body": None, "text": "function FindProxyForURL(){}"}
    cl = ot.OfflineRawClient(st, {})

    assert st.answer_get("/zpa/mgmtconfig/v2/admin/customers/1/idp")[0] == 200
    assert st.answer_get("/zia/api/v1/casbTenant/lite") == (200, [{"tenantId": 5}])
    assert st.answer_get("/zia/api/v1/casbTenant/5") == (200, {"tenantId": 5})
    assert cl.get_text("/zia/pacFiles/31/text")[0].startswith("function")
    assert cl.get_text("/zia/nothing")[1] == 404


def test_the_sample_answers_activation_expression_checks_and_url_lookups_in_memory():
    """ASVS V1.14.1 · CWE-653: activation, a DLP expression check and a URL lookup are answered by the sample; a snapshot answers none of them."""
    sample = ot.sample_store(reset=True)
    snap = _snapshot_store({"/zia/api/v1/x": []})

    assert sample.answer_write("POST", "/zia/api/v1/status/activate") == (200, {"status": "ACTIVE"})
    assert sample.answer_write("POST", "/zia/api/v1/dlpEngines/validateDlpExpr", "((D1.S > 0))") == (200, {"status": "VALID"})
    assert sample.answer_write("POST", "/zia/api/v1/urlLookup", "not a list")[1] == []
    assert snap.answer_write("POST", "/zia/api/v1/urlLookup", ["a.com"])[0] == 404
    assert sample.answer_write("POST", "/zins/graphql", {})[1]["code"] == "NOT_OFFLINE"


def test_the_cloud_app_control_fan_out_tags_each_rule_with_its_type():
    """ASVS V1.14.1 · CWE-1287: /zia/cloudApplicationRules is read per rule type from the sample and each rule keeps its type."""
    st = ot.sample_store(reset=True)
    cl = ot.OfflineRawClient(st, ot.creds_for(st))

    rules, code = cl.get("/zia/cloudApplicationRules")

    assert code == 200 and {r["type"] for r in rules} == {"AI_ML", "FILE_SHARE", "WEBMAIL"}


def test_the_cloud_app_control_fan_out_reports_the_first_failure_when_nothing_answers():
    """ASVS V7.4.1 · CWE-755: when no rule type answers, the fan-out returns the first refusal, not an empty success."""
    cl = ot.OfflineRawClient(_snapshot_store({"/zia/api/v1/x": []}), {})

    body, code = cl.get("/zia/cloudApplicationRules")

    assert code == 404 and "Not in this snapshot" in body["message"]


def test_the_sdk_executor_answers_raw_and_empty_bodies():
    """ASVS V1.14.1 · CWE-1287: the in-memory executor hands the raw answer when asked, reads query strings, converts a body as the SDK sends it, and answers a 204 delete."""
    st = ot.sample_store(reset=True)
    ex = ot.OfflineExecutor(st)

    req, _ = ex.create_request("GET", "/zia/api/v1/webDlpRules?page=2", params={"pageSize": 5})
    raw, err = ex.execute(req, return_raw_response=True)
    post, _ = ex.create_request("POST", "/zia/api/v1/ruleLabels", body={"rule_name": "x"})
    deleted, d_err = ex.execute(ex.create_request("DELETE", "/zia/api/v1/webDlpRules/101")[0])

    assert err is None and raw.json() == [] and req["params"] == {"pageSize": 5, "page": "2"}
    assert post["json"] == {"ruleName": "x"} and d_err is None and deleted.get_status() == 204


def test_capture_keeps_the_app_profiles_and_names_a_platform_it_could_not_read():
    """ASVS V7.4.1 · CWE-755: the Client Connector app profiles are read per platform; a platform the tenant refuses is named, the others kept."""
    live = _LiveFake()
    real = live.store.answer_get

    def refuse_ios(url, params=None):
        if (params or {}).get("deviceType") == 1:
            return 503, {"message": "busy"}
        return real(url, params)
    live.store.answer_get = refuse_ios

    got = ot.capture(live.client, ["zcc"], {}, lambda m: None)

    assert any("ios" in u for u in got["unread"]) and got["responses"][f"{ZCC}/application-profiles"]["body"]


def test_capture_logs_a_list_the_tenant_did_not_answer():
    """ASVS V7.1.1 · CWE-778: a list not answered (HTTP 5xx, 429, 0) is logged in words, and counted as not read."""
    live = _LiveFake()
    real = live.store.answer_get
    live.store.answer_get = lambda url, params=None: (503, {}) if url.endswith("/locations") else real(url, params)
    logs: List[str] = []

    got = ot.capture(live.client, ["zia_extras"], {}, logs.append)

    assert any("/zia/locations was not answered (HTTP 503)" in m for m in logs) and "/zia/locations: HTTP 503" in got["unread"]


def test_a_zpa_page_with_an_unreadable_total_is_read_as_the_last():
    """ASVS V5.1.3 · CWE-20 · CWE-755: a ZPA page whose totalPages is not a number ends the read; nothing raises."""
    class Guard:
        def get(self, ep, params=None):
            return {"totalPages": "many", "list": [1]}, 200

    body, code = ot._read_zpa(Guard(), "/zpa/application")

    assert code == 200 and body["list"] == [1]


def test_compare_names_plain_values_and_zdx_lists():
    """ASVS V7.1.1 · CWE-1287: lists of plain values compare by value; ZDX lists are named as ZDX's; Cloud App Control types by their type."""
    old = {"/zdx/v1/administration/locations": {"status": 200, "body": ["a"]}, "/zia/api/v1/webApplicationRules/AI_ML": {"status": 200, "body": []}}
    new = {"/zdx/v1/administration/locations": {"status": 200, "body": ["a", "b"]}, "/zia/api/v1/webApplicationRules/AI_ML": {"status": 200, "body": [{"name": "r"}]}}

    rows = {r["what"]: r for r in ot.compare(old, new)["lists"]}

    assert rows["ZDX locations"]["added"] == ["b"] and rows["Cloud App Control rules (ai ml)"]["added"] == ["r"]


# ── Branch coverage: readiness helpers ───────────────────────────────────

class _BadStatus:
    def get_status(self):
        raise RuntimeError("x")

    def get_body(self):
        raise RuntimeError("x")


class _Model:
    def __init__(self, d, fail=False):
        self.d, self.fail = d, fail

    def as_dict(self):
        if self.fail:
            raise ValueError("x")
        return self.d


def test_readiness_reads_a_status_from_whatever_the_sdk_gives():
    """ASVS V7.4.1 · CWE-755 · CWE-209: a status is taken from the error, the response, or a number in the error text; nothing raises and no text is kept."""
    assert rd._status_of(None, _Err(403)) == 403
    assert rd._status_of(_BadStatus(), Exception("got HTTP 429 back")) == 429
    assert rd._status_of(None, Exception("no number")) == 0


def test_readiness_reads_a_body_from_models_and_lists():
    """ASVS V7.4.1 · CWE-755: an SDK model or a list of models becomes plain data; a model that cannot convert is no body."""
    assert rd._body_of(_BadStatus(), [_Model({"a": 1}), 2]) == [{"a": 1}, 2]
    assert rd._body_of(None, _Model({"b": 2})) == {"b": 2}
    assert rd._body_of(None, _Model({}, fail=True)) is None and rd._body_of(None, "x") == "x"


@pytest.mark.parametrize("fn,state", [(lambda: "not a tuple", "error"), (lambda: (_ for _ in ()).throw(_Err(401)), "denied"),
                                      (lambda: (_ for _ in ()).throw(ValueError("x")), "error"), (lambda: (None, _Resp(None, 404), _Err(404)), "missing")])
def test_one_sdk_call_is_a_state_never_a_crash(fn, state):
    """ASVS V7.4.1 · CWE-755 · CWE-209: an SDK call that raises, refuses, is missing or answers oddly is a state; no error text is kept."""
    out = rd._ask(fn)

    assert out["state"] == state and out["body"] is None


def test_readiness_uses_the_classic_sign_ins_executor():
    """ASVS V1.14.1 · CWE-1287: without get_request_executor (the classic sign-in), the ZIA helper's executor is used."""
    ex = object()

    assert rd._executor(types.SimpleNamespace(zia=types.SimpleNamespace(request_executor=ex))) is ex


@pytest.mark.parametrize("state,words", [("denied", "refused (HTTP 403)"), ("missing", "not available"), ("no_role", "names no ZIA role"),
                                         ("not_found", "not in the role list"), ("error", "no usable answer (HTTP 403)")])
def test_readiness_state_words_oracle(state, words):
    """WCAG 2.2 SC 3.3.1 · CWE-1059: each read state is said in plain words with its HTTP status."""
    assert words in rd._state_words({"state": state, "code": 403})


def test_readiness_resolves_the_zia_role_by_name_when_the_id_read_fails():
    """ASVS V1.4.4 · CWE-1287: when the token's role id cannot be read, the role is found by name in the role list and read by its id."""
    client = _client(ROLES["full"], ALL_SKUS)
    calls = []
    good = client.zia.admin_roles.get_role
    client.zia.admin_roles.get_role = lambda rid: calls.append(rid) or ((None, _Resp(None, 404), _Err(404)) if len(calls) == 1 else good(rid))

    zia = rd.read(client, ["dlp"], now=NOW)["probes"]["ZIA"]

    assert calls == [4711, 4711] and zia["role_state"] == "ok"


def test_readiness_says_when_the_tokens_role_is_not_in_the_list():
    """ASVS V1.4.4 · CWE-1059: a token whose ZIA role has no id and is not in the role list is "not found", said in words."""
    client = _client(ROLES["full"], ALL_SKUS)
    client._auth_token = _jwt([{"prd": "ZIA", "ext": {"rnm": "Missing role"}}])

    zia = rd.read(client, ["dlp"], now=NOW)["probes"]["ZIA"]
    product = {p["product"]: p for p in rd.evaluate({"claims": rd.token_access(client), "probes": {"ZIA": zia}, "in_scope": ["ZIA"]})["products"]}["ZIA"]

    assert zia["role_state"] == "not_found" and product["access"] == "read" and "could not be read" in product["why"]


@pytest.mark.parametrize("probe,access", [
    ({"responds": False, "state": "classic"}, "none"), ({"responds": False, "state": "no_customer_id"}, "unknown"),
    ({"responds": False, "state": "denied", "code": 401}, "none"), ({"responds": False, "state": "error", "code": 500}, "unknown"),
    ({"responds": True, "state": "ok", "classes": {"Application Segment": "FULL"}}, "write"), ({"responds": True, "state": "ok", "classes": {}}, "read"),
])
def test_zpa_product_access_oracle(probe, access):
    """ASVS V1.4.4 · CWE-284 · CWE-1059: ZPA's access follows its probe: classic, no customer id, refused, no answer, full classes or a plain read."""
    facts = {"claims": {"ok": True, "products_listed": False, "products": [{"product": "ZPA", "role": "Viewer", "role_id": ""}]},
             "probes": {"ZPA": probe}, "in_scope": ["ZPA"]}

    assert rd._product_state("ZPA", facts)["access"] == access


def test_zia_refusing_every_read_is_no_access_with_steps():
    """ASVS V1.4.4 · CWE-284: ZIA refusing both the licences and the role is no access, with the steps to add a role."""
    facts = {"claims": {"ok": False, "products": []}, "probes": {"ZIA": {"responds": False, "role_state": "denied", "subscriptions_state": "denied"}}, "in_scope": ["ZIA"]}

    out = rd._product_state("ZIA", facts)

    assert out["access"] == "none" and out["steps"]


def test_ai_guard_probe_answers_every_shape_safely(monkeypatch):
    """ASVS V7.4.1 · CWE-755 · CWE-20: AI Guard's readiness that is missing, not callable, raising 403, or odd is a safe state; the classic sign-in has none."""
    def mod(fn):
        return types.SimpleNamespace(readiness=fn)
    monkeypatch.setitem(sys.modules, "ai_guard", mod("not callable"))
    a = rd.ai_guard_probe(None)
    monkeypatch.setitem(sys.modules, "ai_guard", mod(lambda c, **k: (_ for _ in ()).throw(_Err(403))))
    b = rd.ai_guard_probe(None)
    monkeypatch.setitem(sys.modules, "ai_guard", mod(lambda c, **k: {"ok": True, "state": "<b>x</b>", "detail": "\x00fine"}))
    c = rd.ai_guard_probe(None)

    assert a["state"] == "not_checked" and b["state"] == "denied" and c == {"responds": True, "state": "ok", "detail": "fine"}
    assert rd.ai_guard_probe(None, legacy=True)["state"] == "classic"


def test_a_write_feature_with_no_writable_policy_takes_the_mildest_reason():
    """ASVS V1.4.4 · CWE-1059: Bulk changes acts per policy; when none is writable it reports the mildest status with its reason."""
    client = _client(ROLES["read"], ALL_SKUS)

    writes = {f["key"]: f for f in rd.evaluate(rd.read(client, ["dlp"], now=NOW))["writes"]}

    assert writes["bulk_changes"]["status"] == "read_only" and writes["bulk_changes"]["why"].startswith("None of the policies")


def test_readiness_run_finishes_or_stops_with_no_partial_result(monkeypatch):
    """ASVS V11.1.7 · CWE-400: a finished check is stamped with the injected time; Stop gives no partial result."""
    import data_flow
    done = rd.run(_client(ROLES["full"], ALL_SKUS), ["dlp"], now=NOW, label="acme")
    monkeypatch.setattr(data_flow, "stop_requested", lambda cancel: True)
    stopped = rd.run(_client(ROLES["full"], ALL_SKUS), ["dlp"], now=NOW, label="acme")

    assert done["status"] == "done" and done["checked_at"] == "2027-01-15T08:00:00Z" and stopped == {"status": "stopped", "tenant_label": "acme"}


def test_the_readiness_catalogue_covers_every_scope_write_kind_and_feature():
    """ASVS V1.4.4 · CWE-1059: the static catalogue lists every Scope page key, write kind and write feature with what it needs."""
    cat = rd.catalog()

    assert {s["key"] for s in cat["scopes"]} == set(rd.SCOPE_FEATURES) and {k["kind"] for k in cat["write_kinds"]} == set(rd.WRITE_KINDS)
    assert {w["key"] for w in cat["writes"]} == set(rd.WRITE_FEATURES)
    assert {k["kind"]: k["note"] for k in cat["write_kinds"]}["email"].startswith("No separate permission")


@pytest.mark.parametrize("licences,text", [({"read": True, "rows": []}, "empty licence list"), ({"read": False, "state": "denied"}, "refused to list"),
                                           ({"read": False, "state": "not_in_scope"}, "not in scope"), ({"read": False, "state": "error"}, "could not be read")])
def test_the_readiness_page_says_why_there_are_no_licences(licences, text):
    """WCAG 2.2 SC 3.3.2 · CWE-1059: an empty, refused, out-of-scope or unreadable licence list is explained, not left blank."""
    html = rd.html_section([{"products": [], "licences": licences, "scopes": [], "writes": [], "token": {"ok": True}}])

    assert text in html and "No product was in the token" in html


def test_the_readiness_page_hides_live_answers_from_a_locked_browser():
    """ASVS V4.1.1 · CWE-200 · CWE-284: without the UI token or sign-in the live block names no tenant, role or licence."""
    html = rd.html_section([{"tenant_label": "Acme Secret Tenant"}], locked=True)

    assert "Acme Secret Tenant" not in html and "UI token" in html and rd.scope_badge(None) == ""


# ── Branch coverage: Beacon's map builder ────────────────────────────────

def test_the_map_builder_survives_code_it_cannot_load(monkeypatch):
    """ASVS V7.4.1 · CWE-755: a registry module that does not import, a partial, and an import that fails read nothing; nothing raises."""
    import functools
    monkeypatch.setattr(sys, "path", list(sys.path))   # _registry may add ROOT: never to the real path
    monkeypatch.setattr(bs, "ROOT", "/nonexistent-c6")

    assert bs._registry("no_such_module_c6", "REG") == []
    assert bs._unwrap(functools.partial(functools.partial(_cycle_a))) is _cycle_a
    import ast
    assert bs._local_imports(ast.parse("import no_such_module_c6\nfrom no_such_module_c6 import x\nimport os.path as p")) == {"p": os.path}
    assert bs._parse(len) is None and bs._called(len) == []


def test_an_endpoint_no_check_reads_is_unmapped_and_never_read():
    """ASVS V4.1.3 · CWE-863: an endpoint only a feature module reads is listed as unmapped, never read by the watch."""
    sel = bs.select(["dlp"], {"web_dlp": "zscaler"}, endpoints={"/zia/onlyAFeatureReadsThis": ["x.py"], "/zia/webDlpRules": ["y.py"]})

    assert sel["unmapped"] == ["/zia/onlyAFeatureReadsThis"] and list(sel["endpoints"]) == ["/zia/webDlpRules"]


# ── C6-SCOPE-OFFLINE-15: Traffic flow reads the API's app-profile field names ──

def _flow_profiles(monkeypatch, profiles):
    import data_flow
    monkeypatch.setattr(data_flow, "read_app_profiles", lambda get, cancel=None: (profiles, [], {}))
    out = data_flow.read_client_connector(types.SimpleNamespace(get=lambda *a, **k: ([], 200)))
    return {p["name"]: p for p in out["app_profiles"]}


def test_the_sample_tenant_app_profiles_show_endpoint_dlp_certificate_and_app_bypass():
    """ASVS V5.1.3 · CWE-1287 · WSTG-BUSL-01: on the API-shaped sample tenant, Install Endpoint DLP, the SSL certificate and the custom app bypass are read, not shown as off or dropped."""
    # Arrange
    import data_flow
    cl = ot.OfflineRawClient(ot.sample_store(), {})
    # Act
    prof = {p["name"]: p for p in data_flow.read_client_connector(cl)["app_profiles"]}
    # Assert
    assert prof["Windows - Corporate"]["endpoint_dlp"] is True and prof["Windows - Contractors"]["endpoint_dlp"] is False
    assert prof["Windows - Corporate"]["ssl_cert"] is True and prof["macOS - Corporate"]["ssl_cert"] is True
    assert prof["Windows - Contractors"]["bypass"]["apps"] == ["5001"]
    assert prof["Windows - Contractors"]["tunnel"]["exclude"] == ["10.0.0.0/8", "192.0.2.0/24"]


@pytest.mark.parametrize("profile,field,expected", [
    ({"policyExtension": {"enableZdpService": "1"}}, "endpoint_dlp", True),
    ({"policyExtension": '{"enableZdpService": 1}'}, "endpoint_dlp", True),        # the extension as a JSON string
    ({"policyExtension": {"enableZdpService": "0"}}, "endpoint_dlp", False),       # boundary: "0" is off
    ({"installEndpointDlp": True}, "endpoint_dlp", True),                          # an older export still reads
    ({"windowsPolicy": {"install_ssl_certs": 1}}, "ssl_cert", True),
    ({"linuxPolicy": {"installCerts": 1}}, "ssl_cert", True),
    ({"windowsPolicy": {"install_ssl_certs": 0}}, "ssl_cert", False),
    ({}, "ssl_cert", False),                                                       # nothing said is not "on"
])
def test_an_api_shaped_app_profile_is_read_by_its_api_names(monkeypatch, profile, field, expected):
    """ASVS V5.1.3 · CWE-1287 · WSTG-BUSL-01: each switch is read from the name zscaler-sdk-python's WebPolicy model gives it, older names still read."""
    # Arrange
    p = dict({"id": 1, "name": "P", "device_type": 3, "active": 1}, **profile)
    # Act
    got = _flow_profiles(monkeypatch, [p])["P"]
    # Assert
    assert got[field] is expected


def test_custom_and_predefined_app_bypasses_are_both_counted(monkeypatch):
    """ASVS V5.1.3 · CWE-1287 · WSTG-BUSL-01: bypassCustomAppIds and bypassAppIds both land in the app bypasses."""
    # Arrange
    p = {"id": 1, "name": "P", "device_type": 3, "active": 1, "bypassCustomAppIds": ["c1"], "bypassAppIds": ["a1", "a2"]}
    # Act
    apps = _flow_profiles(monkeypatch, [p])["P"]["bypass"]["apps"]
    # Assert
    assert sorted(apps) == ["a1", "a2", "c1"]
