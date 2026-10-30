"""Client Connector tamper passwords in the profile builder (ops_zcc).

The admin types the uninstall, turn-off and log-out passwords; they are
sent beside the operation for its preview and apply, written once in the
create call and kept nowhere. Every sink is searched for every encoding of
the canary passwords (tests/test_secret_canaries.py's _leaks): the plan,
its hash input and PDF, the job result and log, the record, the audit log,
the error texts and the page's script. FakeSdk (tests/test_ops_zcc.py)
stands in for the SDK; nothing touches the network."""
from __future__ import annotations

import json
import os
import re
import time

import pytest

import admin_ops as ao
import ops_zcc as oz
from test_ops_zcc import ASSESSOR, ZCC_SCOPE, FakeSdk, Resp, spec
from test_secret_canaries import _leaks

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = {"uninstall": 'CANARYun7Qx+/=&"\\9', "disable": "CANARYdis4Lm+/=%2", "logout": "CANARYlogout55"}
CANARIES = list(PW.values())
SALT = "ab" * 16


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    import pack_ops
    monkeypatch.setattr(pack_ops, "_sleep", lambda s: None, raising=False)
    ao.load_plugins()


def tspec(platform="windows", kinds=("uninstall", "disable", "logout"), **kw):
    s = spec(platform=platform, **kw)
    s["app"] = {"template": "best_practice", "name": f"QA {platform}", "tamper": {"set": list(kinds), "salt": SALT}}
    return s


def plan(sdk, s, pw=PW):
    with oz.passwords_in_flight(pw):
        return ao.plan(sdk, s, scope=ZCC_SCOPE, tenant_label="acme")


def apply(sdk, s, p, pw=PW):
    with oz.passwords_in_flight(pw):
        return ao.execute(sdk, s, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"],
                          assessor=ASSESSOR, tenant_label="acme", settle_seconds=0)


def sent_app(sdk):
    return [b for k, b in sdk.sent if k == "app"]


# ── Preview: "set (hidden)", a salted digest only, the Undo note ─────
def test_the_preview_shows_set_hidden_and_carries_no_password():
    """ASVS V8.3.4 · CWE-312 · CWE-200: the preview names each password as "set (hidden)"; no form of a typed password is in the plan."""
    p = plan(FakeSdk(), tspec())
    rows = [u for u in p["items"] if u["key"].startswith("app:tamper_")]
    assert [(u["field"], u["before"], u["after"], u["status"]) for u in rows] == [
        ("Uninstall password", "not set", "set (hidden)", "change"), ("Turn off Internet security password", "not set", "set (hidden)", "change"),
        ("Log out password", "not set", "set (hidden)", "change")]
    assert not _leaks(json.dumps(p), CANARIES)
    g = next(g for g in p["groups"] if g["key"] == "g_app")
    assert set(g["target"]["tamper"]["digest"]) == {"uninstall", "disable", "logout"}

    def filled(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from filled(v, f"{path}.{k}")
        elif re.search(r"pass(word)?$", path, re.I) and isinstance(node, str) and node:
            yield path
    assert list(filled(g["target"]["body"])) == [], "the planned body holds no password"


def test_the_preview_says_undo_cannot_restore_a_password():
    """ASVS V1.4.1 · CWE-1059: the preview says Undo deletes the profiles but cannot restore a password, because none is kept."""
    p = plan(FakeSdk(), tspec())
    assert any("Undo" in n and "cannot restore a password" in n and "none is ever kept" in n for n in p["notes"])
    assert not any("Undo" in n and "restore a password" in n for n in plan(FakeSdk(), spec())["notes"])


def test_the_plan_hash_covers_a_salted_digest_so_another_password_at_apply_writes_nothing():
    """ASVS V11.1.1 · CWE-841 · CWE-345: a password typed differently at apply changes the plan hash; the tenant is not written."""
    sdk = FakeSdk()
    p = plan(sdk, tspec())
    assert plan(FakeSdk(), tspec())["plan_hash"] == p["plan_hash"], "the same passwords give the same plan"
    assert plan(FakeSdk(), tspec(), dict(PW, logout="CANARYother1"))["plan_hash"] != p["plan_hash"]
    other = tspec()
    other["app"]["tamper"]["salt"] = "cd" * 16
    assert plan(FakeSdk(), other)["plan_hash"] != p["plan_hash"], "the salt is part of the digest"
    res = apply(sdk, tspec(), p, dict(PW, uninstall="CANARYwrong77"))
    assert res["status"] == "plan_changed" and sdk.writes() == []


def test_a_password_not_typed_again_refuses_before_anything_is_read():
    """ASVS V4.1.3 · CWE-841: a preview or apply without the passwords typed is refused in words, before any read; no value is echoed."""
    sdk = FakeSdk()
    with pytest.raises(oz.BuilderError, match="Type the log out password again"):
        plan(sdk, tspec(), {k: v for k, v in PW.items() if k != "logout"})
    assert sdk.calls == []
    p = plan(FakeSdk(), tspec())
    with pytest.raises(oz.BuilderError, match="again"):   # the route answers it as a refusal (400)
        apply(sdk, tspec(), p, {})
    assert sdk.writes() == []


# ── Apply: sent once, read back as set, masked in every error ─────────
@pytest.mark.parametrize("platform,keys", [("windows", ("uninstall_password", "disable_password", "logout_password")),
                                           ("macos", ("uninstallPassword", "disablePassword", "logoutPassword"))])
def test_apply_sends_each_password_once_in_the_create_call_and_reads_it_back_as_set(platform, keys):
    """ASVS V8.3.4 · V11.1.1 · CWE-256: each password is in the one create call (the SDK's platform policy fields) and confirmed "set" without its value."""
    sdk = FakeSdk()
    s = tspec(platform)
    p = plan(sdk, s)
    res = apply(sdk, s, p)
    assert res["status"] == "applied", res.get("verification")
    (body,) = sent_app(sdk)
    pol = body[oz.PLATFORMS[platform]["policy_key"]]
    assert [pol[k] for k in keys] == [PW["uninstall"], PW["disable"], PW["logout"]]
    assert sum(json.dumps(b).count("CANARYlogout55") for _k, b in sdk.sent) == (2 if platform == "macos" else 1)   # macOS: both spellings
    rows = [u for u in res["items"] if u["key"].startswith("app:tamper_")]
    assert all(u["verified"] is True and u["after"] == "set (hidden)" for u in rows)
    assert not _leaks(json.dumps(res), CANARIES)


def test_a_read_back_without_the_field_cannot_confirm_it_and_says_so():
    """ASVS V7.4.1 · CWE-754: a read-back that does not return the password field is "could not be confirmed", never "set"."""
    sdk = FakeSdk()
    orig = sdk.zcc.web_policy.list_by_company

    def hide(query_params=None):
        rows, resp, err = orig(query_params=query_params)
        for r in rows:
            r.get("windowsPolicy", {}).pop("uninstall_password", None)
        return rows, Resp(rows), err
    sdk.zcc.web_policy.list_by_company = hide
    s = tspec(kinds=("uninstall",))
    res = apply(sdk, s, plan(sdk, s))
    u = next(u for u in res["items"] if u["key"] == "app:tamper_uninstall")
    assert u["verified"] is None and "could not be confirmed" in u["reason"] and res["verification"]["unread"]
    assert oz.tamper_state({"windowsPolicy": {"uninstall_password": ""}}, "windows", "uninstall") is False
    assert oz.tamper_state({"windowsPolicy": {"uninstall_password": "x"}}, "windows", "uninstall") is True


@pytest.mark.parametrize("how", ["error", "exception", "rejected"])
def test_an_error_that_echoes_the_body_is_masked_everywhere(how, tmp_path):
    """ASVS V7.1.1 · V8.3.4 · CWE-209 · CWE-532: a refusal or exception that quotes the request body shows no form of a password in the result, the log or the audit log."""
    sdk = FakeSdk()
    orig = sdk.zcc.web_policy.web_policy_edit

    def echo(**kw):
        orig(**kw)
        text = "HTTP 400 bad body: " + json.dumps(kw["windowsPolicy"]) + " " + json.dumps(kw)
        if how == "exception":
            raise RuntimeError(text)
        if how == "rejected":
            return None, Resp({"success": "false", "errorMessage": text}), None
        return None, None, text
    sdk.zcc.web_policy.web_policy_edit = echo
    s = tspec()
    logs = []
    p = plan(sdk, s)
    with oz.passwords_in_flight(PW):
        res = ao.execute(sdk, s, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"],
                         assessor=ASSESSOR, tenant_label="acme", settle_seconds=0, log=logs.append)
    failed = next(u for u in res["items"] if u["key"] == "app")
    assert failed["status"] == "failed" and "********" in failed["error"]
    rec = ao.record(res, by=ASSESSOR)
    sinks = [json.dumps(res), "\n".join(logs), (tmp_path / "audit.log").read_text(), json.dumps(rec)]
    assert not _leaks("\n".join(sinks), CANARIES)


def test_the_record_and_its_undo_hold_no_password(tmp_path):
    """ASVS V8.3.4 · CWE-312 · CWE-532: the recorded operation, its inverse and the audit log hold no form of a password; Undo is the profile delete."""
    sdk = FakeSdk()
    s = tspec()
    res = apply(sdk, s, plan(sdk, s))
    rec = ao.record(res, by=ASSESSOR)
    assert rec["inverse"]["type"] == oz.DELETE and "tamper" in json.dumps(rec["spec"])
    files = (tmp_path / "deployments.json").read_text() + (tmp_path / "audit.log").read_text()
    assert not _leaks(files, CANARIES) and "set (hidden)" in files


def test_the_plan_pdf_holds_no_password():
    """ASVS V8.3.4 · CWE-312: the printable plan shows "set (hidden)" and no form of a password."""
    import report_exports
    pdf = report_exports.operation_pdf(plan(FakeSdk(), tspec()))
    assert pdf.startswith(b"%PDF-") and not _leaks(pdf.decode("latin-1"), CANARIES)


# ── Validation ───────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,error", [
    ({"exit_password": "x"}, "Only the uninstall"),
    ({"uninstall_password": "x" * 129}, "at most 128"),
    ({"uninstall_password": "CANARYa\nb"}, "control character"),
    ({"uninstall_password": "   "}, "only spaces"),
    ("CANARYstring", "fields of tamper_passwords"),
])
def test_passwords_are_validated_without_echoing_them(raw, error):
    """ASVS V5.1.3 · CWE-20 · CWE-209: an unknown field, an oversized value or a control character is refused in words that never repeat the value."""
    with pytest.raises(oz.BuilderError) as e:
        oz.check_passwords(raw)
    assert error in str(e.value) and "CANARY" not in str(e.value)


@pytest.mark.parametrize("tamper,error", [({"set": ["exit"], "salt": SALT}, "uninstall, turn-off"), ({"set": ["uninstall"]}, "salt is missing"),
                                          ({"set": ["uninstall"], "salt": "zz"}, "salt is missing"), ("x", "uninstall, turn-off")])
def test_the_spec_names_only_known_passwords_and_a_salt(tamper, error):
    """ASVS V5.1.3 · CWE-20: the spec's tamper part names known passwords and a hex salt, nothing else."""
    s = spec()
    s["app"] = {"template": "best_practice", "name": "QA", "tamper": tamper}
    with pytest.raises(oz.BuilderError, match=error):
        oz.normalize_spec(s)


# ── Routes: every sink of a real preview and apply ────────────────────
@pytest.fixture
def api(monkeypatch, tmp_path):
    for k in [k for k in os.environ if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    import dlp_api_server as srv
    sdk = FakeSdk()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or sdk)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    from fastapi.testclient import TestClient
    return TestClient(srv.app), sdk, built


BODY = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "not-a-real-secret", "scopes": ["zcc"], "channels": {},
        "from_page": True, "assessor": ASSESSOR}
FIELDS = {f"{k}_password": v for k, v in PW.items()}


def _job(c, jid):
    for _ in range(400):
        snap = c.get(f"/api/dlp-packs/jobs/{jid}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.02)
    raise AssertionError("the job did not finish")


def test_preview_and_apply_through_the_routes_leave_no_password_in_any_sink(api, tmp_path, capsys):
    """ASVS V8.3.4 · V7.1.1 · CWE-312 · CWE-532 · WSTG-ATHN-06: a preview and an apply with typed passwords: none reaches the job result, job log, plan PDF, approval request, record, audit log or console."""
    c, sdk, _built = api
    s = tspec()
    r = c.post("/api/operations/preview/start", json=dict(BODY, operation=s, tamper_passwords=FIELDS))
    assert r.status_code == 200, r.text
    jid = r.json()["job_id"]
    prev = _job(c, jid)
    assert prev["status"] == "done" and prev["result"]["status"] == "ready", prev
    texts = [r.text, json.dumps(prev), c.get(f"/api/operations/jobs/{jid}/plan.pdf").content.decode("latin-1"),
             c.get(f"/api/operations/jobs/{jid}/request").text]
    body = dict(BODY, operation=s, plan_hash=prev["result"]["plan_hash"], confirm=True, confirm_text=prev["result"]["confirm_phrase"],
                tamper_passwords=FIELDS)
    r = c.post("/api/operations/apply/start", json=body)
    assert r.status_code == 200, r.text
    done = _job(c, r.json()["job_id"])
    assert done["result"]["status"] == "applied", done
    assert sent_app(sdk)[0]["windowsPolicy"]["uninstall_password"] == PW["uninstall"]
    texts += [r.text, json.dumps(done), c.get("/api/operations").text, c.get(f"/api/operations/{done['result']['operation_id']}").text,
              (tmp_path / "audit.log").read_text() if (tmp_path / "audit.log").exists() else "",
              open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read(), open(os.environ["DLP_CHECK_DEPLOYMENTS"], encoding="utf-8").read()]
    out = capsys.readouterr()
    texts += [out.out, out.err]
    assert not _leaks("\n".join(texts), CANARIES)


def test_the_apply_needs_the_passwords_typed_again(api):
    """ASVS V4.1.3 · CWE-841: an apply without the passwords typed again writes nothing."""
    c, sdk, _built = api
    s = tspec()
    prev = c.post("/api/operations/preview", json=dict(BODY, operation=s, tamper_passwords=FIELDS)).json()
    r = c.post("/api/operations/apply", json=dict(BODY, operation=s, plan_hash=prev["plan_hash"], confirm=True, confirm_text=prev["confirm_phrase"]))
    assert r.status_code == 400 and "again" in r.json()["detail"] and sdk.writes() == []


def test_passwords_are_refused_with_another_operation_before_sign_in(api):
    """ASVS V4.1.3 · CWE-200 · WSTG-INPV-01: passwords sent with any other operation are refused before sign-in, without the value."""
    c, _sdk, built = api
    op = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 1}]}
    r = c.post("/api/operations/preview", json=dict(BODY, scopes=["zcc", "zia_extras", "dlp"], operation=op, tamper_passwords=FIELDS))
    assert r.status_code == 400 and "only by the Client Connector profile builder" in r.text and built == [] and not _leaks(r.text, CANARIES)
    r = c.post("/api/operations/preview", json=dict(BODY, operation=tspec(), tamper_passwords={"uninstall_password": "CANARYx\x00y"}))
    assert r.status_code == 400 and built == [] and "CANARY" not in r.text


def test_out_of_scope_is_refused_before_the_passwords_are_looked_at(api):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: with ZCC not ticked the build is refused before sign-in, whatever passwords are sent."""
    c, _sdk, built = api
    r = c.post("/api/operations/preview", json=dict(BODY, scopes=["dlp"], channels={"web_dlp": "zscaler"}, operation=tspec(), tamper_passwords=FIELDS))
    assert r.status_code == 400 and built == [] and not _leaks(r.text, CANARIES)


def test_a_validation_error_never_echoes_a_password(api):
    """ASVS V7.1.1 · CWE-209 · WSTG-ERRH-01: a malformed passwords field answers 422 with where and why only, never the value."""
    c, _sdk, built = api
    r = c.post("/api/operations/preview", json=dict(BODY, operation=tspec(), tamper_passwords={"uninstall_password": ["CANARYlist99"]}))
    assert r.status_code == 422 and "CANARY" not in r.text and built == []


def test_the_page_keeps_passwords_out_of_the_spec_and_the_browser_storage():
    """ASVS V8.2.2 · CWE-922 · CWE-312 · WCAG 2.2 SC 1.3.5: the builder's password fields are new-password inputs; their values go beside the operation, never into it or storage."""
    js = open(os.path.join(ROOT, "static", "ops_zcc.js"), encoding="utf-8").read()
    page = open(os.path.join(ROOT, "static", "report_operations.html"), encoding="utf-8").read()
    assert 'type="password"' in js and 'autocomplete="new-password"' in js
    assert not re.search(r"localStorage|sessionStorage|indexedDB", js)
    assert "tamper_passwords" in js and "app.tamper = { set, salt: z.salt }" in js
    assert "plugSecrets(spec.type)" in page and "S.spec = (snap.extra && snap.extra.operation) || payload.operation" in page
    # The value is set as a property, never written into the page's HTML.
    assert not re.search(r"value=\"\$\{[^}]*pw", js)
