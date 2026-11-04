"""Client Connector and ZDX: profile writes, the install command builder,
ZDX probe setup, fleet health and the strict evaluation (ops_zcc, ops_zdx,
zcc_fleet, zcc_evaluation, zcc_profiles), tested for regression, Secure by
Design and function.

No tenant, no network, no clock, no sleep: the fakes of test_ops_zcc and
test_ops_zdx stand in for the SDK's zcc services and the ZDX configuration
API's request executor; time is passed in; files live in tmp_path."""
from __future__ import annotations

import csv
import io
import logging
import threading
import unicodedata
from datetime import datetime, timedelta, timezone

import pytest
from conftest import read_store_text

import admin_ops as ao
import ops_zcc as oz
import ops_zdx as zx
import pack_ops as ops
import zcc_evaluation as ze
import zcc_fleet as zf
import zcc_profiles as zp
from test_ops_zcc import CREDS, ZCC_PAGE, FakeSdk, Resp
from test_ops_zcc import build as zcc_build
from test_ops_zdx import BEST, ApiError, FakeZdx, client_for
from test_ops_zdx import apply as zdx_apply
from test_ops_zdx import preview as zdx_preview

ZCC_SCOPE = ao.scope_for(["zcc"], {})
ZDX_SCOPE = ao.scope_for(["zdx"], {})
NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
TOKEN = "CANARYpolicyToken42"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ops, "_sleep", lambda s: None, raising=False)
    ao.load_plugins()


@pytest.fixture
def zdx():
    fake = FakeZdx()
    fake.cols = [{"id": 1, "name": "Custom Apps Collection"}, {"id": 2, "name": "Predefined Apps Collection"}]
    return fake, client_for(fake)


def _win(installer, values, **kw):
    return oz.install_commands("windows", installer, values, now=NOW, **kw)


# ═══ Install command builder (ops_zcc.install_commands) ═══════════════════

@pytest.mark.parametrize("installer", ["msi", "exe"])
@pytest.mark.parametrize("value", ["acme;calc.exe", "acme,corp", "o'brien", "@acme", "acme#x", "{acme}", "acme(1)", "a b"])
def test_windows_values_with_shell_metacharacters_are_double_quoted(installer, value):
    """ASVS V5.3.8 · A03:2021 · CWE-78 · WSTG-INPV-12: a value holding a cmd.exe or PowerShell metacharacter is passed only inside double quotes."""
    out = _win(installer, {"userDomain": value})
    assert out["errors"] == []
    assert f'"{value}"' in out["command"]
    assert f"{value}\"" in out["command"] and f"={value}" not in out["command"] and f" {value}" not in out["command"]


def test_a_tenant_policy_token_with_a_semicolon_cannot_start_a_second_powershell_statement():
    """ASVS V5.3.8 · A03:2021 · CWE-78 · WSTG-INPV-12: the policy token read from the tenant is untrusted; a ; in it stays inside the quoted argument."""
    out = _win("exe", {"policyToken": "abc;Start-Process calc"}, reveal=True)
    assert '--policyToken "abc;Start-Process calc"' in out["command"]


@pytest.mark.parametrize("quote", ["”", "“", "’", "‘", "„", "‟"])
def test_typographic_quotes_that_powershell_closes_a_string_on_are_refused(quote):
    """ASVS V5.3.8 · A03:2021 · CWE-78 · WSTG-INPV-12: PowerShell reads U+2018-U+201F as quotes, so a value holding one is refused, not passed."""
    out = _win("msi", {"userDomain": f"x{quote};calc;{quote}"})
    assert out["errors"] and "typographic" in out["errors"][0]
    assert "calc" not in out["command"] and "calc" not in out["script"]


@pytest.mark.parametrize("ch", ["\t", "\x1b", " ", " ", "​", "\x7f"])
def test_control_format_and_separator_characters_are_refused(ch):
    """ASVS V5.1.4 · A03:2021 · CWE-150 · WSTG-INPV-12: tabs, escapes, line and paragraph separators and zero-width characters never reach a command."""
    out = _win("msi", {"userName": f"jdoe{ch}x", "userDomain": "acme.com"})
    assert out["errors"] and unicodedata.category(ch) in oz._UNSAFE_CATEGORIES
    assert "jdoe" not in out["command"]


@pytest.mark.parametrize("raw", [["a"], {"a": 1}, 1.5, b"acme"])
def test_a_value_that_is_not_text_is_refused_in_words(raw):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-12: a list, object, float or bytes value is refused with a plain reason, never str()-ed into the command."""
    out = _win("msi", {"userDomain": raw})
    assert out["errors"] == ["User domain: give it as text."] and "USERDOMAIN" not in out["command"]


def test_plain_values_stay_bare_so_the_command_shape_is_unchanged():
    """ASVS V14.2.1 · CWE-1357 · WSTG-INPV-12: values with only letters, digits and . _ - \\ / : stay unquoted, as earlier versions printed them."""
    out = _win("msi", {"cloudName": "zscalertwo", "userDomain": "acme.com", "policyToken": TOKEN})
    assert out["command"] == 'msiexec /i Zscaler-windows-installer-x64.msi /qn /L*V "%TEMP%\\ZCC_Install.log" CLOUDNAME=zscalertwo USERDOMAIN=acme.com POLICYTOKEN=********'


def test_a_unicode_user_name_is_accepted_and_quoted():
    """ASVS V5.1.4 · CWE-176 · WSTG-INPV-12: a user name in another script is allowed, and quoted on Windows."""
    out = _win("msi", {"userName": "josé", "userDomain": "acme.com"})
    assert out["errors"] == [] and 'UNAME="josé"' in out["command"]


@pytest.mark.parametrize("n, ok", [(256, True), (257, False)])
def test_a_value_is_capped_at_256_characters(n, ok):
    """ASVS V5.1.4 · CWE-400 · WSTG-INPV-12: 256 characters pass and 257 are refused."""
    out = _win("msi", {"userDomain": "a" * n})
    assert (out["errors"] == []) is ok


def test_macos_values_are_single_quoted_with_an_embedded_quote_escaped():
    """ASVS V5.3.8 · A03:2021 · CWE-78 · WSTG-INPV-12: on macOS every value is single-quoted for /bin/sh, an embedded ' closed and escaped."""
    out = oz.install_commands("macos", "app", {"userName": "o'brien; rm -rf ~", "userDomain": "acme.com"}, now=NOW)
    assert "--userName 'o'\\''brien; rm -rf ~'" in out["command"] and "--userName 'o'\\''brien; rm -rf ~'" in out["script"]


@pytest.mark.parametrize("platform, installer", [("windows", "msi"), ("windows", "exe"), ("macos", "app")])
def test_command_script_and_parameters_hold_no_secret_unless_revealed(platform, installer):
    """ASVS V8.3.4 · A02:2021 · CWE-200 · WSTG-INFO-05: the token and the uninstall password are masked in the command, the script and the parameter list."""
    out = oz.install_commands(platform, installer, {"policyToken": TOKEN, "uninstallPassword": "CANARYpw", "deviceToken": "CANARYdev"}, now=NOW)
    assert "CANARY" not in repr(out) and out["masked"] and not out["revealed"]
    assert "masked" in out["script"]


def test_the_install_route_never_logs_the_policy_token(monkeypatch, tmp_path, caplog):
    """ASVS V7.1.1 · A09:2021 · CWE-532 · WSTG-INFO-05: reading the token for a revealed command leaves no form of it in the Python log or the audit log."""
    for k in [k for k in list(__import__("os").environ) if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    import dlp_api_server as srv
    sdk = FakeSdk()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: sdk)
    from fastapi.testclient import TestClient
    caplog.set_level(logging.DEBUG)
    body = dict(CREDS, **ZCC_PAGE, app_profile_id="21", platform="windows", installer="exe", reveal=True, values={})
    r = TestClient(srv.app).post("/api/zcc/install", json=body)
    assert r.status_code == 200 and TOKEN in r.json()["command"]
    assert TOKEN not in caplog.text
    audit = tmp_path / "audit.log"
    assert not audit.exists() or TOKEN not in read_store_text(audit)


@pytest.mark.parametrize("ret, why", [
    (RuntimeError("boom CANARYsecret"), "could not be read (RuntimeError)"),
    ((None, None, "HTTP 403 forbidden"), "could not be read"),
    (({}, Resp({"id": 21}), None), "has no policy token"),
])
def test_the_policy_token_read_fails_in_plain_words_without_echoing_the_exception(ret, why):
    """ASVS V7.4.1 · A04:2021 · CWE-209 · WSTG-ERRH-01: a refused or empty token read answers a plain reason; an exception's text is not repeated."""
    class Svc:
        def get_application_profile(self, pid):
            if isinstance(ret, Exception):
                raise ret
            return ret
    sdk = type("S", (), {"zcc": type("Z", (), {"application_profiles": Svc()})()})()
    tok, msg = oz.policy_token(sdk, "21")
    assert tok is None and why in msg and "CANARY" not in msg


@pytest.mark.parametrize("pid", ["", "abc", "1/../2", "1" * 20, None])
def test_a_policy_token_is_read_only_for_a_numeric_profile_id(pid):
    """ASVS V5.1.3 · A01:2021 · CWE-22 · WSTG-INPV-12: an id that is not 1-19 digits is refused before any call."""
    sdk = FakeSdk()
    assert oz.policy_token(sdk, pid) == (None, "Pick the app profile.") and sdk.calls == []


# ═══ Profile writes (ops_zcc build / delete) ══════════════════════════════

def _secret_strings(obj, path=""):
    """(path, value) of every string under a key that names a password, passcode or token."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if zf.is_secret_key(k) and isinstance(v, str):
                out.append((p, v))
            out += _secret_strings(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _secret_strings(v, f"{path}[{i}]")
    return out


@pytest.mark.parametrize("platform", ["windows", "macos"])
@pytest.mark.parametrize("enable", [False, True])
def test_no_build_ever_carries_a_tamper_password(platform, enable):
    """ASVS V2.10.4 · A07:2021 · CWE-798 · WSTG-ATHN-07: with every setting ticked, every password and passcode field of both bodies is empty."""
    s = oz.normalize_spec({"platform": platform, "enable": enable,
                           "forwarding": {"template": "best_practice", "name": "QA fwd", "settings": list(oz.FWD_BY_KEY)},
                           "app": {"template": "best_practice", "name": "QA app", "settings": [x.key for x in oz.APP_SETTINGS[platform]]}})
    fwd, app = oz.build_bodies(s, rule_order=1, ctx={"app_ids": [1]})
    found = _secret_strings(fwd) + _secret_strings(app)
    assert len(found) >= 8 and all(v == "" for _p, v in found), [x for x in found if x[1]]


def test_a_spec_cannot_smuggle_a_password_or_an_unknown_setting():
    """ASVS V5.1.3 · A04:2021 · CWE-915 · WSTG-INPV-12: unknown fields are ignored and unknown setting keys refused, so no spec sets a password."""
    s = oz.normalize_spec({"platform": "windows", "app": {"name": "QA", "exit_password": "x", "settings": []},
                           "forwarding": {"name": "F"}, "uninstall_password": "x"})
    _f, app = oz.build_bodies(s, rule_order=1, ctx={})
    assert app["exit_password"] == "" and "uninstall_password" not in s
    with pytest.raises(oz.BuilderError, match="Unknown app profile settings"):
        oz.normalize_spec({"platform": "windows", "app": {"name": "QA", "settings": ["exitPassword"]}, "forwarding": {"name": "F"}})


@pytest.mark.parametrize("bad, needle", [
    (None, "missing"), ({"platform": "linux"}, "platform"),
    ({"platform": "windows", "forwarding": {"template": "x"}}, "forwarding profile"),
    ({"platform": "windows", "app": {"template": "x"}}, "app profile template"),
    ({"platform": "windows", "forwarding": {"template": "existing", "id": "12a"}, "app": {"name": "A"}}, "existing forwarding"),
    ({"platform": "windows", "forwarding": {"name": "F", "settings": "zia_tunnel"}, "app": {"name": "A"}}, "list of setting keys"),
])
def test_bad_build_specs_are_refused_in_words(bad, needle):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-12: every malformed build spec is refused with a plain sentence before any read."""
    with pytest.raises(oz.BuilderError, match=needle):
        oz.normalize_spec(bad)


@pytest.mark.parametrize("name, ok", [("a" * 64, True), ("a" * 65, False), ("  QA  ", True), ("-QA", False), ("QAé", False),
                                      ("QA\nX", False), ("QA;rm", False), ("QA (1).v2_x-y", True)])
def test_profile_names_boundaries(name, ok):
    """ASVS V5.1.4 · A03:2021 · CWE-20 · WSTG-INPV-12: names are 1-64 of letters, digits, spaces and . _ ( ) -, starting with a letter or digit."""
    if ok:
        assert oz.check_name(name, "app profile") == name.strip()
    else:
        with pytest.raises(oz.BuilderError):
            oz.check_name(name, "app profile")


@pytest.mark.parametrize("targets, needle", [
    ([], "Pick the profile"), ([{"kind": "app"}] * 3, "At most 2"), (["x"], "kind, id and name"),
    ([{"kind": "rule", "id": "1", "name": "x"}], "app profile or a forwarding"),
    ([{"kind": "forwarding", "id": "1 OR 1", "name": "x"}], "needs its id"),
    ([{"kind": "forwarding", "id": "1", "name": " "}], "needs its name"),
    ([{"kind": "app", "id": "1", "name": "x", "platform": "beos"}], "needs its platform"),
])
def test_bad_delete_specs_are_refused_in_words(targets, needle):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-12: every malformed delete target is refused before any read."""
    with pytest.raises(oz.BuilderError, match=needle):
        oz.normalize_delete({"targets": targets})


def test_a_delete_lists_app_profiles_before_forwarding_profiles():
    """ASVS V11.1.1 · A04:2021 · CWE-696 · WSTG-BUSL-06: the app profile is deleted first so the forwarding profile is free when its turn comes."""
    out = oz.normalize_delete({"targets": [{"kind": "forwarding", "id": "9", "name": "F"}, {"kind": "app", "id": "8", "name": "A", "platform": "IOS"}]})
    assert [t["kind"] for t in out["targets"]] == ["app", "forwarding"] and out["targets"][0]["platform"] == "ios"


@pytest.mark.parametrize("link", [7001.0, " 7001 ", "7001", 7001])
def test_a_forwarding_profile_linked_by_any_spelling_of_its_id_is_in_use(link):
    """ASVS V4.1.3 · A01:2021 · CWE-284 · WSTG-BUSL-06: an app profile linking by 7001, "7001", " 7001 " or 7001.0 blocks the delete."""
    sdk = FakeSdk()
    sdk.fwd["7001"] = {"id": "7001", "name": "Shared"}
    sdk.apps[("windows", "5")] = {"id": "5", "name": "Laptops", "active": "0", "forwardingProfileId": link}
    p = ao.plan(sdk, {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "7001", "name": "Shared"}]}, scope=ZCC_SCOPE)
    assert p["status"] == "blocked" and "in use by Laptops (windows)" in " ".join(p["blockers"])


def test_a_forwarding_profile_used_only_by_an_ios_profile_is_in_use():
    """ASVS V4.1.3 · A01:2021 · CWE-284 · WSTG-BUSL-06: the in-use check reads app profiles on every platform, not only Windows and macOS."""
    sdk = FakeSdk()
    sdk.fwd["7001"] = {"id": "7001", "name": "Mobile"}
    sdk.apps[("ios", "6")] = {"id": "6", "name": "Phones", "active": "0", "forwardingProfileId": 7001}
    p = ao.plan(sdk, {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "7001", "name": "Mobile"}]}, scope=ZCC_SCOPE)
    assert p["status"] == "blocked" and "Phones (ios)" in " ".join(p["blockers"])
    assert {c[2] for c in sdk.calls if c[1] == "app"} == set(oz.ALL_DEVICE_TYPES)


def test_a_forwarding_profile_whose_users_cannot_all_be_read_is_never_deleted():
    """ASVS V4.1.3 · A01:2021 · CWE-636 · WSTG-BUSL-06: if any platform's app profiles fail to read, the delete is blocked (fail closed)."""
    sdk = FakeSdk()
    sdk.fwd["7001"] = {"id": "7001", "name": "F"}
    real = sdk.zcc.web_policy.list_by_company

    def flaky(query_params=None):
        if (query_params or {}).get("device_type") == "android":
            return None, None, "HTTP 500 server error"
        return real(query_params=query_params)
    sdk.zcc.web_policy.list_by_company = flaky
    p = ao.plan(sdk, {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "7001", "name": "F"}]}, scope=ZCC_SCOPE)
    assert p["status"] == "blocked" and "cannot be shown to be unused" in " ".join(p["blockers"])


def test_a_profile_that_came_into_use_after_the_preview_is_not_deleted():
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-06: a link added between preview and apply changes the plan, so nothing is deleted."""
    sdk = FakeSdk()
    sdk.fwd["7001"] = {"id": "7001", "name": "F"}
    s = {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "7001", "name": "F"}]}
    p = ao.plan(sdk, s, scope=ZCC_SCOPE)
    sdk.apps[("macos", "9")] = {"id": "9", "name": "Macs", "active": "0", "forwardingProfileId": "7001"}
    res = ao.execute(sdk, s, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text="F", assessor="Jane Doe",
                     settle_seconds=0)
    assert res["status"] in ("plan_changed", "blocked") and sdk.writes() == [] and "7001" in sdk.fwd


def test_an_app_profile_enabled_between_the_re_plan_and_its_delete_is_left_alone():
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-06: the handler re-reads the profile right before the delete; one enabled meanwhile is a conflict."""
    sdk = FakeSdk()
    sdk.apps[("windows", "5")] = {"id": "5", "name": "Laptops", "active": "0"}
    run = type("Run", (), {})()
    run.client, run.p, run.log = sdk, {"items": []}, (lambda m: None)
    marked = []
    run.mark = lambda units, status, reason="", **kw: marked.append((status, reason))
    sdk.apps[("windows", "5")]["active"] = "1"
    oz._h_delete(run, {"target": {"kind": "app", "id": "5", "name": "Laptops", "platform": "windows"}}, [{}])
    assert marked and marked[0][0] == "conflict" and "enabled" in marked[0][1] and sdk.writes() == []


def _refuse_second_app_read(sdk):
    real, n = sdk.zcc.web_policy.list_by_company, {"windows": 0}

    def reader(query_params=None):
        if (query_params or {}).get("device_type") == "windows":
            n["windows"] += 1
            if n["windows"] > 2:      # the preview's and the re-plan's reads pass; the handler's re-read fails
                return None, None, "HTTP 500 server error"
        return real(query_params=query_params)
    sdk.zcc.web_policy.list_by_company = reader


def test_an_app_profile_that_cannot_be_re_read_rolls_back_the_new_forwarding_profile():
    """ASVS V11.1.1 · A04:2021 · CWE-460 · WSTG-BUSL-06: when the app profiles cannot be read again before the write, the new forwarding profile is deleted."""
    sdk = FakeSdk()
    _refuse_second_app_read(sdk)
    _p, res = zcc_build(sdk)
    assert [c[:2] for c in sdk.writes()] == [("POST", "forwarding/edit"), ("DELETE", "forwarding")]
    assert sdk.fwd == {} and sdk.apps == {} and res["inverse"] is None
    assert next(u for u in res["items"] if u["key"] == "fwd")["status"] == oz.ROLLED_BACK


def test_a_refused_rollback_keeps_the_forwarding_profile_on_record_for_undo():
    """ASVS V11.1.1 · A09:2021 · CWE-460 · WSTG-BUSL-06: if deleting the half-built forwarding profile is refused, it stays in the record and Undo deletes it."""
    sdk = FakeSdk()
    sdk.refuse_app = True
    sdk.zcc.forwarding_profile.delete_forwarding_profile = lambda pid: (None, None, "HTTP 403 forbidden")
    _p, res = zcc_build(sdk)
    fwd = next(u for u in res["items"] if u["key"] == "fwd")
    assert fwd["status"] == "applied" and "Client Connector Portal or with Undo" in fwd["reason"]
    assert res["inverse"] == {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": fwd["object"]["id"], "name": "QA forwarding"}]}


def test_an_app_profile_accepted_but_not_found_afterwards_is_a_failure_and_rolls_back():
    """ASVS V11.1.1 · A04:2021 · CWE-754 · WSTG-BUSL-06: an accepted create whose profile cannot be found by name fails and removes the new forwarding profile."""
    sdk = FakeSdk()
    sdk.zcc.web_policy.web_policy_edit = lambda **kw: ({}, Resp({"success": "true"}), None)   # accepted, never stored
    _p, res = zcc_build(sdk)
    app = next(u for u in res["items"] if u["key"] == "app")
    assert app["status"] == "failed" and "could not be found by its name" in app["error"]
    assert sdk.fwd == {} and ("DELETE", "forwarding") in [c[:2] for c in sdk.writes()]


def test_zcc_success_false_with_a_message_is_a_refusal_in_its_words():
    """ASVS V7.4.1 · A04:2021 · CWE-754 · WSTG-ERRH-01: HTTP 200 with success false (assumed shape) is a refusal carrying ZCC's message."""
    why = oz._rejected(Resp({"success": "False", "errorMessage": "name taken"}), None)
    assert why == "ZCC rejected the request (HTTP 200, success false): name taken"
    assert oz._rejected(Resp({"success": "true"}), {"success": True}) is None


def test_a_list_that_never_ends_is_reported_incomplete_not_trusted():
    """ASVS V11.1.4 · A04:2021 · CWE-835 · WSTG-BUSL-07: a list answering full pages forever stops at the page cap with an error."""
    full = [{"id": i} for i in range(oz.PAGE_SIZE)]
    rows, err = oz._read_all(lambda query_params: (full, None, None), {}, None)
    assert len(rows) == oz.PAGE_SIZE * oz.MAX_PAGES and "not read to the end" in err


def test_a_list_call_that_raises_is_an_error_not_a_crash():
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: an SDK exception while listing becomes a short error string."""
    def boom(query_params):
        raise ConnectionError("x" * 500)
    rows, err = oz._read_all(boom, {}, None)
    assert rows == [] and err.startswith("ConnectionError: ") and len(err) < 260


def test_stop_before_a_list_read_sends_nothing():
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-07: with Stop set, a list read raises Stopped before any call."""
    calls = []
    ev = threading.Event()
    ev.set()
    with pytest.raises(oz.Stopped):
        oz._read_all(lambda query_params: calls.append(1), {}, ev)
    assert calls == []


def test_the_inventory_counts_links_per_forwarding_profile_and_never_holds_a_setting():
    """ASVS V8.3.4 · A01:2021 · CWE-200 · WSTG-INFO-05: the picker list carries names, ids, state and links only, and counts what uses each forwarding profile."""
    sdk = FakeSdk()
    sdk.fwd["7001"] = {"id": "7001", "name": "F", "active": 1}
    sdk.apps[("windows", "5")] = {"id": "5", "name": "W", "active": "1", "forwardingProfileId": 7001.0, "uninstall_password": "CANARY", "ruleOrder": 2}
    sdk.apps[("macos", "6")] = {"id": "6", "name": "M", "active": "0", "forwardingProfileId": "0"}
    inv = oz.inventory(sdk)
    assert inv["forwarding"][0]["used_by"] == 1 and inv["app"]["macos"][0]["forwarding_profile_id"] == ""
    assert "CANARY" not in repr(inv)


def test_an_empty_build_result_has_no_undo():
    """ASVS V11.1.1 · CWE-754 · WSTG-BUSL-06: a build that applied nothing offers no Undo."""
    assert oz.inverse_build({"items": [{"status": "failed", "field": "exists", "kind": "zcc_app_profile", "object": {"id": "1"}}]}) is None


# ═══ ZDX (ops_zdx) ════════════════════════════════════════════════════════

@pytest.mark.parametrize("url, needle", [
    ("https://127.0.0.1/", "loopback"), ("http://[::1]:8080/", "loopback"), ("https://[::ffff:127.0.0.1]/", "loopback"),
    ("https://169.254.169.254/latest/meta-data", "link-local"), ("https://[fe80::1]/", "link-local"),
    ("https://0.0.0.0/", "unspecified"), ("https://[::]/", "unspecified"), ("https://224.0.0.251/", "multicast"),
    ("https://240.0.0.1/", "reserved"), ("https://app.localhost/", "the device itself"),
    ("https://0x7f.1/", "ends in a number"), ("https://intranet.2130706433/", "ends in a number"),
])
def test_custom_app_urls_that_name_no_app_are_refused(url, needle):
    """ASVS V12.6.1 · A10:2021 · CWE-918 · WSTG-INPV-19: loopback, link-local (cloud metadata), unspecified, multicast, reserved and numeric-tail hosts are refused."""
    got, why = zx.clean_url(url)
    assert got is None and needle in why


@pytest.mark.parametrize("url, want", [
    ("https://10.1.2.3/portal", "https://10.1.2.3/portal"), ("https://[fd00::10]/", "https://[fd00::10]/"),
    ("https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443/x"), ("http://intranet.corp:8080/a?b=c", "http://intranet.corp:8080/a?b=c"),
    ("https://bücher.example/x", "https://xn--bcher-kva.example/x"), ("https://BÜCHER.example:8443/", "https://xn--bcher-kva.example:8443/"),
    ("https://xn--bcher-kva.example/", "https://xn--bcher-kva.example/"),
])
def test_internal_ipv6_and_idn_app_urls_are_accepted(url, want):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-12: private and IPv6 addresses are valid ZDX targets, and an IDN host goes to ZDX in its punycode form."""
    assert zx.clean_url(url) == (want, None)


@pytest.mark.parametrize("url, needle", [
    ("", "enter the app's URL"), ("ftp://a.example/", "must start with"), ("javascript:alert(1)", "must start with"),
    ("https://user:pw@a.example/", "user name or password"), ("https://a.example/ x", "spaces"), ("https://a.example:99999/", "cannot be read"),
    ("https://a.example:0/", "out of range"), ("https://-bad.example/", "not a valid host"), ("https://single/", "not a valid host"),
    ("https://a.example/" + "x" * 1007, "longer than"),
], ids=lambda v: v[:40] if isinstance(v, str) else None)
def test_custom_app_url_boundaries(url, needle):
    """ASVS V5.1.4 · A03:2021 · CWE-20 · WSTG-INPV-12: scheme, credentials, whitespace, port and length are each checked with a plain reason."""
    got, why = zx.clean_url(url)
    assert got is None and needle in why


def test_a_custom_app_url_of_exactly_1024_characters_is_accepted():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-12: the 1024-character boundary passes."""
    url = "https://a.example/" + "x" * (zx.URL_MAX - len("https://a.example/"))
    assert len(url) == zx.URL_MAX and zx.clean_url(url) == (url, None)


def test_a_metadata_url_blocks_the_plan_and_writes_nothing(zdx):
    """ASVS V12.6.1 · A10:2021 · CWE-918 · WSTG-INPV-19: a custom app at the metadata address blocks the plan before any write."""
    fake, client = zdx
    p = zdx_preview(fake, client, dict(BEST, predefined=[], custom=[{"name": "Meta", "url": "http://169.254.169.254/", "cloudpath": True}]))
    assert p["status"] == "blocked" and "link-local" in " ".join(p["blockers"]) and fake.writes == []


@pytest.mark.parametrize("bad", ["..", ".", "...", "a/b", "a b", "", "x" * 81])
def test_ids_that_are_not_ids_are_refused_before_any_read(bad):
    """ASVS V5.1.3 · A01:2021 · CWE-22 · WSTG-ATHZ-01: dot-only, slashed, blank or over-long ids are refused in the spec."""
    with pytest.raises(ao.OperationError):
        zx._clean_targets([{"app": bad, "to": "on"}], with_to=True, with_name=False)


@pytest.mark.parametrize("key", ["..", "."])
def test_a_dot_segment_from_the_tenant_never_reaches_the_executor(key):
    """ASVS V12.3.1 · A01:2021 · CWE-22 · WSTG-ATHZ-01: an app key of . or .. read from the tenant would move the request; it is refused, nothing sent."""
    fake = FakeZdx()
    api = zx.ZdxApi(client_for(fake))
    got, err = api.zdx_delete_app(key)
    assert got is None and "not an id" in err["message"] and fake.requests == []


def _drop_id(fake, kind):
    real = fake._route

    def route(m, p, body, params):
        out = real(m, p, body, params)
        if m == "POST" and p.endswith("/monitors") and body["type"] == kind:
            return {k: v for k, v in out.items() if k != "id"}
        return out
    fake._route = route


@pytest.mark.parametrize("kind", ["WEB", "TRACERT"])
def test_a_probe_accepted_without_an_id_is_found_by_name_and_the_app_is_removed(zdx, kind):
    """ASVS V11.1.1 · A04:2021 · CWE-460 · WSTG-BUSL-06: a probe ZDX accepted without an id is looked up by name, so the half-built app is removed completely."""
    fake, client = zdx
    _drop_id(fake, kind)
    res = zdx_apply(fake, client, dict(BEST, predefined=[], custom=[{"name": "Intranet", "url": "https://intranet.example.com/", "cloudpath": True}]))
    assert not any(a["name"] == "Intranet" for a in fake.apps) and fake.mons == []
    assert "returned no id" in next(u for u in res["items"] if u["status"] == "failed")["error"]
    assert not any(c.get("left_behind") for c in res.get("created") or [])


def test_a_refused_activation_removes_both_probes_then_the_app(zdx):
    """ASVS V11.1.1 · A04:2021 · CWE-460 · WSTG-BUSL-06: when turning the new app on is refused, its CloudPath probe, Web probe and the app are deleted in that order."""
    fake, client = zdx
    fake.fail = {("PUT", "/activate"): ApiError(500, "ERR", "busy")}
    res = zdx_apply(fake, client, dict(BEST, predefined=[], custom=[{"name": "Intranet", "url": "https://intranet.example.com/", "cloudpath": True}]))
    dels = [p for m, p, _b in fake.writes if m == "DELETE"]
    assert len(dels) == 3 and fake.apps == [] and fake.mons == []
    kinds = []
    for d in dels[:2]:
        mid = d.rsplit("/", 1)[-1]
        kinds.append(next(n for n in ("CloudPath", "Web") if any(n in u["object"]["name"] for u in res["items"] if str(u["object"].get("probe")) == mid)))
    assert kinds == ["CloudPath", "Web"] and "/monitors/" not in dels[2]
    assert {u["status"] for u in res["items"] if u["kind"] == "zdx_probe"} == {"rolled_back"}


def test_stop_half_way_leaves_the_app_reported_and_on_record_for_undo(zdx):
    """ASVS V11.1.1 · A09:2021 · CWE-460 · WSTG-BUSL-06: after Stop nothing more is sent, the half-built app is named and kept in the record so Undo removes it."""
    fake, client = zdx
    cancel = threading.Event()
    real = fake._route

    def route(m, p, body, params):
        out = real(m, p, body, params)
        if m == "POST" and p.endswith("/monitors") and body["type"] == "WEB":
            cancel.set()
        return out
    fake._route = route
    spec = dict(BEST, predefined=[], custom=[{"name": "Intranet", "url": "https://intranet.example.com/", "cloudpath": True}])
    res = zdx_apply(fake, client, spec, cancel=cancel)
    assert [m for m, _p, _b in fake.writes] == ["POST", "POST"]
    made = next(c for c in res["created"] if c["type"] == "zdx_custom_app")
    assert made["left_behind"] is True and any("was not removed" in line for line in res["logs"])
    assert res["inverse"]["targets"] == [{"app": str(made["id"]), "probe": None, "name": "Intranet"}]


def test_the_zdx_configuration_paths_stay_marked_assumed():
    """ASVS V1.14.6 · NIST SSDF PW.4.1 · CWE-1059 · WSTG-CONF-01: the ZDX config API is not in the SDK, so every plan and the module say it is assumed."""
    assert "ASSUMED" in zx.__doc__ and "/zdx/v1/config" in zx.__doc__ and zx.CONFIG == "/zdx/v1/config"
    import inspect
    assert "# ASSUMED" in inspect.getsource(zx).split("CONFIG = ", 1)[1].splitlines()[0]
    fake = FakeZdx()
    fake.cols = [{"id": 1, "name": "Custom Apps Collection"}]
    p = zdx_preview(fake, client_for(fake), dict(BEST, predefined=[]))
    assert zx.ASSUMED_NOTE in p["notes"] and "not verified against your tenant" in zx.ASSUMED_NOTE


@pytest.mark.parametrize("err, want", [
    ({"status": "429", "code": "RATE", "message": "slow down"}, (429, "RATE")),
    ({"status_code": "x"}, (None, None)),
    (ApiError(403, None, "no"), (403, None)),
    (RuntimeError("HTTP 404 not found"), (404, None)),
])
def test_zdx_error_shapes_become_status_and_code(err, want):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: every error shape the executor hands back is read into a status and code."""
    parts = zx.error_parts(err)
    assert (parts["status"], parts["code"]) == want


@pytest.mark.parametrize("status, code, needle", [
    (401, None, "sign-in"), (403, None, "configuration write"), (404, None, "does not have"), (409, None, "conflict"), (429, None, "rate limit"),
    (503, None, "side failed"), (400, "INVALID_HOST", "host or URL"), (400, "X", "rejected the request"), (None, None, ""),
])
def test_every_zdx_refusal_has_one_plain_sentence(status, code, needle):
    """ASVS V7.4.1 · A04:2021 · CWE-209 · WSTG-ERRH-01: each HTTP status ZDX may answer is explained in one plain sentence."""
    assert needle in zx.explain(status, code, "")


# ═══ Versions, device states, fleet health (zcc_evaluation, zcc_fleet) ════

@pytest.mark.parametrize("a, op, b", [
    ("4.7", "==", "4.7.0"), ("4.7.0.0", "==", "4.7"), ("4.10", ">", "4.9"), ("4.10.0.100", ">", "4.9.9.999"), ("4.7.0.61 (Build 61)", "==", "4.7.0.61"),
    ("v4.6.1", "<", "4.6.2"), ("3.7.2", "<", "4.0"), ("4", "==", "4.0.0.0"),
])
def test_versions_compare_semantically(a, op, b):
    """ASVS V5.1.3 · A04:2021 · CWE-1025 · WSTG-BUSL-01: 4.7 equals 4.7.0, 4.10 is newer than 4.9, build labels are ignored."""
    ta, tb = ze.version_tuple(a), ze.version_tuple(b)
    assert {"==": ta == tb, ">": ta > tb, "<": ta < tb}[op]


@pytest.mark.parametrize("raw", [None, "", "beta", "x" * 10000])
def test_a_version_without_a_number_is_empty(raw):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-12: no number means no version, never a crash."""
    assert ze.version_tuple(raw) == ()


def test_a_hostile_version_string_cannot_exhaust_int():
    """ASVS V5.1.4 · A04:2021 · CWE-400 · WSTG-INPV-12: a 5000-digit version part (over Python's int-string limit) is capped, not a crash."""
    t = ze.version_tuple("9" * 5000 + ".1")
    assert t[0] == 999_999_999 and len(t) == ze.VERSION_PARTS


@pytest.mark.parametrize("plat, version, unsupported", [
    ("Windows", "4.7", False), ("Windows", "4.7.0.0", False), ("Windows", "4.6.9.99", True), ("macOS", "4.5.2", False), ("macOS", "4.5.1.9", True),
    ("macOS", "4.5", True), ("Linux", "3.7.2.18", False), ("Linux", "3.8", True), ("Linux", "4.2", False), ("Android", "4.0", False),
    ("Android", "3.9.9", True), ("iOS", "4.4.4", False), ("?", "1.0", False), ("Windows", "", False),
])
def test_unsupported_release_oracle(plat, version, unsupported):
    """ASVS V14.2.1 · A06:2021 · CWE-1104 · WSTG-CONF-01: the supported-release table per platform, at its boundaries."""
    assert ze.zcc_unsupported(plat, version) is unsupported


def _dev(i, version, **kw):
    d = {"user": f"u{i}@acme.com", "machineHostname": f"h{i}", "udid": f"U{i}", "type": 3, "agentVersion": version, "registrationState": 1,
         "lastSeenTime": int((NOW - timedelta(hours=1)).timestamp()), "policyName": "P"}
    d.update(kw)
    return d


def test_4_7_and_4_7_0_are_the_same_release_so_neither_drifts():
    """ASVS V5.1.3 · A04:2021 · CWE-1025 · WSTG-BUSL-01: devices on 4.7 and 4.7.0 are on one release: no version drift, no old release."""
    devs = zf.normalize_devices([_dev(1, "4.7"), _dev(2, "4.7.0")], [], NOW)
    alerts = zf.device_alerts(devs, False)
    assert alerts["version_drift"]["count"] == 0 and alerts["old_version"]["count"] == 0


def test_old_release_counts_minor_versions_semantically():
    """ASVS V5.1.3 · A04:2021 · CWE-1025 · WSTG-BUSL-01: 4.10 is two minors ahead of 4.8, so a 4.8 device is old and a 4.9 device only drifts."""
    devs = zf.normalize_devices([_dev(1, "4.10.0.5"), _dev(2, "4.9.1"), _dev(3, "4.8")], [], NOW)
    alerts = zf.device_alerts(devs, False)
    assert alerts["version_drift"]["count"] == 2 and [d["version"] for d in alerts["old_version"]["rows"]] == ["4.8"]


@pytest.mark.parametrize("raw, want", [
    (1, "registered"), ("1", "registered"), (1.0, "registered"), ("1.0", "registered"), (" 6 ", "quarantined"), (3, "removal_pending"),
    (4, "unregistered"), (5, "removed"), ("REGISTERED", "registered"), ("Removal Pending", "removal_pending"), ("UN-REGISTERED", "unregistered"),
    ("quarantined", "quarantined"), (None, "unknown"), (2, "unknown"), (True, "unknown"), ("", "unknown"),
])
def test_registration_states_arrive_as_numbers_or_text(raw, want):
    """ASVS V5.1.3 · A04:2021 · CWE-1287 · WSTG-INPV-12: the SDK's registration codes (as int, text or float) and the portal's words map to one state."""
    assert zf.registration(raw) == want


@pytest.mark.parametrize("d, want", [
    ({"type": 3}, "Windows"), ({"type": "4"}, "macOS"), ({"type": 1.0}, "iOS"), ({"deviceType": "DEVICE_TYPE_ANDROID"}, "Android"),
    ({"type": "5.0"}, "Linux"), ({"osType": "Darwin 23"}, "macOS"), ({"os": "iPadOS 17"}, "iOS"), ({}, "?"), ({"type": 9}, "?"),
])
def test_device_platforms_arrive_as_numbers_or_text(d, want):
    """ASVS V5.1.3 · A04:2021 · CWE-1287 · WSTG-INPV-12: the device type as 3, "3", 3.0, DEVICE_TYPE_<OS> or OS text gives one platform."""
    assert ze.device_platform(d) == want


def test_app_profile_platforms_accept_the_same_spellings():
    """ASVS V5.1.3 · CWE-1287 · WSTG-INPV-12: an app profile's device type as 3.0 or DEVICE_TYPE_MACOS names its platform in the findings."""
    assert ze._plat({"device_type": 3.0}) == "Windows" and ze._plat({"deviceType": "DEVICE_TYPE_MACOS"}) == "macOS"


@pytest.mark.parametrize("raw, want", [
    (1, "active"), (0, "inactive"), (1.0, "active"), ("0.0", "inactive"), ("Active", "active"), ("Tunnel Connected", "active"),
    ("DISABLED", "inactive"), ("not authenticated", "inactive"), ("N/A", "not_applicable"), ("", "not_applicable"), (None, "not_applicable"),
    ("weird", "unknown"),
])
def test_service_states_arrive_as_numbers_or_text(raw, want):
    """ASVS V5.1.3 · A04:2021 · CWE-1287 · WSTG-INPV-12: a service-status cell as a number or the portal's words is read one way; unknown text is unknown."""
    assert zf.service_state(raw) == want


def test_a_list_of_secrets_is_masked_item_by_item():
    """ASVS V8.3.4 · A02:2021 · CWE-200 · WSTG-INFO-05: a password or token held in a list is masked item by item in the drift view."""
    out = zf.mask_settings({"exitPasswords": ["CANARY1", ""], "policyToken": "CANARY2", "nested": {"otpList": [{"x": 1}, "CANARY3"]},
                            "bypassApps": ["Teams"]})
    assert "CANARY" not in repr(out) and out["exitPasswords"] == ["(set)", "(not set)"] and out["bypassApps"] == ["Teams"]


def test_a_large_fleet_is_analysed_completely_and_kept_bounded():
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-07: 12 000 devices are all counted and the rows kept for the page and alerts are capped."""
    n = zf.MAX_RESULT_DEVICES + 2000
    devs = [_dev(i, f"4.{i % 8}.0", lastSeenTime=int((NOW - timedelta(days=40 if i % 10 == 0 else 0, hours=1)).timestamp())) for i in range(n)]
    rows = [{"udid": f"U{i}", "zia": "Active" if i % 7 else "Inactive", "zpa": "Active", "zdx": "1"} for i in range(n)]
    cfg = {"read_status": {"forwarding_profiles": "read"}, "forwarding_profiles": [], "app_profiles": [{"id": 1, "name": "P", "platform": "windows"}]}
    out = zf.analyze(cfg, {"status": "read", "devices": devs, "service": {"status": "read", "rows": rows}}, now=NOW)
    assert out["kpis"]["registered"] == n and out["devices_total"] == n and len(out["devices"]) == zf.MAX_RESULT_DEVICES and out["devices_truncated"]
    assert out["alerts"]["ghost"]["count"] == n // 10 and len(out["alerts"]["ghost"]["rows"]) == zf.MAX_ALERT_ROWS
    assert out["alerts"]["blind_spot"]["count"] == len([i for i in range(n) if i % 7 == 0 and i % 10])


class _Devices:
    def __init__(self, pages, fail_on=None):
        self.pages, self.fail_on, self.asked = pages, fail_on, []

    def list_devices(self, query_params=None):
        page = query_params["page"]
        self.asked.append(dict(query_params))
        if page == self.fail_on:
            return None, None, "HTTP 503 unavailable"
        return (self.pages[page - 1] if page <= len(self.pages) else []), None, None


def _sdk(devices):
    return type("S", (), {"zcc": type("Z", (), {"devices": devices})(), "get_request_executor": lambda self: None})()


def test_the_device_read_follows_every_page(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-07: the device list is read page by page until a short page, with the documented page size."""
    monkeypatch.setattr(zf, "DEVICE_PAGE_SIZE", 2)
    monkeypatch.setattr(zf, "_nap", lambda s, c: None)
    monkeypatch.setattr(zf, "read_service_status", lambda sdk, log, cancel: {"status": "read", "reason": "", "rows": []})
    dev = _Devices([[{"udid": "a"}, {"udid": "b"}], [{"udid": "c"}, {"udid": "d"}], [{"udid": "e"}]])
    out = zf.read_devices(_sdk(dev), log=lambda m: None, cancel=None)
    assert out["status"] == "read" and len(out["devices"]) == 5
    assert [q["page"] for q in dev.asked] == [1, 2, 3] and {q["page_size"] for q in dev.asked} == {2}


def test_a_fleet_beyond_the_page_cap_is_reported_incomplete(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-770 · WSTG-BUSL-07: more devices than the cap are not shown as a complete figure; the reason says why."""
    monkeypatch.setattr(zf, "DEVICE_PAGE_SIZE", 1)
    monkeypatch.setattr(zf, "MAX_DEVICE_PAGES", 3)
    monkeypatch.setattr(zf, "_nap", lambda s, c: None)
    out = zf.read_devices(_sdk(_Devices([[{"udid": str(i)}] for i in range(10)])), log=lambda m: None, cancel=None)
    assert out["status"] == "unavailable" and out["devices"] == [] and "More than 3 devices" in out["reason"]


def test_a_device_page_that_fails_half_way_shows_no_partial_figures(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-754 · WSTG-ERRH-01: a refusal on page 2 drops the figures (unknown, not a smaller fleet) and logs only the HTTP code."""
    monkeypatch.setattr(zf, "DEVICE_PAGE_SIZE", 1)
    monkeypatch.setattr(zf, "_nap", lambda s, c: None)
    lines = []
    out = zf.read_devices(_sdk(_Devices([[{"udid": "a", "user": "jdoe@acme.com"}], [{"udid": "b"}]], fail_on=2)), log=lines.append, cancel=None)
    assert out["status"] == "unavailable" and out["devices"] == [] and "HTTP 503" in out["reason"]
    assert not any("jdoe" in x for x in lines)


@pytest.mark.parametrize("text, needle", [
    ("x" * (zf.MAX_CSV_BYTES + 1), "larger than"), ("User,Device type,Version\nu,3,4.7\n", "no ZIA, ZPA or ZDX column"),
    ('UDID,ZIA Status\n"a' + "x" * 200000 + '"\n', "malformed line"),
], ids=["oversized", "no-service-column", "malformed"])
def test_the_service_status_file_is_parsed_defensively(text, needle):
    """ASVS V12.1.1 · A04:2021 · CWE-400 · WSTG-BUSL-09: an oversized, unrecognised or malformed service-status file is refused in words, never a crash."""
    old = csv.field_size_limit(131072)   # the csv default; another module may raise it process-wide
    try:
        out = zf.parse_service_csv(text)
    finally:
        csv.field_size_limit(old)
    assert out["status"] == "unavailable" and needle in out["reason"]


def test_the_device_export_neutralises_spreadsheet_formulas():
    """ASVS V5.3.10 · A03:2021 · CWE-1236 · WSTG-INPV-12: a user or host name that starts a formula is written as text in the CSV export."""
    devs = zf.normalize_devices([_dev(1, "4.7", user="=HYPERLINK(\"http://x\")", machineHostname="+cmd|' /C calc'!A0")], [], NOW)
    _stem, text = zf.export_csv({"devices": devs}, "devices", False)
    row = list(csv.reader(io.StringIO(text)))[1]
    assert row[0].startswith("'=") and row[1].startswith("'+")


@pytest.mark.parametrize("raw, want", [
    (1790000000, datetime(2026, 9, 21, 14, 13, 20, tzinfo=timezone.utc)), ("1790000000000", datetime(2026, 9, 21, 14, 13, 20, tzinfo=timezone.utc)),
    ("2026-09-21 14:13:20 UTC", datetime(2026, 9, 21, 14, 13, 20, tzinfo=timezone.utc)), ("09/21/2026 02:13:20 PM", datetime(2026, 9, 21, 14, 13, 20, tzinfo=timezone.utc)),
    ("2026-09-21T16:13:20+02:00", datetime(2026, 9, 21, 14, 13, 20, tzinfo=timezone.utc)), (0, None), (True, None), ("", None), ("soon", None),
    (float("inf"), None), (float("nan"), None), (-5, None),
])
def test_device_times_in_every_format_or_none(raw, want):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-12: epoch seconds or milliseconds, ISO and portal formats parse to UTC; nonsense is None, never a crash."""
    assert zf.parse_time(raw) == want


# ═══ Profile inventories (zcc_profiles) ═══════════════════════════════════

def _getter(pages, code=200):
    asked = []

    def get(endpoint, params):
        asked.append(dict(params))
        p = params["page"]
        body = pages[p - 1] if p <= len(pages) else []
        return (body, code) if not callable(body) else body()
    get.asked = asked
    return get


def test_profile_pages_are_read_until_a_short_page():
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-07: full pages are followed, a short page ends the list."""
    full = [{"id": i} for i in range(zp.PAGE_SIZE)]
    get = _getter([full, [{"id": "last"}]])
    items, code = zp.read_profiles(get, "/zcc/x")
    assert code == 200 and len(items) == zp.PAGE_SIZE + 1 and [q["page"] for q in get.asked] == [1, 2]


@pytest.mark.parametrize("pages, needle", [
    ([[{"id": i} for i in range(100)]] * 2, "repeated a page"),
    ([{"list": [{"id": 1}], "totalCount": 5}, {"list": [], "totalCount": 5}], "ended before the total"),
    ([{"list": [{"id": 1}, {"id": 2}], "totalCount": 1}], "invalid profile total"),
    ([{"list": [{"id": 1}], "totalCount": "many"}], "invalid literal"),
    ([[{"id": 1}, "x"]], "invalid item"),
    ([{"error": "denied"}], "did not contain a profile list"),
])
def test_partial_repeated_or_malformed_inventories_are_refused(pages, needle):
    """ASVS V11.1.4 · A04:2021 · CWE-754 · WSTG-BUSL-07: a repeated page, a short total, a bad item or an error body is an error, never a short inventory."""
    body, code = zp.read_profiles(_getter(pages), "/zcc/x")
    assert code == 0 and needle in body["error"]


def test_a_204_ends_the_inventory_and_a_refusal_is_passed_on():
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: HTTP 204 means no more pages; any other non-200 answer is returned with its code."""
    assert zp.read_profiles(lambda e, p: ([], 204), "/zcc/x") == ([], 200)
    assert zp.read_profiles(lambda e, p: ({"error": "no"}, 403), "/zcc/x") == ({"error": "no"}, 403)


def test_app_profiles_of_every_platform_keep_their_failures_and_drop_duplicates():
    """ASVS V11.1.4 · A04:2021 · CWE-1287 · WSTG-BUSL-07: each OS is asked for; a failed one is reported per platform; one profile listed twice (as 3 and 3.0) is kept once."""
    def get(endpoint, params):
        dt = params["deviceType"]
        if dt == 2:
            return {"error": "android off"}, 403
        if dt == 3:
            return [{"id": 9, "name": "W", "deviceType": 3}, {"id": 9, "name": "W", "deviceType": 3.0}, {"id": 10, "name": "W2"}], 200
        return [], 200
    items, errors, statuses = zp.read_app_profiles(get)
    assert [i["id"] for i in items] == [9, 10] and items[1]["deviceType"] == 3
    assert statuses["android"] == "unverified" and statuses["windows"] == "read" and "deviceType=2): HTTP 403 android off" in errors[0]


def test_stop_ends_a_profile_read_before_the_next_page():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-07: the cancel hook runs before every page."""
    get = _getter([[{"id": i} for i in range(100)]] * 3)
    with pytest.raises(RuntimeError):
        zp.read_profiles(get, "/zcc/x", cancel=lambda: (_ for _ in ()).throw(RuntimeError("stop")))
    assert get.asked == []


# ═══ Strict evaluation checks (zcc_evaluation) ════════════════════════════

from dlp_assessment_full_auto import R  # noqa: E402
from test_zcc_evaluation import BAD_PROFILE, GOOD_PROFILE, FakeCl, _cl  # noqa: E402


def test_no_evaluation_finding_repeats_a_password_value():
    """ASVS V8.3.4 · A02:2021 · CWE-200 · WSTG-INFO-05: every check over a profile holding password values names the profile, never the value."""
    prof = dict(GOOD_PROFILE, uninstallPassword="CANARYun", disablePassword="CANARYdis", exitPassword="", zccRevertPassword="CANARYrev", enableZCCRevert=1)
    cl = _cl(profiles=(prof, BAD_PROFILE))
    for _sec, _grp, _name, fn in ze.REG_EXTRA:
        r = fn(cl)
        assert "CANARY" not in f"{r.detail} {r.data}", fn.__name__


@pytest.mark.parametrize("fn", [ze.z_disable_passwords, ze.z_log_level, ze.z_quic, ze.z_fail_open, ze.z_revert, ze.z_adapters,
                                ze.z_disable_window, ze.z_bypass_hygiene, ze.z_forwarding_modes, ze.z_forwarding_hygiene, ze.z_trusted_networks])
def test_an_unreadable_endpoint_is_explained_never_raised(fn):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: every check answers the API's refusal as a result with a reason, never an exception."""
    r = fn(FakeCl({}))
    assert r.status in (R.INFO, R.ERROR, R.WARN, R.FAIL) and r.detail


def test_windows_only_settings_are_not_applicable_elsewhere():
    """ASVS V14.2.1 · CWE-1287 · WSTG-CONF-01: anti-tampering on a fleet without Windows profiles is information, not a failure."""
    mac = dict(BAD_PROFILE, enableAntiTampering=0)
    r = ze.z_anti_tampering(_cl(profiles=(mac,), **{"/zcc/companyInfo": {}}))
    assert r.status == R.INFO and "Windows setting" in r.detail


def test_quic_on_mobile_and_desktop_profiles():
    """ASVS V14.2.1 · CWE-693 · WSTG-CONF-01: an iOS profile on Z-Tunnel 1.0 without Drop QUIC fails; a DNS HTTPS-record block counts for desktops."""
    ios = {"id": 3, "name": "Phones", "device_type": 1, "active": 1, "dropQuicTraffic": 0, "forwardingProfileId": 99}
    dns = [{"name": "No HTTPS RR", "state": "ENABLED", "action": "BLOCK", "dnsRuleRequestTypes": ["HTTPS"]}]
    r = ze.z_quic(_cl(profiles=(ios, GOOD_PROFILE), **{"/zia/firewallDnsRules": dns}))
    assert r.status == R.FAIL and "Phones (iOS)" in r.detail
    r = ze.z_quic(_cl(profiles=(GOOD_PROFILE,), **{"/zia/firewallDnsRules": dns}))
    assert r.status == R.PASS and "No HTTPS RR" in r.detail
    r = ze.z_quic(_cl(profiles=(GOOD_PROFILE,)))
    assert r.status == R.WARN and "no enabled Firewall Filtering rule" in r.detail


def test_fail_open_tunnel_policy_and_lockdown_warnings():
    """ASVS V14.2.1 · CWE-636 · WSTG-CONF-01: a fail-open tunnel policy, a lockdown that does not lock, and proxy and prompt settings are each named."""
    p = dict(GOOD_PROFILE, zccTunnelFailPolicy="FAIL_OPEN", zccFailCloseSettingsLockdownOnTunnelProcessExit=0, enableZCCFailCloseSettingsForSEMode=1)
    pol = [{"enableWebSecOnProxyUnreachable": 0, "captivePortalWebSecDisableMinutes": "x", "enableStrictEnforcementPrompt": 0}]
    r = ze.z_fail_open(_cl(profiles=(p,), **{"/zcc/failOpenPolicy": pol}))
    assert r.status == R.WARN and all(w in r.detail for w in ("fail-open", "does not lock down", "proxy is unreachable", "prompt is off"))


def test_disable_window_adapters_and_bypass_edges():
    """ASVS V14.2.1 · CWE-693 · WSTG-CONF-01: long disable windows, VPN adapters, many exclusions and app bypasses and a PAC on the profile are reported."""
    p = dict(GOOD_PROFILE, reactivateAntiTamperingTime=90, sendDisableServiceReason=0, enableSetProxyOnVPNAdapters=0, vpnGateways=["gw"],
             policyExtension={"packetTunnelExcludeList": ",".join(f"10.{i}.0.0/24" for i in range(25))}, bypassAppIds=list(range(11)),
             pac_url="https://pac.example/p.pac", allowPacExclusionsOnly=0)
    cl = _cl(profiles=(p,))
    assert "anti-tampering can stay off for 90" in ze.z_disable_window(cl).detail
    assert "proxy is not set on VPN adapters" in ze.z_adapters(cl).detail
    d = ze.z_bypass_hygiene(cl).detail
    assert "25 destination exclusions" in d and "11 application bypasses" in d and "PAC file" in d


def test_company_privacy_and_device_edges():
    """ASVS V14.2.1 · CWE-1188 · WSTG-CONF-01: FIPS and a JSON web app config are read, unreadable privacy is information, Z-Tunnel 1.0 devices warn."""
    company = {"dlpEnabled": 1, "enableAntiTampering": 1, "webAppConfig": json.dumps({"slowRolloutZCC": 1, "inactiveDeviceCleanup": 30, "enableFipsMode": 1}),
               "enableGlobalZCCTelemetry": 1, "restrictAdminAccess": 0}
    r = ze.z_company(_cl(**{"/zcc/companyInfo": company}))
    assert r.status == R.WARN and "not restricted" in r.detail
    r = ze.z_company(_cl(**{"/zcc/companyInfo": dict(company, restrictAdminAccess=1)}))
    assert r.status == R.PASS and "FIPS mode on" in r.detail
    assert ze.z_company(_cl(**{"/zcc/companyInfo": dict(company, webAppConfig="{bad")})).status == R.WARN
    assert ze.z_privacy(FakeCl({})).status == R.INFO
    assert "log folder" in ze.z_privacy(_cl(**{"/zcc/privacyInfo": {"grantAccessToZscalerLogFolder": 1, "collectUserInfo": 1}})).detail
    devs = [{"type": 3, "registrationState": "REGISTERED", "strictEnforcement": 0 if i == 0 else 1, "antiTamperingStatus": 0 if i == 0 else 1,
             "zdpEnabled": 1, "agentVersion": "4.8"} for i in range(10)]
    r = ze.z_device_fleet(_cl(**{"/zcc/devices": devs}))
    assert r.status == R.WARN and "1 device(s) without strict enforcement" in r.detail


def test_version_spread_for_a_platform_without_a_support_table_and_failed_upgrades():
    """ASVS V14.2.1 · A06:2021 · CWE-1104 · WSTG-CONF-01: an unnamed platform falls back to the three newest releases; failed upgrades are counted."""
    devs = [{"osType": "ChromeOS", "agentVersion": v} for v in ("1.4", "1.3", "1.2", "1.1", "1.0")] + \
           [{"type": 3, "agentVersion": "4.6", "expectedZCCVersion": "4.8", "zccUpgradeStatus": "failed"}]
    r = ze.z_version_spread(_cl(**{"/zcc/devices": devs}))
    assert "1 device(s) failed to upgrade" in r.detail and "3 of 6" in r.detail and "(?: 2, Windows: 1;" in r.detail
    assert ze.z_version_spread(_cl(**{"/zcc/devices": [{"type": 3}]})).detail == "Devices list no client version."


def test_notification_templates_none_and_unattached():
    """ASVS V14.2.1 · CWE-778 · WSTG-CONF-01: no template at all is a warning; a template no rule uses is named."""
    assert ze.z_notification_templates(_cl(**{"/zia/dlpNotificationTemplates": []})).status == R.WARN
    tpl = [{"id": 7, "name": "Spare", "tlsEnabled": True, "subject": "s ${USER}", "plainTextMessage": "p"}]
    assert "Spare: not attached" in ze.z_notification_templates(_cl(**{"/zia/dlpNotificationTemplates": tpl, "/zia/webDlpRules": [{"notificationTemplate": 9}]})).detail


def test_splice_inserts_each_extra_check_once_after_its_section():
    """ASVS V14.2.1 · CWE-1041 · WSTG-CONF-01: splicing twice adds nothing; each extra check follows the last entry of its section."""
    reg = [("1.1", "1 — CC Portal", "a", None), ("2.1", "2 — Other", "b", None)]
    once = ze.splice(reg)
    assert ze.splice(once) == once and [e[0] for e in once].index("1.15") == 1


def test_flatten_profile_tolerates_a_broken_policy_extension_and_nested_policies():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-12: a policy extension that is not JSON is ignored; platform sub-policies fill only what the top level lacks."""
    f = ze.flatten_profile({"policyExtension": "{not json", "windowsPolicy": {"wfpDriver": 1, "name": "inner"}, "name": "outer"})
    assert f["wfpDriver"] == 1 and f["name"] == "outer"


# ═══ ZDX handlers, read-back and Undo (ops_zdx) ═══════════════════════════

import json  # noqa: E402


def _run(client, items=()):
    return ao._Run(client, {"items": list(items), "groups": []}, lambda m: None, "Jane Doe")


def test_a_collection_created_meanwhile_is_used_not_duplicated(zdx):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-06: the collection handler re-reads first; one that appeared since the preview is reused."""
    fake, client = zdx
    run = _run(client)
    u = {"status": "change"}
    zx._h_collection(run, {"target": {"kind": "custom", "body": {"name": "custom apps collection"}}}, [u])
    assert u["status"] == "noop" and fake.writes == [] and zx._ctx(run)["collections"]["custom"]["id"] == 1


def test_a_probe_renamed_or_gone_before_its_delete_is_left_alone(zdx):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-06: a probe deleted meanwhile is a no-op and one renamed meanwhile is a conflict; nothing is sent."""
    fake, client = zdx
    app = fake.add_app("Wiki")
    m = fake.add_mon(app, "Wiki Web probe", url="https://wiki.example.com/")
    gone, renamed = {"status": "change"}, {"status": "change"}
    zx._h_delete_probe(_run(client), {"target": {"app": app["id"], "probe": 1, "name": "x"}}, [gone])
    zx._h_delete_probe(_run(client), {"target": {"app": app["id"], "probe": m["id"], "name": "Old name"}}, [renamed])
    assert gone["status"] == "noop" and renamed["status"] == "conflict" and fake.writes == []


def test_an_app_gone_or_renamed_before_its_delete_is_left_alone(zdx):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-06: an app already gone (404) is a no-op; one renamed meanwhile is a conflict."""
    fake, client = zdx
    app = fake.add_app("Wiki")
    u1 = [{"kind": "zdx_app", "status": "change", "object": {}}]
    u2 = [{"kind": "zdx_app", "status": "change", "object": {}}]
    zx._h_delete_app(_run(client), {"target": {"app": 999, "name": "Gone", "probes": []}}, u1)
    zx._h_delete_app(_run(client), {"target": {"app": app["id"], "name": "Old", "probes": []}}, u2)
    assert u1[0]["status"] == "noop" and u2[0]["status"] == "conflict" and fake.writes == []


def test_a_refused_probe_delete_keeps_the_app(zdx):
    """ASVS V11.1.1 · A04:2021 · CWE-460 · WSTG-BUSL-06: when one of the app's probes cannot be deleted, the app itself is not attempted."""
    fake, client = zdx
    app = fake.add_app("Wiki")
    m = fake.add_mon(app, "Wiki Web probe", url="https://wiki.example.com/")
    fake.fail = {("DELETE", f"/monitors/{m['id']}"): ApiError(500, "ERR", "busy")}
    units = [{"kind": "zdx_probe", "status": "change", "object": {"probe": m["id"], "name": m["name"]}},
             {"kind": "zdx_app", "status": "change", "object": {}}]
    zx._h_delete_app(_run(client), {"target": {"app": app["id"], "name": "Wiki", "probes": [{"id": m["id"]}]}}, units)
    assert units[0]["status"] == "failed" and units[1]["status"] == "skipped" and app in fake.apps


def test_a_predefined_app_without_its_probes_reports_what_zdx_did_not_create(zdx):
    """ASVS V11.1.1 · A04:2021 · CWE-754 · WSTG-ERRH-01: when ZDX makes no probes for a predefined app, turning them on fails with a plain reason."""
    fake, client = zdx
    real = fake._route

    def route(m, p, body, params):
        out = real(m, p, body, params)
        if m == "POST" and p == "/applications" and body["type"] == "PREDEFINED":
            fake.mons.clear()
        return out
    fake._route = route
    res = zdx_apply(fake, client, dict(BEST, custom=[]))
    failed = [u for u in res["items"] if u["status"] == "failed"]
    assert len(failed) == 2 and all("did not create" in u["error"] for u in failed)
    assert any(a["type"] == "PREDEFINED" and a["active"] for a in fake.apps)


def test_the_read_back_marks_everything_unread_when_zdx_cannot_be_read(zdx):
    """ASVS V7.4.1 · A09:2021 · CWE-754 · WSTG-ERRH-01: if the read-back fails, every item is unverified (None), never confirmed."""
    fake, client = zdx
    run = _run(client, [{"key": "z1", "group": "g1", "status": "applied", "kind": "zdx_app", "object": {"name": "x"}, "field": "exists", "after": True}])
    fake.fail = {("GET", "/monitors"): ApiError(503, None, "down")}
    out = zx.verify(run)
    assert out["confirmed"] == 0 and out["unread"] and run.p["items"][0]["verified"] is None


def test_the_undo_of_a_state_change_is_the_opposite_change():
    """ASVS V11.1.1 · CWE-754 · WSTG-BUSL-06: each probe or app turned on is turned off again by Undo, and the other way round."""
    inv = zx.inverse({"type": zx.T_STATE, "items": [{"status": "applied", "after": "on", "object": {"app": 5, "probe": 9}},
                                                    {"status": "applied", "after": "off", "object": {"app": 6, "probe": None}}]})
    assert inv == {"type": zx.T_STATE, "targets": [{"app": "5", "probe": "9", "to": "off"}, {"app": "6", "probe": None, "to": "on"}]}
    assert zx.inverse({"type": zx.T_DELETE, "items": [{"status": "applied"}]}) is None


@pytest.mark.parametrize("body, want", [(b'{"id": 5}', {"id": 5}), ("", {}), ("not json", {}), (None, {})])
def test_zdx_answers_as_bytes_text_or_nothing_are_read_defensively(body, want):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-12: a body as bytes, text, invalid JSON or no response at all is read without a crash."""
    class Ex:
        def create_request(self, *a, **k):
            return {}, None

        def execute(self, req):
            return (None if body is None else Resp(body)), None
    api = zx.ZdxApi(type("C", (), {"zdx": type("Z", (), {"_request_executor": Ex()})()})())
    assert api.send("POST", "/applications", {}) == (want, None)


def test_an_executor_that_raises_is_a_refusal_not_a_crash():
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: an exception inside the executor becomes a short error, never an exception."""
    class Ex:
        def create_request(self, *a, **k):
            raise TimeoutError("slow")
    api = zx.ZdxApi(type("C", (), {"_request_executor": Ex()})())
    assert api.send("POST", "/collections", {})[1]["message"] == "TimeoutError: slow"
    assert zx.ZdxApi(object()).send("GET", "/applications")[1]["message"].startswith("this sign-in has no ZDX access")
