"""Client Connector profiles on the Bulk changes engine (ops_zcc): the build
and delete plugin types, the full portal payloads, the read-back, the
rollback, Undo, and the install command builder on the fleet page.

No tenant, no network, no clock: FakeZcc stands in for the SDK's zcc
services (the same method names and (result, response, error) tuples as
zscaler-sdk-python 1.11.3) and records every call. State files live in
tmp_path."""
from __future__ import annotations

import copy
import json
import os
import re

import pytest
from conftest import read_store_text

import admin_ops as ao
import ops_zcc as oz

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZCC_SCOPE = ao.scope_for(["zcc"], {})
NO_ZCC = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
ASSESSOR = "Jane Doe"


# ── The fake SDK (zcc services only) ────────────────────────────────────

class Resp:
    def __init__(self, body):
        self._body = body

    def get_body(self):
        return self._body


class _Svc:
    def __init__(self, fake):
        self.f = fake


class FwdSvc(_Svc):
    def list_by_company(self, query_params=None):
        self.f.calls.append(("GET", "forwarding", dict(query_params or {})))
        rows = [copy.deepcopy(v) for v in self.f.fwd.values()] if (query_params or {}).get("page", 1) == 1 else []
        return rows, Resp(rows), None

    def update_forwarding_profile(self, **kw):
        self.f.calls.append(("POST", "forwarding/edit", kw.get("name")))
        self.f.sent.append(("forwarding", copy.deepcopy(kw)))
        if self.f.refuse_forwarding:
            return None, Resp({"success": "false"}), None
        fid = self.f.new_id()
        self.f.fwd[fid] = dict(copy.deepcopy(kw), id=fid)
        return {"id": fid}, Resp({"success": "true", "id": fid}), None

    def delete_forwarding_profile(self, profile_id):
        self.f.calls.append(("DELETE", "forwarding", str(profile_id)))
        self.f.fwd.pop(str(profile_id), None)
        return None, Resp({"success": "true"}), None


class AppSvc(_Svc):
    def list_by_company(self, query_params=None):
        q = dict(query_params or {})
        self.f.calls.append(("GET", "app", q.get("device_type")))
        if q.get("page", 1) != 1:
            return [], Resp([]), None
        rows = [copy.deepcopy(v) for (plat, _i), v in self.f.apps.items() if plat == q.get("device_type")]
        return rows, Resp(rows), None

    def web_policy_edit(self, **kw):
        self.f.calls.append(("PUT", "app/edit", kw.get("name")))
        self.f.sent.append(("app", copy.deepcopy(kw)))
        if self.f.refuse_app:
            return None, Resp({"success": "false"}), None
        plat = {3: "windows", 4: "macos"}[kw["device_type"]]
        aid = self.f.new_id()
        self.f.apps[(plat, aid)] = dict(copy.deepcopy(kw), id=aid)
        return {}, Resp({"success": "true"}), None    # no id: the builder finds it by name

    def delete_web_policy(self, policy_id):
        self.f.calls.append(("DELETE", "app", str(policy_id)))
        for k in [k for k in self.f.apps if k[1] == str(policy_id)]:
            self.f.apps.pop(k)
        return None, Resp({"success": "true"}), None


class AppServices(_Svc):
    def list_by_company(self, query_params=None):
        self.f.calls.append(("GET", "app_services", None))
        rows = [{"id": 3, "appName": "Microsoft Teams"}, {"id": 5, "appName": "Zoom Meetings"},
                {"id": 13, "appName": "Windows 365 & Azure Virtual Desktop"}] if (query_params or {}).get("page", 1) == 1 else []
        return rows, Resp(rows), None


class AppProfiles(_Svc):
    def get_application_profile(self, profile_id):
        self.f.calls.append(("GET", "application-profiles", str(profile_id)))
        return {}, Resp({"id": profile_id, "policyToken": self.f.token}), None


class Zcc:
    def __init__(self, fake):
        self.forwarding_profile = FwdSvc(fake)
        self.web_policy = AppSvc(fake)
        self.web_app_service = AppServices(fake)
        self.application_profiles = AppProfiles(fake)


class FakeSdk:
    def __init__(self):
        self.fwd, self.apps, self.calls, self.sent = {}, {}, [], []
        self.refuse_app = self.refuse_forwarding = False
        self.token = "CANARYpolicyToken42"
        self._n = 7000
        self.zcc = Zcc(self)

    def new_id(self):
        self._n += 1
        return str(self._n)

    def writes(self):
        return [c for c in self.calls if c[0] in ("POST", "PUT", "DELETE")]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    import pack_ops
    monkeypatch.setattr(pack_ops, "_sleep", lambda s: None, raising=False)
    ao.load_plugins()


def spec(**kw):
    s = {"type": oz.BUILD, "platform": "windows", "forwarding": {"template": "best_practice", "name": "QA forwarding"},
         "app": {"template": "best_practice", "name": "QA Windows"}}
    s.update(kw)
    return s


def build(sdk, s=None):
    s = s or spec()
    p = ao.plan(sdk, s, scope=ZCC_SCOPE, tenant_label="acme")
    return p, ao.execute(sdk, s, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"],
                         assessor=ASSESSOR, tenant_label="acme", settle_seconds=0)


# ── Catalog and payloads ────────────────────────────────────────────────

def test_every_setting_shows_its_value_the_portal_default_and_a_plain_explanation():
    """WCAG 2.2 SC 3.3.2 · ASVS V1.1.2: every setting the builder can write names its value, the portal default and what it does."""
    cat = oz.catalog()
    rows = cat["forwarding"]["settings"] + cat["app"]["windows"]["settings"] + cat["app"]["macos"]["settings"]
    assert len(rows) >= 30
    for r in rows:
        assert r["value"] and r["portal_default"] and len(r["explain"]) >= 40, r
        assert r["label"][0].isupper() or r["label"][0].isdigit(), r["label"]


def test_the_best_practice_forwarding_template_covers_the_listed_settings():
    """ASVS V1.1.2: best practice = tunnel everywhere, listening-proxy redirect, Z-Tunnel 2.0, drop IPv6, latency ZEN, PAC off, ZPA VPN-trusted and latency."""
    keys = set(oz.FWD_TEMPLATES["best_practice"]["settings"])
    assert keys == {"zia_tunnel", "redirect_web", "tunnel2_proxied", "drop_ipv6", "drop_ipv6_only", "latency_zen", "system_pac_off",
                    "zpa_vpn_trusted", "zpa_latency"}
    assert oz.FWD_TEMPLATES["portal_default"]["settings"] == []


@pytest.mark.parametrize("setting", oz.FWD_SETTINGS, ids=[s.key for s in oz.FWD_SETTINGS])
def test_each_forwarding_setting_changes_the_portal_default_and_is_read_back(setting):
    """ASVS V11.1.1 · CWE-354: each forwarding setting's check fails on the portal default and passes once the setting is applied."""
    body = oz.forwarding_body("QA")
    assert setting.verify(body, {}) is False
    setting.apply(body, {})
    assert setting.verify(body, {}) is True


@pytest.mark.parametrize("plat,setting", [(p, s) for p in oz.PLATFORMS for s in oz.APP_SETTINGS[p]],
                         ids=[f"{p}-{s.key}" for p in oz.PLATFORMS for s in oz.APP_SETTINGS[p]])
def test_each_app_setting_changes_the_portal_default_and_is_read_back(plat, setting):
    """ASVS V11.1.1 · CWE-354: each app profile setting's check fails on the portal default and passes once applied."""
    ctx = {"app_ids": [3, 5]}
    body = oz.app_body(plat, "QA", rule_order=1)
    assert setting.verify(body, ctx) is False
    setting.apply(body, ctx)
    assert setting.verify(body, ctx) is True


@pytest.mark.parametrize("plat", list(oz.PLATFORMS))
def test_the_full_portal_payload_survives_the_sdk_serializer_unchanged(plat):
    """ASVS V5.1.1 · CWE-20: the SDK's ZCC serializer (zcc_to_wire) sends the portal-shaped bodies key for key as built."""
    from zscaler.zcc._serialize import zcc_to_wire
    from zscaler.zcc.models.forwardingprofile import ForwardingProfile
    from zscaler.zcc.models.webpolicy import WebPolicy
    s = oz.normalize_spec(spec(platform=plat, app={"template": "best_practice", "name": "QA"}))
    fwd, app = oz.build_bodies(s, rule_order=3, ctx={"app_ids": [3]})
    assert json.loads(json.dumps(zcc_to_wire(fwd, ForwardingProfile))) == fwd
    assert json.loads(json.dumps(zcc_to_wire(app, WebPolicy))) == app


def test_new_profiles_are_disabled_and_carry_no_password():
    """ASVS V1.4.1 · CWE-1188 · CWE-256: by default both bodies are created disabled, and no password or passcode field holds a value."""
    s = oz.normalize_spec(spec())
    fwd, app = oz.build_bodies(s, rule_order=1, ctx={"app_ids": []})
    assert fwd["active"] == 0 and app["active"] == "0" and fwd["id"] == "-1"

    def secrets(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from secrets(v, f"{path}.{k}")
        elif isinstance(node, list):
            for v in node:
                yield from secrets(v, path)
        elif re.search(r"pass(word|code)$", path, re.I) and isinstance(node, str) and node:
            yield path
    assert list(secrets(app)) == [] and list(secrets(fwd)) == []


@pytest.mark.parametrize("bad", ["", " ", "x" * 65, "-lead", "semi;colon", "quote\"", "new\nline"])
def test_profile_names_are_validated(bad):
    """ASVS V5.1.3 · CWE-20: a name that is empty, too long or carries control or shell characters is refused in words."""
    with pytest.raises(oz.BuilderError):
        oz.normalize_spec(spec(app={"template": "best_practice", "name": bad}))


# ── Scope, preview, gates ───────────────────────────────────────────────

@pytest.mark.parametrize("op", [spec(), {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "1", "name": "x"}]}], ids=["build", "delete"])
def test_out_of_scope_is_refused_before_anything_is_read(op):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZCC ticked, preview and the object picker are refused before any read."""
    sdk = FakeSdk()
    with pytest.raises(ao.OperationError, match="ZCC"):
        ao.plan(sdk, op, scope=NO_ZCC)
    with pytest.raises(ao.OperationError, match="ZCC"):
        ao.read_objects(sdk, oz.FAMILY, NO_ZCC)
    assert sdk.calls == []


def test_the_picker_lists_profiles_and_templates_without_writing():
    """ASVS V1.4.1 · CWE-200: the object list is names, ids, state and links (no setting value), and nothing is written."""
    sdk = FakeSdk()
    sdk.fwd["11"] = dict(oz.forwarding_body("Corp"), id="11")
    sdk.apps[("windows", "21")] = dict(oz.app_body("windows", "Corp Win", rule_order=1, forwarding_profile_id=11), id="21")
    out = ao.read_objects(sdk, oz.FAMILY, ZCC_SCOPE)
    inv = out["inventory"]
    assert inv["forwarding"] == [{"kind": "forwarding", "id": "11", "name": "Corp", "active": False, "used_by": 1}]
    assert inv["app"]["windows"][0]["forwarding_profile_id"] == "11" and "catalog" in out
    assert sdk.writes() == []


def test_the_preview_lists_every_setting_and_call_and_writes_nothing():
    """ASVS V1.4.1 · CWE-841: the preview has one item per setting (value, portal default, explanation), each call in words, a typed phrase and a hash."""
    sdk = FakeSdk()
    p = ao.plan(sdk, spec(), scope=ZCC_SCOPE)
    assert p["status"] == "ready" and len(p["plan_hash"]) == 64 and p["confirm_phrase"] == "CREATE QA WINDOWS"
    settings = [u for u in p["items"] if u["kind"] == "zcc_setting"]
    assert len(settings) == len(oz.FWD_SETTINGS) + len(oz.WINDOWS_SETTINGS)
    assert all(u["before"] and u["after"] and u["reason"] for u in settings)
    assert any("webForwardingProfile/edit" in n for n in p["notes"]) and any("web/policy/edit" in n for n in p["notes"])
    assert [g["handler"] for g in p["groups"]] == ["zcc_create_forwarding", "zcc_create_app"]
    assert sdk.writes() == []


def test_a_name_already_taken_blocks_the_build():
    """ASVS V11.1.1 · CWE-694: an app or forwarding profile name already in the tenant blocks the preview; nothing is overwritten."""
    sdk = FakeSdk()
    sdk.fwd["11"] = dict(oz.forwarding_body("QA forwarding"), id="11")
    p = ao.plan(sdk, spec(), scope=ZCC_SCOPE)
    assert p["status"] == "blocked" and "already exists" in " ".join(p["blockers"])
    res = ao.execute(sdk, spec(), plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text="CREATE QA WINDOWS",
                     assessor=ASSESSOR)
    assert res["status"] == "blocked" and sdk.writes() == []


def test_apply_refuses_without_write_mode_a_stale_hash_or_the_typed_name():
    """ASVS V4.1.3 · V11.1.1 · CWE-862 · CWE-841: write mode off, a stale preview or a wrong typed phrase each write nothing."""
    sdk = FakeSdk()
    p = ao.plan(sdk, spec(), scope=ZCC_SCOPE)
    with pytest.raises(PermissionError):
        ao.execute(sdk, spec(), plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=False, confirm_text="CREATE QA WINDOWS")
    stale = ao.execute(sdk, spec(), plan_hash="0" * 64, scope=ZCC_SCOPE, writes_enabled=True, confirm_text="CREATE QA WINDOWS", assessor=ASSESSOR)
    wrong = ao.execute(sdk, spec(), plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text="CREATE QA", assessor=ASSESSOR)
    assert stale["status"] == "plan_changed" and wrong["status"] == "refused" and sdk.writes() == []


# ── Apply, read-back, rollback ──────────────────────────────────────────

def test_the_build_creates_the_forwarding_profile_first_then_the_linked_app_profile_and_reads_back():
    """ASVS V11.1.1 · CWE-841 · CWE-354: forwarding profile, then the app profile linked to its new id, disabled; every setting read back."""
    sdk = FakeSdk()
    p, res = build(sdk)
    assert [c[:2] for c in sdk.writes()] == [("POST", "forwarding/edit"), ("PUT", "app/edit")]
    (fid, fwd), = sdk.fwd.items()
    (key, app), = sdk.apps.items()
    assert app["forwardingProfileId"] == int(fid) and app["active"] == "0" and fwd["active"] == 0
    assert app["appServiceIds"] == [3, 5, 13]     # resolved by name; SharePoint, Exchange and Microsoft 365 are not in this tenant
    assert any("Microsoft SharePoint" in w for w in p["warnings"])
    assert res["status"] == "applied", res.get("verification")
    v = res["verification"]
    assert v["checked"] == v["confirmed"] == p["counts"]["change"] and not v["mismatched"]
    assert res["inverse"] == {"type": oz.DELETE, "targets": [{"kind": "app", "id": key[1], "name": "QA Windows", "platform": "windows"},
                                                            {"kind": "forwarding", "id": fid, "name": "QA forwarding"}]}


def test_a_refused_app_profile_deletes_the_new_forwarding_profile_again():
    """ASVS V11.1.1 · CWE-460 · CWE-841: when the app profile is refused (HTTP 200, success false), the forwarding profile just created is deleted."""
    sdk = FakeSdk()
    sdk.refuse_app = True
    _p, res = build(sdk)
    assert [c[:2] for c in sdk.writes()] == [("POST", "forwarding/edit"), ("PUT", "app/edit"), ("DELETE", "forwarding")]
    assert sdk.fwd == {} and sdk.apps == {}
    assert res["status"] == "failed" and res["inverse"] is None
    statuses = {u["status"] for u in res["items"] if u["group"] == "g_fwd" and u["kind"] != "zcc_setting" or u["key"] == "fwd"}
    assert statuses == {oz.ROLLED_BACK}
    assert any("success false" in str(u.get("error")) for u in res["items"] if u["group"] == "g_app")


def test_a_refused_forwarding_profile_stops_before_the_app_profile():
    """ASVS V11.1.1 · CWE-841: if the forwarding profile is refused, the app profile is not attempted."""
    sdk = FakeSdk()
    sdk.refuse_forwarding = True
    _p, res = build(sdk)
    assert [c[:2] for c in sdk.writes()] == [("POST", "forwarding/edit")]
    assert all(u["status"] == "skipped" for u in res["items"] if u["group"] == "g_app" and u["kind"] != "zcc_setting" or u["key"] == "app")


def test_linking_to_an_existing_forwarding_profile_creates_only_the_app_profile():
    """ASVS V11.1.1 · CWE-841: with an existing forwarding profile picked, only the app profile is written, linked to it."""
    sdk = FakeSdk()
    sdk.fwd["11"] = dict(oz.forwarding_body("Corp"), id="11")
    s = spec(platform="macos", forwarding={"template": "existing", "id": "11"}, app={"template": "portal_default", "name": "QA Mac"})
    _p, res = build(sdk, s)
    assert [c[:2] for c in sdk.writes()] == [("PUT", "app/edit")]
    (_k, app), = sdk.apps.items()
    assert app["forwardingProfileId"] == 11 and app["device_type"] == 4 and res["status"] == "applied"


def test_an_existing_forwarding_profile_gone_since_the_preview_is_a_conflict():
    """ASVS V11.1.1 · CWE-367: the forwarding profile is re-read right before the write; gone means nothing is created."""
    sdk = FakeSdk()
    sdk.fwd["11"] = dict(oz.forwarding_body("Corp"), id="11")
    s = spec(forwarding={"template": "existing", "id": "11"})
    p = ao.plan(sdk, s, scope=ZCC_SCOPE)
    real = ao.plan

    def plan_then_delete(*a, **k):
        out = real(*a, **k)
        sdk.fwd.clear()
        return out
    ao_plan = ao.plan
    try:
        ao.plan = plan_then_delete
        res = ao.execute(sdk, s, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text=p["confirm_phrase"], assessor=ASSESSOR)
    finally:
        ao.plan = ao_plan
    assert sdk.writes() == [] and any(u["status"] == "conflict" for u in res["items"])


# ── Delete and Undo ─────────────────────────────────────────────────────

def test_undo_of_a_build_deletes_the_app_profile_then_the_forwarding_profile_with_the_typed_name():
    """ASVS V11.1.1 · V4.1.3 · CWE-841: Undo is a delete previewed and confirmed with the profile's typed name; both are gone and verified."""
    sdk = FakeSdk()
    _p, res = build(sdk)
    undo = res["inverse"]
    p = ao.plan(sdk, undo, scope=ZCC_SCOPE)
    assert p["status"] == "ready" and p["confirm_phrase"] == "QA WINDOWS"
    assert ao.execute(sdk, undo, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text="",
                      assessor=ASSESSOR)["status"] == "refused"
    out = ao.execute(sdk, undo, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text="qa windows", assessor=ASSESSOR)
    assert out["status"] == "applied" and sdk.fwd == {} and sdk.apps == {}
    assert [c[:2] for c in sdk.writes()][-2:] == [("DELETE", "app"), ("DELETE", "forwarding")]
    assert out["verification"]["confirmed"] == 2


def test_a_forwarding_profile_in_use_is_never_deleted():
    """ASVS V4.1.3 · CWE-672 · CWE-841: a forwarding profile that an app profile (any platform) links to is refused."""
    sdk = FakeSdk()
    sdk.fwd["11"] = dict(oz.forwarding_body("Corp"), id="11")
    sdk.apps[("macos", "21")] = dict(oz.app_body("macos", "Corp Mac", rule_order=1, forwarding_profile_id=11), id="21")
    op = {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "11", "name": "Corp"}]}
    p = ao.plan(sdk, op, scope=ZCC_SCOPE)
    assert p["status"] == "blocked" and "in use by Corp Mac (macos)" in p["blockers"][0]
    res = ao.execute(sdk, op, plan_hash=p["plan_hash"], scope=ZCC_SCOPE, writes_enabled=True, confirm_text="CORP", assessor=ASSESSOR)
    assert res["status"] == "blocked" and sdk.writes() == []


def test_an_enabled_app_profile_or_a_renamed_one_is_never_deleted():
    """ASVS V4.1.3 · CWE-672 · CWE-639: an enabled app profile, or one whose name is not the name given, is refused."""
    sdk = FakeSdk()
    sdk.apps[("windows", "21")] = dict(oz.app_body("windows", "Live", rule_order=1), id="21", active="1")
    sdk.apps[("windows", "22")] = dict(oz.app_body("windows", "Other", rule_order=2), id="22")
    on = ao.plan(sdk, {"type": oz.DELETE, "targets": [{"kind": "app", "id": "21", "name": "Live", "platform": "windows"}]}, scope=ZCC_SCOPE)
    renamed = ao.plan(sdk, {"type": oz.DELETE, "targets": [{"kind": "app", "id": "22", "name": "Live", "platform": "windows"}]}, scope=ZCC_SCOPE)
    assert on["status"] == "blocked" and "enabled" in on["blockers"][0]
    assert renamed["status"] == "blocked" and "its name is now" in renamed["blockers"][0]


def test_a_delete_of_a_profile_already_gone_writes_nothing():
    """ASVS V11.1.1 · CWE-841: boundary: a profile no longer in the tenant is 'already gone', nothing to change."""
    sdk = FakeSdk()
    p = ao.plan(sdk, {"type": oz.DELETE, "targets": [{"kind": "forwarding", "id": "99", "name": "Gone"}]}, scope=ZCC_SCOPE)
    assert p["status"] == "nothing_to_do" and sdk.writes() == []


def test_the_build_and_its_undo_are_recorded_and_audited_without_secrets(tmp_path):
    """ASVS V7.1.3 · V7.2.2 · CWE-778 · CWE-532: the change is recorded with Undo offered and audited per write; no token or password is written."""
    import deployments
    sdk = FakeSdk()
    _p, res = build(sdk)
    rec = ao.record(res, by=ASSESSOR, actor=None)
    assert rec and deployments.list_operations()[0]["can_undo"] is True
    log = read_store_text(tmp_path / "audit.log")
    assert log.count('"object_write"') >= 2 and '"zcc_app_profile"' in log
    assert "CANARY" not in log and "CANARY" not in read_store_text(tmp_path / "deployments.json")


# ── Install command builder ─────────────────────────────────────────────

VALUES = {"cloudName": "zscalertwo", "userDomain": "acme.example", "policyToken": "CANARYpolicyToken42", "strictEnforcement": True,
          "uninstallPassword": "CANARYpw-Secret", "deviceToken": "CANARYdeviceTok"}


@pytest.mark.parametrize("platform,installer", [("windows", "msi"), ("windows", "exe"), ("macos", "app")])
def test_install_commands_mask_every_secret_unless_revealed(platform, installer):
    """ASVS V8.3.4 · V7.1.1 · CWE-200 · CWE-312: tokens and passwords show as ******** in the command and script unless revealed."""
    masked = oz.install_commands(platform, installer, VALUES)
    text = json.dumps(masked)
    assert "CANARY" not in text and oz.MASK in masked["command"] and oz.MASK in masked["script"]
    assert "POLICYTOKEN" in masked["masked"] or "policyToken" in masked["masked"]
    shown = oz.install_commands(platform, installer, VALUES, reveal=True)
    assert "CANARYpolicyToken42" in shown["command"] and "CANARYpolicyToken42" in shown["script"] and shown["revealed"] is True
    assert masked["errors"] == [] and shown["errors"] == []


def test_install_command_shapes():
    """ASVS V5.3.8 · CWE-78: MSI properties, EXE flags and the macOS installbuilder.sh flags are built with quoting, scripts end in CRLF on Windows."""
    msi = oz.install_commands("windows", "msi", {"cloudName": "zscloud", "userDomain": "acme.example", "launchTray": False})
    assert msi["command"].startswith("msiexec /i Zscaler-windows-installer-x64.msi /qn") and "CLOUDNAME=zscloud" in msi["command"]
    assert "LAUNCHTRAY=0" in msi["command"] and msi["script"].endswith("\r\n") and msi["script_name"].endswith(".bat")
    exe = oz.install_commands("windows", "exe", {"cloudName": "zscloud"}, installer_name="ZCC 4.5.exe")
    assert exe["command"].startswith('"ZCC 4.5.exe" --mode unattended') and "--cloudName zscloud" in exe["command"]
    mac = oz.install_commands("macos", "app", {"cloudName": "zscloud", "userDomain": "acme.example"})
    assert "installbuilder.sh" in mac["command"] and "--userDomain 'acme.example'" in mac["command"] and mac["script_name"].endswith(".command")


@pytest.mark.parametrize("values,error", [
    ({"strictEnforcement": True}, "needs the cloud name"),
    ({"cloudName": "zscaler.net"}, "leave out .net"),
    ({"cloudName": "nocloud"}, "not a Zscaler cloud"),
    ({"userName": "jdoe"}, "needs the user domain"),
    ({"userDomain": 'acme" & calc'}, "cannot be passed"),
    ({"userDomain": "a\nb"}, "cannot be passed"),
    ({"userDomain": "%PATH%"}, "cannot be passed"),
])
def test_install_values_that_break_the_command_are_refused(values, error):
    """ASVS V5.3.8 · CWE-78 · CWE-88: values with quotes, line breaks or shell characters, and inconsistent options, are refused in words."""
    out = oz.install_commands("windows", "msi", values)
    assert any(error in e for e in out["errors"]), out["errors"]


@pytest.mark.parametrize("platform,installer,name", [("linux", "", ""), ("windows", "app", ""), ("windows", "msi", "a&b.msi")])
def test_install_platform_installer_and_file_name_are_validated(platform, installer, name):
    """ASVS V5.1.3 · CWE-20: an unknown platform, a wrong installer type or an unsafe file name is refused."""
    with pytest.raises(oz.BuilderError):
        oz.install_commands(platform, installer, {}, installer_name=name)


# ── Routes and pages ────────────────────────────────────────────────────

@pytest.fixture
def app(monkeypatch, tmp_path):
    for k in [k for k in os.environ if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    import dlp_api_server as srv
    sdk = FakeSdk()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or sdk)
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    from fastapi.testclient import TestClient
    return TestClient(srv.app), sdk, built


CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "not-a-real-secret"}
ZCC_PAGE = {"scopes": ["zcc"], "channels": {}, "from_page": True}


def test_the_install_route_without_a_profile_signs_in_to_nothing(app):
    """ASVS V1.4.1 · CWE-272: building a command from typed options reads no tenant."""
    c, _sdk, built = app
    r = c.post("/api/zcc/install", json={"platform": "windows", "installer": "msi", "values": {"cloudName": "zscloud"}})
    assert r.status_code == 200 and built == [] and r.headers["cache-control"] == "no-store"


def test_the_install_route_reads_the_policy_token_only_in_scope(app):
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: the policy token is read only when ZCC is ticked; otherwise 400 before sign-in."""
    c, _sdk, built = app
    r = c.post("/api/zcc/install", json=dict(CREDS, app_profile_id="21", scopes=["dlp"], channels={}, from_page=True))
    assert r.status_code == 400 and "scope" in r.text.lower() and built == []


def test_the_install_route_masks_the_token_and_the_audit_log_never_holds_it(app, tmp_path):
    """ASVS V7.1.1 · V8.3.4 · CWE-532 · CWE-200: the token read from the app profile is masked unless revealed, and no form of it reaches the audit log."""
    c, sdk, built = app
    body = dict(CREDS, **ZCC_PAGE, app_profile_id="21", platform="windows", installer="msi",
                values={"cloudName": "zscloud", "uninstallPassword": "CANARYpw-Secret"})
    masked = c.post("/api/zcc/install", json=body)
    shown = c.post("/api/zcc/install", json=dict(body, reveal=True))
    assert masked.status_code == 200 and "CANARY" not in masked.text and "POLICYTOKEN=********" in masked.json()["command"]
    assert "POLICYTOKEN=CANARYpolicyToken42" in shown.json()["command"]
    assert ("GET", "application-profiles", "21") in sdk.calls and sdk.writes() == []
    assert "CANARY" not in read_store_text(tmp_path / "audit.log")


def test_the_builder_is_offered_on_bulk_changes_with_its_form():
    """ASVS V14.3.3 · CWE-200: both types are in the plugin catalog with their form script, which registers both."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[oz.BUILD]["script"] == cat[oz.DELETE]["script"] == "ops_zcc.js" and cat[oz.BUILD]["group"] == "Build new"
    js = open(os.path.join(ROOT, "static", "ops_zcc.js"), encoding="utf-8").read()
    assert f"type: '{oz.BUILD}'" in js and f"type: '{oz.DELETE}'" in js and "OPS_PLUGINS.register" in js
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", js)


def test_the_fleet_page_holds_the_install_command_builder():
    """WCAG 2.2 SC 1.3.1 · SC 4.1.2: the install section is on the fleet page, with labelled inputs and a live status."""
    html = open(os.path.join(ROOT, "static", "report_fleet.html"), encoding="utf-8").read()
    js = open(os.path.join(ROOT, "static", "zcc_fleet.js"), encoding="utf-8").read()
    assert 'id="zfInstall"' in html and "/api/zcc/install" in js and "reveal" in js
    assert not os.path.exists(os.path.join(ROOT, "static", "report_zcc_builder.html"))
