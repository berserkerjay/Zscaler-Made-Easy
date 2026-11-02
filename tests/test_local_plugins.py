"""Local plugins (local_plugins): off by default, loaded only when the
folder's exact SHA-256 is on the admin's allow-list, through a narrow API
(Bulk changes operations and read-only pages) that never bypasses the
engine's gates. The example plugin in docs/plugins is used as the package;
fakes only, no network."""
from __future__ import annotations

import builtins
import copy
import json
import os
import shutil

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import local_plugins as lp
import pack_channels as pc

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "plugins", "example_rule_counter")
NAME = "example_rule_counter"


@pytest.fixture()
def pdir(tmp_path, monkeypatch):
    d = tmp_path / "plugins"
    d.mkdir()
    shutil.copytree(EXAMPLE, d / NAME)
    monkeypatch.setenv(lp.ENV_DIR, str(d))
    monkeypatch.setenv("DLP_CHECK_PLUGINS_FILE", str(tmp_path / "plugins.json"))
    yield d
    for n in list(lp.LOADED):
        lp.unload(n)
    if hasattr(builtins, "_zme_plugin_ran"):
        delattr(builtins, "_zme_plugin_ran")


def _approve(d, users=None):
    rows = {r["name"]: r for r in lp.discover()}
    lp.approve(NAME, rows[NAME]["sha256"], by="admin", confirm=NAME, users=users)


def _mark_code(d):
    """Make the plugin's code leave a mark when it runs, so a test can tell it never ran."""
    p = d / NAME / "__init__.py"
    p.write_text("import builtins\nbuiltins._zme_plugin_ran = True\n" + p.read_text())


def test_plugins_are_off_by_default_and_the_example_is_not_loaded(tmp_path, monkeypatch):
    """ASVS V14.1.1 · CWE-1188 · CWE-829: no folder configured and the switch off: nothing is discovered or loaded, the example included."""
    monkeypatch.delenv(lp.ENV_DIR, raising=False)
    monkeypatch.setenv("DLP_CHECK_PLUGINS_FILE", str(tmp_path / "plugins.json"))
    assert lp.enabled() is False and lp.discover() == []
    assert lp.load_enabled() == {"loaded": [], "refused": []}
    assert not any(t.startswith("plugin_") for t in ao.types())
    with pytest.raises(lp.PluginError, match="off"):
        lp.load(NAME)


def test_an_unlisted_plugin_is_refused_and_its_code_never_runs(pdir):
    """ASVS V10.3.2 · V14.2.4 · CWE-494 · CWE-829: a plugin not on the allow-list is listed as not approved and never imported."""
    _mark_code(pdir)
    lp.set_enabled(True)
    row = next(r for r in lp.discover() if r["name"] == NAME)
    assert row["status"] == "not_approved" and len(row["sha256"]) == 64 and row["permissions"] == ["operations", "pages"]
    with pytest.raises(lp.PluginError, match="allow-list"):
        lp.load(NAME)
    assert lp.load_enabled()["loaded"] == []
    assert not hasattr(builtins, "_zme_plugin_ran")


def test_a_plugin_modified_after_approval_is_refused(pdir):
    """ASVS V10.3.2 · V14.2.4 · CWE-494 · CWE-345: one changed byte (or one added file) after approval changes the hash: refused, not run."""
    lp.set_enabled(True)
    _approve(pdir)
    _mark_code(pdir)
    row = next(r for r in lp.discover() if r["name"] == NAME)
    assert row["status"] == "changed"
    with pytest.raises(lp.PluginError, match="changed since it was approved"):
        lp.load(NAME)
    out = lp.load_enabled()
    assert out["loaded"] == [] and out["refused"][0]["name"] == NAME
    assert not hasattr(builtins, "_zme_plugin_ran")
    # An extra file is a change too.
    (pdir / NAME / "__init__.py").write_text((pdir / NAME / "__init__.py").read_text().split("\n", 2)[2])
    assert next(r for r in lp.discover() if r["name"] == NAME)["status"] == "approved"
    (pdir / NAME / "extra.py").write_text("x = 1\n")
    assert next(r for r in lp.discover() if r["name"] == NAME)["status"] == "changed"


def test_approval_needs_the_typed_name_and_the_hash_the_admin_saw(pdir):
    """ASVS V4.1.5 · V11.1.1 · CWE-367: approving needs the plugin's name typed and the exact current hash."""
    row = next(r for r in lp.discover() if r["name"] == NAME)
    with pytest.raises(lp.PluginError, match="Type the plugin's name"):
        lp.approve(NAME, row["sha256"], by="admin", confirm="yes")
    with pytest.raises(lp.PluginError, match="changed since you looked"):
        lp.approve(NAME, "0" * 64, by="admin", confirm=NAME)
    assert lp.settings()["approved"] == {}


@pytest.mark.parametrize("bad,why", [
    ({"plugin.json": json.dumps({"name": "other", "version": "1", "permissions": ["pages"]})}, "folder's name"),
    ({"plugin.json": json.dumps({"name": NAME, "version": "1", "permissions": ["network"]})}, "permissions"),
    ({"run.sh": "#!/bin/sh\n"}, "not an allowed file"),
])
def test_a_package_outside_the_rules_is_refused(pdir, bad, why):
    """ASVS V12.1.1 · CWE-434 · CWE-20: a wrong manifest, an unknown permission or another kind of file refuses the package."""
    for fn, text in bad.items():
        (pdir / NAME / fn).write_text(text)
    row = next(r for r in lp.discover() if r["name"] == NAME)
    assert row["status"] == "refused" and why in row["reason"]


def test_a_symlinked_file_is_refused(pdir, tmp_path):
    """ASVS V12.3.1 · CWE-59: a link inside a plugin folder is refused (links are never followed)."""
    target = tmp_path / "elsewhere.py"
    target.write_text("x = 1\n")
    os.symlink(target, pdir / NAME / "linked.py")
    row = next(r for r in lp.discover() if r["name"] == NAME)
    assert row["status"] == "refused" and "plain file" in row["reason"]


class _Tenant:
    def __init__(self):
        from test_ops_zia_baseline import Rules
        self.reads, self.writes = [], []
        z = type("Zia", (), {})()
        z.cloud_firewall_rules = Rules(self, "cloud_firewall_rules", [
            {"id": 21, "name": "Default Firewall Filtering Rule", "order": -1, "default_rule": True, "action": "ALLOW"},
            {"id": 31, "name": "tmp-allow-a", "order": 1, "action": "ALLOW", "state": "ENABLED"},
            {"id": 32, "name": "tmp-allow-b", "order": 2, "action": "ALLOW", "state": "ENABLED"},
            {"id": 33, "name": "keep-me", "order": 3, "action": "ALLOW", "state": "ENABLED"}])
        self.zia, self.zpa = z, None


SCOPE = ao.scope_for(["dlp", "zia_extras"], {"web_dlp": "zscaler"})


@pytest.fixture()
def _no_activation(monkeypatch):
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


def test_an_approved_plugin_adds_an_operation_that_goes_through_every_gate(pdir, _no_activation):
    """ASVS V1.4.1 · V4.1.5 · CWE-862: the plugin's operation is previewed with a plan hash and applies only with write mode and an assessor."""
    lp.set_enabled(True)
    _approve(pdir)
    info = lp.load(NAME)
    t_name = "plugin_example_rule_counter_disable"
    assert info["types"] == [t_name] and t_name in ao.types() and ao.product_of(t_name) == "zia"
    t = _Tenant()
    spec = {"type": t_name, "name_prefix": "tmp-"}
    p = ao.plan(t, spec, scope=SCOPE, tenant_label="acme")
    assert p["status"] == "ready" and p["counts"]["change"] == 2 and t.writes == []
    assert all(g["handler"].startswith("plg_example_rule_counter_") for g in p["groups"])
    with pytest.raises(PermissionError):
        ao.execute(t, spec, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=False, assessor="Jane", confirm_text="")
    with pytest.raises(ao.OperationError, match="assessor"):
        ao.execute(t, spec, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="", confirm_text="")
    assert t.writes == []
    res = ao.execute(t, spec, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="Jane", confirm_text=p["confirm_phrase"],
                     settle_seconds=0)
    assert res["status"] != "plan_changed", res.get("status")
    states = {r["name"]: r["state"] for r in t.zia.cloud_firewall_rules.rows if r["id"] != 21}
    assert states == {"tmp-allow-a": "DISABLED", "tmp-allow-b": "DISABLED", "keep-me": "ENABLED"}
    # Out of scope: refused before anything is read.
    with pytest.raises(ao.OperationError, match="Not in scope"):
        ao.plan(_Tenant(), spec, scope=ao.scope_for([], {}))


def test_a_plugin_planning_with_a_write_is_stopped_by_the_read_only_client():
    """ASVS V1.4.1 · CWE-269 · CWE-250: the client a plugin plans with refuses every write and every private attribute."""
    t = _Tenant()
    ro = lp.ReadOnly(t)
    assert ro.zia.cloud_firewall_rules.list_rules()[0]
    with pytest.raises(PermissionError, match="not a read"):
        ro.zia.cloud_firewall_rules.update_rule(31, state="DISABLED")
    with pytest.raises(PermissionError, match="not a read"):
        ro.zia.cloud_firewall_rules.delete_rule(31)
    with pytest.raises(PermissionError):
        ro.zia.cloud_firewall_rules._find
    with pytest.raises(PermissionError):
        ro.zia = None
    assert t.writes == []


def test_a_plugin_write_outside_an_apply_is_refused(pdir):
    """ASVS V1.4.1 · CWE-862: run.create / update / delete work only inside an apply the engine started."""
    class _R:
        client = zia = object()
        zpa = None
        log = staticmethod(lambda m: None)
        assessor, units = "Jane", {}
    with pytest.raises(PermissionError, match="inside an apply"):
        lp.PluginRun(_R(), "zia").update("policy", 31, {"state": "DISABLED"}, channel="firewall")


def test_permissions_not_asked_for_are_refused():
    """ASVS V1.4.4 · CWE-250: a plugin that asked only for pages cannot register an operation."""
    api = lp.PluginAPI("onlypages", {"pages"})
    with pytest.raises(lp.PluginError, match="operations"):
        api.add_operation("x_op", label="x", hint="x", product="zia", plan=lambda *a: {}, read_objects=lambda *a: {}, handlers={"h_x": lambda *a: None})
    with pytest.raises(lp.PluginError, match="product"):
        lp.PluginAPI("p2", {"operations"}).add_operation("ok_op", label="x", hint="x", product="tenant_admin", plan=lambda *a: {},
                                                         read_objects=lambda *a: {}, handlers={"h_x": lambda *a: None})


def test_per_user_enablement(pdir):
    """ASVS V4.1.3 · V4.2.1 · CWE-285: an approval naming people lets only them use the plugin's operations and pages."""
    lp.set_enabled(True)
    _approve(pdir, users=["alice@example.test"])
    lp.load(NAME)
    t_name = "plugin_example_rule_counter_disable"
    assert lp.check_user({"type": t_name}, "alice@example.test") is None
    assert "not enabled for you" in lp.check_user({"type": t_name}, "bob@example.test")
    assert lp.check_user({"type": "rule_state"}, "bob@example.test") is None, "built-in types are not affected"
    slug = lp.LOADED[NAME]["pages"][0]
    assert lp.render_page(slug, "alice@example.test")["columns"] == ["Operation type", "Product"]
    with pytest.raises(PermissionError):
        lp.render_page(slug, "bob@example.test")


def test_plugin_page_output_is_reduced_to_text():
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-01: a page's cells are capped text; the page escapes them (no HTML from the plugin)."""
    lp.PAGES["t-x"] = {"slug": "t-x", "plugin": "", "title": "T", "render": lambda: {"columns": ["<b>c</b>"], "rows": [["\x1b[31m<script>x</script>" + "a" * 900]]}}
    try:
        lp.LOADED[""] = {"users": []}
        out = lp.render_page("t-x", None)
        assert len(out["rows"][0][0]) == lp.MAX_CELL and "\x1b" not in out["rows"][0][0]
    finally:
        lp.PAGES.pop("t-x", None)
        lp.LOADED.pop("", None)
    page = open(os.path.join(os.path.dirname(EXAMPLE), "..", "..", "static", "report_plugin.html"), encoding="utf-8").read()
    script = page.split("<script>", 1)[1]
    assert "innerHTML" not in script and "textContent" in script


def test_the_api_lists_plugins_and_approval_is_for_a_writer_on_this_computer(pdir, monkeypatch):
    """ASVS V4.1.1 · V4.1.5 · CWE-306 · WSTG-ATHZ-02: GET /api/plugins lists name, version, hash and permissions; approval needs the typed name."""
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.headers.update({security.UI_TOKEN_HEADER: security.ui_token()})
    d = c.get("/api/plugins").json()
    row = next(r for r in d["plugins"] if r["name"] == NAME)
    assert d["enabled"] is False and row["status"] == "not_approved" and len(row["sha256"]) == 64 and "folder" in d
    assert str(pdir) not in json.dumps(d), "only the folder's name is shown"
    r = c.post("/api/plugins/approve", json={"name": NAME, "sha256": row["sha256"], "confirm": "no"})
    assert r.status_code == 400
    r = c.post("/api/plugins/approve", json={"name": NAME, "sha256": row["sha256"], "confirm": NAME})
    assert r.status_code == 200 and next(x for x in r.json()["plugins"] if x["name"] == NAME)["status"] == "approved"
    monkeypatch.setattr(security, "may_write", lambda: False)
    assert c.post("/api/plugins/revoke", json={"name": NAME}).status_code == 403
    assert c.put("/api/plugins/settings", json={"enabled": True}).status_code == 403
