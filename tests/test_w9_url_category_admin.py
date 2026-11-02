"""Rename or delete one custom URL category (ops_url_category_admin) on the
Bulk changes engine.

Runs against the fake ZIA tenant of tests/test_admin_ops.py (every write
logged, refused outright during a preview): no network, no clock, state in
tmp_path."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_url_category_admin as uc  # noqa: E402
import pack_channels as pc  # noqa: E402
from test_admin_ops import CATEGORIES, FULL_SCOPE, FakeCategories, FakeRules, Tenant, refused, ok, rule  # noqa: E402

ASSESSOR = "Jane Doe"
NO_URLS = ao.scope_for(["zpa"], {})


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    ao.load_plugins()
    return tmp_path, acts


class Categories(FakeCategories):
    """Full updates (action None) replace the category, as ZIA's PUT does."""

    def update_url_category(self, category_id, action=None, **kw):
        if action is not None:
            return FakeCategories.update_url_category(self, category_id, action, **kw)
        bad = self._write("update_url_category", category_id, dict(kw, action=action))
        if bad:
            return bad
        c = self._find(category_id)
        if c is None:
            return refused("not found", 404)
        keep = {"id": c["id"], "custom_category": True}
        c.clear()
        c.update(keep, **kw)
        return ok(c)


def tenant(categories=None):
    cats = categories if categories is not None else CATEGORIES + [
        {"id": "CUSTOM_03", "configured_name": "Unused list", "super_category": "USER_DEFINED", "custom_category": True,
         "urls": ["old.example.com", "legacy.example.net"], "keywords": ["legacy"], "description": "kept from 2024"}]
    t = Tenant(categories=[])
    t.zia.url_categories = Categories(t, cats)
    t.zia.cloud_firewall_dns = FakeRules(t, "cloud_firewall_dns", [rule(1101, "Block resolved", 1, res_categories=["CUSTOM_02"])])
    return t


def preview(t, spec, scope=FULL_SCOPE):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme")
    finally:
        t.frozen = False


def apply(t, spec, *, phrase=None, prepared=None):
    p = prepared or preview(t, spec)
    return p, ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase)


def test_registered_on_the_engine_under_change_with_its_form():
    """ASVS V1.14.1 · CWE-1059: rename and delete are one ZIA plugin type of the one engine, with its page script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[uc.TYPE]["product"] == "zia" and cat[uc.TYPE]["group"] == "Change" and cat[uc.TYPE]["script"] == "ops_url_category_admin.js"
    assert os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_url_category_admin.js"))


def test_out_of_scope_is_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without URL filtering in scope the plan and the picker are refused; nothing is read or written."""
    t = tenant()
    t.read_error = ("must not be read", 500)
    for spec in ({"type": uc.TYPE, "action": "delete", "id": "CUSTOM_03"}, {"type": uc.TYPE, "action": "rename", "id": "CUSTOM_03", "new_name": "x"}):
        with pytest.raises(ao.OperationError, match="URL filtering"):
            ao.plan(t, spec, scope=NO_URLS)
    with pytest.raises(ao.OperationError):
        ao.read_objects(t, uc.FAMILY, NO_URLS)
    assert t.writes == []


def test_the_picker_lists_each_category_with_the_rules_that_use_it():
    """ASVS V1.14.1 · CWE-1164: each custom category shows the rules in scope naming it (URL filtering, Web DLP, DNS resolved categories)."""
    out = ao.read_objects(tenant(), uc.FAMILY, FULL_SCOPE)
    by = {c["id"]: c for c in out["categories"]}
    assert "MUSIC" not in by     # predefined: never offered
    assert {r["name"] for r in by["CUSTOM_01"]["used_by"]} == {"Allow finance", "Web DLP - PHI"}
    assert {r["name"] for r in by["CUSTOM_02"]["used_by"]} == {"Block custom", "Block resolved"}
    assert by["CUSTOM_03"]["used_by"] == []


def test_rename_sends_the_category_as_read_with_only_the_name_changed_and_undo_renames_back(isolated):
    """ASVS V1.4.1 · CWE-841: payload oracle: a full update carrying every URL, keyword and the description, the name changed; read back; Undo restores the name."""
    tmp, acts = isolated
    t = tenant()
    p, r = apply(t, {"type": uc.TYPE, "action": "rename", "id": "CUSTOM_03", "new_name": "Legacy sites"})
    assert p["confirm_phrase"] == "" and r["status"] == "applied" and r["verification"]["confirmed"] == 1
    w = t.writes_of("update_url_category")
    assert w == [("url_categories", "update_url_category", "CUSTOM_03",
                  {"configured_name": "Legacy sites", "super_category": "USER_DEFINED", "urls": ["old.example.com", "legacy.example.net"],
                   "keywords": ["legacy"], "description": "kept from 2024", "custom_category": True, "action": None})]
    assert len(acts) == 1     # one ZIA activation
    rec = ao.record(r, by=ASSESSOR, actor="alice")
    assert r["inverse"] == {"type": uc.TYPE, "action": "rename", "id": "CUSTOM_03", "new_name": "Unused list"} and rec
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied" and t.zia.url_categories._find("CUSTOM_03")["configured_name"] == "Unused list"
    assert t.zia.url_categories._find("CUSTOM_03")["urls"] == ["old.example.com", "legacy.example.net"]


def test_rename_to_a_name_another_category_has_is_blocked():
    """ASVS V5.1.3 · CWE-694: two categories cannot share a name; the preview blocks it and nothing is sent."""
    t = tenant()
    p = preview(t, {"type": uc.TYPE, "action": "rename", "id": "CUSTOM_03", "new_name": "finance PARTNERS"})
    assert p["status"] == "blocked" and t.writes == []


def test_delete_is_refused_while_rules_use_the_category_and_lists_them():
    """ASVS V4.1.3 · CWE-672 · WSTG-BUSL-01: a category named by rules is never deleted; the preview names each rule (policy, order, name, state)."""
    t = tenant()
    p = preview(t, {"type": uc.TYPE, "action": "delete", "id": "CUSTOM_01"})
    assert p["counts"]["change"] == 0 and p["groups"] == []
    why = p["items"][0]["reason"]
    assert why.startswith("still used by") and "URL filtering rule 2 'Allow finance' (enabled)" in why and "Web DLP - PHI" in why
    assert {r["name"] for r in p["impact"][0]["rules"]} == {"Allow finance", "Web DLP - PHI"}
    p2 = preview(t, {"type": uc.TYPE, "action": "delete", "id": "CUSTOM_02"})
    assert "DNS Control rule 1 'Block resolved'" in p2["items"][0]["reason"]
    assert t.writes == []


def test_delete_needs_delete_and_the_name_typed_and_undo_creates_it_again(isolated):
    """ASVS V4.1.3 · CWE-862: DELETE <name> is the phrase; a wrong phrase sends nothing; the delete reads back gone; Undo re-creates it with its URLs."""
    t = tenant()
    spec = {"type": uc.TYPE, "action": "delete", "id": "CUSTOM_03"}
    p = preview(t, spec)
    assert p["confirm_phrase"] == "DELETE UNUSED LIST" and p["status"] == "ready"
    _p, r = apply(t, spec, phrase="DELETE", prepared=p)
    assert r["status"] == "refused" and t.writes == []
    _p, r = apply(t, spec, prepared=p)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1 and t.zia.url_categories._find("CUSTOM_03") is None
    assert t.writes_of("delete_category") == [("url_categories", "delete_category", "CUSTOM_03", {})]
    inv = r["inverse"]
    assert inv["action"] == "recreate" and ao.is_undo_only(inv)
    _p, r2 = apply(t, inv)
    assert r2["status"] == "applied"
    made = [c for c in t.zia.url_categories.rows if c["configured_name"] == "Unused list"][0]
    assert made["urls"] == ["old.example.com", "legacy.example.net"] and made["description"] == "kept from 2024" and made["id"] != "CUSTOM_03"


def test_delete_is_blocked_when_a_policy_that_can_name_it_is_not_in_scope():
    """ASVS V4.1.3 · CWE-863: deny by default: rules not in scope cannot be checked, so the delete is blocked and names what to tick."""
    t = tenant()
    narrow = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
    p = preview(t, {"type": uc.TYPE, "action": "delete", "id": "CUSTOM_03"}, scope=narrow)
    assert p["status"] == "blocked" and any("not in scope" in b for b in p["blockers"])
    assert t.writes == []


def test_a_category_changed_after_the_preview_is_not_deleted():
    """ASVS V11.1.4 · CWE-367: a URL added since the preview gives plan_changed; nothing is deleted."""
    t = tenant()
    spec = {"type": uc.TYPE, "action": "delete", "id": "CUSTOM_03"}
    p = preview(t, spec)
    t.zia.url_categories._find("CUSTOM_03")["urls"].append("new.example.com")
    _p, r = apply(t, spec, prepared=p)
    assert r["status"] == "plan_changed" and t.writes == []


@pytest.mark.parametrize("spec", [{"action": "rename", "id": "CUSTOM_03", "new_name": ""}, {"action": "rename", "id": "CUSTOM_03", "new_name": "a\x07b"},
                                  {"action": "rename", "id": "CUSTOM_03", "new_name": "x" * 300}, {"action": "delete", "id": "../x"},
                                  {"action": "recreate", "category": {"name": "x"}, "deleted_id": "CUSTOM_09"}, {"action": "purge", "id": "CUSTOM_03"}])
def test_bad_requests_are_refused_before_any_write(spec):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an empty, control-character or oversized name, a bad id, a recreate outside an Undo, an unknown action: 400."""
    t = tenant()
    with pytest.raises(ao.OperationError):
        ao.plan(t, dict({"type": uc.TYPE}, **spec), scope=FULL_SCOPE)
    assert t.writes == []


def test_a_predefined_category_is_never_offered_or_deleted():
    """ASVS V4.1.3 · CWE-284: a predefined category (MUSIC) is not a custom category of the tenant: refused."""
    with pytest.raises(ao.OperationError):
        ao.plan(tenant(), {"type": uc.TYPE, "action": "rename", "id": "MUSIC", "new_name": "x"}, scope=FULL_SCOPE)
    p = preview(tenant(), {"type": uc.TYPE, "action": "delete", "id": "MUSIC"})
    assert p["counts"]["change"] == 0
