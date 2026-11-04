"""Managed-name prefix (name_prefix.py, DLP_CHECK_NAME_PREFIX): off by
default; validated (a bad prefix blocks the plan before the tenant is read,
never dropped silently); applied when a pack is loaded so the plan, the
deploy, the removal and the Terraform build agree, with every in-pack
reference rewritten and predefined references left alone; shown in the
preview; an object the tenant already holds under the prefixed name is
reused and recognised as this app's. Fake tenant only (tests/test_pack_deploy.py)."""
from __future__ import annotations

import os

import pytest

import name_prefix as np_
import pack_deploy as pd
import pack_removal as pr
import pack_terraform
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack

SETTING = "DLP_CHECK_NAME_PREFIX"


def _pack(tmp_path):
    return write_pack(tmp_path, "alpha", dicts=[_dict("Alpha Dict")],
                      engines=[_engine("Alpha Engine", "((D:Alpha Dict > 0) AND (D:Social Security Numbers (US) > 0))")],
                      policies=[_policy("Alpha-Monitor", ["Alpha Engine", "PCI"])],
                      meta={"name": "Alpha Pack", "version": "2", "confidence_tweaks": []})


# ── validation ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["-ZME", " ZME", "ZME[", "Z]ME", "a" * 17, "ZME\n", "Z  ME", "ZME/", "Zscaler Made Easy ", "DLP Check-", "Z‮ME"])
def test_a_prefix_that_could_break_a_name_or_forge_a_tag_is_refused(bad):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: brackets (provenance tags), control and bidi characters, leading punctuation or space, double spaces, the tool's own name and more than 16 characters are refused."""
    assert np_.problem(bad)


@pytest.mark.parametrize("good", ["ZME-", "ACME ", "dlp_", "Team.A:", "X", "a" * 16])
def test_ordinary_prefixes_are_accepted(good):
    """ASVS V5.1.3 · CWE-20: letters, digits, space and - _ . : up to 16 characters."""
    assert np_.problem(good) is None


def test_off_by_default_and_a_bad_setting_blocks_the_plan_before_the_tenant_is_read(tmp_path, monkeypatch):
    """ASVS V5.1.3 · V14.1.1 · CWE-20 · CWE-1188: unset is off (names as the pack gives them); an invalid prefix blocks the preflight and the removal preview with a plain reason and reads nothing."""
    monkeypatch.delenv(SETTING, raising=False)
    assert np_.configured() == ""
    pack = _pack(tmp_path)
    rep = pd.preflight(FakeClient(dicts=[PREDEF_SSN]), [pack], writes_enabled=True)
    assert rep["name_prefix"]["on"] is False and "name_prefix" not in rep["options"]
    assert {i["name"] for i in rep["items"]} >= {"Alpha Dict", "Alpha Engine", "Alpha-Monitor"}
    monkeypatch.setenv(SETTING, "ZME[")

    class Boom:
        @property
        def zia(self):
            raise AssertionError("the tenant was read")
    rep = pd.preflight(Boom(), [pack], writes_enabled=True)
    assert rep["status"] == "blocked" and SETTING in rep["blockers"][0] and rep["plan_hash"] == ""
    plan = pr.plan_removal(Boom(), [pack])
    assert plan["status"] == "blocked" and SETTING in plan["blockers"][0]


# ── applied at load, references rewritten ───────────────────────────────
def test_the_prefix_renames_pack_objects_and_their_references_but_never_predefined_ones():
    """ASVS V5.1.3 · CWE-20: dictionaries, engines, rules and groups get the prefix; D:<pack dictionary>, a rule's pack engines, groups and parent rule follow; predefined dictionaries and engines keep their names; a name already prefixed is not prefixed twice."""
    d, e, p, g = np_.apply([{"name": "Alpha Dict"}, {"name": "ZME-Done"}],
                           [{"name": "Alpha Engine", "expression": "((D:Alpha Dict > 0) OR (D:Alpha Dict Extra > 0) OR (D:Social Security Numbers (US) > 0))"}],
                           [{"name": "Parent", "engines": ["Alpha Engine", "PCI"], "endpoint_application_groups": ["Apps"]},
                            {"name": "Child", "parent_rule": "Parent", "engines": []}],
                           [{"name": "Apps"}], "ZME-")
    assert [x["name"] for x in d] == ["ZME-Alpha Dict", "ZME-Done"]
    assert e[0]["name"] == "ZME-Alpha Engine"
    assert e[0]["expression"] == "((D:ZME-Alpha Dict > 0) OR (D:Alpha Dict Extra > 0) OR (D:Social Security Numbers (US) > 0))"
    assert p[0]["engines"] == ["ZME-Alpha Engine", "PCI"] and p[0]["endpoint_application_groups"] == ["ZME-Apps"]
    assert p[1]["name"] == "ZME-Child" and p[1]["parent_rule"] == "ZME-Parent" and g[0]["name"] == "ZME-Apps"
    assert np_.strip("ZME-Alpha Dict", "ZME-") == "Alpha Dict" and np_.has("zme-alpha", "ZME-")


# ── shown in the preview; deploy and reuse by the prefixed name ─────────
def test_the_preview_shows_the_prefix_and_the_deploy_creates_prefixed_names(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-451 · WSTG-BUSL-01: the preview names the prefix and each item's name in the pack, the plan hash binds it, and the deploy creates the prefixed names (engine expression rewritten)."""
    monkeypatch.setenv(SETTING, "ZME-")
    pack = _pack(tmp_path)
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert rep["name_prefix"] == {"on": True, "prefix": "ZME-", "note": np_.preview("ZME-")["note"]}
    assert rep["options"]["name_prefix"] == "ZME-"
    by = {i["name"]: i for i in rep["items"]}
    assert by["ZME-Alpha Dict"]["pack_name"] == "Alpha Dict" and by["ZME-Alpha-Monitor"]["status"] == pd.CREATE
    monkeypatch.setenv(SETTING, "ACME-")
    assert pd.preflight(client, [pack], writes_enabled=True)["plan_hash"] != rep["plan_hash"]
    monkeypatch.setenv(SETTING, "ZME-")
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, assessor="Jane Doe")
    assert res["status"] == "applied"
    assert [d["name"] for d in client.zia.dlp_dictionary.added] == ["ZME-Alpha Dict"]
    assert [r["name"] for r in client.zia.dlp_web_rules.added] == ["ZME-Alpha-Monitor"]
    # The provenance tag is unchanged by the prefix.
    assert all("[Jane Doe pack alpha v2]" in r["description"] for r in client.zia.dlp_web_rules.added)


def test_an_object_under_the_prefixed_name_is_reused_and_recognised_as_ours(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-694 · WSTG-BUSL-01: a dictionary already in the tenant as "<prefix><name>" (its tag edited away) is reused, not created again, and marked as this app's; one under the plain pack name is not reused when a prefix is set."""
    monkeypatch.setenv(SETTING, "ZME-")
    pack = _pack(tmp_path)
    client = FakeClient(dicts=[PREDEF_SSN, Obj(id=5, name="ZME-Alpha Dict", custom=True, description="edited by someone")])
    by = {i["name"]: i for i in pd.preflight(client, [pack], writes_enabled=True)["items"]}
    item = by["ZME-Alpha Dict"]
    assert item["status"] in (pd.REUSE, pd.REUSE_DIFFERS) and item["ours"] == "prefix" and item["adopt"] is False
    assert "managed-name prefix" in item["reason"]
    plain = FakeClient(dicts=[PREDEF_SSN, Obj(id=6, name="Alpha Dict", custom=True, description="the customer's")])
    by = {i["name"]: i for i in pd.preflight(plain, [pack], writes_enabled=True)["items"]}
    assert by["ZME-Alpha Dict"]["status"] == pd.CREATE


def test_the_removal_recognises_objects_under_the_prefixed_name(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-694: the removal preview finds an untagged rule under the prefixed name as this app's (a "prefix" match, removed), while the same name without the prefix stays a name-only match that is kept."""
    monkeypatch.setenv(SETTING, "ZME-")
    pack = _pack(tmp_path)
    client = FakeClient(rules=[Obj(id=21, name="ZME-Alpha-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[], description=""),
                               Obj(id=22, name="Alpha-Monitor", order=2, action="ALLOW", state="DISABLED", dlp_engines=[], description="")])
    plan = pr.plan_removal(client, [pack])
    by = {i["name"]: i for i in plan["items"] if i["kind"] == "policy"}
    assert by["ZME-Alpha-Monitor"]["match"] == "prefix" and not by["ZME-Alpha-Monitor"].get("keep")
    assert by["Alpha-Monitor"]["match"] == "name" and by["Alpha-Monitor"].get("keep")


def test_the_terraform_build_carries_the_prefix_but_the_kept_workspace_does_not(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-20: the pack's Terraform workspace built for hand-off uses the prefixed names; the workspace kept in terraform/<pack> (name_prefix="") keeps the pack's own names."""
    monkeypatch.setenv(SETTING, "ZME-")
    hcl = "".join(v for k, v in pack_terraform.generate(_pack(tmp_path), assessor="Jane Doe").items() if k.endswith(".tf"))
    assert "ZME-Alpha Dict" in hcl and "ZME-Alpha-Monitor" in hcl
    kept = "".join(v for k, v in pack_terraform.generate(_pack(tmp_path / "b"), assessor="Jane Doe", name_prefix="").items() if k.endswith(".tf"))
    assert "ZME-" not in kept and "Alpha Dict" in kept


def test_help_and_settings_explain_the_trade_off():
    """ASVS V14.1.1 · CWE-1059: the preview's help entry explains the trade-off (longer names, look-alike objects, a change makes new copies) in both help catalogues, and the settings example names the setting."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("static/help_catalog.js", "browser_extension/help_catalog.js"):
        text = open(os.path.join(root, rel), encoding="utf-8").read()
        assert "#dlpDeployModal #dzNamePrefix" in text and "Trade-off" in text and "new copies" in text
    assert "DLP_CHECK_NAME_PREFIX" in open(os.path.join(root, "local_settings.env.example"), encoding="utf-8").read()
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "_dzNamePrefix(R.name_prefix)" in js and "i.pack_name" in js
