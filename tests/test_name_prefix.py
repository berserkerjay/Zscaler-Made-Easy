"""Managed-name prefix (name_prefix.py, DLP_CHECK_NAME_PREFIX): off by
default; validated (a bad prefix blocks the plan before the tenant is read,
never dropped silently); applied when a pack is loaded so the plan, the
deploy, the removal and the Terraform build agree, with every in-pack
reference rewritten and predefined references left alone; shown in the
preview; an object the tenant already holds under the prefixed name is
reused, but a name is never provenance: a removal deletes it only with
this app's tag or a deployment record for the tenant. Fake tenant only
(tests/test_pack_deploy.py)."""
from __future__ import annotations

import os

import pytest

import name_prefix as np_
import pack_deploy as pd
import pack_removal as pr
import deployments
import pack_terraform
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack

SETTING = "DLP_CHECK_NAME_PREFIX"


def _pack(tmp_path):
    return write_pack(tmp_path, "alpha", dicts=[_dict("Alpha Dict")],
                      engines=[_engine("Alpha Engine", "((D:Alpha Dict > 0) AND (D:Social Security Numbers (US) > 0))")],
                      policies=[_policy("Alpha-Monitor", ["Alpha Engine"])],
                      meta={"name": "Alpha Pack", "version": "2", "confidence_tweaks": []})


# ── validation ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["-ZME", " ZME", "ZME[", "Z]ME", "a" * 17, "ZME\n", "Z  ME", "ZME/", "Zscaler Made Easy ", "DLP Check-", "Z‮ME"])
def test_a_prefix_that_could_break_a_name_or_forge_a_tag_is_refused(bad):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: brackets (provenance tags), control and bidi characters, leading punctuation or space, double spaces, the tool's own name and more than 16 characters are refused."""
    assert np_.problem(bad)


@pytest.mark.parametrize("bad", ["R AND D ", "X OR ", "A NOT ", "and-", "Not", "or.x"])
def test_a_prefix_holding_an_expression_keyword_is_refused(bad):
    """ASVS V5.1.3 · CWE-20 · CWE-917 · WSTG-INPV-01: AND, OR or NOT as a whole word (any case) would go into every D:<dictionary> of an engine expression, so it is refused."""
    assert "AND, OR or NOT" in np_.problem(bad)


@pytest.mark.parametrize("good", ["ZME-", "ACME ", "dlp_", "Team.A:", "X", "a" * 16, "ORACLE-", "Band ", "NOTE.", "ANDES_"])
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
    """ASVS V5.1.3 · CWE-20: dictionaries, engines, rules and groups get the prefix; D:<pack dictionary>, a rule's pack engines, groups and parent rule follow; predefined dictionaries and engines keep their names; a name that already starts with the prefix is prefixed too."""
    d, e, p, g = np_.apply([{"name": "Alpha Dict"}, {"name": "ZME-Done"}],
                           [{"name": "Alpha Engine", "expression": "((D:Alpha Dict > 0) OR (D:Alpha Dict Extra > 0) OR (D:Social Security Numbers (US) > 0))"}],
                           [{"name": "Parent", "engines": ["Alpha Engine", "PCI"], "endpoint_application_groups": ["Apps"]},
                            {"name": "Child", "parent_rule": "Parent", "engines": []}],
                           [{"name": "Apps"}], "ZME-")
    assert [x["name"] for x in d] == ["ZME-Alpha Dict", "ZME-ZME-Done"]
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


def test_an_untagged_object_under_the_prefixed_name_is_reused_but_not_called_ours(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-694 · WSTG-BUSL-01: a dictionary already in the tenant as "<prefix><name>" without this app's tag is reused, not created again, but not marked as this app's (a name is not provenance) and the preview says so; one under the plain pack name is not reused when a prefix is set."""
    monkeypatch.setenv(SETTING, "ZME-")
    pack = _pack(tmp_path)
    client = FakeClient(dicts=[PREDEF_SSN, Obj(id=5, name="ZME-Alpha Dict", custom=True, description="edited by someone")])
    rep = pd.preflight(client, [pack], writes_enabled=True)
    item = {i["name"]: i for i in rep["items"]}["ZME-Alpha Dict"]
    assert item["status"] in (pd.REUSE, pd.REUSE_DIFFERS) and item.get("ours") is None
    assert "does not prove this app made it" in item["reason"]
    assert "A name alone does not prove" in rep["name_prefix"]["note"]
    plain = FakeClient(dicts=[PREDEF_SSN, Obj(id=6, name="Alpha Dict", custom=True, description="the customer's")])
    by = {i["name"]: i for i in pd.preflight(plain, [pack], writes_enabled=True)["items"]}
    assert by["ZME-Alpha Dict"]["status"] == pd.CREATE


def test_a_pack_name_that_already_starts_with_the_prefix_is_prefixed_so_the_customers_object_is_not_taken(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-694 · WSTG-BUSL-01: with the prefix "Alpha", the pack's "Alpha Dict" is deployed as "AlphaAlpha Dict": the customer's own untagged "Alpha Dict" is neither reused as this app's nor removed."""
    monkeypatch.setenv(SETTING, "Alpha")
    pack = _pack(tmp_path)
    client = FakeClient(dicts=[PREDEF_SSN, Obj(id=7, name="Alpha Dict", custom=True, description="the customer's")],
                        rules=[Obj(id=23, name="Alpha-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[], description="")])
    by = {i["name"]: i for i in pd.preflight(client, [pack], writes_enabled=True)["items"]}
    assert by["AlphaAlpha Dict"]["status"] == pd.CREATE and by["AlphaAlpha Dict"]["pack_name"] == "Alpha Dict"
    assert "Alpha Dict" not in by
    rules = {i["name"]: i for i in pr.plan_removal(client, [pack])["items"] if i["kind"] == "policy"}
    assert rules["Alpha-Monitor"]["match"] == "name" and rules["Alpha-Monitor"]["status"] == "keep"


def _prefixed_rules():
    return FakeClient(rules=[Obj(id=21, name="ZME-Alpha-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[], description=""),
                             Obj(id=22, name="Alpha-Monitor", order=2, action="ALLOW", state="DISABLED", dlp_engines=[], description=""),
                             Obj(id=24, name="ZME-Alpha-Monitor-2", order=3, action="ALLOW", state="DISABLED", dlp_engines=[],
                                 description="x [Jane Doe pack alpha v2]")])


def test_the_removal_keeps_an_untagged_object_under_the_prefixed_name(tmp_path, monkeypatch):
    """ASVS V1.14.6 · ASVS V4.1.3 · CWE-694 · WSTG-BUSL-01: an untagged rule under the prefixed name is a "prefix" match that is KEPT, with a reason and a warning saying a name is not proof; the plain pack name stays a kept name-only match."""
    monkeypatch.setenv(SETTING, "ZME-")
    plan = pr.plan_removal(_prefixed_rules(), [_pack(tmp_path)])
    by = {i["name"]: i for i in plan["items"] if i["kind"] == "policy"}
    assert by["ZME-Alpha-Monitor"]["match"] == "prefix" and by["ZME-Alpha-Monitor"]["status"] == "keep"
    assert by["ZME-Alpha-Monitor"]["keep"] == pr.PREFIX_ONLY_KEEP
    assert any("ZME-Alpha-Monitor" in w and "deployment record" in w for w in plan["warnings"])
    assert by["Alpha-Monitor"]["match"] == "name" and by["Alpha-Monitor"].get("keep")


def test_the_removal_deletes_a_prefixed_object_only_with_a_deployment_record_for_this_tenant(tmp_path, monkeypatch):
    """ASVS V1.14.6 · ASVS V4.1.3 · CWE-694 · WSTG-BUSL-01: the same untagged rule is removable when a deployment record for this tenant lists its id; a record of another kind or id does not count."""
    monkeypatch.setenv(SETTING, "ZME-")
    pack = _pack(tmp_path)
    other = pr.plan_removal(_prefixed_rules(), [pack], recorded=[("engine", "21"), ("policy", "99")])
    assert {i["name"]: i for i in other["items"]}["ZME-Alpha-Monitor"]["status"] == "keep"
    plan = pr.plan_removal(_prefixed_rules(), [pack], recorded=[("policy", "21")])
    item = {i["name"]: i for i in plan["items"]}["ZME-Alpha-Monitor"]
    assert item["status"] == "remove" and item["provenance"] == "deployment record"
    assert plan["plan_hash"] != other["plan_hash"]


def test_deployment_records_give_provenance_only_for_their_own_tenant_and_not_once_undone(tmp_path, monkeypatch):
    """ASVS V4.1.3 · CWE-639 · WSTG-ATHZ-02: created_in lists (kind, id) of the records the tenant check accepts, skipping undone items and kinds a removal cannot undo."""
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    deployments.add({"id": "dep-a", "tenant_label": "T1", "created": [
        {"kind": "policy", "id": 21}, {"kind": "engine", "id": 31, "undone": True}, {"kind": "tweak", "id": 41}]})
    deployments.add({"id": "dep-b", "tenant_label": "T2", "created": [{"kind": "policy", "id": 22}]})
    assert deployments.created_in(lambda r: r.get("tenant_label") == "T1") == [("policy", "21")]


def test_the_terraform_build_carries_the_prefix_but_the_kept_workspace_does_not(tmp_path, monkeypatch):
    """ASVS V1.14.6 · CWE-20: the pack's Terraform workspace built for hand-off uses the prefixed names; the workspace kept in terraform/<pack> (name_prefix="") keeps the pack's own names."""
    monkeypatch.setenv(SETTING, "ZME-")
    hcl = "".join(v for k, v in pack_terraform.generate(_pack(tmp_path), assessor="Jane Doe").items() if k.endswith(".tf"))
    assert "ZME-Alpha Dict" in hcl and "ZME-Alpha-Monitor" in hcl
    kept = "".join(v for k, v in pack_terraform.generate(_pack(tmp_path / "b"), assessor="Jane Doe", name_prefix="").items() if k.endswith(".tf"))
    assert "ZME-" not in kept and "Alpha Dict" in kept


def test_help_and_settings_explain_the_trade_off():
    """ASVS V14.1.1 · CWE-1059: the preview's help entry explains the trade-off (longer names, a change makes new copies) and that a name alone is not proof in both help catalogues, and the settings example names the setting."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("static/help_catalog.js", "browser_extension/help_catalog.js"):
        text = open(os.path.join(root, rel), encoding="utf-8").read()
        assert "#dlpDeployModal #dzNamePrefix" in text and "Trade-off" in text and "new copies" in text
        assert "a name alone does not prove this app made it" in text
    assert "DLP_CHECK_NAME_PREFIX" in open(os.path.join(root, "local_settings.env.example"), encoding="utf-8").read()
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "_dzNamePrefix(R.name_prefix)" in js and "i.pack_name" in js
