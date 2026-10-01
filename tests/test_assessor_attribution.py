"""
A pack deploy names only the assessor: the provenance tag in every object's
description says "[<assessor> pack <id> v1]" instead of "[DLP-Check ...]",
and the deployment record and on-screen tenant label never carry the
vanity domain or the admin login when the classic API is used. Objects
tagged before (the "[DLP-Check ...]" form) are still found by removal,
export and the journey check.
"""
from __future__ import annotations

import deployments
import pack_deploy as pd
import pack_export
import pack_library
import pack_removal as pr
import pack_terraform
import tenant_auth
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack


def _pack(tmp_path):
    return write_pack(tmp_path, "alpha", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict > 0)")],
                      policies=[_policy("Z-Alpha-Monitor", ["Alpha Engine"])],
                      meta={"name": "Alpha Pack", "version": "2", "confidence_tweaks": []})


# --- the tag -----------------------------------------------------------------

def test_the_tag_names_the_assessor_and_falls_back_to_dlp_check():
    item = {"kind": "dictionary", "pack": "alpha", "pack_version": "2"}
    assert pd.pack_description(item, "Card numbers", by="Jane Doe") == "Card numbers [Jane Doe pack alpha v2]"
    assert pd.pack_description(item, "Card numbers") == "Card numbers [DLP-Check pack alpha v2]"
    b = {"kind": "policy", "baseline": {"pack": "zbp", "version": "4"}}
    assert pd.baseline_description(b, "", by="Jane Doe").startswith("[Jane Doe baseline zbp v4] Measured on every journey check")


def test_the_assessor_name_cannot_break_the_tag():
    assert pd.attribution("  Jane ]\n[ Doe ") == "Jane Doe"
    assert pd.attribution("x" * 200) == "x" * pd.BY_MAX
    assert pd.attribution("") == pd.attribution(None) == pd.attribution("[]") == "DLP-Check"


def test_redeploying_replaces_the_previous_tag_whoever_wrote_it():
    item = {"kind": "engine", "pack": "alpha", "pack_version": "2"}
    once = pd.pack_description(item, "Engine", by="Jane Doe")
    assert pd.pack_description(item, once, by="Sam Lee") == "Engine [Sam Lee pack alpha v2]"
    assert pd.pack_description(item, "Engine [DLP-Check pack alpha v1]", by="Sam Lee") == "Engine [Sam Lee pack alpha v2]"


def test_tags_are_recognised_in_both_forms_and_customer_text_is_not():
    new = "Cards [Jane Doe pack alpha v2]"
    old = "Cards [DLP-Check pack alpha v1]"
    assert pd.has_mark(new, pack_id="alpha") and pd.has_mark(old, pack_id="alpha")
    assert not pd.has_mark(new, pack_id="beta")
    assert pd.tag_pack(new) == "alpha" and pd.tag_pack(old) == "alpha"
    # A customer's own bracketed text is not a tag: not at the end, or naming no pack the caller asked for.
    assert not pd.has_mark("[Q3 baseline review] owned by finance", kind="baseline")
    assert not pd.has_mark("Reviewed [Q3 pack review]")          # unscoped: only the tool's own tags
    assert pd.has_mark("Reviewed [Q3 pack review]", pack_id="alpha") is False
    assert pd.strip_mark(new) == "Cards" and pd.strip_mark(old) == "Cards"


def test_baseline_tags_by_an_assessor_still_mark_the_object_as_the_baselines():
    obj = Obj(id=1, name="x", description="[Jane Doe baseline zbp v4] Measured on every journey check, never overwritten.")
    assert pd._has_mark(obj)


# --- deploy --------------------------------------------------------------------

def test_a_deploy_writes_the_assessors_name_and_never_dlp_check(tmp_path):
    pack = _pack(tmp_path)
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, assessor="Jane Doe")
    assert res["status"] == "applied"
    descs = ([d["description"] for d in client.zia.dlp_dictionary.added]
             + [e.get("description") for e in client.zia.dlp_engine.added]
             + [r["description"] for r in client.zia.dlp_web_rules.added])
    assert descs and all("[Jane Doe pack alpha v2]" in d for d in descs), descs
    assert not any("DLP-Check" in d for d in descs)


def test_objects_tagged_by_an_assessor_are_found_by_the_removal_by_tag(tmp_path):
    pack = _pack(tmp_path)
    tag = "[Jane Doe pack alpha v2]"
    # Renamed in the portal, so only the tag can tie them to the pack.
    client = FakeClient(dicts=[Obj(id=1, name="Renamed Dict", custom=True, description=f"Cards {tag}")],
                        engines=[Obj(id=11, name="Renamed Engine", engine_expression="D1.S > 0", description=tag)],
                        rules=[Obj(id=21, name="Renamed Rule", order=1, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 11}],
                                   description=f"Monitor. {tag} Deployed DISABLED; enable once reviewed.")])
    plan = pr.plan_removal(client, [pack])
    assert plan["remove_count"] == 3
    # A rule tagged for another pack, or carrying look-alike customer text, is not touched.
    other = FakeClient(rules=[Obj(id=22, name="Theirs", order=1, action="ALLOW", state="ENABLED", dlp_engines=[],
                                  description="Owner note [Q3 pack review]")])
    assert pr.plan_removal(other, [pack])["remove_count"] == 0


# --- export, library, Terraform ------------------------------------------------

def test_export_and_the_library_strip_tags_naming_an_assessor():
    assert pack_export._strip_mark("Cards [Jane Doe pack alpha v2] Deployed DISABLED; enable once reviewed.") == "Cards"
    assert pack_library._strip_provenance("Cards [Jane Doe pack alpha v2] Terraform-managed.") == "Cards"
    assert pack_library._strip_provenance("Cards [DLP-Check pack alpha v2] Terraform-managed.") == "Cards"


def test_terraform_tags_name_the_assessor(tmp_path):
    files = pack_terraform.generate(_pack(tmp_path), assessor="Jane Doe")
    hcl = "".join(v for k, v in files.items() if k.endswith(".tf"))
    assert "[Jane Doe pack alpha v2] Terraform-managed." in hcl and "[DLP-Check pack" not in hcl
    assert "[DLP-Check pack alpha v2] Terraform-managed." in "".join(pack_terraform.generate(_pack(tmp_path / "b")).values())


# --- records and labels ---------------------------------------------------------

def test_classic_api_labels_never_carry_the_vanity_domain_or_admin_login():
    legacy = {"auth_method": "legacy", "username": "admin@acme.zscalerthree.net", "password": "p", "api_key": "k",
              "vanity_domain": "acme", "cloud": "zscalerthree"}
    label = tenant_auth.record_label(legacy)
    assert label == "classic API (zscalerthree)"
    assert "acme" not in label and "admin" not in label
    # Records written before this change are still recognised for undo.
    assert "acme (zscalerthree)" in tenant_auth.record_labels(legacy)
    assert tenant_auth.record_label({"vanity_domain": "acme", "client_id": "c", "client_secret": "s", "cloud": "zscalerten"}) == "acme (zscalerten)"


def test_a_deployment_record_names_only_the_assessor():
    result = {"status": "applied", "results": [{"kind": "dictionary", "name": "Alpha Dict", "id": 9001, "status": "created"}]}
    rec = deployments.from_apply(result, tenant_label="classic API (production)", packs=["alpha"], options={}, by="Jane Doe")
    s = deployments.summary(rec)
    assert s["by"] == "Jane Doe" and s["tenant_label"] == "classic API (production)"


def test_the_server_takes_the_assessor_from_the_request_then_the_profile(monkeypatch):
    import dlp_api_server as srv
    import tenant_profiles
    assert srv._assessor(srv.DLPPackDeployRequest(assessor=" Jane Doe ")) == "Jane Doe"
    monkeypatch.setattr(tenant_profiles, "get", lambda pid, **kw: {"assessor": "Sam Lee"} if pid == "p1" else None)
    assert srv._assessor(srv.DLPPackDeployRequest(profile_id="p1")) == "Sam Lee"
    assert srv._assessor(srv.DLPPackDeployRequest()) == ""
