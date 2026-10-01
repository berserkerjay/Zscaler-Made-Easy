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
    # Capped by UTF-8 bytes (ZIA measures descriptions in bytes), never mid-character.
    assert pd.attribution("\U0001F600" * 40) == "\U0001F600" * (pd.BY_MAX // 4)
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
    assert pd.tag_pack(new, known={"alpha"}) == "alpha" and pd.tag_pack(old) == "alpha"
    # A tag carrying a version is a deploy's, whatever the library holds now (a pack since removed included).
    assert pd.tag_pack(new) == "alpha" and pd.tag_pack(new, known={"beta"}) == "alpha"
    # A customer's own bracketed text is not a tag: not at the end, or naming no pack the caller asked for.
    assert not pd.has_mark("[Q3 baseline review] owned by finance", kind="baseline")
    assert not pd.has_mark("Reviewed [Q3 pack review]")          # unscoped: only the tool's own tags
    assert pd.has_mark("Reviewed [Q3 pack review]", pack_id="alpha") is False
    assert pd.strip_mark(new, known={"alpha"}) == "Cards" and pd.strip_mark(old) == "Cards"
    assert pd.strip_mark("Reviewed [Q3 pack review]", known={"alpha"}) == "Reviewed [Q3 pack review]"


def test_baseline_tags_by_an_assessor_still_mark_the_object_as_the_baselines():
    obj = Obj(id=1, name="x", description="[Jane Doe baseline zbp v4] Measured on every journey check, never overwritten.")
    assert pd._has_mark(obj, "zbp")
    # Customer text that only looks like a baseline tag does not stop the object being adopted.
    assert not pd._has_mark(Obj(id=2, name="y", description="Owned by SecOps [team baseline v2]"), "zbp")


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

def test_export_and_the_library_strip_tags_naming_an_assessor(monkeypatch):
    monkeypatch.setattr(pack_export, "_known_packs", lambda: frozenset({"alpha"}))
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


# --- round 1 regressions ----------------------------------------------------------

def test_inventory_never_marks_customer_bracket_text_as_a_tool_tag(monkeypatch):
    monkeypatch.setattr(pd, "library_ids", lambda: {"alpha"})
    snap = {"reachable": True, "dictionaries": {}, "engines": {}, "channels": {},
            "rules": [{"id": 7, "name": "Finance exfil", "description": "Customer finance rule [Q3 pack review]"},
                      {"id": 8, "name": "HR", "description": "Owned by SecOps [team baseline v2]"},
                      {"id": 9, "name": "Ours", "description": "Monitor. [Jane Doe pack alpha v2] Deployed DISABLED; enable once reviewed."},
                      {"id": 10, "name": "Old", "description": "Monitor. [DLP-Check pack gone v1]"}]}
    monkeypatch.setattr(pd, "fetch_tenant", lambda client, need=None: snap)
    got = {r["name"]: (r["tagged"], r["pack"]) for r in pr.inventory(object())["rules"]}
    assert got == {"Finance exfil": (False, None), "HR": (False, None), "Ours": (True, "alpha"), "Old": (True, "gone")}
    assert pr._read_summary(snap)["tagged_rules"] == 2


def test_export_keeps_customer_bracket_text_and_strips_an_inner_assessor_tag(monkeypatch):
    monkeypatch.setattr(pack_export, "_known_packs", lambda: frozenset({"alpha"}))
    assert pack_export._strip_mark("Block uploads to personal storage [Q3 pack review]") == "Block uploads to personal storage [Q3 pack review]"
    assert pack_export._strip_mark("Owned by SecOps [team baseline v2]") == "Owned by SecOps [team baseline v2]"
    # An admin's note after the tag is kept; the tag itself goes, so a redeploy does not stack a second one.
    assert pack_export._strip_mark("Cards [Jane Doe pack alpha v2] owner: finance") == "Cards owner: finance"
    item = {"kind": "dictionary", "pack": "alpha", "pack_version": "3"}
    assert pd.pack_description(item, "Cards [Jane Doe pack alpha v2] owner", by="Sam") == "Cards owner [Sam pack alpha v3]"


def test_a_long_multibyte_assessor_name_never_breaks_a_255_byte_tag():
    pid = "a" * 64
    for by in ("\U0001F600" * 40, "é" * 40, "x" * 200):
        d = pd.baseline_description({"kind": "dictionary", "baseline": {"pack": pid, "version": "1.10.3"}}, "A" * 400, limit=255, by=by)
        assert len(d.encode("utf-8")) <= 255 and d.endswith("never overwritten.")
        assert pd.has_mark(d, pack_id=pid) and pd.strip_mark(d, known={pid}).startswith("AAA")
        t = pack_terraform._provenance({"version": "1.10.3", "_by": by}, pid, "A" * 400, limit=255)
        assert t.endswith("Terraform-managed.") and pd.has_mark(t, pack_id=pid)


LEGACY = {"auth_method": "legacy", "username": "admin@acme.com", "password": "pw", "api_key": "k" * 12,
          "vanity_domain": "acme-stale", "cloud": "zscalerten"}


def test_the_deployment_record_stores_the_sanitized_assessor(monkeypatch, tmp_path):
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    seen = {}

    def fake_apply(client, packs, **kw):
        seen.update(kw)
        return {"status": "applied", "results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}], "summary": {"created": 1}}
    monkeypatch.setattr(pd, "apply", fake_apply)
    req = srv.DLPPackDeployRequest(pack_ids=["alpha"], plan_hash="h", assessor="Eve]\n[DLP-Check pack pci v9] " + "A" * 200)
    out = srv._run_apply(object(), tenant_auth.normalize(LEGACY), req, [{"id": "alpha"}], None, None)
    by = out["deployment"]["by"]
    assert by == seen["assessor"] == pd.attribution(req.assessor)
    assert "[" not in by and "\n" not in by and len(by.encode("utf-8")) <= pd.BY_MAX
    assert out["deployment"]["tenant_label"] == "classic API (zscalerten)"
    assert srv._assessor(srv.DLPPackDeployRequest(assessor=" [ ] ")) == ""


def test_the_terraform_gap_hand_off_names_a_classic_api_tenant_without_the_admin_login(monkeypatch, tmp_path):
    import io
    import zipfile
    import dlp_api_server as srv
    pack = _pack(tmp_path)
    monkeypatch.setattr(pd, "preflight", lambda client, packs, **kw: {"items": []})
    monkeypatch.setattr(pd, "public_report", lambda full: {"items": []})
    creds = tenant_auth.normalize(LEGACY)
    req = srv.DLPPackDeployRequest(pack_ids=["alpha"], mode="gap", assessor="Jane Doe")
    out = srv._run_terraform(object(), creds, req, [pack], None, None)
    assert out["tenant_label"] == "classic API (zscalerten)"
    text = "\n".join(out["logs"])
    z = zipfile.ZipFile(io.BytesIO(out["artifact"][2]))
    text += "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())
    assert "admin@acme.com" not in text and "acme-stale" not in text
    assert "classic API (zscalerten)" in text and "[Jane Doe pack alpha v2] Terraform-managed." in text


def test_the_classic_api_client_rate_label_matches_new_and_old_deployment_records(monkeypatch, tmp_path):
    from datetime import datetime, timezone
    import dlp_api_server as srv
    import zia_rate
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))

    class Client:
        pass
    monkeypatch.setattr(tenant_auth, "build_legacy_sdk_client", lambda c, **kw: Client())
    client = srv._build_sdk_client(dict(LEGACY))
    assert zia_rate.label_of(client) == "classic API (zscalerten)"
    now = datetime.now(timezone.utc)
    for label in ("classic API (zscalerten)", "acme-stale (zscalerten)", "other (zscalerten)"):
        rec = deployments.from_apply({"results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}]},
                                     tenant_label=label, packs=["alpha"], options={})
        rec["at"] = now.isoformat()
        rec["failed"] = [{"kind": "engine", "name": "e", "error": "HTTP 429 Too Many Requests"}]
        deployments.add(rec)
    t = now.timestamp() + 1
    assert zia_rate._track_record(t, zia_rate.labels_of(client))["runs"] == 2
    assert len(zia_rate._deployment_refusals(t, zia_rate.labels_of(client))) == 2


def test_export_from_a_classic_api_tenant_never_names_its_vanity_domain(monkeypatch):
    import dlp_api_server as srv
    seen = {}

    def fake_export(client, **kw):
        seen.update(kw)
        return {"status": "blocked"}
    monkeypatch.setattr(pack_export, "export_pack", fake_export)
    logs: list = []
    out = srv._run_pack_export(object(), tenant_auth.normalize(LEGACY), srv.PackExportRequest(pack_name="x"), None, logs.append, None)
    assert seen["tenant_label"] == out["tenant_label"] == "classic API (zscalerten)"
    assert not any("acme" in line for line in logs)


def test_the_browser_sends_the_assessor_with_every_pack_request():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    body = js[js.index("function _dzCreds()"):js.index("const _dzE")]
    assert body.count("assessor: v('assessor').trim()") + body.count("b.assessor = v('assessor').trim()") == 2
    assert "assessor: (_dzCreds() || {}).assessor" in js   # the static Terraform hand-off
