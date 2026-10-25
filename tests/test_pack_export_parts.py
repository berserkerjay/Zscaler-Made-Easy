"""Export from tenant: dictionaries, engines and rules each on their own,
as a JSON pack, as Terraform, or both.

The source tenant is test_pack_export's: three custom dictionaries (one a
clone), three custom engines (one no rule uses), a predefined engine and
rules on all four DLP channels. What is proved here:
  - each part exports on its own, with or without what it uses;
  - what is left out is named, never silently dropped (referenced_only);
  - the Terraform comes from the hand-off's generator, looks up by name
    what it does not create, and says so in the file;
  - the job serves the whole zip and each part's own file;
  - nothing is written to the tenant, and a bad request is refused before
    any read.
"""
from __future__ import annotations

import io
import json
import re
import zipfile

import pytest

import pack_deploy as pd
import pack_export as pe
import pack_library as pl
import pack_terraform as ptf
from test_pack_deploy import items_by
from test_pack_export import ALL_DLP_IN_SCOPE, SECRET, ReadOnly, _empty_target, _source, _upload, _wait, _zip_text

CUSTOM_DICTS = {"Project Codes", "Board Phrases", "SSN Clone High"}
CUSTOM_ENGINES = {"Project Leak", "Board Leak", "Unused Engine"}
RULES = {"Web-Projects", "Web-PCI", "EP-Board", "SaaS-Projects", "Email-Board"}


def _export(**kw):
    res = pe.export_pack(_source(), tenant_label="acme", **kw)
    assert res["status"] == "ready", res
    assert res["validation"]["ok"], res["validation"]["problems"]
    return res["pack"]


def _names(pack, key):
    return {x["name"] for x in pack[key]}


def _resources(text, kind):
    return re.findall(rf'^resource "{kind}" "(\w+)"', text, re.M)


# ---------------------------------------------------------------------------
# Each part on its own, with or without what it uses
# ---------------------------------------------------------------------------

def test_dictionaries_alone_reads_no_rule_and_carries_every_custom_dictionary():
    client = ReadOnly(_source())
    calls = []
    for svc in ("dlp_web_rules", "endpoint_dlp_rules", "casb_dlp_rules", "outbound_email_dlp_rules"):
        real = getattr(client.zia, svc)
        lister = next(m for m in ("list_rules",) if hasattr(real, m))
        setattr(real, lister, (lambda f, s: (lambda *a, **k: calls.append(s) or f(*a, **k)))(getattr(real, lister), svc))
    res = pe.export_pack(client, tenant_label="acme", parts=["dictionaries"])
    assert res["status"] == "ready", res
    pack = res["pack"]
    assert _names(pack, "dictionaries") == CUSTOM_DICTS
    assert pack["engines"] == [] and pack["policies"] == []
    assert calls == [], "an export of dictionaries alone reads no DLP rule"
    assert pack["meta"]["parts"] == ["dictionaries"] and pack["meta"]["referenced_only"] == {"dictionaries": [], "engines": []}
    assert client.writes == []


def test_engines_bring_their_dictionaries_unless_told_not_to():
    with_deps = _export(parts=["engines"])
    assert _names(with_deps, "engines") == CUSTOM_ENGINES, "an engine no rule uses is exportable too"
    assert _names(with_deps, "dictionaries") == CUSTOM_DICTS and with_deps["policies"] == []

    alone = _export(parts=["engines"], include_dependencies=False)
    assert _names(alone, "engines") == CUSTOM_ENGINES and alone["dictionaries"] == []
    # What they use is named in the expression and listed, not dropped.
    exprs = {e["name"]: e["expression"] for e in alone["engines"]}
    assert exprs["Project Leak"] == "((D:Project Codes > 0) AND (D:SSN > 2))"
    assert alone["meta"]["referenced_only"] == {"dictionaries": sorted(CUSTOM_DICTS), "engines": []}
    assert alone["meta"]["dependencies_included"] is False
    assert "must already exist" in alone["meta"]["description"]


def test_rules_without_dependencies_name_their_engines():
    pack = _export(parts=["rules"], include_dependencies=False)
    assert _names(pack, "policies") == RULES and pack["engines"] == [] and pack["dictionaries"] == []
    pols = {p["name"]: p for p in pack["policies"]}
    assert pols["Web-Projects"]["engines"] == ["Project Leak"] and pols["Web-PCI"]["engines"] == ["PCI"]
    assert pack["meta"]["referenced_only"] == {"dictionaries": [], "engines": ["Board Leak", "Project Leak"]}


def test_the_default_is_unchanged_rules_with_everything_they_use():
    pack = _export()
    assert _names(pack, "policies") == RULES
    assert _names(pack, "engines") == {"Project Leak", "Board Leak"}, "an unused engine only comes when engines are picked"
    assert _names(pack, "dictionaries") == CUSTOM_DICTS
    assert pack["meta"]["parts"] == ["rules"] and pack["meta"]["dependencies_included"] is True


def test_picking_by_id_and_what_cannot_be_picked_is_listed():
    pack = _export(parts=["engines", "dictionaries"], engines=["5001", "61", "999"], dictionaries=["1002", "2"])
    assert _names(pack, "engines") == {"Project Leak"}
    assert _names(pack, "dictionaries") == {"Board Phrases", "Project Codes"}, "the picked one, and the one the picked engine uses"
    left = {(d["kind"], d["name"]): d["reason"] for d in pack["meta"]["not_exported"]}
    assert "not in the tenant's engine list" in left[("engine", "id 999")]
    assert "predefined Zscaler engine" in left[("engine", "PCI")]
    assert "predefined Zscaler dictionary" in left[("dictionary", "CREDIT_CARD")]


def test_nothing_picked_is_refused_before_any_read():
    client = ReadOnly(_source())
    res = pe.export_pack(client, tenant_label="acme", parts=["engines", "dictionaries"], engines=[], dictionaries=[])
    assert res["status"] == "error" and res["error"] == pe.NOTHING_IN_PARTS
    assert client.writes == []
    with pytest.raises(ValueError):
        pe.normalize_parts(["engines", "ftp"])
    with pytest.raises(ValueError):
        pe.normalize_format("xml")
    with pytest.raises(ValueError):
        pe.normalize_object_pick({"id": 1}, "engines")


def test_a_dictionaries_only_pack_deploys_into_an_empty_tenant(tmp_path):
    pack = _export(parts=["dictionaries"])
    fname, data = pe.zip_pack(pack)
    loaded = pl.assemble_pack(_upload(data, fname))
    assert pl.validate_pack(loaded)["ok"]
    saved = pl.save_pack(loaded, root=str(tmp_path))
    rep = pd.preflight(_empty_target(), [{"id": saved["id"], "dir": saved["dir"]}], writes_enabled=True)
    assert rep["status"] in ("ready", "warnings"), rep.get("blockers")
    assert {n: d["status"] for n, d in items_by(rep, "dictionary").items()} == {n: pd.CREATE for n in CUSTOM_DICTS}
    assert not items_by(rep, "engine") and not items_by(rep, "policy")


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------

def _tf(pack, assessor=""):
    pack_id, files = pe.terraform_files(pack, assessor)
    for name, text in files.items():
        if name.endswith(".tf"):
            assert ptf.hcl_fmt(text) == text, f"{name} is not terraform fmt-clean"
            assert text.count("{") == text.count("}"), name
    return pack_id, files


def test_terraform_of_each_part_creates_only_that_part():
    _, files = _tf(_export(parts=["dictionaries"]))
    assert len(_resources(files["dictionaries.tf"], "zia_dlp_dictionaries")) == 3
    assert not _resources(files["engines.tf"], "zia_dlp_engines")
    assert not re.search(r'^resource "', files["rules.tf"], re.M)

    _, files = _tf(_export(parts=["rules"]))
    assert len(_resources(files["dictionaries.tf"], "zia_dlp_dictionaries")) == 3
    assert len(_resources(files["engines.tf"], "zia_dlp_engines")) == 2
    import pack_channels as pc
    for ch in pc.DLP_CHANNELS:
        assert _resources(files["rules.tf"], ptf.RESOURCE_BY_CHANNEL[ch]), ch
    assert re.search(r'state\s+=\s+"DISABLED"', files["rules.tf"]), "every rule is created disabled"
    assert not re.search(r'state\s+=\s+"ENABLED"', files["rules.tf"])


def test_terraform_without_dependencies_looks_them_up_by_name_and_says_so():
    _, files = _tf(_export(parts=["engines"], include_dependencies=False))
    eng = files["engines.tf"]
    assert len(_resources(eng, "zia_dlp_engines")) == 3
    assert "data.zia_dlp_dictionaries.project_codes.id" in eng and "zia_dlp_dictionaries.project_codes.id" not in eng.replace("data.zia_dlp_dictionaries", "")
    dic = files["dictionaries.tf"]
    assert not _resources(dic, "zia_dlp_dictionaries")
    assert 'data "zia_dlp_dictionaries" "project_codes"' in dic
    assert "Exported without dependencies" in dic and "Board Phrases, Project Codes, SSN Clone High" in dic

    _, files = _tf(_export(parts=["rules"], include_dependencies=False))
    rules = files["rules.tf"]
    assert 'data "zia_dlp_engines"' in rules and "data.zia_dlp_engines." in rules
    assert "these custom engines are not created by this workspace" in rules and "Board Leak, Project Leak" in rules
    assert not _resources(files["engines.tf"], "zia_dlp_engines")


def test_terraform_names_the_assessor_or_asks_for_it():
    _, named = _tf(_export(parts=["engines"]), assessor="Jane Doe")
    assert "[Jane Doe pack " in named["engines.tf"]
    _, unnamed = _tf(_export(parts=["engines"]))
    assert "${var.assessor}" in unnamed["engines.tf"] and 'variable "assessor"' in unnamed["variables.tf"]
    assert "DLP-Check pack" not in unnamed["engines.tf"]


def test_the_zip_and_each_parts_own_file_per_format():
    pack = _export(parts=["dictionaries", "engines"])
    name, data, index = pe.zip_export(pack, "both")
    folder = pe.zip_export(pack, "json")[0][:-4]
    files = _zip_text(data)
    assert name == f"{folder}-pack-and-terraform.zip"
    assert f"{folder}/pack.json" in files and f"{folder}-terraform/engines.tf" in files
    assert {(f["part"], f["format"]) for f in index} == {("dictionaries", "json"), ("engines", "json"),
                                                          ("dictionaries", "terraform"), ("engines", "terraform")}, "no rules part: none were exported"
    for f in index:
        assert pe.zip_member(data, f["path"]) is not None, f
    assert json.loads(pe.zip_member(data, f"{folder}/configs/dlp_engines.json"))[0]["name"] in CUSTOM_ENGINES
    assert pe.zip_member(data, "../etc/passwd") is None

    tname, tdata, tindex = pe.zip_export(pack, "terraform")
    assert tname == f"{folder}-terraform.zip" and all(n.startswith(f"{folder}-terraform/") for n in _zip_text(tdata))
    assert {f["format"] for f in tindex} == {"terraform"}
    jname, jdata, _ = pe.zip_export(pack, "json")
    assert (jname, _zip_text(jdata)) == (pe.zip_pack(pack)[0], _zip_text(pe.zip_pack(pack)[1])), "JSON is the pack zip, as before"


# ---------------------------------------------------------------------------
# The job, its downloads, and refusals
# ---------------------------------------------------------------------------

@pytest.fixture
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    ro = ReadOnly(_source())
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ro)
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    return TestClient(srv.app), ro


CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}


def test_the_job_serves_the_zip_and_each_part_separately(api):
    c, ro = api
    body = dict(CREDS, parts=["dictionaries", "engines"], include_dependencies=False, format="both", assessor="Jane Doe", **ALL_DLP_IN_SCOPE)
    r = c.post("/api/dlp-packs/export/start", json=body)
    assert r.status_code == 200, r.text
    snap = _wait(c, r.json()["job_id"])
    res = snap["result"]
    assert snap["status"] == "done" and res["status"] == "ready", snap
    assert res["format"] == "both" and res["parts"] == ["dictionaries", "engines"] and res["assessor_named"] is True
    assert res["referenced_only"]["dictionaries"] == [], "dictionaries were exported too, so nothing is only named"
    whole = c.get(snap["download"])
    assert whole.status_code == 200 and whole.headers["content-type"].startswith("application/zip")
    for f in res["part_files"]:
        one = c.get(snap["download"], params={"file": f["path"]})
        assert one.status_code == 200, f
        assert one.content == zipfile.ZipFile(io.BytesIO(whole.content)).read(f["path"])
        ctype = one.headers["content-type"]
        assert ctype.startswith("application/json") if f["format"] == "json" else ctype.startswith("text/plain"), f
        assert one.headers["content-disposition"].endswith(f'-{f["part"]}.{"tf" if f["format"] == "terraform" else "json"}"')
    engines_tf = next(f["path"] for f in res["part_files"] if f["part"] == "engines" and f["format"] == "terraform")
    tf = c.get(snap["download"], params={"file": engines_tf})
    assert "[Jane Doe pack " in tf.text
    # Only the listed parts: no other member, no path tricks.
    assert c.get(snap["download"], params={"file": "x/pack.json"}).status_code == 404
    assert c.get(snap["download"], params={"file": "../../etc/passwd"}).status_code == 404
    assert ro.writes == []
    assert SECRET not in json.dumps(snap) and SECRET not in whole.content.decode("latin-1")


def test_bad_requests_are_refused_before_any_read(api):
    c, ro = api
    for extra in ({"parts": ["ftp"]}, {"format": "xml"}, {"parts": ["engines"], "engines": []},
                  {"parts": ["engines", "dictionaries"], "engines": [], "dictionaries": []},
                  {"parts": ["engines"], "engines": {"id": 1}},
                  {"parts": ["engines"], "format": "terraform", "assessor": "Zscaler Made Easy"}):
        r = c.post("/api/dlp-packs/export/start", json=dict(CREDS, **extra, **ALL_DLP_IN_SCOPE))
        assert r.status_code == 400, (extra, r.text)
    assert ro.writes == []


def test_the_inventory_lists_every_custom_engine_for_the_picker():
    import pack_removal
    inv = pack_removal.inventory(_source())
    assert inv["status"] == "ready"
    engines = {e["name"]: e for e in inv["engines"]}
    assert set(engines) == CUSTOM_ENGINES, "predefined engines are not offered"
    assert engines["Unused Engine"]["used"] is False and engines["Project Leak"]["used"] is True
    assert engines["Project Leak"]["dictionaries"] == ["Project Codes", "SSN"]
    assert {n for n, d in inv["dictionaries"].items() if d["custom"]} >= CUSTOM_DICTS


def test_the_export_screen_offers_parts_formats_and_per_part_downloads():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    for needle in ("What to export", "Include what they use", "_dzExportPart(", "_dzExportOpt('format'", "name=\"dzExportFmt\"",
                   "JSON pack and Terraform", "Download one part", "async function _dzExportFile(path)", "file=${encodeURIComponent(path)}",
                   "parts: [...P], include_dependencies: X.deps !== false, format: X.format || 'json'", "Named, not included"):
        assert needle in js, needle
    # An export state built the old way (rules only, no new fields) still renders as before.
    assert "function _dzExportParts(X) { return X.parts instanceof Set ? X.parts : new Set(['rules']); }" in js
