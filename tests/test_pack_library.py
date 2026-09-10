"""
Advanced settings: the policy pack library. Uploads arrive as JSON (one
bundle or the three pack files), Terraform for the zscaler/zia provider,
or a ZIP; they are validated, stored under user_packs/ and discovered
like built-in packs. Removal only touches uploaded packs.
"""
from __future__ import annotations

import base64
import io
import json
import os
import zipfile

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import pack_library as pl
import pack_terraform as pt
from dlp_importer import discover_packs
from test_pack_deploy import _clone, _dict, _engine, _policy, write_pack  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _bundle(name="Acme Pack"):
    return {"name": name, "description": "test", "dictionaries": [_dict("Acme Dict"), _clone("Acme SSN")],
            "engines": [_engine("Acme Engine", "((D:Acme Dict > 0) OR (D:Acme SSN > 2))")],
            "policies": [dict(_policy("Acme-Web-Monitor", ["Acme Engine"]), state="DISABLED")]}


# ---- HCL reader -------------------------------------------------------------

def test_hcl_reader_handles_strings_lists_blocks_refs_and_comprehensions():
    doc = pl.parse_hcl(r'''
# comment
data "zia_dlp_dictionaries" "tpl_ssn" { name = "SSN" }
resource "zia_dlp_dictionaries" "d1" {
  name        = "Alpha \"Dict\""          // trailing comment
  description = "has $${x} and %%{y}"
  proximity   = 100
  custom      = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bA\\d{3}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)x"
  }
  dict_template_id = data.zia_dlp_dictionaries.tpl_ssn.id
  cloud_applications = sort(distinct(concat([for a in data.zia_cloud_applications.apps.applications : a.app])))
  lifecycle { ignore_changes = [tags] }
}
output "o" { value = { for k, v in zia_dlp_dictionaries.d1 : k => v } }
''')
    d = doc["resource"][0]
    assert d["_labels"] == ["zia_dlp_dictionaries", "d1"]
    assert d["name"] == 'Alpha "Dict"' and d["description"] == "has ${x} and %{y}"
    assert d["proximity"] == 100 and d["custom"] is True
    assert [p["pattern"] for p in d["patterns"]] == [r"\bA\d{3}\b", "(?i)x"]
    assert isinstance(d["dict_template_id"], pl.Ref) and "tpl_ssn" in d["dict_template_id"].text
    assert isinstance(d["cloud_applications"], pl.Ref)
    assert doc["data"][0]["name"] == "SSN"


@pytest.mark.parametrize("pack_id", ["global_banking_baseline", "zbp_source_code_baseline", "zbp_endpoint_dlp_baseline", "cjis_policy_pack"])
def test_terraform_export_round_trips_into_a_pack(pack_id):
    pack = next(p for p in discover_packs(ROOT) if p["id"] == pack_id)
    files = {k: v for k, v in pt.generate(pack).items() if k.endswith(".tf")}
    got, warnings = pl.pack_from_terraform(files)
    src = pl.pack_bundle(pack["dir"])
    assert {d["name"] for d in got["dictionaries"]} == {d["name"] for d in src["dictionaries"]}
    assert {e["name"]: e["expression"] for e in got["engines"]} == {e["name"]: e["expression"] for e in src["engines"]}
    assert [p["name"] for p in got["policies"]] == [p["name"] for p in src["policies"]]
    by_name = {p["name"]: p for p in src["policies"]}
    for p in got["policies"]:
        s = by_name[p["name"]]
        assert sorted(p.get("engines") or []) == sorted(s.get("engines") or [])
        assert (p.get("saas_type") or None) == (s.get("saas_type") or None)
        assert len(p.get("sub_rules") or []) == len(s.get("sub_rules") or [])
        if s.get("cloud_app_classes"):
            assert sorted(p["cloud_app_classes"]) == sorted(s["cloud_app_classes"])
        if s.get("actions_by_verb"):
            assert p["actions_by_verb"] == {k.upper(): v.upper() for k, v in s["actions_by_verb"].items()}
    assert pl.validate_pack(dict(got, meta={"name": "x"}))["ok"], pl.validate_pack(dict(got, meta={"name": "x"}))["problems"]
    assert not any("id" in w and "another tenant" in w for w in warnings)


def test_terraform_with_tenant_ids_is_reported():
    got, warnings = pl.pack_from_terraform({"main.tf": '''
resource "zia_dlp_engines" "e" {
  name              = "Old Engine"
  engine_expression = "((D63.S > 0) AND (D${zia_dlp_dictionaries.missing.id}.S > 1))"
}
resource "zia_dlp_web_rules" "r" {
  name = "Old Rule"
  dlp_engines { id = [1234] }
}
'''})
    assert got["engines"][0]["expression"].startswith("((D63.S > 0)")
    v = pl.validate_pack(dict(got, meta={"name": "x"}))
    assert not v["ok"] and any("dictionary id 63" in p for p in v["problems"])
    assert any("engine id 1234" in w for w in warnings)


# ---- assembling uploads ----------------------------------------------------

def test_one_json_bundle():
    pack = pl.assemble_pack([{"name": "acme.json", "content": json.dumps(_bundle())}])
    assert pack["meta"]["name"] == "Acme Pack" and pack["format"] == "json"
    v = pl.validate_pack(pack)
    assert v["ok"] and v["counts"] == {"dictionaries": 2, "engines": 1, "policies": 1, "app_groups": 0, "clones": 1}
    assert v["channels"] == ["web"]


def test_three_files_named_or_recognised_by_content():
    b = _bundle()
    pack = pl.assemble_pack([
        {"name": "dlp_dictionaries.json", "content": json.dumps(b["dictionaries"])},
        {"name": "whatever.json", "content": json.dumps(b["engines"])},      # recognised: items carry an expression
        {"name": "rules.json", "content": json.dumps(b["policies"])},
        {"name": "pack.json", "content": json.dumps({"name": "Named In Pack", "version": "2.1"})},
    ])
    assert pack["meta"]["name"] == "Named In Pack" and pack["meta"]["version"] == "2.1"
    assert pl.validate_pack(pack)["counts"]["engines"] == 1


def test_zip_of_terraform_workspace():
    pack = next(p for p in discover_packs(ROOT) if p["id"] == "zbp_source_code_baseline")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in pt.generate(pack).items():
            z.writestr(f"workspace/{k}", v)
        z.writestr("__MACOSX/._junk.tf", "x")
    got = pl.assemble_pack([{"name": "ws.zip", "content": base64.b64encode(buf.getvalue()).decode(), "encoding": "base64"}], pack_name="From Zip")
    assert got["format"] == "terraform" and got["meta"]["name"] == "From Zip"
    assert pl.validate_pack(got)["counts"]["engines"] == 13


def test_bad_uploads_are_explained():
    with pytest.raises(ValueError, match="not valid JSON"):
        pl.assemble_pack([{"name": "x.json", "content": "{"}])
    with pytest.raises(ValueError, match="cannot tell"):
        pl.assemble_pack([{"name": "x.json", "content": json.dumps([{"foo": 1}])}])
    with pytest.raises(ValueError, match="no dictionaries, engines or rules"):
        pl.assemble_pack([{"name": "README.md", "content": "hello"}, {"name": "empty.json", "content": "[]"}])
    with pytest.raises(ValueError, match="rules.tf"):
        pl.assemble_pack([{"name": "rules.tf", "content": 'resource "zia_dlp_web_rules" {'}])


def test_validation_blocks_broken_packs_and_warns_on_the_rest():
    v = pl.validate_pack({"meta": {}, "dictionaries": [{"name": "D", "patterns": [{"pattern": "("}], "phrases": []}, {"name": "D", "phrases": [{"phrase": "abc"}]}],
                          "engines": [{"name": "E", "expression": "(D:D > 0) AND (D:Other > 0)"}, {"name": "Empty", "expression": ""}],
                          "policies": [{"name": "R", "engines": ["E", "Nope"], "state": "ENABLED"}, {"name": "S", "channel": "saas", "engines": ["E"]}]})
    assert not v["ok"]
    joined = " | ".join(v["problems"])
    assert "does not compile" in joined and "appears twice" in joined and "empty expression" in joined and "saas_type" in joined
    warned = " | ".join(v["warnings"])
    assert "'Other' is not in this pack" in warned and "engine 'Nope'" in warned and "ENABLED" in warned


# ---- library on disk --------------------------------------------------------

def test_save_discover_bundle_and_delete(tmp_path):
    write_pack(tmp_path, "builtin", dicts=[_dict("B")], engines=[_engine("BE", "(D:B > 0)")], policies=[_policy("B-Rule", ["BE"])])
    pack = pl.assemble_pack([{"name": "acme.json", "content": json.dumps(_bundle())}])
    saved = pl.save_pack(pack, root=str(tmp_path))
    assert saved["id"] == "acme_pack" and saved["source"] == "uploaded"
    assert os.path.isfile(tmp_path / "user_packs" / "acme_pack" / "configs" / "dlp_engines.json")
    meta = json.load(open(tmp_path / "user_packs" / "acme_pack" / "pack.json"))
    assert meta["source"] == "uploaded" and meta["upload_format"] == "json" and meta["uploaded_at"].endswith("Z")

    found = {p["id"]: p for p in discover_packs(str(tmp_path))}
    assert found["builtin"]["source"] == "built-in" and found["acme_pack"]["source"] == "uploaded"
    assert found["acme_pack"]["dictionaries"] == 2 and found["acme_pack"]["policies"] == 1

    with pytest.raises(FileExistsError):
        pl.save_pack(pack, root=str(tmp_path))
    with pytest.raises(FileExistsError):
        pl.save_pack(pack, pack_id="builtin", root=str(tmp_path))

    b = pl.pack_bundle(found["acme_pack"]["dir"])
    assert b["name"] == "Acme Pack" and [e["name"] for e in b["engines"]] == ["Acme Engine"]

    with pytest.raises(FileNotFoundError):
        pl.delete_pack("builtin", root=str(tmp_path))
    with pytest.raises(FileNotFoundError):
        pl.delete_pack("../builtin", root=str(tmp_path))
    pl.delete_pack("acme_pack", root=str(tmp_path))
    assert "acme_pack" not in {p["id"] for p in discover_packs(str(tmp_path))}
    assert (tmp_path / "builtin").is_dir()


def test_user_packs_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_USER_PACKS", str(tmp_path / "elsewhere"))
    assert pl.user_packs_dir() == str(tmp_path / "elsewhere")
    assert pl.user_packs_dir(str(tmp_path)) == str(tmp_path / "user_packs")   # an explicit root wins (tests, tools)


# ---- HTTP -------------------------------------------------------------------

@pytest.fixture
def lib_client(monkeypatch, tmp_path):
    monkeypatch.setattr(srv, "PACKS_ROOT", str(tmp_path))
    monkeypatch.setattr("dlp_importer.PACKS_ROOT", str(tmp_path))
    monkeypatch.setattr("pack_library.PACKS_ROOT", str(tmp_path))
    monkeypatch.setattr(srv, "get_bind_host", lambda: "127.0.0.1")
    write_pack(tmp_path, "builtin", dicts=[_dict("B")], engines=[_engine("BE", "(D:B > 0)")], policies=[_policy("B-Rule", ["BE"])])
    return TestClient(srv.app)


def test_preview_upload_list_and_remove_over_http(lib_client):
    c = lib_client
    r = c.post("/api/pack-library/preview", json={"files": [{"name": "acme.json", "content": json.dumps(_bundle())}]})
    assert r.status_code == 200 and r.json()["ok"] and r.json()["pack_id"] == "acme_pack"
    assert [d["name"] for d in r.json()["dictionaries"]] == ["Acme Dict", "Acme SSN"]
    assert r.json()["policies"][0]["channel"] == "web"

    r = c.post("/api/pack-library/preview", json={"files": [{"name": "acme.json", "content": json.dumps(_bundle("Builtin"))}]})
    assert not r.json()["ok"] and "already exists" in r.json()["problems"][-1]

    r = c.post("/api/pack-library/upload", json={"files": [{"name": "acme.json", "content": json.dumps(_bundle())}], "pack_id": "my_acme"})
    assert r.status_code == 200, r.text
    assert r.json()["pack"]["id"] == "my_acme" and r.json()["pack"]["source"] == "uploaded"
    assert c.post("/api/pack-library/upload", json={"files": [{"name": "acme.json", "content": json.dumps(_bundle())}], "pack_id": "my_acme"}).status_code == 409
    assert c.post("/api/pack-library/upload", json={"files": [{"name": "x.json", "content": "{"}]}).status_code == 400

    lib = c.get("/api/pack-library").json()
    assert {p["id"]: p["source"] for p in lib["packs"]} == {"builtin": "built-in", "my_acme": "uploaded"}
    assert lib["writes_allowed"] is True and lib["user_packs_dir"].endswith("user_packs")
    # The generic pack list (Deploy Policy Packs) sees it too.
    assert "my_acme" in {p["id"] for p in c.get("/api/dlp-packs").json()["packs"]}

    r = c.get("/api/pack-library/my_acme/bundle")
    assert r.status_code == 200 and r.headers["content-disposition"].endswith('my_acme.json"') and r.json()["name"] == "Acme Pack"

    assert c.post("/api/pack-library/builtin/remove").status_code == 404
    assert c.post("/api/pack-library/my_acme/remove").status_code == 200
    assert "my_acme" not in {p["id"] for p in c.get("/api/pack-library").json()["packs"]}


def test_writes_are_refused_when_exposed_without_the_ui_token(lib_client, monkeypatch):
    monkeypatch.setattr(srv, "get_bind_host", lambda: "0.0.0.0")
    c = lib_client
    body = {"files": [{"name": "acme.json", "content": json.dumps(_bundle())}]}
    assert c.post("/api/pack-library/preview", json=body).status_code == 200      # looking is fine
    assert c.post("/api/pack-library/upload", json=body).status_code == 403
    assert c.post("/api/pack-library/builtin/remove").status_code == 403
    assert c.get("/api/pack-library").json()["writes_allowed"] is False
    # With the UI token gate on, a network-exposed server may accept uploads (the token guards the request).
    monkeypatch.setattr(srv._security, "ui_auth_enabled", lambda: True)
    assert c.post("/api/pack-library/upload", json=body).status_code == 401          # no token: the gate holds
    assert c.post("/api/pack-library/upload", json=body, headers={"X-DLP-Check-Token": srv._security.ui_token()}).status_code == 200


def test_advanced_page_is_served_and_wired_into_the_gui(lib_client):
    c = lib_client
    r = c.get("/report/advanced")
    assert r.status_code == 200 and 'id="advFiles"' in r.text and "/static/advanced.js" in r.text
    index = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert "openAdvancedTab()" in index and "/report/advanced" in index
