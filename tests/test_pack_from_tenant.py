"""Rebuilding the source-code pack from the tenant's own Anchor/Signal
dictionaries."""
from __future__ import annotations

import json
import os
import shutil

from fastapi.testclient import TestClient

import dlp_api_server as srv
import pack_from_tenant as pft
from test_pack_deploy import Obj
from test_pack_channels import make_client


def _dict(id_, name, patterns, proximity=0, **kw):
    return Obj(id=id_, name=name, custom=True, custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
               patterns=[{"action": "PATTERN_COUNT_TYPE_UNIQUE", "pattern": p} for p in patterns], phrases=[], proximity=proximity, **kw)


def _tenant():
    client = make_client()
    client.zia.dlp_dictionary.items = [
        _dict(1, "SRC-Python Signal", [r"\bdef\b", r"\bimport\b", r"__init__"]),
        _dict(2, "SRC-Python Anchor", [r"^\s*def\s+\w+\("]),
        _dict(3, "Go_Signal_v4", [r"\bfunc\b", r"fmt\.Print"]),
        _dict(4, "Go_Anchor_v4", [r"^package\s+\w+$"]),
        _dict(5, "HTML Signal", [r"<div", r"<span"]),
        _dict(6, "HTML Anchor", [r"<!DOCTYPE html>"]),
        _dict(7, "Rust Signal", [r"\bfn\b"]),                       # no anchor: unpaired
        _dict(8, "Board Confidential", [r"CONFIDENTIAL"]),           # no role: ignored
        Obj(id=9, name="CREDIT_CARD", custom=False),                  # predefined: skipped
        _dict(10, "ZBP-Credit Cards - High", [], dict_template_id=9),  # clone: skipped
    ]
    return client


def test_pairs_anchor_and_signal_by_language_and_builds_all_engines():
    dicts, err = pft.read_custom_dictionaries(_tenant())
    assert err is None and [d["name"] for d in dicts] == ["SRC-Python Signal", "SRC-Python Anchor", "Go_Signal_v4", "Go_Anchor_v4",
                                                          "HTML Signal", "HTML Anchor", "Rust Signal", "Board Confidential"]
    g = pft.pair_anchor_signal(dicts)
    assert sorted(g["pairs"]) == ["go", "html", "src python"]
    assert g["unpaired"] == ["Rust: signal only"] and g["ignored"] == ["Board Confidential"]
    new_dicts, engines = pft.build_configs(g["pairs"], prefix="SRC-", threshold=4, html_threshold=3)
    assert [e["name"] for e in engines] == ["SRC-Go", "SRC-HTML", "SRC-SRCPython"]
    by = {e["name"]: e["expression"] for e in engines}
    assert by["SRC-Go"] == "((D:Go_Signal_v4 > 4) AND (D:Go_Anchor_v4 > 0))"
    assert by["SRC-HTML"] == "((D:HTML Signal > 3) AND (D:HTML Anchor > 0))"
    assert {d["name"] for d in new_dicts} == {"SRC-Python Signal", "SRC-Python Anchor", "Go_Signal_v4", "Go_Anchor_v4", "HTML Signal", "HTML Anchor"}
    assert all("id" not in d for d in new_dicts)
    # A filter narrows to one library.
    g2 = pft.pair_anchor_signal(dicts, "^SRC-")
    assert list(g2["pairs"]) == ["src python"]


def test_rebuild_replaces_the_pack_objects_and_rewires_the_rules(tmp_path):
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zbp_source_code_baseline")
    pack = tmp_path / "pack"
    shutil.copytree(src, pack)
    preview = pft.rebuild_from_tenant(_tenant(), str(pack), name_filter="", dry_run=True)
    assert preview["status"] == "preview" and preview["engines"] == ["SRC-Go", "SRC-HTML", "SRC-SRCPython"]
    assert json.load(open(pack / "configs" / "dlp_engines.json"))[0]["name"].startswith("SRC-CSharp")   # untouched by a preview
    res = pft.rebuild_from_tenant(_tenant(), str(pack), dry_run=False)
    # Every rule that used the old engines is rewired: the inline rule and its per-channel mirrors.
    assert res["status"] == "written" and "SRC-Python" in res["removed_engines"]
    assert "SRC-Python Code to AI-Monitor" in res["rules_rewired"] and len([r for r in res["rules_rewired"] if r.startswith("SRC-") and "[" not in r]) == 13   # one rule per engine
    engines = json.load(open(pack / "configs" / "dlp_engines.json"))
    dicts = json.load(open(pack / "configs" / "dlp_dictionaries.json"))
    policies = json.load(open(pack / "configs" / "dlp_policies.json"))
    assert len(engines) == 3 and len(dicts) == 6
    assert policies[0]["engines"] == ["SRC-Go", "SRC-HTML", "SRC-SRCPython"]
    # The pack still plans cleanly against that tenant: its dictionaries are reused, engines and rules created.
    import pack_deploy as pd
    from test_pack_channels import add_control_services
    client = add_control_services(_tenant())
    rep = pd.preflight(client, [{"id": "zbp_source_code_baseline", "dir": str(pack)}], writes_enabled=True)
    # ready, or warnings only because the SaaS mirror can't bind without an onboarded CASB tenant in this fixture.
    assert rep["status"] in ("ready", "warnings"), rep["blockers"]
    st = {(i["kind"], i["name"]): i["status"] for i in rep["items"]}
    assert st[("dictionary", "SRC-Python Signal")] == pd.REUSE and st[("engine", "SRC-Go")] == pd.CREATE


def test_no_pairs_is_an_error_not_a_wipe(tmp_path):
    pack = tmp_path / "pack"
    (pack / "configs").mkdir(parents=True)
    json.dump([{"name": "Old"}], open(pack / "configs" / "dlp_engines.json", "w"))
    client = make_client()
    client.zia.dlp_dictionary.items = [_dict(1, "Board Confidential", ["X"])]
    res = pft.rebuild_from_tenant(client, str(pack), dry_run=False)
    assert res["status"] == "error" and "No Anchor/Signal" in res["error"]
    assert json.load(open(pack / "configs" / "dlp_engines.json")) == [{"name": "Old"}]


def test_from_tenant_endpoint_previews_then_writes(monkeypatch, tmp_path):
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zbp_source_code_baseline")
    pack = tmp_path / "zbp_source_code_baseline"
    shutil.copytree(src, pack)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _tenant())
    monkeypatch.setattr(srv, "_resolve_pack_ids", lambda ids: [{"id": i, "dir": str(pack)} for i in ids])
    monkeypatch.setattr(srv, "_regenerate_terraform", lambda pack_id, pack_dir: "skipped")
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "name_filter": "", "confirm": False}
    r = c.post("/api/dlp-packs/zbp_source_code_baseline/from-tenant", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "preview" and len(r.json()["languages"]) == 3
    assert len(json.load(open(pack / "configs" / "dlp_engines.json"))) == 13
    body["confirm"] = True
    r = c.post("/api/dlp-packs/zbp_source_code_baseline/from-tenant", json=body)
    assert r.status_code == 200 and r.json()["status"] == "written", r.text
    assert len(json.load(open(pack / "configs" / "dlp_engines.json"))) == 3
