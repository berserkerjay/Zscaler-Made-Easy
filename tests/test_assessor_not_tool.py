"""
The assessor's name never names the tool (user rule 2). "Zscaler Made Easy" in any
spelling is refused (400) by every pack push and the library's Terraform
download before the tenant is signed in to, by the Terraform CLI, and by
the workspace's var.assessor validation: one shared rule,
pack_deploy.TOOL_NAME_PATTERN.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import pack_deploy
import pack_terraform

ROOT = os.path.join(os.path.dirname(__file__), "..")
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
PACK = "zbp_enterprise_baseline"
TOOL_NAMES = ["Zscaler Made Easy", "dlp-check", "dlp check", "DLPCheck", "DLP_Check", "DLP–Check",
              "DLP-Check pack", "Zscaler Made Easy Team", "Jane (Zscaler Made Easy)",
              "  [DLP-Check]  ", "[dlp-check]", "dlp-check team"]   # F2-6: brackets are stripped first


@pytest.fixture
def client(monkeypatch):
    def no_tenant(*a, **k):
        raise AssertionError("the tenant must not be signed in to with the tool's name as assessor")
    monkeypatch.setattr(srv, "_build_sdk_client", no_tenant)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv._security, "require_writer", lambda *a, **k: None)
    return TestClient(srv.app)


@pytest.mark.parametrize("name", TOOL_NAMES)
def test_the_shared_rule_refuses_the_tool_name_in_any_spelling(name):
    assert pack_deploy.is_tool_name(name)
    assert pack_deploy.assessor_name(name) == ""
    for ok in ("Jane Doe", "Pat", "Check Point team"):
        assert not pack_deploy.is_tool_name(ok) and pack_deploy.assessor_name(ok) == ok


@pytest.mark.parametrize("path,body", [
    ("/api/dlp-packs/apply", dict(CREDS, pack_ids=[PACK], plan_hash="h", confirm=True)),
    ("/api/dlp-packs/apply/start", dict(CREDS, pack_ids=[PACK], plan_hash="h", confirm=True)),
    (f"/api/dlp-packs/{PACK}/import", dict(CREDS, plan_hash="h")),
    ("/api/dlp-packs/terraform", {"pack_ids": [PACK], "mode": "static"}),
    ("/api/dlp-packs/terraform/start", dict(CREDS, pack_ids=[PACK], mode="gap")),
])
@pytest.mark.parametrize("name", ["Zscaler Made Easy", "dlp check", "DLP-Check pack", "  [DLP-Check]  "])
def test_every_pack_push_refuses_the_tool_name(client, path, body, name):
    r = client.post(path, json=dict(body, assessor=name))
    assert r.status_code == 400, r.text
    assert "not the tool" in r.json()["detail"]


@pytest.mark.parametrize("name", ["Zscaler Made Easy", "dlp check", "DLP-Check pack"])
def test_the_library_download_refuses_the_tool_name(client, name):
    r = client.get(f"/api/pack-library/{PACK}/terraform.zip", params={"assessor": name})
    assert r.status_code == 400 and "not the tool" in r.json()["detail"]


def test_a_saved_profile_named_after_the_tool_is_refused_too(client, monkeypatch):
    import tenant_profiles
    monkeypatch.setattr(tenant_profiles, "get", lambda p, **kw: {"assessor": "Zscaler Made Easy"} if p == "p1" else None)
    r = client.get(f"/api/pack-library/{PACK}/terraform.zip", params={"profile_id": "p1"})
    assert r.status_code == 400 and "not the tool" in r.json()["detail"]


def test_a_tool_name_in_the_request_does_not_fall_back_to_the_profile(client, monkeypatch):
    import tenant_profiles
    monkeypatch.setattr(tenant_profiles, "get", lambda p, **kw: {"assessor": "Sam Lee"})
    r = client.get(f"/api/pack-library/{PACK}/terraform.zip", params={"profile_id": "p1", "assessor": "Zscaler Made Easy"})
    assert r.status_code == 400


def test_generate_never_stamps_the_tool_name():
    from dlp_importer import discover_packs
    pack = next(p for p in discover_packs() if p["id"] == PACK)
    files = pack_terraform.generate({"id": PACK, "dir": pack["dir"]}, assessor="Zscaler Made Easy")
    text = "\n".join(files.values())
    assert "[DLP-Check pack" not in text and "[DLP-Check baseline" not in text
    assert "var.assessor" in text, "the workspace asks for a real name instead"


def test_the_cli_and_the_workspace_validation_use_the_same_rule(tmp_path):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "pack_terraform.py"), PACK, "--out", str(tmp_path),
                        "--assessor", "DLP Check"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode != 0 and "not the tool" in r.stderr
    hcl = 'regexall("(?i)dlp[\\\\W_]*check|zscaler[\\\\W_]*made[\\\\W_]*easy", var.assessor)'
    assert hcl in pack_terraform._ASSESSOR_VARIABLE
    assert hcl.replace("\\\\", "\\").split('"')[1] == pack_deploy.TOOL_NAME_PATTERN
    committed = glob.glob(os.path.join(ROOT, "terraform", "*", "variables.tf"))
    assert committed
    for f in committed:
        assert hcl in open(f, encoding="utf-8").read(), f


def test_the_pages_refuse_the_tool_name_before_pushing():
    studio = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    adv = open(os.path.join(ROOT, "static", "advanced.js"), encoding="utf-8").read()
    assert "/dlp[\\W_]*check|zscaler[\\W_]*made[\\W_]*easy/i.test(who)" in studio and "/dlp[\\W_]*check|zscaler[\\W_]*made[\\W_]*easy/i.test(who)" in adv
