"""
The assessor's name is mandatory for every policy pack push: deploy,
the single-pack import, the Terraform hand-off and the library's
Terraform download. Without it the request is refused (400) before the
tenant is signed in to or read, so no object is ever tagged DLP-Check.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
PACK = "zbp_enterprise_baseline"


@pytest.fixture
def client(monkeypatch):
    def no_tenant(*a, **k):
        raise AssertionError("the tenant must not be signed in to without an assessor name")
    monkeypatch.setattr(srv, "_build_sdk_client", no_tenant)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv._security, "require_writer", lambda *a, **k: None)
    return TestClient(srv.app)


@pytest.mark.parametrize("path,body", [
    ("/api/dlp-packs/apply", dict(CREDS, pack_ids=[PACK], plan_hash="h", confirm=True)),
    ("/api/dlp-packs/apply/start", dict(CREDS, pack_ids=[PACK], plan_hash="h", confirm=True)),
    (f"/api/dlp-packs/{PACK}/import", dict(CREDS, plan_hash="h")),
    ("/api/dlp-packs/terraform", {"pack_ids": [PACK], "mode": "static"}),
    ("/api/dlp-packs/terraform/start", dict(CREDS, pack_ids=[PACK], mode="gap")),
])
@pytest.mark.parametrize("assessor", ["", "   ", "[]"])
def test_every_pack_push_refuses_without_an_assessor_before_reading_the_tenant(client, path, body, assessor):
    r = client.post(path, json=dict(body, assessor=assessor))
    assert r.status_code == 400, r.text
    assert "assessor" in r.json()["detail"].lower() and "never DLP-Check" in r.json()["detail"]


def test_the_library_terraform_download_refuses_without_an_assessor(client):
    assert client.get(f"/api/pack-library/{PACK}/terraform.zip").status_code == 400
    assert client.get(f"/api/pack-library/{PACK}/terraform.zip", params={"assessor": "Jane Doe"}).status_code == 200


def test_the_saved_profiles_assessor_counts(client, monkeypatch):
    import tenant_profiles
    monkeypatch.setattr(tenant_profiles, "get", lambda p, **kw: {"assessor": "Sam Lee"} if p == "p1" else None)
    r = client.get(f"/api/pack-library/{PACK}/terraform.zip", params={"profile_id": "p1"})
    assert r.status_code == 200


def test_the_import_plan_still_works_without_an_assessor(monkeypatch):
    """Planning writes nothing, so only the deploying call needs the name."""
    import pack_deploy
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv._security, "require_writer", lambda *a, **k: None)
    monkeypatch.setattr(pack_deploy, "preflight", lambda *a, **k: {"items": [], "plan_hash": "h"})
    monkeypatch.setattr(pack_deploy, "public_report", lambda rep: dict(rep))
    r = TestClient(srv.app).post(f"/api/dlp-packs/{PACK}/import", json=CREDS)
    assert r.status_code == 200 and r.json()["status"] == "plan"


def test_the_pages_ask_for_the_assessor_before_pushing():
    root = os.path.join(os.path.dirname(__file__), "..", "static")
    studio = open(os.path.join(root, "deploy_studio.js"), encoding="utf-8").read()
    adv = open(os.path.join(root, "advanced.js"), encoding="utf-8").read()
    assert studio.count("_dzNeedAssessor();") == 2, "deploy and the Terraform hand-off both check first"
    assert "never DLP-Check" in studio
    assert "Enter the assessor's name first" in adv and "e.preventDefault()" in adv


def test_no_page_promises_a_dlp_check_tag_when_the_assessor_is_blank():
    # The assessor is required for every push and download: no page may say
    # a blank name falls back to a DLP-Check tag.
    import glob
    import re
    root = os.path.join(os.path.dirname(__file__), "..", "static")
    promise = re.compile(r"DLP-Check\s+(only\s+)?(when|if)\b[^.<]*\bblank|blank[^.<]*\b(falls back|defaults?) to\s+DLP-Check", re.I)
    for path in glob.glob(os.path.join(root, "*.html")) + glob.glob(os.path.join(root, "*.js")):
        text = open(path, encoding="utf-8").read()
        m = promise.search(text)
        assert not m, f"{os.path.basename(path)} promises a DLP-Check fallback: {m.group(0)!r}"
    adv = open(os.path.join(root, "report_advanced.html"), encoding="utf-8").read()
    assert "never DLP-Check" in adv and "download is refused" in adv
