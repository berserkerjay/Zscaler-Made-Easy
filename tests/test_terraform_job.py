"""The Terraform hand-off never looks stuck: gap mode's tenant read is
logged step by step, the hand-off runs as a job the browser follows, and
the zip is fetched from the finished job. The same read lines show up at
the start of a deploy (its preflight) and at its read-back."""
from __future__ import annotations

import io
import time
import zipfile

import pack_deploy as pd
from dlp_importer import discover_packs
from test_pack_channels import TENANTS, add_control_services, make_client
from test_zia_contract import strict_tenant


def _pack(pid):
    return next({"id": p["id"], "dir": p["dir"]} for p in discover_packs() if p["id"] == pid)


def test_the_tenant_read_says_what_it_is_reading():
    client = add_control_services(make_client(casb_tenants=TENANTS))
    logs = []
    pd.preflight(client, [_pack("fed_policy_pack")], writes_enabled=True, log=logs.append)
    text = "\n".join(logs)
    for step in ("Reading the tenant: DLP dictionaries", "DLP dictionaries: ", "Reading the tenant: DLP engines", "Reading the tenant: Web DLP rules",
                 "Reading the tenant: Endpoint DLP rules", "Reading the tenant: SaaS Security API rules", "Reading the tenant: Email DLP rules",
                 "Reading the tenant: SaaS application tenants", "Tenant read in "):
        assert step in text, step
    assert logs[-1].startswith("Tenant read in "), logs[-1]


def test_a_deploy_logs_its_preflight_and_read_back_before_and_after_the_writes():
    client = strict_tenant()
    pack = _pack("zbp_enterprise_baseline")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    logs = []
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, log=logs.append)
    assert res["status"] == "applied"
    assert logs[0].startswith("Checking the approved plan against the tenant")
    reads = [i for i, l in enumerate(logs) if l.startswith("Reading the tenant: DLP dictionaries (custom")]
    phase1 = logs.index("Phase 1: dictionaries")
    back = logs.index("Reading the tenant back to verify the deployment…")
    assert len(reads) == 2 and reads[0] < phase1 < back < reads[1], "one read before the writes, one after"


def _wait(c, job_id, timeout=60):
    since, logs = 0, []
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = c.get(f"/api/dlp-packs/jobs/{job_id}?since={since}").json()
        logs += snap["logs"]
        since = snap["next"]
        if snap["status"] != "running":
            snap["logs"] = logs
            return snap
        time.sleep(0.05)
    raise AssertionError("the job did not finish in time")


def test_the_hand_off_runs_as_a_job_and_the_zip_comes_from_it(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    client = add_control_services(make_client(casb_tenants=TENANTS))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "assessor": "Jane Doe"}
    # Static: no tenant read, the whole pack.
    r = c.post("/api/dlp-packs/terraform/start", json={"pack_ids": ["zbp_enterprise_baseline"], "mode": "static", "assessor": "Jane Doe"})
    assert r.status_code == 200 and r.json()["kind"] == "terraform", r.text
    snap = _wait(c, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "ready" and snap["result"]["mode"] == "static"
    assert snap["download"].endswith("/download") and snap["filename"].startswith("dlp-check-terraform-static-") and snap["bytes"] > 1000
    assert any(l.startswith("Static mode") for l in snap["logs"]) and not any("Reading the tenant" in l for l in snap["logs"])
    assert "artifact" not in snap["result"], "the zip is not in the JSON"
    z = c.get(snap["download"])
    assert z.status_code == 200 and z.headers["content-type"].startswith("application/zip") and z.headers["x-dlp-check-mode"] == "static"
    names = zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    assert any(n.endswith("zbp_enterprise_baseline/rules.tf") for n in names) and not any(n.endswith("imports.tf") for n in names)
    # Gap: the tenant read is logged and imports.tf is written for what exists.
    pd.apply(client, [_pack("zbp_enterprise_baseline")], plan_hash=pd.preflight(client, [_pack("zbp_enterprise_baseline")], writes_enabled=True)["plan_hash"],
             writes_enabled=True, verify=False)
    r = c.post("/api/dlp-packs/terraform/start", json=dict(creds, pack_ids=["zbp_enterprise_baseline"], mode="gap"))
    snap = _wait(c, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["mode"] == "gap" and snap["result"]["gap"].get("reuse", 0) > 0, snap.get("error")
    assert any(l.startswith("Reading the tenant: DLP dictionaries") for l in snap["logs"]) and any(l.startswith("Plan: ") for l in snap["logs"])
    names = zipfile.ZipFile(io.BytesIO(c.get(snap["download"]).content)).namelist()
    assert any(n.endswith("imports.tf") for n in names)
    # A gap request without credentials is refused before any job starts; a running or unknown job has no download.
    assert c.post("/api/dlp-packs/terraform/start", json={"pack_ids": ["zbp_enterprise_baseline"], "mode": "gap", "assessor": "Jane Doe"}).status_code == 400
    assert c.get("/api/dlp-packs/jobs/nope/download").status_code == 404
    # The waiting endpoint still answers with the zip itself.
    z = c.post("/api/dlp-packs/terraform", json={"pack_ids": ["zbp_enterprise_baseline"], "mode": "static", "assessor": "Jane Doe"})
    assert z.status_code == 200 and z.headers["x-dlp-check-mode"] == "static" and zipfile.ZipFile(io.BytesIO(z.content)).namelist()


def test_the_hand_off_page_follows_the_job():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    for needle in ("/api/dlp-packs/terraform/start", "snap.download", "TF.last", "Hand-off log", "Reading the tenant, then building the workspace"):
        assert needle in js, needle
    assert "fetch('/api/dlp-packs/terraform'" not in js, "the page no longer waits on one long request"
