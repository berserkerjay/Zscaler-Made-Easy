"""
Assessor attribution, round 2: every tag the deploy writes is read back
(free-text versions and pack ids with spaces), objects of a pack since gone
from the library are still found, an assessor's name cannot forge another
pack's tag, the historical tag texts still remove cleanly, classic-API
tenants on one cloud keep their rate history apart, the assessor is
resolved once per run, and the server wiring the CHANGELOG describes is
covered end to end.
"""
from __future__ import annotations

import io
import os
import zipfile
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import deployments
import pack_deploy as pd
import pack_export
import pack_removal as pr
import pack_terraform
import tenant_auth
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack

LEGACY = {"auth_method": "legacy", "username": "admin@acme.com", "password": "pw", "api_key": "k" * 12,
          "vanity_domain": "acme-stale", "cloud": "zscalerten"}
OTHER_LEGACY = dict(LEGACY, username="admin@other.com", vanity_domain="other")


def _pack(tmp_path, version="2", pack_id="alpha"):
    return write_pack(tmp_path, pack_id, dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict > 0)")],
                      policies=[_policy("Z-Alpha-Monitor", ["Alpha Engine"])],
                      meta={"name": "Alpha Pack", "version": version, "confidence_tweaks": []})


def _deployed_descs(tmp_path, version, assessor):
    pack = _pack(tmp_path, version)
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, assessor=assessor)
    assert res["status"] == "applied"
    z = client.zia
    return pack, z.dlp_dictionary.added[0]["description"], z.dlp_engine.added[0].get("description"), z.dlp_web_rules.added[0]["description"]


def _renamed(d, e, r):
    return FakeClient(dicts=[Obj(id=1, name="Renamed Dict", custom=True, description=d)],
                      engines=[Obj(id=11, name="Renamed Engine", engine_expression="D1.S > 0", description=e)],
                      rules=[Obj(id=21, name="Renamed Rule", order=1, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 11}],
                                 description=r)])


# --- free-text versions and pack ids -------------------------------------------

@pytest.mark.parametrize("assessor", ["", "Jane Doe"])
def test_a_version_with_a_space_is_read_back_whoever_deployed(tmp_path, assessor):
    pack, d, e, r = _deployed_descs(tmp_path, "1.0 beta", assessor)
    assert all("alpha v1.0 beta]" in x for x in (d, e, r))
    assert pr.plan_removal(_renamed(d, e, r), [pack])["remove_count"] == 3
    for x in (d, e, r):
        assert pd.has_mark(x, pack_id="alpha") and pd.tag_pack(x, known={"alpha"}) == "alpha" and pd.tag_pack(x) == "alpha"
        assert "[" not in pd.strip_mark(x, known={"alpha"}) and "[" not in pd.strip_mark(x)
    item = {"kind": "policy", "pack": "alpha", "pack_version": "1.0 beta"}
    assert pd.pack_description(item, r, by="Sam Lee") == "[Sam Lee pack alpha v1.0 beta] Deployed DISABLED; enable once reviewed."
    item = {"kind": "dictionary", "pack": "alpha", "pack_version": "1.0 beta"}
    assert pd.pack_description(item, "Cards [Jane Doe pack alpha v1.0 beta]", by="Sam Lee") == "Cards [Sam Lee pack alpha v1.0 beta]"


def test_baselines_and_terraform_with_free_text_versions_and_spaced_pack_ids():
    assert pd._has_mark("Eng [Jane Doe baseline zbp v4.16 rc1] Measured on every journey check, never overwritten.", "zbp")
    spaced = "[Jane Doe baseline My Pack v1] Measured on every journey check, never overwritten."
    assert pd.has_mark(spaced, pack_id="My Pack") and pd.tag_pack(spaced, known={"My Pack"}) == "My Pack"
    assert pd.strip_mark("Eng " + spaced, known={"My Pack"}) == "Eng"
    b = {"kind": "dictionary", "baseline": {"pack": "My Pack", "version": "1 rc"}}
    once = pd.baseline_description(b, "Eng", by="Jane Doe")
    assert pd.baseline_description(b, once, by="Sam Lee") == pd.baseline_description(b, "Eng", by="Sam Lee")
    t = pack_terraform._provenance({"version": "1.0 beta", "_by": "Jane Doe"}, "alpha", "Cards")
    assert t == "Cards [Jane Doe pack alpha v1.0 beta] Terraform-managed." and pd.has_mark(t, pack_id="alpha")


# --- packs since gone from the library -------------------------------------------

def test_objects_of_a_pack_no_longer_in_the_library_are_still_found(monkeypatch):
    monkeypatch.setattr(pd, "library_ids", lambda: {"fed_policy_pack"})
    monkeypatch.setattr(pack_export, "_known_packs", lambda: frozenset({"fed_policy_pack"}))
    rules = [{"id": 1, "name": "Old A", "description": "x [DLP-Check pack retired-upload v1] Deployed DISABLED; enable once reviewed."},
             {"id": 2, "name": "Old B", "description": "x [Jane Doe pack retired-upload v1] Deployed DISABLED; enable once reviewed."},
             {"id": 3, "name": "Dict-like", "description": "Cards [Jane Doe pack retired-upload v1]"},
             {"id": 4, "name": "Theirs", "description": "Customer finance rule [Q3 pack review]"}]
    snap = {"reachable": True, "dictionaries": {}, "engines": {}, "channels": {}, "rules": rules}
    monkeypatch.setattr(pd, "fetch_tenant", lambda client, need=None: snap)
    got = {r["name"]: (r["tagged"], r["pack"]) for r in pr.inventory(object())["rules"]}
    assert got == {"Old A": (True, "retired-upload"), "Old B": (True, "retired-upload"), "Dict-like": (True, "retired-upload"),
                   "Theirs": (False, None)}
    assert pack_export._strip_mark(rules[1]["description"]) == "x"
    client = FakeClient(rules=[Obj(id=r["id"], name=r["name"], order=r["id"], action="ALLOW", state="DISABLED", dlp_engines=[],
                                   description=r["description"]) for r in rules])
    plan = pr.plan_removal(client, [], everything=True)
    names = sorted(i["name"] for i in plan["items"] if i.get("status") == "remove" and i.get("kind") == "policy")
    assert names == ["Dict-like", "Old A", "Old B"]


# --- a name cannot forge another pack's tag -------------------------------------

def test_an_assessor_name_cannot_forge_the_legacy_tag_of_another_pack(tmp_path):
    for name in ("DLP-Check pack alpha", "dlp-check  baseline alpha", " DLP-Check pack alpha "):
        assert "DLP-Check pack" not in pd.attribution(name) and "dlp-check baseline" not in pd.attribution(name).lower()
    item = {"kind": "policy", "pack": "beta", "pack_version": "1"}
    d = pd.pack_description(item, "Beta rule", by="DLP-Check pack alpha")
    assert "[DLP-Check pack alpha" not in d
    # Even a forged tag written by an older build counts only for the pack id it really names.
    forged = "Beta rule [DLP-Check pack alpha pack beta v1] Deployed DISABLED; enable once reviewed."
    assert not pd.has_mark(forged, pack_id="alpha") and pd.has_mark(forged, pack_id="beta")
    assert pd.tag_pack(forged) == "beta"
    alpha = _pack(tmp_path)
    client = FakeClient(rules=[Obj(id=21, name="Beta rule", order=1, action="BLOCK", state="ENABLED", dlp_engines=[], description=forged)])
    assert pr.plan_removal(client, [alpha])["remove_count"] == 0


# --- tag texts earlier versions wrote ------------------------------------------

HISTORICAL = [
    ("[DLP-Check baseline zbp v4] Immutable: drift is reverted on the next deploy.", "zbp", "baseline"),
    ("Eng [DLP-Check baseline zbp v4] Deployed by DLP-Check; measured on every journey check, never overwritten.", "zbp", "baseline"),
    ("Cards [DLP-Check pack alpha v2] Deployed by DLP-Check.", "alpha", "pack"),
    ("Cards [DLP-Check pack alpha v2] owner: finance", "alpha", "pack"),
]


@pytest.mark.parametrize("desc,pid,kind", HISTORICAL)
def test_tags_written_by_earlier_versions_are_still_recognised(desc, pid, kind):
    assert pd.MARK_RE.search(desc) is None          # only the legacy recogniser reads these
    assert pd.has_mark(desc, pack_id=pid) and pd.has_mark(desc, kind=kind) and pd.has_mark(desc)
    assert not pd.has_mark(desc, pack_id="other")
    assert pd.tag_pack(desc) == pid and "DLP-Check" not in pd.strip_mark(desc)
    if kind == "baseline":
        assert pd._has_mark(desc, pid) and pd._has_mark(Obj(id=1, name="n", description=desc), pid)


def test_objects_with_historical_tags_remove_by_tag(tmp_path):
    pack = _pack(tmp_path)
    d, e, r = HISTORICAL[2][0], "[DLP-Check pack alpha v1] Deployed by DLP-Check.", "Mon [DLP-Check pack alpha v1] Deployed by DLP-Check."
    plan = pr.plan_removal(_renamed(d, e, r), [pack])
    assert plan["remove_count"] == 3


# --- classic-API tenants keep their rate history apart ----------------------------

def test_two_classic_api_tenants_on_one_cloud_do_not_share_rate_history(monkeypatch, tmp_path):
    import dlp_api_server as srv
    import zia_rate
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    a, b = tenant_auth.normalize(LEGACY), tenant_auth.normalize(OTHER_LEGACY)
    assert tenant_auth.record_label(a) == tenant_auth.record_label(b)
    now = datetime.now(timezone.utc)
    rec = deployments.from_apply({"results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}]},
                                 tenant_label=tenant_auth.record_label(a), packs=["alpha"], options={}, tenant_key=srv._tenant_key(a))
    rec["at"] = now.isoformat()
    rec["failed"] = [{"kind": "engine", "name": "e", "error": "HTTP 429 Rate Limit (1/SECOND) exceeded"}]
    deployments.add(rec)
    assert "tenant_key" not in deployments.summary(rec)        # never shown
    assert "acme" not in rec["tenant_key"] and "admin" not in rec["tenant_key"]
    fb = zia_rate.forecast({"write": 3}, key=srv._tenant_key(b), tenant_label=tenant_auth.record_labels(b))
    fa = zia_rate.forecast({"write": 3}, key=srv._tenant_key(a), tenant_label=tenant_auth.record_labels(a))
    t = now.timestamp() + 1
    assert zia_rate._track_record(t, tenant_auth.record_labels(b), srv._tenant_key(b))["runs"] == 0
    assert zia_rate._track_record(t, tenant_auth.record_labels(a), srv._tenant_key(a))["runs"] == 1
    assert not fb.get("refused_runs") and fa.get("refused_runs")


# --- the assessor is resolved once per run --------------------------------------

def test_the_tag_and_the_record_name_the_same_assessor_when_the_profile_changes_mid_run(monkeypatch, tmp_path):
    import dlp_api_server as srv
    import tenant_profiles
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    profile = {"assessor": "Alice Auditor"}
    monkeypatch.setattr(tenant_profiles, "get", lambda pid, **kw: dict(profile))
    seen = {}

    def fake_apply(client, packs, **kw):
        seen["tag"] = kw["assessor"]
        profile["assessor"] = "Bob Builder"          # saved in another tab during the deploy
        return {"status": "applied", "results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}], "summary": {"created": 1}}
    monkeypatch.setattr(pd, "apply", fake_apply)
    req = srv.DLPPackDeployRequest(pack_ids=["alpha"], plan_hash="h", profile_id="acme")
    out = srv._run_apply(object(), tenant_auth.normalize(LEGACY), req, [{"id": "alpha"}], None, None)
    assert seen["tag"] == out["deployment"]["by"] == "Alice Auditor"

    profile["assessor"] = "Alice Auditor"
    names = []

    def fake_generate(p, **kw):
        names.append(kw.get("assessor"))
        profile["assessor"] = "Bob Builder"
        return {"main.tf": "# x\n"}
    monkeypatch.setattr(pack_terraform, "generate", fake_generate)
    srv._run_terraform(None, {}, srv.DLPPackDeployRequest(pack_ids=["a", "b"], profile_id="acme"), [{"id": "a"}, {"id": "b"}], None, None)
    assert names == ["Alice Auditor", "Alice Auditor"]


# --- the pack library's Terraform download names the assessor --------------------

def _zip_text(content):
    z = zipfile.ZipFile(io.BytesIO(content))
    return "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".tf"))


def test_the_pack_library_terraform_download_names_the_assessor(monkeypatch):
    import dlp_api_server as srv
    import tenant_profiles
    from dlp_importer import discover_packs
    pid = discover_packs()[0]["id"]
    c = TestClient(srv.app)
    r = c.get(f"/api/pack-library/{pid}/terraform.zip", params={"assessor": "Jane Doe"})
    assert r.status_code == 200
    text = _zip_text(r.content)
    assert f"[Jane Doe " in text and "[DLP-Check " not in text
    monkeypatch.setattr(tenant_profiles, "get", lambda p, **kw: {"assessor": "Sam Lee"} if p == "p1" else None)
    assert "[Sam Lee " in _zip_text(c.get(f"/api/pack-library/{pid}/terraform.zip", params={"profile_id": "p1"}).content)
    assert "[DLP-Check " in _zip_text(c.get(f"/api/pack-library/{pid}/terraform.zip").content)


def test_the_advanced_page_sends_the_assessor_with_its_terraform_downloads():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "advanced.js"), encoding="utf-8").read()
    html = open(os.path.join(root, "static", "report_advanced.html"), encoding="utf-8").read()
    assert 'id="advAssessor"' in html and 'for="advAssessor"' in html
    assert "searchParams.set('assessor'" in js and 'a[href*="/terraform.zip"]' in js
    body = js[js.index("async function advTerraform"):]
    assert "assessor: advAssessorName()" in body


# --- server wiring --------------------------------------------------------------

def _legacy_body(**kw):
    return dict(LEGACY, **kw)


def test_the_single_pack_import_tags_and_records_the_assessor(monkeypatch, tmp_path):
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv, "_resolve_pack_ids", lambda ids: [{"id": "alpha"}])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    seen = {}

    def fake_apply(client, packs, **kw):
        seen.update(kw)
        return {"status": "applied", "results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}], "summary": {"created": 1}}
    monkeypatch.setattr(pd, "apply", fake_apply)
    r = TestClient(srv.app).post("/api/dlp-packs/alpha/import", json=_legacy_body(plan_hash="h", assessor=" Jane ]Doe "))
    assert r.status_code == 200, r.text
    rec = deployments._read()["deployments"][-1]
    assert seen["assessor"] == rec["by"] == "Jane Doe"
    assert rec["tenant_label"] == "classic API (zscalerten)" and rec.get("tenant_key")
    assert "acme" not in str(rec) and "admin@" not in str(rec)


def test_undo_and_removal_accept_old_label_records_and_refuse_another_classic_tenant(monkeypatch, tmp_path):
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(pd, "undo", lambda client, rec, **kw: {"status": "undone", "complete": True, "results": []})
    created = {"results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}]}
    old = deployments.add(deployments.from_apply(created, tenant_label="acme-stale (zscalerten)", packs=["alpha"], options={}))
    theirs = deployments.add(deployments.from_apply(created, tenant_label="classic API (zscalerten)", packs=["alpha"], options={},
                                                    tenant_key=srv._tenant_key(tenant_auth.normalize(OTHER_LEGACY))))
    mine = deployments.add(deployments.from_apply(created, tenant_label="classic API (zscalerten)", packs=["alpha"], options={},
                                                  tenant_key=srv._tenant_key(tenant_auth.normalize(LEGACY))))
    c = TestClient(srv.app)
    assert c.post(f"/api/deployments/{old['id']}/undo", json=_legacy_body(confirm=True)).status_code == 200
    assert c.post(f"/api/deployments/{mine['id']}/undo", json=_legacy_body(confirm=True)).status_code == 200
    r = c.post(f"/api/deployments/{theirs['id']}/undo", json=_legacy_body(confirm=True))
    assert r.status_code == 409 and "Switch tenant" in r.json()["detail"]
    creds = tenant_auth.normalize(LEGACY)
    assert srv._deployment_for_removal(srv.PackRemovalRequest(deployment_id=old["id"]), creds)["id"] == old["id"]
    with pytest.raises(srv.HTTPException) as ex:
        srv._deployment_for_removal(srv.PackRemovalRequest(deployment_id=theirs["id"]), creds)
    assert ex.value.status_code == 409


def test_every_pack_screen_names_a_classic_api_tenant_without_vanity_or_login(monkeypatch):
    import dlp_api_server as srv
    import zia_rate
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv, "_resolve_pack_ids", lambda ids: [{"id": "alpha"}])
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [{"id": "alpha"}])
    monkeypatch.setattr(pd, "preflight", lambda *a, **kw: {})
    monkeypatch.setattr(pd, "public_report", lambda rep: {"items": []})
    monkeypatch.setattr(pr, "plan_removal", lambda *a, **kw: {"items": []})
    monkeypatch.setattr(pr, "inventory", lambda client: {"rules": []})
    monkeypatch.setattr(srv, "_journey_for", lambda *a, **kw: {"status": "ok"})
    seen = {}

    def fake_forecast(counts, **kw):
        seen.update(kw)
        return {"verdict": "ok"}
    monkeypatch.setattr(zia_rate, "forecast", fake_forecast)
    monkeypatch.setattr(zia_rate, "history_text", lambda f: "")
    c = TestClient(srv.app)
    for path, body in (("/api/dlp-packs/preflight", {"pack_ids": ["alpha"]}),
                       ("/api/dlp-packs/removal/preflight", {"pack_ids": ["alpha"]}),
                       ("/api/dlp-packs/removal/inventory", {}),
                       ("/api/dlp-packs/journey", {"pack_ids": ["alpha"]})):
        r = c.post(path, json=_legacy_body(**body))
        assert r.status_code == 200, (path, r.text)
        assert r.json()["tenant_label"] == "classic API (zscalerten)", path
    assert c.post("/api/rate-check", json=_legacy_body(counts={"write": 2})).status_code == 200
    assert tuple(seen["tenant_label"])[0] == "classic API (zscalerten)"
    assert seen["key"] == srv._tenant_key(tenant_auth.normalize(LEGACY))


def test_the_assessment_journey_names_a_classic_api_tenant_without_vanity_or_login(monkeypatch):
    import json
    import dlp_api_server as srv
    from dlp_assessment_full_auto import R

    class Fake:
        def __init__(self, *a, **k):
            self.requests_made = 0

        def auth(self):
            return True
    monkeypatch.setattr(srv, "Client", Fake)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda cl: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [{"id": "p1", "dir": "x"}])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(srv, "_journey_for", lambda sdk, packs, progress=None, **kw: {"status": "in_progress"})
    events, kind = [], None
    with TestClient(srv.app).stream("POST", "/api/assess", json=_legacy_body(scopes=["dlp"])) as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("event: "):
                kind = line[7:]
            elif line.startswith("data: "):
                events.append((kind, json.loads(line[6:])))
    j = next(d for k, d in events if k == "journey")["journey"]
    assert j["tenant_label"] == "classic API (zscalerten)"
