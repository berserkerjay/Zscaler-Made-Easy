"""Export from tenant as a pack.

The tenant's DLP rules on every channel, with every engine they use and
every dictionary those engines use, come out as an ordinary policy pack
(pack.json + configs/dlp_*.json) that the pack library accepts and Deploy
Policy Packs can deploy into another tenant. The key proof is the round
trip: export from a fake tenant, load the zip with the pack library's own
loader, plan it into an EMPTY fake tenant, and find the same dictionaries,
engines and rules, predefined references resolved by name.
"""
from __future__ import annotations

import base64
import io
import json
import os
import time
import zipfile

import pytest

import pack_deploy as pd
import pack_export as pe
import pack_library as pl
from test_pack_channels import TENANTS, FakeCasbRules, FakeChannelRules, make_client
from test_pack_deploy import Obj, items_by

SECRET = "secret-secret-secret"


# ---------------------------------------------------------------------------
# The source tenant, an empty target, and a guard against writes
# ---------------------------------------------------------------------------

def _source():
    """Two custom dictionaries, a clone, two predefined dictionaries, two
    custom engines the rules use (and one they don't), a predefined engine
    and rules on all four DLP channels. Ids are the source tenant's own."""
    client = make_client(casb_tenants=TENANTS)
    z = client.zia
    z.dlp_dictionary.items = [
        # Predefined: the API answers with the code as the name.
        Obj(id=1, name="SSN", description="Social Security Numbers (US)", custom=False),
        Obj(id=2, name="CREDIT_CARD", description="Credit Cards", custom=False),
        Obj(id=1001, name="Project Codes", description="Internal project codes [DLP-Check pack fed v1]", custom=True,
            dictionary_type="PATTERNS_AND_PHRASES", custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            patterns=[Obj(action="PATTERN_COUNT_TYPE_UNIQUE", pattern=r"\bPRJ-\d{4}\b")], phrases=[], proximity=0),
        Obj(id=1002, name="Board Phrases", description="", custom=True, dictionary_type="PATTERNS_AND_PHRASES",
            custom_phrase_match_type="MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE",
            patterns=[{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": r"\bBRD\d{3}\b"}],
            phrases=[{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "board only"}], proximity=40),
        Obj(id=1003, name="SSN Clone High", description="SSNs near the word ssn", custom=True, predefined_clone=True,
            dict_template_id=1, custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            confidence_threshold="CONFIDENCE_LEVEL_HIGH", phrases=[{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "ssn"}], proximity=500),
    ]
    z.dlp_engine.items = [
        Obj(id=5001, name="Project Leak", description="Project codes with SSNs", custom_dlp_engine=True,
            engine_expression="((D1001.S > 0) AND (D1.S > 2))"),
        Obj(id=5002, name="Board Leak", description="", custom_dlp_engine=True,
            engine_expression="((D1002.S > 1) OR (D1003.S > 0) OR (D2.S > 5))"),
        Obj(id=61, name="PCI", predefined_engine_name="PCI", custom_dlp_engine=False),
        Obj(id=5009, name="Unused Engine", custom_dlp_engine=True, engine_expression="((D1002.S > 0))"),
    ]
    z.dlp_web_rules.items = [
        # Listed out of order on purpose: the export keeps the tenant's order.
        Obj(id=12, name="Web-PCI", order=2, rank=7, action="ALLOW", state="DISABLED", protocols=["ANY_RULE"],
            dlp_engines=[Obj(id=61, name="PCI")]),
        Obj(id=11, name="Web-Projects", order=1, rank=7, action="BLOCK", state="ENABLED", protocols=["HTTPS_RULE", "HTTP_RULE"],
            severity="RULE_SEVERITY_HIGH", description="Blocks project leaks", dlp_engines=[Obj(id=5001, name="Project Leak")],
            file_types=["FTCATEGORY_MS_WORD"]),
    ]
    z.endpoint_dlp_rules = FakeChannelRules([
        Obj(id=21, name="EP-Board", order=1, rank=7, action="ALLOW", state="ENABLED", severity="RULE_SEVERITY_MEDIUM",
            dlp_engines=[Obj(id=5002, name="Board Leak")], data_transfer_method="REMOVABLE_DRIVE_TRANSFER"),
    ], start=8000)
    z.casb_dlp_rules = FakeCasbRules([
        Obj(id=31, name="SaaS-Projects", order=1, rank=7, type="OFLCASB_DLP_FILE", action="OFLCASB_DLP_REPORT_INCIDENT",
            state="ENABLED", dlp_engines=[Obj(id=5001, name="Project Leak")], cloud_app_tenants=[Obj(id=501, name="Acme Box")]),
    ], start=8500)
    z.outbound_email_dlp_rules = FakeChannelRules([
        Obj(id=41, name="Email-Board", order=1, action="ALLOW", state="DISABLED", dlp_engines=[Obj(id=5002, name="Board Leak")],
            email_tenants=[Obj(id=503, name="Acme M365 Mail")]),
    ], start=8800)
    return client


def _empty_target():
    """Another tenant: nothing custom, only what every tenant has (the
    predefined dictionaries, under their portal names and other ids, and
    the predefined engines) plus its onboarded SaaS tenants."""
    client = make_client(casb_tenants=TENANTS)
    client.zia.dlp_dictionary.items = [
        Obj(id=91, name="Social Security Numbers (US)", custom=False),
        Obj(id=92, name="Credit Cards", custom=False),
    ]
    client.zia.dlp_engine.items = [Obj(id=97, name="PCI", predefined_engine_name="PCI", custom_dlp_engine=False)]
    return client


_WRITE_PREFIXES = ("add", "update", "delete", "create", "remove", "activate", "reorder", "bulk")


class _Guard:
    """A read-only view of a fake service: any write call is recorded and fails."""
    def __init__(self, target, writes):
        self._t, self._w = target, writes

    def __getattr__(self, name):
        v = getattr(self._t, name)
        if callable(v) and name.startswith(_WRITE_PREFIXES):
            def refuse(*a, **k):
                self._w.append(name)
                raise AssertionError(f"the export wrote to the tenant: {name}")
            return refuse
        if not callable(v) and hasattr(v, "__dict__") and not isinstance(v, (list, dict, str, int)):
            return _Guard(v, self._w)
        return v


class ReadOnly:
    def __init__(self, client):
        self.writes = []
        self.zia = _Guard(client.zia, self.writes)


def _export(client=None, **kw):
    res = pe.export_pack(client or _source(), tenant_label="acme (zscalerten)", **kw)
    assert res["status"] == "ready", res
    return res["pack"]


def _upload(zip_bytes, name="export.zip"):
    return [{"name": name, "content": base64.b64encode(zip_bytes).decode(), "encoding": "base64"}]


def _zip_text(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    return {n: z.read(n).decode("utf-8") for n in z.namelist()}


# ---------------------------------------------------------------------------
# The round trip
# ---------------------------------------------------------------------------

def test_round_trip_export_then_plan_into_an_empty_tenant_recreates_the_same_objects(tmp_path):
    pack = _export()
    fname, data = pe.zip_pack(pack)
    folder = fname[:-4]
    assert set(_zip_text(data)) == {f"{folder}/pack.json", f"{folder}/configs/dlp_dictionaries.json",
                                    f"{folder}/configs/dlp_engines.json", f"{folder}/configs/dlp_policies.json"}

    # The pack library's own loader takes the zip as an upload and saves it.
    loaded = pl.assemble_pack(_upload(data))
    v = pl.validate_pack(loaded)
    assert v["ok"], v["problems"]
    assert v["channels"] == ["email", "endpoint", "saas", "web"]
    saved = pl.save_pack(loaded, root=str(tmp_path))
    packs = [{"id": saved["id"], "dir": saved["dir"]}]

    target = _empty_target()
    rep = pd.preflight(target, packs, writes_enabled=True)
    assert rep["status"] in ("ready", "warnings"), rep.get("blockers")

    # Dictionaries: the custom ones and the clone are created; predefined ones are not in the pack.
    dicts = items_by(rep, "dictionary")
    assert {n: d["status"] for n, d in dicts.items()} == {"Project Codes": pd.CREATE, "Board Phrases": pd.CREATE, "SSN Clone High": pd.CREATE}
    assert dicts["SSN Clone High"]["detail"]["type"] == "clone"
    assert dicts["Board Phrases"]["detail"] == {"type": "custom", "patterns": 1, "phrases": 1, "proximity": 40}
    # The clone's template "SSN" is found by name in a tenant that shows it as "Social Security Numbers (US)".
    assert not any(dep.startswith("predefined:") for d in dicts.values() for dep in d["depends_on"])

    # Engines: only the ones the rules use; expressions name the dictionaries.
    engines = items_by(rep, "engine")
    assert {n: e["status"] for n, e in engines.items()} == {"Project Leak": pd.CREATE, "Board Leak": pd.CREATE}
    assert engines["Project Leak"]["detail"]["expression"] == "((D:Project Codes > 0) AND (D:SSN > 2))"
    assert engines["Board Leak"]["detail"]["expression"] == "((D:Board Phrases > 1) OR (D:SSN Clone High > 0) OR (D:CREDIT_CARD > 5))"

    # Rules: every channel, in the tenant's order, same engines; a blocking action is kept as the target.
    pols = items_by(rep, "policy")
    assert {n: p["status"] for n, p in pols.items()} == {n: pd.CREATE for n in ("Web-Projects", "Web-PCI", "EP-Board", "SaaS-Projects", "Email-Board")}
    assert pols["Web-PCI"]["detail"]["engines"] == ["PCI"]
    assert pols["Web-Projects"]["detail"]["engines"] == ["Project Leak"] and pols["Web-Projects"]["detail"]["target_action"] == "BLOCK"
    assert pols["Web-Projects"]["detail"]["protocols"] == ["HTTPS_RULE", "HTTP_RULE"]
    assert pols["EP-Board"]["detail"]["channel"] == "endpoint" and pols["EP-Board"]["detail"]["engines"] == ["Board Leak"]
    assert pols["SaaS-Projects"]["detail"]["tenants"] == ["Acme Box"]
    assert pols["Email-Board"]["detail"]["tenants"] == ["Acme M365 Mail"]
    web_order = [i["name"] for i in rep["items"] if i["kind"] == "policy" and i["detail"]["channel"] == "web"]
    assert web_order == ["Web-Projects", "Web-PCI"]

    # Deploy it into the fake target and look at what was sent: the same
    # definitions, with the TARGET's ids for everything predefined.
    res = pd.apply(target, packs, plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied", res
    z = target.zia
    added = {d["name"]: d for d in z.dlp_dictionary.added}
    pairs = lambda items, key: [tuple(x) if isinstance(x, (list, tuple)) else (x["action"], x[key]) for x in items or []]  # noqa: E731
    assert pairs(added["Project Codes"]["patterns"], "pattern") == [("PATTERN_COUNT_TYPE_UNIQUE", r"\bPRJ-\d{4}\b")]
    assert added["Board Phrases"]["match"] == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE" and added["Board Phrases"]["proximity"] == 40
    assert pairs(added["Board Phrases"]["phrases"], "phrase") == [("PHRASE_COUNT_TYPE_ALL", "board only")]
    assert added["SSN Clone High"]["dict_template_id"] == 91, "the clone's template is the target's SSN, found by name"
    ids = {o.name: o.id for o in z.dlp_dictionary.items}
    exprs = {e["name"]: e["engine_expression"] for e in z.dlp_engine.added}
    assert exprs == {"Project Leak": f"((D{ids['Project Codes']}.S > 0) AND (D91.S > 2))",
                     "Board Leak": f"((D{ids['Board Phrases']}.S > 1) OR (D{ids['SSN Clone High']}.S > 0) OR (D92.S > 5))"}
    web = {r["name"]: r for r in z.dlp_web_rules.added}
    assert set(web) == {"Web-Projects", "Web-PCI"}
    assert web["Web-PCI"]["dlp_engines"] == [97], "the predefined engine is the target's own, found by name"
    assert [r["name"] for r in z.endpoint_dlp_rules.added] == ["EP-Board"]
    assert [r["name"] for r in z.casb_dlp_rules.added] == ["SaaS-Projects"]
    assert [r["name"] for r in z.outbound_email_dlp_rules.added] == ["Email-Board"]
    # Deploy Policy Packs creates every rule DISABLED, as the note in pack.json says.
    assert all(r["state"] == "DISABLED" for r in z.dlp_web_rules.added + z.endpoint_dlp_rules.added)


def test_the_pack_has_the_layout_and_field_shapes_the_built_in_packs_use():
    pack = _export()
    files = pe.pack_files(pack)
    meta = json.loads(files["pack.json"])
    dicts = {d["name"]: d for d in json.loads(files["configs/dlp_dictionaries.json"])}
    engines = {e["name"]: e for e in json.loads(files["configs/dlp_engines.json"])}
    pols = json.loads(files["configs/dlp_policies.json"])

    for k in ("name", "version", "description", "exported_from", "exported_at", "counts", "not_exported"):
        assert k in meta, k
    assert meta["exported_from"] == "acme (zscalerten)"
    assert meta["counts"]["rules"] == 5 and meta["counts"]["engines"] == 2 and meta["counts"]["dictionaries"] == 3 and meta["counts"]["clones"] == 1
    assert "DISABLED" in meta["deploy_note"]
    assert meta["predefined_dictionaries"] == ["CREDIT_CARD", "SSN"] and meta["predefined_engines"] == ["PCI"]
    assert meta["rule_order"]["web"] == ["Web-Projects", "Web-PCI"]

    # Custom dictionaries in full; the provenance tag an earlier deploy added is gone from the description.
    assert dicts["Project Codes"] == {"name": "Project Codes", "description": "Internal project codes",
                                      "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                                      "patterns": [{"action": "PATTERN_COUNT_TYPE_UNIQUE", "pattern": r"\bPRJ-\d{4}\b"}]}
    assert dicts["Board Phrases"]["proximity"] == 40
    assert dicts["Board Phrases"]["phrases"] == [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "board only"}]
    # The clone as a clone, its template by name (the fed pack's shape), never by id.
    clone = dicts["SSN Clone High"]
    assert clone["predefined_clone"] is True and clone["dict_template_name"] == "SSN" and "dict_template_id" not in clone
    assert clone["confidence_threshold"] == "CONFIDENCE_LEVEL_HIGH" and clone["proximity"] == 500
    # Predefined dictionaries and engines are named, never copied; unused engines stay out.
    assert not {"SSN", "CREDIT_CARD"} & set(dicts) and "PCI" not in engines and "Unused Engine" not in engines
    assert engines["Project Leak"] == {"name": "Project Leak", "description": "Project codes with SSNs",
                                       "expression": "((D:Project Codes > 0) AND (D:SSN > 2))"}

    # Rules keep their order, action and state; channel fields as the built-in packs write them.
    by = {p["name"]: p for p in pols}
    assert [p["name"] for p in pols] == ["Web-Projects", "Web-PCI", "EP-Board", "SaaS-Projects", "Email-Board"]
    assert by["Web-Projects"]["action"] == "BLOCK" and by["Web-Projects"]["state"] == "ENABLED"
    assert by["Web-PCI"]["state"] == "DISABLED" and by["Web-PCI"]["engines"] == ["PCI"]
    assert by["Web-Projects"]["protocols"] == ["HTTPS_RULE", "HTTP_RULE"] and by["Web-Projects"]["file_types"] == ["FTCATEGORY_MS_WORD"]
    assert by["EP-Board"]["channel"] == "endpoint" and by["EP-Board"]["data_transfer_method"] == "REMOVABLE_DRIVE_TRANSFER"
    assert by["SaaS-Projects"]["saas_type"] == "OFLCASB_DLP_FILE" and by["SaaS-Projects"]["tenants"] == ["Acme Box"]
    assert by["Email-Board"]["channel"] == "email" and by["Email-Board"]["tenants"] == ["Acme M365 Mail"] and "rank" not in by["Email-Board"]


def test_labels_and_notification_templates_travel_by_name_and_land_on_the_targets_ids(tmp_path):
    from test_pack_channels import FakeNamed
    client = _source()
    for r in client.zia.dlp_web_rules.items + client.zia.endpoint_dlp_rules.items:
        r.labels = [Obj(id=5, name="Compliance")]
        r.notification_template = Obj(id=3, name="DLP Notice")
    pack = _export(client)
    by = {p["name"]: p for p in pack["policies"]}
    assert by["Web-Projects"]["labels"] == ["Compliance"] and by["Web-Projects"]["notification_template"] == "DLP Notice"
    saved = pl.save_pack(pl.assemble_pack(_upload(pe.zip_pack(pack)[1])), root=str(tmp_path))
    packs = [{"id": saved["id"], "dir": saved["dir"]}]
    target = _empty_target()
    target.zia.dlp_templates = FakeNamed([Obj(id=77, name="DLP Notice")])
    target.zia.rule_labels = FakeNamed([Obj(id=9, name="Compliance")])
    rep = pd.preflight(target, packs, writes_enabled=True)
    assert "resource:Label: Compliance" in items_by(rep, "policy")["Web-Projects"]["depends_on"]
    res = pd.apply(target, packs, plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied", res
    web = next(r for r in target.zia.dlp_web_rules.added if r["name"] == "Web-Projects")
    assert web["labels"] == [9] and web["notification_template"] == {"id": 77}, "the target's ids, never the pack's names"
    ep = target.zia.endpoint_dlp_rules.added[0]
    assert ep["labels"] == [{"id": 9}] and ep["notification_template"] == {"id": 77}


def test_a_selection_exports_only_those_rules_and_what_they_use():
    pack = _export(selection={"web": [12], "email": "all"})
    assert [p["name"] for p in pack["policies"]] == ["Web-PCI", "Email-Board"]
    assert [e["name"] for e in pack["engines"]] == ["Board Leak"]
    assert sorted(d["name"] for d in pack["dictionaries"]) == ["Board Phrases", "SSN Clone High"]
    with pytest.raises(ValueError):
        pe.normalize_selection({"ftp": "all"})


# ---------------------------------------------------------------------------
# Read-only, nothing silent, no secrets
# ---------------------------------------------------------------------------

def test_the_export_only_reads():
    ro = ReadOnly(_source())
    pack = _export(ro)
    assert ro.writes == [] and pack["meta"]["counts"]["rules"] == 5


def test_references_a_pack_cannot_carry_are_listed_in_pack_json():
    client = _source()
    r = next(x for x in client.zia.dlp_web_rules.items if x.name == "Web-Projects")
    r.locations = [Obj(id=301, name="HQ")]
    r.groups = [Obj(id=302, name="Finance")]
    r.url_categories = ["CUSTOM_07", "OTHER_MISCELLANEOUS"]
    r.icap_server = Obj(id=9, name="ICAP-1")
    r.external_auditor_email = "auditor@example.com"
    r.dlp_engines = r.dlp_engines + [Obj(id=6666, name="Gone Engine")]
    pack = _export(client)
    meta = pack["meta"]
    left = {(d["name"], d.get("field")): d for d in meta["not_exported"]}
    assert left[("Web-Projects", "locations")]["values"] == ["HQ"]
    assert "ids differ between tenants" in left[("Web-Projects", "groups")]["reason"]
    assert left[("Web-Projects", "url_categories")]["values"] == ["CUSTOM_07"]
    assert ("Web-Projects", "icap_server") in left and ("Web-Projects", "external_auditor_email") in left
    assert ("Gone Engine", None) in left and ("Web-Projects", "dlp_engines") in left
    assert all(d["reason"] for d in meta["not_exported"])
    assert meta["counts"]["not_exported"] == len(meta["not_exported"])
    rule = next(p for p in pack["policies"] if p["name"] == "Web-Projects")
    assert rule["url_categories"] == ["OTHER_MISCELLANEOUS"] and rule["engines"] == ["Project Leak"]
    assert not {"locations", "groups", "icap_server", "external_auditor_email"} & set(rule)
    assert "auditor@example.com" not in json.dumps(pe.pack_files(pack)), "a person's address is named, never copied"


def test_a_channel_that_cannot_be_read_is_listed_not_silently_empty():
    client = _source()
    client.zia.endpoint_dlp_rules.fail = True
    pack = _export(client)
    assert "EP-Board" not in {p["name"] for p in pack["policies"]}
    assert any(d.get("channel") == "endpoint" and "could not be read" in d["reason"] for d in pack["meta"]["not_exported"])


# ---------------------------------------------------------------------------
# The job, the download and the UI
# ---------------------------------------------------------------------------

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


def test_the_export_runs_as_a_read_only_job_and_the_zip_comes_from_its_download(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    import audit
    import dlp_api_server as srv
    from fastapi.testclient import TestClient

    def no_writer(*a, **k):
        raise AssertionError("the export asked for the writer check")

    ro = ReadOnly(_source())
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ro)
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)     # read-only: works with write mode off
    monkeypatch.setattr(srv._security, "require_writer", no_writer)
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
    r = c.post("/api/dlp-packs/export/start", json=dict(creds, pack_name="Acme export"))
    assert r.status_code == 200 and r.json()["kind"] == "export", r.text
    job_id = r.json()["job_id"]
    snap = _wait(c, job_id)
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    assert any(l.startswith("Reading the tenant: DLP dictionaries") for l in snap["logs"])
    assert any("Nothing is written to the tenant" in l for l in snap["logs"])
    assert "artifact" not in snap["result"] and snap["result"]["counts"]["rules"] == 5
    assert snap["download"] == f"/api/dlp-packs/jobs/{job_id}/download" and snap["filename"].endswith(".zip")
    z = c.get(snap["download"])
    assert z.status_code == 200 and z.headers["content-type"].startswith("application/zip")
    assert ro.writes == []

    # No secret anywhere: the zip, the job's JSON, the audit log.
    files = _zip_text(z.content)
    blob = "\n".join(files.values())
    assert SECRET not in blob and "abc123456789" not in blob
    assert SECRET not in json.dumps(snap)
    meta = json.loads(next(t for n, t in files.items() if n.endswith("pack.json")))
    assert meta["name"] == "Acme export" and meta["exported_from"] == "acme (production)"
    fin = [e for e in audit.tail(1000) if e.get("event") == "job_finished" and e.get("job_id") == job_id]
    assert len(fin) == 1 and fin[0]["kind"] == "export" and fin[0]["status"] == "done" and fin[0]["tenant"] == "acme (production)"
    assert SECRET not in open(audit.path(), encoding="utf-8").read()

    # The pack library's upload accepts the downloaded zip as it is, and lists it as a pack.
    monkeypatch.setattr(srv, "PACKS_ROOT", str(tmp_path))
    monkeypatch.setattr("dlp_importer.PACKS_ROOT", str(tmp_path))
    monkeypatch.delenv("DLP_CHECK_USER_PACKS", raising=False)
    preview = c.post("/api/pack-library/preview", json={"files": _upload(z.content, snap["filename"])}).json()
    assert preview["ok"], preview["problems"]
    up = c.post("/api/pack-library/upload", json={"files": _upload(z.content, snap["filename"])})
    assert up.status_code == 200 and up.json()["pack"]["name"] == "Acme export", up.text
    assert sorted(up.json()["pack"]["channels"]) == ["email", "endpoint", "saas", "web"]

    # A selection naming an unknown channel is refused before any job starts.
    assert c.post("/api/dlp-packs/export/start", json=dict(creds, rules={"ftp": "all"})).status_code == 400


def test_both_ui_entry_points_start_the_export_job():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    index = open(os.path.join(root, "static", "index.html"), encoding="utf-8").read()
    studio = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    # Evaluate All Rules, Step 2: the JSON download stays, the pack download sits beside it.
    assert 'onclick="step2Download()"' in index and "Download as a pack (rules, engines and dictionaries)" in index
    assert "async function step2DownloadPack()" in index and "'/api/dlp-packs/export/start'" in index
    # Deploy policy packs: the export action with its rule picker.
    assert "Export from tenant as a pack" in studio and 'onclick="_dzExportPick()"' in studio
    assert "'/api/dlp-packs/export/start'" in studio
