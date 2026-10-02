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

# The Scope page with DLP ticked and every DLP channel on Zscaler (export reads only what is in scope).
ALL_DLP_IN_SCOPE = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "saas_casb": "zscaler", "email_dlp": "zscaler"}, "from_page": True}

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
    r = c.post("/api/dlp-packs/export/start", json=dict(creds, pack_name="Acme export", **ALL_DLP_IN_SCOPE))
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


# ---------------------------------------------------------------------------
# Refused reads, rate limits and Stop
# ---------------------------------------------------------------------------

def _refuse(svc, method, text):
    setattr(svc, method, lambda *a, **k: (None, None, Exception(text)))


def test_a_refused_dictionary_or_engine_read_fails_the_export_instead_of_an_empty_ready_pack():
    for svc, method, path in (("dlp_dictionary", "list_dicts", "dlpDictionaries"), ("dlp_engine", "list_dlp_engines", "dlpEngines")):
        client = _source()
        _refuse(getattr(client.zia, svc), method, '{"status": 403, "code": null, "message": "Resource Access Blocked", "url": "https://api.zsapi.net/zia/api/v1/%s"}' % path)
        res = pe.export_pack(client, tenant_label="acme")
        assert res["status"] == "error", (svc, res["status"])
        assert "resource access blocked" in res["error"].lower()
        assert "pack" not in res


def test_a_dictionary_list_that_could_not_be_read_is_not_reported_as_missing_dictionaries():
    snap = pe.read_tenant(_source())
    snap["dictionaries"], snap["errors"]["dictionaries"] = [], "HTTP 500"
    pack = pe.build_pack(snap)
    reasons = [d["reason"] for d in pack["not_exported"] if d["kind"] == "engine"]
    assert reasons and all("could not be read" in r and "does not have" not in r for r in reasons), reasons


def _refuse_n(svc, method, text, times):
    real, left, calls = getattr(svc, method), [times], []

    def fn(*a, **k):
        calls.append(1)
        if left[0] > 0:
            left[0] -= 1
            return None, None, Exception(text)
        return real(*a, **k)
    setattr(svc, method, fn)
    return calls


TOO_MANY = '{"status": 429, "code": null, "message": "Too Many Requests"}'
BLOCKED = '{"status": 403, "code": null, "message": "Resource Access Blocked"}'


def test_a_rate_refused_rule_read_is_waited_out_and_retried(monkeypatch):
    import zia_rate
    monkeypatch.setattr(zia_rate, "hold", lambda s, key=None, **kw: 0.0)
    monkeypatch.setattr(pe, "_sleep", lambda s: None, raising=False)
    client = _source()
    _refuse_n(client.zia.dlp_web_rules, "list_rules", TOO_MANY, times=1)
    logs = []
    res = pe.export_pack(client, tenant_label="acme", log=logs.append)
    assert res["status"] == "ready"
    assert {"Web-Projects", "Web-PCI"} <= {p["name"] for p in res["pack"]["policies"]}
    assert any("rate" in l.lower() for l in logs)


def test_a_persistent_resource_access_blocked_fails_the_export_and_stops_reading(monkeypatch):
    import zia_rate
    monkeypatch.setattr(zia_rate, "hold", lambda s, key=None, **kw: 0.0)
    monkeypatch.setattr(pe, "_sleep", lambda s: None, raising=False)
    client = _source()
    _refuse_n(client.zia.dlp_web_rules, "list_rules", BLOCKED, times=99)
    later = _refuse_n(client.zia.endpoint_dlp_rules, "list_rules", "unused", times=0)
    res = pe.export_pack(client, tenant_label="acme")
    assert res["status"] == "error" and "resource access blocked" in res["error"].lower()
    assert later == [], "kept sending reads to a client ZIA had just blocked"


def test_stop_during_the_reads_sends_no_more_reads():
    import threading
    calls = []
    cancel = threading.Event()
    src = _source()

    class Proxy:
        def __init__(self, t):
            self._t = t

        def __getattr__(self, name):
            v = getattr(self._t, name)
            if callable(v) and name.startswith('list'):
                def call(*a, **k):
                    calls.append(name)
                    cancel.set()          # Stop arrives during the first read
                    return v(*a, **k)
                return call
            if not callable(v) and hasattr(v, '__dict__') and not isinstance(v, (list, dict, str, int)):
                return Proxy(v)
            return v

    class C:
        pass
    c = C()
    c.zia = Proxy(src.zia)
    res = pe.export_pack(c, tenant_label='acme', cancel=cancel)
    assert res['status'] == 'stopped'
    assert calls == ['list_dicts'], calls


def test_stop_on_an_export_job_speaks_of_reads():
    import threading
    import pack_jobs
    gate = threading.Event()

    def fn(log, cancel):
        gate.wait(5)
        return {'status': 'stopped', 'stopped': 'You clicked Stop.'}
    job = pack_jobs.start('export', fn, label='t')
    assert pack_jobs.cancel(job.id)
    gate.set()
    for _ in range(200):
        if job.status != pack_jobs.RUNNING:
            break
        time.sleep(0.01)
    line = [l for l in job.logs if l.startswith('Stop requested')][0]
    assert 'activation' not in line and 'write' not in line, line
    assert job.status == pack_jobs.CANCELLED


# ---------------------------------------------------------------------------
# Names: renames, clashes and names ZIA accepts
# ---------------------------------------------------------------------------

def test_a_cross_channel_rename_never_collides_with_another_rule_name():
    client = make_client(casb_tenants=TENANTS)
    client.zia.dlp_dictionary.items = [Obj(id=1001, name="A", description="", custom=True, dictionary_type="PATTERNS_AND_PHRASES",
        custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", phrases=[{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "aaa aaa"}], patterns=[], proximity=0)]
    client.zia.dlp_engine.items = [Obj(id=5000, name="E", description="", custom_dlp_engine=True, engine_expression="((D1001.S > 0))")]
    client.zia.dlp_web_rules.items = [Obj(id=11, name="Block", order=1, rank=7, action="ALLOW", state="ENABLED", protocols=["ANY_RULE"], dlp_engines=[Obj(id=5000, name="E")])]
    ep = lambda i, n, o: Obj(id=i, name=n, order=o, rank=7, action="ALLOW", state="ENABLED", dlp_engines=[Obj(id=5000, name="E")], data_transfer_method="REMOVABLE_DRIVE_TRANSFER")  # noqa: E731
    client.zia.endpoint_dlp_rules = FakeChannelRules([ep(21, "Block [Endpoint]", 1), ep(22, "Block", 2)], start=8000)
    res = pe.export_pack(client, tenant_label="src")
    names = [p["name"] for p in res["pack"]["policies"]]
    assert len(names) == 3 and len(set(names)) == 3, names
    assert res["validation"]["ok"], res["validation"]["problems"]
    assert pl.validate_pack(res["pack"])["ok"]
    assert [r["from"] for r in res["pack"]["meta"]["renamed_rules"]] == ["Block"]


def test_a_sub_rule_named_like_a_rule_on_another_channel_is_renamed():
    import pack_channels as pc
    client = _source()
    client.zia.endpoint_dlp_rules.items[0].sub_rules = [
        Obj(id=22, name="Web-PCI", order=1, action="ALLOW", state="ENABLED", dlp_engines=[Obj(id=5002, name="Board Leak")])]
    res = pe.export_pack(client, tenant_label="t")
    names = [p["name"] for p in pc.expand_sub_rules(res["pack"]["policies"])]
    assert len(names) == len(set(names)), names
    assert res["validation"]["ok"], res["validation"]["problems"]
    assert any(r["from"] == "Web-PCI" for r in res["pack"]["meta"].get("renamed_rules", []))


def test_endpoint_sub_rules_keep_the_tenants_order():
    client = _source()
    eng = [Obj(id=5002, name="Board Leak")]
    client.zia.endpoint_dlp_rules.items[0].sub_rules = [
        Obj(id=23, name="EP-exc-second", order=2, action="ALLOW", state="ENABLED", dlp_engines=eng),
        Obj(id=22, name="EP-exc-first", order=1, action="BLOCK", state="DISABLED", dlp_engines=eng)]
    pack = pe.export_pack(client, tenant_label="t")["pack"]
    ep = next(p for p in pack["policies"] if p["name"] == "EP-Board")
    assert [s["name"] for s in ep["sub_rules"]] == ["EP-exc-first", "EP-exc-second"]


def _cd(i, name, phrase):
    return Obj(id=i, name=name, description="", custom=True, dictionary_type="PATTERNS_AND_PHRASES",
               custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
               phrases=[{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": phrase}], patterns=[], proximity=0)


def _one_rule_client(dicts, expr):
    c = make_client(casb_tenants=TENANTS)
    c.zia.dlp_dictionary.items = [Obj(id=1, name="SSN", custom=False)] + dicts
    c.zia.dlp_engine.items = [Obj(id=5000, name="E", description="", custom_dlp_engine=True, engine_expression=expr)]
    c.zia.dlp_web_rules.items = [Obj(id=11, name="R", order=1, rank=7, action="ALLOW", state="ENABLED", protocols=["ANY_RULE"], dlp_engines=[Obj(id=5000, name="E")])]
    return c


def test_two_source_dictionaries_that_map_to_one_pack_name_are_not_silently_merged():
    pack = pe.export_pack(_one_rule_client([_cd(1001, "Codes", "one phrase"), _cd(1002, "Codes ", "two phrase")],
                                           "((D1001.S > 0) AND (D1002.S > 0))"), tenant_label="src")["pack"]
    phrases = sorted(ph["phrase"] for d in pack["dictionaries"] for ph in d.get("phrases", []))
    assert phrases == ["one phrase", "two phrase"] or pack["meta"]["not_exported"] or pack["warnings"], (phrases, pack["engines"])


def test_a_custom_dictionary_named_like_a_predefined_one_does_not_hide_the_predefined_term():
    pack = pe.export_pack(_one_rule_client([_cd(1001, "SSN", "my ssn phrase")], "((D1001.S > 0) AND (D1.S > 0))"), tenant_label="src")["pack"]
    expr = pack["engines"][0]["expression"] if pack["engines"] else ""
    assert not (expr.count("D:SSN ") == 2 and not pack["meta"]["not_exported"] and not pack["warnings"]), expr


def _plan_and_apply(pack, tmp_path, target=None):
    saved = pl.save_pack(pl.assemble_pack(_upload(pe.zip_pack(pack)[1])), root=str(tmp_path))
    packs = [{"id": saved["id"], "dir": saved["dir"]}]
    target = target or _empty_target()
    rep = pd.preflight(target, packs, writes_enabled=True)
    assert rep["status"] in ("ready", "warnings"), rep.get("blockers")
    res = pd.apply(target, packs, plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied", res
    return target.zia


def test_renamed_dictionaries_plan_into_an_empty_tenant_as_two_distinct_dictionaries(tmp_path):
    res = pe.export_pack(_one_rule_client([_cd(1001, "Codes", "one phrase"), _cd(1002, "Codes ", "two phrase")],
                                          "((D1001.S > 0) AND (D1002.S > 0))"), tenant_label="src")
    assert res["validation"]["ok"], res["validation"]["problems"]
    renamed = res["pack"]["meta"]["renamed_dictionaries"]
    assert [(r["from"], r["to"]) for r in renamed] == [("Codes ", "Codes (2)")]
    z = _plan_and_apply(res["pack"], tmp_path)
    ids = {o.name: o.id for o in z.dlp_dictionary.items}
    assert z.dlp_engine.added[0]["engine_expression"] == f"((D{ids['Codes']}.S > 0) AND (D{ids['Codes (2)']}.S > 0))"

    res = pe.export_pack(_one_rule_client([_cd(1001, "SSN", "my ssn phrase")], "((D1001.S > 0) AND (D1.S > 0))"), tenant_label="src")
    assert res["pack"]["engines"][0]["expression"] == "((D:SSN (custom) > 0) AND (D:SSN > 0))"
    z = _plan_and_apply(res["pack"], tmp_path / "second")
    ids = {o.name: o.id for o in z.dlp_dictionary.items}
    assert z.dlp_engine.added[0]["engine_expression"] == f"((D{ids['SSN (custom)']}.S > 0) AND (D91.S > 0))"


def test_a_custom_dictionary_or_engine_named_like_a_predefined_one_is_not_merged_with_it():
    c = make_client(casb_tenants=TENANTS)
    z = c.zia
    z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules = FakeChannelRules([]), FakeCasbRules([]), FakeChannelRules([])
    z.dlp_dictionary.items = [Obj(id=1, name="SSN", custom=False),
        Obj(id=300, name="SSN", custom=True, dictionary_type="PATTERNS_AND_PHRASES", patterns=[{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": r"\bX\d+\b"}], phrases=[])]
    eng = lambda i, n, x: Obj(id=i, name=n, custom_dlp_engine=True, engine_expression=x)  # noqa: E731
    z.dlp_engine.items = [eng(10, "Uses predefined SSN", "((D1.S > 0))"), eng(11, "Uses custom SSN", "((D300.S > 0))"),
        Obj(id=61, name="PCI", predefined_engine_name="PCI", custom_dlp_engine=False), eng(12, "PCI", "((D300.S > 1))")]
    rule = lambda i, n, e: Obj(id=i, name=n, order=i, rank=7, action="ALLOW", state="ENABLED", protocols=["ANY_RULE"], dlp_engines=[Obj(id=e, name="x")])  # noqa: E731
    z.dlp_web_rules.items = [rule(1, "R1", 10), rule(2, "R2", 11), rule(3, "R3", 61), rule(4, "R4", 12)]
    pack = pe.export_pack(c, tenant_label="t")["pack"]
    listed = {d["name"] for d in pack["not_exported"]}
    exprs = {e["name"]: e["expression"] for e in pack["engines"]}
    assert exprs.get("Uses predefined SSN") != exprs.get("Uses custom SSN") or listed & {"SSN", "Uses predefined SSN", "Uses custom SSN"}
    rules = {p["name"]: p.get("engines") for p in pack["policies"]}
    assert rules.get("R3") != rules.get("R4") or listed & {"PCI", "R3", "R4"}


def test_a_custom_dictionary_named_like_a_predefined_one_deploys_beside_the_targets_predefined_one(tmp_path):
    c = make_client(casb_tenants=TENANTS)
    z = c.zia
    z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules = FakeChannelRules([]), FakeCasbRules([]), FakeChannelRules([])
    z.dlp_dictionary.items = [Obj(id=1, name="SSN", custom=False), _cd(300, "SSN", "my ssn phrase")]
    eng = lambda i, n, x: Obj(id=i, name=n, custom_dlp_engine=True, engine_expression=x)  # noqa: E731
    z.dlp_engine.items = [eng(10, "Uses predefined SSN", "((D1.S > 0))"), eng(11, "Uses custom SSN", "((D300.S > 0))"),
                          Obj(id=61, name="PCI", predefined_engine_name="PCI", custom_dlp_engine=False), eng(12, "PCI", "((D300.S > 1))")]
    rule = lambda i, n, e: Obj(id=i, name=n, order=i, rank=7, action="ALLOW", state="ENABLED", protocols=["ANY_RULE"], dlp_engines=[Obj(id=e, name="x")])  # noqa: E731
    z.dlp_web_rules.items = [rule(1, "R1", 10), rule(2, "R2", 11), rule(3, "R3", 61), rule(4, "R4", 12)]
    res = pe.export_pack(c, tenant_label="t")
    meta = res["pack"]["meta"]
    assert [(r["from"], r["to"]) for r in meta["renamed_engines"]] == [("PCI", "PCI (custom)")]
    assert {p["name"]: p["engines"] for p in res["pack"]["policies"]}["R4"] == ["PCI (custom)"]
    t = _plan_and_apply(res["pack"], tmp_path)
    ids = {o.name: o.id for o in t.dlp_dictionary.items}
    exprs = {e["name"]: e["engine_expression"] for e in t.dlp_engine.added}
    assert exprs["Uses predefined SSN"] == "((D91.S > 0))", "the target's own predefined SSN, not the pack's custom one"
    assert exprs["Uses custom SSN"] == f"((D{ids['SSN (custom)']}.S > 0))"
    web = {r["name"]: r for r in t.dlp_web_rules.added}
    assert web["R3"]["dlp_engines"] == [97] and web["R4"]["dlp_engines"] != [97]


def test_dictionary_names_zia_accepts_do_not_make_the_exported_pack_invalid(tmp_path):
    mk = lambda i, n, ph: Obj(id=i, name=n, description="", custom=True, dictionary_type="PATTERNS_AND_PHRASES",  # noqa: E731
        custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", phrases=[{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": ph}], patterns=[], proximity=0)
    c = make_client(casb_tenants=TENANTS)
    c.zia.dlp_dictionary.items = [mk(1001, "Codes (legacy", "one phrase"), mk(1002, "Ref D7.S v2", "two phrase")]
    c.zia.dlp_engine.items = [Obj(id=5000, name="E", description="", custom_dlp_engine=True, engine_expression="((D1001.S > 0) OR (D1002.S > 0))")]
    c.zia.dlp_web_rules.items = [Obj(id=11, name="R", order=1, rank=7, action="ALLOW", state="ENABLED", protocols=["ANY_RULE"], dlp_engines=[Obj(id=5000, name="E")])]
    res = pe.export_pack(c, tenant_label="src")
    assert res["validation"]["ok"], res["validation"]["problems"]
    z = _plan_and_apply(res["pack"], tmp_path)
    ids = {o.name: o.id for o in z.dlp_dictionary.items}
    assert z.dlp_engine.added[0]["engine_expression"] == f"((D{ids['Codes (legacy']}.S > 0) OR (D{ids['Ref D7.S v2']}.S > 0))"


@pytest.mark.parametrize("name", ["名前", "Отчёт", "..."])
def test_a_pack_name_without_latin_letters_still_gives_a_pack_the_library_saves(tmp_path, name):
    res = pe.export_pack(_source(), name=name, tenant_label="acme (production)")
    assert res["status"] == "ready" and res["validation"]["ok"]
    fname, data = pe.zip_pack(res["pack"])
    saved = pl.save_pack(pl.assemble_pack(_upload(data, fname)), root=str(tmp_path))
    assert saved["id"]


# ---------------------------------------------------------------------------
# Broken references and nothing to export
# ---------------------------------------------------------------------------

def test_an_export_with_no_rules_is_not_offered_as_a_pack_the_library_then_refuses():
    def client_with(dicts, engines, web):
        c = make_client(casb_tenants=TENANTS)
        z = c.zia
        z.dlp_dictionary.items, z.dlp_engine.items, z.dlp_web_rules.items = dicts, engines, web
        z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules = FakeChannelRules([]), FakeCasbRules([]), FakeChannelRules([])
        return c
    gone = Obj(id=1, name="Only rule", order=1, rank=7, action="ALLOW", state="ENABLED", dlp_engines=[Obj(id=999, name="Deleted")])
    for client in (client_with([], [], []), client_with([Obj(id=1, name="SSN", custom=False)], [], [gone])):
        res = pe.export_pack(client, tenant_label="t")
        if res["status"] == "ready":
            pl.assemble_pack(_upload(pe.zip_pack(res["pack"])[1]))
        else:
            assert res.get("error"), res


@pytest.mark.parametrize("selection", [{"web": [99999]}, {"web": "Web-PCI"}, {"web": "some"}])
def test_a_selection_that_matches_no_rule_is_not_reported_as_a_ready_pack(selection):
    try:
        res = pe.export_pack(_source(), selection=selection, name="x", tenant_label="acme (production)")
    except ValueError:
        return  # refusing a malformed selection up front is fine
    assert res["status"] != "ready" or not res["validation"]["ok"], (res["status"], res["pack"]["meta"]["counts"])


def test_web_all_on_a_tenant_without_web_rules_is_not_a_ready_empty_pack():
    client = _source()
    client.zia.dlp_web_rules.items = []
    res = pe.export_pack(client, selection={"web": "all"}, name="Step 2", tenant_label="acme (production)")
    assert res["status"] != "ready" or not res["validation"]["ok"], res["pack"]["meta"]["counts"]


def test_a_clone_whose_template_is_missing_says_so_and_names_the_template_id():
    c = make_client(casb_tenants=TENANTS)
    z = c.zia
    z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules = FakeChannelRules([]), FakeCasbRules([]), FakeChannelRules([])
    z.dlp_dictionary.items = [Obj(id=1, name="SSN", custom=False),
        Obj(id=100, name="Orphan Clone", custom=True, predefined_clone=True, dict_template_id=4242),
        Obj(id=101, name="Clone of clone", custom=True, predefined_clone=True, dict_template_id=100)]
    z.dlp_engine.items = [Obj(id=10, name="E", custom_dlp_engine=True, engine_expression="((D100.S > 0) OR (D101.S > 0) OR (D1.S > 0))")]
    z.dlp_web_rules.items = [Obj(id=1, name="R", order=1, rank=7, action="ALLOW", state="ENABLED", protocols=["ANY_RULE"], dlp_engines=[Obj(id=10, name="E")])]
    pack = pe.export_pack(c, tenant_label="t")["pack"]
    why = {d["name"]: d["reason"] for d in pack["not_exported"] if d["kind"] == "dictionary"}
    assert "no template id" not in why["Orphan Clone"] and "4242" in why["Orphan Clone"], why
    assert "no template id" not in why.get("Clone of clone", ""), why


def test_a_rule_without_a_name_is_listed_not_dropped_silently():
    c = make_client(casb_tenants=TENANTS)
    z = c.zia
    z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules = FakeChannelRules([]), FakeCasbRules([]), FakeChannelRules([])
    z.dlp_dictionary.items = []
    z.dlp_engine.items = [Obj(id=61, name="PCI", predefined_engine_name="PCI", custom_dlp_engine=False)]
    z.dlp_web_rules.items = [Obj(id=7, order=1, rank=7, action="ALLOW", state="ENABLED", dlp_engines=[Obj(id=61, name="PCI")])]
    res = pe.export_pack(c, tenant_label="t")
    # No rule is left to export, so the export fails; not_exported still says why.
    left = res["pack"]["not_exported"] if res["status"] == "ready" else res["not_exported"]
    assert any(d["kind"] == "rule" and "7" in str(d["name"]) for d in left), left


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------

def test_saas_rule_tenants_survive_the_sdk_model():
    from zscaler.zia.models.casb_dlp_rules import CasbdDlpRules
    raw = [{"id": 31, "name": "SaaS-Projects", "order": 1, "rank": 7, "type": "OFLCASB_DLP_FILE",
            "action": "OFLCASB_DLP_REPORT_INCIDENT", "state": "ENABLED",
            "dlpEngines": [{"id": 5001, "name": "Project Leak"}], "cloudAppTenants": [{"id": 501, "name": "Acme Box"}]}]

    class Resp:
        def get_results(self):
            return raw

    class SdkCasb:
        # As the SDK builds its models: from form_response_body(item), a copy,
        # so the raw answer keeps the references the model loses.
        def list_all_rules(self, *a, **k):
            from zscaler.api_client import APIClient
            return [CasbdDlpRules(APIClient.form_response_body(r)) for r in raw], Resp(), None
        list_rules = list_all_rules

    client = _source()
    client.zia.casb_dlp_rules = SdkCasb()
    pack = pe.export_pack(client, tenant_label="t", selection={"saas": "all"})["pack"]
    assert pack["policies"][0]["tenants"] == ["Acme Box"]
    assert not [d for d in pack["meta"]["not_exported"] if d.get("field") == "cloud_app_tenants"]


def test_deploying_an_exported_pack_does_not_change_the_confidence_of_existing_predefined_dictionaries(tmp_path):
    pack = pe.export_pack(_source(), tenant_label="src")["pack"]
    assert pack["meta"]["confidence_tweaks"] == []
    saved = pl.save_pack(pl.assemble_pack(_upload(pe.zip_pack(pack)[1])), root=str(tmp_path))
    packs = [{"id": saved["id"], "dir": saved["dir"]}]
    target = _empty_target()
    target.zia.dlp_dictionary.items += [
        Obj(id=93, name="MEDICAL", custom=False, confidence_threshold="CONFIDENCE_LEVEL_MEDIUM"),
        Obj(id=94, name="FINANCIAL", custom=False, confidence_threshold="CONFIDENCE_LEVEL_MEDIUM"),
    ]
    rep = pd.preflight(target, packs, writes_enabled=True)
    assert [t for t in items_by(rep, "tweak").values() if t["status"] == pd.MODIFY] == []
    res = pd.apply(target, packs, plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied", res
    assert target.zia.dlp_dictionary.updated == []


# ---------------------------------------------------------------------------
# Input checks and privacy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rules", [{"web": 5}, {"web": True}, {"endpoint": 1.5}, {"web": "abc"}, {"saas": {"a": 1}}, {"web": "some"}])
def test_export_start_rejects_malformed_rule_selection_with_400(monkeypatch, rules):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ReadOnly(_source()))
    c = TestClient(srv.app, raise_server_exceptions=False)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "x" * 20}
    r = c.post("/api/dlp-packs/export/start", json=dict(creds, rules=rules))
    assert r.status_code == 400, (r.status_code, r.text[:200])


def test_normalize_selection_rejects_non_list_ids():
    for bad in ({"web": 5}, {"web": True}, {"web": "abc"}, {"web": {"a": 1}}, {"web": [True]}, {"web": [1.5]}):
        with pytest.raises(ValueError):
            pe.normalize_selection(bad)
    assert pe.normalize_selection({"web": ["11", 12], "email": "all"}) == {"web": {"11", "12"}, "email": None}
    assert pe.normalize_selection([{"channel": "web", "id": 11}, {"channel": "email", "id": "41"}]) == {"web": {"11"}, "email": {"41"}}


def test_a_string_selection_is_refused():
    with pytest.raises(ValueError):
        pe.normalize_selection({"web": "some"})


def test_people_named_in_rule_scope_never_reach_the_pack():
    client = _source()
    r = next(x for x in client.zia.dlp_web_rules.items if x.name == "Web-Projects")
    r.auditor = Obj(id=77, name="auditor.person@corp.example")
    r.users = [Obj(id=78, name="jane.admin@corp.example")]
    r.excluded_users = [Obj(id=79, name="bob@corp.example")]
    res = pe.export_pack(client, tenant_label="acme")
    blob = json.dumps(pe.pack_files(res["pack"])) + json.dumps(res["pack"]["meta"])
    for who in ("auditor.person@corp.example", "jane.admin@corp.example", "bob@corp.example"):
        assert who not in blob, who
    left = {(d["name"], d.get("field")) for d in res["pack"]["meta"]["not_exported"]}
    assert {("Web-Projects", "auditor"), ("Web-Projects", "users"), ("Web-Projects", "excluded_users")} <= left


class InsertingRules(FakeChannelRules):
    """Like ZIA Web / Endpoint / Email DLP: a rule added at order N goes to N, the rest move down."""
    def add_rule(self, **kw):
        obj, resp, err = super().add_rule(**kw)
        self.items.remove(obj)
        ordered = sorted(self.items, key=lambda r: int(r.order))
        ordered.insert(int(kw.get("order") or 1) - 1, obj)
        for i, r in enumerate(ordered, 1):
            r.order = i
        self.items = ordered
        return obj, resp, err


def test_the_tenants_rule_order_comes_back_after_export_deploy_export(tmp_path):
    src = _source()
    z = src.zia
    z.dlp_web_rules.items = [Obj(id=10 + i, name=f"Web-{i}", order=i, rank=7, action="ALLOW", state="ENABLED",
                                 protocols=["ANY_RULE"], dlp_engines=[Obj(id=61, name="PCI")]) for i in (1, 2, 3)]
    z.endpoint_dlp_rules = FakeChannelRules([Obj(id=20 + i, name=f"EP-{i}", order=i, rank=7, action="ALLOW", state="ENABLED",
                                                 dlp_engines=[Obj(id=61, name="PCI")], data_transfer_method="REMOVABLE_DRIVE_TRANSFER")
                                             for i in (1, 2, 3)])
    pack = pe.export_pack(src, selection={"web": "all", "endpoint": "all"}, tenant_label="src")["pack"]
    saved = pl.save_pack(pl.assemble_pack(_upload(pe.zip_pack(pack)[1])), root=str(tmp_path))
    packs = [{"id": saved["id"], "dir": saved["dir"]}]
    target = _empty_target()
    target.zia.dlp_web_rules = InsertingRules(start=7000)
    target.zia.endpoint_dlp_rules = InsertingRules(start=8000)
    rep = pd.preflight(target, packs, writes_enabled=True)
    res = pd.apply(target, packs, plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied", res
    assert [r.name for r in sorted(target.zia.dlp_web_rules.items, key=lambda r: int(r.order))] == ["Web-1", "Web-2", "Web-3"]
    assert [r.name for r in sorted(target.zia.endpoint_dlp_rules.items, key=lambda r: int(r.order))] == ["EP-1", "EP-2", "EP-3"]
    # The report still lists the rules in pack order.
    assert [r["name"] for r in res["results"] if r["kind"] == "policy" and r.get("channel") == "web"] == ["Web-1", "Web-2", "Web-3"]


def test_a_same_named_tenant_engine_whose_dictionaries_the_plan_creates_is_reported_as_differing(tmp_path):
    pack = pe.export_pack(_source(), tenant_label="src")["pack"]
    saved = pl.save_pack(pl.assemble_pack(_upload(pe.zip_pack(pack)[1])), root=str(tmp_path))
    packs = [{"id": saved["id"], "dir": saved["dir"]}]
    target = _empty_target()
    target.zia.dlp_engine.items.append(Obj(id=3101, name="Project Leak", custom_dlp_engine=True, engine_expression="((D91.S > 9))"))
    rep = pd.preflight(target, packs, writes_enabled=True)
    eng = items_by(rep, "engine")["Project Leak"]
    assert eng["status"] == pd.REUSE_DIFFERS, (eng["status"], eng.get("reason"))


# ---------------------------------------------------------------------------
# Independent review of PR #39
# ---------------------------------------------------------------------------

# What zscaler-sdk-python returns (RetryTooLong) when ZIA's Retry-After is
# longer than the app lets it wait: the hourly limit is reached.
HOURLY = "Retry wait time 3600 seconds exceeds configured maxRetrySeconds 30."


def test_the_sdks_hourly_limit_refusal_on_a_rule_read_fails_the_export_instead_of_a_ready_pack_without_that_channel(monkeypatch):
    import zia_rate
    monkeypatch.setattr(zia_rate, "hold", lambda s, key=None, **kw: 0.0)
    monkeypatch.setattr(pe, "_sleep", lambda s: None, raising=False)
    client = _source()
    calls = _refuse_n(client.zia.dlp_web_rules, "list_rules", HOURLY, times=99)
    later = _refuse_n(client.zia.endpoint_dlp_rules, "list_rules", "unused", times=0)
    res = pe.export_pack(client, tenant_label="acme")
    assert res["status"] == "error" and "pack" not in res, res.get("status")
    assert "hour" in res["error"] and "nothing was exported" in res["error"].lower(), res["error"]
    assert calls == [1], "read again although ZIA's hourly limit was reached"
    assert later == [], "kept sending reads to a client ZIA had just refused"


def test_the_sdks_hourly_limit_refusal_on_the_dictionary_read_is_reported_as_the_rate_limit():
    client = _source()
    _refuse(client.zia.dlp_dictionary, "list_dicts", HOURLY)
    res = pe.export_pack(client, tenant_label="acme")
    assert res["status"] == "error" and "hour" in res["error"] and "role" not in res["error"], res["error"]


def test_stop_while_the_pack_is_built_produces_no_pack(monkeypatch, tmp_path):
    import threading
    import dlp_api_server as srv
    import pack_jobs
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}

    def fn(log, cancel):
        def log_and_stop(line):
            log(line)
            if line.startswith("Pack built"):   # every read is done; Stop arrives now
                pack_jobs.cancel(pack_jobs.current().id)
        return srv._run_pack_export(_source(), creds, srv.PackExportRequest(pack_name="x"), None, log_and_stop, cancel)
    job = pack_jobs.start("export", fn)
    for _ in range(500):
        if job.status != pack_jobs.RUNNING:
            break
        time.sleep(0.01)
    assert any(l.startswith("Stop requested") and "no pack is produced" in l for l in job.logs)
    assert job.status == pack_jobs.CANCELLED and job.artifact is None, (job.status, (job.result or {}).get("status"))

    # The same promise when Stop arrives after the pack is built, while it is zipped.
    cancel = threading.Event()
    real_zip = pe.zip_pack
    monkeypatch.setattr(pe, "zip_pack", lambda pack: (cancel.set(), real_zip(pack))[1])
    res = srv._run_pack_export(_source(), creds, srv.PackExportRequest(pack_name="x"), None, lambda m: None, cancel)
    assert res["status"] == "stopped" and "artifact" not in res


def test_a_pick_of_no_rule_reads_nothing_and_says_so(monkeypatch):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    ro = ReadOnly(_source())
    reads = []
    real = ro.zia.dlp_dictionary.list_dicts
    ro.zia._t.dlp_dictionary.list_dicts = lambda *a, **k: (reads.append(1), real(*a, **k))[1]
    res = pe.export_pack(ro, selection={"web": [], "email": [None]}, tenant_label="acme")
    assert res["status"] == "error" and "no rule was picked" in res["error"].lower(), res
    assert "has no DLP rules" not in res["error"] and reads == [], "read the tenant for an empty pick"

    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or ro)
    c = TestClient(srv.app, raise_server_exceptions=False)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "x" * 20}
    r = c.post("/api/dlp-packs/export/start", json=dict(creds, rules={"web": []}))
    assert r.status_code == 400 and "no rule was picked" in r.text.lower(), (r.status_code, r.text[:200])
    assert built == [], "signed in to the tenant for an empty pick"
    # A channel left empty beside one with picks still exports the picks.
    assert pe.export_pack(_source(), selection={"web": [], "email": "all"}, tenant_label="acme")["status"] == "ready"


# ---------------------------------------------------------------------------
# Independent review of PR #39, round 3
# ---------------------------------------------------------------------------

def test_a_short_429_is_waited_out_in_seconds_and_does_not_hold_the_tenant_for_the_hour(monkeypatch):
    import zia_rate
    holds, slept = [], []
    monkeypatch.setattr(zia_rate, "hold", lambda s, key=None, **kw: holds.append(s) or 0.0)
    monkeypatch.setattr(pe, "_sleep", lambda s: slept.append(s), raising=False)
    for refusal in ('{"status": 429, "message": "Rate Limit (2/SECOND) exceeded"}', TOO_MANY,
                    "Retry wait time 2 seconds exceeds configured maxRetrySeconds 1."):
        holds.clear(), slept.clear()
        client = _source()
        calls = _refuse_n(client.zia.dlp_web_rules, "list_rules", refusal, times=1)
        res = pe.export_pack(client, tenant_label="acme")
        assert res["status"] == "ready", (refusal, res.get("error"))
        assert len(calls) == 2, "the short refusal was not retried"
        assert holds and max(holds) <= 30 and sum(slept) <= 30, (refusal, holds, sum(slept))


def test_a_short_retry_too_long_waits_at_least_what_zia_asked_for_before_the_read_is_sent_again(monkeypatch):
    # ZIA asks for 120 s: above both short fallbacks (5 s / 15 s), below the
    # hourly limit. Retrying sooner sends a read ZIA refuses (rule 4), and a
    # shorter hold lets other sessions on this tenant send too soon.
    import zia_rate
    holds, slept, logged = [], [], []
    monkeypatch.setattr(zia_rate, "hold", lambda s, key=None, **kw: holds.append(s) or 0.0)
    monkeypatch.setattr(pe, "_sleep", lambda s: slept.append(s), raising=False)
    asked = 120
    refusal = f"RetryTooLong: Retry wait time {asked} seconds exceeds configured maxRetrySeconds 30"
    assert not pe._is_hourly(refusal) and asked > max(pe.SHORT_RATE_WAIT_SECONDS)
    answers = iter([([], refusal), (["ok"], None)])
    sent_after = []
    def fn():
        sent_after.append(sum(slept))
        return next(answers)
    data, err, refused = pe._read("rules", fn, logged.append)
    assert (data, err, refused) == (["ok"], None, False)
    assert len(sent_after) == 2 and sent_after[1] >= asked, sent_after
    assert sum(slept) >= asked, slept
    assert holds and max(holds) >= asked, holds


def test_only_a_retry_too_long_with_a_long_wait_is_the_hourly_limit():
    assert pe._is_hourly(HOURLY)
    assert pe._is_hourly("Retry wait time 1800 seconds exceeds configured maxRetrySeconds 30.")
    assert not pe._is_hourly("Retry wait time 2 seconds exceeds configured maxRetrySeconds 1.")
    assert not pe._is_hourly('{"status": 429, "message": "Rate Limit (2/SECOND) exceeded"}')
    assert pe._is_rate("Retry wait time 2 seconds exceeds configured maxRetrySeconds 1.")


def test_blank_rule_ids_are_no_pick_and_are_refused_before_any_sign_in_or_read(monkeypatch):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    for rules in ({"web": [""]}, {"web": ["   "]}, {"web": [], "email": [""]}):
        assert pe.nothing_picked(pe.normalize_selection(rules)), rules
        ro = ReadOnly(_source())
        reads = []
        real = ro.zia.dlp_dictionary.list_dicts
        ro.zia._t.dlp_dictionary.list_dicts = lambda *a, **k: (reads.append(1), real(*a, **k))[1]
        res = pe.export_pack(ro, selection=rules, tenant_label="acme")
        assert res["status"] == "error" and "no rule was picked" in res["error"].lower(), res
        assert reads == [], "read the tenant for a blank pick"
        built = []
        monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or ro)
        c = TestClient(srv.app, raise_server_exceptions=False)
        creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "x" * 20}
        r = c.post("/api/dlp-packs/export/start", json=dict(creds, rules=rules))
        assert r.status_code == 400 and "no rule was picked" in r.text.lower(), (rules, r.status_code, r.text[:200])
        assert built == [], "signed in to the tenant for a blank pick"
    # An id with spaces around it still names its rule.
    res = pe.export_pack(_source(), selection={"web": [" 11 "]}, tenant_label="acme")
    assert res["status"] == "ready", res.get("error")


def test_a_channel_named_with_an_empty_pick_is_not_read(monkeypatch):
    import zia_rate
    monkeypatch.setattr(zia_rate, "hold", lambda s, key=None, **kw: 0.0)
    monkeypatch.setattr(pe, "_sleep", lambda s: None, raising=False)
    client = _source()
    email = _refuse_n(client.zia.outbound_email_dlp_rules, "list_rules", HOURLY, times=99)
    res = pe.export_pack(client, selection={"web": "all", "email": []}, tenant_label="acme")
    assert email == [], "read the Email rules although no Email rule was picked"
    assert res["status"] == "ready", res.get("error")
    assert not any("Email" in d["name"] for d in res["pack"]["not_exported"]), res["pack"]["not_exported"]


def test_a_refused_export_read_holds_every_jobs_reads_on_the_tenant(monkeypatch):
    # RS2-5: the export's hold after a refused read is the tenant's, for
    # reads too: the assessment's Client and other SDK sessions wait for it.
    import zia_rate
    monkeypatch.setattr(pe, "_sleep", lambda s: None, raising=False)
    key = "t" * 16
    answers = iter([([], '{"status": 429, "message": "Rate Limit (2/SECOND) exceeded"}'), (["ok"], None)])
    with zia_rate.using(key):
        assert pe._read("rules", lambda: next(answers), lambda m: None) == (["ok"], None, False)
    assert zia_rate.paused_for(key, reads=True) > 0
    assert zia_rate.wait("GET", "/dlpDictionaries", key=key) > 0, "another job's read waits for the export's hold"
    assert zia_rate.paused_for("u" * 16, reads=True) == 0.0, "another tenant is not held"


def test_an_hourly_export_refusal_holds_every_jobs_reads_for_the_hour(monkeypatch):
    import zia_rate
    key = "t" * 16
    with zia_rate.using(key):
        data, err, refused = pe._read("rules", lambda: ([], HOURLY), lambda m: None)
    assert refused
    assert zia_rate.paused_for(key, reads=True) >= pe._retry_wait(HOURLY) - 5
