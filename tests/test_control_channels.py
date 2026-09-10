"""
Containment channels: Cloud App Control, File Type Control, URL Filtering
and SSL Inspection rules in packs. They carry no engines, resolve their
application scope (and, for Cloud App Control, their exact actions) from
the tenant at preflight, and are created/restored/exported like any rule.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _keep_containment(monkeypatch):
    """These tests exercise the containment-channel machinery itself, so
    they run with the pack carve-out disabled (see pack_channels)."""
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")


import pack_channels as pc
import pack_deploy as pd
import pack_terraform as pt
from test_baselines import BASELINE_META, FakeCloudApps  # noqa: F401
from test_pack_channels import AVAILABLE, APPS, FakeChannelRules, FakeCloudAppControl, FakeClassApps, add_control_services, make_client, tenant as casb_tenant  # noqa: F401
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack, items_by  # noqa: F401

def control_client(**kw):
    cac_rules = kw.pop("cac_rules", None)
    return add_control_services(make_client(**kw), cac_rules=cac_rules)


def control_pack(tmp_path, meta=None):
    return write_pack(
        tmp_path, "contain",
        dicts=[], engines=[],
        policies=[
            {"name": "CAC-FileShare", "channel": "cloud_app", "type": "FILE_SHARE", "state": "DISABLED", "rank": 7,
             "actions_by_verb": {"UPLOAD": "BLOCK", "SHARE": "BLOCK", "*": "ALLOW"}},
            {"name": "FTC-Block-Archives", "channel": "file_type", "filtering_action": "BLOCK", "operation": "UPLOAD",
             "file_types": ["FTCATEGORY_ZIP"], "protocols": ["HTTPS_RULE"], "cloud_app_classes": ["FILE_SHARE"], "state": "DISABLED"},
            {"name": "URL-Block-Unknown-Post", "channel": "url", "action": "BLOCK", "url_categories": ["OTHER_MISCELLANEOUS"],
             "protocols": ["HTTPS_RULE"], "request_methods": ["POST"], "state": "DISABLED"},
            {"name": "SSL-Decrypt-AI", "channel": "ssl", "cloud_app_classes": ["AI_ML"], "state": "DISABLED",
             "action": {"type": "DECRYPT", "ssl_interception_cert": {"id": 1}, "decrypt_sub_actions": {"ocsp_check": True}}},
        ],
        meta=meta or {"name": "Containment", "confidence_tweaks": []},
    )


def test_choose_cloud_app_actions_by_verb():
    chosen = pc.choose_cloud_app_actions(AVAILABLE["FILE_SHARE"], {"UPLOAD": "BLOCK", "SHARE": "BLOCK", "*": "ALLOW"})
    assert chosen == ["BLOCK_FILE_SHARE_SHARE", "BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"]
    assert "ISOLATE_FILE_SHARE_VIEW" not in chosen
    chosen = pc.choose_cloud_app_actions(AVAILABLE["WEBMAIL"], {"SEND": "BLOCK", "*": "ALLOW"})
    assert chosen == ["BLOCK_WEBMAIL_ATTACHMENT_SEND", "BLOCK_WEBMAIL_SEND", "ALLOW_WEBMAIL_VIEW"]  # SEND matches ATTACHMENT_SEND too


def test_validate_control_rules_name_missing_fields():
    assert "type" in pc.validate({"name": "x", "channel": "cloud_app"})
    assert "actions" in pc.validate({"name": "x", "channel": "cloud_app", "type": "FILE_SHARE"})
    assert "file_types" in pc.validate({"name": "x", "channel": "file_type"})
    assert "url_categories" in pc.validate({"name": "x", "channel": "url"})
    assert "action" in pc.validate({"name": "x", "channel": "ssl"})
    assert pc.validate({"name": "x", "channel": "ssl", "action": {"type": "DECRYPT"}}) is None


def test_control_rules_plan_resolve_and_apply(tmp_path):
    client = control_client()
    pack = control_pack(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert {n: p["status"] for n, p in pol.items()} == {
        "CAC-FileShare": pd.CREATE, "FTC-Block-Archives": pd.CREATE, "URL-Block-Unknown-Post": pd.CREATE, "SSL-Decrypt-AI": pd.CREATE}
    cac = pol["CAC-FileShare"]
    assert cac["detail"]["channel"] == "cloud_app"
    assert cac["detail"]["applications"] == ["BOX", "DROPBOX", "GOOGLE_DRIVE"]
    assert cac["detail"]["actions"] == ["BLOCK_FILE_SHARE_SHARE", "BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"]
    assert any(d.startswith("resource:Cloud App Control actions: FILE_SHARE") for d in cac["depends_on"])
    assert pol["SSL-Decrypt-AI"]["detail"]["applications"] == ["CHATGPT_AI", "GEMINI"]
    assert not pol["CAC-FileShare"]["depends_on"] or all(not d.startswith("engine:") for d in pol["CAC-FileShare"]["depends_on"])
    # Impact: enforcing (BLOCK/DECRYPT) rules are called out, and the containment card explains ordering.
    titles = [i["type"] for i in rep["impacts"]]
    assert "enforcement_disabled" in titles and "containment" in titles   # BLOCK/DECRYPT actions, but shipped DISABLED
    assert rep["status"] == "ready", rep["warnings"]
    assert any(r["requirement"].startswith("Cloud App Control rule API reachable") for r in rep["dependencies"])

    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied" and res["summary"] == {"created": 4}
    z = client.zia
    rtype, kw = z.cloudappcontrol.added[0]
    assert rtype == "FILE_SHARE" and kw["type"] == "FILE_SHARE"
    assert kw["actions"] == ["BLOCK_FILE_SHARE_SHARE", "BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"]
    assert kw["applications"] == ["BOX", "DROPBOX", "GOOGLE_DRIVE"] and kw["state"] == "DISABLED"
    assert z.cloudappcontrol.calls[0] == ("FILE_SHARE", ["BOX", "DROPBOX", "GOOGLE_DRIVE"])
    ftc = z.file_type_control_rule.added[0]
    assert ftc["filtering_action"] == "BLOCK" and ftc["operation"] == "UPLOAD" and ftc["file_types"] == ["FTCATEGORY_ZIP"]
    assert ftc["cloud_applications"] == ["BOX", "DROPBOX", "GOOGLE_DRIVE"]
    url = z.url_filtering.added[0]
    assert url["action"] == "BLOCK" and url["url_categories"] == ["OTHER_MISCELLANEOUS"] and url["request_methods"] == ["POST"]
    ssl = z.ssl_inspection_rules.added[0]
    assert ssl["action"]["type"] == "DECRYPT" and ssl["cloud_applications"] == ["CHATGPT_AI", "GEMINI"] and ssl["platforms"]
    assert "dlp_engines" not in ssl and "dlp_engines" not in url


def test_control_rules_customized_kept_unless_converging(tmp_path):
    existing = Obj(id=9501, name="CAC-FileShare", type="FILE_SHARE", order=2, rank=7, state="DISABLED",
                   actions=["ALLOW_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_SHARE", "ALLOW_FILE_SHARE_VIEW"],  # someone allowed upload
                   applications=["BOX", "DROPBOX", "GOOGLE_DRIVE"], description="")
    client = control_client(cac_rules=[existing])
    pack = control_pack(tmp_path, meta=dict(BASELINE_META, name="Containment Baseline"))
    # Default: the customer's version is kept and reported as customized.
    rep = pd.preflight(client, [pack], writes_enabled=True)
    cac = items_by(rep, "policy")["CAC-FileShare"]
    assert cac["status"] == pd.REUSE_DIFFERS and cac["drift"] == ["action"] and cac["position"] == "customized"
    # Converge mode restores it.
    rep = pd.preflight(client, [pack], writes_enabled=True, restore_drift=True)
    cac = items_by(rep, "policy")["CAC-FileShare"]
    assert cac["status"] == pd.RESTORE and cac["drift"] == ["action"]
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, restore_drift=True)
    assert res["summary"]["restored"] == 1
    rtype, rid, kw = client.zia.cloudappcontrol.updated[0]
    assert (rtype, rid) == ("FILE_SHARE", 9501) and kw["order"] == 2
    assert kw["actions"] == ["BLOCK_FILE_SHARE_SHARE", "BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"]


def test_missing_available_actions_blocks_only_that_rule(tmp_path):
    client = control_client()
    client.zia.cloudappcontrol.list_available_actions = lambda t, apps: (None, None, {"message": "FEATURE_NOT_ENABLED"})
    rep = pd.preflight(client, [control_pack(tmp_path)], writes_enabled=True)
    pol = items_by(rep, "policy")
    assert pol["CAC-FileShare"]["status"] == pd.BLOCKED_DEPENDENCY and "available Cloud App Control actions" in pol["CAC-FileShare"]["reason"]
    assert pol["URL-Block-Unknown-Post"]["status"] == pd.CREATE


def test_terraform_for_control_rules(tmp_path):
    pack = control_pack(tmp_path, meta=dict(BASELINE_META, name="Containment Baseline"))
    files = pt.generate(pack)
    r = files["rules.tf"]
    assert 'resource "zia_cloud_app_control_rule" "cac_fileshare"' in r
    assert 'type                         = "FILE_SHARE"' in r
    assert 'data "zia_cloud_app_control_rule_actions" "cac_fileshare_actions"' in r
    assert 'endswith(a, v)]) ? startswith(a, "BLOCK_")' in r and '["_UPLOAD", "_SHARE"]' in r
    assert 'data "zia_cloud_applications" "apps_file_share"' in r and 'policy_type = "cloud_application_policy"' in r
    assert 'resource "zia_file_type_control_rules" "ftc_block_archives"' in r and 'filtering_action             = "BLOCK"' in r
    assert 'resource "zia_url_filtering_rules" "url_block_unknown_post"' in r and 'request_methods              = ["POST"]' in r
    assert 'resource "zia_ssl_inspection_rules" "ssl_decrypt_ai"' in r
    assert 'data "zia_cloud_applications" "apps_ssl_ai_ml"' in r and 'policy_type = "cloud_application_ssl_policy"' in r
    assert "  action {\n" in r and 'type                   = "DECRYPT"' in r and "ssl_interception_cert {" in r
    assert "dlp_engines" not in r
    # Gap mode import id for Cloud App Control rules is type:id.
    client = control_client(cac_rules=[Obj(id=9501, name="CAC-FileShare", type="FILE_SHARE", order=1, rank=7, state="DISABLED",
                                           actions=["BLOCK_FILE_SHARE_SHARE", "BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"],
                                           applications=["BOX", "DROPBOX", "GOOGLE_DRIVE"])])
    rep = pd.public_report(pd.preflight(client, [pack], writes_enabled=True))
    files = pt.generate(pack, report=pt.split_report(rep, "contain"))
    assert 'id = "FILE_SHARE:9501"' in files["imports.tf"]


def test_shipped_phi_and_source_code_baselines_include_containment():
    from dlp_importer import discover_packs
    packs = {p["id"]: p for p in discover_packs()}
    phi = packs["healthcare_phi_baseline"]
    assert phi["channels"].get("cloud_app") == 3 and phi["channels"].get("file_type") == 2
    assert phi["channels"].get("url") == 1 and phi["channels"].get("ssl") == 1
    client = control_client(casb_tenants=[casb_tenant("Acme M365 Mail", "OFFICE_365", 503)])   # the baseline also ships an email rule
    client.zia.dlp_dictionary.items += [Obj(id=1, name="MEDICAL", custom=False), Obj(id=2, name="ML_MEDICAL_DOC_LEAKAGE", custom=False)]
    rep = pd.preflight(client, [{"id": phi["id"], "dir": phi["dir"]}], writes_enabled=True)
    assert rep["status"] in ("ready", "warnings"), rep["blockers"]
    assert all(i["status"] == pd.CREATE for i in rep["items"]), [(i["name"], i["status"], i["reason"]) for i in rep["items"] if i["status"] != pd.CREATE]
