"""Native Zscaler API JSON (dlpDictionaries, dlpEngines, *DlpRules exports)
uploads as a pack and renders as Terraform."""
import json

import native_zscaler as nz
import pack_library as pl
import pack_terraform

DICTS = [
    {"id": 63, "name": "Project Codenames", "description": "internal", "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES",
     "customPhraseMatchType": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "proximityLengthEnabled": True, "proximity": 20,
     "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "Project Falcon"}], "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "\\bFALC-\\d{4}\\b"}], "nameL10nTag": False},
    {"id": 7, "name": "Credit Cards", "custom": False, "dictionaryType": "PREDEFINED", "nameL10nTag": True},
    {"id": 64, "name": "Card Clone", "custom": True, "predefinedClone": True, "dictTemplateName": "Credit Cards", "dictionaryType": "PATTERNS_AND_PHRASES", "confidenceThreshold": "CONFIDENCE_LEVEL_HIGH", "phrases": [], "patterns": []},
]
ENGINES = [
    {"id": 5001, "name": "Codenames + Cards", "engineExpression": "((D63.S > 0) AND (D7.S > 1))", "customDlpEngine": True, "description": "x"},
    {"id": 1, "name": "PCI", "predefinedEngineName": "PCI", "engineExpression": "((D7.S > 0))", "customDlpEngine": False},
    {"id": 5002, "name": "Orphan", "engineExpression": "((D999.S > 0))", "customDlpEngine": True},
]
WEB = [{"id": 7001, "order": 3, "rank": 7, "name": "Block codenames to GenAI", "description": "d", "protocols": ["HTTPS_RULE"], "action": "BLOCK", "state": "ENABLED",
        "dlpEngines": [{"id": 5001, "name": "Codenames + Cards"}], "cloudApplications": ["CHATGPT_AI"], "urlCategories": [{"id": "AI_ML_APPS"}], "minSize": 10,
        "ocrEnabled": True, "zscalerIncidentReceiver": True, "severity": "RULE_SEVERITY_HIGH", "locations": [{"id": 1, "name": "HQ"}], "groups": [{"id": 2}],
        "notificationTemplate": {"id": 9, "name": "Auditor"}, "labels": [{"id": 3, "name": "Compliance"}]}]
ENDPOINT = [{"id": 8001, "name": "Codenames on USB", "action": "CONFIRM", "state": "DISABLED", "dlpEngines": [{"id": 5001}], "dataTransferMethod": "REMOVABLE_DRIVE_TRANSFER",
             "deviceTrustLevels": ["ANY"], "eunEnabled": True, "endPointApplicationGroups": [{"id": 4, "name": "Browsers"}],
             "subRules": [{"id": 8002, "name": "Except IT", "action": "ALLOW", "state": "ENABLED", "dlpEngines": [{"id": 5001}], "departments": [{"id": 5}]}]}]
CASB = [{"id": 8500, "name": "Codenames at rest", "type": "OFLCASB_DLP_FILE", "action": "OFLCASB_DLP_REPORT_INCIDENT", "state": "ENABLED",
         "dlpEngines": [{"id": 5001}], "cloudAppTenants": [{"id": 501, "name": "Acme Box"}], "collaborationScope": ["ANY"], "components": ["COMPONENT_FILE_ATTACHMENTS"]}]
EMAIL = [{"id": 8800, "name": "Codenames by mail", "action": "BLOCK", "state": "ENABLED", "dlpEngines": [{"id": 5001}], "emailTenants": [{"id": 503}]}]


def _files():
    return [{"name": "dlpDictionaries.json", "content": json.dumps(DICTS)}, {"name": "dlpEngines.json", "content": json.dumps(ENGINES)},
            {"name": "webDlpRules.json", "content": json.dumps(WEB)}, {"name": "endpointDlpRules.json", "content": json.dumps(ENDPOINT)},
            {"name": "casbDlpRules.json", "content": json.dumps(CASB)}, {"name": "emailDlpRules.json", "content": json.dumps(EMAIL)}]


def test_native_objects_are_recognised():
    assert nz.is_native(DICTS[0]) and nz.kind_of(DICTS[0]) == "dictionaries"
    assert nz.is_native(ENGINES[0]) and nz.kind_of(ENGINES[0]) == "engines"
    assert nz.is_native(WEB[0]) and nz.kind_of(WEB[0]) == "policies"
    assert not nz.is_native({"name": "pack rule", "engines": ["E"], "action": "ALLOW"})
    assert pl._looks_like(WEB) == "policies" and pl._looks_like(ENGINES) == "engines" and pl._looks_like(DICTS) == "dictionaries"


def test_upload_transcribes_native_json_into_a_pack_and_terraform(tmp_path):
    pack = pl.assemble_pack(_files(), pack_name="Acme Export")
    assert pack["format"] == "zscaler" and pack["native"]["dictionaries"] == 2 and pack["native"]["engines"] == 2 and pack["native"]["policies"] == 4
    d = {x["name"]: x for x in pack["dictionaries"]}
    assert set(d) == {"Project Codenames", "Card Clone"} and d["Project Codenames"]["proximity"] == 20 and d["Project Codenames"]["patterns"][0]["pattern"] == "\\bFALC-\\d{4}\\b"
    # Proximity is only accepted on the any-pattern-with-any-phrase type: the export's Match Any is switched and the change is named.
    assert d["Project Codenames"]["custom_phrase_match_type"] == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
    assert any("Project Codenames" in w and "match type changed" in w for w in pack.get("warnings") or pack.get("native", {}).get("warnings") or [])
    assert d["Card Clone"]["predefined_clone"] and d["Card Clone"]["dict_template_name"] == "Credit Cards" and d["Card Clone"]["confidence_threshold"] == "CONFIDENCE_LEVEL_HIGH"
    e = {x["name"]: x for x in pack["engines"]}
    assert e["Codenames + Cards"]["expression"] == "((D:Project Codenames > 0) AND (D:Credit Cards > 1))"
    assert e["Orphan"]["expression"] == "((D:UNKNOWN_DICTIONARY_999 > 0))" and "PCI" not in e
    p = {x["name"]: x for x in pack["policies"]}
    web = p["Block codenames to GenAI"]
    assert web["channel"] == "web" and web["engines"] == ["Codenames + Cards"] and web["cloud_applications"] == ["CHATGPT_AI"] and web["url_categories"] == ["AI_ML_APPS"]
    assert web["ocr_enabled"] and web["zscaler_incident_receiver"] and web["min_size"] == 10 and web["notification_template"] == "Auditor" and web["labels"] == ["Compliance"]
    assert "locations" not in web and "order" not in web
    ep = p["Codenames on USB"]
    assert ep["channel"] == "endpoint" and ep["data_transfer_method"] == "REMOVABLE_DRIVE_TRANSFER" and ep["endpoint_application_groups"] == ["Browsers"] and ep["eun_enabled"] is True
    assert ep["sub_rules"][0]["name"] == "Except IT" and "channel" not in ep["sub_rules"][0]
    saas = p["Codenames at rest"]
    assert saas["channel"] == "saas" and saas["saas_type"] == "OFLCASB_DLP_FILE" and saas["tenants"] == "any" and saas["components"] == ["COMPONENT_FILE_ATTACHMENTS"]
    assert p["Codenames by mail"]["channel"] == "email" and p["Codenames by mail"]["tenants"] == "any"
    w = " ".join(pack["warnings"])
    assert "predefined dictionary left out" in w and "predefined engine" in w and "tenant-specific scope" in w and "dictionary id(s) 999" in w and "SaaS tenant ids" in w
    v = pl.validate_pack(pack)
    assert v["counts"]["policies"] == 4 and set(v["channels"]) == {"web", "endpoint", "saas", "email"}
    # The Orphan engine's unknown dictionary is a real problem the validator names; the rest passes.
    assert any("UNKNOWN_DICTIONARY_999" in x for x in v["problems"] + v["warnings"])
    # Terraform: the same pack renders as a workspace with every channel's rule.
    good = dict(pack, engines=[e["Codenames + Cards"]])
    saved = pl.save_pack(good, pack_id="acme_export", root=str(tmp_path))
    files = pack_terraform.generate({"id": "acme_export", "dir": saved["dir"]})
    tf = "\n".join(files.values())
    assert "Project Codenames" in tf and "Block codenames to GenAI" in tf and "Codenames on USB" in tf and "Codenames at rest" in tf and "Codenames by mail" in tf
    assert "rules.tf" in files and "imports.tf" not in files   # static: nothing to import
