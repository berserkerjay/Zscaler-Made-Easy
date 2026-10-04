"""The upstream contract check (upstream_check.py): what this app sends
against the installed SDK (offline, every CI push), and against the SDK's
2.x service definition, the Terraform provider's schema and docs and
Zscaler's API reference (online, the daily job)."""
from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("zscaler", reason="the installed SDK is what the offline check reads; install from requirements.lock")

import upstream_check as uc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── What the app sends ───────────────────────────────────────────────

def test_the_payload_keys_come_from_the_real_builders_for_every_channel():
    keys = uc.app_payload_keys()
    assert not keys.get("_errors"), keys.get("_errors")
    assert {"name", "custom_phrase_match_type", "dictionary_type", "description", "patterns", "dict_template_id", "confidence_threshold"} <= keys["dictionary"]
    assert keys["engine"] == {"name", "engine_expression", "custom_dlp_engine", "description"}
    assert {"name", "order", "rank", "state", "action", "dlp_engines", "protocols"} <= keys["web"]
    assert {"name", "state", "action", "dlp_engines", "data_transfer_method", "device_trust_levels"} <= keys["endpoint"]
    assert {"name", "state", "action", "dlp_engines", "type", "cloud_app_tenants", "rank"} <= keys["saas"]
    assert {"name", "state", "action", "dlp_engines", "email_tenants"} <= keys["email"]
    assert "rank_note" not in keys["saas"] and "rank_note" not in keys["web"]
    assert keys["activation"] == set()


def test_snake_to_camel_matches_the_sdk():
    assert uc.snake_to_camel("cloud_app_tenants") == "cloudAppTenants"
    assert uc.snake_to_camel("dict_template_id") == "dictTemplateId"
    assert uc.snake_to_camel("name") == "name"


# ── The installed SDK (offline) ──────────────────────────────────────

def test_every_key_the_app_sends_is_known_to_the_installed_sdk():
    keys = uc.app_payload_keys()
    findings, detail = uc.check_installed_sdk(keys)
    assert detail["version"], "the SDK is installed"
    for kind in uc.ENDPOINTS:
        assert detail["endpoints"][kind]["method"], kind
    assert [f for f in findings if f["level"] == "drift"] == [], findings


def test_the_offline_run_is_clean_and_reports_the_pin_and_the_workspaces():
    report = uc.run(offline=True)
    assert report["ok"] is True and report["drift"] == [], report["findings"]
    assert report["terraform"]["pinned"].startswith("~>"), "the provider constraint, not Terraform's required_version"
    emitted = report["terraform"]["emitted"]
    assert {"zia_dlp_web_rules", "zia_dlp_dictionaries", "zia_dlp_engines", "zia_endpoint_dlp_rules", "zia_casb_dlp_rules"} <= set(emitted)
    assert {"name", "order", "rank", "state", "action", "dlp_engines", "protocols"} <= set(emitted["zia_dlp_web_rules"])
    md = uc.to_markdown(report)
    assert md.startswith("# Upstream contract check — OK") and "zscaler-sdk-python" in md and "What the app sends" in md


def test_a_field_the_installed_sdk_does_not_know_is_drift(monkeypatch):
    keys = uc.app_payload_keys()
    keys["web"] = set(keys["web"]) | {"made_up_field"}
    findings, detail = uc.check_installed_sdk(keys)
    drift = [f for f in findings if f["level"] == "drift"]
    assert len(drift) == 1 and "made_up_field" in drift[0]["text"] and "dlp_web_rules.add_rule" in drift[0]["text"]
    assert detail["endpoints"]["web"]["unknown"] == ["made_up_field"]


# ── The 2.x service definition ────────────────────────────────────────

def _defn(with_saas=True):
    ops = {
        "CreateWebDlpRule": {"http": {"method": "POST", "requestUri": "/zia/api/v1/webDlpRules"}, "input": {"shape": "CreateWebDlpRuleRequest"}},
        "CreateDlpDictionary": {"http": {"method": "POST", "requestUri": "/zia/api/v1/dlpDictionaries"}, "input": {"shape": "CreateDlpDictionaryRequest"}},
        "CreateDlpEngine": {"http": {"method": "POST", "requestUri": "/zia/api/v1/dlpEngines"}, "input": {"shape": "CreateDlpEngineRequest"}},
        "CreateEndpointDlpRule": {"http": {"method": "POST", "requestUri": "/zia/api/v1/endPointDlpRules"}, "input": {"shape": "CreateEndpointDlpRuleRequest"}},
        "CreateEmailDlpRule": {"http": {"method": "POST", "requestUri": "/zia/api/v1/emailDlpRules"}, "input": {"shape": "CreateEmailDlpRuleRequest"}},
        "Activate": {"http": {"method": "POST", "requestUri": "/zia/api/v1/status/activate"}, "input": {"shape": "ActivateRequest"}},
        "ListWebDlpRules": {"http": {"method": "GET", "requestUri": "/zia/api/v1/webDlpRules"}, "input": {"shape": "ListRequest"}},
    }
    if with_saas:
        ops["CreateCasbDlpRule"] = {"http": {"method": "POST", "requestUri": "/zia/api/v1/casbDlpRules"}, "input": {"shape": "CreateCasbDlpRuleRequest"}}
    body = lambda *names: {"type": "structure", "members": {n: {"shape": "String"} for n in names}}  # noqa: E731
    shapes = {
        "CreateWebDlpRuleRequest": {"type": "structure", "members": {"body": {"shape": "WebDlpRule"}}},
        "WebDlpRule": body("name", "order", "rank", "state", "action", "severity", "description", "dlpEngines", "protocols", "withoutContentInspection", "newField"),
        "CreateDlpDictionaryRequest": {"type": "structure", "members": {"body": {"shape": "DlpDictionary"}}},
        "DlpDictionary": body("name", "customPhraseMatchType", "dictionaryType", "description", "patterns", "phrases", "proximity", "dictTemplateId", "custom",
                              "confidenceThreshold", "confidenceLevelForPredefinedDict", "hierarchicalIdentifiers", "proximityEnabledForCustomDictionary", "proximityLengthEnabled"),
        "CreateDlpEngineRequest": {"type": "structure", "members": {"body": {"shape": "DlpEngine"}}},
        "DlpEngine": body("name", "engineExpression", "customDlpEngine", "description"),
        "CreateEndpointDlpRuleRequest": {"type": "structure", "members": {"body": {"shape": "EndpointDlpRule"}}},
        "EndpointDlpRule": body("name", "order", "rank", "state", "action", "severity", "description", "dlpEngines", "dataTransferMethod", "deviceTrustLevels",
                                "userRiskScoreLevels", "withoutContentInspection", "eunEnabled"),
        "CreateEmailDlpRuleRequest": {"type": "structure", "members": {"body": {"shape": "EmailDlpRule"}}},
        "EmailDlpRule": body("name", "order", "state", "action", "severity", "description", "dlpEngines", "emailTenants", "withoutContentInspection"),
        "CreateCasbDlpRuleRequest": {"type": "structure", "members": {"body": {"shape": "CasbDlpRule"}}},
        "CasbDlpRule": body("name", "order", "rank", "state", "action", "severity", "description", "dlpEngines", "type", "cloudAppTenants", "collaborationScope",
                            "withoutContentInspection"),
        "ActivateRequest": {"type": "structure", "members": {}},
        "ListRequest": {"type": "structure", "members": {}},
        "String": {"type": "string"},
    }
    return {"metadata": {"apiVersion": "2026-03-01"}, "operations": ops, "shapes": shapes}


def test_the_service_definition_check_finds_missing_operations_and_unknown_fields():
    keys = uc.app_payload_keys()
    findings, detail = uc.check_service_definition(_defn(), keys, "sdk 2.0.0test")
    assert [f for f in findings if f["level"] == "drift"] == [], findings
    assert detail["api_version"] == "2026-03-01" and detail["endpoints"]["web"]["operation"] == "CreateWebDlpRule"
    assert detail["endpoints"]["web"]["unused"] >= 1   # newField is offered and not sent: informational
    # The real 2.0.0b2 shape: SaaS and Endpoint operations absent → drift naming the path.
    findings, detail = uc.check_service_definition(_defn(with_saas=False), keys, "sdk 2.0.0test")
    drift = [f for f in findings if f["level"] == "drift"]
    assert len(drift) == 1 and "/casbDlpRules" in drift[0]["text"] and "saas" in drift[0]["text"]
    assert detail["endpoints"]["saas"]["operation"] is None
    # A field the app sends that the schema does not list → drift naming the field.
    keys["engine"] = set(keys["engine"]) | {"engine_channels_x"}
    findings, _ = uc.check_service_definition(_defn(), keys, "sdk 2.0.0test")
    assert any("engineChannelsX" in f["text"] and f["level"] == "drift" for f in findings)


def test_body_members_reads_a_wrapped_body_or_the_input_itself():
    d = _defn()
    assert "dlpEngines" in uc.body_members(d, d["operations"]["CreateWebDlpRule"])
    assert uc.body_members(d, d["operations"]["Activate"]) == set()
    assert uc.operation_for(d, "/webDlpRules")[0] == "CreateWebDlpRule" and uc.operation_for(d, "/nothing") is None


# ── Versions ─────────────────────────────────────────────────────────

def test_version_ordering_puts_a_final_after_its_betas_and_prereleases_apart():
    vs = ["1.9.44", "1.10.0", "2.0.0b1", "2.0.0b2", "1.9.9"]
    assert sorted(vs, key=uc._version_key) == ["1.9.9", "1.9.44", "1.10.0", "2.0.0b1", "2.0.0b2"]
    assert uc._version_key("2.0.0") > uc._version_key("2.0.0b2")
    assert uc.is_prerelease("2.0.0b2") and not uc.is_prerelease("1.10.0")


def test_pypi_releases_separates_latest_from_prerelease():
    payload = json.dumps({"info": {"version": "1.10.0"}, "releases": {
        "1.9.44": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"}], "1.10.0": [{"upload_time_iso_8601": "2026-09-18T17:46:48Z"}],
        "2.0.0b2": [{"upload_time_iso_8601": "2026-09-20T00:00:00Z"}], "0.0.1": []}})
    rel, err = uc.pypi_releases(lambda url: (payload, ""))
    assert not err and rel["latest"] == "1.10.0" and rel["latest_prerelease"] == "2.0.0b2" and rel["latest_uploaded"].startswith("2026-09-18")
    rel, err = uc.pypi_releases(lambda url: (None, "blocked"))
    assert rel is None and err == "blocked"


def test_terraform_constraints():
    assert uc.constraint_allows("~> 4.8", "4.8.9") and uc.constraint_allows("~> 4.8", "4.12.0")
    assert not uc.constraint_allows("~> 4.8", "5.0.0") and not uc.constraint_allows("~> 4.8", "4.7.9")
    assert uc.constraint_allows("~> 4.8.1", "4.8.9") and not uc.constraint_allows("~> 4.8.1", "4.9.0")
    assert uc.constraint_allows(">= 1.5.0", "1.9.8")
    assert uc.pinned_provider_constraint().startswith("~> 4.")


# ── Terraform docs and schema ────────────────────────────────────────

DOC = """# zia_dlp_web_rules
## Example Usage
* `ignored` - this is in an example, but the parser only reads from the schema section on
## Argument Reference
### Required
* `name` - (Required) The rule name.
* `order` - (Required) The order.
### Optional
* `state` - (Optional) ENABLED or DISABLED.
* `dlp_engines` - (Block) engines
  * `id` - (List of Number) ids
"""


def test_doc_attributes_start_at_the_schema_section():
    attrs = uc.doc_attributes(DOC)
    assert attrs == {"name", "order", "state", "dlp_engines", "id"}


def test_emitted_attributes_walks_the_committed_workspaces():
    emitted = uc.emitted_attributes()
    assert "zia_dlp_web_rules" in emitted and "zia_activation_status" in emitted
    web = emitted["zia_dlp_web_rules"]
    assert {"name", "description", "order", "rank", "state", "action", "severity", "without_content_inspection", "protocols", "dlp_engines"} <= web
    assert "id" not in web, "a nested block's members are not top-level attributes"


def test_docs_alone_only_note_and_the_schema_settles_it():
    emitted = {"zia_dlp_web_rules": {"name", "order", "state", "rank", "protocols", "lifecycle", "dlp_engines"}}
    fetch = lambda url: (DOC, "")  # noqa: E731
    findings, detail = uc.check_terraform_docs(fetch, emitted)
    assert [f["level"] for f in findings] == ["note"] and "rank" in findings[0]["text"] and "lifecycle" not in findings[0]["text"]
    assert detail["zia_dlp_web_rules"]["undocumented"] == ["protocols", "rank"]
    # The provider schema accepts them: still a note (docs lag).
    accepted = {"zia_dlp_web_rules": {"name", "order", "state", "rank", "protocols", "dlp_engines"}}
    findings, _ = uc.check_terraform_docs(fetch, emitted, accepted)
    assert [f["level"] for f in findings] == ["note"] and "docs lag" in findings[0]["text"]
    # The provider schema does not accept one of them: drift naming it.
    accepted = {"zia_dlp_web_rules": {"name", "order", "state", "rank", "dlp_engines"}}
    findings, _ = uc.check_terraform_docs(fetch, emitted, accepted)
    assert [f["level"] for f in findings] == ["drift"] and "protocols" in findings[0]["text"] and "rank" not in findings[0]["text"].split("emits")[1].split(",")[0]
    findings, detail = uc.check_terraform_docs(lambda url: (None, "HTTP 404"), emitted)
    assert findings[0]["level"] == "note" and "could not be read" in findings[0]["text"]


def test_the_provider_schema_check_is_authoritative():
    schema = {"provider_schemas": {"registry.terraform.io/zscaler/zia": {"resource_schemas": {
        "zia_dlp_web_rules": {"block": {"attributes": {"name": {}, "order": {}, "rank": {}, "state": {}, "protocols": {}}, "block_types": {"dlp_engines": {}}}},
    }}}}
    accepted = uc.parse_provider_schema(schema)
    assert accepted == {"zia_dlp_web_rules": {"name", "order", "rank", "state", "protocols", "dlp_engines"}}
    findings, detail = uc.check_terraform_schema(accepted, {"zia_dlp_web_rules": {"name", "order", "rank", "lifecycle", "dlp_engines", "count"}})
    assert findings == [] and detail["zia_dlp_web_rules"]["unknown"] == []
    findings, _ = uc.check_terraform_schema(accepted, {"zia_dlp_web_rules": {"name", "bogus"}, "zia_gone": {"name"}})
    assert sorted(f["text"].split(":")[0] for f in findings) == ["zia_dlp_web_rules", "zia_gone"] and all(f["level"] == "drift" for f in findings)


# ── The daily job ────────────────────────────────────────────────────

def test_the_daily_workflow_runs_the_check_and_files_the_drift():
    wf = open(os.path.join(ROOT, ".github", "workflows", "upstream_check.yml"), encoding="utf-8").read()
    assert "schedule:" in wf and "cron:" in wf and "workflow_dispatch" in wf
    assert "python upstream_check.py --json upstream_report.json --md upstream_report.md" in wf
    assert "hashicorp/setup-terraform" in wf, "the provider schema needs the terraform binary"
    assert "pip install --require-hashes --no-deps -r requirements.lock" in wf, "checked against the SDK the app actually runs on"
    assert "upstream-drift" in wf and "issues: write" in wf and "upload-artifact" in wf
    ci = open(os.path.join(ROOT, ".github", "workflows", "tests.yml"), encoding="utf-8").read()
    assert "python upstream_check.py --offline" in ci
    mk = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
    assert "upstream_check.py --offline" in mk and "\nupstream:" in mk
    from zscaler_update_check import ALLOWED_HOSTS
    assert {"pypi.org", "registry.terraform.io", "raw.githubusercontent.com", "automate.zscaler.com"} <= ALLOWED_HOSTS


def test_a_prerelease_that_does_not_describe_a_resource_at_all_is_a_note_not_drift():
    # zscaler-sdk-python 2.0.0b2: its ZIA definition has no operation of any
    # kind on /casbDlpRules or /endPointDlpRules (an incomplete preview), while
    # the stable 1.x SDK the app runs still has both. Not something to act on.
    keys = uc.app_payload_keys()
    d = _defn(with_saas=False)
    del d["operations"]["CreateEndpointDlpRule"]
    findings, detail = uc.check_service_definition(d, keys, "sdk 2.0.0b2", prerelease=True)
    assert [f for f in findings if f["level"] == "drift"] == [], findings
    notes = [f["text"] for f in findings if f["level"] == "note"]
    assert any("/casbDlpRules" in t and "does not describe" in t for t in notes)
    assert any("/endPointDlpRules" in t for t in notes)
    assert detail["endpoints"]["saas"] == {"operation": None, "resource_described": False}
    # The same gap in a stable release is drift: the app could not move to it.
    findings, _ = uc.check_service_definition(d, keys, "sdk 2.0.0", prerelease=False)
    assert sum(f["level"] == "drift" for f in findings) == 2


def test_a_described_resource_without_its_create_operation_is_drift_even_in_a_prerelease():
    keys = uc.app_payload_keys()
    d = _defn(with_saas=False)
    d["operations"]["ListCasbDlpRules"] = {"http": {"method": "GET", "requestUri": "/zia/api/v1/casbDlpRules"}, "input": {"shape": "ListRequest"}}
    findings, detail = uc.check_service_definition(d, keys, "sdk 2.0.0b3", prerelease=True)
    drift = [f for f in findings if f["level"] == "drift"]
    assert len(drift) == 1 and "/casbDlpRules" in drift[0]["text"] and detail["endpoints"]["saas"]["resource_described"] is True
    # A field the app sends that a prerelease does not list is still drift.
    keys["engine"] = set(keys["engine"]) | {"engine_channels_x"}
    findings, _ = uc.check_service_definition(_defn(), keys, "sdk 2.0.0b3", prerelease=True)
    assert any("engineChannelsX" in f["text"] and f["level"] == "drift" for f in findings)


def test_the_prerelease_service_definition_is_checked_as_a_prerelease():
    src = open(uc.__file__, encoding="utf-8").read()
    assert 'check_service_definition(defn, keys, f"{SDK_PACKAGE} {pre}", prerelease=True)' in src
