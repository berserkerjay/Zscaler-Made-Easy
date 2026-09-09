"""
Terraform workspace generation for packs and baselines (official
zscaler/zia provider): resource shapes, reference rewriting, HCL escaping,
per-channel resources, dynamic AI_ML scope, and gap mode import blocks
derived from a preflight report.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

import pack_deploy as pd
import pack_terraform as pt
from test_baselines import BASELINE_META, in_sync_client, tenant_dict, tenant_engine, tenant_rule  # noqa: F401
from test_pack_channels import make_client, tenant as casb_tenant  # noqa: F401
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _clone, _dict, _engine, _policy, write_pack  # noqa: F401


def test_hcl_string_escaping():
    assert pt.hcl_str(r"\bZ\d{4}\b") == r'"\\bZ\\d{4}\\b"'
    assert pt.hcl_str('say "hi" ${x} %{y}') == r'"say \"hi\" $${x} %%{y}"'
    assert pt.hcl_str("D${zia_dlp_dictionaries.a.id}.S > 0", interpolate=True) == '"D${zia_dlp_dictionaries.a.id}.S > 0"'


def test_reference_regex_handles_parentheses_in_names():
    expr = "((D:Social Security Numbers (US) > 4) OR (D:Alpha Dict > 0)) AND (D:Beta OR D:Gamma)"
    assert [m.group(1) for m in pt._REF_RE.finditer(expr)] == [
        "Social Security Numbers (US)", "Alpha Dict", "Beta", "Gamma"]


def test_static_workspace_shapes(tmp_path):
    pack = write_pack(
        tmp_path, "tfpack",
        dicts=[_dict("Alpha Dict", pattern=r"\bA\d{3}\b", proximity=100), _clone("SSN Clone")],
        engines=[_engine("Alpha Engine", "((D:Alpha Dict > 0) OR (D:SSN Clone > 2) OR (D:Medical Information > 0))")],
        policies=[dict(_policy("Web-Monitor", ["Alpha Engine"]), cloud_app_classes=["AI_ML"], ocr_enabled=True, min_size=10),
                  dict(_policy("EP-Monitor", ["Alpha Engine"]), channel="endpoint"),
                  dict(_policy("SaaS-File", ["Alpha Engine"], action="OFLCASB_DLP_REPORT_INCIDENT"), channel="saas",
                       saas_type="OFLCASB_DLP_FILE", tenants=["Acme Box"]),
                  dict(_policy("Email-Monitor", ["Alpha Engine"]), channel="email")],
        meta=BASELINE_META,
    )
    files = pt.generate(pack)
    assert set(files) >= {"versions.tf", "provider.tf", "variables.tf", "dictionaries.tf", "engines.tf", "rules.tf",
                          "activation.tf", "outputs.tf", "README.md", ".gitignore", "terraform.tfvars.example"}
    assert "imports.tf" not in files
    v = files["versions.tf"]
    assert 'source  = "zscaler/zia"' in v and 'version = "~> 4.8"' in v and 'required_version = ">= 1.5.0"' in v

    d = files["dictionaries.tf"]
    assert 'data "zia_dlp_dictionaries" "social_security_numbers_us"' in d and 'name = "Social Security Numbers (US)"' in d
    assert 'data "zia_dlp_dictionaries" "medical_information"' in d            # predefined referenced only by the engine
    assert 'resource "zia_dlp_dictionaries" "alpha_dict"' in d
    assert 'pattern = "\\\\bA\\\\d{3}\\\\b"' in d                              # regex backslashes doubled
    assert "proximity                    = 100" in d and "proximity_enabled_for_custom_dictionary = true" in d
    assert 'dict_template_id             = data.zia_dlp_dictionaries.social_security_numbers_us.id' in d
    assert "[DLP-Check baseline tfpack v2.1] Terraform-managed." in d

    e = files["engines.tf"]
    assert ('engine_expression            = "((D${zia_dlp_dictionaries.alpha_dict.id}.S > 0) OR '
            '(D${zia_dlp_dictionaries.ssn_clone.id}.S > 2) OR (D${data.zia_dlp_dictionaries.medical_information.id}.S > 0))"') in e

    r = files["rules.tf"]
    assert 'resource "zia_dlp_web_rules" "web_monitor"' in r
    assert 'data "zia_cloud_applications" "apps_ai_ml"' in r and "app_class   = [\"AI_ML\"]" in r
    assert "cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))" in r
    assert "# ocr_enabled = true" in r and "min_size                     = 10" in r   # OCR is not in the 4.8.x schema
    assert "id = [zia_dlp_engines.alpha_engine.id]" in r
    assert 'resource "zia_endpoint_dlp_rules" "ep_monitor"' in r and "device_trust_levels" in r
    assert 'resource "zia_casb_dlp_rules" "saas_file"' in r and 'type                         = "OFLCASB_DLP_FILE"' in r
    assert 'data "zia_casb_tenant" "acme_box"' in r and "id = [data.zia_casb_tenant.acme_box.tenant_id]" in r
    assert 'resource "zia_outbound_email_dlp" "email_monitor"' in r and "id = var.saas_tenant_ids_email_monitor" in r
    assert "rank" not in r.split('resource "zia_outbound_email_dlp"')[1]        # email rules have no rank
    assert 'variable "saas_tenant_ids_email_monitor"' in files["variables.tf"]

    a = files["activation.tf"]
    assert 'resource "zia_activation_status" "this"' in a and "zia_dlp_web_rules.web_monitor," in a


def test_gap_mode_imports_existing_objects(tmp_path):
    pack = write_pack(
        tmp_path, "alpha_baseline",
        dicts=[_dict("ZBP-Alpha Dict", pattern=r"\bZ\d{4}\b"), _dict("ZBP-New Dict")],
        engines=[_engine("ZBP-Alpha Engine", "(D:ZBP-Alpha Dict)")],
        policies=[_policy("ZBP-Alpha-Monitor", ["ZBP-Alpha Engine"])],
        meta=BASELINE_META,
    )
    client = FakeClient(dicts=[PREDEF_SSN, tenant_dict(pattern=r"\bTAMPERED\b")], engines=[tenant_engine()],
                        rules=[tenant_rule(order=3)])
    rep = pd.public_report(pd.preflight(client, [pack], writes_enabled=True))
    rep["tenant_label"] = "acme (production)"
    files = pt.generate(pack, report=pt.split_report(rep, "alpha_baseline"))
    imp = files["imports.tf"]
    assert "to = zia_dlp_dictionaries.zbp_alpha_dict" in imp and 'id = "4100"' in imp
    assert "drifted: patterns" in imp
    assert "to = zia_dlp_engines.zbp_alpha_engine" in imp and 'id = "5100"' in imp
    assert "to = zia_dlp_web_rules.zbp_alpha_monitor" in imp and 'id = "7100"' in imp
    assert "zbp_new_dict" not in imp                                            # missing → created, not imported
    # An existing rule keeps its tenant order instead of the starting-order variable.
    assert "order                        = 3" in files["rules.tf"]
    assert "| 2 | 1 | 1 | 0 |" in files["README.md"]                            # in sync, drifted, missing, blocked


def test_saas_import_id_uses_rule_type(tmp_path):
    saas = dict(_policy("SaaS-File", ["Alpha Engine"], action="OFLCASB_DLP_REPORT_INCIDENT"), channel="saas", saas_type="OFLCASB_DLP_FILE")
    pack = write_pack(tmp_path / "s", "saaspack", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
                      policies=[saas], meta={"name": "S", "confidence_tweaks": []})
    existing = Obj(id=8501, name="SaaS-File", order=1, rank=7, action="OFLCASB_DLP_REPORT_INCIDENT", state="ENABLED",
                   dlp_engines=[], type="OFLCASB_DLP_FILE")
    client = make_client(casb_tenants=[casb_tenant("Acme Box", "BOX", 501)], saas_rules=[existing])
    rep = pd.public_report(pd.preflight(client, [pack], writes_enabled=True))
    files = pt.generate(pack, report=pt.split_report(rep, "saaspack"))
    assert 'id = "OFLCASB_DLP_FILE:8501"' in files["imports.tf"]
    # Tenants resolved by preflight become data lookups by name.
    assert 'data "zia_casb_tenant" "acme_box"' in files["rules.tf"]


def test_shipped_packs_generate_and_zip():
    from dlp_importer import discover_packs
    ws = {}
    for p in discover_packs():
        ws[p["id"]] = pt.generate({"id": p["id"], "dir": p["dir"]})
        assert "$${zia_dlp" not in ws[p["id"]]["engines.tf"], p["id"]      # interpolations must stay live
    data = pt.zip_workspaces(ws)
    import io, zipfile
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert "zbp_enterprise_baseline/rules.tf" in names and "cjis_policy_pack/versions.tf" in names


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")
def test_generated_workspaces_validate(tmp_path):
    """Runs only where terraform is available (CI installs it)."""
    from dlp_importer import discover_packs
    for p in discover_packs():
        out = tmp_path / p["id"]
        pt.write_workspace(pt.generate({"id": p["id"], "dir": p["dir"]}), str(out))
        for cmd in (["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                    ["terraform", "validate", "-no-color"]):
            r = subprocess.run(cmd, cwd=out, capture_output=True, text=True)
            assert r.returncode == 0, f"{p['id']}: {' '.join(cmd)}\n{r.stdout}\n{r.stderr}"
