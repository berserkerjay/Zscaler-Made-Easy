"""
Terraform workspace generation for packs and baselines (official
zscaler/zia provider): resource shapes, reference rewriting, HCL escaping,
per-channel resources, dynamic AI_ML scope, and gap mode import blocks
derived from a preflight report.
"""
from __future__ import annotations

import json
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


def _sp(text: str) -> str:
    """Attribute lines with their fmt alignment collapsed to single spaces."""
    return re.sub(r"[ \t]+", " ", text)


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
    assert set(files) >= {"terraform.tf", "providers.tf", "variables.tf", "dictionaries.tf", "engines.tf", "rules.tf",
                          "activation.tf", "locals.tf", "outputs.tf", "README.md", ".gitignore", "terraform.tfvars.example"}
    assert "imports.tf" not in files and "versions.tf" not in files and "provider.tf" not in files, "the style guide's file names"
    v = files["terraform.tf"]
    assert 'source  = "zscaler/zia"' in v and 'version = "~> 4.8"' in v and 'required_version = ">= 1.5.0"' in v

    d = files["dictionaries.tf"]
    assert 'data "zia_dlp_dictionaries" "social_security_numbers_us"' in d and 'name = "Social Security Numbers (US)"' in d
    assert 'data "zia_dlp_dictionaries" "medical_information"' in d            # predefined referenced only by the engine
    assert 'resource "zia_dlp_dictionaries" "alpha_dict"' in d
    assert 'pattern = "\\\\bA\\\\d{3}\\\\b"' in d                              # regex backslashes doubled
    assert "proximity = 100" in _sp(d) and "proximity_enabled_for_custom_dictionary = true" in d
    assert 'dict_template_id = data.zia_dlp_dictionaries.social_security_numbers_us.id' in _sp(d)
    assert "[DLP-Check baseline tfpack v2.1] Terraform-managed." in d

    e = files["engines.tf"]
    assert ('engine_expression = "((D${zia_dlp_dictionaries.alpha_dict.id}.S > 0) OR '
            '(D${zia_dlp_dictionaries.ssn_clone.id}.S > 2) OR (D${data.zia_dlp_dictionaries.medical_information.id}.S > 0))"') in _sp(e)

    r = files["rules.tf"]
    assert 'resource "zia_dlp_web_rules" "web_monitor"' in r
    assert 'data "zia_cloud_applications" "apps_ai_ml"' in r and "app_class = [\"AI_ML\"]" in _sp(r)
    assert "cloud_applications = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))" in _sp(r)
    assert "# ocr_enabled = true" in r and "min_size = 10" in _sp(r)   # OCR is not in the 4.8.x schema
    assert "id = [zia_dlp_engines.alpha_engine.id]" in r
    assert 'resource "zia_endpoint_dlp_rules" "ep_monitor"' in r and "device_trust_levels" in r
    assert 'resource "zia_casb_dlp_rules" "saas_file"' in r and 'type = "OFLCASB_DLP_FILE"' in _sp(r)
    assert 'data "zia_casb_tenant" "acme_box"' in r and "id = [data.zia_casb_tenant.acme_box.tenant_id]" in r
    assert 'resource "zia_outbound_email_dlp" "email_monitor"' in r
    assert 'id = lookup(var.email_tenant_ids, "Email-Monitor", var.email_tenant_ids_default)' in r, "one map variable per channel, not one variable per rule"
    email = r.split('resource "zia_outbound_email_dlp"')[1]
    assert "rank" not in email.split("lifecycle")[0]        # email rules have no rank
    assert email.count("lifecycle {") == 1 and email.rstrip().endswith("}\n  }\n}") and 'error_message = "Rule Email-Monitor: set email_tenant_ids' in email, "one lifecycle block, last, with the plan-time check"
    vt = files["variables.tf"]
    assert 'variable "email_tenant_ids"' in vt and "type        = map(list(number))" in vt and 'variable "email_tenant_ids_default"' in vt
    assert 'variable "saas_tenant_ids"' not in vt, "the SaaS rule names its tenants, so no SaaS variable is needed"
    assert "nullable    = false" in vt and "validation {" in vt and "var.policy_rank >= 0 && var.policy_rank <= 7" in vt
    assert "saas_tenant_ids_email_monitor" not in vt and "saas_tenant_ids_email_monitor" not in files["terraform.tfvars.example"]
    assert "# email_tenant_ids_default = [123456]" in files["terraform.tfvars.example"]
    lc = files["locals.tf"]
    assert "zia_dlp_dictionaries.alpha_dict," in lc and "zia_dlp_engines.alpha_engine," in lc and "zia_dlp_web_rules.web_monitor," in lc
    o = files["outputs.tf"]
    assert o.count("description = ") == 3 and "{ for r in local.dictionaries : r.name => r.id }" in o and "[for r in local.rules : r.name]" in o
    readme = files["README.md"]
    for heading in ("## Requirements", "## Inputs", "## Outputs", "## State and the lock file", "## Verify and review", "## Renaming a resource"):
        assert heading in readme, heading
    assert "| `email_tenant_ids` | `map(list(number))` | `{}` |" in readme and "| `policy_rank` | `number` | `7` |" in readme
    assert "\ntfplan\n" in files[".gitignore"] and "terraform plan -out=tfplan" in readme, "the plan file the README saves is ignored"
    assert "*.tfplan" in files[".gitignore"] and "override.tf" in files[".gitignore"] and ".terraform.lock.hcl" not in files[".gitignore"].replace("Commit .terraform.lock.hcl", "")
    web = r.split('resource "zia_dlp_web_rules" "web_monitor"')[1].split("\nresource ")[0]
    assert web.index("dlp_engines {") < web.index("lifecycle {") and web.rstrip().endswith("}\n  }\n}"), "the cloud-app precondition sits in the one lifecycle block, last"

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
    assert "customized in the tenant: patterns" in imp
    assert "to = zia_dlp_engines.zbp_alpha_engine" in imp and 'id = "5100"' in imp
    assert "to = zia_dlp_web_rules.zbp_alpha_monitor" in imp and 'id = "7100"' in imp
    assert "zbp_new_dict" not in imp                                            # missing → created, not imported
    # An existing rule keeps its tenant order instead of the starting-order variable.
    assert "order = 3" in _sp(files["rules.tf"])
    assert "| 2 | 1 | 1 | 0 |" in files["README.md"]                            # in sync, customized, missing, blocked


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
    assert "zbp_enterprise_baseline/rules.tf" in names and "cjis_policy_pack/terraform.tf" in names and "cjis_policy_pack/locals.tf" in names


def test_the_generator_lays_out_hcl_the_way_terraform_fmt_does():
    """Runs of single-line attributes align their `=` on the longest key; a
    comment, a blank line, a nested block or a multi-line value ends the
    run and stands with single spaces, exactly as `terraform fmt` does
    (checked against the CLI on the shipped packs whenever it is present)."""
    src = ('resource "x" "a" {\n  name = "x"\n  description = "y"\n  # note\n  order = 1\n  without_content_inspection = false\n'
           '  dlp_engines {\n    id = [zia_dlp_engines.e.id]\n  }\n  cloud_applications = sort(distinct(concat(x)))\n  lifecycle {\n'
           '    precondition {\n      condition = length(x) > 0\n      error_message = "No apps ] ) }"\n    }\n  }\n\n  depends_on = [\n    zia_dlp_web_rules.a,\n  ]\n}\n')
    want = ('resource "x" "a" {\n  name        = "x"\n  description = "y"\n  # note\n  order                      = 1\n  without_content_inspection = false\n'
            '  dlp_engines {\n    id = [zia_dlp_engines.e.id]\n  }\n  cloud_applications = sort(distinct(concat(x)))\n  lifecycle {\n'
            '    precondition {\n      condition     = length(x) > 0\n      error_message = "No apps ] ) }"\n    }\n  }\n\n  depends_on = [\n    zia_dlp_web_rules.a,\n  ]\n}\n')
    assert pt.hcl_fmt(src) == want
    assert pt.hcl_fmt('  pattern = "\\\\d{4}"\n  p = 1\n') == '  pattern = "\\\\d{4}"\n  p       = 1\n', "brackets inside strings do not open a multi-line value"
    from dlp_importer import discover_packs
    for p in discover_packs():
        files = pt.generate({"id": p["id"], "dir": p["dir"]})
        for name, text in files.items():
            if name.endswith(".tf"):
                assert pt.hcl_fmt(text) == text, f"{p['id']}/{name} is not fmt-stable"
                assert not any(l != l.rstrip() for l in text.split("\n")), f"{p['id']}/{name} has trailing whitespace"


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")
def test_shipped_workspaces_pass_terraform_fmt_check():
    r = subprocess.run(["terraform", "fmt", "-check", "-recursive", "-list=true", "terraform"], cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       capture_output=True, text=True)
    assert r.returncode == 0, f"terraform fmt would change: {r.stdout}{r.stderr}"


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


def test_a_terraform_json_document_renders_as_the_same_workspace_layout_the_packs_get():
    """The vendor migration compiles to Terraform JSON (the machine-readable
    form its tests pin); the hand-off renders that JSON as the reviewable
    HCL workspace: versions, provider from env, variables with
    descriptions, resources by kind, outputs with descriptions, README,
    .gitignore, tfvars example, fmt-clean, and readable back into a pack by
    the library's Terraform reader."""
    import pack_library as pl
    tf = {"terraform": {"required_providers": {"zia": {"source": "zscaler/zia", "version": "4.8.8"}}}, "provider": {"zia": {}},
          "resource": {"zia_dlp_dictionaries": {"ctx": {"name": "CTX $${literal}", "description": "d %%{x}", "dictionary_type": "PATTERNS_AND_PHRASES",
                                                         "custom_phrase_match_type": "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                                                         "phrases": [{"phrase": "customer", "action": "PHRASE_COUNT_TYPE_ALL"}],
                                                         "patterns": [{"pattern": "acct[ -]?\\d{6}", "action": "PATTERN_COUNT_TYPE_UNIQUE"}]}},
                       "zia_dlp_engines": {"pci": {"name": "PCI", "description": "e", "engine_expression": "((D${zia_dlp_dictionaries.ctx.id}.S > 2))", "custom_dlp_engine": True}},
                       "zia_dlp_web_rules": {"sym_1": {"name": "PCI upload", "action": "BLOCK", "order": 1, "state": "DISABLED", "without_content_inspection": False,
                                                        "dlp_engines": [{"id": ["${zia_dlp_engines.pci.id}"]}], "protocols": ["HTTPS_RULE", "HTTP_RULE"]}},
                       "zia_outbound_email_dlp": {"sym_1_email": {"name": "PCI [Email]", "action": "BLOCK", "order": 1, "state": "DISABLED", "without_content_inspection": False,
                                                                   "dlp_engines": [{"id": ["${zia_dlp_engines.pci.id}"]}], "email_tenants": [{"id": "${var.email_tenant_ids_sym_1_email}"}]}}},
          "data": {"zia_casb_tenant": {"tenant_box": {"tenant_name": "Box"}}},
          "variable": {"email_tenant_ids_sym_1_email": {"type": "list(number)", "description": "IDs of the onboarded email tenants."},
                       "endpoint_dlp_user_confirmation_template_name": {"type": "string", "default": None, "description": "Template; null uses the default."}}}
    files = pt.render_json_workspace(tf, title="Symantec migration", source_note="Generated from a reviewed export.")
    assert set(files) == {"terraform.tf", "providers.tf", "variables.tf", "dictionaries.tf", "engines.tf", "rules.tf", "locals.tf", "outputs.tf", "terraform.tfvars.example", ".gitignore", "README.md"}
    assert 'version = "4.8.8"' in files["terraform.tf"] and 'required_version = ">= 1.5.0"' in files["terraform.tf"]
    assert "var.zscaler_client_secret" in files["providers.tf"] and 'variable "zscaler_client_secret"' in files["variables.tf"] and "sensitive   = true" in files["variables.tf"]
    v = files["variables.tf"]
    assert 'variable "email_tenant_ids_sym_1_email"' in v and "type        = list(number)" in v and "description = \"IDs of the onboarded email tenants.\"" in v
    assert 'variable "endpoint_dlp_user_confirmation_template_name"' in v and "default     = null" in v
    d = files["dictionaries.tf"]
    assert 'name                     = "CTX $${literal}"' in d and 'description              = "d %%{x}"' in d, "template escapes from the JSON are kept as they are"
    assert 'pattern = "acct[ -]?\\\\d{6}"' in d, "backslashes are escaped for HCL"
    assert "phrases {\n    phrase = \"customer\"" in d and "patterns {\n    pattern" in d
    e = files["engines.tf"]
    assert 'engine_expression = "((D${zia_dlp_dictionaries.ctx.id}.S > 2))"' in re.sub(r"[ \t]+", " ", e), "the interpolation stays live"
    r = files["rules.tf"]
    assert 'data "zia_casb_tenant" "tenant_box"' in r and r.index('data "zia_casb_tenant"') < r.index('resource "zia_dlp_web_rules"')
    assert "dlp_engines {\n    id = [zia_dlp_engines.pci.id]\n  }" in r and "email_tenants {\n    id = var.email_tenant_ids_sym_1_email\n  }" in r
    o = files["outputs.tf"]
    assert 'output "dictionaries"' in o and o.count("description = ") == 3 and "local.dictionaries" in o
    assert "zia_dlp_dictionaries.ctx," in files["locals.tf"] and "zia_outbound_email_dlp.sym_1_email," in files["locals.tf"]
    assert "email_tenant_ids_sym_1_email" in files["terraform.tfvars.example"] and "rule_starting_order" not in files["terraform.tfvars.example"]
    assert "*.tfstate" in files[".gitignore"] and "DISABLED" in files["README.md"] and ".terraform.lock.hcl" in files["README.md"]
    for name, text in files.items():
        if name.endswith(".tf"):
            assert pt.hcl_fmt(text) == text, name
    got, warnings = pl.pack_from_terraform({k: v for k, v in files.items() if k.endswith(".tf")})
    # The reader resolves the template escapes, so the pack carries the literal text the JSON meant.
    assert [x["name"] for x in got["dictionaries"]] == ["CTX ${literal}"] and got["engines"][0]["expression"] == "((D:CTX ${literal} > 2))"
    assert {p["name"] for p in got["policies"]} == {"PCI upload", "PCI [Email]"} and all(p["engines"] == ["PCI"] for p in got["policies"])


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")
def test_the_rendered_vendor_workspace_passes_terraform_fmt_check(tmp_path):
    import json
    import vendor_migrate as vm
    from test_vendor_migrate import RICH, _multi_decisions
    snap = vm.inventory_bytes(RICH)
    tf, report = vm.compile_export(snap, _multi_decisions(snap), prefix="sym", vendor_id="symantec")
    assert report["ready"]
    pt.write_workspace(pt.render_json_workspace(tf, title="Symantec migration", source_note="test"), str(tmp_path))
    (tmp_path / "main.tf.json.bak").write_text(json.dumps(tf))   # not read by terraform: .bak
    r = subprocess.run(["terraform", "fmt", "-check", "-recursive", "-list=true", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_every_generated_file_says_what_generated_it_and_ci_enforces_fmt_and_staleness():
    from dlp_importer import discover_packs
    p = next(x for x in discover_packs() if x["id"] == "fed_policy_pack")
    files = pt.generate({"id": p["id"], "dir": p["dir"]})
    for name, text in files.items():
        if name.endswith(".tf"):
            assert text.startswith("# Generated by DLP-Check from pack fed_policy_pack v"), name
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ci = open(os.path.join(root, ".github", "workflows", "tests.yml"), encoding="utf-8").read()
    assert 'git status --porcelain -- terraform' in ci, "a file the generator starts or stops emitting is caught"
    assert "terraform fmt -check -recursive" in ci and "tools/terraform_samples.py" in ci
    assert "/tmp/tf_samples/vendor_hcl/ /tmp/tf_samples/vendor_json/ /tmp/tf_samples/containment/ /tmp/tf_samples/endpoint/" in ci, "the vendor output and the containment rules are validated too"
    mk = open(os.path.join(root, "Makefile"), encoding="utf-8").read()
    assert "git status --porcelain -- terraform" in mk and "terraform fmt -check" in mk
    # write_workspace removes only files this generator wrote and no longer emits; the team's own files and state stay.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        old = {"versions.tf": 'terraform {\n  required_providers {\n    zia = {\n      source  = "zscaler/zia"\n    }\n  }\n  # Remote state (recommended for shared use). Uncomment\n}\n',
               "provider.tf": '# Credentials come from variables (see terraform.tfvars.example) or, when the\nprovider "zia" {}\n',
               "stale_generated.tf": "# Generated by DLP-Check from pack x v1 for zscaler/zia ~> 4.8.\n\nlocals {}\n"}
        mine = {"backend.tf": 'terraform {\n  backend "s3" {}\n}\n', "labels.tf": "# our own rule labels\n", "terraform.tfvars": "policy_rank = 7\n",
                "terraform.tfstate": "{}", ".terraform.lock.hcl": "x", "override.tf": 'provider "zia" {}\n'}
        for name, text in {**old, **mine}.items():
            open(os.path.join(d, name), "w").write(text)
        pt.write_workspace(files, d)
        assert not any(os.path.exists(os.path.join(d, n)) for n in old), "earlier generated files are gone"
        assert all(open(os.path.join(d, n)).read() == t for n, t in mine.items()), "the team's own files, tfvars, state and lock stay untouched"
        # A blocked compile removes what the generator wrote, and nothing else.
        pt.remove_generated(d, names=("README.md", ".gitignore", "terraform.tfvars.example"))
        left = set(os.listdir(d))
        assert left == set(mine), left
    # Engine descriptions stay within ZIA's 255 characters, like dictionaries.
    from dlp_importer import ENGINE_DESCRIPTION_MAX
    for m in re.finditer(r'resource "zia_dlp_engines"[^{]*\{\n(?:.*\n)*?\s*description\s*=\s*"((?:[^"\\]|\\.)*)"', files["engines.tf"]):
        assert len(m.group(1).encode().decode("unicode_escape")) <= ENGINE_DESCRIPTION_MAX


def test_a_long_engine_description_is_clamped_to_what_zia_accepts(tmp_path):
    from dlp_importer import ENGINE_DESCRIPTION_MAX
    long_text = "Detects protected health information in clinical notes \u2014 " * 12
    pack = write_pack(tmp_path, "clamp", dicts=[_dict("Alpha Dict")],
                      engines=[dict(_engine("Alpha Engine", "(D:Alpha Dict)"), description=long_text)],
                      policies=[_policy("Web-Monitor", ["Alpha Engine"])], meta=BASELINE_META)
    engines = pt.generate(pack)["engines.tf"]
    m = re.search(r'resource "zia_dlp_engines" "alpha_engine" \{\n(?:.*\n)*?\s*description\s*=\s*"((?:[^"\\]|\\.)*)"', engines)
    assert m, engines
    text = json.loads('"' + m.group(1) + '"')
    assert len(long_text.encode()) > ENGINE_DESCRIPTION_MAX >= len(text.encode()), len(text.encode())
    assert "[DLP-Check" in text, "the provenance tag survives the clamp"


def test_the_committed_lock_files_cover_windows_mac_and_linux():
    # A lock file with one platform's h1 checksum makes terraform init refuse
    # the provider on every other platform, so each lock records the four
    # platforms the README names, plus the release's zh checksums.
    from dlp_importer import discover_packs
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for p in discover_packs():
        lock = open(os.path.join(root, "terraform", p["id"], ".terraform.lock.hcl")).read()
        assert 'constraints = "~> 4.8"' in lock, p["id"]
        assert lock.count('"h1:') >= 4 and lock.count('"zh:') >= 4, p["id"]


def test_a_whole_interpolation_is_unwrapped_even_when_a_quoted_string_holds_braces():
    assert pt._whole_interpolation('${lookup(var.m, "PCI mail {EU}", var.d)}') == 'lookup(var.m, "PCI mail {EU}", var.d)'
    assert pt._whole_interpolation('${lookup(var.m, "a \\"}\\" b", var.d)}') == 'lookup(var.m, "a \\"}\\" b", var.d)'
    assert pt._whole_interpolation('${a.b}-${c.d}') is None and pt._whole_interpolation('x ${a}') is None
    assert pt._whole_interpolation('${length(lookup(var.m, "x}", []))} > 0') is None
    tf = {"resource": {"zia_outbound_email_dlp": {"r": {"name": "PCI mail {EU}", "email_tenants": [{"id": '${lookup(var.email_tenant_ids, "PCI mail {EU}", var.email_tenant_ids_default)}'}]}}},
          "variable": {"email_tenant_ids": {"type": "map(list(number))", "default": {}}, "email_tenant_ids_default": {"type": "list(number)", "default": []}}}
    files = pt.render_json_workspace(tf, title="t", source_note="n")
    assert 'id = lookup(var.email_tenant_ids, "PCI mail {EU}", var.email_tenant_ids_default)' in files["rules.tf"]
    assert "\\\"" not in files["rules.tf"], "no backslash-escaped quote inside an expression"


def test_the_provenance_header_is_one_line_whatever_the_pack_metadata_says(tmp_path):
    pack = write_pack(tmp_path, "hdr", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
                      policies=[_policy("Web-Monitor", ["Alpha Engine"])], meta={"name": "H", "version": "1.0\nresource \"x\" \"y\" {}", "confidence_tweaks": []})
    files = pt.generate(pack)
    for name, text in files.items():
        if name.endswith(".tf"):
            first, rest = text.split("\n", 1)
            assert first.startswith("# Generated by DLP-Check") and 'resource "x"' in first and not rest.startswith('resource "x"'), name
