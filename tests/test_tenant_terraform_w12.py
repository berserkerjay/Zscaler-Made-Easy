"""Terraform export, wave 12: selecting resource types by key, provider
resource name or pattern; a local static check of the written files and a
validate script (nothing is run); a masked support log; the output folder
name; and hostile tenant names written safely."""
from __future__ import annotations

import json

import pytest

import tenant_terraform as tt

HOSTILE = 'x"; } resource "evil" "y" { a = "${file("/etc/passwd")}" %{ if true }\n# ‮'


def _snap():
    return {"types": {"zia.rule_labels": [{"id": 1, "name": HOSTILE, "description": HOSTILE},
                                          {"id": 2, "name": "Plain"}]},
            "unread": {}, "log": []}


def _gen(**kw):
    return tt.generate(_snap(), tt.normalize_options(["zia"], **kw), tenant_label="T", generated_at="2026-11-07T00:00:00Z")


def test_types_and_exclude_take_keys_resource_names_and_patterns():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a type is selected by key, provider resource name or pattern; an unknown one is refused by name."""
    o = tt.normalize_options(None, types=["zia_rule_labels", "zpa.segment_*"], exclude=["zia.*"])
    assert "zia.rule_labels" in o["types"] and "zpa.segment_groups" in o["types"]
    assert all(k.startswith("zia.") for k in o["exclude"]) and len(o["exclude"]) > 20
    assert tt.normalize_options(None, types=["zia.rule_labels", "zia_rule_labels"])["types"] == ["zia.rule_labels"]
    for bad in (["nope_*"], ["zia.rule_labels;ls"], ["../x"]):
        with pytest.raises(tt.ExportRefused):
            tt.normalize_options(None, types=bad)


def test_resource_name_selection_limits_what_is_planned():
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: selecting by resource name reads only that type, and still only inside the Scope page."""
    o = tt.normalize_options(["zia"], types=["zia_rule_labels"])
    p = tt.plan(["zia_extras"], {}, o)
    assert p["read"] == ["zia.rule_labels"]
    with pytest.raises(tt.ExportRefused):
        tt.plan([], {}, tt.normalize_options(["zpa"], types=["zpa_segment_group"]))


def test_hostile_names_are_escaped_in_hcl_and_the_static_check_passes():
    """ASVS V5.3.1 · CWE-94 · WSTG-INPV-11: quotes, template sequences, newlines and bidi marks in a tenant name cannot break out of the HCL string."""
    files, rep = _gen()
    tf = files["tenant-terraform/zia/objects.tf"]
    live = "\n".join(ln for ln in tf.splitlines() if not ln.lstrip().startswith("#"))   # a comment is one inert line
    assert "${file(" not in live.replace("$${file(", "") and "%{ if" not in live.replace("%%{ if", "")
    assert not any(ln.lstrip().startswith('resource "evil"') for ln in tf.splitlines())
    assert "‮" not in "".join(files.values())
    assert live.count('resource "') == 2
    assert rep["validation"]["ok"], rep["validation"]


def test_static_check_finds_a_broken_workspace():
    """ASVS V5.1.3 · CWE-1284: the local check reports unbalanced braces, a repeated address and an import without a resource."""
    bad = {"w/zia/a.tf": 'resource "zia_rule_labels" "a" {\n name = "x"\n',
           "w/zia/b.tf": 'resource "zia_rule_labels" "b" {\n}\nresource "zia_rule_labels" "b" {\n}\n'
                         'import {\n  to = zia_rule_labels.gone\n  id = "1"\n}\n'}
    v = tt.validate_files(bad)
    text = " ".join(v["problems"])
    assert not v["ok"] and "unbalanced" in text and "written twice" in text and "zia_rule_labels.gone" in text


def test_validate_script_is_written_but_nothing_is_run():
    """ASVS V10.2.1 · CWE-78: validate.sh is only text in the zip; it validates and never plans or applies."""
    files, _rep = _gen()
    sh = files["tenant-terraform/validate.sh"]
    commands = [ln for ln in sh.splitlines() if not ln.startswith("#")]
    assert "terraform validate" in sh and "-backend=false" in sh
    assert not any("terraform apply" in c or "terraform plan" in c for c in commands)
    assert json.loads(files["tenant-terraform/export_report.json"])["validation"]["ok"]


def test_output_folder_name_is_checked_and_used():
    """ASVS V12.3.1 · CWE-22 · WSTG-INPV-11: the output folder is a plain name; a path or traversal is refused."""
    files, _ = _gen(output_dir="acme-prod")
    assert all(p.startswith("acme-prod/") for p in files)
    for bad in ("../x", "a/b", "/etc", "A B", "x" * 41):
        with pytest.raises(tt.ExportRefused):
            tt.normalize_options(["zia"], output_dir=bad)
    assert tt.normalize_options(["zia"])["output_dir"] == tt.ROOT_DIR


def test_support_log_is_opt_in_and_masked():
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: the support log is off by default; when asked for it holds progress and counts and masks credentials."""
    snap = _snap()
    snap["log"] = ["Reading ZIA Rule labels…", "ZIA X: not read (401 Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789 password=hunter2hunter2)"]
    snap["unread"] = {"zia.locations": "token=CANARY-TOKEN-a9c1-aaaaaaaaaaaaaaaa"}
    off, _ = tt.generate(snap, tt.normalize_options(["zia"]), generated_at="2026-11-07T00:00:00Z")
    assert not any("support" in p for p in off)
    on, _ = tt.generate(snap, tt.normalize_options(["zia"], support_log=True), generated_at="2026-11-07T00:00:00Z")
    log = on["tenant-terraform/support/export_log.txt"]
    assert "Reading ZIA Rule labels" in log and "zia_rule_labels=2" in log
    for leak in ("abcdefghijklmnopqrstuvwxyz0123456789", "hunter2", "CANARY-TOKEN"):
        assert leak not in log
    assert "evil" not in log and "Plain" not in log


def test_read_tenant_keeps_a_bounded_progress_log():
    """ASVS V7.1.1 · CWE-779: read_tenant records progress lines in the snapshot for the support log, bounded."""
    import test_tenant_terraform as base
    t = tt.BY_KEY["zia.rule_labels"]
    snap = tt.read_tenant(base.store_for([t]), ["zia.rule_labels"])
    assert any("Rule labels" in m for m in snap["log"]) and len(snap["log"]) <= tt.MAX_LOG_LINES


def test_cloud_connector_unsupported_items_are_listed_not_hidden():
    """ASVS V1.14.1 · CWE-1059: Cloud & Branch Connector objects the provider cannot take are named in the not-covered list, and the Client Connector workspace is a separate product."""
    cat = tt.catalogue()
    assert len(cat["products"]["ztc"]) >= 10 and "zcc" in cat["products"]
    nc = " ".join(x["what"] for x in cat["not_covered"] if x["product"] == "ztc")
    assert "Account groups" in nc and "DNS / log forwarding rules" in nc
    _f, rep = tt.generate({"types": {}, "unread": {}}, tt.normalize_options(["ztc"]), generated_at="2026-11-07T00:00:00Z")
    assert any(x["product"] == "ztc" for x in rep["not_covered"])


def test_route_model_carries_the_new_options():
    """ASVS V5.1.3 · CWE-20: the start request accepts output_dir and support_log, off by default."""
    import dlp_api_server as s
    r = s.TenantTerraformRequest()
    assert r.output_dir == "" and r.support_log is False
