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
    assert len(cat["products"]["ztc"]) == 11 and "zcc" in cat["products"]
    nc = " ".join(x["what"] for x in cat["not_covered"] if x["product"] == "ztc")
    assert "Account groups" not in nc and "DNS forwarding rules and log (control) rules" in nc and "Locations" in nc and "Cloud & Branch Connector groups" in nc
    _f, rep = tt.generate({"types": {}, "unread": {}}, tt.normalize_options(["ztc"]), generated_at="2026-11-07T00:00:00Z")
    assert any(x["product"] == "ztc" for x in rep["not_covered"])


def test_route_model_carries_the_new_options():
    """ASVS V5.1.3 · CWE-20: the start request accepts output_dir and support_log, off by default."""
    import dlp_api_server as s
    r = s.TenantTerraformRequest()
    assert r.output_dir == "" and r.support_log is False


# ── Cloud & Branch Connector: account groups, and what the API / SDK cannot give ──

ZTC_HOSTILE = 'Prod "AWS" ${var.x} %{ if true }'


def _ztc_snapshot():
    return {"types": {"ztc.account_groups": [{"id": 4851, "name": ZTC_HOSTILE, "description": HOSTILE, "cloud_type": "AWS",
                                              "public_cloud_accounts": [{"id": 4801, "name": "a"}],
                                              "cloud_connector_groups": [{"id": 4101, "name": "g"}]}]},
            "unread": {}, "log": []}


def test_ztc_account_groups_are_written_valid_escaped_and_imported():
    """ASVS V5.3.3 · CWE-94 · WSTG-INPV-11: an account group (name and description hostile) is written as ztc_account_groups, passes the module's own static check, its values are escaped and its import block is present."""
    files, rep = tt.generate(_ztc_snapshot(), tt.normalize_options(["ztc"]), tenant_label="T", generated_at="2026-11-07T00:00:00Z")
    assert rep["products"]["ztc"]["resources"] == {"ztc_account_groups": 1}
    text = "\n".join(ln for p, c in files.items() if p.endswith(".tf") for ln in c.split("\n") if not ln.lstrip().startswith("#"))
    assert 'resource "ztc_account_groups"' in text and "cloud_type" in text and "public_cloud_accounts" in text
    assert "${var.x}" not in text.replace("$${var.x}", "") and "%{ if true }" not in text.replace("%%{ if true }", "")
    assert 'resource "evil"' not in text.replace('\\"evil\\"', "")
    assert tt.validate_files(files)["ok"] is True
    imports = files[f"{tt.ROOT_DIR}/ztc/imports.tf"]
    assert "to = ztc_account_groups." in imports and 'id = "4851"' in imports


class _Ex:
    """A request executor that answers the documented account group path, and counts what it was asked."""

    def __init__(self):
        self.asked = []

    def create_request(self, method, path, body, headers, params=None):
        self.asked.append((method, path))
        return {"m": method, "p": path}, None

    def execute(self, req):
        class R:
            def get_body(self_inner):
                return [{"id": 7, "name": "G", "cloudType": "AWS", "publicCloudAccounts": [{"id": 1}], "cloudConnectorGroups": []}]
        return R(), None


class _Ztw:
    def __init__(self, ex):
        self._request_executor = ex

    @property
    def account_groups(self):
        raise AssertionError("the SDK's account group reader fails on the installed version and must not be called")


class _Client:
    def __init__(self):
        self.ex = _Ex()
        self.ztw = _Ztw(self.ex)


def test_ztc_account_groups_are_read_with_the_raw_get_not_the_broken_sdk_reader():
    """ASVS V13.2.1 · CWE-754 · WSTG-BUSL-01: the installed SDK's account group model cannot be built, so the type is read with GET /ztw/api/v1/accountGroups through the client's executor; only a GET is made."""
    c = _Client()
    snap = tt.read_tenant(c, ["ztc.account_groups"])
    assert c.ex.asked == [("GET", "/ztw/api/v1/accountGroups")] and snap["unread"] == {}
    row = snap["types"]["ztc.account_groups"][0]
    assert row["cloud_type"] == "AWS" and row["public_cloud_accounts"] == [{"id": 1}]
    from zscaler.ztw.models.account_groups import AccountGroups
    with pytest.raises(AttributeError):
        AccountGroups({"id": 1, "cloudConnectorGroups": [{"id": 2}]})


def test_ztc_types_without_a_provider_resource_or_read_api_say_so_exactly():
    """ASVS V1.14.1 · CWE-1059: Cloud & Branch Connector groups and locations (read-only API), DNS and log rules (no read API), multi-range IP pools and other forwarding methods (the provider's validator) are reported, never silently dropped."""
    nc = {x["what"]: x["why"] for x in tt.catalogue()["not_covered"] if x["product"] == "ztc"}
    assert "no read API" in nc["DNS forwarding rules and log (control) rules"] and "no module" in nc["DNS forwarding rules and log (control) rules"]
    assert "read-only" in nc["Locations"] and "read-only" in nc["Cloud & Branch Connector groups (ecgroup)"]
    snap = {"types": {"ztc.ip_pool_groups": [{"id": 3, "name": "Two", "ip_addresses": ["10.0.0.0/24", "10.0.1.0/24"]}],
                      "ztc.forwarding_rules": [{"id": 1, "name": "P", "order": 1, "type": "EC_RDR", "forward_method": "PROXYCHAIN"}]}}
    _f, rep = tt.generate(snap, tt.normalize_options(["ztc"]), tenant_label="T", generated_at="2026-11-07T00:00:00Z")
    why = {s["what"]: s["why"] for s in rep["products"]["ztc"]["skipped"]}
    assert "holds exactly one" in why["IP pool groups: Two"] and "PROXYCHAIN" in why["Traffic forwarding rules: P"]
