"""Terraform providers and namespaces (wave 9):

* the Client Connector provider zscaler/zcc has published pre-releases only
  (0.1.2-beta.3 the newest), and Terraform selects a pre-release only by an
  exact constraint, so the whole-tenant export pins it exactly and labels
  the workspace beta; the provider signs in with ZIdentity OneAPI only, so
  the zcc workspace is skipped, with the reason, for a classic ZIA sign-in
  and on the zscalergov and zscalerten clouds;
* the provider's fail-open policy, device cleanup and web privacy settings
  are exported (the SDK reads them), and so are notification templates and
  ZIA posture profiles (read raw at the provider's v2 paths: the SDK has no
  call for them); every zcc argument written is one the provider's
  0.1.2-beta.3 schema declares;
* the CI sample export holds a workspace for every product and CI
  validates each one, as a blocking step;
* policy packs take the same private-registry namespace option as the
  whole-tenant export.

Offline: fixture tenants (offline_tenant) only; no registry, tenant or network."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import offline_tenant as ot
import pack_terraform as pt
import tenant_terraform as tt

ROOT = Path(__file__).resolve().parents[1]
ZCC = "/zcc/papi/public/v1"


def _settings_store(extra=None):
    responses = {f"{ZCC}/webFailOpenPolicy/listByCompany": {"status": 200, "body": [
                     {"id": 41, "active": "1", "enableFailOpen": 0, "enableStrictEnforcementPrompt": 1, "strictEnforcementPromptMessage": "Call IT",
                      "tunnelFailureRetryCount": 25, "enableCaptivePortalDetection": 1, "captivePortalWebSecDisableMinutes": 10}]},
                 f"{ZCC}/getDeviceCleanupInfo": {"status": 200, "body": {"id": 3, "active": "1", "forceRemoveType": "0", "deviceExceedLimit": 16,
                                                                          "autoRemovalDays": 30, "autoPurgeDays": 60}},
                 f"{ZCC}/getWebPrivacyInfo": {"status": 200, "body": {"id": 9, "active": "1", "collectUserInfo": "1", "collectMachineHostname": "0",
                                                                       "enablePacketCapture": "0", "enforceSecurePacUrls": True}}}
    responses.update(extra or {})
    st = ot.OfflineStore("snap-" + "9" * 16, "snapshot", responses, {"tenant_label": "ZCC settings"})
    return ot.OfflineSdkClient(st, ot.creds_for(st))


def _block(files, resource):
    text = "\n".join(c for p, c in files.items() if p.endswith(".tf"))
    m = re.search(r'resource "%s" "[a-z0-9_]+" \{\n(.*?)\n\}\n' % re.escape(resource), text, re.S)
    assert m, f"no {resource}"
    return re.sub(r" +=", " =", m.group(1))


def test_the_zcc_provider_is_pinned_exactly_to_its_beta_and_labelled_beta():
    """ASVS V14.2.1 · V10.3.2 · CWE-1104 · CWE-1357: the zcc workspace pins zscaler/zcc exactly to 0.1.2-beta.3 (a `~>` constraint selects no pre-release), and its terraform.tf, README and the catalogue say it is a beta."""
    # Arrange
    client = _settings_store()
    keys = ["zcc.failopen_policy"]
    # Act
    snap = tt.read_tenant(client, keys)
    files, _rep = tt.generate(snap, tt.normalize_options(["zcc"]), tenant_label="Fixture", generated_at="2026-10-31T00:00:00Z")
    tf = files[f"{tt.ROOT_DIR}/zcc/terraform.tf"]
    readme = files[f"{tt.ROOT_DIR}/zcc/README.md"]
    cat = tt.catalogue()
    # Assert
    assert re.search(r'source  = "zscaler/zcc"\n      version = "0\.1\.2-beta\.3"\n', tf), tf
    assert "~>" not in tf.split("required_providers", 1)[1].split("}", 2)[0]
    assert "pinned exactly" in tf and "(beta provider)" in readme and "OneAPI" in readme and "zscalerten" in readme
    assert cat["providers"]["zcc"] == {"source": "zscaler/zcc", "version": "0.1.2-beta.3", "beta": True}
    assert not cat["providers"]["zia"]["beta"] and "beta" in cat["beta_note"]["zcc"]


def test_the_zcc_settings_are_read_through_the_sdk_and_written_as_the_providers_resources():
    """ASVS V5.1.3 · V5.3.1 · CWE-20 · CWE-116: the fail-open policy (a one-record list), device cleanup and web privacy are read with the SDK's calls and written as zcc_failopen_policy, zcc_device_cleanup and zcc_web_privacy; the API's 0 / 1 switches become true / false; each has an import block."""
    # Arrange
    client = _settings_store()
    keys = ["zcc.failopen_policy", "zcc.device_cleanup", "zcc.web_privacy"]
    # Act
    snap = tt.read_tenant(client, keys)
    files, rep = tt.generate(snap, tt.normalize_options(["zcc"]), tenant_label="Fixture", generated_at="2026-10-31T00:00:00Z")
    # Assert
    assert not snap["unread"], snap["unread"]
    fo, dc, wp = _block(files, "zcc_failopen_policy"), _block(files, "zcc_device_cleanup"), _block(files, "zcc_web_privacy")
    assert "active = true" in fo and "enable_fail_open = false" in fo and "enable_strict_enforcement_prompt = true" in fo
    assert 'strict_enforcement_prompt_message = "Call IT"' in fo and "tunnel_failure_retry_count = 25" in fo
    assert "active = true" in dc and 'force_remove_type = "0"' in dc and "auto_removal_days = 30" in dc and "auto_purge_days = 60" in dc
    assert "collect_user_info = true" in wp and "collect_machine_hostname = false" in wp and "enforce_secure_pac_urls = true" in wp
    imports = files[f"{tt.ROOT_DIR}/zcc/imports.tf"]
    assert 'to = zcc_failopen_policy.failopen_policy\n  id = "41"' in imports, "fail-open is imported by its own id"
    assert 'to = zcc_device_cleanup.device_cleanup\n  id = "device_cleanup"' in imports
    assert 'to = zcc_web_privacy.web_privacy\n  id = "web_privacy"' in imports


# The configurable attributes of each zcc resource in the provider's 0.1.2-beta.3 source
# (internal/framework/resources/<name>.go, Schema(); version/version.go ProviderVersion
# "0.1.2-beta.3"), transcribed: computed-only `id` left out. Nested attributes as name -> {..}.
PROVIDER_ZCC = {
    "zcc_failopen_policy": {"active", "captive_portal_web_sec_disable_minutes", "enable_captive_portal_detection", "enable_fail_open",
                            "enable_strict_enforcement_prompt", "enable_web_sec_on_proxy_unreachable", "enable_web_sec_on_tunnel_failure",
                            "strict_enforcement_prompt_delay_minutes", "strict_enforcement_prompt_message", "tunnel_failure_retry_count"},
    "zcc_device_cleanup": {"active", "force_remove_type", "device_exceed_limit", "auto_removal_days", "auto_purge_days"},
    "zcc_web_privacy": {"active", "collect_user_info", "collect_machine_hostname", "collect_zdx_location", "enable_packet_capture",
                        "disable_crashlytics", "override_t2_protocol_setting", "restrict_remote_packet_capture",
                        "grant_access_to_zscaler_log_folder", "export_logs_for_non_admin", "enable_auto_log_snippet", "enforce_secure_pac_urls",
                        "enable_fqdn_match_for_vpn_bypasses"},
    "zcc_notification_template": {"name", "is_default_template", "enable_client", "enable_zia", "enable_app_updates", "enable_service_status",
                                  "duration_in_seconds", "enable_persistent", "enable_do_not_disturb",
                                  ("zia_notification_template", frozenset({"enable_zia_firewall", "enable_zia_firewall_popup", "enable_zia_dns",
                                                                           "enable_zia_dns_popup", "enable_zia_ips", "enable_zia_ips_popup",
                                                                           "enable_zia_persistent"})),
                                  ("zpa_notification_template", frozenset({"enable_device_posture_failure", "enable_zpa_reauth",
                                                                           "zpa_reauth_interval_in_minutes", "delay_posture_failure_seconds"}))},
    "zcc_zia_posture": {"name", "platform"} | {(f"{tier}_trust_criteria", "cs.cn", frozenset({"id", "name", "udid"}))
                                               for tier in ("high", "medium", "low")},
}


def _schema_shape(resource):
    out = set()
    for name, kind, _req, sub in tt.schema_of(resource):
        if kind == "obj" and len(sub) == 1 and sub[0][1] == "objs" and sub[0][3] and sub[0][3][0][1] == "objs":
            cn = sub[0][3][0]
            out.add((name, f"{sub[0][0]}.{cn[0]}", frozenset(a for a, *_ in cn[3])))
        elif kind == "obj":
            out.add((name, frozenset(a for a, *_ in sub)))
        else:
            out.add(name)
    return out


@pytest.mark.parametrize("resource", sorted(PROVIDER_ZCC))
def test_every_zcc_argument_written_is_one_the_pinned_provider_declares(resource):
    """ASVS V14.2.1 · V5.3.1 · CWE-1059 · CWE-20: fail-open, device cleanup, web privacy, notification templates and ZIA posture write exactly the configurable attributes the provider 0.1.2-beta.3 declares (nested attributes included), and the required ones are marked required."""
    # Act
    shape = _schema_shape(resource)
    required = {n for n, _k, req, _s in tt.schema_of(resource) if req}
    # Assert
    assert shape == PROVIDER_ZCC[resource]
    assert required == ({"name"} if resource == "zcc_notification_template" else {"name", "platform"} if resource == "zcc_zia_posture" else set())


def test_a_oneapi_sample_tenant_exports_notification_templates_and_zia_posture_with_the_settings():
    """ASVS V5.3.1 · V14.2.1 · CWE-116 · CWE-1357: the sample tenant (OneAPI) exports zcc_notification_template and zcc_zia_posture (read at the provider's v2 paths) beside fail-open, device cleanup and web privacy, in the provider's nested-attribute form, each with an import block, under a provider pinned exactly to 0.1.2-beta.3."""
    # Arrange
    st = ot.sample_store(reset=True)
    client = ot.OfflineSdkClient(st, ot.creds_for(st))
    keys = ["zcc.failopen_policy", "zcc.device_cleanup", "zcc.web_privacy", "zcc.notification_templates", "zcc.zia_posture"]
    # Act
    snap = tt.read_tenant(client, keys)
    files, rep = tt.generate(snap, tt.normalize_options(["zcc"]), tenant_label="Larkspur", generated_at="2026-11-01T00:00:00Z")
    # Assert
    assert not snap["unread"], snap["unread"]
    assert set(rep["products"]["zcc"]["resources"]) == {"zcc_failopen_policy", "zcc_device_cleanup", "zcc_web_privacy",
                                                         "zcc_notification_template", "zcc_zia_posture"}
    nt, zp = _block(files, "zcc_notification_template"), _block(files, "zcc_zia_posture")
    assert 'name = "Larkspur default"' in nt and "is_default_template = true" in nt and "duration_in_seconds = 8" in nt
    assert "zia_notification_template = {\n    enable_zia_firewall = true" in nt and "zpa_reauth_interval_in_minutes = 60" in nt
    assert 'platform = "windows"' in zp and "high_trust_criteria = {\n    cs = [\n      {\n        cn = [\n          {\n            id = \"1\"" in zp
    assert "low_trust_criteria" not in zp, "an empty tier is left to the provider"
    imports = files[f"{tt.ROOT_DIR}/zcc/imports.tf"]
    assert 'to = zcc_notification_template.larkspur_default\n  id = "71"' in imports
    assert 'to = zcc_zia_posture.larkspur_laptops_windows\n  id = "81"' in imports
    assert re.search(r'source  = "zscaler/zcc"\n      version = "0\.1\.2-beta\.3"\n', files[f"{tt.ROOT_DIR}/zcc/terraform.tf"])
    assert {"/zcc/papi/public/v2/notification-templates", "/zcc/papi/public/v2/zia-posture-profiles"} == set(tt.ZCC_RAW_PATHS.values())


def test_a_tenant_string_in_a_notification_template_or_posture_profile_is_escaped():
    """ASVS V5.3.1 · CWE-94 · CWE-116 · WSTG-INPV-11: a template or criterion name carrying a quote, a newline and an interpolation stays one escaped HCL string."""
    # Arrange
    evil = 'x"\n} resource "null" "y" { ${file("/etc/passwd")}'
    client = _settings_store({"/zcc/papi/public/v2/notification-templates": {"status": 200, "body": [{"id": 5, "name": evil}]},
                              "/zcc/papi/public/v2/zia-posture-profiles": {"status": 200, "body": [
                                  {"id": 6, "name": "p", "platform": "2", "highTrustCriteria": {"cs": [{"cn": [{"id": 9, "name": evil}]}]}}]}})
    # Act
    snap = tt.read_tenant(client, ["zcc.notification_templates", "zcc.zia_posture"])
    files, _rep = tt.generate(snap, tt.normalize_options(["zcc"]), tenant_label="Fixture", generated_at="2026-11-01T00:00:00Z")
    text = files[f"{tt.ROOT_DIR}/zcc/client_connector.tf"]
    # Assert
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r'^\s*resource "null"', code, re.M) and not re.search(r"(?<!\$)\$\{file", code) and code.count("$${file") == 2
    assert code.count('resource "') == 2 and 'platform = "android"' in re.sub(r" +=", " =", code) and 'id   = "9"' in code


def test_a_posture_profile_on_an_unknown_platform_is_not_exported_and_a_missing_read_is_named():
    """ASVS V1.14.6 · CWE-20 · CWE-1059: a posture profile whose platform is not 1..5 is listed as not exported (never written with a guess); a snapshot without the v2 answers names the type as not read."""
    # Arrange
    client = _settings_store({"/zcc/papi/public/v2/zia-posture-profiles": {"status": 200, "body": [{"id": 6, "name": "odd", "platform": 9}]}})
    # Act
    snap = tt.read_tenant(client, ["zcc.zia_posture", "zcc.notification_templates"])
    files, rep = tt.generate(snap, tt.normalize_options(["zcc"]), tenant_label="Fixture", generated_at="2026-11-01T00:00:00Z")
    # Assert
    assert "zcc.notification_templates" in snap["unread"]
    assert not any('resource "zcc_zia_posture"' in c for c in files.values())
    skipped = rep["products"]["zcc"]["skipped"]
    assert any("odd" in x["what"] and "platform" in x["why"] for x in skipped), skipped


@pytest.mark.parametrize("creds,why", [
    ({"auth_method": "legacy", "cloud": "zscaler"}, "classic ZIA sign-in"),
    ({"auth_method": "oneapi", "cloud": "zscalergov"}, "zscalergov"),
    ({"auth_method": "oneapi", "cloud": "zscalergovus"}, "zscalergovus"),
    ({"auth_method": "oneapi", "cloud": "zscalerten"}, "zscalerten"),
    ({"auth_method": "oneapi", "cloud": "production"}, None),
    ({"auth_method": "oneapi", "cloud": ""}, None),
])
def test_the_zcc_workspace_is_unavailable_without_oneapi(creds, why):
    """ASVS V1.14.6 · CWE-440 · CWE-1059: the Client Connector provider needs a ZIdentity OneAPI client, so a classic sign-in and the zscalergov / zscalerten clouds get a plain reason; other OneAPI tenants get none."""
    # Act
    got = tt.zcc_unavailable(creds)
    # Assert
    if why is None:
        assert got is None
    else:
        assert got and got.startswith("skipped:") and why in got and "OneAPI" in got


def test_plan_skips_the_zcc_workspace_with_the_reason_and_keeps_the_rest():
    """ASVS V1.14.6 · CWE-440: with a skip reason for zcc, every Client Connector type is left out with that reason and the other products are still planned; zcc alone is refused with the reason."""
    # Arrange
    opts = tt.normalize_options(["zia", "zcc"])
    why = tt.zcc_unavailable({"auth_method": "oneapi", "cloud": "zscalerten"})
    # Act
    p = tt.plan(["zia_extras", "zcc"], {}, opts, skip_products={"zcc": why})
    # Assert
    assert p["read"] and all(tt.BY_KEY[k]["product"] == "zia" for k in p["read"])
    assert {k for k in p["left_out"] if k.startswith("zcc.")} == {t["key"] for t in tt.TYPES if t["product"] == "zcc"}
    assert all(v == why for k, v in p["left_out"].items() if k.startswith("zcc."))
    with pytest.raises(tt.ExportRefused, match="zscalerten"):
        tt.plan(["zcc"], {}, tt.normalize_options(["zcc"]), skip_products={"zcc": why})


def test_the_route_skips_the_zcc_workspace_on_zscalerten_and_says_why(monkeypatch):
    """ASVS V1.14.6 · CWE-440 · WSTG-BUSL-01: exporting ZIA and Client Connector for a zscalerten tenant exports ZIA and lists every Client Connector type as not exported with the OneAPI reason; Client Connector alone with a classic sign-in is a 400 naming the reason, before any sign-in."""
    # Arrange
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    st = ot.sample_store(reset=True)
    client = ot.OfflineSdkClient(st, ot.creds_for(st))
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(creds.get("cloud")) or client)
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "cloud": "zscalerten",
            "scopes": ["zia_extras", "zcc"], "channels": {}, "from_page": True, "products": ["zia", "zcc"]}
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-pw-pw-pw", "api_key": "a" * 12, "cloud": "zscaler",
              "scopes": ["zcc"], "channels": {}, "from_page": True, "products": ["zcc"]}
    # Act
    r = c.post("/api/tenant-terraform/start", json=body)
    deadline = time.time() + 60
    snap = None
    while time.time() < deadline:
        snap = c.get(f"/api/dlp-packs/jobs/{r.json()['job_id']}").json()
        if snap["status"] != "running":
            break
        time.sleep(0.05)
    built_before = list(built)
    r2 = c.post("/api/tenant-terraform/start", json=legacy)
    # Assert
    assert r.status_code == 200, r.text
    res = snap["result"]
    assert res["status"] == "ready" and "zcc" not in res["products"] and res["products"]["zia"]["resources"] > 0
    zcc_rows = [x for x in res["not_exported"] if "Client Connector" in x.get("what", "") or "zcc" in str(x).lower()]
    assert zcc_rows and all("OneAPI" in x["why"] and "zscalerten" in x["why"] for x in zcc_rows), zcc_rows
    assert r2.status_code == 400 and "classic ZIA sign-in" in r2.json()["detail"], r2.text
    assert built == built_before, "the refused export signed in to nothing"


def test_the_ci_sample_has_a_workspace_for_every_product_and_ci_validates_each(tmp_path):
    """ASVS V14.2.1 · V1.14.6 · CWE-1357: tools/terraform_samples.py writes the whole-tenant sample with a zia, zpa, ztc and zcc workspace (zcc with notification templates and ZIA posture), and the CI step checks each one is there and validates every workspace folder, blocking the run."""
    # Act
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "terraform_samples.py"), str(tmp_path)], capture_output=True, text=True,
                         timeout=300, env=dict(os.environ, PYTHONPATH=str(ROOT)))
    ci = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    step = ci.split("Validate the whole-tenant export of the sample tenant", 1)[1].split("- name:", 1)[0]
    # Assert
    assert out.returncode == 0, out.stderr[-800:]
    for p in tt.PRODUCTS:
        assert (tmp_path / "tenant" / tt.ROOT_DIR / p / "terraform.tf").is_file(), p
    zcc_tf = (tmp_path / "tenant" / tt.ROOT_DIR / "zcc" / "client_connector.tf").read_text(encoding="utf-8")
    assert 'resource "zcc_notification_template"' in zcc_tf and 'resource "zcc_zia_posture"' in zcc_tf
    assert "for p in zia zpa ztc zcc" in step and "tenant-terraform/*/" in step and "terraform -chdir=\"$d\" validate" in step
    assert "continue-on-error" not in step and "(advisory)" not in step, "a workspace that does not validate fails CI"


def _pack():
    import dlp_importer
    return next(p for p in dlp_importer.discover_packs() if p["id"] == "zbp_enterprise_baseline")


def test_a_policy_pack_takes_the_private_registry_namespace():
    """ASVS V14.2.4 · V10.3.2 · CWE-829: a pack's Terraform workspace points the zia provider at the private registry namespace asked for (terraform.tf, the file headers and the README); the default stays zscaler/zia."""
    # Arrange
    pack = _pack()
    # Act
    files = pt.generate(pack, namespace="registry.example.com/zscaler")
    plain = pt.generate(pack)
    # Assert
    assert 'source  = "registry.example.com/zscaler/zia"' in files["terraform.tf"]
    assert "registry.example.com/zscaler/zia" in files["README.md"] and "private registry mirror" in files["README.md"]
    assert all("for registry.example.com/zscaler/zia ~> 4.8" in c for n, c in files.items() if n.endswith(".tf") and c.startswith("# Generated"))
    assert 'source  = "zscaler/zia"' in plain["terraform.tf"] and "registry.example.com" not in "".join(plain.values())


@pytest.mark.parametrize("bad", ['zscaler"\nprovider "x', "../zscaler", "Zscaler", "registry.example.com/zscaler/extra", "a b", "x" * 80, "-x"])
def test_a_malformed_pack_namespace_is_refused(bad):
    """ASVS V5.1.3 · V5.3.6 · CWE-20 · CWE-74: a namespace that is not a registry host and one namespace is refused before any file is made (nothing reaches HCL)."""
    # Act / Assert
    with pytest.raises(ValueError):
        pt.generate(_pack(), namespace=bad)


def test_the_pack_terraform_routes_take_the_namespace_and_refuse_a_bad_one():
    """ASVS V5.1.3 · V12.5.1 · CWE-20 · WSTG-INPV-01: the pack library's Terraform download and the Terraform hand-off take provider_namespace; a malformed one is a 400 and no zip is made."""
    # Arrange
    import zipfile
    import io
    import dlp_api_server as srv
    import security
    from fastapi.testclient import TestClient
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    # Act
    ok = c.get("/api/pack-library/zbp_enterprise_baseline/terraform.zip", params={"assessor": "Jane Doe", "provider_namespace": "registry.example.com/zscaler"})
    bad = c.get("/api/pack-library/zbp_enterprise_baseline/terraform.zip", params={"assessor": "Jane Doe", "provider_namespace": "bad ns"})
    hand = c.post("/api/dlp-packs/terraform", json={"pack_ids": ["zbp_enterprise_baseline"], "mode": "static", "client_id": "", "client_secret": "",
                                                   "vanity_domain": "", "assessor": "Jane Doe", "provider_namespace": "mirror.example/zs"})
    hand_bad = c.post("/api/dlp-packs/terraform/start", json={"pack_ids": ["zbp_enterprise_baseline"], "mode": "static", "assessor": "Jane Doe",
                                                             "provider_namespace": 'x"y'})
    # Assert
    assert ok.status_code == 200, ok.text[:300]
    tf = next(zipfile.ZipFile(io.BytesIO(ok.content)).read(n).decode() for n in zipfile.ZipFile(io.BytesIO(ok.content)).namelist() if n.endswith("terraform.tf"))
    assert 'source  = "registry.example.com/zscaler/zia"' in tf
    assert bad.status_code == 400 and "namespace" in bad.json()["detail"]
    assert hand.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(hand.content))
    assert any('source  = "mirror.example/zs/zia"' in z.read(n).decode() for n in z.namelist() if n.endswith("terraform.tf"))
    assert hand_bad.status_code == 400
