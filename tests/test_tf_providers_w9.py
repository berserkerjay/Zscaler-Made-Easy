"""Terraform providers and namespaces (wave 9):

* the Client Connector provider zscaler/zcc has published pre-releases only
  (0.1.2-beta.3 the newest), and Terraform selects a pre-release only by an
  exact constraint, so the whole-tenant export pins it exactly and labels
  the workspace beta; the provider signs in with ZIdentity OneAPI only, so
  the zcc workspace is skipped, with the reason, for a classic ZIA sign-in
  and on the zscalergov and zscalerten clouds;
* the provider's fail-open policy, device cleanup and web privacy settings
  are exported (the SDK reads them); notification templates and ZIA posture
  profiles are listed as not exported (the SDK has no call for them);
* the CI sample export holds a workspace for every product and CI
  validates each one;
* policy packs take the same private-registry namespace option as the
  whole-tenant export.

Offline: fixture tenants (offline_tenant) only; no registry, tenant or network."""
from __future__ import annotations

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


def test_notification_templates_and_zia_posture_are_listed_as_not_exported():
    """ASVS V1.1.2 · CWE-1059: the provider's notification templates and ZIA posture profiles, which the SDK cannot read, are named as not exported with the reason, never silently missing."""
    # Act
    rows = [(p, w, y) for p, w, y in tt.NOT_COVERED if p == "zcc"]
    # Assert
    assert rows and "zcc_notification_template" in rows[0][1] and "zcc_zia_posture" in rows[0][1] and "sdk" in rows[0][2]
    assert {t["resource"] for t in tt.TYPES if t["product"] == "zcc"} == {
        "zcc_trusted_network", "zcc_forwarding_profile", "zcc_failopen_policy", "zcc_device_cleanup", "zcc_web_privacy"}


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
    """ASVS V14.2.1 · V1.14.6 · CWE-1357: tools/terraform_samples.py writes the whole-tenant sample with a zia, zpa, ztc and zcc workspace, and the CI step checks each one is there and validates every workspace folder (advisory)."""
    # Act
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "terraform_samples.py"), str(tmp_path)], capture_output=True, text=True,
                         timeout=300, env=dict(os.environ, PYTHONPATH=str(ROOT)))
    ci = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    step = ci.split("Validate the whole-tenant export of the sample tenant", 1)[1].split("- name:", 1)[0]
    # Assert
    assert out.returncode == 0, out.stderr[-800:]
    for p in tt.PRODUCTS:
        assert (tmp_path / "tenant" / tt.ROOT_DIR / p / "terraform.tf").is_file(), p
    assert "for p in zia zpa ztc zcc" in step and "tenant-terraform/*/" in step and "terraform -chdir=\"$d\" validate" in step
    assert "continue-on-error: true" in step, "advisory until a first green run"


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
