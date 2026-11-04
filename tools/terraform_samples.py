#!/usr/bin/env python3
"""Write the generated Terraform that no shipped pack exercises, so CI and
`make check` can run `terraform fmt -check` and `terraform validate` on it:

    <out>/vendor_json/main.tf.json   the vendor migration's JSON for the test
                                     suite's multi-channel sample (one reviewed
                                     Symantec policy on web, endpoint, SaaS, email)
    <out>/vendor_hcl/                the same as the workspace layout
    <out>/containment/               a pack with one Cloud App Control, File
                                     Type, URL Filtering and SSL Inspection rule
    <out>/endpoint/                  a pack with an Endpoint DLP rule, a sub-rule
                                     and an application group
    <out>/tenant/tenant-terraform/   the sample tenant exported whole (tenant_terraform):
                                     one workspace per product (zia/, zpa/, ztc/, zcc/)
                                     with import blocks; CI validates every one

    python tools/terraform_samples.py /tmp/tf_samples
"""
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Packs deploy detection only and carve Cloud App Control, File Type, URL and
# SSL rules out unless this says otherwise; the containment sample needs them.
os.environ["DLP_CHECK_CARVED_CHANNELS"] = "none"
sys.path[:0] = [ROOT, os.path.join(ROOT, "tests")]

import pack_terraform as pt  # noqa: E402
import vendor_migrate as vm  # noqa: E402
from test_baselines import BASELINE_META  # noqa: E402
from test_control_channels import control_pack  # noqa: E402
from test_endpoint_baseline import endpoint_pack  # noqa: E402
from test_vendor_migrate import RICH, _multi_decisions  # noqa: E402


def main(out: str) -> int:
    snap = vm.inventory_bytes(RICH)
    tf, report = vm.compile_export(snap, _multi_decisions(snap), prefix="sym", vendor_id="symantec")
    if not report["ready"]:
        print("the vendor sample did not compile:", json.dumps(report["questions"], indent=1), file=sys.stderr)
        return 2
    os.makedirs(os.path.join(out, "vendor_json"), exist_ok=True)
    with open(os.path.join(out, "vendor_json", "main.tf.json"), "w", encoding="utf-8") as f:
        json.dump(tf, f, indent=2)
    pt.write_workspace(vm.workspace_files(tf, report, vm.VENDORS["symantec"]["name"], "sample.xml"), os.path.join(out, "vendor_hcl"))
    with tempfile.TemporaryDirectory() as d:
        pack = control_pack(Path(d), meta=dict(BASELINE_META, name="Containment sample"))
        files = pt.generate(pack, name_prefix="")
        kinds = set(re.findall(r'(?m)^resource "(zia_[a-z_]+)"', files["rules.tf"]))
        want = {"zia_cloud_app_control_rule", "zia_file_type_control_rules", "zia_url_filtering_rules", "zia_ssl_inspection_rules"}
        if not want <= kinds:
            print(f"the containment sample is missing {sorted(want - kinds)}", file=sys.stderr)
            return 2
        pt.write_workspace(files, os.path.join(out, "containment"))
    with tempfile.TemporaryDirectory() as d:
        pack = endpoint_pack(Path(d), meta=dict(BASELINE_META, name="Endpoint sample"))
        pt.write_workspace(pt.generate(pack, name_prefix=""), os.path.join(out, "endpoint"))
    import offline_tenant as ot
    import tenant_terraform as tt
    st = ot.sample_store(reset=True)
    opts = tt.normalize_options(list(tt.PRODUCTS))
    sel = tt.plan(["dlp", "zia_extras", "zpa", "ztw", "zcc"], {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb",
                                                                       "ssl_inspection", "cloud_app_control")}, opts)
    snap = tt.read_tenant(ot.OfflineSdkClient(st, ot.creds_for(st)), sel["read"])
    files, _report = tt.generate(snap, opts, tenant_label="Sample tenant", plan_info=sel, generated_at="2026-10-31T00:00:00Z")
    missing = [p for p in tt.PRODUCTS if f"{tt.ROOT_DIR}/{p}/terraform.tf" not in files]
    if missing:   # CI validates every product's workspace: the sample must produce each one
        print(f"the whole-tenant sample has no workspace for {missing}", file=sys.stderr)
        return 2
    for path, content in files.items():
        target = os.path.join(out, "tenant", path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    print(f"Terraform samples written to {out}/vendor_json, {out}/vendor_hcl, {out}/containment, {out}/endpoint and {out}/tenant")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "terraform_samples"))
