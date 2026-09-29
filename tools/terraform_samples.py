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

    python tools/terraform_samples.py /tmp/tf_samples
"""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
        pt.write_workspace(pt.generate(pack), os.path.join(out, "containment"))
    with tempfile.TemporaryDirectory() as d:
        pack = endpoint_pack(Path(d), meta=dict(BASELINE_META, name="Endpoint sample"))
        pt.write_workspace(pt.generate(pack), os.path.join(out, "endpoint"))
    print(f"Terraform samples written to {out}/vendor_json, {out}/vendor_hcl, {out}/containment and {out}/endpoint")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "terraform_samples"))
