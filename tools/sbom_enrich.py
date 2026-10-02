"""Complete the CycloneDX SBOM that `cyclonedx-py requirements` builds from
requirements.lock, and write THIRD_PARTY_NOTICES.md from it.

`cyclonedx-py requirements` reads only the lock, which holds names, versions
and hashes but no licence data, so every component it emits has no licence.
It also never sees the Terraform provider the policy packs run with, which is
pinned in terraform/*/.terraform.lock.hcl. This script:

  * gives every Python component its SPDX licence from
    tools/third_party_licenses.json (a package missing from that file is an
    error, so a new dependency cannot land without a licence decision);
  * gives the root component the project's own licence (a LicenseRef, since
    LICENSE is not an SPDX licence);
  * adds each Terraform provider pinned in the lockfiles, with its licence;
  * writes THIRD_PARTY_NOTICES.md, listing every component and pointing at
    the full texts in third_party_licenses/ for the copyleft licences.

Usage (docs/SBOM.md):  python tools/sbom_enrich.py docs/sbom.cdx.json
The script is idempotent: running it on its own output changes nothing.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LICENSE_MAP = os.path.join(ROOT, "tools", "third_party_licenses.json")
NOTICES = os.path.join(ROOT, "THIRD_PARTY_NOTICES.md")

# Licences whose terms require their full text to travel with the software.
# Value: the files in third_party_licenses/ that hold that text.
LICENCE_TEXTS = {
    "MPL-2.0": ["third_party_licenses/MPL-2.0.txt"],
    # The LGPL-3.0 is a set of additional permissions on top of the GPL-3.0,
    # so both texts are needed.
    "LGPL-3.0-or-later": ["third_party_licenses/LGPL-3.0.txt", "third_party_licenses/GPL-3.0.txt"],
    # pywin32 (Windows only) bundles adodbapi under the LGPL-2.1.
    "LGPL-2.1-or-later": ["third_party_licenses/LGPL-2.1.txt"],
}


def licence_ids(expression: str) -> set[str]:
    """The licence identifiers in an SPDX expression."""
    return {t for t in re.split(r"[\s()]+", expression) if t and t not in ("AND", "OR", "WITH")}


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_license_map(path: str = LICENSE_MAP) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data["python"] = {_canon(k): v for k, v in data["python"].items()}
    return data


def _licence_entry(spdx: str) -> list[dict]:
    """CycloneDX `licenses`: a single SPDX id, or an expression for anything
    compound (AND/OR/WITH) or a LicenseRef."""
    if re.search(r"\s(AND|OR|WITH)\s", spdx) or spdx.startswith("LicenseRef-"):
        return [{"expression": spdx}]
    return [{"license": {"id": spdx}}]


def terraform_providers(root: str = ROOT) -> list[dict]:
    """[{source, version, files}] from every terraform/*/.terraform.lock.hcl."""
    found: dict[tuple[str, str], list[str]] = {}
    for path in sorted(glob.glob(os.path.join(root, "terraform", "*", ".terraform.lock.hcl"))):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for m in re.finditer(r'provider\s+"([^"]+)"\s*\{(.*?)\n\}', text, re.S):
            v = re.search(r'^\s*version\s*=\s*"([^"]+)"', m.group(2), re.M)
            if v:
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                found.setdefault((m.group(1), v.group(1)), []).append(rel)
    return [{"source": s, "version": v, "files": files} for (s, v), files in sorted(found.items())]


def _provider_component(p: dict, spdx: str) -> dict:
    host, namespace, ptype = p["source"].split("/")
    return {
        "bom-ref": f"terraform-provider:{p['source']}@{p['version']}",
        "type": "library",
        "group": namespace,
        "name": f"terraform-provider-{ptype}",
        "version": p["version"],
        "purl": f"pkg:generic/{namespace}/terraform-provider-{ptype}@{p['version']}"
                f"?download_url=https://{host}/providers/{namespace}/{ptype}/{p['version']}",
        "description": f"Terraform provider {p['source']}, pinned in " + ", ".join(p["files"]),
        "licenses": _licence_entry(spdx),
        "externalReferences": [{"type": "distribution", "url": f"https://{host}/providers/{namespace}/{ptype}/{p['version']}"}],
    }


def enrich(sbom: dict, licences: dict | None = None, root: str = ROOT) -> dict:
    licences = licences or load_license_map()
    missing = []
    comps = [c for c in sbom.get("components", []) if not str(c.get("bom-ref", "")).startswith("terraform-provider:")]
    for c in comps:
        spdx = licences["python"].get(_canon(c["name"]))
        if spdx is None:
            missing.append(f"{c['name']}=={c.get('version')}")
            continue
        c["licenses"] = _licence_entry(spdx)
    for p in terraform_providers(root):
        spdx = licences["terraform"].get(p["source"])
        if spdx is None:
            missing.append(f"terraform provider {p['source']}")
            continue
        comps.append(_provider_component(p, spdx))
    if missing:
        raise SystemExit("no licence recorded in tools/third_party_licenses.json for: " + ", ".join(missing))
    sbom["components"] = comps

    meta = sbom.setdefault("metadata", {})
    rootc = meta.setdefault("component", {"bom-ref": "root-component", "type": "application", "name": "dlp-check"})
    rootc["licenses"] = _licence_entry(licences["project"])
    root_ref = rootc.get("bom-ref", "root-component")

    tf_refs = sorted(c["bom-ref"] for c in comps if c["bom-ref"].startswith("terraform-provider:"))
    deps = [d for d in sbom.get("dependencies", []) if not d["ref"].startswith("terraform-provider:")]
    for d in deps:
        if d["ref"] == root_ref:
            keep = [r for r in d.get("dependsOn", []) if not r.startswith("terraform-provider:")]
            if keep or tf_refs:
                d["dependsOn"] = sorted(keep + tf_refs)
    deps += [{"ref": r} for r in tf_refs]
    sbom["dependencies"] = sorted(deps, key=lambda d: d["ref"])
    return sbom


def _licence_of(c: dict) -> str:
    entry = c["licenses"][0]
    return entry.get("expression") or entry["license"]["id"]


def notices(sbom: dict) -> str:
    rows = sorted(((c.get("group") + "/" if c.get("group") else "") + c["name"], c["version"], _licence_of(c))
                  for c in sbom["components"])
    lines = [
        "# Third-party notices",
        "",
        "DLP-Check itself is under the terms in [LICENSE](LICENSE). It runs with the",
        "third-party components below, each under its own licence. This file is",
        "generated from the SBOM ([docs/sbom.cdx.json](docs/sbom.cdx.json)) by",
        "`python tools/sbom_enrich.py docs/sbom.cdx.json`; see [docs/SBOM.md](docs/SBOM.md).",
        "",
        "Each Python package's own licence file, with its copyright notice, is",
        "installed with it (in the package's `*.dist-info` folder). The full texts",
        "of the copyleft licences are kept in [third_party_licenses/](third_party_licenses/):",
        "",
    ]
    used = sorted({i for _n, _v, lic in rows for i in licence_ids(lic) if i in LICENCE_TEXTS})
    for lic in used:
        users = ", ".join(f"{n} {v}" for n, v, l in rows if lic in licence_ids(l))
        files = " and ".join(f"[{os.path.basename(p)}]({p})" for p in LICENCE_TEXTS[lic])
        lines.append(f"- **{lic}** ({users}): {files}")
    lines += ["", "These components are used unmodified; their source is available from the",
              "distribution links in the SBOM.", "",
              "| Component | Version | Licence (SPDX) |", "|---|---|---|"]
    lines += [f"| {n} | {v} | {lic} |" for n, v, lic in rows]
    return "\n".join(lines) + "\n"


def _dump(sbom: dict) -> str:
    return json.dumps(sbom, indent=2, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("sbom", help="CycloneDX JSON from cyclonedx-py; rewritten in place")
    ap.add_argument("--notices", default=NOTICES, help="where to write THIRD_PARTY_NOTICES.md")
    args = ap.parse_args(argv)
    with open(args.sbom, encoding="utf-8") as f:
        sbom = enrich(json.load(f))
    with open(args.sbom, "w", encoding="utf-8", newline="\n") as f:
        f.write(_dump(sbom))
    with open(args.notices, "w", encoding="utf-8", newline="\n") as f:
        f.write(notices(sbom))
    return 0


if __name__ == "__main__":
    sys.exit(main())
