"""Complete the CycloneDX SBOM that `cyclonedx-py requirements` builds from
requirements.lock, and write THIRD_PARTY_NOTICES.md from it.

`cyclonedx-py requirements` reads only the lock, which holds names, versions
and hashes but no licence data, so every component it emits has no licence.
It also never sees the Terraform provider the policy packs run with, which is
pinned in terraform/*/.terraform.lock.hcl. This script:

  * gives every Python component its SPDX licence from
    tools/third_party_licenses.json (a package missing from that file is an
    error, so a new dependency cannot land without a licence decision);
  * gives the root component the project's own licence, read from
    pyproject.toml's `license` (Apache-2.0, the text in LICENSE), and writes
    the root component's fields in one fixed (sorted) order, so the output is
    the same whether or not cyclonedx-py already copied the licence over;
  * adds each Terraform provider pinned in the lockfiles, with its licence;
  * gives every Python component its package URL as bom-ref (cyclonedx-py
    uses the lock's line numbers, which move whenever the lock changes);
  * builds the dependency graph, which `cyclonedx-py requirements` leaves
    flat: the root depends on what requirements.txt asks for (the lock's
    `# via -r requirements.txt`) and on the Terraform providers, and each
    package depends on the packages whose `# via` comment names it;
  * writes THIRD_PARTY_NOTICES.md, listing every component and pointing at
    the full texts in third_party_licenses/ for the copyleft licences, plus
    the container image's base (CPython and the Debian packages the
    Dockerfile keeps), which this SBOM does not cover: CI inventories the
    built image separately (the `image-sbom` artifact, docs/SBOM.md).

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
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from open_source import NOTE_MD  # noqa: E402  (the repository root's one wording)

LICENSE_MAP = os.path.join(ROOT, "tools", "third_party_licenses.json")
NOTICES = os.path.join(ROOT, "THIRD_PARTY_NOTICES.md")
LOCK = "requirements.lock"
DIRECT = "-r requirements.txt"

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

# The container image's base, which docs/sbom.cdx.json does not cover (it is
# built from requirements.lock and the Terraform lockfiles). These are the
# parts of the base image the Dockerfile keeps; the full package list of a
# built image is CI's `image-sbom` artifact.
# (component, where its licence text is in the image, SPDX licence)
BASE_IMAGE_COMPONENTS = [
    ("CPython 3.11", "/usr/local/lib/python3.11/LICENSE.txt", "PSF-2.0"),
    ("glibc (libc6)", "/usr/share/doc/libc6/copyright", "LGPL-2.1-or-later"),
    ("OpenSSL library (libssl3t64)", "/usr/share/doc/libssl3t64/copyright", "Apache-2.0"),
    ("zlib (zlib1g)", "/usr/share/doc/zlib1g/copyright", "Zlib"),
    ("dash", "/usr/share/doc/dash/copyright", "BSD-3-Clause AND GPL-2.0-or-later"),
    ("coreutils", "/usr/share/doc/coreutils/copyright", "GPL-3.0-or-later"),
]


def base_image(root: str = ROOT) -> str:
    """The image the Dockerfile's `base` stage is built FROM."""
    with open(os.path.join(root, "Dockerfile"), encoding="utf-8") as f:
        m = re.search(r"^FROM\s+(\S+)\s+AS\s+base\b", f.read(), re.M | re.I)
    if not m:
        raise SystemExit("Dockerfile has no `FROM <image> AS base` stage")
    return m.group(1)


def licence_ids(expression: str) -> set[str]:
    """The licence identifiers in an SPDX expression."""
    return {t for t in re.split(r"[\s()]+", expression) if t and t not in ("AND", "OR", "WITH")}


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def project_licence(root: str = ROOT) -> str:
    """The project's own SPDX licence: pyproject.toml's `license` (PEP 639)."""
    with open(os.path.join(root, "pyproject.toml"), "rb") as f:
        spdx = tomllib.load(f).get("project", {}).get("license")
    if not isinstance(spdx, str) or not spdx.strip():
        raise SystemExit("pyproject.toml has no SPDX `license` string in [project]")
    return spdx.strip()


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


def lock_via(root: str = ROOT) -> dict[str, set[str]]:
    """{canonical package: {canonical names (or DIRECT) it is pulled in via}}
    from the `# via` comments uv writes into requirements.lock."""
    via: dict[str, set[str]] = {}
    current = None
    in_via = False
    with open(os.path.join(root, LOCK), encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==", line)
            if m:
                current, in_via = _canon(m.group(1)), False
                via.setdefault(current, set())
                continue
            if current is None:
                continue
            m = re.match(r"^\s+# via(?:\s+(.*?))?\s*$", line)
            if m:
                in_via = True
                if m.group(1):
                    via[current].add(m.group(1))
                continue
            m = re.match(r"^\s+#\s{2,}(.*?)\s*$", line)
            if m and in_via:
                via[current].add(m.group(1))
                continue
            in_via = False
    return {k: {v if v.startswith("-r ") else _canon(v) for v in vs} for k, vs in via.items()}


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
    rootc = dict(meta.get("component") or {"bom-ref": "root-component", "type": "application", "name": "dlp-check"})
    rootc["licenses"] = _licence_entry(project_licence(root))
    # Sorted, as cyclonedx-py writes it when pyproject declares a licence, so a
    # regenerated SBOM never differs from the committed one by key order alone.
    rootc = meta["component"] = {k: rootc[k] for k in sorted(rootc)}
    root_ref = rootc.get("bom-ref", "root-component")

    # Package URLs as bom-refs, so a ref names the package, not a lock line.
    for c in comps:
        if c.get("purl", "").startswith("pkg:pypi/"):
            c["bom-ref"] = c["purl"]

    # The graph, from the lock's `# via` comments.
    tf_refs = sorted(c["bom-ref"] for c in comps if c["bom-ref"].startswith("terraform-provider:"))
    py_refs = {_canon(c["name"]): c["bom-ref"] for c in comps if c["bom-ref"].startswith("pkg:pypi/")}
    edges: dict[str, set[str]] = {root_ref: set(tf_refs)}
    edges.update({c["bom-ref"]: set() for c in comps})
    for child, parents in lock_via(root).items():
        if child not in py_refs:
            continue
        for parent in parents:
            if parent == DIRECT:
                edges[root_ref].add(py_refs[child])
            elif parent in py_refs:
                edges[py_refs[parent]].add(py_refs[child])
    deps = []
    for ref in sorted(edges):
        entry = {"ref": ref}
        if edges[ref]:
            entry["dependsOn"] = sorted(edges[ref])
        deps.append(entry)
    sbom["dependencies"] = deps
    return sbom


def _licence_of(c: dict) -> str:
    entry = c["licenses"][0]
    return entry.get("expression") or entry["license"]["id"]


def notices(sbom: dict, root: str = ROOT) -> str:
    rows = sorted(((c.get("group") + "/" if c.get("group") else "") + c["name"], c["version"], _licence_of(c))
                  for c in sbom["components"])
    lines = [
        "# Third-party notices",
        "",
        NOTE_MD,
        "",
        "Zscaler Made Easy itself is under the Apache License 2.0 ([LICENSE](LICENSE), with",
        "its [NOTICE](NOTICE)). It runs with the",
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
    lines += ["", "## Container image", "",
              f"The container image is built on `{base_image(root)}` (Debian 13 with CPython 3.11).",
              "The components of that base image are not in the SBOM above, which covers",
              "the Python packages and the Terraform provider only; CI builds a CycloneDX",
              "SBOM of the built image (every Debian package and its licence) as the",
              "`image-sbom` artifact. The Dockerfile removes the base packages the app",
              "does not need; what stays includes the components below, used unmodified.",
              "Each one's licence text and copyright notice are in the image at the path",
              "shown, and the Debian licence texts are in `/usr/share/common-licenses/`.", "",
              "| Component | Licence text in the image | Licence (SPDX) |", "|---|---|---|"]
    lines += [f"| {n} | `{path}` | {lic} |" for n, path, lic in BASE_IMAGE_COMPONENTS]
    lines += ["", *REDISTRIBUTION]
    return "\n".join(lines) + "\n"


# What the GPL and LGPL components above mean for redistributing the app.
# Facts, checked against the tree: no module of the app imports jwcrypto or
# pywin32; the Zscaler SDK imports jwcrypto (zscaler/oneapi_oauth_client.py);
# pywin32 is pinned for Windows only, asked for by requirements.txt and mcp.
REDISTRIBUTION = [
    "## What these licences mean for redistributing Zscaler Made Easy",
    "",
    "Zscaler Made Easy's own code is under the Apache License 2.0. None of it is copied",
    "from a GPL or LGPL work, and every third-party component is used unmodified, as",
    "its own package or program. The GPL and LGPL components, and how they are used:",
    "",
    "- **jwcrypto (LGPL-3.0-or-later).** The app's own code does not import it; the",
    "  Zscaler SDK (zscaler-sdk-python) imports it for OneAPI sign-in. So it is installed",
    "  on every platform: in a local install's virtual environment, in the container",
    "  image (the Dockerfile installs requirements.lock) and frozen into the standalone",
    "  (no-install) edition by PyInstaller. The LGPL lets a work that only uses the",
    "  library keep its own licence, so the app stays under Apache-2.0. Whoever passes",
    "  on a build that contains jwcrypto passes on the LGPL-3.0 and GPL-3.0 texts (the",
    "  LGPL-3.0 is a set of extra permissions on top of the GPL-3.0, which is the only",
    "  reason GPL-3.0.txt is here), says where jwcrypto's source is (its unmodified PyPI",
    "  release) and leaves the recipient able to use a changed jwcrypto: it is a separate",
    "  package folder in a local install and in the container, and the app's full source",
    "  and build script (tools/build_standalone.py) let anyone rebuild the standalone",
    "  edition with another jwcrypto.",
    "- **pywin32 (partly LGPL-2.1-or-later).** Windows only. The LGPL-2.1 part is its",
    "  adodbapi module, which nothing in the app imports; the rest of pywin32 is under",
    "  BSD-3-Clause, PSF-2.0, HPND and MIT. It is not in the container image (Linux). A",
    "  local Windows install has it, unmodified, in the virtual environment; PyInstaller",
    "  freezes only modules that something imports, so adodbapi is not expected in the",
    "  Windows standalone edition.",
    "- **The container image's base: dash (GPL-2.0-or-later), coreutils",
    "  (GPL-3.0-or-later) and glibc (LGPL-2.1-or-later).** Debian packages of the base",
    "  image, unmodified. dash and coreutils are separate programs beside the app in",
    "  the same image (an aggregate, which the GPL allows next to software under other",
    "  licences); the app does not link to them. CPython links to glibc dynamically,",
    "  which the LGPL allows. Whoever passes on the image passes on their licence texts",
    "  (in the image, at the paths above) and offers their source (Debian publishes it",
    "  for each package version). The standalone edition does not carry them.",
    "",
    "The Apache License 2.0 is compatible with the GPL-3.0 in one direction only:",
    "Apache-2.0 code may become part of a GPL-3.0 work (the combined work is then",
    "passed on under the GPL-3.0), but GPL-3.0 code may not become part of an",
    "Apache-2.0 work. So Zscaler Made Easy may be passed on under Apache-2.0 with the",
    "components above used as they are, and someone may build it into a GPL-3.0",
    "project; copying GPL or LGPL source code into this repository, instead of using",
    "those libraries and programs unmodified, would put the result under those",
    "licences, so it is not done. This summary is not legal advice.",
]


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
