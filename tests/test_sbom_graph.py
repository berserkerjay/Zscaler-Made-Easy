"""The committed SBOM (docs/sbom.cdx.json) carries the dependency graph, not
just a flat list: the root depends on the packages requirements.txt asks for
(and the Terraform provider), each package depends on what the lock's
`# via` comments say pulled it in, and every component is reachable from the
root. Component bom-refs are package URLs, so they do not move when a line
is added to requirements.lock.

docs/SBOM.md also says exactly what the SBOM covers: the Python packages and
the Terraform provider, not the container image's base (CPython and the
Debian packages kept in it). Those are inventoried by the image SBOM CI
builds from the image, and named with their licences in
THIRD_PARTY_NOTICES.md."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _sbom() -> dict:
    return json.loads(_read("docs", "sbom.cdx.json"))


def _enricher():
    spec = importlib.util.spec_from_file_location("sbom_enrich", os.path.join(ROOT, "tools", "sbom_enrich.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _graph(sbom: dict) -> dict[str, set[str]]:
    return {d["ref"]: set(d.get("dependsOn", [])) for d in sbom["dependencies"]}


def _python(sbom: dict) -> dict[str, dict]:
    return {_canon(c["name"]): c for c in sbom["components"] if c.get("purl", "").startswith("pkg:pypi/")}


def _direct_from_requirements() -> set[str]:
    names = set()
    for line in _read("requirements.txt").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.add(_canon(re.match(r"[A-Za-z0-9_.-]+", line).group(0)))
    return names


def test_python_components_use_purl_bom_refs_not_lock_line_numbers():
    for c in _python(_sbom()).values():
        assert c["bom-ref"] == c["purl"], c["bom-ref"]
    assert "requirements-L" not in _read("docs", "sbom.cdx.json")


def test_the_root_depends_on_the_direct_requirements_and_the_terraform_provider():
    sbom = _sbom()
    py = _python(sbom)
    root = sbom["metadata"]["component"]["bom-ref"]
    deps = _graph(sbom)[root]
    direct = _direct_from_requirements()
    assert direct, "requirements.txt lists no dependency"
    assert {py[n]["bom-ref"] for n in direct} | {r for r in deps if r.startswith("terraform-provider:")} == deps
    assert any(r.startswith("terraform-provider:registry.terraform.io/zscaler/zia@") for r in deps)


def test_transitive_edges_follow_the_lock_via_comments():
    sbom = _sbom()
    py = _python(sbom)
    g = _graph(sbom)
    # jwcrypto (LGPL) is traceable to the package that pulls it in.
    assert py["jwcrypto"]["bom-ref"] in g[py["zscaler-sdk-python"]["bom-ref"]]
    assert py["starlette"]["bom-ref"] in g[py["fastapi"]["bom-ref"]]
    assert py["anyio"]["bom-ref"] in g[py["starlette"]["bom-ref"]]


def test_every_component_is_reachable_from_the_root():
    sbom = _sbom()
    g = _graph(sbom)
    refs = {c["bom-ref"] for c in sbom["components"]}
    assert set(g) == refs | {sbom["metadata"]["component"]["bom-ref"]}
    seen, todo = set(), [sbom["metadata"]["component"]["bom-ref"]]
    while todo:
        r = todo.pop()
        if r not in seen:
            seen.add(r)
            todo.extend(g.get(r, ()))
    assert not refs - seen, f"orphan components: {sorted(refs - seen)}"


def test_the_enricher_builds_the_graph_from_a_flat_cyclonedx_py_bom():
    """`cyclonedx-py requirements` emits lock-line bom-refs and no edges; the
    enricher turns that into exactly the committed SBOM."""
    committed = _sbom()
    raw = copy.deepcopy(committed)
    raw["components"] = [c for c in raw["components"] if not c["bom-ref"].startswith("terraform-provider:")]
    for i, c in enumerate(raw["components"]):
        c["bom-ref"] = f"requirements-L{i * 7 + 3}"
        c.pop("licenses", None)
    raw["dependencies"] = [{"ref": "root-component"}] + [{"ref": c["bom-ref"]} for c in raw["components"]]
    assert _enricher().enrich(raw) == committed


def test_sbom_md_does_not_claim_to_cover_the_container_base_image():
    doc = _read("docs", "SBOM.md")
    assert "everything Zscaler Made Easy runs with" not in doc
    for word in ("CPython", "glibc", "coreutils", "image-sbom"):
        assert word in doc, word


def test_ci_builds_an_image_sbom_artifact():
    ci = _read(".github", "workflows", "tests.yml")
    assert re.search(r"image\b.*--format cyclonedx.*zscaler-made-easy:ci", ci), "no CycloneDX image SBOM step"
    assert re.search(r"name:\s*image-sbom\b", ci)


def test_notices_name_the_container_base_image_and_its_os_licences():
    notices = _read("THIRD_PARTY_NOTICES.md")
    base = re.search(r"^FROM\s+(python:\S+)\s+AS\s+base", _read("Dockerfile"), re.M).group(1)
    assert base in notices
    for pkg, lic in (("CPython", "PSF-2.0"), ("glibc", "LGPL-2.1-or-later"),
                     ("coreutils", "GPL-3.0-or-later"), ("zlib", "Zlib"), ("OpenSSL", "Apache-2.0")):
        assert re.search(rf"^\| {pkg}[^|]*\|[^\n]*{re.escape(lic)}", notices, re.M), pkg
