"""The committed SBOM (docs/sbom.cdx.json) is a complete inventory: every
component carries its SPDX licence, the Terraform provider the policy packs
run with is in it next to the Python packages, and THIRD_PARTY_NOTICES.md
(which LICENSE points at) lists them with the full texts of the copyleft
licences. `cyclonedx-py requirements` alone emits no licence at all, because
requirements.lock holds none, and never sees the Terraform lockfiles."""
from __future__ import annotations

import copy
import importlib.metadata as md
import importlib.util
import json
import os
import re

import pytest

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


def _licence(c: dict) -> str | None:
    lic = c.get("licenses") or []
    if not lic:
        return None
    return lic[0].get("expression") or (lic[0].get("license") or {}).get("id")


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_every_sbom_component_and_the_root_carry_a_licence():
    sbom = _sbom()
    unlicensed = [f"{c['name']}=={c['version']}" for c in sbom["components"] if not _licence(c)]
    assert not unlicensed, f"SBOM components without a licence: {unlicensed}"
    assert _licence(sbom["metadata"]["component"]) == "LicenseRef-DLP-Check-Internal"


def test_the_weak_copyleft_components_are_labelled_as_such():
    by_name = {_canon(c["name"]): _licence(c) for c in _sbom()["components"]}
    assert by_name["jwcrypto"] == "LGPL-3.0-or-later"
    assert by_name["certifi"] == "MPL-2.0"
    assert "LGPL-2.1-or-later" in by_name["pywin32"]


def test_the_sbom_lists_the_terraform_provider_pinned_in_every_lockfile():
    enrich = _enricher()
    providers = enrich.terraform_providers()
    assert providers and any(p["source"] == "registry.terraform.io/zscaler/zia" for p in providers)
    in_sbom = {(c.get("group"), c["name"], c["version"]): c for c in _sbom()["components"]}
    for p in providers:
        _host, ns, ptype = p["source"].split("/")
        c = in_sbom.get((ns, f"terraform-provider-{ptype}", p["version"]))
        assert c, f"{p['source']} {p['version']} is not in docs/sbom.cdx.json"
        assert _licence(c) == "MPL-2.0"
        assert len(p["files"]) == len([f for f in os.listdir(os.path.join(ROOT, "terraform"))
                                       if os.path.exists(os.path.join(ROOT, "terraform", f, ".terraform.lock.hcl"))])


def test_the_committed_sbom_and_notices_are_what_the_enricher_produces():
    """Regenerating (docs/SBOM.md) on the committed file changes nothing: the
    licences, the Terraform provider and THIRD_PARTY_NOTICES.md are current."""
    enrich = _enricher()
    sbom = _sbom()
    again = enrich.enrich(copy.deepcopy(sbom))
    assert again == sbom
    assert _read("THIRD_PARTY_NOTICES.md") == enrich.notices(sbom)


def test_a_locked_package_without_a_recorded_licence_stops_the_build():
    enrich = _enricher()
    sbom = _sbom()
    sbom["components"].append({"bom-ref": "x", "type": "library", "name": "brand-new-dep", "version": "1.0"})
    with pytest.raises(SystemExit, match="brand-new-dep"):
        enrich.enrich(sbom)


def test_the_licence_map_matches_the_installed_package_metadata():
    """Where a package declares a PEP 639 License-Expression, the recorded
    licence is exactly that expression."""
    licences = _enricher().load_license_map()["python"]
    checked = 0
    for name, spdx in licences.items():
        try:
            expr = md.metadata(name).get("License-Expression")
        except md.PackageNotFoundError:
            continue
        if expr:
            checked += 1
            assert spdx == expr, f"{name}: recorded {spdx!r}, package declares {expr!r}"
    if not checked:
        pytest.skip("no locked package installed in this environment")


def test_third_party_notices_ship_the_copyleft_texts_and_license_points_at_them():
    notices = _read("THIRD_PARTY_NOTICES.md")
    for name in ("jwcrypto", "certifi", "zscaler/terraform-provider-zia"):
        assert re.search(rf"^\| {re.escape(name)} \|", notices, re.M), name
    for path, title in (("third_party_licenses/MPL-2.0.txt", "Mozilla Public License Version 2.0"),
                        ("third_party_licenses/LGPL-3.0.txt", "GNU LESSER GENERAL PUBLIC LICENSE"),
                        ("third_party_licenses/GPL-3.0.txt", "GNU GENERAL PUBLIC LICENSE"),
                        ("third_party_licenses/LGPL-2.1.txt", "GNU LESSER GENERAL PUBLIC LICENSE")):
        assert path in notices
        assert title in _read(*path.split("/"))[:400]
    lic = _read("LICENSE")
    assert "THIRD_PARTY_NOTICES.md" in lic and "docs/sbom.cdx.json" in lic
    # requirements.lock and the Terraform lockfiles hold no licence data.
    assert "see requirements.lock" not in lic


def test_pyproject_licence_is_the_license_file_not_a_free_text_claim():
    pyproject = _read("pyproject.toml")
    assert re.search(r'^license\s*=\s*\{\s*file\s*=\s*"LICENSE"\s*\}', pyproject, re.M)
    assert "Not for redistribution." not in pyproject.split("[project]", 1)[1].split("\n[", 1)[0]


def test_ci_pins_its_supply_chain_tools_and_checks_the_enriched_sbom():
    wf = _read(".github", "workflows", "tests.yml")
    for tool in ("cyclonedx-bom", "pip-audit", "uv"):
        installs = re.findall(rf"pip install[^\n]*\b{re.escape(tool)}\b[^\n]*", wf)
        assert installs, tool
        for line in installs:
            assert re.search(rf"\b{re.escape(tool)}==\d", line), f"unpinned: {line.strip()}"
    assert "tools/sbom_enrich.py" in wf
    assert re.search(r"git diff --exit-code[^\n]*docs/sbom\.cdx\.json[^\n]*THIRD_PARTY_NOTICES\.md", wf)
    # Windows-only pins (pywin32, colorama) are audited on Windows too.
    job = wf.split("windows-lock:", 1)[1].split("\n  container:", 1)[0]
    assert "pip-audit" in job
    assert "tools/sbom_enrich.py" in _read("docs", "SBOM.md")
