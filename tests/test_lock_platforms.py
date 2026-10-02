"""requirements.lock is installed with `pip install --require-hashes --no-deps`
on Linux, macOS, Windows and in the container, so it must be complete on every
one of those platforms (no dependency left to a resolver that --no-deps never
runs) and free of pins with known vulnerabilities that the CI audit rejects."""
from __future__ import annotations

import importlib.metadata as md
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

packaging_markers = pytest.importorskip("packaging.markers")
packaging_requirements = pytest.importorskip("packaging.requirements")
packaging_utils = pytest.importorskip("packaging.utils")
packaging_version = pytest.importorskip("packaging.version")

# Marker environments for the platforms the installers support.
_BASE = {
    "implementation_name": "cpython", "platform_python_implementation": "CPython",
    "python_version": "3.11", "python_full_version": "3.11.9", "implementation_version": "3.11.9",
    "platform_release": "", "platform_version": "", "platform_machine": "x86_64",
}
PLATFORMS = {
    "windows": dict(_BASE, sys_platform="win32", platform_system="Windows", os_name="nt", platform_machine="AMD64"),
    "linux": dict(_BASE, sys_platform="linux", platform_system="Linux", os_name="posix"),
    "macos": dict(_BASE, sys_platform="darwin", platform_system="Darwin", os_name="posix", platform_machine="arm64"),
}


def _read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def _lock_pins() -> dict[str, list[tuple[str, str]]]:
    """{normalized name: [(version, marker or "")]} from requirements.lock."""
    pins: dict[str, list[tuple[str, str]]] = {}
    for line in _read("requirements.lock").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([^\s;\\]+)\s*(?:;\s*(.*?))?\s*\\?\s*$", line)
        if m:
            pins.setdefault(packaging_utils.canonicalize_name(m.group(1)), []).append((m.group(2), (m.group(3) or "").strip()))
    return pins


def _pinned_on(pins, name: str, env: dict) -> bool:
    for _version, marker in pins.get(packaging_utils.canonicalize_name(name), []):
        if not marker or packaging_markers.Marker(marker).evaluate(env):
            return True
    return False


def _requested_extras() -> dict[str, set[str]]:
    extras: dict[str, set[str]] = {}
    for line in _read("requirements.txt").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            req = packaging_requirements.Requirement(line)
            extras.setdefault(packaging_utils.canonicalize_name(req.name), set()).update(req.extras)
    return extras


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
def test_every_dependency_of_a_pinned_package_is_pinned_for_that_platform(platform):
    """A --no-deps install from the lock gets nothing that is not pinned in it.
    mcp needs pywin32 and typer needs colorama on Windows only; a lock compiled
    on Linux left both out, and the MCP server could not import on Windows."""
    env = PLATFORMS[platform]
    pins = _lock_pins()
    extras = _requested_extras()
    missing, checked = [], 0
    for name in sorted(pins):
        if not any(not mk or packaging_markers.Marker(mk).evaluate(env) for _v, mk in pins[name]):
            continue  # not installed on this platform
        try:
            requires = md.requires(name) or []
        except md.PackageNotFoundError:
            continue  # not installed in this test environment (e.g. pywin32 on Linux)
        checked += 1
        for spec in requires:
            req = packaging_requirements.Requirement(spec)
            wanted = req.marker is None or any(
                req.marker.evaluate(dict(env, extra=x)) for x in ({""} | extras.get(name, set())))
            if wanted and not _pinned_on(pins, req.name, env):
                missing.append(f"{name} requires {spec!r}")
    assert checked >= 20, "too few lock packages installed to check; install from requirements.lock"
    assert not missing, f"requirements.lock is incomplete on {platform}: {missing}"


def test_windows_only_dependencies_are_pinned_with_a_windows_marker():
    pins = _lock_pins()
    for name in ("pywin32", "colorama"):
        assert _pinned_on(pins, name, PLATFORMS["windows"]), f"{name} is not pinned for Windows"
        assert not _pinned_on(pins, name, PLATFORMS["linux"]), f"{name} must not install on Linux (no wheel)"


def test_pyjwt_is_at_or_above_the_release_that_fixes_cve_2026_101918():
    fixed = packaging_version.Version("2.15.0")
    versions = [packaging_version.Version(v) for v, _m in _lock_pins()["pyjwt"]]
    assert versions and all(v >= fixed for v in versions), versions
    for name in ("requirements.txt", "pyproject.toml"):
        floor = re.search(r"pyjwt\[crypto\]>=([0-9.]+)", _read(name))
        assert floor and packaging_version.Version(floor.group(1)) >= fixed, name


def test_lock_is_compiled_universally_and_ci_checks_it_on_windows():
    """pip-compile only resolves for the platform it runs on, so a lock made on
    Linux drops Windows-only dependencies. make lock and CI's staleness check
    both use a universal resolution, and a Windows job installs the lock."""
    assert "--universal" in _read("Makefile")
    wf = _read(os.path.join(".github", "workflows", "tests.yml"))
    assert "--universal" in wf
    job = wf.split("windows-lock:", 1)[1].split("\n  container:", 1)[0] if "windows-lock:" in wf else ""
    assert "windows-latest" in job and "--no-deps -r requirements.lock" in job
    assert "pip check" in job and re.search(r"import [^\n]*dlp_mcp_server", job)


def test_committed_sbom_lists_exactly_the_locked_packages():
    """docs/sbom.cdx.json is generated from requirements.lock (docs/SBOM.md);
    a re-lock without regenerating it leaves the SBOM describing old pins."""
    import json
    with open(os.path.join(ROOT, "docs", "sbom.cdx.json"), encoding="utf-8") as f:
        sbom = json.load(f)
    assert sbom.get("bomFormat") == "CycloneDX"
    in_sbom = {(packaging_utils.canonicalize_name(c["name"]), c["version"]) for c in sbom["components"]
               if c.get("purl", "").startswith("pkg:pypi/")}
    in_lock = {(name, v) for name, rows in _lock_pins().items() for v, _m in rows}
    assert in_sbom == in_lock, {"only in sbom": sorted(in_sbom - in_lock), "only in lock": sorted(in_lock - in_sbom)}
    assert "docs/sbom.cdx.json" in _read(os.path.join("docs", "SBOM.md"))
