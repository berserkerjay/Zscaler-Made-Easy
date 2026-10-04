"""The credential store for remembered profile secrets (tenant_profiles.py
imports `keyring`) is part of the hash-pinned install on Windows and macOS
and of the SBOM and notices, and no page or document asks for an unpinned
`pip install keyring`."""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESKTOP = ("win32", "darwin")


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock() -> dict[str, tuple[str, str, bool]]:
    """{name: (version, marker, hashed)} from requirements.lock."""
    out: dict[str, tuple[str, str, bool]] = {}
    lines = _read("requirements.lock").splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)\s*(?:;\s*([^\\]+?))?\s*\\?$", line)
        if m:
            hashed = i + 1 < len(lines) and "--hash=sha256:" in lines[i + 1]
            out[_canon(m.group(1))] = (m.group(2), (m.group(3) or "").strip(), hashed)
    return out


def _marker_true(marker: str, platform: str, py: str = "3.11") -> bool:
    if not marker:
        return True
    from packaging.markers import Marker
    return Marker(marker).evaluate({"sys_platform": platform, "python_full_version": py + ".0",
                                    "python_version": py, "platform_python_implementation": "CPython",
                                    "implementation_name": "cpython", "platform_system": ""})


def _keyring_closure() -> set[str]:
    """keyring and every package the lock pins because keyring needs it."""
    lock_text = _read("requirements.lock")
    blocks = re.split(r"\n(?=[A-Za-z0-9])", lock_text)
    via: dict[str, set[str]] = {}
    for b in blocks:
        m = re.match(r"([A-Za-z0-9_.-]+)==", b)
        if m:
            via[_canon(m.group(1))] = {_canon(v) for v in re.findall(r"#\s+(?:via\s+)?([A-Za-z0-9_.-]+)\s*$", b, re.M)} - {"via"}
    closure = {"keyring"}
    grew = True
    while grew:
        grew = False
        for name, parents in via.items():
            if name not in closure and parents and parents <= closure:
                closure.add(name)
                grew = True
    return closure


def test_keyring_is_declared_with_desktop_markers():
    req = [ln for ln in _read("requirements.txt").splitlines() if re.match(r"^keyring\b", ln)]
    assert req, "keyring is not declared in requirements.txt"
    marker = req[0].split(";", 1)[1].strip() if ";" in req[0] else ""
    for plat in DESKTOP:
        assert _marker_true(marker, plat), plat
    assert not _marker_true(marker, "linux"), "the container has no Secret Service; keyring stays off Linux"
    py = _read("pyproject.toml")
    assert re.search(r"""['"]keyring>=[0-9.]+; sys_platform == "win32" or sys_platform == "darwin"['"]""", py)


def test_keyring_and_everything_it_needs_are_hash_pinned_for_windows_and_macos():
    lock = _lock()
    assert "keyring" in lock, "keyring is not in requirements.lock"
    closure = _keyring_closure()
    assert {"jaraco-classes", "jaraco-context", "jaraco-functools", "more-itertools", "pywin32-ctypes"} <= closure
    for name in closure:
        version, marker, hashed = lock[name]
        assert hashed, f"{name} is not hash-pinned"
        assert not _marker_true(marker, "linux"), f"{name} would be installed on Linux"
    assert _marker_true(lock["keyring"][1], "win32") and _marker_true(lock["keyring"][1], "darwin")
    assert _marker_true(lock["pywin32-ctypes"][1], "win32") and not _marker_true(lock["pywin32-ctypes"][1], "darwin")


def test_keyring_and_its_dependencies_are_in_the_sbom_licences_and_notices():
    lock = _lock()
    licences = json.loads(_read("tools", "third_party_licenses.json"))["python"]
    sbom = {(_canon(c["name"]), c["version"]): c for c in json.loads(_read("docs", "sbom.cdx.json"))["components"]}
    notices = _read("THIRD_PARTY_NOTICES.md")
    for name in _keyring_closure():
        version = lock[name][0]
        assert licences.get(name), f"{name} has no licence in tools/third_party_licenses.json"
        c = sbom.get((name, version))
        assert c and c.get("licenses"), f"{name}=={version} is missing from docs/sbom.cdx.json"
        assert f"| {name} | {version} |" in notices, f"{name} is missing from THIRD_PARTY_NOTICES.md"


def test_no_page_or_document_asks_for_an_unpinned_keyring_install():
    for parts in (("SECURITY.md",), ("README.md",), ("INSTALL.md",), ("GETTING_STARTED.md",),
                  ("static", "index.html"), ("static", "guide.js")):
        text = _read(*parts)
        assert not re.search(r"pip install (-U )?keyring\b", text), parts
        assert "optional <code>keyring</code>" not in text and "optional `keyring`" not in text, parts


def test_tests_never_reach_the_real_credential_store(monkeypatch):
    """conftest blocks the installed keyring, so a remembered secret in a
    test never lands in this machine's Credential Manager or Keychain.
    Without a store a secret is not remembered, unless the profile file is
    chosen explicitly (DLP_CHECK_SECRET_STORE=file): no silent fallback."""
    import tenant_profiles as tp
    assert sys.modules.get("keyring", "absent") is None
    monkeypatch.delenv("DLP_CHECK_SECRET_STORE", raising=False)
    assert tp._keyring() is None and tp.secret_storage() == "none"
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    assert tp.secret_storage() == "file"
