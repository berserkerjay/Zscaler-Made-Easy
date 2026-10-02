"""CI runs only pinned tooling (sbom2-2).

Every package CI installs comes from a hash-pinned lock or an exact `==`
pin, every container image it runs is pinned by digest, and every action is
referenced by a full commit SHA. A new release, or a moved tag, of pytest,
httpx, pip, Trivy or an action then cannot change what CI runs unnoticed.
"""
import glob
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml")))
DEV_TOOLS = ("pytest", "pyflakes", "httpx")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _run_lines(text):
    """Shell lines of a workflow, with `\\` continuations joined."""
    return [l.strip() for l in text.replace("\\\n", " ").splitlines()]


def _lock_pins(name):
    return dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", _read(name), re.M))


def test_workflows_exist():
    names = {os.path.basename(p) for p in WORKFLOWS}
    assert {"tests.yml", "upstream_check.yml", "apply-patch.yml"} <= names


@pytest.mark.parametrize("path", WORKFLOWS, ids=os.path.basename)
def test_every_action_is_pinned_by_full_commit_sha(path):
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", _read(path), re.M)
    assert uses
    for ref in uses:
        if ref.startswith(("./", "docker://")):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"not pinned by commit SHA: {ref}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=os.path.basename)
def test_every_pip_install_is_hash_locked_or_exactly_pinned(path):
    for line in _run_lines(_read(path)):
        m = re.search(r"\bpip install\b(.*)", line)
        if not m:
            continue
        assert "|| true" not in line, f"install failure hidden: {line}"
        args = [a for a in m.group(1).split() if a not in ("--upgrade", "-U", "--quiet", "-q")]
        if "-r" in args:
            assert "--require-hashes" in args, f"lock installed without hashes: {line}"
            for i, a in enumerate(args):
                if a == "-r":
                    assert args[i + 1].endswith(".lock"), f"not a lock: {line}"
            continue
        pkgs = [a for a in args if not a.startswith("-")]
        assert pkgs, line
        for p in pkgs:
            assert re.fullmatch(r"[A-Za-z0-9_.\[\]-]+==\d[\w.]*", p), f"unpinned install of {p!r}: {line}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=os.path.basename)
def test_every_container_image_is_pinned_by_digest(path):
    for line in _run_lines(_read(path)):
        if not re.search(r"\bdocker run\b", line):
            continue
        images = re.findall(r"\b([a-z0-9.-]+/[a-z0-9._/-]+)(?::[\w.-]+)?(@sha256:[0-9a-f]{64})?", line)
        for name, digest in images:
            if name.startswith(("var/run", "out")):
                continue
            assert digest, f"image {name} not pinned by digest: {line}"
        assert ":latest" not in line, line


def test_ci_installs_the_dev_tools_from_a_hash_pinned_lock():
    lock = _read("requirements-dev.lock")
    pins = _lock_pins("requirements-dev.lock")
    for tool in DEV_TOOLS:
        assert tool in pins, tool
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", lock)
    for block in blocks[1:]:
        assert "--hash=sha256:" in block, block.splitlines()[0]
    wf = _read(".github", "workflows", "tests.yml")
    assert "pip install --require-hashes --no-deps -r requirements-dev.lock" in wf


def test_dev_lock_agrees_with_the_app_lock():
    """Installed after requirements.lock with --no-deps: a shared package at
    another version would silently replace the app's pin."""
    app, dev = _lock_pins("requirements.lock"), _lock_pins("requirements-dev.lock")
    clash = {n: (app[n], dev[n]) for n in set(app) & set(dev) if app[n] != dev[n]}
    assert not clash, clash


def test_pyproject_dev_extra_pins_the_locked_versions():
    pyproject = _read("pyproject.toml")
    dev = re.search(r"^dev\s*=\s*\[([^\]]*)\]", pyproject, re.M).group(1)
    reqs = dict(re.findall(r'"([A-Za-z0-9_.-]+)==([^"]+)"', dev))
    pins = _lock_pins("requirements-dev.lock")
    assert set(reqs) == set(DEV_TOOLS), dev
    for tool in DEV_TOOLS:
        assert reqs[tool] == pins[tool], tool


def test_ci_checks_the_dev_lock_is_fresh_and_make_can_rebuild_it():
    wf = _read(".github", "workflows", "tests.yml")
    assert re.search(r"uv pip compile[^\n]*-c requirements\.lock[^\n]*requirements-dev\.txt", wf)
    assert re.search(r"uv pip compile[^\n]*-c requirements\.lock[^\n]*requirements-dev\.txt", _read("Makefile"))
