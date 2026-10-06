"""Offline Architect registry/model/component matrix, without a browser or tenant.

Each parametrized ID is a distinct flow, domain invariant, branch or interaction.
The JavaScript runner shares one deterministic run; pytest reports every case.
Browser layout and assistive-technology behavior are explicitly a separate stage.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "dsa_player_cases.js"
NODE = shutil.which("node")


def _catalog():
    if not NODE:
        return []
    result = subprocess.run(
        [NODE, str(RUNNER), "--list"], capture_output=True, text=True, check=True,
        cwd=ROOT, timeout=30,
    )
    return json.loads(result.stdout)


CASES = _catalog()


@pytest.fixture(scope="module")
def dsa_results():
    if not NODE:
        pytest.skip("Node is required for the Architect player behavior suite")
    result = subprocess.run(
        [NODE, str(RUNNER)], capture_output=True, text=True,
        cwd=ROOT, timeout=60,
    )
    assert result.stdout, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["cases"]) == len(CASES)
    return {case["id"]: case for case in payload["cases"]}


@pytest.mark.skipif(NODE is None, reason="Node is not installed")
@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_architect_reference_flow(case, dsa_results):
    result = dsa_results[case["id"]]
    assert result["status"] == "passed", result.get("error", result)


def test_architect_scope_matrix_is_substantial():
    if not NODE:
        pytest.skip("Node is required to discover the distinct case matrix")
    for scope in ("per-flow animation", "Play All / Guided Next"):
        relevant = [case for case in CASES if case["scope"] == scope]
        assert len(relevant) >= 100
        assert len({case["id"] for case in relevant}) == len(relevant)
        assert all(case["assertion"] for case in relevant)
