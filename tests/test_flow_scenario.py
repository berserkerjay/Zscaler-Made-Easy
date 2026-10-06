"""Behavioral offline tests for the unified flow scenario and its browser page.

Each named JavaScript scenario runs in a new Node process. The IDs describe
separate user-visible or evidence-integrity contracts, rather than repeated
executions being counted as extra coverage. No browser, package installation,
credentials, or tenant requests are involved.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "flow_scenario_cases.js"
NODE = shutil.which("node")


def _case_ids():
    if NODE is None:
        return ["node-unavailable"]
    proc = subprocess.run(
        [NODE, str(HARNESS), "--list"], cwd=ROOT, capture_output=True,
        text=True, timeout=30,
    )
    if proc.returncode:
        raise RuntimeError(f"Cannot collect flow scenarios: {proc.stderr}")
    return json.loads(proc.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize("case_id", _case_ids())
def test_unified_flow_frontend_case(case_id):
    proc = subprocess.run(
        [NODE, str(HARNESS), case_id], cwd=ROOT, capture_output=True,
        text=True, timeout=30,
    )
    assert proc.returncode == 0, f"{case_id}\n{proc.stderr}\n{proc.stdout}"
    report = json.loads(proc.stdout)
    assert report == {"id": case_id, "passed": True}
