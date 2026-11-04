"""The agent workspace (agent-workspace/) stays true to the code and to its own
layered-context rules: compiled references are current, every stage has a
complete contract, every layer's index lists its files, and nothing is over
its token budget."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import agent_workspace  # noqa: E402


def test_the_workspace_has_no_problems():
    """SSDF PW.1.2 · CWE-1059 · ASVS V1.1.2: the agent workspace's compiled references are current and its layers keep their rules."""
    # Arrange / Act
    bad = agent_workspace.problems()
    # Assert
    assert bad == [], "\n".join(bad)


def test_every_module_is_on_the_architecture_map():
    """SSDF PW.1.2 · CWE-1059 · ASVS V1.1.2: a new module appears on the map the agents use to find files."""
    # Arrange
    py, js, html = agent_workspace._modules()
    # Act
    text = agent_workspace.compile_architecture()
    # Assert
    missing = [n for n in py if f"`{n}`" not in text] + [n for n in js + html if f"`static/{n}`" not in text]
    assert missing == []


def test_a_stage_contract_without_outputs_is_reported(tmp_path, monkeypatch):
    """SSDF PW.1.2 · CWE-1059 · ASVS V1.1.2: a stage missing a contract section is caught (the check is not a no-op)."""
    # Arrange: a copy of the workspace whose build stage has lost its Outputs
    import shutil
    ws = tmp_path / "agent-workspace"
    shutil.copytree(agent_workspace.WS, ws, ignore=shutil.ignore_patterns("output"))
    (ws / "output").mkdir()
    stage = ws / "stages" / "02-build" / "CONTEXT.md"
    stage.write_text(stage.read_text(encoding="utf-8").replace("## Outputs", "## Results"), encoding="utf-8")
    monkeypatch.setattr(agent_workspace, "WS", str(ws))
    # Act
    bad = agent_workspace.problems()
    # Assert
    assert any("02-build" in b and "## Outputs" in b for b in bad)


@pytest.mark.parametrize("marker", ["# assumed: ZIA keeps 32 rules", "x = 1  # ASSUMED field name", "// assumed: path"])
def test_assumed_markers_are_found(marker):
    """SSDF PW.4.4 · CWE-1059 · ASVS V1.1.2: each style of assumption marker is picked up for the register."""
    # Arrange / Act / Assert
    assert agent_workspace.ASSUMED.search(marker)


@pytest.mark.parametrize("path,rule", [
    ("_config/testing.md", "Run the full suite under `taskset -c 0,1` (CI runners have 2 CPUs) before a branch goes to CI."),
    ("stages/04-integrate/CONTEXT.md", "Archive child cloud sessions once their work is merged; answer their questions and blocked prompts "
                                       "yourself (the coordinator), never leave them for the owner."),
])
def test_the_owner_rules_of_wave_10_are_in_the_workspace(path, rule):
    """SSDF PO.3.2 · CWE-1059 · ASVS V1.1.2: the two-CPU full-suite rule (testing) and the child-session rule (integrate) are where the agents read them."""
    # Arrange / Act
    with open(os.path.join(ROOT, "agent-workspace", path), encoding="utf-8") as f:
        text = f.read()
    # Assert
    assert rule in text, path
