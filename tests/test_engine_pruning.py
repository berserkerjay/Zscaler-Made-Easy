"""
A predefined dictionary the tenant does not expose must not take a whole
engine (and every rule behind it) down with it: preflight drops the term,
keeps the rest of the expression valid, and says so.
"""
from __future__ import annotations

import pack_deploy as pd
from dlp_importer import prune_engine_terms
from test_pack_deploy import PREDEF_SSN, FakeClient, _dict, _engine, _policy, items_by, write_pack

META = {"name": "Prune Pack", "confidence_tweaks": []}


def test_prune_keeps_structure_valid():
    known = ["Alpha", "Beta (US) - High"]
    assert prune_engine_terms("((D:Alpha > 0) OR (D:NOPE_LEAKAGE > 1))", ["NOPE_LEAKAGE"], known) == ("((D:Alpha > 0))", ["NOPE_LEAKAGE"])
    # An AND NOT over a pruned term is dropped; the operator goes with the operand.
    assert prune_engine_terms("((D:Alpha > 0) AND NOT (D:NOPE > 0))", ["NOPE"], known)[0] == "((D:Alpha > 0))"
    # A pruned first operand hands its place to the next one.
    assert prune_engine_terms("((D:NOPE > 2) OR (D:Beta (US) - High > 4) OR (D:Alpha > 0))", ["NOPE"], known)[0] == "((D:Beta (US) - High > 4) OR (D:Alpha > 0))"
    # Nested group emptied entirely disappears.
    out, dropped = prune_engine_terms("((D:Alpha > 0) AND ((D:NOPE > 0) OR (D:ALSO_NOPE > 1)))", ["NOPE", "ALSO_NOPE"], known)
    assert out == "((D:Alpha > 0))" and dropped == ["ALSO_NOPE", "NOPE"]
    # Nothing meaningful left -> None.
    assert prune_engine_terms("((D:NOPE > 0))", ["NOPE"], known) == (None, ["NOPE"])
    # Nothing to prune -> unchanged.
    assert prune_engine_terms("((D:Alpha > 0))", [], known) == ("((D:Alpha > 0))", [])


def test_preflight_deploys_engine_without_the_missing_predefined_dictionary(tmp_path):
    pack = write_pack(tmp_path, "prune",
                      dicts=[_dict("PR-Dict")],
                      engines=[_engine("PR-Engine", "((D:PR-Dict > 0) OR (D:ASPP_LEAKAGE > 1) OR (D:Social Security Numbers (US) > 4))"),
                               _engine("PR-Only-Missing", "((D:ASPP_LEAKAGE > 1))")],
                      policies=[_policy("PR-Monitor", ["PR-Engine"]), _policy("PR-Other", ["PR-Only-Missing"])],
                      meta=META)
    rep = pd.preflight(FakeClient(dicts=[PREDEF_SSN]), [pack], writes_enabled=True)
    e = items_by(rep, "engine")
    assert e["PR-Engine"]["status"] == pd.CREATE
    assert e["PR-Engine"]["detail"]["expression"] == "((D:PR-Dict > 0) OR (D:Social Security Numbers (US) > 4))"
    assert e["PR-Engine"]["pruned"] == ["ASPP_LEAKAGE"] and "deployed without ASPP_LEAKAGE" in e["PR-Engine"]["warnings"]
    # An engine made only of missing dictionaries still cannot be created.
    assert e["PR-Only-Missing"]["status"] == pd.BLOCKED_DEPENDENCY
    p = items_by(rep, "policy")
    assert p["PR-Monitor"]["status"] == pd.CREATE and p["PR-Other"]["status"] == pd.BLOCKED_DEPENDENCY
    assert any("ASPP_LEAKAGE" in w and "PR-Engine" in w for w in rep["warnings"])
