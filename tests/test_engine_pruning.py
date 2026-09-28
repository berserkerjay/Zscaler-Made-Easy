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


def test_packs_without_a_baseline_section_are_tagged_too(tmp_path):
    """Fed/CJIS-style packs used to deploy untagged, so a removal could
    only find them by name. Every object now carries a pack tag."""
    pack = write_pack(tmp_path, "plainpack", dicts=[_dict("PP-Dict")], engines=[_engine("PP-Engine", "(D:PP-Dict > 0)")],
                      policies=[_policy("PP-Monitor", ["PP-Engine"])], meta={"name": "Plain Pack", "version": "3.1", "confidence_tweaks": []})
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied"
    z = client.zia
    assert "[DLP-Check pack plainpack v3.1]" in z.dlp_dictionary.added[0]["description"]
    assert "[DLP-Check pack plainpack v3.1]" in z.dlp_engine.added[0]["description"]
    assert "[DLP-Check pack plainpack v3.1]" in z.dlp_web_rules.added[0]["description"]
    assert pd.BASELINE_MARK not in z.dlp_engine.added[0]["description"]
    # The rule ships DISABLED, and the description says so (dictionaries/engines don't).
    assert z.dlp_web_rules.added[0]["state"] == "DISABLED"
    assert "Deployed DISABLED" in z.dlp_web_rules.added[0]["description"]
    assert "Deployed DISABLED" not in z.dlp_dictionary.added[0]["description"]
    assert "Deployed DISABLED" not in z.dlp_engine.added[0]["description"]


def test_sum_operator_is_resolved_pruned_and_referenced():
    """The Engine Builder's Sum: ((D:A + D:B + D:C) > n). Terms inside a Sum
    carry no comparison of their own; a pruned term leaves the Sum intact."""
    from dlp_importer import resolve_engine_expression, prune_engine_terms, engine_references, default_counts
    ids = {"A": 1, "B": 2, "C": 3}
    assert resolve_engine_expression("((D:A + D:B + D:C) > 1)", ids) == ("((D1.S + D2.S + D3.S) > 1)", [])
    assert resolve_engine_expression("((D:A > 0) AND ((D:B + D:C) > 4))", ids) == ("((D1.S > 0) AND ((D2.S + D3.S) > 4))", [])
    assert resolve_engine_expression("((D:A) OR (D:B > 2))", ids) == ("((D1.S > 0) OR (D2.S > 2))", [])
    assert resolve_engine_expression("((D:A + D:Nope) > 1)", ids)[1] == ["Nope"]
    assert engine_references("((D:A + D:B) > 1)", ["A", "B", "C"]) == ["A", "B"]
    assert prune_engine_terms("((D:A + D:B + D:C) > 1)", ["B"], ["A", "C"]) == ("((D:A + D:C) > 1)", ["B"])
    assert prune_engine_terms("((D:A > 0) AND ((D:B + D:C) > 4))", ["B", "C"], ["A"]) == ("((D:A > 0))", ["B", "C"])
    import re
    assert default_counts("D1.S + D2.S > 3 AND D3.S", re.compile(r"(D\d+\.S)(?!\s*[<>=+])")) == "D1.S + D2.S > 3 AND D3.S > 0"


def test_missing_names_with_parentheses_are_reported_whole_and_pruned():
    """A tenant without "Names (US)" or the driver's-licence dictionaries
    must get the engine without those terms, not a blocked engine and 32
    skipped rules."""
    from dlp_importer import resolve_engine_expression, prune_engine_terms
    expr = ("((D:Social Security Numbers (US) > 0) AND (D:Names (US) > 0) AND (D:Custom-Date-of-Birth > 0)) "
            "OR ((D:Names (US) > 0) AND (D:Custom-Date-of-Birth > 0) AND ((D:Driver's License (United States) > 0) OR (D:Tax Identification Number (US) > 0)))")
    known = {"Social Security Numbers (US)": 1, "Custom-Date-of-Birth": 2}
    resolved, unresolved = resolve_engine_expression(expr, known)
    assert set(unresolved) == {"Names (US)", "Driver's License (United States)", "Tax Identification Number (US)"}, unresolved
    pruned, dropped = prune_engine_terms(expr, unresolved, list(known))
    assert set(dropped) == set(unresolved) and "Names (US" not in pruned and "D:Social Security Numbers (US)" in pruned and "D:Custom-Date-of-Birth" in pruned
    total = "((D:Social Security Numbers (US) + D:Custom-Medical-Record-Number + D:National Provider Identifier + D:Tax Identification Number (US) + D:Driver's License (United States)) > 50)"
    resolved, unresolved = resolve_engine_expression(total, {"Social Security Numbers (US)": 1, "Custom-Medical-Record-Number": 2})
    assert set(unresolved) == {"National Provider Identifier", "Tax Identification Number (US)", "Driver's License (United States)"}
    pruned, dropped = prune_engine_terms(total, unresolved, ["Social Security Numbers (US)", "Custom-Medical-Record-Number"])
    assert pruned and "Driver" not in pruned and "> 50" in pruned and "D:Social Security Numbers (US) + D:Custom-Medical-Record-Number" in pruned.replace("  ", " ")
