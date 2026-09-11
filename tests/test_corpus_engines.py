"""Local corpus test: predefined dictionaries approximated, engines evaluated, rules named."""
import corpus_engines as ce
import dlp_efficacy as eff


def test_validators():
    assert ce.luhn_ok("4111 1111 1111 1111") and not ce.luhn_ok("4111 1111 1111 1112")
    assert ce.ssn_ok("123-45-6788") and not ce.ssn_ok("666-45-6788") and not ce.ssn_ok("219-09-9999")
    assert ce.aba_ok("021000021") and not ce.aba_ok("123456789")
    assert ce.iban_ok("GB82 WEST 1234 5698 7654 32") and not ce.iban_ok("GB82 WEST 1234 5698 7654 33")
    assert ce.npi_ok("1234567893") and ce.mask("4111111111111111") == "••••••••••••1111"


def test_expression_tri_state_and_forms():
    c = {1: 3, 2: 0, 3: None}
    assert ce.evaluate_expression("((D1.S > 1) AND (D2.S > 0))", c)[0] is False
    assert ce.evaluate_expression("(D1.S > 1) OR (D3.S > 0)", c)[0] is True
    assert ce.evaluate_expression("(D3.S > 0) AND (D1.S > 0)", c)[0] is None
    assert ce.evaluate_expression("NOT (D2.S > 0) AND D(1) > 2", c)[0] is True
    assert ce.evaluate_expression("D1 AND D2", c)[0] is False and ce.evaluate_expression("garbage", c)[0] is None


class FakeClient:
    def __init__(self):
        self.routes = {
            "/zia/dlpDictionaries": [
                {"id": 10, "name": "Project Codenames", "custom": True, "phrases": [{"phrase": "Project Falcon"}], "patterns": []},
                {"id": 20, "name": "Credit Cards", "dictionaryType": "PREDEFINED"},
                {"id": 21, "name": "Social Security Numbers", "dictionaryType": "PREDEFINED"},
                {"id": 22, "name": "Financial Statements", "dictionaryType": "PREDEFINED"},
            ],
            "/zia/dlpEngines": [
                {"id": 100, "name": "PCI", "engineExpression": "((D20.S > 0))", "customDlpEngine": True},
                {"id": 101, "name": "Codename + SSN", "engineExpression": "((D10.S > 0) AND (D21.S > 0))", "customDlpEngine": True},
                {"id": 102, "name": "Financials", "engineExpression": "((D22.S > 0) OR (D10.S > 5))", "customDlpEngine": True},
                {"id": 103, "name": "Nothing", "engineExpression": "((D21.S > 3))", "customDlpEngine": True},
            ],
            "/zia/webDlpRules": [{"id": 1, "name": "Block-PCI", "dlpEngines": [{"id": 100}]}, {"id": 2, "name": "Monitor-Codenames", "dlpEngines": [{"id": 101}, {"id": 102}]}],
        }

    def get(self, path, params=None):
        return self.routes.get(path, {"error": "nope"}), 200 if path in self.routes else 404


def test_corpus_test_reports_predefined_engines_and_rules():
    corpus = "Project Falcon budget. Card 4111 1111 1111 1111, SSN 123-45-6788. Quarterly balance sheet attached."
    out = eff.corpus_test(FakeClient(), corpus)
    assert out["dicts_tested"] == 1 and out["results"][0]["total_hits"] == 1
    pre = {r["name"]: r for r in out["predefined"]}
    assert pre["Credit Cards"]["simulated"] and pre["Credit Cards"]["hits"] == 1 and pre["Credit Cards"]["samples"] == ["•••• •••• •••• 1111"]
    assert pre["Social Security Numbers"]["hits"] == 1
    assert pre["Financial Statements"]["simulated"] is False and "machine learning" in pre["Financial Statements"]["note"]
    eng = {e["name"]: e for e in out["engines"]}
    assert eng["PCI"]["verdict"] == "fires" and eng["PCI"]["rules"] == ["Block-PCI"]
    assert eng["Codename + SSN"]["verdict"] == "fires" and eng["Codename + SSN"]["rules"] == ["Monitor-Codenames"]
    assert eng["Financials"]["verdict"] == "possible" and eng["Nothing"]["verdict"] == "does not fire"
    assert out["engines_firing"] == 2 and out["engines_possible"] == 1 and out["predefined_simulated"] == 2
    assert eng["PCI"]["dictionaries"] == ["Credit Cards"] and "4111" not in str(out)


def test_sum_groups_are_totalled():
    assert ce.evaluate_expression("((D1.S + D2.S + D3.S) > 4)", {1: 2, 2: 3, 3: 0})[0] is True
    assert ce.evaluate_expression("((D1.S + D2.S) > 4)", {1: 2, 2: 1})[0] is False
    r = ce.evaluate_expression("((D1.S + D2.S) > 4) AND (D3.S > 0)", {1: 2, 2: None, 3: 1})
    assert r[0] is None and "Sum(D1.S + D2.S) > 4: unknown" in r[2][0]
