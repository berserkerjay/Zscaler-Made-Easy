"""The standards mapping of the QA tests (docs/SECURITY_TESTING.md) stays
complete and current: every test in a QA file names the control it checks,
and the generated document matches the tests."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import security_test_matrix as stm  # noqa: E402


def test_every_qa_test_names_the_standard_it_checks():
    """SSDF PW.8.2 · ASVS V1.1.1: each test in a QA file opens its docstring with its ASVS / CWE / WSTG / WCAG / SLSA / SSDF mapping."""
    # Act
    _, unmapped, mapped = stm.collect()
    # Assert
    assert unmapped == [], "these QA tests name no standard on their docstring's first line: " + ", ".join(unmapped)
    assert mapped > 200


def test_every_listed_qa_file_exists():
    """SSDF PW.8.2: the QA file list names only files that exist, so a renamed file cannot drop out of the check unnoticed."""
    missing = [f for f in stm.QA_FILES if not os.path.exists(os.path.join(ROOT, "tests", f))]
    assert missing == []


def test_the_standards_document_is_current():
    """SSDF PW.8.2 · PO.3.2: docs/SECURITY_TESTING.md is regenerated whenever a mapped test changes (python tools/security_test_matrix.py)."""
    assert stm.main(["--check"]) == 0


def test_the_label_keeps_a_top_ten_category_with_its_colon():
    """SSDF PW.8.2: "A01:2021" in a mapping is read whole; the label ends at the first ': '."""
    by, _, _ = stm.collect()
    assert any(k.startswith("A0") and k.endswith(":2021") for k in by.get("OWASP Top 10 2021", {}))
