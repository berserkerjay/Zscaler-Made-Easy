"""Editorial audit of the app's own documents (tools/docs_audit.py, `--audit-docs`): it finds broken links and
anchors, skipped heading levels, a missing open-source note, earlier or misspelled product names, CHANGELOG dates
out of order, TODO and FIXME, glossary variants and (report only) very long sentences, reads only, and passes on
this repository. CI runs it with the rest of the tests."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tools")]

import docs_audit as da  # noqa: E402
import open_source  # noqa: E402

NOTE = open_source.NOTE_MD


OLD_PRODUCT = "Zscaler " + "Assessment"   # built, so tests/test_product_name.py does not count this fixture as a use

def make(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return str(tmp_path)


def rules(res, severity="error"):
    return sorted({(f["rule"], f["line"]) for f in res["findings"] if f["severity"] == severity})


def test_the_repository_documents_pass_the_audit():
    """CWE-1059 · WCAG 2.2 SC 3.2.4: README.md, INSTALL.md, CHANGELOG.md and docs/*.md have no error-level finding (CI runs this with the other tests)."""
    res = da.audit(ROOT)
    assert {"README.md", "INSTALL.md", "CHANGELOG.md", "docs/OVERVIEW.md"} <= set(res["files"])
    errors = [f"{f['file']}:{f['line']} [{f['rule']}] {f['message']}" for f in res["findings"] if f["severity"] == "error"]
    assert not errors, "\n".join(errors[:30])


def test_broken_links_and_anchors_are_found_with_file_and_line(tmp_path):
    """CWE-1059 · WSTG-INFO-07: a link to a missing file, and one to a heading that does not exist, are reported at their line; good links and code samples are not."""
    root = make(tmp_path, {"README.md": f"# T\n\n{NOTE}\n\n## Real heading\n\n[ok](docs/A.md#first-part) [bad file](docs/Nope.md) [bad anchor](docs/A.md#nope)\n"
                                        "[self](#real-heading) [web](https://example.com/x) `[code](missing.md)`\n```\n[fenced](missing.md)\n```\n",
                           "docs/A.md": f"# A\n\n{NOTE}\n\n## First part\n"})
    res = da.audit(root)
    msgs = [(f["file"], f["line"], f["message"]) for f in res["findings"] if f["rule"] == "broken-link"]
    assert [(m[0], m[1]) for m in msgs] == [("README.md", 7), ("README.md", 7)]
    assert "Nope.md" in msgs[0][2] and "#nope" in msgs[1][2]


def test_a_heading_that_skips_a_level_is_found(tmp_path):
    """WCAG 2.2 SC 1.3.1 · SC 2.4.6: ## then #### is an error at the #### line; going back up, and headings in a code fence, are fine."""
    root = make(tmp_path, {"README.md": f"# T\n\n{NOTE}\n\n## A\n\n#### Deep\n\n### Ok\n\n## B\n```\n###### in code\n```\n"})
    assert rules(da.audit(root)) == [("heading-skip", 7)]


def test_the_open_source_note_is_required_near_the_top(tmp_path):
    """SSDF PS.3.1 · CWE-1059: a document without the note before its first section is reported; with it, not."""
    root = make(tmp_path, {"README.md": "# T\n\n## A\n\ntext\n", "INSTALL.md": f"# I\n\n{NOTE}\n\n## A\n"})
    assert [(f["file"], f["rule"]) for f in da.audit(root)["findings"] if f["severity"] == "error"] == [("README.md", "open-source-note")]


def test_earlier_and_misspelled_product_names_are_found_but_history_and_compat_strings_are_not(tmp_path):
    """WCAG 2.2 SC 3.2.4: the earlier repo and app names and a misspelling are errors; the CHANGELOG (history), the kept command aliases and the file name ZscalerMadeEasy are not."""
    body = (f"# T\n\n{NOTE}\n\n## A\n\nThe DLP-Check tool.\n{OLD_PRODUCT} here.\nZscaler Made-Easy and Zscaler made easy.\n"
            "The `dlp-check` command still works. ZscalerMadeEasy-1.0.zip\n")
    root = make(tmp_path, {"README.md": body, "CHANGELOG.md": body.replace("## A", "## 2026-11-07")})
    found = [(f["file"], f["line"]) for f in da.audit(root)["findings"] if f["rule"] == "product-name"]
    assert found == [("CHANGELOG.md", 9), ("README.md", 7), ("README.md", 8), ("README.md", 9)]


def test_changelog_dates_must_descend(tmp_path):
    """CWE-1059: a date heading newer than the one above it, or repeated, is an error; descending dates are fine."""
    log = f"# Changelog\n\n{NOTE}\n\n## 2026-11-07\n\n- a\n\n## 2026-11-06\n\n## 2026-11-08\n\n## 2026-11-08\n\n## 2026-10-01\n"
    root = make(tmp_path, {"CHANGELOG.md": log})
    assert rules(da.audit(root)) == [("changelog-order", 11), ("changelog-order", 13)]


def test_todo_and_fixme_are_found(tmp_path):
    """CWE-1059: TODO and FIXME left in a document are errors; the word todo in lower case (the To-do page) is not."""
    root = make(tmp_path, {"README.md": f"# T\n\n{NOTE}\n\n## A\n\nTODO: write\nFIXME later\nThe todo page.\n"})
    assert rules(da.audit(root)) == [("todo", 7), ("todo", 8)]


def test_glossary_variants_are_found_outside_code(tmp_path):
    """WCAG 2.2 SC 3.2.4: Cloud and Branch Connector, Zidentity, One API and Client connector are errors in prose; the same words in code are not."""
    root = make(tmp_path, {"README.md": f"# T\n\n{NOTE}\n\n## A\n\nCloud and Branch Connector, Zidentity.\nThe One API and Client connector.\n`One API` is fine in code.\n"})
    assert [f["line"] for f in da.audit(root)["findings"] if f["rule"] == "glossary"] == [7, 7, 8, 8]


def test_very_long_sentences_are_reported_but_never_fail(tmp_path):
    """CWE-1059: a sentence over the limit is a note with its line and does not make the audit fail; boundary: exactly the limit is not reported."""
    long = " ".join(["word"] * (da.LONG_SENTENCE + 1)) + "."
    edge = " ".join(["word"] * da.LONG_SENTENCE) + "."
    root = make(tmp_path, {"README.md": f"# T\n\n{NOTE}\n\n## A\n\n{long}\n\n{edge}\n"})
    res = da.audit(root)
    assert rules(res, "note") == [("long-sentence", 7)] and res["counts"]["errors"] == 0
    assert da.main(["--root", root]) == 0


def test_the_audit_is_read_only_and_prints_file_line(tmp_path, capsys):
    """CWE-73 · CWE-459: the audit changes no file; the report names file:line, the rule and the severity, and exits 1 when an error is found."""
    root = make(tmp_path, {"README.md": f"# T\n\n{NOTE}\n\n## A\n\nTODO now\n"})
    before = {p: (os.path.getmtime(os.path.join(root, p)), open(os.path.join(root, p), "rb").read()) for p in os.listdir(root)}
    assert da.main(["--root", root]) == 1
    out = capsys.readouterr().out
    assert "README.md:7: [todo] error:" in out and "Nothing was changed." in out
    after = {p: (os.path.getmtime(os.path.join(root, p)), open(os.path.join(root, p), "rb").read()) for p in os.listdir(root)}
    assert before == after


def test_the_command_line_flag_runs_the_audit():
    """CWE-1059: dlp_assessment_full_auto.py --audit-docs prints the report for this repository and exits 0 without reading a tenant."""
    r = subprocess.run([sys.executable, os.path.join(ROOT, "dlp_assessment_full_auto.py"), "--audit-docs"], capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert r.returncode == 0, r.stdout[-500:] + r.stderr[-500:]
    assert "Docs audit:" in r.stdout and "0 error(s)" in r.stdout
    import dlp_assessment_full_auto as m
    assert "--audit-docs" in m.build_parser().format_help()
