"""Zscaler Made Easy is open source under the Apache License 2.0.

LICENSE is the exact Apache-2.0 text, NOTICE carries the attribution, and
every hand-written document, every generated one and the app's help page
and Advanced settings carry the same open-source note (open_source.py)
near the top. The old internal-use, not-for-redistribution terms are gone.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tools")]

import open_source  # noqa: E402

# The owner's wording, word for word (only the markup may change).
OWNER_WORDING = ("**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). "
                 "It is built entirely from information provided by Zscaler (its public documentation, public API and "
                 "open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an "
                 "official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.")

# SHA-256 of the official Apache License 2.0 text (apache.org/licenses/LICENSE-2.0.txt).
APACHE_2_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

# Markdown in the agent workspace that routes AI agents through one step of
# work, under token budgets (tools/agent_workspace.py): rules and stage
# instructions, not documentation. The workspace's IDENTITY.md, read first by
# every agent, and its references carry the note. Run folders (output/) are
# local hand-offs and are skipped.
EXEMPT_PREFIXES = ("agent-workspace/output/", "agent-workspace/_config/", "agent-workspace/stages/")
EXEMPT_FILES = {"agent-workspace/CONTEXT.md": "routing only, under a 450-token budget",
                "agent-workspace/references/_index.md": "the references' table of contents, read by agents only"}

# The note must come before the document's first section: within this many
# lines of the top (front matter and the title come first).
NEAR_TOP_LINES = 12

OLD_TERMS = ("not for redistribution", "internal tooling", "internal use only", "proprietary, internal use",
             "all rights reserved", "may not be redistributed")


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as f:
        return f.read()


def _flat(text: str) -> str:
    """Whitespace collapsed, HTML tags and Markdown bold removed."""
    text = re.sub(r"<[^>]+>", "", text).replace("**", "")
    return " ".join(text.split())


def _markdown_files() -> list[str]:
    """Every Markdown file in the repository (git's list; a walk without git)."""
    try:
        out = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30).stdout
        files = [p for p in out.splitlines() if p]
    except (OSError, subprocess.SubprocessError):
        files = []
        for base, dirs, names in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d == ".agents" or not (d.startswith(".") or d in {"node_modules", "venv", "build", "dist", "__pycache__"})]
            files += [os.path.relpath(os.path.join(base, n), ROOT).replace(os.sep, "/") for n in names if n.endswith(".md")]
    return sorted(p for p in files if os.path.exists(os.path.join(ROOT, p)))


def _documents() -> list[str]:
    return [p for p in _markdown_files() if not p.startswith(EXEMPT_PREFIXES) and p not in EXEMPT_FILES]


def test_the_note_is_the_owners_exact_wording():
    """SSDF PS.3.1 · CWE-1059: the one note every document carries is the owner's wording, word for word, and its plain form only drops the markup."""
    assert open_source.NOTE_MD == OWNER_WORDING
    assert open_source.NOTE_TEXT == OWNER_WORDING.replace("**", "")
    assert open_source.NOTE_BODY.startswith("Zscaler Made Easy is open-source software") and open_source.NOTE_BODY.endswith("Zscaler, Inc.")


def test_license_is_the_exact_apache_2_text():
    """SSDF PS.3.1 · Scorecard License · CWE-1059: LICENSE is the official Apache License 2.0 text, byte for byte (line endings aside), with nothing added."""
    with open(os.path.join(ROOT, "LICENSE"), "rb") as f:
        data = f.read().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == APACHE_2_SHA256
    # Boundary: one changed character is a different licence file.
    assert hashlib.sha256(data.replace(b"Version 2.0", b"Version 2.1", 1)).hexdigest() != APACHE_2_SHA256


def test_notice_names_the_project_the_owner_the_note_and_the_third_party_notices():
    """SSDF PS.3.1 · Scorecard License · CWE-1059: NOTICE (carried with every copy, Apache-2.0 section 4(d)) names the project and its copyright holder, carries the note and points at THIRD_PARTY_NOTICES.md."""
    notice = _read("NOTICE")
    assert notice.startswith("Zscaler Made Easy\nCopyright 2026 the repository owner\n")
    assert open_source.NOTE_BODY in _flat(notice)
    assert "THIRD_PARTY_NOTICES.md" in notice and "third_party_licenses/" in notice


def test_the_documents_are_found():
    """CWE-1059: the document list covers the top-level guides, docs/, the skills, the packs' Terraform and the generated files (an empty list would pass the next test)."""
    docs = set(_documents())
    for rel in ("README.md", "INSTALL.md", "SECURITY.md", "CHANGELOG.md", "THIRD_PARTY_NOTICES.md", "docs/OVERVIEW.md",
                "docs/SECURITY_TESTING.md", "docs/QUALITY_SCORE.md", "skills/zscaler-made-easy/SKILL.md",
                "agent-workspace/IDENTITY.md", "agent-workspace/references/architecture.md",
                "agent-workspace/references/assumed.md", "terraform/cjis_policy_pack/README.md"):
        assert rel in docs, rel
    assert not any(p.startswith("agent-workspace/output/") for p in docs)


@pytest.mark.parametrize("rel", _documents())
def test_every_document_carries_the_note_near_the_top(rel):
    """SSDF PS.3.1 · CWE-1059: every hand-written and generated Markdown document carries the open-source note before its first section."""
    lines = _read(rel).splitlines()
    top = [i for i, line in enumerate(lines[:NEAR_TOP_LINES + 8]) if open_source.NOTE_MD in line]
    assert top, f"{rel} lacks the open-source note"
    first_section = next((i for i, line in enumerate(lines) if line.startswith("## ")), len(lines))
    start = lines.index("---", 1) + 1 if lines and lines[0] == "---" else 0
    assert top[0] - start < NEAR_TOP_LINES and top[0] < first_section, f"{rel}: the note is not near the top (line {top[0] + 1})"


def test_the_generators_write_the_note():
    """SSDF PS.3.1 · CWE-1059: the generated documents get the note from their generators, so regenerating keeps it (pack Terraform READMEs, the standalone README, the pack notes)."""
    import build_standalone
    import pack_terraform
    import pack_from_design
    import quality_score
    import sbom_enrich
    import security_test_matrix
    import agent_workspace
    assert open_source.NOTE_TEXT in " ".join(build_standalone.README.split())
    for mod in (pack_terraform, pack_from_design, quality_score, sbom_enrich, security_test_matrix, agent_workspace):
        assert mod.NOTE_MD is open_source.NOTE_MD, mod.__name__
    assert agent_workspace.compile_architecture().split("\n")[2] == open_source.NOTE_MD


def test_the_help_page_and_advanced_settings_show_the_note():
    """WCAG 2.2 SC 1.3.1 · SC 2.4.6 · CWE-1059: the help page's About this app section and Advanced settings' App version and updates section show the note under their own heading, as static text."""
    hp = _read("static/help.html")
    assert '<section class="hp-sec" aria-labelledby="hpAboutH" id="about">' in hp and '<h2 id="hpAboutH">About this app</h2>' in hp
    assert '<a class="rp-btn" href="#about">About this app</a>' in hp
    about = hp.split('id="about">', 1)[1].split("</section>", 1)[0]
    assert open_source.NOTE_TEXT in _flat(about)
    adv = _read("static/report_advanced.html")
    update = adv.split('<section id="update"', 1)[1].split("</section>", 1)[0]
    assert '<h2 class="df-h" id="advUpdH">App version and updates</h2>' in update and 'id="advLicH">Licence</h3>' in update
    assert open_source.NOTE_TEXT in _flat(update)
    for page in (about, update):
        assert "http" not in page, "the note adds no link and no outbound call"


def test_no_document_licence_or_page_keeps_the_old_internal_use_terms():
    """SSDF PS.3.1 · CWE-1059: no document, LICENSE, NOTICE or page says the app is internal-use only or not for redistribution (the CHANGELOG's history excepted)."""
    names = [p for p in _markdown_files() if p != "CHANGELOG.md" and not p.startswith("agent-workspace/output/")] + ["LICENSE", "NOTICE"]
    names += ["static/" + n for n in sorted(os.listdir(os.path.join(ROOT, "static"))) if n.endswith((".html", ".js"))]
    found = [(n, t) for n in names for t in OLD_TERMS if t in " ".join(_read(n).split()).lower()]
    assert not found, found
    # The repository's visibility is the owner's choice: never stated as a fact.
    for name in ("README.md", "INSTALL.md", "GETTING_STARTED.md", "SECURITY.md"):
        text = " ".join(_read(name).split()).lower()
        assert "the repository is private, so" not in text and "this repository is public" not in text, name
