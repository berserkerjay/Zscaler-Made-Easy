"""The repository and the app are called Zscaler Made Easy. The repository's
first name (DLP-Check, dlp-check, dlpcheck) and the app's first name
(Zscaler Assessment) appear in no user-facing place: docs, downloads,
commands, Docker names, messages, clone URLs.

What stays is functional or keeps existing installs working, and is listed
below as exact strings in named files, each with its reason: environment
settings, HTTP header names, provenance tags on tenant objects and the
code that recognises them, cookie and browser-storage keys, the
extension's internal ids, the legacy clean-up code, and the command and
Docker names an install from before the rename still has. Anything else
that matches fails the guard, wherever it is added.

Not scanned: tests (they spell the old names to prove the paths above),
CHANGELOG.md (history), QA records and generated reports (docs/qa/,
docs/QUALITY_SCORE.md, docs/quality_score.json, docs/SECURITY_TESTING.md),
the generated SBOM (docs/sbom.cdx.json: its root component is the Python
distribution name, kept in pyproject.toml) and lock files. The older app
name in all its spellings is also guarded by tests/test_product_name.py.
"""
from __future__ import annotations

import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OLD = re.compile(r"DLP-Check|dlp-check|dlpcheck|Zscaler Assessment")

NOT_SCANNED = re.compile(r"^(tests/|docs/qa/)|^(CHANGELOG\.md|docs/QUALITY_SCORE\.md|docs/quality_score\.json"
                         r"|docs/SECURITY_TESTING\.md|docs/sbom\.cdx\.json)$|\.lock$")

# Allowed in any file: HTTP header names (clients and the extension send them)
# and the provenance tag written on tenant objects ("[DLP-Check pack x v1]"),
# which the deploy, removal and export code must keep recognising.
ANYWHERE = ("X-DLP-Check-Token", "X-DLP-Check-Mode", "[DLP-Check")

OLD_SHORTCUT = "Zscaler Assessment.lnk"

# Exact strings a file may contain, and why.
COMPAT = {
    # ── The installed distribution is still named dlp-check in pyproject.toml ─
    "cli_extras.py": {'md.version("dlp-check")'},
    # ── Provenance tags and the code that recognises them ─────────────
    "pack_deploy.py": {
        'DEFAULT_BY = "DLP-Check"',                       # what every tag written before assessor names says
        '("DLP-Check pack alpha")',                        # comment: the forged-name example
        r'r"(?i)^dlp-check(?=\s+(?:pack|baseline)\b)"',  # refuses an assessor name that forges the tag
        '"DLP-Check pack|baseline"',
    },
    "pack_terraform.py": {'"DLP-Check" in head', "older workspaces say DLP-Check"},
    # ── Names other software stores: changing them would lose data ─────
    "security.py": {'"dlpcheck_token"', '"dlpcheck_session"', '"dlpcheck_sso_login"'},   # cookie names
    "static/sidebar_order.js": {"'dlpcheck_sidebar_order_v1'"},                          # browser storage keys
    "static/update_beacon.js": {"'dlpcheck_update_dismissed'", "'dlpcheck_upstream_dismissed'"},
    "tenant_profiles.py": {'KEYRING_SERVICE = "dlp-check"'},                            # where remembered secrets are stored
    "store_crypto.py": {'KEYRING_SERVICE = "dlp-check"'},                              # the same keyring service (the store key)
    "server_acme.py": {'KEYRING_SERVICE = "dlp-check"'},                               # the same keyring service (the ACME DNS token)
    # ── The extension's internal ids (menu ids, script id, DOM marker) ─
    "browser_extension/background.js": {"'dlpcheck-link'", "'dlpcheck-selection'", "'dlpcheck-page'"},
    "browser_extension/common.js": {"'dlpcheck-console-badges'"},
    "browser_extension/console.js": {"data-dlpcheck-badge"},
    # ── Internal temporary names, never shown ─────────────────────────
    "pack_export.py": {'prefix="dlpcheck-export-"'},
    "UPDATE_Zscaler_Made_Easy.bat": {"dlpcheck_update.bat", OLD_SHORTCUT},
    # ── Legacy clean-up and the repository's earlier name ─────────────
    "app_update.py": {'UPSTREAM_ALIASES = ("berserkerjay/DLP-Check",)', OLD_SHORTCUT},
    "INSTALL_Zscaler_Made_Easy.bat": {OLD_SHORTCUT},
    "UNINSTALL_Zscaler_Made_Easy.bat": {OLD_SHORTCUT},
    # ── The Python distribution and the command aliases from before the rename
    "pyproject.toml": {'name = "dlp-check"', 'dlp-check = "dlp_api_server:main"',
                       'dlp-check-assess = "dlp_assessment_full_auto:main"', 'dlp-check-evaluate = "continuous_eval:main"'},
    "tools/sbom_enrich.py": {'"name": "dlp-check"'},
    "tools/verify_native_install.py": {OLD_SHORTCUT, "('zscaler-made-easy', 'dlp-check')",
                                       "{'dlp-check','dlp-check-assess','dlp-check-evaluate'}"},
    "install.sh": {"(the old name `dlp-check` still works)"},
    "README.md": {"(`dlp-check`, `dlp-check-assess`,\n`dlp-check-evaluate`) still work"},
    "docs/OVERVIEW.md": {"(`dlp-check`, `dlp-check-assess`,\n  `dlp-check-evaluate`) still work"},
    "INSTALL.md": {
        "`dlp-check`, `dlp-check-assess` and\n`dlp-check-evaluate`, still work",
        "a `DLP-Check` folder? That install keeps working",
        "container called `dlp-check`? Follow",
        "SECTION:### Moving to the new name",             # the migration note names every old Docker name
        '"dlp-check" entry: choose **Always Allow**',     # the Keychain prompt shows the keyring service's real name (KEYRING_SERVICE)
    },
    # ── The Docker image's own user (internal; owns files on existing volumes)
    "Dockerfile": {"groupadd --system dlpcheck && useradd --system --gid dlpcheck --home-dir /app --shell /usr/sbin/nologin dlpcheck",
                   "--chown=dlpcheck:dlpcheck", "chown dlpcheck:dlpcheck /data", "USER dlpcheck", "internal name dlpcheck"},
    # ── Moving Docker installs to the new names: find the old ones ─────
    "docker-compose.yml": {"<folder>_dlpcheck-data"},
    "update_container.sh": {
        "the container was dlp-check and\n# the data was on a volume called dlpcheck-data or <folder>_dlpcheck-data.",
        "'^(dlpcheck-data|.+_dlpcheck-data)$'", "# docker run -v dlpcheck-data, or compose's <project>_dlpcheck-data",
        "'^(dlp-check|.+-dlp-check-.+)$'", "# container_name dlp-check, or compose's <project>-dlp-check-1",
    },
    "update_container.ps1": {
        "the container was dlp-check and\n# the data was on a volume called dlpcheck-data or <folder>_dlpcheck-data.",
        "'^(dlpcheck-data|.+_dlpcheck-data)$'", "# docker run -v dlpcheck-data, or compose's <project>_dlpcheck-data",
        "'^(dlp-check|.+-dlp-check-.+)$'", "# container_name dlp-check, or compose's <project>-dlp-check-1",
    },
    ".github/workflows/tests.yml": {"SECTION:      - name: Moving to the new name copies the old data volume and keeps it"},
}


def _section(text: str, heading: str):
    """The span of a heading's section: to the next "---" rule (docs) or the next step (workflow)."""
    start = text.find(heading)
    if start < 0:
        return None
    if heading.lstrip().startswith("- name:"):
        nxt = text.find("\n      - ", start + len(heading))
    else:
        nxt = text.find("\n---\n", start)
    return start, (len(text) if nxt < 0 else nxt)


def _tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p and not NOT_SCANNED.search(p)]


def _text(rel):
    try:
        with open(os.path.join(ROOT, rel), "rb") as f:
            data = f.read()
    except OSError:   # deleted in the working tree
        return None
    if b"\0" in data[:8192]:
        return None   # binary
    return data.decode("utf-8", "replace").replace("\r\n", "\n")


def offenders(rel, text):
    """Each old-name match in `text` not covered by an allowed string of the file (or of every file)."""
    spans = []
    for token in (*ANYWHERE, *COMPAT.get(rel, ())):
        if token.startswith("SECTION:"):
            span = _section(text, token[len("SECTION:"):])
            spans += [span] if span else []
        else:
            spans += [(m.start(), m.end()) for m in re.finditer(re.escape(token), text)]
    bad = []
    for m in OLD.finditer(text):
        if not any(a <= m.start() and m.end() <= b for a, b in spans):
            line = text.count("\n", 0, m.start()) + 1
            snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
            bad.append(f"{rel}:{line}: {m.group(0)!r} in …{snippet}…")
    return bad


# ── The guard ─────────────────────────────────────────────────────────

def test_no_user_facing_place_uses_an_old_name():
    """WCAG 2.2 SC 3.2.4 · SSDF PW.9.1: docs, downloads, commands and Docker names use Zscaler Made Easy only."""
    # Arrange
    files = _tracked()
    # Act
    bad = [hit for rel in files for hit in offenders(rel, _text(rel) or "")]
    # Assert
    assert not bad, "an old name is still used (rename it, or add it to COMPAT with the reason):\n" + "\n".join(bad[:80])


def test_every_allowance_is_still_needed():
    """WCAG 2.2 SC 3.2.4: an exception whose string has gone from its file is removed from the list, so it cannot hide a new use."""
    stale = []
    for rel, tokens in COMPAT.items():
        text = _text(rel) or ""
        for token in tokens:
            found = _section(text, token[len("SECTION:"):]) if token.startswith("SECTION:") else token in text
            if not found or not (OLD.search(token) or token.startswith("SECTION:")):
                stale.append(f"{rel}: {token}")
    assert not stale, stale


def test_no_file_name_carries_the_repositorys_old_name():
    """WCAG 2.2 SC 3.2.4: no tracked file is named after the repository's first name."""
    assert [rel for rel in _tracked() if re.search(r"(?i)dlp-?check", os.path.basename(rel))] == []


@pytest.mark.parametrize("sample", [
    "docker logs dlp-check", "dlp-check:local", "-v dlpcheck-data:/data", "dlp-check-extension.zip",
    "https://github.com/berserkerjay/DLP-Check.git", "Documents\\DLP-Check", "DLP-Check-main",
    "LicenseRef-DLP-Check-Internal", "the dlp-check command", "Zscaler Assessment",
])
def test_the_guard_catches_each_old_user_facing_form(sample):
    """WCAG 2.2 SC 3.2.4: Docker names, downloads, clone URLs, folders, the licence id and commands are all caught."""
    assert offenders("README.md", f"see {sample} here") != []


@pytest.mark.parametrize("sample", [
    "Zscaler Made Easy", "zscaler-made-easy:local", "DLP_CHECK_HOST_PORT", "DLPCHECK_HIDDEN", "DLP-CHECK-QA",
    "X-DLP-Check-Token", "X-DLP-Check-Mode", "[DLP-Check pack pci v1]",
])
def test_the_guard_leaves_kept_forms_alone(sample):
    """WCAG 2.2 SC 3.2.4: settings, header names and provenance tags are functional and stay."""
    assert offenders("README.md", sample) == []


def test_an_allowed_string_is_allowed_only_in_its_own_file():
    """WCAG 2.2 SC 3.2.4: a compatibility string copied into another file is caught there."""
    assert offenders("security.py", 'UI_TOKEN_COOKIE = "dlpcheck_token"') == []
    assert offenders("README.md", 'UI_TOKEN_COOKIE = "dlpcheck_token"') != []
    assert offenders("security.py", '"dlpcheck_token" and docker logs dlp-check') != []


def test_the_migration_note_allows_old_names_only_inside_itself():
    """WCAG 2.2 SC 3.2.4: the INSTALL.md section that explains the move may name old volumes; the text after it may not."""
    text = "intro\n### Moving to the new name\nold volume dlpcheck-data\n\n---\n\nrun docker logs dlp-check\n"
    bad = offenders("INSTALL.md", text)
    assert len(bad) == 1 and "dlp-check" in bad[0] and ":7:" in bad[0]
