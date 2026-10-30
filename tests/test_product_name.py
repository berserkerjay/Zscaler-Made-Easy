"""The app is called Zscaler Made Easy. Its name before that appears in no
tracked file except where an existing install needs it.

This file and tests/test_old_repo_name.py (the guard for the repository's
first name, which forbids this one too) are the places that spell the old
name out, because it is what the guards look for. The other exceptions are
listed in COMPAT below, each with the reason, and are exact strings in
named files: anything else that matches fails the guard, wherever it is
added.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THIS = "tests/test_product_name.py"
# The other guard: it must name what it forbids, as this file does.
OTHER_GUARD = "tests/test_old_repo_name.py"

# Every spelling: any case, with a space, underscore, hyphen, line break or
# nothing between the words, and the longer "Platform" form.
OLD_NAME = re.compile(r"zscaler[\s_-]*(?:platform[\s_-]*)?assessment", re.I)

# Launchers kept under the old name. Each only hands over to the renamed
# file; desktop shortcuts and running builds from before the rename call them.
SHIMS = {
    "START_Zscaler_Assessment.bat": "START_Zscaler_Made_Easy.bat",
    "START_Zscaler_Assessment.vbs": "START_Zscaler_Made_Easy.vbs",
    "UPDATE_Zscaler_Assessment.bat": "UPDATE_Zscaler_Made_Easy.bat",
}
# History: entries describe what was true when they were written.
WHOLE_FILE = set(SHIMS) | {"CHANGELOG.md", THIS, OTHER_GUARD}

OLD_SHORTCUT = "Zscaler Assessment.lnk"
OLD_DATA_DIRS = {"ZscalerAssessment", "zscaler_assessment"}
OLD_CONFIG_KEY = "zscaler_assessment_config"

# Exact old-name strings a file may contain, and why.
COMPAT = {
    # The shortcut name from before the rename: install and update replace
    # it with "Zscaler Made Easy.lnk", uninstall removes both.
    "INSTALL_Zscaler_Made_Easy.bat": {OLD_SHORTCUT},
    "UPDATE_Zscaler_Made_Easy.bat": {OLD_SHORTCUT},
    "UNINSTALL_Zscaler_Made_Easy.bat": {OLD_SHORTCUT},
    "app_update.py": {OLD_SHORTCUT},
    # The native Windows check plants an old shortcut and starts the shims.
    "tools/verify_native_install.py": {OLD_SHORTCUT, "START_Zscaler_Assessment.vbs", "START_Zscaler_Assessment.bat"},
    # The per-user data folder under its old name is moved to the new one once.
    "zscaler_update_check.py": OLD_DATA_DIRS,
    # Settings saved in the browser under the old key are moved to the new key once.
    "static/index.html": {OLD_CONFIG_KEY},
    # The tests that prove the paths above.
    "tests/test_app_update.py": {OLD_SHORTCUT, *SHIMS},
    "tests/test_native_install_contracts.py": {OLD_SHORTCUT},
}


def _tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def _text(rel):
    try:
        with open(os.path.join(ROOT, rel), "rb") as f:
            data = f.read()
    except OSError:   # deleted in the working tree
        return None
    if b"\0" in data[:8192]:
        return None   # binary
    return data.decode("utf-8", "replace")


def offenders(rel, text):
    """Each old-name match in `text` that is not one of the file's allowed strings."""
    if rel in WHOLE_FILE:
        return []
    allowed = COMPAT.get(rel, set())
    spans = [(m.start(), m.end()) for token in allowed for m in re.finditer(re.escape(token), text)]
    bad = []
    for m in OLD_NAME.finditer(text):
        if not any(a <= m.start() and m.end() <= b for a, b in spans):
            line = text.count("\n", 0, m.start()) + 1
            bad.append(f"{rel}:{line}: {m.group(0)!r}")
    return bad


# ── The guard ─────────────────────────────────────────────────────────

def test_no_tracked_file_uses_the_old_name():
    """WCAG 2.2 SC 3.2.4: the product is identified by one name in the app, its files and its documents."""
    # Arrange
    files = _tracked()
    # Act
    bad = [hit for rel in files for hit in offenders(rel, _text(rel) or "")]
    # Assert
    assert not bad, "the old product name is still used:\n" + "\n".join(bad[:60])


def test_only_the_three_shims_keep_the_old_name_as_a_file_name():
    """WCAG 2.2 SC 3.2.4: no file name outside the legacy launchers carries the old name."""
    named = {rel for rel in _tracked() if OLD_NAME.search(rel)}
    assert named == set(SHIMS)


def test_every_allowance_is_still_needed():
    """WCAG 2.2 SC 3.2.4: an exception whose string has gone from its file is removed from the list, so it cannot hide a new use."""
    stale = [f"{rel}: {token}" for rel, tokens in COMPAT.items() for token in tokens if token not in (_text(rel) or "")]
    assert not stale, stale


@pytest.mark.parametrize("sample", [
    "Zscaler Assessment", "ZSCALER ASSESSMENT", "zscaler assessment", "Zscaler_Assessment", "zscaler-assessment",
    "ZscalerAssessment", "Zscaler\nAssessment", "Zscaler  Assessment", "Zscaler Platform Assessment",
    "zscaler_platform_assessment", "Zscaler-Platform-Assessment", "START_Zscaler_Assessment_WRITES_ENABLED.bat",
])
def test_the_guard_finds_every_spelling(sample):
    """WCAG 2.2 SC 3.2.4: case, separators, a line break and the Platform form are all caught."""
    assert offenders("README.md", f"see {sample} here") != []


@pytest.mark.parametrize("sample", ["Zscaler Made Easy", "the assessment", "a Zscaler tenant assessment",
                                    "DLP-Check", "DLP_CHECK_PORT", "dlp_assessment_full_auto.py"])
def test_the_guard_leaves_other_text_alone(sample):
    """WCAG 2.2 SC 3.2.4: the new name, the repository name and the word assessment on its own pass."""
    assert offenders("README.md", sample) == []


def test_an_allowed_string_is_allowed_only_in_its_own_file():
    """WCAG 2.2 SC 3.2.4: a compatibility string copied into another file is caught there."""
    assert offenders("app_update.py", f"x = '{OLD_SHORTCUT}'") == []
    assert offenders("README.md", f"x = '{OLD_SHORTCUT}'") != []
    assert offenders("app_update.py", f"x = '{OLD_SHORTCUT}' and Zscaler Assessment") != []


# ── The legacy launchers ──────────────────────────────────────────────

@pytest.mark.parametrize("shim, target", sorted(SHIMS.items()))
def test_each_shim_says_why_it_exists_and_its_target_is_tracked(shim, target):
    """an old launcher name is kept only as a documented hand-over, never as a second launcher."""
    text = _text(shim)
    comments = [l for l in text.splitlines() if l.lstrip().upper().startswith("REM ") or l.lstrip().startswith("'")]
    assert comments[0].split(None, 1)[1].startswith("Exists only for shortcuts made before the rename to Zscaler Made Easy")
    assert target in _tracked() and target in text
    code = [l for l in text.splitlines() if l.strip() and l not in comments]
    assert len(code) <= (13 if shim.endswith(".vbs") else 2), "a shim only hands over"


# ── Data kept across the rename ───────────────────────────────────────

def _data_dir_case(monkeypatch, tmp_path, platform):
    import zscaler_update_check as zu
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    return zu


def test_the_old_data_folder_is_moved_once_with_its_contents(monkeypatch, tmp_path):
    """the Beacon history and crawler finds in the old per-user folder survive the rename."""
    # Arrange
    zu = _data_dir_case(monkeypatch, tmp_path, "linux")
    old = tmp_path / "zscaler_assessment"
    old.mkdir()
    (old / "beacon_state.json").write_text('{"runs": [1]}')
    # Act
    d = zu.data_dir()
    # Assert
    assert d == str(tmp_path / "zscaler_made_easy") and not old.exists()
    assert json.loads((tmp_path / "zscaler_made_easy" / "beacon_state.json").read_text()) == {"runs": [1]}
    assert zu._cache_path() == os.path.join(d, "update_cache.json")


def test_windows_uses_the_new_folder_name_and_moves_the_old_one(monkeypatch, tmp_path):
    """on Windows the folder under %LOCALAPPDATA% is renamed the same way."""
    zu = _data_dir_case(monkeypatch, tmp_path, "win32")
    (tmp_path / "ZscalerAssessment").mkdir()
    (tmp_path / "ZscalerAssessment" / "bp_discovered.json").write_text("[]")
    assert zu.data_dir() == os.path.join(str(tmp_path), "ZscalerMadeEasy")
    assert (tmp_path / "ZscalerMadeEasy" / "bp_discovered.json").is_file()


def test_an_existing_new_folder_is_never_overwritten_by_the_old_one(monkeypatch, tmp_path):
    """when both folders exist the new one is used and the old one is left untouched."""
    zu = _data_dir_case(monkeypatch, tmp_path, "linux")
    (tmp_path / "zscaler_made_easy").mkdir()
    (tmp_path / "zscaler_made_easy" / "beacon_state.json").write_text("new")
    (tmp_path / "zscaler_assessment").mkdir()
    (tmp_path / "zscaler_assessment" / "beacon_state.json").write_text("old")
    assert zu.data_dir() == str(tmp_path / "zscaler_made_easy")
    assert (tmp_path / "zscaler_made_easy" / "beacon_state.json").read_text() == "new"
    assert (tmp_path / "zscaler_assessment" / "beacon_state.json").read_text() == "old"


def test_an_old_folder_that_cannot_be_moved_is_still_used(monkeypatch, tmp_path):
    """a folder that cannot be renamed (a file in it is open) is read where it is, never emptied."""
    zu = _data_dir_case(monkeypatch, tmp_path, "linux")
    (tmp_path / "zscaler_assessment").mkdir()
    def refuse(src, dst):
        raise PermissionError("in use")
    monkeypatch.setattr(zu.os, "rename", refuse)
    assert zu.data_dir() == str(tmp_path / "zscaler_assessment")
    assert not (tmp_path / "zscaler_made_easy").exists()


def test_a_linked_old_folder_is_not_followed(monkeypatch, tmp_path):
    """CWE-59: an old-name symbolic link is not moved into place as the data folder."""
    zu = _data_dir_case(monkeypatch, tmp_path, "linux")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "zscaler_assessment").symlink_to(elsewhere, target_is_directory=True)
    d = zu.data_dir()
    assert d == str(tmp_path / "zscaler_made_easy") and os.path.isdir(d) and not os.path.islink(d)
    assert (tmp_path / "zscaler_assessment").is_symlink()


@pytest.mark.parametrize("module, fn, name", [("bp_crawler", "_cache_path", "bp_crawl_cache.json"),
                                              ("zscaler_best_practices", "_discovered_store_path", "bp_discovered.json"),
                                              ("beacon", "state_path", "beacon_state.json")])
def test_every_store_in_the_data_folder_uses_the_new_name(monkeypatch, tmp_path, module, fn, name):
    """the crawler cache, the discovered best practices and the Beacon history share the renamed folder."""
    import importlib
    _data_dir_case(monkeypatch, tmp_path, "linux")
    monkeypatch.delenv("DLP_CHECK_BEACON_STATE", raising=False)
    path = getattr(importlib.import_module(module), fn)()
    assert path == os.path.join(str(tmp_path), "zscaler_made_easy", name)


_LS_HARNESS = r"""
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const start = html.indexOf("const LS_KEY = ");
const end = html.indexOf("\n", html.indexOf("})('", start));
const store = new Map(Object.entries(JSON.parse(process.argv[3])));
global.localStorage = { getItem: k => store.has(k) ? store.get(k) : null, setItem: (k, v) => store.set(k, String(v)),
                        removeItem: k => store.delete(k) };
eval(html.slice(start, end));
console.log(JSON.stringify(Object.fromEntries(store)));
"""


def _run_ls(tmp_path, store):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    h = tmp_path / "ls.js"
    h.write_text(_LS_HARNESS, encoding="utf-8")
    r = subprocess.run([node, str(h), os.path.join(ROOT, "static", "index.html"), json.dumps(store)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_settings_saved_under_the_old_key_are_moved_to_the_new_one(tmp_path):
    """the org, assessor and scope saved in the browser before the rename are still there after it."""
    out = _run_ls(tmp_path, {OLD_CONFIG_KEY: '{"org":"Acme"}'})
    assert out == {"zscaler_made_easy_config": '{"org":"Acme"}'}


def test_settings_saved_under_the_new_key_win_over_an_old_copy(tmp_path):
    """a newer save is never replaced by the old copy, and the old copy is removed."""
    out = _run_ls(tmp_path, {OLD_CONFIG_KEY: '{"org":"Old"}', "zscaler_made_easy_config": '{"org":"New"}'})
    assert out == {"zscaler_made_easy_config": '{"org":"New"}'}


def test_nothing_saved_stays_nothing_saved(tmp_path):
    """with nothing saved the move writes nothing."""
    assert _run_ls(tmp_path, {}) == {}
