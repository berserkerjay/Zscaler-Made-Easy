"""The docs describe the release as it behaves.

* Export from tenant (PR #50): the CHANGELOG names its user-visible
  changes (an hourly rate refusal fails the export, short 429s are retried
  after a few seconds, an empty pick is refused before any tenant read, and
  Stop during the build gives no pack).
* The assessor's name is required for every pack push, so no doc may still
  say a missing assessor gives a ``DLP-Check`` tag.
"""
from pathlib import Path

import pack_export

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
POLICY_PACKS = (ROOT / "POLICY_PACKS.md").read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n## ", start + len(heading))
    return text[start: nxt if nxt != -1 else len(text)]


def _export_entry() -> str:
    day = _section(CHANGELOG, "## 2026-10-02")
    marker = "### Export from tenant"
    assert marker in day, "the 2026-10-02 CHANGELOG has no Export from tenant entry"
    start = day.index(marker)
    nxt = day.find("\n### ", start + len(marker))
    return day[start: nxt if nxt != -1 else len(day)]


def test_changelog_names_the_export_rate_limit_changes():
    entry = _export_entry()
    assert "hourly" in entry and "RetryTooLong" in entry
    assert "5 s" in entry and "15 s" in entry
    assert "full_reset" in entry          # no longer waits for the hour's window


def test_changelog_names_the_empty_pick_refusal_before_any_read():
    entry = _export_entry()
    assert pack_export.NOTHING_PICKED.split(":")[0] in entry   # "No rule was picked"
    assert "400" in entry and "before" in entry


def test_changelog_names_stop_during_the_build():
    entry = _export_entry()
    assert "Stop" in entry and "no pack" in entry


def test_no_doc_still_says_a_missing_assessor_gives_a_dlp_check_tag():
    assert "With no assessor name it still says DLP-Check" not in CHANGELOG
    assert "superseded on 2026-10-02" in CHANGELOG
    flat = " ".join(POLICY_PACKS.split())
    assert "only when no assessor is named" not in flat
    assert "in place of the assessor when none is named" not in flat
    assert "assessor's name is required" in flat
