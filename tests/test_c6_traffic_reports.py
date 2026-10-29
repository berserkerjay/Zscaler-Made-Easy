"""
Cloud wave 6 QA: traffic reports (bypass_report, ssl_coverage, ssl_flow,
insights, log_analyzer, detection_health).

Every test is offline: fakes and fixtures only, no tenant, no network, no
real clock (each time is injected). The first line of every docstring maps
the test to the standards it checks.
"""
from __future__ import annotations

import base64
import gzip
import io
import os
import re
import stat
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

import bypass_report as br
import detection_health as dh
import insights
import log_analyzer as la
import ssl_coverage as sc
import ssl_flow as sf

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
DAY_MS = insights.DAY_MS


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


# ═══ log_analyzer: uploads are untrusted ════════════════════════════════
@pytest.mark.parametrize("line, secret", [
    ("Authorization: Bearer 3f9a8b7c6d5e4f3a2b1c", "3f9a8b7c6d5e4f3a2b1c"),
    ('{"password":"hunter2","user":"a"}', "hunter2"),
    ("POST /oauth access_token=abcdef123456&x=1", "abcdef123456"),
    ("refresh_token: zzz111yyy", "zzz111yyy"),
    ("id_token=QWERTY12345", "QWERTY12345"),
    ("Set JSESSIONID=ABCDEF1234 for the portal", "ABCDEF1234"),
    ("enrol with provisioning_key=PK123abcXYZ", "PK123abcXYZ"),
    ("Cookie: sid=abc123; zs_auth=def456", "def456"),
    ("proxy-authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
])
def test_redact_hides_credentials_in_every_common_log_shape(line, secret):
    """ASVS V7.1.1 · A09:2021 · CWE-532 · WSTG-ERRH-01: a credential in an uploaded log line never reaches the evidence shown back."""
    out = la.redact(line)

    assert secret not in out and "redacted" in out


def test_redact_leaves_ordinary_log_text_alone():
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: lines with no credential are shown as they are (redaction is not a blanket wipe)."""
    line = "2026-09-01 08:00:04 ERR ZSATunnel: tunnel to gateway.zscalerthree.net dropped, reconnecting"

    assert la.redact(line) == line


def test_redact_of_a_long_hostile_line_is_linear():
    """ASVS V12.1.1 · CWE-1333 · WSTG-INPV-11: a 4 KB line of key-like words costs a linear scan, never a quadratic one."""
    import time
    line = ("a_" * 2040)[: la.MAX_LINE_CHARS]
    t0 = time.perf_counter()

    for _ in range(50):
        la.redact(line)

    assert time.perf_counter() - t0 < 1.0


def test_a_zip_with_thousands_of_entries_notes_the_member_cap_once(monkeypatch):
    """ASVS V12.1.1 · A04:2021 · CWE-400 · WSTG-BUSL-09: an archive past the member cap stops reading and says so once, not once per entry."""
    monkeypatch.setattr(la, "MAX_MEMBERS", 3)
    data = _zip([(f"f{i}.log", "2026-09-01 08:00:01 INF x\n") for i in range(400)])

    members, notes = la.expand([{"name": "many.zip", "content": _b64(data), "encoding": "base64"}])

    assert len(members) == 3
    assert sum("stopped after 3 files" in n for n in notes) == 1


def test_notes_about_skipped_members_are_capped(monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-09: thousands of oversized members give a bounded list of notes ending in a count of the rest."""
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 10)
    data = _zip([(f"big{i}.log", "X" * 50) for i in range(300)])

    _members, notes = la.expand([{"name": "big.zip", "content": _b64(data), "encoding": "base64"}])

    assert len(notes) <= la.MAX_NOTES + 1
    assert re.search(r"and \d+ more", notes[-1])


def test_a_gzip_bomb_is_refused_without_inflating_past_the_cap(monkeypatch):
    """ASVS V12.1.1 · CWE-409 · WSTG-BUSL-09: a .gz that inflates past the per-member cap is skipped; nothing past the cap is read."""
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 1024)
    bomb = gzip.compress(b"A" * 200_000)

    members, notes = la.expand([{"name": "ZSATray.log.gz", "content": _b64(bomb), "encoding": "base64"}])

    assert members == [] and any("larger than" in n for n in notes)


def test_a_tar_bomb_stops_at_the_total_cap(monkeypatch):
    """ASVS V12.1.1 · CWE-409 · WSTG-BUSL-09: a compressed tar is read as one stream that ends at the total cap."""
    monkeypatch.setattr(la, "MAX_TOTAL_BYTES", 4096)
    monkeypatch.setattr(la, "_TAR_SLACK", 0)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for i in range(4):
            data = b"2026-09-01 08:00:01 INF x\n" * 200
            info = tarfile.TarInfo(f"f{i}.log")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

    members, notes = la.expand([{"name": "b.tgz", "content": _b64(buf.getvalue()), "encoding": "base64"}])

    assert sum(len(d) for _, d in members) <= 4096
    assert any("stopped after" in n or "expands past" in n for n in notes)


def test_a_zip_member_name_is_never_a_path():
    """ASVS V12.3.1 · A01:2021 · CWE-22 · WSTG-ATHZ-01: a traversal or absolute member name is reduced to its last part and nothing is written."""
    data = _zip([("../../../../tmp/evil.log", "x\n"), ("/abs/C:\\Windows\\win.log", "y\n")])

    members, _ = la.expand([{"name": "../up.zip", "content": _b64(data), "encoding": "base64"}])

    assert [n for n, _ in members] == ["evil.log", "win.log"]


def test_a_huge_single_line_is_read_only_up_to_the_line_cap():
    """ASVS V12.1.1 · CWE-400 · CWE-1333 · WSTG-INPV-11: one multi-megabyte line is cut at MAX_LINE_CHARS before any pattern runs."""
    import time
    text = "2026-09-01 08:00:01 ERR " + "fail" * 500_000 + "\n"
    t0 = time.perf_counter()

    r = la.analyze_logs([("a.log", text)])

    assert time.perf_counter() - t0 < 1.5
    assert all(len(e["line"]) <= la.EVIDENCE_WIDTH for f in r["findings"] for e in f["evidence"])


def test_invalid_base64_is_a_plain_error_without_the_content():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: a broken upload is refused in plain words that do not echo the upload back."""
    with pytest.raises(ValueError) as e:
        la.analyze([{"name": "x.zip", "content": "@@SECRETPAYLOAD@@=", "encoding": "base64"}])

    assert "base64" in str(e.value) and "SECRETPAYLOAD" not in str(e.value)


def test_counts_of_log_findings_add_up():
    """ASVS V5.1.3 · CWE-682 · WSTG-BUSL-01: a finding's count equals the sum of its per-file counts, and levels count each line once."""
    a = "2026-09-01 08:00:01 ERR ZSATunnel: request timed out\n" * 6
    b = "2026-09-01 08:00:02 ERR ZSATunnel: request timed out\n" * 3

    r = la.analyze_logs([("a.log", a), ("b.log", b)])

    t = next(f for f in r["findings"] if f["key"] == "timeouts")
    assert t["count"] == 9 == sum(x["count"] for x in t["files"])
    assert r["levels"] == {"error": 9}
    assert sum(f["lines"] for f in r["files"]) == 9
