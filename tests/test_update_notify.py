"""Update notifications (update_notify): when the app's update check finds a
newer version, a notice on the digests' e-mail / webhook channel, off by
default and at most once per version. A recording fake sender; no network."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import update_notify as un

NEWER = {"update_available": True, "remote_commit": "abc1234", "local_commit": "9f8e7d6", "target_branch": "main"}


@pytest.fixture(autouse=True)
def _file(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_UPDATE_NOTIFY_FILE", str(tmp_path / "update_notify.json"))
    for k in ("DLP_CHECK_SMTP_HOST", "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK", "DLP_CHECK_SMTP_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path / "update_notify.json"


class Sender:
    def __init__(self, ok=True):
        self.sent, self.ok = [], ok

    def __call__(self, subject, body):
        self.sent.append((subject, body))
        return [{"channel": "webhook", "sent": self.ok}]


def test_off_by_default_nothing_is_sent():
    """ASVS V14.1.1 · CWE-1188: with the setting never turned on, a newer version sends nothing."""
    s = Sender()
    assert un.settings()["enabled"] is False
    assert un.maybe_notify(NEWER, send=s)["why"] == "update notifications are off"
    assert s.sent == []


def test_once_per_version():
    """ASVS V11.1.4 · CWE-799: the same version is announced once, however often the check runs; a newer one again."""
    un.save_settings(True)
    s = Sender()
    assert un.maybe_notify(NEWER, send=s)["sent"] is True
    assert un.maybe_notify(NEWER, send=s)["why"] == "already announced"
    assert un.maybe_notify(dict(NEWER, remote_commit="abc1234ffff"), send=s)["why"] == "already announced", "a longer form of the same commit"
    assert len(s.sent) == 1
    assert un.maybe_notify(dict(NEWER, remote_commit="def5678"), send=s)["sent"] is True
    assert len(s.sent) == 2


def test_a_notice_no_channel_took_is_tried_again():
    """ASVS V7.4.1 · CWE-390: a version nobody was told about is not recorded as announced."""
    un.save_settings(True)
    assert un.maybe_notify(NEWER, send=Sender(ok=False))["sent"] is False
    s = Sender()
    assert un.maybe_notify(NEWER, send=s)["sent"] is True and len(s.sent) == 1


def test_no_newer_version_or_a_bad_commit_sends_nothing():
    """ASVS V5.1.3 · CWE-20: no newer version, or a commit id that is not hex, sends nothing."""
    un.save_settings(True)
    s = Sender()
    assert un.maybe_notify(dict(NEWER, update_available=False), send=s)["sent"] is False
    assert un.maybe_notify(dict(NEWER, remote_commit="<script>"), send=s)["sent"] is False
    assert s.sent == []


def test_the_notice_carries_no_secret_and_uses_the_digest_channel(monkeypatch):
    """ASVS V8.3.4 · CWE-200 · CWE-532: the notice names branch and commits only; it goes out on the digests' webhook."""
    import continuous_eval as ce
    un.save_settings(True)
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "https://hooks.example.test/services/T000/SECRET-PART")
    posted = []
    monkeypatch.setattr(ce, "_send_webhook", lambda subject, body, url: posted.append((subject, body, url)) or {"channel": "webhook", "sent": True})
    out = un.maybe_notify(dict(NEWER, app_dir="/home/someone/app", restart_command=["secret-ish"]))
    assert out["sent"] is True and len(posted) == 1
    subject, body, _url = posted[0]
    assert "abc1234" in subject and "9f8e7d6" in body
    assert "/home/someone" not in body and "SECRET-PART" not in body + subject
    ov = un.overview()
    assert ov["channels"]["webhook"] is True and "SECRET-PART" not in json.dumps(ov)


def test_the_settings_file_is_owner_only_and_a_broken_one_means_off(_file):
    """ASVS V14.1.3 · CWE-732: saved owner-only; a hand-broken file reads as off, never an error."""
    un.save_settings(True)
    import os
    import stat
    assert stat.S_IMODE(os.stat(_file).st_mode) == 0o600
    _file.write_text("{not json")
    assert un.settings()["enabled"] is False


def test_the_setting_is_saved_by_a_writer_and_the_status_route_notifies(monkeypatch):
    """ASVS V4.1.1 · CWE-862 · WSTG-ATHZ-02: PUT /api/app/update/notify needs a writer; the update check triggers the notice."""
    import app_update
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.headers.update({security.UI_TOKEN_HEADER: security.ui_token()})
    r = c.put("/api/app/update/notify", json={"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    calls = []
    monkeypatch.setattr(srv, "_latest_remote_commit", lambda b: "abc1234")
    monkeypatch.setattr(app_update, "status", lambda d, remote, target: dict(NEWER))
    monkeypatch.setattr(srv, "_start_update_notice", lambda st: calls.append(st))
    st = c.get("/api/app/update/status").json()
    assert calls and calls[0]["remote_commit"] == "abc1234" and st["notify"]["enabled"] is True
    monkeypatch.setattr(security, "may_write", lambda: False)
    assert c.put("/api/app/update/notify", json={"enabled": False}).status_code == 403
