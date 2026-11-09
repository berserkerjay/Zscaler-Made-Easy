"""Opt-in report delivery (report_delivery.py) and the log pipeline CLI (log_pipeline_cli.py).

Every transport is a fake: no network, no real credential store, no tenant.
"""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest

import log_pipeline_cli
import report_delivery as rd

SECRET = "S3cret-canary-pw"


class FakeKeyring:
    def __init__(self):
        self.d = {}

    def get_keyring(self):
        return self

    def set_password(self, svc, user, pw):
        self.d[(svc, user)] = pw

    def get_password(self, svc, user):
        return self.d.get((svc, user))


class FakeChan:
    def __init__(self, replies=b"\x00\x00\x00\x00", code=0):
        self.replies, self.code = replies, code

    def recv(self, n):
        r, self.replies = self.replies[:n], self.replies[n:]
        return r

    def recv_exit_status(self):
        return self.code

    def shutdown_write(self):
        pass


class FakeStream:
    def __init__(self, chan=None):
        self.channel, self.buf = chan or FakeChan(), io.BytesIO()

    def write(self, b):
        self.buf.write(b)

    def flush(self):
        pass


class FakeSFTPFile(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSSH:
    instances = []

    def __init__(self):
        FakeSSH.instances.append(self)
        self.sent, self.cmd, self.connected, self.policy = {}, None, None, None
        self.stdin = FakeStream()

    def load_system_host_keys(self):
        pass

    def load_host_keys(self, p):
        pass

    def set_missing_host_key_policy(self, p):
        self.policy = p

    def connect(self, host, **kw):
        self.connected = (host, kw)

    def open_sftp(self):
        outer = self

        class S:
            def open(self, path, mode):
                f = FakeSFTPFile()
                outer.sent[path] = f
                return f
        return S()

    def exec_command(self, cmd):
        self.cmd = cmd
        out = FakeStream()
        return self.stdin, out, None

    def close(self):
        pass


class FakeParamiko:
    SSHClient = FakeSSH

    class RejectPolicy:
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_REPORT_DELIVERY", str(tmp_path / "rd.json"))
    kr = FakeKeyring()
    monkeypatch.setattr(rd, "_keyring", lambda: kr)
    FakeSSH.instances.clear()
    monkeypatch.setattr(rd, "_paramiko", lambda: FakeParamiko)
    return kr


def _cfg(tr="sftp", enabled=True, hosts=("files.example.com",), host="files.example.com", **extra):
    t = {"transport": tr, "host": host, "user": "svc", "remote_dir": "/in"}
    t.update(extra)
    return rd.save_settings({"enabled": enabled, "allowed_hosts": list(hosts), "targets": {"t1": t}})


def test_off_by_default(env):
    """ASVS V1.14.6 · CWE-1188 · WSTG-CONF-01: delivery is off and has no targets until the operator turns it on."""
    s = rd.get_settings()
    assert s["enabled"] is False and s["targets"] == {} and s["allowed_hosts"] == []
    with pytest.raises(rd.DeliveryError, match="off"):
        rd.deliver("t1", "a.csv", b"x")


def test_non_allowlisted_host_refused_before_any_connection(env):
    """ASVS V12.6.1 · CWE-918 · WSTG-CLNT-07: a target whose host is not in the allowlist is refused and nothing connects."""
    _cfg(hosts=("other.example.com",))
    rd.set_credential("t1", SECRET)
    with pytest.raises(rd.DeliveryError, match="not in the allowed"):
        rd.deliver("t1", "a.csv", b"x")
    assert FakeSSH.instances == []


def test_wildcard_host_rejected(env):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: wildcards are not accepted in the allowlist."""
    with pytest.raises(rd.DeliveryError):
        rd.save_settings({"allowed_hosts": ["*.example.com"]})


def test_sftp_sends_to_fixed_folder_with_sanitised_name(env):
    """ASVS V12.3.1 · CWE-22 · WSTG-INPV-11: the remote path comes from the target; the file name is rebuilt, no traversal."""
    _cfg()
    rd.set_credential("t1", SECRET)
    r = rd.deliver("t1", "../../etc/pass wd.csv", b"a,b\n")
    c = FakeSSH.instances[0]
    assert list(c.sent) == ["/in/pass_wd.csv"] and c.sent["/in/pass_wd.csv"].getvalue() == b"a,b\n"
    assert isinstance(c.policy, FakeParamiko.RejectPolicy) and c.connected[1]["password"] == SECRET
    assert r["status"] == "sent" and SECRET not in json.dumps(r)


def test_scp_protocol(env):
    """ASVS V12.6.1 · CWE-319 · WSTG-CRYP-03: the SCP transport sends the file header, body and terminator over the SSH channel."""
    _cfg("scp")
    rd.set_credential("t1", SECRET)
    rd.deliver("t1", "r.csv", b"abc")
    c = FakeSSH.instances[0]
    assert c.cmd == "scp -t /in" and c.stdin.buf.getvalue() == b"C0600 3 r.csv\nabc\x00"


def test_ssh_push_uses_quoted_cat(env):
    """ASVS V5.3.8 · CWE-78 · WSTG-INPV-12: SSH push builds its remote command from validated, quoted parts only."""
    _cfg("ssh")
    rd.set_credential("t1", SECRET)
    rd.deliver("t1", "x;rm -rf.csv", b"z")
    c = FakeSSH.instances[0]
    assert c.cmd == "cat > /in/x_rm_-rf.csv" and c.stdin.buf.getvalue() == b"z"


def test_smb_uses_share_path(env, monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-CLNT-07: SMB delivery writes under the target's share and folder via the optional library."""
    calls = {}

    class FakeSmb:
        @staticmethod
        def register_session(host, **kw):
            calls["reg"] = (host, kw)

        @staticmethod
        def open_file(path, mode):
            buf = FakeSFTPFile()
            calls["path"], calls["buf"] = path, buf
            return buf
    monkeypatch.setattr(rd, "_smb", lambda: FakeSmb)
    _cfg("smb", share="reports", remote_dir="daily")
    rd.set_credential("t1", SECRET)
    rd.deliver("t1", "r.csv", b"q")
    assert calls["path"] == "\\\\files.example.com\\reports\\daily\\r.csv" and calls["buf"].getvalue() == b"q"


def test_not_installed_is_reported_gracefully(env, monkeypatch):
    """ASVS V1.14.2 · CWE-755 · WSTG-ERRH-01: without the optional libraries the feature says so and sends nothing."""
    monkeypatch.setattr(rd, "_paramiko", lambda: None)
    monkeypatch.setattr(rd, "_smb", lambda: None)
    _cfg()
    rd.set_credential("t1", SECRET)
    with pytest.raises(rd.DeliveryError, match="not installed"):
        rd.deliver("t1", "a.csv", b"x")
    assert rd.get_settings()["libraries"]["ssh"] is False


def test_credential_only_in_keyring_and_never_logged(env, monkeypatch):
    """ASVS V2.10.4 · CWE-532 · WSTG-ATHN-06: the password lives only in the credential store; failures, results, settings and audit never carry it."""
    _cfg()
    rd.set_credential("t1", SECRET)
    assert SECRET not in open(rd.store_path()).read()
    seen = []
    import audit
    monkeypatch.setattr(audit, "record", lambda ev, **kw: seen.append((ev, kw)))

    def boom(self, host, **kw):
        raise OSError(f"cannot reach with {SECRET}")
    monkeypatch.setattr(FakeSSH, "connect", boom)
    with pytest.raises(rd.DeliveryError) as e:
        rd.deliver("t1", "a.csv", b"x")
    assert SECRET not in str(e.value) and SECRET not in json.dumps(seen) and "OSError" in str(e.value)
    assert SECRET not in json.dumps(rd.get_settings())


def test_no_keyring_no_file_fallback(env, monkeypatch):
    """ASVS V2.10.3 · CWE-522 · WSTG-ATHN-07: with no credential store the password is refused, not written to a file."""
    monkeypatch.setattr(rd, "_keyring", lambda: None)
    with pytest.raises(rd.DeliveryError):
        rd.set_credential("t1", SECRET)
    _cfg()
    with pytest.raises(rd.DeliveryError):
        rd.deliver("t1", "a.csv", b"x")


def test_bad_remote_dir_and_transport_rejected(env):
    """ASVS V5.1.3 · CWE-22 · WSTG-INPV-11: traversal in the remote folder and unknown transports are refused."""
    with pytest.raises(rd.DeliveryError):
        _cfg(remote_dir="/in/../etc")
    with pytest.raises(rd.DeliveryError):
        _cfg("ftp")


def test_cron_matching():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: five-field cron expressions match as expected and bad ones are refused."""
    t = datetime(2026, 11, 9, 6, 30, tzinfo=timezone.utc)   # a Monday
    assert rd.cron_matches("30 6 * * 1", t) and rd.cron_matches("*/15 6 * * 1-5", t)
    assert not rd.cron_matches("0 6 * * *", t)
    with pytest.raises(rd.DeliveryError):
        rd.check_cron("61 * * * *")
    with pytest.raises(rd.DeliveryError):
        rd.check_cron("* * *")


def test_tick_sends_newest_once_per_minute(env, monkeypatch):
    """ASVS V1.14.6 · CWE-770 · WSTG-BUSL-05: a due schedule sends the newest report once; scheduled work only sends, nothing else."""
    _cfg()
    rd.save_settings({"schedule": {"enabled": True, "cron": "30 6 * * *", "target": "t1"}})
    rd.set_credential("t1", SECRET)
    sent = []

    def fake_deliver_saved(target, name, trigger="manual"):
        sent.append((target, name, trigger))
        return {"status": "sent"}
    monkeypatch.setattr(rd, "deliver_saved", fake_deliver_saved)   # restored after the test
    at = datetime(2026, 11, 9, 6, 30, 20, tzinfo=timezone.utc)
    assert rd.tick(at, newest=lambda: "n.json")["status"] == "sent"
    assert rd.tick(at, newest=lambda: "n.json") is None
    assert rd.tick(datetime(2026, 11, 9, 7, 30, tzinfo=timezone.utc), newest=lambda: "n.json") is None
    assert sent == [("t1", "n.json", "schedule")]


def test_tick_off_when_disabled(env):
    """ASVS V1.14.6 · CWE-1188 · WSTG-CONF-01: a schedule does nothing while the feature is off."""
    rd.save_settings({"schedule": {"enabled": True, "cron": "* * * * *", "target": ""}})
    assert rd.tick(datetime(2026, 11, 9, 6, 30, tzinfo=timezone.utc), newest=lambda: "n.json") is None


def test_cli_health_and_selftest(env, capsys):
    """ASVS V1.14.2 · CWE-200 · WSTG-INFO-05: the CLI reports health and a self-test as JSON and shows no credential or setting value of a target."""
    assert log_pipeline_cli.main(["selftest"]) == 0
    assert log_pipeline_cli.main(["health"]) == 0
    out = capsys.readouterr().out
    assert '"delivery"' in out and SECRET not in out


def test_cli_refuses_with_one_line(env, capsys):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: a refused delivery from the CLI exits 1 with one error line."""
    assert log_pipeline_cli.main(["deliver", "20240101-000000-abcdefgh.json", "t1"]) == 1
    assert capsys.readouterr().err.startswith("error:")
