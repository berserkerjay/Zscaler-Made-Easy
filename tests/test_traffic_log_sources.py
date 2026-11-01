"""Traffic and session logs without an upload, and the session filter:

* the session list filtered by Client Connector version and platform, on the
  page and in its downloads (traffic_logs.filter_sessions, the export route);
* the opt-in daily report from a watched folder (traffic_log_watch.py): off
  by default, read-only on the folder, plain files only, capped, counts only
  by default, bounded retention of its own reports, writer-only settings;
* the optional syslog listener (syslog_listener.py): off by default, binds
  127.0.0.1 unless another address and allow_remote are both given, UDP and
  TCP with size, rate, buffer and connection caps, headers stripped, lines
  read as untrusted, kept in memory only.

Fixtures are synthetic (made-up users at example.com, documentation
addresses). The listener tests send to 127.0.0.1 only, on a port the
system picks; no tenant and no outside network are touched."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import syslog_listener as sl
import traffic_log_watch as tw
import traffic_logs as tl
from test_traffic_logs import T0, ctime, iso, lines, status, upload, web


def _sessions_report():
    recs = [status("s1", "ann@example.com", T0, auth=T0, unauth=T0 + timedelta(minutes=30), st="ZPN_STATUS_DISCONNECTED", version="4.4.0.300", platform="windows"),
            status("s2", "bob@example.com", T0, auth=T0, unauth=T0 + timedelta(minutes=20), st="ZPN_STATUS_DISCONNECTED", version="4.5.0.334", platform="mac"),
            status("s3", "cat@example.com", T0, auth=T0, unauth=T0 + timedelta(minutes=10), st="ZPN_STATUS_DISCONNECTED", version="4.5.0.334", platform="windows")]
    return tl.analyze(upload(lines(*recs)))


@pytest.fixture
def api(monkeypatch, tmp_path):
    import dlp_api_server as srv
    import security
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    yield c
    sl.stop(clear=True)


# ── Session filter ───────────────────────────────────────────────────
def test_the_session_list_filters_by_client_connector_version_and_platform():
    """ASVS V5.1.3 · CWE-20: the session list keeps only the sessions of the Client Connector version and/or platform picked (exact, as the log wrote it); the counts stay those of all the logs and the filter is named."""
    # Arrange
    rep = _sessions_report()
    # Act
    by_version = tl.filter_sessions(rep, version="4.5.0.334")
    both = tl.filter_sessions(rep, version="4.5.0.334", platform="windows")
    choices = tl.session_choices(rep)
    # Assert
    assert {r["user"] for r in by_version["zpa"]["status"]["rows"]} == {"bob@example.com", "cat@example.com"}
    assert [r["user"] for r in both["zpa"]["status"]["rows"]] == ["cat@example.com"]
    assert both["session_filter"] == {"version": "4.5.0.334", "platform": "windows"}
    assert by_version["zpa"]["status"]["sessions"] == rep["zpa"]["status"]["sessions"] == 3
    assert len(rep["zpa"]["status"]["rows"]) == 3, "the report itself is unchanged"
    assert choices["version"] == ["4.4.0.300", "4.5.0.334"]
    assert tl.filter_sessions(rep) is rep


def test_the_export_keeps_only_the_filtered_sessions_and_refuses_a_bad_value(api):
    """ASVS V5.1.3 · V5.3.1 · CWE-20 · CWE-116 · WSTG-INPV-01: the CSV download with names keeps only the filtered sessions and says the filter in its summary; a filter value with control characters is a 400."""
    # Arrange
    recs = [status("s1", "ann@example.com", T0, auth=T0, unauth=T0 + timedelta(minutes=30), st="ZPN_STATUS_DISCONNECTED", version="4.4.0.300"),
            status("s2", "bob@example.com", T0, auth=T0, unauth=T0 + timedelta(minutes=20), st="ZPN_STATUS_DISCONNECTED", version="4.5.0.334")]
    rid = api.post("/api/traffic-logs/analyze", json={"files": upload(lines(*recs))}).json()["report_id"]
    # Act
    r = api.get(f"/api/traffic-logs/report/{rid}/export", params={"format": "csv", "names": "true", "version": "4.5.0.334"})
    bad = api.get(f"/api/traffic-logs/report/{rid}/export", params={"format": "csv", "names": "true", "version": "4.5\n=cmd"})
    # Assert
    assert r.status_code == 200
    session_rows = [ln for ln in r.text.splitlines() if ln.startswith("ZPA session list,")]
    assert any("bob@example.com" in ln for ln in session_rows) and not any("ann@example.com" in ln for ln in session_rows)
    assert "Sessions listed: version is,4.5.0.334" in r.text
    assert bad.status_code == 400


# ── Daily report from a watched folder ───────────────────────────────
def _folder(tmp_path):
    d = tmp_path / "lss"
    d.mkdir()
    (d / "user-status.json").write_text(lines(status("s1", "ann@example.com", T0, auth=T0, unauth=T0 + timedelta(minutes=30),
                                                     st="ZPN_STATUS_DISCONNECTED")), encoding="utf-8")
    (d / "web.json").write_text(lines(web(T0), web(T0 + timedelta(minutes=1), action="Blocked")), encoding="utf-8")
    return d


def _fingerprint(d):
    out = {}
    for root, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(root, n)
            st = os.lstat(p)
            out[os.path.relpath(p, d)] = (st.st_mode, st.st_size, st.st_mtime_ns,
                                          hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) and not os.path.islink(p) else "")
    return out


def test_the_daily_report_is_off_by_default(monkeypatch, tmp_path):
    """ASVS V1.14.6 · V14.1.3 · CWE-1188: with nothing set, the daily report is off, has no folder, keeps no names and is never due."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    # Act
    st = tw.get_state()
    # Assert
    assert st["settings"] == {"enabled": False, "folder": "", "hour": 6, "names": False, "keep": 7}
    assert st["next_run"] is None and st["last_run"] is None and tw.due() is False


@pytest.mark.parametrize("folder,why", [("", "Type the folder"), ("relative/logs", "full path"), ("/no/such/folder/zme", "does not exist"),
                                        ("/", "root"), ("/tmp/x\nrm", "control characters")])
def test_the_watched_folder_is_checked(monkeypatch, tmp_path, folder, why):
    """ASVS V5.1.3 · V12.3.1 · CWE-22 · CWE-73: the folder must be a full path to an existing folder, not a drive root and without control characters."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    # Act / Assert
    with pytest.raises(tw.WatchError, match=why):
        tw.check_folder(folder)


def test_the_saved_reports_folder_cannot_be_watched(monkeypatch, tmp_path):
    """ASVS V12.3.1 · CWE-73: the app's own saved reports folder (or one inside it) is refused as the watched folder."""
    # Arrange
    saved = tmp_path / "saved"
    (saved / "inner").mkdir(parents=True)
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(saved))
    # Act / Assert
    for f in (saved, saved / "inner"):
        with pytest.raises(tw.WatchError, match="saved reports"):
            tw.check_folder(str(f))


def test_a_run_reads_only_plain_log_files_and_never_changes_the_folder(monkeypatch, tmp_path):
    """ASVS V12.3.1 · V12.3.2 · CWE-59 · CWE-22 · CWE-552: a run reads only regular log files directly in the folder (no link, sub-folder, hidden file or other extension), saves a counts-only report, and leaves every file and folder exactly as it was."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    d = _folder(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text(lines(web(T0, user="leak@example.com")), encoding="utf-8")
    os.symlink(secret, d / "link.json")
    (d / "sub").mkdir()
    (d / "sub" / "deep.json").write_text(lines(web(T0, user="deep@example.com")), encoding="utf-8")
    (d / ".hidden.json").write_text(lines(web(T0, user="hidden@example.com")), encoding="utf-8")
    (d / "notes.exe").write_bytes(b"MZ" + b"\0" * 10)
    tw.save_settings({"enabled": True, "folder": str(d), "hour": 0, "keep": 3})
    before = _fingerprint(d)
    # Act
    rec = tw.run(trigger="manual")
    # Assert
    assert rec["status"] == "saved" and rec["files"] == 2, rec
    assert _fingerprint(d) == before, "the folder is read-only to the app"
    assert any("link.json" in n for n in rec["notes"])
    saved = tl.load_saved(rec["report"])
    text = json.dumps(saved)
    assert saved["counts_only"] is True and "ann@example.com" not in text
    for other in ("leak@example.com", "deep@example.com", "hidden@example.com"):
        assert other not in text
    assert saved["input"]["records"] == 3


def test_the_next_run_reads_only_files_changed_since_the_last(monkeypatch, tmp_path):
    """ASVS V11.1.4 · CWE-400: a second run reads only files changed after the first; with none, it saves nothing ("nothing new")."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    d = _folder(tmp_path)
    tw.save_settings({"enabled": True, "folder": str(d), "hour": 0})
    first = tw.run(trigger="manual", now=datetime.now(timezone.utc) + timedelta(seconds=2))
    # Act
    again = tw.run(trigger="manual", now=datetime.now(timezone.utc) + timedelta(seconds=4))
    later = time.time() + 10
    (d / "new.json").write_text(lines(web(T0)), encoding="utf-8")
    os.utime(d / "new.json", (later, later))
    third = tw.run(trigger="manual", now=datetime.now(timezone.utc) + timedelta(seconds=20))
    # Assert
    assert first["status"] == "saved" and first["files"] == 2
    assert again["status"] == "nothing new" and again["files"] == 0 and again["report"] is None
    assert third["status"] == "saved" and third["files"] == 1


def test_a_run_keeps_names_only_when_asked_and_respects_the_caps(monkeypatch, tmp_path):
    """ASVS V8.3.4 · V12.1.1 · CWE-359 · CWE-400: names are kept only with the names setting; files past the per-file size and the file count are listed as not read."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    d = _folder(tmp_path)
    (d / "big.log").write_text("x" * 5000, encoding="utf-8")
    monkeypatch.setattr(tw, "MAX_FILE_BYTES", 4000)
    tw.save_settings({"enabled": True, "folder": str(d), "hour": 0, "names": True})
    # Act
    rec = tw.run(trigger="manual")
    monkeypatch.setattr(tw, "MAX_FILES", 1)
    got = tw.collect(str(d), None)
    # Assert
    assert rec["status"] == "saved" and any("big.log" in n and "larger than" in n for n in rec["notes"])
    assert "ann@example.com" in json.dumps(tl.load_saved(rec["report"])), "names kept when asked"
    assert len(got["files"]) == 1 and any("more than 1 changed files" in n for n in got["notes"])


def test_retention_trims_only_the_reports_the_daily_run_made(monkeypatch, tmp_path):
    """ASVS V8.3.8 · CWE-404: with keep = 2, older daily reports are deleted after each run, and a report saved by hand is never touched."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    d = _folder(tmp_path)
    by_hand = tl.save_report(tl.analyze(upload(lines(web(T0)))), "by hand")
    tw.save_settings({"enabled": True, "folder": str(d), "hour": 0, "keep": 2})
    made = []
    # Act
    for i in range(4):
        t = time.time() + 100 * (i + 1)
        os.utime(d / "web.json", (t, t))
        time.sleep(1.05)   # saved report names carry the second
        made.append(tw.run(trigger="manual", now=datetime.fromtimestamp(t + 1, timezone.utc))["report"])
    names = {x["name"] for x in tl.list_saved()}
    # Assert
    assert all(made)
    assert names == {by_hand["name"], made[2], made[3]}
    assert tw.get_state()["reports"] == made[2:]


def test_the_daily_report_is_due_once_a_day_after_its_hour(monkeypatch, tmp_path):
    """ASVS V11.1.2 · CWE-799: on, with a folder, it is due once the hour is reached and not again after a scheduled run that day; a run by hand does not count."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_WATCH", str(tmp_path / "watch.json"))
    d = _folder(tmp_path)
    local_now = datetime.now().astimezone().replace(hour=12, minute=0, second=0, microsecond=0)
    tw.save_settings({"enabled": True, "folder": str(d), "hour": 9})
    # Act / Assert
    assert tw.due(local_now.replace(hour=8)) is False
    assert tw.due(local_now) is True
    tw.run(trigger="manual", now=local_now)
    assert tw.due(local_now) is True, "a run by hand is not the daily run"
    tw.run(trigger="schedule", now=local_now)
    assert tw.due(local_now.replace(hour=13)) is False
    assert tw.due(local_now + timedelta(days=1)) is True


def test_the_watch_routes_need_the_writer_and_are_audited(api, monkeypatch, tmp_path):
    """ASVS V4.1.1 · V7.1.3 · CWE-285 · CWE-778 · WSTG-ATHZ-02: changing the daily report or running it now needs the writer (403 otherwise); each change and run is in the audit log; a bad folder is a 400."""
    # Arrange
    import security
    d = _folder(tmp_path)
    monkeypatch.setattr(security, "may_write", lambda: False)
    denied = api.post("/api/traffic-logs/watch", json={"enabled": True, "folder": str(d), "hour": 6})
    denied_run = api.post("/api/traffic-logs/watch/run")
    monkeypatch.setattr(security, "may_write", lambda: True)
    # Act
    bad = api.post("/api/traffic-logs/watch", json={"enabled": True, "folder": "relative", "hour": 6})
    ok = api.post("/api/traffic-logs/watch", json={"enabled": True, "folder": str(d), "hour": 6})
    ran = api.post("/api/traffic-logs/watch/run")
    # Assert
    assert denied.status_code == 403 and denied_run.status_code == 403
    assert bad.status_code == 400
    assert ok.status_code == 200 and ok.json()["settings"]["enabled"] is True and ok.json()["settings"]["names"] is False
    assert ran.status_code == 200 and ran.json()["last_run"]["status"] == "saved"
    log = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()
    mine = [ln for ln in log.splitlines() if '"event":"traffic_logs_watch_settings"' in ln or '"event": "traffic_logs_watch_settings"' in ln]
    assert mine and "traffic_logs_watch_run" in log
    assert all('"enabled":true' in ln.replace(" ", "") for ln in mine)


# ── Syslog listener ──────────────────────────────────────────────────
@pytest.mark.parametrize("raw,msg", [
    ("<134>Oct 31 10:00:00 nss01 zscaler-nss: 2026-10-31\tann\tblocked", "2026-10-31\tann\tblocked"),
    ("<14>1 2026-10-31T10:00:00Z lss01 zpa - - - {\"LogTimestamp\": \"x\"}", "{\"LogTimestamp\": \"x\"}"),
    ("<14>1 2026-10-31T10:00:00Z lss01 zpa 77 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\"] {\"a\": 1}", "{\"a\": 1}"),
    ("<14>Oct  1 01:02:03 host app[123]: hello", "hello"),
    ("{\"plain\": true}", "{\"plain\": true}"),
    ("<999", "<999"),
])
def test_the_syslog_header_is_taken_off(raw, msg):
    """ASVS V5.1.4 · CWE-20: RFC 3164 and RFC 5424 headers (priority, time, host, tag, structured data) are taken off; a line without one is kept as it is."""
    # Act / Assert
    assert sl.strip_header(raw) == msg


@pytest.mark.parametrize("kw,why", [
    ({"host": "10.0.0.5"}, "Allow other computers"),
    ({"host": "0.0.0.0"}, "every address"),
    ({"host": "localhost"}, "IP address"),
    ({"host": "224.0.0.1", "allow_remote": True}, "multicast"),
    ({"port": 514}, "1024"),
    ({"port": 70000}, "1024"),
    ({"protocol": "http"}, "UDP or TCP"),
])
def test_the_listener_binds_this_computer_only_unless_told_otherwise(kw, why):
    """ASVS V14.1.1 · V1.14.6 · CWE-1327 · CWE-605: the listener defaults to 127.0.0.1; another address (or every address) needs allow_remote; a host name, multicast, a privileged port or an unknown protocol is refused."""
    # Act / Assert
    assert sl.check_settings() == {"host": "127.0.0.1", "port": 5514, "protocol": "udp", "allow_remote": False}
    assert sl.check_settings("10.0.0.5", 5514, "tcp", True)["host"] == "10.0.0.5"
    with pytest.raises(sl.ListenerError, match=why):
        sl.check_settings(**dict({"host": "127.0.0.1", "port": 5514, "protocol": "udp"}, **kw))


def test_the_listener_caps_message_size_rate_and_buffer(monkeypatch):
    """ASVS V11.1.4 · V12.1.1 · CWE-400 · CWE-770: an oversized message, messages past the rate and lines past the buffer are dropped and counted; control characters never reach the buffer."""
    # Arrange
    monkeypatch.setattr(sl, "MAX_LINES", 5)
    lst = sl.Listener(sl.check_settings(), rate=0.0001, burst=8)
    # Act
    big = lst.feed(b"x" * (sl.MAX_MESSAGE + 1), "127.0.0.1")
    kept = [lst.feed(f"<14>Oct 31 10:00:00 h t: line {i}\x07\x1b".encode(), "127.0.0.1") for i in range(10)]
    st = lst.status()
    # Assert
    assert big is False and st["counts"]["too_long"] == 1
    assert kept.count(True) == 8 and st["counts"]["rate_limited"] == 2
    assert st["lines"] == 5 and st["counts"]["buffer_dropped"] == 3
    assert list(lst.lines) == [f"line {i}" for i in range(3, 8)]


def _wait_for(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_the_listener_receives_udp_and_tcp_on_loopback():
    """ASVS V12.1.1 · CWE-400 · CWE-770: over 127.0.0.1, UDP datagrams and newline-framed TCP lines arrive; a TCP line past the size cap is counted and skipped up to its newline; stopping closes the socket."""
    # Arrange
    udp = sl.Listener({"host": "127.0.0.1", "port": 0, "protocol": "udp"})
    tcp = sl.Listener({"host": "127.0.0.1", "port": 0, "protocol": "tcp"})
    udp.start()
    tcp.start()
    try:
        # Act
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<134>Oct 31 10:00:00 nss01 nss: udp one", udp.bound)
        s.close()
        c = socket.create_connection(tcp.bound, timeout=5)
        c.sendall(b"<134>Oct 31 10:00:00 nss01 nss: tcp one\n" + b"y" * (sl.MAX_MESSAGE + 10) + b"\n<134>Oct 31 10:00:00 nss01 nss: tcp two\n")
        c.close()
        got_udp = _wait_for(lambda: list(udp.lines) == ["udp one"])
        got_tcp = _wait_for(lambda: list(tcp.lines) == ["tcp one", "tcp two"])
    finally:
        udp.stop()
        tcp.stop()
    # Assert
    assert got_udp, list(udp.lines)
    assert got_tcp and tcp.status()["counts"]["too_long"] == 1, (list(tcp.lines), tcp.status())
    assert udp.sock.fileno() == -1 and tcp.sock.fileno() == -1


def test_the_listener_is_off_by_default_and_its_routes_need_the_writer(api, monkeypatch, tmp_path):
    """ASVS V1.14.6 · V4.1.1 · CWE-1188 · CWE-285 · WSTG-ATHZ-02: nothing listens until started; starting or stopping needs the writer; another address without allow_remote is a 400; the start is audited."""
    # Arrange
    import security
    monkeypatch.setattr(sl, "DEFAULT_PORT", 5514)
    # Act
    idle = api.get("/api/traffic-logs/syslog").json()
    monkeypatch.setattr(security, "may_write", lambda: False)
    denied = api.post("/api/traffic-logs/syslog/start", json={})
    monkeypatch.setattr(security, "may_write", lambda: True)
    remote = api.post("/api/traffic-logs/syslog/start", json={"host": "192.0.2.10"})
    # Assert
    assert idle["running"] is False and idle["defaults"]["host"] == "127.0.0.1"
    assert denied.status_code == 403
    assert remote.status_code == 400 and "Allow other computers" in remote.json()["detail"]
    assert sl.current() is None or sl.current().stop_event.is_set()


def _held_listener(monkeypatch):
    """A listener holding two lines, never bound to a socket (feed() is its one intake)."""
    lst = sl.Listener(sl.check_settings("127.0.0.1", 5514, "udp", False))
    for n in range(2):
        assert lst.feed(f"<134>Oct 31 10:00:0{n} nss01 zscaler-nss: line {n}".encode(), "127.0.0.1")
    monkeypatch.setattr(sl, "_CURRENT", lst)
    return lst


def _audit_events():
    path = os.environ["DLP_CHECK_AUDIT"]
    if not os.path.exists(path):
        return []
    return [json.loads(ln) for ln in open(path, encoding="utf-8").read().splitlines() if ln.strip()]


@pytest.mark.parametrize("route,body", [("/api/traffic-logs/syslog/clear", None), ("/api/traffic-logs/syslog/stop", {"clear": True})])
def test_clearing_or_stopping_the_listener_without_the_writer_is_refused_and_keeps_the_lines(api, monkeypatch, route, body):
    """ASVS V4.1.1 · V4.1.3 · CWE-285 · CWE-862 · WSTG-ATHZ-02: clearing the lines that arrived, or stopping the listener, without the writer is a 403; the lines are kept, the listener keeps running and nothing is audited as done."""
    # Arrange
    import security
    lst = _held_listener(monkeypatch)
    monkeypatch.setattr(security, "may_write", lambda: False)
    # Act
    r = api.post(route, json=body) if body is not None else api.post(route)
    # Assert
    assert r.status_code == 403, r.text
    assert len(lst.lines) == 2 and not lst.stop_event.is_set()
    assert not [e for e in _audit_events() if e["event"] in ("traffic_logs_syslog_clear", "traffic_logs_syslog_stop")]


def test_clearing_the_lines_with_the_writer_is_audited(api, monkeypatch):
    """ASVS V7.1.3 · V7.2.2 · CWE-778 · WSTG-ATHZ-02: with the writer, clearing forgets the lines that arrived and writes a traffic_logs_syslog_clear audit record naming the actor."""
    # Arrange
    import security
    lst = _held_listener(monkeypatch)
    monkeypatch.setattr(security, "may_write", lambda: True)
    # Act
    r = api.post("/api/traffic-logs/syslog/clear")
    # Assert
    assert r.status_code == 200 and r.json()["lines"] == 0 and len(lst.lines) == 0
    rec = [e for e in _audit_events() if e["event"] == "traffic_logs_syslog_clear"]
    assert len(rec) == 1 and rec[0]["actor"], rec


def test_stopping_the_listener_with_the_writer_is_audited(api, monkeypatch):
    """ASVS V7.1.3 · V7.2.2 · CWE-778 · WSTG-ATHZ-02: with the writer, stopping (and clearing) the listener writes a traffic_logs_syslog_stop audit record naming the actor, whether the lines were cleared and how many arrived; no line's text is in it."""
    # Arrange
    import security
    lst = _held_listener(monkeypatch)
    monkeypatch.setattr(security, "may_write", lambda: True)
    # Act
    r = api.post("/api/traffic-logs/syslog/stop", json={"clear": True})
    # Assert
    assert r.status_code == 200 and r.json()["running"] is False and lst.stop_event.is_set() and len(lst.lines) == 0
    rec = [e for e in _audit_events() if e["event"] == "traffic_logs_syslog_stop"]
    assert len(rec) == 1 and rec[0]["actor"] and rec[0]["cleared"] is True and rec[0]["received"] == 2, rec
    assert "line 0" not in json.dumps(rec)


def test_lines_that_arrived_are_analysed_as_untrusted_and_never_written(api, monkeypatch, tmp_path):
    """ASVS V5.1.4 · V8.3.4 · CWE-20 · CWE-532 · CWE-312: NSS JSON lines that arrived are analysed like an upload (a hostile value stays data); nothing is written to disk until a report is saved, and the save is counts only."""
    # Arrange
    import security
    monkeypatch.setattr(security, "may_write", lambda: True)
    start = api.post("/api/traffic-logs/syslog/start", json={"host": "127.0.0.1", "port": 5514 + (os.getpid() % 2000), "protocol": "udp"})
    assert start.status_code == 200, start.text
    lst = sl.current()
    for rec in (web(T0, user="ann@example.com"), web(T0 + timedelta(minutes=1), action="Blocked", url="<script>x</script>.example")):
        lst.feed(("<134>Oct 31 10:00:00 nss01 zscaler-nss: " + json.dumps(rec)).encode(), "127.0.0.1")
    files_before = sorted(os.listdir(tmp_path))
    # Act
    rep = api.post("/api/traffic-logs/syslog/analyze")
    files_after = sorted(os.listdir(tmp_path))
    saved = api.post(f"/api/traffic-logs/report/{rep.json()['report_id']}/save", json={"title": "syslog"})
    stop = api.post("/api/traffic-logs/syslog/stop", json={"clear": True})
    # Assert
    assert rep.status_code == 200 and rep.json()["input"]["records"] == 2 and rep.json()["input"]["source"] == "syslog listener"
    assert set(files_after) - set(files_before) <= {"audit.log"}, "no raw line reached the disk"
    assert saved.status_code == 200 and saved.json()["saved"]["names"] is False
    text = "".join(open(os.path.join(tmp_path, "saved", n), encoding="utf-8").read() for n in os.listdir(tmp_path / "saved"))
    assert "ann@example.com" not in text
    assert stop.status_code == 200 and stop.json()["lines"] == 0 and stop.json()["running"] is False
