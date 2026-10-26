"""The entry points fail in plain words, never with a traceback: the server
launcher (port taken, bad port setting), the assessment CLI (missing,
invalid or incomplete configuration file, unwritable report)."""
from __future__ import annotations

import json
import sys

import pytest

import security


def test_get_port_accepts_a_valid_port_and_falls_back_with_a_warning(monkeypatch, capsys):
    monkeypatch.setenv("ZSCALER_PORT", "8443")
    assert security.get_port() == 8443
    for bad in ("eight", "0", "70000", ""):
        monkeypatch.setenv("ZSCALER_PORT", bad)
        assert security.get_port() == security.DEFAULT_PORT
        assert "not a port number" in capsys.readouterr().err
    monkeypatch.delenv("ZSCALER_PORT")
    assert security.get_port() == security.DEFAULT_PORT


def _free_port() -> int:
    """A port nothing on this machine listens on now (the OS picks it), so a
    test of the launcher never depends on whether 8000 happens to be taken."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_server_main_reports_a_taken_port_instead_of_a_traceback(monkeypatch, capsys):
    """ASVS V7.4.1 · CWE-209: a taken port is reported in plain words, on a port the OS says is free (never 8000)."""
    import dlp_api_server as srv
    import uvicorn

    def taken(app, host, port, **kw):
        raise OSError(98, "Address already in use")
    monkeypatch.setattr(uvicorn, "run", taken)
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    port = _free_port()   # free for the pre-start check, so uvicorn's own failure is what is reported
    monkeypatch.setenv("ZSCALER_PORT", str(port))
    assert srv.main([]) == 2
    err = capsys.readouterr().err
    assert f"port {port}" in err and "already in use" in err and "Traceback" not in err


def test_server_main_checks_the_port_before_uvicorn_starts(monkeypatch, capsys):
    """uvicorn exits on its own (code 3, a bare errno) when the port is taken,
    so the plain message has to come from a check made before it starts."""
    import socket
    import dlp_api_server as srv
    import uvicorn
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0)); holder.listen(1)
    port = holder.getsockname()[1]
    try:
        monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: pytest.fail("uvicorn.run must not be called when the port is taken"))
        monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
        monkeypatch.setenv("ZSCALER_BIND_HOST", "127.0.0.1")
        monkeypatch.setenv("ZSCALER_PORT", str(port))
        assert srv.main([]) == 2
        err = capsys.readouterr().err
        assert f"port {port} on 127.0.0.1 is already in use" in err and "stop.sh" in err and "Traceback" not in err
    finally:
        holder.close()
    assert srv._port_problem("127.0.0.1", port) is None
    assert "cannot be used" in (srv._port_problem("203.0.113.9", 8000) or "cannot be used")


def test_server_main_reports_any_other_bind_failure(monkeypatch, capsys):
    import dlp_api_server as srv
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port, **kw: (_ for _ in ()).throw(OSError(99, "Cannot assign requested address")))
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    monkeypatch.setenv("ZSCALER_BIND_HOST", "10.9.9.9")
    assert srv.main([]) == 2
    err = capsys.readouterr().err
    # An address this machine does not own is caught by the pre-start check (or, if the
    # platform lets the check bind, by uvicorn's failure); either way the fix is named.
    assert "10.9.9.9:8000 cannot be used" in err or "Could not start the server on 10.9.9.9" in err
    assert "ZSCALER_BIND_HOST" in err and "Traceback" not in err


def test_server_main_returns_zero_when_the_server_stops_normally(monkeypatch, capsys):
    """SSDF PW.8.2 · Scorecard CI-Tests: the launcher returns 0 on a normal stop, whatever else listens on 8000."""
    import dlp_api_server as srv
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port, **kw: None)
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    port = _free_port()   # never 8000, which another server on this machine may hold
    monkeypatch.setenv("ZSCALER_PORT", str(port))
    assert srv.main([]) == 0
    assert f"Open http://localhost:{port}/" in capsys.readouterr().out


def test_config_file_errors_are_explained(tmp_path):
    import dlp_assessment_full_auto as fa
    with pytest.raises(fa.ConfigError, match="does not exist"):
        fa.load_config_file(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"; bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(fa.ConfigError, match="not valid JSON"):
        fa.load_config_file(str(bad))
    lst = tmp_path / "list.json"; lst.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(fa.ConfigError, match="must contain a JSON object"):
        fa.load_config_file(str(lst))
    partial = tmp_path / "partial.json"; partial.write_text(json.dumps({"client_id": "abc"}), encoding="utf-8")
    with pytest.raises(fa.ConfigError, match="missing client_secret, vanity_domain"):
        fa.load_config_file(str(partial))
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"client_id": "abc", "client_secret": "s", "vanity_domain": "acme"}), encoding="utf-8")
    cfg = fa.load_config_file(str(good))
    assert cfg["cloud"] == "production" and cfg["vanity_domain"] == "acme"


def test_cli_exits_with_code_2_and_a_message_on_a_bad_config(monkeypatch, capsys, tmp_path):
    import dlp_assessment_full_auto as fa
    monkeypatch.setattr(sys, "argv", ["dlp_assessment_full_auto.py", "--config", str(tmp_path / "nope.json")])
    with pytest.raises(SystemExit) as ex:
        fa.main()
    assert ex.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith("Error: the configuration file") and "does not exist" in err


def test_cli_reports_an_unwritable_report_path(monkeypatch, capsys, tmp_path):
    import dlp_assessment_full_auto as fa
    cfg = tmp_path / "t.json"
    cfg.write_text(json.dumps({"client_id": "abc", "client_secret": "s", "vanity_domain": "acme", "cloud": "production"}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["dlp_assessment_full_auto.py", "--config", str(cfg), "--output", str(tmp_path / "no_such_dir" / "r.json")])
    monkeypatch.setattr(fa.Client, "auth", lambda self: True)
    monkeypatch.setattr(fa, "run_checks", lambda cl, checks, con: [])
    monkeypatch.setattr(fa, "report", lambda results, cfg, con=None: None)
    with pytest.raises(SystemExit) as ex:
        fa.main()
    assert ex.value.code == 2
    assert "could not be written" in capsys.readouterr().err
