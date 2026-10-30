"""The terminal UI (tui.py): a curses client of the app's own server. It is
driven here against the real routes in-process (FastAPI TestClient as the
transport) on the sample tenant, with a fake curses screen fed scripted
keys. No network, no real tenant, no terminal."""
from __future__ import annotations

import json
import os
import socket

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import offline_tenant as ot
import panos_migrate as pm
import security
import tui

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "panos", "synthetic_config.xml")


class Transport:
    """tui.HttpTransport's interface over the in-process app."""

    def __init__(self, client):
        self.c, self.calls = client, []

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        r = self.c.request(method, path, json=body)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {"detail": r.text[:200]}

    def stream(self, path, body):
        self.calls.append(("STREAM", path))
        with self.c.stream("POST", path, json=body) as r:
            if r.status_code != 200:
                raise tui.ApiError(r.read().decode()[:200])
            for ln in r.iter_lines():
                yield ln


@pytest.fixture
def api(tmp_path, monkeypatch):
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json")):
        monkeypatch.setenv(var, str(tmp_path / name))

    def no_network(*a, **k):
        raise AssertionError("the network was used")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    monkeypatch.setattr(tui, "SAMPLE_SCOPES", ["dlp", "zia_extras"])
    c = TestClient(srv.app, base_url="http://127.0.0.1")
    c.headers[security.UI_TOKEN_HEADER] = security.ui_token()
    a = tui.Api(Transport(c))
    a.use_sample()
    return a


class Screen:
    """The few curses window calls the TUI makes, recording what is drawn."""

    def __init__(self, keys, h=40, w=120):
        self.keys = list(keys)
        self.h, self.w = h, w
        self.drawn = []

    def getmaxyx(self):
        return self.h, self.w

    def erase(self):
        pass

    def refresh(self):
        pass

    def addnstr(self, y, x, text, n, attr=0):
        assert len(text) <= n and "\x1b" not in text
        self.drawn.append(text)

    def getch(self):
        if not self.keys:
            return 27   # Esc: leaves any prompt, page or the menu
        k = self.keys.pop(0)
        return ord(k) if isinstance(k, str) else k


def keys(*parts):
    out = []
    for p in parts:
        out.extend(list(p) if isinstance(p, str) and len(p) > 1 else [p])
    return out


def test_terminal_escape_sequences_and_control_characters_never_reach_the_screen():
    """ASVS V5.3.1 · CWE-150 · CWE-117: a tenant string with escape sequences or control characters is drawn as plain text."""
    assert tui.clean("\x1b[2J\x1b]0;owned\x07Acme\x00\nInc‮") == "Acme  Inc "
    assert tui.clean("a" * 1000, 50) == "a" * 50


def test_secrets_are_masked_in_anything_shown():
    """ASVS V8.3.4 · CWE-200 · CWE-532: a value under a secret-looking key is masked before it is drawn."""
    shown = "\n".join(tui.fmt_any({"client_id": "abc", "client_secret": "S3CRET", "nested": [{"api_key": "K3Y", "password": "P"}]}))
    assert "S3CRET" not in shown and "K3Y" not in shown and "abc" in shown and "•••" in shown


@pytest.mark.parametrize("url,ok", [("http://127.0.0.1:8000", True), ("http://localhost:8001", True), ("https://zme.example.test", True),
                                    ("http://10.0.0.5:8000", False), ("file:///etc/passwd", False), ("javascript:x", False)])
def test_the_token_never_crosses_a_network_in_clear(url, ok):
    """ASVS V9.1.1 · CWE-319: plain http only to this computer; https elsewhere; other schemes refused."""
    if ok:
        assert tui.check_url(url)
    else:
        with pytest.raises(tui.ApiError):
            tui.check_url(url)


def test_the_tui_command_and_its_old_alias_start_the_tui(monkeypatch):
    """ASVS V14.1.1 · CWE-1059: `zscaler-made-easy tui` and `dlp-check tui` (both dlp_api_server:main) hand over to tui.main."""
    seen = []
    monkeypatch.setattr(tui, "main", lambda argv: seen.append(argv) or 0)
    assert srv.main(["tui", "--sample"]) == 0 and seen == [["--sample"]]
    import tomllib
    with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml"), "rb") as f:
        scripts = tomllib.load(f)["project"]["scripts"]
    assert scripts["zscaler-made-easy"] == scripts["dlp-check"] == "dlp_api_server:main"


def test_without_a_terminal_the_tui_says_so(monkeypatch, capsys):
    """ASVS V7.4.1 · CWE-755: piped (no terminal) it exits 2 with a plain reason, printing no token."""
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "tok-must-not-print")
    assert tui.main([]) == 2
    err = capsys.readouterr()
    assert "terminal" in err.err and "tok-must-not-print" not in err.err + err.out


def test_path_analyzer_view_on_the_sample(api):
    """ASVS V4.1.3 · CWE-284: the Path analyzer view asks the same read-only route as the web page and shows verdict and steps."""
    scr = Screen(keys("4", "chat.openai.com", 10, "q", "q"))
    tui.Tui(scr, api).run()
    text = "\n".join(scr.drawn)
    assert "Outcome:" in text and "Steps:" in text
    assert ("POST", "/api/path-analyzer") in api.t.calls


def test_assessment_and_findings_views(api):
    """ASVS V1.1.2 · CWE-1059: the assessment streams from /api/assess (the sample's scope) and the findings list its failed checks."""
    scr = Screen(keys("2", "q", "3", "q", "q"))
    tui.Tui(scr, api).run()
    text = "\n".join(scr.drawn)
    assert "Score:" in text and "Critical findings" in text
    assert ("STREAM", "/api/assess") in api.t.calls


def test_test_a_list_from_a_file(api, tmp_path):
    """ASVS V12.1.1 · CWE-400: a list file is read (size-capped, UTF-8) and tested through the Test a list route."""
    f = tmp_path / "list.txt"
    f.write_text("chat.openai.com\nexample.com\n")
    res = api.bulk_test(tui.read_text_file(str(f)))
    lines = tui.fmt_bulk(res)
    assert lines[0].startswith("2 destination(s) tested") and ("POST", "/api/bulk-test/start") in api.t.calls
    big = tmp_path / "big.txt"
    big.write_bytes(b"a" * (tui.MAX_FILE_BYTES + 1))
    with pytest.raises(tui.ApiError, match="larger"):
        tui.read_text_file(str(big))


def test_preview_then_apply_goes_through_the_servers_gates(api, tmp_path, monkeypatch):
    """ASVS V4.1.5 · V11.1.1 · CWE-862: a plan file is previewed (hash shown); Apply needs the typed phrase, the name and write mode on the server."""
    doc = pm.build_plan(open(FIXTURE, "rb").read(), prefix="pan")
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(doc))
    specs = tui.specs_from_file(f.read_text())
    assert [s[0] for s in specs] == ["ZIA firewall import", "ZPA application segments", "ZPA access rule"]
    scope_body = {"scopes": ["dlp", "zia_extras"], "channels": tui.SAMPLE_CHANNELS, "from_page": True}
    assert api.tenant_body() == scope_body
    # Preview with the TUI: pick the first operation of the plan.
    scr = Screen(keys("7", str(f), 10, "1", 10, "q", "q"))
    tui.Tui(scr, api).run()
    assert api.prepared and api.prepared["plan_hash"] and "Plan hash:" in "\n".join(scr.drawn)
    phrase = api.prepared["confirm_phrase"]
    # A wrong phrase: nothing is sent.
    calls = len(api.t.calls)
    monkeypatch.setattr(security, "_write_override", True)
    scr = Screen(keys("8", "WRONG", 10, "q"))
    tui.Tui(scr, api).run()
    assert not any(p == "/api/operations/apply" for _m, p in api.t.calls[calls:])
    assert "did not match" in "\n".join(scr.drawn)
    # Write mode off on the server: refused there, with its reason.
    monkeypatch.setattr(security, "_write_override", False)
    with pytest.raises(tui.ApiError, match="(?i)write"):
        api.apply(phrase, "Jane Doe")
    # Phrase, name and write mode: the server applies (to the sample's memory).
    monkeypatch.setattr(security, "_write_override", True)
    scr = Screen(keys("8", phrase, 10, "Jane Doe", 10, "q", "q"))
    tui.Tui(scr, api).run()
    assert ("POST", "/api/operations/apply") in api.t.calls
    assert "Status:" in "\n".join(scr.drawn)


def test_a_view_that_fails_shows_the_reason_and_the_tui_keeps_running(api):
    """ASVS V7.4.1 · CWE-755: a server refusal is shown on the status line; the menu stays."""
    api.sample, api.profile = False, None
    scr = Screen(keys("4", "example.com", 10, "q"))
    tui.Tui(scr, api).run()
    assert any("Pick a tenant first" in d for d in scr.drawn)
