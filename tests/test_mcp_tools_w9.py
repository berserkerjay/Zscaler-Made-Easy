"""The assistant's wave 9 tools (mcp_tools / dlp_mcp_server): a saved
traffic log report, Cloud & Branch Connector, ZDX, the app's own timeline
and the admin's case notes. Each answers counts on the sample tenant (or
local records), refuses what the server's scope does not tick, names no
person and changes no tenant.

Offline: the sample tenant, stores in tmp_path; no sign-in, no network."""
from __future__ import annotations

import asyncio
import json
import os

import pytest

import offline_tenant

TOOL_SCOPE = {"traffic_logs_summary": "insights", "ztw_summary": "ztw", "zdx_summary": "zdx", "timeline": "automation"}


def call(tool, /, **args):
    import dlp_mcp_server
    res = asyncio.run(dlp_mcp_server.mcp.call_tool(tool, args))
    return json.loads(res.content[0].text)


@pytest.fixture
def local(tmp_path, monkeypatch):
    for var, name in (("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_WORKSPACE_NOTES", "notes.json"), ("DLP_CHECK_TRAFFIC_LOG_REPORTS", "tl")):
        monkeypatch.setenv(var, str(tmp_path / name))
    for k in ("ZSCALER_MCP_PROFILE", "ZSCALER_MCP_SCOPES", "ZSCALER_MCP_CHANNELS", "ZSCALER_CLIENT_SECRET", "ZSCALER_CLIENT_ID",
              "ZSCALER_VANITY_DOMAIN", "ZSCALER_AUTH_METHOD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", ",".join(sorted(set(TOOL_SCOPE.values()))))
    import dlp_api_server as api

    def boom(*a, **k):
        pytest.fail("a live tenant client was built")
    monkeypatch.setattr(api, "_signed_in_raw", boom)
    offline_tenant.sample_store(reset=True)
    return tmp_path


def _saved_report(tmp_path):
    import traffic_logs as tl
    line = json.dumps({"LogTimestamp": "2026-10-30T10:00:00Z", "Username": "ann.lee@larkspur-freight.example", "Application": "Freight billing",
                       "Host": "billing.larkspur-freight.example", "ServerPort": 443, "ConnectionStatus": "close", "InternalReason": "",
                       "Connector": "hq-ac-1", "ConnectorGroup": "HQ", "ClientPublicIP": "198.51.100.7", "Policy": "Allow billing"})
    rep = tl.analyze([{"name": "zpa.json", "content": line + "\n" + line.replace("ann.lee", "bo.chan") + "\n"}])
    return tl.save_report(rep, title="Week 44", names=True)["name"]


def test_ztw_summary_counts_the_connectors_on_the_sample_and_lists_no_admin(local):
    """ASVS V8.3.4 · CWE-359 · CWE-200: Cloud & Branch Connector on the sample answers counts and checks; admins and API clients are counts, no secret-looking count is masked away."""
    # Act
    out = call("ztw_summary", source="sample")
    # Assert
    d = out["data"]
    assert d["counts"]["groups"] == 2 and d["counts"]["connectors"] == 3 and isinstance(d["counts"]["admins_local_sign_in"], int)
    assert isinstance(d["counts"]["api_clients"], int) and d["findings"] and all("objects" not in f for f in d["findings"])
    assert offline_tenant.sample_store().writes == 0


def test_zdx_summary_counts_scores_and_alerts_and_names_no_device(local):
    """ASVS V8.3.4 · CWE-359: ZDX on the sample answers score bands, the lowest apps and alert counts; no device or user name appears."""
    # Act
    out = call("zdx_summary", source="sample")
    # Assert
    d = out["data"]
    assert d["apps"]["scored"] == 3 and d["apps"]["bands"] == {"poor": 0, "okay": 1, "good": 2}
    assert d["alerts_last_14_days"]["count"] == 2 and d["alerts_last_14_days"]["by_severity"] == {"critical": 1, "warning": 1}
    text = json.dumps(out)
    assert "LKF-LT-0001" not in text and "LKF-MBP-0002" not in text and "userid" not in text


def test_traffic_logs_summary_lists_then_summarises_a_saved_report_as_counts(local):
    """ASVS V8.3.4 · CWE-359 · WSTG-INPV-01: the saved reports are listed; one saved with names is summarised with its people counted, never named; an unknown name is not_found."""
    # Arrange
    name = _saved_report(local)
    # Act
    listed = call("traffic_logs_summary")
    one = call("traffic_logs_summary", saved_report=name)
    missing = call("traffic_logs_summary", saved_report="20260101-000000-zzzzzzzz.json")
    # Assert
    assert [r["name"] for r in listed["data"]["saved_reports"]] == [name]
    assert one["data"]["zpa"]["users"] == 2 and one["data"]["input"]["records"] == 2
    assert "ann.lee" not in json.dumps(one) and "bo.chan" not in json.dumps(one)
    assert missing["code"] == "not_found"


def test_timeline_counts_the_apps_own_records_and_names_no_person(local):
    """ASVS V7.2.1 · V8.3.4 · CWE-359: the app's audit records since a date are counted by action and day; who acted is a count; a date too far back is refused."""
    # Arrange
    import audit
    audit.record("object_write", actor="jane.admin@example.com", action="update", kind="url_filtering_rule", name="Block gambling",
                 tenant="acme (production)")
    # Act
    out = call("timeline", since="2026-10-25")
    old = call("timeline", since="2020-01-01")
    # Assert
    assert out["data"]["summary"]["events"] >= 1 and out["data"]["people"] == 1
    assert "jane.admin" not in json.dumps(out)
    assert old["code"] == "bad_input"


def test_case_notes_reads_a_local_note_without_touching_the_tenant(local):
    """ASVS V4.1.3 · V7.2.1 · CWE-284 · CWE-359: a case note the admin added on the app's pages is read back from the local store; authors are counted, not named; the sample tenant is unchanged."""
    # Arrange
    import workspace_notes
    tenant = call("case_notes", source="sample")["data"]["tenant"]
    workspace_notes.apply(tenant, "rule", "rule:web:Block SSN", "add_comment", by="jane.admin@example.com", text="Check the SSN engine threshold")
    # Act
    got = call("case_notes", source="sample")
    # Assert
    assert got["data"]["total"] == 1 and got["data"]["authors"] == 1
    assert got["data"]["notes"][0]["comments"][0]["text"] == "Check the SSN engine threshold"
    assert "jane.admin" not in json.dumps(got)
    assert offline_tenant.sample_store().writes == 0


def test_the_assistant_cannot_add_a_case_note(local):
    """ASVS V1.4.1 · V4.1.3 · CWE-841 · WSTG-ATHZ-02: the MCP server offers no tool that adds to the admin's notes (every tool is read-only); asking for one is refused and nothing is stored."""
    # Arrange
    import dlp_mcp_server
    # Act / Assert
    with pytest.raises(Exception):
        asyncio.run(dlp_mcp_server.mcp.call_tool("add_case_note", {"kind": "rule", "ref": "r", "comment": "x", "source": "sample"}))
    assert call("case_notes", source="sample")["data"]["total"] == 0


@pytest.mark.parametrize("tool,args", [("traffic_logs_summary", {}), ("ztw_summary", {"source": "sample"}),
                                       ("zdx_summary", {"source": "sample"}), ("timeline", {})])
def test_each_new_tool_refuses_when_its_scope_is_not_ticked(tool, args, local, monkeypatch):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: with the server's scope ticking something else, each tool is refused with not_in_scope and how to fix it, before anything is read."""
    # Arrange
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "dlp")
    # Act
    out = call(tool, **args)
    # Assert
    assert out.get("code") == "not_in_scope", out
    assert "ZSCALER_MCP_SCOPES" in out["how_to_fix"]


def test_the_changelog_says_which_assistant_tools_check_scope(local, monkeypatch):
    """ASVS V1.1.2 · V14.3.3 · CWE-1059 · WSTG-INFO-05: the case-notes tools work on the app's local notes and take no Scope key (they answer with the scope ticking something else), so the release notes do not claim every new tool checks the server's scope first; they say which ones do."""
    # Arrange
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "dlp")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8").read()
    section = text.split("## 2026-11-01", 1)[1].split("\n## ", 1)[0]
    line = next(ln for ln in section.splitlines() if ln.startswith("- Assistant (MCP) tools"))
    # Act
    notes = call("case_notes")
    # Assert
    assert notes.get("code") != "not_in_scope", notes
    assert "Each is read-only toward the tenant, checks the server's scope first" not in line
    assert "each tool that reads tenant data checks the server's scope first" in line and "case-notes tools work on the app's local notes" in line


def test_the_new_tools_take_no_secret_or_scope_argument_and_are_read_only():
    """ASVS V1.4.1 · CWE-841: the new tools take no credential, scope or write switch; every one is marked read-only and none is destructive."""
    # Arrange
    import dlp_mcp_server
    ts = {t.name: t for t in asyncio.run(dlp_mcp_server.mcp.list_tools())}
    # Act
    new = {n: ts[n] for n in ("traffic_logs_summary", "ztw_summary", "zdx_summary", "timeline", "case_notes")}
    # Assert
    for name, t in new.items():
        props = set((getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}).get("properties") or {})
        assert not props & {"client_secret", "password", "scopes", "channels", "confirm", "write"}, name
        assert t.annotations.destructive_hint is False and t.annotations.read_only_hint is True, name


def test_the_skill_glossary_holds_every_simple_mode_word_and_the_reference_page_list_is_real():
    """SSDF PW.8.2 · CWE-1059: the skill's glossary has every word the app's Simple mode explains (static/glossary.js), and the reference library names only pages the app ships."""
    # Arrange
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "glossary.js"), encoding="utf-8").read()
    gl = open(os.path.join(root, "skills", "zscaler-made-easy", "references", "glossary.md"), encoding="utf-8").read()
    lib = open(os.path.join(root, "skills", "zscaler-made-easy", "references", "reference-library.md"), encoding="utf-8").read()
    # Act
    terms = {t.replace("\\'", "'") for t in re.findall(r"term:\s*'((?:[^'\\]|\\.)*)'", js)}
    titles = {re.search(r"<title>([^<|]+)", open(os.path.join(root, "static", "reference", f), encoding="utf-8").read()).group(1).strip()
              .replace("Zscaler Data Security — ", "") for f in os.listdir(os.path.join(root, "static", "reference")) if f.endswith(".html")}
    # Assert
    assert len(terms) > 100 and all(f"| {t} |" in gl for t in terms), sorted(t for t in terms if f"| {t} |" not in gl)[:5]
    assert all(f"| {t} |" in lib for t in titles), sorted(t for t in titles if f"| {t} |" not in lib)
