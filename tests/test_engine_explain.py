"""DLP engine explainability (engine_explain): an engine expression with
dictionary names and in one plain sentence, wherever an engine is shown
(console index, Deploy/inventory views, the DLP inventory workbook); file
types as people read them; and the configuration exports never carrying a
secret (config_exports)."""
from __future__ import annotations

import json
import os

import pytest

import engine_explain as ee

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAMES = {"63": "SSN", "7": "CREDIT_CARD", "1001": "Project Codes"}


# ── Readable expression ────────────────────────────────────────────────
@pytest.mark.parametrize("expr, want", [
    ("((D63.S > 1) AND (D7.S > 0))", "(SSN count > 1) AND (Credit card count > 0)"),
    ("((D63.S > 1))", "SSN count > 1"),
    ("D63.S", "SSN count > 0"),                                       # a bare term: at least one match
    ("(D63.S + D7.S) > 1", "(SSN count + Credit card count) > 1"),      # the Engine Builder's Sum
    ("((D63.S > 0) AND ((D7.S > 2) OR (D1001.U >= 3)))",
     "(SSN count > 0) AND ((Credit card count > 2) OR (Project Codes unique count >= 3))"),
    ("((D63.S > 0) AND NOT (D7.S > 0))", "(SSN count > 0) AND (NOT (Credit card count > 0))"),
    ("((D:Project Codes > 0) AND (D:SSN > 2))", "(Project Codes count > 0) AND (SSN count > 2)"),   # a pack's names
    ("D63.S = 0", "SSN count = 0"),
    ("D63.S<=2", "SSN count <= 2"),
])
def test_ids_become_dictionary_names_with_operators_and_nesting_kept(expr, want):
    assert ee.readable(expr, NAMES) == want


def test_unknown_ids_are_named_as_unknown_and_listed():
    x = ee.explain("((D63.S > 1) OR (D999.S > 0))", NAMES)
    assert x["readable"] == "(SSN count > 1) OR (unknown dictionary 999 count > 0)"
    assert x["unknown_ids"] == ["999"] and x["dictionaries"][0] == {"id": "63", "name": "SSN", "known": True}
    assert x["expression"] == "((D63.S > 1) OR (D999.S > 0))", "the raw expression is kept as is, for copying"
    assert x["parsed"] is True


def test_an_expression_that_cannot_be_parsed_keeps_its_shape_and_gets_no_summary():
    for bad in ("((D63.S > 0)", "D63.S > 1 > 2", "garbage ((", "5", "x" * (ee.MAX_EXPRESSION + 1)):
        x = ee.explain(bad, NAMES)
        assert x["summary"] == "" and x["parsed"] is False, bad
    assert ee.readable("((D63.S > 0)", NAMES) == "((SSN count > 0)"
    assert ee.readable("", NAMES) == "" and ee.summary(None) == ""


# ── Plain English ──────────────────────────────────────────────────────
@pytest.mark.parametrize("expr, want", [
    ("((D63.S > 1) AND (D7.S > 0))", "Fires when the content has more than one SSN match and at least one Credit card match."),
    ("((D63.S > 2))", "Fires when the content has more than two SSN matches."),
    ("((D63.S > 12))", "Fires when the content has more than 12 SSN matches."),
    ("((D63.S >= 3))", "Fires when the content has at least three SSN matches."),
    ("((D63.S < 3))", "Fires when the content has fewer than three SSN matches."),
    ("D63.S = 1", "Fires when the content has exactly one SSN match."),
    ("NOT (D63.S > 0)", "Fires when the content has no SSN match."),
    ("((D63.S > 0) OR (D7.S > 0) OR (D1001.S > 4))",
     "Fires when the content has at least one SSN match, at least one Credit card match or more than four Project Codes matches."),
    ("((D63.S > 0) AND ((D7.S > 2) OR (D1001.U >= 3)))",
     "Fires when the content has at least one SSN match and either more than two Credit card matches or at least three unique Project Codes matches."),
    ("((D63.S > 0) OR ((D7.S > 0) AND (D1001.S > 0)))",
     "Fires when the content has at least one SSN match or both at least one Credit card match and at least one Project Codes match."),
    ("(D63.S + D7.S) > 1", "Fires when the content has more than one match of SSN and Credit card combined."),
    ("D999.S > 0", "Fires when the content has at least one unknown dictionary 999 match."),
])
def test_the_summary_says_when_the_engine_fires(expr, want):
    assert ee.summary(expr, NAMES) == want


def test_names_by_id_reads_every_shape_the_app_holds():
    assert ee.names_by_id([{"id": 1, "name": "A"}, {"id": None, "name": "B"}]) == {"1": "A"}
    assert ee.names_by_id({"A": {"id": 1}, "B": {"id": 2}}) == {"1": "A", "2": "B"}
    assert ee.names_by_id({"1": "A"}) == {"1": "A"}
    assert ee.display_name("CREDIT_CARD") == "Credit card" and ee.display_name("SSN") == "SSN" and ee.display_name("Project Codes") == "Project Codes"


# ── File types ─────────────────────────────────────────────────────────
def test_file_types_read_as_words_and_say_which_rules_use_them():
    assert ee.file_type_label("FTCATEGORY_WINDOWS_EXECUTABLES") == ("Windows executables", "File type category")
    assert ee.file_type_label("FTCATEGORY_MS_WORD") == ("MS Word", "File type category")
    assert ee.file_type_label("PDF_DOCUMENT")[1] == "File type"
    usage = ee.file_type_usage({"file_type_control": [{"name": "Block exe", "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES", "ANY"]}],
                                "web_dlp": [{"name": "Web-Projects", "file_types": ["FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_MS_WORD"]}]})
    by = {u["token"]: u for u in usage}
    assert set(by) == {"FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_MS_WORD"}
    assert by["FTCATEGORY_WINDOWS_EXECUTABLES"]["used_by"] == {"file_type_control": ["Block exe"], "web_dlp": ["Web-Projects"]}


# ── Where engines are shown ────────────────────────────────────────────
def test_the_inventory_and_the_console_index_carry_the_readable_expression():
    import console_index as ci
    import pack_removal
    from test_pack_export import _source
    inv = pack_removal.inventory(_source())
    leak = next(e for e in inv["engines"] if e["name"] == "Project Leak")
    assert leak["expression"] == "((D1001.S > 0) AND (D1.S > 2))"
    assert leak["readable"] == "(Project Codes count > 0) AND (SSN count > 2)"
    assert leak["summary"] == "Fires when the content has at least one Project Codes match and more than two SSN matches."
    orphan = next(e for e in inv["orphans"]["engines"] if e["name"] == "Unused Engine")
    assert orphan["readable"] == "Board Phrases count > 0"
    idx = ci.from_inventory(inv, tenant_label="acme", now=1)
    o = next(x for x in idx["objects"] if x["kind"] == "engine" and x["name"] == "Project Leak")
    assert o["expression"] == leak["expression"] and o["readable"] == leak["readable"] and o["summary"] == leak["summary"]


def test_the_panel_and_the_deploy_views_show_it_and_copy_the_raw_expression():
    panel = open(os.path.join(ROOT, "browser_extension", "panel.js"), encoding="utf-8").read()
    assert "function engineExpression(o)" in panel and "navigator.clipboard.writeText(o.expression" in panel
    assert "o.readable || o.expression" in panel and "innerHTML" not in panel
    studio = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "function _dzEngineExplain(o)" in studio and "data-expr=\"${_dzE(o.expression || '')}\"" in studio
    assert studio.count("_dzEngineExplain(o)") >= 3   # the definition, the export picker and the orphan engines


def test_the_console_index_names_file_types_and_the_rules_that_use_them():
    import console_index as ci
    zia = {"rules": {"file_type_control": [{"id": 1, "name": "Block exe", "order": 1, "state": "ENABLED", "filteringAction": "BLOCK",
                                            "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"]}]}, "categories": []}
    idx = ci.from_inventory({"rules": [], "engines": [], "dictionaries": {}}, zia=zia, now=1)
    ft = next(o for o in idx["objects"] if o["kind"] == "file_type")
    assert ft["name"] == "Windows executables" and ft["id"] == "FTCATEGORY_WINDOWS_EXECUTABLES" and ft["category"] == "File type category"
    assert ft["used_by"] == {"file_type_control": ["Block exe"]} and "file_type" in {k["kind"] for k in idx["kinds"]}


# ── No secrets in the configuration exports ────────────────────────────
PSK = "psk-SuperSecret-123"
PASSWORD = "uninstall-Pa55word"


def test_the_location_export_never_carries_a_psk_or_a_password():
    import config_exports as ce
    from test_xlsx_writer import read_workbook
    got = {"locations": [{"id": 1, "name": "HQ", "ipAddresses": ["198.51.100.7"], "childCount": 0,
                          "vpnCredentials": [{"id": 9, "type": "UFQDN", "fqdn": "hq@acme.example", "preSharedKey": PSK, "comments": "psk"}],
                          "preSharedKey": PSK, "password": PASSWORD, "apiToken": PSK, "someFutureSecretField": PSK}],
           "sublocations": {}, "groups": [{"id": 5, "name": "Branches", "groupType": "STATIC", "password": PASSWORD,
                                           "locations": [{"id": 1, "name": "HQ"}]}], "rules": {}, "errors": {}}
    data = ce.locations_workbook(got, {"usage": [], "summary": "s"}, tenant_label="acme")
    blob = data
    assert PSK.encode() not in blob and PASSWORD.encode() not in blob and b"198.51.100.7" not in blob and b"hq@acme.example" not in blob
    loc = dict(zip(*read_workbook(data)["Locations"][:2]))
    assert loc["IP addresses"] == "1" and loc["VPN credentials"] == "1"


def test_the_client_connector_export_never_carries_a_password_token_or_key():
    import config_exports as ce
    from test_xlsx_writer import read_workbook
    raw = {"id": 1, "name": "Default", "uninstallPassword": PASSWORD, "disablePassword": PASSWORD, "exitPassword": PASSWORD,
           "zccRevertPassword": PASSWORD, "passcode": PASSWORD, "nonce": PSK, "ziaRSAPubKey": PSK, "zccFailCloseSettingsThumbPrint": PSK,
           "logLevel": "DEBUG", "users": [{"id": 1, "name": "jane.doe@acme.com"}], "loginName": "jane.doe@acme.com",
           "bypassAppIds": [1, 2]}
    zcc = {"app_profiles": [{"id": 1, "name": "Default", "platform": "windows", "active": True, "priority": 1, "forwarding_profile": 7,
                             "bypass": {}, "groups": [], "raw": raw}],
           "forwarding_profiles": [{"id": 7, "name": "Fwd", "actions": {}, "trusted_networks": [], "raw": {"id": 7, "name": "Fwd", "apiKey": PSK}}],
           "pac_files": [], "errors": []}
    data = ce.client_connector_workbook(zcc, {"summary": "s"}, tenant_label="acme")
    assert PASSWORD.encode() not in data and PSK.encode() not in data and b"jane.doe" not in data
    app = dict(zip(*read_workbook(data)["App profiles"][:2]))
    assert "Log level: DEBUG" in app["Settings"] and "Users: 1 person" in app["Settings"] and "Bypass app ids: 1, 2" in app["Settings"]
    assert app["Forwarding profile"] == "Fwd"
    for key in ("uninstallPassword", "passcode", "nonce", "ziaRSAPubKey", "zccFailCloseSettingsThumbPrint", "apiKey", "preSharedKey", "psk", "otp"):
        assert ce.is_secret(key), key
    for key in ("bypassAppIds", "logLevel", "keywords", "bypassProxyForPrivateIP", "pinnedApps"):
        assert not ce.is_secret(key), key
    json.dumps(ce.column_catalogue())
