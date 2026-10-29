"""ASVS V5.1.3 · ASVS V5.1.4 · ASVS V12.1.1 · CWE-20 · CWE-400 · OWASP A03:2021 · A04:2021: secure by design, untrusted input.

Everything a user, a file or a tenant can feed the app, checked with hostile
values: the PAC evaluator (a deterministic generator plus an adversarial
corpus), Test a list (CIDR and range limits, encodings), the untrusted file
imports (snapshot, ZIA framework, POV, HAR, the live feed's echoed tally),
the what-if identity search (the query never reaches a URL path), the ZDX
custom app URL and AI Guard (no request from the app's own process) and the
shared export cleaners (bidirectional controls). Each case answers or
refuses in words, never an exception, a 500 or a hang (CISA Secure by
Design: deny by default, fail closed).

Deterministic and isolated: no network, no clock (PAC time is injected,
CPU budgets use time.process_time against at least ten times what the fixed
code needs), stores in tmp_path, random.Random with a fixed seed.
"""
from __future__ import annotations

import ast
import json
import math
import os
import random
import shutil
import subprocess
import time
import typing
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import bulk_test
import csv_safe
import detection_health
import dlp_api_server as srv
import md_safe
import offline_tenant as ot
import ops_zia_baseline as zb
import pac_eval as pe
import path_whatif as pw
import pov
import safe_files
import sample_tenant
import tenant_profiles
import xlsx_writer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "sbd-input-secret-Zq81-never-stored"
ALL_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"]
CHANNELS = {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it",
                                   "ssl_inspection", "cloud_app_control")}
SCOPE = {"scopes": ALL_SCOPES, "channels": CHANNELS, "from_page": True}


def _cpu(fn, *a, **kw):
    start = time.process_time()
    out = fn(*a, **kw)
    return time.process_time() - start, out


def pac(body: str, pre: str = "") -> str:
    return pre + "function FindProxyForURL(url, host) {\n" + body + "\n}"


@pytest.fixture
def app(tmp_path, monkeypatch):
    """An isolated app: every store in tmp_path, no environment tenant, a fresh offline registry."""
    for var, name in (("DLP_CHECK_PROFILES", "profiles/tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json"),
                      ("DLP_CHECK_FINGERPRINT_KEY", "fp.key")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    return TestClient(srv.app, base_url="http://127.0.0.1", raise_server_exceptions=False)


# ── PAC evaluator ──────────────────────────────────────────────────────

ADVERSARIAL_PACS = {
    "hex literal past a double": pac("return 0x" + "f" * 400 + ";"),
    "hex literal in a top-level var": "var big = 0x" + "F" * 300 + ";\n" + pac('return "DIRECT";'),
    "hex string to a number": pac('return "0x' + "f" * 400 + '" * 1;'),
    "decimal past a double": pac("return 1" + "0" * 5000 + ";"),
    "deep method chain": pac('return "a"' + ".trim()" * 3000 + ";"),
    "deep .length chain": pac('return "a"' + ".length" * 3000 + ";"),
    "unary minus run": pac("return " + "-" * 3000 + "1;"),
    "unicode escapes": pac(r'return "\u0044IRECT";'),
    "unicode identifier": pac("var \u0430 = 'DIRECT'; return \u0430;"),
    "escaped identifier": pac(r'var \u0061 = 1; return "DIRECT";'),
    "comment hides a brace": pac('/* } return "PROXY a:1"; { */ return "DIRECT"; // }'),
    "unterminated comment": pac('/* return "DIRECT";'),
    "byte order mark": "\ufeff" + pac('return "DIRECT";'),
    "CRLF line ends": pac('return "DIRECT";').replace("\n", "\r\n"),
    "NUL inside a string": pac('return "DIR\x00ECT";'),
    "NUL between tokens": pac('return\x00 "DIRECT";'),
    "lone surrogate": pac('return "\ud800";'),
    "escaped lone surrogate": pac(r'return "\ud800";'),
    "markup in the answer": pac('return "PROXY <img src=x onerror=alert(1)>:80";'),
    "right-to-left override": pac('return "PROXY \u202eevil.example:80";'),
    "superscript digit": pac("return \u00b2;"),
    "Arabic-Indic digits": pac("return \u0663\u0663;"),
    "__proto__ and constructor": pac('var __proto__ = 1; var constructor = 2; return "DIRECT";'),
    "a function named constructor": "function constructor(){return 1}\nfunction __proto__(){return 2}\n" + pac('return "DIRECT";'),
    "calling __proto__": pac("return __proto__();"),
    "self recursion": "function f(x){return f(x)}\n" + pac("return f(1);"),
    "mutual recursion": "function f(x){return g(x)}\nfunction g(x){return f(x)}\n" + pac("return f(1);"),
    "string doubling": pac('var s="aaaaaaaaaaaaaaaa";' + " s+=s;" * 14 + " return s;"),
    "upper-case expansion": pac('var s="' + "ß" * 60000 + '"; return s.toUpperCase().toUpperCase();'),
    "glob against a long host": pac('var s="' + "a" * 60000 + '"; return shExpMatch(s, "' + "*a" * 2000 + 'b") ? "DIRECT" : "PROXY x:1";'),
    "substr of Infinity": pac('return "abc".substr(1/0);'),
    "charAt of Infinity": pac('return "abc".charAt(1/0);'),
    "isInNet with an IPv6 pattern": pac('return isInNet("::1", "::", "0") ? "DIRECT" : "PROXY x:1";'),
    "only whitespace": " \n\t" * 1000,
    "empty": "",
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL_PACS))
def test_an_adversarial_pac_is_answered_or_refused_in_words_within_the_caps(name):
    """ASVS V5.1.3 · ASVS V12.1.1 · CWE-20 · CWE-248 · CWE-400 · CWE-1333 · WSTG-INPV-11: every adversarial PAC ends in a result or "could not evaluate safely", never an exception or a hang."""
    # Arrange
    src = ADVERSARIAL_PACS[name]
    # Act
    spent, r = _cpu(pe.evaluate, src, "https://www.example.com/", dns="assume_public")
    spent2, info = _cpu(pe.inspect, src)
    pe._CACHE.clear()
    # Assert
    assert r["status"] in ("ok", "depends", "error"), name
    assert r["status"] != "error" or r["error"].startswith(pe.PREFIX), r["error"]
    assert isinstance(info["ok"], bool)
    assert spent < 2.0 and spent2 < 2.0, f"{name}: {spent:.2f} s / {spent2:.2f} s"


def test_a_hex_literal_too_large_for_a_double_is_infinity_as_in_javascript():
    """ASVS V5.1.4 · CWE-190 · CWE-248: 0xFFF... past 2^1024 reads as Infinity (JavaScript's value), never an OverflowError out of evaluate or inspect."""
    # Arrange
    src = pac("return 0x" + "f" * 400 + ' > 1 ? "PROXY ${GATEWAY}:80" : "DIRECT";')
    # Act
    r = pe.evaluate(src, "https://a.example/")
    info = pe.inspect(pac("var n = 0x" + "f" * 400 + '; return "DIRECT";'))
    # Assert
    assert r["status"] == "ok" and r["kind"] == "zscaler"
    assert info["ok"] is True


def test_a_parse_that_breaks_fails_closed_as_a_refusal(monkeypatch):
    """ASVS V7.4.1 · CWE-755 · CWE-636: an unexpected error while parsing is "could not evaluate safely", never an exception (fail closed)."""
    # Arrange
    pe._CACHE.clear()
    monkeypatch.setattr(pe._Parser, "program", lambda self: {}["boom"])
    src = pac('return "DIRECT";') + "// fail-closed case"
    # Act
    r = pe.evaluate(src, "https://a.example/")
    info = pe.inspect(src)
    pe._CACHE.clear()
    # Assert
    assert r["status"] == "error" and r["error"] == pe.PREFIX + "an internal error (KeyError)"
    assert info["ok"] is False and info["error"].startswith(pe.PREFIX)


class _CountingSource(str):
    """PAC source that adds up how many characters str.count is asked to scan."""
    scanned = 0

    def count(self, sub, start=0, end=None):  # noqa: D401
        stop = len(self) if end is None else end
        type(self).scanned += max(0, stop - start)
        return str.count(self, sub, start, end)


def test_line_numbers_cost_one_pass_not_one_scan_per_call():
    """ASVS V12.1.1 · CWE-407 · CWE-400 · WSTG-BUSL-09: every call records its line from one index of the newlines; the parse stays linear (was one rescan of the source per call)."""
    # Arrange: 20,000 calls, one per line, then a refusal on the last line
    body = "a();\n" * 20000 + "while (1) {}"
    src = _CountingSource(pac(body) + "\n")
    _CountingSource.scanned = 0
    pe._CACHE.clear()
    # Act
    r = pe.evaluate(src, "https://a.example/")
    pe._CACHE.clear()
    # Assert: the refusal names the right line, and the newline scans stayed within one pass
    assert r["status"] == "error" and "'while' (line 20002)" in r["error"], r["error"]
    assert _CountingSource.scanned <= len(src), _CountingSource.scanned


def test_generated_pacs_never_raise():
    """ASVS V5.1.3 · CWE-20 · CWE-248: a deterministic generator of random PAC programs (statements, expressions, helpers, hostile literals) never makes evaluate or inspect raise."""
    # Arrange
    rnd = random.Random(20261029)
    atoms = ["host", "url", '"DIRECT"', '"PROXY ${GATEWAY}:80"', "0x" + "f" * 300, "1e400", "-0", "NaN", "undefined", "null",
             '"\\u202e"', '"<img src=x>"', "'\\x00'", "__proto__", "constructor", "1/0", "dnsResolve(host)", "myIpAddress()"]
    calls = ["shExpMatch({}, {})", "dnsDomainIs({}, {})", "isInNet({}, {}, {})", "isPlainHostName({})", "({}).substr({})",
             "({}).indexOf({}, {})", "({}).charAt({})", "({}).toUpperCase()", "localHostOrDomainIs({}, {})", "dnsDomainLevels({})",
             "timeRange({})", "weekdayRange({}, {})"]
    ops = [" + ", " - ", " * ", " / ", " % ", " == ", " !== ", " < ", " && ", " || "]

    def expr(d):
        if d <= 0 or rnd.random() < 0.3:
            return rnd.choice(atoms)
        k = rnd.random()
        if k < 0.35:
            c = rnd.choice(calls)
            return c.format(*[expr(d - 1) for _ in range(c.count("{}"))])
        if k < 0.7:
            return "(" + expr(d - 1) + rnd.choice(ops) + expr(d - 1) + ")"
        if k < 0.85:
            return "!" + expr(d - 1)
        return "(" + expr(d - 1) + " ? " + expr(d - 1) + " : " + expr(d - 1) + ")"

    def stmt(d):
        k = rnd.random()
        if d <= 0 or k < 0.3:
            return f"return {expr(3)};"
        if k < 0.6:
            return f"if ({expr(3)}) {{ {stmt(d - 1)} }} else {{ {stmt(d - 1)} }}"
        if k < 0.8:
            return f"var v{rnd.randrange(5)} = {expr(3)}; {stmt(d - 1)}"
        return f"host = {expr(2)}; {stmt(d - 1)}"

    for i in range(300):
        src = pac(" ".join(stmt(4) for _ in range(rnd.randint(1, 4))), pre=rnd.choice(["", "function h(a) { return a; }\n"]))
        # Act
        r = pe.evaluate(src, "https://www.example.com/", dns=rnd.choice(["none", "assume_public"]))
        info = pe.inspect(src)
        # Assert
        assert r["status"] in ("ok", "depends", "error"), (i, src)
        assert r["status"] != "error" or r["error"].startswith(pe.PREFIX), (i, r["error"])
        assert isinstance(info["ok"], bool)
    pe._CACHE.clear()


# ── Strict JSON for uploads ────────────────────────────────────────────

@pytest.mark.parametrize("text", ["NaN", "[Infinity]", '{"a": -Infinity}', "[1e400]", '{"total": -1e999}'])
def test_strict_json_refuses_what_json_itself_refuses(text):
    """ASVS V5.1.4 · CWE-20 · CWE-1287: NaN, Infinity and a number past a double are refused (RFC 8259), as a ValueError."""
    # Act / Assert
    with pytest.raises(ValueError):
        safe_files.strict_json_loads(text)


def test_strict_json_keeps_every_valid_value():
    """ASVS V5.1.4 · CWE-20: valid JSON reads exactly as json.loads reads it (boundary: the largest double, a long integer)."""
    # Arrange
    text = json.dumps({"a": [1, 2.5, -0.0, 1.7976931348623157e308, 10 ** 30, None, True, "NaN"], "b": {"c": "Infinity"}})
    # Act / Assert
    assert safe_files.strict_json_loads(text) == json.loads(text)


# ── Snapshot files ─────────────────────────────────────────────────────

def _snapshot_text(value: str) -> str:
    doc = ot.build_snapshot({"/zia/api/v1/webDlpRules": {"status": 200, "body": [{"id": 1, "name": "R", "order": 1}]}}, {"tenant_label": "t"})
    return ot.dumps(doc).replace('"order":1', f'"order":{value}')


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_a_snapshot_with_a_number_json_does_not_have_is_refused(value):
    """ASVS V5.1.4 · CWE-20 · CWE-1287 · WSTG-INPV-13: NaN or Infinity in an opened snapshot is refused in words (opened, it made every job poll on it a 500)."""
    # Act / Assert
    with pytest.raises(ot.SnapshotInvalid, match="not valid JSON"):
        ot.parse_snapshot(_snapshot_text(value).encode())


def test_a_snapshot_with_nan_never_reaches_a_job(app):
    """ASVS V5.1.4 · ASVS V7.4.1 · CWE-1287 · CWE-755: the open-file route answers 400 for NaN and the browser stays on the live tenant."""
    # Act
    r = app.post("/api/tenant-profiles/snapshots/open-file", json={"name": "x.json", "content": _snapshot_text("NaN")})
    # Assert
    assert r.status_code == 400 and "not valid JSON" in r.json()["detail"]
    assert ot.COOKIE not in r.cookies and app.get("/api/offline/status").json()["mode"] == "live"


# ── ZIA policy framework files ─────────────────────────────────────────

def _framework(**rule):
    r = {"name": "BL-Block-gambling", "default": "BLOCK", "fields": {}}
    r.update(rule)
    return {"format": zb.FRAMEWORK_FORMAT, "format_version": zb.FRAMEWORK_VERSION, "areas": {"url": [r]}}


@pytest.mark.parametrize("rule", [
    {"fields": [1]}, {"fields": "url_categories"}, {"fields": 5},
    {"name": {"a": 1}}, {"name": ["a"]}, {"name": 12345}, {"title": ["t"]},
    {"name": "Allow\u202egnilbmag"}, {"name": "Al\u200blow"}, {"name": "a<b"}, {"name": "bell\x07here"}, {"name": "del\x7fhere"},
])
def test_a_framework_rule_of_the_wrong_type_or_with_hidden_characters_is_refused(rule):
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20 · CWE-843 · CWE-451: fields must be an object, name and title text; a name with a bidirectional, invisible or control character is refused (it becomes a rule name in the tenant)."""
    # Act / Assert
    with pytest.raises(zb.ao.OperationError):
        zb.load_framework(_framework(**rule))


def test_a_framework_format_version_must_be_the_number_itself():
    """ASVS V5.1.4 · CWE-843: format_version true is not version 1 (True == 1 in Python, not in the file format)."""
    # Act / Assert
    with pytest.raises(zb.ao.OperationError):
        zb.load_framework(dict(_framework(), format_version=True))


def test_a_framework_title_keeps_its_text_and_loses_control_characters():
    """ASVS V5.1.3 · CWE-116: a title's control and bidirectional characters become spaces; the rest is kept (happy path)."""
    # Act
    out = zb.load_framework(_framework(title="Block\x00 gambling\u202e sites", fields={"url_categories": ["GAMBLING"]}))
    # Assert
    rule = out["rules"][0]
    assert rule["title"] == "Block gambling sites" and rule["fields"] == {"url_categories": ["GAMBLING"]}


def test_a_framework_with_a_megabyte_title_is_cut_in_linear_time():
    """ASVS V12.1.1 · CWE-407 · CWE-400 · WSTG-BUSL-09: a 200,000-character title is cut to 200 bytes at once (the old character-by-character cut took seconds to hours)."""
    # Arrange
    fw = _framework(title="x" * 200_000)
    # Act
    spent, out = _cpu(zb.load_framework, fw)
    # Assert
    assert len(out["rules"][0]["title"].encode("utf-8")) <= 200 and out["rules"][0]["title"].endswith("…")
    assert spent < 0.5, f"{spent:.2f} s"


@pytest.mark.parametrize("text,limit", [("", 10), ("abc", 3), ("abcd", 3), ("é" * 50, 10), ("a b  c", 200), ("€" * 1000, 200)])
def test_fit_bytes_keeps_its_meaning_at_the_boundaries(text, limit):
    """ASVS V5.1.3 · CWE-131: the cut text fits the byte limit, keeps a prefix of the text and ends with … only when it was cut."""
    # Act
    out = zb._fit_bytes(text, limit)
    # Assert
    flat = " ".join(text.split())
    assert len(out.encode("utf-8")) <= limit or flat == ""
    assert out == flat if len(flat.encode("utf-8")) <= limit else (out.endswith("…") and flat.startswith(out[:-1].rstrip()))


def test_the_preview_route_answers_400_for_a_framework_of_the_wrong_shape(app):
    """ASVS V5.1.4 · ASVS V7.4.1 · CWE-20 · CWE-755: a framework whose fields are a list is a 400 in words, not a 500 (AttributeError)."""
    # Arrange
    app.post("/api/offline/sample", json={})
    op = {"type": zb.TYPE, "framework": _framework(fields=[1]), "areas": ["url"]}
    # Act
    r = app.post("/api/operations/preview", json=dict(SCOPE, operation=op))
    # Assert
    assert r.status_code == 400 and "fields an object" in r.json()["detail"]


# ── POV import ─────────────────────────────────────────────────────────

def _profile():
    return tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789"},
                                  client_secret=SECRET, remember_secret=True)["id"]


@pytest.mark.parametrize("total", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_a_pov_file_with_nan_is_refused_and_the_pov_still_opens(app, total):
    """ASVS V5.1.4 · ASVS V7.4.1 · CWE-1287 · CWE-400: NaN or Infinity in an imported POV is refused in words; kept, it made the import and every later open a 500."""
    # Arrange
    pid = _profile()
    assert app.post("/api/pov/create", json={"profile_id": pid, "intake": {"customer": "Acme", "vertical": "healthcare"}}).status_code == 200
    data = json.loads(app.post("/api/pov/export", json={"profile_id": pid}).text)
    data["insights"] = [{"counts": {"sections": {"web_action": {"rows": [{"name": "x", "total": 7}]}}}}]
    text = json.dumps(data).replace('"total": 7', f'"total": {total}')
    # Act
    r = app.post("/api/pov/import", json={"profile_id": pid, "content": text, "replace": True})
    opened = app.post("/api/pov/open", json={"profile_id": pid})
    # Assert
    assert r.status_code == 400 and "not JSON" in r.json()["detail"]
    assert opened.status_code == 200 and opened.json()["pov"]["intake"]["customer"] == "Acme"


@pytest.mark.parametrize("total,kept", [(7, 7), (2.5, 2.5), (10 ** 30, 10 ** 30), (float("nan"), None), (float("inf"), None), (True, None), ("9", None)])
def test_an_insights_count_is_a_finite_number_or_nothing(total, kept):
    """ASVS V5.1.4 · CWE-1287: a count kept in a POV is a finite number; anything else is dropped, never stored."""
    # Act
    out = pov._clean_counts({"sections": {"web_action": {"rows": [{"name": "x", "total": total}]}}})
    # Assert
    assert out["sections"]["web_action"]["rows"][0]["total"] == kept
    json.dumps(out, allow_nan=False)


# ── Policy pack uploads ────────────────────────────────────────────────

@pytest.mark.parametrize("where", ["dictionary", "policy"])
def test_a_pack_upload_with_nan_is_refused_and_nothing_is_kept(app, monkeypatch, tmp_path, where):
    """ASVS V5.1.4 · ASVS V12.1.1 · CWE-1287 · CWE-20: a pack file with NaN is refused in words; kept, it passed validation (a rule rank of NaN) and its bundle download was not JSON."""
    # Arrange
    import dlp_importer
    import pack_library as pl
    for mod in (srv, dlp_importer, pl):
        monkeypatch.setattr(mod, "PACKS_ROOT", str(tmp_path))
    monkeypatch.setenv("DLP_CHECK_USER_PACKS", str(tmp_path / "user_packs"))
    monkeypatch.setattr(srv, "get_bind_host", lambda: "127.0.0.1")
    from test_pack_library import _bundle
    b = _bundle()
    (b["dictionaries"][0] if where == "dictionary" else b["policies"][0])["rank"] = "__NAN__"
    text = json.dumps(b).replace('"__NAN__"', "NaN")
    # Act
    r = app.post("/api/pack-library/upload", json={"files": [{"name": "acme.json", "content": text}], "pack_id": "nan_pack"})
    # Assert
    assert r.status_code == 400 and "NaN" in r.json()["detail"]
    assert app.get("/api/pack-library/nan_pack/bundle").status_code == 404
    assert not (tmp_path / "user_packs" / "nan_pack").exists()


# ── HAR batch and the live feed's echoed tally ─────────────────────────

@pytest.mark.parametrize("item", [
    {"host": "a.example.com", "methods": 5}, {"host": "a.example.com", "schemes": 7}, {"host": "a.example.com", "methods": "GET"},
    {"host": "a.example.com", "schemes": [1, None]}, {"host": "a.example.com", "requests": 1e308},
    {"host": "a.example.com", "uploads": [1]}, {"host": "a.example.com", "bytes_sent": {"x": 1}},
])
def test_a_har_host_entry_of_the_wrong_type_is_read_as_nothing_not_a_500(app, item):
    """ASVS V5.1.4 · ASVS V7.4.1 · CWE-843 · CWE-755: a host's counts and lists are type-checked (deny by default); the route goes on to its scope check instead of a 500."""
    # Act
    r = app.post("/api/path-analyzer/batch/start", json={"har_hosts": [item]})
    # Assert
    assert r.status_code == 400 and "in scope" in r.json()["detail"], r.text


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity"])
def test_a_har_count_of_nan_or_infinity_is_not_a_500(app, raw):
    """ASVS V5.1.4 · CWE-1287 · CWE-681: JSON's non-standard NaN and Infinity are refused by the request parser (422) or count as nothing (400 before sign-in); never a 500."""
    # Act
    r = app.post("/api/path-analyzer/batch/start", content='{"har_hosts": [{"host": "a.example.com", "requests": %s}]}' % raw,
                 headers={"Content-Type": "application/json"})
    # Assert
    assert r.status_code in (400, 422) and (r.status_code == 422 or "in scope" in r.json()["detail"]), r.text


def test_batch_host_counts_keep_valid_numbers():
    """ASVS V5.1.3 · CWE-20: valid counts, methods and schemes are kept as sent (happy path, boundary 10**12)."""
    # Arrange
    req = srv.PathBatchRequest(har_hosts=[{"host": "a.example.com", "requests": 3, "uploads": 1.0, "bytes_sent": 10 ** 15,
                                           "methods": ["GET", "post", "PUT"], "schemes": ["https", "ftp"]}])
    # Act
    hosts, stats, skipped = srv._batch_hosts(req)
    # Assert
    assert hosts == ["a.example.com"] and skipped == []
    assert stats["a.example.com"] == {"requests": 3, "uploads": 1, "bytes_sent": 10 ** 12, "methods": ["GET", "PUT"], "schemes": ["https"]}


@pytest.mark.parametrize("prev", [{"a": [1]}, {"seen": "x"}, {"seen": -5, "real": True}, [], "tally", {"seen": float("nan")}])
def test_the_live_feeds_echoed_tally_is_rebuilt_from_known_counters(prev):
    """ASVS V5.1.4 · CWE-20 · CWE-472: the tally the browser sends back is untrusted: unknown keys and wrong types count from zero, never a KeyError."""
    # Act
    t = detection_health.live_stats(prev, [], {})
    # Assert
    assert {k: t[k] for k in ("seen", "enforced", "monitor", "unknown_action", "open", "real", "not_real")} == dict.fromkeys(
        ("seen", "enforced", "monitor", "unknown_action", "open", "real", "not_real"), 0)
    assert "a" not in t


def test_the_live_feeds_tally_still_adds_up_across_polls():
    """ASVS V5.1.3 · CWE-20: a valid tally carries on (happy path)."""
    # Act
    t = detection_health.live_stats({"seen": 4, "real": 1, "not_real": 1, "open": 2}, [], {})
    # Assert
    assert t["seen"] == 4 and t["real"] == 1 and t["not_real"] == 1 and t["open"] == 2


# ── Every POST body: loosely typed fields never make a 500 ──────────────

_APP_CONTROL = ("/api/app/restart", "/api/app/update", "/api/app/shutdown", "/api/update", "/api/shutdown")
_HOSTILE = [5, [1], {"a": [1]}, [{"x": {"y": 1}}], 1e308, "text"]


def _loose(ann) -> bool:
    if ann is typing.Any or ann in (dict, list):
        return True
    args = typing.get_args(ann)
    origin = typing.get_origin(ann)
    if origin in (dict, list, typing.Union):
        return any(a is typing.Any or a in (dict, list) or _loose(a) for a in args) if args else True
    return False


def _loose_fields():
    out = []
    for r in srv.app.routes:
        if not isinstance(r, APIRoute) or "POST" not in r.methods or "{" in r.path or r.path in _APP_CONTROL or r.body_field is None:
            continue
        model = r.body_field.field_info.annotation
        fields = getattr(model, "model_fields", {})
        out += [(r.path, n) for n, f in fields.items() if n != "channels" and _loose(f.annotation)]
    return out


LOOSE_FIELDS = _loose_fields()


def test_the_route_table_has_loosely_typed_fields_to_check():
    """ASVS V5.1.4 · CWE-20: the table below is not empty (a refactor of the route introspection cannot silently test nothing)."""
    # Assert
    assert len(LOOSE_FIELDS) >= 20 and ("/api/path-analyzer/batch/start", "har_hosts") in LOOSE_FIELDS


@pytest.mark.parametrize("path,field", LOOSE_FIELDS)
def test_a_hostile_value_in_a_loosely_typed_field_is_never_a_500(app, monkeypatch, path, field):
    """ASVS V5.1.4 · ASVS V7.4.1 · CWE-20 · CWE-843 · CWE-755 · WSTG-INPV-13: every POST field typed Any/dict/list is checked by the code that reads it: a hostile value is refused in words or ignored, never an internal error. Table-driven over the route table."""
    # Arrange: the sample tenant (offline, no network); jobs are not run (their readers are tested elsewhere)
    import pack_jobs
    monkeypatch.setattr(pack_jobs, "start", lambda kind, fn, **k: type("J", (), {"id": "j", "status": "running", "kind": kind})())
    app.post("/api/offline/sample", json={})
    for value in _HOSTILE:
        # Act
        r = app.post(path, json=dict(SCOPE, **{field: value}))
        # Assert
        assert r.status_code < 500, (path, field, value, r.text[:200])


# ── Test a list: limits and encodings ──────────────────────────────────

@pytest.mark.parametrize("text,why", [
    ("0.0.0.0/0", "at most"), ("::/0", "at most"), ("10.0.0.0/8", "at most"), ("2001:db8::/64", "at most"),
    ("10.0.0.9-10.0.0.1", "ends before it starts"), ("10.0.0.9-1", "ends before it starts"), ("10.0.0.1-::1", "ends before it starts"),
    ("10.0.0.1-300", "over 255"), ("10.0.0.0/33", "CIDR"),
])
def test_a_block_or_range_that_cannot_be_tested_is_skipped_with_its_reason(text, why):
    """ASVS V5.1.3 · ASVS V12.1.1 · CWE-20 · CWE-770 · CWE-1284: a /0 (IPv4 or IPv6), an inverted or mixed range and a bad prefix are skipped in words before anything is expanded."""
    # Act
    p = bulk_test.parse(text + "\nexample.com")
    # Assert
    assert len(p) == 1 and p.skipped and why in p.skipped[0]["why"], p.skipped


def test_the_largest_block_a_row_may_name_expands_exactly():
    """ASVS V12.1.1 · CWE-770: a /16 is the boundary: 65,536 rows; a /15 is skipped."""
    # Act
    ok = bulk_test.parse("10.1.0.0/16")
    over = bulk_test.parse("10.2.0.0/15\nexample.com")
    # Assert
    assert len(ok) == 65536 and ok.targets[0] == "10.1.0.0" and ok.targets[-1] == "10.1.255.255"
    assert len(over) == 1 and "at most" in over.skipped[0]["why"]


@pytest.mark.parametrize("text", ['"' * 4000, '"a' * 2000, ",".join(["x"] * 3000), "\x00" * 100 + "example.com", "\ufeff\ufeffexample.com"])
def test_quote_bombs_wide_rows_and_nul_never_raise(text):
    """ASVS V5.1.3 · CWE-20 · CWE-400: hostile CSV lines are skipped or read, never an exception other than the list error in words."""
    # Act
    try:
        p = bulk_test.parse(text)
    except bulk_test.ListError as e:
        # Assert
        assert str(e)
        return
    assert all("\x00" not in t for t in p.targets)


node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
_DECODE = r"""
const fs = require('fs');
global.window = globalThis; global.document = { getElementById: () => null, querySelectorAll: () => [] };
eval(fs.readFileSync(process.argv[1], 'utf8'));
const b = Buffer.from(process.argv[2], 'base64');
process.stdout.write(JSON.stringify(window.PathListDecode(b.buffer.slice(b.byteOffset, b.byteOffset + b.length))));
"""


@node
@pytest.mark.parametrize("encoding,bom", [("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff"), ("utf-8", b"\xef\xbb\xbf"), ("utf-8", b"")])
def test_a_list_file_is_read_in_the_encoding_its_byte_order_mark_names(encoding, bom):
    """ASVS V5.1.3 · CWE-172 · CWE-838: a UTF-16 list (Excel's Unicode Text) keeps its header and its non-ASCII letters; it was read as UTF-8, losing every column."""
    # Arrange
    import base64
    text = "destination,expected\nexample.com,block\ncafé.example,allow\n"
    raw = bom + text.encode(encoding)
    # Act
    r = subprocess.run(["node", "-e", _DECODE, os.path.join(ROOT, "static", "path_list.js"), base64.b64encode(raw).decode()],
                       capture_output=True, text=True, timeout=60)
    # Assert
    assert r.returncode == 0, r.stderr
    decoded = json.loads(r.stdout)
    assert decoded == text
    parsed = bulk_test.parse(decoded)
    assert parsed.columns == ["destination", "expected"] and parsed.entries[0]["expected"] == "BLOCK"


# ── What-if identity search: the query stays a query ──────────────────

class _Recorder:
    def __init__(self):
        self.calls = []

    def get(self, ep, params=None):
        self.calls.append((ep, dict(params or {})))
        return [], 200


@pytest.mark.parametrize("query", ["../../admin", "a/b?pageSize=10000&x=", "%2e%2e%2fusers", "#frag", "jo\u202ehn", "x" * 64, "'; DROP"])
def test_an_identity_query_reaches_only_the_query_string(query):
    """ASVS V5.3.1 · CWE-74 · CWE-22 · WSTG-INPV-12: whatever is typed, the endpoint path is the fixed one and the query string carries the text exactly once, encoded."""
    # Arrange
    import requests
    cl = _Recorder()
    # Act
    pw.search_identities(cl, "user", query)
    ep, params = cl.calls[0]
    url = requests.Request("GET", "https://api.example.invalid" + ep, params=params).prepare().url
    # Assert: the same composition the raw client sends (sess.get(base + endpoint, params=...))
    parts = urlsplit(url)
    assert ep == "/zia/users" and parts.path == "/zia/users" and not parts.fragment
    q = parse_qs(parts.query, keep_blank_values=True)
    assert q == {"name": [query.strip()], "page": ["1"], "pageSize": [str(pw.SEARCH_LIMIT)]}


@pytest.mark.parametrize("query", ["j", "x" * 65, "jo\nhn", "\x00\x00", "", "   "])
def test_an_identity_query_outside_its_bounds_reads_nothing(query):
    """ASVS V5.1.3 · CWE-20 · CWE-770: 2 to 64 printable characters; anything else is refused before any read."""
    # Arrange
    cl = _Recorder()
    # Act / Assert
    with pytest.raises(ValueError):
        pw.search_identities(cl, "user", query)
    assert cl.calls == []


# ── ZDX custom app URL and AI Guard: no request from the app ────────────

_NETWORK = {"socket", "requests", "httpx", "aiohttp", "urllib3", "http", "ssl", "ftplib", "smtplib"}


@pytest.mark.parametrize("module", ["ops_zdx.py", "ops_aiguard.py", "ai_guard.py"])
def test_the_url_and_app_list_builders_import_no_network_library(module):
    """ASVS V12.6.1 · CWE-918 · OWASP A10:2021 · WSTG-INPV-19: a custom app URL and the AI Guard app list are data sent to the Zscaler API, never fetched by the app's own process."""
    # Arrange
    tree = ast.parse(open(os.path.join(ROOT, module), encoding="utf-8").read())
    # Act
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} \
        | {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    urlopen = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in ("urlopen", "urlretrieve", "create_connection")]
    # Assert
    assert not (imported & _NETWORK) and not urlopen, imported & _NETWORK


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x.example/", "javascript:alert(1)", "https://user:pw@x.example/",
                                 "https://x.example:99999/", "https://exa mple.com/", "http://\u202eevil.example/", "https://localhost/",
                                 "https://" + "a" * 2000 + ".example/", "//x.example/"])
def test_a_custom_app_url_outside_http_and_a_real_host_is_refused(url):
    """ASVS V5.1.3 · ASVS V12.6.1 · CWE-20 · CWE-918: only http(s) URLs to a real host name or address, without credentials, become a ZDX probe."""
    # Arrange
    import ops_zdx
    # Act
    clean, why = ops_zdx.clean_url(url)
    # Assert
    assert clean is None and why


# ── Exports: bidirectional controls stay visible, never reorder text ───

RLO = "Allow \u202eexe.txt"


@pytest.mark.parametrize("render", [
    lambda s: md_safe.text(s), lambda s: md_safe.code(s), lambda s: csv_safe.safe_cell(s), lambda s: xlsx_writer.clean_text(s),
    lambda s: xlsx_writer.cell_text(s),
])
def test_an_explicit_bidirectional_control_is_shown_not_obeyed_in_exports(render):
    """ASVS V5.3.1 · CWE-451 · CWE-116: a right-to-left override (or any embedding or isolate) in a tenant name becomes U+FFFD in Markdown, CSV, Excel and Word, so the text after it is not turned around."""
    # Act
    out = render(RLO + " \u2066x\u2069 \u202ay\u202c")
    # Assert
    assert not md_safe.BIDI_CONTROLS.search(out) and out.count("\ufffd") == 5 and "exe.txt" in out


@pytest.mark.parametrize("name", ["\u0645\u0631\u062d\u0628\u0627 rule", "\u05e9\u05dc\u05d5\u05dd", "ZW\u200dJ and ZW\u200cNJ", "a\u200bb"])
def test_right_to_left_names_and_joiners_are_kept(name):
    """ASVS V5.1.3 · CWE-176: Arabic and Hebrew names and zero-width joiners (which scripts need) pass through unchanged."""
    # Act / Assert
    assert md_safe.one_line(name) == name and csv_safe.safe_cell(name) == name and xlsx_writer.clean_text(name) == name


@pytest.mark.parametrize("value", ["Allow \u202eexe.txt", "a\u2066b\u2069c", "zero\u200bwidth", "bom\ufeff", "plain \\u202e text", "\u202e${x}%{y}\\"])
def test_terraform_writes_invisible_characters_as_escapes_and_reads_them_back(value):
    """ASVS V5.3.1 · CWE-451 · CWE-1007 · CWE-94: a bidirectional or invisible character in a Terraform string is written as \\uNNNN (CVE-2021-42574): the file shows text in the order it runs, and the value read back is the same."""
    # Arrange
    import pack_library
    import pack_terraform
    from hcl_strict import string_value
    # Act
    quoted = pack_terraform.hcl_str(value)
    comment = pack_terraform.hcl_comment(value)
    # Assert
    assert not md_safe.BIDI_CONTROLS.search(quoted) and "\u200b" not in quoted and "\ufeff" not in quoted
    assert string_value(quoted) == value and pack_library._unescape(quoted[1:-1]) == value
    assert not md_safe.BIDI_CONTROLS.search(comment) and "\u200b" not in comment


# ── One IDN encoder (UTS 46) for every module that places a host name ────

_IDN_CASES = [("straße.example", "xn--strae-oqa.example"), ("faß.de", "xn--fa-hia.de"), ("σς.example", "xn--3xab.example"),
              ("münchen.de", "xn--mnchen-3ya.de"), ("Example.COM.", "example.com")]


@pytest.mark.parametrize("typed,expected", _IDN_CASES, ids=[c[1] for c in _IDN_CASES])
def test_every_module_encodes_an_international_host_name_the_same_way(typed, expected):
    """ASVS V5.1.3 · CWE-176 · CWE-180: the ZPA analysis, the ZPA builder's domain check, Bulk changes and the Path analyzer give one ASCII form for the same typed name (UTS 46, deviation characters ß and ς kept, not mapped to ss and σ)."""
    # Arrange
    import admin_ops
    import ops_zpa
    import path_analyzer
    import zia_path_modules
    import zpa_analysis
    # Act
    got = {
        "zia_path_modules.ascii_host": zia_path_modules.ascii_host(typed),
        "path_analyzer.parse_destination": path_analyzer.parse_destination(typed)["host"],
        "zpa_analysis.parse_destination": zpa_analysis.parse_destination(typed)["host"],
        "zpa_analysis._entry_key": zpa_analysis._entry_key(typed),
        "ops_zpa.check_domain": ops_zpa.check_domain(typed, "Domain"),
        "admin_ops._ascii_host": admin_ops._ascii_host(typed.lower().rstrip(".")),
        "admin_ops.normalize_domain": admin_ops.normalize_domain(typed)[0],
        "admin_ops.normalize_url": admin_ops.normalize_url(typed)[0],
    }
    # Assert
    assert got == {k: expected for k in got}


def test_a_zpa_segment_holding_the_uts46_form_matches_what_the_user_typed():
    """ASVS V5.1.3 · CWE-180 · CWE-697: a segment that holds xn--strae-oqa.example (or the name in Unicode) matches the typed straße.example, and a wildcard keeps its "*." while the rest is encoded."""
    # Arrange
    import zpa_analysis
    host = zpa_analysis.parse_destination("straße.example")["host"]
    # Act
    exact = zpa_analysis._domain_match("xn--strae-oqa.example", host, False)
    unicode_entry = zpa_analysis._domain_match("Straße.example.", host, False)
    wildcard = zpa_analysis._entry_key("*.straße.example")
    # Assert
    assert exact is not None and unicode_entry == exact
    assert wildcard == "*.xn--strae-oqa.example"


@pytest.mark.parametrize("bad", ["a‍b.example", "xn--zz.ß́́́.example" * 3, "\ud800.example"])
def test_a_host_name_uts46_refuses_is_refused_in_words_in_every_module(bad):
    """ASVS V5.1.3 · CWE-20 · CISA SbD fail closed: a name UTS 46 refuses is refused in words by the ZPA analysis, the ZPA builder and Bulk changes (never encoded another way, never an exception other than ValueError)."""
    # Arrange
    import admin_ops
    import ops_zpa
    import zpa_analysis
    # Act / Assert
    with pytest.raises(ValueError):
        zpa_analysis.parse_destination(bad)
    with pytest.raises(ValueError):
        ops_zpa.check_domain(bad, "Domain")
    assert admin_ops._ascii_host(bad) is None and admin_ops.normalize_domain(bad)[0] is None


# ── One pack-file reader: deploy, Terraform export and the library agree ──

def _pack_on_disk(tmp_path, pack_id, policies_bytes):
    from test_pack_deploy import _dict, _engine, _policy, write_pack
    pack = write_pack(tmp_path, pack_id, dicts=[_dict("QA Dict")], engines=[_engine("QA Engine", "(D:QA Dict)")],
                      policies=[_policy("QA-Monitor", ["QA Engine"])], meta={"name": "QA pack", "confidence_tweaks": []})
    if policies_bytes is not None:
        with open(os.path.join(pack["dir"], "configs", "dlp_policies.json"), "wb") as f:
            f.write(policies_bytes)
    return pack


def _reader_verdicts(pack):
    """Accepted (True) or refused (False) by each reader of a pack folder."""
    import dlp_importer
    import pack_deploy
    import pack_library
    import pack_terraform

    def ok(fn):
        try:
            out = fn()
        except ValueError:      # PackFileError is a ValueError
            return False
        return not (isinstance(out, dict) and out.get("error"))
    return {
        "deploy (pack_deploy.load_sources)": ok(lambda: pack_deploy.load_sources([pack])),
        "Terraform export (pack_terraform.load_pack)": ok(lambda: pack_terraform.load_pack(pack)),
        "library listing (dlp_importer.load_pack_metadata)": ok(lambda: dlp_importer.load_pack_metadata(pack["dir"])),
        "pack detail (dlp_importer.load_pack_contents)": ok(lambda: dlp_importer.load_pack_contents(pack["dir"])),
        "library bundle (pack_library.pack_bundle)": ok(lambda: pack_library.pack_bundle(pack["dir"])),
    }


_PACK_FILES = [
    ("plain", None, True),
    ("utf8-bom", b"\xef\xbb\xbf" + json.dumps([{"name": "QA-Monitor", "engines": ["QA Engine"], "channel": "web"}]).encode(), True),
    ("name-not-text", json.dumps([{"name": 5, "engines": ["QA Engine"]}]).encode(), False),
    ("not-a-list", b'{"policies": []}', False),
    ("too-deep", ("[" * 40 + "]" * 40).encode(), False),
]


@pytest.mark.parametrize("label,content,accepted", _PACK_FILES, ids=[c[0] for c in _PACK_FILES])
def test_every_pack_reader_accepts_and_refuses_the_same_files(tmp_path, label, content, accepted):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-1287: one pack-file reader: a pack with a UTF-8 BOM, a non-text name, a non-list or deep nesting gets the same verdict from deploy, Terraform export and the library."""
    # Arrange
    pack = _pack_on_disk(tmp_path, f"qa_{label.replace('-', '_')}", content)
    # Act
    verdicts = _reader_verdicts(pack)
    # Assert
    assert verdicts == {k: accepted for k in verdicts}


def test_an_oversize_pack_file_is_refused_by_every_reader(tmp_path, monkeypatch):
    """ASVS V12.1.1 · CWE-400 · CWE-770: a pack file over the size cap is refused by deploy, Terraform export and the library alike, never parsed."""
    # Arrange
    import pack_deploy
    monkeypatch.setattr(pack_deploy, "PACK_FILE_MAX_BYTES", 64)
    pack = _pack_on_disk(tmp_path, "qa_big", json.dumps([{"name": "P" * 200}]).encode())
    # Act
    verdicts = _reader_verdicts(pack)
    # Assert
    assert verdicts == {k: False for k in verdicts}


def test_the_fan_out_tool_reads_packs_through_the_one_reader(tmp_path):
    """SSDF PW.4.1 · CWE-20 · CWE-1287: tools/fan_out_channels.py reads a pack with the same reader (a BOM pack loads, a non-text name is refused)."""
    # Arrange
    import importlib.util
    spec = importlib.util.spec_from_file_location("fan_out_channels_qa", os.path.join(ROOT, "tools", "fan_out_channels.py"))
    fan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fan)
    bom = _pack_on_disk(tmp_path, "qa_fan_bom", _PACK_FILES[1][1])
    bad = _pack_on_disk(tmp_path, "qa_fan_bad", _PACK_FILES[2][1])
    # Act
    changed, _summary = fan.process(bom, write=False)
    # Assert
    assert changed is True
    with pytest.raises(ValueError):
        fan.process(bad, write=False)
