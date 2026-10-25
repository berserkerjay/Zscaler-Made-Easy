"""The companion browser extension (browser_extension/).

It is a thin launcher for the app on this computer: it holds no
credentials or tenant data, asks for the least the browser offers
(activeTab, not every site), talks only to loopback, never passes a query
string on, and never sends a selected paragraph anywhere. The app serves
it as a zip from Advanced settings.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT = os.path.join(ROOT, "browser_extension")
NODE = shutil.which("node")


def _read(*parts):
    with open(os.path.join(EXT, *parts), encoding="utf-8") as f:
        return f.read()


def _manifest():
    return json.loads(_read("manifest.json"))


def test_the_manifest_asks_for_the_least_it_needs():
    m = _manifest()
    assert m["manifest_version"] == 3
    assert sorted(m["permissions"]) == ["activeTab", "contextMenus", "scripting", "sidePanel", "storage"]
    assert m["host_permissions"] == ["http://127.0.0.1/*", "http://localhost/*"], "only the app on this computer"
    # The console badges are opt-in: the ZIA admin consoles are optional and asked for on a click.
    assert "optional_permissions" not in m
    import zscaler_clouds
    consoles = sorted({f"https://{c['admin']}/*" for c in zscaler_clouds.CLOUDS.values()}) if hasattr(zscaler_clouds, "CLOUDS") else None
    assert all(re.fullmatch(r"https://admin\.[a-z]+\.(net|us)/\*", o) for o in m["optional_host_permissions"])
    if consoles:
        assert sorted(m["optional_host_permissions"]) == consoles
    assert "content_scripts" not in m, "no page script is declared; the console one is registered only once allowed"
    assert m["side_panel"]["default_path"] == "panel.html"
    assert "externally_connectable" not in m and "web_accessible_resources" not in m
    csp = m["content_security_policy"]["extension_pages"]
    assert "script-src 'self'" in csp and "object-src 'none'" in csp and "unsafe" not in csp
    assert "connect-src http://127.0.0.1:* http://localhost:*" in csp
    for size in ("16", "32", "48", "128"):
        path = m["icons"][size]
        with open(os.path.join(EXT, path), "rb") as f:
            assert f.read(8) == b"\x89PNG\r\n\x1a\n", path


def test_every_file_the_manifest_names_exists_and_no_remote_code():
    m = _manifest()
    named = [m["action"]["default_popup"], m["options_page"], m["background"]["service_worker"], m["side_panel"]["default_path"], "console.js", "tokens.css"]
    for n in named:
        assert os.path.isfile(os.path.join(EXT, n)), n
    for name in os.listdir(EXT):
        if not name.endswith((".js", ".html", ".css")):
            continue
        text = _read(name)
        # Match patterns (http://*/*) say where the menu shows, not where anything is sent.
        urls = [u for u in re.findall(r"https?://[^\s'\"`)<]+", text) if "*" not in u]
        assert all(re.match(r"https?://(127\.0\.0\.1|localhost)\b", u) for u in urls), (name, urls)
        assert "eval(" not in text and "new Function" not in text and "innerHTML" not in text and "insertAdjacentHTML" not in text, name
        assert not re.search(r"(secret|password|token|client_id|api_key)\s*[:=]", text, re.I), f"{name} must hold no credential"
    for html in ("popup.html", "options.html"):
        text = _read(html)
        assert "<script>" not in text and "onclick=" not in text, "no inline script (the extension CSP forbids it)"


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_addresses_are_loopback_only_and_destinations_are_trimmed():
    script = """
const m = await import(process.argv[1]);
const out = {
  app: ['http://127.0.0.1:8001', 'http://localhost:8000/x?y', 'https://127.0.0.1', 'http://[::1]:8000', 'http://evil.example:8000',
        'http://127.0.0.1.evil.example', 'file:///etc', 'http://user:pw@127.0.0.1:8000', 'javascript:alert(1)', ''].map(m.normalizeAppUrl),
  url: ['https://drive.google.com/u/0/upload?token=abc#frag', 'https://example.com/', 'chrome://settings', 'ftp://x.example', 'not a url',
        'http://10.0.0.5:8080/a?b=c'].map(m.destinationFromUrl),
  text: ['dropbox.com', 'https://box.com/s/abc?share=1', '203.0.113.10', '*.wetransfer.com', 'my secret plan is this',
         'John.Smith@corp.example', 'card 4111111111111111', 'pastebin.com/raw/xyz?x=1', 'a'.repeat(3000), 'localhost'].map(m.destinationFromText),
  path: m.pathAnalyzerUrl('http://127.0.0.1:8000', 'https://drive.google.com/a b'),
  empty: m.pathAnalyzerUrl('http://127.0.0.1:8000', null),
};
console.log(JSON.stringify(out));
"""
    r = subprocess.run([NODE, "--input-type=module", "-e", script, os.path.join(EXT, "common.js")],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["app"] == ["http://127.0.0.1:8001", "http://localhost:8000", "https://127.0.0.1", "http://[::1]:8000",
                          None, None, None, None, None, None]
    assert out["url"] == ["https://drive.google.com/u/0/upload", "https://example.com", None, None, None, "http://10.0.0.5:8080/a"], \
        "query strings and fragments never travel"
    assert out["text"] == ["dropbox.com", "https://box.com/s/abc", "203.0.113.10", "*.wetransfer.com", None,
                           None, None, "pastebin.com/raw/xyz", None, None], "only one hostname, URL or IP: never a sentence or an e-mail"
    assert out["path"] == "http://127.0.0.1:8000/report/path?d=https%3A%2F%2Fdrive.google.com%2Fa%20b"
    assert out["empty"] == "http://127.0.0.1:8000/report/path"


def test_the_extension_talks_only_to_the_app_and_holds_no_token():
    common = _read("common.js")
    assert common.count("fetch(") == 3, "ping, the API call and a job's file: nothing else"
    assert "${base}/api/ping" in common and "credentials: 'omit'" in common and "body.ok !== true" in common
    assert common.count("credentials: 'include'") == 2, "the app's own sign-in cookie authenticates; the extension stores no token"
    for name in ("background.js", "popup.js", "options.js", "panel.js", "console.js"):
        assert "fetch(" not in _read(name), name
    calls = set(re.findall(r"api\(S\.base, '([^'`]+)", _read("panel.js")))
    assert calls == {"/api/tenant-profiles", "/api/console-index", "/api/dlp-packs/export/start", "/api/workspace/notes?"}, calls
    # Workspace notes are only read from the panel (a GET: no body argument); writing them stays in the app.
    assert "api(S.base, '/api/workspace/notes?' + new URLSearchParams({ tenant, kind: o.kind, ref: objectKey(o) }).toString())" in _read("panel.js")
    import security
    assert not any("workspace" in p for p in security.EXTENSION_POST_PATHS)
    # The console script sends nothing from the page: only keys of objects Zscaler Made Easy already knows.
    con = _read("console.js")
    assert "sendMessage({ type: 'focus', key: e.key, keys: entries.map(x => x.key) })" in con and "sendMessage({ type: 'names' })" in con
    assert con.count("sendMessage(") == 2 and "fetch" not in con and "XMLHttpRequest" not in con
    assert "attachShadow({ mode: 'closed' })" in con, "badges cannot be styled or read by the console page"
    bg = _read("background.js")
    assert "chrome.permissions.contains({ origins: CONSOLE_ORIGINS })" in bg and "registerContentScripts" in bg and "unregisterContentScripts" in bg
    bg = _read("background.js")
    assert "chrome.tabs.create" in bg and "contexts: ['link']" in bg and "contexts: ['selection']" in bg
    # The Path analyzer pre-fills from ?d= and does not run until Analyze is clicked.
    path = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    assert "if (q.get('d')) document.getElementById('paDest').value = q.get('d');" in path


def test_the_app_serves_the_extension_and_advanced_settings_offers_it():
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    c = TestClient(srv.app)
    r = c.get("/api/browser-extension.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert 'filename="dlp-check-extension.zip"' in r.headers["content-disposition"]
    names = set(zipfile.ZipFile(io.BytesIO(r.content)).namelist())
    on_disk = {f"dlp-check-extension/{os.path.relpath(os.path.join(d, n), EXT).replace(os.sep, '/')}"
               for d, _, files in os.walk(EXT) for n in files if not n.startswith(".")}
    assert names == on_disk and "dlp-check-extension/manifest.json" in names
    adv = open(os.path.join(ROOT, "static", "report_advanced.html"), encoding="utf-8").read()
    assert 'href="/api/browser-extension.zip"' in adv and "Load unpacked" in adv and "chrome://extensions" in adv
    assert "companion browser extension" in open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()


def test_the_extension_ships_in_the_container_and_the_docs():
    ignore = open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8").read().split()
    assert not any(p.strip("/") == "browser_extension" for p in ignore)
    doc = open(os.path.join(ROOT, "docs", "BROWSER_EXTENSION.md"), encoding="utf-8").read()
    low = doc.lower()
    for needle in ("Load unpacked", "activeTab", "127.0.0.1", "query string"):
        assert needle in doc, needle
    assert "no credentials" in low


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_badges_say_what_uses_an_object_or_its_worst_finding_for_every_kind():
    """The badge text for each kind, from the app's own index (console_index
    built from the test fixtures), and the keys the panel, badges and stage share."""
    import console_index as ci
    import test_console_index as tci
    idx = ci.from_inventory(tci._inventory(), zia=tci._zia(), now=1)
    pick = {f"{o['kind']}|{o['name']}": o for o in idx["objects"]}
    want = ["url_category|Partner sites", "url_category|Never used", "url_rule|Block gambling", "url_rule|Old rule", "url_rule|Allow all",
            "firewall_rule|Allow DNS", "location|HQ", "group|Finance", "engine|Unused Engine", "rule|EP-Board", "dictionary|Board Phrases"]
    objs = [pick[k] for k in want]
    script = """
const m = await import(process.argv[1]);
const objs = JSON.parse(process.argv[2]);
console.log(JSON.stringify({ labels: objs.map(o => m.badgeLabel(o)), keys: objs.map(m.objectKey),
  legacy: m.objectKey({ kind: 'rule', channel: 'web', name: 'X' }), kinds: ['url_category', 'nope'].map(k => m.kindInfo(JSON.parse(process.argv[3]), k).label),
  shadow: m.PAGES.shadow.path, shadowKinds: m.SHADOW_KINDS }));
"""
    r = subprocess.run([NODE, "--input-type=module", "-e", script, os.path.join(EXT, "common.js"), json.dumps(objs), json.dumps({"kinds": idx["kinds"]})],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    labels = dict(zip(want, out["labels"]))
    assert labels["url_category|Partner sites"] == {"label": "used in 3 rules", "sev": "info"}
    assert labels["url_category|Never used"] == {"label": "unused", "sev": "low"}
    assert labels["url_rule|Block gambling"] == {"label": "shadowed", "sev": "high"}
    assert labels["url_rule|Old rule"]["label"] == "disabled"
    assert labels["url_rule|Allow all"]["label"] == "order 1 · allow"
    assert labels["firewall_rule|Allow DNS"]["label"] == "order 1 · allow"
    assert labels["location|HQ"]["label"] == "used in 2 rules" and labels["group|Finance"]["label"] == "used in 2 rules"
    assert labels["engine|Unused Engine"]["label"] == "unused" and labels["rule|EP-Board"]["label"] == "monitor only"
    assert labels["dictionary|Board Phrases"]["label"].endswith("rules")
    assert out["keys"] == [o["key"] for o in objs] and out["legacy"] == "rule:web:X"
    assert out["kinds"] == ["URL category", "nope"] and out["shadow"] == "/report/shadow" and "ftc_rule" not in out["shadowKinds"]


def test_the_panel_filters_by_kind_and_stages_only_what_export_supports():
    panel = _read("panel.js")
    # A kind filter (a labelled select grouped DLP / Policies / Objects) on On this page and Search.
    assert "h('select', { id: 'kindFilter', 'aria-label': 'Kind'" in panel and "h('optgroup', { label: g.name }" in panel
    assert panel.count("kindFilter(all, run)") == 2
    # Used by is grouped per policy; uses per kind; a name shared by several objects lists them.
    assert "function usedBySections(o)" in panel and "Used by ${policyLabel(p)} rules" in panel and "function viewSameName(keys)" in panel
    # Only DLP objects (the kinds Export from tenant supports) can be staged; others get deep links.
    assert "if (o && exportable(o) && !S.stage.includes(key))" in panel and "S.byKey.get(k)).filter(o => o && exportable(o))" in panel
    assert "openIn('shadow')" in panel and "SHADOW_KINDS.includes(o.kind)" in panel
    assert "not shown: Zscaler Made Easy keeps" in panel, "a capped kind says how many more there are"
    bg = _read("background.js")
    assert "slice(0, 20)" in bg and "typeof k === 'string'" in bg, "a badge click carries at most 20 known keys"
