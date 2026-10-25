"""Find anything (static/find_anything.js): one search box, Ctrl/Cmd+J or /,
over the app's pages (the explain.js catalogue), the glossary, the tenant's
objects from the last console index, the findings on screen and the open
to-dos.

The matching runs in node against the real catalogue and glossary: every
page is found by its own name, typos and synonyms land where a person
means, and a tenant object or a finding is found by name. The page wiring
is checked statically: every report page and the assessment page load the
script after explain.js, the dialog is a real ARIA combobox and listbox in
a modal dialog that traps and restores focus, and typing never reads the
tenant (only Load tenant objects posts the console index)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
NODE = shutil.which("node")
TAG = '<script src="/static/find_anything.js"></script>'


def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


# The node harness: explain.js and glossary.js loaded as a browser would
# (they only set window.*), then find_anything.js as a module of pure functions.
HARNESS = r"""
const root = process.argv[1];
global.window = {}; global.document = { body: null, addEventListener() {} };
require(root + '/static/explain.js'); require(root + '/static/glossary.js');
const W = global.window; delete global.window;
const c = require(root + '/static/find_anything.js');
const input = JSON.parse(process.argv[2]);
const items = c.pageItems(W.DLP_EXPLAIN, W.DLP_EXPLAIN_ORDER)
  .concat(c.findingItems(input.report)).concat(c.objectItems(input.index, input.tags)).concat(c.todoItems(input.notes))
  .concat(c.termItems(W.SIMPLE_GLOSSARY, W.DLP_GLOSSARY));
const out = { keys: Object.keys(W.DLP_EXPLAIN), pages: items.filter(i => i.type === 'Page').map(i => i.key), queries: {},
  byName: {}, syn: { block: c.synonymsOf('block'), tf: c.synonymsOf('tf') }, parsed: c.parseQuery('how do I stop data loss').map(t => t.text),
  osa: [c.osa('terrafrom', 'terraform', 2), c.osa('kitten', 'sitting', 5), c.osa('abc', 'abc', 1)] };
for (const q of input.queries) out.queries[q] = c.search(items, q, 5).map(i => ({ type: i.type, title: i.title, key: i.key || null, line: i.line }));
for (const k of Object.keys(W.DLP_EXPLAIN)) {
  const name = W.DLP_EXPLAIN[k].name;
  const typo = name.length > 6 ? name.slice(0, 2) + name[3] + name[2] + name.slice(4) : name;
  out.byName[k] = [c.search(items, name, 3).map(i => i.key), c.search(items, typo, 5).map(i => i.key)];
}
console.log(JSON.stringify(out));
"""

QUERIES = ["how do I export to terraform", "terrafrom", "tf", "deny", "data loss", "what is an engine", "dictonary", "pth analyser",
           "to-do", "Board Phrases", "partner sites", "5.20", "evaluate all", "urgent", "SSN"]


def _index():
    import console_index as ci
    import test_console_index as tci
    return ci.from_inventory(tci._inventory(), zia=tci._zia(), tenant_label="acme (production)", now=1)


def _run():
    report = {"checks": [
        {"id": "5.20", "label": "Inline DLP evaluates all rules", "status": "FAIL", "section": "DLP policy",
         "plain": {"found": "The tenant runs first match.", "do": "Switch to Evaluate All Rules."}},
        {"id": "5.21", "label": "A passing check", "status": "PASS", "section": "DLP policy"},
        {"id": "9.9", "label": "Out of scope check", "status": "FAIL", "section": "ZPA", "out_of_scope": True}]}
    notes = [{"id": "n1", "kind": "rule", "ref": "rule:endpoint:EP-Board", "label": "DLP rule: EP-Board", "tags": ["urgent"],
              "todos": [{"id": "t1", "text": "Raise the threshold on the board engine", "done": False},
                        {"id": "t2", "text": "Already done item", "done": True}]}]
    payload = {"report": report, "index": _index(), "tags": {"rule:endpoint:EP-Board": ["urgent"]}, "notes": notes, "queries": QUERIES}
    r = subprocess.run([NODE, "-e", HARNESS, ROOT, json.dumps(payload)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


@needs_node
def test_every_catalogue_entry_is_a_page_found_by_its_name_even_with_a_typo():
    out = _run()
    assert sorted(out["pages"]) == sorted(out["keys"]), "every explain.js entry is searchable"
    for key, (exact, typo) in out["byName"].items():
        assert exact and exact[0] == key, (key, exact)
        assert key in typo, (key, typo)


@needs_node
def test_plain_language_typos_and_synonyms_land_where_people_mean():
    out = _run()
    q = out["queries"]
    assert q["how do I export to terraform"][0]["key"] == "terraform"
    assert q["terrafrom"][0]["key"] == "terraform" and q["tf"][0]["key"] == "terraform"
    assert {"type": "Term", "title": "block"} in [{"type": x["type"], "title": x["title"]} for x in q["deny"][:3]], q["deny"]
    assert q["data loss"][0]["title"] == "DLP" and q["data loss"][0]["type"] == "Term"
    eng = q["what is an engine"][0]
    assert eng["type"] == "Term" and eng["title"] == "engine" and "engine" in eng["line"].lower(), "a term shows its plain meaning inline"
    assert q["dictonary"][0]["title"] == "dictionary"
    assert q["pth analyser"][0]["key"] == "path"
    assert q["to-do"][0]["title"] in ("to-do", "To-do list")
    assert "deny" in out["syn"]["block"] and "terraform" in out["syn"]["tf"]
    assert out["parsed"] == ["stop", "data loss"], "stop words go; a known phrase is one term"
    assert out["osa"] == [1, 3, 0]


@needs_node
def test_tenant_objects_findings_and_todos_are_searchable():
    out = _run()
    q = out["queries"]
    assert q["Board Phrases"][0]["type"] == "DLP dictionary" and q["Board Phrases"][0]["title"] == "Board Phrases"
    assert q["partner sites"][0]["type"] == "URL category"
    f = q["5.20"][0]
    assert f["type"] == "Finding" and f["title"] == "Inline DLP evaluates all rules" and "Action required" in f["line"]
    assert all(x["title"] != "A passing check" and x["title"] != "Out of scope check" for v in q.values() for x in v), \
        "only findings that need action, in scope"
    types = [x["type"] for x in q["urgent"]]
    assert "To-do" in types and "DLP rule" in types, "a tag finds the object and its to-do"
    assert not any(x["title"] == "Already done item" for v in q.values() for x in v)


def test_every_report_page_and_the_assessment_page_load_it_after_explain():
    pages = sorted(n for n in os.listdir(STATIC) if n.startswith("report_") and n.endswith(".html")) + ["help.html"]
    for name in pages:
        html = _read(name)
        assert html.count(TAG) == 1, name
        assert html.index('<script src="/static/explain.js"></script>') < html.index(TAG), name
    assert srv.GUI_ADDONS.index(("find_anything.js", "script")) == srv.GUI_ADDONS.index(("explain.js", "script")) + 1
    c = TestClient(srv.app)
    home = c.get("/").text
    assert home.index("/static/explain.js") < home.index("/static/find_anything.js") < home.index("/static/guide.js")
    assert c.get("/static/find_anything.js").status_code == 200
    index = _read("index.html")
    assert 'onclick="openFindAnything()"' in index and "function openFindAnything()" in index and "window.DLP_FIND.open()" in index


def test_the_dialog_is_an_accessible_combobox_in_a_modal_that_traps_and_restores_focus():
    js = _read("find_anything.js")
    for needle in ("role: 'combobox'", "'aria-expanded'", "'aria-controls': 'faList'", "'aria-autocomplete': 'list'", "aria-activedescendant",
                   "role: 'listbox'", "role: 'option'", "'aria-selected'", "role: 'dialog'", "'aria-modal': 'true'", "'aria-labelledby': 'faTitle'",
                   "e.key === 'Escape'", "e.key === 'Tab'", "ArrowDown", "ArrowUp", "e.key === 'Enter'", "S.lastFocus = document.activeElement",
                   "back.focus()", "role: 'status'", "'aria-live': 'polite'", "(e.ctrlKey || e.metaKey)", "=== 'j'", "e.key === '/'", "typing(e.target)",
                   "'aria-keyshortcuts'", "text: 'Find'"):
        assert needle in js, needle
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js, "every value is set as text"
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", js), "colours come from the theme tokens"
    assert "gradient" not in js and "box-shadow" not in js and "blur(" not in js
    assert "@media (max-width:600px)" in js


def test_typing_never_reads_the_tenant():
    js = _read("find_anything.js")
    # The one POST of the console index is the Load tenant objects button's.
    posts = [m.start() for m in re.finditer(r"getJson\('/api/console-index',", js)]
    assert len(posts) == 1
    load = js[js.index("async function loadTenant()"):]
    load = load[:load.index("\n  }\n")]
    assert "getJson('/api/console-index'," in load and "scopeSelection()" in load
    assert "onclick: loadTenant" in js
    # As you type: the search only, over what is already in the page.
    run = js[js.index("function runSearch()"):]
    run = run[:run.index("\n  }\n")]
    assert "fetch" not in run and "getJson" not in run
    assert "/api/console-index/cached?" in js, "the kept index is read from the server's cache, which never reads the tenant"
