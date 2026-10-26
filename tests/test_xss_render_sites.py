"""ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: the render sites fixed in the injection pass escape tenant and upload text.

Each case runs the page's real function, cut out of the shipped file, in
node's vm with a small DOM stand-in (no browser, no network, no clock), feeds
it an injection payload where tenant or uploaded data goes, and checks the
HTML it writes: the payload must arrive as text (&lt;img ...), never as an
element. Skips only when node is not installed (CI has it).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

import html_sink_scan as scan

PAYLOAD = '<img src=x onerror=alert(1)>"><svg onload=alert(2)>\'-alert(3)-\''
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")

RUNNER = r"""
const vm = require('vm');
const fs = require('fs');
const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const els = {};
function mk(id) {
  return { id, innerHTML: '', textContent: '', style: {}, dataset: {}, children: [],
           insertAdjacentElement(pos, e) { if (e.id) els[e.id] = e; },
           insertAdjacentHTML(pos, h) { this.innerHTML += h; },
           appendChild(e) { this.children.push(e); }, addEventListener() {}, setAttribute() {},
           querySelector() { return null; }, querySelectorAll() { return []; }, focus() {}, scrollIntoView() {} };
}
const document = {
  getElementById: id => (els[id] = els[id] || mk(id)),
  createElement: tag => { const e = mk(''); e.tagName = tag; return new Proxy(e, { set(t, k, v) { t[k] = v; if (k === 'id') els[v] = t; return true; } }); },
  querySelector: () => null, querySelectorAll: () => [], body: mk('body'),
};
const sandbox = { console, document, window: {}, JSON, Object, Array, String, Math, Number, Promise, encodeURIComponent,
  fetch: async () => ({ ok: true, status: 200, json: async () => cfg.response }), confirm: () => true, alert: () => {} };
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(cfg.code, sandbox);
Promise.resolve(vm.runInContext(cfg.call, sandbox)).then(ret => {
  const html = {}; for (const [k, v] of Object.entries(els)) html[k] = v.innerHTML;
  process.stdout.write(JSON.stringify({ ret: typeof ret === 'string' ? ret : null, html }));
});
"""


def _source(rel: str) -> str:
    path = os.path.join(scan.ROOT, rel)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return scan.inline_scripts(text) if rel.endswith(".html") else text


def extract(rel: str, name: str) -> str:
    """The source of `function name(...) {...}` or `const name = ...;` in a shipped file."""
    src = _source(rel)
    toks, _ = scan.lex(src)
    br = scan.match_brackets(toks)
    for k, t in enumerate(toks):
        if t.kind == "ident" and t.text == "function" and k + 1 < len(toks) and toks[k + 1].text == name:
            start = toks[k - 1].pos if k and toks[k - 1].text == "async" else t.pos
            j = k + 2
            close = br[j]
            return src[start:toks[br[close + 1]].end]
        if t.kind == "ident" and t.text in ("const", "let", "var") and k + 2 < len(toks) and toks[k + 1].text == name \
                and toks[k + 2].text == "=":
            j = k + 3
            while j < len(toks) and toks[j].text != ";":
                j = br.get(j, j) + 1 if toks[j].text in "([{" else j + 1
            return src[t.pos:toks[j].end]
    raise AssertionError(f"{name} not found in {rel}")


def run(tmp_path, code: str, call: str, response=None):
    (tmp_path / "runner.js").write_text(RUNNER, encoding="utf-8")
    (tmp_path / "cfg.json").write_text(json.dumps({"code": code, "call": call, "response": response}), encoding="utf-8")
    out = subprocess.run([NODE, str(tmp_path / "runner.js"), str(tmp_path / "cfg.json")], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def assert_inert(html: str):
    assert html, "nothing was rendered"
    low = html.lower()
    assert "<img" not in low and "<svg" not in low, html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html, "the payload should be shown as text"


def _index(*names):
    return "\n".join([extract("static/index.html", "escapeHtml")] + [extract("static/index.html", n) for n in names])


def test_operations_preview_escapes_object_names(tmp_path):
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: a tenant URL category or rule name in the bulk-operation preview is text."""
    # Arrange
    code = extract("static/report_operations.html", "E") + "\n" + extract("static/report_operations.html", "objName")
    # Act
    out = run(tmp_path, code, f"objName({{object: {{name: {json.dumps(PAYLOAD)}, type: 'url_category'}}}})")
    # Assert
    assert_inert(out["ret"])


def test_operations_preview_falls_back_to_the_id_escaped(tmp_path):
    """ASVS V5.3.3 · CWE-79: boundary, an object with no name shows its id, escaped too."""
    code = extract("static/report_operations.html", "E") + "\n" + extract("static/report_operations.html", "objName")
    out = run(tmp_path, code, f"objName({{object: {{id: {json.dumps(PAYLOAD)}}}}})")
    assert_inert(out["ret"])


def test_rule_migrator_diff_escapes_uploaded_rule_fields(tmp_path):
    """ASVS V5.3.3 · CWE-79 · WSTG-BUSL-09: an uploaded rules file's id, action and positions are text in the diff."""
    code = _index("showDiff")
    diff = [{"rule_id": PAYLOAD, "rule_name": PAYLOAD, "action": PAYLOAD, "old_position": PAYLOAD, "new_position": PAYLOAD}]
    out = run(tmp_path, code, f"showDiff({json.dumps(diff)})")
    assert_inert(out["html"]["migrateDiff"])


def test_rule_migrator_manual_reorder_escapes_uploaded_rule_id(tmp_path):
    """ASVS V5.3.3 · CWE-79 · WSTG-BUSL-09: an uploaded rule id in the manual reorder table is text."""
    code = _index("showManualReorder") + f"\nvar optimizedRules = {json.dumps([{'id': PAYLOAD, 'name': PAYLOAD, 'action': 'block'}])};"
    out = run(tmp_path, code, "showManualReorder()")
    assert_inert(out["html"]["manualReorder"])


def test_rule_migrator_plan_escapes_actions_ids_and_severities(tmp_path):
    """ASVS V5.3.3 · CWE-79 · WSTG-BUSL-09: the migration plan's action counts, issues and diff are text."""
    code = _index("showMigratePlan")
    plan = {"analysis": {"total_rules": 1, "action_counts": {PAYLOAD: 1},
                         "issues": [{"severity": PAYLOAD, "rule_id": PAYLOAD, "rule_name": "r", "type": "t", "message": "m"}]},
            "diff": [{"rule_id": PAYLOAD, "rule_name": "r", "action": PAYLOAD, "old_position": PAYLOAD, "new_position": PAYLOAD, "shift": 1}]}
    out = run(tmp_path, code, f"showMigratePlan({json.dumps(plan)})")
    assert_inert(out["html"]["migrateAnalysis"])
    assert "<img" not in out["html"].get("migrateDiff", "").lower()


def test_rule_migrator_delete_preview_escapes_rule_id_and_action(tmp_path):
    """ASVS V5.3.3 · CWE-79: the delete-all dry run lists tenant rule ids and actions as text."""
    code = _index("step3bDeleteAll") + "\nfunction migrateValidateCreds() { return {}; } function clearPendingAction() {} " \
                                       "function scopePageSelection() { return {}; } function savePendingAction() {} function renderPendingActions() {} " \
                                       "function updateActivationBanner() { return ''; } function registerPendingAction() {}"
    resp = {"status": "dry_run", "would_delete_count": 1, "message": "m",
            "would_delete": [{"rule_id": PAYLOAD, "rule_name": PAYLOAD, "action": PAYLOAD}]}
    out = run(tmp_path, code, "step3bDeleteAll(true)", response=resp)
    assert_inert(out["html"]["step3bResult"])


def test_guide_escaper_does_not_depend_on_a_global(tmp_path):
    """ASVS V5.3.3 · CWE-79 · CWE-636: guide.js escapes on its own (fail closed) when index.html's escapeHtml is absent."""
    out = run(tmp_path, extract("static/guide.js", "_gdE"), f"_gdE({json.dumps(PAYLOAD)})")
    assert "<img" not in out["ret"] and "&#39;" in out["ret"] and "&quot;" in out["ret"]


@pytest.mark.parametrize("value,expected", [(None, ""), (0, "0"), ("", ""), ("a&b", "a&amp;b")])
def test_guide_escaper_boundaries(tmp_path, value, expected):
    """ASVS V5.3.3 · CWE-79: boundary values (null, zero, empty, ampersand) render as expected."""
    out = run(tmp_path, extract("static/guide.js", "_gdE"), f"_gdE({json.dumps(value)})")
    assert out["ret"] == expected


def test_deploy_flow_page_escaper_escapes(tmp_path):
    """ASVS V5.3.3 · CWE-79: deploy_flow.html's esc() is a real escaper, not the identity."""
    out = run(tmp_path, extract("static/deploy_flow.html", "esc"), f"esc({json.dumps(PAYLOAD)})")
    assert "<img" not in out["ret"] and "&lt;img" in out["ret"]
