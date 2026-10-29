"""Bulk changes, its Build new forms and the other UI-ops pages (QA wave 6,
slice ui-ops): the typed confirmation, keyboard use, focus after Apply and
Undo, escaping of tenant data, plain-language errors, reflow at 320px, the
HAR parser's caps and the browser extension's address check.

The browser tests serve the real app (tests/test_findings_reflow.run_in_browser,
headless Chrome over CDP, loopback only, temporary profiles) and replace the
page's API with a fake (injected before the page loads), so no tenant and no
server state is involved; they skip without node or Chrome. One driver run
collects every measurement (module fixture); each test asserts one of them.
The node tests load the shipped files and skip without node.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
EXT = os.path.join(ROOT, "browser_extension")
NODE = shutil.which("node")
node = pytest.mark.skipif(NODE is None, reason="node is not installed")

PHRASE = "APPLY 12 CHANGES"
XSS = '<img src=x onerror="window.__xss=1">'
ASSESSOR = "Zoë 李 <b>QA</b> & co"


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node(script, *args, timeout=30):
    r = subprocess.run([NODE, "--input-type=module", "-e", script, *args], capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


# ── The fake API the Bulk changes page talks to ─────────────────────
# Twelve rules (one named with markup, one with unicode), a preview that
# needs the typed phrase, an apply that records an inverse, and its Undo.
# Every request body the page sends is kept in window.__calls.
FAKE_API = r"""
(() => {
  if (location.pathname !== '/report/operations') return;
  const XSS = %(xss)s, PHRASE = %(phrase)s;
  const rules = Array.from({ length: 12 }, (_, i) => ({ policy: 'url_filtering', policy_label: 'URL filtering', rule_type: '', id: i + 1,
    name: i === 0 ? XSS : i === 1 ? 'Règle 李 ①' : `Rule ${i + 1}`, order: i + 1, state: 'ENABLED', locked: '' }));
  const plan = undo => ({ status: 'ready', plan_hash: (undo ? 'b' : 'a').repeat(64), confirm_phrase: PHRASE, title: undo ? 'Enable 12 rules' : 'Disable 12 rules',
    tenant_label: XSS, writes: 12, needs_activation: true, counts: { change: 12, noop: 0, excluded: 0, total: 12 },
    blockers: [], warnings: [XSS], notes: [], impact: [],
    items: rules.map(r => ({ key: 'r' + r.id, object: { name: r.name, policy_label: r.policy_label }, field: 'state', before: undo ? 'DISABLED' : 'ENABLED',
      after: undo ? 'ENABLED' : 'DISABLED', status: 'change', reason: '' })) });
  const jobs = {
    j_read: { status: 'done', result: { status: 'done', tenant_label: 'Fake', policies: [{ policy: 'url_filtering', label: 'URL filtering', ordered: true, rules }] } },
    j_prev: { status: 'done', result: plan(false) },
    j_apply: { status: 'done', result: { status: 'applied', type: 'rule_state', product: 'zia', title: 'Disable 12 rules', operation_id: 'op-1', inverse: { type: 'rule_state' },
      counts_run: { applied: 12 }, verification: { checked: 12, confirmed: 12 }, activation: { activated: true }, items: [] } },
    j_undo: { status: 'done', result: plan(true) },
  };
  window.__calls = []; window.__fail422 = false;
  const real = window.fetch.bind(window);
  const json = (body, status) => Promise.resolve(new Response(JSON.stringify(body), { status: status || 200, headers: { 'Content-Type': 'application/json' } }));
  window.fetch = (url, opts) => {
    const u = String(url), body = opts && opts.body ? JSON.parse(opts.body) : null;
    if (u.startsWith('/api/')) window.__calls.push({ url: u, body });
    if (u === '/api/operations/plugins') return json({ plugins: [
      { type: 'zpa_connector_group', family: 'zpa_build', label: 'ZPA connector group', hint: '', script: 'ops_zpa.js' },
      { type: 'zpa_app_segments', family: 'zpa_build', label: 'ZPA segments', hint: '', script: 'ops_zpa.js' },
      { type: 'zpa_policies', family: 'zpa_build', label: 'ZPA policies', hint: '', script: 'ops_zpa.js' },
      { type: 'zpa_prefix_delete', family: 'zpa_build', label: 'ZPA delete', hint: '', script: 'ops_zpa.js' },
      { type: 'zdx_probes', family: 'zdx', label: 'ZDX probes', hint: '', script: 'ops_zdx.js' },
      { type: 'zdx_probe_state', family: 'zdx', label: 'ZDX state', hint: '', script: 'ops_zdx.js' }] });
    if (u === '/api/write-mode') return json({ enabled: true });
    if (u === '/api/tenant-profiles') return json({ profiles: [] });
    if (u === '/api/operations') return json({ operations: [] });
    if (u === '/api/operations/objects/start') return window.__fail422
      ? json({ detail: [{ type: 'missing', loc: ['body', 'family'], msg: 'Field required' }] }, 422) : json({ job_id: 'j_read' });
    if (u === '/api/operations/preview/start') return json({ job_id: 'j_prev', operation: body.operation });
    if (u === '/api/operations/apply/start') return json({ job_id: 'j_apply' });
    if (u === '/api/operations/op-1/undo/preview/start') return json({ job_id: 'j_undo', operation: { type: 'rule_state', value: 'ENABLED' }, undo_of: 'op-1' });
    const m = /^\/api\/dlp-packs\/jobs\/(j_[a-z]+)\?/.exec(u);
    if (m) return json(Object.assign({ logs: [], next: 0 }, jobs[m[1]]));
    return real(url, opts);
  };
})();
""" % {"xss": json.dumps(XSS), "phrase": json.dumps(PHRASE)}

DRIVER = CDP_PRELUDE + r"""
const [fakeApi, assessor] = args;
const out = {};
// Each measurement is kept on its own: one that throws is recorded as an error and the run goes on.
const safe = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'ERR ' + String(e.message).slice(0, 120); } };
const key = async (k, code, vk, text) => {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk, text });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk });
};
const pressTab = () => key('Tab', 'Tab', 9);
const active = () => ev('document.activeElement && document.activeElement.id');
const goOff = () => ev("document.getElementById('opGo').disabled");
const typeIn = t => send('Input.insertText', { text: t });
const clear = async id => { await ev(`(() => { const el = document.getElementById('${id}'); el.focus(); el.select(); return 1; })()`); await key('Backspace', 'Backspace', 8); };
const frame = () => until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');

await send('Page.addScriptToEvaluateOnNewDocument', { source: fakeApi });
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/operations' });
await until(() => ev(`document.readyState === 'complete' && document.querySelectorAll('input[name=opKind]').length >= 10 && !!(window.OPS_PLUGINS.defs.zdx_probes && window.OPS_PLUGINS.defs.zpa_policies)`), 'the builders');
await safe('scripts', () => ev(`(() => { const c = {}; document.querySelectorAll('script[src^="/static/ops_"]').forEach(s => { const n = s.getAttribute('src'); c[n] = (c[n] || 0) + 1; }); return c; })()`));

// Read, pick all twelve, preview.
await ev(`document.getElementById('opRead').click(), 1`);
await until(() => ev(`document.querySelectorAll('input[data-k]').length === 12`), 'the rules');
await safe('pickXss', () => ev(`window.__xss === undefined && [...document.querySelectorAll('#opObjects td')].some(td => td.textContent === ${JSON.stringify(%(xss)s)})`));
await ev(`document.getElementById('opAll').click(), 1`);
await ev(`document.getElementById('opPreview').click(), 1`);
await until(() => ev(`!!document.getElementById('opGo')`), 'the preview');
await safe('planXss', () => ev(`window.__xss === undefined && document.getElementById('opPlan').textContent.includes('<img src=x')`));
await safe('phraseShown', () => ev(`(document.querySelector('#opApply .op-phrase') || {}).textContent || ''`));
await safe('offAtStart', goOff);
await safe('hintAtStart', () => ev(`document.getElementById('opGoWhy').textContent`));

// By keyboard: the assessor's name, Tab to the phrase, Tab to the box, Space, Tab to Apply.
await ev(`document.getElementById('opAssessor').focus(), 1`);
await typeIn(assessor);
await safe('focusTyping', active);
await safe('offNoPhrase', goOff);
await pressTab(); await safe('tab1', active);
await typeIn('apply 12 changeſ');               // long s: str.upper() would make it the phrase
await safe('offLookalike', goOff);
await clear('opPhrase');
await typeIn('APPLY 12 CHANGES!');                  // one character too many (boundary)
await safe('offExtra', goOff);
await clear('opPhrase');
await typeIn('  apply 12 changes ');                 // case and surrounding spaces do not matter
await safe('offNoAgree', goOff);
await safe('hintNoAgree', () => ev(`document.getElementById('opGoWhy').textContent`));
await pressTab(); await safe('tab2', active);
await key(' ', 'Space', 32, ' ');
await safe('agreed', () => ev(`document.getElementById('opAgree').checked`));
await safe('offReady', goOff);
// Coming back to the tab (a window focus) asks for write mode again; nothing typed or ticked is lost.
await ev(`window.dispatchEvent(new Event('focus')), 1`);
await until(() => ev(`window.__calls.filter(c => c.url === '/api/write-mode').length >= 2`), 'the write-mode check').catch(() => null);
await ev(`new Promise(r => setTimeout(() => r(true), 50))`);   // the answer is drawn within a task
await safe('afterFocus', () => ev(`({ phrase: document.getElementById('opPhrase').value, agree: document.getElementById('opAgree').checked,
  active: document.activeElement.id, off: document.getElementById('opGo').disabled })`));
await ev(`document.getElementById('opAgree').focus(), 1`);
await pressTab(); await safe('tab3', active);
await clear('opAssessor');
await safe('offNoAssessor', goOff);
await typeIn(assessor);
await ev(`(() => { const a = document.getElementById('opAgree'); if (!a.checked) a.click(); const p = document.getElementById('opPhrase'); if (!p.value) { p.value = '  apply 12 changes '; p.dispatchEvent(new Event('input')); } document.getElementById('opGo').focus(); return 1; })()`);
await key('Enter', 'Enter', 13, '\r');
await until(() => ev(`!!document.querySelector('#opResult .bp-card')`), 'the result');
await safe('focusAfterApply', active);
await safe('applyCall', () => ev(`window.__calls.filter(c => c.url === '/api/operations/apply/start').map(c => c.body)`));
await safe('previewCall', () => ev(`window.__calls.filter(c => c.url === '/api/operations/preview/start').map(c => c.body.operation)`));

// Undo: preview first, focus on the plan it made.
await ev(`document.querySelector('#opResult button[data-undo]').click(), 1`);
await until(() => ev(`document.getElementById('opPlan').textContent.includes('Enable 12 rules')`), 'the Undo preview').catch(() => null);
await safe('focusAfterUndo', active);
await safe('undoChip', () => ev(`!!document.querySelector('#opPlan .op-summary .df-chip.st-warn')`));
await safe('offUndo', goOff);

// Reflow with the plan and the apply form on screen.
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await frame();
await safe('opsOverflow', () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`));

// A validation error (FastAPI's list detail) reads as words.
await ev(`window.__fail422 = true, document.getElementById('opRead').click(), 1`);
await until(() => ev(`/could not be read/.test(document.getElementById('opObjects').textContent)`), 'the read error').catch(() => null);
await safe('error422', () => ev(`document.getElementById('opObjects').textContent`));

// The ZPA connector group form: the enrollment count reaches the spec as typed.
await safe('maxUsage', () => ev(`(() => {
  const def = window.OPS_PLUGINS.defs.zpa_connector_group, box = document.createElement('div'), H = { E: s => String(s), say() {} };
  document.body.append(box);
  def.render({ connector_groups: [], locations: [{ id: 'san_jose', label: 'San Jose' }] }, box, {}, H);
  const set = (id, v) => { const el = box.querySelector('#' + id); el.value = v; el.dispatchEvent(new Event('input')); };
  set('zbPrefix', 'pov1');
  const got = {};
  for (const v of ['0', '7', '', '501']) { set('zbMax', v); got[v === '' ? 'blank' : v] = def.spec().max_usage; }
  box.remove();
  return got;
})()`));

// The Client Connector fleet page at the WCAG reflow width.
await send('Page.navigate', { url: base + '/report/fleet' });
await until(() => ev(`document.readyState === 'complete' && !!document.querySelector('#zfInstOpts input')`), 'the fleet page').catch(() => null);
await frame();
await safe('fleetOverflow', () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`));

// The bypass report renderer with a crafted rule id and a huge aggregated list.
await send('Page.navigate', { url: base + '/report/bypass' });
await until(() => ev(`document.readyState === 'complete' && typeof window.renderBypassReport === 'function'`), 'the bypass page');
await safe('bypass', () => ev(`(() => {
  const X = ${JSON.stringify(%(xss)s)}, box = document.createElement('div');
  const rule = { source: 'url', id: X, name: 'r' };
  const items = Array.from({ length: 600 }, (_, i) => ({ value: 'h' + i + '.example', count: X, rules: Array.from({ length: 10 }, () => rule) }));
  window.renderBypassReport({ summary: { total_bypass_items: X, ssl_bypass_rules: X }, aggregated: { urls: { items } },
    category_expansion: [], sections: {}, risk_flags: [] }, box);
  const tbl = [...box.querySelectorAll('table')].find(t => t.textContent.includes('h0.example'));
  return { xss: window.__xss !== undefined || !!box.querySelector('img'), rows: tbl.querySelectorAll('tbody tr').length,
    refs: tbl.querySelector('tbody tr').querySelectorAll('.bp-ref').length, more: /…and 100 more/.test(box.textContent) };
})()`));

console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
""" % {"xss": json.dumps(XSS)}


@pytest.fixture(scope="module")
def ui(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("c6ui"), DRIVER, FAKE_API, ASSESSOR)


# ── Typed confirmation and the other gates (Bulk changes, step 4) ────

def test_the_confirmation_phrase_is_shown_on_the_page(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.2: the phrase to type is shown as itself."""
    assert ui["phraseShown"] == PHRASE


def test_apply_is_disabled_until_any_gate_is_met(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: right after the preview, Apply is disabled and says what is still needed."""
    assert ui["offAtStart"] is True
    assert "assessor" in ui["hintAtStart"] and PHRASE in ui["hintAtStart"]


def test_apply_stays_disabled_without_the_phrase(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: the assessor's name alone does not arm Apply (negative)."""
    assert ui["offNoPhrase"] is True


def test_a_lookalike_phrase_does_not_arm_apply(ui):
    """ASVS V1.11.3 · CWE-1289 · WSTG-INPV-01: 'ſ' (which upper-cases to S) is not the phrase, as on the server."""
    assert ui["offLookalike"] is True


def test_one_character_too_many_does_not_arm_apply(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: the phrase plus one character is refused (boundary)."""
    assert ui["offExtra"] is True


def test_the_phrase_alone_needs_the_review_box(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: the right phrase without the review box keeps Apply disabled."""
    assert ui["offNoAgree"] is True and "review box" in ui["hintNoAgree"]


def test_every_gate_met_arms_apply(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: name, phrase (any case, spaces trimmed) and the box arm Apply."""
    assert ui["agreed"] is True and ui["offReady"] is False


def test_clearing_the_assessor_disarms_apply(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: Apply disarms again when a gate is undone (negative)."""
    assert ui["offNoAssessor"] is True


def test_the_undo_preview_is_disarmed_again(ui):
    """ASVS V1.11.3 · CWE-841 · WSTG-BUSL-06: an Undo is a new plan: its Apply starts disabled."""
    assert ui["undoChip"] is True and ui["offUndo"] is True


# ── Keyboard and focus (WCAG 2.2) ───────────────────────────────────

def test_typing_the_assessor_keeps_the_focus(ui):
    """WCAG 2.2 SC 2.4.3 · SC 3.3.7: the first keystroke on the page (a window focus) does not redraw the form under the cursor."""
    assert ui["focusTyping"] == "opAssessor"


def test_a_window_focus_keeps_the_phrase_the_box_and_the_cursor(ui):
    """WCAG 2.2 SC 3.3.7 · ASVS V1.11.3: returning to the tab keeps the typed phrase, the ticked box and the focus."""
    assert ui["afterFocus"] == {"phrase": "  apply 12 changes ", "agree": True, "active": "opAgree", "off": False}


def test_the_apply_form_is_in_keyboard_order(ui):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3: Tab goes assessor → phrase → review box → Apply."""
    assert (ui["tab1"], ui["tab2"], ui["tab3"]) == ("opPhrase", "opAgree", "opGo")


def test_focus_moves_to_the_outcome_after_apply(ui):
    """WCAG 2.2 SC 2.4.3: the Apply button goes away; focus lands on the result, not on the page."""
    assert ui["focusAfterApply"] == "opResultCard"


def test_focus_moves_to_the_plan_after_undo(ui):
    """WCAG 2.2 SC 2.4.3: Undo's button goes away with the result; focus lands on the Undo preview."""
    assert ui["focusAfterUndo"] == "opH3"


def test_bulk_changes_reflows_at_320px(ui):
    """WCAG 2.2 SC 1.4.10: with the plan and apply form shown, the page does not scroll sideways at 320px."""
    assert ui["opsOverflow"] <= 0


def test_the_fleet_page_reflows_at_320px(ui):
    """WCAG 2.2 SC 1.4.10: the install command builder's fields wrap at 320px (they pushed the page 38px wide)."""
    assert ui["fleetOverflow"] <= 0


# ── Values reach the API without loss; tenant data stays text ───────

def test_the_apply_request_carries_the_values_as_typed(ui):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: unicode and markup in the assessor's name reach the API unchanged."""
    (body,) = ui["applyCall"]
    assert body["assessor"] == ASSESSOR.strip()
    assert body["confirm_text"] == "  apply 12 changes "     # the server compares it, so it goes as typed
    assert body["plan_hash"] == "a" * 64 and body["confirm"] is True and body["undo_of"] == ""


def test_the_applied_operation_is_the_previewed_one(ui):
    """ASVS V1.11.3 · CWE-367 · WSTG-BUSL-04: Apply sends exactly the spec that was previewed (twelve rules, ids as numbers)."""
    (prev,) = ui["previewCall"]
    assert ui["applyCall"][0]["operation"] == prev
    assert prev["type"] == "rule_state" and sorted(t["id"] for t in prev["targets"]) == list(range(1, 13))


def test_tenant_names_in_the_pick_list_are_text(ui):
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: a rule named with markup shows as text in the pick list."""
    assert ui["pickXss"] is True


def test_tenant_strings_in_the_preview_are_text(ui):
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: rule names, the tenant label and warnings in the preview are escaped."""
    assert ui["planXss"] is True


def test_a_validation_error_reads_as_words(ui):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: FastAPI's list detail becomes a sentence, never '[object Object]'."""
    assert "Field required" in ui["error422"] and "[object Object]" not in ui["error422"]


def test_each_builder_script_loads_once(ui):
    """ASVS V14.2.1 · CWE-1188 · NIST SSDF PW.4: a script serving several builder types is added to the page once."""
    assert ui["scripts"] == {"/static/ops_zpa.js": 1, "/static/ops_zdx.js": 1}


def test_the_zpa_enrollment_count_is_sent_as_typed(ui):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: 0 and 501 go to the server to refuse (never a silent 5); blank means 5."""
    assert ui["maxUsage"] == {"0": 0, "7": 7, "blank": 5, "501": 501}


def test_the_bypass_report_escapes_rule_ids_and_counts(ui):
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: a rule id or count that is markup (an untrusted snapshot) renders as text."""
    assert ui["bypass"]["xss"] is False


def test_the_bypass_report_caps_huge_lists(ui):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: 600 rows with 10 references draw as 500 rows of 6, with a note."""
    b = ui["bypass"]
    assert (b["rows"], b["refs"], b["more"]) == (500, 6, True)


# ── The typed phrase: the page agrees with the server (oracle table) ─

PHRASE_CASES = [("APPLY 12 CHANGES", PHRASE, True), ("apply 12 changes", PHRASE, True), ("  Apply 12 Changes  ", PHRASE, True),
                ("APPLY 12 CHANGE\u017f", PHRASE, False), ("\uff21PPLY 12 CHANGES", PHRASE, False), ("APPLY 12 CHANGE", PHRASE, False),
                ("APPLY 12 CHANGES!", PHRASE, False), ("", PHRASE, False), ("   ", PHRASE, False), ("APPLY  12 CHANGES", PHRASE, False),
                ("anything", "", False), ("\u00e9t\u00e9", "\u00c9T\u00c9", True), ("e\u0301te\u0301", "\u00c9T\u00c9", True),
                ("\u0131TI", "ITI", False)]


@node
def test_the_page_compares_the_phrase_as_the_server_does():
    """ASVS V1.11.3 · CWE-1289 · WSTG-INPV-01: phraseMatches agrees with security.typed_phrase_matches on every case."""
    # Arrange
    import security
    html = _read("static", "report_operations.html")
    fn = re.search(r"(function phraseMatches\(typed, phrase\) \{.*?\n    \})", html, re.S).group(1)
    cases = [[t, p] for t, p, _ in PHRASE_CASES]
    # Act
    got = _node(f"{fn}\nconsole.log(JSON.stringify({json.dumps(cases)}.map(([t, p]) => phraseMatches(t, p))));")
    # Assert
    assert got == [security.typed_phrase_matches(t, p) for t, p, _ in PHRASE_CASES] == [ok for _, _, ok in PHRASE_CASES]


# ── Error text helper (every UI-ops page) ───────────────────────────

ERR_FILES = ["pov.js", "zcc_fleet.js", "beacon.js", "path_list.js", "path_whatif.js", "detection_health.js",
             "report_browser.html", "report_device_posture.html", "report_shadow.html", "report_operations.html"]


@pytest.mark.parametrize("name", ERR_FILES)
def test_no_page_turns_an_error_detail_into_object_text(name):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: no page passes FastAPI's detail (a list or object) straight to Error()."""
    src = _read("static", name)
    assert not re.search(r"new Error\(\(?(?:d|data)(?:\.detail| && (?:d|data)\.detail)", src), name
    assert re.search(r"(?:errText|_dhErrText|detailText)\((?:d|data), r\.status\)", src), name


@node
def test_the_error_helper_words_every_detail_shape():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: string, {cause}, a 422 list, null and junk each give a sentence."""
    # Arrange
    src = _read("static", "path_whatif.js")
    fn = re.search(r"(const errText = .*?\}\;)\n", src, re.S).group(1)
    shapes = [{"detail": "Plain."}, {"detail": {"cause": "Cause."}}, {"detail": [{"msg": "Field required"}, {"msg": "Bad"}]}, None, {"detail": 5}]
    # Act
    got = _node(f"{fn}\nconsole.log(JSON.stringify({json.dumps(shapes)}.map(d => errText(d, 502))));")
    # Assert
    assert got == ["Plain.", "Cause.", "The request was not accepted: Field required; Bad.", "HTTP 502", "HTTP 502"]


# ── Links built from data ───────────────────────────────────────────

def test_beacon_links_only_https_addresses():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-04: every link the Beacon page builds from data goes through safeHref."""
    src = _read("static", "beacon.js")
    assert re.search(r"const safeHref = u => \(/\^https:", src)
    assert not re.search(r'href="\$\{E\((?!safeHref)', src)


# ── HAR parsing in the browser (untrusted file) ─────────────────────

def _har(n_hosts, body_size=0):
    return json.dumps({"log": {"entries": [{"request": {"url": f"https://h{i}.example/p?q=secret", "method": "POST", "bodySize": body_size}}
                                           for i in range(n_hosts)]}})


@node
def test_the_list_of_hosts_left_out_is_capped(tmp_path):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: 1,500 hosts over the cap list 1,000 and count all 1,500."""
    # Arrange
    f = tmp_path / "a.har"; f.write_text(_har(1700))
    # Act
    got = _node("import fs from 'node:fs'; import { createRequire } from 'node:module'; const m = createRequire(import.meta.url)(process.argv[1]);"
                "const p = m.parse(fs.readFileSync(process.argv[2], 'utf8'));"
                "console.log(JSON.stringify({ hosts: p.hosts.length, more: p.more.length, total: p.more_total, capped: p.capped }));",
                os.path.join(STATIC, "har_parse.js"), str(f))
    # Assert
    assert got == {"hosts": 200, "more": 1000, "total": 1500, "capped": True}


@node
def test_distinct_hosts_past_the_tracking_cap_are_counted_not_kept(tmp_path):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: past MAX_TRACKED distinct hosts, entries are counted as untracked."""
    # Arrange
    f = tmp_path / "b.har"; f.write_text(_har(20005))
    # Act
    got = _node("import fs from 'node:fs'; import { createRequire } from 'node:module'; const m = createRequire(import.meta.url)(process.argv[1]);"
                "const p = m.parse(fs.readFileSync(process.argv[2], 'utf8'));"
                "console.log(JSON.stringify({ total: p.total_hosts, untracked: p.untracked, capped: p.capped, max: m.MAX_TRACKED }));",
                os.path.join(STATIC, "har_parse.js"), str(f))
    # Assert
    assert got == {"total": 20000, "untracked": 5, "capped": True, "max": 20000}


@node
def test_a_huge_claimed_body_size_keeps_the_sums_finite(tmp_path):
    """ASVS V5.1.4 · CWE-190 · WSTG-INPV-01: bodySize 1e308 on two requests to one host sums to a finite number."""
    # Arrange
    f = tmp_path / "c.har"
    f.write_text(json.dumps({"log": {"entries": [{"request": {"url": "https://up.example/", "method": "PUT", "bodySize": 1e308}}] * 2}}))
    # Act
    got = _node("import fs from 'node:fs'; import { createRequire } from 'node:module'; const m = createRequire(import.meta.url)(process.argv[1]);"
                "const h = m.parse(fs.readFileSync(process.argv[2], 'utf8')).hosts[0];"
                "console.log(JSON.stringify({ finite: Number.isFinite(h.bytes_sent), bytes: h.bytes_sent, uploads: h.uploads, max: m.MAX_BYTES }));",
                os.path.join(STATIC, "har_parse.js"), str(f))
    # Assert
    assert got["finite"] is True and got["bytes"] == 2 * got["max"] and got["uploads"] == 2


# ── Browser extension ───────────────────────────────────────────────

ADDRESSES = ["http://127.0.0.1:8000", "http://localhost:9", "https://127.0.0.1:8000", "https://localhost", "http://[::1]:8000",
             "http://127.0.0.2:8000", "http://0x7f000001:8000"]


@node
def test_every_accepted_app_address_is_one_the_manifest_lets_the_extension_reach():
    """ASVS V14.4.3 · CWE-284 · WSTG-CONF-12: normalizeAppUrl accepts only the CSP connect-src and host_permissions origins."""
    # Arrange
    m = json.loads(_read("browser_extension", "manifest.json"))
    connect = re.search(r"connect-src ([^;]+)", m["content_security_policy"]["extension_pages"]).group(1).split()
    # Act
    got = _node("const m = await import(process.argv[1]);"
                f"console.log(JSON.stringify({json.dumps(ADDRESSES)}.map(m.normalizeAppUrl)));", os.path.join(EXT, "common.js"))
    # Assert
    accepted = [a for a in got if a]
    assert accepted == ["http://127.0.0.1:8000", "http://localhost:9", "http://127.0.0.1:8000"]   # 0x7f000001 is 127.0.0.1
    for a in accepted:
        host = re.sub(r":\d+$", "", a)
        assert f"{host}:*" in connect and f"{host}/*" in m["host_permissions"], a


@node
def test_a_badge_for_a_finding_with_no_text_still_has_a_label():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a finding with no text or short label gives a badge, not a TypeError."""
    got = _node("const m = await import(process.argv[1]);"
                "console.log(JSON.stringify([m.badgeLabel({ kind: 'engine', findings: [{ severity: 'high' }] }),"
                " m.badgeLabel({ kind: 'engine', findings: [{ severity: 'medium', short: 42 }] })]));", os.path.join(EXT, "common.js"))
    assert got == [{"label": "finding", "sev": "high"}, {"label": "42", "sev": "medium"}]
