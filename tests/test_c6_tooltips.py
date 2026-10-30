"""Help marks: a superscript "?" after a page title, a sidebar item or a
control whose label does not say it all opens what it does and what input it
expects (static/hover_help.js, static/hover_help.css and the catalogue
static/help_catalog.js; the browser extension carries copies). Pointing at,
or tabbing to, an ordinary control opens nothing.

Two halves:

* static tests (no browser): the catalogue is complete and well formed, every
  key names a control that exists in that page's sources (no orphans), every
  page and the extension load the add-on, the copies match, the engine never
  writes HTML, the words stay plain;
* browser tests (node + headless Chrome over CDP, the same harness as
  tests/test_findings_reflow.py; skipped without node or Chrome): every page
  is loaded on the made-up sample tenant and toured (tabs, folded sections,
  dialogs, Analyze / Read / Preview), every visible control is enumerated
  after each step and must have a catalogue entry and a "?" mark that opens
  its words, or one of the recorded reasons it needs none; then the WCAG 2.2
  behaviours (hover and focus on a control open nothing; hover, click, tap,
  Enter and Space on the mark open it; Esc and a click elsewhere close it;
  one at a time; names, aria-expanded, 24px target, contrast, reflow at
  320px, reduced motion) and escaping are checked with real input events.

No real tenant is contacted: the sample tenant is served from memory and the
suite's offline guard stays on. A control without help fails the coverage
test with its page and selector named.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
EXT = ROOT / "browser_extension"
CATALOG = STATIC / "help_catalog.js"
EFFECTS = {"local", "read", "write", "download", "nav", "confirm"}
EXT_PAGES = {"ext:popup": "popup.html", "ext:options": "options.html", "ext:panel": "panel.html"}

# Every page the app serves to a person, with the file behind it.
PAGES = {
    "/": "index.html", "/simple": "simple.html", "/help": "help.html",
    "/report/queue": "report_queue.html", "/report/zpa": "report_zpa.html", "/report/browser": "report_browser.html",
    "/report/device-posture": "report_device_posture.html", "/report/digest": "report_digest.html",
    "/report/health": "report_health.html", "/report/exports": "report_exports.html",
    "/report/operations": "report_operations.html", "/report/todo": "report_todo.html",
    "/report/insights": "report_insights.html", "/report/beacon": "report_beacon.html",
    "/report/advanced": "report_advanced.html", "/report/deploy-flow": "deploy_flow.html",
    "/report/evalall": "report_evalall.html", "/report/logs": "report_logs.html", "/report/vendor": "report_vendor.html",
    "/report/compliance": "report_compliance.html", "/report/fleet": "report_fleet.html", "/report/view": "report_view.html",
    "/report/flow": "report_flow.html", "/report/bypass": "report_bypass.html", "/report/dataflow": "report_dataflow.html",
    "/report/live": "report_live.html", "/report/audit": "report_audit.html", "/report/motion": "report_motion.html",
    "/report/shadow": "report_shadow.html", "/report/posture": "report_posture.html",
    "/report/self-heal": "report_self_heal.html", "/report/path": "report_path.html", "/report/pov": "report_pov.html",
    "/report/sslflow": "report_sslflow.html", "/report/sslcoverage": "report_ssl_coverage.html",
    "/report/traffic-logs": "report_traffic_logs.html",
}


def _read(path) -> str:
    return Path(path).read_text(encoding="utf-8")


def load_catalog(text: str | None = None) -> dict:
    """The catalogue as data: help_catalog.js is one JSON object assigned to
    window.HELP_CATALOG, so it parses without running any JavaScript."""
    text = _read(CATALOG) if text is None else text
    m = re.search(r"window\.HELP_CATALOG\s*=\s*(\{.*\})\s*;\s*$", text, re.S)
    assert m, "help_catalog.js must be `window.HELP_CATALOG = {...};`"
    return json.loads(m.group(1))


CAT = load_catalog()


def _entries():
    for page, entries in CAT["pages"].items():
        for sel, e in entries.items():
            yield page, sel, e


# ── Sources per page, for the orphan check ───────────────────────────

def _scripts_of(html: str):
    return re.findall(r'<script[^>]+src="/static/([\w.-]+\.js)', html)


def page_sources(page: str) -> str:
    """Everything that can put a control on a page: its HTML, the scripts it
    loads (the add-ons for /, the Build new forms for /report/operations)."""
    import dlp_api_server as srv
    if page in EXT_PAGES:
        html = _read(EXT / EXT_PAGES[page])
        js = re.findall(r'<script[^>]+src="([\w.-]+\.js)"', html)
        mods = {"common.js"} | set(js)
        return html + "".join(_read(EXT / n) for n in sorted(mods) if (EXT / n).is_file() and n != "help_catalog.js")
    html = _read(STATIC / PAGES[page])
    names = set(_scripts_of(html))
    if page == "/":
        names |= {n for n, k in srv.GUI_ADDONS if k == "script"}
    if page == "/report/operations":
        names |= {p.name for p in STATIC.glob("ops_*.js")}
    names.discard("help_catalog.js")
    return html + "".join(_read(STATIC / n) for n in sorted(names) if (STATIC / n).is_file())


_SERVER = None


def server_sources() -> str:
    """The Python modules: some controls are drawn from data the server sends
    (an option's key becomes part of the field's id)."""
    global _SERVER
    if _SERVER is None:
        _SERVER = "".join(_read(p) for p in sorted(ROOT.glob("*.py")))
    return _SERVER


def all_sources() -> str:
    return "".join(page_sources(p) for p in PAGES)


_STD_ATTRS = {"type", "role", "href", "name", "value", "id", "class", "for", "disabled", "hidden", "open", "checked",
              "aria-label", "aria-controls", "aria-expanded", "aria-pressed", "aria-selected", "download", "target",
              "placeholder", "tabindex", "contenteditable", "readonly", "multiple", "accept", "rel", "title", "list"}


def selector_tokens(sel: str):
    """The ids, classes and attribute names/values a selector depends on."""
    s = re.sub(r'"[^"]*"|\'[^\']*\'', lambda m: " " * len(m.group(0)), sel)   # mask quoted values for # and .
    toks = [("id", t) for t in re.findall(r"#([\w-]+)", s)]
    toks += [("class", t) for t in re.findall(r"(?<![\w-])\.([A-Za-z_][\w-]*)", s)]
    for name, val in re.findall(r'\[([\w-]+)\s*(?:[~|^$*]?=\s*["\']([^"\']*)["\'])?\s*(?:i\s*)?\]', sel):
        if name not in _STD_ATTRS:
            toks.append(("attr", name))
        if val and name not in ("type", "role", "href", "target", "rel", "download", "tabindex"):
            toks.append(("value", val))
    return toks


# ── Static tests ──────────────────────────────────────────────────────

def test_catalogue_is_one_json_object_with_complete_entries():
    """ASVS V5.1.3 · CWE-20 · WCAG 2.2 SC 3.3.2: every entry says what the control does, what input it expects and its effect."""
    bad = [(p, s, e) for p, s, e in _entries()
           if not isinstance(e, dict) or not str(e.get("what", "")).strip() or not str(e.get("input", "")).strip()
           or e.get("effect") not in EFFECTS or set(e) - {"what", "input", "effect"}]
    assert not bad, bad[:10]
    assert sum(1 for _ in _entries()) > 300, "the catalogue covers every page"


def test_catalogue_text_is_plain_text_never_markup():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: catalogue words carry no markup (the engine sets them as text anyway)."""
    bad = [(p, s) for p, s, e in _entries() for f in ("what", "input") if "<" in e[f]]
    assert not bad, bad


def test_every_page_and_extension_page_has_entries():
    """WCAG 2.2 SC 3.3.2 · SC 4.1.2: every page the app serves, and the extension's popup, options and panel, has its own entries."""
    keys = set(CAT["pages"])
    assert set(PAGES) | set(EXT_PAGES) | {"*"} == keys, (sorted(set(PAGES) | set(EXT_PAGES) - keys), sorted(keys - set(PAGES) - set(EXT_PAGES) - {"*"}))


def test_every_page_key_is_a_route_the_app_serves():
    """ASVS V1.14.1 · CWE-1059: the page keys are the app's real routes, so no entry hides under a typo."""
    import dlp_api_server as srv
    routes = {getattr(r, "path", "") for r in srv.app.routes}
    assert set(PAGES) <= routes, sorted(set(PAGES) - routes)


@pytest.mark.parametrize("page", sorted(set(PAGES) | set(EXT_PAGES) | {"*"}))
def test_every_catalogue_key_names_a_real_control(page):
    """ASVS V1.14.1 · CWE-1164 (dead code): no orphan entries; every id, class and attribute a key uses exists in that page's sources."""
    src = all_sources() if page == "*" else page_sources(page)
    orphans = []
    for sel in CAT["pages"].get(page, {}):
        for kind, tok in selector_tokens(sel):
            # A value or id built at run time ("fwd:" + key, `zfIo_${key}`)
            # counts when each of its word pieces is in the sources.
            pieces = [w for w in re.split(r"[^A-Za-z0-9]+", tok) if len(w) > 1]
            built = kind in ("value", "id") and pieces and re.search(r"[^A-Za-z0-9]", tok) \
                and all(w in src or w in server_sources() for w in pieces)
            if tok not in src and not built:
                orphans.append(f"{sel}  ({kind} {tok!r} is not in the sources)")
    assert not orphans, f"{page}: " + "; ".join(orphans[:15])


def test_selectors_are_balanced_and_never_match_by_text():
    """ASVS V5.1.3 · CWE-20: selectors are well formed CSS with stable hooks (no :contains, no positional :nth-child)."""
    bad = []
    for page, sel, _ in _entries():
        bare = re.sub(r'"[^"]*"|\'[^\']*\'', '""', sel)
        if bare.count("[") != bare.count("]") or bare.count("(") != bare.count(")") or bare.count('"') % 2:
            bad.append((page, sel, "unbalanced"))
        if re.search(r":contains|:nth-child|:nth-of-type", sel):
            bad.append((page, sel, "positional or text match"))
    assert not bad, bad


@pytest.mark.parametrize("route", sorted(PAGES))
def test_every_page_loads_the_hover_help(route):
    """ASVS V14.4 · WCAG 2.2 SC 1.4.13: every served page loads the style, the catalogue and the engine, catalogue first."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    html = TestClient(srv.app).get(route).text
    assert "/static/hover_help.css" in html
    i, j = html.find("/static/help_catalog.js"), html.find("/static/hover_help.js")
    assert 0 <= i < j, route


def test_gui_addons_inject_the_hover_help_into_the_home_page():
    """ASVS V14.4: the home page gets the add-on through GUI_ADDONS like every other add-on (catalogue before the engine)."""
    import dlp_api_server as srv
    names = [n for n, _ in srv.GUI_ADDONS]
    assert ("hover_help.css", "style") in srv.GUI_ADDONS
    assert names.index("help_catalog.js") + 1 == names.index("hover_help.js")
    assert names.index("sidebar_order.js") + 1 == names.index("dashboard.js") == len(names) - 1, "the existing order is kept: dashboard.js last"


@pytest.mark.parametrize("name,key", sorted((v, k) for k, v in EXT_PAGES.items()))
def test_the_extension_pages_load_the_hover_help(name, key):
    """OpenSSF Scorecard (no remote code) · WCAG 2.2 SC 1.4.13: the extension's pages load local copies, no inline script."""
    html = _read(EXT / name)
    assert f'data-hh-page="{key}"' in html
    assert '<link rel="stylesheet" href="hover_help.css">' in html
    assert html.find('src="help_catalog.js"') < html.find('src="hover_help.js"') < html.find('type="module"')
    assert "<script>" not in html


@pytest.mark.parametrize("name", ["hover_help.js", "hover_help.css", "help_catalog.js"])
def test_the_extension_copies_are_identical(name):
    """SLSA v1.0 build integrity · NIST SSDF PW.4: one source of truth; the extension ships byte-identical copies."""
    assert (EXT / name).read_bytes() == (STATIC / name).read_bytes(), f"copy static/{name} to browser_extension/{name}"


def test_catalogue_obeys_the_extension_content_rules():
    """ASVS V14.2 · CWE-200 · CWE-829: no remote address and nothing shaped like a credential in the catalogue the extension ships."""
    text = _read(CATALOG)
    urls = [u for u in re.findall(r"https?://[^\s'\"`)<]+", text) if not re.match(r"https?://(127\.0\.0\.1|localhost)\b", u)]
    assert not urls, urls[:5]
    assert not re.search(r"(secret|password|token|client_id|api_key)\s*[:=]", text, re.I)


def test_the_engine_never_writes_html():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the pop-up and the descriptions are built with textContent only."""
    js = re.sub(r"//[^\n]*|/\*.*?\*/", "", _read(STATIC / "hover_help.js"), flags=re.S)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute('on"):
        assert sink not in js, sink
    assert "textContent" in js


def test_html_sink_scanner_finds_nothing_in_the_engine_or_the_catalogue():
    """ASVS V5.3.3 · CWE-79: the repository's sink scanner reports nothing for the new files."""
    import html_sink_scan
    found = [f for f in html_sink_scan.scan_all() if os.path.basename(f.file) in ("hover_help.js", "help_catalog.js")] \
        if hasattr(html_sink_scan, "scan_all") else []
    assert not found, found


def test_static_titles_are_reused_word_for_word():
    """WCAG 2.2 SC 1.4.13 · ASVS V1.14.1: a control's native title is converted, not duplicated: its words are in the entry keyed by its id."""
    misses = []
    for page, fname in PAGES.items():
        html = _read(STATIC / fname)
        for tag in re.findall(r"<(?:button|input|select|textarea|a)\b[^>]*>", html):
            idm, tm = re.search(r'\bid="([\w-]+)"', tag), re.search(r'\btitle="([^"$`{]+)"', tag)
            if not idm or not tm:
                continue
            e = CAT["pages"].get(page, {}).get("#" + idm.group(1)) or CAT["pages"].get("*", {}).get("#" + idm.group(1))
            if not e:
                continue
            import html as _h
            title = re.sub(r"\s+", " ", _h.unescape(tm.group(1))).strip().lower()
            text = re.sub(r"\s+", " ", (e["what"] + " " + e["input"])).lower()
            if title not in text:
                misses.append((page, idm.group(1), title))
    assert not misses, misses[:10]


def _sentences(text):
    return [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s]


def _syllables(word):
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    n = len(re.findall(r"[aeiouy]+", w))
    if w.endswith("e") and not w.endswith(("le", "ee")) and n > 1:
        n -= 1
    return max(1, n)


def test_the_words_stay_plain():
    """WCAG 2.2 SC 3.1.5 (Reading level, AAA guidance applied as the owner asked): short sentences and short words on average.

    A sentence reused word for word from the page (a converted title or hint)
    may run longer: the page's own wording stays the source of truth."""
    src = re.sub(r"\s+", " ", all_sources())
    words = sentences = syll = 0
    long_sentences = []
    for page, sel, e in _entries():
        for s in _sentences(e["what"]):
            w = re.findall(r"[A-Za-z][A-Za-z'-]*", s)
            words += len(w); sentences += 1; syll += sum(_syllables(x) for x in w)
            if len(w) > 30 and re.sub(r"\s+", " ", s).rstrip(".") not in src:
                long_sentences.append((page, sel, s))
    grade = 0.39 * words / sentences + 11.8 * syll / words - 15.59
    assert words / sentences <= 16, words / sentences
    assert grade <= 8.5, f"Flesch-Kincaid grade {grade:.1f}"
    assert not long_sentences, long_sentences[:5]


def test_write_controls_say_they_need_write_mode():
    """ASVS V4.1.3 · CWE-841: a control marked as changing the tenant says it needs write mode (the pop-up adds the four gates)."""
    bad = [(p, s) for p, s, e in _entries() if e["effect"] == "write" and "write mode" not in (e["what"] + e["input"]).lower()]
    assert not bad, bad[:10]


# ── Browser harness ───────────────────────────────────────────────────

def _chrome():
    from test_sidebar_order import _chrome as find
    return find()


# Per page: what to do after loading, so the controls that only appear later
# (results after Analyze / Read / Preview, dialogs, tabs, folded sections,
# wizard steps) are enumerated too. Each step is [kind, selector, value?]:
# click (the first visible match), clickEach (every visible match, one at a
# time), fill, check, key. Tabs and <details> are opened on every page.
SCOPES = re.findall(r'class="scope-cb" value="([a-z_]+)"', _read(STATIC / "index.html")) + ["zia", "zia_platform"]
# kind: goto, fill, check, click (first visible match), clickEach (every
# visible match in turn, then the sub-steps), wait (until a selector is
# visible: a read on the sample tenant runs as a job), key.
TOURS = {
    "/": [["clickEach", "#dbTools button.db-item"], ["clickEach", "#dbTools button[onclick]", [["key", "Escape"]]]],
    "/simple": [["clickEach", "#smTiles button.sm-tile", [["click", "#smNext"], ["click", "#smNext"], ["click", "#smBack"], ["click", "#smBack"], ["click", "#smBack"]]]],
    "/report/path": [["fill", "#paDest", "dropbox.com"], ["click", "#paRun"], ["wait", "#paHeadline, .bp-card.risk"],
                     ["click", "button[data-flow-view=\"hops\"]"], ["click", "#tab-list"],
                     ["fill", "#plText", "destination,expected\ndropbox.com,block\n10.0.0.1,allow"], ["click", "#plRun"], ["wait", "#plSummary"]],
    "/report/operations": [["clickEach", "input[name=\"opKind\"]", [["click", "#opRead"], ["wait", "#opObjects *"]]]],
    "/report/zpa": [["click", "#zpRun"], ["wait", "#zoTables details"], ["click", "#tab-findings"],
                    ["click", "#tab-diagnose"], ["fill", "#dDest", "git.corp.example"], ["click", "#dRun"], ["wait", "#zpWalk button"]],
    "/report/device-posture": [["click", "#dvRun"], ["wait", "#dvTabs:not([hidden])"]],
    "/report/browser": [["click", "#bwRun"], ["wait", "#expXlsx:not([hidden])"]],
    "/report/insights": [["click", "#tiRun"], ["wait", "#tiGrid"]],
    "/report/motion": [["goto", "/report/motion#path"], ["fill", "#scenarioDestination", "drive.google.com"],
                       ["fill", "#scenarioCorpus", "Test card 4111 1111 1111 1111"], ["click", "#scenarioRun"]],
    "/report/live": [["click", "#lfStart"]],
    "/report/audit": [["click", "#atRun"]],
    "/report/beacon": [["click", "#bcRun"]],
    "/report/digest": [["click", "#dgRun"]],
    "/report/fleet": [["click", "#zfRun"]],
    "/report/shadow": [["click", "#shRun"]],
    "/report/sslcoverage": [["click", "#scRun"]],
}
# Pages that show a stored report (?id=): the tour opens one built by the
# app's own code from fake reads (filled in by the fixture).
REPORT_PAGES = ("/report/bypass", "/report/dataflow", "/report/sslflow", "/report/sslcoverage", "/report/compliance")


def _stored_reports():
    import dlp_api_server as srv
    import flow_motion_fixtures as fx
    from test_flow_pages import bypass_rep
    from compliance_mapping import get_framework_summary, get_control_drilldown, FRAMEWORK_DESCRIPTIONS
    checks = [{"id": "4.1", "section": "4 - SSL Policy", "label": "Inspection scope", "status": "FAIL", "detail": "No SSL Inspect rules"},
              {"id": "5.3", "section": "5 - Endpoint DLP", "label": "Web DLP rules", "status": "PASS", "detail": "3 active"}]
    comp = {"summary": get_framework_summary(checks), "drilldown": get_control_drilldown(checks),
            "descriptions": dict(FRAMEWORK_DESCRIPTIONS), "frameworks_selected": [], "check_count": 2, "metadata": {"org": "Larkspur Freight"}}
    ids = {"/report/bypass": srv._remember_report("bypass", bypass_rep(), "Sample"),
           "/report/dataflow": srv._remember_report("dataflow", fx.dataflow_report(), "Sample"),
           "/report/sslflow": srv._remember_report("sslflow", fx.sslflow_report(), "Sample"),
           "/report/sslcoverage": srv._remember_report("sslcoverage", fx.sslcoverage_report(), "Sample"),
           "/report/compliance": srv._remember_report("compliance", comp, "Sample")}
    return {page: [["goto", f"{page}?id={rid}"]] for page, rid in ids.items()}

DRIVER_JS = r"""
const [pagesJson, toursJson, scopesJson] = args;
const pages = JSON.parse(pagesJson), tours = JSON.parse(toursJson), SCOPES = JSON.parse(scopesJson);
await send('Page.addScriptToEvaluateOnNewDocument', { source: `
  window.print = () => {}; window.confirm = () => false; window.alert = () => {}; window.prompt = () => null;
  window.open = () => null;
  window.__inflight = 0; window.__act = performance.now(); const _f = window.fetch;
  const bump = () => { window.__act = performance.now(); };
  window.fetch = function (...a) { window.__inflight++; bump(); return _f.apply(this, a).finally(() => { window.__inflight--; bump(); }); };
  document.addEventListener('DOMContentLoaded', () => new MutationObserver(bump).observe(document.documentElement, { subtree: true, childList: true }));` });
const errors = [];
ws.addEventListener('message', e => { const m = JSON.parse(e.data);
  if (m.method === 'Page.javascriptDialogOpening') send('Page.handleJavaScriptDialog', { accept: false });
  if (m.method === 'Runtime.exceptionThrown') errors.push(String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200)); });
await send('Emulation.setDeviceMetricsOverride', { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });   // pictures start still
const frames = n => ev(`new Promise(r => { let k = ${n}; const f = () => (--k <= 0 ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
async function settle() {
  // Quiet: loaded, no request in flight and no DOM change for 600 ms (a
  // job's polls leave gaps between requests, so one idle moment is not enough).
  // A page that keeps animating never goes quiet: after 20 s it counts as settled.
  await until(() => ev(`document.readyState === 'complete' && !!window.HoverHelp`), 'the page to load', 60000);
  await until(() => ev(`(window.__inflight || 0) === 0 && performance.now() - (window.__act || 0) > 600`), 'quiet', 20000).catch(() => null);
  await frames(2);
}
await send('Page.navigate', { url: base + '/' }); await settle();
const sample = await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
// Everything ticked on the Scope page, so every page reads (the sample) and shows its results.
const SET_SCOPES = `localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ${JSON.stringify(SCOPES)} })), 1`;
await ev(SET_SCOPES);
// One pass over the visible controls: a control that needs explanation has
// a "?" mark; opening it shows its entry's words beside the mark, inside the
// viewport, and the mark's aria-describedby carries the same words. A
// control without a mark says why (skipReason).
const AUDIT = `(() => { const H = window.HoverHelp; window.__hhSeen = window.__hhSeen || new WeakSet();
  H.scan(); const out = [];
  const els = H.controls(document).filter(e => H.isVisible(e));
  for (const el of els) {
    const item = H.entryFor(el), mark = H.markOf(el), help = mark && mark.getAttribute('data-hh-mark') === 'help' ? mark : null;
    const row = { control: H.describe(el), key: item ? item.sel : null, mark: !!help, skip: item ? H.skipReason(el, item) : 'no entry',
      title: H.titleHost(el).getAttribute('data-hh-title') || '', focus: null };
    if (help && !window.__hhSeen.has(el)) {
      window.__hhSeen.add(el);
      const e = item.e;
      H.hide(); H.open(help, true);
      const tip = H.tip(), vw = document.documentElement.clientWidth, vh = window.innerHeight;
      const t = tip.getBoundingClientRect(), c = help.getBoundingClientRect();
      const desc = (document.getElementById(help.getAttribute('aria-describedby') || '') || {}).textContent || '';
      const overlap = Math.max(0, Math.min(t.right, c.right) - Math.max(t.left, c.left)) * Math.max(0, Math.min(t.bottom, c.bottom) - Math.max(t.top, c.top));
      const words = e.what.replace(/\\s+/g, ' ').trim(), problems = [];
      if (tip.hidden || !tip.textContent.includes(words)) problems.push('pop-up missing or wrong words');
      if (!desc.includes(words)) problems.push('the mark\\'s aria-describedby does not carry the words');
      if (help.getAttribute('aria-expanded') !== 'true' || help.getAttribute('aria-controls') !== tip.id) problems.push('aria-expanded or aria-controls wrong');
      if (!/^Help: \\S/.test(help.getAttribute('aria-label') || '')) problems.push('the mark is not named Help: <item>');
      if (overlap > 1 && c.top >= 0 && c.bottom <= vh) problems.push('covers the mark');
      if (t.left < -0.5 || t.right > vw + 0.5) problems.push('outside the viewport sideways');
      if (H.titleHost(el).hasAttribute('title')) problems.push('a native title is still there');
      H.hide();
      if (help.getAttribute('aria-expanded') !== 'false') problems.push('aria-expanded stays true after closing');
      row.focus = problems.join('; ');
    }
    out.push(row);
  }
  return out; })()`;
async function audit(page, state, acc) {
  const rows = await ev(AUDIT).catch(e => [{ control: 'AUDIT FAILED ' + String(e).slice(0, 200), key: null }]);
  for (const r of rows) {
    const k = r.control;
    if (!acc.controls[k]) acc.controls[k] = { key: r.key, state, title: r.title, mark: r.mark, skip: r.skip };
    else if (r.mark) acc.controls[k].mark = true;
    if (r.key) acc.used[r.key] = 1;
    if (r.focus) acc.focus.push(`${k}: ${r.focus} (${state})`);
  }
}
async function generic(page, acc, label) {
  await ev(`document.querySelectorAll('details:not([open])').forEach(d => { if (d.getBoundingClientRect().width) d.open = true; }), 1`);
  await frames(2); await audit(page, label + ' + folded sections opened', acc);
  const tabs = await ev(`[...document.querySelectorAll('[role=tab]')].filter(t => window.HoverHelp.isVisible(t)).map(t => window.HoverHelp.describe(t))`);
  const chosen = await ev(`[...document.querySelectorAll('[role=tab][aria-selected=true]')].filter(t => window.HoverHelp.isVisible(t)).map(t => window.HoverHelp.describe(t))`);
  for (const d of tabs) {
    const ok = await ev(`(() => { const t = [...document.querySelectorAll('[role=tab]')].find(x => window.HoverHelp.describe(x) === ${JSON.stringify(d)}); if (!t) return false; t.click(); return true; })()`);
    if (!ok) continue;
    await settle();
    await ev(`document.querySelectorAll('details:not([open])').forEach(d => { if (d.getBoundingClientRect().width) d.open = true; }), 1`);
    await audit(page, label + ' + tab ' + d, acc);
  }
  // Back to the tabs that were chosen, so the next step finds its panel.
  for (const d of chosen) await ev(`(() => { const t = [...document.querySelectorAll('[role=tab]')].find(x => window.HoverHelp.describe(x) === ${JSON.stringify(d)}); if (t) t.click(); return 1; })()`);
  if (chosen.length) await settle();
}
async function step(page, s, acc) {
  const [kind, sel, value] = s;
  const q = JSON.stringify(sel);
  if (kind === 'goto') { await send('Page.navigate', { url: base + sel }); await settle(); return true; }
  if (kind === 'fill') return ev(`(() => { const el = [...document.querySelectorAll(${q})].find(e => window.HoverHelp.isVisible(e)); if (!el) return false;
    el.value = ${JSON.stringify(value || '')}; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  if (kind === 'check') return ev(`(() => { const el = [...document.querySelectorAll(${q})].find(e => window.HoverHelp.isVisible(e)); if (!el) return false; if (!el.checked) el.click(); return true; })()`);
  if (kind === 'key') { await send('Input.dispatchKeyEvent', { type: 'keyDown', key: sel, code: sel }); await send('Input.dispatchKeyEvent', { type: 'keyUp', key: sel, code: sel }); return true; }
  if (kind === 'wait') return !!(await until(() => ev(`[...document.querySelectorAll(${q})].some(e => window.HoverHelp.isVisible(e))`), sel, 60000).catch(() => false));
  if (kind === 'click') return ev(`(() => { const el = [...document.querySelectorAll(${q})].find(e => window.HoverHelp.isVisible(e) && !e.disabled); if (!el) return false; el.click(); return true; })()`);
  if (kind === 'clickEach') {
    acc.log = (acc.log || []).concat([`clickEach ${sel}: ` + await ev(`document.querySelectorAll(${q}).length`)]);
    const n = await ev(`[...document.querySelectorAll(${q})].filter(e => window.HoverHelp.isVisible(e) && !e.disabled).length`);
    const here = await ev('location.pathname');
    for (let i = 0; i < n; i++) {
      const ok = await ev(`(() => { const el = [...document.querySelectorAll(${q})].filter(e => window.HoverHelp.isVisible(e) && !e.disabled)[${i}]; if (!el) return false; el.click(); return true; })()`);
      if (!ok) continue;
      await settle();
      // A button that opens another page: come back and carry on.
      if ((await ev('location.pathname')) !== here) { await send('Page.navigate', { url: base + here }); await settle(); continue; }
      await audit(page, `after ${kind} ${sel} #${i}`, acc);
      if (value) for (const sub of value) { await step(page, sub, acc); await settle(); await audit(page, `after ${sub.join(' ')}`, acc); }
    }
    return true;
  }
  return false;
}
const out = { sample, pages: {}, errors };
for (const page of pages) {
  const t0 = Date.now();
  const acc = out.pages[page] = { controls: {}, used: {}, focus: [], failedSteps: [], invalid: [] };
  await ev(SET_SCOPES).catch(() => null);   // the home page saves its own scope as it is toured
  await send('Page.navigate', { url: base + page }); await settle();
  await audit(page, 'loaded', acc);
  await generic(page, acc, 'loaded');
  for (const s of (tours[page] || [])) {
    const ok = await step(page, s, acc).catch(e => false);
    if (!ok) acc.failedSteps.push(s.join(' ') + (s[0] === 'wait' ? ' | page says: ' + (await ev(`document.body.innerText.replace(/\\s+/g, ' ').slice(0, 400)`).catch(() => '')) : ''));
    await settle();
    await audit(page, 'after ' + s.join(' '), acc);
    if (s[0] === 'click') await generic(page, acc, 'after ' + s.join(' '));
  }
  acc.count = Object.keys(acc.controls).length; acc.ms = Date.now() - t0;
  fs.appendFileSync(path.join(dir, 'progress.log'), `${page} ${acc.count} ${acc.ms}\n`);
  acc.invalid = await ev(`(() => { const c = window.HELP_CATALOG.pages; const keys = Object.keys(c[window.HoverHelp.pageKey()] || {}).concat(Object.keys(c['*'] || {}));
    return keys.filter(k => { try { document.querySelector(k); return false; } catch (e) { return true; } }); })()`);
}
fs.writeFileSync(path.join(dir, 'hh-out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'hh-out.json') }));
ws.close(); p.kill(); process.exit(0);
"""


def _unlimited_dispatch(dispatch):
    """The API rate limiter with its bucket refilled before every request:
    one browser touring every page is one client, not a flood."""
    async def wrapped(self, request, call_next):
        self.buckets.clear()
        return await dispatch(self, request, call_next)
    return wrapped


def _run(tmp_dir, driver, *args, timeout=900):
    """The real app on a loopback port (sample tenant, UI token off, write
    mode off, the updater and restart neutralised), driven by node in
    headless Chrome; returns the driver's JSON."""
    from test_findings_reflow import CDP_PRELUDE, run_in_browser
    import app_update
    mp = pytest.MonkeyPatch()
    mp.setattr(app_update, "update", lambda *a, **k: {"ok": False})
    mp.setattr(app_update, "schedule_restart", lambda *a, **k: {"ok": False})
    # As conftest's autouse fixtures do per test (they do not reach a
    # module-scoped fixture): ZIA's pacing off and a fresh request bucket,
    # so a tour of every page is never held back by the rate limiters.
    import zia_rate
    import security
    import dlp_api_server as srv
    for bucket in zia_rate.DEFAULTS:
        mp.setenv(f"DLP_CHECK_ZIA_LIMIT_{bucket.upper()}", "off")
    mp.setattr(zia_rate, "_covers", lambda bucket: True)
    mp.setattr(zia_rate, "_sleep", lambda s: None)
    zia_rate.reset()
    mp.setattr(security.RateLimitMiddleware, "dispatch", _unlimited_dispatch(security.RateLimitMiddleware.dispatch))
    try:
        res = run_in_browser(tmp_dir, CDP_PRELUDE + driver, *args, timeout=timeout)
    finally:
        mp.undo()
    return json.loads(Path(res["file"]).read_text(encoding="utf-8"))   # a file: stdout may be cut at 64 KB


def _tours():
    tours = {k: list(v) for k, v in TOURS.items()}
    for page, steps in _stored_reports().items():
        tours[page] = steps + tours.get(page, [])
    return tours


@pytest.fixture(scope="module")
def tour(tmp_path_factory):
    if not _chrome() or not shutil.which("node"):
        pytest.skip("needs node and Chrome/Chromium")
    out = _run(tmp_path_factory.mktemp("hh-tour"), DRIVER_JS, json.dumps(sorted(os.environ.get("HH_PAGES", "").split(",")) if os.environ.get("HH_PAGES") else sorted(PAGES)), json.dumps(_tours()), json.dumps(SCOPES))
    assert out["sample"] == 200, "the sample tenant switched on"
    return out


def _page(tour, page):
    if page not in tour["pages"]:
        pytest.skip("not toured in this run (HH_PAGES)")
    return tour["pages"][page]


# Why a control may have no "?" mark (hover_help.js, skipReason): each one
# is a label or a place that already says what the control is.
SKIP_REASONS = {
    "the label says it all",
    "a tab names its panel",
    "a step in a diagram: the picture and its words name it",
    'part of the page\'s own "What is this page" box',
    "one row of a table: its column says what it is",
    "a link inside a sentence",
    "an option with its own description",
    "a tile that carries its own description",
    "the first of the same kind in this list carries the mark",
}


@pytest.mark.parametrize("page", sorted(PAGES))
def test_every_visible_control_has_help(tour, page):
    """WCAG 2.2 SC 3.3.2 · SC 4.1.2 · ASVS V1.14.1: after every tour step, each visible control has a catalogue entry and a "?" mark, or a recorded reason it needs none (failures name page and selector)."""
    acc = _page(tour, page)
    missing = [f"{page} {c}  (seen {v['state']})" for c, v in acc["controls"].items() if not v["key"]]
    assert not missing, "controls without help:\n" + "\n".join(missing)
    unmarked = [f"{page} {c}: {v['skip'] or 'no reason'}" for c, v in acc["controls"].items() if not v["mark"] and v["skip"] not in SKIP_REASONS]
    assert not unmarked, "controls that need a ? mark:\n" + "\n".join(unmarked)


@pytest.mark.parametrize("page", sorted(PAGES))
def test_every_help_mark_opens_its_words(tour, page):
    """WCAG 2.2 SC 1.4.13 · SC 1.3.1 · SC 4.1.2: each "?" mark opens the entry's words beside it, names its item, sets aria-expanded, and its aria-describedby carries the words."""
    acc = _page(tour, page)
    assert not acc["focus"], "\n".join(acc["focus"][:20])


def test_most_controls_with_help_have_a_mark_and_the_skips_are_recorded(tour):
    """WCAG 2.2 SC 3.3.2 · ASVS V1.14.1: the coverage list stays honest: every page toured has marks, and each skipped control carries one of the recorded reasons."""
    for page, acc in tour["pages"].items():
        rows = list(acc["controls"].values())
        assert all(v["mark"] or v["skip"] in SKIP_REASONS for v in rows if v["key"]), page
    assert sum(1 for acc in tour["pages"].values() for v in acc["controls"].values() if v["mark"]) >= 150


@pytest.mark.parametrize("page", sorted(PAGES))
def test_every_catalogue_selector_is_valid_css(tour, page):
    """ASVS V5.1.3 · CWE-20: every key of the page (and the shared ones) is a selector the browser accepts."""
    assert not _page(tour, page)["invalid"], _page(tour, page)["invalid"]


@pytest.mark.parametrize("page", sorted(PAGES))
def test_the_tour_reaches_every_state_it_names(tour, page):
    """ISTQB test-basis traceability: every tour step found its control, so the dynamic controls really were enumerated."""
    assert not _page(tour, page)["failedSteps"], _page(tour, page)["failedSteps"]


def test_the_tour_left_no_script_errors(tour):
    """ASVS V7.4.1 · CWE-755: touring every page with Help on hover raises no uncaught exception."""
    errs = [e for e in tour["errors"] if "HoverHelp" in e or "hover_help" in e]
    assert not errs, errs[:5]


# ── WCAG 2.2 behaviours with real input events ────────────────────────

A11Y_JS = r"""
const [pagesJson] = args;
const pages = JSON.parse(pagesJson);
await send('Page.addScriptToEvaluateOnNewDocument', { source: `window.__inflight = 0; const _f = window.fetch;
  window.fetch = function (...a) { window.__inflight++; return _f.apply(this, a).finally(() => { window.__inflight--; }); };` });
const frames = n => ev(`new Promise(r => { let k = ${n}; const f = () => (--k <= 0 ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
// Block coverage of hover_help.js across every page this driver opens (V8's own counters).
await send('Profiler.enable'); await send('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
const covered = { len: 0, hit: null, fns: {} };
async function cov() {
  const r = await send('Profiler.takePreciseCoverage');
  for (const s of ((r.result || {}).result || [])) {
    if (!/\/static\/hover_help\.js/.test(s.url)) continue;
    const fn = s.functions[0], len = fn.ranges[0].endOffset;
    if (!covered.hit) { covered.len = len; covered.hit = new Uint8Array(len); }
    const mark = new Int8Array(len).fill(-1);
    for (const f of s.functions) {
      for (const rg of f.ranges) for (let i = rg.startOffset; i < Math.min(rg.endOffset, len); i++) mark[i] = rg.count > 0 ? 1 : 0;
      if (f.functionName || f.ranges[0].startOffset) { const k = f.functionName + '@' + f.ranges[0].startOffset; covered.fns[k] = (covered.fns[k] || 0) + f.ranges[0].count; }
    }
    for (let i = 0; i < len; i++) if (mark[i] === 1) covered.hit[i] = 1;
  }
}
const wait = ms => ev(`new Promise(r => setTimeout(() => r(true), ${ms}))`);   // the page's own clock: the pop-up's timers run there
async function open(url, width, reduce) {
  await cov();
  await send('Emulation.setDeviceMetricsOverride', { width, height: 1200, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: reduce ? 'reduce' : 'no-preference' }] });
  await send('Page.navigate', { url: base + url });
  await until(() => ev(`document.readyState === 'complete' && !!window.HoverHelp && (window.__inflight || 0) === 0`), 'page', 30000);
  await frames(2);
}
const tipState = `(() => { const t = window.HoverHelp.tip(); return !!t && !t.hidden; })()`;
const mouse = (type, x, y) => send('Input.dispatchMouseEvent', { type, x, y, button: 'none' });
const clickAt = async (x, y) => { await send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 }); await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 }); };
const key = async k => { const c = { Escape: 27, Tab: 9, Enter: 13, ' ': 32 }[k]; await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code: k === ' ' ? 'Space' : k, windowsVirtualKeyCode: c, text: k === 'Enter' ? '\r' : k === ' ' ? ' ' : undefined }); await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code: k === ' ' ? 'Space' : k, windowsVirtualKeyCode: c }); };
const centre = js => ev(`(() => { const el = ${js}; el.scrollIntoView({ block: 'center', behavior: 'instant' }); const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
const out = {};
const page = pages[0], sel = pages[1];
const CTL = `document.querySelector(${JSON.stringify(sel)})`, MARK = `window.HoverHelp.markOf(${CTL})`;
const state = () => ev(`(() => { const m = ${MARK}, t = window.HoverHelp.tip(); return { open: !!t && !t.hidden, expanded: m.getAttribute('aria-expanded'), active: document.activeElement === m ? 'mark' : document.activeElement === ${CTL} ? 'control' : (document.activeElement || {}).id || '' }; })()`);

// An ordinary control opens nothing: not on hover, not on keyboard focus.
await open(page, 1280, false);
await mouse('mouseMoved', 2, 1190);
let c = await centre(CTL);
await mouse('mouseMoved', c.x, c.y);
await wait(700);
out.controlHover = await ev(tipState);
await ev(`(${CTL}.blur(), document.body.focus(), 1)`);
await ev(`(() => { const el = ${CTL}; const all = [...document.querySelectorAll('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter(e => !e.disabled && e.getClientRects().length); const i = all.indexOf(el); all[Math.max(0, i - 1)].focus(); return 1; })()`);
await key('Tab');
await wait(600);
out.controlFocus = { open: await ev(tipState), focused: await ev(`document.activeElement === ${CTL}`) };
// The mark: next in the tab order, named, a 24px target beside the control, never over it.
await key('Tab');
out.markInfo = await ev(`(() => { const m = ${MARK}, el = ${CTL}; const r = m.getBoundingClientRect(), c = el.getBoundingClientRect(), t = window.HoverHelp.tip();
  return { isMark: document.activeElement === m, tag: m.tagName, type: m.type, label: m.getAttribute('aria-label'), expanded: m.getAttribute('aria-expanded'), controls: m.getAttribute('aria-controls'),
    tipId: t.id, role: t.getAttribute('role'), w: r.width, h: r.height, glyph: getComputedStyle(m, '::before').content,
    covers: Math.max(0, Math.min(r.right, c.right) - Math.max(r.left, c.left)) * Math.max(0, Math.min(r.bottom, c.bottom) - Math.max(r.top, c.top)),
    desc: (document.getElementById(m.getAttribute('aria-describedby') || '') || {}).textContent || '' }; })()`);
await wait(600);
out.markFocusAlone = await ev(tipState);
// Keyboard: Enter opens it, Esc closes it and focus stays on the mark; Space opens it again.
await key('Enter'); await frames(2);
out.enter = await state();
await key('Escape'); await frames(2);
out.esc = await state();
await key(' '); await frames(2);
out.space = await state();
await key('Escape'); await frames(2);
out.entry = await ev(`window.HoverHelp.entryFor(${CTL}).e`);
out.tipText = await ev(`(window.HoverHelp.open(${MARK}, true), window.HoverHelp.tip().textContent)`);
await ev(`(window.HoverHelp.hide(), 1)`);

// Pointer: hovering the mark opens it; the pointer can move onto the pop-up; leaving both closes it.
await open(page, 1280, false);
await mouse('mouseMoved', 2, 1190);
c = await centre(MARK);
await mouse('mouseMoved', c.x, c.y);
out.hoverOpens = !!(await until(() => ev(tipState), 'hover pop-up', 5000).catch(() => false));
const tr = await ev(`(() => { const r = window.HoverHelp.tip().getBoundingClientRect(); return { x: r.left + 10, y: r.top + 5 }; })()`);
await mouse('mouseMoved', c.x, (c.y + tr.y) / 2); await mouse('mouseMoved', tr.x, tr.y);
await wait(700);
out.hoverable = await ev(tipState);
await mouse('mouseMoved', 2, 1190);
out.leaveCloses = !!(await until(async () => !(await ev(tipState)), 'closed', 5000).catch(() => false));
// A click keeps it open after the pointer leaves; a click elsewhere closes it; the control is not pressed.
c = await centre(MARK);
await ev(`(window.__ctlClicks = 0, ${CTL}.addEventListener('click', () => window.__ctlClicks++), 1)`);
await clickAt(c.x, c.y);
await mouse('mouseMoved', 2, 1190);
await wait(700);
out.clickKeeps = await state();
await clickAt(640, 1180);
await frames(2);
out.outsideCloses = !(await ev(tipState));
out.controlPressed = await ev(`window.__ctlClicks`);
// One at a time: opening another mark closes the first.
out.oneAtATime = await ev(`(() => { const H = window.HoverHelp, ms = H.marks().filter(m => !m.hidden).slice(0, 2); H.open(ms[0], true); H.open(ms[1], true);
  const r = { first: ms[0].getAttribute('aria-expanded'), second: ms[1].getAttribute('aria-expanded'), forSecond: H.current() === ms[1] }; H.hide(); return r; })()`);
// A sidebar item's mark opens help and the item itself still opens its page.
await open('/', 1280, false);
out.sidebar = await ev(`(() => { const item = document.querySelector('#dbSidebar button[onclick="openPathAnalyzerTab()"]'), H = window.HoverHelp, m = H.markOf(item);
  let opened = 0; const real = window.openPathAnalyzerTab; window.openPathAnalyzerTab = () => { opened++; };
  m.click(); const tip = !H.tip().hidden && H.tip().textContent.includes(H.entryFor(item).e.what.replace(/\\s+/g, ' ').trim()); H.hide();
  item.click(); window.openPathAnalyzerTab = real;
  return { markLabel: m.getAttribute('aria-label'), tip, opened, sibling: item.nextElementSibling && item.nextElementSibling.classList.contains('hh-mark'), sameRow: Math.abs(m.getBoundingClientRect().top + m.getBoundingClientRect().height / 2 - item.getBoundingClientRect().top - item.getBoundingClientRect().height / 2) < item.getBoundingClientRect().height / 2 }; })()`);

// Motion: a short fade normally, none at all with reduced motion.
await open(page, 1280, false);
out.motion = await ev(`(() => { window.HoverHelp.open(${MARK}, true); return getComputedStyle(window.HoverHelp.tip()).transitionDuration; })()`);
await open(page, 1280, true);
out.reduced = await ev(`(() => { window.HoverHelp.open(${MARK}, true); return getComputedStyle(window.HoverHelp.tip()).transitionDuration; })()`);

// Contrast in the dark (default) and light themes: the pop-up's lines, and the marks against the page.
const CONTRAST = `(() => { const lum = c => { const v = c.match(/[\\d.]+/g).slice(0, 3).map(Number).map(x => /^color\\(srgb/.test(c) ? x * 255 : x).map(x => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }); return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2]; };
  const H = window.HoverHelp; H.open(${MARK}, true); const t = H.tip(); const bg = lum(getComputedStyle(t).backgroundColor);
  return Math.min(...[t, ...t.querySelectorAll('p, strong')].map(n => { const f = lum(getComputedStyle(n).color); return (Math.max(f, bg) + 0.05) / (Math.min(f, bg) + 0.05); })); })()`;
await ev(`document.body.classList.remove('theme-light'), 1`);
out.themes = [await ev(`getComputedStyle((window.HoverHelp.open(${MARK}, true), window.HoverHelp.tip())).backgroundColor`)];
out.contrastDark = await ev(CONTRAST);
await ev(`document.body.classList.add('theme-light'), 1`);
out.contrastLight = await ev(CONTRAST);
out.themes.push(await ev(`getComputedStyle(window.HoverHelp.tip()).backgroundColor`));

// Touch: a tap on the mark opens it; a tap on the control does not.
await open(page, 390, false);
await send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 1 });
const tap = async (x, y) => { await send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }] }); await send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] }); };
c = await centre(CTL);
await tap(c.x, c.y); await wait(700);
out.tapControl = await ev(tipState);
await ev(`(document.activeElement && document.activeElement.blur && document.activeElement.blur(), 1)`);
c = await centre(MARK);
await tap(c.x, c.y);
out.tapMark = !!(await until(() => ev(tipState), 'tap pop-up', 5000).catch(() => false));
await send('Emulation.setTouchEmulationEnabled', { enabled: false });

// Reflow at 320px: every visible mark's pop-up stays inside the viewport and the page never scrolls sideways.
out.reflow = {};
for (const p of pages.slice(2)) {
  await open(p, 320, false);
  out.reflow[p] = await ev(`(() => { const H = window.HoverHelp, bad = []; const vw = document.documentElement.clientWidth; H.hide(); const base = Math.max(vw, document.documentElement.scrollWidth);
    if (base > vw + 0.5) bad.push('the page scrolls sideways with the marks: ' + base);
    for (const m of H.marks().filter(m => !m.hidden && m.getClientRects().length).slice(0, 80)) { if (!H.open(m, true)) continue;
      const r = H.tip().getBoundingClientRect(), sw = document.documentElement.scrollWidth;
      if (r.left < 0 || r.right > vw + 0.5 || sw > base + 0.5) bad.push(m.getAttribute('aria-label') + ' tip ' + Math.round(r.left) + '..' + Math.round(r.right) + ' page ' + sw); H.hide(); }
    return { vw, base, bad: bad.slice(0, 10), marks: H.marks().length }; })()`);
}

// Escaping: hostile catalogue words and a hostile native title stay text.
await open(page, 1280, false);
out.xss = await ev(`(() => { const H = window.HoverHelp, el = ${CTL}; const key = H.entryFor(el).sel;
  const evil = '<img src=x onerror="window.__xss=1"><b>bold</b>';
  window.HELP_CATALOG.pages[H.pageKey()][key] = { what: evil, input: evil, effect: 'write' };
  el.setAttribute('title', '<svg onload="window.__xss=1">'); H.reset(); H.show(el); const t = H.tip();
  return { imgs: document.querySelectorAll('img[src="x"], svg[onload]').length + t.querySelectorAll('*:not(p):not(strong)').length,
    text: t.textContent, titleGone: !el.hasAttribute('title'), fired: window.__xss === 1 }; })()`);

// A new button nobody wrote help for is reported with its page and selector.
out.canary = await ev(`(() => { const b = document.createElement('button'); b.id = 'hhCanaryButton'; b.textContent = 'Brand new'; document.body.prepend(b);
  return window.HoverHelp.audit().filter(r => !r.key).map(r => r.page + ' ' + r.control); })()`);
await cov();
const fnv = Object.values(covered.fns);
out.coverage = { bytes: covered.hit ? covered.hit.reduce((a, b) => a + b, 0) / covered.len : 0, functions: fnv.length ? fnv.filter(c => c > 0).length / fnv.length : 0,
  uncalled: Object.entries(covered.fns).filter(([k, c]) => !c).map(([k]) => k) };
fs.writeFileSync(path.join(dir, 'hh-out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'hh-out.json') }));
ws.close(); p.kill(); process.exit(0);
"""

A11Y_PAGE, A11Y_CONTROL = "/report/path", "#paDest"
REFLOW_PAGES = sorted(PAGES)


@pytest.fixture(scope="module")
def a11y(tmp_path_factory):
    if not _chrome() or not shutil.which("node"):
        pytest.skip("needs node and Chrome/Chromium")
    return _run(tmp_path_factory.mktemp("hh-a11y"), A11Y_JS, json.dumps([A11Y_PAGE, A11Y_CONTROL] + REFLOW_PAGES))


def test_pointing_at_or_tabbing_to_an_ordinary_control_opens_nothing(a11y):
    """WCAG 2.2 SC 1.4.13 · SC 3.2.1 (On Focus): resting the pointer on a control, or Tab focus landing on it, opens no help; only its mark does."""
    assert a11y["controlHover"] is False
    assert a11y["controlFocus"] == {"open": False, "focused": True}, a11y["controlFocus"]


def test_the_mark_is_a_named_button_beside_its_item(a11y):
    """WCAG 2.2 SC 4.1.2 · SC 2.5.8 · SC 1.3.1: the mark is a real button named "Help: <item>", next in the tab order, 24px, beside the control and never over it, with aria-expanded and aria-controls the tooltip."""
    m = a11y["markInfo"]
    assert m["isMark"] and m["tag"] == "BUTTON" and m["type"] == "button", m
    assert m["label"] == "Help: Destination" and m["expanded"] == "false" and m["controls"] == m["tipId"] == "hhTip" and m["role"] == "tooltip", m
    assert m["w"] >= 24 and m["h"] >= 24 and m["covers"] == 0 and m["glyph"] == '"?"', m
    assert a11y["markFocusAlone"] is False, "focus alone opens nothing: Enter or Space does"


def test_the_keyboard_opens_and_closes_the_mark(a11y):
    """WCAG 2.2 SC 2.1.1 · SC 1.4.13 (dismissible): Enter opens the mark's help, Esc closes it with focus kept on the mark, Space opens it again."""
    assert a11y["enter"] == {"open": True, "expanded": "true", "active": "mark"}, a11y["enter"]
    assert a11y["esc"] == {"open": False, "expanded": "false", "active": "mark"}, a11y["esc"]
    assert a11y["space"]["open"] is True and a11y["space"]["expanded"] == "true", a11y["space"]


def test_the_mark_opens_the_entrys_words(a11y):
    """WCAG 2.2 SC 3.3.2 · SC 1.3.1: the pop-up and the mark's aria-describedby carry the entry's words: what it does and what input it expects."""
    e = a11y["entry"]
    assert e["what"] in a11y["tipText"] and e["input"] in a11y["tipText"]
    assert e["what"] in a11y["markInfo"]["desc"] and e["input"] in a11y["markInfo"]["desc"]


def test_hovering_the_mark_opens_the_help_and_it_is_hoverable(a11y):
    """WCAG 2.2 SC 1.4.13 (hoverable, persistent): pointing at the mark opens it, the pointer can move onto it, and leaving both closes it."""
    assert a11y["hoverOpens"] and a11y["hoverable"] and a11y["leaveCloses"]


def test_a_click_keeps_it_open_and_a_click_elsewhere_closes_it(a11y):
    """WCAG 2.2 SC 1.4.13 · SC 2.5.2: a click on the mark keeps the help open after the pointer leaves; a click elsewhere closes it; the control itself is never pressed."""
    assert a11y["clickKeeps"]["open"] and a11y["clickKeeps"]["expanded"] == "true", a11y["clickKeeps"]
    assert a11y["outsideCloses"] and a11y["controlPressed"] == 0


def test_one_help_is_open_at_a_time(a11y):
    """WCAG 2.2 SC 1.4.13: opening another mark closes the first."""
    assert a11y["oneAtATime"] == {"first": "false", "second": "true", "forSecond": True}, a11y["oneAtATime"]


def test_a_sidebar_mark_never_hijacks_the_item(a11y):
    """WCAG 2.2 SC 2.5.2 · SC 3.2.2: in the sidebar the mark opens help and the item's own words still open its page; the mark sits on the item's row."""
    sb = a11y["sidebar"]
    assert sb["markLabel"] == "Help: Path analyzer" and sb["tip"] and sb["opened"] == 1 and sb["sibling"] and sb["sameRow"], sb


def test_a_tap_on_the_mark_opens_the_help_and_a_tap_on_the_control_does_not(a11y):
    """WCAG 2.2 SC 2.5.8 · SC 1.4.13: on touch a tap on the mark opens the help; tapping the control opens nothing."""
    assert a11y["tapMark"] and a11y["tapControl"] is False


def test_reduced_motion_shows_the_help_without_animation(a11y):
    """WCAG 2.2 SC 2.3.3 (prefers-reduced-motion honoured): a short fade normally, none with reduced motion."""
    assert a11y["motion"] != "0s" and a11y["reduced"] == "0s"


@pytest.mark.parametrize("theme", ["contrastDark", "contrastLight"])
def test_the_help_text_has_enough_contrast(a11y, theme):
    """WCAG 2.2 SC 1.4.3 (Contrast, Minimum): every line of the pop-up is at least 4.5:1 in dark and light mode."""
    assert a11y[theme] >= 4.5, a11y[theme]
    assert a11y["themes"][0] != a11y["themes"][1], "the pop-up follows the page theme"


@pytest.mark.parametrize("page", REFLOW_PAGES)
def test_the_help_stays_inside_320px_and_never_scrolls_sideways(a11y, page):
    """WCAG 2.2 SC 1.4.10 (Reflow): at 320px the marks never make the page scroll sideways and every mark's pop-up stays inside the viewport."""
    assert not a11y["reflow"][page]["bad"], a11y["reflow"][page]


def test_hostile_words_and_titles_stay_text(a11y):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: markup in the catalogue or a title is shown as text and never runs."""
    x = a11y["xss"]
    assert x["imgs"] == 0 and not x["fired"] and "<img src=x" in x["text"] and "<svg onload" in x["text"] and x["titleGone"], x


def test_a_new_button_without_help_is_named(a11y):
    """ASVS V1.14.1 · NIST SSDF PW.8: a control added without help is reported with its page and selector."""
    assert f"{A11Y_PAGE} #hhCanaryButton" in a11y["canary"], a11y["canary"]


@pytest.mark.parametrize("page", sorted(PAGES))
def test_a_converted_title_keeps_its_words(tour, page):
    """WCAG 2.2 SC 1.4.13 · ASVS V1.14.1: a control's native title (as written in the source) is taken off and its words live in the entry, so there is one text per control."""
    _page(tour, page)
    src = re.sub(r"\s+", " ", all_sources())
    import html as _h
    entries = {**CAT["pages"].get("*", {}), **CAT["pages"].get(page, {})}
    lost = []
    controls = tour["pages"][page]["controls"]
    titles_per_key = {}
    for v in controls.values():
        if v["key"] and v.get("title"):
            titles_per_key.setdefault(v["key"], set()).add(re.sub(r"\s+", " ", v["title"]).strip())
    for control, v in controls.items():
        title = re.sub(r"\s+", " ", v.get("title") or "").strip()
        if not title or not v["key"] or (title not in src and _h.escape(title, quote=True) not in src and _h.escape(title, quote=False) not in src):
            continue   # no title, or one built at run time (a state, shown as the pop-up's "Note" line)
        if len(titles_per_key[v["key"]]) > 1:
            continue   # one entry for a list whose items each carry their own words (the "Note" line shows them)
        e = entries[v["key"]]
        if title.lower() not in re.sub(r"\s+", " ", e["what"] + " " + e["input"]).lower():
            lost.append(f"{page} {control} [{v['key']}]: {title}")
    assert not lost, "\n".join(lost)


# ── The browser extension's pages ─────────────────────────────────────

EXT_JS = r"""
const [extBase, pagesJson] = args;
const appBase = base;
await send('Page.addScriptToEvaluateOnNewDocument', { source: `
  const store = { app: ${JSON.stringify(appBase)} };
  const ev = () => ({ addListener() {} });
  window.chrome = {
    storage: { sync: { get: async () => ({ ...store }), set: async () => {} }, session: { get: async () => ({}), set: async () => {} }, onChanged: ev() },
    tabs: { query: async () => [{ id: 1, url: 'https://www.example.com/path?q=1' }], create() {}, sendMessage: async () => null, onActivated: ev() },
    runtime: { openOptionsPage() {}, sendMessage: async () => null, onMessage: ev() },
    permissions: { contains: async () => false, request: async () => false, remove: async () => true },
    windows: { getCurrent: async () => ({ id: 1 }) }, sidePanel: { open: async () => {} },
  };
  window.close = () => {};` });
const frames = n => ev(`new Promise(r => { let k = ${n}; const f = () => (--k <= 0 ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
const out = {};
for (const [key, file] of Object.entries(JSON.parse(pagesJson))) {
  await send('Page.navigate', { url: extBase + '/' + file });
  await until(() => ev(`document.readyState === 'complete' && !!window.HoverHelp`), file, 20000);
  await ev(`new Promise(r => setTimeout(() => r(1), 800))`);   // the module's async start (ping, storage)
  const seen = {};
  const take = async () => { for (const r of await ev(`window.HoverHelp.audit()`)) seen[r.control] = r; };
  await take();
  const tabs = await ev(`[...document.querySelectorAll('[role=tab]')].map(t => t.id)`);
  for (const t of tabs) { await ev(`document.getElementById(${JSON.stringify(t)}).click(), 1`); await frames(3); await take(); }
  out[key] = { page: await ev(`window.HoverHelp.pageKey()`), rows: Object.values(seen) };
}
fs.writeFileSync(path.join(dir, 'hh-out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'hh-out.json') }));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def ext(tmp_path_factory):
    if not _chrome() or not shutil.which("node"):
        pytest.skip("needs node and Chrome/Chromium")
    import functools
    import http.server
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(EXT))
    handler.log_message = lambda *a: None
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        return _run(tmp_path_factory.mktemp("hh-ext"), EXT_JS, f"http://127.0.0.1:{httpd.server_address[1]}", json.dumps(EXT_PAGES))
    finally:
        httpd.shutdown()


@pytest.mark.parametrize("key", sorted(EXT_PAGES))
def test_every_extension_control_has_help(ext, key):
    """WCAG 2.2 SC 3.3.2 · SC 4.1.2: the extension's popup, options and side panel controls each have an entry, and a "?" mark or a recorded reason they need none (failures name page and selector)."""
    page = ext[key]
    assert page["page"] == key
    missing = [f"{key} {r['control']}" for r in page["rows"] if not r["key"]]
    assert page["rows"] and not missing, missing
    unmarked = [f"{key} {r['control']}: {r['skip']}" for r in page["rows"] if not r["mark"] and r["skip"] not in SKIP_REASONS]
    assert not unmarked, unmarked


def test_the_engine_is_exercised_by_these_tests(a11y):
    """NIST SSDF PW.8 · ISTQB coverage: the browser tests run at least 85% of hover_help.js's code and 90% of its functions (V8 block coverage)."""
    c = a11y["coverage"]
    assert c["bytes"] >= 0.85 and c["functions"] >= 0.90, c


# ── Review fixes: the write line, the phrase field, Esc and focus in dialogs ──

def _effect_lines() -> dict:
    """EFFECTS from hover_help.js, as data (each line is one quoted string)."""
    js = _read(STATIC / "hover_help.js")
    block = re.search(r"const EFFECTS = \{(.*?)\};", js, re.S).group(1)
    return dict(re.findall(r"(\w+):\s*'([^']*)'", block))


def test_the_write_line_names_all_four_gates():
    """ASVS V4.1.3 · CWE-841 · WCAG 2.2 SC 3.3.2: the line every write control gets names write mode, a writer, the named assessor and the confirmation."""
    line = _effect_lines()["write"].lower()
    for gate in ("write mode", "writer", "assessor", "confirm"):
        assert gate in line, (gate, line)


def test_no_write_entry_says_nothing_to_type_and_gets_a_typed_line():
    """ASVS V4.1.3 · CWE-841 · WCAG 2.2 SC 3.3.2: the shared write line never promises a typed phrase that an entry (a yes in a dialog) says is not there."""
    line = _effect_lines()["write"].lower()
    clash = [(p, s) for p, s, e in _entries() if e["effect"] == "write" and "nothing to type" in e["input"].lower() and "typ" in line]
    assert not clash, clash


@pytest.mark.parametrize("page,sel", [("/report/self-heal", "#shHealSel"), ("/report/self-heal", 'button[data-act="heal"]'),
                                      ("/report/self-heal", 'button[data-act="undo"]'), ("/report/queue", 'button[data-act="apply"]')])
def test_the_heal_undo_and_queue_apply_help_names_the_writer_and_the_assessor(page, sel):
    """ASVS V4.1.3 · CWE-841 · WCAG 2.2 SC 3.3.2: these writes also refuse without a writer and a named assessor, so their help says so."""
    e = CAT["pages"][page][sel]
    text = (e["what"] + " " + e["input"]).lower()
    assert e["effect"] == "write" and "write mode" in text and "writer" in text and "assessor" in text, e


@pytest.mark.parametrize("sel", ["#dlpPhraseInput", "#dlpPhraseGo"])
def test_the_confirmation_phrase_help_says_type_it_as_shown(sel):
    """WCAG 2.2 SC 3.3.2 · SC 3.3.4 · CWE-1021: the phrase help never asks for underscores (I UNDERSTAND has a space) and never calls the consent step tenant-free."""
    e = CAT["pages"]["*"][sel]
    line = _effect_lines().get(e["effect"], "")
    text = " ".join((e["what"], e["input"], line))
    assert "underscore" not in text.lower() and "does not touch your tenant" not in text.lower(), text
    if sel == "#dlpPhraseInput":
        assert "Type the phrase shown above exactly as shown" in e["input"], e


def test_the_phrase_dialog_error_never_asks_for_underscores():
    """WCAG 2.2 SC 3.3.1 · SC 3.3.3: a mistyped phrase is told to type it as shown, not 'with the underscores' (the queue and self-heal phrase has a space)."""
    js = _read(STATIC / "ui_auth.js")
    assert "underscore" not in js.lower()
    assert "Type it exactly as shown above" in js


DIALOG_JS = r"""
const frames = n => ev(`new Promise(r => { let k = ${n}; const f = () => (--k <= 0 ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
const wait = ms => ev(`new Promise(r => setTimeout(() => r(true), ${ms}))`);
const tipState = `(() => { const t = window.HoverHelp.tip(); return !!t && !t.hidden; })()`;
const mouse = (x, y) => send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, button: 'none' });
const key = async (k, vk) => { await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code: k, windowsVirtualKeyCode: vk || 27 }); await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code: k, windowsVirtualKeyCode: vk || 27 }); };
const centre = js => ev(`(() => { const r = (${js}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
const out = {};
async function load() {
  await send('Page.navigate', { url: base + '/report/path' });
  await until(() => ev(`document.readyState === 'complete' && !!window.HoverHelp && !!window.dlpDialog && !!window.DLP_FIND`), 'the page', 30000);
  await frames(2); await mouse(2, 890);
}
async function probe(name, fieldId, openJs, isOpenJs, cancelledJs) {
  await load();
  await ev(openJs);
  await until(() => ev(`(document.activeElement || {}).id === ${JSON.stringify(fieldId)}`), 'focus in ' + fieldId);
  await ev(`window.HoverHelp.scan(), 1`); await frames(2);
  await wait(600);
  const r = out[name] = { autoOpen: await ev(tipState) };
  let c = await centre(`document.getElementById(${JSON.stringify(fieldId)})`);
  await mouse(c.x, c.y); await wait(700);
  r.fieldHover = await ev(tipState);
  const MARK = `window.HoverHelp.markOf(document.getElementById(${JSON.stringify(fieldId)}))`;
  r.mark = await ev(`(() => { const m = ${MARK}; return m ? { label: m.getAttribute('aria-label'), inDialog: !!m.closest('dialog, [role="dialog"]') } : null; })()`);
  c = await centre(MARK);
  await mouse(c.x, c.y);
  r.hoverOpens = !!(await until(() => ev(tipState), 'hover pop-up', 5000).catch(() => false));
  await key('Escape');
  await frames(2);
  r.tipClosed = !(await ev(tipState));
  r.dialogOpen = await ev(isOpenJs);
  r.result = await ev(`window.__res`);
  r.focus = await ev(`(document.activeElement || {}).id || ''`);
  // Opened by hover, it closes when the pointer leaves.
  await mouse(2, 890); await wait(300);
  await mouse(c.x, c.y);
  const again = !!(await until(() => ev(tipState), 'hover again', 5000).catch(() => false));
  await mouse(2, 890);
  r.leave = { again, closes: !!(await until(async () => !(await ev(tipState)), 'closed', 5000).catch(() => false)) };
  await key('Escape');
  r.secondEscCancels = !!(await until(() => ev(cancelledJs), 'cancel', 5000).catch(() => false));
}
// The shared typed-confirmation dialog (ui_auth.js), opened as a write would open it.
await probe('phrase', 'dlpPhraseInput',
  `(window.__res = 'open', window.dlpDialog.phrase({ title: 'Apply this approved request?', body: 'It changes the tenant.', phrase: 'I UNDERSTAND', okLabel: 'Apply' }).then(v => { window.__res = v; }), 1)`,
  `!!document.querySelector('dialog.dlp-dlg[open]')`, `window.__res === null && !document.querySelector('dialog.dlp-dlg[open]')`);
// Find anything (find_anything.js): a combobox in an aria-modal dialog.
await probe('find', 'faInput', `(window.__res = 'open', window.DLP_FIND.open(), 1)`, `window.DLP_FIND.isOpen()`, `!window.DLP_FIND.isOpen()`);
// Tab to a dialog's button opens nothing either.
await load();
await ev(`(window.dlpDialog.phrase({ title: 'Confirm', body: 'Body', phrase: 'I UNDERSTAND' }), 1)`);
await until(() => ev(`(document.activeElement || {}).id === 'dlpPhraseInput'`), 'focus in the phrase field');
for (let i = 0; i < 4 && (await ev(`(document.activeElement || {}).id`)) !== 'dlpPhraseCancel'; i++) await key('Tab', 9);
await wait(600);
out.buttonFocus = { el: await ev(`(document.activeElement || {}).id || ''`), opens: await ev(tipState) };
fs.writeFileSync(path.join(dir, 'hh-out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'hh-out.json') }));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def dialogs(tmp_path_factory):
    if not _chrome() or not shutil.which("node"):
        pytest.skip("needs node and Chrome/Chromium")
    return _run(tmp_path_factory.mktemp("hh-dialogs"), DIALOG_JS, timeout=300)


@pytest.mark.parametrize("which", ["phrase", "find"])
def test_focus_or_hover_on_a_dialog_field_opens_nothing_and_its_mark_does(dialogs, which):
    """WCAG 2.2 SC 1.4.13 · SC 2.4.11 (Focus Not Obscured): the phrase field and Find anything open with no pop-up over the dialog, pointing at the field opens nothing, and its mark, inside the dialog, opens the help."""
    d = dialogs[which]
    assert d["autoOpen"] is False and d["fieldHover"] is False and d["hoverOpens"] is True, d
    assert d["mark"] and d["mark"]["inDialog"] and d["mark"]["label"].startswith("Help: "), d


@pytest.mark.parametrize("which", ["phrase", "find"])
def test_esc_closes_only_the_help_and_keeps_the_dialog(dialogs, which):
    """WCAG 2.2 SC 1.4.13 (dismissible) · SC 2.1.2 · CWE-1021: with the pop-up shown, Esc closes the pop-up only: the dialog stays open, unanswered, with focus in its field."""
    d = dialogs[which]
    assert d["tipClosed"] and d["dialogOpen"], d
    assert d["focus"] == ("dlpPhraseInput" if which == "phrase" else "faInput"), d
    assert d["result"] == "open", d


@pytest.mark.parametrize("which", ["phrase", "find"])
def test_esc_without_the_help_still_closes_the_dialog(dialogs, which):
    """WCAG 2.2 SC 2.1.2 (No Keyboard Trap): boundary: once no pop-up is shown, Esc reaches the dialog and cancels it (the phrase dialog answers null)."""
    assert dialogs[which]["secondEscCancels"], dialogs[which]


def test_tab_to_a_dialog_button_opens_nothing(dialogs):
    """WCAG 2.2 SC 3.2.1 (On Focus) · SC 2.4.11: Tab to the dialog's Cancel button opens no help over the dialog."""
    assert dialogs["buttonFocus"] == {"el": "dlpPhraseCancel", "opens": False}, dialogs["buttonFocus"]


@pytest.mark.parametrize("which", ["phrase", "find"])
def test_a_hover_opened_help_in_a_dialog_closes_when_hover_leaves(dialogs, which):
    """WCAG 2.2 SC 1.4.13 · SC 2.4.11: opened by pointing at the mark, the pop-up follows the pointer, so it does not stay over the dialog's buttons."""
    assert dialogs[which]["leave"] == {"again": True, "closes": True}, dialogs[which]["leave"]
