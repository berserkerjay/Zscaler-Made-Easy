// ── What's new: a * after the label of each new feature ───────────────
// The manifest below is the one list of what is new. Each feature names the
// CHANGELOG.md release it came in ("release", the heading's date), a short
// plain label, what it is (the words after "New in the <date> update: "),
// the CHANGELOG phrases it covers, and where it shows ("marks": the page and
// the item: a control, a sidebar item, a page title or a heading). "shown"
// says when a mark's item appears later (after a read, in a dialog).
//
// Only the features of the newest two releases are marked ("keep"): add the
// next release to "releases", with its features, and the oldest set stops
// showing. A CHANGELOG release with nothing to mark goes in "skipped" with
// the reason, and pushes nothing out (tests/test_new_marks.py checks both
// lists against CHANGELOG.md).
//
// This file only says which item is new: it puts the words on the item
// (data-wn-new). The help marks (hover_help.js) draw the superscript * after
// it, a button of its own named "New in this version: <item>", whose pop-up
// says "New in the <date> update: …", beside the item's ? help mark. It also
// puts the legend "* New in this version" in the page header (the sidebar
// foot on the home page), and "Hide new marks" in Advanced settings, kept in
// this browser only. Every word is set with textContent, never as HTML.
window.WHATS_NEW = {
  "keep": 2,
  "releases": {
    "2026-10-31": "The whole platform, assessed: deeper Workflow Automation incidents and AI Guard",
    "2026-10-29": "Wave 6: regression and secure-by-design testing, live motion, help on hover, Liquid Glass, a quality score"
  },
  "skipped": {
    "2026-10-30": "The new name everywhere, ZIA admin ranking in the rule decisions (no new control) and the help and new marks themselves: a * on the marks would push 2026-10-28 out, so this release is not marked and the two releases above stay"
  },
  "legend": { "/": ["#dbFoot", ".hero"], "*": [".rp-hero"] },
  "features": [
    {
      "id": "live-motion", "release": "2026-10-29", "label": "Live motion",
      "what": "The result shows as a live flow. It stays still under reduced motion, pauses when the tab is hidden, and is said in words too.",
      "changelog": ["Live motion"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openPathAnalyzerTab()\"]" },
        { "page": "/report/path", "at": "#paFlowRefH" },
        { "page": "/report/path", "at": "#paFlowH", "shown": "after Analyze" },
        { "page": "/report/path", "at": "#plFlowH", "shown": "after a list is tested" },
        { "page": "/report/motion", "at": "#tpH" },
        { "page": "/report/dataflow", "at": "#dfMotionTitle" },
        { "page": "/report/sslflow", "at": "#sfWalkTitle", "shown": "after a read" },
        { "page": "/report/sslcoverage", "at": "#hRiver", "shown": "after a read" },
        { "page": "/report/zpa", "at": "#zoFlowH", "shown": "after a read" },
        { "page": "/report/zpa", "at": "#zpWalkH", "shown": "after Diagnose" },
        { "page": "/report/insights", "at": "#tiFlowH", "shown": "after a read" },
        { "page": "/report/live", "at": "#lfLanesH" },
        { "page": "/report/bypass", "at": "#bpFlowH", "shown": "after a read" }
      ]
    },
    {
      "id": "liquid-glass", "release": "2026-10-29", "label": "Liquid Glass",
      "what": "The Liquid Glass look: see-through, blurred bars, cards, dialogs and buttons, with a switch in Advanced settings to turn it off.",
      "changelog": ["Liquid Glass"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openAdvancedTab()\"]" },
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#appearance\"]" },
        { "page": "/report/advanced", "at": "#advGlass" }
      ]
    },
    {
      "id": "quality-score", "release": "2026-10-29", "label": "Quality and security score",
      "what": "The quality and security score for this app, built from every QA record, the standards each test covers and the last full test run.",
      "changelog": ["Quality and security score"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openAdvancedTab()\"]" },
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#quality\"]" },
        { "page": "/report/advanced", "at": "#advQsH" }
      ]
    },
    {
      "id": "aiguard-page", "release": "2026-10-31", "label": "AI Guard page",
      "what": "The AI Guard page: its detection policies, policy match rules, LLM applications and credential names (never a key), read only when AI Guard is ticked.",
      "changelog": ["AI Guard page", "AI Guard"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openAiGuardTab()\"]" },
        { "page": "/report/aiguard", "at": ".rp-hero h1" }
      ]
    },
    {
      "id": "aiguard-test-prompt", "release": "2026-10-31", "label": "Test a prompt",
      "what": "Test a prompt: send one made-up prompt from a fixed list to AI Guard and see what each detector did. Nothing you type is ever sent.",
      "changelog": ["Test a prompt"],
      "marks": [
        { "page": "/report/aiguard", "at": "#agTestH" }
      ]
    },
    {
      "id": "zwa-incidents-in-depth", "release": "2026-10-31", "label": "Incidents in depth",
      "what": "Incidents in depth on the FP/TP detection ratio page: one Workflow Automation incident's details, triggers, change history and tickets (metadata only), and the Workflow Automation audit log.",
      "changelog": ["Incidents in depth", "Details"],
      "marks": [
        { "page": "/report/health", "at": "#zwaH" }
      ]
    },
    {
      "id": "zwa-close-false-positives", "release": "2026-10-31", "label": "Close as false positives",
      "what": "Close as false positives: close a noisy rule's or destination's open Workflow Automation incidents through Bulk changes, with the typed phrase and your name in each incident's note.",
      "changelog": ["Close as false positives"],
      "marks": [
        { "page": "/report/health", "at": "a.dh-close", "shown": "after the report, on a noisy rule or destination" }
      ]
    }
  ]
};
// ── end of the manifest ──

(function () {
  'use strict';
  if (window.WhatsNew) return;
  const M = window.WHATS_NEW || {};
  const KEY = 'zme_hide_new_marks';
  const DATE = /^\d{4}-\d{2}-\d{2}$/;
  const norm = s => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();

  // ── Which features are marked ───────────────────────────────────────
  // The newest `keep` releases (default 2), newest first: the dates in
  // "releases" and on the features, so a release with nothing to mark still
  // pushes the oldest set out.
  function releases(m) {
    m = m || M;
    const keep = Math.max(1, Number(m.keep) || 2);
    const named = Object.keys(m.releases || {});
    const dates = Array.from(new Set(named.concat((m.features || []).map(f => f && f.release)).filter(d => typeof d === 'string' && DATE.test(d))));
    return dates.sort().reverse().slice(0, keep);
  }
  function active(m) {
    m = m || M;
    const keep = releases(m);
    return (m.features || []).filter(f => f && keep.indexOf(f.release) >= 0 && Array.isArray(f.marks));
  }
  function sentence(f) { return words([f]); }
  // "New in the <date> update: <what>", one line per release, newest first.
  function words(features) {
    const by = {};
    features.forEach(f => { (by[f.release] = by[f.release] || []).push(norm(f.what)); });
    return Object.keys(by).sort().reverse().map(d => `New in the ${d} update: ${by[d].join(' ')}`).join(' ');
  }
  function pageKey() {
    const forced = document.documentElement.getAttribute('data-hh-page');
    if (forced) return forced;
    return (location.pathname || '/').replace(/\/+$/, '') || '/';
  }
  function hidden() {
    try { return window.localStorage.getItem(KEY) === '1'; } catch (e) { return false; }
  }
  function setHidden(on) {
    try { if (on) window.localStorage.setItem(KEY, '1'); else window.localStorage.removeItem(KEY); } catch (e) { /* storage blocked: this page only */ }
    forced = on ? 'hide' : 'show';
    refresh();
  }
  let forced = '';   // the choice made on this page when storage is blocked
  const isHidden = () => (forced ? forced === 'hide' : hidden());

  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function all(sel) {
    try { return Array.from(document.querySelectorAll(sel)); } catch (e) { return []; }
  }

  // ── Saying which item is new ────────────────────────────────────────
  // The items on this page: element → the features it shows.
  function plan() {
    const page = pageKey(), out = new Map();
    active().forEach(f => f.marks.forEach(mk => {
      if (!mk || mk.page !== page || typeof mk.at !== 'string') return;
      all(mk.at).forEach(el => {
        if (el.closest('[data-hh-ui]')) return;
        const list = out.get(el) || [];
        if (list.indexOf(f) < 0) list.push(f);
        out.set(el, list);
      });
    }));
    return out;
  }
  function unmark(el) { el.removeAttribute('data-wn-new'); el.removeAttribute('data-wn-for'); }
  function legendFor() {
    const anchors = (M.legend && (M.legend[pageKey()] || M.legend['*'])) || [];
    for (const sel of anchors) { const a = all(sel)[0]; if (a) return a; }
    return null;
  }
  function placeLegend() {
    const at = legendFor();
    if (!at) return;
    const have = document.querySelector('.wn-legend');
    if (have && have.parentElement === at) return;
    if (have) have.remove();
    const p = make('p', 'wn-legend');
    const star = make('span', 'wn-legend-mark', '*');
    star.setAttribute('aria-hidden', 'true');
    p.append(star, document.createTextNode(' New in this version'));
    if (at.id === 'dbFoot') at.insertBefore(p, at.firstChild); else at.appendChild(p);
  }

  // Take every "new" and the legend off the page.
  function clear() {
    all('.wn-legend').forEach(n => n.remove());
    all('[data-wn-for]').forEach(unmark);
  }
  function apply() {
    if (isHidden()) { clear(); return 0; }
    const want = plan();
    all('[data-wn-for]').forEach(el => { if (!want.has(el)) unmark(el); });
    want.forEach((features, el) => {
      const text = words(features);
      if (el.getAttribute('data-wn-new') !== text) el.setAttribute('data-wn-new', text);
      if (!el.hasAttribute('data-wn-for')) el.setAttribute('data-wn-for', '');
    });
    if (want.size) placeLegend(); else all('.wn-legend').forEach(n => n.remove());
    return want.size;
  }
  let queued = false;
  function soon() {
    if (queued) return;
    queued = true;
    (window.requestAnimationFrame || (f => window.setTimeout(f, 16)))(() => { queued = false; apply(); });
  }
  function refresh() { clear(); apply(); toggle(); }

  // ── "Hide new marks" in Advanced settings (this browser only) ───────
  function toggle() {
    if (pageKey() !== '/report/advanced') return;
    const after = document.getElementById('advGlassNote');
    if (!after) return;
    let box = document.getElementById('advWnHide');
    if (!box) {
      const lead = make('p', 'adv-lead', 'A * after a name marks a feature from the newest two updates. Point at it, or click it, to read what is new. Hide the marks if you do not need them; the choice is kept in this browser only.');
      lead.id = 'advWnLead';
      const lab = make('label', 'adv-switch');
      lab.htmlFor = 'advWnHide';
      box = make('input');
      box.type = 'checkbox';
      box.id = 'advWnHide';
      box.setAttribute('aria-describedby', 'advWnLead');
      box.addEventListener('change', () => setHidden(box.checked));
      lab.append(box, make('span', null, 'Hide new marks'));
      after.insertAdjacentElement('afterend', lead);
      lead.insertAdjacentElement('afterend', lab);
    }
    box.checked = isHidden();
  }

  function start() {
    if (!document.body) { document.addEventListener('DOMContentLoaded', start, { once: true }); return; }
    toggle();
    apply();
    new MutationObserver(soon).observe(document.body, { subtree: true, childList: true });
    window.addEventListener('storage', e => { if (e.key === KEY || e.key === null) { forced = ''; refresh(); } });
  }

  window.WhatsNew = { manifest: M, KEY, releases, active, sentence, words, pageKey, hidden: isHidden, setHidden, apply, clear, refresh };
  start();
})();
