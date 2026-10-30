// ── What's new: a * after the label of each new feature ───────────────
// The manifest below is the one list of what is new. Each feature names the
// CHANGELOG.md release it came in ("release", the heading's date), a short
// plain label, what it is (the words after "New in the <date> update: "),
// the CHANGELOG phrases it covers, and where it shows ("marks": the page,
// the element the * goes after, and the control whose help says it, when
// that is not the element itself or the control around it). "shown" says
// when a mark's element appears later (after a read, in a dialog).
//
// Only the features of the newest two releases are marked ("keep"): add the
// next release to "releases", with its features, and the oldest set stops
// showing (tests/test_new_marks.py checks this list against CHANGELOG.md).
//
// How a mark reads: the * is drawn by CSS (the page's words stay as they
// are) and hidden from screen readers; a control's name gets "(new)" (its
// aria-label, made from its label when it had none, comes back when the mark
// goes), and its help on hover (hover_help.js) opens with "New in the <date>
// update: …".
// A mark on a heading or other text is a small button with that help. The
// legend "* New in this version" goes in the page header (on the home page,
// the sidebar foot). Advanced settings has "Hide new marks", kept in this
// browser only. Every word is set with textContent, never as HTML.
window.WHATS_NEW = {
  "keep": 2,
  "releases": {
    "2026-10-29": "Wave 6: regression and secure-by-design testing, live motion, help on hover, Liquid Glass, a quality score",
    "2026-10-28": "Build, prove and predict: tenant builders, a deeper Path analyzer, readiness, sample tenant, POV planner and a no-install edition"
  },
  "legend": { "/": ["#dbFoot", ".hero"], "*": [".rp-hero"] },
  "features": [
    {
      "id": "build-new", "release": "2026-10-28", "label": "Build new",
      "what": "Build new on Bulk changes: builders for a ZIA security baseline, the SSL certificate manager, ZPA, Client Connector profiles, ZDX probes and AI Guard, with the same preview, write gates, read-back and Undo.",
      "changelog": ["One engine for every builder", "Build new", "ZIA security baseline", "SSL certificate manager", "ZPA builder", "Client Connector profiles", "ZDX probe setup", "AI Guard"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openOperationsTab()\"]" },
        { "page": "/report/operations", "at": "#opBuildKinds > legend" }
      ]
    },
    {
      "id": "zcc-install-builder", "release": "2026-10-28", "label": "Install command builder",
      "what": "The Client Connector install command builder, with a script to run next to the installer.",
      "changelog": ["Client Connector profiles"],
      "marks": [{ "page": "/report/fleet", "at": "#zfInstallH" }]
    },
    {
      "id": "path-one-answer", "release": "2026-10-28", "label": "Path analyzer: one answer for the whole path",
      "what": "The Path analyzer checks ZPA first, then Client Connector, the PAC file (never run) and every ZIA module, each with the rule that decides.",
      "changelog": ["Path analyzer, one answer for everything on the path"],
      "marks": [{ "page": "/", "at": "button[onclick=\"openPathAnalyzerTab()\"]" }]
    },
    {
      "id": "path-any-protocol", "release": "2026-10-28", "label": "Any protocol and port",
      "what": "Every ZIA module on the path, for web traffic or any protocol and port.",
      "changelog": ["Path analyzer, one answer for everything on the path"],
      "marks": [{ "page": "/report/path", "at": "label:has(#paProto) > .lbl", "control": "#paProto" }]
    },
    {
      "id": "path-workload", "release": "2026-10-28", "label": "Traffic from a workload",
      "what": "Traffic from a workload, through Cloud and Branch Connector.",
      "changelog": ["Path analyzer, one answer for everything on the path"],
      "marks": [{ "page": "/report/path", "at": "label:has(#paSource) > .lbl", "control": "#paSource" }]
    },
    {
      "id": "path-whatif", "release": "2026-10-28", "label": "What-if",
      "what": "A what-if for a user, group, department or location.",
      "changelog": ["Path analyzer, one answer for everything on the path"],
      "marks": [{ "page": "/report/path", "at": "#paWhatIf > summary" }]
    },
    {
      "id": "test-a-list", "release": "2026-10-28", "label": "Test a list",
      "what": "Test a list: up to 250,000 destinations, each against what it was expected to do, with Fix selected handing off to Bulk changes.",
      "changelog": ["Test a list"],
      "marks": [{ "page": "/report/path", "at": "#tab-list" }]
    },
    {
      "id": "readiness", "release": "2026-10-28", "label": "Readiness",
      "what": "Readiness after sign-in: what this API client's role and licences allow, and the steps to ask for what will not work.",
      "changelog": ["Readiness after sign-in"],
      "marks": [
        { "page": "/", "at": ".db-item[data-db=\"configure\"]" },
        { "page": "/", "at": "#rdConnect .rd-h", "shown": "after Authenticate" }
      ]
    },
    {
      "id": "sample-tenant", "release": "2026-10-28", "label": "Sample tenant and snapshots",
      "what": "A made-up sample tenant to try every page on, and read-only snapshots of a tenant to open offline or compare with the live one.",
      "changelog": ["Sample tenant and snapshots"],
      "marks": [
        { "page": "/", "at": ".db-item[data-db=\"configure\"]" },
        { "page": "/", "at": "#zoTitle", "shown": "on Connect to the tenant" },
        { "page": "/simple", "at": ".sm-opt:has(> input[name=\"smHow\"][value=\"sample\"]) .sm-ot", "control": "input[name=\"smHow\"][value=\"sample\"]", "shown": "in the Connect task" }
      ]
    },
    {
      "id": "pov-planner", "release": "2026-10-28", "label": "POV planner",
      "what": "The POV planner: intake, success criteria, a runbook, Prove it through the Path analyzer, and a Word or PDF report.",
      "changelog": ["POV planner", "Prove it"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openPovTab()\"]" },
        { "page": "/report/pov", "at": ".rp-hero h1" },
        { "page": "/simple", "at": "#smPovLink" }
      ]
    },
    {
      "id": "zia-framework-export", "release": "2026-10-28", "label": "ZIA policy framework export",
      "what": "Export from tenant can save the ZIA policy framework (URL, firewall, SSL, Sandbox, DNS and File Type Control rules) for the baseline builder to load into another tenant.",
      "changelog": ["ZIA policy framework export"],
      "marks": [
        { "page": "/", "at": "#dlpDeployModal label.dz-chk:has(input[onchange^=\"_dzExportPart('framework'\"])", "control": "#dlpDeployModal input[onchange^=\"_dzExportPart('framework'\"]", "shown": "in Deploy policy packs, Export from tenant" }
      ]
    },
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
        { "page": "/report/advanced", "at": "label[for=\"advGlass\"] > span", "control": "#advGlass" }
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
  const CONTROL = 'button, a[href], input:not([type="hidden"]), select, textarea, summary, [role="button"], [role="tab"], ' +
    '[role="checkbox"], [role="switch"], [role="radio"], [role="menuitem"], [role="option"][tabindex]';
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

  // ── Placing a mark ──────────────────────────────────────────────────
  // The marks on this page: element → {control, features}.
  function plan() {
    const page = pageKey(), out = new Map();
    active().forEach(f => f.marks.forEach(mk => {
      if (!mk || mk.page !== page || typeof mk.at !== 'string') return;
      all(mk.at).forEach(host => {
        if (host.closest('[data-hh-ui]')) return;
        let control = null;
        if (mk.control) control = all(mk.control)[0] || null;
        if (!control) { try { control = host.closest(CONTROL); } catch (e) { control = null; } }
        const rec = out.get(host) || { control, features: [] };
        if (!rec.control) rec.control = control;
        if (rec.features.indexOf(f) < 0) rec.features.push(f);
        out.set(host, rec);
      });
    }));
    return out;
  }
  function placeOne(host, rec) {
    const text = words(rec.features);
    const ids = rec.features.map(f => f.id).join(' ');
    let mark = Array.from(host.children).find(c => c.classList.contains('wn-mark'));
    if (mark && mark.getAttribute('data-wn-ids') === ids) return false;
    if (mark) unmarkHost(host);
    const control = rec.control;
    // The * itself is drawn by CSS (.wn-mark::before), so the words of the
    // label, heading or button (their textContent) stay exactly as they were.
    if (control) {
      // In (or the label of) a control: the * is decoration; the name says "new".
      mark = make('span', 'wn-mark');
      mark.setAttribute('aria-hidden', 'true');
      mark.setAttribute('data-wn-ids', ids);
      host.appendChild(mark);
      if (!control.hasAttribute('data-wn-for')) {
        const had = control.hasAttribute('aria-label');
        const name = had ? norm(control.getAttribute('aria-label')) : nameOf(control);
        if (name && !control.hasAttribute('aria-labelledby')) {
          control.setAttribute('data-wn-aria', had ? control.getAttribute('aria-label') : '');
          if (!had) control.setAttribute('data-wn-noaria', '');
          control.setAttribute('aria-label', name + ' (new)');
        }
        control.setAttribute('data-wn-for', '');
      }
      if (control.getAttribute('data-wn-new') !== text) control.setAttribute('data-wn-new', text);
    } else {
      // On a heading or other words: a small button, so pointer, keyboard
      // and touch can open the help that says what is new.
      mark = make('button', 'wn-mark');
      mark.type = 'button';
      mark.setAttribute('aria-label', 'New in this version');
      mark.setAttribute('data-wn-ids', ids);
      mark.setAttribute('data-wn-new', text);
      mark.addEventListener('click', ev => {
        ev.preventDefault(); ev.stopPropagation();
        const hh = window.HoverHelp;
        if (!hh) return;
        if (hh.current() === mark && hh.tip() && !hh.tip().hidden) hh.hide(); else hh.show(mark);
      });
      host.appendChild(mark);
    }
    return true;
  }
  // The words a control is named by, when it has no aria-label: its labels,
  // or its own text, without what is hidden from screen readers or other fields.
  function textOf(node) {
    let t = '';
    node.childNodes.forEach(n => {
      if (n.nodeType === 3) t += n.nodeValue;
      else if (n.nodeType === 1 && n.getAttribute('aria-hidden') !== 'true' && !n.matches('input, select, textarea, .wn-mark')) t += ' ' + textOf(n);
    });
    return t;
  }
  function nameOf(control) {
    const labels = Array.from(control.labels || []);
    return norm(labels.length ? labels.map(textOf).join(' ') : textOf(control));
  }
  function restore(c) {
    if (c.hasAttribute('data-wn-noaria')) c.removeAttribute('aria-label');
    else if (c.hasAttribute('data-wn-aria')) c.setAttribute('aria-label', c.getAttribute('data-wn-aria'));
    ['data-wn-aria', 'data-wn-noaria', 'data-wn-new', 'data-wn-for'].forEach(a => c.removeAttribute(a));
  }
  function unmarkHost(host) {
    Array.from(host.children).forEach(c => { if (c.classList.contains('wn-mark')) c.remove(); });
  }
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

  // Take every mark, hidden word, name change and legend off the page.
  function clear() {
    all('.wn-mark, .wn-legend').forEach(n => n.remove());
    all('[data-wn-for]').forEach(restore);
  }
  function apply() {
    if (isHidden()) { clear(); return 0; }
    const want = plan();
    // A mark whose element no longer wants it (the page changed): take it off.
    all('.wn-mark').forEach(m => { if (!want.has(m.parentElement)) { const h = m.parentElement; unmarkHost(h); } });
    all('[data-wn-for]').forEach(c => { if (!Array.from(want.values()).some(r => r.control === c)) restore(c); });
    want.forEach((rec, host) => placeOne(host, rec));
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
      const lead = make('p', 'adv-lead', 'A * after a name marks a feature from the newest two updates. Point at it, or focus it, to read what is new. Hide the marks if you do not need them; the choice is kept in this browser only.');
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
