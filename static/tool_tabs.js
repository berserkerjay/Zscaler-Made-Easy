// ── Tools open in their own tab ─────────────────────────────────────
// Every report / tool dialog (Zscaler updates, Best practices, DLP
// Efficacy, ZCC diagnostics, Required API access, Terraform hand-off) and
// the assessment results open in a new browser tab with a link back to
// the assessment, instead of a dialog that has to fight the page for
// space. The tool itself still runs in this page: the dialog is kept
// hidden and its content is mirrored into the tab whenever it changes;
// clicks in the tab are forwarded to the real buttons here and typed
// values flow back. (The Bypass and SSL flow reports have their own
// server-side tabs, see openBypassReportTab / openSslFlowTab.)
//
// A spec either names a dialog (`modal`, mirrored from its first child and
// hidden here) or a list of page `panels` (mirrored in order, only the
// visible ones, and left visible on this page — the assessment results).

const TOOL_TABS = {
  updates:       { title: 'Zscaler update check',   open: 'openUpdateModal',        modal: 'updateModal' },
  // `stop` ends what the tool keeps running while its dialog is open (here
  // the 30 s re-fetch, which only closeBestPracticesModal cleared): called
  // when its tab is closed, and before the tool is opened in a tab again.
  bestpractices: { title: 'Best practices',         open: 'openBestPracticesModal', modal: 'bestPracticesModal',
                   stop: () => { if (typeof _bestPracticesPoll !== 'undefined' && _bestPracticesPoll) { clearInterval(_bestPracticesPoll); _bestPracticesPoll = null; } } },
  efficacy:      { title: 'DLP efficacy',           open: 'openDlpEfficacyModal',   modal: 'dlpEffModal' },
  zcc:           { title: 'ZCC endpoint diagnostics', open: 'diagnoseZcc',          modal: 'zccDiagModal' },
  permissions:   { title: 'Required API access',    open: 'openPermissionsModal',   modal: 'permissionsModal' },
  terraform:     { title: 'Terraform hand-off',     open: 'openTerraformModal',     modal: 'terraformModal' },
  // dbHero (added by dashboard.js) is the score-hero card: moved out of
  // #results so it stays on screen before a run, so it has to be named
  // here explicitly or the mirrored tab loses the rings and pillars.
  results:       { title: 'Assessment results',     open: '_openResultsPanel',      panels: ['dbHero', 'progressCard', 'results'], keep: true },
};
const _TT = {};   // kind -> { win, observers, timer, poll, watch }

function _ttE(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function _ttVisible(el) { return !!el && getComputedStyle(el).display !== 'none'; }
// The elements mirrored into the tab, in order. Dialogs: the panel inside
// the overlay. Page panels: each element, but only while it is shown.
function _ttPanels(kind, all) {
  const spec = TOOL_TABS[kind];
  if (spec.panels) {
    const els = spec.panels.map(id => document.getElementById(id)).filter(Boolean);
    return all ? els : els.filter(_ttVisible);
  }
  const modal = document.getElementById(spec.modal);
  return modal && modal.firstElementChild ? [modal.firstElementChild] : [];
}
function _ttInputs(panels) {
  const out = [];
  for (const p of panels) for (const el of p.querySelectorAll('input, textarea, select')) out.push({ value: el.value, checked: el.checked });
  return out;
}
function _ttClickables(panels) {
  const out = [];
  for (const p of panels) out.push(...p.querySelectorAll('[onclick]'));
  return out;
}
function _ttSync(kind) {
  const t = _TT[kind];
  if (!t || !t.win || t.win.closed) return _ttStop(kind);
  const panels = _ttPanels(kind);
  if (!panels.length) return;   // nothing shown yet (assessment not started): the tab keeps its waiting note
  try {
    if (typeof t.win.__ttApply !== 'function') return;   // tab not ready yet
    t.win.__ttApply(panels.map(p => p.innerHTML).join(''), _ttInputs(panels));
  } catch (e) { /* cross-tab hiccup; next mutation retries */ }
}
function _ttStop(kind) {
  const t = _TT[kind];
  if (!t) return;
  for (const o of t.observers || []) o.disconnect();
  clearInterval(t.poll); clearInterval(t.watch); clearTimeout(t.timer);
  delete _TT[kind];
  const spec = TOOL_TABS[kind];
  if (spec && typeof spec.stop === 'function') { try { spec.stop(); } catch (e) { /* best effort */ } }
}
function _ttHideModal(kind) {
  const spec = TOOL_TABS[kind];
  if (spec.keep) return;
  const modal = document.getElementById(spec.modal);
  if (modal) modal.style.display = 'none';
  document.body.style.overflow = '';
}

async function openToolTab(kind, arg) {
  const spec = TOOL_TABS[kind];
  if (!spec || typeof window[spec.open] !== 'function') return;
  // Open the tab inside the click (popup blockers allow that), then run the tool here.
  const win = window.open(`/report/view?tool=${encodeURIComponent(kind)}`, '_blank');
  if (!win) { window[spec.open](arg); return; }   // blocked: fall back to the dialog / the page
  _ttStop(kind);
  const p = window[spec.open](arg);
  if (p === false) { win.close(); return; }       // the tool refused to start (missing credentials, for example)
  const panels = _ttPanels(kind, true);
  if (!panels.length) { win.close(); return; }
  _ttHideModal(kind);
  const t = _TT[kind] = { win, observers: [], timer: null, poll: null, watch: null };
  // Wait for the tab to load, then push styles, title and content; keep it in sync.
  const styleEl = document.querySelector('style');
  const ready = () => {
    try {
      if (!win.document || !win.document.getElementById('rpBody') || typeof win.__ttApply !== 'function') return false;
      win.document.title = `${spec.title} — Zscaler Assessment`;
      const h = win.document.getElementById('rpTitle');
      const words = spec.title.split(' ');
      h.innerHTML = `<span class="accent">${_ttE(words[0])}</span> ${_ttE(words.slice(1).join(' '))}`;
      // The tab links /app.css itself; the copy is a fallback for old tabs.
      const st = win.document.getElementById('appStyle');
      if (st && !st.textContent && !win.document.querySelector('link[href="/app.css"]')) st.textContent = styleEl ? styleEl.textContent : '';
      win.document.body.classList.toggle('theme-light', document.body.classList.contains('theme-light'));
      return true;
    } catch (e) { return false; }
  };
  t.poll = setInterval(() => {
    if (win.closed) return _ttStop(kind);
    if (ready()) {
      clearInterval(t.poll); t.poll = null; _ttSync(kind);
      // A closed tab is noticed even when the tool's content never changes
      // again (no mutation, so no _ttSync), and whatever it runs is stopped.
      t.watch = setInterval(() => { if (win.closed) _ttStop(kind); }, 1000);
    }
  }, 120);
  for (const panel of panels) {
    const o = new MutationObserver(() => { clearTimeout(t.timer); t.timer = setTimeout(() => _ttSync(kind), 80); });
    o.observe(panel, { subtree: true, childList: true, characterData: true, attributes: true });
    t.observers.push(o);
  }
  if (p && typeof p.then === 'function') { try { await p; } catch (e) { /* the dialog shows the error */ } _ttHideModal(kind); _ttSync(kind); }
}

// Assessment results in their own tab. 'run' starts the assessment from
// here (the tab mirrors the progress card, then the results); 'view'
// shows results that already exist. Returns false when nothing is shown,
// so the tab is closed again.
window._openResultsPanel = function (mode) {
  const results = document.getElementById('results');
  const progress = document.getElementById('progressCard');
  if (mode === 'run') {
    if (typeof runAssessment !== 'function') return false;
    runAssessment();
    const btn = document.getElementById('runBtn');
    return !!(btn && btn.disabled);   // the run only starts after the credential and scope checks
  }
  return _ttVisible(results) || _ttVisible(progress);
};

// Called from the tab.
window.__toolTabClick = function (kind, idx) {
  const el = _ttClickables(_ttPanels(kind))[idx];
  if (el) { el.click(); setTimeout(() => { _ttHideModal(kind); _ttSync(kind); }, 50); }
};
window.__toolTabInput = function (kind, idx, value, checked) {
  const els = [];
  for (const p of _ttPanels(kind)) els.push(...p.querySelectorAll('input, textarea, select'));
  const el = els[idx];
  if (!el) return;
  if (el.type === 'checkbox' || el.type === 'radio') el.checked = !!checked; else el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
};
