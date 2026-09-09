// ── Tools open in their own tab ─────────────────────────────────────
// Every report / tool dialog (Zscaler Updates, Best Practices, DLP
// Efficacy, ZCC diagnostics, Required API Access) opens in a new browser
// tab with a link back to the assessment, instead of a dialog that has to
// fight the page for space. The tool itself still runs in this page: the
// dialog is kept hidden and its content is mirrored into the tab whenever
// it changes; clicks in the tab are forwarded to the real buttons here
// and typed values flow back. (The Bypass report has its own server-side
// tab, see openBypassReportTab.)

const TOOL_TABS = {
  updates:       { title: 'Zscaler Update Check',   open: 'openUpdateModal',        modal: 'updateModal' },
  bestpractices: { title: 'Best Practices',         open: 'openBestPracticesModal', modal: 'bestPracticesModal' },
  efficacy:      { title: 'DLP Efficacy',           open: 'openDlpEfficacyModal',   modal: 'dlpEffModal' },
  zcc:           { title: 'ZCC Endpoint Diagnostics', open: 'diagnoseZcc',          modal: 'zccDiagModal' },
  permissions:   { title: 'Required API Access',    open: 'openPermissionsModal',   modal: 'permissionsModal' },
  terraform:     { title: 'Terraform hand-off',     open: 'openTerraformModal',     modal: 'terraformModal' },
};
const _TT = {};   // kind -> { win, panel, observer, timer }

function _ttPanel(kind) {
  const modal = document.getElementById(TOOL_TABS[kind].modal);
  return modal ? modal.firstElementChild : null;
}
function _ttInputs(panel) {
  return Array.from(panel.querySelectorAll('input, textarea, select')).map(el => ({ value: el.value, checked: el.checked }));
}
function _ttSync(kind) {
  const t = _TT[kind];
  if (!t || !t.win || t.win.closed) return _ttStop(kind);
  const panel = _ttPanel(kind);
  if (!panel) return;
  try {
    if (typeof t.win.__ttApply !== 'function') return;   // tab not ready yet
    t.win.__ttApply(panel.innerHTML, _ttInputs(panel));
  } catch (e) { /* cross-tab hiccup; next mutation retries */ }
}
function _ttStop(kind) {
  const t = _TT[kind];
  if (!t) return;
  if (t.observer) t.observer.disconnect();
  clearInterval(t.poll);
  delete _TT[kind];
}
function _ttHideModal(kind) {
  const modal = document.getElementById(TOOL_TABS[kind].modal);
  if (modal) modal.style.display = 'none';
  document.body.style.overflow = '';
}

async function openToolTab(kind, arg) {
  const spec = TOOL_TABS[kind];
  if (!spec || typeof window[spec.open] !== 'function') return;
  // Open the tab inside the click (popup blockers allow that), then run the tool here.
  const win = window.open(`/report/view?tool=${encodeURIComponent(kind)}`, '_blank');
  if (!win) { window[spec.open](arg); return; }   // blocked: fall back to the dialog
  _ttStop(kind);
  const p = window[spec.open](arg);
  const modal = document.getElementById(spec.modal);
  if (!modal) { win.close(); return; }          // the tool refused to start (missing credentials, for example)
  _ttHideModal(kind);
  const t = _TT[kind] = { win, observer: null, timer: null, poll: null };
  const panel = _ttPanel(kind);
  // Wait for the tab to load, then push styles, title and content; keep it in sync.
  const styleEl = document.querySelector('style');
  const ready = () => {
    try {
      if (!win.document || !win.document.getElementById('rpBody') || typeof win.__ttApply !== 'function') return false;
      win.document.title = `${spec.title} — Zscaler Assessment`;
      win.document.getElementById('rpTitle').textContent = spec.title;
      win.document.getElementById('appStyle').textContent = styleEl ? styleEl.textContent : '';
      win.document.body.className = 'tool-tab ' + (document.body.classList.contains('theme-light') ? 'theme-light' : '');
      return true;
    } catch (e) { return false; }
  };
  t.poll = setInterval(() => {
    if (win.closed) return _ttStop(kind);
    if (ready()) { clearInterval(t.poll); t.poll = null; _ttSync(kind); }
  }, 120);
  if (panel) {
    t.observer = new MutationObserver(() => { clearTimeout(t.timer); t.timer = setTimeout(() => _ttSync(kind), 80); });
    t.observer.observe(panel, { subtree: true, childList: true, characterData: true, attributes: true });
  }
  if (p && typeof p.then === 'function') { try { await p; } catch (e) { /* the dialog shows the error */ } _ttHideModal(kind); _ttSync(kind); }
}

// Called from the tab.
window.__toolTabClick = function (kind, idx) {
  const panel = _ttPanel(kind);
  if (!panel) return;
  const el = panel.querySelectorAll('[onclick]')[idx];
  if (el) { el.click(); setTimeout(() => { _ttHideModal(kind); _ttSync(kind); }, 50); }
};
window.__toolTabInput = function (kind, idx, value, checked) {
  const panel = _ttPanel(kind);
  if (!panel) return;
  const el = panel.querySelectorAll('input, textarea, select')[idx];
  if (!el) return;
  if (el.type === 'checkbox' || el.type === 'radio') el.checked = !!checked; else el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
};
