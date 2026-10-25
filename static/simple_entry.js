// ── Simple mode, from the assessment page ─────────────────────────────
// Injected into the assessment page (GUI_ADDONS). Two jobs:
//   1. A one-line, dismissible banner "New here? Try Simple mode" for a
//      first-time visitor (no saved choice in localStorage 'zsimple_mode');
//      after a hand-off from Simple mode, the same line offers the way back.
//   2. The deep links Simple mode hands work to (/?simple=...): the page's
//      own flows open exactly as their toolbar buttons open them, so write
//      mode, the preview and every confirmation stay theirs:
//        connect          → the Connect to the tenant step
//        deploy&pack=ID   → Deploy policy packs with that pack picked
//        fix&check=ID     → Review & remediate's wizard for that check
//        finding&check=ID → the finding in the restored results
// Everything is set with textContent; nothing from the URL is parsed as HTML.
(function () {
  if (window.__simpleEntry || (location.pathname.replace(/\/+$/, '') || '/') !== '/') return;
  window.__simpleEntry = true;
  const KEY = 'zsimple_mode';
  function saved() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function save(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* storage blocked */ } }
  const params = new URLSearchParams(location.search);
  const action = params.get('simple') || '';

  const CSS = `
#simpleBanner { display: flex; flex-wrap: wrap; align-items: center; gap: var(--sp-2) var(--sp-3); margin: 0 0 var(--sp-4);
  padding: var(--sp-2) var(--sp-4); border: 1px solid var(--border); border-left: 4px solid var(--accent);
  border-radius: var(--r-lg); background: var(--card); color: var(--text); font-size: var(--fs-callout); }
#simpleBanner .sbn-t { flex: 1 1 14rem; min-width: 0; }
#simpleBanner .sbn-t strong { font-weight: 700; }
#simpleBanner button, #simpleBanner a.sbn-go { min-height: var(--ctl-lg); padding: 0 var(--sp-4); border-radius: var(--r-md); font: inherit; font-weight: 600;
  cursor: pointer; border: 1px solid var(--border-strong); background: transparent; color: var(--text); display: inline-flex; align-items: center; text-decoration: none; }
#simpleBanner a.sbn-go { background: var(--btn); border-color: transparent; color: white; }
#simpleBanner button:focus-visible, #simpleBanner a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (max-width: 480px) { #simpleBanner button, #simpleBanner a.sbn-go { flex: 1 1 auto; justify-content: center; } }
@media print { #simpleBanner { display: none; } }`;

  function banner(text, goLabel, dismissLabel) {
    if (document.getElementById('simpleBanner')) return;
    const host = document.querySelector('.container');
    if (!host) return;
    if (!document.getElementById('simpleBannerStyle')) { const s = document.createElement('style'); s.id = 'simpleBannerStyle'; s.textContent = CSS; document.head.appendChild(s); }
    const el = document.createElement('div');
    el.id = 'simpleBanner'; el.setAttribute('role', 'region'); el.setAttribute('aria-label', 'Simple mode');
    const t = document.createElement('span'); t.className = 'sbn-t';
    const strong = document.createElement('strong'); strong.textContent = text; t.appendChild(strong);
    el.appendChild(t);
    const go = document.createElement('a'); go.className = 'sbn-go'; go.href = '/simple'; go.textContent = goLabel;
    go.addEventListener('click', () => save('simple'));
    el.appendChild(go);
    const no = document.createElement('button'); no.type = 'button'; no.className = 'sbn-no'; no.textContent = dismissLabel;
    no.setAttribute('aria-label', 'Dismiss: stay in expert mode');
    no.addEventListener('click', () => { save('expert'); el.remove(); const h = document.querySelector('#main-content, main, h1'); if (h && h.focus) { try { h.focus(); } catch (e) { /* ignore */ } } });
    el.appendChild(no);
    host.insertBefore(el, host.firstChild);
  }

  function whenReady(fn, delay) {
    const run = () => setTimeout(fn, delay || 0);
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
  }
  function cleanUrl() {
    try { history.replaceState(null, '', location.pathname + location.hash); } catch (e) { /* ignore */ }
  }

  // ── The deep links ──────────────────────────────────────────────
  async function deepLink() {
    const check = params.get('check') || '';
    const pack = params.get('pack') || '';
    cleanUrl();
    if (action === 'connect') {
      if (typeof _gdGoConfig === 'function') _gdGoConfig();
      else if (typeof _stepGo === 'function') _stepGo('configure');
    } else if (action === 'deploy') {
      if (typeof openDlpPacksModal !== 'function') return;
      await openDlpPacksModal();
      if (pack && typeof DZ !== 'undefined' && Array.isArray(DZ.packs) && DZ.packs.some(p => p.id === pack)) {
        DZ.selected = new Set([pack]);
        if (typeof _dzRender === 'function') _dzRender();
      }
    } else if (action === 'fix' && check) {
      if (typeof openRemediationWizard === 'function') openRemediationWizard(encodeURIComponent(check));
    } else if (action === 'finding' && check) {
      const ids = [...document.querySelectorAll('#checksList .check-id')];
      const hit = ids.find(el => el.textContent.trim() === `[${check}]`);
      const row = hit && hit.closest('.check-item');
      if (row) {
        row.setAttribute('tabindex', '-1');
        row.scrollIntoView({ block: 'center' });
        try { row.focus(); } catch (e) { /* ignore */ }
      }
    }
  }

  whenReady(() => {
    if (action) {
      banner('You came here from Simple mode.', 'Back to Simple mode', 'Stay here');
      setTimeout(deepLink, action === 'finding' ? 900 : 300);
    } else if (!saved()) {
      banner('New here? Try Simple mode: big tasks in plain words, one step at a time.', 'Try Simple mode', 'No thanks');
    }
  }, 50);
})();
