// ── Safety banner ─────────────────────────────────────────────────────
// A persistent warning at the top of every page of the app while this
// server is in a riskier state than its default:
//   - write mode is on (/api/write-mode → enabled): the app can change the
//     Zscaler tenant. The banner offers "Back to read-only", which turns
//     write mode off through the same API Deploy Studio uses;
//   - the UI token gate is off (/api/auth/status → required: false,
//     i.e. ZSCALER_UI_AUTH=0): anyone who can reach the address can use it;
//   - this browser uses the sample tenant or an offline snapshot
//     (/api/offline/status → mode sample / snapshot): nothing on the page is
//     the live tenant. The banner offers "Leave", which goes back to it.
// The banner sits in the page flow (first child of <body>), so it pushes the
// page down instead of covering it. It is refreshed on load, when write mode
// changes in this tab (the "dlp:write-mode" event Deploy Studio fires), when
// another tab says so (localStorage "dlp_write_mode_ping"), when the tab
// becomes visible again, and every 60 seconds. Everything it shows is set
// with textContent, never as HTML, so nothing from the server is parsed.
(function () {
  if (window.dlpSafetyBanner) return;
  const POLL_MS = 60000;
  const PING_KEY = 'dlp_write_mode_ping';
  const ID = 'dlpSafetyBanner';
  const CSS = `
#dlpSafetyBanner { display: grid; gap: 1px; background: var(--warn, #ff9f0a); border-bottom: 1px solid var(--warn, #ff9f0a); font-family: var(--font, system-ui, sans-serif); font-size: var(--fs-subhead, 0.8125rem); line-height: 1.45; color: var(--text, #fff); }
#dlpSafetyBanner[hidden] { display: none; }
#dlpSafetyBanner .sb-row { display: flex; align-items: center; flex-wrap: wrap; gap: var(--sp-2, 8px) var(--sp-3, 12px); padding: var(--sp-2, 8px) var(--sp-4, 16px); background: color-mix(in srgb, var(--warn, #ff9f0a) 16%, var(--card-solid, var(--card, #1c1c1e))); border-left: 4px solid var(--warn, #ff9f0a); }
#dlpSafetyBanner .sb-row[hidden] { display: none; }
#dlpSafetyBanner .sb-ic { color: var(--warn, #ff9f0a); font-weight: 800; flex: none; }
#dlpSafetyBanner .sb-text { flex: 1 1 18rem; min-width: 0; overflow-wrap: anywhere; }
#dlpSafetyBanner .sb-text strong { font-weight: 700; }
#dlpSafetyBanner .sb-how { color: var(--dim, #98989f); }
#dlpSafetyBanner code { font-family: var(--mono, monospace); font-size: 0.95em; }
#dlpSafetyBanner .sb-btn { flex: none; min-height: var(--ctl-sm, 28px); padding: 0 var(--sp-3, 12px); border-radius: var(--r-md, 10px); border: 1px solid var(--warn, #ff9f0a); background: var(--card-solid, var(--card, #1c1c1e)); color: var(--text, #fff); font: inherit; font-weight: 600; cursor: pointer; }
#dlpSafetyBanner .sb-btn:hover { background: var(--well, #2c2c2e); }
#dlpSafetyBanner .sb-btn:focus-visible { outline: 2px solid var(--accent, #0a84ff); outline-offset: 2px; }
#dlpSafetyBanner .sb-btn[disabled] { opacity: 0.6; cursor: progress; }
#dlpSafetyBanner .sb-msg { flex-basis: 100%; color: var(--fail, #ff453a); font-weight: 600; }
#dlpSafetyBanner .sb-msg:empty { display: none; }
/* The assessment page's sidebar is fixed on the left: keep the banner beside it, not under it. */
body.db-layout #dlpSafetyBanner { margin-left: var(--db-w, 264px); }
@media (max-width: 1000px) {
  body.db-layout #dlpSafetyBanner { margin-left: 0; }
  body.db-layout #dlpSafetyBanner .sb-row { padding-left: 7.5rem; }   /* clear of the fixed Menu button */
}
@media (max-width: 480px) {
  #dlpSafetyBanner .sb-row, body.db-layout #dlpSafetyBanner .sb-row { padding-left: var(--sp-3, 12px); padding-right: var(--sp-3, 12px); }
  body.db-layout #dlpSafetyBanner { padding-top: 3.25rem; background: var(--card-solid, var(--card, #1c1c1e)); }   /* the Menu button sits above the rows */
  #dlpSafetyBanner .sb-btn { width: 100%; min-height: var(--ctl-md, 36px); }
}
@media print { #dlpSafetyBanner { display: none !important; } }
`;
  const state = { write: null, auth: null, offline: null, busy: false, lastEnabled: null };
  let el = null;

  function node(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    return n;
  }

  function build() {
    if (el && document.body.contains(el)) return el;
    if (!document.getElementById('dlpSafetyBannerStyle')) {
      const s = node('style'); s.id = 'dlpSafetyBannerStyle'; s.textContent = CSS; document.head.appendChild(s);
    }
    el = node('div'); el.id = ID; el.hidden = true;
    el.setAttribute('role', 'region'); el.setAttribute('aria-label', 'Safety warnings for this server');

    const w = node('div', 'sb-row sb-write'); w.hidden = true;
    w.appendChild(node('span', 'sb-ic', '!')).setAttribute('aria-hidden', 'true');
    const wt = node('span', 'sb-text');
    wt.appendChild(node('strong', null, 'Write mode is on: this app can change your Zscaler tenant.'));
    wt.appendChild(document.createTextNode(' '));
    wt.appendChild(node('span', 'sb-how sb-write-how'));
    w.appendChild(wt);
    const btn = node('button', 'sb-btn', 'Back to read-only'); btn.type = 'button';
    btn.addEventListener('click', backToReadOnly);
    w.appendChild(btn);
    w.appendChild(node('span', 'sb-msg')).setAttribute('role', 'alert');

    const g = node('div', 'sb-row sb-gate'); g.hidden = true;
    g.appendChild(node('span', 'sb-ic', '!')).setAttribute('aria-hidden', 'true');
    const gt = node('span', 'sb-text');
    gt.appendChild(node('strong', null, 'The UI token gate is off: anyone who can reach this address can use the app.'));
    gt.appendChild(document.createTextNode(' '));
    const how = node('span', 'sb-how');
    how.appendChild(document.createTextNode('To turn it back on, remove '));
    how.appendChild(node('code', null, 'ZSCALER_UI_AUTH=0'));
    how.appendChild(document.createTextNode(' (or set '));
    how.appendChild(node('code', null, 'ZSCALER_UI_AUTH=1'));
    how.appendChild(document.createTextNode(') where the app is started, and restart it.'));
    gt.appendChild(how);
    g.appendChild(gt);

    const o = node('div', 'sb-row sb-offline'); o.hidden = true;
    o.appendChild(node('span', 'sb-ic', '!')).setAttribute('aria-hidden', 'true');
    const ot = node('span', 'sb-text');
    ot.appendChild(node('strong', 'sb-offline-head'));
    ot.appendChild(document.createTextNode(' '));
    ot.appendChild(node('span', 'sb-how sb-offline-how'));
    o.appendChild(ot);
    const leave = node('button', 'sb-btn sb-leave', 'Leave'); leave.type = 'button';
    leave.addEventListener('click', leaveOffline);
    o.appendChild(leave);
    o.appendChild(node('span', 'sb-msg sb-offline-msg')).setAttribute('role', 'alert');

    el.appendChild(o); el.appendChild(w); el.appendChild(g);
    document.body.insertBefore(el, document.body.firstChild);
    return el;
  }

  function render() {
    const b = build();
    const w = state.write, a = state.auth;
    const writeOn = !!(w && w.enabled);
    const gateOff = !!(a && a.required === false);
    const wr = b.querySelector('.sb-write'), gr = b.querySelector('.sb-gate');
    const off = state.offline, offOn = !!(off && (off.mode === 'sample' || off.mode === 'snapshot' || off.mode === 'gone'));
    const or_ = b.querySelector('.sb-offline');
    or_.hidden = !offOn;
    if (offOn) {
      const sample = off.mode === 'sample', gone = off.mode === 'gone';
      or_.querySelector('.sb-offline-head').textContent = sample ? 'Sample tenant: nothing here is real.'
        : gone ? 'The sample or snapshot this page used is closed.' : 'Offline snapshot: nothing here is live.';
      or_.querySelector('.sb-offline-how').textContent = sample
        ? `${off.company || 'A made-up company'} is invented. Changes stay in this app's memory and never reach a tenant.`
        : gone ? 'Leave to use the live tenant, or open the sample or the snapshot again.'
        : `${off.tenant_label || 'A saved tenant read'}${off.saved_at ? `, read ${String(off.saved_at).slice(0, 16).replace('T', ' ')} UTC` : ''}. Nothing is read from or sent to a tenant; it is read-only.`;
      or_.querySelector('.sb-leave').textContent = sample ? 'Leave the sample' : gone ? 'Leave' : 'Close the snapshot';
    }
    wr.hidden = !writeOn;
    gr.hidden = !gateOff;
    if (writeOn) {
      wr.querySelector('.sb-write-how').textContent = w.source === 'environment'
        ? 'It was set at start (ENABLE_WRITE_ACTIONS), so it comes back on when the server restarts unless that setting is removed.'
        : 'It applies to every browser using this server until you switch back or the server restarts.';
    }
    b.hidden = !(writeOn || gateOff || offOn);
  }

  async function getJson(url) {
    try {
      const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
      return r.ok ? await r.json() : null;
    } catch (e) { return null; }
  }

  function tellOthers(status) {
    try { window.dispatchEvent(new CustomEvent('dlp:write-mode', { detail: { from: 'banner', status } })); } catch (e) { /* old browser */ }
  }
  function pingOtherTabs() {
    try { localStorage.setItem(PING_KEY, String(Date.now())); } catch (e) { /* private mode */ }
  }

  async function refresh() {
    const auth = await getJson('/api/auth/status');
    if (auth) state.auth = auth;
    // Only ask for write mode when this browser may: a locked page must not
    // pop the unlock dialog every minute just for the banner.
    if (auth && (!auth.required || auth.unlocked)) {
      const w = await getJson('/api/write-mode');
      if (w) {
        const changed = state.lastEnabled !== null && state.lastEnabled !== !!w.enabled;
        state.write = w; state.lastEnabled = !!w.enabled;
        if (changed) tellOthers(w);   // e.g. another tab switched it: Deploy Studio re-reads its own copy
      }
      const off = await getJson('/api/offline/status');
      if (off) state.offline = off;
    }
    if (document.body) render();
  }

  async function backToReadOnly() {
    if (state.busy) return;
    const b = build();
    const btn = b.querySelector('.sb-btn'), msg = b.querySelector('.sb-msg');
    state.busy = true; btn.disabled = true; msg.textContent = '';
    try {
      const r = await fetch('/api/write-mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enable: false, confirm: '' }) });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((data && data.detail && (data.detail.cause || data.detail)) || ('HTTP ' + r.status));
      state.write = data; state.lastEnabled = !!data.enabled;
      render();
      tellOthers(data); pingOtherTabs();
      if (typeof window.announce === 'function') { try { window.announce('Read-only mode.'); } catch (e) { /* optional */ } }
    } catch (e) {
      msg.textContent = 'Could not switch back to read-only: ' + String((e && e.message) || e);
    } finally {
      state.busy = false; btn.disabled = false;
    }
  }

  // Back to the live tenant in this browser, then reload: what the page
  // shows came from the sample or the snapshot.
  async function leaveOffline() {
    if (state.busy) return;
    const b = build();
    const btn = b.querySelector('.sb-leave'), msg = b.querySelector('.sb-offline-msg');
    state.busy = true; btn.disabled = true; msg.textContent = '';
    try {
      const r = await fetch('/api/offline/leave', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      state.offline = { mode: 'live' };
      render();
      pingOtherTabs();
      try { window.dispatchEvent(new CustomEvent('zme:offline', { detail: Object.assign({ from: 'banner' }, state.offline) })); } catch (e) { /* old browser */ }
      location.reload();
    } catch (e) {
      msg.textContent = 'Could not leave: ' + String((e && e.message) || e);
    } finally {
      state.busy = false; btn.disabled = false;
    }
  }
  // The Connect page opened or left the sample or a snapshot in this tab.
  window.addEventListener('zme:offline', e => { if (e && e.detail && e.detail.from !== 'banner') refresh(); });

  // Deploy Studio (or anything else) changed write mode in this tab.
  window.addEventListener('dlp:write-mode', e => {
    const d = (e && e.detail) || {};
    if (d.from === 'banner') return;
    if (d.status && typeof d.status === 'object') { state.write = d.status; state.lastEnabled = !!d.status.enabled; if (document.body) render(); }
    else refresh();
    pingOtherTabs();
  });
  // Another tab changed it.
  window.addEventListener('storage', e => { if (e.key === PING_KEY) refresh(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);

  window.dlpSafetyBanner = { refresh };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refresh);
  else refresh();
})();
