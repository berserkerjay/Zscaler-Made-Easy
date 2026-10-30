// ── Sample tenant and snapshots (Connect page, beside the tenant profiles) ──
// "Try with a sample tenant" uses Larkspur Freight, a made-up company,
// in this browser: every page then reads it instead of a tenant, and its
// changes stay in the server's memory. A snapshot is a read of the live
// tenant (only what is in scope on the Scope page, no credentials) saved
// beside the tenant profile it was read for; "Open" uses it offline and
// read-only, "Compare with the live tenant" reads the tenant again and says
// what changed. The server keeps which one this browser uses (a cookie);
// the safety banner (safety_banner.js) says so on every page and offers
// Leave. Everything is built with DOM calls and textContent: nothing the
// server or a file says is parsed as HTML.
(function () {
  'use strict';
  if (window.zmeOffline) return;
  const S = { status: { mode: 'live' }, busy: false, msg: '', compare: null, host: null, profile: null, unfiled: [] };

  function el(tag, attrs, text) {
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'class') n.className = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : String(v));
    });
    if (text != null) n.textContent = String(text);
    return n;
  }
  function active() { return S.status.mode === 'sample' || S.status.mode === 'snapshot'; }
  function tell() {
    window.ZME_OFFLINE = active() ? S.status : null;
    try { window.dispatchEvent(new CustomEvent('zme:offline', { detail: Object.assign({ from: 'connect' }, S.status) })); } catch (e) { /* old browser */ }
  }
  function say(text) { S.msg = text || ''; const st = document.getElementById('zoStatus'); if (st) st.textContent = S.msg; }
  async function api(url, body) {
    const opts = body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    const r = await fetch(url, opts);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((d && d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
    return d;
  }
  async function refresh() {
    try { S.status = await api('/api/offline/status'); } catch (e) { S.status = { mode: 'live' }; }
    tell(); draw();
  }
  async function loadUnfiled() {
    try { S.unfiled = (await api('/api/tenant-profiles')).unfiled_snapshots || []; } catch (e) { S.unfiled = []; }
  }
  function afterSwitch(d, words) {
    S.status = d; S.compare = null; tell(); say(words); draw();
    if (typeof window.announce === 'function') { try { window.announce(words); } catch (e) { /* optional */ } }
  }

  async function trySample() {
    if (S.busy) return; S.busy = true; draw();
    try { afterSwitch(await api('/api/offline/sample', {}), 'Sample tenant opened. Run the assessment or open any page.'); }
    catch (e) { say(`Could not open the sample tenant: ${e.message}`); }
    S.busy = false; draw();
  }
  async function leave() {
    if (S.busy) return; S.busy = true; draw();
    try { afterSwitch(await api('/api/offline/leave', {}), 'Back to the live tenant.'); }
    catch (e) { say(`Could not leave: ${e.message}`); }
    S.busy = false; draw();
  }
  async function openSaved(id) {
    if (S.busy) return; S.busy = true; draw();
    try { const d = await api(`/api/tenant-profiles/snapshots/${encodeURIComponent(id)}/open`, {}); afterSwitch(d, 'Snapshot opened. Run the assessment or open any page.'); }
    catch (e) { say(`Could not open the snapshot: ${e.message}`); }
    S.busy = false; draw();
  }
  async function openFile(input) {
    const f = input.files && input.files[0]; input.value = '';
    if (!f || S.busy) return;
    if (f.size > 8 * 1024 * 1024) { say('That file is larger than 8 MB, so it is not a snapshot this app saved. Nothing was opened.'); return; }
    S.busy = true; draw();
    try { const text = await f.text(); const d = await api('/api/tenant-profiles/snapshots/open-file', { name: f.name.slice(0, 120), content: text }); afterSwitch(d, 'Snapshot opened. Run the assessment or open any page.'); }
    catch (e) { say(`Could not open the file: ${e.message}`); }
    S.busy = false; draw();
  }
  async function remove(id) {
    if (!confirm('Delete this snapshot? The file is removed from this computer; the tenant is not touched.')) return;
    try { const d = await api(`/api/tenant-profiles/snapshots/${encodeURIComponent(id)}/delete`, {}); if (d.mode === 'live' && active()) await refresh(); say('Snapshot deleted.'); }
    catch (e) { say(`Could not delete it: ${e.message}`); }
    reloadLists();
  }
  function liveBody() {
    // The live tenant's sign-in (the form or the saved profile) and the Scope page's selection.
    const creds = typeof migrateValidateCreds === 'function' ? migrateValidateCreds() : {};
    if (!creds) return null;
    const scope = typeof scopePageSelection === 'function' ? scopePageSelection() : { scopes: [], channels: {}, from_page: true };
    return Object.assign({}, creds, scope);
  }
  async function poll(jobId, what) {
    for (;;) {
      await new Promise(r => setTimeout(r, 700));
      const j = await api(`/api/dlp-packs/jobs/${encodeURIComponent(jobId)}`);
      const last = (j.logs || []).slice(-1)[0];
      if (last) say(`${what}: ${last}`);
      if (j.status !== 'running') return j;
    }
  }
  async function save() {
    if (S.busy) return;
    if (active()) { say('Leave the sample or the snapshot first: a snapshot is a read of your own tenant.'); return; }
    const body = liveBody(); if (!body) return;
    S.busy = true; draw(); say('Saving a snapshot: signing in…');
    try {
      const st = await api('/api/tenant-profiles/snapshots/save/start', body);
      S.job = st.job_id; draw();
      const j = await poll(st.job_id, 'Saving a snapshot');
      if (j.status === 'done' && j.result && j.result.snapshot) {
        const c = j.result.counts || {};
        say(`Snapshot saved: ${c.answers || 0} lists, ${c.objects || 0} objects, no credentials.${(j.result.unread || []).length ? ` ${(j.result.unread || []).length} lists could not be read.` : ''}`);
      } else if (j.status === 'cancelled' || (j.result && j.result.stopped)) say('Stopped. No snapshot was saved.');
      else say(`The snapshot was not saved: ${j.error || j.status}`);
    } catch (e) { say(`The snapshot was not saved: ${e.message}`); }
    S.busy = false; S.job = null; reloadLists();
  }
  async function compareWith(id) {
    if (S.busy) return;
    const body = liveBody(); if (!body) return;
    body.snapshot_id = id;
    S.busy = true; S.compare = null; draw(); say('Comparing with the live tenant: signing in…');
    try {
      const st = await api('/api/tenant-profiles/snapshots/compare/start', body);
      S.job = st.job_id; draw();
      const j = await poll(st.job_id, 'Comparing');
      if (j.status === 'done' && j.result && !j.result.stopped) { S.compare = j.result; say(j.result.same ? 'Nothing changed in the lists both reads hold.' : `Compared ${j.result.compared} lists.`); }
      else if (j.status === 'cancelled' || (j.result && j.result.stopped)) say('Stopped. Nothing was compared.');
      else say(`Could not compare: ${j.error || j.status}`);
    } catch (e) { say(`Could not compare: ${e.message}`); }
    S.busy = false; S.job = null; draw();
  }
  async function stop() {
    if (!S.job) return;
    try { await api(`/api/dlp-packs/jobs/${encodeURIComponent(S.job)}/cancel`, {}); say('Stopping…'); } catch (e) { /* the poll reports it */ }
  }
  function reloadLists() {
    if (typeof _gdProfilesLoad === 'function') { _gdProfilesLoad(); } else { loadUnfiled().then(draw); }
  }

  function snapshotTable(rows, emptyText) {
    if (!rows.length) return el('p', { class: 'gd-need' }, emptyText);
    const t = el('table', { class: 'gd-hist zo-snaps' });
    const cap = el('caption', { class: 'sr-only' }, 'Saved snapshots');
    t.appendChild(cap);
    const head = el('tr');
    ['Saved', 'Read from', 'What it holds', 'Actions'].forEach(h => head.appendChild(el('th', { scope: 'col' }, h)));
    t.appendChild(el('thead')).appendChild(head);
    const tb = el('tbody');
    rows.forEach(r => {
      const tr = el('tr');
      tr.appendChild(el('td', null, r.saved_at ? new Date(r.saved_at).toLocaleString() : '–'));
      tr.appendChild(el('td', null, r.tenant_label || '–'));
      const c = r.counts || {};
      tr.appendChild(el('td', null, `${c.answers || 0} lists, ${c.objects || 0} objects · ${(r.scopes || []).join(', ') || 'no scope'}`));
      const td = el('td', { class: 'zo-actions' });
      const label = `snapshot saved ${r.saved_at || ''}`;
      td.appendChild(el('button', { type: 'button', class: 'gd-btn quiet gd-btn-sm', 'aria-label': `Open ${label}`, onclick: () => openSaved(r.id), disabled: S.busy }, 'Open'));
      td.appendChild(el('button', { type: 'button', class: 'gd-btn quiet gd-btn-sm', 'aria-label': `Compare ${label} with the live tenant`, onclick: () => compareWith(r.id), disabled: S.busy }, 'Compare with the live tenant'));
      td.appendChild(el('a', { class: 'gd-btn quiet gd-btn-sm', href: `/api/tenant-profiles/snapshots/${encodeURIComponent(r.id)}/download`, download: '', 'aria-label': `Download ${label}` }, 'Download'));
      td.appendChild(el('button', { type: 'button', class: 'gd-btn quiet gd-btn-sm', 'aria-label': `Delete ${label}`, onclick: () => remove(r.id), disabled: S.busy }, 'Delete'));
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    const wrap = el('div', { class: 'zo-scroll' });
    wrap.appendChild(t);
    return wrap;
  }
  function compareView(d) {
    const box = el('div', { class: 'zo-compare', role: 'region', 'aria-label': 'Snapshot compared with the live tenant' });
    const t = d.totals || {};
    box.appendChild(el('p', null, d.same
      ? `Compared with ${d.live_label}: the ${d.compared} lists both reads hold are the same.`
      : `Compared with ${d.live_label}: ${t.added || 0} added, ${t.removed || 0} removed, ${t.changed || 0} changed since ${d.snapshot && d.snapshot.saved_at ? new Date(d.snapshot.saved_at).toLocaleString() : 'the snapshot'}.`));
    if (!d.same) {
      const ul = el('ul', { class: 'zo-diff' });
      (d.lists || []).forEach(x => {
        const li = el('li');
        li.appendChild(el('strong', null, x.what + ': '));
        const parts = [];
        if (x.added.length) parts.push(`added ${x.added.join(', ')}`);
        if (x.removed.length) parts.push(`removed ${x.removed.join(', ')}`);
        if (x.changed.length) parts.push(`changed ${x.changed.join(', ')}`);
        li.appendChild(document.createTextNode(parts.join('; ')));
        ul.appendChild(li);
      });
      box.appendChild(ul);
    }
    if ((d.only_in_snapshot || []).length) box.appendChild(el('p', { class: 'gd-need' }, `Not read now (not in scope today, or not readable): ${d.only_in_snapshot.join(', ')}.`));
    if ((d.only_live || []).length) box.appendChild(el('p', { class: 'gd-need' }, `Read now but not in the snapshot: ${d.only_live.join(', ')}.`));
    return box;
  }

  function draw() {
    const host = S.host;
    if (!host || !document.body.contains(host)) return;
    host.textContent = '';
    host.appendChild(el('span', { class: 'gd-eyebrow', id: 'zoTitle' }, 'Sample tenant and snapshots'));
    host.setAttribute('role', 'group'); host.setAttribute('aria-labelledby', 'zoTitle');
    host.appendChild(el('p', { class: 'gd-need' }, 'No tenant at hand? Try the app on a made-up company. A snapshot keeps a copy of a tenant\'s settings (only what is in scope, never a secret) so you can open it offline later or see what changed since.'));
    const row = el('div', { class: 'gd-prof-controls zo-row' });
    if (active()) {
      row.appendChild(el('button', { type: 'button', class: 'gd-btn primary', onclick: leave, disabled: S.busy }, S.status.mode === 'sample' ? 'Leave the sample' : 'Close the snapshot'));
    } else {
      row.appendChild(el('button', { type: 'button', class: 'gd-btn primary', onclick: trySample, disabled: S.busy }, 'Try with a sample tenant'));
      row.appendChild(el('button', { type: 'button', class: 'gd-btn quiet', onclick: save, disabled: S.busy }, 'Save a snapshot'));
    }
    const fileId = 'zoFile';
    const lab = el('label', { class: 'gd-btn quiet zo-file', for: fileId }, 'Open a snapshot file');
    const inp = el('input', { type: 'file', id: fileId, accept: '.json,application/json', class: 'sr-only', onchange: e => openFile(e.target), disabled: S.busy });
    inp.addEventListener('focus', () => lab.classList.add('zo-focus')); inp.addEventListener('blur', () => lab.classList.remove('zo-focus'));
    row.appendChild(inp); row.appendChild(lab);
    if (S.job) row.appendChild(el('button', { type: 'button', class: 'gd-btn quiet', onclick: stop }, 'Stop'));
    host.appendChild(row);
    if (active()) {
      host.appendChild(el('p', { class: 'gd-need' }, S.status.mode === 'sample'
        ? `Using ${S.status.company || 'the sample tenant'}: nothing here is real. Every page reads it; plans and dry runs work here as a rehearsal, and nothing is ever applied to it.`
        : `In use: ${S.status.tenant_label}, offline and read-only. Nothing is read from or sent to a tenant.`));
    }
    host.appendChild(el('p', { id: 'zoStatus', class: 'gd-need', role: 'status', 'aria-live': 'polite' }, S.msg));
    const p = S.profile;
    const rows = p ? (p.snapshots || []) : S.unfiled;
    host.appendChild(el('span', { class: 'lbl' }, p ? `Snapshots of ${p.name}` : 'Snapshots saved without a profile'));
    host.appendChild(snapshotTable(rows, p
      ? 'No snapshot saved for this profile yet. Sign in to the tenant, set the Scope page, then choose Save a snapshot.'
      : 'No snapshot saved without a profile. Pick a profile above to see its snapshots, or save one.'));
    if (S.compare) host.appendChild(compareView(S.compare));
  }

  // Called by the tenant profiles bar (guide.js) each time it is drawn.
  function render(host, profile) {
    S.host = host; S.profile = profile || null;
    if (!profile) loadUnfiled().then(draw);
    draw();
  }

  const CSS = `
.gd-offline { display: grid; gap: var(--sp-2, 8px); padding-top: var(--sp-3, 12px); margin-top: var(--sp-3, 12px); border-top: 1px solid var(--border); }
.gd-offline .zo-row { flex-wrap: wrap; }
.gd-offline .zo-scroll { max-width: 100%; overflow-x: auto; }
.gd-offline .zo-actions { display: flex; flex-wrap: wrap; gap: var(--sp-1, 4px); }
.gd-offline .zo-file { cursor: pointer; }
.gd-offline .zo-file.zo-focus { outline: 2px solid var(--accent); outline-offset: 2px; }
.gd-offline .zo-compare { padding: var(--sp-2, 8px) var(--sp-3, 12px); border: 1px solid var(--border); border-radius: var(--r-md, 10px); background: var(--well); }
.gd-offline .zo-diff { margin: var(--sp-1, 4px) 0; padding-left: 1.2em; overflow-wrap: anywhere; }
`;
  function style() {
    if (document.getElementById('zoStyle')) return;
    const s = document.createElement('style'); s.id = 'zoStyle'; s.textContent = CSS; document.head.appendChild(s);
  }

  window.zmeOffline = { render, refresh, active, status: () => S.status };
  style();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refresh); else refresh();
  window.addEventListener('zme:offline', e => { if (e && e.detail && e.detail.from === 'banner') refresh(); });
})();
