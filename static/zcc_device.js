/* Client Connector fleet page: one device's details and the disable-reason
   counts (zcc_devices.py through /api/zcc/device-details and
   /api/zcc/disable-reasons). Read-only, only with ZCC ticked on the Scope
   page. No user or device name is ever shown; every word from the tenant
   is escaped. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('zfDevice')) return;
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function credBody() {
    const sel = $('zfTenant'); const v = (sel && sel.value) || 'server';
    if (v === 'opener' && window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function') return window.opener.migrateCredBody();
    if (v.startsWith('profile:')) return { profile_id: v.slice(8) };
    return {};
  }
  function readJson(key, fallback) {
    try { const raw = localStorage.getItem(key); const v = raw ? JSON.parse(raw) : fallback; return v == null ? fallback : v; } catch (e) { return fallback; }
  }
  function declared(state) {
    const o = {};
    Object.entries(state || {}).forEach(([id, v]) => { const c = v && typeof v === 'object' ? v.choice : v; if (c === 'zscaler' || c === 'alternative') o[id] = c; });
    return o;
  }
  function scopeSelection() {
    let scopes = null, channels = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (op && typeof op.__dbChannelScope === 'function') channels = declared(op.__dbChannelScope()); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) { const l = readJson('zassess_scopes_live_v1', null); scopes = l && Array.isArray(l.scopes) ? l.scopes : null; }
    if (!Array.isArray(scopes)) return { scopes: [], channels: {}, from_page: false };
    if (!channels) channels = declared(readJson('zassess_channels_v1', {}));
    return { scopes: scopes.map(String), channels, from_page: true };
  }
  async function post(path, extra) {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store',
      body: JSON.stringify(Object.assign({}, credBody(), scopeSelection(), extra || {})) });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error((d && typeof d.detail === 'string' && d.detail) || `HTTP ${r.status}`);
    }
    return r;
  }
  function fail(where, title, msg) {
    where.innerHTML = `<div class="bp-card warn"><div class="t">${E(title)}</div><div>${E(msg)}</div></div>`;
  }

  async function showDevice() {
    const out = $('zfDevOut'), btn = $('zfDevShow'), udid = $('zfDevUdid').value.trim();
    if (!/^[A-Za-z0-9_.:{}-]{1,128}$/.test(udid)) { out.textContent = 'Type the device id (UDID) as the Client Connector Portal shows it.'; $('zfDevUdid').focus(); return; }
    btn.disabled = true; out.textContent = 'Reading the device…';
    try {
      const d = await (await post('/api/zcc/device-details', { udid })).json();
      if (!d.found) { out.textContent = d.error || 'No enrolled device has that id.'; return; }
      out.innerHTML = `<p><strong>${E(d.summary)}</strong></p>
        <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">The device's service state</caption>
        <tbody>${(d.rows || []).map(r => `<tr${r.warn ? ' class="st-warn"' : ''}><th scope="row">${E(r.label)}</th><td>${E(r.value)}${r.warn ? ' <span class="df-chip st-warn">check</span>' : ''}</td></tr>`).join('')}</tbody></table></div>
        <p class="df-hint">${E(d.note || '')}</p>`;
    } catch (e) { fail(out, 'The device could not be read', e.message); }
    finally { btn.disabled = false; }
  }
  $('zfDevShow').addEventListener('click', showDevice);
  $('zfDevUdid').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); showDevice(); } });

  $('zfDisShow').addEventListener('click', async () => {
    const out = $('zfDisOut'), btn = $('zfDisShow');
    btn.disabled = true; out.textContent = 'Reading the disable-reason report…';
    try {
      const d = await (await post('/api/zcc/disable-reasons', { format: 'json' })).json();
      const rows = d.rows || [];
      out.innerHTML = `<p><strong>Switched off ${E(d.events)} time(s) by ${E(d.people)} people.</strong>${d.skipped ? ` ${E(d.skipped)} row(s) could not be read.` : ''}</p>
        ${rows.length ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Times Client Connector was switched off, per reason</caption>
        <thead><tr><th scope="col">Reason</th><th scope="col">Device type</th><th scope="col">Service</th><th scope="col">Times</th><th scope="col">People</th></tr></thead>
        <tbody>${rows.slice(0, 200).map(r => `<tr><th scope="row">${E(r.reason)}</th><td>${E(r.device_type)}</td><td>${E(r.service)}</td><td>${E(r.times)}</td><td>${E(r.people)}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
    } catch (e) { fail(out, 'The disable-reason report could not be read', e.message); }
    finally { btn.disabled = false; }
  });
  $('zfDisCsv').addEventListener('click', async () => {
    const out = $('zfDisOut'), btn = $('zfDisCsv');
    btn.disabled = true; out.textContent = 'Preparing the CSV…';
    try {
      const r = await post('/api/zcc/disable-reasons', { format: 'csv' });
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'zcc_disable_reasons_counts.csv';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      out.textContent = 'Downloaded: counts only, no user or device names.';
    } catch (e) { fail(out, 'The CSV could not be made', e.message); }
    finally { btn.disabled = false; }
  });
})();
