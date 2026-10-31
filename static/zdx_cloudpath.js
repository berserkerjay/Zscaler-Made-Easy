/* ZDX on the Path analyzer page (zdx_insights.py through /api/zdx/*).
   The measured cloud path of a ZDX application, leg by leg, next to the
   predicted path; and a ZDX score analysis (root cause) on one device,
   started only with every write gate (write mode, a writer, the assessor
   and the typed phrase START ANALYSIS) and rate-limited by the server.
   Read-only otherwise. Every word from the tenant is escaped. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('zdxCp')) return;
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const PHRASE = 'START ANALYSIS';
  let analysisId = '';

  // ── credentials and scope, as the rest of the page sends them ───────
  function credBody() {
    const sel = $('paTenant'); const v = (sel && sel.value) || 'server';
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
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((d && (typeof d.detail === 'string' ? d.detail : (d.detail && d.detail.cause))) || `HTTP ${r.status}`);
    return d;
  }
  function host() {
    const v = (($('paDest') || {}).value || '').trim().toLowerCase();
    return v.replace(/^[a-z]+:\/\//, '').split(/[/:?#]/)[0].slice(0, 253);
  }
  function fail(where, title, msg) {
    where.innerHTML = `<div class="bp-card warn"><div class="t">${E(title)}</div><div>${E(msg)}</div></div>`;
  }

  // ── the applications and the cloud path ─────────────────────────────
  $('zdxCpLoad').addEventListener('click', async () => {
    const btn = $('zdxCpLoad'), out = $('zdxCpOut'), sel = $('zdxCpApp');
    btn.disabled = true; out.textContent = 'Reading the ZDX applications…';
    try {
      const d = await post('/api/zdx/cloudpath', { host: host() });
      const apps = d.apps || [];
      sel.innerHTML = apps.length ? apps.map(a => `<option value="${E(a.id)}"${a.id === d.suggested ? ' selected' : ''}>${E(a.name)}${a.score != null ? ` (score ${E(Math.round(a.score))})` : ''}</option>`).join('')
        : '<option value="">ZDX monitored no application in the last day</option>';
      sel.disabled = !apps.length; $('zdxCpShow').disabled = !apps.length; $('zdxRcaStart').disabled = !apps.length;
      out.textContent = d.error ? `The ZDX applications could not all be read: ${d.error}` :
        (d.suggested ? 'The application whose name matches the destination is picked; change it if needed.' : `${apps.length} ZDX application(s). Pick one.`);
    } catch (e) { fail(out, 'The ZDX applications could not be read', e.message); }
    finally { btn.disabled = false; }
  });

  function legRow(l) {
    const warn = (l.loss_pct || 0) > 1 || (l.latency_ms || 0) > 80;
    return `<tr${warn ? ' class="st-warn"' : ''}><th scope="row">${E(l.from)} → ${E(l.to)}</th><td>${E(l.latency_ms != null ? l.latency_ms + ' ms' : '—')}</td>
      <td>${E(l.loss_pct != null ? l.loss_pct + '%' : '—')}</td><td>${E(l.hops != null ? Math.round(l.hops) : '—')}${l.unanswered_hops ? ` (${E(Math.round(l.unanswered_hops))} silent)` : ''}</td>
      <td>${E(l.tunnel || '—')}</td></tr>`;
  }
  $('zdxCpShow').addEventListener('click', async () => {
    const btn = $('zdxCpShow'), out = $('zdxCpOut'), app = $('zdxCpApp').value;
    if (!app) { out.textContent = 'Pick a ZDX application first.'; return; }
    btn.disabled = true; out.textContent = 'Reading the cloud path ZDX measured…';
    try {
      const d = await post('/api/zdx/cloudpath', { app_id: app, host: host() });
      const p = d.path || {};
      if (p.error) { fail(out, 'The cloud path could not be read', p.error); return; }
      const legs = p.legs || [];
      out.innerHTML = `<p class="pa-cp-verdict"><strong>${E(p.verdict || '')}</strong></p>
        ${legs.length ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">The cloud path ZDX measured, leg by leg</caption>
          <thead><tr><th scope="col">Leg</th><th scope="col">Latency</th><th scope="col">Loss</th><th scope="col">Hops</th><th scope="col">Tunnel</th></tr></thead>
          <tbody>${legs.map(legRow).join('')}</tbody></table></div>` : ''}
        <p class="df-hint">${E(p.note || '')} ${E(p.devices_checked != null ? `Devices looked at: ${p.devices_checked}.` : '')}</p>`;
    } catch (e) { fail(out, 'The cloud path could not be read', e.message); }
    finally { btn.disabled = false; }
  });

  // ── the score analysis ──────────────────────────────────────────────
  function rcaBody(extra) {
    return Object.assign({ app_id: $('zdxCpApp').value, assessor: $('zdxRcaWho').value.trim(), confirm: true }, extra || {});
  }
  function showResult(d) {
    const out = $('zdxRcaOut');
    const res = d.result;
    if (d.error) { fail(out, 'The analysis could not be read', d.error); return; }
    const rows = res && typeof res === 'object' ? Object.entries(res).slice(0, 30) : [];
    out.innerHTML = rows.length ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">What ZDX says about the analysis</caption>
      <tbody>${rows.map(([k, v]) => `<tr><th scope="row">${E(k)}</th><td>${E(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`).join('')}</tbody></table></div>`
      : '<p class="df-hint">ZDX has nothing to say about this analysis yet. Read it again in a minute.</p>';
  }
  $('zdxRcaStart').addEventListener('click', async () => {
    const out = $('zdxRcaOut'), btn = $('zdxRcaStart');
    if (!$('zdxCpApp').value) { out.textContent = 'Load the ZDX applications and pick one first.'; return; }
    if ($('zdxRcaPhrase').value.trim().toUpperCase() !== PHRASE) { out.textContent = `Type ${PHRASE} to start the analysis.`; $('zdxRcaPhrase').focus(); return; }
    const dev = $('zdxRcaDev').value.trim();
    if (dev && !/^\d{1,20}$/.test(dev)) { out.textContent = 'A ZDX device id is digits only (or leave it empty).'; $('zdxRcaDev').focus(); return; }
    btn.disabled = true; out.textContent = 'Asking ZDX to start the analysis…';
    try {
      const d = await post('/api/zdx/analysis/start', rcaBody({ device_id: dev, hours: parseInt($('zdxRcaHours').value, 10) || 2, confirm_text: $('zdxRcaPhrase').value }));
      analysisId = d.analysis_id || '';
      $('zdxRcaStatus').disabled = !analysisId; $('zdxRcaStop').disabled = !analysisId;
      out.innerHTML = `<p><strong>Started</strong> on ${E(d.device)} for the last ${E(d.hours)} hour(s). ${E(d.note || '')}</p>`;
      $('zdxRcaPhrase').value = '';
    } catch (e) { fail(out, 'The analysis was not started', e.message); }
    finally { btn.disabled = false; }
  });
  $('zdxRcaStatus').addEventListener('click', async () => {
    if (!analysisId) return;
    const btn = $('zdxRcaStatus'); btn.disabled = true; $('zdxRcaOut').textContent = 'Reading the analysis…';
    try { showResult(await post('/api/zdx/analysis/status', { analysis_id: analysisId })); }
    catch (e) { fail($('zdxRcaOut'), 'The analysis could not be read', e.message); }
    finally { btn.disabled = false; }
  });
  $('zdxRcaStop').addEventListener('click', async () => {
    if (!analysisId) return;
    const btn = $('zdxRcaStop'); btn.disabled = true;
    try {
      await post('/api/zdx/analysis/stop', rcaBody({ analysis_id: analysisId }));
      $('zdxRcaOut').textContent = 'The analysis was stopped.'; analysisId = ''; $('zdxRcaStatus').disabled = true;
    } catch (e) { fail($('zdxRcaOut'), 'The analysis was not stopped', e.message); btn.disabled = false; }
  });
})();
