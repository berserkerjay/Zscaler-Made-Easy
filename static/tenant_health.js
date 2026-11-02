/* Tenant health on /report/health (#th): ZIA changes waiting for
 * activation, the SSL inspection rule order, certificate expiry (ZIA SSL
 * inspection, ZPA enrollment, web server and client signing certificates)
 * and App Connector groups with no connector (tenant_health.py). The check
 * reads only what the Scope page ticks, with the sign-in of the assessment
 * tab (window.opener), as a job this page follows. The latest answer this
 * server holds is shown on load. Every value is escaped. */
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const WORDS = { ok: 'Healthy', warning: 'Fix soon', critical: 'Fix now', unknown: 'Could not be checked', not_in_scope: 'Not in scope' };
  const CERT = { ok: 'OK', warning: 'Expires soon', critical: 'Expires very soon', expired: 'Expired', unknown: 'No date' };
  const ORDER = { critical: 0, warning: 1, unknown: 2, ok: 3, not_in_scope: 4 };
  const T = { running: false, result: null, job: null };
  const CHIP = { ok: 'st-ok', warning: 'st-warn', critical: 'st-fail', expired: 'st-fail' };
  const chip = st => `df-chip ${CHIP[st] || ''}`;

  function opener() { try { return window.opener && !window.opener.closed ? window.opener : null; } catch (e) { return null; } }
  function say(t) { const l = $('thLive'); if (l) l.textContent = t; }
  function startToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }
  function declared(state) {
    const out = {};
    Object.entries(state || {}).forEach(([id, v]) => { const c = v && typeof v === 'object' ? v.choice : v; if (c === 'zscaler' || c === 'alternative') out[id] = c; });
    return out;
  }
  // The assessment tab's sign-in and Scope page selection, never guessed.
  function body() {
    const op = opener();
    if (!op || typeof op.migrateCredBody !== 'function') return null;
    let scopes = [], channels = {};
    try { scopes = typeof op.getSelectedScopes === 'function' ? op.getSelectedScopes() : []; } catch (e) { scopes = []; }
    try { channels = typeof op.__dbChannelScope === 'function' ? declared(op.__dbChannelScope()) : {}; } catch (e) { channels = {}; }
    const out = Object.assign({}, op.migrateCredBody(), { scopes: (scopes || []).map(String), channels, from_page: true });
    const w = $('thWarn').value.trim(), c = $('thCrit').value.trim();
    if (w) out.warn_days = Number(w);
    if (c) out.crit_days = Number(c);
    return out;
  }

  function stepsHtml(steps) {
    steps = (steps || []).filter(Boolean);
    return steps.length ? `<details class="th-steps"><summary>How to fix it</summary><ol>${steps.map(s => `<li>${E(s)}</li>`).join('')}</ol></details>` : '';
  }
  function rowsHtml(it) {
    const rows = it.rows || [];
    if (!rows.length || !rows.some(r => r.ends_on !== undefined)) {
      return rows.length ? `<ul class="th-names">${rows.slice(0, 50).map(r => `<li>${E(r.name)}</li>`).join('')}</ul>` : '';
    }
    const enrolled = rows.some(r => r.connectors || r.service_edges);
    return `<div class="df-tablewrap" tabindex="0" role="region" aria-label="${E(it.label)}"><table class="df-table th-t"><caption class="sr-only">${E(it.label)}</caption>
      <thead><tr><th scope="col">Certificate</th><th scope="col">Expires</th><th scope="col">Days left</th><th scope="col">State</th>${enrolled ? '<th scope="col">Enrolled with it</th>' : ''}</tr></thead>
      <tbody>${rows.slice(0, 100).map(r => `<tr><th scope="row">${E(r.name)}${r.default ? ' <span class="df-chip">default</span>' : ''}</th><td>${E(r.ends_on || '—')}</td>
        <td>${r.days_left == null ? '—' : E(r.days_left)}</td><td><span class="${chip(r.state)}">${E(CERT[r.state] || r.state)}</span></td>
        ${enrolled ? `<td>${E(r.connectors || 0)} connector(s), ${E(r.service_edges || 0)} service edge(s)</td>` : ''}</tr>`).join('')}</tbody></table></div>`;
  }
  function render() {
    const host = $('thBody');
    if (!host) return;
    const r = T.result;
    if (T.running) { host.innerHTML = '<div class="rp-wait"><div class="spin"></div>Reading the tenant: only what the Scope page ticks, nothing is changed…</div>'; return; }
    if (!r) {
      host.innerHTML = `<p class="dim">${opener() ? 'No tenant-health check has run yet. Click Check tenant health.' : 'No tenant-health check has run on this server yet. Open this page from the assessment page (sign in there first) to run one.'}</p>`;
      return;
    }
    const items = (r.items || []).slice().sort((a, b) => (ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9));
    const th = r.thresholds || {};
    host.innerHTML = `<p class="th-sum"><strong>${E(r.tenant_label || 'Tenant')}</strong> · checked ${E(String(r.checked_at || '').replace('T', ' ').replace('Z', ' UTC'))}
        · certificates warn at ${E(th.warning_days)} days, critical at ${E(th.critical_days)} days.<br>${E(r.summary)}</p>
      <ul class="th-items">${items.map(it => `<li class="th-item th-${E(it.status)}"><div class="th-h"><span class="${chip(it.status)}">${E(WORDS[it.status] || it.status)}</span>
        <strong>${E(it.label)}</strong> <span class="dim">${E(it.product)}</span></div><div>${E(it.summary)}</div>${rowsHtml(it)}${stepsHtml(it.steps)}</li>`).join('')}</ul>`;
  }

  async function follow(id) {
    const t0 = Date.now();
    for (;;) {
      await new Promise(res => setTimeout(res, 700));
      const q = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(id)}`, { cache: 'no-store' });
      if (!q.ok) throw new Error(`HTTP ${q.status}`);
      const snap = await q.json();
      if (snap.status !== 'running') return snap;
      if (Date.now() - t0 > 300000) throw new Error('it took longer than five minutes');
    }
  }
  async function run() {
    if (T.running) return;
    const b = body();
    const err = $('thErr');
    err.hidden = true;
    if (!b) { err.hidden = false; err.textContent = 'Open this page from the assessment page, signed in, to check the tenant: it uses that tab\'s sign-in and Scope page.'; return; }
    T.running = true; render(); say('Checking tenant health.');
    $('thRun').disabled = true;
    try {
      const r = await fetch('/api/tenant-health/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken() }, body: JSON.stringify(b) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : ((d.detail && d.detail.cause) || `HTTP ${r.status}`));
      const snap = await follow(d.job_id);
      if (snap.status === 'done' && snap.result && snap.result.status === 'done') { T.result = snap.result; T.job = d.job_id; }
      else throw new Error(snap.error || 'The check stopped before it finished.');
      say(`Tenant health: ${T.result.summary}`);
    } catch (e) {
      err.hidden = false; err.textContent = `The tenant-health check could not finish: ${e.message}`;
      say(err.textContent);
    } finally {
      T.running = false; $('thRun').disabled = false; render();
      const a = $('thCalls');
      if (a) { a.hidden = !T.job; if (T.job) a.href = `/report/advanced?job=${encodeURIComponent(T.job)}#apicalls`; }
    }
  }
  async function latest() {
    try {
      const r = await fetch('/api/tenant-health/latest', { cache: 'no-store' });
      if (!r.ok) return;
      const d = await r.json();
      const th = d.thresholds || {};
      if (th.warning_days && !$('thWarn').value) $('thWarn').placeholder = String(th.warning_days);
      if (th.critical_days && !$('thCrit').value) $('thCrit').placeholder = String(th.critical_days);
      if (!T.result && (d.results || []).length) T.result = d.results[0];
    } catch (e) { /* nothing held */ }
    render();
  }
  function wire() {
    if (!$('th')) return;
    $('thRun').addEventListener('click', run);
    latest();
  }
  window.dlpTenantHealth = { run, render, latest };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
})();
