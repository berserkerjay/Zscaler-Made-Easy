/* API calls on Advanced settings (#apicalls): every Zscaler API call this
 * server made since it started (GET /api/api-calls, api_calls.py), newest
 * first, with the run (job) and product filters and the CSV / JSON export.
 * ?job=<id> (the "API calls of this run" link of a builder) opens it on one
 * run. Reading it calls nothing; every value is escaped. */
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const JOB_RE = /^[A-Za-z0-9_-]{1,40}$/;
  const PRODUCTS = ['ZIA', 'ZPA', 'ZCC', 'ZDX', 'Z-Insights', 'ZIdentity', 'AI Guard', 'Cloud & Branch Connector', 'Workflow Automation', 'Sign-in', 'other'];
  const ERR = { rate_limited: 'Rate limit', denied: 'Refused (no access)', not_found: 'Not found', conflict: 'Conflict', rejected: 'Rejected',
                server_error: 'Zscaler error', timeout: 'Timed out', stopped: 'Stopped', network: 'No connection', error: 'Error' };
  const V = { job: '', product: '', failed: false, data: null };
  try { const j = new URLSearchParams(location.search).get('job') || ''; if (JOB_RE.test(j)) V.job = j; } catch (e) { /* no query */ }

  function ms(n) {
    n = Number(n) || 0;
    if (n < 1000) return `${n} ms`;
    if (n < 60000) return `${(n / 1000).toFixed(1)} s`;
    return `${Math.floor(n / 60000)} min ${Math.round((n % 60000) / 1000)} s`;
  }
  function errWords(e) {
    if (!e) return '';
    const m = /^([a-z_]+)(?: \(([A-Za-z0-9_]+)\))?$/.exec(String(e));
    return m ? `${ERR[m[1]] || m[1]}${m[2] ? ` (${m[2]})` : ''}` : String(e);
  }
  function exportHref(fmt) {
    const q = new URLSearchParams({ format: fmt });
    if (V.job) q.set('job', V.job);
    if (V.product) q.set('product', V.product);
    return `/api/api-calls/export?${q.toString()}`;
  }

  function render() {
    const d = V.data, box = $('advApiBox'), tb = document.querySelector('#advApi tbody');
    if (!box || !tb) return;
    if (!d) return;
    const s = d.summary || {};
    box.innerHTML = `<strong>${E(s.rows || 0)} call${s.rows === 1 ? '' : 's'}</strong> since ${E(String(s.since || '').replace('T', ' ').replace(/\.\d+Z$/, ' UTC'))}`
      + ` · ${E(s.failed || 0)} failed · ${E(s.retried || 0)} sent again · waited ${E(ms(s.wait_ms || 0))} in all`
      + ` · keeps the newest ${E(s.max || 0)}${s.dropped ? ` (${E(s.dropped)} older call${s.dropped === 1 ? '' : 's'} already dropped)` : ''}.`;
    const jobSel = $('advApiJob');
    if (jobSel) {
      const jobs = (d.jobs || []).filter(j => JOB_RE.test(j.id));
      if (V.job && !jobs.some(j => j.id === V.job)) jobs.unshift({ id: V.job, kind: '', calls: 0 });
      jobSel.innerHTML = '<option value="">Every call</option>' + jobs.map(j => `<option value="${E(j.id)}"${j.id === V.job ? ' selected' : ''}>${E(j.kind || 'run')} ${E(j.id)} (${E(j.calls)} call${j.calls === 1 ? '' : 's'})</option>`).join('');
    }
    const prodSel = $('advApiProduct');
    if (prodSel && prodSel.options.length <= 1) prodSel.innerHTML = '<option value="">Every product</option>' + PRODUCTS.map(p => `<option value="${E(p)}">${E(p)}</option>`).join('');
    if (prodSel) prodSel.value = V.product;
    const csv = $('advApiCsv'), json = $('advApiJson');
    if (csv) csv.href = exportHref('csv');
    if (json) json.href = exportHref('json');
    let rows = d.rows || [];
    if (V.failed) rows = rows.filter(r => r.error || r.retries);
    if (!rows.length) {
      const why = V.job ? 'This run made no Zscaler API call that is still in the log.' : (V.failed ? 'No call failed or was sent again.' : 'No Zscaler API call has been made since this server started (a sample tenant or a snapshot makes none).');
      tb.innerHTML = `<tr><td colspan="10" class="dim">${E(why)}</td></tr>`;
      return;
    }
    tb.innerHTML = rows.map(r => `<tr${r.error ? ' class="adv-api-bad"' : ''}><td>${E(String(r.at || '').replace('T', ' ').replace('Z', ''))}</td><td>${E(r.product)}</td><td>${E(r.method)}</td>`
      + `<td><code>${E(r.path)}</code></td><td>${r.status == null ? '—' : E(r.status)}</td><td>${E(ms(r.ms))}</td><td>${E(r.retries || 0)}</td>`
      + `<td>${r.wait_ms ? E(ms(r.wait_ms)) : '—'}</td><td>${E(errWords(r.error)) || '—'}</td><td>${r.job ? `${E(r.job_kind)} <code>${E(r.job)}</code>` : '—'}</td></tr>`).join('');
  }

  async function load() {
    const box = $('advApiBox');
    try {
      const q = new URLSearchParams({ limit: '1000' });
      if (V.job) q.set('job', V.job);
      if (V.product) q.set('product', V.product);
      const r = await fetch(`/api/api-calls?${q.toString()}`, { cache: 'no-store' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : `HTTP ${r.status}`);
      V.data = d;
      render();
    } catch (e) {
      if (box) box.innerHTML = `<span class="dim">The API calls could not be read: ${E(e.message)}</span>`;
    }
  }

  function wire() {
    if (!$('advApi')) return;
    const j = $('advApiJob'), p = $('advApiProduct'), f = $('advApiFailed'), b = $('advApiReload');
    if (j) j.addEventListener('change', () => { V.job = JOB_RE.test(j.value) ? j.value : ''; load(); });
    if (p) p.addEventListener('change', () => { V.product = PRODUCTS.includes(p.value) ? p.value : ''; load(); });
    if (f) f.addEventListener('change', () => { V.failed = !!f.checked; render(); });
    if (b) b.addEventListener('click', load);
    load();
    if (V.job && location.hash !== '#apicalls') location.hash = '#apicalls';
  }
  window.dlpApiCalls = { load, render, errWords, ms };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
})();
