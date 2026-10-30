/* Client Connector fleet (/report/fleet): starts the read-only fleet job,
 * follows it with Stop, and renders KPIs, alerts with their definitions,
 * the profile heatmap, profile compare, PAC compare, the remediation plan
 * and the device table. User and device names are shown here only; the
 * exports offer a counts-only form. */
(function () {
  'use strict';
  // An error answer in plain words: FastAPI's detail is a string, {cause} or a list of {msg}.
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x; if (x && typeof x === 'object' && !Array.isArray(x) && (x.cause || x.message)) return String(x.cause || x.message);
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const out = $('zfOut');
  const live = $('liveRegion');
  const say = t => { live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  const STATUS = { pass: ['Pass', 'st-pass'], warn: ['Warn', 'st-warn'], fail: ['Fail', 'st-fail'], unknown: ['Unknown', 'st-unknown'], 'n/a': ['N/A', 'st-na'] };
  const SVC = { active: 'Active', inactive: 'Not active', not_applicable: 'Not applicable', unknown: 'Unreadable', unread: 'No status' };
  let running = false, job = null, startToken = null, stopAsked = false, last = null, lastJob = null;

  function newStartToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }
  function status(t, bad) { const s = $('zfStatus'); if (s) { s.textContent = t; s.classList.toggle('bad', !!bad); } }
  function setEnabled(id, on) { const b = $(id); if (b) { b.disabled = !on; b.setAttribute('aria-disabled', on ? 'false' : 'true'); } }

  // ── credentials and scope: as the Path analyzer takes them ─────────
  async function tenantChoices() {
    const wrap = $('zfTenantWrap'), sel = $('zfTenant');
    const fromOpener = !!(window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function');
    let profiles = [];
    try { const r = await fetch('/api/tenant-profiles', { cache: 'no-store' }); if (r.ok) profiles = ((await r.json()).profiles || []); } catch (e) { /* no profiles */ }
    const opts = [];
    if (fromOpener) opts.push(['opener', 'Signed in on the assessment tab']);
    profiles.forEach(p => opts.push([`profile:${p.id}`, `${p.name || p.vanity_domain || p.id}${p.has_secret === false ? ' (no remembered secret)' : ''}`]));
    opts.push(['server', 'Saved on this computer (environment or tenant_config.json)']);
    sel.innerHTML = opts.map(([v, l]) => `<option value="${E(v)}">${E(l)}</option>`).join('');
    wrap.hidden = opts.length < 2;
  }
  function credBody() {
    const v = $('zfTenant').value || 'server';
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
  // The Scope page's selection, never guessed: live from the assessment tab,
  // else the ticks it publishes; without either the server uses the chosen
  // profile's saved selection, or refuses before signing in.
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

  // ── the job ─────────────────────────────────────────────────────────
  function mmss(s) { s = Math.max(0, Math.round(s || 0)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; }
  function liveHtml() {
    return `<section class="zf-sec pa-live" aria-labelledby="zfLiveH">
      <div class="pa-live-h"><span class="spin" aria-hidden="true"></span><strong id="zfLiveH">Reading the fleet</strong><span class="sep"></span><span class="pa-elapsed" id="zfElapsed">0:00</span><button type="button" class="rp-btn" id="zfStop">Stop</button></div>
      <div class="pa-log pa-log-live" id="zfLog" role="log" aria-live="polite" aria-label="What the read is doing">Connecting to the tenant…</div>
    </section>`;
  }
  async function follow(jobId) {
    let next = 0, misses = 0; const logs = [];
    for (;;) {
      await new Promise(res => setTimeout(res, 1000));
      let snap;
      try {
        const r = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(jobId)}?since=${next}`, { cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        snap = await r.json(); misses = 0;
      } catch (e) {
        if (++misses >= 20) throw new Error(`Lost contact with the app while the read continued (${e.message}).`);
        continue;
      }
      logs.push(...(snap.logs || [])); next = snap.next;
      const log = $('zfLog'); if (log) { log.textContent = logs.join('\n') || 'Connecting to the tenant…'; log.scrollTop = log.scrollHeight; }
      const el = $('zfElapsed'); if (el && snap.elapsed_seconds != null) el.textContent = mmss(snap.elapsed_seconds);
      const st = $('zfStop'); if (st && snap.cancel_requested) { st.disabled = true; st.textContent = 'Stopping…'; }
      if (snap.status !== 'running') return Object.assign({}, snap, { logs });
    }
  }
  async function stop() {
    if (!running || stopAsked) return;
    stopAsked = true;
    const b = $('zfStop'); if (b) { b.disabled = true; b.textContent = 'Stopping…'; }
    if (!job) {
      try { await fetch('/api/dlp-packs/jobs/stop-before-start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_token: startToken }) }); } catch (e) { /* cancelled by id below */ }
      return;
    }
    try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows it */ }
  }
  const EXPORTS = ['zfExpPlan', 'zfExpDevices', 'zfExpSummary', 'zfExpXlsx', 'zfExpPdf'];
  // A read of the tenant (no body) or an import of the portal's CSV files (body: the files, already encoded).
  async function run(importBody) {
    if (running) return;
    running = true; stopAsked = false; startToken = newStartToken(); job = null;
    const btn = $('zfRun'); btn.disabled = true; btn.textContent = importBody ? 'Importing…' : 'Reading…';
    setEnabled('zfImpGo', false);
    EXPORTS.forEach(id => setEnabled(id, false));
    out.innerHTML = liveHtml();
    $('zfStop').addEventListener('click', stop);
    status('');
    say(importBody ? 'Importing the Client Connector Portal exports.' : 'Reading the Client Connector fleet.');
    const t0 = Date.now();
    const tick = setInterval(() => { const el = $('zfElapsed'); if (el) el.textContent = mmss((Date.now() - t0) / 1000); }, 1000);
    try {
      const r = importBody
        ? await fetch('/api/zcc/fleet/import', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken },
          body: JSON.stringify(Object.assign({}, importBody, { site: siteRule() })) })
        : await fetch('/api/zcc/fleet/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken },
          body: JSON.stringify(Object.assign({}, credBody(), scopeSelection(), { site: siteRule() })) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      job = d.job_id;
      if (stopAsked) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* token stopped it */ } }
      const snap = await follow(job);
      if (snap.status !== 'done' || !snap.result || snap.result.status !== 'done') {
        if (snap.status === 'cancelled' || (snap.result && snap.result.status === 'stopped')) {
          const err = new Error('You clicked Stop: nothing more was read and no partial result is kept.'); err.stopped = true; throw err;
        }
        throw new Error(snap.error || 'The read did not finish.');
      }
      last = snap.result; lastJob = job;
      render(last, snap.logs || []);
      instProfiles();
      ['zfExpPlan', 'zfExpSummary', 'zfExpXlsx', 'zfExpPdf'].forEach(id => setEnabled(id, true));
      setEnabled('zfExpDevices', !!(last.devices || []).length && !$('zfCounts').checked);
      say(`${importBody ? 'Files imported' : 'Fleet read'}. ${last.banner}`);
      if (importBody) impStatus(`Imported ${last.devices_total} device record${last.devices_total === 1 ? '' : 's'}.`);
      loadHistory();
    } catch (e) {
      const stopped = !!e.stopped;
      const what = importBody ? 'The files could not be imported' : 'The fleet could not be read';
      out.innerHTML = `<div class="bp-card ${stopped ? 'info' : 'risk'}" role="alert"><div class="t">${stopped ? 'Stopped' : what}</div><div>${E(e.message)}${!importBody && /credential|sign in|401|403|profile/i.test(e.message) ? ' Sign in on the assessment page first and open this page from there, or choose a saved tenant profile in the bar above.' : ''}</div></div>`;
      say(stopped ? 'Stopped.' : `${what}: ${e.message}`);
      if (importBody) impStatus(`${what}: ${e.message}`, true);
    } finally {
      clearInterval(tick); running = false; job = null; startToken = null; stopAsked = false; btn.disabled = false; btn.textContent = 'Read the fleet';
      setEnabled('zfImpGo', true);
    }
  }

  // ── import of the portal's CSV exports: read in the browser, gzip-compressed when it can, sent as base64 ──
  const IMPORT_MAX_MB = 48;
  function impStatus(t, bad) { const s = $('zfImpStatus'); s.textContent = t; s.classList.toggle('bad', !!bad); }
  function b64(buf) {
    const u = new Uint8Array(buf); let bin = '';
    for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(bin);
  }
  async function encodeFile(file) {
    if (file.size > IMPORT_MAX_MB * 1024 * 1024) throw new Error(`${file.name} is larger than ${IMPORT_MAX_MB} MB.`);
    const buf = await file.arrayBuffer();
    if (typeof CompressionStream === 'function') {
      try {
        const gz = await new Response(new Blob([buf]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer();
        return { name: file.name, content: b64(gz), encoding: 'gzip-base64' };
      } catch (e) { /* send it uncompressed */ }
    }
    return { name: file.name, content: b64(buf), encoding: 'base64' };
  }
  async function importFiles() {
    if (running) return;
    const dev = ($('zfImpDev').files || [])[0], svc = ($('zfImpSvc').files || [])[0];
    if (!dev && !svc) { impStatus('Choose the Device Details export, the Service Status export, or both.', true); return; }
    impStatus('Reading the files…');
    let body;
    try {
      body = { tenant_label: $('zfImpLabel').value.trim().slice(0, 80) };
      if (dev) body.devices = await encodeFile(dev);
      if (svc) body.service = await encodeFile(svc);
    } catch (e) { impStatus(`The files could not be read: ${e.message}`, true); return; }
    impStatus('Importing…');
    await run(body);
  }
  $('zfImpGo').addEventListener('click', importFiles);

  // ── site grouping: a prefix, a delimiter or a pick list (never a pattern); kept in this browser ──
  const SITE_KEY = 'zf_site_rule_v1';
  function savedSite() {
    try {
      const v = JSON.parse(localStorage.getItem(SITE_KEY) || 'null');
      return v && typeof v === 'object' && ['none', 'prefix', 'delimiter', 'list'].includes(v.mode) ? v : { mode: 'none' };
    } catch (e) { return { mode: 'none' }; }
  }
  function keepSite(rule) { try { localStorage.setItem(SITE_KEY, JSON.stringify(rule)); } catch (e) { /* kept for this page only */ } }
  let siteState = savedSite();
  function siteRule() { return siteState; }
  function siteFormRule() {
    const mode = $('zfSiteMode').value;
    if (mode === 'prefix') return { mode, length: Number($('zfSiteLen').value || 2) };
    if (mode === 'delimiter') return { mode, delimiter: $('zfSiteDelim').value, segments: Number($('zfSiteSeg').value || 1) };
    if (mode === 'list') return { mode, prefixes: $('zfSiteList').value };
    return { mode: 'none' };
  }
  function siteFormShow() {
    const mode = $('zfSiteMode').value;
    $('zfSiteLenW').hidden = mode !== 'prefix';
    $('zfSiteDelimW').hidden = mode !== 'delimiter';
    $('zfSiteSegW').hidden = mode !== 'delimiter';
    $('zfSiteListW').hidden = mode !== 'list';
  }
  async function applySites() {
    const rule = siteFormRule();
    const st = $('zfSiteStatus');
    try {
      const r = await fetch(`/api/zcc/fleet/${encodeURIComponent(lastJob)}/sites`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ site: rule }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      siteState = d.rule; keepSite(d.rule); last.sites = d;
      $('zfSiteTable').innerHTML = sitesTable(d);
      st.textContent = d.rule.mode === 'none' ? 'Site grouping is off.' : `${d.groups.length} site${d.groups.length === 1 ? '' : 's'}.`; st.classList.remove('bad');
      say(st.textContent);
    } catch (e) { st.textContent = `The sites could not be grouped: ${e.message}`; st.classList.add('bad'); say(st.textContent); }
  }

  // ── history: counts-only snapshots kept on this computer ──
  let hist = null;
  async function loadHistory() {
    if (!last || !last.kpis || !$('zfHist')) return;
    try {
      const r = await fetch(`/api/zcc/fleet/history?tenant=${encodeURIComponent(last.tenant_label || '')}`, { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      hist = await r.json(); drawHistory();
    } catch (e) { const b = $('zfHistBody'); if (b) b.innerHTML = `<p class="zf-dim">The saved snapshots could not be loaded (${E(e.message)}).</p>`; }
  }
  async function saveHistory() {
    const st = $('zfHistStatus');
    try {
      const r = await fetch(`/api/zcc/fleet/${encodeURIComponent(lastJob)}/history`, { method: 'POST' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      hist = d; drawHistory();
      st.textContent = `Saved. ${d.history.length} snapshot${d.history.length === 1 ? '' : 's'} of ${d.tenant} kept on this computer (at most ${d.keep}).`; st.classList.remove('bad');
      say(st.textContent);
    } catch (e) { st.textContent = `Not saved: ${e.message}`; st.classList.add('bad'); say(st.textContent); }
  }
  async function forgetHistory() {
    if (!hist || !hist.history.length) return;
    if (!window.confirm(`Remove all ${hist.history.length} saved fleet snapshots of ${hist.tenant} from this computer? This cannot be undone.`)) return;
    const st = $('zfHistStatus');
    try {
      const r = await fetch('/api/zcc/fleet/history/forget', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tenant: hist.tenant, confirm: true }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      st.textContent = `Removed ${d.removed} snapshot${d.removed === 1 ? '' : 's'}.`; st.classList.remove('bad');
      await loadHistory(); say(st.textContent);
    } catch (e) { st.textContent = `Not removed: ${e.message}`; st.classList.add('bad'); }
  }
  async function compareHistory() {
    const a = Number($('zfHistA').value), b = Number($('zfHistB').value), box = $('zfHistCmp');
    if (a === b) { box.innerHTML = '<p class="zf-dim">Choose two different snapshots.</p>'; return; }
    try {
      const r = await fetch(`/api/zcc/fleet/history/compare?tenant=${encodeURIComponent(hist.tenant)}&a=${a}&b=${b}`, { cache: 'no-store' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      box.innerHTML = compareTable(d); say('Snapshots compared.');
    } catch (e) { box.innerHTML = `<p class="zf-status bad">${E(e.message)}</p>`; }
  }

  // ── rendering ───────────────────────────────────────────────────────
  const pct = v => (v == null ? null : `${v}%`);
  function tile(k, v, note) {
    const na = v == null || v === '';
    return `<div class="zf-tile"><div class="k">${E(k)}</div><div class="v${na ? ' na' : ''}">${na ? 'Not available' : E(v)}</div>${note ? `<div class="n">${E(note)}</div>` : ''}</div>`;
  }
  function cell(st, detail) {
    const [lab, cls] = STATUS[st] || [st, 'st-unknown'];
    return `<span class="zf-cell ${cls}" title="${E(detail || '')}">${E(lab)}</span>`;
  }
  function when(d) { return d.last_seen ? `${E(String(d.last_seen).replace('T', ' ').slice(0, 16))} (${E(d.hours_since_seen)} h)` : 'never'; }
  function deviceRows(rows, extra) {
    if (!rows.length) return '<p class="zf-dim">None.</p>';
    return `<div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">User</th><th scope="col">Device</th><th scope="col">Platform</th><th scope="col">Version</th><th scope="col">Last seen (UTC)</th><th scope="col">App profile</th><th scope="col">ZIA</th><th scope="col">ZPA</th>${extra ? `<th scope="col">${E(extra[0])}</th>` : ''}</tr></thead><tbody>
      ${rows.map(d => `<tr><td>${E(d.user)}</td><td>${E(d.hostname)}</td><td>${E(d.platform)}</td><td>${E(d.version)}</td><td>${when(d)}</td><td>${E(d.profile)}</td><td>${E(SVC[d.services.zia] || d.services.zia)}</td><td>${E(SVC[d.services.zpa] || d.services.zpa)}</td>${extra ? `<td>${E(d[extra[1]])}</td>` : ''}</tr>`).join('')}
    </tbody></table></div>`;
  }
  function alertHtml(a) {
    const count = !a.evaluated ? '<span class="zf-chip">not evaluated</span>' : `<span class="zf-count">${E(a.count)}</span>`;
    let body;
    if (!a.evaluated) body = `<p>${E(a.why_not)}</p>`;
    else if (a.key === 'multi_device') {
      body = a.rows.length ? `<div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">User</th><th scope="col" class="num">Registered devices</th><th scope="col">Devices</th><th scope="col">Platforms</th></tr></thead><tbody>
        ${a.rows.map(u => `<tr><td>${E(u.user)}</td><td class="num">${E(u.devices)}</td><td>${E([].concat(u.hostnames || []).join(', '))}</td><td>${E([].concat(u.platforms || []).join(', '))}</td></tr>`).join('')}</tbody></table></div>` : '<p class="zf-dim">None.</p>';
    } else {
      const extra = a.key === 'registration_anomaly' ? ['Why', 'reason'] : (a.rows[0] && a.rows[0].newest ? ['Newest on platform', 'newest'] : null);
      body = deviceRows(a.rows, extra);
    }
    return `<details class="zf-alert"${a.evaluated && a.count && a.impact >= 2 ? ' open' : ''}><summary>${E(a.label)} ${count}</summary><div class="body">
      <p class="def"><strong>Definition:</strong> ${E(a.definition)}</p>${body}
      ${a.truncated ? `<p class="zf-dim">The first ${a.rows.length} are listed; export the device table for all of them.</p>` : ''}
      ${a.evaluated && a.count ? `<p><strong>What to do:</strong> ${E(a.fix)}</p>` : ''}</div></details>`;
  }
  function countTable(caption, obj, labels) {
    const rows = Object.entries(obj || {});
    if (!rows.length) return '';
    return `<div class="zf-wrap"><table class="zf-t"><caption>${E(caption)}</caption><thead><tr><th scope="col">${E(caption.split(' ')[0])}</th><th scope="col" class="num">Devices</th></tr></thead><tbody>
      ${rows.map(([k, n]) => `<tr><th scope="row">${E((labels || {})[k] || k)}</th><td class="num">${E(n)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function heatmap(res) {
    const cols = res.checks;
    const profs = res.profiles;
    if (!profs.length) return '<p class="zf-dim">No app profile was read.</p>';
    return `<div class="zf-legend" aria-hidden="true">${Object.keys(STATUS).map(s => cell(s, '')).join('')}</div>
      <div class="zf-wrap"><table class="zf-t zf-heat"><caption>Each cell says pass, warn, fail, unknown or not applicable; hover or read the list below for the reason.</caption>
      <thead><tr><th scope="col">App profile</th><th scope="col" class="num">Devices</th><th scope="col" class="num">Score</th>${cols.map(c => `<th scope="col" title="${E(c.definition)}">${E(c.label)}</th>`).join('')}</tr></thead>
      <tbody>${profs.map(p => `<tr><th scope="row">${E(p.name)} <span class="zf-dim">${E(p.platform)}${p.active ? '' : ', inactive'}</span></th>
        <td class="num">${p.devices == null ? '—' : E(p.devices)}</td><td class="num">${p.score == null ? '—' : E(p.score)}</td>
        ${cols.map(c => { const x = p.checks[c.key] || { status: 'unknown', detail: '' }; return `<td>${cell(x.status, x.detail)}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>
      <details class="zf-details"><summary>Why each profile fails or warns</summary>
        ${profs.map(p => { const bad = cols.filter(c => p.checks[c.key] && ['fail', 'warn', 'unknown'].includes(p.checks[c.key].status));
          return bad.length ? `<h3>${E(p.name)} (${E(p.platform)})</h3><ul>${bad.map(c => `<li><strong>${E(c.label)}</strong> (${E(STATUS[p.checks[c.key].status][0])}): ${E(p.checks[c.key].detail)}</li>`).join('')}</ul>` : ''; }).join('')}
      </details>
      <details class="zf-details"><summary>What each check means</summary><dl>${cols.map(c => `<dt><strong>${E(c.label)}</strong> (impact ${E(c.impact)})</dt><dd>${E(c.definition)}</dd>`).join('')}</dl></details>`;
  }
  function compareHtml(res) {
    const opts = res.profiles.map(p => `<option value="${E(p.pid)}">${E(p.name)} (${E(p.platform)})</option>`).join('');
    return `<div class="zf-row"><label for="zfA">Profile A</label><select id="zfA">${opts}</select>
      <label for="zfB">Profile B</label><select id="zfB">${opts}</select>
      <button type="button" class="rp-btn" id="zfCompare">Compare</button>
      <label><input type="checkbox" id="zfOnlyDiff" checked> Only differences</label></div>
      <div id="zfDiff" aria-live="polite"></div>`;
  }
  function renderDiff(d) {
    const only = $('zfOnlyDiff').checked;
    const rows = d.rows.filter(r => !only || !r.same);
    const add = l => (l.startsWith('+') && !l.startsWith('+++') ? `<span class="add">${E(l)}</span>` : l.startsWith('-') && !l.startsWith('---') ? `<span class="del">${E(l)}</span>` : E(l));
    $('zfDiff').innerHTML = `<p>${E(d.differences)} setting${d.differences === 1 ? '' : 's'} differ between <strong>${E(d.a)}</strong> and <strong>${E(d.b)}</strong>. Passwords and secrets show only whether they are set.</p>
      <div class="zf-wrap"><table class="zf-t zf-diff"><thead><tr><th scope="col">Setting</th><th scope="col">${E(d.a)}</th><th scope="col">${E(d.b)}</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="${r.same ? '' : 'diff'}"><th scope="row">${E(r.key)}</th><td>${r.a == null ? '<span class="zf-dim">absent</span>' : E(r.a)}</td><td>${r.b == null ? '<span class="zf-dim">absent</span>' : E(r.b)}</td></tr>`).join('') || '<tr><td colspan="3">The two profiles have the same settings.</td></tr>'}</tbody></table></div>
      <details class="zf-details"><summary>Raw JSON diff</summary><pre class="zf-pre" tabindex="0" aria-label="Unified diff of the two profiles">${d.unified ? d.unified.split('\n').map(add).join('\n') : 'No difference.'}</pre></details>`;
  }
  async function compare() {
    const a = $('zfA').value, b = $('zfB').value;
    if (a === b) { $('zfDiff').innerHTML = '<p class="zf-dim">Choose two different profiles.</p>'; return; }
    try {
      const r = await fetch(`/api/zcc/fleet/${encodeURIComponent(lastJob)}/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`, { cache: 'no-store' });
      const d = await r.json();
      if (!r.ok) throw new Error(errText(d, r.status));
      renderDiff(d); say(`${d.differences} settings differ.`);
    } catch (e) { $('zfDiff').innerHTML = `<p class="zf-status bad">${E(e.message)}</p>`; }
  }
  function pacHtml(res) {
    const m = res.pac.matrix, files = res.pac.files;
    const head = files.length ? `<p class="zf-dim">${files.length} hosted PAC file${files.length === 1 ? '' : 's'} read; ${E(m.risky)} risky DIRECT entr${m.risky === 1 ? 'y' : 'ies'}; ${E(m.differing)} entr${m.differing === 1 ? 'y differs' : 'ies differ'} between profiles. A PAC that is not hosted in ZIA cannot be read here: drop it into the Log analyzer.</p>` : '<p class="zf-dim">No hosted PAC file was read.</p>';
    if (!m.columns.length) return head + '<p class="zf-dim">No app profile uses a PAC file this read could open.</p>';
    const risk = r => (r === 'ok' ? '<span class="zf-chip">ok</span>' : `<span class="zf-chip st-${r === 'broad' ? 'warn' : 'fail'}">${E(r)}</span>`);
    return head + `<div class="zf-wrap"><table class="zf-t"><caption>DIRECT statements (rows) per app profile (columns): DIRECT means the profile's PAC sends that traffic around Zscaler.</caption>
      <thead><tr><th scope="col">Sent DIRECT</th><th scope="col">Risk</th>${m.columns.map(c => `<th scope="col">${E(c.name)} <span class="zf-dim">${E(c.platform)}; default ${E(c.default)}</span></th>`).join('')}</tr></thead>
      <tbody>${m.rows.map(r => `<tr><th scope="row"><code>${E(r.kind)}(${E(r.value)})</code></th><td>${risk(r.risk)}</td>${m.columns.map(c => `<td>${r.profiles.includes(c.pid) ? '<strong>DIRECT</strong>' : '<span class="zf-dim">no</span>'}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  }
  function planHtml(res) {
    if (!res.plan.length) return '<p>Nothing to fix: every check passed and no alert has a device in it.</p>';
    const known = res.plan[0].device_count_known;
    return `${known ? '' : '<p class="zf-dim">Device counts are unknown (no device telemetry), so the plan is ranked by impact alone.</p>'}
      <div class="zf-wrap"><table class="zf-t zf-plan"><caption>Ranked by impact (1 to 3, halved for a warning) times the devices affected.</caption>
      <thead><tr><th scope="col" class="num">Rank</th><th scope="col">What</th><th scope="col" class="num">Devices</th><th scope="col" class="num">Priority</th><th scope="col">Fix</th></tr></thead>
      <tbody>${res.plan.map(x => `<tr><td class="num">${E(x.rank)}</td><td>${cell(x.status, x.detail)} <strong>${E(x.title)}</strong><div class="why">${E(x.detail)}</div></td>
        <td class="num">${x.devices == null ? 'unknown' : E(x.devices)}</td><td class="num">${E(x.priority)}</td><td class="fix">${E(x.fix)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function devicesHtml(res) {
    if (!res.devices.length) return '<p class="zf-dim">No device list (see the note at the top).</p>';
    return `<div class="zf-row"><label for="zfFilter">Filter</label><input type="search" id="zfFilter" placeholder="User, device, profile or version" autocomplete="off">
      <span class="zf-dim" id="zfShown"></span></div><div id="zfDevTable"></div>
      ${res.devices_truncated ? `<p class="zf-dim">The first ${res.devices.length} of ${E(res.devices_total)} devices are kept for this page and the device export; every figure above counts all of them.</p>` : ''}`;
  }
  function drawDevices() {
    const q = ($('zfFilter') ? $('zfFilter').value : '').trim().toLowerCase();
    const all = last.devices.filter(d => !q || [d.user, d.hostname, d.profile, d.version, d.platform].some(v => String(v || '').toLowerCase().includes(q)));
    const rows = all.slice(0, 500);
    $('zfDevTable').innerHTML = deviceRows(rows, ['Registration', 'registration']);
    $('zfShown').textContent = `${all.length} device${all.length === 1 ? '' : 's'}${all.length > rows.length ? `, first ${rows.length} shown` : ''}`;
  }

  // ── fleet depth: version x service matrix, profile health, last seen, sites, history ──
  const SVCS = ['zia', 'zpa', 'zdx'];
  function svcCell(row, s) {
    const v = row.services[s];
    if (!v || v.percent == null) return `<td class="num"><span class="zf-dim">${v && v.known ? 'not read' : '—'}</span></td>`;
    const low = (row.below_fleet || []).includes(s);
    return `<td class="num">${E(v.percent)}%<span class="zf-dim"> (${E(v.active)}/${E(v.known)})</span>${low ? ' <span class="zf-below">below fleet</span>' : ''}</td>`;
  }
  const svcHead = () => SVCS.map(s => `<th scope="col" class="num">${s.toUpperCase()} active</th>`).join('');
  function versionHtml(res) {
    const vh = res.version_health;
    if (!vh || !vh.rows.length) return '<p class="zf-dim">No registered device reports a Client Connector version.</p>';
    return `<p class="zf-dim">${E(vh.definition)}${vh.service_read ? '' : ' The service status was not read, so only the device counts are shown.'}</p>
      <div class="zf-wrap"><table class="zf-t"><caption>Client Connector versions (rows) against ZIA, ZPA and ZDX (columns): the share active among devices with a known status.</caption>
      <thead><tr><th scope="col">Platform</th><th scope="col">Version</th><th scope="col" class="num">Devices</th><th scope="col" class="num">% of platform</th>${svcHead()}</tr></thead>
      <tbody>${vh.rows.map(r => `<tr><th scope="row">${E(r.platform)}</th><td>${E(r.version)}${r.newest ? ' <span class="zf-chip">newest</span>' : ''}${r.unsupported ? ' <span class="zf-chip st-fail">unsupported</span>' : ''}</td>
        <td class="num">${E(r.devices)}</td><td class="num">${r.share == null ? '—' : `${E(r.share)}%`}</td>${SVCS.map(s => svcCell(r, s)).join('')}</tr>`).join('')}
      <tr><th scope="row" colspan="4">Whole fleet (registered)</th>${SVCS.map(s => svcCell({ services: vh.fleet, below_fleet: [] }, s)).join('')}</tr></tbody></table></div>
      ${vh.truncated ? '<p class="zf-dim">The most common versions are listed; the Excel export has the same rows.</p>' : ''}`;
  }
  function profileHealthHtml(res) {
    const ph = res.profile_health;
    if (!ph || !ph.app_profiles.length) return '<p class="zf-dim">No registered device.</p>';
    const fwd = r => (r.forwarding_profile ? E(r.forwarding_profile) : `<span class="zf-dim">${r.matched ? 'not linked' : 'not known'}</span>`);
    return `<p class="zf-dim">${E(ph.definition)}${ph.config_read ? '' : ' No app profile was read, so no forwarding profile is known.'}</p>
      <h3>Per app profile</h3>
      <div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">App profile</th><th scope="col">Platform</th><th scope="col" class="num">Devices</th><th scope="col">Forwarding profile</th><th scope="col" class="num">Seen 24 h</th><th scope="col" class="num">Ghosts</th>${svcHead()}</tr></thead>
      <tbody>${ph.app_profiles.map(r => `<tr><th scope="row">${E(r.name)}</th><td>${E(r.platform)}</td><td class="num">${E(r.devices)}</td><td>${fwd(r)}</td><td class="num">${E(r.seen_24h)}</td><td class="num">${E(r.ghosts)}</td>${SVCS.map(s => svcCell(r, s)).join('')}</tr>`).join('')}</tbody></table></div>
      <h3>Per forwarding profile</h3>
      <div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">Forwarding profile</th><th scope="col" class="num">App profiles</th><th scope="col" class="num">Devices</th><th scope="col" class="num">Seen 24 h</th>${svcHead()}</tr></thead>
      <tbody>${ph.forwarding_profiles.map(g => `<tr><th scope="row">${E(g.name)}</th><td class="num">${E(g.app_profiles)}</td><td class="num">${E(g.devices)}</td><td class="num">${E(g.seen_24h)}</td>${SVCS.map(s => svcCell(g, s)).join('')}</tr>`).join('')}</tbody></table></div>`;
  }
  function lastSeenHtml(res) {
    const ls = res.last_seen;
    if (!ls || !ls.registered) return '<p class="zf-dim">No registered device.</p>';
    const max = Math.max(1, ...ls.buckets.map(b => b.devices));
    const cls = k => (k === 'never' ? ' never' : (k === 'over_30d' || k === '7_30d') ? ' stale' : '');
    return `<p class="zf-dim">${E(ls.definition)}</p>
      <div class="zf-wrap"><table class="zf-t"><caption>${E(ls.registered)} registered devices by when they were last seen</caption>
      <thead><tr><th scope="col">Last seen</th><th scope="col" class="num">Devices</th><th scope="col" class="num">Share</th><th scope="col" class="zf-barcell"><span class="sr-only">Bar</span></th></tr></thead>
      <tbody>${ls.buckets.map(b => `<tr><th scope="row">${E(b.label)}</th><td class="num">${E(b.devices)}</td><td class="num">${b.percent == null ? '—' : `${E(b.percent)}%`}</td>
        <td class="zf-barcell" aria-hidden="true"><span class="zf-bar${cls(b.key)}" style="width:${Math.round(100 * b.devices / max)}%"></span></td></tr>`).join('')}</tbody></table></div>`;
  }
  function sitesTable(st) {
    if (!st || st.rule.mode === 'none') return '<p class="zf-dim">Choose how host names name a site, then Group.</p>';
    if (!st.groups.length) return '<p class="zf-dim">No device.</p>';
    return `<p class="zf-dim">Grouped by ${E(st.rule_text)}.${st.counted < st.of ? ` Counted over the first ${E(st.counted)} of ${E(st.of)} devices kept for this page.` : ''}</p>
      <div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">Site</th><th scope="col" class="num">Devices</th><th scope="col" class="num">Registered</th><th scope="col" class="num">Seen 24 h</th><th scope="col" class="num">Ghosts</th><th scope="col" class="num">Quarantined</th><th scope="col">Most common version</th>${svcHead()}</tr></thead>
      <tbody>${st.groups.map(g => `<tr><th scope="row">${E(g.site)}</th><td class="num">${E(g.devices)}</td><td class="num">${E(g.registered)}</td><td class="num">${E(g.seen_24h)}</td><td class="num">${E(g.ghosts)}</td><td class="num">${E(g.quarantined)}</td><td>${E(g.top_version || '—')}${g.versions > 1 ? ` <span class="zf-dim">(${E(g.versions)} versions)</span>` : ''}</td>${SVCS.map(s => svcCell(g, s)).join('')}</tr>`).join('')}</tbody></table></div>
      ${st.truncated ? '<p class="zf-dim">The largest sites are listed; the rest are counted together.</p>' : ''}`;
  }
  function sitesHtml(res) {
    const r = siteState || { mode: 'none' };
    const opt = (v, l, cur) => `<option value="${E(v)}"${String(cur) === String(v) ? ' selected' : ''}>${E(l)}</option>`;
    return `<p class="zf-dim">Group devices into sites by their host names: the first letters (LON-LT-001 → LON with 3), the part before a separator, or a list of site prefixes. Kept in this browser; never a pattern that could run.</p>
      <div class="zf-row">
        <label>Group by <select id="zfSiteMode">${opt('none', 'No grouping', r.mode)}${opt('prefix', 'First characters', r.mode)}${opt('delimiter', 'Part before a separator', r.mode)}${opt('list', 'A list of site prefixes', r.mode)}</select></label>
        <label id="zfSiteLenW">Characters <input type="number" id="zfSiteLen" min="1" max="12" step="1" value="${E(r.length || 2)}"></label>
        <label id="zfSiteDelimW">Separator <select id="zfSiteDelim">${opt('-', '- (hyphen)', r.delimiter || '-')}${opt('_', '_ (underscore)', r.delimiter || '-')}${opt('.', '. (dot)', r.delimiter || '-')}</select></label>
        <label id="zfSiteSegW">Parts <input type="number" id="zfSiteSeg" min="1" max="4" step="1" value="${E(r.segments || 1)}"></label>
        <label id="zfSiteListW">Site prefixes <textarea id="zfSiteList" rows="1" maxlength="7000" placeholder="LON, NYC, PAR">${E(Array.isArray(r.prefixes) ? r.prefixes.join(', ') : '')}</textarea></label>
        <button type="button" class="rp-btn" id="zfSiteApply">Group</button>
      </div>
      <div class="zf-status" id="zfSiteStatus" role="status" aria-live="polite"></div>
      <div id="zfSiteTable">${sitesTable(res.sites)}</div>`;
  }
  function historyHtml(res) {
    if (!res.kpis) return '<p class="zf-dim">Needs device figures: there is nothing to keep from a configuration-only read.</p>';
    return `<p class="zf-dim">Save each read to keep its figures for <strong>${E(res.tenant_label || 'this tenant')}</strong> on this computer: counts only, never a user, device or site name. Then follow the trend and compare any two reads.</p>
      <div class="zf-row"><button type="button" class="rp-btn primary" id="zfHistSave">Save this read to the history</button>
        <button type="button" class="rp-btn" id="zfHistForget" disabled aria-disabled="true">Remove this tenant's history</button></div>
      <div class="zf-status" id="zfHistStatus" role="status" aria-live="polite"></div>
      <div id="zfHistBody"><p class="zf-dim">Loading the saved snapshots…</p></div>`;
  }
  const when2 = at => String(at || '').replace('T', ' ').slice(0, 16);
  function chartSvg(rows) {
    const W = 640, H = 200, L = 36, R = 12, T = 12, B = 28;
    const xs = i => L + (rows.length === 1 ? 0 : i * (W - L - R) / (rows.length - 1));
    const ys = v => T + (100 - v) * (H - T - B) / 100;
    const grid = [0, 25, 50, 75, 100].map(v => `<line class="grid" x1="${L}" x2="${W - R}" y1="${ys(v)}" y2="${ys(v)}"/><text x="${L - 6}" y="${ys(v) + 4}" text-anchor="end">${v}%</text>`).join('');
    const lines = SVCS.map(s => {
      const pts = rows.map((r, i) => [i, r.values[s]]).filter(p => p[1] != null);
      if (!pts.length) return '';
      return `<polyline class="ln s-${s}" points="${pts.map(([i, v]) => `${xs(i).toFixed(1)},${ys(v).toFixed(1)}`).join(' ')}"/>`
        + pts.map(([i, v]) => `<circle class="dot-${s}" cx="${xs(i).toFixed(1)}" cy="${ys(v).toFixed(1)}" r="3.5"><title>${s.toUpperCase()} ${v}% on ${E(when2(rows[i].at))}</title></circle>`).join('');
    }).join('');
    const ticks = rows.map((r, i) => (rows.length <= 8 || i === 0 || i === rows.length - 1) ? `<text x="${xs(i).toFixed(1)}" y="${H - 8}" text-anchor="middle">${E(when2(r.at).slice(5, 10))}</text>` : '').join('');
    const summary = SVCS.map(s => { const v = rows.filter(r => r.values[s] != null); return v.length ? `${s.toUpperCase()} from ${v[0].values[s]}% to ${v[v.length - 1].values[s]}%` : `${s.toUpperCase()} not read`; }).join('; ');
    return `<svg class="zf-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Active share over ${rows.length} saved reads: ${E(summary)}">${grid}${lines}${ticks}</svg>
      <div aria-hidden="true">${SVCS.map(s => `<span class="zf-key"><svg viewBox="0 0 28 8"><line class="ln s-${s}" x1="0" x2="28" y1="4" y2="4" style="fill:none;stroke-width:2.5"/></svg>${s.toUpperCase()}</span>`).join('')}</div>`;
  }
  function deltaHtml(d, higherIsBetter) {
    if (d == null || d === 0) return '';
    const good = higherIsBetter == null ? null : (d > 0) === higherIsBetter;
    return ` <span class="zf-delta${good == null ? '' : good ? ' up' : ' down'}">(${d > 0 ? '+' : '−'}${E(Math.abs(d))})</span>`;
  }
  const BETTER = { devices: null, registered: null, seen_24h: true, never_seen: false, quarantined: false, zia: true, zpa: true, zdx: true };
  function drawHistory() {
    const box = $('zfHistBody'); if (!box || !hist) return;
    const rows = hist.trend.rows;
    setEnabled('zfHistForget', rows.length > 0);
    if (!rows.length) { box.innerHTML = '<p class="zf-dim">Nothing saved yet for this tenant.</p>'; return; }
    const fields = hist.trend.fields;
    const val = (k, v) => (v == null ? '—' : ['zia', 'zpa', 'zdx'].includes(k) ? `${E(v)}%` : E(v));
    const opts = sel => rows.map((r, i) => `<option value="${i}"${i === sel ? ' selected' : ''}>${E(when2(r.at))}${r.source === 'import' ? ' (CSV)' : ''}</option>`).join('');
    box.innerHTML = `${rows.length > 1 ? chartSvg(rows) : '<p class="zf-dim">Save another read later to see a trend.</p>'}
      <div class="zf-wrap"><table class="zf-t"><caption>Saved reads, oldest first; the change since the read before is in brackets.</caption>
      <thead><tr><th scope="col">Read at (UTC)</th>${fields.map(f => `<th scope="col" class="num">${E(f.label)}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(r => `<tr><th scope="row">${E(when2(r.at))}${r.source === 'import' ? ' <span class="zf-chip">CSV</span>' : ''}</th>${fields.map(f => `<td class="num">${val(f.key, r.values[f.key])}${deltaHtml(r.delta[f.key], BETTER[f.key])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
      ${rows.length > 1 ? `<h3>Compare two reads</h3><div class="zf-row"><label>From <select id="zfHistA">${opts(rows.length - 2)}</select></label>
        <label>To <select id="zfHistB">${opts(rows.length - 1)}</select></label><button type="button" class="rp-btn" id="zfHistCompare">Compare</button></div>
        <div id="zfHistCmp" aria-live="polite"></div>` : ''}`;
    if ($('zfHistCompare')) $('zfHistCompare').addEventListener('click', compareHistory);
  }
  function compareTable(d) {
    const rows = d.rows.filter(r => r.a != null || r.b != null);
    return `<p>From <strong>${E(when2(d.a.at))}</strong> to <strong>${E(when2(d.b.at))}</strong>. ${E(d.note)}</p>
      <div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">Group</th><th scope="col">Item</th><th scope="col" class="num">From</th><th scope="col" class="num">To</th><th scope="col" class="num">Change</th></tr></thead>
      <tbody>${rows.map(r => `<tr><td>${E(r.group)}</td><th scope="row">${E(r.item)}${r.change ? ` <span class="zf-chip">${E(r.change)}</span>` : ''}</th><td class="num">${r.a == null ? '—' : E(r.a)}</td><td class="num">${r.b == null ? '—' : E(r.b)}</td><td class="num">${r.delta == null || r.delta === 0 ? '' : `${r.delta > 0 ? '+' : '−'}${E(Math.abs(r.delta))}`}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function render(res, logs) {
    const k = res.kpis, sc = res.scores, t = res.telemetry;
    $('rpMeta').textContent = `${res.tenant_label || ''} · read ${new Date(res.read_at).toLocaleString()}`;
    const svc = s => (k ? k.services[s] : null);
    const order = res.alert_order.map(key => Object.assign({ key }, res.alerts[key]));
    out.innerHTML = `
      <div class="zf-banner ${E(res.mode)}" role="status"><strong>${res.mode === 'full' ? 'Everything was read' : res.mode === 'devices' ? 'Partly read: no per-device service status' : 'No device telemetry'}</strong>${E(res.banner)}</div>
      ${(res.errors || []).length ? `<div class="bp-card warn"><div class="t">Parts that could not be read</div><ul>${res.errors.map(e => `<li>${E(e)}</li>`).join('')}</ul></div>` : ''}
      <section class="zf-sec" aria-labelledby="zfKpiH"><h2 id="zfKpiH">The fleet at a glance</h2>
        <div class="zf-tiles">
          ${tile('Device records', k ? k.devices : null, k ? `${k.registered} registered` : 'No device list')}
          ${tile('Seen in 24 hours', k ? k.seen_24h : null, k ? `of ${k.registered} registered` : '')}
          ${tile('Quarantined', k ? k.quarantined : null, k ? (k.quarantined ? 'Usually a failed posture or compliance check: release or remove them' : 'No device is quarantined') : 'No device list')}
          ${['zia', 'zpa', 'zdx'].map(s => tile(`${s.toUpperCase()} active`, svc(s) ? pct(svc(s).percent) : null, svc(s) ? svc(s).note : 'No device list')).join('')}
          ${tile('Score, equal weight', sc.equal_weight, `${sc.profiles_scored} active profile(s), each counted once`)}
          ${tile('Score, device weighted', sc.device_weighted, sc.device_weighted == null ? 'Needs device telemetry' : `Exposure ${sc.device_weighted_exposure}%`)}
        </div>
        <p class="zf-dim">${E(sc.note)}</p>
        ${k ? `<div class="zf-tiles" style="margin-top:0.6rem;align-items:start">${countTable('Registration state', k.registration_states, k.registration_labels)}${countTable('Platform (registered)', k.os_mix)}</div>
        <details class="zf-details"><summary>Client Connector versions per platform</summary>${Object.entries(k.versions).map(([p, v]) => countTable(`${p} versions (newest ${(k.newest || {})[p] || '—'})`, v)).join('')}</details>` : ''}
        ${t.service_values && t.service_values.length ? `<details class="zf-details"><summary>How the service status was read</summary><p class="zf-dim">The service status file's wording is not documented, so every value seen is listed with how it was read. Columns used: ${E(Object.entries(t.service_columns).map(([s, c]) => `${s.toUpperCase()}: ${c || 'none'}`).join(', '))}.</p>
          <div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">Service</th><th scope="col">Value</th><th scope="col">Read as</th><th scope="col" class="num">Devices</th></tr></thead><tbody>${t.service_values.map(v => `<tr><td>${E(v.service)}</td><td>${E(v.value)}</td><td>${E(SVC[v.read_as] || v.read_as)}</td><td class="num">${v.devices}</td></tr>`).join('')}</tbody></table></div></details>` : ''}
      </section>
      ${res.import ? `<div class="bp-card info"><div class="t">What was imported</div><ul>${res.import.files.map(f => `<li>${E(f.kind)}: ${E(f.rows)} row${f.rows === 1 ? '' : 's'}${f.time ? `, exported ${E(when2(f.time))} UTC` : ''}; columns used: ${E(Object.entries(f.columns).map(([k2, c]) => `${k2.replace(/_/g, ' ')} = ${c}`).join(', '))}.</li>`).join('')}${res.import.notes.map(n => `<li>${E(n)}</li>`).join('')}</ul></div>` : ''}
      ${k ? `<section class="zf-sec" aria-labelledby="zfVerH"><h2 id="zfVerH">Service health by Client Connector version</h2>${versionHtml(res)}</section>
      <section class="zf-sec" aria-labelledby="zfProfHealthH"><h2 id="zfProfHealthH">Health per app and forwarding profile</h2>${profileHealthHtml(res)}</section>
      <section class="zf-sec" aria-labelledby="zfSeenH"><h2 id="zfSeenH">When devices were last seen</h2>${lastSeenHtml(res)}</section>
      <section class="zf-sec" aria-labelledby="zfSiteH"><h2 id="zfSiteH">Sites</h2>${sitesHtml(res)}</section>` : ''}
      <section class="zf-sec" aria-labelledby="zfHistH" id="zfHist"><h2 id="zfHistH">History and trends</h2>${historyHtml(res)}</section>
      <section class="zf-sec" aria-labelledby="zfAlertH"><h2 id="zfAlertH">Alerts</h2>
        <p class="zf-dim">Each alert shows its exact definition. "Not evaluated" means the data it needs could not be read: it is not a zero.</p>
        ${order.map(alertHtml).join('')}
      </section>
      <section class="zf-sec" aria-labelledby="zfHeatH"><h2 id="zfHeatH">Profiles against the checks</h2>${heatmap(res)}
        ${(res.unmatched_profiles || []).length ? `<p class="zf-dim">Devices name app profiles this read did not find: ${E(res.unmatched_profiles.join(', '))}.</p>` : ''}</section>
      <section class="zf-sec" aria-labelledby="zfCmpH"><h2 id="zfCmpH">Compare two profiles</h2>${res.profiles.length > 1 ? compareHtml(res) : '<p class="zf-dim">Needs at least two app profiles.</p>'}</section>
      <section class="zf-sec" aria-labelledby="zfPacH"><h2 id="zfPacH">PAC files compared</h2>${pacHtml(res)}</section>
      <section class="zf-sec" aria-labelledby="zfPlanH"><h2 id="zfPlanH">Remediation plan</h2>${planHtml(res)}</section>
      <section class="zf-sec" aria-labelledby="zfDevH"><h2 id="zfDevH">Devices</h2>${devicesHtml(res)}</section>
      <details class="pa-details"><summary>What was read (${logs.length} line${logs.length === 1 ? '' : 's'})</summary><div class="pa-log">${E(logs.join('\n'))}</div></details>`;
    if ($('zfCompare')) {
      const b = $('zfB'); if (b.options.length > 1) b.selectedIndex = 1;
      $('zfCompare').addEventListener('click', compare);
      $('zfOnlyDiff').addEventListener('change', () => { if ($('zfDiff').innerHTML) compare(); });
    }
    if ($('zfFilter')) { $('zfFilter').addEventListener('input', drawDevices); drawDevices(); }
    if ($('zfSiteMode')) {
      $('zfSiteMode').addEventListener('change', siteFormShow); siteFormShow();
      $('zfSiteApply').addEventListener('click', applySites);
    }
    if ($('zfHistSave')) { $('zfHistSave').addEventListener('click', saveHistory); $('zfHistForget').addEventListener('click', forgetHistory); }
  }

  // format csv (one table) or xlsx (every table in one workbook; `what` ignored).
  async function exportCsv(what, format) {
    if (!lastJob) return;
    const counts = $('zfCounts').checked;
    const fmt = format || 'csv';
    try {
      const r = await fetch(`/api/zcc/fleet/${encodeURIComponent(lastJob)}/export?what=${what}&counts_only=${counts}&format=${fmt}`, { cache: 'no-store' });
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(errText(d, r.status)); }
      const cd = r.headers.get('Content-Disposition') || '';
      const name = ((cd.match(/filename="?([^";]+)"?/) || [])[1]) || `zcc_fleet_${what}.${fmt}`;
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      say(`Downloaded ${name}.`);
    } catch (e) { say(`Export failed: ${e.message}`); alert(`Export failed: ${e.message}`); }
  }
  $('zfCounts').addEventListener('change', () => { setEnabled('zfExpDevices', !!(last && last.devices.length) && !$('zfCounts').checked); });
  $('zfExpPlan').addEventListener('click', () => exportCsv('plan'));
  $('zfExpDevices').addEventListener('click', () => exportCsv('devices'));
  $('zfExpSummary').addEventListener('click', () => exportCsv('summary'));
  $('zfExpXlsx').addEventListener('click', () => exportCsv('all', 'xlsx'));
  $('zfRun').addEventListener('click', () => run());
  $('zfExpPdf').addEventListener('click', () => exportCsv('all', 'pdf'));

  // ── Install command builder (POST /api/zcc/install): secrets masked unless revealed ──
  let instCat = null, instOut = null, reveal = false;
  async function instLoad() {
    try { const r = await fetch('/api/zcc/install/catalog', { cache: 'no-store' }); if (r.ok) instCat = await r.json(); } catch (e) { instCat = null; }
    instForm();
  }
  function instForm() {
    const plat = $('zfInstPlat').value;
    const types = (instCat && instCat.installer_types[plat]) || (plat === 'macos' ? ['app'] : ['msi', 'exe']);
    $('zfInstType').innerHTML = types.map(t => `<option value="${E(t)}">${E(t === 'app' ? 'macOS app' : t.toUpperCase())}</option>`).join('');
    const params = ((instCat && instCat.params) || []).filter(p => (plat === 'macos' ? p.mac : (p.msi || p.exe)) && p.key !== 'policyToken');
    $('zfInstOpts').innerHTML = params.map(p => {
      const id = `zfIo_${E(p.key)}`;
      if (p.type === 'toggle' || p.type === 'toggle_on') return `<label title="${E(p.help)}"><input type="checkbox" id="${id}" data-k="${E(p.key)}"${p.type === 'toggle_on' ? ' checked' : ''}> ${E(p.label)}</label>`;
      if (p.type === 'cloud') return `<label title="${E(p.help)}">${E(p.label)} <select id="${id}" data-k="${E(p.key)}"><option value="">Not set</option>${(instCat.clouds || []).map(c => `<option value="${E(c)}">${E(c)}</option>`).join('')}</select></label>`;
      return `<label title="${E(p.help)}">${E(p.label)} <input type="${p.secret ? 'password' : 'search'}" id="${id}" data-k="${E(p.key)}" maxlength="256" autocomplete="off"></label>`;
    }).join('');
    instProfiles();
  }
  function instProfiles() {
    const plat = $('zfInstPlat').value, sel = $('zfInstProfile');
    const rows = ((last && last.profiles) || []).filter(p => p.id != null && String(p.platform || '').toLowerCase() === plat);
    sel.innerHTML = '<option value="">None (no policy token)</option>' + rows.map(p => `<option value="${E(p.id)}">${E(p.name)}</option>`).join('');
    if (!rows.length) sel.title = 'Read the fleet first to pick an app profile.';
  }
  async function instBuild() {
    const values = {};
    $('zfInstOpts').querySelectorAll('[data-k]').forEach(el => { values[el.dataset.k] = el.type === 'checkbox' ? el.checked : el.value; });
    const payload = Object.assign({}, $('zfInstProfile').value ? Object.assign({}, credBody(), scopeSelection()) : {},
      { platform: $('zfInstPlat').value, installer: $('zfInstType').value, installer_name: $('zfInstName').value.trim(),
        app_profile_id: $('zfInstProfile').value, values, reveal });
    const st = $('zfInstStatus'); st.textContent = $('zfInstProfile').value ? 'Reading the app profile\'s policy token…' : 'Building…';
    try {
      const r = await fetch('/api/zcc/install', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      instOut = d;
      const pre = $('zfInstCmd'); pre.hidden = false; pre.textContent = d.command;
      const notes = [...(d.errors || []).map(x => `Fix: ${x}`), ...(d.warnings || [])];
      st.textContent = (d.masked && d.masked.length ? `Masked: ${d.masked.join(', ')}. ` : d.revealed ? 'Secrets are shown: copy them only where they belong. ' : '') + (notes.join(' ') || 'Ready.');
      st.classList.toggle('bad', !!(d.errors || []).length);
      setEnabled('zfInstCopy', true); setEnabled('zfInstSave', true);
      say(d.errors && d.errors.length ? `The command needs fixing: ${d.errors[0]}` : 'Install command built.');
    } catch (e) { st.textContent = `The command could not be built: ${e.message}`; st.classList.add('bad'); say(st.textContent); }
  }
  $('zfInstPlat').addEventListener('change', instForm);
  $('zfInstBuild').addEventListener('click', instBuild);
  // A change to the form makes the built command stale: Copy and Download wait for the next build.
  const instStale = () => {
    if (!instOut) return;
    instOut = null; $('zfInstCmd').hidden = true; setEnabled('zfInstCopy', false); setEnabled('zfInstSave', false);
    const st = $('zfInstStatus'); st.classList.remove('bad'); st.textContent = 'The form changed: build the command again.';
  };
  ['input', 'change'].forEach(ev => $('zfInstall').addEventListener(ev, e => { if (e.target && e.target.closest('#zfInstOpts, #zfInstPlat, #zfInstType, #zfInstName, #zfInstProfile')) instStale(); }));
  $('zfInstReveal').addEventListener('click', () => {
    reveal = !reveal;
    $('zfInstReveal').setAttribute('aria-pressed', reveal ? 'true' : 'false');
    $('zfInstReveal').textContent = reveal ? 'Mask secrets' : 'Reveal secrets';
    if (instOut) instBuild();
  });
  $('zfInstCopy').addEventListener('click', async () => {
    if (!instOut) return;
    try { await navigator.clipboard.writeText(instOut.command); say(instOut.masked && instOut.masked.length ? 'Copied, with the secrets masked.' : 'Copied.'); }
    catch (e) { say('Copy is blocked in this browser: select the command and copy it.'); }
  });
  $('zfInstSave').addEventListener('click', () => {
    if (!instOut) return;
    const url = URL.createObjectURL(new Blob([instOut.script], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = instOut.script_name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    say(instOut.masked && instOut.masked.length ? `Downloaded ${instOut.script_name}, with the secrets masked: reveal them first for a script that runs as is.` : `Downloaded ${instOut.script_name}.`);
  });
  instLoad();
  tenantChoices();
})();
