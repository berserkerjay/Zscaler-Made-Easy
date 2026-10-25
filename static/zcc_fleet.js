/* Client Connector fleet (/report/fleet): starts the read-only fleet job,
 * follows it with Stop, and renders KPIs, alerts with their definitions,
 * the profile heatmap, profile compare, PAC compare, the remediation plan
 * and the device table. User and device names are shown here only; the
 * exports offer a counts-only form. */
(function () {
  'use strict';
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
  async function run() {
    if (running) return;
    running = true; stopAsked = false; startToken = newStartToken(); job = null;
    const btn = $('zfRun'); btn.disabled = true; btn.textContent = 'Reading…';
    ['zfExpPlan', 'zfExpDevices', 'zfExpSummary', 'zfExpXlsx'].forEach(id => setEnabled(id, false));
    out.innerHTML = liveHtml();
    $('zfStop').addEventListener('click', stop);
    status('');
    say('Reading the Client Connector fleet.');
    const t0 = Date.now();
    const tick = setInterval(() => { const el = $('zfElapsed'); if (el) el.textContent = mmss((Date.now() - t0) / 1000); }, 1000);
    try {
      const r = await fetch('/api/zcc/fleet/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken },
        body: JSON.stringify(Object.assign({}, credBody(), scopeSelection())) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
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
      ['zfExpPlan', 'zfExpSummary', 'zfExpXlsx'].forEach(id => setEnabled(id, true));
      setEnabled('zfExpDevices', !!(last.devices || []).length);
      say(`Fleet read. ${last.banner}`);
    } catch (e) {
      const stopped = !!e.stopped;
      out.innerHTML = `<div class="bp-card ${stopped ? 'info' : 'risk'}" role="alert"><div class="t">${stopped ? 'Stopped' : 'The fleet could not be read'}</div><div>${E(e.message)}${/credential|sign in|401|403|profile/i.test(e.message) ? ' Sign in on the assessment page first and open this page from there, or choose a saved tenant profile in the bar above.' : ''}</div></div>`;
      say(stopped ? 'Stopped.' : `The fleet could not be read: ${e.message}`);
    } finally {
      clearInterval(tick); running = false; job = null; startToken = null; stopAsked = false; btn.disabled = false; btn.textContent = 'Read the fleet';
    }
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
  function when(d) { return d.last_seen ? `${E(d.last_seen.replace('T', ' ').slice(0, 16))} (${d.hours_since_seen} h)` : 'never'; }
  function deviceRows(rows, extra) {
    if (!rows.length) return '<p class="zf-dim">None.</p>';
    return `<div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">User</th><th scope="col">Device</th><th scope="col">Platform</th><th scope="col">Version</th><th scope="col">Last seen (UTC)</th><th scope="col">App profile</th><th scope="col">ZIA</th><th scope="col">ZPA</th>${extra ? `<th scope="col">${E(extra[0])}</th>` : ''}</tr></thead><tbody>
      ${rows.map(d => `<tr><td>${E(d.user)}</td><td>${E(d.hostname)}</td><td>${E(d.platform)}</td><td>${E(d.version)}</td><td>${when(d)}</td><td>${E(d.profile)}</td><td>${E(SVC[d.services.zia] || d.services.zia)}</td><td>${E(SVC[d.services.zpa] || d.services.zpa)}</td>${extra ? `<td>${E(d[extra[1]])}</td>` : ''}</tr>`).join('')}
    </tbody></table></div>`;
  }
  function alertHtml(a) {
    const count = !a.evaluated ? '<span class="zf-chip">not evaluated</span>' : `<span class="zf-count">${a.count}</span>`;
    let body;
    if (!a.evaluated) body = `<p>${E(a.why_not)}</p>`;
    else if (a.key === 'multi_device') {
      body = a.rows.length ? `<div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">User</th><th scope="col" class="num">Registered devices</th><th scope="col">Devices</th><th scope="col">Platforms</th></tr></thead><tbody>
        ${a.rows.map(u => `<tr><td>${E(u.user)}</td><td class="num">${u.devices}</td><td>${E(u.hostnames.join(', '))}</td><td>${E(u.platforms.join(', '))}</td></tr>`).join('')}</tbody></table></div>` : '<p class="zf-dim">None.</p>';
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
      ${rows.map(([k, n]) => `<tr><th scope="row">${E((labels || {})[k] || k)}</th><td class="num">${n}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function heatmap(res) {
    const cols = res.checks;
    const profs = res.profiles;
    if (!profs.length) return '<p class="zf-dim">No app profile was read.</p>';
    return `<div class="zf-legend" aria-hidden="true">${Object.keys(STATUS).map(s => cell(s, '')).join('')}</div>
      <div class="zf-wrap"><table class="zf-t zf-heat"><caption>Each cell says pass, warn, fail, unknown or not applicable; hover or read the list below for the reason.</caption>
      <thead><tr><th scope="col">App profile</th><th scope="col" class="num">Devices</th><th scope="col" class="num">Score</th>${cols.map(c => `<th scope="col" title="${E(c.definition)}">${E(c.label)}</th>`).join('')}</tr></thead>
      <tbody>${profs.map(p => `<tr><th scope="row">${E(p.name)} <span class="zf-dim">${E(p.platform)}${p.active ? '' : ', inactive'}</span></th>
        <td class="num">${p.devices == null ? '—' : p.devices}</td><td class="num">${p.score == null ? '—' : p.score}</td>
        ${cols.map(c => { const x = p.checks[c.key] || { status: 'unknown', detail: '' }; return `<td>${cell(x.status, x.detail)}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>
      <details class="zf-details"><summary>Why each profile fails or warns</summary>
        ${profs.map(p => { const bad = cols.filter(c => p.checks[c.key] && ['fail', 'warn', 'unknown'].includes(p.checks[c.key].status));
          return bad.length ? `<h3>${E(p.name)} (${E(p.platform)})</h3><ul>${bad.map(c => `<li><strong>${E(c.label)}</strong> (${E(STATUS[p.checks[c.key].status][0])}): ${E(p.checks[c.key].detail)}</li>`).join('')}</ul>` : ''; }).join('')}
      </details>
      <details class="zf-details"><summary>What each check means</summary><dl>${cols.map(c => `<dt><strong>${E(c.label)}</strong> (impact ${c.impact})</dt><dd>${E(c.definition)}</dd>`).join('')}</dl></details>`;
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
    $('zfDiff').innerHTML = `<p>${d.differences} setting${d.differences === 1 ? '' : 's'} differ between <strong>${E(d.a)}</strong> and <strong>${E(d.b)}</strong>. Passwords and secrets show only whether they are set.</p>
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
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      renderDiff(d); say(`${d.differences} settings differ.`);
    } catch (e) { $('zfDiff').innerHTML = `<p class="zf-status bad">${E(e.message)}</p>`; }
  }
  function pacHtml(res) {
    const m = res.pac.matrix, files = res.pac.files;
    const head = files.length ? `<p class="zf-dim">${files.length} hosted PAC file${files.length === 1 ? '' : 's'} read; ${m.risky} risky DIRECT entr${m.risky === 1 ? 'y' : 'ies'}; ${m.differing} entr${m.differing === 1 ? 'y differs' : 'ies differ'} between profiles. A PAC that is not hosted in ZIA cannot be read here: drop it into the Log analyzer.</p>` : '<p class="zf-dim">No hosted PAC file was read.</p>';
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
      <tbody>${res.plan.map(x => `<tr><td class="num">${x.rank}</td><td>${cell(x.status, x.detail)} <strong>${E(x.title)}</strong><div class="why">${E(x.detail)}</div></td>
        <td class="num">${x.devices == null ? 'unknown' : x.devices}</td><td class="num">${x.priority}</td><td class="fix">${E(x.fix)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function devicesHtml(res) {
    if (!res.devices.length) return '<p class="zf-dim">No device list (see the note at the top).</p>';
    return `<div class="zf-row"><label for="zfFilter">Filter</label><input type="search" id="zfFilter" placeholder="User, device, profile or version" autocomplete="off">
      <span class="zf-dim" id="zfShown"></span></div><div id="zfDevTable"></div>
      ${res.devices_truncated ? `<p class="zf-dim">The first ${res.devices.length} of ${res.devices_total} devices are kept for this page and the device export; every figure above counts all of them.</p>` : ''}`;
  }
  function drawDevices() {
    const q = ($('zfFilter') ? $('zfFilter').value : '').trim().toLowerCase();
    const all = last.devices.filter(d => !q || [d.user, d.hostname, d.profile, d.version, d.platform].some(v => String(v || '').toLowerCase().includes(q)));
    const rows = all.slice(0, 500);
    $('zfDevTable').innerHTML = deviceRows(rows, ['Registration', 'registration']);
    $('zfShown').textContent = `${all.length} device${all.length === 1 ? '' : 's'}${all.length > rows.length ? `, first ${rows.length} shown` : ''}`;
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
          ${['zia', 'zpa', 'zdx'].map(s => tile(`${s.toUpperCase()} active`, svc(s) ? pct(svc(s).percent) : null, svc(s) ? svc(s).note : 'No device list')).join('')}
          ${tile('Score, equal weight', sc.equal_weight, `${sc.profiles_scored} active profile(s), each counted once`)}
          ${tile('Score, device weighted', sc.device_weighted, sc.device_weighted == null ? 'Needs device telemetry' : `Exposure ${sc.device_weighted_exposure}%`)}
        </div>
        <p class="zf-dim">${E(sc.note)}</p>
        ${k ? `<div class="zf-tiles" style="margin-top:0.6rem;align-items:start">${countTable('Registration state', k.registration_states, k.registration_labels)}${countTable('Platform (registered)', k.os_mix)}</div>
        <details class="zf-details"><summary>Client Connector versions per platform</summary>${Object.entries(k.versions).map(([p, v]) => countTable(`${p} versions (newest ${k.newest[p] || '—'})`, v)).join('')}</details>` : ''}
        ${t.service_values && t.service_values.length ? `<details class="zf-details"><summary>How the service status was read</summary><p class="zf-dim">The service status file's wording is not documented, so every value seen is listed with how it was read. Columns used: ${E(Object.entries(t.service_columns).map(([s, c]) => `${s.toUpperCase()}: ${c || 'none'}`).join(', '))}.</p>
          <div class="zf-wrap"><table class="zf-t"><thead><tr><th scope="col">Service</th><th scope="col">Value</th><th scope="col">Read as</th><th scope="col" class="num">Devices</th></tr></thead><tbody>${t.service_values.map(v => `<tr><td>${E(v.service)}</td><td>${E(v.value)}</td><td>${E(SVC[v.read_as] || v.read_as)}</td><td class="num">${v.devices}</td></tr>`).join('')}</tbody></table></div></details>` : ''}
      </section>
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
  }

  // format csv (one table) or xlsx (every table in one workbook; `what` ignored).
  async function exportCsv(what, format) {
    if (!lastJob) return;
    const counts = $('zfCounts').checked;
    const fmt = format || 'csv';
    try {
      const r = await fetch(`/api/zcc/fleet/${encodeURIComponent(lastJob)}/export?what=${what}&counts_only=${counts}&format=${fmt}`, { cache: 'no-store' });
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
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
  $('zfRun').addEventListener('click', run);
  tenantChoices();
})();
