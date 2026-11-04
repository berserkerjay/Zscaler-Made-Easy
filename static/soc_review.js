// SOC review (static/report_soc_review.html): the RBAC review and the
// telemetry review (soc_review.py), each read once as a job the page
// follows. Read-only. Every value reaches the page through textContent.
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const body = $('scBody'), meta = $('rpMeta'), live = $('liveRegion');
  if (!body) return;
  const say = t => { live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  const STATUSES = [['fail', 'Fix'], ['review', 'Review'], ['pass', 'As recommended'], ['unknown', 'Unknown'], ['na', 'Not applicable']];
  const ST_WORD = Object.fromEntries(STATUSES);
  const ST_CLS = { fail: 'st-fail', review: 'st-warn', pass: 'st-pass', unknown: '', na: '' };
  const ACCESS = { full: 'Full', scoped: 'Limited', read_only: 'Read-only', unknown: 'Unknown' };
  const STATE = { read: 'Read', derived: 'From ZIdentity', not_in_scope: 'Not ticked on the Scope page', not_permitted: 'Not permitted',
    not_available: 'Not available', not_readable: 'Could not be read', unknown: 'Not in the API' };
  const PARTS = { rbac: { url: '/api/soc-review/rbac/start', what: 'admin access' }, telemetry: { url: '/api/soc-review/telemetry/start', what: 'logging' } };
  let running = false, job = null, startToken = null, stopAsked = false, stFilter = '', last = null, lastLogs = [];

  // ── DOM helpers: text only, never HTML ─────────────────────────────
  function el(tag, attrs, kids) {
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (v == null || v === false) return;
      if (k === 'text') n.textContent = String(v);
      else if (k === 'cls') n.className = v;
      else n.setAttribute(k, v === true ? '' : String(v));
    });
    (kids || []).forEach(k => { if (k != null) n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k); });
    return n;
  }
  const clear = n => { while (n.firstChild) n.removeChild(n.firstChild); };
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x;
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  function newStartToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }

  // ── tenant and scope, as the other report pages send them ──────────
  async function tenantChoices() {
    const wrap = $('scTenantWrap'), sel = $('scTenant');
    const fromOpener = !!(window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function');
    let profiles = [];
    try { const r = await fetch('/api/tenant-profiles', { cache: 'no-store' }); if (r.ok) profiles = ((await r.json()).profiles || []); } catch (e) { /* none */ }
    const opts = [];
    if (fromOpener) opts.push(['opener', 'Signed in on the assessment tab']);
    profiles.forEach(p => opts.push([`profile:${p.id}`, `${p.name || p.vanity_domain || p.id}${p.has_secret === false ? ' (no remembered secret)' : ''}`]));
    opts.push(['server', 'Saved on this computer (environment or tenant_config.json)']);
    clear(sel);
    opts.forEach(([v, l]) => sel.appendChild(el('option', { value: v, text: l })));
    wrap.hidden = opts.length < 2;
  }
  function credBody() {
    const v = $('scTenant').value || 'server';
    if (v === 'opener' && window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function') return window.opener.migrateCredBody();
    if (v.startsWith('profile:')) return { profile_id: v.slice(8) };
    return {};
  }
  function readJson(key, fallback) {
    try { const raw = localStorage.getItem(key); const v = raw ? JSON.parse(raw) : fallback; return v == null ? fallback : v; } catch (e) { return fallback; }
  }
  function scopeSelection() {
    let scopes = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    if (!Array.isArray(scopes)) { const lv = readJson('zassess_scopes_live_v1', null); scopes = lv && Array.isArray(lv.scopes) ? lv.scopes : null; }
    if (!Array.isArray(scopes)) return { scopes: [], channels: {}, from_page: false };
    return { scopes: scopes.map(String), channels: {}, from_page: true };
  }

  // ── the job ────────────────────────────────────────────────────────
  const mmss = s => { s = Math.max(0, Math.round(s || 0)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
  function liveBox(what) {
    clear(body);
    body.appendChild(el('div', { cls: 'pa-live' }, [
      el('div', { cls: 'pa-live-h' }, [el('span', { cls: 'spin', 'aria-hidden': 'true' }), el('strong', { text: `Reading ${what}` }),
        el('span', { cls: 'sep' }), el('span', { cls: 'pa-elapsed', id: 'scElapsed', text: '0:00' }),
        el('button', { type: 'button', cls: 'rp-btn', id: 'scStop', text: 'Stop' })]),
      el('div', { cls: 'pa-log pa-log-live', id: 'scLog', role: 'log', 'aria-live': 'polite', 'aria-label': 'What the read is doing', text: 'Connecting to the tenant…' })]));
    $('scStop').addEventListener('click', stop);
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
      const log = $('scLog'); if (log) { log.textContent = logs.join('\n') || 'Connecting to the tenant…'; log.scrollTop = log.scrollHeight; }
      if (snap.status !== 'running') return Object.assign({}, snap, { logs });
    }
  }
  async function stop() {
    if (!running || stopAsked) return;
    stopAsked = true;
    const b = $('scStop'); if (b) { b.disabled = true; b.textContent = 'Stopping…'; }
    if (!job) {
      try { await fetch('/api/dlp-packs/jobs/stop-before-start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_token: startToken }) }); } catch (e) { /* cancelled by id */ }
      return;
    }
    try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows it */ }
  }
  async function run(part) {
    if (running) return;
    const p = PARTS[part], buttons = [$('scRbacRun'), $('scTelRun')];
    running = true; stopAsked = false; startToken = newStartToken(); stFilter = '';
    buttons.forEach(b => { b.disabled = true; });
    liveBox(p.what);
    say(`Reading ${p.what}.`);
    const t0 = Date.now();
    const tick = setInterval(() => { const e = $('scElapsed'); if (e) e.textContent = mmss((Date.now() - t0) / 1000); }, 1000);
    try {
      const r = await fetch(p.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken },
        body: JSON.stringify(Object.assign({}, credBody(), scopeSelection())) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      job = d.job_id;
      if (stopAsked) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* token */ } }
      const snap = await follow(job);
      if (snap.status !== 'done' || !snap.result || snap.result.status !== 'done') {
        throw new Error((snap.result && snap.result.stopped) || snap.error || (snap.status === 'cancelled' ? 'You clicked Stop before the read finished.' : 'The read did not finish.'));
      }
      last = snap.result; lastLogs = snap.logs || [];
      render();
      const c = last.counts || {};
      say(`${c.fail || 0} to fix, ${c.review || 0} to review, ${c.unknown || 0} unknown.`);
    } catch (e) {
      clear(body);
      const stopped = /You clicked Stop|Stopped/.test(e.message);
      body.appendChild(el('div', { cls: 'bp-card risk' }, [el('div', { cls: 't', text: stopped ? 'Stopped' : 'The read could not run' }), el('div', { text: e.message })]));
      say(`The read could not run: ${e.message}`);
    } finally {
      clearInterval(tick); running = false; job = null; startToken = null; stopAsked = false;
      buttons.forEach(b => { b.disabled = false; });
    }
  }

  // ── the result ─────────────────────────────────────────────────────
  const chip = st => el('span', { cls: `df-chip ${ST_CLS[st] || ''}`, text: ST_WORD[st] || st });
  const yes = (v, goodYes, unknown) => v === true ? el('span', { cls: goodYes ? 'sc-ok' : 'sc-bad', text: 'Yes' })
    : v === false ? el('span', { cls: goodYes ? 'sc-bad' : 'sc-ok', text: 'No' }) : el('span', { cls: 'sc-dim', text: unknown || 'not reported' });
  function table(caption, heads, rows, empty) {
    if (!rows.length) return el('div', { cls: 'df-hop-d pa-none', text: empty });
    const cell = c => (c instanceof Node ? c : document.createTextNode(c == null ? '' : String(c)));
    return el('div', { cls: 'df-tablewrap' }, [el('table', { cls: 'df-table' }, [
      el('caption', { cls: 'sr-only', text: caption }),
      el('thead', {}, [el('tr', {}, heads.map(h => el('th', { scope: 'col', text: h })))]),
      el('tbody', {}, rows.map(r => el('tr', {}, [el('th', { scope: 'row' }, [cell(r[0])])].concat(r.slice(1).map(c => el('td', {}, [cell(c)]))))))])]);
  }
  function stats(c, extra) {
    const tiles = [['st-fail', c.fail, 'Fix'], ['st-review', c.review, 'Review'], ['st-pass', c.pass, 'As recommended'], ['', c.unknown, 'Unknown']].concat(extra || []);
    return el('div', { cls: 'sc-stats' }, tiles.map(([cls, n, k]) => el('div', { cls: `sc-stat ${cls}` }, [el('div', { cls: 'n', text: n == null ? 0 : n }), el('div', { cls: 'k', text: k })])));
  }
  function findingsBlock(list, label) {
    const order = { fail: 0, review: 1, unknown: 2, pass: 3, na: 4 };
    const all = list.slice().sort((a, b) => order[a.status] - order[b.status]);
    const shown = all.filter(f => !stFilter || f.status === stFilter);
    const bar = el('div', { cls: 'sh-filter sc-filter', role: 'group', 'aria-label': `Show ${label} by result` },
      [['', 'All']].concat(STATUSES).map(([s, l]) => {
        const b = el('button', { type: 'button', cls: `rp-btn${stFilter === s ? ' primary' : ''}`, 'data-st': s, 'aria-pressed': String(stFilter === s),
          text: `${l} (${all.filter(f => !s || f.status === s).length})` });
        b.addEventListener('click', () => { stFilter = s; render(); const again = body.querySelector(`.sc-filter button[data-st="${s}"]`); if (again) again.focus(); say(`Showing ${s ? ST_WORD[s] : 'all'}.`); });
        return b;
      }));
    const items = shown.map(f => el('li', { cls: `pa-impact sev-${f.status === 'fail' ? 'high' : f.status === 'review' ? 'medium' : 'low'}` }, [
      el('div', { cls: 'df-hop-h' }, [chip(f.status), el('strong', { text: f.title || f.label }), el('span', { cls: 'df-by', text: f.id })]),
      el('div', { cls: 'df-hop-d', text: f.detail }),
      f.fix && (f.status === 'fail' || f.status === 'review') ? el('div', { cls: 'df-hop-d pa-fix' }, [el('strong', { text: 'How to fix: ' }), f.fix]) : null]));
    return [bar, items.length ? el('ol', { cls: 'pa-impacts' }, items) : el('div', { cls: 'df-hop-d pa-none', text: 'Nothing with this result.' })];
  }
  function section(id, title, kids) {
    return el('section', { cls: 'sc-sec', 'aria-labelledby': id }, [el('h2', { cls: 'df-h', id, text: title })].concat(kids));
  }
  function productState(p) {
    return el('div', { cls: 'df-hint' }, [el('strong', { text: `${STATE[p.state] || p.state}. ` }), p.why || '']);
  }
  function rbacProduct(p) {
    const kids = [productState(p)];
    if (p.state === 'read' || p.state === 'derived') {
      const c = p.counts || {};
      kids.push(el('div', { cls: 'df-hop-d', text: `${c.enabled || 0} enabled admin(s): ${c.full || 0} full, ${c.scoped || 0} limited, ${c.read_only || 0} read-only; ${c.disabled || 0} disabled.` }));
      kids.push(table(`${p.name} admins`, ['Admin', 'Role', 'Rights', 'Scope', 'Enabled', 'Second factor', 'Last sign-in'],
        (p.admins || []).map(a => [a.name, a.role, ACCESS[a.access] || a.access, a.scope, yes(a.enabled, true),
          a.mfa === null || a.mfa === undefined ? el('span', { cls: 'sc-dim', text: a.mfa_note || 'not reported' }) : yes(a.mfa, true),
          a.last_sign_in || el('span', { cls: 'sc-dim', text: 'not reported' })]), 'No admin is listed.'));
      if ((p.roles || []).length) kids.push(table(`${p.name} roles`, ['Role', 'Rights'].concat(p.key === 'zia' ? ['Rank'] : []),
        p.roles.map(r => [r.name, ACCESS[r.kind] || r.kind].concat(p.key === 'zia' ? [r.rank == null ? '' : r.rank] : [])), ''));
      if (p.admin_rank) kids.push(el('div', { cls: 'df-hint', text: `Admin Ranking: ${p.admin_rank.state}${p.admin_rank.why ? ` (${p.admin_rank.why})` : ''}.` }));
      if ((p.api_clients || []).length) kids.push(table(`${p.name} API keys and clients`, ['Name', 'Kind', 'Enabled', 'Rights', 'Scopes or role', 'Token lifetime (s)'],
        p.api_clients.map(k => [k.name, k.kind, yes(k.enabled, true), k.broad ? el('span', { cls: 'sc-bad', text: 'Full' }) : (ACCESS[k.access] || k.access),
          (k.scopes || []).join(', ') || k.role || '', k.token_lifetime_seconds == null ? '' : k.token_lifetime_seconds]), ''));
      if (p.api_note) kids.push(el('div', { cls: 'df-hint', text: p.api_note }));
      if (p.break_glass) kids.push(el('div', { cls: 'df-hint', text: `Emergency access accounts: ${p.break_glass.accounts}, ${p.break_glass.active} active, last used ${p.break_glass.last_used || 'never reported'}.` }));
    }
    return section(`scP_${p.key}`, p.name, kids);
  }
  function telProduct(p) {
    const kids = [productState(p)];
    if (p.state === 'read') {
      if (p.key === 'zia' || p.key === 'zpa') {
        kids.push(table(`${p.name} log streams`, ['Stream', 'Kind', 'Log type', 'Enabled', 'Destination', 'SIEM', 'TLS', 'Read on the Traffic logs page'],
          (p.streams || []).map(s => [s.name, s.kind, s.log_type, yes(s.enabled, true), s.destination || el('span', { cls: 'sc-dim', text: 'not reported' }),
            s.siem || '', s.tls === null || s.tls === undefined ? '' : yes(s.tls, true), s.traffic_logs || '']), 'No log stream is configured.'));
      }
      if (p.key === 'zia') {
        kids.push(table('NSS servers', ['NSS server', 'Type', 'Status', 'Health'], (p.servers || []).map(s => [s.name, s.type, s.status,
          s.health === 'down' ? el('span', { cls: 'sc-bad', text: 'down' }) : s.health]), 'No NSS server is registered.'));
        kids.push(el('div', { cls: 'df-hint', text: `NSS collectors: ${p.collectors || 0}. Log streaming licensed: ${p.licensed === null || p.licensed === undefined ? 'not known' : p.licensed ? 'yes' : 'no'}.` }));
      }
      if (p.key === 'zcc') {
        kids.push(table('App profile log settings', ['App profile', 'Log mode', 'Log level', 'Log file size (MB)'],
          (p.profiles || []).map(x => [x.name, x.log_mode || el('span', { cls: 'sc-dim', text: 'not reported' }), x.log_level == null ? '' : x.log_level,
            x.log_file_size_mb == null ? '' : x.log_file_size_mb]), 'No app profile was read.'));
        const st = p.settings || {};
        kids.push(table('Client Connector log settings', ['Setting', 'Value'], [['Telemetry', yes(st.telemetry, true)], ['Admins can fetch device logs', yes(st.admins_fetch_logs, true)],
          ['Flow logger', yes(st.flow_logger, true)], ['Logging controls hidden from users', yes(st.logging_controls_hidden, true)]], ''));
      }
    }
    return section(`scP_${p.key}`, p.name, kids);
  }
  function render() {
    const res = last, c = res.counts || {}, rbac = res.kind === 'soc-rbac';
    meta.textContent = `${res.tenant_label || ''} · ${rbac ? 'admin access' : 'logging'} · ${c.fail || 0} to fix, ${c.review || 0} to review`;
    clear(body);
    const extra = rbac ? [['', (res.products || []).reduce((n, p) => n + ((p.counts || {}).enabled || 0), 0), 'Enabled admins (all products)']]
      : [['', (res.destinations || []).length, 'Destinations']];
    body.appendChild(stats(c, extra));
    body.appendChild(el('div', { cls: 'sc-note' }, [el('strong', { text: 'In short' }), el('ul', {}, (res.summary || []).map(l => el('li', { text: l })))]));
    body.appendChild(section('scFindH', 'Findings', findingsBlock(res.findings || [], 'findings')));
    (res.products || []).forEach(p => body.appendChild(rbac ? rbacProduct(p) : telProduct(p)));
    if (!rbac) {
      body.appendChild(section('scDestH', 'Where the logs go', [table('Log destinations', ['Destination', 'Kind', 'Products', 'Log types', 'Enabled streams', 'Ready-made queries'],
        (res.destinations || []).map(d => [d.destination, d.kind, (d.products || []).join(', '), (d.log_types || []).join(', '), d.enabled_streams, d.queries || '']),
        'No log destination is configured.')]));
    }
    const checks = (res.checks || []).map(x => Object.assign({ title: x.label }, x));
    body.appendChild(section('scChecksH', 'Assessment checks used', [table('Assessment checks used', ['Check', 'Result', 'What it found'],
      checks.map(x => [`${x.id} ${x.label}`, chip(x.status), x.detail]), 'No assessment check ran.')]));
    body.appendChild(el('details', { cls: 'pa-details' }, [el('summary', { text: `Assumptions (${(res.assumptions || []).length})` }),
      el('ul', {}, (res.assumptions || []).map(a => el('li', { text: a })))]));
    body.appendChild(el('details', { cls: 'pa-details' }, [el('summary', { text: `What was read (${lastLogs.length} line${lastLogs.length === 1 ? '' : 's'})` }),
      el('div', { cls: 'pa-log', text: lastLogs.join('\n') })]));
  }

  $('scRbacRun').addEventListener('click', () => run('rbac'));
  $('scTelRun').addEventListener('click', () => run('telemetry'));
  tenantChoices();
})();
