// Path analyzer: the "Test a list" view (bulk_test.py on the server).
//
// The page's two views are ARIA tabs (arrow keys, Home, End, roving
// tabindex): "One destination or a HAR file" (the page's analysis, in
// its own panel) and "Test a list".
// A CSV file is read in this browser and only its text is sent to
// /api/bulk-test/start, with the Network, Platform and Tenant of the bar
// and the Scope page's selection; the job is followed and its summary
// drawn: counts, the deciding rules and categories, the rows that need a
// look, what the file expected, the downloads and a list per area.
// "Fix selected" opens Bulk changes with a URL category change filled in:
// it never writes on its own.
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const MAX_BYTES = 8 * 1024 * 1024;
  const RESULT_LABEL = { blocked: 'Blocked', allowed: 'Allowed', bypassed: 'Bypassed', isolated: 'Isolated', caution: 'Caution',
    allowed_but_blockable: 'Allowed but blockable', unverified: 'Unverified', not_tested: 'Not tested' };
  const RESULT_CLS = { blocked: '', allowed: 'mute', bypassed: 'bad', isolated: 'warn', caution: 'warn', allowed_but_blockable: 'warn', unverified: 'warn', not_tested: 'mute' };
  const AREA_KEY = { 'ATP': 'atp', 'Firewall': 'firewall', 'URL': 'url', 'DNS': 'dns', 'Client Connector': 'client_connector', 'Cloud App': 'cloud_app', 'ZPA': 'zpa' };
  const FIX_AREAS = ['URL', 'DNS', 'Cloud App'];
  const live = $('liveRegion');
  const say = t => { if (!live) return; live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  if (!$('panel-list') || !$('panel-one')) return;

  // ── the tabs ────────────────────────────────────────────────────────
  const tabs = Array.from(document.querySelectorAll('.rp-tabs [role="tab"]'));
  function selectTab(t, focus) {
    tabs.forEach(x => {
      const on = x === t;
      x.setAttribute('aria-selected', String(on)); x.tabIndex = on ? 0 : -1;
      const p = $(x.getAttribute('aria-controls')); if (p) p.hidden = !on;
    });
    if (focus) t.focus();
    try { history.replaceState(null, '', location.pathname + location.search + (t.id === 'tab-list' ? '#list' : '')); } catch (e) { /* ignore */ }
  }
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => selectTab(t, false));
    t.addEventListener('keydown', e => {
      let j = null;
      if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = tabs.length - 1;
      if (j !== null) { e.preventDefault(); selectTab(tabs[j], true); }
    });
  });
  // The bar's Analyze and HAR import show their result in the first view.
  ['paRun', 'paHarBtn'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', () => selectTab($('tab-one'), false)); });
  if (location.hash === '#list') selectTab($('tab-list'), false);

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
    const out = {};
    Object.entries(state || {}).forEach(([id, v]) => {
      const choice = v && typeof v === 'object' ? v.choice : v;
      if (choice === 'zscaler' || choice === 'alternative') out[id] = choice;
    });
    return out;
  }
  function scopeSelection() {
    let scopes = null, channels = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (op && typeof op.__dbChannelScope === 'function') channels = declared(op.__dbChannelScope()); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) {
      const lv = readJson('zassess_scopes_live_v1', null);
      scopes = lv && Array.isArray(lv.scopes) ? lv.scopes : null;
    }
    if (!Array.isArray(scopes)) return { scopes: [], channels: {}, from_page: false };
    if (!channels) channels = declared(readJson('zassess_channels_v1', {}));
    return { scopes: scopes.map(String), channels, from_page: true };
  }
  function newStartToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }

  // ── the file or the pasted text ─────────────────────────────────────
  let fileText = null, fileName = '';
  $('plFile').addEventListener('change', async e => {
    const f = e.target.files && e.target.files[0];
    fileText = null; fileName = '';
    const info = $('plFileInfo');
    if (!f) { info.textContent = ''; return; }
    if (f.size > MAX_BYTES) { info.textContent = `${f.name} is larger than 8 MB: split it into smaller files.`; e.target.value = ''; return; }
    try { fileText = await f.text(); fileName = f.name; info.textContent = `${f.name}: ${fileText.split(/\r?\n/).filter(Boolean).length.toLocaleString()} line(s) read. The pasted text is ignored while a file is chosen.`; }
    catch (err) { info.textContent = `${f.name} could not be read.`; }
  });

  // ── the job ─────────────────────────────────────────────────────────
  let running = false, job = null, startToken = null, stopAsked = false, last = null;
  const body = $('plBody');
  function mmss(s) { s = Math.max(0, Math.round(s || 0)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; }
  function liveHtml() {
    return `<div class="pa-live">
      <div class="pa-live-h"><span class="spin" aria-hidden="true"></span><strong>Testing the list</strong><span class="df-by" id="plPhase">Connecting to the tenant…</span><span class="sep"></span><span class="pa-elapsed" id="plElapsed">0:00</span><span class="df-chip" id="plPause" hidden></span><button type="button" class="rp-btn" id="plStop">Stop</button></div>
      <div class="pa-log pa-log-live" id="plLog" role="log" aria-live="polite" aria-label="What the test is doing">Connecting to the tenant…</div>
    </div>`;
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
        if (++misses >= 20) throw new Error(`Lost contact with the app while the test continued (${e.message}).`);
        continue;
      }
      logs.push(...(snap.logs || [])); next = snap.next;
      const lg = $('plLog'); if (lg) { lg.textContent = logs.join('\n') || 'Connecting to the tenant…'; lg.scrollTop = lg.scrollHeight; }
      const ph = $('plPhase'); if (ph && logs.length) ph.textContent = logs[logs.length - 1].slice(0, 120);
      const el = $('plElapsed'); if (el && snap.elapsed_seconds != null) el.textContent = mmss(snap.elapsed_seconds);
      const pz = $('plPause'); if (pz) { pz.hidden = !snap.paused_seconds; pz.textContent = snap.paused_seconds ? `Waiting for ZIA's rate limit: ${mmss(snap.paused_seconds)}` : ''; }
      const st = $('plStop'); if (st && snap.cancel_requested) { st.disabled = true; st.textContent = 'Stopping…'; }
      if (snap.status !== 'running') return Object.assign({}, snap, { logs });
    }
  }
  async function stop() {
    if (!running || stopAsked) return;
    stopAsked = true;
    const b = $('plStop'); if (b) { b.disabled = true; b.textContent = 'Stopping…'; }
    if (!job) {
      try { await fetch('/api/dlp-packs/jobs/stop-before-start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_token: startToken }) }); } catch (e) { /* cancelled by id below */ }
      return;
    }
    try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows it */ }
  }
  function fail(title, msg) {
    const hint = /credential|sign in|token|401|403|profile/i.test(msg) ? ' Sign in on the assessment page first and open this page from there, or choose a saved tenant profile in the bar above.' : '';
    body.innerHTML = `<div class="bp-card risk" role="alert"><div class="t">${E(title)}</div><div>${E(msg)}${E(hint)}</div></div>`;
  }
  async function run() {
    if (running) return;
    const text = fileText != null ? fileText : $('plText').value;
    if (!text.trim()) { fail('Nothing to test', 'Choose a CSV file or paste the list first.'); $('plText').focus(); return; }
    if (new Blob([text]).size > MAX_BYTES) { fail('The list is too large', 'The list is larger than 8 MB: split it into smaller files.'); return; }
    const max = Math.round(Number($('plMax').value) || 400);
    if (max < 1 || max > 2500) { fail('Lookup requests out of range', 'Lookup requests at most must be 1 to 2500.'); $('plMax').focus(); return; }
    const btn = $('plRun');
    running = true; stopAsked = false; job = null; startToken = newStartToken(); btn.disabled = true; btn.textContent = 'Testing…';
    body.innerHTML = liveHtml();
    $('plStop').addEventListener('click', stop);
    say('Testing the list. Only what is in scope is read.');
    const t0 = Date.now();
    const tick = setInterval(() => { const el = $('plElapsed'); if (el) el.textContent = mmss((Date.now() - t0) / 1000); }, 1000);
    try {
      const payload = Object.assign({}, credBody(), scopeSelection(), {
        text, network: ($('paNet') || {}).value || 'off', platform: ($('paPlat') || {}).value || 'windows',
        lookup: $('plLookup').checked, max_lookup_requests: max });
      const r = await fetch('/api/bulk-test/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken }, body: JSON.stringify(payload) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
      job = d.job_id;
      if (stopAsked) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the token stopped it */ } }
      const snap = await follow(job);
      const res = snap.result;
      if (!res || !(res.status === 'done' || res.status === 'stopped')) {
        throw new Error(snap.error || (snap.status === 'cancelled' ? 'You clicked Stop before the test started.' : 'The test did not finish.'));
      }
      last = res;
      render(res, snap.logs || []);
    } catch (e) {
      fail('The list could not be tested', e.message);
      say(`The list could not be tested: ${e.message}`);
    } finally {
      clearInterval(tick); running = false; startToken = null; stopAsked = false; btn.disabled = false; btn.textContent = 'Test the list';
    }
  }
  $('plRun').addEventListener('click', run);

  // ── the result ──────────────────────────────────────────────────────
  const n = v => Number(v || 0).toLocaleString();
  function sentence(res) {
    const c = res.counts || {};
    const parts = [];
    ['blocked', 'allowed', 'bypassed', 'isolated', 'caution', 'unverified'].forEach(k => { if (c[k]) parts.push(`${n(c[k])} ${RESULT_LABEL[k].toLowerCase()}`); });
    let s = `Tested ${n(res.rows)} destination(s): ${parts.join(', ') || 'none decided'}.`;
    if (c.allowed_but_blockable) s += ` ${n(c.allowed_but_blockable)} allowed row(s) would be blocked by a rule that applies only to some users or places.`;
    const ex = res.expectations;
    if (ex) s += ` ${n(ex.meets)} of ${n(ex.rows)} row(s) with an expected result meet it.`;
    let next;
    if (ex && ex.misses) next = 'Next: read "Where to fix the misses" below, copy a list into the area it names, or pick rows and click Fix selected to open Bulk changes with them filled in.';
    else if (!ex) next = 'Next: add an "expected" column (block or allow) to get a recommendation for every row that does not do what you want.';
    else next = 'Next: nothing to fix for the rows with an expected result; download the results for your records.';
    return `${s} ${next}`;
  }
  function table(caption, head, rows, empty) {
    if (!rows.length) return `<div class="df-hint pa-none">${E(empty)}</div>`;
    return `<div class="df-tablewrap"><table class="df-table pl-table"><caption class="sr-only">${E(caption)}</caption>
      <thead><tr>${head.map(h => `<th scope="col">${E(h)}</th>`).join('')}</tr></thead>
      <tbody>${rows.join('')}</tbody></table></div>`;
  }
  function statsHtml(c) {
    const keys = ['blocked', 'allowed', 'bypassed', 'isolated', 'caution', 'allowed_but_blockable', 'unverified'].concat(c.not_tested ? ['not_tested'] : []);
    return `<div class="df-stats pl-stats">${keys.map(k => `<div class="df-stat pl-stat ${c[k] ? RESULT_CLS[k] : 'mute'}"><div class="n">${n(c[k])}</div><div class="l">${E(RESULT_LABEL[k])}</div></div>`).join('')}</div>`;
  }
  function lookupHtml(res) {
    const lk = res.lookup || {};
    if (res.lookup_in_scope === false) return '<div class="df-hint">ZIA\'s URL lookup is not in scope on the Scope page, so the categories come from the tenant\'s own custom categories and your file.</div>';
    if (!lk.destinations) return '';
    const head = `ZIA looked up ${n(lk.looked_up)} of ${n(lk.destinations)} destination(s) in ${n(lk.requests)} request(s)${lk.retries ? `, ${n(lk.retries)} retried` : ''}.`;
    return lk.stopped ? `<div class="pl-note" role="note"><strong>${E(head)}</strong> ${E(lk.stopped)}</div>` : `<div class="df-hint">${E(head)}</div>`;
  }
  function resultChip(r) {
    const k = r.result === 'allowed' && r.blockable_by ? 'allowed_but_blockable' : r.result.replace(' ', '_');
    const cls = { ok: 'st-ok', bad: 'st-fail', warn: 'st-warn', mute: '' }[RESULT_CLS[k] || 'mute'];
    return `<span class="df-chip ${cls}">${E(RESULT_LABEL[k] || r.result)}</span>`;
  }
  function previewHtml(res) {
    const rows = res.preview || [];
    const head = ['Pick', 'Row', 'Destination', 'Result', 'Deciding rule', 'Category', 'Expected', 'Recommended area', 'Recommendation'];
    const body = rows.map(r => `<tr><td><input type="checkbox" class="pl-pick" data-row="${E(r.row)}" aria-label="Pick row ${E(r.row)}, ${E(r.target)}"></td>
      <td class="num">${E(r.row)}</td><td>${E(r.target)}${r.label ? ` <span class="df-by">${E(r.label)}</span>` : ''}</td><td>${resultChip(r)}${r.blockable_by ? `<div class="df-by">could be blocked by ${E(r.blockable_by)}</div>` : ''}</td>
      <td>${E(r.rule)}${r.area ? ` <span class="df-by">${E(r.area)}</span>` : ''}${r.segment ? ` <span class="df-by">segment ${E(r.segment)}</span>` : ''}</td><td>${E(r.category || '–')}</td><td>${E(r.expected ? r.expected.toLowerCase() : '–')}${r.meets ? ` <span class="df-by">${r.meets === 'yes' ? 'met' : 'not met'}</span>` : ''}</td>
      <td>${E(r.recommended_area)}</td><td>${E(r.recommendation || r.notes)}</td></tr>`);
    const why = res.rows ? 'Every row is allowed with no scoped rule that would block it, and none misses what your file expected, so there is nothing to look at here.' : 'No row was tested.';
    return `<h2 class="df-h" id="plRowsH">Rows to look at (${n(res.unmet)} not as expected, ${n(res.flagged)} flagged)</h2>
      <div class="df-hint">Rows that miss what your file expected come first, then rows that are blocked, bypassed, isolated, cautioned, unverified or blockable. The first ${n(rows.length)} are shown; the downloads have every row.</div>
      ${table('Rows to look at', head, body, why)}
      ${rows.length ? `<div class="pl-row"><label class="df-ctl"><span class="lbl">The picked destinations should be</span><select id="plPurpose" aria-label="What the picked destinations should be"><option value="block">Blocked</option><option value="allow">Allowed</option></select></label>
        <button type="button" class="rp-btn" id="plFix">Fix selected in Bulk changes</button><span class="df-hint" id="plFixInfo" role="status" aria-live="polite">Opens Bulk changes with a URL category change filled in. Nothing is written until you preview it and apply it there in write mode.</span></div>` : ''}`;
  }
  function expectationsHtml(res) {
    const ex = res.expectations;
    if (!ex) return `<h2 class="df-h">Where to fix the misses</h2><div class="df-hint pa-none">Your list has no "expected" column (block or allow), so no row can be compared with what you want. Add one and test again to get a recommendation per row.</div>`;
    const byArea = (ex.by_area || []).map(a => `<tr><td>${E(a.expected.toLowerCase())}</td><td>${E(a.area_label || a.area)}</td><td class="num">${n(a.count)}</td><td>${E(a.examples.join(', '))}</td><td>${E(a.recommendation)}${(a.segments || []).length ? `<div class="df-by">ZPA segments: ${E(a.segments.join(', '))}</div>` : ''}</td></tr>`);
    const cats = (ex.categories || []).map(c => `<tr><td>${E(c.expected.toLowerCase())}</td><td>${E(c.category)}</td><td>${E(c.kind.replace('_', ' '))}</td><td class="num">${n(c.count)}</td><td>${E(c.advice)}</td></tr>`);
    return `<h2 class="df-h">Where to fix the misses</h2>
      <div class="df-hint">${n(ex.meets)} of ${n(ex.rows)} row(s) meet what your file expected; ${n(ex.misses)} do not.</div>
      ${table('Misses by area', ['Expected', 'Area', 'Rows', 'Examples', 'What to do (the first row\'s advice)'], byArea, 'Every row with an expected result meets it.')}
      <h2 class="df-h">Advice per category</h2>
      ${table('Advice per category', ['Expected', 'Category', 'Kind', 'Rows', 'Advice'], cats, 'No miss, so no category advice.')}`;
  }
  function listsHtml(res, runId) {
    const lists = res.lists || [];
    const rows = lists.map((l, i) => {
      const key = AREA_KEY[l.area];
      return `<tr><td>${E(l.area_label)}</td><td>${E(l.purpose === 'block' ? 'to block' : 'to allow')}</td><td class="num">${n(l.count)}</td><td>${E(l.where)}${l.note ? `<div class="df-by">${E(l.note)}</div>` : ''}</td>
        <td class="pl-list"><button type="button" class="rp-btn" data-list="${i}" aria-expanded="false" aria-controls="plList${i}">Show</button> <a class="rp-btn" href="/api/bulk-test/${encodeURIComponent(runId)}/list?area=${E(key)}&amp;purpose=${E(l.purpose)}" download>Download</a>
        ${FIX_AREAS.includes(l.area) ? ` <button type="button" class="rp-btn" data-fixarea="${E(key)}" data-purpose="${E(l.purpose)}">Fix in Bulk changes</button>` : ''}
        <textarea id="plList${i}" readonly hidden aria-label="${E(l.area_label)} destinations ${l.purpose === 'block' ? 'to block' : 'to allow'}, one per line"></textarea></td></tr>`;
    });
    return `<h2 class="df-h">Lists to paste</h2>
      <div class="df-hint">The destinations that miss what your file expected, per area, one per line: paste them into an IP destination group (Cloud Firewall) or a custom URL category (URL filtering) in the ZIA Admin Portal, or open the URL ones in Bulk changes. Rows ZPA carries are changed in ZPA: their list names the segments.</div>
      ${table('Lists to paste', ['Area', 'Purpose', 'Destinations', 'Paste into', 'List'], rows, res.expectations ? 'No row misses what your file expected, so there is nothing to paste.' : 'Add an "expected" column to get these lists.')}`;
  }
  function render(res, logs) {
    const runId = res.run_id;
    const meta = $('rpMeta'); if (meta) meta.textContent = `${res.tenant_label || ''} · list tested ${new Date().toLocaleTimeString()} · ${n(res.rows)} row(s)`;
    const dl = (fmt, rows, label) => `<a class="rp-btn" href="/api/bulk-test/${encodeURIComponent(runId)}/export?format=${fmt}&amp;rows=${rows}" download>${E(label)}</a>`;
    const rules = (res.top_rules || []).map(t => `<tr><td>${E(t.rule)}</td><td>${E(t.area_label)}</td><td>${E(t.action)}</td><td class="num">${n(t.count)}</td></tr>`);
    const cats = (res.top_categories || []).map(t => `<tr><td>${E(t.category)}</td><td class="num">${n(t.count)}</td></tr>`);
    const skipped = (res.skipped || []).map(s => `<tr><td class="num">${E(s.line)}</td><td>${E(s.text)}</td><td>${E(s.why)}</td></tr>`);
    body.innerHTML = `
      ${res.stopped ? `<div class="pl-note" role="note"><strong>Stopped.</strong> ${E(res.stopped)}</div>` : ''}
      <p class="pl-lead" id="plSummary" tabindex="-1">${E(sentence(res))}</p>
      ${statsHtml(res.counts || {})}
      ${lookupHtml(res)}
      ${res.scope && res.scope.summary ? `<div class="df-hint">${E(res.scope.summary)}</div>` : ''}
      <div class="pl-row" role="group" aria-label="Downloads">
        <span class="df-hint">Download:</span>
        ${dl('csv', 'all', 'All rows (CSV)')}${dl('xlsx', 'all', 'All rows (Excel)')}${dl('csv', 'flagged', 'Flagged (CSV)')}${dl('xlsx', 'flagged', 'Flagged (Excel)')}${dl('csv', 'unmet', 'Not as expected (CSV)')}${dl('xlsx', 'unmet', 'Not as expected (Excel)')}
      </div>
      ${previewHtml(res)}
      ${expectationsHtml(res)}
      ${listsHtml(res, runId)}
      <h2 class="df-h">Top deciding rules</h2>
      ${table('Top deciding rules', ['Rule', 'Area', 'Action', 'Rows'], rules, 'No rule blocked, bypassed, isolated or cautioned any row.')}
      <h2 class="df-h">Top categories</h2>
      ${table('Top categories', ['Category', 'Rows'], cats, 'No row was tested.')}
      ${res.skipped_count ? `<h2 class="df-h">Lines skipped (${n(res.skipped_count)})</h2>${table('Lines skipped', ['Line', 'Text', 'Why'], skipped, '')}` : ''}
      <details class="pa-details"><summary>Assumptions (${(res.assumptions || []).length})</summary><ul>${(res.assumptions || []).map(a => `<li>${E(a)}</li>`).join('')}</ul></details>
      <details class="pa-details"><summary>What was done (${logs.length} line${logs.length === 1 ? '' : 's'})</summary><div class="pa-log">${E(logs.join('\n'))}</div></details>`;
    body.querySelectorAll('button[data-list]').forEach(b => b.addEventListener('click', async () => {
      const ta = $(`plList${b.dataset.list}`), l = (res.lists || [])[Number(b.dataset.list)];
      if (!ta || !l) return;
      const show = ta.hidden;
      if (show && !ta.value) {
        try { const r = await fetch(`/api/bulk-test/${encodeURIComponent(runId)}/list?area=${AREA_KEY[l.area]}&purpose=${l.purpose}`, { cache: 'no-store' }); ta.value = r.ok ? await r.text() : 'This list is no longer kept: test the list again.'; }
        catch (e) { ta.value = 'The list could not be loaded.'; }
      }
      ta.hidden = !show; b.setAttribute('aria-expanded', String(show)); b.textContent = show ? 'Hide' : 'Show';
      if (show) { ta.focus(); ta.select(); }
    }));
    body.querySelectorAll('button[data-fixarea]').forEach(b => b.addEventListener('click', () => fix(runId, { area: b.dataset.fixarea, purpose: b.dataset.purpose }, b)));
    const fb = $('plFix');
    if (fb) fb.addEventListener('click', () => {
      const rows = Array.from(body.querySelectorAll('.pl-pick:checked')).map(c => Number(c.dataset.row));
      if (!rows.length) { $('plFixInfo').textContent = 'Pick at least one row first.'; return; }
      fix(runId, { rows, purpose: $('plPurpose').value }, fb);
    });
    $('plSummary').focus();
    say(sentence(res));
  }
  async function fix(runId, what, btn) {
    const info = $('plFixInfo');
    const tell = t => { if (info) info.textContent = t; say(t); };
    btn.disabled = true;
    try {
      const r = await fetch(`/api/bulk-test/${encodeURIComponent(runId)}/fix`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({}, credBody(), scopeSelection(), what)) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
      const open = `/report/operations?fix=${encodeURIComponent(String(d.fix_id || ''))}`;
      const w = window.open(open, '_blank');
      const left = (d.excluded || []).length ? ` ${d.excluded.length} could not go into a URL category and were left out.` : '';
      if (!w) {
        if (info) info.innerHTML = `${E(d.urls)} destination(s) are ready. Your browser blocked the new tab: <a href="/report/operations?fix=${encodeURIComponent(String(d.fix_id || ''))}" target="_blank" rel="noopener">open Bulk changes</a>.${E(left)}`;
        say(`${d.urls} destinations are ready; the new tab was blocked.`);
      } else tell(`Bulk changes opened with ${d.urls} destination(s) filled in. Nothing is written until you preview and apply there.${left}`);
    } catch (e) { tell(`Fix selected could not start: ${e.message}`); }
    finally { btn.disabled = false; }
  }
})();
