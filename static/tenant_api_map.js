// Tenant API map (static/report_api_map.html): which features the tenant has and which reads its API client may make
// (tenant_api_map.py). Its own action: the page lists every endpoint it will read, the admin confirms, and one job
// reads them (GET only, one at a time). Statuses, item counts and field names only. Every value reaches the page
// through textContent.
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const body = $('amBody'), meta = $('rpMeta'), live = $('liveRegion'), confirmBox = $('amConfirmBox'), savedBox = $('amSavedBox');
  if (!body) return;
  const say = t => { live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  const PRODUCT = { zia: 'ZIA', zpa: 'ZPA', zcc: 'Client Connector', zdx: 'ZDX', zid: 'ZIdentity', ztw: 'Cloud & Branch Connector', zwa: 'Workflow Automation',
    zeasm: 'External Attack Surface', ztb: 'Zero Trust Branch', zbi: 'Business Insights', aiguard: 'AI Guard', zcell: 'Zero Trust Cellular' };
  const VERDICTS = [['present', 'Present', 'st-ok'], ['not licensed or not enabled', 'Not licensed or not enabled', ''], ['no permission', 'No permission', 'st-warn'],
    ['error', 'Error', 'st-fail'], ['not probed', 'Not checked', '']];
  const VWORD = Object.fromEntries(VERDICTS.map(v => [v[0], v[1]]));
  const VCLS = Object.fromEntries(VERDICTS.map(v => [v[0], v[2]]));
  let running = false, job = null, startToken = null, stopAsked = false, last = null, lastLogs = [], vFilter = '', pFilter = '', planNow = null, tenantLabel = '';

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
  const pname = p => PRODUCT[p] || p;
  const mmss = s => { s = Math.max(0, Math.round(s || 0)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
  const when = iso => { try { return new Date(iso).toLocaleString(); } catch (e) { return String(iso || ''); } };

  // ── tenant: as the other report pages (the signed-in tenant is the server's fallback) ──
  async function tenantChoices() {
    const wrap = $('amTenantWrap'), sel = $('amTenant');
    const fromOpener = !!(window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function');
    let profiles = [];
    try { const r = await fetch('/api/tenant-profiles', { cache: 'no-store' }); if (r.ok) profiles = ((await r.json()).profiles || []); } catch (e) { /* none */ }
    const opts = [];
    if (fromOpener) opts.push(['opener', 'Signed in on the assessment tab']);
    profiles.forEach(p => opts.push([`profile:${p.id}`, `${p.name || p.vanity_domain || p.id}${p.has_secret === false ? ' (no remembered secret)' : ''}`]));
    opts.push(['server', 'The tenant I am signed in to (or saved on this computer)']);
    clear(sel);
    opts.forEach(([v, l]) => sel.appendChild(el('option', { value: v, text: l })));
    wrap.hidden = opts.length < 2;
  }
  function credBody() {
    const v = $('amTenant').value || 'server';
    if (v === 'opener' && window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function') return window.opener.migrateCredBody();
    if (v.startsWith('profile:')) return { profile_id: v.slice(8) };
    return {};
  }
  async function post(url, data, headers) {
    const r = await fetch(url, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: JSON.stringify(data) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(errText(d, r.status));
    return d;
  }

  // ── what to map ────────────────────────────────────────────────────
  async function productChoices() {
    const box = $('amProducts');
    let plan = null;
    try { plan = await post('/api/tenant-api-map/plan', {}); } catch (e) { box.textContent = 'The list of products could not be loaded.'; return; }
    clear(box);
    Object.keys(plan.by_product).sort().forEach(p => {
      const id = `amP_${p}`;
      box.appendChild(el('label', { for: id }, [el('input', { type: 'checkbox', id, value: p, checked: true, 'data-product': p }), `${pname(p)} (${plan.by_product[p]})`]));
    });
  }
  function chosenProducts() {
    const boxes = Array.from(document.querySelectorAll('#amProducts input[data-product]'));
    const on = boxes.filter(b => b.checked).map(b => b.value);
    return on.length === boxes.length ? [] : on;   // none ticked below means all: the server's blank
  }
  function planBody() {
    return { products: chosenProducts(), features_only: $('amFeaturesOnly').checked, rps: Number($('amSpeed').value) || 1 };
  }

  // ── the confirmation: exactly what will be read ────────────────────
  function table(caption, heads, rows, empty, cls) {
    if (!rows.length) return el('div', { cls: 'df-hop-d pa-none', text: empty });
    const cell = c => (c instanceof Node ? c : document.createTextNode(c == null ? '' : String(c)));
    return el('div', { cls: cls || 'df-tablewrap' }, [el('table', { cls: 'df-table' }, [
      el('caption', { cls: 'sr-only', text: caption }),
      el('thead', {}, [el('tr', {}, heads.map(h => el('th', { scope: 'col', text: h })))]),
      el('tbody', {}, rows.map(r => el('tr', {}, [el('th', { scope: 'row' }, [cell(r[0])])].concat(r.slice(1).map(c => el('td', {}, [cell(c)]))))))])]);
  }
  const pathCell = p => el('span', { cls: 'am-path', text: p });
  async function askToConfirm() {
    if (running) return;
    const boxes = Array.from(document.querySelectorAll('#amProducts input[data-product]'));
    if (boxes.length && !boxes.some(b => b.checked)) { say('Tick at least one product to map.'); boxes[0].focus(); return; }
    $('amRun').disabled = true;
    let plan;
    try { plan = await post('/api/tenant-api-map/plan', planBody()); } catch (e) { $('amRun').disabled = false; showError('The list could not be made', e.message); return; }
    planNow = plan;
    clear(confirmBox); confirmBox.hidden = false;
    const mins = Math.max(1, Math.round(plan.seconds / 60));
    const reasons = Object.entries(plan.skipped_by_reason || {}).map(([why, n]) => `${n}: ${why}`);
    confirmBox.appendChild(el('section', { cls: 'am-confirm', 'aria-labelledby': 'amConfirmH' }, [
      el('h2', { cls: 'df-h', id: 'amConfirmH', tabindex: '-1', text: `Read these ${plan.count} endpoints?` }),
      el('p', { text: `The map will send ${plan.count} GET requests, one at a time, up to ${plan.rps} a second (about ${plan.seconds < 90 ? `${plan.seconds} seconds` : `${mins} minutes`}), through the tenant you are signed in to. ` +
        'Nothing is created, changed, activated or deleted. For each answer it keeps only the status, the number of items and the names of the top-level fields: no value, id, name or secret. ' +
        'This is its own action; it does not use the Scope page\'s ticks.' }),
      el('div', { cls: 'am-stats' }, Object.entries(plan.by_product).map(([p, n]) => el('div', { cls: 'am-stat' }, [el('div', { cls: 'n', text: n }), el('div', { cls: 'k', text: pname(p) })]))),
      el('details', { cls: 'pa-details', open: true }, [el('summary', { text: `The ${plan.count} endpoints it will read` }),
        table('Endpoints the map will read', ['Product', 'Endpoint (GET)', 'Used for'], plan.reads.map(r => [pname(r.product), pathCell(r.path + (r.params.length ? '?' + r.params.map(p => p[0] + '=…').join('&') : '')),
          r.purpose === 'decider' ? 'Decides a feature' : r.purpose === 'info' ? 'Detail for a feature' : 'Catalogue']), 'Nothing would be read.', 'df-tablewrap am-scroll')]),
      el('details', { cls: 'pa-details' }, [el('summary', { text: `Skipped (${plan.skipped_count}): ${reasons.join('; ')}` }),
        table('Endpoints the map skips', ['Product', 'Endpoint', 'Why not read'], plan.skipped.map(s => [pname(s.product), pathCell(s.path), s.reason]), '', 'df-tablewrap am-scroll')]),
      el('div', { cls: 'rp-bar' }, [el('button', { type: 'button', cls: 'rp-btn primary', id: 'amConfirm', text: `Read these ${plan.count} endpoints` }),
        el('button', { type: 'button', cls: 'rp-btn', id: 'amCancel', text: 'Cancel' })])]));
    $('amConfirm').addEventListener('click', () => start(plan));
    $('amCancel').addEventListener('click', () => { closeConfirm(); $('amRun').focus(); say('Cancelled. Nothing was read.'); });
    const h = $('amConfirmH'); h.focus(); h.scrollIntoView({ block: 'nearest' });
    say(`${plan.count} endpoints will be read. Read the list, then confirm or cancel.`);
  }
  function closeConfirm() { clear(confirmBox); confirmBox.hidden = true; $('amRun').disabled = false; }

  // ── the job ────────────────────────────────────────────────────────
  function liveBox() {
    clear(body);
    body.appendChild(el('div', { cls: 'pa-live' }, [
      el('div', { cls: 'pa-live-h' }, [el('span', { cls: 'spin', 'aria-hidden': 'true' }), el('strong', { text: 'Mapping the tenant\'s APIs' }),
        el('span', { cls: 'sep' }), el('span', { cls: 'pa-elapsed', id: 'amElapsed', text: '0:00' }),
        el('button', { type: 'button', cls: 'rp-btn', id: 'amStop', text: 'Stop' })]),
      el('div', {}, [el('progress', { id: 'amProg', cls: 'am-prog', max: '100', value: '0', 'aria-label': 'Endpoints read so far' }), el('span', { id: 'amProgText', cls: 'am-dim', text: ' 0 read' })]),
      el('div', { cls: 'pa-log pa-log-live', id: 'amLog', role: 'log', 'aria-live': 'off', 'aria-label': 'What the map is doing', text: 'Connecting to the tenant…' })]));
    $('amStop').addEventListener('click', stop);
  }
  async function follow(jobId) {
    let next = 0, misses = 0, said = 0; const logs = [];
    for (;;) {
      await new Promise(res => setTimeout(res, 1000));
      let snap;
      try {
        const r = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(jobId)}?since=${next}`, { cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        snap = await r.json(); misses = 0;
      } catch (e) {
        if (++misses >= 20) throw new Error(`Lost contact with the app while the map continued (${e.message}).`);
        continue;
      }
      logs.push(...(snap.logs || [])); next = snap.next;
      const log = $('amLog'); if (log) { log.textContent = logs.join('\n') || 'Connecting to the tenant…'; log.scrollTop = log.scrollHeight; }
      const pr = snap.progress;
      if (pr && pr.total) {
        const bar = $('amProg'); if (bar) { bar.max = pr.total; bar.value = pr.done; }
        const t = $('amProgText'); if (t) t.textContent = ` ${pr.done} of ${pr.total} read`;
        if (pr.done - said >= Math.max(25, Math.ceil(pr.total / 4))) { said = pr.done; say(`${pr.done} of ${pr.total} read.`); }
      }
      if (snap.status !== 'running') return Object.assign({}, snap, { logs });
    }
  }
  async function stop() {
    if (!running || stopAsked) return;
    stopAsked = true;
    const b = $('amStop'); if (b) { b.disabled = true; b.textContent = 'Stopping…'; }
    if (!job) {
      try { await post('/api/dlp-packs/jobs/stop-before-start', { start_token: startToken }); } catch (e) { /* cancelled by id */ }
      return;
    }
    try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows it */ }
  }
  function showError(title, text) {
    clear(body);
    body.appendChild(el('div', { cls: 'bp-card risk', role: 'alert' }, [el('div', { cls: 't', text: title }), el('div', { text })]));
    say(`${title}: ${text}`);
  }
  async function start(plan) {
    if (running) return;
    running = true; stopAsked = false; startToken = newStartToken(); vFilter = ''; pFilter = '';
    ['amRun', 'amFeaturesOnly', 'amSpeed'].forEach(id => { $(id).disabled = true; });
    document.querySelectorAll('#amProducts input').forEach(i => { i.disabled = true; });
    clear(confirmBox); confirmBox.hidden = true;
    ['amExpJson', 'amExpFeat', 'amExpEps'].forEach(id => { $(id).hidden = true; });
    liveBox();
    say('Mapping the tenant\'s APIs.');
    const t0 = Date.now();
    const tick = setInterval(() => { const e = $('amElapsed'); if (e) e.textContent = mmss((Date.now() - t0) / 1000); }, 1000);
    try {
      const d = await post('/api/tenant-api-map/start', Object.assign({}, credBody(), planBody(), { confirm: true, plan_hash: plan.plan_hash }), { 'X-Start-Token': startToken });
      job = d.job_id;
      if (stopAsked) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* token */ } }
      const snap = await follow(job);
      if (snap.status !== 'done' || !snap.result || snap.result.status !== 'done') {
        throw new Error((snap.result && snap.result.stopped) || snap.error || (snap.status === 'cancelled' ? 'You clicked Stop before the map finished. Nothing was saved.' : 'The map did not finish.'));
      }
      last = snap.result; lastLogs = snap.logs || []; tenantLabel = last.tenant_label || tenantLabel;
      render();
      const c = last.counts || {};
      say(`Done: ${c.features_present || 0} features present, ${c.features_not_licensed || 0} not licensed or not enabled, ${c.features_no_permission || 0} with no permission.`);
    } catch (e) {
      const stopped = /Stop|Stopped/.test(e.message);
      showError(stopped ? 'Stopped' : 'The map could not run', e.message);
    } finally {
      clearInterval(tick); running = false; job = null; startToken = null; stopAsked = false;
      ['amRun', 'amFeaturesOnly', 'amSpeed'].forEach(id => { $(id).disabled = false; });
      document.querySelectorAll('#amProducts input').forEach(i => { i.disabled = false; });
    }
  }

  // ── the result ─────────────────────────────────────────────────────
  const chip = v => el('span', { cls: `df-chip ${VCLS[v] || ''}`, text: VWORD[v] || v });
  const dash = (v, none) => (v == null || v === '' ? el('span', { cls: 'am-dim', text: none || '—' }) : String(v));
  function section(id, title, kids) {
    return el('section', { cls: 'am-sec', 'aria-labelledby': id }, [el('h2', { cls: 'df-h', id, text: title })].concat(kids));
  }
  function render() {
    const res = last, c = res.counts || {};
    meta.textContent = `${res.tenant_label || ''} · ${when(res.started_at)}${res.saved ? ' · saved map' : ''}`;
    clear(body);
    const tiles = [['Features present', c.features_present], ['Not licensed or not enabled', c.features_not_licensed], ['No permission', c.features_no_permission],
      ['Features with an error', c.features_error], ['Features not checked', c.features_not_probed], ['Endpoints read', c.read]];
    body.appendChild(el('div', { cls: 'am-stats' }, tiles.map(([k, n]) => el('div', { cls: 'am-stat' }, [el('div', { cls: 'n', text: n == null ? 0 : n }), el('div', { cls: 'k', text: k })]))));
    body.appendChild(el('div', { cls: 'am-note' }, [el('strong', { text: 'In short' }), el('ul', {}, [
      el('li', { text: `${c.present || 0} of ${c.read || 0} endpoints answered; ${c.not_licensed || 0} said the feature is not licensed or not enabled; ${c.no_permission || 0} refused this API client; ${c.error || 0} failed.` }),
      el('li', { text: `Read with GET only, one at a time, at most ${res.rps} a second, in ${mmss(res.duration_seconds)}. ${res.skipped_count || 0} endpoints were skipped (they need an object id, or return credentials or exports).` }),
      el('li', { text: 'Only the status, the number of items and the names of the top-level fields were kept: never a value, id, name or secret.' }),
      res.history_error ? el('li', { text: res.history_error }) : null])]));
    body.appendChild(section('amFeaturesH', 'Features', [el('div', { id: 'amFeatures' }, [table('Features and whether the tenant has them', ['Feature', 'Result', 'Deciding endpoint', 'HTTP status', 'Items', 'Detail'],
      (res.features || []).map(f => [f.feature, chip(f.verdict), f.deciding_endpoint ? pathCell(f.deciding_endpoint) : el('span', { cls: 'am-dim', text: 'none' }), dash(f.status), dash(f.item_count),
        (f.detail || '') + ((f.info || []).length ? (f.detail ? ' · ' : '') + f.info.map(i => `${i.endpoint.split('/').pop()}: ${VWORD[i.verdict] || i.verdict}${i.item_count == null ? '' : ' (' + i.item_count + ')'}`).join(', ') : '')]),
      'No feature was checked.', 'df-tablewrap am-scroll')])]));
    body.appendChild(section('amEpsH', 'Every endpoint read', [endpointFilters(), el('div', { id: 'amEps' })]));
    drawEndpoints();
    body.appendChild(el('details', { cls: 'pa-details' }, [el('summary', { text: `What was read (${lastLogs.length} line${lastLogs.length === 1 ? '' : 's'})` }),
      el('div', { cls: 'pa-log', text: lastLogs.length ? lastLogs.join('\n') : 'The log of a saved map is not kept.' })]));
    exports(res.report_id);
    savedList(res.history || null);
  }
  function endpointFilters() {
    const eps = last.endpoints || [];
    const n = v => eps.filter(e => !v || e.verdict === v).length;
    const prods = Array.from(new Set(eps.map(e => e.product))).sort();
    const sel = el('select', { id: 'amProdFilter', 'aria-label': 'Show one product' }, [el('option', { value: '', text: 'All products' })].concat(prods.map(p => el('option', { value: p, text: pname(p) }))));
    sel.value = pFilter;
    sel.addEventListener('change', () => { pFilter = sel.value; drawEndpoints(); say(`Showing ${pFilter ? pname(pFilter) : 'all products'}.`); });
    return el('div', { cls: 'am-filter', role: 'group', 'aria-label': 'Show endpoints by result' }, [['', 'All', ''] ].concat(VERDICTS).map(([v, l]) => {
      const b = el('button', { type: 'button', cls: `rp-btn${vFilter === v ? ' primary' : ''}`, 'data-v': v, 'aria-pressed': String(vFilter === v), text: `${l} (${n(v)})` });
      b.addEventListener('click', () => { vFilter = v; render(); const again = body.querySelector(`.am-filter button[data-v="${v}"]`); if (again) again.focus(); say(`Showing ${v ? VWORD[v] : 'all'} endpoints.`); });
      return b;
    }).concat([sel]));
  }
  function drawEndpoints() {
    const holder = $('amEps'); if (!holder) return;
    clear(holder);
    const rows = (last.endpoints || []).filter(e => (!vFilter || e.verdict === vFilter) && (!pFilter || e.product === pFilter));
    const fields = e => { const f = (e.field_names || []).join(', '); return f ? f + (e.other_names ? ` (+${e.other_names} other)` : '') : (e.other_names ? `${e.other_names} names not shown` : ''); };
    holder.appendChild(table('Every endpoint the map read', ['Endpoint', 'Product', 'HTTP status', 'Result', 'Items', 'Top-level field names', 'Note'],
      rows.map(e => [pathCell(e.path + ((e.params || []).length ? '?' + e.params.map(p => p + '=…').join('&') : '')), pname(e.product), dash(e.status, 'not sent'), chip(e.verdict),
        dash(e.item_count), fields(e), [e.error_code_hint, e.error].filter(Boolean).join(' · ')]), 'No endpoint has this result.', 'df-tablewrap am-scroll'));
  }
  function exports(rid) {
    const q = encodeURIComponent(rid || '');
    const set = (id, qs) => { const a = $(id); a.href = `/api/tenant-api-map/export/${q}?${qs}`; a.hidden = !rid; };
    set('amExpJson', 'format=json'); set('amExpFeat', 'format=csv&what=features'); set('amExpEps', 'format=csv&what=endpoints');
  }

  // ── saved maps (this computer, this tenant) ────────────────────────
  function savedList(list) {
    clear(savedBox);
    if (!list || !list.length) { savedBox.hidden = true; return; }
    savedBox.hidden = false;
    const sel = el('select', { id: 'amSaved', 'aria-label': 'Saved maps of this tenant' }, list.slice().reverse().map(m => el('option', { value: m.started_at, text: `${when(m.started_at)} · ${((m.counts || {}).features_present) || 0} features present` })));
    savedBox.appendChild(el('div', { cls: 'am-note' }, [el('strong', { text: 'Saved maps of this tenant, on this computer' }), ' ',
      el('label', { cls: 'df-ctl' }, [el('span', { cls: 'lbl', text: 'Saved' }), sel]), ' ',
      el('button', { type: 'button', cls: 'rp-btn', id: 'amOpenSaved', text: 'Open' }), ' ',
      el('button', { type: 'button', cls: 'rp-btn', id: 'amForget', text: 'Remove saved maps…' })]));
    $('amOpenSaved').addEventListener('click', () => openSaved(sel.value));
    $('amForget').addEventListener('click', () => forgetAsk(list.length));
  }
  async function openSaved(at) {
    if (!tenantLabel) return;
    try {
      const r = await fetch(`/api/tenant-api-map/saved?tenant=${encodeURIComponent(tenantLabel)}&at=${encodeURIComponent(at || '')}`, { cache: 'no-store' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      if (!d.map) { savedList(d.saved); return; }
      last = Object.assign({}, d.map, { history: d.saved }); lastLogs = []; vFilter = ''; pFilter = '';
      render();
      say('Opened a saved map.');
    } catch (e) { showError('The saved map could not be opened', e.message); }
  }
  function forgetAsk(n) {
    const box = savedBox;
    if ($('amForgetSure')) return;
    box.appendChild(el('div', { cls: 'am-confirm', id: 'amForgetSure', role: 'group', 'aria-label': 'Confirm removing saved maps' }, [
      el('p', { text: `Remove the ${n} saved map${n === 1 ? '' : 's'} of this tenant from this computer? This cannot be undone. Nothing in Zscaler changes.` }),
      el('button', { type: 'button', cls: 'rp-btn primary', id: 'amForgetYes', text: 'Remove them' }), ' ',
      el('button', { type: 'button', cls: 'rp-btn', id: 'amForgetNo', text: 'Keep them' })]));
    $('amForgetNo').addEventListener('click', () => { $('amForgetSure').remove(); $('amForget').focus(); });
    $('amForgetYes').addEventListener('click', async () => {
      try {
        const d = await post('/api/tenant-api-map/forget', { tenant: tenantLabel, confirm: true });
        savedList(null); say(`Removed ${d.removed} saved map${d.removed === 1 ? '' : 's'}.`);
      } catch (e) { showError('The saved maps could not be removed', e.message); }
    });
    $('amForgetNo').focus();
  }
  async function loadSaved() {
    try {
      const s = await (await fetch('/api/tenant/session', { cache: 'no-store' })).json();
      tenantLabel = s.connected || s.offline ? (s.tenant_label || '') : '';
      if (!tenantLabel && s.offline) {
        const o = await (await fetch('/api/offline/status', { cache: 'no-store' })).json().catch(() => ({}));
        tenantLabel = o.label || o.tenant_label || '';
      }
      if (!tenantLabel) return;
      const r = await fetch(`/api/tenant-api-map/saved?tenant=${encodeURIComponent(tenantLabel)}`, { cache: 'no-store' });
      if (!r.ok) return;
      const d = await r.json();
      if (d.saved && d.saved.length) { savedList(d.saved); }
    } catch (e) { /* no saved maps to offer */ }
  }

  $('amRun').addEventListener('click', askToConfirm);
  tenantChoices();
  productChoices();
  loadSaved();
})();
