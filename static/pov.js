// POV planner (/report/pov): one proof of value per tenant profile.
// Everything is drawn with DOM nodes and textContent (never HTML from data).
// The POV is kept by this server in the tenant profile's folder; Prove it
// and the Insights counts read the tenant through the Path analyzer and
// Traffic insights (read-only, only what is in scope on the Scope page).
(function () {
  'use strict';
  // An error answer in plain words: FastAPI's detail is a string, {cause} or a list of {msg}.
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x; if (x && typeof x === 'object' && !Array.isArray(x) && (x.cause || x.message)) return String(x.cause || x.message);
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  const $ = id => document.getElementById(id);
  const live = $('liveRegion');
  const say = t => { live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  const PROFILE_KEY = 'pov_profile_v1';
  let cat = null, profiles = [], pov = null, tenantLabel = '', templates = [];
  let busy = false;

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (v === undefined || v === null || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked' || k === 'selected' || k === 'disabled') el[k] = !!v;
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    kids.flat().forEach(c => { if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c))); });
    return el;
  }
  const W = k => (cat && cat.status_words[k]) || k;
  const when = t => String(t || '').replace('T', ' ').slice(0, 16);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
  let uid = 0;
  const nid = p => `${p}_${++uid}`;
  function status(text, bad) { const s = $('pvStatus'); s.className = 'pv-status' + (bad ? ' bad' : ''); s.textContent = text; }
  function readJson(key, fallback) {
    try { const raw = localStorage.getItem(key); const v = raw ? JSON.parse(raw) : fallback; return v == null ? fallback : v; } catch (e) { return fallback; }
  }

  // ── tabs (arrow keys, Home, End; roving tabindex), as on ZPA analysis ──
  const tabs = Array.from(document.querySelectorAll('.zp-tabs [role="tab"]'));
  function selectTab(t, focus) {
    tabs.forEach(x => { const on = x === t; x.setAttribute('aria-selected', String(on)); x.tabIndex = on ? 0 : -1; $(x.getAttribute('aria-controls')).hidden = !on; });
    if (focus) t.focus();
    try { history.replaceState(null, '', location.pathname + location.search + (t.id === 'tab-plan' ? '' : '#' + t.id.slice(4))); } catch (e) { /* ignore */ }
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

  // ── the tenant: a saved profile, and the assessment tab's sign-in when it is the same profile ──
  function profileId() { return $('pvProfile').value || ''; }
  function credBody() {
    const pid = profileId();
    try {
      const op = window.opener && !window.opener.closed ? window.opener : null;
      if (op && typeof op.migrateCredBody === 'function') {
        const b = op.migrateCredBody();
        if (b && b.profile_id === pid) return b;
      }
    } catch (e) { /* the opener is gone */ }
    return { profile_id: pid };
  }
  function declared(state) {
    const out = {};
    Object.entries(state || {}).forEach(([id, v]) => { const c = v && typeof v === 'object' ? v.choice : v; if (c === 'zscaler' || c === 'alternative') out[id] = c; });
    return out;
  }
  // What is in scope: the Scope page's ticks (live from the opener, else what
  // it publishes), never guessed; without either the profile's saved selection.
  function scopeSelection() {
    let scopes = null, channels = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (op && typeof op.__dbChannelScope === 'function') channels = declared(op.__dbChannelScope()); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) { const lv = readJson('zassess_scopes_live_v1', null); scopes = lv && Array.isArray(lv.scopes) ? lv.scopes : null; }
    if (!Array.isArray(scopes)) return { scopes: [], channels: {}, from_page: false };
    if (!channels) channels = declared(readJson('zassess_channels_v1', {}));
    return { scopes: scopes.map(String), channels, from_page: true };
  }

  async function api(path, body, opts) {
    const r = await fetch(path, Object.assign({ method: body ? 'POST' : 'GET', headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined, cache: 'no-store' }, opts || {}));
    if ((opts || {}).raw) {
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(errText(d, r.status)); }
      return r;
    }
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(errText(d, r.status)); e.status = r.status; throw e; }
    return d;
  }
  function take(d) { pov = d.pov || null; tenantLabel = d.tenant_label || tenantLabel; if (d.templates) templates = d.templates; render(); }

  async function load() {
    status('Loading…');
    try {
      const [c, p] = await Promise.all([api('/api/pov/catalog'), api('/api/tenant-profiles')]);
      cat = c; templates = c.templates || []; profiles = p.profiles || [];
    } catch (e) { status(`Could not load the planner: ${e.message}`, true); return; }
    const sel = $('pvProfile');
    const want = new URLSearchParams(location.search).get('profile') || readJson(PROFILE_KEY, '') || (() => {
      try { return window.opener && window.opener.GD ? window.opener.GD.profile : ''; } catch (e) { return ''; } })();
    sel.replaceChildren(...(profiles.length ? profiles.map(p => h('option', { value: p.id, text: p.name || p.vanity_domain || p.id })) : [h('option', { value: '', text: 'No saved tenant profile' })]));
    if (profiles.some(p => p.id === want)) sel.value = want;
    await openPov();
  }
  async function openPov() {
    pov = null; tenantLabel = '';
    if (!profileId()) {
      status('');
      render();
      return;
    }
    try { localStorage.setItem(PROFILE_KEY, JSON.stringify(profileId())); } catch (e) { /* private window */ }
    try { take(await api('/api/pov/open', credBody())); status(''); } catch (e) { status(`Could not open the POV: ${e.message}`, true); render(); }
  }
  async function save(changes, done) {
    if (!pov || busy) return;
    busy = true;
    try {
      take(await api('/api/pov/update', Object.assign(credBody(), { rev: pov.rev, changes })));
      status(`Saved at ${new Date().toLocaleTimeString()}.`);
      say(done || 'Saved.');
    } catch (e) {
      status(e.status === 409 ? `Not saved: ${e.message} Click Reload.` : `Not saved: ${e.message}`, true);
      say(`Not saved: ${e.message}`);
    } finally { busy = false; }
  }
  const copy = x => JSON.parse(JSON.stringify(x));

  // ── render ────────────────────────────────────────────────────────
  // A redraw keeps the reader where they were: the open test cards stay
  // open, and focus returns to the control with the same id (ids are given
  // in drawing order, so the same control gets the same id each time).
  const openTests = new Set();
  function render() {
    const had = document.activeElement && document.activeElement.id;
    uid = 0;
    $('rpMeta').textContent = pov ? `${pov.intake.customer} · ${tenantLabel} · ${W(pov.status)}` : (tenantLabel || '');
    renderPlan(); renderRunbook(); renderKit(); renderNotes(); renderReport();
    const back = had && document.getElementById(had);
    if (back && back !== document.activeElement && !back.closest('[hidden]')) back.focus({ preventScroll: true });
  }
  function needPov(box) {
    if (!profileId()) {
      box.replaceChildren(h('p', { class: 'pv-empty', text: 'There is no saved tenant profile yet, so there is nothing to plan for. A POV belongs to a tenant profile: on the assessment page, connect to the tenant and save it as a profile, then come back here.' }));
      return false;
    }
    if (!pov) { box.replaceChildren(h('p', { class: 'pv-empty', text: 'This tenant has no POV yet, so this tab is empty. Start one on the Plan tab.' })); return false; }
    return true;
  }

  // Plan: intake, status, success criteria, timeline.
  function intakeForm(intake, onSubmit, submitLabel) {
    const f = h('form', { class: 'pv-form', novalidate: true });
    const cust = h('input', { type: 'text', id: nid('pv'), value: intake.customer || '', maxlength: 120, required: true, autocomplete: 'off' });
    const dom = h('input', { type: 'text', id: nid('pv'), value: intake.domain || '', maxlength: 253, placeholder: 'corp.example.com', autocomplete: 'off', spellcheck: 'false' });
    const pre = h('input', { type: 'text', id: nid('pv'), value: intake.prefix || '', maxlength: 8, placeholder: 'Made from the name', autocomplete: 'off' });
    const vert = h('select', { id: nid('pv') }, cat.verticals.map(v => h('option', { value: v.key, text: v.label, selected: v.key === (intake.vertical || 'general') })));
    // The one compliance choice (compliance_profiles.py): the vertical preset picks one, the operator can change it.
    const cpList = cat.compliance_profiles || [];
    const cpGroups = [...new Set(cpList.map(p => p.group))];
    const vertDefault = key => (cat.verticals.find(v => v.key === key) || {}).compliance_profile || '';
    const cpStart = intake.compliance_profile !== undefined ? (intake.compliance_profile || '') : vertDefault(vert.value);
    const cpSel = h('select', { id: nid('pv'), 'data-pv-compliance': '1' }, h('option', { value: '', text: 'None', selected: !cpStart }),
      cpGroups.map(g => h('optgroup', { label: g }, cpList.filter(p => p.group === g).map(p => h('option', { value: p.key, text: p.label, selected: p.key === cpStart })))));
    let tpl = null;
    if (!pov && templates.length) tpl = h('select', { id: nid('pv') }, h('option', { value: '', text: 'No template' }), templates.map(t => h('option', { value: t.id, text: t.name })));
    const prodBox = h('fieldset', { class: 'pv-checks' }, h('legend', { text: 'Products in scope' }));
    const chosen = new Set(intake.products || (cat.verticals.find(v => v.key === vert.value) || {}).products || []);
    const boxes = cat.products.map(p => { const id = nid('pp'); const b = h('input', { type: 'checkbox', id, value: p.key, checked: chosen.has(p.key) }); prodBox.append(h('label', { for: id }, b, p.label)); return b; });
    const desc = h('p', { class: 'pv-meta' });
    const showDesc = () => { const v = cat.verticals.find(x => x.key === vert.value); desc.textContent = v ? v.description : ''; };
    vert.addEventListener('change', () => {
      showDesc();
      if (!pov) { const v = cat.verticals.find(x => x.key === vert.value); boxes.forEach(b => { b.checked = v.products.includes(b.value); }); cpSel.value = vertDefault(vert.value); }
    });
    cust.addEventListener('input', () => { if (!pre.dataset.touched) pre.value = suggest(cust.value); });
    pre.addEventListener('input', () => { pre.dataset.touched = '1'; });
    showDesc();
    f.append(...[h('label', { for: cust.id }, 'Customer name', cust), h('label', { for: dom.id }, 'Internal domain', dom),
      h('label', { for: pre.id }, 'Short prefix (2 to 8 letters or digits)', pre), h('label', { for: vert.id }, 'Vertical preset', vert, desc),
      cpList.length ? h('label', { for: cpSel.id }, 'Compliance profile', cpSel, h('span', { class: 'pv-meta', text: 'Drives the ZIA baseline, the DLP packs offered, the AI Guard profile and the compliance pack.' })) : null,
      tpl ? h('label', { for: tpl.id }, 'Start from a template', tpl) : null,
      h('div', { class: 'pv-field', style: 'grid-column: 1 / -1' }, prodBox),
      h('div', { class: 'pv-row', style: 'grid-column: 1 / -1' }, h('button', { type: 'submit', class: 'rp-btn primary', text: submitLabel }))].filter(Boolean));
    f.addEventListener('submit', e => {
      e.preventDefault();
      const out = { customer: cust.value, domain: dom.value, prefix: pre.value, vertical: vert.value, products: boxes.filter(b => b.checked).map(b => b.value) };
      if (cpList.length) out.compliance_profile = cpSel.value;
      onSubmit(out, tpl ? tpl.value : '');
    });
    return f;
  }
  // The same rule as pov.suggest_prefix, so the field shows what the server would choose.
  function suggest(name) {
    const stop = ['the', 'of', 'and', 'inc', 'llc', 'ltd', 'co', 'corp', 'plc', 'gmbh'];
    let words = String(name || '').replace(/[^A-Za-z0-9 ]+/g, ' ').split(/\s+/).filter(Boolean);
    const kept = words.filter(w => !stop.includes(w.toLowerCase())); if (kept.length) words = kept;
    if (!words.length) return '';
    const ini = words.map(w => w[0]).join('');
    const s = (ini.length >= 3 ? ini : words.length > 1 ? ini + words[words.length - 1].slice(1) : words[0]).toUpperCase().slice(0, 6);
    return s.length >= 2 ? s : s ? (s + 'POV').slice(0, 6) : '';
  }
  function renderPlan() {
    const box = $('pvPlan');
    if (!cat) return;
    if (!profileId()) { needPov(box); return; }
    if (!pov) {
      box.replaceChildren(
        h('p', { class: 'pv-lead', text: `${tenantLabel || 'This tenant'} has no POV yet. Fill in the intake below and click Start the POV; the vertical preset fills in the products and suggested success criteria, and you can change them later.` }),
        h('div', { class: 'pv-sec' }, h('h2', { text: 'Intake' }), intakeForm({}, async (intake, templateId) => {
          try { take(await api('/api/pov/create', Object.assign(credBody(), { intake, template_id: templateId }))); status('POV started.'); say('POV started.'); }
          catch (e) { status(`Not started: ${e.message}`, true); say(`Not started: ${e.message}`); }
        }, 'Start the POV')));
      return;
    }
    const st = h('select', { id: nid('pv'), 'aria-label': 'POV status' }, cat.pov_statuses.map(s => h('option', { value: s, text: W(s), selected: s === pov.status })));
    st.addEventListener('change', () => save({ status: st.value }, `Status: ${W(st.value)}.`));
    const tests = (cat.runbook || []).filter(t => pov.intake.products.includes(t.product));
    const res = id => ((pov.tests || {})[id] || {}).status || 'not_run';
    box.replaceChildren(
      h('p', { class: 'pv-lead', text: `${pov.intake.customer} on ${tenantLabel}: ${plural(tests.filter(t => res(t.id) !== 'not_run').length, 'test')} of ${tests.length} have a result, ${pov.criteria.filter(c => c.status === 'met').length} of ${plural(pov.criteria.length, 'success criterion', 'success criteria')} met. Next: run the tests on the Runbook tab.` }),
      h('div', { class: 'pv-row' }, h('label', { class: 'df-ctl', for: st.id }, h('span', { class: 'lbl', text: 'Status' }), st)),
      h('details', { class: 'pv-sec' }, h('summary', { text: `Intake: ${pov.intake.customer}, ${(cat.verticals.find(v => v.key === pov.intake.vertical) || {}).label || ''}, prefix ${pov.intake.prefix}${pov.intake.domain ? ', ' + pov.intake.domain : ''}` }),
        intakeForm(pov.intake, intake => save({ intake }, 'Intake saved.'), 'Save the intake')),
      criteriaSection(tests), timelineSection());
  }
  function criteriaSection(tests) {
    const sec = h('div', { class: 'pv-sec' }, h('h2', { text: 'Success criteria' }),
      h('p', { class: 'pv-meta', text: 'What the customer needs to see for the POV to succeed. Link each one to the tests that prove it; the report shows each criterion with its tests\' results.' }));
    const list = h('ul', { class: 'pv-list' });
    if (!pov.criteria.length) list.append(h('li', { class: 'pv-empty', text: 'No success criteria yet, so the report will have none. Add the first one below.' }));
    pov.criteria.forEach((c, i) => {
      const sel = h('select', { 'aria-label': `Status of: ${c.text}` }, cat.criterion_statuses.map(s => h('option', { value: s, text: W(s), selected: s === c.status })));
      sel.addEventListener('change', () => { const cr = copy(pov.criteria); cr[i].status = sel.value; save({ criteria: cr }, `${c.text}: ${W(sel.value)}.`); });
      const linked = h('fieldset', { class: 'pv-checks' }, h('legend', { text: 'Proved by' }));
      tests.forEach(t => {
        const id = nid('cl');
        const b = h('input', { type: 'checkbox', id, checked: (c.tests || []).includes(t.id) });
        b.addEventListener('change', () => { const cr = copy(pov.criteria); const s = new Set(cr[i].tests || []); if (b.checked) s.add(t.id); else s.delete(t.id); cr[i].tests = [...s]; save({ criteria: cr }, 'Linked tests saved.'); });
        linked.append(h('label', { for: id }, b, t.title));
      });
      const del = h('button', { type: 'button', class: 'rp-btn', 'aria-label': `Remove the criterion: ${c.text}`, text: 'Remove' });
      del.addEventListener('click', () => { const cr = copy(pov.criteria); cr.splice(i, 1); save({ criteria: cr }, 'Criterion removed.'); });
      list.append(h('li', {}, h('div', { class: 'grow' }, h('span', { text: c.text }), ' ', h('span', { class: `pv-chip ${c.status}`, text: W(c.status) }),
        h('details', {}, h('summary', { class: 'pv-meta', text: `Proved by ${plural((c.tests || []).length, 'test')}` }), linked)), sel, del));
    });
    const inp = h('input', { type: 'text', id: nid('pv'), maxlength: 300, placeholder: 'For example: card numbers uploaded to webmail are blocked' });
    const f = h('form', { class: 'pv-row' }, h('label', { for: inp.id, class: 'pv-field', style: 'flex: 1 1 18rem' }, 'New success criterion', inp),
      h('button', { type: 'submit', class: 'rp-btn', text: 'Add' }));
    f.addEventListener('submit', e => { e.preventDefault(); if (!inp.value.trim()) return; save({ criteria: copy(pov.criteria).concat([{ text: inp.value, status: 'pending', tests: [] }]) }, 'Criterion added.'); });
    sec.append(list, f);
    return sec;
  }
  function timelineSection() {
    const tl = pov.timeline || { checkins: [] };
    const k = h('input', { type: 'date', id: nid('pv'), value: tl.kickoff || '' });
    const e = h('input', { type: 'date', id: nid('pv'), value: tl.end || '' });
    const both = () => save({ timeline: Object.assign(copy(tl), { kickoff: k.value || null, end: e.value || null }) }, 'Dates saved.');
    k.addEventListener('change', both); e.addEventListener('change', both);
    const list = h('ul', { class: 'pv-list' });
    if (!(tl.checkins || []).length) list.append(h('li', { class: 'pv-empty', text: 'No check-in planned yet. Add the dates you agreed with the customer.' }));
    (tl.checkins || []).forEach((c, i) => {
      const del = h('button', { type: 'button', class: 'rp-btn', 'aria-label': `Remove the check-in ${c.label} on ${c.date}`, text: 'Remove' });
      del.addEventListener('click', () => { const t = copy(tl); t.checkins.splice(i, 1); save({ timeline: t }, 'Check-in removed.'); });
      list.append(h('li', {}, h('span', { class: 'grow', text: `${c.date} · ${c.label}` }), del));
    });
    const cd = h('input', { type: 'date', id: nid('pv') }), cl = h('input', { type: 'text', id: nid('pv'), maxlength: 80, placeholder: 'Weekly check-in' });
    const f = h('form', { class: 'pv-row' }, h('label', { for: cd.id, class: 'pv-field' }, 'Check-in date', cd), h('label', { for: cl.id, class: 'pv-field' }, 'What', cl),
      h('button', { type: 'submit', class: 'rp-btn', text: 'Add check-in' }));
    f.addEventListener('submit', ev => { ev.preventDefault(); if (!cd.value) return; const t = copy(tl); t.checkins = (t.checkins || []).concat([{ date: cd.value, label: cl.value || 'Check-in' }]); save({ timeline: t }, 'Check-in added.'); });
    return h('div', { class: 'pv-sec' }, h('h2', { text: 'Timeline' }),
      h('div', { class: 'pv-form' }, h('label', { for: k.id }, 'Kickoff', k), h('label', { for: e.id }, 'POV ends', e)), list, f);
  }

  // Runbook: the tests of the products in scope, with Prove it and the Insights counts.
  function latestCounts() { const r = (pov.insights || []).slice(-1)[0]; return r ? r : null; }
  function countsFor(t) {
    const run = latestCounts(); if (!run || !(t.insights || []).length) return null;
    const secs = (run.counts || {}).sections || {};
    const lines = t.insights.map(k => secs[k]).filter(Boolean).map(s => `${s.title}: ${(s.rows || []).map(r => `${r.name} ${r.total == null ? '—' : Number(r.total).toLocaleString()}`).join(', ') || 'no data in this window'}`);
    return lines.length ? h('div', { class: 'pv-counts' }, h('strong', { text: `Insights, ${(run.counts || {}).window || ''} (read ${when(run.at)}): ` }), lines.join(' · ')) : null;
  }
  function renderRunbook() {
    const box = $('pvRunbook');
    if (!cat || !needPov(box)) return;
    const res = id => (pov.tests || {})[id] || { status: 'not_run', notes: '', evidence: [] };
    const win = h('select', { id: nid('pv'), 'aria-label': 'Insights time window' }, ['24h', '7d', '14d', '30d'].map(v => h('option', { value: v, text: { '24h': 'Last 24 hours', '7d': 'Last 7 days', '14d': 'Last 14 days', '30d': 'Last 30 days' }[v], selected: v === '7d' })));
    const ibtn = h('button', { type: 'button', class: 'rp-btn', text: 'Read Insights counts' });
    const ilive = h('div', { 'aria-live': 'polite' });
    ibtn.addEventListener('click', () => runJob('/api/pov/insights/start', Object.assign(credBody(), scopeSelection(), { window: win.value }), ilive, ibtn, 'Reading ZIA Insights', snap => {
      if (snap.result.pov_error) return `The counts were read but not recorded: ${snap.result.pov_error}`;
      return 'Insights counts recorded on the POV.';
    }));
    const head = h('div', { class: 'pv-sec' },
      h('p', { class: 'pv-lead', text: 'Run each test on a POV device, then mark it pass or fail with notes and evidence. Prove it asks the Path analyzer what the tenant\'s configuration does with the test\'s destination (read-only, only what is in scope), so you know the expected result before the live test.' }),
      h('div', { class: 'pv-row' }, h('label', { class: 'df-ctl', for: win.id }, h('span', { class: 'lbl', text: 'Window' }), win), ibtn,
        h('span', { class: 'pv-meta', text: latestCounts() ? `Last counts read ${when(latestCounts().at)}.` : 'Counts need ZIA Insights ticked on the Scope page and a OneAPI API client.' })), ilive);
    const groups = cat.products.filter(p => pov.intake.products.includes(p.key)).map(p => {
      const sec = h('div', { class: 'pv-sec' }, h('h2', { text: p.label }));
      cat.runbook.filter(t => t.product === p.key).forEach(t => sec.append(testCard(t, res(t.id))));
      return sec;
    });
    box.replaceChildren(head, ...groups);
  }
  function testCard(t, r) {
    const d = h('details', { class: 'pv-test', id: `test-${t.id}`, open: openTests.has(t.id) });
    d.addEventListener('toggle', () => { if (d.open) openTests.add(t.id); else openTests.delete(t.id); });
    const sel = h('select', { id: nid('pv') }, cat.test_statuses.map(s => h('option', { value: s, text: W(s), selected: s === r.status })));
    const notes = h('textarea', { id: nid('pv'), maxlength: 2000, value: r.notes || '' });
    const saveTest = (patch, msg) => { const tt = {}; tt[t.id] = Object.assign({ status: r.status, notes: r.notes || '', evidence: (r.evidence || []).filter(e => e.kind === 'note') }, patch); save({ tests: tt }, msg); };
    sel.addEventListener('change', () => saveTest({ status: sel.value }, `${t.title}: ${W(sel.value)}.`));
    notes.addEventListener('change', () => saveTest({ notes: notes.value }, 'Notes saved.'));
    const ev = h('ul', { class: 'pv-evidence' });
    (r.evidence || []).forEach(e => {
      let line;
      if (e.kind === 'prove') {
        const v = e.verdict || {};
        const chip = v.agrees === true ? h('span', { class: 'pv-chip agrees', text: 'Configuration agrees' }) : v.agrees === false ? h('span', { class: 'pv-chip disagrees', text: 'Configuration differs' }) : h('span', { class: 'pv-chip', text: 'Not decided' });
        line = h('span', { class: 'grow' }, h('strong', { text: 'Path analyzer: ' }), `${v.destination}: ${v.headline}`, ' ', chip, h('span', { class: 'pv-meta', text: ` ${when(e.at)}, ${e.by || ''}` }),
          (v.not_in_scope || []).length ? h('span', { class: 'pv-meta', text: ` Not in scope: ${v.not_in_scope.join(', ')}.` }) : null);
        ev.append(h('li', {}, line));
      } else {
        const rm = h('button', { type: 'button', class: 'rp-btn', 'aria-label': `Remove the evidence: ${e.text}`, text: 'Remove' });
        rm.addEventListener('click', () => saveTest({ evidence: (r.evidence || []).filter(x => x.kind === 'note' && x.id !== e.id) }, 'Evidence removed.'));
        ev.append(h('li', {}, h('span', { class: 'grow' }, e.text, h('span', { class: 'pv-meta', text: ` ${when(e.at)}, ${e.by || ''}` })), rm));
      }
    });
    if (!(r.evidence || []).length) ev.append(h('li', { class: 'pv-meta', text: 'No evidence yet: run Prove it, or add what you saw (the block page, the incident, a screenshot\'s file name).' }));
    const add = h('input', { type: 'text', id: nid('pv'), maxlength: 300, placeholder: 'Block page named rule "Block gambling"' });
    const addF = h('form', { class: 'pv-row' }, h('label', { for: add.id, class: 'pv-field', style: 'flex: 1 1 16rem' }, 'Add evidence', add), h('button', { type: 'submit', class: 'rp-btn', text: 'Add' }));
    addF.addEventListener('submit', e => { e.preventDefault(); if (!add.value.trim()) return; saveTest({ evidence: (r.evidence || []).filter(x => x.kind === 'note').concat([{ kind: 'note', text: add.value }]) }, 'Evidence added.'); });
    let prove = null;
    if (t.destination) {
      const dest = h('input', { type: 'text', id: nid('pv'), value: t.destination, maxlength: 300, spellcheck: 'false', autocomplete: 'off' });
      const btn = h('button', { type: 'button', class: 'rp-btn primary', text: 'Prove it' });
      const out = h('div', { 'aria-live': 'polite' });
      btn.addEventListener('click', () => runJob('/api/pov/prove/start', Object.assign(credBody(), scopeSelection(), { test_id: t.id, destination: dest.value }), out, btn, `Analyzing ${dest.value}`, snap => {
        const v = snap.result.verdict || {};
        return `${v.headline || 'No verdict.'}${snap.result.pov_error ? ` Not recorded: ${snap.result.pov_error}` : ''}`;
      }));
      prove = h('div', {}, h('div', { class: 'pv-row' }, h('label', { for: dest.id, class: 'pv-field', style: 'flex: 1 1 14rem' }, 'Destination', dest), btn),
        t.check ? h('p', { class: 'pv-meta', text: `Expected: ${cat.checks[t.check]}` }) : null, t.prove_note ? h('p', { class: 'pv-meta', text: t.prove_note }) : null, out);
    } else {
      prove = h('p', { class: 'pv-meta', text: t.prove_note });
    }
    d.append(h('summary', {}, h('span', { class: 't', text: t.title }), h('span', { class: `pv-chip ${r.status}`, text: W(r.status) }),
      (r.evidence || []).length ? h('span', { class: 'pv-meta', text: plural(r.evidence.length, 'evidence item') }) : null),
      h('div', { class: 'pv-test-body' }, h('strong', { text: 'Steps' }), h('ol', {}, t.steps.map(s => h('li', { text: s }))),
        h('p', {}, h('strong', { text: 'Expected: ' }), t.expect), prove, countsFor(t),
        h('div', { class: 'pv-form' }, h('label', { for: sel.id }, 'Result', sel), h('label', { for: notes.id, style: 'grid-column: 1 / -1' }, 'Notes', notes)),
        h('h3', { class: 'pv-meta', text: 'Evidence' }), ev, addF));
    return d;
  }

  // A job the page follows (the Path analyzer and Insights jobs), with Stop.
  function newStartToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }
  async function runJob(path, body, out, btn, title, done) {
    if (btn.disabled) return;
    const token = newStartToken();
    let job = null, stopped = false;
    const log = h('pre', { role: 'log', 'aria-label': 'What is being read', text: 'Connecting to the tenant…' });
    const stop = h('button', { type: 'button', class: 'rp-btn', text: 'Stop' });
    stop.addEventListener('click', async () => {
      stopped = true; stop.disabled = true; stop.textContent = 'Stopping…';
      try {
        if (job) await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' });
        else await fetch('/api/dlp-packs/jobs/stop-before-start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_token: token }) });
      } catch (e) { /* the poll shows the state */ }
    });
    out.replaceChildren(h('div', { class: 'pv-live' }, h('div', { class: 'pv-row' }, h('strong', { text: title }), stop), log));
    btn.disabled = true; say(`${title}.`);
    try {
      const d = await api(path, body, { headers: { 'Content-Type': 'application/json', 'X-Start-Token': token } });
      job = d.job_id;
      if (stopped) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* token */ } }
      let next = 0, misses = 0; const lines = [];
      for (;;) {
        await new Promise(r => setTimeout(r, 800));
        let snap;
        try { snap = await api(`/api/dlp-packs/jobs/${encodeURIComponent(job)}?since=${next}`); misses = 0; }
        catch (e) { if (++misses >= 20) throw new Error(`Lost contact with the app (${e.message}).`); continue; }
        lines.push(...(snap.logs || [])); next = snap.next; log.textContent = lines.join('\n') || 'Connecting to the tenant…';
        if (snap.status === 'running') continue;
        if (snap.status !== 'done' || !snap.result || snap.result.stopped) throw new Error(snap.error || (snap.result && snap.result.stopped) || 'You clicked Stop before the read finished; nothing was recorded.');
        const msg = done(snap);
        out.replaceChildren(h('p', { class: 'pv-meta', text: msg }));
        say(msg);
        await openPov();
        return;
      }
    } catch (e) {
      out.replaceChildren(h('div', { class: 'bp-card risk' }, h('div', { class: 't', text: stopped ? 'Stopped' : 'Not read' }), h('div', { text: e.message })));
      say(`Not read: ${e.message}`);
    } finally { btn.disabled = false; }
  }

  // Test kit.
  function renderKit() {
    const box = $('pvKit');
    if (!cat) return;
    const k = cat.kit;
    const vertical = pov ? pov.intake.vertical : '';
    const files = k.files.slice().sort((a, b) => (b.vertical === vertical) - (a.vertical === vertical));
    const links = list => h('ul', { class: 'pv-list' }, list.map(l => h('li', {}, h('a', { class: 'pv-ext', href: /^https:\/\//i.test(String(l.url || '')) ? String(l.url) : '#', target: '_blank', rel: 'noopener noreferrer', text: l.label }), h('span', { class: 'pv-meta', text: l.url }))));
    box.replaceChildren(
      h('p', { class: 'pv-lead', text: 'Files and links to run the tests with. Every file is synthetic test data or a harmless test file, never real data. ' + k.how }),
      h('div', { class: 'pv-sec' }, h('h2', { text: 'Files' }), h('ul', { class: 'pv-list pv-kit' }, files.map(f => h('li', {},
        h('div', { class: 'grow' }, h('strong', { text: f.label }), f.vertical && f.vertical === vertical ? h('span', { class: 'pv-chip pass', text: ' This POV\'s vertical' }) : null, h('div', { class: 'pv-meta', text: f.why })),
        h('a', { class: 'rp-btn', href: `/api/pov/kit/${encodeURIComponent(f.id)}`, download: '', text: 'Download' })))),
        h('p', { class: 'pv-meta', text: k.ssn_note })),
      compliancePackSec(),
      h('div', { class: 'pv-sec' }, h('h2', { text: 'EICAR antivirus test files (through ZIA)' }), links(k.eicar_links)),
      h('div', { class: 'pv-sec' }, h('h2', { text: 'AMTSO security features checks' }), links(k.amtso_links)));
  }

  // The compliance pack for this POV's compliance profile: local files, made for the profile's own defaults.
  function compliancePackSec() {
    const key = pov && pov.intake ? String(pov.intake.compliance_profile || '') : '';
    const p = (cat.compliance_profiles || []).find(x => x.key === key);
    if (!p) return h('div', { class: 'pv-sec' }, h('h2', { text: 'Compliance pack' }),
      h('p', { class: 'pv-meta', text: 'Pick a compliance profile in the POV intake (Plan tab) for a control mapping, a test plan by control and one synthetic DLP test file per DLP rule.' }));
    const files = [['mapping.html', 'Control mapping (HTML)'], ['mapping.xlsx', 'Control mapping (Excel)'], ['testplan.html', 'Test plan by control'],
      ['policy.json', 'Policy export'], ['compliance-pack.zip', 'Everything, with the DLP test files (ZIP)']];
    return h('div', { class: 'pv-sec' }, h('h2', { text: `Compliance pack: ${p.label}` }),
      h('p', { class: 'pv-meta', text: 'Made for the profile\'s own defaults (its tier, the default areas and Advanced Threat Protection); for the exact build use the ZIA security baseline in Bulk changes. Local files only: nothing is written to the tenant.' }),
      h('div', { class: 'pv-row' }, files.map(([id, label]) => h('a', { class: 'rp-btn', href: `/api/compliance-pack/${encodeURIComponent(key)}/${encodeURIComponent(id)}`, download: '', text: label }))));
  }

  // Notes and follow-ups.
  function renderNotes() {
    const box = $('pvNotes');
    if (!cat || !needPov(box)) return;
    const fl = h('ul', { class: 'pv-list' });
    if (!pov.follow_ups.length) fl.append(h('li', { class: 'pv-empty', text: 'No follow-ups yet. Add what you or the customer promised to do.' }));
    pov.follow_ups.forEach((f, i) => {
      const id = nid('fu');
      const b = h('input', { type: 'checkbox', id, checked: f.done });
      b.addEventListener('change', () => { const x = copy(pov.follow_ups); x[i].done = b.checked; save({ follow_ups: x }, b.checked ? `Done: ${f.text}` : `Open again: ${f.text}`); });
      const rm = h('button', { type: 'button', class: 'rp-btn', 'aria-label': `Remove the follow-up: ${f.text}`, text: 'Remove' });
      rm.addEventListener('click', () => { const x = copy(pov.follow_ups); x.splice(i, 1); save({ follow_ups: x }, 'Follow-up removed.'); });
      fl.append(h('li', {}, b, h('label', { for: id, class: 'grow', text: f.text + (f.due ? ` (due ${f.due})` : '') + (f.owner ? `, ${f.owner}` : '') }), rm));
    });
    const ft = h('input', { type: 'text', id: nid('pv'), maxlength: 300 }), fd = h('input', { type: 'date', id: nid('pv') }), fo = h('input', { type: 'text', id: nid('pv'), maxlength: 80 });
    const ff = h('form', { class: 'pv-row' }, h('label', { for: ft.id, class: 'pv-field', style: 'flex: 1 1 16rem' }, 'Follow-up', ft), h('label', { for: fd.id, class: 'pv-field' }, 'Due', fd),
      h('label', { for: fo.id, class: 'pv-field' }, 'Owner', fo), h('button', { type: 'submit', class: 'rp-btn', text: 'Add' }));
    ff.addEventListener('submit', e => { e.preventDefault(); if (!ft.value.trim()) return; save({ follow_ups: copy(pov.follow_ups).concat([{ text: ft.value, due: fd.value || null, owner: fo.value }]) }, 'Follow-up added.'); });
    const nl = h('ul', { class: 'pv-list' });
    if (!pov.notes.length) nl.append(h('li', { class: 'pv-empty', text: 'No notes yet. Notes stay with the POV and are not put in the customer report.' }));
    pov.notes.slice().reverse().forEach(n => {
      const rm = h('button', { type: 'button', class: 'rp-btn', 'aria-label': 'Remove this note', text: 'Remove' });
      rm.addEventListener('click', () => save({ notes: pov.notes.filter(x => x.id !== n.id) }, 'Note removed.'));
      nl.append(h('li', {}, h('div', { class: 'grow' }, h('div', { style: 'white-space: pre-wrap', text: n.text }), h('div', { class: 'pv-meta', text: `${when(n.at)}, ${n.by || ''}` })), rm));
    });
    const nt = h('textarea', { id: nid('pv'), maxlength: 2000 });
    const nf = h('form', {}, h('label', { for: nt.id, class: 'pv-field' }, 'New note', nt), h('div', { class: 'pv-row' }, h('button', { type: 'submit', class: 'rp-btn', text: 'Add note' })));
    nf.addEventListener('submit', e => { e.preventDefault(); if (!nt.value.trim()) return; save({ notes: copy(pov.notes).concat([{ text: nt.value }]) }, 'Note added.'); });
    box.replaceChildren(h('div', { class: 'pv-sec' }, h('h2', { text: 'Follow-ups' }), fl, ff), h('div', { class: 'pv-sec' }, h('h2', { text: 'Notes' }), nl, nf));
  }

  // Report, export, import, templates, delete.
  async function download(path, body, fallbackName) {
    const r = await api(path, body, { raw: true });
    const cd = r.headers.get('content-disposition') || '';
    const m = /filename=([^;]+)/.exec(cd);
    const blob = await r.blob();
    const a = h('a', { href: URL.createObjectURL(blob), download: m ? m[1].trim() : fallbackName });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function renderReport() {
    const box = $('pvReport');
    if (!cat) return;
    if (!profileId()) { needPov(box); return; }
    const imp = h('input', { type: 'file', id: nid('pv'), accept: '.json,application/json' });
    const rep = h('input', { type: 'checkbox', id: nid('pv') });
    const ib = h('button', { type: 'button', class: 'rp-btn', text: 'Import' });
    ib.addEventListener('click', async () => {
      const f = imp.files && imp.files[0];
      if (!f) { status('Choose an exported POV file first.', true); return; }
      if (f.size > cat.limits.import_bytes) { status('The file is larger than any exported POV; it was not sent.', true); return; }
      try { take(await api('/api/pov/import', Object.assign(credBody(), { content: await f.text(), replace: rep.checked }))); status('POV imported.'); say('POV imported.'); }
      catch (e) { status(`Not imported: ${e.message}`, true); say(`Not imported: ${e.message}`); }
    });
    const importSec = h('div', { class: 'pv-sec' }, h('h2', { text: 'Import' }),
      h('p', { class: 'pv-meta', text: 'An exported POV opens only for the tenant it was made for: a file from another tenant is refused.' }),
      h('div', { class: 'pv-row' }, h('label', { for: imp.id, class: 'pv-field' }, 'Exported POV file', imp), h('label', { for: rep.id }, rep, ' Replace this tenant\'s POV'), ib));
    const tl = h('ul', { class: 'pv-list' });
    if (!templates.length) tl.append(h('li', { class: 'pv-empty', text: 'No templates yet. Save this POV\'s plan as one to start the next POV from it.' }));
    templates.forEach(t => {
      const rm = h('button', { type: 'button', class: 'rp-btn', 'aria-label': `Delete the template ${t.name}`, text: 'Delete' });
      rm.addEventListener('click', async () => {
        try { const d = await api(`/api/pov/templates/${encodeURIComponent(t.id)}`, null, { method: 'DELETE' }); templates = d.templates || []; render(); say('Template deleted.'); }
        catch (e) { status(`Not deleted: ${e.message}`, true); }
      });
      tl.append(h('li', {}, h('span', { class: 'grow', text: `${t.name}${t.description ? ' — ' + t.description : ''}` }), rm));
    });
    if (!pov) { box.replaceChildren(h('p', { class: 'pv-lead', text: 'This tenant has no POV yet, so there is no report. Start one on the Plan tab, or import an exported POV of this tenant.' }), importSec, h('div', { class: 'pv-sec' }, h('h2', { text: 'Templates' }), tl)); return; }
    const tests = cat.runbook.filter(t => pov.intake.products.includes(t.product));
    const ran = tests.filter(t => ((pov.tests || {})[t.id] || {}).status && pov.tests[t.id].status !== 'not_run');
    const btn = (label, fmt) => { const b = h('button', { type: 'button', class: 'rp-btn primary', text: label });
      b.addEventListener('click', async () => { try { await download('/api/pov/report', Object.assign(credBody(), { format: fmt }), `pov.${fmt}`); say(`${label} downloaded.`); } catch (e) { status(`No report: ${e.message}`, true); } }); return b; };
    const exp = h('button', { type: 'button', class: 'rp-btn', text: 'Export the POV (JSON)' });
    exp.addEventListener('click', async () => { try { await download('/api/pov/export', credBody(), 'pov.json'); say('POV exported.'); } catch (e) { status(`Not exported: ${e.message}`, true); } });
    const tn = h('input', { type: 'text', id: nid('pv'), maxlength: 80 }), td = h('input', { type: 'text', id: nid('pv'), maxlength: 300 });
    const tf = h('form', { class: 'pv-row' }, h('label', { for: tn.id, class: 'pv-field' }, 'Template name', tn), h('label', { for: td.id, class: 'pv-field', style: 'flex: 1 1 14rem' }, 'Description', td),
      h('button', { type: 'submit', class: 'rp-btn', text: 'Save as template' }));
    tf.addEventListener('submit', async e => {
      e.preventDefault();
      try { const d = await api('/api/pov/templates', Object.assign(credBody(), { name: tn.value, description: td.value })); templates = d.templates || []; render(); say('Template saved.'); }
      catch (er) { status(`Not saved: ${er.message}`, true); }
    });
    const del = h('button', { type: 'button', class: 'rp-btn', text: 'Delete this POV' });
    del.addEventListener('click', async () => {
      const ok = window.dlpDialog ? await window.dlpDialog.ask({ title: 'Delete this POV?', body: `The POV for ${pov.intake.customer} and everything in it is deleted from this computer. Export it first to keep a copy. The tenant is not changed.`, okLabel: 'Delete', cancelLabel: 'Keep it', tone: 'bad' }) : false;
      if (!ok) return;
      try { await api('/api/pov/delete', Object.assign(credBody(), { confirm: true })); pov = null; render(); status('POV deleted.'); say('POV deleted.'); }
      catch (e) { status(`Not deleted: ${e.message}`, true); }
    });
    box.replaceChildren(
      h('p', { class: 'pv-lead', text: `The customer report is built from what actually ran: ${plural(ran.length, 'test')} with a result (of ${tests.length}), the success criteria, the evidence, the latest Insights counts and the changes this app's deploy and bulk-change records show for ${tenantLabel} since the POV started. Notes stay out of it.` }),
      h('div', { class: 'pv-sec' }, h('h2', { text: 'Customer report' }), h('div', { class: 'pv-row' }, btn('Word report', 'docx'), btn('PDF report', 'pdf'))),
      h('div', { class: 'pv-sec' }, h('h2', { text: 'Export' }), h('p', { class: 'pv-meta', text: 'The whole POV as a file, to keep or move to another computer. It holds no secret.' }), h('div', { class: 'pv-row' }, exp)),
      importSec, h('div', { class: 'pv-sec' }, h('h2', { text: 'Templates' }), h('p', { class: 'pv-meta', text: 'A template keeps the vertical, the products and the success criteria, never the customer, the tenant or results.' }), tl, tf),
      h('div', { class: 'pv-sec' }, h('h2', { text: 'Delete' }), h('div', { class: 'pv-row' }, del)));
  }

  $('pvProfile').addEventListener('change', openPov);
  $('pvReload').addEventListener('click', openPov);
  const start = (location.hash || '').slice(1);
  const t0 = tabs.find(t => t.id === `tab-${start}`);
  if (t0) selectTab(t0, false);
  load();
})();
