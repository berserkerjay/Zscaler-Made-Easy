// Path analyzer: the "Category lookup" view (category_lookup.py on the server).
//
// One entry per line (a URL, a host name, an IP address or a category) is
// sent to /api/category-lookup/start with the Tenant of the bar and the
// Scope page's selection (window.PathRequest, static/path_list.js); the job
// is followed and the answer drawn: per entry its ZIA URL categories
// (predefined and custom, and where each came from), and per category every
// rule that names it across URL filtering, SSL inspection, Cloud Firewall,
// DNS Control, File Type Control, Web DLP and Sandbox, in evaluation order,
// with order, rank and action; the Cloud App Control rules that name the
// application; the custom categories that list it; what was not read.
// Read-only. Every value from the tenant is escaped before it is shown.
// window.CategoryLookup.open(query, run) fills it in (from a Test a list
// row, or from /report/path#categories=<query> as Find anything links it).
(function () {
  'use strict';
  // ── the answer (pure: tests/test_category_lookup.py renders it in node) ──
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const n = v => Number(v || 0).toLocaleString();
  function actionChip(a) {
    const t = String(a || '');
    const cls = /^(BLOCK|DENY|DROP|RESET)/.test(t) || /(^|, )BLOCK/.test(t) ? 'st-fail' : /CAUTION|ISOLATE|REDIR/.test(t) ? 'st-warn' : /ALLOW|DO_NOT_DECRYPT|^DECRYPT/.test(t) ? 'st-ok' : '';
    return t ? `<span class="df-chip ${cls}">${E(t.replace(/_/g, ' ').toLowerCase())}</span>` : '–';
  }
  function rulesTable(caption, rules, ranked) {
    if (!rules.length) return '<div class="df-hint pa-none">No rule names it in the policies that were read.</div>';
    const rows = rules.map(r => `<tr class="${r.enabled ? '' : 'cl-off'}"><td>${E(r.section_label)}</td><td class="num">${r.position == null ? '–' : E(r.position)}</td>
      <td>${E(r.name)}${r.default ? ' <span class="df-by">default rule</span>' : ''}${r.enabled ? '' : ' <span class="df-chip">disabled</span>'}</td>
      <td class="num">${r.order == null ? '–' : E(r.order)}</td><td class="num">${r.rank == null ? '–' : E(r.rank)}</td><td>${actionChip(r.action)}</td><td>${E(r.via)}</td></tr>`);
    return `<div class="df-tablewrap" tabindex="0" role="region" aria-label="${E(caption)}"><table class="df-table cl-table"><caption class="sr-only">${E(caption)}</caption>
      <thead><tr><th scope="col">Policy</th><th scope="col" title="Where it is evaluated in its policy (enabled rules)">Evaluated</th><th scope="col">Rule</th><th scope="col">Order</th><th scope="col">Rank</th><th scope="col">Action</th><th scope="col">Names it through</th></tr></thead>
      <tbody>${rows.join('')}</tbody></table></div>`;
  }
  function entryHtml(e, i, ranked) {
    const head = e.kind === 'category' ? 'Category' : 'Destination';
    const lines = [];
    if (e.lookup_error) lines.push(`<p class="cl-line"><strong>ZIA's URL lookup did not answer:</strong> ${E(e.lookup_error)}</p>`);
    if ((e.security_alerts || []).length) lines.push(`<p class="cl-line"><span class="df-chip st-fail">security alert</span> ${E(e.security_alerts.join(', '))}</p>`);
    if (e.custom_containing && e.custom_containing.length) lines.push(`<p class="cl-line"><strong>Custom categories that list it:</strong> ${E(e.custom_containing.map(c => `${c.name} (${c.id})`).join(', '))}</p>`);
    else if (e.kind === 'host') lines.push('<p class="cl-line">No custom category in the tenant lists it.</p>');
    if (e.note) lines.push(`<p class="cl-line">${E(e.note)}</p>`);
    const cats = (e.categories || []).map(c => `<h3><span>${E(c.name)}</span> <span class="df-by">${E(c.id)}</span>
        <span class="df-chip ${c.custom ? 'st-block' : ''}">${c.custom ? 'custom' : 'predefined'}</span><span class="df-by">${E(c.source)}</span></h3>
      ${rulesTable(`Rules that name ${c.name}`, c.rules || [], ranked)}${c.rules_cut ? '<div class="df-hint">Only the first 300 rules are shown.</div>' : ''}`);
    const app = e.application ? `<h3><span>Application ${E(e.application)}</span> <span class="df-chip">cloud app</span><span class="df-by">from ZIA's URL lookup</span></h3>
      ${rulesTable(`Cloud App Control rules that name ${e.application}`, e.application_rules || [], ranked)}` : '';
    const trace = e.kind === 'host' && e.host ? ` <button type="button" class="rp-btn" data-cltrace="${E(e.host)}">Trace its path</button>` : '';
    return `<section class="cl-entry" aria-labelledby="clE${i}"><h2 id="clE${i}" tabindex="-1">${E(head)}: ${E(e.input)}${trace}</h2>${lines.join('')}
      ${cats.join('')}${app}</section>`;
  }
  function sectionsHtml(res) {
    const rows = (res.sections || []).map(s => {
      const st = s.state === 'read' ? `<span class="df-chip st-ok">read</span> ${n(s.rules)} rule(s)` : s.state === 'out_of_scope' ? '<span class="df-chip">not in scope</span>' : '<span class="df-chip st-warn">could not be read</span>';
      return `<tr><td>${E(s.label)}</td><td>${st}${s.why ? `<div class="df-by">${E(s.why)}</div>` : ''}</td><td class="num">${s.state === 'read' && s.key !== 'cac' && s.key !== 'firewall' && s.key !== 'dns' ? n(s.any_count) : '–'}</td></tr>`;
    });
    return `<h2 class="df-h">What was read</h2><div class="df-tablewrap" tabindex="0" role="region" aria-label="What was read"><table class="df-table cl-table"><caption class="sr-only">What was read</caption>
      <thead><tr><th scope="col">Policy</th><th scope="col">Read</th><th scope="col">Rules for every category</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>
      <div class="df-hint">Rules for every category have no URL category condition, so they apply to every category above too; they are counted, not listed.</div>`;
  }
  function headline(res) {
    const k = (res.entries || []).length;
    return `Looked up ${n(k)} entr${k === 1 ? 'y' : 'ies'}` + (res.ranked ? '; rules in admin rank order, then rule order.' : '; rules in evaluation order (rule order, the default rule last).');
  }
  function pageHtml(res, logs) {
    const entries = res.entries || [];
    logs = logs || [];
    const skipped = (res.skipped || []).map(s => `<li>${E(s.text)}: ${E(s.why)}</li>`).join('');
    return `<p class="pl-lead" id="clSummary" tabindex="-1">${E(headline(res))}</p>
      ${res.scope_summary ? `<div class="df-hint">${E(res.scope_summary)}</div>` : ''}
      ${entries.map((e, i) => entryHtml(e, i, res.ranked)).join('')}
      ${skipped ? `<h2 class="df-h">Not looked up</h2><ul>${skipped}</ul>` : ''}
      ${sectionsHtml(res)}
      <details class="pa-details"><summary>Notes (${(res.notes || []).length})</summary><ul>${(res.notes || []).map(x => `<li>${E(x)}</li>`).join('')}</ul></details>
      <details class="pa-details"><summary>What was done (${logs.length} line${logs.length === 1 ? '' : 's'})</summary><div class="pa-log">${E(logs.join('\n'))}</div></details>`;
  }
  if (typeof window === 'undefined') {
    if (typeof module !== 'undefined' && module.exports) module.exports = { pageHtml, entryHtml, E };
    return;
  }
  const $ = id => document.getElementById(id);
  if (!$('panel-cat') || !$('clRun')) return;
  const live = $('liveRegion');
  const say = t => { if (!live) return; live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  const req = () => window.PathRequest || { credBody: () => ({}), scopeSelection: () => ({ scopes: [], channels: {}, from_page: false }),
    newStartToken: () => String(Date.now()), errText: (d, s) => `HTTP ${s}` };
  const MAX_CHARS = 16000;
  let running = false, job = null, startToken = null, stopAsked = false, reportId = '';
  const body = $('clBody');

  const fresh = $('clFresh');
  fresh.addEventListener('click', () => fresh.setAttribute('aria-pressed', String(fresh.getAttribute('aria-pressed') !== 'true')));

  function fail(title, msg) {
    const hint = /credential|sign in|token|401|403|profile/i.test(msg) ? ' Sign in on the assessment page first and open this page from there, or choose a saved tenant profile in the bar above.' : '';
    body.innerHTML = `<div class="bp-card risk" role="alert"><div class="t">${E(title)}</div><div>${E(msg)}${E(hint)}</div></div>`;
  }
  async function follow(id) {
    let next = 0, misses = 0; const logs = [];
    for (;;) {
      await new Promise(res => setTimeout(res, 800));
      let snap;
      try {
        const r = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(id)}?since=${next}`, { cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        snap = await r.json(); misses = 0;
      } catch (e) {
        if (++misses >= 20) throw new Error(`Lost contact with the app while the lookup continued (${e.message}).`);
        continue;
      }
      logs.push(...(snap.logs || [])); next = snap.next;
      const lg = $('clLog'); if (lg) { lg.textContent = logs.join('\n') || 'Connecting to the tenant…'; lg.scrollTop = lg.scrollHeight; }
      const st = $('clStop'); if (st && snap.cancel_requested) { st.disabled = true; st.textContent = 'Stopping…'; }
      if (snap.status !== 'running') return Object.assign({}, snap, { logs });
    }
  }
  async function stop() {
    if (!running || stopAsked) return;
    stopAsked = true;
    const b = $('clStop'); if (b) { b.disabled = true; b.textContent = 'Stopping…'; }
    if (!job) {
      try { await fetch('/api/dlp-packs/jobs/stop-before-start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_token: startToken }) }); } catch (e) { /* by id below */ }
      return;
    }
    try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows it */ }
  }
  async function run() {
    if (running) return;
    const text = $('clText').value;
    if (!text.trim()) { fail('Nothing to look up', 'Type a URL, a host name, an IP address or a category first.'); $('clText').focus(); return; }
    if (text.length > MAX_CHARS) { fail('Too long', `Look up at most 25 entries (${MAX_CHARS.toLocaleString()} characters) at a time.`); return; }
    const btn = $('clRun');
    running = true; stopAsked = false; job = null; startToken = req().newStartToken(); btn.disabled = true; btn.textContent = 'Looking up…';
    body.innerHTML = `<div class="pa-live"><div class="pa-live-h"><span class="spin" aria-hidden="true"></span><strong>Looking up</strong><span class="sep"></span><button type="button" class="rp-btn" id="clStop">Stop</button></div>
      <div class="pa-log pa-log-live" id="clLog" role="log" aria-live="polite" aria-label="What the lookup is doing">Connecting to the tenant…</div></div>`;
    $('clStop').addEventListener('click', stop);
    say('Looking up. Only what is in scope is read.');
    try {
      const useKept = fresh.getAttribute('aria-pressed') !== 'true';
      const payload = Object.assign({}, req().credBody(), req().scopeSelection(), { text, report_id: useKept ? reportId : '' });
      const r = await fetch('/api/category-lookup/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken }, body: JSON.stringify(payload) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(req().errText(d, r.status));
      job = d.job_id;
      if (stopAsked) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, { method: 'POST' }); } catch (e) { /* the token stopped it */ } }
      const snap = await follow(job);
      const res = snap.result;
      if (!res || res.status !== 'done') throw new Error(snap.error || (snap.status === 'cancelled' ? 'You clicked Stop before the lookup finished.' : 'The lookup did not finish.'));
      reportId = res.report_id || reportId;
      fresh.setAttribute('aria-pressed', 'false');
      render(res, snap.logs || []);
    } catch (e) {
      fail('The lookup could not run', e.message);
      say(`The lookup could not run: ${e.message}`);
    } finally {
      running = false; startToken = null; stopAsked = false; btn.disabled = false; btn.textContent = 'Look up';
    }
  }
  $('clRun').addEventListener('click', run);
  $('clText').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });

  function render(res, logs) {
    const meta = $('rpMeta'); if (meta) meta.textContent = `${res.tenant_label || ''} · categories looked up ${new Date().toLocaleTimeString()}`;
    body.innerHTML = pageHtml(res, logs);
    body.querySelectorAll('button[data-cltrace]').forEach(b => b.addEventListener('click', () => {
      const d = $('paDest'); if (d) d.value = b.dataset.cltrace;
      if (window.PathSelectTab) window.PathSelectTab('tab-one', true);
      if (d) d.focus();
    }));
    $('clSummary').focus();
    say(headline(res));
  }

  // ── opening it from elsewhere ───────────────────────────────────────
  function open(q, go) {
    if (window.PathSelectTab) window.PathSelectTab('tab-cat', false);
    const t = $('clText');
    if (q) t.value = String(q).slice(0, 512);
    t.focus();
    if (go && q) run();
  }
  window.CategoryLookup = { open };
  function fromHash() {
    const m = /^#categories(?:=(.*))?$/.exec(location.hash || '');
    if (!m) return;
    let q = '';
    try { q = m[1] ? decodeURIComponent(m[1]) : ''; } catch (e) { q = ''; }
    open(q, false);   // filled in, never run on its own: Look up reads the tenant
  }
  window.addEventListener('hashchange', fromHash);
  fromHash();
})();
