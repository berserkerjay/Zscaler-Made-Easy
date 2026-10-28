// ── Path analyzer: what-if for a user, group, department and location ──
// Adds the optional identity inputs to the Path analyzer and, under each
// result, the list "Policy action also depends on" (path_whatif.py on the
// server). Loaded by report_path.html after its other scripts; it keeps to
// itself so the page needs only its <script> line:
//
// * the identity is added to the body of POST /api/path-analyzer/start
//   (only that request, only when something was typed);
// * the result is read from the job poll the page already makes
//   (GET /api/dlp-packs/jobs/<id>, a copy of the answer) and the list is
//   shown under the verdict once the page has drawn it.
//
// Names are looked up in ZIA only when ZIA platform is ticked on the Scope
// page (the server checks it again): one search of at most 20 names per
// click, never a bulk listing. Nothing here writes to the tenant.
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const FIELDS = [
    ['user', 'User', 'jane@acme.com or a display name'],
    ['group', 'Group', 'one or more, separated by commas'],
    ['department', 'Department', 'Finance'],
    ['location', 'Location', 'HQ office'],
  ];
  const STATE = { match: ['met', 'ok'], nomatch: ['not met', 'fail'], unknown: ['depends', 'warn'] };
  const picked = {};          // field -> {id, name, email?} chosen from a ZIA search
  let lastResult = null;      // the newest Path analyzer result seen in a job poll

  // ── Credentials and scope, read the way the page reads them ──────────
  function credBody() {
    const sel = document.getElementById('paTenant');
    const v = (sel && sel.value) || 'server';
    const op = window.opener && !window.opener.closed ? window.opener : null;
    if (v === 'opener' && op && typeof op.migrateCredBody === 'function') return op.migrateCredBody() || {};
    if (v.startsWith('profile:')) return { profile_id: v.slice(8) };
    return {};
  }
  function readJson(key, fallback) {
    try { const raw = localStorage.getItem(key); const v = raw ? JSON.parse(raw) : fallback; return v == null ? fallback : v; } catch (e) { return fallback; }
  }
  function scopeSelection() {
    let scopes = null, channels = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (op && typeof op.__dbChannelScope === 'function') channels = op.__dbChannelScope(); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) {
      const live = readJson('zassess_scopes_live_v1', null);
      scopes = live && Array.isArray(live.scopes) ? live.scopes : null;
    }
    if (!Array.isArray(scopes)) return { scopes: [], channels: {}, from_page: false };
    const out = {};
    Object.entries(channels || readJson('zassess_channels_v1', {}) || {}).forEach(([id, v]) => {
      const c = v && typeof v === 'object' ? v.choice : v;
      if (c === 'zscaler' || c === 'alternative') out[id] = c;
    });
    return { scopes: scopes.map(String), channels: out, from_page: true };
  }
  const lookupAllowed = () => scopeSelection().scopes.includes('zia_extras');

  // ── The inputs ───────────────────────────────────────────────────────
  function identity() {
    const out = {};
    FIELDS.forEach(([k]) => {
      const el = document.getElementById(`paWi_${k}`);
      const v = el ? el.value.trim().slice(0, 200) : '';
      if (!v) return;
      const p = picked[k];
      out[k] = p && p.name === v ? p : v;
    });
    if (picked.groups && out.group === picked.groups.map(g => g.name).join(', ')) { out.groups = picked.groups; delete out.group; }
    return out;
  }
  function mount() {
    const main = document.querySelector('main.rp-card');
    const body = document.getElementById('paBody');
    if (!main || !body || document.getElementById('paWhatIf')) return;
    const box = document.createElement('details');
    box.className = 'pa-framework pa-whatif';
    box.id = 'paWhatIf';
    box.innerHTML = `<summary>What-if: a user, group, department or location (optional)</summary>
      <div class="df-hint">Leave these empty to analyze for anyone; the result then lists what the policy action also depends on. Fill any of them to evaluate rules scoped to that identity: rules for it apply, rules for others are skipped. Groups you give are taken as the user's only groups.</div>
      <div class="pa-wi-grid">${FIELDS.map(([k, label, ph]) => `
        <div class="pa-wi-field">
          <label class="df-ctl"><span class="lbl">${E(label)}</span><input type="text" id="paWi_${E(k)}" placeholder="${E(ph)}" autocomplete="off" spellcheck="false" maxlength="200"></label>
          <button type="button" class="rp-btn" data-wi-find="${E(k)}" aria-describedby="paWiScope">Look up in ZIA</button>
          <ul class="pa-wi-results" id="paWiRes_${E(k)}" aria-label="${E(label)} matches in ZIA" hidden></ul>
        </div>`).join('')}
      </div>
      <p class="df-hint" id="paWiScope"></p>
      <div class="sr-only" id="paWiLive" role="status" aria-live="polite"></div>`;
    main.insertBefore(box, body);
    const hint = document.getElementById('paWiScope');
    const refresh = () => {
      const ok = lookupAllowed();
      hint.textContent = ok ? 'Look up searches ZIA by name: one search of at most 20 names, nothing else is read.'
        : 'Looking names up in ZIA needs ZIA platform ticked on the Scope page. You can still type them.';
      box.querySelectorAll('[data-wi-find]').forEach(b => { b.disabled = !ok; });
    };
    refresh();
    box.addEventListener('toggle', refresh);
    box.addEventListener('click', e => {
      const b = e.target.closest('[data-wi-find]');
      if (b) { find(b.dataset.wiFind, b); return; }
      const r = e.target.closest('[data-wi-pick]');
      if (r) pick(r.dataset.wiField, Number(r.dataset.wiPick));
    });
  }
  const found = {};
  async function find(kind, btn) {
    const input = document.getElementById(`paWi_${kind}`);
    const list = document.getElementById(`paWiRes_${kind}`);
    const live = document.getElementById('paWiLive');
    const q = input.value.trim();
    if (q.length < 2) { live.textContent = 'Type at least 2 characters to look a name up.'; input.focus(); return; }
    if (btn) { btn.disabled = true; btn.textContent = 'Looking up…'; }
    try {
      const r = await fetch('/api/path-analyzer/identities', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({}, credBody(), scopeSelection(), { kind, query: q })) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
      found[kind] = d.results || [];
      list.hidden = false;
      if (d.error) { list.innerHTML = `<li class="df-hint">ZIA could not answer: ${E(d.error)}</li>`; live.textContent = `The lookup failed: ${d.error}`; return; }
      if (!found[kind].length) { list.innerHTML = `<li class="df-hint">No ${E(kind)} in ZIA starts with or contains “${E(q)}”. You can keep the name as typed.</li>`; live.textContent = 'No match.'; return; }
      list.innerHTML = found[kind].map((x, i) => `<li><button type="button" class="rp-btn" data-wi-field="${E(kind)}" data-wi-pick="${i}">${E(x.name)}${x.email ? ` <span class="df-by">${E(x.email)}</span>` : ''}${x.department && x.department.name ? ` <span class="df-by">${E(x.department.name)}</span>` : ''}</button></li>`).join('')
        + (d.capped ? '<li class="df-hint">Showing the first 20; type more of the name to narrow it.</li>' : '');
      live.textContent = `${found[kind].length} match(es). Choose one.`;
      const first = list.querySelector('button'); if (first) first.focus();
    } catch (e) {
      list.hidden = false;
      list.innerHTML = `<li class="df-hint">${E(e.message)}</li>`;
      live.textContent = `The lookup could not run: ${e.message}`;
    } finally {
      if (btn) { btn.disabled = !lookupAllowed(); btn.textContent = 'Look up in ZIA'; }
    }
  }
  function pick(kind, i) {
    const x = (found[kind] || [])[i];
    if (!x) return;
    const input = document.getElementById(`paWi_${kind}`);
    picked[kind] = { id: x.id, name: x.name, email: x.email || undefined };
    input.value = x.name;
    if (kind === 'user') {
      // A user found in ZIA brings their department and groups along.
      if (x.department && x.department.name) { picked.department = x.department; document.getElementById('paWi_department').value = x.department.name; }
      if ((x.groups || []).length) { picked.groups = x.groups; document.getElementById('paWi_group').value = x.groups.map(g => g.name).join(', '); }
    }
    const list = document.getElementById(`paWiRes_${kind}`);
    list.hidden = true; list.innerHTML = '';
    document.getElementById('paWiLive').textContent = `${x.name} chosen.`;
    input.focus();
  }

  // ── The result: "Policy action also depends on" ───────────────────────
  function crit(c) {
    const [lab, cls] = STATE[c.state] || [c.state, 'dim'];
    return `<div><span class="df-chip st-${E(cls)}">${E(lab)}</span> ${E(c.name)}</div>`;
  }
  function section(w) {
    const deps = w.depends_on || [];
    const n = w.shown || 3;
    const who = w.identity_label ? `<div class="df-hint">Evaluated for ${E(w.identity_label)}: ${E(w.counts.applies)} scoped rule(s) apply, ${E(w.counts.skipped)} are for others and skipped, ${E(w.counts.open)} still depend on something not given.</div>` : '';
    const rows = deps.map((d, i) => `<tr${i >= n ? ' hidden data-wi-more' : ''}>
        <td>${(d.criteria || []).map(crit).join('')}</td>
        <td>${E(d.section)}<br><code>${E(d.rule && d.rule.name)}</code>${d.rule && d.rule.order != null ? ` <span class="df-by">order ${E(d.rule.order)}</span>` : ''}</td>
        <td><strong>${E(d.action)}</strong></td>
        <td>${E(d.otherwise)}${d.otherwise_rule ? `<br><span class="df-by">${E(d.otherwise_rule)}</span>` : ''}</td></tr>`).join('');
    const table = deps.length ? `<div class="df-tablewrap"><table class="df-table">
        <caption class="sr-only">Conditions that change the policy action, with the rule and the action it would give</caption>
        <thead><tr><th scope="col">When</th><th scope="col">Rule</th><th scope="col">Action it would give</th><th scope="col">Otherwise</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
        ${deps.length > n ? `<p><button type="button" class="rp-btn" id="paWiMore" aria-expanded="false">Show ${deps.length - n} more</button></p>` : ''}`
      : `<div class="df-hop-d pa-none">${E(w.empty_reason || 'Nothing else changes the action.')}</div>`;
    return `<section class="pa-whatif-out" id="paWhatIfOut" aria-labelledby="paWiH">
        <h2 class="df-h" id="paWiH">Policy action also depends on</h2>
        <div class="df-hint">Each row is a rule scoped to a user, group, department, location, time window or device trust level that would change what happens to this traffic, most disruptive first.</div>
        ${who}${table}</section>`;
  }
  function place() {
    const res = lastResult;
    const body = document.getElementById('paBody');
    const verdict = body && body.querySelector('.pa-verdict');
    if (!res || !res.whatif || !verdict || document.getElementById('paWhatIfOut')) return;
    const head = document.getElementById('paHeadline');
    if (!head || !res.verdict || head.textContent !== res.verdict.headline) return;
    verdict.insertAdjacentHTML('afterend', section(res.whatif));
    const more = document.getElementById('paWiMore');
    if (more) more.addEventListener('click', () => {
      const open = more.getAttribute('aria-expanded') !== 'true';
      document.querySelectorAll('#paWhatIfOut [data-wi-more]').forEach(tr => { tr.hidden = !open; });
      more.setAttribute('aria-expanded', open ? 'true' : 'false');
      more.textContent = open ? 'Show fewer' : `Show ${document.querySelectorAll('#paWhatIfOut [data-wi-more]').length} more`;
    });
  }

  // ── The two requests this joins ───────────────────────────────────────
  const START = '/api/path-analyzer/start';
  const JOBS = /^\/api\/dlp-packs\/jobs\/[A-Za-z0-9_-]+(\?|$)/;
  const realFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    let path = '';
    try { const u = new URL(url, location.href); if (u.origin === location.origin) path = u.pathname + u.search; } catch (e) { path = ''; }
    if (path === START && init && typeof init.body === 'string') {
      try {
        const ident = identity();
        if (Object.keys(ident).length) init = Object.assign({}, init, { body: JSON.stringify(Object.assign(JSON.parse(init.body), { identity: ident })) });
      } catch (e) { /* the body is sent as the page made it */ }
      lastResult = null;
    }
    const p = realFetch(input, init);
    if (JOBS.test(path)) {
      p.then(r => (r.ok ? r.clone().json() : null)).then(snap => {
        if (snap && snap.status === 'done' && snap.result && snap.result.verdict && snap.result.whatif) { lastResult = snap.result; place(); }
      }).catch(() => { /* the page reports its own errors */ });
    }
    return p;
  };

  function init() {
    mount();
    const body = document.getElementById('paBody');
    if (body && window.MutationObserver) new MutationObserver(place).observe(body, { childList: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  window.PathWhatIf = { identity, section };
})();
