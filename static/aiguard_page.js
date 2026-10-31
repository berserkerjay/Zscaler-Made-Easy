// The AI Guard page (/report/aiguard): read AI Guard's configuration
// (POST /api/aiguard/inventory) and test one made-up prompt from the server's
// fixed list (POST /api/aiguard/test-prompt). Read-only. No free text is ever
// sent; credential values are never read by the server, only names.
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x;
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  const $ = id => document.getElementById(id);
  const live = $('liveRegion');
  const say = t => { live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30); };
  let prompts = [];

  async function tenantChoices() {
    const wrap = $('agTenantWrap'), sel = $('agTenant');
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
    const v = $('agTenant').value || 'server';
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
  async function post(url, extra) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({}, credBody(), scopeSelection(), extra || {})) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(errText(d, r.status));
    return d;
  }
  const tbl = (cap, heads, rows) => `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">${E(cap)}</caption><thead><tr>${heads.map(h => `<th scope="col">${E(h)}</th>`).join('')}</tr></thead><tbody>${rows || `<tr><td colspan="${heads.length}">None.</td></tr>`}</tbody></table></div>`;
  const yn = (v, good) => v == null ? '<span class="ag-dim">not said</span>' : (v === good ? `<span class="ag-ok">${v ? 'yes' : 'no'}</span>` : `<span class="ag-yes">${v ? 'yes' : 'no'}</span>`);
  const dets = list => (list || []).length ? list.map(d => `${E(d.detector)}${d.action ? ` (${E(d.action.toLowerCase())})` : ''}${d.enabled ? '' : ' <span class="ag-dim">off</span>'}`).join(', ') : '<span class="ag-yes">none</span>';

  async function read() {
    const btn = $('agRun'), out = $('agBody');
    btn.disabled = true; btn.textContent = 'Reading…'; say('Reading AI Guard.');
    out.innerHTML = '<div class="rp-wait"><div class="spin"></div>Reading AI Guard…</div>';
    try {
      const d = await post('/api/aiguard/inventory');
      $('rpMeta').textContent = `${d.tenant_label || ''} · read ${new Date().toLocaleTimeString()}`;
      if (!d.read) { out.innerHTML = `<div class="bp-card risk" role="alert"><div class="t">AI Guard could not be read</div><div>${E(d.error || '')}</div></div>`; say('AI Guard could not be read.'); return; }
      const errs = Object.entries(d.errors || {});
      const pname = Object.fromEntries((d.policies || []).map(p => [String(p.id), p.name]));
      const aname = Object.fromEntries((d.applications || []).map(a => [String(a.id), a.name]));
      out.innerHTML = `
        ${errs.length ? `<div class="bp-card warn"><div class="t">Could not be read in full</div><ul>${errs.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : ''}
        <h2 class="df-h">Detection policies</h2>
        ${tbl('AI Guard detection policies', ['Policy', 'Checks on prompts', 'Checks on answers'], (d.policies || []).map(p => `<tr><td>${E(p.name)}</td><td>${dets(p.input)}</td><td>${dets(p.output)}</td></tr>`).join(''))}
        <h2 class="df-h">Policy match rules</h2>
        ${tbl('AI Guard policy match rules', ['Order', 'Rule', 'On', 'Policy', 'LLM providers'], (d.rules || []).map(r => `<tr><td>${E(r.order)}</td><td>${E(r.name)}</td><td>${yn(r.enabled, true)}</td><td>${E(pname[String(r.policy_id)] || `missing (${r.policy_id})`)}</td><td>${E((r.providers || []).join(', '))}</td></tr>`).join(''))}
        <h2 class="df-h">LLM applications</h2>
        ${tbl('AI Guard LLM applications', ['Application', 'Keeps prompts', 'Encrypted', 'Credentials'], (d.applications || []).map(a => `<tr><td>${E(a.name)}</td><td>${a.stores_contents ? 'yes' : 'no'}</td><td>${a.stores_contents ? yn(!!a.encrypts_contents, true) : '<span class="ag-dim">not kept</span>'}</td><td>${a.credentials ? E(a.credentials) : '<span class="ag-yes">none</span>'}</td></tr>`).join(''))}
        <h2 class="df-h">Application credentials (names only)</h2>
        ${tbl('AI Guard application credentials', ['Credential', 'Application', 'Mode'], (d.credentials || []).map(c => `<tr><td>${E(c.name)}</td><td>${E(aname[String(c.application_id)] || c.application_id)}</td><td>${E(c.mode || '')}</td></tr>`).join(''))}
        <div class="df-hint">LLM providers AI Guard knows: ${E((d.providers || []).join(', ') || 'none')}. The owners of the applications are counted, not listed. Assumptions: ${E((d.assumed || []).slice(-2).join(' '))}</div>`;
      const sel = $('agPolicy');
      sel.innerHTML = '<option value="">The one AI Guard picks</option>' + (d.policies || []).map(p => `<option value="${E(p.id)}">${E(p.name)}</option>`).join('');
      say(`AI Guard read: ${(d.policies || []).length} policies, ${(d.applications || []).length} applications.`);
    } catch (e) { out.innerHTML = `<div class="bp-card risk" role="alert"><div class="t">AI Guard could not be read</div><div>${E(e.message)}</div></div>`; say(`AI Guard could not be read: ${e.message}`); }
    finally { btn.disabled = false; btn.textContent = 'Read'; }
  }

  function showPrompt() {
    const p = prompts.find(x => x.id === $('agPrompt').value);
    $('agPromptText').innerHTML = p ? `<strong>Sent as written:</strong> ${E(p.text)}<div class="df-hint">Expected: ${E(p.expect)}</div>` : '';
  }
  async function loadPrompts() {
    try {
      const r = await fetch('/api/aiguard/prompts', { cache: 'no-store' });
      const d = await r.json();
      prompts = d.prompts || [];
      $('agPrompt').innerHTML = prompts.map(p => `<option value="${E(p.id)}">${E(p.label)}</option>`).join('');
      $('agKey').textContent = d.key_configured ? 'The server has an AI Guard API key for live tests.'
        : 'On a live tenant the test needs an AI Guard API key in the server\'s AIGUARD_API_KEY (never typed here). The sample tenant answers with a made-up detector.';
      showPrompt();
    } catch (e) { $('agKey').textContent = 'The list of made-up prompts could not be loaded.'; }
  }
  async function test() {
    const btn = $('agTest'), out = $('agTestOut');
    btn.disabled = true; say('Testing the prompt.');
    out.innerHTML = '<div class="rp-wait"><div class="spin"></div>Sending the made-up prompt…</div>';
    try {
      const pol = $('agPolicy').value;
      const d = await post('/api/aiguard/test-prompt', { prompt_id: $('agPrompt').value, direction: $('agDir').value, policy_id: pol ? Number(pol) : null });
      if (d.error) { out.innerHTML = `<div class="bp-card warn" role="alert"><div class="t">Not tested</div><div>${E(d.error)}</div></div>`; say('Not tested.'); return; }
      const x = d.result || {};
      const src = d.source === 'sample' ? ' <span class="df-chip st-dim">made-up sample detector</span>' : '';
      out.innerHTML = `<div class="df-outcome ${(x.triggered || []).length ? 'st-warn' : 'st-ok'}"><span class="df-chip">${E(x.action || '–')}</span><strong>${(x.triggered || []).length ? `Detected: ${E(x.triggered.join(', '))}` : 'Nothing detected'}</strong>${src}</div>
        ${tbl('What each detector did', ['Detector', 'Triggered', 'Action', 'Severity'], (x.detectors || []).map(t => `<tr><td>${E(t.detector)}</td><td>${t.triggered ? '<span class="ag-yes">yes</span>' : 'no'}</td><td>${E(t.action)}</td><td>${E(t.severity)}</td></tr>`).join(''))}`;
      say((x.triggered || []).length ? `Detected: ${x.triggered.join(', ')}.` : 'Nothing detected.');
    } catch (e) { out.innerHTML = `<div class="bp-card risk" role="alert"><div class="t">The prompt could not be tested</div><div>${E(e.message)}</div></div>`; say(`Not tested: ${e.message}`); }
    finally { btn.disabled = false; }
  }

  $('agRun').addEventListener('click', read);
  $('agTest').addEventListener('click', test);
  $('agPrompt').addEventListener('change', showPrompt);
  tenantChoices();
  loadPrompts();
})();
