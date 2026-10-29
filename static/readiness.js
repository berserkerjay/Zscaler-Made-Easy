/* Readiness on the Start page: right after Authenticate, what this API
 * client can do here (POST /api/readiness/start, readiness.py), as a short
 * summary in step 1 with a link to Required API access (/permissions) for
 * everything. A Scope page key that will not work is greyed out with the
 * steps to ask the admin for, and a change the role cannot make is stopped
 * before it is sent. Reads only what is in scope; the access token itself
 * never reaches this page. The answer is kept for this tab only. */
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const KEY = 'zassess_readiness_v1';   // sessionStorage: this tab only, gone when it closes
  const PROBLEM = ['blocked', 'not_licensed', 'read_only', 'partial'];
  const GREY = ['blocked', 'not_licensed'];
  const WORDS = { ok: 'Will work', partial: 'Works in part', read_only: 'Can read, cannot change', blocked: 'Will not work',
                  not_licensed: 'Not licensed', unknown: 'Not checked', not_in_scope: 'Not in scope' };
  const ACCESS = { write: 'can read and change', read: 'can read', none: 'no access', unknown: 'not checked' };
  const RD = { ident: '', access: null, result: null, running: false, error: '' };

  const ident = () => (typeof _gdIdent === 'function' ? _gdIdent() : '');
  const mine = () => !!RD.ident && RD.ident === ident();
  function load() {
    try { const v = JSON.parse(sessionStorage.getItem(KEY) || 'null'); if (v && typeof v === 'object') Object.assign(RD, { ident: v.ident || '', access: v.access || null, result: v.result || null }); } catch (e) { /* storage blocked */ }
  }
  function save() {
    try { sessionStorage.setItem(KEY, JSON.stringify({ ident: RD.ident, access: RD.access, result: RD.result })); } catch (e) { /* storage blocked */ }
  }
  function say(t) { if (typeof announce === 'function') announce(t); }
  // The summary sits right under Authenticate on Connect to the tenant (the
  // tenant card travels with it into Start here when the guide shows it).
  function rerender() {
    const actions = document.getElementById('authBtn') && document.getElementById('authBtn').closest('.actions');
    let host = document.getElementById('rdConnect');
    if (!host && actions) { host = document.createElement('div'); host.id = 'rdConnect'; actions.insertAdjacentElement('afterend', host); }
    if (host) {
      const html = summaryHtml();
      if (host.innerHTML !== html) host.innerHTML = html;
      host.hidden = !html;
    }
  }
  function startToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }
  // The Scope page's selection, never guessed (as every scoped read sends it).
  function scopeSelection() {
    const scopes = typeof getSelectedScopes === 'function' ? getSelectedScopes() : [];
    const channels = {};
    try {
      const st = typeof window.__dbChannelScope === 'function' ? window.__dbChannelScope() : {};
      Object.entries(st || {}).forEach(([id, v]) => { const c = v && typeof v === 'object' ? v.choice : v; if (c === 'zscaler' || c === 'alternative') channels[id] = c; });
    } catch (e) { /* no channel view */ }
    return { scopes, channels, from_page: true };
  }
  function features() { return mine() && RD.result ? [...(RD.result.scopes || []), ...(RD.result.writes || [])] : []; }
  function feature(key) { return features().find(f => f.key === key) || null; }

  async function follow(id) {
    const t0 = Date.now();
    for (;;) {
      await new Promise(res => setTimeout(res, 700));
      const r = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(id)}`, { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const snap = await r.json();
      if (snap.status !== 'running') return snap;
      if (Date.now() - t0 > 120000) throw new Error('it took longer than two minutes');
    }
  }

  async function run() {
    if (RD.running || typeof migrateCredBody !== 'function') return;
    RD.running = true; RD.error = ''; RD.result = null; RD.ident = ident();
    rerender();
    say('Checking what this API client can do.');
    try {
      const body = Object.assign({}, migrateCredBody(), scopeSelection());
      const r = await fetch('/api/readiness/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Start-Token': startToken() }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { RD.error = typeof d.detail === 'string' ? d.detail : ((d.detail && d.detail.cause) || `HTTP ${r.status}`); return; }
      const snap = await follow(d.job_id);
      if (snap.status === 'done' && snap.result && snap.result.status === 'done') RD.result = snap.result;
      else RD.error = snap.error || 'The readiness check stopped before it finished.';
    } catch (e) {
      RD.error = `The readiness check could not finish: ${e.message}.`;
    } finally {
      RD.running = false; save(); apply(); rerender();
      say(RD.result ? `Readiness: ${RD.result.summary}` : `Readiness check: ${RD.error}`);
    }
  }

  // Called by the guide when Authenticate succeeds: the token's products
  // (from /api/tenant/check, no tenant read) at once, then the check.
  function signedIn(access) {
    RD.ident = ident(); RD.access = access || null; RD.result = null; RD.error = '';
    save(); apply();
    run();
  }

  function stepsHtml(steps) {
    steps = (steps || []).filter(Boolean);
    return steps.length ? `<details class="rd-steps"><summary>Ask your admin: the steps</summary><ol>${steps.map(s => `<li>${E(s)}</li>`).join('')}</ol></details>` : '';
  }
  function tokenLine() {
    const a = RD.access;
    if (!a) return '';
    if (!a.ok && a.source !== 'classic') return `<p class="rd-line">${E(a.why || 'The access token could not be read.')}</p>`;
    const ps = (a.products || []).filter(p => p.product !== 'OTHER');
    if (a.source === 'classic') return '<p class="rd-line">Classic ZIA API sign-in: ZIA only, with the admin\'s own role.</p>';
    return ps.length ? `<p class="rd-line">The access token lists: ${ps.map(p => `${E(p.product === 'ZINSIGHTS' ? 'Z-Insights' : p.product === 'ZGUARD' ? 'AI Guard' : p.product === 'ZIDENTITY' ? 'ZIdentity' : p.product)}${p.role ? ` (role ${E(p.role)})` : ''}`).join(', ')}.</p>` : '';
  }

  // The short summary in Start, step 1 (inside the signed-in box).
  function summaryHtml() {
    if (!mine()) return '';
    const link = '<a class="rd-link" href="/permissions" target="_blank" rel="noopener">See everything on Required API access</a>';
    const again = '<button type="button" class="gd-btn quiet gd-btn-sm" onclick="dlpReadiness.run()">Check again</button>';
    let body;
    if (RD.running) {
      body = `${tokenLine()}<p class="rd-line">Checking what this API client can do: the API role and the licences, only for what is in scope on the Scope page (a few reads, nothing else)…</p>`;
    } else if (RD.error) {
      body = `${tokenLine()}<p class="rd-line">${E(RD.error)}</p><div class="rd-acts">${again} ${link}</div>`;
    } else if (RD.result) {
      const r = RD.result;
      const gaps = [...(r.scopes || []), ...(r.writes || [])].filter(f => PROBLEM.includes(f.status));
      const prods = (r.products || []).filter(p => p.access !== 'not_in_scope' && (p.in_token || p.responds !== null));
      body = `<ul class="rd-prods">${prods.map(p => `<li><strong>${E(p.label)}</strong>: ${E(ACCESS[p.access] || p.access)}${p.role ? ` <span class="rd-dim">(role ${E(p.role)})</span>` : ''}</li>`).join('')}</ul>`
        + (gaps.length ? `<p class="rd-line"><strong>${gaps.length} thing${gaps.length === 1 ? '' : 's'} will not fully work:</strong></p><ul class="rd-gaps">${gaps.slice(0, 6).map(f =>
            `<li><strong>${E(f.label)}</strong> <span class="rd-chip ${E(f.status)}">${E(WORDS[f.status] || f.status)}</span> <span class="rd-dim">${E(f.why)}</span>${stepsHtml(f.steps)}</li>`).join('')}</ul>${gaps.length > 6 ? `<p class="rd-line rd-dim">And ${gaps.length - 6} more on Required API access.</p>` : ''}`
          : '<p class="rd-line">Everything that was checked will work.</p>')
        + `<div class="rd-acts">${again} ${link}</div>`;
    } else {
      body = `${tokenLine()}<div class="rd-acts">${again} ${link}</div>`;
    }
    return `<div class="rd-sum" role="status" aria-live="polite"><div class="rd-h">Readiness</div>${body}</div>`;
  }

  // Grey out the Scope page keys that will not work, with the steps beside them.
  function apply() {
    const byKey = {};
    features().forEach(f => { if (f.kind === 'scope') byKey[f.key] = f; });
    const off = [];
    document.querySelectorAll('.scope-cb').forEach(cb => {
      const f = byKey[cb.value];
      const lab = cb.closest('label');
      if (f && GREY.includes(f.status)) {
        if (cb.checked) { cb.checked = false; cb.dispatchEvent(new Event('change', { bubbles: true })); }
        cb.disabled = true; cb.dataset.rdOff = '1'; cb.setAttribute('aria-describedby', 'rdScopeNote');
        if (lab) { lab.classList.add('rd-off'); lab.title = `${WORDS[f.status]}: ${f.why}`; }
        off.push(f);
      } else if (cb.dataset.rdOff) {
        cb.disabled = false; delete cb.dataset.rdOff; cb.removeAttribute('aria-describedby');
        if (lab) { lab.classList.remove('rd-off'); lab.removeAttribute('title'); }
      }
    });
    const field = document.getElementById('scopeField');
    let note = document.getElementById('rdScopeNote');
    const partial = Object.values(byKey).filter(f => f.status === 'partial');
    if (!off.length && !partial.length) { if (note) note.remove(); return; }
    if (!note && field) {
      note = document.createElement('div'); note.id = 'rdScopeNote'; note.className = 'rd-scope-note';
      const grid = field.querySelector('.scope-cb') && field.querySelector('.scope-cb').closest('div');
      (grid || field).insertAdjacentElement('afterend', note);
    }
    if (!note) return;
    note.innerHTML = `<p><strong>From the readiness check:</strong> ${off.length ? 'the greyed-out scopes will not work with this API client, so they cannot be ticked. ' : ''}`
      + 'Ask the admin for the access below, then click Check again.</p>'
      + `<ul>${[...off, ...partial].map(f => `<li><strong>${E(f.label)}</strong>: ${E(WORDS[f.status])}. ${E(f.why)}${stepsHtml(f.steps)}</li>`).join('')}</ul>`
      + '<button type="button" class="gd-btn quiet gd-btn-sm" onclick="dlpReadiness.run()">Check again</button>';
  }

  // A change the role cannot make: say why and stop it before it is sent.
  function isBlocked(key) { const f = feature(key); return !!(f && (GREY.includes(f.status) || f.status === 'read_only')); }
  function allowWrite(key) {
    const f = feature(key);
    if (!f || !isBlocked(key)) return true;
    const title = `${f.label}: this API client cannot do this yet`;
    const fix = (f.steps || []).join(' ');
    if (window.dlpDialog && window.dlpDialog.notice) window.dlpDialog.notice({ title, body: f.why, fix: fix || 'Ask the admin for the access, then click Authenticate again.', tone: 'bad', okLabel: 'Back' });
    else alert(`${title}\n\n${f.why}\n\n${fix}`);
    say(`${title}. ${f.why}`);
    return false;
  }
  function blockedNote(key) {
    const f = feature(key);
    return f && isBlocked(key) ? `${WORDS[f.status]}: ${f.why} Ask the admin for the access (Required API access lists the steps).` : '';
  }

  load();
  window.dlpReadiness = { run, signedIn, summaryHtml, apply, isBlocked, allowWrite, blockedNote, feature, get result() { return mine() ? RD.result : null; } };
  document.addEventListener('DOMContentLoaded', () => { apply(); rerender(); setTimeout(() => { apply(); rerender(); }, 1000); });
  // A different tenant typed in the form: the old answer no longer applies.
  document.addEventListener('input', e => { if (e.target && ['vd', 'zuser', 'cloud'].includes(e.target.id)) { apply(); rerender(); } });
})();
