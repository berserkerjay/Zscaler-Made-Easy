// Detection health: one Workflow Automation incident in depth, and the
// Workflow Automation admin audit log. Read-only, metadata only: the
// incident's evidence (the content that matched) is never fetched, and the
// user, file name and client IP are withheld by the server (zwa_incidents.py).
// Credentials: the assessment tab that opened this page, else the profile the
// report was made from. Scope: the Scope page's selection, never guessed.
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x;
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/;

  function creds() {
    try {
      const op = window.opener && !window.opener.closed ? window.opener : null;
      if (op && typeof op.migrateValidateCreds === 'function') { const b = op.migrateValidateCreds(); if (b) return b; }
    } catch (e) { /* cross-window */ }
    return { profile_id: (window.__dhReport || {}).profile_id || '' };
  }
  function readJson(key, fallback) {
    try { const raw = localStorage.getItem(key); const v = raw ? JSON.parse(raw) : fallback; return v == null ? fallback : v; } catch (e) { return fallback; }
  }
  function declared(state) {
    const out = {};
    Object.entries(state || {}).forEach(([id, v]) => { const c = v && typeof v === 'object' ? v.choice : v; if (c === 'zscaler' || c === 'alternative') out[id] = c; });
    return out;
  }
  function scope() {
    let scopes = null, channels = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (op && typeof op.__dbChannelScope === 'function') channels = declared(op.__dbChannelScope()); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) { const lv = readJson('zassess_scopes_live_v1', null); scopes = lv && Array.isArray(lv.scopes) ? lv.scopes : null; }
    if (!Array.isArray(scopes)) { const sc = (window.__dhReport || {}).scope || {}; scopes = Array.isArray(sc.scopes) ? sc.scopes : []; }
    if (!channels) channels = declared(readJson('zassess_channels_v1', {}));
    return { scopes: scopes.map(String), channels, from_page: true };
  }
  async function post(url, extra) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({}, creds(), scope(), extra)) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(errText(d, r.status));
    return d;
  }

  function mount() {
    const main = document.querySelector('main.rp-card');
    if (!main || document.getElementById('zwaPanel')) return;
    const sec = document.createElement('section');
    sec.id = 'zwaPanel';
    sec.className = 'zwa-panel';
    sec.setAttribute('aria-labelledby', 'zwaH');
    sec.innerHTML = `
      <h2 class="df-h" id="zwaH">Incidents in depth</h2>
      <p class="df-hint">One incident's details, what triggered it, its change history and its tickets; and who changed what in Workflow Automation. Metadata only: the evidence (the content that matched) is never fetched, and the user, file name and client IP are not shown. Read-only.</p>
      <div class="op-row">
        <label class="df-ctl"><span class="lbl">Incident id</span><input id="zwaIncId" maxlength="80" autocomplete="off" spellcheck="false" placeholder="1-152-DFZG-17410647793298599936" aria-label="Incident id"></label>
        <button type="button" class="rp-btn primary" id="zwaIncRead">Read the incident</button>
        <label class="df-ctl"><span class="lbl">Audit log window</span><select id="zwaAuditDays" aria-label="Audit log window in days"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option><option value="90">90 days</option></select></label>
        <button type="button" class="rp-btn" id="zwaAuditRead">Read the audit log</button>
      </div>
      <div id="zwaLive" class="sr-only" role="status" aria-live="polite"></div>
      <div id="zwaOut"></div>`;
    main.appendChild(sec);
    document.getElementById('zwaIncRead').addEventListener('click', () => readIncident(document.getElementById('zwaIncId').value));
    document.getElementById('zwaIncId').addEventListener('keydown', e => { if (e.key === 'Enter') readIncident(e.target.value); });
    document.getElementById('zwaAuditRead').addEventListener('click', readAudit);
    document.addEventListener('click', e => {
      const b = e.target && e.target.closest ? e.target.closest('button.dh-inc[data-inc]') : null;
      if (!b) return;
      document.getElementById('zwaIncId').value = b.dataset.inc;
      readIncident(b.dataset.inc);
      sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }
  const say = t => { const l = document.getElementById('zwaLive'); if (!l) return; l.textContent = ''; setTimeout(() => { l.textContent = t; }, 30); };
  const out = () => document.getElementById('zwaOut');
  const fail = (title, msg) => { out().innerHTML = `<div class="bp-card risk" role="alert"><div class="t">${E(title)}</div><div>${E(msg)}</div></div>`; say(`${title}: ${msg}`); };
  const tbl = (cap, heads, rows) => `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">${E(cap)}</caption><thead><tr>${heads.map(h => `<th scope="col">${E(h)}</th>`).join('')}</tr></thead><tbody>${rows || `<tr><td colspan="${heads.length}">None.</td></tr>`}</tbody></table></div>`;

  async function readIncident(raw) {
    const id = String(raw || '').trim();
    if (!ID_RE.test(id) || id.includes('..')) { fail('Not an incident id', 'Use the id Workflow Automation shows, letters, digits and - _ . : only.'); return; }
    const btn = document.getElementById('zwaIncRead');
    btn.disabled = true; say('Reading the incident…');
    out().innerHTML = '<div class="rp-wait"><div class="spin"></div>Reading the incident (metadata only)…</div>';
    try {
      const d = await post('/api/zwa/incident', { incident_id: id });
      const x = d.details || {};
      const errs = Object.entries(d.errors || {});
      out().innerHTML = `
        <h3 class="df-h">Incident ${E(d.id)}</h3>
        ${errs.length ? `<div class="bp-card warn"><div class="t">Could not be read in full</div><ul>${errs.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : ''}
        ${d.details ? `<dl class="zwa-dl">
          <dt>Status</dt><dd>${E(x.status || '–')}${x.resolution ? ` (${E(x.resolution)})` : ''}</dd>
          <dt>Severity</dt><dd>${E(x.severity || '–')}${x.priority ? ` · priority ${E(x.priority)}` : ''}</dd>
          <dt>Channel</dt><dd>${E(x.channel || '–')}${x.sub_type ? ` · ${E(x.sub_type)}` : ''}${(x.actions || []).length ? ` · ${E(x.actions.join(', '))}` : ''}</dd>
          <dt>Where it was going</dt><dd>${E(x.application || '(not recorded)')}${x.file_type ? ` · file type ${E(x.file_type)}` : ''}</dd>
          <dt>Created</dt><dd>${E(x.created_at || '–')}</dd>
          <dt>Assigned to</dt><dd>${E(x.assigned_admin || 'nobody')}</dd>
          <dt>Labels</dt><dd>${E((x.labels || []).map(l => `${l.key}=${l.value}`).join(', ') || 'none')}</dd>
          <dt>Notes</dt><dd>${E(x.notes || 0)} (text not shown)</dd>
        </dl>` : ''}
        <h3 class="df-h">What triggered it</h3>
        ${tbl('What triggered the incident', ['Kind', 'Name', 'Matches'], (d.triggers || []).map(t => `<tr><td>${E(t.kind)}</td><td>${E(t.name)}</td><td class="num">${E(t.matches)}</td></tr>`).join(''))}
        <h3 class="df-h">Change history</h3>
        ${(d.history || []).length ? `<ol class="zwa-hist">${d.history.map(h => `<li>${E(h)}</li>`).join('')}</ol>` : '<div class="df-hint">No change recorded.</div>'}
        <h3 class="df-h">Tickets</h3>
        ${tbl('Tickets the incident generated', ['System', 'Ticket', 'Project', 'State'], (d.tickets || []).map(t => `<tr><td>${E(t.system)}</td><td>${E(t.ticket)}</td><td>${E(t.project)}</td><td>${E(t.state)}</td></tr>`).join(''))}
        <div class="df-hint">Not shown: ${E((d.withheld || []).join(', '))}.</div>
        ${x.open ? `<div class="op-row"><a class="rp-btn" href="/report/operations?build=zwa_close_false_positives">Close incidents as false positives (Bulk changes)</a></div>` : ''}`;
      say(`Incident ${d.id} read.`);
    } catch (e) { fail('The incident could not be read', e.message); }
    finally { btn.disabled = false; }
  }

  async function readAudit() {
    const btn = document.getElementById('zwaAuditRead');
    const days = Number(document.getElementById('zwaAuditDays').value) || 7;
    btn.disabled = true; say('Reading the audit log…');
    out().innerHTML = '<div class="rp-wait"><div class="spin"></div>Reading the Workflow Automation audit log…</div>';
    try {
      const d = await post('/api/zwa/audit-log', { days });
      out().innerHTML = `
        <h3 class="df-h">Workflow Automation audit log, last ${E(d.days)} day(s)</h3>
        <div class="df-hint">${E(d.count)} admin action(s) by ${E(d.admins)} admin(s)${d.truncated ? ' (only the first pages were read)' : ''}.</div>
        ${(d.errors || []).length ? `<div class="bp-card warn"><div class="t">Could not be read in full</div><div>${E(d.errors.join('; '))}</div></div>` : ''}
        ${tbl('Workflow Automation audit log', ['When', 'Admin', 'Action', 'Module', 'Resource'], (d.entries || []).map(x => `<tr><td>${E(x.time)}</td><td>${E(x.admin)}</td><td>${E(x.action)}</td><td>${E(x.module)}</td><td>${E(x.resource)}</td></tr>`).join(''))}`;
      say(`Audit log read: ${d.count} entries.`);
    } catch (e) { fail('The audit log could not be read', e.message); }
    finally { btn.disabled = false; }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount); else mount();
})();
