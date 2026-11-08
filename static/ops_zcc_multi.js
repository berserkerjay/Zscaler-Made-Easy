/* Remove Client Connector devices on several tenants (POST
   /api/operations/zcc/multi-remove/preview and /apply). One plan per saved
   tenant profile, each shown on its own with its own plan hash and typed
   confirmation, and applied on its own: one tenant failing leaves the others.
   Uses the removal built above (Remove devices, or Remove from a list) as the
   operation. No inline handlers; every value is escaped with E. */
(function () {
  'use strict';
  const box = document.getElementById('opMultiBody');
  if (!box) return;
  const M = () => window.OPS_PLUGINS && window.OPS_PLUGINS.multi;
  const st = { profiles: [], picked: new Set(), op: null, rows: [], busy: false };
  let E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const REMOVALS = ['zcc_device_remove', 'zcc_device_bulk_remove'];

  async function post(url, payload) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', body: JSON.stringify(payload) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(M().detailText ? M().detailText(d, r.status) : `HTTP ${r.status}`);
    return d;
  }
  function base() {
    const m = M();
    return Object.assign({}, m.scope(), { assessor: m.assessor(), profile_ids: Array.from(st.picked), operation: st.op });
  }
  function draw() {
    const m = M(); if (m && m.E) E = m.E;
    const rows = st.rows.map((r, i) => {
      const p = r.plan || {}, c = p.counts || {};
      const ready = r.status === 'ready' && (c.change || 0) > 0;
      const name = E(r.tenant_label || r.profile_id);
      const body = r.status === 'applied' || r.status === 'partial' || r.status === 'failed' || r.status === 'refused' || r.status === 'plan_changed' || r.status === 'blocked' || r.status === 'stopped'
        ? `<div class="df-hint" role="status">${E(r.status)}${r.message ? `: ${E(r.message)}` : ''}${r.operation_id ? ` (record ${E(r.operation_id)})` : ''}</div>` : '';
      const plan = r.plan ? `<div class="df-hint">${E(c.change || 0)} to remove, ${E(c.noop || 0)} already as asked, ${E(c.excluded || 0)} excluded. Plan hash ${E(String(p.plan_hash || '').slice(0, 12))}…</div>
        ${(p.warnings || []).map(w => `<div class="df-hint">${E(w)}</div>`).join('')}${(p.blockers || []).map(w => `<div class="bp-card risk">${E(w)}</div>`).join('')}` : '';
      const apply = ready && !r.done ? `<div class="op-row"><label class="df-ctl"><span class="lbl">Type ${E(p.confirm_phrase)} for ${name}</span>
        <input data-mtphrase="${i}" autocomplete="off" aria-label="Confirmation for ${name}"></label>
        <button type="button" class="rp-btn primary" data-mtapply="${i}">Apply on ${name}</button></div>` : '';
      return `<div class="bp-card ${r.status === 'failed' || r.status === 'refused' ? 'risk' : ''}"><strong>${name}</strong>${plan}${body}${apply}</div>`;
    }).join('');
    document.getElementById('opMultiOut').innerHTML = rows;
    box.querySelectorAll('button[data-mtapply]').forEach(b => b.addEventListener('click', () => apply(Number(b.dataset.mtapply))));
  }
  async function preview() {
    const m = M();
    try {
      const spec = m.spec();
      if (!spec || REMOVALS.indexOf(spec.type) < 0) throw new Error('Build a Client Connector device removal above first (Remove devices, or Remove from a list).');
      st.op = spec;
      if (!st.picked.size) throw new Error('Tick at least one saved tenant.');
      m.say('Planning on each tenant. Nothing is written.');
      const d = await post('/api/operations/zcc/multi-remove/preview', base());
      st.rows = d.tenants || [];
      draw();
      m.say(`${st.rows.length} tenant(s) planned.`);
    } catch (e) { document.getElementById('opMultiOut').innerHTML = `<div class="bp-card risk" role="alert">${E(e.message)}</div>`; }
  }
  async function apply(i) {
    const m = M(), r = st.rows[i]; if (!r || st.busy) return;
    const phrase = (box.querySelector(`input[data-mtphrase="${i}"]`) || {}).value || '';
    if (!m.write()) { m.say('Write mode is off: turn it on to apply.'); return; }
    st.busy = true;
    try {
      const d = await post('/api/operations/zcc/multi-remove/apply', Object.assign(base(), { profile_ids: [r.profile_id], confirm: true,
        tenants: [{ profile_id: r.profile_id, plan_hash: (r.plan || {}).plan_hash || '', confirm_text: phrase }] }));
      const out = (d.tenants || [])[0] || { status: 'failed' };
      st.rows[i] = Object.assign({}, r, out, { done: true });
      m.say(`${r.tenant_label || r.profile_id}: ${out.status}.`);
    } catch (e) { st.rows[i] = Object.assign({}, r, { status: 'failed', message: e.message, done: true }); }
    st.busy = false;
    draw();
  }
  async function init() {
    const m = M(); if (!m) return;
    if (m.E) E = m.E;
    try { const r = await fetch('/api/tenant-profiles', { cache: 'no-store' }); if (r.ok) st.profiles = ((await r.json()).profiles || []); } catch (e) { st.profiles = []; }
    box.innerHTML = `<p class="df-hint">Plans the removal you built above on each ticked saved tenant. Every tenant has its own preview, its own typed confirmation and its own result; one that fails leaves the others. The same limits apply to each tenant. No Undo.</p>
      <fieldset class="op-inline"><legend>Tenants</legend>${st.profiles.length ? st.profiles.map(p => `<label><input type="checkbox" data-mtprof="${E(p.id)}"> ${E(p.name || p.vanity_domain || p.id)}</label>`).join(' ')
        : '<span class="df-hint">No saved tenant profiles.</span>'}</fieldset>
      <div class="op-row"><button type="button" class="rp-btn" id="opMultiPreview">Preview on each tenant</button></div>
      <div id="opMultiOut"></div>`;
    box.querySelectorAll('input[data-mtprof]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? st.picked.add(cb.dataset.mtprof) : st.picked.delete(cb.dataset.mtprof); }));
    document.getElementById('opMultiPreview').addEventListener('click', preview);
  }
  document.getElementById('opMulti').addEventListener('toggle', function once(ev) { if (ev.target.open) { ev.target.removeEventListener('toggle', once); init(); } });
}());
