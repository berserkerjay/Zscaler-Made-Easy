/* Cloud application sanction on Bulk changes (/report/operations).
   One form on the shared engine (ops_sanction.py): every cloud application
   whose current state ZIA Insights reports, with its risk and traffic; pick
   up to 100, choose Sanctioned or Unsanctioned, preview. The page does the
   rest: the gates (the typed phrase is always asked: the change is
   tenant-wide), Apply, the read-back and Undo (each app back as it was). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const MAX = 100;
  const WORD = { sanctioned: 'Sanctioned', unsanctioned: 'Unsanctioned' };

  function st(S) {
    if (!S.sanction) S.sanction = { to: 'unsanctioned', pick: new Map(), filter: '', risky: false };
    return S.sanction;
  }
  function bytes(n) {
    if (n == null || !Number.isFinite(Number(n))) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let v = Number(n), i = 0;
    while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toLocaleString(undefined, { maximumFractionDigits: i ? 1 : 0 })} ${u[i]}`;
  }
  function visible(apps, z) {
    const f = z.filter.trim().toLowerCase();
    return apps.filter(a => (!f || String(a.name).toLowerCase().includes(f) || String(a.application_category || '').toLowerCase().includes(f))
      && (!z.risky || Number(a.risk_index) >= 4));
  }
  function rows(apps, z, E) {
    return apps.map(a => `<tr>
        <td><input type="checkbox" data-id="${E(a.id)}" data-name="${E(a.name)}" aria-label="Pick ${E(a.name)}"${z.pick.has(String(a.id)) ? ' checked' : ''}></td>
        <td>${E(a.name)}<div class="df-by">${E(a.application_category || '')}</div></td>
        <td><span class="df-chip ${a.state === 'unsanctioned' ? 'st-warn' : 'st-ok'}">${E(WORD[a.state] || a.state)}</span></td>
        <td class="num">${a.risk_index == null ? '—' : E(a.risk_index)}</td>
        <td class="num">${E(bytes(a.data_consumed))}</td><td class="num">${E(bytes(a.data_uploaded))}</td></tr>`).join('');
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), apps = res.apps || [], shown = visible(apps, z);
    where.innerHTML = `${H.errorsHtml(res)}
      <p class="df-hint">Every cloud application whose current state ZIA Insights reports (last 30 days), riskiest first. ${E(res.unknown || 0)} more application(s) in the tenant have no known state and cannot be changed here (no exact Undo); change those in the ZIA Admin Portal.</p>
      <div class="bp-card warn" role="note"><div class="t">Tenant-wide change</div><div>${E(res.tenant_wide || '')}</div></div>
      <div class="op-row"><fieldset class="op-inline" id="sanTo"><legend>Mark the picked apps as</legend>
        <label><input type="radio" name="sanTo" value="unsanctioned"${z.to === 'unsanctioned' ? ' checked' : ''}> Unsanctioned</label>
        <label><input type="radio" name="sanTo" value="sanctioned"${z.to === 'sanctioned' ? ' checked' : ''}> Sanctioned</label></fieldset></div>
      <div class="op-row">
        <label class="df-ctl"><span class="lbl">Filter</span><input id="sanFilter" type="search" maxlength="80" value="${E(z.filter)}" aria-label="Filter the applications by name or category" placeholder="Name or category"></label>
        <label class="df-ctl"><input type="checkbox" id="sanRisky"${z.risky ? ' checked' : ''}><span>High risk only (4 or 5)</span></label>
        <span class="df-chip" id="sanCount" aria-live="polite">${z.pick.size} picked</span>
        <button type="button" class="rp-btn" id="sanNone">Clear</button></div>
      ${shown.length ? `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Cloud applications with a known sanction state</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">Application</th><th scope="col">Now</th><th scope="col" class="num">Risk</th><th scope="col" class="num">Data (30 days)</th><th scope="col" class="num">Uploaded</th></tr></thead>
        <tbody>${rows(shown, z, E)}</tbody></table></div>`
        : `<div class="df-hint">${apps.length ? 'No application matches the filter.' : 'No cloud application with a known state was found: ZIA Insights reports none for the last 30 days.'}</div>`}
      <div class="df-hint">${E(res.note || '')}</div>`;
    where.querySelectorAll('input[name="sanTo"]').forEach(r => r.addEventListener('change', () => { z.to = r.value; }));
    const again = id => { render(res, where, S, H); const el = H.$(id); if (el) { el.focus(); if (id === 'sanFilter') el.setSelectionRange(el.value.length, el.value.length); } };
    H.$('sanFilter').addEventListener('input', e => { z.filter = e.target.value; again('sanFilter'); });
    H.$('sanRisky').addEventListener('change', e => { z.risky = e.target.checked; again('sanRisky'); });
    H.$('sanNone').addEventListener('click', () => { z.pick.clear(); again('sanNone'); });
    where.querySelectorAll('input[data-id]').forEach(cb => cb.addEventListener('change', () => {
      if (cb.checked && z.pick.size >= MAX) { cb.checked = false; H.say(`At most ${MAX} applications per change.`); return; }
      if (cb.checked) z.pick.set(cb.dataset.id, cb.dataset.name); else z.pick.delete(cb.dataset.id);
      H.$('sanCount').textContent = `${z.pick.size} picked`;
    }));
  }
  function spec(S) {
    const z = st(S);
    if (!z.pick.size) throw new Error('Pick at least one cloud application.');
    return { type: 'cloud_app_sanction', targets: [...z.pick].map(([id, name]) => ({ id, name, to: z.to })) };
  }

  window.OPS_PLUGINS.register({ type: 'cloud_app_sanction', render, spec });
})();
