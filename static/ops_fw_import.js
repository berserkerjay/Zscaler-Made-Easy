/* Firewall import from Palo Alto Networks on Bulk changes (/report/operations,
   "Build new"). The form takes the migration plan built on Migrate from another
   vendor (handed over in this tab, or a plan file chosen here) and sends its ZIA
   part as the operation (ops_fw_import.py). The page does the rest: Read from
   the tenant, Preview (every object and rule against the tenant), the gates,
   Apply, Undo. The plan is checked again on the server: it is never trusted. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const KEY = 'zme.panosPlan';
  const MAX_FILE = 4 * 1024 * 1024;

  function st(S) {
    if (!S.fwi) {
      S.fwi = { plan: null, name: '', error: '', enable: false };
      try {
        const raw = sessionStorage.getItem(KEY);
        if (raw && raw.length < MAX_FILE) {
          const d = JSON.parse(raw);
          if (d && d.format === 'panos-migration-plan') { S.fwi.plan = d; S.fwi.name = String(d.source_file || 'the migration page').slice(0, 120); }
        }
      } catch (e) { /* no hand-off */ }
    }
    return S.fwi;
  }

  function render(res, where, S, H) {
    const E = H.E, z = st(S), p = z.plan, zia = p && p.zia;
    const counts = (res && res.counts) || {};
    const rules = (zia && zia.rules) || [];
    where.innerHTML = `${H.errorsHtml(res || {})}
      <p class="df-hint">Load the migration plan you built on <a href="/report/vendor#panos">Migrate from another vendor</a> (Palo Alto Networks), then preview. The preview checks every group, service and rule against this tenant; nothing is written until you apply, and the rules arrive disabled.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Migration plan file (JSON)</span><input type="file" id="fwiFile" accept="application/json,.json" aria-label="Migration plan file"></label>
        ${p ? `<span class="df-chip st-ok">Plan: ${E(z.name)}</span>` : ''}</div>
      ${z.error ? `<div class="bp-card warn" role="alert">${E(z.error)}</div>` : ''}
      ${p && !zia ? '<div class="bp-card warn">This plan has nothing for ZIA (every rule went to ZPA or could not be mapped). Build the ZPA part with the ZPA builders.</div>' : ''}
      ${zia ? `<div class="op-row"><span class="df-chip">${E(rules.length)} rule(s)</span><span class="df-chip">${E((zia.ip_source_groups || []).length)} source group(s)</span>
          <span class="df-chip">${E((zia.ip_destination_groups || []).length)} destination group(s)</span><span class="df-chip">${E((zia.network_services || []).length)} network service(s)</span>
          <span class="df-hint">Prefix ${E(zia.prefix)} · the tenant has ${E(counts['Cloud Firewall rules'] == null ? '?' : counts['Cloud Firewall rules'])} Cloud Firewall rule(s)</span></div>
        <div class="op-row"><label class="df-ctl"><input type="checkbox" id="fwiEnable"${z.enable ? ' checked' : ''}><span>Create the rules enabled (they decide traffic as soon as ZIA activates)</span></label></div>
        <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Rules in the plan</caption>
          <thead><tr><th scope="col">Rule</th><th scope="col">From PAN-OS rule</th><th scope="col">Action</th><th scope="col">Matches</th></tr></thead>
          <tbody>${rules.map(r => `<tr><td>${E(r.name)}</td><td>${E(r.source_rule || '')}</td><td>${E(r.action)}</td>
            <td class="df-hint">${E([].concat(r.src_ip_groups || [], r.src_ips || []).join(', ') || 'any source')} → ${E([].concat(r.dest_ip_groups || [], r.dest_addresses || []).join(', ') || 'any destination')}${(r.nw_services || []).length ? ` · ${E(r.nw_services.join(', '))}` : ''}${(r.nw_applications || []).length ? ` · ${E(r.nw_applications.join(', '))}` : ''}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
    const f = document.getElementById('fwiFile');
    if (f) f.addEventListener('change', () => {
      const file = f.files && f.files[0];
      if (!file) return;
      if (file.size > MAX_FILE) { z.error = 'The file is larger than 4 MB: not a migration plan.'; render(res, where, S, H); return; }
      const rd = new FileReader();
      rd.onload = () => {
        try {
          const d = JSON.parse(String(rd.result));
          if (!d || d.format !== 'panos-migration-plan') throw new Error('not a migration plan from the migration page');
          z.plan = d; z.name = String(file.name).slice(0, 120); z.error = '';
          H.say(`Migration plan loaded: ${z.name}.`);
        } catch (e) { z.plan = null; z.error = `Could not load it: ${e.message}.`; }
        render(res, where, S, H);
      };
      rd.readAsText(file);
    });
    const en = document.getElementById('fwiEnable');
    if (en) en.addEventListener('change', () => { z.enable = en.checked; });
  }

  function spec(S) {
    const z = st(S);
    if (!z.plan || !z.plan.zia) throw new Error('Load a migration plan with ZIA rules first.');
    return Object.assign({}, z.plan.zia, { type: 'zia_firewall_import', enable: !!z.enable });
  }

  window.OPS_PLUGINS.register({ type: 'zia_firewall_import', render, spec });
})();
