/* Client Connector profiles on Bulk changes (/report/operations, "Build new").
   Two forms on the shared engine (ops_zcc.py): build a forwarding profile and
   a Windows or macOS app profile from a template, or delete a profile. The
   page does the rest: Read from the tenant, Preview (every setting with its
   value, the portal default and what it does), the gates, Apply, Undo. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function st(S) {
    if (!S.zcc) {
      S.zcc = { platform: 'windows', fwdTpl: 'best_practice', fwdName: '', fwdId: '', appTpl: 'best_practice', appName: '',
        fwdOn: null, appOn: null, enable: false, del: '', pw: {}, salt: '' };
    }
    return S.zcc;
  }
  // Tamper passwords: kept in this object only while the page is open (never
  // in the browser's storage), sent beside the operation, never in it.
  function newSalt() {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  }
  function typedPasswords(z) {
    const out = {};
    Object.entries(z.pw || {}).forEach(([k, v]) => { if (v) out[`${k}_password`] = v; });
    return out;
  }
  function forgetPasswords(z) {
    z.pw = {}; z.salt = '';
    document.querySelectorAll('input[data-zpw]').forEach(el => { el.value = ''; });
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function tplKeys(cat, z, kind) {
    if (kind === 'fwd') return ((cat.forwarding.templates || []).find(t => t.id === z.fwdTpl) || { settings: [] }).settings;
    return ((cat.app[z.platform].templates || []).find(t => t.id === z.appTpl) || { settings: [] }).settings;
  }
  function radios(H, name, opts, val, legend) {
    return `<fieldset class="op-inline"><legend>${H.E(legend)}</legend>${opts.map(([v, l, hint]) =>
      `<label><input type="radio" name="${name}" value="${H.E(v)}"${v === val ? ' checked' : ''}> ${H.E(l)}</label>${hint ? ` <span class="df-hint">${H.E(hint)}</span>` : ''}`).join(' ')}</fieldset>`;
  }
  function settingsTable(H, rows, on, kind, caption) {
    return `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">${H.E(caption)}</caption>
      <thead><tr><th scope="col">Use</th><th scope="col">Setting</th><th scope="col">Value</th><th scope="col">Portal default</th><th scope="col">What it does</th></tr></thead>
      <tbody>${rows.map(s => `<tr><td><input type="checkbox" data-zk="${kind}:${H.E(s.key)}" aria-label="Use ${H.E(s.label)}"${on.has(s.key) ? ' checked' : ''}></td>
        <td>${H.E(s.label)}${s.impact === 'caution' ? ' <span class="df-chip st-warn">check first</span>' : ''}<div class="df-by">${H.E(s.category)}</div></td>
        <td>${H.E(s.value)}</td><td>${H.E(s.portal_default)}</td><td class="df-hint">${H.E(s.explain)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  // ── Build ──
  function renderBuild(res, where, S, H) {
    const E = H.E, z = st(S), cat = res.catalog || {}, inv = res.inventory || { forwarding: [], app: {} };
    if (!cat.forwarding) { where.innerHTML = `${errs(H, res)}<div class="df-hint">Read from the tenant to load the templates.</div>`; return; }
    if (z.fwdOn === null) z.fwdOn = new Set(tplKeys(cat, z, 'fwd'));
    if (z.appOn === null) z.appOn = new Set(tplKeys(cat, z, 'app'));
    const fwds = inv.forwarding || [];
    const ftpls = (cat.forwarding.templates || []).map(t => [t.id, t.label, t.describe]);
    const atpls = (cat.app[z.platform].templates || []).map(t => [t.id, t.label, t.describe]);
    const plats = (cat.platforms || []).map(p => [p.id, p.label]);
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick the platform and the templates, untick any setting you do not want, then preview. Nothing is written until you apply, and the profiles are created disabled.</p>
      <h3 class="op-h">1. Platform</h3>
      <div class="op-row">${radios(H, 'zcPlat', plats, z.platform, 'Platform')}</div>
      <h3 class="op-h">2. Forwarding profile</h3>
      <div class="op-row">${radios(H, 'zcFwdTpl', ftpls, z.fwdTpl, 'Forwarding profile')}</div>
      <div class="op-row">${z.fwdTpl === 'existing'
        ? `<label class="df-ctl"><span class="lbl">Existing forwarding profile</span><select id="zcFwdId" aria-label="Existing forwarding profile">
            <option value="">Pick one…</option>${fwds.map(f => `<option value="${E(f.id)}"${f.id === z.fwdId ? ' selected' : ''}>${E(f.name)} (used by ${E(f.used_by)} app profile${f.used_by === 1 ? '' : 's'})</option>`).join('')}</select></label>
           ${fwds.length ? '' : '<span class="df-hint">The tenant has no forwarding profile yet: pick best practice instead.</span>'}`
        : `<label class="df-ctl"><span class="lbl">Forwarding profile name</span><input id="zcFwdName" value="${E(z.fwdName)}" maxlength="64" aria-label="Forwarding profile name" placeholder="Best practice forwarding"></label>`}</div>
      <h3 class="op-h">3. App profile</h3>
      <div class="op-row">${radios(H, 'zcAppTpl', atpls, z.appTpl, 'App profile template')}</div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">App profile name</span><input id="zcAppName" value="${E(z.appName)}" maxlength="64" aria-label="App profile name" placeholder="Best practice ${E(z.platform === 'macos' ? 'macOS' : 'Windows')}"></label></div>
      <h3 class="op-h">4. Customize</h3>
      ${z.fwdTpl === 'existing' ? '<div class="df-hint">The existing forwarding profile is linked as it is; nothing in it changes.</div>'
        : settingsTable(H, cat.forwarding.settings || [], z.fwdOn, 'fwd', 'Forwarding profile settings')}
      ${settingsTable(H, cat.app[z.platform].settings || [], z.appOn, 'app', 'App profile settings')}
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zcEnable"${z.enable ? ' checked' : ''}><span>Turn the profiles on when they are created (off by default: review them in the Client Connector Portal first)</span></label></div>
      <h3 class="op-h" id="zcPwH">5. Tamper protection passwords (optional)</h3>
      <p class="df-hint" id="zcPwHint">Leave a box empty to set no password. A password you type is sent once, when the app profile is created, and never kept: not in the plan, the record, the audit log or this browser. The preview shows it as "set (hidden)", and you type it again to apply.</p>
      <div class="op-row zc-pw" role="group" aria-labelledby="zcPwH">${((cat.tamper || {}).fields || []).map(f =>
        `<label class="df-ctl"><span class="lbl">${E(f.label)}</span><input type="password" id="zcPw_${E(f.key)}" data-zpw="${E(f.key)}" maxlength="${E((cat.tamper || {}).max || 128)}" autocomplete="new-password" spellcheck="false" aria-describedby="zcPwHint"></label>`).join('')}</div>
      <ul class="op-checks">${((cat.tamper || {}).notes || []).map(n => `<li class="df-hint">${E(n)}</li>`).join('')}</ul>
      <ul class="op-checks">${(cat.not_set_here || []).map(n => `<li class="df-hint">${E(n)}</li>`).join('')}</ul>
      <div class="df-hint">6. Review and 7. preview: click Preview the change below. 8. Apply needs write mode, your permission to change the tenant, the assessor's name, the typed confirmation and any password typed again.</div>`;
    const again = id => { renderBuild(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="zcPlat"]').forEach(r => r.addEventListener('change', () => { z.platform = r.value; z.appOn = null; again('zcPlat'); }));
    where.querySelectorAll('input[name="zcFwdTpl"]').forEach(r => r.addEventListener('change', () => { z.fwdTpl = r.value; z.fwdOn = null; again('zcFwdTpl'); }));
    where.querySelectorAll('input[name="zcAppTpl"]').forEach(r => r.addEventListener('change', () => { z.appTpl = r.value; z.appOn = null; again('zcAppTpl'); }));
    const bind = (id, key) => { const el = document.getElementById(id); if (el) el.addEventListener('input', e => { z[key] = e.target.value; }); };
    bind('zcFwdName', 'fwdName'); bind('zcAppName', 'appName');
    const sel = document.getElementById('zcFwdId'); if (sel) sel.addEventListener('change', e => { z.fwdId = e.target.value; });
    document.getElementById('zcEnable').addEventListener('change', e => { z.enable = e.target.checked; });
    // Set as properties, never written into the page's HTML.
    where.querySelectorAll('input[data-zpw]').forEach(el => {
      el.value = (z.pw || {})[el.dataset.zpw] || '';
      el.addEventListener('input', () => { z.pw[el.dataset.zpw] = el.value; });
    });
    where.querySelectorAll('input[data-zk]').forEach(cb => cb.addEventListener('change', () => {
      const [kind, key] = cb.dataset.zk.split(':'); const set = kind === 'fwd' ? z.fwdOn : z.appOn;
      if (cb.checked) set.add(key); else set.delete(key);
    }));
  }
  function specBuild(S) {
    const z = st(S);
    if (!z.appName.trim()) throw new Error('Give the app profile a name.');
    const fwd = { template: z.fwdTpl };
    if (z.fwdTpl === 'existing') {
      if (!z.fwdId) throw new Error('Pick the existing forwarding profile to link to.');
      fwd.id = z.fwdId;
    } else {
      if (!z.fwdName.trim()) throw new Error('Give the forwarding profile a name.');
      fwd.name = z.fwdName.trim(); fwd.settings = [...(z.fwdOn || [])];
    }
    const app = { template: z.appTpl, name: z.appName.trim(), settings: [...(z.appOn || [])] };
    const set = Object.keys(z.pw || {}).filter(k => z.pw[k]);
    if (set.length) {
      if (!z.salt) z.salt = newSalt();
      app.tamper = { set, salt: z.salt };   // which passwords and a salt: never a password
    }
    return { type: 'zcc_profile_build', platform: z.platform, forwarding: fwd, app, enable: !!z.enable };
  }

  // ── Delete ──
  function rowsFor(inv) {
    const out = (inv.forwarding || []).map(f => ({ k: `forwarding|${f.id}`, kind: 'forwarding', id: f.id, name: f.name, platform: '',
      what: 'Forwarding profile', note: f.used_by ? `In use by ${f.used_by} app profile${f.used_by === 1 ? '' : 's'}: cannot be deleted` : '' }));
    Object.entries(inv.app || {}).forEach(([p, list]) => (list || []).forEach(a => out.push({ k: `app|${a.id}|${p}`, kind: 'app', id: a.id, name: a.name,
      platform: p, what: `${p === 'macos' ? 'macOS' : 'Windows'} app profile`, note: a.active ? 'Enabled: disable it in the Client Connector Portal first' : '' })));
    return out;
  }
  function renderDelete(res, where, S, H) {
    const E = H.E, z = st(S), rows = rowsFor(res.inventory || {});
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick one profile. A profile in use is refused: an enabled app profile, or a forwarding profile an app profile links to. You type the profile's name to confirm when you apply.</p>
      <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Client Connector profiles</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">Profile</th><th scope="col">Kind</th><th scope="col">Note</th></tr></thead>
        <tbody>${rows.map(r => `<tr><td><input type="radio" name="zcDel" value="${E(r.k)}" aria-label="Delete ${E(r.name)}"${z.del === r.k ? ' checked' : ''}${r.note ? ' disabled' : ''}></td>
          <td>${E(r.name)}</td><td>${E(r.what)}</td><td class="df-hint">${E(r.note)}</td></tr>`).join('')
          || '<tr><td colspan="4">The tenant has no Windows or macOS app profile and no forwarding profile, so there is nothing to delete.</td></tr>'}</tbody></table></div>`;
    where.querySelectorAll('input[name="zcDel"]').forEach(r => r.addEventListener('change', () => { z.del = r.value; }));
    S.zccDelRows = rows;
  }
  function specDelete(S) {
    const z = st(S), r = (S.zccDelRows || []).find(x => x.k === z.del);
    if (!r) throw new Error('Pick the profile to delete.');
    const t = { kind: r.kind, id: r.id, name: r.name };
    if (r.kind === 'app') t.platform = r.platform;
    return { type: 'zcc_profile_delete', targets: [t] };
  }

  window.OPS_PLUGINS.register({ type: 'zcc_profile_build', render: renderBuild, spec: S => specBuild(S),
    // Sent beside the operation for its preview and its apply, never inside it.
    secrets: S => ({ tamper_passwords: typedPasswords(st(S)) }),
    // Applied (or not): the typed passwords are dropped from the page either way.
    result: () => { const S = window.OPS_PLUGINS.state; if (S) forgetPasswords(st(S)); } });
  window.OPS_PLUGINS.register({ type: 'zcc_profile_delete', render: renderDelete, spec: S => specDelete(S) });
})();
