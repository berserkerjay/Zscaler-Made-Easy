/* Client Connector live changes on Bulk changes (/report/operations, ops_zcc_live.py).
   Turn app profiles on or off, or change one app profile's DNS and tunnel
   settings from an allowlist (never a password). Devices get the change as
   soon as it is saved, so the page's typed confirmation is always the
   profile's name. The page does the rest: Preview, the gates, Apply, Undo. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const PLAT = { windows: 'Windows', macos: 'macOS', ios: 'iOS', android: 'Android', linux: 'Linux' };

  function st(S) {
    if (!S.zccLive) S.zccLive = { picks: {}, profile: '', values: {} };
    return S.zccLive;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  const key = p => `${p.platform}|${p.id}`;

  // ── on / off ──
  function renderState(res, where, S, H) {
    const E = H.E, z = st(S), rows = res.profiles || [];
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick up to ${E(res.max_targets || 10)} app profiles and what each should be. Devices get the change at once: you type the profile's name to confirm when you apply.</p>
      <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Client Connector app profiles</caption>
        <thead><tr><th scope="col">Profile</th><th scope="col">Platform</th><th scope="col">Now</th><th scope="col">Change to</th></tr></thead>
        <tbody>${rows.map(p => `<tr><th scope="row">${E(p.name)}</th><td>${E(PLAT[p.platform] || p.platform)}</td><td>${p.active ? 'on' : 'off'}</td>
          <td><select data-zl="${E(key(p))}" aria-label="Change ${E(p.name)} (${E(PLAT[p.platform] || p.platform)}) to">
            <option value="">leave as it is</option><option value="on"${z.picks[key(p)] === 'on' ? ' selected' : ''}>on</option><option value="off"${z.picks[key(p)] === 'off' ? ' selected' : ''}>off</option></select></td></tr>`).join('')
          || '<tr><td colspan="4">The tenant has no app profile.</td></tr>'}</tbody></table></div>`;
    where.querySelectorAll('select[data-zl]').forEach(s => s.addEventListener('change', () => {
      if (s.value) z.picks[s.dataset.zl] = s.value; else delete z.picks[s.dataset.zl];
    }));
  }
  function specState(S) {
    const z = st(S);
    const targets = Object.entries(z.picks).map(([k, to]) => { const [platform, id] = k.split('|'); return { id, platform, to }; });
    if (!targets.length) throw new Error('Pick at least one app profile to turn on or off.');
    return { type: 'zcc_app_profile_state', targets };
  }

  // ── settings ──
  function renderSettings(res, where, S, H) {
    const E = H.E, z = st(S), rows = res.profiles || [], settings = res.settings || [];
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick one app profile, then set only what should change; the preview shows each value now and after. Passwords are never read unless revealed on demand, and never changed here. Devices get the change at once: you type the profile's name to confirm.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">App profile</span><select id="zlProfile" aria-label="App profile to change">
        <option value="">Pick one…</option>${rows.map(p => `<option value="${E(key(p))}"${key(p) === z.profile ? ' selected' : ''}>${E(p.name)} (${E(PLAT[p.platform] || p.platform)})</option>`).join('')}</select></label></div>
      <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Settings this page can change</caption>
        <thead><tr><th scope="col">Setting</th><th scope="col">Set to</th><th scope="col">What it does</th></tr></thead>
        <tbody>${settings.map(s => `<tr><th scope="row">${E(s.label)}</th><td>${s.kind === 'list'
          ? `<input type="text" data-zs="${E(s.key)}" maxlength="4000" value="${E(z.values[s.key] == null ? '' : z.values[s.key])}" placeholder="leave empty to keep it" aria-label="${E(s.label)}: addresses, ranges or host names, separated by commas" spellcheck="false">`
          : `<select data-zs="${E(s.key)}" aria-label="${E(s.label)}"><option value="">leave as it is</option><option value="1"${z.values[s.key] === '1' ? ' selected' : ''}>on</option><option value="0"${z.values[s.key] === '0' ? ' selected' : ''}>off</option></select>`}</td>
          <td class="df-hint">${E(s.explain)}</td></tr>`).join('')}</tbody></table></div>`;
    document.getElementById('zlProfile').addEventListener('change', e => { z.profile = e.target.value; });
    where.querySelectorAll('[data-zs]').forEach(el => el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', () => {
      if (el.value === '') delete z.values[el.dataset.zs]; else z.values[el.dataset.zs] = el.value;
    }));
  }
  function specSettings(S) {
    const z = st(S);
    if (!z.profile) throw new Error('Pick the app profile.');
    const [platform, profile] = z.profile.split('|');
    const settings = {};
    Object.entries(z.values).forEach(([k, v]) => { if (String(v).trim() !== '') settings[k] = String(v).trim(); });
    if (!Object.keys(settings).length) throw new Error('Set at least one setting to change.');
    return { type: 'zcc_app_profile_settings', profile, platform, settings };
  }

  window.OPS_PLUGINS.register({ type: 'zcc_app_profile_state', render: renderState, spec: specState });
  window.OPS_PLUGINS.register({ type: 'zcc_app_profile_settings', render: renderSettings, spec: specSettings });
})();
