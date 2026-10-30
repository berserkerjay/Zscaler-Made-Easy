// Bulk changes builders: the ZIA security baseline and the SSL certificate
// manager (ops_zia_baseline.py). Each registers its form on the Bulk changes
// page (window.OPS_PLUGINS); the page then runs it through the same preview,
// gates, apply and Undo as every other bulk change.
(function () {
  if (!window.OPS_PLUGINS || window.__opsZiaBaselineLoaded) return;
  window.__opsZiaBaselineLoaded = true;
  const E = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const RESTRICTIVE = /^(BLOCK|DENY|CAUTION|ISOLATE|DECRYPT|QUARANTINE)/;
  const restrictive = a => (Array.isArray(a) ? a : [a]).some(x => RESTRICTIVE.test(String(x || '')));
  const actLabel = a => {
    if (Array.isArray(a)) return a.some(x => /^(BLOCK|DENY)/.test(x)) ? 'Block' : a.some(x => /^CAUTION/.test(x)) ? 'Caution' : 'Allow';
    const s = String(a || '').replace(/_/g, ' ').toLowerCase();
    return s.charAt(0).toUpperCase() + s.slice(1);
  };
  const MAX_FILE = 2 * 1024 * 1024;
  // Source links come from the server's own catalogue (ops_zia_baseline.SOURCES); anything but https is not linked.
  const httpsOnly = u => (/^https:\/\//.test(String(u || '')) ? String(u) : '#');
  const errorsHtml = res => Object.entries((res && res.errors) || {}).map(([k, v]) =>
    `<div class="bp-card warn" role="alert"><div class="t">${E(k.replace(/_/g, ' '))} could not be read</div><div>${E(v)}</div></div>`).join('');

  function state(S, res) {
    if (!S.zb) {
      S.zb = { tier: 'balanced', overlays: new Set(), areas: null, prefix: 'BL', mode: 'tier', rules: {}, atp: {}, enable: false,
        profile: '', cert: '', framework: null, frameworkName: '', fileError: '', compliance: '', cpReady: false, cpSaved: '', cpInfo: null, cpError: '' };
    }
    if (!S.zb.areas && res && res.areas) {
      S.zb.areas = new Set(res.areas.filter(a => a.default && (res.in_scope || []).includes(a.key)).map(a => a.key));
    }
    return S.zb;
  }

  // The compliance profile picked (compliance_profiles.py): its entry in the catalogue the server sent.
  const cpOf = (res, z) => (res.compliance_profiles || []).find(p => p.key === z.compliance) || null;
  // The rules the review lists: the tier's catalog rules (changed by the
  // compliance profile as the server's _template_rules does), or a loaded framework's.
  function templateRules(res, z) {
    if (z.framework) {
      const out = [];
      Object.entries(z.framework.areas || {}).forEach(([area, rows]) => (rows || []).forEach((r, i) => out.push({
        key: `${area}.c${i + 1}`, area, suffix: r.name, name: r.name, title: r.title || r.name, def: r.default, locked: '', action_locked: '',
        catch_all: !!r.catch_all, default_on: true, choices: (res.areas.find(a => a.key === area) || {}).choices || [], sources: [] })));
      return out;
    }
    const sm = (cpOf(res, z) || {}).summary || {};
    const adds = {}, req = {}, forbid = new Set((sm.forbids || []).map(f => f.key));
    (sm.adds || []).forEach(a => { adds[a.key] = a; });
    (sm.requires || []).forEach(q => { req[q.key] = q; });
    const has = r => r.tiers && Object.prototype.hasOwnProperty.call(r.tiers, z.tier);
    return (res.rules || []).filter(r => !forbid.has(r.key) && (has(r) || adds[r.key]))
      .map(r => {
        const x = Object.assign({}, r, { def: has(r) ? r.tiers[z.tier] : adds[r.key].action, name: `${z.prefix}-${r.suffix}`, profileNote: '' });
        if (!has(r)) x.profileNote = `Added by ${sm.label} (${adds[r.key].control}): ${adds[r.key].why}`;
        if (req[r.key]) {
          x.locked = `required by ${sm.label} (${req[r.key].control}): always on, with the tier's action`;
          x.choices = [];
          x.profileNote = (x.profileNote ? x.profileNote + ' ' : '') + `Required by ${sm.label} (${req[r.key].control}).`;
        }
        return x;
      });
  }
  function effective(r, z) {
    const ch = z.rules[r.key] || {};
    let on = ch.on === undefined ? r.default_on !== false : ch.on;
    if (r.locked) on = true;
    let choice = ch.action || 'TIER';
    if (choice === 'TIER' && z.mode !== 'tier' && (r.choices || []).length) choice = z.mode === 'allow_all' ? 'ALLOW' : 'BLOCK';
    if (r.locked || r.action_locked || !(r.choices || []).includes(choice)) choice = 'TIER';
    let action = r.def;
    if (choice === 'ALLOW') action = Array.isArray(r.def) ? ['ALLOW'] : 'ALLOW';
    else if (choice === 'BLOCK') action = Array.isArray(r.def) ? ['BLOCK'] : 'BLOCK';
    else if (choice === 'ISOLATE') action = 'ISOLATE';
    let weakened = '';
    if (restrictive(r.def) && !on && r.default_on !== false) weakened = 'switched off';
    else if (restrictive(r.def) && !restrictive(action)) weakened = `${actLabel(r.def)} → ${actLabel(action)}`;
    // As the server's review (ops_zia_baseline.review): isolation and a caution page both let the user in.
    else if (String(r.def).startsWith('BLOCK') && (action === 'ISOLATE' || action === 'CAUTION')) weakened = `${actLabel(r.def)} → ${actLabel(action)}`;
    return { on, choice, action, weakened };
  }

  function renderBaseline(res, where, S, H) {
    const z = state(S, res);
    const inScope = new Set(res.in_scope || []);
    const nis = res.not_in_scope_areas || {};
    const rules = templateRules(res, z);
    const picked = a => z.areas && z.areas.has(a);
    const areaRules = a => rules.filter(r => r.area === a);
    const controlsFor = a => ((res.area_controls || {})[a] || []).filter(c => z.overlays.has(c.overlay));
    const choiceLabel = { TIER: 'Tier default', ALLOW: 'Allow', BLOCK: 'Block', ISOLATE: 'Isolate' };
    const weakCount = rules.filter(r => picked(r.area) && effective(r, z).weakened).length;
    const ruleRow = r => {
      const e = effective(r, z);
      const id = `zbr-${r.key.replace(/[^a-z0-9]/gi, '-')}`;
      const opts = ['TIER'].concat(r.locked || r.action_locked ? [] : (r.choices || []));
      return `<tr>
        <td><input type="checkbox" id="${E(id)}" data-zb-on="${E(r.key)}"${e.on ? ' checked' : ''}${r.locked ? ' disabled' : ''} aria-label="Include ${E(r.name)}"></td>
        <td><label for="${E(id)}">${E(r.name)}</label><div class="df-hint">${E(r.title)}</div></td>
        <td>${E(actLabel(r.def))}</td>
        <td>${opts.length > 1 ? `<select data-zb-act="${E(r.key)}" aria-label="Action for ${E(r.name)}">${opts.map(o => `<option value="${E(o)}"${e.choice === o ? ' selected' : ''}>${E(choiceLabel[o])}</option>`).join('')}</select>` : '<span class="df-hint">Tier default</span>'}</td>
        <td>${r.locked ? `<span class="df-chip">Locked</span> <span class="df-hint">${E(r.locked)}</span>` : ''}${r.action_locked ? `<span class="df-chip">Action locked</span> <span class="df-hint">${E(r.action_locked)}</span>` : ''}
          ${r.catch_all ? '<span class="df-chip">Goes last</span>' : ''}${e.weakened ? ` <span class="df-chip st-warn">Weaker than the tier: ${E(e.weakened)}</span>` : ''}
          ${r.profileNote ? `<div class="df-hint">${E(r.profileNote)}</div>` : ''}</td>
        <td>${(r.sources || []).map(s => `<a href="${E(httpsOnly(s.url))}" target="_blank" rel="noopener noreferrer">${E(s.title)}</a>`).join('<br>') || '<span class="df-hint">From the framework file</span>'}</td></tr>`;
    };
    const areaBlock = a => {
      if (!picked(a) || a === 'atp') return '';
      const list = areaRules(a);
      const ctrls = controlsFor(a);
      return `<h3 class="op-h">${E((res.areas.find(x => x.key === a) || {}).label || a)}</h3>
        ${ctrls.length ? `<div class="df-hint">Overlay controls: ${ctrls.map(c => `${E(c.label)}: ${E(c.controls.join('; '))} (<a href="${E(httpsOnly(c.source.url))}" target="_blank" rel="noopener noreferrer">${E(c.source.title)}</a>)`).join(' · ')}</div>` : ''}
        ${list.length ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">${E(a)} rules of the baseline</caption>
          <thead><tr><th scope="col">On</th><th scope="col">Rule</th><th scope="col">Tier default</th><th scope="col">Action</th><th scope="col">Notes</th><th scope="col">Source</th></tr></thead>
          <tbody>${list.map(ruleRow).join('')}</tbody></table></div>`
          : `<div class="df-hint">${z.framework ? 'The framework file has no rules for this area.' : 'This tier has no rules for this area.'}</div>`}`;
    };
    const atpBlock = () => {
      if (!picked('atp')) return '';
      const ctrls = controlsFor('atp');
      return `<h3 class="op-h">Advanced Threat Protection</h3>
        <div class="df-hint">These settings take effect when ZIA activates the change: they have no disabled state.${ctrls.length ? ` Overlay controls: ${ctrls.map(c => `${E(c.label)}: ${E(c.controls.join('; '))}`).join(' · ')}.` : ''}</div>
        <div class="op-row">${(res.atp || []).map(s => {
          const def = !(s.off_in || []).includes(z.tier); const v = z.atp[s.key] === undefined ? def : z.atp[s.key];
          return `<label class="df-ctl"><input type="checkbox" data-zb-atp="${E(s.key)}"${v ? ' checked' : ''}><span>${E(s.label)}${def && !v ? ' <span class="df-chip st-warn">Weaker than the tier</span>' : ''}</span></label>`;
        }).join('')}</div>`;
    };
    const C = window.ZMECompliance;
    if (C && !z.cpReady && !z.cpLoading) {
      // The choice remembered for the saved tenant profile picked above, once.
      z.cpLoading = true;
      Promise.all([C.catalog().catch(() => null), C.remembered()]).then(([, key]) => {
        z.cpReady = true; z.cpLoading = false;
        if (key && !z.compliance && (res.compliance_profiles || []).some(p => p.key === key)) { applyProfile(res, z, key); z.cpSaved = 'Remembered for this tenant profile.'; }
        renderBaseline(res, where, S, H);
      });
    }
    const cp = cpOf(res, z), cps = (cp && cp.summary) || null;
    const groups = {};
    (res.compliance_profiles || []).forEach(p => { (groups[p.group] = groups[p.group] || []).push(p); });
    const https = u => httpsOnly(u);
    const cpBlock = `<fieldset class="op-cp" style="border:0;margin:0 0 0.6rem;padding:0;min-width:0"><legend class="df-h">Compliance profile</legend>
        <div class="df-hint">One choice drives the tier, the overlay, the rules the profile adds or requires, the DLP policy packs offered, the AI Guard detection profile and the compliance pack. It is remembered for the saved tenant profile picked above.</div>
        <div class="op-row"><label class="df-ctl" style="max-width:100%"><span class="lbl">Compliance profile</span><select id="zbCompliance" aria-label="Compliance profile" style="max-width:100%">
          <option value="">None (no compliance profile)</option>${Object.keys(groups).map(g => `<optgroup label="${E(g)}">${groups[g].map(p => `<option value="${E(p.key)}"${z.compliance === p.key ? ' selected' : ''}>${E(p.label)}</option>`).join('')}</optgroup>`).join('')}</select></label>
          ${z.cpSaved ? `<span class="df-chip" role="status">${E(z.cpSaved)}</span>` : ''}</div>
        ${cps ? `<div class="bp-card" id="zbCpSummary"><div class="t">What ${E(cps.label)} will do</div><ul>${(cps.lines || []).map(l => `<li>${E(l)}</li>`).join('')}</ul>
          <div class="df-hint">${E(cps.reuses)}${cps.assumed_profile ? ` Assumed: ${E(cps.assumed_profile)}` : ''}</div>
          ${(cps.sources || []).length ? `<div class="df-hint">Sources: ${cps.sources.map(x => `<a href="${E(https(x.url))}" target="_blank" rel="noopener noreferrer">${E(x.title)}</a>`).join('; ')}</div>` : ''}
          ${(cps.assumed_controls || []).length ? `<div class="df-hint">Controls marked assumed (not verified against the source): ${E(cps.assumed_controls.join(', '))}</div>` : ''}
          ${cps.tier && !z.framework && cps.tier !== z.tier ? `<div class="df-chip st-warn" role="status">${E(cps.label)} builds on the ${E(cps.tier)} tier; this build uses ${E(z.tier)}. ${E(cps.tier_why)}</div>` : ''}
          <div class="op-row">${(cps.packs || []).map(pk => pk.available ? `<a class="rp-btn" href="/?simple=deploy&amp;pack=${encodeURIComponent(pk.id)}">Deploy ${E(pk.name)}</a>` : `<span class="df-hint">${E(pk.name)} is not installed</span>`).join('')}
            <span class="df-hint">AI Guard detection policy: ${E(cps.aiguard_name)} (pick AI Guard detection policy under Build new).</span></div>
          <h3 class="op-h">Compliance pack</h3>
          <div class="df-hint">Local files from the build on screen: nothing is written to the tenant. Every rule is mapped to a control of the profile or carries a reason code; the DLP test files hold synthetic test data only.</div>
          <div class="op-row" id="zbCpFiles">${[['mapping.html', 'Control mapping (HTML)'], ['mapping.xlsx', 'Control mapping (Excel)'], ['mapping.csv', 'Control mapping (CSV)'], ['policy.json', 'Policy export'], ['testplan.html', 'Test plan by control'], ['compliance-pack.zip', 'Everything, with the DLP test files (ZIP)']]
            .map(([id, l]) => `<button type="button" class="rp-btn" data-zb-cp-file="${E(id)}">${E(l)}</button>`).join('')}
            <button type="button" class="rp-btn" id="zbCpCheck">Check the mapping</button></div>
          ${z.cpInfo ? `<div class="df-hint" role="status">${E(z.cpInfo)}</div>` : ''}${z.cpError ? `<div class="df-chip st-fail" role="alert">${E(z.cpError)}</div>` : ''}</div>` : ''}
      </fieldset>`;
    where.innerHTML = `${errorsHtml(res)}
      <p>Build a ZIA security baseline: pick a tier (or load a framework file saved from another tenant), the compliance frameworks to map it to and the areas, then check each rule below and preview. New rules arrive disabled; nothing is written until you apply.</p>
      <fieldset class="op-kinds"><legend class="df-h">Tier</legend>
        ${(res.tiers || []).map(t => `<label class="op-kind"><input type="radio" name="zbTier" value="${E(t.key)}"${!z.framework && z.tier === t.key ? ' checked' : ''}${z.framework ? ' disabled' : ''}><span><strong>${E(t.label)}</strong><span class="df-hint">${E(t.what)}</span></span></label>`).join('')}
      </fieldset>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Or load a framework file (from Export from tenant, ZIA policy framework)</span><input type="file" id="zbFile" accept="application/json,.json" aria-label="Framework file"></label>
        ${z.framework ? `<span class="df-chip st-ok">Framework: ${E(z.frameworkName)}</span> <button type="button" class="rp-btn" id="zbClearFw">Use a tier instead</button>` : ''}
        ${z.fileError ? `<span class="df-chip st-fail" role="alert">${E(z.fileError)}</span>` : ''}</div>
      ${cpBlock}
      <fieldset class="op-kinds"><legend class="df-h">Compliance overlays</legend>
        <div class="df-hint">An overlay adds the controls of that framework to each rule it fits, with the document they come from. It does not change the rules.</div>
        <div class="op-row">${(res.overlays || []).map(o => `<label class="df-ctl"><input type="checkbox" data-zb-ov="${E(o.key)}"${z.overlays.has(o.key) ? ' checked' : ''}><span>${E(o.label)}</span></label>`).join('')}</div>
      </fieldset>
      <fieldset class="op-kinds"><legend class="df-h">Areas</legend>
        <div class="op-row">${(res.areas || []).map(a => `<label class="df-ctl"><input type="checkbox" data-zb-area="${E(a.key)}"${picked(a.key) ? ' checked' : ''}${inScope.has(a.key) ? '' : ' disabled'}><span>${E(a.label)}${a.key === 'atp' ? ' (only when picked)' : ''}</span></label>`).join('')}</div>
        ${(res.areas || []).filter(a => !inScope.has(a.key)).map(a => `<div class="df-hint">${E(a.label)}: ${E(nis[a.key] || 'Not in scope on the Scope page.')}</div>`).join('')}
      </fieldset>
      <div class="op-row">
        <label class="df-ctl"><span class="lbl">Rule name prefix</span><input id="zbPrefix" value="${E(z.prefix)}" maxlength="10" aria-label="Rule name prefix" ${z.framework ? 'disabled' : ''}></label>
        <label class="df-ctl"><span class="lbl">Whole baseline</span><select id="zbMode" aria-label="Allow or block for the whole baseline">
          ${[['tier', 'Tier default'], ['allow_all', 'Allow all'], ['block_all', 'Block all']].map(([v, l]) => `<option value="${E(v)}"${z.mode === v ? ' selected' : ''}>${E(l)}</option>`).join('')}</select></label>
        <label class="df-ctl"><span class="lbl">Isolation profile</span><select id="zbProfile" aria-label="Cloud Browser Isolation profile">
          <option value="">The tenant's default profile</option>${(res.isolation_profiles || []).map(p => `<option value="${E(p.name)}"${z.profile === p.name ? ' selected' : ''}>${E(p.name)}</option>`).join('')}</select></label>
        <label class="df-ctl"><span class="lbl">Certificate for Inspect rules</span><select id="zbCert" aria-label="Intermediate certificate for the Inspect rules">
          <option value="">The tenant's default certificate</option>${(res.certificates || []).map(c => `<option value="${E(c.name)}"${z.cert === c.name ? ' selected' : ''}>${E(c.name)}</option>`).join('')}</select></label>
      </div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zbEnable"${z.enable ? ' checked' : ''}><span>Create the rules enabled (off: every new rule arrives disabled, to be turned on after review)</span></label></div>
      <div class="op-row"><span class="df-chip">${rules.filter(r => picked(r.area) && effective(r, z).on).length} rules on</span>${weakCount ? `<span class="df-chip st-warn">${weakCount} weaker than the tier</span>` : ''}
        <span class="df-hint">Names are shortened to ZIA's 31 characters in the preview; categories, apps and profiles the tenant lacks are dropped there with a warning.</span></div>
      ${(res.areas || []).map(a => areaBlock(a.key)).join('')}${atpBlock()}
      ${z.areas && z.areas.size ? '' : '<div class="df-hint">No area is picked: tick at least one area above.</div>'}`;
    const rerender = (focusId) => { renderBaseline(res, where, S, H); if (focusId) { const el = document.getElementById(focusId); if (el) el.focus(); } };
    where.querySelectorAll('input[name="zbTier"]').forEach(r => r.addEventListener('change', () => { z.tier = r.value; z.rules = {}; z.atp = {}; rerender(); }));
    where.querySelectorAll('input[data-zb-ov]').forEach(c => c.addEventListener('change', () => { c.checked ? z.overlays.add(c.dataset.zbOv) : z.overlays.delete(c.dataset.zbOv); rerender(); }));
    where.querySelectorAll('input[data-zb-area]').forEach(c => c.addEventListener('change', () => { c.checked ? z.areas.add(c.dataset.zbArea) : z.areas.delete(c.dataset.zbArea); rerender(); }));
    where.querySelectorAll('input[data-zb-on]').forEach(c => c.addEventListener('change', () => { const k = c.dataset.zbOn; z.rules[k] = Object.assign({}, z.rules[k], { on: c.checked }); rerender(c.id); }));
    where.querySelectorAll('select[data-zb-act]').forEach(c => c.addEventListener('change', () => { const k = c.dataset.zbAct; z.rules[k] = Object.assign({}, z.rules[k], { action: c.value }); rerender(); }));
    where.querySelectorAll('input[data-zb-atp]').forEach(c => c.addEventListener('change', () => { z.atp[c.dataset.zbAtp] = c.checked; rerender(); }));
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };
    on('zbPrefix', 'change', e => { z.prefix = e.target.value.trim(); rerender('zbPrefix'); });
    on('zbMode', 'change', e => { z.mode = e.target.value; rerender('zbMode'); });
    on('zbProfile', 'change', e => { z.profile = e.target.value; });
    on('zbCert', 'change', e => { z.cert = e.target.value; });
    on('zbEnable', 'change', e => { z.enable = e.target.checked; });
    on('zbClearFw', 'click', () => { z.framework = null; z.frameworkName = ''; z.rules = {}; rerender(); });
    on('zbCompliance', 'change', async e => {
      applyProfile(res, z, e.target.value);
      z.cpSaved = ''; z.cpInfo = ''; z.cpError = '';
      rerender('zbCompliance');
      if (C) {
        const ok = await C.remember(z.compliance).catch(() => false);
        z.cpSaved = ok ? (z.compliance ? 'Remembered for this tenant profile.' : 'No compliance profile for this tenant profile.') : 'Pick a saved tenant profile above to remember this choice.';
        rerender('zbCompliance');
      }
      H.say(z.compliance ? `Compliance profile: ${(cpOf(res, z) || {}).label}.` : 'No compliance profile.');
    });
    where.querySelectorAll('button[data-zb-cp-file]').forEach(b => b.addEventListener('click', async () => {
      if (!C) return;
      z.cpError = '';
      try { await C.download({ compliance_profile: z.compliance, spec: specOf(z), file: b.dataset.zbCpFile }); H.say('Downloaded.'); } catch (err) { z.cpError = `Could not make the file: ${err.message}`; rerender(); }
    }));
    on('zbCpCheck', 'click', async () => {
      if (!C) return;
      z.cpError = '';
      try {
        const m = await C.manifest({ compliance_profile: z.compliance, spec: specOf(z) });
        const c = m.counts || {};
        z.cpInfo = `${c.rules} rules and settings: ${c.mapped} map to controls of ${m.label}, ${c.reasoned} carry a reason code, none has neither. ${(m.files || []).filter(f => f.dlp).length} synthetic DLP test files.${m.tier_warning ? ' ' + m.tier_warning : ''}`;
      } catch (err) { z.cpError = `Could not check the mapping: ${err.message}`; }
      rerender('zbCpCheck');
    });
    on('zbFile', 'change', async e => {
      const f = e.target.files && e.target.files[0];
      z.fileError = '';
      if (!f) return;
      if (f.size > MAX_FILE) { z.fileError = 'The file is larger than 2 MB: not a framework file.'; rerender(); return; }
      try {
        const data = JSON.parse(await f.text());
        if (!data || data.format !== 'zia-policy-framework' || typeof data.areas !== 'object') throw new Error('not a ZIA policy framework file');
        z.framework = data; z.frameworkName = String(data.name || f.name).slice(0, 120); z.rules = {};
        H.say(`Framework loaded: ${z.frameworkName}.`);
      } catch (err) { z.framework = null; z.fileError = `Could not load it: ${err.message}.`; }
      rerender();
    });
  }

  // Picking a compliance profile: its tier (unless a framework file is loaded), its overlay, the choice shared with the other builders.
  function applyProfile(res, z, key) {
    z.compliance = key || '';
    const p = cpOf(res, z);
    if (p && p.tier && !z.framework) z.tier = p.tier;
    if (p && p.overlay) z.overlays.add(p.overlay);
    z.rules = {}; z.atp = {};
    if (window.ZMECompliance) window.ZMECompliance.set(z.compliance);
  }
  function specOf(z) {
    const spec = { type: 'zia_baseline', tier: z.framework ? undefined : z.tier, overlays: [...z.overlays], areas: [...(z.areas || [])], prefix: z.prefix,
      mode: z.mode, rules: z.rules, atp: z.atp, enable_rules: !!z.enable, isolation_profile: z.profile, certificate: z.cert };
    if (z.compliance) spec.compliance_profile = z.compliance;
    if (z.framework) spec.framework = z.framework;
    return spec;
  }
  function baselineSpec(S) {
    const z = S.zb;
    if (!z || !z.areas || !z.areas.size) throw new Error('Pick at least one area.');
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$/.test(z.prefix)) throw new Error('The rule name prefix is 1 to 10 letters, digits, - or _.');
    return specOf(z);
  }

  // ── SSL certificate manager ──
  function renderCerts(res, where, S, H) {
    if (!S.zc) S.zc = { picked: new Set(), target: '' };
    const z = S.zc;
    const rules = res.ssl_rules || [], certs = res.certificates || [];
    const movable = r => r.inspect && !r.locked;
    where.innerHTML = `${errorsHtml(res)}
      <p>Each SSL inspection rule and the intermediate certificate it uses. Pick Inspect rules and the certificate to move them to, then preview. Devices must trust the new certificate's root before you activate the change.</p>
      <h3 class="op-h">Ready-to-use certificates</h3>
      ${certs.length ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Ready-to-use intermediate certificates</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Default</th><th scope="col">Expires</th></tr></thead>
        <tbody>${certs.map(c => `<tr><td>${E(c.name)}</td><td>${E(String(c.type || '').replace(/_/g, ' ').toLowerCase())}</td><td>${E(String(c.status || '').toLowerCase())}</td><td>${c.default_certificate ? 'Yes' : ''}</td><td>${E(c.cert_exp_date ? new Date(Number(c.cert_exp_date) * 1000).toISOString().slice(0, 10) : '')}</td></tr>`).join('')}</tbody></table></div>`
        : '<div class="df-hint">The tenant has no ready-to-use intermediate certificate besides its default, or they could not be read (see above): rules can only be moved back to the default certificate.</div>'}
      <h3 class="op-h">SSL inspection rules</h3>
      ${rules.length ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">SSL inspection rules and their certificates</caption>
        <thead><tr><th scope="col">Move</th><th scope="col">Rule</th><th scope="col">Action</th><th scope="col">State</th><th scope="col">Certificate</th></tr></thead>
        <tbody>${rules.map(r => { const id = `zc-${String(r.id).replace(/[^a-z0-9]/gi, '-')}`; return `<tr>
          <td><input type="checkbox" id="${E(id)}" data-zc="${E(r.id)}"${z.picked.has(String(r.id)) ? ' checked' : ''}${movable(r) ? '' : ' disabled'} aria-label="Move ${E(r.name)}"></td>
          <td><label for="${E(id)}">${E(r.name)}</label>${r.locked ? `<div class="df-hint">${E(r.locked)}</div>` : !r.inspect ? '<div class="df-hint">Not an Inspect rule: it uses no certificate.</div>' : ''}</td>
          <td>${E(r.inspect ? 'Inspect' : String(r.action || '').replace(/_/g, ' ').toLowerCase())}</td><td>${E(String(r.state || '').toLowerCase())}</td><td>${E(r.certificate)}</td></tr>`; }).join('')}</tbody></table></div>`
        : '<div class="df-hint">No SSL inspection rule was read: the policy is empty, or it could not be read (see above).</div>'}
      <div class="op-row"><label class="df-ctl"><span class="lbl">Move the picked rules to</span><select id="zcTarget" aria-label="Certificate to move the rules to">
        <option value="">Pick a certificate…</option><option value="default"${z.target === 'default' ? ' selected' : ''}>The tenant's default certificate</option>
        ${certs.filter(c => !c.default_certificate).map(c => `<option value="${E(c.id)}"${String(z.target) === String(c.id) ? ' selected' : ''}>${E(c.name)}</option>`).join('')}</select></label>
        <span class="df-chip">${z.picked.size} picked</span></div>`;
    where.querySelectorAll('input[data-zc]').forEach(c => c.addEventListener('change', () => { c.checked ? z.picked.add(c.dataset.zc) : z.picked.delete(c.dataset.zc); renderCerts(res, where, S, H); const el = document.getElementById(c.id); if (el) el.focus(); }));
    const t = document.getElementById('zcTarget'); if (t) t.addEventListener('change', () => { z.target = t.value; });
  }
  function certSpec(S) {
    const z = S.zc;
    if (!z || !z.picked.size) throw new Error('Pick at least one Inspect rule.');
    if (!z.target) throw new Error('Pick the certificate to move the rules to.');
    const num = v => (/^\d+$/.test(v) ? Number(v) : v);
    return { type: 'ssl_certificate_move', rules: [...z.picked].map(num), certificate: num(z.target) };
  }

  // effective: the form's own reading of a rule (on, action, weaker than the tier), kept beside the plugin for its parity test.
  window.OPS_PLUGINS.register({ type: 'zia_baseline', render: renderBaseline, spec: baselineSpec, effective });
  window.OPS_PLUGINS.register({ type: 'ssl_certificate_move', render: renderCerts, spec: certSpec });
})();
