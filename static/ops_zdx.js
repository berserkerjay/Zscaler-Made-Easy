// ZDX probe setup: the forms of the three ZDX operation types (ops_zdx.py)
// on the Bulk changes page. Each registers with window.OPS_PLUGINS and goes
// through the page's own read, preview, gates, apply and Undo; this file
// only draws the form from the tenant read and builds the spec.
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const KIND = { web: 'Web probe', cloudpath: 'CloudPath probe', other: 'Probe' };
  const PROTO = { ADAPTIVE: 'Adaptive', ICMP: 'ICMP', TCP: 'TCP', UDP: 'UDP' };

  function zs(S) {
    if (!S.zdx) S.zdx = { template: '', tier: '', pre: {}, custom: [], interval: 5, protocol: 'ADAPTIVE', pick: new Set(), to: 'off', del: new Set(), names: {} };
    return S.zdx;
  }
  function data(res) { return (res && res.zdx) || { apps: [], catalogue: [], templates: [], tiers: [], intervals: [5, 10, 15, 30], protocols: Object.keys(PROTO) }; }
  // The tier (ops_zdx.TIERS): the one the ZIA security baseline form has picked, else the default.
  const tierOf = (d, key) => (d.tiers || []).find(t => t.tier === key) || null;
  function startTier(z, d, S) {
    if (z.tier && tierOf(d, z.tier)) return;
    const zb = S.zb && S.zb.tier;
    z.tier = tierOf(d, zb) ? zb : (tierOf(d, d.default_tier) ? d.default_tier : '');
  }
  // Start from a tier: its apps, its interval and whether it adds CloudPath probes.
  function useTier(z, d, key) {
    const t = tierOf(d, key);
    if (!t) return;
    z.tier = key; z.template = ''; z.pre = {};
    (t.predefined || []).forEach(p => { z.pre[p.provider] = { on: true, web: p.web !== false, cloudpath: p.cloudpath !== false, prefix: '' }; });
    z.custom.forEach(c => { c.cloudpath = !!t.cloudpath; });
    z.interval = t.interval_minutes || 5; z.protocol = t.protocol || 'ADAPTIVE';
  }
  function head(res, H) {
    const d = data(res);
    const na = d.not_available ? `<div class="bp-card risk" role="alert"><div class="t">ZDX could not be read</div><div>${H.E(d.not_available)}</div></div>` : '';
    const c = d.counts || {};
    const now = d.not_available ? '' : `<div class="df-hint">In the tenant now: ${H.E(c.apps || 0)} ZDX app${c.apps === 1 ? '' : 's'} (${H.E(c.apps_on || 0)} on), ${H.E(c.probes || 0)} probe${c.probes === 1 ? '' : 's'} (${H.E(c.probes_on || 0)} on).</div>`;
    const errs = Object.entries((res && res.errors) || {});
    const er = errs.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${errs.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
    // The licensed ZDX edition (editions.py): what it leaves out, in plain words; the preview leaves those apps out.
    const ed = d.edition || {};
    const edn = (ed.notes || []).length ? `<div class="bp-card info" id="zdxEdition" role="note"><div class="t">${H.E(ed.label ? `Edition: ${ed.label}` : 'ZDX edition')}</div><ul>${ed.notes.map(x => `<li>${H.E(x)}</li>`).join('')}</ul></div>` : '';
    return `${er}${na}${now}${edn}`;
  }
  const note = (H, res) => `<div class="df-hint">${H.E(data(res).assumed || '')}</div>`;

  // ── ZDX probe setup: template, apps and probes ──
  function useTemplate(z, d, id) {
    const t = (d.templates || []).find(x => x.id === id);
    z.template = id; z.pre = {}; z.custom = [];
    if (!t) return;
    (t.predefined || []).forEach(p => { z.pre[p.provider] = { on: true, web: p.web !== false, cloudpath: p.cloudpath !== false, prefix: '' }; });
    z.custom = (t.custom || []).map(c => ({ name: c.name, url: c.url, cloudpath: c.cloudpath !== false }));
    z.interval = t.interval_minutes || 5; z.protocol = t.protocol || 'ADAPTIVE';
    const tier = tierOf(d, z.tier);
    if (tier) z.interval = tier.interval_minutes || z.interval;   // the tier sets how often
  }
  function stateWord(p) { return !p.configured ? 'Not set up' : p.active ? 'On' : 'Off'; }
  function renderSetup(res, where, S, H) {
    const E = H.E, d = data(res), z = zs(S);
    startTier(z, d, S);
    if (!z.started) { z.started = true; if (!z.template) useTemplate(z, d, 'best_practice'); }
    const tiers = (d.tiers || []).map(t => `<label class="op-kind"><input type="radio" name="zdxTier" value="${E(t.tier)}"${z.tier === t.tier ? ' checked' : ''}>
        <span><strong>${E(t.label)}</strong> <span class="df-chip">every ${E(t.interval_minutes)} min${t.cloudpath ? ', CloudPath' : ', Web only'}</span><span class="df-hint">${E(t.about)}</span></span></label>`).join('');
    const tpl = (d.templates || []).map(t => `<label class="op-kind"><input type="radio" name="zdxTpl" value="${E(t.id)}"${z.template === t.id ? ' checked' : ''}>
        <span><strong>${E(t.name)}</strong><span class="df-hint">${E(t.about)}</span></span></label>`).join('');
    const rows = (d.catalogue || []).map(p => {
      const s = z.pre[p.provider] || { on: false, web: true, cloudpath: true, prefix: '' };
      const nm = E(p.label);
      return `<tr><td><input type="checkbox" data-pre="${E(p.provider)}" data-f="on" aria-label="Set up ${nm}"${s.on ? ' checked' : ''}></td>
        <td>${nm}<div class="df-by">${E(p.about)}</div></td>
        <td><span class="df-chip ${p.active ? 'st-ok' : ''}">${E(stateWord(p))}</span>${p.prefix ? ` <span class="df-by">prefix ${E(p.prefix)}</span>` : ''}</td>
        <td><input type="checkbox" data-pre="${E(p.provider)}" data-f="web" aria-label="Turn on the Web probe of ${nm}"${s.web ? ' checked' : ''}></td>
        <td><input type="checkbox" data-pre="${E(p.provider)}" data-f="cloudpath" aria-label="Turn on the CloudPath probe of ${nm}"${s.cloudpath ? ' checked' : ''}></td>
        <td>${p.needs_prefix ? `<input data-pre="${E(p.provider)}" data-f="prefix" value="${E(s.prefix)}" size="14" autocomplete="off" aria-label="Customer's tenant prefix for ${nm}" placeholder="${E(String(p.host || '').split('.')[0] === '<prefix>' ? 'acme' : '')}">` : '<span class="df-hint">not needed</span>'}</td></tr>`;
    }).join('');
    const cus = z.custom.map((c, i) => `<tr><td><input data-cus="${i}" data-f="name" value="${E(c.name)}" maxlength="64" aria-label="Name of custom app ${i + 1}"></td>
        <td><input data-cus="${i}" data-f="url" type="url" value="${E(c.url)}" maxlength="1024" aria-label="URL of custom app ${i + 1}" placeholder="https://portal.example.com/"></td>
        <td><input type="checkbox" data-cus="${i}" data-f="cloudpath" aria-label="Add a CloudPath probe to custom app ${i + 1}"${c.cloudpath ? ' checked' : ''}></td>
        <td><button type="button" class="rp-btn" data-rm="${i}" aria-label="Remove custom app ${i + 1}">Remove</button></td></tr>`).join('');
    where.innerHTML = `${head(res, H)}
      <p>Pick a template, then adjust the apps. Every app gets a Web probe (is the page reachable and how fast) and a CloudPath probe (the network path to it), for all users. Apps that already exist are skipped or only get what they lack; the preview shows each step.</p>
      ${tiers ? `<fieldset class="op-kinds" id="zdxTierSet"><legend class="op-h" id="zdxTierH">Tier</legend>
        <div class="df-hint">How closely to watch: a stricter tier monitors more apps, more often. Picking one sets the apps, the interval and the CloudPath probes below; the preview warns about anything looser than the tier.</div>${tiers}</fieldset>` : ''}
      <fieldset class="op-kinds"><legend class="op-h">Template</legend>${tpl}</fieldset>
      <h3 class="op-h">Predefined apps (Zscaler's own definitions)</h3>
      ${rows ? `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Predefined apps ZDX offers to this tenant</caption>
        <thead><tr><th scope="col">Set up</th><th scope="col">App</th><th scope="col">In the tenant</th><th scope="col">Web probe</th><th scope="col">CloudPath probe</th><th scope="col">Tenant prefix</th></tr></thead>
        <tbody>${rows}</tbody></table></div>` : '<div class="df-hint">No predefined apps listed: ZDX did not return its catalogue for this tenant (see above).</div>'}
      <h3 class="op-h">Custom apps (any URL)</h3>
      ${cus ? `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Custom apps to set up</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">URL</th><th scope="col">CloudPath probe</th><th scope="col">Remove</th></tr></thead><tbody>${cus}</tbody></table></div>`
        : '<div class="df-hint">No custom app yet: add one for a site the customer depends on (an internal portal, a line-of-business app).</div>'}
      <div class="op-row"><button type="button" class="rp-btn" id="zdxAdd">Add a custom app</button></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Probe interval</span><select id="zdxInterval" aria-label="How often the probes run">
          ${(d.intervals || []).map(n => `<option value="${E(n)}"${Number(z.interval) === Number(n) ? ' selected' : ''}>Every ${E(n)} minutes</option>`).join('')}</select></label>
        <label class="df-ctl"><span class="lbl">CloudPath protocol</span><select id="zdxProto" aria-label="CloudPath probe protocol">
          ${(d.protocols || []).map(p => `<option value="${E(p)}"${z.protocol === p ? ' selected' : ''}>${E(PROTO[p] || p)}</option>`).join('')}</select></label></div>
      <div class="df-hint">The interval and protocol apply to the custom apps' probes; a predefined app keeps the probes ZDX made for it.</div>
      ${note(H, res)}`;
    where.querySelectorAll('input[name="zdxTier"]').forEach(r => r.addEventListener('change', () => {
      useTier(z, d, r.value); renderSetup(res, where, S, H);
      const again = where.querySelector(`input[name="zdxTier"][value="${r.value}"]`); if (again) again.focus();
      H.say(`Tier ${r.closest('label').querySelector('strong').textContent} picked: its apps, every ${z.interval} minutes.`);
    }));
    where.querySelectorAll('input[name="zdxTpl"]').forEach(r => r.addEventListener('change', () => {
      useTemplate(z, d, r.value); renderSetup(res, where, S, H);
      const again = where.querySelector(`input[name="zdxTpl"][value="${r.value}"]`); if (again) again.focus();
      H.say(`Template ${r.closest('label').querySelector('strong').textContent} picked.`);
    }));
    where.querySelectorAll('[data-pre]').forEach(el => el.addEventListener(el.type === 'checkbox' ? 'change' : 'input', () => {
      const k = el.dataset.pre, s = z.pre[k] || (z.pre[k] = { on: false, web: true, cloudpath: true, prefix: '' });
      s[el.dataset.f] = el.type === 'checkbox' ? el.checked : el.value.trim();
    }));
    where.querySelectorAll('[data-cus]').forEach(el => el.addEventListener(el.type === 'checkbox' ? 'change' : 'input', () => {
      const c = z.custom[Number(el.dataset.cus)]; if (c) c[el.dataset.f] = el.type === 'checkbox' ? el.checked : el.value;
    }));
    where.querySelectorAll('[data-rm]').forEach(b => b.addEventListener('click', () => {
      z.custom.splice(Number(b.dataset.rm), 1); renderSetup(res, where, S, H); H.$('zdxAdd').focus(); H.say('Custom app removed.');
    }));
    H.$('zdxAdd').addEventListener('click', () => {
      if (z.custom.length >= 20) { H.say('At most 20 custom apps in one setup.'); return; }
      z.custom.push({ name: '', url: '', cloudpath: true }); renderSetup(res, where, S, H);
      const el = where.querySelector(`input[data-cus="${z.custom.length - 1}"][data-f="name"]`); if (el) el.focus();
    });
    H.$('zdxInterval').addEventListener('change', e => { z.interval = Number(e.target.value); });
    H.$('zdxProto').addEventListener('change', e => { z.protocol = e.target.value; });
  }
  function setupSpec(S) {
    const z = zs(S);
    const predefined = Object.entries(z.pre).filter(([, s]) => s.on).map(([provider, s]) => ({ provider, web: !!s.web, cloudpath: !!s.cloudpath, prefix: s.prefix || '' }));
    const custom = z.custom.filter(c => String(c.name || '').trim() || String(c.url || '').trim())
      .map(c => ({ name: String(c.name || '').trim(), url: String(c.url || '').trim(), cloudpath: !!c.cloudpath }));
    if (!predefined.length && !custom.length) throw new Error('Pick at least one predefined app or add a custom app.');
    const spec = { type: 'zdx_probes', template: z.template || '', predefined, custom, interval_minutes: Number(z.interval) || 5, protocol: z.protocol || 'ADAPTIVE' };
    if (z.tier) spec.tier = z.tier;
    return spec;
  }

  // ── Every app and probe (on or off, delete) ──
  const keyOf = (a, p) => `${a.key}|${p ? p.id : ''}`;
  // The pick cell of one app or probe row: a checkbox to turn it on or off,
  // or (mode 'del') a checkbox to delete it when it may be deleted.
  function pickCell(mode, z, a, p, E) {
    const k = keyOf(a, p), nm = p ? p.name : a.name;
    if (mode === 'del') {
      const ok = p ? p.deletable : a.deletable;
      return ok ? `<input type="checkbox" data-k="${E(k)}" data-name="${E(nm)}" aria-label="Delete ${E(nm)}"${z.del.has(k) ? ' checked' : ''}>`
        : '<span class="df-hint">turn off only</span>';
    }
    return `<input type="checkbox" data-k="${E(k)}" aria-label="Pick ${E(nm)}"${z.pick.has(k) ? ' checked' : ''}>`;
  }
  function rowsFor(d, z, H, mode) {
    const E = H.E;
    return (d.apps || []).map(a => {
      const appRow = `<tr><td>${pickCell(mode, z, a, null, E)}</td><td><strong>${E(a.name)}</strong></td><td>${E(a.type === 'PREDEFINED' ? 'Predefined app' : 'Custom app')}</td>
          <td>${E(a.host || '')}</td><td></td><td><span class="df-chip ${a.active ? 'st-ok' : ''}">${a.active ? 'on' : 'off'}</span></td></tr>`;
      const probes = (a.probes || []).map(p => `<tr><td>${pickCell(mode, z, a, p, E)}</td><td><span class="df-by" aria-hidden="true">↳</span> ${E(p.name)}</td><td>${E(KIND[p.kind] || p.type)}</td>
          <td>${E(p.target)}</td><td>${p.frequency ? `every ${E(Math.round(p.frequency / 60))} min` : ''}</td>
          <td><span class="df-chip ${p.active ? 'st-ok' : ''}">${p.active ? 'on' : 'off'}</span></td></tr>`).join('');
      return appRow + probes;
    }).join('');
  }
  function table(d, z, H, caption, mode) {
    const rows = rowsFor(d, z, H, mode);
    if (!rows) return `<div class="df-hint">${d.not_available ? 'Nothing is listed because ZDX could not be read (see above).' : 'This tenant has no ZDX apps yet: use ZDX probe setup (under Build new) to add some.'}</div>`;
    return `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">${H.E(caption)}</caption>
      <thead><tr><th scope="col">Pick</th><th scope="col">App or probe</th><th scope="col">Kind</th><th scope="col">Target</th><th scope="col">Interval</th><th scope="col">State</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  }
  function renderState(res, where, S, H) {
    const E = H.E, d = data(res), z = zs(S);
    where.innerHTML = `${head(res, H)}
      <p>Every ZDX app and probe in the tenant. Pick the ones to change, then preview: probes are turned off before their app (CloudPath before Web), and on after it.</p>
      <div class="op-row"><fieldset class="op-inline"><legend>Turn the picked ones</legend>
        <label><input type="radio" name="zdxTo" value="off"${z.to === 'off' ? ' checked' : ''}> Off</label>
        <label><input type="radio" name="zdxTo" value="on"${z.to === 'on' ? ' checked' : ''}> On</label></fieldset>
        <span class="df-chip" id="zdxCount">${z.pick.size} picked</span><button type="button" class="rp-btn" id="zdxNone">Clear</button></div>
      ${table(d, z, H, 'ZDX apps and probes', 'state')}
      ${note(H, res)}`;
    where.querySelectorAll('input[name="zdxTo"]').forEach(r => r.addEventListener('change', () => { z.to = r.value; }));
    where.querySelectorAll('input[data-k]').forEach(cb => cb.addEventListener('change', () => {
      if (cb.checked && z.pick.size >= 100) { cb.checked = false; H.say('At most 100 apps or probes per change.'); return; }
      cb.checked ? z.pick.add(cb.dataset.k) : z.pick.delete(cb.dataset.k);
      H.$('zdxCount').textContent = `${z.pick.size} picked`;
    }));
    H.$('zdxNone').addEventListener('click', () => { z.pick.clear(); renderState(res, where, S, H); H.$('zdxNone').focus(); });
  }
  function stateSpec(S) {
    const z = zs(S);
    if (!z.pick.size) throw new Error('Pick at least one app or probe.');
    return { type: 'zdx_probe_state', targets: [...z.pick].map(k => { const [app, probe] = k.split('|'); return { app, probe: probe || null, to: z.to }; }) };
  }

  function renderDelete(res, where, S, H) {
    const E = H.E, d = data(res), z = zs(S);
    where.innerHTML = `${head(res, H)}
      <p>Delete custom apps (their probes go first, CloudPath before Web) and custom probes. Zscaler's predefined apps and their own probes can only be turned off. Deleting cannot be undone: type each name exactly to confirm it.</p>
      ${table(d, z, H, 'ZDX apps and probes that can be deleted', 'del')}
      <div id="zdxNames"></div>${note(H, res)}`;
    const names = () => {
      const box = H.$('zdxNames');
      const picked = [...z.del];
      box.innerHTML = picked.length ? `<h3 class="op-h">Type each name to confirm</h3>${picked.map((k, i) => {
        const cb = where.querySelector(`input[data-k="${CSS.escape(k)}"]`); const nm = cb ? cb.dataset.name : k;
        return `<div class="op-row"><label class="df-ctl"><span class="lbl">Type ${E(nm)}</span><input data-nk="${E(k)}" value="${E(z.names[k] || '')}" autocomplete="off" aria-label="Type ${E(nm)} to confirm deleting it" id="zdxN${i}"></label></div>`;
      }).join('')}` : '';
      box.querySelectorAll('input[data-nk]').forEach(el => el.addEventListener('input', () => { z.names[el.dataset.nk] = el.value; }));
    };
    where.querySelectorAll('input[data-k]').forEach(cb => cb.addEventListener('change', () => {
      if (cb.checked) z.del.add(cb.dataset.k); else { z.del.delete(cb.dataset.k); delete z.names[cb.dataset.k]; }
      names();
    }));
    names();
  }
  function deleteSpec(S) {
    const z = zs(S);
    if (!z.del.size) throw new Error('Pick at least one custom app or probe to delete.');
    const missing = [...z.del].filter(k => !String(z.names[k] || '').trim());
    if (missing.length) throw new Error('Type the name of each app or probe you picked to confirm deleting it.');
    return { type: 'zdx_probe_delete', targets: [...z.del].map(k => { const [app, probe] = k.split('|'); return { app, probe: probe || null, name: z.names[k] }; }) };
  }

  window.OPS_PLUGINS.register({ type: 'zdx_probes', render: renderSetup, spec: setupSpec });
  window.OPS_PLUGINS.register({ type: 'zdx_probe_state', render: renderState, spec: stateSpec });
  window.OPS_PLUGINS.register({ type: 'zdx_probe_delete', render: renderDelete, spec: deleteSpec });
})();
