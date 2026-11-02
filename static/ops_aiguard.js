// AI Guard builders for Bulk changes (/report/operations, "Build new"):
// the forms of the two operation types ops_aiguard.py registers,
// aiguard_routing and aiguard_detection_policy. Each form only builds the
// operation spec; reading, the preview, the gates, the apply, the read-back
// and Undo are the page's own (window.OPS_PLUGINS).
(function () {
  'use strict';
  if (!window.OPS_PLUGINS || window.__opsAiguardLoaded) return;
  window.__opsAiguardLoaded = true;

  const ST = { pass: ['ready', 'st-ok'], warn: ['check', 'st-warn'], fail: ['needed', 'st-fail'], info: ['note', ''], not_read: ['not read', ''] };
  const F = {
    aiguard_routing: { apps: null, certMode: '', certId: '', pem: '', pemName: '', block_quic: true, ssl_inspect: true, prompt_capture: true, allow_in_zia: true, prefix: '' },
    aiguard_detection_policy: { apps: null, profile: 'HIPAA', mode: 'monitor', prefix: '', picked: false, fromCompliance: '', cpAsked: false }
  };
  const MAX_PEM = 16384;
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function errorsHtml(res) {
    const errs = Object.entries(res.errors || {});
    return errs.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${errs.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : '';
  }

  function checksHtml(H, rd, ids) {
    const rows = (rd && rd.checks || []).filter(c => !ids || ids.includes(c.id));
    if (!rows.length) return '';
    return `<h3 class="op-h">Is AI Guard ready?</h3><ul class="op-gates">${rows.map(c => {
      const [lab, cls] = ST[c.status] || [c.status, ''];
      return `<li><span class="df-chip ${E(cls)}">${E(lab)}</span> <strong>${E(c.name)}</strong>: ${E(c.detail)}${c.fix ? ` <span class="df-hint">${E(c.fix)}</span>` : ''}</li>`;
    }).join('')}</ul>`;
  }
  function appsHtml(H, cat, st, legend) {
    if (!st.apps) st.apps = cat.apps.filter(a => a.default).map(a => a.id);
    return `<fieldset class="op-inline"><legend>${E(legend)}</legend>${cat.apps.map(a =>
      `<label class="df-ctl"><input type="checkbox" data-aig-app="${E(a.id)}"${st.apps.includes(a.id) ? ' checked' : ''}><span>${E(a.name)}</span></label>`).join('')}</fieldset>`;
  }
  function prefixHtml(H, st, names) {
    return `<div class="op-row"><label class="df-ctl"><span class="lbl">Name prefix (optional)</span><input id="aigPrefix" maxlength="12" value="${E(st.prefix)}" aria-label="Name prefix for the objects this builder creates" placeholder="ACME"></label>
      <span class="df-hint">Objects are named like ${E(names.proxy)}; Undo deletes only objects whose names carry AIG-.</span></div>`;
  }
  function assumedHtml(H, cat) {
    return `<details class="pa-details"><summary>What the app assumes (${(cat.assumed || []).length})</summary><ul>${(cat.assumed || []).map(a => `<li>${E(a)}</li>`).join('')}</ul></details>`;
  }
  function bindCommon(where, st) {
    where.querySelectorAll('input[data-aig-app]').forEach(cb => cb.addEventListener('change', () => {
      const id = cb.dataset.aigApp;
      st.apps = cb.checked ? st.apps.concat([id]) : st.apps.filter(x => x !== id);
    }));
    const pf = where.querySelector('#aigPrefix');
    if (pf) pf.addEventListener('input', () => { st.prefix = pf.value.trim(); });
    where.querySelectorAll('input[data-aig-opt]').forEach(cb => cb.addEventListener('change', () => { st[cb.dataset.aigOpt] = cb.checked; }));
  }

  // ── routing ──
  function renderRouting(res, where, S, H) {
    const st = F.aiguard_routing, cat = res.catalog || { apps: [], assumed: [] }, rd = res.readiness || {};
    const certs = res.certificates || [], proxies = res.proxies || [], scope = res.in_scope || {};
    if (!st.certMode) { st.certMode = certs.length ? 'existing' : 'upload'; st.certId = certs.length ? String(certs[0].id) : ''; }
    const gwMissing = (rd.checks || []).some(c => c.id === 'zia.gateway' && c.status === 'fail');
    where.innerHTML = `${errorsHtml(res)}
      <div class="df-hint">This sends the GenAI apps you pick through Zscaler AI Guard, which inspects every prompt and answer. Preview first: nothing changes until you apply in write mode.</div>
      ${checksHtml(H, rd)}
      ${gwMissing ? `<div class="bp-card warn"><div class="t">The proxy gateway is a step in the ZIA portal</div><ol class="pa-steps">${(cat.gateway_steps || []).map(s => `<li>${E(s)}</li>`).join('')}</ol><div>The plan still adds everything else; preview again once the gateway exists to add the forwarding rule.</div></div>` : ''}
      <h3 class="op-h">GenAI apps</h3>${appsHtml(H, cat, st, 'Send to AI Guard')}
      <h3 class="op-h">Root certificate for proxy chaining</h3>
      ${proxies.length ? `<div class="df-hint">ZIA already has an AI Guard proxy (${E(proxies.map(p => p.name).join(', '))}): it is reused with its own certificate.</div>` : ''}
      <fieldset class="op-inline"><legend>Certificate</legend>
        <label class="df-ctl"><input type="radio" name="aigCert" value="existing"${st.certMode === 'existing' ? ' checked' : ''}${certs.length ? '' : ' disabled'}><span>Use one already in ZIA</span></label>
        <label class="df-ctl"><input type="radio" name="aigCert" value="upload"${st.certMode === 'upload' ? ' checked' : ''}><span>Upload the AI Guard certificate</span></label></fieldset>
      <div id="aigCertExisting"${st.certMode === 'existing' ? '' : ' hidden'}><div class="op-row"><label class="df-ctl"><span class="lbl">Certificate</span><select id="aigCertId" aria-label="Root certificate already in ZIA">${certs.map(c => `<option value="${E(c.id)}"${String(c.id) === st.certId ? ' selected' : ''}>${E(c.name)}</option>`).join('') || '<option value="">None in ZIA</option>'}</select></label></div></div>
      <div id="aigCertUpload"${st.certMode === 'upload' ? '' : ' hidden'}><div class="op-block">
        <span class="lbl">The Proxy Chain certificate from the AI Guard portal (Tenant Settings, Integrations), as a .pem file or pasted</span>
        <input type="file" id="aigPemFile" accept=".pem,.crt,.cer" aria-label="AI Guard certificate file (.pem)">
        <textarea id="aigPem" rows="4" aria-label="AI Guard certificate (PEM)" placeholder="-----BEGIN CERTIFICATE-----">${E(st.pem)}</textarea></div></div>
      <h3 class="op-h">What else the plan adds</h3>
      <ul class="op-gates">
        <li><label class="df-ctl"><input type="checkbox" data-aig-opt="block_quic"${st.block_quic ? ' checked' : ''}><span>Block QUIC, so the apps use TCP 443 that ZIA can inspect</span></label></li>
        <li><label class="df-ctl"><input type="checkbox" data-aig-opt="ssl_inspect"${st.ssl_inspect ? ' checked' : ''}><span>An SSL Inspect rule for the apps at the top, above every Do Not Decrypt bypass</span></label>${scope.ssl_inspection ? '' : ' <span class="df-hint">Not in scope: mark SSL/TLS Inspection as Zscaler on the Scope page.</span>'}</li>
        <li><label class="df-ctl"><input type="checkbox" data-aig-opt="prompt_capture"${st.prompt_capture ? ' checked' : ''}><span>Turn on GenAI prompt capture for the apps</span></label>${res.genai_licensed === false ? ' <span class="df-hint">Needs the Gen AI Security subscription, which this tenant does not have: left off.</span>' : ''}</li>
        <li><label class="df-ctl"><input type="checkbox" data-aig-opt="allow_in_zia"${st.allow_in_zia ? ' checked' : ''}><span>Allow the apps in ZIA above any Block, Caution or Isolate rule, so they reach AI Guard</span></label>${scope.cloud_app_control ? '' : ' <span class="df-hint">Cloud App Control is not in scope: only URL filtering is checked.</span>'}</li>
      </ul>
      ${prefixHtml(H, st, res.names || {})}
      ${assumedHtml(H, cat)}`;
    bindCommon(where, st);
    where.querySelectorAll('input[name="aigCert"]').forEach(r => r.addEventListener('change', () => {
      st.certMode = r.value;
      where.querySelector('#aigCertExisting').hidden = r.value !== 'existing';
      where.querySelector('#aigCertUpload').hidden = r.value !== 'upload';
    }));
    const sel = where.querySelector('#aigCertId'); if (sel) sel.addEventListener('change', () => { st.certId = sel.value; });
    const ta = where.querySelector('#aigPem'); ta.addEventListener('input', () => { st.pem = ta.value; });
    where.querySelector('#aigPemFile').addEventListener('change', e => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      if (file.size > MAX_PEM) { H.say('The certificate file is larger than 16 KB: pick the PEM certificate from the AI Guard portal.'); e.target.value = ''; return; }
      const fr = new FileReader();
      fr.onload = () => { st.pem = String(fr.result || ''); ta.value = st.pem; H.say('Certificate read in the browser.'); };
      fr.readAsText(file);
    });
  }
  function specRouting() {
    const st = F.aiguard_routing;
    if (!st.apps || !st.apps.length) throw new Error('Pick at least one GenAI app.');
    const spec = { type: 'aiguard_routing', apps: st.apps.slice(), block_quic: st.block_quic, ssl_inspect: st.ssl_inspect,
      prompt_capture: st.prompt_capture, allow_in_zia: st.allow_in_zia };
    if (st.prefix) spec.prefix = st.prefix;
    if (st.certMode === 'existing' && st.certId) spec.cert = { mode: 'existing', id: st.certId };
    else if (st.certMode === 'upload' && st.pem.trim()) {
      if (st.pem.length > MAX_PEM) throw new Error('The certificate is larger than 16 KB.');
      spec.cert = { mode: 'upload', pem: st.pem.trim() };
    }
    return spec;
  }

  // ── detection policy ──
  function renderPolicy(res, where, S, H) {
    const st = F.aiguard_detection_policy, cat = res.catalog || { apps: [], profiles: [], assumed: [] }, rd = res.readiness || {};
    const pols = res.policies || [];
    // The one compliance choice (picked in the ZIA baseline builder, remembered per tenant profile) names the AI Guard profile.
    const C = window.ZMECompliance;
    const fromChoice = key => {
      const p = C && C.profile(key);
      if (!p || st.picked || !cat.profiles.some(x => x.id === p.aiguard)) return;
      st.profile = p.aiguard; st.fromCompliance = p.label;
    };
    if (C && !st.cpAsked) {
      st.cpAsked = true;
      Promise.all([C.catalog().catch(() => null), C.current ? Promise.resolve(C.current) : C.remembered()]).then(([, key]) => {
        if (key) { fromChoice(key); renderPolicy(res, where, S, H); }
      });
      C.onChange(key => { fromChoice(key); });
    }
    where.innerHTML = `${errorsHtml(res)}
      <div class="df-hint">This turns a compliance profile into an AI Guard detection policy and a match rule for the GenAI apps you pick. Monitor detects and logs only; Block stops prompts with the profile's identifiers and prompt attacks.</div>
      ${checksHtml(H, rd, ['aiguard.api', 'aiguard.policy'])}
      <div class="op-row"><label class="df-ctl"><span class="lbl">Compliance profile</span><select id="aigProfile" aria-label="Compliance profile">${cat.profiles.map(p => `<option value="${E(p.id)}"${p.id === st.profile ? ' selected' : ''}>${E(p.name)}</option>`).join('')}</select></label>
        <span class="df-hint" id="aigWhy">${E((cat.profiles.find(p => p.id === st.profile) || {}).why || '')}</span>
        ${st.fromCompliance && !st.picked ? `<span class="df-chip" id="aigFromCp">From the compliance profile: ${E(st.fromCompliance)}</span>` : ''}</div>
      <fieldset class="op-inline"><legend>Mode</legend>
        <label class="df-ctl"><input type="radio" name="aigMode" value="monitor"${st.mode === 'monitor' ? ' checked' : ''}><span>Monitor (detect only, recommended first)</span></label>
        <label class="df-ctl"><input type="radio" name="aigMode" value="block"${st.mode === 'block' ? ' checked' : ''}><span>Block</span></label></fieldset>
      <h3 class="op-h">GenAI apps</h3>${appsHtml(H, cat, st, 'Match these apps')}
      ${prefixHtml(H, st, res.names || {})}
      <div class="df-hint">${pols.length ? `AI Guard already has ${pols.length} detection polic${pols.length === 1 ? 'y' : 'ies'}: ${E(pols.slice(0, 5).map(p => p.name).join(', '))}. The new match rule goes after the existing rules.` : 'AI Guard has no detection policy yet.'}</div>
      ${assumedHtml(H, cat)}`;
    bindCommon(where, st);
    const prof = where.querySelector('#aigProfile');
    prof.addEventListener('change', () => {
      st.profile = prof.value; st.picked = true;
      where.querySelector('#aigWhy').textContent = (cat.profiles.find(p => p.id === st.profile) || {}).why || '';
      const chip = where.querySelector('#aigFromCp'); if (chip) chip.remove();
    });
    where.querySelectorAll('input[name="aigMode"]').forEach(r => r.addEventListener('change', () => { st.mode = r.value; }));
  }
  function specPolicy() {
    const st = F.aiguard_detection_policy;
    if (!st.apps || !st.apps.length) throw new Error('Pick at least one GenAI app.');
    const spec = { type: 'aiguard_detection_policy', profile: st.profile, mode: st.mode, apps: st.apps.slice() };
    if (st.prefix) spec.prefix = st.prefix;
    return spec;
  }

  window.OPS_PLUGINS.register({ type: 'aiguard_routing', render: renderRouting, spec: specRouting });
  window.OPS_PLUGINS.register({ type: 'aiguard_detection_policy', render: renderPolicy, spec: specPolicy });

  // A GenAI finding links here as /report/operations?build=<type>: pick that builder once.
  try {
    const want = new URLSearchParams(window.location.search).get('build');
    if (want === 'aiguard_routing' || want === 'aiguard_detection_policy') {
      const pick = () => {
        const r = document.querySelector(`input[name="opKind"][value="${want}"]`);
        if (!r || r.checked) return !!r;
        r.checked = true;
        r.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      };
      if (!pick()) setTimeout(pick, 300);
    }
  } catch (e) { /* no preselection */ }
})();
