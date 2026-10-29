// ZPA builder forms for Bulk changes (/report/operations, "Build new").
// The engine (admin_ops + ops_zpa.py) plans, previews, gates, applies,
// reads back and offers Undo; these forms only collect the spec. A new
// provisioning key is fetched once, right after the apply, and never stored.
(function () {
  'use strict';
  if (!window.OPS_PLUGINS || window.__opsZpaLoaded) return;   // the page loads the script once per type
  window.__opsZpaLoaded = true;
  const F = { prefix: '', mode: 'create', cg: '', location: 'san_jose', max: '5', wDomain: '', wTcp: '1-65535', wUdp: '', vertical: '', pDomain: '',
    csv: '', csvName: '', enable: false, baDomain: '', baPort: '443', baCert: '', rdp: '', ssh: '', portal: '', segCg: '',
    access: true, timeout: true, inspection: false, iso: '', rt: '28800', it: '3600', everything: false, pick: new Set() };
  const PREFIX = /^[A-Za-z0-9_-]{1,20}$/;
  let E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function opt(list, val, first) {
    return (first || '') + (list || []).map(x => `<option value="${E(x.id)}"${String(x.id) === String(val) ? ' selected' : ''}>${E(x.label || x.name)}</option>`).join('');
  }
  function bind(where, rerender) {
    where.querySelectorAll('[data-f]').forEach(el => {
      const k = el.dataset.f;
      const ev = el.tagName === 'SELECT' || el.type === 'checkbox' || el.type === 'radio' ? 'change' : 'input';
      el.addEventListener(ev, () => {
        if (el.type === 'checkbox') F[k] = el.checked;
        else if (el.type === 'radio') { if (el.checked) F[k] = el.value; }
        else F[k] = el.value;
        if (el.dataset.rerender) rerender(el.id);
      });
    });
  }
  function prefixRow() {
    return `<div class="op-row"><label class="df-ctl"><span class="lbl">Prefix</span><input id="zbPrefix" data-f="prefix" value="${E(F.prefix)}"
      maxlength="20" autocomplete="off" aria-describedby="zbPrefixHint" placeholder="pov1"></label>
      <span class="df-hint" id="zbPrefixHint">1 to 20 letters, digits, - or _. Every object is named with it (pov1-server-group, ...), so running the same build again updates them instead of making copies.</span></div>`;
  }
  function needPrefix() {
    const p = String(F.prefix || '').trim();
    if (!PREFIX.test(p)) throw new Error('Enter a prefix: 1 to 20 letters, digits, - or _.');
    return p;
  }
  function errs(res) {
    const list = Object.entries(res.errors || {});
    return list.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${list.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : '';
  }

  // ── App Connector group and provisioning key ──
  function renderGroup(res, where, H) {
    const groups = (res.connector_groups || []).map(g => ({ id: g.id, label: `${g.name} (${g.connectors} App Connector${g.connectors === 1 ? '' : 's'})` }));
    where.innerHTML = `${errs(res)}${prefixRow()}
      <fieldset class="op-inline"><legend>App Connector group</legend>
        <label class="df-ctl"><input type="radio" name="zbMode" data-f="mode" data-rerender="1" id="zbModeNew" value="create"${F.mode === 'create' ? ' checked' : ''}><span>Create one named with the prefix</span></label>
        <label class="df-ctl"><input type="radio" name="zbMode" data-f="mode" data-rerender="1" id="zbModeOld" value="existing"${F.mode === 'existing' ? ' checked' : ''}><span>Reuse an existing one</span></label></fieldset>
      ${F.mode === 'existing' ? `<div class="op-row"><label class="df-ctl"><span class="lbl">Existing group</span><select id="zbCg" data-f="cg">${opt(groups, F.cg, '<option value="">Pick a group…</option>')}</select></label>
          ${groups.length ? '' : '<span class="df-hint">This tenant has no App Connector group yet: create one instead.</span>'}</div>`
        : `<div class="op-row"><label class="df-ctl"><span class="lbl">Location</span><select id="zbLoc" data-f="location">${opt(res.locations, F.location)}</select></label></div>`}
      <div class="op-row"><label class="df-ctl"><span class="lbl">App Connectors that may enroll with the key</span><input id="zbMax" data-f="max" type="number" min="1" max="500" value="${E(F.max)}"></label></div>
      <div class="df-hint">The provisioning key is what an App Connector uses to enroll. It is shown once, right after the apply: copy it then. This app never keeps, logs or exports it.</div>`;
    bind(where, id => { renderGroup(res, where, H); const el = document.getElementById(id); if (el) el.focus(); });
  }
  // The number as typed: a whole number goes as a number, anything else (0.5, 1e3, 'ten')
  // goes as typed so the server answers its own plain error, never a silent 5; blank is 5.
  function maxUsage() {
    const v = String(F.max == null ? '' : F.max).trim();
    return !v ? 5 : /^\d{1,6}$/.test(v) ? Number(v) : v;
  }
  function specGroup() {
    const spec = { type: 'zpa_connector_group', prefix: needPrefix(), mode: F.mode, location: F.location, max_usage: maxUsage() };
    if (F.mode === 'existing') { if (!F.cg) throw new Error('Pick the existing App Connector group.'); spec.connector_group_id = F.cg; }
    return spec;
  }

  // ── Application segments ──
  function renderSegments(res, where, H) {
    const lim = res.limits || {};
    const vert = (res.verticals || []).find(v => v.id === F.vertical);
    where.innerHTML = `${errs(res)}${prefixRow()}
      <div class="op-row"><label class="df-ctl"><span class="lbl">App Connector group</span><select id="zbSegCg" data-f="segCg">${opt(res.connector_groups, F.segCg, `<option value="">The prefix's own (${E(F.prefix || 'prefix')}-connector-group)</option>`)}</select></label></div>
      <h3 class="op-h">A wildcard domain</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Domain (*. is added)</span><input id="zbWDom" data-f="wDomain" value="${E(F.wDomain)}" placeholder="corp.example.com"></label>
        <label class="df-ctl"><span class="lbl">TCP ports</span><input id="zbWTcp" data-f="wTcp" value="${E(F.wTcp)}" placeholder="1-65535"></label>
        <label class="df-ctl"><span class="lbl">UDP ports</span><input id="zbWUdp" data-f="wUdp" value="${E(F.wUdp)}" placeholder="none"></label></div>
      <h3 class="op-h">A preset for the customer's sector</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Preset</span><select id="zbVert" data-f="vertical" data-rerender="1">${opt(res.verticals, F.vertical, '<option value="">None</option>')}</select></label>
        <label class="df-ctl"><span class="lbl">Base domain</span><input id="zbPDom" data-f="pDomain" value="${E(F.pDomain)}" placeholder="hospital.org"></label></div>
      ${vert ? `<div class="df-hint">Creates: ${vert.apps.map(a => `${E(a.label)} (${E(a.host)}.${E(F.pDomain || 'domain')}, TCP ${E(a.tcp)})`).join('; ')}. These are templates: check them with the customer.</div>` : ''}
      <h3 class="op-h">A CSV of applications</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">CSV file</span><input type="file" id="zbCsvFile" accept=".csv,text/csv,text/plain"></label>
        <span class="df-hint">Columns name,domains,tcp_ports,udp_ports,description; domains separated by ; and ports like 443;8000-8100. Up to ${E(lim.csv_rows || 500)} rows.</span></div>
      <label class="op-block"><span class="lbl">Or paste the CSV${F.csvName ? ` (loaded from ${E(F.csvName)})` : ''}</span><textarea id="zbCsv" data-f="csv" rows="4" aria-label="CSV of applications">${E(F.csv)}</textarea></label>
      <h3 class="op-h">Browser Access (optional)</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Web server name</span><input id="zbBaDom" data-f="baDomain" value="${E(F.baDomain)}" placeholder="ehr.hospital.org"></label>
        <label class="df-ctl"><span class="lbl">Port</span><input id="zbBaPort" data-f="baPort" type="number" min="1" max="65535" value="${E(F.baPort)}"></label>
        <label class="df-ctl"><span class="lbl">Web server certificate</span><select id="zbBaCert" data-f="baCert">${opt(res.certificates, F.baCert, '<option value="">Pick a certificate…</option>')}</select></label></div>
      <h3 class="op-h">Privileged Remote Access (optional)</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">RDP server</span><input id="zbRdp" data-f="rdp" value="${E(F.rdp)}" placeholder="rdp01.corp.example.com"></label>
        <label class="df-ctl"><span class="lbl">SSH server</span><input id="zbSsh" data-f="ssh" value="${E(F.ssh)}" placeholder="10.0.0.12"></label>
        <label class="df-ctl"><span class="lbl">PRA portal</span><select id="zbPortal" data-f="portal">${opt(res.pra_portals, F.portal, '<option value="">No console (no portal)</option>')}</select></label></div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zbEnable" data-f="enable"${F.enable ? ' checked' : ''}><span>Create the applications enabled (off: they are created disabled and decide nothing until you enable them)</span></label></div>`;
    bind(where, id => { renderSegments(res, where, H); const el = document.getElementById(id); if (el) el.focus(); });
    const file = document.getElementById('zbCsvFile');
    file.addEventListener('change', () => {
      const f = file.files && file.files[0];
      if (!f) return;
      const max = lim.csv_bytes || 262144;
      if (f.size > max) { H.say(`The CSV is larger than ${Math.round(max / 1024)} KB.`); file.value = ''; return; }
      const rd = new FileReader();
      rd.onload = () => { F.csv = String(rd.result || ''); F.csvName = f.name; renderSegments(res, where, H); H.say(`Loaded ${f.name}.`); };
      rd.onerror = () => H.say('The file could not be read.');
      rd.readAsText(f);
    });
  }
  function specSegments() {
    const spec = { type: 'zpa_app_segments', prefix: needPrefix(), enable: !!F.enable };
    if (F.segCg) spec.connector_group_id = F.segCg;
    if (F.wDomain.trim()) spec.wildcard = { domain: F.wDomain.trim(), tcp: F.wTcp, udp: F.wUdp };
    if (F.vertical) { if (!F.pDomain.trim()) throw new Error('Enter the base domain for the preset.'); spec.preset = { vertical: F.vertical, domain: F.pDomain.trim() }; }
    if (F.csv.trim()) spec.csv = F.csv;
    if (F.baDomain.trim()) { if (!F.baCert) throw new Error('Pick the web server certificate for Browser Access.'); spec.browser_access = { domain: F.baDomain.trim(), port: F.baPort, certificate_id: F.baCert }; }
    if (F.rdp.trim() || F.ssh.trim()) spec.pra = { rdp_host: F.rdp.trim(), ssh_host: F.ssh.trim(), portal_id: F.portal };
    if (!spec.wildcard && !spec.preset && !spec.csv && !spec.browser_access && !spec.pra) throw new Error('Add at least one application: a wildcard, a preset, a CSV, Browser Access or a PRA server.');
    return spec;
  }

  // ── Policy rules ──
  function renderPolicies(res, where, H) {
    where.innerHTML = `${errs(res)}${prefixRow()}
      <div class="df-hint">The rules cover every application segment named with the prefix.</div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zbAccess" data-f="access"${F.access ? ' checked' : ''}><span>Access: allow the applications</span></label></div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zbTimeout" data-f="timeout"${F.timeout ? ' checked' : ''}><span>Timeout: re-authenticate every</span></label>
        <label class="df-ctl"><span class="sr-only">Re-authentication timeout</span><select id="zbRt" data-f="rt" aria-label="Re-authentication timeout">${opt(res.timeouts, F.rt)}</select></label>
        <label class="df-ctl"><span class="lbl">or after idle</span><select id="zbIt" data-f="it">${opt(res.idle_timeouts, F.it)}</select></label></div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zbInsp" data-f="inspection"${F.inspection ? ' checked' : ''}><span>Inspection: an inspection profile of Zscaler's predefined OWASP controls (needs AppProtection)</span></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Isolation profile</span><select id="zbIso" data-f="iso">${opt(res.isolation_profiles, F.iso, '<option value="">No isolation rule</option>')}</select></label>
        ${(res.isolation_profiles || []).length ? '' : '<span class="df-hint">No isolation profile was read: this tenant may not have Cloud Browser Isolation for ZPA.</span>'}</div>`;
    bind(where, () => renderPolicies(res, where, H));
  }
  function specPolicies() {
    const spec = { type: 'zpa_policies', prefix: needPrefix(), access: !!F.access, timeout: !!F.timeout, inspection: !!F.inspection,
      isolation_profile_id: F.iso, reauth_timeout: F.rt, reauth_idle_timeout: F.it };
    if (!spec.access && !spec.timeout && !spec.inspection && !spec.isolation_profile_id) throw new Error('Pick at least one policy.');
    return spec;
  }

  // ── Delete by prefix ──
  function renderDelete(res, where, H) {
    const p = String(F.prefix || '').trim();
    const rows = PREFIX.test(p) ? (res.inventory || []).filter(o => String(o.name).startsWith(p + '-')) : [];
    where.innerHTML = `${errs(res)}${prefixRow()}
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zbAll" data-f="everything"${F.everything ? ' checked' : ''}><span>Everything named ${E(p || 'prefix')}-…</span></label>
        <button type="button" class="rp-btn" id="zbShow">Show what the prefix matches</button></div>
      ${PREFIX.test(p) ? `<div class="df-hint">${rows.length} object${rows.length === 1 ? '' : 's'} named ${E(p)}-… in the last read${res.inventory_truncated ? ' (the list was cut at 5000 objects; the preview reads ZPA again)' : ''}. The preview reads ZPA again and deletes only objects that still carry the prefix, in dependency order; anything still used by an object you did not pick is kept and named.</div>
      <ul class="op-checks">${rows.map(o => { const k = `${o.kind}:${o.id}`; return `<li><label><input type="checkbox" data-k="${E(k)}"${F.pick.has(k) || F.everything ? ' checked' : ''}${F.everything ? ' disabled' : ''}> ${E(o.label)}: ${E(o.name)}</label></li>`; }).join('') || '<li class="df-hint">Nothing in ZPA is named with this prefix.</li>'}</ul>`
        : '<div class="df-hint">Enter the prefix, then pick what to delete.</div>'}`;
    bind(where, () => renderDelete(res, where, H));
    document.getElementById('zbAll').addEventListener('change', () => renderDelete(res, where, H));
    document.getElementById('zbShow').addEventListener('click', () => { F.pick.clear(); renderDelete(res, where, H); });
    where.querySelectorAll('input[data-k]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? F.pick.add(cb.dataset.k) : F.pick.delete(cb.dataset.k); }));
  }
  function specDelete() {
    const spec = { type: 'zpa_prefix_delete', prefix: needPrefix(), everything: !!F.everything, select: F.everything ? [] : [...F.pick] };
    if (!spec.everything && !spec.select.length) throw new Error('Pick the objects to delete, or tick everything named with the prefix.');
    return spec;
  }

  // ── The new provisioning key, fetched once after the apply ──
  async function showKeys(r, where, H) {
    const list = r.one_time_secrets || [];
    for (const s of list) {
      const box = document.createElement('div');
      box.className = 'bp-card warn';
      box.setAttribute('role', 'alert');
      where.prepend(box);
      try {
        const q = await fetch('/api/operations/zpa/provisioning-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', body: JSON.stringify({ token: s.token }) });
        const d = await q.json().catch(() => ({}));
        if (!q.ok) throw new Error(d.detail || `HTTP ${q.status}`);
        box.innerHTML = `<div class="t">Provisioning key ${E(d.name)}: copy it now</div>
          <div>It is shown this once. This app does not keep it; if you lose it, copy it from the ZPA Admin Portal.</div>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Key</span><input id="zbKey" readonly autocomplete="off" spellcheck="false" aria-label="Provisioning key"></label>
            <button type="button" class="rp-btn" id="zbCopy">Copy</button></div>`;
        const inp = box.querySelector('#zbKey'); inp.value = d.provisioning_key;
        box.querySelector('#zbCopy').addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(inp.value); H.say('Copied.'); } catch (e) { inp.select(); H.say('Select the key and copy it.'); }
        });
        H.say('The new provisioning key is shown once: copy it now.');
      } catch (e) {
        box.innerHTML = `<div class="t">The provisioning key could not be shown</div><div>${E(e.message)}</div>`;
      }
    }
  }

  const DEFS = { zpa_connector_group: [renderGroup, specGroup], zpa_app_segments: [renderSegments, specSegments], zpa_policies: [renderPolicies, specPolicies],
    zpa_prefix_delete: [renderDelete, specDelete] };
  Object.entries(DEFS).forEach(([type, [render, spec]]) => window.OPS_PLUGINS.register({
    type,
    render(res, where, S, H) { E = H.E || E; render(res, where, H); },
    spec() { return spec(); },
    result(r, where, H) { E = H.E || E; showKeys(r, where, H); },
  }));

  // /report/operations?build=zpa (the link on the ZPA page) opens the first ZPA builder.
  try {
    const want = new URLSearchParams(window.location.search).get('build');
    const type = want === 'zpa' ? 'zpa_connector_group' : (DEFS[want] ? want : '');
    const r = type && document.querySelector(`input[name="opKind"][value="${type}"]`);
    if (r && !r.checked) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); }
  } catch (e) { /* the page still works without it */ }
}());
