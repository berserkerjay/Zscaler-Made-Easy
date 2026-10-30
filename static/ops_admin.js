/* Day-to-day admin on Bulk changes (/report/operations): the forms of the
   ZPA (ops_zpa_admin.py), Client Connector (ops_zcc_admin.py) and ZDX
   (ops_zdx_trace.py) operation types. The page does the rest: Read from the
   tenant, Preview (plan hash), the four gates, Apply, read-back and Undo.
   Lookups (a user's devices, a list matched against the fleet, ZDX views)
   only read, through POST /api/operations/lookup. Every tenant string is
   escaped (H.E); nothing secret is kept here: a certificate's private key is
   sent once to the app and its field is cleared at once. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  let E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const DAYS = ['SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY'];
  const A = { pick: new Set(), on: '', name: '', moveTo: '', day: '', hour: '', ver: '', del: new Set(), filter: '',
    keyType: 'connector', keyGroup: '', keyName: '', keyMax: 1, keyOn: false,
    certMode: 'upload', certName: '', certDesc: '', upload: null, certId: '', ba: new Set(),
    user: '', devices: [], devPick: new Set(), mode: 'remove',
    listText: '', listDomain: '', match: null, resolved: {}, batch: 25,
    appAct: 'create', appId: '', appName: '', appOn: false, appEntries: '',
    svc: 'zpa', all: '', addGroups: '', rmGroups: new Set(),
    zUser: '', zDevices: [], zDev: '', zApps: [], zApp: '', zWeb: [], zPath: [], zWebId: '', zPathId: '', zName: '', zLen: 5, zHealth: false,
    zTraces: [], zTrace: '', zView: null, zUsers: [] };

  async function lookup(H, family, what, extra) {
    const r = await fetch('/api/operations/lookup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store',
      body: JSON.stringify(H.body(Object.assign({ family, what }, extra || {}))) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(H.detailText ? H.detailText(d, r.status) : (typeof d.detail === 'string' ? d.detail : `HTTP ${r.status}`));
    return d;
  }
  const errs = (H, res) => H.errorsHtml(res || {});
  const chip = (txt, cls) => `<span class="df-chip ${cls || ''}">${E(txt)}</span>`;
  const health = h => chip(h, h === 'connected' ? 'st-ok' : h === 'disconnected' ? 'st-fail' : 'st-warn');
  const table = (caption, head, rows, empty) => `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">${E(caption)}</caption>
    <thead><tr>${head.map(h => `<th scope="col">${E(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('') || `<tr><td colspan="${head.length}">${E(empty)}</td></tr>`}</tbody></table></div>`;
  const match = (x, f) => !f || JSON.stringify(x).toLowerCase().includes(f.toLowerCase());
  const assumed = res => (res.assumed || []).length ? `<details class="pa-details"><summary>What is assumed</summary><ul>${res.assumed.map(a => `<li class="df-hint">${E(a)}</li>`).join('')}</ul></details>` : '';

  // ── ZPA: change (health first) ──
  function zpaRows(res) {
    const out = [];
    (res.connectors || []).forEach(c => out.push({ k: `connector:${c.id}`, kind: 'connector', id: c.id, name: c.name, what: 'App Connector',
      detail: `${c.group_name || ''}`, health: c.health, ver: `${c.current_version || '?'}${c.update_pending ? ` → ${c.expected_version}` : ''}`, seen: c.last_connect || '' }));
    (res.connector_groups || []).forEach(g => out.push({ k: `connector_group:${g.id}`, kind: 'connector_group', id: g.id, name: g.name, what: 'App Connector group',
      detail: `${g.members_connected}/${g.members} connected · updates ${String(g.upgrade_day || '').toLowerCase()} ${g.upgrade_time_label || ''} · ${g.version_profile_label}`,
      health: g.enabled ? (g.members && !g.members_connected ? 'disconnected' : 'connected') : 'turned off', ver: '', seen: '' }));
    (res.service_edges || []).forEach(e => out.push({ k: `service_edge:${e.id}`, kind: 'service_edge', id: e.id, name: e.name, what: 'Private Service Edge',
      detail: '', health: e.health, ver: e.current_version || '', seen: '' }));
    (res.service_edge_groups || []).forEach(g => out.push({ k: `service_edge_group:${g.id}`, kind: 'service_edge_group', id: g.id, name: g.name, what: 'Service Edge group',
      detail: `${g.members_connected}/${g.members} connected · updates ${String(g.upgrade_day || '').toLowerCase()} ${g.upgrade_time_label || ''} · ${g.version_profile_label}`,
      health: g.enabled ? 'connected' : 'turned off', ver: '', seen: '' }));
    [['pra_portals', 'pra_portal', 'PRA portal'], ['pra_consoles', 'pra_console', 'PRA console'], ['user_portals', 'user_portal', 'User portal']].forEach(([key, kind, what]) =>
      (res[key] || []).forEach(p => out.push({ k: `${kind}:${p.id}`, kind, id: p.id, name: p.name, what, detail: p.domain || p.application || '',
        health: p.enabled ? 'on' : 'turned off', ver: '', seen: '', inUse: p.in_use || '' })));
    return out;
  }
  function renderUpdate(res, where, S, H) {
    const rows = zpaRows(res).filter(r => match(r, A.filter));
    const groups = res.connector_groups || [];
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick the objects, then say what to change. Each one is read again right before its change, and Undo puts it back.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Filter</span><input id="admFilter" value="${E(A.filter)}" aria-label="Filter the objects" placeholder="name, group or health"></label></div>
      ${table('ZPA objects and their health', ['Pick', 'Name', 'Kind', 'Health', 'Version', 'Details'], rows.map(r => `<tr>
        <td><input type="checkbox" data-admpick="${E(r.k)}" aria-label="Pick ${E(r.name)}"${A.pick.has(r.k) ? ' checked' : ''}></td><td>${E(r.name)}</td><td>${E(r.what)}</td>
        <td>${health(r.health)}</td><td>${E(r.ver)}</td><td class="df-hint">${E(r.detail)}${r.seen ? ` · last connected ${E(r.seen)}` : ''}</td></tr>`), 'Nothing to show.')}
      <h3 class="op-h">What to change</h3>
      <div class="op-row"><fieldset class="op-inline"><legend>On or off</legend>${[['', 'Leave as it is'], ['on', 'Turn on'], ['off', 'Turn off']].map(([v, l]) =>
        `<label><input type="radio" name="admOn" value="${v}"${A.on === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">New name (one object only)</span><input id="admName" maxlength="128" value="${E(A.name)}" aria-label="New name"></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Move picked App Connectors to</span><select id="admMoveTo" aria-label="Move picked App Connectors to">
        <option value="">Do not move</option>${groups.map(g => `<option value="${E(g.id)}"${A.moveTo === g.id ? ' selected' : ''}>${E(g.name)}</option>`).join('')}</select></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Update day (groups)</span><select id="admDay" aria-label="Software update day">
        <option value="">Leave as it is</option>${DAYS.map(d => `<option value="${d}"${A.day === d ? ' selected' : ''}>${d[0] + d.slice(1).toLowerCase()}</option>`).join('')}</select></label>
        <label class="df-ctl"><span class="lbl">Update hour</span><select id="admHour" aria-label="Software update hour"><option value="">Leave as it is</option>
        ${Array.from({ length: 24 }, (_, h) => `<option value="${h}"${A.hour === String(h) ? ' selected' : ''}>${String(h).padStart(2, '0')}:00</option>`).join('')}</select></label>
        <label class="df-ctl"><span class="lbl">Version profile</span><select id="admVer" aria-label="Version profile"><option value="">Leave as it is</option>
        ${(res.version_profiles || []).map(v => `<option value="${E(v.id)}"${A.ver === v.id ? ' selected' : ''}>${E(v.label)}</option>`).join('')}</select></label></div>
      ${assumed(res)}`;
    const f = where.querySelector('#admFilter');
    f.addEventListener('input', () => { A.filter = f.value; renderUpdate(res, where, S, H); const g = where.querySelector('#admFilter'); g.focus(); g.setSelectionRange(g.value.length, g.value.length); });
    where.querySelectorAll('input[data-admpick]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? A.pick.add(cb.dataset.admpick) : A.pick.delete(cb.dataset.admpick); }));
    where.querySelectorAll('input[name="admOn"]').forEach(r => r.addEventListener('change', () => { A.on = r.value; }));
    [['admName', 'name'], ['admMoveTo', 'moveTo'], ['admDay', 'day'], ['admHour', 'hour'], ['admVer', 'ver']].forEach(([id, k]) => {
      const el = where.querySelector('#' + id); el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', () => { A[k] = el.value; });
    });
    S.admRows = zpaRows(res);
  }
  function specUpdate(S) {
    const picked = (S.admRows || []).filter(r => A.pick.has(r.k));
    if (!picked.length) throw new Error('Pick at least one object.');
    if (A.name.trim() && picked.length !== 1) throw new Error('A new name is for one object: pick only that one.');
    const targets = picked.map(r => {
      const set = {};
      if (A.on) set.enabled = A.on === 'on';
      if (A.name.trim()) set.name = A.name.trim();
      if (A.moveTo && r.kind === 'connector') set.group_id = A.moveTo;
      if (/_group$/.test(r.kind)) {
        if (A.day) set.upgrade_day = A.day;
        if (A.hour !== '') set.upgrade_hour = Number(A.hour);
        if (A.ver) set.version_profile = A.ver;
      }
      return { kind: r.kind, id: r.id, set };
    }).filter(t => Object.keys(t.set).length);
    if (!targets.length) throw new Error('Say what to change on the picked objects.');
    return { type: 'zpa_infra_update', targets };
  }

  // ── ZPA: delete ──
  function delRows(res) {
    const rows = zpaRows(res).map(r => ({ k: r.k, kind: r.kind, id: r.id, name: r.name, what: r.what,
      note: r.inUse || (r.health === 'connected' && /^(connector|service_edge)$/.test(r.kind) ? 'Connected: turn it off first' : '') }));
    (res.certificates || []).forEach(c => rows.push({ k: `certificate:${c.id}`, kind: 'certificate', id: c.id, name: c.name, what: 'Browser Access certificate',
      note: (c.used_by || []).length ? `Used by ${c.used_by[0]}` : c.expiry }));
    (res.provisioning_keys || []).forEach(k => rows.push({ k: `provisioning_key:${k.id}`, kind: 'provisioning_key', id: k.id, name: k.name, keyType: k.key_type,
      what: k.key_type === 'connector' ? 'App Connector provisioning key' : 'Service Edge provisioning key', note: `used ${k.usage} of ${k.max_usage || '?'}` }));
    return rows;
  }
  function renderDelete(res, where, S, H) {
    const rows = delRows(res);
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick what to delete. Anything connected or still used is kept and named in the preview. You type the confirmation every time; there is no Undo.</p>
      ${table('ZPA objects that can be deleted', ['Pick', 'Name', 'Kind', 'Note'], rows.map(r => `<tr><td><input type="checkbox" data-admdel="${E(r.k)}" aria-label="Delete ${E(r.name)}"${A.del.has(r.k) ? ' checked' : ''}></td>
        <td>${E(r.name)}</td><td>${E(r.what)}</td><td class="df-hint">${E(r.note)}</td></tr>`), 'Nothing to delete.')}`;
    where.querySelectorAll('input[data-admdel]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? A.del.add(cb.dataset.admdel) : A.del.delete(cb.dataset.admdel); }));
    S.admDelRows = rows;
  }
  function specDelete(S) {
    const t = (S.admDelRows || []).filter(r => A.del.has(r.k)).map(r => Object.assign({ kind: r.kind, id: r.id, name: r.name }, r.keyType ? { key_type: r.keyType } : {}));
    if (!t.length) throw new Error('Pick what to delete.');
    return { type: 'zpa_infra_delete', targets: t };
  }

  // ── ZPA: new provisioning key ──
  function renderKey(res, where, S, H) {
    const groups = A.keyType === 'connector' ? (res.connector_groups || []) : (res.service_edge_groups || []);
    where.innerHTML = `${errs(H, res)}
      <div class="op-row"><fieldset class="op-inline"><legend>For</legend>${[['connector', 'An App Connector group'], ['service_edge', 'A Service Edge group']].map(([v, l]) =>
        `<label><input type="radio" name="admKeyType" value="${v}"${A.keyType === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Group</span><select id="admKeyGroup" aria-label="Group the key enrolls into"><option value="">Pick one…</option>
        ${groups.map(g => `<option value="${E(g.id)}"${A.keyGroup === g.id ? ' selected' : ''}>${E(g.name)}</option>`).join('')}</select></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Key name</span><input id="admKeyName" maxlength="128" value="${E(A.keyName)}" aria-label="Key name"></label>
        <label class="df-ctl"><span class="lbl">How many may enroll</span><input id="admKeyMax" type="number" min="1" max="500" value="${E(A.keyMax)}" aria-label="How many may enroll with the key"></label></div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="admKeyOn"${A.keyOn ? ' checked' : ''}><span>Turn the key on now (off by default: nothing can enroll with it until it is on)</span></label></div>
      <div class="df-hint">The key is shown once, right after it is created. It is never kept, logged or exported.</div>`;
    where.querySelectorAll('input[name="admKeyType"]').forEach(r => r.addEventListener('change', () => { A.keyType = r.value; A.keyGroup = ''; renderKey(res, where, S, H); where.querySelector('input[name="admKeyType"]:checked').focus(); }));
    where.querySelector('#admKeyGroup').addEventListener('change', e => { A.keyGroup = e.target.value; });
    where.querySelector('#admKeyName').addEventListener('input', e => { A.keyName = e.target.value; });
    where.querySelector('#admKeyMax').addEventListener('input', e => { A.keyMax = e.target.value; });
    where.querySelector('#admKeyOn').addEventListener('change', e => { A.keyOn = e.target.checked; });
  }
  function specKey() {
    if (!A.keyGroup) throw new Error('Pick the group the key enrolls into.');
    if (!A.keyName.trim()) throw new Error('Give the key a name.');
    return { type: 'zpa_provisioning_key_new', key_type: A.keyType, group_id: A.keyGroup, name: A.keyName.trim(), max_usage: parseInt(A.keyMax, 10) || 0, enabled: !!A.keyOn };
  }
  async function showKeys(r, where, H) {
    for (const s of r.one_time_secrets || []) {
      const box = document.createElement('div');
      box.className = 'bp-card warn'; box.setAttribute('role', 'alert'); where.prepend(box);
      try {
        const q = await fetch('/api/operations/zpa/provisioning-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', body: JSON.stringify({ token: s.token }) });
        const d = await q.json().catch(() => ({}));
        if (!q.ok) throw new Error(typeof d.detail === 'string' ? d.detail : `HTTP ${q.status}`);
        box.innerHTML = `<div class="t">Provisioning key ${E(d.name)}: copy it now</div><div>It is shown this once. This app does not keep it.</div>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Key</span><input id="admKeyValue" readonly autocomplete="off" spellcheck="false" aria-label="Provisioning key"></label>
          <button type="button" class="rp-btn" id="admKeyCopy">Copy</button></div>`;
        const inp = box.querySelector('#admKeyValue'); inp.value = d.provisioning_key;
        box.querySelector('#admKeyCopy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(inp.value); H.say('Copied.'); } catch (e) { inp.select(); H.say('Select the key and copy it.'); } });
      } catch (e) { box.innerHTML = `<div class="t">The provisioning key could not be shown</div><div>${E(e.message)}</div>`; }
    }
  }

  // ── ZPA: Browser Access certificate ──
  function renderCert(res, where, S, H) {
    const certs = res.certificates || [], apps = res.ba_apps || [];
    const up = A.upload;
    where.innerHTML = `${errs(H, res)}
      ${table('Browser Access certificates', ['Certificate', 'Names', 'Expiry', 'Used by'], certs.map(c => `<tr><td>${E(c.name)}</td><td class="df-hint">${E((c.san || []).slice(0, 3).join(', ') || c.cname)}</td>
        <td>${chip(c.expiry, c.expiry === 'expired' ? 'st-fail' : c.expiring ? 'st-warn' : 'st-ok')} ${E(c.valid_to)}</td><td class="df-hint">${E((c.used_by || []).join('; '))}</td></tr>`), 'No Browser Access certificate.')}
      <div class="op-row"><fieldset class="op-inline"><legend>Certificate</legend>${[['upload', 'Upload a new one'], ['existing', 'Use one ZPA has']].map(([v, l]) =>
        `<label><input type="radio" name="admCertMode" value="${v}"${A.certMode === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      ${A.certMode === 'upload' ? `
        <div class="op-row"><label class="df-ctl"><span class="lbl">Name in ZPA</span><input id="admCertName" maxlength="128" value="${E(A.certName)}" aria-label="Certificate name in ZPA"></label>
          <label class="df-ctl"><span class="lbl">Description</span><input id="admCertDesc" maxlength="255" value="${E(A.certDesc)}" aria-label="Certificate description"></label></div>
        <div class="op-row"><label class="op-block"><span class="lbl">Certificate (PEM, the server certificate first, then its chain)</span><textarea id="admCertPem" rows="4" spellcheck="false" aria-label="Certificate PEM"></textarea></label>
          <label class="df-ctl"><span class="lbl">or a file</span><input type="file" id="admCertFile" accept=".pem,.crt,.cer" aria-label="Certificate file"></label></div>
        <div class="op-row"><label class="op-block"><span class="lbl">Private key (PEM, unencrypted). Sent to this app once, never kept or shown</span><textarea id="admKeyPem" rows="3" spellcheck="false" autocomplete="off" aria-label="Private key PEM"></textarea></label>
          <label class="df-ctl"><span class="lbl">or a file</span><input type="file" id="admKeyFile" accept=".pem,.key" aria-label="Private key file"></label></div>
        <div class="op-row"><button type="button" class="rp-btn" id="admCertUpload">Check and hold the certificate</button>
          <span class="df-hint" id="admCertState" aria-live="polite">${up ? `Held for ten minutes: ${E(up.facts.subject)}, valid to ${E(up.facts.valid_to)}, SHA-256 ${E(String(up.facts.fingerprint_sha256).slice(0, 16))}…` : 'Not uploaded yet.'}</span></div>`
      : `<div class="op-row"><label class="df-ctl"><span class="lbl">Certificate</span><select id="admCertPick" aria-label="Certificate ZPA has"><option value="">Pick one…</option>
          ${certs.map(c => `<option value="${E(c.id)}"${A.certId === c.id ? ' selected' : ''}>${E(c.name)} (${E(c.expiry)})</option>`).join('')}</select></label></div>`}
      <h3 class="op-h">Browser Access applications to point at it</h3>
      ${table('Browser Access applications', ['Pick', 'Application', 'Segment', 'Certificate now'], apps.map(a => `<tr><td><input type="checkbox" data-admba="${E(a.segment_id)}|${E(a.app_id)}" aria-label="Point ${E(a.domain)} at the certificate"${A.ba.has(`${a.segment_id}|${a.app_id}`) ? ' checked' : ''}></td>
        <td>${E(a.domain)}:${E(a.port)}</td><td>${E(a.segment_name)}</td><td>${E(a.certificate_name || a.certificate_id)}</td></tr>`), 'No Browser Access application.')}`;
    where.querySelectorAll('input[name="admCertMode"]').forEach(r => r.addEventListener('change', () => { A.certMode = r.value; renderCert(res, where, S, H); where.querySelector('input[name="admCertMode"]:checked').focus(); }));
    where.querySelectorAll('input[data-admba]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? A.ba.add(cb.dataset.admba) : A.ba.delete(cb.dataset.admba); }));
    const pick = where.querySelector('#admCertPick'); if (pick) pick.addEventListener('change', e => { A.certId = e.target.value; });
    const nm = where.querySelector('#admCertName'); if (nm) nm.addEventListener('input', e => { A.certName = e.target.value; });
    const ds = where.querySelector('#admCertDesc'); if (ds) ds.addEventListener('input', e => { A.certDesc = e.target.value; });
    const file = (inp, area) => { if (!inp) return; inp.addEventListener('change', () => { const f = inp.files && inp.files[0]; if (!f) return;
      if (f.size > 65536) { H.say('That file is too large for a certificate or key.'); inp.value = ''; return; }
      const rd = new FileReader(); rd.onload = () => { where.querySelector(area).value = String(rd.result || ''); inp.value = ''; }; rd.readAsText(f); }); };
    file(where.querySelector('#admCertFile'), '#admCertPem'); file(where.querySelector('#admKeyFile'), '#admKeyPem');
    const btn = where.querySelector('#admCertUpload');
    if (btn) btn.addEventListener('click', async () => {
      const certEl = where.querySelector('#admCertPem'), keyEl = where.querySelector('#admKeyPem'), state = where.querySelector('#admCertState');
      const cert = certEl.value, key = keyEl.value;
      keyEl.value = '';   // the key leaves the page once, now
      try {
        const r = await fetch('/api/operations/zpa/ba-certificate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', body: JSON.stringify({ cert_pem: cert, key_pem: key }) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : `HTTP ${r.status}`);
        A.upload = d; state.textContent = `Held for ten minutes: ${d.facts.subject}, valid to ${d.facts.valid_to}. Now pick the applications and preview.`;
        H.say('The certificate is checked and held. Pick the applications, then preview.');
      } catch (e) { A.upload = null; state.textContent = `Not uploaded: ${e.message}`; H.say(`Not uploaded: ${e.message}`); }
    });
  }
  function specCert() {
    const assign = [...A.ba].map(k => { const [segment_id, app_id] = k.split('|'); return { segment_id, app_id }; });
    if (A.certMode === 'upload') {
      if (!A.upload) throw new Error('Check and hold the certificate first (the upload button).');
      if (!A.certName.trim()) throw new Error('Give the certificate a name in ZPA.');
      return { type: 'zpa_ba_certificate', upload_token: A.upload.token, name: A.certName.trim(), description: A.certDesc.trim(), assign };
    }
    if (!A.certId) throw new Error('Pick the certificate.');
    if (!assign.length) throw new Error('Pick the Browser Access applications to point at it.');
    return { type: 'zpa_ba_certificate', certificate_id: A.certId, assign };
  }

  // ── Client Connector: remove a user's devices ──
  function renderRemove(res, where, S, H) {
    where.innerHTML = `${errs(H, res)}
      <div class="op-row"><label class="df-ctl"><span class="lbl">User (email)</span><input id="admUser" value="${E(A.user)}" aria-label="User's email" placeholder="jdoe@acme.com"></label>
        <button type="button" class="rp-btn" id="admFind">Find devices</button></div>
      <div class="op-row"><fieldset class="op-inline"><legend>Removal</legend>${[['remove', 'Remove (marked Removal Pending; unenrolls at its next check-in)'], ['force', 'Force remove (dropped at once)']].map(([v, l]) =>
        `<label><input type="radio" name="admMode" value="${v}"${A.mode === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      <div id="admDevs">${devTable()}</div>`;
    where.querySelector('#admUser').addEventListener('input', e => { A.user = e.target.value; });
    where.querySelectorAll('input[name="admMode"]').forEach(r => r.addEventListener('change', () => { A.mode = r.value; }));
    const bindPicks = () => where.querySelectorAll('input[data-admdev]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? A.devPick.add(cb.dataset.admdev) : A.devPick.delete(cb.dataset.admdev); }));
    bindPicks();
    where.querySelector('#admFind').addEventListener('click', async () => {
      try { const d = await lookup(H, 'zcc_admin', 'devices', { user: A.user.trim() }); A.devices = d.devices || []; A.devPick.clear();
        where.querySelector('#admDevs').innerHTML = (d.error ? `<div class="bp-card warn">${E(d.error)}</div>` : '') + devTable(); bindPicks(); H.say(`${A.devices.length} device(s).`);
      } catch (e) { where.querySelector('#admDevs').innerHTML = `<div class="bp-card risk" role="alert">${E(e.message)}</div>`; }
    });
  }
  function devTable() {
    return table("The user's devices", ['Pick', 'Host name', 'Platform', 'Version', 'State', 'Last seen'], A.devices.map(d => `<tr><td><input type="checkbox" data-admdev="${E(d.udid)}" aria-label="Remove ${E(d.hostname || d.udid)}"${A.devPick.has(d.udid) ? ' checked' : ''}></td>
      <td>${E(d.hostname)}<div class="df-by">${E(d.udid)}</div></td><td>${E(d.os)}</td><td>${E(d.version)}</td><td>${E(d.state)}</td><td>${E(d.last_seen)}</td></tr>`), 'Find a user to list their devices.');
  }
  function specRemove() {
    const devices = A.devices.filter(d => A.devPick.has(d.udid)).map(d => ({ udid: d.udid, user: d.user || A.user.trim() }));
    if (!devices.length) throw new Error('Find the user and pick their devices.');
    return { type: 'zcc_device_remove', mode: A.mode, devices };
  }

  // ── Client Connector: remove devices from a list (batched) ──
  function renderBulk(res, where, S, H) {
    const m = A.match;
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">One entry a line: a user's email, a host name, a device id, "email,hostname", or @domain for every device of that domain. Ambiguous entries (a host name enrolled more than once) and unmatched ones are listed for you to settle before the preview.</p>
      <div class="op-row"><label class="op-block"><span class="lbl">List</span><textarea id="admList" rows="5" spellcheck="false" aria-label="List of users, host names, device ids or domains">${E(A.listText)}</textarea></label>
        <label class="df-ctl"><span class="lbl">or a .txt or .csv file</span><input type="file" id="admListFile" accept=".txt,.csv" aria-label="List file"></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Only users of this domain (optional)</span><input id="admListDomain" value="${E(A.listDomain)}" aria-label="Only users of this domain" placeholder="acme.com"></label>
        <label class="df-ctl"><span class="lbl">Batch size</span><input id="admBatch" type="number" min="1" max="100" value="${E(A.batch)}" aria-label="Devices per call"></label></div>
      <div class="op-row"><fieldset class="op-inline"><legend>Removal</legend>${[['remove', 'Remove'], ['force', 'Force remove']].map(([v, l]) =>
        `<label><input type="radio" name="admBulkMode" value="${v}"${A.mode === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset>
        <button type="button" class="rp-btn" id="admMatch">Match the list</button></div>
      <div id="admMatchOut">${m ? matchHtml(m) : ''}</div>`;
    where.querySelector('#admList').addEventListener('input', e => { A.listText = e.target.value; });
    where.querySelector('#admListDomain').addEventListener('input', e => { A.listDomain = e.target.value; });
    where.querySelector('#admBatch').addEventListener('input', e => { A.batch = e.target.value; });
    where.querySelectorAll('input[name="admBulkMode"]').forEach(r => r.addEventListener('change', () => { A.mode = r.value; }));
    const lf = where.querySelector('#admListFile');
    lf.addEventListener('change', () => { const f = lf.files && lf.files[0]; if (!f) return; if (f.size > 1048576) { H.say('The list file is larger than 1 MB.'); lf.value = ''; return; }
      const rd = new FileReader(); rd.onload = () => { A.listText = String(rd.result || ''); where.querySelector('#admList').value = A.listText; lf.value = ''; H.say(`Loaded ${f.name}.`); }; rd.readAsText(f); });
    const bindAmb = () => where.querySelectorAll('select[data-admamb]').forEach(sel => sel.addEventListener('change', () => { A.resolved[sel.dataset.admamb] = sel.value; }));
    bindAmb();
    where.querySelector('#admMatch').addEventListener('click', async () => {
      const out = where.querySelector('#admMatchOut');
      try { const d = await lookup(H, 'zcc_admin', 'match', { user: '', text: A.listText, mode: A.mode, domain: A.listDomain.trim() });
        if (d.error) throw new Error(d.error);
        A.match = d; A.resolved = {}; out.innerHTML = matchHtml(d); bindAmb(); H.say(`${d.counts.planned} device(s) matched, ${d.counts.ambiguous} ambiguous, ${d.counts.not_found} not found.`);
      } catch (e) { out.innerHTML = `<div class="bp-card risk" role="alert">${E(e.message)}</div>`; }
    });
  }
  function matchHtml(m) {
    const c = m.counts || {}, b = m.budget || {};
    const list = (title, rows, f) => rows && rows.length ? `<details class="pa-details"><summary>${E(title)} (${rows.length})</summary><ul>${rows.slice(0, 200).map(r => `<li>${f(r)}</li>`).join('')}</ul></details>` : '';
    return `<div class="op-summary">${chip(`${c.planned || 0} to remove`, 'st-block')}${chip(`${c.ambiguous || 0} ambiguous`, c.ambiguous ? 'st-warn' : '')}${chip(`${c.not_found || 0} not found`)}${chip(`${c.already_removed || 0} already removed`)}${chip(`${c.filtered || 0} outside the domain`)}${chip(`${c.invalid || 0} not understood`)}</div>
      <div class="df-hint">Client Connector API calls left this hour: ${E(b.remaining)} of ${E(b.limit)}. Per user domain: ${E(Object.entries(m.per_domain || {}).map(([k, v]) => `${k} ${v}`).join(', ') || 'none')}.</div>
      ${(m.ambiguous || []).length ? `<h3 class="op-h">Settle the ambiguous entries</h3>${(m.ambiguous || []).map((a, i) => `<div class="op-row"><label class="df-ctl"><span class="lbl">${E(a.entry)}</span>
        <select data-admamb="${i}" aria-label="Which device is ${E(a.entry)}"><option value="">Leave it out</option>${a.candidates.map(d => `<option value="${E(d.udid)}|${E(d.user)}">${E(d.user)} · ${E(d.state)} · last seen ${E(d.last_seen || '?')}</option>`).join('')}</select></label></div>`).join('')}` : ''}
      ${list('To remove', m.planned, d => `${E(d.hostname || d.udid)} · ${E(d.user)} · ${E(d.state)} <span class="df-by">${E(d.entry)}</span>`)}
      ${list('Not found', m.not_found, d => E(d.entry))}${list('Already removed', m.already_removed, d => `${E(d.entry)}: ${E(d.state)}`)}
      ${list('Outside the domain', m.filtered, d => `${E(d.entry)}: ${E(d.user)}`)}${list('Not understood', m.invalid, d => E(d.entry))}`;
  }
  function specBulk() {
    const m = A.match;
    if (!m) throw new Error('Match the list first.');
    const devices = (m.planned || []).map(d => ({ udid: d.udid, user: d.user, entry: d.entry }));
    Object.entries(A.resolved).forEach(([i, v]) => { if (!v) return; const [udid, user] = v.split('|'); if (!devices.some(d => d.udid === udid)) devices.push({ udid, user, entry: (m.ambiguous[i] || {}).entry || '' }); });
    if (!devices.length) throw new Error('Nothing to remove: no entry matched a removable device.');
    return { type: 'zcc_device_bulk_remove', mode: A.mode, batch_size: parseInt(A.batch, 10) || 25, devices };
  }
  function csvLinks(r, where, what, jobId) {
    const job = jobId || (r && r.job_id) || '';
    if (!job || !/^[A-Za-z0-9_-]{6,80}$/.test(job)) return;
    const box = document.createElement('div');
    box.className = 'op-row';
    box.innerHTML = `<a class="rp-btn" data-admcsv="full" href="/api/operations/jobs/${encodeURIComponent(job)}/devices.csv" download>Download the ${what} as CSV (user and host names: personal data)</a>
      <a class="rp-btn" data-admcsv="counts" href="/api/operations/jobs/${encodeURIComponent(job)}/devices.csv?counts_only=true" download>Counts only</a>`;
    where.append(box);
  }

  // ── Client Connector: custom bypass apps ──
  function renderBypass(res, where, S, H) {
    const apps = res.bypass_apps || [];
    const cur = apps.find(a => a.id === A.appId);
    where.innerHTML = `${errs(H, res)}
      ${table('Custom bypass apps', ['Pick', 'App', 'On', 'Entries'], apps.map(a => `<tr><td><input type="radio" name="admApp" value="${E(a.id)}" aria-label="Pick ${E(a.name)}"${A.appId === a.id ? ' checked' : ''}></td>
        <td>${E(a.name)}</td><td>${a.active ? 'on' : 'off'}</td><td class="df-hint">${E(a.entries.map(e => `${e.proto} ${e.port} ${e.ipaddr || e.fqdn}`).join('; '))}</td></tr>`), 'No custom bypass app yet.')}
      <div class="op-row"><fieldset class="op-inline"><legend>Do</legend>${[['create', 'Create a new one'], ['update', 'Edit the picked one'], ['delete', 'Delete the picked one']].map(([v, l]) =>
        `<label><input type="radio" name="admAppAct" value="${v}"${A.appAct === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      ${A.appAct === 'delete' ? '<div class="df-hint">You type its name to confirm. An app an app profile bypasses is never deleted. No Undo.</div>' : `
      <div class="op-row"><label class="df-ctl"><span class="lbl">Name</span><input id="admAppName" maxlength="64" value="${E(A.appName || (A.appAct === 'update' && cur ? cur.name : ''))}" aria-label="App name"></label>
        <label class="df-ctl"><input type="checkbox" id="admAppOn"${A.appOn ? ' checked' : ''}><span>On (new apps start off)</span></label></div>
      <div class="op-row"><label class="op-block"><span class="lbl">Entries, one a line: protocol port address (TCP 443 10.0.0.0/8, UDP 3478-3481 52.112.0.0/14, TCP 443 zoom.us)</span>
        <textarea id="admAppEntries" rows="4" spellcheck="false" aria-label="Bypass entries">${E(A.appEntries || (A.appAct === 'update' && cur ? cur.entries.map(e => `${e.proto} ${e.port} ${e.ipaddr || e.fqdn}`).join('\n') : ''))}</textarea></label></div>
      <div class="df-hint">Traffic to these addresses skips the Zscaler tunnel (nothing inspects it) once an app profile bypasses the app.</div>`}`;
    where.querySelectorAll('input[name="admApp"]').forEach(r => r.addEventListener('change', () => { A.appId = r.value; const a = apps.find(x => x.id === r.value); A.appName = a ? a.name : ''; A.appOn = !!(a && a.active);
      A.appEntries = a ? a.entries.map(e => `${e.proto} ${e.port} ${e.ipaddr || e.fqdn}`).join('\n') : ''; renderBypass(res, where, S, H); where.querySelector('input[name="admApp"]:checked').focus(); }));
    where.querySelectorAll('input[name="admAppAct"]').forEach(r => r.addEventListener('change', () => { A.appAct = r.value; renderBypass(res, where, S, H); where.querySelector('input[name="admAppAct"]:checked').focus(); }));
    const n = where.querySelector('#admAppName'); if (n) n.addEventListener('input', e => { A.appName = e.target.value; });
    const o = where.querySelector('#admAppOn'); if (o) o.addEventListener('change', e => { A.appOn = e.target.checked; });
    const t = where.querySelector('#admAppEntries'); if (t) t.addEventListener('input', e => { A.appEntries = e.target.value; });
    S.admApps = apps;
  }
  function entries() {
    return String(A.appEntries || '').split('\n').map(l => l.trim()).filter(Boolean).map(l => { const [proto, port, address] = l.split(/[\s,]+/); return { proto: proto || '', port: port || '', address: address || '' }; });
  }
  function specBypass(S) {
    if (A.appAct === 'create') return { type: 'zcc_bypass_app', action: 'create', name: A.appName.trim(), active: !!A.appOn, entries: entries() };
    const a = (S.admApps || []).find(x => x.id === A.appId);
    if (!a) throw new Error('Pick the app.');
    if (A.appAct === 'delete') return { type: 'zcc_bypass_app', action: 'delete', id: a.id, name: a.name };
    return { type: 'zcc_bypass_app', action: 'update', id: a.id, name: A.appName.trim() || a.name, active: !!A.appOn, entries: entries() };
  }

  // ── Client Connector: entitlements ──
  function renderEnt(res, where, S, H) {
    const ents = res.entitlements || {}, cur = ents[A.svc];
    const card = e => e ? `<div class="bp-card info"><div class="t">${E(e.label)}</div><div>On for every user: ${e.enable_for_all ? 'yes' : 'no'}. Groups: ${E(e.groups.join(', ') || 'none')}.${e.device_groups.length ? ` Device groups: ${E(e.device_groups.join(', '))}.` : ''}</div></div>` : '';
    where.innerHTML = `${errs(H, res)}${card(ents.zpa)}${card(ents.zdx)}
      <div class="op-row"><fieldset class="op-inline"><legend>Service</legend>${[['zpa', 'ZPA'], ['zdx', 'ZDX']].map(([v, l]) => `<label><input type="radio" name="admSvc" value="${v}"${A.svc === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      <div class="op-row"><fieldset class="op-inline"><legend>On for every user</legend>${[['', 'Leave as it is'], ['on', 'On'], ['off', 'Off (only the groups listed)']].map(([v, l]) =>
        `<label><input type="radio" name="admAll" value="${v}"${A.all === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      <div class="op-row"><label class="op-block"><span class="lbl">Groups to add, one a line</span><textarea id="admAddGroups" rows="3" aria-label="Groups to add">${E(A.addGroups)}</textarea></label></div>
      ${cur && cur.groups.length ? `<h3 class="op-h">Take groups out</h3><ul class="op-checks">${cur.groups.map(g => `<li><label><input type="checkbox" data-admgrp="${E(g)}"${A.rmGroups.has(g) ? ' checked' : ''}> ${E(g)}</label></li>`).join('')}</ul>` : ''}`;
    where.querySelectorAll('input[name="admSvc"]').forEach(r => r.addEventListener('change', () => { A.svc = r.value; A.rmGroups.clear(); renderEnt(res, where, S, H); where.querySelector('input[name="admSvc"]:checked').focus(); }));
    where.querySelectorAll('input[name="admAll"]').forEach(r => r.addEventListener('change', () => { A.all = r.value; }));
    where.querySelector('#admAddGroups').addEventListener('input', e => { A.addGroups = e.target.value; });
    where.querySelectorAll('input[data-admgrp]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? A.rmGroups.add(cb.dataset.admgrp) : A.rmGroups.delete(cb.dataset.admgrp); }));
  }
  function specEnt() {
    const s = { type: 'zcc_entitlements', service: A.svc, add_groups: A.addGroups.split('\n').map(x => x.trim()).filter(Boolean), remove_groups: [...A.rmGroups] };
    if (A.all) s.enable_for_all = A.all === 'on';
    return s;
  }

  // ── ZDX: look-up views and the deep trace ──
  function zdxDevicesHtml() {
    return A.zDevices.length ? `<div class="op-row"><label class="df-ctl"><span class="lbl">Device</span><select id="admZDev" aria-label="The user's device"><option value="">Pick one…</option>
      ${A.zDevices.map(d => `<option value="${E(d.id)}"${A.zDev === d.id ? ' selected' : ''}>${E(d.name || d.id)}</option>`).join('')}</select></label></div>` : '';
  }
  function zdxView(v) {
    if (!v) return '';
    const pre = x => `<pre class="pa-log">${E(JSON.stringify(x, null, 1).slice(0, 6000))}</pre>`;
    if (v.kind === 'health') return `<h3 class="op-h">Device details and health</h3>${pre(v.data.device)}${pre(v.data.health_metrics)}`;
    if (v.kind === 'perf') return `<h3 class="op-h">Application performance on this device</h3>${pre(v.data.performance)}`;
    if (v.kind === 'score') return `<h3 class="op-h">Score trend (24 hours)</h3>${pre(v.data.score)}`;
    if (v.kind === 'follow') { const r = v.data || {}; return `<h3 class="op-h">Deep trace: ${E(r.status)} after ${E(r.polls)} read(s)${r.timed_out ? ' (still running: follow it again later)' : ''}</h3>${r.results ? pre(r.results) : ''}`; }
    return '';
  }
  function renderTrace(res, where, S, H, stopForm) {
    const apps = res.apps || [];
    where.innerHTML = `${errs(H, res)}
      ${stopForm ? '' : table('ZDX application scores (last 2 hours)', ['Application', 'Score', 'Users', 'Most affected', 'Trend'], apps.map(a => `<tr><td>${E(a.name)}</td><td>${E(a.score == null ? '' : a.score)}</td><td>${E(a.users == null ? '' : a.users)}</td><td>${E(a.most_impacted_region)}</td>
        <td><button type="button" class="rp-btn" data-admscore="${E(a.id)}" aria-label="Score trend of ${E(a.name)}">Trend</button></td></tr>`), 'No application measured.')}
      <div class="op-row"><label class="df-ctl"><span class="lbl">User (name or email)</span><input id="admZUser" value="${E(A.zUser)}" aria-label="User name or email" placeholder="jdoe@acme.com"></label>
        <button type="button" class="rp-btn" id="admZFind">Find the user's devices</button></div>
      <div id="admZDevs">${zdxDevicesHtml()}</div>
      <div id="admZMore"></div><div id="admZView" aria-live="polite">${zdxView(A.zView)}</div>`;
    const view = () => { where.querySelector('#admZView').innerHTML = zdxView(A.zView); };
    const fail = (e) => { where.querySelector('#admZView').innerHTML = `<div class="bp-card risk" role="alert">${E(e.message)}</div>`; };
    where.querySelectorAll('button[data-admscore]').forEach(b => b.addEventListener('click', async () => {
      try { A.zView = { kind: 'score', data: await lookup(H, 'zdx_trace', 'app_score', { device_id: '', app_id: b.dataset.admscore }) }; view(); } catch (e) { fail(e); } }));
    where.querySelector('#admZUser').addEventListener('input', e => { A.zUser = e.target.value; });
    const more = async () => {
      const box = where.querySelector('#admZMore');
      if (!A.zDev) { box.innerHTML = ''; return; }
      try {
        const [ap, tr] = await Promise.all([lookup(H, 'zdx_trace', 'apps', { device_id: A.zDev }), lookup(H, 'zdx_trace', 'traces', { device_id: A.zDev })]);
        A.zApps = ap.apps || []; A.zTraces = tr.traces || [];
        box.innerHTML = `<div class="op-row"><button type="button" class="rp-btn" id="admZHealthView">Device details and health</button></div>
          ${table("The device's applications", ['Application', 'Score', 'Performance'], A.zApps.map(a => `<tr><td>${E(a.name)}</td><td>${E(a.score == null ? '' : a.score)}</td>
            <td><button type="button" class="rp-btn" data-admperf="${E(a.id)}" aria-label="Performance of ${E(a.name)} on this device">Show</button></td></tr>`), 'No application on this device.')}
          ${table('Deep traces on this device', [stopForm ? 'Pick' : 'Follow', 'Session', 'Status', 'Started'], A.zTraces.map(t => `<tr><td>${stopForm
            ? `<input type="radio" name="admTrace" value="${E(t.trace_id)}" aria-label="Stop ${E(t.session_name || t.trace_id)}"${A.zTrace === t.trace_id ? ' checked' : ''}>`
            : `<button type="button" class="rp-btn" data-admfollow="${E(t.trace_id)}" aria-label="Follow ${E(t.session_name || t.trace_id)}">Follow</button>`}</td>
            <td>${E(t.session_name)}</td><td>${E(t.status)}</td><td>${E(t.started_at || t.created_at)}</td></tr>`), 'No deep trace on this device.')}
          ${stopForm ? '' : `<h3 class="op-h">Start a deep trace</h3>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Session name</span><input id="admZName" maxlength="64" value="${E(A.zName)}" aria-label="Session name" placeholder="slow teams calls"></label>
            <label class="df-ctl"><span class="lbl">Length</span><select id="admZLen" aria-label="Length in minutes">${(res.lengths || [5, 15, 30, 60]).map(m => `<option value="${m}"${Number(A.zLen) === m ? ' selected' : ''}>${m} minutes</option>`).join('')}</select></label></div>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Application</span><select id="admZApp" aria-label="Application to trace"><option value="">None</option>
            ${A.zApps.map(a => `<option value="${E(a.id)}"${A.zApp === a.id ? ' selected' : ''}>${E(a.name)}</option>`).join('')}</select></label>
            <label class="df-ctl"><span class="lbl">Web probe</span><select id="admZWeb" aria-label="Web probe"><option value="">None</option>${A.zWeb.map(p => `<option value="${E(p.id)}"${A.zWebId === p.id ? ' selected' : ''}>${E(p.name)}</option>`).join('')}</select></label>
            <label class="df-ctl"><span class="lbl">CloudPath probe</span><select id="admZPath" aria-label="CloudPath probe"><option value="">None</option>${A.zPath.map(p => `<option value="${E(p.id)}"${A.zPathId === p.id ? ' selected' : ''}>${E(p.name)}</option>`).join('')}</select></label></div>
          <div class="op-row"><label class="df-ctl"><input type="checkbox" id="admZHealth"${A.zHealth ? ' checked' : ''}><span>Collect the device's own health too</span></label></div>`}`;
        bindMore();
      } catch (e) { box.innerHTML = `<div class="bp-card risk" role="alert">${E(e.message)}</div>`; }
    };
    const bindMore = () => {
      const q = id => where.querySelector('#' + id);
      if (q('admZHealthView')) q('admZHealthView').addEventListener('click', async () => { try { A.zView = { kind: 'health', data: await lookup(H, 'zdx_trace', 'health', { device_id: A.zDev }) }; view(); } catch (e) { fail(e); } });
      where.querySelectorAll('button[data-admperf]').forEach(b => b.addEventListener('click', async () => {
        try { A.zView = { kind: 'perf', data: await lookup(H, 'zdx_trace', 'device_app', { device_id: A.zDev, app_id: b.dataset.admperf }) }; view(); } catch (e) { fail(e); } }));
      where.querySelectorAll('button[data-admfollow]').forEach(b => b.addEventListener('click', () => follow(H, where, b.dataset.admfollow)));
      where.querySelectorAll('input[name="admTrace"]').forEach(r => r.addEventListener('change', () => { A.zTrace = r.value; }));
      if (q('admZName')) q('admZName').addEventListener('input', e => { A.zName = e.target.value; });
      if (q('admZLen')) q('admZLen').addEventListener('change', e => { A.zLen = Number(e.target.value); });
      if (q('admZHealth')) q('admZHealth').addEventListener('change', e => { A.zHealth = e.target.checked; });
      if (q('admZWeb')) q('admZWeb').addEventListener('change', e => { A.zWebId = e.target.value; });
      if (q('admZPath')) q('admZPath').addEventListener('change', e => { A.zPathId = e.target.value; });
      if (q('admZApp')) q('admZApp').addEventListener('change', async e => {
        A.zApp = e.target.value; A.zWeb = []; A.zPath = []; A.zWebId = ''; A.zPathId = '';
        if (A.zApp) { try { const p = await lookup(H, 'zdx_trace', 'probes', { device_id: A.zDev, app_id: A.zApp }); A.zWeb = p.web_probes || []; A.zPath = p.cloudpath_probes || []; } catch (err) { fail(err); } }
        await more(); const s = where.querySelector('#admZApp'); if (s) s.focus();
      });
    };
    const bindDev = () => { const s = where.querySelector('#admZDev'); if (s) s.addEventListener('change', async () => { A.zDev = s.value; A.zApp = ''; A.zTrace = ''; await more(); }); };
    bindDev();
    if (A.zDev) more();
    where.querySelector('#admZFind').addEventListener('click', async () => {
      const term = A.zUser.trim();
      try {
        let devs = [];
        if (/^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/.test(term)) devs = (await lookup(H, 'zdx_trace', 'devices', { user: term })).devices || [];
        else { const u = await lookup(H, 'zdx_trace', 'users', { user: term }); (u.users || []).forEach(x => (x.devices || []).forEach(d => devs.push({ id: d.id, name: `${d.name} (${x.email || x.name})` }))); }
        A.zDevices = devs; A.zDev = '';
        where.querySelector('#admZDevs').innerHTML = zdxDevicesHtml() || '<div class="df-hint">No device found for this user.</div>';
        bindDev(); where.querySelector('#admZMore').innerHTML = ''; H.say(`${devs.length} device(s).`);
      } catch (e) { fail(e); }
    });
  }
  async function follow(H, where, traceId) {
    const box = where.querySelector('#admZView');
    try {
      const snap = await H.runJob('/api/operations/zdx/deeptrace/follow/start', H.body({ device_id: A.zDev, trace_id: traceId }), box, 'Following the deep trace (read-only)');
      A.zView = { kind: 'follow', data: snap.result || {} };
      box.innerHTML = zdxView(A.zView);
    } catch (e) { box.innerHTML = `<div class="bp-card risk" role="alert">${E(e.message)}</div>`; }
  }
  function specTraceStart() {
    if (!A.zDev) throw new Error("Find the user's device first.");
    if (!A.zName.trim()) throw new Error('Give the session a name.');
    const s = { type: 'zdx_deeptrace_start', device_id: A.zDev, session_name: A.zName.trim(), session_length_minutes: Number(A.zLen) || 5, probe_device: !!A.zHealth, user: A.zUser.trim() };
    if (A.zApp) s.app_id = A.zApp;
    if (A.zWebId) s.web_probe_id = A.zWebId;
    if (A.zPathId) s.cloudpath_probe_id = A.zPathId;
    return s;
  }
  function specTraceStop() {
    if (!A.zDev || !A.zTrace) throw new Error('Find the device and pick the deep trace to stop.');
    return { type: 'zdx_deeptrace_stop', device_id: A.zDev, trace_id: A.zTrace };
  }

  const DEFS = {
    zpa_infra_update: [renderUpdate, specUpdate], zpa_infra_delete: [renderDelete, specDelete], zpa_provisioning_key_new: [renderKey, specKey, showKeys],
    zpa_ba_certificate: [renderCert, specCert], zcc_device_remove: [renderRemove, specRemove], zcc_device_bulk_remove: [renderBulk, specBulk, (r, w) => csvLinks(r, w, 'result')],
    zcc_bypass_app: [renderBypass, specBypass], zcc_entitlements: [renderEnt, specEnt],
    zdx_deeptrace_start: [(r, w, S, H) => renderTrace(r, w, S, H, false), specTraceStart], zdx_deeptrace_stop: [(r, w, S, H) => renderTrace(r, w, S, H, true), specTraceStop],
  };
  Object.entries(DEFS).forEach(([type, [render, spec, result]]) => window.OPS_PLUGINS.register({
    type,
    render(res, where, S, H) { E = H.E || E; render(res, where, S, H); },
    spec(S) { return spec(S); },
    result(r, where, H) { E = H.E || E; if (result) result(r, where, H); },
    preview(p, where, H, jobId) { E = H.E || E; if (type === 'zcc_device_bulk_remove' || type === 'zcc_device_remove') csvLinks(p, where, 'plan', jobId); },
  }));
}());
